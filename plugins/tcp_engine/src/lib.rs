#![no_std]

pub mod connections;
extern crate alloc;

use alloc::vec::Vec;
use core::{ptr, slice};
use core::cell::{Cell, RefCell};

use network_types::eth::EtherType;
use macaddr::MacAddr6;

use xbricks_protocol::headers::{HeaderKind, IpHeader, MacHeader, TcpHeader};
//use xbricks_protocol::hstack::HeaderStack;
use xbricks_protocol::helpers::{parse_ip, parse_mac, parse_suffixed_number, update_tcp_checksum};
use xbricks_protocol::{PluginOpcode, StandardOpcode};
use xbricks_protocol::packet::{Packet, PacketBatch};
use crate::connections::{ConnectionNode, ConnectionPool, FlowKey, TcpState};
use crate::exports::xbricks::plugins::packet_engine::Guest;
use crate::xbricks::plugins::logging;

// 1. Tell the macro to read the .wit file and generate the bindings
wit_bindgen::generate!({
    path: "../../wit/xbricks.wit",
    world: "engine-plugin",
});

// =====================================================================
// ZERO-COST WASM STATE CONTAINERS
// =====================================================================

/// A zero-cost, single-threaded state container for WASM.
/// Uses `RefCell` to prevent re-entrancy panics, but uses NO ATOMICS.
pub struct WasmCell<T>(RefCell<T>);
// SAFETY: WASM is single-threaded by specification; there is no concurrent access to these
// statics. `Sync` is needed to place `WasmCell` in a `static`, but no thread can ever
// observe a data race in this environment.
unsafe impl<T> Sync for WasmCell<T> {}

impl<T> WasmCell<T> {
    pub const fn new(value: T) -> Self {
        Self(RefCell::new(value))
    }
    pub fn borrow_mut(&self) -> core::cell::RefMut<'_, T> {
        self.0.borrow_mut()
    }
    pub fn borrow(&self) -> core::cell::Ref<'_, T> {
        self.0.borrow()
    }
}

/// An even faster container for simple Copy types (like u64).
/// Uses `Cell`, which doesn't even have a borrow counter. Absolute zero overhead.
pub struct WasmValue<T>(Cell<T>);
// SAFETY: Same as `WasmCell` — WASM is single-threaded, so `Sync` cannot be violated.
// `Cell<T>` itself is not `Sync`, but no concurrent access is possible in this runtime.
unsafe impl<T> Sync for WasmValue<T> {}

impl<T> WasmValue<T> {
    pub const fn new(value: T) -> Self {
        Self(Cell::new(value))
    }
    pub fn get(&self) -> T where T: Copy {
        self.0.get()
    }
    pub fn set(&self, val: T) {
        self.0.set(val)
    }
}



// Standard TCP Flags
const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_ACK: u8 = 0x10;

// 1. Define a structured config to hold parsed data
#[derive(Clone, Default)]
struct EngineConfig {
    src_mac: Option<[u8; 6]>,
    dst_mac: Option<[u8; 6]>,
    src_ip: Option<[u8; 4]>,
    dst_ip: Option<[u8; 4]>,
    rng_seed: Option<u32>,
    syn_rate: Option<u64>,
    tsc_frequency: u64,
    syn_limit: Option<u64>,
    close_timeout_millis: Option<u64>,
    /// Whether to bypass the TCP engine and forward packets to the standard Linux networking stack.
    bypass: bool,
}

struct SynGenerator {
    last_tsc: u64,
    cycle_accumulator: u128,
    port_counter: u16,
    /// if ports are exhausted, we increase the IP address
    ip_offset: u32,
    /// Simple seed for ISNs
    prng_state: u32,
    /// Track total SYNs generated
    syns_sent: u64,
    activated: bool,
}
const MAX_TIMEOUTS: usize = 131072;  // 128k timeouts

// Add a dummy constructor to your FlowKey (if you don't have one)
impl FlowKey {
    pub const fn empty() -> Self {
        Self(0, 0, 0, 0)
    }
}

pub struct TimeoutStack {
    // We dropped the Option! Array is now densely packed at 12 bytes per slot.
    items: [FlowKey; MAX_TIMEOUTS],
    len: usize,
}

impl TimeoutStack {
    pub const fn new() -> Self {
        Self {
            // Fill the array with dummy data. We will overwrite it later.
            items: [FlowKey::empty(); MAX_TIMEOUTS],
            len: 0,
        }
    }

    pub fn push(&mut self, key: FlowKey) {
        if self.len < MAX_TIMEOUTS {
            self.items[self.len] = key; // Overwrite the dummy/old data
            self.len += 1;
        }
    }

    pub fn pop(&mut self) -> Option<FlowKey> {
        if self.len > 0 {
            self.len -= 1;
            // Return a copy of the valid key. The old data remains in the array
            // as garbage, but the `len` pointer ensures we never read it again.
            Some(self.items[self.len])
        } else {
            None
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl core::iter::Extend<FlowKey> for TimeoutStack {
    /// Extends the stack with items from an iterator.
    /// Safely drops any excess items if `MAX_TIMEOUTS` is reached.
    fn extend<T: IntoIterator<Item = FlowKey>>(&mut self, iter: T) {
        for key in iter {
            if self.len < MAX_TIMEOUTS {
                self.items[self.len] = key;
                self.len += 1;
            } else {
                // The queue is full. Break early to ignore the remaining items
                // and naturally apply backpressure to the scavenger.
                break;
            }
        }
    }
}

static CONFIG: WasmCell<Option<EngineConfig>> = WasmCell::new(None);
static CONNECTIONS: WasmCell<Option<ConnectionPool>> = WasmCell::new(None);
static TIMEOUT_QUEUE: WasmCell<TimeoutStack> = WasmCell::new(TimeoutStack::new());
static SYN_GEN: WasmCell<SynGenerator> = WasmCell::new(SynGenerator {
    last_tsc: 0,
    cycle_accumulator: 0,
    port_counter: PORT_START_RANGE,
    ip_offset: 0,
    prng_state: 1,
    syns_sent: 0,
    activated: false,
});

// Replaced AtomicU64 and Mutex<u64> with WasmValue (Instant access)
static CURRENT_TSC: WasmValue<u64> = WasmValue::new(0);
static LAST_TIMEOUT_SCAN: WasmValue<u64> = WasmValue::new(0);

const ROUTE_TX: u32 = 0;
const ROUTE_LINUX: u32 = 1;
const ROUTE_DROP: u32 = 2;


pub const STAT_SENT_SYN: usize = 0;
pub const STAT_SENT_SYNACK: usize = 1;
pub const STAT_SENT_SYNACK2: usize = 2;
pub const STAT_SENT_FIN: usize = 3;
pub const STAT_SENT_FIN_PSSV: usize = 4;
pub const STAT_SENT_ACK4FIN: usize = 5;
pub const STAT_SENT_ACK: usize = 6;
pub const STAT_SENT_RST: usize = 7;
pub const STAT_RECV_SYN: usize = 8;
pub const STAT_RECV_SYNACK: usize = 9;
pub const STAT_RECV_SYNACK2: usize = 10;
pub const STAT_RECV_FIN: usize = 11;
pub const STAT_RECV_FIN_PSSV: usize = 12;
pub const STAT_RECV_ACK4FIN: usize = 13;
pub const STAT_RECV_ACK: usize = 14;
pub const STAT_RECV_RST: usize = 15;
pub const STAT_UNEXPECTED: usize = 16;
pub const STAT_RECV_PAYLOAD: usize = 17;
pub const STAT_SENT_PAYLOAD: usize = 18;
pub const STAT_TICK_DROP: usize = 19;
pub const STAT_TO_LINUX: usize = 20;
pub const STAT_DROP: usize = 21;
pub const STAT_COUNT: usize = 22;

// The zero-cost global counter array
static TCP_STATS: WasmCell<[u64; STAT_COUNT]> = WasmCell::new([0; STAT_COUNT]);

// The macro to use inside process_batch
macro_rules! inc_stat {
    ($stat:expr) => {
        TCP_STATS.borrow_mut()[$stat] += 1
    }
}


const PORT_START_RANGE: u16 = 10000;
const PORT_END_RANGE: u16 = 65535;

struct HostLogger;

impl log::Log for HostLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true // You can add level filtering here if you want to save cycles
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            // Format the message using the alloc crate
            let msg = alloc::format!("tcp_engine: {}", record.args());
            // Call the WIT-generated host function.
            // The path matches your package: xbricks:plugins/logging
            logging::log(record.level() as u32, &msg);
        }
    }

    fn flush(&self) {}
}

// 2. Add an init function to wire it up when the plugin starts
pub fn init_logging() {
    // We use set_logger instead of set_boxed_logger to avoid allocations if possible,
    // or Box::new if required by the log crate version.
    static LOGGER: HostLogger = HostLogger;
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Info); // Set your desired Wasm log level
}

fn init_state_machine() {
    // 524,288 is a power of 2. It will consume ~25MB of Wasm heap instantly at boot,
    // but it will NEVER trigger a resize or memory.grow during execution.
    *CONNECTIONS.borrow_mut() = Some(ConnectionPool::new(524_288));
}

struct TcpEngine;

impl Guest for TcpEngine {
    // init_data is called once per plugin instance, and is responsible for initializing the state of the plugin.
    // It is called before any other function in the plugin.
    // The init_data function is called with the following arguments:
    // - data: A vector of key-value pairs, where each pair is a (key, value) tuple.
    //   the key value pairs are set in the .toml file for a node of type WasmEngine in the section "wasm_data"
    // - tsc_frequency: The frequency of the TSC counter, in Hz.
    // The init_data function should initialize the plugin's state, such as the connection pool
    // or any other state that needs to be maintained across batches.
    // The init_data function should also set the tsc_frequency value in the EngineConfig struct.
    // The init_data function should return a boolean value indicating whether the initialization was successful.
    // If the initialization is successful, the plugin will be ready to process batches.
    fn init_data(data: Vec<(alloc::string::String, alloc::string::String)>, tsc_frequency:u64) {
        init_logging();
        let mut config = EngineConfig::default();
        config.bypass = false;
        init_state_machine();
        for (key, value) in data {
            match key.as_str() {
                "src_mac" => config.src_mac = parse_mac(&value),
                "dst_mac" => config.dst_mac = parse_mac(&value),
                "src_ip" => config.src_ip = parse_ip(&value),
                "dst_ip" => config.dst_ip = parse_ip(&value),
                "rng_seed" => config.rng_seed = value.parse::<u32>().ok(),
                "syn_rate" => config.syn_rate = parse_suffixed_number(&value).ok(),
                "syn_limit" => config.syn_limit = parse_suffixed_number(&value).ok(),
                "close_timeout" => config.close_timeout_millis = value.parse::<u64>().ok(),
                _ => {}
            }
        }
        config.tsc_frequency = tsc_frequency;
        *CONFIG.borrow_mut() = Some(config);
    }

    fn process_batch(mut batch_bytes: Vec<u8>, partition_offset: u32) -> (Vec<u32>, Vec<u32>) {
        log::trace!("process_batch: len= {}, partition_offset= {}", batch_bytes.len(), partition_offset);
        let mut batch = PacketBatch::new(&mut batch_bytes, partition_offset);
        let local_config = CONFIG.borrow().clone().unwrap_or_default();

        // =======================================================
        // Fast-Path Bypass
        // =======================================================
        if local_config.bypass {
            let mut actions = Vec::with_capacity(batch.len());
            let mut lengths = Vec::with_capacity(batch.len());
            for mut packet in batch.iter_mut() {
                // 2. Wrap PDU to cleanly check for ticks
                let action = if packet.is_a_tick() {
                    inc_stat!(STAT_DROP);
                    inc_stat!(STAT_TICK_DROP);
                    ROUTE_DROP
                } else {
                    inc_stat!(STAT_TO_LINUX);
                    ROUTE_LINUX
                };
                actions.push(action);
                lengths.push(packet.data_len());
            }
            return (actions, lengths);
        }
        // =======================================================

        let mut actions = Vec::with_capacity(batch.len());
        let mut lengths = Vec::with_capacity(batch.len());

        // Lock Global States ONCE per batch
        let mut connections_guard = CONNECTIONS.borrow_mut();
        let Some(pool) = connections_guard.as_mut() else {
            log::error!("process_batch: connection table uninitialized — dropping all packets");
            let n = batch.len();
            let mut drop_actions = Vec::with_capacity(n);
            let mut drop_lengths = Vec::with_capacity(n);
            drop_actions.resize(n, ROUTE_DROP);
            drop_lengths.resize(n, 0u32);
            return (drop_actions, drop_lengths);
        };

        for mut packet in batch.iter_mut() {
            let mut action = 0;
            let mut len = 64;
            if packet.is_a_tick() {
                log::trace!("process_batch: tick");
                let mut generated_reply = false;

                // PRIORITY 1: Process Timeout Teardowns
                let pending_timeout = {
                    let mut queue = TIMEOUT_QUEUE.borrow_mut();
                    queue.pop()
                };

                if let Some(flow_key) = pending_timeout {
                    log::trace!("process_batch: processing timeout for flow_key {:?}", flow_key);
                    let current_tsc = CURRENT_TSC.get();
                    let (snd_nxt, rcv_nxt, state, exists) = if let Some(conn) = pool.get_mut_and_touch(&flow_key, current_tsc) {
                        (conn.snd_nxt, conn.rcv_nxt, conn.state, true)
                    } else {
                        (0, 0, TcpState::Closed, false)
                    };

                    if exists {
                        let data_ptr = packet.data_ptr_mut();
                        let reply_src_mac = local_config.src_mac.unwrap_or([0; 6]);
                        let reply_dst_mac = local_config.dst_mac.unwrap_or([0xff; 6]);

                        if state == TcpState::Established || state == TcpState::SynReceived {
                            if let Some(conn) = pool.get_mut(&flow_key) {
                                conn.state = TcpState::FinWait1;
                                conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
                            }
                            len = write_tcp_reply(
                                data_ptr, reply_src_mac, reply_dst_mac,
                                flow_key.2, flow_key.3, flow_key.0, flow_key.1,
                                snd_nxt, rcv_nxt, FLAG_FIN | FLAG_ACK
                            );
                            inc_stat!(STAT_SENT_FIN);
                            action = ROUTE_TX;
                            generated_reply = true;
                        } else {
                            pool.remove(&flow_key);
                            inc_stat!(STAT_SENT_RST);
                            len = write_tcp_reply(
                                data_ptr, reply_src_mac, reply_dst_mac,
                                flow_key.2, flow_key.3, flow_key.0, flow_key.1,
                                snd_nxt, rcv_nxt, FLAG_RST | FLAG_ACK
                            );
                            action = ROUTE_TX;
                            generated_reply = true;
                        }
                    }
                }
                // PRIORITY 2: Generate new SYNs
                if !generated_reply {
                    log::trace!("process_batch: generating new SYN");
                    let syn_rate = local_config.syn_rate.unwrap_or(0);
                    if syn_rate > 0 {
                        let mut gen = SYN_GEN.borrow_mut();
                        let allowed_to_send = gen.activated && match local_config.syn_limit {
                            Some(max_syns) => gen.syns_sent < max_syns || max_syns == 0,
                            None => true,
                        };

                        if allowed_to_send {
                            gen.syns_sent += 1;
                            gen.prng_state = gen.prng_state.wrapping_mul(1664525).wrapping_add(1013904223);
                            let isn = gen.prng_state;

                            let src_port = gen.port_counter;
                            let base_ip = u32::from_be_bytes(local_config.src_ip.unwrap_or([0, 0, 0, 0]));
                            let our_ip = base_ip.wrapping_add(gen.ip_offset);

                            if gen.port_counter >= PORT_END_RANGE {
                                gen.port_counter = PORT_START_RANGE;
                                // Shift to the next IP address (cycle through 250 IPs)
                                gen.ip_offset = (gen.ip_offset + 1) % 250;
                            } else {
                                gen.port_counter += 1;
                            }

                            let dst_port = 80;
                            let their_ip = u32::from_be_bytes(local_config.dst_ip.unwrap_or([0, 0, 0, 0]));

                            let flow_key = FlowKey(their_ip, dst_port, our_ip, src_port);
                            pool.insert(flow_key, TcpState::SynSent, isn.wrapping_add(1), 0, CURRENT_TSC.get());

                            let data_ptr = packet.data_ptr_mut();
                            let reply_src_mac = local_config.src_mac.unwrap_or([0; 6]);
                            let reply_dst_mac = local_config.dst_mac.unwrap_or([0xff; 6]);

                            len = write_tcp_reply(
                                data_ptr, reply_src_mac, reply_dst_mac,
                                our_ip, src_port, their_ip, dst_port,
                                isn, 0, FLAG_SYN
                            );
                            inc_stat!(STAT_SENT_SYN);
                            action = ROUTE_TX;
                            generated_reply = true;
                        }
                    }
                }
                // nothing generated, drop the tick
                if !generated_reply {
                    inc_stat!(STAT_DROP);
                    inc_stat!(STAT_TICK_DROP);
                    action = ROUTE_DROP;
                    len = 64;
                }
            } else if packet.headers().fingerprint() == Packet::TCP_OVER_IPV4 {
                // TCP FRAME - Delegate to the clean state machine
                (action, len) = handle_tcp_packet(&mut packet, pool, &local_config);
            } else {
                inc_stat!(STAT_TO_LINUX);
                action = ROUTE_LINUX;
                len = packet.data_len();
            }
            actions.push(action);
            lengths.push(len);
        }
        log::trace!("process_batch: Finished successfully with {}, {} actions", actions.len(), lengths.len());
        (actions, lengths)
    }

    fn process_timers(current_tsc: u64) -> u32 {
        // Share time with process_batch
        CURRENT_TSC.set(current_tsc);

        let config = CONFIG.borrow().clone().unwrap_or_default();
        let tsc_freq = config.tsc_frequency;
        let mut frames_to_request = 0;

        if tsc_freq == 0 { return 0; }

        // =================================================================
        // 1. TIMEOUT SCAVENGER
        // =================================================================
        if let Some(timeout_millis) = config.close_timeout_millis {
            let timeout_cycles = ((timeout_millis as u128 * tsc_freq as u128)/1000) as u64;
            let last_scan = LAST_TIMEOUT_SCAN.get();

            // Run the table scan only once every 10ms to save CPU
            if current_tsc.saturating_sub(last_scan) > (tsc_freq / 100) {

                LAST_TIMEOUT_SCAN.set(current_tsc);
                let mut pool_guard = CONNECTIONS.borrow_mut();
                let mut queue = TIMEOUT_QUEUE.borrow_mut();

                if let Some(pool) = pool_guard.as_mut() {
                    let timeouts= pool.scavenge_timeouts(current_tsc, timeout_cycles);
                    log::trace!("process_timers: timeouts.len= {}", timeouts.len());
                    queue.extend(timeouts);
                }
            }
        }
        frames_to_request += TIMEOUT_QUEUE.borrow().len() as u32;

        // =================================================================
        // 2. SYN GENERATOR
        // =================================================================
        let syn_rate = config.syn_rate.unwrap_or(0);
        if syn_rate > 0 {
            let mut gen = SYN_GEN.borrow_mut();

            let allowed_to_send = gen.activated && match config.syn_limit {
                Some(max_syns) => gen.syns_sent < max_syns || max_syns == 0,
                None => true,
            };

            if allowed_to_send {
                if gen.last_tsc == 0 { gen.last_tsc = current_tsc; }
                let delta_tsc = current_tsc.saturating_sub(gen.last_tsc);
                gen.last_tsc = current_tsc;

                gen.cycle_accumulator += (delta_tsc as u128) * (syn_rate as u128);
                let mut syn_frames = (gen.cycle_accumulator / (tsc_freq as u128)) as u32;

                if let Some(max_syns) = config.syn_limit {
                    let remaining = max_syns.saturating_sub(gen.syns_sent);
                    if (syn_frames as u64) > remaining {
                        syn_frames = remaining as u32;
                    }
                }
                gen.cycle_accumulator %= tsc_freq as u128;

                log::trace!("process_timers: syn_frames= {}, gen.syns_sent= {}, max_syns= {:?}", syn_frames, gen.syns_sent, config.syn_limit);
                frames_to_request += syn_frames;
            }
        }
        frames_to_request
    }

    // Inside the Wasm plugin code

    fn on_control_event(raw_opcode: u32, payload: Vec<u8>) -> bool {
        // 1. Convert the raw u32 into our rich enum
        let opcode = PluginOpcode::from(raw_opcode);

        // 2. Route the command safely
        match opcode {
            PluginOpcode::Standard(StandardOpcode::SetOperationalState) => {
                if payload.len() == 1 {
                    set_state(payload[0]);
                    true
                } else {
                    false
                }
            }
            PluginOpcode::Standard(StandardOpcode::FlushState) => {
                flush_state(payload[0]);
                true
            }
            PluginOpcode::Standard(StandardOpcode::Ping) => {
                // Echo the payload back or log it
                log::info!("PING received");
                true
            }

            // --- Developer's Custom Commands ---
            PluginOpcode::Custom(0x1001) => {
                //apply_modbus_rules(payload);
                true
            }
            PluginOpcode::Custom(0x1002) => {
                //clear_connection_cache();
                true
            }

            // Unhandled or unknown commands
            _ => {
                log::warn!("Ignored opcode: {:?}", opcode);
                false
            }
        }
    }

    fn get_telemetry() -> Vec<u64> {
        TCP_STATS.borrow().to_vec()
    }
}

fn set_state(state: u8) {
    let mut syn_gen = SYN_GEN.borrow_mut();
    let mut config_guard = CONFIG.borrow_mut();

    // Safely attempt to modify the config only if it exists
    if let Some(config) = config_guard.as_mut() {
        match state {
            0 => {
                // State 0: Offline / Paused
                syn_gen.activated = false;
                config.bypass = false;
            }
            1 => {
                // State 1: Online / Active
                syn_gen.activated = true;
                config.bypass = false;
            }
            2 => {
                // State 2: Bypass Mode
                // Disable generation, let all traffic flow transparently
                syn_gen.activated = false;
                config.bypass = true;
            }
            _ => {
                // Ignore unknown states
            }
        }
    }
}

fn flush_state(mode: u8) {

    // This stops the generator and prevents a new run from starting automatically.
    set_state(0);

    // Clear the pool in-place instead of re-allocating
    if let Some(pool) = CONNECTIONS.borrow_mut().as_mut() {
        pool.clear();
    }

    // Clear the pending timeout teardowns so we don't send FINs for connections
    // that just got wiped out.
    TIMEOUT_QUEUE.borrow_mut().clear();

    // Reset the SYN generator tracking
    {
        let mut syn_gen = SYN_GEN.borrow_mut();
        syn_gen.syns_sent = 0;
        syn_gen.cycle_accumulator = 0;
        syn_gen.last_tsc = 0;

        // Optional: If mode == 1 (Hard Reset), also reset the PRNG and Port Counter
        // to ensure perfectly repeatable PCAP generation across test runs.
        if mode == 1 {
            syn_gen.port_counter = PORT_START_RANGE;
            syn_gen.prng_state = 1;
        }
    }

    // 5. Clear all telemetry counters
    *TCP_STATS.borrow_mut() = [0; STAT_COUNT];

    log::trace!("TCP Engine state flushed (mode: {})", mode);
}

/// Extracts protocol data, runs the state machine, and formats replies
fn handle_tcp_packet(
    packet: &mut Packet,
    pool: &mut ConnectionPool,
    config: &EngineConfig,
) -> (u32, u32) {
    let current_tsc = CURRENT_TSC.get();

    // Safely extract the strongly-typed headers using the Context Wrapper
    let mac_hdr = match packet.mac_header() {
        Some(m) => m,
        None => return (ROUTE_LINUX, packet.data_len()),
    };
    let ip_hdr = match packet.ipv4_header() {
        Some(i) => i,
        None => return (ROUTE_LINUX, packet.data_len()),
    };
    let tcp_hdr = match packet.tcp_header() {
        Some(t) => t,
        None => return (ROUTE_LINUX, packet.data_len()),
    };

    let incoming_src_mac = mac_hdr.src.into_array();
    let incoming_dst_mac = mac_hdr.dst.into_array();

    let src_ip = ip_hdr.src();
    let dst_ip = ip_hdr.dst();
    let src_port = tcp_hdr.src_port();
    let dst_port = tcp_hdr.dst_port();
    let flow_key = FlowKey(src_ip, src_port, dst_ip, dst_port);
    log::trace!("handle_tcp_packet: processing packet with flow_key {:?}", flow_key);

    let tcp_flags = tcp_hdr.flags();
    let seq_num = tcp_hdr.seq_num();
    let ack_num = tcp_hdr.ack_num();

    let ip_total_len = ip_hdr.length() as u32;
    let ip_hdr_len = (ip_hdr.ihl() * 4) as u32;
    let tcp_hdr_len = (tcp_hdr.data_offset() * 4) as u32;
    let payload_len = ip_total_len.saturating_sub(ip_hdr_len + tcp_hdr_len);

    let action_opt;
    let mut current_state = None;

    if let Some(conn) = pool.get_mut_and_touch(&flow_key, current_tsc) {
        action_opt = run_tcp_state_machine(conn, tcp_flags, seq_num, ack_num, payload_len);
        current_state = Some(conn.state);
    } else {
        if tcp_flags & FLAG_RST != 0 {
            inc_stat!(STAT_RECV_RST);
            return (ROUTE_DROP, 0);
        }
        // Catch stray ACKs and SYN-ACKs for dead connections
        if tcp_flags & FLAG_ACK != 0 {
            inc_stat!(STAT_UNEXPECTED);
            let reply_seq = ack_num;
            let reply_ack = seq_num.wrapping_add(payload_len).wrapping_add(if tcp_flags & FLAG_FIN != 0 { 1 } else { 0 });

            inc_stat!(STAT_SENT_RST);
            action_opt = Some((FLAG_RST | FLAG_ACK, reply_seq, reply_ack));
        }
        else if tcp_flags & FLAG_SYN != 0 {
            inc_stat!(STAT_RECV_SYN);
            let rcv_nxt = seq_num.wrapping_add(1);
            let initial_snd_nxt = 1000u32;
            pool.insert(flow_key, TcpState::SynReceived, initial_snd_nxt.wrapping_add(1), rcv_nxt, current_tsc);

            inc_stat!(STAT_SENT_SYNACK);
            action_opt = Some((FLAG_SYN | FLAG_ACK, initial_snd_nxt, rcv_nxt));
        } else {
            inc_stat!(STAT_UNEXPECTED);
            let reply_seq = if tcp_flags & FLAG_ACK != 0 { ack_num } else { 0 };
            let reply_ack = seq_num.wrapping_add(payload_len).wrapping_add(if tcp_flags & FLAG_FIN != 0 { 1 } else { 0 });

            inc_stat!(STAT_SENT_RST);
            action_opt = Some((FLAG_RST | FLAG_ACK, reply_seq, reply_ack));
        }
    }

    if current_state == Some(TcpState::Closed) { pool.remove(&flow_key); }

    if let Some((reply_flags, reply_seq, reply_ack)) = action_opt {
        let data_ptr = packet.data_ptr_mut();
        let reply_dst_mac = incoming_src_mac;
        let reply_src_mac = config.src_mac.unwrap_or(incoming_dst_mac);

        let len = write_tcp_reply(
            data_ptr, reply_src_mac, reply_dst_mac,
            dst_ip, dst_port, src_ip, src_port,
            reply_seq, reply_ack, reply_flags
        );
        return (ROUTE_TX, len);
    }

    (ROUTE_DROP, 0)
}

/// The core RFC 793 State Machine Logic
fn run_tcp_state_machine(
    conn: &mut ConnectionNode,
    tcp_flags: u8,
    seq_num: u32,
    ack_num: u32,
    payload_len: u32,
) -> Option<(u8, u32, u32)> {

    // Fast-path: Reset drops connection instantly
    if tcp_flags & FLAG_RST != 0 {
        inc_stat!(STAT_RECV_RST);
        conn.state = TcpState::Closed;
        return None;
    }

    // ==========================================
    // INCOMING PACKET TRACKING
    // ==========================================
    if tcp_flags & FLAG_FIN != 0 {
        inc_stat!(STAT_RECV_FIN);
    } else if tcp_flags & FLAG_SYN != 0 && tcp_flags & FLAG_ACK != 0 {
        inc_stat!(STAT_RECV_SYNACK);
    } else if payload_len > 0 {
        inc_stat!(STAT_RECV_PAYLOAD);
    } else if tcp_flags & FLAG_ACK != 0 {
        // Categorize the ACK based on our current state
        match conn.state {
            TcpState::SynReceived => inc_stat!(STAT_RECV_SYNACK2),
            TcpState::FinWait1 | TcpState::LastAck | TcpState::Closing => inc_stat!(STAT_RECV_ACK4FIN),
            _ => inc_stat!(STAT_RECV_ACK),
        }
    }

    macro_rules! reply {
        ($flags:expr) => { Some(($flags, conn.snd_nxt, conn.rcv_nxt)) }
    }

    // ==========================================
    // STATE TRANSITIONS & OUTGOING TRACKING
    // ==========================================
    match conn.state {
        TcpState::Listen => {
            if tcp_flags & FLAG_SYN != 0 {
                conn.state = TcpState::SynReceived;
                conn.rcv_nxt = seq_num.wrapping_add(1);
                let send_seq = conn.snd_nxt;
                conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
                inc_stat!(STAT_SENT_SYNACK);
                return Some((FLAG_SYN | FLAG_ACK, send_seq, conn.rcv_nxt));
            }
        }
        TcpState::SynSent => {
            if tcp_flags & FLAG_SYN != 0 && tcp_flags & FLAG_ACK != 0 {
                if ack_num == conn.snd_nxt {
                    conn.state = TcpState::Established;
                    conn.rcv_nxt = seq_num.wrapping_add(1);
                    inc_stat!(STAT_SENT_SYNACK2); // Final ACK of the 3-way handshake
                    return reply!(FLAG_ACK);
                } else {
                    inc_stat!(STAT_SENT_RST);
                    return Some((FLAG_RST, ack_num, 0)); // Bad ACK sequence
                }
            } else if tcp_flags & FLAG_RST != 0 {
                conn.state = TcpState::Closed; // Connection refused
            }
        }
        TcpState::SynReceived => {
            if tcp_flags & FLAG_ACK != 0 && ack_num == conn.snd_nxt {
                conn.state = TcpState::Established;
            }
        }
        TcpState::Established => {
            if tcp_flags & FLAG_FIN != 0 {
                conn.state = TcpState::LastAck;
                conn.rcv_nxt = seq_num.wrapping_add(1).wrapping_add(payload_len);
                let send_seq = conn.snd_nxt;
                conn.snd_nxt = conn.snd_nxt.wrapping_add(1);

                inc_stat!(STAT_SENT_FIN_PSSV);
                inc_stat!(STAT_SENT_ACK4FIN);
                return Some((FLAG_FIN | FLAG_ACK, send_seq, conn.rcv_nxt));
            } else if tcp_flags & FLAG_ACK != 0 && payload_len > 0 {
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(payload_len);

                inc_stat!(STAT_SENT_ACK); // Pure data acknowledgment
                return reply!(FLAG_ACK);
            }
        }
        TcpState::FinWait1 => {
            if tcp_flags & FLAG_FIN != 0 && tcp_flags & FLAG_ACK != 0 {
                conn.state = TcpState::Closed;
                conn.rcv_nxt = seq_num.wrapping_add(1);
                inc_stat!(STAT_SENT_ACK4FIN);
                return reply!(FLAG_ACK);
            } else if tcp_flags & FLAG_FIN != 0 {
                conn.state = TcpState::Closing;
                conn.rcv_nxt = seq_num.wrapping_add(1);
                inc_stat!(STAT_SENT_ACK4FIN);
                return reply!(FLAG_ACK);
            } else if tcp_flags & FLAG_ACK != 0 {
                conn.state = TcpState::FinWait2;
            }
        }
        TcpState::FinWait2 => {
            if tcp_flags & FLAG_FIN != 0 {
                conn.state = TcpState::Closed;
                conn.rcv_nxt = seq_num.wrapping_add(1);
                inc_stat!(STAT_SENT_ACK4FIN);
                return reply!(FLAG_ACK);
            }
        }
        TcpState::Closing => {
            if tcp_flags & FLAG_ACK != 0 {
                conn.state = TcpState::Closed;
            }
        }
        TcpState::LastAck => {
            if tcp_flags & FLAG_ACK != 0 && ack_num == conn.snd_nxt {
                conn.state = TcpState::Closed;
            }
        }
        TcpState::Closed => {
            if tcp_flags & FLAG_RST == 0 {
                inc_stat!(STAT_SENT_RST);
                return Some((FLAG_RST | FLAG_ACK, 0, seq_num.wrapping_add(payload_len)));
            }
        }
        _ => {}
    }

    None
}

/// Formats the outbound headers back into WASM linear memory
fn write_tcp_reply(
    data_ptr: *mut u8,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
) -> u32 {
    let mut mac = MacHeader::new();
    mac.src = MacAddr6::new(src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    mac.dst = MacAddr6::new(dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    mac.set_ethertype(EtherType::Ipv4);

    let mut ip = IpHeader::new();
    ip.set_src(src_ip);
    ip.set_dst(dst_ip);
    ip.set_ttl(64);
    ip.set_version(4);
    ip.set_protocol(6);
    ip.set_ihl(5);
    ip.set_length(40);
    ip.set_flags(0x2);

    ip.update_checksum();

    let mut tcp = TcpHeader::new();
    tcp.set_flags(flags);
    tcp.set_src_port(src_port);
    tcp.set_dst_port(dst_port);
    tcp.set_data_offset(5);
    tcp.set_seq_num(seq_num);
    tcp.set_ack_num(ack_num);

    // we have space to receive data!
    tcp.set_window_size(64240);

    // Because this is a pure protocol reply (SYN/ACK/RST) with no application data,
    // the IP payload size is exactly the size of the TCP header (20 bytes).
    update_tcp_checksum(&mut tcp, 20, src_ip, dst_ip);

    let mac_size = core::mem::size_of::<MacHeader>();
    let ip_size = core::mem::size_of::<IpHeader>();
    let tcp_size = core::mem::size_of::<TcpHeader>();

    // SAFETY: `data_ptr` comes from `packet.data_ptr_mut()`, which returns a valid pointer into
    // the WASM linear memory frame. The combined header size (54 bytes) is well below the
    // minimum WASM frame size. `mac`, `ip`, and `tcp` are local stack variables; source and
    // destination regions do not overlap. All three types are `Copy` + `#[repr(C)]`.
    unsafe {
        ptr::copy_nonoverlapping(&mac, data_ptr as *mut MacHeader, 1);
        ptr::copy_nonoverlapping(&ip, data_ptr.add(mac_size) as *mut IpHeader, 1);
        ptr::copy_nonoverlapping(&tcp, data_ptr.add(mac_size + ip_size) as *mut TcpHeader, 1);
    }

    (mac_size + ip_size + tcp_size) as u32
}

// Export the implementation to the runtime
export!(TcpEngine);