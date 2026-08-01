#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::ptr;

use macaddr::MacAddr6;
use network_types::eth::EtherType;

use wabrix_api::headers::{IpHeader, MacHeader, TcpHeader};
//use wabrix_api::hstack::HeaderStack;
use crate::exports::wabrix::plugins::packet_engine::Guest;
use crate::wabrix::plugins::logging;
use wabrix_api::connections::{ConnectionNode, ConnectionPool, FlowKey, TcpState};
use wabrix_api::helpers::{parse_ip, parse_mac, parse_suffixed_number, update_tcp_checksum};
use wabrix_api::mailbox_api::MailboxBatch;
use wabrix_api::packet::Packet;
use wabrix_api::{PluginOpcode, StandardOpcode};

use wabrix_api::tcp_common::{
    run_tcp_state_machine, write_tcp_reply, EngineConfig, SynGenerator, TimeoutStack, FLAG_ACK,
    FLAG_FIN, FLAG_RST, FLAG_SYN, PORT_END_RANGE, PORT_START_RANGE, STAT_COUNT, STAT_DROP,
    STAT_RECV_RST, STAT_RECV_SYN, STAT_SENT_FIN, STAT_SENT_RST, STAT_SENT_SYN, STAT_SENT_SYNACK,
    STAT_TICK_DROP, STAT_TO_LINUX, STAT_UNEXPECTED,
};

// 1. Tell the macro to read the .wit file and generate the bindings
wit_bindgen::generate!({
    path: "../../wit/wabrix.wit",
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
    pub fn get(&self) -> T
    where
        T: Copy,
    {
        self.0.get()
    }
    pub fn set(&self, val: T) {
        self.0.set(val)
    }
}

const MAX_TIMEOUTS: usize = 131072; // 128k timeouts

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

// The zero-cost global counter array
static TCP_STATS: WasmCell<[u64; STAT_COUNT]> = WasmCell::new([0; STAT_COUNT]);

// The macro to use inside process_batch
macro_rules! inc_stat {
    ($stat:expr) => {
        TCP_STATS.borrow_mut()[$stat] += 1
    };
}

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
            // The path matches your package: wabrix:plugins/logging
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

const MAX_CONNECTIONS: usize = 524_288;

fn init_state_machine(tcp_node_name: String) {
    // 524,288 is a power of 2. It will consume ~25MB of Wasm heap instantly at boot,
    // but it will NEVER trigger a resize or memory.grow during execution.
    *CONNECTIONS.borrow_mut() = Some(ConnectionPool::new(MAX_CONNECTIONS, tcp_node_name));
}

struct TcpEngine;

impl Guest for TcpEngine {
    // - init_data is called once per plugin instance, and is responsible for initializing the state of the plugin.
    // - It is called before any other function in the plugin.
    // - The init_data function is called with the following arguments:
    //   - data: A vector of key-value pairs, where each pair is a (key, value) tuple.
    //     The key value pairs are set in the .toml file for a node of type WasmEngine in the section "wasm_data"
    //   - tsc_frequency: The frequency of the TSC counter, in Hz.
    // - The init_data function should initialize the plugin's state, such as the connection pool
    //   or any other state that needs to be maintained across batches.
    // - The init_data function should also set the tsc_frequency value in the EngineConfig struct.
    // - The init_data function returns a boolean value indicating whether the initialization was successful.
    // - If the initialization is successful, the plugin will be ready to process batches.
    fn init_data(data: Vec<(alloc::string::String, alloc::string::String)>, tsc_frequency: u64) -> bool {
        init_logging();
        let mut config = EngineConfig::default();
        config.bypass = false;

        let mut raw_src_ip: Option<alloc::string::String> = None;

        for (key, value) in data {
            match key.as_str() {
                "name" => config.name = Some(value),
                "src_mac" => {
                    config.src_mac = parse_mac(&value);
                    if config.src_mac.is_none() {
                        return false;
                    }
                }
                "dst_mac" => {
                    config.dst_mac = parse_mac(&value);
                    if config.dst_mac.is_none() {
                        return false;
                    }
                }
                "src_ip" => {
                    raw_src_ip = Some(value.clone());
                    config.src_ip = parse_ip(&value);
                    if config.src_ip.is_none() {
                        return false;
                    }
                }
                "dst_ip" => {
                    config.dst_ip = parse_ip(&value);
                    if config.dst_ip.is_none() {
                        return false;
                    }
                }
                "rng_seed" => {
                    config.rng_seed = value.parse::<u32>().ok();
                    if config.rng_seed.is_none() {
                        return false;
                    }
                }
                "syn_rate" => {
                    config.syn_rate = parse_suffixed_number(&value).ok();
                    if config.syn_rate.is_none() {
                        return false;
                    }
                }
                "syn_limit" => {
                    config.syn_limit = parse_suffixed_number(&value).ok();
                    if config.syn_limit.is_none() {
                        return false;
                    }
                }
                "close_timeout" => {
                    config.close_timeout_millis = value.parse::<u64>().ok();
                    if config.close_timeout_millis.is_none() {
                        return false;
                    }
                }
                _ => {}
            }
        }

        // - Verify the presence of strictly required parameters.
        // - Reject initialization if fundamental routing data is missing.
        // - Note, dst_ip is not necessary for pure tcp servers, as they always reply to the client ip
        //   but we need dst mac as we have no full routing stack
        if config.src_ip.is_none()
            || config.src_mac.is_none()
            || config.dst_mac.is_none()
        {
            return false;
        }

        // - Resolve node name using fallback chain
        let node_name = config
            .name
            .clone()
            .or(raw_src_ip)
            .unwrap_or_else(|| alloc::string::String::from("unknown"));

        init_state_machine(node_name);

        config.tsc_frequency = tsc_frequency;
        *CONFIG.borrow_mut() = Some(config);

        true
    }

    fn process_batch(batch_size: u32, partition_offset: u32, mailbox_offset: u32) -> u32 {
        log::trace!(
            "process_batch: batch_size={}, partition_offset={}",
            batch_size,
            partition_offset
        );
        let mut batch = MailboxBatch::new(batch_size, partition_offset, mailbox_offset);
        let local_config = CONFIG.borrow().clone().unwrap_or_default();
        let mut processed_count = 0;

        // Fast-Path Bypass
        if local_config.bypass {
            for mut packet in batch.iter_mut() {
                let action = if packet.is_a_tick() {
                    inc_stat!(STAT_DROP);
                    inc_stat!(STAT_TICK_DROP);
                    ROUTE_DROP
                } else {
                    inc_stat!(STAT_TO_LINUX);
                    ROUTE_LINUX
                };
                packet.set_action(action);
                processed_count += 1;
            }
            return processed_count;
        }

        let mut connections_guard = CONNECTIONS.borrow_mut();
        let Some(pool) = connections_guard.as_mut() else {
            log::error!("process_batch: connection table uninitialized — dropping all packets");
            for mut packet in batch.iter_mut() {
                packet.set_action(ROUTE_DROP);
                processed_count += 1;
            }
            return processed_count;
        };

        for mut packet in batch.iter_mut() {
            let (action, _len) = if packet.is_a_tick() {
                log::trace!("process_batch: tick");
                let mut a = ROUTE_DROP;
                let mut l = 64u32;
                let mut generated_reply = false;

                // PRIORITY 1: Process Timeout Teardowns
                let pending_timeout = {
                    let mut queue = TIMEOUT_QUEUE.borrow_mut();
                    queue.pop()
                };

                if let Some(flow_key) = pending_timeout {
                    log::trace!(
                        "process_batch: processing timeout for flow_key {:?}",
                        flow_key
                    );
                    let current_tsc = CURRENT_TSC.get();
                    let (snd_nxt, rcv_nxt, state, exists) =
                        if let Some(conn) = pool.get_mut_and_touch(&flow_key, current_tsc) {
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
                            l = write_tcp_reply(
                                data_ptr,
                                reply_src_mac,
                                reply_dst_mac,
                                flow_key.2,
                                flow_key.3,
                                flow_key.0,
                                flow_key.1,
                                snd_nxt,
                                rcv_nxt,
                                FLAG_FIN | FLAG_ACK,
                            );
                            inc_stat!(STAT_SENT_FIN);
                            a = ROUTE_TX;
                            generated_reply = true;
                        } else {
                            pool.remove(&flow_key);
                            inc_stat!(STAT_SENT_RST);
                            l = write_tcp_reply(
                                data_ptr,
                                reply_src_mac,
                                reply_dst_mac,
                                flow_key.2,
                                flow_key.3,
                                flow_key.0,
                                flow_key.1,
                                snd_nxt,
                                rcv_nxt,
                                FLAG_RST | FLAG_ACK,
                            );
                            a = ROUTE_TX;
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
                        let allowed_to_send = gen.activated
                            && match local_config.syn_limit {
                                Some(max_syns) => gen.syns_sent < max_syns || max_syns == 0,
                                None => true,
                            };

                        if allowed_to_send {
                            gen.syns_sent += 1;
                            gen.prng_state = gen
                                .prng_state
                                .wrapping_mul(1664525)
                                .wrapping_add(1013904223);
                            let isn = gen.prng_state;

                            let src_port = gen.port_counter;
                            let base_ip =
                                u32::from_be_bytes(local_config.src_ip.unwrap_or([0, 0, 0, 0]));
                            let our_ip = base_ip.wrapping_add(gen.ip_offset);

                            if gen.port_counter >= PORT_END_RANGE {
                                gen.port_counter = PORT_START_RANGE;
                                gen.ip_offset = (gen.ip_offset + 1) % 250;
                            } else {
                                gen.port_counter += 1;
                            }

                            let dst_port = 80;
                            let their_ip =
                                u32::from_be_bytes(local_config.dst_ip.unwrap_or([0, 0, 0, 0]));
                            let flow_key = FlowKey(their_ip, dst_port, our_ip, src_port);
                            pool.insert(
                                flow_key,
                                TcpState::SynSent,
                                isn.wrapping_add(1),
                                0,
                                CURRENT_TSC.get(),
                            );

                            let data_ptr = packet.data_ptr_mut();
                            let reply_src_mac = local_config.src_mac.unwrap_or([0; 6]);
                            let reply_dst_mac = local_config.dst_mac.unwrap_or([0xff; 6]);

                            l = write_tcp_reply(
                                data_ptr,
                                reply_src_mac,
                                reply_dst_mac,
                                our_ip,
                                src_port,
                                their_ip,
                                dst_port,
                                isn,
                                0,
                                FLAG_SYN,
                            );
                            inc_stat!(STAT_SENT_SYN);
                            a = ROUTE_TX;
                            generated_reply = true;
                        }
                    }
                }

                if !generated_reply {
                    inc_stat!(STAT_DROP);
                    inc_stat!(STAT_TICK_DROP);
                    a = ROUTE_DROP;
                    l = 64;
                }
                (a, l)
            } else {
                //packet.parse_fast();  // is already done within the DAG by FastParser Node
                if packet.fingerprint() == Packet::TCP_OVER_IPV4 {
                    let mut p = packet.as_packet();
                    handle_tcp_packet(&mut p, pool, &local_config)
                } else {
                    inc_stat!(STAT_TO_LINUX);
                    (ROUTE_LINUX, packet.data_len())
                }
            };
            packet.set_action(action);
            processed_count += 1;
        }
        log::trace!(
            "process_batch: Finished successfully with {} packets",
            processed_count
        );
        processed_count
    }

    fn process_timers(current_tsc: u64) -> u32 {
        // Share time with process_batch
        CURRENT_TSC.set(current_tsc);

        let config = CONFIG.borrow().clone().unwrap_or_default();
        let tsc_freq = config.tsc_frequency;
        let mut frames_to_request = 0;

        if tsc_freq == 0 {
            return 0;
        }

        // =================================================================
        // 1. TIMEOUT SCAVENGER
        // =================================================================
        if let Some(timeout_millis) = config.close_timeout_millis {
            let timeout_cycles = ((timeout_millis as u128 * tsc_freq as u128) / 1000) as u64;
            let last_scan = LAST_TIMEOUT_SCAN.get();

            // Run the table scan only once every 10ms to save CPU
            if current_tsc.saturating_sub(last_scan) > (tsc_freq / 100) {
                LAST_TIMEOUT_SCAN.set(current_tsc);
                let mut pool_guard = CONNECTIONS.borrow_mut();
                let mut queue = TIMEOUT_QUEUE.borrow_mut();

                if let Some(pool) = pool_guard.as_mut() {
                    let available_capacity = queue.available_capacity();
                    if available_capacity > 0 {
                        pool.scavenge_timeouts(
                            current_tsc,
                            timeout_cycles,
                            available_capacity,
                            &mut queue,
                        );
                    }
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

            let allowed_to_send = gen.activated
                && match config.syn_limit {
                    Some(max_syns) => gen.syns_sent < max_syns || max_syns == 0,
                    None => true,
                };

            if allowed_to_send {
                if gen.last_tsc == 0 {
                    gen.last_tsc = current_tsc;
                }
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

                log::trace!(
                    "process_timers: syn_frames= {}, gen.syns_sent= {}, max_syns= {:?}",
                    syn_frames,
                    gen.syns_sent,
                    config.syn_limit
                );
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
        let mut stats = TCP_STATS.borrow().to_vec();
        // Add current pool usage to stats
        if let Some(pool) = CONNECTIONS.borrow().as_ref() {
            stats.push(pool.watermark as u64); // Current active/reused nodes
        }
        stats
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
    log::trace!(
        "handle_tcp_packet: processing packet with flow_key {:?}",
        flow_key
    );

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
        // Scope the borrow so it drops immediately after the state machine runs
        let mut stats_guard = TCP_STATS.borrow_mut();
        action_opt = run_tcp_state_machine(
            conn,
            tcp_flags,
            seq_num,
            ack_num,
            payload_len,
            &mut stats_guard,
        );
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
            let reply_ack = seq_num
                .wrapping_add(payload_len)
                .wrapping_add(if tcp_flags & FLAG_FIN != 0 { 1 } else { 0 });

            inc_stat!(STAT_SENT_RST);
            action_opt = Some((FLAG_RST | FLAG_ACK, reply_seq, reply_ack));
        } else if tcp_flags & FLAG_SYN != 0 {
            inc_stat!(STAT_RECV_SYN);
            let rcv_nxt = seq_num.wrapping_add(1);
            let initial_snd_nxt = 1000u32;
            pool.insert(
                flow_key,
                TcpState::SynReceived,
                initial_snd_nxt.wrapping_add(1),
                rcv_nxt,
                current_tsc,
            );

            inc_stat!(STAT_SENT_SYNACK);
            action_opt = Some((FLAG_SYN | FLAG_ACK, initial_snd_nxt, rcv_nxt));
        } else {
            inc_stat!(STAT_UNEXPECTED);
            let reply_seq = if tcp_flags & FLAG_ACK != 0 {
                ack_num
            } else {
                0
            };
            let reply_ack = seq_num
                .wrapping_add(payload_len)
                .wrapping_add(if tcp_flags & FLAG_FIN != 0 { 1 } else { 0 });

            inc_stat!(STAT_SENT_RST);
            action_opt = Some((FLAG_RST | FLAG_ACK, reply_seq, reply_ack));
        }
    }

    if current_state == Some(TcpState::Closed) {
        pool.remove(&flow_key);
    }

    if let Some((reply_flags, reply_seq, reply_ack)) = action_opt {
        let data_ptr = packet.data_ptr_mut();
        let reply_dst_mac = incoming_src_mac;
        let reply_src_mac = config.src_mac.unwrap_or(incoming_dst_mac);

        let len = write_tcp_reply(
            data_ptr,
            reply_src_mac,
            reply_dst_mac,
            dst_ip,
            dst_port,
            src_ip,
            src_port,
            reply_seq,
            reply_ack,
            reply_flags,
        );
        return (ROUTE_TX, len);
    }

    (ROUTE_DROP, 0)
}

// Export the implementation to the runtime
export!(TcpEngine);
