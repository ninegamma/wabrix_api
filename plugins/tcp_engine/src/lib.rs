#![no_std]

pub mod connections;

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use network_types::eth::EtherType;
use macaddr::MacAddr6;

use xbricks_protocol::headers::{HeaderKind, IpHeader, MacHeader, TcpHeader};
use xbricks_protocol::headers::hstack::HeaderStack;
use xbricks_protocol::helpers::{parse_ip, parse_mac, parse_suffixed_number, update_tcp_checksum};
use xbricks_protocol::wbatch::Pdu0;
use crate::connections::{ConnectionNode, ConnectionPool, FlowKey, TcpState};
use crate::exports::xbricks::plugins::packet_engine::Guest;

// 1. Tell the macro to read the .wit file and generate the bindings
wit_bindgen::generate!({
    path: "../../wit/xbricks.wit",
    world: "engine-plugin",
});


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
}

static CONFIG: Mutex<Option<EngineConfig>> = Mutex::new(None);

struct Connection {
    state: TcpState,
    snd_nxt: u32,
    rcv_nxt: u32,
    last_active_tsc: u64, // NEW: Track idle time
}

static CONNECTIONS: Mutex<Option<ConnectionPool>> = Mutex::new(None);
// NEW: Global Time & Timeout Queues
static CURRENT_TSC: AtomicU64 = AtomicU64::new(0);
static LAST_TIMEOUT_SCAN: Mutex<u64> = Mutex::new(0);
static TIMEOUT_QUEUE: Mutex<Vec<FlowKey>> = Mutex::new(Vec::new());

const ROUTE_TX: u32 = 0;
const ROUTE_LINUX: u32 = 1;
const ROUTE_DROP: u32 = 2;

const TM_DROP: u32 = 0;
const TM_LINUX: u32 = 1;
const TM_TCP_REPLY: u32 = 2;
const TM_SYN_GEN: u32 = 3;
const TM_FIN_GEN: u32 = 4;

const PORT_START_RANGE: u16 = 10000;
const PORT_END_RANGE: u16 = 65535;

struct SynGenerator {
    last_tsc: u64,
    cycle_accumulator: u128,
    port_counter: u16,
    /// Simple seed for ISNs
    prng_state: u32,
    /// Track total SYNs generated
    syns_sent: u64,
}

static SYN_GEN: Mutex<SynGenerator> = Mutex::new(SynGenerator {
    last_tsc: 0,
    cycle_accumulator: 0,
    port_counter: PORT_START_RANGE, // Ephemeral port start range
    prng_state: 1,       // Simple seed for ISNs
    syns_sent: 0,
});


fn init_state_machine() {
    // 65536 is a good default capacity to prevent re-allocations
    *CONNECTIONS.lock() = Some(ConnectionPool::new(65536));
}

struct TcpEngine;

impl Guest for TcpEngine {
    fn init_data(data: Vec<(alloc::string::String, alloc::string::String)>, tsc_frequency:u64) {
        init_state_machine();
        let mut config = EngineConfig::default();

        for (key, value) in data {
            match key.as_str() {
                "src_mac" => config.src_mac = parse_mac(&value),
                "dst_mac" => config.dst_mac = parse_mac(&value),
                "src_ip" => config.src_ip = parse_ip(&value),
                "dst_ip" => config.dst_ip = parse_ip(&value),
                "rng_seed" => config.rng_seed = value.parse::<u32>().ok(),
                "syn_rate" => config.syn_rate = parse_suffixed_number(&value).ok(),
                "syn_limit" => config.syn_limit = value.parse::<u64>().ok(),
                "close_timeout" => config.close_timeout_millis = value.parse::<u64>().ok(),
                _ => {}
            }
        }
        config.tsc_frequency = tsc_frequency;
        *CONFIG.lock() = Some(config);
    }

    fn process_batch(mut batch_bytes: Vec<u8>, partition_offset: u32) -> (Vec<u32>, Vec<u32>) {
        let pdus = Pdu0::slice_from_bytes(&mut batch_bytes);

        let mut actions = Vec::with_capacity(pdus.len());
        let mut lengths = Vec::with_capacity(pdus.len());
        let umem_addr = (0u32).wrapping_sub(partition_offset) as usize;

        // Lock Global States ONCE per batch
        let mut connections_guard = CONNECTIONS.lock();
        let pool = connections_guard.as_mut().expect("Table uninitialized");
        let local_config = CONFIG.lock().clone().unwrap_or_default();

        for pdu in pdus.iter_mut() {
            let mut action = 0;
            let mut len = 64;
            if pdu.is_a_tick(umem_addr) {
                let mut generated_reply = false;

                // PRIORITY 1: Process Timeout Teardowns
                let pending_timeout = {
                    let mut queue = TIMEOUT_QUEUE.lock();
                    queue.pop()
                };

                if let Some(flow_key) = pending_timeout {
                    if let Some(conn) = pool.get_mut(&flow_key) {
                        let data_ptr = pdu.data_ptr(umem_addr);

                        // Extract IPs/Ports from the FlowKey.
                        // Note: Our generator uses (TheirIP, TheirPort, OurIP, OurPort)
                        len = write_tcp_reply(
                            data_ptr, &local_config,
                            flow_key.2, flow_key.3, // Our IP / Port
                            flow_key.0, flow_key.1, // Their IP / Port
                            conn.snd_nxt, conn.rcv_nxt, FLAG_FIN | FLAG_ACK
                        );

                        conn.snd_nxt = conn.snd_nxt.wrapping_add(1); // Increment for FIN flag
                        action = ROUTE_TX;
                        action |= TM_FIN_GEN << 16;
                        generated_reply = true;
                    }
                }

                // PRIORITY 2: Generate new SYNs
                if !generated_reply {
                    let syn_rate = local_config.syn_rate.unwrap_or(0);
                    if syn_rate > 0 {
                        let mut gen = SYN_GEN.lock();

                        // Check if we are still allowed to send
                        let allowed_to_send = match local_config.syn_limit {
                            Some(max_syns) => gen.syns_sent < max_syns,
                            None => true, // Infinite generation if no limit provided
                        };

                        if allowed_to_send {
                            gen.syns_sent += 1; // Increment the generated count!

                            // 1. Generate LCG Random ISN
                            gen.prng_state = gen.prng_state.wrapping_mul(1664525).wrapping_add(1013904223);
                            let isn = gen.prng_state;

                            // 2. Assign Source Port
                            let src_port = gen.port_counter;
                            gen.port_counter = if gen.port_counter >= PORT_END_RANGE { PORT_START_RANGE } else { gen.port_counter + 1 };

                            let dst_port = 80; // Target port (e.g., HTTP)
                            let our_ip = u32::from_be_bytes(local_config.src_ip.unwrap_or([0, 0, 0, 0]));
                            let their_ip = u32::from_be_bytes(local_config.dst_ip.unwrap_or([0, 0, 0, 0]));

                            let flow_key = FlowKey(their_ip, dst_port, our_ip, src_port);

                            // 3. Register state so we can handle the SYN-ACK
                            pool.insert(flow_key, TcpState::SynSent, isn.wrapping_add(1),0, CURRENT_TSC.load(Ordering::Relaxed));

                            // 4. Write the packet
                            let data_ptr = pdu.data_ptr(umem_addr) as *mut u8;
                            len = write_tcp_reply(
                                data_ptr, &local_config,
                                our_ip, src_port,
                                their_ip, dst_port,
                                isn, 0, FLAG_SYN
                            );
                            action = ROUTE_TX;
                            action |= TM_SYN_GEN << 16;
                            generated_reply = true;
                        }
                    }
                }
                // nothing generated, drop the tick
                if !generated_reply {
                    action = ROUTE_DROP;
                    action |= TM_DROP << 16;
                    len = 64;
                }
            } else if pdu.headers().fingerprint() == HeaderStack::TCP_OVER_IPV4 {
                // TCP FRAME
                (action, len) = handle_tcp_packet(pdu, pool, &local_config, umem_addr);
                action |= TM_TCP_REPLY << 16;
            } else {
                // Not TCP -> Forward to standard Linux networking stack
                action = ROUTE_LINUX;
                action |= TM_LINUX << 16;
                len = pdu.data_len();
            }
            actions.push(action);
            lengths.push(len);
        }

        (actions, lengths)
    }

    fn process_timers(current_tsc: u64) -> u32 {
        // Share time with process_batch
        CURRENT_TSC.store(current_tsc, Ordering::Relaxed);

        let config = CONFIG.lock().clone().unwrap_or_default();
        let tsc_freq = config.tsc_frequency;
        let mut frames_to_request = 0;

        if tsc_freq == 0 { return 0; }

        // =================================================================
        // 1. TIMEOUT SCAVENGER
        // =================================================================
        if let Some(timeout_millis) = config.close_timeout_millis {
            let timeout_cycles = ((timeout_millis as u128 * tsc_freq as u128)/1000) as u64;
            let mut last_scan = LAST_TIMEOUT_SCAN.lock();

            // Run the table scan only once every 20ms to save CPU
            if current_tsc.saturating_sub(*last_scan) > (tsc_freq / 50) {
                *last_scan = current_tsc;
                let mut pool_guard = CONNECTIONS.lock();
                let mut queue = TIMEOUT_QUEUE.lock();

                if let Some(pool) = pool_guard.as_mut() {
                    let timeouts= pool.scavenge_timeouts(current_tsc, timeout_cycles);
                    queue.extend(timeouts);
                }
            }
        }
        frames_to_request += TIMEOUT_QUEUE.lock().len() as u32;

        // =================================================================
        // 2. SYN GENERATOR (Your existing logic)
        // =================================================================
        let syn_rate = config.syn_rate.unwrap_or(0);
        if syn_rate > 0 {
            let mut gen = SYN_GEN.lock();

            let allowed_to_send = match config.syn_limit {
                Some(max_syns) => gen.syns_sent < max_syns,
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
                frames_to_request += syn_frames;
            }
        }

        frames_to_request
    }
}

/// Extracts protocol data, runs the state machine, and formats replies
fn handle_tcp_packet(
    pdu: &mut Pdu0,
    pool: &mut ConnectionPool,
    config: &EngineConfig,
    umem_addr: usize,
) -> (u32, u32) {
    let current_tsc = CURRENT_TSC.load(Ordering::Relaxed); // Grab the time
    let base_addr = pdu.base_addr(umem_addr);
    let headers = pdu.headers();

    // Find header indices safely
    let mut ip_idx = None;
    let mut tcp_idx = None;
    for i in 0..headers.count() {
        if headers.kinds[i] == HeaderKind::Ip { ip_idx = Some(i); }
        if headers.kinds[i] == HeaderKind::Tcp { tcp_idx = Some(i); }
    }

    let (ip_i, tcp_i) = match (ip_idx, tcp_idx) {
        (Some(i), Some(t)) => (i, t),
        _ => return (ROUTE_LINUX, pdu.data_len()), // Forward malformed/unexpected packets
    };

    let ip_hdr = headers.ip(base_addr, ip_i);
    let tcp_hdr = headers.tcp(base_addr, tcp_i);

    // Extract 4-tuple Flow ID
    let src_ip = ip_hdr.src();
    let dst_ip = ip_hdr.dst();
    let src_port = tcp_hdr.src_port();
    let dst_port = tcp_hdr.dst_port();
    let flow_key = FlowKey(src_ip, src_port, dst_ip, dst_port);

    // Extract State Machine variables
    let tcp_flags = tcp_hdr.flags();
    let seq_num = tcp_hdr.seq_num();
    let ack_num = tcp_hdr.ack_num();

    // =========================================================
    // Calculate true payload using IPv4 Total Length
    // =========================================================
    let ip_total_len = ip_hdr.length() as u32;
    let ip_hdr_len = (ip_hdr.ihl() * 4) as u32;
    let tcp_hdr_len = (tcp_hdr.data_offset() * 4) as u32;

    // The true TCP payload is the IP Total Length minus both headers.
    // This safely ignores any trailing Ethernet zero-padding! (which is counted by pdu.data_len())
    let payload_len = ip_total_len.saturating_sub(ip_hdr_len + tcp_hdr_len);

    let mut action_opt = None;
    let mut current_state = None;

    // 1. IS THIS A KNOWN CONNECTION?
    if let Some(conn) = pool.get_mut_and_touch(&flow_key, current_tsc) {
        // Yes! Run the normal state machine
        action_opt = run_tcp_state_machine(conn, tcp_flags, seq_num, ack_num, payload_len);
        current_state = Some(conn.state);

    } else {
        // NO! The connection does NOT exist in our BTreeMap.

        // Rule 1: Ignore stray RSTs
        if tcp_flags & FLAG_RST != 0 {
            return (ROUTE_DROP, 0);
        }

        // Rule 2: Accept new SYNs and create the connection!
        if tcp_flags & FLAG_SYN != 0 {
            let rcv_nxt = seq_num.wrapping_add(1);
            let initial_snd_nxt = 1000u32; // In production, generate a random ISN here!

            pool.insert(flow_key, TcpState::SynReceived, initial_snd_nxt.wrapping_add(1), rcv_nxt, current_tsc);

            // Reply with SYN-ACK
            action_opt = Some((FLAG_SYN | FLAG_ACK, initial_snd_nxt, rcv_nxt));
        } else {
            // Rule 3: Stray ACK, FIN, or Data. Send an RST, but DO NOT save state!
            // RFC 793: If incoming ACK flag is 0, reply SEQ = 0, ACK = incoming SEQ + len
            // If incoming ACK is 1, reply SEQ = incoming ACK
            let reply_seq = if tcp_flags & FLAG_ACK != 0 { ack_num } else { 0 };
            let reply_ack = seq_num.wrapping_add(payload_len).wrapping_add(
                if tcp_flags & FLAG_FIN != 0 { 1 } else { 0 }
            );

            action_opt = Some((FLAG_RST | FLAG_ACK, reply_seq, reply_ack));
        }
    }

    // 2. MEMORY CLEANUP: Delete dead connections
    if current_state == Some(TcpState::Closed) {
        pool.remove(&flow_key);
    }

    // 3. FORMAT REPLY
    if let Some((reply_flags, reply_seq, reply_ack)) = action_opt {
        let data_ptr = pdu.data_ptr(umem_addr) as *mut u8;

        let len = write_tcp_reply(
            data_ptr, config,
            dst_ip, dst_port, // New Src (Us)
            src_ip, src_port, // New Dst (Them)
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
        conn.state = TcpState::Closed;
        return None;
    }

    macro_rules! reply {
        ($flags:expr) => { Some(($flags, conn.snd_nxt, conn.rcv_nxt)) }
    }

    match conn.state {
        TcpState::Listen => {
            if tcp_flags & FLAG_SYN != 0 {
                conn.state = TcpState::SynReceived;
                conn.rcv_nxt = seq_num.wrapping_add(1);
                let send_seq = conn.snd_nxt;
                conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
                return Some((FLAG_SYN | FLAG_ACK, send_seq, conn.rcv_nxt));
            }
        }
        TcpState::SynSent => {
            if tcp_flags & FLAG_SYN != 0 && tcp_flags & FLAG_ACK != 0 {
                // The server acknowledged our SYN!
                if ack_num == conn.snd_nxt {
                    conn.state = TcpState::Established;
                    conn.rcv_nxt = seq_num.wrapping_add(1);
                    return reply!(FLAG_ACK); // Complete the 3-way handshake
                } else {
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
                return Some((FLAG_FIN | FLAG_ACK, send_seq, conn.rcv_nxt));
            } else if tcp_flags & FLAG_ACK != 0 && payload_len > 0 {
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(payload_len);
                return reply!(FLAG_ACK);
            }
        }
        TcpState::FinWait1 => {
            if tcp_flags & FLAG_FIN != 0 && tcp_flags & FLAG_ACK != 0 {
                // conn.state = TcpState::TimeWait;
                conn.state = TcpState::Closed;
                conn.rcv_nxt = seq_num.wrapping_add(1);
                return reply!(FLAG_ACK);
            } else if tcp_flags & FLAG_FIN != 0 {
                conn.state = TcpState::Closing;
                conn.rcv_nxt = seq_num.wrapping_add(1);
                return reply!(FLAG_ACK);
            } else if tcp_flags & FLAG_ACK != 0 {
                conn.state = TcpState::FinWait2;
            }
        }
        TcpState::FinWait2 => {
            if tcp_flags & FLAG_FIN != 0 {
                // conn.state = TcpState::TimeWait;
                conn.state = TcpState::Closed;
                conn.rcv_nxt = seq_num.wrapping_add(1);
                return reply!(FLAG_ACK);
            }
        }
        TcpState::Closing => {
            if tcp_flags & FLAG_ACK != 0 {
                // conn.state = TcpState::TimeWait;
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
                return Some((FLAG_RST | FLAG_ACK, 0, seq_num.wrapping_add(payload_len)));
            }
        }
        _ => {}
    }

    None
}

/// Formats the outbound headers back into WASM linear memory
fn write_tcp_reply(
    wasm_ptr: *mut u8,
    config: &EngineConfig,
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
) -> u32 {
    let mut mac = MacHeader::new();
    let sm = config.src_mac.unwrap_or([0; 6]);
    mac.src = MacAddr6::new(sm[0], sm[1], sm[2], sm[3], sm[4], sm[5]);
    let dm = config.dst_mac.unwrap_or([0xff; 6]);
    mac.dst = MacAddr6::new(dm[0], dm[1], dm[2], dm[3], dm[4], dm[5]);
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

    unsafe {
        ptr::copy_nonoverlapping(&mac, wasm_ptr as *mut MacHeader, 1);
        ptr::copy_nonoverlapping(&ip, wasm_ptr.add(mac_size) as *mut IpHeader, 1);
        ptr::copy_nonoverlapping(&tcp, wasm_ptr.add(mac_size + ip_size) as *mut TcpHeader, 1);
    }

    (mac_size + ip_size + tcp_size) as u32
}

// Export the implementation to the runtime
export!(TcpEngine);