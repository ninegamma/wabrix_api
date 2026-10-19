use alloc::string::String;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};
use core::ptr;
use macaddr::MacAddr6;
use network_types::eth::EtherType;

use crate::connections::{ConnectionNode, FlowKey, TcpState};
use crate::headers::check::ipv4_checksum;
use crate::headers::{IpHeader, MacHeader, TcpHeader, UdpHeader};
use crate::helpers::update_tcp_checksum;
use crate::packet::Packet;

// Standard TCP Flags
pub const FLAG_FIN: u8 = 0x01;
pub const FLAG_SYN: u8 = 0x02;
pub const FLAG_RST: u8 = 0x04;
pub const FLAG_ACK: u8 = 0x10;

pub const PORT_START_RANGE: u16 = 10000;
pub const PORT_END_RANGE: u16 = 65535;
pub const MAX_CONNECTIONS: usize = 1_048_576;
pub const MAX_TIMEOUTS: usize = 262_144;

// Telemetry Stat Indices
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
pub const TCP_WATERMARK_INDEX: usize = STAT_COUNT;
pub const TCP_TELEMETRY_LEN: usize = STAT_COUNT + 1;

/// Stable route meanings used by native and Wasm TCP engines.
pub const TCP_ROUTE_TX: u32 = 0;
pub const TCP_ROUTE_LINUX: u32 = 1;
pub const TCP_ROUTE_DROP: u32 = 2;

/// Stable counter order for `get-telemetry()` and native telemetry mirrors.
pub const TCP_STAT_NAMES: [&str; STAT_COUNT] = [
    "sent_syn",
    "sent_synack",
    "sent_synack2",
    "sent_fin",
    "sent_fin_pssv",
    "sent_ack4fin",
    "sent_ack",
    "sent_rst",
    "recv_syn",
    "recv_synack",
    "recv_synack2",
    "recv_fin",
    "recv_fin_pssv",
    "recv_ack4fin",
    "recv_ack",
    "recv_rst",
    "unexpected",
    "recv_payload",
    "sent_payload",
    "tick_drop",
    "to_linux",
    "drop",
];

/// Builds the shared telemetry vector: all packet counters followed by the
/// connection arena high-water mark.
pub fn tcp_telemetry(stats: &[u64; STAT_COUNT], watermark: u64) -> Vec<u64> {
    let mut values = stats.to_vec();
    values.push(watermark);
    values
}

/// Common meaning of a timer request across native and Wasm engines.
///
/// The requested fields describe work before UMEM allocation. The host or
/// native frame registry fills in `allocated_frames` after allocation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EngineTimerPlan {
    pub timeout_frames: u32,
    pub packet_frames: u32,
    pub allocated_frames: u32,
    pub route: u32,
}

#[cfg(test)]
mod timer_plan_tests {
    use super::{
        tcp_telemetry, EngineTimerPlan, FlowKey, TimeoutStack, STAT_COUNT, TCP_ROUTE_DROP,
        TCP_ROUTE_LINUX, TCP_ROUTE_TX, TCP_STAT_NAMES, TCP_TELEMETRY_LEN, TCP_WATERMARK_INDEX,
    };

    #[test]
    fn timer_plan_accounts_for_requests_and_allocation() {
        let plan = EngineTimerPlan::new(12, 20, 0);
        assert_eq!(plan.requested_frames(), 32);
        assert_eq!(plan.with_allocated(7).allocated_frames, 7);
        assert_eq!(plan.route, 0);
    }

    #[test]
    fn telemetry_contract_has_stable_order_and_watermark() {
        assert_eq!(TCP_STAT_NAMES.len(), STAT_COUNT);
        assert_eq!(TCP_TELEMETRY_LEN, STAT_COUNT + 1);
        assert_eq!(TCP_WATERMARK_INDEX, STAT_COUNT);
        assert_eq!((TCP_ROUTE_TX, TCP_ROUTE_LINUX, TCP_ROUTE_DROP), (0, 1, 2));

        let stats = [7; STAT_COUNT];
        let telemetry = tcp_telemetry(&stats, 99);
        assert_eq!(telemetry.len(), TCP_TELEMETRY_LEN);
        assert_eq!(telemetry[TCP_WATERMARK_INDEX], 99);
        assert_eq!(TCP_STAT_NAMES[0], "sent_syn");
        assert_eq!(TCP_STAT_NAMES[STAT_COUNT - 1], "drop");
    }

    #[test]
    fn boxed_timeout_stack_is_heap_backed() {
        let mut stack = TimeoutStack::new_boxed();
        assert_eq!(stack.available_capacity(), super::MAX_TIMEOUTS);
        stack.push(FlowKey::empty());
        assert!(stack.pop().is_some());
    }
}

impl EngineTimerPlan {
    pub const fn new(timeout_frames: u32, packet_frames: u32, route: u32) -> Self {
        Self {
            timeout_frames,
            packet_frames,
            allocated_frames: 0,
            route,
        }
    }

    #[inline]
    pub const fn requested_frames(self) -> u32 {
        self.timeout_frames.saturating_add(self.packet_frames)
    }

    #[inline]
    pub const fn with_allocated(self, allocated_frames: u32) -> Self {
        Self {
            allocated_frames,
            ..self
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GeneratorProtocol {
    #[default]
    Syn,
    Udp,
}

impl GeneratorProtocol {
    #[inline]
    pub fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("SYN") {
            Some(Self::Syn)
        } else if value.eq_ignore_ascii_case("UDP") {
            Some(Self::Udp)
        } else {
            None
        }
    }
}

#[derive(Clone, Default)]
pub struct CommonEngineConfig {
    pub name: Option<String>,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub src_ip: Option<[u8; 4]>,
    pub dst_ip: Option<[u8; 4]>,
    pub rng_seed: Option<u32>,
    pub tsc_frequency: u64,
    pub bypass: bool,
}

#[derive(Clone, Default)]
pub struct TcpEngineConfig {
    pub common: CommonEngineConfig,
    pub generation_rate: Option<u64>,
    pub syn_limit: Option<u64>,
    pub close_timeout_millis: Option<u64>,
    /// Timeout converted to TSC cycles during configuration, not on the timer hot path.
    pub timeout_cycles: Option<u64>,
}

impl TcpEngineConfig {
    pub fn refresh_timeout_cycles(&mut self) {
        self.timeout_cycles = self.close_timeout_millis.map(|timeout_millis| {
            ((timeout_millis as u128 * self.tsc_frequency as u128) / 1_000) as u64
        });
    }
}

impl Deref for TcpEngineConfig {
    type Target = CommonEngineConfig;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for TcpEngineConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

#[derive(Clone, Default)]
pub struct GeneratorConfig {
    pub common: CommonEngineConfig,
    pub protocol: GeneratorProtocol,
    pub generation_rate: Option<u64>,
    pub generation_limit: Option<u64>,
}

impl Deref for GeneratorConfig {
    type Target = CommonEngineConfig;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for GeneratorConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

pub struct PacketGenerator {
    pub last_tsc: u64,
    pub cycle_accumulator: u64,
    pub port_counter: u16,
    pub ip_offset: u32,
    pub prng_state: u32,
    pub packets_sent: u64,
    pub activated: bool,
}

impl Default for PacketGenerator {
    fn default() -> Self {
        Self {
            last_tsc: 0,
            cycle_accumulator: 0,
            port_counter: PORT_START_RANGE,
            ip_offset: 0,
            prng_state: 1,
            packets_sent: 0,
            activated: false,
        }
    }
}

pub struct TimeoutStack {
    items: [FlowKey; MAX_TIMEOUTS],
    len: usize,
}

impl TimeoutStack {
    pub const fn new() -> Self {
        Self {
            items: [FlowKey::empty(); MAX_TIMEOUTS],
            len: 0,
        }
    }

    /// Allocates the fixed-capacity timeout storage on the heap. Native nodes
    /// use this during construction so the multi-megabyte backing array does
    /// not pass through the main thread's stack.
    pub fn new_boxed() -> alloc::boxed::Box<Self> {
        let mut boxed = alloc::boxed::Box::<Self>::new_uninit();
        unsafe {
            let ptr = boxed.as_mut_ptr();
            core::ptr::write_bytes(
                core::ptr::addr_of_mut!((*ptr).items) as *mut FlowKey,
                0,
                MAX_TIMEOUTS,
            );
            core::ptr::addr_of_mut!((*ptr).len).write(0);
            boxed.assume_init()
        }
    }

    pub fn push(&mut self, key: FlowKey) {
        if self.len < MAX_TIMEOUTS {
            self.items[self.len] = key;
            self.len += 1;
        }
    }

    pub fn pop(&mut self) -> Option<FlowKey> {
        if self.len > 0 {
            self.len -= 1;
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

    // Returns the exact number of slots currently free
    pub fn available_capacity(&self) -> usize {
        MAX_TIMEOUTS - self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for TimeoutStack {
    fn default() -> Self {
        Self::new()
    }
}

impl core::iter::Extend<FlowKey> for TimeoutStack {
    fn extend<T: IntoIterator<Item = FlowKey>>(&mut self, iter: T) {
        for key in iter {
            if self.len < MAX_TIMEOUTS {
                self.items[self.len] = key;
                self.len += 1;
            } else {
                break;
            }
        }
    }
}

/// Formats outbound Ethernet/IPv4/TCP headers directly into the frame buffer.
/// Returns the total byte length of the written headers.
///
#[allow(clippy::too_many_arguments)]
pub fn write_tcp_packet(
    packet: &mut Packet,
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
    mac.src = MacAddr6::from(src_mac);
    mac.dst = MacAddr6::from(dst_mac);
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
    tcp.set_window_size(64240);
    update_tcp_checksum(&mut tcp, 20, src_ip, dst_ip);

    packet.write_mac_ipv4_tcp_headers(&mac, &ip, &tcp)
}

/// Formats an Ethernet/IPv4/UDP packet with the supplied payload.
/// Returns the total byte length of the written packet.
#[allow(clippy::too_many_arguments)]
pub fn write_udp_packet(
    packet: &mut Packet,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    payload: &[u8],
) -> u32 {
    let mac_size = size_of::<MacHeader>();
    let ip_size = size_of::<IpHeader>();
    let udp_size = size_of::<UdpHeader>();

    let udp_len = (udp_size + payload.len()) as u16;
    let ip_len = (ip_size + udp_len as usize) as u16;

    let mut mac = MacHeader::new();
    mac.src = MacAddr6::from(src_mac);
    mac.dst = MacAddr6::from(dst_mac);
    mac.set_ethertype(EtherType::Ipv4);

    let mut ip = IpHeader::new();
    ip.set_src(src_ip);
    ip.set_dst(dst_ip);
    ip.set_ttl(64);
    ip.set_version(4);
    ip.set_protocol(17);
    ip.set_ihl(5);
    ip.set_length(ip_len);
    ip.set_flags(0x2);
    ip.update_checksum();

    let mut udp = UdpHeader::new();
    udp.set_src_port(src_port);
    udp.set_dst_port(dst_port);
    udp.set_length(udp_len);

    let header_len = packet.write_mac_ipv4_udp_headers(&mac, &ip, &udp);
    let udp_ptr = unsafe { packet.data_ptr_mut().add(mac_size + ip_size) };
    let payload_ptr = unsafe { packet.data_ptr_mut().add(header_len as usize) };

    // The frame is exclusively owned by this packet view.
    unsafe {
        ptr::copy_nonoverlapping(payload.as_ptr(), payload_ptr, payload.len());
    }

    let checksum = ipv4_checksum(udp_ptr, udp_len as usize, 3, &[], src_ip, dst_ip, 17);
    unsafe {
        (*(udp_ptr as *mut UdpHeader)).set_checksum(checksum);
    }

    let packet_len = (mac_size + ip_size + udp_len as usize) as u32;
    packet.resize_payload(packet_len);
    packet_len
}

/// RFC 793 state machine. Returns the reply flags/seq/ack on a transition that
/// requires sending a packet, or `None` to silently drop.
pub fn run_tcp_state_machine(
    conn: &mut ConnectionNode,
    tcp_flags: u8,
    seq_num: u32,
    ack_num: u32,
    payload_len: u32,
    stats: &mut [u64; STAT_COUNT],
) -> Option<(u8, u32, u32)> {
    macro_rules! inc_stat {
        ($stat:expr) => {
            stats[$stat] += 1
        };
    }
    macro_rules! reply {
        ($flags:expr) => {
            Some(($flags, conn.snd_nxt, conn.rcv_nxt))
        };
    }

    if tcp_flags & FLAG_RST != 0 {
        inc_stat!(STAT_RECV_RST);
        conn.state = TcpState::Closed;
        return None;
    }

    if tcp_flags & FLAG_FIN != 0 {
        if conn.state == TcpState::Established {
            inc_stat!(STAT_RECV_FIN_PSSV);
        } else {
            inc_stat!(STAT_RECV_FIN);
        }
    } else if tcp_flags & FLAG_SYN != 0 && tcp_flags & FLAG_ACK != 0 {
        inc_stat!(STAT_RECV_SYNACK);
    } else if payload_len > 0 {
        inc_stat!(STAT_RECV_PAYLOAD);
    } else if tcp_flags & FLAG_ACK != 0 {
        match conn.state {
            TcpState::SynReceived | TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck => {}
            _ => inc_stat!(STAT_RECV_ACK),
        }
    }

    match conn.state {
        TcpState::Listen if tcp_flags & FLAG_SYN != 0 => {
            conn.state = TcpState::SynReceived;
            conn.rcv_nxt = seq_num.wrapping_add(1);
            let send_seq = conn.snd_nxt;
            conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
            inc_stat!(STAT_SENT_SYNACK);
            return Some((FLAG_SYN | FLAG_ACK, send_seq, conn.rcv_nxt));
        }

        TcpState::SynSent
            if tcp_flags & FLAG_SYN != 0
                && tcp_flags & FLAG_ACK != 0
                && ack_num == conn.snd_nxt =>
        {
            conn.state = TcpState::Established;
            conn.rcv_nxt = seq_num.wrapping_add(1);
            inc_stat!(STAT_SENT_SYNACK2);
            return reply!(FLAG_ACK);
        }
        TcpState::SynSent if tcp_flags & FLAG_SYN != 0 && tcp_flags & FLAG_ACK != 0 => {
            inc_stat!(STAT_SENT_RST);
            return Some((FLAG_RST, ack_num, 0));
        }
        TcpState::SynSent if tcp_flags & FLAG_RST != 0 => {
            conn.state = TcpState::Closed;
        }

        TcpState::SynReceived if tcp_flags & FLAG_ACK != 0 && ack_num == conn.snd_nxt => {
            conn.state = TcpState::Established;
            inc_stat!(STAT_RECV_SYNACK2);
        }

        TcpState::Established if tcp_flags & FLAG_FIN != 0 => {
            conn.state = TcpState::LastAck;
            if seq_num == conn.rcv_nxt {
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(payload_len).wrapping_add(1);
            }
            let send_seq = conn.snd_nxt;
            conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
            inc_stat!(STAT_SENT_FIN_PSSV);
            inc_stat!(STAT_SENT_ACK4FIN);
            return Some((FLAG_FIN | FLAG_ACK, send_seq, conn.rcv_nxt));
        }
        TcpState::Established if tcp_flags & FLAG_ACK != 0 && payload_len > 0 => {
            if seq_num == conn.rcv_nxt {
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(payload_len);
            }
            inc_stat!(STAT_SENT_ACK);
            return reply!(FLAG_ACK);
        }
        TcpState::Established
            if tcp_flags & FLAG_ACK != 0 && seq_num == conn.rcv_nxt.wrapping_sub(1) =>
        {
            inc_stat!(STAT_SENT_ACK);
            return reply!(FLAG_ACK);
        }

        TcpState::FinWait2 if tcp_flags & FLAG_FIN != 0 => {
            conn.state = TcpState::Closed;
            conn.rcv_nxt = seq_num.wrapping_add(1);
            inc_stat!(STAT_SENT_ACK4FIN);
            return reply!(FLAG_ACK);
        }

        TcpState::FinWait1 if tcp_flags & FLAG_FIN != 0 => {
            if seq_num == conn.rcv_nxt {
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(payload_len).wrapping_add(1);
            }
            inc_stat!(STAT_SENT_ACK4FIN);

            if tcp_flags & FLAG_ACK != 0 && ack_num == conn.snd_nxt {
                // Client ACKed our FIN and sent theirs simultaneously
                conn.state = TcpState::Closed;
                inc_stat!(STAT_RECV_ACK4FIN);
            } else {
                conn.state = TcpState::Closing;
            }
            return reply!(FLAG_ACK);
        }
        TcpState::FinWait1 if tcp_flags & FLAG_ACK != 0 && ack_num == conn.snd_nxt => {
            conn.state = TcpState::FinWait2;
            inc_stat!(STAT_RECV_ACK4FIN);
        }

        TcpState::CloseWait if tcp_flags & FLAG_FIN != 0 => {
            // Retransmit ACK for FIN if client missed the first pure ACK
            inc_stat!(STAT_SENT_ACK4FIN);
            return reply!(FLAG_ACK);
        }

        TcpState::Closing if tcp_flags & FLAG_ACK != 0 => {
            conn.state = TcpState::Closed;
            inc_stat!(STAT_RECV_ACK4FIN);
        }

        TcpState::LastAck if tcp_flags & FLAG_ACK != 0 && ack_num == conn.snd_nxt => {
            conn.state = TcpState::Closed;
            inc_stat!(STAT_RECV_ACK4FIN);
        }

        TcpState::Closed if tcp_flags & FLAG_RST == 0 => {
            inc_stat!(STAT_SENT_RST);
            return Some((FLAG_RST, 0, seq_num.wrapping_add(payload_len)));
        }

        _ => {}
    }

    None
}
