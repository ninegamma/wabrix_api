use alloc::string::String;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};
use core::ptr;
use macaddr::MacAddr6;
use network_types::eth::EtherType;

use crate::connections::{ConnectionNode, FlowKey, TcpState};
use crate::headers::{IpHeader, MacHeader, TcpHeader, UdpHeader};
use crate::headers::check::ipv4_checksum;
use crate::helpers::update_tcp_checksum;

// Standard TCP Flags
pub const FLAG_FIN: u8 = 0x01;
pub const FLAG_SYN: u8 = 0x02;
pub const FLAG_RST: u8 = 0x04;
pub const FLAG_ACK: u8 = 0x10;

pub const PORT_START_RANGE: u16 = 10000;
pub const PORT_END_RANGE: u16 = 65535;
pub const UDP_PAYLOAD: &[u8] = b"Hello World";
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
    pub syn_rate: Option<u64>,
    pub syn_limit: Option<u64>,
    pub close_timeout_millis: Option<u64>,
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
    pub cycle_accumulator: u128,
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
/// # Safety
///
/// `data_ptr` points into the frame buffer with exclusive access granted
/// by the caller. The three header structs are local stack variables; source and
/// destination regions do not overlap. All types are `Copy` and `#[repr(C)]`.
#[allow(clippy::too_many_arguments)]
pub unsafe fn write_tcp_reply(
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
    mac.src = MacAddr6::new(
        src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
    );
    mac.dst = MacAddr6::new(
        dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
    );
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

    let mac_size = size_of::<MacHeader>();
    let ip_size = size_of::<IpHeader>();
    let tcp_size = size_of::<TcpHeader>();

    ptr::copy_nonoverlapping(&mac, data_ptr as *mut MacHeader, 1);
    ptr::copy_nonoverlapping(&ip, data_ptr.add(mac_size) as *mut IpHeader, 1);
    ptr::copy_nonoverlapping(&tcp, data_ptr.add(mac_size + ip_size) as *mut TcpHeader, 1);

    (mac_size + ip_size + tcp_size) as u32
}

/// Formats an Ethernet/IPv4/UDP packet with the fixed generator payload.
/// Returns the total byte length of the written packet.
// SAFETY: The caller guarantees that `data_ptr` points to an exclusively-owned
// frame with enough capacity for the Ethernet, IPv4, UDP, and payload bytes.
#[allow(clippy::too_many_arguments)]
pub unsafe fn write_udp_packet(
    data_ptr: *mut u8,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
) -> u32 {
    let mut mac = MacHeader::new();
    mac.src = MacAddr6::new(
        src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
    );
    mac.dst = MacAddr6::new(
        dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
    );
    mac.set_ethertype(EtherType::Ipv4);

    let udp_len = (size_of::<UdpHeader>() + UDP_PAYLOAD.len()) as u16;
    let ip_len = (size_of::<IpHeader>() + udp_len as usize) as u16;

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
    udp.set_checksum(0);

    let mac_size = size_of::<MacHeader>();
    let ip_size = size_of::<IpHeader>();
    let udp_size = size_of::<UdpHeader>();
    let udp_ptr = data_ptr.add(mac_size + ip_size);

    // SAFETY: The caller-provided frame has capacity for the exact packet;
    // the three writes target disjoint, correctly-sized regions in that frame.
    ptr::copy_nonoverlapping(&mac, data_ptr as *mut MacHeader, 1);
    ptr::copy_nonoverlapping(
        &ip,
        data_ptr.add(mac_size) as *mut IpHeader,
        1,
    );
    ptr::copy_nonoverlapping(&udp, udp_ptr as *mut UdpHeader, 1);
    ptr::copy_nonoverlapping(
        UDP_PAYLOAD.as_ptr(),
        udp_ptr.add(udp_size),
        UDP_PAYLOAD.len(),
    );

    let checksum = ipv4_checksum(udp_ptr, udp_len as usize, 3, &[], src_ip, dst_ip, 17);
    (*((udp_ptr) as *mut UdpHeader)).set_checksum(checksum);

    (mac_size + ip_size + udp_len as usize) as u32
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
