use super::{EndOffset, HeaderKind};
use core::convert::From;
use core::default::Default;
use core::fmt;
use core::net::Ipv6Addr;

/// IPv6 header structure (40 bytes fixed size)
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct Ipv6Header {
    /// Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    version_to_flow: u32,
    /// Payload Length (16 bits)
    payload_len: u16,
    /// Next Header (8 bits) - Protocol type
    next_header: u8,
    /// Hop Limit (8 bits) - Similar to TTL in IPv4
    hop_limit: u8,
    /// Source IPv6 address (128 bits / 16 bytes)
    src_ip: [u8; 16],
    /// Destination IPv6 address (128 bits / 16 bytes)
    dst_ip: [u8; 16],
}

impl fmt::Display for Ipv6Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let src = self.src();
        let dst = self.dst();
        write!(
            f,
            "{} > {} version: {} traffic_class: {} flow_label: {} payload_len: {} next_header: {} hop_limit: {}",
            src,
            dst,
            self.version(),
            self.traffic_class(),
            self.flow_label(),
            self.payload_length(),
            self.next_header(),
            self.hop_limit()
        )
    }
}

impl EndOffset for Ipv6Header {
    #[inline]
    fn offset(&self) -> usize {
        // IPv6 header is always 40 bytes (no variable length like IPv4)
        40
    }

    #[inline]
    fn size() -> usize {
        40
    }

    #[inline]
    fn payload_size(&self, _: usize) -> usize {
        self.payload_length() as usize
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Ipv6
    }
}

impl Ipv6Header {
    #[inline]
    pub fn new() -> Ipv6Header {
        let mut header = Ipv6Header::default();
        header.set_version(6);
        header
    }

    #[inline]
    pub fn version(&self) -> u8 {
        // SAFETY:
        // - Extracts the raw constant pointer to the packed field without creating an intermediate reference.
        // - Performs a safe unaligned read to prevent hardware alignment faults.
        let raw_vtf = unsafe { core::ptr::read_unaligned(&raw const self.version_to_flow) };
        (u32::from_be(raw_vtf) >> 28) as u8
    }

    #[inline]
    pub fn set_version(&mut self, version: u8) {
        // SAFETY:
        // - Extracts the raw mutable pointer to the packed field without creating a reference.
        // - Performs a safe unaligned write directly to the memory address.
        unsafe {
            let vtf = u32::from_be(core::ptr::read_unaligned(&raw const self.version_to_flow));
            let new_vtf = u32::to_be((vtf & 0x0FFFFFFF) | ((version as u32 & 0xF) << 28));
            core::ptr::write_unaligned(&raw mut self.version_to_flow, new_vtf);
        }
    }

    #[inline]
    pub fn traffic_class(&self) -> u8 {
        let raw_vtf = unsafe { core::ptr::read_unaligned(&raw const self.version_to_flow) };
        ((u32::from_be(raw_vtf) >> 20) & 0xFF) as u8
    }

    #[inline]
    pub fn set_traffic_class(&mut self, tc: u8) {
        unsafe {
            let vtf = u32::from_be(core::ptr::read_unaligned(&raw const self.version_to_flow));
            let new_vtf = u32::to_be((vtf & 0xF00FFFFF) | ((tc as u32) << 20));
            core::ptr::write_unaligned(&raw mut self.version_to_flow, new_vtf);
        }
    }

    #[inline]
    pub fn flow_label(&self) -> u32 {
        let raw_vtf = unsafe { core::ptr::read_unaligned(&raw const self.version_to_flow) };
        u32::from_be(raw_vtf) & 0x000FFFFF
    }

    #[inline]
    pub fn set_flow_label(&mut self, label: u32) {
        unsafe {
            let vtf = u32::from_be(core::ptr::read_unaligned(&raw const self.version_to_flow));
            let new_vtf = u32::to_be((vtf & 0xFFF00000) | (label & 0x000FFFFF));
            core::ptr::write_unaligned(&raw mut self.version_to_flow, new_vtf);
        }
    }

    #[inline]
    pub fn payload_length(&self) -> u16 {
        let raw_len = unsafe { core::ptr::read_unaligned(&raw const self.payload_len) };
        u16::from_be(raw_len)
    }

    #[inline]
    pub fn set_payload_length(&mut self, len: u16) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.payload_len, u16::to_be(len));
        }
    }

    #[inline]
    pub fn next_header(&self) -> u8 {
        unsafe { core::ptr::read_unaligned(&raw const self.next_header) }
    }

    #[inline]
    pub fn set_next_header(&mut self, nh: u8) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.next_header, nh);
        }
    }

    #[inline]
    pub fn hop_limit(&self) -> u8 {
        unsafe { core::ptr::read_unaligned(&raw const self.hop_limit) }
    }

    #[inline]
    pub fn set_hop_limit(&mut self, hl: u8) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.hop_limit, hl);
        }
    }

    #[inline]
    pub fn src(&self) -> Ipv6Addr {
        let raw_ip = unsafe { core::ptr::read_unaligned(&raw const self.src_ip) };
        Ipv6Addr::from(raw_ip)
    }

    #[inline]
    pub fn set_src(&mut self, addr: Ipv6Addr) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.src_ip, addr.octets());
        }
    }

    #[inline]
    pub fn dst(&self) -> Ipv6Addr {
        let raw_ip = unsafe { core::ptr::read_unaligned(&raw const self.dst_ip) };
        Ipv6Addr::from(raw_ip)
    }

    #[inline]
    pub fn set_dst(&mut self, addr: Ipv6Addr) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.dst_ip, addr.octets());
        }
    }

    #[inline]
    pub fn src_bytes(&self) -> &[u8; 16] {
        // SAFETY:
        // - Returning a reference directly to an array field within a packed struct requires caution.
        // - Callers must treat this as unaligned or copy bytes if safety guarantees are strict.
        unsafe { &*(&raw const self.src_ip) }
    }

    #[inline]
    pub fn dst_bytes(&self) -> &[u8; 16] {
        unsafe { &*(&raw const self.dst_ip) }
    }
}