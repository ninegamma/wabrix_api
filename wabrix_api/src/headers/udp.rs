use super::{EndOffset, HeaderKind};
use core::default::Default;
use core::fmt;

/// UDP header using SSE
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    len: u16,
    csum: u16,
}

impl fmt::Display for UdpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "src_port: {} dst_port: {} len: {} checksum: {}",
            self.src_port(),
            self.dst_port(),
            self.length(),
            self.checksum()
        )
    }
}

impl EndOffset for UdpHeader {
    #[inline]
    fn offset(&self) -> usize {
        8
    }

    #[inline]
    fn size() -> usize {
        8
    }

    #[inline]
    fn payload_size(&self, _: usize) -> usize {
        self.length() as usize - self.offset()
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Udp
    }
}

impl UdpHeader {
    #[inline]
    pub fn new() -> UdpHeader {
        Default::default()
    }

    #[inline]
    pub fn src_port(&self) -> u16 {
        // SAFETY:
        // - Extracts the raw constant pointer to the packed field without creating an intermediate reference.
        // - Performs a safe unaligned read to prevent hardware alignment faults.
        let raw_port = unsafe { core::ptr::read_unaligned(&raw const self.src_port) };
        u16::from_be(raw_port)
    }

    #[inline]
    pub fn dst_port(&self) -> u16 {
        let raw_port = unsafe { core::ptr::read_unaligned(&raw const self.dst_port) };
        u16::from_be(raw_port)
    }

    #[inline]
    pub fn set_src_port(&mut self, port: u16) {
        // SAFETY:
        // - Extracts the raw mutable pointer to the packed field without creating a reference.
        // - Performs a safe unaligned write directly to the memory address.
        unsafe {
            core::ptr::write_unaligned(&raw mut self.src_port, u16::to_be(port));
        }
    }

    #[inline]
    pub fn set_dst_port(&mut self, port: u16) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.dst_port, u16::to_be(port));
        }
    }

    #[inline]
    pub fn length(&self) -> u16 {
        let raw_len = unsafe { core::ptr::read_unaligned(&raw const self.len) };
        u16::from_be(raw_len)
    }

    #[inline]
    pub fn set_length(&mut self, len: u16) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.len, u16::to_be(len));
        }
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        let raw_csum = unsafe { core::ptr::read_unaligned(&raw const self.csum) };
        u16::from_be(raw_csum)
    }

    #[inline]
    pub fn set_checksum(&mut self, csum: u16) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.csum, u16::to_be(csum));
        }
    }
}