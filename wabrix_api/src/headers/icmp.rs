use super::{EndOffset, HeaderKind};
use core::default::Default;
use core::fmt;

/// ICMP header (ICMPv4)
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct IcmpHeader {
    icmp_type: u8,
    code: u8,
    csum: u16,
    rest_of_header: u32,
}

impl fmt::Display for IcmpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_str = match self.icmp_type() {
            Self::ECHO_REPLY => "Echo Reply",
            Self::DEST_UNREACHABLE => "Destination Unreachable",
            Self::SOURCE_QUENCH => "Source Quench",
            Self::REDIRECT => "Redirect",
            Self::ECHO_REQUEST => "Echo Request",
            Self::TIME_EXCEEDED => "Time Exceeded",
            Self::PARAMETER_PROBLEM => "Parameter Problem",
            Self::TIMESTAMP_REQUEST => "Timestamp Request",
            Self::TIMESTAMP_REPLY => "Timestamp Reply",
            _ => "Unknown",
        };

        write!(
            f,
            "type: {} ({}) code: {} checksum: 0x{:04x}",
            self.icmp_type(),
            type_str,
            self.code(),
            self.checksum()
        )
    }
}

impl EndOffset for IcmpHeader {
    #[inline]
    fn offset(&self) -> usize {
        8
    }

    #[inline]
    fn size() -> usize {
        8
    }

    #[inline]
    fn payload_size(&self, hint: usize) -> usize {
        hint - self.offset()
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Icmp
    }
}

impl IcmpHeader {
    #[inline]
    pub fn new() -> IcmpHeader {
        Default::default()
    }

    #[inline]
    pub fn icmp_type(&self) -> u8 {
        // SAFETY:
        // - Extracts the raw constant pointer to the packed field without creating an intermediate reference.
        // - Performs a safe unaligned read to prevent hardware alignment faults.
        unsafe { core::ptr::read_unaligned(&raw const self.icmp_type) }
    }

    #[inline]
    pub fn set_icmp_type(&mut self, icmp_type: u8) {
        // SAFETY:
        // - Extracts the raw mutable pointer to the packed field without creating a reference.
        // - Performs a safe unaligned write directly to the memory address.
        unsafe {
            core::ptr::write_unaligned(&raw mut self.icmp_type, icmp_type);
        }
    }

    #[inline]
    pub fn code(&self) -> u8 {
        unsafe { core::ptr::read_unaligned(&raw const self.code) }
    }

    #[inline]
    pub fn set_code(&mut self, code: u8) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.code, code);
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

    #[inline]
    pub fn rest_of_header(&self) -> u32 {
        let raw_rest = unsafe { core::ptr::read_unaligned(&raw const self.rest_of_header) };
        u32::from_be(raw_rest)
    }

    #[inline]
    pub fn set_rest_of_header(&mut self, value: u32) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.rest_of_header, u32::to_be(value));
        }
    }

    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACHABLE: u8 = 3;
    pub const SOURCE_QUENCH: u8 = 4;
    pub const REDIRECT: u8 = 5;
    pub const ECHO_REQUEST: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
    pub const PARAMETER_PROBLEM: u8 = 12;
    pub const TIMESTAMP_REQUEST: u8 = 13;
    pub const TIMESTAMP_REPLY: u8 = 14;
}
