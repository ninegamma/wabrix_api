use super::{EndOffset, HeaderKind};
use core::default::Default;
use core::fmt;
use macaddr::MacAddr6 as MacAddress;
use network_types::eth::EtherType;

/// A packet's MAC header.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C, packed)]
pub struct MacHeader {
    pub dst: MacAddress,
    pub src: MacAddress,
    etype: u16,
}

impl fmt::Display for MacHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SAFETY:
        // - Extracts the raw constant pointers without creating intermediate references.
        // - Performs safe unaligned reads to prevent hardware alignment faults.
        let src = unsafe { core::ptr::read_unaligned(&raw const self.src) };
        let dst = unsafe { core::ptr::read_unaligned(&raw const self.dst) };

        write!(f, "{} > {} 0x{:04x}", src, dst, self.etype())
    }
}

pub const MAC_HDR_SIZE: usize = 14;
pub const HDR_SIZE_802_1Q: usize = MAC_HDR_SIZE + 4;
pub const HDR_SIZE_802_1AD: usize = HDR_SIZE_802_1Q + 4;

impl EndOffset for MacHeader {
    #[inline]
    fn offset(&self) -> usize {
        match self.etype() {
            0x8100 => HDR_SIZE_802_1Q,
            0x9100 => HDR_SIZE_802_1AD,
            _ => MAC_HDR_SIZE,
        }
    }
    #[inline]
    fn size() -> usize {
        MAC_HDR_SIZE
    }

    #[inline]
    fn payload_size(&self, hint: usize) -> usize {
        hint - self.offset()
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Mac
    }
}

impl MacHeader {
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn src(&self) -> MacAddress {
        // SAFETY:
        // - Extracts the raw constant pointer to the packed field without creating an intermediate reference.
        // - Performs a safe unaligned read to prevent hardware alignment faults.
        unsafe { core::ptr::read_unaligned(&raw const self.src) }
    }

    #[inline]
    pub fn dst(&self) -> MacAddress {
        unsafe { core::ptr::read_unaligned(&raw const self.dst) }
    }

    #[inline]
    pub fn etype(&self) -> u16 {
        let raw_etype = unsafe { core::ptr::read_unaligned(&raw const self.etype) };
        u16::from_be(raw_etype)
    }

    #[inline]
    pub fn set_etype(&mut self, etype: u16) {
        // SAFETY:
        // - Extracts the raw mutable pointer to the packed field without creating a reference.
        // - Performs a safe unaligned write directly to the memory address.
        unsafe {
            core::ptr::write_unaligned(&raw mut self.etype, u16::to_be(etype));
        }
    }

    #[inline]
    pub fn set_ethertype(&mut self, ethertype: EtherType) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.etype, ethertype as u16);
        }
    }

    #[inline]
    pub fn swap_addresses(&mut self) {
        // SAFETY:
        // - core::mem::swap requires mutable references, which triggers UB on packed fields.
        // - Performing unaligned reads and writes manually bypasses the reference requirement.
        unsafe {
            let temp_src = core::ptr::read_unaligned(&raw const self.src);
            let temp_dst = core::ptr::read_unaligned(&raw const self.dst);
            core::ptr::write_unaligned(&raw mut self.src, temp_dst);
            core::ptr::write_unaligned(&raw mut self.dst, temp_src);
        }
    }

    pub fn set_dmac(&mut self, dmac: &MacAddress) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.dst, *dmac);
        }
    }

    pub fn set_smac(&mut self, smac: &MacAddress) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.src, *smac);
        }
    }
}
