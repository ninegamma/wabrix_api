use crate::headers::check::checksum;
use crate::headers::flow::FiveTupleV4;
use crate::headers::{EndOffset, HeaderKind};
use byteorder::{BigEndian, ByteOrder};
use core::convert::From;
use core::default::Default;
use core::fmt;
use core::net::Ipv4Addr;
use core::slice;

/// IP header using SSE
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct IpHeader {
    version_to_len: u32,
    id_to_foffset: u32,
    ttl_to_csum: u32,
    src_ip: u32,
    dst_ip: u32,
}

impl fmt::Display for IpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let src = Ipv4Addr::from(self.src());
        let dst = Ipv4Addr::from(self.dst());
        write!(
            f,
            "{} > {} version: {} ihl: {} len: {} ttl: {} proto: {} csum: {}",
            src,
            dst,
            self.version(),
            self.ihl(),
            self.length(),
            self.ttl(),
            self.protocol(),
            self.csum()
        )
    }
}

impl EndOffset for IpHeader {
    #[inline]
    fn offset(&self) -> usize {
        self.ihl() as usize * 4
    }

    #[inline]
    fn size() -> usize {
        // The struct itself is always 20 bytes.
        20
    }

    #[inline]
    fn payload_size(&self, _: usize) -> usize {
        (self.length() as usize) - self.offset()
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Ip
    }
}

impl IpHeader {
    #[inline]
    pub fn flow(&self) -> Option<FiveTupleV4> {
        let protocol = self.protocol();
        let src_ip = self.src();
        let dst_ip = self.dst();
        if (protocol == 6 || protocol == 17) && self.payload_size(0) >= 4 {
            // SAFETY:
            // - `self.offset()` returns the IP header length in bytes (validated by `payload_size(0) >= 4` above).
            // - `port_as_u8` points into the L4 payload region which is at least 4 bytes long.
            // - Reading 2+2 bytes for src/dst port via `from_raw_parts` is within bounds.
            // - Using `&raw const` avoids intermediate alignment assertions.
            unsafe {
                let self_as_u8 = &raw const *self as *const u8;
                let port_as_u8 = self_as_u8.add(self.offset());
                let port_slice = slice::from_raw_parts(port_as_u8, 4);
                let src_port = BigEndian::read_u16(&port_slice[..2]);
                let dst_port = BigEndian::read_u16(&port_slice[2..]);
                Some(FiveTupleV4 {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    proto: protocol,
                })
            }
        } else {
            None
        }
    }

    #[inline]
    pub fn new() -> IpHeader {
        Default::default()
    }

    #[inline]
    pub fn src(&self) -> u32 {
        // SAFETY:
        // - Extracts the raw constant pointer to the packed field without creating an intermediate reference.
        // - Performs a safe unaligned read to prevent hardware alignment faults.
        let raw_src = unsafe { core::ptr::read_unaligned(&raw const self.src_ip) };
        u32::from_be(raw_src)
    }

    #[inline]
    pub fn set_src(&mut self, src: u32) {
        // SAFETY:
        // - Extracts the raw mutable pointer to the packed field without creating a reference.
        // - Performs a safe unaligned write directly to the memory address.
        unsafe {
            core::ptr::write_unaligned(
                &raw mut self.src_ip,
                u32::to_be(src)
            );
        }
    }

    #[inline]
    pub fn dst(&self) -> u32 {
        let raw_dst = unsafe { core::ptr::read_unaligned(&raw const self.dst_ip) };
        u32::from_be(raw_dst)
    }

    #[inline]
    pub fn set_dst(&mut self, dst: u32) {
        unsafe {
            core::ptr::write_unaligned(
                &raw mut self.dst_ip,
                u32::to_be(dst)
            );
        }
    }

    #[inline]
    pub fn ttl(&self) -> u8 {
        let ttlpcsum = unsafe { core::ptr::read_unaligned(&raw const self.ttl_to_csum) };
        (ttlpcsum & 0x000000ff) as u8
    }

    #[inline]
    pub fn set_ttl(&mut self, ttl: u8) {
        unsafe {
            let current_val = core::ptr::read_unaligned(&raw const self.ttl_to_csum);
            let blanked = current_val & !0x000000ff;
            core::ptr::write_unaligned(
                &raw mut self.ttl_to_csum,
                blanked | (ttl as u32)
            );
        }
    }

    pub fn set_src_address(&mut self, src: Ipv4Addr) {
        unsafe {
            core::ptr::write_unaligned(
                &raw mut self.src_ip,
                u32::from(src).to_be()
            );
        }
    }

    #[inline]
    pub fn set_dst_address(&mut self, dst: Ipv4Addr) {
        unsafe {
            core::ptr::write_unaligned(
                &raw mut self.dst_ip,
                u32::from(dst).to_be()
            );
        }
    }

    #[inline]
    pub fn protocol(&self) -> u8 {
        let ttlpcsum = unsafe { core::ptr::read_unaligned(&raw const self.ttl_to_csum) };
        ((ttlpcsum & 0xff00) >> 8) as u8
    }

    #[inline]
    pub fn set_protocol(&mut self, protocol: u8) {
        unsafe {
            let ttlpcsum = core::ptr::read_unaligned(&raw const self.ttl_to_csum);
            let blanked = ttlpcsum & !0xff00;
            core::ptr::write_unaligned(
                &raw mut self.ttl_to_csum,
                blanked | ((protocol as u32) << 8)
            );
        }
    }

    #[inline]
    pub fn csum(&self) -> u16 {
        let ttlpcsum = unsafe { core::ptr::read_unaligned(&raw const self.ttl_to_csum) };
        ((ttlpcsum & 0xffff0000) >> 16) as u16
    }

    #[inline]
    pub fn set_csum(&mut self, csum: u16) {
        unsafe {
            let ttlpcsum = core::ptr::read_unaligned(&raw const self.ttl_to_csum);
            let blanked = ttlpcsum & !0xffff0000;
            core::ptr::write_unaligned(
                &raw mut self.ttl_to_csum,
                blanked | ((u16::to_be(csum) as u32) << 16)
            );
        }
    }

    #[inline]
    pub fn id(&self) -> u16 {
        let id_flag_fragment = unsafe { core::ptr::read_unaligned(&raw const self.id_to_foffset) };
        u16::from_be((id_flag_fragment & 0xffff) as u16)
    }

    #[inline]
    pub fn set_id(&mut self, id: u16) {
        unsafe {
            let id_flag_fragment = core::ptr::read_unaligned(&raw const self.id_to_foffset);
            let blanked = id_flag_fragment & !0xffff;
            core::ptr::write_unaligned(
                &raw mut self.id_to_foffset,
                blanked | (u16::to_be(id) as u32)
            );
        }
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        let id_flag_fragment = unsafe { core::ptr::read_unaligned(&raw const self.id_to_foffset) };
        let flag_fragment = (id_flag_fragment >> 21) as u16;
        (flag_fragment & 0x7) as u8
    }

    #[inline]
    pub fn set_flags(&mut self, flags: u8) {
        unsafe {
            let id_flag_fragment = core::ptr::read_unaligned(&raw const self.id_to_foffset);
            let blanked = id_flag_fragment & !0x00e00000;
            core::ptr::write_unaligned(
                &raw mut self.id_to_foffset,
                blanked | (((flags & 0x7) as u32) << (16 + 5))
            );
        }
    }

    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        let id_flag_fragment = unsafe { core::ptr::read_unaligned(&raw const self.id_to_foffset) };
        let flag_fragment = (id_flag_fragment & 0xffff) as u16;
        u16::from_be(flag_fragment & !0xe >> 3)
    }

    #[inline]
    pub fn set_fragment_offset(&mut self, offset: u16) {
        let offset_correct = offset as u32;
        unsafe {
            let id_to_offset_le = u32::from_be(core::ptr::read_unaligned(&raw const self.id_to_foffset));
            let new_val = u32::to_be(id_to_offset_le & !0x1fff | offset_correct);
            core::ptr::write_unaligned(
                &raw mut self.id_to_foffset,
                new_val
            );
        }
    }

    #[inline]
    pub fn version(&self) -> u8 {
        let version_to_len = unsafe { core::ptr::read_unaligned(&raw const self.version_to_len) };
        ((version_to_len & 0xf0) as u8) >> 4
    }

    #[inline]
    pub fn set_version(&mut self, version: u8) {
        unsafe {
            let version_to_len = core::ptr::read_unaligned(&raw const self.version_to_len);
            let blanked = version_to_len & !0xf0;
            core::ptr::write_unaligned(
                &raw mut self.version_to_len,
                blanked | (((version & 0xf) as u32) << 4)
            );
        }
    }

    #[inline]
    pub fn ihl(&self) -> u8 {
        let version_to_len = unsafe { core::ptr::read_unaligned(&raw const self.version_to_len) };
        (version_to_len & 0x0f) as u8
    }

    #[inline]
    pub fn set_ihl(&mut self, ihl: u8) {
        unsafe {
            let version_to_len = core::ptr::read_unaligned(&raw const self.version_to_len);
            let blanked = version_to_len & !0x0f;
            core::ptr::write_unaligned(
                &raw mut self.version_to_len,
                blanked | ((ihl & 0x0f) as u32)
            );
        }
    }

    #[inline]
    pub fn dscp(&self) -> u8 {
        let version_to_len = unsafe { core::ptr::read_unaligned(&raw const self.version_to_len) };
        ((version_to_len & 0xfc00) >> 10) as u8
    }

    #[inline]
    pub fn set_dscp(&mut self, dscp: u8) {
        unsafe {
            let version_to_len = core::ptr::read_unaligned(&raw const self.version_to_len);
            let blanked = version_to_len & !0xfc00;
            core::ptr::write_unaligned(
                &raw mut self.version_to_len,
                blanked | (((dscp & 0x3f) as u32) << 10)
            );
        }
    }

    #[inline]
    pub fn ecn(&self) -> u8 {
        let version_to_len = unsafe { core::ptr::read_unaligned(&raw const self.version_to_len) };
        ((version_to_len & 0x0300) >> 8) as u8
    }

    #[inline]
    pub fn set_ecn(&mut self, ecn: u8) {
        unsafe {
            let version_to_len = core::ptr::read_unaligned(&raw const self.version_to_len);
            let blanked = version_to_len & !0x0300;
            core::ptr::write_unaligned(
                &raw mut self.version_to_len,
                blanked | (((ecn & 0x03) as u32) << 8)
            );
        }
    }

    #[inline]
    pub fn length(&self) -> u16 {
        let version_to_len = unsafe { core::ptr::read_unaligned(&raw const self.version_to_len) };
        u16::from_be(((version_to_len & 0xffff0000) >> 16) as u16)
    }

    #[inline]
    pub fn set_length(&mut self, len: u16) {
        unsafe {
            let version_to_len = core::ptr::read_unaligned(&raw const self.version_to_len);
            let blanked = version_to_len & !0xffff0000;
            core::ptr::write_unaligned(
                &raw mut self.version_to_len,
                blanked | ((u16::to_be(len) as u32) << 16)
            );
        }
    }

    #[inline]
    pub fn trim_length_by(&mut self, delta: u16) {
        let newlen = self.length().wrapping_sub(delta);
        self.set_length(newlen);
    }

    #[inline]
    pub fn update_checksum(&mut self) {
        // SAFETY:
        // - Using the raw const operator prevents the compiler from asserting natural alignment
        //   on the packed struct, avoiding Undefined Behavior.
        // - Casting to *const u8 and reading the exact struct size in bytes is sound
        //   because all bit patterns are valid for a byte slice.
        // - The resulting slice does not outlive the mutable reference to self.
        unsafe {
            let ptr = &raw const *self as *const u8;
            let bytes = slice::from_raw_parts(ptr, size_of::<IpHeader>());
            self.set_csum(checksum(bytes, 5));
        };
    }
}