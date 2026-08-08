use crate::headers::{
    ArpIpv4Header, HeaderKind, IcmpHeader, IpHeader, Ipv6Header, MacHeader, TcpHeader, UdpHeader,
};
use crate::hstack::HeaderStack;
use crate::umem;
use core::marker::PhantomData;

const HEADER_STACK_OFFSET: u32 = 0;
const DESC_ADDR_OFFSET: u32 = 16;
const DESC_LEN_OFFSET: u32 = 24;
const FRAME_SIZE_LOG2_OFFSET: u32 = 36;

/// Offset-backed packet view. UMEM values are copied only into fixed-size stack values.
pub struct Packet<'a> {
    pdu_offset: u32,
    heap_backed: bool,
    _exclusive: PhantomData<&'a mut ()>,
}

impl<'a> Packet<'a> {
    pub const TCP_OVER_IPV4: u32 =
        (HeaderKind::Mac as u32) | ((HeaderKind::Ip as u32) << 4) | ((HeaderKind::Tcp as u32) << 8);

    #[inline(always)]
    pub(crate) fn from_offset(pdu_offset: u32) -> Self {
        Self {
            pdu_offset,
            heap_backed: false,
            _exclusive: PhantomData,
        }
    }

    #[inline(always)]
    fn read_pdu<T: Copy>(&self, field_offset: u32) -> T {
        // SAFETY: `pdu_offset` identifies an initialized mailbox PDU and every caller uses
        // a field offset and type matching the stable `Pdu0`/`WPdu` C layout.
        unsafe {
            let offset = self.pdu_offset + field_offset;
            if self.heap_backed {
                (offset as usize as *const T).read_unaligned()
            } else {
                umem::read(offset)
            }
        }
    }

    #[inline(always)]
    fn write_pdu<T: Copy>(&mut self, field_offset: u32, value: &T) {
        // SAFETY: This packet exclusively owns its mailbox slot for `'a`.
        unsafe {
            let offset = self.pdu_offset + field_offset;
            if self.heap_backed {
                (offset as usize as *mut T).write_unaligned(*value)
            } else {
                umem::write(offset, value)
            }
        }
    }

    #[inline(always)]
    fn desc_addr(&self) -> u64 {
        self.read_pdu(DESC_ADDR_OFFSET)
    }

    #[inline(always)]
    fn frame_size_log2(&self) -> u8 {
        self.read_pdu(FRAME_SIZE_LOG2_OFFSET)
    }

    #[inline(always)]
    fn frame_base(&self) -> u32 {
        let log2 = self.frame_size_log2();
        (self.desc_addr() & !((1u64 << log2) - 1)) as u32
    }

    #[inline(always)]
    fn header_stack_value(&self) -> HeaderStack {
        self.read_pdu(HEADER_STACK_OFFSET)
    }

    #[inline(always)]
    fn header_offset(&self, kind: HeaderKind, reverse: bool) -> Option<u32> {
        let stack = self.header_stack_value();
        if reverse {
            (0..stack.count())
                .rev()
                .find(|&i| stack.kinds[i] == kind)
                .map(|i| self.frame_base() + stack.offsets[i] as u32)
        } else {
            (0..stack.count())
                .find(|&i| stack.kinds[i] == kind)
                .map(|i| self.frame_base() + stack.offsets[i] as u32)
        }
    }

    #[inline(always)]
    fn read_header<T: Copy>(&self, kind: HeaderKind, reverse: bool) -> Option<T> {
        let offset = self.header_offset(kind, reverse)?;
        // SAFETY: HeaderStack was populated by the host parser and identifies a complete header.
        Some(unsafe {
            if self.heap_backed {
                (offset as usize as *const T).read_unaligned()
            } else {
                umem::read(offset)
            }
        })
    }

    #[inline(always)]
    fn write_header<T: Copy>(&mut self, kind: HeaderKind, reverse: bool, value: &T) -> bool {
        let Some(offset) = self.header_offset(kind, reverse) else {
            return false;
        };
        // SAFETY: The header offset and type correspond to `kind`; this packet is exclusive.
        unsafe {
            if self.heap_backed {
                (offset as usize as *mut T).write_unaligned(*value)
            } else {
                umem::write(offset, value)
            }
        };
        true
    }

    #[inline(always)]
    pub fn headers(&self) -> HeaderStack {
        self.header_stack_value()
    }

    #[inline(always)]
    pub fn fingerprint(&self) -> u32 {
        self.header_stack_value().fingerprint()
    }

    #[inline(always)]
    pub fn data_len(&self) -> u32 {
        self.read_pdu(DESC_LEN_OFFSET)
    }

    #[inline(always)]
    pub fn resize_payload(&mut self, new_len: u32) -> &mut Self {
        self.write_pdu(DESC_LEN_OFFSET, &new_len);
        self
    }

    #[inline(always)]
    pub fn headroom(&self) -> usize {
        (self.desc_addr() as u32 - self.frame_base()) as usize
    }

    #[inline(always)]
    pub fn is_a_tick(&self) -> bool {
        if self.data_len() < core::mem::size_of::<MacHeader>() as u32 {
            return false;
        }

        let offset = self.desc_addr() as u32;
        // Tick PDUs do not pass through FastParserNode, so their HeaderStack is empty.
        // Read the Ethernet header directly from the frame, matching WPdu::is_a_tick().
        let mac = unsafe {
            if self.heap_backed {
                (offset as usize as *const MacHeader).read_unaligned()
            } else {
                umem::read(offset)
            }
        };
        mac.etype() == 0x88B5
    }

    pub fn mac_header(&self) -> Option<MacHeader> {
        self.read_header(HeaderKind::Mac, false)
    }
    pub fn ipv4_header(&self) -> Option<IpHeader> {
        self.read_header(HeaderKind::Ip, false)
    }
    pub fn ipv6_header(&self) -> Option<Ipv6Header> {
        self.read_header(HeaderKind::Ipv6, false)
    }
    pub fn tcp_header(&self) -> Option<TcpHeader> {
        self.read_header(HeaderKind::Tcp, true)
    }
    pub fn udp_header(&self) -> Option<UdpHeader> {
        self.read_header(HeaderKind::Udp, true)
    }
    pub fn icmp_header(&self) -> Option<IcmpHeader> {
        self.read_header(HeaderKind::Icmp, true)
    }
    pub fn arp_header(&self) -> Option<ArpIpv4Header> {
        self.read_header(HeaderKind::ArpIpv4, false)
    }

    pub fn write_mac_header(&mut self, value: &MacHeader) -> bool {
        self.write_header(HeaderKind::Mac, false, value)
    }
    pub fn write_ipv4_header(&mut self, value: &IpHeader) -> bool {
        self.write_header(HeaderKind::Ip, false, value)
    }
    pub fn write_ipv6_header(&mut self, value: &Ipv6Header) -> bool {
        self.write_header(HeaderKind::Ipv6, false, value)
    }
    pub fn write_tcp_header(&mut self, value: &TcpHeader) -> bool {
        self.write_header(HeaderKind::Tcp, true, value)
    }
    pub fn write_udp_header(&mut self, value: &UdpHeader) -> bool {
        self.write_header(HeaderKind::Udp, true, value)
    }
    pub fn write_icmp_header(&mut self, value: &IcmpHeader) -> bool {
        self.write_header(HeaderKind::Icmp, true, value)
    }
    pub fn write_arp_header(&mut self, value: &ArpIpv4Header) -> bool {
        self.write_header(HeaderKind::ArpIpv4, false, value)
    }

    #[inline(always)]
    pub fn write_bytes(&mut self, relative_offset: u32, bytes: &[u8]) {
        // SAFETY: The caller supplies bytes within the frame; source is a live Memory-0 slice.
        unsafe {
            let offset = self.desc_addr() as u32 + relative_offset;
            if self.heap_backed {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    offset as usize as *mut u8,
                    bytes.len(),
                )
            } else {
                umem::copy_to(offset, bytes.as_ptr(), bytes.len())
            }
        }
    }

    pub fn contains(&self, needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        let len = self.data_len() as usize;
        if needle.len() > len {
            return false;
        }
        let mut window = [0u8; 256];
        if needle.len() > window.len() {
            return false;
        }
        let mut offset = 0usize;
        while offset < len {
            let overlap = needle.len().saturating_sub(1);
            let count = core::cmp::min(window.len(), len - offset);
            unsafe {
                let src = self.desc_addr() as u32 + offset as u32;
                if self.heap_backed {
                    core::ptr::copy_nonoverlapping(
                        src as usize as *const u8,
                        window.as_mut_ptr(),
                        count,
                    )
                } else {
                    umem::copy_from(window.as_mut_ptr(), src, count)
                }
            }
            if window[..count]
                .windows(needle.len())
                .any(|part| part == needle)
            {
                return true;
            }
            if count == len - offset {
                break;
            }
            offset += count - overlap;
        }
        false
    }

    pub fn write_tcp_ipv4_headers(
        &mut self,
        mac: &MacHeader,
        ip: &IpHeader,
        tcp: &TcpHeader,
    ) -> u32 {
        let mac_len = core::mem::size_of::<MacHeader>();
        let ip_len = core::mem::size_of::<IpHeader>();
        self.write_bytes(0, unsafe {
            core::slice::from_raw_parts(mac as *const _ as *const u8, mac_len)
        });
        self.write_bytes(mac_len as u32, unsafe {
            core::slice::from_raw_parts(ip as *const _ as *const u8, ip_len)
        });
        self.write_bytes((mac_len + ip_len) as u32, unsafe {
            core::slice::from_raw_parts(
                tcp as *const _ as *const u8,
                core::mem::size_of::<TcpHeader>(),
            )
        });
        (mac_len + ip_len + core::mem::size_of::<TcpHeader>()) as u32
    }
}

pub struct PacketBatch<'a> {
    pdu_base: u32,
    len: usize,
    heap_backed: bool,
    _exclusive: PhantomData<&'a mut ()>,
}

impl<'a> PacketBatch<'a> {
    pub fn new(batch_bytes: &'a mut [u8]) -> Self {
        Self {
            pdu_base: batch_bytes.as_mut_ptr() as usize as u32,
            len: batch_bytes.len() / 64,
            heap_backed: true,
            _exclusive: PhantomData,
        }
    }
    #[inline(always)]
    pub(crate) unsafe fn from_packet_memory(batch_size: usize, pdu_offset: u32) -> Self {
        Self {
            pdu_base: pdu_offset,
            len: batch_size,
            heap_backed: false,
            _exclusive: PhantomData,
        }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn iter_mut(&mut self) -> PacketBatchIter<'_> {
        PacketBatchIter {
            next_offset: self.pdu_base,
            remaining: self.len,
            heap_backed: self.heap_backed,
            _exclusive: PhantomData,
        }
    }
}

pub struct PacketBatchIter<'a> {
    next_offset: u32,
    remaining: usize,
    heap_backed: bool,
    _exclusive: PhantomData<&'a mut ()>,
}

impl<'a> Iterator for PacketBatchIter<'a> {
    type Item = Packet<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let offset = self.next_offset;
        self.next_offset += core::mem::size_of::<crate::exports::Pdu0>() as u32;
        self.remaining -= 1;
        let mut packet = Packet::from_offset(offset);
        packet.heap_backed = self.heap_backed;
        Some(packet)
    }
}
