//! Guest-local behavior for the shared-memory packet layouts.

use crate::headers::{
    ArpIpv4Header, EndOffset, Header, HeaderKind, IcmpHeader, IpHeader, Ipv6Header, MacHeader,
    TcpHeader, UdpHeader, MAC_HDR_SIZE,
};
use crate::shared_memory::{HeaderStack, Pdu0, WPdu};
use core::ptr;
// Adjust imports as needed

impl WPdu {
    pub fn new(
        desc_addr: u64,
        desc_len: u32,
        desc_options: u32,
        global_frame_idx: u32,
        frame_size_log2: u8,
        owner_id: u8,
    ) -> WPdu {
        WPdu {
            header_stack: HeaderStack::new(),
            desc_addr,
            desc_len,
            desc_options,
            global_frame_idx,
            frame_size_log2,
            owner_id,
            ..Default::default()
        }
    }
}

impl Default for WPdu {
    fn default() -> Self {
        WPdu {
            header_stack: HeaderStack::new(),
            desc_addr: 0,
            desc_len: 0,
            desc_options: 0,
            global_frame_idx: 0,
            frame_size_log2: 11, // 2^11 = 2048 (common default frame size)
            owner_id: 0,
            flags: 0,
            timer_kind: 0,
            rx_timestamp: 0,
            timestamp: 0,
        }
    }
}

impl WPdu {
    /// Helper: Get the frame size in bytes
    #[inline(always)]
    pub(crate) fn frame_size(&self) -> usize {
        1usize << self.frame_size_log2
    }

    /// Calculates the byte offset of the frame's start relative to the UMEM base.
    /// Returns a byte count (e.g., 0, 2048, 4096), NOT an array index.
    #[inline(always)]
    pub fn local_frame_offset(&self) -> usize {
        (self.desc_addr & !((1u64 << self.frame_size_log2) - 1)) as usize
    }
    #[allow(dead_code)]
    #[inline(always)]
    fn local_frame_idx(&self) -> u32 {
        (self.local_frame_offset() >> self.frame_size_log2) as u32
    }

    /// Accessors for logic compatibility
    #[inline]
    pub fn data_len(&self) -> u32 {
        self.desc_len
    }

    #[inline]
    pub fn global_frame_idx(&self) -> u32 {
        self.global_frame_idx
    }

    /// Returns the 8 bit partition ID carried by the frame token.
    #[inline]
    pub fn partition_id(&self) -> u8 {
        ((self.global_frame_idx >> 23) & 0xff) as u8
    }

    #[inline]
    pub fn owner_id(&self) -> u8 {
        self.owner_id
    }

    /// Returns the host/plugin timer classification stored in reserved padding.
    #[inline(always)]
    pub fn timer_kind(&self) -> u8 {
        self.timer_kind
    }

    /// Sets the host/plugin timer classification without changing WPdu layout.
    #[inline(always)]
    pub fn set_timer_kind(&mut self, kind: u8) {
        self.timer_kind = kind;
    }

    #[inline]
    pub fn headroom(&self) -> usize {
        (self.desc_addr - self.local_frame_offset() as u64) as usize
    }

    /// Returns a pointer to the start of the packet data in the frame.
    #[inline]
    pub fn data_ptr(&self, umem_addr: usize) -> *mut u8 {
        self.data_address(umem_addr, 0)
    }

    /// Sets the packet data length.
    /// Use this when you've written data into the frame and need to update the length.
    #[inline]
    pub fn set_data_length(&mut self, length: u32) {
        self.desc_len = length;
    }

    /// Returns a mutable pointer to the start of the packet data plus the offset argument.
    #[inline(always)]
    pub fn data_address(&self, umem_addr: usize, offset: usize) -> *mut u8 {
        // Add offset to the virtual memory pointer of the frame
        (umem_addr + self.desc_addr as usize + offset) as *mut u8
    }
    #[inline(always)]
    pub fn base_ptr(&self, umem_addr: usize) -> *mut u8 {
        (umem_addr + self.local_frame_offset()) as *mut u8
    }
    #[inline(always)]
    pub fn base_addr(&self, umem_addr: usize) -> usize {
        umem_addr + self.local_frame_offset()
    }
    #[inline(always)]
    pub fn is_a_tick(&self, umem_addr: usize) -> bool {
        // 1. Safety Guard: Ensure the frame is long enough to have an EtherType
        if self.desc_len < 14 {
            return false;
        }
        // SAFETY: The `desc_len < 14` guard above ensures at least 14 bytes are accessible.
        // `data_ptr` returns a pointer into valid WASM linear memory; offsets 12 and 13 are
        // within the checked bounds and do not alias any live reference.
        let ethertype = unsafe {
            u16::from_be_bytes([
                *self.data_ptr(umem_addr).add(12),
                *self.data_ptr(umem_addr).add(13),
            ])
        };
        // check for "Local Experimental EtherType (0x88B5)"
        ethertype == 0x88B5
    }
    #[inline]
    pub fn headers(&self) -> &HeaderStack {
        &self.header_stack
    }

    #[inline]
    pub fn headers_mut(&mut self) -> &mut HeaderStack {
        &mut self.header_stack
    }

    pub fn get_header_kind(&self, which: usize) -> HeaderKind {
        if which < self.header_stack.count() {
            self.header_stack.kinds[which]
        } else {
            HeaderKind::Null
        }
    }

    /// Returns the host-provided timestamp associated with this packet.
    #[inline(always)]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Associates a host-provided timestamp with this packet.
    #[inline(always)]
    pub fn set_timestamp(&mut self, timestamp: u64) {
        self.timestamp = timestamp;
    }

    /// Returns the hardware RX timestamp supplied by XDP metadata, or zero
    /// when the driver did not provide one.
    #[inline(always)]
    pub fn rx_timestamp(&self) -> u64 {
        self.rx_timestamp
    }

    /// Stores the hardware RX timestamp supplied by XDP metadata.
    #[inline(always)]
    pub fn set_rx_timestamp(&mut self, timestamp: u64) {
        self.rx_timestamp = timestamp;
    }

    #[inline]
    pub fn replace_header(&mut self, umem_addr: usize, which: usize, hdr: &Header) {
        // SAFETY: `pdu_header` is reconstructed from `HeaderStack` offsets that were set during
        // parsing from valid frame data. `assert_eq!` enforces type consistency so each
        // `copy_nonoverlapping` copies exactly one element of the correct type. `hdr` is a
        // caller-supplied reference; because it points to a local or caller-owned value, it
        // cannot alias the destination inside the UMEM frame.
        unsafe {
            // HeaderStack calculates headers on the fly. We get a view (pointer wrapper).
            let mut pdu_header = self.header_stack.get(self.base_addr(umem_addr), which);
            assert_eq!(hdr.kind(), pdu_header.kind());

            match pdu_header {
                Header::Null => (),
                Header::Mac(ref mut p) => {
                    ptr::copy_nonoverlapping(hdr.as_mac().unwrap() as *const MacHeader, *p, 1)
                }
                Header::Ip(ref mut p) => {
                    ptr::copy_nonoverlapping(hdr.as_ip().unwrap() as *const IpHeader, *p, 1)
                }
                Header::Ipv6(ref mut p) => {
                    ptr::copy_nonoverlapping(hdr.as_ipv6().unwrap() as *const Ipv6Header, *p, 1)
                }
                Header::Tcp(ref mut p) => {
                    ptr::copy_nonoverlapping(hdr.as_tcp().unwrap() as *const TcpHeader, *p, 1)
                }
                Header::Udp(ref mut p) => {
                    ptr::copy_nonoverlapping(hdr.as_udp().unwrap() as *const UdpHeader, *p, 1)
                }
                Header::Icmp(ref mut p) => {
                    ptr::copy_nonoverlapping(hdr.as_icmp().unwrap() as *const IcmpHeader, *p, 1)
                }
                Header::ArpIpv4(ref mut p) => ptr::copy_nonoverlapping(
                    hdr.as_arpipv4().unwrap() as *const ArpIpv4Header,
                    *p,
                    1,
                ),
            };
        }
    }

    /// Assumes an Ethernet frame and parses up to L4
    #[inline]
    pub fn parse(&mut self, umem_addr: usize) -> usize {
        // Clear any existing headers before parsing
        self.header_stack.clear();

        let l = self.data_len() as usize;
        if l < MacHeader::size() {
            return 0;
        };

        // Get pointer to the start of the buffer
        let hdr_ptr = self.data_address(umem_addr, 0) as *mut MacHeader;

        // SAFETY: `data_len() >= MacHeader::size()` was verified above, so `hdr_ptr` points
        // to at least `size_of::<MacHeader>()` valid bytes within the UMEM frame.
        // `&mut *hdr_ptr` and `&*hdr_ptr` are never used simultaneously: `mac` is a shared
        // borrow used only for dispatch, and the mutable reference is consumed by `push()`.
        unsafe {
            self.header_stack
                .push(self.base_addr(umem_addr), Header::Mac(&mut *hdr_ptr));
            let mac = &*hdr_ptr;

            match mac.etype() {
                0x0800      // IPv4
                    if l >= mac.offset() + IpHeader::size() => {
                        self.parse_ipv4(umem_addr, mac.offset());
                    }

                0x86DD      // IPv6
                    if l >= mac.offset() + Ipv6Header::size() => {
                        self.parse_ipv6(umem_addr, mac.offset());
                    }

                0x0806      // ARP
                    if l >= mac.offset() + ArpIpv4Header::size() => {
                        self.parse_arp(umem_addr, mac.offset());
                    }

                _ => {}
            }
        }
        self.header_stack.count()
    }

    /// The fixed Fast Parser. It now accounts for the headroom!
    /// Supports: IPv4, IPv6, ARP, TCP, UDP, ICMP, ICMPv6, SCTP
    #[inline]
    pub fn parse_fast(&mut self, umem_addr: usize) -> usize {
        self.header_stack.clear();
        let l = self.data_len();
        if l < MAC_HDR_SIZE as u32 {
            return 0;
        }

        // Fetch headroom once to shift all our manual offsets
        let hr = self.headroom() as u16;

        self.header_stack.kinds[0] = HeaderKind::Mac;
        self.header_stack.offsets[0] = hr;
        self.header_stack.hc = 1;

        let mac_ptr = self.data_address(umem_addr, 0) as *const MacHeader;
        // SAFETY: `l >= MAC_HDR_SIZE` was checked above, so the MAC header bytes are accessible.
        // `mac_ptr` is derived from `data_address` which adds `umem_base + desc_addr`.
        let etype = unsafe { (*mac_ptr).etype() };

        match etype {
            0x0800 => {
                // IPv4
                if l < 14 + 20 {
                    return 1;
                } // Minimum IPv4 header size

                self.header_stack.kinds[1] = HeaderKind::Ip;
                self.header_stack.offsets[1] = hr + 14;

                let ip_ptr = self.data_address(umem_addr, 14) as *const IpHeader;
                // SAFETY: `l >= 14 + 20` was checked above; both reads are within the
                // fully-accessible IPv4 header at `ip_ptr`.
                let (l4_proto, ip_len) =
                    unsafe { ((*ip_ptr).protocol(), (*ip_ptr).offset() as u16) };

                let l4_offset = 14 + ip_len;

                match l4_proto {
                    1 if l >= (l4_offset + 8) as u32 => {
                        // ICMP
                        self.header_stack.kinds[2] = HeaderKind::Icmp;
                        self.header_stack.offsets[2] = hr + l4_offset;
                        self.header_stack.hc = 3;
                    }
                    6 if l >= (l4_offset + 20) as u32 => {
                        // TCP
                        self.header_stack.kinds[2] = HeaderKind::Tcp;
                        self.header_stack.offsets[2] = hr + l4_offset;
                        self.header_stack.hc = 3;
                    }
                    17 if l >= (l4_offset + 8) as u32 => {
                        // UDP
                        self.header_stack.kinds[2] = HeaderKind::Udp;
                        self.header_stack.offsets[2] = hr + l4_offset;
                        self.header_stack.hc = 3;
                    }
                    // SCTP (132), truncated packets, and unknown protocols drop here
                    _ => {
                        self.header_stack.hc = 2;
                    }
                }
            }
            0x86DD => {
                // IPv6
                if l < 14 + 40 {
                    return 1;
                } // IPv6 header is fixed 40 bytes

                self.header_stack.kinds[1] = HeaderKind::Ipv6;
                self.header_stack.offsets[1] = hr + 14;

                let ipv6_ptr = self.data_address(umem_addr, 14) as *const Ipv6Header;
                // SAFETY: `l >= 14 + 40` was checked above; the IPv6 fixed header (40 bytes) is
                // fully accessible at offset 14.
                let next_header = unsafe { (*ipv6_ptr).next_header() };

                let l4_offset = 14 + 40; // IPv6 header is always 40 bytes (no options in base header)

                match next_header {
                    6 if l >= l4_offset + 20 => {
                        // TCP
                        self.header_stack.kinds[2] = HeaderKind::Tcp;
                        self.header_stack.offsets[2] = hr + l4_offset as u16;
                        self.header_stack.hc = 3;
                    }
                    17 if l >= l4_offset + 8 => {
                        // UDP
                        self.header_stack.kinds[2] = HeaderKind::Udp;
                        self.header_stack.offsets[2] = hr + l4_offset as u16;
                        self.header_stack.hc = 3;
                    }
                    58 if l >= l4_offset + 8 => {
                        // ICMPv6
                        self.header_stack.kinds[2] = HeaderKind::Icmp;
                        self.header_stack.offsets[2] = hr + l4_offset as u16;
                        self.header_stack.hc = 3;
                    }
                    // SCTP (132), truncated packets, and unknown protocols drop here
                    _ => {
                        self.header_stack.hc = 2;
                    }
                }
            }
            0x0806 if l >= 14 + 28 => {
                // ARP (Minimum ARP for IPv4: 28 bytes)
                self.header_stack.kinds[1] = HeaderKind::ArpIpv4;
                self.header_stack.offsets[1] = hr + 14;
                self.header_stack.hc = 2;
            }
            _ => {
                // Unknown EtherType or truncated ARP - just MAC header
            }
        }

        self.header_stack.count()
    }

    #[inline]
    fn parse_ipv4(&mut self, umem_addr: usize, offset: usize) {
        let hdr_ptr = self.data_address(umem_addr, offset) as *mut IpHeader;
        // SAFETY: The caller (`parse`) checks `l >= mac.offset() + IpHeader::size()` before
        // calling this function, so `hdr_ptr` points to at least `size_of::<IpHeader>()` valid
        // bytes. The mutable reference is used only within this block and is not aliased.
        unsafe {
            let ip = &mut *hdr_ptr;
            self.header_stack
                .push(self.base_addr(umem_addr), Header::Ip(ip));

            let next_offset = offset + ip.offset();
            match ip.protocol() {
                1 => self.parse_icmp(umem_addr, next_offset),
                6 => self.parse_tcp(umem_addr, next_offset),
                17 => self.parse_udp(umem_addr, next_offset),
                _ => {}
            }
        }
    }

    #[inline]
    fn parse_tcp(&mut self, umem_addr: usize, offset: usize) {
        let hdr = self.data_address(umem_addr, offset) as *mut TcpHeader;
        // SAFETY: All callers check that `data_len >= offset + TcpHeader::size()` before
        // calling, so `hdr` points to at least `size_of::<TcpHeader>()` valid bytes.
        unsafe {
            self.header_stack
                .push(self.base_addr(umem_addr), Header::Tcp(&mut *hdr));
        }
    }

    #[inline]
    fn parse_udp(&mut self, umem_addr: usize, offset: usize) {
        let hdr = self.data_address(umem_addr, offset) as *mut UdpHeader;
        // SAFETY: All callers check that `data_len >= offset + UdpHeader::size()` before
        // calling, so `hdr` points to at least `size_of::<UdpHeader>()` valid bytes.
        unsafe {
            self.header_stack
                .push(self.base_addr(umem_addr), Header::Udp(&mut *hdr));
        }
    }

    #[inline]
    fn parse_icmp(&mut self, umem_addr: usize, offset: usize) {
        let hdr = self.data_address(umem_addr, offset) as *mut IcmpHeader;
        // SAFETY: All callers check that `data_len >= offset + IcmpHeader::size()` before
        // calling, so `hdr` points to at least `size_of::<IcmpHeader>()` valid bytes.
        unsafe {
            self.header_stack
                .push(self.base_addr(umem_addr), Header::Icmp(&mut *hdr));
        }
    }

    #[inline]
    fn parse_arp(&mut self, umem_addr: usize, offset: usize) {
        //TODO generalize for any protocol type, not only Ipv4
        let hdr = self.data_address(umem_addr, offset) as *mut ArpIpv4Header;

        // SAFETY: The caller checks `l >= mac.offset() + ArpIpv4Header::size()` before
        // calling, so `hdr` points to at least `size_of::<ArpIpv4Header>()` valid bytes.
        // The hw_type/proto_etype check validates the ARP packet before pushing.
        unsafe {
            let arp = &mut *hdr;
            if arp.hw_type() == 1 && arp.proto_etype() == 0x0800 {
                self.header_stack
                    .push(self.base_addr(umem_addr), Header::ArpIpv4(&mut *hdr));
            }
        }
    }

    #[inline]
    fn parse_ipv6(&mut self, umem_addr: usize, offset: usize) {
        let hdr = self.data_address(umem_addr, offset) as *mut Ipv6Header;
        // SAFETY: The caller checks `l >= offset + Ipv6Header::size()` before calling, so
        // `hdr` points to at least `size_of::<Ipv6Header>()` (40) valid bytes.
        unsafe {
            self.header_stack
                .push(self.base_addr(umem_addr), Header::Ipv6(&mut *hdr));
        }
        let next_header;
        // SAFETY: Same bounds as above; reading `next_header` from an already-validated pointer.
        unsafe {
            let ipv6 = &mut *hdr;
            next_header = ipv6.next_header();
        }
        match next_header {
            6   // TCP
                if self.data_len() >= (offset + Ipv6Header::size() + TcpHeader::size()) as u32 => {
                    self.parse_tcp(umem_addr, offset + Ipv6Header::size());
                }

            17  // UDP
                if self.data_len() >= (offset + Ipv6Header::size() + UdpHeader::size()) as u32 => {
                    self.parse_udp(umem_addr, offset + Ipv6Header::size());
                }

            58  // ICMPv6
                if self.data_len() >= (offset + Ipv6Header::size() + IcmpHeader::size()) as u32 => {
                    self.parse_icmp(umem_addr, offset + Ipv6Header::size());
                }

            _ => {}
        }
    }

    /// Adds a new header onto the front of the PDU.
    ///
    /// # Safety
    /// This method assumes there is sufficient **Headroom** available in the
    /// underlying memory buffer before `header_stack.base_ptr`.
    ///
    /// Pushes a new header onto the front of the PDU.
    ///
    /// This consumes headroom, updates the descriptor address/length,
    /// and invalidates the header stack.
    pub fn push_header<T: Copy>(&mut self, umem_addr: usize, header: &T) -> anyhow::Result<()> {
        let header_size = core::mem::size_of::<T>();

        // 1. Calculate Frame Boundaries
        // frame_base is the absolute UMEM index where this frame starts
        let local_frame_base = self.local_frame_offset();

        // 2. Check Headroom
        // desc_addr is the absolute UMEM index where data currently starts.
        // We must ensure that moving back by header_size doesn't cross the frame boundary.
        //trace!("Pdu::push_header: desc_addr = {:#x}, frame_base = {:#x}, header_size = {:#x}", self.desc_addr, frame_base, header_size);
        if self.desc_addr < local_frame_base as u64 + header_size as u64 {
            return Err(anyhow::anyhow!("Insufficient headroom to push header"));
        }

        // 3. Calculate New Absolute Address
        let new_desc_addr = self.desc_addr - header_size as u64;

        // SAFETY: The headroom check above (`desc_addr >= local_frame_base + header_size`) proves
        // there are at least `header_size` writable bytes before the current data start within
        // the frame. `header` is a valid `&T` reference on the caller's stack; casting to
        // `*const u8` and copying `size_of::<T>()` bytes is sound for any `Copy + Sized` type.
        // Source (stack) and destination (UMEM frame) do not overlap.
        unsafe {
            let dst_addr = umem_addr + new_desc_addr as usize;
            ptr::copy_nonoverlapping(
                header as *const T as *const u8,
                dst_addr as *mut u8,
                header_size,
            );
        }

        // 6. Update PDU State
        self.desc_addr = new_desc_addr;
        self.desc_len += header_size as u32;

        // 7. Invalidate Parsed Headers
        // The offsets in HeaderStack are no longer valid because we changed
        // the structure of the packet.
        self.header_stack.clear();

        Ok(())
    }

    #[inline]
    pub fn is_ipv4(&self) -> bool {
        (0..self.header_stack.count()).any(|i| self.header_stack.kinds[i] == HeaderKind::Ip)
    }

    #[inline]
    pub fn is_tcp(&self) -> bool {
        (0..self.header_stack.count()).any(|i| self.header_stack.kinds[i] == HeaderKind::Tcp)
    }

    #[inline]
    pub fn is_udp(&self) -> bool {
        (0..self.header_stack.count()).any(|i| self.header_stack.kinds[i] == HeaderKind::Udp)
    }

    #[inline]
    pub fn is_icmp(&self) -> bool {
        (0..self.header_stack.count()).any(|i| self.header_stack.kinds[i] == HeaderKind::Icmp)
    }

    #[inline]
    pub fn is_arp_ipv4(&self) -> bool {
        (0..self.header_stack.count()).any(|i| self.header_stack.kinds[i] == HeaderKind::ArpIpv4)
    }

    #[inline]
    pub fn is_ipv6(&self) -> bool {
        (0..self.header_stack.count()).any(|i| self.header_stack.kinds[i] == HeaderKind::Ipv6)
    }

    /// Gibt den Typ des obersten (letzten) Headers zurück
    #[inline]
    pub fn top_header_kind(&self) -> HeaderKind {
        let count = self.header_stack.count();
        if count == 0 {
            HeaderKind::Null
        } else {
            self.header_stack.kinds[count - 1]
        }
    }

    /// Get the EtherType from the MAC header (if present)
    #[inline]
    pub fn ether_type(&self, umem_addr: usize) -> u16 {
        let base_addr = self.base_addr(umem_addr);
        for i in 0..self.header_stack.count() {
            if self.header_stack.get(base_addr, i).kind() == HeaderKind::Mac {
                return self.header_stack.mac(base_addr, i).etype();
            }
        }
        0 // Return 0 if no MAC header found
    }

    /// Get the IPv4 source address (if present)
    #[inline]
    pub fn ipv4_src(&self, umem_addr: usize) -> Option<u32> {
        for i in 0..self.header_stack.count() {
            if self.header_stack.get(self.base_addr(umem_addr), i).kind() == HeaderKind::Ip {
                return Some(self.header_stack.ip(self.base_addr(umem_addr), i).src());
            }
        }
        None
    }
    #[inline]
    fn payload_bounds(&self, umem_addr: usize) -> Option<(usize, usize)> {
        let count = self.header_stack.count();
        if count == 0 {
            return None; // No headers parsed, so the payload boundary is unknown
        }

        let base_addr = self.base_addr(umem_addr);
        let last_idx = count - 1;

        // Retrieve the last parsed header
        let last_header = self.header_stack.get(base_addr, last_idx);

        // Determine the byte size of the last header using the offset trait/method.
        let last_header_size = last_header.offset().unwrap_or(0);

        // Calculate absolute bounds relative to base_addr
        let last_offset = self.header_stack.offsets[last_idx] as usize;
        let payload_start = last_offset + last_header_size;

        // Data boundaries
        let data_end_offset = self.headroom() + self.desc_len as usize;

        // Bounds check to ensure the payload doesn't exceed the frame data
        if payload_start <= data_end_offset {
            let payload_len = data_end_offset - payload_start;
            Some((payload_start, payload_len))
        } else {
            None
        }
    }

    /// Returns a slice to the payload data following the last parsed header.
    #[inline]
    pub fn payload(&self, umem_addr: usize) -> Option<&[u8]> {
        let base_addr = self.base_addr(umem_addr);
        if let Some((payload_start, payload_len)) = self.payload_bounds(umem_addr) {
            let payload_ptr = (base_addr + payload_start) as *const u8;

            // SAFETY: payload_start and payload_len are bounds-checked against the PDU's
            // verified total data length (desc_len) and headroom.
            Some(unsafe { core::slice::from_raw_parts(payload_ptr, payload_len) })
        } else {
            None
        }
    }

    /// Returns a mutable slice to the payload data following the last parsed header.
    #[inline]
    pub fn payload_mut(&mut self, umem_addr: usize) -> Option<&mut [u8]> {
        let base_addr = self.base_addr(umem_addr);
        if let Some((payload_start, payload_len)) = self.payload_bounds(umem_addr) {
            let payload_ptr = (base_addr + payload_start) as *mut u8;

            // SAFETY: Bounds are verified against the PDU data boundaries.
            // Exclusive mutable access is guaranteed by taking `&mut self`.
            Some(unsafe { core::slice::from_raw_parts_mut(payload_ptr, payload_len) })
        } else {
            None
        }
    }
}

// This lets you call `packet.parse_fast()` directly on Pdu0 in Wasm!
impl core::ops::Deref for Pdu0 {
    type Target = WPdu;
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.w
    }
}

impl core::ops::DerefMut for Pdu0 {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.w
    }
}

impl Drop for Pdu0 {
    fn drop(&mut self) {
        // If a Wasm developer lets a Pdu0 fall out of scope, the plugin will
        // instantly trap and print this exact error to the Host logs!
        panic!(
            "FATAL: Pdu0 dropped inside Wasm! \
            All packets must be explicitly pushed to a WBatch and returned to the Host."
        );
    }
}
/*
impl Pdu0 {
    #[inline]
    pub fn slice_from_bytes(bytes: &mut [u8]) -> &mut [Self] {
        let count = bytes.len() / core::mem::size_of::<Self>();
        // SAFETY: `bytes` is an exclusively-held `&mut [u8]`, so the pointer is valid and
        // uniquely owned. `count` is rounded down to whole `Pdu0` structs, so we never read
        // past the slice end. `Pdu0` is `#[repr(C, align(64))]`; the caller must ensure the
        // buffer is 64-byte aligned (guaranteed by the host WASM ABI).
        unsafe { core::slice::from_raw_parts_mut(bytes.as_mut_ptr() as *mut Self, count) }
    }

    /// Returns a mutable slice to the packet data.
    /// `offset` is the positive UMEM offset provided by the host.
    ///
    /// # Safety
    /// The caller must ensure `offset` is the exact `umem_offset` received from the host
    /// ABI (i.e., `umem_base = offset`). The resulting slice covers the
    /// full frame (`frame_size()` bytes) starting at `desc_addr`; the caller must not create
    /// overlapping mutable slices into the same frame.
    #[inline(always)]
    pub unsafe fn data_mut(&mut self, offset: u32) -> &mut [u8] {
        let umem_addr = offset as usize;
        let ptr = self.w.data_ptr(umem_addr);
        // SAFETY: `ptr` is `umem_base + desc_addr` — a valid address within the WASM linear
        // memory region for this frame. `frame_size()` is the pre-allocated frame capacity;
        // the contract from `data_mut`'s caller guarantees no aliasing mutable reference.
        core::slice::from_raw_parts_mut(ptr, self.frame_size())
    }

    /// Serializes fully formed MAC, IPv4, and TCP headers into Wasm linear memory.
    /// Returns the total length of the written headers.
    #[inline(always)]
    pub fn write_tcp_ipv4_headers(
        &mut self,
        mac: &MacHeader,
        ip: &IpHeader,
        tcp: &TcpHeader,
        umem_offset: u32,
    ) -> u32 {
        // SAFETY: `umem_offset` comes directly from the host ABI; `data_mut` is called
        // once and its result is used exclusively within this function — no other reference
        // to the same frame is live concurrently.
        let data = unsafe { self.data_mut(umem_offset) };

        let mac_len = core::mem::size_of::<MacHeader>();
        let ip_len = core::mem::size_of::<IpHeader>();
        let tcp_len = core::mem::size_of::<TcpHeader>();

        // SAFETY: `mac`, `ip`, and `tcp` are valid references to `#[repr(C)]` Copy types on
        // the caller's stack. Casting to `*const u8` and reading `size_of::<T>()` bytes is
        // sound because all bit patterns are valid for byte slices. Source (stack) and
        // destination (WASM linear memory) do not overlap.
        unsafe {
            let mac_bytes = core::slice::from_raw_parts(mac as *const _ as *const u8, mac_len);
            let ip_bytes = core::slice::from_raw_parts(ip as *const _ as *const u8, ip_len);
            let tcp_bytes = core::slice::from_raw_parts(tcp as *const _ as *const u8, tcp_len);

            data[0..mac_len].copy_from_slice(mac_bytes);
            data[mac_len..mac_len + ip_len].copy_from_slice(ip_bytes);
            data[mac_len + ip_len..mac_len + ip_len + tcp_len].copy_from_slice(tcp_bytes);
        }

        (mac_len + ip_len + tcp_len) as u32
    }
}
*/
const _: () = assert!(size_of::<Pdu0>() == 64);
