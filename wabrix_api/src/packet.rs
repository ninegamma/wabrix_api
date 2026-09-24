use crate::exports::Pdu0;
use crate::headers::{
    ArpIpv4Header, HeaderKind, IcmpHeader, IpHeader, Ipv6Header, MacHeader, TcpHeader, UdpHeader,
};
use crate::hstack::HeaderStack;
use core::slice;

/// The safe, high-level interface for a single packet.
pub struct Packet<'a> {
    pdu: &'a mut Pdu0,
    umem_base: usize,
}

impl<'a> Packet<'a> {
    /// if headers().fingerprint() == TCP_OVER_IPV4 { ... }
    pub const TCP_OVER_IPV4: u32 =
        (HeaderKind::Mac as u32) | ((HeaderKind::Ip as u32) << 4) | ((HeaderKind::Tcp as u32) << 8);

    /// Internal constructor.
    #[inline(always)]
    pub fn new(pdu: &'a mut Pdu0, umem_base: usize) -> Self {
        Self { pdu, umem_base }
    }

    // Now, all API methods drop the `umem_addr` parameter!

    #[inline]
    pub fn parse_fast(&mut self) -> usize {
        self.pdu.parse_fast(self.umem_base)
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        // SAFETY: `data_ptr` returns `umem_base + desc_addr`, a pointer into the WASM linear
        // memory region backing this packet. `data_len()` is the byte count set by the host
        // and is guaranteed to fit within the frame. The slice lifetime is tied to `&self`,
        // so no mutable alias to the same region can exist concurrently.
        unsafe {
            core::slice::from_raw_parts(
                self.pdu.data_ptr(self.umem_base),
                self.pdu.data_len() as usize,
            )
        }
    }

    #[inline]
    pub fn headroom(&self) -> usize {
        self.pdu.headroom()
    }

    #[inline]
    pub fn headers(&self) -> &HeaderStack {
        &self.pdu.header_stack
    }

    /// Pushes a new header. Returns Result to allow graceful error handling.
    #[inline]
    pub fn push_header<T: Copy>(&mut self, header: &T) -> anyhow::Result<&mut Self> {
        self.pdu.push_header(self.umem_base, header)?;
        Ok(self)
    }

    /// Truncates or expands the packet payload
    #[inline]
    pub fn resize_payload(&mut self, new_len: u32) -> &mut Self {
        self.pdu.set_data_length(new_len);
        self
    }

    #[inline(always)]
    pub fn is_a_tick(&self) -> bool {
        self.pdu.is_a_tick(self.umem_base)
    }

    /// Returns the timer kind when this packet is a timer/control tick.
    ///
    /// The EtherType is the packet-level marker, while `timer_kind` identifies
    /// the specific timer operation. Keeping both checks here prevents callers
    /// from accidentally interpreting a normal packet's metadata as a timer.
    #[inline(always)]
    pub fn tick_kind(&self) -> Option<u8> {
        if self.pdu.is_a_tick(self.umem_base) {
            Some(self.pdu.timer_kind())
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn timer_kind(&self) -> u8 {
        self.pdu.timer_kind()
    }


    /// Returns the host-provided timestamp associated with this packet.
    #[inline(always)]
    pub fn timestamp(&self) -> u64 {
        self.pdu.timestamp
    }

    /// Associates a host-provided timestamp with this packet.
    #[inline(always)]
    pub fn set_timestamp(&mut self, timestamp: u64) {
        self.pdu.timestamp = timestamp;
    }

    /// Returns the hardware RX timestamp supplied by XDP metadata, or zero
    /// when the driver did not provide one.
    #[inline(always)]
    pub fn rx_timestamp(&self) -> u64 {
        self.pdu.rx_timestamp()
    }

    #[inline(always)]
    pub fn data_len(&self) -> u32 {
        self.pdu.data_len()
    }



    /// Provides a mutable pointer to the raw payload for zero-copy rewriting
    #[inline(always)]
    pub fn data_ptr_mut(&mut self) -> *mut u8 {
        self.pdu.data_ptr(self.umem_base)
    }

    #[inline(always)]
    pub fn data_ptr(&self) -> *const u8 {
        self.pdu.data_ptr(self.umem_base)
    }

    // =================================================================
    // FAST-PATH PROTOCOL MATCHING
    // =================================================================

    /// Exposes your ultra-fast fingerprinting for instant protocol matching
    #[inline(always)]
    pub fn fingerprint(&self) -> u32 {
        self.pdu.header_stack.fingerprint()
    }

    // =================================================================
    // SAFE IMMUTABLE ACCESSORS
    // =================================================================

    /// Returns a typed reference to the TCP header if it exists
    #[inline]
    pub fn tcp_header(&self) -> Option<&TcpHeader> {
        let base = self.pdu.base_addr(self.umem_base);
        let stack = &self.pdu.header_stack;

        // Iterate backwards: L4 headers are usually at the top of the stack
        for i in (0..stack.count()).rev() {
            if stack.kinds[i] == HeaderKind::Tcp {
                return Some(stack.tcp(base, i));
            }
        }
        None
    }

    /// Returns a typed reference to the IPv4 header if it exists
    #[inline]
    pub fn ipv4_header(&self) -> Option<&IpHeader> {
        let base = self.pdu.base_addr(self.umem_base);
        let stack = &self.pdu.header_stack;

        for i in 0..stack.count() {
            if stack.kinds[i] == HeaderKind::Ip {
                return Some(stack.ip(base, i));
            }
        }
        None
    }

    /// Returns a typed reference to the MAC header if it exists
    #[inline]
    pub fn mac_header(&self) -> Option<&MacHeader> {
        let base = self.pdu.base_addr(self.umem_base);
        for i in 0..self.pdu.header_stack.count() {
            if self.pdu.header_stack.kinds[i] == HeaderKind::Mac {
                return Some(self.pdu.header_stack.mac(base, i));
            }
        }
        None
    }

    /// Returns a typed reference to the UDP header if it exists
    #[inline]
    pub fn udp_header(&self) -> Option<&UdpHeader> {
        let base = self.pdu.base_addr(self.umem_base);
        for i in (0..self.pdu.header_stack.count()).rev() {
            if self.pdu.header_stack.kinds[i] == HeaderKind::Udp {
                return Some(self.pdu.header_stack.udp(base, i));
            }
        }
        None
    }

    /// Returns a typed reference to the ARP header if it exists
    #[inline]
    pub fn arp_header(&self) -> Option<&ArpIpv4Header> {
        let base = self.pdu.base_addr(self.umem_base);
        let stack = &self.pdu.header_stack;
        for i in 0..stack.count() {
            if stack.kinds[i] == HeaderKind::ArpIpv4 {
                return Some(stack.arp(base, i));
            }
        }
        None
    }

    /// Returns a typed reference to the IPv6 header if it exists
    #[inline]
    pub fn ipv6_header(&self) -> Option<&Ipv6Header> {
        let base = self.pdu.base_addr(self.umem_base);
        let stack = &self.pdu.header_stack;
        for i in 0..stack.count() {
            if stack.kinds[i] == HeaderKind::Ipv6 {
                return Some(stack.ipv6(base, i));
            }
        }
        None
    }

    /// Returns a typed reference to the ICMP header if it exists
    #[inline]
    pub fn icmp_header(&self) -> Option<&IcmpHeader> {
        let base = self.pdu.base_addr(self.umem_base);
        let stack = &self.pdu.header_stack;
        for i in (0..stack.count()).rev() {
            if stack.kinds[i] == HeaderKind::Icmp {
                return Some(stack.icmp(base, i));
            }
        }
        None
    }

    // =================================================================
    // SAFE MUTABLE ACCESSORS
    // =================================================================

    /// Returns a mutable typed reference to the TCP header
    #[inline]
    pub fn tcp_header_mut(&mut self) -> Option<&mut TcpHeader> {
        let base = self.pdu.base_addr(self.umem_base);
        let stack = &mut self.pdu.header_stack;

        for i in (0..stack.count()).rev() {
            if stack.kinds[i] == HeaderKind::Tcp {
                return Some(stack.tcp_mut(base, i));
            }
        }
        None
    }

    /// Returns a mutable typed reference to the IPv4 header
    #[inline]
    pub fn ipv4_header_mut(&mut self) -> Option<&mut IpHeader> {
        let base = self.pdu.base_addr(self.umem_base);
        let stack = &mut self.pdu.header_stack;

        for i in 0..stack.count() {
            if stack.kinds[i] == HeaderKind::Ip {
                return Some(stack.ip_mut(base, i));
            }
        }
        None
    }

    /// Returns a mutable typed reference to the MAC header
    #[inline]
    pub fn mac_header_mut(&mut self) -> Option<&mut MacHeader> {
        let base = self.pdu.base_addr(self.umem_base);
        let stack = &mut self.pdu.header_stack;
        for i in 0..stack.count() {
            if stack.kinds[i] == HeaderKind::Mac {
                return Some(stack.mac_mut(base, i));
            }
        }
        None
    }

    /// Returns a mutable typed reference to the ARP header
    #[inline]
    pub fn arp_header_mut(&mut self) -> Option<&mut ArpIpv4Header> {
        let base = self.pdu.base_addr(self.umem_base);
        let stack = &mut self.pdu.header_stack;
        for i in 0..stack.count() {
            if stack.kinds[i] == HeaderKind::ArpIpv4 {
                return Some(stack.arp_mut(base, i));
            }
        }
        None
    }

    /// Returns a mutable typed reference to the IPv6 header
    #[inline]
    pub fn ipv6_header_mut(&mut self) -> Option<&mut Ipv6Header> {
        let base = self.pdu.base_addr(self.umem_base);
        let stack = &mut self.pdu.header_stack;
        for i in 0..stack.count() {
            if stack.kinds[i] == HeaderKind::Ipv6 {
                return Some(stack.ipv6_mut(base, i));
            }
        }
        None
    }

    /// Returns a mutable typed reference to the UDP header
    #[inline]
    pub fn udp_header_mut(&mut self) -> Option<&mut UdpHeader> {
        let base = self.pdu.base_addr(self.umem_base);
        let stack = &mut self.pdu.header_stack;
        for i in (0..stack.count()).rev() {
            if stack.kinds[i] == HeaderKind::Udp {
                return Some(stack.udp_mut(base, i));
            }
        }
        None
    }

    /// Returns a mutable typed reference to the ICMP header
    #[inline]
    pub fn icmp_header_mut(&mut self) -> Option<&mut IcmpHeader> {
        let base = self.pdu.base_addr(self.umem_base);
        let stack = &mut self.pdu.header_stack;
        for i in (0..stack.count()).rev() {
            if stack.kinds[i] == HeaderKind::Icmp {
                return Some(stack.icmp_mut(base, i));
            }
        }
        None
    }

    #[inline]
    pub fn payload(&self) -> Option<&[u8]> {
        self.pdu.payload(self.umem_base)
    }

    /// Serializes fully formed MAC, IPv4, and TCP headers into Wasm linear memory.
    /// Returns the total length of the written headers.
    #[inline(always)]
    pub fn write_tcp_ipv4_headers(
        &mut self,
        mac: &MacHeader,
        ip: &IpHeader,
        tcp: &TcpHeader,
    ) -> u32 {
        let mac_len = core::mem::size_of::<MacHeader>();
        let ip_len = core::mem::size_of::<IpHeader>();
        let tcp_len = core::mem::size_of::<TcpHeader>();

        let ptr = self.pdu.data_ptr(self.umem_base);
        // SAFETY: `ptr` points to the start of the frame's data region in WASM linear memory.
        // `frame_size()` is the pre-allocated frame capacity (a power-of-2 byte count) and is
        // always larger than the combined header sizes written below. `&mut self` ensures no
        // other reference to this frame exists concurrently.
        let data = unsafe { core::slice::from_raw_parts_mut(ptr, self.pdu.frame_size()) };

        // SAFETY: `mac`, `ip`, and `tcp` are valid references to `#[repr(C)]` Copy types on
        // the caller's stack. Casting them to `*const u8` and reading `size_of::<T>()` bytes
        // is sound because all bit patterns are valid for byte slices. The source and destination
        // slices do not overlap (stack locals vs. WASM linear memory).
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
    /// Writes a MAC header to the start of the frame and updates the header stack.
    #[inline(always)]
    pub fn write_mac_header(&mut self, mac: &MacHeader) -> u32 {
        let mac_len = core::mem::size_of::<MacHeader>();
        let ptr = self.data_ptr_mut();

        // SAFETY: The frame size is pre-allocated and guaranteed to be larger than the MAC header.
        // `mac` is a valid reference on the caller's stack targeting a disjoint UMEM region.
        unsafe {
            core::ptr::copy_nonoverlapping(mac, ptr as *mut MacHeader, 1);
        }

        self.resize_payload(mac_len as u32);

        let hr = self.headroom() as u16;
        let stack = &mut self.pdu.header_stack;

        stack.kinds[0] = HeaderKind::Mac;
        stack.offsets[0] = hr;

        stack.hc = 1;

        mac_len as u32
    }

    /// Writes MAC and IPv4 headers sequentially into the frame and updates the header stack.
    #[inline(always)]
    pub fn write_mac_ipv4_headers(&mut self, mac: &MacHeader, ip: &IpHeader) -> u32 {
        let mac_len = core::mem::size_of::<MacHeader>();
        let ip_len = core::mem::size_of::<IpHeader>();

        let ptr = self.data_ptr_mut();

        // SAFETY: Writes originate from stack-allocated structs and target disjoint UMEM regions.
        // The frame capacity is guaranteed to hold the combined headers.
        unsafe {
            core::ptr::copy_nonoverlapping(mac, ptr as *mut MacHeader, 1);
            core::ptr::copy_nonoverlapping(ip, ptr.add(mac_len) as *mut IpHeader, 1);
        }

        let total_len = (mac_len + ip_len) as u32;
        self.resize_payload(total_len);

        let hr = self.headroom() as u16;
        let stack = &mut self.pdu.header_stack;

        stack.kinds[0] = HeaderKind::Mac;
        stack.offsets[0] = hr;

        stack.kinds[1] = HeaderKind::Ip;
        stack.offsets[1] = hr + mac_len as u16;

        stack.hc = 2;

        total_len
    }
    #[inline(always)]
    pub fn write_mac_ipv4_tcp_headers(
        &mut self,
        mac: &MacHeader,
        ip: &IpHeader,
        tcp: &TcpHeader,
    ) -> u32 {
        let mac_len = core::mem::size_of::<MacHeader>();
        let ip_len = core::mem::size_of::<IpHeader>();
        let tcp_len = core::mem::size_of::<TcpHeader>();

        let ptr = self.data_ptr_mut();

        // SAFETY: Writes originate from stack-allocated structs and target disjoint UMEM regions.
        // The frame capacity is guaranteed to hold the combined headers.
        unsafe {
            core::ptr::copy_nonoverlapping(mac, ptr as *mut MacHeader, 1);
            core::ptr::copy_nonoverlapping(ip, ptr.add(mac_len) as *mut IpHeader, 1);
            core::ptr::copy_nonoverlapping(tcp, ptr.add(mac_len + ip_len) as *mut TcpHeader, 1);
        }

        let total_len = (mac_len + ip_len + tcp_len) as u32;
        self.resize_payload(total_len);

        let hr = self.headroom() as u16;
        let stack = &mut self.pdu.header_stack;

        stack.kinds[0] = HeaderKind::Mac;
        stack.offsets[0] = hr;

        stack.kinds[1] = HeaderKind::Ip;
        stack.offsets[1] = hr + mac_len as u16;

        stack.kinds[2] = HeaderKind::Tcp;
        stack.offsets[2] = hr + (mac_len + ip_len) as u16;

        stack.hc = 3;

        total_len
    }

    #[inline(always)]
    pub fn write_mac_ipv4_udp_headers(
        &mut self,
        mac: &MacHeader,
        ip: &IpHeader,
        udp: &UdpHeader,
    ) -> u32 {
        let mac_len = core::mem::size_of::<MacHeader>();
        let ip_len = core::mem::size_of::<IpHeader>();
        let udp_len = core::mem::size_of::<UdpHeader>();

        let ptr = self.data_ptr_mut();

        // SAFETY: Operations write sequentially into the exclusively owned UMEM frame.
        unsafe {
            core::ptr::copy_nonoverlapping(mac, ptr as *mut MacHeader, 1);
            core::ptr::copy_nonoverlapping(ip, ptr.add(mac_len) as *mut IpHeader, 1);
            core::ptr::copy_nonoverlapping(udp, ptr.add(mac_len + ip_len) as *mut UdpHeader, 1);
        }

        let total_len = (mac_len + ip_len + udp_len) as u32;
        self.resize_payload(total_len);

        let hr = self.headroom() as u16;
        let stack = &mut self.pdu.header_stack;

        stack.kinds[0] = HeaderKind::Mac;
        stack.offsets[0] = hr;

        stack.kinds[1] = HeaderKind::Ip;
        stack.offsets[1] = hr + mac_len as u16;

        stack.kinds[2] = HeaderKind::Udp;
        stack.offsets[2] = hr + (mac_len + ip_len) as u16;

        stack.hc = 3;

        total_len
    }
}

/// A safe, zero-cost wrapper around the raw linear memory passed to Wasm.
pub struct PacketBatch<'a> {
    pub(crate) pdus: &'a mut [Pdu0],
    pub(crate) umem_base: usize,
}

const _: () = assert!(size_of::<Pdu0>() == 64);

impl<'a> PacketBatch<'a> {
    /// Safely constructs the batch from the raw Wasm inputs.
    /// Hides the pointer casting from the user.
    #[inline(always)]
    pub fn new(batch_bytes: &'a mut [u8], umem_offset: u32) -> Self {
        // SAFETY: `batch_bytes` is a `&mut [u8]` owned by the caller for lifetime `'a`, so the
        // pointer is valid and exclusively held. The host ABI guarantees the buffer contains a
        // contiguous array of packed `Pdu0` structs. `Pdu0` is `#[repr(C, align(64))]`; the
        // count is rounded down to whole structs, so we never read past the slice end. The
        // caller must ensure the buffer is 64-byte aligned (guaranteed by the WASM host ABI).
        let pdus = unsafe {
            slice::from_raw_parts_mut(
                batch_bytes.as_mut_ptr() as *mut Pdu0,
                batch_bytes.len() / core::mem::size_of::<Pdu0>(),
            )
        };

        // The host maps the shared UMEM at this positive Wasm-linear offset.
        let umem_base = umem_offset as usize;

        Self { pdus, umem_base }
    }

    /// Returns the number of packets in this batch
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.pdus.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.pdus.is_empty()
    }

    /// Creates a zero-cost iterator that yields safe `Packet` wrappers
    #[inline(always)]
    pub fn iter_mut(&mut self) -> PacketBatchIter<'_> {
        PacketBatchIter {
            iter: self.pdus.iter_mut(),
            umem_base: self.umem_base,
        }
    }
}

/// The Iterator that instantiates `Packet` wrappers on the fly
pub struct PacketBatchIter<'a> {
    iter: core::slice::IterMut<'a, Pdu0>,
    umem_base: usize,
}

impl<'a> Iterator for PacketBatchIter<'a> {
    type Item = Packet<'a>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        // As we iterate over the raw WPdus, we wrap them in the safe Packet context!
        self.iter.next().map(|pdu| Packet::new(pdu, self.umem_base))
    }
}
