use crate::headers::{Header, HeaderKind};
pub use crate::shared_memory::HeaderStack;
use crate::shared_memory::MAX_HEADERS;
use core::fmt;
use network_types::arp::ArpHdr;
use network_types::eth::EthHdr;
use network_types::icmp::{Icmpv4Hdr, Icmpv6Hdr};
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

impl HeaderStack {
    #[inline]
    pub fn new() -> Self {
        HeaderStack {
            offsets: [0; MAX_HEADERS],
            kinds: [HeaderKind::Null; MAX_HEADERS],
            hc: 0,
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.hc = 0;
    }

    #[inline]
    pub fn which_ix(&self, kind: HeaderKind) -> Option<usize> {
        if kind == HeaderKind::Null {
            return None;
        }

        let target_layer = match kind {
            HeaderKind::Eth => 0,
            HeaderKind::ArpIpv4 | HeaderKind::Ip | HeaderKind::Ipv6 => 1,
            HeaderKind::Tcp | HeaderKind::Udp | HeaderKind::Icmpv4 | HeaderKind::Icmpv6 => 2,
            HeaderKind::Null => return None,
        };

        let count = (self.hc as usize).min(MAX_HEADERS);
        if target_layer < count && self.kinds[target_layer] == kind {
            return Some(target_layer);
        }

        for i in 0..count {
            if self.kinds[i] == kind {
                return Some(i);
            }
        }
        None
    }
    #[inline]
    pub fn try_push(&mut self, base_addr: usize, h: Header) -> Result<(), &'static str> {
        let idx = self.hc as usize;
        if idx >= MAX_HEADERS {
            return Err("HeaderStack overflow: max headers exceeded");
        }
        self.kinds[idx] = h.kind();

        let h_addr = h.as_ptr_u8().unwrap() as usize;
        debug_assert!(
            h_addr >= base_addr,
            "Header address is before base pointer!"
        );
        debug_assert!(
            h_addr - base_addr <= u16::MAX as usize,
            "Header offset exceeds u16!"
        );
        self.offsets[idx] = (h_addr - base_addr) as u16;
        self.hc += 1;
        Ok(())
    }

    #[inline]
    pub fn push(&mut self, base_addr: usize, h: Header) {
        self.try_push(base_addr, h)
            .expect("HeaderStack overflow: cannot push more than MAX_HEADERS");
    }

    /// Internal helper to reconstruct the Header enum on the fly
    #[inline]
    fn reconstruct(&self, base_addr: usize, which: usize) -> Header {
        debug_assert!(
            which < self.hc as usize,
            "Attempted to access uninitialized header!"
        );
        let ptr_addr = base_addr + self.offsets[which] as usize;
        Header::from_kind_and_ptr(self.kinds[which], ptr_addr as *mut u8)
    }

    /// Pointer calculation helper for shared borrows
    #[inline]
    unsafe fn ptr_at<T>(&self, base_addr: usize, which: usize) -> *const T {
        debug_assert!(
            which < self.hc as usize,
            "Attempted to access uninitialized header!"
        );
        (base_addr + self.offsets[which] as usize) as *const T
    }

    /// Pointer calculation helper for mutable borrows
    #[inline]
    unsafe fn mut_ptr_at<T>(&mut self, base_addr: usize, which: usize) -> *mut T {
        debug_assert!(
            which < self.hc as usize,
            "Attempted to access uninitialized header!"
        );
        (base_addr + self.offsets[which] as usize) as *mut T
    }

    /// Returns a u32 fingerprint where every 4 bits represent a HeaderKind
    #[inline]
    pub fn fingerprint(&self) -> u32 {
        let mut f = 0u32;
        let count = (self.hc as usize).min(MAX_HEADERS);
        for i in 0..count {
            f |= (self.kinds[i] as u32) << (i * 4);
        }
        f
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.hc as usize
    }

    #[inline]
    pub fn get(&self, base_addr: usize, which: usize) -> Header {
        self.reconstruct(base_addr, which)
    }

    #[inline]
    pub fn eth_hdr(&self, base_addr: usize, which: usize) -> &EthHdr {
        unsafe { &*self.ptr_at(base_addr, which) }
    }

    #[inline]
    pub fn arp_hdr(&self, base_addr: usize, which: usize) -> &ArpHdr {
        unsafe { &*self.ptr_at(base_addr, which) }
    }

    #[inline]
    pub fn ip_hdr(&self, base_addr: usize, which: usize) -> &Ipv4Hdr {
        unsafe { &*self.ptr_at(base_addr, which) }
    }

    #[inline]
    pub fn ipv6_hdr(&self, base_addr: usize, which: usize) -> &Ipv6Hdr {
        unsafe { &*self.ptr_at(base_addr, which) }
    }

    #[inline]
    pub fn tcp_hdr(&self, base_addr: usize, which: usize) -> &TcpHdr {
        unsafe { &*self.ptr_at(base_addr, which) }
    }

    #[inline]
    pub fn udp_hdr(&self, base_addr: usize, which: usize) -> &UdpHdr {
        unsafe { &*self.ptr_at(base_addr, which) }
    }

    #[inline]
    pub fn icmpv4_hdr(&self, base_addr: usize, which: usize) -> &Icmpv4Hdr {
        unsafe { &*self.ptr_at(base_addr, which) }
    }

    #[inline]
    pub fn icmpv6_hdr(&self, base_addr: usize, which: usize) -> &Icmpv6Hdr {
        unsafe { &*self.ptr_at(base_addr, which) }
    }

    #[inline]
    pub fn icmpv4_hdr_mut(&mut self, base_addr: usize, which: usize) -> &mut Icmpv4Hdr {
        unsafe { &mut *self.mut_ptr_at(base_addr, which) }
    }

    #[inline]
    pub fn icmpv6_hdr_mut(&mut self, base_addr: usize, which: usize) -> &mut Icmpv6Hdr {
        unsafe { &mut *self.mut_ptr_at(base_addr, which) }
    }
}


impl Default for HeaderStack {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for HeaderStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.hc == 0 {
            write!(f, "<no headers>")
        } else {
            for i in 0..self.hc as usize {
                writeln!(
                    f,
                    "{:1}: {:?} at offset {}",
                    i, self.kinds[i], self.offsets[i]
                )?;
            }
            Ok(())
        }
    }
}
