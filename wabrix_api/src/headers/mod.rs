use core::fmt;

pub use self::arp::*;
pub use self::icmp::*;
pub use self::ip::*;
pub use self::ipv6::*;
pub use self::mac::*;
pub use self::null_header::*;
pub use self::tcp::*;
pub use self::udp::*;

mod arp;
pub mod check;
pub mod flow;
mod icmp;
mod ip;
mod ipv6;
mod mac;
mod null_header;
mod tcp;
mod udp;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderKind {
    Null = 0,
    Eth,
    ArpIpv4,
    Ip,
    Ipv6,
    Tcp,
    Udp,
    Icmpv4 = 7,
    Icmpv6 = 8,
}

/// A trait implemented by all headers, used for reading them from a frame.
pub trait EndOffset: Send {
    /// Offset returns the number of bytes to skip to get to the next header, relative to the start
    /// of the frame data.
    fn offset(&self) -> usize;

    /// Returns the size of this header in bytes.
    fn size() -> usize;

    /// Returns the size of the payload in bytes. The hint is necessary for things like the L2 header which have no
    /// explicit length field.
    fn payload_size(&self, hint: usize) -> usize;

    fn header_kind(&self) -> HeaderKind;
}

#[derive(Debug)]
pub enum HeaderPtr {
    Null,
    Eth(*mut EthHdr),
    ArpIpv4(*mut ArpHdr),
    Ip(*mut Ipv4Hdr),
    Ipv6(*mut Ipv6Hdr),
    Tcp(*mut TcpHdr),
    Udp(*mut UdpHdr),
    Icmpv4(*mut Icmpv4Hdr),
    Icmpv6(*mut Icmpv6Hdr),
}

// Keep initialization ergonomics
impl HeaderPtr {
    #[inline]
    /// # Safety
    /// `ptr` must be a valid pointer derived from a live UMEM frame reference.
    ///
    /// * Passing `kind` explicitly avoids dereferencing a potentially unaligned pointer
    ///   to a packed struct, preventing Undefined Behavior.
    /// * The caller must ensure that the provided `kind` matches the actual data
    ///   layout at the given pointer.
    pub unsafe fn new<T>(kind: HeaderKind, ptr: *mut T) -> HeaderPtr {
        Self::from_kind_and_ptr(kind, ptr as *mut u8)
    }

    // Accessors create temporary borrows on demand (no persistent &mut stored).
    #[inline]
    pub fn as_eth_mut(&mut self) -> Option<&mut EthHdr> {
        match self {
            // SAFETY: `p` was stored by `new()` from a live `*mut EthHdr` into valid UMEM
            // memory. `&mut self` prevents any aliased mutable borrow of the same slot.
            HeaderPtr::Eth(p) => Some(unsafe { &mut **p }),
            _ => None,
        }
    }
    #[inline]
    pub fn as_eth(&self) -> Option<&EthHdr> {
        match self {
            // SAFETY: Same pointer invariant as `as_mac_mut`; `&self` prevents concurrent
            // mutable access.
            HeaderPtr::Eth(p) => Some(unsafe { &**p }),
            _ => None,
        }
    }
    // ArpIpv4 accessors
    #[inline]
    pub fn as_arpipv4_mut(&mut self) -> Option<&mut ArpHdr> {
        match self {
            // SAFETY: `p` is a valid `*mut ArpHdr` from UMEM; `&mut self` prevents aliasing.
            HeaderPtr::ArpIpv4(p) => Some(unsafe { &mut **p }),
            _ => None,
        }
    }
    #[inline]
    pub fn as_arpipv4(&self) -> Option<&ArpHdr> {
        match self {
            // SAFETY: Same pointer invariant; `&self` prevents concurrent mutation.
            HeaderPtr::ArpIpv4(p) => Some(unsafe { &**p }),
            _ => None,
        }
    }

    // Ip accessors
    #[inline]
    pub fn as_ip_mut(&mut self) -> Option<&mut Ipv4Hdr> {
        match self {
            // SAFETY: `p` is a valid `*mut Ipv4Hdr` from UMEM; `&mut self` prevents aliasing.
            HeaderPtr::Ip(p) => Some(unsafe { &mut **p }),
            _ => None,
        }
    }
    #[inline]
    pub fn as_ip(&self) -> Option<&Ipv4Hdr> {
        match self {
            // SAFETY: Same pointer invariant; `&self` prevents concurrent mutation.
            HeaderPtr::Ip(p) => Some(unsafe { &**p }),
            _ => None,
        }
    }

    // Ipv6 accessors
    #[inline]
    pub fn as_ipv6_mut(&mut self) -> Option<&mut Ipv6Hdr> {
        match self {
            // SAFETY: `p` is a valid `*mut Ipv6Hdr` from UMEM; `&mut self` prevents aliasing.
            HeaderPtr::Ipv6(p) => Some(unsafe { &mut **p }),
            _ => None,
        }
    }
    #[inline]
    pub fn as_ipv6(&self) -> Option<&Ipv6Hdr> {
        match self {
            // SAFETY: Same pointer invariant; `&self` prevents concurrent mutation.
            HeaderPtr::Ipv6(p) => Some(unsafe { &**p }),
            _ => None,
        }
    }

    // Tcp accessors
    #[inline]
    pub fn as_tcp_mut(&mut self) -> Option<&mut TcpHdr> {
        match self {
            // SAFETY: `p` is a valid `*mut TcpHdr` from UMEM; `&mut self` prevents aliasing.
            HeaderPtr::Tcp(p) => Some(unsafe { &mut **p }),
            _ => None,
        }
    }
    #[inline]
    pub fn as_tcp(&self) -> Option<&TcpHdr> {
        match self {
            // SAFETY: Same pointer invariant; `&self` prevents concurrent mutation.
            HeaderPtr::Tcp(p) => Some(unsafe { &**p }),
            _ => None,
        }
    }

    // Udp accessors
    #[inline]
    pub fn as_udp_mut(&mut self) -> Option<&mut UdpHdr> {
        match self {
            // SAFETY: `p` is a valid `*mut UdpHdr` from UMEM; `&mut self` prevents aliasing.
            HeaderPtr::Udp(p) => Some(unsafe { &mut **p }),
            _ => None,
        }
    }
    #[inline]
    pub fn as_udp(&self) -> Option<&UdpHdr> {
        match self {
            // SAFETY: Same pointer invariant; `&self` prevents concurrent mutation.
            HeaderPtr::Udp(p) => Some(unsafe { &**p }),
            _ => None,
        }
    }

    // ICMPv4 accessors
    #[inline]
    pub fn as_icmpv4_mut(&mut self) -> Option<&mut Icmpv4Hdr> {
        match self {
            // SAFETY: `p` is a valid `*mut Icmpv4Hdr` from UMEM; `&mut self` prevents aliasing.
            HeaderPtr::Icmpv4(p) => Some(unsafe { &mut **p }),
            _ => None,
        }
    }
    #[inline]
    pub fn as_icmpv4(&self) -> Option<&Icmpv4Hdr> {
        match self {
            // SAFETY: Same pointer invariant; `&self` prevents concurrent mutation.
            HeaderPtr::Icmpv4(p) => Some(unsafe { &**p }),
            _ => None,
        }
    }

    // ICMPv6 accessors
    #[inline]
    pub fn as_icmpv6_mut(&mut self) -> Option<&mut Icmpv6Hdr> {
        match self {
            // SAFETY: `p` is a valid `*mut Icmpv6Hdr` from UMEM; `&mut self` prevents aliasing.
            HeaderPtr::Icmpv6(p) => Some(unsafe { &mut **p }),
            _ => None,
        }
    }
    #[inline]
    pub fn as_icmpv6(&self) -> Option<&Icmpv6Hdr> {
        match self {
            // SAFETY: Same pointer invariant; `&self` prevents concurrent mutation.
            HeaderPtr::Icmpv6(p) => Some(unsafe { &**p }),
            _ => None,
        }
    }

    #[inline]
    pub fn kind(&self) -> HeaderKind {
        match self {
            HeaderPtr::Null => HeaderKind::Null,
            HeaderPtr::Eth(_) => HeaderKind::Eth,
            HeaderPtr::ArpIpv4(_) => HeaderKind::ArpIpv4,
            HeaderPtr::Ip(_) => HeaderKind::Ip,
            HeaderPtr::Ipv6(_) => HeaderKind::Ipv6,
            HeaderPtr::Tcp(_) => HeaderKind::Tcp,
            HeaderPtr::Udp(_) => HeaderKind::Udp,
            HeaderPtr::Icmpv4(_) => HeaderKind::Icmpv4,
            HeaderPtr::Icmpv6(_) => HeaderKind::Icmpv6,
        }
    }

    // Raw pointer views used by payload computations
    #[inline]
    pub fn as_ptr_u8(&self) -> Option<*const u8> {
        match self {
            HeaderPtr::Null => None,
            HeaderPtr::Eth(p) => Some(*p as *const u8),
            HeaderPtr::ArpIpv4(p) => Some(*p as *const u8),
            HeaderPtr::Ip(p) => Some(*p as *const u8),
            HeaderPtr::Ipv6(p) => Some(*p as *const u8),
            HeaderPtr::Tcp(p) => Some(*p as *const u8),
            HeaderPtr::Udp(p) => Some(*p as *const u8),
            HeaderPtr::Icmpv4(p) => Some(*p as *const u8),
            HeaderPtr::Icmpv6(p) => Some(*p as *const u8),
        }
    }
    #[inline]
    pub fn as_ptr_u8_mut(&mut self) -> Option<*mut u8> {
        match self {
            HeaderPtr::Null => None,
            HeaderPtr::Eth(p) => Some(*p as *mut u8),
            HeaderPtr::ArpIpv4(p) => Some(*p as *mut u8),
            HeaderPtr::Ip(p) => Some(*p as *mut u8),
            HeaderPtr::Ipv6(p) => Some(*p as *mut u8),
            HeaderPtr::Tcp(p) => Some(*p as *mut u8),
            HeaderPtr::Udp(p) => Some(*p as *mut u8),
            HeaderPtr::Icmpv4(p) => Some(*p as *mut u8),
            HeaderPtr::Icmpv6(p) => Some(*p as *mut u8),
        }
    }

    /// Reconstructs the Header enum variant from a tag and a raw pointer.
    /// This is the "secret sauce" for the offset-based HeaderStack.
    #[inline]
    pub fn from_kind_and_ptr(kind: HeaderKind, ptr: *mut u8) -> Self {
        match kind {
            HeaderKind::Null => HeaderPtr::Null,
            HeaderKind::Eth => HeaderPtr::Eth(ptr as *mut EthHdr),
            HeaderKind::ArpIpv4 => HeaderPtr::ArpIpv4(ptr as *mut ArpHdr),
            HeaderKind::Ip => HeaderPtr::Ip(ptr as *mut Ipv4Hdr),
            HeaderKind::Ipv6 => HeaderPtr::Ipv6(ptr as *mut Ipv6Hdr),
            HeaderKind::Tcp => HeaderPtr::Tcp(ptr as *mut TcpHdr),
            HeaderKind::Udp => HeaderPtr::Udp(ptr as *mut UdpHdr),
            HeaderKind::Icmpv4 => HeaderPtr::Icmpv4(ptr as *mut Icmpv4Hdr),
            HeaderKind::Icmpv6 => HeaderPtr::Icmpv6(ptr as *mut Icmpv6Hdr),
        }
    }
}

pub type Header = HeaderPtr;

impl HeaderPtr {
    #[inline]
    pub fn offset(&self) -> Option<usize> {
        match self {
            Header::Null => None,
            Header::Eth(_) => Some(self.as_eth().unwrap().offset()),
            Header::Ip(_) => Some(self.as_ip().unwrap().offset()),
            Header::Ipv6(_) => Some(self.as_ipv6().unwrap().offset()),
            Header::Tcp(_) => Some(self.as_tcp().unwrap().offset()),
            Header::Udp(_) => Some(self.as_udp().unwrap().offset()),
            Header::Icmpv4(_) => Some(self.as_icmpv4().unwrap().offset()),
            Header::Icmpv6(_) => Some(self.as_icmpv6().unwrap().offset()),
            Header::ArpIpv4(_) => Some(self.as_arpipv4().unwrap().offset()),
        }
    }
}

impl fmt::Display for HeaderPtr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Header::Null => write!(f, "{:?}", self),
            Header::Eth(_) => write!(f, "{:?}", self.as_eth().unwrap()),
            Header::Ip(_) => write!(f, "{:?}", self.as_ip().unwrap()),
            Header::Ipv6(_) => write!(f, "{:?}", self.as_ipv6().unwrap()),
            Header::Tcp(_) => write!(f, "{:?}", self.as_tcp().unwrap()),
            Header::Udp(_) => write!(f, "{:?}", self.as_udp().unwrap()),
            Header::Icmpv4(_) => write!(f, "{:?}", self.as_icmpv4().unwrap()),
            Header::Icmpv6(_) => write!(f, "{:?}", self.as_icmpv6().unwrap()),
            Header::ArpIpv4(_) => write!(f, "{:?}", self.as_arpipv4().unwrap()),
        }
    }
}

#[test]

fn test_headers() {
    let mut ip_header = new_ipv4_header();
    let header = Header::Ip(&mut ip_header);
    assert_eq!(header.kind(), HeaderKind::Ip);
    assert!(header.as_ip().is_some());
    assert!(header.as_eth().is_none());
    assert!(header.as_tcp().is_none());
    assert!(header.as_udp().is_none());
}
