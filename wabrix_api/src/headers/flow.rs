use byteorder::{BigEndian, ByteOrder};
use core::fmt;
use core::hash::Hasher;
use core::mem;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::slice;
use fnv::FnvHasher;

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[repr(C, packed)]
pub struct FiveTupleV4 {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl FiveTupleV4 {
    pub fn new(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
        }
    }

    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            proto: self.proto,
        }
    }
}

impl fmt::Display for FiveTupleV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SAFETY:
        // - Extracts raw unaligned fields from the packed struct without creating intermediate references.
        // - Prevents hardware alignment faults on architectures without native unaligned access.
        let src_ip = unsafe { core::ptr::read_unaligned(&raw const self.src_ip) };
        let dst_ip = unsafe { core::ptr::read_unaligned(&raw const self.dst_ip) };
        let src_port = unsafe { core::ptr::read_unaligned(&raw const self.src_port) };
        let dst_port = unsafe { core::ptr::read_unaligned(&raw const self.dst_port) };
        let proto = unsafe { core::ptr::read_unaligned(&raw const self.proto) };

        write!(
            f,
            "src_ip={}, dst_ip= {}, src_port= {:#04x}, dst_port= {:#04x}, proto= {:#x}",
            Ipv4Addr::from(src_ip),
            Ipv4Addr::from(dst_ip),
            src_port,
            dst_port,
            proto,
        )
    }
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Ipv4Prefix {
    pub ip_address: u32,
    pub prefix: u8,
    mask: u32,
}

impl Ipv4Prefix {
    pub fn new(address: u32, prefix: u8) -> Ipv4Prefix {
        let mask = if prefix == 0 {
            0
        } else {
            let inv_pfx = 32 - prefix;
            !((1u32 << (inv_pfx as u32)) - 1)
        };
        Ipv4Prefix {
            ip_address: address & mask,
            prefix,
            mask,
        }
    }

    #[inline]
    pub fn in_range(&self, address: u32) -> bool {
        (address & self.mask) == self.ip_address
    }
}

const IHL_TO_BYTE_FACTOR: usize = 4;

#[inline]
pub fn ipv4_extract_flow(bytes: &[u8]) -> FiveTupleV4 {
    let port_start = (bytes[0] & 0xf) as usize * IHL_TO_BYTE_FACTOR;
    FiveTupleV4 {
        proto: bytes[9],
        src_ip: BigEndian::read_u32(&bytes[12..16]),
        dst_ip: BigEndian::read_u32(&bytes[16..20]),
        src_port: BigEndian::read_u16(&bytes[(port_start)..(port_start + 2)]),
        dst_port: BigEndian::read_u16(&bytes[(port_start + 2)..(port_start + 4)]),
    }
}

impl FiveTupleV4 {
    #[inline]
    pub fn reverse_flow(&self) -> FiveTupleV4 {
        // SAFETY: Reads fields via unaligned primitives or direct values from self.
        let src_ip = unsafe { core::ptr::read_unaligned(&raw const self.src_ip) };
        let dst_ip = unsafe { core::ptr::read_unaligned(&raw const self.dst_ip) };
        let src_port = unsafe { core::ptr::read_unaligned(&raw const self.src_port) };
        let dst_port = unsafe { core::ptr::read_unaligned(&raw const self.dst_port) };
        let proto = unsafe { core::ptr::read_unaligned(&raw const self.proto) };

        FiveTupleV4 {
            src_ip: dst_ip,
            dst_ip: src_ip,
            src_port: dst_port,
            dst_port: src_port,
            proto,
        }
    }

    pub fn src_socket_addr(&self) -> SocketAddrV4 {
        let src_ip = unsafe { core::ptr::read_unaligned(&raw const self.src_ip) };
        let src_port = unsafe { core::ptr::read_unaligned(&raw const self.src_port) };
        SocketAddrV4::new(Ipv4Addr::from(src_ip), src_port)
    }

    pub fn dst_socket_addr(&self) -> SocketAddrV4 {
        let dst_ip = unsafe { core::ptr::read_unaligned(&raw const self.dst_ip) };
        let dst_port = unsafe { core::ptr::read_unaligned(&raw const self.dst_port) };
        SocketAddrV4::new(Ipv4Addr::from(dst_ip), dst_port)
    }
}

#[inline]
pub fn ipv4_flow_hash(bytes: &[u8], _iv: u32) -> usize {
    let flow = ipv4_extract_flow(bytes);
    flow_hash(&flow)
}

#[inline]
pub fn flow_hash(flow: &FiveTupleV4) -> usize {
    let mut hasher = FnvHasher::default();
    hasher.write(flow_as_u8(flow));
    hasher.finish() as usize
}

fn flow_as_u8(flow: &FiveTupleV4) -> &[u8] {
    let size = mem::size_of::<FiveTupleV4>();
    // SAFETY:
    // - `flow` is a valid shared reference, so its address is non-null.
    // - Using `&raw const *flow` prevents alignment assertions on packed structs.
    // - Casting to `*const u8` and reading `size_of::<FiveTupleV4>()` bytes is sound because all bit patterns are valid for bytes.
    unsafe {
        let ptr = &raw const *flow as *const u8;
        slice::from_raw_parts(ptr, size)
    }
}
