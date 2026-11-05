use super::{EndOffset, HeaderKind};
use crate::headers::check::checksum;
use zerocopy::IntoBytes;

pub use network_types::ip::Ipv4Hdr;

/// Creates a zeroed IPv4 header for packet construction.
#[inline]
pub fn new_ipv4_header() -> Ipv4Hdr {
    Ipv4Hdr {
        vihl: 0,
        tos: 0,
        tot_len: [0; 2],
        id: [0; 2],
        frags: [0; 2],
        ttl: 0,
        proto: 0,
        check: [0; 2],
        src_addr: [0; 4],
        dst_addr: [0; 4],
    }
}

/// Recalculates the IPv4 header checksum after its fields have been updated.
#[inline]
pub fn update_ipv4_checksum(header: &mut Ipv4Hdr) {
    header.check = [0; 2];
    header.set_checksum(checksum(header.as_bytes(), 5));
}

impl EndOffset for Ipv4Hdr {
    #[inline]
    fn offset(&self) -> usize {
        self.ihl() as usize
    }

    #[inline]
    fn size() -> usize {
        Ipv4Hdr::LEN
    }

    #[inline]
    fn payload_size(&self, _: usize) -> usize {
        self.tot_len() as usize - self.offset()
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Ip
    }
}
