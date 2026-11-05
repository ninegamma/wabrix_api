use super::{EndOffset, HeaderKind};

pub use network_types::arp::ArpHdr;

impl EndOffset for ArpHdr {
    #[inline]
    fn offset(&self) -> usize {
        2 * self.hlen() as usize + 2 * self.plen() as usize + 8
    }

    #[inline]
    fn size() -> usize {
        ArpHdr::LEN
    }

    #[inline]
    fn payload_size(&self, hint: usize) -> usize {
        hint - self.offset()
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::ArpIpv4
    }
}
