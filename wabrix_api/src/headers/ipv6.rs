use super::{EndOffset, HeaderKind};

pub use network_types::ip::Ipv6Hdr;

impl EndOffset for Ipv6Hdr {
    #[inline]
    fn offset(&self) -> usize {
        Ipv6Hdr::LEN
    }

    #[inline]
    fn size() -> usize {
        Ipv6Hdr::LEN
    }

    #[inline]
    fn payload_size(&self, _: usize) -> usize {
        self.payload_len() as usize
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Ipv6
    }
}
