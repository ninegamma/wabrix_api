use super::{EndOffset, HeaderKind};

pub use network_types::udp::UdpHdr;

impl EndOffset for UdpHdr {
    #[inline]
    fn offset(&self) -> usize {
        UdpHdr::LEN
    }

    #[inline]
    fn size() -> usize {
        UdpHdr::LEN
    }

    #[inline]
    fn payload_size(&self, _: usize) -> usize {
        self.len() as usize - self.offset()
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Udp
    }
}
