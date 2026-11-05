use super::{EndOffset, HeaderKind};

pub use network_types::icmp::{Icmpv4Hdr, Icmpv6Hdr};

impl EndOffset for Icmpv4Hdr {
    #[inline]
    fn offset(&self) -> usize {
        Icmpv4Hdr::LEN
    }

    #[inline]
    fn size() -> usize {
        Icmpv4Hdr::LEN
    }

    #[inline]
    fn payload_size(&self, hint: usize) -> usize {
        hint - self.offset()
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Icmpv4
    }
}

impl EndOffset for Icmpv6Hdr {
    #[inline]
    fn offset(&self) -> usize {
        Icmpv6Hdr::LEN
    }

    #[inline]
    fn size() -> usize {
        Icmpv6Hdr::LEN
    }

    #[inline]
    fn payload_size(&self, hint: usize) -> usize {
        hint - self.offset()
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Icmpv6
    }
}
