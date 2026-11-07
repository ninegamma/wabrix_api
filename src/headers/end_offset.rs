use network_types::arp::ArpHdr;
use network_types::eth::EthHdr;
use network_types::icmp::{Icmpv4Hdr, Icmpv6Hdr};
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;
use crate::headers::{HeaderKind, NullHeader};

pub const ETH_HDR_SIZE: usize = EthHdr::LEN;
pub const HDR_SIZE_802_1Q: usize = ETH_HDR_SIZE + 4;
pub const HDR_SIZE_802_1AD: usize = HDR_SIZE_802_1Q + 4;


/// A trait implemented by all headers, used for reading them from a frame.
pub trait EndOffset: Send {
    /// Offset returns the number of bytes to skip to get to the next header, relative to the start
    /// of the frame data.
    fn offset(&self) -> usize;

    /// Returns the size of this header in bytes.
    fn size() -> usize;

    /// Returns the size of the payload in bytes. The hint is necessary for things like the L2
    /// header which have no explicit length field.
    fn payload_size(&self, hint: usize) -> usize;

    fn header_kind(&self) -> HeaderKind;
}

impl EndOffset for NullHeader {
    #[inline]
    fn offset(&self) -> usize {
        0
    }

    #[inline]
    fn size() -> usize {
        0
    }

    #[inline]
    fn payload_size(&self, hint: usize) -> usize {
        hint
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Null
    }
}

impl EndOffset for EthHdr {
    #[inline]
    fn offset(&self) -> usize {
        match u16::from_be_bytes(self.ether_type) {
            0x8100 => HDR_SIZE_802_1Q,
            0x9100 => HDR_SIZE_802_1AD,
            _ => ETH_HDR_SIZE,
        }
    }

    #[inline]
    fn size() -> usize {
        EthHdr::LEN
    }

    #[inline]
    fn payload_size(&self, hint: usize) -> usize {
        hint - self.offset()
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Eth
    }
}

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

impl EndOffset for TcpHdr {
    #[inline]
    fn offset(&self) -> usize {
        // data offset is in 32-bit words
        self.doff() as usize * 4
    }

    #[inline]
    fn size() -> usize {
        TcpHdr::LEN
    }

    #[inline]
    fn payload_size(&self, hint: usize) -> usize {
        hint - self.offset()
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Tcp
    }
}

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
