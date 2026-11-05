use super::{EndOffset, HeaderKind};

pub use network_types::eth::EthHdr;

pub const ETH_HDR_SIZE: usize = EthHdr::LEN;
pub const HDR_SIZE_802_1Q: usize = ETH_HDR_SIZE + 4;
pub const HDR_SIZE_802_1AD: usize = HDR_SIZE_802_1Q + 4;

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
