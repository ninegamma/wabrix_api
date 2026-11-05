use super::{EndOffset, HeaderKind};

pub use network_types::tcp::TcpHdr;

/// Creates a zeroed TCP header for packet construction.
#[inline]
pub fn new_tcp_header() -> TcpHdr {
    TcpHdr {
        source: [0; 2],
        dest: [0; 2],
        seq: [0; 4],
        ack_seq: [0; 4],
        _bitfield_align_1: [],
        _bitfield_1: TcpHdr::new_bitfield_1(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        window: [0; 2],
        check: [0; 2],
        urg_ptr: [0; 2],
    }
}

/// Converts the TCP flag bitfield to the conventional wire flag byte.
#[inline]
pub fn tcp_flags(header: &TcpHdr) -> u8 {
    (header.fin() as u8)
        | ((header.syn() as u8) << 1)
        | ((header.rst() as u8) << 2)
        | ((header.psh() as u8) << 3)
        | ((header.ack() as u8) << 4)
        | ((header.urg() as u8) << 5)
        | ((header.ece() as u8) << 6)
        | ((header.cwr() as u8) << 7)
}

/// Sets the standard TCP flags from their conventional wire flag byte.
#[inline]
pub fn set_tcp_flags(header: &mut TcpHdr, flags: u8) {
    header.set_fin((flags & 0x01) as u16);
    header.set_syn(((flags >> 1) & 1) as u16);
    header.set_rst(((flags >> 2) & 1) as u16);
    header.set_psh(((flags >> 3) & 1) as u16);
    header.set_ack(((flags >> 4) & 1) as u16);
    header.set_urg(((flags >> 5) & 1) as u16);
    header.set_ece(((flags >> 6) & 1) as u16);
    header.set_cwr(((flags >> 7) & 1) as u16);
}

impl EndOffset for TcpHdr {
    #[inline]
    fn offset(&self) -> usize {
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
