use super::{EndOffset, HeaderKind};
use crate::headers::check::update_checksum_incremental;
use core::default::Default;
use core::fmt;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    offset_to_ns: u8,
    flags: u8,
    window: u16,
    csum: u16,
    urgent: u16,
}

const CWR: u8 = 0b1000_0000;
const ECE: u8 = 0b0100_0000;
const URG: u8 = 0b0010_0000;
const ACK: u8 = 0b0001_0000;
const PSH: u8 = 0b0000_1000;
const RST: u8 = 0b0000_0100;
const SYN: u8 = 0b0000_0010;
const FIN: u8 = 0b0000_0001;

macro_rules! write_or_return {
    ($dst: expr, $($arg:tt)*) => {
        {
            let result = write!($dst, $($arg)*);
            result?
        }
    }
}

impl fmt::Display for TcpHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_or_return!(
            f,
            "tcp src_port {} dst_port {} seq {} ack {} data_offset {} flags ",
            self.src_port(),
            self.dst_port(),
            self.seq_num(),
            self.ack_num(),
            self.data_offset()
        );
        let ret = self.fmt_flags(f);
        ret?;
        write!(
            f,
            "cwnd {} csum {} urgent {}",
            self.window_size(),
            self.checksum(),
            self.urgent()
        )
    }
}

impl EndOffset for TcpHeader {
    #[inline]
    fn offset(&self) -> usize {
        (self.data_offset() * 4) as usize
    }

    #[inline]
    fn size() -> usize {
        20
    }

    #[inline]
    fn payload_size(&self, hint: usize) -> usize {
        // - The hint parameter must be derived from the IP header length field
        // - Subtracting the TCP offset yields the true L4 payload size
        // - Using the raw hardware frame size introduces padding corruption
        hint - self.offset()
    }

    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Tcp
    }
}

impl TcpHeader {
    #[inline]
    pub fn new() -> TcpHeader {
        Default::default()
    }

    #[inline]
    pub fn src_port(&self) -> u16 {
        // SAFETY:
        // - Extracts the raw constant pointer to the packed field without creating an intermediate reference.
        // - Performs a safe unaligned read to prevent hardware alignment faults.
        let raw_port = unsafe { core::ptr::read_unaligned(&raw const self.src_port) };
        u16::from_be(raw_port)
    }

    #[inline]
    pub fn dst_port(&self) -> u16 {
        let raw_port = unsafe { core::ptr::read_unaligned(&raw const self.dst_port) };
        u16::from_be(raw_port)
    }

    #[inline]
    pub fn set_src_port(&mut self, port: u16) {
        // SAFETY:
        // - Extracts the raw mutable pointer to the packed field without creating a reference.
        // - Performs a safe unaligned write directly to the memory address.
        unsafe {
            core::ptr::write_unaligned(&raw mut self.src_port, u16::to_be(port));
        }
    }

    #[inline]
    pub fn incr_src_port(&mut self) {
        unsafe {
            let current = core::ptr::read_unaligned(&raw const self.src_port);
            core::ptr::write_unaligned(
                &raw mut self.src_port,
                u16::to_be(u16::from_be(current) + 1)
            );
        }
    }

    #[inline]
    pub fn set_dst_port(&mut self, port: u16) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.dst_port, u16::to_be(port));
        }
    }

    #[inline]
    pub fn seq_num(&self) -> u32 {
        let raw_seq = unsafe { core::ptr::read_unaligned(&raw const self.seq) };
        u32::from_be(raw_seq)
    }

    #[inline]
    pub fn set_seq_num(&mut self, seq: u32) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.seq, u32::to_be(seq));
        }
    }

    #[inline]
    pub fn ack_num(&self) -> u32 {
        let raw_ack = unsafe { core::ptr::read_unaligned(&raw const self.ack) };
        u32::from_be(raw_ack)
    }

    #[inline]
    pub fn set_ack_num(&mut self, ack: u32) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.ack, u32::to_be(ack));
        }
    }

    #[inline]
    pub fn data_offset(&self) -> u8 {
        let offset_to_ns = unsafe { core::ptr::read_unaligned(&raw const self.offset_to_ns) };
        (offset_to_ns & 0xf0) >> 4
    }

    #[inline]
    pub fn set_data_offset(&mut self, offset: u8) {
        debug_assert!(offset <= 15, "TCP data offset exceeds 4 bits!");
        unsafe {
            let offset_to_ns = core::ptr::read_unaligned(&raw const self.offset_to_ns);
            let blanked = offset_to_ns & 0x0f;
            core::ptr::write_unaligned(&raw mut self.offset_to_ns, blanked | (offset << 4));
        }
    }

    pub fn flags(&self) -> u8 {
        unsafe { core::ptr::read_unaligned(&raw const self.flags) }
    }

    pub fn set_flags(&mut self, flags: u8) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.flags, flags);
        }
    }

    /// ECN nonce concealment flag: RFC 3540.
    #[inline]
    pub fn ns_flag(&self) -> bool {
        let offset_to_ns = unsafe { core::ptr::read_unaligned(&raw const self.offset_to_ns) };
        (offset_to_ns & 0x01) == 1
    }

    #[inline]
    pub fn set_ns(&mut self) {
        unsafe {
            let offset_to_ns = core::ptr::read_unaligned(&raw const self.offset_to_ns);
            core::ptr::write_unaligned(&raw mut self.offset_to_ns, offset_to_ns | 1);
        }
    }

    #[inline]
    pub fn unset_ns(&mut self) {
        unsafe {
            let offset_to_ns = core::ptr::read_unaligned(&raw const self.offset_to_ns);
            core::ptr::write_unaligned(&raw mut self.offset_to_ns, offset_to_ns & !0x1);
        }
    }

    /// Congestion window reduction flag.
    #[inline]
    pub fn cwr_flag(&self) -> bool {
        let flags = unsafe { core::ptr::read_unaligned(&raw const self.flags) };
        (flags & CWR) != 0
    }

    /// Set CWR flag to 1.
    #[inline]
    pub fn set_cwr_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags | CWR);
        }
    }

    /// Set CWR flag to 0.
    #[inline]
    pub fn unset_cwr_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags & !CWR);
        }
    }

    /// ECN echo flag.
    #[inline]
    pub fn ece_flag(&self) -> bool {
        let flags = unsafe { core::ptr::read_unaligned(&raw const self.flags) };
        (flags & ECE) != 0
    }

    /// Set ECE flag to 1.
    #[inline]
    pub fn set_ece_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags | ECE);
        }
    }

    /// Set ECE flag to 0.
    #[inline]
    pub fn unset_ece_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags & !ECE);
        }
    }

    /// Urgent pointer field is significant.
    #[inline]
    pub fn urg_flag(&self) -> bool {
        let flags = unsafe { core::ptr::read_unaligned(&raw const self.flags) };
        (flags & URG) != 0
    }

    /// Set URG flag to 1.
    #[inline]
    pub fn set_urg_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags | URG);
        }
    }

    /// Set URG flag to 0.
    #[inline]
    pub fn unset_urg_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags & !URG);
        }
    }

    /// Acknowledgment field is significant.
    #[inline]
    pub fn ack_flag(&self) -> bool {
        let flags = unsafe { core::ptr::read_unaligned(&raw const self.flags) };
        (flags & ACK) != 0
    }

    /// Set ACK flag to 1.
    #[inline]
    pub fn set_ack_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags | ACK);
        }
    }

    /// Set ACK flag to 0.
    #[inline]
    pub fn unset_ack_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags & !ACK);
        }
    }

    /// Push function: Push buffered data to receiving application.
    #[inline]
    pub fn psh_flag(&self) -> bool {
        let flags = unsafe { core::ptr::read_unaligned(&raw const self.flags) };
        (flags & PSH) != 0
    }

    /// Set PSH flag to 1.
    #[inline]
    pub fn set_psh_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags | PSH);
        }
    }

    /// Set PSH flag to 0.
    #[inline]
    pub fn unset_psh_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags & !PSH);
        }
    }

    /// Reset connection.
    #[inline]
    pub fn rst_flag(&self) -> bool {
        let flags = unsafe { core::ptr::read_unaligned(&raw const self.flags) };
        (flags & RST) != 0
    }

    /// Set RST flag to 1.
    #[inline]
    pub fn set_rst_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags | RST);
        }
    }

    /// Set RST flag to 0.
    #[inline]
    pub fn unset_rst_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags & !RST);
        }
    }

    /// Synchronize sequence number.
    #[inline]
    pub fn syn_flag(&self) -> bool {
        let flags = unsafe { core::ptr::read_unaligned(&raw const self.flags) };
        (flags & SYN) != 0
    }

    /// Set SYN flag to 1.
    #[inline]
    pub fn set_syn_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags | SYN);
        }
    }

    /// Set SYN flag to 0.
    #[inline]
    pub fn unset_syn_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags & !SYN);
        }
    }

    /// No more data transfer from sender.
    #[inline]
    pub fn fin_flag(&self) -> bool {
        let flags = unsafe { core::ptr::read_unaligned(&raw const self.flags) };
        (flags & FIN) != 0
    }

    /// Set FIN flag to 1.
    #[inline]
    pub fn set_fin_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags | FIN);
        }
    }

    /// Set FIN flag to 0.
    #[inline]
    pub fn unset_fin_flag(&mut self) {
        unsafe {
            let flags = core::ptr::read_unaligned(&raw const self.flags);
            core::ptr::write_unaligned(&raw mut self.flags, flags & !FIN);
        }
    }

    pub fn fmt_flags(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_or_return!(f, "| ");
        if self.ns_flag() {
            write_or_return!(f, "NS ")
        };
        if self.cwr_flag() {
            write_or_return!(f, "CWR ")
        };
        if self.ece_flag() {
            write_or_return!(f, "ECE ")
        };
        if self.urg_flag() {
            write_or_return!(f, "URG ")
        };
        if self.ack_flag() {
            write_or_return!(f, "ACK ")
        };
        if self.psh_flag() {
            write_or_return!(f, "PSH ")
        };
        if self.rst_flag() {
            write_or_return!(f, "RST ")
        };
        if self.syn_flag() {
            write_or_return!(f, "SYN ")
        };
        if self.fin_flag() {
            write_or_return!(f, "FIN ")
        };
        write!(f, "|")
    }

    /// Receive window.
    #[inline]
    pub fn window_size(&self) -> u16 {
        let raw_window = unsafe { core::ptr::read_unaligned(&raw const self.window) };
        u16::from_be(raw_window)
    }

    #[inline]
    pub fn set_window_size(&mut self, wnd: u16) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.window, u16::to_be(wnd));
        }
    }

    /// Checksum
    #[inline]
    pub fn checksum(&self) -> u16 {
        let raw_csum = unsafe { core::ptr::read_unaligned(&raw const self.csum) };
        u16::from_be(raw_csum)
    }

    #[inline]
    pub fn set_checksum(&mut self, csum: u16) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.csum, u16::to_be(csum));
        }
    }

    #[inline]
    pub fn update_checksum_incremental(&mut self, old_word: u16, new_word: u16) {
        unsafe {
            let current_csum = core::ptr::read_unaligned(&raw const self.csum);
            let new_csum = update_checksum_incremental(
                u16::from_be(current_csum),
                old_word,
                new_word,
            );
            core::ptr::write_unaligned(&raw mut self.csum, u16::to_be(new_csum));
        }
    }

    /// Urgent pointer
    #[inline]
    pub fn urgent(&self) -> u16 {
        let raw_urgent = unsafe { core::ptr::read_unaligned(&raw const self.urgent) };
        u16::from_be(raw_urgent)
    }

    #[inline]
    pub fn set_urgent(&mut self, urgent: u16) {
        unsafe {
            core::ptr::write_unaligned(&raw mut self.urgent, u16::to_be(urgent));
        }
    }
}