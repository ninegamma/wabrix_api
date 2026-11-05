use crate::headers::{Header, HeaderKind};
pub use crate::shared_memory::HeaderStack;
use crate::shared_memory::MAX_HEADERS;
use core::fmt;

impl HeaderStack {
    #[inline]
    pub fn new() -> Self {
        HeaderStack {
            offsets: [0; MAX_HEADERS],
            kinds: [HeaderKind::Null; MAX_HEADERS],
            hc: 0,
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.hc = 0;
    }

    #[inline]
    pub fn push(&mut self, base_addr: usize, h: Header) {
        let idx = self.hc as usize;
        if idx >= MAX_HEADERS {
            // TODO: return an Err
            panic!(
                "HeaderStack overflow: cannot push more than {} headers",
                MAX_HEADERS
            );
        }
        self.kinds[idx] = h.kind();

        let h_addr = h.as_ptr_u8().unwrap() as usize;
        debug_assert!(
            h_addr >= base_addr,
            "Header address is before base pointer!"
        );
        debug_assert!(
            h_addr - base_addr <= u16::MAX as usize,
            "Header offset exceeds u16!"
        );
        self.offsets[idx] = (h_addr - base_addr) as u16;
        self.hc += 1;
    }

    /// Internal helper to reconstruct the Header enum on the fly
    #[inline]
    fn reconstruct(&self, base_addr: usize, which: usize) -> Header {
        debug_assert!(
            which < self.hc as usize,
            "Attempted to access uninitialized header!"
        );
        let ptr_addr = base_addr + self.offsets[which] as usize;
        Header::from_kind_and_ptr(self.kinds[which], ptr_addr as *mut u8)
    }

    /// a fingerprint of the protocol stack. Returns a u32 where every 4 bits represent a HeaderKind
    #[inline]
    pub fn fingerprint(&self) -> u32 {
        let mut f = 0u32;
        for i in 0..self.hc as usize {
            f |= (self.kinds[i] as u32) << (i * 4);
        }
        f
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.hc as usize
    }

    /// Note: To keep the API returning `&Header`, the Header objects
    /// would need to be stored. However, if Header is a "View" type
    /// (pointer wrapper), returning it by value is more efficient.
    /// If you MUST return a reference, see the 'Storage' note below.
    /// The specific typed accessors (tcp_mut, etc.) use raw pointer arithmetic
    /// based on the offsets stored during parsing.
    #[inline]
    pub fn get(&self, base_addr: usize, which: usize) -> Header {
        self.reconstruct(base_addr, which)
    }

}

impl Default for HeaderStack {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for HeaderStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.hc == 0 {
            write!(f, "<no headers>")
        } else {
            for i in 0..self.hc as usize {
                writeln!(
                    f,
                    "{:1}: {:?} at offset {}",
                    i, self.kinds[i], self.offsets[i]
                )?;
            }
            Ok(())
        }
    }
}
