use core::marker::PhantomData;
use crate::BatchMetadata;
use crate::exports::{Pdu0, WPdu};
use crate::packet::Packet;

// =============================================================================
// MAILBOX-BASED ZERO-COPY API
// =============================================================================

/// A batch backed by the shared UMEM mailbox rather than an inline byte slice.
///
/// The host writes `desc_addrs` and `lengths` into the `BatchMetadata` before
/// calling `process-batch`. The plugin reads them, processes each packet in
/// place, then writes routing decisions back into `actions` / `new_lengths`.
pub struct MailboxBatch {
    mailbox_ptr: *mut BatchMetadata,
    batch_size: usize,
    umem_base: usize,
}

// SAFETY: WASM is single-threaded; the raw pointer is valid for the lifetime of the call.
unsafe impl Send for MailboxBatch {}

impl MailboxBatch {
    /// Constructs a `MailboxBatch` from the three arguments passed by the host.
    ///
    /// - `batch_size`: number of valid slots in the mailbox.
    /// - `partition_offset`: equals `partition_start_bytes` for this instance; used to compute
    ///   `umem_base = 0u32.wrapping_sub(partition_offset) as usize`.
    /// - `mailbox_offset`: UMEM-relative byte offset to this instance's `BatchMetadata`.
    #[inline(always)]
    pub fn new(batch_size: u32, partition_offset: u32, mailbox_offset: u32) -> Self {
        let umem_base = (0u32).wrapping_sub(partition_offset) as usize;
        let mailbox_ptr = (umem_base + mailbox_offset as usize) as *mut BatchMetadata;
        Self { mailbox_ptr, batch_size: batch_size as usize, umem_base }
    }

    #[inline(always)]
    pub fn len(&self) -> usize { self.batch_size }

    #[inline(always)]
    pub fn is_empty(&self) -> bool { self.batch_size == 0 }

    /// Iterates over each packet slot, yielding a `MailboxPacket` for each one.
    /// The iterator pre-populates a local `WPdu` from the mailbox's `desc_addrs`/`lengths`.
    #[inline(always)]
    pub fn iter_mut(&mut self) -> MailboxBatchIter<'_> {
        MailboxBatchIter {
            mailbox_ptr: self.mailbox_ptr,
            umem_base: self.umem_base,
            idx: 0,
            total: self.batch_size,
            _phantom: PhantomData,
        }
    }
}

/// Iterator over `MailboxBatch` that yields one `MailboxPacket` per slot.
pub struct MailboxBatchIter<'a> {
    mailbox_ptr: *mut BatchMetadata,
    umem_base: usize,
    idx: usize,
    total: usize,
    _phantom: PhantomData<&'a mut BatchMetadata>,
}

impl<'a> Iterator for MailboxBatchIter<'a> {
    type Item = MailboxPacket<'a>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.total {
            return None;
        }
        // SAFETY: idx < total, which is bounded by the host-provided batch_size (<= MAX_BATCH_SIZE).
        let (desc_addr, length) = unsafe {
            let m = &*self.mailbox_ptr;
            (m.desc_addrs[self.idx], m.lengths[self.idx])
        };

        let mut wpdu = WPdu::default();
        wpdu.desc_addr = desc_addr as u64;
        wpdu.desc_len  = length;

        let item = MailboxPacket {
            pdu: Pdu0::local(wpdu),
            umem_base: self.umem_base,
            idx: self.idx,
            mailbox_ptr: self.mailbox_ptr,
            _phantom: PhantomData,
        };
        self.idx += 1;
        Some(item)
    }
}

/// A single packet slot from a `MailboxBatch`.
///
/// Owns a local `Pdu0` populated from the mailbox inputs. Call `parse_fast()` before
/// accessing any header accessors. Writes results back to the mailbox via
/// `set_action()` / `set_new_length()`.
///
/// As Pdu0 must not be dropped, dropping is prevented here using `ManuallyDrop`.
pub struct MailboxPacket<'a> {
    pdu: core::mem::ManuallyDrop<Pdu0>,
    umem_base: usize,
    idx: usize,
    mailbox_ptr: *mut BatchMetadata,
    _phantom: PhantomData<&'a mut BatchMetadata>,
}

impl<'a> MailboxPacket<'a> {
    /// Parse packet headers into the local `WPdu`. Must be called before `fingerprint()` or
    /// any header accessor on a `Packet` obtained via `as_packet()`.
    #[inline(always)]
    pub fn parse_fast(&mut self) -> usize {
        self.pdu.parse_fast(self.umem_base)
    }

    /// Returns `true` if this packet carries the 0x88B5 "tick" EtherType.
    /// Does NOT require `parse_fast()` to have been called first.
    #[inline(always)]
    pub fn is_a_tick(&self) -> bool {
        self.pdu.is_a_tick(self.umem_base)
    }

    /// Original packet length as supplied by the host.
    #[inline(always)]
    pub fn data_len(&self) -> u32 { self.pdu.data_len() }

    /// Raw mutable pointer to the start of the packet payload within WASM linear memory.
    #[inline(always)]
    pub fn data_ptr_mut(&mut self) -> *mut u8 {
        self.pdu.data_ptr(self.umem_base)
    }

    /// Protocol fingerprint from the header stack (populated by `parse_fast()`).
    #[inline(always)]
    pub fn fingerprint(&self) -> u32 {
        self.pdu.header_stack.fingerprint()
    }

    /// Creates a temporary `Packet<'_>` that borrows this packet's local `WPdu`.
    /// Use this to call functions that take `&mut Packet<'_>` (e.g. `handle_tcp_packet`).
    /// The borrow ends when the returned `Packet` is dropped.
    #[inline(always)]
    pub fn as_packet(&mut self) -> Packet<'_> {
        Packet::new(&mut *self.pdu, self.umem_base)
    }

    /// Write the routing decision for this packet back into the mailbox.
    #[inline(always)]
    pub fn set_action(&mut self, action: u32) {
        // SAFETY: idx < batch_size (enforced by iterator), mailbox_ptr is valid for the call window.
        unsafe { (*self.mailbox_ptr).actions[self.idx] = action; }
    }

    /// Write the new packet length back into the mailbox.
    /// Pass `0` to leave the length unchanged (the host will keep the original).
    #[inline(always)]
    pub fn set_new_length(&mut self, new_len: u32) {
        // SAFETY: same as set_action.
        unsafe { (*self.mailbox_ptr).new_lengths[self.idx] = new_len; }
    }
}
