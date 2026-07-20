use crate::exports::Pdu0;
use crate::packet::Packet;
use crate::BatchMetadata;

// =============================================================================
// MAILBOX-BASED ZERO-COPY API
// =============================================================================

/// A batch backed by the shared UMEM mailbox rather than an inline byte slice.
///
/// The host writes `pdus` into the `BatchMetadata` before calling `process-batch`.
/// The plugin processes each packet in place, then writes routing decisions back
/// into `actions`.
pub struct MailboxBatch<'a> {
    pdus: &'a mut [Pdu0],
    actions: &'a mut [u32],
    umem_base: usize,
}

impl<'a> MailboxBatch<'a> {
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

        // SAFETY: The host guarantees `mailbox_ptr` points to a valid, exclusively-owned
        // `BatchMetadata` for the duration of the `process-batch` call.
        let mailbox = unsafe { &mut *mailbox_ptr };
        let len = batch_size as usize;

        Self {
            pdus: &mut mailbox.pdus[..len],
            actions: &mut mailbox.actions[..len],
            umem_base,
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.pdus.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.pdus.is_empty()
    }

    /// Iterates over each packet slot, yielding a `MailboxPacket` for each one.
    #[inline(always)]
    pub fn iter_mut(&mut self) -> MailboxBatchIter<'_> {
        MailboxBatchIter {
            iter: self.pdus.iter_mut().zip(self.actions.iter_mut()),
            umem_base: self.umem_base,
        }
    }
}

impl<'a> IntoIterator for MailboxBatch<'a> {
    type Item = MailboxPacket<'a>;
    type IntoIter = MailboxBatchIter<'a>;

    #[inline(always)]
    fn into_iter(self) -> Self::IntoIter {
        MailboxBatchIter {
            iter: self.pdus.iter_mut().zip(self.actions.iter_mut()),
            umem_base: self.umem_base,
        }
    }
}

/// Iterator over `MailboxBatch` that yields one `MailboxPacket` per slot.
pub struct MailboxBatchIter<'a> {
    iter: core::iter::Zip<core::slice::IterMut<'a, Pdu0>, core::slice::IterMut<'a, u32>>,
    umem_base: usize,
}

impl<'a> Iterator for MailboxBatchIter<'a> {
    type Item = MailboxPacket<'a>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        let (pdu, action) = self.iter.next()?;
        Some(MailboxPacket {
            pdu,
            umem_base: self.umem_base,
            action,
        })
    }
}

/// A single packet slot from a `MailboxBatch`.
///
/// Holds a direct mutable reference into the host-written `Pdu0` in the mailbox.
/// Call `parse_fast()` before accessing any header accessors. Write the routing
/// decision back via `set_action()`.
pub struct MailboxPacket<'a> {
    pdu: &'a mut Pdu0,
    umem_base: usize,
    action: &'a mut u32,
}

impl<'a> MailboxPacket<'a> {
    /// Parse packet headers. Must be called before `fingerprint()` or any header
    /// accessor on a `Packet` obtained via `as_packet()`.
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
    pub fn data_len(&self) -> u32 {
        self.pdu.data_len()
    }

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

    /// Creates a temporary `Packet<'_>` that borrows this packet's `Pdu0`.
    /// Use this to call functions that take `&mut Packet<'_>` (e.g. `handle_tcp_packet`).
    #[inline(always)]
    pub fn as_packet(&mut self) -> Packet<'_> {
        Packet::new(self.pdu, self.umem_base)
    }

    /// Write the routing decision for this packet back into the mailbox.
    #[inline(always)]
    pub fn set_action(&mut self, action: u32) {
        *self.action = action;
    }
}
