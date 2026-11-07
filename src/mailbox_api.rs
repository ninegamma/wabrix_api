use crate::packet::{Packet, PacketBatch, PacketBatchIter};
use crate::shared_memory::SharedMailbox;

// =============================================================================
// MAILBOX-BASED ZERO-COPY API
// =============================================================================

/// A batch backed by the instance's private Wasm-memory mailbox rather than an
/// inline byte slice.
///
/// The host writes `pdus` into the shared mailbox before calling `process-batch`.
/// The plugin processes each packet in place, then writes routing decisions back
/// into `actions`.
/// A batch of mailbox packets, wrapping a standard `PacketBatch`.
pub struct MailboxBatch<'a> {
    batch: PacketBatch<'a>,
    // Additional mailbox-specific ring pointers or action slices
    actions: &'a mut [u32],
}

impl<'a> MailboxBatch<'a> {
    #[inline(always)]
    pub fn new(batch_size: u32, umem_offset: u32, mailbox_offset: u32) -> Self {
        let umem_base = umem_offset as usize;
        // `mailbox_offset` is an address in the Wasm linear memory. Packet
        // descriptors remain UMEM-relative and use `umem_base` below.
        let mailbox_ptr = mailbox_offset as usize as *mut SharedMailbox;

        // SAFETY: The host guarantees `mailbox_ptr` points to a valid, exclusively-owned
        // `SharedMailbox` for the duration of the `process-batch` call.
        let mailbox = unsafe { &mut *mailbox_ptr };
        let len = batch_size as usize;

        Self {
            batch: PacketBatch {
                pdus: &mut mailbox.pdus[..len],
                umem_base,
            },
            actions: &mut mailbox.actions[..len],
        }
    }

    /// Custom batch-level method unique to mailboxes
    #[inline(always)]
    pub fn flush_actions(&mut self) {
        // Mailbox-specific ring submission logic
    }

    #[inline(always)]
    pub fn iter_mut(&mut self) -> MailboxBatchIter<'_> {
        MailboxBatchIter {
            packet_iter: self.batch.iter_mut(),
            action_iter: self.actions.iter_mut(),
        }
    }
}

// =====================================================================
// MAGIC: Deref Coercion for Batches
// =====================================================================

impl<'a> core::ops::Deref for MailboxBatch<'a> {
    type Target = PacketBatch<'a>;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<'a> core::ops::DerefMut for MailboxBatch<'a> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.batch
    }
}

pub struct MailboxBatchIter<'a> {
    packet_iter: PacketBatchIter<'a>,
    // An iterator or slice over the concurrent action buffer
    action_iter: core::slice::IterMut<'a, u32>,
}

impl<'a> Iterator for MailboxBatchIter<'a> {
    type Item = MailboxPacket<'a>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        // Pull the next standard packet and the next mutable action reference simultaneously
        let packet = self.packet_iter.next()?;

        // SAFETY: `packet_iter` and `action_iter` are initialized from slices
        // of the exact same length in `MailboxBatch::new`. If packet is Some,
        // action is guaranteed to be Some.
        let action = unsafe { self.action_iter.next().unwrap_unchecked() };

        Some(MailboxPacket::new(packet, action))
    }
}

/// A single packet slot from a `MailboxBatch`.
///
/// Wraps a standard `Packet<'a>` and adds mailbox-specific action handling.
pub struct MailboxPacket<'a> {
    packet: Packet<'a>,
    action: &'a mut u32,
}

impl<'a> MailboxPacket<'a> {
    #[inline(always)]
    pub fn new(packet: Packet<'a>, action: &'a mut u32) -> Self {
        Self { packet, action }
    }

    /// Write the routing decision for this packet back into the mailbox.
    #[inline(always)]
    pub fn set_action(&mut self, action: u32) {
        *self.action = action;
    }

    /// Optional: If code specifically expects to unwrap into a standard Packet reference
    #[inline(always)]
    pub fn as_packet(&mut self) -> &mut Packet<'a> {
        &mut self.packet
    }
}

// =====================================================================
// MAGIC: Deref Coercion lets MailboxPacket inherit all Packet methods!
// =====================================================================

impl<'a> core::ops::Deref for MailboxPacket<'a> {
    type Target = Packet<'a>;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

impl<'a> core::ops::DerefMut for MailboxPacket<'a> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.packet
    }
}
