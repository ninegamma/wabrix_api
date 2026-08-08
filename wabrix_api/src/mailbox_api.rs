use crate::packet::{Packet, PacketBatch, PacketBatchIter};
use crate::{BatchMetadata, MAX_BATCH_SIZE};

// =============================================================================
// MAILBOX-BASED ZERO-COPY API
// =============================================================================

/// A batch backed by the shared UMEM mailbox in host-provided packet memory.
///
/// To preserve strict zero-copy semantics, data must not be buffered in the primary memory.
/// The WIT entry point supplies an absolute mailbox offset; construction turns it into bounded,
/// disjoint PDU and action views once, before entering the per-packet loop.
pub struct MailboxBatch<'a> {
    batch: PacketBatch<'a>,
    action_base: u32,
}

impl<'a> MailboxBatch<'a> {
    #[inline(always)]
    pub fn new(batch_size: u32, mailbox_offset: u32) -> Self {
        let len = (batch_size as usize).min(MAX_BATCH_SIZE);
        let action_offset = mailbox_offset as usize + core::mem::offset_of!(BatchMetadata, actions);

        // SAFETY: The ABI grants exclusive access to `len` PDU slots in this mailbox.
        let batch = unsafe { PacketBatch::from_packet_memory(len, mailbox_offset) };
        Self {
            batch,
            action_base: action_offset as u32,
        }
    }

    /// Flushes mutated actions.
    ///
    /// Mailbox writes are immediate, so no deferred flush or bulk copy is required.
    #[inline(always)]
    pub fn flush_actions(&mut self) {}

    #[inline(always)]
    pub fn iter_mut(&mut self) -> MailboxBatchIter<'_> {
        MailboxBatchIter {
            packet_iter: self.batch.iter_mut(),
            next_action: self.action_base,
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
    next_action: u32,
}

impl<'a> Iterator for MailboxBatchIter<'a> {
    type Item = MailboxPacket<'a>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        let packet = self.packet_iter.next()?;
        let action_offset = self.next_action;
        self.next_action += core::mem::size_of::<u32>() as u32;
        Some(MailboxPacket::new(packet, action_offset))
    }
}

/// A single packet slot from a `MailboxBatch`.
pub struct MailboxPacket<'a> {
    packet: Packet<'a>,
    action_offset: u32,
}

impl<'a> MailboxPacket<'a> {
    #[inline(always)]
    pub fn new(packet: Packet<'a>, action_offset: u32) -> Self {
        Self {
            packet,
            action_offset,
        }
    }

    /// Writes the routing decision directly into the mailbox.
    #[inline(always)]
    pub fn set_action(&mut self, action: u32) {
        // SAFETY: The iterator assigns one exclusive action slot to each packet.
        unsafe { crate::umem::write(self.action_offset, &action) }
    }

    /// Provides access to the standard Packet reference if explicitly required.
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
