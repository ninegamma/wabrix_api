//! Raw layouts exchanged through the shared Wasm mailbox.
//!
//! This module contains data layout only. Pointer arithmetic, packet parsing,
//! and other behavior remain in `wpdu_impl`, `packet`, and `mailbox_api`.

use crate::headers::HeaderKind;

/// Maximum number of packet descriptors in one mailbox batch.
pub const MAX_BATCH_SIZE: usize = 768;

/// Number of headers represented by [`HeaderStack`].
pub const MAX_HEADERS: usize = 5;

/// Parsed-header metadata stored at the start of every packet descriptor.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct HeaderStack {
    /// Offsets relative to the start of the packet data.
    pub offsets: [u16; MAX_HEADERS],
    /// Header kinds corresponding to `offsets`.
    pub kinds: [HeaderKind; MAX_HEADERS],
    /// Number of valid entries in the arrays above.
    pub hc: u8,
}

/// The 56-byte portable packet descriptor exchanged between host and guest.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct PduCore {
    /// Parsed header metadata.
    pub header_stack: HeaderStack,
    /// UMEM-relative packet-data offset.
    pub desc_addr: u64,
    /// Packet-data length.
    pub desc_len: u32,
    /// AF_XDP descriptor options.
    pub desc_options: u32,
    /// UMEM group containing the frame described by `desc_addr`.
    pub(crate) umem_group_id: u32,
    /// Base-2 logarithm of the frame size.
    pub frame_size_log2: u8,
    /// Worker that owns this frame.
    pub(crate) worker_id: u8,
    /// Packet flags.
    pub flags: u8,
    /// Host/plugin timer classification.
    pub timer_kind: u8,
    /// Hardware receive timestamp, when supplied by XDP metadata.
    pub rx_timestamp: u64,
    /// Host or plugin timestamp.
    pub timestamp: u64,
}

/// A 64-byte mailbox descriptor slot.
#[repr(C, align(64))]
pub struct SharedPdu {
    /// Portable packet state visible to the guest.
    pub w: PduCore,
    /// Opaque host-only state. Guests must never read or modify it.
    _do_not_touch_padding: u64,
}

/// Shared metadata mailbox for one Wasm instance.
#[repr(C)]
pub struct BatchMetadata {
    /// Packet descriptors written by the host and updated by the guest.
    pub pdus: [SharedPdu; MAX_BATCH_SIZE],
    /// Routing actions written by the guest.
    pub actions: [u32; MAX_BATCH_SIZE],
}

/// Explicit ABI names for consumers that do not use the historical Rust names.
pub type SharedMailbox = BatchMetadata;

const _: () = assert!(core::mem::size_of::<HeaderStack>() == 16);
const _: () = assert!(core::mem::size_of::<PduCore>() == 56);
const _: () = assert!(core::mem::size_of::<SharedPdu>() == 64);
const _: () = assert!(core::mem::align_of::<SharedPdu>() == 64);
const _: () = assert!(
    core::mem::size_of::<BatchMetadata>()
        == MAX_BATCH_SIZE * core::mem::size_of::<SharedPdu>()
            + MAX_BATCH_SIZE * core::mem::size_of::<u32>()
);

const _: () = {
    assert!(core::mem::offset_of!(HeaderStack, offsets) == 0);
    assert!(core::mem::offset_of!(HeaderStack, kinds) == 10);
    assert!(core::mem::offset_of!(HeaderStack, hc) == 15);
    assert!(core::mem::offset_of!(PduCore, header_stack) == 0);
    assert!(core::mem::offset_of!(PduCore, desc_addr) == 16);
    assert!(core::mem::offset_of!(PduCore, desc_len) == 24);
    assert!(core::mem::offset_of!(PduCore, desc_options) == 28);
    assert!(core::mem::offset_of!(PduCore, umem_group_id) == 32);
    assert!(core::mem::offset_of!(PduCore, frame_size_log2) == 36);
    assert!(core::mem::offset_of!(PduCore, worker_id) == 37);
    assert!(core::mem::offset_of!(PduCore, flags) == 38);
    assert!(core::mem::offset_of!(PduCore, timer_kind) == 39);
    assert!(core::mem::offset_of!(PduCore, rx_timestamp) == 40);
    assert!(core::mem::offset_of!(PduCore, timestamp) == 48);
    assert!(core::mem::offset_of!(SharedPdu, w) == 0);
    assert!(core::mem::offset_of!(SharedPdu, _do_not_touch_padding) == 56);
    assert!(core::mem::offset_of!(BatchMetadata, pdus) == 0);
    assert!(
        core::mem::offset_of!(BatchMetadata, actions)
            == MAX_BATCH_SIZE * core::mem::size_of::<SharedPdu>()
    );
};
