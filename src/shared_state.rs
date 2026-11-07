//! Typed access to the host-validated shared state payload.
//!
//! The host supplies a payload offset and capacity through the shared-state
//! WIT import. This wrapper validates the size and alignment of `T`; plugins
//! still need to obey the single-active-writer lifecycle when dereferencing it.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};

/// A typed pointer into a host-validated shared state payload.
///
/// `T` should be a fixed-layout `repr(C)` value containing only fixed-width
/// fields and arrays. Do not place pointers, references, or allocation-owning
/// Rust values in shared state.
pub struct SharedState<T: Copy> {
    pointer: *mut T,
    _marker: PhantomData<T>,
}

impl<T: Copy> SharedState<T> {
    /// Construct a typed view from the payload size, offset, and capacity
    /// returned by the host's `shared-state.attach` import. When
    /// `upgrade_required` is true, the typed view describes the target schema;
    /// do not dereference it until `upgrade-shared-state` has initialized its
    /// appended fields.
    ///
    /// # Safety
    /// The offset and capacity must come from the host's validated state view
    /// for this instance. The caller must only dereference the view while this
    /// plugin instance has exclusive access to the shared payload.
    pub unsafe fn from_region(
        payload_offset: u32,
        current_payload_size: u32,
        payload_capacity: u32,
        upgrade_required: bool,
    ) -> Result<Self, String> {
        if payload_offset == 0 {
            return Err(String::from("shared-state payload offset is zero"));
        }
        let typed_size = size_of::<T>();
        if typed_size == 0 || typed_size > payload_capacity as usize {
            return Err(format!(
                "shared-state payload type requires {typed_size} bytes but capacity is {payload_capacity}"
            ));
        }
        if current_payload_size > payload_capacity {
            return Err(format!(
                "shared-state payload size {} exceeds capacity {}",
                current_payload_size, payload_capacity
            ));
        }
        if (upgrade_required && current_payload_size as usize > typed_size)
            || (!upgrade_required && current_payload_size as usize != typed_size)
        {
            return Err(format!(
                "shared-state payload size {current_payload_size} is incompatible with the {} byte guest type",
                typed_size
            ));
        }

        let alignment = align_of::<T>();
        if alignment > 64 || !(payload_offset as usize).is_multiple_of(alignment) {
            return Err(format!(
                "shared-state payload offset {payload_offset} does not meet alignment {alignment}"
            ));
        }

        Ok(Self {
            pointer: payload_offset as usize as *mut T,
            _marker: PhantomData,
        })
    }

    /// Return the instance-local guest pointer to the shared payload.
    #[inline]
    pub const fn as_ptr(&self) -> *mut T {
        self.pointer
    }

    /// Access the payload for one read operation.
    ///
    /// # Safety
    /// No other runtime may mutably access this payload for the duration of the
    /// callback. The returned reference must not escape the callback.
    pub unsafe fn with_ref<R>(&self, callback: impl FnOnce(&T) -> R) -> R {
        // SAFETY: The caller guarantees that this host-provided offset remains
        // mapped and that no mutable access overlaps the callback.
        callback(unsafe { &*self.pointer })
    }

    /// Access the payload for one write operation.
    ///
    /// # Safety
    /// This instance must be the sole reader/writer for the duration of the
    /// callback. The returned reference must not escape the callback.
    pub unsafe fn with_mut<R>(&mut self, callback: impl FnOnce(&mut T) -> R) -> R {
        // SAFETY: The caller guarantees exclusive lifecycle access and the
        // host-provided offset is mapped for at least `size_of::<T>()` bytes.
        callback(unsafe { &mut *self.pointer })
    }
}
