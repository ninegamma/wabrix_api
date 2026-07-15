// src/exports

// ============================================================================
// HOST ACCESS:
// If the 'host' feature is enabled in Cargo.toml, WPdu becomes fully public.
// ============================================================================
#[cfg(feature = "host")]
pub use crate::wpdu_impl::*;
#[cfg(feature = "host")]
pub use crate::hstack::*;

// ============================================================================
// PUBLIC/PLUGIN ACCESS:
// If the 'host' feature is NOT enabled, WPdu is restricted to crate-internal use.
// ============================================================================
#[cfg(not(feature = "host"))]
pub(crate) use crate::wpdu_impl::*;
#[cfg(not(feature = "host"))]
pub(crate) use crate::hstack::*;