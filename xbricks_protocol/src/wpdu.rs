// src/wpdu.rs

// ============================================================================
// HOST ACCESS: 
// If the 'host' feature is enabled in Cargo.toml, WPdu becomes fully public.
// ============================================================================
#[cfg(feature = "host")]
pub use crate::wpdu_impl::*;

// ============================================================================
// PUBLIC/PLUGIN ACCESS: 
// If the 'host' feature is NOT enabled, WPdu is restricted to crate-internal use.
// ============================================================================
#[cfg(not(feature = "host"))]
pub(crate) use crate::wpdu_impl::*;