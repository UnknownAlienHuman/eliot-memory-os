//! Single-owner, fail-closed privacy erasure orchestration.
//!
//! This crate owns the erasure decision and its proof of completion.  It does
//! not own canonical storage, indexes, blobs, provider connections, or the
//! purge ledger.  Those remain behind [`ErasureBackend`].

#![forbid(unsafe_code)]

mod erasure_scope;
mod model;

pub use erasure_scope::*;
pub use model::*;

pub const CONTRACT_NAME: &str = "eliot.security.erasure";
/// Unchanged: this change is additive contract shapes only (new scope types
/// plus a digest binding; no wire, ledger, or canonical format break), and
/// the crate history sets this version once at introduction without a bump
/// convention for additive shapes.
pub const CONTRACT_VERSION: &str = "eliot-erasure-v1";
