//! Single-owner, fail-closed privacy erasure orchestration.
//!
//! This crate owns the erasure decision and its proof of completion.  It does
//! not own canonical storage, indexes, blobs, provider connections, or the
//! purge ledger.  Those remain behind [`ErasureBackend`].

#![forbid(unsafe_code)]

mod model;

pub use model::*;

pub const CONTRACT_NAME: &str = "eliot.security.erasure";
pub const CONTRACT_VERSION: &str = "eliot-erasure-v1";
