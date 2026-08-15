//! P-06 durable, non-semantic Operational Recovery State (ORS).
//!
//! ORS stores opaque encrypted bytes or immutable locators plus the minimum
//! operational metadata needed to recover ordering and reconcile canonical
//! receipts. It never parses payload meaning, grants authority, or advances a
//! canonical ordering head.

#![forbid(unsafe_code)]

mod model;
mod store;

pub use model::*;
pub use store::{
    CanonicalEvidenceProvider, OperationalRecoveryStore, OrsCoordinator, RedbRecoveryStore,
};

/// Stable wire/storage contract version for this crate.
pub const CONTRACT_VERSION: u16 = 1;
/// Hard ceiling for one recovery page.
pub const MAX_RECOVERY_PAGE: u16 = 256;
/// Hard ceiling for ciphertext held inline by one ORS record.
pub const MAX_INLINE_RECOVERY_BYTES: u64 = 4 * 1024 * 1024;
/// Hard ceiling for one detached inbox signature.
pub const MAX_INBOX_SIGNATURE_BYTES: usize = 64 * 1024;

#[cfg(test)]
mod tests;
