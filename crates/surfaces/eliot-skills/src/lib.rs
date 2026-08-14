//! Pure, fail-closed contracts for generated short Skills and host packages.
//!
//! This surface materializes a package projection only.  It does not own Skill
//! definition, activation, conflict resolution, execution, authority, storage,
//! process, network, or lifecycle state.  Those concerns remain with G-16 and
//! the governed runtime owners.

#![forbid(unsafe_code)]

mod contract;

pub use contract::*;

/// Stable package contract name.
pub const CONTRACT_NAME: &str = "eliot.surface.skills";
/// Current package contract revision.
pub const CONTRACT_REVISION: &str = "1.0.0";
