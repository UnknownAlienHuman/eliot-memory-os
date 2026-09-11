//! Deterministic, bounded cue-snapshot construction from A-10 projections.
//!
//! The builder is a bounded strict all-or-error prototype: it accepts active
//! records with exact freshness and supported evidence statuses, caps measured
//! input at 512 KiB, and sorts the resulting member set deterministically. The
//! registry revision is optional only for zero-edge builds. It remains a
//! candidate producer and does not authenticate admission, publish a snapshot,
//! run activation, or provide a complete rejection report.
//!
#![forbid(unsafe_code)]

mod bounds;
mod build;

pub use build::{build_cue_snapshot, rebuild_cue_snapshot};
