//! Bounded A14 cue activation.
//!
//! This prototype evaluates a supplied A10 `CueSnapshotBuildCandidate` under a
//! caller-supplied, versioned numerical profile. It supports exact-first direct
//! matching and forward-only bounded spreading. It performs no normalization,
//! indexing, I/O, admission, publication or authority decision.
//!
//! Row lifecycle must be `Active`; candidate and evidence freshness must be one
//! of the three exact labels accepted by this prototype, with epistemic status
//! `Observed`, `Supported` or `Verified`. A14 uses the reused A10 independent
//! limits and requires the profile bounds to equal the request bounds. The
//! numerical profile is caller supplied, unbenchmarked and never default enabled.
//! Full currentness/authentication, registry authorization, publication and the
//! complete 42-case matrix remain outside this prototype.
#![forbid(unsafe_code)]

mod error;
mod evaluate;
mod profile;

pub use error::ActivationError;
pub use evaluate::{CueActivationEvaluation, evaluate_activation};
pub use profile::{ACTIVATION_PROFILE_REVISION, ActivationProfile, MatchRule, RelationRule};
