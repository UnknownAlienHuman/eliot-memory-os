//! Bounded A14 cue activation.
//!
//! This prototype evaluates a supplied A10 `CueSnapshotBuildCandidate` under a
//! caller-supplied, versioned numerical profile. It supports exact-first direct
//! matching and bounded relation spreading. It performs no normalization,
//! indexing, I/O, admission, publication or authority decision.
//!
//! Row lifecycle must be `Active`; candidate and evidence freshness must be one
//! of the three exact labels accepted by this prototype, with epistemic status
//! `Observed`, `Supported` or `Verified`. A14 uses the reused A10 independent
//! limits and requires the profile bounds to equal the request bounds. The
//! numerical profile is caller supplied and unbenchmarked.
//!
//! Two seams keep the runtime obligations outside the pure evaluator:
//!
//! - [`evaluate_published_activation`] binds an owner-resolved
//!   [`PublicationGrant`] before evaluating, so a build candidate is never
//!   evaluated as a live publication and a limited direct read stays explicit.
//!   [`evaluate_activation`] remains the pure seam over supplied inputs.
//! - [`resolve_enablement`] decides whether relation spreading is enabled at
//!   all. Its default answer is [`SpreadEnablement::Disabled`]: an unbenchmarked
//!   profile has no path to being enabled by not being asked about, and only an
//!   immutable [`SpreadQualification`] bound to the exact weights, registry,
//!   normalization revision and runtime identity can enable it.
//!
//! Derived activations are advisory retrieval signals. [`classify`] states what
//! a consumer may do with a result, and a derived-only result is never blocking.
//! Full currentness/authentication, registry authorization, publication and the
//! complete 42-case matrix remain outside this prototype.
#![forbid(unsafe_code)]

pub mod advisory;
pub mod derived_stage;
mod error;
mod evaluate;
mod profile;
pub mod publication;
pub mod qualification;

pub use advisory::{CueUse, blocking_evidence, classify, direct_activations};
pub use error::ActivationError;
pub use evaluate::{CueActivationEvaluation, evaluate_activation, evaluate_published_activation};
pub use profile::{
    ACTIVATION_PROFILE_REVISION, ActivationProfile, MatchRule, RelationDirection, RelationRule,
};
pub use publication::{
    DirectReadLimit, DirectReadLimitation, DisclosureInfluenceState, PublicationGrant,
};
pub use qualification::{
    QualificationRefusal, SpreadEnablement, SpreadQualification, resolve_enablement,
};
