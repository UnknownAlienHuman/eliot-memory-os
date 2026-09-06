//! Provider-neutral cue vocabulary: observation, identity, binding, snapshot
//! and bounded activation.
//!
//! This cell owns schemas, canonical identities and intrinsic validation. It
//! runs no normalization algorithm, builds no index, traverses no graph and
//! performs no I/O. Its consumers — A-11 normalizer, A-12 binding, A-13 index,
//! A-14a activation, A-16a context candidates — share this one vocabulary so a
//! cue writer and a cue reader agree without importing each other.
//!
//! The type system keeps these apart, because collapsing any two of them is how
//! a retrieval proposal turns into a claim it never earned:
//!
//! ```text
//! observed source material
//!     != canonical cue identity
//!     != comparison key
//!     != admitted binding
//!     != snapshot membership
//!     != direct match
//!     != relation-derived activation
//! ```
//!
//! `declared_support: TARGET` per `I0.5`. Nothing here is product evidence.
//!
//! Normative sources: `docs/architecture/I12-06-cue-binding.md`,
//! `docs/architecture/I12-07-cue-index.md`,
//! `docs/architecture/I12-15-bounded-spreading-activation.md`,
//! `docs/architecture/I05-15-canonical-contract-catalogue.md`,
//! `docs/architecture/I05-16-common-durable-fields.md`,
//! `docs/architecture/I07-20-agent-facing-error-contract.md`.

#![forbid(unsafe_code)]

mod activation;
mod binding;
mod error;
mod identity;
mod normalization;
mod observation;
mod snapshot;

pub use activation::{
    ActivationBounds, ActivationRequest, ActivationResult, ActivationStrength, ActivationTrace,
    BoundKind, Completeness, DerivedActivation, DirectActivation, RelationEdgeInput, TraceStep,
};
pub use binding::{BindingDisposition, BindingRole, CueBindingCandidate};
pub use error::CueContractError;
pub use identity::{
    ActivationRequestId, BindingCandidateId, CanonicalCueId, ComparisonKeyId, Digest,
    ObservedCueId, RelationEdgeId, SnapshotId, TargetHandle,
};
pub use normalization::{
    CanonicalCueIdentity, ComparisonKey, CueKind, MatchMode, NormalizationOutcome,
    NormalizationProfile, NormalizedCue, TransformationStep,
};
pub use observation::{ObservedCue, SourceHandle};
pub use snapshot::{CueSnapshot, RebuildIdentity, SnapshotMember};

/// Schema revision of this vocabulary. A change to any wire shape changes it.
pub const CONTRACT_REVISION: &str = "1.0.0";

/// Maximum comparison keys one canonical identity may carry.
///
/// `EmpiricalParameter` status `UNVALIDATED` per `I2.16`: it guides planning and
/// bounds the wire, and by itself it neither blocks an action nor certifies one.
pub const MAX_COMPARISON_KEYS: usize = 8;

/// Maximum ordered transformation steps recorded for one normalization.
///
/// `EmpiricalParameter` status `UNVALIDATED`.
pub const MAX_TRANSFORMATION_STEPS: usize = 16;

/// Maximum seeds accepted in one activation request.
///
/// `EmpiricalParameter` status `UNVALIDATED`.
pub const MAX_SEEDS: usize = 64;

/// Maximum relation edges accepted in one activation request.
///
/// `EmpiricalParameter` status `UNVALIDATED`.
pub const MAX_RELATION_EDGES: usize = 4096;

/// Maximum direct activations one result may carry.
///
/// `EmpiricalParameter` status `UNVALIDATED`.
pub const MAX_DIRECT: usize = 256;

/// Maximum relation-derived activations one result may carry.
///
/// `EmpiricalParameter` status `UNVALIDATED`.
pub const MAX_DERIVED: usize = 512;

/// Maximum hops in one derived activation path.
///
/// `EmpiricalParameter` status `UNVALIDATED`.
pub const MAX_PATH_LEN: usize = 8;

/// Maximum members one snapshot may carry.
///
/// `EmpiricalParameter` status `UNVALIDATED`.
pub const MAX_SNAPSHOT_MEMBERS: usize = 65_536;

/// Maximum recorded steps in one activation trace.
///
/// `EmpiricalParameter` status `UNVALIDATED`.
pub const MAX_TRACE_STEPS: usize = 1024;

pub(crate) fn bound<T>(
    items: &[T],
    limit: usize,
    field: &'static str,
) -> Result<(), CueContractError> {
    if items.len() > limit {
        return Err(CueContractError::BoundExceeded { field, limit });
    }
    Ok(())
}
