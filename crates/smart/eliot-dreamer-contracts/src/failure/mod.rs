//! Provider-neutral typed Failure curation handoff (A-03).
//!
//! This module validates bounded structural joins and emits inert candidate
//! artifacts. It does not classify triggers, decide blocks, mutate memory, or
//! grant authority; those decisions remain with the owning downstream brief.

#![forbid(unsafe_code)]

mod input;
mod records;
mod result;

pub use input::{FailureInput, failure_input_digest, validate_failure};
pub use records::{
    FailureAction, FailureActionEvidence, FailureApplicability, FailureCausalStatus, FailureClass,
    FailureComparator, FailureComparisonProfile, FailureControlRecord, FailureCoverage,
    FailureDimension, FailureDimensionDescriptor, FailureDimensionSource, FailureDimensionValue,
    FailureEnvironment, FailureEvidence, FailureEvidenceKind, FailureExpectation,
    FailureExpectedState, FailureHistory, FailureHistoryEntry, FailureHypothesis, FailureLifecycle,
    FailureMitigation, FailureObservationState, FailureOperation, FailureOutcome,
    FailureProfileDefinition, FailureProposal, FailureReceiptMaterial, FailureRollback,
    FailureSourceMember, SCHEMA_VERSION,
};
pub use result::{
    FailureCandidate, FailureDisposition, FailureResult, failure_proposal_digest,
    failure_result_digest, seal_failure,
};

/// Alias documenting that the shared I9.7 preservation report is the exact
/// subtype used by Failure; no donor-shaped report is introduced here.
pub type FailurePreservation = crate::relation::RelationPreservation;
