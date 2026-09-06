//! Versioned store-neutral contracts for the Current Epistemic Position.
//!
//! This crate owns the versioned, owner-neutral types crossing the position boundary: identity, requests,
//! grades, support, denominators, receipts, absence, claim maps, provenance, assumptions, investigations,
//! verifiers, temporal roles, causal claims, conflicts, candidates, admitted views, assertability, and
//! transitions. Foundation vocabularies are reused, never redefined. The crate resolves, acquires, ranks,
//! stores, and applies nothing; unknown, assumed, conflicted, and stale stay distinct; every load-bearing
//! mutation invalidates the frozen digest. Donor notes: request, position, provenance (subsuming
//! `ProvenanceView`), and assumption/investigation fields harden the donor scope of
//! `crates/smart/eliot-epistemic/src/lib.rs`; donor `resolve`, `provenance_for`, and `lowest_assertability`
//! are resolver policy, not carried.

#![forbid(unsafe_code)]

pub mod absence;
pub mod admitted;
pub mod assertability;
pub mod assumption;
pub mod candidate;
pub mod causal;
pub mod claim_map;
pub mod conflict;
pub mod coverage;
pub mod error;
pub mod grade;
pub mod identity;
pub mod investigation;
pub mod provenance;
pub mod receipt;
pub mod request;
pub mod support;
pub mod temporal;
pub mod transition;
pub mod verifier;

#[cfg(test)]
mod tests;

pub use absence::{AbsenceClaim, BoundedProof, OwnerLookup};
pub use admitted::{
    AdmittedKind, AdmittedReceipt, CurrentEpistemicPosition, CurrentEpistemicPositionView,
    Currentness, PositionId, PositionRevision, PositionState,
};
pub use assertability::PositionAssertability;
pub use assumption::{AssumptionKind, AssumptionRecord, AssumptionRetraction};
pub use candidate::{CandidateKind, EpistemicPositionCandidate};
pub use causal::{CausalClaim, CausalStatus};
pub use claim_map::{ClaimAuditOutcome, ClaimEntry, ClaimMap, ClaimVerdict, DependenceGroup};
pub use conflict::{
    ArgumentAcceptability, ConflictKind, ConflictLifecycle, ConflictPosition, ConflictSet,
};
pub use coverage::{
    CoverageDenominator, DenominatorKind, ExclusionRecord, FrontierSpec, PaginationBounds,
    QuerySpec, SnapshotRef,
};
pub use error::{
    ContractError, MAX_HANDLES, MAX_MEMBERS, MAX_POSITIONS, MAX_PROOF_BYTES, MAX_SHORT_TEXT,
    MAX_STATEMENT_TEXT,
};
pub use grade::{EvidenceGrade, GRADE_ORDER, GradeAssignment};
pub use identity::{
    ClaimId, EvidenceSetId, IdentityBundle, LineageRootId, ManifestId, PredecessorId,
    PropositionId, SourceRevisionId, TransformedLineage, ValidityId,
};
pub use investigation::{InvestigationKind, InvestigationRequirement, RequirementKind};
pub use provenance::{ProvenanceClosure, ProvenanceClosureKind, SourceLineage};
pub use receipt::{CoverageReceipt, MemberDisposition, MemberOutcome, OmittedMember};
pub use request::{PositionRequest, RequestKind};
pub use support::{SupportRecord, SupportResult, ValidityBounds, weakest_link};
pub use temporal::{TemporalPrecedence, TemporalRecord, TemporalRole};
pub use transition::{
    EpistemicTransition, InvalidationKind, InvalidationRecord, SupportDelta, TransitionTrigger,
};
pub use verifier::{
    DisclosureClass, PrivacyHandling, RequiredVerifier, SourceAssurance, VerifierStanding,
};

/// Stable identity of this contract surface.
pub const CONTRACT_NAME: &str = "eliot.smart.epistemic-contracts";
/// Current wire revision of this contract surface: prototype wire, where minor revisions add hardened
/// families (request, closure, assumption, investigation, verifier) without reinterpreting frozen bytes.
pub const CONTRACT_VERSION: eliot_contracts::ContractVersion =
    eliot_contracts::ContractVersion::new(1, 1, 0);
