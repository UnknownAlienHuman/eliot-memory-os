//! Versioned store-neutral contracts for the Current Epistemic Position.
//!
//! This crate owns the versioned, owner-neutral types crossing the Current
//! Epistemic Position boundary: position identity with canonical digests,
//! the frozen I21.2 evidence grade, per-proposition support, coverage
//! denominators with receipts, scoped absence, claim maps, temporal roles,
//! causal claims, conflict sets, inert candidates, admitted read views,
//! assertability ceilings, and inert transitions. Identifiers, fences,
//! digests, and evidence dimensions are reused from `eliot-contracts` and
//! `eliot-evidence` and never redefined here.
//!
//! The crate resolves nothing, acquires nothing, and applies nothing: there
//! is no resolver, no store, no authority grant, no material effect, and no
//! finish input. Unknown, assumed, conflicted, and stale stay distinct;
//! provenance and fence remain exact; every load-bearing mutation invalidates
//! the frozen digest that covered the previous shape.

#![forbid(unsafe_code)]

pub mod absence;
pub mod admitted;
pub mod assertability;
pub mod candidate;
pub mod causal;
pub mod claim_map;
pub mod conflict;
pub mod coverage;
pub mod error;
pub mod grade;
pub mod identity;
pub mod receipt;
pub mod support;
pub mod temporal;
pub mod transition;

#[cfg(test)]
mod tests;

pub use absence::{AbsenceClaim, BoundedProof, OwnerLookup};
pub use admitted::{AdmittedKind, CurrentEpistemicPositionView, Currentness};
pub use assertability::PositionAssertability;
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
pub use receipt::{CoverageReceipt, MemberDisposition, MemberOutcome, OmittedMember};
pub use support::{SupportRecord, SupportResult, ValidityBounds, weakest_link};
pub use temporal::{TemporalPrecedence, TemporalRecord, TemporalRole};
pub use transition::{
    EpistemicTransition, InvalidationKind, InvalidationRecord, SupportDelta, TransitionTrigger,
};

/// Stable identity of this contract surface.
pub const CONTRACT_NAME: &str = "eliot.smart.epistemic-contracts";
/// Current wire revision of this contract surface.
pub const CONTRACT_VERSION: eliot_contracts::ContractVersion =
    eliot_contracts::ContractVersion::new(1, 0, 0);
