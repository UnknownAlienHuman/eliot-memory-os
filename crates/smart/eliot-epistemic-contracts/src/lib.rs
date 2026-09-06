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
//!
//! Validation doctrine: what holds by construction and what needs an explicit call.
//!
//! Identity newtypes validate on construction and on deserialization, so a decoded id is
//! already sound and never needs a second check. Records with public fields and stored
//! digests are shape-validated two ways: `new(params)` enforces intrinsic validity at
//! construction and freezes the canonical digest, while deserialization of the three core
//! closed types goes through a checked wire `TryFrom` route, so `from_str` rejects an
//! invalid document instead of building an unchecked value. The wire shape is unchanged:
//! each wire mirrors its record field for field and re-runs the same constructor checks,
//! including frozen-digest recomputation; unknown fields still fail at the wire boundary.
//! Relational (cross-record closed) validity is never inferred from one record alone: it
//! always requires an explicit `validate_closed` or `validate_for` call with the governing
//! records, and only those calls derive completeness, binding, or ceiling closure.
//! Valid by construction: identity newtypes; every `new` output with its frozen digest;
//! every wire-decoded core record, re-validated through its constructor route.
//! Needing explicit calls: cross-record closure with governing records; coverage
//! completeness, which only closed validation derives; store existence, which is challenged.
//! This crate performs no I/O: external existence is challenged, never claimed.
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
pub use absence::{AbsenceClaim, AbsenceClaimParams, BoundedProof, OwnerLookup};
pub use admitted::{
    AdmittedKind, AdmittedReceipt, AdmittedReceiptParams, ChallengeInvariant, ContractChallenge,
    CurrentEpistemicPosition, CurrentEpistemicPositionView, Currentness, PositionId,
    PositionRevision, PositionState,
};
pub use assertability::PositionAssertability;
pub use assumption::{
    AssumptionDigest, AssumptionKind, AssumptionRecord, AssumptionRecordParams,
    AssumptionRetraction, RetractionReason,
};
pub use candidate::{CandidateKind, EpistemicPositionCandidate, EpistemicPositionCandidateParams};
pub use causal::{CausalClaim, CausalClaimParams, CausalStatus};
pub use claim_map::{
    ClaimAuditOutcome, ClaimEntry, ClaimEntryParams, ClaimMap, ClaimVerdict, DependenceGroup,
};
pub use conflict::{
    ArgumentAcceptability, ConflictKind, ConflictLifecycle, ConflictPosition, ConflictSet,
    ConflictSetParams,
};
pub use coverage::{
    CoverageDenominator, CoverageDenominatorParams, DenominatorKind, ExclusionReason,
    ExclusionRecord, FrontierRevision, FrontierSpec, PaginationBounds, QueryRevision, QuerySpec,
    SnapshotRef,
};
pub use error::{
    ContractError, MAX_HANDLES, MAX_MEMBERS, MAX_POSITIONS, MAX_PROOF_BYTES, MAX_SHORT_TEXT,
    MAX_STATEMENT_TEXT,
};
pub use grade::{EvidenceGrade, GRADE_ORDER, GradeAssignment};
pub use identity::{
    ClaimId, EvidenceSetId, IdentityBundle, IdentityBundleParams, LineageRootId, ManifestId,
    PredecessorId, PropositionId, SourceRevisionId, TransformedLineage, ValidityId,
};
pub use investigation::{
    InvestigationKind, InvestigationRequirement, InvestigationRequirementParams, RequirementKind,
};
pub use provenance::{
    ProvenanceClosure, ProvenanceClosureKind, ProvenanceClosureParams, SourceLineage,
};
pub use receipt::{
    CoverageReceipt, CoverageReceiptParams, MemberDisposition, MemberOutcome, OmittedMember,
};
pub use request::{PositionRequest, PositionRequestParams, RequestKind};
pub use support::{
    Precision, SupportRecord, SupportRecordParams, SupportResult, ValidityBounds, weakest_link,
};
pub use temporal::{TemporalPrecedence, TemporalRecord, TemporalRole};
pub use transition::{
    EpistemicTransition, EpistemicTransitionParams, InvalidationKind, InvalidationRecord,
    SupportDelta, TransitionTrigger,
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
