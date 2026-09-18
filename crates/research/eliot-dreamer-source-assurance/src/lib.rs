//! Role-separated source assurance over frozen Research evidence sets.
//!
//! One bounded assurance result describes exact source identity, acquisition
//! lineage, coverage, independence, freshness, conflict, blind boundaries,
//! invalidation, and the applicable support ceiling. The crate acquires no
//! sources, chooses no truth, promotes no support, widens no influence, and
//! decides no task completion.
//!
//! Role separation, by construction:
//!
//! ```text
//! Research acquisition  -> elapsed before freezing; only checked, never run.
//! Provenance            -> per-member lineage roots, routes, publishers.
//! Independence          -> unique authoritative lineage roots; mirrors and
//!                          reference multiplicity add nothing.
//! Availability          -> explicit disposition per expected member.
//! Content integrity     -> pinned digest match only; never truth or support.
//! Relevance and support -> claim linkages with separate stances.
//! Contradiction         -> preserved per member, per claim, and per envelope.
//! Confidence            -> typed observation per claim, never a scalar score.
//! Permitted influence   -> candidacy ceiling copied from policy, never issued.
//! ```
//!
//! Proof ceiling: module and consumer-edge evidence only. Open dependencies
//! on Research acquisition, the Dreamer runtime, Governor admission, and
//! product proof mean this crate alone establishes no Research or product
//! support.
//!
//! Forbidden in this package: network, provider, or source acquisition;
//! store writes; model or provider calls; authority issuance; influence
//! mutation; completion decisions; scalar trust or confidence scores;
//! transport or decoder work.

#![forbid(unsafe_code)]

mod assess;
mod consumers;
mod error;
mod portfolio;

pub use assess::{
    AccessibilityState, AssuranceResult, AvailabilityState, BlindBoundary, CommonModeFlag,
    CommonModeKind, Completeness, ConfidenceObservation, CoverageReceipt, DispositionCount,
    EpistemicUse, IncompletenessReason, IndependenceAssessment, IndependenceState, IntegrityState,
    MemberAxisRecord, MemberContradiction, MirrorGroup, ProvenanceState, RelevanceState,
    ReplayConflict, ReplayOutcome, SupportCeiling, assess, replay, replay_at,
};
pub use consumers::{
    DreamerEnvelope, GovernorCandidateMetadata, dreamer_envelope, governor_candidate,
    verify_dreamer_envelope,
};
pub use error::RoleSeparationError;
pub use portfolio::{
    AssurancePolicy, ClaimLinkage, ExpectedMember, FreezeInput, FrozenEvidenceSet,
    InfluenceCeiling, LineageAttribution, MemberDisposition, MemberObservation, SupportStance,
};

use serde::Serialize;

/// Wire and schema revision for this role-separation cell.
pub const ASSURANCE_SCHEMA_VERSION: &str = "eliot-dreamer-source-assurance-v1";
/// Policy revision whose field semantics are implemented by this crate.
pub const ASSURANCE_POLICY_VERSION: &str = "dreamer-source-assurance-policy-v1";
/// Proof ceiling for evidence produced by this crate.
pub const ASSURANCE_PROOF_CEILING: &str = "SOURCE_ASSURANCE_MODULE_AND_EDGE_CANDIDATE_ONLY";
/// Bounded portfolio size.
pub const MAX_MEMBERS: usize = 256;
/// Byte cap for one free-text field.
pub const MAX_TEXT_BYTES: usize = 4096;
/// Cap for reference strings carried per member.
pub const MAX_CITATIONS_PER_MEMBER: usize = 32;

/// Return the JSON schema for the assurance result contract.
pub fn assurance_result_schema() -> schemars::Schema {
    schemars::schema_for!(AssuranceResult)
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, RoleSeparationError> {
    let bytes = serde_json::to_vec(value)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn require_field(field: &'static str, value: &str) -> Result<(), RoleSeparationError> {
    if value.trim().is_empty() {
        Err(RoleSeparationError::MissingField(field))
    } else {
        Ok(())
    }
}

fn require_text(field: &'static str, value: &str) -> Result<(), RoleSeparationError> {
    require_field(field, value)?;
    if value.len() > MAX_TEXT_BYTES {
        return Err(RoleSeparationError::TextTooLong(field));
    }
    Ok(())
}

fn require_digest(field: &'static str, value: &str) -> Result<(), RoleSeparationError> {
    require_field(field, value)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RoleSeparationError::InvalidDigest(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
