use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ContractError, Digest, FindingId, MemberId, ProfileId, RuleId, SnapshotId, SourceIdentity,
    source_matches, text,
};

/// Closed structural finding vocabulary. It contains no action or semantic kind.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingClass {
    /// Exact duplicate or collision.
    Duplicate,
    /// Stale or superseded source reference.
    StaleSuperseded,
    /// Malformed or incomplete source shape.
    MalformedIncomplete,
    /// Missing provenance or raw-history link.
    ProvenanceGap,
    /// Missing, stale, or unknown protection evidence.
    ProtectionGap,
    /// Structural conflict or ambiguity.
    ConflictAmbiguity,
    /// Bounded work or output prevented processing.
    BoundedOut,
    /// Member was left unprocessed by a partial screen.
    Unprocessed,
}

/// Proof state for a structural observation.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingProof {
    /// Deterministically established from supplied records.
    Deterministic,
    /// Observed but not established as true.
    Observed,
    /// Could not be established from available evidence.
    Unknown,
}

/// A closed structural finding bound to exact records and evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationFinding {
    /// Finding identity.
    pub finding_id: FindingId,
    /// Source identity and snapshot binding.
    pub source: SourceIdentity,
    /// Exact profile binding.
    pub profile_id: ProfileId,
    /// Member to which this finding applies.
    pub member_id: MemberId,
    /// Exact rule and profile that produced the observation.
    pub rule_id: RuleId,
    /// Finding class.
    pub class: FindingClass,
    /// Evidence handles supporting the observation.
    pub evidence: BTreeSet<eliot_contracts::ArtifactId>,
    /// Invariant or structural predicate observed.
    pub invariant: String,
    /// Bounded proof status.
    pub proof: FindingProof,
    /// Optional invalidation identity.
    pub invalidated_by: Option<FindingId>,
    /// Digest of the immutable finding payload.
    pub digest: Digest,
}
impl CurationFinding {
    /// Validates source/member/rule/evidence bindings and digest integrity.
    pub fn validate(
        &self,
        profile_id: &ProfileId,
        snapshot_id: &SnapshotId,
    ) -> Result<(), ContractError> {
        self.source.validate()?;
        text(&self.invariant, "finding.invariant")?;
        if &self.source.snapshot_id != snapshot_id {
            return Err(ContractError::BindingMismatch {
                field: "finding.snapshot",
            });
        }
        if self.evidence.len() > 256 {
            return Err(ContractError::Bound {
                field: "finding.evidence",
            });
        }
        if &self.profile_id != profile_id {
            return Err(ContractError::BindingMismatch {
                field: "finding.profile",
            });
        }
        Ok(())
    }
}

/// Validates every finding against one source and checks duplicate identities.
pub fn validate_findings(
    findings: &[CurationFinding],
    source: &SourceIdentity,
    profile_id: &ProfileId,
) -> Result<(), ContractError> {
    let mut ids = BTreeSet::new();
    for finding in findings {
        finding.validate(profile_id, &source.snapshot_id)?;
        source_matches(source, &finding.source)?;
        if !ids.insert(finding.finding_id.clone()) {
            return Err(ContractError::Duplicate { field: "findings" });
        }
    }
    Ok(())
}
