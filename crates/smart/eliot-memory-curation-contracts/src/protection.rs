use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, SourceId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ContractError, Digest, MemberId, ProtectionEvidenceId, RuleId, SnapshotId, SourceIdentity,
};

/// Protection classes that can block semantic curation.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectionClass {
    /// Current truth or owner-supported material.
    CurrentTruth,
    /// Minority or dissent material.
    MinorityDissent,
    /// Counterexample or failure evidence.
    Counterexample,
    /// Unresolved conflict set.
    UnresolvedConflict,
    /// Negative memory or failure fingerprint.
    NegativeMemory,
    /// Audit and raw history retention.
    AuditHistory,
    /// Privacy, erasure, or legal obligation.
    RetentionErasure,
    /// A dependency whose protection must be inherited.
    ProtectedDependency,
}

/// State of owner evidence; only current/verified evidence can clear protection.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectionEvidenceState {
    /// Evidence is current and owner verified.
    CurrentVerified,
    /// Evidence exists but is not current.
    Stale,
    /// Evidence is absent.
    Missing,
    /// Evidence cannot be interpreted.
    Malformed,
    /// Evidence source is unavailable.
    Unavailable,
    /// Evidence state is not known.
    Unknown,
}

/// Whether the checked protection condition is present or explicitly clear.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectionOutcome {
    /// The protected condition is present and must be preserved.
    Present,
    /// The owner explicitly verified that this condition is absent.
    Absent,
    /// The owner could not establish presence or absence.
    Unknown,
}

/// Disclosure ceiling carried by protection evidence.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DisclosureCeiling {
    /// Full structural detail may be retained.
    Structural,
    /// Only bounded references may be retained.
    ReferenceOnly,
    /// No further detail may be disclosed.
    Redacted,
}

/// One independently owner-evidenced protection record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtectionEvidence {
    /// Evidence identity.
    pub evidence_id: ProtectionEvidenceId,
    /// Protected member and source snapshot.
    pub member_id: MemberId,
    /// Source owner identity.
    pub source_id: SourceId,
    /// Snapshot identity.
    pub snapshot_id: SnapshotId,
    /// Protection class.
    pub class: ProtectionClass,
    /// Owner evidence state.
    pub state: ProtectionEvidenceState,
    /// Result of the owner protection check.
    pub outcome: ProtectionOutcome,
    /// Owner supplied provenance/evidence handles.
    pub references: BTreeSet<ArtifactId>,
    /// Fence under which this evidence is valid.
    pub state_fence: StateFence,
    /// Scope in which this evidence applies.
    pub scope: eliot_receipts::WorkScopeId,
    /// Disclosure ceiling; canonical proof strength is deferred.
    pub disclosure_ceiling: DisclosureCeiling,
    /// Optional invalidation reference.
    pub invalidated_by: Option<ProtectionEvidenceId>,
    /// Digest of this immutable evidence record.
    pub digest: Digest,
}
impl ProtectionEvidence {
    /// Validates exact source, scope, fence and bounded references.
    pub fn validate(&self, source: &SourceIdentity) -> Result<(), ContractError> {
        if self.source_id != source.source_id
            || self.snapshot_id != source.snapshot_id
            || self.scope != source.scope
            || self.state_fence != source.state_fence
        {
            return Err(ContractError::BindingMismatch {
                field: "protection.source",
            });
        }
        if self.references.len() > 256 {
            return Err(ContractError::Bound {
                field: "protection.references",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| ContractError::BindingMismatch {
                field: "protection.state_fence",
            })
    }
}

/// Aggregate protection state for one member.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectionDecision {
    /// Required evidence is current and no protection blocks curation.
    Unprotected,
    /// Owner evidence protects the member.
    Protected,
    /// Missing, stale, or unknown evidence blocks a safe conclusion.
    Unknown,
}

/// Protection assessment bound to one exact source member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtectionAssessment {
    /// Source snapshot binding.
    pub source: SourceIdentity,
    /// Member identity.
    pub member_id: MemberId,
    /// Profile rules this producer declares applicable to this member.
    pub applicable_rule_ids: BTreeSet<RuleId>,
    /// Required classes for this profile/member.
    pub required: BTreeSet<ProtectionClass>,
    /// Independently supplied evidence records.
    pub evidence: Vec<ProtectionEvidence>,
    /// Closed decision derived by owner policy.
    pub decision: ProtectionDecision,
}
impl ProtectionAssessment {
    /// Validates evidence completeness and fail-closed decision semantics.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.source.validate()?;
        if self.applicable_rule_ids.len() > 32 {
            return Err(ContractError::Bound {
                field: "protection.applicable_rule_ids",
            });
        }
        let mut ids = BTreeSet::new();
        let mut clear_classes = BTreeSet::new();
        let mut positive = false;
        let mut uncertain = false;
        for item in &self.evidence {
            item.validate(&self.source)?;
            if item.member_id != self.member_id {
                return Err(ContractError::BindingMismatch {
                    field: "protection.member",
                });
            }
            if !ids.insert(item.evidence_id.clone()) {
                return Err(ContractError::Duplicate {
                    field: "protection.evidence",
                });
            }
            if item.state == ProtectionEvidenceState::CurrentVerified {
                match item.outcome {
                    ProtectionOutcome::Present => positive = true,
                    ProtectionOutcome::Absent => {
                        clear_classes.insert(item.class);
                    }
                    ProtectionOutcome::Unknown => uncertain = true,
                }
            } else {
                uncertain = true;
            }
        }
        let all_clear = !self.evidence.is_empty()
            && !positive
            && !uncertain
            && self
                .required
                .iter()
                .all(|class| clear_classes.contains(class))
            && self.evidence.iter().all(|item| {
                item.state == ProtectionEvidenceState::CurrentVerified
                    && item.invalidated_by.is_none()
            });
        if self.decision == ProtectionDecision::Unprotected && !all_clear {
            return Err(ContractError::Reconciliation {
                field: "protection.fail_closed",
            });
        }
        if self.decision == ProtectionDecision::Protected && !positive {
            return Err(ContractError::Reconciliation {
                field: "protection.protected_without_positive",
            });
        }
        if self.decision == ProtectionDecision::Unknown && self.required.is_empty() {
            return Err(ContractError::Reconciliation {
                field: "protection.unknown_without_requirement",
            });
        }
        Ok(())
    }
}

/// Returns whether all required evidence is current and verified.
pub fn evidence_clears_protection(
    required: &BTreeSet<ProtectionClass>,
    evidence: &[ProtectionEvidence],
) -> bool {
    !required.is_empty()
        && !evidence.is_empty()
        && evidence.iter().all(|item| {
            item.state == ProtectionEvidenceState::CurrentVerified
                && item.outcome == ProtectionOutcome::Absent
                && item.invalidated_by.is_none()
        })
        && required
            .iter()
            .all(|class| evidence.iter().any(|item| item.class == *class))
}
