//! Immutable Critical Attention projection for reactive planning.

use eliot_contracts::{ArtifactId, StateFence, TaskId};
use eliot_evidence::EvidenceEnvelope;
use eliot_protocol::ReactiveContextStage;
use eliot_receipts::{ReceiptDisposition, ReceiptEnvelope, WorkScopeId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ReactiveInputError, bounded_preflight};

const MAX_MEMBERS: usize = 256;
const MAX_HANDLES: usize = 256;
const ATTENTION_CLAIM_DOMAIN: &str = "eliot.context-contracts.reactive.attention-resolution";
const ATTENTION_CLAIM_VERSION: u16 = 1;

fn text(value: &str, field: &'static str) -> Result<(), ReactiveInputError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ReactiveInputError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

/// Acknowledgement state, separate from whether an obligation is resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttentionAcknowledgement {
    Unacknowledged,
    Acknowledged,
    Unknown,
}

/// Influence/use state retained without implying benefit or completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttentionInfluence {
    NotObserved,
    Observed,
    Unknown,
}

/// Resolution state named by the Critical Attention contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttentionResolution {
    Open,
    Resolved,
    Waived,
    Superseded,
    Unknown,
}

/// Actual owner-issued support for status, resolution, waiver, or supersession.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttentionOwnerClosure {
    pub owner_id: String,
    pub source_revision: String,
    pub attention_id: ArtifactId,
    pub task_id: TaskId,
    pub scope_id: WorkScopeId,
    pub state_fence: StateFence,
    pub source: Vec<eliot_protocol::ReactiveContextContentRef>,
    pub receipts: Vec<ReceiptEnvelope>,
    pub evidence: Vec<EvidenceEnvelope>,
    pub resolution_receipt: Option<ReceiptEnvelope>,
}

impl AttentionOwnerClosure {
    fn validate(&self, terminal: bool) -> Result<(), ReactiveInputError> {
        text(&self.owner_id, "attention.closure.owner_id")?;
        text(&self.source_revision, "attention.closure.source_revision")?;
        text(self.attention_id.as_str(), "attention.closure.attention_id")?;
        text(self.task_id.as_str(), "attention.closure.task_id")?;
        text(self.scope_id.as_str(), "attention.closure.scope_id")?;
        self.state_fence
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "attention.closure.state_fence",
                reason: "invalid State Fence",
            })?;
        if self.receipts.len() > MAX_HANDLES || self.evidence.len() > MAX_HANDLES {
            return Err(ReactiveInputError::InvalidField {
                field: "attention.closure",
                reason: "closure exceeds bounded collection size",
            });
        }
        if self.source.len() > MAX_HANDLES {
            return Err(ReactiveInputError::InvalidField {
                field: "attention.closure.source",
                reason: "closure exceeds bounded collection size",
            });
        }
        for reference in &self.source {
            reference
                .validate()
                .map_err(|_| ReactiveInputError::InvalidField {
                    field: "attention.closure.source",
                    reason: "invalid closure source binding",
                })?;
        }
        for receipt in &self.receipts {
            receipt
                .validate()
                .map_err(|_| ReactiveInputError::InvalidField {
                    field: "attention.receipts",
                    reason: "invalid retained ReceiptEnvelope",
                })?;
        }
        for evidence in &self.evidence {
            evidence
                .validate()
                .map_err(|_| ReactiveInputError::InvalidField {
                    field: "attention.evidence",
                    reason: "invalid retained EvidenceEnvelope",
                })?;
        }
        if let Some(receipt) = &self.resolution_receipt {
            receipt
                .validate()
                .map_err(|_| ReactiveInputError::InvalidField {
                    field: "attention.resolution_receipt",
                    reason: "invalid resolution ReceiptEnvelope",
                })?;
        }
        if terminal && self.evidence.is_empty() && self.resolution_receipt.is_none() {
            return Err(ReactiveInputError::InvalidField {
                field: "attention.closure",
                reason: "terminal resolution needs retained owner closure",
            });
        }
        Ok(())
    }
}

/// One complete Critical Attention member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CriticalAttentionMember {
    pub attention_id: ArtifactId,
    pub claim_artifact_id: ArtifactId,
    pub claim_digest: String,
    pub kind: String,
    pub source_revision: String,
    pub source: Vec<eliot_protocol::ReactiveContextContentRef>,
    pub evidence: Vec<eliot_protocol::ReactiveContextContentRef>,
    pub task_id: TaskId,
    pub scope_id: WorkScopeId,
    pub owner_id: String,
    pub affected_action_classes: Vec<String>,
    pub delivery_stage: ReactiveContextStage,
    pub acknowledgement: AttentionAcknowledgement,
    pub influence: AttentionInfluence,
    pub resolution: AttentionResolution,
    pub deadline_unix_ms: Option<u64>,
    pub review_ref: Option<ArtifactId>,
    pub escalation_target: Option<String>,
    pub resolution_condition: String,
    pub waiver_authority: Option<String>,
    pub superseded_by: Option<eliot_protocol::ReactiveContextContentRef>,
    pub missing_coverage: Vec<String>,
    pub state_fence: StateFence,
    pub owner_closure: AttentionOwnerClosure,
}

impl CriticalAttentionMember {
    fn superseding_ref(
        &self,
    ) -> Result<Option<&eliot_protocol::ReactiveContextContentRef>, ReactiveInputError> {
        let Some(replacement) = self.superseded_by.as_ref() else {
            if matches!(self.resolution, AttentionResolution::Superseded) {
                return Err(ReactiveInputError::InvalidField {
                    field: "attention.superseded_by",
                    reason: "superseded attention needs an explicit replacement",
                });
            }
            return Ok(None);
        };
        replacement
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "attention.superseded_by",
                reason: "invalid replacement binding",
            })?;
        if replacement.artifact_id.is_none() {
            return Err(ReactiveInputError::InvalidField {
                field: "attention.superseded_by",
                reason: "replacement needs an explicit artifact identity",
            });
        }
        if replacement.artifact_id.as_ref() == Some(&self.attention_id) {
            return Err(ReactiveInputError::BindingMismatch {
                field: "attention.superseded_by",
            });
        }
        if matches!(self.resolution, AttentionResolution::Superseded) {
            Ok(Some(replacement))
        } else {
            Ok(None)
        }
    }

    fn terminal_receipt_matches(
        &self,
        receipt: &ReceiptEnvelope,
        authority: &str,
        replacement: Option<&eliot_protocol::ReactiveContextContentRef>,
    ) -> bool {
        matches!(
            &receipt.core.disposition,
            ReceiptDisposition::Success { .. }
        ) && receipt.core.authority.authority_owner == authority
            && receipt.core.artifacts.iter().any(|artifact| {
                artifact.artifact_id == self.claim_artifact_id
                    && artifact.sha256 == self.claim_digest
                    && artifact.source_revision.as_deref() == Some(self.source_revision.as_str())
            })
            && replacement.is_none_or(|replacement| {
                receipt.core.artifacts.iter().any(|artifact| {
                    replacement.artifact_id.as_ref() == Some(&artifact.artifact_id)
                        && replacement.content_sha256 == artifact.sha256
                        && artifact.source_revision.as_deref()
                            == Some(replacement.source_revision.as_str())
                })
            })
    }

    fn validate_terminal_claim(&self) -> Result<(), ReactiveInputError> {
        if self.claim_digest != self.canonical_resolution_claim_digest()? {
            return Err(ReactiveInputError::DigestMismatch {
                field: "attention.claim_digest",
            });
        }
        let terminal = matches!(
            self.resolution,
            AttentionResolution::Resolved
                | AttentionResolution::Waived
                | AttentionResolution::Superseded
        );
        if !terminal {
            return Ok(());
        }
        if matches!(self.resolution, AttentionResolution::Resolved)
            && !self
                .owner_closure
                .evidence
                .iter()
                .any(|evidence| evidence.status == eliot_evidence::EpistemicStatus::Verified)
        {
            return Err(ReactiveInputError::InvalidField {
                field: "attention.resolution_evidence",
                reason: "resolved attention needs verified owner evidence",
            });
        }
        let superseding_ref = self.superseding_ref()?;
        let required_authority = if matches!(self.resolution, AttentionResolution::Waived) {
            self.waiver_authority
                .as_deref()
                .ok_or(ReactiveInputError::InvalidField {
                    field: "attention.waiver_authority",
                    reason: "waiver requires an explicit authority",
                })?
        } else {
            self.owner_id.as_str()
        };
        let claim_receipt = !matches!(self.resolution, AttentionResolution::Waived)
            && self
                .owner_closure
                .receipts
                .iter()
                .chain(self.owner_closure.resolution_receipt.iter())
                .any(|receipt| {
                    self.terminal_receipt_matches(receipt, required_authority, superseding_ref)
                });
        let waiver_receipt = matches!(self.resolution, AttentionResolution::Waived)
            && self
                .owner_closure
                .resolution_receipt
                .as_ref()
                .is_some_and(|receipt| {
                    self.terminal_receipt_matches(receipt, required_authority, superseding_ref)
                });
        if (!matches!(self.resolution, AttentionResolution::Waived) && !claim_receipt)
            || (matches!(self.resolution, AttentionResolution::Waived) && !waiver_receipt)
        {
            return Err(ReactiveInputError::BindingMismatch {
                field: "attention.claim_receipt",
            });
        }
        Ok(())
    }

    pub fn canonical_resolution_claim_digest(&self) -> Result<String, ReactiveInputError> {
        crate::canonical_planning_digest(&(
            ATTENTION_CLAIM_DOMAIN,
            ATTENTION_CLAIM_VERSION,
            (
                &self.claim_artifact_id,
                &self.attention_id,
                &self.source_revision,
                &self.owner_id,
                &self.task_id,
                &self.scope_id,
                &self.state_fence,
                &self.resolution,
                &self.resolution_condition,
                &self.waiver_authority,
                &self.superseded_by,
                &self.review_ref,
                &self.source,
                &self.evidence,
                &self.owner_closure.evidence,
            ),
        ))
    }

    fn validate_owner_receipt(
        &self,
        receipt: &ReceiptEnvelope,
        expected_owner: &str,
    ) -> Result<(), ReactiveInputError> {
        if receipt.core.work_scope.scope_id != self.scope_id
            || receipt.core.work_scope.state_fence != self.state_fence
            || receipt.core.authority.authority_owner != expected_owner
            || !receipt
                .core
                .artifacts
                .iter()
                .any(|artifact| artifact.artifact_id == self.attention_id)
        {
            return Err(ReactiveInputError::BindingMismatch {
                field: "attention.receipt_binding",
            });
        }
        if matches!(
            &receipt.core.disposition,
            ReceiptDisposition::Failure { .. }
                | ReceiptDisposition::Unknown { .. }
                | ReceiptDisposition::Cancelled { .. }
        ) {
            return Err(ReactiveInputError::BindingMismatch {
                field: "attention.receipt_resolution",
            });
        }
        Ok(())
    }

    fn validate_owner_binding(&self) -> Result<(), ReactiveInputError> {
        if self.owner_closure.owner_id != self.owner_id
            || self.owner_closure.source_revision != self.source_revision
            || self.owner_closure.attention_id != self.attention_id
            || self.owner_closure.task_id != self.task_id
            || self.owner_closure.scope_id != self.scope_id
            || self.owner_closure.state_fence != self.state_fence
        {
            return Err(ReactiveInputError::BindingMismatch {
                field: "attention.owner_closure_binding",
            });
        }
        if self.owner_closure.source != self.source {
            return Err(ReactiveInputError::BindingMismatch {
                field: "attention.source_closure_binding",
            });
        }
        for evidence in &self.owner_closure.evidence {
            if evidence.state_fence != self.state_fence
                || evidence.provenance.scope != self.scope_id.as_str()
                || evidence.provenance.revision.as_deref() != Some(self.source_revision.as_str())
                || !self
                    .source
                    .iter()
                    .chain(self.evidence.iter())
                    .any(|reference| {
                        evidence.provenance.raw_handle.as_deref()
                            == Some(reference.content_sha256.as_str())
                            && reference.source_revision == self.source_revision
                    })
            {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "attention.evidence_binding",
                });
            }
        }
        for receipt in &self.owner_closure.receipts {
            self.validate_owner_receipt(receipt, self.owner_id.as_str())?;
        }
        if let Some(receipt) = &self.owner_closure.resolution_receipt {
            let expected_owner = if matches!(self.resolution, AttentionResolution::Waived) {
                self.waiver_authority
                    .as_deref()
                    .unwrap_or(self.owner_id.as_str())
            } else {
                self.owner_id.as_str()
            };
            self.validate_owner_receipt(receipt, expected_owner)?;
        }
        Ok(())
    }

    /// Validate the complete member and retain unresolved states explicitly.
    pub fn validate(&self) -> Result<(), ReactiveInputError> {
        bounded_preflight(self, "attention.member.preflight")?;
        text(self.attention_id.as_str(), "attention.attention_id")?;
        text(
            self.claim_artifact_id.as_str(),
            "attention.claim_artifact_id",
        )?;
        text(&self.claim_digest, "attention.claim_digest")?;
        text(&self.kind, "attention.kind")?;
        text(&self.source_revision, "attention.source_revision")?;
        text(self.task_id.as_str(), "attention.task_id")?;
        text(self.scope_id.as_str(), "attention.scope_id")?;
        text(&self.owner_id, "attention.owner_id")?;
        text(&self.resolution_condition, "attention.resolution_condition")?;
        for action in &self.affected_action_classes {
            text(action, "attention.affected_action_classes.item")?;
        }
        for gap in &self.missing_coverage {
            text(gap, "attention.missing_coverage.item")?;
        }
        if self.source.len() > MAX_HANDLES || self.evidence.len() > MAX_HANDLES {
            return Err(ReactiveInputError::InvalidField {
                field: "attention.source_or_evidence",
                reason: "too many retained handles",
            });
        }
        for reference in self.source.iter().chain(self.evidence.iter()) {
            reference
                .validate()
                .map_err(|_| ReactiveInputError::InvalidField {
                    field: "attention.source_or_evidence",
                    reason: "invalid owner content binding",
                })?;
        }
        self.state_fence
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "attention.state_fence",
                reason: "invalid State Fence",
            })?;
        let terminal = matches!(
            self.resolution,
            AttentionResolution::Resolved
                | AttentionResolution::Waived
                | AttentionResolution::Superseded
        );
        if matches!(self.resolution, AttentionResolution::Waived)
            && self
                .waiver_authority
                .as_ref()
                .is_none_or(|v| v.trim().is_empty())
        {
            return Err(ReactiveInputError::InvalidField {
                field: "attention.waiver_authority",
                reason: "waiver requires an explicit authority",
            });
        }
        if let Some(authority) = &self.waiver_authority {
            text(authority, "attention.waiver_authority")?;
        }
        if let Some(target) = &self.escalation_target {
            text(target, "attention.escalation_target")?;
        }
        self.validate_owner_binding()?;
        self.validate_terminal_claim()?;
        self.owner_closure.validate(terminal)
    }
}

/// Immutable projection containing current and superseded/unknown members.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CriticalAttentionProjection {
    pub owner_id: String,
    pub source_revision: String,
    pub snapshot_revision: String,
    pub task_id: TaskId,
    pub scope_id: WorkScopeId,
    pub state_fence: StateFence,
    pub members: Vec<CriticalAttentionMember>,
    pub missing_coverage: Vec<String>,
    pub projection_digest: String,
}

impl CriticalAttentionProjection {
    /// Compute the digest over every safety-relevant projection field.
    pub fn canonical_digest(&self) -> Result<String, ReactiveInputError> {
        crate::canonical_planning_digest(&(
            &self.owner_id,
            &self.source_revision,
            &self.snapshot_revision,
            &self.task_id,
            &self.scope_id,
            &self.members,
            &self.missing_coverage,
            &self.state_fence,
        ))
    }

    /// Validate every retained member and the immutable projection digest.
    pub fn validate(&self) -> Result<(), ReactiveInputError> {
        bounded_preflight(self, "attention.preflight")?;
        text(&self.owner_id, "attention.owner_id")?;
        text(&self.source_revision, "attention.source_revision")?;
        text(&self.snapshot_revision, "attention.snapshot_revision")?;
        text(self.task_id.as_str(), "attention.task_id")?;
        text(self.scope_id.as_str(), "attention.scope_id")?;
        self.state_fence
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "attention.state_fence",
                reason: "invalid State Fence",
            })?;
        if self.members.len() > MAX_MEMBERS || self.missing_coverage.len() > MAX_HANDLES {
            return Err(ReactiveInputError::InvalidField {
                field: "attention.members",
                reason: "projection exceeds bounded collection size",
            });
        }
        for member in &self.members {
            member.validate()?;
            if member.task_id != self.task_id || member.scope_id != self.scope_id {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "attention.member_scope",
                });
            }
            if member.state_fence != self.state_fence {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "attention.member_fence",
                });
            }
        }
        let mut attention_ids = std::collections::BTreeSet::new();
        for member in &self.members {
            if !attention_ids.insert(&member.attention_id) {
                return Err(ReactiveInputError::InvalidField {
                    field: "attention.members",
                    reason: "duplicate attention identity",
                });
            }
        }
        for gap in &self.missing_coverage {
            text(gap, "attention.missing_coverage.item")?;
        }
        let expected = self.canonical_digest()?;
        if self.projection_digest != expected {
            return Err(ReactiveInputError::DigestMismatch {
                field: "attention.projection_digest",
            });
        }
        Ok(())
    }
}
