//! Bounded input closure for a typed A-03 Failure handoff.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

use crate::budget::BudgetUsage;
use crate::bundle::DreamInputBundle;
use crate::curation::{CurationKind, CurationPayload};
use crate::draft::{CurationAcceptanceCtx, GroundedDreamDraft, ValidatedCurationItem};
use crate::encoding::{canonical_bytes, digest_hex};
use crate::error::{ContractViolation, check_fence, check_text, check_vec_bound};
use crate::job::{DreamJobInput, JobClass};
use crate::registry::{CurationFamily, TypedCurationHandlerRequest};
use crate::screen::{ScreenBinding, ScreenState};

use super::records::{
    FailureActionEvidence, FailureDimension, FailureDimensionSource, FailureDimensionValue,
    FailureEnvironment, FailureHistory, FailureOperation, FailureProposal, FailureSourceMember,
    MAX_TEXT, SCHEMA_VERSION, digest, normalize_action_evidence, normalize_history,
    normalize_preservation, normalize_proposal,
};

const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;

struct BoundedWriter {
    len: usize,
    max: usize,
}
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.len = self
            .len
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("bounded input length overflow"))?;
        if self.len > self.max {
            return Err(io::Error::other("bounded input exceeded"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Complete typed input presented to the future Failure handler.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureInput {
    pub schema_version: u32,
    pub operation: FailureOperation,
    pub job: DreamJobInput,
    pub bundle: DreamInputBundle,
    pub grounded: GroundedDreamDraft,
    pub usage: BudgetUsage,
    pub source_members: Vec<FailureSourceMember>,
    pub item: ValidatedCurationItem,
    pub request: TypedCurationHandlerRequest,
    pub screen: ScreenBinding,
    pub action_evidence: FailureActionEvidence,
    pub environment: FailureEnvironment,
    pub history: FailureHistory,
    pub proposal: FailureProposal,
    pub policy_digest: String,
    pub preservation: crate::relation::RelationPreservation,
}

impl FailureInput {
    /// Measures the complete serialized envelope before validation allocates or sorts.
    pub fn preflight(&self) -> Result<(), ContractViolation> {
        let mut writer = BoundedWriter {
            len: 0,
            max: MAX_INPUT_BYTES,
        };
        match serde_json::to_writer(&mut writer, self) {
            Ok(()) => Ok(()),
            Err(_error) if writer.len > MAX_INPUT_BYTES => Err(ContractViolation::OutOfBounds {
                field: "failure.input_bytes",
                min: 0,
                max: i64::try_from(MAX_INPUT_BYTES).unwrap_or(i64::MAX),
                got: i64::try_from(writer.len).unwrap_or(i64::MAX),
            }),
            Err(error) => Err(ContractViolation::Malformed {
                field: "failure.input",
                reason: error.to_string(),
            }),
        }
    }

    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.preflight()?;
        self.validate_header()?;
        self.validate_evidence_joins()?;
        self.validate_proposal_joins()?;
        self.validate_preservation()
    }

    fn validate_header(&self) -> Result<(), ContractViolation> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "failure.input.schema_version",
                min: 1,
                max: 1,
                got: self.schema_version.into(),
            });
        }
        self.operation.validate()?;
        self.job.validate()?;
        if self.job.job_class != JobClass::Curation
            || self.job.operation_id != self.operation.operation_id
            || self.job.idempotency_key != self.operation.idempotency_key
            || self.job.task_id != self.operation.task_id
            || self.job.scope_id != self.operation.scope_id
            || self.job.state_fence != self.operation.state_fence
            || self.job.requester != self.operation.requester
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.job_identity",
                reason: "job and operation identity/fence/requester drift".to_owned(),
            });
        }
        self.item.validate()?;
        if self.item.kind_spelling != CurationKind::Failure.as_str()
            || self.item.payload.kind() != CurationKind::Failure
            || self.item.task_id != self.operation.task_id
            || self.item.scope_id != self.operation.scope_id
            || self.item.state_fence != self.operation.state_fence
            || self.item.requester != self.operation.requester
        {
            return Err(ContractViolation::KindPayload(
                "failure input requires a bound Failure curation item".to_owned(),
            ));
        }
        let job_digest = digest_hex(&canonical_bytes(&self.job)?);
        if self.item.job_digest != job_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.item.job_digest",
                reason: "item does not bind complete job".to_owned(),
            });
        }
        self.bundle.validate()?;
        if self.bundle.state_fence != self.operation.state_fence {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.bundle.state_fence",
                reason: "current bundle must use the curation creation fence".to_owned(),
            });
        }
        self.grounded.validate()?;
        self.item.accept(&CurationAcceptanceCtx {
            job: &self.job,
            bundle: &self.bundle,
            receipt: &self.item.receipt,
            screen: &self.screen,
            grounded: &self.grounded,
            request: &self.request,
            usage: &self.usage,
        })?;
        self.request.validate()?;
        if self.request.kind != CurationKind::Failure
            || self.request.family != CurationFamily::Failure
            || self.request.request_id != self.operation.request_id
            || self.request.job_id != self.item.receipt.job_id
            || self.request.task_id != self.operation.task_id
            || self.request.scope_id != self.operation.scope_id
            || self.request.state_fence != self.operation.state_fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.request_identity",
                reason: "typed request does not join operation/item".to_owned(),
            });
        }
        if self.request.screen_binding.as_ref() != Some(&self.screen) {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.screen_binding",
                reason: "request and input screen differ".to_owned(),
            });
        }
        self.screen.validate()?;
        if self.screen.state != ScreenState::Eligible {
            return Err(ContractViolation::ScreenIneligible(
                self.screen.state.reason().to_owned(),
            ));
        }
        if self.screen.request_id.as_str() != self.operation.request_id
            || self.screen.task_id != self.operation.task_id
            || self.screen.scope_id != self.operation.scope_id
            || self.screen.state_fence != self.operation.state_fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.screen_identity",
                reason: "screen request/task/scope/fence drift".to_owned(),
            });
        }
        check_fence(&self.operation.state_fence)?;
        check_text(&self.policy_digest, "failure.policy_digest", MAX_TEXT)?;
        digest(&self.policy_digest, "failure.policy_digest")
    }

    fn validate_evidence_joins(&self) -> Result<(), ContractViolation> {
        self.validate_action_evidence_join()?;
        self.validate_source_members_join()?;
        self.validate_evidence_materials_join()?;
        self.history.validate()?;
        self.validate_shared_evidence_domain()?;
        self.validate_history_scope()
    }

    fn validate_action_evidence_join(&self) -> Result<(), ContractViolation> {
        self.action_evidence.validate()?;
        if self.action_evidence.action_operation.task_id != self.operation.task_id
            || self.action_evidence.action_operation.scope_id != self.operation.scope_id
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.action_evidence.scope",
                reason: "failed action is outside current curation scope".to_owned(),
            });
        }
        if self.action_evidence.action != self.proposal.action {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.action_evidence.action",
                reason: "action evidence differs from proposal".to_owned(),
            });
        }
        if self.action_evidence.outcome != self.proposal.outcome {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.action_evidence.outcome",
                reason: "outcome evidence differs from proposal".to_owned(),
            });
        }
        self.environment.validate()
    }

    fn validate_source_members_join(&self) -> Result<(), ContractViolation> {
        check_vec_bound(
            self.source_members.len(),
            super::records::MAX_ITEMS,
            "failure.source_members",
        )?;
        let mut source_ids = Vec::new();
        for source in &self.source_members {
            source.validate()?;
            if !source_ids.iter().all(|id: &String| id != &source.handle) {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.source_members",
                    reason: "duplicate source member".to_owned(),
                });
            }
            source_ids.push(source.handle.clone());
            if source.task_id != self.operation.task_id
                || source.scope_id != self.operation.scope_id
                || source.state_fence != self.operation.state_fence
                || source.source_snapshot != self.request.source_snapshot
                || source.source_revision != self.request.source_revision
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.source_members.join",
                    reason: "source member task/scope/snapshot/revision drift".to_owned(),
                });
            }
        }
        for material in &self.bundle.materials {
            if !self
                .source_members
                .iter()
                .any(|source| source.handle == material.handle && source.digest == material.digest)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.source_members",
                    reason: "bundle material is not retained as a source member".to_owned(),
                });
            }
        }
        for source in &self.source_members {
            let Some(material) = self
                .bundle
                .materials
                .iter()
                .find(|material| material.handle == source.handle)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.source_members",
                    reason: "source member is not a frozen bundle material".to_owned(),
                });
            };
            if material.digest != source.digest
                || usize::try_from(material.bytes).unwrap_or(usize::MAX) != source.bytes.len()
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.source_members.bytes",
                    reason: "source member digest or byte count differs from bundle material"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_evidence_materials_join(&self) -> Result<(), ContractViolation> {
        for evidence in self
            .action_evidence
            .evidence
            .iter()
            .chain(self.history.historical_evidence.iter())
        {
            let Some(material) = self
                .source_members
                .iter()
                .find(|source| source.handle == evidence.material_handle)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.evidence.material_handle",
                    reason: "evidence material is outside current retained source members"
                        .to_owned(),
                });
            };
            if material.digest != evidence.material_digest
                || material.bytes != evidence.material_bytes
                || material.state_fence != self.operation.state_fence
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.evidence.material",
                    reason: "evidence material handle/digest/bytes/fence drift".to_owned(),
                });
            }
        }
        for material in self
            .action_evidence
            .receipt_materials
            .iter()
            .chain(self.history.receipt_materials.iter())
        {
            let Some(source) = self
                .source_members
                .iter()
                .find(|source| source.handle == material.handle)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.receipt_material.handle",
                    reason: "receipt material is outside current retained source members"
                        .to_owned(),
                });
            };
            if source.digest != material.digest
                || source.bytes != material.bytes
                || source.state_fence != self.operation.state_fence
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.receipt_material",
                    reason: "receipt material handle/digest/bytes/fence drift".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_shared_evidence_domain(&self) -> Result<(), ContractViolation> {
        for action_evidence in &self.action_evidence.evidence {
            for historical_evidence in &self.history.historical_evidence {
                if action_evidence.evidence_id == historical_evidence.evidence_id
                    && action_evidence != historical_evidence
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "failure.evidence.shared_domain",
                        reason: "same evidence ID has conflicting records across streams"
                            .to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_history_scope(&self) -> Result<(), ContractViolation> {
        for entry in &self.history.entries {
            if entry.task_id != self.operation.task_id || entry.scope_id != self.operation.scope_id
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.history.join",
                    reason: "history entry outside current task/scope".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_proposal_joins(&self) -> Result<(), ContractViolation> {
        self.validate_profile_join()?;
        self.validate_proposal_payload_join()?;
        self.validate_proposal_reference_domains()?;
        self.validate_mitigation_verifier()
    }

    fn validate_profile_join(&self) -> Result<(), ContractViolation> {
        self.proposal.validate()?;
        let definition = &self.proposal.comparison.definition;
        let Some(source) = self
            .source_members
            .iter()
            .find(|source| source.handle == definition.source_handle)
        else {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.profile.definition.source_handle",
                reason: "profile definition source is outside current retained materials"
                    .to_owned(),
            });
        };
        if source.digest != definition.definition_digest
            || source.bytes != definition.definition_bytes
            || source.bytes.len() as u64 != definition.definition_bytes_len
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.profile.definition.source",
                reason: "retained profile definition bytes do not match current source material"
                    .to_owned(),
            });
        }
        for dimension in self
            .proposal
            .trigger
            .iter()
            .chain(self.proposal.comparison.dimensions.iter())
        {
            self.validate_dimension(dimension)?;
        }
        if self.proposal.trigger.len() != self.proposal.comparison.dimensions.len()
            || self
                .proposal
                .trigger
                .iter()
                .any(|dimension| !self.proposal.comparison.dimensions.contains(dimension))
            || self
                .proposal
                .comparison
                .dimensions
                .iter()
                .any(|dimension| !self.proposal.trigger.contains(dimension))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.profile.dimensions",
                reason: "trigger and comparison dimensions must be the exact same typed set"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn validate_proposal_payload_join(&self) -> Result<(), ContractViolation> {
        if self.proposal.operation != self.operation
            || self.proposal.policy_digest != self.policy_digest
            || self.proposal.candidate_id != self.operation.candidate_id
            || self.proposal.action != self.action_evidence.action
            || self.proposal.environment != self.environment
            || self.proposal.history != self.history
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.proposal.join",
                reason: "proposal does not preserve complete typed input closure".to_owned(),
            });
        }
        let CurationPayload::Failure(payload) = &self.item.payload else {
            return Err(ContractViolation::KindPayload(
                "failure payload drift".to_owned(),
            ));
        };
        if payload.fingerprint != self.proposal.fingerprint
            || payload.signature != self.proposal.signature
            || payload.target_evidence != self.proposal.target_evidence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.payload",
                reason: "legacy FailurePayload is not exactly bound to proposal".to_owned(),
            });
        }
        if !payload
            .target_evidence
            .targets
            .contains(&self.proposal.action.target_id)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.payload.targets",
                reason: "FailurePayload target membership differs from failed action".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_proposal_reference_domains(&self) -> Result<(), ContractViolation> {
        let evidence_ids: Vec<&str> = self
            .action_evidence
            .evidence
            .iter()
            .map(|e| e.evidence_id.as_str())
            .collect();
        for id in self
            .proposal
            .evidence_refs
            .iter()
            .chain(self.proposal.counterevidence_refs.iter())
            .chain(self.proposal.causal.evidence_refs.iter())
        {
            if !evidence_ids.contains(&id.as_str()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.proposal.evidence_refs",
                    reason: "proposal references evidence outside admitted closure".to_owned(),
                });
            }
        }
        for id in &self.proposal.source_refs {
            if !self
                .source_members
                .iter()
                .any(|source| &source.handle == id)
                && !self
                    .bundle
                    .omissions
                    .iter()
                    .any(|omission| &omission.handle == id)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.proposal.source_refs",
                    reason: "proposal source is outside retained source members".to_owned(),
                });
            }
        }
        let history_ids: Vec<&str> = self
            .proposal
            .history
            .entries
            .iter()
            .map(|entry| entry.history_id.as_str())
            .collect();
        let historical_evidence_ids: Vec<&str> = self
            .proposal
            .history
            .historical_evidence
            .iter()
            .map(|entry| entry.evidence_id.as_str())
            .collect();
        for control in &self.proposal.controls {
            if control.task_id != self.operation.task_id
                || control.scope_id != self.operation.scope_id
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.control.join",
                    reason: "control outside current scope".to_owned(),
                });
            }
        }
        let domains: Vec<&str> = evidence_ids
            .iter()
            .copied()
            .chain(
                self.source_members
                    .iter()
                    .map(|source| source.handle.as_str()),
            )
            .chain(history_ids)
            .chain(historical_evidence_ids)
            .chain(
                self.proposal
                    .controls
                    .iter()
                    .map(|control| control.control_id.as_str()),
            )
            .collect();
        for control in &self.proposal.controls {
            for verifier_ref in &control.verifier_refs {
                if !domains.contains(&verifier_ref.as_str()) {
                    return Err(ContractViolation::BindingMismatch {
                        field: "failure.control.verifier_refs",
                        reason: "control verifier is outside retained evidence domain".to_owned(),
                    });
                }
            }
        }
        self.validate_causal_reference_domains(&domains)?;
        Ok(())
    }

    fn validate_causal_reference_domains(&self, domains: &[&str]) -> Result<(), ContractViolation> {
        for id in self
            .proposal
            .causal
            .limitation_refs
            .iter()
            .chain(self.proposal.causal.rival_refs.iter())
            .chain(self.proposal.causal.confounder_refs.iter())
            .chain(self.proposal.lifecycle.inverse_refs.iter())
            .chain(self.proposal.lifecycle.raw_history_refs.iter())
        {
            if !domains.contains(&id.as_str()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.proposal.reference",
                    reason: "proposal control/history reference is outside retained domain"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_mitigation_verifier(&self) -> Result<(), ContractViolation> {
        let Some(receipt) = self.action_evidence.receipts.iter().find(|receipt| {
            receipt.identity.receipt_id.as_str() == self.proposal.mitigation.verifier_receipt_ref
        }) else {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.mitigation.verifier_receipt_ref",
                reason: "safe-reattempt verifier receipt is outside retained action receipts"
                    .to_owned(),
            });
        };
        let Some(verifier) = receipt.core.verifier.as_ref() else {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.mitigation.verifier_receipt_ref",
                reason: "safe-reattempt verifier receipt lacks a canonical verifier binding"
                    .to_owned(),
            });
        };
        if verifier.verifier_id.as_str() != self.proposal.mitigation.safe_reattempt_verifier
            || verifier.verifier_revision.to_string() != self.proposal.mitigation.verifier_revision
            || digest_hex(&canonical_bytes(verifier)?) != self.proposal.mitigation.verifier_digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.mitigation.verifier_digest",
                reason:
                    "safe-reattempt verifier does not match the original canonical receipt verifier"
                        .to_owned(),
            });
        }
        Ok(())
    }

    fn validate_dimension(&self, dimension: &FailureDimension) -> Result<(), ContractViolation> {
        if matches!(
            (&dimension.source, dimension.field.as_str()),
            (FailureDimensionSource::Applicability, "effect_class")
        ) {
            let expected = match self.proposal.applicability.effect_class {
                eliot_receipts::EffectClass::Read => "READ",
                eliot_receipts::EffectClass::Candidate => "CANDIDATE",
                eliot_receipts::EffectClass::ReversibleMutation => "REVERSIBLE_MUTATION",
                eliot_receipts::EffectClass::ExternalEffect => "EXTERNAL_EFFECT",
            };
            return if matches!(&dimension.value, FailureDimensionValue::Text(value) if value == expected)
            {
                Ok(())
            } else {
                Err(ContractViolation::BindingMismatch {
                    field: "failure.dimension.value",
                    reason: "typed effect-class dimension differs from applicability".to_owned(),
                })
            };
        }
        let expected = match (&dimension.source, dimension.field.as_str()) {
            (FailureDimensionSource::Action, "target_id") => {
                Some((&self.action_evidence.action.target_id, false))
            }
            (FailureDimensionSource::Action, "input_digest") => {
                Some((&self.action_evidence.action.input_digest, true))
            }
            (FailureDimensionSource::Action | FailureDimensionSource::Receipt, "operation_id") => {
                Some((&self.action_evidence.action_operation.operation_id, false))
            }
            (FailureDimensionSource::Action, "attempt_id") => {
                Some((&self.action_evidence.action_operation.attempt_id, false))
            }
            (FailureDimensionSource::Environment, "environment_id") => {
                Some((&self.environment.environment_id, false))
            }
            (FailureDimensionSource::Environment, "platform") => {
                Some((&self.environment.platform, false))
            }
            (FailureDimensionSource::Environment, "tool_revision") => {
                Some((&self.environment.tool_revision, false))
            }
            (FailureDimensionSource::Environment, "config_revision") => {
                Some((&self.environment.config_revision, false))
            }
            (FailureDimensionSource::Environment, "capability_revision") => {
                Some((&self.environment.capability_revision, false))
            }
            (FailureDimensionSource::Environment, "policy_revision") => {
                Some((&self.environment.policy_revision, false))
            }
            (FailureDimensionSource::Applicability, "task_id") => {
                Some((&self.proposal.applicability.task_id, false))
            }
            (FailureDimensionSource::Applicability, "scope_id") => {
                Some((&self.proposal.applicability.scope_id, false))
            }
            (FailureDimensionSource::Applicability, "target_id") => {
                Some((&self.proposal.applicability.target_id, false))
            }
            (FailureDimensionSource::Scope, "task_id") => Some((&self.operation.task_id, false)),
            (FailureDimensionSource::Scope, "scope_id") => Some((&self.operation.scope_id, false)),
            (FailureDimensionSource::Receipt, "request_id") => {
                Some((&self.action_evidence.action_operation.request_id, false))
            }
            _ => None,
        };
        let Some((expected, is_digest)) = expected else {
            return Err(ContractViolation::UnknownVariant {
                field: "failure.dimension.field",
                value: dimension.field.clone(),
            });
        };
        let matches = if is_digest {
            matches!(&dimension.value, FailureDimensionValue::Digest(value) if value == expected)
        } else {
            matches!(&dimension.value, FailureDimensionValue::Text(value) if value == expected)
        };
        if matches {
            Ok(())
        } else {
            Err(ContractViolation::BindingMismatch {
                field: "failure.dimension.value",
                reason: "typed trigger dimension differs from its owned fact".to_owned(),
            })
        }
    }

    fn validate_preservation(&self) -> Result<(), ContractViolation> {
        self.preservation.validate()?;
        if self.proposal.preservation != self.preservation {
            return Err(ContractViolation::Preservation(
                "proposal and input must reuse one I9.7 preservation report".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn validate_failure(input: &FailureInput) -> Result<(), ContractViolation> {
    input.validate()
}

/// Stable digest over the complete, validated envelope. All receipts and screen fields remain included.
pub fn failure_input_digest(input: &FailureInput) -> Result<String, ContractViolation> {
    input.validate()?;
    let mut normalized = input.clone();
    normalize_input(&mut normalized)?;
    Ok(digest_hex(&canonical_bytes(&normalized)?))
}

pub(crate) fn normalize_input(input: &mut FailureInput) -> Result<(), ContractViolation> {
    normalize_action_evidence(&mut input.action_evidence)?;
    normalize_history(&mut input.history)?;
    input.source_members.sort_by(|a, b| a.handle.cmp(&b.handle));
    normalize_proposal(&mut input.proposal)?;
    normalize_preservation(&mut input.preservation);
    normalize_preservation(&mut input.proposal.preservation);
    Ok(())
}

pub(crate) fn failure_request_digest(
    request: &TypedCurationHandlerRequest,
) -> Result<String, ContractViolation> {
    request.validate()?;
    Ok(digest_hex(&canonical_bytes(request)?))
}

#[cfg(test)]
#[allow(clippy::too_many_lines, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::budget::BudgetUsage;
    use crate::bundle::{BundleMaterial, SourceDisposition};
    use crate::curation::{CurationKind, TargetEvidence};
    use crate::draft::{ClaimResidue, GroundedDreamDraft, SupportState};
    use crate::failure::records::*;
    use crate::registry::{AtomicityMode, CurationFamily, TargetDenominator};
    use crate::relation::{RelationPreservationDimension, RelationPreservationVerdict};
    use crate::screen::ScreenState;
    use eliot_contracts::{
        ArtifactId, AuthorityEpoch, ClockReading, ContractId, ContractVersion, OperationId,
        ProductId, RequestId, ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision,
        TransactionSequence, sha256_hex,
    };
    use eliot_evidence::{
        Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
        EvidenceFreshness, Provenance,
    };
    use eliot_receipts::{
        AuthorityBinding, CausalBinding, EffectClass, OperationBinding, ProofCeiling, ReceiptCore,
        ReceiptDisposition, ReceiptEnvelope, ReceiptKind, RequestBinding, TaskBinding,
        VerifierBinding, WorkScopeBinding, WorkScopeId, contract_identity,
    };

    fn preservation() -> crate::relation::RelationPreservation {
        crate::relation::RelationPreservation {
            verdicts: RelationPreservationDimension::all()
                .iter()
                .copied()
                .map(|dimension| RelationPreservationVerdict {
                    dimension,
                    passed: true,
                    known: true,
                    note: "retained".into(),
                })
                .collect(),
        }
    }
    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }
    fn distinct_fence(generation: u64) -> StateFence {
        StateFence::new(
            AuthorityEpoch::genesis(),
            ResourceGeneration::new(generation).unwrap(),
        )
    }
    fn digest(value: &[u8]) -> String {
        sha256_hex(value)
    }
    fn action_receipt(
        operation: &FailureOperation,
        disposition: ReceiptDisposition,
    ) -> ReceiptEnvelope {
        let state_fence = operation.state_fence.clone();
        let request_id = RequestId::new(operation.request_id.clone()).unwrap();
        let operation_id = OperationId::new(operation.operation_id.clone()).unwrap();
        let task_id = TaskId::new(operation.task_id.clone()).unwrap();
        let scope_id = WorkScopeId::new(operation.scope_id.clone()).unwrap();
        let product_id = ProductId::new("product-1").unwrap();
        let source_id = SourceId::new("source-1").unwrap();
        let metadata = eliot_contracts::RequestMetadata {
            request_id: request_id.clone(),
            session_id: None,
            task_id: Some(task_id.clone()),
            product_id: product_id.clone(),
            source_id,
            state_fence: state_fence.clone(),
            clock: ClockReading {
                valid_time_ms: Some(1),
                known_time_ms: Some(1),
                transaction_sequence: Some(TransactionSequence::genesis()),
                monotonic_ns: None,
            },
        };
        ReceiptEnvelope::issue(ReceiptCore {
            contract: contract_identity().unwrap(),
            kind: ReceiptKind::Operation,
            work_scope: WorkScopeBinding {
                scope_id,
                product_id,
                resource_generation: state_fence.resource_generation,
                state_fence: state_fence.clone(),
            },
            task: Some(TaskBinding {
                task_id,
                task_revision: TaskRevision::genesis(),
                state_fence: state_fence.clone(),
            }),
            session: None,
            causal: CausalBinding {
                state_fence: state_fence.clone(),
                transaction_sequence: TransactionSequence::genesis(),
                parent_receipt_id: None,
                predecessor_receipt_ids: Vec::new(),
            },
            request: RequestBinding {
                metadata,
                state_fence: state_fence.clone(),
            },
            operation: OperationBinding {
                operation_id,
                request_id,
                idempotency_key: operation.idempotency_key.clone(),
                operation_kind: "failed-action".into(),
                effect: EffectClass::Candidate,
                state_fence: state_fence.clone(),
            },
            authority: AuthorityBinding {
                authority_id: ContractId::new("authority-1").unwrap(),
                authority_owner: "owner".into(),
                authority_epoch: state_fence.authority_epoch,
                state_fence,
                allowed_effect: EffectClass::Candidate,
                proof_ceiling: ProofCeiling::CandidateArtifact,
            },
            artifacts: vec![eliot_receipts::ArtifactBinding {
                artifact_id: ArtifactId::new("action-artifact").unwrap(),
                sha256: digest(b"action"),
                role: ReceiptKind::Artifact,
                source_revision: None,
            }],
            verifier: Some(VerifierBinding {
                verifier_id: ContractId::new("verifier-1").unwrap(),
                verifier_revision: ContractVersion::new(1, 0, 0),
                artifact_ids: vec![ArtifactId::new("action-artifact").unwrap()],
                proof_ceiling: ProofCeiling::CandidateArtifact,
                state_fence: operation.state_fence.clone(),
            }),
            problem: None,
            coordination: None,
            disposition,
        })
        .unwrap()
    }
    fn evidence_envelope(state_fence: StateFence, raw_handle: &str) -> EvidenceEnvelope {
        EvidenceEnvelope {
            authority: EvidenceAuthority::SourceIdentity,
            freshness: EvidenceFreshness::ExactCandidate,
            coverage: EvidenceCoverage::CompleteForScope,
            status: EpistemicStatus::Supported,
            assertability: Assertability::Assertable,
            provenance: Provenance {
                source_id: SourceId::new("source-1").unwrap(),
                capture_route: "failure-fixture".into(),
                scope: "scope-1".into(),
                raw_handle: Some(raw_handle.into()),
                revision: Some("source-r1".into()),
            },
            verification: None,
            state_fence,
        }
    }
    fn full_input() -> FailureInput {
        let mut job = crate::job::sample_job();
        job.job_class = JobClass::Curation;
        job.frozen_manifest_digest = digest(b"manifest");
        let grounded = GroundedDreamDraft {
            schema_version: 1,
            job_id: "job-1".into(),
            draft_digest: digest(b"draft"),
            residues: vec![ClaimResidue {
                claim: "failure".into(),
                state: SupportState::Partial,
                detail: "grounded".into(),
            }],
            coverage_note: "one claim".into(),
        };
        let receipt = crate::draft::valid_receipt(&grounded.draft_digest, fence());
        let mut payload = crate::curation::sample_payload(CurationKind::Failure);
        if let crate::curation::CurationPayload::Failure(payload) = &mut payload {
            payload.target_evidence.evidence_refs = vec!["action-envelope".into()];
        }
        let denominator = TargetDenominator {
            mode: AtomicityMode::AllOrNothing,
            members: vec!["a".into(), "b".into(), "ab".into()],
            expected_total: 3,
        };
        let source_digest = digest(b"a");
        let profile_definition = FailureProfileDefinition::from_parts(
            "profile-owner".into(),
            "exact".into(),
            1,
            "profile-r1".into(),
            FailureComparator::ExactEquality,
            vec![
                FailureDimensionDescriptor {
                    source: FailureDimensionSource::Action,
                    field: "target_id".into(),
                    name: "target".into(),
                },
                FailureDimensionDescriptor {
                    source: FailureDimensionSource::Environment,
                    field: "environment_id".into(),
                    name: "environment".into(),
                },
            ],
            "profile".into(),
        )
        .unwrap();
        let item = ValidatedCurationItem {
            receipt: receipt.clone(),
            kind_spelling: "failure".into(),
            family_spelling: "failure".into(),
            payload: payload.clone(),
            denominator: denominator.clone(),
            source_digest: source_digest.clone(),
            task_id: "task-1".into(),
            scope_id: "scope-1".into(),
            state_fence: fence(),
            job_digest: digest(&canonical_bytes(&job).unwrap()),
            requester: job.requester.clone(),
            budget_note: "bounded".into(),
        };
        let mut screen = crate::registry::sample_binding();
        screen.request_id = eliot_contracts::RequestId::new("req-1").unwrap();
        screen.receipt_id = eliot_contracts::ReceiptId::new("rcpt-1").unwrap();
        screen.task_id = "task-1".into();
        screen.scope_id = "scope-1".into();
        screen.state_fence = fence();
        screen.state = ScreenState::Eligible;
        let mut request = TypedCurationHandlerRequest {
            request_id: "req-1".into(),
            receipt_id: "rcpt-1".into(),
            source_snapshot: screen.source_snapshot.clone(),
            source_revision: screen.source_revision.clone(),
            profile: screen.profile.clone(),
            kind: CurationKind::Failure,
            family: CurationFamily::Failure,
            job_id: "job-1".into(),
            scope_id: "scope-1".into(),
            task_id: "task-1".into(),
            state_fence: fence(),
            payload: payload.clone(),
            denominator: denominator.clone(),
            screen_binding: Some(screen.clone()),
        };
        let materials = vec![
            BundleMaterial {
                handle: "a".into(),
                disposition: SourceDisposition::Required,
                bytes: 1,
                digest: source_digest.clone(),
            },
            BundleMaterial {
                handle: "b".into(),
                disposition: SourceDisposition::Required,
                bytes: 1,
                digest: digest(b"b"),
            },
            BundleMaterial {
                handle: "ab".into(),
                disposition: SourceDisposition::Required,
                bytes: 2,
                digest: digest(b"ab"),
            },
            BundleMaterial {
                handle: "profile".into(),
                disposition: SourceDisposition::Required,
                bytes: profile_definition.definition_bytes.len() as u64,
                digest: profile_definition.definition_digest.clone(),
            },
        ];
        let mut bundle = crate::bundle::DreamInputBundle {
            schema_version: 1,
            job_id: "job-1".into(),
            scope_id: "scope-1".into(),
            task_id: "task-1".into(),
            state_fence: fence(),
            manifest_digest: digest(b"manifest"),
            materials,
            omissions: vec![crate::bundle::OmissionHandle {
                handle: "e-1".into(),
                reason: "not carried".into(),
                reversible: true,
                scope_id: "scope-1".into(),
                task_id: "task-1".into(),
                digest: digest(b"e-1"),
                nonrecoverable_reason: None,
            }],
            completeness: crate::bundle::BundleCompleteness::CompleteForScope,
            authoritative_denominator: Some("denom".into()),
        };
        let item_digest = item.item_digest(&grounded).unwrap();
        screen.item_digest = item_digest;
        request.screen_binding = Some(screen.clone());
        let action_operation = FailureOperation {
            operation_id: "failed-op".into(),
            idempotency_key: "failed-idem".into(),
            request_id: "failed-req".into(),
            candidate_id: "failed-cand".into(),
            attempt_id: "attempt-1".into(),
            task_id: "task-1".into(),
            scope_id: "scope-1".into(),
            state_fence: distinct_fence(2),
            requester: job.requester.clone(),
        };
        let action = FailureAction {
            action_id: "action-1".into(),
            operation_id: "failed-op".into(),
            attempt_id: "attempt-1".into(),
            target_id: "a".into(),
            input_schema: "schema".into(),
            input_digest: digest(b"input"),
            effect_id: "effect".into(),
            effect_class: EffectClass::Candidate,
            owner: "owner".into(),
            contract_revision: "r1".into(),
            contract_digest: digest(b"contract"),
        };
        let failed_receipt = action_receipt(
            &action_operation,
            ReceiptDisposition::Failure {
                code: eliot_contracts::ErrorCode::InvalidRequest,
                proof: ProofCeiling::CandidateArtifact,
            },
        );
        let action_envelope = evidence_envelope(distinct_fence(2), "raw-failed");
        let action_envelope_digest = digest(&canonical_bytes(&action_envelope).unwrap());
        bundle.materials.push(BundleMaterial {
            handle: "action-envelope".into(),
            disposition: SourceDisposition::Required,
            bytes: canonical_bytes(&action_envelope).unwrap().len() as u64,
            digest: action_envelope_digest.clone(),
        });
        let evidence = FailureEvidence {
            evidence_id: "e-1".into(),
            kind: FailureEvidenceKind::Attempt,
            operation_id: "failed-op".into(),
            request_id: "failed-req".into(),
            idempotency_key: "failed-idem".into(),
            action_id: "action-1".into(),
            task_id: "task-1".into(),
            scope_id: "scope-1".into(),
            state_fence: distinct_fence(2),
            digest: digest(b"verify"),
            envelope_digest: action_envelope_digest.clone(),
            material_handle: "action-envelope".into(),
            material_digest: action_envelope_digest.clone(),
            material_bytes: canonical_bytes(&action_envelope).unwrap(),
            owner: "owner".into(),
            coverage: FailureCoverage::Complete,
        };
        let outcome = FailureOutcome {
            intended: FailureExpectation {
                expected: FailureExpectedState::Failure,
                verifier: "verify".into(),
            },
            attempted: None,
            observed: ReceiptDisposition::Failure {
                code: eliot_contracts::ErrorCode::InvalidRequest,
                proof: ProofCeiling::CandidateArtifact,
            },
            verified: ReceiptDisposition::Failure {
                code: eliot_contracts::ErrorCode::InvalidRequest,
                proof: ProofCeiling::CandidateArtifact,
            },
            failure_state: Some(FailureObservationState::ExecutedButSemanticallyFailed),
            observed_receipt_ref: Some(failed_receipt.identity.receipt_id.to_string()),
            verified_receipt_ref: Some(failed_receipt.identity.receipt_id.to_string()),
            output_digest: None,
            possible_effects: vec!["unknown".into()],
            receipt_refs: vec![failed_receipt.identity.receipt_id.to_string()],
            coverage: FailureCoverage::Complete,
        };
        let action_evidence = FailureActionEvidence {
            action_operation: action_operation.clone(),
            action: action.clone(),
            outcome: outcome.clone(),
            evidence: vec![evidence.clone()],
            receipts: vec![failed_receipt.clone()],
            receipt_materials: vec![FailureReceiptMaterial {
                receipt_id: failed_receipt.identity.receipt_id.to_string(),
                handle: "action-receipt".into(),
                digest: failed_receipt.canonical_sha256().into(),
                bytes: failed_receipt.canonical_bytes().unwrap(),
            }],
            evidence_envelopes: vec![action_envelope.clone()],
            omitted_envelope_refs: vec![],
            coverage: FailureCoverage::Complete,
        };
        let environment = FailureEnvironment {
            environment_id: "env".into(),
            environment_revision: "r1".into(),
            platform: "windows".into(),
            tool_revision: "tool".into(),
            model_revision: None,
            config_revision: "cfg".into(),
            capability_revision: "cap".into(),
            policy_revision: "pol".into(),
            state_fence: fence(),
            coverage: FailureCoverage::Complete,
        };
        let control_operation = FailureOperation {
            operation_id: "control-op".into(),
            idempotency_key: "control-idem".into(),
            request_id: "control-req".into(),
            candidate_id: "control-cand".into(),
            attempt_id: "control-attempt".into(),
            task_id: "task-1".into(),
            scope_id: "scope-1".into(),
            state_fence: distinct_fence(3),
            requester: job.requester.clone(),
        };
        let control_receipt = action_receipt(
            &control_operation,
            ReceiptDisposition::Success {
                proof: ProofCeiling::CandidateArtifact,
            },
        );
        let control_envelope = evidence_envelope(distinct_fence(3), "raw-control");
        let control_envelope_digest = digest(&canonical_bytes(&control_envelope).unwrap());
        let mut historical_failed_evidence = evidence.clone();
        historical_failed_evidence.evidence_id = "e-1".into();
        bundle.materials.push(BundleMaterial {
            handle: "control-envelope".into(),
            disposition: SourceDisposition::Required,
            bytes: canonical_bytes(&control_envelope).unwrap().len() as u64,
            digest: control_envelope_digest.clone(),
        });
        bundle.materials.push(BundleMaterial {
            handle: "action-receipt".into(),
            disposition: SourceDisposition::Required,
            bytes: failed_receipt.canonical_bytes().unwrap().len() as u64,
            digest: failed_receipt.canonical_sha256().into(),
        });
        bundle.materials.push(BundleMaterial {
            handle: "control-receipt".into(),
            disposition: SourceDisposition::Required,
            bytes: control_receipt.canonical_bytes().unwrap().len() as u64,
            digest: control_receipt.canonical_sha256().into(),
        });
        let history = FailureHistory {
            coverage: FailureCoverage::Complete,
            expected_total: 2,
            entries: vec![
                FailureHistoryEntry {
                    history_id: "history-failed".into(),
                    operation_id: action_operation.operation_id.clone(),
                    request_id: action_operation.request_id.clone(),
                    idempotency_key: action_operation.idempotency_key.clone(),
                    fingerprint_id: "failed-fingerprint".into(),
                    trigger_digest: digest(b"failed-trigger"),
                    outcome: ReceiptDisposition::Failure {
                        code: eliot_contracts::ErrorCode::InvalidRequest,
                        proof: ProofCeiling::CandidateArtifact,
                    },
                    failure_state: Some(FailureObservationState::ExecutedButSemanticallyFailed),
                    task_id: action_operation.task_id.clone(),
                    scope_id: action_operation.scope_id.clone(),
                    state_fence: action_operation.state_fence.clone(),
                    independent: true,
                    semantic_success: false,
                    near_match: false,
                    false_activation: false,
                    observed: true,
                    evidence_refs: vec!["e-1".into()],
                    receipt_refs: vec![failed_receipt.identity.receipt_id.to_string()],
                    coverage: FailureCoverage::Complete,
                },
                FailureHistoryEntry {
                    history_id: "history-control".into(),
                    operation_id: control_operation.operation_id.clone(),
                    request_id: control_operation.request_id.clone(),
                    idempotency_key: control_operation.idempotency_key.clone(),
                    fingerprint_id: "control-fingerprint".into(),
                    trigger_digest: digest(b"control-trigger"),
                    outcome: ReceiptDisposition::Success {
                        proof: ProofCeiling::CandidateArtifact,
                    },
                    failure_state: None,
                    task_id: control_operation.task_id.clone(),
                    scope_id: control_operation.scope_id.clone(),
                    state_fence: control_operation.state_fence.clone(),
                    independent: true,
                    semantic_success: true,
                    near_match: false,
                    false_activation: false,
                    observed: true,
                    evidence_refs: vec!["history-evidence".into()],
                    receipt_refs: vec![control_receipt.identity.receipt_id.to_string()],
                    coverage: FailureCoverage::Complete,
                },
            ],
            omitted_refs: vec![],
            success_count: 1,
            near_match_count: 0,
            false_activation_count: 0,
            unknown_count: 0,
            receipts: vec![failed_receipt.clone(), control_receipt.clone()],
            receipt_materials: vec![
                FailureReceiptMaterial {
                    receipt_id: failed_receipt.identity.receipt_id.to_string(),
                    handle: "action-receipt".into(),
                    digest: failed_receipt.canonical_sha256().into(),
                    bytes: failed_receipt.canonical_bytes().unwrap(),
                },
                FailureReceiptMaterial {
                    receipt_id: control_receipt.identity.receipt_id.to_string(),
                    handle: "control-receipt".into(),
                    digest: control_receipt.canonical_sha256().into(),
                    bytes: control_receipt.canonical_bytes().unwrap(),
                },
            ],
            historical_evidence: vec![
                historical_failed_evidence,
                FailureEvidence {
                    evidence_id: "history-evidence".into(),
                    kind: FailureEvidenceKind::Control,
                    operation_id: control_operation.operation_id,
                    request_id: "control-req".into(),
                    idempotency_key: "control-idem".into(),
                    action_id: "control-action".into(),
                    task_id: "task-1".into(),
                    scope_id: "scope-1".into(),
                    state_fence: distinct_fence(3),
                    digest: digest(b"control-evidence"),
                    envelope_digest: control_envelope_digest.clone(),
                    material_handle: "control-envelope".into(),
                    material_digest: control_envelope_digest,
                    material_bytes: canonical_bytes(&control_envelope).unwrap(),
                    owner: "control-owner".into(),
                    coverage: FailureCoverage::Complete,
                },
            ],
            historical_evidence_envelopes: vec![action_envelope.clone(), control_envelope.clone()],
            omitted_evidence_envelope_refs: vec![],
        };
        let comparison = FailureComparisonProfile {
            profile_id: "exact".into(),
            schema_version: 1,
            comparator: FailureComparator::ExactEquality,
            definition: profile_definition.clone(),
            dimensions: vec![
                FailureDimension {
                    source: FailureDimensionSource::Action,
                    field: "target_id".into(),
                    name: "target".into(),
                    value: FailureDimensionValue::Text("a".into()),
                },
                FailureDimension {
                    source: FailureDimensionSource::Environment,
                    field: "environment_id".into(),
                    name: "environment".into(),
                    value: FailureDimensionValue::Text("env".into()),
                },
            ],
            missing_dimensions: vec![],
        };
        let proposal = FailureProposal {
            schema_version: 1,
            candidate_id: "cand-1".into(),
            fingerprint: "fp-1".into(),
            signature: "sig-1".into(),
            operation: FailureOperation {
                operation_id: job.operation_id.clone(),
                idempotency_key: job.idempotency_key.clone(),
                request_id: "req-1".into(),
                candidate_id: "cand-1".into(),
                attempt_id: "attempt-1".into(),
                task_id: "task-1".into(),
                scope_id: "scope-1".into(),
                state_fence: fence(),
                requester: job.requester.clone(),
            },
            class: FailureClass::PartialOrUnknownEffect,
            target_evidence: TargetEvidence {
                targets: vec!["a".into(), "b".into(), "ab".into()],
                evidence_refs: vec!["action-envelope".into()],
            },
            comparison,
            trigger: vec![
                FailureDimension {
                    source: FailureDimensionSource::Action,
                    field: "target_id".into(),
                    name: "target".into(),
                    value: FailureDimensionValue::Text("a".into()),
                },
                FailureDimension {
                    source: FailureDimensionSource::Environment,
                    field: "environment_id".into(),
                    name: "environment".into(),
                    value: FailureDimensionValue::Text("env".into()),
                },
            ],
            action: action.clone(),
            outcome,
            environment: environment.clone(),
            applicability: FailureApplicability {
                task_id: "task-1".into(),
                scope_id: "scope-1".into(),
                target_id: "a".into(),
                environment_id: "env".into(),
                platform: "windows".into(),
                tool_revision: "tool".into(),
                model_revision: None,
                config_revision: "cfg".into(),
                capability_revision: "cap".into(),
                effect_class: EffectClass::Candidate,
                coverage: FailureCoverage::Complete,
            },
            violated_invariant: "invariant".into(),
            evidence_refs: vec!["e-1".into()],
            counterevidence_refs: vec![],
            causal: FailureHypothesis {
                hypothesis_id: "h".into(),
                statement: "unknown".into(),
                evidence_refs: vec!["e-1".into()],
                limitation_refs: vec![],
                rival_refs: vec![],
                confounder_refs: vec![],
                status: FailureCausalStatus::Unknown,
            },
            controls: vec![],
            mitigation: FailureMitigation {
                do_not_repeat_until: "verify".into(),
                note: "safe".into(),
                owner: "owner".into(),
                safe_reattempt_verifier: "verifier-1".into(),
                verifier_revision: "1.0.0".into(),
                verifier_digest: digest(
                    &canonical_bytes(action_evidence.receipts[0].core.verifier.as_ref().unwrap())
                        .unwrap(),
                ),
                verifier_receipt_ref: action_evidence.receipts[0].identity.receipt_id.to_string(),
            },
            lifecycle: FailureLifecycle {
                reopen_condition: "new evidence".into(),
                extinction_condition: "superseded".into(),
                expiry_ms: None,
                inverse_refs: vec![],
                predecessor_fingerprint: None,
                current_fingerprint_revision: "r1".into(),
                raw_history_refs: vec![],
            },
            history,
            preservation: preservation(),
            source_refs: vec!["a".into()],
            policy_digest: digest(b"policy"),
            proof_ceiling: ProofCeiling::CandidateArtifact,
        };
        let mut source_members = vec![
            FailureSourceMember {
                handle: "a".into(),
                digest: source_digest,
                bytes: b"a".to_vec(),
                source_snapshot: screen.source_snapshot.clone(),
                source_revision: screen.source_revision.clone(),
                task_id: "task-1".into(),
                scope_id: "scope-1".into(),
                state_fence: fence(),
            },
            FailureSourceMember {
                handle: "b".into(),
                digest: digest(b"b"),
                bytes: b"b".to_vec(),
                source_snapshot: screen.source_snapshot.clone(),
                source_revision: screen.source_revision.clone(),
                task_id: "task-1".into(),
                scope_id: "scope-1".into(),
                state_fence: fence(),
            },
            FailureSourceMember {
                handle: "ab".into(),
                digest: digest(b"ab"),
                bytes: b"ab".to_vec(),
                source_snapshot: screen.source_snapshot.clone(),
                source_revision: screen.source_revision.clone(),
                task_id: "task-1".into(),
                scope_id: "scope-1".into(),
                state_fence: fence(),
            },
            FailureSourceMember {
                handle: "profile".into(),
                digest: profile_definition.definition_digest.clone(),
                bytes: profile_definition.definition_bytes.clone(),
                source_snapshot: screen.source_snapshot.clone(),
                source_revision: screen.source_revision.clone(),
                task_id: "task-1".into(),
                scope_id: "scope-1".into(),
                state_fence: fence(),
            },
        ];
        for (handle, bytes, member_digest) in [
            (
                "action-envelope",
                canonical_bytes(&action_envelope).unwrap(),
                action_envelope_digest.clone(),
            ),
            (
                "control-envelope",
                canonical_bytes(&control_envelope).unwrap(),
                digest(&canonical_bytes(&control_envelope).unwrap()),
            ),
            (
                "action-receipt",
                failed_receipt.canonical_bytes().unwrap(),
                failed_receipt.canonical_sha256().to_owned(),
            ),
            (
                "control-receipt",
                control_receipt.canonical_bytes().unwrap(),
                control_receipt.canonical_sha256().to_owned(),
            ),
        ] {
            source_members.push(FailureSourceMember {
                handle: handle.into(),
                digest: member_digest,
                bytes,
                source_snapshot: screen.source_snapshot.clone(),
                source_revision: screen.source_revision.clone(),
                task_id: "task-1".into(),
                scope_id: "scope-1".into(),
                state_fence: fence(),
            });
        }
        FailureInput {
            schema_version: 1,
            operation: proposal.operation.clone(),
            job,
            bundle,
            grounded,
            usage: BudgetUsage {
                input_bytes: 1,
                output_bytes: 1,
                source_width: 1,
                reference_width: 1,
                model_calls: 0,
                attempts: 0,
                candidates: 0,
                wall_ms: 0,
                work_fan_out: 0,
                report_bytes: 0,
                stu_used: 0,
            },
            source_members,
            item,
            request,
            screen,
            action_evidence,
            environment,
            history: proposal.history.clone(),
            proposal,
            policy_digest: digest(b"policy"),
            preservation: preservation(),
        }
    }

    #[test]
    fn complete_input_accepts_upstream_item_and_preserves_distinct_failed_operation() {
        let input = full_input();
        let validation = input.validate();
        assert!(validation.is_ok(), "{validation:?}");
        let first = failure_input_digest(&input).unwrap();
        assert_eq!(first, failure_input_digest(&input).unwrap());
        let proposal_digest =
            crate::failure::result::failure_proposal_digest(&input.proposal).unwrap();
        let mut permuted = input;
        permuted.source_members.reverse();
        permuted.action_evidence.receipt_materials.reverse();
        permuted.history.receipts.reverse();
        permuted.proposal.history.receipts.reverse();
        assert_eq!(first, failure_input_digest(&permuted).unwrap());
        assert_eq!(
            proposal_digest,
            crate::failure::result::failure_proposal_digest(&permuted.proposal).unwrap()
        );
    }

    #[test]
    fn sealed_result_retains_complete_input_and_local_preservation() {
        let input = full_input();
        let result = crate::failure::result::FailureResult {
            schema_version: 1,
            candidate_id: String::new(),
            operation_id: String::new(),
            input_digest: "0".repeat(64),
            policy_digest: "0".repeat(64),
            input: input.clone(),
            proposal: input.proposal.clone(),
            disposition: crate::failure::result::FailureDisposition::Candidate,
            common_disposition: crate::candidate::CandidateDisposition::Candidate,
            preservation: input.preservation.clone(),
            final_preservation: preservation(),
            assessment_refs: vec!["e-1".into()],
            assessment_missing_refs: Vec::new(),
            rollback: crate::failure::records::FailureRollback {
                predecessor: None,
                inverse_refs: Vec::new(),
                invalidation_refs: Vec::new(),
                raw_history_refs: Vec::new(),
                note: "retained".into(),
            },
            proof_ceiling: ProofCeiling::CandidateArtifact,
            handler_result: crate::registry::TypedCurationHandlerResult {
                request_id: "req-1".into(),
                kind: CurationKind::Failure,
                family: CurationFamily::Failure,
                disposition: crate::candidate::CandidateDisposition::Candidate,
                handler_id: "failure-handler".into(),
                request_digest: "0".repeat(64),
                result_digest: "0".repeat(64),
            },
        };
        let sealed = crate::failure::result::seal_failure(result, &input).unwrap();
        assert_eq!(sealed.input, input);
        assert!(sealed.validate_against(&input).is_ok());
        let mut permuted_input = input.clone();
        permuted_input.source_members.reverse();
        permuted_input.history.receipts.reverse();
        permuted_input.proposal.history.receipts.reverse();
        let mut permuted_result = sealed.clone();
        permuted_result.input = permuted_input.clone();
        permuted_result.proposal = permuted_input.proposal.clone();
        assert_eq!(
            crate::failure::result::failure_result_digest(&sealed).unwrap(),
            crate::failure::result::failure_result_digest(&permuted_result).unwrap()
        );
        assert!(permuted_result.validate_against(&permuted_input).is_ok());
    }

    #[test]
    fn changed_failed_receipt_binding_is_rejected_after_valid_fixture() {
        let mut input = full_input();
        assert!(input.validate().is_ok());
        let mut conflicting = input.clone();
        conflicting.history.historical_evidence[0].owner = "different-owner".into();
        assert!(conflicting.validate().is_err());
        input.action_evidence.action_operation.idempotency_key = "changed-idempotency".into();
        input.action_evidence.evidence[0].idempotency_key = "changed-idempotency".into();
        assert!(input.validate().is_err());
    }
}
