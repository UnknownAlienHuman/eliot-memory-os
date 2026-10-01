//! Original Governor-admitted cue source for the Orientation stage.

use eliot_contracts::StateFence;
use eliot_contracts::TransactionSequence;
use eliot_receipts::{EffectClass, ProofCeiling, ReceiptEnvelope, ReceiptKind};
use eliot_contracts::TaskId;
use eliot_receipts::WorkScopeId;
use serde::{Deserialize, Serialize};

use crate::{
    CueContractError, CueSnapshotBuildCandidate, NormalizationProfile, SnapshotId,
};

/// Exact operation kind used by the Governor's original cue-admission receipt.
pub const ORIENTATION_CUE_ADMISSION_OPERATION_KIND: &str =
    "eliot.orientation.cue_binding_admission.v1";

/// Native source document read by the Orientation cue stage.
///
/// It retains the exact closed A-10 snapshot candidate, its original A-12
/// admitted-binding projections, the complete A-12 result digest, and one
/// full Governor decision receipt covering that digest and every candidate
/// artifact. The owner row metadata is separately joined to these explicit
/// task, scope, fence and source-revision fields by the campaign reader.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationCueBindingsSource {
    /// Wire schema version for this Orientation-only source.
    pub schema_version: u16,
    /// Original task identity for this cue closure.
    pub task_id: TaskId,
    /// Original work scope for this cue closure.
    pub scope_id: WorkScopeId,
    /// Full original fence captured by the Governor admission decision.
    pub state_fence: StateFence,
    /// Exact source revision retained by the closed cue snapshot.
    pub source_revision: u64,
    /// Original snapshot identity retained in the native A-10 candidate.
    pub snapshot_id: SnapshotId,
    /// Exact normalization profile used by every retained source row.
    pub normalization_profile: NormalizationProfile,
    /// Current Policy owner snapshot used by the Governor admission gate.
    pub policy_snapshot_id: String,
    /// Exact canonical digest of the current Policy owner snapshot.
    pub policy_snapshot_digest: crate::Digest,
    /// Digest retained by the original A-12 result and covered by the decision receipt.
    pub a12_result_digest: crate::Digest,
    /// Exact canonical bytes of the full native A-12 result, including cold and omitted rows.
    pub a12_result_canonical_bytes: Vec<u8>,
    /// Original closed A-10 candidate and all retained A-12 projections.
    pub snapshot_candidate: CueSnapshotBuildCandidate,
    /// One original full Governor decision receipt for the complete A-12 result.
    pub admission_receipt: ReceiptEnvelope,
}

impl OrientationCueBindingsSource {
    /// Current Orientation cue source wire version.
    pub const SCHEMA_VERSION: u16 = 1;

    /// Validate every retained owner record and exact cross-record join.
    pub fn validate(&self) -> Result<(), CueContractError> {
        let fail = |field| CueContractError::Foundation { field };
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(fail("orientation_cue.schema_version"));
        }
        self.state_fence
            .validate()
            .map_err(|_| fail("orientation_cue.state_fence"))?;
        self.normalization_profile.validate()?;
        self.snapshot_candidate.validate_published()?;
        if self.a12_result_canonical_bytes.is_empty() {
            return Err(fail("orientation_cue.a12_result_bytes"));
        }
        self.admission_receipt
            .validate()
            .map_err(|_| fail("orientation_cue.admission_receipt"))?;

        let snapshot = &self.snapshot_candidate.snapshot;
        if self.snapshot_candidate.scope_id != self.scope_id
            || snapshot.snapshot_id != self.snapshot_id
            || snapshot.state_fence != self.state_fence
            || snapshot.source_revision != self.source_revision
            || snapshot.rebuild.normalization_profile != self.normalization_profile
        {
            return Err(fail("orientation_cue.snapshot_binding"));
        }
        if self.source_revision == 0 {
            return Err(fail("orientation_cue.source_revision"));
        }

        let bindings = &self.snapshot_candidate.admitted_bindings;
        validate_decision_receipt(
            &self.admission_receipt,
            &self.task_id,
            &self.scope_id,
            &self.state_fence,
            &self.policy_snapshot_id,
            self.policy_snapshot_digest.as_str(),
            self.a12_result_digest.as_str(),
            bindings,
        )?;

        for binding in bindings {
            let candidate = &binding.candidate;
            let normalized = &binding.normalized;
            let admission = &binding.admission;
            binding.validate()?;
            if admission.task_id != self.task_id
                || admission.scope_id != self.scope_id
                || admission.state_fence != self.state_fence
                || normalized.observed.context.task_id != self.task_id
                || normalized.observed.context.scope_id != self.scope_id
                || normalized.observed.context.state_fence != self.state_fence
                || normalized.profile != self.normalization_profile
            {
                return Err(fail("orientation_cue.binding_context"));
            }
            if self.admission_receipt.identity != admission.receipt {
                return Err(fail("orientation_cue.admission_identity"));
            }
        }
        Ok(())
    }
}

fn validate_decision_receipt(
    receipt: &ReceiptEnvelope,
    task_id: &TaskId,
    scope_id: &WorkScopeId,
    state_fence: &StateFence,
    policy_snapshot_id: &str,
    policy_snapshot_digest: &str,
    a12_result_digest: &str,
    bindings: &[crate::AdmittedCueBindingProjection],
) -> Result<(), CueContractError> {
    let core = &receipt.core;
    let task_matches = core.task.as_ref().is_some_and(|task| {
        &task.task_id == task_id
            && &task.state_fence == state_fence
            && state_fence.task_revision.as_ref() == Some(&task.task_revision)
    });
    let result_artifact_matches = core.artifacts.iter().any(|artifact| {
        artifact.artifact_id.as_str() == a12_result_digest
            && artifact.sha256 == a12_result_digest
            && artifact.role == ReceiptKind::Artifact
    });
    let policy_artifact_matches = core.artifacts.iter().any(|artifact| {
        artifact.artifact_id.as_str() == policy_snapshot_id
            && artifact.sha256 == policy_snapshot_digest
            && artifact.source_revision.as_deref() == Some(policy_snapshot_id)
            && artifact.role == ReceiptKind::Artifact
    });
    let candidate_artifacts_match = bindings.iter().all(|binding| {
        core.artifacts.iter().any(|artifact| {
            artifact.artifact_id.as_str() == binding.candidate.binding_candidate_id.as_str()
                && artifact.sha256 == binding.candidate.digest.as_str()
                && artifact.role == ReceiptKind::Artifact
        })
    });
    let expected_artifact_count = bindings.len().saturating_add(2);
    let expected_success = eliot_receipts::ReceiptDisposition::Success {
        proof: ProofCeiling::CandidateArtifact,
    };
    if core.kind != ReceiptKind::Operation
        || eliot_receipts::contract_identity().ok().as_ref() != Some(&core.contract)
        || !task_matches
        || core.work_scope.scope_id != *scope_id
        || &core.work_scope.state_fence != state_fence
        || core.work_scope.resource_generation != state_fence.resource_generation
        || core.work_scope.product_id != core.request.metadata.product_id
        || &core.request.state_fence != state_fence
        || core.request.metadata.task_id.as_ref() != Some(task_id)
        || core.request.metadata.session_id.is_none()
        || core.request.metadata.clock.valid_time_ms.is_none()
        || core.session.as_ref().is_none_or(|session| {
            Some(&session.session_id) != core.request.metadata.session_id.as_ref()
                || &session.state_fence != state_fence
                || !session
                    .authority_epoch
                    .is_same_authority(&state_fence.authority_epoch)
        })
        || &core.operation.state_fence != state_fence
        || core.operation.request_id != core.request.metadata.request_id
        || core.operation.idempotency_key.as_str() != core.request.metadata.request_id.as_str()
        || core.operation.effect != EffectClass::Candidate
        || core.operation.operation_kind != ORIENTATION_CUE_ADMISSION_OPERATION_KIND
        || &core.authority.state_fence != state_fence
        || core.authority.allowed_effect != EffectClass::Candidate
        || core.authority.proof_ceiling != ProofCeiling::CandidateArtifact
        || core.authority.authority_owner != "owner:eliot-governor/orientation-cue-bindings"
        || core.authority.authority_epoch != state_fence.authority_epoch
        || &core.causal.state_fence != state_fence
        || core.causal.transaction_sequence != TransactionSequence::genesis()
        || core.causal.parent_receipt_id.is_some()
        || !core.causal.predecessor_receipt_ids.is_empty()
        || core.disposition != expected_success
        || core.artifacts.len() != expected_artifact_count
        || !policy_artifact_matches
        || !result_artifact_matches
        || !candidate_artifacts_match
    {
        return Err(CueContractError::Foundation {
            field: "orientation_cue.admission_receipt_binding",
        });
    }
    Ok(())
}
