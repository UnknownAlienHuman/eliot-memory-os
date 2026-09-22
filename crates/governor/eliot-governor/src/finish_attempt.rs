//! Governor-owned production FinishAttempt path.
//!
//! The adapter owns the boundary between the public candidate draft and the
//! rebuildable [`eliot_finish::FinishService`].  It reads the current task and
//! canonical finish-evidence owner at one fence, evaluates a scratch service,
//! persists the complete receipt projection through the existing canonical
//! transition path, and never treats a worker/provider result as task finish.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_canonical::{
    AcceptanceCoverage, CanonicalWriteEnvelope, FinishAttemptDraft, FinishEvidence,
};
use eliot_contracts::{canonical_json_bytes, sha256_hex, OperationId, StateFence, TaskId};
use eliot_coordination::CoordinationOwner;
use eliot_finish::{
    FinishAdmission, FinishAttempt, FinishClosureIntent, FinishContext, FinishDecisionReceipt,
    FinishError, FinishService, TaskLifecycleState,
};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    generated_operation_manifests, operation_manifest_set_digest, EffectClass,
    EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationManifestDigest, ScopeId, SecurityContext, StoreFailure, TransitionClass, WriteReceipt,
    WriteReceiptStatus,
};
use eliot_observation::{
    EpistemicStatus, ObservationAdmissionResult, ObservationJournal, ObservationPlanBinding,
};
use eliot_task::{TaskCommand, TaskLifecycleOwner, TaskRecord, TaskState};
use thiserror::Error;

use crate::{
    CanonicalAdmissionOwner, CanonicalAdmissionSnapshot, CanonicalFinishEvidence,
    CanonicalPlanBinding, CompositionError, GovernorOwners, KernelPortError, KernelTransitionPort,
};

const GOVERNOR_SCOPE_ID: &str = "governor";

/// Typed failure at the production finish boundary.
#[derive(Debug, Error)]
pub enum FinishAttemptError {
    /// The strict finish service rejected the candidate or rehydrated state.
    #[error("finish owner rejected the attempt: {0}")]
    Finish(#[from] FinishError),
    /// The canonical owner or composition rejected the operation.
    #[error("finish composition rejected the attempt: {0}")]
    Composition(#[from] CompositionError),
    /// The neutral Kernel transition could not establish an outcome.
    #[error("finish Kernel transition failed: {0}")]
    Kernel(#[from] KernelPortError),
    /// The canonical receipt was not a committed finish mutation.
    #[error("finish mutation was not committed: {0}")]
    Store(String),
    /// Canonical bytes or the production manifest could not be built.
    #[error("finish transition serialization failed: {0}")]
    Serialization(String),
}

impl FinishAttemptError {
    /// Returns a typed Store failure when a caller needs the existing failure
    /// projection. Finish owner rejection and transport gaps have no Store
    /// mutation and therefore return `None`.
    #[must_use]
    pub const fn store_failure(&self) -> Option<&StoreFailure> {
        None
    }
}

/// Governor adapter over the single task, canonical, and finish owners.
pub struct GovernorFinishAttempt<'a, P: ?Sized> {
    task: &'a TaskLifecycleOwner,
    canonical: &'a CanonicalAdmissionOwner,
    coordination: &'a CoordinationOwner,
    observation: &'a ObservationJournal,
    finish: &'a FinishService,
    kernel: &'a P,
    finish_owner_revision: u64,
}

impl<'a, P: ?Sized> GovernorFinishAttempt<'a, P> {
    pub(crate) fn new(
        owners: &'a GovernorOwners<P>,
        canonical: &'a CanonicalAdmissionOwner,
        kernel: &'a P,
        finish_owner_revision: u64,
    ) -> Self {
        Self {
            task: &owners.task,
            canonical,
            coordination: &owners.coordination,
            observation: &owners.observation,
            finish: &owners.finish,
            kernel,
            finish_owner_revision,
        }
    }
}

/// Pure output of one canonical finish-evidence derivation. The snapshot is
/// the next owner image; it is committed together with the durable decision.
struct ProducedFinishEvidence {
    canonical: CanonicalFinishEvidence,
    snapshot: CanonicalAdmissionSnapshot,
}

impl<P: ?Sized> GovernorFinishAttempt<'_, P> {
    /// Rehydrates finish evidence from the current owner projections.
    ///
    /// Every handle in the result comes from a same-fence task event,
    /// task-and-plan-bound observation admission, or the coordination owner.
    /// Missing material is retained as an explicit gap where the finish
    /// contract permits it; missing owner identity or acceptance evidence
    /// prevents publication entirely.
    fn produce_finish_evidence(
        &self,
        task_id: &TaskId,
        task: &TaskRecord,
        fence: &StateFence,
        plan: &CanonicalPlanBinding,
    ) -> Result<ProducedFinishEvidence, FinishAttemptError> {
        let mut frame_refs = BTreeSet::new();
        let mut finish_authority_ref = None;
        let mut executed_verifier_run_refs = BTreeSet::new();
        for event in self.task.events().iter().filter(|event| {
            event.task_id == *task_id && event.state_fence == *fence
        }) {
            let Some(command) = &event.command else {
                continue;
            };
            match command {
                TaskCommand::Frame { frame_ref } => {
                    frame_refs.insert(frame_ref.clone());
                }
                TaskCommand::AuthorizeAction { authority_ref, .. } => {
                    finish_authority_ref = Some(authority_ref.clone());
                }
                TaskCommand::Verify { verification_ref } => {
                    executed_verifier_run_refs.insert(verification_ref.clone());
                }
                _ => {}
            }
        }
        let finish_authority_ref = finish_authority_ref.ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical task has no same-fence action authority for finish".to_owned(),
            ))
        })?;
        if frame_refs.is_empty() {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical task has no same-fence acceptance frame".to_owned(),
            )));
        }

        let coordination = self
            .coordination
            .finish_projection(task_id.as_str(), fence)
            .map_err(|error| {
                FinishAttemptError::Composition(CompositionError::Recovery(format!(
                    "coordination finish projection failed: {error}"
                )))
            })?;
        if coordination.state_fence != *fence || coordination.task_id != task_id.as_str() {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "coordination finish projection has a stale task fence".to_owned(),
            )));
        }

        let mut evidence_refs = BTreeSet::new();
        let mut acceptance_digests = BTreeSet::new();
        let mut stale_verifier_run_refs = BTreeSet::new();
        let mut effect_receipt_refs = BTreeSet::new();
        for entry in self.observation.snapshot() {
            let ObservationAdmissionResult::Accepted { receipt } = entry.result else {
                continue;
            };
            if receipt.state_fence != *fence {
                continue;
            }
            let Some(selection) = receipt.task_selection.as_ref() else {
                continue;
            };
            if selection.task_ref != task_id.as_str() || selection.task_revision != task.revision {
                continue;
            }
            if !matches_plan(receipt.plan.as_ref(), plan, fence) {
                continue;
            }
            acceptance_digests.insert(selection.acceptance_digest.clone());
            evidence_refs.insert(receipt.record_id.clone());
            evidence_refs.insert(selection.evidence_ref.clone());
            if let Some(event) = &receipt.record.event {
                for reference in &event.evidence_and_raw_handles {
                    evidence_refs.insert(reference.clone());
                }
                effect_receipt_refs.insert(format!("effect:{}", event.dedup_key));
            }
            if let Some(evidence) = receipt.evidence {
                if evidence.state_fence != *fence {
                    continue;
                }
                if let Some(binding) = evidence.verification {
                    if matches!(evidence.status, EpistemicStatus::Verified) {
                        executed_verifier_run_refs.insert(binding.run_id.to_string());
                    } else {
                        stale_verifier_run_refs.insert(binding.run_id.to_string());
                    }
                }
            }
        }
        if evidence_refs.is_empty() {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical finish evidence has no accepted task-and-plan-bound observation"
                    .to_owned(),
            )));
        }
        evidence_refs.extend(coordination.artifact_refs.iter().cloned());
        evidence_refs.extend(effect_receipt_refs);

        let mut acceptance = Vec::with_capacity(frame_refs.len() + acceptance_digests.len() + 1);
        let mut requirement_ids: Vec<String> = frame_refs
            .into_iter()
            .map(|frame_ref| format!("task-acceptance:{frame_ref}"))
            .collect();
        requirement_ids.extend(
            acceptance_digests
                .into_iter()
                .map(|digest| format!("acceptance:{digest}")),
        );
        requirement_ids.push(format!(
            "plan-requirement:{}:{}",
            plan.plan_id, plan.plan_revision
        ));
        requirement_ids.sort();
        requirement_ids.dedup();
        let mut verifier_refs: Vec<String> = executed_verifier_run_refs.iter().cloned().collect();
        verifier_refs.sort();
        let mut stale_refs: Vec<String> = stale_verifier_run_refs.into_iter().collect();
        stale_refs.sort();
        let complete = task.state == TaskState::DoneVerified
            && !coordination.artifact_refs.is_empty()
            && !verifier_refs.is_empty()
            && stale_refs.is_empty()
            && coordination.unresolved_refs.is_empty()
            && coordination.descendant_receipt_ref.is_some();
        for item_id in requirement_ids {
            acceptance.push(AcceptanceCoverage {
                item_id,
                satisfied: complete,
                evidence_refs: evidence_refs.iter().cloned().collect(),
                verifier_run_refs: verifier_refs.clone(),
                requires_verifier: true,
            });
        }
        let mut artifact_refs = coordination.artifact_refs.clone();
        artifact_refs.sort();
        artifact_refs.dedup();
        let mut unresolved_effect_refs = coordination.unresolved_refs.clone();
        unresolved_effect_refs.sort();
        unresolved_effect_refs.dedup();
        let descendant_closure = if let Some(receipt_ref) = coordination.descendant_receipt_ref {
            eliot_finish::DescendantClosure::Complete { receipt_ref }
        } else {
            eliot_finish::DescendantClosure::Incomplete {
                unresolved_refs: unresolved_effect_refs.clone(),
            }
        };
        let evidence = FinishEvidence {
            task_id: task_id.as_str().to_owned(),
            current_task_revision: task.revision,
            artifact_refs,
            acceptance,
            executed_verifier_run_refs: verifier_refs,
            stale_verifier_run_refs: stale_refs,
            unresolved_effect_refs,
        };
        evidence
            .validate()
            .map_err(|error| FinishAttemptError::Finish(FinishError::from(error)))?;
        let canonical = CanonicalFinishEvidence {
            state_fence: fence.clone(),
            evidence,
            descendant_closure,
            finish_authority_ref: finish_authority_ref.clone(),
            closure_authority_ref: Some(finish_authority_ref.clone()),
        };
        let snapshot = self.canonical.prepare_finish_evidence(canonical.clone())?;
        Ok(ProducedFinishEvidence { canonical, snapshot })
    }
}

fn matches_plan(
    observed: Option<&ObservationPlanBinding>,
    plan: &CanonicalPlanBinding,
    fence: &StateFence,
) -> bool {
    observed.is_some_and(|observed| {
        observed.plan_id == plan.plan_id
            && observed.plan_revision == plan.plan_revision
            && observed.state_fence == *fence
    })
}

impl<P: KernelTransitionPort + ?Sized> GovernorFinishAttempt<'_, P> {
    /// Produces and commits the next canonical finish-evidence owner image.
    ///
    /// The derived child identity is created by Governor for this owner leg;
    /// it carries the admitted request binding and never accepts proof or
    /// evidence from the public draft.  An identical current owner image is
    /// already materialized and therefore is a readback no-op.
    pub async fn publish_finish_evidence(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        draft: &FinishAttemptDraft,
    ) -> Result<Option<WriteReceipt>, FinishAttemptError> {
        validate_identity(identity)?;
        draft.validate().map_err(FinishError::from)?;
        let fence = identity.request.metadata.state_fence.clone();
        if self.canonical.state_fence() != &fence {
            return Err(FinishError::FenceMismatch.into());
        }
        let task_id = TaskId::new(draft.task_id.clone())
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
        if identity.request.metadata.task_id.as_ref() != Some(&task_id) {
            return Err(FinishError::Canonical(
                eliot_canonical::CanonicalError::TaskBindingMismatch,
            )
            .into());
        }
        let expected_revision = fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value())
            .ok_or_else(|| {
                FinishAttemptError::Serialization(
                    "finish request is missing its task revision fence".to_owned(),
                )
            })?;
        if expected_revision != draft.expected_task_revision {
            return Err(
                FinishError::Canonical(eliot_canonical::CanonicalError::StaleTaskRevision).into(),
            );
        }
        let task = self.task.task(&task_id).ok_or_else(|| {
            FinishAttemptError::Serialization(format!(
                "canonical task {} is absent",
                task_id.as_str()
            ))
        })?;
        validate_task(task, &fence, expected_revision)?;
        let plan = self.canonical.read_current_plan(&fence)?;
        if plan.task_id != task_id {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical task does not match the current canonical plan".to_owned(),
            )));
        }
        let produced = self.produce_finish_evidence(&task_id, task, &fence, &plan)?;
        if self
            .canonical
            .read_finish_evidence(&fence)
            .ok()
            .is_some_and(|existing| existing == produced.canonical)
        {
            return Ok(None);
        }

        let evidence_operation = OperationId::new(format!("{operation_id}/finish-evidence"))
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
        let evidence_idempotency = format!("{}:finish-evidence", identity.idempotency_key);
        let evidence_identity = RequestIdentity {
            request: identity.request.clone(),
            idempotency_key: evidence_idempotency,
            deadline_unix_ms: identity.deadline_unix_ms,
            cancellation_id: identity.cancellation_id.clone(),
        };
        let envelope = finish_evidence_envelope(
            &evidence_identity,
            evidence_operation.clone(),
            &produced.snapshot,
        )?;
        let committed = match self
            .canonical
            .commit(self.kernel, &evidence_identity, envelope)
            .await
        {
            Ok(receipt) => receipt,
            Err(CompositionError::Kernel(KernelPortError::Unknown(_))) => self
                .kernel
                .receipt(evidence_operation.clone())
                .await?
                .ok_or_else(|| {
                    FinishAttemptError::Kernel(KernelPortError::Unknown(
                        "finish-evidence receipt is unresolved after an unknown commit outcome"
                            .to_owned(),
                    ))
                })?,
            Err(error) => return Err(error.into()),
        };
        check_finish_receipt(
            &committed,
            &evidence_operation,
            &fence,
            &evidence_identity.idempotency_key,
        )?;
        Ok(Some(committed))
    }

    /// Rehydrates and evaluates one candidate against canonical owner state.
    ///
    /// The attempt identity is the admitted idempotency identity.  Public
    /// callers provide only the draft; closure intent is a fail-closed owner
    /// mapping, and evidence comes exclusively from the canonical owner.
    pub async fn submit(
        &self,
        identity: &RequestIdentity,
        operation_id: OperationId,
        draft: FinishAttemptDraft,
    ) -> Result<FinishDecisionReceipt, FinishAttemptError> {
        validate_identity(identity)?;
        draft.validate().map_err(FinishError::from)?;
        let fence = identity.request.metadata.state_fence.clone();
        if self.canonical.state_fence() != &fence {
            return Err(FinishError::FenceMismatch.into());
        }
        let task_id = TaskId::new(draft.task_id.clone())
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
        if identity.request.metadata.task_id.as_ref() != Some(&task_id) {
            return Err(FinishError::Canonical(
                eliot_canonical::CanonicalError::TaskBindingMismatch,
            )
            .into());
        }
        let expected_revision = fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value())
            .ok_or_else(|| {
                FinishAttemptError::Serialization(
                    "finish request is missing its task revision fence".to_owned(),
                )
            })?;
        if expected_revision != draft.expected_task_revision {
            return Err(
                FinishError::Canonical(eliot_canonical::CanonicalError::StaleTaskRevision).into(),
            );
        }
        let task = self.task.task(&task_id).ok_or_else(|| {
            FinishAttemptError::Serialization(format!(
                "canonical task {} is absent",
                task_id.as_str()
            ))
        })?;
        validate_task(task, &fence, expected_revision)?;
        let plan = self.canonical.read_current_plan(&fence)?;
        if plan.task_id != task_id {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical task does not match the current canonical plan".to_owned(),
            )));
        }
        let canonical = self.canonical.read_finish_evidence(&fence)?;
        if canonical.evidence.task_id != task_id.as_str()
            || canonical.evidence.current_task_revision != task.revision
        {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical finish evidence is stale for the current task".to_owned(),
            )));
        }
        if self.finish_owner_revision == 0 {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "finish owner revision is absent; finish persistence is unavailable".to_owned(),
            )));
        }

        let context = FinishContext {
            task_id: task_id.as_str().to_owned(),
            current_task_revision: task.revision,
            current_state_fence: fence.clone(),
            lifecycle: lifecycle_state(task.state),
            finish_authority_ref: canonical.finish_authority_ref,
            closure_authority_ref: canonical.closure_authority_ref,
            descendant_closure: canonical.descendant_closure,
            evidence: canonical.evidence,
        };
        let requested_outcome = draft.requested_outcome;
        let attempt = FinishAttempt {
            attempt_id: identity.idempotency_key.clone(),
            state_fence: fence.clone(),
            draft,
            closure_intent: closure_intent(requested_outcome),
            completion_proof: None,
        };
        let mut scratch = self.finish.clone();
        let admission = scratch.evaluate(attempt.clone(), &context)?;
        let receipt = match admission {
            FinishAdmission::Replayed { receipt } => return Ok(receipt),
            FinishAdmission::Accepted { receipt } => receipt,
        };
        let receipts = scratch.receipts();
        let envelope = finish_envelope(
            identity,
            operation_id.clone(),
            &attempt,
            &context,
            &receipts,
            self.finish_owner_revision,
        )?;
        let committed = match self.canonical.commit(self.kernel, identity, envelope).await {
            Ok(receipt) => receipt,
            Err(CompositionError::Kernel(KernelPortError::Unknown(_))) => self
                .kernel
                .receipt(operation_id.clone())
                .await?
                .ok_or_else(|| {
                    FinishAttemptError::Kernel(KernelPortError::Unknown(
                        "finish receipt is unresolved after an unknown commit outcome".to_owned(),
                    ))
                })?,
            Err(error) => return Err(error.into()),
        };
        check_finish_receipt(&committed, &operation_id, &fence, &identity.idempotency_key)?;
        Ok(receipt)
    }
}

fn validate_identity(identity: &RequestIdentity) -> Result<(), FinishAttemptError> {
    identity
        .validate()
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    if identity.request.state_fence != identity.request.metadata.state_fence {
        return Err(FinishError::FenceMismatch.into());
    }
    Ok(())
}

fn validate_task(
    task: &TaskRecord,
    fence: &StateFence,
    expected_revision: u64,
) -> Result<(), FinishAttemptError> {
    if task.state_fence != *fence {
        return Err(FinishError::FenceMismatch.into());
    }
    if task.revision != expected_revision || task.revision == 0 {
        return Err(
            FinishError::Canonical(eliot_canonical::CanonicalError::StaleTaskRevision).into(),
        );
    }
    Ok(())
}

fn lifecycle_state(state: TaskState) -> TaskLifecycleState {
    match state {
        TaskState::Proposed => TaskLifecycleState::Proposed,
        TaskState::Open => TaskLifecycleState::Open,
        TaskState::Framed => TaskLifecycleState::Framed,
        TaskState::Verifying => TaskLifecycleState::Verifying,
        TaskState::Blocked => TaskLifecycleState::Blocked,
        TaskState::UnderstandingRequired | TaskState::ActionAuthorized | TaskState::Executing => {
            TaskLifecycleState::Active
        }
        TaskState::DoneVerified | TaskState::Failed | TaskState::Partial => {
            TaskLifecycleState::Closing
        }
    }
}

fn closure_intent(outcome: eliot_canonical::RequestedFinishOutcome) -> FinishClosureIntent {
    match outcome {
        eliot_canonical::RequestedFinishOutcome::Cancelled => FinishClosureIntent::Cancel,
        eliot_canonical::RequestedFinishOutcome::Superseded => FinishClosureIntent::Supersede,
        _ => FinishClosureIntent::Continue,
    }
}

fn production_manifest_digest() -> Result<OperationManifestDigest, FinishAttemptError> {
    operation_manifest_set_digest(
        &generated_operation_manifests()
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?,
    )
    .map_err(|error| FinishAttemptError::Serialization(error.to_string()))
}

fn finish_evidence_envelope(
    identity: &RequestIdentity,
    operation_id: OperationId,
    snapshot: &CanonicalAdmissionSnapshot,
) -> Result<CanonicalWriteEnvelope, FinishAttemptError> {
    let snapshot_bytes = canonical_json_bytes(snapshot)
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let snapshot_json = String::from_utf8(snapshot_bytes.clone())
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let expected_canonical_revision = snapshot
        .owner_revision
        .checked_sub(1)
        .ok_or_else(|| {
            FinishAttemptError::Serialization(
                "canonical finish-evidence snapshot revision has no CAS predecessor".to_owned(),
            )
        })?;
    let evidence = snapshot.finish_evidence.as_ref().ok_or_else(|| {
        FinishAttemptError::Serialization(
            "finish-evidence envelope cannot publish an absent evidence owner".to_owned(),
        )
    })?;
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "expected_canonical_revision".to_owned(),
        serde_json::Value::String(expected_canonical_revision.to_string()),
    );
    parameters.insert(
        "snapshot_json".to_owned(),
        serde_json::Value::String(snapshot_json),
    );
    let scope_id = ScopeId::new(GOVERNOR_SCOPE_ID)
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    Ok(CanonicalWriteEnvelope {
        operation_id,
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id,
        task_id: Some(evidence.evidence.task_id.clone()),
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: sha256_hex(&snapshot_bytes),
        operation_manifest_digest: production_manifest_digest()?,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::RecordFinishEvidence,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: vec![evidence.finish_authority_ref.clone()],
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    })
}

fn finish_envelope(
    identity: &RequestIdentity,
    operation_id: OperationId,
    attempt: &FinishAttempt,
    context: &FinishContext,
    receipts: &[FinishDecisionReceipt],
    expected_finish_revision: u64,
) -> Result<CanonicalWriteEnvelope, FinishAttemptError> {
    let receipt_bytes = canonical_json_bytes(&receipts)
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let receipt_json = String::from_utf8(receipt_bytes.clone())
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let contract_bytes = canonical_json_bytes(&(attempt, context, receipts))
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "attempt_id".to_owned(),
        serde_json::Value::String(attempt.attempt_id.clone()),
    );
    parameters.insert(
        "expected_finish_revision".to_owned(),
        serde_json::Value::String(expected_finish_revision.to_string()),
    );
    parameters.insert(
        "receipt_json".to_owned(),
        serde_json::Value::String(receipt_json),
    );
    let scope_id = ScopeId::new(GOVERNOR_SCOPE_ID)
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    Ok(CanonicalWriteEnvelope {
        operation_id,
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id,
        task_id: Some(context.task_id.clone()),
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: sha256_hex(&contract_bytes),
        operation_manifest_digest: production_manifest_digest()?,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::RecordFinishDecision,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: vec![context.finish_authority_ref.clone()],
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    })
}

fn check_finish_receipt(
    receipt: &WriteReceipt,
    operation_id: &OperationId,
    fence: &StateFence,
    idempotency_key: &str,
) -> Result<(), FinishAttemptError> {
    receipt
        .validate()
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    if receipt.operation_id != *operation_id
        || receipt.state_fence != *fence
        || receipt.idempotency_key != idempotency_key
    {
        return Err(FinishAttemptError::Store(
            "committed receipt does not bind the finish identity".to_owned(),
        ));
    }
    if receipt.transition_class != TransitionClass::RecoverySchema {
        return Err(FinishAttemptError::Store(
            "finish receipt has the wrong transition class".to_owned(),
        ));
    }
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(FinishAttemptError::Store(format!(
            "finish receipt status is {:?}",
            receipt.status
        )));
    }
    Ok(())
}
