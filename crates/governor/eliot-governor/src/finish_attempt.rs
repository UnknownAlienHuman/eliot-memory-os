//! Governor-owned production FinishAttempt path.
//!
//! The adapter owns the boundary between the public candidate draft and the
//! rebuildable [`eliot_finish::FinishService`].  It reads the current task and
//! canonical finish-evidence owner at one fence, evaluates a scratch service,
//! persists the complete receipt projection through the existing canonical
//! transition path, and never treats a worker/provider result as task finish.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_canonical::{CanonicalWriteEnvelope, FinishAttemptDraft};
use eliot_contracts::{canonical_json_bytes, sha256_hex, OperationId, StateFence, TaskId};
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
use eliot_task::{TaskLifecycleOwner, TaskRecord, TaskState};
use thiserror::Error;

use crate::{
    CanonicalAdmissionOwner, CompositionError, GovernorOwners, KernelPortError,
    KernelTransitionPort,
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
            finish: &owners.finish,
            kernel,
            finish_owner_revision,
        }
    }
}

impl<P: KernelTransitionPort + ?Sized> GovernorFinishAttempt<'_, P> {
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
