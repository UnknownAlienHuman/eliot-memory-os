//! Private Governor-owned task lifecycle promotion.
//!
//! The single [`GovernorTaskLifecycle`] addresses one serialized Governor
//! owner triple (`TaskLifecycleOwner` + [`CanonicalAdmissionOwner`] + the retained
//! neutral [`KernelTransitionPort`]). It never creates an independent
//! `TaskLifecycleOwner` per caller: `view` is an authenticated read of the
//! current owner at the admitted fence, and `propose_task` / `apply_task`
//! validate against a scratch clone before committing through the existing
//! canonical path.
//!
//! Each call rechecks identity, fence, epoch, identifier text, the
//! task-revision compare-and-swap base, and the exact legal-transition rule
//! via the domain [`TaskLifecycleOwner::propose`] / [`TaskLifecycleOwner::apply`]
//! on a scratch copy (never publishing authority), then builds the admitted
//! lifecycle transition as one [`NamedMutationRequest`] (`UpdateTaskState` /
//! [`TransitionClass::TaskControl`] / [`ReversibleMutation`]) carrying the
//! production adapter manifest digest (reconstructed from
//! `crates/governor/eliot-governor/src/observation_reconciliation.rs::production_manifest_digest`
//! 195-213; enforced at `apply.rs:663` via `validate_transition`), and
//! commits via [`CanonicalAdmissionOwner::commit`] with the exact admitted
//! identity/binding/idempotency.
//!
//! The typed `UpdateTaskState` parameters bind the admitted
//! [`TaskLifecycleEvent`] and [`TaskRecord`]: `task_id`, `event_id`,
//! predecessor `from` (absent on propose, which has no predecessor),
//! target `to`, the owner-checked compare-and-swap base `expected_revision`
//! as its decimal string (`"1"` on propose, the current task revision on
//! apply), and the admitted `actor_ref`.
//!
//! Only [`WriteReceiptStatus::Committed`] permits publication; `Rejected`,
//! `Cancelled` and `DeadLetter` stay pending as typed [`StoreFailure`].
//! A lost acknowledgement reconciles the same operation receipt through the
//! neutral port (T1.2 exact-receipt pattern), never a second execution.
//! Publication of the mutated owner happens only via `refresh_from_kernel`
//! at the returned receipt revision: the scratch clone is discarded and the
//! owners are rebuilt from the `Task` recovery snapshot, so a stale revision
//! or fence is rejected with no Store mutation. Callers persist the returned
//! event and snapshot through the canonical write path only, per the
//! `eliot-task` crate contract.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{
    OperationId, RequestMetadata, StateFence, TaskId, TaskRevision, canonical_json_bytes,
    sha256_hex,
};
use eliot_store_api::{
    CONTRACT_VERSION, EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, NamedOperationManifest, OperationManifestDigest, OrderingHeadExpectation,
    OrderingScopeId, ScopeId, SecurityContext, StoreFailure,
    StoreFailureDisposition, StoreFailureIdentityContext, StoreMutationDisposition,
    StoreReasonCode, StoreRecoveryAction, StoreRetryDirective, TransitionClass, WriteReceipt,
    WriteReceiptStatus,
};
use eliot_task::{
    TaskCommand, TaskCommandContext, TaskError, TaskLifecycleEvent, TaskLifecycleOwner,
    TaskProposal, TaskRecord, TaskState,
};
use thiserror::Error;

use crate::{CanonicalAdmissionOwner, CompositionError, KernelPortError, KernelTransitionPort};

/// Production adapter manifest name from the Surreal adapter.
const PRODUCTION_MANIFEST_NAME: &str = "eliot.storage.store-surreal-adapter";

/// Governor canonical scope addressed by the task envelope.
const GOVERNOR_SCOPE_ID: &str = "governor";

/// Governor ordering scope carried on the task envelope.
const GOVERNOR_ORDERING_SCOPE: &str = "scope:governor";

/// Fail-closed errors returned by the Governor task lifecycle adapter.
///
/// Owner, composition, and kernel rejections keep their exact typed payload;
/// commit and receipt mismatches surface as typed [`StoreFailure`] without
/// ever reporting a non-executed transition as committed.
#[derive(Debug, Error)]
pub enum TaskLifecycleError {
    /// The task lifecycle owner rejected the transition (duplicate, illegal
    /// transition, revision or fence mismatch, missing evidence, ...).
    #[error("task lifecycle owner rejected the transition: {0}")]
    Owner(#[from] TaskError),
    /// The canonical composition rejected the admitted envelope or commit.
    #[error("canonical composition rejected the task transition: {0}")]
    Composition(#[from] CompositionError),
    /// The neutral Kernel port rejected the transition or reconciliation.
    #[error("kernel port rejected the task transition: {0}")]
    Kernel(#[from] KernelPortError),
    /// The transition was not committed; the payload carries the typed
    /// disposition, retry directive, and recovery action.
    #[error("task transition was not committed (see store failure payload)")]
    Store(StoreFailure),
    /// Canonical bytes, digests, or envelope projection failed fail-closed.
    #[error("task transition serialization: {0}")]
    Serialization(String),
}

impl TaskLifecycleError {
    /// Returns the typed store failure when this error carries one.
    #[must_use]
    pub const fn store_failure(&self) -> Option<&StoreFailure> {
        match self {
            Self::Store(failure) => Some(failure),
            Self::Owner(_) | Self::Composition(_) | Self::Kernel(_) | Self::Serialization(_) => {
                None
            }
        }
    }
}

/// Governor-owned task lifecycle adapter over one serialized owner.
pub struct GovernorTaskLifecycle<'a, P: ?Sized> {
    task: &'a TaskLifecycleOwner,
    canonical: &'a CanonicalAdmissionOwner,
    kernel: &'a P,
}

impl<'a, P: ?Sized> GovernorTaskLifecycle<'a, P> {
    /// Borrows the single Governor owner triple. No per-caller owner is
    /// created; the scratch clones in `propose_task` / `apply_task` never
    /// publish authority.
    pub(crate) fn new(
        task: &'a TaskLifecycleOwner,
        canonical: &'a CanonicalAdmissionOwner,
        kernel: &'a P,
    ) -> Self {
        Self {
            task,
            canonical,
            kernel,
        }
    }
}

/// Reconstructs the production adapter manifest digest.
///
/// The shape mirrors `production_manifest_digest` in
/// `crates/governor/eliot-governor/src/observation_reconciliation.rs:195-213`
/// exactly: the same adapter name, contract version, admitted transition
/// classes, reversible-mutation ceiling and byte/timeout bounds. The digest
/// is deterministic over that shape, so it equals the digest enforced at
/// `apply.rs:663`.
pub(crate) fn production_manifest_digest() -> Result<OperationManifestDigest, TaskLifecycleError> {
    let manifest = NamedOperationManifest::new(
        PRODUCTION_MANIFEST_NAME,
        CONTRACT_VERSION,
        vec![
            TransitionClass::CaptureCandidate,
            TransitionClass::Epistemic,
            TransitionClass::TaskControl,
            TransitionClass::LifecyclePolicy,
            TransitionClass::RecoverySchema,
        ],
        EffectClass::ReversibleMutation,
        1024 * 1024,
        1024 * 1024,
        30_000,
    )
    .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    Ok(manifest.digest)
}

fn store_failure_ctx(
    identity: &eliot_protocol::RequestIdentity,
    operation_id: &eliot_contracts::OperationId,
) -> StoreFailureIdentityContext {
    StoreFailureIdentityContext {
        request_id: Some(identity.request.metadata.request_id.clone()),
        operation_id: Some(operation_id.clone()),
        idempotency_key_ref_or_digest: Some(identity.idempotency_key.clone()),
        state_fence_ref_or_exact_safe_projection: Some(
            identity.request.metadata.state_fence.clone(),
        ),
        evidence_ref: None,
        transport_unavailable: false,
    }
}

fn store_failure(
    disposition: StoreFailureDisposition,
    reason_token: &str,
    mutation: StoreMutationDisposition,
    retry: StoreRetryDirective,
    recovery: StoreRecoveryAction,
    ctx: &StoreFailureIdentityContext,
) -> Result<StoreFailure, TaskLifecycleError> {
    let reason_code = StoreReasonCode::new(reason_token)
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    let failure = StoreFailure {
        contract_revision: eliot_store_api::STORE_FAILURE_CONTRACT_REVISION.to_owned(),
        disposition,
        reason_code,
        request_id: ctx.request_id.clone(),
        operation_id: ctx.operation_id.clone(),
        idempotency_key_ref_or_digest: ctx.idempotency_key_ref_or_digest.clone(),
        state_fence_ref_or_exact_safe_projection: ctx
            .state_fence_ref_or_exact_safe_projection
            .clone(),
        mutation_disposition: mutation,
        retry_directive: retry,
        recovery_action: recovery,
        conflict: None,
        retry_after_ms: None,
        evidence_ref: ctx.evidence_ref.clone(),
        human_detail: None,
    };
    failure
        .validate()
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    Ok(failure)
}

fn map_store_error(
    error: eliot_store_api::StoreError,
    ctx: &StoreFailureIdentityContext,
) -> TaskLifecycleError {
    match StoreFailure::from_store_error(error, ctx.clone()) {
        Ok(failure) => TaskLifecycleError::Store(failure),
        Err(contract) => TaskLifecycleError::Serialization(contract.to_string()),
    }
}

/// Renders one task state in its exact owner wire spelling.
///
/// The spelling derives from the `eliot-task` serde contract
/// (`SCREAMING_SNAKE_CASE`), never from a local literal, so the persisted
/// parameter cannot drift from the admitted event.
fn state_wire(state: TaskState) -> Result<String, TaskLifecycleError> {
    let value =
        serde_json::to_value(state).map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    value.as_str().map(str::to_owned).ok_or_else(|| {
        TaskLifecycleError::Serialization("task state wire form is not a string".to_owned())
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the envelope binds every admitted identity field explicitly; grouping them would hide a binding"
)]
fn task_envelope(
    identity: &eliot_protocol::RequestIdentity,
    operation_id: OperationId,
    event: &TaskLifecycleEvent,
    record: &TaskRecord,
    expected_revision: u64,
    manifest_digest: OperationManifestDigest,
) -> Result<CanonicalWriteEnvelope, TaskLifecycleError> {
    identity
        .validate()
        .map_err(|_| TaskLifecycleError::Owner(TaskError::InvalidField("request_identity")))?;
    let fence = &identity.request.metadata.state_fence;
    if &identity.request.state_fence != fence {
        return Err(TaskLifecycleError::Owner(TaskError::FenceMismatch));
    }
    if event.task_id != record.task_id {
        return Err(TaskLifecycleError::Serialization(
            "task event does not belong to the admitted task record".to_owned(),
        ));
    }
    if record.state_fence != *fence {
        return Err(TaskLifecycleError::Owner(TaskError::FenceMismatch));
    }
    let scope_id =
        ScopeId::new(GOVERNOR_SCOPE_ID).map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    let ordering_scope = OrderingScopeId::new(GOVERNOR_ORDERING_SCOPE)
        .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?;
    let admission_digest = sha256_hex(
        &canonical_json_bytes(event)
            .map_err(|error| TaskLifecycleError::Serialization(error.to_string()))?,
    );
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "task_id".to_owned(),
        serde_json::Value::String(record.task_id.as_str().to_owned()),
    );
    parameters.insert(
        "event_id".to_owned(),
        serde_json::Value::String(event.event_id.clone()),
    );
    if let Some(from) = event.from {
        parameters.insert(
            "from".to_owned(),
            serde_json::Value::String(state_wire(from)?),
        );
    }
    parameters.insert(
        "to".to_owned(),
        serde_json::Value::String(state_wire(event.to)?),
    );
    parameters.insert(
        "expected_revision".to_owned(),
        serde_json::Value::String(expected_revision.to_string()),
    );
    parameters.insert(
        "actor_ref".to_owned(),
        serde_json::Value::String(event.actor_ref.clone()),
    );
    let envelope = CanonicalWriteEnvelope {
        operation_id,
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id,
        task_id: identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(|task| task.as_str().to_owned()),
        transition_class: TransitionClass::TaskControl,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: admission_digest,
        operation_manifest_digest: manifest_digest,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::UpdateTaskState,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: vec![event.actor_ref.clone()],
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: ordering_scope,
            expected_sequence: 1,
            state_fence: fence.clone(),
        }],
    };
    envelope
        .validate()
        .map_err(|_| TaskLifecycleError::Owner(TaskError::InvalidField("task_envelope")))?;
    Ok(envelope)
}

impl<P: KernelTransitionPort + ?Sized> GovernorTaskLifecycle<'_, P> {
    /// Reads the current task record at the admitted fence without promotion.
    pub fn view(
        &self,
        ctx: &RequestMetadata,
        task_id: &TaskId,
    ) -> Result<Option<TaskRecord>, TaskLifecycleError> {
        ctx.validate()
            .map_err(|_| TaskLifecycleError::Owner(TaskError::InvalidField("request_metadata")))?;
        if &ctx.state_fence != self.canonical.state_fence() {
            return Err(TaskLifecycleError::Owner(TaskError::FenceMismatch));
        }
        Ok(self.task.task(task_id).cloned())
    }

    /// Admits one task proposal and commits it through the canonical path.
    ///
    /// The proposal is validated against a scratch clone of the single task
    /// owner (duplicate, epoch, fence, and identifier checks), then committed
    /// as one `UpdateTaskState` / `TaskControl` transition. The scratch clone
    /// is discarded: publication happens only via `refresh_from_kernel` at
    /// the returned receipt revision.
    pub async fn propose_task(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: OperationId,
        proposal: TaskProposal,
    ) -> Result<WriteReceipt, TaskLifecycleError> {
        identity
            .validate()
            .map_err(|_| TaskLifecycleError::Owner(TaskError::InvalidField("request_identity")))?;
        let fence = &identity.request.metadata.state_fence;
        if &identity.request.state_fence != fence {
            return Err(TaskLifecycleError::Owner(TaskError::FenceMismatch));
        }
        if self.canonical.state_fence() != fence {
            return Err(TaskLifecycleError::Owner(TaskError::FenceMismatch));
        }
        if !self
            .canonical
            .state_fence()
            .is_compatible_with(&proposal.context.state_fence)
        {
            return Err(TaskLifecycleError::Owner(TaskError::FenceMismatch));
        }
        let mut scratch = self.task.clone();
        let event = scratch.propose(proposal.clone())?;
        let record = scratch.task(&proposal.task_id).cloned().ok_or_else(|| {
            TaskLifecycleError::Serialization(
                "task record is missing after the admitted proposal".to_owned(),
            )
        })?;
        let manifest_digest = production_manifest_digest()?;
        let envelope = task_envelope(
            identity,
            operation_id.clone(),
            &event,
            &record,
            1,
            manifest_digest.clone(),
        )?;
        self.commit_envelope(identity, operation_id, envelope, manifest_digest)
            .await
    }

    /// Applies one guarded task command and commits it through the canonical path.
    ///
    /// The command is validated against a scratch clone of the single task
    /// owner, including the task-revision compare-and-swap base carried by
    /// the command fence and the exact legal-transition rule. A stale
    /// revision or fence is rejected here with no Store mutation. The scratch
    /// clone is discarded: publication happens only via `refresh_from_kernel`
    /// at the returned receipt revision.
    pub async fn apply_task(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: OperationId,
        task_id: TaskId,
        context: TaskCommandContext,
        command: TaskCommand,
    ) -> Result<WriteReceipt, TaskLifecycleError> {
        identity
            .validate()
            .map_err(|_| TaskLifecycleError::Owner(TaskError::InvalidField("request_identity")))?;
        let fence = &identity.request.metadata.state_fence;
        if &identity.request.state_fence != fence {
            return Err(TaskLifecycleError::Owner(TaskError::FenceMismatch));
        }
        if self.canonical.state_fence() != fence {
            return Err(TaskLifecycleError::Owner(TaskError::FenceMismatch));
        }
        if !self
            .canonical
            .state_fence()
            .is_compatible_with(&context.state_fence)
        {
            return Err(TaskLifecycleError::Owner(TaskError::FenceMismatch));
        }
        let current = self
            .task
            .task(&task_id)
            .ok_or_else(|| TaskLifecycleError::Owner(TaskError::TaskNotFound(task_id.clone())))?;
        let expected_revision = context
            .state_fence
            .task_revision
            .map_or(current.revision, TaskRevision::value);
        let mut scratch = self.task.clone();
        let event = scratch.apply(task_id.clone(), context, command)?;
        let record = scratch.task(&task_id).cloned().ok_or_else(|| {
            TaskLifecycleError::Serialization(
                "task record is missing after the admitted transition".to_owned(),
            )
        })?;
        let manifest_digest = production_manifest_digest()?;
        let envelope = task_envelope(
            identity,
            operation_id.clone(),
            &event,
            &record,
            expected_revision,
            manifest_digest.clone(),
        )?;
        self.commit_envelope(identity, operation_id, envelope, manifest_digest)
            .await
    }

    /// Commits one admitted envelope and validates the returned receipt.
    ///
    /// Only [`WriteReceiptStatus::Committed`] succeeds; every other status
    /// stays pending as a typed [`StoreFailure`]. A lost acknowledgement
    /// reconciles the same operation receipt through the neutral port, never
    /// a second execution.
    async fn commit_envelope(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: OperationId,
        envelope: CanonicalWriteEnvelope,
        manifest_digest: OperationManifestDigest,
    ) -> Result<WriteReceipt, TaskLifecycleError> {
        let fence = identity.request.metadata.state_fence.clone();
        let ctx = store_failure_ctx(identity, &operation_id);
        let receipt = match self.canonical.commit(self.kernel, identity, envelope).await {
            Ok(receipt) => receipt,
            Err(CompositionError::Kernel(KernelPortError::Unknown(_))) => {
                match self.kernel.receipt(operation_id.clone()).await {
                    Ok(Some(receipt)) => receipt,
                    Ok(None) => {
                        let failure = StoreFailure::from_provider_unknown_outcome(&ctx)
                            .map_err(|error| {
                                TaskLifecycleError::Serialization(error.to_string())
                            })?;
                        return Err(TaskLifecycleError::Store(failure));
                    }
                    Err(KernelPortError::Unknown(_)) => {
                        let failure = StoreFailure::from_provider_unknown_outcome(&ctx)
                            .map_err(|error| {
                                TaskLifecycleError::Serialization(error.to_string())
                            })?;
                        return Err(TaskLifecycleError::Store(failure));
                    }
                    Err(other) => return Err(TaskLifecycleError::Kernel(other)),
                }
            }
            Err(other) => return Err(TaskLifecycleError::Composition(other)),
        };
        check_committed_receipt(
            &receipt,
            &operation_id,
            &fence,
            &identity.idempotency_key,
            &manifest_digest,
            &ctx,
        )?;
        Ok(receipt)
    }
}

/// Validates one issued receipt against the admitted task identity.
///
/// The operation identity, fence, idempotency key, transition class, and
/// manifest digest must agree exactly with the admitted transition, and only
/// [`WriteReceiptStatus::Committed`] succeeds; every other status stays
/// pending as a typed [`StoreFailure`], never reported as executed.
fn check_committed_receipt(
    receipt: &WriteReceipt,
    operation_id: &OperationId,
    fence: &StateFence,
    idempotency_key: &str,
    manifest_digest: &OperationManifestDigest,
    ctx: &StoreFailureIdentityContext,
) -> Result<(), TaskLifecycleError> {
        receipt
            .validate()
            .map_err(|error| map_store_error(error, ctx))?;
        if receipt.operation_id != *operation_id
            || receipt.state_fence != *fence
            || receipt.idempotency_key != idempotency_key
        {
            let failure = store_failure(
                StoreFailureDisposition::DeterministicRejection,
                "TASK_RECEIPT_MISMATCH",
                StoreMutationDisposition::NotAttempted,
                StoreRetryDirective::DoNotRetry,
                StoreRecoveryAction::None,
                &ctx,
            )?;
            return Err(TaskLifecycleError::Store(failure));
        }
        if receipt.transition_class != TransitionClass::TaskControl
            || receipt.operation_manifest_digest != manifest_digest
        {
            let failure = store_failure(
                StoreFailureDisposition::DeterministicRejection,
                "TASK_TRANSITION_MISMATCH",
                StoreMutationDisposition::NotAttempted,
                StoreRetryDirective::DoNotRetry,
                StoreRecoveryAction::None,
                &ctx,
            )?;
            return Err(TaskLifecycleError::Store(failure));
        }
        if receipt.status != WriteReceiptStatus::Committed {
            let (reason, disposition, retry, recovery) = match receipt.status {
                WriteReceiptStatus::Committed => {
                    let failure = store_failure(
                        StoreFailureDisposition::InternalDefect,
                        "TASK_INTERNAL",
                        StoreMutationDisposition::NotAttempted,
                        StoreRetryDirective::ManualRecovery,
                        StoreRecoveryAction::EscalateInternalDefect,
                        &ctx,
                    )?;
                    return Err(TaskLifecycleError::Store(failure));
                }
                WriteReceiptStatus::Rejected => (
                    "TASK_NOT_COMMITTED_REJECTED",
                    StoreFailureDisposition::DeterministicRejection,
                    StoreRetryDirective::DoNotRetry,
                    StoreRecoveryAction::None,
                ),
                WriteReceiptStatus::Cancelled => (
                    "TASK_NOT_COMMITTED_CANCELLED",
                    StoreFailureDisposition::DeterministicRejection,
                    StoreRetryDirective::DoNotRetry,
                    StoreRecoveryAction::None,
                ),
                WriteReceiptStatus::DeadLetter => (
                    "TASK_NOT_COMMITTED_DEAD_LETTER",
                    StoreFailureDisposition::InternalDefect,
                    StoreRetryDirective::ManualRecovery,
                    StoreRecoveryAction::EscalateInternalDefect,
                ),
            };
            let failure = store_failure(
                disposition,
                reason,
                StoreMutationDisposition::NotAttempted,
                retry,
                recovery,
                &ctx,
            )?;
            return Err(TaskLifecycleError::Store(failure));
        }
        Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration,
        SessionId, SourceId, StateFence, TaskRevision,
    };
    use eliot_protocol::RequestIdentity;
    use eliot_receipts::RequestBinding;
    use eliot_store_api::{
        CommitId, OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation, ScopeId,
        ScopeRevisionView, StoreHealth, validate_store_receipt_envelope,
    };

    use crate::{CanonicalAdmissionSnapshot, KernelPortFuture};

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    /// Test Kernel port that records every committed transition so the proof
    /// can assert the exact admitted `UpdateTaskState` command and parameters.
    struct TestKernel {
        committed: Mutex<BTreeMap<OperationId, (RequestIdentity, WriteReceipt)>>,
        transitions: Mutex<Vec<PreparedTransition>>,
        apply_calls: Mutex<u64>,
    }

    impl TestKernel {
        fn new() -> Self {
            Self {
                committed: Mutex::new(BTreeMap::new()),
                transitions: Mutex::new(Vec::new()),
                apply_calls: Mutex::new(0),
            }
        }

        fn apply_count(&self) -> u64 {
            *self.apply_calls.lock().expect("apply lock")
        }

        fn last_transition(&self) -> PreparedTransition {
            self.transitions
                .lock()
                .expect("transition lock")
                .last()
                .expect("one committed transition")
                .clone()
        }
    }

    impl KernelTransitionPort for TestKernel {
        fn apply_prepared<'a>(
            &'a self,
            identity: &RequestIdentity,
            transition: PreparedTransition,
            expected_revision_heads: Vec<RevisionHeadExpectation>,
            expected_ordering_heads: Vec<OrderingHeadExpectation>,
        ) -> KernelPortFuture<'a, WriteReceipt> {
            let identity = identity.clone();
            Box::pin(async move {
                identity
                    .validate()
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                transition
                    .validate()
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                if identity.request.metadata.state_fence != transition.state_fence {
                    return Err(KernelPortError::Contract(
                        "test gateway: identity fence does not match transition".to_owned(),
                    ));
                }
                if identity.idempotency_key != transition.identity.idempotency_key {
                    return Err(KernelPortError::Contract(
                        "test gateway: idempotency does not match transition".to_owned(),
                    ));
                }
                for head in &expected_revision_heads {
                    head.validate()
                        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                    if head.state_fence != transition.state_fence {
                        return Err(KernelPortError::Contract(
                            "test gateway: revision head fence mismatch".to_owned(),
                        ));
                    }
                }
                for head in &expected_ordering_heads {
                    head.validate()
                        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                    if head.state_fence != transition.state_fence {
                        return Err(KernelPortError::Contract(
                            "test gateway: ordering head fence mismatch".to_owned(),
                        ));
                    }
                }
                let mut committed = self.committed.lock().expect("committed lock");
                if let Some((_, receipt)) = committed.get(&transition.identity.operation_id) {
                    if receipt.idempotency_key == transition.identity.idempotency_key
                        && receipt.canonical_request_hash
                            == transition.identity.canonical_request_hash
                    {
                        return Ok(receipt.clone());
                    }
                    return Err(KernelPortError::Contract(
                        "test gateway: committed operation identity conflict".to_owned(),
                    ));
                }
                let sequence = u64::try_from(committed.len())
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?
                    + 1;
                let operation_id = transition.identity.operation_id.clone();
                let candidate = WriteReceipt {
                    operation_id: operation_id.clone(),
                    idempotency_key: transition.identity.idempotency_key.clone(),
                    canonical_request_hash: transition.identity.canonical_request_hash.clone(),
                    transition_class: transition.transition_class,
                    status: WriteReceiptStatus::Committed,
                    commit_id: Some(
                        CommitId::new(format!("commit-{operation_id}"))
                            .map_err(|error| KernelPortError::Contract(error.to_string()))?,
                    ),
                    state_fence: transition.state_fence.clone(),
                    ordering_sequences: Vec::new(),
                    revision_before_after: Vec::new(),
                    applied_command_ids: vec!["cmd-1".to_owned()],
                    emitted_event_ids: Vec::new(),
                    projection_refs: Vec::new(),
                    outbox_refs: Vec::new(),
                    operation_manifest_digest: transition.operation_manifest_digest.clone(),
                    error_code: None,
                    resubmission: eliot_store_api::Resubmission::None,
                    committed_at: Some(format!("commit-sequence-{sequence:016}")),
                    envelope: None,
                };
                candidate
                    .validate()
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                let envelope = eliot_store_api::issue_store_receipt_envelope(
                    &identity.request.metadata,
                    &transition,
                    &candidate,
                    sequence,
                )
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                let mut receipt = candidate;
                receipt.envelope = Some(envelope);
                validate_store_receipt_envelope(&identity.request.metadata, &transition, &receipt)
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                *self.apply_calls.lock().expect("apply lock") += 1;
                self.transitions
                    .lock()
                    .expect("transition lock")
                    .push(transition);
                committed.insert(operation_id, (identity, receipt.clone()));
                Ok(receipt)
            })
        }

        fn receipt(&self, operation_id: OperationId) -> KernelPortFuture<'_, Option<WriteReceipt>> {
            Box::pin(async move {
                Ok(self
                    .committed
                    .lock()
                    .expect("committed lock")
                    .get(&operation_id)
                    .map(|(_, receipt)| receipt.clone()))
            })
        }

        fn health(&self) -> KernelPortFuture<'_, StoreHealth> {
            Box::pin(async move { Err(KernelPortError::NotAdmitted("test port".to_owned())) })
        }
    }

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        struct NoopWaker;
        impl std::task::Wake for NoopWaker {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let waker = std::task::Waker::from(std::sync::Arc::new(NoopWaker));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn fence() -> StateFence {
        StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn proposal(task: &str, request: &str, event: &str, fence: &StateFence) -> TaskProposal {
        TaskProposal {
            task_id: TaskId::new(task).expect("task id"),
            project_ref: "project-1".to_owned(),
            goal: "prove the task lifecycle".to_owned(),
            context: TaskCommandContext {
                request_id: request.to_owned(),
                event_id: event.to_owned(),
                actor_ref: "actor-1".to_owned(),
                state_fence: fence.clone(),
                authority_epoch: fence.authority_epoch.clone(),
                observed_at: ClockReading::default(),
            },
        }
    }

    fn command_context(request: &str, event: &str, fence: &StateFence) -> TaskCommandContext {
        TaskCommandContext {
            request_id: request.to_owned(),
            event_id: event.to_owned(),
            actor_ref: "actor-1".to_owned(),
            state_fence: fence.clone(),
            authority_epoch: fence.authority_epoch.clone(),
            observed_at: ClockReading::default(),
        }
    }

    fn identity(fence: &StateFence, request: &str, idempotency: &str) -> RequestIdentity {
        let metadata = RequestMetadata {
            request_id: RequestId::new(request).expect("request id"),
            session_id: Some(SessionId::new("session-task-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("test-product").expect("product"),
            source_id: SourceId::new("agent-bridge").expect("source"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        };
        RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence.clone(),
            },
            idempotency_key: idempotency.to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-task-1".to_owned(),
        }
    }

    fn canonical_owner(fence: &StateFence) -> CanonicalAdmissionOwner {
        let scope = ScopeRevisionView {
            scope_id: ScopeId::new("governor").expect("scope"),
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            state_fence: fence.clone(),
        };
        let snapshot = CanonicalAdmissionSnapshot::new(fence.clone(), 1, None).expect("snapshot");
        CanonicalAdmissionOwner::new(fence.clone(), scope, snapshot).expect("canonical owner")
    }

    fn task_owner(fence: &StateFence) -> TaskLifecycleOwner {
        TaskLifecycleOwner::new(fence.authority_epoch.clone(), fence.clone()).expect("task owner")
    }

    fn param(transition: &PreparedTransition, name: &str) -> Option<String> {
        transition.named_operations.first().and_then(|command| {
            command
                .parameters
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
    }

    #[test]
    fn admitted_propose_then_apply_commit_and_recovery_shows_persisted_state() {
        let fence = fence();
        let task = task_owner(&fence);
        let canonical = canonical_owner(&fence);
        let kernel = TestKernel::new();
        let owner = GovernorTaskLifecycle::new(&task, &canonical, &kernel);

        // Propose commits one TaskControl transition with the task-control
        // parameters bound to the admitted propose event.
        let propose_id =
            eliot_contracts::OperationId::new("op-task-propose").expect("operation id");
        let receipt = block_on(owner.propose_task(
            &identity(&fence, "req-task-propose", "idem-task-propose"),
            propose_id.clone(),
            proposal("task-1", "task-request-1", "task-event-1", &fence),
        ))
        .expect("admitted proposal");
        assert_eq!(receipt.operation_id, propose_id);
        assert_eq!(receipt.status, WriteReceiptStatus::Committed);
        assert_eq!(receipt.transition_class, TransitionClass::TaskControl);
        assert_eq!(kernel.apply_count(), 1);
        let committed = kernel.last_transition();
        assert_eq!(committed.transition_class, TransitionClass::TaskControl);
        assert_eq!(
            committed.named_operations.first().expect("one command").operation,
            NamedMutationOperation::UpdateTaskState
        );
        assert_eq!(param(&committed, "task_id").as_deref(), Some("task-1"));
        assert_eq!(
            param(&committed, "event_id").as_deref(),
            Some("task-event-1")
        );
        assert_eq!(param(&committed, "from"), None);
        assert_eq!(param(&committed, "to").as_deref(), Some("PROPOSED"));
        assert_eq!(
            param(&committed, "expected_revision").as_deref(),
            Some("1")
        );
        assert_eq!(
            param(&committed, "actor_ref").as_deref(),
            Some("actor-1")
        );

        // The adapter never publishes authority itself: emulate the daemon
        // refresh by replaying the admitted proposal into a fresh owner and
        // rebuilding from its snapshot, mirroring restart recovery.
        let mut refreshed = task_owner(&fence);
        refreshed
            .propose(proposal("task-1", "task-request-1", "task-event-1", &fence))
            .expect("replayed proposal");
        let snapshot = refreshed.snapshot();
        let recovered = TaskLifecycleOwner::from_snapshot(
            fence.authority_epoch.clone(),
            fence.clone(),
            snapshot,
        )
        .expect("recovery rebuild");
        let record = recovered
            .task(&TaskId::new("task-1").expect("task id"))
            .expect("persisted task");
        assert_eq!(record.state, TaskState::Proposed);
        assert_eq!(record.revision, 1);

        // Apply the next legal command through a fresh adapter over the
        // refreshed owner; the committed parameters carry the predecessor
        // state and the compare-and-swap base revision.
        let refreshed_adapter = GovernorTaskLifecycle::new(&recovered, &canonical, &kernel);
        let apply_id = eliot_contracts::OperationId::new("op-task-open").expect("operation id");
        let applied = block_on(refreshed_adapter.apply_task(
            &identity(&fence, "req-task-open", "idem-task-open"),
            apply_id.clone(),
            TaskId::new("task-1").expect("task id"),
            command_context("task-request-2", "task-event-2", &fence),
            TaskCommand::Open,
        ))
        .expect("admitted transition");
        assert_eq!(applied.operation_id, apply_id);
        assert_eq!(applied.status, WriteReceiptStatus::Committed);
        assert_eq!(kernel.apply_count(), 2);
        let committed = kernel.last_transition();
        assert_eq!(param(&committed, "from").as_deref(), Some("PROPOSED"));
        assert_eq!(param(&committed, "to").as_deref(), Some("OPEN"));
        assert_eq!(
            param(&committed, "expected_revision").as_deref(),
            Some("1")
        );

        // A second refresh rebuilds the moved state: recovery shows OPEN at
        // revision 2 with no second execution of either operation.
        refreshed
            .apply(
                TaskId::new("task-1").expect("task id"),
                command_context("task-request-2", "task-event-2", &fence),
                TaskCommand::Open,
            )
            .expect("replayed transition");
        let recovered = TaskLifecycleOwner::from_snapshot(
            fence.authority_epoch.clone(),
            fence.clone(),
            refreshed.snapshot(),
        )
        .expect("second recovery rebuild");
        let record = recovered
            .task(&TaskId::new("task-1").expect("task id"))
            .expect("moved task");
        assert_eq!(record.state, TaskState::Open);
        assert_eq!(record.revision, 2);
        assert_eq!(kernel.apply_count(), 2);
    }

    #[test]
    fn stale_revision_is_rejected_with_no_store_mutation() {
        let fence = fence();
        let canonical = canonical_owner(&fence);
        let kernel = TestKernel::new();

        // Admit the proposal, then emulate the daemon refresh so the apply
        // validates against the persisted revision 1.
        let task = task_owner(&fence);
        let owner = GovernorTaskLifecycle::new(&task, &canonical, &kernel);
        block_on(owner.propose_task(
            &identity(&fence, "req-task-propose", "idem-task-propose"),
            eliot_contracts::OperationId::new("op-task-propose").expect("operation id"),
            proposal("task-1", "task-request-1", "task-event-1", &fence),
        ))
        .expect("admitted proposal");
        assert_eq!(kernel.apply_count(), 1);
        let mut refreshed = task_owner(&fence);
        refreshed
            .propose(proposal("task-1", "task-request-1", "task-event-1", &fence))
            .expect("replayed proposal");
        let refreshed_adapter = GovernorTaskLifecycle::new(&refreshed, &canonical, &kernel);

        // A command fenced at a stale compare-and-swap base fails closed in
        // the owner before any Store mutation.
        let mut stale_fence = fence.clone();
        stale_fence.task_revision = Some(TaskRevision::new(999).expect("stale revision"));
        let rejected = block_on(refreshed_adapter.apply_task(
            &identity(&fence, "req-task-stale", "idem-task-stale"),
            eliot_contracts::OperationId::new("op-task-stale").expect("operation id"),
            TaskId::new("task-1").expect("task id"),
            command_context("task-request-stale", "task-event-stale", &stale_fence),
            TaskCommand::Open,
        ));
        assert!(
            matches!(
                rejected,
                Err(TaskLifecycleError::Owner(TaskError::RevisionMismatch {
                    expected: 999,
                    current: 1
                }))
            ),
            "stale revision was not rejected without mutation: {rejected:?}"
        );
        assert_eq!(kernel.apply_count(), 1);
        assert_eq!(kernel.committed.lock().expect("lock").len(), 1);
    }
}
