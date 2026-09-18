//! Private Governor-owned Skill lifecycle promotion.
//!
//! The single [`GovernorSkillLifecycle`] addresses one serialized Governor
//! owner triple (`SkillRegistry` + [`CanonicalAdmissionOwner`] + the retained
//! neutral [`KernelTransitionPort`]). It never creates an independent
//! `SkillRegistry` per caller: `view` and `propose` are authenticated reads of
//! the current owner at the admitted fence, and `promote` validates against a
//! scratch clone before committing through the existing canonical path.
//!
//! Promotion rechecks base digest/revision, exact evidence, fence, approval
//! and reversibility via the domain [`SkillRegistry::promote`] on a scratch
//! copy (never publishing authority), then builds the admitted lifecycle
//! transition as one [`NamedMutationRequest`] (`ApplyLifecyclePolicy` /
//! [`TransitionClass::LifecyclePolicy`] / [`ReversibleMutation`]) carrying the
//! production adapter manifest digest (reconstructed from
//! `crates/storage/eliot-store-surreal-adapter/src/lib.rs::default_manifest`
//! 314-335; enforced at `apply.rs:613` via `validate_against_manifest`), and
//! commits via [`CanonicalAdmissionOwner::commit`] with the exact admitted
//! identity/binding/idempotency.
//!
//! Only [`WriteReceiptStatus::Committed`] permits publication; `Rejected`,
//! `Cancelled` and `DeadLetter` stay pending as typed [`StoreFailure`].
//! A lost acknowledgement reconciles the same operation receipt through the
//! neutral port (T1.2 exact-receipt pattern), never a second execution.
//! [`SkillPromotionReceipt`] remains a domain payload/projection validated
//! locally, never a second receipt ledger.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_skill::{
    PromotionGate, SkillCandidate, SkillError, SkillLifecycleApi, SkillLifecycleView, SkillRegistry,
};
use eliot_store_api::{
    CONTRACT_VERSION, EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, NamedOperationManifest, OperationManifestDigest, OrderingHeadExpectation,
    OrderingScopeId, STORE_FAILURE_CONTRACT_REVISION, ScopeId, SecurityContext, StoreFailure,
    StoreEvidenceHandles, StoreFailureDisposition, StoreFailureIdentityContext, StoreMutationDisposition,
    StoreReasonCode, StoreRecoveryAction, StoreRetryDirective, TransitionClass, WriteReceiptStatus,
};

use crate::{CanonicalAdmissionOwner, CompositionError, KernelPortError, KernelTransitionPort};

/// Production adapter manifest name from the Surreal adapter.
const PRODUCTION_MANIFEST_NAME: &str = "eliot.storage.store-surreal-adapter";

/// Governor-owned Skill lifecycle adapter over one serialized owner.
pub struct GovernorSkillLifecycle<'a, P: ?Sized> {
    skill: &'a SkillRegistry,
    canonical: &'a CanonicalAdmissionOwner,
    kernel: &'a P,
}

impl<'a, P: ?Sized> GovernorSkillLifecycle<'a, P> {
    /// Borrows the single Governor owner triple. No per-caller registry is
    /// created; the scratch clone in `promote` never publishes authority.
    pub(crate) fn new(
        skill: &'a SkillRegistry,
        canonical: &'a CanonicalAdmissionOwner,
        kernel: &'a P,
    ) -> Self {
        Self {
            skill,
            canonical,
            kernel,
        }
    }
}

/// Reconstructs the production adapter manifest digest.
///
/// The shape mirrors `default_manifest` 314-335 exactly: the same adapter
/// name, contract version, admitted transition classes, reversible-mutation
/// ceiling and byte/timeout bounds. The digest is deterministic over that
/// shape, so it equals the digest enforced at `apply.rs:613`.
pub(crate) fn production_manifest_digest() -> Result<OperationManifestDigest, SkillError> {
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
    .map_err(|error| SkillError::Serialization(error.to_string()))?;
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
) -> Result<StoreFailure, SkillError> {
    let reason_code = StoreReasonCode::new(reason_token)
        .map_err(|error| SkillError::Serialization(error.to_string()))?;
    let failure = StoreFailure {
        contract_revision: STORE_FAILURE_CONTRACT_REVISION.to_owned(),
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
        retry_after_dependency_revision: None,
        evidence_ref: ctx.evidence_ref.clone(),
        evidence_handles: StoreEvidenceHandles::default(),
        human_detail: None,
    };
    failure
        .validate()
        .map_err(|error| SkillError::Serialization(error.to_string()))?;
    Ok(failure)
}

fn map_store_error(
    error: eliot_store_api::StoreError,
    ctx: &StoreFailureIdentityContext,
) -> SkillError {
    match StoreFailure::from_store_error(error, ctx.clone()) {
        Ok(failure) => SkillError::Store(failure),
        Err(contract) => SkillError::Serialization(contract.to_string()),
    }
}

fn map_kernel_error(error: KernelPortError, ctx: &StoreFailureIdentityContext) -> SkillError {
    match error {
        KernelPortError::Unknown(_) => match StoreFailure::from_provider_unknown_outcome(ctx) {
            Ok(failure) => SkillError::Store(failure),
            Err(_) => SkillError::IdentityMismatch,
        },
        KernelPortError::Contract(_) => store_failure(
            StoreFailureDisposition::DeterministicRejection,
            "CONTRACT_REJECTED",
            StoreMutationDisposition::NotAttempted,
            StoreRetryDirective::DoNotRetry,
            StoreRecoveryAction::None,
            ctx,
        )
        .map(SkillError::Store)
        .unwrap_or(SkillError::IdentityMismatch),
        KernelPortError::NotAdmitted(_) => store_failure(
            StoreFailureDisposition::Denied,
            "KERNEL_NOT_ADMITTED",
            StoreMutationDisposition::NotAttempted,
            StoreRetryDirective::DoNotRetry,
            StoreRecoveryAction::RestoreStoreConnectivity,
            ctx,
        )
        .map(SkillError::Store)
        .unwrap_or(SkillError::IdentityMismatch),
    }
}

fn map_composition_error(error: CompositionError, ctx: &StoreFailureIdentityContext) -> SkillError {
    match error {
        CompositionError::Kernel(inner) => map_kernel_error(inner, ctx),
        CompositionError::Canonical(_) => store_failure(
            StoreFailureDisposition::DeterministicRejection,
            "CANONICAL_REJECTED",
            StoreMutationDisposition::NotAttempted,
            StoreRetryDirective::DoNotRetry,
            StoreRecoveryAction::None,
            ctx,
        )
        .map(SkillError::Store)
        .unwrap_or(SkillError::IdentityMismatch),
        CompositionError::Provider(_) => store_failure(
            StoreFailureDisposition::DeterministicRejection,
            "PROVIDER_MISMATCH",
            StoreMutationDisposition::NotAttempted,
            StoreRetryDirective::DoNotRetry,
            StoreRecoveryAction::None,
            ctx,
        )
        .map(SkillError::Store)
        .unwrap_or(SkillError::IdentityMismatch),
        CompositionError::Recovery(_) => store_failure(
            StoreFailureDisposition::Conflict,
            "RECOVERY_MISMATCH",
            StoreMutationDisposition::NotAttempted,
            StoreRetryDirective::NewIdentityAfterCondition,
            StoreRecoveryAction::RefreshStateFence,
            ctx,
        )
        .map(SkillError::Store)
        .unwrap_or(SkillError::IdentityMismatch),
        CompositionError::NotReady => store_failure(
            StoreFailureDisposition::Unavailable,
            "GOVERNOR_NOT_READY",
            StoreMutationDisposition::NotAttempted,
            StoreRetryDirective::RetrySameIdentityAfterBackoff,
            StoreRecoveryAction::RestoreStoreConnectivity,
            ctx,
        )
        .map(SkillError::Store)
        .unwrap_or(SkillError::IdentityMismatch),
        CompositionError::Owner(_) => store_failure(
            StoreFailureDisposition::DeterministicRejection,
            "OWNER_REJECTED",
            StoreMutationDisposition::NotAttempted,
            StoreRetryDirective::DoNotRetry,
            StoreRecoveryAction::None,
            ctx,
        )
        .map(SkillError::Store)
        .unwrap_or(SkillError::IdentityMismatch),
        CompositionError::Authority(_) => store_failure(
            StoreFailureDisposition::Denied,
            "AUTHORITY_REJECTED",
            StoreMutationDisposition::NotAttempted,
            StoreRetryDirective::DoNotRetry,
            StoreRecoveryAction::None,
            ctx,
        )
        .map(SkillError::Store)
        .unwrap_or(SkillError::IdentityMismatch),
        CompositionError::StartupOrder { .. } => store_failure(
            StoreFailureDisposition::DeterministicRejection,
            "STARTUP_ORDER",
            StoreMutationDisposition::NotAttempted,
            StoreRetryDirective::DoNotRetry,
            StoreRecoveryAction::None,
            ctx,
        )
        .map(SkillError::Store)
        .unwrap_or(SkillError::IdentityMismatch),
    }
}

fn action_str(action: eliot_skill::LifecycleAction) -> &'static str {
    match action {
        eliot_skill::LifecycleAction::Keep => "keep",
        eliot_skill::LifecycleAction::Patch => "patch",
        eliot_skill::LifecycleAction::Split => "split",
        eliot_skill::LifecycleAction::Merge => "merge",
        eliot_skill::LifecycleAction::Suppress => "suppress",
        eliot_skill::LifecycleAction::Archive => "archive",
        eliot_skill::LifecycleAction::Quarantine => "quarantine",
        eliot_skill::LifecycleAction::Restore => "restore",
    }
}

fn skill_envelope(
    identity: &eliot_protocol::RequestIdentity,
    operation_id: eliot_contracts::OperationId,
    candidate: &SkillCandidate,
    gate: &PromotionGate,
    manifest_digest: OperationManifestDigest,
) -> Result<CanonicalWriteEnvelope, SkillError> {
    identity
        .validate()
        .map_err(|_| SkillError::IdentityMismatch)?;
    let fence = &identity.request.metadata.state_fence;
    if &identity.request.state_fence != fence {
        return Err(SkillError::FenceMismatch);
    }
    if &candidate.state_fence != fence || &gate.state_fence != fence {
        return Err(SkillError::FenceMismatch);
    }
    let scope_id =
        ScopeId::new("governor").map_err(|error| SkillError::Serialization(error.to_string()))?;
    let ordering_scope = OrderingScopeId::new("scope:governor")
        .map_err(|error| SkillError::Serialization(error.to_string()))?;
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "action".to_owned(),
        serde_json::Value::String(action_str(candidate.proposed_action).to_owned()),
    );
    parameters.insert(
        "base_view_digest".to_owned(),
        serde_json::Value::String(candidate.base_view_digest.clone()),
    );
    parameters.insert(
        "candidate_digest".to_owned(),
        serde_json::Value::String(candidate.candidate_digest.clone()),
    );
    parameters.insert(
        "candidate_package_digest".to_owned(),
        serde_json::Value::String(candidate.candidate_package_digest.clone()),
    );
    parameters.insert(
        "skill_id".to_owned(),
        serde_json::Value::String(candidate.base_skill_ref.skill_id().to_owned()),
    );
    parameters.insert(
        "verifier_ref".to_owned(),
        serde_json::Value::String(gate.verifier_ref.clone()),
    );
    let mut proof_refs = BTreeSet::new();
    proof_refs.insert(gate.verifier_ref.clone());
    if let Some(approval) = &gate.human_approval_ref {
        proof_refs.insert(approval.clone());
    }
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
        transition_class: TransitionClass::LifecyclePolicy,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: candidate.candidate_digest.clone(),
        operation_manifest_digest: manifest_digest,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::ApplyLifecyclePolicy,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: proof_refs.into_iter().collect(),
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: ordering_scope,
            expected_sequence: 1,
            state_fence: fence.clone(),
        }],
    };
    envelope
        .validate()
        .map_err(|_| SkillError::IdentityMismatch)?;
    Ok(envelope)
}

impl<P: KernelTransitionPort + ?Sized> SkillLifecycleApi for GovernorSkillLifecycle<'_, P> {
    async fn view(
        &self,
        ctx: &eliot_contracts::RequestMetadata,
        skill_id: String,
    ) -> Result<Option<SkillLifecycleView>, SkillError> {
        ctx.validate().map_err(|_| SkillError::IdentityMismatch)?;
        if &ctx.state_fence != self.canonical.state_fence() {
            return Err(SkillError::FenceMismatch);
        }
        if skill_id.trim().is_empty() || skill_id.chars().any(char::is_control) {
            return Err(SkillError::InvalidField {
                field: "skill_id",
                reason: "must be non-blank and contain no control characters",
            });
        }
        Ok(self.skill.view(&skill_id).cloned())
    }

    async fn propose(
        &self,
        ctx: &eliot_contracts::RequestMetadata,
        skill_id: String,
        candidate_package_digest: String,
        action: eliot_skill::LifecycleAction,
        evidence_refs: Vec<String>,
        dependencies: Vec<eliot_skill::DependencyVersion>,
        scope: eliot_skill::SkillScope,
    ) -> Result<SkillCandidate, SkillError> {
        ctx.validate().map_err(|_| SkillError::IdentityMismatch)?;
        if &ctx.state_fence != self.canonical.state_fence() {
            return Err(SkillError::FenceMismatch);
        }
        self.skill.propose(
            &skill_id,
            candidate_package_digest,
            action,
            evidence_refs,
            dependencies,
            scope,
            ctx.state_fence.clone(),
        )
    }

    async fn promote(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: eliot_contracts::OperationId,
        candidate: SkillCandidate,
        gate: PromotionGate,
        promoted_view: SkillLifecycleView,
    ) -> Result<eliot_store_api::WriteReceipt, SkillError> {
        identity
            .validate()
            .map_err(|_| SkillError::IdentityMismatch)?;
        let fence = &identity.request.metadata.state_fence;
        if &identity.request.state_fence != fence {
            return Err(SkillError::FenceMismatch);
        }
        if &candidate.state_fence != fence
            || &gate.state_fence != fence
            || &promoted_view.state_fence != fence
        {
            return Err(SkillError::FenceMismatch);
        }
        if self.canonical.state_fence() != fence {
            return Err(SkillError::FenceMismatch);
        }
        candidate.validate()?;
        gate.validate_for(&candidate)?;
        promoted_view.validate()?;
        let mut scratch = self.skill.clone();
        let domain_receipt = scratch.promote(&candidate, &gate, promoted_view.clone())?;
        domain_receipt.validate()?;
        let manifest_digest = production_manifest_digest()?;
        let envelope = skill_envelope(
            identity,
            operation_id.clone(),
            &candidate,
            &gate,
            manifest_digest.clone(),
        )?;
        let ctx = store_failure_ctx(identity, &operation_id);
        let receipt = match self.canonical.commit(self.kernel, identity, envelope).await {
            Ok(receipt) => receipt,
            Err(CompositionError::Kernel(KernelPortError::Unknown(_))) => {
                match self.kernel.receipt(operation_id.clone()).await {
                    Ok(Some(receipt)) => receipt,
                    Ok(None) => {
                        let failure = StoreFailure::from_provider_unknown_outcome(&ctx)
                            .map_err(|_| SkillError::IdentityMismatch)?;
                        return Err(SkillError::Store(failure));
                    }
                    Err(KernelPortError::Unknown(_)) => {
                        let failure = StoreFailure::from_provider_unknown_outcome(&ctx)
                            .map_err(|_| SkillError::IdentityMismatch)?;
                        return Err(SkillError::Store(failure));
                    }
                    Err(other) => return Err(map_kernel_error(other, &ctx)),
                }
            }
            Err(other) => return Err(map_composition_error(other, &ctx)),
        };
        receipt
            .validate()
            .map_err(|error| map_store_error(error, &ctx))?;
        if receipt.operation_id != operation_id
            || receipt.state_fence != *fence
            || receipt.idempotency_key != identity.idempotency_key
        {
            let failure = store_failure(
                StoreFailureDisposition::DeterministicRejection,
                "SKILL_RECEIPT_MISMATCH",
                StoreMutationDisposition::NotApplicable,
                StoreRetryDirective::DoNotRetry,
                StoreRecoveryAction::None,
                &ctx,
            )?;
            return Err(SkillError::Store(failure));
        }
        if receipt.transition_class != TransitionClass::LifecyclePolicy
            || receipt.operation_manifest_digest != manifest_digest
        {
            let failure = store_failure(
                StoreFailureDisposition::DeterministicRejection,
                "SKILL_TRANSITION_MISMATCH",
                StoreMutationDisposition::NotApplicable,
                StoreRetryDirective::DoNotRetry,
                StoreRecoveryAction::None,
                &ctx,
            )?;
            return Err(SkillError::Store(failure));
        }
        if receipt.status != WriteReceiptStatus::Committed {
            let (reason, disposition, mutation, retry, recovery) = match receipt.status {
                WriteReceiptStatus::Committed => {
                    let failure = store_failure(
                        StoreFailureDisposition::InternalDefect,
                        "SKILL_INTERNAL",
                        StoreMutationDisposition::NotAttempted,
                        StoreRetryDirective::ManualRecovery,
                        StoreRecoveryAction::EscalateInternalDefect,
                        &ctx,
                    )?;
                    return Err(SkillError::Store(failure));
                }
                // Definitive refusals: the store refused to commit, so no
                // mutation could ever apply through these outcomes.
                WriteReceiptStatus::Rejected => (
                    "SKILL_NOT_COMMITTED_REJECTED",
                    StoreFailureDisposition::DeterministicRejection,
                    StoreMutationDisposition::NotApplicable,
                    StoreRetryDirective::DoNotRetry,
                    StoreRecoveryAction::None,
                ),
                WriteReceiptStatus::Cancelled => (
                    "SKILL_NOT_COMMITTED_CANCELLED",
                    StoreFailureDisposition::DeterministicRejection,
                    StoreMutationDisposition::NotApplicable,
                    StoreRetryDirective::DoNotRetry,
                    StoreRecoveryAction::None,
                ),
                // Abnormal terminal state with an unclear effect: stay
                // fail-closed and claim no attempted mutation.
                WriteReceiptStatus::DeadLetter => (
                    "SKILL_NOT_COMMITTED_DEAD_LETTER",
                    StoreFailureDisposition::InternalDefect,
                    StoreMutationDisposition::NotAttempted,
                    StoreRetryDirective::ManualRecovery,
                    StoreRecoveryAction::EscalateInternalDefect,
                ),
            };
            let failure = store_failure(disposition, reason, mutation, retry, recovery, &ctx)?;
            return Err(SkillError::Store(failure));
        }
        Ok(receipt)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SessionId, SourceId, StateFence,
    };
    use eliot_protocol::RequestIdentity;
    use eliot_receipts::RequestBinding;
    use eliot_skill::{
        LifecycleAction, LifecycleCounters, PromotionGate, SkillCandidate, SkillInteractionView,
        SkillLifecycleView, SkillRef, SkillRegistry, SkillScope, SkillStatus,
    };
    use eliot_store_api::{
        CommitId, OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation, ScopeId,
        ScopeRevisionView, StoreHealth, TransitionClass, WriteReceipt, WriteReceiptStatus,
        validate_store_receipt_envelope,
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

    struct TestKernel {
        committed: Mutex<BTreeMap<OperationId, (RequestIdentity, WriteReceipt)>>,
        apply_calls: Mutex<u64>,
    }

    impl TestKernel {
        fn new() -> Self {
            Self {
                committed: Mutex::new(BTreeMap::new()),
                apply_calls: Mutex::new(0),
            }
        }

        fn apply_count(&self) -> u64 {
            *self.apply_calls.lock().expect("apply lock")
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

    fn skill_ref(package: &str) -> SkillRef {
        SkillRef::new("skill-demo", "rev-1", "Demo Skill", package.to_owned()).expect("skill ref")
    }

    fn scope() -> SkillScope {
        SkillScope {
            task_scope: "task-scope".to_owned(),
            host: "host-1".to_owned(),
            route: "route-1".to_owned(),
            governance_scope: "gov-1".to_owned(),
        }
    }

    fn base_view(fence: &StateFence) -> SkillLifecycleView {
        SkillLifecycleView {
            skill_ref: skill_ref(&"a".repeat(64)),
            scope: scope(),
            applies_when: vec!["when-a".to_owned()],
            does_not_apply_when: vec!["not-when-a".to_owned()],
            dependencies: Vec::new(),
            counters: LifecycleCounters::default(),
            execution_evidence: Vec::new(),
            observed_decision_or_verifier_delta: None,
            false_activation_refs: Vec::new(),
            interactions: SkillInteractionView::default(),
            status: SkillStatus::Current,
            stale_or_quarantine_reason: None,
            proposed_action: LifecycleAction::Keep,
            review: None,
            state_fence: fence.clone(),
            lifecycle_revision: 1,
        }
    }

    fn promoted_view(fence: &StateFence) -> SkillLifecycleView {
        let mut view = base_view(fence);
        view.skill_ref = skill_ref(&"b".repeat(64));
        view.lifecycle_revision = 2;
        view
    }

    fn candidate(fence: &StateFence, base: &SkillLifecycleView) -> SkillCandidate {
        SkillCandidate::new(
            base,
            "b".repeat(64),
            LifecycleAction::Patch,
            vec!["evidence-1".to_owned()],
            Vec::new(),
            scope(),
            fence.clone(),
        )
        .expect("candidate")
    }

    fn gate(fence: &StateFence, candidate: &SkillCandidate) -> PromotionGate {
        PromotionGate {
            candidate_digest: candidate.candidate_digest.clone(),
            base_view_digest: candidate.base_view_digest.clone(),
            verifier_ref: "verifier-1".to_owned(),
            evidence_refs: vec!["evidence-1".to_owned()],
            independent_route_count: 1,
            human_approval_ref: None,
            reversible: true,
            state_fence: fence.clone(),
        }
    }

    fn identity(fence: &StateFence) -> RequestIdentity {
        let metadata = RequestMetadata {
            request_id: RequestId::new("req-skill-1").expect("request id"),
            session_id: Some(SessionId::new("session-skill-1").expect("session")),
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
            idempotency_key: "idem-skill-1".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-skill-1".to_owned(),
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

    fn adapter<'a>(
        skill: &'a SkillRegistry,
        canonical: &'a CanonicalAdmissionOwner,
        kernel: &'a TestKernel,
    ) -> GovernorSkillLifecycle<'a, TestKernel> {
        GovernorSkillLifecycle::new(skill, canonical, kernel)
    }

    #[test]
    fn admitted_promotion_commits_and_survives_reconstruction_with_exact_receipt() {
        let fence = fence();
        let base = base_view(&fence);
        base.validate().expect("base valid");
        let promoted = promoted_view(&fence);
        promoted.validate().expect("promoted valid");
        let skill = SkillRegistry::from_snapshot([base.clone()]).expect("registry");
        let canonical = canonical_owner(&fence);
        let kernel = TestKernel::new();
        let owner = adapter(&skill, &canonical, &kernel);
        let candidate_value = candidate(&fence, &base);
        let gate_value = gate(&fence, &candidate_value);
        let identity_value = identity(&fence);
        let operation_id = OperationId::new("op-skill-positive").expect("operation id");
        let receipt = block_on(owner.promote(
            &identity_value,
            operation_id.clone(),
            candidate_value.clone(),
            gate_value.clone(),
            promoted.clone(),
        ))
        .expect("admitted promotion");
        assert_eq!(receipt.operation_id, operation_id);
        assert_eq!(receipt.idempotency_key, identity_value.idempotency_key);
        assert_eq!(receipt.status, WriteReceiptStatus::Committed);
        assert_eq!(receipt.transition_class, TransitionClass::LifecyclePolicy);
        assert_eq!(*kernel.apply_calls.lock().expect("lock"), 1);
        let stored = block_on(kernel.receipt(operation_id.clone()))
            .expect("receipt route")
            .expect("stored receipt");
        assert_eq!(stored, receipt);
        let rebuilt = SkillRegistry::from_snapshot([promoted.clone()]).expect("reconstruction");
        let read = rebuilt.view("skill-demo").expect("rebuilt view");
        assert_eq!(read.lifecycle_revision, 2);
        assert_eq!(read.skill_ref.package_digest, "b".repeat(64));
        assert_eq!(read.state_fence, fence);
    }

    #[test]
    fn changed_base_fails_without_promotion() {
        let fence = fence();
        let base = base_view(&fence);
        let stale_candidate = candidate(&fence, &base);
        let stale_gate = gate(&fence, &stale_candidate);
        let stale_promoted = promoted_view(&fence);
        let mut skill = SkillRegistry::from_snapshot([base]).expect("registry");
        skill
            .record_view(stale_promoted.clone())
            .expect("advance base to revision 2");
        let canonical = canonical_owner(&fence);
        let kernel = TestKernel::new();
        let owner = adapter(&skill, &canonical, &kernel);
        let identity_value = identity(&fence);
        let operation_id = OperationId::new("op-skill-stale").expect("operation id");
        let rejected = block_on(owner.promote(
            &identity_value,
            operation_id.clone(),
            stale_candidate,
            stale_gate,
            stale_promoted,
        ));
        assert!(
            matches!(
                rejected,
                Err(SkillError::IdentityMismatch
                    | SkillError::RevisionConflict
                    | SkillError::NotFound)
            ),
            "stale base was not rejected without promotion: {rejected:?}"
        );
        assert_eq!(kernel.apply_count(), 0);
        assert!(kernel.committed.lock().expect("lock").is_empty());
    }

    #[test]
    fn lost_acknowledgement_reconciles_to_the_same_operation_receipt() {
        let fence = fence();
        let base = base_view(&fence);
        let promoted = promoted_view(&fence);
        let skill = SkillRegistry::from_snapshot([base.clone()]).expect("registry");
        let canonical = canonical_owner(&fence);
        let kernel = TestKernel::new();
        let owner = adapter(&skill, &canonical, &kernel);
        let candidate_value = candidate(&fence, &base);
        let gate_value = gate(&fence, &candidate_value);
        let identity_value = identity(&fence);
        let operation_id = OperationId::new("op-skill-reconcile").expect("operation id");
        let receipt = block_on(owner.promote(
            &identity_value,
            operation_id.clone(),
            candidate_value.clone(),
            gate_value.clone(),
            promoted.clone(),
        ))
        .expect("admitted promotion");
        let reconciled = block_on(kernel.receipt(receipt.operation_id.clone()))
            .expect("receipt route")
            .expect("stored receipt");
        assert_eq!(reconciled, receipt);
        let mut retry = identity_value.clone();
        retry.deadline_unix_ms = 1_900_000_000_000;
        retry.cancellation_id = "cancel-skill-retry".to_owned();
        let replayed = block_on(owner.promote(
            &retry,
            operation_id.clone(),
            candidate_value,
            gate_value,
            promoted,
        ))
        .expect("idempotent replay");
        assert_eq!(replayed, receipt);
        assert_eq!(
            kernel.apply_count(),
            1,
            "retry with a new deadline must not re-execute"
        );
    }

    #[test]
    fn denied_mapping_validates_with_empty_evidence() {
        let ctx = StoreFailureIdentityContext::default();
        // Kernel admission refusal is an authorization denial: non-retryable,
        // never capacity backoff.
        let SkillError::Store(denied) =
            map_kernel_error(KernelPortError::NotAdmitted("gate".to_owned()), &ctx)
        else {
            panic!("kernel NotAdmitted must map to a typed store failure");
        };
        assert_eq!(denied.disposition, StoreFailureDisposition::Denied);
        assert_eq!(denied.retry_directive, StoreRetryDirective::DoNotRetry);
        assert!(denied.evidence_handles.is_empty());
        denied.validate().expect("denied failure validates");
    }
}
