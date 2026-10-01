//! Governor-owned production FinishAttempt path.
//!
//! The adapter owns the boundary between the public candidate draft and the
//! rebuildable [`eliot_finish::FinishService`].  It reads the current task and
//! canonical finish-evidence owner at one fence, evaluates a scratch service,
//! persists the complete receipt projection through the existing canonical
//! transition path, and never treats a worker/provider result as task finish.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_canonical::{CanonicalWriteEnvelope, FinishAttemptDraft, FinishEvidence};
use eliot_change_monitor::ChangeMonitor;
use eliot_contracts::{
    OperationId, StateFence, TaskId, canonical_json_bytes, fences_match_exact, sha256_hex,
};
use eliot_coordination::{CoordinationOwner, FinishCoordinationProjection};
use eliot_finish::{
    FinishAdmission, FinishAttempt, FinishClosureIntent, FinishContext, FinishDecisionReceipt,
    FinishError, FinishService, TaskLifecycleState,
};
use eliot_observation::{ObservationAdmissionResult, ObservationJournal, ObservationPlanBinding};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationManifestDigest, OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation,
    ScopeId, SecurityContext, StoreFailure, TransitionClass, WriteReceipt, WriteReceiptStatus,
    generated_operation_manifests, operation_manifest_set_digest,
};
use eliot_task::{TaskCommand, TaskLifecycleOwner, TaskRecord, TaskState};
use eliot_testd_core::{
    JobState as TestdJobState, TestdStore, TestdTerminalCompletionEvidence,
    verification_receipt_sha256,
};
use thiserror::Error;

use crate::{
    AcceptanceDenominatorError, CanonicalAdmissionOwner, CanonicalAdmissionSnapshot,
    CanonicalFinishEvidence, CanonicalPlanBinding, CanonicalVerifierExecutionFact,
    CanonicalVerifierPlanState, CompositionError, GovernorOwners, KernelPortError,
    KernelTransitionPort, RehydratedContractAcceptanceSet, acceptance_coverage_from_verifier_fact,
    evaluate_testd_verification_current, task_acceptance_set_commitment,
};

/// The Governor's own canonical store scope identity.
///
/// One scope identity for every Governor-owned durable owner row, so the
/// capability-evidence commit leg (issue #1773) and its complete paged
/// hydration read address exactly the same rows instead of inventing a second
/// scope string per leg.
pub const GOVERNOR_SCOPE_ID: &str = "governor";

/// Typed failure at the production finish boundary.
#[derive(Debug, Error)]
pub enum FinishAttemptError {
    /// The strict finish service rejected the candidate or rehydrated state.
    #[error("finish owner rejected the attempt: {0}")]
    Finish(#[from] FinishError),
    /// An unreconciled unknown-origin material change blocks governed acceptance.
    #[error("finish acceptance is blocked by an unreconciled unknown-origin material change")]
    UnreconciledMaterialChange,
    /// A host/filesystem hint has not completed its Git/content re-read.
    #[error("finish acceptance is blocked by an unverified host/filesystem change hint")]
    UnverifiedChangeHint,
    /// The canonical owner or composition rejected the operation.
    #[error("finish composition rejected the attempt: {0}")]
    Composition(#[from] CompositionError),
    /// The neutral Kernel transition could not establish an outcome.
    #[error("finish Kernel transition failed: {0}")]
    Kernel(#[from] KernelPortError),
    /// The contract owner's acceptance denominator could not be rehydrated or
    /// joined with the plan's declared set.
    ///
    /// This is a refusal, not a degradation: there is no path here that keeps
    /// the plan's own enumeration when the owner set is absent, stale, or
    /// different, because adopting the plan's list is the exact defect the
    /// owner read exists to close.
    #[error("finish acceptance denominator refused: {0}")]
    AcceptanceDenominator(#[from] AcceptanceDenominatorError),
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
    /// The current `WorkScope` binding owner, the declared owner of scope
    /// identity. `None` while the Kernel has not installed one, which is an
    /// explicit refusal for every consumer that needs a bound scope, never a
    /// default scope.
    work_scope: Option<&'a eliot_workscope::WorkScopeBindingOwner>,
    canonical: &'a CanonicalAdmissionOwner,
    coordination: &'a CoordinationOwner,
    observation: &'a ObservationJournal,
    change_monitor: &'a ChangeMonitor,
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
            work_scope: owners.work_scope.as_ref(),
            canonical,
            coordination: &owners.coordination,
            observation: &owners.observation,
            change_monitor: &owners.change_monitor,
            finish: &owners.finish,
            kernel,
            finish_owner_revision,
        }
    }

    /// Returns the retained receipt for an exact original Finish attempt,
    /// without consulting current task state or deriving a new decision.
    ///
    /// The receipt is only a candidate for historical replay here. The caller
    /// must still read the exact canonical operation receipt from Kernel and
    /// validate its operation, idempotency key, fence, and committed status
    /// before returning the historical decision to the host.
    pub(crate) fn historical_finish_receipt(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        draft: &FinishAttemptDraft,
        kernel_attempt: &eliot_protocol::FinishAttempt,
    ) -> Result<Option<FinishDecisionReceipt>, FinishAttemptError> {
        validate_identity(identity)?;
        draft
            .validate()
            .map_err(eliot_canonical::CanonicalError::from)
            .map_err(FinishError::from)?;
        kernel_attempt
            .validate()
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;

        let task_id = TaskId::new(draft.task_id.clone())
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
        let semantic_fence = &kernel_attempt.semantic_state_fence;
        if kernel_attempt.operation_id != operation_id.as_str()
            || kernel_attempt.task_id != task_id.as_str()
            || kernel_attempt.task_revision != draft.expected_task_revision
            || kernel_attempt.session_id
                != identity
                    .request
                    .metadata
                    .session_id
                    .as_ref()
                    .map_or("", eliot_contracts::SessionId::as_str)
            || identity.request.metadata.task_id.as_ref() != Some(&task_id)
            || semantic_fence.authority_epoch
                != identity.request.metadata.state_fence.authority_epoch
            || semantic_fence.resource_generation
                != identity.request.metadata.state_fence.resource_generation
            || semantic_fence
                .task_revision
                .map(eliot_contracts::TaskRevision::value)
                != Some(draft.expected_task_revision)
        {
            return Err(FinishError::IdentityConflict.into());
        }

        let attempt = FinishAttempt {
            attempt_id: identity.idempotency_key.clone(),
            state_fence: identity.request.metadata.state_fence.clone(),
            closure_intent: closure_intent(draft.requested_outcome),
            draft: draft.clone(),
            completion_proof: None,
        };
        let Some(receipt) = self.finish.receipt(&attempt.attempt_id) else {
            return Ok(None);
        };
        receipt.validate()?;
        if receipt.attempt_digest != attempt.digest()?
            || receipt.attempt_id != identity.idempotency_key
            || receipt.task_id != task_id.as_str()
            || receipt.task_revision != draft.expected_task_revision
            || receipt.requested_outcome != draft.requested_outcome
            || receipt.state_fence != identity.request.metadata.state_fence
        {
            return Err(FinishError::IdentityConflict.into());
        }
        Ok(Some(receipt.clone()))
    }
}

fn validate_nominated_artifact_bytes(
    verifier_fact: &CanonicalVerifierExecutionFact,
    references: &[String],
) -> Result<(), FinishAttemptError> {
    for reference in references {
        let artifact = verifier_fact
            .raw_artifact_bindings
            .iter()
            .find(|artifact| artifact.handle == *reference)
            .ok_or_else(|| {
                FinishAttemptError::Composition(CompositionError::Recovery(format!(
                    "artifact {reference:?} has no verified stored-byte binding in the current task/plan/fence-bound TestD receipt"
                )))
            })?;
        if artifact.truncated {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                format!("artifact {reference:?} is truncated in the original TestD receipt"),
            )));
        }
    }
    Ok(())
}

/// A caller may nominate the verifier run it expects Finish to use, but the
/// selector is admitted only when it names the exact current owner run. The
/// caller list never supplies or narrows the verifier denominator.
fn validate_nominated_verifier_run_refs(
    current_run_ref: &str,
    references: &[String],
) -> Result<(), FinishAttemptError> {
    if let Some(reference) = references
        .iter()
        .find(|reference| reference.as_str() != current_run_ref)
    {
        return Err(FinishAttemptError::Composition(CompositionError::Recovery(
            format!(
                "caller-nominated verifier run {reference:?} is not the current task-and-plan-bound executed run"
            ),
        )));
    }
    Ok(())
}

/// Pure output of one canonical finish-evidence derivation. The snapshot is
/// the next owner image; it is committed together with the durable decision.
struct ProducedFinishEvidence {
    canonical: CanonicalFinishEvidence,
    snapshot: CanonicalAdmissionSnapshot,
}

/// The exact neutral-Kernel exchange one prepared Governor owner leg still
/// owes, together with the identity it binds and the owner fence observed
/// before the caller began the exchange.
///
/// Preparing is pure. It rehydrates the current owner state, derives the one
/// `CanonicalWriteEnvelope`, checks the admitted identity against that
/// envelope, and returns the single immutable `PreparedTransition` plus the
/// compare-and-swap heads it was derived from. No transport is touched while
/// preparing, so a caller may hold a composition lock for the whole
/// preparation and release it before [`Self::exchange`]; the composition
/// borrow is only required again by the accept step, which re-checks the
/// retained [`Self::pre_commit_fence`] before a receipt is admitted.
///
/// A leg whose derived owner image is already current owes only a receipt
/// readback under its exact operation identity — re-deriving a transition
/// there would mint a second fact for the same owner revision — so
/// [`Self::transition`] is absent and [`Self::exchange`] reconciles instead of
/// committing. That distinction is carried by the value itself and is never
/// inferred by the caller.
#[derive(Clone, Debug)]
pub struct PreparedKernelExchange {
    identity: RequestIdentity,
    operation_id: OperationId,
    idempotency_key: String,
    transition: Option<PreparedTransition>,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
    pre_commit_fence: StateFence,
}

impl PreparedKernelExchange {
    /// The admitted identity this exchange must be submitted under. It is the
    /// identity the envelope and the derived transition were both checked
    /// against; nothing here is synthesized locally.
    #[must_use]
    pub const fn identity(&self) -> &RequestIdentity {
        &self.identity
    }

    /// The exact operation identity this exchange commits or reconciles.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// The owner fence captured while preparing, before this leg committed
    /// anything. The accept step compares it against the live owner fence so a
    /// fence that moved during the exchange refuses the receipt.
    #[must_use]
    pub const fn pre_commit_fence(&self) -> &StateFence {
        &self.pre_commit_fence
    }

    /// Runs the owed exchange over the neutral Kernel port.
    ///
    /// This method deliberately borrows no `GovernorComposition`: the caller
    /// runs it with no composition lock held, which is what keeps a
    /// `tokio::sync::MutexGuard` over the daemon composition off a Kernel
    /// round trip. The unresolved-outcome reconciliation is the owner's and is
    /// unchanged: an unknown commit outcome is settled by reading the receipt
    /// for this exact operation rather than by re-deriving the transition.
    pub async fn exchange<P: KernelTransitionPort + ?Sized>(
        &self,
        port: &P,
    ) -> Result<WriteReceipt, FinishAttemptError> {
        let Some(transition) = self.transition.clone() else {
            return self.reconcile_receipt(port).await;
        };
        let committed = match port
            .apply_prepared(
                &self.identity,
                transition,
                self.expected_revision_heads.clone(),
                self.expected_ordering_heads.clone(),
            )
            .await
        {
            Ok(receipt) => receipt,
            Err(KernelPortError::Unknown(_)) => return self.reconcile_receipt(port).await,
            Err(error) => return Err(error.into()),
        };
        check_finish_receipt(
            &committed,
            &self.operation_id,
            &self.pre_commit_fence,
            &self.idempotency_key,
        )?;
        Ok(committed)
    }

    /// Reads back the committed receipt for this exact operation.
    ///
    /// Used for the already-current owner image, where the transition must not
    /// be re-derived, and for an unknown commit outcome, where the outcome
    /// must be established rather than assumed.
    async fn reconcile_receipt<P: KernelTransitionPort + ?Sized>(
        &self,
        port: &P,
    ) -> Result<WriteReceipt, FinishAttemptError> {
        let committed = port
            .receipt(self.operation_id.clone())
            .await?
            .ok_or_else(|| {
                FinishAttemptError::Kernel(KernelPortError::Unknown(format!(
                    "{} receipt is unresolved after an unknown commit outcome",
                    self.operation_id.as_str()
                )))
            })?;
        check_finish_receipt(
            &committed,
            &self.operation_id,
            &self.pre_commit_fence,
            &self.idempotency_key,
        )?;
        Ok(committed)
    }
}

/// One prepared finish-decision leg: the decision the Governor derived from
/// canonical evidence, and the exchange that leg still owes.
///
/// A `None` exchange means the finish service already admitted this attempt
/// under the admitted idempotency identity, so the retained decision replays
/// and no canonical mutation is owed; the decision is the same value either
/// way and is never recomputed.
#[derive(Clone, Debug)]
pub struct PreparedFinishDecision {
    decision: FinishDecisionReceipt,
    exchange: Option<PreparedKernelExchange>,
}

impl PreparedFinishDecision {
    /// The exchange this decision still owes, or `None` when the retained
    /// decision replays without a canonical mutation.
    #[must_use]
    pub const fn exchange(&self) -> Option<&PreparedKernelExchange> {
        self.exchange.as_ref()
    }

    /// Consumes the plan and returns the Governor-derived decision.
    #[must_use]
    pub fn into_decision(self) -> FinishDecisionReceipt {
        self.decision
    }
}

/// Derives the single immutable transition one Governor-owned leg will submit.
///
/// This is the whole of the pre-transport half of the canonical owner commit:
/// the admitted identity is validated, the envelope's request and idempotency
/// binding must agree with it exactly, and the transition derived from the
/// envelope must agree with both. Nothing is rehashed or repaired locally.
fn prepare_exchange(
    canonical: &CanonicalAdmissionOwner,
    identity: &RequestIdentity,
    envelope: CanonicalWriteEnvelope,
) -> Result<PreparedKernelExchange, FinishAttemptError> {
    identity.validate().map_err(|error| {
        FinishAttemptError::Composition(CompositionError::Provider(error.to_string()))
    })?;
    if envelope.request != identity.request.metadata {
        return Err(FinishAttemptError::Composition(CompositionError::Provider(
            "admitted request binding does not match the Canonical envelope request".to_owned(),
        )));
    }
    if envelope.idempotency_key != identity.idempotency_key {
        return Err(FinishAttemptError::Composition(CompositionError::Provider(
            "admitted idempotency key does not match the Canonical envelope".to_owned(),
        )));
    }
    let transition = canonical.prepare(&envelope)?;
    if transition.identity.idempotency_key != identity.idempotency_key
        || transition.state_fence != identity.request.metadata.state_fence
    {
        return Err(FinishAttemptError::Composition(CompositionError::Provider(
            "immutable transition does not agree with the admitted request identity".to_owned(),
        )));
    }
    // The envelope is consumed here: the operation and the compare-and-swap
    // heads the transition was derived from move into the exchange, so the
    // Kernel leg cannot be handed a different head set than the one the
    // admission actually produced.
    Ok(PreparedKernelExchange {
        operation_id: envelope.operation_id,
        idempotency_key: identity.idempotency_key.clone(),
        pre_commit_fence: canonical.state_fence().clone(),
        identity: identity.clone(),
        transition: Some(transition),
        expected_revision_heads: envelope.expected_revision_heads,
        expected_ordering_heads: envelope.expected_ordering_heads,
    })
}

/// Prepares the receipt readback owed by a leg whose derived owner image is
/// already current. The operation and idempotency binding are the ones the
/// original commit used, so the readback resolves the same logical transition.
fn prepare_receipt_readback(
    canonical: &CanonicalAdmissionOwner,
    operation_id: OperationId,
    identity: &RequestIdentity,
) -> PreparedKernelExchange {
    PreparedKernelExchange {
        identity: identity.clone(),
        operation_id,
        idempotency_key: identity.idempotency_key.clone(),
        transition: None,
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
        pre_commit_fence: canonical.state_fence().clone(),
    }
}

impl<P: ?Sized> GovernorFinishAttempt<'_, P> {
    /// Rehydrates the task-and-plan-bound observation receipts this finish
    /// attempt depends on, at the exact `task.revision` and fence
    /// (issue #325 P1, I7.9).
    ///
    /// This walks the same-fence, task-and-plan-bound receipts the path already
    /// required and contributes each accepted receipt's record id to
    /// `observation_refs`, so the rehydration and the observation join cannot
    /// drift apart. Task-bound receipts that disagree about the recorded task
    /// selection identity are ambiguous owner state, not a majority vote, so
    /// this fails closed rather than picking one.
    ///
    /// The acceptance identity carried on those receipts is NOT the finish
    /// denominator: the denominator is the contract owner's own enumeration,
    /// rehydrated through [`Self::rehydrate_task_contract_acceptance`]. What
    /// this walk returns is `TaskSelectionEvidence::acceptance_digest`, and that
    /// field is **caller-stated at intake** — the intake path can supply an
    /// arbitrary 64-hex value, and the exploratory `eliot-workscope` branch
    /// computes it as `sha256_hex` over the task goal rather than over the
    /// contract's obligation set. It is not an independent owner of the same
    /// fact and it proves nothing on its own; it is only a cross-check that the
    /// task-selection evidence agrees with the contract owner's enumeration.
    ///
    /// That is why the conjunct is an *addition* to
    /// [`crate::AcceptanceDenominatorError::bind`] and never a replacement for
    /// it: `bind` is the enforcement, and this one is a consistency check over a
    /// caller-stated value. Before the owner-enumeration change the commitment
    /// was forced implicitly, because the receipt digest *was* the denominator's
    /// digest and `ContractAcceptanceDenominator::admits` recomputed the
    /// commitment over the enumeration retained beside it. Restating it as an
    /// explicit conjunct keeps that refusal while leaving the receipt digest the
    /// weak, caller-stated value it always was.
    fn rehydrate_task_bound_observation_refs(
        &self,
        task_id: &TaskId,
        task: &TaskRecord,
        plan: &CanonicalPlanBinding,
        fence: &StateFence,
        nominated_refs: &[String],
        observation_refs: &mut BTreeSet<String>,
    ) -> Result<String, FinishAttemptError> {
        let mut selection_identity: Option<String> = None;
        for entry in self.observation.snapshot() {
            let receipt = match &entry.result {
                ObservationAdmissionResult::Accepted { receipt }
                | ObservationAdmissionResult::Replayed { receipt } => receipt,
                ObservationAdmissionResult::Rejected { .. } => continue,
            };
            let Some(selection) = receipt.task_selection.as_ref().filter(|selection| {
                receipt.state_fence == *fence
                    && selection.task_ref == task_id.as_str()
                    && selection.task_revision == task.revision
                    && matches_plan(receipt.plan.as_ref(), plan, fence)
            }) else {
                continue;
            };
            receipt.validate().map_err(|error| {
                FinishAttemptError::Composition(CompositionError::Recovery(format!(
                    "accepted task observation receipt is invalid: {error}"
                )))
            })?;
            if selection_identity
                .as_ref()
                .is_some_and(|seen| *seen != selection.acceptance_digest)
            {
                return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                    "task-bound owner evidence disagrees about the current contract acceptance set"
                        .to_owned(),
                )));
            }
            selection_identity = Some(selection.acceptance_digest.clone());
            observation_refs.insert(receipt.record_id.clone());
        }
        if let Some(reference) = nominated_refs
            .iter()
            .find(|reference| !observation_refs.contains(*reference))
        {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                format!(
                    "caller-nominated observation {reference:?} is not a current task-and-plan-bound accepted observation"
                ),
            )));
        }
        selection_identity.ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical finish evidence has no accepted task-and-plan-bound observation"
                    .to_owned(),
            ))
        })
    }

    /// Reads the canonical owner fact that is the ONLY source of verifier
    /// authority, and refuses it when it is stale for the current task or plan.
    ///
    /// Task commands and observation epistemic labels are requests and
    /// projections; neither is an executed verifier outcome, so neither may
    /// stand in for this fact. A fact bound to a different task revision or a
    /// different plan describes a run of some other decision.
    ///
    /// Returns the fact and its run reference together so the caller cannot
    /// derive the run id from anywhere but the fact it just admitted.
    fn read_current_verifier_fact(
        &self,
        task_id: &TaskId,
        task: &TaskRecord,
        plan: &CanonicalPlanBinding,
        fence: &StateFence,
    ) -> Result<(CanonicalVerifierExecutionFact, String), FinishAttemptError> {
        let verifier_fact = self
            .canonical
            .read_verifier_execution_fact(fence)
            .map_err(FinishAttemptError::Composition)?;
        if verifier_fact.task_id != task_id.as_str()
            || verifier_fact.task_revision != task.revision
            || verifier_fact.plan != *plan
        {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical verifier execution fact is stale for the current task/plan".to_owned(),
            )));
        }
        verifier_fact
            .revalidate_retained_testd_bytes(fence, plan)
            .map_err(FinishAttemptError::Composition)?;
        let verifier_run_ref = verifier_fact.verification_run.run_id.to_string();
        Ok((verifier_fact, verifier_run_ref))
    }

    /// Collects the frame references and the finish authority reference the
    /// task itself carries, over the task's own committed event range.
    ///
    /// Only events inside the fence and the task's last sequence are read, so a
    /// frame or authority from another fence, another task, or a sequence this
    /// task has not reached cannot enter the evidence. The authority reference
    /// is the LAST one in range, matching the task owner's own projection order.
    fn scan_task_frame_and_authority(
        &self,
        task_id: &TaskId,
        task: &TaskRecord,
        fence: &StateFence,
    ) -> (BTreeSet<String>, Option<String>) {
        let mut frame_refs = BTreeSet::new();
        let mut finish_authority_ref = None;
        for event in self.task.events().iter().filter(|event| {
            event.task_id == *task_id
                && event.state_fence == *fence
                && event.authority_epoch == fence.authority_epoch
                && event.sequence > 0
                && event.sequence <= task.last_sequence
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
                _ => {}
            }
        }
        (frame_refs, finish_authority_ref)
    }

    /// Reads the coordination owner's finish projection and refuses it when it
    /// is not this task's projection under this fence.
    ///
    /// A projection carrying another task's id or another fence describes a
    /// different decision's coordination state; adopting its artifact or effect
    /// references would attribute them to this finish.
    fn read_current_finish_projection(
        &self,
        task_id: &TaskId,
        fence: &StateFence,
    ) -> Result<FinishCoordinationProjection, FinishAttemptError> {
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
        Ok(coordination)
    }

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
        nominated_refs: (&[String], &[String], &[String]),
        contract_acceptance_set: &RehydratedContractAcceptanceSet,
    ) -> Result<ProducedFinishEvidence, FinishAttemptError> {
        let (frame_refs, finish_authority_ref) =
            self.scan_task_frame_and_authority(task_id, task, fence);
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

        // Verifier authority comes only from the canonical owner fact
        // produced from the current durable TestD row. Task commands and
        // observation epistemic labels are requests/projections; neither is
        // an executed verifier outcome.
        let (verifier_fact, verifier_run_ref) =
            self.read_current_verifier_fact(task_id, task, plan, fence)?;
        validate_nominated_artifact_bytes(&verifier_fact, nominated_refs.0)?;
        validate_nominated_verifier_run_refs(&verifier_run_ref, nominated_refs.2)?;
        // This fact has already been rehydrated and validated against the
        // current task, plan, fence, and durable terminal TestD receipt. A
        // failed or partial verifier is still an executed run; its outcome is
        // represented per required test below, not mislabeled as stale.

        let coordination = self.read_current_finish_projection(task_id, fence)?;
        validate_nominated_artifact_bytes(&verifier_fact, &coordination.artifact_refs)?;

        let mut observation_refs = BTreeSet::new();
        // The task-and-plan-bound observation receipts are joined here so their
        // record ids enter the artifact evidence. They are not the acceptance
        // denominator: the denominator is rehydrated from the contract owner
        // instead. The digest they carry is a caller-stated value, not a second
        // owner of the fact, so it is returned only as a cross-check that the
        // task-selection evidence agrees with the contract owner's enumeration.
        let selection_acceptance_digest = self.rehydrate_task_bound_observation_refs(
            task_id,
            task,
            plan,
            fence,
            nominated_refs.1,
            &mut observation_refs,
        )?;
        // The verifier requirement is unchanged: a plan the Task Controller has
        // not yet given a verifier request contract cannot support a verifier-
        // backed completion. What changed is that the refusal now names the
        // typed state and the owner's own reason reference instead of reporting
        // an indistinguishable absent binding.
        let verifier_plan = plan.verifier_binding().map_err(|error| {
            FinishAttemptError::Composition(CompositionError::Recovery(format!(
                "canonical plan has no verifier binding: {error}"
            )))
        })?;
        // Issue #1741, I7.9: the denominator is the CONTRACT OWNER's
        // enumeration, rehydrated at this exact task id and task revision through
        // the neutral `GetTaskContractAcceptanceSet` named read
        // ([`Self::rehydrate_task_contract_acceptance`]). The plan's declared
        // `required_acceptance_item_ids` are compared against it item by item
        // and are never adopted: a plan that declares a strict subset would
        // otherwise report a smaller denominator as complete coverage, and a plan
        // that declares a strict superset would make the gate carry an
        // obligation the contract never required. The retained acceptance
        // identity is the owner's own recorded value, and the existing
        // `CanonicalContractAcceptance::validate` proves it commits to the
        // enumeration retained beside it.
        let contract_acceptance = AcceptanceDenominatorError::bind(
            task_id.as_str(),
            task.revision,
            contract_acceptance_set,
            verifier_plan,
        )?;

        let denominator = contract_acceptance.denominator();

        // The additional conjunct: the task-selection owner evidence must also
        // commit to the enumerated set. `bind` has already refused unless the
        // plan's declared ids and the contract owner's ids are the same set, so
        // recomputing the commitment over the denominator's own `item_ids` is
        // the commitment over the plan's list as well. This is the check the
        // pre-owner-enumeration design got implicitly, when the receipt digest
        // *was* this denominator's digest; restoring it as an explicit
        // conjunct keeps the prior refusal instead of trading it away, and it
        // is an addition to `bind`, never a replacement for it.
        if task_acceptance_set_commitment(&denominator.item_ids)? != selection_acceptance_digest {
            return Err(AcceptanceDenominatorError::SelectionEvidenceDisagrees.into());
        }

        let acceptance =
            acceptance_coverage_from_verifier_fact(&denominator, plan, &verifier_fact)?;
        let stale_verifier_run_refs = if verifier_fact.certifies_completion() {
            Vec::new()
        } else {
            vec![verifier_run_ref.clone()]
        };
        let mut artifact_refs = coordination.artifact_refs.clone();
        artifact_refs.extend(frame_refs);
        artifact_refs.extend(observation_refs);
        let descendant_receipt_ref = coordination.descendant_receipt_ref;
        if let Some(receipt_ref) = &descendant_receipt_ref {
            artifact_refs.push(receipt_ref.clone());
        }
        artifact_refs.sort();
        artifact_refs.dedup();
        let mut unresolved_effect_refs = coordination.unresolved_refs.clone();
        unresolved_effect_refs.sort();
        unresolved_effect_refs.dedup();
        let descendant_closure = match descendant_receipt_ref {
            Some(receipt_ref) => eliot_finish::DescendantClosure::Complete { receipt_ref },
            None => eliot_finish::DescendantClosure::Incomplete {
                unresolved_refs: unresolved_effect_refs.clone(),
            },
        };
        let evidence = FinishEvidence {
            task_id: task_id.as_str().to_owned(),
            current_task_revision: task.revision,
            artifact_refs,
            acceptance,
            executed_verifier_run_refs: vec![verifier_run_ref.clone()],
            stale_verifier_run_refs,
            unresolved_effect_refs,
        };
        evidence
            .validate()
            .map_err(|error| FinishAttemptError::Finish(FinishError::from(error)))?;
        let canonical = CanonicalFinishEvidence {
            state_fence: fence.clone(),
            contract_acceptance,
            evidence,
            effect_reference_bindings: verifier_fact.effect_reference_bindings.clone(),
            descendant_closure,
            finish_authority_ref: finish_authority_ref.clone(),
            closure_authority_ref: task_closure_authority_ref(
                task_id,
                task,
                self.task.events(),
                fence,
                &verifier_run_ref,
            ),
        };
        let snapshot = self.canonical.prepare_finish_evidence(canonical.clone())?;
        Ok(ProducedFinishEvidence {
            canonical,
            snapshot,
        })
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

fn task_closure_authority_ref(
    task_id: &TaskId,
    task: &TaskRecord,
    events: &[eliot_task::TaskLifecycleEvent],
    fence: &StateFence,
    verifier_run_ref: &str,
) -> Option<String> {
    let event = events.iter().find(|event| {
        event.task_id == *task_id
            && event.sequence == task.last_sequence
            && event.event_id == task.last_event_id
            && event.to == task.state
            && event.state_fence == *fence
            && event.authority_epoch == fence.authority_epoch
    })?;
    let owner_disposition_matches = match (task.state, event.command.as_ref()) {
        (TaskState::DoneVerified, Some(TaskCommand::Verify { verification_ref })) => {
            verification_ref == verifier_run_ref
        }
        (TaskState::Partial, Some(TaskCommand::MarkPartial { .. }))
        | (TaskState::Failed, Some(TaskCommand::Fail { .. })) => true,
        _ => false,
    };
    owner_disposition_matches.then(|| {
        format!(
            "task-lifecycle:event:{}:{}:{}",
            task_id.as_str(),
            event.sequence,
            event.event_id
        )
    })
}

impl<P: KernelTransitionPort + ?Sized> GovernorFinishAttempt<'_, P> {
    /// Derives the Task Controller's current plan revision for one task from
    /// owner state alone (issue #1741, I7.9).
    ///
    /// This is the read half of current-plan admission, and the only place the
    /// plan identity is assembled. It reads the live task-lifecycle record and
    /// the current `WorkScope` binding; it takes no plan, no revision, and no
    /// scope from a caller, so no caller can hand the canonical owner a plan of
    /// its own choosing.
    ///
    /// # Why the task-lifecycle owner, not an observation receipt
    ///
    /// A10.4:22 places the current plan revision of one task under the active
    /// Authority Epoch with exactly one Task Controller, and A2.2:22 keeps it
    /// from the Main Agent and from workers. The task-lifecycle owner *is* that
    /// Task Controller's durable record: it holds the current `TaskRecord`
    /// (identity, revision, state, fence) and the committed event range the
    /// controller framed the task in. The `WorkScope` binding owner is the
    /// declared owner of scope identity (`StateFence::I45_KEY_OMISSIONS` assigns
    /// the scope dimension to it and forbids a fence-wide counter).
    ///
    /// The previous derivation read `ObservationPlanBinding` off the
    /// Task-selection owner's accepted receipts. That field is `None` at every
    /// production construction site — `ObservationSubmission.plan` is `None` in
    /// `observation_reconciliation.rs` at all five, and `task_selection: Some(..)`
    /// has no production constructor at all — so that derivation refused on every
    /// live daemon and moved the W3 refusal from `read_current_plan` to
    /// `admit_task_controller_plan` without making the rehydration reachable.
    /// A receipt field nobody sets is not an owner read, so the plan is re-derived
    /// here from the two owners that do hold it.
    ///
    /// `plan_id` is the frame reference the Task Controller itself committed on
    /// the task's own event range, at this exact fence, inside the task's last
    /// sequence — the same range and the same filter
    /// [`Self::scan_task_frame_and_authority`] reads for artifact evidence, so
    /// the plan identity and the artifact evidence cannot be two different
    /// statements about the same framing. `plan_revision` is the owner record's
    /// own current revision. `work_scope_id` is the current `WorkScope` binding's
    /// own scope reference.
    ///
    /// Fails closed, without synthesizing anything: an absent task, a record
    /// stale for the fence, a zero revision, a state outside the plan-bearing set,
    /// no committed frame in range, an absent or fence-mismatched `WorkScope`
    /// binding, or a derived image that does not validate.
    pub fn admit_task_controller_plan(
        &self,
        task_id: &TaskId,
    ) -> Result<(CanonicalPlanBinding, u64), FinishAttemptError> {
        let task = self.task.task(task_id).ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(format!(
                "canonical task {} is absent; no current plan can be admitted for it",
                task_id.as_str()
            )))
        })?;
        let fence = self.canonical.state_fence().clone();
        if task.task_id != *task_id || task.state_fence != fence {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "task-lifecycle owner record is stale for current plan admission".to_owned(),
            )));
        }
        let (plan_id, work_scope_id) = self.current_task_plan_identity(task_id, task, &fence)?;
        let mut plan = CanonicalPlanBinding::new(
            plan_id,
            task.revision.to_string(),
            task_id.clone(),
            work_scope_id,
        )
        .map_err(FinishAttemptError::Composition)?;
        if let Some(retained) = self.retained_verifier_state(&plan, &fence) {
            plan.verifier = retained;
        }
        Ok((plan, task.revision))
    }

    /// Resolves the Task Controller's published plan identity for one task from
    /// the two owners that hold it: the committed same-fence frame on the task's
    /// own event range, and the current `WorkScope` binding.
    ///
    /// This is the whole of the owner derivation
    /// [`Self::admit_task_controller_plan`] performs; that method keeps the
    /// admission preconditions and the verifier-state carry-forward and delegates
    /// the identity read here, so neither half can grow into the other. Every
    /// refusal is the same typed one, raised from the same check at the same
    /// point: an absent task, a record stale for the fence, a zero revision, a
    /// state outside the plan-bearing set, no committed frame in range, or an
    /// absent or fence-mismatched `WorkScope` binding.
    fn current_task_plan_identity(
        &self,
        task_id: &TaskId,
        task: &TaskRecord,
        fence: &StateFence,
    ) -> Result<(String, String), FinishAttemptError> {
        // A task holds a plan only while the Task Controller's authority over it
        // is live. This is the same state set `read_unique_agent_activation`
        // admits, so the plan cannot be installed for a task that is already
        // closing, blocked, or never authorized.
        if task.revision == 0
            || !matches!(
                task.state,
                TaskState::ActionAuthorized | TaskState::Executing | TaskState::Verifying
            )
        {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "task is not in a plan-bearing state; current plan admission is refused".to_owned(),
            )));
        }
        let plan_id = self
            .current_task_frame_ref(task_id, task, fence)
            .ok_or_else(|| {
                FinishAttemptError::Composition(CompositionError::Recovery(format!(
                    "task-lifecycle owner has no committed same-fence acceptance frame for task {} \
                     at revision {}; current plan admission is refused",
                    task_id.as_str(),
                    task.revision
                )))
            })?;
        let work_scope = self.work_scope.ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(
                "no current WorkScope binding owner is installed; current plan admission is refused"
                    .to_owned(),
            ))
        })?;
        let scope = work_scope.read_current(fence).map_err(|error| {
            FinishAttemptError::Composition(CompositionError::Recovery(format!(
                "current WorkScope binding read failed; current plan admission is refused: {error}"
            )))
        })?;
        Ok((plan_id, scope.binding.scope.scope_ref.clone()))
    }

    /// Returns the verifier state the retained owner image already records for
    /// this exact plan identity, or `None` when there is nothing to carry.
    ///
    /// The verifier request contract is a separate dimension of the owner image
    /// that only an owner decision sets, and the plan derivation must neither
    /// author one nor discard one. When the retained owner plan has the same
    /// identity — the same frame, the same task revision, the same task, the same
    /// bound scope — its recorded state is carried forward verbatim. That
    /// carry-forward is what makes an absent decision non-terminal: an owner
    /// decision that later binds a verifier changes the derived value, the caller
    /// compares it against the retained image by full equality, and the change
    /// advances the owner revision instead of being absorbed by the idempotence
    /// branch. See `CanonicalPlanBinding::verifier_binding` for what each state
    /// means.
    ///
    /// `None` covers both "no plan is retained yet" and "the retained plan is a
    /// different identity", and it is not a silent skip: `read_current_plan`
    /// validates the retained owner image first, and the image
    /// `admit_task_controller_plan` builds is validated again by
    /// `prepare_current_plan` before the envelope is built, so a corrupt retained
    /// plan cannot be overwritten by a derived one.
    fn retained_verifier_state(
        &self,
        plan: &CanonicalPlanBinding,
        fence: &StateFence,
    ) -> Option<CanonicalVerifierPlanState> {
        let retained = self.canonical.read_current_plan(fence).ok()?;
        (retained.plan_id == plan.plan_id
            && retained.plan_revision == plan.plan_revision
            && retained.task_id == plan.task_id
            && retained.work_scope_id == plan.work_scope_id)
            .then_some(retained.verifier)
    }

    /// Returns the frame reference the Task Controller last committed for one
    /// task inside its own committed event range at this exact fence.
    ///
    /// The filter is the one [`Self::scan_task_frame_and_authority`] uses, so the
    /// plan identity and the artifact evidence are the same owner value read
    /// twice, never two statements about the same framing. The LAST frame in
    /// range is returned, matching the task owner's own projection order: a task
    /// may be re-framed, and only the current framing is the current plan.
    fn current_task_frame_ref(
        &self,
        task_id: &TaskId,
        task: &TaskRecord,
        fence: &StateFence,
    ) -> Option<String> {
        self.task
            .events()
            .iter()
            .filter(|event| {
                event.task_id == *task_id
                    && event.state_fence == *fence
                    && event.authority_epoch == fence.authority_epoch
                    && event.sequence > 0
                    && event.sequence <= task.last_sequence
            })
            .filter_map(|event| match &event.command {
                Some(TaskCommand::Frame { frame_ref }) => Some(frame_ref.clone()),
                _ => None,
            })
            .next_back()
    }

    /// Wraps the current-plan owner transition in the exact prepared exchange
    /// the finish path already uses for every other canonical owner leg.
    ///
    /// The prepared leg is pure: it derives the immutable transition from the
    /// envelope and checks it against the admitted identity, so the caller may
    /// release its composition borrow before
    /// [`PreparedKernelExchange::exchange`].
    ///
    /// No operation identity is taken here because none is needed at this call
    /// site: `prepare_exchange` binds the exchange's operation from
    /// `envelope.operation_id` alone, which is the same binding the sibling
    /// owner legs rely on. The identity is therefore already committed upstream
    /// by `current_plan_envelope` (from the caller's `<operation>/current-plan`
    /// id) and travels inside the envelope, exactly as the finish-evidence leg's
    /// identity does. Accepting a second copy here would create a second source
    /// for one identity and could let the two disagree.
    pub(crate) fn prepare_current_plan_exchange(
        &self,
        identity: &RequestIdentity,
        envelope: CanonicalWriteEnvelope,
    ) -> Result<PreparedKernelExchange, FinishAttemptError> {
        prepare_exchange(self.canonical, identity, envelope)
    }

    /// Rehydrates the contract owner's exact `TaskContract` acceptance-item
    /// enumeration for one finish candidate (issue #1741, I7.9).
    ///
    /// I7.9 requires the Finish service to rehydrate the current `TaskContract`
    /// and its acceptance items. The canonical plan enumerates the obligations a
    /// plan *declares*, and the task-selection evidence carries an acceptance
    /// identity that is caller-stated at intake (or `sha256_hex` over the task
    /// goal on the exploratory branch of `eliot-workscope`), so neither can be
    /// the contract owner's enumeration. This is the only route that can.
    ///
    /// The read travels over the existing neutral Kernel named-read route
    /// through the existing [`KernelTransitionPort`] async port. No runtime is
    /// started inside the owner, no second port scheme is introduced, and the
    /// read is bounded to one round trip; the write legs of the finish path
    /// still run with no composition borrow held, as before.
    ///
    /// The task revision is the live task-lifecycle owner's own `TaskRecord`
    /// revision, never a value the caller supplies and never a
    /// `StateFence::task_revision`. That field is `None` on every production
    /// Kernel-generation fence by construction
    /// (`KernelGenerationSnapshot::state_fence` is
    /// `StateFence::new(authority_epoch, resource_generation)`), and
    /// `StateFence::I45_KEY_OMISSIONS` assigns the task-revision dimension to
    /// the operation's own owner record instead of the transport fence. The
    /// task-lifecycle owner already holds the current `TaskRecord.revision`,
    /// which is the durable task-bound write precondition I5.5 requires, so
    /// requiring the fence to restate it could only ever refuse.
    ///
    /// Fails closed with a typed [`AcceptanceDenominatorError`] when this task
    /// has no live owner record, when the port route is not admitted, or when
    /// the returned set is bound to another task, revision, or fence. There is
    /// no fallback to the plan's declared list.
    pub async fn rehydrate_task_contract_acceptance(
        &self,
        task_id: &TaskId,
    ) -> Result<RehydratedContractAcceptanceSet, FinishAttemptError> {
        let fence = self.canonical.state_fence().clone();
        let task = self.task.task(task_id).ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(format!(
                "canonical task {} is absent; its acceptance set cannot be rehydrated",
                task_id.as_str()
            )))
        })?;
        // A zero owner revision is not a current revision, so it never reaches
        // the contract owner's read.
        if task.revision == 0 {
            return Err(AcceptanceDenominatorError::TaskRevisionStale.into());
        }
        let set = self
            .kernel
            .task_contract_acceptance_set(task_id, task.revision, &fence)
            .await?;
        if set.task_id.as_str() != task_id.as_str() {
            return Err(AcceptanceDenominatorError::TaskSubstituted.into());
        }
        if set.task_revision != task.revision {
            return Err(AcceptanceDenominatorError::TaskRevisionStale.into());
        }
        if set.read_state_fence != fence {
            return Err(AcceptanceDenominatorError::FenceStale.into());
        }
        set.validate()
            .map_err(|error| AcceptanceDenominatorError::Malformed(error.to_string()))?;
        // Admitted here and nowhere else. This is the single production site
        // that can produce a `RehydratedContractAcceptanceSet`, and it produces
        // one only from the value the owner's neutral read returned. Every
        // downstream phase therefore receives a set whose provenance is the
        // type, not a convention its callers are trusted to honour.
        Ok(RehydratedContractAcceptanceSet::admit_owner_read(set))
    }

    /// Resolves the current task revision for one task-bound owner leg from the
    /// live task-lifecycle owner record (issue #1741, I7.9).
    ///
    /// This is the same treatment
    /// [`Self::rehydrate_task_contract_acceptance`] already applies to the
    /// acceptance denominator, applied here so the two owner legs cannot disagree
    /// about which revision they are admitted against. The value is the owner
    /// record's own `TaskRecord.revision`: never a caller-supplied revision, and
    /// never `StateFence::task_revision`.
    ///
    /// `StateFence::task_revision` is `None` on every production
    /// Kernel-generation fence by construction (`StateFence::new` sets
    /// `task_revision: None`, and `git grep 'task_revision: Some('` finds only a
    /// bridge dry-run projection and tests), so requiring it here could only ever
    /// refuse. `StateFence::I45_KEY_OMISSIONS` assigns the task-revision
    /// dimension to the operation's own owner record instead of the transport
    /// fence, and the task-lifecycle owner already holds the current
    /// `TaskRecord.revision`, which is the durable task-bound write precondition
    /// I5.5 requires.
    ///
    /// A presented fence that *does* carry a task revision is still checked, so
    /// the owner's own value is compared against any restatement of it: a
    /// disagreement is the typed `StaleTaskRevision` refusal, never a widened
    /// revision. Fails closed on an absent task, a record stale for this fence, or
    /// a zero owner revision.
    fn rehydrate_task_revision(
        &self,
        task_id: &TaskId,
        fence: &StateFence,
    ) -> Result<u64, FinishAttemptError> {
        let task = self.task.task(task_id).ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(format!(
                "canonical task {} is absent",
                task_id.as_str()
            )))
        })?;
        validate_task(task, fence)?;
        if let Some(presented) = fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value())
            && presented != task.revision
        {
            return Err(
                FinishError::Canonical(eliot_canonical::CanonicalError::StaleTaskRevision).into(),
            );
        }
        Ok(task.revision)
    }

    /// Rehydrates and publishes the verifier-execution owner from the
    /// current durable TestD row. `job_id` is the only TestD input crossing
    /// this boundary: the row, receipt, run, canonical task, current plan,
    /// and fence are all read and joined here, and the current task revision is
    /// resolved from the task-lifecycle owner. A caller-held `TestJob` or
    /// verdict cannot become canonical proof.
    ///
    /// This is the composed form of the same three phases
    /// [`Self::prepare_testd_verifier_execution_fact`],
    /// [`PreparedKernelExchange::exchange`] and
    /// [`Self::accept_prepared_exchange`] provide, for the caller that holds
    /// only `&self` and therefore has no mutable composition to refresh. The
    /// `TestD` owner drain does not use it: it runs the phases itself so no
    /// lock is held across the exchange.
    pub async fn publish_testd_verifier_execution_fact(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        task_id: &TaskId,
        job_id: &str,
        testd: &TestdStore,
    ) -> Result<Option<WriteReceipt>, FinishAttemptError> {
        let prepared = self.prepare_testd_verifier_execution_fact(
            identity,
            operation_id,
            task_id,
            job_id,
            testd,
        )?;
        let Some(exchange) = prepared.as_ref() else {
            return Ok(None);
        };
        let committed = exchange.exchange(self.kernel).await?;
        self.accept_prepared_exchange(exchange)?;
        Ok(Some(committed))
    }

    /// Rehydrates the verifier-execution owner from the current durable `TestD`
    /// row and returns the exact exchange it still owes, without touching the
    /// transport. See
    /// [`Self::prepare_testd_verifier_execution_fact_from_evidence`] for the
    /// daemon-side entry over Kernel-enumerated evidence.
    pub fn prepare_testd_verifier_execution_fact(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        task_id: &TaskId,
        job_id: &str,
        testd: &TestdStore,
    ) -> Result<Option<PreparedKernelExchange>, FinishAttemptError> {
        validate_identity(identity)?;
        let fence = identity.request.metadata.state_fence.clone();
        if self.canonical.state_fence() != &fence {
            return Err(FinishError::FenceMismatch.into());
        }
        if identity.request.metadata.task_id.as_ref() != Some(task_id) {
            return Err(FinishError::Canonical(
                eliot_canonical::CanonicalError::TaskBindingMismatch,
            )
            .into());
        }
        let task_revision = self.rehydrate_task_revision(task_id, &fence)?;
        let plan = self.canonical.read_current_plan(&fence)?;
        if plan.task_id != *task_id {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical verifier plan is task-mismatched".to_owned(),
            )));
        }
        let job = testd
            .get(job_id)
            .map_err(|error| {
                FinishAttemptError::Composition(CompositionError::Recovery(format!(
                    "TestD owner read failed: {error}"
                )))
            })?
            .ok_or_else(|| {
                FinishAttemptError::Composition(CompositionError::Recovery(format!(
                    "durable TestD job {job_id} is absent"
                )))
            })?;
        let receipt = job.verification_receipt.as_ref().ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(
                "durable TestD job has no full verification receipt".to_owned(),
            ))
        })?;
        let verifier_plan = plan.verifier_binding().map_err(|error| {
            FinishAttemptError::Composition(CompositionError::Recovery(format!(
                "canonical plan has no verifier binding: {error}"
            )))
        })?;
        let run = evaluate_testd_verification_current(&job, receipt, verifier_plan)?;
        let fact = CanonicalVerifierExecutionFact::from_testd(
            task_id,
            task_revision,
            &plan,
            &fence,
            &job,
            receipt,
            run,
        )?;
        let fact_operation = OperationId::new(format!("{operation_id}/verifier-execution"))
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
        let fact_identity = RequestIdentity {
            request: identity.request.clone(),
            idempotency_key: format!("{}:verifier-execution", identity.idempotency_key),
            deadline_unix_ms: identity.deadline_unix_ms,
            cancellation_id: identity.cancellation_id.clone(),
        };
        self.commit_verifier_execution_fact(task_id, &fence, &fact, &fact_identity, fact_operation)
    }

    /// Rehydrates the verifier-execution owner from complete identity-joined
    /// terminal evidence supplied by the Kernel owner route and returns the
    /// exact exchange it still owes, without touching the transport.
    ///
    /// This is the daemon-side prepare: the caller gives the exact evidence
    /// projection the Kernel owner just enumerated (durable job plus the
    /// admitted frame identity). The row, receipt, run, canonical task,
    /// current plan, and fence are all re-validated and joined here; a
    /// caller-held `TestJob` or verdict that disagrees with the admitted
    /// binding cannot become canonical proof. The daemon never opens the
    /// `TestD` database.
    ///
    /// Because nothing is transported here, the caller can release its
    /// composition lock before [`PreparedKernelExchange::exchange`] and take
    /// it again only for [`Self::accept_prepared_exchange`].
    pub fn prepare_testd_verifier_execution_fact_from_evidence(
        &self,
        evidence: &TestdTerminalCompletionEvidence,
    ) -> Result<Option<PreparedKernelExchange>, FinishAttemptError> {
        let identity = &evidence.request_identity;
        let job = &evidence.job;
        validate_identity(identity)?;
        let fence = identity.request.metadata.state_fence.clone();
        if self.canonical.state_fence() != &fence {
            return Err(FinishError::FenceMismatch.into());
        }
        let task_id = identity.request.metadata.task_id.clone().ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(
                "verifier fact evidence carries no admitted task id".to_owned(),
            ))
        })?;
        // The current task revision is the task-lifecycle owner record's own
        // value, resolved by the same owner read the acceptance denominator
        // uses. It is not taken from `StateFence::task_revision`, which is
        // structurally `None` on every production Kernel-generation fence and
        // therefore refused this leg on every row, and it is not a caller claim.
        let task_revision = self.rehydrate_task_revision(&task_id, &fence)?;
        if !matches!(
            job.state,
            TestdJobState::Succeeded | TestdJobState::Failed | TestdJobState::Cancelled
        ) || job.lease.is_some()
        {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "verifier fact evidence is not a settled terminal job".to_owned(),
            )));
        }
        let binding = job.verifier_dispatch.as_ref().ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(
                "verifier fact evidence has no admitted verifier binding".to_owned(),
            ))
        })?;
        binding.validate_for_job(job).map_err(|error| {
            FinishAttemptError::Composition(CompositionError::Recovery(format!(
                "verifier fact evidence binding does not match its job: {error}"
            )))
        })?;
        if binding.request_identity != *identity {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "verifier fact evidence identity differs from its admitted binding".to_owned(),
            )));
        }
        let receipt = job.verification_receipt.as_ref().ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(
                "verifier fact evidence has no full verification receipt".to_owned(),
            ))
        })?;
        verification_receipt_sha256(receipt).map_err(|error| {
            FinishAttemptError::Composition(CompositionError::Recovery(format!(
                "verifier fact evidence receipt is undecodable: {error}"
            )))
        })?;
        let plan = self.canonical.read_current_plan(&fence)?;
        if plan.task_id != task_id {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical verifier plan is task-mismatched".to_owned(),
            )));
        }
        let verifier_plan = plan.verifier_binding().map_err(|error| {
            FinishAttemptError::Composition(CompositionError::Recovery(format!(
                "canonical plan has no verifier binding: {error}"
            )))
        })?;
        let run = evaluate_testd_verification_current(job, receipt, verifier_plan)?;
        let fact = CanonicalVerifierExecutionFact::from_testd(
            &task_id,
            task_revision,
            &plan,
            &fence,
            job,
            receipt,
            run,
        )?;
        let operation_id = OperationId::new(job.process.operation_id.clone())
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
        let fact_operation = OperationId::new(format!("{operation_id}/verifier-execution"))
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
        let fact_identity = RequestIdentity {
            request: identity.request.clone(),
            idempotency_key: format!("{}:verifier-execution", identity.idempotency_key),
            deadline_unix_ms: identity.deadline_unix_ms,
            cancellation_id: identity.cancellation_id.clone(),
        };
        self.commit_verifier_execution_fact(&task_id, &fence, &fact, &fact_identity, fact_operation)
    }

    /// Derives the exact exchange that publishes one verifier-execution fact
    /// through the canonical owner CAS, without touching the transport. An
    /// identical current owner image is prepared as a receipt readback so the
    /// retained receipt is returned instead of a second fact being minted.
    fn commit_verifier_execution_fact(
        &self,
        task_id: &TaskId,
        fence: &StateFence,
        fact: &CanonicalVerifierExecutionFact,
        fact_identity: &RequestIdentity,
        fact_operation: OperationId,
    ) -> Result<Option<PreparedKernelExchange>, FinishAttemptError> {
        if self
            .canonical
            .read_verifier_execution_fact(fence)
            .ok()
            .is_some_and(|existing| existing == *fact)
        {
            return Ok(Some(prepare_receipt_readback(
                self.canonical,
                fact_operation,
                fact_identity,
            )));
        }
        let snapshot = self
            .canonical
            .prepare_verifier_execution_fact(fact.clone())?;
        let envelope = canonical_owner_snapshot_envelope(
            fact_identity,
            fact_operation,
            &snapshot,
            task_id.as_str(),
            fact.task_revision,
            &fact.verification_run.run_id.to_string(),
        )?;
        prepare_exchange(self.canonical, fact_identity, envelope).map(Some)
    }

    /// Re-checks a completed exchange against the live canonical owner before
    /// its receipt is admitted downstream.
    ///
    /// The prepared leg captured [`PreparedKernelExchange::pre_commit_fence`]
    /// before the caller started the exchange. The exchange itself runs with no
    /// composition borrow, so this is where the guarantee is recovered: if the
    /// owner fence moved while the exchange was in flight, the leg is refused
    /// with the same typed `FenceMismatch` the prepare half uses, instead of a
    /// stale owner image being published. The receipt was already bound to that
    /// fence by [`PreparedKernelExchange::exchange`], so nothing is re-derived
    /// and no receipt is repaired here.
    pub fn accept_prepared_exchange(
        &self,
        prepared: &PreparedKernelExchange,
    ) -> Result<(), FinishAttemptError> {
        if !fences_match_exact(prepared.pre_commit_fence(), self.canonical.state_fence()) {
            return Err(FinishError::FenceMismatch.into());
        }
        Ok(())
    }

    /// Produces the next canonical finish-evidence owner image and returns the
    /// exact exchange it still owes, without touching the transport.
    ///
    /// The derived child identity is created by Governor for this owner leg;
    /// it carries the admitted request binding and never accepts proof or
    /// evidence from the public draft.  An identical current owner image is
    /// already materialized, so nothing is owed and `None` is returned.
    pub fn prepare_finish_evidence(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        draft: &FinishAttemptDraft,
        contract_acceptance_set: &RehydratedContractAcceptanceSet,
    ) -> Result<Option<PreparedKernelExchange>, FinishAttemptError> {
        validate_identity(identity)?;
        draft
            .validate()
            .map_err(eliot_canonical::CanonicalError::from)
            .map_err(FinishError::from)?;
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
        let task = self.task.task(&task_id).ok_or_else(|| {
            FinishAttemptError::Serialization(format!(
                "canonical task {} is absent",
                task_id.as_str()
            ))
        })?;
        // The current task revision is the live task-lifecycle owner record's
        // revision, not `fence.task_revision` (structurally `None` on the
        // production Kernel-generation fence) and not the draft's claim. The
        // draft's `expected_task_revision` is the candidate's stale-write guard
        // and is compared against that owner-resolved value.
        if task.revision != draft.expected_task_revision {
            return Err(
                FinishError::Canonical(eliot_canonical::CanonicalError::StaleTaskRevision).into(),
            );
        }
        validate_task(task, &fence)?;
        let plan = self.canonical.read_current_plan(&fence)?;
        if plan.task_id != task_id {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical task does not match the current canonical plan".to_owned(),
            )));
        }
        let produced = self.produce_finish_evidence(
            &task_id,
            task,
            &fence,
            &plan,
            (
                &draft.artifact_refs,
                &draft.observation_refs,
                &draft.verifier_run_refs,
            ),
            contract_acceptance_set,
        )?;
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
            evidence_operation,
            &produced.snapshot,
            produced.canonical.evidence.current_task_revision,
        )?;
        prepare_exchange(self.canonical, &evidence_identity, envelope).map(Some)
    }

    /// Rehydrates and evaluates one candidate against canonical owner state,
    /// returning the decision and the exact exchange it still owes.
    ///
    /// The attempt identity is the admitted idempotency identity.  Public
    /// callers provide only the draft; closure intent is a fail-closed owner
    /// mapping, and evidence comes exclusively from the canonical owner.
    ///
    /// Evaluation is pure — it runs the existing finish service against a
    /// scratch clone — so the whole derivation completes with no composition
    /// borrow held across a Kernel exchange. A retained decision replays with
    /// no exchange owed.
    #[allow(
        clippy::too_many_lines,
        reason = "finish admission keeps its canonical evidence and change-monitor gates together"
    )]
    pub fn prepare_finish_decision(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        draft: FinishAttemptDraft,
    ) -> Result<PreparedFinishDecision, FinishAttemptError> {
        validate_identity(identity)?;
        draft
            .validate()
            .map_err(eliot_canonical::CanonicalError::from)
            .map_err(FinishError::from)?;
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
        let task = self.task.task(&task_id).ok_or_else(|| {
            FinishAttemptError::Serialization(format!(
                "canonical task {} is absent",
                task_id.as_str()
            ))
        })?;
        // Same owner-resolved revision as the evidence leg: the live
        // task-lifecycle record, with the draft's claim checked against it.
        if task.revision != draft.expected_task_revision {
            return Err(
                FinishError::Canonical(eliot_canonical::CanonicalError::StaleTaskRevision).into(),
            );
        }
        validate_task(task, &fence)?;
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
        if self.change_monitor.has_pending_hints() {
            return Err(FinishAttemptError::UnverifiedChangeHint);
        }
        if self.change_monitor.has_unknown_material_change() {
            return Err(FinishAttemptError::UnreconciledMaterialChange);
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
            FinishAdmission::Replayed { receipt } => {
                return Ok(PreparedFinishDecision {
                    decision: receipt,
                    exchange: None,
                });
            }
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
            context.current_task_revision,
        )?;
        let exchange = prepare_exchange(self.canonical, identity, envelope)?;
        Ok(PreparedFinishDecision {
            decision: receipt,
            exchange: Some(exchange),
        })
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

/// Proves the live task-lifecycle record belongs to this exact fence and holds
/// a real current revision.
///
/// The revision itself is the owner record's own value: the caller does not
/// supply it and the transport fence does not carry it, so this proves fence
/// identity only and refuses a zero revision. Callers compare the owner value
/// against their candidate's `expected_task_revision` themselves.
fn validate_task(task: &TaskRecord, fence: &StateFence) -> Result<(), FinishAttemptError> {
    if task.state_fence != *fence {
        return Err(FinishError::FenceMismatch.into());
    }
    if task.revision == 0 {
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

fn canonical_owner_snapshot_envelope(
    identity: &RequestIdentity,
    operation_id: OperationId,
    snapshot: &CanonicalAdmissionSnapshot,
    task_id: &str,
    task_revision: u64,
    required_proof_ref: &str,
) -> Result<CanonicalWriteEnvelope, FinishAttemptError> {
    let snapshot_bytes = canonical_json_bytes(snapshot)
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let snapshot_json = String::from_utf8(snapshot_bytes.clone())
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let expected_canonical_revision = snapshot.owner_revision.checked_sub(1).ok_or_else(|| {
        FinishAttemptError::Serialization(
            "canonical owner snapshot has no CAS predecessor".to_owned(),
        )
    })?;
    if task_id.trim().is_empty() || required_proof_ref.trim().is_empty() {
        return Err(FinishAttemptError::Serialization(
            "canonical owner snapshot has an empty task/proof binding".to_owned(),
        ));
    }
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "expected_canonical_revision".to_owned(),
        serde_json::Value::String(expected_canonical_revision.to_string()),
    );
    parameters.insert(
        "snapshot_json".to_owned(),
        serde_json::Value::String(snapshot_json),
    );
    if task_revision == 0 {
        return Err(FinishAttemptError::Serialization(
            "canonical owner snapshot has no admitted task revision".to_owned(),
        ));
    }
    parameters.insert(
        "task_revision".to_owned(),
        serde_json::Value::String(task_revision.to_string()),
    );
    let scope_id = ScopeId::new(GOVERNOR_SCOPE_ID)
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    Ok(CanonicalWriteEnvelope {
        operation_id,
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id,
        task_id: Some(task_id.to_owned()),
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: eliot_canonical::supported_admission_contract_set_digest()
            .map_err(|error| {
            FinishAttemptError::Composition(CompositionError::Canonical(error))
        })?,
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
        required_proof_and_approval_refs: vec![required_proof_ref.to_owned()],
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    })
}

/// Builds the envelope that publishes a current-plan owner image.
///
/// This deliberately reuses [`canonical_owner_snapshot_envelope`] and therefore
/// the same activated `RecordFinishEvidence` mutation, for the same reason the
/// store keeps that image opaque: `owner/canonical` holds exactly one
/// `CanonicalAdmissionSnapshot`, and `current_plan` is one field of it. A
/// separate mutation would arbitrate the same `owner/canonical` revision head
/// with a second name for the same row, which is precisely the second scheme
/// this must not introduce. The store applies the identical fenced revision CAS
/// over the identical opaque `snapshot_json`, so the plan image commits
/// atomically and is read back by the same owner recovery that every other
/// canonical leg uses.
///
/// The proof handle is a digest over the exact admitted plan binding, so the
/// published image is content-bound to the plan it admits rather than to a
/// restated label.
pub(crate) fn current_plan_envelope(
    identity: &RequestIdentity,
    operation_id: &OperationId,
    snapshot: &CanonicalAdmissionSnapshot,
    task_id: &TaskId,
    task_revision: u64,
) -> Result<CanonicalWriteEnvelope, FinishAttemptError> {
    let plan = snapshot.current_plan.as_ref().ok_or_else(|| {
        FinishAttemptError::Serialization(
            "current-plan envelope cannot publish an absent plan owner".to_owned(),
        )
    })?;
    if plan.task_id != *task_id {
        return Err(FinishAttemptError::Serialization(
            "current-plan envelope names another task than the admitted one".to_owned(),
        ));
    }
    let plan_digest = sha256_hex(
        &canonical_json_bytes(plan)
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?,
    );
    canonical_owner_snapshot_envelope(
        identity,
        operation_id.clone(),
        snapshot,
        task_id.as_str(),
        task_revision,
        &format!("current-plan:{plan_digest}"),
    )
}

fn finish_evidence_envelope(
    identity: &RequestIdentity,
    operation_id: OperationId,
    snapshot: &CanonicalAdmissionSnapshot,
    task_revision: u64,
) -> Result<CanonicalWriteEnvelope, FinishAttemptError> {
    let evidence = snapshot.finish_evidence.as_ref().ok_or_else(|| {
        FinishAttemptError::Serialization(
            "finish-evidence envelope cannot publish an absent evidence owner".to_owned(),
        )
    })?;
    canonical_owner_snapshot_envelope(
        identity,
        operation_id,
        snapshot,
        &evidence.evidence.task_id,
        task_revision,
        &evidence.finish_authority_ref,
    )
}

fn finish_envelope(
    identity: &RequestIdentity,
    operation_id: OperationId,
    attempt: &FinishAttempt,
    context: &FinishContext,
    receipts: &[FinishDecisionReceipt],
    expected_finish_revision: u64,
    task_revision: u64,
) -> Result<CanonicalWriteEnvelope, FinishAttemptError> {
    let receipt_bytes = canonical_json_bytes(&receipts)
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let receipt_json = String::from_utf8(receipt_bytes.clone())
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let contract_bytes = canonical_json_bytes(&(attempt, context, receipts))
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let contract_digest = sha256_hex(&contract_bytes);
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
    if task_revision == 0 {
        return Err(FinishAttemptError::Serialization(
            "finish decision has no admitted task revision".to_owned(),
        ));
    }
    parameters.insert(
        "task_revision".to_owned(),
        serde_json::Value::String(task_revision.to_string()),
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
        admission_contract_set_digest: eliot_canonical::supported_admission_contract_set_digest()
            .map_err(|error| {
            FinishAttemptError::Composition(CompositionError::Canonical(error))
        })?,
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
        required_proof_and_approval_refs: vec![
            context.finish_authority_ref.clone(),
            contract_digest,
        ],
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
