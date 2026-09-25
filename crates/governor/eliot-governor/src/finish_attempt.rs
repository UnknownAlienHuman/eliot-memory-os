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
use eliot_contracts::{
    OperationId, StateFence, TaskId, canonical_json_bytes, fences_match_exact, sha256_hex,
};
use eliot_coordination::CoordinationOwner;
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
    CanonicalAdmissionOwner, CanonicalAdmissionSnapshot, CanonicalFinishEvidence,
    CanonicalPlanBinding, CanonicalVerifierExecutionFact, CompositionError, GovernorOwners,
    KernelPortError, KernelTransitionPort, acceptance_coverage_from_verifier_fact,
    evaluate_testd_verification_current,
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
        let verifier_run_ref = verifier_fact.verification_run.run_id.to_string();
        // This fact has already been rehydrated and validated against the
        // current task, plan, fence, and durable terminal TestD receipt. A
        // failed or partial verifier is still an executed run; its outcome is
        // represented per required test below, not mislabeled as stale.

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

        let mut observation_refs = BTreeSet::new();
        for entry in self.observation.snapshot() {
            let receipt = match &entry.result {
                ObservationAdmissionResult::Accepted { receipt }
                | ObservationAdmissionResult::Replayed { receipt } => receipt,
                ObservationAdmissionResult::Rejected { .. } => continue,
            };
            if receipt.state_fence == *fence
                && receipt.task_selection.as_ref().is_some_and(|selection| {
                    selection.task_ref == task_id.as_str()
                        && selection.task_revision == task.revision
                })
                && matches_plan(receipt.plan.as_ref(), plan, fence)
            {
                receipt.validate().map_err(|error| {
                    FinishAttemptError::Composition(CompositionError::Recovery(format!(
                        "accepted task observation receipt is invalid: {error}"
                    )))
                })?;
                observation_refs.insert(receipt.record_id.clone());
            }
        }
        if observation_refs.is_empty() {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical finish evidence has no accepted task-and-plan-bound observation"
                    .to_owned(),
            )));
        }

        let acceptance = acceptance_coverage_from_verifier_fact(plan, &verifier_fact)?;
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
    /// Rehydrates and publishes the verifier-execution owner from the
    /// current durable TestD row. `job_id` is the only TestD input crossing
    /// this boundary: the row, receipt, run, canonical task, current plan,
    /// and fence are all read and joined here. A caller-held `TestJob` or
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
        task_revision: u64,
        job_id: &str,
        testd: &TestdStore,
    ) -> Result<Option<WriteReceipt>, FinishAttemptError> {
        let prepared = self.prepare_testd_verifier_execution_fact(
            identity,
            operation_id,
            task_id,
            task_revision,
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
        task_revision: u64,
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
        let expected_revision = fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value())
            .ok_or_else(|| {
                FinishAttemptError::Serialization(
                    "verifier fact request is missing its task revision fence".to_owned(),
                )
            })?;
        if expected_revision != task_revision {
            return Err(
                FinishError::Canonical(eliot_canonical::CanonicalError::StaleTaskRevision).into(),
            );
        }
        let task = self.task.task(task_id).ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(format!(
                "canonical task {} is absent",
                task_id.as_str()
            )))
        })?;
        if task.revision != task_revision || task.state_fence != fence {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical task owner is stale for verifier fact publication".to_owned(),
            )));
        }
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
        let verifier_plan = plan.verifier.as_ref().ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical plan has no verifier binding".to_owned(),
            ))
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
        let (task_id, task_revision) = evidence_task_binding(identity)?;
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
        let task = self.task.task(&task_id).ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(format!(
                "canonical task {} is absent",
                task_id.as_str()
            )))
        })?;
        if task.revision != task_revision || task.state_fence != fence {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical task owner is stale for verifier fact publication".to_owned(),
            )));
        }
        let plan = self.canonical.read_current_plan(&fence)?;
        if plan.task_id != task_id {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical verifier plan is task-mismatched".to_owned(),
            )));
        }
        let verifier_plan = plan.verifier.as_ref().ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical plan has no verifier binding".to_owned(),
            ))
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
    ) -> Result<Option<PreparedKernelExchange>, FinishAttemptError> {
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
        let envelope =
            finish_evidence_envelope(&evidence_identity, evidence_operation, &produced.snapshot)?;
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
    pub fn prepare_finish_decision(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        draft: FinishAttemptDraft,
    ) -> Result<PreparedFinishDecision, FinishAttemptError> {
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

/// Extracts the admitted task binding carried by terminal evidence: the
/// task id from request metadata and the revision from the state fence.
fn evidence_task_binding(identity: &RequestIdentity) -> Result<(TaskId, u64), FinishAttemptError> {
    let task_id = identity.request.metadata.task_id.clone().ok_or_else(|| {
        FinishAttemptError::Serialization(
            "verifier fact evidence carries no admitted task id".to_owned(),
        )
    })?;
    let task_revision = identity
        .request
        .state_fence
        .task_revision
        .as_ref()
        .map(|revision| revision.value())
        .ok_or_else(|| {
            FinishAttemptError::Serialization(
                "verifier fact evidence is missing its task revision fence".to_owned(),
            )
        })?;
    Ok((task_id, task_revision))
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

fn canonical_owner_snapshot_envelope(
    identity: &RequestIdentity,
    operation_id: OperationId,
    snapshot: &CanonicalAdmissionSnapshot,
    task_id: &str,
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
        required_proof_and_approval_refs: vec![required_proof_ref.to_owned()],
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    })
}

fn finish_evidence_envelope(
    identity: &RequestIdentity,
    operation_id: OperationId,
    snapshot: &CanonicalAdmissionSnapshot,
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
