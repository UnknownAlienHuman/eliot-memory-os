//! Authenticated `TestD` terminal handoff into the canonical Governor owner.
//!
//! The `TestD` transport carries only a durable job id and finish-receipt
//! digest. This module rehydrates request identity, operation, task revision,
//! and the exact pre-dispatch canonical verifier plan from the `TestD` owner,
//! then re-reads the current Governor plan before publishing.

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{OperationId, TaskId, canonical_json_bytes};
use eliot_governor::{
    CanonicalPlanBinding, FinishAttemptDraft, PreparedFinishDecision, PreparedKernelExchange,
};
use eliot_instrument_api::InstrumentInvocation;
use eliot_protocol::RequestIdentity;
use eliot_store_api::{WriteReceipt, WriteReceiptStatus};
use eliot_testd_core::{
    JobState as TestdJobState, TestJob, TestdPendingVerifierDispatch, TestdStore,
    TestdTerminalCompletionEvidence, TestdTerminalCompletionNotice, TestdVerifierDispatchBinding,
    verification_receipt_sha256,
};

use crate::daemon_kernel_client::TESTD_OWNER_POLL_LIMIT;
use crate::{DaemonComposition, DaemonError, DaemonKernelClient};

/// The shared `TestD` owner composition. Named here so the terminal completion
/// seam can be driven from [`commit_testd_terminal_owner_fact`] without the
/// drain holding a guard across an exchange.
type SharedTestdOwnerComposition = std::sync::Arc<tokio::sync::Mutex<DaemonComposition>>;

fn completion_error(error: impl std::fmt::Display) -> DaemonError {
    DaemonError::Lifecycle(format!("TestD terminal completion: {error}"))
}

/// Denies one terminal material commit when the admitted identity carries no
/// task (issue #1789 A1, task-binding leg production consult).
///
/// Both terminal legs publish canonical Material effects, so the task-binding
/// leg of the material-readiness gate is enforced with the gate's own typed
/// directive before anything launches. This mirrors the full evaluator's
/// no-task verdict (`TASK_SELECTION_REQUIRED`, missing
/// `current_task_contract`); the remaining legs (coverage, truth surface,
/// verifier, authority route, lease, guard currency) have no production
/// producer yet and stay with the existing authorities (admitted identity,
/// task owner, `#1787` guard).
fn no_task_material_denial(context: &str) -> DaemonError {
    completion_error(format!(
        "material readiness denies {context}: {}; missing: current_task_contract",
        eliot_workscope::MaterialReadinessDirective::TaskSelectionRequired.kind_str()
    ))
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| {
            u64::try_from(duration.as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX)
        })
}

impl DaemonComposition {
    /// Captures the current canonical verifier plan with its admitted owner
    /// identity. Call this before inserting/dispatching the productive `TestD`
    /// job; the returned binding is persisted in the durable `TestD` row.
    pub fn testd_verifier_dispatch_binding(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        task_id: &TaskId,
        task_revision: u64,
        invocation: &InstrumentInvocation,
    ) -> Result<TestdVerifierDispatchBinding, DaemonError> {
        identity.validate().map_err(completion_error)?;
        if identity.request.metadata.task_id.as_ref() != Some(task_id)
            || identity
                .request
                .state_fence
                .task_revision
                .as_ref()
                .map(|revision| revision.value())
                != Some(task_revision)
            || task_revision == 0
        {
            return Err(completion_error(
                "admitted identity does not bind the requested task revision",
            ));
        }
        if invocation.request != identity.request.metadata
            || invocation.request.task_id.as_ref() != Some(task_id)
            || invocation.request.state_fence != identity.request.state_fence
        {
            return Err(completion_error(
                "TestD invocation does not match the admitted request identity",
            ));
        }
        invocation.validate().map_err(completion_error)?;
        let current_task = self
            .governor
            .owners()
            .task
            .task(task_id)
            .ok_or_else(|| completion_error("canonical task owner is absent"))?;
        if current_task.revision != task_revision
            || current_task.state_fence != identity.request.state_fence
        {
            return Err(completion_error(
                "TestD invocation does not bind the current canonical task revision",
            ));
        }
        let plan = self
            .governor
            .read_current_plan(&identity.request.state_fence)
            .map_err(completion_error)?;
        plan.validate().map_err(completion_error)?;
        let verifier = plan.verifier.as_ref().ok_or_else(|| {
            completion_error("current canonical plan is missing the task-bound verifier request")
        })?;
        if plan.task_id != *task_id
            || verifier.instrument != invocation.instrument
            || verifier.kind != invocation.kind
            || verifier.profile != invocation.profile
            || verifier.target != invocation.target
            || verifier.arguments != invocation.arguments
            || verifier.declared_scope != invocation.declared_scope
            || verifier.input_artifacts != invocation.input_artifacts
        {
            return Err(completion_error(
                "TestD invocation differs from the current canonical verifier plan",
            ));
        }
        let bytes = canonical_json_bytes(&plan).map_err(completion_error)?;
        let canonical_plan_json = String::from_utf8(bytes.clone()).map_err(completion_error)?;
        Ok(TestdVerifierDispatchBinding {
            request_identity: identity.clone(),
            operation_id: operation_id.to_string(),
            canonical_plan_json,
            canonical_plan_sha256: eliot_contracts::sha256_hex(&bytes),
        })
    }

    /// Persists the admitted identity and current canonical verifier plan in
    /// the durable `TestD` row before Kernel launch. The invocation and process
    /// operation are rehydrated from the submitted `TestD` owner row; productive
    /// claims remain ineligible until this write commits.
    pub fn persist_testd_verifier_dispatch_before_launch(
        &self,
        testd: &TestdStore,
        job_id: &str,
        identity: &RequestIdentity,
    ) -> Result<TestJob, DaemonError> {
        let job = testd
            .get(job_id)
            .map_err(completion_error)?
            .ok_or_else(|| completion_error("queued TestD owner row is absent"))?;
        if job.job_id != job_id {
            return Err(completion_error(
                "TestD owner key differs from the requested dispatch job",
            ));
        }
        let task_id = identity
            .request
            .metadata
            .task_id
            .as_ref()
            .ok_or_else(|| completion_error("admitted request has no task id"))?;
        let task_revision = identity
            .request
            .state_fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value())
            .ok_or_else(|| completion_error("admitted request has no task revision"))?;
        let operation_id =
            OperationId::new(job.process.operation_id.clone()).map_err(completion_error)?;
        let binding = self.testd_verifier_dispatch_binding(
            identity,
            &operation_id,
            task_id,
            task_revision,
            &job.invocation,
        )?;
        testd
            .bind_verifier_dispatch(job_id, binding, unix_ms())
            .map_err(completion_error)
    }

    /// Consumes one pending authenticated `TestD` notification. The returned
    /// receipt is the canonical `WriteReceipt` from Governor; the durable `TestD`
    /// row is updated only after that commit has been observed.
    pub async fn publish_testd_terminal_completion(
        &self,
        notice: &TestdTerminalCompletionNotice,
        testd: &TestdStore,
    ) -> Result<WriteReceipt, DaemonError> {
        let job = testd
            .get(&notice.job_id)
            .map_err(completion_error)?
            .ok_or_else(|| completion_error("durable TestD job is absent"))?;
        let publication = job
            .terminal_publication
            .as_ref()
            .ok_or_else(|| completion_error("authenticated terminal notification is absent"))?;
        if publication.receipt_sha256 != notice.receipt_sha256 {
            return Err(completion_error(
                "terminal notification digest differs from its durable owner row",
            ));
        }
        let receipt = job
            .verification_receipt
            .as_ref()
            .ok_or_else(|| completion_error("durable finish receipt is absent"))?;
        if verification_receipt_sha256(receipt).map_err(completion_error)? != notice.receipt_sha256
        {
            return Err(completion_error(
                "terminal notification does not bind the exact durable finish receipt",
            ));
        }
        if job.lease.is_some() {
            return Err(completion_error(
                "TestD job still has an active worker lease",
            ));
        }
        let binding = job
            .verifier_dispatch
            .as_ref()
            .ok_or_else(|| completion_error("pre-dispatch Governor binding is absent"))?;
        binding.validate_for_job(&job).map_err(completion_error)?;
        let bound_plan: CanonicalPlanBinding =
            serde_json::from_str(&binding.canonical_plan_json).map_err(completion_error)?;
        bound_plan.validate().map_err(completion_error)?;
        let current_plan = self
            .governor
            .read_current_plan(&binding.request_identity.request.state_fence)
            .map_err(completion_error)?;
        if current_plan != bound_plan {
            return Err(completion_error(
                "canonical verifier plan changed after TestD dispatch",
            ));
        }
        let task_id = binding
            .request_identity
            .request
            .metadata
            .task_id
            .clone()
            .ok_or_else(|| no_task_material_denial("TestD terminal publication"))?;
        let task_revision = binding
            .request_identity
            .request
            .state_fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value())
            .ok_or_else(|| completion_error("admitted request has no task revision"))?;
        let operation_id =
            OperationId::new(binding.operation_id.clone()).map_err(completion_error)?;
        if let Some(receipt_json) = &publication.committed_receipt_json {
            let committed: WriteReceipt =
                serde_json::from_str(receipt_json).map_err(completion_error)?;
            validate_committed_receipt(&committed, binding, &operation_id)
                .map_err(completion_error)?;
            return Ok(committed);
        }
        let committed = Box::pin(self.governor.publish_testd_verifier_execution_fact(
            &binding.request_identity,
            &operation_id,
            &task_id,
            task_revision,
            &job.job_id,
            testd,
        ))
        .await
        .map_err(completion_error)?
        .ok_or_else(|| {
            completion_error(
                "Governor reported an existing verifier fact without its committed WriteReceipt",
            )
        })?;
        validate_committed_receipt(&committed, binding, &operation_id).map_err(completion_error)?;
        let bytes = canonical_json_bytes(&committed).map_err(completion_error)?;
        let receipt_json = String::from_utf8(bytes).map_err(completion_error)?;
        testd
            .record_terminal_publication_receipt(
                &job.job_id,
                &notice.receipt_sha256,
                receipt_json,
                unix_ms(),
            )
            .map_err(completion_error)?;
        Ok(committed)
    }

    /// Drains one bounded batch from the durable `TestD` terminal owner. The
    /// daemon reactive-feed owner calls this API; each item is rehydrated and
    /// committed independently before its canonical receipt is recorded.
    pub async fn publish_pending_testd_terminal_completions(
        &self,
        testd: &TestdStore,
        limit: usize,
    ) -> Result<Vec<WriteReceipt>, DaemonError> {
        let pending = testd
            .pending_terminal_publications(limit)
            .map_err(completion_error)?;
        let mut committed = Vec::with_capacity(pending.len());
        for notice in pending {
            committed.push(Box::pin(self.publish_testd_terminal_completion(&notice, testd)).await?);
        }
        Ok(committed)
    }

    /// Plans the exact owner bind payload for one pending productive dispatch:
    /// the canonical plan binding is computed from the current Governor read
    /// against the exact admitted identity.
    ///
    /// #18 item B: this leg is a pure read of the retained owners. The caller
    /// holds the composition guard only for this call and releases it before
    /// the owner bind leg crosses the Kernel, so no guard is alive across that
    /// exchange. Persisting the returned binding is
    /// [`bind_testd_owner_verifier_dispatch`]'s job, not this composition's.
    pub fn plan_testd_verifier_dispatch_binding(
        &self,
        entry: &TestdPendingVerifierDispatch,
    ) -> Result<TestdVerifierDispatchBinding, DaemonError> {
        let identity = &entry.request_identity;
        let job = &entry.job;
        let task_id = identity
            .request
            .metadata
            .task_id
            .clone()
            .ok_or_else(|| completion_error("pending dispatch has no admitted task id"))?;
        let task_revision = identity
            .request
            .state_fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value())
            .ok_or_else(|| completion_error("pending dispatch has no task revision fence"))?;
        let operation_id =
            OperationId::new(job.process.operation_id.clone()).map_err(completion_error)?;
        self.testd_verifier_dispatch_binding(
            identity,
            &operation_id,
            &task_id,
            task_revision,
            &job.invocation,
        )
    }

    /// Plans the two Governor-owned canonical legs for one terminal evidence
    /// row and returns the exact exchanges they still owe.
    ///
    /// This is the pure prepare half of the terminal finish ceremony: it reads
    /// the retained owners, derives the verifier-execution fact and the
    /// evidence-led finish candidate, and hands back the immutable transitions
    /// with the identity, operation and pre-commit fence each one binds. It
    /// performs no transport and mutates nothing, so the caller holds the
    /// composition guard for this call alone and releases it before
    /// [`exchange_testd_owner_finish_leg`].
    ///
    /// The task-binding denial stays ahead of both legs exactly as before: a
    /// missing admitted task denies the whole completion with the readiness
    /// gate's typed directive before anything launches. The finish candidate is
    /// derived here rather than after the fact leg, and that reorder is not
    /// observable: its only rejection cases are an absent task id or task
    /// revision fence and a job state that is not settled terminal, and the
    /// fact prepare already refuses exactly those rows.
    pub fn plan_testd_terminal_owner_fact(
        &self,
        evidence: &TestdTerminalCompletionEvidence,
    ) -> Result<TestdTerminalOwnerPlan, DaemonError> {
        let identity = &evidence.request_identity;
        let job = &evidence.job;
        // Issue #1789 A1: both legs below publish canonical Material effects,
        // so a missing admitted task denies the whole completion here with
        // the readiness gate's typed directive before either leg launches.
        if identity.request.metadata.task_id.is_none() {
            return Err(no_task_material_denial("TestD terminal completion"));
        }
        let draft = finish_draft_from_testd_terminal_evidence(job, identity)?;
        let operation_id = OperationId::new(format!("testd-owner-finish-{}", job.job_id))
            .map_err(completion_error)?;
        let verifier_fact = self
            .governor
            .prepare_testd_verifier_execution_fact_from_evidence(evidence)
            .map_err(DaemonError::Finish)?;
        Ok(TestdTerminalOwnerPlan {
            verifier_fact,
            finish_draft: draft,
            finish_operation_id: operation_id,
        })
    }

    /// Re-checks a completed exchange against the live canonical owner and, for
    /// the finish decision, publishes the refreshed image it was evaluated
    /// against.
    ///
    /// The prepared leg captured its owner fence before the caller began the
    /// exchange, and the exchange ran with no composition borrow, so this is
    /// where a fence that moved in the meantime refuses the leg with the
    /// Governor's own typed mismatch. Nothing is re-derived and no receipt is
    /// repaired.
    pub fn accept_testd_terminal_owner_fact(
        &self,
        prepared: &PreparedKernelExchange,
    ) -> Result<(), DaemonError> {
        self.governor
            .accept_prepared_exchange(prepared)
            .map_err(DaemonError::Finish)
    }

    /// Publishes the verifier-execution fact's owner image and derives the
    /// exact exchange that persists the finish decision for this row.
    ///
    /// The synchronous `refresh_from_kernel` runs here, under the caller's
    /// `&mut self`, because the decision must be evaluated against the
    /// canonical image the fact leg actually published and never against a
    /// pre-publish snapshot. Nothing is transported, so the guard is released
    /// again before the decision exchange.
    pub fn plan_testd_terminal_owner_finish(
        &mut self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        draft: FinishAttemptDraft,
    ) -> Result<PreparedFinishDecision, DaemonError> {
        self.governor
            .prepare_finish_decision(identity, operation_id, draft)
            .map_err(DaemonError::Finish)
    }
}

/// The two Governor-owned canonical legs planned for one terminal `TestD` row.
///
/// Each leg carries its own identity, operation binding and pre-commit fence;
/// a caller that exchanges them is running the Governor's decision, not
/// inventing one.
pub struct TestdTerminalOwnerPlan {
    /// The exchange that publishes the verifier-execution fact. `None` means
    /// the derived fact is already the current canonical owner image, so the
    /// row yields no committed verifier-execution receipt to acknowledge.
    pub verifier_fact: Option<PreparedKernelExchange>,
    /// The evidence-led finish candidate derived for this row.
    pub finish_draft: FinishAttemptDraft,
    /// The exact finish operation identity derived for this row.
    pub finish_operation_id: OperationId,
}

/// Runs one prepared Governor-owned exchange over the daemon's own Kernel port.
///
/// The port is the daemon's mechanical boundary: it applies the immutable
/// transition the Governor already derived, under the exact admitted identity,
/// and re-checks the canonical request hash before transport. Taking no
/// composition handle at all is the point — that is what lets a caller run the
/// exchange with no composition guard held.
pub async fn exchange_testd_owner_finish_leg(
    kernel: &DaemonKernelClient,
    prepared: &PreparedKernelExchange,
) -> Result<WriteReceipt, DaemonError> {
    prepared.exchange(kernel).await.map_err(completion_error)
}

/// Commits the two Governor-owned canonical legs for one terminal evidence row
/// as plan, exchange, apply.
///
/// ```text
/// publish the verifier-execution fact (rehydrate -> canonical write)
/// -> submit the finish candidate draft (rehydrate -> FinishService::evaluate -> persisted decision)
/// ```
///
/// The ceremony is now three phases, and the composition guard is alive only
/// across the two that are pure reads of the retained owners:
///
/// ```text
/// (1) guard held  — plan both legs: derive the two immutable transitions and
///                   the evidence-led candidate (no exchange);
/// (2) no guard    — publish the verifier-execution fact over the Kernel port;
/// (3) guard held  — revalidate the fact against the live owner fence, refresh,
///                   and derive the finish decision against that image;
/// (4) no guard    — persist the finish decision over the Kernel port;
/// (5) guard held  — revalidate the decision against the live owner fence;
/// (6) guard held  — commit the non-blocking learning-closure edge (phase 6,
///                   issue #1863 / I12.24): one durable AttemptLearningDelta
///                   edge per consequential attempt, read-only over the
///                   retained owner images, no transport, and never able to
///                   fail or gate the finish.
/// ```
///
/// Before the split the guard was taken once and held across every await in the
/// row, including both Kernel round trips. A `tokio::sync::MutexGuard` is
/// not reentrant and blocks every other `run_loop` arm on the same lock, so one
/// bounded drain step could stall the activation feed and the local-read poller
/// for the whole duration of a Kernel exchange. The mutual exclusion the guard
/// does provide is unchanged — each phase still runs alone, and phases (1)/(3)/
/// (5)/(6) still observe exactly the state the preceding exchange published,
/// because (3) refreshes the owner before the decision is derived and (3)/(5)
/// re-check the pre-commit fence before the receipt is admitted.
///
/// The daemon never opens the `TestD` database: the row arrives through the
/// Kernel owner poll. The candidate draft carries only the terminal job
/// identity and the evidence-led candidate outcome; the Governor rehydrates
/// canonical evidence and derives the decision, so worker success never becomes
/// a Task outcome here. A fence-moved row is refused with the Governor's typed
/// mismatch and simply rejects owner-side on the next poll.
pub async fn commit_testd_terminal_owner_fact(
    kernel: &DaemonKernelClient,
    composition: &SharedTestdOwnerComposition,
    evidence: &TestdTerminalCompletionEvidence,
) -> Result<WriteReceipt, DaemonError> {
    // (1) guard held, no exchange.
    let plan = {
        let guard = composition.lock().await;
        guard.plan_testd_terminal_owner_fact(evidence)?
    };
    let Some(fact) = plan.verifier_fact.as_ref() else {
        return Err(completion_error(
            "Governor reported a verifier fact without its committed receipt",
        ));
    };
    // (2) no guard: the verifier-execution fact exchange.
    let committed = exchange_testd_owner_finish_leg(kernel, fact).await?;
    // (3) guard held, no exchange: revalidate the fact, publish its image, and
    // derive the finish decision against that refreshed canonical owner.
    let decision = {
        let mut guard = composition.lock().await;
        guard.accept_testd_terminal_owner_fact(fact)?;
        guard.plan_testd_terminal_owner_finish(
            &evidence.request_identity,
            &plan.finish_operation_id,
            plan.finish_draft,
        )?
    };
    // (4) no guard: the finish decision exchange.
    if let Some(prepared) = decision.exchange() {
        let _receipt = exchange_testd_owner_finish_leg(kernel, prepared).await?;
        // (5) guard held, no exchange: revalidate the decision.
        let guard = composition.lock().await;
        guard.accept_testd_terminal_owner_fact(prepared)?;
    }
    let decision = decision.into_decision();
    // (6) guard held, no exchange: commit the learning-closure edge. The finish
    // decision is already durable at this point, so this phase is a pure
    // read of the retained owner images plus one in-process durable commit; it
    // cannot fail the finish and its outcome is a diagnostic, not a receipt.
    {
        let guard = composition.lock().await;
        close_terminal_attempt_learning(&guard, evidence, &decision);
    }
    Ok(committed)
}

/// Commits one durable learning-closure edge for a settled terminal attempt.
///
/// The activity identity is the instrument contract the durable terminal job
/// row recorded for the observed step, and it is the value the ordinary-read
/// exclusion is applied to: a recorded `read_file`, `read` or `grep` derives no
/// consequential boundary and commits no record.
///
/// No admission-receipt owner issues a receipt at this seam, so `None` is
/// presented to the delivery gate. That is the required outcome rather than a
/// stub: an unadmitted proposed behavioural change is not delivered to the
/// subsequent attempt, and the durable receipt records the typed refusal.
fn close_terminal_attempt_learning(
    composition: &DaemonComposition,
    evidence: &TestdTerminalCompletionEvidence,
    decision: &eliot_governor::FinishDecisionReceipt,
) {
    let activity_name = evidence.job.invocation.instrument.as_str();
    let detail = match composition.close_attempt_learning(evidence, decision, activity_name, None) {
        Ok(eliot_governor::LearningClosureOutcome::Committed(receipt)) => if receipt.delivered {
            "committed; admitted delivery surface is live"
        } else {
            "committed; unadmitted, behavioural effect withheld"
        }
        .to_owned(),
        Ok(eliot_governor::LearningClosureOutcome::NonConsequential { .. }) => {
            "no consequential boundary; no record committed".to_owned()
        }
        Err(error) => format!("closure refused: {error}"),
    };
    let _ = crate::diagnostics::ErrorRecord::of(
        crate::diagnostics::OwningComponent::DaemonRuntime,
        "learning-closure",
        &format!(
            "job {}: {detail}",
            crate::diagnostics::sanitize_identity(&evidence.job.job_id)
        ),
    )
    .emit();
}

/// Queries the Kernel-owned pending verifier dispatches for one bounded drain
/// step.
///
/// #18 item B: takes no composition handle at all, so the caller can run this
/// bounded owner poll with no guard held. Transport failure aborts the step so
/// the supervisor restarts the daemon onto a fresh handshake.
pub async fn query_testd_owner_pending_dispatches(
    kernel: &DaemonKernelClient,
) -> Result<Vec<TestdPendingVerifierDispatch>, DaemonError> {
    kernel
        .query_testd_pending_dispatches_async(TESTD_OWNER_POLL_LIMIT)
        .await
        .map_err(|error| DaemonError::Kernel(error.to_string()))
}

/// Persists one planned verifier-dispatch binding through the Kernel owner.
///
/// #18 item B: a pure Kernel exchange over the retained binding value, so the
/// caller holds no composition guard while it runs. The binding must reuse the
/// exact admitted identity the Kernel retained at job admission; anything else
/// fails closed owner-side as a binding conflict.
pub async fn bind_testd_owner_verifier_dispatch(
    kernel: &DaemonKernelClient,
    job_id: &str,
    binding: TestdVerifierDispatchBinding,
) -> Result<(), DaemonError> {
    kernel
        .acknowledge_testd_verifier_dispatch_async(job_id, binding)
        .await
        .map(|_| ())
        .map_err(|error| DaemonError::Kernel(error.to_string()))
}

/// Queries the Kernel-owned pending terminal evidence for one bounded drain
/// step. Each entry is a complete identity-joined productive terminal row still
/// missing its canonical `WriteReceipt`; worker exit alone never qualifies.
///
/// #18 item B: takes no composition handle, so the poll runs with no guard held.
pub async fn query_testd_owner_terminal_evidence(
    kernel: &DaemonKernelClient,
) -> Result<Vec<TestdTerminalCompletionEvidence>, DaemonError> {
    kernel
        .query_testd_terminal_evidence_async(TESTD_OWNER_POLL_LIMIT)
        .await
        .map_err(|error| DaemonError::Kernel(error.to_string()))
}

/// Records one committed canonical `WriteReceipt` through the Kernel owner for
/// the acknowledged terminal row.
///
/// #18 item B: a pure Kernel exchange over the committed receipt, so it runs
/// with no composition guard held. The receipt must be the exact canonical
/// bytes advertised by the terminal publication; anything else fails closed
/// owner-side. The leg is owner-side idempotent, so a repeated poll replays
/// rather than duplicates.
pub async fn ack_testd_owner_terminal_completion(
    kernel: &DaemonKernelClient,
    job_id: &str,
    receipt: WriteReceipt,
) -> Result<(), DaemonError> {
    kernel
        .acknowledge_testd_terminal_completion_async(job_id, receipt)
        .await
        .map(|_| ())
        .map_err(|error| DaemonError::Kernel(error.to_string()))
}

/// Records one poisoned or fence-moved drain row as a diagnostic.
///
/// #18 item B: the bounded step skips such a row and keeps draining, so it
/// never fails the daemon closed and is never silently discarded.
pub fn emit_testd_owner_drain_skip(job_id: &str, error: &DaemonError) {
    emit_drain_skip(job_id, error);
}

/// Outcome of one bounded `TestD` owner drain step. Every counter names work
/// the Kernel owner committed; skipped rows were recorded as diagnostics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TestdOwnerDrainOutcome {
    /// Verifier-dispatch bindings persisted through the owner bind leg.
    pub dispatch_bindings_persisted: usize,
    /// Terminal rows whose verifier fact, finish decision, and ack all
    /// committed.
    pub terminals_drained: usize,
    /// Finish decisions persisted through `FinishService::evaluate`.
    pub finish_decisions_persisted: usize,
    /// Terminal receipts acknowledged owner-side.
    pub terminals_acked: usize,
    /// Rows recorded as diagnostics and skipped this step.
    pub rows_skipped: usize,
}

/// Builds the evidence-led finish candidate for one terminal `TestD` row.
/// The requested outcome reports the terminal job state; it never promotes
/// worker success into a Task outcome — the Governor rehydrates canonical
/// evidence and derives the decision, and a candidate never asserts a
/// verifier run.
fn finish_draft_from_testd_terminal_evidence(
    job: &TestJob,
    identity: &RequestIdentity,
) -> Result<eliot_governor::FinishAttemptDraft, DaemonError> {
    let task_id = identity
        .request
        .metadata
        .task_id
        .clone()
        .ok_or_else(|| completion_error("terminal evidence has no admitted task id"))?;
    let expected_task_revision = identity
        .request
        .state_fence
        .task_revision
        .as_ref()
        .map(|revision| revision.value())
        .ok_or_else(|| completion_error("terminal evidence has no task revision fence"))?;
    let requested_outcome = match job.state {
        TestdJobState::Succeeded => eliot_governor::RequestedFinishOutcome::CompleteCandidate,
        TestdJobState::Failed => eliot_governor::RequestedFinishOutcome::FailedVerification,
        TestdJobState::Cancelled => eliot_governor::RequestedFinishOutcome::Cancelled,
        _ => {
            return Err(completion_error(
                "terminal evidence is not a settled terminal job",
            ));
        }
    };
    Ok(eliot_governor::FinishAttemptDraft {
        task_id: task_id.as_str().to_owned(),
        expected_task_revision,
        requested_outcome,
        artifact_refs: vec![job.job_id.clone(), job.process.operation_id.clone()],
        observation_refs: Vec::new(),
        // Verifier ownership remains in the canonical evidence projection;
        // a TestD terminal candidate cannot assert a verifier run.
        verifier_run_refs: Vec::new(),
        remaining_unknowns_declared_by_caller: Vec::new(),
        rationale_candidate: format!("testd-owner-terminal:{}", job.job_id),
    })
}

fn emit_drain_skip(job_id: &str, error: &DaemonError) {
    let _ = crate::diagnostics::ErrorRecord::of(
        crate::diagnostics::OwningComponent::DaemonRuntime,
        "testd-owner-drain-skip",
        &format!("job {job_id}: {error}"),
    )
    .emit();
}

fn validate_committed_receipt(
    receipt: &WriteReceipt,
    binding: &TestdVerifierDispatchBinding,
    operation_id: &OperationId,
) -> Result<(), String> {
    receipt.validate().map_err(|error| error.to_string())?;
    let expected_operation = format!("{}/verifier-execution", operation_id.as_str());
    let expected_idempotency = format!(
        "{}:verifier-execution",
        binding.request_identity.idempotency_key
    );
    if receipt.status != WriteReceiptStatus::Committed
        || receipt.operation_id.as_str() != expected_operation
        || receipt.idempotency_key != expected_idempotency
        || receipt.state_fence != binding.request_identity.request.state_fence
    {
        return Err(
            "Governor response is not the exact committed verifier WriteReceipt".to_owned(),
        );
    }
    Ok(())
}
