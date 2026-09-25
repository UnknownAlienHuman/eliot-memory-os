//! Authenticated `TestD` terminal handoff into the canonical Governor owner.
//!
//! The `TestD` transport carries only a durable job id and finish-receipt
//! digest. This module rehydrates request identity, operation, task revision,
//! and the exact pre-dispatch canonical verifier plan from the `TestD` owner,
//! then re-reads the current Governor plan before publishing.

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{OperationId, TaskId, canonical_json_bytes};
use eliot_governor::CanonicalPlanBinding;
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

    /// Commits the two Governor-owned canonical legs for one terminal evidence
    /// row: publishes the verifier-execution fact and submits the evidence-led
    /// finish candidate through the Governor production caller. The returned
    /// [`WriteReceipt`] is the committed verifier-execution receipt the owner
    /// ack leg must carry.
    ///
    /// ```text
    /// publish the verifier-execution fact (rehydrate -> canonical write)
    /// -> submit the finish candidate draft (rehydrate -> FinishService::evaluate -> persisted decision)
    /// ```
    ///
    /// The daemon never opens the `TestD` database: the row arrives through the
    /// Kernel owner poll. The candidate draft carries only the terminal job
    /// identity and the evidence-led candidate outcome; the Governor rehydrates
    /// canonical evidence and derives the decision, so worker success never
    /// becomes a Task outcome here.
    ///
    /// #18 item B: these two legs are the one place the drain still holds the
    /// composition guard across a Kernel exchange. Both are `&mut
    /// GovernorComposition` operations on the single Governor owner — the fact
    /// publication rehydrates the retained owner state and the finish decision
    /// refreshes it — so they are reachable only through this guard; moving
    /// them out would require a second handle to that owner. They stay one
    /// contiguous, per-row phase. The caller acknowledges the terminal through
    /// [`ack_testd_owner_terminal_completion`] with no guard held, and a
    /// fence-moved row simply rejects owner-side on the next poll.
    pub async fn commit_testd_terminal_owner_fact(
        &mut self,
        evidence: &TestdTerminalCompletionEvidence,
    ) -> Result<WriteReceipt, DaemonError> {
        let identity = &evidence.request_identity;
        let job = &evidence.job;
        // Issue #1789 A1: both legs below publish canonical Material effects,
        // so a missing admitted task denies the whole completion here with
        // the readiness gate's typed directive before either leg launches.
        if identity.request.metadata.task_id.is_none() {
            return Err(no_task_material_denial("TestD terminal completion"));
        }
        // Boxed: the committed receipt carries the full issue-#18 digest
        // bindings and is held across the finish await, so keeping it inline
        // would push this future past the large-future bound. Same value, same
        // move into the caller's ack leg.
        let committed = Box::new(
            self.governor
                .publish_testd_verifier_execution_fact_from_evidence(evidence)
                .await
                .map_err(DaemonError::Finish)?
                .ok_or_else(|| {
                    completion_error(
                        "Governor reported a verifier fact without its committed receipt",
                    )
                })?,
        );
        let draft = finish_draft_from_testd_terminal_evidence(job, identity)?;
        let operation_id = OperationId::new(format!("testd-owner-finish-{}", job.job_id))
            .map_err(completion_error)?;
        let _decision = self.finish_attempt(identity, operation_id, draft).await?;
        Ok(*committed)
    }
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
