//! Admitted one-shot testd worker (T6-X2 slice B, issue #20).
//!
//! This module is the admitted one-shot driver for `eliot-testd`: given
//! session-bound admission material (the Kernel-issued envelope, the parsed
//! typed invocation, the concrete in-memory [`ProcessRequest`][eliot_process::ProcessRequest],
//! and the live authority epoch), it drives exactly one durable claim to a
//! deterministic disposition and returns the local status projection.
//!
//! Division of ownership (binary is I/O/lifecycle composition only):
//!
//! - Durable scheduling, leases, retry timing, and the transition journal
//!   stay owned by `eliot-testd-core` (`TestdStore`); this worker only calls
//!   `claim_next` / `finish` / `cancel` and never reimplements them. There is
//!   no second scheduler here, and no task, budget, memory, finish-authority,
//!   or canonical-write ownership: `finish` records testd-owned scheduling
//!   state, while semantic verdicts (`VerificationRun`) stay `None` because
//!   verification belongs to the verifier, not the driver.
//! - Permit sealing stays owned by `eliot-testd-core`
//!   (`issue_process_admission`); the narrow replay provider below hands back
//!   the dispatched concrete request once and mints nothing. Authority
//!   validation (envelope byte-identity, process binding, lease, contour)
//!   runs through the existing `kernel_client` read paths and
//!   `TestdComposition::start_claimed`, never through duplicated checks.
//! - Physical process mechanics stay in the shared `#100` implementation
//!   behind the existing [`ProcessExecutor`][eliot_process::ProcessExecutor]
//!   boundary. Only typed `Instrument` profiles are driven here; there is no
//!   arbitrary shell, no command construction, and no ambient
//!   argv/stdin/environment authority.
//!
//! Deterministic disposition contract:
//!
//! - `Succeeded` is local only: the durable job stops retrying and the caller
//!   receives the status projection. Nothing canonical is written; a
//!   `Succeeded` scheduling label is never promoted to a verification
//!   verdict.
//! - Executor-unknown outcomes (`UnknownOutcome` from `start` or `inspect`,
//!   or a non-terminal view at the one-shot boundary) finish as
//!   `ExecutionStatus::Unknown` with evidence, which the durable store
//!   reschedules under its bounded retry policy. The caller reconciles by
//!   exact identity and never blind-retries.
//! - A crash or restart between claim and finish leaves the lease held; the
//!   restart-safe disposition for an interrupted or undrivable claim is
//!   likewise `Unknown` with evidence, never an assumed success or failure.
//! - Foreign or stale presentations (claimed job does not bind the presented
//!   material, or the fresh seal refuses) are refused without executing and
//!   rescheduled as `Unknown` with the refusal reason, so the lease is always
//!   released and no claim is ever orphaned by this worker.
//! - Cancelled presentations project cancellation through the durable store
//!   without executing.
//!
//! The caller must pass the [`TestdStore`] handle backing `composition`
//! (see [`TestdComposition::store`][crate::TestdComposition::store]); claim,
//! finish, cancel, and the consuming start must observe one durable view.
//!
//! This crate takes no async runtime dependency, so the two executor awaits
//! are driven by a small std-only noop-waker driver
//! ([`block_on_one_shot`]) that resolves futures which progress without an
//! external reactor. The production dispatch launch seam owns the runtime
//! decision when the admitted drive goes live.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use eliot_instrument_api::{ExecutionStatus, KernelProcessAdmissionRequest};
use eliot_process::{
    ExitDisposition, OperationId, ProcessEvidence, ProcessExecutionError, ProcessExecutionView,
    ProcessExecutor, ProcessLifecycle, ProcessRequest,
};
use eliot_testd_core::{
    EvidenceCollector, KernelProcessAdmissionEvidence, KernelProcessAdmissionProvider, Lease,
    NormalizedEvidence, TestJob, TestdError, TestdStore, issue_process_admission,
};

use crate::kernel_client::{
    PresentedAdmission, TestdIpcError, canonical_invocation_digest,
    is_testd_diagnose_only_invocation, validate_envelope_invocation_binding,
    validate_process_binding,
};
use crate::{TestReceipt, TestdComposition};

/// Fence bound for one admitted claim, in Unix milliseconds.
///
/// The lease only fences the single consuming attempt; scheduling, backoff,
/// and retry bounds stay owned by the durable store's retry policy.
pub const ADMITTED_WORKER_LEASE_MS: u64 = 60_000;

/// Upper bound for free-form reason text recorded on durable transitions.
///
/// Reasons carry no secrets, paths, or raw output; they name the
/// deterministic rule that produced the disposition.
const MAX_REASON_CHARS: usize = 512;

/// Prefix for raw-artifact handles synthesized from inline stream previews.
///
/// Inline previews have no durable locator; the handle only keys the exact
/// retained bytes inside this shot's receipt. Resolving `Blob` /
/// `OmittedPayload` durable locators into handles is future work that changes
/// no semantics here: unresolvable streams are simply not recorded, and every
/// recorded artifact keeps exactly one normalized reference either way.
const INLINE_STREAM_HANDLE_PREFIX: &str = "testd-inline-stream";

/// Drives exactly one admitted one-shot claim to a deterministic disposition.
///
/// `presented` is the session-bound admission: envelope, parsed typed
/// invocation, concrete in-memory process request, live epoch, evidence
/// handle, and cancellation flag. Every identity-bearing value arrives with
/// the authenticated dispatch; no value is taken from argv, stdin,
/// environment, or files by this worker.
///
/// Returns the local status projection (`Succeeded` stays local, never
/// canonical). Every post-claim path finishes or cancels through the durable
/// store, so the lease is always released. Errors are fail-closed and carry
/// no raw output.
pub fn drive_admitted_one_shot<E: ProcessExecutor + 'static>(
    composition: &TestdComposition,
    store: &TestdStore,
    presented: PresentedAdmission,
    executor: &E,
    owner: &str,
    lease_ms: u64,
    now: u64,
) -> Result<TestReceipt, TestdError> {
    validate_envelope_invocation_binding(&presented.request, &presented.invocation)
        .map_err(|error| ipc_to_contract(&error))?;
    if is_testd_diagnose_only_invocation(&presented.invocation) {
        return Err(TestdError::Contract(
            "testd worker admits only TEST invocations; diagnose-only presentations never execute"
                .to_owned(),
        ));
    }
    // Closed-profile Drive gate (issue #20): only the admitted tool-probe
    // profile drives, and it takes no caller arguments: the fixed argv
    // comes from the registry binding, never from the invocation.
    if !eliot_testd_core::is_admitted_testd_profile(&presented.invocation.profile) {
        return Err(TestdError::Contract(
            "testd admits only the closed cargo-test tool-probe profile".to_owned(),
        ));
    }
    if !presented.invocation.arguments.is_empty() {
        return Err(TestdError::Contract(
            "the admitted profile takes fixed argv; caller arguments are refused".to_owned(),
        ));
    }
    if !presented
        .epoch
        .is_same_authority(&presented.request.authority_epoch)
    {
        return Err(TestdError::Contract(
            "presented live epoch disagrees with the envelope epoch; stale or foreign admission"
                .to_owned(),
        ));
    }
    validate_process_binding(
        &presented.process,
        &presented.invocation,
        &presented.epoch,
        presented.request.generation,
    )
    .map_err(|error| ipc_to_contract(&error))?;
    let claimed = store.claim_next(owner, now, lease_ms)?;
    let job = claimed.ok_or_else(|| {
        TestdError::Contract(
            "no claimable test job for the admitted presentation; nothing was executed".to_owned(),
        )
    })?;
    let lease = job
        .lease
        .clone()
        .ok_or_else(|| TestdError::Corrupt("claimed job carries no lease".to_owned()))?;
    drive_claimed(
        composition,
        store,
        &job,
        &lease,
        presented,
        executor,
        owner,
        now,
    )
}

/// Drives one claimed job against the presented admission to a deterministic
/// disposition. The job is already leased to this shot; every path below ends
/// in `finish` or `cancel` so the lease is always released.
#[allow(
    clippy::too_many_arguments,
    reason = "DISPATCH-LIVE residual: one admitted-shot context (composition, store, job, lease, presented material, executor, owner, now); a params-struct refactor is deferred until the dispatch-launch seam fixes the call shape, never a bare allow"
)]
fn drive_claimed<E: ProcessExecutor + 'static>(
    composition: &TestdComposition,
    store: &TestdStore,
    job: &TestJob,
    lease: &Lease,
    presented: PresentedAdmission,
    executor: &E,
    owner: &str,
    now: u64,
) -> Result<TestReceipt, TestdError> {
    if let Err(binding) = check_presented_job_binding(job, &presented) {
        finish_unknown(
            store,
            job,
            lease,
            &EvidenceCollector::default(),
            now,
            format!("refused foreign or stale presentation without executing: {binding}"),
        )?;
        return composition.status(&job.job_id);
    }
    if presented.cancelled {
        store.cancel(&job.job_id, Some(lease), owner, now)?;
        return composition.status(&job.job_id);
    }
    // Fresh bound admission: rebuild the Kernel request from the CLAIMED
    // durable job and seal it with the single-use replay of the presented
    // concrete process. The durable roots are canonical strings and the seal
    // plus `start_claimed` compare exact strings, so every party (submitter,
    // issuer, and this drive) must seal the canonical form; deterministic
    // re-issuance then reproduces the persisted invocation digest, which
    // `start_claimed` re-proves. Any mismatch fails closed inside the seal
    // and never executes.
    let admission_request = KernelProcessAdmissionRequest {
        job_id: job.job_id.clone(),
        project_id: job.project_id.clone(),
        invocation: job.invocation.clone(),
        source_root: job.target_roots.source_root.clone(),
        target_root: job.target_roots.target_root.clone(),
        cache_root: job.target_roots.cache_root.clone(),
    };
    // The inspected identity below is the presented operation, never a guess;
    // capture it before the concrete request moves into the single-use seal.
    let operation_id = presented.process.operation_id().clone();
    let evidence_ref = presented.evidence_ref.clone();
    let provider = PresentedProcessProvider::single_use(
        presented.process,
        job.target_roots.allowed_contour_root.clone(),
        evidence_ref,
    );
    let permit = match issue_process_admission(&provider, &admission_request) {
        Ok(permit) => permit,
        Err(error) => {
            finish_unknown(
                store,
                job,
                lease,
                &EvidenceCollector::default(),
                now,
                format!("fresh admission refused without executing: {error}"),
            )?;
            return composition.status(&job.job_id);
        }
    };
    let collector = Arc::new(EvidenceCollector::default());
    let sink: Arc<dyn eliot_process::ProcessEvidenceSink> = collector.clone();
    // The consuming start proves nothing about the outcome by itself:
    // `start_claimed` maps every executor failure (including the
    // executor-owned `UnknownOutcome`) onto `TestdError`, so the single
    // `inspect` in `observe_and_finish` is the only observation that
    // dispositions the attempt.
    let start_result =
        block_on_one_shot(composition.start_claimed(job, lease, now, permit, executor, sink));
    let start_note = match &start_result {
        Ok(_) => None,
        Err(error) => Some(truncate_reason(error.to_string())),
    };
    observe_and_finish(
        store,
        job,
        lease,
        executor,
        &collector,
        operation_id,
        start_note,
        now,
    )?;
    composition.status(&job.job_id)
}

/// Observes the started operation exactly once and finishes the attempt with
/// the deterministic disposition plus captured evidence.
///
/// The observation is one `inspect` of the presented operation: a clean exit
/// completes locally, cancellation cancels, and anything without terminal
/// proof (executor-unknown, failed observation, or a still-running view at
/// the one-shot boundary) finishes as `Unknown` with evidence so the exact
/// identity reconciles later under the bounded retry policy.
#[allow(
    clippy::too_many_arguments,
    reason = "DISPATCH-LIVE residual: one observation context (store, job, lease, executor, collector, operation, start note, now); a params-struct refactor is deferred until the dispatch-launch seam fixes the call shape, never a bare allow"
)]
fn observe_and_finish<E: ProcessExecutor + 'static>(
    store: &TestdStore,
    job: &TestJob,
    lease: &Lease,
    executor: &E,
    collector: &EvidenceCollector,
    operation_id: OperationId,
    start_note: Option<String>,
    now: u64,
) -> Result<(), TestdError> {
    let observed = block_on_one_shot(executor.inspect(operation_id));
    let (execution, reason) = match (&observed, start_note) {
        (Ok(view), _) => (
            classify_observation(view),
            observation_reason(view).to_owned(),
        ),
        (Err(ProcessExecutionError::UnknownOutcome), _) => (
            ExecutionStatus::Unknown,
            "observation returned UnknownOutcome; reconcile by exact identity, never blind-retry"
                .to_owned(),
        ),
        (Err(error), Some(note)) => (
            ExecutionStatus::Unknown,
            format!(
                "consuming start failed ({note}); observation also failed ({error}) so the outcome is unproven; reconcile by exact identity"
            ),
        ),
        (Err(error), None) => (
            ExecutionStatus::Unknown,
            format!(
                "observation failed ({error}) so the outcome is unproven; reconcile by exact identity"
            ),
        ),
    };
    let records = collector.snapshot();
    let synthetic = match capture_inline_previews(collector, &records) {
        Ok(synthetic) => synthetic,
        Err(error) => {
            finish_unknown(
                store,
                job,
                lease,
                collector,
                now,
                format!(
                    "raw capture failed after execution; outcome rescheduled as unknown: {error}"
                ),
            )?;
            return Ok(());
        }
    };
    let mut receipt = collector.verification_receipt(job, execution);
    for handle in &synthetic {
        receipt.normalized.push(NormalizedEvidence {
            kind: "process.observation".to_owned(),
            summary: format!("one-shot worker observed inline stream {handle}"),
            raw_handles: vec![handle.clone()],
            execution,
        });
    }
    if receipt.validate(job).is_err() {
        finish_unknown(
            store,
            job,
            lease,
            &EvidenceCollector::default(),
            now,
            "enriched receipt failed validation; outcome rescheduled as unknown without evidence promotion"
                .to_owned(),
        )?;
        return Ok(());
    }
    store.finish(
        &job.job_id,
        lease,
        execution,
        None,
        &receipt,
        now,
        Some(truncate_reason(reason)),
    )?;
    Ok(())
}

/// Checks that the claimed durable job is exactly the presented admission.
///
/// Identity is (`job_id`, canonical invocation digest over the exact
/// presented bytes, authority epoch exact tuple, generation, operation and
/// tree binding of the concrete process). Bare paths, PIDs, and service
/// names are never identity. Any mismatch refuses without executing.
fn check_presented_job_binding(
    job: &TestJob,
    presented: &PresentedAdmission,
) -> Result<(), String> {
    if job.job_id != presented.request.job_id {
        return Err("claimed job identity differs from the presented job".to_owned());
    }
    let digest = canonical_invocation_digest(&job.invocation)
        .map_err(|error| format!("cannot canonicalize claimed invocation: {error}"))?;
    if digest != presented.request.invocation_digest {
        return Err("claimed invocation bytes differ from the presented envelope".to_owned());
    }
    if !job
        .process
        .authority_epoch
        .is_same_authority(&presented.epoch)
    {
        return Err("claimed authority epoch disagrees with the live epoch".to_owned());
    }
    if job.process.generation != presented.request.generation {
        return Err("claimed generation disagrees with the presented generation".to_owned());
    }
    if job.process.operation_id != presented.process.operation_id().as_str() {
        return Err("claimed operation disagrees with the presented process".to_owned());
    }
    if job.process.process_tree_id != presented.process.process_tree_id().as_str() {
        return Err("claimed process tree disagrees with the presented process".to_owned());
    }
    Ok(())
}

/// Maps one observed execution view to the deterministic durable status.
///
/// Only a cleanly exited process completes locally; an exit observed under
/// cancellation cancels; anything without terminal proof (including a still
/// running view at the one-shot boundary, or an owner-foreign lifecycle)
/// stays `Unknown` so the exact identity reconciles later. Semantic
/// pass/fail of the test profile itself belongs to verifier evidence, never
/// to this physical mapping.
fn classify_observation(view: &ProcessExecutionView) -> ExecutionStatus {
    match view.lifecycle() {
        ProcessLifecycle::Exited => match view.exit() {
            Some(status) if status.disposition() == ExitDisposition::Completed => {
                ExecutionStatus::Succeeded
            }
            Some(status) if status.disposition() == ExitDisposition::Cancelled => {
                ExecutionStatus::Cancelled
            }
            _ => ExecutionStatus::Failed,
        },
        ProcessLifecycle::Failed => ExecutionStatus::Failed,
        ProcessLifecycle::Cancelling => ExecutionStatus::Cancelled,
        ProcessLifecycle::UnknownOutcome
        | ProcessLifecycle::Created
        | ProcessLifecycle::Starting
        | ProcessLifecycle::Running
        | ProcessLifecycle::Reconciled
        | ProcessLifecycle::Quarantined => ExecutionStatus::Unknown,
    }
}

/// Names the deterministic rule behind one observed execution status for the
/// durable transition journal. Carries no secrets, paths, or raw output.
fn observation_reason(view: &ProcessExecutionView) -> &'static str {
    match classify_observation(view) {
        ExecutionStatus::Succeeded => "one-shot admitted drive observed clean process exit",
        ExecutionStatus::Failed => "one-shot admitted drive observed process failure",
        ExecutionStatus::Cancelled => "one-shot admitted drive observed cancellation",
        ExecutionStatus::Unknown => {
            "one-shot admitted drive left the outcome unknown; reconcile by exact identity"
        }
        ExecutionStatus::Accepted
        | ExecutionStatus::Running
        | ExecutionStatus::Partial
        | ExecutionStatus::Blocked => {
            "one-shot admitted drive mapped a non-terminal observation without effect"
        }
    }
}

/// Captures inline stream previews observed on the evidence sink as raw
/// artifacts, preserving the exact bytes plus the truncated flag.
///
/// Raw capture is bytes-first: the digest stored with each artifact is always
/// over the retained bytes, never over handle text. Streams with no retained
/// bytes and no truncation carry nothing and are skipped; streams whose bytes
/// live behind a durable `Blob` / omitted locator (or are withheld by
/// policy) are left for future handle resolution and change no semantics.
/// Returns the synthesized handles so the caller can reference each exactly
/// once from normalized evidence.
fn capture_inline_previews(
    collector: &EvidenceCollector,
    records: &[ProcessEvidence],
) -> Result<Vec<String>, TestdError> {
    let mut synthetic = Vec::new();
    for (index, record) in records.iter().enumerate() {
        for (stream, evidence) in [("stdout", record.stdout()), ("stderr", record.stderr())]
            .into_iter()
            .filter_map(|(stream, evidence)| evidence.map(|evidence| (stream, evidence)))
        {
            let preview = evidence.preview();
            let bytes = preview.bytes();
            if bytes.is_empty() && !preview.is_truncated() {
                continue;
            }
            let handle = match evidence.legacy_reference() {
                Some(reference) => reference.to_owned(),
                None => format!("{INLINE_STREAM_HANDLE_PREFIX}-{index}-{stream}"),
            };
            collector.record_raw_artifact(
                handle.clone(),
                "application/octet-stream",
                bytes.to_vec(),
                preview.is_truncated(),
            )?;
            if evidence.legacy_reference().is_none() {
                synthetic.push(handle);
            }
        }
    }
    Ok(synthetic)
}

/// Finishes one claimed attempt as `Unknown` with the evidence captured so
/// far, for refusal, interruption, and unprovable-outcome paths.
///
/// The durable store reschedules under its bounded retry policy; the caller
/// reconciles by exact identity and never blind-retries.
fn finish_unknown(
    store: &TestdStore,
    job: &TestJob,
    lease: &Lease,
    collector: &EvidenceCollector,
    now: u64,
    reason: String,
) -> Result<(), TestdError> {
    let receipt = collector.verification_receipt(job, ExecutionStatus::Unknown);
    store.finish(
        &job.job_id,
        lease,
        ExecutionStatus::Unknown,
        None,
        &receipt,
        now,
        Some(truncate_reason(reason)),
    )?;
    Ok(())
}

/// Bounds free-form reason text kept on durable transitions.
fn truncate_reason(reason: String) -> String {
    if reason.chars().count() > MAX_REASON_CHARS {
        reason.chars().take(MAX_REASON_CHARS).collect()
    } else {
        reason
    }
}

/// Maps a transport-layer admission failure onto the durable error surface
/// without inventing authority or success.
fn ipc_to_contract(error: &TestdIpcError) -> TestdError {
    TestdError::Contract(truncate_reason(error.to_string()))
}

/// Single-use replay of the dispatched concrete process for the fresh-permit
/// seal.
///
/// This narrow adapter hands the in-memory [`ProcessRequest`] delivered with
/// the dispatch back to [`issue_process_admission`], which performs the
/// private grant sealing and every binding check. It mints no authority,
/// admits no second attempt (the request is consumed on first use), and
/// invents no contour: the contour root is the claimed job's durable contour
/// and the grant handle is the presented evidence handle, so any mismatch
/// with the fresh Kernel request fails closed inside the seal.
struct PresentedProcessProvider {
    process: Mutex<Option<ProcessRequest>>,
    contour_root: String,
    grant_id: String,
}

impl PresentedProcessProvider {
    /// Seeds the single consuming admission from dispatched material.
    fn single_use(process: ProcessRequest, contour_root: String, grant_id: String) -> Self {
        Self {
            process: Mutex::new(Some(process)),
            contour_root,
            grant_id,
        }
    }
}

impl KernelProcessAdmissionProvider for PresentedProcessProvider {
    fn admit(
        &self,
        _request: &KernelProcessAdmissionRequest,
    ) -> Result<KernelProcessAdmissionEvidence, TestdError> {
        let process = self
            .process
            .lock()
            .map_err(|_| TestdError::Contract("presented admission lock failed".to_owned()))?
            .take()
            .ok_or_else(|| {
                TestdError::Contract(
                    "presented process was already consumed; one attempt consumes exactly one admission"
                        .to_owned(),
                )
            })?;
        Ok(KernelProcessAdmissionEvidence {
            process,
            contour_root: self.contour_root.clone(),
            grant_id: self.grant_id.clone(),
        })
    }
}

/// Minimal std-only driver for futures that resolve without an external
/// reactor.
///
/// Built on the stable [`Waker::noop`] waker, so no unsafe is required.
/// Test doubles resolve on the first poll; the production dispatch launch
/// seam owns the runtime decision before the admitted drive goes live, so
/// this never spins on reactor-backed work today.
fn block_on_one_shot<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut pinned = Box::pin(future);
    loop {
        match pinned.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}
