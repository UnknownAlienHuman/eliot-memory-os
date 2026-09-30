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
use std::time::Duration;

use eliot_contracts::ClockReading;
use eliot_instrument_api::{ExecutionStatus, KernelProcessAdmissionRequest};
use eliot_process::{
    ExitDisposition, OperationId, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionView,
    ProcessExecutor, ProcessLifecycle, ProcessRequest,
};
use eliot_testd_core::{
    EvidenceCollector, JobState, KernelProcessAdmissionEvidence, KernelProcessAdmissionProvider,
    Lease, NormalizedEvidence, RawArtifactStream, SourceObservationGitPort, TestJob, TestdError,
    TestdSourceObservation, TestdSourceObservationRange, TestdStore, TestdToolObservation,
    evaluate_testd_verification, issue_process_admission,
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

/// Poll interval for the owning worker's terminal lifecycle observation.
const SUPERVISION_POLL_INTERVAL_MS: u64 = 100;
/// Bounded grace period after a deadline or durable cancellation request.
const SUPERVISION_CANCEL_GRACE_MS: u64 = 5_000;

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

/// The governed physical-process contour for one admitted shot.
///
/// The tool child and the terminal source observation are launched by the SAME
/// admitted `ProcessExecutor`, and the observation's Git port is that executor
/// itself. They are bound together here so they cannot be passed apart: a shot
/// that launched the tool under the Job Object contour but took its source
/// observation from somewhere else is exactly the bypass issue #1140 AC3
/// removes (issue #1140, AC3).
///
/// `git` is `None` only when no Git observation is available at all; every
/// productive profile then fails closed rather than falling back to an
/// ungoverned source observation.
pub struct GovernedContour<'a, E: ?Sized> {
    /// The admitted executor that owns the Job Object contour.
    executor: &'a E,
    /// The same executor, presented as the physical Git port.
    git: Option<&'a dyn SourceObservationGitPort>,
}

impl<'a, E: ?Sized> GovernedContour<'a, E> {
    /// Binds one executor as both the launch contour and the Git port.
    pub const fn new(executor: &'a E, git: Option<&'a dyn SourceObservationGitPort>) -> Self {
        Self { executor, git }
    }

    /// The admitted executor that owns the Job Object contour.
    pub const fn executor(&self) -> &'a E {
        self.executor
    }

    /// The same executor presented as the physical Git port.
    pub const fn git(&self) -> Option<&'a dyn SourceObservationGitPort> {
        self.git
    }
}

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
///
/// `contour` is the governed process contour used for BOTH the tool child and
/// the terminal source observation (issue #1140, AC3). Without its Git port
/// the finish path fails closed rather than falling back to an ungoverned
/// source observation.
pub fn drive_admitted_one_shot<E: ProcessExecutor + 'static>(
    _composition: &TestdComposition,
    store: &TestdStore,
    presented: PresentedAdmission,
    contour: &GovernedContour<'_, E>,
    owner: &str,
    lease_ms: u64,
    now: u64,
) -> Result<TestReceipt, TestdError> {
    drive_admitted_one_shot_from_store(store, presented, contour, owner, lease_ms, now)
}

/// Drives one admitted shot against the already-open canonical TestD store.
///
/// The production child uses this entry after opening the daemon-owned store;
/// it shares the exact validation, claim, supervision, and finish path with
/// the composition wrapper above.
pub(crate) fn drive_admitted_one_shot_from_store<E: ProcessExecutor + 'static>(
    store: &TestdStore,
    presented: PresentedAdmission,
    contour: &GovernedContour<'_, E>,
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
    // Profile and argv admission runs in `drive_claimed` against the shared
    // profile.rs boundary (`AdmittedStage::admit_testd_launch`), after the
    // fresh seal below binds the exact durable job. No parallel allowlist
    // is consulted here; every refusal still lands before any start.
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
    let mut lease = job
        .lease
        .clone()
        .ok_or_else(|| TestdError::Corrupt("claimed job carries no lease".to_owned()))?;
    drive_claimed(store, &job, &mut lease, presented, contour, owner, lease_ms)
}

/// Admits one freshly sealed drive claim against the shared profile.rs
/// boundary (issue #1814) before the consuming start.
///
/// The observation is built from the owner-sealed permit only: sealed
/// executable path and digest, a digest over the sealed environment, and
/// the sealed argv. No path is resolved and no file is read here — the
/// productive tool re-read below stays the file-observing check — so the
/// observation always describes exactly the request about to start. The
/// admitted stage is returned so the launch receipt records the exact
/// matched spec digest, profile revision, and parser identity/generation.
///
/// This is `pub(crate)` because `start_claimed_from_store` is the single
/// choke point that reaches `executor.start`: every launch re-admits there,
/// so no caller can start a sealed request the boundary did not admit.
pub(crate) fn admit_sealed_drive_claim(
    invocation: &eliot_instrument_api::InstrumentInvocation,
    request: &ProcessRequest,
) -> Result<eliot_instrument_runner::AdmittedStage, TestdError> {
    let environment_digest = eliot_contracts::canonical_json_bytes(request.environment())
        .map(|bytes| eliot_contracts::sha256_hex(&bytes))
        .map_err(|_| {
            TestdError::Contract("sealed tool environment does not canonicalize".to_owned())
        })?;
    let observed = eliot_instrument_runner::ResolvedExecutableIdentity::new(
        invocation.instrument.as_str(),
        request.executable().to_owned(),
        request.executable_sha256().to_owned(),
        None,
        environment_digest,
        request.argv().to_vec(),
    )
    .map_err(|error| TestdError::Contract(error.to_string()))?;
    eliot_instrument_runner::AdmittedStage::admit_testd_launch(
        invocation,
        request.argv(),
        &observed,
        None,
        eliot_testd_core::TESTD_PROFILE_REVISION,
    )
    .map_err(|error| TestdError::Contract(error.to_string()))
}

/// Drives one claimed job against the presented admission to a deterministic
/// disposition. The job is already leased to this shot; every path below ends
/// in `finish` or `cancel` so the lease is always released.
fn drive_claimed<E: ProcessExecutor + 'static>(
    store: &TestdStore,
    job: &TestJob,
    lease: &mut Lease,
    presented: PresentedAdmission,
    contour: &GovernedContour<'_, E>,
    owner: &str,
    lease_ms: u64,
) -> Result<TestReceipt, TestdError> {
    if let Err(binding) = check_presented_job_binding(job, &presented) {
        finish_unknown(
            store,
            job,
            lease,
            &EvidenceCollector::default(),
            format!("refused foreign or stale presentation without executing: {binding}"),
        )?;
        return Ok(crate::receipt(&store.get(&job.job_id)?.ok_or_else(
            || TestdError::Corrupt("job disappeared after refusal".to_owned()),
        )?));
    }
    if presented.cancelled {
        store.cancel(&job.job_id, Some(lease), owner, current_clock_ms())?;
        return Ok(crate::receipt(&store.get(&job.job_id)?.ok_or_else(
            || TestdError::Corrupt("job disappeared after cancellation".to_owned()),
        )?));
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
                format!("fresh admission refused without executing: {error}"),
            )?;
            return Ok(crate::receipt(&store.get(&job.job_id)?.ok_or_else(
                || TestdError::Corrupt("job disappeared after admission refusal".to_owned()),
            )?));
        }
    };
    // Shared admission boundary (issue #1814): the seal above proves
    // identity, fence, roots, and generation against the claimed durable
    // job; this admits the invocation against the ONE profile.rs contract
    // before any start. Refusal finishes unknown without executing, under
    // the same typed pattern as a seal refusal. The admitted stage is kept:
    // its matched spec digest, profile revision, and parser
    // identity/generation are recorded in the launch receipt below.
    let admitted = match admit_sealed_drive_claim(&job.invocation, permit.request()) {
        Ok(admitted) => admitted,
        Err(error) => {
            finish_unknown(
                store,
                job,
                lease,
                &EvidenceCollector::default(),
                format!("shared admission refused without executing: {error}"),
            )?;
            return Ok(crate::receipt(&store.get(&job.job_id)?.ok_or_else(
                || TestdError::Corrupt("job disappeared after admission refusal".to_owned()),
            )?));
        }
    };
    let collector = Arc::new(EvidenceCollector::default());
    if eliot_testd_core::is_productive_testd_profile(&job.invocation.profile) {
        let observation = match observe_tool_identity(permit.request(), &admitted) {
            Ok(observation) => observation,
            Err(error) => {
                finish_unknown(
                    store,
                    job,
                    lease,
                    &collector,
                    format!(
                        "productive tool identity was not owner-observed; no process started: {error}"
                    ),
                )?;
                return Ok(crate::receipt(&store.get(&job.job_id)?.ok_or_else(
                    || TestdError::Corrupt("job disappeared after tool observation".to_owned()),
                )?));
            }
        };
        collector.record_tool_observation(observation)?;
    }
    let sink: Arc<dyn eliot_process::ProcessEvidenceSink> = collector.clone();
    // The consuming start proves nothing about the outcome by itself:
    // `start_claimed` maps every executor failure (including the
    // executor-owned `UnknownOutcome`) onto `TestdError`, so the single
    // worker-owned `inspect` is the only observation that dispositions the
    // attempt.
    let start_result = block_on_one_shot(crate::start_claimed_from_store(
        store,
        job,
        lease,
        current_clock_ms(),
        permit,
        contour.executor(),
        sink,
    ));
    let started_at = start_result
        .as_ref()
        .ok()
        .map(|receipt| observation_clock(receipt.identity().resumed_at_unix_ms()))
        .unwrap_or_default();
    let start_note = match &start_result {
        Ok(_) => None,
        Err(error) => Some(truncate_reason(error.to_string())),
    };
    observe_and_finish(
        store,
        job,
        lease,
        contour,
        &collector,
        SupervisionInput::for_start(operation_id, start_note, lease_ms),
        started_at,
    )?;
    Ok(crate::receipt(&store.get(&job.job_id)?.ok_or_else(
        || TestdError::Corrupt("job disappeared after finish".to_owned()),
    )?))
}

/// Revalidates the exact tool identity carried by the admitted productive
/// ProcessRequest immediately before the consuming start. The resolver has
/// already selected cargo/rustc through rustup; this readback binds the
/// resulting files and nextest executable into the durable receipt.
///
/// `admitted` is the stage the shared boundary just returned for this exact
/// sealed request: its matched spec digest, profile revision, and parser
/// identity/generation are copied into the observation, never re-derived,
/// so the receipt records the generations the launch was admitted under.
fn observe_tool_identity(
    request: &ProcessRequest,
    admitted: &eliot_instrument_runner::AdmittedStage,
) -> Result<TestdToolObservation, TestdError> {
    let environment = request.environment().non_secret();
    let required = |key: &'static str| {
        environment.get(key).cloned().ok_or(TestdError::Invalid {
            field: "tool_environment",
            reason: "productive process request is missing owner-observed tool identity",
        })
    };
    let nextest_path = request.executable().to_owned();
    let nextest_sha256 = request.executable_sha256().to_owned();
    let cargo_path = required(crate::TESTD_ENV_CARGO)?;
    let cargo_sha256 = required(crate::TESTD_ENV_CARGO_SHA256)?;
    let rustc_path = required(crate::TESTD_ENV_RUSTC)?;
    let rustc_sha256 = required(crate::TESTD_ENV_RUSTC_SHA256)?;
    let selected_toolchain = required(crate::TESTD_ENV_TOOLCHAIN)?;
    let observation = TestdToolObservation {
        nextest_path,
        nextest_sha256,
        cargo_path,
        cargo_sha256,
        rustc_path,
        rustc_sha256,
        selected_toolchain,
        admitted_profile: admitted.profile.clone(),
        admitted_profile_revision: admitted.profile_revision,
        admitted_spec_digest: admitted.spec_digest.clone(),
        admitted_parser: admitted.parser.as_str().to_owned(),
        admitted_parser_generation: admitted.parser_generation,
    };
    observation.validate()?;
    for (path, expected) in [
        (
            observation.nextest_path.as_str(),
            observation.nextest_sha256.as_str(),
        ),
        (
            observation.cargo_path.as_str(),
            observation.cargo_sha256.as_str(),
        ),
        (
            observation.rustc_path.as_str(),
            observation.rustc_sha256.as_str(),
        ),
    ] {
        let bytes = std::fs::read(path).map_err(|_| TestdError::Invalid {
            field: "tool_environment",
            reason: "owner-observed tool cannot be reread before start",
        })?;
        if eliot_testd_core::sha256_hex(&bytes) != expected {
            return Err(TestdError::Invalid {
                field: "tool_environment",
                reason: "owner-observed tool changed before start",
            });
        }
    }
    Ok(observation)
}

/// Supervises the started operation to a bounded terminal observation and
/// finishes the attempt with the deterministic disposition plus captured
/// evidence.
///
/// `start` is only a resume receipt. The worker owns repeated lifecycle
/// inspection until the admitted profile deadline, renews the exact durable
/// fence while the process is live, requests cancellation once at the
/// deadline (or after a durable cancellation), and reconciles the exact
/// operation before accepting an unproven outcome. There is no second claim
/// or scheduler in this loop.
fn observe_and_finish<E: ProcessExecutor + 'static>(
    store: &TestdStore,
    job: &TestJob,
    lease: &mut Lease,
    contour: &GovernedContour<'_, E>,
    collector: &EvidenceCollector,
    supervision: SupervisionInput,
    started_at: ClockReading,
) -> Result<(), TestdError> {
    let started_at_ms = clock_ms(&started_at).unwrap_or_else(current_clock_ms);
    let lease_ms = supervision.lease_ms;
    let deadline_ms =
        started_at_ms.saturating_add(profile_wall_timeout_ms(job.invocation.profile.as_str())?);
    let outcome = supervise_operation(
        store,
        job,
        lease,
        contour.executor(),
        collector,
        SupervisionInput {
            deadline_ms,
            ..supervision
        },
    )?;

    if outcome.durable_cancelled || outcome.owner_lost {
        // A durable cancellation or a replaced fence already removed this
        // worker's write authority. Physical cancellation above is best
        // effort; this worker must never write through the cleared/replaced
        // lease.
        return Ok(());
    }
    let finish_now = current_clock_ms();
    let current = store
        .get(&job.job_id)?
        .ok_or_else(|| TestdError::Corrupt("job disappeared before finish".to_owned()))?;
    if current.state == JobState::Cancelled && current.lease.is_none() {
        return Ok(());
    }
    if current.state != JobState::Running || current.lease.as_ref() != Some(&*lease) {
        return Ok(());
    }
    if lease.expires_at_ms <= finish_now.saturating_add(SUPERVISION_POLL_INTERVAL_MS) {
        *lease = store.renew_lease(&job.job_id, &*lease, finish_now, lease_ms)?;
    }
    finish_observed_attempt(
        store,
        lease,
        contour,
        collector,
        &FinishInputs {
            claimed: job,
            observed: &current,
        },
        outcome,
        started_at,
    )
}

struct SupervisionInput {
    operation_id: OperationId,
    start_note: Option<String>,
    /// Unused by `observe_and_finish`, which derives the deadline from the
    /// claimed job's own profile; carried so one struct serves both callers.
    deadline_ms: u64,
    lease_ms: u64,
}

impl SupervisionInput {
    /// The supervision inputs a starting caller knows; the deadline is filled
    /// in by `observe_and_finish` from the job's admitted wall timeout.
    const fn for_start(
        operation_id: OperationId,
        start_note: Option<String>,
        lease_ms: u64,
    ) -> Self {
        Self {
            operation_id,
            start_note,
            deadline_ms: 0,
            lease_ms,
        }
    }
}

struct SupervisionOutcome {
    execution: ExecutionStatus,
    reason: String,
    reconcile_note: Option<String>,
    durable_cancelled: bool,
    owner_lost: bool,
}

/// Inspects and reconciles the exact operation while renewing the durable
/// lease that admitted it.
fn supervise_operation<E: ProcessExecutor + 'static>(
    store: &TestdStore,
    job: &TestJob,
    lease: &mut Lease,
    executor: &E,
    collector: &EvidenceCollector,
    input: SupervisionInput,
) -> Result<SupervisionOutcome, TestdError> {
    let SupervisionInput {
        operation_id,
        start_note,
        deadline_ms,
        lease_ms,
    } = input;
    let mut execution = ExecutionStatus::Unknown;
    let mut reason =
        "terminal observation did not prove an outcome; reconcile by exact identity".to_owned();
    let mut reconcile_note = None;
    let mut owner_lost = false;
    let mut durable_cancelled = false;
    let mut cancel_requested = false;
    let mut cancel_deadline_ms = 0_u64;

    loop {
        let observed_now = current_clock_ms();
        let current = store
            .get(&job.job_id)?
            .ok_or_else(|| TestdError::Corrupt("job disappeared during supervision".to_owned()))?;
        if current.state == JobState::Cancelled && current.lease.is_none() {
            durable_cancelled = true;
            if !cancel_requested {
                if let Err(error) = block_on_one_shot(executor.cancel(operation_id.clone())) {
                    reconcile_note = Some(format!("durable cancellation request failed: {error}"));
                }
                cancel_requested = true;
                cancel_deadline_ms = observed_now.saturating_add(SUPERVISION_CANCEL_GRACE_MS);
            }
        } else if current.state != JobState::Running || current.lease.as_ref() != Some(&*lease) {
            // A different owner or reconciler has taken the durable fence.
            // Do not cancel or overwrite that owner's process; its exact
            // identity will be reconciled by the current owner.
            owner_lost = true;
            break;
        } else if lease.expires_at_ms
            <= observed_now.saturating_add((lease_ms / 2).max(SUPERVISION_POLL_INTERVAL_MS))
        {
            *lease = store.renew_lease(&job.job_id, &*lease, observed_now, lease_ms)?;
        }

        match block_on_one_shot(executor.inspect(operation_id.clone())) {
            Ok(view) if view.lifecycle().is_terminal() => {
                execution = classify_observation(&view);
                reason = observation_reason(&view).to_owned();
                // A terminal inspect is only a lifecycle observation. The
                // executor's reconcile owner joins the real stdout/stderr
                // capture sessions and publishes typed final evidence into
                // this same collector.
                reconcile_note = reconcile_operation(executor, collector, &operation_id);
                break;
            }
            Ok(_) => {
                if !cancel_requested && observed_now >= deadline_ms {
                    if let Err(error) = block_on_one_shot(executor.cancel(operation_id.clone())) {
                        reconcile_note = Some(format!(
                            "wall deadline cancellation request failed: {error}"
                        ));
                    }
                    cancel_requested = true;
                    cancel_deadline_ms = observed_now.saturating_add(SUPERVISION_CANCEL_GRACE_MS);
                }
                if cancel_requested && observed_now >= cancel_deadline_ms {
                    reason = "bounded terminal supervision expired after cancellation; reconcile by exact identity".to_owned();
                    reconcile_note = reconcile_operation(executor, collector, &operation_id);
                    break;
                }
            }
            Err(error) => {
                execution = ExecutionStatus::Unknown;
                reason = if let Some(note) = start_note.as_deref() {
                    format!(
                        "consuming start failed ({note}); observation also failed ({error}) so the outcome is unproven; reconcile by exact identity"
                    )
                } else {
                    format!(
                        "observation failed ({error}) so the outcome is unproven; reconcile by exact identity"
                    )
                };
                reconcile_note = reconcile_operation(executor, collector, &operation_id);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(SUPERVISION_POLL_INTERVAL_MS));
    }

    Ok(SupervisionOutcome {
        execution,
        reason,
        reconcile_note,
        durable_cancelled,
        owner_lost,
    })
}

/// Takes the terminal source observation through the governed Git port.
///
/// Returns the observed range when one was taken, plus the typed fault that made
/// the attempt `Unknown` when it was not. A productive profile is never observed
/// by an ungoverned fallback: with no Git port, or with no persisted
/// pre-dispatch observation to compare against, the attempt is `Unknown` with
/// the reason recorded rather than silently unobserved (issue #1140, AC3).
fn observe_terminal_source<E: ProcessExecutor + 'static>(
    observed: &TestJob,
    contour: &GovernedContour<'_, E>,
    execution: &mut ExecutionStatus,
) -> (Option<TestdSourceObservationRange>, Option<String>) {
    if !eliot_testd_core::is_productive_testd_profile(&observed.invocation.profile) {
        return (None, None);
    }
    let Some(before) = observed.source_observation_before.as_ref() else {
        *execution = ExecutionStatus::Unknown;
        return (
            None,
            Some("productive verifier has no persisted pre-dispatch source observation".to_owned()),
        );
    };
    let Some(git) = contour.git() else {
        *execution = ExecutionStatus::Unknown;
        return (
            None,
            Some(
                "productive verifier has no governed Git port for its terminal source observation"
                    .to_owned(),
            ),
        );
    };
    match TestdSourceObservation::capture(&observed.target_roots.source_root, git) {
        Ok(after) => (
            Some(TestdSourceObservationRange {
                before: before.clone(),
                after,
            }),
            None,
        ),
        Err(error) => {
            *execution = ExecutionStatus::Unknown;
            (
                None,
                Some(format!(
                    "terminal source state was not observed after verifier execution: {error}"
                )),
            )
        }
    }
}

/// Captures terminal evidence and finishes the already-revalidated attempt.
///
/// The terminal source observation is taken through `contour`'s physical Git
/// port, the same admitted `ProcessExecutor`/Job Object contour that launched
/// the tool child (issue #1140, AC3).
///
/// The claimed job and the durable view re-read from the store beside it.
///
/// They are kept as two values on purpose: `claimed` is the job this worker
/// leased and presented, and `observed` is the store's current durable state.
/// The finish path compares them (state, lease, source observation) rather than
/// assuming the durable view still matches what was claimed.
struct FinishInputs<'a> {
    claimed: &'a TestJob,
    observed: &'a TestJob,
}

/// Finishes one observed attempt through the same governed contour that
/// launched the tool child.
///
/// The terminal source observation is taken through `contour`'s physical Git
/// port, which is the same admitted `ProcessExecutor`/Job Object contour
/// (issue #1140, AC3). A productive profile without that port is never
/// observed by an ungoverned fallback: the attempt finishes as `Unknown` with
/// the reason recorded.
fn finish_observed_attempt<E: ProcessExecutor + 'static>(
    store: &TestdStore,
    lease: &mut Lease,
    contour: &GovernedContour<'_, E>,
    collector: &EvidenceCollector,
    inputs: &FinishInputs<'_>,
    outcome: SupervisionOutcome,
    started_at: ClockReading,
) -> Result<(), TestdError> {
    let FinishInputs { claimed, observed } = *inputs;
    let SupervisionOutcome {
        mut execution,
        mut reason,
        reconcile_note,
        ..
    } = outcome;
    let finished_at = observation_clock(current_clock_ms());
    let records = collector.snapshot();
    let synthetic = match capture_inline_previews(
        collector,
        &claimed.invocation.profile,
        &records,
        finished_at,
    ) {
        Ok(synthetic) => synthetic,
        Err(error) => {
            finish_unknown(
                store,
                claimed,
                lease,
                collector,
                format!(
                    "raw capture failed after execution; outcome rescheduled as unknown: {error}"
                ),
            )?;
            return Ok(());
        }
    };
    let (source_observation, observation_fault) =
        observe_terminal_source(observed, contour, &mut execution);
    if let Some(message) = observation_fault {
        reason = message;
    }
    let mut receipt =
        collector.verification_receipt_at(claimed, execution, started_at, finished_at);
    receipt.source_observation = source_observation;
    for handle in &synthetic {
        receipt.normalized.push(NormalizedEvidence {
            kind: "process.observation".to_owned(),
            summary: format!("one-shot worker observed inline stream {handle}"),
            raw_handles: vec![handle.clone()],
            execution,
        });
    }
    if receipt.validate(claimed).is_err() {
        finish_unknown(
            store,
            claimed,
            lease,
            &EvidenceCollector::default(),
            "enriched receipt failed validation; outcome rescheduled as unknown without evidence promotion"
                .to_owned(),
        )?;
        return Ok(());
    }
    let finish_now = current_clock_ms();
    let verification = match evaluate_testd_verification(claimed, &receipt, finish_now) {
        Ok(run) => Some(run),
        Err(error) => {
            // A receipt without the raw evidence required by the verifier
            // contract remains a durable non-certifying TestD outcome. Do
            // not manufacture a semantic result from the process label.
            let _ = error;
            None
        }
    };
    let reason = match reconcile_note {
        Some(note) => format!("{}; {note}", truncate_reason(reason)),
        None => reason,
    };
    store.finish(
        &claimed.job_id,
        lease,
        execution,
        verification,
        &receipt,
        finish_now,
        Some(truncate_reason(reason)),
    )?;
    Ok(())
}

fn reconcile_operation<E: ProcessExecutor + 'static>(
    executor: &E,
    collector: &EvidenceCollector,
    operation_id: &OperationId,
) -> Option<String> {
    match block_on_one_shot(executor.reconcile(operation_id.clone())) {
        Ok(evidence) => collector
            .record(evidence)
            .err()
            .map(|error| format!("reconciliation evidence was rejected: {error}")),
        Err(error) => Some(format!("reconciliation failed: {error}")),
    }
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
    profile: &str,
    records: &[ProcessEvidence],
    captured_at: ClockReading,
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
            let handle = format!("{INLINE_STREAM_HANDLE_PREFIX}-{index}-{stream}");
            let stream_kind = if stream == "stdout" {
                RawArtifactStream::Stdout
            } else {
                RawArtifactStream::Stderr
            };
            // Content domains stay disjoint per profile: discovery
            // stdout is inventory, never run events, so it must never
            // reach the run-event parser. Literals mirror the nextest
            // owner's content-type constants without a dependency.
            let content_type = if stream_kind == RawArtifactStream::Stdout {
                if profile == eliot_testd_core::TESTD_LIST_PROFILE {
                    "application/x-nextest-list-json"
                } else {
                    "application/x-nextest-libtest-json-plus"
                }
            } else {
                "text/plain"
            };
            collector.record_raw_artifact_at(
                handle.clone(),
                content_type,
                bytes.to_vec(),
                preview.is_truncated(),
                stream_kind,
                captured_at,
            )?;
            synthetic.push(handle);
        }
    }
    Ok(synthetic)
}

fn observation_clock(now: u64) -> ClockReading {
    let now = now.min(i64::MAX as u64) as i64;
    ClockReading {
        valid_time_ms: Some(now),
        known_time_ms: Some(now),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

fn current_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn profile_wall_timeout_ms(profile: &str) -> Result<u64, TestdError> {
    match profile {
        eliot_testd_core::TESTD_ADMITTED_PROFILE => {
            Ok(eliot_testd_core::TESTD_PROFILE_WALL_TIMEOUT_MS)
        }
        eliot_testd_core::TESTD_PRODUCTIVE_PROFILE | eliot_testd_core::TESTD_SCOPED_PROFILE => {
            Ok(eliot_testd_core::TESTD_PRODUCTIVE_PROFILE_WALL_TIMEOUT_MS)
        }
        eliot_testd_core::TESTD_LIST_PROFILE => {
            Ok(eliot_testd_core::TESTD_LIST_PROFILE_WALL_TIMEOUT_MS)
        }
        _ => Err(TestdError::Invalid {
            field: "profile",
            reason: "testd supervision requires a registered profile",
        }),
    }
}

fn clock_ms(clock: &ClockReading) -> Option<u64> {
    clock
        .valid_time_ms
        .or(clock.known_time_ms)
        .and_then(|value| u64::try_from(value).ok())
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
    reason: String,
) -> Result<(), TestdError> {
    let receipt = collector.verification_receipt(job, ExecutionStatus::Unknown);
    let finish_now = current_clock_ms();
    let verification = evaluate_testd_verification(job, &receipt, finish_now).ok();
    store.finish(
        &job.job_id,
        lease,
        ExecutionStatus::Unknown,
        verification,
        &receipt,
        finish_now,
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
///
/// Shared with the composition root so the governed Git source-observation
/// port drives the same executor futures on the same driver as the
/// productive tool start; there is exactly one noop-waker driver in this
/// binary.
pub(crate) fn block_on_one_shot<F: Future>(future: F) -> F::Output {
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures intentionally panic when construction invariants fail"
)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochId, EpochLineageId};
    use eliot_instrument_api::EvidenceAxes;
    use eliot_platform::ClockObservation;
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
        EnvironmentInheritance, EnvironmentProjection, FencingToken, Generation, ImageId, JobId,
        KernelDispatchKey, PermitIssuance, PhysicalProcessBinding, ProcessHealth,
        ProcessHealthStatus, ProcessId, ProcessIntent, ProcessState, ProcessStreamEvidence,
        ProcessStreamKind, ProcessStreamPolicyBinding, ProcessStreamPrefixPreview, ProcessTreeId,
        ResourceLimits, SessionId, StreamEvidenceGap, StreamPersistenceStatus,
        StreamTransportStatus, SuspendedProcessIdentity,
    };

    fn admitted_test_view() -> ProcessExecutionView {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(7).expect("non-zero test sequence"))
            .expect("valid test epoch");
        let generation = Generation::new(1).expect("non-zero test generation");
        let fence =
            FencingToken::new(epoch.clone(), generation, "fence-1").expect("valid test fence");
        let heads = BTreeMap::from([
            ("authority".to_owned(), "a".repeat(64)),
            ("state".to_owned(), "b".repeat(64)),
        ]);
        let intent = ProcessIntent::new(
            OperationId::new("operation-1").expect("valid test operation"),
            ProcessTreeId::new("tree-1").expect("valid test tree"),
            JobId::new("job-1").expect("valid test job"),
            ImageId::new("image-1").expect("valid test image"),
            SessionId::new("session-1").expect("valid test session"),
            generation,
            "C:\\tools\\worker.exe",
            "c".repeat(64),
            vec!["--check".to_owned()],
            "C:\\work",
            EnvironmentProjection::new(
                BTreeMap::from([("PATH".to_owned(), "C:\\Windows".to_owned())]),
                Vec::new(),
                EnvironmentInheritance::None,
            )
            .expect("valid test environment"),
            ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4)
                .expect("valid test limits"),
        )
        .expect("valid test intent");
        let authority_id = DispatchAuthorityId::new("authority-1").expect("valid test authority");
        let key = KernelDispatchKey::from_secret_bytes([0x5a; 32]).expect("valid test key");
        let mut authority = DispatchPermitAuthority::activate(authority_id, key);
        let issuance = PermitIssuance::new(
            ActionLeaseRef::new("lease-1").expect("valid test lease"),
            fence.clone(),
            heads.clone(),
            100,
            200,
            "nonce-1",
        )
        .expect("valid test issuance");
        let permit = authority
            .issue(&intent, issuance)
            .expect("authority issues the test permit");
        let observed = SuspendedProcessIdentity::new(
            ProcessId::new("process-1").expect("valid test process"),
            ProcessTreeId::new("tree-1").expect("valid test tree"),
            JobId::new("job-1").expect("valid test job"),
            ImageId::new("image-1").expect("valid test image"),
            SessionId::new("session-1").expect("valid test session"),
            generation,
            PhysicalProcessBinding::new(
                4242,
                11,
                "C:\\tools\\worker.exe",
                "Local\\Eliot-Process-Test",
            )
            .expect("valid physical binding"),
            120,
            "c".repeat(64),
        )
        .expect("valid observed identity");
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            epoch,
            heads,
            41,
        )
        .expect("valid validation context");
        let request = ProcessRequest::new(intent, permit).expect("valid test process request");
        let validated = authority
            .validate_and_consume(request, observed, &context)
            .expect("consumed test dispatch validates");
        let mut state = ProcessState::from_validated(&validated);
        state
            .mark_resumed(
                151,
                ProcessHealth::new(ProcessHealthStatus::Healthy, true, 151, None)
                    .expect("valid test health"),
            )
            .expect("test child resumes");
        state.view()
    }

    #[test]
    fn legacy_bearing_evidence_still_yields_native_synthetic_handle() {
        let view = admitted_test_view();
        let binding = view.binding().clone();
        let stdout_bytes = b"inline-stdout-bytes".to_vec();
        let stdout_total = u64::try_from(stdout_bytes.len()).expect("preview length fits u64");
        let stdout = ProcessStreamEvidence::new_raw(
            binding.clone(),
            ProcessStreamKind::Stdout,
            ProcessStreamPolicyBinding::new(
                "p04:stream-policy:transport-preview-v1",
                "p04:privacy:raw-transport-preview",
                "p04:visibility:operation-diagnostic",
                "p04:retention:bounded-prefix-only",
                "p04:redaction:none-raw-preview",
            )
            .expect("valid test stream policy"),
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::SourceUnavailable,
            eliot_testd_core::sha256_hex(&stdout_bytes),
            stdout_total,
            ProcessStreamPrefixPreview::from_transport_prefix(stdout_bytes, stdout_total)
                .expect("valid test preview"),
            None,
            vec![StreamEvidenceGap::PersistenceUnavailable],
        )
        .expect("valid inline stdout evidence");
        let stderr = ProcessStreamEvidence::new_legacy_raw_reference(
            binding,
            ProcessStreamKind::Stderr,
            "raw:legacy-stderr",
        )
        .expect("valid legacy stderr evidence");
        let evidence =
            ProcessEvidence::new_typed(view, Some(stdout), Some(stderr), EvidenceAxes::observed())
                .expect("mixed legacy-bearing evidence validates");
        assert_eq!(evidence.stdout_ref(), None);
        assert_eq!(evidence.stderr_ref(), Some("raw:legacy-stderr"));

        let collector = EvidenceCollector::default();
        let synthetic = capture_inline_previews(
            &collector,
            eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
            std::slice::from_ref(&evidence),
            observation_clock(current_clock_ms()),
        )
        .expect("inline capture succeeds");
        assert_eq!(synthetic, vec!["testd-inline-stream-0-stdout".to_owned()]);
        assert!(
            !synthetic.iter().any(|handle| handle == "raw:legacy-stderr"),
            "synthetic handles stay on the native path; legacy text never becomes a handle"
        );
    }
}
