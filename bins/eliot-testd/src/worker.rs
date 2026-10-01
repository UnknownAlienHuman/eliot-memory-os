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
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use eliot_contracts::ClockReading;
use eliot_instrument_api::{ExecutionStatus, KernelProcessAdmissionRequest};
use eliot_process::{
    ExitDisposition, ExitStatus, OperationId, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionView,
    ProcessExecutor, ProcessLifecycle, ProcessRequest, ProcessStreamSinkOpenRequest,
};
use eliot_testd_core::{
    EvidenceCollector, JobState, KernelProcessAdmissionEvidence, KernelProcessAdmissionProvider,
    AsyncProcessStreamSourceReadbackPort, EphemeralSourceBytes, Lease, SourceObservationGitPort,
    TestJob, TestdError, TestdReadbackContext, TestdSourceObservationRange,
    TestdStreamEvidenceBinding, TestdToolObservation,
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
    /// Stored-source readback port used before immutable terminal evidence is
    /// written. The port returns only verified ephemeral bytes.
    readback: Option<&'a dyn AsyncProcessStreamSourceReadbackPort>,
    /// Independently verified current-registry replay context.
    replay: Option<&'a dyn VerifiedStreamReplayPort>,
}

/// Authenticated currentness owner for replaying stored process bytes.
/// Implementations must source their registries from an accepted live catalog
/// owner readback, never from the retained stage alone.
pub trait VerifiedStreamReplayPort: Send + Sync {
    /// Replays one exact stored stream under its retained runner stage.
    fn replay_stream(
        &self,
        stage: &eliot_testd_core::InstrumentStageRequest,
        source: &TestdStreamEvidenceBinding,
        bytes: &EphemeralSourceBytes,
        observations: &TestdReplayObservedInputs,
        terminal: Option<&ExitStatus>,
        started_at: ClockReading,
        finished_at: ClockReading,
    ) -> Result<eliot_instrument_runner::ProfileReplayReceipt, String>;
}

/// Builds a fresh parser/evaluator context from the authenticated owner facts
/// that accompanied this exact stored-byte readback. No launch-time registry
/// object or scalar stage projection is reused as current authority.
pub struct KernelReadbackVerifiedReplay;

impl VerifiedStreamReplayPort for KernelReadbackVerifiedReplay {
    fn replay_stream(
        &self,
        stage: &eliot_testd_core::InstrumentStageRequest,
        source: &TestdStreamEvidenceBinding,
        bytes: &EphemeralSourceBytes,
        observations: &TestdReplayObservedInputs,
        terminal: Option<&ExitStatus>,
        started_at: ClockReading,
        finished_at: ClockReading,
    ) -> Result<eliot_instrument_runner::ProfileReplayReceipt, String> {
        let owner = bytes.replay_owner_readback();
        owner
            .validate()
            .map_err(|error| format!("fresh owner readback failed canonical validation: {error}"))?;
        let owner_facts: eliot_blob_api::wire::BlobProcessStreamVerifiedOwnerFacts =
            serde_json::from_str(&owner.owner_facts_json)
                .map_err(|error| format!("fresh Kernel owner facts are not typed JSON: {error}"))?;
        owner_facts
            .validate()
            .map_err(|error| format!("fresh Kernel owner facts were refused: {error}"))?;
        validate_ready_process_source_admission(source, bytes, owner, &owner_facts)?;
        let owner_grant = observations
            .blob_process_stream_grant
            .as_ref()
            .ok_or_else(|| "productive job has no durable Blob owner grant".to_owned())?;
        let job_currentness = eliot_contracts::canonical_json_bytes(&(
            &stage.provider_freshness,
            &stage.provider_catalog_lifecycle,
            &observations.tools,
            &observations.submitted_environment,
        ))
        .map_err(|error| format!("job currentness tuple is not canonical: {error}"))?;
        let process_binding_sha256 = sha256_hex(
            &eliot_contracts::canonical_json_bytes(&source.binding)
                .map_err(|error| format!("process binding is not canonical: {error}"))?,
        );
        let fence_sha256 = sha256_hex(
            &eliot_contracts::canonical_json_bytes(source.binding.state_fence())
                .map_err(|error| format!("process fence is not canonical: {error}"))?,
        );
        if owner.owner_facts_sha256 != owner_grant.owner_facts_sha256
            || owner.work_scope_binding_sha256 != owner_grant.work_scope_snapshot_sha256
            || owner.module_catalog_owner_readback_sha256
                != owner_grant.module_catalog_owner_readback_sha256
            || owner.generation_admission_sha256 != owner_grant.generation_admission_sha256
            || owner_facts.currentness_sha256 != owner_grant.owner_currentness_sha256
            || owner_facts.policy_sha256 != owner_grant.policy_sha256
            || process_binding_sha256 != owner_grant.process_binding_sha256
            || fence_sha256 != owner_grant.fence_sha256
            || sha256_hex(&job_currentness) != owner_grant.job_currentness_sha256
        {
            return Err("fresh owner PULL no longer matches the immutable launch grant".to_owned());
        }
        let expected_fence = source.binding.state_fence();
        let profile_registry = eliot_instrument_runner::testd_builtin_profile_registry()
        .map_err(|error| format!("current closed TestD profile registry refused: {error}"))?;
        let replay = eliot_instrument_runner::VerifiedTestdReplayContext::from_canonical_owner_readback_json(
            profile_registry,
            expected_fence,
            owner.module_catalog_owner_readback_json.as_bytes(),
            &owner.module_catalog_owner_readback_sha256,
            owner.generation_admission_json.as_bytes(),
            &owner.generation_admission_sha256,
            owner_facts.work_scope_binding_json.as_bytes(),
            &owner_facts.work_scope_binding_sha256,
        )
        .map_err(|error| format!("fresh owner/catalog replay context refused: {error}"))?;
        let replay_observations = eliot_instrument_runner::ReplayObservedInputs {
            source: observations.source.clone(),
            tools: observations.tools.clone(),
            environment: observations.environment.clone(),
            cargo_lock_sha256: observations.cargo_lock_sha256.clone(),
            lane_fingerprint_digest: observations.lane_fingerprint_digest.clone(),
            normative_pair_receipt: observations.normative_pair_receipt.clone(),
            required_test_ids: observations.required_test_ids.clone(),
        };
        replay
            .replay_stream(
                stage,
                source,
                bytes,
                terminal,
                started_at,
                finished_at,
                &replay_observations,
            )
            .map_err(|error| error.to_string())
    }
}

fn validate_ready_process_source_admission(
    source: &TestdStreamEvidenceBinding,
    bytes: &EphemeralSourceBytes,
    owner: &eliot_testd_core::TestdReplayOwnerReadback,
    owner_facts: &eliot_blob_api::wire::BlobProcessStreamVerifiedOwnerFacts,
) -> Result<(), String> {
    use eliot_store_api::blob_process_source_admission::{
        BlobProcessSourceAdmissionIdentity, BlobProcessSourceAdmissionPhase,
        BlobProcessSourceAdmissionReadback,
    };

    let readback: BlobProcessSourceAdmissionReadback =
        serde_json::from_str(&owner.process_source_admission_readback_json)
            .map_err(|error| format!("process source admission is not typed JSON: {error}"))?;
    let work_scope: serde_json::Value = serde_json::from_str(&owner_facts.work_scope_binding_json)
        .map_err(|error| format!("fresh WorkScope snapshot is not JSON: {error}"))?;
    let scope_ref = work_scope
        .pointer("/binding/scope/scope_ref")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "fresh WorkScope snapshot omitted its exact scope identity".to_owned())?;
    let work_scope_revision = work_scope
        .get("owner_revision")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "fresh WorkScope snapshot omitted its owner revision".to_owned())?;
    let work_scope_fence: eliot_contracts::StateFence = serde_json::from_value(
        work_scope
            .get("state_fence")
            .cloned()
            .ok_or_else(|| "fresh WorkScope snapshot omitted its fence".to_owned())?,
    )
    .map_err(|error| format!("fresh WorkScope fence is not typed: {error}"))?;
    work_scope_fence
        .validate()
        .map_err(|error| format!("fresh WorkScope fence is invalid: {error}"))?;

    let admission = &readback.admission;
    let open: ProcessStreamSinkOpenRequest = serde_json::from_str(&admission.open_request_json)
        .map_err(|error| format!("retained process Open request is not typed: {error}"))?;
    open.validate()
        .map_err(|error| format!("retained process Open request is invalid: {error}"))?;
    let binding_bytes = eliot_contracts::canonical_json_bytes(&source.binding)
        .map_err(|error| format!("process binding is not canonical: {error}"))?;
    let binding_sha256 = eliot_testd_core::sha256_hex(&binding_bytes);
    let identity = BlobProcessSourceAdmissionIdentity {
        work_scope_ref: scope_ref.to_owned(),
        session_id: open.session_id().as_str().to_owned(),
        source_id: open.source_id().as_str().to_owned(),
        process_binding_sha256: binding_sha256.clone(),
    };
    readback
        .validate_for(&identity, source.binding.state_fence())
        .map_err(|error| {
            format!("process source admission failed exact identity/fence validation: {error}")
        })?;

    let canonical_open = eliot_contracts::canonical_json_bytes(&open)
        .map_err(|error| format!("retained process Open request is not canonical: {error}"))?;
    let work_scope_fence_matches = work_scope_fence == *source.binding.state_fence();
    let expected_source_sha256 = source
        .source_sha256
        .as_deref()
        .ok_or_else(|| "replayed source binding omitted its whole-source digest".to_owned())?;
    let expected_source_byte_length = source
        .source_byte_length
        .ok_or_else(|| "replayed source binding omitted its whole-source length".to_owned())?;
    let ready = admission
        .ready
        .as_ref()
        .ok_or_else(|| "process source admission has no Ready commitment".to_owned())?;
    let ready_receipt: serde_json::Value = serde_json::from_str(&ready.blob_ready_receipt_json)
        .map_err(|error| format!("retained Blob Ready receipt is not JSON: {error}"))?;
    let receipt_id = ready_receipt
        .pointer("/receipt/identity/receipt_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "retained Blob Ready receipt omitted its identity".to_owned())?;
    let expected_receipt_ref = source
        .ready_receipt_ref
        .as_deref()
        .ok_or_else(|| "replayed source binding omitted its Ready receipt identity".to_owned())?;

    let canonical_binding = String::from_utf8(binding_bytes)
        .map_err(|error| format!("canonical process binding is not UTF-8: {error}"))?;
    let canonical_open = String::from_utf8(canonical_open)
        .map_err(|error| format!("canonical Open request is not UTF-8: {error}"))?;

    if admission.phase != BlobProcessSourceAdmissionPhase::Ready
        || readback.owner_revision != 2
        || admission.owner_revision != 2
        || admission.work_scope_owner_revision != work_scope_revision
        || admission.state_fence != *source.binding.state_fence()
        || !work_scope_fence_matches
        || admission.owner_facts_sha256 != owner.owner_facts_sha256
        || admission.owner_facts_json != owner.owner_facts_json
        || admission.process_binding_sha256 != binding_sha256
        || admission.process_binding_json != canonical_binding
        || admission.open_request_sha256 != open.open_request_sha256()
        || admission.open_request_json != canonical_open
        || open.binding() != &source.binding
        || open.policy() != &source.policy
        || open.stream() != source.stream
        || ready.whole_source_sha256 != expected_source_sha256
        || ready.whole_source_byte_length != expected_source_byte_length
        || expected_source_byte_length != bytes.len() as u64
        || expected_source_sha256 != eliot_testd_core::sha256_hex(bytes.bytes())
        || receipt_id != expected_receipt_ref
    {
        return Err(
            "Ready process source admission does not bind this exact stream, WorkScope, receipt, and stored bytes"
                .to_owned(),
        );
    }
    Ok(())
}

/// Actual replay-time observations supplied by the productive TestD worker.
/// Registry/profile freshness values are intentionally absent; the replay
/// owner combines these measured inputs with its authenticated catalog and
/// normative-pair readback.
#[derive(Clone, Debug)]
pub struct TestdReplayObservedInputs {
    /// Source before/after observation from the same governed Git executor.
    pub source: TestdSourceObservationRange,
    /// Tool files and selected toolchain remeasured at the finish boundary.
    pub tools: TestdToolObservation,
    /// Exact secret-safe child environment from the sealed launch request.
    pub environment: eliot_process::EnvironmentProjection,
    /// Secret-safe environment projection from the exact sealed
    /// `ProcessRequest` immediately before launch. This is kept distinct from
    /// the durable submit-time provider projection above so replay cannot
    /// relabel old owner data as a fresh observation.
    pub submitted_environment: eliot_process::EnvironmentProjection,
    /// SHA-256 of the exact current Cargo.lock bytes at the admitted root.
    pub cargo_lock_sha256: String,
    /// Exact bounded repository normative-pair receipt bytes. The replay
    /// owner parses these through `eliot-bootstrap` and compares the
    /// independently admitted pair key.
    pub normative_pair_receipt: Vec<u8>,
    /// Original plan-required test IDs parsed from the canonical owner binding.
    pub required_test_ids: BTreeSet<String>,
    /// Exact admitted lane fingerprint digest, rederived from the durable
    /// work envelope and paired with the fresh before/after Git observation.
    pub lane_fingerprint_digest: String,
    /// Exact immutable owner projection persisted on the claimed job. Fresh
    /// readback values are compared to it before context construction.
    pub blob_process_stream_grant: Option<eliot_testd_core::TestdBlobProcessStreamGrant>,
}

impl<'a, E: ?Sized> GovernedContour<'a, E> {
    /// Binds one executor as both the launch contour and the Git port.
    pub const fn new(executor: &'a E, git: Option<&'a dyn SourceObservationGitPort>) -> Self {
        Self {
            executor,
            git,
            readback: None,
            replay: None,
        }
    }

    /// Adds the Kernel-authenticated stored-source reader for productive
    /// capture. It is awaited outside the collector lock and before finish.
    pub const fn with_readback_port(
        executor: &'a E,
        git: Option<&'a dyn SourceObservationGitPort>,
        readback: &'a dyn AsyncProcessStreamSourceReadbackPort,
    ) -> Self {
        Self {
            executor,
            git,
            readback: Some(readback),
            replay: None,
        }
    }

    /// Binds stored-source readback and independently verified replay into
    /// one finish path.
    pub const fn with_readback_and_replay(
        executor: &'a E,
        git: Option<&'a dyn SourceObservationGitPort>,
        readback: &'a dyn AsyncProcessStreamSourceReadbackPort,
        replay: &'a dyn VerifiedStreamReplayPort,
    ) -> Self {
        Self {
            executor,
            git,
            readback: Some(readback),
            replay: Some(replay),
        }
    }

    /// The admitted executor that owns the Job Object contour.
    pub const fn executor(&self) -> &'a E {
        self.executor
    }

    /// The same executor presented as the physical Git port.
    pub const fn git(&self) -> Option<&'a dyn SourceObservationGitPort> {
        self.git
    }

    /// The authenticated immutable-source readback port, when productive
    /// capture is composed for this attempt.
    pub const fn readback(&self) -> Option<&'a dyn AsyncProcessStreamSourceReadbackPort> {
        self.readback
    }

    /// The authenticated live replay context, when the Kernel supplied one.
    pub const fn replay(&self) -> Option<&'a dyn VerifiedStreamReplayPort> {
        self.replay
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
    // Closed-profile Drive gate (issue #20): only registered profiles
    // drive. Fixed-argv profiles take no caller arguments: the fixed argv
    // comes from the registry binding, never from the invocation. Slotted
    // profiles (issue #1802, step 4) validate their arguments through the
    // slot schema; the sealed argv derives from the binding.
    if !eliot_testd_core::is_admitted_testd_profile(&presented.invocation.profile) {
        return Err(TestdError::Contract(
            "testd admits only the closed cargo-test tool-probe profile".to_owned(),
        ));
    }
    if !presented.invocation.arguments.is_empty() {
        if eliot_testd_core::is_slotted_testd_profile(&presented.invocation.profile) {
            eliot_testd_core::parse_testd_slot_suffix(
                &presented.invocation.profile,
                &presented.invocation.arguments,
            )
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        } else {
            return Err(TestdError::Contract(
                "the admitted profile takes fixed argv; caller arguments are refused".to_owned(),
            ));
        }
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
    let mut lease = job
        .lease
        .clone()
        .ok_or_else(|| TestdError::Corrupt("claimed job carries no lease".to_owned()))?;
    drive_claimed(store, &job, &mut lease, presented, contour, owner, lease_ms)
}

fn receipt_or_corrupt(
    store: &TestdStore,
    job: &TestJob,
    context: &'static str,
) -> Result<TestReceipt, TestdError> {
    Ok(crate::receipt(
        &store
            .get(&job.job_id)?
            .ok_or_else(|| TestdError::Corrupt(context.to_owned()))?,
    ))
}

/// Drives one claimed job against the presented admission to a deterministic
/// disposition. The job is already leased to this shot; every path below ends
/// in `finish` or `cancel` so the lease is always released.
#[allow(
    clippy::too_many_arguments,
    reason = "DISPATCH-LIVE residual: one admitted-shot context (composition, store, job, lease, presented material, executor, owner, now); a params-struct refactor is deferred until the dispatch-launch seam fixes the call shape, never a bare allow"
)]fn drive_claimed<E: ProcessExecutor + 'static>(
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
        return receipt_or_corrupt(store, job, "job disappeared after refusal");
    }
    if presented.cancelled {
        store.cancel(&job.job_id, Some(lease), owner, current_clock_ms())?;
        return receipt_or_corrupt(store, job, "job disappeared after cancellation");
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
            return receipt_or_corrupt(store, job, "job disappeared after admission refusal");
        }
    };
    // Internally built from this exact attempt (#456 Wave B): admits only
    // records carrying the presented operation; start refuses other sinks.
    let collector = Arc::new(EvidenceCollector::for_operation(operation_id.clone()));
    let mut process_environment = None;
    if eliot_testd_core::is_productive_testd_profile(&job.invocation.profile) {
        let (observation, launch_environment) = match observe_tool_identity(&job, permit.request()) {
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
                return receipt_or_corrupt(store, job, "job disappeared after tool observation");
            }
        };
        collector.record_tool_observation(observation)?;
        process_environment = Some(launch_environment);
    }
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
        &collector,
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
        process_environment,
    )?;
    Ok(crate::receipt(&store.get(&job.job_id)?.ok_or_else(
        || TestdError::Corrupt("job disappeared after finish".to_owned()),
    )?))
}

/// Revalidates the exact tool identity carried by the admitted productive
/// ProcessRequest immediately before the consuming start. The resolver has
/// already selected cargo/rustc through rustup; this readback binds the
/// resulting files and nextest executable into the durable receipt.
fn observe_tool_identity(
    job: &TestJob,
    request: &ProcessRequest,
) -> Result<(TestdToolObservation, eliot_process::EnvironmentProjection), TestdError> {
    let observation = job
        .provider_tool_observation
        .clone()
        .ok_or(TestdError::Invalid {
            field: "tool_environment",
            reason: "productive job has no durable owner-observed tool identities",
        })?;
    observation.validate()?;
    let stage_command = job
        .stage_request
        .as_ref()
        .and_then(|stage| stage.stage_command.as_ref())
        .ok_or(TestdError::Invalid {
            field: "stage_request.stage_command",
            reason: "productive job has no sealed registered command",
        })?;
    let (selected_path, selected_sha256) = match stage_command.executable.as_str() {
        "cargo" => (&observation.cargo_path, &observation.cargo_sha256),
        "cargo-nextest" => (&observation.nextest_path, &observation.nextest_sha256),
        _ => {
            return Err(TestdError::Invalid {
                field: "stage_request.stage_command.executable",
                reason: "productive command selector is not admitted",
            });
        }
    };
    if request.executable() != selected_path.as_str()
        || request.executable_sha256() != selected_sha256.as_str()
    {
        return Err(TestdError::InvalidBinding);
    }
    let process_environment = eliot_process::EnvironmentProjection::new(
        request.environment().non_secret().clone(),
        request.environment().secret_refs().to_vec(),
        request.environment().inheritance(),
    )
    .map_err(|error| TestdError::Contract(error.to_string()))?;
    let environment = process_environment.non_secret();
    let required = |key: &'static str| {
        environment.get(key).cloned().ok_or(TestdError::Invalid {
            field: "tool_environment",
            reason: "productive process request is missing owner-observed tool identity",
        })
    };
    for (key, expected) in [
        (crate::TESTD_ENV_NEXTEST, observation.nextest_path.as_str()),
        (
            crate::TESTD_ENV_NEXTEST_SHA256,
            observation.nextest_sha256.as_str(),
        ),
        (crate::TESTD_ENV_CARGO, observation.cargo_path.as_str()),
        (
            crate::TESTD_ENV_CARGO_SHA256,
            observation.cargo_sha256.as_str(),
        ),
        (crate::TESTD_ENV_RUSTC, observation.rustc_path.as_str()),
        (
            crate::TESTD_ENV_RUSTC_SHA256,
            observation.rustc_sha256.as_str(),
        ),
        (crate::TESTD_ENV_TOOLCHAIN, observation.selected_toolchain.as_str()),
    ] {
        if required(key)? != expected {
            return Err(TestdError::InvalidBinding);
        }
    }
    reobserve_tool_files(&observation)?;
    Ok((observation, process_environment))
}

fn reobserve_tool_files(observation: &TestdToolObservation) -> Result<(), TestdError> {
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
            reason: "owner-observed tool cannot be reread at the replay boundary",
        })?;
        if eliot_testd_core::sha256_hex(&bytes) != expected {
            return Err(TestdError::Invalid {
                field: "tool_environment",
                reason: "owner-observed tool changed before replay",
            });
        }
    }
    Ok(())
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
    process_environment: Option<eliot_process::EnvironmentProjection>,
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
        process_environment,
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
    /// Exact physical terminal observation from the admitted executor. This
    /// never substitutes for parser/evaluator evidence.
    exit_status: Option<ExitStatus>,
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
    let mut exit_status = None;
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
                exit_status = view.exit().cloned();
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
        exit_status,
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

fn build_replay_observed_inputs(
    job: &TestJob,
    source: &TestdSourceObservationRange,
    process_environment: Option<eliot_process::EnvironmentProjection>,
) -> Result<TestdReplayObservedInputs, TestdError> {
    source.validate()?;
    if source.before.repository_root != job.target_roots.source_root
        || source.after.repository_root != job.target_roots.source_root
        || !source.unchanged()
    {
        return Err(TestdError::InvalidBinding);
    }
    let tools = job
        .provider_tool_observation
        .clone()
        .ok_or(TestdError::InvalidBinding)?;
    tools.validate()?;
    reobserve_tool_files(&tools)?;
    let submitted_environment = job
        .provider_environment_projection
        .clone()
        .ok_or(TestdError::InvalidBinding)?;
    eliot_process::EnvironmentProjection::new(
        submitted_environment.non_secret().clone(),
        submitted_environment.secret_refs().to_vec(),
        submitted_environment.inheritance(),
    )
    .map_err(|error| TestdError::Contract(error.to_string()))?;
    let process_environment = process_environment.ok_or(TestdError::Invalid {
        field: "provider_currentness.environment",
        reason: "the exact sealed launch environment was not observed before execution",
    })?;
    let mut expected_process_environment = submitted_environment.non_secret().clone();
    expected_process_environment.insert(
        "CARGO_TARGET_DIR".to_owned(),
        job.target_roots.target_root.clone(),
    );
    expected_process_environment.insert("CARGO_HOME".to_owned(), job.target_roots.cache_root.clone());
    let expected_process_environment = eliot_process::EnvironmentProjection::new(
        expected_process_environment,
        submitted_environment.secret_refs().to_vec(),
        submitted_environment.inheritance(),
    )
    .map_err(|error| TestdError::Contract(error.to_string()))?;
    if process_environment != expected_process_environment {
        return Err(TestdError::InvalidBinding);
    }
    let lock_path = Path::new(&job.target_roots.source_root).join("Cargo.lock");
    let lock_bytes = std::fs::read(lock_path).map_err(|_| TestdError::Invalid {
        field: "provider_currentness.lock",
        reason: "the exact admitted Cargo.lock cannot be reread before replay",
    })?;
    if lock_bytes.is_empty() {
        return Err(TestdError::Invalid {
            field: "provider_currentness.lock",
            reason: "the admitted Cargo.lock is empty at replay time",
        });
    }
    let normative_pair_receipt = std::fs::read(
        Path::new(&job.target_roots.source_root).join("docs/normative-pair.toml"),
    )
    .map_err(|_| TestdError::Invalid {
        field: "provider_currentness.normative_pair",
        reason: "the exact normative-pair receipt cannot be reread before replay",
    })?;
    if normative_pair_receipt.is_empty()
        || normative_pair_receipt.len()
            > eliot_bootstrap::normative::MAX_NORMATIVE_PAIR_RECEIPT_BYTES
    {
        return Err(TestdError::Invalid {
            field: "provider_currentness.normative_pair",
            reason: "the normative-pair receipt is empty or exceeds its 16 KiB bound",
        });
    }
    let verifier_dispatch = job
        .verifier_dispatch
        .as_ref()
        .ok_or(TestdError::InvalidBinding)?;
    let required_test_ids = verifier_dispatch
        .required_test_ids_for_job(job)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if required_test_ids.is_empty() {
        return Err(TestdError::InvalidBinding);
    }
    let lane_fingerprint_digest = job
        .work_envelope
        .as_ref()
        .ok_or(TestdError::InvalidBinding)?
        .fingerprint
        .digest()
        .map_err(|_| TestdError::InvalidBinding)?;
    let blob_process_stream_grant = Some(
        job.blob_process_stream_grant
            .clone()
            .ok_or(TestdError::InvalidBinding)?,
    );
    Ok(TestdReplayObservedInputs {
        source: source.clone(),
        tools,
        environment: process_environment,
        submitted_environment,
        cargo_lock_sha256: eliot_testd_core::sha256_hex(&lock_bytes),
        normative_pair_receipt,
        required_test_ids,
        lane_fingerprint_digest,
        blob_process_stream_grant,
    })
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
    process_environment: Option<eliot_process::EnvironmentProjection>,
) -> Result<(), TestdError> {
    let FinishInputs { claimed, observed } = *inputs;
    let SupervisionOutcome {
        mut execution,
        exit_status,
        mut reason,
        reconcile_note,
        ..
    } = outcome;
    let finished_at = observation_clock(current_clock_ms());
    let (source_observation, observation_fault) =
        observe_terminal_source(observed, contour, &mut execution);
    if let Some(message) = observation_fault {
        reason = message;
    }
    let replay_observed_inputs = match source_observation.as_ref() {
        Some(source) => match build_replay_observed_inputs(claimed, source, process_environment) {
            Ok(inputs) => Some(inputs),
            Err(error) => {
                execution = ExecutionStatus::Unknown;
                reason = format!("replay-time source/tool currentness observation failed: {error}");
                None
            }
        },
        None => None,
    };
    if let Some(port) = contour.readback() {
        let context = TestdReadbackContext {
            job_id: claimed.job_id.clone(),
            invocation_id: claimed.invocation.request.request_id.clone(),
            expected_operation_id: claimed.process.operation_id.clone(),
            expected_process_tree_id: claimed.process.process_tree_id.clone(),
            expected_process_generation: claimed.process.generation,
            expected_authority_epoch: claimed.process.authority_epoch.clone(),
            max_bytes: eliot_blob_api::BLOB_MAX_PLAINTEXT_BYTES as u64,
            deadline_ms: current_clock_ms().saturating_add(30_000),
        };
        match block_on_one_shot(collector.resolve_typed_sources_async(port, &context)) {
            Err(error) => {
                execution = ExecutionStatus::Unknown;
                reason = format!("stored-source readback did not complete safely: {error}");
            }
            Ok(groups) => {
                let mut resolved_streams = 0usize;
                let mut replay_fault = None;
                let replay_context = contour.replay();
                let stage = claimed.stage_request.as_ref();
                for resolution in groups.into_iter().flatten() {
                    match resolution {
                        eliot_testd_core::TestdStreamResolution::Resolved {
                            source, bytes, ..
                        } => {
                            resolved_streams += 1;
                            let Some(replay_context) = replay_context else {
                                replay_fault.get_or_insert_with(|| {
                                    "no authenticated current replay context was supplied".to_owned()
                                });
                                continue;
                            };
                            let Some(stage) = stage else {
                                replay_fault.get_or_insert_with(|| {
                                    "the productive job has no retained runner stage".to_owned()
                                });
                                continue;
                            };
                            let Some(observations) = replay_observed_inputs.as_ref() else {
                                replay_fault.get_or_insert_with(|| {
                                    "replay-time source/tool currentness observations are unavailable".to_owned()
                                });
                                continue;
                            };
                            let replayed = match replay_context.replay_stream(
                                stage,
                                &source,
                                &bytes,
                                observations,
                                exit_status.as_ref(),
                                started_at,
                                finished_at,
                            ) {
                                Ok(replayed) => replayed,
                                Err(error) => {
                                    replay_fault.get_or_insert_with(|| {
                                        format!("current parser/evaluator replay refused: {error}")
                                    });
                                    continue;
                                }
                            };
                            let Some(parsing) = replayed.parsing.as_ref() else {
                                replay_fault.get_or_insert_with(|| {
                                    "replay returned no executed parser observation".to_owned()
                                });
                                continue;
                            };
                            if let Err(error) = collector.apply_stream_replay(
                                &source,
                                parsing,
                                replayed.evaluation.as_ref(),
                            ) {
                                replay_fault.get_or_insert_with(|| {
                                    format!("replay evidence no longer matches its stream: {error}")
                                });
                            }
                        }
                        eliot_testd_core::TestdStreamResolution::Refused { error, .. } => {
                            replay_fault.get_or_insert_with(|| {
                                format!("stored-source readback refused a stream: {error}")
                            });
                        }
                    }
                }
                if let Some(error) = replay_fault {
                    execution = ExecutionStatus::Unknown;
                    reason = error;
                } else if resolved_streams == 0 {
                    execution = ExecutionStatus::Unknown;
                    reason = "productive process emitted no readback-bound stream evidence".to_owned();
                }
            }
        }
    }
    let mut receipt =
        collector.verification_receipt_at(claimed, execution, started_at, finished_at);
    receipt.source_observation = source_observation;
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
