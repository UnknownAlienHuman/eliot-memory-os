//! I3.3/I3.15: retained, native append-only evidence for one survey process.
//!
//! The executor owns pipe draining and calls this provider-neutral port
//! synchronously through bounded request futures. This adapter retains the
//! original survey area, its native artifact root, each checked session, and
//! every unresolved physical outcome until Kernel proves owner release.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Poll;
use std::time::{Duration, Instant};

use eliot_contracts::sha256_hex;
use eliot_installation::SurveyProbeWorkingArea;
use eliot_platform_windows::{
    FileIdentity, SurveyStreamArtifact, SurveyStreamArtifactError, SurveyStreamArtifactReadback,
    SurveyStreamArtifactRoot,
};
use eliot_process::{
    DurableProcessStreamSource, DurableStreamLocatorKind, ProcessExecutionBinding, ProcessRequest,
    ProcessStreamEvidence, ProcessStreamKind, ProcessStreamPolicyBinding,
    ProcessStreamSinkAbortReason, ProcessStreamSinkAbortRequest, ProcessStreamSinkAppend,
    ProcessStreamSinkAppendDisposition, ProcessStreamSinkClient, ProcessStreamSinkError,
    ProcessStreamSinkFinalizeRequest, ProcessStreamSinkFuture, ProcessStreamSinkOpenRequest,
    ProcessStreamSinkReadback, ProcessStreamSinkSession, ProcessStreamSinkSessionId,
    ProcessStreamSinkSessionView, ProcessStreamSinkState, ProcessStreamSinkTerminal,
    ProcessStreamSinkTerminalCommandIdentity, ProcessStreamSinkUnknownOutcome, StreamEvidenceGap,
    StreamPersistenceStatus, StreamTransportStatus,
};
#[cfg(test)]
use eliot_process::{ProcessStreamPrefixPreview, ProcessStreamSinkLimits};
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;

const MAX_STREAM_SESSIONS: usize = 2;
/// `StreamSinkPump` currently seals this event-count ceiling into every P-04
/// stream session. Keeping the receipt table within that same bound makes
/// replay identity retention finite as well.
const MAX_REPLAY_RECEIPTS: u64 = 2_048;
const P04_BOUNDED_PREFIX_RETENTION: &str = "p04:retention:bounded-prefix-only";

/// Failure to construct this survey-owned sink or prove its owner releasable.
#[derive(Debug)]
pub(crate) struct InstallationSurveyStreamSinkError {
    detail: String,
}

impl InstallationSurveyStreamSinkError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for InstallationSurveyStreamSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl Error for InstallationSurveyStreamSinkError {}

/// Concrete six-method stream sink owned by the original survey operation.
///
/// Production construction always opens the native root from the retained
/// installer-verified area before the executor admits its temporary child
/// path. The area and root remain held through write-close readback.
pub(crate) struct InstallationSurveyStreamSink {
    core: Arc<StreamSinkCore>,
}

struct StreamSinkCore {
    // The root lease itself is retained by `SurveyStreamArtifactRoot`; this
    // Arc keeps the original installer transaction and its root proof alive.
    _area: Option<Arc<SurveyProbeWorkingArea>>,
    root: ArtifactRoot,
    expected: ExpectedRequest,
    policy: ProcessStreamPolicyBinding,
    sessions: Mutex<HashMap<ProcessStreamSinkSessionId, SessionRecord>>,
    runtime: Handle,
    in_flight: Arc<AtomicUsize>,
    owner_gate: Mutex<bool>,
}

impl InstallationSurveyStreamSink {
    /// Opens the native artifact root once from the exact retained survey area.
    ///
    /// # Errors
    ///
    /// Refuses an invalid sealed request, changed installer-root proof, or
    /// unsafe/unavailable native evidence area.
    pub(crate) fn new(
        area: Arc<SurveyProbeWorkingArea>,
        request: &ProcessRequest,
        policy: ProcessStreamPolicyBinding,
    ) -> Result<Self, InstallationSurveyStreamSinkError> {
        let runtime = Handle::try_current().map_err(|_| {
            InstallationSurveyStreamSinkError::new(
                "a Tokio runtime handle is required for bounded native stream calls",
            )
        })?;
        request
            .validate()
            .map_err(|error| InstallationSurveyStreamSinkError::new(error.to_string()))?;
        let expected_binding = request
            .expected_execution_binding()
            .map_err(|error| InstallationSurveyStreamSinkError::new(error.to_string()))?;
        if policy.retention_ref() == P04_BOUNDED_PREFIX_RETENTION {
            return Err(InstallationSurveyStreamSinkError::new(
                "bounded-prefix-only policy cannot create a durable raw survey sink",
            ));
        }
        let root_lease = area
            .verified_native_root_read_lease()
            .map_err(|error| InstallationSurveyStreamSinkError::new(error.to_string()))?;
        let root = SurveyStreamArtifactRoot::open(&root_lease).map_err(|error| {
            InstallationSurveyStreamSinkError::new(format!(
                "could not retain native survey evidence root: {error:?}"
            ))
        })?;
        Ok(Self {
            core: Arc::new(StreamSinkCore::from_parts(
                Some(area),
                ArtifactRoot::Native(root),
                ExpectedRequest::capture(request, expected_binding),
                policy,
                runtime,
            )),
        })
    }

    pub(crate) fn matches_request(
        &self,
        request: &ProcessRequest,
        policy: &ProcessStreamPolicyBinding,
    ) -> bool {
        request
            .expected_execution_binding()
            .is_ok_and(|binding| binding == self.core.expected.binding)
            && policy == &self.core.policy
            && request.resource_limits().stdout_bytes() == self.core.expected.stdout_bytes
            && request.resource_limits().stderr_bytes() == self.core.expected.stderr_bytes
    }

    /// Proves owner release using only the original completed native
    /// readback. Any scheduled/running native worker or unresolved session
    /// keeps the original area and provider owner retained.
    pub(crate) fn reconcile_for_owner_release(
        &self,
    ) -> Result<(), InstallationSurveyStreamSinkError> {
        self.core.reconcile_for_owner_release()
    }
}

impl StreamSinkCore {
    fn from_parts(
        area: Option<Arc<SurveyProbeWorkingArea>>,
        root: ArtifactRoot,
        expected: ExpectedRequest,
        policy: ProcessStreamPolicyBinding,
        runtime: Handle,
    ) -> Self {
        Self {
            _area: area,
            root,
            expected,
            policy,
            sessions: Mutex::new(HashMap::new()),
            runtime,
            in_flight: Arc::new(AtomicUsize::new(0)),
            owner_gate: Mutex::new(false),
        }
    }

    fn schedule_blocking<T, F>(
        self: &Arc<Self>,
        operation: F,
    ) -> Result<BlockingCall<T>, ProcessStreamSinkError>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Self>, Arc<AtomicBool>) -> Result<T, ProcessStreamSinkError> + Send + 'static,
    {
        let reservation = self.reserve_blocking_call()?;
        Ok(self.schedule_reserved(reservation, operation))
    }

    fn reserve_blocking_call(&self) -> Result<InFlightGuard, ProcessStreamSinkError> {
        let owner_gate = try_lock_owner_gate(&self.owner_gate)?;
        if *owner_gate {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        }
        self.in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_STREAM_SESSIONS).then_some(current + 1)
            })
            .map_err(|_| ProcessStreamSinkError::ProviderUnavailable)?;
        drop(owner_gate);
        Ok(InFlightGuard(Arc::clone(&self.in_flight)))
    }

    fn schedule_reserved<T, F>(
        self: &Arc<Self>,
        reservation: InFlightGuard,
        operation: F,
    ) -> BlockingCall<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Self>, Arc<AtomicBool>) -> Result<T, ProcessStreamSinkError> + Send + 'static,
    {
        let timed_out = Arc::new(AtomicBool::new(false));
        let worker_timed_out = Arc::clone(&timed_out);
        let worker_core = Arc::clone(self);
        let worker = self.runtime.spawn_blocking(move || {
            let _owner = reservation;
            operation(worker_core, worker_timed_out)
        });
        BlockingCall {
            worker,
            timed_out,
            runtime: self.runtime.clone(),
        }
    }

    async fn wait_bounded<T>(
        call: BlockingCall<T>,
        wait_budget_ms: u64,
    ) -> Result<T, ProcessStreamSinkError> {
        Self::wait_bounded_until(call, Instant::now() + Duration::from_millis(wait_budget_ms)).await
    }

    async fn wait_bounded_until<T>(
        call: BlockingCall<T>,
        deadline: Instant,
    ) -> Result<T, ProcessStreamSinkError> {
        let mut worker = call.worker;
        let timed_out = call.timed_out;
        let mut completion = WaitCompletionGuard {
            timed_out: Arc::clone(&timed_out),
            finished: false,
        };
        let runtime = call.runtime;
        let _entered = runtime.enter();
        let mut deadline_sleep = Box::pin(tokio::time::sleep_until(
            tokio::time::Instant::from_std(deadline),
        ));
        drop(_entered);
        poll_fn(|context| {
            if Instant::now() >= deadline {
                timed_out.store(true, Ordering::Release);
                completion.finished = true;
                return Poll::Ready(Err(ProcessStreamSinkError::ProviderUnavailable));
            }
            if let Poll::Ready(result) = Pin::new(&mut worker).poll(context) {
                if Instant::now() >= deadline {
                    timed_out.store(true, Ordering::Release);
                    completion.finished = true;
                    return Poll::Ready(Err(ProcessStreamSinkError::ProviderUnavailable));
                }
                let output = match result {
                    Ok(result) => result,
                    Err(_) => {
                        timed_out.store(true, Ordering::Release);
                        Err(ProcessStreamSinkError::ProviderUnavailable)
                    }
                };
                completion.finished = true;
                return Poll::Ready(output);
            }
            if Instant::now() >= deadline || deadline_sleep.as_mut().poll(context).is_ready() {
                timed_out.store(true, Ordering::Release);
                completion.finished = true;
                return Poll::Ready(Err(ProcessStreamSinkError::ProviderUnavailable));
            }
            Poll::Pending
        })
        .await
    }

    /// Resolves retained stream ownership before Kernel releases the same
    /// survey-area record. It never deletes, adopts, or replaces an artifact.
    ///
    /// # Errors
    ///
    /// Returns an error while a create/write/terminal effect remains unknown,
    /// while an original session lacks its terminal, or when closed native
    /// readback no longer matches the exact original terminal/source proof.
    pub(crate) fn reconcile_for_owner_release(
        &self,
    ) -> Result<(), InstallationSurveyStreamSinkError> {
        let mut owner_gate = lock_owner_gate(&self.owner_gate);
        if self.in_flight.load(Ordering::Acquire) != 0 {
            return Err(InstallationSurveyStreamSinkError::new(
                "native stream call remains queued or in flight",
            ));
        }
        *owner_gate = true;
        drop(owner_gate);

        let result = self.prove_owner_release();
        if result.is_err() {
            *lock_owner_gate(&self.owner_gate) = false;
        }
        result
    }

    fn prove_owner_release(&self) -> Result<(), InstallationSurveyStreamSinkError> {
        if self.in_flight.load(Ordering::Acquire) != 0 {
            return Err(InstallationSurveyStreamSinkError::new(
                "native stream call was queued during owner release",
            ));
        }
        let sessions = lock_sessions(&self.sessions);
        for record in sessions.values() {
            if record.phase == SessionPhase::Refused {
                // The exact create-only request was refused before this root
                // created a stream file; a foreign collision is never adopted.
                continue;
            }

            if record.phase == SessionPhase::Unknown || record.phase == SessionPhase::Opening {
                return Err(owner_release_error(
                    record,
                    "native stream outcome remains unknown",
                ));
            }
            let Some(terminal) = record.terminal.clone() else {
                return Err(owner_release_error(
                    record,
                    "original stream session has no write-closed terminal",
                ));
            };
            terminal
                .validate()
                .map_err(|error| owner_release_error(record, &error.to_string()))?;
            let admitted_sha256 = record.admitted_sha256();
            if terminal.session_id() != record.session.session_id()
                || terminal.source_id() != record.session.source_id()
                || terminal.terminal_id() != record.session.terminal_id()
                || terminal.open_request_sha256() != record.session.open_request_sha256()
                || terminal.final_sequence() != record.next_sequence
                || terminal.final_offset() != record.next_offset
                || terminal.admitted_sha256() != admitted_sha256.as_str()
            {
                return Err(owner_release_error(
                    record,
                    "terminal no longer matches its original session counters",
                ));
            }
            match record.terminal_command.as_ref() {
                Some(PendingTerminal::Finalize(request)) => terminal
                    .validate_against_finalize(request)
                    .map_err(|error| owner_release_error(record, &error.to_string()))?,
                Some(PendingTerminal::Abort(request)) => {
                    terminal
                        .validate_against_abort(request)
                        .map_err(|error| owner_release_error(record, &error.to_string()))?
                }
                None => {
                    return Err(owner_release_error(
                        record,
                        "terminal has no retained original command identity",
                    ));
                }
            }
            if record.late_append.is_some()
                && (!terminal_has_persistence_gap(&terminal)
                    || terminal.evidence().persistence()
                        != StreamPersistenceStatus::SourceUnavailable
                    || terminal.state() == ProcessStreamSinkState::CompleteSource
                    || terminal.evidence().source().is_some())
            {
                return Err(owner_release_error(
                    record,
                    "late unacknowledged bytes lack source-unavailable persistence gap evidence",
                ));
            }

            if record.artifact.is_none() {
                return Err(owner_release_error(
                    record,
                    "terminal has no retained native artifact owner",
                ));
            }
            let proof = record.closed_proof.as_ref().ok_or_else(|| {
                owner_release_error(record, "terminal lacks its original close/readback proof")
            })?;
            verify_existing_stable_object(record, proof)
                .map_err(|error| owner_release_error(record, &error.to_string()))?;
            if record.late_append.is_some() {
                if !matches_late_tail(record, proof) {
                    return Err(owner_release_error(
                        record,
                        "closed native artifact does not match its retained unadmitted tail",
                    ));
                }
            } else if proof.byte_length != record.next_offset
                || proof.sha256 != record.admitted_sha256()
            {
                return Err(owner_release_error(
                    record,
                    "closed native artifact differs from the admitted transport prefix",
                ));
            }
            if record.late_append.is_some()
                && (terminal.evidence().source().is_some()
                    || terminal.evidence().persistence()
                        != StreamPersistenceStatus::SourceUnavailable
                    || terminal.state() == ProcessStreamSinkState::CompleteSource)
            {
                return Err(owner_release_error(
                    record,
                    "unadmitted tail cannot produce a source-ready terminal state",
                ));
            }
            match terminal.evidence().source() {
                Some(source)
                    if source.kind() != DurableStreamLocatorKind::ImmutableArtifact
                        || source.locator() != proof.locator.as_str()
                        || source.ready_receipt_ref() != proof.ready_receipt_ref.as_str()
                        || source.byte_length() != proof.byte_length
                        || source.sha256() != proof.sha256.as_str() =>
                {
                    return Err(owner_release_error(
                        record,
                        "terminal source does not match actual closed native readback",
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn prepare_open(
        &self,
        request: ProcessStreamSinkOpenRequest,
    ) -> Result<(ProcessStreamSinkSession, OpenAction, Option<InFlightGuard>), ProcessStreamSinkError>
    {
        request.validate()?;
        self.validate_open_request(&request)?;
        let session = ProcessStreamSinkSession::from_open_request(request.clone())?;
        let session_id = session.session_id().clone();
        let file_name = artifact_file_name(session.stream(), session.session_id());
        let mut sessions = try_lock_sessions(&self.sessions)?;

        if let Some(record) = sessions.get_mut(&session_id) {
            if record.session.open_request_sha256() != session.open_request_sha256() {
                return Err(ProcessStreamSinkError::SessionMismatch);
            }
            if record.phase == SessionPhase::Refused {
                return Err(record.primary_failure.as_ref().map_or(
                    ProcessStreamSinkError::SourceMismatch,
                    Failure::as_sink_error,
                ));
            }
            let action = match record.phase {
                SessionPhase::Unknown => OpenAction::Reconcile,
                SessionPhase::Opening if self.in_flight.load(Ordering::Acquire) != 0 => {
                    OpenAction::AlreadyPending
                }
                SessionPhase::Opening => {
                    record.primary_failure.get_or_insert(Failure::Invariant(
                        "open worker ended before recording a physical disposition",
                    ));
                    mark_unknown(record, "open-worker-disposition-missing")?;
                    OpenAction::Reconcile
                }
                SessionPhase::Open | SessionPhase::Terminal => OpenAction::AlreadyReady,
                SessionPhase::Refused => return Err(ProcessStreamSinkError::SourceMismatch),
            };
            let session = record.session.clone();
            if action == OpenAction::Reconcile {
                return match self.reserve_blocking_call() {
                    Ok(reservation) => Ok((session, action, Some(reservation))),
                    Err(_) => Ok((session, OpenAction::AlreadyPending, None)),
                };
            }
            return Ok((session, action, None));
        }
        if sessions.len() >= MAX_STREAM_SESSIONS {
            return Err(ProcessStreamSinkError::InvalidRequest {
                reason: "survey stream session count exceeds stdout/stderr",
            });
        }
        if sessions
            .values()
            .any(|record| record.session.stream() == session.stream())
        {
            return Err(ProcessStreamSinkError::StreamMismatch);
        }

        let reservation = self.reserve_blocking_call()?;
        let mut record = SessionRecord::new(session.clone(), file_name.clone());
        record.phase = SessionPhase::Opening;
        sessions.insert(session_id.clone(), record);
        Ok((session, OpenAction::Create, Some(reservation)))
    }

    fn open_checked(
        &self,
        session: ProcessStreamSinkSession,
        action: OpenAction,
        timed_out: &AtomicBool,
    ) -> Result<ProcessStreamSinkSession, ProcessStreamSinkError> {
        let mut sessions = lock_sessions(&self.sessions);
        let record = sessions
            .get_mut(session.session_id())
            .ok_or(ProcessStreamSinkError::SessionMismatch)?;
        require_exact_session(record, &session)?;
        match action {
            OpenAction::AlreadyReady | OpenAction::AlreadyPending => Ok(session),
            OpenAction::Reconcile => {
                if timed_out.load(Ordering::Acquire) {
                    mark_unknown(record, "open-reconcile-deadline")?;
                    return Ok(session);
                }
                let _ = self.reconcile_record(record, timed_out);
                Ok(session)
            }
            OpenAction::Create => match self.root.create_stream_file(&record.file_name) {
                Ok(artifact) => {
                    record.artifact = Some(artifact);
                    if timed_out.load(Ordering::Acquire) {
                        record.primary_failure.get_or_insert(Failure::Invariant(
                            "open native create completed after its wait budget",
                        ));
                        mark_unknown(record, "open-create-deadline")?;
                    } else {
                        record.phase = SessionPhase::Open;
                    }
                    Ok(session)
                }
                Err(
                    error @ (SurveyStreamArtifactError::ExistingArtifact
                    | SurveyStreamArtifactError::UnsupportedPlatform),
                ) => {
                    record.phase = SessionPhase::Refused;
                    record.primary_failure = Some(Failure::Native(error));
                    Err(Failure::Native(error).as_sink_error())
                }
                Err(error) => {
                    record.primary_failure.get_or_insert(Failure::Native(error));
                    if timed_out.load(Ordering::Acquire) {
                        mark_unknown(record, "open-create-deadline-unknown")?;
                        return Ok(session);
                    }
                    let file_name = record.file_name.clone();
                    match self.root.reconcile_created_stream_file(&file_name) {
                        Ok(artifact) => {
                            record.artifact = Some(artifact);
                            if timed_out.load(Ordering::Acquire) {
                                mark_unknown(record, "open-create-reconcile-deadline")?;
                                return Ok(session);
                            }
                            match self.read_artifact(record, false) {
                                Ok(proof)
                                    if proof.byte_length == 0
                                        && proof.sha256 == sha256_hex(&[]) =>
                                {
                                    if timed_out.load(Ordering::Acquire) {
                                        mark_unknown(record, "open-readback-deadline")?;
                                    } else {
                                        record.phase = SessionPhase::Open;
                                        record.unknown_outcome = None;
                                    }
                                }
                                Ok(_) | Err(_) => {
                                    mark_unknown(record, "open-create-readback-mismatch")?;
                                }
                            }
                        }
                        Err(_) => mark_unknown(record, "open-create-reconcile-pending")?,
                    }
                    Ok(session)
                }
            },
        }
    }

    fn validate_open_request(
        &self,
        request: &ProcessStreamSinkOpenRequest,
    ) -> Result<(), ProcessStreamSinkError> {
        if request.policy() != &self.policy {
            return Err(ProcessStreamSinkError::PolicyMismatch);
        }
        if request.policy().retention_ref() == P04_BOUNDED_PREFIX_RETENTION {
            return Err(ProcessStreamSinkError::InvalidRequest {
                reason: "bounded-prefix-only retention cannot open a durable raw sink",
            });
        }
        let binding = request.binding();
        if binding != &self.expected.binding {
            return Err(ProcessStreamSinkError::BindingMismatch);
        }
        let expected_session_id = p04_sink_identity(binding, request.stream(), "session");
        let expected_source_id = p04_sink_identity(binding, request.stream(), "source");
        let expected_terminal_id = p04_sink_identity(binding, request.stream(), "terminal");
        if request.session_id().as_str() != expected_session_id.as_str()
            || request.source_id().as_str() != expected_source_id.as_str()
            || request.terminal_id().as_str() != expected_terminal_id.as_str()
        {
            return Err(ProcessStreamSinkError::SessionMismatch);
        }
        let stream_bound = match request.stream() {
            ProcessStreamKind::Stdout => self.expected.stdout_bytes,
            ProcessStreamKind::Stderr => self.expected.stderr_bytes,
        };
        let limits = request.limits();
        if limits.max_total_admitted_bytes() > stream_bound
            || limits.max_chunk_bytes() > stream_bound
            || limits.max_preview_bytes() > limits.max_total_admitted_bytes()
            || limits.max_chunks() > MAX_REPLAY_RECEIPTS
        {
            return Err(ProcessStreamSinkError::InvalidLimits {
                reason: "stream sink ceilings exceed the sealed request or replay bound",
            });
        }
        Ok(())
    }

    fn append_checked(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAppend,
        deadline: Instant,
        timed_out: Arc<AtomicBool>,
    ) -> Result<AppendWorkerResult, ProcessStreamSinkError> {
        let mut sessions = lock_sessions(&self.sessions);
        let record = sessions
            .get_mut(session.session_id())
            .ok_or(ProcessStreamSinkError::SessionMismatch)?;
        require_exact_session(record, &session)?;
        session.validate_append(&request)?;

        if let Some(terminal) = &record.terminal {
            return Ok(AppendWorkerResult::Disposition(
                ProcessStreamSinkAppendDisposition::Terminal {
                    state: terminal.state(),
                    terminal_sha256: terminal.terminal_sha256().to_owned(),
                },
            ));
        }
        if record.phase == SessionPhase::Unknown {
            return Ok(AppendWorkerResult::Disposition(
                ProcessStreamSinkAppendDisposition::Backpressured { retry_after_ms: 1 },
            ));
        }
        if record.phase != SessionPhase::Open {
            return Err(ProcessStreamSinkError::AppendAfterFinalizing);
        }
        if record.late_append.is_some() {
            return Ok(AppendWorkerResult::Disposition(
                ProcessStreamSinkAppendDisposition::Backpressured { retry_after_ms: 1 },
            ));
        }
        if request.bytes().is_empty() {
            return Err(ProcessStreamSinkError::InvalidRequest {
                reason: "empty chunks do not advance a bounded stream session",
            });
        }

        if request.sequence() <= record.next_sequence {
            return match record.receipts.get(&request.sequence()) {
                Some(receipt)
                    if receipt.offset == request.offset()
                        && receipt.byte_length == request.byte_length()
                        && receipt.sha256 == request.sha256() =>
                {
                    Ok(AppendWorkerResult::Disposition(
                        ProcessStreamSinkAppendDisposition::Replayed {
                            next_sequence: record.next_sequence,
                            next_offset: record.next_offset,
                        },
                    ))
                }
                Some(_) => Err(ProcessStreamSinkError::MismatchedReplay),
                None => Err(ProcessStreamSinkError::MismatchedReplay),
            };
        }
        let expected_sequence = record
            .next_sequence
            .checked_add(1)
            .ok_or(ProcessStreamSinkError::ChunkCountLimitExceeded)?;
        if request.sequence() != expected_sequence {
            return Err(ProcessStreamSinkError::SequenceGap {
                expected: expected_sequence,
                observed: request.sequence(),
            });
        }
        if request.offset() != record.next_offset {
            return Err(ProcessStreamSinkError::OffsetMismatch {
                expected: record.next_offset,
                observed: request.offset(),
            });
        }
        let candidate_offset = record
            .next_offset
            .checked_add(request.byte_length())
            .ok_or(ProcessStreamSinkError::TotalLimitExceeded)?;
        if candidate_offset > session.limits().max_total_admitted_bytes() {
            return Err(ProcessStreamSinkError::TotalLimitExceeded);
        }
        if expected_sequence > session.limits().max_chunks() {
            return Err(ProcessStreamSinkError::ChunkCountLimitExceeded);
        }
        let candidate_hasher = {
            let mut hasher = record.admitted_hasher.clone();
            hasher.update(request.bytes());
            hasher
        };
        let candidate_sha256 = digest_hex(&candidate_hasher);
        let candidate_preview = preview_extension(
            &record.preview,
            request.bytes(),
            session.limits().max_preview_bytes(),
        );
        let candidate = PendingAppend {
            sequence: request.sequence(),
            offset: request.offset(),
            byte_length: request.byte_length(),
            sha256: request.sha256().to_owned(),
            candidate_sha256,
            candidate_hasher,
            candidate_preview,
            acknowledgement_deadline: deadline,
            acknowledgement_expired: Arc::clone(&timed_out),
        };

        if timed_out.load(Ordering::Acquire) || Instant::now() >= deadline {
            timed_out.store(true, Ordering::Release);
            return Ok(AppendWorkerResult::Disposition(
                ProcessStreamSinkAppendDisposition::DeadlineExceeded,
            ));
        }

        let append_result = match record.artifact.as_mut() {
            Some(artifact) => artifact.append(
                record.next_offset,
                request.bytes(),
                session.limits().max_total_admitted_bytes(),
            ),
            None => {
                record.primary_failure.get_or_insert(Failure::Invariant(
                    "open session lost its retained native artifact",
                ));
                mark_unknown(record, "append-without-native-artifact")?;
                return Ok(AppendWorkerResult::Disposition(
                    ProcessStreamSinkAppendDisposition::Backpressured { retry_after_ms: 1 },
                ));
            }
        };
        let deadline_expired = timed_out.load(Ordering::Acquire) || Instant::now() >= deadline;
        if deadline_expired {
            timed_out.store(true, Ordering::Release);
        }
        let pending_ack = PendingAppendTicket::from_candidate(&candidate);
        match append_result {
            Ok(next_offset) if next_offset == candidate_offset => {
                record.pending_append = Some(candidate);
                if deadline_expired {
                    record.primary_failure.get_or_insert(Failure::Invariant(
                        "native append completed after its original wait budget",
                    ));
                    mark_unknown(record, "append-native-deadline")?;
                    return Ok(AppendWorkerResult::Disposition(
                        ProcessStreamSinkAppendDisposition::DeadlineExceeded,
                    ));
                }
                Ok(AppendWorkerResult::NeedsAcknowledgement(pending_ack))
            }
            Ok(_) => {
                record.primary_failure.get_or_insert(Failure::Invariant(
                    "native append returned a different physical offset",
                ));
                record.pending_append = Some(candidate);
                mark_unknown(record, "append-offset-readback-required")?;
                Ok(AppendWorkerResult::Disposition(
                    ProcessStreamSinkAppendDisposition::Backpressured { retry_after_ms: 1 },
                ))
            }
            Err(error) => {
                record.primary_failure.get_or_insert(Failure::Native(error));
                match self.read_artifact(record, false) {
                    Ok(proof)
                        if proof.byte_length == record.next_offset
                            && proof.sha256 == record.admitted_sha256() =>
                    {
                        if deadline_expired {
                            mark_unknown(record, "append-error-readback-deadline")?;
                            Ok(AppendWorkerResult::Disposition(
                                ProcessStreamSinkAppendDisposition::DeadlineExceeded,
                            ))
                        } else {
                            Ok(AppendWorkerResult::Disposition(
                                ProcessStreamSinkAppendDisposition::Backpressured {
                                    retry_after_ms: 1,
                                },
                            ))
                        }
                    }
                    Ok(proof)
                        if proof.byte_length == candidate_offset
                            && proof.sha256 == candidate.candidate_sha256 =>
                    {
                        record.pending_append = Some(candidate);
                        if timed_out.load(Ordering::Acquire) || Instant::now() >= deadline {
                            timed_out.store(true, Ordering::Release);
                            record.primary_failure.get_or_insert(Failure::Invariant(
                                "native append readback completed after its original wait budget",
                            ));
                            mark_unknown(record, "append-candidate-readback-deadline")?;
                            Ok(AppendWorkerResult::Disposition(
                                ProcessStreamSinkAppendDisposition::DeadlineExceeded,
                            ))
                        } else {
                            Ok(AppendWorkerResult::NeedsAcknowledgement(pending_ack))
                        }
                    }
                    Ok(_) => {
                        record.pending_append = Some(candidate);
                        mark_unknown(record, "append-native-bytes-not-admitted-prefix")?;
                        Ok(AppendWorkerResult::Disposition(
                            ProcessStreamSinkAppendDisposition::Backpressured { retry_after_ms: 1 },
                        ))
                    }
                    Err(_) => {
                        record.pending_append = Some(candidate);
                        mark_unknown(record, "append-readback-unknown")?;
                        Ok(AppendWorkerResult::Disposition(
                            ProcessStreamSinkAppendDisposition::Backpressured { retry_after_ms: 1 },
                        ))
                    }
                }
            }
        }
    }

    fn acknowledge_pending_append(
        &self,
        session: &ProcessStreamSinkSession,
        ticket: &PendingAppendTicket,
        deadline: Instant,
        timed_out: &Arc<AtomicBool>,
    ) -> Result<ProcessStreamSinkAppendDisposition, ProcessStreamSinkError> {
        let mut sessions = match try_lock_sessions(&self.sessions) {
            Ok(sessions) => sessions,
            Err(error) => {
                timed_out.store(true, Ordering::Release);
                return if matches!(&error, ProcessStreamSinkError::ProviderUnavailable) {
                    Ok(ProcessStreamSinkAppendDisposition::DeadlineExceeded)
                } else {
                    Err(error)
                };
            }
        };
        let record = sessions
            .get_mut(session.session_id())
            .ok_or(ProcessStreamSinkError::SessionMismatch)?;
        require_exact_session(record, session)?;
        if !matches!(record.phase, SessionPhase::Open | SessionPhase::Unknown) {
            return Err(ProcessStreamSinkError::AppendAfterFinalizing);
        }
        let pending = record
            .pending_append
            .as_ref()
            .ok_or(ProcessStreamSinkError::TerminalIdentityConflict)?;
        if !ticket.matches(pending)
            || !Arc::ptr_eq(&pending.acknowledgement_expired, timed_out)
            || pending.acknowledgement_deadline != deadline
        {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        if Instant::now() >= deadline || timed_out.load(Ordering::Acquire) {
            timed_out.store(true, Ordering::Release);
            record.primary_failure.get_or_insert(Failure::Invariant(
                "append acknowledgement missed its original wait budget",
            ));
            mark_unknown(record, "append-acknowledgement-deadline")?;
            return Ok(ProcessStreamSinkAppendDisposition::DeadlineExceeded);
        }
        let pending = record
            .pending_append
            .take()
            .ok_or(ProcessStreamSinkError::TerminalIdentityConflict)?;
        admit_append(record, pending);
        Ok(ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: record.next_sequence,
            next_offset: record.next_offset,
        })
    }

    fn finalize_checked(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkFinalizeRequest,
        timed_out: &AtomicBool,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        let mut sessions = lock_sessions(&self.sessions);
        let record = sessions
            .get_mut(session.session_id())
            .ok_or(ProcessStreamSinkError::SessionMismatch)?;
        require_exact_session(record, &session)?;
        session.validate_finalize(&request)?;
        if timed_out.load(Ordering::Acquire) {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        }
        let command = request.command_identity()?;
        if let Some(terminal) = terminal_for_command(record, &command)? {
            return Ok(terminal);
        }
        validate_terminal_counters(
            record,
            request.expected_final_sequence(),
            request.expected_final_offset(),
            request.observed_sha256(),
            request.observed_bytes(),
        )?;
        if request.transformation().is_some() {
            record.primary_failure.get_or_insert(Failure::Invariant(
                "raw survey artifact cannot attest a policy transformation",
            ));
            return Err(ProcessStreamSinkError::PolicyMismatch);
        }
        begin_terminal(record, PendingTerminal::Finalize(request.clone()), command)?;
        if record.phase == SessionPhase::Unknown {
            let _ = self.reconcile_record(record, timed_out);
        }
        if let Some(terminal) = &record.terminal {
            return Ok(terminal.clone());
        }
        if record.phase != SessionPhase::Open {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        }
        self.close_and_terminalize(record, TerminalCommand::Finalize(request), timed_out)
    }

    fn abort_checked(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAbortRequest,
        timed_out: &AtomicBool,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        let mut sessions = lock_sessions(&self.sessions);
        let record = sessions
            .get_mut(session.session_id())
            .ok_or(ProcessStreamSinkError::SessionMismatch)?;
        require_exact_session(record, &session)?;
        session.validate_abort(&request)?;
        if timed_out.load(Ordering::Acquire) {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        }
        let command = request.command_identity()?;
        if let Some(terminal) = terminal_for_command(record, &command)? {
            return Ok(terminal);
        }
        validate_terminal_counters(
            record,
            request.expected_final_sequence(),
            request.expected_final_offset(),
            request.observed_sha256(),
            request.observed_bytes(),
        )?;
        if request.transformation().is_some() {
            record.primary_failure.get_or_insert(Failure::Invariant(
                "raw survey artifact cannot attest a policy transformation",
            ));
            return Err(ProcessStreamSinkError::PolicyMismatch);
        }
        begin_terminal(record, PendingTerminal::Abort(request.clone()), command)?;
        if record.phase == SessionPhase::Unknown {
            let _ = self.reconcile_record(record, timed_out);
        }
        if let Some(terminal) = &record.terminal {
            return Ok(terminal.clone());
        }
        if record.phase != SessionPhase::Open {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        }
        self.close_and_terminalize(record, TerminalCommand::Abort(request), timed_out)
    }

    fn close_and_terminalize(
        &self,
        record: &mut SessionRecord,
        command: TerminalCommand,
        timed_out: &AtomicBool,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        let Some(artifact) = record.artifact.as_mut() else {
            record.primary_failure.get_or_insert(Failure::Invariant(
                "terminal command has no retained native artifact",
            ));
            mark_unknown(record, "terminal-without-native-artifact")?;
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        };
        let max_total_bytes = record.session.limits().max_total_admitted_bytes();
        let proof = match artifact.readback(max_total_bytes, true) {
            Ok(proof) => proof,
            Err(error) => {
                record.primary_failure.get_or_insert(Failure::Native(error));
                mark_unknown(record, "terminal-close-readback-unknown")?;
                return Err(ProcessStreamSinkError::ProviderUnavailable);
            }
        };
        if timed_out.load(Ordering::Acquire) {
            record.closed_proof = Some(proof);
            mark_unknown(record, "terminal-readback-deadline")?;
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        }
        if let Err(error) = verify_stable_object(record, &proof) {
            record
                .primary_failure
                .get_or_insert(Failure::Sink(error.clone()));
            mark_unknown(record, "terminal-native-identity-mismatch")?;
            return Err(error);
        }
        let admitted_sha256 = record.admitted_sha256();
        let admitted_exact =
            proof.byte_length == record.next_offset && proof.sha256 == admitted_sha256;
        let late_tail_exact = matches_late_tail(record, &proof);
        if (record.late_append.is_some() && !late_tail_exact)
            || (!admitted_exact && !late_tail_exact)
        {
            record.primary_failure.get_or_insert(Failure::Invariant(
                "closed native artifact differs from admitted stream bytes",
            ));
            mark_unknown(record, "terminal-native-content-mismatch")?;
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        }
        record.closed_proof = Some(proof.clone());
        match self.build_terminal(record, command, proof) {
            Ok(terminal) => {
                record.terminal = Some(terminal.clone());
                record.terminal_command = record.pending_terminal.take();
                record.phase = SessionPhase::Terminal;
                record.unknown_outcome = None;
                Ok(terminal)
            }
            Err(error) => {
                record
                    .primary_failure
                    .get_or_insert(Failure::Sink(error.clone()));
                mark_unknown(record, "terminal-evidence-construction-failed")?;
                Err(error)
            }
        }
    }

    fn build_terminal(
        &self,
        record: &mut SessionRecord,
        command: TerminalCommand,
        proof: ArtifactProof,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        match command {
            TerminalCommand::Finalize(request) => {
                if record.late_append.is_some()
                    && !request.gaps().iter().any(|gap| {
                        matches!(
                            gap,
                            StreamEvidenceGap::PersistenceUnavailable
                                | StreamEvidenceGap::PersistenceBackpressure
                        )
                    })
                {
                    return Err(ProcessStreamSinkError::EvidenceInvariant {
                        reason: "late native bytes require the original persistence gap".to_owned(),
                    });
                }
                let complete = request.transport() == StreamTransportStatus::Complete
                    && request.gaps().is_empty()
                    && record.policy_retains_raw_source()
                    && request.transformation().is_none()
                    && record.late_append.is_none()
                    && proof.byte_length == request.observed_bytes()
                    && proof.sha256 == request.observed_sha256();
                let (state, persistence, source) = if complete {
                    let source = DurableProcessStreamSource::exact_transport(
                        DurableStreamLocatorKind::ImmutableArtifact,
                        proof.locator.clone(),
                        proof.ready_receipt_ref.clone(),
                        proof.sha256.clone(),
                        proof.byte_length,
                    )
                    .map_err(ProcessStreamSinkError::from)?;
                    (
                        ProcessStreamSinkState::CompleteSource,
                        StreamPersistenceStatus::CompleteSource,
                        Some(source),
                    )
                } else {
                    (
                        ProcessStreamSinkState::SourceUnavailable,
                        StreamPersistenceStatus::SourceUnavailable,
                        None,
                    )
                };
                let evidence = ProcessStreamEvidence::new_raw(
                    record.session.binding().clone(),
                    record.session.stream(),
                    record.session.policy().clone(),
                    request.transport(),
                    persistence,
                    request.observed_sha256().to_owned(),
                    request.observed_bytes(),
                    request.preview().clone(),
                    source,
                    request.gaps().to_vec(),
                )
                .map_err(ProcessStreamSinkError::from)?;
                ProcessStreamSinkTerminal::from_finalize(
                    record.session.clone(),
                    request,
                    state,
                    record.next_sequence,
                    record.next_offset,
                    record.admitted_sha256(),
                    evidence,
                )
            }
            TerminalCommand::Abort(request) => {
                let (state, preview) = match request.reason() {
                    ProcessStreamSinkAbortReason::Cancellation
                    | ProcessStreamSinkAbortReason::CallerShutdown => {
                        (ProcessStreamSinkState::Cancelled, request.preview().clone())
                    }
                    ProcessStreamSinkAbortReason::PolicyProhibition => (
                        ProcessStreamSinkState::PolicyProhibited,
                        request.preview().clone(),
                    ),
                    ProcessStreamSinkAbortReason::RedactionFailure => (
                        ProcessStreamSinkState::RedactionFailed,
                        request.preview().clone(),
                    ),
                    ProcessStreamSinkAbortReason::TransportFailure => (
                        ProcessStreamSinkState::SourceUnavailable,
                        request.preview().clone(),
                    ),
                };
                let evidence = ProcessStreamEvidence::new_raw(
                    record.session.binding().clone(),
                    record.session.stream(),
                    record.session.policy().clone(),
                    request.transport(),
                    StreamPersistenceStatus::SourceUnavailable,
                    request.observed_sha256().to_owned(),
                    request.observed_bytes(),
                    preview,
                    None,
                    request.gaps().to_vec(),
                )
                .map_err(ProcessStreamSinkError::from)?;
                ProcessStreamSinkTerminal::from_abort(
                    record.session.clone(),
                    request,
                    state,
                    record.next_sequence,
                    record.next_offset,
                    record.admitted_sha256(),
                    evidence,
                )
            }
        }
    }

    fn read_artifact(
        &self,
        record: &mut SessionRecord,
        close_writer: bool,
    ) -> Result<ArtifactProof, SurveyStreamArtifactError> {
        let max_total_bytes = record.session.limits().max_total_admitted_bytes();
        let artifact = record
            .artifact
            .as_mut()
            .ok_or(SurveyStreamArtifactError::IdentityMismatch)?;
        let proof = artifact.readback(max_total_bytes, close_writer)?;
        verify_stable_object(record, &proof)
            .map_err(|_| SurveyStreamArtifactError::IdentityMismatch)?;
        if close_writer {
            record.closed_proof = Some(proof.clone());
        }
        Ok(proof)
    }

    fn readback_checked(
        &self,
        session: ProcessStreamSinkSession,
        timed_out: &AtomicBool,
    ) -> Result<ProcessStreamSinkReadback, ProcessStreamSinkError> {
        let mut sessions = lock_sessions(&self.sessions);
        let record = sessions
            .get_mut(session.session_id())
            .ok_or(ProcessStreamSinkError::SessionMismatch)?;
        require_exact_session(record, &session)?;
        if record.phase == SessionPhase::Refused {
            return Err(ProcessStreamSinkError::SourceMismatch);
        }
        if record.phase == SessionPhase::Terminal {
            let terminal = record
                .terminal
                .as_ref()
                .ok_or(ProcessStreamSinkError::SessionMismatch)?;
            return Ok(ProcessStreamSinkReadback::Terminal {
                terminal: terminal.clone(),
            });
        }
        self.reconcile_record(record, timed_out)
    }

    fn reconcile_checked(
        &self,
        session: ProcessStreamSinkSession,
        outcome: ProcessStreamSinkUnknownOutcome,
        timed_out: &AtomicBool,
    ) -> Result<ProcessStreamSinkReadback, ProcessStreamSinkError> {
        let mut sessions = lock_sessions(&self.sessions);
        let record = sessions
            .get_mut(session.session_id())
            .ok_or(ProcessStreamSinkError::SessionMismatch)?;
        require_exact_session(record, &session)?;
        outcome.validate_against_session(&session)?;
        let original = record
            .unknown_outcome
            .as_ref()
            .ok_or(ProcessStreamSinkError::TerminalIdentityConflict)?;
        if original != &outcome {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        self.reconcile_record(record, timed_out)
    }

    fn reconcile_record(
        &self,
        record: &mut SessionRecord,
        timed_out: &AtomicBool,
    ) -> Result<ProcessStreamSinkReadback, ProcessStreamSinkError> {
        if record.phase == SessionPhase::Refused {
            return Err(ProcessStreamSinkError::SourceMismatch);
        }
        if let Some(terminal) = &record.terminal {
            return Ok(ProcessStreamSinkReadback::Terminal {
                terminal: terminal.clone(),
            });
        }
        if record.artifact.is_none() {
            if timed_out.load(Ordering::Acquire) {
                mark_unknown(record, "native-create-reconcile-deadline")?;
                return Ok(unknown_readback(record)?);
            }
            match self.root.reconcile_created_stream_file(&record.file_name) {
                Ok(artifact) => record.artifact = Some(artifact),
                Err(error) => {
                    record.primary_failure.get_or_insert(Failure::Native(error));
                    mark_unknown(record, "native-create-still-pending")?;
                    return Ok(unknown_readback(record)?);
                }
            }
        }

        if record.pending_append.is_some() {
            let acknowledgement_expired = record.pending_append.as_ref().is_some_and(|pending| {
                pending.acknowledgement_expired.load(Ordering::Acquire)
                    || Instant::now() >= pending.acknowledgement_deadline
            });
            if !acknowledgement_expired {
                mark_unknown(record, "original-append-acknowledgement-pending")?;
                return Ok(unknown_readback(record)?);
            }
            if let Some(pending) = record.pending_append.as_ref() {
                pending
                    .acknowledgement_expired
                    .store(true, Ordering::Release);
            }
            record.primary_failure.get_or_insert(Failure::Invariant(
                "original append acknowledgement expired before admission",
            ));
            if timed_out.load(Ordering::Acquire) {
                mark_unknown(record, "pending-append-reconcile-deadline")?;
                return Ok(unknown_readback(record)?);
            }
            let proof = match self.read_artifact(record, false) {
                Ok(proof) => proof,
                Err(error) => {
                    record.primary_failure.get_or_insert(Failure::Native(error));
                    mark_unknown(record, "pending-append-readback-still-unknown")?;
                    return Ok(unknown_readback(record)?);
                }
            };
            if timed_out.load(Ordering::Acquire) {
                mark_unknown(record, "pending-append-readback-deadline")?;
                return Ok(unknown_readback(record)?);
            }
            let pending = record
                .pending_append
                .take()
                .ok_or(ProcessStreamSinkError::SessionMismatch)?;
            if proof.byte_length == record.next_offset && proof.sha256 == record.admitted_sha256() {
                record.phase = SessionPhase::Open;
                record.unknown_outcome = None;
            } else if proof.byte_length == pending.offset.saturating_add(pending.byte_length)
                && proof.sha256 == pending.candidate_sha256
            {
                record.late_proof = Some(proof);
                record.late_append = Some(pending);
                record.phase = SessionPhase::Open;
                record.unknown_outcome = None;
            } else {
                // The original append did not return a timely acknowledgement,
                // so P-04 did not advance its admitted prefix. Later readback
                // cannot promote these bytes into that original sequence.
                record.pending_append = Some(pending);
                record.primary_failure.get_or_insert(Failure::Invariant(
                    "native file contains bytes not admitted by the original executor call",
                ));
                mark_unknown(record, "pending-append-is-not-originally-admitted")?;
                return Ok(unknown_readback(record)?);
            }
        } else if let Some(pending) = record.pending_terminal.clone() {
            if record.phase != SessionPhase::Unknown {
                return Err(ProcessStreamSinkError::SessionMismatch);
            }
            let proof = match self.read_artifact(record, true) {
                Ok(proof) => proof,
                Err(error) => {
                    record.primary_failure.get_or_insert(Failure::Native(error));
                    mark_unknown(record, "pending-terminal-close-still-unknown")?;
                    return Ok(unknown_readback(record)?);
                }
            };
            if timed_out.load(Ordering::Acquire) {
                record.closed_proof = Some(proof);
                mark_unknown(record, "pending-terminal-readback-deadline")?;
                return Ok(unknown_readback(record)?);
            }
            let admitted_exact =
                proof.byte_length == record.next_offset && proof.sha256 == record.admitted_sha256();
            if (record.late_append.is_some() && !matches_late_tail(record, &proof))
                || (record.late_append.is_none() && !admitted_exact)
            {
                record.primary_failure.get_or_insert(Failure::Invariant(
                    "pending terminal artifact matches neither the admitted prefix nor retained late tail",
                ));
                mark_unknown(record, "pending-terminal-content-remains-unknown")?;
                return Ok(unknown_readback(record)?);
            }
            record.closed_proof = Some(proof.clone());
            let terminal = match pending {
                PendingTerminal::Finalize(request) => {
                    self.build_terminal(record, TerminalCommand::Finalize(request), proof)
                }
                PendingTerminal::Abort(request) => {
                    self.build_terminal(record, TerminalCommand::Abort(request), proof)
                }
            };
            match terminal {
                Ok(terminal) => {
                    record.terminal_command = record.pending_terminal.take();
                    record.terminal = Some(terminal.clone());
                    record.phase = SessionPhase::Terminal;
                    record.unknown_outcome = None;
                    return Ok(ProcessStreamSinkReadback::Terminal { terminal });
                }
                Err(error) => {
                    record.primary_failure.get_or_insert(Failure::Sink(error));
                    mark_unknown(record, "pending-terminal-evidence-still-invalid")?;
                    return Ok(unknown_readback(record)?);
                }
            }
        } else if record.late_append.is_some() {
            if timed_out.load(Ordering::Acquire) {
                mark_unknown(record, "late-tail-readback-deadline")?;
                return Ok(unknown_readback(record)?);
            }
            let proof = match self.read_artifact(record, false) {
                Ok(proof) => proof,
                Err(error) => {
                    record.primary_failure.get_or_insert(Failure::Native(error));
                    mark_unknown(record, "late-tail-readback-unknown")?;
                    return Ok(unknown_readback(record)?);
                }
            };
            let late_matches = matches_late_tail(record, &proof);
            if !late_matches || timed_out.load(Ordering::Acquire) {
                record.primary_failure.get_or_insert(Failure::Invariant(
                    "unadmitted append changed after its original readback",
                ));
                mark_unknown(record, "late-tail-native-content-mismatch")?;
                return Ok(unknown_readback(record)?);
            }
            record.phase = SessionPhase::Open;
            record.unknown_outcome = None;
        } else {
            if timed_out.load(Ordering::Acquire) {
                mark_unknown(record, "native-session-readback-deadline")?;
                return Ok(unknown_readback(record)?);
            }
            let proof = match self.read_artifact(record, false) {
                Ok(proof) => proof,
                Err(error) => {
                    record.primary_failure.get_or_insert(Failure::Native(error));
                    mark_unknown(record, "native-session-readback-unknown")?;
                    return Ok(unknown_readback(record)?);
                }
            };
            if timed_out.load(Ordering::Acquire) {
                mark_unknown(record, "native-session-readback-deadline")?;
                return Ok(unknown_readback(record)?);
            }
            if proof.byte_length != record.next_offset || proof.sha256 != record.admitted_sha256() {
                record.primary_failure.get_or_insert(Failure::Invariant(
                    "native session bytes differ from admitted stream bytes",
                ));
                mark_unknown(record, "native-session-content-mismatch")?;
                return Ok(unknown_readback(record)?);
            }
            record.phase = SessionPhase::Open;
            record.unknown_outcome = None;
        }
        Ok(ProcessStreamSinkReadback::Session {
            view: session_view(record)?,
        })
    }
}

impl ProcessStreamSinkClient for InstallationSurveyStreamSink {
    fn open(
        &self,
        request: ProcessStreamSinkOpenRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkSession> {
        let core = Arc::clone(&self.core);
        Box::pin(async move {
            let (session, action, reservation) = core.prepare_open(request)?;
            let Some(reservation) = reservation else {
                return Ok(session);
            };
            let wait_budget_ms = session.limits().max_append_wait_ms();
            let worker_session = session.clone();
            let call = core.schedule_reserved(reservation, move |core, timed_out| {
                core.open_checked(worker_session, action, &timed_out)
            });
            let timed_out = Arc::clone(&call.timed_out);
            match StreamSinkCore::wait_bounded(call, wait_budget_ms).await {
                Ok(session) => Ok(session),
                Err(_error) if timed_out.load(Ordering::Acquire) => Ok(session),
                Err(error) => Err(error),
            }
        })
    }

    fn append(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAppend,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkAppendDisposition> {
        let core = Arc::clone(&self.core);
        Box::pin(async move {
            let wait_budget_ms = request.wait_budget_ms();
            let deadline = Instant::now() + Duration::from_millis(wait_budget_ms);
            let worker_session = session.clone();
            let call = match core.schedule_blocking(move |core, timed_out| {
                core.append_checked(worker_session, request, deadline, timed_out)
            }) {
                Ok(call) => call,
                Err(ProcessStreamSinkError::ProviderUnavailable) => {
                    return Ok(ProcessStreamSinkAppendDisposition::Backpressured {
                        retry_after_ms: 1,
                    });
                }
                Err(error) => return Err(error),
            };
            let timed_out = Arc::clone(&call.timed_out);
            match StreamSinkCore::wait_bounded_until(call, deadline).await {
                Err(_) if timed_out.load(Ordering::Acquire) => {
                    Ok(ProcessStreamSinkAppendDisposition::DeadlineExceeded)
                }
                Err(error) => Err(error),
                Ok(AppendWorkerResult::Disposition(disposition)) => Ok(disposition),
                Ok(AppendWorkerResult::NeedsAcknowledgement(ticket)) => {
                    core.acknowledge_pending_append(&session, &ticket, deadline, &timed_out)
                }
            }
        })
    }

    fn finalize(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkFinalizeRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        let core = Arc::clone(&self.core);
        Box::pin(async move {
            let wait_budget_ms = request.wait_budget_ms();
            let call = core.schedule_blocking(move |core, timed_out| {
                core.finalize_checked(session, request, &timed_out)
            })?;
            let wait_result = StreamSinkCore::wait_bounded(call, wait_budget_ms).await;
            wait_result
        })
    }

    fn abort(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAbortRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        let core = Arc::clone(&self.core);
        Box::pin(async move {
            let wait_budget_ms = request.wait_budget_ms();
            let call = core.schedule_blocking(move |core, timed_out| {
                core.abort_checked(session, request, &timed_out)
            })?;
            StreamSinkCore::wait_bounded(call, wait_budget_ms).await
        })
    }

    fn readback(
        &self,
        session: ProcessStreamSinkSession,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        let core = Arc::clone(&self.core);
        Box::pin(async move {
            let wait_budget_ms = session.limits().max_finalize_wait_ms();
            let call = core.schedule_blocking(move |core, timed_out| {
                core.readback_checked(session, &timed_out)
            })?;
            StreamSinkCore::wait_bounded(call, wait_budget_ms).await
        })
    }

    fn reconcile(
        &self,
        session: ProcessStreamSinkSession,
        outcome: ProcessStreamSinkUnknownOutcome,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        let core = Arc::clone(&self.core);
        Box::pin(async move {
            let wait_budget_ms = session.limits().max_finalize_wait_ms();
            let call = core.schedule_blocking(move |core, timed_out| {
                core.reconcile_checked(session, outcome, &timed_out)
            })?;
            StreamSinkCore::wait_bounded(call, wait_budget_ms).await
        })
    }
}

#[derive(Clone)]
struct ExpectedRequest {
    binding: ProcessExecutionBinding,
    stdout_bytes: u64,
    stderr_bytes: u64,
}

impl ExpectedRequest {
    fn capture(request: &ProcessRequest, binding: ProcessExecutionBinding) -> Self {
        Self {
            binding,
            stdout_bytes: request.resource_limits().stdout_bytes(),
            stderr_bytes: request.resource_limits().stderr_bytes(),
        }
    }
}

enum ArtifactRoot {
    Native(SurveyStreamArtifactRoot),
    #[cfg(test)]
    Test(Arc<TestArtifactRoot>),
}

impl ArtifactRoot {
    fn create_stream_file(
        &self,
        file_name: &str,
    ) -> Result<ArtifactFile, SurveyStreamArtifactError> {
        match self {
            Self::Native(root) => root.create_stream_file(file_name).map(ArtifactFile::Native),
            #[cfg(test)]
            Self::Test(root) => root.create_stream_file(file_name).map(ArtifactFile::Test),
        }
    }

    fn reconcile_created_stream_file(
        &self,
        file_name: &str,
    ) -> Result<ArtifactFile, SurveyStreamArtifactError> {
        match self {
            Self::Native(root) => root
                .reconcile_created_stream_file(file_name)
                .map(ArtifactFile::Native),
            #[cfg(test)]
            Self::Test(root) => root
                .reconcile_created_stream_file(file_name)
                .map(ArtifactFile::Test),
        }
    }
}

enum ArtifactFile {
    Native(SurveyStreamArtifact),
    #[cfg(test)]
    Test(TestArtifactFile),
}

impl ArtifactFile {
    fn append(
        &mut self,
        expected_offset: u64,
        bytes: &[u8],
        max_total_bytes: u64,
    ) -> Result<u64, SurveyStreamArtifactError> {
        match self {
            Self::Native(file) => file.append(expected_offset, bytes, max_total_bytes),
            #[cfg(test)]
            Self::Test(file) => file.append(expected_offset, bytes, max_total_bytes),
        }
    }

    fn readback(
        &mut self,
        max_total_bytes: u64,
        close_writer: bool,
    ) -> Result<ArtifactProof, SurveyStreamArtifactError> {
        match self {
            Self::Native(file) => file
                .readback(max_total_bytes, close_writer)
                .map(ArtifactProof::from_native),
            #[cfg(test)]
            Self::Test(file) => file.readback(max_total_bytes, close_writer),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArtifactProof {
    locator: String,
    ready_receipt_ref: String,
    file_identity: FileIdentity,
    byte_length: u64,
    sha256: String,
}

impl ArtifactProof {
    fn from_native(readback: SurveyStreamArtifactReadback) -> Self {
        Self {
            locator: readback.locator,
            ready_receipt_ref: readback.ready_receipt_ref,
            file_identity: readback.file_identity,
            byte_length: readback.byte_length,
            sha256: readback.sha256,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionPhase {
    Opening,
    Open,
    Refused,
    Unknown,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenAction {
    AlreadyReady,
    AlreadyPending,
    Create,
    Reconcile,
}

struct BlockingCall<T> {
    worker: JoinHandle<Result<T, ProcessStreamSinkError>>,
    timed_out: Arc<AtomicBool>,
    runtime: Handle,
}

struct WaitCompletionGuard {
    timed_out: Arc<AtomicBool>,
    finished: bool,
}

impl Drop for WaitCompletionGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.timed_out.store(true, Ordering::Release);
        }
    }
}

struct InFlightGuard(Arc<AtomicUsize>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct SessionRecord {
    session: ProcessStreamSinkSession,
    file_name: String,
    artifact: Option<ArtifactFile>,
    phase: SessionPhase,
    next_sequence: u64,
    next_offset: u64,
    admitted_hasher: Sha256,
    preview: Vec<u8>,
    receipts: HashMap<u64, AppendReceipt>,
    pending_append: Option<PendingAppend>,
    late_append: Option<PendingAppend>,
    late_proof: Option<ArtifactProof>,
    pending_terminal: Option<PendingTerminal>,
    terminal_command: Option<PendingTerminal>,
    terminal: Option<ProcessStreamSinkTerminal>,
    unknown_outcome: Option<ProcessStreamSinkUnknownOutcome>,
    primary_failure: Option<Failure>,
    object_identity: Option<(String, FileIdentity)>,
    closed_proof: Option<ArtifactProof>,
}

impl SessionRecord {
    fn new(session: ProcessStreamSinkSession, file_name: String) -> Self {
        Self {
            session,
            file_name,
            artifact: None,
            phase: SessionPhase::Open,
            next_sequence: 0,
            next_offset: 0,
            admitted_hasher: Sha256::new(),
            preview: Vec::new(),
            receipts: HashMap::new(),
            pending_append: None,
            late_append: None,
            late_proof: None,
            pending_terminal: None,
            terminal_command: None,
            terminal: None,
            unknown_outcome: None,
            primary_failure: None,
            object_identity: None,
            closed_proof: None,
        }
    }

    fn admitted_sha256(&self) -> String {
        digest_hex(&self.admitted_hasher)
    }

    fn policy_retains_raw_source(&self) -> bool {
        self.session.policy().retention_ref() != P04_BOUNDED_PREFIX_RETENTION
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AppendReceipt {
    offset: u64,
    byte_length: u64,
    sha256: String,
}

struct PendingAppend {
    sequence: u64,
    offset: u64,
    byte_length: u64,
    sha256: String,
    candidate_sha256: String,
    candidate_hasher: Sha256,
    candidate_preview: Vec<u8>,
    acknowledgement_deadline: Instant,
    acknowledgement_expired: Arc<AtomicBool>,
}

struct PendingAppendTicket {
    sequence: u64,
    offset: u64,
    byte_length: u64,
    sha256: String,
    candidate_sha256: String,
}

impl PendingAppendTicket {
    fn from_candidate(candidate: &PendingAppend) -> Self {
        Self {
            sequence: candidate.sequence,
            offset: candidate.offset,
            byte_length: candidate.byte_length,
            sha256: candidate.sha256.clone(),
            candidate_sha256: candidate.candidate_sha256.clone(),
        }
    }

    fn matches(&self, candidate: &PendingAppend) -> bool {
        self.sequence == candidate.sequence
            && self.offset == candidate.offset
            && self.byte_length == candidate.byte_length
            && self.sha256 == candidate.sha256
            && self.candidate_sha256 == candidate.candidate_sha256
    }
}

enum AppendWorkerResult {
    NeedsAcknowledgement(PendingAppendTicket),
    Disposition(ProcessStreamSinkAppendDisposition),
}

#[derive(Clone)]
enum PendingTerminal {
    Finalize(ProcessStreamSinkFinalizeRequest),
    Abort(ProcessStreamSinkAbortRequest),
}

impl PendingTerminal {
    fn identity(&self) -> Result<ProcessStreamSinkTerminalCommandIdentity, ProcessStreamSinkError> {
        match self {
            Self::Finalize(request) => request.command_identity(),
            Self::Abort(request) => request.command_identity(),
        }
    }
}

enum TerminalCommand {
    Finalize(ProcessStreamSinkFinalizeRequest),
    Abort(ProcessStreamSinkAbortRequest),
}

#[derive(Clone, Debug)]
enum Failure {
    Native(SurveyStreamArtifactError),
    Sink(ProcessStreamSinkError),
    Invariant(&'static str),
}

impl Failure {
    fn as_sink_error(&self) -> ProcessStreamSinkError {
        match self {
            Self::Native(SurveyStreamArtifactError::ExistingArtifact) => {
                ProcessStreamSinkError::SourceMismatch
            }
            Self::Native(SurveyStreamArtifactError::InvalidInput) => {
                ProcessStreamSinkError::InvalidRequest {
                    reason: "native stream artifact input is invalid",
                }
            }
            Self::Native(
                SurveyStreamArtifactError::UnsupportedPlatform
                | SurveyStreamArtifactError::IdentityMismatch
                | SurveyStreamArtifactError::SecurityMismatch
                | SurveyStreamArtifactError::NativeIo,
            ) => ProcessStreamSinkError::ProviderUnavailable,
            Self::Sink(error) => error.clone(),
            Self::Invariant(_) => ProcessStreamSinkError::ProviderUnavailable,
        }
    }
}

fn lock_sessions(
    sessions: &Mutex<HashMap<ProcessStreamSinkSessionId, SessionRecord>>,
) -> MutexGuard<'_, HashMap<ProcessStreamSinkSessionId, SessionRecord>> {
    sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn try_lock_sessions(
    sessions: &Mutex<HashMap<ProcessStreamSinkSessionId, SessionRecord>>,
) -> Result<
    MutexGuard<'_, HashMap<ProcessStreamSinkSessionId, SessionRecord>>,
    ProcessStreamSinkError,
> {
    match sessions.try_lock() {
        Ok(guard) => Ok(guard),
        Err(std::sync::TryLockError::Poisoned(error)) => Ok(error.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => {
            Err(ProcessStreamSinkError::ProviderUnavailable)
        }
    }
}

fn lock_owner_gate(gate: &Mutex<bool>) -> MutexGuard<'_, bool> {
    gate.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn try_lock_owner_gate(gate: &Mutex<bool>) -> Result<MutexGuard<'_, bool>, ProcessStreamSinkError> {
    match gate.try_lock() {
        Ok(guard) => Ok(guard),
        Err(std::sync::TryLockError::Poisoned(error)) => Ok(error.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => {
            Err(ProcessStreamSinkError::ProviderUnavailable)
        }
    }
}

fn require_exact_session(
    record: &SessionRecord,
    supplied: &ProcessStreamSinkSession,
) -> Result<(), ProcessStreamSinkError> {
    if record.session == *supplied {
        Ok(())
    } else {
        Err(ProcessStreamSinkError::SessionMismatch)
    }
}

fn p04_sink_identity(
    binding: &ProcessExecutionBinding,
    stream: ProcessStreamKind,
    role: &str,
) -> String {
    let stream = match stream {
        ProcessStreamKind::Stdout => "stdout",
        ProcessStreamKind::Stderr => "stderr",
    };
    let operation = binding.operation_id().as_str();
    let full = format!("p04-sink:{operation}:{stream}:{role}");
    if full.len() <= 256 {
        full
    } else {
        format!(
            "p04-sink:{}:{stream}:{role}",
            sha256_hex(operation.as_bytes())
        )
    }
}

fn artifact_file_name(
    stream: ProcessStreamKind,
    session_id: &ProcessStreamSinkSessionId,
) -> String {
    let label = match stream {
        ProcessStreamKind::Stdout => "stdout",
        ProcessStreamKind::Stderr => "stderr",
    };
    let digest = sha256_hex(format!("{}-{label}", session_id.as_str()).as_bytes());
    format!("{digest}-{label}.raw")
}

fn digest_hex(hasher: &Sha256) -> String {
    format!("{:x}", hasher.clone().finalize())
}

fn preview_extension(existing: &[u8], bytes: &[u8], ceiling: u64) -> Vec<u8> {
    let ceiling = usize::try_from(ceiling).unwrap_or(usize::MAX);
    let take = ceiling.saturating_sub(existing.len()).min(bytes.len());
    let mut preview = Vec::with_capacity(existing.len().saturating_add(take));
    preview.extend_from_slice(existing);
    preview.extend_from_slice(&bytes[..take]);
    preview
}

fn admit_append(record: &mut SessionRecord, append: PendingAppend) {
    record.next_sequence = append.sequence;
    record.next_offset = append.offset.saturating_add(append.byte_length);
    record.admitted_hasher = append.candidate_hasher;
    record.preview = append.candidate_preview;
    record.receipts.insert(
        append.sequence,
        AppendReceipt {
            offset: append.offset,
            byte_length: append.byte_length,
            sha256: append.sha256,
        },
    );
    record.phase = SessionPhase::Open;
    record.pending_append = None;
    record.unknown_outcome = None;
}

fn validate_terminal_counters(
    record: &SessionRecord,
    expected_sequence: u64,
    expected_offset: u64,
    observed_sha256: &str,
    observed_bytes: u64,
) -> Result<(), ProcessStreamSinkError> {
    if expected_sequence != record.next_sequence {
        return Err(ProcessStreamSinkError::SequenceGap {
            expected: record.next_sequence,
            observed: expected_sequence,
        });
    }
    if expected_offset != record.next_offset {
        return Err(ProcessStreamSinkError::OffsetMismatch {
            expected: record.next_offset,
            observed: expected_offset,
        });
    }
    if observed_bytes != record.next_offset || observed_sha256 != record.admitted_sha256() {
        return Err(ProcessStreamSinkError::EvidenceInvariant {
            reason: "terminal must identify the exact admitted transport prefix".to_owned(),
        });
    }
    Ok(())
}

fn begin_terminal(
    record: &mut SessionRecord,
    command: PendingTerminal,
    identity: ProcessStreamSinkTerminalCommandIdentity,
) -> Result<(), ProcessStreamSinkError> {
    if let Some(existing) = record.pending_terminal.as_ref() {
        if existing.identity()? != identity {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        return Ok(());
    }
    if let Some(existing) = record.terminal_command.as_ref() {
        if existing.identity()? != identity {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        return Ok(());
    }
    record.pending_terminal = Some(command);
    Ok(())
}

fn terminal_for_command(
    record: &SessionRecord,
    identity: &ProcessStreamSinkTerminalCommandIdentity,
) -> Result<Option<ProcessStreamSinkTerminal>, ProcessStreamSinkError> {
    if let Some(terminal) = &record.terminal {
        let retained = record
            .terminal_command
            .as_ref()
            .ok_or(ProcessStreamSinkError::TerminalIdentityConflict)?;
        if retained.identity()? != *identity {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        return Ok(Some(terminal.clone()));
    }
    if let Some(pending) = &record.pending_terminal
        && pending.identity()? != *identity
    {
        return Err(ProcessStreamSinkError::TerminalIdentityConflict);
    }
    Ok(None)
}

fn verify_stable_object(
    record: &mut SessionRecord,
    proof: &ArtifactProof,
) -> Result<(), ProcessStreamSinkError> {
    if record.object_identity.is_none() {
        record.object_identity = Some((proof.locator.clone(), proof.file_identity));
    }
    verify_existing_stable_object(record, proof)
}

fn verify_existing_stable_object(
    record: &SessionRecord,
    proof: &ArtifactProof,
) -> Result<(), ProcessStreamSinkError> {
    match &record.object_identity {
        Some((locator, identity))
            if locator != &proof.locator || identity != &proof.file_identity =>
        {
            Err(ProcessStreamSinkError::SourceMismatch)
        }
        Some(_) => Ok(()),
        None => Err(ProcessStreamSinkError::SourceMismatch),
    }
}

fn matches_late_tail(record: &SessionRecord, proof: &ArtifactProof) -> bool {
    let Some(late) = record.late_append.as_ref() else {
        return false;
    };
    record.late_proof.as_ref().is_some_and(|original| {
        original.locator == proof.locator
            && original.file_identity == proof.file_identity
            && original.byte_length == proof.byte_length
            && original.sha256 == proof.sha256
    }) && proof.byte_length == late.offset.saturating_add(late.byte_length)
        && proof.sha256 == late.candidate_sha256
}

fn mark_unknown(record: &mut SessionRecord, evidence: &str) -> Result<(), ProcessStreamSinkError> {
    if record.unknown_outcome.is_some() {
        record.phase = SessionPhase::Unknown;
        return Ok(());
    }
    let primary = record.primary_failure.as_ref().map_or_else(
        || "unclassified".to_owned(),
        |failure| format!("{failure:?}"),
    );
    let uncertainty = sha256_hex(
        format!(
            "{}:{primary}:{evidence}",
            record.session.open_request_sha256()
        )
        .as_bytes(),
    );
    let outcome = ProcessStreamSinkUnknownOutcome::new(
        record.session.session_id().clone(),
        record.session.terminal_id().clone(),
        record.session.open_request_sha256(),
        uncertainty,
    )?;
    record.phase = SessionPhase::Unknown;
    record.unknown_outcome = Some(outcome);
    Ok(())
}

fn unknown_readback(
    record: &SessionRecord,
) -> Result<ProcessStreamSinkReadback, ProcessStreamSinkError> {
    let outcome = record
        .unknown_outcome
        .clone()
        .ok_or(ProcessStreamSinkError::TerminalIdentityConflict)?;
    Ok(ProcessStreamSinkReadback::UnknownOutcome { outcome })
}

fn session_view(
    record: &SessionRecord,
) -> Result<ProcessStreamSinkSessionView, ProcessStreamSinkError> {
    ProcessStreamSinkSessionView::new(
        record.session.session_id().clone(),
        record.session.source_id().clone(),
        record.session.terminal_id().clone(),
        ProcessStreamSinkState::Open,
        record.next_sequence,
        record.next_offset,
        record.next_sequence,
        record.next_offset,
        record.admitted_sha256(),
        record.session.open_request_sha256(),
        None,
    )
}

fn owner_release_error(record: &SessionRecord, detail: &str) -> InstallationSurveyStreamSinkError {
    let cause = record.primary_failure.as_ref().map_or_else(
        || "none retained".to_owned(),
        |failure| format!("{failure:?}"),
    );
    InstallationSurveyStreamSinkError::new(format!(
        "survey stream {} cannot release its original owner: {detail}; primary cause: {cause}",
        record.session.session_id().as_str()
    ))
}

fn terminal_has_persistence_gap(terminal: &ProcessStreamSinkTerminal) -> bool {
    terminal.evidence().gaps().iter().any(|gap| {
        matches!(
            gap,
            StreamEvidenceGap::PersistenceUnavailable | StreamEvidenceGap::PersistenceBackpressure
        )
    })
}

#[cfg(test)]
fn mutex_lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
struct TestArtifactRoot {
    files: Mutex<HashMap<String, Arc<Mutex<TestArtifactState>>>>,
    controls: Mutex<TestArtifactControls>,
}

#[cfg(test)]
#[derive(Default)]
struct TestArtifactControls {
    fail_create_after_effect: bool,
    fail_reconcile: bool,
    fail_append_after_effect: bool,
    delay_next_append_ms: u64,
    append_barrier: Option<Arc<std::sync::Barrier>>,
}

#[cfg(test)]
struct TestArtifactState {
    bytes: Vec<u8>,
    identity: FileIdentity,
    locator: String,
    closed: bool,
}

#[cfg(test)]
struct TestArtifactFile {
    state: Arc<Mutex<TestArtifactState>>,
    root: Arc<TestArtifactRoot>,
}

#[cfg(test)]
impl TestArtifactRoot {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            files: Mutex::new(HashMap::new()),
            controls: Mutex::new(TestArtifactControls::default()),
        })
    }

    fn create_stream_file(
        self: &Arc<Self>,
        file_name: &str,
    ) -> Result<TestArtifactFile, SurveyStreamArtifactError> {
        let mut files = mutex_lock_recover(&self.files);
        if files.contains_key(file_name) {
            return Err(SurveyStreamArtifactError::ExistingArtifact);
        }
        let digest = sha256_hex(file_name.as_bytes());
        let index = u64::from_str_radix(&digest[..16], 16).unwrap_or(1);
        let state = Arc::new(Mutex::new(TestArtifactState {
            bytes: Vec::new(),
            identity: FileIdentity {
                volume_serial_number: 1,
                file_index: index,
            },
            locator: format!("native-artifact:test-root/{file_name}"),
            closed: false,
        }));
        files.insert(file_name.to_owned(), Arc::clone(&state));
        drop(files);
        let fail = {
            let mut controls = mutex_lock_recover(&self.controls);
            std::mem::take(&mut controls.fail_create_after_effect)
        };
        if fail {
            return Err(SurveyStreamArtifactError::NativeIo);
        }
        Ok(TestArtifactFile {
            state,
            root: Arc::clone(self),
        })
    }

    fn reconcile_created_stream_file(
        self: &Arc<Self>,
        file_name: &str,
    ) -> Result<TestArtifactFile, SurveyStreamArtifactError> {
        if mutex_lock_recover(&self.controls).fail_reconcile {
            return Err(SurveyStreamArtifactError::NativeIo);
        }
        let state = mutex_lock_recover(&self.files)
            .get(file_name)
            .cloned()
            .ok_or(SurveyStreamArtifactError::IdentityMismatch)?;
        Ok(TestArtifactFile {
            state,
            root: Arc::clone(self),
        })
    }
}

#[cfg(test)]
impl TestArtifactFile {
    fn append(
        &mut self,
        expected_offset: u64,
        bytes: &[u8],
        max_total_bytes: u64,
    ) -> Result<u64, SurveyStreamArtifactError> {
        let mut state = mutex_lock_recover(&self.state);
        if state.closed
            || u64::try_from(state.bytes.len()).ok() != Some(expected_offset)
            || expected_offset.saturating_add(bytes.len() as u64) > max_total_bytes
        {
            return Err(SurveyStreamArtifactError::InvalidInput);
        }
        state.bytes.extend_from_slice(bytes);
        let length = state.bytes.len() as u64;
        drop(state);
        let (fail, delay_ms, barrier) = {
            let mut controls = mutex_lock_recover(&self.root.controls);
            let fail = std::mem::take(&mut controls.fail_append_after_effect);
            let delay_ms = std::mem::take(&mut controls.delay_next_append_ms);
            (fail, delay_ms, controls.append_barrier.take())
        };
        if let Some(barrier) = barrier {
            barrier.wait();
        }
        if delay_ms != 0 {
            std::thread::sleep(Duration::from_millis(delay_ms));
        }
        if fail {
            Err(SurveyStreamArtifactError::NativeIo)
        } else {
            Ok(length)
        }
    }

    fn readback(
        &mut self,
        max_total_bytes: u64,
        close_writer: bool,
    ) -> Result<ArtifactProof, SurveyStreamArtifactError> {
        let mut state = mutex_lock_recover(&self.state);
        if state.bytes.len() as u64 > max_total_bytes {
            return Err(SurveyStreamArtifactError::InvalidInput);
        }
        if close_writer {
            state.closed = true;
        }
        let byte_length = state.bytes.len() as u64;
        let sha256 = sha256_hex(&state.bytes);
        let proof = ArtifactProof {
            locator: state.locator.clone(),
            ready_receipt_ref: format!(
                "native-readback:{:016x}-{:016x}:{byte_length}:{sha256}",
                state.identity.volume_serial_number, state.identity.file_index
            ),
            file_identity: state.identity,
            byte_length,
            sha256,
        };
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::future::Future;
    use std::num::NonZeroU64;
    use std::task::{Context, Poll, Waker};

    use eliot_contracts::{EpochId, EpochLineageId};
    use eliot_platform::ClockObservation;
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
        EnvironmentInheritance, EnvironmentProjection, FencingToken, Generation, ImageId, JobId,
        KernelDispatchKey, OperationId, PermitIssuance, PhysicalProcessBinding, ProcessId,
        ProcessIntent, ProcessRequest, ProcessStreamDigestAlgorithm, ProcessTreeId, ResourceLimits,
        SessionId, StreamEvidenceGap, SuspendedProcessIdentity,
    };

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;
    const TEST_EXECUTABLE: &str = r"C:\tools\survey-probe.exe";
    const TEST_EXECUTABLE_SHA256: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn drive<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        loop {
            if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return value;
            }
        }
    }

    fn process_request_and_binding(
        operation: &str,
        max_stream_bytes: u64,
    ) -> TestResult<(ProcessRequest, ProcessExecutionBinding)> {
        let generation = Generation::new(1)?;
        let operation_id = OperationId::new(operation)?;
        let tree_id = ProcessTreeId::new(format!("{operation}-tree"))?;
        let job_id = JobId::new(format!("{operation}-job"))?;
        let image_id = ImageId::new("file-identity:survey-test")?;
        let session_id = SessionId::new(format!("{operation}-session"))?;
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?,
            NonZeroU64::new(7)
                .ok_or_else(|| std::io::Error::other("test epoch must be non-zero"))?,
        )?;
        let fence = FencingToken::new(epoch.clone(), generation, "survey-sink-test-fence")?;
        let intent = ProcessIntent::new(
            operation_id,
            tree_id.clone(),
            job_id.clone(),
            image_id.clone(),
            session_id.clone(),
            generation,
            TEST_EXECUTABLE,
            TEST_EXECUTABLE_SHA256,
            vec!["--version".to_owned()],
            r"C:\eliot\survey-probe-working",
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)?,
            ResourceLimits::new(
                10_000,
                Some(5_000),
                Some(1_048_576),
                max_stream_bytes,
                max_stream_bytes,
                0,
            )?,
        )?;
        let revision_heads = BTreeMap::from([
            ("authority".to_owned(), "a".repeat(64)),
            ("state".to_owned(), "b".repeat(64)),
        ]);
        let authority_id = DispatchAuthorityId::new("survey-sink-test-authority")?;
        let mut sealed_authority = DispatchPermitAuthority::activate(
            authority_id,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let mut validating_authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("survey-sink-test-authority")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let issuance = || -> TestResult<PermitIssuance> {
            Ok(PermitIssuance::new_with_validation_revision(
                ActionLeaseRef::new("survey-sink-test-lease")?,
                fence.clone(),
                revision_heads.clone(),
                100,
                200,
                "survey-sink-test-nonce",
                41,
            )?)
        };
        let sealed_permit = sealed_authority.issue(&intent, issuance()?)?;
        let validating_permit = validating_authority.issue(&intent, issuance()?)?;
        let sealed_request = ProcessRequest::new(intent.clone(), sealed_permit)?;
        let validating_request = ProcessRequest::new(intent.clone(), validating_permit)?;
        let suspended = SuspendedProcessIdentity::new(
            ProcessId::new(format!("{operation}-pid"))?,
            tree_id,
            job_id,
            image_id,
            session_id,
            generation,
            PhysicalProcessBinding::new(
                4242,
                11,
                TEST_EXECUTABLE,
                r"Local\Eliot-Survey-Sink-Test",
            )?,
            120,
            TEST_EXECUTABLE_SHA256,
        )?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence.clone(),
            epoch,
            revision_heads,
            41,
        )?;
        let validated =
            validating_authority.validate_and_consume(validating_request, suspended, &context)?;
        Ok((sealed_request, validated.binding().clone()))
    }

    fn policy() -> TestResult<ProcessStreamPolicyBinding> {
        Ok(ProcessStreamPolicyBinding::new(
            "policy:survey-test",
            "privacy:survey-output",
            "visibility:authenticated-session",
            "retention:created-by-transaction",
            "redaction:raw-transport-v1",
        )?)
    }

    fn limits(total: u64) -> TestResult<ProcessStreamSinkLimits> {
        let chunk = total.min(8).max(1);
        Ok(ProcessStreamSinkLimits::new(
            chunk,
            total,
            2_048,
            total.min(16),
            8,
            total.min(64).max(chunk),
            250,
            2_000,
            2_000,
        )?)
    }

    fn open_request(
        binding: ProcessExecutionBinding,
        policy: ProcessStreamPolicyBinding,
        max_bytes: u64,
    ) -> TestResult<ProcessStreamSinkOpenRequest> {
        let stream = ProcessStreamKind::Stdout;
        Ok(ProcessStreamSinkOpenRequest::new(
            ProcessStreamSinkSessionId::new(p04_sink_identity(&binding, stream, "session"))?,
            eliot_process::ProcessStreamSinkSourceId::new(p04_sink_identity(
                &binding, stream, "source",
            ))?,
            eliot_process::ProcessStreamSinkTerminalId::new(p04_sink_identity(
                &binding, stream, "terminal",
            ))?,
            binding,
            stream,
            policy,
            limits(max_bytes)?,
            ProcessStreamDigestAlgorithm::Sha256,
            ProcessStreamDigestAlgorithm::Sha256,
        )?)
    }

    fn test_sink(
        request: &ProcessRequest,
        policy: ProcessStreamPolicyBinding,
        root: Arc<TestArtifactRoot>,
    ) -> TestResult<InstallationSurveyStreamSink> {
        Ok(InstallationSurveyStreamSink {
            core: Arc::new(StreamSinkCore::from_parts(
                None,
                ArtifactRoot::Test(root),
                ExpectedRequest::capture(request, request.expected_execution_binding()?),
                policy,
                test_runtime().handle().clone(),
            )),
        })
    }

    fn test_runtime() -> &'static tokio::runtime::Runtime {
        static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
        RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap_or_else(|error| panic!("test runtime creation failed: {error}"))
        })
    }

    fn finalize_request(
        session: &ProcessStreamSinkSession,
        sequence: u64,
        bytes: &[u8],
        gaps: Vec<StreamEvidenceGap>,
    ) -> TestResult<ProcessStreamSinkFinalizeRequest> {
        Ok(ProcessStreamSinkFinalizeRequest::new(
            session.terminal_id().clone(),
            sequence,
            bytes.len() as u64,
            session.limits().max_finalize_wait_ms(),
            StreamTransportStatus::Complete,
            sha256_hex(bytes),
            bytes.len() as u64,
            ProcessStreamPrefixPreview::from_transport_prefix(bytes.to_vec(), bytes.len() as u64)?,
            None,
            gaps,
        )?)
    }

    #[test]
    fn complete_and_zero_byte_streams_use_actual_readback_proofs() -> TestResult {
        let (request, binding) = process_request_and_binding("survey-sink-bytes", 128)?;
        let stream_policy = policy()?;
        let root = TestArtifactRoot::new();
        let sink = test_sink(&request, stream_policy.clone(), Arc::clone(&root))?;
        let session = drive(sink.open(open_request(binding, stream_policy, 128)?))?;
        let chunk = ProcessStreamSinkAppend::from_bytes(1, 0, b"version ".to_vec(), 250);
        assert!(matches!(
            drive(sink.append(session.clone(), chunk))?,
            ProcessStreamSinkAppendDisposition::Accepted {
                next_sequence: 1,
                next_offset: 8
            }
        ));
        let chunk = ProcessStreamSinkAppend::from_bytes(2, 8, b"1\n".to_vec(), 250);
        assert!(matches!(
            drive(sink.append(session.clone(), chunk))?,
            ProcessStreamSinkAppendDisposition::Accepted {
                next_sequence: 2,
                next_offset: 10
            }
        ));
        let terminal = drive(sink.finalize(
            session.clone(),
            finalize_request(&session, 2, b"version 1\n", Vec::new())?,
        ))?;
        assert_eq!(terminal.state(), ProcessStreamSinkState::CompleteSource);
        assert_eq!(
            terminal
                .evidence()
                .source()
                .map(DurableProcessStreamSource::byte_length),
            Some(10)
        );
        sink.reconcile_for_owner_release()?;

        let (empty_request, empty_binding) = process_request_and_binding("survey-sink-empty", 128)?;
        let empty_policy = policy()?;
        let empty_sink = test_sink(&empty_request, empty_policy.clone(), root)?;
        let empty_session =
            drive(empty_sink.open(open_request(empty_binding, empty_policy, 128)?))?;
        let empty_terminal = drive(empty_sink.finalize(
            empty_session.clone(),
            finalize_request(&empty_session, 0, b"", Vec::new())?,
        ))?;
        assert_eq!(
            empty_terminal.state(),
            ProcessStreamSinkState::CompleteSource
        );
        assert_eq!(empty_terminal.evidence().observed_bytes(), 0);
        empty_sink.reconcile_for_owner_release()?;
        Ok(())
    }

    #[test]
    fn gaps_offsets_foreign_bindings_and_bounded_prefix_policy_fail_closed() -> TestResult {
        let (request, binding) = process_request_and_binding("survey-sink-gaps", 128)?;
        let policy = policy()?;
        let root = TestArtifactRoot::new();
        let sink = test_sink(&request, policy.clone(), Arc::clone(&root))?;
        let session = drive(sink.open(open_request(binding.clone(), policy.clone(), 128)?))?;
        let sequence_gap = ProcessStreamSinkAppend::from_bytes(2, 0, b"a".to_vec(), 250);
        assert!(matches!(
            drive(sink.append(session.clone(), sequence_gap)),
            Err(ProcessStreamSinkError::SequenceGap {
                expected: 1,
                observed: 2
            })
        ));
        let offset_gap = ProcessStreamSinkAppend::from_bytes(1, 1, b"a".to_vec(), 250);
        assert!(matches!(
            drive(sink.append(session.clone(), offset_gap)),
            Err(ProcessStreamSinkError::OffsetMismatch {
                expected: 0,
                observed: 1
            })
        ));

        let foreign = process_request_and_binding("survey-sink-foreign", 128)?.1;
        assert!(matches!(
            drive(sink.open(open_request(foreign, policy.clone(), 128)?)),
            Err(ProcessStreamSinkError::BindingMismatch)
        ));
        assert_eq!(mutex_lock_recover(&root.files).len(), 1);

        for (field, replacement) in [
            ("action_lease_ref", serde_json::json!("foreign-lease")),
            ("authority_id", serde_json::json!("foreign-authority")),
            ("validation_revision", serde_json::json!(42)),
        ] {
            let mut wire = serde_json::to_value(&binding)?;
            wire[field] = replacement;
            let substituted: ProcessExecutionBinding = serde_json::from_value(wire)?;
            assert!(matches!(
                drive(sink.open(open_request(substituted, policy.clone(), 128,)?)),
                Err(ProcessStreamSinkError::BindingMismatch)
            ));
            assert_eq!(mutex_lock_recover(&root.files).len(), 1);
        }

        let bounded_policy = ProcessStreamPolicyBinding::new(
            "p04:stream-policy:transport-preview-v1",
            "privacy:survey-output",
            "visibility:authenticated-session",
            P04_BOUNDED_PREFIX_RETENTION,
            "redaction:raw-transport-v1",
        )?;
        let bounded_sink = test_sink(&request, bounded_policy.clone(), Arc::clone(&root))?;
        assert!(matches!(
            drive(bounded_sink.open(open_request(binding, bounded_policy, 128)?)),
            Err(ProcessStreamSinkError::InvalidRequest { .. })
        ));
        assert_eq!(mutex_lock_recover(&root.files).len(), 1);

        let accepted = ProcessStreamSinkAppend::from_bytes(1, 0, b"a".to_vec(), 250);
        assert!(matches!(
            drive(sink.append(session.clone(), accepted))?,
            ProcessStreamSinkAppendDisposition::Accepted { .. }
        ));
        let terminal = drive(sink.finalize(
            session.clone(),
            finalize_request(
                &session,
                1,
                b"a",
                vec![
                    StreamEvidenceGap::PersistenceUnavailable,
                    StreamEvidenceGap::PersistenceBackpressure,
                ],
            )?,
        ))?;
        assert_eq!(terminal.state(), ProcessStreamSinkState::SourceUnavailable);
        assert!(terminal.evidence().source().is_none());
        sink.reconcile_for_owner_release()?;
        Ok(())
    }

    #[test]
    fn uncertain_create_keeps_the_original_typed_session_until_reconciled() -> TestResult {
        let (request, binding) = process_request_and_binding("survey-sink-unknown", 128)?;
        let policy = policy()?;
        let root = TestArtifactRoot::new();
        {
            let mut controls = mutex_lock_recover(&root.controls);
            controls.fail_create_after_effect = true;
            controls.fail_reconcile = true;
        }
        let sink = test_sink(&request, policy.clone(), Arc::clone(&root))?;
        let session = drive(sink.open(open_request(binding, policy, 128)?))?;
        let unknown = match drive(sink.readback(session.clone()))? {
            ProcessStreamSinkReadback::UnknownOutcome { outcome } => outcome,
            other => {
                return Err(std::io::Error::other(format!(
                    "expected typed unknown, got {other:?}"
                ))
                .into());
            }
        };
        unknown.validate_against_session(&session)?;
        assert!(sink.reconcile_for_owner_release().is_err());

        mutex_lock_recover(&root.controls).fail_reconcile = false;
        assert!(matches!(
            drive(sink.reconcile(session.clone(), unknown))?,
            ProcessStreamSinkReadback::Session { .. }
        ));
        let terminal = drive(sink.finalize(
            session.clone(),
            finalize_request(&session, 0, b"", Vec::new())?,
        ))?;
        assert_eq!(terminal.state(), ProcessStreamSinkState::CompleteSource);
        sink.reconcile_for_owner_release()?;
        Ok(())
    }

    #[test]
    fn delayed_native_append_settles_only_as_source_unavailable() -> TestResult {
        let (request, binding) = process_request_and_binding("survey-sink-deadline", 128)?;
        let policy = policy()?;
        let root = TestArtifactRoot::new();
        let sink = test_sink(&request, policy.clone(), Arc::clone(&root))?;
        let session = drive(sink.open(open_request(binding, policy, 128)?))?;
        let barrier = Arc::new(std::sync::Barrier::new(2));
        {
            let mut controls = mutex_lock_recover(&root.controls);
            controls.delay_next_append_ms = 400;
            controls.append_barrier = Some(Arc::clone(&barrier));
        }
        let mut append_future = Box::pin(sink.append(
            session.clone(),
            ProcessStreamSinkAppend::from_bytes(1, 0, b"x".to_vec(), 250),
        ));
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(
            append_future.as_mut().poll(&mut context),
            Poll::Pending
        ));
        barrier.wait();
        let disposition = drive(append_future)?;
        assert_eq!(
            disposition,
            ProcessStreamSinkAppendDisposition::DeadlineExceeded
        );
        assert!(sink.reconcile_for_owner_release().is_err());

        // The caller's wait ended while the blocking worker still owned the
        // original session. Let that bounded fixture finish before asking the
        // six-method port to reconcile its retained physical outcome.
        std::thread::sleep(Duration::from_millis(300));
        let readback = drive(sink.readback(session.clone()))?;
        match readback {
            ProcessStreamSinkReadback::Session { view }
                if view.next_sequence() == 0 && view.next_offset() == 0 => {}
            other => {
                return Err(std::io::Error::other(format!(
                    "expected settled acknowledged prefix after a late append, got {other:?}"
                ))
                .into());
            }
        }
        let terminal = drive(sink.finalize(
            session.clone(),
            finalize_request(
                &session,
                0,
                b"",
                vec![StreamEvidenceGap::PersistenceBackpressure],
            )?,
        ))?;
        assert_eq!(terminal.state(), ProcessStreamSinkState::SourceUnavailable);
        assert!(terminal.evidence().source().is_none());
        sink.reconcile_for_owner_release()?;
        Ok(())
    }

    #[test]
    fn delayed_client_poll_cannot_ack_native_append_after_its_deadline() -> TestResult {
        let (request, binding) = process_request_and_binding("survey-sink-delayed-poll", 128)?;
        let policy = policy()?;
        let root = TestArtifactRoot::new();
        let sink = test_sink(&request, policy.clone(), Arc::clone(&root))?;
        let session = drive(sink.open(open_request(binding, policy, 128)?))?;
        let barrier = Arc::new(std::sync::Barrier::new(2));
        {
            let mut controls = mutex_lock_recover(&root.controls);
            controls.delay_next_append_ms = 10;
            controls.append_barrier = Some(Arc::clone(&barrier));
        }

        let mut append_future = Box::pin(sink.append(
            session.clone(),
            ProcessStreamSinkAppend::from_bytes(1, 0, b"late".to_vec(), 250),
        ));
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(
            append_future.as_mut().poll(&mut context),
            Poll::Pending
        ));
        // The fixture reaches this barrier after writing the candidate bytes.
        // The original caller then stays unpolled past its absolute deadline,
        // while the native worker returns and retains the unacknowledged result.
        barrier.wait();
        std::thread::sleep(Duration::from_millis(300));
        {
            let sessions = lock_sessions(&sink.core.sessions);
            let record = sessions
                .get(session.session_id())
                .ok_or_else(|| std::io::Error::other("original stream session was lost"))?;
            let pending = record
                .pending_append
                .as_ref()
                .ok_or_else(|| std::io::Error::other("native append did not finish"))?;
            assert!(!pending.acknowledgement_expired.load(Ordering::Acquire));
            assert_eq!(record.next_sequence, 0);
            assert_eq!(record.next_offset, 0);
        }
        assert_eq!(
            drive(append_future)?,
            ProcessStreamSinkAppendDisposition::DeadlineExceeded
        );
        assert!(sink.reconcile_for_owner_release().is_err());

        assert!(matches!(
            drive(sink.readback(session.clone()))?,
            ProcessStreamSinkReadback::Session { ref view }
                if view.next_sequence() == 0 && view.next_offset() == 0
        ));
        {
            let sessions = lock_sessions(&sink.core.sessions);
            let record = sessions
                .get(session.session_id())
                .ok_or_else(|| std::io::Error::other("original stream session was lost"))?;
            let late = record
                .late_append
                .as_ref()
                .ok_or_else(|| std::io::Error::other("late append outcome was not retained"))?;
            let proof = record
                .late_proof
                .as_ref()
                .ok_or_else(|| std::io::Error::other("late append readback was not retained"))?;
            assert_eq!(late.sequence, 1);
            assert_eq!(late.offset, 0);
            assert_eq!(late.byte_length, 4);
            assert_eq!(proof.byte_length, 4);
            assert_eq!(proof.sha256, sha256_hex(b"late"));
            assert!(matches_late_tail(record, proof));
            assert!(record.primary_failure.is_some());
        }
        let terminal = drive(sink.finalize(
            session.clone(),
            finalize_request(
                &session,
                0,
                b"",
                vec![StreamEvidenceGap::PersistenceBackpressure],
            )?,
        ))?;
        assert_eq!(terminal.state(), ProcessStreamSinkState::SourceUnavailable);
        assert!(terminal.evidence().source().is_none());
        {
            let sessions = lock_sessions(&sink.core.sessions);
            let record = sessions
                .get(session.session_id())
                .ok_or_else(|| std::io::Error::other("terminal stream session was lost"))?;
            let proof = record
                .closed_proof
                .as_ref()
                .ok_or_else(|| std::io::Error::other("closed native proof was not retained"))?;
            assert!(matches_late_tail(record, proof));
        }
        sink.reconcile_for_owner_release()?;
        Ok(())
    }

    #[test]
    fn delayed_native_append_cancellation_preserves_cancelled_state_and_releases_owner()
    -> TestResult {
        let (request, binding) = process_request_and_binding("survey-sink-cancel-deadline", 128)?;
        let policy = policy()?;
        let root = TestArtifactRoot::new();
        let sink = test_sink(&request, policy.clone(), Arc::clone(&root))?;
        let session = drive(sink.open(open_request(binding, policy, 128)?))?;
        let barrier = Arc::new(std::sync::Barrier::new(2));
        {
            let mut controls = mutex_lock_recover(&root.controls);
            controls.delay_next_append_ms = 400;
            controls.append_barrier = Some(Arc::clone(&barrier));
        }
        let mut append_future = Box::pin(sink.append(
            session.clone(),
            ProcessStreamSinkAppend::from_bytes(1, 0, b"x".to_vec(), 250),
        ));
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(
            append_future.as_mut().poll(&mut context),
            Poll::Pending
        ));
        barrier.wait();
        assert_eq!(
            drive(append_future)?,
            ProcessStreamSinkAppendDisposition::DeadlineExceeded
        );
        assert!(sink.reconcile_for_owner_release().is_err());

        std::thread::sleep(Duration::from_millis(300));
        assert!(matches!(
            drive(sink.readback(session.clone()))?,
            ProcessStreamSinkReadback::Session { .. }
        ));
        let abort = ProcessStreamSinkAbortRequest::new(
            session.terminal_id().clone(),
            ProcessStreamSinkAbortReason::Cancellation,
            0,
            0,
            session.limits().max_abort_wait_ms(),
            StreamTransportStatus::CancelledBeforeEof,
            sha256_hex(&[]),
            0,
            ProcessStreamPrefixPreview::from_transport_prefix(Vec::new(), 0)?,
            None,
            vec![
                StreamEvidenceGap::PersistenceBackpressure,
                StreamEvidenceGap::CancelledBeforeEof,
            ],
        )?;
        let terminal = drive(sink.abort(session.clone(), abort))?;
        assert_eq!(terminal.state(), ProcessStreamSinkState::Cancelled);
        assert_eq!(
            terminal.evidence().persistence(),
            StreamPersistenceStatus::SourceUnavailable
        );
        assert!(terminal.evidence().source().is_none());
        assert!(
            terminal
                .evidence()
                .gaps()
                .contains(&StreamEvidenceGap::PersistenceBackpressure)
        );
        {
            let sessions = lock_sessions(&sink.core.sessions);
            let record = sessions
                .get(session.session_id())
                .ok_or("cancelled session lost its retained record")?;
            assert!(record.primary_failure.is_some());
        }
        sink.reconcile_for_owner_release()?;
        Ok(())
    }
}
