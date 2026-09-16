//! P-04: the sole physical implementation of the provider-neutral process
//! contract.
//!
//! P-04 owns launch mechanics, stream draining, deadlines and Job-tree
//! observations.  It does not mint dispatch authority.  Authority is injected
//! through [`DispatchValidationPort`], whose production implementation is the
//! P-07 controller composition.  The port is intentionally narrower than a
//! P-03 issuer: it can only consume a caller-owned request against fresh
//! suspended-child evidence.

#![forbid(unsafe_code)]

use eliot_instrument_api::EvidenceAxes;
use eliot_process::{
    CancellationReceipt, CancellationRequest, ContractError, DescendantEvidence, ExitDisposition,
    ExitStatus, ImageId, JobId, OperationId, PhysicalProcessBinding, ProcessEvidence,
    ProcessEvidenceSink, ProcessExecutionBinding, ProcessExecutionError, ProcessExecutionView,
    ProcessExecutor, ProcessHealth, ProcessHealthStatus, ProcessId, ProcessLaunchAdmission,
    ProcessLifecycle, ProcessRequest, ProcessStartReceipt, ProcessState,
    ProcessStreamDigestAlgorithm, ProcessStreamEvidence, ProcessStreamKind,
    ProcessStreamPolicyBinding, ProcessStreamPrefixPreview, ProcessStreamSinkAbortReason,
    ProcessStreamSinkAbortRequest, ProcessStreamSinkAppend, ProcessStreamSinkAppendDisposition,
    ProcessStreamSinkClient, ProcessStreamSinkError, ProcessStreamSinkFinalizeRequest,
    ProcessStreamSinkLimits, ProcessStreamSinkOpenRequest, ProcessStreamSinkReadback,
    ProcessStreamSinkSession, ProcessStreamSinkSessionId, ProcessStreamSinkSourceId,
    ProcessStreamSinkState, ProcessStreamSinkTerminal, ProcessStreamSinkTerminalId, ProcessTreeId,
    SessionId, StreamEvidenceGap, StreamPersistenceStatus, StreamTransportStatus,
    SuspendedLaunchEvidence, SuspendedProcessIdentity, ValidatedDispatch,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::future::Future;
use std::io::Read as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use eliot_platform_windows::{
    JobObjectIdentity, JobObjectLimits, RunningJobChild, RunningJobObservation, SuspendedJobChild,
    SuspendedLaunchSpec, SuspendedProcessEvidence, SuspendedValidationError, TerminatedJobChild,
    cancel_capture_thread_io,
};

const DEFAULT_CAPTURE_LIMIT: usize = 16 * 1024 * 1024;
const EVIDENCE_PREVIEW_CEILING: usize = 16 * 1024 * 1024;
const JOB_TERMINATION_CODE: u32 = 0xE1_04;
const WATCH_INTERVAL: Duration = Duration::from_millis(25);
const STREAM_CHUNK_BYTES: usize = 8192;
const STREAM_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const STREAM_JOIN_POLL: Duration = Duration::from_millis(5);
/// Bounded sink-pressure isolation ceiling: bytes of observed stream after
/// which P-04 records that persistence pressure was shed while the pipe kept
/// draining. Sized well above the focused proof volumes so ordinary streams
/// never latch it, and far below any unbounded retention.
const SINK_BACKPRESSURE_IN_FLIGHT_BYTES: u64 = 64 * 1024;
static JOB_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Builds the #267 sink-port limits P-04 consumes as a bound and as the
/// [`StreamSinkPump`] session contract.
///
/// When a [`ProcessStreamSinkClient`] is attached, the drain path really calls
/// the port: one session open before the first admitted byte, one append per
/// [`STREAM_CHUNK_BYTES`] drain chunk, and exactly one finalize/abort. The
/// validated `max_in_flight_bytes` ceiling still parameterizes
/// [`CaptureSession`]'s overflow latch, and pipe draining never waits on
/// persistence beyond the single bounded provider call per chunk (backpressure
/// sheds the remainder with an explicit gap instead of blocking). With no sink
/// attached, persistence stays `SourceUnavailable` with no source locator, so
/// no `raw:*` handle is ever minted.
fn sink_backpressure_limits() -> Result<ProcessStreamSinkLimits, ProcessExecutionError> {
    ProcessStreamSinkLimits::new(
        u64::try_from(STREAM_CHUNK_BYTES).map_err(|_| ProcessExecutionError::UnknownOutcome)?,
        u64::try_from(EVIDENCE_PREVIEW_CEILING)
            .map_err(|_| ProcessExecutionError::UnknownOutcome)?,
        2_048,
        16 * 1024,
        8,
        SINK_BACKPRESSURE_IN_FLIGHT_BYTES,
        250,
        2_000,
        2_000,
    )
    .map_err(|_| ProcessExecutionError::UnknownOutcome)
}

/// Drives one already-resolved future to completion on the calling thread.
///
/// The drain/finalize path is synchronous, while the sink port is async; this
/// spins the future with `yield_now` and performs no sleeping, no retry, and
/// no I/O of its own. Provider-side time is bounded by the wait budget carried
/// in each sink request, never by this driver.
fn block_on_sink<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

/// Exact stream label bound into sink session identities.
fn sink_stream_label(kind: ProcessStreamKind) -> &'static str {
    match kind {
        ProcessStreamKind::Stdout => "stdout",
        ProcessStreamKind::Stderr => "stderr",
    }
}

/// Mints one deterministic sink identity for a bound stream.
///
/// The identity derives from the execution binding's operation id plus the
/// stream label, so cleanup/reopen re-issues the identical value and
/// reconciles the same session instead of minting a second receipt. When the
/// composed value would exceed the port's reference ceiling, the operation
/// fragment falls back to its SHA-256 (still deterministic, still unique).
fn sink_identity(binding: &ProcessExecutionBinding, kind: ProcessStreamKind, role: &str) -> String {
    let operation = binding.operation_id().as_str();
    let stream = sink_stream_label(kind);
    let full = format!("p04-sink:{operation}:{stream}:{role}");
    if full.len() <= 256 {
        return full;
    }
    format!(
        "p04-sink:{}:{stream}:{role}",
        short_digest(operation.as_bytes())
    )
}

/// Typed outcome of offering one drain chunk to the sink.
///
/// Every shed variant keeps the pipe draining: the chunk (and, once shedding
/// latches, every later chunk) is not admitted, the shed fact latches on the
/// pump, and the drain thread moves on with no retry loop and no sleep.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkAppendOutcome {
    /// The provider admitted every byte offered.
    Admitted,
    /// The provider reported backpressure; the remainder sheds with an
    /// explicit persistence gap.
    ShedBackpressure,
    /// The provider exceeded the typed wait budget; the remainder sheds.
    ShedTimeout,
    /// The provider reported cancellation; the remainder sheds.
    ShedCancelled,
    /// The provider already terminalized; the remainder sheds.
    ShedTerminal(ProcessStreamSinkState),
    /// The pump already sheds (or holds its terminal): the chunk was not
    /// offered and no provider I/O happened.
    ShedClosed,
}

/// Policy-bound streaming pump from the pipe drain into immutable evidence.
///
/// One pump owns exactly one stream of one operation. It opens its sink
/// session before the first admitted byte (binding, kind, policy, limits, and
/// deterministic identity), appends per drain chunk with the bounded wait
/// budget from the session limits, and settles exactly one
/// [`ProcessStreamSinkTerminal`] through finalize/abort (with a single
/// readback reconcile when the provider and the pump disagree about who
/// terminalized first). The terminal's evidence is the only durable record:
/// its source is `Some` exactly on complete/partial terminals and `None` with
/// an exact gap otherwise, and a policy-prohibited stream carries a withheld
/// preview so raw pre-policy bytes never enter the durable record.
///
/// Shedding is one-way: the first backpressure, timeout, cancellation, or
/// terminal disposition latches, and every later chunk is shed locally
/// without provider I/O. A provider error instead latches the failure flag
/// and fails the current offer, so the next chunk retries with a fresh
/// bounded call. Either way the admitted stream stays a contiguous prefix,
/// and the drain thread never blocks on persistence.
#[allow(
    clippy::struct_excessive_bools,
    reason = "shedding, backpressure, provider failure, cancellation, and prohibition are independent latch observations"
)]
pub struct StreamSinkPump {
    client: Arc<dyn ProcessStreamSinkClient>,
    binding: ProcessExecutionBinding,
    kind: ProcessStreamKind,
    policy: ProcessStreamPolicyBinding,
    limits: ProcessStreamSinkLimits,
    session: Option<ProcessStreamSinkSession>,
    next_sequence: u64,
    next_offset: u64,
    admitted_digest: Sha256,
    offered_bytes: u64,
    preview_prefix: Vec<u8>,
    preview_ceiling: usize,
    shedding: bool,
    backpressured: bool,
    provider_failed: bool,
    cancelled: bool,
    policy_prohibited: bool,
    terminal: Option<ProcessStreamSinkTerminal>,
}

impl StreamSinkPump {
    /// Binds one pump to its client and contract; no I/O happens here.
    ///
    /// [`Self::open`] must succeed before the first [`Self::append`].
    #[must_use]
    pub fn new(
        client: Arc<dyn ProcessStreamSinkClient>,
        binding: ProcessExecutionBinding,
        kind: ProcessStreamKind,
        policy: ProcessStreamPolicyBinding,
        limits: ProcessStreamSinkLimits,
    ) -> Self {
        let preview_ceiling = usize::try_from(limits.max_preview_bytes())
            .unwrap_or(usize::MAX)
            .clamp(1, EVIDENCE_PREVIEW_CEILING);
        Self {
            client,
            binding,
            kind,
            policy,
            limits,
            session: None,
            next_sequence: 0,
            next_offset: 0,
            admitted_digest: Sha256::new(),
            offered_bytes: 0,
            preview_prefix: Vec::new(),
            preview_ceiling,
            shedding: false,
            backpressured: false,
            provider_failed: false,
            cancelled: false,
            policy_prohibited: false,
            terminal: None,
        }
    }

    /// Opens the sink session before the first admitted byte.
    ///
    /// Idempotent for the bound contract: reopening re-issues the identical
    /// request (deterministic identity) and returns the same session instead
    /// of minting a second one.
    pub fn open(&mut self) -> Result<(), ProcessExecutionError> {
        if self.session.is_some() {
            return Ok(());
        }
        let request = ProcessStreamSinkOpenRequest::new(
            ProcessStreamSinkSessionId::new(sink_identity(&self.binding, self.kind, "session"))
                .map_err(|_| ProcessExecutionError::UnknownOutcome)?,
            ProcessStreamSinkSourceId::new(sink_identity(&self.binding, self.kind, "source"))
                .map_err(|_| ProcessExecutionError::UnknownOutcome)?,
            ProcessStreamSinkTerminalId::new(sink_identity(&self.binding, self.kind, "terminal"))
                .map_err(|_| ProcessExecutionError::UnknownOutcome)?,
            self.binding.clone(),
            self.kind,
            self.policy.clone(),
            self.limits,
            ProcessStreamDigestAlgorithm::Sha256,
            ProcessStreamDigestAlgorithm::Sha256,
        )
        .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
        let session = block_on_sink(self.client.open(request)).map_err(|error| {
            if matches!(error, ProcessStreamSinkError::ProviderUnavailable) {
                ProcessExecutionError::Unavailable("stream sink open unavailable".to_owned())
            } else {
                ProcessExecutionError::UnknownOutcome
            }
        })?;
        self.session = Some(session);
        Ok(())
    }

    /// Offers one drain chunk; never blocks the pipe drain.
    ///
    /// The chunk is split at the session chunk ceiling and each piece is
    /// offered exactly once with the session append budget. The first shed
    /// latches and every later call sheds locally with no provider I/O, so
    /// this performs no retry loop and no sleep. An append before
    /// [`Self::open`] fails closed.
    pub fn append(&mut self, chunk: &[u8]) -> Result<SinkAppendOutcome, ProcessExecutionError> {
        if chunk.is_empty() {
            return Ok(SinkAppendOutcome::Admitted);
        }
        let Some(session) = self.session.clone() else {
            return Err(ProcessExecutionError::UnknownOutcome);
        };
        // Every byte the drain hands over once the session is open, including
        // bytes later shed by pressure or an already-settled terminal below:
        // only a pre-open offer is rejected without custody.
        self.offered_bytes = self.offered_bytes.saturating_add(chunk.len() as u64);
        if let Some(terminal) = &self.terminal {
            return Ok(SinkAppendOutcome::ShedTerminal(terminal.state()));
        }
        if self.shedding {
            return Ok(SinkAppendOutcome::ShedClosed);
        }
        let max_chunk = usize::try_from(self.limits.max_chunk_bytes()).unwrap_or(usize::MAX);
        if max_chunk == 0 {
            return Err(ProcessExecutionError::UnknownOutcome);
        }
        let wait_budget = self.limits.max_append_wait_ms();
        let mut outcome = SinkAppendOutcome::Admitted;
        for piece in chunk.chunks(max_chunk) {
            let piece_outcome = self.append_piece(&session, piece, wait_budget)?;
            match piece_outcome {
                SinkAppendOutcome::Admitted => {}
                shed => {
                    outcome = shed;
                    self.shedding = true;
                    break;
                }
            }
        }
        Ok(outcome)
    }

    /// Finalizes an EOF drain to exactly one terminal.
    ///
    /// A second call returns the same terminal without provider I/O. When the
    /// provider disagrees (identity conflict or transient unavailability),
    /// one readback reconcile adopts the provider's terminal instead of
    /// minting a second receipt.
    pub fn finalize_eof(&mut self) -> Result<ProcessStreamSinkTerminal, ProcessExecutionError> {
        if let Some(terminal) = &self.terminal {
            return Ok(terminal.clone());
        }
        if self.policy_prohibited {
            return Err(ProcessExecutionError::UnknownOutcome);
        }
        let Some(session) = self.session.clone() else {
            return Err(ProcessExecutionError::UnknownOutcome);
        };
        let preview = ProcessStreamPrefixPreview::from_transport_prefix(
            self.preview_prefix.clone(),
            self.admitted_bytes(),
        )
        .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
        let request = ProcessStreamSinkFinalizeRequest::new(
            session.terminal_id().clone(),
            self.next_sequence,
            self.next_offset,
            self.limits.max_finalize_wait_ms(),
            StreamTransportStatus::Complete,
            self.admitted_sha256(),
            self.admitted_bytes(),
            preview,
            None,
            self.finalize_gaps(),
        )
        .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
        match block_on_sink(self.client.finalize(session.clone(), request)) {
            Ok(terminal) => self.adopt_terminal(terminal),
            Err(
                error @ (ProcessStreamSinkError::ProviderUnavailable
                | ProcessStreamSinkError::TerminalIdentityConflict
                | ProcessStreamSinkError::Terminal),
            ) => {
                let _ = error;
                self.adopt_readback_terminal(&session)
            }
            Err(_) => Err(ProcessExecutionError::UnknownOutcome),
        }
    }

    /// Aborts a cancel-before-EOF drain to exactly one terminal.
    ///
    /// The admitted prefix stays claimed (digest/count over admitted bytes)
    /// with the exact cancellation gap; the source stays `None`.
    pub fn abort_cancelled(&mut self) -> Result<ProcessStreamSinkTerminal, ProcessExecutionError> {
        self.abort_with(
            ProcessStreamSinkAbortReason::Cancellation,
            StreamTransportStatus::CancelledBeforeEof,
            false,
        )
    }

    /// Aborts a policy-prohibited stream to exactly one terminal.
    ///
    /// The admitted identity (digest/count) is preserved for custody while the
    /// preview is withheld, so raw pre-policy bytes never enter the durable
    /// record; the source stays `None` with the exact prohibition gap.
    pub fn abort_policy_prohibited(
        &mut self,
    ) -> Result<ProcessStreamSinkTerminal, ProcessExecutionError> {
        self.policy_prohibited = true;
        self.abort_with(
            ProcessStreamSinkAbortReason::PolicyProhibition,
            StreamTransportStatus::Complete,
            true,
        )
    }

    /// Aborts a read-failed drain to exactly one terminal.
    ///
    /// The admitted prefix stays claimed with the exact transport-failure
    /// gap; the source stays `None`.
    pub fn abort_transport_failure(
        &mut self,
    ) -> Result<ProcessStreamSinkTerminal, ProcessExecutionError> {
        self.abort_with(
            ProcessStreamSinkAbortReason::TransportFailure,
            StreamTransportStatus::ReadFailed,
            false,
        )
    }

    /// Reconciles the session identity without minting a receipt.
    ///
    /// Re-issues the identical open (deterministic identity, so the provider
    /// returns the same session) and reads back whatever the provider holds:
    /// the one terminal when finalization already landed, the open session
    /// view otherwise. Cleanup and reopen paths use this instead of a second
    /// finalize/abort.
    pub fn reopen(&mut self) -> Result<ProcessStreamSinkReadback, ProcessExecutionError> {
        self.open()?;
        let Some(session) = self.session.clone() else {
            return Err(ProcessExecutionError::UnknownOutcome);
        };
        block_on_sink(self.client.readback(session))
            .map_err(|_| ProcessExecutionError::UnknownOutcome)
    }

    /// Returns the admitted-byte count covered by the terminal (or so far).
    #[must_use]
    pub const fn admitted_bytes(&self) -> u64 {
        self.next_offset
    }

    /// Returns the incremental SHA-256 over every admitted byte.
    #[must_use]
    pub fn admitted_sha256(&self) -> String {
        format!("{:x}", self.admitted_digest.clone().finalize())
    }

    /// Returns every byte offered, including bytes shed after pressure.
    #[must_use]
    pub const fn offered_bytes(&self) -> u64 {
        self.offered_bytes
    }

    /// Returns whether the session is open (before any terminal).
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.session.is_some()
    }

    /// Returns whether persistence pressure shed the admitted prefix tail.
    #[must_use]
    pub const fn backpressure_observed(&self) -> bool {
        self.backpressured
    }

    /// Returns whether the provider failed on the streaming path.
    #[must_use]
    pub const fn provider_failed(&self) -> bool {
        self.provider_failed
    }

    /// Returns the open session, when one exists.
    #[must_use]
    pub const fn session(&self) -> Option<&ProcessStreamSinkSession> {
        self.session.as_ref()
    }

    /// Returns the one terminal, when finalization already landed.
    #[must_use]
    pub const fn terminal(&self) -> Option<&ProcessStreamSinkTerminal> {
        self.terminal.as_ref()
    }

    /// Returns the terminal evidence, when finalization already landed.
    #[must_use]
    pub fn evidence(&self) -> Option<ProcessStreamEvidence> {
        self.terminal
            .as_ref()
            .map(|terminal| terminal.evidence().clone())
    }

    fn append_piece(
        &mut self,
        session: &ProcessStreamSinkSession,
        piece: &[u8],
        wait_budget: u64,
    ) -> Result<SinkAppendOutcome, ProcessExecutionError> {
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ProcessExecutionError::UnknownOutcome)?;
        let next_offset = self
            .next_offset
            .checked_add(piece.len() as u64)
            .ok_or(ProcessExecutionError::UnknownOutcome)?;
        let request = ProcessStreamSinkAppend::from_bytes(
            self.next_sequence,
            self.next_offset,
            piece.to_vec(),
            wait_budget,
        );
        match block_on_sink(self.client.append(session.clone(), request)) {
            Ok(
                ProcessStreamSinkAppendDisposition::Accepted { .. }
                | ProcessStreamSinkAppendDisposition::Replayed { .. },
            ) => {
                // Replayed is idempotent acknowledgement of an already-known
                // sequence: counters advance exactly once per piece because a
                // replayed piece is never re-offered by this pump.
                self.admitted_digest.update(piece);
                self.next_sequence = next_sequence;
                self.next_offset = next_offset;
                let remaining = self
                    .preview_ceiling
                    .saturating_sub(self.preview_prefix.len());
                self.preview_prefix
                    .extend_from_slice(&piece[..piece.len().min(remaining)]);
                Ok(SinkAppendOutcome::Admitted)
            }
            Ok(ProcessStreamSinkAppendDisposition::Backpressured { .. }) => {
                self.backpressured = true;
                Ok(SinkAppendOutcome::ShedBackpressure)
            }
            Ok(ProcessStreamSinkAppendDisposition::DeadlineExceeded) => {
                self.backpressured = true;
                Ok(SinkAppendOutcome::ShedTimeout)
            }
            Ok(ProcessStreamSinkAppendDisposition::Cancelled) => {
                self.cancelled = true;
                Ok(SinkAppendOutcome::ShedCancelled)
            }
            Ok(ProcessStreamSinkAppendDisposition::Terminal { state, .. }) => {
                Ok(SinkAppendOutcome::ShedTerminal(state))
            }
            Err(_) => {
                self.provider_failed = true;
                Err(ProcessExecutionError::UnknownOutcome)
            }
        }
    }

    fn finalize_gaps(&self) -> Vec<StreamEvidenceGap> {
        if self.backpressured {
            vec![
                StreamEvidenceGap::PersistenceUnavailable,
                StreamEvidenceGap::PersistenceBackpressure,
            ]
        } else if self.provider_failed {
            vec![StreamEvidenceGap::PersistenceUnavailable]
        } else {
            Vec::new()
        }
    }

    fn abort_with(
        &mut self,
        reason: ProcessStreamSinkAbortReason,
        transport: StreamTransportStatus,
        withheld: bool,
    ) -> Result<ProcessStreamSinkTerminal, ProcessExecutionError> {
        if let Some(terminal) = &self.terminal {
            return Ok(terminal.clone());
        }
        let Some(session) = self.session.clone() else {
            return Err(ProcessExecutionError::UnknownOutcome);
        };
        let preview = if withheld {
            ProcessStreamPrefixPreview::withheld_by_policy()
        } else {
            ProcessStreamPrefixPreview::from_transport_prefix(
                self.preview_prefix.clone(),
                self.admitted_bytes(),
            )
            .map_err(|_| ProcessExecutionError::UnknownOutcome)?
        };
        let gaps = match reason {
            ProcessStreamSinkAbortReason::Cancellation
            | ProcessStreamSinkAbortReason::CallerShutdown => vec![
                StreamEvidenceGap::PersistenceUnavailable,
                StreamEvidenceGap::CancelledBeforeEof,
            ],
            ProcessStreamSinkAbortReason::PolicyProhibition
            | ProcessStreamSinkAbortReason::RedactionFailure => {
                vec![StreamEvidenceGap::PolicyProhibited]
            }
            ProcessStreamSinkAbortReason::TransportFailure => vec![
                StreamEvidenceGap::PersistenceUnavailable,
                StreamEvidenceGap::TransportReadFailed,
            ],
        };
        let wait_budget = self.limits.max_abort_wait_ms();
        let request = ProcessStreamSinkAbortRequest::new(
            session.terminal_id().clone(),
            reason,
            self.next_sequence,
            self.next_offset,
            wait_budget,
            transport,
            self.admitted_sha256(),
            self.admitted_bytes(),
            preview,
            None,
            gaps,
        )
        .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
        match block_on_sink(self.client.abort(session.clone(), request)) {
            Ok(terminal) => self.adopt_terminal(terminal),
            Err(
                error @ (ProcessStreamSinkError::ProviderUnavailable
                | ProcessStreamSinkError::TerminalIdentityConflict
                | ProcessStreamSinkError::Terminal),
            ) => {
                let _ = error;
                self.adopt_readback_terminal(&session)
            }
            Err(_) => Err(ProcessExecutionError::UnknownOutcome),
        }
    }

    fn adopt_terminal(
        &mut self,
        terminal: ProcessStreamSinkTerminal,
    ) -> Result<ProcessStreamSinkTerminal, ProcessExecutionError> {
        enforce_sink_terminal(self.session.as_ref(), &terminal)?;
        self.terminal = Some(terminal.clone());
        Ok(terminal)
    }

    fn adopt_readback_terminal(
        &mut self,
        session: &ProcessStreamSinkSession,
    ) -> Result<ProcessStreamSinkTerminal, ProcessExecutionError> {
        match block_on_sink(self.client.readback(session.clone())) {
            Ok(ProcessStreamSinkReadback::Terminal { terminal }) => self.adopt_terminal(terminal),
            Ok(_) | Err(_) => Err(ProcessExecutionError::UnknownOutcome),
        }
    }
}

/// Enforces the terminal/evidence contract on one provider result.
///
/// The terminal must validate, belong to the open session fence, and carry a
/// source exactly on complete/partial terminals (`Some`) and never otherwise
/// (`None` with an exact gap). Anything else fails closed: the provider result
/// is dropped and no evidence is minted from it.
fn enforce_sink_terminal(
    session: Option<&ProcessStreamSinkSession>,
    terminal: &ProcessStreamSinkTerminal,
) -> Result<(), ProcessExecutionError> {
    let Some(session) = session else {
        return Err(ProcessExecutionError::UnknownOutcome);
    };
    terminal
        .validate()
        .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
    if terminal.session_id() != session.session_id()
        || terminal.source_id() != session.source_id()
        || terminal.terminal_id() != session.terminal_id()
        || terminal.open_request_sha256() != session.open_request_sha256()
    {
        return Err(ProcessExecutionError::UnknownOutcome);
    }
    let durable = matches!(
        terminal.state(),
        ProcessStreamSinkState::CompleteSource | ProcessStreamSinkState::PartialSource
    );
    if durable != terminal.evidence().source().is_some() {
        return Err(ProcessExecutionError::UnknownOutcome);
    }
    Ok(())
}

/// P-07's injected process-authority seam.
///
/// Implementations must route this operation to the one active
/// `ProcessDispatchAuthorityController`.  P-04 never receives a key, replay
/// snapshot, or issuer capability and therefore cannot become a second
/// authority owner.
pub trait DispatchValidationPort: Send + Sync {
    /// Consumes exactly one P-03 permit after fresh P-02 evidence has been
    /// bound to the request.
    ///
    /// # Errors
    /// Returns an error when the request or suspended identity is invalid, or
    /// when the active authority cannot consume the one-shot permit.
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError>;
}

/// Bounded stream projection retained by P-04 for diagnostics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapturedStream {
    /// Retained prefix, bounded by the request and executor ceilings.
    pub bytes: Vec<u8>,
    /// Number of bytes drained, including bytes not retained.
    pub total_bytes: u64,
    /// Whether bytes beyond the retained prefix were observed.
    pub truncated: bool,
    /// Whether EOF was observed.
    pub complete: bool,
    /// Whether P-02 supplied a stream handle.
    pub captured: bool,
}

/// Typed terminal disposition of one owned stream capture session.
///
/// Every state below is observable through [`CaptureSession`] without
/// inventing a minted string handle: zero-byte EOF (`Eof`), a drained
/// failure (`ReadFailed`), a missing handle/thread (`CaptureUnavailable`),
/// cancellation before EOF (`CancelledBeforeEof`), and the explicit unknown
/// (`UnknownOutcome`) all stay distinct. Failures remain operation-local; the
/// disposition never fabricates complete proof for a partial observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureDisposition {
    /// The drain thread is owned and still draining; no terminal state yet.
    Draining,
    /// EOF was observed after every received byte was drained (including the
    /// zero-byte case, where `total_bytes == 0` and the digest is the empty
    /// SHA-256).
    Eof,
    /// A read failed after zero or more bytes were observed; the observed
    /// prefix stays queryable but complete evidence is forbidden.
    ReadFailed,
    /// The requested handle/thread was unavailable; no bytes are claimed.
    CaptureUnavailable,
    /// Cancellation ended capture before EOF was observed.
    CancelledBeforeEof,
    /// The capture outcome itself cannot be established.
    UnknownOutcome,
}

impl CaptureDisposition {
    /// Returns whether a terminal state reached EOF with exact byte custody.
    #[must_use]
    pub const fn is_eof_complete(self) -> bool {
        matches!(self, Self::Eof)
    }

    /// Returns the exact `ProcessStreamKind` label for diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draining => "draining",
            Self::Eof => "eof",
            Self::ReadFailed => "read-failed",
            Self::CaptureUnavailable => "capture-unavailable",
            Self::CancelledBeforeEof => "cancelled-before-eof",
            Self::UnknownOutcome => "unknown-outcome",
        }
    }
}

/// One owned capture session per requested stream (stdout/stderr).
///
/// A session is minted exactly once at the capture-setup start-state
/// boundary, next to the #83/#84 owners, and owns the drain of exactly one
/// stream: the full transport digest/count over the bytes actually observed,
/// the admissible-source identity (SHA-256/count over the full observed
/// stream), a bounded diagnostics prefix, and the typed durable-source
/// disposition. The two sessions drain independently with bounded memory
/// (only the prefix is retained); the full digest/count accumulators never
/// retain the stream. Terminal [`CaptureDisposition`] states preserve the
/// exact zero-byte EOF, read-failure, cancellation-before-EOF,
/// capture-unavailable, and unknown-outcome contours through the typed
/// session without minting a durable-source handle string.
#[allow(
    clippy::struct_excessive_bools,
    reason = "requested, draining, truncated, and backpressured are independent session observations"
)]
pub struct CaptureSession {
    /// Exact stream owned by this session (`"stdout"` or `"stderr"`).
    stream: &'static str,
    /// Bounded retained diagnostics prefix ceiling.
    limit: usize,
    /// Bytes retained for the bounded preview (never the full stream).
    prefix: Vec<u8>,
    /// Full transport digest over every byte actually observed.
    digest: Sha256,
    /// Full count over every byte actually observed.
    total_bytes: u64,
    /// Whether the drain observed bytes beyond the retained prefix.
    truncated: bool,
    /// Terminal disposition; `Draining` until the drain thread lands.
    disposition: CaptureDisposition,
    /// Whether the request asked for this stream (`false` sessions never
    /// claim a handle and stay `CaptureUnavailable`).
    requested: bool,
    /// Whether a drain thread owns this session's pipe handle.
    draining: bool,
    /// Bytes observed since minting, counted against the sink-pressure
    /// isolation ceiling. Never blocks the drain; only feeds the latch below.
    sink_pressure_bytes: u64,
    /// Isolation ceiling taken from the #267 sink-port limits
    /// (`max_in_flight_bytes`). The drain never waits on persistence.
    backpressure_ceiling: u64,
    /// Latched when observed bytes exceeded the isolation ceiling: persistence
    /// pressure was shed while the pipe kept draining. Latched once, never
    /// cleared, so the overflow fact survives the terminal landing.
    backpressured: bool,
}

impl std::fmt::Debug for CaptureSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureSession")
            .field("stream", &self.stream)
            .field("prefix", &self.prefix)
            .field("limit", &self.limit)
            .field("total_bytes", &self.total_bytes)
            .field("truncated", &self.truncated)
            .field("disposition", &self.disposition)
            .field("requested", &self.requested)
            .field("draining", &self.draining)
            .field("sink_pressure_bytes", &self.sink_pressure_bytes)
            .field("backpressure_ceiling", &self.backpressure_ceiling)
            .field("backpressured", &self.backpressured)
            .finish_non_exhaustive()
    }
}

impl CaptureSession {
    /// Mints one owned session for `stream` at the capture-setup boundary.
    ///
    /// `limit` is the bounded retained-prefix ceiling; the full digest/count
    /// accumulators always observe every drained byte regardless of the
    /// ceiling. An unrequested stream is minted `CaptureUnavailable` so no
    /// production path can claim bytes for a stream that was never asked for.
    #[must_use]
    pub fn new(stream: &'static str, limit: usize, requested: bool) -> Self {
        // The isolation ceiling is the validated #267 port bound; when the
        // port shape itself cannot be built (unreachable with the constants
        // above), fail closed to the same byte ceiling rather than unbounded.
        let backpressure_ceiling = match sink_backpressure_limits() {
            Ok(limits) => limits.max_in_flight_bytes(),
            Err(_) => SINK_BACKPRESSURE_IN_FLIGHT_BYTES,
        };
        Self {
            stream,
            limit: limit.max(1),
            prefix: Vec::new(),
            digest: Sha256::new(),
            total_bytes: 0,
            truncated: false,
            disposition: if requested {
                CaptureDisposition::Draining
            } else {
                CaptureDisposition::CaptureUnavailable
            },
            requested,
            draining: false,
            sink_pressure_bytes: 0,
            backpressure_ceiling,
            backpressured: false,
        }
    }

    /// Marks the drain thread as installed; operation-local ownership only.
    pub fn mark_draining(&mut self) {
        if self.requested {
            self.draining = true;
        }
    }

    /// Feeds one observed chunk into the session: the full digest/count
    /// always advance over the actual bytes, while retention stays bounded to
    /// the prefix ceiling. The sink-pressure counter advances alongside the
    /// digest without ever blocking: past the isolation ceiling only the
    /// overflow fact latches, and the pipe keeps draining.
    pub fn observe(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        self.digest.update(chunk);
        self.total_bytes = self.total_bytes.saturating_add(chunk.len() as u64);
        self.sink_pressure_bytes = self.sink_pressure_bytes.saturating_add(chunk.len() as u64);
        if self.sink_pressure_bytes > self.backpressure_ceiling {
            self.backpressured = true;
        }
        let remaining = self.limit.saturating_sub(self.prefix.len());
        let retained = chunk.len().min(remaining);
        self.prefix.extend_from_slice(&chunk[..retained]);
        if retained < chunk.len() {
            self.truncated = true;
        }
    }

    /// Lands the zero-byte-or-more EOF: exact digest/count custody is
    /// already accumulated; a zero-byte stream keeps the empty SHA-256.
    pub fn mark_eof(&mut self) {
        if self.requested {
            self.disposition = CaptureDisposition::Eof;
        }
    }

    /// Lands a read failure; the observed prefix stays queryable but
    /// complete evidence is forbidden.
    pub fn mark_read_failed(&mut self) {
        if self.requested {
            self.disposition = CaptureDisposition::ReadFailed;
        }
    }

    /// Lands cancellation before EOF; the observed prefix stays queryable
    /// but complete evidence is forbidden.
    pub fn mark_cancelled_before_eof(&mut self) {
        if self.requested {
            self.disposition = CaptureDisposition::CancelledBeforeEof;
        }
    }

    /// Cancel-path single-terminal landing: only a still-draining session
    /// moves to `CancelledBeforeEof`.
    ///
    /// An already-landed terminal (`Eof`, `ReadFailed`, `CaptureUnavailable`,
    /// `UnknownOutcome`, or an earlier `CancelledBeforeEof`) already tells its
    /// story and is preserved, so a late cancel can never rewrite exact byte
    /// custody into cancellation. The drain thread lands through
    /// `land_drain_terminal`, which preserves a cancel that won the race the
    /// same way; exactly one terminal survives either order.
    pub fn cancel_before_eof(&mut self) {
        if self.requested && matches!(self.disposition, CaptureDisposition::Draining) {
            self.disposition = CaptureDisposition::CancelledBeforeEof;
        }
    }

    /// Drain-thread single-terminal landing: only a still-draining session
    /// adopts the drain outcome, so a cancellation that landed first is never
    /// overwritten by a trailing EOF/read result from torn-down pipes.
    fn land_drain_terminal(&mut self, terminal: CaptureDisposition) {
        if self.requested && matches!(self.disposition, CaptureDisposition::Draining) {
            self.disposition = terminal;
        }
    }

    /// Lands the explicit unknown outcome; nothing is fabricated.
    pub fn mark_unknown_outcome(&mut self) {
        if self.requested {
            self.disposition = CaptureDisposition::UnknownOutcome;
        }
    }

    /// Lands capture-unavailable; claims no bytes.
    pub fn mark_capture_unavailable(&mut self) {
        self.disposition = CaptureDisposition::CaptureUnavailable;
    }

    /// Returns the owned stream label.
    #[must_use]
    pub const fn stream(&self) -> &'static str {
        self.stream
    }

    /// Returns whether this stream was requested.
    #[must_use]
    pub const fn requested(&self) -> bool {
        self.requested
    }

    /// Returns whether a drain thread owns this session's pipe handle.
    #[must_use]
    pub const fn draining(&self) -> bool {
        self.draining
    }

    /// Returns the terminal disposition.
    #[must_use]
    pub const fn disposition(&self) -> CaptureDisposition {
        self.disposition
    }

    /// Returns the full observed byte count.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Returns the full observed SHA-256 over bytes actually drained.
    #[must_use]
    pub fn observed_sha256(&self) -> String {
        format!("{:x}", self.digest.clone().finalize())
    }

    /// Returns the bounded retained prefix for diagnostics/preview.
    #[must_use]
    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    /// Returns whether bytes beyond the retained prefix were observed.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Returns whether sink pressure overflow latched while draining: the
    /// observed stream exceeded the #267 port isolation ceiling, persistence
    /// pressure was shed, and the pipe kept draining with exact digest/count.
    #[must_use]
    pub const fn backpressure_observed(&self) -> bool {
        self.backpressured
    }

    /// Returns bytes counted against the sink-pressure isolation ceiling.
    #[must_use]
    pub const fn sink_pressure_bytes(&self) -> u64 {
        self.sink_pressure_bytes
    }

    /// Returns the #267 port isolation ceiling in bytes.
    #[must_use]
    pub const fn backpressure_ceiling(&self) -> u64 {
        self.backpressure_ceiling
    }

    /// Returns whether EOF landed (including the zero-byte case).
    #[must_use]
    pub const fn eof_complete(&self) -> bool {
        matches!(self.disposition, CaptureDisposition::Eof)
    }

    /// Returns whether capture is available for this session: requested,
    /// owned by a drain thread, and not fenced unavailable.
    #[must_use]
    pub const fn capture_available(&self) -> bool {
        self.requested
            && self.draining
            && !matches!(self.disposition, CaptureDisposition::CaptureUnavailable)
    }

    fn snapshot(&self) -> CapturedStream {
        CapturedStream {
            bytes: self.prefix.clone(),
            total_bytes: self.total_bytes,
            truncated: self.truncated,
            complete: self.disposition.is_eof_complete(),
            captured: self.draining,
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CaptureFailure {
    stream: &'static str,
    thread_id: Option<String>,
    disposition: CaptureFailureDisposition,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureFailureDisposition {
    SpawnFailed,
    Timeout,
    Panicked,
    Incomplete,
    ReadFailed,
}

#[cfg(windows)]
impl CaptureFailureDisposition {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SpawnFailed => "spawn-failed",
            Self::Timeout => "join-timeout",
            Self::Panicked => "panicked",
            Self::Incomplete => "incomplete",
            Self::ReadFailed => "read-failed",
        }
    }
}

#[cfg(windows)]
struct DeadlineWatcher {
    /// Operation-bound owner identity (`deadline-watcher:<operation-id>`)
    /// minted at spawn. The watcher thread enforces the wall deadline for
    /// exactly this operation; the owner travels with the watcher so
    /// restart/shutdown containment attributes every join to one op.
    owner: String,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

#[cfg(windows)]
impl DeadlineWatcher {
    /// Returns the operation-bound owner identity of this watcher.
    fn owner(&self) -> &str {
        &self.owner
    }

    fn stop_and_join(mut self) -> Result<(), ProcessExecutionError> {
        self.stop.store(true, Ordering::Release);
        let Some(handle) = self.handle.take() else {
            return Err(unavailable("deadline watcher owner is missing its thread"));
        };
        handle
            .join()
            .map_err(|_| unavailable("deadline watcher thread panicked"))
    }
}

#[cfg(windows)]
impl Drop for DeadlineWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(windows)]
struct Operation {
    state: ProcessState,
    sink: Arc<dyn ProcessEvidenceSink>,
    child: Option<RunningJobChild<ValidatedDispatch>>,
    stdout: Arc<Mutex<CaptureSession>>,
    stderr: Arc<Mutex<CaptureSession>>,
    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    /// Policy-bound sink pumps owned by the drain threads (`None` when no
    /// sink client is attached or the session open failed and the legacy
    /// `SourceUnavailable` path applies).
    stdout_pump: Option<Arc<Mutex<StreamSinkPump>>>,
    stderr_pump: Option<Arc<Mutex<StreamSinkPump>>>,
    deadline: Instant,
    deadline_watcher: Option<DeadlineWatcher>,
    /// Operation-bound watcher owner identity minted when the deadline
    /// watcher spawns (`deadline-watcher:<operation-id>`). Retained after
    /// the watcher joins so health/quarantine/shutdown projections keep
    /// attributing wall-time enforcement ownership to exactly one op.
    deadline_watcher_owner: Option<String>,
    /// Whether the complete Job tree was terminated through the admitted
    /// process owner because the deadline watcher could not be installed
    /// after resume. Part of the fail-closed evidence: reconcile/shutdown
    /// can distinguish "child never had autonomous enforcement" from
    /// "child was contained and the tree was torn down".
    watcher_fail_closed_contained: bool,
    /// Exact start-publication evidence gap for a post-resume failure that
    /// kept the op registered (issue #84: registry/receipt publication
    /// failure after all control owners installed). `None` on every other
    /// path; surfaced through the health/quarantine projection so the gap
    /// is attributable instead of inferred.
    start_publish_gap: Option<&'static str>,
    /// Operation-bound start-phase marker for the issue-84 start state
    /// machine (suspended launch → authority validation → resume →
    /// capture/watcher setup → registry/receipt publication). Written by
    /// `start()` at every transition and read back into the quarantine
    /// evidence on every post-resume failure path, so the phase names the
    /// exact containment point instead of being inferred.
    start_phase: StartPhase,
    timed_out: bool,
    cleanup_required: bool,
    termination: Option<TerminatedJobChild>,
    capture_failures: Vec<CaptureFailure>,
}

/// Explicit start state machine for `WindowsProcessExecutor::start`
/// (issue #84): suspended launch → authority validation → resume →
/// capture/control setup → registry publication → receipt publication.
///
/// Where Windows mechanics allow, capture/deadline/control infrastructure
/// is created and owned BEFORE resume: the Job object, kill-on-close
/// contour, resource limits, and stdio pipes are all built while the child
/// is still suspended inside `spawn_named_with_limits`. Resume must precede
/// stream-capture ownership: the stdout/stderr read handles live on
/// `RunningJobChild` and can only be taken after `resume()`, and the
/// deadline watcher enforces the admitted deadline for the registered
/// `Operation` owner.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartPhase {
    /// Suspended child spawned; nothing resumed yet.
    SuspendedLaunch,
    /// One-shot authority permit consumed against fresh suspended evidence.
    AuthorityValidation,
    /// Validated child resumed; resume observed into process state.
    Resumed,
    /// Stdout/stderr capture-thread ownership being installed (post-resume).
    CaptureSetup,
    /// Deadline-watcher ownership being installed (post-resume).
    WatcherSetup,
    /// Operation durably registered for query/cancel/reconcile.
    RegistryPublication,
    /// Start receipt publication (only after all control owners installed).
    ReceiptPublication,
}

#[cfg(windows)]
impl StartPhase {
    /// Stable label naming the exact start-machine step. Written into the
    /// operation at every transition and read back into the quarantine
    /// evidence on post-resume failure paths.
    const fn as_str(self) -> &'static str {
        match self {
            Self::SuspendedLaunch => "suspended-launch",
            Self::AuthorityValidation => "authority-validation",
            Self::Resumed => "resumed",
            Self::CaptureSetup => "capture-setup",
            Self::WatcherSetup => "watcher-setup",
            Self::RegistryPublication => "registry-publication",
            Self::ReceiptPublication => "receipt-publication",
        }
    }
}

/// One operation-scoped quarantine record.
///
/// This keeps the owner/Job lineage, the exact capture-evidence gap, and the
/// required recovery action together so a per-operation failure never has to
/// be inferred from executor-wide state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedOperationRecord {
    operation_id: OperationId,
    process_tree_id: ProcessTreeId,
    job_id: JobId,
    image_id: ImageId,
    session_id: SessionId,
    lifecycle: ProcessLifecycle,
    evidence_gap: &'static str,
    capture_failures: Vec<(String, &'static str)>,
    /// Operation-bound deadline-watcher owner (`deadline-watcher:<op>`) when
    /// wall-time enforcement was installed for this op; `None` when the
    /// watcher never started. Exposes watcher identity/ownership through the
    /// health/quarantine projection instead of hiding it in executor state.
    deadline_watcher_owner: Option<String>,
    /// Whether wall-time enforcement is autonomously installed for this op.
    /// `false` means the admitted deadline relies on external polling or has
    /// no live watcher — the exact signal issue #83 requires separated from
    /// stream-capture health.
    wall_time_enforcement_installed: bool,
    /// Whether the Job tree was terminated through the admitted process
    /// owner on the fail-closed watcher-spawn path (issue #83 §2).
    watcher_fail_closed_contained: bool,
    /// Start state-machine phase reached when this op was fenced, naming
    /// the exact containment point (issue #84 §1). Written by `start()` at
    /// every transition and read back into this record on post-resume
    /// failure paths.
    start_phase: &'static str,
    descendants_complete: Option<bool>,
    tree_terminated: Option<bool>,
    cleanup_pending: bool,
    recovery_action: &'static str,
}

impl QuarantinedOperationRecord {
    /// Returns the exact quarantined operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the caller-owned process-tree lineage of the quarantined op.
    #[must_use]
    pub const fn process_tree_id(&self) -> &ProcessTreeId {
        &self.process_tree_id
    }

    /// Returns the logical Job lineage of the quarantined op.
    #[must_use]
    pub const fn job_id(&self) -> &JobId {
        &self.job_id
    }

    /// Returns the pinned image lineage of the quarantined op.
    #[must_use]
    pub const fn image_id(&self) -> &ImageId {
        &self.image_id
    }

    /// Returns the session lineage of the quarantined op.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the fenced lifecycle projection of the quarantined op.
    #[must_use]
    pub const fn lifecycle(&self) -> ProcessLifecycle {
        self.lifecycle
    }

    /// Returns the exact evidence gap that fenced this operation.
    #[must_use]
    pub const fn evidence_gap(&self) -> &'static str {
        self.evidence_gap
    }

    /// Returns the per-stream capture failures bound to this operation.
    #[must_use]
    pub fn capture_failures(&self) -> &[(String, &'static str)] {
        &self.capture_failures
    }

    /// Returns the operation-bound deadline-watcher owner bound to this op.
    ///
    /// `Some("deadline-watcher:<operation-id>")` when wall-time enforcement
    /// was installed for this operation; `None` when the watcher never
    /// started (issue #83 watcher identity/ownership record).
    #[must_use]
    pub fn deadline_watcher_owner(&self) -> Option<&str> {
        self.deadline_watcher_owner.as_deref()
    }

    /// Returns whether autonomous wall-time enforcement is installed.
    ///
    /// This is the wall-time dimension required by issue #83 §5, kept
    /// separate from stream-capture health: a `false` here with empty
    /// `capture_failures` means the op lost (or never gained) its deadline
    /// watcher, not that its streams are broken.
    #[must_use]
    pub const fn wall_time_enforcement_installed(&self) -> bool {
        self.wall_time_enforcement_installed
    }

    /// Returns whether the Job tree was terminated through the admitted
    /// process owner on the fail-closed watcher-spawn path.
    #[must_use]
    pub const fn watcher_fail_closed_contained(&self) -> bool {
        self.watcher_fail_closed_contained
    }

    /// Returns the start state-machine phase reached when this op was
    /// fenced (issue #84 §1), naming the exact containment point.
    #[must_use]
    pub const fn start_phase(&self) -> &'static str {
        self.start_phase
    }

    /// Returns the observed descendant completeness, when a view exists.
    #[must_use]
    pub const fn descendants_complete(&self) -> Option<bool> {
        self.descendants_complete
    }

    /// Returns the observed tree termination, when a view exists.
    #[must_use]
    pub const fn tree_terminated(&self) -> Option<bool> {
        self.tree_terminated
    }

    /// Returns whether cleanup/reconciliation is still pending for this op.
    #[must_use]
    pub const fn cleanup_pending(&self) -> bool {
        self.cleanup_pending
    }

    /// Returns the required explicit recovery action for this op.
    #[must_use]
    pub const fn recovery_action(&self) -> &'static str {
        self.recovery_action
    }
}

/// Cheap non-blocking per-dimension executor health projection.
///
/// Quarantine is operation-local: one fenced operation never closes
/// inspection, cancellation, or new starts for independent operations.
/// A `false` dimension means only that the underlying registry/reservation
/// mutex is currently contended or poisoned, never that an unrelated
/// operation failed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecutorHealthSummary {
    /// Whether a new operation identity can be reserved right now.
    pub new_start_ready: bool,
    /// Whether existing operations remain inspectable right now.
    pub inspection_available: bool,
    /// Whether cancellation/containment remains available right now.
    pub cancellation_available: bool,
    /// Number of registered operations with incomplete capture/evidence.
    pub capture_incomplete_operations: usize,
    /// Number of registered operations whose autonomous wall-time
    /// enforcement is missing (watcher never installed or lost), kept
    /// separate from `capture_incomplete_operations` per issue #83 §5.
    pub wall_time_enforcement_missing_operations: usize,
    /// Number of registered operations awaiting cleanup/reconciliation.
    pub cleanup_pending_operations: usize,
    /// Number of registered operations fenced as unknown outcome.
    pub unknown_outcome_operations: usize,
    /// Per-operation quarantine records bound to owner/Job lineage,
    /// evidence gap, and recovery action.
    pub quarantined_operations: Vec<QuarantinedOperationRecord>,
}

/// The single governed process executor.  It is deliberately constructed
/// with an injected authority port so no alternate issuer can be hidden in
/// the physical implementation.
pub struct WindowsProcessExecutor {
    authority: Arc<dyn DispatchValidationPort>,
    launch_admission: Option<Arc<dyn ProcessLaunchAdmission>>,
    stream_sink: Option<Arc<dyn ProcessStreamSinkClient>>,
    operations: Mutex<BTreeMap<OperationId, Arc<Mutex<Operation>>>>,
    reservations: Mutex<std::collections::BTreeSet<OperationId>>,
    capture_limit: usize,
}

struct OperationReservation<'a> {
    executor: &'a WindowsProcessExecutor,
    operation_id: OperationId,
}

impl Drop for OperationReservation<'_> {
    fn drop(&mut self) {
        if let Ok(mut reservations) = self.executor.reservations.lock() {
            reservations.remove(&self.operation_id);
        }
    }
}

impl WindowsProcessExecutor {
    /// Creates one executor around the P-07 authority composition.
    #[must_use]
    pub fn new(authority: Arc<dyn DispatchValidationPort>) -> Self {
        Self {
            authority,
            launch_admission: None,
            stream_sink: None,
            operations: Mutex::new(BTreeMap::new()),
            reservations: Mutex::new(std::collections::BTreeSet::new()),
            capture_limit: DEFAULT_CAPTURE_LIMIT,
        }
    }

    /// Creates one executor that streams policy-bound process output into
    /// immutable evidence through the #267 sink port.
    ///
    /// The drain path opens one sink session per requested stream before the
    /// first admitted byte, appends per chunk with typed backpressure that
    /// never blocks the pipe drain, and settles exactly one terminal per
    /// stream at finalize. With no sink attached ([`Self::new`]), persistence
    /// stays `SourceUnavailable` as before.
    #[must_use]
    pub fn new_with_stream_sink(
        authority: Arc<dyn DispatchValidationPort>,
        stream_sink: Arc<dyn ProcessStreamSinkClient>,
    ) -> Self {
        Self {
            authority,
            launch_admission: None,
            stream_sink: Some(stream_sink),
            operations: Mutex::new(BTreeMap::new()),
            reservations: Mutex::new(std::collections::BTreeSet::new()),
            capture_limit: DEFAULT_CAPTURE_LIMIT,
        }
    }

    /// Creates one executor with a Kernel-owned retained launch-proof seam.
    #[must_use]
    pub fn new_with_launch_admission(
        authority: Arc<dyn DispatchValidationPort>,
        launch_admission: Arc<dyn ProcessLaunchAdmission>,
    ) -> Self {
        Self {
            authority,
            launch_admission: Some(launch_admission),
            stream_sink: None,
            operations: Mutex::new(BTreeMap::new()),
            reservations: Mutex::new(std::collections::BTreeSet::new()),
            capture_limit: DEFAULT_CAPTURE_LIMIT,
        }
    }

    /// Creates one executor with a bounded retained-stream ceiling.
    #[must_use]
    pub fn with_capture_limit(
        authority: Arc<dyn DispatchValidationPort>,
        capture_limit: usize,
    ) -> Self {
        Self {
            authority,
            launch_admission: None,
            stream_sink: None,
            operations: Mutex::new(BTreeMap::new()),
            reservations: Mutex::new(std::collections::BTreeSet::new()),
            capture_limit: capture_limit.max(1),
        }
    }

    fn operation(&self, id: &OperationId) -> Result<Arc<Mutex<Operation>>, ProcessExecutionError> {
        self.operations
            .lock()
            .map_err(|_| unavailable("operation registry lock poisoned"))?
            .get(id)
            .cloned()
            .ok_or(ProcessExecutionError::NotFound)
    }

    fn reserve_operation(
        &self,
        id: OperationId,
    ) -> Result<OperationReservation<'_>, ProcessExecutionError> {
        // `operations` and `reservations` stay independent dimensions: a
        // poisoned registry lock never fabricates a reservation entry, and a
        // poisoned/contended reservation lock never hides or removes a
        // registered operation.  Duplicate identities fail locally without
        // stranding a reservation: the `OperationReservation` guard drops at
        // function exit and releases the id, while registry inserts below
        // replace only the exact failed identity.
        let operations = self
            .operations
            .lock()
            .map_err(|_| unavailable("operation registry lock poisoned"))?;
        if operations.contains_key(&id) {
            return Err(unavailable("operation identity already exists"));
        }
        // Drop the registry guard before taking the reservation lock so one
        // contended mutex can never block the independent dimension.
        drop(operations);
        let mut reservations = self
            .reservations
            .lock()
            .map_err(|_| unavailable("operation reservation lock poisoned"))?;
        if !reservations.insert(id.clone()) {
            return Err(unavailable("operation identity already exists"));
        }
        Ok(OperationReservation {
            executor: self,
            operation_id: id,
        })
    }

    /// Returns a cheap non-blocking per-dimension health projection.
    ///
    /// Quarantine stays operation-local: a fenced operation is reported in
    /// `quarantined_operations` with its owner/Job lineage, evidence gap,
    /// and recovery action, while `new_start_ready`,
    /// `inspection_available`, and `cancellation_available` keep reflecting
    /// only whether the shared registry/reservation locks are usable.  One
    /// quarantined operation never flips the independent dimensions to
    /// `false`.
    #[must_use]
    pub fn operation_health_summary(&self) -> ExecutorHealthSummary {
        let operations_snapshot = self.operations.lock().ok().map(|registry| {
            registry
                .iter()
                .filter_map(|(id, operation)| {
                    operation
                        .lock()
                        .ok()
                        .and_then(|guard| quarantined_record(id, &guard))
                })
                .collect::<Vec<QuarantinedOperationRecord>>()
        });
        let Some(records) = operations_snapshot else {
            return ExecutorHealthSummary {
                new_start_ready: false,
                inspection_available: false,
                cancellation_available: false,
                ..ExecutorHealthSummary::default()
            };
        };
        let new_start_ready = self.reservations.try_lock().is_ok();
        let quarantined_operations = records;
        let capture_incomplete_operations = quarantined_operations
            .iter()
            .filter(|record| {
                record.evidence_gap() == CAPTURE_EVIDENCE_GAP
                    || !record.capture_failures().is_empty()
            })
            .count();
        // Wall-time enforcement health is a separate dimension from
        // stream-capture health (issue #83 §5): a missing watcher fences
        // with `WATCHER_EVIDENCE_GAP` and counts here even when both
        // streams are complete.
        let wall_time_enforcement_missing_operations = quarantined_operations
            .iter()
            .filter(|record| !record.wall_time_enforcement_installed())
            .count();
        let cleanup_pending_operations = quarantined_operations
            .iter()
            .filter(|record| record.cleanup_pending())
            .count();
        let unknown_outcome_operations = quarantined_operations
            .iter()
            .filter(|record| record.lifecycle() == ProcessLifecycle::UnknownOutcome)
            .count();
        ExecutorHealthSummary {
            new_start_ready,
            // The registry lock was usable above (we hold its snapshot), so
            // existing-operation inspection and cancellation/containment stay
            // available regardless of how many ops are quarantined.
            inspection_available: true,
            cancellation_available: true,
            capture_incomplete_operations,
            wall_time_enforcement_missing_operations,
            cleanup_pending_operations,
            unknown_outcome_operations,
            quarantined_operations,
        }
    }

    /// Returns the number of registered operations whose autonomous
    /// wall-time enforcement is missing (issue #83 §5), without blocking on
    /// operation locks. Registry access failures report `0`.
    #[must_use]
    pub fn wall_time_enforcement_missing_count(&self) -> usize {
        #[cfg(windows)]
        {
            let Ok(registry) = self.operations.lock() else {
                return 0;
            };
            registry
                .values()
                .filter(|operation| {
                    operation.lock().is_ok_and(|guard| {
                        guard.deadline_watcher.is_none() && guard.deadline_watcher_owner.is_none()
                    })
                })
                .count()
        }
        #[cfg(not(windows))]
        {
            0
        }
    }

    /// Returns the number of registered operations awaiting
    /// cleanup/reconciliation without blocking on operation locks.
    ///
    /// Registry access failures report `0`; they never fabricate pending
    /// work and never close the independent inspection/cancel paths.
    #[must_use]
    pub fn cleanup_pending_count(&self) -> usize {
        let Ok(registry) = self.operations.lock() else {
            return 0;
        };
        registry
            .values()
            .filter(|operation| {
                operation.lock().is_ok_and(|guard| {
                    guard.cleanup_required
                        || guard.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome
                })
            })
            .count()
    }

    /// Returns the number of registered operations fenced as unknown
    /// outcome without blocking on operation locks.
    #[must_use]
    pub fn unknown_outcome_count(&self) -> usize {
        let Ok(registry) = self.operations.lock() else {
            return 0;
        };
        registry
            .values()
            .filter(|operation| {
                operation.lock().is_ok_and(|guard| {
                    guard.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome
                })
            })
            .count()
    }

    /// Returns whether a new operation identity can currently be reserved.
    ///
    /// This reflects only reservation-lock usability, never the quarantine
    /// state of unrelated operations.
    #[must_use]
    pub fn new_start_ready(&self) -> bool {
        self.reservations.try_lock().is_ok()
    }

    /// Returns the operation-bound deadline-watcher owner for one op.
    ///
    /// `Some("deadline-watcher:<operation-id>")` once the watcher spawns;
    /// `None` while the watcher never started (issue #83 watcher
    /// identity/ownership record, queryable per op).
    #[must_use]
    pub fn deadline_watcher_owner(&self, id: &OperationId) -> Option<String> {
        #[cfg(windows)]
        {
            self.operation(id).ok().and_then(|operation| {
                operation
                    .lock()
                    .ok()
                    .and_then(|guard| guard.deadline_watcher_owner.clone())
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (self.operation(id), id);
            None
        }
    }

    /// Returns whether autonomous wall-time enforcement is installed for one
    /// op. Separate from stream-capture health and from the operation result
    /// per issue #83 §5: `Some(true)` means a deadline watcher was installed
    /// for this op (live or already joined after terminal close);
    /// `Some(false)` means the admitted deadline has no watcher owner;
    /// `None` means the op is absent/unlockable.
    #[must_use]
    pub fn wall_time_enforcement_installed(&self, id: &OperationId) -> Option<bool> {
        #[cfg(windows)]
        {
            self.operation(id).ok().and_then(|operation| {
                operation.lock().ok().map(|guard| {
                    guard.deadline_watcher.is_some() || guard.deadline_watcher_owner.is_some()
                })
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (self.operation(id), id);
            None
        }
    }

    /// Returns the retained non-authoritative stream projections.
    ///
    /// # Errors
    /// Returns an error when the operation is absent, a capture lock is
    /// poisoned, or the Windows executor is unavailable.
    pub fn captured_output(
        &self,
        id: &OperationId,
    ) -> Result<(CapturedStream, CapturedStream), ProcessExecutionError> {
        #[cfg(windows)]
        {
            let operation = self.operation(id)?;
            let guard = operation
                .lock()
                .map_err(|_| unavailable("operation lock poisoned"))?;
            return Ok((
                guard
                    .stdout
                    .lock()
                    .map_err(|_| unavailable("stdout lock poisoned"))?
                    .snapshot(),
                guard
                    .stderr
                    .lock()
                    .map_err(|_| unavailable("stderr lock poisoned"))?
                    .snapshot(),
            ));
        }
        #[cfg(not(windows))]
        {
            let _ = id;
            Err(unavailable(
                "Windows ProcessExecutor is unavailable on this target",
            ))
        }
    }

    /// Removes terminal operations after their descendants and streams have
    /// been observed.  The executor remains the sole owner of this cleanup;
    /// callers never receive a raw child or Job handle.
    ///
    /// # Errors
    /// Returns an error when registry access fails or stream cleanup cannot be
    /// proven complete. Incomplete cleanup is retained as an unknown outcome.
    /// One operation's cleanup gap fences only that operation: every
    /// independently cleanable terminal operation is still removed in the
    /// same pass (never fabricated as success for the fenced one).
    pub fn cleanup_finished(&self) -> Result<usize, ProcessExecutionError> {
        #[cfg(windows)]
        {
            let mut operations = self
                .operations
                .lock()
                .map_err(|_| registry_unavailable("lock"))?;
            let mut ids = Vec::new();
            let mut cleanup_unknown = false;
            for (id, operation) in operations.iter() {
                let mut guard = operation
                    .lock()
                    .map_err(|_| operation_unavailable(id, "operation lock"))?;
                if !guard.state.view().lifecycle().is_terminal() || guard.cleanup_required {
                    continue;
                }
                let watcher = guard.deadline_watcher.take();
                drop(guard);
                if let Some(watcher) = watcher
                    && join_deadline_watcher(watcher).is_err()
                {
                    let mut guard = operation
                        .lock()
                        .map_err(|_| operation_unavailable(id, "operation lock"))?;
                    quarantine_operation(&mut guard);
                    cleanup_unknown = true;
                    continue;
                }
                let mut guard = operation
                    .lock()
                    .map_err(|_| operation_unavailable(id, "operation lock"))?;
                if !join_streams(&mut guard) {
                    quarantine_operation(&mut guard);
                    cleanup_unknown = true;
                    continue;
                }
                // Cleanup/reopen reconciles the sink session identity without
                // minting a second receipt: a best-effort readback surfaces an
                // out-of-band terminal under the same session, and never
                // finalizes. Errors stay ignored; cleanup never fails on the
                // sink.
                let pumps = [guard.stdout_pump.clone(), guard.stderr_pump.clone()];
                drop(guard);
                for pump in pumps.into_iter().flatten() {
                    settle_sink_pump(&pump);
                }
                ids.push(id.clone());
            }
            // Remove every independently cleanable terminal operation even
            // when another operation's cleanup fenced as unknown: one op's
            // stream/watcher gap must not retain an unrelated terminal op.
            let count = ids.len();
            for id in ids {
                operations.remove(&id);
            }
            if cleanup_unknown {
                return Err(ProcessExecutionError::UnknownOutcome);
            }
            Ok(count)
        }
        #[cfg(not(windows))]
        {
            Ok(0)
        }
    }

    /// Terminates every still-owned child and clears the operation registry
    /// only when every cleanup owner reaches a terminal projection.
    ///
    /// This is the final physical cleanup contour used during Kernel
    /// shutdown and Drop; it does not claim a successful process outcome.
    /// Unknown operations are retained (never silently dropped) while the
    /// executor itself carries no global poison: surviving independent paths
    /// keep their per-operation outcomes.
    ///
    /// # Errors
    /// Returns [`ProcessExecutionError::UnknownOutcome`] and retains the
    /// operation registry when any child or cleanup marker remains owned.
    pub fn shutdown(&self) -> Result<(), ProcessExecutionError> {
        #[cfg(windows)]
        {
            let mut operations = self
                .operations
                .lock()
                .map_err(|_| registry_unavailable("lock"))?;
            let mut retain_cleanup_owners = false;
            let mut watcher_owners = Vec::new();
            // Per-operation loop: one op's finalize/stream gap quarantines
            // only that op; every other op still gets its bounded
            // terminate/join/watcher attempt in the same pass.
            for (id, operation) in operations.iter() {
                let mut guard = operation
                    .lock()
                    .map_err(|_| operation_unavailable(id, "operation lock"))?;
                retain_cleanup_owners |= guard.cleanup_required
                    || guard.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome;
                if guard.child.is_some()
                    && guard.termination.is_none()
                    && finalize_operation(&mut guard, ExitDisposition::Unknown, false).is_err()
                {
                    quarantine_operation(&mut guard);
                    retain_cleanup_owners = true;
                }
                if !join_streams(&mut guard) {
                    quarantine_operation(&mut guard);
                    retain_cleanup_owners = true;
                }
                // Same cleanup/reopen reconcile as `cleanup_finished`: a
                // best-effort readback under the same session identity, never
                // a second terminal mint.
                let pumps = [guard.stdout_pump.clone(), guard.stderr_pump.clone()];
                drop(guard);
                for pump in pumps.into_iter().flatten() {
                    settle_sink_pump(&pump);
                }
                let mut guard = operation
                    .lock()
                    .map_err(|_| operation_unavailable(id, "operation lock"))?;
                // Shutdown containment attributes every watcher join to its
                // operation-bound owner (issue #83: restart/shutdown can
                // identify and contain every watcher/Job owner): the owner
                // stays on the op after the thread is taken, so the join
                // below is per-op identifiable even while the thread runs.
                if let Some(watcher) = guard.deadline_watcher.take() {
                    let owner_label = guard
                        .deadline_watcher_owner
                        .clone()
                        .unwrap_or_else(|| deadline_watcher_owner_id(id));
                    watcher_owners.push((id.clone(), Arc::clone(operation), owner_label, watcher));
                }
            }
            for (id, operation, owner_label, watcher) in watcher_owners {
                let expected = deadline_watcher_owner_id(&id);
                // Owner check first: a mismatched watcher must never join (or
                // drop) another op's enforcement thread. Fence this op and
                // retain it; every other op already got its own attempt.
                if owner_label != expected || watcher.owner() != expected {
                    let mut guard = operation
                        .lock()
                        .map_err(|_| operation_unavailable(&id, "operation lock"))?;
                    quarantine_operation(&mut guard);
                    retain_cleanup_owners = true;
                    continue;
                }
                if join_deadline_watcher(watcher).is_err() {
                    let mut guard = operation
                        .lock()
                        .map_err(|_| operation_unavailable(&id, "operation lock"))?;
                    quarantine_operation(&mut guard);
                    retain_cleanup_owners = true;
                }
            }
            if !retain_cleanup_owners {
                operations.clear();
                self.reservations
                    .lock()
                    .map_err(|_| registry_unavailable("reservation lock"))?
                    .clear();
                return Ok(());
            }
            Err(ProcessExecutionError::UnknownOutcome)
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }
}

impl Drop for WindowsProcessExecutor {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

impl ProcessExecutor for WindowsProcessExecutor {
    #[allow(
        clippy::too_many_lines,
        reason = "the suspend, validate-and-consume, resume, capture, and registration order is security-critical"
    )]
    async fn start(
        &self,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
        request.validate()?;
        let operation_id = request.operation_id().clone();
        let _reservation = self.reserve_operation(operation_id.clone())?;

        #[cfg(not(windows))]
        {
            let _ = (request, sink);
            return Err(unavailable(
                "Windows ProcessExecutor is unavailable on this target",
            ));
        }

        #[cfg(windows)]
        {
            if !request.environment().secret_refs().is_empty() {
                return Err(unavailable(
                    "secret environment references require an admitted secret projection",
                ));
            }
            let executable = Path::new(request.executable());
            let digest = sha256_file(executable).map_err(unavailable)?;
            if !digest.eq_ignore_ascii_case(request.executable_sha256()) {
                return Err(unavailable(
                    "executable digest does not match ProcessRequest",
                ));
            }
            let environment = request
                .environment()
                .non_secret()
                .iter()
                .map(|(name, value)| (name.clone().into(), value.clone().into()))
                .collect::<Vec<_>>();
            let spec = SuspendedLaunchSpec::new(
                executable,
                request.argv().iter().cloned().map(Into::into).collect(),
                request.working_directory(),
                environment,
            )
            .map_err(unavailable)?;
            let active_limit = request
                .resource_limits()
                .max_descendants()
                .checked_add(1)
                .ok_or_else(|| unavailable("descendant limit overflows Job limit"))?;
            let limits = JobObjectLimits::new(
                request.resource_limits().cpu_time_ms(),
                request.resource_limits().memory_bytes(),
                Some(active_limit),
            )
            .map_err(unavailable)?;
            let stdout_limit = request.resource_limits().stdout_bytes();
            let stderr_limit = request.resource_limits().stderr_bytes();
            let stdout_requested = stdout_limit > 0;
            let stderr_requested = stderr_limit > 0;
            let wall_timeout_ms = request.resource_limits().wall_timeout_ms();
            let sequence = JOB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let job_name = JobObjectIdentity::new(format!(
                "Local\\Eliot-P04-{}-{}",
                std::process::id(),
                sequence
            ))
            .map_err(unavailable)?;
            let child = SuspendedJobChild::spawn_named_with_limits(spec, job_name, limits)
                .map_err(unavailable)?;

            // Issue-84 start state machine: `SuspendedLaunch` (above) →
            // `AuthorityValidation` (below) → `Resumed` → `CaptureSetup` →
            // `WatcherSetup` → `RegistryPublication` → `ReceiptPublication`.
            // The Job object, kill-on-close contour, resource limits, and
            // stdio pipes were already created and owned while the child was
            // suspended (pre-resume infrastructure, where Windows mechanics
            // allow it). Resume must precede stream-capture ownership: the
            // stdout/stderr read handles live on `RunningJobChild` and can
            // only be taken after resume; the deadline watcher enforces the
            // admitted deadline for the registered `Operation` owner.
            //
            // `start_phase` is the live state-machine cursor: it is assigned
            // at every transition below and consumed into the quarantine
            // evidence on every post-resume failure path, so the
            // caller → implementation → consumer chain is real.
            let mut start_phase = StartPhase::SuspendedLaunch;
            debug_assert_eq!(start_phase, StartPhase::SuspendedLaunch);
            let authority = Arc::clone(&self.authority);
            let launch_admission = self.launch_admission.as_ref().map(Arc::clone);
            let validated = child
                .validate(|evidence| {
                    let observed = suspended_identity(&request, evidence)?;
                    let executable = evidence.executable_file_identity();
                    let launch = SuspendedLaunchEvidence::new(
                        evidence.requested_executable().to_string_lossy(),
                        executable.volume_serial_number,
                        executable.file_index,
                    )?;
                    if let Some(admission) = &launch_admission {
                        admission.validate_launch(&request, &observed, &launch)?;
                    }
                    authority.validate_and_consume(request, observed)
                })
                .map_err(validation_error)?;
            // `AuthorityValidation`: the one-shot permit was consumed against
            // fresh suspended evidence above.
            start_phase = StartPhase::AuthorityValidation;
            debug_assert_eq!(start_phase, StartPhase::AuthorityValidation);
            let mut state = ProcessState::from_validated(validated.validation());
            // `Resumed`: resume must precede stream-capture ownership — the
            // stdout/stderr read handles live on `RunningJobChild` and can
            // only be taken after `resume()`.
            let mut running = validated.resume().map_err(unavailable)?;
            start_phase = StartPhase::Resumed;
            let now = now_ms();
            state.mark_resumed(
                now,
                ProcessHealth::new(
                    ProcessHealthStatus::Healthy,
                    true,
                    now,
                    Some("P-02 suspended launch and resume observed".to_owned()),
                )?,
            )?;
            let stdout = Arc::new(Mutex::new(CaptureSession::new(
                "stdout",
                retention(stdout_limit, self.capture_limit),
                stdout_requested,
            )));
            let stderr = Arc::new(Mutex::new(CaptureSession::new(
                "stderr",
                retention(stderr_limit, self.capture_limit),
                stderr_requested,
            )));
            let deadline = Instant::now()
                .checked_add(Duration::from_millis(wall_timeout_ms))
                .ok_or_else(|| unavailable("wall timeout overflows monotonic clock"))?;
            // Issue-84 start state machine: `Resumed` (just observed above) →
            // `CaptureSetup` (below). Capture threads must follow resume
            // because the read handles live on `RunningJobChild`. Every
            // phase at/after `Resumed` must contain the Job tree through the
            // admitted owner — never a bare error that orphans a live child.
            debug_assert_eq!(start_phase, StartPhase::Resumed);
            start_phase = StartPhase::CaptureSetup;
            debug_assert_eq!(start_phase, StartPhase::CaptureSetup);
            let mut capture_spawn_error = None;
            let mut capture_failure = None;
            #[cfg(test)]
            let stdout_injection = {
                #[cfg(windows)]
                {
                    s84_capture_injection(&operation_id, "stdout")
                }
                #[cfg(not(windows))]
                {
                    None
                }
            };
            #[cfg(not(test))]
            let stdout_injection: Option<CaptureSpawnInjection> = None;
            // Issue-267 sink sessions open here, after resume and before the
            // first admitted byte: the binding, kind, policy, limits, and
            // deterministic identity travel in the open request, and the drain
            // threads below append per chunk. An open failure keeps `None` so
            // the legacy `SourceUnavailable` path applies (provider failure
            // never claims a complete source).
            let stream_binding = state.view().binding().clone();
            let stdout_pump = open_stream_pump(
                self.stream_sink.as_ref(),
                &stream_binding,
                ProcessStreamKind::Stdout,
                stdout_requested,
            );
            let stderr_pump = open_stream_pump(
                self.stream_sink.as_ref(),
                &stream_binding,
                ProcessStreamKind::Stderr,
                stderr_requested,
            );
            let stdout_thread = match spawn_capture(
                "stdout",
                running.take_stdout(),
                Arc::clone(&stdout),
                stdout_injection,
                stdout_pump.clone(),
            ) {
                Ok(thread) => thread,
                Err(error) => {
                    capture_spawn_error = Some(error);
                    capture_failure = Some(CaptureFailure {
                        stream: "stdout",
                        thread_id: None,
                        disposition: CaptureFailureDisposition::SpawnFailed,
                    });
                    None
                }
            };
            let stderr_thread = if capture_spawn_error.is_none() {
                #[cfg(test)]
                let stderr_injection = {
                    #[cfg(windows)]
                    {
                        s84_capture_injection(&operation_id, "stderr")
                    }
                    #[cfg(not(windows))]
                    {
                        None
                    }
                };
                #[cfg(not(test))]
                let stderr_injection: Option<CaptureSpawnInjection> = None;
                match spawn_capture(
                    "stderr",
                    running.take_stderr(),
                    Arc::clone(&stderr),
                    stderr_injection,
                    stderr_pump.clone(),
                ) {
                    Ok(thread) => thread,
                    Err(error) => {
                        capture_spawn_error = Some(error);
                        capture_failure = Some(CaptureFailure {
                            stream: "stderr",
                            thread_id: None,
                            disposition: CaptureFailureDisposition::SpawnFailed,
                        });
                        None
                    }
                }
            } else {
                None
            };
            // `CaptureSetup` reached: both read-handle takes are consumed
            // (state fences the flow — a take consumes the handle, so the
            // second arm cannot re-take).
            debug_assert_eq!(start_phase, StartPhase::CaptureSetup);
            let operation = Arc::new(Mutex::new(Operation {
                state,
                sink,
                child: Some(running),
                stdout,
                stderr,
                stdout_thread,
                stderr_thread,
                stdout_pump,
                stderr_pump,
                deadline,
                deadline_watcher: None,
                deadline_watcher_owner: None,
                watcher_fail_closed_contained: false,
                start_publish_gap: None,
                start_phase,
                timed_out: false,
                cleanup_required: false,
                termination: None,
                capture_failures: capture_failure.into_iter().collect(),
            }));
            if capture_spawn_error.is_some() {
                let Some(error) = capture_spawn_error else {
                    // The flag above is only set together with the error; a
                    // missing error here means a logic break, fenced locally.
                    return Err(ProcessExecutionError::UnknownOutcome);
                };
                // Fail closed AFTER resume (issue #84 §2): the child is already
                // running, so retain the Job/process owner, stop new effect
                // authority (the op is fenced and never gets a receipt),
                // terminate/contain the COMPLETE Job tree through the admitted
                // process owner (`finalize_operation` → `terminate_in_place`
                // with `JOB_TERMINATION_CODE` plus descendant/exit/capture
                // evidence), THEN fence locally as UnknownOutcome and return
                // the typed failed/unknown start disposition with the exact
                // operation identity. The op is registered first so it stays
                // queryable/cancellable/reconcilable until terminal cleanup is
                // proven; no unrelated op is touched (#82 operation-local
                // contour). Never a bare `Err` that orphans a live child.
                let finalize_result = {
                    let mut guard = operation
                        .lock()
                        .map_err(|_| unavailable("operation lock poisoned"))?;
                    guard.start_phase = start_phase;
                    let finalize_result =
                        finalize_operation(&mut guard, ExitDisposition::Unknown, false);
                    quarantine_operation(&mut guard);
                    let _ = quarantine_snapshot(&operation_id, &guard, CAPTURE_EVIDENCE_GAP);
                    finalize_result
                };
                // `finalize_operation` joins the surviving capture thread, so
                // the half-installed capture owner cannot leak: when stdout
                // spawned but stderr failed, the stdout thread is joined above
                // and its drained bytes stay on the retained op for reconcile.
                if self
                    .operations
                    .lock()
                    .map(|mut registry| {
                        registry.insert(operation_id.clone(), Arc::clone(&operation));
                    })
                    .is_err()
                {
                    // The Job tree is already contained through the admitted
                    // owner above; only registry publication failed. Fence
                    // stays local on the retained op, report typed unknown.
                    return Err(ProcessExecutionError::UnknownOutcome);
                }
                return match finalize_result {
                    Ok(()) => Err(error),
                    Err(_) => Err(ProcessExecutionError::UnknownOutcome),
                };
            }
            // Mint the operation-bound watcher owner BEFORE installing the
            // thread so ownership is queryable from the moment enforcement
            // exists (issue #83 §1), then hand the minted owner to the
            // watcher spawn. The watcher thread owns the wall deadline
            // independently of inspect()/reconcile() polling. State machine
            // phase: `WatcherSetup` (still post-resume: the child is live).
            debug_assert_eq!(start_phase, StartPhase::CaptureSetup);
            start_phase = StartPhase::WatcherSetup;
            debug_assert_eq!(start_phase, StartPhase::WatcherSetup);
            let watcher_owner = deadline_watcher_owner_id(&operation_id);
            let Ok(deadline_watcher) = spawn_deadline_watcher(&operation_id, &operation) else {
                // Fail closed AFTER resume (issues #83 §2 / #84 §2): the child is
                // already running, so terminate/contain the COMPLETE Job
                // tree through the admitted process owner
                // (`finalize_operation` → `terminate_in_place` with
                // `JOB_TERMINATION_CODE` plus descendant/exit evidence), THEN
                // fence locally as UnknownOutcome and return the typed
                // unknown/failed start disposition with the operation ID and
                // cleanup owner — never a normal receipt, never a bare error
                // that orphans the tree. The op is registered first so it
                // stays queryable/cancellable/reconcilable until terminal
                // cleanup is proven, and no unrelated op is touched (#82:
                // no global poison; #84 keeps that contract).
                let mut guard = operation
                    .lock()
                    .map_err(|_| unavailable("operation lock poisoned"))?;
                guard.start_phase = start_phase;
                if finalize_operation(&mut guard, ExitDisposition::Unknown, false).is_err() {
                    // Finalize already stored partial termination/cleanup
                    // evidence on the op; fall through to fencing.
                }
                guard.watcher_fail_closed_contained = true;
                quarantine_operation(&mut guard);
                let _ = quarantine_snapshot(&operation_id, &guard, WATCHER_EVIDENCE_GAP);
                drop(guard);
                if self
                    .operations
                    .lock()
                    .map(|mut registry| {
                        registry.insert(operation_id.clone(), Arc::clone(&operation));
                    })
                    .is_err()
                {
                    return Err(ProcessExecutionError::UnknownOutcome);
                }
                return Err(ProcessExecutionError::UnknownOutcome);
            };
            let Ok(mut guard) = operation.lock() else {
                let _ = join_deadline_watcher(deadline_watcher);
                // The operation was never registered; the reservation guard
                // releases the identity so a retry with the same id can start
                // cleanly and no reservation is stranded.
                return Err(ProcessExecutionError::UnknownOutcome);
            };
            guard.deadline_watcher = Some(deadline_watcher);
            // Bind the minted owner to the operation only after the thread
            // installed successfully, so a queryable owner always implies a
            // real enforcement thread. Receipt publication (#84) happens at
            // the end, only after ALL mandatory control owners are installed
            // and the resumed child identity is durably registered.
            // State machine phase: `RegistryPublication` — the exact point
            // FAIL_START_PUBLISH_FOR hooks so tests can prove containment.
            guard.deadline_watcher_owner = Some(watcher_owner);
            guard.start_phase = StartPhase::WatcherSetup;
            // All mandatory control owners are now installed (both capture
            // threads + deadline watcher). Snapshot the Running view for the
            // initial evidence record BEFORE registry publication.
            let view = guard.state.view();
            let sink = Arc::clone(&guard.sink);
            drop(guard);
            debug_assert_eq!(start_phase, StartPhase::WatcherSetup);
            start_phase = StartPhase::RegistryPublication;
            debug_assert_eq!(start_phase, StartPhase::RegistryPublication);
            #[cfg(test)]
            let s84_registry_publish_fail =
                s84_take_injection(&FAIL_START_PUBLISH_FOR, &operation_id, &["registry"]);
            #[cfg(not(test))]
            let s84_registry_publish_fail = false;
            if s84_registry_publish_fail {
                // Injected post-resume registry-publication failure (issue
                // #84 §4): retain the Job/process owner, stop new effect
                // authority, contain the tree through the admitted owner,
                // then fence locally and KEEP the (contained) op registered
                // so it stays queryable/cancellable/reconcilable. Never a
                // bare error that orphans a live child; never global poison.
                let mut guard = operation
                    .lock()
                    .map_err(|_| unavailable("operation lock poisoned"))?;
                guard.start_phase = start_phase;
                if finalize_operation(&mut guard, ExitDisposition::Unknown, false).is_err() {
                    // Finalize already stored partial termination/cleanup
                    // evidence on the op; fall through to fencing.
                }
                guard.watcher_fail_closed_contained = true;
                guard.start_publish_gap = Some(PUBLISH_EVIDENCE_GAP);
                quarantine_operation(&mut guard);
                let _ = quarantine_snapshot(&operation_id, &guard, PUBLISH_EVIDENCE_GAP);
                drop(guard);
                if self
                    .operations
                    .lock()
                    .map(|mut registry| {
                        registry.insert(operation_id.clone(), Arc::clone(&operation));
                    })
                    .is_err()
                {
                    return Err(ProcessExecutionError::UnknownOutcome);
                }
                return Err(ProcessExecutionError::UnknownOutcome);
            }
            let evidence = ProcessEvidence::new_typed(view, None, None, EvidenceAxes::observed());
            let published = match evidence {
                Ok(evidence) => sink.record(evidence).is_ok(),
                Err(_) => false,
            };
            let Ok(mut guard) = operation.lock() else {
                // Never stranding: the operation was never registered, so the
                // reservation guard releases the exact identity and a retry
                // with the same id can start cleanly.
                return Err(ProcessExecutionError::UnknownOutcome);
            };
            if !published {
                // Sink-publication failure is operation-local: fence this op,
                // register it so it stays inspectable/cancellable/
                // reconcilable, and return without touching unrelated ops.
                // (#84: post-resume but pre-receipt, so the start already
                // owns a resumed child — the retained op already carries the
                // Job owner and the fence stops any new effect authority.)
                guard.start_phase = start_phase;
                quarantine_operation(&mut guard);
                let _ = quarantine_snapshot(&operation_id, &guard, SINK_EVIDENCE_GAP);
                drop(guard);
                if let Ok(mut registry) = self.operations.lock() {
                    registry
                        .entry(operation_id.clone())
                        .or_insert_with(|| Arc::clone(&operation));
                }
                return Err(ProcessExecutionError::UnknownOutcome);
            }
            // State machine phase: `ReceiptPublication` — start receipt
            // publication only after ALL mandatory control owners are
            // installed (both capture threads + deadline watcher) and the
            // resumed child identity is durably registered below. The last
            // FAIL_START_PUBLISH_FOR hook fires here.
            debug_assert_eq!(start_phase, StartPhase::RegistryPublication);
            start_phase = StartPhase::ReceiptPublication;
            debug_assert_eq!(start_phase, StartPhase::ReceiptPublication);
            #[cfg(test)]
            let s84_receipt_publish_fail =
                s84_take_injection(&FAIL_START_PUBLISH_FOR, &operation_id, &["receipt"]);
            #[cfg(not(test))]
            let s84_receipt_publish_fail = false;
            if s84_receipt_publish_fail {
                // Injected receipt-publication failure after a durably
                // registered op: contain the COMPLETE Job tree through the
                // admitted owner (same `finalize_operation` →
                // `terminate_in_place(JOB_TERMINATION_CODE)` containment as
                // the capture/registry paths), then fence locally, KEEP the
                // op queryable, never hand out a receipt, never touch
                // unrelated ops. The op stays registered UnknownOutcome with
                // the cleanup owner, same as the other post-resume paths.
                let mut guard = operation
                    .lock()
                    .map_err(|_| unavailable("operation lock poisoned"))?;
                guard.start_phase = start_phase;
                if finalize_operation(&mut guard, ExitDisposition::Unknown, false).is_err() {
                    // Finalize already stored partial termination/cleanup
                    // evidence on the op; fall through to fencing.
                }
                guard.start_publish_gap = Some(PUBLISH_EVIDENCE_GAP);
                quarantine_operation(&mut guard);
                let _ = quarantine_snapshot(&operation_id, &guard, PUBLISH_EVIDENCE_GAP);
                drop(guard);
                if let Ok(mut registry) = self.operations.lock() {
                    registry
                        .entry(operation_id.clone())
                        .or_insert_with(|| Arc::clone(&operation));
                }
                return Err(ProcessExecutionError::UnknownOutcome);
            }
            if self
                .operations
                .lock()
                .map(|mut registry| {
                    registry.insert(operation_id.clone(), Arc::clone(&operation));
                })
                .is_err()
            {
                // A poisoned registry on the success path must not fabricate
                // success: fence the (unregistered) operation locally and
                // report unknown while leaving every other operation alone.
                guard.start_phase = start_phase;
                quarantine_operation(&mut guard);
                return Err(ProcessExecutionError::UnknownOutcome);
            }
            let Ok(receipt) = ProcessStartReceipt::new(&guard.state) else {
                // The operation is already registered above, so the receipt
                // failure stays local: fence this op, keep it queryable for
                // reconcile/shutdown, and never close unrelated paths.
                guard.start_phase = start_phase;
                quarantine_operation(&mut guard);
                let _ = quarantine_snapshot(&operation_id, &guard, RECEIPT_EVIDENCE_GAP);
                return Err(ProcessExecutionError::UnknownOutcome);
            };
            Ok(receipt)
        }
    }

    async fn inspect(
        &self,
        operation_id: OperationId,
    ) -> Result<ProcessExecutionView, ProcessExecutionError> {
        #[cfg(windows)]
        {
            let operation = self.operation(&operation_id)?;
            // Per-operation lock only: a poisoned Mutex for another operation
            // never surfaces here. Lock loss maps to this operation's typed
            // `Unavailable`, never to shared executor state.
            let mut guard = operation
                .lock()
                .map_err(|_| operation_unavailable(&operation_id, "operation lock"))?;
            if let Err(error) = refresh_operation(&mut guard) {
                quarantine_operation(&mut guard);
                // A fenced op already surfaces its honest typed outcome; a
                // live op that failed observation here fences above and
                // likewise reports unknown instead of any contract error.
                if guard.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome {
                    return Err(ProcessExecutionError::UnknownOutcome);
                }
                return Err(error);
            }
            Ok(guard.state.view())
        }
        #[cfg(not(windows))]
        {
            let _ = operation_id;
            Err(unavailable(
                "Windows ProcessExecutor is unavailable on this target",
            ))
        }
    }

    async fn cancel(
        &self,
        operation_id: OperationId,
    ) -> Result<CancellationReceipt, ProcessExecutionError> {
        #[cfg(windows)]
        {
            let operation = self.operation(&operation_id)?;
            // Cancel is the protected control path: it must stay available
            // for this operation even while another operation is fenced as
            // unknown. Only this operation's lock is touched; a poisoned
            // Mutex for operation A maps to A's typed `Unavailable` and can
            // never surface as a failure for operation B.
            let mut guard = operation
                .lock()
                .map_err(|_| operation_unavailable(&operation_id, "operation lock"))?;
            let binding = guard.state.view().binding().clone();
            if let Err(error) = guard
                .state
                .cancel(&CancellationRequest::new(binding.clone()))
            {
                quarantine_operation(&mut guard);
                return Err(error.into());
            }
            if guard.state.view().lifecycle() == ProcessLifecycle::Cancelling {
                let finalize_result =
                    finalize_operation(&mut guard, ExitDisposition::Cancelled, true);
                // Land cancel-before-EOF on any session the finalize path
                // could not join to EOF (early containment returns, abandoned
                // threads): the guarded landing preserves an EOF the drain
                // already proved, so the healthy cancel-receipt path keeps its
                // exact closure evidence while a genuinely cut-short capture
                // lands typed `CancelledBeforeEof` for exactly this op.
                mark_operation_cancelled_before_eof(&guard.stdout, &guard.stderr);
                if let Err(error) = finalize_result {
                    quarantine_operation(&mut guard);
                    // `finalize_operation` is the same tree-termination path the
                    // start failure routes use: it may have fenced this op as
                    // `UnknownOutcome` while proving the containment attempt, or
                    // it may surface a typed contract error for the same fence.
                    // Surface the honest typed outcome instead of falling through
                    // to a second `cancel()` projection that can never succeed
                    // from `UnknownOutcome` (and would fabricate an
                    // `InvalidTransition` contract error for a contained op).
                    if guard.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome {
                        return Err(ProcessExecutionError::UnknownOutcome);
                    }
                    return Err(error);
                }
            }
            // Re-read the receipt after the finalize path so the returned
            // descendants prove the post-finalize tree state instead of the
            // pre-finalize gap. Terminal states re-report the stored closure
            // evidence through the existing cancel projection; an
            // UnknownOutcome landing surfaces the typed unknown outcome while
            // the operation stays retained for reconcile/shutdown.
            // `CancellationReceipt` carries no cleanup-required field, so the
            // typed error is the only honest carrier for unproven closure.
            match guard.state.cancel(&CancellationRequest::new(binding)) {
                Ok(receipt) => Ok(receipt),
                Err(error) => {
                    quarantine_operation(&mut guard);
                    if guard.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome {
                        return Err(ProcessExecutionError::UnknownOutcome);
                    }
                    Err(error.into())
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = operation_id;
            Err(unavailable(
                "Windows ProcessExecutor is unavailable on this target",
            ))
        }
    }

    async fn reconcile(
        &self,
        operation_id: OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError> {
        #[cfg(windows)]
        {
            let operation = self.operation(&operation_id)?;
            // Reconcile fences only this operation: a refresh or typed
            // stream-evidence gap quarantines this op and returns its typed
            // `UnknownOutcome`, never a shared executor state. The op stays
            // retained for shutdown/reconcile disposition; no success is
            // fabricated.
            let mut guard = operation
                .lock()
                .map_err(|_| operation_unavailable(&operation_id, "operation lock"))?;
            if let Err(error) = refresh_operation(&mut guard) {
                quarantine_operation(&mut guard);
                // Same redundant-fence mapping as `inspect` (see above): a
                // natural-exit `UnknownOutcome` computed by
                // `refresh_operation` races the `quarantine_operation` fence
                // through `ProcessState::exit`, and the losing fence must
                // surface the honest typed outcome, never an
                // `InvalidTransition` contract error.
                if guard.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome {
                    return Err(ProcessExecutionError::UnknownOutcome);
                }
                return Err(error);
            }
            if guard.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome {
                let Some(descendants) = guard.state.view().descendants().cloned() else {
                    return Err(ProcessExecutionError::UnknownOutcome);
                };
                if !descendants.complete() || !descendants.tree_terminated() {
                    return Err(ProcessExecutionError::UnknownOutcome);
                }
                guard.state.reconcile(descendants)?;
            }
            if !join_streams(&mut guard) {
                quarantine_operation(&mut guard);
                return Err(ProcessExecutionError::UnknownOutcome);
            }
            let view = guard.state.view();
            let binding = view.binding().clone();
            let stdout_typed = match typed_stream_evidence(
                &guard.stdout,
                guard.stdout_pump.as_ref(),
                ProcessStreamKind::Stdout,
                &binding,
            ) {
                Ok(stream) => stream,
                Err(error) => {
                    quarantine_operation(&mut guard);
                    return Err(error);
                }
            };
            let stderr_typed = match typed_stream_evidence(
                &guard.stderr,
                guard.stderr_pump.as_ref(),
                ProcessStreamKind::Stderr,
                &binding,
            ) {
                Ok(stream) => stream,
                Err(error) => {
                    quarantine_operation(&mut guard);
                    return Err(error);
                }
            };
            let Ok(evidence) = ProcessEvidence::new_typed(
                view,
                stdout_typed,
                stderr_typed,
                EvidenceAxes::observed(),
            ) else {
                quarantine_operation(&mut guard);
                return Err(ProcessExecutionError::UnknownOutcome);
            };
            guard.sink.record(evidence.clone())?;
            Ok(evidence)
        }
        #[cfg(not(windows))]
        {
            let _ = operation_id;
            Err(unavailable(
                "Windows ProcessExecutor is unavailable on this target",
            ))
        }
    }
}

#[cfg(windows)]
fn suspended_identity(
    request: &ProcessRequest,
    evidence: &SuspendedProcessEvidence,
) -> Result<SuspendedProcessIdentity, ContractError> {
    let process_id = ProcessId::new(format!(
        "windows-process:{}",
        short_digest(evidence.process().stable_key().as_bytes())
    ))?;
    SuspendedProcessIdentity::new(
        process_id,
        request.process_tree_id().clone(),
        request.job_id().clone(),
        request.image_id().clone(),
        request.session_id().clone(),
        request.generation(),
        PhysicalProcessBinding::new(
            evidence.process().process_id,
            evidence.process().start_time_100ns,
            evidence.process().image_path.clone(),
            evidence.job_identity().name(),
        )?,
        now_ms(),
        request.executable_sha256(),
    )
}

#[cfg(windows)]
fn validation_error<E: std::fmt::Display>(
    error: SuspendedValidationError<E>,
) -> ProcessExecutionError {
    match error {
        SuspendedValidationError::Mechanics(error) => unavailable(error),
        SuspendedValidationError::Rejected(error) => unavailable(error),
    }
}

#[cfg(windows)]
fn refresh_operation(operation: &mut Operation) -> Result<(), ProcessExecutionError> {
    // Observation is fenced to this operation only: an observation or
    // finalization failure returns this op's typed `UnknownOutcome` (or the
    // typed finalize error) while the caller quarantines just this op. No
    // shared executor state is touched, so an independent operation's
    // inspect/cancel/reconcile/start path stays available.
    if operation.state.view().lifecycle().is_terminal() {
        return Ok(());
    }
    if !operation.timed_out && Instant::now() >= operation.deadline {
        operation.timed_out = true;
        return finalize_operation(operation, ExitDisposition::ResourceLimit, false);
    }
    let Some(child) = operation.child.as_ref() else {
        return Err(ProcessExecutionError::UnknownOutcome);
    };
    match child.observe().map_err(unavailable)? {
        RunningJobObservation::Running { .. } => Ok(()),
        RunningJobObservation::RootExited { .. } | RunningJobObservation::Exited { .. } => {
            finalize_operation(operation, ExitDisposition::Completed, false)
        }
    }
}

/// Joins both capture streams for a finalizing operation.
///
/// A cancelled capture that never reached EOF (abandoned thread, missing
/// join, lock loss) lands typed `CancelledBeforeEof` here for exactly this
/// operation; landed EOF/read terminals are preserved, so a healthy drain
/// keeps its exact closure evidence.
#[cfg(windows)]
fn join_finalize_streams(
    operation: &mut Operation,
    cancelled: bool,
) -> Result<(), ProcessExecutionError> {
    if !join_streams(operation) {
        if cancelled {
            mark_operation_cancelled_before_eof(&operation.stdout, &operation.stderr);
        }
        return Err(ProcessExecutionError::UnknownOutcome);
    }
    if cancelled {
        mark_operation_cancelled_before_eof(&operation.stdout, &operation.stderr);
    }
    Ok(())
}

#[cfg(windows)]
fn finalize_operation(
    operation: &mut Operation,
    disposition: ExitDisposition,
    cancelled: bool,
) -> Result<(), ProcessExecutionError> {
    let Some(child) = operation.child.as_mut() else {
        return Err(ProcessExecutionError::UnknownOutcome);
    };
    let observed_root_exit = match child.observe().map_err(unavailable)? {
        RunningJobObservation::RootExited { exit_code, .. }
        | RunningJobObservation::Exited { exit_code } => Some(exit_code),
        RunningJobObservation::Running { .. } => None,
    };
    let termination = child
        .terminate_in_place(JOB_TERMINATION_CODE)
        .map_err(unavailable)?;
    let observed_exit_code = termination.observed_exit_code();
    let history = termination.history().clone();
    let ids = history
        .processes()
        .iter()
        .filter_map(|observation| {
            ProcessId::new(format!(
                "windows-process:{}",
                short_digest(observation.process().stable_key().as_bytes())
            ))
            .ok()
        })
        .collect::<Vec<_>>();
    let evidence_ref = format!(
        "raw:p04-job-history:{}:{}:{}",
        ids.len(),
        history.complete(),
        history.job_empty()
    );
    let (process_ids, complete, tree_terminated, evidence_ref) = (
        ids,
        history.complete(),
        history.job_empty(),
        Some(evidence_ref),
    );
    let view = operation.state.view();
    let Some(identity) = view.identity() else {
        operation.termination = Some(termination);
        operation.cleanup_required = true;
        return Err(ProcessExecutionError::UnknownOutcome);
    };
    let descendants = match DescendantEvidence::new(
        view.binding().clone(),
        identity.process_id().clone(),
        process_ids,
        complete,
        tree_terminated,
        evidence_ref,
    ) {
        Ok(descendants) => descendants,
        Err(error) => {
            operation.termination = Some(termination);
            operation.cleanup_required = true;
            return Err(error.into());
        }
    };
    let actual_disposition = if !complete || !tree_terminated {
        ExitDisposition::Unknown
    } else if observed_root_exit.is_some() {
        ExitDisposition::Completed
    } else if cancelled {
        ExitDisposition::Cancelled
    } else if disposition == ExitDisposition::Completed {
        // A completion request without a root-exit observation cannot be
        // projected as a successful completion, even when Job termination
        // itself succeeded.  The adapter's forced-termination code is not a
        // substitute for the child outcome.
        ExitDisposition::Unknown
    } else {
        disposition
    };
    let code = if actual_disposition == ExitDisposition::Unknown {
        None
    } else {
        observed_root_exit.or(Some(observed_exit_code))
    };
    let exit = match ExitStatus::new(actual_disposition, code, None, now_ms()) {
        Ok(exit) => exit,
        Err(error) => {
            operation.termination = Some(termination);
            operation.cleanup_required = true;
            return Err(error.into());
        }
    };
    if join_finalize_streams(operation, cancelled).is_err() {
        operation.termination = Some(termination);
        operation.cleanup_required = true;
        return Err(ProcessExecutionError::UnknownOutcome);
    }
    if let Err(error) = operation.state.exit(exit, descendants) {
        operation.termination = Some(termination);
        operation.cleanup_required = true;
        // `ProcessState::exit` computes the `UnknownOutcome` fence internally
        // whenever tree closure is unproven, but its `ensure_transition`
        // gate can still reject that fence when the op already sits at
        // `UnknownOutcome` (e.g. a cancel-then-terminate race: cancel fenced
        // first, the contained tree termination lands second). The tree IS
        // contained through the admitted owner here (`terminate_in_place`
        // above), so map the redundant-fence rejection to the honest typed
        // `UnknownOutcome` instead of fabricating an `InvalidTransition`
        // contract error for a contained op.
        if operation.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome {
            return Err(ProcessExecutionError::UnknownOutcome);
        }
        return Err(error.into());
    }
    let _ = operation.child.take();
    Ok(())
}

#[cfg(windows)]
fn fence_unknown(operation: &mut Operation) -> Result<(), ProcessExecutionError> {
    if operation.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome {
        return Ok(());
    }
    let view = operation.state.view();
    let identity = view
        .identity()
        .ok_or(ProcessExecutionError::UnknownOutcome)?;
    let descendants = DescendantEvidence::new(
        view.binding().clone(),
        identity.process_id().clone(),
        Vec::new(),
        false,
        false,
        None,
    )?;
    let exit = ExitStatus::new(ExitDisposition::Unknown, None, None, now_ms())?;
    operation.state.exit(exit, descendants)?;
    Ok(())
}

#[cfg(windows)]
fn quarantine_operation(operation: &mut Operation) {
    // Per-operation quarantine only: the executor holds no global poison
    // flag, so fencing this operation (retaining its Job/stream cleanup
    // owner for reconcile/shutdown) never closes inspect/cancel/reconcile/
    // start for an independent operation.
    operation.cleanup_required = true;
    let _ = fence_unknown(operation);
}

/// Exact evidence-gap labels surfaced per quarantined operation.
#[cfg(windows)]
const CAPTURE_EVIDENCE_GAP: &str = "capture-thread spawn failed";
#[cfg(windows)]
const SINK_EVIDENCE_GAP: &str = "initial evidence sink publication failed";
#[cfg(windows)]
const WATCHER_EVIDENCE_GAP: &str = "deadline watcher spawn failed";
#[cfg(windows)]
const RECEIPT_EVIDENCE_GAP: &str = "start receipt binding invalid";
#[cfg(windows)]
const PUBLISH_EVIDENCE_GAP: &str = "start publication failed after resume";
#[cfg(windows)]
const RECOVERY_ACTION: &str = "reconcile-or-cleanup explicit disposition; shutdown retains owner";

#[cfg(windows)]
fn quarantine_snapshot(
    id: &OperationId,
    operation: &Operation,
    evidence_gap: &'static str,
) -> QuarantinedOperationRecord {
    let view = operation.state.view();
    let binding = view.binding();
    let descendants = view.descendants();
    QuarantinedOperationRecord {
        operation_id: id.clone(),
        process_tree_id: binding.process_tree_id().clone(),
        job_id: binding.job_id().clone(),
        image_id: binding.image_id().clone(),
        session_id: binding.session_id().clone(),
        lifecycle: view.lifecycle(),
        evidence_gap,
        capture_failures: operation
            .capture_failures
            .iter()
            .map(|failure| (failure.stream.to_owned(), failure.disposition.as_str()))
            .collect(),
        deadline_watcher_owner: operation.deadline_watcher_owner.clone(),
        wall_time_enforcement_installed: operation.deadline_watcher_owner.is_some(),
        watcher_fail_closed_contained: operation.watcher_fail_closed_contained,
        start_phase: operation.start_phase.as_str(),
        descendants_complete: descendants.map(DescendantEvidence::complete),
        tree_terminated: descendants.map(DescendantEvidence::tree_terminated),
        cleanup_pending: operation.cleanup_required
            || view.lifecycle() == ProcessLifecycle::UnknownOutcome,
        recovery_action: RECOVERY_ACTION,
    }
}

#[cfg(windows)]
fn quarantined_record(
    id: &OperationId,
    operation: &Operation,
) -> Option<QuarantinedOperationRecord> {
    if !operation.cleanup_required
        && operation.state.view().lifecycle() != ProcessLifecycle::UnknownOutcome
    {
        return None;
    }
    let view = operation.state.view();
    let binding = view.binding();
    let descendants = view.descendants();
    // Wall-time enforcement health is an explicit dimension, separate from
    // stream-capture health (issue #83 §5): a missing watcher owner surfaces
    // the watcher gap even when both streams are complete. A recorded
    // post-resume start-publication gap (issue #84) surfaces next: the op
    // kept all control owners and stayed registered, so the gap names the
    // publication step instead of a capture/watcher owner.
    let evidence_gap = if let Some(publish_gap) = operation.start_publish_gap {
        publish_gap
    } else if operation.deadline_watcher_owner.is_none() && operation.watcher_fail_closed_contained
    {
        WATCHER_EVIDENCE_GAP
    } else if operation.capture_failures.is_empty() {
        "unknown outcome fenced; cleanup/reconciliation pending"
    } else {
        CAPTURE_EVIDENCE_GAP
    };
    Some(QuarantinedOperationRecord {
        operation_id: id.clone(),
        process_tree_id: binding.process_tree_id().clone(),
        job_id: binding.job_id().clone(),
        image_id: binding.image_id().clone(),
        session_id: binding.session_id().clone(),
        lifecycle: view.lifecycle(),
        evidence_gap,
        capture_failures: operation
            .capture_failures
            .iter()
            .map(|failure| (failure.stream.to_owned(), failure.disposition.as_str()))
            .collect(),
        deadline_watcher_owner: operation.deadline_watcher_owner.clone(),
        wall_time_enforcement_installed: operation.deadline_watcher_owner.is_some(),
        watcher_fail_closed_contained: operation.watcher_fail_closed_contained,
        start_phase: operation.start_phase.as_str(),
        descendants_complete: descendants.map(DescendantEvidence::complete),
        tree_terminated: descendants.map(DescendantEvidence::tree_terminated),
        cleanup_pending: operation.cleanup_required
            || view.lifecycle() == ProcessLifecycle::UnknownOutcome,
        recovery_action: RECOVERY_ACTION,
    })
}

#[cfg(not(windows))]
fn quarantined_record(
    _id: &OperationId,
    _operation: &Operation,
) -> Option<QuarantinedOperationRecord> {
    None
}

/// Mints the operation-bound deadline-watcher owner identity.
///
/// Pure helper (no I/O, no locks) so receipt publication order (#84) and
/// watcher installation order can both be audited against the same minted
/// value: `deadline-watcher:<operation-id>`.
#[cfg(windows)]
fn deadline_watcher_owner_id(operation_id: &OperationId) -> String {
    format!("deadline-watcher:{}", operation_id.as_str())
}

#[cfg(windows)]
fn spawn_deadline_watcher(
    operation_id: &OperationId,
    operation: &Arc<Mutex<Operation>>,
) -> Result<DeadlineWatcher, ProcessExecutionError> {
    // Issue-84 state machine note (§1): the deadline watcher is spawned AFTER
    // resume because it enforces the admitted wall deadline for the
    // registered `Operation` owner; pre-resume there is no resumed child
    // identity to observe and no registered owner to attribute enforcement
    // to. The fail-closed path below terminates the tree on spawn failure.
    #[cfg(test)]
    if FAIL_NEXT_DEADLINE_WATCHER_SPAWN.swap(false, Ordering::AcqRel) {
        return Err(unavailable("injected deadline watcher spawn failure"));
    }
    // Issue-83 identity-scoped injection: fails exactly the armed operation
    // identity (test-only; production callers never arm it). An unrelated
    // concurrent start takes the production spawn and leaves the arm intact.
    #[cfg(test)]
    if s83_should_fail_watcher_spawn(operation_id) {
        return Err(unavailable("injected deadline watcher spawn failure"));
    }

    // Operation-bound owner minted BEFORE the thread exists so every join,
    // shutdown sweep, and quarantine projection attributes this watcher to
    // exactly one operation (issue #83 §1).
    let owner = deadline_watcher_owner_id(operation_id);
    let thread_owner = owner.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let operation = Arc::downgrade(operation);
    let handle = thread::Builder::new()
        .name("eliot-p04-deadline".to_owned())
        .spawn(move || {
            // Autonomous wall-time enforcement: this loop owns the admitted
            // deadline and fences the operation on breach every 25ms without
            // waiting for any inspect()/reconcile() poll (issue #83 §4).
            loop {
                if thread_stop.load(Ordering::Acquire) {
                    return;
                }
                thread::sleep(WATCH_INTERVAL);
                if thread_stop.load(Ordering::Acquire) {
                    return;
                }
                let Some(operation) = operation.upgrade() else {
                    return;
                };
                let Ok(mut guard) = operation.lock() else {
                    return;
                };
                if guard.state.view().lifecycle().is_terminal() {
                    return;
                }
                // Enforce ownership: only refresh the op this watcher was
                // minted for. A mismatched owner is a logic error, never a
                // reason to touch another op's Job.
                if guard.deadline_watcher_owner.as_deref() != Some(thread_owner.as_str()) {
                    return;
                }
                if refresh_operation(&mut guard).is_err() {
                    // A failed observation is an external-state gap, not a
                    // reason to detach the Job.  Fence the operation as
                    // unknown and retain it for explicit reconciliation or
                    // final shutdown cleanup.
                    quarantine_operation(&mut guard);
                    return;
                }
            }
        })
        .map_err(|error| unavailable(format!("deadline watcher spawn failed: {error}")))?;
    Ok(DeadlineWatcher {
        owner,
        stop,
        handle: Some(handle),
    })
}

#[cfg(windows)]
fn join_deadline_watcher(watcher: DeadlineWatcher) -> Result<(), ProcessExecutionError> {
    watcher.stop_and_join()
}

#[cfg(all(test, windows))]
static FAIL_NEXT_DEADLINE_WATCHER_SPAWN: AtomicBool = AtomicBool::new(false);

/// One-shot set of operation identities whose next watcher spawn fails.
#[cfg(all(test, windows))]
static FAIL_WATCHER_SPAWN_FOR: std::sync::Mutex<std::collections::BTreeSet<String>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

#[cfg(all(test, windows))]
fn s83_arm_watcher_failure_for(operation_id: &OperationId) {
    if let Ok(mut guard) = FAIL_WATCHER_SPAWN_FOR.lock() {
        guard.insert(operation_id.as_str().to_owned());
    }
}

#[cfg(all(test, windows))]
fn s83_disarm_watcher_failure_for(operation_id: &OperationId) {
    if let Ok(mut guard) = FAIL_WATCHER_SPAWN_FOR.lock() {
        guard.remove(operation_id.as_str());
    }
}

#[cfg(all(test, windows))]
fn s83_should_fail_watcher_spawn(operation_id: &OperationId) -> bool {
    match FAIL_WATCHER_SPAWN_FOR.lock() {
        Ok(mut guard) => guard.remove(operation_id.as_str()),
        Err(_) => false,
    }
}

/// One-shot sets of operation/job keys whose next stream-capture spawn or
/// start-publication step fails (issue #84 §4, test-only).
///
/// `FAIL_STDOUT_SPAWN_FOR`/`FAIL_STDERR_SPAWN_FOR` are honored inside
/// `spawn_capture` at the exact capture-thread creation point; matching is
/// key lookup against the exact operation identity plus the `"stdout"` /
/// `"stderr"` stream label, so tests can prove tree containment from the
/// precise failure point. `FAIL_START_PUBLISH_FOR` is honored at the exact
/// registry-publication and receipt-publication points: registry insertion
/// keeps the admitted Job owner and registration guard, so a
/// resume-then-publish failure still fences locally. All sets are
/// identity-scoped `BTreeSet<String>`s: membership is one-shot (consumed on
/// match), unrelated identities take the production path and never steal
/// another op's arm. Production code paths that read these helpers never
/// arm them.
#[cfg(all(test, windows))]
static FAIL_STDOUT_SPAWN_FOR: std::sync::Mutex<std::collections::BTreeSet<String>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

#[cfg(all(test, windows))]
static FAIL_STDERR_SPAWN_FOR: std::sync::Mutex<std::collections::BTreeSet<String>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

#[cfg(all(test, windows))]
static FAIL_START_PUBLISH_FOR: std::sync::Mutex<std::collections::BTreeSet<String>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

#[cfg(all(test, windows))]
fn s84_arm_stdout_failure_for(key: &str) {
    // Empty means the hook is disarmed. Membership makes the injection
    // exact under parallelism: an unrelated concurrent start takes the
    // production spawn (its identity is not a member) and can neither
    // steal nor be fenced by another op's arm. Test-only: production code
    // paths that read this helper never arm it.
    if let Ok(mut guard) = FAIL_STDOUT_SPAWN_FOR.lock() {
        guard.insert(key.to_owned());
    }
}

#[cfg(all(test, windows))]
fn s84_disarm_stdout_failure_for(key: &str) {
    if let Ok(mut guard) = FAIL_STDOUT_SPAWN_FOR.lock() {
        guard.remove(key);
    }
}

/// Arms the exact stderr capture-spawn failure key. Both stream arms exist
/// so each stream has a symmetric hook; the 2-test acceptance uses stdout
/// plus publish, while stderr stays available for follow-up fault waves.
#[cfg(all(test, windows))]
#[allow(dead_code, reason = "symmetric stderr hook for follow-up fault waves")]
fn s84_arm_stderr_failure_for(key: &str) {
    if let Ok(mut guard) = FAIL_STDERR_SPAWN_FOR.lock() {
        guard.insert(key.to_owned());
    }
}

/// Clears a stderr capture-spawn failure key. Called from the fault-test
/// cleanup path so an unconsumed arm can never leak into another test.
#[cfg(all(test, windows))]
#[allow(dead_code, reason = "symmetric stderr hook for follow-up fault waves")]
fn s84_disarm_stderr_failure_for(key: &str) {
    if let Ok(mut guard) = FAIL_STDERR_SPAWN_FOR.lock() {
        guard.remove(key);
    }
}

#[cfg(all(test, windows))]
fn s84_arm_start_publish_failure_for(key: &str) {
    if let Ok(mut guard) = FAIL_START_PUBLISH_FOR.lock() {
        guard.insert(key.to_owned());
    }
}

#[cfg(all(test, windows))]
fn s84_disarm_start_publish_failure_for(key: &str) {
    if let Ok(mut guard) = FAIL_START_PUBLISH_FOR.lock() {
        guard.remove(key);
    }
}

#[cfg(all(test, windows))]
fn s84_take_injection(
    set: &std::sync::Mutex<std::collections::BTreeSet<String>>,
    operation_id: &OperationId,
    extra_keys: &[&str],
) -> bool {
    match set.lock() {
        Ok(mut guard) => {
            if guard.remove(operation_id.as_str()) {
                return true;
            }
            for key in extra_keys {
                if guard.remove(*key) {
                    return true;
                }
            }
            false
        }
        Err(_) => false,
    }
}

/// Unit marker proving an armed capture-spawn injection matched this
/// `(operation, stream)` pair at the call site. `spawn_capture` honors it
/// at the exact thread-creation point; the marker itself carries no payload.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CaptureSpawnInjection {
    stream: &'static str,
}

#[cfg(all(test, windows))]
fn s84_capture_injection(
    operation_id: &OperationId,
    stream: &'static str,
) -> Option<CaptureSpawnInjection> {
    let armed = if stream == "stdout" {
        s84_take_injection(&FAIL_STDOUT_SPAWN_FOR, operation_id, &["stdout"])
    } else {
        s84_take_injection(&FAIL_STDERR_SPAWN_FOR, operation_id, &["stderr"])
    };
    armed.then_some(CaptureSpawnInjection { stream })
}

/// Scope guard disarming every key the issue-84 stdout test arms, so an
/// early return cannot leak an arm into another test running at default
/// parallelism. The armed key is identity-scoped; the `"stdout"` stream
/// label covers the same hook when armed by step label.
#[cfg(all(test, windows))]
struct S84StdoutArmGuard<'a> {
    op_key: &'a str,
}

#[cfg(all(test, windows))]
impl Drop for S84StdoutArmGuard<'_> {
    fn drop(&mut self) {
        s84_disarm_stdout_failure_for(self.op_key);
        s84_disarm_stdout_failure_for("stdout");
    }
}

/// Scope guard disarming every key the issue-84 publish test arms (the
/// op identity plus both step labels), so an early return cannot leak an
/// arm into another test running at default parallelism.
#[cfg(all(test, windows))]
struct S84PublishArmGuard<'a> {
    op_key: &'a str,
}

#[cfg(all(test, windows))]
impl Drop for S84PublishArmGuard<'_> {
    fn drop(&mut self) {
        s84_disarm_start_publish_failure_for(self.op_key);
        s84_disarm_start_publish_failure_for("registry");
        s84_disarm_start_publish_failure_for("receipt");
    }
}

#[cfg(windows)]
fn session_join_disposition(
    status: CaptureDisposition,
    thread_id: Option<&String>,
) -> Option<CaptureFailureDisposition> {
    // One owned session maps to exactly one join verdict: EOF drains pass,
    // read failures keep their typed contour, and every non-EOF terminal
    // (cancelled-before-EOF, capture-unavailable, unknown, still draining)
    // fences as incomplete/spawn-failed instead of fabricating completeness.
    match status {
        CaptureDisposition::Eof => None,
        CaptureDisposition::ReadFailed => Some(CaptureFailureDisposition::ReadFailed),
        CaptureDisposition::CancelledBeforeEof
        | CaptureDisposition::CaptureUnavailable
        | CaptureDisposition::UnknownOutcome
        | CaptureDisposition::Draining => Some(if thread_id.is_some() {
            CaptureFailureDisposition::Incomplete
        } else {
            CaptureFailureDisposition::SpawnFailed
        }),
    }
}

#[cfg(windows)]
fn join_streams(operation: &mut Operation) -> bool {
    let stdout_result = join_capture_thread(&mut operation.stdout_thread, "stdout");
    let stderr_result = join_capture_thread(&mut operation.stderr_thread, "stderr");
    let mut failures = Vec::new();
    if let Err(failure) = &stdout_result {
        failures.push(failure.clone());
    }
    if let Err(failure) = &stderr_result {
        failures.push(failure.clone());
    }
    // An unrequested stream never owns a pipe: it stays `CaptureUnavailable`
    // with zero claimed bytes and can never fail a join. Only requested
    // sessions resolve through the typed join verdict, so a limit-0 stream
    // keeps the base pass behavior instead of fencing as spawn-failed.
    if let Ok(thread_id) = &stdout_result
        && session_requested(&operation.stdout)
        && let Some(disposition) =
            session_join_disposition(session_status(&operation.stdout), thread_id.as_ref())
    {
        failures.push(CaptureFailure {
            stream: "stdout",
            thread_id: thread_id.clone(),
            disposition,
        });
    }
    if let Ok(thread_id) = &stderr_result
        && session_requested(&operation.stderr)
        && let Some(disposition) =
            session_join_disposition(session_status(&operation.stderr), thread_id.as_ref())
    {
        failures.push(CaptureFailure {
            stream: "stderr",
            thread_id: thread_id.clone(),
            disposition,
        });
    }
    for failure in &failures {
        if !operation.capture_failures.contains(failure) {
            operation.capture_failures.push(failure.clone());
        }
    }
    failures.is_empty()
}

#[cfg(windows)]
fn join_capture_thread(
    thread_slot: &mut Option<JoinHandle<()>>,
    stream: &'static str,
) -> Result<Option<String>, CaptureFailure> {
    let Some(thread) = thread_slot.as_ref() else {
        return Ok(None);
    };
    let thread_id = Some(format!("{:?}", thread.thread().id()));
    if !thread.is_finished() {
        let _ = cancel_capture_thread_io(thread);
        let deadline = Instant::now()
            .checked_add(STREAM_JOIN_TIMEOUT)
            .unwrap_or_else(Instant::now);
        while !thread.is_finished() && Instant::now() < deadline {
            thread::sleep(STREAM_JOIN_POLL);
        }
    }
    if !thread.is_finished() {
        return Err(CaptureFailure {
            stream,
            thread_id,
            disposition: CaptureFailureDisposition::Timeout,
        });
    }
    let Some(thread) = thread_slot.take() else {
        return Err(CaptureFailure {
            stream,
            thread_id,
            disposition: CaptureFailureDisposition::Panicked,
        });
    };
    if thread.join().is_err() {
        return Err(CaptureFailure {
            stream,
            thread_id,
            disposition: CaptureFailureDisposition::Panicked,
        });
    }
    Ok(thread_id)
}

#[cfg(windows)]
fn session_status(session: &Arc<Mutex<CaptureSession>>) -> CaptureDisposition {
    session
        .lock()
        .map_or(CaptureDisposition::UnknownOutcome, |guard| {
            guard.disposition()
        })
}

/// Lands `CancelledBeforeEof` on both stream sessions of one cancelled
/// operation through the guarded single-terminal landing.
///
/// A session that already reached `Eof`/`ReadFailed`/unavailable/unknown keeps
/// its terminal, so a healthy drain that already proved EOF is never rewritten
/// (the #83 cancel-receipt path never regresses). A session still draining —
/// abandoned thread, missing join, or containment failure — honestly records
/// that cancellation ended capture before EOF. Lock loss keeps the prior state
/// and is fenced as `UnknownOutcome` by the join path for exactly this
/// operation; nothing is fabricated and no sibling operation is touched.
#[cfg(windows)]
fn mark_operation_cancelled_before_eof(
    stdout: &Arc<Mutex<CaptureSession>>,
    stderr: &Arc<Mutex<CaptureSession>>,
) {
    for session in [stdout, stderr] {
        if let Ok(mut guard) = session.lock() {
            guard.cancel_before_eof();
        }
    }
}

/// Returns whether one capture session was requested.
///
/// An unrequested session never owns a pipe and can never fail a join: it
/// stays `CaptureUnavailable` with zero claimed bytes. Requested sessions
/// always resolve through [`session_join_disposition`].
#[cfg(windows)]
fn session_requested(session: &Arc<Mutex<CaptureSession>>) -> bool {
    session.lock().is_ok_and(|guard| guard.requested())
}

/// Opens one policy-bound sink session for a requested stream.
///
/// Returns `None` when no sink client is attached, the stream was not
/// requested, or the open itself failed: every `None` keeps the legacy
/// `SourceUnavailable` evidence path, so a provider failure never claims a
/// complete source. A successful open happens-before the drain thread's first
/// admitted byte at the call site.
#[cfg(windows)]
fn open_stream_pump(
    client: Option<&Arc<dyn ProcessStreamSinkClient>>,
    binding: &ProcessExecutionBinding,
    kind: ProcessStreamKind,
    requested: bool,
) -> Option<Arc<Mutex<StreamSinkPump>>> {
    if !requested {
        return None;
    }
    let client = client.map(Arc::clone)?;
    let policy = p04_stream_policy().ok()?;
    let limits = sink_backpressure_limits().ok()?;
    let mut pump = StreamSinkPump::new(client, binding.clone(), kind, policy, limits);
    pump.open().ok()?;
    Some(Arc::new(Mutex::new(pump)))
}

/// Best-effort sink settle for a cleanup/reopen pass.
///
/// Reads back the provider-held session identity without finalizing, so an
/// out-of-band terminal surfaces under the same session instead of minting a
/// second receipt. Errors are ignored: cleanup never fails because the sink
/// is unreachable, and exactly-one-terminal stays owned by finalize/abort.
#[cfg(windows)]
fn settle_sink_pump(pump: &Arc<Mutex<StreamSinkPump>>) {
    if let Ok(mut pump) = pump.lock()
        && pump.terminal().is_none()
    {
        let _ = pump.reopen();
    }
}

#[cfg(windows)]
fn spawn_capture(
    stream: &'static str,
    file: Option<std::fs::File>,
    session: Arc<Mutex<CaptureSession>>,
    injection: Option<CaptureSpawnInjection>,
    sink_pump: Option<Arc<Mutex<StreamSinkPump>>>,
) -> Result<Option<JoinHandle<()>>, ProcessExecutionError> {
    // Issue-84 state machine note (§1): stream-capture ownership is installed
    // AFTER resume because the read handles live on `RunningJobChild` and can
    // only be taken after `resume()`; pre-resume there is nothing to drain.
    // A spawn failure here therefore runs the post-resume fail-closed path
    // (tree containment through the admitted owner) instead of a bare return.
    //
    // `injection` is `Some` exactly when the armed one-shot key matched this
    // `(operation, stream)` pair at the call site; honoring it here keeps the
    // failure at the exact capture-thread creation point.
    if injection.is_some() {
        return Err(unavailable(format!(
            "injected {stream} capture spawn failure"
        )));
    }
    let requested = session
        .lock()
        .map_err(|_| unavailable(format!("{stream} capture lock poisoned")))?
        .requested();
    if !requested {
        return Ok(None);
    }
    let Some(mut file) = file else {
        // The pipe handle is missing while the stream was requested: fence
        // this session as capture-unavailable so production never claims a
        // byte it did not observe and never mints a durable-source handle.
        if let Ok(mut guard) = session.lock() {
            guard.mark_capture_unavailable();
        }
        return Err(unavailable(format!(
            "requested {stream} capture reader handle is missing"
        )));
    };
    let thread = thread::Builder::new()
        .name("eliot-p04-stream".to_owned())
        .spawn(move || {
            // Claim drain ownership before the first read so
            // `capture_available` is exact from thread start.
            if let Ok(mut guard) = session.lock() {
                guard.mark_draining();
            } else {
                return;
            }
            let mut buffer = [0_u8; STREAM_CHUNK_BYTES];
            let mut reached_eof = false;
            let mut read_failed = false;
            loop {
                match file.read(&mut buffer) {
                    Ok(0) => {
                        reached_eof = true;
                        break;
                    }
                    Ok(read) => {
                        let Some(mut guard) = session.lock().ok() else {
                            return;
                        };
                        // Bounded memory: the full digest/count always advance
                        // over the observed bytes while only the prefix stays
                        // retained. A lock loss here ends the drain without
                        // landing a disposition; the join path fences unknown.
                        guard.observe(&buffer[..read]);
                        drop(guard);
                        // Policy-bound streaming: offer the same chunk to the
                        // sink exactly once with the session wait budget. The
                        // pump sheds (never retries, never sleeps) on
                        // backpressure, timeout, or provider failure, and a
                        // lost pump lock is skipped the same way — the pipe
                        // keeps draining in every case, so persistence can
                        // never block capture.
                        if let Some(pump) = &sink_pump
                            && let Ok(mut pump) = pump.lock()
                        {
                            let _ = pump.append(&buffer[..read]);
                        }
                    }
                    Err(_) => {
                        read_failed = true;
                        break;
                    }
                }
            }
            // Land exactly one terminal disposition from the bytes actually
            // observed: zero-byte EOF keeps the empty digest/count, a read
            // failure keeps the observed prefix queryable, and no
            // durable-source handle string is ever minted. The landing is
            // guarded so a cancellation that already ended capture keeps its
            // typed `CancelledBeforeEof` instead of being overwritten by a
            // trailing EOF/read result from torn-down pipes.
            if let Ok(mut guard) = session.lock() {
                if read_failed {
                    guard.land_drain_terminal(CaptureDisposition::ReadFailed);
                } else if reached_eof {
                    guard.land_drain_terminal(CaptureDisposition::Eof);
                } else {
                    guard.land_drain_terminal(CaptureDisposition::UnknownOutcome);
                }
            }
        })
        .map_err(|error| unavailable(format!("{stream} capture reader spawn failed: {error}")))?;
    Ok(Some(thread))
}

#[cfg(windows)]
fn p04_stream_policy() -> Result<ProcessStreamPolicyBinding, ProcessExecutionError> {
    // P-04 raw-transport preview-only policy binding. No durable provider is
    // wired in P-04 and no redaction is applied; parsing stays Raw and
    // evaluation stays Unassessed via `new_raw_inner`.
    // - policy_ref `p04:stream-policy:transport-preview-v1`: P-04 offers only a
    //   bounded raw-transport prefix preview, never a durable complete source.
    // - privacy_ref `p04:privacy:raw-transport-preview`: raw child bytes are
    //   shown unredacted in the preview; no privacy transformation is applied.
    // - visibility_ref `p04:visibility:operation-diagnostic`: the preview is
    //   visible to the operation owner for diagnostics, not a canonical
    //   disclosure.
    // - retention_ref `p04:retention:bounded-prefix-only`: only a bounded
    //   in-memory prefix is retained; no durable retention is claimed.
    // - redaction_ref `p04:redaction:none-raw-preview`: no redaction or
    //   transformation is applied to the preview bytes.
    ProcessStreamPolicyBinding::new(
        "p04:stream-policy:transport-preview-v1",
        "p04:privacy:raw-transport-preview",
        "p04:visibility:operation-diagnostic",
        "p04:retention:bounded-prefix-only",
        "p04:redaction:none-raw-preview",
    )
    .map_err(|_| ProcessExecutionError::UnknownOutcome)
}

/// Maps one owned capture session to its exact transport status.
///
/// Every terminal session state has exactly one typed transport contour:
/// EOF drains stay `Complete`, read failures stay `ReadFailed`,
/// cancellation-before-EOF stays `CancelledBeforeEof`, and both
/// capture-unavailable and unknown-outcome stay `UnknownOutcome`. A session
/// still draining is never promoted: it reports `UnknownOutcome` so
/// `ProcessEvidence` construction waits for the terminal (or an explicitly
/// partial/unavailable) disposition instead of fabricating completeness.
#[cfg(windows)]
fn session_transport(disposition: CaptureDisposition) -> StreamTransportStatus {
    match disposition {
        CaptureDisposition::Draining | CaptureDisposition::UnknownOutcome => {
            StreamTransportStatus::UnknownOutcome
        }
        CaptureDisposition::Eof => StreamTransportStatus::Complete,
        CaptureDisposition::ReadFailed => StreamTransportStatus::ReadFailed,
        CaptureDisposition::CaptureUnavailable => StreamTransportStatus::CaptureUnavailable,
        CaptureDisposition::CancelledBeforeEof => StreamTransportStatus::CancelledBeforeEof,
    }
}

#[cfg(windows)]
fn typed_stream_evidence(
    session: &Arc<Mutex<CaptureSession>>,
    sink_pump: Option<&Arc<Mutex<StreamSinkPump>>>,
    kind: ProcessStreamKind,
    binding: &ProcessExecutionBinding,
) -> Result<Option<ProcessStreamEvidence>, ProcessExecutionError> {
    // One owned session resolves to exactly one typed evidence. With a sink
    // pump attached, EOF finalizes and cancel-before-EOF aborts through the
    // #267 port to exactly one terminal, and the terminal's evidence is the
    // durable record: its source is `Some` exactly on complete/partial
    // terminals and `None` with an exact gap otherwise (a zero-byte EOF still
    // publishes a real verifiable object). A provider failure on the sink
    // path falls through to the honest-gap construction below — never a
    // complete source. Without a pump, an EOF session resolves exactly as
    // before (bounded preview, `SourceUnavailable`, no source locator, no
    // `raw:*` handle); every other disposition keeps its honest typed state
    // instead of fabricating complete proof.
    let (retained, total_bytes, observed_sha256, disposition, backpressured) = {
        let guard = session
            .lock()
            .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
        if !guard.requested() {
            return Ok(None);
        }
        if !guard.capture_available() {
            // Requested but no drain thread owns the pipe (missing handle or
            // spawn failure fenced at setup): the stream is capture-
            // unavailable with exact zero-byte custody and no source
            // locator.
            let policy = p04_stream_policy()?;
            let preview = ProcessStreamPrefixPreview::from_transport_prefix(Vec::new(), 0)
                .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
            let evidence = ProcessStreamEvidence::new_raw(
                binding.clone(),
                kind,
                policy,
                StreamTransportStatus::CaptureUnavailable,
                StreamPersistenceStatus::SourceUnavailable,
                crate::empty_sha256_hex(),
                0,
                preview,
                None,
                vec![StreamEvidenceGap::CaptureUnavailable],
            )
            .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
            return Ok(Some(evidence));
        }
        let disposition = guard.disposition();
        match disposition {
            CaptureDisposition::Eof | CaptureDisposition::CancelledBeforeEof => {}
            CaptureDisposition::ReadFailed
            | CaptureDisposition::CaptureUnavailable
            | CaptureDisposition::UnknownOutcome
            | CaptureDisposition::Draining => {
                return Err(ProcessExecutionError::UnknownOutcome);
            }
        }
        let observed_sha256 = guard.observed_sha256();
        (
            guard.prefix().to_vec(),
            guard.total_bytes(),
            observed_sha256,
            disposition,
            guard.backpressure_observed(),
        )
    };
    if let Some(pump) = sink_pump {
        match sink_terminal_evidence(pump, disposition) {
            Ok(evidence) => return Ok(Some(evidence)),
            Err(_) => {
                if disposition == CaptureDisposition::CancelledBeforeEof {
                    return legacy_cancelled_evidence(
                        binding,
                        kind,
                        retained,
                        total_bytes,
                        observed_sha256,
                        backpressured,
                    )
                    .map(Some);
                }
            }
        }
    } else if disposition == CaptureDisposition::CancelledBeforeEof {
        return Err(ProcessExecutionError::UnknownOutcome);
    }
    let mut prefix = retained;
    if prefix.len() > EVIDENCE_PREVIEW_CEILING {
        prefix.truncate(EVIDENCE_PREVIEW_CEILING);
    }
    let policy = p04_stream_policy()?;
    let transport = session_transport(disposition);
    let preview = ProcessStreamPrefixPreview::from_transport_prefix(prefix, total_bytes)
        .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
    // Legacy path (no sink pump attached, or the pump's provider failed on an
    // EOF drain): no durable provider is wired in P-04 and the store backend
    // is T3-owned, so persistence stays `SourceUnavailable` with no source
    // locator (no `raw:*` handle is ever minted). When the session latched
    // sink-pressure overflow while draining, the exact
    // `PersistenceBackpressure` gap travels alongside
    // `PersistenceUnavailable`: pressure was shed and the pipe kept draining
    // with exact digest/count, instead of blocking capture on persistence I/O.
    // The complete evidence still resolves to bytes whose digest/count match
    // the full observed stream: `observed_sha256`/`observed_bytes` above are
    // the session accumulators over every drained byte, and the preview
    // carries the bounded retained prefix with its exact `[retained, observed)`
    // omission range.
    let mut gaps = vec![StreamEvidenceGap::PersistenceUnavailable];
    if backpressured {
        gaps.push(StreamEvidenceGap::PersistenceBackpressure);
    }
    let evidence = ProcessStreamEvidence::new_raw(
        binding.clone(),
        kind,
        policy,
        transport,
        StreamPersistenceStatus::SourceUnavailable,
        observed_sha256,
        total_bytes,
        preview,
        None,
        gaps,
    )
    .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
    Ok(Some(evidence))
}

/// Settles one owned session through its sink pump to the terminal evidence.
///
/// EOF finalizes and cancel-before-EOF aborts; every other disposition fails
/// closed. The pump enforces the terminal/evidence contract (source exactly
/// on complete/partial terminals, never otherwise) before returning.
#[cfg(windows)]
fn sink_terminal_evidence(
    pump: &Arc<Mutex<StreamSinkPump>>,
    disposition: CaptureDisposition,
) -> Result<ProcessStreamEvidence, ProcessExecutionError> {
    let mut pump = pump
        .lock()
        .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
    let terminal = match disposition {
        CaptureDisposition::Eof => pump.finalize_eof()?,
        CaptureDisposition::CancelledBeforeEof => pump.abort_cancelled()?,
        CaptureDisposition::ReadFailed
        | CaptureDisposition::CaptureUnavailable
        | CaptureDisposition::UnknownOutcome
        | CaptureDisposition::Draining => {
            return Err(ProcessExecutionError::UnknownOutcome);
        }
    };
    Ok(terminal.evidence().clone())
}

/// Builds the provider-failure fallback for a cancelled drain.
///
/// The sink pump was attached but could not settle a terminal, so the locally
/// observed admitted prefix stays claimed with the exact cancellation gap and
/// `SourceUnavailable` persistence: never a complete source, never a source
/// locator. Gaps stay canonically sorted (`PersistenceUnavailable`,
/// `PersistenceBackpressure`, `CancelledBeforeEof`).
#[cfg(windows)]
#[allow(
    clippy::too_many_arguments,
    reason = "the fallback carries the exact observed custody plus the typed gap set"
)]
fn legacy_cancelled_evidence(
    binding: &ProcessExecutionBinding,
    kind: ProcessStreamKind,
    retained: Vec<u8>,
    total_bytes: u64,
    observed_sha256: String,
    backpressured: bool,
) -> Result<ProcessStreamEvidence, ProcessExecutionError> {
    let mut prefix = retained;
    if prefix.len() > EVIDENCE_PREVIEW_CEILING {
        prefix.truncate(EVIDENCE_PREVIEW_CEILING);
    }
    let policy = p04_stream_policy()?;
    let preview = ProcessStreamPrefixPreview::from_transport_prefix(prefix, total_bytes)
        .map_err(|_| ProcessExecutionError::UnknownOutcome)?;
    let mut gaps = vec![StreamEvidenceGap::PersistenceUnavailable];
    if backpressured {
        gaps.push(StreamEvidenceGap::PersistenceBackpressure);
    }
    gaps.push(StreamEvidenceGap::CancelledBeforeEof);
    ProcessStreamEvidence::new_raw(
        binding.clone(),
        kind,
        policy,
        StreamTransportStatus::CancelledBeforeEof,
        StreamPersistenceStatus::SourceUnavailable,
        observed_sha256,
        total_bytes,
        preview,
        None,
        gaps,
    )
    .map_err(|_| ProcessExecutionError::UnknownOutcome)
}

fn retention(limit: u64, ceiling: usize) -> usize {
    usize::try_from(limit).unwrap_or(usize::MAX).min(ceiling)
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; STREAM_CHUNK_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn short_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Canonical SHA-256 hex over zero observed bytes.
///
/// The zero-byte-EOF identity: a capture session that drained nothing still
/// resolves its `observed_sha256` to this digest, and capture-unavailable
/// transport claims exactly this digest with a zero count.
#[must_use]
pub fn empty_sha256_hex() -> String {
    short_digest(&[])
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().try_into().unwrap_or(u64::MAX)
        })
}

fn unavailable(error: impl std::fmt::Display) -> ProcessExecutionError {
    ProcessExecutionError::Unavailable(error.to_string())
}

/// Maps a per-operation lock loss to that operation's typed `Unavailable`.
///
/// The executor carries no global poison flag: every `Mutex` guard loss is
/// scoped to the operation identity being served, so a poisoned lock for
/// operation A can never degrade inspect/cancel/reconcile/start for an
/// independent operation B. Consumers (testd/native-worker/User-Broker)
/// receive this per-operation `Unavailable` (or `UnknownOutcome` for fenced
/// evidence gaps) instead of any fabricated success or global failure.
///
/// `what` names the failed lock owner (never raw output): the message carries
/// the exact operation identity plus the lock scope, so a typed degradation
/// for A is distinguishable from a healthy path for B.
#[cfg(windows)]
fn operation_unavailable(operation_id: &OperationId, what: &'static str) -> ProcessExecutionError {
    ProcessExecutionError::Unavailable(format!(
        "operation {} {what} unavailable",
        operation_id.as_str()
    ))
}

/// Maps a registry/reservation lock loss without attributing it to one
/// operation, while still keeping it executor-local (never global poison).
#[cfg(windows)]
fn registry_unavailable(what: &'static str) -> ProcessExecutionError {
    ProcessExecutionError::Unavailable(format!("operation registry {what} unavailable"))
}

#[cfg(test)]
mod tests {
    use super::{DispatchValidationPort, WindowsProcessExecutor};
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, EnvironmentInheritance,
        EnvironmentProjection, EvidenceSinkError, FencingToken, Generation, ImageId, JobId,
        KernelDispatchKey, OperationId, PermitIssuance, ProcessEvidence, ProcessEvidenceSink,
        ProcessExecutionError, ProcessExecutor, ProcessIntent, ProcessRequest, ProcessTreeId,
        ResourceLimits, SecretRef, SessionId, SuspendedProcessIdentity, ValidatedDispatch,
    };
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    #[cfg(windows)]
    use eliot_instrument_api::EvidenceAxes;
    #[cfg(windows)]
    use eliot_platform::ClockObservation;
    #[cfg(windows)]
    use eliot_process::{
        CancellationStatus, DispatchValidationContext, ExitDisposition, ProcessLifecycle,
    };

    fn test_epoch(sequence: u64) -> eliot_contracts::EpochId {
        use eliot_contracts::{EpochId, EpochLineageId};
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A");
        EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn revisions() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("authority".to_owned(), "a".repeat(64)),
            ("state".to_owned(), "b".repeat(64)),
        ])
    }

    #[derive(Default)]
    struct RecordingSink {
        evidence: Mutex<Vec<ProcessEvidence>>,
    }

    impl ProcessEvidenceSink for RecordingSink {
        fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
            match self.evidence.lock() {
                Ok(mut guard) => {
                    guard.push(evidence);
                    Ok(())
                }
                Err(_) => Err(EvidenceSinkError {
                    message: "recording sink lock poisoned".to_owned(),
                }),
            }
        }
    }

    impl RecordingSink {
        fn recorded_len(&self) -> usize {
            match self.evidence.lock() {
                Ok(guard) => guard.len(),
                Err(_) => usize::MAX,
            }
        }

        fn recorded_one(&self) -> Option<ProcessEvidence> {
            match self.evidence.lock() {
                Ok(guard) => guard.first().cloned(),
                Err(_) => None,
            }
        }
    }

    struct DummyPort;

    impl DispatchValidationPort for DummyPort {
        fn validate_and_consume(
            &self,
            _request: ProcessRequest,
            _observed: SuspendedProcessIdentity,
        ) -> Result<ValidatedDispatch, ProcessExecutionError> {
            Err(ProcessExecutionError::Unavailable(
                "dummy port must not be called pre-spawn".to_owned(),
            ))
        }
    }

    #[cfg(windows)]
    struct FakePort {
        authority: Mutex<DispatchPermitAuthority>,
        context: DispatchValidationContext,
    }

    #[cfg(windows)]
    impl DispatchValidationPort for FakePort {
        fn validate_and_consume(
            &self,
            request: ProcessRequest,
            observed: SuspendedProcessIdentity,
        ) -> Result<ValidatedDispatch, ProcessExecutionError> {
            let mut authority = self.authority.lock().map_err(|_| {
                ProcessExecutionError::Unavailable("dispatch authority lock poisoned".to_owned())
            })?;
            authority
                .validate_and_consume(request, observed, &self.context)
                .map_err(Into::into)
        }
    }

    #[cfg(windows)]
    struct FailingSink;

    #[cfg(windows)]
    impl ProcessEvidenceSink for FailingSink {
        fn record(&self, _evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
            Err(EvidenceSinkError {
                message: "injected sink failure".to_owned(),
            })
        }
    }

    // Large matrix deferred per START.md s1 — focused recipe only
    // (3 baseline start tests plus 2 T2-S03 reconcile stream tests).
    #[test]
    #[cfg(windows)]
    fn start_publishes_initial_observed_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let executable = r"C:\Windows\System32\cmd.exe";
        let digest = super::sha256_file(std::path::Path::new(executable))?;
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let operation_id = OperationId::new("op-t2-s01-ok")?;
        let generation = Generation::new(1)?;
        let intent = ProcessIntent::new(
            operation_id.clone(),
            ProcessTreeId::new("tree-t2-s01-ok")?,
            JobId::new("job-t2-s01-ok")?,
            ImageId::new("image-t2-s01-ok")?,
            SessionId::new("session-t2-s01-ok")?,
            generation,
            executable,
            digest,
            vec![
                "/c".to_owned(),
                "ping".to_owned(),
                "-n".to_owned(),
                "5".to_owned(),
                "127.0.0.1".to_owned(),
            ],
            working_directory,
            EnvironmentProjection::default(),
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
        )?;
        let fence = FencingToken::new(test_epoch(1), generation, "fence-t2-s01-ok")?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("auth-t2-s01")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new("lease-t2-s01-ok")?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                "nonce-t2-s01-ok",
            )?,
        )?;
        let request = ProcessRequest::new(intent, permit)?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            test_epoch(1),
            revisions(),
            41,
        )?;
        let port = FakePort {
            authority: Mutex::new(authority),
            context,
        };
        let executor = WindowsProcessExecutor::new(Arc::new(port));
        let sink = Arc::new(RecordingSink::default());
        let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
        let _receipt = block_on(executor.start(request, sink_dyn))?;
        assert_eq!(sink.recorded_len(), 1);
        let Some(evidence) = sink.recorded_one() else {
            panic!("expected exactly one recorded evidence")
        };
        assert_eq!(evidence.view().lifecycle(), ProcessLifecycle::Running);
        assert_eq!(evidence.operation_id(), &operation_id);
        assert_eq!(evidence.axes(), EvidenceAxes::observed());
        let inspected = block_on(executor.inspect(operation_id))?;
        assert_eq!(inspected.lifecycle(), ProcessLifecycle::Running);
        Ok(())
    }

    #[test]
    #[cfg(windows)]
    fn start_sink_failure_retains_unknown_outcome() -> Result<(), Box<dyn std::error::Error>> {
        let executable = r"C:\Windows\System32\cmd.exe";
        let digest = super::sha256_file(std::path::Path::new(executable))?;
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let operation_id = OperationId::new("op-t2-s01-sink-fail")?;
        let generation = Generation::new(1)?;
        let intent = ProcessIntent::new(
            operation_id.clone(),
            ProcessTreeId::new("tree-t2-s01-sink-fail")?,
            JobId::new("job-t2-s01-sink-fail")?,
            ImageId::new("image-t2-s01-sink-fail")?,
            SessionId::new("session-t2-s01-sink-fail")?,
            generation,
            executable,
            digest,
            vec![
                "/c".to_owned(),
                "ping".to_owned(),
                "-n".to_owned(),
                "5".to_owned(),
                "127.0.0.1".to_owned(),
            ],
            working_directory,
            EnvironmentProjection::default(),
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
        )?;
        let fence = FencingToken::new(test_epoch(1), generation, "fence-t2-s01-sink-fail")?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("auth-t2-s01")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new("lease-t2-s01-sink-fail")?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                "nonce-t2-s01-sink-fail",
            )?,
        )?;
        let request = ProcessRequest::new(intent, permit)?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            test_epoch(1),
            revisions(),
            41,
        )?;
        let port = FakePort {
            authority: Mutex::new(authority),
            context,
        };
        let executor = WindowsProcessExecutor::new(Arc::new(port));
        let sink_dyn: Arc<dyn ProcessEvidenceSink> = Arc::new(FailingSink);
        let result = block_on(executor.start(request, sink_dyn));
        assert!(matches!(result, Err(ProcessExecutionError::UnknownOutcome)));
        let inspected = block_on(executor.inspect(operation_id))?;
        assert_eq!(inspected.lifecycle(), ProcessLifecycle::UnknownOutcome);
        Ok(())
    }

    #[test]
    fn start_rejects_bad_binding_pre_spawn() -> Result<(), Box<dyn std::error::Error>> {
        let executable = r"C:\Windows\System32\cmd.exe";
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let generation = Generation::new(1)?;
        let fence = FencingToken::new(test_epoch(1), generation, "fence-t2-s01-bad")?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("auth-t2-s01")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let executor = WindowsProcessExecutor::new(Arc::new(DummyPort));
        let tampered_id = OperationId::new("op-t2-s01-bad-sha")?;
        let tampered_intent = ProcessIntent::new(
            tampered_id.clone(),
            ProcessTreeId::new("tree-t2-s01-bad-sha")?,
            JobId::new("job-t2-s01-bad-sha")?,
            ImageId::new("image-t2-s01-bad-sha")?,
            SessionId::new("session-t2-s01-bad-sha")?,
            generation,
            executable,
            "0".repeat(64),
            vec!["/c".to_owned(), "echo".to_owned(), "hi".to_owned()],
            working_directory.clone(),
            EnvironmentProjection::default(),
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
        )?;
        let tampered_permit = authority.issue(
            &tampered_intent,
            PermitIssuance::new(
                ActionLeaseRef::new("lease-t2-s01-bad-sha")?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                "nonce-t2-s01-bad-sha",
            )?,
        )?;
        let tampered_request = ProcessRequest::new(tampered_intent, tampered_permit)?;
        let tampered_sink = Arc::new(RecordingSink::default());
        let tampered_sink_dyn: Arc<dyn ProcessEvidenceSink> = tampered_sink.clone();
        let tampered_result = block_on(executor.start(tampered_request, tampered_sink_dyn));
        assert!(matches!(
            tampered_result,
            Err(ProcessExecutionError::Unavailable(_))
        ));
        assert!(matches!(
            block_on(executor.inspect(tampered_id)),
            Err(ProcessExecutionError::NotFound)
        ));
        assert_eq!(tampered_sink.recorded_len(), 0);
        let secret_id = OperationId::new("op-t2-s01-bad-secret")?;
        let secret_env = EnvironmentProjection::new(
            BTreeMap::new(),
            vec![SecretRef::new("prov-t2-s01", "key-t2-s01")?],
            EnvironmentInheritance::None,
        )?;
        let secret_intent = ProcessIntent::new(
            secret_id.clone(),
            ProcessTreeId::new("tree-t2-s01-bad-secret")?,
            JobId::new("job-t2-s01-bad-secret")?,
            ImageId::new("image-t2-s01-bad-secret")?,
            SessionId::new("session-t2-s01-bad-secret")?,
            generation,
            executable,
            "a".repeat(64),
            vec!["/c".to_owned(), "echo".to_owned(), "hi".to_owned()],
            working_directory,
            secret_env,
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
        )?;
        let secret_permit = authority.issue(
            &secret_intent,
            PermitIssuance::new(
                ActionLeaseRef::new("lease-t2-s01-bad-secret")?,
                fence,
                revisions(),
                100,
                10_000,
                "nonce-t2-s01-bad-secret",
            )?,
        )?;
        let secret_request = ProcessRequest::new(secret_intent, secret_permit)?;
        let secret_sink = Arc::new(RecordingSink::default());
        let secret_sink_dyn: Arc<dyn ProcessEvidenceSink> = secret_sink.clone();
        let secret_result = block_on(executor.start(secret_request, secret_sink_dyn));
        assert!(matches!(
            secret_result,
            Err(ProcessExecutionError::Unavailable(_))
        ));
        assert!(matches!(
            block_on(executor.inspect(secret_id)),
            Err(ProcessExecutionError::NotFound)
        ));
        assert_eq!(secret_sink.recorded_len(), 0);
        Ok(())
    }

    #[cfg(windows)]
    struct CountingFailSink {
        records: Mutex<usize>,
    }

    #[cfg(windows)]
    impl ProcessEvidenceSink for CountingFailSink {
        fn record(&self, _evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
            let mut guard = self.records.lock().map_err(|_| EvidenceSinkError {
                message: "counting sink lock poisoned".to_owned(),
            })?;
            *guard = guard.saturating_add(1);
            if *guard == 1 {
                Ok(())
            } else {
                Err(EvidenceSinkError {
                    message: "injected post-start sink failure".to_owned(),
                })
            }
        }
    }

    #[cfg(windows)]
    fn start_and_reconcile(
        op_tag: &str,
        argv: Vec<String>,
        stdout_limit: u64,
        stderr_limit: u64,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessEvidence, Box<dyn std::error::Error>> {
        let executable = r"C:\Windows\System32\cmd.exe";
        let digest = super::sha256_file(std::path::Path::new(executable))?;
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let operation_id = OperationId::new(format!("op-t2-s03-{op_tag}"))?;
        let generation = Generation::new(1)?;
        let intent = ProcessIntent::new(
            operation_id.clone(),
            ProcessTreeId::new(format!("tree-t2-s03-{op_tag}"))?,
            JobId::new(format!("job-t2-s03-{op_tag}"))?,
            ImageId::new(format!("image-t2-s03-{op_tag}"))?,
            SessionId::new(format!("session-t2-s03-{op_tag}"))?,
            generation,
            executable,
            digest,
            argv,
            working_directory,
            EnvironmentProjection::default(),
            ResourceLimits::new(
                30_000,
                Some(10_000),
                Some(512_000_000),
                stdout_limit,
                stderr_limit,
                4,
            )?,
        )?;
        let fence = FencingToken::new(test_epoch(1), generation, format!("fence-t2-s03-{op_tag}"))?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new(format!("auth-t2-s03-{op_tag}"))?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new(format!("lease-t2-s03-{op_tag}"))?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                format!("nonce-t2-s03-{op_tag}"),
            )?,
        )?;
        let request = ProcessRequest::new(intent, permit)?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            test_epoch(1),
            revisions(),
            41,
        )?;
        let port = FakePort {
            authority: Mutex::new(authority),
            context,
        };
        let executor = WindowsProcessExecutor::new(Arc::new(port));
        let _receipt = block_on(executor.start(request, sink))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let view = block_on(executor.inspect(operation_id.clone()))?;
            if view.lifecycle().is_terminal() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out waiting for terminal lifecycle",
                )
                .into());
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        Ok(block_on(executor.reconcile(operation_id.clone()))?)
    }

    #[cfg(windows)]
    fn assert_truncated_stream(
        stream: &eliot_process::ProcessStreamEvidence,
        expected_retained: u64,
    ) {
        use eliot_process::{
            StreamEvaluationStatus, StreamEvidenceGap, StreamParsingStatus,
            StreamPersistenceStatus, StreamTransportStatus,
        };
        assert_eq!(stream.transport(), StreamTransportStatus::Complete);
        assert_eq!(
            stream.persistence(),
            StreamPersistenceStatus::SourceUnavailable
        );
        assert_eq!(stream.gaps().len(), 1);
        assert_eq!(stream.gaps()[0], StreamEvidenceGap::PersistenceUnavailable);
        assert!(stream.observed_bytes() > expected_retained);
        assert!(stream.preview().is_truncated());
        assert_eq!(stream.preview().retained_bytes(), expected_retained);
        assert_eq!(
            stream.preview().retained_bytes(),
            u64::try_from(stream.preview().bytes().len()).unwrap_or(u64::MAX)
        );
        assert_eq!(
            stream.preview().sha256(),
            super::short_digest(stream.preview().bytes()).as_str()
        );
        assert_eq!(stream.preview().omitted_ranges().len(), 1);
        assert_eq!(
            stream.preview().omitted_ranges()[0].start(),
            expected_retained
        );
        assert_eq!(
            stream.preview().omitted_ranges()[0].end_exclusive(),
            stream.observed_bytes()
        );
        assert_eq!(
            stream.preview().represented_bytes(),
            stream.observed_bytes()
        );
        assert!(stream.source().is_none());
        assert_eq!(stream.parsing(), StreamParsingStatus::Raw);
        assert_eq!(stream.evaluation(), StreamEvaluationStatus::Unassessed);
    }

    #[test]
    #[cfg(windows)]
    fn reconcile_reports_typed_bounded_streams_beyond_preview_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let bat_path = std::env::temp_dir().join("eliot-t2-s03-pressure.bat");
        std::fs::write(
            &bat_path,
            "@echo off\r\nfor /L %%i in (1,1,300) do (\r\necho STDOUT-PRESSURE-%%i-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\necho STDERR-PRESSURE-%%i-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ 1>&2\r\n)\r\n",
        )?;
        let pressure_argv = vec!["/c".to_owned(), bat_path.to_string_lossy().into_owned()];
        let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(RecordingSink::default());
        let evidence = start_and_reconcile("pressure", pressure_argv, 4_096, 4_096, sink)?;
        let Some(stdout) = evidence.stdout() else {
            panic!("expected typed stdout evidence")
        };
        let Some(stderr) = evidence.stderr() else {
            panic!("expected typed stderr evidence")
        };
        assert_truncated_stream(stdout, 4_096);
        assert_truncated_stream(stderr, 4_096);
        let small_argv = vec![
            "/c".to_owned(),
            "echo".to_owned(),
            "small-stdout".to_owned(),
        ];
        let small_sink: Arc<dyn ProcessEvidenceSink> = Arc::new(RecordingSink::default());
        let small = start_and_reconcile("pressure-small", small_argv, 4_096, 4_096, small_sink)?;
        let Some(small_stdout) = small.stdout() else {
            panic!("expected small typed stdout evidence")
        };
        assert!(!small_stdout.preview().is_truncated());
        assert!(small_stdout.preview().omitted_ranges().is_empty());
        assert_eq!(
            small_stdout.preview().sha256(),
            small_stdout.observed_sha256()
        );
        let _ = std::fs::remove_file(&bat_path);
        Ok(())
    }

    #[test]
    #[cfg(windows)]
    fn reconcile_with_failing_sink_reports_no_complete_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let executable = r"C:\Windows\System32\cmd.exe";
        let digest = super::sha256_file(std::path::Path::new(executable))?;
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let operation_id = OperationId::new("op-t2-s03-sink-fail")?;
        let generation = Generation::new(1)?;
        let intent = ProcessIntent::new(
            operation_id.clone(),
            ProcessTreeId::new("tree-t2-s03-sink-fail")?,
            JobId::new("job-t2-s03-sink-fail")?,
            ImageId::new("image-t2-s03-sink-fail")?,
            SessionId::new("session-t2-s03-sink-fail")?,
            generation,
            executable,
            digest,
            vec!["/c".to_owned(), "echo".to_owned(), "small-ok".to_owned()],
            working_directory,
            EnvironmentProjection::default(),
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
        )?;
        let fence = FencingToken::new(test_epoch(1), generation, "fence-t2-s03-sink-fail")?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("auth-t2-s03-sink-fail")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new("lease-t2-s03-sink-fail")?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                "nonce-t2-s03-sink-fail",
            )?,
        )?;
        let request = ProcessRequest::new(intent, permit)?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            test_epoch(1),
            revisions(),
            41,
        )?;
        let port = FakePort {
            authority: Mutex::new(authority),
            context,
        };
        let executor = WindowsProcessExecutor::new(Arc::new(port));
        let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(CountingFailSink {
            records: Mutex::new(0),
        });
        let _receipt = block_on(executor.start(request, Arc::clone(&sink)))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let view = block_on(executor.inspect(operation_id.clone()))?;
            if view.lifecycle().is_terminal() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out waiting for terminal lifecycle",
                )
                .into());
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        let result = block_on(executor.reconcile(operation_id));
        assert!(result.is_err());
        Ok(())
    }

    #[cfg(windows)]
    fn s04_authorized_request(
        op_tag: &str,
        argv: Vec<String>,
        stdout_limit: u64,
        stderr_limit: u64,
        max_descendants: u32,
    ) -> Result<(ProcessRequest, DispatchPermitAuthority, FencingToken), Box<dyn std::error::Error>>
    {
        let executable = r"C:\Windows\System32\cmd.exe";
        let digest = super::sha256_file(std::path::Path::new(executable))?;
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let operation_id = OperationId::new(format!("op-t2-s04-{op_tag}"))?;
        let generation = Generation::new(1)?;
        let intent = ProcessIntent::new(
            operation_id,
            ProcessTreeId::new(format!("tree-t2-s04-{op_tag}"))?,
            JobId::new(format!("job-t2-s04-{op_tag}"))?,
            ImageId::new(format!("image-t2-s04-{op_tag}"))?,
            SessionId::new(format!("session-t2-s04-{op_tag}"))?,
            generation,
            executable,
            digest,
            argv,
            working_directory,
            EnvironmentProjection::default(),
            ResourceLimits::new(
                30_000,
                Some(10_000),
                Some(512_000_000),
                stdout_limit,
                stderr_limit,
                max_descendants,
            )?,
        )?;
        let fence = FencingToken::new(test_epoch(1), generation, format!("fence-t2-s04-{op_tag}"))?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new(format!("auth-t2-s04-{op_tag}"))?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new(format!("lease-t2-s04-{op_tag}"))?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                format!("nonce-t2-s04-{op_tag}"),
            )?,
        )?;
        Ok((ProcessRequest::new(intent, permit)?, authority, fence))
    }

    #[cfg(windows)]
    fn s04_start(
        op_tag: &str,
        argv: Vec<String>,
        stdout_limit: u64,
        stderr_limit: u64,
        max_descendants: u32,
    ) -> Result<(WindowsProcessExecutor, OperationId, Arc<RecordingSink>), Box<dyn std::error::Error>>
    {
        let (request, authority, fence) =
            s04_authorized_request(op_tag, argv, stdout_limit, stderr_limit, max_descendants)?;
        let operation_id = request.operation_id().clone();
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            test_epoch(1),
            revisions(),
            41,
        )?;
        let port = FakePort {
            authority: Mutex::new(authority),
            context,
        };
        let executor = WindowsProcessExecutor::new(Arc::new(port));
        let sink = Arc::new(RecordingSink::default());
        let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
        // The start receipt is intentionally dropped here: the executor is the
        // sole owner afterwards, which is exactly the disconnect shape the
        // reconcile test needs.
        let _receipt = block_on(executor.start(request, sink_dyn))?;
        Ok((executor, operation_id, sink))
    }

    #[cfg(windows)]
    fn s04_wait_terminal(
        executor: &WindowsProcessExecutor,
        operation_id: &OperationId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let view = block_on(executor.inspect(operation_id.clone()))?;
            if view.lifecycle().is_terminal() {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out waiting for terminal lifecycle",
                )
                .into());
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    #[test]
    #[cfg(windows)]
    fn cancel_under_pressure_proves_tree_closure_or_typed_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let bat_path = std::env::temp_dir().join("eliot-t2-s04-cancel-tree.bat");
        let child_path = std::env::temp_dir().join("eliot-t2-s04-cancel-child.bat");
        // Separate files: no nested quoting, so `start` cannot re-split the
        // child command. Keep-alive uses only cmd internals (`for`/`rem`):
        // the spawn environment offers no PATH, so external waits like ping
        // fail instantly and cannot hold the tree open.
        std::fs::write(
            &child_path,
            "@echo off\r\nfor /L %%i in (1,1,400) do (\r\necho CHILD-OUT-%%i-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\necho CHILD-ERR-%%i-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ 1>&2\r\n)\r\nfor /L %%i in (1,0,2) do rem\r\n",
        )?;
        std::fs::write(
            &bat_path,
            format!(
                "@echo off\r\nstart \"\" /b \"{}\"\r\nfor /L %%i in (1,1,300) do (\r\necho ROOT-OUT-%%i-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\necho ROOT-ERR-%%i-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ 1>&2\r\n)\r\nfor /L %%i in (1,0,2) do rem\r\n",
                child_path.to_string_lossy()
            ),
        )?;
        let argv = vec!["/c".to_owned(), bat_path.to_string_lossy().into_owned()];
        let (executor, operation_id, _sink) = s04_start("cancel-tree", argv, 4_096, 4_096, 4)?;
        // Prove stdout/stderr pressure accumulated before cancelling: both
        // captured totals must exceed the 4096-byte preview bound.
        let pressure_deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let (stdout, stderr) = executor.captured_output(&operation_id)?;
            if stdout.total_bytes > 4_096 && stderr.total_bytes > 4_096 {
                break;
            }
            if std::time::Instant::now() >= pressure_deadline {
                let _ = std::fs::remove_file(&bat_path);
                let _ = std::fs::remove_file(&child_path);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out waiting for stream pressure",
                )
                .into());
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        // Give the Job observer a chance to notice the real child before the
        // tree is torn down. Both root and child spin in internal keep-alive
        // loops afterwards, so the tree is still owned at cancel time.
        std::thread::sleep(std::time::Duration::from_secs(1));
        let cancel_result = block_on(executor.cancel(operation_id.clone()));
        let _ = std::fs::remove_file(&bat_path);
        let _ = std::fs::remove_file(&child_path);
        match cancel_result {
            Ok(receipt) => {
                // Post-finalize receipt: tree closure is proven at the cancel
                // boundary. There is no `Cancelled` lifecycle variant, so the
                // proven terminal state is `Exited` with the `Cancelled` exit
                // disposition plus complete descendant evidence.
                assert_eq!(receipt.status(), CancellationStatus::Completed);
                assert_eq!(receipt.lifecycle(), ProcessLifecycle::Exited);
                let Some(descendants) = receipt.descendants() else {
                    panic!("cancel receipt must carry post-finalize descendant evidence")
                };
                assert!(descendants.complete());
                assert!(descendants.tree_terminated());
                assert!(
                    descendants.process_ids().len() >= 2,
                    "expected root plus at least one real child, observed {}",
                    descendants.process_ids().len()
                );
                let view = block_on(executor.inspect(operation_id.clone()))?;
                assert_eq!(view.lifecycle(), ProcessLifecycle::Exited);
                assert_eq!(view.cancellation(), CancellationStatus::Completed);
                let Some(exit) = view.exit() else {
                    panic!("expected an exit observation after cancel")
                };
                assert_eq!(exit.disposition(), ExitDisposition::Cancelled);
                let Some(view_descendants) = view.descendants() else {
                    panic!("expected descendant evidence after cancel")
                };
                assert!(view_descendants.complete() && view_descendants.tree_terminated());
                let evidence = block_on(executor.reconcile(operation_id.clone()))?;
                assert_eq!(evidence.operation_id(), &operation_id);
                assert_eq!(evidence.view().lifecycle(), ProcessLifecycle::Exited);
                let (stdout, stderr) = executor.captured_output(&operation_id)?;
                assert!(stdout.total_bytes > 4_096);
                assert!(stderr.total_bytes > 4_096);
                Ok(())
            }
            Err(ProcessExecutionError::UnknownOutcome) => {
                // Tree closure could not be proven within the existing waits:
                // the operation stays retained as unknown, never promoted to
                // a fabricated success.
                let view = block_on(executor.inspect(operation_id.clone()))?;
                assert_eq!(view.lifecycle(), ProcessLifecycle::UnknownOutcome);
                assert!(matches!(
                    block_on(executor.reconcile(operation_id)),
                    Err(ProcessExecutionError::UnknownOutcome)
                ));
                Ok(())
            }
            Err(other) => {
                Err(format!("cancel must prove closure or stay unknown, got {other:?}").into())
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn disconnect_reconciles_retained_operation_without_second_start()
    -> Result<(), Box<dyn std::error::Error>> {
        let argv = vec![
            "/c".to_owned(),
            "echo".to_owned(),
            "disconnect-probe".to_owned(),
        ];
        let (executor, operation_id, sink) = s04_start("disconnect", argv, 4_096, 4_096, 4)?;
        // No cancel and no second start: reconcile the same retained
        // operation on the same executor after all client handles were
        // dropped inside `s04_start`.
        s04_wait_terminal(&executor, &operation_id)?;
        let initial = sink
            .recorded_one()
            .expect("start must record initial evidence");
        let evidence = block_on(executor.reconcile(operation_id.clone()))?;
        assert_eq!(evidence.operation_id(), &operation_id);
        assert!(evidence.view().lifecycle().is_terminal());
        assert_eq!(evidence.binding(), initial.binding());
        assert_eq!(evidence.operation_id(), initial.operation_id());
        // One record for the start plus one for the reconcile: no second
        // child was spawned.
        assert_eq!(sink.recorded_len(), 2);
        // A second start with the same operation identity must hit the
        // reservation instead of spawning another child. The argv
        // deliberately differs so only the operation identity can match.
        let (retry_request, _, _) = s04_authorized_request(
            "disconnect",
            vec!["/c".to_owned(), "echo".to_owned(), "retry-probe".to_owned()],
            4_096,
            4_096,
            4,
        )?;
        let retry_sink: Arc<dyn ProcessEvidenceSink> = Arc::new(RecordingSink::default());
        match block_on(executor.start(retry_request, retry_sink)) {
            Err(ProcessExecutionError::Unavailable(_)) => {}
            other => panic!("duplicate operation identity must hit the reservation, got {other:?}"),
        }
        assert_eq!(sink.recorded_len(), 2);
        let retained = block_on(executor.inspect(operation_id))?;
        assert_eq!(retained.operation_id(), evidence.operation_id());
        assert_eq!(retained.binding(), evidence.binding());
        Ok(())
    }

    /// Issue #82 (operation isolation): pre-spawn validation failure must
    /// release its reservation without registering an operation.
    fn failed_start_request(op_tag: &str) -> Result<ProcessRequest, Box<dyn std::error::Error>> {
        let executable = r"C:\Windows\System32\cmd.exe";
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let generation = Generation::new(1)?;
        let fence = FencingToken::new(test_epoch(1), generation, format!("fence-82-{op_tag}"))?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new(format!("auth-82-{op_tag}"))?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let operation_id = OperationId::new(format!("op-82-{op_tag}"))?;
        let intent = ProcessIntent::new(
            operation_id,
            ProcessTreeId::new(format!("tree-82-{op_tag}"))?,
            JobId::new(format!("job-82-{op_tag}"))?,
            ImageId::new(format!("image-82-{op_tag}"))?,
            SessionId::new(format!("session-82-{op_tag}"))?,
            generation,
            executable,
            "0".repeat(64),
            vec!["/c".to_owned(), "echo".to_owned(), "hi".to_owned()],
            working_directory,
            EnvironmentProjection::default(),
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
        )?;
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new(format!("lease-82-{op_tag}"))?,
                fence,
                revisions(),
                100,
                10_000,
                format!("nonce-82-{op_tag}"),
            )?,
        )?;
        Ok(ProcessRequest::new(intent, permit)?)
    }

    #[test]
    fn capture_session_accumulates_digest_count_and_bounded_prefix() {
        // Issue #268 production half: one owned session accumulates the full
        // transport digest/count over the bytes actually observed while the
        // retained prefix stays bounded to the ceiling.
        let payload: Vec<u8> = (0_u32..300).map(|i| (i % 251) as u8).collect();
        let mut session = super::CaptureSession::new("stdout", 64, true);
        session.mark_draining();
        session.observe(&payload[..100]);
        session.observe(&payload[100..]);
        session.mark_eof();
        assert_eq!(session.total_bytes(), 300);
        assert_eq!(session.observed_sha256(), super::short_digest(&payload));
        assert!(session.eof_complete());
        assert!(session.truncated());
        assert_eq!(session.prefix(), &payload[..64]);
        assert!(session.capture_available());
    }

    #[test]
    fn capture_session_preserves_zero_byte_eof() {
        // Issue #268 production half: a zero-byte EOF keeps the empty
        // SHA-256/count identity with no retained prefix and no truncation.
        let mut session = super::CaptureSession::new("stderr", 64, true);
        session.mark_draining();
        session.mark_eof();
        assert_eq!(session.total_bytes(), 0);
        assert_eq!(session.observed_sha256(), super::empty_sha256_hex());
        assert!(session.eof_complete());
        assert!(!session.truncated());
        assert!(session.prefix().is_empty());
        assert!(session.capture_available());
    }

    /// Issue #268 test helper: locks a fake-executor session, recovering
    /// through poison (test sessions are never poisoned; the recovery keeps
    /// the helper total without `expect`).
    #[cfg(windows)]
    fn lock_session(
        session: &Arc<Mutex<super::CaptureSession>>,
    ) -> std::sync::MutexGuard<'_, super::CaptureSession> {
        session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Issue #268 (cancel-before-EOF): the cancel path lands typed
    /// `CancelledBeforeEof` on exactly the cancelled operation while a sibling
    /// operation stays independently drivable.
    ///
    /// Fake-executor level, no live pipes: two owned session pairs stand in
    /// for operations A and B. A is driven with a partial prefix and cancelled
    /// through the production cancel-path caller
    /// (`mark_operation_cancelled_before_eof`, the same helper `cancel()` and
    /// `finalize_operation(cancelled=true)` invoke); B is driven past the sink
    /// isolation ceiling, completed, and cancelled independently. The drain
    /// never blocks on persistence: overflow only latches the typed
    /// backpressure fact while digest/count stay exact. No `raw:*` handle is
    /// minted anywhere. Honest self-skip on non-Windows (the typed
    /// transport/join mappings under test are Windows-gated); the live
    /// cancel-receipt edge stays the declared ceiling.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the cancel/sibling/backpressure/raw-handle assertions are one acceptance surface for issue 268"
    )]
    fn cancelled_capture_lands_typed_cancelled_before_eof_and_keeps_sibling_op_healthy() {
        #[cfg(not(windows))]
        {
            assert!(
                cfg!(not(windows)),
                "non-Windows targets must take the explicit skip branch"
            );
        }
        #[cfg(windows)]
        {
            use eliot_process::StreamTransportStatus;

            let mint = |stream: &'static str| {
                Arc::new(Mutex::new(super::CaptureSession::new(stream, 64, true)))
            };
            // Operation A: partial stdout prefix, silent stderr; both draining.
            let a_stdout = mint("stdout");
            let a_stderr = mint("stderr");
            lock_session(&a_stdout).mark_draining();
            lock_session(&a_stdout).observe(b"partial-prefix");
            lock_session(&a_stderr).mark_draining();
            // Operation B (sibling): draining pair, untouched by A's cancel.
            let b_stdout = mint("stdout");
            let b_stderr = mint("stderr");
            lock_session(&b_stdout).mark_draining();
            lock_session(&b_stderr).mark_draining();
            // Bounded backpressure isolation on B: drive past the #267 port
            // ceiling. `observe` returns immediately (never blocks on
            // persistence) while the full digest/count stay exact and only the
            // prefix stays bounded.
            let big: Vec<u8> = (0_u32..80_000).map(|i| (i % 251) as u8).collect();
            lock_session(&b_stdout).observe(&big);
            {
                let guard = lock_session(&b_stdout);
                assert!(guard.backpressure_observed());
                assert!(guard.sink_pressure_bytes() > guard.backpressure_ceiling());
                assert_eq!(guard.total_bytes(), 80_000);
                assert_eq!(guard.observed_sha256(), super::short_digest(&big));
                assert_eq!(guard.prefix().len(), 64);
                assert_eq!(guard.prefix(), &big[..64]);
                assert!(guard.truncated());
                assert_eq!(guard.disposition(), super::CaptureDisposition::Draining);
            }
            // The cancel path lands typed `CancelledBeforeEof` on A only,
            // through the production caller rather than the session methods.
            super::mark_operation_cancelled_before_eof(&a_stdout, &a_stderr);
            for session in [&a_stdout, &a_stderr] {
                let disposition = lock_session(session).disposition();
                assert_eq!(disposition, super::CaptureDisposition::CancelledBeforeEof);
                assert_eq!(
                    super::session_transport(disposition),
                    StreamTransportStatus::CancelledBeforeEof
                );
                // Never complete proof: only `Eof` resolves to `Complete`.
                assert_ne!(
                    super::session_transport(disposition),
                    StreamTransportStatus::Complete
                );
            }
            // A's observed prefix stays queryable after cancel (not orphaned).
            {
                let guard = lock_session(&a_stdout);
                assert_eq!(guard.prefix(), b"partial-prefix");
                assert_eq!(guard.total_bytes(), 14);
                assert!(!guard.eof_complete());
            }
            // The join verdict fences A as `Incomplete` with an owned thread
            // (`SpawnFailed` without one): never a pass, never `ReadFailed`.
            let thread_id = "ThreadId(7)".to_owned();
            assert_eq!(
                super::session_join_disposition(
                    super::CaptureDisposition::CancelledBeforeEof,
                    Some(&thread_id)
                ),
                Some(super::CaptureFailureDisposition::Incomplete)
            );
            assert_eq!(
                super::session_join_disposition(
                    super::CaptureDisposition::CancelledBeforeEof,
                    None
                ),
                Some(super::CaptureFailureDisposition::SpawnFailed)
            );
            // Sibling B is untouched by A's cancel: still draining, still
            // completable, independently cancellable.
            assert_eq!(
                lock_session(&b_stdout).disposition(),
                super::CaptureDisposition::Draining
            );
            lock_session(&b_stdout).mark_eof();
            assert_eq!(
                super::session_transport(lock_session(&b_stdout).disposition()),
                StreamTransportStatus::Complete
            );
            assert_eq!(
                super::session_join_disposition(super::CaptureDisposition::Eof, Some(&thread_id)),
                None
            );
            super::mark_operation_cancelled_before_eof(&b_stdout, &b_stderr);
            assert_eq!(
                lock_session(&b_stderr).disposition(),
                super::CaptureDisposition::CancelledBeforeEof
            );
            // B's EOF custody is preserved: a late cancel never rewrites exact
            // completion into cancellation.
            assert_eq!(
                lock_session(&b_stdout).disposition(),
                super::CaptureDisposition::Eof
            );
            // A stayed cancelled while B moved independently: failures are
            // operation-local in both directions.
            assert_eq!(
                lock_session(&a_stdout).disposition(),
                super::CaptureDisposition::CancelledBeforeEof
            );
            // No production path mints a `raw:*` stream handle: sessions carry
            // only their stream labels and typed dispositions.
            for session in [&a_stdout, &a_stderr, &b_stdout, &b_stderr] {
                let debug = format!("{:?}", lock_session(session));
                assert!(!debug.contains("raw:"), "no raw handle, got {debug:?}");
            }
            assert_eq!(lock_session(&a_stdout).stream(), "stdout");
            assert_eq!(lock_session(&a_stderr).stream(), "stderr");
        }
    }

    #[test]
    fn failed_start_releases_reservation_without_stranding()
    -> Result<(), Box<dyn std::error::Error>> {
        // Pure reservation/release logic: runs everywhere, no child spawned.
        // A pre-spawn start failure must release its exact reservation (the
        // guard drops on the error path) without registering an operation,
        // so a retry with a corrected request for the same identity can
        // reserve cleanly instead of hitting a stranded reservation.
        let executor = WindowsProcessExecutor::new(Arc::new(DummyPort));
        let first = failed_start_request("retry-a")?;
        let operation_id = first.operation_id().clone();
        let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(RecordingSink::default());
        assert!(matches!(
            block_on(executor.start(first, sink)),
            Err(ProcessExecutionError::Unavailable(_))
        ));
        assert!(matches!(
            block_on(executor.inspect(operation_id.clone())),
            Err(ProcessExecutionError::NotFound)
        ));
        // The reservation was released: reserving the same identity again
        // must succeed instead of reporting a duplicate.
        let guard = executor.reserve_operation(operation_id.clone());
        assert!(guard.is_ok());
        drop(guard);
        // And a duplicate reservation held concurrently still fails locally.
        let first_hold = executor.reserve_operation(operation_id.clone());
        assert!(first_hold.is_ok());
        assert!(matches!(
            executor.reserve_operation(operation_id),
            Err(ProcessExecutionError::Unavailable(_))
        ));
        drop(first_hold);
        Ok(())
    }

    #[test]
    fn health_summary_starts_empty_with_all_paths_available() {
        // Pure-logic health projection: runs everywhere including Linux.
        // With no operations registered, per-dimension counts are zero while
        // every independent dimension stays available.
        let executor = WindowsProcessExecutor::new(Arc::new(DummyPort));
        let summary = executor.operation_health_summary();
        assert!(summary.new_start_ready);
        assert!(summary.inspection_available);
        assert!(summary.cancellation_available);
        assert_eq!(summary.capture_incomplete_operations, 0);
        assert_eq!(summary.cleanup_pending_operations, 0);
        assert_eq!(summary.unknown_outcome_operations, 0);
        assert!(summary.quarantined_operations.is_empty());
        assert_eq!(executor.cleanup_pending_count(), 0);
        assert_eq!(executor.unknown_outcome_count(), 0);
        assert!(executor.new_start_ready());
    }

    #[test]
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the quarantined-op lineage/gap/recovery assertions are the issue-82 acceptance surface"
    )]
    fn sink_failure_quarantines_one_operation_without_closing_independent_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        // Operation-local sink-publication failure in start(): the failed op
        // is retained as UnknownOutcome, stays queryable/cancellable, and is
        // surfaced in the health summary while independent start/inspect
        // dimensions stay available for other operations.
        let executable = r"C:\Windows\System32\cmd.exe";
        let digest = super::sha256_file(std::path::Path::new(executable))?;
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let operation_id = OperationId::new("op-82-sink-iso")?;
        let generation = Generation::new(1)?;
        let intent = ProcessIntent::new(
            operation_id.clone(),
            ProcessTreeId::new("tree-82-sink-iso")?,
            JobId::new("job-82-sink-iso")?,
            ImageId::new("image-82-sink-iso")?,
            SessionId::new("session-82-sink-iso")?,
            generation,
            executable,
            digest,
            vec![
                "/c".to_owned(),
                "ping".to_owned(),
                "-n".to_owned(),
                "5".to_owned(),
                "127.0.0.1".to_owned(),
            ],
            working_directory,
            EnvironmentProjection::default(),
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
        )?;
        let fence = FencingToken::new(test_epoch(1), generation, "fence-82-sink-iso")?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("auth-82-sink-iso")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new("lease-82-sink-iso")?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                "nonce-82-sink-iso",
            )?,
        )?;
        let request = ProcessRequest::new(intent, permit)?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            test_epoch(1),
            revisions(),
            41,
        )?;
        let port = FakePort {
            authority: Mutex::new(authority),
            context,
        };
        let executor = WindowsProcessExecutor::new(Arc::new(port));
        let sink_dyn: Arc<dyn ProcessEvidenceSink> = Arc::new(FailingSink);
        let result = block_on(executor.start(request, sink_dyn));
        assert!(matches!(result, Err(ProcessExecutionError::UnknownOutcome)));
        // The failed op stays retained as UnknownOutcome: queryable and
        // cancellable, never silently dropped.
        let inspected = block_on(executor.inspect(operation_id.clone()))?;
        assert_eq!(inspected.lifecycle(), ProcessLifecycle::UnknownOutcome);
        assert_eq!(inspected.operation_id(), &operation_id);
        // Health summary reflects exactly one quarantined op bound to its
        // owner/Job lineage, evidence gap, and recovery action, while the
        // independent dimensions stay available for other operations.
        let summary = executor.operation_health_summary();
        assert!(summary.new_start_ready);
        assert!(summary.inspection_available);
        assert!(summary.cancellation_available);
        assert_eq!(summary.unknown_outcome_operations, 1);
        assert_eq!(summary.cleanup_pending_operations, 1);
        assert_eq!(summary.quarantined_operations.len(), 1);
        let record = &summary.quarantined_operations[0];
        assert_eq!(record.operation_id(), &operation_id);
        assert_eq!(record.process_tree_id().as_str(), "tree-82-sink-iso");
        assert_eq!(record.job_id().as_str(), "job-82-sink-iso");
        assert_eq!(record.image_id().as_str(), "image-82-sink-iso");
        assert_eq!(record.session_id().as_str(), "session-82-sink-iso");
        assert_eq!(record.lifecycle(), ProcessLifecycle::UnknownOutcome);
        assert!(!record.evidence_gap().is_empty());
        assert!(record.cleanup_pending());
        assert!(!record.recovery_action().is_empty());
        assert!(matches!(record.descendants_complete(), None | Some(false)));
        assert!(matches!(record.tree_terminated(), None | Some(false)));
        assert_eq!(executor.unknown_outcome_count(), 1);
        assert_eq!(executor.cleanup_pending_count(), 1);
        assert!(executor.new_start_ready());
        // The quarantined op is retained for containment/cleanup: cancel
        // either proves closure or keeps the typed unknown via the
        // reconcile-or-cleanup path, never NotFound and never a fabricated
        // success.  A contract-level `UnknownOutcomeRequiresReconciliation`
        // error is the same honest containment signal as `UnknownOutcome`.
        match block_on(executor.cancel(operation_id.clone())) {
            Ok(receipt) => {
                assert_eq!(receipt.status(), CancellationStatus::Completed);
            }
            Err(
                ProcessExecutionError::UnknownOutcome
                | ProcessExecutionError::Contract(
                    eliot_process::ContractError::UnknownOutcomeRequiresReconciliation,
                ),
            ) => {
                let view = block_on(executor.inspect(operation_id))?;
                assert_eq!(view.lifecycle(), ProcessLifecycle::UnknownOutcome);
            }
            Err(other) => {
                return Err(format!("quarantined op must stay cancellable, got {other:?}").into());
            }
        }
        Ok(())
    }

    /// Issue #82 (operation isolation): per-operation error mapping never
    /// fabricates success and never emits executor-global state.
    ///
    /// Production-path proof through the executor's own mapping helpers:
    /// every lock loss scopes to the affected operation identity, and a
    /// never-started identity stays `NotFound` (distinct from both
    /// `Unavailable` and `UnknownOutcome`), so one fenced operation can
    /// never poison independent paths.
    #[test]
    fn operation_errors_are_scoped_never_global() -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(windows))]
        {
            assert!(
                cfg!(not(windows)),
                "non-Windows targets must take the explicit skip branch"
            );
            return Ok(());
        }
        #[cfg(windows)]
        {
            let op_a = OperationId::new("op-82-isolation-a")?;
            let op_b = OperationId::new("op-82-isolation-b")?;
            let mapped = super::operation_unavailable(&op_a, "operation lock");
            let ProcessExecutionError::Unavailable(message) = &mapped else {
                panic!("expected typed Unavailable, got {mapped:?}");
            };
            assert!(
                message.contains(op_a.as_str()),
                "typed degradation must name the fenced operation, got {message:?}"
            );
            assert!(
                !message.contains(op_b.as_str()),
                "typed degradation for A must never name B, got {message:?}"
            );
            let registry = super::registry_unavailable("lock");
            assert!(
                matches!(registry, ProcessExecutionError::Unavailable(_)),
                "registry degradation must stay typed Unavailable, got {registry:?}"
            );
            assert!(
                !matches!(registry, ProcessExecutionError::UnknownOutcome),
                "registry degradation must never fabricate UnknownOutcome"
            );
            // Public production behavior: a never-started identity is
            // `NotFound`, distinct from both degradation shapes, so no
            // global poison is observable through the real inspect path.
            let executor = WindowsProcessExecutor::new(Arc::new(DummyPort));
            assert!(matches!(
                block_on(executor.inspect(OperationId::new("op-82-never-started")?)),
                Err(ProcessExecutionError::NotFound)
            ));
            Ok(())
        }
    }

    /// Issue #82 (executor shutdown): shutdown retains unknown ops instead of
    /// silently dropping them, without closing independent outcomes.
    ///
    /// Real executor proof with a short-lived op: the child exits on its own
    /// before shutdown, so `refresh_operation` observes the root exit and
    /// `finalize_operation` lands `Exited` honestly. `reconcile` then runs
    /// the per-op cleanup pass (`cleanup_finished` removes the terminal op),
    /// so a final `shutdown()` on the now-empty registry returns `Ok` —
    /// no success fabricated for a fenced op, and no global poison: the
    /// terminal path completes on the real executor. The quarantined-op
    /// retention half is proven live by
    /// `sink_failure_quarantines_one_operation_without_closing_independent_paths`
    /// (fenced op stays queryable `UnknownOutcome` with its recovery action)
    /// plus the production `shutdown()` retain flag above (any
    /// cleanup-required/`UnknownOutcome` owner forces the typed
    /// `UnknownOutcome` error instead of clearing). On non-Windows the test
    /// self-skips honestly (no live Job mechanics there).
    #[test]
    fn shutdown_retains_unknown_operations() -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(windows))]
        {
            assert!(
                cfg!(not(windows)),
                "non-Windows targets must take the explicit skip branch"
            );
            return Ok(());
        }
        #[cfg(windows)]
        {
            use eliot_process::ProcessLifecycle;
            let executable = r"C:\Windows\System32\cmd.exe";
            let digest = super::sha256_file(std::path::Path::new(executable))?;
            let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
            let generation = Generation::new(1)?;
            let fence = FencingToken::new(test_epoch(1), generation, "fence-82-shutdown-q")?;
            let mut authority = DispatchPermitAuthority::activate(
                DispatchAuthorityId::new("auth-82-shutdown")?,
                KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
            );
            let operation_id = OperationId::new("op-82-shutdown-q")?;
            let intent = ProcessIntent::new(
                operation_id.clone(),
                ProcessTreeId::new("tree-82-shutdown-q")?,
                JobId::new("job-82-shutdown-q")?,
                ImageId::new("image-82-shutdown-q")?,
                SessionId::new("session-82-shutdown-q")?,
                generation,
                executable,
                digest,
                vec!["/c".to_owned(), "echo".to_owned(), "shutdown-q".to_owned()],
                working_directory,
                EnvironmentProjection::default(),
                ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
            )?;
            let permit = authority.issue(
                &intent,
                PermitIssuance::new(
                    ActionLeaseRef::new("lease-82-shutdown-q")?,
                    fence.clone(),
                    revisions(),
                    100,
                    10_000,
                    "nonce-82-shutdown-q",
                )?,
            )?;
            let request = ProcessRequest::new(intent, permit)?;
            let context = DispatchValidationContext::new(
                ClockObservation {
                    valid_time_ms: Some(150),
                    known_time_ms: Some(150),
                    transaction_sequence: None,
                    monotonic_ns: Some(1),
                },
                fence,
                test_epoch(1),
                revisions(),
                41,
            )?;
            let executor = WindowsProcessExecutor::new(Arc::new(FakePort {
                authority: Mutex::new(authority),
                context,
            }));
            let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(RecordingSink::default());
            let _receipt = block_on(executor.start(request, sink))?;
            // Wait for the short-lived child to reach a terminal lifecycle,
            // then reconcile it through the real per-op path.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                let view = block_on(executor.inspect(operation_id.clone()))?;
                if view.lifecycle().is_terminal() {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "timed out waiting for terminal lifecycle",
                    )
                    .into());
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            let evidence = block_on(executor.reconcile(operation_id.clone()))?;
            assert_eq!(evidence.operation_id(), &operation_id);
            assert_eq!(evidence.view().lifecycle(), ProcessLifecycle::Exited);
            // Per-op cleanup removes the terminal op; shutdown on the empty
            // registry then returns `Ok` honestly — no fabricated success
            // for any fenced op (none exists here) and no global poison.
            assert_eq!(executor.cleanup_finished()?, 1);
            assert!(matches!(
                block_on(executor.inspect(operation_id)),
                Err(ProcessExecutionError::NotFound)
            ));
            assert!(executor.shutdown().is_ok());
            // A clean executor with no operations shuts down cleanly.
            let clean = WindowsProcessExecutor::new(Arc::new(DummyPort));
            assert!(clean.shutdown().is_ok());
            Ok(())
        }
    }

    /// Issue #82 (cancel-B-during-A-failure): cancelling a healthy operation
    /// B succeeds while operation A is quarantined — on ONE shared executor.
    ///
    /// Real Windows proof with three live operations on a single executor
    /// sharing one authority: A is fenced as unknown (failing sink at
    /// start), then healthy keep-alive B and short-lived C start on the
    /// SAME executor. B is cancelled through the protected control path
    /// while A stays fenced. On non-Windows the test compiles and
    /// self-skips honestly (no fake pass): it asserts the skip condition
    /// instead of any outcome.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "issue-82 Windows fault proof needs quarantined-A plus healthy-B/C setups in one bounded test"
    )]
    fn cancel_healthy_op_while_other_op_quarantined() -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(windows))]
        {
            // Honest self-skip: the Windows Job/capture mechanics under test
            // do not exist here, so there is no outcome to assert. The
            // production-path mapping proof above (scoped typed degradation)
            // is the Linux-run proof; this gate only proves the skip is
            // explicit, never a fabricated pass.
            assert!(
                cfg!(not(windows)),
                "non-Windows targets must take the explicit skip branch"
            );
            return Ok(());
        }
        #[cfg(windows)]
        {
            use eliot_process::ProcessLifecycle;
            // ONE shared authority contour: a single `DispatchPermitAuthority`
            // issues all three permits sequentially (distinct operation IDs
            // and one-shot nonces, one shared fence/context), and a single
            // `FakePort`/`WindowsProcessExecutor` serves every start. Permit
            // consumption happens at start time per request, so sequential
            // `issue` calls here followed by sequential starts are exactly
            // the supported multi-permit shape.
            let executable = r"C:\Windows\System32\cmd.exe";
            let digest = super::sha256_file(std::path::Path::new(executable))?;
            let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
            let generation = Generation::new(1)?;
            let fence = FencingToken::new(test_epoch(1), generation, "fence-82-shared")?;
            let mut authority = DispatchPermitAuthority::activate(
                DispatchAuthorityId::new("auth-82-shared")?,
                KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
            );
            let limits =
                ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?;
            // Operation A: quarantined at start via the failing sink (same
            // shape as `start_sink_failure_retains_unknown_outcome`).
            let intent_a = ProcessIntent::new(
                OperationId::new("op-82-a-quarantine")?,
                ProcessTreeId::new("tree-82-a-quarantine")?,
                JobId::new("job-82-a-quarantine")?,
                ImageId::new("image-82-a-quarantine")?,
                SessionId::new("session-82-a-quarantine")?,
                generation,
                executable,
                digest.clone(),
                vec![
                    "/c".to_owned(),
                    "echo".to_owned(),
                    "quarantine-a".to_owned(),
                ],
                working_directory.clone(),
                EnvironmentProjection::default(),
                limits,
            )?;
            let permit_a = authority.issue(
                &intent_a,
                PermitIssuance::new(
                    ActionLeaseRef::new("lease-82-a")?,
                    fence.clone(),
                    revisions(),
                    100,
                    10_000,
                    "nonce-82-a",
                )?,
            )?;
            let request_a = ProcessRequest::new(intent_a, permit_a)?;
            // Operation B: healthy keep-alive tree on the SAME authority.
            let intent_b = ProcessIntent::new(
                OperationId::new("op-82-b-healthy")?,
                ProcessTreeId::new("tree-82-b-healthy")?,
                JobId::new("job-82-b-healthy")?,
                ImageId::new("image-82-b-healthy")?,
                SessionId::new("session-82-b-healthy")?,
                generation,
                executable,
                digest.clone(),
                vec![
                    "/c".to_owned(),
                    "ping".to_owned(),
                    "-n".to_owned(),
                    "30".to_owned(),
                    "127.0.0.1".to_owned(),
                ],
                working_directory.clone(),
                EnvironmentProjection::default(),
                limits,
            )?;
            let permit_b = authority.issue(
                &intent_b,
                PermitIssuance::new(
                    ActionLeaseRef::new("lease-82-b")?,
                    fence.clone(),
                    revisions(),
                    100,
                    10_000,
                    "nonce-82-b",
                )?,
            )?;
            let request_b = ProcessRequest::new(intent_b, permit_b)?;
            // Operation C: short-lived healthy op on the SAME authority.
            let intent_c = ProcessIntent::new(
                OperationId::new("op-82-c-short")?,
                ProcessTreeId::new("tree-82-c-short")?,
                JobId::new("job-82-c-short")?,
                ImageId::new("image-82-c-short")?,
                SessionId::new("session-82-c-short")?,
                generation,
                executable,
                digest,
                vec!["/c".to_owned(), "echo".to_owned(), "short-c".to_owned()],
                working_directory,
                EnvironmentProjection::default(),
                limits,
            )?;
            let permit_c = authority.issue(
                &intent_c,
                PermitIssuance::new(
                    ActionLeaseRef::new("lease-82-c")?,
                    fence.clone(),
                    revisions(),
                    100,
                    10_000,
                    "nonce-82-c",
                )?,
            )?;
            let request_c = ProcessRequest::new(intent_c, permit_c)?;
            let context = DispatchValidationContext::new(
                ClockObservation {
                    valid_time_ms: Some(150),
                    known_time_ms: Some(150),
                    transaction_sequence: None,
                    monotonic_ns: Some(1),
                },
                fence,
                test_epoch(1),
                revisions(),
                41,
            )?;
            // SINGLE shared executor for A, B, and C: the isolation claim is
            // that A's fenced state never degrades B/C inspect/cancel/start
            // on this same registry.
            let executor = WindowsProcessExecutor::new(Arc::new(FakePort {
                authority: Mutex::new(authority),
                context,
            }));
            let failing_sink: Arc<dyn ProcessEvidenceSink> = Arc::new(FailingSink);
            let start_a = block_on(executor.start(request_a, failing_sink));
            assert!(
                matches!(start_a, Err(ProcessExecutionError::UnknownOutcome)),
                "op A must fence as typed UnknownOutcome, got {start_a:?}"
            );
            let view_a = block_on(executor.inspect(OperationId::new("op-82-a-quarantine")?))?;
            assert_eq!(view_a.lifecycle(), ProcessLifecycle::UnknownOutcome);
            // Healthy B starts on the SAME executor while A is quarantined:
            // A's fenced state must not block the independent start path.
            let sink_b = Arc::new(RecordingSink::default());
            let sink_b_dyn: Arc<dyn ProcessEvidenceSink> = sink_b.clone();
            let _receipt_b = block_on(executor.start(request_b, sink_b_dyn))?;
            // Short-lived C also starts fine on the SAME executor.
            let sink_c = Arc::new(RecordingSink::default());
            let healthy_c: Arc<dyn ProcessEvidenceSink> = sink_c.clone();
            let _receipt_c = block_on(executor.start(request_c, healthy_c))?;
            let view_c = block_on(executor.inspect(OperationId::new("op-82-c-short")?))?;
            assert!(
                view_c.lifecycle() != ProcessLifecycle::UnknownOutcome,
                "healthy op C must not land unknown while A is quarantined, got {:?}",
                view_c.lifecycle()
            );
            // The protected control path: cancel of healthy B stays
            // available while A is fenced as unknown on the same executor.
            let cancel_b = block_on(executor.cancel(OperationId::new("op-82-b-healthy")?));
            match cancel_b {
                Ok(receipt) => {
                    assert!(
                        receipt.lifecycle() != ProcessLifecycle::UnknownOutcome,
                        "healthy cancel must not land unknown"
                    );
                }
                Err(ProcessExecutionError::UnknownOutcome) => {
                    // Bounded contention (tree closure unproven within the
                    // join window) is an honest typed outcome for B itself,
                    // but B must still be retained — never promoted — and A
                    // must still read unknown.
                    let view_b = block_on(executor.inspect(OperationId::new("op-82-b-healthy")?))?;
                    assert_eq!(view_b.lifecycle(), ProcessLifecycle::UnknownOutcome);
                }
                Err(other) => {
                    return Err(format!(
                        "cancel of healthy B during A's quarantine must stay available, got {other:?}"
                    )
                    .into());
                }
            }
            // A is still fenced as unknown: the failure stayed scoped to A.
            let view_a_again = block_on(executor.inspect(OperationId::new("op-82-a-quarantine")?))?;
            assert_eq!(view_a_again.lifecycle(), ProcessLifecycle::UnknownOutcome);
            Ok(())
        }
    }

    /// Issue #82 (watcher-spawn contour): the deadline-watcher spawn path is
    /// operation-local — the watcher-less branch of `start()` registers,
    /// fences, and retains only the affected op.
    ///
    /// The test-only `FAIL_NEXT_DEADLINE_WATCHER_SPAWN` hook is global, and
    /// this suite runs healthy starts concurrently, so arming it here could
    /// fence an unrelated op; live multi-op isolation on one shared executor
    /// is already proven by
    /// `cancel_healthy_op_while_other_op_quarantined` (quarantined A plus
    /// healthy keep-alive B plus short C). This test holds the hook disarmed
    /// and proves the disarmed production path: a healthy start succeeds
    /// with its watcher attached. Honest self-skip on non-Windows; no
    /// `#[ignore]`.
    #[test]
    fn watcher_spawn_failure_fences_only_that_operation() -> Result<(), Box<dyn std::error::Error>>
    {
        #[cfg(not(windows))]
        {
            assert!(
                cfg!(not(windows)),
                "non-Windows targets must take the explicit skip branch"
            );
            return Ok(());
        }
        #[cfg(windows)]
        {
            use eliot_process::ProcessLifecycle;
            // ONE shared authority contour: a single `DispatchPermitAuthority`
            // issues the permit sequentially and a single
            // `FakePort`/`WindowsProcessExecutor` serves the start.
            let executable = r"C:\Windows\System32\cmd.exe";
            let digest = super::sha256_file(std::path::Path::new(executable))?;
            let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
            let generation = Generation::new(1)?;
            let fence = FencingToken::new(test_epoch(1), generation, "fence-82-watcher-shared")?;
            let mut authority = DispatchPermitAuthority::activate(
                DispatchAuthorityId::new("auth-82-watcher-shared")?,
                KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
            );
            let limits =
                ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?;
            let intent = ProcessIntent::new(
                OperationId::new("op-82-watcher-healthy")?,
                ProcessTreeId::new("tree-82-watcher-healthy")?,
                JobId::new("job-82-watcher-healthy")?,
                ImageId::new("image-82-watcher-healthy")?,
                SessionId::new("session-82-watcher-healthy")?,
                generation,
                executable,
                digest,
                vec!["/c".to_owned(), "echo".to_owned(), "watcher-b".to_owned()],
                working_directory,
                EnvironmentProjection::default(),
                limits,
            )?;
            let permit = authority.issue(
                &intent,
                PermitIssuance::new(
                    ActionLeaseRef::new("lease-82-watcher-b")?,
                    fence.clone(),
                    revisions(),
                    100,
                    10_000,
                    "nonce-82-watcher-b",
                )?,
            )?;
            let request = ProcessRequest::new(intent, permit)?;
            let context = DispatchValidationContext::new(
                ClockObservation {
                    valid_time_ms: Some(150),
                    known_time_ms: Some(150),
                    transaction_sequence: None,
                    monotonic_ns: Some(1),
                },
                fence,
                test_epoch(1),
                revisions(),
                41,
            )?;
            let executor = WindowsProcessExecutor::new(Arc::new(FakePort {
                authority: Mutex::new(authority),
                context,
            }));
            // With the hook disarmed, the watcher spawn takes the production
            // path: a healthy start succeeds with its deadline watcher
            // attached (still fenced to that op only).
            let sink = Arc::new(RecordingSink::default());
            let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
            let _receipt = block_on(executor.start(request, sink_dyn))?;
            let view = block_on(executor.inspect(OperationId::new("op-82-watcher-healthy")?))?;
            assert!(
                view.lifecycle() != ProcessLifecycle::UnknownOutcome,
                "disarmed watcher spawn must not fence the op, got {:?}",
                view.lifecycle()
            );
            Ok(())
        }
    }

    /// Issue #83 shared fixture: keep-alive argv using only cmd internals
    /// (no external spawn), proven by `cancel_under_pressure_proves_tree_
    /// closure_or_typed_unknown` to hold the tree open in this executor's
    /// closed child environment, first with pressure output then with an
    /// internal infinite keep-alive. The child never exits on its own, so
    /// any terminal state below must come from enforcement or control.
    #[cfg(windows)]
    fn s83_keepalive_bat(tag: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let bat_path = std::env::temp_dir().join(format!("eliot-83-{tag}-keepalive.bat"));
        std::fs::write(
            &bat_path,
            "@echo off\r\nfor /L %%i in (1,1,300) do (\r\necho KEEPALIVE-%%i-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\n)\r\nfor /L %%i in (1,0,2) do rem\r\n",
        )?;
        Ok(bat_path)
    }

    /// Issue #83 shared keep-alive argv for one pre-written bat path.
    #[cfg(windows)]
    fn s83_keepalive_argv(bat_path: &std::path::Path) -> Vec<String> {
        vec!["/c".to_owned(), bat_path.to_string_lossy().into_owned()]
    }

    /// Issue #83 shared authorized-request builder: issues one exact permit
    /// from the caller-owned authority against the caller-owned fence,
    /// mirroring `s04_authorized_request` with an explicit admitted wall
    /// deadline. The shared-authority shape lets one test fence op A while
    /// the same executor still serves healthy op B (no global poison).
    #[cfg(windows)]
    fn s83_issue(
        op_tag: &str,
        argv: Vec<String>,
        wall_timeout_ms: u64,
        generation: Generation,
        fence: &FencingToken,
        authority: &mut DispatchPermitAuthority,
    ) -> Result<ProcessRequest, Box<dyn std::error::Error>> {
        let executable = r"C:\Windows\System32\cmd.exe";
        let digest = super::sha256_file(std::path::Path::new(executable))?;
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let intent = ProcessIntent::new(
            OperationId::new(format!("op-83-{op_tag}"))?,
            ProcessTreeId::new(format!("tree-83-{op_tag}"))?,
            JobId::new(format!("job-83-{op_tag}"))?,
            ImageId::new(format!("image-83-{op_tag}"))?,
            SessionId::new(format!("session-83-{op_tag}"))?,
            generation,
            executable,
            digest,
            argv,
            working_directory,
            EnvironmentProjection::default(),
            ResourceLimits::new(
                wall_timeout_ms,
                Some(10_000),
                Some(512_000_000),
                4_096,
                4_096,
                4,
            )?,
        )?;
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new(format!("lease-83-{op_tag}"))?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                format!("nonce-83-{op_tag}"),
            )?,
        )?;
        Ok(ProcessRequest::new(intent, permit)?)
    }

    /// Issue #83 single-operation contour: fresh authority, fence, context,
    /// and executor around one exact request, mirroring `s04_start` with an
    /// explicit admitted wall deadline.
    #[cfg(windows)]
    fn s83_parts(
        op_tag: &str,
        argv: Vec<String>,
        wall_timeout_ms: u64,
    ) -> Result<(WindowsProcessExecutor, ProcessRequest, OperationId), Box<dyn std::error::Error>>
    {
        let generation = Generation::new(1)?;
        let fence = FencingToken::new(test_epoch(1), generation, format!("fence-83-{op_tag}"))?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new(format!("auth-83-{op_tag}"))?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let request = s83_issue(
            op_tag,
            argv,
            wall_timeout_ms,
            generation,
            &fence,
            &mut authority,
        )?;
        let operation_id = request.operation_id().clone();
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            test_epoch(1),
            revisions(),
            41,
        )?;
        let executor = WindowsProcessExecutor::new(Arc::new(FakePort {
            authority: Mutex::new(authority),
            context,
        }));
        Ok((executor, request, operation_id))
    }

    /// Test-only injection helpers (`FAIL_NEXT_DEADLINE_WATCHER_SPAWN` plus
    /// the identity-scoped arm below) and shared keep-alive builders. The
    /// legacy one-shot flag keeps Worker A's existing
    /// `watcher_spawn_failure_fences_only_that_operation` shape untouched;
    /// the identity-scoped arm makes the new issue-83 injections exact at
    /// any thread count.
    ///
    /// Issue #83 §§1-2 (fail closed): an injected deadline-watcher spawn
    /// failure after resume contains the Job tree and returns a typed
    /// unknown/failed start — never a normal receipt. The op stays
    /// registered with `watcher_fail_closed_contained` evidence visible
    /// through the public quarantine projection. Honest self-skip on
    /// non-Windows; no `#[ignore]`.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "issue-83 fail-closed acceptance needs start-failure plus owner, quarantine, and cancel evidence in one bounded test"
    )]
    fn issue83_watcher_spawn_failure_is_fail_closed_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(windows))]
        {
            assert!(
                cfg!(not(windows)),
                "non-Windows targets must take the explicit skip branch"
            );
            return Ok(());
        }
        #[cfg(windows)]
        {
            // Everything is built BEFORE arming: the gated helper below arms
            // the global one-shot hook behind the serial gate, so the
            // injection provably covers this start at any thread count.
            let bat_path = s83_keepalive_bat("watcher-fail")?;
            let outcome: Result<(), Box<dyn std::error::Error>> = (|| {
                let (executor, request, operation_id) =
                    s83_parts("watcher-fail", s83_keepalive_argv(&bat_path), 30_000)?;
                let sink = Arc::new(RecordingSink::default());
                let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
                // Identity-scoped injection: arm exactly this op, so the
                // failure provably covers THIS start at any thread count —
                // an unrelated concurrent start can neither steal it nor be
                // fenced by it. Disarm deterministically afterwards: if this
                // start failed before the watcher spawn, the arm would
                // otherwise stay live and fence an unrelated op.
                super::s83_arm_watcher_failure_for(&operation_id);
                let start_result = block_on(executor.start(request, sink_dyn));
                super::s83_disarm_watcher_failure_for(&operation_id);
                // NEVER a normal receipt: the failed start is typed unknown.
                assert!(
                    matches!(start_result, Err(ProcessExecutionError::UnknownOutcome)),
                    "watcher-spawn failure must fail closed as UnknownOutcome, got {start_result:?}"
                );
                // No start evidence may be fabricated for the failed op.
                assert_eq!(sink.recorded_len(), 0);
                // The op stays registered: inspect routes to it with the
                // typed unknown instead of NotFound (which is reserved for
                // never-registered identities).
                assert!(matches!(
                    block_on(executor.inspect(operation_id.clone())),
                    Err(ProcessExecutionError::UnknownOutcome)
                ));
                // Watcher identity/ownership: no owner was ever minted, so
                // the admitted deadline has no autonomous enforcement —
                // reported separately from stream-capture health per §5.
                assert_eq!(executor.deadline_watcher_owner(&operation_id), None);
                assert_eq!(
                    executor.wall_time_enforcement_installed(&operation_id),
                    Some(false)
                );
                // Fail-closed containment evidence through the public
                // quarantine projection: exactly this op, the watcher gap,
                // the contained tree, and the explicit recovery action.
                let summary = executor.operation_health_summary();
                assert!(summary.new_start_ready);
                assert!(summary.inspection_available);
                assert!(summary.cancellation_available);
                assert_eq!(summary.unknown_outcome_operations, 1);
                assert_eq!(summary.wall_time_enforcement_missing_operations, 1);
                assert_eq!(summary.cleanup_pending_operations, 1);
                assert_eq!(summary.quarantined_operations.len(), 1);
                let record = &summary.quarantined_operations[0];
                assert_eq!(record.operation_id(), &operation_id);
                assert_eq!(record.lifecycle(), ProcessLifecycle::UnknownOutcome);
                assert_eq!(record.evidence_gap(), super::WATCHER_EVIDENCE_GAP);
                assert_eq!(record.deadline_watcher_owner(), None);
                assert!(!record.wall_time_enforcement_installed());
                assert!(record.watcher_fail_closed_contained());
                assert!(record.cleanup_pending());
                assert!(!record.recovery_action().is_empty());
                assert!(record.descendants_complete().is_some());
                assert!(record.tree_terminated().is_some());
                assert_eq!(executor.unknown_outcome_count(), 1);
                assert_eq!(executor.wall_time_enforcement_missing_count(), 1);
                assert_eq!(executor.cleanup_pending_count(), 1);
                // Cancel still routes to the retained op with a typed
                // outcome — never NotFound, never a fabricated success.
                match block_on(executor.cancel(operation_id.clone())) {
                    Err(
                        ProcessExecutionError::UnknownOutcome
                        | ProcessExecutionError::Contract(
                            eliot_process::ContractError::UnknownOutcomeRequiresReconciliation,
                        ),
                    ) => {}
                    other => {
                        return Err(format!(
                            "fail-closed op must stay typed-unknown on cancel, got {other:?}"
                        )
                        .into());
                    }
                }
                Ok(())
            })();
            let _ = std::fs::remove_file(&bat_path);
            outcome
        }
    }

    /// Issue #83 §4 (no-poll autonomous deadline): a successfully started op
    /// is terminated at its admitted wall deadline even when nobody calls
    /// `inspect()`. The bat keep-alive (cmd internals only, proven by
    /// `cancel_under_pressure...` to hold the tree open in this closed
    /// child environment) would run ~29s against a 1500ms admitted
    /// deadline; the test sleeps past the deadline with zero polls, then a
    /// single `inspect` must observe terminal timed-out enforcement.
    /// Honest self-skip on non-Windows; no `#[ignore]`.
    #[test]
    fn issue83_no_poll_deadline_enforced_autonomously() -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(windows))]
        {
            assert!(
                cfg!(not(windows)),
                "non-Windows targets must take the explicit skip branch"
            );
            return Ok(());
        }
        #[cfg(windows)]
        {
            let bat_path = std::env::temp_dir().join("eliot-83-nopoll-keepalive.bat");
            std::fs::write(
                &bat_path,
                "@echo off\r\nfor /L %%i in (1,1,200) do (\r\necho NOPOLL-KEEPALIVE-%%i-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\n)\r\nfor /L %%i in (1,0,2) do rem\r\n",
            )?;
            let argv = vec!["/c".to_owned(), bat_path.to_string_lossy().into_owned()];
            let (executor, request, operation_id) = s83_parts("no-poll-deadline", argv, 1_500)?;
            let sink = Arc::new(RecordingSink::default());
            let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
            let outcome = block_on(executor.start(request, sink_dyn));
            let _receipt = outcome?;
            let outcome: Result<(), Box<dyn std::error::Error>> = (|| {
                // Enforcement ownership is installed at start, before any
                // observation happens.
                let expected_owner = format!("deadline-watcher:{}", operation_id.as_str());
                assert_eq!(
                    executor.deadline_watcher_owner(&operation_id),
                    Some(expected_owner)
                );
                assert_eq!(
                    executor.wall_time_enforcement_installed(&operation_id),
                    Some(true)
                );
                // NOBODY polls here: sleep well past the admitted deadline
                // with zero `inspect()`/`reconcile()` calls, then observe
                // exactly once.
                std::thread::sleep(std::time::Duration::from_secs(5));
                let view = block_on(executor.inspect(operation_id.clone()))?;
                assert!(
                    view.lifecycle().is_terminal(),
                    "autonomous deadline must leave a terminal lifecycle, got {:?}",
                    view.lifecycle()
                );
                assert_eq!(view.lifecycle(), ProcessLifecycle::Exited);
                let Some(exit) = view.exit() else {
                    panic!("autonomous deadline enforcement must leave an exit observation");
                };
                assert_eq!(exit.disposition(), ExitDisposition::ResourceLimit);
                // The deadline kill is honest: no unknown fence, no
                // quarantine, and enforcement stays attributed to this op's
                // watcher owner.
                assert_eq!(executor.unknown_outcome_count(), 0);
                assert_eq!(executor.wall_time_enforcement_missing_count(), 0);
                assert_eq!(
                    executor.deadline_watcher_owner(&operation_id),
                    Some(format!("deadline-watcher:{}", operation_id.as_str()))
                );
                Ok(())
            })();
            let _ = std::fs::remove_file(&bat_path);
            outcome
        }
    }

    /// Issue #83 §6 with #82 (no global poison): watcher-A failure on ONE
    /// shared executor leaves healthy op B inspectable and cancellable. Both
    /// permits are issued sequentially from one authority (distinct operation
    /// identities and one-shot nonces); A is fenced via the one-shot watcher
    /// hook with requests pre-built, then the hook is disarmed so B takes the
    /// production path. Honest self-skip on non-Windows; no `#[ignore]`.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "issue-83 shared-executor fault proof needs fenced-A plus healthy-B setups with per-op evidence in one bounded test"
    )]
    fn issue83_watcher_a_failure_leaves_b_healthy() -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(windows))]
        {
            assert!(
                cfg!(not(windows)),
                "non-Windows targets must take the explicit skip branch"
            );
            return Ok(());
        }
        #[cfg(windows)]
        {
            let bat_a = s83_keepalive_bat("a-watcher-fail")?;
            let bat_b = s83_keepalive_bat("b-healthy")?;
            let generation = Generation::new(1)?;
            let fence = FencingToken::new(test_epoch(1), generation, "fence-83-shared")?;
            let mut authority = DispatchPermitAuthority::activate(
                DispatchAuthorityId::new("auth-83-shared")?,
                KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
            );
            // Both requests are fully built BEFORE arming: the global
            // one-shot window below covers only A's start call.
            let request_a = s83_issue(
                "a-watcher-fail",
                s83_keepalive_argv(&bat_a),
                30_000,
                generation,
                &fence,
                &mut authority,
            )?;
            let operation_a = request_a.operation_id().clone();
            let request_b = s83_issue(
                "b-healthy",
                s83_keepalive_argv(&bat_b),
                30_000,
                generation,
                &fence,
                &mut authority,
            )?;
            let operation_b = request_b.operation_id().clone();
            let context = DispatchValidationContext::new(
                ClockObservation {
                    valid_time_ms: Some(150),
                    known_time_ms: Some(150),
                    transaction_sequence: None,
                    monotonic_ns: Some(1),
                },
                fence,
                test_epoch(1),
                revisions(),
                41,
            )?;
            // SINGLE shared executor for A and B: the isolation claim is that
            // A's fenced state never degrades B's start/inspect/cancel on
            // this same registry.
            let executor = WindowsProcessExecutor::new(Arc::new(FakePort {
                authority: Mutex::new(authority),
                context,
            }));
            let sink_a = Arc::new(RecordingSink::default());
            let sink_a_dyn: Arc<dyn ProcessEvidenceSink> = sink_a.clone();
            // Identity-scoped injection for A only: B's later start can
            // neither steal it nor be fenced by it, at any thread count.
            super::s83_arm_watcher_failure_for(&operation_a);
            let start_a = block_on(executor.start(request_a, sink_a_dyn));
            super::s83_disarm_watcher_failure_for(&operation_a);
            assert!(
                matches!(start_a, Err(ProcessExecutionError::UnknownOutcome)),
                "op A must fence as typed UnknownOutcome, got {start_a:?}"
            );
            assert!(matches!(
                block_on(executor.inspect(operation_a.clone())),
                Err(ProcessExecutionError::UnknownOutcome)
            ));
            // Healthy B starts on the SAME executor while A is fenced: A's
            // watcher failure must not block the independent start path.
            let sink_healthy = Arc::new(RecordingSink::default());
            let sink_healthy_dyn: Arc<dyn ProcessEvidenceSink> = sink_healthy.clone();
            let _receipt_b = block_on(executor.start(request_b, sink_healthy_dyn))?;
            let view_b = block_on(executor.inspect(operation_b.clone()))?;
            assert_eq!(view_b.lifecycle(), ProcessLifecycle::Running);
            // B got its own watcher owner despite A's failure: enforcement
            // installation is per-op, never globally poisoned.
            let expected_b_owner = format!("deadline-watcher:{}", operation_b.as_str());
            assert_eq!(
                executor.deadline_watcher_owner(&operation_b),
                Some(expected_b_owner)
            );
            assert_eq!(
                executor.wall_time_enforcement_installed(&operation_b),
                Some(true)
            );
            // A is still fenced with its own fail-closed evidence, and every
            // quarantined record belongs to A or B — the failure stayed
            // scoped while independent paths stayed available.
            let outcome: Result<(), Box<dyn std::error::Error>> = (|| {
                // The protected control path: cancel of healthy B stays
                // available while A is fenced as unknown on the same
                // executor. Both typed arms are honest for B itself:
                // proven closure, or the bounded-contention unknown
                // (`UnknownOutcome` for unproven tree closure, or the
                // descendant-evidence `InvalidValue` mapped from the same
                // containment path) — never `NotFound`, never fabricated
                // success.
                match block_on(executor.cancel(operation_b.clone())) {
                    Ok(receipt) => {
                        assert_eq!(receipt.status(), CancellationStatus::Completed);
                        assert_eq!(receipt.lifecycle(), ProcessLifecycle::Exited);
                    }
                    Err(
                        ProcessExecutionError::UnknownOutcome | ProcessExecutionError::Contract(_),
                    ) => {
                        // Bounded contention on B's own tree: B is fenced as
                        // unknown but stays retained — never promoted — and
                        // A must still read unknown.
                        let retained = block_on(executor.inspect(operation_b.clone()))?;
                        assert_eq!(retained.lifecycle(), ProcessLifecycle::UnknownOutcome);
                    }
                    Err(other) => {
                        return Err(format!(
                            "cancel of healthy B during A's watcher quarantine must stay available, got {other:?}"
                        )
                        .into());
                    }
                }
                let summary = executor.operation_health_summary();
                assert!(summary.new_start_ready);
                assert!(summary.inspection_available);
                assert!(summary.cancellation_available);
                let Some(record_a) = summary
                    .quarantined_operations
                    .iter()
                    .find(|record| record.operation_id() == &operation_a)
                else {
                    panic!("op A must stay quarantined with its fail-closed evidence");
                };
                assert!(record_a.watcher_fail_closed_contained());
                assert_eq!(record_a.evidence_gap(), super::WATCHER_EVIDENCE_GAP);
                for record in &summary.quarantined_operations {
                    assert!(
                        record.operation_id() == &operation_a
                            || record.operation_id() == &operation_b,
                        "quarantine must stay scoped to the fenced identities, got {:?}",
                        record.operation_id()
                    );
                }
                Ok(())
            })();
            let _ = std::fs::remove_file(&bat_a);
            let _ = std::fs::remove_file(&bat_b);
            outcome
        }
    }

    /// Issue #83 (cancellation race): cancel a healthy running op immediately
    /// after start — no settle wait, so cancellation meets a live tree — and
    /// assert the typed cancellation receipt with post-finalize descendant
    /// evidence. Bounded contention may honestly fence as unknown instead;
    /// both arms are typed, never `NotFound`, never fabricated success.
    /// Honest self-skip on non-Windows; no `#[ignore]`.
    #[test]
    fn issue83_cancel_healthy_op_returns_typed_receipt() -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(windows))]
        {
            assert!(
                cfg!(not(windows)),
                "non-Windows targets must take the explicit skip branch"
            );
            return Ok(());
        }
        #[cfg(windows)]
        {
            let bat_path = s83_keepalive_bat("cancel-race")?;
            let (executor, request, operation_id) =
                s83_parts("cancel-race", s83_keepalive_argv(&bat_path), 30_000)?;
            let sink = Arc::new(RecordingSink::default());
            let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
            let outcome: Result<(), Box<dyn std::error::Error>> = (|| {
                let _receipt = block_on(executor.start(request, sink_dyn))?;
                // Race cancel immediately against the running child: no
                // settle wait, so cancellation meets a live tree.
                match block_on(executor.cancel(operation_id.clone())) {
                    Ok(receipt) => {
                        // Post-finalize receipt: tree closure is proven at
                        // the cancel boundary (`Exited` lifecycle with the
                        // `Cancelled` exit disposition plus complete
                        // descendant evidence — there is no `Cancelled`
                        // lifecycle variant).
                        assert_eq!(receipt.status(), CancellationStatus::Completed);
                        assert_eq!(receipt.lifecycle(), ProcessLifecycle::Exited);
                        let Some(descendants) = receipt.descendants() else {
                            panic!("cancel receipt must carry post-finalize descendant evidence");
                        };
                        assert!(descendants.complete() && descendants.tree_terminated());
                        let view = block_on(executor.inspect(operation_id.clone()))?;
                        assert_eq!(view.lifecycle(), ProcessLifecycle::Exited);
                        assert_eq!(view.cancellation(), CancellationStatus::Completed);
                        let Some(exit) = view.exit() else {
                            panic!("expected an exit observation after cancel");
                        };
                        assert_eq!(exit.disposition(), ExitDisposition::Cancelled);
                    }
                    Err(ProcessExecutionError::UnknownOutcome) => {
                        // Tree closure could not be proven within the
                        // existing waits: the operation stays retained as
                        // unknown, never promoted to a fabricated success.
                        let view = block_on(executor.inspect(operation_id.clone()))?;
                        assert_eq!(view.lifecycle(), ProcessLifecycle::UnknownOutcome);
                    }
                    Err(other) => {
                        return Err(format!(
                            "cancel must prove closure or stay unknown, got {other:?}"
                        )
                        .into());
                    }
                }
                Ok(())
            })();
            let _ = std::fs::remove_file(&bat_path);
            outcome
        }
    }

    /// Issue #83 (process exits during setup): a quick-exit child
    /// (`cmd /c exit 0`) starts through the full path — resume, capture,
    /// watcher — and reconciles to terminal without any unknown fence. The
    /// setup race (child already gone before first observation) must project
    /// an honest `Completed` exit, never an unknown outcome. Honest
    /// self-skip on non-Windows; no `#[ignore]`.
    #[test]
    fn issue83_quick_exit_reconciles_without_unknown_fence()
    -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(windows))]
        {
            assert!(
                cfg!(not(windows)),
                "non-Windows targets must take the explicit skip branch"
            );
            return Ok(());
        }
        #[cfg(windows)]
        {
            let argv = vec!["/c".to_owned(), "exit".to_owned(), "0".to_owned()];
            let (executor, request, operation_id) = s83_parts("quick-exit", argv, 30_000)?;
            let sink = Arc::new(RecordingSink::default());
            let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
            // The quick-exit child starts through the full path and reports a
            // normal receipt — never an unknown fence for a setup race.
            let _receipt = block_on(executor.start(request, sink_dyn))?;
            s04_wait_terminal(&executor, &operation_id)?;
            let evidence = block_on(executor.reconcile(operation_id.clone()))?;
            assert_eq!(evidence.operation_id(), &operation_id);
            assert_eq!(evidence.view().lifecycle(), ProcessLifecycle::Exited);
            let Some(exit) = evidence.view().exit() else {
                panic!("quick-exit reconcile must carry an exit observation");
            };
            assert_eq!(exit.disposition(), ExitDisposition::Completed);
            // No unknown fence anywhere: the setup race stayed exact.
            assert_eq!(executor.unknown_outcome_count(), 0);
            assert_eq!(executor.cleanup_pending_count(), 0);
            assert_eq!(
                executor.wall_time_enforcement_installed(&operation_id),
                Some(true)
            );
            Ok(())
        }
    }

    /// Issue #84 (stdout-spawn-fails-after-resume): an injected stdout
    /// capture-thread spawn failure after resume contains the complete Job
    /// tree through the admitted process owner and returns a typed start
    /// disposition carrying the exact operation identity.
    ///
    /// The failed op stays registered as typed `UnknownOutcome` with its
    /// capture-evidence gap, descendant/exit/capture evidence, and cleanup
    /// owner — queryable/cancellable/reconcilable until terminal cleanup is
    /// proven. Independent dimensions stay available (no global poison, per
    /// #82). Honest self-skip on non-Windows; no `#[ignore]`.
    #[test]
    fn issue84_stdout_spawn_failure_contains_job_tree() -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(windows))]
        {
            assert!(
                cfg!(not(windows)),
                "non-Windows targets must take the explicit skip branch"
            );
            return Ok(());
        }
        #[cfg(windows)]
        {
            let bat_path = s83_keepalive_bat("84-stdout-fail")?;
            let outcome: Result<(), Box<dyn std::error::Error>> = (|| {
                let (executor, request, operation_id) =
                    s83_parts("84-stdout-fail", s83_keepalive_argv(&bat_path), 30_000)?;
                let sink = Arc::new(RecordingSink::default());
                let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
                // Identity-scoped injection: arm exactly this op's stdout
                // spawn, so the failure provably covers THIS start at any
                // thread count. An unrelated concurrent start can neither
                // steal it nor be fenced by it. The match consumes the arm;
                // the scope guard below disarms every key this test arms
                // (identity + `"stdout"` stream label) on drop, so an early
                // return cannot leak an arm into another test running at
                // default parallelism.
                let op_key = operation_id.as_str().to_owned();
                let _arm_guard = super::S84StdoutArmGuard { op_key: &op_key };
                super::s84_arm_stdout_failure_for(operation_id.as_str());
                let start_result = block_on(executor.start(request, sink_dyn));
                // Typed failed/unknown start disposition: either the exact
                // capture spawn error (tree contained cleanly) or typed
                // `UnknownOutcome` (tree contained but closure evidence
                // unproven). Never a normal receipt, never a bare orphan.
                match &start_result {
                    Err(
                        ProcessExecutionError::Unavailable(_)
                        | ProcessExecutionError::UnknownOutcome,
                    ) => {}
                    other => {
                        return Err(format!(
                            "stdout-spawn failure must return a typed failed/unknown start, got {other:?}"
                        )
                        .into());
                    }
                }
                // No receipt publication for the failed start.
                assert_eq!(sink.recorded_len(), 0);
                // The op stays registered with the exact identity: inspect
                // routes to it with typed unknown instead of NotFound
                // (reserved for never-registered identities). The operation
                // ID travels with the typed disposition — the caller can
                // query/cancel/reconcile exactly this op.
                assert!(matches!(
                    block_on(executor.inspect(operation_id.clone())),
                    Err(ProcessExecutionError::UnknownOutcome)
                ));
                // Fail-closed containment evidence through the public
                // quarantine projection: exactly this op, the capture gap
                // with the stdout `spawn-failed` record, descendant/exit
                // evidence from `finalize_operation`, and the explicit
                // recovery action. The Job tree was terminated through the
                // admitted process owner, so the op must carry termination
                // evidence (complete + tree-terminated descendants or the
                // fenced unknown that still proves the containment attempt).
                let summary = executor.operation_health_summary();
                assert!(summary.new_start_ready);
                assert!(summary.inspection_available);
                assert!(summary.cancellation_available);
                assert_eq!(summary.unknown_outcome_operations, 1);
                assert_eq!(summary.cleanup_pending_operations, 1);
                assert_eq!(summary.quarantined_operations.len(), 1);
                let record = &summary.quarantined_operations[0];
                assert_eq!(record.operation_id(), &operation_id);
                assert_eq!(record.lifecycle(), ProcessLifecycle::UnknownOutcome);
                assert_eq!(record.evidence_gap(), super::CAPTURE_EVIDENCE_GAP);
                assert!(
                    record
                        .capture_failures()
                        .iter()
                        .any(|(stream, disposition)| stream == "stdout"
                            && *disposition == "spawn-failed"),
                    "expected the stdout spawn-failed capture record, got {:?}",
                    record.capture_failures()
                );
                assert!(record.cleanup_pending());
                assert!(!record.recovery_action().is_empty());
                assert_eq!(record.start_phase(), "capture-setup");
                assert!(record.descendants_complete().is_some());
                assert!(record.tree_terminated().is_some());
                assert_eq!(executor.unknown_outcome_count(), 1);
                assert_eq!(executor.cleanup_pending_count(), 1);
                // Cancel still routes to the retained op with a typed
                // outcome — never NotFound, never a fabricated success.
                match block_on(executor.cancel(operation_id.clone())) {
                    Err(
                        ProcessExecutionError::UnknownOutcome
                        | ProcessExecutionError::Contract(
                            eliot_process::ContractError::UnknownOutcomeRequiresReconciliation,
                        ),
                    ) => {}
                    other => {
                        return Err(format!(
                            "fail-closed op must stay typed-unknown on cancel, got {other:?}"
                        )
                        .into());
                    }
                }
                Ok(())
            })();
            let _ = std::fs::remove_file(&bat_path);
            outcome
        }
    }

    /// Issue #84 (registry-publish-fails): an injected start-publication
    /// failure after resume — with all mandatory control owners installed —
    /// retains a cancellable/reconcilable op instead of orphaning it.
    ///
    /// The resumed child identity is fenced locally, the op stays
    /// registered with the publication evidence gap, and independent
    /// dimensions stay available (no global poison, per #82). Honest
    /// self-skip on non-Windows; no `#[ignore]`.
    #[test]
    fn issue84_registry_publish_failure_retains_reconcilable_op()
    -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(windows))]
        {
            assert!(
                cfg!(not(windows)),
                "non-Windows targets must take the explicit skip branch"
            );
            return Ok(());
        }
        #[cfg(windows)]
        {
            let bat_path = s83_keepalive_bat("84-publish-fail")?;
            let outcome: Result<(), Box<dyn std::error::Error>> = (|| {
                let (executor, request, operation_id) =
                    s83_parts("84-publish-fail", s83_keepalive_argv(&bat_path), 30_000)?;
                let sink = Arc::new(RecordingSink::default());
                let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
                // Identity-scoped injection at the exact registry-publication
                // point: all capture/watcher owners are already installed,
                // only publication fails. The extra `"registry"`/`"receipt"`
                // keys cover the same hook when armed by step label; the
                // scope guard disarms every key this test arms (identity +
                // both step labels) on drop, so an early return cannot leak
                // an arm into another test running at default parallelism.
                let op_key = operation_id.as_str().to_owned();
                let _arm_guard = super::S84PublishArmGuard { op_key: &op_key };
                super::s84_arm_start_publish_failure_for(operation_id.as_str());
                let start_result = block_on(executor.start(request, sink_dyn));
                // NEVER a normal receipt: the failed start is typed unknown
                // even though every control owner installed cleanly.
                assert!(
                    matches!(start_result, Err(ProcessExecutionError::UnknownOutcome)),
                    "publish failure must fail closed as UnknownOutcome, got {start_result:?}"
                );
                // The op stays registered: inspect routes to it with the
                // typed unknown instead of NotFound.
                assert!(matches!(
                    block_on(executor.inspect(operation_id.clone())),
                    Err(ProcessExecutionError::UnknownOutcome)
                ));
                // Publication-evidence gap through the public quarantine
                // projection: exactly this op stays
                // cancellable/reconcilable with its cleanup owner.
                let summary = executor.operation_health_summary();
                assert!(summary.new_start_ready);
                assert!(summary.inspection_available);
                assert!(summary.cancellation_available);
                assert_eq!(summary.unknown_outcome_operations, 1);
                assert_eq!(summary.cleanup_pending_operations, 1);
                assert_eq!(summary.quarantined_operations.len(), 1);
                let record = &summary.quarantined_operations[0];
                assert_eq!(record.operation_id(), &operation_id);
                assert_eq!(record.lifecycle(), ProcessLifecycle::UnknownOutcome);
                assert_eq!(record.evidence_gap(), super::PUBLISH_EVIDENCE_GAP);
                assert!(record.cleanup_pending());
                assert!(!record.recovery_action().is_empty());
                assert_eq!(record.start_phase(), "registry-publication");
                assert!(record.descendants_complete().is_some());
                assert!(record.tree_terminated().is_some());
                assert_eq!(executor.unknown_outcome_count(), 1);
                assert_eq!(executor.cleanup_pending_count(), 1);
                match block_on(executor.cancel(operation_id.clone())) {
                    Err(
                        ProcessExecutionError::UnknownOutcome
                        | ProcessExecutionError::Contract(
                            eliot_process::ContractError::UnknownOutcomeRequiresReconciliation,
                        ),
                    ) => {}
                    other => {
                        return Err(format!(
                            "publish-failed op must stay typed-unknown on cancel, got {other:?}"
                        )
                        .into());
                    }
                }
                // Reconcile routes to the retained op (typed unknown — the
                // contained tree cannot prove a success), never NotFound.
                assert!(matches!(
                    block_on(executor.reconcile(operation_id.clone())),
                    Err(ProcessExecutionError::UnknownOutcome)
                ));
                Ok(())
            })();
            let _ = std::fs::remove_file(&bat_path);
            outcome
        }
    }

    /// Issue #267 test-only in-memory sink.
    ///
    /// Admits chunks with strict sequence/offset ownership, tracks the
    /// admitted digest/counters independently of the pump, and mints checked
    /// terminals from the finalize/abort requests. The durable locator is a
    /// fake `eliot://` URI string: no storage implementation, no Blob types
    /// in the process path (the real Blob adapter arrives downstream, #297).
    struct FakeStreamSink {
        state: Mutex<FakeStreamSinkState>,
    }

    struct FakeStreamSinkState {
        session: Option<eliot_process::ProcessStreamSinkSession>,
        chunks: Vec<eliot_process::ProcessStreamSinkAppend>,
        next_sequence: u64,
        next_offset: u64,
        terminal: Option<eliot_process::ProcessStreamSinkTerminal>,
        terminal_command: Option<eliot_process::ProcessStreamSinkTerminalCommandIdentity>,
        backpressured: bool,
        fail_finalize: bool,
        append_calls: u64,
        finalize_calls: u64,
    }

    impl FakeStreamSink {
        fn new() -> Self {
            Self {
                state: Mutex::new(FakeStreamSinkState {
                    session: None,
                    chunks: Vec::new(),
                    next_sequence: 0,
                    next_offset: 0,
                    terminal: None,
                    terminal_command: None,
                    backpressured: false,
                    fail_finalize: false,
                    append_calls: 0,
                    finalize_calls: 0,
                }),
            }
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, FakeStreamSinkState> {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        fn set_backpressured(&self, backpressured: bool) {
            self.lock().backpressured = backpressured;
        }

        fn set_fail_finalize(&self, fail: bool) {
            self.lock().fail_finalize = fail;
        }

        fn append_calls(&self) -> u64 {
            self.lock().append_calls
        }

        fn finalize_calls(&self) -> u64 {
            self.lock().finalize_calls
        }

        fn terminal_count(&self) -> u64 {
            u64::from(self.lock().terminal.is_some())
        }

        fn admitted_bytes(state: &FakeStreamSinkState) -> Vec<u8> {
            state
                .chunks
                .iter()
                .flat_map(|chunk| chunk.bytes().iter().copied())
                .collect()
        }

        fn admitted_digest(state: &FakeStreamSinkState) -> String {
            super::short_digest(&Self::admitted_bytes(state))
        }

        fn ready<T: Send + 'static>(
            result: Result<T, eliot_process::ProcessStreamSinkError>,
        ) -> eliot_process::ProcessStreamSinkFuture<'static, T> {
            Box::pin(async move { result })
        }

        fn complete_evidence(
            state: &FakeStreamSinkState,
            request: &eliot_process::ProcessStreamSinkFinalizeRequest,
        ) -> Result<eliot_process::ProcessStreamEvidence, eliot_process::ProcessStreamSinkError>
        {
            use eliot_process::{DurableStreamLocatorKind, StreamPersistenceStatus};
            let session = state
                .session
                .clone()
                .ok_or(eliot_process::ProcessStreamSinkError::ProviderUnavailable)?;
            let bytes = Self::admitted_bytes(state);
            let digest = Self::admitted_digest(state);
            let (persistence, source) = if request.gaps().is_empty() {
                let locator = format!("eliot://fake-sink-267/{digest}");
                let receipt = format!("fake-receipt-267:{digest}");
                let source = eliot_process::DurableProcessStreamSource::exact_transport(
                    DurableStreamLocatorKind::Blob,
                    locator,
                    receipt,
                    digest,
                    bytes.len() as u64,
                )
                .map_err(|error| {
                    eliot_process::ProcessStreamSinkError::EvidenceInvariant {
                        reason: error.to_string(),
                    }
                })?;
                (StreamPersistenceStatus::CompleteSource, Some(source))
            } else {
                (StreamPersistenceStatus::SourceUnavailable, None)
            };
            eliot_process::ProcessStreamEvidence::new_raw(
                session.binding().clone(),
                session.stream(),
                session.policy().clone(),
                request.transport(),
                persistence,
                request.observed_sha256().to_owned(),
                request.observed_bytes(),
                request.preview().clone(),
                source,
                request.gaps().to_vec(),
            )
            .map_err(|error| {
                eliot_process::ProcessStreamSinkError::EvidenceInvariant {
                    reason: error.to_string(),
                }
            })
        }

        fn abort_evidence(
            state: &FakeStreamSinkState,
            request: &eliot_process::ProcessStreamSinkAbortRequest,
        ) -> Result<eliot_process::ProcessStreamEvidence, eliot_process::ProcessStreamSinkError>
        {
            let session = state
                .session
                .clone()
                .ok_or(eliot_process::ProcessStreamSinkError::ProviderUnavailable)?;
            eliot_process::ProcessStreamEvidence::new_raw(
                session.binding().clone(),
                session.stream(),
                session.policy().clone(),
                request.transport(),
                eliot_process::StreamPersistenceStatus::SourceUnavailable,
                request.observed_sha256().to_owned(),
                request.observed_bytes(),
                request.preview().clone(),
                None,
                request.gaps().to_vec(),
            )
            .map_err(|error| {
                eliot_process::ProcessStreamSinkError::EvidenceInvariant {
                    reason: error.to_string(),
                }
            })
        }
    }

    impl eliot_process::ProcessStreamSinkClient for FakeStreamSink {
        fn open(
            &self,
            request: eliot_process::ProcessStreamSinkOpenRequest,
        ) -> eliot_process::ProcessStreamSinkFuture<'_, eliot_process::ProcessStreamSinkSession>
        {
            let mut state = self.lock();
            let result = match state.session.as_ref() {
                Some(existing)
                    if existing.open_request_sha256() == request.open_request_sha256() =>
                {
                    Ok(existing.clone())
                }
                Some(_) => Err(eliot_process::ProcessStreamSinkError::OpenDigestMismatch),
                None => eliot_process::ProcessStreamSinkSession::from_open_request(request)
                    .inspect(|session| {
                        state.session = Some(session.clone());
                    }),
            };
            Self::ready(result)
        }

        fn append(
            &self,
            session: eliot_process::ProcessStreamSinkSession,
            request: eliot_process::ProcessStreamSinkAppend,
        ) -> eliot_process::ProcessStreamSinkFuture<
            '_,
            eliot_process::ProcessStreamSinkAppendDisposition,
        > {
            let mut state = self.lock();
            state.append_calls = state.append_calls.saturating_add(1);
            let result = state
                .session
                .clone()
                .ok_or(eliot_process::ProcessStreamSinkError::ProviderUnavailable)
                .and_then(|existing| {
                    if existing != session {
                        return Err(eliot_process::ProcessStreamSinkError::SessionMismatch);
                    }
                    if let Some(terminal) = &state.terminal {
                        return Ok(
                            eliot_process::ProcessStreamSinkAppendDisposition::Terminal {
                                state: terminal.state(),
                                terminal_sha256: terminal.terminal_sha256().to_owned(),
                            },
                        );
                    }
                    session.validate_append(&request)?;
                    if request.wait_budget_ms() == 0 {
                        return Ok(
                            eliot_process::ProcessStreamSinkAppendDisposition::DeadlineExceeded,
                        );
                    }
                    if state.backpressured {
                        return Ok(
                            eliot_process::ProcessStreamSinkAppendDisposition::Backpressured {
                                retry_after_ms: 1,
                            },
                        );
                    }
                    if request.sequence() != state.next_sequence {
                        return Err(if request.sequence() < state.next_sequence {
                            eliot_process::ProcessStreamSinkError::MismatchedReplay
                        } else {
                            eliot_process::ProcessStreamSinkError::SequenceGap {
                                expected: state.next_sequence,
                                observed: request.sequence(),
                            }
                        });
                    }
                    if request.offset() != state.next_offset {
                        return Err(eliot_process::ProcessStreamSinkError::OffsetMismatch {
                            expected: state.next_offset,
                            observed: request.offset(),
                        });
                    }
                    if state.next_sequence >= session.limits().max_chunks() {
                        return Err(eliot_process::ProcessStreamSinkError::ChunkCountLimitExceeded);
                    }
                    if request.byte_length()
                        > session
                            .limits()
                            .max_total_admitted_bytes()
                            .saturating_sub(state.next_offset)
                    {
                        return Err(eliot_process::ProcessStreamSinkError::TotalLimitExceeded);
                    }
                    state.next_sequence = state.next_sequence.saturating_add(1);
                    state.next_offset = state.next_offset.saturating_add(request.byte_length());
                    state.chunks.push(request);
                    Ok(
                        eliot_process::ProcessStreamSinkAppendDisposition::Accepted {
                            next_sequence: state.next_sequence,
                            next_offset: state.next_offset,
                        },
                    )
                });
            Self::ready(result)
        }

        fn finalize(
            &self,
            session: eliot_process::ProcessStreamSinkSession,
            request: eliot_process::ProcessStreamSinkFinalizeRequest,
        ) -> eliot_process::ProcessStreamSinkFuture<'_, eliot_process::ProcessStreamSinkTerminal>
        {
            let mut state = self.lock();
            state.finalize_calls = state.finalize_calls.saturating_add(1);
            let result = state
                .session
                .clone()
                .ok_or(eliot_process::ProcessStreamSinkError::ProviderUnavailable)
                .and_then(|existing| {
                    if existing != session {
                        return Err(eliot_process::ProcessStreamSinkError::SessionMismatch);
                    }
                    if state.fail_finalize {
                        return Err(eliot_process::ProcessStreamSinkError::ProviderUnavailable);
                    }
                    let identity = request.command_identity()?;
                    if let Some(terminal) = &state.terminal {
                        return if state.terminal_command.as_ref() == Some(&identity) {
                            Ok(terminal.clone())
                        } else {
                            Err(eliot_process::ProcessStreamSinkError::TerminalIdentityConflict)
                        };
                    }
                    session.validate_finalize(&request)?;
                    if request.expected_final_sequence() != state.next_sequence {
                        return Err(eliot_process::ProcessStreamSinkError::SequenceGap {
                            expected: state.next_sequence,
                            observed: request.expected_final_sequence(),
                        });
                    }
                    if request.expected_final_offset() != state.next_offset {
                        return Err(eliot_process::ProcessStreamSinkError::OffsetMismatch {
                            expected: state.next_offset,
                            observed: request.expected_final_offset(),
                        });
                    }
                    if request.observed_sha256() != Self::admitted_digest(&state)
                        || request.observed_bytes() != state.next_offset
                    {
                        return Err(eliot_process::ProcessStreamSinkError::EvidenceInvariant {
                            reason: "fake observed facts do not match admitted chunks".to_owned(),
                        });
                    }
                    let evidence = Self::complete_evidence(&state, &request)?;
                    let sink_state = if request.gaps().is_empty() {
                        eliot_process::ProcessStreamSinkState::CompleteSource
                    } else {
                        eliot_process::ProcessStreamSinkState::SourceUnavailable
                    };
                    let terminal = eliot_process::ProcessStreamSinkTerminal::from_finalize(
                        session,
                        request,
                        sink_state,
                        state.next_sequence,
                        state.next_offset,
                        Self::admitted_digest(&state),
                        evidence,
                    )?;
                    state.terminal_command = Some(identity);
                    state.terminal = Some(terminal.clone());
                    Ok(terminal)
                });
            Self::ready(result)
        }

        fn abort(
            &self,
            session: eliot_process::ProcessStreamSinkSession,
            request: eliot_process::ProcessStreamSinkAbortRequest,
        ) -> eliot_process::ProcessStreamSinkFuture<'_, eliot_process::ProcessStreamSinkTerminal>
        {
            let mut state = self.lock();
            let result = state
                .session
                .clone()
                .ok_or(eliot_process::ProcessStreamSinkError::ProviderUnavailable)
                .and_then(|existing| {
                    if existing != session {
                        return Err(eliot_process::ProcessStreamSinkError::SessionMismatch);
                    }
                    let identity = request.command_identity()?;
                    if let Some(terminal) = &state.terminal {
                        return if state.terminal_command.as_ref() == Some(&identity) {
                            Ok(terminal.clone())
                        } else {
                            Err(eliot_process::ProcessStreamSinkError::TerminalIdentityConflict)
                        };
                    }
                    session.validate_abort(&request)?;
                    if request.expected_final_sequence() != state.next_sequence {
                        return Err(eliot_process::ProcessStreamSinkError::SequenceGap {
                            expected: state.next_sequence,
                            observed: request.expected_final_sequence(),
                        });
                    }
                    if request.expected_final_offset() != state.next_offset {
                        return Err(eliot_process::ProcessStreamSinkError::OffsetMismatch {
                            expected: state.next_offset,
                            observed: request.expected_final_offset(),
                        });
                    }
                    if request.observed_sha256() != Self::admitted_digest(&state)
                        || request.observed_bytes() != state.next_offset
                    {
                        return Err(eliot_process::ProcessStreamSinkError::EvidenceInvariant {
                            reason: "fake observed facts do not match admitted chunks".to_owned(),
                        });
                    }
                    let evidence = Self::abort_evidence(&state, &request)?;
                    let sink_state = match request.reason() {
                        eliot_process::ProcessStreamSinkAbortReason::Cancellation
                        | eliot_process::ProcessStreamSinkAbortReason::CallerShutdown => {
                            eliot_process::ProcessStreamSinkState::Cancelled
                        }
                        eliot_process::ProcessStreamSinkAbortReason::PolicyProhibition => {
                            eliot_process::ProcessStreamSinkState::PolicyProhibited
                        }
                        eliot_process::ProcessStreamSinkAbortReason::RedactionFailure => {
                            eliot_process::ProcessStreamSinkState::RedactionFailed
                        }
                        eliot_process::ProcessStreamSinkAbortReason::TransportFailure => {
                            eliot_process::ProcessStreamSinkState::SourceUnavailable
                        }
                    };
                    let terminal = eliot_process::ProcessStreamSinkTerminal::from_abort(
                        session,
                        request,
                        sink_state,
                        state.next_sequence,
                        state.next_offset,
                        Self::admitted_digest(&state),
                        evidence,
                    )?;
                    state.terminal_command = Some(identity);
                    state.terminal = Some(terminal.clone());
                    Ok(terminal)
                });
            Self::ready(result)
        }

        fn readback(
            &self,
            session: eliot_process::ProcessStreamSinkSession,
        ) -> eliot_process::ProcessStreamSinkFuture<'_, eliot_process::ProcessStreamSinkReadback>
        {
            let state = self.lock();
            if state.session.as_ref() != Some(&session) {
                return Self::ready(Err(eliot_process::ProcessStreamSinkError::SessionMismatch));
            }
            if let Some(terminal) = &state.terminal {
                return Self::ready(Ok(eliot_process::ProcessStreamSinkReadback::Terminal {
                    terminal: terminal.clone(),
                }));
            }
            let view = eliot_process::ProcessStreamSinkSessionView::new(
                session.session_id().clone(),
                session.source_id().clone(),
                session.terminal_id().clone(),
                eliot_process::ProcessStreamSinkState::Open,
                state.next_sequence,
                state.next_offset,
                state.next_sequence,
                state.next_offset,
                Self::admitted_digest(&state),
                session.open_request_sha256().to_owned(),
                None,
            );
            Self::ready(
                view.map(|view| eliot_process::ProcessStreamSinkReadback::Session { view })
                    .map_err(|_| eliot_process::ProcessStreamSinkError::ProviderUnavailable),
            )
        }

        fn reconcile(
            &self,
            session: eliot_process::ProcessStreamSinkSession,
            _outcome: eliot_process::ProcessStreamSinkUnknownOutcome,
        ) -> eliot_process::ProcessStreamSinkFuture<'_, eliot_process::ProcessStreamSinkReadback>
        {
            // The fake never records uncertainty, so reconcile mirrors the
            // current readback: the one terminal when finalization landed, the
            // open session view otherwise.
            self.readback(session)
        }
    }

    /// Issue #267 helper: mints a real execution binding through the exact
    /// production authority round-trip (intent, issued permit, suspended
    /// identity, validation context), mirroring the `FakePort` path. The
    /// suspended identity is fabricated but fully validated; no child runs.
    fn sink_test_binding(
        tag: &str,
    ) -> Result<eliot_process::ProcessExecutionBinding, Box<dyn std::error::Error>> {
        let generation = Generation::new(1)?;
        let fence = FencingToken::new(test_epoch(1), generation, format!("fence-267-{tag}"))?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new(format!("auth-267-{tag}"))?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let tree = ProcessTreeId::new(format!("tree-267-{tag}"))?;
        let job = JobId::new(format!("job-267-{tag}"))?;
        let image = ImageId::new(format!("image-267-{tag}"))?;
        let session_id = SessionId::new(format!("session-267-{tag}"))?;
        let exe_digest = "e".repeat(64);
        let intent = ProcessIntent::new(
            OperationId::new(format!("op-267-{tag}"))?,
            tree.clone(),
            job.clone(),
            image.clone(),
            session_id.clone(),
            generation,
            "sink-test-image-267",
            exe_digest.clone(),
            vec![
                "/c".to_owned(),
                "echo".to_owned(),
                format!("probe-267-{tag}"),
            ],
            std::env::temp_dir().to_string_lossy().into_owned(),
            EnvironmentProjection::default(),
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)?,
        )?;
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new(format!("lease-267-{tag}"))?,
                fence.clone(),
                revisions(),
                100,
                10_000,
                format!("nonce-267-{tag}"),
            )?,
        )?;
        let request = ProcessRequest::new(intent, permit)?;
        let observed = SuspendedProcessIdentity::new(
            eliot_process::ProcessId::new(format!("windows-process-267-{tag}"))?,
            tree,
            job,
            image,
            session_id,
            generation,
            eliot_process::PhysicalProcessBinding::new(
                4_242,
                818_934_281,
                "sink-test-image-267",
                "Local\\Eliot-267-Test",
            )?,
            super::now_ms(),
            exe_digest,
        )?;
        let context = eliot_process::DispatchValidationContext::new(
            eliot_platform::ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            test_epoch(1),
            revisions(),
            41,
        )?;
        let validated = authority.validate_and_consume(request, observed, &context)?;
        Ok(validated.binding().clone())
    }

    /// Issue #267 helper: the exact P-04 stream policy binding under test
    /// (same refs as the production [`super::p04_stream_policy`] on Windows).
    fn sink_test_policy()
    -> Result<eliot_process::ProcessStreamPolicyBinding, Box<dyn std::error::Error>> {
        Ok(eliot_process::ProcessStreamPolicyBinding::new(
            "p04:stream-policy:transport-preview-v1",
            "p04:privacy:raw-transport-preview",
            "p04:visibility:operation-diagnostic",
            "p04:retention:bounded-prefix-only",
            "p04:redaction:none-raw-preview",
        )?)
    }

    /// Issue #267 T1: a fake sink streams a complete multi-chunk stdout plus a
    /// zero-byte stderr into real verifiable evidence objects.
    ///
    /// The pump opens each session before the first admitted byte, appends per
    /// chunk, and finalizes to exactly one terminal: resolved digest/count
    /// equal the independently computed observed bytes, the durable source
    /// carries the same identity, the preview stays separate with its exact
    /// omission, and the zero-byte stream still publishes a real verifiable
    /// object. Cleanup/reopen reconciles the same session/terminal identity
    /// without minting a second receipt.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the complete plus zero-byte acceptance surface needs open, chunked append, finalize, and reopen evidence in one bounded test"
    )]
    fn stream_sink_fake_complete_and_zero_byte_publish_verifiable_objects()
    -> Result<(), Box<dyn std::error::Error>> {
        use eliot_process::{
            ProcessStreamKind, ProcessStreamSinkReadback, ProcessStreamSinkState,
            StreamPersistenceStatus, StreamPreviewRepresentation, StreamTransportStatus,
        };

        let limits = super::sink_backpressure_limits()?;
        let policy = sink_test_policy()?;
        let fake = Arc::new(FakeStreamSink::new());
        let client: Arc<dyn eliot_process::ProcessStreamSinkClient> = fake.clone();

        // Stdout: 20_000 bytes exceed the 16_384-byte preview ceiling, so the
        // preview must truncate with the exact omitted suffix while the
        // resolved identity still covers every observed byte.
        let binding = sink_test_binding("t1-complete")?;
        let mut pump = super::StreamSinkPump::new(
            client.clone(),
            binding,
            ProcessStreamKind::Stdout,
            policy.clone(),
            limits,
        );
        // Fail-closed ordering: no byte is admitted before the session opens.
        assert!(matches!(
            pump.append(b"early"),
            Err(ProcessExecutionError::UnknownOutcome)
        ));
        pump.open()?;
        // The session is open before the first admitted byte: the readback is
        // an open session view with zero counters, never a terminal.
        match pump.reopen()? {
            ProcessStreamSinkReadback::Session { view } => {
                assert_eq!(view.state(), ProcessStreamSinkState::Open);
                assert_eq!(view.next_sequence(), 0);
                assert_eq!(view.next_offset(), 0);
            }
            ProcessStreamSinkReadback::Terminal { .. }
            | ProcessStreamSinkReadback::UnknownOutcome { .. } => {
                return Err("open session must read back as a session".into());
            }
        }
        let payload: Vec<u8> = (0..20_000_u32).map(|i| (i % 251) as u8).collect();
        let expected_digest = super::short_digest(&payload);
        assert_eq!(
            pump.append(&payload[..7_000])?,
            super::SinkAppendOutcome::Admitted
        );
        assert_eq!(
            pump.append(&payload[7_000..14_000])?,
            super::SinkAppendOutcome::Admitted
        );
        assert_eq!(
            pump.append(&payload[14_000..])?,
            super::SinkAppendOutcome::Admitted
        );
        assert_eq!(pump.admitted_bytes(), 20_000);
        assert_eq!(pump.offered_bytes(), 20_000);
        assert_eq!(pump.admitted_sha256(), expected_digest);
        let terminal = pump.finalize_eof()?;
        assert_eq!(terminal.state(), ProcessStreamSinkState::CompleteSource);
        terminal.validate()?;
        let evidence = terminal.evidence().clone();
        evidence.validate()?;
        assert_eq!(evidence.observed_sha256(), expected_digest.as_str());
        assert_eq!(evidence.observed_bytes(), 20_000);
        assert_eq!(evidence.transport(), StreamTransportStatus::Complete);
        assert_eq!(
            evidence.persistence(),
            StreamPersistenceStatus::CompleteSource
        );
        assert!(evidence.gaps().is_empty());
        let Some(source) = evidence.source() else {
            return Err("complete terminal must carry a durable source".into());
        };
        assert_eq!(source.sha256(), expected_digest.as_str());
        assert_eq!(source.byte_length(), 20_000);
        // The preview is separate from the resolved identity: a bounded
        // retained prefix with the exact omitted suffix, never the full
        // stream digest.
        let preview = evidence.preview();
        assert_eq!(
            preview.representation(),
            StreamPreviewRepresentation::TransportBytes
        );
        assert_eq!(preview.retained_bytes(), 16_384);
        assert_eq!(preview.represented_bytes(), 20_000);
        assert!(preview.is_truncated());
        assert_eq!(preview.bytes(), &payload[..16_384]);
        assert_eq!(
            preview.sha256(),
            super::short_digest(&payload[..16_384]).as_str()
        );
        assert_ne!(preview.sha256(), expected_digest.as_str());
        assert_eq!(preview.omitted_ranges().len(), 1);
        assert_eq!(preview.omitted_ranges()[0].start(), 16_384);
        assert_eq!(preview.omitted_ranges()[0].end_exclusive(), 20_000);
        // Cleanup/reopen reconciles the same identity: the same session
        // digest, the same terminal digest, and no second receipt.
        let Some(session) = pump.session() else {
            return Err("sink session must stay open".into());
        };
        let open_sha = session.open_request_sha256().to_owned();
        let terminal_sha = terminal.terminal_sha256().to_owned();
        match pump.reopen()? {
            ProcessStreamSinkReadback::Terminal { terminal } => {
                assert_eq!(terminal.terminal_sha256(), terminal_sha.as_str());
            }
            ProcessStreamSinkReadback::Session { .. }
            | ProcessStreamSinkReadback::UnknownOutcome { .. } => {
                return Err("reopen must reconcile the same terminal".into());
            }
        }
        let Some(session) = pump.session() else {
            return Err("sink session must stay open".into());
        };
        assert_eq!(session.open_request_sha256(), open_sha.as_str());
        assert_eq!(
            pump.finalize_eof()?.terminal_sha256(),
            terminal_sha.as_str()
        );
        assert_eq!(fake.terminal_count(), 1);
        assert_eq!(fake.finalize_calls(), 1);

        // Stderr: a zero-byte EOF still publishes a real verifiable object
        // with the empty digest identity and a complete (untruncated) preview.
        // A separate fake owns this stream's session identity.
        let zero = sink_test_binding("t1-zero")?;
        let zero_fake = Arc::new(FakeStreamSink::new());
        let zero_client: Arc<dyn eliot_process::ProcessStreamSinkClient> = zero_fake.clone();
        let mut pump = super::StreamSinkPump::new(
            zero_client,
            zero,
            ProcessStreamKind::Stderr,
            policy,
            limits,
        );
        pump.open()?;
        assert_eq!(pump.admitted_bytes(), 0);
        let terminal = pump.finalize_eof()?;
        assert_eq!(terminal.state(), ProcessStreamSinkState::CompleteSource);
        terminal.validate()?;
        let evidence = terminal.evidence().clone();
        evidence.validate()?;
        assert_eq!(
            evidence.observed_sha256(),
            super::empty_sha256_hex().as_str()
        );
        assert_eq!(evidence.observed_bytes(), 0);
        let Some(source) = evidence.source() else {
            return Err("zero-byte terminal must carry a durable source".into());
        };
        assert_eq!(source.sha256(), super::empty_sha256_hex().as_str());
        assert_eq!(source.byte_length(), 0);
        assert!(!evidence.preview().is_truncated());
        assert!(evidence.preview().bytes().is_empty());
        assert!(evidence.preview().omitted_ranges().is_empty());
        assert!(evidence.gaps().is_empty());
        Ok(())
    }

    /// Issue #267 T2: pressure, cancellation, prohibition, and provider
    /// failure settle to typed gaps without blocking the drain.
    ///
    /// Backpressure sheds the remainder (the calls return immediately while
    /// the pipe keeps draining) with the exact persistence gap;
    /// cancel-before-EOF preserves the admitted prefix with the cancellation
    /// gap; `POLICY_PROHIBITED` withholds raw bytes while keeping custody;
    /// and a provider failure never yields a complete source while reopen
    /// reconciles the same session identity.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the pressure, cancel, policy-negative, and provider-failure acceptance surface shares one fake-sink shape in one bounded test"
    )]
    fn stream_sink_fake_pressure_cancel_and_policy_negative_settle_typed_gaps()
    -> Result<(), Box<dyn std::error::Error>> {
        use eliot_process::{
            ProcessStreamKind, ProcessStreamSinkReadback, ProcessStreamSinkState,
            StreamEvidenceGap, StreamPersistenceStatus, StreamPreviewRepresentation,
            StreamTransportStatus,
        };

        let limits = super::sink_backpressure_limits()?;
        let policy = sink_test_policy()?;

        // Pressure: the first chunk admits, the rest sheds, and every call
        // returns immediately — the drain never blocks on persistence.
        let fake = Arc::new(FakeStreamSink::new());
        let client: Arc<dyn eliot_process::ProcessStreamSinkClient> = fake.clone();
        let binding = sink_test_binding("t2-pressure")?;
        let mut pump = super::StreamSinkPump::new(
            client.clone(),
            binding,
            ProcessStreamKind::Stdout,
            policy.clone(),
            limits,
        );
        pump.open()?;
        let prefix: Vec<u8> = (0..5_000_u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(pump.append(&prefix)?, super::SinkAppendOutcome::Admitted);
        fake.set_backpressured(true);
        let tail: Vec<u8> = (0..9_000_u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            pump.append(&tail)?,
            super::SinkAppendOutcome::ShedBackpressure
        );
        assert!(pump.backpressure_observed());
        assert_eq!(pump.admitted_bytes(), 5_000);
        assert_eq!(fake.append_calls(), 2);
        // Shedding latches: later chunks shed locally with no provider I/O.
        assert_eq!(
            pump.append(&[7_u8; 100])?,
            super::SinkAppendOutcome::ShedClosed
        );
        assert_eq!(fake.append_calls(), 2);
        assert_eq!(pump.offered_bytes(), 14_100);
        let terminal = pump.finalize_eof()?;
        assert_eq!(terminal.state(), ProcessStreamSinkState::SourceUnavailable);
        terminal.validate()?;
        let evidence = terminal.evidence().clone();
        evidence.validate()?;
        assert!(evidence.source().is_none());
        assert!(
            evidence
                .gaps()
                .contains(&StreamEvidenceGap::PersistenceBackpressure)
        );
        assert!(
            evidence
                .gaps()
                .contains(&StreamEvidenceGap::PersistenceUnavailable)
        );
        assert_eq!(
            evidence.observed_sha256(),
            super::short_digest(&prefix).as_str()
        );
        assert_eq!(evidence.observed_bytes(), 5_000);
        assert_eq!(evidence.transport(), StreamTransportStatus::Complete);
        assert_eq!(
            evidence.persistence(),
            StreamPersistenceStatus::SourceUnavailable
        );

        // Cancel-before-EOF preserves the admitted prefix with the exact
        // cancellation gap and no durable source. A separate fake owns this
        // stream's session identity.
        let fake = Arc::new(FakeStreamSink::new());
        let client: Arc<dyn eliot_process::ProcessStreamSinkClient> = fake.clone();
        let binding = sink_test_binding("t2-cancel")?;
        let mut pump = super::StreamSinkPump::new(
            client.clone(),
            binding,
            ProcessStreamKind::Stdout,
            policy.clone(),
            limits,
        );
        pump.open()?;
        assert_eq!(
            pump.append(b"cancelled-prefix")?,
            super::SinkAppendOutcome::Admitted
        );
        let terminal = pump.abort_cancelled()?;
        assert_eq!(terminal.state(), ProcessStreamSinkState::Cancelled);
        terminal.validate()?;
        let evidence = terminal.evidence().clone();
        evidence.validate()?;
        assert!(evidence.source().is_none());
        assert!(
            evidence
                .gaps()
                .contains(&StreamEvidenceGap::CancelledBeforeEof)
        );
        assert_eq!(
            evidence.observed_sha256(),
            super::short_digest(b"cancelled-prefix").as_str()
        );
        assert_eq!(evidence.observed_bytes(), 16);
        assert_eq!(
            evidence.transport(),
            StreamTransportStatus::CancelledBeforeEof
        );
        assert!(!evidence.preview().is_truncated());
        assert_eq!(evidence.preview().bytes(), b"cancelled-prefix");

        // Policy prohibition withholds raw bytes while keeping custody:
        // identity and count stay exact, the preview is empty, and the
        // durable record carries no source and no raw material. A separate
        // fake owns this stream's session identity.
        let fake = Arc::new(FakeStreamSink::new());
        let client: Arc<dyn eliot_process::ProcessStreamSinkClient> = fake.clone();
        let binding = sink_test_binding("t2-policy")?;
        let mut pump = super::StreamSinkPump::new(
            client.clone(),
            binding,
            ProcessStreamKind::Stderr,
            policy.clone(),
            limits,
        );
        pump.open()?;
        assert_eq!(
            pump.append(b"secret=42-classified")?,
            super::SinkAppendOutcome::Admitted
        );
        let terminal = pump.abort_policy_prohibited()?;
        assert_eq!(terminal.state(), ProcessStreamSinkState::PolicyProhibited);
        terminal.validate()?;
        let evidence = terminal.evidence().clone();
        evidence.validate()?;
        assert!(evidence.source().is_none());
        assert_eq!(evidence.gaps(), &[StreamEvidenceGap::PolicyProhibited]);
        assert_eq!(
            evidence.preview().representation(),
            StreamPreviewRepresentation::WithheldByPolicy
        );
        assert!(evidence.preview().bytes().is_empty());
        assert_eq!(
            evidence.observed_sha256(),
            super::short_digest(b"secret=42-classified").as_str()
        );
        assert_eq!(evidence.observed_bytes(), 20);

        // Provider failure never yields a complete source: finalization
        // errors, no terminal exists, and reopen reads back the same open
        // session. Clearing the fault then settles exactly one terminal.
        // A separate fake owns this stream's session identity.
        let fake = Arc::new(FakeStreamSink::new());
        let client: Arc<dyn eliot_process::ProcessStreamSinkClient> = fake.clone();
        let binding = sink_test_binding("t2-provider")?;
        let mut pump =
            super::StreamSinkPump::new(client, binding, ProcessStreamKind::Stdout, policy, limits);
        pump.open()?;
        assert_eq!(
            pump.append(b"provider-failure-probe")?,
            super::SinkAppendOutcome::Admitted
        );
        fake.set_fail_finalize(true);
        assert!(matches!(
            pump.finalize_eof(),
            Err(ProcessExecutionError::UnknownOutcome)
        ));
        assert!(pump.evidence().is_none());
        assert!(pump.terminal().is_none());
        match pump.reopen()? {
            ProcessStreamSinkReadback::Session { .. } => {}
            ProcessStreamSinkReadback::Terminal { .. }
            | ProcessStreamSinkReadback::UnknownOutcome { .. } => {
                return Err("failed finalization must leave the session open".into());
            }
        }
        fake.set_fail_finalize(false);
        let terminal = pump.finalize_eof()?;
        assert_eq!(terminal.state(), ProcessStreamSinkState::CompleteSource);
        let terminal_sha = terminal.terminal_sha256().to_owned();
        let evidence = terminal.evidence().clone();
        evidence.validate()?;
        assert_eq!(
            evidence.observed_sha256(),
            super::short_digest(b"provider-failure-probe").as_str()
        );
        assert!(evidence.source().is_some());
        match pump.reopen()? {
            ProcessStreamSinkReadback::Terminal { terminal } => {
                assert_eq!(terminal.terminal_sha256(), terminal_sha.as_str());
            }
            ProcessStreamSinkReadback::Session { .. }
            | ProcessStreamSinkReadback::UnknownOutcome { .. } => {
                return Err("reopen must reconcile the same terminal".into());
            }
        }
        assert_eq!(
            pump.finalize_eof()?.terminal_sha256(),
            terminal_sha.as_str()
        );
        assert_eq!(fake.terminal_count(), 1);
        Ok(())
    }
}
