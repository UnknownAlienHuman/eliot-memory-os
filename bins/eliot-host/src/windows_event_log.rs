//! Host Windows Event Log sink seam (F-LOG-HOST-0, issue #889).
//!
//! Thin bounded wrapper over #984's accepted safe platform port
//! (`eliot_platform_windows`, landed `bf37d3e1` / #1706): admitted
//! start/stop/failure events map to the fixed source, event ids, severity,
//! and one redacted insertion string, and delivery goes through
//! `report_local_event`. The Host diagnostics facade uses
//! [`try_admit_admitted_event`] for nonblocking producer admission; one
//! bounded worker owns every synchronous call to [`report_event`]. The
//! wrapper registers no source, edits no registry, and performs no
//! elevation; it acquires no Event Log FFI on the producer path and never
//! fakes delivery through another sink. Production delivery smoke on
//! isolated Windows stays an honest residual for the test phase.
//!
//! Delivery outcomes stay five-way distinct: OS acceptance under the fixed
//! registered-source profile, the explicitly admitted degraded Application
//! profile (never substituted silently; unreachable without installation
//! policy admission), source/access unavailability, OS acceptance versus
//! registered-source proof (acceptance never proves registration or
//! formatted-message availability), and downstream delivery uncertainty
//! (success proves OS acceptance only, never downstream delivery). Handle
//! acquisition is never equated with installed message resources.
//!
//! The wrapper owns the finite nonblocking producer admission, queue and
//! in-flight limits, drop reporting, and shutdown policy for the potentially
//! blocking OS port, so a slow or unavailable port can never block Host
//! control, spawn unbounded workers or retries, or recurse into the sink.
//! Queue and sink outcomes are diagnostics only, never Host semantic
//! failures.

use std::collections::VecDeque;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, TryLockError};
use std::thread;

use eliot_platform_windows::{
    AdmittedEventLogEvent, EventLogError, is_event_log_supported, report_local_event,
};

use crate::host_diagnostics::{BoundedDetail, HostRequestEvidence};

/// Fixed Event Log source named by the #984 consumer contract.
///
/// No runtime source registration happens here: this string is the admitted
/// name #984's safe port uses. There is no fallback source and no silent
/// substitution.
pub const EVENT_LOG_SOURCE: &str = "EliotHost";

/// Bound for one redacted insertion string. Mirrors
/// [`crate::host_diagnostics::MAX_DIAGNOSTIC_DETAIL_BYTES`]; the wrapper pins
/// its own constant so the consumer contract stays explicit.
pub const EVENT_LOG_MAX_INSERTION_BYTES: usize = 1024;

/// Default bounded queue capacity for the nonblocking admission wrapper.
/// Finite and small: slow delivery drops with a count, never grows.
pub const EVENT_LOG_QUEUE_CAPACITY: usize = 64;

/// Event Log severity for an admitted Host event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventLogSeverity {
    /// Service start/stop lifecycle notice.
    Information,
    /// Service failure notice.
    Error,
}

impl EventLogSeverity {
    /// Stable severity name carried in the insertion contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Information => "information",
            Self::Error => "error",
        }
    }
}

/// The only Host events admitted to the Event Log.
///
/// Start, stop, and failure only. Every other Host observation stays on the
/// stderr `tracing` sink; the wrapper never invents an Event Log mapping for
/// it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmittedEvent {
    /// Host service start.
    ServiceStart,
    /// Host service stop.
    ServiceStop,
    /// Host service failure (carries the terminal correlation code).
    ServiceFailure,
}

impl AdmittedEvent {
    /// Stable event name for the consumer contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceStart => "service_start",
            Self::ServiceStop => "service_stop",
            Self::ServiceFailure => "service_failure",
        }
    }

    /// Fixed event identifier for the consumer contract.
    #[must_use]
    pub const fn event_id(self) -> u32 {
        match self {
            Self::ServiceStart => 100,
            Self::ServiceStop => 101,
            Self::ServiceFailure => 102,
        }
    }

    /// Fixed severity for the consumer contract: start/stop are
    /// informational, failure is an error.
    #[must_use]
    pub const fn severity(self) -> EventLogSeverity {
        match self {
            Self::ServiceStart | Self::ServiceStop => EventLogSeverity::Information,
            Self::ServiceFailure => EventLogSeverity::Error,
        }
    }
}

impl AdmittedEvent {
    /// Whether one projected evidence class actually supports this event.
    ///
    /// The Event Log admits an event only when the owner's own evidence
    /// proves it happened: a start once the serving process started, a stop
    /// once the durable effect committed, a failure once the request failed.
    /// Evidence that asserts no completed operation (sighted, admitted,
    /// ready, cancelled, unknown) never admits an Event Log record, so the
    /// sink is never asked to state an outcome the owner did not produce
    /// (I14.20).
    #[must_use]
    pub const fn is_admitted_by(self, evidence: HostRequestEvidence) -> bool {
        matches!(
            (self, evidence),
            (Self::ServiceStart, HostRequestEvidence::ProcessStarted)
                | (Self::ServiceStop, HostRequestEvidence::DurableCommitted)
                | (Self::ServiceFailure, HostRequestEvidence::Failed)
        )
    }
}

/// One bounded, redacted Event Log record.
///
/// The insertion string carries only nonsecret material (terminal codes,
/// stage names, bounded reason codes); it never carries credentials, tokens,
/// connection strings, environment values, command lines, source/user/model
/// payloads, or arbitrary error text. Bounding limits size, not sensitivity:
/// callers must redact before constructing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventLogRecord {
    event: AdmittedEvent,
    insertion: BoundedDetail,
}

impl EventLogRecord {
    /// Bounds one redacted insertion string to
    /// [`EVENT_LOG_MAX_INSERTION_BYTES`], recording truncation honesty.
    #[must_use]
    pub fn new(event: AdmittedEvent, insertion: &str) -> Self {
        debug_assert_eq!(
            EVENT_LOG_MAX_INSERTION_BYTES,
            crate::host_diagnostics::MAX_DIAGNOSTIC_DETAIL_BYTES,
            "wrapper insertion bound must mirror the facade detail bound"
        );
        Self {
            event,
            insertion: crate::host_diagnostics::bound_detail(insertion),
        }
    }

    #[must_use]
    pub const fn event(&self) -> AdmittedEvent {
        self.event
    }

    #[must_use]
    pub fn insertion(&self) -> &str {
        self.insertion.text()
    }

    #[must_use]
    pub const fn original_bytes(&self) -> usize {
        self.insertion.original_bytes()
    }

    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.insertion.truncated()
    }

    /// Fixed consumer mapping: source, event id, severity.
    #[must_use]
    pub const fn mapping(&self) -> (&'static str, u32, EventLogSeverity) {
        (
            EVENT_LOG_SOURCE,
            self.event.event_id(),
            self.event.severity(),
        )
    }
}

/// Honest delivery disposition for one admitted record reported through #984.
///
/// Success proves OS acceptance only: not a registered source, not
/// formatted-message availability, not downstream delivery, and not a Host
/// semantic result. The two arms keep the registered-source profile and the
/// explicitly admitted degraded Application profile distinct; this wrapper
/// uses only the registered-source profile and never substitutes the
/// degraded one silently, so the degraded arm is unreachable without
/// installation-policy admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventLogDelivery {
    /// The OS accepted the record under the fixed registered-source profile
    /// (`EliotHost`, fixed event id and severity). Source registration and
    /// downstream delivery stay unproven.
    RegisteredSourceAccepted {
        /// The admitted event that was accepted, for correlation.
        event: AdmittedEvent,
    },
    /// The OS accepted the record under the explicitly admitted degraded
    /// Application profile. Never produced without installation-policy
    /// admission; no silent fallback exists.
    DegradedApplicationAccepted {
        /// The admitted event that was accepted, for correlation.
        event: AdmittedEvent,
    },
}

impl EventLogDelivery {
    /// The admitted event that was accepted, for correlation with the
    /// submitted record.
    #[must_use]
    pub const fn event(&self) -> AdmittedEvent {
        match self {
            Self::RegisteredSourceAccepted { event }
            | Self::DegradedApplicationAccepted { event } => *event,
        }
    }

    /// Stable outcome name for a bounded diagnostic record.
    ///
    /// The two arms stay named apart so a reader can never read the
    /// registered-source acceptance as the explicitly admitted degraded
    /// Application profile, which this wrapper never substitutes silently.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RegisteredSourceAccepted { .. } => "registered_source_accepted",
            Self::DegradedApplicationAccepted { .. } => "degraded_application_accepted",
        }
    }
}

/// Typed Event Log wrapper failures.
///
/// All outcomes are diagnostics only: they never change the Host
/// operation, result, error, order, retry, state, or receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsEventLogError {
    /// The OS port cannot carry the record: this build has no live port
    /// (non-Windows) or the reachable port is currently unavailable. Never a
    /// silent fallback and never FFI acquired inside Host.
    EventLogUnavailable,
    /// The record was rejected before any OS call (over-bound, `NUL`, or a
    /// protected marker). Nothing was submitted.
    InvalidRecord,
    /// No source handle could be acquired: the source is missing or access
    /// was denied. Nothing was submitted. Carries only the bounded `Win32`
    /// error code, never message text or insertion contents.
    SourceUnavailable {
        /// Bounded `Win32` error code; no message text.
        code: u32,
    },
    /// The OS refused the validated record; OS acceptance is unknown.
    /// Carries only the bounded `Win32` error code, never message text or
    /// insertion contents.
    ReportRefused {
        /// Bounded `Win32` error code; no message text.
        code: u32,
    },
    /// Bounded admission rejected the record; `dropped_total` on the queue
    /// advanced by one. Nonblocking by construction.
    QueueFull,
    /// The queue is shut down; further admission is rejected without
    /// changing the drop count.
    Closed,
}

impl WindowsEventLogError {
    /// Stable outcome name for a bounded diagnostic record.
    ///
    /// Names the typed outcome only: no message text and no insertion
    /// contents cross this boundary, so an operator-facing record can name
    /// the disposition without echoing what was submitted.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EventLogUnavailable => "event_log_unavailable",
            Self::InvalidRecord => "invalid_record",
            Self::SourceUnavailable { .. } => "source_unavailable",
            Self::ReportRefused { .. } => "report_refused",
            Self::QueueFull => "queue_full",
            Self::Closed => "closed",
        }
    }
}

impl fmt::Display for WindowsEventLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventLogUnavailable => {
                write!(f, "windows event log sink unavailable (see issue #984)")
            }
            Self::InvalidRecord => {
                write!(
                    f,
                    "windows event log record failed validation; nothing was submitted"
                )
            }
            Self::SourceUnavailable { code } => {
                write!(f, "windows event log source/access unavailable ({code})")
            }
            Self::ReportRefused { code } => {
                write!(
                    f,
                    "windows event log report refused ({code}); OS acceptance unknown"
                )
            }
            Self::QueueFull => write!(f, "windows event log queue full; record dropped"),
            Self::Closed => write!(f, "windows event log queue is shut down"),
        }
    }
}

impl std::error::Error for WindowsEventLogError {}

/// Reports whether the Event Log sink can carry Host diagnostics.
///
/// Answers `Ok` where #984's safe port is live (Windows): delivery is
/// attempted through `report_local_event`. Off Windows the port stays
/// [`WindowsEventLogError::EventLogUnavailable`]: absence stays missing,
/// never a faked delivery and never handle acquisition equated with
/// installed message resources.
pub fn event_log_sink_status() -> Result<(), WindowsEventLogError> {
    if is_event_log_supported() {
        Ok(())
    } else {
        Err(WindowsEventLogError::EventLogUnavailable)
    }
}

/// Attempts Event Log delivery for one admitted record through #984.
///
/// Maps the admitted event to the fixed source, event id, and severity and
/// submits the bounded redacted insertion string via the safe port. Success
/// proves OS acceptance only, under the registered-source profile; source
/// registration, formatted-message availability, and downstream delivery
/// stay unproven. The degraded Application profile is never substituted
/// silently. This low-level seam is synchronous and may block inside the OS
/// port. Production Host code uses [`try_admit_admitted_event`]; direct
/// callers must not invoke it from Host control work. It never spawns a
/// worker, logs through the Event Log sink, or changes a Host result.
pub fn report_event(record: &EventLogRecord) -> Result<EventLogDelivery, WindowsEventLogError> {
    let event = record.event();
    match report_local_event(to_platform_event(event), record.insertion()) {
        Ok(receipt) => {
            debug_assert_eq!(
                receipt.event_id(),
                event.event_id(),
                "platform receipt must carry the submitted admitted mapping"
            );
            debug_assert_eq!(
                receipt.source(),
                EVENT_LOG_SOURCE,
                "platform receipt must carry the fixed source"
            );
            Ok(EventLogDelivery::RegisteredSourceAccepted { event })
        }
        Err(error) => Err(map_event_log_error(error)),
    }
}

/// Legacy synchronous seam for direct Event Log callers.
///
/// This call may block inside the OS port. Production Host diagnostics use
/// [`try_admit_admitted_event`] so Host control work never waits for delivery.
/// Callers outside the producer must keep this operation off Host control
/// paths.
pub fn report_admitted_event(
    event: AdmittedEvent,
    correlation: &str,
) -> Result<EventLogDelivery, WindowsEventLogError> {
    report_event(&EventLogRecord::new(event, correlation))
}

/// Maps one admitted wrapper event to #984's platform event.
fn to_platform_event(event: AdmittedEvent) -> AdmittedEventLogEvent {
    match event {
        AdmittedEvent::ServiceStart => AdmittedEventLogEvent::ServiceStart,
        AdmittedEvent::ServiceStop => AdmittedEventLogEvent::ServiceStop,
        AdmittedEvent::ServiceFailure => AdmittedEventLogEvent::ServiceFailure,
    }
}

/// Maps #984's typed port failure to the wrapper's typed outcome.
///
/// Unavailable and unsupported ports stay
/// [`WindowsEventLogError::EventLogUnavailable`]; refused source acquisition
/// and refused reports keep their bounded codes; pre-OS rejections stay
/// invalid without echoing insertion contents.
fn map_event_log_error(error: EventLogError) -> WindowsEventLogError {
    match error {
        EventLogError::InvalidInput => WindowsEventLogError::InvalidRecord,
        EventLogError::Unavailable | EventLogError::UnsupportedPlatform => {
            WindowsEventLogError::EventLogUnavailable
        }
        EventLogError::RegistrationFailed { code } => {
            WindowsEventLogError::SourceUnavailable { code }
        }
        EventLogError::ReportFailed { code } => WindowsEventLogError::ReportRefused { code },
    }
}

/// Finite nonblocking producer admission queue in front of the OS port.
///
/// Bounded [`EVENT_LOG_QUEUE_CAPACITY`] by default; a slow or unavailable
/// port surfaces as [`WindowsEventLogError::QueueFull`] with an exact
/// `dropped_total`, never an unbounded worker, retry, or blocking wait. All
/// methods are nonblocking and perform no sink logging, so admission can
/// never recurse into the port.
#[derive(Debug)]
pub struct WindowsEventLogQueue {
    capacity: usize,
    queue: VecDeque<EventLogRecord>,
    dropped_total: u64,
    closed: bool,
}

impl WindowsEventLogQueue {
    /// Creates a queue with the given finite capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            queue: VecDeque::new(),
            dropped_total: 0,
            closed: false,
        }
    }

    /// Creates a queue with [`EVENT_LOG_QUEUE_CAPACITY`].
    #[must_use]
    pub fn with_default_capacity() -> Self {
        Self::new(EVENT_LOG_QUEUE_CAPACITY)
    }

    /// Nonblocking admission: enqueues or drops with an exact count.
    ///
    /// A shut-down queue rejects with [`WindowsEventLogError::Closed`]
    /// without advancing the drop count. A full queue advances
    /// `dropped_total` by exactly one and returns
    /// [`WindowsEventLogError::QueueFull`].
    pub fn try_admit(&mut self, record: EventLogRecord) -> Result<(), WindowsEventLogError> {
        if self.closed {
            return Err(WindowsEventLogError::Closed);
        }
        if self.queue.len() >= self.capacity {
            self.dropped_total = self.dropped_total.saturating_add(1);
            return Err(WindowsEventLogError::QueueFull);
        }
        self.queue.push_back(record);
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    #[must_use]
    pub const fn dropped_total(&self) -> u64 {
        self.dropped_total
    }

    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Marks the queue shut down and reports the honest terminal snapshot.
    ///
    /// The returned `unsent` count is records still held with delivery
    /// disposition Unknown: dropping a future, reaching a caller timeout, or
    /// calling shutdown is not proof that a synchronous OS call stopped, and
    /// this function claims no drain or abort that did not complete. Held
    /// records are kept (not delivered, not silently freed as delivered);
    /// further admission is [`WindowsEventLogError::Closed`].
    pub fn shutdown(&mut self) -> QueueShutdown {
        self.closed = true;
        QueueShutdown {
            unsent: self.queue.len(),
            dropped_total: self.dropped_total,
        }
    }
}

/// Honest terminal snapshot from [`WindowsEventLogQueue::shutdown`].
///
/// `unsent` records have Unknown delivery disposition: they were neither
/// delivered nor proven stopped, only parked. No drain or abort is claimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueShutdown {
    unsent: usize,
    dropped_total: u64,
}

impl QueueShutdown {
    #[must_use]
    pub const fn unsent(&self) -> usize {
        self.unsent
    }

    #[must_use]
    pub const fn dropped_total(&self) -> u64 {
        self.dropped_total
    }
}

/// Queue work count from a nonblocking producer or shutdown snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventLogWorkCount {
    /// The count was observed while holding the queue lock.
    Known(usize),
    /// The nonblocking snapshot could not acquire the queue lock.
    Unknown,
}

impl EventLogWorkCount {
    /// Returns the observed count, or `None` when a nonblocking snapshot
    /// could not establish it.
    #[must_use]
    pub const fn known(self) -> Option<usize> {
        match self {
            Self::Known(count) => Some(count),
            Self::Unknown => None,
        }
    }
}

/// Delivery knowledge for work left outstanding by shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventLogWorkDisposition {
    /// Shutdown did not prove acceptance, completion, or cancellation.
    Unknown,
}

impl EventLogWorkDisposition {
    /// Stable name for the outstanding-work disposition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
        }
    }
}

/// Result of one finite, nonblocking Event Log producer admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventLogAdmission {
    /// The bounded record was admitted. `truncated` reports bounded-detail
    /// truncation; `dropped_total` includes prior capacity or sink drops.
    Admitted {
        /// Whether the redacted insertion was truncated to its byte bound.
        truncated: bool,
        /// Monotone process-wide drop count observed at this admission.
        dropped_total: u64,
    },
    /// The finite queue was full; this record was counted as dropped.
    DroppedQueueFull {
        /// Monotone process-wide drop count after this drop.
        dropped_total: u64,
    },
    /// The queue lock was busy; this record was dropped without waiting.
    DroppedProducerBusy {
        /// Monotone process-wide drop count after this drop.
        dropped_total: u64,
    },
    /// Bounded record construction panicked and was contained.
    DroppedFormattingPanic {
        /// Monotone process-wide drop count after this drop.
        dropped_total: u64,
    },
    /// Startup has not run, so admission did not create a worker.
    RejectedNotStarted {
        /// Current count, or zero before producer state exists.
        dropped_total: u64,
    },
    /// Shutdown has started; this record was not admitted.
    RejectedShutdown {
        /// Current count; closed admission does not increment it.
        dropped_total: u64,
    },
    /// The single worker could not start or has exited; this record was
    /// counted as dropped.
    RejectedWorkerUnavailable {
        /// Monotone process-wide drop count after this drop.
        dropped_total: u64,
    },
}

impl EventLogAdmission {
    /// Stable outcome name suitable for the bounded stderr diagnostic.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted {
                truncated: false, ..
            } => "admitted",
            Self::Admitted {
                truncated: true, ..
            } => "admitted_truncated",
            Self::DroppedQueueFull { .. } => "queue_full",
            Self::DroppedProducerBusy { .. } => "producer_busy",
            Self::DroppedFormattingPanic { .. } => "formatting_panic_contained",
            Self::RejectedNotStarted { .. } => "not_started",
            Self::RejectedShutdown { .. } => "shutdown",
            Self::RejectedWorkerUnavailable { .. } => "worker_unavailable",
        }
    }

    /// Monotone drop count observed when this outcome was produced.
    #[must_use]
    pub const fn dropped_total(self) -> u64 {
        match self {
            Self::Admitted { dropped_total, .. }
            | Self::DroppedQueueFull { dropped_total }
            | Self::DroppedProducerBusy { dropped_total }
            | Self::DroppedFormattingPanic { dropped_total }
            | Self::RejectedNotStarted { dropped_total }
            | Self::RejectedShutdown { dropped_total }
            | Self::RejectedWorkerUnavailable { dropped_total } => dropped_total,
        }
    }
}

/// Point-in-time producer status captured without waiting for queue access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventLogProducerSnapshot {
    worker_started: bool,
    dropped_total: u64,
    queued: EventLogWorkCount,
    in_flight: EventLogWorkCount,
    shutdown: bool,
}

impl EventLogProducerSnapshot {
    /// Whether the process-wide worker thread was created successfully.
    #[must_use]
    pub const fn worker_started(self) -> bool {
        self.worker_started
    }

    /// Current process-wide monotone drop count.
    #[must_use]
    pub const fn dropped_total(self) -> u64 {
        self.dropped_total
    }

    /// Number of records waiting in the bounded queue, when observable.
    #[must_use]
    pub const fn queued(self) -> EventLogWorkCount {
        self.queued
    }

    /// Number of records held by the sole worker, when observable (zero or
    /// one).
    #[must_use]
    pub const fn in_flight(self) -> EventLogWorkCount {
        self.in_flight
    }

    /// Whether shutdown was requested.
    #[must_use]
    pub const fn is_shutdown(self) -> bool {
        self.shutdown
    }
}

/// Nonblocking terminal view of outstanding Event Log work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventLogShutdownSnapshot {
    dropped_total: u64,
    queued: EventLogWorkCount,
    in_flight: EventLogWorkCount,
    delivery_disposition: EventLogWorkDisposition,
}

impl EventLogShutdownSnapshot {
    /// Current process-wide monotone drop count.
    #[must_use]
    pub const fn dropped_total(self) -> u64 {
        self.dropped_total
    }

    /// Number of records retained in the bounded queue, when observable.
    #[must_use]
    pub const fn queued(self) -> EventLogWorkCount {
        self.queued
    }

    /// Number of records held by the sole worker, when observable (zero or
    /// one).
    #[must_use]
    pub const fn in_flight(self) -> EventLogWorkCount {
        self.in_flight
    }

    /// Delivery status for outstanding work. Shutdown does not claim a drain
    /// or abort.
    #[must_use]
    pub const fn delivery_disposition(self) -> EventLogWorkDisposition {
        self.delivery_disposition
    }
}

const WORKER_NOT_STARTED: u8 = 0;
const WORKER_STARTING: u8 = 1;
const WORKER_RUNNING: u8 = 2;
const WORKER_EXITED: u8 = 3;
const WORKER_UNAVAILABLE: u8 = 4;

struct EventLogProducerState {
    queue: Mutex<WindowsEventLogQueue>,
    wake: Condvar,
    shutdown: AtomicBool,
    start_attempted: AtomicBool,
    worker_spawned: AtomicBool,
    worker_state: AtomicU8,
    in_flight: AtomicBool,
    dropped_total: AtomicU64,
}

impl EventLogProducerState {
    fn new() -> Self {
        Self {
            queue: Mutex::new(WindowsEventLogQueue::with_default_capacity()),
            wake: Condvar::new(),
            shutdown: AtomicBool::new(false),
            start_attempted: AtomicBool::new(false),
            worker_spawned: AtomicBool::new(false),
            worker_state: AtomicU8::new(WORKER_NOT_STARTED),
            in_flight: AtomicBool::new(false),
            dropped_total: AtomicU64::new(0),
        }
    }
}

static EVENT_LOG_PRODUCER: OnceLock<Arc<EventLogProducerState>> = OnceLock::new();
static EVENT_LOG_SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

fn producer_state() -> &'static Arc<EventLogProducerState> {
    EVENT_LOG_PRODUCER.get_or_init(|| Arc::new(EventLogProducerState::new()))
}

/// Starts the process-wide Event Log worker at most once.
///
/// Call during process setup before the first diagnostic projection. Startup
/// creates one worker and never retries. The worker owns synchronous OS port
/// calls; this function does not acquire the Event Log source.
#[must_use]
pub fn start_event_log_producer() -> EventLogProducerSnapshot {
    let state = producer_state();
    if !state.start_attempted.swap(true, Ordering::AcqRel) {
        if EVENT_LOG_SHUTDOWN_REQUESTED.load(Ordering::Acquire)
            || state.shutdown.load(Ordering::Acquire)
        {
            state
                .worker_state
                .store(WORKER_UNAVAILABLE, Ordering::Release);
        } else {
            state.worker_state.store(WORKER_STARTING, Ordering::Release);
            let worker_state = Arc::clone(state);
            let panic_state = Arc::clone(state);
            let spawned = catch_unwind(AssertUnwindSafe(|| {
                thread::Builder::new()
                    .name("eliot-event-log".to_owned())
                    .spawn(move || {
                        if catch_unwind(AssertUnwindSafe(|| {
                            run_event_log_worker(&worker_state);
                        }))
                        .is_err()
                        {
                            mark_worker_exited(&panic_state);
                        }
                    })
            }));
            match spawned {
                Ok(Ok(worker)) => {
                    state.worker_spawned.store(true, Ordering::Release);
                    drop(worker);
                }
                Ok(Err(_)) | Err(_) => state
                    .worker_state
                    .store(WORKER_UNAVAILABLE, Ordering::Release),
            }
        }
    }
    producer_snapshot(state)
}

/// Nonblocking admission for an owner-admitted start, stop, or failure.
///
/// The producer bounds the redacted insertion, uses the fixed 64-entry queue,
/// and returns immediately on queue-lock contention or saturation. It never
/// calls the OS port, waits for the worker, retries, or logs through the
/// Event Log sink.
#[must_use]
pub fn try_admit_admitted_event(event: AdmittedEvent, correlation: &str) -> EventLogAdmission {
    let Some(state) = EVENT_LOG_PRODUCER.get() else {
        return if EVENT_LOG_SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
            EventLogAdmission::RejectedShutdown { dropped_total: 0 }
        } else {
            EventLogAdmission::RejectedNotStarted { dropped_total: 0 }
        };
    };
    if EVENT_LOG_SHUTDOWN_REQUESTED.load(Ordering::Acquire)
        || state.shutdown.load(Ordering::Acquire)
    {
        return EventLogAdmission::RejectedShutdown {
            dropped_total: state.dropped_total.load(Ordering::Relaxed),
        };
    }
    if !state.worker_spawned.load(Ordering::Acquire) {
        return EventLogAdmission::RejectedWorkerUnavailable {
            dropped_total: increment_dropped_total(state),
        };
    }
    match state.worker_state.load(Ordering::Acquire) {
        WORKER_STARTING | WORKER_RUNNING => {}
        _ => {
            return EventLogAdmission::RejectedWorkerUnavailable {
                dropped_total: increment_dropped_total(state),
            };
        }
    }

    let Ok(record) = catch_unwind(AssertUnwindSafe(|| EventLogRecord::new(event, correlation)))
    else {
        return EventLogAdmission::DroppedFormattingPanic {
            dropped_total: increment_dropped_total(state),
        };
    };
    let truncated = record.truncated();
    let mut queue = match state.queue.try_lock() {
        Ok(queue) => queue,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => {
            return EventLogAdmission::DroppedProducerBusy {
                dropped_total: increment_dropped_total(state),
            };
        }
    };
    if EVENT_LOG_SHUTDOWN_REQUESTED.load(Ordering::Acquire)
        || state.shutdown.load(Ordering::Acquire)
        || queue.is_closed()
    {
        return EventLogAdmission::RejectedShutdown {
            dropped_total: state.dropped_total.load(Ordering::Relaxed),
        };
    }
    match state.worker_state.load(Ordering::Acquire) {
        WORKER_STARTING | WORKER_RUNNING => {}
        _ => {
            return EventLogAdmission::RejectedWorkerUnavailable {
                dropped_total: increment_dropped_total(state),
            };
        }
    }
    match queue.try_admit(record) {
        Ok(()) => {
            state.wake.notify_one();
            EventLogAdmission::Admitted {
                truncated,
                dropped_total: state.dropped_total.load(Ordering::Relaxed),
            }
        }
        Err(WindowsEventLogError::QueueFull) => EventLogAdmission::DroppedQueueFull {
            dropped_total: increment_dropped_total(state),
        },
        Err(WindowsEventLogError::Closed) => EventLogAdmission::RejectedShutdown {
            dropped_total: state.dropped_total.load(Ordering::Relaxed),
        },
        Err(_) => EventLogAdmission::RejectedWorkerUnavailable {
            dropped_total: increment_dropped_total(state),
        },
    }
}

/// Requests worker shutdown and returns a nonblocking terminal snapshot.
///
/// The worker stops dequeuing after shutdown is requested. Queued records stay
/// parked and the synchronous report already held by the worker may continue.
/// No join, drain, or abort is attempted. The queue and in-flight counts are
/// exact when the queue lock is immediately available; otherwise both are
/// `Unknown`. Outstanding records retain an `Unknown` delivery disposition.
#[must_use]
pub fn shutdown_event_log_producer() -> EventLogShutdownSnapshot {
    EVENT_LOG_SHUTDOWN_REQUESTED.store(true, Ordering::Release);
    let Some(state) = EVENT_LOG_PRODUCER.get() else {
        return EventLogShutdownSnapshot {
            dropped_total: 0,
            queued: EventLogWorkCount::Known(0),
            in_flight: EventLogWorkCount::Known(0),
            delivery_disposition: EventLogWorkDisposition::Unknown,
        };
    };
    state.shutdown.store(true, Ordering::Release);
    let counts = match state.queue.try_lock() {
        Ok(mut queue) => {
            let shutdown = queue.shutdown();
            (
                EventLogWorkCount::Known(shutdown.unsent()),
                EventLogWorkCount::Known(usize::from(state.in_flight.load(Ordering::Acquire))),
            )
        }
        Err(TryLockError::Poisoned(poisoned)) => {
            let mut queue = poisoned.into_inner();
            let shutdown = queue.shutdown();
            (
                EventLogWorkCount::Known(shutdown.unsent()),
                EventLogWorkCount::Known(usize::from(state.in_flight.load(Ordering::Acquire))),
            )
        }
        Err(TryLockError::WouldBlock) => (EventLogWorkCount::Unknown, EventLogWorkCount::Unknown),
    };
    state.wake.notify_all();
    EventLogShutdownSnapshot {
        dropped_total: state.dropped_total.load(Ordering::Relaxed),
        queued: counts.0,
        in_flight: counts.1,
        delivery_disposition: EventLogWorkDisposition::Unknown,
    }
}

fn producer_snapshot(state: &EventLogProducerState) -> EventLogProducerSnapshot {
    let (queued, in_flight) = match state.queue.try_lock() {
        Ok(queue) => (
            EventLogWorkCount::Known(queue.len()),
            EventLogWorkCount::Known(usize::from(state.in_flight.load(Ordering::Acquire))),
        ),
        Err(TryLockError::Poisoned(poisoned)) => {
            let queue = poisoned.into_inner();
            (
                EventLogWorkCount::Known(queue.len()),
                EventLogWorkCount::Known(usize::from(state.in_flight.load(Ordering::Acquire))),
            )
        }
        Err(TryLockError::WouldBlock) => (EventLogWorkCount::Unknown, EventLogWorkCount::Unknown),
    };
    EventLogProducerSnapshot {
        worker_started: state.worker_spawned.load(Ordering::Acquire),
        dropped_total: state.dropped_total.load(Ordering::Relaxed),
        queued,
        in_flight,
        shutdown: EVENT_LOG_SHUTDOWN_REQUESTED.load(Ordering::Acquire)
            || state.shutdown.load(Ordering::Acquire),
    }
}

fn increment_dropped_total(state: &EventLogProducerState) -> u64 {
    let previous = state
        .dropped_total
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_add(1))
        })
        .unwrap_or_else(|current| current);
    previous.saturating_add(1)
}

fn run_event_log_worker(state: &EventLogProducerState) {
    state.worker_state.store(WORKER_RUNNING, Ordering::Release);
    let _exit = EventLogWorkerExit(state);
    loop {
        let record = {
            let mut queue = match state.queue.lock() {
                Ok(queue) => queue,
                Err(poisoned) => poisoned.into_inner(),
            };
            loop {
                if EVENT_LOG_SHUTDOWN_REQUESTED.load(Ordering::Acquire)
                    || state.shutdown.load(Ordering::Acquire)
                {
                    return;
                }
                if let Some(record) = queue.queue.pop_front() {
                    state.in_flight.store(true, Ordering::Release);
                    break record;
                }
                queue = match state.wake.wait(queue) {
                    Ok(queue) => queue,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
        };

        let event = record.event();
        let delivery_result = catch_unwind(AssertUnwindSafe(|| report_event(&record)));
        let (outcome, dropped) = match delivery_result {
            Ok(Ok(delivery)) => (delivery.as_str(), false),
            Ok(Err(error)) => (error.as_str(), true),
            Err(_) => ("report_panic_contained", true),
        };
        if dropped {
            increment_dropped_total(state);
        }
        let tracing_result = catch_unwind(AssertUnwindSafe(|| {
            crate::host_diagnostics::info!(
                target: "eliot_host::windows_event_log",
                event = "host.event_log_delivery",
                operation = event.as_str(),
                event_id = event.event_id(),
                severity = event.severity().as_str(),
                outcome = outcome,
                "host event log delivery outcome"
            );
        }));
        if tracing_result.is_err() {
            // Tracing panic is contained; delivery already has its own
            // disposition and remains independent of Host semantics.
        }

        let _queue = match state.queue.lock() {
            Ok(queue) => queue,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.in_flight.store(false, Ordering::Release);
    }
}

struct EventLogWorkerExit<'a>(&'a EventLogProducerState);

impl Drop for EventLogWorkerExit<'_> {
    fn drop(&mut self) {
        mark_worker_exited(self.0);
    }
}

fn mark_worker_exited(state: &EventLogProducerState) {
    if state.in_flight.swap(false, Ordering::AcqRel) {
        increment_dropped_total(state);
    }
    state.worker_state.store(WORKER_EXITED, Ordering::Release);
}
