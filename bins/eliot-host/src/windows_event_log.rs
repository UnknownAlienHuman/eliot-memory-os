//! Host Windows Event Log sink seam (F-LOG-HOST-0, issue #889).
//!
//! Thin bounded wrapper over #984's accepted safe platform port
//! (`eliot_platform_windows`, landed `bf37d3e1` / #1706): admitted
//! start/stop/failure events map to the fixed source, event ids, severity,
//! and one redacted insertion string, and delivery goes through
//! `report_local_event`. The wrapper registers no source, edits no registry,
//! and performs no elevation; it acquires no Event Log FFI and never fakes
//! delivery through another sink. Production delivery smoke on isolated
//! Windows stays an honest residual for the test phase.
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

use eliot_platform_windows::{
    AdmittedEventLogEvent, EventLogError, is_event_log_supported, report_local_event,
};

use crate::host_diagnostics::BoundedDetail;

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
/// silently. This call is synchronous and may block inside the OS port; it
/// never spawns a worker, never logs through the sink (no recursion), and
/// never changes the caller's Host result.
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
