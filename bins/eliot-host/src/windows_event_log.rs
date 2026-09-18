//! Host Windows Event Log sink seam (F-LOG-HOST-0, issue #889).
//!
//! Thin bounded wrapper naming #984's accepted safe platform port. On the
//! current base #984 is absent (no `event_log.rs` in
//! `crates/kernel/eliot-platform-windows`, no `Win32_System_EventLog`
//! feature, zero `eventlog` matches), so this wrapper ships the same
//! typed-unavailable seam as the kernel precedent
//! (`kernel_diagnostics.rs:54-94`): it names the consumer contract (fixed
//! source, event ids, severity, redacted insertion strings; admitted
//! start/stop/failure only) but performs no delivery, acquires no Event Log
//! FFI, registers no source, edits no registry, and never fakes delivery
//! through another sink. Production delivery smoke on isolated Windows stays
//! an honest residual until #984 lands.
//!
//! The wrapper owns the finite nonblocking producer admission, queue and
//! in-flight limits, drop reporting, and shutdown policy for the potentially
//! blocking OS port, so a slow or unavailable port can never block Host
//! control, spawn unbounded workers or retries, or recurse into the sink.
//! Queue and sink outcomes are diagnostics only, never Host semantic
//! failures.

use std::collections::VecDeque;
use std::fmt;

use crate::host_diagnostics::BoundedDetail;

/// Fixed Event Log source named by the #984 consumer contract.
///
/// No runtime source registration happens here: this string is the admitted
/// name #984's safe port must use once landed. There is no fallback source
/// and no silent substitution.
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

/// Typed Event Log wrapper failures.
///
/// All outcomes are diagnostics only: they never change the Host
/// operation, result, error, order, retry, state, or receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsEventLogError {
    /// Delivery was requested but #984's safe port is still absent. Never a
    /// silent fallback and never FFI acquired inside Host.
    EventLogUnavailable,
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
            Self::QueueFull => write!(f, "windows event log queue full; record dropped"),
            Self::Closed => write!(f, "windows event log queue is shut down"),
        }
    }
}

impl std::error::Error for WindowsEventLogError {}

/// Reports whether the Event Log sink can carry Host diagnostics.
///
/// Always answers [`WindowsEventLogError::EventLogUnavailable`] until #984
/// lands. Absence stays missing, never a faked delivery and never handle
/// acquisition equated with installed message resources.
pub fn event_log_sink_status() -> Result<(), WindowsEventLogError> {
    Err(WindowsEventLogError::EventLogUnavailable)
}

/// Attempts Event Log delivery for one admitted record.
///
/// Currently always returns [`WindowsEventLogError::EventLogUnavailable`]:
/// #984's safe port is absent, so there is no handle, no OS acceptance, and
/// no downstream delivery to report. The record's mapping (source, event id,
/// severity) is still validated by construction, so this function proves
/// mapping and failure handling only. It never blocks, never spawns a
/// worker, never logs through the sink (no recursion), and never changes the
/// caller's Host result.
pub fn report_event(_record: &EventLogRecord) -> Result<(), WindowsEventLogError> {
    Err(WindowsEventLogError::EventLogUnavailable)
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
