//! Safe local-only Windows Event Log port (issue #984).
//!
//! This leaf owns the only Event Log FFI in the repository:
//! `RegisterEventSourceW`, `ReportEventW`, and `DeregisterEventSource` from
//! the pinned `windows-sys` `Win32_System_EventLog` feature. Public callers
//! see a typed, bounded, local-only surface; raw handles, pointers, server
//! names, log names, and Win32 details never escape this module.
//!
//! Admitted profile (mirrors the #889 consumer contract in
//! `bins/eliot-host/src/windows_event_log.rs`):
//!
//! ```text
//! source:            EliotHost (fixed; no fallback, no substitution)
//! events:            100/service_start/information,
//!                    101/service_stop/information,
//!                    102/service_failure/error
//! insertions:        exactly one already-redacted string,
//!                    at most 1024 bytes and 1024 UTF-16 units, NUL-free
//! in-flight bound:   64 records (owned by the Host queue; informational here)
//! ```
//!
//! Local-only: the server name passed to `RegisterEventSourceW` is always
//! null (local machine). There is no remote-host, log-name, registry-path,
//! command, or credential parameter, so the Security log cannot be selected
//! and no other component can be impersonated.
//!
//! Blocking: the underlying Win32 calls are synchronous and may block. No
//! cancellable timeout is offered, and dropping a caller future does not
//! interrupt an in-flight OS call. At most the admitted finite work remains
//! in flight; uncertain delivery stays visible as [`EventLogError`] rather
//! than claimed success.
//!
//! Redaction: only already-redacted text crosses this port. Bounding limits
//! size, not sensitivity: callers must redact before calling, and obvious
//! protected markers (`password`, `secret`, `token`, `credential`, …) are
//! rejected before FFI. Error values never carry insertion contents.
//!
//! Registration: obtaining a source handle does not install an Event Log
//! source. `ReportEventW` acceptance is OS acceptance only, not proof of a
//! registered source, formatted-message availability, or downstream delivery.
//! The receipt therefore carries [`EventLogSourceAvailability::Unknown`];
//! a degraded Application fallback is never silently substituted for the
//! intended registered-source profile. Source provisioning belongs to the
//! approved installation policy, not to this writer.
//!
//! Non-goals: no logging framework, no remote collector, no lifecycle
//! authority, no queue (Host owns admission/drop/shutdown in #889), no
//! registry/SCM edits, no new thread or service.
//!
//! Normative anchors: Implementation I1.6 (Windows isolation boundary),
//! I13.11 (diagnostics carry bounded evidence, not raw dumps), I15.4
//! (secret values never reach logs), I7.20 (typed failure disposition).

use std::fmt;

use super::WindowsAdapterError;
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;

/// Fixed Event Log source for this port. The only admitted name.
pub const EVENT_LOG_SOURCE: &str = "EliotHost";

/// Bound for one redacted insertion string, in bytes.
pub const EVENT_LOG_MAX_INSERTION_BYTES: usize = 1024;

/// Bound for one redacted insertion string, in UTF-16 code units.
pub const EVENT_LOG_MAX_INSERTION_UTF16_UNITS: usize = 1024;

/// Exactly one insertion string is carried per report.
pub const EVENT_LOG_MAX_INSERTIONS: u16 = 1;

/// Admitted in-flight bound mirrored from the Host queue owner (#889).
/// Informational here: Host owns admission, drop counting, and shutdown.
pub const EVENT_LOG_QUEUE_CAPACITY: usize = 64;

/// Admitted event identifier for Host service start.
pub const EVENT_LOG_SERVICE_START_ID: u32 = 100;

/// Admitted event identifier for Host service stop.
pub const EVENT_LOG_SERVICE_STOP_ID: u32 = 101;

/// Admitted event identifier for Host service failure.
pub const EVENT_LOG_SERVICE_FAILURE_ID: u32 = 102;

/// Severity admitted for one Event Log record.
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

    /// Win32 report type value (`EVENTLOG_INFORMATION_TYPE` = 4,
    /// `EVENTLOG_ERROR_TYPE` = 1). Plain `u16`: no Win32 type escapes.
    const fn as_report_type(self) -> u16 {
        match self {
            Self::Information => 4,
            Self::Error => 1,
        }
    }
}

/// The only Host events admitted to the Event Log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmittedEventLogEvent {
    /// Host service start.
    ServiceStart,
    /// Host service stop.
    ServiceStop,
    /// Host service failure.
    ServiceFailure,
}

impl AdmittedEventLogEvent {
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
            Self::ServiceStart => EVENT_LOG_SERVICE_START_ID,
            Self::ServiceStop => EVENT_LOG_SERVICE_STOP_ID,
            Self::ServiceFailure => EVENT_LOG_SERVICE_FAILURE_ID,
        }
    }

    /// Fixed severity: start/stop are informational, failure is an error.
    #[must_use]
    pub const fn severity(self) -> EventLogSeverity {
        match self {
            Self::ServiceStart | Self::ServiceStop => EventLogSeverity::Information,
            Self::ServiceFailure => EventLogSeverity::Error,
        }
    }

    /// Classifies an event identifier without touching the OS.
    ///
    /// # Errors
    ///
    /// Returns [`EventLogError::InvalidInput`] for any unadmitted identifier.
    pub fn from_event_id(event_id: u32) -> Result<Self, EventLogError> {
        match event_id {
            EVENT_LOG_SERVICE_START_ID => Ok(Self::ServiceStart),
            EVENT_LOG_SERVICE_STOP_ID => Ok(Self::ServiceStop),
            EVENT_LOG_SERVICE_FAILURE_ID => Ok(Self::ServiceFailure),
            _ => Err(EventLogError::InvalidInput),
        }
    }
}

/// Typed failure for the local Event Log port.
///
/// Variants never carry insertion contents: bounding limits size, not
/// sensitivity, and diagnostics must stay free of redacted material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventLogError {
    /// Pre-FFI validation rejected the record (wrong profile, over-bound,
    /// NUL, or protected marker). Nothing reached the OS.
    InvalidInput,
    /// The OS port is reachable but currently unavailable.
    Unavailable,
    /// This port requires Windows. Never simulated success elsewhere.
    UnsupportedPlatform,
    /// `RegisterEventSourceW` refused the local handle; nothing was submitted.
    RegistrationFailed {
        /// Bounded Win32 error code; no message text.
        code: u32,
    },
    /// `ReportEventW` refused the validated record; OS acceptance unknown.
    ReportFailed {
        /// Bounded Win32 error code; no message text.
        code: u32,
    },
}

impl fmt::Display for EventLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => formatter.write_str("event log record failed pre-FFI validation"),
            Self::Unavailable => formatter.write_str("event log port unavailable"),
            Self::UnsupportedPlatform => formatter.write_str("event log port requires Windows"),
            Self::RegistrationFailed { code } => {
                write!(formatter, "event log source acquisition failed ({code})")
            }
            Self::ReportFailed { code } => {
                write!(formatter, "event log report failed ({code})")
            }
        }
    }
}

impl std::error::Error for EventLogError {}

impl From<EventLogError> for WindowsAdapterError {
    fn from(error: EventLogError) -> Self {
        match error {
            EventLogError::InvalidInput => Self::InvalidInput,
            EventLogError::Unavailable | EventLogError::UnsupportedPlatform => Self::Unavailable,
            EventLogError::RegistrationFailed { .. } | EventLogError::ReportFailed { .. } => {
                Self::Failed
            }
        }
    }
}

/// Source-registration knowledge attached to a receipt.
///
/// Kept separate from the submit disposition: OS acceptance never proves a
/// registered source or formatted-message availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventLogSourceAvailability {
    /// Acceptance is recorded; registration state is not claimed.
    /// A degraded Application fallback must be admitted explicitly by
    /// installation policy, never inferred here.
    Unknown,
}

/// Proof that the OS accepted one validated record.
///
/// OS acceptance only: not delivery, not registered-source proof, and not a
/// Host semantic result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventLogReceipt {
    event: AdmittedEventLogEvent,
    availability: EventLogSourceAvailability,
}

impl EventLogReceipt {
    const fn accepted(event: AdmittedEventLogEvent) -> Self {
        Self {
            event,
            availability: EventLogSourceAvailability::Unknown,
        }
    }

    /// The admitted event that was accepted.
    #[must_use]
    pub const fn event(&self) -> AdmittedEventLogEvent {
        self.event
    }

    /// The fixed event identifier that was reported.
    #[must_use]
    pub const fn event_id(&self) -> u32 {
        self.event.event_id()
    }

    /// The fixed severity that was reported.
    #[must_use]
    pub const fn severity(&self) -> EventLogSeverity {
        self.event.severity()
    }

    /// The fixed source the record was reported under.
    #[must_use]
    pub const fn source(&self) -> &'static str {
        EVENT_LOG_SOURCE
    }

    /// Registration knowledge for this acceptance (always unknown here).
    #[must_use]
    pub const fn source_availability(&self) -> EventLogSourceAvailability {
        self.availability
    }
}

/// Reports whether this build carries the live OS port.
#[must_use]
pub const fn is_event_log_supported() -> bool {
    cfg!(windows)
}

/// Substrings that mark text as not-redacted. Matching is ASCII
/// case-insensitive; any hit rejects the record before FFI.
const PROTECTED_MARKERS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "connectionstring",
    "connection_string",
    "privatekey",
    "private_key",
    "apikey",
    "api_key",
    "bearer",
    "authorization",
];

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle.iter())
            .all(|(left, right)| left.to_ascii_lowercase() == *right)
    })
}

fn contains_protected_marker(insertion: &str) -> bool {
    PROTECTED_MARKERS
        .iter()
        .any(|marker| contains_ascii_case_insensitive(insertion, marker))
}

/// Validates one insertion string without touching the OS.
///
/// Checks the byte bound, the UTF-16 bound, embedded NUL, and protected
/// markers. Validation failure means not-attempted, never submitted.
///
/// # Errors
///
/// Returns [`EventLogError::InvalidInput`] when any bound or redaction check
/// fails. Error values never echo the insertion.
pub fn validate_event_log_insertion(insertion: &str) -> Result<(), EventLogError> {
    if insertion.len() > EVENT_LOG_MAX_INSERTION_BYTES {
        return Err(EventLogError::InvalidInput);
    }
    if insertion.encode_utf16().count() > EVENT_LOG_MAX_INSERTION_UTF16_UNITS {
        return Err(EventLogError::InvalidInput);
    }
    if insertion.as_bytes().contains(&0) {
        return Err(EventLogError::InvalidInput);
    }
    if contains_protected_marker(insertion) {
        return Err(EventLogError::InvalidInput);
    }
    Ok(())
}

/// Reports one admitted event with one redacted insertion to the local
/// Event Log under the fixed `EliotHost` source.
///
/// This call is synchronous and may block; there is no timeout, and
/// abandoning the caller does not interrupt the OS work. The returned
/// receipt proves OS acceptance only.
///
/// # Errors
///
/// Returns [`EventLogError::InvalidInput`] before any FFI when the profile,
/// bounds, or redaction checks fail; [`EventLogError::UnsupportedPlatform`]
/// off Windows; [`EventLogError::RegistrationFailed`] when no handle could
/// be acquired (nothing submitted); [`EventLogError::ReportFailed`] when the
/// OS refused the validated record.
pub fn report_local_event(
    event: AdmittedEventLogEvent,
    insertion: &str,
) -> Result<EventLogReceipt, EventLogError> {
    validate_event_log_insertion(insertion)?;
    submit_validated(event, insertion)
}

#[cfg(windows)]
fn encode_wide_nul(text: &str) -> Result<Vec<u16>, EventLogError> {
    if text.as_bytes().contains(&0) {
        return Err(EventLogError::InvalidInput);
    }
    let mut wide: Vec<u16> = text.encode_utf16().collect();
    if wide.len() > EVENT_LOG_MAX_INSERTION_UTF16_UNITS {
        return Err(EventLogError::InvalidInput);
    }
    wide.push(0);
    Ok(wide)
}

/// RAII owner for one `RegisterEventSourceW` handle.
///
/// Deregisters with `DeregisterEventSource` exactly once on drop, including
/// error paths in the reporting scope. The handle is never copied or
/// exposed, so release cannot double-fire or leak.
#[cfg(windows)]
struct RegisteredEventSource {
    handle: HANDLE,
}

#[cfg(windows)]
impl RegisteredEventSource {
    fn register_local(source_wide: &[u16]) -> Result<Self, EventLogError> {
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::System::EventLog::RegisterEventSourceW;

        let handle: HANDLE = unsafe {
            // SAFETY: a null server selects the local machine; `source_wide`
            // is a live NUL-terminated UTF-16 buffer retained by the caller
            // for the call; the returned handle is checked for null below.
            RegisterEventSourceW(std::ptr::null(), source_wide.as_ptr())
        };
        if handle.is_null() {
            let code = unsafe {
                // SAFETY: `GetLastError` is called immediately on this thread
                // after the failed `RegisterEventSourceW`; it takes no
                // pointers and owns no resources.
                GetLastError()
            };
            Err(EventLogError::RegistrationFailed { code })
        } else {
            Ok(Self { handle })
        }
    }
}

#[cfg(windows)]
impl Drop for RegisteredEventSource {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            use windows_sys::Win32::System::EventLog::DeregisterEventSource;

            unsafe {
                // SAFETY: the handle came from a successful
                // `RegisterEventSourceW`, is deregistered exactly once here,
                // and is never copied or used afterwards; `Drop` runs once,
                // and the ignored result cannot leak because the OS owns
                // handle lifetime after this call.
                DeregisterEventSource(self.handle);
            }
        }
    }
}

#[cfg(windows)]
fn report_validated(
    handle: HANDLE,
    event: AdmittedEventLogEvent,
    insertion_wide: &[u16],
) -> Result<(), EventLogError> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::EventLog::ReportEventW;

    let strings = [insertion_wide.as_ptr()];
    let string_count = u16::try_from(strings.len()).map_err(|_| EventLogError::InvalidInput)?;
    if string_count != EVENT_LOG_MAX_INSERTIONS {
        return Err(EventLogError::InvalidInput);
    }
    let accepted = unsafe {
        // SAFETY: `handle` is a live registered source owned by the caller
        // scope; severity/category/identifier are validated admitted values;
        // `strings` is a live one-element array of pointers to live
        // NUL-terminated UTF-16 retained for the call; SID and raw data are
        // null with zero sizes, so no other buffer is read.
        ReportEventW(
            handle,
            event.severity().as_report_type(),
            0,
            event.event_id(),
            std::ptr::null_mut(),
            string_count,
            0,
            strings.as_ptr(),
            std::ptr::null(),
        )
    };
    if accepted == 0 {
        let code = unsafe {
            // SAFETY: `GetLastError` is called immediately on this thread
            // after the failed `ReportEventW`; it takes no pointers and owns
            // no resources.
            GetLastError()
        };
        Err(EventLogError::ReportFailed { code })
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn submit_validated(
    event: AdmittedEventLogEvent,
    insertion: &str,
) -> Result<EventLogReceipt, EventLogError> {
    let source_wide = encode_wide_nul(EVENT_LOG_SOURCE)?;
    let insertion_wide = encode_wide_nul(insertion)?;
    let source = RegisteredEventSource::register_local(&source_wide)?;
    report_validated(source.handle, event, &insertion_wide)?;
    Ok(EventLogReceipt::accepted(event))
}

#[cfg(not(windows))]
fn submit_validated(
    event: AdmittedEventLogEvent,
    insertion: &str,
) -> Result<EventLogReceipt, EventLogError> {
    let _ = (event, insertion);
    Err(EventLogError::UnsupportedPlatform)
}
