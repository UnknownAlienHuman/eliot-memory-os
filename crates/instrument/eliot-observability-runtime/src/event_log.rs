//! Windows Event Log startup/recovery surface for the `system_service`
//! profile (I16.2).
//!
//! The Event Log FFI stays in `eliot-platform-windows`; this module owns the
//! profile rule and the admitted event vocabulary, and it never acquires a
//! handle, registers a source, or edits the registry. A record is attempted
//! through the safe port and the outcome is reported honestly: OS acceptance is
//! not registered-source proof and not downstream delivery, so the receipt
//! never claims more than acceptance.

use eliot_platform_windows::{
    AdmittedEventLogEvent, EventLogError, is_event_log_supported, report_local_event,
};

use crate::critical_path::{CriticalEventRecord, SinkStatus, UnavailableReason};

/// Host/Kernel lifecycle events admitted to the Windows Event Log.
///
/// I16.2 names startup and recovery for the `system_service` profile; I16.4
/// requires process start, restart, and restart-intensity exhaustion to be
/// visible. Nothing else is admitted here, and no other observation is
/// silently routed into the Event Log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemServiceEvent {
    /// The service process started.
    ServiceStart,
    /// The service process stopped.
    ServiceStop,
    /// The service process crashed.
    Crash,
    /// A supervised restart was performed.
    Restart,
    /// Restart intensity is exhausted and the unit is quarantined.
    RestartExhausted,
}

impl SystemServiceEvent {
    /// Stable event name carried in a bounded diagnostic record.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceStart => "service_start",
            Self::ServiceStop => "service_stop",
            Self::Crash => "crash",
            Self::Restart => "restart",
            Self::RestartExhausted => "restart_exhausted",
        }
    }

    /// Maps onto the fixed Event Log profile owned by the safe port.
    fn platform_event(self) -> AdmittedEventLogEvent {
        match self {
            Self::ServiceStart | Self::Restart => AdmittedEventLogEvent::ServiceStart,
            Self::ServiceStop => AdmittedEventLogEvent::ServiceStop,
            Self::Crash | Self::RestartExhausted => AdmittedEventLogEvent::ServiceFailure,
        }
    }
}

/// Honest Event Log disposition. Absence stays missing: an unavailable port is
/// never faked through another sink (I16.11).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventLogOutcome {
    /// The OS accepted the record. This is acceptance only: it is not proof of
    /// a registered source, formatted-message availability, or downstream
    /// delivery.
    Accepted,
    /// This build carries no live Event Log port (non-Windows).
    UnsupportedPlatform,
    /// The insertion failed pre-FFI validation; nothing was submitted.
    Rejected,
    /// The port is present but the source or the report was refused.
    Refused {
        /// Stable refusal reason, never message text or insertion contents.
        reason: &'static str,
    },
}

impl EventLogOutcome {
    /// Stable outcome name for a bounded diagnostic record.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::Rejected => "rejected",
            Self::Refused { reason } => reason,
        }
    }
}

/// Last-resort Event Log sink for the I16.11 third stage.
///
/// Constructed only for the `system_service` profile; `user_mode` and portable
/// installations use the protected event spool instead.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EventLogReport;

impl EventLogReport {
    /// Reports one admitted event with one already-redacted insertion.
    ///
    /// `Ok` carries the accepted outcomes and `Err` carries the non-accepted
    /// ones, so the return type itself keeps acceptance and refusal apart.
    ///
    /// # Errors
    ///
    /// Returns [`EventLogOutcome::Rejected`] when the insertion fails the
    /// port's pre-FFI bound or redaction check, and
    /// [`EventLogOutcome::UnsupportedPlatform`] off Windows. A refused source
    /// or report returns the matching [`EventLogOutcome::Refused`] reason. No
    /// outcome is ever fabricated.
    pub fn report(
        &self,
        event: SystemServiceEvent,
        insertion: &str,
    ) -> Result<EventLogOutcome, EventLogOutcome> {
        if !is_event_log_supported() {
            return Err(EventLogOutcome::UnsupportedPlatform);
        }
        match report_local_event(event.platform_event(), insertion) {
            Ok(_) => Ok(EventLogOutcome::Accepted),
            Err(EventLogError::InvalidInput) => Err(EventLogOutcome::Rejected),
            Err(EventLogError::UnsupportedPlatform) => Err(EventLogOutcome::UnsupportedPlatform),
            Err(EventLogError::Unavailable) => Err(EventLogOutcome::Refused {
                reason: "event_log_unavailable",
            }),
            Err(EventLogError::RegistrationFailed { .. }) => Err(EventLogOutcome::Refused {
                reason: "event_log_source_unavailable",
            }),
            Err(EventLogError::ReportFailed { .. }) => Err(EventLogOutcome::Refused {
                reason: "event_log_report_refused",
            }),
        }
    }

    /// Writes one critical record to the last-resort Event Log stage.
    ///
    /// The insertion is rebuilt from the record's own bounded fields, so an
    /// arbitrary payload can never reach the OS insertion string.
    pub fn write(&self, record: &CriticalEventRecord) -> SinkStatus {
        let insertion = format!(
            "event={} profile={} detail={}",
            record.event, record.profile, record.detail
        );
        match self.report(event_for(&record.event), &insertion) {
            Ok(EventLogOutcome::Accepted) => SinkStatus::Delivered,
            Ok(outcome) | Err(outcome) => SinkStatus::Unavailable(outcome.unavailable_reason()),
        }
    }
}

impl EventLogOutcome {
    /// Projects the outcome onto the I16.11 chain's typed reason.
    ///
    /// A pre-FFI rejection is `NotApplicable` because the record was never
    /// offered to the OS; every other non-accepted outcome is `Unavailable`.
    fn unavailable_reason(self) -> UnavailableReason {
        match self {
            Self::Accepted | Self::Refused { .. } | Self::UnsupportedPlatform => {
                UnavailableReason::Unavailable
            }
            Self::Rejected => UnavailableReason::NotApplicable,
        }
    }
}

fn event_for(name: &str) -> SystemServiceEvent {
    match name {
        "service_stop" | "quiesce" | "stop" => SystemServiceEvent::ServiceStop,
        "crash" | "restart" | "restart_exhausted" | "quarantine" => SystemServiceEvent::Crash,
        _ => SystemServiceEvent::ServiceStart,
    }
}
