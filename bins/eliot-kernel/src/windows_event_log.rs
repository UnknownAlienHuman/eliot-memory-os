//! Bounded asynchronous producer for the admitted Kernel Event Log profile.
//!
//! Admission is a capacity-64 nonblocking queue with one process-lifetime
//! worker. Only the worker calls the synchronous platform port; a queued
//! record means pending admission, never OS acceptance. The platform receipt
//! reports OS acceptance only and keeps source availability unknown. Source
//! provisioning remains an installer/Host policy.

use std::sync::OnceLock;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread;

use eliot_platform_windows::{
    AdmittedKernelEventLogEvent, EVENT_LOG_QUEUE_CAPACITY, EventLogError,
    EventLogSourceAvailability, report_kernel_event, validate_event_log_insertion,
};

use crate::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};

struct QueuedKernelEvent {
    event: AdmittedKernelEventLogEvent,
    insertion: String,
}

static EVENT_LOG_QUEUE: OnceLock<Result<SyncSender<QueuedKernelEvent>, ()>> = OnceLock::new();

/// Admission result for one fixed Kernel event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventLogAdmission {
    /// The event is queued and pending worker-side OS reporting.
    Pending,
    /// This runtime did not start the SystemService-only queue.
    NotApplicable,
    /// The bounded queue had no capacity at admission time.
    QueueFull,
    /// The worker could not be started or its receiver is unavailable.
    WorkerUnavailable,
    /// The protected insertion failed pre-FFI validation.
    Rejected,
}

impl EventLogAdmission {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::NotApplicable => "not_applicable",
            Self::QueueFull => "queue_full",
            Self::WorkerUnavailable => "worker_unavailable",
            Self::Rejected => "rejected",
        }
    }
}

/// Starts the single worker and admits the startup event after the entrypoint
/// has validated both the `SystemService` binding and `ProgramData` contour.
///
/// The event means that the Kernel entered startup. It does not mean the
/// service is ready or that the OS accepted the record.
pub fn start_and_enqueue_startup() -> EventLogAdmission {
    let Some(sender) = initialize_worker() else {
        return report_admission(
            AdmittedKernelEventLogEvent::Startup,
            EventLogAdmission::WorkerUnavailable,
        );
    };
    let admission = enqueue(
        sender,
        AdmittedKernelEventLogEvent::Startup,
        "event=kernel_startup phase=entered_startup".to_owned(),
    );
    report_admission(AdmittedKernelEventLogEvent::Startup, admission)
}

/// Admits one event from the original typed process/audit draft.
///
/// Only these already-present lineage references are eligible. The draft body,
/// audit append result, current owner state, and failure text never cross this
/// boundary.
pub(crate) fn enqueue_audit_event(
    event: AdmittedKernelEventLogEvent,
    operation_id: Option<&str>,
    module_generation: Option<&str>,
    authority_epoch: Option<&str>,
) -> EventLogAdmission {
    let insertion = audit_insertion(event, operation_id, module_generation, authority_epoch);
    let admission = match existing_worker_sender() {
        Some(sender) => enqueue(sender, event, insertion),
        None if matches!(EVENT_LOG_QUEUE.get(), Some(Err(()))) => {
            EventLogAdmission::WorkerUnavailable
        }
        None => EventLogAdmission::NotApplicable,
    };
    report_admission(event, admission)
}

/// Whether queue initialization succeeded. This is not proof that the worker
/// remains live or that any event reached the OS.
pub(crate) fn queue_initialized() -> bool {
    matches!(EVENT_LOG_QUEUE.get(), Some(Ok(_)))
}

fn initialize_worker() -> Option<&'static SyncSender<QueuedKernelEvent>> {
    EVENT_LOG_QUEUE
        .get_or_init(|| {
            let (sender, receiver) = sync_channel(EVENT_LOG_QUEUE_CAPACITY);
            thread::Builder::new()
                .name("eliot-kernel-event-log".to_owned())
                .spawn(move || report_worker(&receiver))
                .map_err(|_| ())?;
            Ok(sender)
        })
        .as_ref()
        .ok()
}

fn existing_worker_sender() -> Option<&'static SyncSender<QueuedKernelEvent>> {
    EVENT_LOG_QUEUE.get()?.as_ref().ok()
}

fn enqueue(
    sender: &SyncSender<QueuedKernelEvent>,
    event: AdmittedKernelEventLogEvent,
    insertion: String,
) -> EventLogAdmission {
    if validate_event_log_insertion(&insertion).is_err() {
        return EventLogAdmission::Rejected;
    }
    match sender.try_send(QueuedKernelEvent { event, insertion }) {
        Ok(()) => EventLogAdmission::Pending,
        Err(TrySendError::Full(_)) => EventLogAdmission::QueueFull,
        Err(TrySendError::Disconnected(_)) => EventLogAdmission::WorkerUnavailable,
    }
}

fn audit_insertion(
    event: AdmittedKernelEventLogEvent,
    operation_id: Option<&str>,
    module_generation: Option<&str>,
    authority_epoch: Option<&str>,
) -> String {
    let mut insertion = format!("event={}", event.as_str());
    append_reference(&mut insertion, "operation_id", operation_id);
    append_reference(&mut insertion, "module_generation", module_generation);
    append_reference(&mut insertion, "authority_epoch", authority_epoch);
    insertion
}

fn append_reference(insertion: &mut String, name: &str, value: Option<&str>) {
    let Some(value) = value else {
        return;
    };
    let bounded = bound_field(value);
    let value = bounded.text();
    if value.is_empty() || !value.bytes().all(is_safe_reference_byte) {
        return;
    }
    insertion.push(' ');
    insertion.push_str(name);
    insertion.push('=');
    insertion.push_str(value);
}

fn is_safe_reference_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.')
}

fn report_admission(
    event: AdmittedKernelEventLogEvent,
    admission: EventLogAdmission,
) -> EventLogAdmission {
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = "kernel.event_log_admission",
        event_kind = event.as_str(),
        admission = admission.as_str(),
        "Kernel Event Log queue admission recorded; pending is not OS acceptance"
    );
    admission
}

fn report_worker(receiver: &Receiver<QueuedKernelEvent>) {
    while let Ok(record) = receiver.recv() {
        match report_kernel_event(record.event, &record.insertion) {
            Ok(receipt) => {
                let source_availability = match receipt.source_availability() {
                    EventLogSourceAvailability::Unknown => "unknown",
                };
                tracing::info!(
                    target: KERNEL_DIAGNOSTICS_TARGET,
                    event = "kernel.event_log_delivery",
                    event_kind = receipt.event().as_str(),
                    event_id = receipt.event_id(),
                    source = receipt.source(),
                    source_availability,
                    outcome = "os_accepted",
                    downstream_delivery = "unknown",
                    "Kernel Event Log report received OS acceptance"
                );
            }
            Err(error) => report_worker_failure(record.event, error),
        }
    }
}

fn report_worker_failure(event: AdmittedKernelEventLogEvent, error: EventLogError) {
    let outcome = match error {
        EventLogError::InvalidInput => "invalid_input",
        EventLogError::Unavailable => "unavailable",
        EventLogError::UnsupportedPlatform => "unsupported_platform",
        EventLogError::RegistrationFailed { .. } => "source_handle_unavailable",
        EventLogError::ReportFailed { .. } => "report_refused",
    };
    tracing::warn!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = "kernel.event_log_delivery",
        event_kind = event.as_str(),
        outcome,
        source_availability = "unknown",
        "Kernel Event Log report was not confirmed as OS accepted"
    );
}
