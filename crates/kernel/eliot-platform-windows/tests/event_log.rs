//! Focused port proofs for issue #984.
//!
//! Port existence and typed surface, bounded/redacted pre-FFI behavior, the
//! fail-closed typed-unavailable path, and the frozen admitted-profile
//! fixture. Host queue consumption belongs to #889, not this file.

use eliot_platform_windows::{
    AdmittedEventLogEvent, EVENT_LOG_MAX_INSERTION_BYTES, EVENT_LOG_QUEUE_CAPACITY,
    EVENT_LOG_SOURCE, EventLogError, EventLogSourceAvailability, is_event_log_supported,
    report_local_event, validate_event_log_insertion,
};

const FIXTURE: &str = include_str!("data/event-log/admitted-profile.json");

#[test]
fn port_surface_exposes_only_the_typed_local_profile() -> Result<(), String> {
    if EVENT_LOG_SOURCE != "EliotHost" {
        return Err("source must stay EliotHost".to_string());
    }
    if EVENT_LOG_MAX_INSERTION_BYTES != 1024 || EVENT_LOG_QUEUE_CAPACITY != 64 {
        return Err("bounds must stay 1024B/64".to_string());
    }
    let mapping = [
        (AdmittedEventLogEvent::ServiceStart, 100_u32, "information"),
        (AdmittedEventLogEvent::ServiceStop, 101_u32, "information"),
        (AdmittedEventLogEvent::ServiceFailure, 102_u32, "error"),
    ];
    for (event, id, severity) in mapping {
        if event.event_id() != id || event.severity().as_str() != severity {
            return Err("event/severity mapping drifted".to_string());
        }
        if AdmittedEventLogEvent::from_event_id(id).map_err(|e| format!("{e}"))? != event {
            return Err("event id round-trip failed".to_string());
        }
    }
    if AdmittedEventLogEvent::from_event_id(999).is_ok() {
        return Err("unknown event id must be rejected".to_string());
    }
    Ok(())
}

#[test]
fn bounds_and_redaction_rejected_before_ffi() -> Result<(), String> {
    let one_over = "a".repeat(EVENT_LOG_MAX_INSERTION_BYTES + 1);
    let boundary = "a".repeat(EVENT_LOG_MAX_INSERTION_BYTES);
    for bad in [
        one_over.as_str(),
        "before\0after",
        "restarted with password=hunter2",
        "token abc123 rotated",
        "leaked SECRET value",
    ] {
        let error = match validate_event_log_insertion(bad) {
            Ok(()) => return Err("over-bound/NUL/protected insertion must fail".to_string()),
            Err(error) => error,
        };
        if error != EventLogError::InvalidInput || format!("{error}").contains("hunter2") {
            return Err("rejection must be InvalidInput without content".to_string());
        }
    }
    validate_event_log_insertion(boundary.as_str())
        .map_err(|_| "exact-bound insertion must validate".to_string())?;
    validate_event_log_insertion("").map_err(|_| "empty insertion must validate".to_string())
}

#[test]
fn unavailable_path_is_fail_closed_without_content() -> Result<(), String> {
    if is_event_log_supported() != cfg!(windows) {
        return Err("support flag must match the Windows build".to_string());
    }
    let probe = "probe-984-redacted-boundary-ok";
    match report_local_event(AdmittedEventLogEvent::ServiceStart, probe) {
        Ok(receipt) => {
            if !cfg!(windows) {
                return Err("non-Windows must never report success".to_string());
            }
            if receipt.event_id() != 100
                || receipt.source() != EVENT_LOG_SOURCE
                || receipt.source_availability() != EventLogSourceAvailability::Unknown
            {
                return Err("receipt must carry the admitted mapping".to_string());
            }
        }
        Err(EventLogError::UnsupportedPlatform) => {
            if cfg!(windows) {
                return Err("Windows must attempt the OS port".to_string());
            }
        }
        Err(
            EventLogError::RegistrationFailed { .. }
            | EventLogError::ReportFailed { .. }
            | EventLogError::Unavailable,
        ) => {
            if !cfg!(windows) {
                return Err("non-Windows must report UnsupportedPlatform".to_string());
            }
        }
        Err(EventLogError::InvalidInput) => {
            return Err("valid probe must not fail validation".to_string());
        }
    }
    Ok(())
}

#[test]
fn frozen_fixture_matches_the_port() -> Result<(), String> {
    let profile: serde_json::Value =
        serde_json::from_str(FIXTURE).map_err(|e| format!("fixture must parse: {e}"))?;
    let get = |key: &str| {
        profile
            .get(key)
            .ok_or_else(|| format!("fixture missing {key}"))
    };
    if get("source")?.as_str() != Some(EVENT_LOG_SOURCE) {
        return Err("fixture source drifted".to_string());
    }
    if get("max_insertion_bytes")?.as_u64() != Some(1024)
        || get("queue_capacity")?.as_u64() != Some(64)
    {
        return Err("fixture bounds drifted".to_string());
    }
    let events = get("events")?
        .as_array()
        .ok_or_else(|| "fixture events must be an array".to_string())?;
    if events.len() != 3 {
        return Err("fixture must admit exactly three events".to_string());
    }
    Ok(())
}
