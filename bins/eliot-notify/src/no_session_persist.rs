//! Best-effort no-session / control-loss persistence for `eliot-notify`.
//!
//! Normative anchors (issue #1781): I11.6:13-14 (no toast is promised without
//! an interactive session; the Event Log / spool record persists instead),
//! I11.6:19 (adapter loss degrades delivery only), I11.7:7-8 (a suppressed
//! delivery never resolves its item).
//!
//! [`record_no_session`] is called from the fail-closed no-session branches of
//! the Watchdog fallback composition (`register`, `activate`, `load`). It
//! never claims a toast, never resolves an item, and never echoes payloads,
//! identities, or secrets: every persisted value is a fixed code.
//!
//! The Windows Event Log write reuses the already-used repository facility
//! ([`eliot_platform_windows::report_local_event`]); no new `winapi` or
//! `eventlog` dependency is introduced. The spool write reuses the existing
//! fallback-ledger store (`crate::FALLBACK_LEDGER_RELATIVE`) through the same
//! protected-path lease and atomic-publication primitives as the composition
//! root, inserting a schema-compatible marker entry. Both attempts are a
//! single best-effort pass with no retry: failure is reported in the outcome,
//! never escalated, and the caller's existing error variant is preserved.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_platform::WorkScopePath;
use eliot_platform_windows::{
    AdmittedEventLogEvent, ProtectedPathLease, WindowsPlatform, protected_program_data_path,
    report_local_event,
};
use serde_json::Value;

/// Delivery-degradation code recorded when the no-session marker durably
/// persists. Delivery is degraded; the item stays unresolved.
const DELIVERY_SUPPRESSED_NO_SESSION: &str = "DELIVERY_SUPPRESSED_NO_SESSION";
/// Code recorded when the Event Log write is deferred but the spool marker
/// persists. Delivery is still suppressed; nothing is resolved.
const EVENTLOG_DEFERRED: &str = "EVENTLOG_DEFERRED";
/// Fail-closed code recorded when even the spool marker cannot persist.
/// Delivery is still suppressed; nothing is resolved.
const DELIVERY_SUPPRESSED_SPOOL_UNAVAILABLE: &str = "DELIVERY_SUPPRESSED_SPOOL_UNAVAILABLE";

/// Fixed, already-redacted Event Log insertion. It carries codes only and
/// never echoes request payloads, identities, or secrets, so it passes the
/// Event Log port's pre-FFI redaction screen.
const NO_SESSION_EVENT_INSERTION: &str =
    "eliot-notify: no interactive session; delivery suppressed; item unresolved";

/// Scope file published by [`WindowsPlatform::publish_atomic`], matching the
/// fallback-ledger scope used by the composition root.
const LEDGER_SCOPE_FILE: &str = "watchdog-ledger.json";

/// Work-root contour that owns the fallback ledger, matching the composition
/// root's installer-owned notification contour.
const NOTIFY_WORK_CONTOUR: &str = "Eliot/notify";

/// Outcome of one best-effort no-session persistence attempt.
///
/// Every field is fail-closed: `claimed_toast` is always `false`, and
/// `reason_code` is always a delivery-degradation code, never a
/// success or resolution claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoSessionOutcome {
    /// Always `false`: no toast is ever claimed on the no-session path.
    pub claimed_toast: bool,
    /// Whether the best-effort Windows Event Log write was OS-accepted.
    pub event_logged: bool,
    /// Whether the canonical no-session marker read back from the spool.
    pub spool_persisted: bool,
    /// Fail-closed disposition code: [`DELIVERY_SUPPRESSED_NO_SESSION`],
    /// [`EVENTLOG_DEFERRED`], or [`DELIVERY_SUPPRESSED_SPOOL_UNAVAILABLE`].
    pub reason_code: &'static str,
}

/// Records one no-session / control-loss observation without claiming a toast
/// and without resolving any item.
///
/// `condition` is mapped to a fixed code; any other value (including secrets
/// or payload text a caller might pass) is replaced by
/// `unknown-no-session` and never persisted. Both the Event Log write and the
/// spool append are best-effort: their dispositions are reported in the
/// returned outcome and the caller keeps its existing error variant.
#[must_use]
pub fn record_no_session(condition: &str) -> NoSessionOutcome {
    let condition_code = classify_condition(condition);
    let event_logged = report_local_event(
        AdmittedEventLogEvent::ServiceFailure,
        NO_SESSION_EVENT_INSERTION,
    )
    .is_ok();
    let spool_persisted = append_no_session_marker(condition_code);
    let reason_code = if spool_persisted {
        if event_logged {
            DELIVERY_SUPPRESSED_NO_SESSION
        } else {
            EVENTLOG_DEFERRED
        }
    } else {
        DELIVERY_SUPPRESSED_SPOOL_UNAVAILABLE
    };
    NoSessionOutcome {
        claimed_toast: false,
        event_logged,
        spool_persisted,
        reason_code,
    }
}

/// Maps a caller-supplied condition to a fixed code. Unknown input (and any
/// embedded payload or secret text) is never echoed into a persisted record.
fn classify_condition(condition: &str) -> &'static str {
    match condition {
        "register:no-session" => "register:no-session",
        "activate:no-session" => "activate:no-session",
        "load:no-session" => "load:no-session",
        _ => "unknown-no-session",
    }
}

/// Durable marker key for one no-session observation. The `no-session/`
/// prefix keeps the marker disjoint from every one-shot reservation key, so
/// the canonical upsert-before-attempt ordering is preserved and no item can
/// resolve through this record.
fn no_session_key(condition_code: &'static str) -> String {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    format!("no-session/{condition_code}/{now_ms}")
}

/// Reads the protected fallback ledger through a verified lease. Returns
/// `None` on any failure; the caller treats that as spool-unavailable.
fn read_ledger_bytes(relative: &PathBuf) -> Option<Vec<u8>> {
    let lease = ProtectedPathLease::open_or_create(relative).ok()?;
    lease.verify_stable_identity().ok()?;
    lease.verify_path_identity().ok()?;
    lease.read_bounded(crate::FALLBACK_BYTES_LIMIT).ok()
}

/// Decodes the ledger snapshot, accepting an empty file as the default
/// snapshot. Corrupt bytes decode to `None` so a damaged spool is never
/// clobbered by a diagnostic marker.
fn parse_ledger_snapshot(previous_bytes: &[u8]) -> Option<Value> {
    if previous_bytes.is_empty() {
        return Some(serde_json::json!({
            "entries": {},
            "reservations": {},
            "next_reservation": 0,
            "poisoned_keys": [],
        }));
    }
    serde_json::from_slice(previous_bytes).ok()
}

/// Publishes the desired ledger bytes through the same atomic-publication
/// primitive as the composition root. The caller always verifies by
/// readback; this result only reports the publication attempt.
fn publish_ledger_bytes(desired: &[u8]) -> Result<(), ()> {
    let root = protected_program_data_path(NOTIFY_WORK_CONTOUR).map_err(|_| ())?;
    let platform = WindowsPlatform::new(root).map_err(|_| ())?;
    let scope = WorkScopePath::new(LEDGER_SCOPE_FILE).map_err(|_| ())?;
    platform
        .publish_atomic(&scope, desired)
        .map(|_| ())
        .map_err(|_| ())
}

/// Appends one canonical no-session marker to the existing fallback ledger.
///
/// The marker is a schema-compatible `entries` record whose
/// `claim_digest` carries the delivery-degradation code and whose
/// `observation` stays `null`, plus a durable `poisoned_keys` entry so the
/// marker can never be treated as a retryable reservation. Reservation
/// counters, existing entries, and existing reservations are preserved.
/// A compare-and-swap guard aborts when another writer moved the ledger, and
/// an exact readback decides persistence. Any failure returns `false`.
fn append_no_session_marker(condition_code: &'static str) -> bool {
    let relative = PathBuf::from(crate::FALLBACK_LEDGER_RELATIVE);
    let Some(previous_bytes) = read_ledger_bytes(&relative) else {
        return false;
    };
    let Some(mut snapshot) = parse_ledger_snapshot(&previous_bytes) else {
        return false;
    };
    let key = no_session_key(condition_code);
    {
        let Some(entries) = snapshot.get_mut("entries").and_then(Value::as_object_mut) else {
            return false;
        };
        let mut record = serde_json::Map::new();
        record.insert(
            String::from("claim_digest"),
            Value::String(String::from(DELIVERY_SUPPRESSED_NO_SESSION)),
        );
        record.insert(String::from("observation"), Value::Null);
        entries.insert(key.clone(), Value::Object(record));
    }
    if let Some(poisoned) = snapshot
        .get_mut("poisoned_keys")
        .and_then(Value::as_array_mut)
        && !poisoned
            .iter()
            .any(|existing| existing.as_str() == Some(key.as_str()))
    {
        poisoned.push(Value::String(key.clone()));
    }
    let Ok(desired) = serde_json::to_vec(&snapshot) else {
        return false;
    };
    let Ok(limit) = usize::try_from(crate::FALLBACK_BYTES_LIMIT) else {
        return false;
    };
    if desired.len() > limit {
        return false;
    }
    // Another writer may have moved the ledger since the first read; abort
    // rather than clobber canonical state.
    if read_ledger_bytes(&relative) != Some(previous_bytes) {
        return false;
    }
    let _ = publish_ledger_bytes(&desired);
    // The readback is the arbiter: it also reconciles a lost publication
    // response without ever claiming persistence that is not durable.
    read_ledger_bytes(&relative) == Some(desired)
}
