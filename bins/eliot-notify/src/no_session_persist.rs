//! Best-effort no-session / control-loss persistence for `eliot-notify`.
//!
//! Normative anchors (issue #1781): I11.6:13-14 (no toast is promised without
//! an interactive session; the Event Log / spool record persists instead),
//! I11.6:19 (adapter loss degrades delivery only), I11.7:7-8 (a suppressed
//! delivery never resolves its item).
//!
//! [`record_no_session`] is called from four production contours, all of them
//! real delivery outcomes rather than identity-lookup failures:
//!
//! - the fail-closed no-session branches of the Watchdog fallback composition
//!   (`register`, `activate`, `load`);
//! - the normal and fallback delivery contours of
//!   [`crate::NotificationComposition`], whenever the adapter returned no
//!   observed OS acceptance (a missing interactive session, an unavailable
//!   adapter, or a provider failure);
//! - the two quiet-hours contours of that same composition, where the session
//!   was present and the policy decided not to pop up
//!   (`deliver:quiet-hours-suppressed`) or refused the request before any
//!   delivery attempt (`deliver:quiet-hours-rejected`). These record their own
//!   codes and their own Event Log sentence, so a policy decision is never
//!   persisted as a lost session.
//!
//! It never claims a toast, never resolves an item, and never echoes payloads,
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
//! [`spool_obligation_available`] reads the marker back so the surviving
//! obligation is observable rather than assumed.

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
/// Delivery-degradation code carried by a spool marker whose condition is a
/// canonical quiet-hours policy decision rather than a session loss. The
/// session was present and the adapter was reached; the policy withheld the
/// popup, so the marker must not claim a missing session. The persistent
/// canonical item stays on the board either way (I11.7:7,23).
const DELIVERY_SUPPRESSED_QUIET_HOURS: &str = "DELIVERY_SUPPRESSED_QUIET_HOURS";
/// Code recorded when the Event Log write is deferred but the spool marker
/// persists. Delivery is still suppressed; nothing is resolved.
const EVENTLOG_DEFERRED: &str = "EVENTLOG_DEFERRED";
/// Fail-closed code recorded when even the spool marker cannot persist.
/// Delivery is still suppressed; nothing is resolved.
const DELIVERY_SUPPRESSED_SPOOL_UNAVAILABLE: &str = "DELIVERY_SUPPRESSED_SPOOL_UNAVAILABLE";

/// Fixed, already-redacted Event Log insertion for a missing interactive
/// session. It carries codes only and never echoes request payloads,
/// identities, or secrets, so it passes the Event Log port's pre-FFI
/// redaction screen.
const NO_SESSION_EVENT_INSERTION: &str =
    "eliot-notify: no interactive session; delivery suppressed; item unresolved";

/// Fixed, already-redacted Event Log insertion for a canonical quiet-hours
/// policy decision. It is deliberately a *different* sentence from
/// [`NO_SESSION_EVENT_INSERTION`]: the session existed and the adapter was
/// reached, so an operator reading the log must not be told the session was
/// missing. Codes only, no payload, identities, or secrets.
const QUIET_HOURS_EVENT_INSERTION: &str =
    "eliot-notify: quiet-hours policy suppressed delivery; item unresolved";

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
        event_insertion(condition_code),
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

/// The fixed, already-redacted Event Log sentence for one classified condition.
///
/// A quiet-hours policy decision gets its own sentence: the interactive
/// session was present and the adapter was reached, so logging the no-session
/// sentence would misreport a policy decision as a lost session. Both
/// sentences are module constants — no caller text, payload, identity, or
/// secret can reach the Event Log through this seam.
fn event_insertion(condition_code: &str) -> &'static str {
    if is_quiet_hours_condition(condition_code) {
        QUIET_HOURS_EVENT_INSERTION
    } else {
        NO_SESSION_EVENT_INSERTION
    }
}

/// The delivery-degradation code a spool marker carries for one condition.
///
/// The marker is a durable operator-facing record, so it names the same class
/// of condition as the Event Log sentence: a quiet-hours policy decision is
/// never recorded as a no-session delivery.
fn marker_disposition(condition_code: &str) -> &'static str {
    if is_quiet_hours_condition(condition_code) {
        DELIVERY_SUPPRESSED_QUIET_HOURS
    } else {
        DELIVERY_SUPPRESSED_NO_SESSION
    }
}

/// Whether one classified condition is a canonical quiet-hours policy decision
/// rather than an observed session condition.
fn is_quiet_hours_condition(condition_code: &str) -> bool {
    condition_code == crate::DELIVER_QUIET_HOURS_SUPPRESSED
        || condition_code == crate::DELIVER_QUIET_HOURS_REJECTED
}

/// Maps a caller-supplied condition to a fixed code. Unknown input (and any
/// embedded payload or secret text) is never echoed into a persisted record.
fn classify_condition(condition: &str) -> &'static str {
    match condition {
        "register:no-session" => "register:no-session",
        "activate:no-session" => "activate:no-session",
        "load:no-session" => "load:no-session",
        "deliver:no-session" => "deliver:no-session",
        "deliver:adapter-unavailable" => "deliver:adapter-unavailable",
        "fallback:no-session" => "fallback:no-session",
        "fallback:adapter-unavailable" => "fallback:adapter-unavailable",
        "deliver:quiet-hours-suppressed" => "deliver:quiet-hours-suppressed",
        "deliver:quiet-hours-rejected" => "deliver:quiet-hours-rejected",
        _ => "unknown-no-session",
    }
}

/// Prefix of every durable no-session marker key. The read-back below matches
/// exactly this prefix, and the `no-session/` namespace is disjoint from every
/// one-shot reservation key, so a marker can never be mistaken for a delivery
/// claim or a resolution.
const NO_SESSION_KEY_PREFIX: &str = "no-session/";

/// Reports whether a durable no-session marker is still readable from the
/// spool.
///
/// I11.6:13-14 requires the Event Log / spool to persist the obligation, so the
/// obligation's survival is read back from the owning store rather than assumed
/// from the write's return value. This appends no marker, mutates no
/// reservation, and resolves nothing: it applies exactly the same bounded
/// protected-lease read the marker writer uses. An unreadable or absent ledger
/// reports `false` so a caller reports spool-unavailable instead of claiming a
/// durable record it cannot see.
#[must_use]
pub fn spool_obligation_available() -> bool {
    let relative = PathBuf::from(crate::FALLBACK_LEDGER_RELATIVE);
    let Some(bytes) = read_ledger_bytes(&relative) else {
        return false;
    };
    let Some(snapshot) = parse_ledger_snapshot(&bytes) else {
        return false;
    };
    snapshot
        .get("entries")
        .and_then(Value::as_object)
        .is_some_and(|entries| {
            entries
                .keys()
                .any(|key| key.starts_with(NO_SESSION_KEY_PREFIX))
        })
}

/// Durable marker key for one no-session observation. The `no-session/`
/// prefix keeps the marker disjoint from every one-shot reservation key, so
/// the canonical upsert-before-attempt ordering is preserved and no item can
/// resolve through this record.
fn no_session_key(condition_code: &'static str) -> String {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    format!("{NO_SESSION_KEY_PREFIX}{condition_code}/{now_ms}")
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
            Value::String(String::from(marker_disposition(condition_code))),
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
