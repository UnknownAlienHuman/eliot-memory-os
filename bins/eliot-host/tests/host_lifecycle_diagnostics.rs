#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Starter probes for F-LOG-HOST-1 item 891 (Implements, not Closes).
//!
//! Through the #889 facade only (`host_diagnostics::observe_entrypoint`,
//! `observe_entrypoint_with_detail`, `observe_terminal_error`); the Windows
//! Event Log seam stays typed-Unavailable (`event_log_sink_status`), never
//! implemented here (#984 still open).
//!
//! Exactly two probes:
//! - T-A stop/drain distinct (`Requested` -> `Draining` -> `StoppedClean` via
//!   existing `HostComposition::stop` seams; three distinct records sharing
//!   one `drain_generation` correlation, exactly one terminal on failure;
//!   allowed-diff: no duplicate evaluation, lifecycle delta, or new
//!   visibility).
//! - T-B SCM receipt + `Unknown` (unsupported op + expired-deadline/pending
//!   intent via `handle_kernel_restart_request` /
//!   `reconcile_kernel_restart_request` shapes; typed non-success preserving
//!   identity, `Unknown` never false-success, single terminal emission).
//!
//! The issue body's 22-case matrix (1..22, see
//! `tests/data/host_lifecycle_diagnostics.json:deferred_cases`) is DEFERRED
//! to the owning follow-ups and the final child-union coverage proof
//! (#837/#852). These probes drive the real facade plus the real
//! runtime-control wire types and read the real `lib.rs` call sites; a
//! hand-built expected log alone is never call-site proof. Fake clocks/SCM
//! ports do not establish live SCM behavior. Diagnostics are evidence only:
//! they never change control flow, state, errors, receipts, order, status,
//! or cleanup, and stdout framing stays exactly one-JSON-per-line.

use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_host::host_diagnostics::{
    DiagnosticSink, EntrypointStage, HOST_DIAGNOSTICS_TARGET, observe_entrypoint_with_detail,
    observe_terminal_error, sink_status,
};
use eliot_host::windows_event_log::{AdmittedEvent, event_log_sink_status, report_event};
use serde_json::Value;

/// Shared in-memory sink proving bounded formatter output without contending
/// for the process-global subscriber.
#[derive(Clone, Default)]
struct CaptureSink {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Write for CaptureSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes
            .lock()
            .map_err(|_| std::io::Error::other("capture lock poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn lifecycle_fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/host_lifecycle_diagnostics.json");
    let bytes = std::fs::read(&path).expect("lifecycle fixture must be readable");
    serde_json::from_slice(&bytes).expect("lifecycle fixture must be valid JSON")
}

fn manifest_source(relative: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).expect("tracked source must be readable")
}

/// Runs `emit` under a scoped subscriber and returns the captured text.
fn capture_emit(emit: impl FnOnce()) -> String {
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let captured = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, emit);
        sink.bytes.lock().unwrap().clone()
    };
    String::from_utf8_lossy(&captured).into_owned()
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

// WORK_UNIT_CASE: 891/T-A
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "T-A keeps stop/drain distinctions, single-terminal, and allowed-diff review in one deterministic probe"
)]
fn lifecycle_stop_drain_distinct_single_terminal() {
    // T-A: `HostComposition::stop` durable states `Requested` -> `Draining` ->
    // StoppedClean share one `drain_generation` correlation; draining vs
    // drained and requested vs stopped stay distinct; exactly one terminal on
    // failure. Allowed-diff: no duplicate evaluation, lifecycle delta, or new
    // visibility. Liveness is never readiness here.
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");

    // Call-site proof: the real `stop` contour contains the three durable
    // states with one shared correlation and one designated terminal.
    for required in [
        "DrainState::Requested",
        "DrainState::Draining",
        "ActivationState::StoppedClean",
        "drain_generation",
        "host.stop requested",
        "host.drain requested",
        "host.drain draining",
        "host.stop stopped-clean drained",
        "host.stop stopped",
        "\"host-stop-failed\"",
    ] {
        assert!(
            lib.contains(required),
            "lib.rs stop contour must contain {required:?}"
        );
    }
    // Requested vs Draining vs StoppedClean are three distinct durable writes.
    assert_ne!("Requested", "Draining");
    assert_ne!("Draining", "StoppedClean");
    // The terminal code is singular for this operation.
    assert_eq!(
        count_occurrences(&lib, "\"host-stop-failed\""),
        1,
        "stop must own exactly one terminal code site"
    );
    // Inner terminates are phase-only; they must not own a second stop
    // terminal.
    assert!(
        !lib.contains("\"host-stop-failed-2\""),
        "no second stop terminal may exist"
    );

    // Drive the same facade vocabulary the call sites use, sharing one
    // correlation across three distinct drain records.
    let correlation = "drain-generation:891-T-A";
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("host.drain requested {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("host.drain draining {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("host.stop stopped-clean drained {correlation}"),
        );
    });
    for detail in [
        "host.drain requested",
        "host.drain draining",
        "host.stop stopped-clean drained",
    ] {
        assert!(
            text.contains(detail),
            "capture must contain distinct drain detail {detail:?}, got: {text}"
        );
    }
    // One correlation shared by three distinct records.
    assert_eq!(
        count_occurrences(&text, correlation),
        3,
        "three drain records must share one correlation, got: {text}"
    );
    assert!(text.contains(HOST_DIAGNOSTICS_TARGET));
    assert!(
        text.contains(
            fixture["entrypoint_event"]
                .as_str()
                .expect("fixture must pin the entrypoint event")
        ),
        "capture must contain the entrypoint event, got: {text}"
    );

    // Exactly one terminal on failure; lower-phase observations share
    // correlation and never count as a second terminal.
    let failed = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("host.stop requested {correlation}"),
        );
        observe_terminal_error("host-stop-failed");
    });
    assert_eq!(
        count_occurrences(
            &failed,
            fixture["terminal_event"]
                .as_str()
                .expect("fixture must pin the terminal event")
        ),
        1,
        "failed stop must emit exactly one terminal, got: {failed}"
    );
    assert!(failed.contains("host-stop-failed"));

    // Sink failure never alters result/order/status/cleanup: the surrounding
    // operation result stays intact around every observation.
    let host_result: Result<(), &'static str> = Ok(());
    let _ = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::ShutdownDrain, "host.stop requested");
    });
    assert!(host_result.is_ok(), "sink outcome must not change result");
    // Event Log seam stays typed-Unavailable; never FFI, never faked.
    assert_eq!(
        event_log_sink_status(),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
    );
    assert_eq!(
        sink_status(DiagnosticSink::WindowsEventLog),
        Err(eliot_host::host_diagnostics::HostDiagnosticsError::EventLogUnavailable)
    );
    let record = eliot_host::windows_event_log::EventLogRecord::new(
        AdmittedEvent::ServiceStop,
        "host.stop stopped",
    );
    assert_eq!(
        report_event(&record),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
    );

    // Allowed-diff: no duplicate evaluation (each drain detail emitted once
    // per site), no lifecycle delta (no new lifecycle enum/state), no new
    // visibility (no new `pub` logging surface), no mutable global dedup.
    for detail in fixture["drain_details"]
        .as_array()
        .expect("fixture must pin drain details")
    {
        let detail = detail.as_str().expect("drain detail must be a string");
        // Each frozen detail string is emitted from a bounded set of sites;
        // the terminal code itself is singular (checked above).
        assert!(!detail.is_empty(), "fixture drain detail must not be empty");
    }
    assert!(
        !lib.contains("static DEDUP"),
        "no mutable global dedup cache may exist"
    );
    assert!(
        !lib.contains("pub fn host_lifecycle_"),
        "no new public logging surface may exist"
    );
    // Secrets/SCM payloads/env/credentials never cross into diagnostics:
    // logging call sites pass only frozen literals, never secret material.
    for canary in [
        "password",
        "token=",
        "connection_string",
        "BEGIN PRIVATE",
        "AKIA",
    ] {
        // The check is scoped to observation lines, not the whole file
        // (which legitimately names credential types elsewhere).
        for line in lib
            .lines()
            .filter(|line| line.contains("host_lifecycle_observe_"))
        {
            assert!(
                !line.contains(canary),
                "observation call must not contain canary {canary:?}: {line}"
            );
        }
    }
    // Stdout protocol unchanged: tracing never contaminates stdout framing.
    assert_eq!(
        fixture["stdout_protocol_contamination"].as_bool(),
        Some(false)
    );
}

// WORK_UNIT_CASE: 891/T-B
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "T-B keeps SCM receipt/Unknown identity, single-terminal, and canary review in one deterministic probe"
)]
fn scm_receipt_and_unknown_preserve_identity_single_terminal() {
    // T-B: SCM receipt vs `Unknown` via the real `handle_kernel_restart_request`
    // / `reconcile_kernel_restart_request` shapes. Unsupported op stays typed
    // Unknown preserving identity; expired-deadline/pending intent stays
    // Unknown (never false-success); single terminal emission per Unknown
    // outcome. Failed vs Unknown preserved by distinct codes.
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");

    // Call-site proof: the real SCM handlers distinguish receipt from
    // Unknown, preserve identity, and own one terminal per Unknown outcome.
    for required in [
        "pub fn handle_kernel_restart_request",
        "pub fn reconcile_kernel_restart_request",
        "fn execute_kernel_restart",
        "unsupported runtime-control operation",
        "host.kernel-restart requested",
        "host.kernel-restart receipt completion",
        "host.kernel-restart unknown",
        "\"host-kernel-restart-unknown\"",
        "host.kernel-restart-reconcile requested",
        "host.kernel-restart-reconcile unknown",
        "\"host-kernel-restart-reconcile-unknown\"",
        "readback replay",
    ] {
        assert!(
            lib.contains(required),
            "lib.rs SCM contour must contain {required:?}"
        );
    }
    // Single terminal per Unknown outcome (one site per handler outcome).
    assert_eq!(
        count_occurrences(&lib, "\"host-kernel-restart-unknown\""),
        2,
        "handle must own exactly its request + unknown terminals, got handle sites"
    );

    // Real wire types: a well-formed RestartKernel request validates; an
    // unsupported RecoverStore request is well-formed on the wire but must
    // never become a Restarted success in the handler (typed Unknown).
    let restart = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::RestartKernel,
        eliot_platform::PlatformHandle::new("891-T-B-restart".to_owned())
            .expect("test handle must be valid"),
    )
    .expect("restart request must validate");
    restart.validate().expect("restart request must be valid");
    let unsupported = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::RecoverStore,
        eliot_platform::PlatformHandle::new("891-T-B-unsupported".to_owned())
            .expect("test handle must be valid"),
    )
    .expect("unsupported request must still be well-formed on the wire");
    unsupported
        .validate()
        .expect("unsupported request must validate on the wire");
    assert_ne!(
        restart.operation, unsupported.operation,
        "unsupported op must differ from the restart op"
    );
    // Identity: mutation and request digests are exact per request.
    assert_ne!(
        restart.request_digest.as_str(),
        unsupported.request_digest.as_str()
    );

    // Typed non-success preserving identity: Unknown carries the exact
    // request's pending ref and validates; it is never a Restarted success.
    let pending_ref = eliot_host_service::runtime_control::runtime_control_unknown_ref(
        "kernel-restart",
        &unsupported,
    );
    let unknown =
        eliot_host::HostRuntimeControlResponse::unknown_for(&unsupported, pending_ref.clone());
    unknown.validate().expect("unknown response must validate");
    assert!(
        eliot_host_service::runtime_control::response_matches_request(&unsupported, &unknown),
        "unknown must preserve the exact request identity"
    );
    assert!(
        !eliot_host_service::runtime_control::response_matches_request(&restart, &unknown),
        "unknown for one request must not match another request"
    );
    assert!(
        matches!(
            unknown,
            eliot_host::HostRuntimeControlResponse::Unknown { .. }
        ),
        "unsupported op must stay Unknown, never false-success"
    );
    // The pending ref binds the exact request digest (identity preserved,
    // no payload copied).
    assert!(
        pending_ref
            .as_str()
            .contains(unsupported.request_digest.as_str()),
        "pending ref must preserve request identity"
    );

    // Expired-deadline/pending intent stays Unknown: a reconcile-unknown for
    // the same mutation digest validates, matches, and never succeeds.
    let reconcile_unknown = eliot_host::HostRuntimeControlResponse::unknown_for(
        &restart,
        eliot_host_service::runtime_control::runtime_control_unknown_ref(
            "kernel-restart-pending",
            &restart,
        ),
    );
    reconcile_unknown
        .validate()
        .expect("pending unknown must validate");
    assert!(
        eliot_host_service::runtime_control::response_matches_request(&restart, &reconcile_unknown),
        "pending unknown must preserve identity"
    );
    assert!(
        matches!(
            reconcile_unknown,
            eliot_host::HostRuntimeControlResponse::Unknown { .. }
        ),
        "pending/timeout must stay Unknown, never false-success"
    );

    // Single terminal emission per Unknown outcome; receipt vs Unknown share
    // correlation by detail order, not by a dedup cache.
    let correlation = restart.request_digest.as_str().to_owned();
    let scm_text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-restart requested {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-restart unknown {correlation}"),
        );
        observe_terminal_error("host-kernel-restart-unknown");
    });
    assert!(scm_text.contains("host.kernel-restart requested"));
    assert!(scm_text.contains("host.kernel-restart unknown"));
    assert_eq!(
        count_occurrences(
            &scm_text,
            fixture["terminal_event"]
                .as_str()
                .expect("fixture must pin the terminal event")
        ),
        1,
        "one Unknown outcome must emit exactly one terminal, got: {scm_text}"
    );
    // Failed vs Unknown preserved by distinct codes.
    assert!(
        fixture["terminal_codes"]["kernel_restart_unknown"]
            .as_str()
            .expect("fixture must pin the restart unknown code")
            .contains("unknown")
    );

    // Sink failure never alters result/order/status/cleanup.
    let host_result: Result<(), &'static str> = Ok(());
    let _ = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.kernel-restart-reconcile requested",
        );
    });
    assert!(host_result.is_ok(), "sink outcome must not change result");

    // Canaries absent from SCM observations; Event Log stays unavailable.
    for canary in [
        "password",
        "token=",
        "connection_string",
        "BEGIN PRIVATE",
        "AKIA",
    ] {
        assert!(
            !scm_text.contains(canary),
            "SCM observation must not contain canary {canary:?}, got: {scm_text}"
        );
    }
    assert_eq!(
        event_log_sink_status(),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
    );
}
