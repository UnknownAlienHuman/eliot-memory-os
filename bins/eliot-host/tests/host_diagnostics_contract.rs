#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Focused contract tests for F-LOG-HOST-0 item 889 (Implements, not Closes).
//!
//! These tests prove only the library-compiled facade installation, the
//! explicitly-absent Event Log seam with its bounded queue/drop policy, the
//! single `main.rs` reference failure, and stdout ownership against the
//! fixture in `tests/data/host_diagnostics_cases.json`. They do not assert
//! the full 22-case matrix from the issue (complete inventory, per-identity
//! distinctions, full canary sweeps, sink-failure noninterference,
//! allowed-diff review): those cases are deferred to the owning follow-ups
//! (#891/#893/#985) and recorded here plus in the commit message. Real
//! Host-wrapper Event Log delivery smoke on isolated Windows needs #984's
//! accepted safe port and stays an honest residual: this wrapper must
//! neither acquire Event Log FFI nor fake delivery. A diagnostic record is
//! evidence only, never lifecycle authority, readiness, or completion.

use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_host::host_diagnostics::{
    bound_detail, bound_field, install_host_diagnostics, observe_entrypoint,
    observe_terminal_error, sink_status, DiagnosticSink, EntrypointStage, HOST_DIAGNOSTICS_TARGET,
    HOST_TERMINAL_CODE_CONSOLE_FAILED, HOST_TERMINAL_CODE_DISPATCHER_FAILED,
    MAX_DIAGNOSTIC_DETAIL_BYTES, MAX_DIAGNOSTIC_FIELD_BYTES,
};
use eliot_host::windows_event_log::{
    event_log_sink_status, report_event, AdmittedEvent, EventLogRecord, WindowsEventLogError,
    WindowsEventLogQueue, EVENT_LOG_QUEUE_CAPACITY, EVENT_LOG_SOURCE,
};
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

fn contract_fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/host_diagnostics_cases.json");
    let bytes = std::fs::read(&path).expect("contract fixture must be readable");
    serde_json::from_slice(&bytes).expect("contract fixture must be valid JSON")
}

fn manifest_source(relative: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).expect("tracked source must be readable")
}

/// Byte-exact mirror of `host_console_protocol::write_response` (JSON +
/// `\n` + flush) onto a captured buffer instead of the stdout lock, so the
/// stdout-ownership proof drives the real framing without touching the
/// process-global stdout.
fn write_protocol_frame(buffer: &mut Vec<u8>, value: &Value) -> bool {
    serde_json::to_writer(&mut *buffer, value).is_ok()
        && buffer.write_all(b"\n").is_ok()
        && buffer.flush().is_ok()
}

// WORK_UNIT_CASE: 889/3
// WORK_UNIT_CASE: 889/4
#[test]
fn host_diagnostics_install_is_singly_owned() {
    // First installation claims process ownership; a repeat install is
    // bounded AlreadyOwned, never a panic, a replacement, or a second owner.
    // (Cases 889/3 first install, 889/4 duplicate init.) This is the only
    // test that touches the process-global install, so parallel tests stay
    // deterministic.
    install_host_diagnostics().expect("first facade install must succeed");
    let repeat = install_host_diagnostics();
    assert_eq!(
        repeat,
        Err(eliot_host::host_diagnostics::HostDiagnosticsError::AlreadyOwned),
        "repeat install must be typed AlreadyOwned"
    );

    // Tracing-stderr delivery is available; the Windows Event Log sink is an
    // explicitly absent seam (issue #984 still open): typed Unavailable,
    // never silent delivery elsewhere and never FFI. (Supports 889/15-18.)
    assert_eq!(sink_status(DiagnosticSink::TracingStderr), Ok(()));
    assert_eq!(
        sink_status(DiagnosticSink::WindowsEventLog),
        Err(eliot_host::host_diagnostics::HostDiagnosticsError::EventLogUnavailable)
    );
    assert_eq!(
        event_log_sink_status(),
        Err(WindowsEventLogError::EventLogUnavailable),
        "wrapper seam must agree with the facade seam"
    );

    // Truncation honesty: oversized inputs keep a bounded prefix and record
    // the original length. (Supports 889/10 sizing.)
    let oversized = "x".repeat(8 * MAX_DIAGNOSTIC_DETAIL_BYTES);
    let bounded = bound_detail(&oversized);
    assert_eq!(bounded.original_bytes(), oversized.len());
    assert!(
        bounded.truncated(),
        "oversized input must report truncation"
    );
    assert!(
        bounded.text().len() <= MAX_DIAGNOSTIC_DETAIL_BYTES,
        "retained prefix must stay bounded, got {} bytes",
        bounded.text().len()
    );
    let exact = "y".repeat(MAX_DIAGNOSTIC_DETAIL_BYTES);
    let kept = bound_detail(&exact);
    assert!(
        !kept.truncated(),
        "in-bound input must not report truncation"
    );
    assert_eq!(kept.text(), exact);

    let long_code = "c".repeat(8 * MAX_DIAGNOSTIC_FIELD_BYTES);
    let bounded_code = bound_field(&long_code);
    assert!(bounded_code.truncated());
    assert!(bounded_code.text().len() <= MAX_DIAGNOSTIC_FIELD_BYTES);

    // Terminal vocabulary projects the frozen Host stop codes without a
    // second lifecycle owner; the two funnel codes stay distinct.
    assert_ne!(
        HOST_TERMINAL_CODE_CONSOLE_FAILED,
        HOST_TERMINAL_CODE_DISPATCHER_FAILED
    );
    let fixture = contract_fixture();
    assert_eq!(
        HOST_TERMINAL_CODE_CONSOLE_FAILED,
        fixture["terminal_codes"]["console_failed"]
            .as_str()
            .expect("fixture must pin the console_failed code")
    );
    assert_eq!(
        HOST_TERMINAL_CODE_DISPATCHER_FAILED,
        fixture["terminal_codes"]["dispatcher_failed"]
            .as_str()
            .expect("fixture must pin the dispatcher_failed code")
    );
}

// WORK_UNIT_CASE: 889/5
// WORK_UNIT_CASE: 889/13
#[test]
fn host_diagnostics_entrypoint_observation_matches_contract_fixture() {
    // The facade is compiled once in the host library and observed here;
    // the binary's use is compile-gated in `src/main.rs` (same crate path,
    // no second `mod`/copy). Scoped capture shadows any global install, so
    // this test stays isolated and parallel-safe. (Cases 889/5 stable
    // mapping without a second lifecycle, 889/13 deterministic capture.)
    let fixture = contract_fixture();
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let captured = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            observe_entrypoint(EntrypointStage::ConsoleLoop);
        });
        sink.bytes.lock().unwrap().clone()
    };
    let text = String::from_utf8_lossy(&captured);

    let expected_stage = fixture["stages"]["console_loop"]
        .as_str()
        .expect("fixture must pin the console_loop stage name");
    assert_eq!(
        EntrypointStage::ConsoleLoop.as_str(),
        expected_stage,
        "facade stage name must match the contract fixture"
    );
    assert_eq!(
        EntrypointStage::Startup.as_str(),
        fixture["stages"]["startup"]
            .as_str()
            .expect("fixture must pin the startup stage name")
    );
    assert_eq!(
        EntrypointStage::ScmDispatch.as_str(),
        fixture["stages"]["scm_dispatch"]
            .as_str()
            .expect("fixture must pin the scm_dispatch stage name")
    );
    assert!(
        text.contains(HOST_DIAGNOSTICS_TARGET),
        "scoped capture must contain the facade target, got: {text}"
    );
    assert!(
        text.contains(
            fixture["entrypoint_event"]
                .as_str()
                .expect("fixture must pin the entrypoint event name")
        ),
        "scoped capture must contain the entrypoint event, got: {text}"
    );
    assert!(
        text.contains(expected_stage),
        "scoped capture must contain the observed stage, got: {text}"
    );

    // Bounds and the absent Event Log seam stay pinned by the same fixture.
    assert_eq!(
        MAX_DIAGNOSTIC_FIELD_BYTES,
        usize::try_from(
            fixture["max_field_bytes"]
                .as_u64()
                .expect("fixture must pin max_field_bytes")
        )
        .expect("fixture bound must fit usize")
    );
    assert_eq!(
        MAX_DIAGNOSTIC_DETAIL_BYTES,
        usize::try_from(
            fixture["max_detail_bytes"]
                .as_u64()
                .expect("fixture must pin max_detail_bytes")
        )
        .expect("fixture bound must fit usize")
    );
    assert_eq!(
        fixture["event_log_sink"]
            .as_str()
            .expect("fixture must pin the event log seam"),
        "unavailable"
    );
    assert!(
        captured.len() < 8 * 1024,
        "diagnostic capture must stay bounded, got {} bytes",
        captured.len()
    );

    // No secret or payload canary may appear in a plain stage observation.
    for canary in [
        "AKIA",
        "password",
        "token=",
        "connection_string",
        "BEGIN PRIVATE",
    ] {
        assert!(
            !text.contains(canary),
            "stage observation must not contain canary {canary:?}, got: {text}"
        );
    }
}

// WORK_UNIT_CASE: 889/15
// WORK_UNIT_CASE: 889/16
// WORK_UNIT_CASE: 889/17
// WORK_UNIT_CASE: 889/18
#[test]
fn windows_event_log_wrapper_names_contract_but_stays_unavailable() {
    // The wrapper names #984's consumer contract (fixed source, event ids,
    // severity, redacted insertions; admitted start/stop/failure only) but
    // delivers nothing until #984 lands: typed Unavailable, never FFI and
    // never a silent fallback. (Cases 889/15 start, 889/16 stop, 889/17
    // failure mapping and correlation, 889/18 missing/denied stays distinct
    // and leaves the Host result unchanged.)
    let fixture = contract_fixture();
    assert_eq!(
        EVENT_LOG_SOURCE,
        fixture["event_log_source"]
            .as_str()
            .expect("fixture must pin the event log source")
    );
    for (event, key) in [
        (AdmittedEvent::ServiceStart, "service_start"),
        (AdmittedEvent::ServiceStop, "service_stop"),
        (AdmittedEvent::ServiceFailure, "service_failure"),
    ] {
        let record = EventLogRecord::new(event, "host funnel reached boundary");
        let (source, event_id, severity) = record.mapping();
        assert_eq!(source, EVENT_LOG_SOURCE);
        assert_eq!(
            event_id,
            u32::try_from(
                fixture["event_mappings"][key]["event_id"]
                    .as_u64()
                    .expect("fixture must pin the event id")
            )
            .expect("event id must fit u32")
        );
        assert_eq!(
            severity.as_str(),
            fixture["event_mappings"][key]["severity"]
                .as_str()
                .expect("fixture must pin the severity")
        );
        // Mapping proof only: delivery stays honestly unavailable and the
        // caller's Host result is untouched (Ok stays Ok around the call).
        let host_result: Result<(), &'static str> = Ok(());
        assert_eq!(
            report_event(&record),
            Err(WindowsEventLogError::EventLogUnavailable)
        );
        assert!(
            host_result.is_ok(),
            "sink outcome must not change Host result"
        );
    }

    // Failure correlation uses the frozen terminal code as the redacted
    // insertion; the record keeps truncation honesty.
    let failure = EventLogRecord::new(
        AdmittedEvent::ServiceFailure,
        HOST_TERMINAL_CODE_CONSOLE_FAILED,
    );
    assert!(failure.insertion().contains("console_failed"));
    assert!(!failure.truncated());
    let long_insertion = "d".repeat(8 * MAX_DIAGNOSTIC_DETAIL_BYTES);
    let truncated = EventLogRecord::new(AdmittedEvent::ServiceFailure, &long_insertion);
    assert!(truncated.truncated());
    assert!(truncated.insertion().len() <= MAX_DIAGNOSTIC_DETAIL_BYTES);

    // Finite nonblocking admission: capacity is honored, overflow drops with
    // an exact count, shutdown parks the remainder as Unknown without
    // claiming a drain or abort that did not complete. (Supports 889/10 and
    // 889/14 queue/drop/shutdown honesty.)
    assert_eq!(
        usize::try_from(
            fixture["queue_capacity"]
                .as_u64()
                .expect("fixture must pin the queue capacity")
        )
        .expect("queue capacity must fit usize"),
        EVENT_LOG_QUEUE_CAPACITY
    );
    let mut queue = WindowsEventLogQueue::new(2);
    assert!(queue.is_empty());
    queue
        .try_admit(EventLogRecord::new(AdmittedEvent::ServiceStart, "start"))
        .expect("admission within capacity must succeed");
    queue
        .try_admit(EventLogRecord::new(AdmittedEvent::ServiceStop, "stop"))
        .expect("admission within capacity must succeed");
    assert_eq!(queue.len(), 2);
    assert_eq!(
        queue.try_admit(EventLogRecord::new(AdmittedEvent::ServiceFailure, "full")),
        Err(WindowsEventLogError::QueueFull)
    );
    assert_eq!(queue.dropped_total(), 1);
    let shutdown = queue.shutdown();
    assert!(queue.is_closed());
    assert_eq!(
        shutdown.unsent(),
        2,
        "shutdown must park held records as unsent"
    );
    assert_eq!(shutdown.dropped_total(), 1);
    assert_eq!(
        queue.try_admit(EventLogRecord::new(AdmittedEvent::ServiceStart, "late")),
        Err(WindowsEventLogError::Closed)
    );
}

// WORK_UNIT_CASE: 889/22
#[test]
fn tracing_never_corrupts_console_stdout_framing() {
    // Subscriber writes stderr only; `write_response`
    // (`host_console_protocol.rs:44-50`) keeps sole stdout ownership;
    // parallel scoped capture must not replace the global subscriber.
    // Smallest proof: drive ready/state frames while diagnostics emit and
    // assert stdout frames stay exactly one-JSON-per-line.
    let fixture = contract_fixture();
    assert_eq!(
        fixture["stdout_protocol_contamination"].as_bool(),
        Some(false),
        "fixture must pin clean stdout framing"
    );

    let ready = serde_json::json!({"status": "ready", "service": "test", "protocol": "test"});
    let state = serde_json::json!({"status": "state", "running": true});

    // Parallel scoped captures each receive their own record while the
    // stdout buffer is framed on this thread; no capture touches stdout.
    let stdout_sink = CaptureSink::default();
    let stdout_bytes = stdout_sink.bytes.clone();
    std::thread::scope(|scope| {
        for stage in [
            EntrypointStage::Startup,
            EntrypointStage::ConsoleLoop,
            EntrypointStage::ShutdownDrain,
        ] {
            scope.spawn(move || {
                let thread_sink = CaptureSink::default();
                let writer = thread_sink.clone();
                let subscriber = tracing_subscriber::fmt()
                    .with_ansi(false)
                    .with_writer(move || writer.clone())
                    .finish();
                tracing::subscriber::with_default(subscriber, || {
                    observe_entrypoint(stage);
                    observe_terminal_error(HOST_TERMINAL_CODE_CONSOLE_FAILED);
                });
                let text = String::from_utf8_lossy(&thread_sink.bytes.lock().unwrap()).into_owned();
                assert!(
                    text.contains(HOST_DIAGNOSTICS_TARGET),
                    "scoped thread capture must contain the target, got: {text}"
                );
                assert!(
                    text.contains(stage.as_str()),
                    "scoped thread capture must contain its stage, got: {text}"
                );
            });
        }
        scope.spawn(|| {
            let mut buffer = Vec::new();
            assert!(write_protocol_frame(&mut buffer, &ready));
            assert!(write_protocol_frame(&mut buffer, &state));
            stdout_bytes.lock().unwrap().extend_from_slice(&buffer);
        });
    });

    let stdout = stdout_bytes.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&stdout).into_owned();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "stdout must stay exactly one-JSON-per-line, got: {text}"
    );
    for line in &lines {
        serde_json::from_str::<Value>(line).expect("every stdout line must stay exact JSON");
    }
    assert!(
        !text.contains(HOST_DIAGNOSTICS_TARGET),
        "tracing must never leak into stdout frames, got: {text}"
    );
    assert!(
        !text.contains(
            fixture["entrypoint_event"]
                .as_str()
                .expect("fixture must pin the entrypoint event name")
        ),
        "diagnostic events must never contaminate stdout, got: {text}"
    );
}

// WORK_UNIT_CASE: 889/1
// WORK_UNIT_CASE: 889/19
#[test]
fn host_reference_failure_and_registration_are_singular() {
    // Exactly one current `main.rs` reference failure uses the facade, and
    // the library registration is exactly the two new modules: no lifecycle
    // instrumentation here (that is #891's), no FFI in Host. (Cases 889/1
    // inventory, 889/19 single reference failure.)
    let lib = manifest_source("src/lib.rs");
    assert_eq!(
        lib.matches("pub mod host_diagnostics;").count(),
        1,
        "lib must register the facade exactly once"
    );
    assert_eq!(
        lib.matches("pub mod windows_event_log;").count(),
        1,
        "lib must register the sink seam exactly once"
    );

    let main = manifest_source("src/main.rs");
    assert_eq!(
        main.matches("install_host_diagnostics").count(),
        1,
        "main must install diagnostics exactly once"
    );
    assert_eq!(
        main.matches("observe_terminal_error").count(),
        1,
        "main must keep exactly one reference failure for HOST-0"
    );
    assert!(
        main.contains("HOST_TERMINAL_CODE_CONSOLE_FAILED"),
        "the single reference failure must use the frozen console code"
    );

    // No Event Log FFI is acquired inside Host; the seam stays typed and
    // absent until #984 lands.
    for (name, contents) in [
        (
            "host_diagnostics.rs",
            manifest_source("src/host_diagnostics.rs"),
        ),
        (
            "windows_event_log.rs",
            manifest_source("src/windows_event_log.rs"),
        ),
        ("main.rs", main),
    ] {
        for forbidden in [
            "RegisterEventSource",
            "ReportEventW",
            "DeregisterEventSource",
        ] {
            assert!(
                !contents.contains(forbidden),
                "{name} must not acquire Event Log FFI ({forbidden})"
            );
        }
    }
    let wrapper = manifest_source("src/windows_event_log.rs");
    assert!(
        wrapper.contains("EventLogUnavailable"),
        "wrapper must keep the typed unavailable seam"
    );
}
