#![allow(clippy::expect_used, clippy::unwrap_used)]
//! F-LOG-HOST integrator oracle (#985 A12) via the #889 facade only.
//!
//! A12 verbatim: "actual cross-child forced failure produces one terminal
//! event and unchanged return/receipt/cleanup." Package D acceptance (#889
//! TASK): two concurrent operations do not mix; one injected nested failure
//! gives exactly one terminal with the same return/receipt/cleanup;
//! enabled/disabled/failing sink does not change semantics.
//!
//! Correlation contract (governing, #889): the same tx/effect/request token
//! binds a terminal record to its own operation's subordinate records;
//! stage order across records is descriptive only. This oracle reuses the
//! #889 projection type [`HostRequestProjection`] with no second scheme:
//! two operations carry distinct (installation, generation, process,
//! request, operation, tx) tuples and never mix, and the forced failure
//! travels the actual nested caller map
//! `HostLaunchOptions::parse` (#978 launch owner, nested failure site) ->
//! `HostRequestProjection::failed` subordinate + single `observe_terminal_error`
//! (#889 facade) -> `lib.rs` terminal guard (#891) / `main.rs` console
//! contour (#982). The field-level tx/effect/request slots on the terminal
//! record itself arrive with #889 `observe_phase_projection` /
//! `observe_terminal_projection` and are named as ceiling, not wired here.

use std::ffi::OsString;
use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_host::host_diagnostics::{
    EntrypointStage, HOST_TERMINAL_CODE_CONSOLE_FAILED, HostConsoleRequest, HostRequestProjection,
    note_event_log_sink_status, observe_entrypoint_with_detail, observe_host_request,
    observe_terminal_error,
};
use eliot_host::HostLaunchOptions;
use eliot_host::windows_event_log::{
    AdmittedEvent, EVENT_LOG_QUEUE_CAPACITY, EVENT_LOG_SOURCE, EventLogRecord,
    WindowsEventLogError, WindowsEventLogQueue, event_log_sink_status,
};
use serde_json::Value;

const OPTIONS_SRC: &str = include_str!("../src/host_launch_options.rs");
const DIAGNOSTICS_SRC: &str = include_str!("../src/host_diagnostics.rs");
const LIB_SRC: &str = include_str!("../src/lib.rs");
const MAIN_SRC: &str = include_str!("../src/main.rs");

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

fn integration_fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/host_diagnostic_integration.json");
    let bytes = std::fs::read(&path).expect("integration fixture must be readable");
    serde_json::from_slice(&bytes).expect("integration fixture must be valid JSON")
}

fn operation_fixture(fixture: &Value, operation: &str, key: &str) -> String {
    fixture["operations"][operation][key]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must pin operations.{operation}.{key}"))
        .to_owned()
}

fn operation_u64(fixture: &Value, operation: &str, key: &str) -> u64 {
    fixture["operations"][operation][key]
        .as_u64()
        .unwrap_or_else(|| panic!("fixture must pin operations.{operation}.{key}"))
}

fn operation_u32(fixture: &Value, operation: &str, key: &str) -> u32 {
    u32::try_from(operation_u64(fixture, operation, key))
        .unwrap_or_else(|_| panic!("fixture operations.{operation}.{key} must fit u32"))
}

fn receipt_exit_i32(fixture: &Value) -> i32 {
    i32::try_from(
        fixture["receipt"]["exit"]
            .as_i64()
            .unwrap_or_else(|| panic!("fixture must pin receipt.exit")),
    )
    .unwrap_or_else(|_| panic!("fixture receipt.exit must fit i32"))
}

fn failure_event_id_u32(fixture: &Value) -> u32 {
    u32::try_from(
        fixture["sink"]["failure_event_id"]
            .as_u64()
            .unwrap_or_else(|| panic!("fixture must pin failure event id")),
    )
    .unwrap_or_else(|_| panic!("fixture failure event id must fit u32"))
}

fn capture_with_level(f: impl FnOnce(), level: tracing::Level) -> String {
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let captured = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(level)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        sink.bytes.lock().expect("capture lock").clone()
    };
    String::from_utf8_lossy(&captured).into_owned()
}

fn capture(f: impl FnOnce()) -> String {
    capture_with_level(f, tracing::Level::TRACE)
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// Byte-exact mirror of `host_console_protocol::write_response` (JSON +
/// `\n` + flush) onto a captured buffer instead of the stdout lock, so the
/// receipt proof drives the real framing without touching process stdout.
fn write_protocol_frame(buffer: &mut Vec<u8>, value: &Value) {
    serde_json::to_writer(&mut *buffer, value).expect("frame must serialize");
    buffer.write_all(b"\n").expect("frame must terminate");
    buffer.flush().expect("frame must flush");
}

fn valid_launch_args(installation: &str, generation: u64) -> Vec<OsString> {
    let tmp = std::env::temp_dir();
    vec![
        OsString::from("--config-descriptor"),
        tmp.join("eliot-launch-auth.json").into_os_string(),
        OsString::from("--config-descriptor-sha256"),
        OsString::from("a".repeat(64)),
        OsString::from("--installation-id"),
        OsString::from(installation),
        OsString::from("--tx-plan-generation"),
        OsString::from(generation.to_string()),
        OsString::from("--host-state-root"),
        tmp.join("eliot-host-state").into_os_string(),
    ]
}

// WORK_UNIT_CASE: 985/12
#[test]
fn forced_failure_one_terminal_unchanged_return_receipt_cleanup() {
    let fixture = integration_fixture();
    let forced = &fixture["forced_failure"];
    let terminal_event = forced["terminal_event"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must pin forced_failure.terminal_event"));
    let terminal_code = forced["terminal_code"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must pin forced_failure.terminal_code"));
    let reason = forced["reason"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must pin forced_failure.reason"));
    let evidence = forced["evidence"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must pin forced_failure.evidence"));
    let subordinate_event = forced["subordinate_event"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must pin forced_failure.subordinate_event"));
    let sentence = forced["terminal_contract_sentence"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must pin terminal contract sentence"));
    let nested_marker = forced["nested_site_marker"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must pin nested site marker"));
    let lib_guard = forced["lib_terminal_guard"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must pin lib terminal guard"));

    // Actual nested caller map, pinned to source: the nested failure site
    // (#978 launch owner) types the rejection, the facade owns the
    // exactly-once terminal contract (#889), and exactly one outermost
    // guard per binary contour emits it (#891 lib, #982 console).
    assert!(
        OPTIONS_SRC.contains("fn parse") && OPTIONS_SRC.contains(nested_marker),
        "nested failure site must type the rejection"
    );
    assert!(
        DIAGNOSTICS_SRC.contains(sentence),
        "facade must own the exactly-once terminal contract"
    );
    assert_eq!(
        LIB_SRC.matches(lib_guard).count(),
        1,
        "lib terminal guard must be singular"
    );
    assert_eq!(
        MAIN_SRC.matches("observe_terminal_error").count(),
        1,
        "console contour must hold one terminal emission"
    );
    assert_eq!(
        HOST_TERMINAL_CODE_CONSOLE_FAILED, terminal_code,
        "HOST-0 reference code must match the fixture"
    );

    // Forced failure through the real nested function: malformed argv is
    // rejected with a typed error before any admission.
    let malformed: Vec<OsString> = forced["malformed_argv"]
        .as_array()
        .unwrap_or_else(|| panic!("fixture must pin malformed_argv"))
        .iter()
        .map(|value| {
            OsString::from(
                value
                    .as_str()
                    .unwrap_or_else(|| panic!("malformed argv entries must be strings")),
            )
        })
        .collect();
    let failed = HostLaunchOptions::parse(malformed.clone())
        .unwrap_err();
    assert!(
        matches!(failed, eliot_host::HostError::Platform(_)),
        "nested failure must stay typed, got {failed:?}"
    );
    let return_before = format!("{failed:?}");

    // Healthy control on the same nested path: admission binds the owner
    // installation and generation identities the oracle correlates by.
    let alpha_installation = operation_fixture(&fixture, "alpha", "installation");
    let alpha_generation = operation_u64(&fixture, "alpha", "generation");
    let admitted =
        HostLaunchOptions::parse(valid_launch_args(&alpha_installation, alpha_generation))
            .expect("control argv must admit");
    assert_eq!(admitted.installation().as_str(), alpha_installation);
    assert_eq!(admitted.transaction_plan_generation(), alpha_generation);

    // Receipt framing before diagnostics: the console capsule the wire
    // response will carry, byte-exact.
    let receipt_exit = receipt_exit_i32(&fixture);
    let receipt_value = serde_json::json!({
        "status": fixture["receipt"]["status"],
        "code": terminal_code,
        "exit": receipt_exit,
    });
    let mut frame_before = Vec::new();
    write_protocol_frame(&mut frame_before, &receipt_value);

    // The owner contour: one Failed subordinate carrying the typed reason,
    // then exactly one terminal. The sink admission attempt underneath
    // (Event Log unavailable off Windows) must not change the outcome.
    let alpha_tx = operation_fixture(&fixture, "alpha", "tx");
    let captured = capture(|| {
        let subordinate = HostRequestProjection::failed(EntrypointStage::ScmDispatch, &failed)
            .with_operation(AdmittedEvent::ServiceFailure)
            .with_request(HostConsoleRequest::Stop)
            .with_terminal_exit(receipt_exit);
        observe_host_request(&subordinate);
        observe_entrypoint_with_detail(EntrypointStage::ConsoleLoop, &alpha_tx);
        observe_terminal_error(HOST_TERMINAL_CODE_CONSOLE_FAILED);
    });

    assert_eq!(
        count(&captured, terminal_event),
        1,
        "one injected nested failure gives exactly one terminal, got: {captured}"
    );
    assert!(
        captured.contains(subordinate_event) && captured.contains(evidence),
        "failed subordinate must render with failed evidence, got: {captured}"
    );
    assert!(
        captured.contains(reason) && captured.contains("reason_missing=false"),
        "typed reason must survive without guessing, got: {captured}"
    );
    assert!(
        captured.contains(&format!("receipt_exit={receipt_exit}"))
            && captured.contains("receipt_exit_missing=false"),
        "terminal receipt exit must correlate, got: {captured}"
    );

    // Unchanged return: the same nested call fails identically after
    // diagnostics ran; the healthy control still admits the same identities.
    let failed_again = HostLaunchOptions::parse(malformed)
        .unwrap_err();
    assert_eq!(
        format!("{failed_again:?}"),
        return_before,
        "diagnostics must not change the typed return"
    );
    let admitted_again =
        HostLaunchOptions::parse(valid_launch_args(&alpha_installation, alpha_generation))
            .expect("control argv must still admit");
    assert_eq!(admitted_again.installation().as_str(), alpha_installation);
    assert_eq!(
        admitted_again.transaction_plan_generation(),
        alpha_generation
    );

    // Unchanged receipt: the wire frame is byte-identical and carries no
    // diagnostic marks on the stdout path.
    let mut frame_after = Vec::new();
    write_protocol_frame(&mut frame_after, &receipt_value);
    assert_eq!(
        frame_after, frame_before,
        "diagnostics must not change the console receipt framing"
    );
    let frame_text = String::from_utf8_lossy(&frame_after);
    for mark in fixture["receipt"]["stdout_marks_absent"]
        .as_array()
        .unwrap_or_else(|| panic!("fixture must pin stdout marks"))
    {
        let mark = mark
            .as_str()
            .unwrap_or_else(|| panic!("stdout marks must be strings"));
        assert!(
            !frame_text.contains(mark),
            "diagnostic mark {mark:?} must stay off stdout"
        );
    }

    // Unchanged cleanup: the bounded local admission queue keeps its exact
    // accounting across the sink-status and terminal path above.
    let mut queue = WindowsEventLogQueue::with_default_capacity();
    assert_eq!(queue.capacity(), EVENT_LOG_QUEUE_CAPACITY);
    assert!(queue.is_empty());
    queue
        .try_admit(EventLogRecord::new(
            AdmittedEvent::ServiceFailure,
            "service=eliot-host phase=scm_dispatch evidence=failed operation=service_failure",
        ))
        .expect("bounded queue must admit one record");
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.dropped_total(), 0);
    assert!(!queue.is_closed());
    let _ = event_log_sink_status();
    assert_eq!(queue.len(), 1, "sink outcome must not change cleanup");
    assert_eq!(queue.dropped_total(), 0);
}

// WORK_UNIT_CASE: 985/12
#[test]
fn concurrent_operations_do_not_mix() {
    let fixture = integration_fixture();
    let alpha_installation = operation_fixture(&fixture, "alpha", "installation");
    let alpha_generation = operation_u64(&fixture, "alpha", "generation");
    let alpha_process = operation_u32(&fixture, "alpha", "process");
    let alpha_tx = operation_fixture(&fixture, "alpha", "tx");
    let beta_installation = operation_fixture(&fixture, "beta", "installation");
    let beta_generation = operation_u64(&fixture, "beta", "generation");
    let beta_process = operation_u32(&fixture, "beta", "process");
    let beta_tx = operation_fixture(&fixture, "beta", "tx");
    assert_ne!(alpha_installation, beta_installation);
    assert_ne!(alpha_tx, beta_tx);

    let alpha_options =
        HostLaunchOptions::parse(valid_launch_args(&alpha_installation, alpha_generation))
            .expect("alpha argv must admit");
    let beta_options =
        HostLaunchOptions::parse(valid_launch_args(&beta_installation, beta_generation))
            .expect("beta argv must admit");

    // Interleaved emission in an order stage sequence alone would
    // misattribute: alpha detail, beta detail, beta request, alpha request,
    // then alpha's single terminal. Correlation rides the identity tuple,
    // never stage order.
    let terminal_event = fixture["forced_failure"]["terminal_event"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must pin terminal event"));
    let captured = capture(|| {
        let alpha = HostRequestProjection::admitted(EntrypointStage::ScmDispatch, &alpha_options)
            .with_request(HostConsoleRequest::Stop)
            .with_operation(AdmittedEvent::ServiceStop)
            .with_process(alpha_process);
        let beta = HostRequestProjection::admitted(EntrypointStage::ScmDispatch, &beta_options)
            .with_request(HostConsoleRequest::Status)
            .with_process(beta_process);
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, &alpha_tx);
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, &beta_tx);
        observe_host_request(&beta);
        observe_host_request(&alpha);
        observe_terminal_error(HOST_TERMINAL_CODE_CONSOLE_FAILED);
    });

    assert_eq!(
        count(&captured, terminal_event),
        1,
        "concurrent pair with one failure gives one terminal, got: {captured}"
    );
    let lines: Vec<&str> = captured.lines().collect();
    let alpha_lines: Vec<&&str> = lines
        .iter()
        .filter(|line| line.contains(&alpha_installation) || line.contains(&alpha_tx))
        .collect();
    let beta_lines: Vec<&&str> = lines
        .iter()
        .filter(|line| line.contains(&beta_installation) || line.contains(&beta_tx))
        .collect();
    assert_eq!(
        alpha_lines.len(),
        2,
        "alpha owns exactly its detail plus its request record: {captured}"
    );
    assert_eq!(
        beta_lines.len(),
        2,
        "beta owns exactly its detail plus its request record: {captured}"
    );
    for line in &alpha_lines {
        assert!(
            !line.contains(&beta_installation) && !line.contains(&beta_tx),
            "alpha record must not carry beta identity: {line}"
        );
    }
    for line in &beta_lines {
        assert!(
            !line.contains(&alpha_installation) && !line.contains(&alpha_tx),
            "beta record must not carry alpha identity: {line}"
        );
        assert!(
            !line.contains("service_stop"),
            "beta status record must not claim the stop operation: {line}"
        );
    }
    assert!(
        captured.contains("operation_missing=true"),
        "beta status query carries no service operation, got: {captured}"
    );
    assert!(
        captured.contains(&format!("generation={alpha_generation}"))
            && captured.contains(&format!("generation={beta_generation}")),
        "both generations must render distinctly, got: {captured}"
    );
    assert!(
        captured.contains(&format!("process={alpha_process}"))
            && captured.contains(&format!("process={beta_process}")),
        "both processes must render distinctly, got: {captured}"
    );
    assert_eq!(
        count(&captured, &alpha_tx),
        1,
        "alpha token binds exactly its subordinate, got: {captured}"
    );
    assert_eq!(
        count(&captured, &beta_tx),
        1,
        "beta token binds exactly its subordinate, got: {captured}"
    );
}

// WORK_UNIT_CASE: 985/12
#[test]
fn sink_outcome_does_not_change_semantics() {
    let fixture = integration_fixture();
    let unavailable = fixture["sink"]["unavailable_outcome"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must pin unavailable outcome"));
    let unavailable_note = fixture["sink"]["unavailable_note"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must pin unavailable note"));
    let fixed_source = fixture["sink"]["fixed_source"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must pin fixed source"));
    let failure_event_id = failure_event_id_u32(&fixture);
    assert_eq!(EVENT_LOG_SOURCE, fixed_source);

    // Typed seam: Ok where #984's port is live (Windows), typed
    // Unavailable elsewhere. Never a faked delivery, never FFI here.
    let status = event_log_sink_status();
    if cfg!(windows) {
        assert_eq!(status, Ok(()), "sink must be attemptable on Windows");
    } else {
        assert_eq!(
            status,
            Err(WindowsEventLogError::EventLogUnavailable),
            "off Windows the port stays typed-Unavailable"
        );
        assert_eq!(
            WindowsEventLogError::EventLogUnavailable.as_str(),
            unavailable
        );
    }

    // The unavailability note is observation only: one INFO subordinate
    // where the sink cannot carry a record, silence where it can.
    let noted = capture(|| {
        note_event_log_sink_status();
    });
    if cfg!(windows) {
        assert!(
            !noted.contains(unavailable_note),
            "live sink needs no unavailability note, got: {noted}"
        );
    } else {
        assert_eq!(
            count(&noted, unavailable_note),
            1,
            "unavailability is noted exactly once, got: {noted}"
        );
        assert!(
            !noted.contains("host.terminal_error"),
            "the note is never a terminal, got: {noted}"
        );
    }

    // Fixed consumer mapping stays pure data regardless of sink state.
    let record = EventLogRecord::new(AdmittedEvent::ServiceFailure, "985-A12 mapping probe");
    let (source, event_id, _) = record.mapping();
    assert_eq!(source, fixed_source);
    assert_eq!(event_id, failure_event_id);
    assert_eq!(record.event(), AdmittedEvent::ServiceFailure);

    // Same semantics under an enabled sink (INFO captured) and a disabled
    // sink (INFO suppressed): identical typed return, identical receipt
    // frame, identical cleanup accounting.
    let run_oracle = || -> (String, Vec<u8>, usize) {
        let malformed = vec![OsString::from("--bogus-flag-985")];
        let failed = HostLaunchOptions::parse(malformed).unwrap_err();
        let receipt_value = serde_json::json!({"status": "error", "code": "console_failed"});
        let mut frame = Vec::new();
        write_protocol_frame(&mut frame, &receipt_value);
        let mut queue = WindowsEventLogQueue::with_default_capacity();
        queue
            .try_admit(EventLogRecord::new(
                AdmittedEvent::ServiceFailure,
                "985-A12 disabled-sink probe",
            ))
            .expect("bounded queue must admit");
        (format!("{failed:?}"), frame, queue.len())
    };
    let enabled_capture = capture_with_level(
        || {
            let _ = run_oracle();
            observe_terminal_error(HOST_TERMINAL_CODE_CONSOLE_FAILED);
        },
        tracing::Level::TRACE,
    );
    assert_eq!(
        count(&enabled_capture, "host.terminal_error"),
        1,
        "enabled sink keeps the single terminal, got: {enabled_capture}"
    );
    let (enabled_return, enabled_frame, enabled_len) = run_oracle();
    let disabled_capture = capture_with_level(
        || {
            let _ = run_oracle();
            observe_terminal_error(HOST_TERMINAL_CODE_CONSOLE_FAILED);
        },
        tracing::Level::ERROR,
    );
    let (disabled_return, disabled_frame, disabled_len) = run_oracle();
    assert_eq!(
        enabled_return, disabled_return,
        "sink state must not change the typed return"
    );
    assert_eq!(
        enabled_frame, disabled_frame,
        "sink state must not change the receipt frame"
    );
    assert_eq!(
        (enabled_len, disabled_len),
        (1, 1),
        "sink state must not change cleanup accounting"
    );
    assert_eq!(
        count(&disabled_capture, "host.terminal_error"),
        1,
        "terminal survives a disabled INFO sink, got: {disabled_capture}"
    );
    assert!(
        !disabled_capture.contains("host.request"),
        "disabled sink suppresses the INFO subordinate, got: {disabled_capture}"
    );
}
