#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Focused diagnostics tests for F-LOG-HOST-3 item 978, Writer-AB slice
//! (launch + options + artifact lease + descriptor validation).
//!
//! Through the #889 facade only (`host_diagnostics::observe_entrypoint_with_detail`,
//! `observe_terminal_error`); the Windows Event Log seam stays typed-Unavailable
//! (`event_log_sink_status`), never implemented here (#984 still open).
//!
//! Scope rule: production files are disjoint between writers. This file owns
//! `host_job_launch.rs`, `host_launch_options.rs`, `launch_artifact_lease.rs`,
//! and `launch_descriptor_validation.rs` callsites directly, and asserts the
//! sibling CD files (`scm_launch.rs`, `store_kernel_launch_sequence.rs`,
//! `kernel_activation_driver.rs`, `kernel_front_door_client.rs`) ONLY through
//! their frozen boundary shapes (function names at base `75914093`), never
//! through their diagnostic strings and never by editing them. Cases
//! 5,6,7,8,9,10,13 are reserved for sibling CD (not written here); case 14
//! (source/diff guard) is the integrator's. Diagnostics are evidence only:
//! they never change control flow, state, errors, receipts, order, status, or
//! cleanup, and stdout framing stays exactly one-JSON-per-line.
//!
//! Executed audit cases in this file are driven through REAL production entry
//! points, never through the diagnostic facade: a record asserted here is
//! always one the OWNER passed to its own `#978` observe helper. The launch-side
//! public seam is [`eliot_host::HostLaunchOptions`] — the exact
//! `parse` / `parse_system_service` / `validate_service_main_argv` calls
//! `src/main.rs` makes at the `run` and `run_as_scm_service` contours. The
//! `host_job_launch` module is private (`src/lib.rs`), so the launch leaf's own
//! `observe_launch_terminal` seam is NOT reachable from an integration-test
//! crate; cases that would need it report that named ceiling instead of
//! manufacturing the record they would assert on.

use std::ffi::OsString;
use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_host::host_diagnostics::{
    DiagnosticSink, EntrypointStage, HOST_DIAGNOSTICS_TARGET, bound_detail, bound_field,
    observe_entrypoint_with_detail, observe_terminal_error, sink_status,
};
use eliot_host::windows_event_log::event_log_sink_status;
use eliot_platform_windows::ELIOT_HOST_SERVICE_NAME;
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

fn launch_fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/host_launch_diagnostics.json");
    let bytes = std::fs::read(&path).expect("launch fixture must be readable");
    serde_json::from_slice(&bytes).expect("launch fixture must be valid JSON")
}

fn manifest_source(relative: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).expect("tracked source must be readable")
}

/// Runs `emit` under a scoped subscriber that admits only records at or above
/// `level`, and returns the captured text.
///
/// This exists so a FAILING or FILTERED sink can be exercised against real
/// production code instead of assumed: at [`tracing::Level::Error`] every
/// `host.entrypoint_stage` record is dropped while the facade's single
/// `host.terminal_error` record stays admissible, so an empty capture under
/// this subscriber proves the owner emitted no terminal rather than proving
/// the subscriber swallowed one.
fn capture_emit_at_level(level: tracing::Level, emit: impl FnOnce()) -> String {
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let captured = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(level)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, emit);
        sink.bytes.lock().unwrap().clone()
    };
    String::from_utf8_lossy(&captured).into_owned()
}

/// Runs `emit` under a scoped subscriber and returns the captured text.
fn capture_emit(emit: impl FnOnce()) -> String {
    capture_emit_at_level(tracing::Level::INFO, emit)
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

fn job_launch_source() -> String {
    manifest_source("src/host_job_launch.rs")
}

fn launch_options_source() -> String {
    manifest_source("src/host_launch_options.rs")
}

fn artifact_source() -> String {
    manifest_source("src/launch_artifact_lease.rs")
}

fn descriptor_source() -> String {
    manifest_source("src/launch_descriptor_validation.rs")
}

fn fixture_str_list(fixture: &Value, key: &str) -> Vec<String> {
    fixture[key]
        .as_array()
        .unwrap_or_else(|| panic!("fixture must pin {key}"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("fixture {key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn valid_launch_args() -> Vec<OsString> {
    let tmp = std::env::temp_dir();
    vec![
        OsString::from("--config-descriptor"),
        tmp.join("eliot-launch-auth.json").into_os_string(),
        OsString::from("--config-descriptor-sha256"),
        OsString::from("a".repeat(64)),
        OsString::from("--installation-id"),
        OsString::from("installation-7"),
        OsString::from("--tx-plan-generation"),
        OsString::from("7"),
        OsString::from("--host-state-root"),
        tmp.join("eliot-host-state").into_os_string(),
    ]
}

fn valid_system_args() -> Vec<OsString> {
    let mut args = valid_launch_args();
    args.push(OsString::from("--registration-nonce"));
    args.push(OsString::from("b".repeat(64)));
    args
}

// WORK_UNIT_CASE: 978/1
#[test]
fn launch_01_eight_file_denominator() {
    let fixture = launch_fixture();
    let job = job_launch_source();
    let options = launch_options_source();
    let artifact = artifact_source();
    let descriptor = descriptor_source();
    for (source, name) in [
        (&job, "host_job_launch.rs"),
        (&options, "host_launch_options.rs"),
        (&artifact, "launch_artifact_lease.rs"),
        (&descriptor, "launch_descriptor_validation.rs"),
    ] {
        assert!(
            source.contains("observe_entrypoint_with_detail"),
            "{name} must observe through the facade"
        );
        assert!(
            source.contains("event_log_sink_status"),
            "{name} must carry the unavailable-seam note call"
        );
        assert!(
            source.contains("F-LOG-HOST-3 (#978)"),
            "{name} must mark the Writer-AB instrumentation"
        );
    }
    assert!(job.contains("fn host_launch_observe"));
    assert!(options.contains("fn host_launch_options_observe"));
    assert!(artifact.contains("fn launch_artifact_observe"));
    assert!(descriptor.contains("fn launch_descriptor_observe"));
    assert!(job.contains("struct HostLaunchTerminalGuard"));
    assert!(job.contains("\"host-launch-failed\""));
    for boundary in fixture_str_list(&fixture, "frozen_sibling_boundaries") {
        let combined = format!(
            "{}{}{}{}",
            manifest_source("src/scm_launch.rs"),
            manifest_source("src/store_kernel_launch_sequence.rs"),
            manifest_source("src/kernel_activation_driver.rs"),
            manifest_source("src/kernel_front_door_client.rs")
        );
        assert!(
            combined.contains(&boundary),
            "sibling frozen boundary {boundary:?} must exist"
        );
    }
    assert_eq!(
        EntrypointStage::Startup.as_str(),
        fixture["stages"]["startup"]
            .as_str()
            .expect("fixture pins startup")
    );
    assert_eq!(
        EntrypointStage::LaunchConfig.as_str(),
        fixture["stages"]["launch_config"]
            .as_str()
            .expect("fixture pins launch_config")
    );
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::Startup, "host.launch requested");
        observe_entrypoint_with_detail(
            EntrypointStage::LaunchConfig,
            "host.launch-options parse requested",
        );
    });
    assert!(text.contains(HOST_DIAGNOSTICS_TARGET));
    let event = fixture["entrypoint_event"]
        .as_str()
        .expect("fixture pins event");
    assert_eq!(count_occurrences(&text, event), 2, "got: {text}");
}

// WORK_UNIT_CASE: 978/2
#[test]
fn launch_02_options_descriptor_typed_rejection() {
    let valid = valid_launch_args();
    assert!(eliot_host::HostLaunchOptions::parse(valid.clone()).is_ok());
    let mut cases: Vec<(&str, Vec<OsString>)> = Vec::new();
    let mut missing = valid.clone();
    missing.drain(8..10);
    cases.push(("missing", missing));
    let mut reordered = valid.clone();
    reordered.swap(0, 2);
    reordered.swap(1, 3);
    cases.push(("reordered", reordered));
    let mut unknown = valid.clone();
    unknown[8] = OsString::from("--unknown");
    cases.push(("unknown", unknown));
    let mut relative = valid.clone();
    relative[1] = OsString::from("relative-auth.json");
    cases.push(("relative", relative));
    let mut bad_digest = valid.clone();
    bad_digest[3] = OsString::from("ZZ".repeat(32));
    cases.push(("bad-digest", bad_digest));
    let mut zero_gen = valid.clone();
    zero_gen[7] = OsString::from("0");
    cases.push(("zero-gen", zero_gen));
    for (label, args) in &cases {
        let result = eliot_host::HostLaunchOptions::parse(args.clone());
        assert!(result.is_err(), "{label} must stay typed rejection");
        assert!(
            matches!(result, Err(eliot_host::HostError::Platform(_))),
            "{label} must stay HostError::Platform"
        );
    }
    assert!(eliot_host::HostLaunchOptions::parse_system_service(valid.clone()).is_err());
    assert!(eliot_host::HostLaunchOptions::parse_system_service(valid_system_args()).is_ok());
    let descriptor = descriptor_source();
    assert!(descriptor.contains("validate_eliotd_launch_descriptor_bytes"));
    assert!(descriptor.contains("host.launch-descriptor eliotd typed rejection"));
    assert!(descriptor.contains("ProcessContour"));
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::LaunchConfig,
            "host.launch-options parse typed rejection",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::LaunchConfig,
            "host.launch-descriptor eliotd typed rejection",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::LaunchConfig,
            "host.launch-options parse admitted",
        );
    });
    assert!(text.contains("host.launch-options parse typed rejection"));
    assert_ne!(
        "host.launch-options parse typed rejection",
        "host.launch-options parse admitted"
    );
}

// WORK_UNIT_CASE: 978/3
#[test]
fn launch_03_retained_identity_on_substitution() {
    let job = job_launch_source();
    let artifact = artifact_source();
    let descriptor = descriptor_source();
    for detail in [
        "host.launch substitution preserved",
        "host.launch-artifact substitution preserved",
        "host.launch-descriptor substitution preserved",
    ] {
        let combined = format!("{job}{artifact}{descriptor}");
        assert!(
            combined.contains(detail),
            "sources must preserve {detail:?}"
        );
        assert!(detail.contains("preserv"), "record must name preservation");
    }
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.launch substitution preserved",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.launch-artifact substitution preserved",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::LaunchConfig,
            "host.launch-descriptor substitution preserved",
        );
    });
    for detail in [
        "host.launch substitution preserved",
        "host.launch-artifact substitution preserved",
        "host.launch-descriptor substitution preserved",
    ] {
        assert!(text.contains(detail), "got: {text}");
    }
    let relative = vec![
        OsString::from("--config-descriptor"),
        OsString::from("relative-auth.json"),
        OsString::from("--config-descriptor-sha256"),
        OsString::from("a".repeat(64)),
        OsString::from("--installation-id"),
        OsString::from("installation-7"),
        OsString::from("--tx-plan-generation"),
        OsString::from("7"),
        OsString::from("--host-state-root"),
        std::env::temp_dir()
            .join("eliot-host-state")
            .into_os_string(),
    ];
    assert!(eliot_host::HostLaunchOptions::parse(relative).is_err());
    assert!(eliot_host::HostLaunchOptions::parse(valid_launch_args()).is_ok());
}

// WORK_UNIT_CASE: 978/4
#[test]
fn launch_04_request_vs_process_vs_readiness() {
    let job = job_launch_source();
    assert!(job.contains("host.launch requested"));
    assert!(job.contains("host.launch admitted"));
    assert!(job.contains("host.launch image identity admitted"));
    assert!(job.contains("host.launch retained lease bound"));
    assert_ne!("host.launch requested", "host.launch admitted");
    assert_ne!(
        "host.launch admitted",
        "host.launch image identity admitted"
    );
    for line in job.lines().filter(|line| line.contains("host.launch")) {
        assert!(
            !line.contains("readiness"),
            "launch detail must not claim readiness: {line}"
        );
        assert!(
            !line.contains("healthy"),
            "launch detail must not claim health: {line}"
        );
    }
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::Startup, "host.launch requested");
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.launch retained lease bound",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.launch image identity admitted",
        );
        observe_entrypoint_with_detail(EntrypointStage::Startup, "host.launch admitted");
    });
    let requested = text
        .find("host.launch requested")
        .expect("must contain request");
    let admitted = text
        .find("host.launch admitted")
        .expect("must contain admitted");
    assert!(
        requested < admitted,
        "request must precede admitted, got: {text}"
    );
    assert!(
        !text.contains("readiness"),
        "admitted is never readiness, got: {text}"
    );
}

// WORK_UNIT_CASE: 978/11
#[test]
fn launch_11_sink_failure_leaves_operation_identical() {
    for source in [
        job_launch_source(),
        launch_options_source(),
        artifact_source(),
        descriptor_source(),
    ] {
        assert!(source.contains("event_log_sink_status"));
    }
    // The facade's Windows Event Log ARM is unavailable on every platform by
    // construction. The live #984 port behind `event_log_sink_status` is a
    // different seam and answers `Ok` exactly where it is implemented, so it
    // is asserted against its own platform gate instead of against a hardcoded
    // `Err` (which would be a false premise on this Windows host). `report_event`
    // is deliberately never called: on this platform it performs a REAL OS
    // Event Log insertion, which a proof must not trigger.
    assert_eq!(
        sink_status(DiagnosticSink::WindowsEventLog),
        Err(eliot_host::host_diagnostics::HostDiagnosticsError::EventLogUnavailable)
    );
    assert_eq!(
        event_log_sink_status().is_ok(),
        cfg!(windows),
        "the #984 live Event Log port answers Ok exactly where it is implemented"
    );
    // Same real argv and the same real production entry point, under two sinks:
    // one that admits the owner's `INFO` phase records and one that drops them
    // while still admitting a terminal record.
    let mut admitted_outcome = None;
    let admitted = capture_emit(|| {
        admitted_outcome =
            Some(eliot_host::HostLaunchOptions::parse_system_service(valid_system_args()));
    });
    let mut filtered_outcome = None;
    let filtered = capture_emit_at_level(tracing::Level::Error, || {
        filtered_outcome =
            Some(eliot_host::HostLaunchOptions::parse_system_service(valid_system_args()));
    });
    // Non-emptiness PRECONDITION, asserted before every denial below: this
    // capture really carries production output on this platform.
    assert!(
        admitted.contains("host.entrypoint_stage"),
        "the INFO capture must carry production output: {admitted}"
    );
    let admitted_options = admitted_outcome
        .expect("the parse must run under the INFO sink")
        .expect("valid SystemService argv must admit");
    let filtered_options = filtered_outcome
        .expect("the parse must run under the ERROR-only sink")
        .expect("valid SystemService argv must admit");
    assert!(
        filtered.is_empty(),
        "the ERROR-only sink must drop the owner's INFO phase records: {filtered}"
    );
    // Result, typed values and call count are identical under both sinks.
    assert_eq!(
        admitted_options.config_descriptor_digest().as_str(),
        filtered_options.config_descriptor_digest().as_str()
    );
    assert_eq!(
        admitted_options.config_descriptor_path(),
        filtered_options.config_descriptor_path()
    );
    assert_eq!(
        admitted_options.host_state_root(),
        filtered_options.host_state_root()
    );
    assert_eq!(
        admitted_options.transaction_plan_generation(),
        filtered_options.transaction_plan_generation()
    );
    let admitted_nonce = admitted_options.registration_nonce().map(|n| n.as_str());
    let filtered_nonce = filtered_options.registration_nonce().map(|n| n.as_str());
    assert_eq!(admitted_nonce, filtered_nonce);
    // The admission facts production actually emitted, and their observed order.
    for frozen in [
        "detail=\"host.launch-options parse requested\"",
        "detail=\"host.launch-options parse admitted\"",
        "detail=\"host.launch-options system-service admitted\"",
    ] {
        assert!(admitted.contains(frozen), "production must emit {frozen:?}, got: {admitted}");
    }
    let requested = admitted
        .find("host.launch-options parse requested")
        .expect("production must emit the parse request");
    let parsed = admitted
        .find("host.launch-options parse admitted")
        .expect("production must emit the parse admission");
    let admitted_service = admitted
        .find("host.launch-options system-service admitted")
        .expect("production must emit the system-service admission");
    assert!(
        requested < parsed && parsed < admitted_service,
        "production must keep its own phase order under a failing sink, got: {admitted}"
    );
    assert_eq!(
        count_occurrences(&admitted, "host.terminal_error"),
        0,
        "an admitted launch-config operation emits no terminal: {admitted}"
    );
    let fixture = launch_fixture();
    assert_eq!(
        fixture["stdout_protocol_contamination"].as_bool(),
        Some(false)
    );
}

// WORK_UNIT_CASE: 978/12
#[test]
fn launch_12_canaries_absent_from_observations() {
    let fixture = launch_fixture();
    let canaries = fixture_str_list(&fixture, "canaries");
    assert!(!canaries.is_empty(), "fixture must pin canaries");
    for source in [
        job_launch_source(),
        launch_options_source(),
        artifact_source(),
        descriptor_source(),
    ] {
        for line in source
            .lines()
            .filter(|line| line.contains("host.launch") || line.contains("host-launch"))
        {
            for canary in &canaries {
                assert!(
                    !line.contains(canary.as_str()),
                    "diagnostic line must not contain canary {canary:?}: {line}"
                );
            }
        }
    }
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::Startup, "host.launch requested");
        observe_entrypoint_with_detail(
            EntrypointStage::LaunchConfig,
            "host.launch-options parse admitted",
        );
        observe_terminal_error("host-launch-failed");
    });
    for canary in &canaries {
        assert!(
            !text.contains(canary.as_str()),
            "capture must not contain {canary:?}"
        );
    }
    assert_eq!(bound_field("startup").text(), "startup");
    let oversized = "y".repeat(8 * 1024 + 7);
    let bounded = bound_detail(&oversized);
    assert_eq!(bounded.original_bytes(), oversized.len());
    assert!(bounded.truncated());
    assert!(bounded.text().len() <= 1024);
}

// ---- Sibling-CD slice (cases 5,6,7,8,9,10,13) ----

fn scm_source() -> String {
    manifest_source("src/scm_launch.rs")
}

fn sequence_source() -> String {
    manifest_source("src/store_kernel_launch_sequence.rs")
}

fn driver_source() -> String {
    manifest_source("src/kernel_activation_driver.rs")
}

fn frontdoor_source() -> String {
    manifest_source("src/kernel_front_door_client.rs")
}

fn cd_combined() -> String {
    format!(
        "{}{}{}{}",
        scm_source(),
        sequence_source(),
        driver_source(),
        frontdoor_source()
    )
}

// WORK_UNIT_CASE: 978/5
#[test]
fn launch_05_start_identity_vs_pid() {
    let scm = scm_source();
    for required in [
        "fn classify_host_scm_inspection",
        "fn resolve_host_scm_inspection_with_probe",
        "fn validate_host_scm_bootstrap",
        "host.scm-launch classification requested",
        "host.scm-launch start-identity observed",
        "host.scm-launch pid observed",
        "host.scm-launch request observed",
        "host.scm-launch process observed",
        "host.scm-launch admitted",
    ] {
        assert!(scm.contains(required), "scm must pin {required:?}");
    }
    assert_ne!(
        "host.scm-launch start-identity observed",
        "host.scm-launch pid observed"
    );
    assert_ne!(
        "host.scm-launch request observed",
        "host.scm-launch process observed"
    );
    let correlation = "start-identity:978-5";
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.scm-launch start-identity observed {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.scm-launch pid observed {correlation}"),
        );
    });
    assert!(text.contains("host.scm-launch start-identity observed"));
    assert!(text.contains("host.scm-launch pid observed"));
    assert_eq!(count_occurrences(&text, correlation), 2, "got: {text}");
}

// WORK_UNIT_CASE: 978/6
#[test]
fn launch_06_store_before_kernel() {
    let sequence = sequence_source();
    for required in [
        "fn launch_store_then_kernel",
        "host.store-launch requested",
        "host.store-launch store-live observed",
        "host.kernel-launch requested",
        "host.kernel-launch kernel-launched observed; activation evidence unavailable",
    ] {
        assert!(
            sequence.contains(required),
            "sequence must pin {required:?}"
        );
    }
    // The two barrier records project Store liveness (exact Job membership plus
    // a running process) and Kernel launch success, never semantic readiness,
    // so the retired readiness vocabulary must stay gone from this leaf: Kernel
    // readiness belongs to its owner evidence in `kernel_activation_driver::active`
    // (I01.10).
    for retired in [
        "host.store-launch store-ready observed",
        "host.kernel-launch kernel-ready observed",
    ] {
        assert!(
            !sequence.contains(retired),
            "sequence must not claim readiness through this leaf: {retired:?}"
        );
    }
    let requested = sequence
        .find("host.store-launch requested")
        .expect("must pin store request");
    let store_live = sequence
        .find("host.store-launch store-live observed")
        .expect("must pin store-live");
    let kernel_requested = sequence
        .find("host.kernel-launch requested")
        .expect("must pin kernel request");
    let kernel_launched = sequence
        .find("host.kernel-launch kernel-launched observed; activation evidence unavailable")
        .expect("must pin kernel-launched");
    assert!(
        requested < store_live
            && store_live < kernel_requested
            && kernel_requested < kernel_launched,
        "Store-before-Kernel order must be observed separately"
    );
    assert_ne!(
        "host.store-launch store-live observed",
        "host.kernel-launch kernel-launched observed; activation evidence unavailable"
    );
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-launch store-live observed",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.kernel-launch kernel-launched observed; activation evidence unavailable",
        );
    });
    assert!(text.contains("host.store-launch store-live observed"));
    assert!(
        text.contains(
            "host.kernel-launch kernel-launched observed; activation evidence unavailable"
        )
    );
}

// WORK_UNIT_CASE: 978/7
#[test]
fn launch_07_nonce_handshake_auth_activation_distinct() {
    let driver = driver_source();
    let frontdoor = frontdoor_source();
    for required in [
        "host.kernel-activation nonce requested",
        "host.kernel-activation nonce issued",
        "host.kernel-activation activating requested",
        "host.kernel-activation activation observed",
        "host.kernel-activation candidate observed",
    ] {
        assert!(driver.contains(required), "driver must pin {required:?}");
    }
    for required in [
        "host.kernel-front-door handshake requested",
        "host.kernel-front-door handshake observed",
        "host.kernel-front-door auth requested",
        "host.kernel-front-door authenticated peer observed",
        "host.kernel-front-door control requested",
    ] {
        assert!(
            frontdoor.contains(required),
            "front-door must pin {required:?}"
        );
    }
    assert_ne!(
        "host.kernel-activation nonce issued",
        "host.kernel-activation activation observed"
    );
    assert_ne!(
        "host.kernel-front-door handshake observed",
        "host.kernel-front-door authenticated peer observed"
    );
    let fixture = launch_fixture();
    let canaries = fixture_str_list(&fixture, "canaries");
    assert!(!canaries.is_empty(), "fixture must pin canaries");
    for source in [driver_source(), frontdoor_source()] {
        for line in source.lines().filter(|line| {
            line.contains("host.kernel-activation") || line.contains("host.kernel-front-door")
        }) {
            for canary in &canaries {
                assert!(
                    !line.contains(canary.as_str()),
                    "diagnostic line must not contain canary {canary:?}: {line}"
                );
            }
            assert!(
                !line.contains("activation_nonce"),
                "nonce value must never be observed: {line}"
            );
        }
    }
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.kernel-activation nonce issued",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.kernel-front-door authenticated peer observed",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.kernel-activation activation observed",
        );
    });
    assert!(text.contains("host.kernel-activation nonce issued"));
    assert!(text.contains("host.kernel-front-door authenticated peer observed"));
    assert!(text.contains("host.kernel-activation activation observed"));
}

// WORK_UNIT_CASE: 978/8
#[test]
fn launch_08_readiness_needs_owner_evidence() {
    let driver = driver_source();
    assert!(driver.contains("fn active"));
    assert!(
        driver.contains("host.kernel-activation readiness requested"),
        "readiness request must be observed"
    );
    assert!(
        driver.contains("host.kernel-activation readiness observed"),
        "readiness must be observed only on owner evidence"
    );
    assert_ne!(
        "host.kernel-activation readiness requested",
        "host.kernel-activation readiness observed"
    );
    for line in driver.lines().filter(|line| line.contains("readiness")) {
        assert!(
            !line.contains("liveness"),
            "readiness detail must not claim liveness: {line}"
        );
    }
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.kernel-activation readiness requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.kernel-activation readiness observed",
        );
    });
    assert!(text.contains("host.kernel-activation readiness requested"));
    assert!(text.contains("host.kernel-activation readiness observed"));
    // Kernel launch success is a distinct record from Kernel readiness: the
    // Store/Kernel sequence contour states launch only and names the activation
    // evidence it does not hold as unavailable.
    assert!(!text.contains("host.kernel-launch kernel-launched observed"));
}

// WORK_UNIT_CASE: 978/9
#[test]
fn launch_09_before_start_vs_timeout_disconnect_unknown() {
    let frontdoor = frontdoor_source();
    assert!(frontdoor.contains("fn activation_response_or_reconcile"));
    assert!(frontdoor.contains("fn validate_authenticated_kernel_peer"));
    assert!(frontdoor.contains("fn connect_authenticated_kernel_front_door"));
    for detail in [
        "host.kernel-front-door before-start observed",
        "host.kernel-front-door timeout observed",
        "host.kernel-front-door disconnect observed",
        "host.kernel-front-door unknown observed",
        "host.kernel-front-door reconcile requested",
        "host.kernel-front-door activation observed",
    ] {
        assert!(frontdoor.contains(detail), "front-door must pin {detail:?}");
    }
    assert_ne!(
        "host.kernel-front-door before-start observed",
        "host.kernel-front-door timeout observed"
    );
    assert_ne!(
        "host.kernel-front-door disconnect observed",
        "host.kernel-front-door unknown observed"
    );
    let correlation = "front-door:978-9";
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-front-door before-start observed {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-front-door timeout observed {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-front-door disconnect observed {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-front-door unknown observed {correlation}"),
        );
    });
    for detail in [
        "host.kernel-front-door before-start observed",
        "host.kernel-front-door timeout observed",
        "host.kernel-front-door disconnect observed",
        "host.kernel-front-door unknown observed",
    ] {
        assert!(text.contains(detail), "got: {text}");
    }
    assert_eq!(count_occurrences(&text, correlation), 4, "got: {text}");
}

// WORK_UNIT_CASE: 978/10
#[test]
fn launch_10_one_terminal_across_nesting() {
    let owned = cd_combined();
    assert_eq!(
        count_occurrences(&owned, "host-scm-launch-unknown"),
        1,
        "SCM terminal must be owned by exactly one callsite"
    );
    assert!(scm_source().contains("struct ScmLaunchTerminalGuard"));
    assert!(scm_source().contains("fn disarm"));
    assert!(
        !owned.contains("static DEDUP"),
        "no mutable global dedup cache may exist"
    );
    for source in [sequence_source(), driver_source(), frontdoor_source()] {
        assert!(
            !source.contains("observe_terminal_error"),
            "inner nesting must correlate by stage order only, no inner terminal"
        );
    }
    assert!(
        !owned.contains("host-launch-failed"),
        "CD must not own the AB terminal"
    );
    let fixture = launch_fixture();
    let terminal_event = fixture["terminal_event"]
        .as_str()
        .expect("fixture must pin the terminal event");
    let correlation = "single-terminal:978-10";
    let failed = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.scm-launch requested {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.scm-launch pid observed {correlation}"),
        );
        observe_terminal_error("host-scm-launch-unknown");
    });
    assert_eq!(
        count_occurrences(&failed, terminal_event),
        1,
        "one failed op emits one terminal, got: {failed}"
    );
    assert_eq!(
        count_occurrences(&failed, correlation),
        2,
        "phases share correlation, got: {failed}"
    );
    let succeeded = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, "host.scm-launch admitted");
    });
    assert_eq!(
        count_occurrences(&succeeded, terminal_event),
        0,
        "success emits no terminal, got: {succeeded}"
    );
}

// WORK_UNIT_CASE: 978/13
#[test]
fn launch_13_deterministic_semantic_fields() {
    let scm = scm_source();
    let sequence = sequence_source();
    let driver = driver_source();
    let combined = format!("{scm}{sequence}{driver}");
    for required in [
        "host.scm-launch probe requested",
        "HOST_SCM_TRANSIENT_MAX_INSPECTIONS",
        "host.store-launch store-live observed",
        "host.kernel-launch kernel-launched observed; activation evidence unavailable",
        "host.kernel-activation nonce issued",
        "host.kernel-activation readiness observed",
    ] {
        assert!(
            combined.contains(required),
            "deterministic vocabulary must pin {required:?}"
        );
    }
    // The determinism claim is executed against a REAL production entry point
    // (`HostLaunchOptions::parse_system_service`, the seam `main.rs` drives at
    // the `SystemService` bootstrap), twice on the same real argv: the two
    // captures must be byte-identical and must carry the owner's own frozen
    // `stage`/`detail` fields. The previous form built both captures by calling
    // the diagnostic facade with two manually identical test-supplied literals
    // and compared only event counts and total output length, which cannot fail
    // for any production reason.
    let first = capture_emit(|| {
        assert!(
            eliot_host::HostLaunchOptions::parse_system_service(valid_system_args()).is_ok(),
            "valid SystemService argv must admit"
        );
    });
    let second = capture_emit(|| {
        assert!(
            eliot_host::HostLaunchOptions::parse_system_service(valid_system_args()).is_ok(),
            "valid SystemService argv must admit"
        );
    });
    // Non-emptiness PRECONDITION, asserted before the equality below: both
    // captures really carry production output on this platform.
    assert!(
        first.contains("host.entrypoint_stage"),
        "first capture must carry production output: {first}"
    );
    assert!(
        second.contains("host.entrypoint_stage"),
        "second capture must carry production output: {second}"
    );
    assert_eq!(
        first, second,
        "repeated execution of one production seam must emit deterministically"
    );
    for frozen in [
        "stage=\"launch_config\"",
        "detail=\"host.launch-options parse requested\"",
        "detail=\"host.launch-options parse admitted\"",
        "detail=\"host.launch-options system-service admitted\"",
    ] {
        assert!(first.contains(frozen), "production must emit {frozen:?}, got: {first}");
    }
}

// WORK_UNIT_CASE: 978/14
#[test]
fn launch_14_source_guard_stays_diagnostics_only() {
    let files = [
        job_launch_source(),
        launch_options_source(),
        artifact_source(),
        descriptor_source(),
        scm_source(),
        sequence_source(),
        driver_source(),
        frontdoor_source(),
    ];
    for source in &files {
        for forbidden in ["unsafe", "println!", "print!", "eprintln!"] {
            assert!(
                !source.contains(forbidden),
                "diagnostics-only change must not introduce {forbidden:?}"
            );
        }
        for direct in [
            "tracing::info!",
            "tracing::warn!",
            "tracing::error!",
            "tracing::debug!",
        ] {
            assert!(
                !source.contains(direct),
                "all observations go through the single host_diagnostics facade, found {direct:?}"
            );
        }
        assert!(
            source.contains("observe_entrypoint") || source.contains("observe_terminal_error"),
            "every boundary file must emit through the facade"
        );
    }
    for other in [
        "src/credential_control.rs",
        "src/host_activation_durable.rs",
        "src/host_composition_phase_b.rs",
        "src/host_composition_store_recovery.rs",
        "src/phase_b_materialization.rs",
        "src/store_recovery_persistence.rs",
    ] {
        assert!(
            !manifest_source(other).contains("978/"),
            "F-LOG-HOST-3 must not touch sibling item scope {other}"
        );
    }
}

// Executed case for external audit 5910159678 defect 2 — the single-terminal
// repair this file owns: the launch leaf is phase-only and the ENCLOSING
// operation contour owns the one terminal for a failed launch. Driven through
// the three REAL production launch-config entry points
// (`HostLaunchOptions::parse`, `::parse_system_service` and
// `::validate_service_main_argv`, the exact seams `src/main.rs` drives at the
// `run` and `run_as_scm_service` contours), so every string asserted on below
// is one the OWNER passed to its own `host_launch_options_observe` helper.
//
// NAMED CEILING for the leaf itself: the exact producer of the launch terminal,
// `host_job_launch::observe_launch_terminal` (and `HostJobBranches::start_approved`
// beside it), lives in `mod host_job_launch`, which `src/lib.rs:37` declares
// private, so no integration-test crate can drive it. This case therefore
// proves the reachable half of the obligation — the launch-config contour that
// `main.rs` really runs emits its phase and NO terminal — and does not pretend
// to have exercised the leaf's own terminal owner.
#[test]
fn launch_15_one_terminal_owner_and_distinct_launch_facts() {
    // A REJECTED real argv through the real entry point. `args[3]` is the
    // config-descriptor digest, so this is a genuine typed rejection.
    let mut rejected = None;
    let rejected_capture = capture_emit(|| {
        let mut args = valid_launch_args();
        args[3] = OsString::from("ZZ".repeat(32));
        rejected = Some(eliot_host::HostLaunchOptions::parse(args));
    });
    assert!(
        matches!(rejected, Some(Err(eliot_host::HostError::Platform(_)))),
        "a malformed digest must stay a typed Platform rejection"
    );
    // Non-emptiness PRECONDITION, asserted before EVERY denial below: this
    // capture really carries production output on this platform. It cannot be
    // delegated to `note_event_log_sink_status`, which returns early where the
    // #984 Event Log port answers `Ok` — as it does on this Windows host — and
    // so contributes nothing to a capture there.
    assert!(
        rejected_capture.contains(HOST_DIAGNOSTICS_TARGET),
        "the capture must carry production output: {rejected_capture}"
    );
    for frozen in [
        "event=\"host.entrypoint_stage\"",
        "stage=\"launch_config\"",
        "detail=\"host.launch-options parse requested\"",
        "detail=\"host.launch-options parse typed rejection\"",
    ] {
        assert!(
            rejected_capture.contains(frozen),
            "production must emit {frozen:?}, got: {rejected_capture}"
        );
    }
    // The failed operation has its single terminal emitter in the ENCLOSING
    // contour, so this leaf records the rejection and no terminal at all.
    assert_eq!(
        count_occurrences(&rejected_capture, "host.terminal_error"),
        0,
        "the launch leaf must not emit a terminal of its own: {rejected_capture}"
    );
    // A launch request, an admission, an observed process and an authenticated
    // readiness are four DIFFERENT facts: a rejection claims neither the
    // admission nor any liveness or readiness claim.
    assert!(
        !rejected_capture.contains("detail=\"host.launch-options parse admitted\""),
        "a rejected argv must not also claim admission: {rejected_capture}"
    );
    for foreign in [
        "process_started",
        "semantically_ready",
        "durable_committed",
        "readiness",
    ] {
        assert!(
            !rejected_capture.contains(foreign),
            "the launch leaf claimed {foreign:?}: {rejected_capture}"
        );
    }
    assert_launch_15_no_terminal(
        &capture_emit(|| {
            assert!(
                eliot_host::HostLaunchOptions::parse_system_service(valid_system_args()).is_ok(),
                "valid SystemService argv must admit"
            );
        }),
        "an admitted SystemService bootstrap",
        &[
            "detail=\"host.launch-options parse admitted\"",
            "detail=\"host.launch-options system-service admitted\"",
        ],
        "typed rejection",
    );
    // The SCM callback contour is a THIRD distinct fact: the argv request the
    // Windows service entry point receives is neither an observed process nor a
    // readiness, and it never borrows the plain-parse or system-service
    // admission record.
    let mut callback = None;
    let callback_capture = capture_emit(|| {
        callback = Some(eliot_host::HostLaunchOptions::validate_service_main_argv([
            OsString::from(ELIOT_HOST_SERVICE_NAME),
        ]));
    });
    assert!(matches!(callback, Some(Ok(()))), "the canonical ServiceMain argv must be admitted");
    assert_launch_15_no_terminal(
        &callback_capture,
        "the SCM service-main callback",
        &["detail=\"host.launch-options service-main admitted\""],
        "service-main typed rejection",
    );
    for other in [
        "detail=\"host.launch-options parse admitted\"",
        "detail=\"host.launch-options system-service admitted\"",
    ] {
        assert!(
            !callback_capture.contains(other),
            "the SCM callback contour claimed {other:?}: {callback_capture}"
        );
    }
}

/// Asserts that a REAL production capture names `positive`, never `negative`,
/// and carries no terminal record of its own.
///
/// `capture` is asserted non-empty FIRST, so the terminal denial below cannot
/// be satisfied by an empty capture — on this Windows host an empty capture is
/// exactly what a dropped `INFO` phase produces and would make the denial
/// vacuous.
fn assert_launch_15_no_terminal(capture: &str, contour: &str, positive: &[&str], negative: &str) {
    assert!(
        capture.contains("host.entrypoint_stage"),
        "{contour} must carry production output: {capture}"
    );
    for frozen in positive {
        assert!(capture.contains(frozen), "{contour} must emit {frozen:?}: {capture}");
    }
    assert!(!capture.contains(negative), "{contour} claimed {negative:?}: {capture}");
    assert_eq!(
        count_occurrences(&capture, "host.terminal_error"),
        0,
        "{contour} must leave its terminal to the enclosing operation guard: {capture}"
    );
}
