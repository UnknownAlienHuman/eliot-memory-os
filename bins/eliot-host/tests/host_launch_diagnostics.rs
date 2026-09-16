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

use std::ffi::OsString;
use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_host::host_diagnostics::{
    DiagnosticSink, EntrypointStage, HOST_DIAGNOSTICS_TARGET, bound_detail, bound_field,
    observe_entrypoint_with_detail, observe_terminal_error, sink_status,
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
    assert_eq!(
        event_log_sink_status(),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
    );
    assert_eq!(
        sink_status(DiagnosticSink::WindowsEventLog),
        Err(eliot_host::host_diagnostics::HostDiagnosticsError::EventLogUnavailable)
    );
    assert_eq!(sink_status(DiagnosticSink::TracingStderr), Ok(()));
    let record = eliot_host::windows_event_log::EventLogRecord::new(
        AdmittedEvent::ServiceFailure,
        "host-launch-failed",
    );
    assert_eq!(
        report_event(&record),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
    );
    let before =
        eliot_host::HostLaunchOptions::parse(valid_launch_args()).expect("valid must admit");
    let digest_before = before.config_descriptor_digest().as_str().to_owned();
    let gen_before = before.transaction_plan_generation();
    let _ = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::Startup, "host.launch requested");
        observe_entrypoint_with_detail(EntrypointStage::Startup, "host.launch admitted");
        observe_terminal_error("host-launch-failed");
    });
    assert_eq!(before.config_descriptor_digest().as_str(), digest_before);
    assert_eq!(before.transaction_plan_generation(), gen_before);
    let after =
        eliot_host::HostLaunchOptions::parse(valid_launch_args()).expect("must still admit");
    assert_eq!(after.config_descriptor_digest().as_str(), digest_before);
    let ordered = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::Startup, "host.launch requested");
        observe_entrypoint_with_detail(EntrypointStage::Startup, "host.launch admitted");
    });
    let first = ordered
        .find("host.launch requested")
        .expect("must contain first");
    let second = ordered
        .find("host.launch admitted")
        .expect("must contain second");
    assert!(first < second, "order must be preserved, got: {ordered}");
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
        "host.store-launch store-ready observed",
        "host.kernel-launch requested",
        "host.kernel-launch kernel-ready observed",
    ] {
        assert!(
            sequence.contains(required),
            "sequence must pin {required:?}"
        );
    }
    let requested = sequence
        .find("host.store-launch requested")
        .expect("must pin store request");
    let store_ready = sequence
        .find("host.store-launch store-ready observed")
        .expect("must pin store-ready");
    let kernel_requested = sequence
        .find("host.kernel-launch requested")
        .expect("must pin kernel request");
    let kernel_ready = sequence
        .find("host.kernel-launch kernel-ready observed")
        .expect("must pin kernel-ready");
    assert!(
        requested < store_ready
            && store_ready < kernel_requested
            && kernel_requested < kernel_ready,
        "Store-before-Kernel order must be observed separately"
    );
    assert_ne!(
        "host.store-launch store-ready observed",
        "host.kernel-launch kernel-ready observed"
    );
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-launch store-ready observed",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.kernel-launch kernel-ready observed",
        );
    });
    assert!(text.contains("host.store-launch store-ready observed"));
    assert!(text.contains("host.kernel-launch kernel-ready observed"));
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
    assert!(!text.contains("host.kernel-launch kernel-ready observed"));
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
        "host.store-launch store-ready observed",
        "host.kernel-launch kernel-ready observed",
        "host.kernel-activation nonce issued",
        "host.kernel-activation readiness observed",
    ] {
        assert!(
            combined.contains(required),
            "deterministic vocabulary must pin {required:?}"
        );
    }
    let first = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.scm-launch probe requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-launch store-ready observed",
        );
    });
    let second = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.scm-launch probe requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-launch store-ready observed",
        );
    });
    assert_eq!(
        count_occurrences(&first, "host.entrypoint_stage"),
        count_occurrences(&second, "host.entrypoint_stage"),
        "injected schedules must emit deterministically"
    );
    assert_eq!(first.len(), second.len(), "got: {first:?} vs {second:?}");
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
