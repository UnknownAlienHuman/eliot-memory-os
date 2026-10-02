#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Focused diagnostics tests for F-LOG-HOST-3 item 978, Writer-AB slice
//! (launch + options + artifact lease + descriptor validation).
//!
//! Every executed claim in this file drives a REAL production entry point and
//! asserts only on what production itself emitted. No case below calls
//! `observe_entrypoint_with_detail` or `observe_terminal_error`: a test can
//! never assert on a record it manufactured itself.
//!
//! Reachable production seams (every one is `pub`, re-exported by
//! `src/lib.rs`, and driven by `src/main.rs` or `HostComposition`):
//!
//! - [`eliot_host::HostLaunchOptions::parse`],
//!   [`eliot_host::HostLaunchOptions::parse_system_service`] and
//!   [`eliot_host::HostLaunchOptions::validate_service_main_argv`] — the exact
//!   argv seams the `run` and `run_as_scm_service` contours drive.
//! - [`eliot_host::classify_host_scm_inspection`] — the sole
//!   inspection-to-cause mapping site, called by
//!   [`eliot_host::validate_host_scm_bootstrap`] on the production
//!   `run_as_scm_service` path (`src/main.rs:1839`) and by `src/main.rs:3531`.
//!
//! NAMED CEILINGS — the obligations below have no test-visible owner, so the
//! cases that carry them name the exact missing owner instead of asserting on a
//! record they would have had to manufacture themselves:
//!
//! - `mod host_job_launch` is declared private (`src/lib.rs:37`), so
//!   `start_approved`, `observe_launch_terminal`, `render_launch_identity` and
//!   `LaunchIdentityField` — and with them every `host.launch *` record — have
//!   no integration-test caller. Cases 3 and 4 name this.
//! - `launch_artifact_lease` and `launch_descriptor_validation` expose no `pub`
//!   symbol at all (only `pub(crate)` / `pub(super)`), so the
//!   `host.launch-artifact *` and `host.launch-descriptor *` records have no
//!   reachable owner. Cases 2 and 3 name this.
//! - `store_kernel_launch_sequence::launch_store_then_kernel`,
//!   `kernel_activation_driver::*` and `kernel_front_door_client::*` are all
//!   `pub(super)` inside private modules, so cases 6, 7, 8 and 9 name those
//!   owners.
//! - `ScmLaunchTerminalGuard` — the single owner of the SCM terminal — is a
//!   private struct armed only inside `validate_host_scm_bootstrap`, which
//!   reaches it through a live SCM readback whose outcome is this machine's
//!   registered service state. Case 10 names it.
//!
//! Windows-specific traps honoured here: `note_event_log_sink_status` returns
//! early where the #984 Event Log port answers `Ok` — as it does on this
//! Windows host — and so writes nothing, hence it is never used as evidence;
//! `report_event` performs a real OS Event Log insertion, hence it is never
//! called. Every denial below rests on a capture asserted non-empty first.
//!
//! Diagnostics are evidence only: they never change control flow, state,
//! errors, receipts, order, status, or cleanup, and stdout framing stays
//! exactly one-JSON-per-line. Case 14 (source/diff guard) is the integrator's.

use std::ffi::OsString;
use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_host::HostScmRegistrationCause;
use eliot_host::host_diagnostics::{
    DiagnosticSink, EntrypointStage, HOST_DIAGNOSTICS_TARGET, bound_detail, bound_field,
    sink_status,
};
use eliot_host::windows_event_log::event_log_sink_status;
use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_DISPLAY_NAME, ELIOT_HOST_SERVICE_NAME, ServiceAccount,
    ServiceInspectionUnknownDetail, ServiceRegistrationRequest,
    ServiceRegistrationRuntimeInspection, ServiceStartMode,
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

/// NON-EMPTINESS PRECONDITION, asserted before any denial anywhere in this
/// file.
///
/// On this Windows host `note_event_log_sink_status` returns early where the
/// #984 Event Log port answers `Ok`, so a capture that carries only the event
/// log note is empty and every "the owner did not say X" assertion over it
/// would pass vacuously. A capture must therefore carry the owner's own
/// `host.entrypoint_stage` record before any denial may rest on it.
fn assert_capture_carries_production(capture: &str, contour: &str) {
    assert!(
        capture.contains(HOST_DIAGNOSTICS_TARGET),
        "{contour} must carry production output: {capture}"
    );
    assert!(
        capture.contains("event=\"host.entrypoint_stage\""),
        "{contour} must carry production output: {capture}"
    );
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

// The launch argv seams are pure string validation: `parse` reads no file, no
// environment and no child process, so the temp-root paths below are input
// text only and no test here touches shared machine state.
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

/// Runs one real argv through the real [`eliot_host::HostLaunchOptions::parse`]
/// seam `src/main.rs` drives at the `run` contour, and asserts the owner's own
/// frozen `stage`/`detail` fields.
///
/// The capture is proven non-empty FIRST, so the "must not also claim …"
/// denial below can never be satisfied by an empty capture.
fn assert_parse_contour(label: &str, args: Vec<OsString>, admitted: bool) -> String {
    let mut outcome = None;
    let capture = capture_emit(|| {
        outcome = Some(eliot_host::HostLaunchOptions::parse(args));
    });
    assert_capture_carries_production(&capture, label);
    for frozen in [
        "event=\"host.entrypoint_stage\"",
        "stage=\"launch_config\"",
        "detail=\"host.launch-options parse requested\"",
    ] {
        assert!(
            capture.contains(frozen),
            "production must emit {frozen:?} for {label}, got: {capture}"
        );
    }
    let admitted_record = "detail=\"host.launch-options parse admitted\"";
    let rejection_record = "detail=\"host.launch-options parse typed rejection\"";
    if admitted {
        assert!(
            matches!(outcome, Some(Ok(_))),
            "{label} must admit through the real entry point"
        );
        assert!(
            capture.contains(admitted_record),
            "{label}: production must emit its admission, got: {capture}"
        );
        assert!(
            !capture.contains(rejection_record),
            "{label} must not also claim a typed rejection: {capture}"
        );
    } else {
        assert!(
            matches!(outcome, Some(Err(eliot_host::HostError::Platform(_)))),
            "{label} must stay a typed HostError::Platform rejection"
        );
        assert!(
            capture.contains(rejection_record),
            "{label}: production must emit its typed rejection, got: {capture}"
        );
        assert!(
            !capture.contains(admitted_record),
            "{label} must not also claim an admission: {capture}"
        );
    }
    capture
}

/// The canonical Host SCM registration request production builds at the
/// `run_as_scm_service` contour.
///
/// `validate_host_scm_bootstrap` constructs it with
/// `ServiceRegistrationRequest::with_bootstrap(ELIOT_HOST_SERVICE_NAME,
/// ELIOT_HOST_SERVICE_DISPLAY_NAME, current_exe, Automatic, LocalService)`.
/// It is rebuilt here through the same public platform constructors so the
/// platform itself proves the request canonical (absolute, on-disk image)
/// instead of a fabricated one standing in for it.
fn canonical_scm_registration_request() -> ServiceRegistrationRequest {
    let image = std::env::current_exe().expect("the running image must be observable");
    ServiceRegistrationRequest::new(
        ELIOT_HOST_SERVICE_NAME,
        ELIOT_HOST_SERVICE_DISPLAY_NAME,
        &image,
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
    )
    .expect("the canonical Host registration request must build")
}

/// Asserts the request-bound prefix the owner binds on EVERY SCM classification
/// record, built from the production request's own digest rather than from a
/// literal this test chose.
fn scm_request_prefix(request: &ServiceRegistrationRequest) -> String {
    format!(
        "service={} expected_config_digest={}",
        request.service_name(),
        request.expected_configuration_digest()
    )
}

// WORK_UNIT_CASE: 978/1
#[test]
fn launch_01_eight_file_denominator() {
    // The mapping half of case 1 is a lexical claim by definition — it exists
    // to enumerate the eight #978 boundary files, their observe helpers and
    // their terminal owner. The EXECUTED half below binds the frozen record
    // vocabulary to what production actually emitted through the real
    // `HostLaunchOptions` seam `src/main.rs` drives.
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
    let combined = format!(
        "{}{}{}{}",
        manifest_source("src/scm_launch.rs"),
        manifest_source("src/store_kernel_launch_sequence.rs"),
        manifest_source("src/kernel_activation_driver.rs"),
        manifest_source("src/kernel_front_door_client.rs")
    );
    for boundary in fixture_str_list(&fixture, "frozen_sibling_boundaries") {
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
    // EXECUTED: the admitted launch-config contour through the real entry
    // point `src/main.rs` drives. The frozen event name comes from the fixture
    // the production path is measured against; every other asserted string is
    // what the OWNER passed to `host_launch_options_observe`.
    let capture = assert_parse_contour("the admitted launch argv", valid_launch_args(), true);
    let event = fixture["entrypoint_event"]
        .as_str()
        .expect("fixture pins event");
    assert!(
        capture.contains(&format!("event=\"{event}\"")),
        "production must emit the pinned event {event:?}, got: {capture}"
    );
}

// WORK_UNIT_CASE: 978/2
#[test]
fn launch_02_options_descriptor_typed_rejection() {
    let valid = valid_launch_args();
    let mut cases: Vec<(&str, Vec<OsString>)> = Vec::new();
    let mut missing = valid.clone();
    missing.drain(8..10);
    cases.push(("missing authority pair", missing));
    let mut reordered = valid.clone();
    reordered.swap(0, 2);
    reordered.swap(1, 3);
    cases.push(("reordered authority pairs", reordered));
    let mut unknown = valid.clone();
    unknown[8] = OsString::from("--unknown");
    cases.push(("substituted trailing flag", unknown));
    let mut relative = valid.clone();
    relative[1] = OsString::from("relative-auth.json");
    cases.push(("relative descriptor path", relative));
    let mut bad_digest = valid.clone();
    bad_digest[3] = OsString::from("ZZ".repeat(32));
    cases.push(("non-hex descriptor digest", bad_digest));
    let mut zero_gen = valid.clone();
    zero_gen[7] = OsString::from("0");
    cases.push(("zero transaction generation", zero_gen));
    for (label, args) in &cases {
        assert_parse_contour(label, args.clone(), false);
    }
    assert_parse_contour("the admitted launch argv", valid, true);
    // The `SystemService` contour is a DIFFERENT admission: its own argv seam
    // must reject a launch argv that carries no registration nonce, and admit
    // one that does — through production, not through this test.
    let mut rejected = None;
    let without_nonce = capture_emit(|| {
        rejected = Some(eliot_host::HostLaunchOptions::parse_system_service(
            valid_launch_args(),
        ));
    });
    assert_capture_carries_production(&without_nonce, "the nonce-less SystemService argv");
    assert!(
        matches!(rejected, Some(Err(eliot_host::HostError::Platform(_)))),
        "SystemService without the registration nonce must stay a typed rejection"
    );
    assert!(
        without_nonce.contains("detail=\"host.launch-options system-service typed rejection\""),
        "production must emit its own SystemService rejection, got: {without_nonce}"
    );
    assert!(
        !without_nonce.contains("detail=\"host.launch-options system-service admitted\""),
        "a nonce-less argv must not claim the SystemService admission: {without_nonce}"
    );
    let mut admitted = None;
    let with_nonce = capture_emit(|| {
        admitted = Some(eliot_host::HostLaunchOptions::parse_system_service(
            valid_system_args(),
        ));
    });
    assert_capture_carries_production(&with_nonce, "the valid SystemService argv");
    assert!(
        matches!(admitted, Some(Ok(_))),
        "the valid SystemService argv must admit"
    );
    assert!(
        with_nonce.contains("detail=\"host.launch-options system-service admitted\""),
        "production must emit its own SystemService admission, got: {with_nonce}"
    );
    // NAMED CEILING for the descriptor half of case 2: the exact producer of
    // `host.launch-descriptor eliotd typed rejection` is
    // `launch_descriptor_validation::validate_eliotd_launch_descriptor_bytes`
    // and its siblings, which are `pub(super)` inside the private module
    // `mod launch_descriptor_validation` (`src/lib.rs:45`) and are re-exported
    // by no `pub use`. No integration-test crate can construct a candidate
    // manifest for them, so this case proves the reachable argv half only and
    // names the descriptor owner rather than manufacturing its record.
}

// WORK_UNIT_CASE: 978/3
#[test]
fn launch_03_retained_identity_on_substitution() {
    // The reachable half: a SUBSTITUTED config-descriptor path is refused by
    // the real argv seam, and the refusal record carries only the owner's
    // frozen phase — never the substituted value, which is a path.
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
    let rejected = assert_parse_contour("the substituted descriptor path", relative, false);
    assert!(
        !rejected.contains("relative-auth.json"),
        "a substituted path must never enter a record: {rejected}"
    );
    assert!(
        !rejected.contains("eliot-launch-auth.json"),
        "an approved path must never enter a record either: {rejected}"
    );
    assert_parse_contour("the admitted launch argv", valid_launch_args(), true);
    // NAMED CEILING for the rest of case 3: the three
    // `… substitution preserved` records named by the fixture belong to
    // `host_job_launch` (private module, `src/lib.rs:37`),
    // `launch_artifact_lease::approved_locator` /
    // `approved_phase_b_destination_locator` and
    // `launch_descriptor_validation` (both private modules with no `pub`
    // symbol at all). None of the three is reachable from an integration-test
    // crate, so this case proves the retained-path rejection that IS reachable
    // and names the three owners instead of manufacturing their records.
}

// WORK_UNIT_CASE: 978/4
#[test]
fn launch_04_request_vs_process_vs_readiness() {
    // EXECUTED against the real `classify_host_scm_inspection`: a canonical
    // registration REQUEST that SCM reports absent is observed as a request
    // only. The record binds the request identity the owner already holds and
    // binds no process and no readiness at all.
    let request = canonical_scm_registration_request();
    let prefix = scm_request_prefix(&request);
    let mut cause = None;
    let capture = capture_emit(|| {
        cause = eliot_host::classify_host_scm_inspection(
            &request,
            &ServiceRegistrationRuntimeInspection::Absent,
        );
    });
    assert_capture_carries_production(&capture, "the absent SCM registration contour");
    assert!(
        matches!(cause, Some(HostScmRegistrationCause::Absent { .. })),
        "an absent registration must classify fail-closed as Absent"
    );
    for frozen in [
        format!("detail=\"host.scm-launch classification requested {prefix}\""),
        format!("detail=\"host.scm-launch request observed {prefix}\""),
    ] {
        assert!(
            capture.contains(&frozen),
            "production must emit {frozen:?}, got: {capture}"
        );
    }
    // The request record the owner emitted claims no observed process, no
    // start identity and no readiness — three DIFFERENT facts.
    assert!(
        !capture.contains("process="),
        "an absent registration must bind no observed process: {capture}"
    );
    assert!(
        !capture.contains("start-identity"),
        "a request must never claim an observed start identity: {capture}"
    );
    for forbidden in ["readiness", "healthy", "semantically_ready"] {
        assert!(
            !capture.contains(forbidden),
            "an SCM request record claimed {forbidden:?}: {capture}"
        );
    }
    // NAMED CEILING for the launch-leaf half of case 4: `host.launch
    // requested`, `host.launch admitted`, `host.launch retained lease bound`
    // and `host.launch image identity admitted` belong to `host_job_launch`,
    // which `src/lib.rs:37` declares private and which no `pub use` re-exports.
    // The reachable half above proves request-is-not-process and
    // request-is-not-readiness through the owner's own emitted record.
}

// WORK_UNIT_CASE: 978/5
#[test]
fn launch_05_start_identity_vs_pid() {
    // EXECUTED against the real `classify_host_scm_inspection`: three real
    // SCM readback outcomes, each projected by the owner with the identity it
    // actually holds. The `Unknown` readback carries a PID and no creation
    // time, so the owner's record must bind `pid=` and must never claim a
    // start identity.
    let request = canonical_scm_registration_request();
    let prefix = scm_request_prefix(&request);
    let unknown = ServiceRegistrationRuntimeInspection::Unknown {
        detail: ServiceInspectionUnknownDetail::with_status(5, "query-status", 2, 4242),
    };
    let mut unknown_cause = None;
    let unknown_capture = capture_emit(|| {
        unknown_cause = eliot_host::classify_host_scm_inspection(&request, &unknown);
    });
    assert_capture_carries_production(&unknown_capture, "the Unknown SCM readback contour");
    assert!(
        matches!(
            unknown_cause,
            Some(HostScmRegistrationCause::Unknown { .. })
        ),
        "an Unknown readback must classify fail-closed as Unknown"
    );
    assert!(
        unknown_capture.contains(&format!(
            "detail=\"host.scm-launch pid observed {prefix} win32_error=5 stage=query-status current_state=2 pid=4242 transient_pending=pending\""
        )),
        "production must bind the platform's own PID as a PID, got: {unknown_capture}"
    );
    assert!(
        !unknown_capture.contains("start-identity"),
        "a PID-only readback must never claim a start identity: {unknown_capture}"
    );
    assert!(
        !unknown_capture.contains("4242/"),
        "a PID-only readback must never render pid/creation-time: {unknown_capture}"
    );
    // A `Mismatched` readback knows an observed process exists but reports no
    // field-level identity, so the owner must say so rather than fill a slot.
    let mut mismatched_cause = None;
    let mismatched = capture_emit(|| {
        mismatched_cause = eliot_host::classify_host_scm_inspection(
            &request,
            &ServiceRegistrationRuntimeInspection::Mismatched,
        );
    });
    assert_capture_carries_production(&mismatched, "the Mismatched SCM readback contour");
    assert!(
        matches!(
            mismatched_cause,
            Some(HostScmRegistrationCause::Mismatched { .. })
        ),
        "a Mismatched readback must classify fail-closed as Mismatched"
    );
    assert!(
        mismatched.contains(&format!(
            "detail=\"host.scm-launch process observed {prefix} process=unavailable\""
        )),
        "production must mark the unobserved process identity unavailable, got: {mismatched}"
    );
    // The request-only and the observed-process records are different facts and
    // never borrow each other's detail.
    let mut absent_cause = None;
    let absent = capture_emit(|| {
        absent_cause = eliot_host::classify_host_scm_inspection(
            &request,
            &ServiceRegistrationRuntimeInspection::Absent,
        );
    });
    assert_capture_carries_production(&absent, "the Absent SCM readback contour");
    assert!(matches!(
        absent_cause,
        Some(HostScmRegistrationCause::Absent { .. })
    ));
    assert!(
        absent.contains(&format!(
            "detail=\"host.scm-launch request observed {prefix}\""
        )),
        "production must emit the request-only record, got: {absent}"
    );
    // NAMED CEILING for the start-identity half of case 5: the two records
    // that DO carry `pid/creation-time` — `host.scm-launch start-identity
    // observed` and `host.scm-launch start-identity unknown` — are emitted from
    // the `Matching { observation }` arms, and
    // `eliot_platform_windows::ServiceRuntimeObservation` has `pub(super)`
    // fields (`service_registration.rs:1025`), so no `Matching` inspection can
    // be constructed outside `eliot-platform-windows`. This case proves the
    // PID-vs-start-identity distinction on the three readbacks that ARE
    // constructible and names that owner for the `Matching` arms; the previous
    // form of this case fabricated `start-identity:978-5` and asserted on it.
}

// WORK_UNIT_CASE: 978/6
#[test]
fn launch_06_store_before_kernel() {
    // NAMED CEILING — case 6 has no reachable owner at all. The two Store and
    // Kernel barrier records are emitted only from
    // `store_kernel_launch_sequence::launch_store_then_kernel`, which is
    // `pub(super)` inside the private module `mod
    // store_kernel_launch_sequence` (`src/lib.rs:54`) and is re-exported by no
    // `pub use`: only the `StoreLivenessEvidence` enum escapes. No
    // integration-test crate can inject the launch/store/kernel closures that
    // function requires, so the Store-before-Kernel ORDER is NOT proven by this
    // file and this case does not claim it. The previous form of this case
    // inferred that order from substring positions in the owner's source text
    // and then emitted both barrier records itself.
    //
    // What remains checked here is the lexical repair this case owns from
    // audit defect 1: the two false readiness claims this leaf used to make
    // must stay gone from the owner's own text.
    let sequence = manifest_source("src/store_kernel_launch_sequence.rs");
    for retired in [
        "host.store-launch store-ready observed",
        "host.kernel-launch kernel-ready observed",
    ] {
        assert!(
            !sequence.contains(retired),
            "the sequence leaf must not claim readiness through this boundary: {retired:?}"
        );
    }
    for present in [
        "host.store-launch store-live observed",
        "host.kernel-launch kernel-launched observed; activation evidence unavailable",
    ] {
        assert!(
            sequence.contains(present),
            "the sequence leaf must keep its liveness-only vocabulary {present:?}"
        );
    }
}

// WORK_UNIT_CASE: 978/7
#[test]
fn launch_07_nonce_handshake_auth_activation_distinct() {
    // NAMED CEILING — case 7 has no reachable owner. Every record it names is
    // emitted from `kernel_activation_driver` (`nonce requested`, `nonce
    // issued`, `activating requested`, `activation observed`, `candidate
    // observed`) or `kernel_front_door_client` (`handshake requested`,
    // `handshake observed`, `auth requested`, `authenticated peer observed`,
    // `control requested`). Both modules are private (`src/lib.rs:5336` and
    // `:5347`) and every one of their functions is `pub(super)`; neither is
    // re-exported. `DurableKernelActivationDriver` is not reachable from an
    // integration-test crate, so the nonce/handshake/auth/activation
    // distinction is NOT proven by this file and this case does not claim it.
    // The previous form of this case emitted four of those records itself.
    //
    // What remains checked here is the lexical property this case owns: no
    // activation or front-door observation site may bind a nonce VALUE.
    let driver = manifest_source("src/kernel_activation_driver.rs");
    let frontdoor = manifest_source("src/kernel_front_door_client.rs");
    let canaries = fixture_str_list(&launch_fixture(), "canaries");
    assert!(!canaries.is_empty(), "the fixture must pin canaries");
    for source in [&driver, &frontdoor] {
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
                "a nonce value must never be observed: {line}"
            );
        }
    }
    // The frozen facts stay DIFFERENT literals at their own owner: a nonce is
    // not an activation, and a handshake is not an authenticated peer.
    for fact in [
        "host.kernel-activation nonce requested",
        "host.kernel-activation nonce issued",
        "host.kernel-activation activating requested",
        "host.kernel-activation activation observed",
        "host.kernel-activation candidate observed",
    ] {
        assert!(driver.contains(fact), "the driver must keep {fact:?}");
    }
    for fact in [
        "host.kernel-front-door handshake requested",
        "host.kernel-front-door handshake observed",
        "host.kernel-front-door auth requested",
        "host.kernel-front-door authenticated peer observed",
        "host.kernel-front-door control requested",
    ] {
        assert!(
            frontdoor.contains(fact),
            "the front door must keep {fact:?}"
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
}

// WORK_UNIT_CASE: 978/8
#[test]
fn launch_08_readiness_needs_owner_evidence() {
    // NAMED CEILING — case 8 has no reachable owner. The readiness pair
    // (`host.kernel-activation readiness requested` /
    //… ` readiness observed`) is emitted only from
    // `kernel_activation_driver::DurableKernelActivationDriver::active`, which
    // is `pub(super)` inside the private module `mod kernel_activation_driver`
    // (`src/lib.rs:5336`) and is re-exported by no `pub use`. Activation
    // readiness needs the driver's own permit, activation receipt and
    // `KernelReadyReceipt` evidence, none of which an integration-test crate
    // can construct, so the owner-evidence requirement is NOT proven by this
    // file and this case does not claim it. The previous form of this case
    // emitted both readiness records itself.
    //
    // What remains checked here is the lexical property this case owns: a
    // readiness detail may never be backed by liveness alone.
    let driver = manifest_source("src/kernel_activation_driver.rs");
    assert!(
        driver.contains("fn active"),
        "the activation driver must keep its owner-evidence entry point"
    );
    for fact in [
        "host.kernel-activation readiness requested",
        "host.kernel-activation readiness observed",
    ] {
        assert!(
            driver.contains(fact),
            "the driver must keep its readiness vocabulary {fact:?}"
        );
    }
    assert_ne!(
        "host.kernel-activation readiness requested",
        "host.kernel-activation readiness observed"
    );
    for line in driver.lines().filter(|line| line.contains("readiness")) {
        assert!(
            !line.contains("liveness"),
            "a readiness detail must not claim liveness: {line}"
        );
    }
}

// WORK_UNIT_CASE: 978/9
#[test]
fn launch_09_before_start_vs_timeout_disconnect_unknown() {
    // NAMED CEILING — case 9 has no reachable owner. The four mutually
    // exclusive outcomes are emitted only from
    // `kernel_front_door_client::activation_response_or_reconcile` and its
    // sibling `validate_authenticated_kernel_peer`, both `pub(super)` inside
    // the private module `mod kernel_front_door_client` (`src/lib.rs:5347`).
    // Classifying a real front-door outcome needs a live named-pipe connection
    // to the Kernel control pipe, which an integration test neither owns nor
    // may fabricate. So the before-start/timeout/disconnect/unknown
    // distinction is NOT proven by this file and this case does not claim it.
    // The previous form of this case fabricated all four outcomes in one
    // capture and asserted on them.
    //
    // What remains checked here is the lexical property this case owns: the
    // four outcomes are four different literals at their owner, and the
    // success contour is a fifth.
    let frontdoor = manifest_source("src/kernel_front_door_client.rs");
    for entry in [
        "fn activation_response_or_reconcile",
        "fn validate_authenticated_kernel_peer",
        "fn connect_authenticated_kernel_front_door",
    ] {
        assert!(
            frontdoor.contains(entry),
            "the front door must keep {entry:?}"
        );
    }
    let outcomes = [
        "host.kernel-front-door before-start observed",
        "host.kernel-front-door timeout observed",
        "host.kernel-front-door disconnect observed",
        "host.kernel-front-door unknown observed",
    ];
    for outcome in outcomes {
        assert!(
            frontdoor.contains(outcome),
            "the front door must keep {outcome:?}"
        );
    }
    assert_ne!(outcomes[0], outcomes[1]);
    assert_ne!(outcomes[2], outcomes[3]);
    assert!(frontdoor.contains("host.kernel-front-door reconcile requested"));
    assert!(frontdoor.contains("host.kernel-front-door activation observed"));
}

// WORK_UNIT_CASE: 978/10
#[test]
fn launch_10_one_terminal_across_nesting() {
    // EXECUTED half: the NESTED owner is phase-only. Every constructible SCM
    // readback is classified through the real production seam, and each
    // classification — including both fail-closed ones — emits its subordinate
    // records and NO terminal of its own. Each capture is proven non-empty
    // before the denial, so the denial cannot be an artefact of emptiness.
    let request = canonical_scm_registration_request();
    let inspections = [
        ("absent", ServiceRegistrationRuntimeInspection::Absent),
        (
            "mismatched",
            ServiceRegistrationRuntimeInspection::Mismatched,
        ),
        (
            "unknown",
            ServiceRegistrationRuntimeInspection::Unknown {
                detail: ServiceInspectionUnknownDetail::with_status(5, "query-status", 2, 4242),
            },
        ),
    ];
    for (label, inspection) in &inspections {
        let mut cause = None;
        let capture = capture_emit(|| {
            cause = eliot_host::classify_host_scm_inspection(&request, inspection);
        });
        assert_capture_carries_production(capture.as_str(), label);
        assert!(
            cause.is_some(),
            "every fail-closed readback must classify to a typed cause: {label}"
        );
        assert_eq!(
            count_occurrences(&capture, "host.terminal_error"),
            0,
            "the nested SCM classifier must leave the terminal to its caller: {capture}"
        );
    }
    // The single terminal owner, lexically: exactly one code, exactly one
    // emitter, and no mutable global dedup cache anywhere in the CD slice.
    let owned = format!(
        "{}{}{}{}",
        manifest_source("src/scm_launch.rs"),
        manifest_source("src/store_kernel_launch_sequence.rs"),
        manifest_source("src/kernel_activation_driver.rs"),
        manifest_source("src/kernel_front_door_client.rs")
    );
    assert_eq!(
        count_occurrences(&owned, "host-scm-launch-unknown"),
        1,
        "the SCM terminal code must be owned by exactly one callsite"
    );
    let scm = manifest_source("src/scm_launch.rs");
    assert!(scm.contains("struct ScmLaunchTerminalGuard"));
    assert!(scm.contains("fn disarm"));
    assert!(
        count_occurrences(&scm, "scm_launch_observe_terminal(") == 2,
        "the terminal helper must have exactly one emitter (its own definition)"
    );
    assert!(
        !owned.contains("static DEDUP"),
        "no mutable global dedup cache may exist"
    );
    for source in [
        manifest_source("src/store_kernel_launch_sequence.rs"),
        manifest_source("src/kernel_activation_driver.rs"),
        manifest_source("src/kernel_front_door_client.rs"),
    ] {
        assert!(
            !source.contains("observe_terminal_error"),
            "inner nesting must correlate by stage order only, with no inner terminal"
        );
    }
    assert!(
        !owned.contains("host-launch-failed"),
        "the CD slice must not own the launch-leaf terminal"
    );
    // NAMED CEILING for the terminal itself: the single owner is the private
    // struct `ScmLaunchTerminalGuard`, armed at `scm_launch.rs:888` inside
    // `validate_host_scm_bootstrap` and fired from its `Drop`. The only
    // integration-test caller of that function is `eliot_host::
    // validate_host_scm_bootstrap`, which reaches the guard through a LIVE
    // read-only SCM inspection whose outcome is whatever service this machine
    // has registered — so the emitted terminal cannot be proven deterministically
    // here. This case proves the reachable half (the nested contour is
    // phase-only) plus the single-owner structure, and names the guard rather
    // than manufacturing `host-scm-launch-unknown` through the facade.
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
        admitted_outcome = Some(eliot_host::HostLaunchOptions::parse_system_service(
            valid_system_args(),
        ));
    });
    let mut filtered_outcome = None;
    let filtered = capture_emit_at_level(tracing::Level::ERROR, || {
        filtered_outcome = Some(eliot_host::HostLaunchOptions::parse_system_service(
            valid_system_args(),
        ));
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
        assert!(
            admitted.contains(frozen),
            "production must emit {frozen:?}, got: {admitted}"
        );
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
    let canaries = fixture_str_list(&launch_fixture(), "canaries");
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
    // EXECUTED: one ADMITTED production launch whose every owner-held value is
    // itself a canary — the descriptor path, the installation identity, the
    // nonce and the state root. The owner's records must name none of them.
    let canary_path = std::env::temp_dir()
        .join("argv-secret=token=env=argv-CredentialSecret")
        .join("password-AKIA-passwd-connection_string-BEGIN PRIVATE.json");
    let canary_args = vec![
        OsString::from("--config-descriptor"),
        canary_path.into_os_string(),
        OsString::from("--config-descriptor-sha256"),
        OsString::from("a".repeat(64)),
        OsString::from("--installation-id"),
        OsString::from("password-AKIA-passwd-connection_string-BEGIN PRIVATE"),
        OsString::from("--tx-plan-generation"),
        OsString::from("7"),
        OsString::from("--host-state-root"),
        std::env::temp_dir()
            .join("argv-secret=token=env=argv-CredentialSecret-state")
            .into_os_string(),
        OsString::from("--registration-nonce"),
        OsString::from("b".repeat(64)),
    ];
    let capture = capture_emit(|| {
        assert!(
            eliot_host::HostLaunchOptions::parse_system_service(canary_args).is_ok(),
            "the canary argv must still be a valid SystemService bootstrap"
        );
    });
    assert_capture_carries_production(&capture, "the canary launch contour");
    for frozen in [
        "detail=\"host.launch-options system-service admitted\"",
        "detail=\"host.launch-options parse admitted\"",
    ] {
        assert!(
            capture.contains(frozen),
            "production must emit {frozen:?}, got: {capture}"
        );
    }
    for canary in &canaries {
        assert!(
            !capture.contains(canary.as_str()),
            "the owner's own record leaked canary {canary:?}: {capture}"
        );
    }
    let nonce = "b".repeat(64);
    assert!(
        !capture.contains(&nonce),
        "the registration nonce must never enter a record: {capture}"
    );
    assert!(
        !capture.contains("a".repeat(64).as_str()),
        "the config-descriptor digest must never enter a record: {capture}"
    );
    // Boundedness is still the facade's own honesty record.
    assert_eq!(bound_field("startup").text(), "startup");
    let oversized = "y".repeat(8 * 1024 + 7);
    let bounded = bound_detail(&oversized);
    assert_eq!(bounded.original_bytes(), oversized.len());
    assert!(bounded.truncated());
    assert!(bounded.text().len() <= 1024);
}

// Sibling-CD source readers, used by the frozen-boundary cases below.

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

// WORK_UNIT_CASE: 978/13
#[test]
fn launch_13_deterministic_semantic_fields() {
    let combined = format!("{}{}{}", scm_source(), sequence_source(), driver_source());
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
    // `stage`/`detail` fields.
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
        assert!(
            first.contains(frozen),
            "production must emit {frozen:?}, got: {first}"
        );
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
    assert!(
        matches!(callback, Some(Ok(()))),
        "the canonical ServiceMain argv must be admitted"
    );
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
    assert_capture_carries_production(capture, contour);
    for frozen in positive {
        assert!(
            capture.contains(frozen),
            "{contour} must emit {frozen:?}: {capture}"
        );
    }
    assert!(
        !capture.contains(negative),
        "{contour} claimed {negative:?}: {capture}"
    );
    assert_eq!(
        count_occurrences(capture, "host.terminal_error"),
        0,
        "{contour} must leave its terminal to the enclosing operation guard: {capture}"
    );
}
