#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Watchdog publication/service/timing diagnostics (item 979, Implements, never Closes).
//!
//! Facade-only bounded diagnostics for the Watchdog composition root:
//! publication readback requested/observed/absent/stale/conflicting,
//! service observation preserving PID/start/image/generation/fence identity
//! (SCM acknowledgement is never readiness, unknown stays unknown), and
//! timing via the injected [`eliot_watchdog::WatchdogSelfAdmissionProbe`]
//! against the existing [`eliot_watchdog::WATCHDOG_SELF_ADMISSION_DEADLINE_MS`].
//! No new clocks, sleeps, retries, or deadline changes; sink drop/failure
//! leaves return/state/cursor identical; secret values are never logged
//! (I15.4). Host-side `bins/eliot-host/src/watchdog_*` files stay for a
//! follow-up after the SHIM wave; live SCM proof stays an honest residual.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_watchdog::{
    HostIdentityMonitor, HostObservationState, WATCHDOG_SELF_ADMISSION_DEADLINE_MS,
    WatchdogRuntimeReadback, WatchdogRuntimeState, WatchdogSelfAdmissionError,
    WatchdogSelfAdmissionProbe, WatchdogSelfAdmissionStatus,
    admit_watchdog_self_start_with_deadline,
};
use serde_json::Value;

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

#[derive(Clone, Default)]
struct FailingSink;

impl Write for FailingSink {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("diagnostic sink failed"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("diagnostic sink failed"))
    }
}

struct TimingProbe {
    now_ms: u64,
    inspect_advance_ms: u64,
    current: Option<eliot_platform_windows::ProcessIdentity>,
    observations: VecDeque<WatchdogRuntimeReadback>,
    sleeps: Vec<u32>,
}

impl WatchdogSelfAdmissionProbe for TimingProbe {
    fn now_ms(&mut self) -> u64 {
        self.now_ms
    }

    fn current_process_identity(&mut self) -> Option<eliot_platform_windows::ProcessIdentity> {
        self.current.clone()
    }

    fn inspect(&mut self) -> WatchdogRuntimeReadback {
        self.now_ms = self.now_ms.saturating_add(self.inspect_advance_ms);
        self.observations
            .pop_front()
            .unwrap_or(WatchdogRuntimeReadback::Unknown)
    }

    fn sleep_ms(&mut self, milliseconds: u32) {
        self.sleeps.push(milliseconds);
        self.now_ms = self.now_ms.saturating_add(u64::from(milliseconds));
    }
}

#[derive(Default)]
struct TimingStatus {
    reports: Vec<(u32, u32)>,
}

impl WatchdogSelfAdmissionStatus for TimingStatus {
    fn report_start_pending(&mut self, checkpoint: u32, wait_hint_ms: u32) {
        self.reports.push((checkpoint, wait_hint_ms));
    }
}

fn test_identity() -> eliot_platform_windows::ProcessIdentity {
    eliot_platform_windows::ProcessIdentity {
        process_id: 979,
        start_time_100ns: 1_979_979,
        image_path: r"C:\ProgramData\Eliot\eliot-watchdog.exe".to_owned(),
    }
}

fn matching(
    state: WatchdogRuntimeState,
    process: Option<eliot_platform_windows::ProcessIdentity>,
) -> WatchdogRuntimeReadback {
    WatchdogRuntimeReadback::Matching {
        state,
        process,
        checkpoint: 2,
        wait_hint_ms: 250,
    }
}

fn fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/watchdog_publication_service_timing_diagnostics.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("read fixture {}: {error}", path.display());
    });
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse fixture: {error}"))
}

fn with_capture<T>(run: impl FnOnce() -> T) -> (T, String) {
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let result = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, run)
    };
    let bytes = sink.bytes.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    (result, text)
}

fn with_failing_sink<T>(run: impl FnOnce() -> T) -> T {
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(|| FailingSink)
        .finish();
    tracing::subscriber::with_default(subscriber, run)
}

fn with_filtered_sink<T>(run: impl FnOnce() -> T) -> T {
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter("off")
        .with_writer(CaptureSink::default)
        .finish();
    tracing::subscriber::with_default(subscriber, run)
}

fn distinct(values: &[String]) -> bool {
    let mut seen = std::collections::HashSet::new();
    values.iter().all(|value| seen.insert(value.clone()))
}

// WORK_UNIT_CASE: 979/1
#[allow(
    clippy::too_many_lines,
    reason = "timing determinism keeps exact, one-over, unknown, and service-unknown cases together"
)]
#[test]
fn injected_probe_timing_is_deterministic_and_deadline_exact() {
    let fixture = fixture();
    let publication = fixture["expected_publication_observations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        publication,
        vec!["requested", "observed", "absent", "stale", "conflicting"],
        "publication vocabulary must stay distinct and frozen"
    );
    assert!(
        distinct(&publication),
        "publication names must not collapse"
    );

    let timing_outcomes = fixture["expected_timing_outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert!(
        distinct(&timing_outcomes),
        "timing outcomes must not collapse"
    );

    let host_observations = fixture["expected_host_observations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert!(
        distinct(&host_observations),
        "host observations must not collapse"
    );

    assert_eq!(
        WATCHDOG_SELF_ADMISSION_DEADLINE_MS, 30_000,
        "production deadline is fixed; diagnostics add no new deadline"
    );
    let deadline = fixture["timing"]["deadline_ms"].as_u64().unwrap();
    let one_over = fixture["timing"]["one_over_advance_ms"].as_u64().unwrap();
    assert_eq!(deadline, 30);
    assert_eq!(one_over, 30);

    // Exact Starting identity is admitted with no sleep when already matching.
    let identity = test_identity();
    let run_admitted = || {
        let mut probe = TimingProbe {
            now_ms: 0,
            inspect_advance_ms: 0,
            current: Some(identity.clone()),
            observations: VecDeque::from([matching(
                WatchdogRuntimeState::Starting,
                Some(identity.clone()),
            )]),
            sleeps: Vec::new(),
        };
        let mut status = TimingStatus::default();
        let result = admit_watchdog_self_start_with_deadline(&mut probe, &mut status, deadline);
        (
            result,
            probe.sleeps.clone(),
            probe.now_ms,
            status.reports.clone(),
        )
    };
    let ((first, first_sleeps, first_now, first_reports), first_text) = with_capture(run_admitted);
    let ((second, second_sleeps, second_now, second_reports), _second_text) =
        with_capture(run_admitted);
    assert_eq!(first, Ok(identity.clone()));
    assert_eq!(second, Ok(identity.clone()));
    assert!(first_sleeps.is_empty(), "immediate match must not sleep");
    assert!(second_sleeps.is_empty(), "immediate match must not sleep");
    assert_eq!(first_sleeps, second_sleeps, "sleeps must be deterministic");
    assert_eq!(
        first_now, second_now,
        "injected clock must be deterministic"
    );
    assert_eq!(
        first_reports, second_reports,
        "status reports must be deterministic"
    );
    assert!(
        first_text.contains("watchdog.self_admission_timing"),
        "timing diagnostics must emit the facade event, got: {first_text}"
    );
    assert!(
        first_text.contains("requested") && first_text.contains("admitted"),
        "requested-vs-observed must both appear deterministically, got: {first_text}"
    );
    assert!(
        first_text.contains("elapsed_ms") && first_text.contains("deadline_ms"),
        "timing must carry injected elapsed/deadline numbers, got: {first_text}"
    );

    // One-over the deadline times out with no reports/sleeps: the exact
    // deadline decision is unchanged by logging.
    let mut exact_probe = TimingProbe {
        now_ms: 0,
        inspect_advance_ms: one_over,
        current: Some(identity.clone()),
        observations: VecDeque::from([matching(
            WatchdogRuntimeState::Starting,
            Some(identity.clone()),
        )]),
        sleeps: Vec::new(),
    };
    let mut exact_status = TimingStatus::default();
    let exact = with_filtered_sink(|| {
        admit_watchdog_self_start_with_deadline(&mut exact_probe, &mut exact_status, deadline)
    });
    assert_eq!(exact, Err(WatchdogSelfAdmissionError::Timeout));
    assert!(
        exact_status.reports.is_empty(),
        "expired-before-read must not report"
    );
    assert!(
        exact_probe.sleeps.is_empty(),
        "expired-before-read must not sleep"
    );

    // Unknown stays unknown-derived timeout without overshooting the deadline.
    let unknown_deadline = fixture["timing"]["unknown_deadline_ms"].as_u64().unwrap();
    let mut unknown_probe = TimingProbe {
        now_ms: 0,
        inspect_advance_ms: 0,
        current: Some(identity.clone()),
        observations: VecDeque::new(),
        sleeps: Vec::new(),
    };
    let mut unknown_status = TimingStatus::default();
    let unknown = with_filtered_sink(|| {
        admit_watchdog_self_start_with_deadline(
            &mut unknown_probe,
            &mut unknown_status,
            unknown_deadline,
        )
    });
    assert_eq!(unknown, Err(WatchdogSelfAdmissionError::Timeout));
    assert!(
        unknown_probe.now_ms <= unknown_deadline,
        "poll must not overshoot the injected deadline"
    );
    assert!(
        !unknown_status.reports.is_empty(),
        "unknown must report pending"
    );
    assert!(!unknown_probe.sleeps.is_empty(), "unknown must poll");

    // Service observation without Windows stays Unknown: an SCM
    // acknowledgement without an exact identity is never readiness.
    let mut monitor = HostIdentityMonitor::new(None);
    let observation = with_filtered_sink(|| monitor.observe());
    assert_eq!(observation.state, HostObservationState::Unknown);
    assert!(
        observation.identity.is_none(),
        "unknown carries no identity"
    );
    let again = with_filtered_sink(|| monitor.observe());
    assert_eq!(
        observation, again,
        "unknown observation must be deterministic"
    );
}

// WORK_UNIT_CASE: 979/2
#[allow(
    clippy::too_many_lines,
    reason = "redaction keeps canary, failing, filtered, absent, and mismatch sinks together"
)]
#[test]
fn redaction_and_sink_drop_leave_semantics_identical() {
    let fixture = fixture();
    let canaries = fixture["canaries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert!(
        !canaries.is_empty(),
        "fixture must carry redaction canaries"
    );
    let capture_max =
        usize::try_from(fixture["bounds"]["capture_bytes_max"].as_u64().unwrap()).unwrap();
    assert!(
        fixture["sink"]["event_log_unavailable"].as_bool().unwrap(),
        "Event Log stays unavailable per #984; no FFI is acquired"
    );

    // Canary identity: the image path carries a raw-path canary plus a
    // lease-secret canary fragment. Diagnostics must preserve the identity
    // distinction without ever logging the values.
    let canary_image = format!("{}-{}", canaries[2], canaries[0]);
    let canary_identity = eliot_platform_windows::ProcessIdentity {
        process_id: 4242,
        start_time_100ns: 7_979_979,
        image_path: canary_image,
    };
    let run_canary = || {
        let mut probe = TimingProbe {
            now_ms: 0,
            inspect_advance_ms: 0,
            current: Some(canary_identity.clone()),
            observations: VecDeque::from([matching(
                WatchdogRuntimeState::Running,
                Some(canary_identity.clone()),
            )]),
            sleeps: Vec::new(),
        };
        let mut status = TimingStatus::default();
        let result = admit_watchdog_self_start_with_deadline(&mut probe, &mut status, 30);
        (result, probe.sleeps.clone(), probe.now_ms)
    };

    let ((captured_result, captured_sleeps, captured_now), captured_text) =
        with_capture(run_canary);
    assert_eq!(captured_result, Ok(canary_identity.clone()));
    for canary in &canaries {
        assert!(
            !captured_text.contains(canary.as_str()),
            "secret canary must never appear in diagnostics, found: {canary}"
        );
    }
    assert!(
        captured_text.len() < capture_max,
        "diagnostic capture must stay bounded, got {} bytes",
        captured_text.len()
    );

    // Sink drop/failure noninterference: failing, filtered, and absent
    // subscribers return identical semantics, sleeps, and clock positions.
    let failing_result = with_failing_sink(run_canary);
    let filtered_result = with_filtered_sink(run_canary);
    let bare_result = run_canary();
    assert_eq!(
        failing_result.0, captured_result,
        "failing sink must not change return"
    );
    assert_eq!(
        filtered_result.0, captured_result,
        "filtered sink must not change return"
    );
    assert_eq!(
        bare_result.0, captured_result,
        "absent subscriber must not change return"
    );
    assert_eq!(
        failing_result.1, captured_sleeps,
        "failing sink must not change sleeps"
    );
    assert_eq!(
        filtered_result.1, captured_sleeps,
        "filtered sink must not change sleeps"
    );
    assert_eq!(
        bare_result.1, captured_sleeps,
        "absent sink must not change sleeps"
    );
    assert_eq!(
        failing_result.2, captured_now,
        "failing sink must not change clock"
    );
    assert_eq!(
        filtered_result.2, captured_now,
        "filtered sink must not change clock"
    );
    assert_eq!(
        bare_result.2, captured_now,
        "absent sink must not change clock"
    );

    // Mismatched identity with canaries also stays secret-free and identical
    // across sinks.
    let run_mismatch = || {
        let mut probe = TimingProbe {
            now_ms: 0,
            inspect_advance_ms: 0,
            current: Some(canary_identity.clone()),
            observations: VecDeque::from([matching(
                WatchdogRuntimeState::Starting,
                Some(test_identity()),
            )]),
            sleeps: Vec::new(),
        };
        let mut status = TimingStatus::default();
        admit_watchdog_self_start_with_deadline(&mut probe, &mut status, 30)
    };
    let (mismatch_result, mismatch_text) = with_capture(run_mismatch);
    assert_eq!(
        mismatch_result,
        Err(WatchdogSelfAdmissionError::RegistrationMismatched)
    );
    for canary in &canaries {
        assert!(
            !mismatch_text.contains(canary.as_str()),
            "mismatch diagnostics must stay secret-free, found: {canary}"
        );
    }
    let mismatch_failing = with_failing_sink(run_mismatch);
    assert_eq!(
        mismatch_failing, mismatch_result,
        "sink must not change mismatch"
    );
}
