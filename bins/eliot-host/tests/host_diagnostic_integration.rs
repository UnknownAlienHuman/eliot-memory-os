//! F-LOG-HOST integrator oracle (#985 W4): the actual cross-child forced
//! failure and capture fixtures for acceptance cases A12 and A13.
//!
//! This file is the only #985 evidence that executes a real child process
//! instead of inspecting source text or calling the diagnostic facade
//! in-process to manufacture the record under test. Nothing here builds an
//! expected log record by hand: every asserted value is read back out of the
//! bytes the real `eliot-host` process wrote to its own stderr sink, its own
//! stdout console-protocol frame, its own bounded failure receipt inside this
//! test's directories, or the Windows Application log itself.
//!
//! The seam, and why it is the real one
//!
//! * A12 (cross-child forced failure). The `SystemService` launch shape really
//!   enters `run_as_scm_service` and really calls `StartServiceCtrlDispatcherW`
//!   against the Windows service control manager, so the forced failure
//!   genuinely crosses a process/OS child boundary rather than a function call
//!   in this test process. The SCM answers with the documented console case,
//!   production records the supported `console_fallback` boundary, and
//!   `open_host` then refuses the empty registry this isolated run owns, so the
//!   child ends at the `open_failed` boundary. Each child is launched twice -
//!   once with the diagnostic sink admitting production's records and once with
//!   the filter that drops every one - which is what makes "unchanged by the
//!   observation" an executed property of the return value, the receipt, and
//!   the shutdown cleanup rather than an assertion about a flag.
//! * A13 (isolated Event Log start delivery). The delivery is executed through
//!   `windows_event_log::report_admitted_event`, which is the synchronous
//!   production function the bounded producer worker itself calls
//!   (`run_event_log_worker` -> `report_event` -> #984 `report_local_event` ->
//!   `RegisterEventSourceW` / `ReportEventW`), and the delivered record is then
//!   read back out of the real Windows Application log. That makes the outcome
//!   distinguishable from a fake, from an unavailable source, and from the
//!   degraded Application profile by observation rather than by construction.
//!
//! Named ceilings (stated, never absorbed)
//!
//! * The child's own Event Log start delivery cannot be read back
//!   deterministically. `shutdown_event_log_producer` joins no worker and
//!   `std::process::exit` discards whatever is still queued, so a child-side
//!   readback would be a race against process exit. The child's leg is
//!   therefore asserted exactly as far as production's own deterministic
//!   evidence reaches: its real admission record, carrying the owner evidence
//!   that admits a start at all. The synchronous delivery above is the leg
//!   that proves OS acceptance and real readback.
//! * The Event Log source is not registered on this machine, so the OS stores
//!   the record without message resources. That is exactly what
//!   `EventLogDelivery::OsAcceptedRegistrationUnknown` reports, and it is why
//!   the registered-source and degraded-application arms are unreachable here
//!   and are asserted to be absent rather than fabricated.
//! * Only the Windows Event Log seam is reached. `AdmittedEvent::ServiceStop`
//!   and `AdmittedEvent::ServiceFailure` delivery identity (case A14), the
//!   stdout-unavailable Event Log failure (case A15), and the canary sweeps
//!   (cases A16/A17) are owned elsewhere and are named by their own files, not
//!   claimed here.
//!
//! Reconciled drift: the terminal facade is not a singleton in `main.rs`
//!
//! The rescued head `feat/985-forced-failure-oracle-W1a` pinned
//! `main.rs` `observe_terminal_error` occurrence count `== 1`. That pin is
//! wrong against current production: the string occurs three times in
//! `main.rs` (the console terminal emission, the dispatcher terminal emission,
//! and once inside the production comment that explains why the console
//! terminal stays uncorrelated). This file deliberately does not restore that
//! pin and does not replace it with another occurrence count. What is asserted
//! instead is the invariant the occurrence count never was: the exact set of
//! (owning function, typed terminal code) pairs in `main.rs`, which stays red
//! if one operation grows a second terminal or reuses another operation's
//! code, and which is reconciled against what the executed children actually
//! emitted. That emission-set assertion is supplementary; the executed children
//! are the evidence.
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use eliot_host::host_diagnostics::{
    HOST_DIAGNOSTICS_TARGET, HOST_TERMINAL_CODE_CONSOLE_FAILED,
    HOST_TERMINAL_CODE_DISPATCHER_FAILED, HostRequestEvidence,
};
use eliot_host::windows_event_log::{
    AdmittedEvent, EVENT_LOG_MAX_INSERTION_BYTES, EVENT_LOG_SOURCE, EventLogDelivery,
    EventLogRecord, WindowsEventLogError, event_log_sink_status, report_admitted_event,
    report_event,
};
use serde_json::Value;

const FIXTURE: &str = include_str!("data/host_diagnostic_integration.json");
const MAIN_SRC: &str = include_str!("../src/main.rs");

/// Non-zero plan generation every child is launched with.
const HOST_PLAN_GENERATION: u64 = 7;
/// The console process exit code production terminates with on Windows.
const HOST_CONSOLE_EXIT_WINDOWS: i32 = 1066;
/// Bounded readback attempts for the Event Log service to make an accepted
/// record queryable. The direction is monotone - an accepted record can only
/// become more visible - and no assertion reads a duration, an ordering, or a
/// timestamp out of the readback.
const READBACK_ATTEMPTS: usize = 20;
/// Interval between two bounded readback attempts.
const READBACK_INTERVAL_MS: u64 = 100;

/// The `key="value"` spelling the facade's `tracing` fields render.
fn binding(key: &str, value: &str) -> String {
    format!("{key}=\"{value}\"")
}

/// The value production bound to `key` in one facade record line.
fn field_value(line: &str, key: &str) -> Option<String> {
    let prefix = binding(key, "");
    let start = line.find(&prefix)? + prefix.len();
    let end = start + line[start..].find('"')?;
    Some(line[start..end].to_owned())
}

/// One fixture string, addressed by its real path inside the JSON.
fn fixture_text(fixture: &Value, path: &[&str]) -> String {
    let (last, parents) = path.split_last().unwrap_or_else(|| panic!("path"));
    let mut node = fixture;
    for key in parents {
        node = &node[*key];
    }
    node[*last]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must pin {}", path.join(".")))
        .to_owned()
}

/// One fixture integer, addressed by its real path inside the JSON.
fn fixture_u64(fixture: &Value, path: &[&str]) -> u64 {
    let (last, parents) = path.split_last().unwrap_or_else(|| panic!("path"));
    let mut node = fixture;
    for key in parents {
        node = &node[*key];
    }
    node[*last]
        .as_u64()
        .unwrap_or_else(|| panic!("fixture must pin {}", path.join(".")))
}

/// One fixture string array, addressed by its real path inside the JSON.
fn fixture_texts(fixture: &Value, path: &[&str]) -> Vec<String> {
    let (last, parents) = path.split_last().unwrap_or_else(|| panic!("path"));
    let mut node = fixture;
    for key in parents {
        node = &node[*key];
    }
    node[*last]
        .as_array()
        .unwrap_or_else(|| panic!("fixture must pin an array at {}", path.join(".")))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("fixture entries must be strings"))
                .to_owned()
        })
        .collect()
}

/// One isolated environment one real child process owns end to end.
///
/// The state root and the child's `TMP`/`TEMP` are created here and removed
/// when the case ends, the installation id is unique per case and per test
/// process so the process-global Host owner lease is never contended between
/// cases, and nothing the child can write lands outside this directory.
struct IsolatedRun {
    base: PathBuf,
    state_root: PathBuf,
    temp: PathBuf,
    installation: String,
    generation: u64,
}

impl IsolatedRun {
    fn new(case: &str) -> Self {
        let base = std::env::temp_dir().join(format!("eliot-985-{case}-{}", std::process::id()));
        let state_root = base.join("state");
        let temp = base.join("temp");
        for directory in [&state_root, &temp] {
            std::fs::create_dir_all(directory)
                .unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
        }
        Self {
            state_root,
            temp,
            base,
            installation: format!("installation-985-{case}"),
            generation: HOST_PLAN_GENERATION,
        }
    }

    /// The exact launch argv one child is handed, shaped by the production
    /// parser that reads it. With a nonce pair this is the `SystemService`
    /// bootstrap shape, which is the contour that really dispatches.
    fn launch_args(&self, nonce: &str) -> Vec<OsString> {
        vec![
            OsString::from("--config-descriptor"),
            self.state_root.join("descriptor.json").into_os_string(),
            OsString::from("--config-descriptor-sha256"),
            OsString::from(descriptor_digest()),
            OsString::from("--installation-id"),
            OsString::from(self.installation.as_str()),
            OsString::from("--tx-plan-generation"),
            OsString::from(self.generation.to_string()),
            OsString::from("--host-state-root"),
            self.state_root.as_os_str().to_owned(),
            OsString::from("--registration-nonce"),
            OsString::from(nonce),
        ]
    }
}

impl Drop for IsolatedRun {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// Lowercase 64-hex config-descriptor digest the launch argv carries.
fn descriptor_digest() -> String {
    "9850".repeat(16)
}

/// Lowercase 64-hex registration nonce the `SystemService` launch carries.
fn registration_nonce() -> String {
    let marker = "c0ffee".repeat(10);
    format!("{marker}9850")
}

/// The console process exit code production terminates with on this platform.
fn console_exit_code() -> i32 {
    if cfg!(windows) {
        HOST_CONSOLE_EXIT_WINDOWS
    } else {
        1
    }
}

/// The real Host executable this integration target launches.
fn host_binary() -> PathBuf {
    let exe = std::env::current_exe()
        .unwrap_or_else(|error| panic!("current_exe: {error}"));
    let top = exe
        .ancestors()
        .nth(2)
        .unwrap_or_else(|| panic!("target directory above {}", exe.display()));
    top.join(format!("eliot-host{}", std::env::consts::EXE_SUFFIX))
}

/// One real `eliot-host` process, captured exactly as production wrote it.
struct HostRun {
    stdout: String,
    stderr: String,
    code: Option<i32>,
}

impl HostRun {
    /// The console protocol frames, exactly as `write_response` framed them.
    fn frames(&self) -> Vec<Value> {
        self.stdout
            .lines()
            .map(|line| {
                serde_json::from_str(line)
                    .unwrap_or_else(|error| panic!("console frame {line:?}: {error}"))
            })
            .collect()
    }

    /// The facade records this run's own sink received, in sink order.
    fn records(&self) -> Vec<&str> {
        self.stderr
            .lines()
            .filter(|line| line.contains(HOST_DIAGNOSTICS_TARGET))
            .collect()
    }

    /// The facade records carrying one exact `key="value"` binding.
    fn records_binding(&self, key: &str, value: &str) -> Vec<&str> {
        let wanted = binding(key, value);
        self.records()
            .into_iter()
            .filter(|line| line.contains(&wanted))
            .collect()
    }

    /// The first facade record carrying every one of these exact bindings.
    fn record_with(&self, bindings: &[(&str, &str)]) -> Option<String> {
        self.records()
            .into_iter()
            .find(|line| {
                bindings
                    .iter()
                    .all(|(key, value)| line.contains(&binding(key, value)))
            })
            .map(String::from)
    }

    /// Sink position of the first facade record carrying `key="value"`.
    fn position_of(&self, key: &str, value: &str) -> Option<usize> {
        let wanted = binding(key, value);
        self.records()
            .into_iter()
            .position(|line| line.contains(&wanted))
    }
}

/// Runs the real `eliot-host` binary once for one isolated launch argv.
///
/// `filter` is the `RUST_LOG` value the child's `install_host_diagnostics`
/// builds its `EnvFilter` from; `None` removes the variable so the sink admits
/// the facade records at their default level. stdin is the null device, so the
/// console read loop meets a real EOF instead of waiting for a peer, and the
/// child terminates on its own without a timeout. `TMP`/`TEMP` are redirected
/// into the isolated run, so even the receipt fallback of a run whose launch
/// argv never parsed stays inside this test.
fn run_host(run: &IsolatedRun, nonce: &str, filter: Option<&str>) -> HostRun {
    let mut command = Command::new(host_binary());
    command
        .args(run.launch_args(nonce))
        .stdin(std::process::Stdio::null())
        .env("TMP", &run.temp)
        .env("TEMP", &run.temp);
    match filter {
        Some(filter) => {
            command.env("RUST_LOG", filter);
        }
        None => {
            command.env_remove("RUST_LOG");
        }
    }
    let child = command
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", run.installation));
    HostRun {
        stdout: String::from_utf8_lossy(&child.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&child.stderr).into_owned(),
        code: child.status.code(),
    }
}

/// The one bounded start-failure receipt this run's owner wrote.
///
/// The owner is production's `persist_host_start_failure`, which writes into
/// the parsed launch options' Host state root or into the process temp
/// directory when the process bootstrap never parsed. Both belong to this test,
/// so exactly one file across them is production's receipt.
fn sole_receipt(run: &IsolatedRun) -> Value {
    let mut files: Vec<PathBuf> = Vec::new();
    for directory in [&run.state_root, &run.temp] {
        let entries = std::fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
        files.extend(
            entries
                .iter()
                .filter(|entry| matches!(entry.file_type(), Ok(kind) if kind.is_file()))
                .map(std::fs::DirEntry::path),
        );
    }
    assert_eq!(
        files.len(),
        1,
        "exactly one start-failure receipt for {}, found {files:?}",
        run.installation
    );
    let bytes =
        std::fs::read(&files[0]).unwrap_or_else(|error| panic!("{}: {error}", files[0].display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("receipt {}: {error}", files[0].display()))
}

/// The failed-open projection this child really emitted, matched on every exact
/// binding production renders for it.
fn failed_open_projection(run: &IsolatedRun, observed: &HostRun, fixture: &Value) -> String {
    let request_event = fixture_text(fixture, &["forced_failure", "request_event"]);
    let request_phase = fixture_text(fixture, &["forced_failure", "request_phase"]);
    let request_evidence = fixture_text(fixture, &["forced_failure", "request_evidence"]);
    let request_operation = fixture_text(fixture, &["forced_failure", "request_operation"]);
    observed
        .record_with(&[
            ("event", request_event.as_str()),
            ("phase", request_phase.as_str()),
            ("evidence", request_evidence.as_str()),
            ("operation", request_operation.as_str()),
            ("installation", run.installation.as_str()),
        ])
        .unwrap_or_else(|| panic!("no failed open projection: {}", observed.stderr))
}

/// Asserts the executed forced-failure contour of one real child.
///
/// Everything asserted here was read out of this child's own bytes: its sink
/// records, its stdout frame, and its exit code.
fn assert_forced_failure_contour(run: &IsolatedRun, observed: &HostRun, fixture: &Value) {
    let terminal_event = fixture_text(fixture, &["forced_failure", "terminal_event"]);
    let terminal_code = fixture_text(fixture, &["forced_failure", "terminal_code"]);
    let open_failed = fixture_text(fixture, &["forced_failure", "open_failed_detail"]);
    let fallback = fixture_text(fixture, &["forced_failure", "console_fallback_detail"]);
    let shutdown_event = fixture_text(fixture, &["forced_failure", "shutdown_event"]);
    let outstanding = fixture_text(fixture, &["forced_failure", "outstanding_delivery"]);
    assert_eq!(terminal_code, HOST_TERMINAL_CODE_CONSOLE_FAILED);

    // The forced failure really crossed the OS service boundary: the child
    // entered the dispatcher and the SCM answered with the documented console
    // case. Off Windows there is no SCM dispatch seam and no fallback may be
    // invented.
    let fallbacks = if cfg!(windows) { 1 } else { 0 };
    assert_eq!(
        observed.records_binding("detail", &fallback).len(),
        fallbacks,
        "stderr: {}",
        observed.stderr
    );

    // Exactly one terminal event for the failed run, carrying the typed code
    // the console contour owns, and nothing else may claim to be that terminal.
    let terminals = observed.records_binding("event", &terminal_event);
    assert_eq!(
        terminals.len(),
        1,
        "one terminal event per failed run, stderr: {}",
        observed.stderr
    );
    let terminal = terminals[0];
    assert_eq!(
        field_value(terminal, "code").as_deref(),
        Some(terminal_code.as_str()),
        "terminal: {terminal}"
    );
    // Production renders this terminal honestly uncorrelated: the collapsed
    // console result reached no owner-issued identity, so every slot is
    // explicitly missing rather than inferred from record order.
    assert_eq!(
        field_value(terminal, "correlation_available").as_deref(),
        Some(fixture_text(fixture, &["forced_failure", "correlation_available"]).as_str()),
        "terminal: {terminal}"
    );
    for missing in fixture_texts(fixture, &["forced_failure", "correlation_missing"]) {
        assert!(
            terminal.contains(&binding(&missing, "true")),
            "terminal must name {missing}, got: {terminal}"
        );
    }

    // Exactly one boundary record for the failed open, correlated to this run's
    // own installation and to the typed operation its evidence supports.
    assert_eq!(
        observed.records_binding("detail", &open_failed).len(),
        1,
        "stderr: {}",
        observed.stderr
    );
    let projection = failed_open_projection(run, observed, fixture);
    assert!(
        field_value(&projection, "reason").is_some_and(|reason| !reason.is_empty()),
        "projection: {projection}"
    );

    // The boundary precedes the terminal that summarises the run: production's
    // order, not an inference about it.
    let opened = observed
        .position_of("detail", &open_failed)
        .unwrap_or_else(|| panic!("no open boundary: {}", observed.stderr));
    let terminal_at = observed
        .position_of("event", &terminal_event)
        .unwrap_or_else(|| panic!("no terminal: {}", observed.stderr));
    assert!(opened < terminal_at, "open at {opened}, terminal at {terminal_at}");

    // Cleanup: production closed its bounded Event Log admission exactly once
    // and reported outstanding delivery as unknown rather than as a drain.
    let shutdowns = observed.records_binding("event", &shutdown_event);
    assert_eq!(
        shutdowns.len(),
        1,
        "stderr: {}",
        observed.stderr
    );
    assert!(
        shutdowns[0].contains(&binding("outstanding_delivery", &outstanding)),
        "shutdown: {}",
        shutdowns[0]
    );

    // The return the child owned: exactly one console-protocol Error frame on
    // stdout and the console process exit code, with no diagnostic mark on the
    // stdout path.
    let frames = observed.frames();
    assert_eq!(frames.len(), 1, "stdout: {}", observed.stdout);
    assert_eq!(frames[0]["status"], "error");
    assert_eq!(observed.code, Some(console_exit_code()));
    for mark in [
        terminal_event.as_str(),
        fixture_text(fixture, &["forced_failure", "request_event"]).as_str(),
        HOST_DIAGNOSTICS_TARGET,
    ] {
        assert!(
            !observed.stdout.contains(mark),
            "diagnostic mark {mark:?} must stay off stdout"
        );
    }
}

/// Asserts that the diagnostic observation changed nothing this child owns.
///
/// Non-vacuity first: the admitted run really produced facade records and the
/// filtered run really produced none, so the comparison below contrasts a live
/// sink against a dead one instead of two runs that each did nothing.
fn assert_observation_changed_nothing(
    admitted: &HostRun,
    filtered: &HostRun,
    admitted_receipt: &Value,
    filtered_receipt: &Value,
) {
    assert!(
        !admitted.records().is_empty(),
        "stderr: {}",
        admitted.stderr
    );
    assert!(filtered.records().is_empty(), "stderr: {}", filtered.stderr);
    assert_eq!(admitted.code, filtered.code, "stderr: {}", filtered.stderr);
    assert_eq!(admitted.stdout, filtered.stdout);
    assert_eq!(admitted_receipt, filtered_receipt);
}

/// Marker the isolated Event Log start delivery carries.
///
/// Bounded, already redacted, and free of any protected marker, because
/// #984's port rejects such text before FFI. It is the only part of the record
/// that identifies this test run, which is what makes the readback below
/// unambiguous.
fn event_log_marker() -> String {
    format!("985-a13-isolated-start-{}", std::process::id())
}

/// Path of the real Windows Event Log query tool.
fn wevtutil_path() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| OsString::from(r"C:\Windows"));
    let candidate = PathBuf::from(&root).join("System32").join("wevtutil.exe");
    if candidate.is_file() {
        candidate
    } else {
        PathBuf::from("wevtutil.exe")
    }
}

/// Every real Event Log start record the Windows log currently stores for the
/// fixed source, oldest first. The whole admitted set is read rather than only
/// the newest record, so a concurrent child's own asynchronous start delivery
/// can never be mistaken for this test's record or hide it.
fn event_log_start_records(fixture: &Value) -> Vec<String> {
    let event_id = fixture_u64(fixture, &["event_log", "start_event_id"]);
    let channel = fixture_text(fixture, &["event_log", "readback_channel"]);
    let provider = fixture_text(fixture, &["event_log", "readback_provider"]);
    let query = format!("*[System[(EventID={event_id}) and Provider[@Name='{provider}']]]");
    let output = Command::new(wevtutil_path())
        .arg("qe")
        .arg(&channel)
        .arg(format!("/q:{query}"))
        .arg("/f:xml")
        .output()
        .unwrap_or_else(|error| panic!("wevtutil readback: {error}"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split("<Event xmlns=")
        .skip(1)
        .map(|record| format!("<Event xmlns={record}"))
        .collect()
}

/// Waits, within a bounded number of attempts, for the Windows Event Log
/// service to make the just-accepted record queryable, and returns that record.
///
/// `before` is how many admitted start records the log already held, so the
/// readback is non-vacuous: the marker must appear in a record the log did not
/// hold before this test's delivery.
fn await_delivered_start_record(fixture: &Value, marker: &str, before: usize) -> String {
    for attempt in 0..READBACK_ATTEMPTS {
        let records = event_log_start_records(fixture);
        if records.len() > before {
            if let Some(found) = records.iter().find(|record| record.contains(marker)) {
                return found.clone();
            }
        }
        if attempt + 1 < READBACK_ATTEMPTS {
            std::thread::sleep(Duration::from_millis(READBACK_INTERVAL_MS));
        }
    }
    panic!("the delivered Event Log start record never became readable for {marker}")
}

/// The verified fixture this file reads every pinned value from.
fn integration_fixture() -> Value {
    serde_json::from_str(FIXTURE).unwrap_or_else(|error| panic!("fixture must parse: {error}"))
}

// WORK_UNIT_CASE: 985/12
//
// A12 verbatim: "actual cross-child forced failure produces one terminal
// event and unchanged return/receipt/cleanup".
//
// Two real children, each with its own installation, its own Host state root
// and its own temp directory, each launched twice on the `SystemService`
// contour that really dispatches. What this proves by execution:
//
// * each child really crossed the Windows service boundary and really failed
//   at the `open_failed` boundary, with the supported console fallback
//   recorded on the contour allowed to fall back;
// * each child's own sink received exactly one terminal event carrying the
//   console terminal code, honestly uncorrelated, after exactly one failed
//   boundary record correlated to that child's own installation;
// * neither child can claim the other: no record of one run carries the other
//   installation, and neither receipt carries the other's identity;
// * the return value (exit code and the single stdout frame), the bounded
//   receipt, and the bounded shutdown cleanup are byte-identical whether the
//   observation happened or not.
#[test]
fn cross_child_forced_failure_emits_one_terminal_and_unchanged_result() {
    let fixture = integration_fixture();
    let alpha = IsolatedRun::new("a12-alpha");
    let beta = IsolatedRun::new("a12-beta");
    assert_ne!(alpha.installation, beta.installation);

    let mut observations = Vec::new();
    for run in [&alpha, &beta] {
        let admitted = run_host(run, &registration_nonce(), None);
        let admitted_receipt = sole_receipt(run);
        let filtered = run_host(run, &registration_nonce(), Some("off"));
        let filtered_receipt = sole_receipt(run);
        assert_observation_changed_nothing(
            &admitted,
            &filtered,
            &admitted_receipt,
            &filtered_receipt,
        );
        assert_forced_failure_contour(run, &admitted, &fixture);
        observations.push((run, admitted, admitted_receipt));
    }

    // The receipt is production's, bound to the launch argv this test handed
    // each child, so the isolation of the two runs is observable in the
    // durable artefact and not only in the captured sink.
    let receipt_type = fixture_text(&fixture, &["receipt", "record_type"]);
    let failure_class = fixture_text(&fixture, &["receipt", "failure_class"]);
    for (run, _, receipt) in &observations {
        assert_eq!(receipt["record_type"], receipt_type.as_str());
        assert_eq!(receipt["failure_class"], failure_class.as_str());
        assert_eq!(receipt["installation_id"], run.installation.as_str());
        assert_eq!(
            receipt["tx_plan_generation"].as_u64(),
            Some(run.generation)
        );
        assert_eq!(
            receipt["win32_exit_code"].as_i64(),
            Some(i64::from(console_exit_code()))
        );
    }

    // Cross-claim negatives: an installation never appears in a sink or a
    // receipt that is not its own, so no reader can pair one child's terminal
    // with the other child's failure.
    for (run, observed, receipt) in &observations {
        for (other, other_receipt) in observations.iter() {
            if other.installation == run.installation {
                continue;
            }
            for line in observed.records() {
                assert!(
                    !line.contains(&binding("installation", other.installation.as_str())),
                    "{other} identity claimed by {}: {line}",
                    run.installation
                );
            }
            assert_ne!(
                receipt["installation_id"],
                other_receipt["installation_id"],
                "receipts must stay per-child"
            );
        }
    }
}

// WORK_UNIT_CASE: 985/13
//
// A13 verbatim: "actual isolated Event Log start delivery, distinct from
// fake/unavailable/degraded source".
//
// Three legs, all executed against production, none of them a hand-built
// record:
//
// 1. Non-vacuity of the port. `event_log_sink_status` answers from the same
//    `#984` support predicate the delivery itself uses, so an accepted
//    delivery below is known to have crossed real OS code and not a stub.
// 2. The delivery. `report_admitted_event` is the synchronous production
//    function the bounded producer worker calls, so the outcome is the OS's
//    own answer rather than a race with an asynchronous worker. The asserted
//    arm is the honest one production can produce on this build, and it is
//    asserted to be neither the unreachable registered-source arm nor the
//    explicitly admitted degraded Application arm.
// 3. Real readback. The record production just submitted is found in the
//    Windows Application log itself, under the fixed source and the fixed
//    start event id, at the informational severity, carrying this run's own
//    marker. That is what separates an actual delivery from a fabricated one.
#[test]
fn isolated_event_log_start_delivery_is_real_and_distinct() {
    let fixture = integration_fixture();
    let source = fixture_text(&fixture, &["event_log", "source"]);
    let delivered_arm = fixture_text(&fixture, &["event_log", "delivered_arm"]);
    let unavailable = fixture_text(&fixture, &["event_log", "unavailable_name"]);
    let rejected = fixture_text(&fixture, &["event_log", "pre_ffi_rejection_name"]);
    assert_eq!(source, EVENT_LOG_SOURCE);

    // Leg 1: is a live port present at all on this build?
    let status = event_log_sink_status();
    if cfg!(windows) {
        assert_eq!(status, Ok(()), "the live Windows Event Log port must exist");
    } else {
        assert_eq!(status, Err(WindowsEventLogError::EventLogUnavailable));
        assert_eq!(
            WindowsEventLogError::EventLogUnavailable.as_str(),
            unavailable
        );
    }

    // Leg 2: the real delivery attempt, with production's own bounded record
    // construction doing the redaction and bounding. The readback baseline is
    // taken first so the record found afterwards is provably a new one.
    let marker = event_log_marker();
    let before = if cfg!(windows) {
        event_log_start_records(&fixture).len()
    } else {
        0
    };
    let delivered = report_admitted_event(AdmittedEvent::ServiceStart, &marker);
    if cfg!(windows) {
        let delivery = delivered.unwrap_or_else(|error| {
            panic!("a real Event Log start delivery must reach the OS port, got {error}")
        });
        assert_eq!(delivery.as_str(), delivered_arm);
        assert_eq!(delivery.event(), AdmittedEvent::ServiceStart);
        // Distinct from fake and from degraded: neither of those arms is
        // reachable on this build, and the arm production really returned is
        // asserted to be the honest OS-acceptance-with-registration-unknown
        // one, never either of them.
        assert!(
            matches!(
                delivery,
                EventLogDelivery::OsAcceptedRegistrationUnknown { .. }
            ),
            "the delivered arm must be the honest one, got {:?}",
            delivery.as_str()
        );
        for unreachable in fixture_texts(&fixture, &["event_log", "unreachable_arms"]) {
            assert_ne!(delivery.as_str(), unreachable);
        }
        // Distinct from unavailable: the unavailable outcome is a different
        // typed name and is not what this call returned.
        assert_ne!(delivery.as_str(), unavailable);
    } else {
        assert_eq!(delivered, Err(WindowsEventLogError::EventLogUnavailable));
    }

    // The wrapper discriminates before it fabricates anything: a submission
    // #984's port rejects pre-FFI never reaches the OS, so the accepted
    // delivery above cannot have been an unconditional success.
    let rejected_record = EventLogRecord::new(
        AdmittedEvent::ServiceStart,
        &format!("{}\0rejected", marker),
    );
    assert_eq!(
        report_event(&rejected_record),
        Err(WindowsEventLogError::InvalidRecord)
    );
    assert_eq!(
        WindowsEventLogError::InvalidRecord.as_str(),
        rejected
    );
    assert!(
        EventLogRecord::new(AdmittedEvent::ServiceStart, &marker).original_bytes()
            <= EVENT_LOG_MAX_INSERTION_BYTES,
        "the wrapper bounds the insertion string it submits"
    );

    // Leg 3: the real readback out of the Windows Application log.
    if cfg!(windows) {
        let record = await_delivered_start_record(&fixture, &marker, before);
        assert!(
            record.contains(&format!(
                "<EventID Qualifiers='0'>{}</EventID>",
                fixture_u64(&fixture, &["event_log", "start_event_id"])
            )),
            "record: {record}"
        );
        assert!(
            record.contains(&format!(
                "<Level>{}</Level>",
                fixture_u64(&fixture, &["event_log", "readback_information_level"])
            )),
            "record: {record}"
        );
        assert!(
            record.contains(&format!(
                "Provider Name='{}'",
                fixture_text(&fixture, &["event_log", "readback_provider"])
            )),
            "record: {record}"
        );
        assert!(record.contains(&marker), "record: {record}");
        // The admission evidence gate production applies to a start, checked
        // against the same evidence the real child below projects.
        assert!(AdmittedEvent::ServiceStart.is_admitted_by(HostRequestEvidence::ProcessStarted));
        assert!(
            !AdmittedEvent::ServiceStart.is_admitted_by(HostRequestEvidence::Observed),
            "a sighted record never admits a start record"
        );
    }
}

// WORK_UNIT_CASE: 985/13
//
// The cross-child leg of A13: a real child really admits a real Event Log
// start record, with the owner evidence that admits it, and this test reads
// that admission out of the child's own sink.
//
// This leg stops where determinism stops. `shutdown_event_log_producer` joins
// no worker and process exit discards whatever is still queued, so the
// child's asynchronous OS delivery cannot be read back without racing the
// child's exit; that boundary is named in the file ceiling instead of being
// asserted as a delivery. What is asserted here is fully deterministic: the
// child really started the bounded producer and really admitted the start
// record its own `process_started` evidence supports.
#[test]
fn a_real_child_admits_its_event_log_start_record() {
    let fixture = integration_fixture();
    let run = IsolatedRun::new("a13-child");
    let observed = run_host(&run, &registration_nonce(), None);
    let admission_event = fixture_text(&fixture, &["event_log", "admission_event"]);
    let start_operation = fixture_text(&fixture, &["event_log", "start_operation"]);
    let start_phase = fixture_text(&fixture, &["event_log", "start_phase"]);
    let start_evidence = fixture_text(&fixture, &["event_log", "start_evidence"]);

    let admissions = observed.record_with(&[
        ("event", admission_event.as_str()),
        ("operation", start_operation.as_str()),
    ]);
    let admission = admissions.unwrap_or_else(|| {
        panic!(
            "no Event Log start admission: {}",
            observed.stderr
        )
    });
    assert!(
        admission.contains(&binding("phase", &start_phase)),
        "admission: {admission}"
    );
    assert!(
        admission.contains(&binding("evidence", &start_evidence)),
        "admission: {admission}"
    );
    // The outcome is production's own stable admission name. It is not pinned
    // to one value: admission contends with the worker's own queue lock, so
    // `admitted` and `producer_busy` are both honest production answers and
    // the record under test is the admission itself.
    let outcome = field_value(&admission, "outcome")
        .unwrap_or_else(|| panic!("admission must name its outcome: {admission}"));
    assert!(!outcome.is_empty(), "admission: {admission}");

    // The bounded producer really started in this child, so the admission
    // above was not refused because no producer existed.
    let starts = observed.records_binding("event", "host.event_log_producer_start");
    assert_eq!(starts.len(), 1, "stderr: {}", observed.stderr);
    assert!(
        starts[0].contains(&binding("worker_started", "true")),
        "producer start: {}",
        starts[0]
    );
}

// WORK_UNIT_CASE: 985/12
//
// Supplementary emission binding for the drift documented in the file header.
//
// This is NOT the primary evidence for A12: the executed children above are.
// It exists because the rescued head's `count() == 1` pin was wrong and must
// not be restored, so the drift needs an honest statement of what is true.
// The occurrence count of a callee name is not the terminal-singularity
// invariant - a correct fix adds a second, differently owned emission for a
// different operation, and prose mentions the callee too - so the invariant
// asserted here is the exact set of (owning function, typed terminal code)
// pairs, reconciled against the code value the executed children really
// emitted.
#[test]
fn main_terminal_emissions_are_owned_per_failed_operation() {
    let fixture = integration_fixture();
    let mentions = fixture_u64(&fixture, &["main_terminal_drift", "callee_name_mentions"]);
    let sites = fixture_u64(&fixture, &["main_terminal_drift", "emission_sites"]);
    let console_code = fixture_text(&fixture, &["main_terminal_drift", "console_terminal_code"]);
    let dispatcher_code =
        fixture_text(&fixture, &["main_terminal_drift", "dispatcher_terminal_code"]);
    assert_eq!(console_code, HOST_TERMINAL_CODE_CONSOLE_FAILED);
    assert_eq!(dispatcher_code, HOST_TERMINAL_CODE_DISPATCHER_FAILED);

    // The drift itself: the callee name occurs more often than there are real
    // emission sites, so no occurrence count of this name can be an invariant.
    assert_eq!(MAIN_SRC.matches("observe_terminal_error").count() as u64, mentions);
    assert!(mentions > sites);

    let lines: Vec<&str> = MAIN_SRC.lines().collect();
    let mut owner = String::new();
    let mut emissions: Vec<(String, String)> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if let Some(name) = line.strip_prefix("fn ") {
            owner = name.split('(').next().unwrap_or(name).trim().to_owned();
        }
        if !line.trim_end().ends_with("observe_terminal_error(") {
            continue;
        }
        let constant = lines
            .get(index + 1)
            .and_then(|next| next.rsplit("::").next())
            .unwrap_or_default()
            .trim()
            .trim_end_matches(',');
        let value = match constant {
            "HOST_TERMINAL_CODE_CONSOLE_FAILED" => HOST_TERMINAL_CODE_CONSOLE_FAILED,
            "HOST_TERMINAL_CODE_DISPATCHER_FAILED" => HOST_TERMINAL_CODE_DISPATCHER_FAILED,
            other => panic!("terminal emission must name its typed code, got {other}"),
        };
        emissions.push((owner.clone(), value.to_owned()));
    }
    assert_eq!(emissions.len() as u64, sites);
    assert_eq!(
        emissions,
        vec![
            ("main".to_owned(), console_code),
            ("fail_scm_dispatcher".to_owned(), dispatcher_code),
        ],
        "one terminal emitter per failed operation"
    );
}