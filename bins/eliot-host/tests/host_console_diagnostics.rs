//! F-LOG-HOST-7 proof (#982): console failure observations preserve wire/exit/fallback/cleanup and record B1-B14 via #889 facade to stderr only.
//!
//! #982 integration-target ceiling, named rather than silently absorbed.
//!
//! Four changed production paths in `bins/eliot-host/src/main.rs` cannot be
//! reached by any binary this target launches, so no test here claims them and
//! no marker in this file names their case number:
//!
//! * `run_console`'s primary-outcome/cleanup split
//!   (`ConsoleRun { primary, drained }`). The judgement differs from the old
//!   drain-only boolean on exactly one contour: a Ready, response, or stdin-read
//!   failure paired with a *successful* drain. Reaching it needs an installed
//!   protected Host root, an approved generation, and a live store, which no
//!   in-repo fixture creates — `open_host` refuses the empty registry these
//!   isolated runs build, so every launched run ends at the `open_failed`
//!   boundary before it writes any protocol frame or reads any stdin line, and
//!   this target always runs the child with the null device as stdin, so the
//!   read loop can only ever meet a clean EOF.
//! * `StopDisposition::Attempted` gating the second `host.stop()`. The gate is
//!   consulted only when the served `Stop` request's own semantic stop failed
//!   and the host is still running, which needs that same successful open plus a
//!   served `Stop`.
//! * `fail_scm_dispatcher`'s typed
//!   `observe_terminal_error(HOST_TERMINAL_CODE_DISPATCHER_FAILED)`. The `Err`
//!   arm needs `StartServiceCtrlDispatcherW` to fail with a code other than
//!   `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`, and that is the code a launched
//!   process always receives; any other code requires the SCM to already own
//!   this service name on the machine.
//! * `observe_service_entry_failure` and the service-entry classes it projects.
//!   Every one of those boundaries lives in `service_main`, which only the SCM
//!   invokes.
//!
//! What this target therefore proves is the *preserved* side: the two contours
//! it can really launch still produce exactly the stdout framing, process exit
//! code, and bounded start-failure receipt they produced before the change, and
//! nothing on those contours moved. The dispatcher terminal's changed binding is
//! pinned structurally by the source-scan test below, because the runtime seam
//! for it does not exist from here; that source pin is supplementary to the
//! executed contours, never a substitute for one.
use eliot_host::host_diagnostics::{HOST_DIAGNOSTICS_TARGET, HOST_TERMINAL_CODE_CONSOLE_FAILED};
use serde_json::Value;
use std::process::Command;
const MAIN: &str = include_str!("../src/main.rs");
const PROTOCOL: &str = include_str!("../src/host_console_protocol.rs");
const FIXTURE: &str = include_str!("data/host_console_diagnostics.json");
const BANNED: [&str; 4] = ["to_string()", "args", "env::", "nonce"];
/// The one fixture boundary whose production binding this issue moved: the bare
/// `dispatcher_failed` ScmDispatch stage detail was replaced by the typed
/// dispatcher terminal, so it is asserted at its real binding instead of by
/// presence in the source.
const REBOUND_BOUNDARY: &str = "dispatcher_failed";
fn console_binary() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("exe: {e}"));
    let top = exe.ancestors().nth(2).unwrap_or_else(|| panic!("dir"));
    top.join(format!("eliot-host{}", std::env::consts::EXE_SUFFIX))
}
// WORK_UNIT_CASE: 982/1, 982/2
//
// The #984 boundary table and its terminal-singularity invariant, proved over
// the source of `main.rs` because these two obligations are structural: one
// declared observation site per declared boundary, and exactly one terminal
// emitter per failed operation. This is SUPPLEMENTARY evidence. The primary
// evidence for every boundary an executed contour can reach is the launched-
// binary tests below; the four boundaries listed in the file ceiling have no
// executed contour from this target, so nothing here is promoted past a source
// pin on their behalf.
#[test]
fn host_console_boundaries_are_complete_and_singular() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap_or_else(|e| panic!("json: {e}"));
    let bounds = fixture["boundaries"].as_array();
    for m in bounds.unwrap_or_else(|| panic!("array")) {
        let m = m.as_str().unwrap_or_else(|| panic!("strings"));
        if m == REBOUND_BOUNDARY {
            // Asserted at the binding it actually has below, not by presence.
            continue;
        }
        assert!(MAIN.contains(m), "marker missing: {m}");
    }
    // The one boundary marker whose production binding moved. The bare
    // `dispatcher_failed` ScmDispatch stage detail is gone, replaced (never
    // joined) by the typed terminal `fail_scm_dispatcher` emits, so a plain
    // presence scan would now be satisfied only by the `HostStopCode`
    // failure-class spelling and would pin nothing about what is observed.
    // Both halves of the real binding are asserted instead: the class spelling
    // the stable receipt depends on, and the absence of the bare detail.
    assert!(
        MAIN.contains("Self::DispatcherFailed => \"dispatcher_failed\","),
        "the dispatcher failure class keeps its stable capsule spelling"
    );
    assert!(
        !MAIN
            .lines()
            .any(|line| line.trim() == "\"dispatcher_failed\","),
        "the bare dispatcher_failed stage detail must not return to the dispatcher arm"
    );
    assert_eq!(MAIN.matches("install_host_diagnostics").count(), 1);
    // One terminal per failed operation, and no second terminal emitter. The
    // occurrence count of the callee name is not the invariant: a correct fix
    // adds a second, differently-owned emission for a different operation. The
    // invariant is the exact set of (owning function, typed terminal code)
    // pairs, which stays red if one operation grows a second terminal or
    // reuses another operation's code.
    let lines: Vec<&str> = MAIN.lines().collect();
    let mut owner = String::new();
    let mut terminals: Vec<(String, String)> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if let Some(name) = line.strip_prefix("fn ") {
            owner = name.split('(').next().unwrap_or(name).trim().to_owned();
        }
        if !line.trim_end().ends_with("observe_terminal_error(") {
            continue;
        }
        let code = lines
            .get(index + 1)
            .and_then(|next| next.rsplit("::").next())
            .unwrap_or_default();
        let code = code.trim().trim_end_matches(',');
        assert!(
            !code.is_empty(),
            "terminal emission must name its typed code"
        );
        terminals.push((owner.clone(), code.to_owned()));
    }
    assert_eq!(
        terminals,
        vec![
            (
                "main".to_owned(),
                "HOST_TERMINAL_CODE_CONSOLE_FAILED".to_owned()
            ),
            (
                "fail_scm_dispatcher".to_owned(),
                "HOST_TERMINAL_CODE_DISPATCHER_FAILED".to_owned()
            ),
        ],
        "one terminal emitter per failed operation"
    );
    assert!(
        MAIN.contains("if console.failed() {")
            && MAIN.contains("fn fail_scm_dispatcher(error: u32) -> ! {"),
        "each terminal emission is guarded by its own operation and ends that process"
    );
    assert_eq!(MAIN.matches("write_response(&").count(), 4);
    // The `std::process::exit(` occurrence count is not asserted here and
    // never was a console invariant: it also counts the two I3.1 profile
    // supervisor exits, which this boundary table does not own, so it stopped
    // binding anything about the console contour when that supervision landed
    // (it reads 4 on `origin/main`, not 2). What the console contour owns is
    // asserted structurally by the terminal-pair set above: exactly one terminal
    // emission per failed operation, and nothing else may end that process.
    //
    // The `match host.stop()` count below is a real console invariant and stays:
    // exactly one semantic stop in the served-`Stop` path and exactly one in the
    // shutdown drain, so a drain that repeated a request's own stop would make
    // this 3.
    assert_eq!(MAIN.matches("match host.stop()").count(), 2);
    assert!(PROTOCOL.contains("io::stdout"));
    assert!(!PROTOCOL.contains("stderr") && !PROTOCOL.contains("observe_"));
    for line in MAIN.lines().filter(|l| l.contains("observe_entrypoint")) {
        let hit = BANNED.iter().any(|b| line.contains(b));
        assert!(!hit, "diagnostic line must stay static: {line}");
    }
}
// WORK_UNIT_CASE: 982/3, 982/14
#[test]
fn host_console_binary_keeps_protocol_on_stdout_only() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap_or_else(|e| panic!("json: {e}"));
    let out = Command::new(console_binary())
        .arg("--no-such-flag-982")
        .output();
    let child = out.unwrap_or_else(|e| panic!("run: {e}"));
    #[cfg(windows)]
    assert_eq!(child.status.code(), Some(1066));
    #[cfg(not(windows))]
    assert_eq!(child.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&child.stdout);
    let stderr = String::from_utf8_lossy(&child.stderr);
    assert_eq!(stdout.lines().count(), 1, "stdout: {stdout}");
    let frame: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("frame: {e}"));
    assert_eq!(frame["status"], fixture["expected_error_status"]);
    let marks = fixture["marks"].as_array();
    for m in marks.unwrap_or_else(|| panic!("array")) {
        let m = m.as_str().unwrap_or_else(|| panic!("strings"));
        assert!(!stdout.contains(m), "diagnostics on stdout: {m}");
    }
    assert!(!stderr.contains("\"status\""), "protocol on stderr");
}

// Executable proof for the boundaries the two cases above cannot reach.
//
// Every case below launches the REAL `eliot-host` binary and asserts only on
// what production actually wrote: the console frames on stdout, the #889
// facade records the child's own diagnostic sink received, the bounded
// start-failure receipt, and the process exit code. No facade call
// manufactures a record under test, no source text is scanned, and no
// expected record is hand-built; each assertion names a production symbol and
// the behavior that symbol preserved.

/// Non-zero plan generation the launch argv carries.
const HOST_PLAN_GENERATION: u64 = 7;
/// The console process exit code production terminates with on Windows.
const HOST_CONSOLE_EXIT_WINDOWS: i32 = 1066;
/// The `Win32` exit code the bounded receipt records for every typed failure.
const HOST_RECEIPT_WIN32_EXIT: i32 = 1066;
/// `HostStopCode::ConsoleFailed` discriminant, the receipt's specific code.
const HOST_CONSOLE_STOP_SPECIFIC: i64 = 13;

/// One isolated environment the child process owns end to end.
///
/// The state root is created here and handed over as `--host-state-root`; the
/// temp directory is handed over as the child's `TMP`/`TEMP`, so even the
/// receipt fallback of a run whose launch argv never parsed stays inside this
/// test. The installation id is unique per case, so the process-global Host
/// owner lease is never contended between cases, and both directories are
/// removed when the case ends.
struct IsolatedRun {
    state_root: std::path::PathBuf,
    temp: std::path::PathBuf,
    base: std::path::PathBuf,
    installation: String,
    generation: u64,
}

impl IsolatedRun {
    fn new(case: &str) -> Self {
        let base = std::env::temp_dir().join(format!("eliot-982-{case}-{}", std::process::id()));
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
            installation: format!("installation-982-{case}"),
            generation: HOST_PLAN_GENERATION,
        }
    }
}

impl Drop for IsolatedRun {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// Lowercase 64-hex config-descriptor digest the launch argv carries.
///
/// `HostLaunchOptions::parse` admits a digest only as exactly 64 lowercase hex
/// characters, so the `9829` marker stays inside the shape production parsed
/// and is the value the launch-material case searches the sink for.
fn descriptor_digest() -> String {
    "9829".repeat(16)
}

/// Lowercase 64-hex registration nonce the service-shaped launch carries.
fn registration_nonce() -> String {
    let marker = "c0ffee".repeat(10);
    format!("{marker}9829")
}

/// The exact launch argv one console run is handed.
///
/// Every value is shaped by the production parser that reads it
/// (`HostLaunchOptions::parse`): an absolute config-descriptor path, a
/// lowercase 64-hex digest, a non-empty installation id, a non-zero plan
/// generation, an absolute Host state root, and optionally the registration
/// nonce pair that only a `SystemService` bootstrap may carry.
fn launch_args(run: &IsolatedRun, nonce: Option<&str>) -> Vec<std::ffi::OsString> {
    let mut args = vec![
        std::ffi::OsString::from("--config-descriptor"),
        run.state_root.join("descriptor.json").into_os_string(),
        std::ffi::OsString::from("--config-descriptor-sha256"),
        std::ffi::OsString::from(descriptor_digest()),
        std::ffi::OsString::from("--installation-id"),
        std::ffi::OsString::from(run.installation.as_str()),
        std::ffi::OsString::from("--tx-plan-generation"),
        std::ffi::OsString::from(run.generation.to_string()),
        std::ffi::OsString::from("--host-state-root"),
        run.state_root.as_os_str().to_owned(),
    ];
    if let Some(nonce) = nonce {
        args.push(std::ffi::OsString::from("--registration-nonce"));
        args.push(std::ffi::OsString::from(nonce));
    }
    args
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

    /// The `#889` facade records this run's own sink received, in sink order.
    fn records(&self) -> Vec<&str> {
        self.stderr
            .lines()
            .filter(|line| line.contains(HOST_DIAGNOSTICS_TARGET))
            .collect()
    }

    /// How many facade records carry this exact `key="value"` binding.
    fn count_binding(&self, key: &str, value: &str) -> usize {
        let binding = binding(key, value);
        self.records()
            .iter()
            .filter(|line| line.contains(&binding))
            .count()
    }

    /// Every typed terminal code this run's sink received, in sink order.
    fn terminal_codes(&self) -> Vec<String> {
        self.records()
            .iter()
            .copied()
            .filter_map(|line| field_value(line, "code"))
            .collect()
    }

    /// The first facade record carrying every one of these exact bindings.
    fn record_with(&self, bindings: &[(&str, &str)]) -> Option<String> {
        self.records()
            .iter()
            .copied()
            .find(|line| {
                bindings
                    .iter()
                    .all(|(key, value)| line.contains(&binding(key, value)))
            })
            .map(String::from)
    }

    /// Sink position of the first facade record carrying `key="value"`.
    fn position_of(&self, key: &str, value: &str) -> Option<usize> {
        let binding = binding(key, value);
        self.records()
            .iter()
            .position(|line| line.contains(&binding))
    }
}

/// The exact `key="value"` spelling the facade's `tracing` fields render.
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

/// Runs the real `eliot-host` binary once for one launch argv.
///
/// `filter` is the `RUST_LOG` value the child's `install_host_diagnostics`
/// builds its `EnvFilter` from; `None` removes the variable so the sink admits
/// the facade records at their default level. stdin is the null device, so the
/// console read loop meets a real EOF instead of waiting for a peer, and the
/// child terminates on its own without a timeout.
fn run_host(run: &IsolatedRun, nonce: Option<&str>, filter: Option<&str>) -> HostRun {
    let mut command = Command::new(console_binary());
    command
        .args(launch_args(run, nonce))
        .stdin(std::process::Stdio::null())
        .env("TMP", &run.temp)
        .env("TEMP", &run.temp);
    if let Some(filter) = filter {
        command.env("RUST_LOG", filter);
    } else {
        command.env_remove("RUST_LOG");
    }
    let child = command
        .output()
        .unwrap_or_else(|error| panic!("run: {error}"));
    HostRun {
        stdout: String::from_utf8_lossy(&child.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&child.stderr).into_owned(),
        code: child.status.code(),
    }
}

/// The console process exit code production terminates with on this platform
/// (`console_process_exit_code` in the binary).
fn console_exit_code() -> i32 {
    if cfg!(windows) {
        HOST_CONSOLE_EXIT_WINDOWS
    } else {
        1
    }
}

/// The one bounded start-failure receipt this run's owner wrote.
///
/// The owner is production's `persist_host_start_failure`, which writes into the
/// parsed launch options' Host state root, or into the process temp directory
/// when the process bootstrap never parsed. Both directories belong to this
/// test, so exactly one file across them is production's receipt and nothing
/// else: a second receipt or a missing one fails here instead of passing
/// unnoticed.
fn sole_receipt(run: &IsolatedRun) -> Value {
    let mut files = Vec::new();
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
        "exactly one start-failure receipt, found {files:?}"
    );
    let bytes =
        std::fs::read(&files[0]).unwrap_or_else(|error| panic!("{}: {error}", files[0].display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("receipt {}: {error}", files[0].display()))
}

// WORK_UNIT_CASE: 982/4, 982/5
//
// The two contours this target can really launch: the `SystemService` argv shape,
// which enters `run_as_scm_service` and receives the documented
// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`, and the nonce-free argv, which
// production recognises from the argv itself and never dispatches at all.
//
// What this proves: the supported console fallback is recorded exactly once and
// only on the contour allowed to fall back; the nonce-free launcher contour never
// emits it; neither run emits a second terminal, the dispatcher's terminal, or
// the dispatcher's receipt text; and both continue into the console protocol
// with the framing, exit code, and bounded receipt they always had.
//
// What this does NOT prove, and must not be read as proving:
// `fail_scm_dispatcher`'s typed `HOST_TERMINAL_CODE_DISPATCHER_FAILED` terminal.
// The `Err` arm is unreachable from this target (see the file ceiling), so the
// assertions below are the proof that the dispatcher-failure arm genuinely did
// not run — a negative boundary, never the changed terminal itself.
#[test]
fn scm_dispatch_console_fallback_stays_distinct_from_a_dispatcher_failure() {
    let entered = IsolatedRun::new("dispatch-entered");
    let skipped = IsolatedRun::new("dispatch-nonce-free");
    // The nonce pair makes this the `SystemService` bootstrap shape, so `main`
    // really entered `run_as_scm_service` and this process really called
    // `StartServiceCtrlDispatcherW`. The nonce-free argv is the documented
    // current-user launcher shape that production recognises from the argv
    // itself, without entering the dispatcher at all.
    let dispatcher_run = run_host(&entered, Some(&registration_nonce()), None);
    let launcher_run = run_host(&skipped, None, None);
    // A process the SCM did not start is answered with the documented console
    // case, so the supported fallback is recorded exactly once, under the one
    // contour that is allowed to fall back. Off Windows there is no SCM
    // dispatch seam at all and no fallback may be invented.
    let fallback_records: usize = if cfg!(windows) { 1 } else { 0 };
    assert_eq!(
        dispatcher_run.count_binding("detail", "console_fallback"),
        fallback_records,
        "stderr: {}",
        dispatcher_run.stderr
    );
    assert_eq!(
        launcher_run.count_binding("detail", "current_user_profile_launcher"),
        fallback_records,
        "stderr: {}",
        launcher_run.stderr
    );
    assert_eq!(
        launcher_run.count_binding("detail", "console_fallback"),
        0,
        "the nonce-free launcher contour never entered the dispatcher: {}",
        launcher_run.stderr
    );
    // The fallback is not a dispatcher failure: the terminal that only
    // `fail_scm_dispatcher` owns must appear on neither contour, and neither
    // run may print the dispatcher receipt line.
    for run in [&dispatcher_run, &launcher_run] {
        assert_eq!(
            run.terminal_codes(),
            vec![HOST_TERMINAL_CODE_CONSOLE_FAILED.to_owned()],
            "stderr: {}",
            run.stderr
        );
        assert!(
            !run.stderr.contains("StartServiceCtrlDispatcherW failed"),
            "dispatcher receipt text: {}",
            run.stderr
        );
    }
    // Both contours continued into the console protocol instead of failing at
    // the process entry, and kept its response, exit, and bounded receipt.
    for (run, fixture, parsed_bootstrap) in [
        (&dispatcher_run, &entered, true),
        (&launcher_run, &skipped, false),
    ] {
        let frames = run.frames();
        assert_eq!(frames.len(), 1, "stdout: {}", run.stdout);
        assert_eq!(frames[0]["status"], "error");
        assert_eq!(run.code, Some(console_exit_code()));
        let receipt = sole_receipt(fixture);
        assert_eq!(receipt["failure_class"], "console_failed");
        // The receipt identity comes from the captured process bootstrap: the
        // parsed `SystemService` argv names its installation, while the
        // launcher argv never produced a bootstrap and honestly has none.
        let identity = if parsed_bootstrap {
            Value::from(fixture.installation.as_str())
        } else {
            Value::Null
        };
        assert_eq!(receipt["installation_id"], identity);
    }
}

// WORK_UNIT_CASE: 982/10
//
// The one failed console contour this target can really launch: `open_host`
// refuses the empty registry this isolated run owns, so the run ends at the
// `open_failed` boundary.
//
// What this proves: on that contour production writes exactly the Error frame
// the protocol always wrote for a failed open, exactly one boundary record for
// the failed open, exactly one terminal — the console terminal `main` owns, not
// a second one for the lib-owned child failure — with the open boundary ordered
// before it, the failed-request projection correlated to this installation, and
// the bounded receipt carrying this run's own identity and typed codes.
//
// What this does NOT prove: the primary-outcome/cleanup split. This run's
// `ConsoleRun` is `{ primary: Failed, drained: false }`, which both the old
// drain-only boolean and the new conjunction judge identically (see the file
// ceiling), so this test is preserved-behaviour evidence and not evidence for
// that change.
#[test]
fn console_open_failure_keeps_one_error_frame_and_the_single_console_terminal() {
    let fixture = IsolatedRun::new("console-open-failure");
    let run = run_host(&fixture, Some(&registration_nonce()), None);
    // The console open boundary writes exactly the Error frame the protocol
    // always wrote for a failed open, and nothing else reaches stdout.
    let frames = run.frames();
    assert_eq!(frames.len(), 1, "stdout: {}", run.stdout);
    assert_eq!(frames[0]["status"], "error");
    assert!(
        frames[0]["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty()),
        "frame: {}",
        frames[0]
    );
    assert_eq!(run.code, Some(console_exit_code()));
    // Exactly one terminal for the failed run, and it is the console terminal
    // `main` owns: the open failure is a child failure whose terminal belongs
    // to the library, so the binary must not add a second terminal for it.
    assert_eq!(
        run.terminal_codes(),
        vec![HOST_TERMINAL_CODE_CONSOLE_FAILED.to_owned()],
        "stderr: {}",
        run.stderr
    );
    assert_eq!(
        run.count_binding("detail", "open_failed"),
        1,
        "stderr: {}",
        run.stderr
    );
    // The open boundary is observed before the terminal that summarises the
    // whole run, so the record order is production's, not an inference.
    let opened = run
        .position_of("detail", "open_failed")
        .unwrap_or_else(|| panic!("no open boundary: {}", run.stderr));
    let terminal = run
        .position_of("code", HOST_TERMINAL_CODE_CONSOLE_FAILED)
        .unwrap_or_else(|| panic!("no console terminal: {}", run.stderr));
    assert!(
        opened < terminal,
        "open at {opened}, terminal at {terminal}"
    );
    // The failing request projection correlates the installation this run was
    // launched with and carries the typed reason, which is a discriminant only.
    let projection = run
        .record_with(&[
            ("event", "host.request"),
            ("phase", "console_loop"),
            ("evidence", "failed"),
            ("operation", "service_start"),
            ("installation", fixture.installation.as_str()),
        ])
        .unwrap_or_else(|| panic!("no failed open projection: {}", run.stderr));
    assert!(
        field_value(&projection, "reason").is_some_and(|reason| !reason.is_empty()),
        "projection: {projection}"
    );
    // The bounded receipt keeps this installation's identity and the console
    // failure class with its own exit codes.
    let receipt = sole_receipt(&fixture);
    assert_eq!(receipt["record_type"], "host_start_failure");
    assert_eq!(receipt["failure_class"], "console_failed");
    assert_eq!(receipt["win32_exit_code"], HOST_RECEIPT_WIN32_EXIT);
    assert_eq!(
        receipt["service_specific_exit_code"],
        HOST_CONSOLE_STOP_SPECIFIC
    );
    assert_eq!(receipt["installation_id"], fixture.installation.as_str());
    assert_eq!(
        receipt["tx_plan_generation"].as_u64(),
        Some(fixture.generation)
    );
}

// WORK_UNIT_CASE: 982/12
//
// The diagnostic sink is not load-bearing for the console outcome.
//
// This is a self-comparison, so it only means anything once both sides are
// shown to be the same real work: below, each run must independently write the
// one bounded `console_failed` receipt, exit with the console failure code, and
// emit exactly one terminal and one `open_failed` boundary. Only then does
// comparing them state a property of production — the sink outcome changes
// nothing the console owns — instead of comparing two runs that may both have
// done nothing.
//
// What this does NOT prove: any changed production path. The sink is a #889
// facade concern and this issue changed no sink code, so this is
// preserved-behaviour evidence; the four changed paths in the file ceiling have
// no executed contour here.
#[test]
fn a_filtered_diagnostic_sink_leaves_the_console_result_unchanged() {
    let fixture = IsolatedRun::new("sink-filtered");
    // The identical launch, twice: once with the sink admitting the facade
    // records and once with the filter that drops every one of them.
    let admitted = run_host(&fixture, Some(&registration_nonce()), None);
    let admitted_receipt = sole_receipt(&fixture);
    let filtered = run_host(&fixture, Some(&registration_nonce()), Some("off"));
    let filtered_receipt = sole_receipt(&fixture);
    // Non-vacuity first: the filter really removed every facade record, so the
    // comparison below contrasts a live sink against a dead one instead of
    // two identical runs.
    assert!(
        !admitted.records().is_empty(),
        "stderr: {}",
        admitted.stderr
    );
    assert!(filtered.records().is_empty(), "stderr: {}", filtered.stderr);
    // Both sides are the same real failed console run, produced independently.
    // Without this the invariance assertion below would be satisfied by two
    // runs that each did nothing observable at all.
    for run in [&admitted, &filtered] {
        assert_eq!(run.code, Some(console_exit_code()), "stderr: {}", run.stderr);
        assert_eq!(
            run.terminal_codes(),
            vec![HOST_TERMINAL_CODE_CONSOLE_FAILED.to_owned()],
            "stderr: {}",
            run.stderr
        );
        assert_eq!(
            run.count_binding("detail", "open_failed"),
            1,
            "stderr: {}",
            run.stderr
        );
        assert_eq!(
            run.frames().len(),
            1,
            "the failed run owes exactly the one Error frame: {}",
            run.stdout
        );
    }
    assert_eq!(admitted_receipt["failure_class"], "console_failed");
    assert_eq!(filtered_receipt["failure_class"], "console_failed");
    // The sink outcome changed nothing the console owns: same response bytes,
    // same exit code, same bounded receipt.
    assert_eq!(filtered.stdout, admitted.stdout);
    assert_eq!(filtered.code, admitted.code);
    assert_eq!(filtered_receipt, admitted_receipt);
}

// WORK_UNIT_CASE: 982/13
//
// No launch material ever reaches the diagnostic records on a contour this
// target can really launch.
//
// This case is a preserved-behaviour obligation, not a changed one: the #889
// facade already emitted no argv, nonce, or path before this issue, and the
// issue added no new callsite that could widen that surface. It is kept because
// it protects observed value, not because it discriminates the change.
//
// The canaries are load-bearing: the permitted identity really did reach the
// sink and the parsed argv really produced this run's receipt, so the absence
// checks below are about the rest of the launch material rather than about a
// silent sink.
#[test]
fn launch_material_never_reaches_the_diagnostic_records() {
    let fixture = IsolatedRun::new("launch-material-canaries");
    let run = run_host(&fixture, Some(&registration_nonce()), None);
    let records = run.records();
    assert!(!records.is_empty(), "stderr: {}", run.stderr);
    // The canaries really were in play for this run: the parsed argv identities
    // are the ones the receipt owner recorded from them.
    let receipt = sole_receipt(&fixture);
    assert_eq!(receipt["installation_id"], fixture.installation.as_str());
    assert_eq!(
        receipt["tx_plan_generation"].as_u64(),
        Some(fixture.generation)
    );
    // The permitted identity really did reach the sink, so the absence checks
    // below are about the rest of the launch material, not about a silent sink.
    assert!(
        records
            .iter()
            .any(|line| line.contains(&binding("installation", fixture.installation.as_str()))),
        "stderr: {}",
        run.stderr
    );
    // The descriptor digest, the registration nonce, and every path this run
    // was handed (descriptor, state root, and the child's own temp directory,
    // all under the case marker) stay out of the records.
    let canaries = [
        descriptor_digest(),
        registration_nonce(),
        fixture.base.to_string_lossy().into_owned(),
    ];
    for canary in &canaries {
        for line in &records {
            assert!(
                !line.contains(canary.as_str()),
                "launch material on the sink: {canary} in {line}"
            );
        }
    }
}
