#![cfg(windows)]

use eliot_types::{ProjectId, TaskId, WriteId};
use eliot_windows_ipc::ProcessTreeGuard;
use serde_json::Value;
use std::fs;
use std::io::{BufRead as _, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

// Debug builds on the certification host normally publish READY within seconds. Thirty
// seconds leaves cold-start headroom while keeping a wedged fixture bounded and actionable.
const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(30);
const DIAGNOSTIC_TAIL_BYTES: u64 = 8 * 1024;
static DAEMON_RUNTIME_LEASE: Mutex<()> = Mutex::new(());

// Fixture-root uniqueness counter. `OwnedRuntime::new` used to derive its
// runtime path from a wall-clock nanosecond plus the process ID alone, which is
// not collision-free: on Windows the system clock is coarse enough that two
// tests constructing a fixture in the same instant on the same thread pool can
// be handed the SAME path, and the first one to finish deletes the shared root
// out from under the other (`OwnedRuntime::drop` calls `remove_dir_all`).
// `DAEMON_RUNTIME_LEASE` used to hide this by serializing every daemon test in
// this binary. Now that the front-door tests no longer need that lease, the
// counter makes each fixture root genuinely unique regardless of scheduling.
static RUNTIME_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Canonical front-door refusal contract (retirement of the legacy route)
// ---------------------------------------------------------------------------
//
// Every test below used to start a real `eliot-governor daemon run` runtime and
// assert live Governor/MCP behaviour over it. That route no longer exists, so
// each test now asserts the contract the product actually publishes: the
// retired entrypoint refuses fail-closed with a stable machine-readable code
// plus the canonical Kernel-governed route, and serves nothing.
//
// Owner of the refusal: `crates/eliot-app/src/front_door_cutover.rs`
// (`LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER`, `LEGACY_ENTRYPOINT_CANONICAL_ROUTE`).
// `assert_canonical_route_matches_source` re-reads that module so the two
// literals below are proven against the real owner instead of assumed, and a
// future change to the owner's text fails here rather than silently passing.

/// Exact `code` field of every retired-entrypoint refusal receipt.
const EXPECTED_CUTOVER_CODE: &str = "LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER";

/// Exact `canonical_route` field of every retired-entrypoint refusal receipt,
/// copied verbatim from `LEGACY_ENTRYPOINT_CANONICAL_ROUTE`.
const EXPECTED_CANONICAL_ROUTE: &str = "eliot setup through the Kernel canonical configuration surface (Host-managed StoreLaunchConfig bound to the installation manifest; Governor operates only as outbound-only eliotd polling Kernel; typed policy resolves only through eliotd::canonical_config_precedence)";

/// Fails unless the two literals above still match the real owner module, byte
/// for byte. This is what keeps the fixture honest: the expectation is read
/// back from `crates/eliot-app/src/front_door_cutover.rs`, never fabricated.
fn assert_canonical_route_matches_source() -> TestResult {
    let source =
        fs::read_to_string(repository_root()?.join("crates/eliot-app/src/front_door_cutover.rs"))?;
    for declaration in [
        format!(
            "pub const LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER: &str = \"{EXPECTED_CUTOVER_CODE}\";"
        ),
        format!(
            "pub const LEGACY_ENTRYPOINT_CANONICAL_ROUTE: &str = \"{EXPECTED_CANONICAL_ROUTE}\";"
        ),
    ] {
        assert!(
            source.contains(&declaration),
            "crates/eliot-app/src/front_door_cutover.rs no longer declares {declaration}"
        );
    }
    Ok(())
}

/// Asserts the full published refusal receipt for one retired entrypoint:
/// fail-closed nonzero exit, stable code, exact canonical route,
/// `completed: false`, and a detail that names both the retirement and the
/// canonical route. Returns the parsed receipt so callers can add route-specific
/// evidence.
fn assert_canonical_front_door_refusal(
    output: &std::process::Output,
    label: &str,
) -> TestResult<Value> {
    assert!(
        !output.status.success(),
        "{label} unexpectedly served instead of refusing"
    );
    let receipt: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("{label} published no refusal receipt: {error}"))?;
    assert_canonical_front_door_receipt(&receipt, label)
}

/// Asserts the parsed refusal receipt itself, so a receipt captured to a file
/// by a reaped child is checked exactly like one captured from `output()`.
fn assert_canonical_front_door_receipt(receipt: &Value, label: &str) -> TestResult<Value> {
    assert_eq!(receipt["status"], "ERROR", "{label} receipt: {receipt}");
    assert_eq!(
        receipt["code"], EXPECTED_CUTOVER_CODE,
        "{label} receipt: {receipt}"
    );
    assert_eq!(
        receipt["canonical_route"], EXPECTED_CANONICAL_ROUTE,
        "{label} receipt: {receipt}"
    );
    assert_eq!(
        receipt["completed"], false,
        "{label} must stay fail-closed: {receipt}"
    );
    let detail = receipt["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("is retired"),
        "{label} detail must record the retirement: {detail}"
    );
    assert!(
        detail.contains(EXPECTED_CANONICAL_ROUTE),
        "{label} detail must name the canonical route: {detail}"
    );
    Ok(receipt.clone())
}

// CONTRACT UPDATE (lane W4, fix/app-daemon-front-door-W4).
//
// Document: `docs/release/WINDOWS_X64_RELEASE.md`, "Claude Code front door
// (issue #1719, OSP1 step 1')" paragraph. Sentence: "plus every non-stdio
// entrypoint (`daemon run`, `service run`, `hook`, and the rest),
// unconditionally refuse with `LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER` plus the
// canonical-route receipt."
//
// What this test asserted before: that the facade and the daemon resolve ONE
// runtime across two Windows spellings of the same config path (raw and
// `canonicalize()`d), proved by one shared `runtime_id` in the publication.
// What it asserts now: the one-runtime property survives as one-ROUTE
// invariance. Both spellings of the same config path produce the identical
// canonical front-door receipt, so the retired route has exactly one outcome
// and Windows path spelling cannot fork it.
#[test]
fn facade_and_daemon_refuse_one_canonical_route_across_windows_path_spellings() -> TestResult {
    assert_canonical_route_matches_source()?;
    let runtime = OwnedRuntime::new()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    write_test_config(runtime.path(), &config_path, free_local_port()?)?;

    let canonical_config = config_path.canonicalize()?;
    assert_ne!(
        canonical_config.to_string_lossy(),
        config_path.to_string_lossy(),
        "the red test requires Windows canonicalization to add a distinct path spelling"
    );

    let raw = run_refused_daemon(runtime.path(), &config_path, "raw path spelling")?;
    let canonical = run_refused_daemon(
        runtime.path(),
        &canonical_config,
        "canonicalized path spelling",
    )?;
    assert_eq!(
        raw["canonical_route"], canonical["canonical_route"],
        "one canonical front door must serve both path spellings"
    );
    assert_eq!(raw["code"], canonical["code"]);
    assert_eq!(raw["status"], canonical["status"]);

    // Neither spelling started a runtime, so no publication or IPC
    // authentication artifact exists for this fixture root.
    assert!(
        !runtime
            .path()
            .join("runtime")
            .join("publication.json")
            .exists()
    );
    assert!(
        !runtime
            .path()
            .join("runtime")
            .join("ipc-auth.json")
            .exists()
    );
    Ok(())
}

/// Runs the retired `daemon run` arm with its receipt captured to a file and
/// waits, bounded, for the fail-closed refusal to be published. Returns the
/// parsed receipt. The child is always reaped, so a wedged fixture cannot hang
/// the suite.
///
/// This deliberately uses a bare `Child`, not [`OwnedChild`]: the retired arm
/// refuses in milliseconds and never spawns a process tree, so there is no
/// tree to guard, and `ProcessTreeGuard::attach` would race the immediate exit
/// (its `OpenProcess` can already report the exited process as not found).
fn run_refused_daemon(fixture_root: &Path, config_path: &Path, label: &str) -> TestResult<Value> {
    let runtime_dir = fixture_root.join("runtime");
    fs::create_dir_all(&runtime_dir)?;
    let receipt_path = runtime_dir.join(format!("daemon-receipt-{label}.json"));
    let stdout = fs::File::create(&receipt_path)?;
    let mut child = governor_command(fixture_root)
        .arg("--config")
        .arg(config_path)
        .args(["daemon", "run"])
        .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::null())
        .spawn()?;
    let status = wait_for_child_exit(&mut child, DAEMON_READY_TIMEOUT, label)?;
    assert!(
        !status.success(),
        "{label} unexpectedly served instead of refusing"
    );
    let receipt: Value = serde_json::from_slice(&fs::read(&receipt_path)?)?;
    assert_canonical_front_door_receipt(&receipt, label)
}

/// Bounded wait for one child to exit, killing it if it overruns the deadline.
fn wait_for_child_exit(
    child: &mut Child,
    timeout: Duration,
    label: &str,
) -> TestResult<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait();
            return Err(format!("{label} did not refuse within {}s", timeout.as_secs()).into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

// CONTRACT UPDATE (lane W4, fix/app-daemon-front-door-W4).
//
// Document: `docs/release/WINDOWS_X64_RELEASE.md`, "Claude Code front door
// (issue #1719, OSP1 step 1')" paragraph. Sentence: "plus every non-stdio
// entrypoint (`daemon run`, `service run`, `hook`, and the rest),
// unconditionally refuse with `LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER` plus the
// canonical-route receipt."
//
// What this test asserted before: a live daemon plus a deliberately corrupted
// `runtime/ipc-auth.json`, and both `daemon doctor` and the facade naming the
// exact `authentication_field_mismatch` / `pipe_name` runtime mismatch.
// What it asserts now: the discriminating property that survives retirement —
// neither surface reaches runtime authentication at all. A mismatched
// authentication artifact can no longer be read, because both arms refuse at
// the entry gate first, so the mismatch can never be the reported cause.
#[test]
fn doctor_and_facade_name_the_canonical_route_instead_of_a_runtime_mismatch() -> TestResult {
    assert_canonical_route_matches_source()?;
    let runtime = OwnedRuntime::new()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    write_test_config(runtime.path(), &config_path, free_local_port()?)?;
    let runtime_dir = runtime.path().join("runtime");
    fs::create_dir_all(&runtime_dir)?;
    // The exact corrupted artifact the retired expectation depended on: a
    // runtime authentication file whose `pipe_name` names a foreign runtime.
    fs::write(
        runtime_dir.join("ipc-auth.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "runtime_id": "multi-agent-path-identity",
            "pipe_name": r"\\.\pipe\wrong-runtime",
            "token": "test-only-token",
            "token_generation_id": "test-only-generation"
        }))?,
    )?;

    let doctor = governor_command(runtime.path())
        .arg("--config")
        .arg(&config_path)
        .args(["daemon", "doctor"])
        .output()?;
    assert_canonical_front_door_refusal(&doctor, "daemon doctor")?;

    let facade = governor_command(runtime.path())
        .arg("--config")
        .arg(&config_path)
        .args(["mcp", "stdio", "--profile", "external_auditor"])
        .stdin(Stdio::null())
        .output()?;
    assert_canonical_front_door_refusal(&facade, "mcp stdio external_auditor")?;

    for (label, output) in [("daemon doctor", &doctor), ("mcp stdio", &facade)] {
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for unreachable_diagnosis in [
            "authentication_field_mismatch",
            "runtime authentication mismatch",
            "wrong-runtime",
        ] {
            assert!(
                !combined.contains(unreachable_diagnosis),
                "{label} still reports the retired runtime diagnosis {unreachable_diagnosis}: {combined}"
            );
        }
    }
    // No daemon was started for either arm, so the fixture publishes no
    // runtime state of its own.
    assert!(!runtime_dir.join("publication.json").exists());
    Ok(())
}

// CONTRACT UPDATE (lane W4, fix/app-daemon-front-door-W4).
//
// Document: `docs/release/WINDOWS_X64_RELEASE.md`, "Claude Code front door
// (issue #1719, OSP1 step 1')" paragraph. Sentence: "plus every non-stdio
// entrypoint (`daemon run`, `service run`, `hook`, and the rest),
// unconditionally refuse with `LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER` plus the
// canonical-route receipt."
//
// Document: `crates/eliot-app/src/front_door_cutover.rs`, module contract.
// Sentence: "A delegated host at the default profile ... emits the stable code
// plus canonical-route receipt and delegates to the approved Bridge. All other
// host/profile values, including the Codex `codex_controller` profile whose
// behavior home is the `eliot-mcp` track with no current-owner Bridge contour
// (issue #18 W11), are rejected with the same stable code and receipt before
// `mcp_stdio::run`."
//
// What this test asserted before: a widening `initialize` handshake carrying
// `eliotProfile: codex_controller` over an `external_auditor` session, refused
// with JSON-RPC -32603 "cannot widen handshake profile".
// What it asserts now: the property that survives retirement — the widening
// handshake is not answered at all. There is no authenticated legacy session to
// widen, so neither the handshake nor the -32603 profile-widening refusal is
// reachable.
#[test]
fn initialize_cannot_widen_a_profile_because_no_legacy_session_is_served() -> TestResult {
    assert_canonical_route_matches_source()?;
    let runtime = OwnedRuntime::new()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    write_test_config(runtime.path(), &config_path, free_local_port()?)?;

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "Antigravity", "version": "multi-agent-test"},
            "eliotProfile": "codex_controller"
        }
    });
    let mut facade = governor_command(runtime.path())
        .arg("--config")
        .arg(&config_path)
        .args(["mcp", "stdio", "--profile", "external_auditor"])
        .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = facade.stdin.take().ok_or("facade stdin unavailable")?;
    serde_json::to_writer(&mut stdin, &request)?;
    writeln!(stdin)?;
    drop(stdin);
    let output = facade.wait_with_output()?;
    assert_canonical_front_door_refusal(&output, "widening initialize")?;

    let served = String::from_utf8_lossy(&output.stdout);
    for unreachable in [
        "\"jsonrpc\"",
        "-32603",
        "cannot widen handshake profile",
        "eliotProfile",
    ] {
        assert!(
            !served.contains(unreachable),
            "widening handshake reached the profile server ({unreachable}): {served}"
        );
    }
    Ok(())
}

// CONTRACT UPDATE (lane W4, fix/app-daemon-front-door-W4).
//
// Document: `docs/release/WINDOWS_X64_RELEASE.md`, "Claude Code front door
// (issue #1719, OSP1 step 1')" paragraph. Sentence that retires the old
// expectation: "plus every non-stdio entrypoint (`daemon run`, `service run`,
// `hook`, and the rest), unconditionally refuse with
// `LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER` plus the canonical-route receipt."
//
// Document: `crates/eliot-app/src/front_door_cutover.rs`, module contract.
// Sentence: "Every one of the 57 top-level `Command` arms - including `writer
// smoke`/`drain`, `maintenance run`, `import` execute, `daemon`/`service`
// status and control arms, `hook` arms, and read-only surfaces such as `mcp
// catalog` - is refused unconditionally at the `dispatch_command` entry gate."
//
// What this test asserted before: one live daemon plus one facade per canonical
// access profile, publishing a bounded tool set per profile.
// What it asserts now: the causal property that survives retirement — no
// canonical profile can publish any tool set at all, because every profile is
// refused at the entry gate before a daemon, store, ControlWal or writer is
// constructed.
#[test]
fn canonical_profiles_are_refused_and_publish_no_tool_sets() -> TestResult {
    assert_canonical_route_matches_source()?;
    let runtime = OwnedRuntime::new()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    write_test_config(runtime.path(), &config_path, free_local_port()?)?;

    for profile in [
        "codex_controller",
        "codex_worker",
        "claude_governed",
        "dynamic_agent",
        "external_auditor",
        "verifier",
        "human_readonly",
    ] {
        let mut facade = governor_command(runtime.path())
            .arg("--config")
            .arg(&config_path)
            .args(["mcp", "stdio", "--profile", profile])
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = facade.stdin.take().ok_or("facade stdin unavailable")?;
        serde_json::to_writer(&mut stdin, &initialize_request(1, profile))?;
        writeln!(stdin)?;
        drop(stdin);
        let output = facade.wait_with_output()?;
        assert_canonical_front_door_refusal(&output, profile)?;
        // No MCP session exists, so no profile publishes a tool set and no
        // access profile is ever reported back to a caller.
        let served = String::from_utf8_lossy(&output.stdout);
        for forbidden in ["\"jsonrpc\"", "\"tools\"", "access_profile", "serverInfo"] {
            assert!(
                !served.contains(forbidden),
                "{profile} served MCP content ({forbidden}): {served}"
            );
        }
    }

    // A refused profile never reaches a runtime: no publication and no IPC
    // authentication artifact may exist for this fixture root.
    assert!(
        !runtime
            .path()
            .join("runtime")
            .join("publication.json")
            .exists()
    );
    assert!(
        !runtime
            .path()
            .join("runtime")
            .join("ipc-auth.json")
            .exists()
    );

    // Document: `docs/release/WINDOWS_X64_RELEASE.md`, same paragraph. Sentence:
    // "`ELIOT_CLAUDE_FRONT_DOOR` survives only as refusal evidence and never
    // gates behavior." Setting the operator flag must therefore still refuse.
    let flagged = governor_command(runtime.path())
        .arg("--config")
        .arg(&config_path)
        .args(["mcp", "stdio", "--profile", "external_auditor"])
        .env("ELIOT_CLAUDE_FRONT_DOOR", "agent-bridge")
        .stdin(Stdio::null())
        .output()?;
    assert_canonical_front_door_refusal(&flagged, "agent-bridge flagged facade")?;
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn default_instance_bootstrap_is_stable_and_outside_the_repository() -> TestResult {
    let runtime = OwnedRuntime::new()?;
    let local_app_data = runtime.path().join("local-app-data");
    let source_config = repository_root()?
        .join(".eliot-governor")
        .join("config")
        .join("governor.toml");
    let output = governor_command(runtime.path())
        .args(["daemon", "init-default", "--source-config"])
        .arg(&source_config)
        .env("LOCALAPPDATA", &local_app_data)
        .output()?;
    assert!(
        output.status.success(),
        "default init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config_path = local_app_data
        .join("Eliot")
        .join("config")
        .join("governor.toml");
    let config = fs::read_to_string(&config_path)?;
    assert!(!config.to_ascii_lowercase().contains("onedrive"));
    assert!(local_app_data.join("Eliot/resources/surql").is_dir());
    assert!(local_app_data.join("Eliot/resources/migrations").is_dir());
    assert!(config.contains("instance_id = \"default\""));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned SurrealDB executable"]
fn standalone_startup_failure_stops_its_owned_database_and_publishes_failed() -> TestResult {
    let _runtime_lease = daemon_runtime_lease();
    let runtime = OwnedRuntime::new()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    let port = free_local_port()?;
    write_test_config(runtime.path(), &config_path, port)?;
    let invalid_wal_path = runtime.path().join("control").join("control.redb");
    fs::create_dir_all(&invalid_wal_path)?;
    let local_app_data = runtime.path().join("local-app-data");

    let output = governor_command(runtime.path())
        .arg("--config")
        .arg(&config_path)
        .args(["daemon", "run", "--instance", "default"])
        .env("LOCALAPPDATA", &local_app_data)
        .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
        .output()?;
    assert!(!output.status.success());

    let publication_path = local_app_data
        .join("Eliot")
        .join("instances")
        .join("default")
        .join("runtime")
        .join("publication.json");
    let publication: Value = serde_json::from_slice(&fs::read(publication_path)?)?;
    assert_eq!(publication["state"], "failed");
    wait_for_tcp_closed(port, Duration::from_secs(10))?;
    assert!(
        local_app_data
            .join("Eliot/instances/default/reports/startup/latest.json")
            .is_file()
    );
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn external_candidate_is_shared_without_authority_widening() -> TestResult {
    let _runtime_lease = daemon_runtime_lease();
    let runtime = OwnedRuntime::new()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    let port = free_local_port()?;
    write_test_config(runtime.path(), &config_path, port)?;
    let mut database = start_surreal(runtime.path(), port)?;
    wait_for_tcp(port, Duration::from_secs(15))?;
    let mut daemon = start_daemon(&config_path)?;
    wait_for_changed_json(
        &mut daemon,
        &runtime.path().join("runtime").join("publication.json"),
        "auth_generation",
        "",
        DAEMON_READY_TIMEOUT,
    )?;

    let project_id = "eliot-governor";
    let task_id = TaskId::new_v7().to_string();
    let task = run_facade_requests(
        &config_path,
        "codex_controller",
        &[
            initialize_request(90, "Codex"),
            serde_json::json!({
                "jsonrpc":"2.0","id":91,"method":"tools/call",
                "params":{"name":"eliot_task_contract_create","arguments":{
                    "project_id": project_id,
                    "task_id": task_id,
                    "write_id": WriteId::new_v7().to_string(),
                    "title": "task-bound external candidate sharing",
                    "acceptance_items": [
                        {"item_id":"candidate","description":"candidate is task scoped","required_evidence":"observation"},
                        {"item_id":"authority","description":"candidate has no completion authority","required_evidence":"verification"}
                    ]
                }}
            }),
        ],
    )?;
    assert!(
        task[1]
            .pointer("/result/structuredContent/task_contract")
            .is_some(),
        "task creation response: {}",
        task[1]
    );
    let phrase = format!("orchid-runtime-{}", WriteId::new_v7());
    let external = run_facade_requests(
        &config_path,
        "external_auditor",
        &[
            initialize_request(1, "Antigravity"),
            serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            serde_json::json!({
                "jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":"eliot_project_identity","arguments":{
                    "project_key": project_id
                }}
            }),
            serde_json::json!({
                "jsonrpc":"2.0","id":4,"method":"tools/call",
                "params":{"name":"eliot_agent_candidate_submit","arguments":{
                    "project_id": project_id,
                    "task_id": task_id,
                    "write_id": WriteId::new_v7().to_string(),
                    "topic": "standalone multi-agent runtime",
                    "statement": format!("{phrase} uses one Governor writer and one canonical store"),
                    "where_applicable": ["standalone default instance"],
                    "where_not_applicable": ["isolated disposable test instances"],
                    "negative_constraints": ["never treat candidate memory as completion authority"],
                    "provenance_refs": ["multi-agent-process-test"],
                    "freshness_rule": "revalidate after runtime generation or repository truth changes"
                }}
            }),
            serde_json::json!({
                "jsonrpc":"2.0","id":5,"method":"tools/call",
                "params":{"name":"eliot_submit_completion_proof","arguments":{}}
            }),
        ],
    )?;
    assert_eq!(
        external[0]
            .pointer("/result/experimental/eliotAgentSession/access_profile")
            .and_then(Value::as_str),
        Some("external_auditor")
    );
    let listed = external[1]
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .ok_or("tools missing")?;
    assert!(
        listed
            .iter()
            .any(|tool| tool["name"] == "eliot_agent_candidate_submit")
    );
    assert!(
        !listed
            .iter()
            .any(|tool| tool["name"] == "eliot_submit_completion_proof")
    );
    let read_tool = listed
        .iter()
        .find(|tool| tool["name"] == "eliot_runtime_status")
        .ok_or("read tool missing")?;
    assert_eq!(
        read_tool.pointer("/annotations/readOnlyHint"),
        Some(&Value::Bool(true))
    );
    let candidate_tool = listed
        .iter()
        .find(|tool| tool["name"] == "eliot_agent_candidate_submit")
        .ok_or("candidate tool missing")?;
    assert_eq!(
        candidate_tool.pointer("/annotations/destructiveHint"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        candidate_tool.pointer("/annotations/idempotentHint"),
        Some(&Value::Bool(true))
    );
    assert!(
        candidate_tool
            .pointer("/inputSchema/required")
            .and_then(Value::as_array)
            .is_some_and(|required| required.iter().any(|field| field == "task_id"))
    );
    assert_eq!(
        external[2]
            .pointer("/result/structuredContent/canonical_project_key")
            .and_then(Value::as_str),
        Some(project_id)
    );
    assert_eq!(
        external[3]
            .pointer("/result/structuredContent/status")
            .and_then(Value::as_str),
        Some("candidate_committed")
    );
    assert_eq!(
        external[4]
            .pointer("/result/isError")
            .and_then(Value::as_bool),
        Some(true)
    );

    let codex = run_facade_requests(
        &config_path,
        "codex_controller",
        &[
            initialize_request(10, "Codex"),
            serde_json::json!({
                "jsonrpc":"2.0","id":12,"method":"tools/call",
                "params":{"name":"eliot_project_identity","arguments":{
                    "project_key": project_id
                }}
            }),
            serde_json::json!({
                "jsonrpc":"2.0","id":11,"method":"tools/call",
                "params":{"name":"eliot_recall_l0","arguments":{
                    "project_id": project_id,
                    "query": phrase,
                    "limit": 10
                }}
            }),
        ],
    )?;
    assert_eq!(
        codex[1]
            .pointer("/result/structuredContent/canonical_project_key")
            .and_then(Value::as_str),
        Some(project_id)
    );
    let recalled = serde_json::to_string(&codex[2])?;
    assert!(
        recalled.contains(&phrase),
        "candidate was not recalled across clients: {recalled}"
    );

    fs::write(
        runtime.path().join("runtime").join("stop.requested"),
        "test\n",
    )?;
    daemon.wait_for_exit(Duration::from_secs(15))?;
    database.stop()?;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn facade_reconnects_after_rotation_and_replay_does_not_duplicate_memory() -> TestResult {
    let _runtime_lease = daemon_runtime_lease();
    let runtime = OwnedRuntime::new()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    let port = free_local_port()?;
    write_test_config(runtime.path(), &config_path, port)?;
    let mut database = start_surreal(runtime.path(), port)?;
    wait_for_tcp(port, Duration::from_secs(15))?;

    let mut first_daemon = start_daemon(&config_path)?;
    let publication_path = runtime.path().join("runtime").join("publication.json");
    let first_publication = wait_for_changed_json(
        &mut first_daemon,
        &publication_path,
        "auth_generation",
        "",
        DAEMON_READY_TIMEOUT,
    )?;
    let first_generation = first_publication["auth_generation"]
        .as_str()
        .ok_or("first auth generation missing")?
        .to_owned();
    let mut facade = LiveFacade::start(&config_path, "external_auditor")?;
    let initialized = facade.request(
        &initialize_request(20, "Antigravity"),
        Duration::from_secs(10),
    )?;
    assert_eq!(
        initialized
            .pointer("/result/experimental/eliotAgentSession/auth_generation")
            .and_then(Value::as_str),
        Some(first_generation.as_str())
    );

    let project_id = ProjectId::new_v7().to_string();
    let task_id = TaskId::new_v7().to_string();
    let task = run_facade_requests(
        &config_path,
        "codex_controller",
        &[
            initialize_request(190, "Codex"),
            serde_json::json!({
                "jsonrpc":"2.0","id":191,"method":"tools/call",
                "params":{"name":"eliot_task_contract_create","arguments":{
                    "project_id": project_id,
                    "task_id": task_id,
                    "write_id": WriteId::new_v7().to_string(),
                    "title": "task-bound candidate survives daemon rotation",
                    "acceptance_items": [
                        {"item_id":"restart","description":"candidate replay survives restart","required_evidence":"observation"},
                        {"item_id":"dedupe","description":"replay remains singular","required_evidence":"verification"}
                    ]
                }}
            }),
        ],
    )?;
    assert!(
        task[1]
            .pointer("/result/structuredContent/task_contract")
            .is_some(),
        "rotation task creation response: {}",
        task[1]
    );
    let phrase = format!("rotation-idempotency-{}", WriteId::new_v7());
    let candidate = serde_json::json!({
        "jsonrpc":"2.0","id":21,"method":"tools/call",
        "params":{"name":"eliot_agent_candidate_submit","arguments":{
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7().to_string(),
            "topic": "rotation replay",
            "statement": phrase,
            "where_applicable": ["same canonical store after daemon restart"],
            "where_not_applicable": ["different instance selector"],
            "negative_constraints": ["replay must not create a second claim"],
            "provenance_refs": ["multi-agent-rotation-test"],
            "freshness_rule": "valid only while project and instance identity remain the same"
        }}
    });
    let first_write = facade.request(&candidate, Duration::from_secs(30))?;
    let first_receipt = first_write
        .pointer("/result/structuredContent/write_receipt/receipt_id")
        .and_then(Value::as_str)
        .ok_or("first write receipt missing")?
        .to_owned();

    fs::write(
        runtime.path().join("runtime").join("stop.requested"),
        "rotate\n",
    )?;
    first_daemon.wait_for_exit(Duration::from_secs(15))?;
    let mut second_daemon = start_daemon(&config_path)?;
    let second_publication = wait_for_changed_json(
        &mut second_daemon,
        &publication_path,
        "auth_generation",
        &first_generation,
        DAEMON_READY_TIMEOUT,
    )?;
    assert_ne!(
        second_publication["runtime_id"],
        first_publication["runtime_id"]
    );

    let replayed = facade.request(&candidate, Duration::from_secs(30))?;
    assert_eq!(
        replayed
            .pointer("/result/structuredContent/write_receipt/receipt_id")
            .and_then(Value::as_str),
        Some(first_receipt.as_str()),
        "replayed response: {replayed}"
    );
    let recalled = facade.request(
        &serde_json::json!({
            "jsonrpc":"2.0","id":22,"method":"tools/call",
            "params":{"name":"eliot_recall_l0","arguments":{
                "project_id": project_id,
                "query": phrase,
                "limit": 10
            }}
        }),
        Duration::from_secs(30),
    )?;
    assert_eq!(
        recalled
            .pointer("/result/structuredContent/handles")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1),
        "idempotent replay must leave exactly one candidate claim"
    );

    facade.stop()?;
    fs::write(
        runtime.path().join("runtime").join("stop.requested"),
        "test\n",
    )?;
    second_daemon.wait_for_exit(Duration::from_secs(15))?;
    database.stop()?;
    Ok(())
}

fn initialize_request(id: u64, client_name: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": client_name, "version": "multi-agent-test"}
        }
    })
}

fn run_facade_requests(
    config_path: &Path,
    profile: &str,
    requests: &[Value],
) -> TestResult<Vec<Value>> {
    let mut child = governor_command(
        config_path
            .parent()
            .and_then(Path::parent)
            .unwrap_or(config_path),
    )
    .arg("--config")
    .arg(config_path)
    .args(["mcp", "stdio", "--profile", profile])
    .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()?;
    let mut stdin = child.stdin.take().ok_or("facade stdin unavailable")?;
    for request in requests {
        serde_json::to_writer(&mut stdin, request)?;
        writeln!(stdin)?;
    }
    drop(stdin);
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "facade {profile} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    String::from_utf8(output.stdout)?
        .lines()
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

fn daemon_runtime_lease() -> MutexGuard<'static, ()> {
    DAEMON_RUNTIME_LEASE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn start_daemon(config_path: &Path) -> TestResult<OwnedChild> {
    let fixture_root = config_path
        .parent()
        .and_then(Path::parent)
        .unwrap_or(config_path);
    let runtime_dir = fixture_root.join("runtime");
    fs::create_dir_all(&runtime_dir)?;
    let stderr = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(runtime_dir.join("daemon.stderr.log"))?;
    OwnedChild::spawn(
        governor_command(fixture_root)
            .arg("--config")
            .arg(config_path)
            .args(["daemon", "run"])
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr)),
    )
}

struct LiveFacade {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    responses: Receiver<TestResult<String>>,
    reader: Option<JoinHandle<()>>,
}

impl LiveFacade {
    fn start(config_path: &Path, profile: &str) -> TestResult<Self> {
        let mut child = governor_command(
            config_path
                .parent()
                .and_then(Path::parent)
                .unwrap_or(config_path),
        )
        .arg("--config")
        .arg(config_path)
        .args(["mcp", "stdio", "--profile", profile])
        .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
        let stdin = child.stdin.take().ok_or("facade stdin unavailable")?;
        let stdout = child.stdout.take().ok_or("facade stdout unavailable")?;
        let (sender, responses) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut lines = std::io::BufReader::new(stdout).lines();
            loop {
                let message = match lines.next() {
                    Some(Ok(line)) => Ok(line),
                    Some(Err(error)) => Err(error.into()),
                    None => Err("facade stdout closed".into()),
                };
                let stop = message.is_err();
                if sender.send(message).is_err() || stop {
                    break;
                }
            }
        });
        Ok(Self {
            child: Some(child),
            stdin: Some(stdin),
            responses,
            reader: Some(reader),
        })
    }

    fn request(&mut self, request: &Value, timeout: Duration) -> TestResult<Value> {
        let stdin = self.stdin.as_mut().ok_or("facade stdin closed")?;
        serde_json::to_writer(&mut *stdin, request)?;
        writeln!(stdin)?;
        stdin.flush()?;
        let line = self
            .responses
            .recv_timeout(timeout)
            .map_err(|error| format!("timed out waiting for facade response: {error}"))??;
        Ok(serde_json::from_str(&line)?)
    }

    fn stop(&mut self) -> TestResult {
        self.stdin.take();
        if let Some(mut child) = self.child.take() {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            let _ = child.wait()?;
        }
        if let Some(reader) = self.reader.take() {
            reader.join().map_err(|_| "facade reader panicked")?;
        }
        Ok(())
    }
}

impl Drop for LiveFacade {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct OwnedRuntime(PathBuf);

impl OwnedRuntime {
    fn new() -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sequence = RUNTIME_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "eliot-multi-agent-path-identity-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for OwnedRuntime {
    fn drop(&mut self) {
        if self.0.starts_with(std::env::temp_dir()) {
            let _ = fs::remove_dir_all(&self.0);
        }
        if let Ok(secret_root) = test_secret_root(&self.0) {
            let _ = fs::remove_dir_all(secret_root);
        }
    }
}

struct OwnedChild {
    child: Option<Child>,
    process_tree: Option<ProcessTreeGuard>,
}

impl OwnedChild {
    fn spawn(command: &mut Command) -> TestResult<Self> {
        let mut child = command.spawn()?;
        let process_tree = match ProcessTreeGuard::attach(child.id()) {
            Ok(process_tree) => process_tree,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        };
        Ok(Self {
            child: Some(child),
            process_tree: Some(process_tree),
        })
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> TestResult {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self
                .child
                .as_mut()
                .ok_or("owned child already consumed")?
                .try_wait()?
                .is_some()
            {
                self.child.take();
                self.process_tree.take();
                return Ok(());
            }
            thread::sleep(Duration::from_millis(25));
        }
        Err("owned child did not stop before deadline".into())
    }

    fn try_wait(&mut self) -> TestResult<Option<ExitStatus>> {
        self.child
            .as_mut()
            .ok_or_else(|| "owned child already consumed".into())
            .and_then(|child| child.try_wait().map_err(Into::into))
    }

    fn stop(&mut self) -> TestResult {
        if let Some(process_tree) = self.process_tree.take() {
            let _ = process_tree.terminate(1);
        }
        if let Some(mut child) = self.child.take() {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            let _ = child.wait()?;
        }
        Ok(())
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(process_tree) = self.process_tree.take() {
            let _ = process_tree.terminate(1);
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[allow(
    clippy::print_stderr,
    reason = "the integration harness emits measured READY latency under --nocapture"
)]
fn wait_for_changed_json(
    daemon: &mut OwnedChild,
    path: &Path,
    field: &str,
    previous: &str,
    timeout: Duration,
) -> TestResult<Value> {
    let started = Instant::now();
    let deadline = started + timeout;
    while Instant::now() < deadline {
        let publication = fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
        if let Some(value) = publication.as_ref()
            && value["state"] == "failed"
        {
            let status = daemon
                .try_wait()?
                .map_or_else(|| "running".to_owned(), |status| status.to_string());
            return Err(daemon_startup_error(
                path,
                &format!("daemon published FAILED (child status: {status}): {value}"),
            )
            .into());
        }
        if let Some(status) = daemon.try_wait()? {
            return Err(daemon_startup_error(
                path,
                &format!("daemon exited before READY with status {status}"),
            )
            .into());
        }
        if let Some(value) = publication
            && value.get(field).and_then(Value::as_str) != Some(previous)
            && value["state"] == "ready"
        {
            eprintln!(
                "daemon READY after {:.3}s ({})",
                started.elapsed().as_secs_f64(),
                path.display()
            );
            return Ok(value);
        }
        thread::sleep(Duration::from_millis(25));
    }
    let status = daemon
        .try_wait()?
        .map_or_else(|| "running".to_owned(), |status| status.to_string());
    Err(daemon_startup_error(
        path,
        &format!(
            "timed out after {:.3}s waiting for changed {field} in {} (child status: {status})",
            started.elapsed().as_secs_f64(),
            path.display()
        ),
    )
    .into())
}

fn daemon_startup_error(publication_path: &Path, reason: &str) -> String {
    let runtime_dir = publication_path.parent().unwrap_or(publication_path);
    let fixture_root = runtime_dir.parent().unwrap_or(runtime_dir);
    let stderr_path = runtime_dir.join("daemon.stderr.log");
    let startup_diagnostic_path = fixture_root
        .join("reports")
        .join("startup")
        .join("latest.json");
    format!(
        "{reason}\ndaemon stderr tail ({}):\n{}\nstartup diagnostic tail ({}):\n{}",
        stderr_path.display(),
        bounded_file_tail(&stderr_path),
        startup_diagnostic_path.display(),
        bounded_file_tail(&startup_diagnostic_path)
    )
}

fn bounded_file_tail(path: &Path) -> String {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) => return format!("<unavailable: {error}>"),
    };
    let len = match file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(error) => return format!("<metadata unavailable: {error}>"),
    };
    if let Err(error) = file.seek(SeekFrom::Start(len.saturating_sub(DIAGNOSTIC_TAIL_BYTES))) {
        return format!("<seek failed: {error}>");
    }
    let mut bytes = Vec::new();
    if let Err(error) = file.take(DIAGNOSTIC_TAIL_BYTES).read_to_end(&mut bytes) {
        return format!("<read failed: {error}>");
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn write_test_config(runtime: &Path, config_path: &Path, port: u16) -> TestResult {
    fs::create_dir_all(config_path.parent().ok_or("config parent missing")?)?;
    fs::create_dir_all(runtime.join("cognitive-field"))?;
    let secret_root = test_secret_root(runtime)?;
    let password_file = secret_root
        .join("secrets")
        .join("surreal_root_password.txt");
    fs::create_dir_all(password_file.parent().ok_or("password parent missing")?)?;
    fs::write(&password_file, "multi-agent-test-secret")?;
    let storage = slash(&runtime.join("surrealdb-rocks"));
    let run_id = runtime
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("test runtime name missing")?;
    let password_file =
        format!("%LOCALAPPDATA%/Eliot/tests/{run_id}/secrets/surreal_root_password.txt");
    let wal = slash(&runtime.join("control").join("control.redb"));
    let blobs = slash(&runtime.join("blobs"));
    let repo = repository_root()?;
    let surql = slash(&repo.join("crates/eliot-store/src/surql"));
    let config = format!(
        r#"schema_version = "1"

[service]
service_name = "EliotGovernorMultiAgent"
instance_id = "multi-agent-path-identity"

[db]
mode = "surreal_rpc_server"

[db.surreal]
exe = "surreal"
bind = "127.0.0.1:{port}"
endpoint = "ws://127.0.0.1:{port}/rpc"
storage = "rocksdb:{storage}"
ns = "eliot_phase_l5"
db = "memory_os_multi_agent_access"
user = "root"
credential_provider = "legacy_password_file"
credential_id = "test-only/multi-agent-path-identity"
password_file = "{password_file}"
log_level = "warn"
query_timeout_ms = 15000
transaction_timeout_ms = 15000
startup_timeout_ms = 20000
restart_backoff_ms = 200
max_restart_backoff_ms = 2000

[db.surreal.capabilities]
deny_all = true
allow_funcs = ["array", "string", "time", "type", "math", "vector", "search"]
allow_net = []
allow_scripting = false
allow_guests = false

[control_wal]
path = "{wal}"

[blob_store]
root = "{blobs}"

[store]
surql_dir = "{surql}"
"#
    );
    fs::write(config_path, config)?;
    Ok(())
}

fn repository_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("repository root missing")?
        .to_path_buf())
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn free_local_port() -> TestResult<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn start_surreal(runtime: &Path, port: u16) -> TestResult<OwnedChild> {
    let storage = format!("rocksdb:{}", slash(&runtime.join("surrealdb-rocks")));
    OwnedChild::spawn(
        Command::new("surreal")
            .env("SURREAL_USER", "root")
            .env("SURREAL_PASS", "multi-agent-test-secret")
            .arg("start")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--log")
            .arg("warn")
            .arg("--deny-all")
            .arg("--allow-funcs")
            .arg("array,string,time,type,math,vector,search")
            .arg("--deny-net")
            .arg("--")
            .arg(storage)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
}

fn wait_for_tcp(port: u16, timeout: Duration) -> TestResult {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(format!("SurrealDB did not listen on port {port}").into())
}

fn wait_for_tcp_closed(port: u16, timeout: Duration) -> TestResult {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(format!("SurrealDB still listens on port {port}").into())
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_eliot-governor"))
}

fn governor_command(fixture_root: &Path) -> Command {
    let mut command = Command::new(binary());
    for variable in [
        "ELIOT_GOVERNOR_CONFIG",
        "ELIOT_TEST_SURREAL_BIND",
        "ELIOT_TEST_SURREAL_ENDPOINT",
        "ELIOT_TEST_SURREAL_PASSWORD_FILE",
        "ELIOT_TEST_SURREAL_STORAGE",
        "ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION",
        "SURREAL_USER",
        "SURREAL_PASS",
    ] {
        command.env_remove(variable);
    }
    command.env("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION", "1");
    eliot_windows_ipc::test_support::IsolatedTestCredentialBackend::EphemeralFile {
        root: fixture_root.join("operator-cursor-credentials"),
    }
    .configure_command(&mut command);
    command
}

fn test_secret_root(runtime: &Path) -> TestResult<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA missing")?;
    let run_id = runtime
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| name.starts_with("eliot-multi-agent-path-identity-"))
        .ok_or("unsafe multi-agent test runtime name")?;
    Ok(PathBuf::from(local_app_data)
        .join("Eliot")
        .join("tests")
        .join(run_id))
}
