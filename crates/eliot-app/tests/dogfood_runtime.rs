use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
static COMMAND_SEQUENCE: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Canonical front-door refusal contract (retirement of the legacy route)
// ---------------------------------------------------------------------------
//
// Every non-ignored test in this file used to drive a live legacy `dogfood`
// runtime (its own SurrealDB, its own `governor.toml`, its own
// `eliot-governor daemon run`) and assert real Codex launch/worktree behavior.
// That route no longer exists. Each test now asserts the contract the product
// actually publishes: the retired `dogfood` group refuses fail-closed with a
// stable machine-readable code plus the canonical Kernel-governed route, and
// provisions nothing.
//
// Owner of the refusal: `crates/eliot-app/src/front_door_cutover.rs`
// (`LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER`, `LEGACY_ENTRYPOINT_CANONICAL_ROUTE`).
// `assert_canonical_route_matches_source` re-reads that module so the two
// literals below are proven against the real owner instead of assumed.

/// Exact `code` field of every retired-entrypoint refusal receipt.
const EXPECTED_CUTOVER_CODE: &str = "LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER";

/// Exact `canonical_route` field of every retired-entrypoint refusal receipt,
/// copied verbatim from `LEGACY_ENTRYPOINT_CANONICAL_ROUTE`.
const EXPECTED_CANONICAL_ROUTE: &str = "eliot setup through the Kernel canonical configuration surface (Host-managed StoreLaunchConfig bound to the installation manifest; Governor operates only as outbound-only eliotd polling Kernel; typed policy resolves only through eliotd::canonical_config_precedence)";

/// Fails unless the two literals above still match the real owner module, byte
/// for byte, so the fixture can never be a fabricated pass.
fn assert_canonical_route_matches_source() -> TestResult {
    let source = fs::read_to_string(
        repo_root()
            .join("crates")
            .join("eliot-app")
            .join("src")
            .join("front_door_cutover.rs"),
    )?;
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

/// Asserts the full published refusal receipt for one retired `dogfood` arm:
/// fail-closed nonzero exit, stable code, exact canonical route,
/// `completed: false`, and a detail that names the retirement and the canonical
/// route.
fn assert_canonical_front_door_refusal(output: &std::process::Output, label: &str) -> TestResult {
    assert!(
        !output.status.success(),
        "{label} unexpectedly served instead of refusing"
    );
    let receipt: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("{label} published no refusal receipt: {error}"))?;
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
        detail.contains("legacy eliot-governor dogfood is retired"),
        "{label} detail must record the retirement: {detail}"
    );
    assert!(
        detail.contains(EXPECTED_CANONICAL_ROUTE),
        "{label} detail must name the canonical route: {detail}"
    );
    Ok(())
}

/// Runs one `dogfood` subcommand and asserts the canonical front-door refusal.
fn assert_dogfood_arm_refuses(args: &[&str], label: &str) -> TestResult {
    let output = Command::new(binary()).args(args).output()?;
    assert_canonical_front_door_refusal(&output, label)
}

struct OwnedRoot(PathBuf);

impl Drop for OwnedRoot {
    fn drop(&mut self) {
        if self.0.is_dir() {
            let _ = Command::new(binary())
                .args(["dogfood", "stop", "--root"])
                .arg(&self.0)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if self.0.starts_with(std::env::temp_dir()) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }
}

#[test]
#[ignore = "requires a provisioned SurrealDB executable"]
fn dogfood_runtime_starts_doctors_stops_and_restarts_persistent_state() -> TestResult {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let owned = OwnedRoot(std::env::temp_dir().join(format!(
        "eliot-dogfood-l3-test-{}-{nonce}",
        std::process::id()
    )));
    let root_arg = owned.0.to_string_lossy().into_owned();
    let project = repo_root();
    let project_arg = project.to_string_lossy().into_owned();
    let surreal_exe_arg = surreal_exe_arg()?;

    let initialized = run(&[
        "dogfood",
        "init",
        "--root",
        &root_arg,
        "--project",
        &project_arg,
        "--surreal-exe",
        &surreal_exe_arg,
    ])?;
    assert_eq!(initialized["status"], "initialized");
    assert_eq!(initialized["runtime_root_safe"], true);
    assert!(
        !fs::read_to_string(owned.0.join("codex").join("config.toml"))?.contains("SURREAL_PASS")
    );

    for cycle in 0..2 {
        let started = run(&["dogfood", "start", "--root", &root_arg])?;
        assert_eq!(started["status"], "running", "cycle {cycle}");
        assert_eq!(started["owned_children"].as_array().map(Vec::len), Some(2));

        let doctor = run(&["dogfood", "doctor", "--root", &root_arg])?;
        assert_eq!(doctor["daemon_health"], "ready", "cycle {cycle}");
        assert_eq!(doctor["db_health"], "ready", "cycle {cycle}");
        assert_eq!(
            doctor["codex_integration_model"],
            "project_mcp_with_native_plugin_available"
        );
        assert!(doctor.get("plugin_bundle_status").is_none());
        assert_eq!(
            doctor["project_codex_config_status"],
            "valid_disposable_config"
        );
        assert_eq!(doctor["provider_kill_switch"], true);
        assert!(
            doctor["antigravity_ledger_count"].is_null(),
            "a detached clean worktree has no controller-local historical provider report"
        );
        assert!(doctor["codex_cli_version"].as_str().is_some());
        assert!(doctor["surrealdb_identity"]["path"].as_str().is_some());
        assert!(doctor["surrealdb_identity"]["version"].as_str().is_some());
        assert!(doctor["surrealdb_identity"]["sha256"].as_str().is_some());
        assert!(
            doctor["surrealdb_identity"]["pe_machine"]
                .as_str()
                .is_some()
        );
        assert_eq!(doctor["blockers"].as_array().map(Vec::len), Some(0));

        let status = run(&["dogfood", "status", "--root", &root_arg])?;
        assert_eq!(status["daemon_health"], "ready");
        assert!(status["children"].as_array().is_some_and(|items| {
            items.len() == 2 && items.iter().all(|item| item["identity_matches"] == true)
        }));

        if cycle == 0 {
            let daemon_pid_path = owned.0.join("runtime").join("daemon.pid");
            let daemon_pid = fs::read_to_string(&daemon_pid_path)?;
            fs::write(&daemon_pid_path, "4294967295\n")?;
            let denial = run_failure(&["dogfood", "stop", "--root", &root_arg])?;
            assert!(denial.contains("daemon PID file does not match"));
            fs::write(&daemon_pid_path, daemon_pid)?;
            let still_running = run(&["dogfood", "status", "--root", &root_arg])?;
            assert_eq!(still_running["daemon_health"], "ready");
        }

        let stopped = run(&["dogfood", "stop", "--root", &root_arg])?;
        assert_eq!(stopped["status"], "stopped");
        assert!(!owned.0.join("runtime").join("daemon.pid").exists());
        assert!(!owned.0.join("runtime").join("ipc-auth.json").exists());
        assert!(owned.0.join("surrealdb-rocks").is_dir());
        let doctor_after_stop = run_failure(&["dogfood", "doctor", "--root", &root_arg])?;
        assert!(doctor_after_stop.contains("\"status\": \"BLOCKED\""));
        assert!(doctor_after_stop.contains("db_not_ready"));
        assert!(doctor_after_stop.contains("daemon_not_ready"));
    }

    let manifest_path = owned.0.join("dogfood-manifest.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let governor_binary = manifest["governor_binary"].clone();
    manifest["governor_binary"] = Value::String(
        owned
            .0
            .join("missing-governor.exe")
            .to_string_lossy()
            .into_owned(),
    );
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    let failure = run_failure(&["dogfood", "start", "--root", &root_arg])?;
    assert!(failure.contains("start owned dogfood governor daemon"));
    let mut failed_manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    assert_eq!(failed_manifest["state"], "start_failed");
    assert_eq!(
        failed_manifest["children"].as_array().map(Vec::len),
        Some(0)
    );
    assert!(!owned.0.join("tmp").join("surreal.pid").exists());
    failed_manifest["governor_binary"] = governor_binary;
    fs::write(&manifest_path, serde_json::to_vec_pretty(&failed_manifest)?)?;
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
// Sentence: "Every one of the 57 top-level `Command` arms ... is refused
// unconditionally at the `dispatch_command` entry gate, with
// [`LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER`] plus the canonical-route receipt. The
// arm label is preserved as identity/route evidence in the detail."
//
// What this test asserted before: `dogfood --help` exposes `run-codex`, then a
// fully provisioned runtime still refuses `run-codex` at preflight with
// "requires a running owned runtime" and writes no live-codex report.
// What it asserts now: the property that survives retirement — the arm is still
// exposed (so the refusal is reachable and observable) and it refuses at the
// entry gate before any preflight, spawn or report path can run.
#[test]
fn dogfood_run_codex_is_exposed_and_the_retired_arm_refuses_before_spawn() -> TestResult {
    assert_canonical_route_matches_source()?;
    let help = Command::new(binary())
        .args(["dogfood", "--help"])
        .output()?;
    assert!(help.status.success());
    assert!(String::from_utf8(help.stdout)?.contains("run-codex"));

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "eliot-dogfood-run-codex-frontdoor-test-{}-{nonce}",
        std::process::id()
    ));
    let root_arg = root.to_string_lossy().into_owned();
    assert_dogfood_arm_refuses(
        &[
            "dogfood",
            "run-codex",
            "--root",
            &root_arg,
            "--project",
            "00000000-0000-0000-0000-000000000001",
            "--task",
            "00000000-0000-0000-0000-000000000002",
            "--agent-session",
            "00000000-0000-0000-0000-000000000003",
            "--role-lease",
            "dogfood-test-role-lease",
            "--work-item",
            "00000000-0000-0000-0000-000000000004",
            "--work-lease",
            "00000000-0000-0000-0000-000000000005",
            "--worktree-lease",
            "00000000-0000-0000-0000-000000000006",
        ],
        "dogfood run-codex",
    )?;

    // The refusal happens before any provisioning, so no runtime root and no
    // live-codex report exists.
    assert!(
        !root.exists(),
        "refused run-codex provisioned {}",
        root.display()
    );
    assert!(!root.join("reports/live-codex/events.jsonl").exists());
    assert!(!root.join("reports/live-codex/latest.json").exists());
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
// Document: `docs/release/WINDOWS_X64_RELEASE.md`, same paragraph, retention
// disposition. Sentence: "the retained Governor binary remains only as an
// unconditional Bridge redirect/refusal shim for installed entrypoints, and
// every other entrypoint refuses without serving."
//
// What this test asserted before: a real independent Codex worktree with no
// alternates object database, a generated hooks artifact outside the worktree,
// a full inline Codex launch-override contract, and a fail-closed dirty-source
// rejection.
// What it asserts now: the property that survives retirement — no Codex
// worktree, hooks artifact, inline override contract or source-clean check can
// be produced by this group at all, because `dogfood init` and
// `dogfood prepare-worktree` both refuse at the entry gate before dispatch.
#[test]
fn dogfood_worktree_arm_is_retired_and_provisions_no_codex_worktree() -> TestResult {
    assert_canonical_route_matches_source()?;
    let help = Command::new(binary())
        .args(["dogfood", "--help"])
        .output()?;
    assert!(help.status.success());
    let help_text = String::from_utf8(help.stdout)?;
    for arm in ["init", "prepare-worktree"] {
        assert!(
            help_text.contains(arm),
            "dogfood help no longer exposes {arm}"
        );
    }

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "eliot-dogfood-worktree-frontdoor-test-{}-{nonce}",
        std::process::id()
    ));
    let root_arg = root.to_string_lossy().into_owned();
    let destination = root.join("worktrees").join("candidate");
    let destination_arg = destination.to_string_lossy().into_owned();
    let surreal_exe_arg = surreal_exe_arg()?;

    assert_dogfood_arm_refuses(
        &[
            "dogfood",
            "init",
            "--root",
            &root_arg,
            "--project",
            &repo_root().to_string_lossy().into_owned(),
            "--surreal-exe",
            &surreal_exe_arg,
        ],
        "dogfood init",
    )?;

    assert_dogfood_arm_refuses(
        &[
            "dogfood",
            "prepare-worktree",
            "--root",
            &root_arg,
            "--destination",
            &destination_arg,
            "--branch",
            "codex/l3-isolated-test",
            "--commit",
            "0000000000000000000000000000000000000000",
        ],
        "dogfood prepare-worktree",
    )?;

    // Nothing a provisioned runtime would have produced may exist.
    assert!(
        !root.exists(),
        "refused dogfood init provisioned a runtime root"
    );
    assert!(!destination.exists());
    assert!(!destination.join(".git").exists());
    assert!(!destination.join(".codex").join("hooks.json").exists());
    assert!(
        !root
            .join("runtime")
            .join("bin")
            .join("surreal.exe")
            .exists()
    );
    assert!(!root.join("config").join("governor.toml").exists());
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
// Sentence: "the refusal is fail-closed and, for every arm except `mcp stdio`
// at a delegated host (which redirects to the approved Bridge), happens in the
// single entry gate at the top of `dispatch_command` - before any arm handler
// runs".
//
// This test previously failed on `assertion failed: failure.contains("must be
// absolute")`. That is the SAME root cause as the two tests above, not a
// different one: `dogfood::init`'s own relative-path validation lives behind
// the entry gate, so the gate refuses first and the arm's argument validation is
// unreachable. The evidence is in the BEFORE receipt for this binary, whose
// `detail` is the `legacy eliot-governor dogfood is retired` refusal. What it
// asserts now: the arm refuses at the gate, before its own argument
// validation, and provisions no runtime root for a rejected preseed path.
#[test]
fn dogfood_init_refuses_before_its_own_argument_validation() -> TestResult {
    assert_canonical_route_matches_source()?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "eliot-dogfood-relative-surreal-test-{}-{nonce}",
        std::process::id()
    ));
    let root_arg = root.to_string_lossy().into_owned();
    let output = Command::new(binary())
        .args([
            "dogfood",
            "init",
            "--root",
            &root_arg,
            "--project",
            &repo_root().to_string_lossy().into_owned(),
            "--surreal-exe",
            "surreal.exe",
        ])
        .output()?;
    assert_canonical_front_door_refusal(&output, "dogfood init (relative preseed)")?;

    // The retired per-arm validation is unreachable behind the gate, so its
    // diagnostic must not be the reported cause any more.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("must be absolute"),
        "the retired per-arm validation is still the reported cause: {combined}"
    );
    assert!(!root.exists());
    Ok(())
}

fn run(args: &[&str]) -> TestResult<Value> {
    let sequence = COMMAND_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "eliot-dogfood-command-{}-{sequence}",
        std::process::id()
    ));
    let stdout_path = base.with_extension("stdout.json");
    let stderr_path = base.with_extension("stderr.log");
    let stdout = fs::File::create(&stdout_path)?;
    let stderr = fs::File::create(&stderr_path)?;
    let status = Command::new(binary())
        .args(args)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .status()?;
    let stdout = fs::read(&stdout_path)?;
    let stderr = fs::read(&stderr_path)?;
    let _ = fs::remove_file(stdout_path);
    let _ = fs::remove_file(stderr_path);
    if !status.success() {
        return Err(format!(
            "command failed: stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&stdout)?)
}

fn run_failure(args: &[&str]) -> TestResult<String> {
    let output = Command::new(binary()).args(args).output()?;
    if output.status.success() {
        return Err("command unexpectedly succeeded".into());
    }
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_eliot-governor")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn surreal_exe_arg() -> TestResult<String> {
    let path = std::env::var_os("ELIOT_DOGFOOD_SURREAL_EXE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"));
    if !path.is_absolute() || !path.is_file() {
        return Err(format!(
            "focused dogfood test requires an operator-preseeded absolute surreal.exe; set ELIOT_DOGFOOD_SURREAL_EXE (resolved {})",
            path.display()
        )
        .into());
    }
    Ok(path.to_string_lossy().into_owned())
}
