use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

// ---------------------------------------------------------------------------
// Canonical front-door refusal contract (retirement of the legacy route)
// ---------------------------------------------------------------------------
//
// Every test in this file used to start a real legacy runtime — its own pinned
// SurrealDB 3.1.4, its own `governor.toml`, its own `eliot-governor daemon run` —
// and then spoke the UL-01 JSON-RPC contract (`INVALID_TOOL_INPUT`,
// `ENCODING_REJECTED`, packet budget decisions) over the legacy MCP surface.
// That route no longer exists, so each test now asserts the contract the
// product actually publishes: the retired daemon and MCP arms refuse
// fail-closed with a stable machine-readable code plus the canonical
// Kernel-governed route, and no runtime report is ever published.
//
// Cluster-3 determination (asked for by the lane owner): this is the SAME root
// cause as the `multi_agent_access` and `dogfood_runtime` clusters, not a
// daemon-readiness harness defect. `start_daemon` here spawns the retired
// `eliot-governor --config <fixture> daemon run`, which `dispatch_command`
// refuses at the entry gate before `commands::run_daemon` can construct a
// `DbClientSet`, `CanonicalStore`, `ControlWal` or `WriterActor`. The refusal
// text appears verbatim in the BEFORE stderr tail for this binary. The
// misleading "daemon runtime report did not become ready for PID <n>" message is
// a second, independent harness defect: `wait_for_runtime_pid` polls only files
// and never observes the child's exit, so an immediate refusal is misreported as
// a 30-second readiness timeout.
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

/// Asserts the full published refusal receipt: fail-closed nonzero exit, stable
/// code, exact canonical route, `completed: false`, and a detail naming both the
/// retirement and the canonical route.
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
        detail.contains("is retired"),
        "{label} detail must record the retirement: {detail}"
    );
    assert!(
        detail.contains(EXPECTED_CANONICAL_ROUTE),
        "{label} detail must name the canonical route: {detail}"
    );
    Ok(())
}

/// One retired fixture root with the legacy `governor.toml` the retired arms
/// used to require. Constructing it proves the fixture is real; the arms below
/// must still refuse to act on it.
struct RetiredRouteFixture {
    runtime: OwnedRuntime,
    config_path: PathBuf,
}

impl RetiredRouteFixture {
    fn new(name: &str) -> TestResult<Self> {
        let runtime = OwnedRuntime::new(name)?;
        let config_path = runtime.path().join("config").join("governor.toml");
        let surreal_exe = pinned_surreal_exe()?;
        write_test_config(runtime.path(), &config_path, test_port()?, &surreal_exe)?;
        Ok(Self {
            runtime,
            config_path,
        })
    }

    /// The absolute runtime root the retired daemon would have published its
    /// runtime report under (`<root>/reports/runtime/latest.json`).
    fn runtime_report_root(&self) -> PathBuf {
        self.runtime.path().join("reports")
    }
}

impl Drop for RetiredRouteFixture {
    fn drop(&mut self) {
        let _ = self.runtime.cleanup();
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
// Document: `crates/eliot-app/src/front_door_cutover.rs`, module contract.
// Sentence: "the refusal is fail-closed and, for every arm except `mcp stdio`
// at a delegated host (which redirects to the approved Bridge), happens in the
// single entry gate at the top of `dispatch_command` - before any arm handler
// runs, before `ensure_daemon_ready` could auto-launch the daemon, before any
// `DbClientSet`/`CanonicalStore` start, and before any `ControlWal` or
// `WriterActor` is constructed".
//
// What this test asserted before: one JSON-RPC -32602 `INVALID_TOOL_INPUT`
// error for an incomplete `material_frame`, naming the four missing field paths
// and carrying a schema-valid `minimal_valid_example`.
// What it asserts now: the property that survives retirement — the MCP tool
// surface that produced -32602 does not exist, so an incomplete frame is never
// classified at all. The session is refused at the entry gate and no JSON-RPC
// error object is emitted.
#[test]
fn t01_incomplete_frame_returns_no_jsonrpc_error_because_no_legacy_session_exists() -> TestResult {
    assert_canonical_route_matches_source()?;
    let fixture = RetiredRouteFixture::new("incomplete-frame")?;

    let output = governor_command(&fixture.config_path)?
        .arg("--config")
        .arg(&fixture.config_path)
        .args(["mcp", "stdio", "--profile", "codex_controller"])
        .stdin(Stdio::null())
        .output()?;
    assert_canonical_front_door_refusal(&output, "mcp stdio codex_controller")?;

    let served = String::from_utf8_lossy(&output.stdout);
    for unreachable in [
        "\"jsonrpc\"",
        "INVALID_TOOL_INPUT",
        "minimal_valid_example",
        "-32602",
    ] {
        assert!(
            !served.contains(unreachable),
            "the retired MCP tool surface answered ({unreachable}): {served}"
        );
    }
    assert!(!fixture.runtime_report_root().exists());
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
// What this test asserted before: a typed -32602 `ENCODING_REJECTED` rejection
// for a `qmark_run` statement, with the memory revision unchanged across the
// rejected submit.
// What it asserts now: the property that survives retirement — the rejected
// write path is unreachable, so no candidate write is even attempted and no
// memory revision can move. It also closes the harness defect that masked this
// test: the retired daemon is now observed to exit (rather than waited on for a
// runtime report that can never be published), and its exit is asserted to be
// the canonical front-door refusal.
#[test]
fn t01_bad_candidate_is_rejected_before_write() -> TestResult {
    assert_canonical_route_matches_source()?;
    let fixture = RetiredRouteFixture::new("bad-candidate")?;

    let mut daemon = start_daemon(&fixture.config_path)?;
    let status = wait_for_observed_exit(&mut daemon, DAEMON_EXIT_TIMEOUT)?;
    assert!(
        !status.success(),
        "the retired daemon run arm served instead of refusing"
    );

    // No runtime report, no publication and no IPC authentication artifact:
    // the refused arm never reached startup.
    assert!(
        !fixture
            .runtime_report_root()
            .join("runtime")
            .join("latest.json")
            .exists()
    );
    assert!(
        !fixture
            .runtime
            .path()
            .join("runtime")
            .join("publication.json")
            .exists()
    );
    assert!(
        !fixture
            .runtime
            .path()
            .join("runtime")
            .join("ipc-auth.json")
            .exists()
    );

    // The write path is unreachable: no MCP session exists that could classify
    // an encoding violation or advance a memory revision.
    let output = governor_command(&fixture.config_path)?
        .arg("--config")
        .arg(&fixture.config_path)
        .args(["mcp", "stdio", "--profile", "codex_controller"])
        .stdin(Stdio::null())
        .output()?;
    assert_canonical_front_door_refusal(&output, "mcp stdio candidate submit")?;
    let served = String::from_utf8_lossy(&output.stdout);
    for unreachable in ["ENCODING_REJECTED", "qmark_run", "\"memory_revision\""] {
        assert!(
            !served.contains(unreachable),
            "the retired write path answered ({unreachable}): {served}"
        );
    }
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
// What this test asserted before: the UL-01 packet-content regression — the
// memory-free control arm's `preferred_tokens`/`hard_ceiling_tokens`/
// `effective_tokens` budget decision and candidate-content inclusion in the
// compiled packet.
// What it asserts now: the property that survives retirement — the packet
// compiler is unreachable, so no packet budget decision and no packet content
// can be produced, and the legacy configuration that would have backed it is
// never acted on.
#[test]
fn t01_packet_content_regression() -> TestResult {
    assert_canonical_route_matches_source()?;
    let fixture = RetiredRouteFixture::new("packet-content")?;
    assert!(fixture.config_path.is_file());

    let output = governor_command(&fixture.config_path)?
        .arg("--config")
        .arg(&fixture.config_path)
        .args(["mcp", "stdio", "--profile", "codex_controller"])
        .stdin(Stdio::null())
        .output()?;
    assert_canonical_front_door_refusal(&output, "mcp stdio compile packet")?;

    let served = String::from_utf8_lossy(&output.stdout);
    for unreachable in [
        "packet_budget_decision",
        "preferred_tokens",
        "hard_ceiling_tokens",
        "eliot_compile_packet_l3",
    ] {
        assert!(
            !served.contains(unreachable),
            "the retired packet compiler answered ({unreachable}): {served}"
        );
    }
    assert!(!fixture.runtime_report_root().exists());
    Ok(())
}

/// Bounded window for observing the retired daemon's immediate refusal. The
/// arm refuses in well under a second; this only exists so a wedged child
/// cannot hang the suite.
const DAEMON_EXIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Waits, bounded, for the owned child to exit and returns its status. This
/// replaces the retired `wait_for_runtime_pid` poll, which observed only files
/// and therefore misreported an immediate refusal as a readiness timeout.
fn wait_for_observed_exit(child: &mut OwnedChild, timeout: Duration) -> TestResult<ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(25));
    }
    child.stop()?;
    Err(format!(
        "the retired daemon arm did not exit within {}s",
        timeout.as_secs()
    )
    .into())
}

/// One owned child process. Kept (rather than `Child` directly) so every
/// spawned retired arm is killed on drop even when a test fails mid-assertion.
struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn spawn(command: &mut Command) -> TestResult<Self> {
        Ok(Self(Some(command.spawn()?)))
    }

    fn try_wait(&mut self) -> TestResult<Option<ExitStatus>> {
        self.0
            .as_mut()
            .ok_or_else(|| "owned child already consumed".into())
            .and_then(|child| child.try_wait().map_err(Into::into))
    }

    fn stop(&mut self) -> TestResult {
        if let Some(mut child) = self.0.take() {
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
        let _ = self.stop();
    }
}

struct OwnedRuntime(PathBuf);

impl OwnedRuntime {
    fn new(name: &str) -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = test_runtime_root()?.join(format!(
            "eliot-ul-t01-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn cleanup(&self) -> TestResult {
        if self
            .0
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("eliot-ul-t01-"))
            && self.0.starts_with(test_runtime_root()?)
        {
            fs::remove_dir_all(&self.0)?;
        }
        Ok(())
    }
}

impl Drop for OwnedRuntime {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn pinned_surreal_exe() -> TestResult<PathBuf> {
    let path = std::env::var_os("ELIOT_SURREAL_EXE").map_or_else(
        || PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
        PathBuf::from,
    );
    let output = Command::new(&path).arg("version").output()?;
    let version = String::from_utf8(output.stdout)?;
    if !output.status.success() || !version.trim().starts_with("3.1.4") {
        return Err(format!("UL-01 requires SurrealDB 3.1.4, got {}", version.trim()).into());
    }
    Ok(path)
}

fn test_port() -> TestResult<u16> {
    for port in 8600..=8699 {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    Err("no free UL-01 app test port in 8600-8699".into())
}

fn start_daemon(config_path: &Path) -> TestResult<OwnedChild> {
    OwnedChild::spawn(
        governor_command(config_path)?
            .arg("--config")
            .arg(config_path)
            .args(["daemon", "run"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit()),
    )
}

fn governor_command(config_path: &Path) -> TestResult<Command> {
    let mut command = Command::new(binary());
    for variable in [
        "ELIOT_GOVERNOR_CONFIG",
        "ELIOT_TEST_SURREAL_BIND",
        "ELIOT_TEST_SURREAL_ENDPOINT",
        "ELIOT_TEST_SURREAL_PASSWORD_FILE",
        "ELIOT_TEST_SURREAL_STORAGE",
        "SURREAL_USER",
        "SURREAL_PASS",
    ] {
        command.env_remove(variable);
    }
    command
        .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
        .env("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION", "1")
        .env("ELIOT_GOVERNOR_REPO_ROOT", repository_root()?);
    eliot_windows_ipc::test_support::IsolatedTestCredentialBackend::EphemeralFile {
        root: config_path
            .parent()
            .and_then(Path::parent)
            .unwrap_or(config_path)
            .join("operator-cursor-credentials"),
    }
    .configure_command(&mut command);
    Ok(command)
}

fn write_test_config(
    runtime: &Path,
    config_path: &Path,
    port: u16,
    surreal_exe: &Path,
) -> TestResult {
    fs::create_dir_all(config_path.parent().ok_or("config parent missing")?)?;
    let wal = slash(&runtime.join("control").join("control.redb"));
    let blobs = slash(&runtime.join("blobs"));
    let storage = format!("rocksdb:{}", slash(&runtime.join("unused-rocksdb")));
    let repo = repository_root()?;
    let surql = slash(&repo.join("crates/eliot-store/src/surql"));
    let exe = slash(surreal_exe);
    let bind = format!("127.0.0.1:{port}");
    let endpoint = format!("ws://127.0.0.1:{port}/rpc");
    let run_id = runtime
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("test runtime name missing")?;
    let password_file = format!("%LOCALAPPDATA%/Eliot/tests/{run_id}/secrets/surreal-root.txt");
    let config = format!(
        r#"schema_version = "1"

[service]
service_name = "EliotGovernorUlT01"
instance_id = "ul-t01-repair"

[db]
mode = "surreal_rpc_server"

[db.surreal]
exe = "{exe}"
bind = "{bind}"
endpoint = "{endpoint}"
storage = "{storage}"
ns = "ultest"
db = "ultest"
user = "root"
credential_provider = "legacy_password_file"
credential_id = "test-only/ul-t01"
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

fn test_runtime_root() -> TestResult<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA missing")?)
            .join("Eliot")
            .join("tests"),
    )
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_eliot-governor"))
}
