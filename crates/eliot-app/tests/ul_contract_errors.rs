use eliot_store::CanonicalStore;
use eliot_types::{
    CredentialProviderKind, GovernorConfig, ProjectId, TaskId, WriteId,
    compile_packet_minimal_example,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn t01_incomplete_frame_returns_one_32602() -> TestResult {
    let _guard = test_guard();
    let mut harness = Harness::start("incomplete-frame")?;
    let schema = harness.compile_packet_schema(10)?;
    let mut input = compile_packet_minimal_example();
    let frame = input
        .get_mut("material_frame")
        .and_then(Value::as_object_mut)
        .ok_or("minimal example has no material frame")?;
    for field in [
        "active_plan",
        "completed_work",
        "killed_paths",
        "expected_observable",
    ] {
        frame.remove(field);
    }

    let response = harness
        .client
        .tool_call_response(11, "eliot_compile_packet_l3", &input)?;
    let error = response.get("error").ok_or("expected one JSON-RPC error")?;
    assert!(response.get("result").is_none());
    assert_eq!(error["code"], -32602);
    assert_eq!(error["data"]["code"], "INVALID_TOOL_INPUT");
    let missing = error["data"]["missing"]
        .as_array()
        .ok_or("error data missing list is absent")?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    for path in [
        "material_frame.active_plan",
        "material_frame.completed_work",
        "material_frame.killed_paths",
        "material_frame.expected_observable",
    ] {
        assert!(
            missing.contains(path),
            "missing field path {path}: {response}"
        );
    }
    assert_ne!(error["code"], -32603);
    validate_schema(
        &schema,
        &schema,
        &error["data"]["minimal_valid_example"],
        "$",
    )?;
    Ok(())
}

#[test]
fn t01_bad_candidate_is_rejected_before_write() -> TestResult {
    let _guard = test_guard();
    if rerun_with_legacy_credential_gate("t01_bad_candidate_is_rejected_before_write")? {
        return Ok(());
    }
    let mut harness = Harness::start("bad-candidate")?;
    let (project_id, task_id) = harness.create_task(20)?;
    let before = harness.current_revision(21, project_id)?;
    let write_id = WriteId::new_v7();
    let response = harness.client.tool_call_response(
        22,
        "eliot_agent_candidate_submit",
        &candidate_arguments(
            project_id,
            task_id,
            write_id,
            "encoding",
            "проверка ????? QUARTZ",
        ),
    )?;
    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(response["error"]["data"]["code"], "ENCODING_REJECTED");
    assert_eq!(
        response["error"]["data"]["invalid"],
        json!([{"field": "$.claim.statement", "reason": "qmark_run"}]),
        "typed encoding violation differs: {response}"
    );

    let exact = harness.client.tool_call(
        23,
        "eliot_fetch_l2",
        &json!({
            "project_id": project_id,
            "handles": [format!("claim:{write_id}")]
        }),
    )?;
    let after = harness.current_revision(24, project_id)?;
    assert_eq!(exact["claims"].as_array().map(Vec::len), Some(0));
    assert_eq!(exact["relations"].as_array().map(Vec::len), Some(0));
    assert!(!harness.write_receipt_exists(write_id)?);
    assert_eq!(before, after);
    Ok(())
}

fn rerun_with_legacy_credential_gate(test_name: &str) -> TestResult<bool> {
    if std::env::var("ELIOT_UL_T01_CREDENTIAL_CHILD").as_deref() == Ok(test_name) {
        return Ok(false);
    }
    let status = Command::new(std::env::current_exe()?)
        .env("ELIOT_UL_T01_CREDENTIAL_CHILD", test_name)
        .env("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION", "1")
        .args(["--exact", test_name, "--nocapture"])
        .status()?;
    if !status.success() {
        return Err(format!("credential-gated child test failed with {status}").into());
    }
    Ok(true)
}

#[test]
fn t01_packet_content_regression() -> TestResult {
    let _guard = test_guard();
    let mut harness = Harness::start("packet-content")?;
    let (project_id, task_id) = harness.create_task(30)?;
    let write_id = WriteId::new_v7();
    harness.submit_candidate(
        31,
        project_id,
        task_id,
        write_id,
        "quartz-config",
        "QUARTZ pipeline reads config from quartz.toml",
    )?;
    let packet = harness.client.tool_call(
        32,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "Inspect the QUARTZ pipeline",
            "candidate_handles": [format!("claim:{write_id}")],
            "max_tokens": 4_000,
            "memory_mode": "include_case_candidates"
        }),
    )?;
    assert!(
        serde_json::to_string(&packet)?.contains("quartz.toml"),
        "packet omitted candidate content: {packet}"
    );
    Ok(())
}

fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct Harness {
    runtime: OwnedRuntime,
    port: u16,
    config_path: PathBuf,
    client: McpClient,
    daemon: OwnedChild,
    surreal: OwnedChild,
    store: CanonicalStore,
    store_runtime: tokio::runtime::Runtime,
}

impl Harness {
    fn start(name: &str) -> TestResult<Self> {
        let runtime = OwnedRuntime::new(name)?;
        let port = test_port()?;
        let surreal_exe = pinned_surreal_exe()?;
        let password_file = runtime.path().join("secrets").join("surreal-root.txt");
        fs::create_dir_all(password_file.parent().ok_or("password parent missing")?)?;
        fs::write(&password_file, "ul-t01-test-secret")?;
        let config_path = runtime.path().join("config").join("governor.toml");
        write_test_config(runtime.path(), &config_path, port, &surreal_exe)?;
        let surreal = start_surreal(&surreal_exe, port)?;
        wait_for_tcp(port, Duration::from_secs(20))?;
        let daemon = start_daemon(&config_path)?;
        wait_for_runtime_pid(
            &runtime
                .path()
                .join("reports")
                .join("runtime")
                .join("latest.json"),
            daemon.id()?,
            Duration::from_secs(30),
        )?;
        let mut client = McpClient::start(&config_path)?;
        client.initialize()?;
        let store = CanonicalStore::new(store_config(runtime.path(), port, &surreal_exe)?);
        let store_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(Self {
            runtime,
            port,
            config_path,
            client,
            daemon,
            surreal,
            store,
            store_runtime,
        })
    }

    fn create_task(&mut self, request_id: u64) -> TestResult<(ProjectId, TaskId)> {
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        self.client.tool_call(
            request_id,
            "eliot_task_contract_create",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "write_id": WriteId::new_v7(),
                "title": "UL-01 contract repair",
                "acceptance_items": [
                    {
                        "item_id": "behavior",
                        "description": "requested behavior is present",
                        "required_evidence": "observation"
                    },
                    {
                        "item_id": "isolation",
                        "description": "test uses an isolated real database",
                        "required_evidence": "verification"
                    }
                ]
            }),
        )?;
        Ok((project_id, task_id))
    }

    fn submit_candidate(
        &mut self,
        request_id: u64,
        project_id: ProjectId,
        task_id: TaskId,
        write_id: WriteId,
        topic: &str,
        statement: &str,
    ) -> TestResult<Value> {
        self.client.tool_call(
            request_id,
            "eliot_agent_candidate_submit",
            &candidate_arguments(project_id, task_id, write_id, topic, statement),
        )
    }

    fn current_revision(&mut self, request_id: u64, project_id: ProjectId) -> TestResult<u64> {
        self.client
            .tool_call(
                request_id,
                "eliot_current_state",
                &json!({"project_id": project_id}),
            )?
            .get("memory_revision")
            .and_then(Value::as_u64)
            .ok_or_else(|| "current state has no memory_revision".into())
    }

    fn compile_packet_schema(&mut self, request_id: u64) -> TestResult<Value> {
        let response = self.client.request(
            &json!({"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": {}}),
            Duration::from_secs(30),
        )?;
        response
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .and_then(|tools| {
                tools
                    .iter()
                    .find(|tool| tool["name"] == "eliot_compile_packet_l3")
            })
            .and_then(|tool| tool.get("inputSchema"))
            .cloned()
            .ok_or_else(|| "compile packet schema is absent".into())
    }

    fn write_receipt_exists(&self, write_id: WriteId) -> TestResult<bool> {
        Ok(self
            .store_runtime
            .block_on(self.store.write_receipt_by_id(&write_id))?
            .is_some())
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.client.stop();
        let _ = self.daemon.stop();
        let _ = self.surreal.stop();
        let _ = wait_for_tcp_closed(self.port, Duration::from_secs(5));
        let _ = fs::remove_file(&self.config_path);
        let _ = self.runtime.cleanup();
    }
}

fn candidate_arguments(
    project_id: ProjectId,
    task_id: TaskId,
    write_id: WriteId,
    topic: &str,
    statement: &str,
) -> Value {
    json!({
        "project_id": project_id,
        "task_id": task_id,
        "write_id": write_id,
        "topic": topic,
        "statement": statement,
        "where_applicable": ["eliot-memory-os"],
        "where_not_applicable": [],
        "negative_constraints": [],
        "provenance_refs": ["test:UL-01"],
        "freshness_rule": "valid only for this isolated repair test",
        "expected_reuse_note": "Reuse only in this isolated contract test.",
        "cue_bindings": [{
            "cue_kind": "file_path",
            "cue_value": "crates/eliot-app/tests/ul_contract_errors.rs",
            "match_mode": "exact",
            "strength": "primary",
            "expected_reuse_note": "Reuse only in this isolated contract test."
        }]
    })
}

struct McpClient {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    responses: Receiver<TestResult<String>>,
    reader: Option<JoinHandle<()>>,
}

impl McpClient {
    fn start(config_path: &Path) -> TestResult<Self> {
        let mut child = governor_command()
            .arg("--config")
            .arg(config_path)
            .args(["mcp", "stdio", "--profile", "codex_controller"])
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

    fn initialize(&mut self) -> TestResult {
        let response = self.request(
            &json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "ul-t01-repair", "version": "0.1.0"}
                }
            }),
            Duration::from_secs(30),
        )?;
        if response
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str)
            != Some("2025-06-18")
        {
            return Err(format!("MCP initialize failed: {response}").into());
        }
        Ok(())
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

    fn tool_call_response(&mut self, id: u64, name: &str, arguments: &Value) -> TestResult<Value> {
        self.request(
            &json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments}
            }),
            Duration::from_secs(60),
        )
    }

    fn tool_call(&mut self, id: u64, name: &str, arguments: &Value) -> TestResult<Value> {
        let response = self.tool_call_response(id, name, arguments)?;
        if let Some(error) = response.get("error") {
            return Err(format!("MCP tool {name} failed: {error}").into());
        }
        let result = response.get("result").ok_or("missing MCP tool result")?;
        if result.get("isError").and_then(Value::as_bool) == Some(true) {
            return Err(format!("MCP tool {name} returned error: {result}").into());
        }
        result
            .get("structuredContent")
            .cloned()
            .ok_or_else(|| "missing MCP structuredContent".into())
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

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn spawn(command: &mut Command) -> TestResult<Self> {
        Ok(Self(Some(command.spawn()?)))
    }

    fn id(&self) -> TestResult<u32> {
        self.0
            .as_ref()
            .map(Child::id)
            .ok_or_else(|| "owned child already consumed".into())
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

fn start_surreal(exe: &Path, port: u16) -> TestResult<OwnedChild> {
    OwnedChild::spawn(
        Command::new(exe)
            .env("SURREAL_USER", "root")
            .env("SURREAL_PASS", "ul-t01-test-secret")
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
            .arg("memory")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit()),
    )
}

fn start_daemon(config_path: &Path) -> TestResult<OwnedChild> {
    OwnedChild::spawn(
        governor_command()
            .arg("--config")
            .arg(config_path)
            .args(["daemon", "run"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit()),
    )
}

fn governor_command() -> Command {
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
        .env("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION", "1");
    command
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
    let migrations = slash(&repo.join("crates/eliot-store/migrations"));
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
migrations_dir = "{migrations}"
"#
    );
    fs::write(config_path, config)?;
    Ok(())
}

fn store_config(
    runtime: &Path,
    port: u16,
    surreal_exe: &Path,
) -> TestResult<eliot_types::SurrealServerConfig> {
    let mut config = GovernorConfig::default();
    config.db.surreal.exe = slash(surreal_exe);
    config.db.surreal.bind = format!("127.0.0.1:{port}");
    config.db.surreal.endpoint = format!("ws://127.0.0.1:{port}/rpc");
    config.db.surreal.storage = format!("rocksdb:{}", slash(&runtime.join("unused-rocksdb")));
    "ultest".clone_into(&mut config.db.surreal.ns);
    "ultest".clone_into(&mut config.db.surreal.db);
    "root".clone_into(&mut config.db.surreal.user);
    config.db.surreal.credential_provider = CredentialProviderKind::LegacyPasswordFile;
    "test-only/ul-t01-app".clone_into(&mut config.db.surreal.credential_id);
    let run_id = runtime
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("test runtime name missing")?;
    config.db.surreal.password_file =
        format!("%LOCALAPPDATA%/Eliot/tests/{run_id}/secrets/surreal-root.txt");
    Ok(config.db.surreal)
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

fn wait_for_runtime_pid(path: &Path, pid: u32, timeout: Duration) -> TestResult {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(bytes) = fs::read(path)
            && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
            && value.pointer("/status/pid").and_then(Value::as_u64) == Some(u64::from(pid))
            && value
                .pointer("/status/ipc_enabled")
                .and_then(Value::as_bool)
                == Some(true)
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(format!("daemon runtime report did not become ready for PID {pid}").into())
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

fn validate_schema(root: &Value, schema: &Value, value: &Value, path: &str) -> TestResult {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let target = reference
            .strip_prefix('#')
            .and_then(|pointer| root.pointer(pointer))
            .ok_or_else(|| format!("unresolved schema ref {reference}"))?;
        return validate_schema(root, target, value, path);
    }
    for keyword in ["allOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            for branch in branches {
                validate_schema(root, branch, value, path)?;
            }
        }
    }
    for keyword in ["anyOf", "oneOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            let branch = branches
                .iter()
                .find(|branch| schema_type_matches(root, branch, value))
                .ok_or_else(|| format!("{path} matches no {keyword} branch"))?;
            return validate_schema(root, branch, value, path);
        }
    }
    if let Some(kind) = schema.get("type").and_then(Value::as_str)
        && !value_matches_type(value, kind)
    {
        return Err(format!("{path} expected {kind}").into());
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.contains(value)
    {
        return Err(format!("{path} is outside the schema enum").into());
    }
    if let Some(object) = value.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for field in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(field) {
                    return Err(format!("{path}.{field} is required").into());
                }
            }
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (field, field_schema) in properties {
                if let Some(field_value) = object.get(field) {
                    validate_schema(root, field_schema, field_value, &format!("{path}.{field}"))?;
                }
            }
        }
    } else if let Some(array) = value.as_array()
        && let Some(items) = schema.get("items")
    {
        for (index, item) in array.iter().enumerate() {
            validate_schema(root, items, item, &format!("{path}[{index}]"))?;
        }
    }
    Ok(())
}

fn schema_type_matches(root: &Value, schema: &Value, value: &Value) -> bool {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str)
        && let Some(target) = reference
            .strip_prefix('#')
            .and_then(|pointer| root.pointer(pointer))
    {
        return schema_type_matches(root, target, value);
    }
    match schema.get("type") {
        Some(Value::String(kind)) => value_matches_type(value, kind),
        Some(Value::Array(kinds)) => kinds
            .iter()
            .filter_map(Value::as_str)
            .any(|kind| value_matches_type(value, kind)),
        _ => true,
    }
}

fn value_matches_type(value: &Value, kind: &str) -> bool {
    match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value
            .as_number()
            .is_some_and(|number| number.is_i64() || number.is_u64()),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => true,
    }
}
