#![allow(dead_code)]

use eliot_engine::{WriteAdmissionService, WriterActor, WriterConfig};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    ControlWalConfig, CredentialProviderKind, CurrentStateRequest, GovernorConfig, MemoryRevision,
    ObservabilityKind, ProjectId, ReadConsistencyMode, SemanticCommand, TaskId, WriteReceipt,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

static TEST_LOCK: Mutex<()> = Mutex::new(());

pub fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub fn rerun_with_credential_gate(test_name: &str) -> TestResult<bool> {
    if std::env::var("ELIOT_UL_T04_APP_CHILD").as_deref() == Ok(test_name) {
        return Ok(false);
    }
    let status = Command::new(std::env::current_exe()?)
        .env("ELIOT_UL_T04_APP_CHILD", test_name)
        .env("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION", "1")
        .args(["--exact", test_name, "--nocapture"])
        .status()?;
    if !status.success() {
        return Err(format!("credential-gated child test failed with {status}").into());
    }
    Ok(true)
}

pub struct Harness {
    runtime: OwnedRuntime,
    port: u16,
    config_path: PathBuf,
    pub client: McpClient,
    daemon: OwnedChild,
    surreal: OwnedChild,
    store: CanonicalStore,
    store_runtime: tokio::runtime::Runtime,
}

impl Harness {
    pub fn start(name: &str) -> TestResult<Self> {
        let runtime = OwnedRuntime::new(name)?;
        let port = test_port()?;
        let surreal_exe = pinned_surreal_exe()?;
        let password_file = runtime.path().join("secrets").join("surreal-root.txt");
        fs::create_dir_all(password_file.parent().ok_or("password parent missing")?)?;
        fs::write(&password_file, "ul-t04-test-secret")?;
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
        store_runtime.block_on(store.migrate_schema())?;
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

    pub fn create_task(
        &mut self,
        request_id: u64,
        project_id: ProjectId,
        task_id: TaskId,
    ) -> TestResult<Value> {
        self.client.tool_call(
            request_id,
            "eliot_task_contract_create",
            &json!({
                "project_id": project_id,
                "task_id": task_id,
                "write_id": eliot_types::WriteId::new_v7(),
                "title": "UL Task 04 integration",
                "acceptance_items": [
                    {
                        "item_id": "t04-observed",
                        "description": "UL delivery is observable",
                        "required_evidence": "observation"
                    },
                    {
                        "item_id": "t04-verified",
                        "description": "UL delivery passes its verifier",
                        "required_evidence": "verification"
                    }
                ]
            }),
        )
    }

    pub fn seed(&self, command: &SemanticCommand) -> TestResult<WriteReceipt> {
        let wal_path = self
            .runtime
            .path()
            .join(format!("seed-{}.redb", command.context().write_id));
        self.store_runtime.block_on(async {
            let wal = ControlWal::open(&ControlWalConfig {
                path: slash(&wal_path),
            })?;
            let (writer, actor) =
                WriterActor::channel(wal, self.store.clone(), &WriterConfig::default());
            let actor = tokio::spawn(actor.run());
            let receipt = writer.submit(WriteAdmissionService.admit(command)?).await?;
            drop(writer);
            actor.await?;
            Ok(receipt)
        })
    }

    pub fn current_revision(&self, project_id: ProjectId) -> TestResult<MemoryRevision> {
        Ok(self
            .store_runtime
            .block_on(self.store.current_state(&CurrentStateRequest {
                project_id,
                consistency: ReadConsistencyMode::Latest,
                at_least_revision: None,
            }))?
            .memory_revision)
    }

    pub fn observability_records<T: DeserializeOwned>(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        kind: ObservabilityKind,
    ) -> TestResult<Vec<T>> {
        Ok(self.store_runtime.block_on(
            self.store
                .observability_records_by_kind(project_id, task_id, kind),
        )?)
    }

    pub fn claim(
        &self,
        project_id: ProjectId,
        claim_id: eliot_types::ClaimId,
    ) -> TestResult<Option<eliot_store::CanonicalClaimCard>> {
        Ok(self
            .store_runtime
            .block_on(self.store.claim_card_by_id(project_id, claim_id))?)
    }

    pub fn cue_rows(&self, project_id: ProjectId) -> TestResult<Vec<eliot_types::CueIndexRow>> {
        Ok(self
            .store_runtime
            .block_on(self.store.load_cue_rows(project_id))?)
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

pub struct McpClient {
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
                    "clientInfo": {"name": "ul-t04-delivery", "version": "0.1.0"}
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

    pub fn tool_call_response(
        &mut self,
        id: u64,
        name: &str,
        arguments: &Value,
    ) -> TestResult<Value> {
        self.request(
            &json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments}
            }),
            Duration::from_secs(90),
        )
    }

    pub fn tool_call(&mut self, id: u64, name: &str, arguments: &Value) -> TestResult<Value> {
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
            "eliot-ul-t04-app-{name}-{}-{nonce}",
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
            .is_some_and(|name| name.starts_with("eliot-ul-t04-app-"))
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
        return Err(format!("UL-04 requires SurrealDB 3.1.4, got {}", version.trim()).into());
    }
    Ok(path)
}

fn test_port() -> TestResult<u16> {
    for port in 9000..=9099 {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    Err("no free UL-04 app test port in 9000-9099".into())
}

fn start_surreal(exe: &Path, port: u16) -> TestResult<OwnedChild> {
    OwnedChild::spawn(
        Command::new(exe)
            .env("SURREAL_USER", "root")
            .env("SURREAL_PASS", "ul-t04-test-secret")
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
service_name = "EliotGovernorUlT04"
instance_id = "ul-t04-delivery"

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
credential_id = "test-only/ul-t04"
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
    "test-only/ul-t04".clone_into(&mut config.db.surreal.credential_id);
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
    Err(format!("daemon runtime report did not publish pid {pid}").into())
}

fn repository_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root missing")?
        .to_path_buf())
}

fn test_runtime_root() -> TestResult<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?)
            .join("Eliot")
            .join("tests"),
    )
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_eliot-governor"))
}

fn slash(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}
