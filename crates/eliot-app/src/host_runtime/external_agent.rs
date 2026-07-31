use super::external_agent_process::{ManagedExternalAgentOutput, run_external_agent_process};
use super::*;
use eliot_engine::adapter::BoxAdapterFuture;
use eliot_engine::{
    Adapter, AdapterRegistry, AdapterSupervisor, AntigravityCommandInput, ClaudeCodeCommandInput,
    ExternalResultCompletenessService, OpenCodeCommandInput, ProviderCallReservationDecision,
    ProviderCallReservationOwner, ProviderCallReservationRequest, ProviderCommandPlan,
    ProviderCompletenessInput, ProviderInvocationJournal, ProviderOutputSpool,
    ProviderTerminalResult, build_antigravity_command, build_claude_code_command,
    build_opencode_command, parse_antigravity_output, parse_claude_code_stream,
    parse_opencode_stream, seal_provider_runtime_contract,
    validate_external_agent_execution_request,
};
use eliot_types::{
    AdapterAuthorityProfile, AdapterCapability, AdapterClass, AdapterError, AdapterHealth,
    AdapterLimits, AdapterObservation, AdapterRequest, AdapterResult, AdapterResultStatus,
    AdapterState, AgentResultEnvelope, AgentResultStatus, AgentRole, ExternalAgentExecutionRequest,
    ExternalAgentPurpose, OperationJobState, PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION,
    ProcessExecutionPolicy, ProviderExecutionEvidence, ProviderInvocationAttempt,
    ProviderInvocationState, ProviderMcpServerContract, ProviderRuntimeContract,
    ProviderStructuredOutputMode, TaintClass,
};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::future::Future;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};

const MAX_PROVIDER_OUTPUT_BYTES: u64 = 1_048_576;
const MAX_MCP_REFERENCE_OUTPUT_BYTES: u64 = 1_048_576;
const MCP_REFERENCE_TIMEOUT: Duration = Duration::from_secs(20);
const MCP_SMOKE_PRE_PROVIDER_TIMEOUT: Duration = Duration::from_secs(60);
const PROVIDER_CLEANUP_GRACE_SECONDS: u64 = 15;
const EXTERNAL_ADAPTER_VERSION: &str = "eliot-external-agent-adapter-v1";
const MCP_SMOKE_PHASE_SCHEMA_VERSION: &str = "eliot-external-agent-smoke-phase-v1";
const SAFE_INHERITED_ENVIRONMENT: &[&str] = &[
    "SystemRoot",
    "WINDIR",
    "ComSpec",
    "PATH",
    "PATHEXT",
    "USERPROFILE",
    "HOME",
    "LOCALAPPDATA",
    "APPDATA",
    "TEMP",
    "TMP",
];

#[derive(Clone)]
struct ExternalAgentAdapterCore {
    host: AgentHostId,
    adapter_id: String,
    executable: Option<PathBuf>,
    version: Option<String>,
    governor_executable: PathBuf,
    config_path: PathBuf,
    manifest: eliot_types::CapabilityManifest,
}

#[derive(Clone)]
pub(crate) struct ClaudeCodeCliAdapter {
    core: ExternalAgentAdapterCore,
}

#[derive(Clone)]
pub(crate) struct AntigravityCliAdapter {
    core: ExternalAgentAdapterCore,
}

#[derive(Clone)]
pub(crate) struct OpenCodeCliAdapter {
    core: ExternalAgentAdapterCore,
}

#[derive(Clone, Debug)]
pub(crate) struct ExternalAgentRuntimePreview {
    pub adapter_id: String,
    pub adapter_version: String,
    pub runtime_contract: ProviderRuntimeContract,
}

struct PreparedExternalAgentExecution {
    executable: PathBuf,
    provider_hash_before: String,
    schema: Value,
    cwd: PathBuf,
    plan: ProviderCommandPlan,
    environment: BTreeMap<String, String>,
    runtime_contract: ProviderRuntimeContract,
}

struct CanonicalAgentResultWrite {
    key: String,
    receipt_kind: &'static str,
    body: Value,
}

pub(crate) fn production_external_agent_supervisor(
    config_path: &Path,
) -> Result<AdapterSupervisor> {
    let governor_executable = resolved_governor_executable()?;
    let mut registry = AdapterRegistry::new();
    registry.register(ClaudeCodeCliAdapter::new(
        config_path,
        &governor_executable,
    )?)?;
    registry.register(AntigravityCliAdapter::new(
        config_path,
        &governor_executable,
    )?)?;
    registry.register(OpenCodeCliAdapter::new(config_path, &governor_executable)?)?;
    Ok(AdapterSupervisor::new(registry))
}

pub(crate) fn prepare_external_agent_runtime(
    config_path: &Path,
    host: AgentHostId,
    execution: &ExternalAgentExecutionRequest,
) -> Result<ExternalAgentRuntimePreview> {
    anyhow::ensure!(
        host != AgentHostId::Codex,
        "Codex does not use an external-agent adapter"
    );
    validate_external_agent_execution_request(execution)?;
    let core = ExternalAgentAdapterCore::new(host, config_path, &resolved_governor_executable()?)?;
    let prepared = core.prepare_governed(execution)?;
    Ok(ExternalAgentRuntimePreview {
        adapter_id: core.adapter_id,
        adapter_version: core.manifest.version,
        runtime_contract: prepared.runtime_contract,
    })
}

pub(crate) fn external_agent_blob_path(config_path: &Path, reference: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        !reference.trim().is_empty(),
        "external-agent blob reference is empty"
    );
    let root = runtime_root(config_path);
    let root = std::fs::canonicalize(&root).with_context(|| {
        format!(
            "canonicalize external-agent runtime root {}",
            root.display()
        )
    })?;
    let path = std::fs::canonicalize(root.join(reference))
        .with_context(|| format!("resolve external-agent blob {reference}"))?;
    anyhow::ensure!(
        path.starts_with(&root) && path.is_file(),
        "external-agent blob escaped its runtime root"
    );
    Ok(path)
}

fn resolved_governor_executable() -> Result<PathBuf> {
    let executable =
        std::env::var_os("ELIOT_GOVERNOR_EXE").map_or(std::env::current_exe()?, PathBuf::from);
    std::fs::canonicalize(&executable)
        .with_context(|| format!("canonicalize Governor executable {}", executable.display()))
}

pub(crate) async fn dispatch(
    config_path: &Path,
    command: crate::ExternalAgentCommand,
) -> Result<()> {
    match command {
        crate::ExternalAgentCommand::Doctor { host } => {
            let host = parse_host(&host)?;
            anyhow::ensure!(
                host != AgentHostId::Codex,
                "Codex is not an external adapter"
            );
            let supervisor = production_external_agent_supervisor(config_path)?;
            let adapter_id = adapter_id(host);
            let health = supervisor.health_probe(adapter_id).await;
            let manifest = supervisor.registry().inspect(adapter_id)?;
            let mcp_preflight = mcp_reference_exchange(
                config_path,
                None,
                Some(host),
                None,
                None,
                None,
                "doctor_mcp",
            )
            .await
            .map_or_else(
                |error| {
                    json!({
                        "passed": false,
                        "error": error.to_string(),
                    })
                },
                |value| {
                    json!({
                        "passed": true,
                        "tool_names": value.tool_names,
                        "raw_database_absent": value.raw_database_absent,
                    })
                },
            );
            write_json(&json!({
                "schema_version": "eliot-external-agent-doctor-v1",
                "host": host,
                "adapter_id": adapter_id,
                "manifest": manifest,
                "health": health,
                "installed": health.healthy,
                "provider_authenticated": false,
                "exact_model_selectable": false,
                "mcp_preflight": mcp_preflight,
                "structured_output_ready": false,
                "console_headless_ready": false,
                "model_calls": 0,
                "note": "static doctor cannot attest authentication, exact model resolution, or structured cognition"
            }))
        }
        crate::ExternalAgentCommand::AuthSmoke { host, model } => {
            let host = parse_host(&host)?;
            let report = run_auth_smoke(config_path, host, &model).await?;
            write_json(&report)
        }
        crate::ExternalAgentCommand::McpSmoke { host, model } => {
            let host = parse_host(&host)?;
            let report = run_mcp_smoke(config_path, host, &model).await?;
            write_json(&report)
        }
        crate::ExternalAgentCommand::McpPreflight { host, model } => {
            let host = parse_host(&host)?;
            let report = run_mcp_preflight(config_path, host, &model).await?;
            write_json(&report)
        }
        crate::ExternalAgentCommand::Inspect { invocation } => {
            anyhow::ensure!(
                !invocation.trim().is_empty()
                    && !invocation.contains(['/', '\\'])
                    && invocation != "."
                    && invocation != "..",
                "invalid external-agent invocation ID"
            );
            let journal = ProviderInvocationJournal::new(runtime_root(config_path));
            let direct = journal.load(&invocation);
            let attempt = direct
                .or_else(|_| journal.load(&format!("external-agent-attempt-{invocation}")))?;
            write_json(&attempt)
        }
    }
}

#[derive(Clone, Debug)]
struct McpReferenceExchange {
    tool_names: Vec<String>,
    raw_database_absent: bool,
    tool_call: Option<Value>,
}

#[derive(Debug)]
struct CappedRead {
    bytes: Vec<u8>,
    overflowed: bool,
}

async fn read_and_drain_capped<R>(
    mut reader: R,
    max_bytes: u64,
    stream_name: &'static str,
) -> Result<CappedRead>
where
    R: AsyncRead + Unpin,
{
    let max_bytes = usize::try_from(max_bytes).context("MCP output cap exceeds usize")?;
    let mut bytes = Vec::new();
    let mut overflowed = false;
    let mut chunk = [0_u8; 8_192];
    loop {
        let read = reader
            .read(&mut chunk)
            .await
            .with_context(|| format!("read MCP reference {stream_name}"))?;
        if read == 0 {
            break;
        }
        let keep = max_bytes.saturating_sub(bytes.len()).min(read);
        bytes.extend_from_slice(&chunk[..keep]);
        overflowed |= keep != read;
    }
    Ok(CappedRead { bytes, overflowed })
}

async fn run_bounded_mcp_child(
    mut command: tokio::process::Command,
    request_bytes: Vec<u8>,
    phase: &str,
    timeout: Duration,
) -> Result<std::process::Output> {
    command.kill_on_drop(true);
    let mut child = command
        .spawn()
        .with_context(|| format!("start Rust MCP reference exchange phase={phase}"))?;
    let pid = child.id().unwrap_or_default();
    let mut stdin = child
        .stdin
        .take()
        .context("MCP reference stdin is absent")?;
    let stdout = child
        .stdout
        .take()
        .context("MCP reference stdout is absent")?;
    let stderr = child
        .stderr
        .take()
        .context("MCP reference stderr is absent")?;

    let writer = tokio::spawn(async move {
        stdin
            .write_all(&request_bytes)
            .await
            .context("write MCP reference requests")?;
        stdin
            .shutdown()
            .await
            .context("shutdown MCP reference stdin")?;
        Ok::<(), anyhow::Error>(())
    });
    let stdout_reader = tokio::spawn(read_and_drain_capped(
        stdout,
        MAX_MCP_REFERENCE_OUTPUT_BYTES,
        "stdout",
    ));
    let stderr_reader = tokio::spawn(read_and_drain_capped(
        stderr,
        MAX_MCP_REFERENCE_OUTPUT_BYTES,
        "stderr",
    ));

    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let status = tokio::select! {
        status = child.wait() => Some(status.context("wait for Rust MCP reference exchange")?),
        () = &mut deadline => None,
    };
    let Some(status) = status else {
        let kill_error = child.kill().await.err();
        let reap_error = child.wait().await.err();
        writer.abort();
        stdout_reader.abort();
        stderr_reader.abort();
        drop(writer.await);
        drop(stdout_reader.await);
        drop(stderr_reader.await);
        anyhow::ensure!(
            kill_error.is_none() && reap_error.is_none(),
            "Rust MCP reference exchange phase={phase} exceeded {} seconds; pid={pid}; kill_error={kill_error:?}; reap_error={reap_error:?}",
            timeout.as_secs_f64()
        );
        anyhow::bail!(
            "Rust MCP reference exchange phase={phase} exceeded {} seconds; pid={pid}; child killed and reaped",
            timeout.as_secs_f64()
        );
    };

    writer.await.context("join MCP reference stdin writer")??;
    let stdout = stdout_reader
        .await
        .context("join MCP reference stdout reader")??;
    let stderr = stderr_reader
        .await
        .context("join MCP reference stderr reader")??;
    anyhow::ensure!(
        !stdout.overflowed,
        "Rust MCP reference exchange phase={phase} stdout exceeded {MAX_MCP_REFERENCE_OUTPUT_BYTES} bytes"
    );
    anyhow::ensure!(
        !stderr.overflowed,
        "Rust MCP reference exchange phase={phase} stderr exceeded {MAX_MCP_REFERENCE_OUTPUT_BYTES} bytes"
    );
    Ok(std::process::Output {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the reference exchange keeps one auditable MCP process lifecycle"
)]
async fn mcp_reference_exchange(
    config_path: &Path,
    profile: Option<&str>,
    host: Option<AgentHostId>,
    scope: Option<&HostLaunchScope>,
    tool_name: Option<&str>,
    tool_arguments: Option<&Value>,
    phase: &str,
) -> Result<McpReferenceExchange> {
    let executable =
        std::env::var_os("ELIOT_GOVERNOR_EXE").map_or(std::env::current_exe()?, PathBuf::from);
    let executable = std::fs::canonicalize(executable)?;
    let mut command = tokio::process::Command::new(executable);
    if config_path.is_file() {
        command.args(["--config", &path_string(config_path)]);
    }
    command.args(["mcp", "stdio"]);
    if let Some(host) = host {
        command.args(["--host", host.as_str()]);
    }
    if let Some(profile) = profile {
        command.args(["--profile", profile]);
    }
    command.args(["--instance", "default"]);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for name in [
        "SURREAL_USER",
        "SURREAL_PASS",
        "ELIOT_TEST_SURREAL_BIND",
        "ELIOT_TEST_SURREAL_ENDPOINT",
        "ELIOT_TEST_SURREAL_PASSWORD_FILE",
        "ELIOT_TEST_SURREAL_STORAGE",
    ] {
        command.env_remove(name);
    }
    command.env("ELIOT_GOVERNOR_CONFIG", config_path);
    if let Some(scope) = scope {
        if let Some(value) = scope.agent_session_id {
            command.env("ELIOT_AGENT_SESSION_ID", value.to_string());
        }
        if let Some(value) = scope.project_id {
            command.env("ELIOT_PROJECT_ID", value.to_string());
        }
        if let Some(value) = scope.task_id {
            command.env("ELIOT_TASK_ID", value.to_string());
        }
        if let Some(value) = scope.work_item_id {
            command.env("ELIOT_WORK_ITEM_ID", value.to_string());
        }
        if let Some(value) = &scope.role_lease_id {
            command.env("ELIOT_ROLE_LEASE_ID", value);
        }
    }
    let mut requests = vec![
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "eliot-rust-external-agent-preflight",
                    "version": "1.0.0"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    ];
    if let Some(tool_name) = tool_name {
        requests.push(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": tool_arguments.cloned().unwrap_or_else(|| json!({}))
            }
        }));
    }
    let mut request_bytes = Vec::new();
    for (index, request) in requests.iter().enumerate() {
        request_bytes.extend_from_slice(&serde_json::to_vec(request)?);
        request_bytes.push(b'\n');
        if index == 0 {
            request_bytes.extend_from_slice(&serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }))?);
            request_bytes.push(b'\n');
        }
    }
    let output =
        run_bounded_mcp_child(command, request_bytes, phase, MCP_REFERENCE_TIMEOUT).await?;
    anyhow::ensure!(
        output.status.success(),
        "Rust MCP reference exchange failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses = String::from_utf8(output.stdout)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let initialize = response_by_id(&responses, 1)?;
    anyhow::ensure!(
        initialize.get("error").is_none(),
        "MCP initialize returned an error: {initialize}"
    );
    let tools = response_by_id(&responses, 2)?;
    anyhow::ensure!(
        tools.get("error").is_none(),
        "MCP tools/list returned an error: {tools}"
    );
    let tool_names = tools
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .context("MCP tools/list returned no tools array")?
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let raw_database_absent = !tool_names.iter().any(|name| {
        let lower = name.to_ascii_lowercase();
        lower.contains("surrealdb") || lower == "query"
    });
    anyhow::ensure!(
        raw_database_absent,
        "raw database tool was exposed by the Governor MCP facade"
    );
    let tool_call = if tool_name.is_some() {
        let response = response_by_id(&responses, 3)?;
        anyhow::ensure!(
            response.get("error").is_none(),
            "MCP tools/call returned an error: {response}"
        );
        response.pointer("/result/structuredContent").cloned()
    } else {
        None
    };
    Ok(McpReferenceExchange {
        tool_names,
        raw_database_absent,
        tool_call,
    })
}

fn response_by_id(responses: &[Value], id: u64) -> Result<&Value> {
    responses
        .iter()
        .find(|response| response.get("id").and_then(Value::as_u64) == Some(id))
        .with_context(|| format!("MCP response {id} is absent"))
}

#[derive(Clone)]
struct SmokePhaseTrace {
    path: PathBuf,
    smoke_id: String,
    active: Arc<Mutex<Option<ActiveSmokePhase>>>,
}

struct ActiveSmokePhase {
    name: String,
    started: Instant,
}

impl SmokePhaseTrace {
    fn new(smoke_root: &Path, smoke_id: &str) -> Result<Self> {
        std::fs::create_dir_all(smoke_root)?;
        Ok(Self {
            path: smoke_root.join("phases.jsonl"),
            smoke_id: smoke_id.to_owned(),
            active: Arc::new(Mutex::new(None)),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn append(
        &self,
        phase: &str,
        status: &str,
        elapsed: Duration,
        detail: Option<&str>,
    ) -> Result<()> {
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        let entry = json!({
            "schema_version": MCP_SMOKE_PHASE_SCHEMA_VERSION,
            "smoke_id": self.smoke_id,
            "phase": phase,
            "status": status,
            "elapsed_ms": elapsed_ms,
            "observed_at": OffsetDateTime::now_utc(),
            "diagnostic_only": true,
            "host_broker_receipt": false,
            "detail": detail,
        });
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("open smoke phase journal {}", self.path.display()))?;
        serde_json::to_writer(&mut file, &entry)?;
        file.write_all(b"\n")?;
        file.sync_data()?;
        Ok(())
    }

    fn start(&self, phase: &str) -> Result<()> {
        {
            let mut active = self
                .active
                .lock()
                .map_err(|_| anyhow::anyhow!("smoke phase mutex is poisoned"))?;
            anyhow::ensure!(
                active.is_none(),
                "cannot start smoke phase {phase}; another phase is active"
            );
            *active = Some(ActiveSmokePhase {
                name: phase.to_owned(),
                started: Instant::now(),
            });
        }
        if let Err(error) = self.append(phase, "started", Duration::ZERO, None) {
            let mut active = self
                .active
                .lock()
                .map_err(|_| anyhow::anyhow!("smoke phase mutex is poisoned"))?;
            *active = None;
            return Err(error);
        }
        Ok(())
    }

    fn finish(&self, phase: &str, status: &str, detail: Option<&str>) -> Result<()> {
        let active = self
            .active
            .lock()
            .map_err(|_| anyhow::anyhow!("smoke phase mutex is poisoned"))?
            .take()
            .context("no active smoke phase to finish")?;
        anyhow::ensure!(
            active.name == phase,
            "smoke phase mismatch: active={} finished={phase}",
            active.name
        );
        self.append(phase, status, active.started.elapsed(), detail)
    }

    async fn run<T, F>(&self, phase: &str, future: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        self.start(phase)?;
        match future.await {
            Ok(value) => {
                self.finish(phase, "passed", None)?;
                Ok(value)
            }
            Err(error) => {
                let detail = error.to_string();
                self.finish(phase, "failed", Some(&detail))?;
                Err(error)
            }
        }
    }

    fn run_sync<T, F>(&self, phase: &str, operation: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        self.start(phase)?;
        match operation() {
            Ok(value) => {
                self.finish(phase, "passed", None)?;
                Ok(value)
            }
            Err(error) => {
                let detail = error.to_string();
                self.finish(phase, "failed", Some(&detail))?;
                Err(error)
            }
        }
    }

    fn abort_active(&self, detail: &str) -> Result<()> {
        let active = self
            .active
            .lock()
            .map_err(|_| anyhow::anyhow!("smoke phase mutex is poisoned"))?
            .take();
        if let Some(active) = active {
            self.append(
                &active.name,
                "aborted",
                active.started.elapsed(),
                Some(detail),
            )?;
        }
        Ok(())
    }
}

struct McpSmokePreparation {
    smoke_id: String,
    smoke_root: PathBuf,
    workspace: PathBuf,
    project_id: ProjectId,
    task_id: TaskId,
    scope: HostLaunchScope,
    work_item_id: WorkItemId,
    memory_revision: u64,
    preflight: McpReferenceExchange,
    trace: SmokePhaseTrace,
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded preparation keeps phase attribution and canonical identity setup together"
)]
async fn prepare_mcp_smoke(
    config_path: &Path,
    host: AgentHostId,
    model: &str,
) -> Result<McpSmokePreparation> {
    anyhow::ensure!(
        host != AgentHostId::Codex,
        "Codex is not an external adapter"
    );
    anyhow::ensure!(
        !model.trim().is_empty(),
        "MCP smoke preparation requires an exact non-empty model"
    );
    let smoke_id = format!("external-agent-smoke-{}-{}", host.as_str(), Uuid::now_v7());
    let smoke_root = runtime_root(config_path)
        .join("external-agent-smokes")
        .join(&smoke_id);
    let workspace = smoke_root.join("workspace");
    let trace = SmokePhaseTrace::new(&smoke_root, &smoke_id)?;

    let preparation = async {
        trace
            .run("workspace_create", async {
                std::fs::create_dir_all(&workspace)?;
                Ok(())
            })
            .await?;
        let identity = trace
            .run(
                "project_identity",
                mcp_reference_exchange(
                    config_path,
                    Some("codex_controller"),
                    None,
                    None,
                    Some("eliot_project_identity"),
                    Some(&json!({"project_key": path_string(&workspace)})),
                    "project_identity",
                ),
            )
            .await?;
        let identity = identity
            .tool_call
            .context("project identity tool returned no structured content")?;
        let project_id = identity
            .get("project_id")
            .or_else(|| identity.pointer("/tool_call/project_id"))
            .and_then(Value::as_str)
            .context("project identity returned no project_id")
            .and_then(|value| ProjectId::from_str(value).context("parse smoke project_id"))?;
        let task_id = TaskId::new_v7();
        let task_create = trace
            .run(
                "task_contract_create",
                mcp_reference_exchange(
                    config_path,
                    Some("codex_controller"),
                    None,
                    None,
                    Some("eliot_task_contract_create"),
                    Some(&json!({
                        "project_id": project_id,
                        "task_id": task_id,
                        "write_id": Uuid::now_v7(),
                        "title": format!("{} production adapter current_state smoke", host.as_str()),
                        "acceptance_items": [
                            {
                                "item_id": "headless_transport",
                                "description": "official headless provider invokes exactly one Governor MCP server",
                                "required_evidence": "observation"
                            },
                            {
                                "item_id": "current_state",
                                "description": "provider returns the canonical bound project/task revision",
                                "required_evidence": "verification"
                            }
                        ]
                    })),
                    "task_contract_create",
                ),
            )
            .await?;
        anyhow::ensure!(
            task_create
                .tool_call
                .as_ref()
                .is_some_and(|value| value.get("task_contract").is_some()),
            "smoke task contract was not created canonically"
        );
        let session_id = SessionId::new_v7();
        let mut scope = trace
            .run(
                "ul_auditor_scope",
                prepare_ul_auditor_scope(
                    config_path,
                    host,
                    project_id,
                    task_id,
                    session_id,
                    &smoke_id,
                ),
            )
            .await?;
        let work_item_id = WorkItemId::new_v7();
        scope.work_item_id = Some(work_item_id);
        scope.planned_verifier_ref = Some(format!("external-agent-smoke-verifier:{smoke_id}"));

        let preflight = trace
            .run(
                "current_state_preflight",
                mcp_reference_exchange(
                    config_path,
                    if host == AgentHostId::OpenCode {
                        Some("default")
                    } else {
                        Some("external_auditor")
                    },
                    Some(host),
                    Some(&scope),
                    Some("eliot_current_state"),
                    Some(&json!({"scope": "memory_free_control"})),
                    "current_state_preflight",
                ),
            )
            .await?;
        anyhow::ensure!(
            preflight
                .tool_names
                .iter()
                .any(|name| name == "eliot_current_state"),
            "zero-model preflight did not expose eliot_current_state"
        );
        let current_state = preflight
            .tool_call
            .as_ref()
            .context("zero-model current_state preflight returned no structured content")?;
        let memory_revision = current_state
            .get("memory_revision")
            .or_else(|| current_state.get("revision"))
            .and_then(Value::as_u64)
            .context("zero-model current_state returned no memory revision")?;
        Ok(McpSmokePreparation {
            smoke_id,
            smoke_root,
            workspace,
            project_id,
            task_id,
            scope,
            work_item_id,
            memory_revision,
            preflight,
            trace: trace.clone(),
        })
    };
    let Ok(result) = tokio::time::timeout(MCP_SMOKE_PRE_PROVIDER_TIMEOUT, preparation).await else {
        trace.abort_active("whole pre-provider deadline exceeded")?;
        anyhow::bail!(
            "MCP smoke pre-provider preparation exceeded {} seconds; phase journal={}",
            MCP_SMOKE_PRE_PROVIDER_TIMEOUT.as_secs(),
            trace.path().display()
        )
    };
    result
}

async fn run_mcp_preflight(config_path: &Path, host: AgentHostId, model: &str) -> Result<Value> {
    let preparation = prepare_mcp_smoke(config_path, host, model).await?;
    let report = json!({
        "schema_version": "eliot-external-agent-mcp-preflight-v1",
        "status": "passed",
        "smoke_id": preparation.smoke_id,
        "host": host,
        "model": model,
        "project_id": preparation.project_id,
        "task_id": preparation.task_id,
        "memory_revision": preparation.memory_revision,
        "tool_names": preparation.preflight.tool_names,
        "raw_database_absent": preparation.preflight.raw_database_absent,
        "phase_journal_ref": path_string(preparation.trace.path()),
        "provider_calls": 0,
        "gui_used": false,
    });
    let report_path = runtime_root(config_path)
        .join("reports")
        .join("external-agent-smokes")
        .join(format!("{}-preflight-latest.json", host.as_str()));
    atomic_write_json(&report_path, &report)?;
    atomic_write_json(
        &preparation.smoke_root.join("preflight-report.json"),
        &report,
    )?;
    Ok(report)
}

fn mcp_smoke_prompt(model: &str) -> String {
    format!(
        "Use the configured ELIOT MCP server. Call eliot_current_state exactly once with the sole argument {{\"scope\":\"memory_free_control\"}}; do not pass project_id or task_id because the Governor binds them. Return one plain JSON object, without Markdown fences or prose, containing only the schema-bound project_id, task_id, memory_revision and resolved_model={model}. Do not edit files."
    )
}

fn memory_revision_within_execution_window(
    preflight_revision: u64,
    observed_revision: u64,
    postflight_revision: u64,
) -> bool {
    observed_revision >= preflight_revision && observed_revision <= postflight_revision
}

#[allow(clippy::too_many_lines)]
async fn run_mcp_smoke(config_path: &Path, host: AgentHostId, model: &str) -> Result<Value> {
    let McpSmokePreparation {
        smoke_id,
        smoke_root,
        workspace,
        project_id,
        task_id,
        scope,
        work_item_id,
        memory_revision,
        preflight,
        trace,
    } = prepare_mcp_smoke(config_path, host, model).await?;

    let (_schema, prompt, prompt_path, schema_path) = trace.run_sync("prompt_build", || {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["project_id", "task_id", "memory_revision", "resolved_model"],
            "properties": {
                "project_id": {"const": project_id.to_string()},
                "task_id": {"const": task_id.to_string()},
                "memory_revision": {
                    "type": "integer",
                    "minimum": memory_revision
                },
                "resolved_model": {"const": model}
            }
        });
        let prompt = mcp_smoke_prompt(model);
        let prompt_path = smoke_root.join("prompt.txt");
        let schema_path = smoke_root.join("schema.json");
        atomic_write_bytes(&prompt_path, prompt.as_bytes())?;
        atomic_write_json(&schema_path, &schema)?;
        Ok((schema, prompt, prompt_path, schema_path))
    })?;
    let (agent_session_id, adapter_request) = trace.run_sync("launch_contract", || {
        let agent_session_id = scope
            .agent_session_id
            .context("smoke scope has no AgentSession")?;
        let role_lease_id = scope
            .role_lease_id
            .clone()
            .context("smoke scope has no TaskRoleLease")?;
        let mut launch_contract = eliot_types::HostLaunchContract {
            invocation_id: smoke_id.clone(),
            host_profile_ref: format!("external-agent-adapter:{}", host.as_str()),
            mode: HostMode::Supervised,
            project_id: Some(project_id),
            agent_session_id: Some(agent_session_id),
            task_id: Some(task_id),
            work_item_id: Some(work_item_id),
            role_lease_id: Some(role_lease_id.clone()),
            work_lease_id: None,
            worktree_lease_id: None,
            planned_verifier_ref: scope.planned_verifier_ref.clone(),
            cwd_or_worktree: path_string(&workspace),
            baseline_commit: None,
            allowed_paths: Vec::new(),
            forbidden_paths: vec![
                "truth-promotion".to_owned(),
                "raw-database".to_owned(),
                "provider-credential-roots".to_owned(),
            ],
            integration_bundle_ref: path_string(&smoke_root),
            mcp_config_ref: path_string(&smoke_root.join("provider-mcp.json")),
            skill_bundle_ref: path_string(&smoke_root.join("skills")),
            lifecycle_bridge_ref: "external-agent-adapter".to_owned(),
            environment_allowlist: SAFE_INHERITED_ENVIRONMENT
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            permission_profile: "external_auditor".to_owned(),
            model_route_if_selected: Some(model.to_owned()),
            max_turns_or_steps: Some(4),
            wall_clock_budget_seconds: 120,
            cost_budget_if_supported: None,
            session_id: None,
            resume_policy: "fresh_only".to_owned(),
            structured_output_schema_ref: Some(path_string(&schema_path)),
            stdout_stderr_spool: path_string(&smoke_root.join("spool")),
            artifact_manifest_ref: path_string(&smoke_root.join("artifacts.json")),
            idempotency_key: format!("external-agent-smoke:{smoke_id}"),
            expected_result_kind: "provider_execution_evidence".to_owned(),
            contract_hash: String::new(),
        };
        launch_contract.contract_hash = blake3::hash(&serde_json::to_vec(&launch_contract)?)
            .to_hex()
            .to_string();
        let invocation = eliot_types::AgentInvocationRequest {
            invocation_id: smoke_id.clone(),
            project_id,
            task_id,
            work_item_id,
            requested_capabilities: vec![
                "emit_candidate_observation".to_owned(),
                "request_controller_review".to_owned(),
            ],
            role_lease_id,
            work_lease_id: None,
            packet_refs: Vec::new(),
            expected_result_kind: "provider_execution_evidence".to_owned(),
            verifier_ref: format!("external-agent-smoke-verifier:{smoke_id}"),
            idempotency_key: format!("external-agent-smoke:{smoke_id}"),
        };
        let execution = ExternalAgentExecutionRequest {
            invocation,
            launch_contract,
            purpose: ExternalAgentPurpose::UnderstandingReader,
            prompt_ref: path_string(&prompt_path),
            prompt_sha256: sha256_bytes(prompt.as_bytes()),
            output_schema_ref: path_string(&schema_path),
            output_schema_sha256: sha256_bytes(&std::fs::read(&schema_path)?),
            requested_model: model.to_owned(),
            max_turns_or_steps: 4,
            timeout_profile_ref: format!("provider-timeout:{}-smoke-120s", host.as_str()),
            allowed_provider_tools: provider_allowed_tools(host),
            denied_provider_tools: vec![
                "Bash".to_owned(),
                "Edit".to_owned(),
                "Write".to_owned(),
                "NotebookEdit".to_owned(),
                "WebFetch".to_owned(),
                "WebSearch".to_owned(),
            ],
            expected_mcp_tool_names: vec!["eliot_current_state".to_owned()],
            forbidden_mcp_server_names: vec!["eliot_surrealdb".to_owned(), "surrealdb".to_owned()],
            read_only: true,
            candidate_only: true,
        };
        let adapter_request = AdapterRequest {
            request_id: format!("adapter-request:{smoke_id}"),
            adapter_id: adapter_id(host).to_owned(),
            requested_capability: AdapterCapability::EmitCandidateObservation,
            context: eliot_types::AdapterContext {
                project_id,
                task_id,
                session_id: Some(agent_session_id),
                trace_id: format!("external-agent-smoke:{smoke_id}"),
                created_at: OffsetDateTime::now_utc(),
            },
            input: serde_json::to_value(execution)?,
        };
        Ok((agent_session_id, adapter_request))
    })?;
    let supervisor = production_external_agent_supervisor(config_path)?;
    let result = trace
        .run("provider_dispatch", async {
            supervisor
                .execute(adapter_id(host), adapter_request, None)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))
        })
        .await?;
    let postflight = trace
        .run(
            "current_state_postflight",
            mcp_reference_exchange(
                config_path,
                if host == AgentHostId::OpenCode {
                    Some("default")
                } else {
                    Some("external_auditor")
                },
                Some(host),
                Some(&scope),
                Some("eliot_current_state"),
                Some(&json!({"scope": "memory_free_control"})),
                "current_state_postflight",
            ),
        )
        .await?;
    let postflight_memory_revision = postflight
        .tool_call
        .as_ref()
        .and_then(|value| {
            value
                .get("memory_revision")
                .or_else(|| value.get("revision"))
        })
        .and_then(Value::as_u64)
        .context("zero-model current_state postflight returned no memory revision")?;
    trace.run_sync("provider_result_validation", || {
        let evidence = result
            .output
            .get("provider_execution_evidence")
            .with_context(|| {
                format!(
                    "adapter smoke returned no ProviderExecutionEvidence; status={:?}; error={:?}; output={}",
                    result.status, result.error, result.output
                )
            })?;
        let structured = evidence
            .get("structured_output")
            .context("adapter smoke returned no structured output")?;
        let observed_tool_names = evidence
            .get("observed_mcp_tool_names")
            .and_then(Value::as_array)
            .context("adapter smoke returned no observed MCP tool-name array")?;
        let observed_current_state = observed_tool_names.iter().any(|name| {
            name.as_str().is_some_and(|name| {
                name == "eliot_current_state"
                    || name == "eliot-governor_eliot_current_state"
                    || name.ends_with("__eliot_current_state")
                    || name.ends_with("/eliot_current_state")
            })
        });
        let observed_memory_revision = structured
            .get("memory_revision")
            .and_then(Value::as_u64)
            .context("adapter smoke returned no unsigned memory_revision")?;
        anyhow::ensure!(
            result.status == AdapterResultStatus::Succeeded
                && observed_current_state
                && structured.get("project_id").and_then(Value::as_str)
                == Some(project_id.to_string().as_str())
                && structured.get("task_id").and_then(Value::as_str)
                    == Some(task_id.to_string().as_str())
                && memory_revision_within_execution_window(
                    memory_revision,
                    observed_memory_revision,
                    postflight_memory_revision,
                )
                && structured.get("resolved_model").and_then(Value::as_str) == Some(model),
            "{} adapter smoke returned a noncanonical result: {}",
            host.as_str(),
            result.output
        );
        Ok(())
    })?;
    let report = json!({
        "schema_version": "eliot-external-agent-mcp-smoke-v1",
        "status": "passed",
        "smoke_id": smoke_id,
        "host": host,
        "model": model,
        "project_id": project_id,
        "task_id": task_id,
        "agent_session_id": agent_session_id,
        "zero_model_preflight": {
            "tool_names": preflight.tool_names,
            "raw_database_absent": preflight.raw_database_absent,
            "memory_revision": memory_revision,
        },
        "zero_model_postflight": {
            "tool_names": postflight.tool_names,
            "raw_database_absent": postflight.raw_database_absent,
            "memory_revision": postflight_memory_revision,
        },
        "phase_journal_ref": path_string(trace.path()),
        "adapter_result": result,
        "provider_calls": 1,
        "gui_used": false,
    });
    let report_path = runtime_root(config_path)
        .join("reports")
        .join("external-agent-smokes")
        .join(format!("{}-latest.json", host.as_str()));
    atomic_write_json(&report_path, &report)?;
    atomic_write_json(&smoke_root.join("smoke-report.json"), &report)?;
    Ok(report)
}

fn provider_allowed_tools(host: AgentHostId) -> Vec<String> {
    match host {
        AgentHostId::Claude => vec![
            "mcp__eliot-governor__eliot_current_state".to_owned(),
            "mcp__eliot_governor__eliot_current_state".to_owned(),
        ],
        AgentHostId::Antigravity | AgentHostId::OpenCode => {
            vec!["eliot_current_state".to_owned()]
        }
        AgentHostId::Codex => Vec::new(),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded diagnostic keeps command, process, parse, and receipt evidence together"
)]
async fn run_auth_smoke(config_path: &Path, host: AgentHostId, model: &str) -> Result<Value> {
    anyhow::ensure!(
        host != AgentHostId::Codex,
        "Codex is not an external adapter"
    );
    anyhow::ensure!(
        !model.trim().is_empty(),
        "auth-smoke requires an exact non-empty model"
    );
    let governor = std::env::current_exe()?.canonicalize()?;
    let core = ExternalAgentAdapterCore::new(host, config_path, &governor)?;
    let executable = core
        .executable
        .context("headless provider executable is not installed")?;
    let auth_id = format!("external-agent-auth-{}-{}", host.as_str(), Uuid::now_v7());
    let root = runtime_root(config_path)
        .join("external-agent-auth-smokes")
        .join(&auth_id);
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace)?;
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["status", "resolved_model"],
        "properties": {
            "status": {"const": "ready"},
            "resolved_model": {"const": model}
        }
    });
    let prompt = format!(
        "Return only the schema-bound status=ready and resolved_model={model}. Do not use tools, inspect files, or edit anything."
    );
    let mode = ProviderStructuredOutputMode::NativeJsonSchema;
    let plan = match host {
        AgentHostId::Claude => ProviderCommandPlan {
            argv: vec![
                "-p".to_owned(),
                "--model".to_owned(),
                model.to_owned(),
                "--output-format".to_owned(),
                "stream-json".to_owned(),
                "--verbose".to_owned(),
                "--json-schema".to_owned(),
                serde_json::to_string(&schema)?,
                "--disallowedTools".to_owned(),
                "Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch".to_owned(),
                "--max-turns".to_owned(),
                "1".to_owned(),
                "--no-session-persistence".to_owned(),
                "--".to_owned(),
                prompt.clone(),
            ],
            nonsecret_environment: BTreeMap::new(),
            structured_output_mode: mode,
            model_selection_mechanism: "cli_flag:--model".to_owned(),
        },
        AgentHostId::Antigravity => build_antigravity_command(&AntigravityCommandInput {
            requested_model: model.to_owned(),
            workspace: path_string(&workspace),
            output_schema: schema.clone(),
            max_runtime_seconds: 120,
            prompt: prompt.clone(),
            native_json_schema: true,
            read_only: true,
        })?,
        AgentHostId::OpenCode => build_opencode_command(&OpenCodeCommandInput {
            requested_model: model.to_owned(),
            workspace: path_string(&workspace),
            prompt: prompt.clone(),
            read_only: true,
        })?,
        AgentHostId::Codex => unreachable!(),
    };
    let mut environment = BTreeMap::new();
    for name in SAFE_INHERITED_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            environment.insert((*name).to_owned(), value.to_string_lossy().into_owned());
        }
    }
    environment.extend(plan.nonsecret_environment.clone());
    if host == AgentHostId::OpenCode {
        let config_dir = root.join("opencode-config");
        let xdg = root.join("opencode-xdg");
        std::fs::create_dir_all(&config_dir)?;
        std::fs::create_dir_all(&xdg)?;
        atomic_write_json(
            &config_dir.join("opencode.json"),
            &json!({"$schema": "https://opencode.ai/config.json", "mcp": {}}),
        )?;
        environment.insert("OPENCODE_CONFIG_DIR".to_owned(), path_string(&config_dir));
        environment.insert("XDG_CONFIG_HOME".to_owned(), path_string(&xdg));
    }
    let mut command = Command::new(&executable);
    command
        .args(&plan.argv)
        .current_dir(&workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (name, value) in &environment {
        command.env(name, value);
    }
    let output = run_external_agent_process(
        command,
        Duration::from_secs(120),
        Duration::from_secs(PROVIDER_CLEANUP_GRACE_SECONDS),
        |_| Ok(()),
    )
    .await?;
    anyhow::ensure!(
        output.exit_code == Some(0) && !output.timed_out,
        "{}; login command: {}",
        provider_failure_message(&output),
        provider_login_command(host)
    );
    let parsed = parse_terminal(
        host,
        &output.stdout,
        model,
        &schema,
        plan.structured_output_mode,
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let report = json!({
        "schema_version": "eliot-external-agent-auth-smoke-v1",
        "status": "passed",
        "auth_smoke_id": auth_id,
        "host": host,
        "requested_model": model,
        "resolved_model": parsed.resolved_model,
        "provider_session_id": parsed.provider_session_id,
        "provider_authenticated": true,
        "mcp_enabled": false,
        "provider_calls": 1,
        "stdout_sha256": sha256_bytes(&output.stdout),
        "stderr_sha256": sha256_bytes(&output.stderr),
        "process_tree_terminated": output.process_tree_terminated,
        "gui_used": false,
    });
    let report_path = runtime_root(config_path)
        .join("reports")
        .join("external-agent-auth-smokes")
        .join(format!("{}-latest.json", host.as_str()));
    atomic_write_json(&report_path, &report)?;
    Ok(report)
}

fn provider_login_command(host: AgentHostId) -> &'static str {
    match host {
        AgentHostId::Claude => "claude auth login",
        AgentHostId::Antigravity => "agy <official onboarding command shown by local help>",
        AgentHostId::OpenCode => "opencode auth login",
        AgentHostId::Codex => "unsupported",
    }
}

impl ClaudeCodeCliAdapter {
    fn new(config_path: &Path, governor_executable: &Path) -> Result<Self> {
        Ok(Self {
            core: ExternalAgentAdapterCore::new(
                AgentHostId::Claude,
                config_path,
                governor_executable,
            )?,
        })
    }
}

impl AntigravityCliAdapter {
    fn new(config_path: &Path, governor_executable: &Path) -> Result<Self> {
        Ok(Self {
            core: ExternalAgentAdapterCore::new(
                AgentHostId::Antigravity,
                config_path,
                governor_executable,
            )?,
        })
    }
}

impl OpenCodeCliAdapter {
    fn new(config_path: &Path, governor_executable: &Path) -> Result<Self> {
        Ok(Self {
            core: ExternalAgentAdapterCore::new(
                AgentHostId::OpenCode,
                config_path,
                governor_executable,
            )?,
        })
    }
}

macro_rules! impl_external_adapter {
    ($adapter:ty) => {
        impl Adapter for $adapter {
            fn id(&self) -> &str {
                &self.core.adapter_id
            }

            fn manifest(&self) -> &eliot_types::CapabilityManifest {
                &self.core.manifest
            }

            fn health(&self) -> BoxAdapterFuture<'_, AdapterHealth> {
                self.core.health()
            }

            fn execute(&self, request: AdapterRequest) -> BoxAdapterFuture<'_, AdapterResult> {
                self.core.execute(request)
            }

            fn shutdown(&self) -> BoxAdapterFuture<'_, ()> {
                Box::pin(async { Ok(()) })
            }
        }
    };
}

impl_external_adapter!(ClaudeCodeCliAdapter);
impl_external_adapter!(AntigravityCliAdapter);
impl_external_adapter!(OpenCodeCliAdapter);

impl ExternalAgentAdapterCore {
    fn new(host: AgentHostId, config_path: &Path, governor_executable: &Path) -> Result<Self> {
        let executable = discover_provider_binary(host)?;
        let version = executable
            .as_deref()
            .map(provider_version)
            .transpose()?
            .filter(|value| !value.trim().is_empty());
        let adapter_id = adapter_id(host).to_owned();
        let manifest = provider_manifest(host, &adapter_id, executable.as_deref());
        Ok(Self {
            host,
            adapter_id,
            executable,
            version,
            governor_executable: governor_executable.to_path_buf(),
            config_path: config_path.to_path_buf(),
            manifest,
        })
    }

    fn health(&self) -> BoxAdapterFuture<'_, AdapterHealth> {
        Box::pin(async move {
            let installed = self.executable.as_deref().is_some_and(Path::is_file)
                && self
                    .version
                    .as_deref()
                    .is_some_and(|value| !value.is_empty());
            Ok(AdapterHealth {
                adapter_id: self.adapter_id.clone(),
                name: self.manifest.name.clone(),
                state: if installed {
                    AdapterState::Healthy
                } else {
                    AdapterState::Unavailable
                },
                healthy: installed,
                message: if installed {
                    format!(
                        "headless executable installed; authentication requires a live smoke ({})",
                        self.version.as_deref().unwrap_or_default()
                    )
                } else {
                    "headless provider executable not found".to_owned()
                },
                consecutive_failures: 0,
                circuit_open: false,
                checked_at: OffsetDateTime::now_utc(),
            })
        })
    }

    fn execute(&self, request: AdapterRequest) -> BoxAdapterFuture<'_, AdapterResult> {
        Box::pin(async move {
            let execution: ExternalAgentExecutionRequest =
                serde_json::from_value(request.input.clone())?;
            validate_external_agent_execution_request(&execution)?;
            if request.context.project_id != execution.invocation.project_id
                || request.context.task_id != execution.invocation.task_id
                || request.context.session_id != execution.launch_contract.agent_session_id
            {
                return Err(eliot_engine::EngineError::WriteRejected(
                    "AdapterContext differs from sealed external-agent authority".to_owned(),
                ));
            }
            self.execute_governed(request, execution).await
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_governed(
        &self,
        request: AdapterRequest,
        execution: ExternalAgentExecutionRequest,
    ) -> Result<AdapterResult, eliot_engine::EngineError> {
        let PreparedExternalAgentExecution {
            executable,
            provider_hash_before,
            schema,
            cwd,
            plan,
            environment,
            runtime_contract,
        } = self.prepare_governed(&execution)?;

        let runtime_root = runtime_root(&self.config_path);
        let attempt_id = format!(
            "external-agent-attempt-{}",
            execution.invocation.invocation_id
        );
        let journal = ProviderInvocationJournal::new(&runtime_root);
        let payload_hash = sha256_bytes(&serde_json::to_vec(&execution)?);
        let execution_request_path =
            persist_external_execution_request(&runtime_root, &execution, &payload_hash)?;
        let mut attempt = journal.create(ProviderInvocationAttempt {
            invocation_attempt_id: attempt_id.clone(),
            provider: self.host.as_str().to_owned(),
            campaign_id: provider_campaign_id(&execution),
            preregistration_id: execution.invocation.verifier_ref.clone(),
            reservation_id: "pending".to_owned(),
            idempotency_key: execution.invocation.idempotency_key.clone(),
            external_invocation_ref: None,
            frozen_input_hash: payload_hash.clone(),
            request_payload_hash: payload_hash,
            route_or_model: Some(execution.requested_model.clone()),
            adapter_version: Some(EXTERNAL_ADAPTER_VERSION.to_owned()),
            executable_or_transport: Some(path_string(&executable)),
            cwd: Some(path_string(&cwd)),
            environment_fingerprint: Some(sha256_bytes(&serde_json::to_vec(&environment)?)),
            timeout_profile_id: execution.timeout_profile_ref.clone(),
            state_transitions: Vec::new(),
            dispatch_started_at: None,
            process_started_at: None,
            provider_ack_at: None,
            first_output_at: None,
            last_output_at: None,
            process_exit_at: None,
            cleanup_completed_at: None,
            stdout_blob_or_hash: None,
            stderr_blob_or_hash: None,
            structured_output_blob_or_hash: None,
            exit_code_or_signal: None,
            process_or_job_identity: None,
            quota_or_cost_if_known: None,
            original_closeout_ref: Some(path_string(&execution_request_path)),
        })?;

        let reservation_owner = ProviderCallReservationOwner::new(&runtime_root);
        let reservation = match reservation_owner.reserve(ProviderCallReservationRequest {
            campaign_id: provider_campaign_id(&execution),
            task_id: execution.invocation.task_id,
            provider: self.host.as_str().to_owned(),
            idempotency_key: execution.invocation.idempotency_key.clone(),
            gate_decision_ref: execution.invocation.verifier_ref.clone(),
            max_calls: 16,
            campaign_closed: false,
        })? {
            ProviderCallReservationDecision::Reserved(reservation) => reservation,
            ProviderCallReservationDecision::IdempotentReplay(reservation) => {
                journal.transition(
                    &mut attempt,
                    ProviderInvocationState::PreDispatchAborted,
                    vec![format!(
                        "idempotent_replay_redispatch_forbidden:{}",
                        reservation.reservation_id
                    )],
                )?;
                return Err(eliot_engine::EngineError::WriteRejected(
                    "idempotent replay requires canonical-result inspection; redispatch is forbidden"
                        .to_owned(),
                ));
            }
            ProviderCallReservationDecision::BudgetExceeded => {
                journal.transition(
                    &mut attempt,
                    ProviderInvocationState::PreDispatchAborted,
                    vec!["provider_call_budget_exceeded".to_owned()],
                )?;
                return Err(eliot_engine::EngineError::WriteRejected(
                    "provider call budget exceeded".to_owned(),
                ));
            }
            ProviderCallReservationDecision::CampaignClosed => {
                journal.transition(
                    &mut attempt,
                    ProviderInvocationState::PreDispatchAborted,
                    vec!["provider_campaign_closed".to_owned()],
                )?;
                return Err(eliot_engine::EngineError::WriteRejected(
                    "provider campaign is closed".to_owned(),
                ));
            }
        };
        attempt.reservation_id = reservation.reservation_id.clone();
        journal.persist(&attempt)?;
        journal.transition(
            &mut attempt,
            ProviderInvocationState::Reserved,
            vec![format!(
                "provider-call-reservation:{}",
                reservation.reservation_id
            )],
        )?;

        let broker_job_id = match enqueue_external_agent_broker_invocation(
            &self.config_path,
            self.host,
            &execution,
        )
        .await
        {
            Ok(job_id) => job_id,
            Err(error) => {
                let _ = reservation_owner.release_pre_dispatch(
                    &reservation.reservation_id,
                    "HostBroker admission failed before provider dispatch",
                );
                let _ = journal.transition(
                    &mut attempt,
                    ProviderInvocationState::PreDispatchAborted,
                    vec![format!("host_broker_admission_failed:{error}")],
                );
                return Err(error);
            }
        };
        if let Err(error) = start_external_agent_broker_job(&self.config_path, &broker_job_id).await
        {
            let _ = reservation_owner.release_pre_dispatch(
                &reservation.reservation_id,
                "HostBroker failed before provider dispatch",
            );
            let _ = journal.transition(
                &mut attempt,
                ProviderInvocationState::PreDispatchAborted,
                vec![format!("host_broker_start_failed:{error}")],
            );
            return Err(error);
        }
        let worktree_before = worktree_snapshot_if_git(&cwd)?;
        let mut command = Command::new(&executable);
        command
            .args(&plan.argv)
            .current_dir(&cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();
        for (name, value) in &environment {
            command.env(name, value);
        }
        reservation_owner.mark_dispatching(&reservation.reservation_id)?;
        journal.transition(
            &mut attempt,
            ProviderInvocationState::DispatchStarting,
            vec![runtime_contract.runtime_contract_sha256.clone()],
        )?;
        let absolute_timeout =
            Duration::from_secs(execution.launch_contract.wall_clock_budget_seconds.max(1));
        let process = run_external_agent_process(
            command,
            absolute_timeout,
            Duration::from_secs(PROVIDER_CLEANUP_GRACE_SECONDS),
            |pid| {
                reservation_owner
                    .mark_dispatched(&reservation.reservation_id, &attempt_id)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                let now = OffsetDateTime::now_utc();
                attempt.dispatch_started_at = Some(now);
                attempt.process_started_at = Some(now);
                attempt.external_invocation_ref = Some(attempt_id.clone());
                attempt.process_or_job_identity = Some(format!("pid:{pid}"));
                journal
                    .transition(
                        &mut attempt,
                        ProviderInvocationState::Dispatched,
                        vec![format!("pid:{pid}")],
                    )
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                journal
                    .transition(
                        &mut attempt,
                        ProviderInvocationState::Running,
                        vec![format!("pid:{pid}")],
                    )
                    .map_err(|error| anyhow::anyhow!(error.to_string()))
            },
        )
        .await;
        let process = match process {
            Ok(process) => process,
            Err(error) => {
                let state = attempt
                    .state_transitions
                    .last()
                    .map(|transition| transition.to);
                if state == Some(ProviderInvocationState::DispatchStarting) {
                    let _ = reservation_owner.release_pre_dispatch(
                        &reservation.reservation_id,
                        "managed process spawn failed before provider dispatch",
                    );
                    let _ = journal.transition(
                        &mut attempt,
                        ProviderInvocationState::PreDispatchAborted,
                        vec![error.to_string()],
                    );
                } else {
                    let _ = reservation_owner.mark_unknown_outcome(
                        &reservation.reservation_id,
                        "managed process failed after dispatch",
                    );
                }
                return Err(eliot_engine::EngineError::WriteRejected(format!(
                    "managed provider process failed: {error}"
                )));
            }
        };
        attempt.process_exit_at = Some(OffsetDateTime::now_utc());
        attempt.cleanup_completed_at = Some(OffsetDateTime::now_utc());
        attempt.exit_code_or_signal = process.exit_code.map(|code| code.to_string());
        attempt.process_or_job_identity = Some(format!(
            "pid:{};terminated={};observed={}",
            process.root_pid,
            process.process_tree_terminated,
            process.observed_processes.join("|")
        ));

        let stdout_capture = ProviderOutputSpool.capture(
            &runtime_root,
            &attempt_id,
            "stdout",
            process.stdout.as_slice(),
            MAX_PROVIDER_OUTPUT_BYTES,
        )?;
        let stderr_capture = ProviderOutputSpool.capture(
            &runtime_root,
            &attempt_id,
            "stderr",
            process.stderr.as_slice(),
            MAX_PROVIDER_OUTPUT_BYTES,
        )?;
        attempt.stdout_blob_or_hash = Some(stdout_capture.blob_ref.clone());
        attempt.stderr_blob_or_hash = Some(stderr_capture.blob_ref.clone());
        if stdout_capture.output_observed {
            attempt.first_output_at = Some(OffsetDateTime::now_utc());
            attempt.last_output_at = attempt.first_output_at;
            journal.transition(
                &mut attempt,
                ProviderInvocationState::OutputObserved,
                vec![stdout_capture.blob_ref.relative_path.clone()],
            )?;
        }
        let worktree_after = worktree_snapshot_if_git(&cwd)?;
        let read_only_mutation = execution.read_only && worktree_before != worktree_after;

        if process.timed_out {
            journal.transition(
                &mut attempt,
                ProviderInvocationState::TimeoutPendingReconciliation,
                vec![stdout_capture.blob_ref.relative_path.clone()],
            )?;
            reservation_owner.mark_unknown_outcome(
                &reservation.reservation_id,
                "provider absolute runtime timeout requires reconciliation",
            )?;
            journal.transition(
                &mut attempt,
                ProviderInvocationState::NonReconcilableUnknown,
                vec!["no provider status lookup is admitted".to_owned()],
            )?;
            return self
                .terminal_result(
                    &request,
                    &execution,
                    &runtime_contract,
                    &process,
                    &stdout_capture,
                    &stderr_capture,
                    None,
                    None,
                    AgentResultStatus::UnknownOutcome,
                    AdapterResultStatus::Timeout,
                    true,
                    Some("provider timed out; outcome is fail-closed and non-retryable".to_owned()),
                )
                .await;
        }
        if process.exit_code != Some(0) || read_only_mutation {
            journal.transition(
                &mut attempt,
                ProviderInvocationState::ProcessExitedNonzero,
                vec![format!(
                    "exit={:?};read_only_mutation={read_only_mutation}",
                    process.exit_code
                )],
            )?;
            reservation_owner.fail_after_dispatch(
                &reservation.reservation_id,
                if read_only_mutation {
                    "read-only provider changed the governed workspace"
                } else {
                    "provider process exited nonzero"
                },
            )?;
            return self
                .terminal_result(
                    &request,
                    &execution,
                    &runtime_contract,
                    &process,
                    &stdout_capture,
                    &stderr_capture,
                    None,
                    None,
                    AgentResultStatus::Failed,
                    AdapterResultStatus::Failed,
                    false,
                    Some(if read_only_mutation {
                        "read-only provider changed the governed workspace".to_owned()
                    } else {
                        provider_failure_message(&process)
                    }),
                )
                .await;
        }

        let parsed = parse_terminal(
            self.host,
            &process.stdout,
            &execution.requested_model,
            &schema,
            plan.structured_output_mode,
        );
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                journal.transition(
                    &mut attempt,
                    ProviderInvocationState::ProtocolParseFailed,
                    vec![stdout_capture.blob_ref.relative_path.clone()],
                )?;
                reservation_owner.fail_after_dispatch(
                    &reservation.reservation_id,
                    "provider terminal output rejected",
                )?;
                return self
                    .terminal_result(
                        &request,
                        &execution,
                        &runtime_contract,
                        &process,
                        &stdout_capture,
                        &stderr_capture,
                        None,
                        None,
                        AgentResultStatus::Failed,
                        AdapterResultStatus::Failed,
                        false,
                        Some(error.to_string()),
                    )
                    .await;
            }
        };
        let structured_bytes = serde_json::to_vec(&parsed.structured_output)?;
        let structured_capture = ProviderOutputSpool.capture(
            &runtime_root,
            &attempt_id,
            "structured",
            structured_bytes.as_slice(),
            MAX_PROVIDER_OUTPUT_BYTES,
        )?;
        attempt.structured_output_blob_or_hash = Some(structured_capture.blob_ref.clone());
        attempt
            .quota_or_cost_if_known
            .clone_from(&parsed.token_or_cost_telemetry);
        let completeness = ExternalResultCompletenessService.evaluate(ProviderCompletenessInput {
            receipt_id: format!("provider-completeness:{attempt_id}"),
            invocation_attempt_ref: attempt_id.clone(),
            raw_output_ref: Some(stdout_capture.blob_ref.relative_path.clone()),
            expected_schema: execution.output_schema_sha256.clone(),
            terminal_marker_or_protocol_status: Some(parsed.terminal_status.clone()),
            required_fields_present: true,
            truncation_detected: false,
            stream_closed_cleanly: true,
            process_exit_success: true,
        });
        if !completeness.result_complete {
            return Err(eliot_engine::EngineError::WriteRejected(
                "provider completeness service rejected a parsed terminal result".to_owned(),
            ));
        }
        journal.transition(
            &mut attempt,
            ProviderInvocationState::CompletedCaptured,
            vec![structured_capture.blob_ref.relative_path.clone()],
        )?;
        let provider_hash_after = engine_anyhow(sha256_file(&executable))?;
        if provider_hash_after != provider_hash_before {
            let _ = journal.transition(
                &mut attempt,
                ProviderInvocationState::CleanupFailedAfterComplete,
                vec!["provider_executable_hash_changed".to_owned()],
            );
            let _ = reservation_owner.fail_after_dispatch(
                &reservation.reservation_id,
                "provider executable hash changed during execution",
            );
            return Err(eliot_engine::EngineError::WriteRejected(
                "provider executable hash changed during execution".to_owned(),
            ));
        }
        let mut result = self
            .terminal_result(
                &request,
                &execution,
                &runtime_contract,
                &process,
                &stdout_capture,
                &stderr_capture,
                Some(&structured_capture),
                Some(parsed),
                AgentResultStatus::Succeeded,
                AdapterResultStatus::Succeeded,
                false,
                None,
            )
            .await?;
        let review_ref = format!("provider-result:{}", result.result_id);
        let closeout = reservation_owner
            .complete(&reservation.reservation_id, &review_ref)
            .and_then(|_| {
                journal.transition(
                    &mut attempt,
                    ProviderInvocationState::ReviewNormalized,
                    vec![review_ref.clone()],
                )
            });
        if let Err(error) = closeout {
            let _ = journal.transition(
                &mut attempt,
                ProviderInvocationState::CleanupFailedAfterComplete,
                vec![format!("post_canonical_closeout_failed:{error}")],
            );
            result.status = AdapterResultStatus::Failed;
            result.error = Some(AdapterError {
                code: "adapter_closeout_failed".to_owned(),
                message: format!(
                    "provider result is canonical, but reservation/journal closeout failed: {error}"
                ),
                retryable: false,
            });
            if let Some(output) = result.output.as_object_mut() {
                output.insert(
                    "adapter_closeout".to_owned(),
                    json!({
                        "status": "cleanup_failed_after_complete",
                        "error": error.to_string(),
                    }),
                );
            }
        }
        Ok(result)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "runtime preview and dispatch must share one exact preparation boundary"
    )]
    fn prepare_governed(
        &self,
        execution: &ExternalAgentExecutionRequest,
    ) -> Result<PreparedExternalAgentExecution, eliot_engine::EngineError> {
        let executable = self.executable.as_deref().ok_or_else(|| {
            eliot_engine::EngineError::ServiceNotReady {
                service: self.adapter_id.clone(),
                reason: "headless provider executable is not installed".to_owned(),
            }
        })?;
        let executable = std::fs::canonicalize(executable)?;
        let provider_hash_before = engine_anyhow(sha256_file(&executable))?;
        let provider_version =
            self.version
                .clone()
                .ok_or_else(|| eliot_engine::EngineError::ServiceNotReady {
                    service: self.adapter_id.clone(),
                    reason: "provider version probe did not complete".to_owned(),
                })?;
        let prompt_path = canonical_bound_file(&execution.prompt_ref, "provider prompt")?;
        let schema_path =
            canonical_bound_file(&execution.output_schema_ref, "provider output schema")?;
        let prompt_bytes = std::fs::read(&prompt_path)?;
        let schema_bytes = std::fs::read(&schema_path)?;
        require_sha256(
            &prompt_bytes,
            &execution.prompt_sha256,
            "provider prompt SHA-256",
        )?;
        require_sha256(
            &schema_bytes,
            &execution.output_schema_sha256,
            "provider output schema SHA-256",
        )?;
        let prompt = String::from_utf8(prompt_bytes).map_err(|_| {
            eliot_engine::EngineError::WriteRejected(
                "provider prompt must be valid UTF-8".to_owned(),
            )
        })?;
        let schema: Value = serde_json::from_slice(&schema_bytes)?;
        if !schema.is_object() && !schema.is_boolean() {
            return Err(eliot_engine::EngineError::WriteRejected(
                "provider output schema root is invalid".to_owned(),
            ));
        }
        let cwd = std::fs::canonicalize(Path::new(&execution.launch_contract.cwd_or_worktree))?;
        let invocation_root = runtime_root(&self.config_path)
            .join("external-agent")
            .join(safe_component(&execution.invocation.invocation_id));
        std::fs::create_dir_all(&invocation_root)?;
        let mcp = materialize_provider_mcp(
            self.host,
            &self.governor_executable,
            &self.config_path,
            &cwd,
            &invocation_root,
            execution,
        )?;
        let plan = provider_command_plan(
            self.host,
            execution,
            &schema,
            &prompt,
            &mcp.provider_config_path,
            &cwd,
        )?;
        let environment = provider_environment(
            self.host,
            &plan,
            &self.config_path,
            &self.governor_executable,
            execution,
            &mcp,
        );
        let mut runtime_contract = ProviderRuntimeContract {
            schema_version: PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION.to_owned(),
            host: self.host,
            purpose: execution.purpose,
            provider_executable: path_string(&executable),
            provider_executable_sha256: provider_hash_before.clone(),
            provider_version,
            requested_model: execution.requested_model.clone(),
            model_selection_mechanism: plan.model_selection_mechanism.clone(),
            provider_cwd: path_string(&cwd),
            provider_argv: plan.argv.clone(),
            nonsecret_environment: environment.clone(),
            mcp_servers: vec![mcp.contract],
            expected_mcp_tool_names: execution.expected_mcp_tool_names.clone(),
            forbidden_mcp_server_names: execution.forbidden_mcp_server_names.clone(),
            allowed_provider_tools: execution.allowed_provider_tools.clone(),
            denied_provider_tools: execution.denied_provider_tools.clone(),
            permission_profile: execution.launch_contract.permission_profile.clone(),
            structured_output_mode: plan.structured_output_mode,
            output_schema_sha256: execution.output_schema_sha256.clone(),
            timeout_profile_ref: execution.timeout_profile_ref.clone(),
            process_containment: "windows-suspended-kill-on-close-job-object-v1".to_owned(),
            candidate_only: true,
            runtime_contract_sha256: String::new(),
        };
        seal_provider_runtime_contract(&mut runtime_contract)?;
        Ok(PreparedExternalAgentExecution {
            executable,
            provider_hash_before,
            schema,
            cwd,
            plan,
            environment,
            runtime_contract,
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(
        clippy::too_many_lines,
        reason = "terminal closeout assembles one canonical evidence and journal transaction"
    )]
    async fn terminal_result(
        &self,
        request: &AdapterRequest,
        execution: &ExternalAgentExecutionRequest,
        runtime_contract: &ProviderRuntimeContract,
        process: &ManagedExternalAgentOutput,
        stdout: &eliot_engine::ProviderOutputCapture,
        stderr: &eliot_engine::ProviderOutputCapture,
        structured: Option<&eliot_engine::ProviderOutputCapture>,
        parsed: Option<ProviderTerminalResult>,
        agent_status: AgentResultStatus,
        adapter_status: AdapterResultStatus,
        unknown_outcome: bool,
        error_message: Option<String>,
    ) -> Result<AdapterResult, eliot_engine::EngineError> {
        let structured_output = parsed
            .as_ref()
            .map(|parsed| parsed.structured_output.clone());
        let evidence = ProviderExecutionEvidence {
            runtime_contract_sha256: runtime_contract.runtime_contract_sha256.clone(),
            requested_model: execution.requested_model.clone(),
            resolved_model: parsed
                .as_ref()
                .map_or_else(String::new, |parsed| parsed.resolved_model.clone()),
            provider_session_id: parsed
                .as_ref()
                .map_or_else(String::new, |parsed| parsed.provider_session_id.clone()),
            exit_code: process.exit_code,
            terminal_status: parsed.as_ref().map_or_else(
                || {
                    if process.timed_out {
                        "timeout".to_owned()
                    } else {
                        "failed".to_owned()
                    }
                },
                |parsed| parsed.terminal_status.clone(),
            ),
            unknown_outcome,
            structured_output: structured_output.clone(),
            structured_output_ref: structured.map(|capture| capture.blob_ref.relative_path.clone()),
            structured_output_sha256: structured_output
                .as_ref()
                .map(serde_json::to_vec)
                .transpose()?
                .map(|bytes| sha256_bytes(&bytes)),
            stdout_ref: Some(stdout.blob_ref.relative_path.clone()),
            stdout_sha256: Some(sha256_bytes(&process.stdout)),
            stderr_ref: Some(stderr.blob_ref.relative_path.clone()),
            stderr_sha256: Some(sha256_bytes(&process.stderr)),
            observed_mcp_server_names: vec!["eliot-governor".to_owned()],
            observed_mcp_tool_names: parsed
                .as_ref()
                .map_or_else(Vec::new, |parsed| parsed.observed_tool_names.clone()),
            provider_tool_call_refs: parsed.as_ref().map_or_else(Vec::new, |parsed| {
                parsed
                    .observed_tool_names
                    .iter()
                    .map(|name| format!("provider-tool:{name}"))
                    .collect()
            }),
            changed_paths: Vec::new(),
            diff_ref: None,
            token_or_cost_telemetry: parsed
                .as_ref()
                .and_then(|parsed| parsed.token_or_cost_telemetry.clone()),
            duration_ms: process.duration_ms,
        };
        let agent_result = AgentResultEnvelope {
            result_id: deterministic_external_result_id(execution),
            invocation_id: execution.invocation.invocation_id.clone(),
            host_id: self.host,
            host_session_id: parsed
                .as_ref()
                .map(|parsed| parsed.provider_session_id.clone()),
            status: agent_status,
            summary: error_message
                .clone()
                .unwrap_or_else(|| "provider returned a schema-valid candidate result".to_owned()),
            artifact_refs: [
                evidence.stdout_ref.clone(),
                evidence.stderr_ref.clone(),
                evidence.diff_ref.clone(),
            ]
            .into_iter()
            .flatten()
            .collect(),
            evidence_refs: vec![
                format!(
                    "provider-runtime-contract:{}",
                    runtime_contract.runtime_contract_sha256
                ),
                format!("adapter-request:{}", request.request_id),
            ],
            verifier_refs: vec![execution.invocation.verifier_ref.clone()],
            candidate_only: true,
            exit_status: process.exit_code,
            token_or_cost_telemetry: evidence.token_or_cost_telemetry.clone(),
            unknown_outcome_evidence_refs: if unknown_outcome {
                vec![
                    evidence.stdout_ref.clone().unwrap_or_default(),
                    evidence.stderr_ref.clone().unwrap_or_default(),
                ]
            } else {
                Vec::new()
            },
            supersedes_result_id: None,
            provider_output_hash: evidence.structured_output_sha256.clone(),
            canonical_receipt: None,
        };
        let agent_result =
            canonicalize_external_agent_broker_result(&self.config_path, execution, agent_result)
                .await?;
        let output = json!({
            "agent_result": agent_result,
            "provider_execution_evidence": evidence,
            "provider_runtime_contract": runtime_contract,
        });
        let result_id = output
            .pointer("/agent_result/result_id")
            .and_then(Value::as_str)
            .unwrap_or("external-agent-result")
            .to_owned();
        let observation = AdapterObservation {
            observation_id: format!("external-agent-observation-{}", Uuid::new_v4()),
            adapter_id: self.adapter_id.clone(),
            result_id: result_id.clone(),
            project_id: request.context.project_id,
            task_id: request.context.task_id,
            summary: output
                .pointer("/agent_result/summary")
                .and_then(Value::as_str)
                .unwrap_or("external agent result")
                .to_owned(),
            payload: output.clone(),
            payload_ref: format!("external-agent-result:{result_id}"),
            raw_blob_ref: Some(stdout.blob_ref.clone()),
            taint: TaintClass::ExternalAgent,
            write_receipt: output
                .pointer("/agent_result/canonical_receipt")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            blackboard_item_id: None,
            mailbox_message_id: None,
            controller_review_required: true,
            generated_at: OffsetDateTime::now_utc(),
        };
        Ok(AdapterResult {
            result_id,
            request_id: request.request_id.clone(),
            adapter_id: self.adapter_id.clone(),
            status: adapter_status,
            output,
            output_blob: None,
            observations: vec![observation],
            error: error_message.map(|message| AdapterError {
                code: if unknown_outcome {
                    "provider_unknown_outcome".to_owned()
                } else {
                    "provider_execution_failed".to_owned()
                },
                message,
                retryable: false,
            }),
            duration_ms: process.duration_ms,
            trace_id: request.context.trace_id.clone(),
            created_at: OffsetDateTime::now_utc(),
        })
    }
}

fn deterministic_external_result_id(execution: &ExternalAgentExecutionRequest) -> String {
    deterministic_external_result_id_from_parts(
        &execution.invocation.invocation_id,
        &execution.invocation.idempotency_key,
    )
}

fn deterministic_external_result_id_from_parts(
    invocation_id: impl AsRef<str>,
    idempotency_key: impl AsRef<str>,
) -> String {
    let semantic_key = format!("{}\0{}", invocation_id.as_ref(), idempotency_key.as_ref());
    format!(
        "external-agent-result:{}",
        blake3::hash(semantic_key.as_bytes()).to_hex()
    )
}

fn canonical_agent_result_write(
    result: &AgentResultEnvelope,
) -> Result<CanonicalAgentResultWrite, eliot_engine::EngineError> {
    if result.canonical_receipt.is_some() {
        return Err(eliot_engine::EngineError::WriteRejected(
            "external AgentResultEnvelope must be unreceipted before canonical write".to_owned(),
        ));
    }
    Ok(CanonicalAgentResultWrite {
        key: format!("managed-provider-result:{}", result.result_id),
        receipt_kind: "agent_result",
        body: serde_json::to_value(result)?,
    })
}

fn existing_receipted_external_result(
    existing: Option<&AgentResultEnvelope>,
    unreceipted_result: &AgentResultEnvelope,
) -> Result<Option<AgentResultEnvelope>, eliot_engine::EngineError> {
    let Some(existing) = existing else {
        return Ok(None);
    };
    let mut existing_semantic = existing.clone();
    existing_semantic.canonical_receipt = None;
    if existing_semantic != *unreceipted_result {
        return Err(eliot_engine::EngineError::WriteRejected(
            "external result replay changed the AgentResultEnvelope".to_owned(),
        ));
    }
    Ok(existing
        .canonical_receipt
        .is_some()
        .then(|| existing.clone()))
}

fn persist_external_execution_request(
    root: &Path,
    execution: &ExternalAgentExecutionRequest,
    payload_hash: &str,
) -> Result<PathBuf, eliot_engine::EngineError> {
    let path = root
        .join("external-agent-requests")
        .join(format!("{payload_hash}.json"));
    engine_anyhow(atomic_write_json(&path, execution))?;
    Ok(path)
}

async fn enqueue_external_agent_broker_invocation(
    config_path: &Path,
    host: AgentHostId,
    execution: &ExternalAgentExecutionRequest,
) -> Result<String, eliot_engine::EngineError> {
    let root = runtime_root(config_path);
    let session_id = execution.launch_contract.agent_session_id.ok_or_else(|| {
        eliot_engine::EngineError::WriteRejected(
            "external invocation lacks governed AgentSession".to_owned(),
        )
    })?;
    let mut state = engine_anyhow(delegation_runtime::load_state(&root))?;
    let binding = state
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == session_id)
        .cloned()
        .ok_or_else(|| {
            eliot_engine::EngineError::WriteRejected(
                "external invocation has no exact AgentSessionHostBinding".to_owned(),
            )
        })?;
    if binding.host_identity.host_id != host {
        return Err(eliot_engine::EngineError::WriteRejected(
            "external invocation host differs from its session binding".to_owned(),
        ));
    }
    let profile = HostProfileService.connected(&binding);
    let work_lease_active = if let Some(work_lease_id) = execution.invocation.work_lease_id {
        let work_state = engine_anyhow(delegation_runtime::load_work_state(&root))?;
        work_state
            .leases
            .iter()
            .find(|lease| lease.work_lease_id == work_lease_id)
            .is_some_and(work_lease_is_active)
    } else {
        false
    };
    let job = HostBrokerService.enqueue(
        &mut state,
        &execution.invocation,
        &profile,
        work_lease_active,
    )?;
    super::managed::write_canonical_managed_invocation_request(
        config_path,
        &state,
        &execution.invocation,
    )
    .await
    .map_err(anyhow_engine)?;
    super::managed::write_canonical_managed_job(config_path, &state, &job)
        .await
        .map_err(anyhow_engine)?;
    engine_anyhow(delegation_runtime::save_host_broker_state(&root, &state))?;
    Ok(job.job_id)
}

async fn start_external_agent_broker_job(
    config_path: &Path,
    job_id: &str,
) -> Result<(), eliot_engine::EngineError> {
    let root = runtime_root(config_path);
    let mut state = engine_anyhow(delegation_runtime::load_state(&root))?;
    let job = state
        .operation_jobs
        .iter_mut()
        .find(|job| job.job_id == job_id)
        .ok_or_else(|| {
            eliot_engine::EngineError::WriteRejected(
                "external invocation OperationJob disappeared before dispatch".to_owned(),
            )
        })?;
    if job.state == OperationJobState::Queued {
        HostBrokerService.transition(job, OperationJobState::Running, None)?;
    } else if job.state != OperationJobState::Running {
        return Err(eliot_engine::EngineError::WriteRejected(
            "external invocation OperationJob is not dispatchable".to_owned(),
        ));
    }
    let job = job.clone();
    super::managed::write_canonical_managed_job(config_path, &state, &job)
        .await
        .map_err(anyhow_engine)?;
    engine_anyhow(delegation_runtime::save_host_broker_state(&root, &state))
}

async fn canonicalize_external_agent_broker_result(
    config_path: &Path,
    execution: &ExternalAgentExecutionRequest,
    unreceipted_result: AgentResultEnvelope,
) -> Result<AgentResultEnvelope, eliot_engine::EngineError> {
    let root = runtime_root(config_path);
    let mut state = engine_anyhow(delegation_runtime::load_state(&root))?;
    let existing = state
        .agent_results
        .iter()
        .find(|result| result.result_id == unreceipted_result.result_id);
    if let Some(existing) = existing_receipted_external_result(existing, &unreceipted_result)? {
        return Ok(existing);
    }
    let mut receipted_result = HostBrokerService.record_result(&mut state, unreceipted_result)?;
    let session_id = execution.launch_contract.agent_session_id.ok_or_else(|| {
        eliot_engine::EngineError::WriteRejected(
            "external result lacks governed AgentSession".to_owned(),
        )
    })?;
    let canonical_write = canonical_agent_result_write(&receipted_result)?;
    let (canonical_receipt, _) = write_canonical_host_observation(
        config_path,
        execution.invocation.project_id,
        execution.invocation.task_id,
        session_id,
        &canonical_write.key,
        canonical_write.receipt_kind,
        &canonical_write.body,
    )
    .await
    .map_err(|error| {
        eliot_engine::EngineError::WriteRejected(format!(
            "canonical external-agent observation failed: {error}"
        ))
    })?;
    receipted_result.canonical_receipt = Some(canonical_receipt);
    let stored = state
        .agent_results
        .iter_mut()
        .find(|result| result.result_id == receipted_result.result_id)
        .ok_or_else(|| {
            eliot_engine::EngineError::WriteRejected(
                "external AgentResultEnvelope disappeared before receipt binding".to_owned(),
            )
        })?;
    *stored = receipted_result.clone();
    let job = state
        .operation_jobs
        .iter()
        .find(|job| job.invocation_id == receipted_result.invocation_id)
        .cloned()
        .ok_or_else(|| {
            eliot_engine::EngineError::WriteRejected(
                "external AgentResultEnvelope has no matching OperationJob".to_owned(),
            )
        })?;
    super::managed::write_canonical_managed_job(config_path, &state, &job)
        .await
        .map_err(anyhow_engine)?;
    engine_anyhow(delegation_runtime::save_host_broker_state(&root, &state))?;
    Ok(receipted_result)
}

struct MaterializedMcp {
    contract: ProviderMcpServerContract,
    provider_config_path: PathBuf,
    extra_environment: BTreeMap<String, String>,
}

#[allow(
    clippy::too_many_lines,
    reason = "provider-specific MCP materialization is one fail-closed contract boundary"
)]
fn materialize_provider_mcp(
    host: AgentHostId,
    governor: &Path,
    config_path: &Path,
    cwd: &Path,
    invocation_root: &Path,
    execution: &ExternalAgentExecutionRequest,
) -> Result<MaterializedMcp, eliot_engine::EngineError> {
    let governor = std::fs::canonicalize(governor)?;
    let governor_sha256 = engine_anyhow(sha256_file(&governor))?;
    let profile = match (host, execution.purpose) {
        (AgentHostId::OpenCode, _) | (_, ExternalAgentPurpose::CognitiveWorker) => "default",
        _ => "external_auditor",
    };
    let args = vec![
        "mcp".to_owned(),
        "stdio".to_owned(),
        "--host".to_owned(),
        host.as_str().to_owned(),
        "--profile".to_owned(),
        profile.to_owned(),
        "--instance".to_owned(),
        "default".to_owned(),
    ];
    let scope_environment = scoped_environment(execution);
    let server = json!({
        "command": path_string(&governor),
        "args": args,
        "env": scope_environment,
    });
    let mut extra_environment = BTreeMap::new();
    let provider_config_path = match host {
        AgentHostId::Claude => {
            let path = invocation_root.join("claude-mcp.json");
            atomic_write_json(&path, &json!({"mcpServers": {"eliot-governor": server}}))
                .map_err(anyhow_engine)?;
            path
        }
        AgentHostId::Antigravity => {
            ensure_antigravity_permissions(invocation_root)?;
            let agents = cwd.join(".agents");
            std::fs::create_dir_all(&agents)?;
            let path = agents.join("mcp_config.json");
            if path.exists() {
                let current: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                let servers = current
                    .get("mcpServers")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        eliot_engine::EngineError::WriteRejected(
                            "existing Antigravity workspace MCP config is not governed".to_owned(),
                        )
                    })?;
                if servers.len() != 1 || !servers.contains_key("eliot-governor") {
                    return Err(eliot_engine::EngineError::WriteRejected(
                        "Antigravity workspace must expose exactly one Governor MCP server"
                            .to_owned(),
                    ));
                }
            }
            atomic_write_json(&path, &json!({"mcpServers": {"eliot-governor": server}}))
                .map_err(anyhow_engine)?;
            path
        }
        AgentHostId::OpenCode => {
            let config_dir = invocation_root.join("opencode-config");
            std::fs::create_dir_all(&config_dir)?;
            let path = config_dir.join("opencode.json");
            let command = std::iter::once(path_string(&governor))
                .chain(args.iter().cloned())
                .collect::<Vec<_>>();
            atomic_write_json(
                &path,
                &json!({
                    "$schema": "https://opencode.ai/config.json",
                    "mcp": {
                        "eliot-governor": {
                            "type": "local",
                            "command": command,
                            "enabled": true,
                            "timeout": 30000,
                            "environment": scope_environment
                        }
                    }
                }),
            )
            .map_err(anyhow_engine)?;
            extra_environment.insert("OPENCODE_CONFIG_DIR".to_owned(), path_string(&config_dir));
            let xdg = invocation_root.join("opencode-xdg");
            std::fs::create_dir_all(&xdg)?;
            extra_environment.insert("XDG_CONFIG_HOME".to_owned(), path_string(&xdg));
            path
        }
        AgentHostId::Codex => {
            return Err(eliot_engine::EngineError::WriteRejected(
                "Codex is not an external provider adapter".to_owned(),
            ));
        }
    };
    let contract = ProviderMcpServerContract {
        name: "eliot-governor".to_owned(),
        command: path_string(&governor),
        args,
        cwd: path_string(cwd),
        required: true,
        enabled: true,
        executable_sha256: governor_sha256,
        build_source_commit: source_commit(cwd),
    };
    let _ = config_path;
    Ok(MaterializedMcp {
        contract,
        provider_config_path,
        extra_environment,
    })
}

fn ensure_antigravity_permissions(invocation_root: &Path) -> Result<(), eliot_engine::EngineError> {
    let profile = std::env::var_os("USERPROFILE").ok_or_else(|| {
        eliot_engine::EngineError::WriteRejected(
            "Antigravity permission merge requires the real USERPROFILE".to_owned(),
        )
    })?;
    let settings = PathBuf::from(profile)
        .join(".gemini")
        .join("antigravity-cli")
        .join("settings.json");
    let existing_bytes = if settings.is_file() {
        std::fs::read(&settings)?
    } else {
        b"{}\n".to_vec()
    };
    let mut value: Value = serde_json::from_slice(&existing_bytes)?;
    let root = value.as_object_mut().ok_or_else(|| {
        eliot_engine::EngineError::WriteRejected(
            "Antigravity CLI settings root is not an object".to_owned(),
        )
    })?;
    let permissions = root
        .entry("permissions")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            eliot_engine::EngineError::WriteRejected(
                "Antigravity CLI permissions field is not an object".to_owned(),
            )
        })?;
    let allow = permissions
        .entry("allow")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| {
            eliot_engine::EngineError::WriteRejected(
                "Antigravity CLI permissions.allow is not an array".to_owned(),
            )
        })?;
    let mut added = Vec::new();
    for tool in crate::mcp_stdio::PART_E_WORKER_TOOLS {
        let rule = format!("mcp(eliot-governor/{tool})");
        if !allow.iter().any(|value| value.as_str() == Some(&rule)) {
            allow.push(Value::String(rule.clone()));
            added.push(rule);
        }
    }
    let deny = permissions
        .entry("deny")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| {
            eliot_engine::EngineError::WriteRejected(
                "Antigravity CLI permissions.deny is not an array".to_owned(),
            )
        })?;
    for rule in [
        "mcp(eliot_surrealdb/*)",
        "mcp(surrealdb/*)",
        "read_file(.git/)",
    ] {
        if !deny.iter().any(|value| value.as_str() == Some(rule)) {
            deny.push(Value::String(rule.to_owned()));
            added.push(rule.to_owned());
        }
    }
    let merged = serde_json::to_vec_pretty(&value)?;
    let before_hash = sha256_bytes(&existing_bytes);
    let after_hash = sha256_bytes(&merged);
    if before_hash != after_hash {
        std::fs::create_dir_all(invocation_root)?;
        atomic_write_bytes(
            &invocation_root.join("antigravity-settings-before.json"),
            &existing_bytes,
        )
        .map_err(anyhow_engine)?;
        atomic_write_bytes(&settings, &merged).map_err(anyhow_engine)?;
    }
    atomic_write_json(
        &invocation_root.join("antigravity-permission-install-receipt.json"),
        &json!({
            "schema_version": "eliot-antigravity-permission-install-v1",
            "settings_path": path_string(&settings),
            "before_sha256": before_hash,
            "after_sha256": after_hash,
            "added_rules": added,
            "wildcard_mcp_allow_added": false,
            "credentials_read_or_copied": false,
            "rollback_source": path_string(&invocation_root.join("antigravity-settings-before.json")),
        }),
    )
    .map_err(anyhow_engine)?;
    Ok(())
}

fn provider_command_plan(
    host: AgentHostId,
    execution: &ExternalAgentExecutionRequest,
    schema: &Value,
    prompt: &str,
    mcp_config: &Path,
    cwd: &Path,
) -> Result<ProviderCommandPlan, eliot_engine::EngineError> {
    match host {
        AgentHostId::Claude => build_claude_code_command(&ClaudeCodeCommandInput {
            requested_model: execution.requested_model.clone(),
            output_schema: schema.clone(),
            mcp_config_path: path_string(mcp_config),
            allowed_tools: execution.allowed_provider_tools.clone(),
            denied_tools: execution.denied_provider_tools.clone(),
            max_turns: execution.max_turns_or_steps,
            prompt: prompt.to_owned(),
        }),
        AgentHostId::Antigravity => build_antigravity_command(&AntigravityCommandInput {
            requested_model: execution.requested_model.clone(),
            workspace: path_string(cwd),
            output_schema: schema.clone(),
            max_runtime_seconds: execution.launch_contract.wall_clock_budget_seconds,
            prompt: prompt.to_owned(),
            native_json_schema: true,
            read_only: execution.read_only,
        }),
        AgentHostId::OpenCode => build_opencode_command(&OpenCodeCommandInput {
            requested_model: execution.requested_model.clone(),
            workspace: path_string(cwd),
            prompt: prompt.to_owned(),
            read_only: execution.read_only,
        }),
        AgentHostId::Codex => Err(eliot_engine::EngineError::WriteRejected(
            "Codex is not an external provider adapter".to_owned(),
        )),
    }
}

fn parse_terminal(
    host: AgentHostId,
    stdout: &[u8],
    requested_model: &str,
    schema: &Value,
    mode: ProviderStructuredOutputMode,
) -> Result<ProviderTerminalResult, eliot_engine::EngineError> {
    match host {
        AgentHostId::Claude => parse_claude_code_stream(stdout, requested_model, schema),
        AgentHostId::Antigravity => parse_antigravity_output(stdout, requested_model, schema, mode),
        AgentHostId::OpenCode => parse_opencode_stream(stdout, requested_model, schema),
        AgentHostId::Codex => Err(eliot_engine::EngineError::WriteRejected(
            "Codex is not an external provider adapter".to_owned(),
        )),
    }
}

fn provider_environment(
    host: AgentHostId,
    plan: &ProviderCommandPlan,
    config_path: &Path,
    governor: &Path,
    execution: &ExternalAgentExecutionRequest,
    mcp: &MaterializedMcp,
) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::new();
    for name in SAFE_INHERITED_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            environment.insert((*name).to_owned(), value.to_string_lossy().into_owned());
        }
    }
    environment.extend(plan.nonsecret_environment.clone());
    environment.extend(mcp.extra_environment.clone());
    environment.extend(scoped_environment(execution));
    environment.insert("ELIOT_GOVERNOR_EXE".to_owned(), path_string(governor));
    environment.insert("ELIOT_GOVERNOR_CONFIG".to_owned(), path_string(config_path));
    if host == AgentHostId::Antigravity
        && execution.purpose != ExternalAgentPurpose::CognitiveWorker
    {
        environment.insert(
            "ELIOT_MCP_ACCESS_PROFILE".to_owned(),
            "external_auditor".to_owned(),
        );
    }
    environment
}

fn scoped_environment(execution: &ExternalAgentExecutionRequest) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::new();
    if let Some(session) = execution.launch_contract.agent_session_id {
        environment.insert("ELIOT_AGENT_SESSION_ID".to_owned(), session.to_string());
    }
    environment.insert(
        "ELIOT_PROJECT_ID".to_owned(),
        execution.invocation.project_id.to_string(),
    );
    environment.insert(
        "ELIOT_TASK_ID".to_owned(),
        execution.invocation.task_id.to_string(),
    );
    environment.insert(
        "ELIOT_WORK_ITEM_ID".to_owned(),
        execution.invocation.work_item_id.to_string(),
    );
    environment.insert(
        "ELIOT_ROLE_LEASE_ID".to_owned(),
        execution.invocation.role_lease_id.clone(),
    );
    if let Some(lease) = execution.invocation.work_lease_id {
        environment.insert("ELIOT_WORK_LEASE_ID".to_owned(), lease.to_string());
    }
    environment
}

fn provider_manifest(
    host: AgentHostId,
    adapter_id: &str,
    executable: Option<&Path>,
) -> eliot_types::CapabilityManifest {
    eliot_types::CapabilityManifest {
        adapter_id: adapter_id.to_owned(),
        name: format!("{} headless CLI adapter", host.as_str()),
        version: EXTERNAL_ADAPTER_VERSION.to_owned(),
        description: "governed candidate-only external provider runtime".to_owned(),
        adapter_class: AdapterClass::ExternalCandidate,
        capabilities: vec![
            AdapterCapability::HealthCheck,
            AdapterCapability::EmitCandidateObservation,
            AdapterCapability::EmitArtifactHandle,
            AdapterCapability::RequestControllerReview,
        ],
        authority_profile: AdapterAuthorityProfile {
            allowed_projects: Vec::new(),
            allowed_roles: vec![
                AgentRole::Implementer,
                AgentRole::Reviewer,
                AgentRole::Auditor,
            ],
            allowed_capabilities: vec![
                AdapterCapability::HealthCheck,
                AdapterCapability::EmitCandidateObservation,
                AdapterCapability::EmitArtifactHandle,
                AdapterCapability::RequestControllerReview,
            ],
            can_write_truth: false,
            can_request_patch: false,
            can_finish_task: false,
        },
        limits: AdapterLimits {
            timeout_ms: 915_000,
            max_payload_bytes: 262_144,
            max_output_bytes: 1_048_576,
            max_concurrent_requests: 1,
            circuit_breaker_failures: 2,
        },
        enabled_by_default: true,
        process_policy: ProcessExecutionPolicy {
            process_spawn_allowed: true,
            allowed_executables: executable.map(path_string).into_iter().collect::<Vec<_>>(),
            inherit_environment: false,
            network_allowed: true,
        },
    }
}

fn discover_provider_binary(host: AgentHostId) -> Result<Option<PathBuf>> {
    let explicit = match host {
        AgentHostId::Claude => "ELIOT_CLAUDE_CODE_EXE",
        AgentHostId::Antigravity => "ELIOT_ANTIGRAVITY_EXE",
        AgentHostId::OpenCode => "ELIOT_OPENCODE_EXE",
        AgentHostId::Codex => return Ok(None),
    };
    if let Some(path) = std::env::var_os(explicit).map(PathBuf::from) {
        return validate_provider_binary(host, &path).map(Some);
    }
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let candidates = match (host, local.as_deref()) {
        (AgentHostId::Claude, Some(local)) => discover_winget_claude(local),
        (AgentHostId::Antigravity, Some(local)) => {
            vec![local.join("agy").join("bin").join("agy.exe")]
        }
        (AgentHostId::OpenCode, Some(local)) => {
            vec![local.join("OpenCode").join("opencode-cli.exe")]
        }
        _ => Vec::new(),
    };
    for candidate in candidates {
        if candidate.is_file() {
            return validate_provider_binary(host, &candidate).map(Some);
        }
    }
    let names: &[&str] = match host {
        AgentHostId::Claude => &["claude"],
        AgentHostId::Antigravity => &["agy", "antigravity"],
        AgentHostId::OpenCode => &["opencode-cli", "opencode"],
        AgentHostId::Codex => &[],
    };
    for name in names {
        if let Some(path) = where_executable(name)? {
            return validate_provider_binary(host, &path).map(Some);
        }
    }
    Ok(None)
}

fn discover_winget_claude(local: &Path) -> Vec<PathBuf> {
    let root = local.join("Microsoft").join("WinGet").join("Packages");
    std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("Anthropic.ClaudeCode_")
        })
        .map(|entry| entry.path().join("claude.exe"))
        .collect()
}

fn where_executable(name: &str) -> Result<Option<PathBuf>> {
    let output = Command::new("where.exe").arg(name).output()?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(PathBuf::from))
}

fn validate_provider_binary(host: AgentHostId, path: &Path) -> Result<PathBuf> {
    let path = std::fs::canonicalize(path)
        .with_context(|| format!("canonicalize provider executable {}", path.display()))?;
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let rejected = match host {
        AgentHostId::Claude => {
            lower.contains(r"\windowsapps\")
                || lower.contains(r"\program files\claude\")
                || name == "claude desktop.exe"
        }
        AgentHostId::Antigravity => name != "agy.exe",
        AgentHostId::OpenCode => name == "opencode.exe" || name == "opencode",
        AgentHostId::Codex => true,
    };
    anyhow::ensure!(
        !rejected,
        "{} is not an admitted headless {} executable",
        path.display(),
        host.as_str()
    );
    Ok(path)
}

fn provider_version(path: &Path) -> Result<String> {
    let output = Command::new(path).arg("--version").output()?;
    anyhow::ensure!(
        output.status.success(),
        "{} --version exited {}",
        path.display(),
        output.status
    );
    let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    anyhow::ensure!(!version.is_empty(), "provider --version returned no text");
    Ok(version)
}

fn canonical_bound_file(value: &str, label: &str) -> Result<PathBuf, eliot_engine::EngineError> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(eliot_engine::EngineError::WriteRejected(format!(
            "{label} path is not absolute"
        )));
    }
    std::fs::canonicalize(path).map_err(eliot_engine::EngineError::from)
}

fn require_sha256(
    bytes: &[u8],
    expected: &str,
    label: &str,
) -> Result<(), eliot_engine::EngineError> {
    let actual = sha256_bytes(bytes);
    if actual == expected {
        Ok(())
    } else {
        Err(eliot_engine::EngineError::WriteRejected(format!(
            "{label} differs: expected={expected} actual={actual}"
        )))
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn adapter_id(host: AgentHostId) -> &'static str {
    match host {
        AgentHostId::Claude => "external-agent:claude",
        AgentHostId::Antigravity => "external-agent:antigravity",
        AgentHostId::OpenCode => "external-agent:opencode",
        AgentHostId::Codex => "external-agent:codex-forbidden",
    }
}

fn provider_campaign_id(execution: &ExternalAgentExecutionRequest) -> String {
    format!(
        "external-agent:{}:{}",
        execution.invocation.task_id, execution.requested_model
    )
}

fn safe_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn engine_anyhow<T>(result: Result<T>) -> Result<T, eliot_engine::EngineError> {
    result.map_err(anyhow_engine)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the signature is used directly as an anyhow Result::map_err callback"
)]
fn anyhow_engine(error: anyhow::Error) -> eliot_engine::EngineError {
    eliot_engine::EngineError::WriteRejected(error.to_string())
}

fn source_commit(cwd: &Path) -> Option<String> {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(cwd)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn worktree_snapshot_if_git(
    cwd: &Path,
) -> Result<Option<(String, String)>, eliot_engine::EngineError> {
    if !cwd.join(".git").exists() {
        return Ok(None);
    }
    let status = Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .current_dir(cwd)
        .output()?;
    let diff = Command::new("git")
        .args(["diff", "--binary", "--no-ext-diff"])
        .current_dir(cwd)
        .output()?;
    if !status.status.success() || !diff.status.success() {
        return Err(eliot_engine::EngineError::WriteRejected(
            "failed to snapshot governed provider worktree".to_owned(),
        ));
    }
    Ok(Some((
        sha256_bytes(&status.stdout),
        sha256_bytes(&diff.stdout),
    )))
}

fn provider_failure_message(process: &ManagedExternalAgentOutput) -> String {
    let stderr = String::from_utf8_lossy(&process.stderr);
    if stderr
        .to_ascii_lowercase()
        .contains("not logged into antigravity")
        || stderr
            .to_ascii_lowercase()
            .contains("not logged in to antigravity")
    {
        "BLOCKED_PROVIDER_AUTH_ANTIGRAVITY".to_owned()
    } else if stderr.to_ascii_lowercase().contains("not logged in")
        || stderr.to_ascii_lowercase().contains("authentication")
    {
        "provider CLI is unauthenticated".to_owned()
    } else {
        format!("provider process exited {:?}", process.exit_code)
    }
}

#[cfg(test)]
pub(super) fn external_adapter_manifest_fixture(
    host: AgentHostId,
) -> eliot_types::CapabilityManifest {
    provider_manifest(host, adapter_id(host), None)
}

#[cfg(test)]
pub(super) fn canonical_external_result_contract_fixture() -> Result<Value> {
    let result = AgentResultEnvelope {
        result_id: deterministic_external_result_id_from_parts(
            "fixture-invocation",
            "fixture-idempotency",
        ),
        invocation_id: "fixture-invocation".to_owned(),
        host_id: AgentHostId::Claude,
        host_session_id: Some("fixture-provider-session".to_owned()),
        status: AgentResultStatus::Succeeded,
        summary: "fixture candidate result".to_owned(),
        artifact_refs: Vec::new(),
        evidence_refs: vec!["fixture-evidence".to_owned()],
        verifier_refs: vec!["fixture-verifier".to_owned()],
        candidate_only: true,
        exit_status: Some(0),
        token_or_cost_telemetry: None,
        unknown_outcome_evidence_refs: Vec::new(),
        supersedes_result_id: None,
        provider_output_hash: Some("a".repeat(64)),
        canonical_receipt: None,
    };
    let write = canonical_agent_result_write(&result)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let mut receipted = result.clone();
    receipted.canonical_receipt = Some(eliot_types::WriteReceiptRef {
        receipt_id: eliot_types::ReceiptId::new_v7(),
        write_id: eliot_types::WriteId::new_v7(),
    });
    let accepted_replay = existing_receipted_external_result(Some(&receipted), &result)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let mut changed = result.clone();
    changed.summary.push_str(" changed");
    let changed_replay_rejected =
        existing_receipted_external_result(Some(&receipted), &changed).is_err();
    Ok(json!({
        "first_result_id": result.result_id,
        "same_result_id": deterministic_external_result_id_from_parts(
            "fixture-invocation",
            "fixture-idempotency",
        ),
        "different_result_id": deterministic_external_result_id_from_parts(
            "fixture-invocation",
            "different-idempotency",
        ),
        "key": write.key,
        "receipt_kind": write.receipt_kind,
        "body": write.body,
        "receipted_replay_accepted": accepted_replay
            .as_ref()
            .and_then(|result| result.canonical_receipt.as_ref())
            .is_some(),
        "changed_replay_rejected": changed_replay_rejected,
    }))
}

#[cfg(test)]
mod mcp_smoke_tests {
    use super::*;

    #[test]
    fn smoke_prompt_requires_the_bound_scope_only() {
        let prompt = mcp_smoke_prompt("opencode/mimo-v2.5-free");
        assert!(
            prompt.contains(
                "exactly once with the sole argument {\"scope\":\"memory_free_control\"}"
            )
        );
        assert!(!prompt.contains("{\"project_id\""));
        assert!(!prompt.contains("{\"task_id\""));
        assert!(prompt.contains("without Markdown fences or prose"));
        assert!(prompt.contains("resolved_model=opencode/mimo-v2.5-free"));
    }

    #[test]
    fn provider_revision_may_advance_inside_the_execution_window() {
        assert!(memory_revision_within_execution_window(3, 6, 8));
        assert!(memory_revision_within_execution_window(3, 3, 3));
        assert!(!memory_revision_within_execution_window(3, 2, 8));
        assert!(!memory_revision_within_execution_window(3, 9, 8));
    }

    #[test]
    fn phase_trace_attributes_an_aborted_phase() -> Result<()> {
        let root = std::env::temp_dir().join(format!("eliot-smoke-phase-test-{}", Uuid::now_v7()));
        let trace = SmokePhaseTrace::new(&root, "phase-test")?;
        trace.start("current_state_preflight")?;
        trace.abort_active("test deadline")?;
        let entries = std::fs::read_to_string(trace.path())?
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["status"], "started");
        assert_eq!(entries[1]["status"], "aborted");
        assert_eq!(entries[1]["phase"], "current_state_preflight");
        assert_eq!(entries[1]["detail"], "test deadline");
        std::fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[cfg(windows)]
    fn powershell_child(script: &str) -> tokio::process::Command {
        let mut command = tokio::process::Command::new("powershell.exe");
        command
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn bounded_child_drains_output_while_writing_input() -> Result<()> {
        let command = powershell_child(
            "$s = 'x' * 131072; [Console]::Out.Write($s); [Console]::Error.Write($s); $null = [Console]::In.ReadToEnd()",
        );
        let output = run_bounded_mcp_child(
            command,
            vec![b'i'; 262_144],
            "flood_regression",
            Duration::from_secs(10),
        )
        .await?;
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 131_072);
        assert_eq!(output.stderr.len(), 131_072);
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn bounded_child_kills_and_reaps_a_hang() -> Result<()> {
        let started = Instant::now();
        let error = run_bounded_mcp_child(
            powershell_child("Start-Sleep -Seconds 30"),
            Vec::new(),
            "hang_regression",
            Duration::from_millis(300),
        )
        .await
        .expect_err("hanging child must be bounded");
        assert!(started.elapsed() < Duration::from_secs(5));
        let message = error.to_string();
        assert!(message.contains("phase=hang_regression"));
        assert!(message.contains("child killed and reaped"));
        let pid = message
            .split("pid=")
            .nth(1)
            .and_then(|tail| tail.split(';').next())
            .context("timeout error did not expose the child PID")?;
        let probe = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 1 }} else {{ exit 0 }}"
                ),
            ])
            .output()?;
        assert!(
            probe.status.success(),
            "timed-out MCP child PID {pid} still exists"
        );
        Ok(())
    }
}
