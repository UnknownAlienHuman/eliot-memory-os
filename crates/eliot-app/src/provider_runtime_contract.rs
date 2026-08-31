//! Provider runtime contract construction, validation, and zero-model preflight.
//!
//! Normative handles in `docs/architecture/ELIOT_ARCHITECTURE.md`: `A2.2` and
//! `A12.2` keep authority explicit, scoped, and fenced; this runtime boundary
//! validates provider bindings without creating authority. Implementation
//! handles in `docs/architecture/ELIOT_IMPLEMENTATION.md`: `I10.11` separates
//! routing from physical model attempts behind provider-neutral contracts, and
//! `I10.17` keeps external-agent adapters replaceable supervised bridges with
//! no canonical-write authority. Precedence remains governed by
//! `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! This cell may construct and inspect candidate runtime contracts and perform
//! bounded preflight observation. It never mutates canonical state, changes
//! authority, seals plans or receipts, or executes a provider model call.

use super::{
    canonical_directory, canonical_file, canonical_path, cognitive_worker_result_schema, is_sha256,
    private_relative_file, read_json, safe_segment, sha256_bytes,
};
use anyhow::{Context, Result, ensure};
use eliot_engine::{
    seal_provider_runtime_contract, validate_external_agent_execution_request,
    validate_provider_runtime_contract,
};
use eliot_types::external_agent::legacy::{
    COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION, CognitiveProviderRuntimeContract,
};
use eliot_types::{
    AgentHostId, CognitiveFieldProviderCallPlan, ExternalAgentExecutionRequest,
    ExternalAgentPurpose, PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION,
    PROVIDER_RUNTIME_PREFLIGHT_SCHEMA_VERSION, ProviderDeclaredBudget, ProviderMcpServerContract,
    ProviderRoutePolicy, ProviderRuntimeContract, ProviderRuntimePreflightReceipt,
    ProviderStructuredOutputMode, inspect_secret_bytes,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::windows::process::ExitStatusExt as _;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use uuid::Uuid;

const CODEX_COGNITIVE_EXPECTED_TOOLS: &[&str] = &[
    "eliot_current_state",
    "eliot_recall_l0",
    "eliot_fetch_l2",
    "eliot_compile_packet_l3",
    "eliot_agent_candidate_submit",
    "eliot.observe",
    "eliot_memory_influence_trace",
    "eliot_write_cognitive_observation",
];
const COGNITIVE_RUNTIME_PREFLIGHT_LIMIT: Duration = Duration::from_secs(20);

pub(super) enum ProviderRuntimeBinding {
    Current(Box<ProviderRuntimeContract>),
    Legacy(Box<CognitiveProviderRuntimeContract>),
}

impl ProviderRuntimeBinding {
    pub(super) fn runtime_contract_sha256(&self) -> &str {
        match self {
            Self::Current(contract) => &contract.runtime_contract_sha256,
            Self::Legacy(contract) => &contract.runtime_contract_sha256,
        }
    }

    pub(super) const fn host(&self) -> AgentHostId {
        match self {
            Self::Current(contract) => contract.host,
            Self::Legacy(contract) => contract.host,
        }
    }

    pub(super) fn provider_executable_sha256(&self) -> &str {
        match self {
            Self::Current(contract) => &contract.provider_executable_sha256,
            Self::Legacy(contract) => &contract.provider_executable_sha256,
        }
    }

    pub(super) fn expected_mcp_tool_names(&self) -> &[String] {
        match self {
            Self::Current(contract) => &contract.expected_mcp_tool_names,
            Self::Legacy(contract) => &contract.expected_mcp_tool_names,
        }
    }

    pub(super) fn forbidden_mcp_server_names(&self) -> &[String] {
        match self {
            Self::Current(contract) => &contract.forbidden_mcp_server_names,
            Self::Legacy(contract) => &contract.forbidden_mcp_server_names,
        }
    }

    pub(super) const fn is_current(&self) -> bool {
        matches!(self, Self::Current(_))
    }
}

pub(super) fn codex_provider_argv(
    provider_cwd: &str,
    governor_executable: &str,
    governor_args: &[String],
) -> Result<Vec<String>> {
    Ok(vec![
        "exec".to_owned(),
        "--cd".to_owned(),
        provider_cwd.to_owned(),
        "-c".to_owned(),
        format!(
            "mcp_servers.eliot-governor.command={}",
            serde_json::to_string(governor_executable)?
        ),
        "-c".to_owned(),
        format!(
            "mcp_servers.eliot-governor.args={}",
            serde_json::to_string(governor_args)?
        ),
        "-c".to_owned(),
        format!(
            "mcp_servers.eliot-governor.cwd={}",
            serde_json::to_string(provider_cwd)?
        ),
        "-c".to_owned(),
        "mcp_servers.eliot-governor.required=true".to_owned(),
        "-c".to_owned(),
        "mcp_servers.eliot_surrealdb.enabled=false".to_owned(),
    ])
}

pub(super) fn codex_cognitive_runtime_contract(
    provider_executable: &Path,
    worktree: &Path,
    governor_executable: &Path,
    governor_build_source_commit: Option<&str>,
) -> Result<ProviderRuntimeContract> {
    let provider_executable = canonical_file(provider_executable, "Codex provider executable")?;
    let worktree = canonical_directory(worktree, "isolated cognitive worktree")?;
    let governor_executable = canonical_file(governor_executable, "Eliot Governor executable")?;
    if let Some(commit) = governor_build_source_commit {
        ensure!(
            commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Governor build source commit must be a 40-character hexadecimal object id"
        );
    }

    let provider_executable = canonical_path(&provider_executable);
    let provider_cwd = canonical_path(&worktree);
    let governor_executable_path = canonical_path(&governor_executable);
    let governor_args = vec![
        "mcp".to_owned(),
        "stdio".to_owned(),
        "--host".to_owned(),
        "codex".to_owned(),
        "--profile".to_owned(),
        "codex_worker".to_owned(),
        "--instance".to_owned(),
        "default".to_owned(),
    ];
    let provider_argv =
        codex_provider_argv(&provider_cwd, &governor_executable_path, &governor_args)?;
    let expected_mcp_tool_names = CODEX_COGNITIVE_EXPECTED_TOOLS
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let route_policy = ProviderRoutePolicy::for_route(
        AgentHostId::Codex,
        "cognitive-field",
        ProviderDeclaredBudget::new(1_200_000, 4 * 1024 * 1024),
    );
    let output_schema_sha256 =
        sha256_bytes(&serde_json::to_vec(&cognitive_worker_result_schema()?)?);
    let mut contract = ProviderRuntimeContract {
        schema_version: PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION.to_owned(),
        host: AgentHostId::Codex,
        purpose: ExternalAgentPurpose::CognitiveWorker,
        provider_executable: provider_executable.clone(),
        provider_executable_sha256: sha256_bytes(&fs::read(&provider_executable)?),
        provider_version: "executable-sha256-bound".to_owned(),
        requested_model: "task-selected".to_owned(),
        model_selection_mechanism: "codex-cli-model-argument".to_owned(),
        provider_cwd: provider_cwd.clone(),
        provider_argv,
        nonsecret_environment: BTreeMap::new(),
        mcp_servers: vec![
            ProviderMcpServerContract {
                name: "eliot-governor".to_owned(),
                command: governor_executable_path,
                args: governor_args,
                cwd: provider_cwd,
                required: true,
                enabled: true,
                executable_sha256: sha256_bytes(&fs::read(&governor_executable)?),
                build_source_commit: governor_build_source_commit.map(str::to_owned),
            },
            ProviderMcpServerContract {
                name: "eliot_surrealdb".to_owned(),
                command: String::new(),
                args: Vec::new(),
                cwd: String::new(),
                required: false,
                enabled: false,
                executable_sha256: String::new(),
                build_source_commit: None,
            },
        ],
        mcp_tool_profile: crate::mcp_stdio::catalog::provider_mcp_tool_profile(
            crate::mcp_stdio::McpAccessProfile::CodexWorker,
        ),
        expected_mcp_tool_names,
        forbidden_mcp_server_names: vec!["eliot_surrealdb".to_owned()],
        allowed_provider_tools: CODEX_COGNITIVE_EXPECTED_TOOLS
            .iter()
            .map(|tool| format!("mcp__eliot-governor__{tool}"))
            .collect(),
        denied_provider_tools: vec!["raw_database".to_owned()],
        permission_profile: "cognitive-candidate-only".to_owned(),
        structured_output_mode: ProviderStructuredOutputMode::NativeJsonSchema,
        output_schema_sha256,
        timeout_profile_ref: route_policy.policy_id().to_owned(),
        provider_route_policy: route_policy.binding(),
        process_containment: "windows_job_object".to_owned(),
        candidate_only: true,
        runtime_contract_sha256: String::new(),
    };
    seal_provider_runtime_contract(&mut contract)?;
    Ok(contract)
}

fn legacy_runtime_contract_without_hash(
    contract: &CognitiveProviderRuntimeContract,
) -> CognitiveProviderRuntimeContract {
    let mut material = contract.clone();
    material.runtime_contract_sha256.clear();
    material
}

fn normalize_legacy_runtime_contract(contract: &mut CognitiveProviderRuntimeContract) {
    contract
        .mcp_servers
        .sort_by(|left, right| left.name.cmp(&right.name));
    contract
        .expected_mcp_tool_names
        .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    contract.expected_mcp_tool_names.dedup();
    contract
        .forbidden_mcp_server_names
        .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    contract.forbidden_mcp_server_names.dedup();
}

fn computed_legacy_runtime_contract_sha256(
    contract: &CognitiveProviderRuntimeContract,
) -> Result<String> {
    let mut material = legacy_runtime_contract_without_hash(contract);
    normalize_legacy_runtime_contract(&mut material);
    Ok(sha256_bytes(&serde_json::to_vec(&material)?))
}

fn validate_legacy_runtime_contract(contract: &CognitiveProviderRuntimeContract) -> Result<()> {
    ensure!(
        contract.schema_version == COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION,
        "provider runtime schema version is invalid"
    );
    let mut normalized = contract.clone();
    normalize_legacy_runtime_contract(&mut normalized);
    ensure!(
        normalized == *contract,
        "provider runtime unordered fields must be sorted and deduplicated"
    );
    ensure!(
        is_sha256(&contract.provider_executable_sha256)
            && is_sha256(&contract.runtime_contract_sha256)
            && computed_legacy_runtime_contract_sha256(contract)?
                == contract.runtime_contract_sha256,
        "provider runtime hashes are invalid"
    );
    let provider_executable = canonical_file(
        Path::new(&contract.provider_executable),
        "provider executable",
    )?;
    let provider_cwd = canonical_directory(
        Path::new(&contract.provider_cwd),
        "provider working directory",
    )?;
    ensure!(
        canonical_path(&provider_executable) == contract.provider_executable
            && canonical_path(&provider_cwd) == contract.provider_cwd
            && sha256_bytes(&fs::read(provider_executable)?) == contract.provider_executable_sha256,
        "provider runtime executable or cwd differs from its canonical binding"
    );
    ensure!(
        !contract.provider_argv.is_empty() && !contract.forbidden_mcp_server_names.is_empty(),
        "provider runtime argv and forbidden servers are required"
    );
    for server in &contract.mcp_servers {
        ensure!(
            safe_segment(&server.name),
            "provider runtime MCP server name is unsafe"
        );
        if server.enabled {
            let executable = canonical_file(Path::new(&server.command), "MCP server executable")?;
            let cwd = canonical_directory(Path::new(&server.cwd), "MCP server cwd")?;
            ensure!(
                canonical_path(&executable) == server.command
                    && canonical_path(&cwd) == server.cwd
                    && is_sha256(&server.executable_sha256)
                    && sha256_bytes(&fs::read(executable)?) == server.executable_sha256,
                "enabled MCP server runtime binding is invalid"
            );
            if let Some(commit) = &server.build_source_commit {
                ensure!(
                    commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
                    "MCP server build source commit is invalid"
                );
            }
        }
    }
    if contract.host == AgentHostId::Codex {
        ensure!(
            !contract.expected_mcp_tool_names.is_empty(),
            "Codex cognitive runtime requires expected MCP tools"
        );
        let governor = contract
            .mcp_servers
            .iter()
            .find(|server| server.name == "eliot-governor")
            .context("Codex cognitive runtime lacks eliot-governor")?;
        ensure!(
            governor.enabled
                && governor.required
                && governor.build_source_commit.is_some()
                && governor.args
                    == [
                        "mcp",
                        "stdio",
                        "--host",
                        "codex",
                        "--profile",
                        "codex_worker",
                        "--instance",
                        "default",
                    ]
                    .map(str::to_owned)
                && contract
                    .mcp_servers
                    .iter()
                    .filter(|server| {
                        server.name.to_ascii_lowercase().contains("surreal")
                            && server.name != "eliot-governor"
                    })
                    .all(|server| !server.enabled),
            "Codex cognitive runtime must require Governor codex_worker and disable raw SurrealDB"
        );
    }
    Ok(())
}

fn codex_mcp_list_argv(contract: &ProviderRuntimeContract) -> Result<Vec<String>> {
    let (subcommand, runtime_args) = contract
        .provider_argv
        .split_first()
        .context("Codex runtime argv is empty")?;
    ensure!(
        subcommand == "exec",
        "Codex cognitive provider argv must begin with exec"
    );
    let mut args = runtime_args.to_vec();
    args.extend(["mcp", "list", "--json"].map(str::to_owned));
    Ok(args)
}

fn configured_mcp_servers(value: &Value) -> Result<Vec<(String, bool)>> {
    let entries = value
        .as_array()
        .or_else(|| value.get("servers").and_then(Value::as_array))
        .context("Codex MCP list JSON is neither an array nor a servers object")?;
    let mut servers = entries
        .iter()
        .map(|entry| {
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .context("Codex MCP entry lacks a name")?;
            let enabled = entry
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            Ok((name.to_owned(), enabled))
        })
        .collect::<Result<Vec<_>>>()?;
    servers.sort();
    servers.dedup();
    Ok(servers)
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded preflight state machine keeps process policy and output conversion together"
)]
fn supervised_preflight_command(
    config_path: &Path,
    command: &Command,
    stdin_payload: Option<Vec<u8>>,
    operation_id: String,
    timeout: Duration,
    child_kind: crate::host_runtime::supervised_process::SupervisedChildKind,
) -> Result<std::process::Output> {
    use crate::host_runtime::supervised_process::{
        ChildCriticality, ProcessRestartPolicy, RestartStrategy, SupervisedProcessSpec,
        run_supervised_process_blocking,
    };

    let mut environment = [
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "PATH",
        "PATHEXT",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "TEMP",
        "TMP",
    ]
    .into_iter()
    .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
    .collect::<BTreeMap<_, _>>();
    for (name, value) in command.get_envs() {
        if let Some(value) = value {
            environment.insert(name.into(), value.into());
        } else {
            environment.remove(name);
        }
    }
    let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    let operation_id_for_context = operation_id.clone();
    let output = run_supervised_process_blocking(
        SupervisedProcessSpec {
            operation_id,
            invocation_id: None,
            generation: 1,
            child_kind,
            criticality: ChildCriticality::InvocationDependency,
            restart_policy: ProcessRestartPolicy {
                strategy: RestartStrategy::Never,
                max_restarts: 0,
                restart_window_seconds: 60,
                base_backoff_ms: 0,
                pre_dispatch_only: false,
            },
            executable: command.get_program().into(),
            args: command.get_args().map(OsString::from).collect(),
            cwd: command
                .get_current_dir()
                .map(ToOwned::to_owned)
                .map_or_else(std::env::current_dir, Ok)?,
            environment,
            stdin_payload,
            stdout_limit_bytes: 4 * 1024 * 1024,
            stderr_limit_bytes: 4 * 1024 * 1024,
            timeout_profile: eliot_types::ProviderRoutePolicy::for_route(
                AgentHostId::Codex,
                "cognitive-preflight",
                eliot_types::ProviderDeclaredBudget::new(timeout_ms, 4 * 1024 * 1024)
                    .with_idle_output_deadline_ms(Some(timeout_ms))
                    .with_cancellation_grace_ms(25)
                    .with_reconciliation_window_ms(0),
            )
            .timeout_profile()
            .clone(),
            runtime_contract_sha256: None,
            role_lease_id: None,
            role_lease_epoch: None,
        },
        eliot_engine::runtime_supervision::AdapterExecutionContext {
            operation_id: operation_id_for_context,
            generation: 1,
            cancellation: eliot_engine::runtime_supervision::CancellationToken::new(),
            deadline: tokio::time::Instant::now() + timeout,
            runtime_store:
                crate::host_runtime::supervised_process::daemon_operation_runtime_handle(
                    config_path,
                )?,
            role_lease_id: None,
            role_lease_epoch: None,
            runtime_contract_sha256: None,
        },
    )?;
    ensure!(
        !output.timed_out && output.reap_receipt.proves_complete_reap(),
        "supervised cognitive preflight timed out or did not reap its Job Object"
    );
    ensure!(
        output.worker_error.is_none(),
        "supervised cognitive preflight failed: {:?}",
        output.worker_error
    );
    Ok(std::process::Output {
        status: std::process::ExitStatus::from_raw(
            output.exit_code.unwrap_or(i32::MAX).cast_unsigned(),
        ),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn json_rpc_response_by_id(responses: &[Value], id: u64) -> Result<&Value> {
    responses
        .iter()
        .find(|response| response.get("id").and_then(Value::as_u64) == Some(id))
        .with_context(|| format!("Governor MCP returned no JSON-RPC response for id {id}"))
}

#[allow(clippy::too_many_lines)]
pub(super) fn preflight_codex_cognitive_runtime(
    config_path: &Path,
    contract: &ProviderRuntimeContract,
    scoped_environment: &BTreeMap<String, String>,
) -> Result<ProviderRuntimePreflightReceipt> {
    let started = Instant::now();
    validate_provider_runtime_contract(contract)?;
    ensure!(
        contract.host == AgentHostId::Codex,
        "Codex runtime preflight requires a Codex contract"
    );

    let mut config_command = Command::new(&contract.provider_executable);
    config_command
        .args(codex_mcp_list_argv(contract)?)
        .current_dir(&contract.provider_cwd)
        .envs(scoped_environment);
    let config_output = supervised_preflight_command(
        config_path,
        &config_command,
        None,
        format!("cognitive-config-preflight-{}", Uuid::now_v7()),
        COGNITIVE_RUNTIME_PREFLIGHT_LIMIT,
        crate::host_runtime::supervised_process::SupervisedChildKind::Verifier,
    )
    .context("run zero-model Codex MCP configuration listing")?;
    ensure!(
        config_output.status.success(),
        "Codex MCP configuration listing failed: {}",
        String::from_utf8_lossy(&config_output.stderr)
    );
    let config_json: Value = serde_json::from_slice(&config_output.stdout)
        .context("parse zero-model Codex MCP configuration listing")?;
    let configured_servers = configured_mcp_servers(&config_json)?;
    let observed_server_names = configured_servers
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let forbidden_servers_absent = configured_servers.iter().all(|(name, enabled)| {
        !enabled
            || (!contract.forbidden_mcp_server_names.contains(name)
                && !name.to_ascii_lowercase().contains("surreal"))
    });
    ensure!(
        configured_servers
            .iter()
            .any(|(name, enabled)| name == "eliot-governor" && *enabled)
            && forbidden_servers_absent,
        "Codex MCP listing did not prove enabled Governor and disabled/absent raw SurrealDB"
    );

    let governor = contract
        .mcp_servers
        .iter()
        .find(|server| server.name == "eliot-governor")
        .context("runtime contract lacks Governor server")?;
    let requests = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "eliot-cognitive-runtime-preflight",
                    "version": PROVIDER_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
                },
            },
        }),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "eliot_host_session_status", "arguments": {}},
        }),
    ];
    let mut request_bytes = Vec::new();
    for request in requests {
        request_bytes.extend_from_slice(&serde_json::to_vec(&request)?);
        request_bytes.push(b'\n');
    }
    let mut governor_command = Command::new(&governor.command);
    governor_command
        .args(&governor.args)
        .current_dir(&governor.cwd)
        .envs(scoped_environment);
    let mcp_output = supervised_preflight_command(
        config_path,
        &governor_command,
        Some(request_bytes),
        format!("cognitive-mcp-preflight-{}", Uuid::now_v7()),
        COGNITIVE_RUNTIME_PREFLIGHT_LIMIT,
        crate::host_runtime::supervised_process::SupervisedChildKind::McpPreflight,
    )
    .context("run exact Governor MCP stdio child")?;
    ensure!(
        mcp_output.status.success(),
        "Governor MCP preflight failed: {}",
        String::from_utf8_lossy(&mcp_output.stderr)
    );
    let responses = String::from_utf8(mcp_output.stdout)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?;
    let result = (|| -> Result<(Vec<String>, bool)> {
        let initialize = json_rpc_response_by_id(&responses, 1)?;
        ensure!(
            initialize.get("error").is_none() && initialize.get("result").is_some(),
            "Governor MCP initialize failed: {initialize}"
        );
        let tools = json_rpc_response_by_id(&responses, 2)?;
        ensure!(
            tools.get("error").is_none(),
            "Governor MCP tools/list failed: {tools}"
        );
        let mut observed_tools = tools
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .context("Governor MCP tools/list lacks result.tools")?
            .iter()
            .map(|tool| {
                tool.get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .context("Governor MCP tool lacks a name")
            })
            .collect::<Result<Vec<_>>>()?;
        observed_tools.sort();
        observed_tools.dedup();
        ensure!(
            contract
                .expected_mcp_tool_names
                .iter()
                .all(|expected| observed_tools.contains(expected)),
            "Governor MCP tools/list lacks one or more expected cognitive tools"
        );

        let status = json_rpc_response_by_id(&responses, 3)?;
        let scoped_status_read_passed =
            status.get("error").is_none() && status.get("result").is_some();
        Ok((observed_tools, scoped_status_read_passed))
    })();

    let (observed_mcp_tool_names, scoped_status_read_passed) = result?;
    let elapsed_ms =
        u64::try_from(started.elapsed().as_millis()).context("preflight duration exceeds u64")?;
    ensure!(
        started.elapsed() <= COGNITIVE_RUNTIME_PREFLIGHT_LIMIT,
        "Governor MCP preflight exceeded 20 seconds"
    );
    Ok(ProviderRuntimePreflightReceipt {
        schema_version: PROVIDER_RUNTIME_PREFLIGHT_SCHEMA_VERSION.to_owned(),
        runtime_contract_sha256: contract.runtime_contract_sha256.clone(),
        config_list_passed: true,
        mcp_process_started: true,
        mcp_initialized: true,
        tools_listed: true,
        expected_tools_present: true,
        forbidden_servers_absent,
        scoped_status_read_passed,
        observed_server_names,
        observed_tool_names: observed_mcp_tool_names,
        governor_executable_sha256: governor.executable_sha256.clone(),
        governor_build_source_commit: governor.build_source_commit.clone(),
        elapsed_ms,
    })
}

pub(super) fn provider_environment_surface() -> Vec<u8> {
    let mut entries = std::env::vars_os()
        .map(|(key, value)| {
            let key = key.to_string_lossy();
            let upper = key.to_ascii_uppercase();
            let sensitive = ["TOKEN", "PASSWORD", "SECRET", "COOKIE", "AUTH", "API_KEY"]
                .iter()
                .any(|marker| upper.contains(marker));
            if sensitive {
                format!("{key}=<redacted>")
            } else {
                format!("{key}={}", value.to_string_lossy())
            }
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries.join("\n").into_bytes()
}

pub(super) fn enforce_provider_secret_boundary(label: &str, bytes: &[u8]) -> Result<()> {
    inspect_secret_bytes(bytes)
        .map_err(|violation| anyhow::anyhow!("{label} failed secret boundary: {violation}"))
}

pub(super) fn provider_runtime_contract(
    private_root: &Path,
    call: &CognitiveFieldProviderCallPlan,
) -> Result<ProviderRuntimeBinding> {
    ensure!(
        !call.runtime_contract_ref.trim().is_empty() && is_sha256(&call.runtime_contract_sha256),
        "new provider calls require a sealed runtime contract reference and SHA-256"
    );
    let path = private_relative_file(
        private_root,
        &call.runtime_contract_ref,
        "provider runtime contract",
    )?;
    let value: Value = read_json(&path)?;
    let schema_version = value
        .get("schema_version")
        .and_then(Value::as_str)
        .context("provider runtime contract has no schema version")?;
    let binding = if schema_version == eliot_types::PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION {
        let contract: ProviderRuntimeContract = serde_json::from_value(value)?;
        validate_provider_runtime_contract(&contract)?;
        ProviderRuntimeBinding::Current(Box::new(contract))
    } else {
        let contract: CognitiveProviderRuntimeContract = serde_json::from_value(value)?;
        validate_legacy_runtime_contract(&contract)?;
        ProviderRuntimeBinding::Legacy(Box::new(contract))
    };
    ensure!(
        binding.runtime_contract_sha256() == call.runtime_contract_sha256
            && binding.host() == call.host
            && binding.provider_executable_sha256() == call.expected_provider_executable_sha256,
        "provider runtime contract differs from the sealed call plan"
    );
    if call.host != AgentHostId::Codex
        && (!call.adapter_id.is_empty()
            || !call.adapter_version.is_empty()
            || !call.execution_request_ref.is_empty()
            || !call.execution_request_sha256.is_empty())
    {
        ensure!(
            binding.is_current()
                && !call.adapter_id.trim().is_empty()
                && !call.adapter_version.trim().is_empty()
                && !call.execution_request_ref.trim().is_empty()
                && is_sha256(&call.execution_request_sha256),
            "external cognitive call lacks current production-adapter bindings"
        );
        let request_path = private_relative_file(
            private_root,
            &call.execution_request_ref,
            "external execution request",
        )?;
        ensure!(
            sha256_bytes(&fs::read(&request_path)?) == call.execution_request_sha256,
            "external execution request hash differs from the sealed call"
        );
        let request: ExternalAgentExecutionRequest = read_json(&request_path)?;
        validate_external_agent_execution_request(&request)?;
        ensure!(
            request.requested_model == call.requested_model
                && request.prompt_sha256 == call.prompt_sha256
                && request.output_schema_sha256 == call.provider_schema_sha256,
            "external execution request differs from the sealed cognitive fields"
        );
    }
    Ok(binding)
}
