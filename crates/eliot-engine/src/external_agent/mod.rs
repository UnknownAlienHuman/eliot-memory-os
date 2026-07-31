use crate::EngineError;
use eliot_types::{
    ExternalAgentExecutionRequest, ExternalAgentPurpose, PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION,
    ProviderRuntimeContract, ProviderStructuredOutputMode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::path::{Component, Path};

mod antigravity;
mod claude_code;
mod opencode;
mod structured_output;

pub use antigravity::{
    AntigravityCommandInput, build_antigravity_command, parse_antigravity_output,
};
pub use claude_code::{
    ClaudeCodeCommandInput, build_claude_code_command, parse_claude_code_stream,
};
pub use opencode::{OpenCodeCommandInput, build_opencode_command, parse_opencode_stream};
pub use structured_output::validate_json_schema_instance;

const RAW_DATABASE_NAMES: [&str; 2] = ["eliot_surrealdb", "surrealdb"];
const SECRET_NAME_FRAGMENTS: [&str; 7] = [
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCommandPlan {
    pub argv: Vec<String>,
    pub nonsecret_environment: BTreeMap<String, String>,
    pub structured_output_mode: ProviderStructuredOutputMode,
    pub model_selection_mechanism: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderTerminalResult {
    pub structured_output: Value,
    pub resolved_model: String,
    pub provider_session_id: String,
    pub terminal_status: String,
    pub observed_tool_names: Vec<String>,
    pub token_or_cost_telemetry: Option<String>,
}

pub fn normalize_provider_runtime_contract(contract: &mut ProviderRuntimeContract) {
    contract
        .mcp_servers
        .sort_by(|left, right| left.name.cmp(&right.name));
    sort_dedup(&mut contract.expected_mcp_tool_names);
    sort_dedup(&mut contract.forbidden_mcp_server_names);
    sort_dedup(&mut contract.allowed_provider_tools);
    sort_dedup(&mut contract.denied_provider_tools);
}

pub fn computed_provider_runtime_contract_sha256(
    contract: &ProviderRuntimeContract,
) -> Result<String, EngineError> {
    let mut material = contract.clone();
    normalize_provider_runtime_contract(&mut material);
    material.runtime_contract_sha256.clear();
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&material)?)
    ))
}

pub fn seal_provider_runtime_contract(
    contract: &mut ProviderRuntimeContract,
) -> Result<(), EngineError> {
    normalize_provider_runtime_contract(contract);
    contract.runtime_contract_sha256.clear();
    contract.runtime_contract_sha256 = computed_provider_runtime_contract_sha256(contract)?;
    validate_provider_runtime_contract(contract)
}

pub fn validate_provider_runtime_contract(
    contract: &ProviderRuntimeContract,
) -> Result<(), EngineError> {
    if contract.schema_version != PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION {
        return rejected("provider runtime schema version is invalid");
    }
    let mut normalized = contract.clone();
    normalize_provider_runtime_contract(&mut normalized);
    if normalized != *contract {
        return rejected("provider runtime unordered fields are not normalized");
    }
    if !contract.candidate_only {
        return rejected("external provider runtime must be candidate-only");
    }
    if !is_sha256(&contract.provider_executable_sha256)
        || !is_sha256(&contract.output_schema_sha256)
        || !is_sha256(&contract.runtime_contract_sha256)
        || computed_provider_runtime_contract_sha256(contract)? != contract.runtime_contract_sha256
    {
        return rejected("provider runtime hash binding is invalid");
    }
    if contract.provider_version.trim().is_empty()
        || contract.requested_model.trim().is_empty()
        || contract.model_selection_mechanism.trim().is_empty()
        || contract.timeout_profile_ref.trim().is_empty()
        || contract.process_containment.trim().is_empty()
        || contract.permission_profile.trim().is_empty()
    {
        return rejected("provider runtime load-bearing fields must be non-empty");
    }
    validate_canonical_absolute_path(&contract.provider_executable, "provider executable")?;
    validate_canonical_absolute_path(&contract.provider_cwd, "provider cwd")?;
    if contract.provider_argv.is_empty() {
        return rejected("provider argv is empty");
    }
    if contract
        .nonsecret_environment
        .keys()
        .any(|name| is_secret_name(name))
    {
        return rejected("provider runtime contains a secret-like environment name");
    }
    if contract.mcp_servers.is_empty() {
        return rejected("provider runtime has no MCP server contract");
    }
    for server in &contract.mcp_servers {
        if server.enabled {
            validate_canonical_absolute_path(&server.command, "MCP executable")?;
            validate_canonical_absolute_path(&server.cwd, "MCP cwd")?;
            if !is_sha256(&server.executable_sha256) {
                return rejected("enabled MCP executable hash is invalid");
            }
        }
    }
    reject_raw_database_surface(
        contract
            .mcp_servers
            .iter()
            .filter(|server| server.enabled)
            .map(|server| server.name.as_str())
            .chain(contract.allowed_provider_tools.iter().map(String::as_str)),
    )?;
    Ok(())
}

pub fn validate_external_agent_execution_request(
    request: &ExternalAgentExecutionRequest,
) -> Result<(), EngineError> {
    let invocation = &request.invocation;
    let launch = &request.launch_contract;
    if !request.candidate_only {
        return rejected("external agent execution must be candidate-only");
    }
    if invocation.invocation_id != launch.invocation_id
        || invocation.project_id
            != launch.project_id.ok_or_else(|| {
                EngineError::WriteRejected("launch contract project_id is required".to_owned())
            })?
        || invocation.task_id
            != launch.task_id.ok_or_else(|| {
                EngineError::WriteRejected("launch contract task_id is required".to_owned())
            })?
        || invocation.work_item_id
            != launch.work_item_id.ok_or_else(|| {
                EngineError::WriteRejected("launch contract work_item_id is required".to_owned())
            })?
        || invocation.role_lease_id != launch.role_lease_id.clone().unwrap_or_default()
        || invocation.role_lease_epoch != launch.role_lease_epoch
        || invocation.operation_generation != launch.operation_generation
        || invocation.idempotency_key != launch.idempotency_key
    {
        return rejected("execution request and launch authority do not agree");
    }
    if launch.agent_session_id.is_none()
        || launch
            .role_lease_id
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        || launch.role_lease_epoch == 0
        || launch.operation_generation == 0
        || request.prompt_ref.trim().is_empty()
        || request.output_schema_ref.trim().is_empty()
        || !is_sha256(&request.prompt_sha256)
        || !is_sha256(&request.output_schema_sha256)
        || request.requested_model.trim().is_empty()
        || request.timeout_profile_ref.trim().is_empty()
        || request.max_turns_or_steps == 0
    {
        return rejected("execution request is missing a required sealed binding");
    }
    if launch
        .model_route_if_selected
        .as_deref()
        .is_some_and(|model| model != request.requested_model)
    {
        return rejected("requested model differs from the sealed launch model");
    }
    reject_raw_database_surface(
        request
            .allowed_provider_tools
            .iter()
            .map(String::as_str)
            .chain(request.expected_mcp_tool_names.iter().map(String::as_str)),
    )?;
    if request.allowed_provider_tools.len() > 64
        || request.denied_provider_tools.len() > 64
        || request.expected_mcp_tool_names.len() > 64
        || request.forbidden_mcp_server_names.len() > 64
    {
        return rejected("provider tool or server bounds exceed 64 entries");
    }
    if matches!(
        request.purpose,
        ExternalAgentPurpose::UnderstandingReader | ExternalAgentPurpose::CognitiveJudge
    ) && (!request.read_only || !launch.allowed_paths.is_empty())
    {
        return rejected("Reader and Judge execution must be read-only");
    }
    if request.purpose == ExternalAgentPurpose::CognitiveWorker
        && (request.read_only || launch.allowed_paths.is_empty() || launch.work_lease_id.is_none())
    {
        return rejected("cognitive Worker requires a bounded write lease");
    }
    Ok(())
}

fn validate_canonical_absolute_path(value: &str, label: &str) -> Result<(), EngineError> {
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return rejected(format!("{label} is not a canonical absolute path"));
    }
    Ok(())
}

pub fn reject_raw_database_surface<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<(), EngineError> {
    if values
        .map(str::to_ascii_lowercase)
        .any(|value| RAW_DATABASE_NAMES.iter().any(|name| value.contains(name)))
    {
        return rejected("raw SurrealDB provider surface is forbidden");
    }
    Ok(())
}

fn is_secret_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SECRET_NAME_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sort_dedup(values: &mut Vec<String>) {
    values.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    values.dedup();
}

pub(super) fn rejected<T>(message: impl Into<String>) -> Result<T, EngineError> {
    Err(EngineError::WriteRejected(message.into()))
}
