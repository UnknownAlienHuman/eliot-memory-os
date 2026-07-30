use crate::{AgentHostId, AgentInvocationRequest, HostLaunchContract};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION: &str = "eliot-provider-runtime-v1";
pub const PROVIDER_RUNTIME_PREFLIGHT_SCHEMA_VERSION: &str = "eliot-provider-runtime-preflight-v1";
pub const LEGACY_COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION: &str =
    "eliot-cognitive-provider-runtime-v1";

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalAgentPurpose {
    #[default]
    ProviderSmoke,
    ExternalAudit,
    CognitiveWorker,
    UnderstandingReader,
    CognitiveJudge,
    ReasoningJob,
    CapsuleRefinement,
    UnderstandingExam,
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStructuredOutputMode {
    NativeJsonSchema,
    NativeJson,
    #[default]
    SentinelJson,
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAuthenticationState {
    Authenticated,
    Unauthenticated,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderMcpServerContract {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub required: bool,
    pub enabled: bool,
    pub executable_sha256: String,
    pub build_source_commit: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRuntimeContract {
    pub schema_version: String,
    #[schemars(with = "String")]
    pub host: AgentHostId,
    #[serde(default)]
    pub purpose: ExternalAgentPurpose,

    pub provider_executable: String,
    pub provider_executable_sha256: String,
    #[serde(default)]
    pub provider_version: String,

    #[serde(default)]
    pub requested_model: String,
    #[serde(default)]
    pub model_selection_mechanism: String,

    pub provider_cwd: String,
    pub provider_argv: Vec<String>,
    pub nonsecret_environment: BTreeMap<String, String>,

    pub mcp_servers: Vec<ProviderMcpServerContract>,
    pub expected_mcp_tool_names: Vec<String>,
    pub forbidden_mcp_server_names: Vec<String>,

    #[serde(default)]
    pub allowed_provider_tools: Vec<String>,
    #[serde(default)]
    pub denied_provider_tools: Vec<String>,
    #[serde(default)]
    pub permission_profile: String,

    #[serde(default)]
    pub structured_output_mode: ProviderStructuredOutputMode,
    #[serde(default)]
    pub output_schema_sha256: String,

    #[serde(default)]
    pub timeout_profile_ref: String,
    #[serde(default)]
    pub process_containment: String,
    #[serde(default)]
    pub candidate_only: bool,

    pub runtime_contract_sha256: String,
}

/// Legacy report shape retained only for decoding pre-HOST-CLI cognitive evidence.
///
/// New product executions must use [`ProviderRuntimeContract`].
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveProviderRuntimeContract {
    pub schema_version: String,
    #[schemars(with = "String")]
    pub host: AgentHostId,
    pub provider_executable: String,
    pub provider_executable_sha256: String,
    pub provider_cwd: String,
    pub provider_argv: Vec<String>,
    pub nonsecret_environment: BTreeMap<String, String>,
    pub mcp_servers: Vec<ProviderMcpServerContract>,
    pub expected_mcp_tool_names: Vec<String>,
    pub forbidden_mcp_server_names: Vec<String>,
    pub runtime_contract_sha256: String,
}

pub type CognitiveProviderMcpServer = ProviderMcpServerContract;

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProviderRuntimePreflightReceipt {
    pub schema_version: String,
    pub runtime_contract_sha256: String,
    pub config_list_passed: bool,
    pub mcp_process_started: bool,
    pub mcp_initialized: bool,
    pub tools_listed: bool,
    pub expected_tools_present: bool,
    pub forbidden_servers_absent: bool,
    pub scoped_status_read_passed: bool,
    pub observed_server_names: Vec<String>,
    pub observed_tool_names: Vec<String>,
    pub governor_executable_sha256: String,
    pub governor_build_source_commit: Option<String>,
    pub elapsed_ms: u64,
}

pub type CognitiveRuntimePreflightReceipt = ProviderRuntimePreflightReceipt;

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAgentExecutionRequest {
    #[schemars(with = "Value")]
    pub invocation: AgentInvocationRequest,
    #[schemars(with = "Value")]
    pub launch_contract: HostLaunchContract,
    pub purpose: ExternalAgentPurpose,

    pub prompt_ref: String,
    pub prompt_sha256: String,
    pub output_schema_ref: String,
    pub output_schema_sha256: String,

    pub requested_model: String,
    pub max_turns_or_steps: u32,
    pub timeout_profile_ref: String,

    pub allowed_provider_tools: Vec<String>,
    pub denied_provider_tools: Vec<String>,
    pub expected_mcp_tool_names: Vec<String>,
    pub forbidden_mcp_server_names: Vec<String>,

    pub read_only: bool,
    pub candidate_only: bool,
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderExecutionEvidence {
    pub runtime_contract_sha256: String,

    pub requested_model: String,
    pub resolved_model: String,
    pub provider_session_id: String,

    pub exit_code: Option<i32>,
    pub terminal_status: String,
    pub unknown_outcome: bool,

    pub structured_output: Option<Value>,
    pub structured_output_sha256: Option<String>,

    pub stdout_ref: Option<String>,
    pub stdout_sha256: Option<String>,
    pub stderr_ref: Option<String>,
    pub stderr_sha256: Option<String>,

    pub observed_mcp_server_names: Vec<String>,
    pub observed_mcp_tool_names: Vec<String>,
    pub provider_tool_call_refs: Vec<String>,

    pub changed_paths: Vec<String>,
    pub diff_ref: Option<String>,

    pub token_or_cost_telemetry: Option<String>,
    pub duration_ms: u64,
}
