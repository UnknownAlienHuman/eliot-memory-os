use crate::{
    AgentHostId, AgentInvocationRequest, AgentRole, AgentSessionHostBinding, AgentSessionId,
    AuthorityRevocationReceipt, HostLaunchContract, HostLaunchScope, OperationJob,
    OperationJobState, ProjectId, ProviderRoutePolicy, ProviderRoutePolicyBinding, TaskId,
    TaskRoleLease, WriteReceiptRef,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use time::OffsetDateTime;

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
    McpPreflight,
}

pub const OPERATION_AUTHORITY_SCHEMA_VERSION: &str = "eliot-operation-authority-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAuthorityOpenRequest {
    pub schema_version: String,
    pub operation_id: String,
    pub purpose: ExternalAgentPurpose,
    pub generation: u64,
    pub host: AgentHostId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub agent_session_id: AgentSessionId,
    pub role: AgentRole,
    pub capability_scope: Vec<String>,
    pub ttl_seconds: u64,
    pub client_instance_id: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationAuthorityOpenReceipt {
    pub operation_id: String,
    pub purpose: ExternalAgentPurpose,
    pub generation: u64,
    pub launch_scope: HostLaunchScope,
    pub operation_job_id: String,
    pub role_authority_receipt: WriteReceiptRef,
    pub host_binding_authority_receipt: WriteReceiptRef,
    pub operation_job_authority_receipt: WriteReceiptRef,
    pub state_hash: String,
    pub idempotent_replay: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub opened_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationAuthorityTerminalOutcome {
    Completed,
    FailedBeforeDispatch,
    FailedAfterDispatch,
    Cancelled,
    TimedOut,
    ReconciledUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAuthorityCloseRequest {
    pub schema_version: String,
    pub operation_id: String,
    pub purpose: ExternalAgentPurpose,
    pub generation: u64,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub agent_session_id: AgentSessionId,
    pub role_lease_id: String,
    pub expected_epoch: u64,
    pub terminal_outcome: OperationAuthorityTerminalOutcome,
    pub result_or_failure_ref: Option<String>,
    pub reason: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationAuthorityCloseReceipt {
    pub operation_id: String,
    pub purpose: ExternalAgentPurpose,
    pub generation: u64,
    pub authority_revocation_receipt: AuthorityRevocationReceipt,
    pub canonical_revoked_role_receipt: WriteReceiptRef,
    pub canonical_retired_binding_receipt: WriteReceiptRef,
    pub canonical_terminal_job_receipt: WriteReceiptRef,
    pub final_role_lease: TaskRoleLease,
    pub final_host_binding: AgentSessionHostBinding,
    pub final_operation_job: OperationJob,
    pub final_job_state: OperationJobState,
    pub state_hash: String,
    pub idempotent_replay: bool,
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
    pub provider_route_policy: ProviderRoutePolicyBinding,
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
    pub provider_route_policy: ProviderRoutePolicy,

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
    pub provider_route_policy: ProviderRoutePolicyBinding,

    pub requested_model: String,
    pub resolved_model: String,
    pub provider_session_id: String,

    pub exit_code: Option<i32>,
    pub terminal_status: String,
    pub unknown_outcome: bool,

    pub structured_output: Option<Value>,
    #[serde(default)]
    pub structured_output_ref: Option<String>,
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
