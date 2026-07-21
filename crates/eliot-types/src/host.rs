use crate::{
    AgentRole, AgentSessionId, ProjectId, TaintClass, TaskId, WorkItemId, WorkLeaseId,
    WorktreeLeaseId, WriteReceiptRef,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentHostId {
    Codex,
    Antigravity,
    #[serde(rename = "opencode")]
    OpenCode,
    Claude,
}

impl AgentHostId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Antigravity => "antigravity",
            Self::OpenCode => "opencode",
            Self::Claude => "claude",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostMode {
    Interactive,
    Supervised,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostProfileStatus {
    Current,
    Stale,
    Unsupported,
    Degraded,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct HostProtocolSurfaces {
    pub mcp_stdio: bool,
    pub mcp_http: bool,
    pub acp_or_sdk: bool,
    pub plugin: bool,
    pub hooks_or_events: bool,
    pub skills: bool,
    pub structured_output: bool,
    pub worktree: bool,
    pub permissions: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentHostRuntimeProfile {
    pub host_id: AgentHostId,
    pub implementation_name: String,
    pub executable_path: String,
    pub executable_hash: String,
    pub version: String,
    #[serde(with = "time::serde::rfc3339")]
    pub discovered_at: OffsetDateTime,
    pub supported_modes: Vec<String>,
    pub protocol_surfaces: HostProtocolSurfaces,
    pub launch_capabilities: Vec<String>,
    pub result_capture: Vec<String>,
    pub resume_contract: String,
    pub timeout_and_unknown_outcome_contract: String,
    pub known_version_constraints: Vec<String>,
    pub operator_configuration_refs: Vec<String>,
    pub capability_probe_receipt: String,
    pub status: HostProfileStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentHostIdentity {
    pub host_id: AgentHostId,
    pub implementation_name: String,
    pub client_instance_id: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct AgentCapabilityEnvelope {
    pub capabilities: Vec<String>,
    pub structured_output: bool,
    pub resumable: bool,
    pub interactive: bool,
    pub supervised: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentSessionHostBinding {
    pub agent_session_id: AgentSessionId,
    pub host_identity: AgentHostIdentity,
    pub capability_envelope: AgentCapabilityEnvelope,
    #[serde(default)]
    pub bound_project_id: Option<ProjectId>,
    #[serde(default)]
    pub bound_task_id: Option<TaskId>,
    pub task_role_lease_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostLaunchContract {
    pub invocation_id: String,
    pub host_profile_ref: String,
    pub mode: HostMode,
    #[serde(default)]
    pub project_id: Option<ProjectId>,
    pub agent_session_id: Option<AgentSessionId>,
    pub task_id: Option<TaskId>,
    pub work_item_id: Option<WorkItemId>,
    pub role_lease_id: Option<String>,
    pub work_lease_id: Option<WorkLeaseId>,
    #[serde(default)]
    pub worktree_lease_id: Option<WorktreeLeaseId>,
    #[serde(default)]
    pub planned_verifier_ref: Option<String>,
    pub cwd_or_worktree: String,
    pub baseline_commit: Option<String>,
    pub allowed_paths: Vec<String>,
    pub forbidden_paths: Vec<String>,
    pub integration_bundle_ref: String,
    pub mcp_config_ref: String,
    pub skill_bundle_ref: String,
    pub lifecycle_bridge_ref: String,
    pub environment_allowlist: Vec<String>,
    pub permission_profile: String,
    pub model_route_if_selected: Option<String>,
    pub max_turns_or_steps: Option<u32>,
    pub wall_clock_budget_seconds: u64,
    pub cost_budget_if_supported: Option<String>,
    pub session_id: Option<String>,
    pub resume_policy: String,
    pub structured_output_schema_ref: Option<String>,
    pub stdout_stderr_spool: String,
    pub artifact_manifest_ref: String,
    pub idempotency_key: String,
    pub expected_result_kind: String,
    pub contract_hash: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostLaunchScope {
    #[serde(default)]
    pub project_id: Option<ProjectId>,
    pub agent_session_id: Option<AgentSessionId>,
    pub task_id: Option<TaskId>,
    pub work_item_id: Option<WorkItemId>,
    pub role_lease_id: Option<String>,
    pub work_lease_id: Option<WorkLeaseId>,
    #[serde(default)]
    pub worktree_lease_id: Option<WorktreeLeaseId>,
    #[serde(default)]
    pub planned_verifier_ref: Option<String>,
    pub baseline_commit: Option<String>,
    pub allowed_paths: Vec<String>,
    pub forbidden_paths: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostEventEnvelope {
    pub host_id: AgentHostId,
    pub host_session_id: Option<String>,
    pub eliot_session_id: Option<AgentSessionId>,
    pub task_id: Option<TaskId>,
    pub work_item_id: Option<WorkItemId>,
    pub event_kind: String,
    #[serde(with = "time::serde::rfc3339")]
    pub event_time: OffsetDateTime,
    pub tool_or_command: Option<String>,
    pub normalized_input_hash: String,
    pub output_or_error_ref: Option<String>,
    pub changed_path_refs: Vec<String>,
    pub permission_event: Option<String>,
    pub compaction_or_resume: Option<String>,
    pub raw_event_ref: Option<String>,
    pub taint: TaintClass,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentInvocationRequest {
    pub invocation_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub work_item_id: WorkItemId,
    pub requested_capabilities: Vec<String>,
    pub role_lease_id: String,
    pub work_lease_id: Option<WorkLeaseId>,
    pub packet_refs: Vec<String>,
    pub expected_result_kind: String,
    pub verifier_ref: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaskRoleLease {
    pub role_lease_id: String,
    pub task_id: TaskId,
    pub agent_session_id: AgentSessionId,
    pub role: AgentRole,
    pub capability_scope: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControllerLease {
    pub controller_lease_id: String,
    pub task_id: TaskId,
    pub agent_session_id: AgentSessionId,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentResultStatus {
    Succeeded,
    Partial,
    Blocked,
    Failed,
    TimedOut,
    UnknownOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentResultEnvelope {
    pub result_id: String,
    pub invocation_id: String,
    pub host_id: AgentHostId,
    pub host_session_id: Option<String>,
    pub status: AgentResultStatus,
    pub summary: String,
    pub artifact_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub verifier_refs: Vec<String>,
    pub candidate_only: bool,
    pub exit_status: Option<i32>,
    pub token_or_cost_telemetry: Option<String>,
    pub unknown_outcome_evidence_refs: Vec<String>,
    #[serde(default)]
    pub supersedes_result_id: Option<String>,
    #[serde(default)]
    pub provider_output_hash: Option<String>,
    #[serde(default)]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentResultDispositionKind {
    Accepted,
    Rejected,
    ProbeRequested,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentResultDisposition {
    pub disposition_id: String,
    pub result_id: String,
    pub invocation_id: String,
    pub task_id: TaskId,
    pub controller_session_id: AgentSessionId,
    pub kind: AgentResultDispositionKind,
    pub reason: String,
    pub evidence_refs: Vec<String>,
    pub idempotency_key: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default)]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationJob {
    pub job_id: String,
    pub invocation_id: String,
    pub host_id: AgentHostId,
    pub state: OperationJobState,
    pub attempt: u32,
    pub resume_session_id: Option<String>,
    pub result_ref: Option<String>,
    pub idempotency_key: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationJobState {
    Queued,
    Running,
    Completed,
    Failed,
    TimedOut,
    UnknownOutcome,
    Reconciled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostIntegrationReceipt {
    pub receipt_id: String,
    pub host_id: AgentHostId,
    pub host_version: String,
    pub scope: String,
    pub installed_paths: Vec<String>,
    pub modified_files: Vec<String>,
    pub before_hashes: Vec<String>,
    pub after_hashes: Vec<String>,
    pub backup_refs: Vec<String>,
    pub integration_bundle_hash: String,
    pub skill_pack_hash: String,
    pub mcp_config_hash: String,
    pub lifecycle_bridge_hash: String,
    pub rollback_command: String,
    #[serde(with = "time::serde::rfc3339")]
    pub verified_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostContextFootprintReport {
    pub host_id: AgentHostId,
    pub host_version: String,
    pub always_on_instruction_bytes: usize,
    pub skill_count_visible: usize,
    pub skill_listing_characters: usize,
    pub skills_loaded: Vec<String>,
    pub loaded_skill_bytes_or_estimated_tokens: Option<usize>,
    pub eliot_tools_visible_or_deferred: String,
    pub mcp_schema_bytes_if_measurable: Option<usize>,
    pub packet_bytes: Option<usize>,
    pub supporting_files_loaded: Vec<String>,
    pub unrelated_architecture_docs_loaded: bool,
    pub result: String,
}
