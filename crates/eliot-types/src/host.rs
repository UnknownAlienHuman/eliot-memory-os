use crate::{
    AgentRole, AgentSessionId, OperationPhase, ProjectId, TaintClass, TaskId, WorkItemId,
    WorkLeaseId, WorktreeLeaseId, WriteReceiptRef,
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

/// Which packaged surface of the Claude host family an operation targets.
///
/// `AgentHostId::Claude` is the vendor: one host family, one Governor
/// authority. It ships as two packages with genuinely different capabilities,
/// and treating them as one blurred surface is what allowed a single session to
/// bind both and see the tool set twice. The distinction is explicit here so it
/// stops being carried around as a magic host string.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeSurface {
    /// Claude Code plugin: MCP server, skills, and lifecycle hooks.
    ClaudeCodePlugin,
    /// Claude Desktop MCPB: MCP tools, prompts, and server instructions.
    /// Desktop has no Claude Code lifecycle hooks and must not claim them.
    ClaudeDesktopMcpb,
}

impl ClaudeSurface {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCodePlugin => "claude_code_plugin",
            Self::ClaudeDesktopMcpb => "claude_desktop_mcpb",
        }
    }

    /// Parses a surface selector.
    ///
    /// `claude-desktop` and `claude_desktop` were historically host strings of
    /// their own, which made the Desktop package look like a separate vendor.
    /// They are still accepted so existing scripts and receipts keep resolving,
    /// but [`Self::as_str`] never emits them as the current spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "code" | "claude_code" | "claude_code_plugin" => Some(Self::ClaudeCodePlugin),
            "desktop" | "claude_desktop" | "claude_desktop_mcpb" => Some(Self::ClaudeDesktopMcpb),
            _ => None,
        }
    }

    /// True when this surface can enforce Claude Code lifecycle hooks.
    #[must_use]
    pub const fn supports_lifecycle_hooks(self) -> bool {
        matches!(self, Self::ClaudeCodePlugin)
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSessionState {
    #[default]
    Active,
    Disconnected,
    Retired,
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
    #[serde(default)]
    pub state: AgentSessionState,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub owner_operation_id: Option<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub disconnected_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub disconnect_reason: Option<String>,
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
    #[serde(default)]
    pub role_lease_epoch: u64,
    #[serde(default)]
    pub operation_generation: u64,
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
    #[serde(default)]
    pub role_lease_epoch: u64,
    #[serde(default)]
    pub operation_generation: u64,
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
    #[serde(default)]
    pub role_lease_epoch: u64,
    #[serde(default)]
    pub operation_generation: u64,
    #[serde(default)]
    pub runtime_contract_sha256: Option<String>,
    pub work_lease_id: Option<WorkLeaseId>,
    pub packet_refs: Vec<String>,
    pub expected_result_kind: String,
    pub verifier_ref: String,
    pub idempotency_key: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityLeaseState {
    Pending,
    #[default]
    Active,
    Consumed,
    Revoked,
    Expired,
}

#[derive(
    Clone, Copy, Debug, Default, Eq, schemars::JsonSchema, PartialEq, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityLeaseLifetime {
    #[default]
    Legacy,
    Persistent,
    OperationBound,
    SealBound,
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
    #[serde(default)]
    pub state: AuthorityLeaseState,
    #[serde(default)]
    pub lifetime: AuthorityLeaseLifetime,
    #[serde(default)]
    pub owner_operation_id: Option<String>,
    #[serde(default)]
    pub seal_attempt_id: Option<String>,
    #[serde(default)]
    pub generation: u64,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub issued_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub activated_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub consumed_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub revoke_reason: Option<String>,
    #[serde(default)]
    pub superseded_by_epoch: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControllerLease {
    pub controller_lease_id: String,
    pub task_id: TaskId,
    pub agent_session_id: AgentSessionId,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub epoch: u64,
    #[serde(default)]
    pub state: AuthorityLeaseState,
    #[serde(default)]
    pub lifetime: AuthorityLeaseLifetime,
    #[serde(default)]
    pub owner_operation_id: Option<String>,
    #[serde(default)]
    pub seal_attempt_id: Option<String>,
    #[serde(default)]
    pub generation: u64,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub issued_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub activated_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub revoke_reason: Option<String>,
    #[serde(default)]
    pub superseded_by_epoch: Option<u64>,
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
    #[serde(default)]
    pub role_lease_epoch: u64,
    #[serde(default)]
    pub operation_generation: u64,
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
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub phase: OperationPhase,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub phase_started_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_progress_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub phase_deadline_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub absolute_deadline_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub restart_count: u32,
    #[serde(default)]
    pub runtime_contract_sha256: Option<String>,
    #[serde(default)]
    pub role_lease_id: Option<String>,
    #[serde(default)]
    pub role_lease_epoch: Option<u64>,
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
    Cancelled,
    Abandoned,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityRevocationReceipt {
    pub receipt_id: String,
    pub role_lease_id: String,
    pub prior_epoch: u64,
    pub prior_generation: u64,
    pub task_id: TaskId,
    pub agent_session_id: AgentSessionId,
    pub reason: String,
    pub owner_operation_id: Option<String>,
    pub seal_attempt_id: Option<String>,
    pub superseded_by_epoch: Option<u64>,
    #[serde(with = "time::serde::rfc3339")]
    pub revoked_at: OffsetDateTime,
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

#[cfg(test)]
mod claude_surface_tests {
    use super::{AgentHostId, AuthorityLeaseLifetime, ClaudeSurface};

    #[test]
    fn authority_lifetime_legacy_decode_and_explicit_variants_are_stable() {
        assert_eq!(
            serde_json::from_str::<AuthorityLeaseLifetime>("\"operation_bound\"")
                .expect("decode operation-bound lifetime"),
            AuthorityLeaseLifetime::OperationBound
        );
        assert_eq!(
            serde_json::from_str::<AuthorityLeaseLifetime>("\"seal_bound\"")
                .expect("decode seal-bound lifetime"),
            AuthorityLeaseLifetime::SealBound
        );
        assert_eq!(
            AuthorityLeaseLifetime::default(),
            AuthorityLeaseLifetime::Legacy
        );
    }

    /// One vendor, two packages. The family never becomes two hosts.
    #[test]
    fn both_surfaces_belong_to_the_same_host_family() {
        assert_eq!(AgentHostId::Claude.as_str(), "claude");
        assert_ne!(
            ClaudeSurface::ClaudeCodePlugin.as_str(),
            ClaudeSurface::ClaudeDesktopMcpb.as_str()
        );
    }

    /// `claude-desktop` used to be a host string of its own. It must keep
    /// resolving so existing scripts and receipts still work.
    #[test]
    fn the_retired_desktop_host_spellings_still_resolve() {
        for spelling in [
            "desktop",
            "claude_desktop",
            "claude-desktop",
            "claude_desktop_mcpb",
            "CLAUDE-DESKTOP",
            "  desktop  ",
        ] {
            assert_eq!(
                ClaudeSurface::parse(spelling),
                Some(ClaudeSurface::ClaudeDesktopMcpb),
                "{spelling} must resolve to the Desktop surface"
            );
        }
        for spelling in ["code", "claude_code", "claude-code", "claude_code_plugin"] {
            assert_eq!(
                ClaudeSurface::parse(spelling),
                Some(ClaudeSurface::ClaudeCodePlugin),
                "{spelling} must resolve to the Code surface"
            );
        }
        assert_eq!(ClaudeSurface::parse("opencode"), None);
    }

    /// The retired spelling resolves but is never written back out.
    #[test]
    fn the_retired_spelling_is_never_emitted_as_the_current_name() {
        assert_eq!(
            ClaudeSurface::parse("claude-desktop"),
            Some(ClaudeSurface::ClaudeDesktopMcpb)
        );
        assert_ne!(ClaudeSurface::ClaudeDesktopMcpb.as_str(), "claude-desktop");
    }

    /// Desktop ships MCP tools and prompts. It does not get Claude Code
    /// lifecycle hooks, and must never be described as if it did.
    #[test]
    fn only_the_code_surface_claims_lifecycle_hooks() {
        assert!(ClaudeSurface::ClaudeCodePlugin.supports_lifecycle_hooks());
        assert!(!ClaudeSurface::ClaudeDesktopMcpb.supports_lifecycle_hooks());
    }

    #[test]
    fn surfaces_round_trip_through_serde() -> Result<(), serde_json::Error> {
        for surface in [
            ClaudeSurface::ClaudeCodePlugin,
            ClaudeSurface::ClaudeDesktopMcpb,
        ] {
            let json = serde_json::to_string(&surface)?;
            assert_eq!(json, format!("\"{}\"", surface.as_str()));
            assert_eq!(serde_json::from_str::<ClaudeSurface>(&json)?, surface);
        }
        Ok(())
    }
}
