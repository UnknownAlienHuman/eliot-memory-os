use crate::{
    ActionLeaseId, AgentRole, AgentSessionId, ModuleId, PatchRunId, ProjectId, TaintClass, TaskId,
    WorkItemId, WorkLeaseId,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeMode {
    DevSingleProcess,
    Daemon,
    StdioShim,
    HookCommand,
    AdminCli,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceHealthState {
    Starting,
    Healthy,
    DegradedReadOnly,
    DegradedQueueing,
    DegradedNoDb,
    DegradedNoVerifier,
    Stopping,
    Stopped,
    Failed,
}

impl ServiceHealthState {
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Healthy)
    }

    pub const fn is_degraded(self) -> bool {
        matches!(
            self,
            Self::DegradedReadOnly
                | Self::DegradedQueueing
                | Self::DegradedNoDb
                | Self::DegradedNoVerifier
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub mode: RuntimeMode,
    pub data_root: String,
    pub log_root: String,
    pub report_root: String,
    pub spool_root: String,
    pub worktree_root: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeLoggingConfig {
    pub format: String,
    pub level: String,
    pub max_file_bytes: u64,
    pub max_files: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeIpcConfig {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeModulesConfig {
    pub enabled: bool,
    pub manifest_dir: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeLocalConfig {
    pub runtime: RuntimeConfig,
    pub logging: RuntimeLoggingConfig,
    pub ipc: RuntimeIpcConfig,
    pub modules: RuntimeModulesConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceRuntimeStatus {
    pub service_name: String,
    pub health: ServiceHealthState,
    pub started: bool,
    pub restart_budget_remaining: u32,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeStatusReport {
    pub component: String,
    pub mode: RuntimeMode,
    pub pid: u32,
    pub data_root: String,
    pub active_profile: String,
    pub single_instance_owned: bool,
    pub ipc_enabled: bool,
    pub services: Vec<ServiceRuntimeStatus>,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeHealthReport {
    pub component: String,
    pub mode: RuntimeMode,
    pub ready: bool,
    pub health: ServiceHealthState,
    pub degraded_reasons: Vec<String>,
    pub services: Vec<ServiceRuntimeStatus>,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchemaRef {
    pub schema_id: String,
    pub version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleKind {
    InternalRust,
    McpStdioAdapter,
    LocalHttpAdapter,
    CliAdapter,
    VerifierAdapter,
    CandidateAgentAdapter,
    DataImportAdapter,
    ExportAdapter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleTransport {
    InProcess,
    Stdio,
    LocalhostHttp,
    FileDrop,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleCapability {
    ReadMemory,
    WriteCandidateMemory,
    SubmitFindingCandidate,
    SubmitArtifactHandle,
    SubmitVerifierResult,
    RequestWorkLease,
    RequestWorktreeLease,
    RequestActionLease,
    RunVerifier,
    ExportReports,
    ImportData,
    HealthCheck,
}

impl ModuleCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadMemory => "read_memory",
            Self::WriteCandidateMemory => "write_candidate_memory",
            Self::SubmitFindingCandidate => "submit_finding_candidate",
            Self::SubmitArtifactHandle => "submit_artifact_handle",
            Self::SubmitVerifierResult => "submit_verifier_result",
            Self::RequestWorkLease => "request_work_lease",
            Self::RequestWorktreeLease => "request_worktree_lease",
            Self::RequestActionLease => "request_action_lease",
            Self::RunVerifier => "run_verifier",
            Self::ExportReports => "export_reports",
            Self::ImportData => "import_data",
            Self::HealthCheck => "health_check",
        }
    }

    pub fn from_wire_name(value: &str) -> Option<Self> {
        Some(match value {
            "read_memory" => Self::ReadMemory,
            "write_candidate_memory" => Self::WriteCandidateMemory,
            "submit_finding_candidate" => Self::SubmitFindingCandidate,
            "submit_artifact_handle" => Self::SubmitArtifactHandle,
            "submit_verifier_result" => Self::SubmitVerifierResult,
            "request_work_lease" => Self::RequestWorkLease,
            "request_worktree_lease" => Self::RequestWorktreeLease,
            "request_action_lease" => Self::RequestActionLease,
            "run_verifier" => Self::RunVerifier,
            "export_reports" => Self::ExportReports,
            "import_data" => Self::ImportData,
            "health_check" => Self::HealthCheck,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointDirection {
    GovernorToModule,
    ModuleToGovernor,
    Bidirectional,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModuleEndpoint {
    pub endpoint_id: String,
    pub name: String,
    pub direction: EndpointDirection,
    pub schema: SchemaRef,
    pub max_payload_bytes: usize,
    pub requires_ack: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModuleAuthorityProfile {
    pub allowed_projects: Vec<ProjectId>,
    pub allowed_roles: Vec<AgentRole>,
    pub allowed_capabilities: Vec<ModuleCapability>,
    pub can_write_truth: bool,
    pub can_request_patch: bool,
    pub can_finish_task: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModuleResourceLimits {
    pub max_runtime_seconds: u64,
    pub max_payload_bytes: usize,
    pub max_concurrent_requests: usize,
    pub idle_ttl_seconds: u64,
    pub restart_budget: u32,
}

impl Default for ModuleResourceLimits {
    fn default() -> Self {
        Self {
            max_runtime_seconds: 30,
            max_payload_bytes: 65_536,
            max_concurrent_requests: 1,
            idle_ttl_seconds: 300,
            restart_budget: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModuleManifest {
    pub module_id: ModuleId,
    pub name: String,
    pub version: String,
    pub description: String,
    pub module_kind: ModuleKind,
    pub transport: ModuleTransport,
    pub capabilities: Vec<ModuleCapability>,
    pub endpoints: Vec<ModuleEndpoint>,
    pub input_schemas: Vec<SchemaRef>,
    pub output_schemas: Vec<SchemaRef>,
    pub authority_profile: ModuleAuthorityProfile,
    pub resource_limits: ModuleResourceLimits,
    pub enabled_by_default: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModuleHealth {
    pub module_id: ModuleId,
    pub name: String,
    pub enabled: bool,
    pub health: ServiceHealthState,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModuleRegistryReport {
    pub component: String,
    pub modules: Vec<ModuleHealth>,
    pub manifests_loaded: usize,
    pub unknown_capabilities_denied: bool,
    pub authority_bypass_denied: bool,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EliotExchangeEnvelope<T> {
    pub envelope_id: String,
    pub schema_version: String,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub source: ExchangeParty,
    pub destination: ExchangeParty,
    pub kind: ExchangeKind,
    pub causality: CausalityHeader,
    pub authority: AuthorityHeader,
    pub payload: T,
    pub payload_hash: String,
    pub payload_ref: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeParty {
    Governor,
    AgentSession(AgentSessionId),
    Module(ModuleId),
    WorkItem(WorkItemId),
    ExternalCandidate(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeKind {
    MailboxMessage,
    BlackboardItem,
    ModuleHealth,
    ModuleFindingCandidate,
    ModuleArtifact,
    ModuleVerifierResult,
    ModuleLogEvent,
    ModuleError,
    RecoveryNotice,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CausalityHeader {
    pub trace_id: String,
    pub parent_envelope_id: Option<String>,
    pub causation_id: Option<String>,
    pub correlation_id: Option<String>,
    pub sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityHeader {
    pub role: Option<AgentRole>,
    pub capabilities: Vec<ModuleCapability>,
    pub lease_refs: Vec<String>,
    pub taint: TaintClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogEventKind {
    DaemonStart,
    DaemonStop,
    ServiceStart,
    ServiceStop,
    ServiceHealth,
    ModuleRegistered,
    ModuleHealth,
    MailboxDelivered,
    BlackboardUpdated,
    LeaseGranted,
    LeaseRevoked,
    PatchApplied,
    VerifierRun,
    CompletionDecision,
    RecoveryAction,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RedactionInfo {
    pub secrets_redacted: bool,
    pub raw_payload_redacted: bool,
    pub redacted_fields: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EliotLogEvent {
    pub timestamp: OffsetDateTime,
    pub level: LogLevel,
    pub target: String,
    pub message: String,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub project_id: Option<ProjectId>,
    pub task_id: Option<TaskId>,
    pub agent_session_id: Option<AgentSessionId>,
    pub work_item_id: Option<WorkItemId>,
    pub work_lease_id: Option<WorkLeaseId>,
    pub action_lease_id: Option<ActionLeaseId>,
    pub patch_run_id: Option<PatchRunId>,
    pub module_id: Option<ModuleId>,
    pub event_kind: LogEventKind,
    pub fields_ref: Option<String>,
    pub redaction: RedactionInfo,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeLogReport {
    pub component: String,
    pub log_path: String,
    pub jsonl_parse_ok: bool,
    pub event_count: usize,
    pub last_trace_id: Option<String>,
    pub redaction_checked: bool,
    pub generated_at: OffsetDateTime,
}
