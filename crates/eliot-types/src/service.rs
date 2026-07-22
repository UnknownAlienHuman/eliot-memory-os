use crate::{PathRef, RuntimeMode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WindowsServiceConfig {
    pub service_name: String,
    pub display_name: String,
    pub description: String,
    pub executable_path: PathRef,
    pub arguments: Vec<String>,
    pub account: ServiceAccountRef,
    pub start_type: ServiceStartType,
    pub restart_policy: ServiceRestartPolicy,
    pub data_root: PathRef,
    pub log_root: PathRef,
    pub ipc: IpcConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceAccountRef {
    CurrentUser,
    LocalService,
    NamedServiceAccount(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceStartType {
    Manual,
    Automatic,
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceRestartPolicy {
    pub enabled: bool,
    pub max_restarts_per_window: u32,
    pub window_seconds: u64,
    pub backoff_seconds: u64,
    pub open_incident_on_exhaustion: bool,
}

impl Default for ServiceRestartPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_restarts_per_window: 1,
            window_seconds: 900,
            backoff_seconds: 30,
            open_incident_on_exhaustion: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceInstallReceipt {
    pub receipt_id: String,
    pub service_name: String,
    pub action: ServiceInstallAction,
    pub status: ServiceInstallStatus,
    pub config_ref: String,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceInstallAction {
    Validate,
    Install,
    Uninstall,
    Start,
    Stop,
    Restart,
    Status,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceInstallStatus {
    Succeeded,
    SucceededWithWarnings,
    Failed,
    DryRun,
    NotSupportedOnThisPlatform,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpcConfig {
    pub pipe_name: String,
    pub token_file: PathRef,
    pub max_frame_bytes: usize,
    pub request_timeout_ms: u64,
    pub allowed_client_sids: Vec<String>,
    pub require_handshake: bool,
    pub bind_local_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpcAuthenticationProfile {
    pub protocol_version: String,
    pub pipe_name: String,
    pub server_identity: String,
    pub allowed_windows_sid_or_user: String,
    pub token_generation: String,
    pub token_storage_ref: PathRef,
    pub token_permissions: String,
    pub token_generation_id: String,
    pub handshake_deadline_ms: u64,
    pub max_frame_bytes: usize,
    pub max_in_flight: usize,
    pub replay_policy: String,
    pub rotation_policy: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpcHandshake {
    pub protocol_version: String,
    pub client_id: String,
    pub runtime_mode: RuntimeMode,
    pub token_hash: String,
    pub requested_capabilities: Vec<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpcHandshakeDecision {
    pub decision_id: String,
    pub accepted: bool,
    pub reasons: Vec<IpcHandshakeReason>,
    pub granted_capabilities: Vec<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcHandshakeReason {
    ProtocolAccepted,
    ProtocolMismatch,
    MissingToken,
    InvalidToken,
    ClientNotAllowed,
    CapabilityDenied,
    RuntimeModeDenied,
    PipeAclDenied,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IpcFrame {
    pub frame_id: String,
    pub protocol_version: String,
    pub trace_id: String,
    pub request_id: String,
    pub kind: IpcFrameKind,
    pub payload_ref: Option<String>,
    pub payload_inline: Option<Value>,
    pub payload_hash: String,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcFrameKind {
    Handshake,
    McpRequest,
    HookEvent,
    AdminRequest,
    HealthRequest,
    EventNotification,
    ErrorResponse,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialRef {
    pub credential_id: String,
    pub provider: CredentialProviderKind,
    pub purpose: CredentialPurpose,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProviderKind {
    WindowsCredentialManager,
    DpapiProtectedFile,
    ServiceEnvironment,
    TestInMemory,
    LegacyPasswordFile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPurpose {
    SurrealDbRuntime,
    IpcHandshakeToken,
    AdapterProviderToken,
    BackupEncryptionKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceReadinessProbe {
    pub probe_id: String,
    pub service_name: String,
    pub checks: Vec<ServiceReadinessCheck>,
    pub status: ServiceReadinessStatus,
    pub started_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceReadinessCheck {
    DataRootValidated,
    CredentialRefsResolved,
    SurrealDbReachable,
    WriterSelfCheckPassed,
    ReadSelfCheckPassed,
    IpcServerListening,
    FastDeterministicEvalGatePassed,
    NoBlockingIncidents,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceReadinessStatus {
    Ready,
    DegradedReadOnly,
    DegradedQueueing,
    NotReady,
    IncidentLockdown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceRestartReceipt {
    pub receipt_id: String,
    pub service_name: String,
    pub reason: ServiceRestartReason,
    pub attempt_number: u32,
    pub budget_remaining: u32,
    pub status: ServiceRestartStatus,
    pub incident_ref: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRestartReason {
    HealthcheckFailed,
    IpcServerFailed,
    DbHealthFailed,
    ConfigChangedRestartRequired,
    ManualAdminRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRestartStatus {
    Attempted,
    Succeeded,
    Failed,
    BudgetExhaustedIncidentOpened,
    DeniedByPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StartupRecoveryReceipt {
    pub receipt_id: String,
    pub data_root: PathRef,
    pub unclean_shutdown_detected: bool,
    pub wal_recovered: bool,
    pub outbox_reconciled: bool,
    pub stale_locks_removed: Vec<PathRef>,
    pub incidents_opened: Vec<String>,
    pub status: StartupRecoveryStatus,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupRecoveryStatus {
    Clean,
    Recovered,
    RecoveredWithWarnings,
    Failed,
    IncidentLockdown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceStatusReport {
    pub component: String,
    pub config: WindowsServiceConfig,
    pub installed: bool,
    pub running: bool,
    pub install_receipt: ServiceInstallReceipt,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpcStatusReport {
    pub component: String,
    pub pipe_name: String,
    pub transport: String,
    pub listening: bool,
    pub bind_local_only: bool,
    pub max_frame_bytes: usize,
    pub handshake_required: bool,
    pub last_handshake: Option<IpcHandshakeDecision>,
    pub warnings: Vec<String>,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialDiagnosticsReport {
    pub component: String,
    pub refs: Vec<CredentialRef>,
    #[serde(default)]
    pub statuses: Vec<CredentialStatus>,
    pub resolved_count: usize,
    pub secret_values_redacted: bool,
    pub toml_contains_secret_values: bool,
    pub command_line_contains_secret_values: bool,
    pub warnings: Vec<String>,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub credential_id: String,
    pub provider: CredentialProviderKind,
    pub present: bool,
    pub version: Option<String>,
    pub fingerprint: Option<String>,
}
