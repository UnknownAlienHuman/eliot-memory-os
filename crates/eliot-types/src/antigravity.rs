use crate::{
    BlobRef, CandidateDiffId, CandidateDiffStatus, ExternalReviewResult, PathRef, ProjectId,
    TaintClass, TaskId, WorkLeaseId, WorktreeLeaseId, WorktreeLeaseState, WriteReceiptRef,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityBinaryResolverConfig {
    pub explicit_binary: Option<PathRef>,
    pub search_path_names: Vec<String>,
    pub reject_temp_download_paths: bool,
    pub allow_install: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityBinaryCandidateSource {
    ExplicitConfig,
    WhereAgy,
    WhereAntigravity,
    LocalAppDataOfficialInstall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityBinarySignatureStatus {
    Valid,
    NotSigned,
    Invalid,
    Unavailable,
    NotChecked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityBinaryResolutionStatus {
    Resolved,
    NotFound,
    Rejected,
    Ambiguous,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityTrustReceipt {
    pub candidate_path: PathRef,
    pub canonical_path: Option<PathRef>,
    pub source: AntigravityBinaryCandidateSource,
    pub accepted: bool,
    pub signature_status: AntigravityBinarySignatureStatus,
    pub signature_subject: Option<String>,
    pub reasons: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityBinaryCandidate {
    pub path: PathRef,
    pub canonical_path: Option<PathRef>,
    pub source: AntigravityBinaryCandidateSource,
    pub accepted: bool,
    pub signature_status: AntigravityBinarySignatureStatus,
    pub signature_subject: Option<String>,
    pub rejection_reasons: Vec<String>,
    pub trust_receipt: AntigravityTrustReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityBinaryResolution {
    pub status: AntigravityBinaryResolutionStatus,
    pub selected_path: Option<PathRef>,
    pub candidates: Vec<AntigravityBinaryCandidate>,
    pub detection_commands: Vec<String>,
    pub install_attempted: bool,
    pub plain_agy_invoked: bool,
    pub message: String,
    #[serde(with = "time::serde::rfc3339")]
    pub resolved_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityGuiProcessProbe {
    pub component: String,
    pub process_names_checked: Vec<String>,
    pub matching_processes: Vec<String>,
    pub gui_running: bool,
    pub command_invoked: Option<String>,
    pub probe_succeeded: bool,
    pub warnings: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityWindowsInstallDiscovery {
    pub component: String,
    pub local_app_data: Option<PathRef>,
    pub official_cli_path: Option<PathRef>,
    pub official_cli_exists: bool,
    pub candidate_source: AntigravityBinaryCandidateSource,
    pub signature_status: AntigravityBinarySignatureStatus,
    pub signature_subject: Option<String>,
    pub detection_only: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub discovered_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityVersionGateStatus {
    Compatible,
    TooOld,
    Unparseable,
    ProbeFailed,
    ProbeTimedOut,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityVersionGateResult {
    pub component: String,
    pub command: String,
    pub raw_output: String,
    pub parsed_version: Option<String>,
    pub minimum_version: String,
    pub status: AntigravityVersionGateStatus,
    pub allowed: bool,
    pub reasons: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct AntigravityOfficialCliInstallerReceipt {
    pub component: String,
    pub installer_url: String,
    pub installed_path: PathRef,
    pub attempted: bool,
    pub installed: bool,
    pub signature_verified: bool,
    pub version_gate_passed: bool,
    pub install_command_exposed: bool,
    pub reasons: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityProviderState {
    NotInstalled,
    DetectedDisabled,
    DetectedButUnauthenticated,
    DetectedButNoNonInteractiveMode,
    DetectedTextOnlyOutput,
    ReadyDisabled,
    ReadyEnabled,
    BlockedByPolicy,
    Incompatible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityEnablementState {
    NotInstalled,
    InstalledNotAuthenticated,
    InstalledNoNonInteractiveMode,
    ReadyDisabled,
    EnableRequested,
    #[serde(alias = "enabled_for_read_only_smoke")]
    EnabledForDisposableWorktreeAudit,
    #[serde(alias = "enabled_for_worktree_candidate_smoke")]
    EnabledForDisposableWorktreeCandidateSmoke,
    EnabledPersistentByAdminReceipt,
    DisabledAfterSmoke,
    BlockedByPolicy,
    FailedLiveSmoke,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityEnablementScope {
    #[serde(alias = "read_only_smoke_only")]
    DisposableWorktreeAuditOnly,
    #[serde(alias = "worktree_candidate_smoke_only")]
    DisposableWorktreeCandidateOnly,
    SessionOnly,
    PersistentLocalAdmin,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityEnablementReceipt {
    pub receipt_id: String,
    pub provider_id: String,
    pub requested_state: AntigravityEnablementState,
    pub previous_state: AntigravityEnablementState,
    pub approved_by: String,
    pub approval_scope: AntigravityEnablementScope,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub reasons: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityAuthCheckMethod {
    HelpOnlyNoAuthCheck,
    NonInteractivePrintProbe,
    LogInferenceNoTokenRead,
    ManualUserReported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityAuthStatus {
    Unknown,
    Authenticated,
    NotAuthenticated,
    AuthTimeout,
    RegionOrPlanUnavailable,
    ProviderError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityAuthCheck {
    pub check_id: String,
    pub provider_id: String,
    pub method: AntigravityAuthCheckMethod,
    pub status: AntigravityAuthStatus,
    pub evidence_refs: Vec<String>,
    pub warnings: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityLiveSmokeMode {
    #[serde(alias = "read_only_audit")]
    DisposableWorktreeAudit,
    #[serde(alias = "worktree_candidate_no_apply")]
    DisposableWorktreeCandidateNoApply,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityLiveSmokeRequest {
    pub smoke_id: String,
    pub mode: AntigravityLiveSmokeMode,
    pub project_id: ProjectId,
    pub work_lease_ref: WorkLeaseId,
    pub worktree_lease_ref: Option<WorktreeLeaseId>,
    pub prompt_ref: String,
    pub expected_marker: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityLiveSmokeStatus {
    Passed,
    Failed,
    ProviderUnavailable,
    NotAuthenticated,
    Timeout,
    MalformedOutput,
    PolicyBlocked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityLiveSmokeResult {
    pub result_id: String,
    pub smoke_ref: String,
    pub run_ref: String,
    pub status: AntigravityLiveSmokeStatus,
    pub marker_seen: bool,
    pub mcp_call_marker_seen: bool,
    pub output_blob_ref: Option<String>,
    pub normalized_result_ref: Option<String>,
    pub telemetry_refs: Vec<String>,
    pub warnings: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityMcpConfigSurface {
    Gui,
    Cli,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct AntigravityMcpConfigStatus {
    pub component: String,
    pub surface: AntigravityMcpConfigSurface,
    pub config_path: PathRef,
    pub exists: bool,
    pub registered: bool,
    pub command: Option<PathRef>,
    pub command_absolute: bool,
    pub profile_args_exact: bool,
    pub secret_fields_present: bool,
    pub recursion_detected: bool,
    pub error: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct AntigravityMcpRegistrationReceipt {
    pub component: String,
    pub surface: AntigravityMcpConfigSurface,
    pub config_path: PathRef,
    pub backup_path: Option<PathRef>,
    pub server_name: String,
    pub command: PathRef,
    pub args: Vec<String>,
    pub merged: bool,
    pub atomic_write: bool,
    pub unknown_fields_preserved: bool,
    pub unknown_servers_preserved: bool,
    pub secret_values_written: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityMcpInvocationReceipt {
    pub component: String,
    pub profile: String,
    pub tool_name: String,
    pub succeeded: bool,
    pub matching_audit_event: bool,
    pub audit_event_ref: Option<String>,
    pub candidate_only: bool,
    pub authority: String,
    #[serde(with = "time::serde::rfc3339")]
    pub invoked_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct AntigravityOfficialPluginStatus {
    pub component: String,
    pub gui_plugin_root: PathRef,
    pub cli_plugin_root: PathRef,
    pub gui_installed: bool,
    pub cli_installed: bool,
    pub official_schema_valid: bool,
    pub mcp_config_present: bool,
    pub skill_visible: bool,
    pub agent_visible: bool,
    pub rule_visible: bool,
    pub warnings: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct AntigravityOfficialPluginInstallReceipt {
    pub component: String,
    pub plugin_name: String,
    pub gui_plugin_root: PathRef,
    pub cli_plugin_root: PathRef,
    pub attempted: bool,
    pub install_command_succeeded: bool,
    pub listed_by_agy: bool,
    pub installed: bool,
    pub files_written: Vec<PathRef>,
    pub official_schema_valid: bool,
    pub agent_visible: bool,
    pub skill_visible: bool,
    pub reasons: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityLiveTreeSnapshot {
    pub repo_root: PathRef,
    pub head: String,
    pub status_porcelain: String,
    pub binary_diff_hash: String,
    pub binary_diff_bytes: usize,
    #[serde(with = "time::serde::rfc3339")]
    pub captured_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AntigravityDisposableWorktreeSmokeEvidence {
    pub component: String,
    pub work_lease_id: WorkLeaseId,
    pub worktree_lease_id: WorktreeLeaseId,
    pub worktree_path: PathRef,
    pub live_before: AntigravityLiveTreeSnapshot,
    pub live_after: AntigravityLiveTreeSnapshot,
    pub live_tree_unchanged: bool,
    pub candidate_diff_id: CandidateDiffId,
    pub candidate_diff_status: CandidateDiffStatus,
    pub cleanup_state: WorktreeLeaseState,
    pub marker_seen: bool,
    pub candidate_only: bool,
    pub taint: TaintClass,
    pub warnings: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AntigravityVisibilityReport {
    pub component: String,
    pub gui: AntigravityGuiProcessProbe,
    pub windows_install: AntigravityWindowsInstallDiscovery,
    pub version_gate: Option<AntigravityVersionGateResult>,
    pub mcp_configs: Vec<AntigravityMcpConfigStatus>,
    pub mcp_invocation: Option<AntigravityMcpInvocationReceipt>,
    pub official_plugin: AntigravityOfficialPluginStatus,
    pub live_smoke: Option<AntigravityLiveSmokeResult>,
    pub disposable_worktree_smoke: Option<AntigravityDisposableWorktreeSmokeEvidence>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityDisableReceipt {
    pub receipt_id: String,
    pub provider_id: String,
    pub previous_state: AntigravityEnablementState,
    pub new_state: AntigravityEnablementState,
    pub reason: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct AntigravityCapabilities {
    pub print_mode: bool,
    pub prompt_arg: bool,
    pub print_timeout: bool,
    pub log_file: bool,
    pub sandbox: bool,
    pub add_dir: bool,
    pub continue_session: bool,
    pub conversation: bool,
    pub json_output: bool,
    pub model_cli_arg: bool,
    pub dangerously_skip_permissions_seen: bool,
    pub text_output_supported: bool,
}

impl Default for AntigravityCapabilities {
    fn default() -> Self {
        Self {
            print_mode: false,
            prompt_arg: false,
            print_timeout: false,
            log_file: false,
            sandbox: false,
            add_dir: false,
            continue_session: false,
            conversation: false,
            json_output: false,
            model_cli_arg: false,
            dangerously_skip_permissions_seen: false,
            text_output_supported: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityCapabilityProbe {
    pub provider_state: AntigravityProviderState,
    pub binary_path: Option<PathRef>,
    pub help_probe_command: Option<String>,
    pub capabilities: AntigravityCapabilities,
    pub timeout_enforced: bool,
    pub plain_agy_invoked: bool,
    pub install_attempted: bool,
    pub output_excerpt: String,
    pub message: String,
    #[serde(with = "time::serde::rfc3339")]
    pub probed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityArgvPolicy {
    pub shell: bool,
    pub fuse_flag_values: bool,
    pub reject_user_value_starting_with_dash: bool,
    pub forbidden_flags: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityPromptPolicy {
    pub deny_sensitive_paths: bool,
    pub deny_destructive_commands: bool,
    pub deny_remote_pipe_install: bool,
    pub max_prompt_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityEnvPolicy {
    pub clear_env_first: bool,
    pub drop_secret_like_vars: bool,
    pub dropped_names: Vec<String>,
    pub fixed_vars: Vec<(String, String)>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravitySensitivePathPolicy {
    pub denied_fragments: Vec<String>,
    pub deny_home_secrets: bool,
    pub deny_data_root: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityStdinMode {
    DevNull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityOutputMode {
    Text,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityWorkdirPolicy {
    #[serde(alias = "controller_repo_read_only")]
    DisposableWorktreeForAudit,
    #[serde(alias = "worktree_for_candidate_implementation")]
    DisposableWorktreeForCandidateImplementation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravitySandboxPolicy {
    RequiredWhenSupported,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityLogFilePolicy {
    pub capture_to_blob: bool,
    pub expose_raw_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravitySessionPolicy {
    pub allow_continue: bool,
    pub allow_conversation_id_from_user: bool,
    pub drop_ungoverned_conversation_env: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityContractSource {
    HelpProbe,
    Fixture,
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct AntigravityCommandContract {
    pub provider_id: String,
    pub binary_path: Option<PathRef>,
    pub source: AntigravityContractSource,
    pub noninteractive_supported: bool,
    pub review_args: Vec<String>,
    pub argv_policy: AntigravityArgvPolicy,
    pub prompt_policy: AntigravityPromptPolicy,
    pub env_policy: AntigravityEnvPolicy,
    pub sensitive_path_policy: AntigravitySensitivePathPolicy,
    pub stdin_mode: AntigravityStdinMode,
    pub output_mode: AntigravityOutputMode,
    pub workdir_policy: AntigravityWorkdirPolicy,
    pub sandbox_policy: AntigravitySandboxPolicy,
    pub log_file_policy: AntigravityLogFilePolicy,
    pub session_policy: AntigravitySessionPolicy,
    pub dangerous_flags_forbidden: bool,
    pub json_output_required: bool,
    pub model_cli_arg_supported: bool,
    pub model_selection_message: String,
    pub limitations: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityReviewMode {
    AuditPlan,
    CandidateImplementation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityReviewRequest {
    pub request_id: String,
    pub project: String,
    pub project_id: ProjectId,
    pub task: String,
    pub task_id: TaskId,
    pub mode: AntigravityReviewMode,
    pub question: String,
    pub work_lease_id: Option<WorkLeaseId>,
    pub worktree_lease_id: Option<WorktreeLeaseId>,
    pub allowed_paths: Vec<PathRef>,
    pub evidence_refs: Vec<String>,
    pub provider_enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityRunState {
    Planned,
    DryRun,
    Running,
    Succeeded,
    Blocked,
    Failed,
    TimedOut,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityOutputRedactionReceipt {
    pub redacted: bool,
    pub redacted_markers: Vec<String>,
    pub original_bytes: usize,
    pub retained_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravitySafetyReceipt {
    /// Governed argv with the prompt argument removed before persistence.
    pub typed_argv: Vec<String>,
    #[serde(default)]
    pub prompt_hash_blake3: String,
    pub shell_false: bool,
    pub stdin_devnull: bool,
    pub process_group_kill_on_timeout: bool,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
    pub effective_cwd: PathRef,
    pub env_fixed_vars: Vec<(String, String)>,
    pub env_dropped_names: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AntigravityRun {
    pub run_id: String,
    pub request_id: String,
    pub state: AntigravityRunState,
    pub provider_state: AntigravityProviderState,
    pub dry_run: bool,
    pub fixture_runner: bool,
    pub binary_path: Option<PathRef>,
    pub effective_cwd: PathRef,
    pub stdout_blob_ref: Option<BlobRef>,
    pub stderr_blob_ref: Option<BlobRef>,
    pub log_blob_ref: Option<BlobRef>,
    pub stdout_excerpt: String,
    pub stderr_excerpt: String,
    pub safety_receipt: AntigravitySafetyReceipt,
    pub redaction_receipt: AntigravityOutputRedactionReceipt,
    pub normalized_result: Option<AntigravityNormalizedResult>,
    pub message: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub completed_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AntigravityNormalizedResult {
    pub result_id: String,
    pub request_id: String,
    pub run_id: String,
    pub candidate_only: bool,
    pub taint: TaintClass,
    pub external_review_result: Option<ExternalReviewResult>,
    pub rejected: bool,
    pub rejection_reasons: Vec<String>,
    pub write_receipt: Option<WriteReceiptRef>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravitySkillTarget {
    UserAgy,
    ProjectBundle,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravitySkillSpec {
    pub name: String,
    pub relative_path: PathRef,
    pub body: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravitySkillBundle {
    pub component: String,
    pub target: AntigravitySkillTarget,
    pub root: PathRef,
    pub skills: Vec<AntigravitySkillSpec>,
    pub install_dry_run: bool,
    pub verification_passed: bool,
    pub forbidden_terms_absent: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct AntigravityPluginBundle {
    pub component: String,
    pub root: PathRef,
    pub manifest_path: PathRef,
    pub official_schema_detected: bool,
    pub installable: bool,
    pub raw_agy_mcp_exposed: bool,
    pub verification_passed: bool,
    pub files: Vec<PathRef>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityExecutionGateDecisionKind {
    AllowDryRun,
    AllowRealRun,
    RequireProviderGate,
    RequireProviderEnable,
    RequireWorkLease,
    RequireWorktreeLease,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityExecutionGateDecision {
    pub decision: AntigravityExecutionGateDecisionKind,
    pub reasons: Vec<String>,
    pub candidate_only: bool,
    pub patch_permission_granted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct AntigravityDoctorStatus {
    pub component: String,
    pub provider_state: AntigravityProviderState,
    pub binary_resolution_status: AntigravityBinaryResolutionStatus,
    pub contract_available: bool,
    pub skills_verified: bool,
    pub plugin_verified: bool,
    pub raw_agy_mcp_exposed: bool,
    pub governed_mcp_tools_only: bool,
    pub message: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AntigravityTelemetryReport {
    pub component: String,
    pub detection_state: AntigravityProviderState,
    pub run_count: usize,
    pub dry_run_count: usize,
    pub real_run_count: usize,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub redaction_count: usize,
    pub timeouts: usize,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct AntigravityRealDoctorStatus {
    pub component: String,
    pub binary_resolved: bool,
    pub capability_contract_valid: bool,
    pub auth_status: AntigravityAuthStatus,
    pub enablement_state: AntigravityEnablementState,
    pub last_live_smoke_status: Option<AntigravityLiveSmokeStatus>,
    pub last_disable_receipt_ref: Option<String>,
    pub live_tree_unchanged: bool,
    pub telemetry_recorded: bool,
    pub provider_disabled_after_smoke: bool,
    pub message: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AntigravityRealReport {
    pub component: String,
    pub resolution: AntigravityBinaryResolution,
    pub probe: AntigravityCapabilityProbe,
    pub contract: AntigravityCommandContract,
    pub auth_check: AntigravityAuthCheck,
    pub enablement: Option<AntigravityEnablementReceipt>,
    pub latest_live_smoke: Option<AntigravityLiveSmokeResult>,
    pub disable_receipt: Option<AntigravityDisableReceipt>,
    pub doctor: AntigravityRealDoctorStatus,
    pub telemetry: AntigravityTelemetryReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<AntigravityVisibilityReport>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AntigravityReport {
    pub component: String,
    pub resolution: AntigravityBinaryResolution,
    pub probe: AntigravityCapabilityProbe,
    pub contract: AntigravityCommandContract,
    pub latest_request: Option<AntigravityReviewRequest>,
    pub latest_run: Option<AntigravityRun>,
    pub doctor: AntigravityDoctorStatus,
    pub telemetry: AntigravityTelemetryReport,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}
