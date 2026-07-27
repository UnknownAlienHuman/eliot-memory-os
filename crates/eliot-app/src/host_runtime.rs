use crate::{
    HostCommand,
    config::load_config,
    delegation_runtime, named_pipe_ipc, runtime_bootstrap,
    runtime_instance::{
        DEFAULT_INSTANCE_NAME, RuntimeInstance, atomic_write_bytes, atomic_write_json,
        path_identity,
    },
};
use anyhow::{Context, Result, bail};
use eliot_engine::{
    HostBrokerService, HostEventService, HostLaunchContractService, HostProfileService,
    SkillPackService, WorkState, WriteAdmissionService, WriterHandle, bundle_hash, bundle_root,
    host_generated_bundle_entry, path_in_scope, work_lease_is_active,
};
use eliot_store::{CanonicalStore, CanonicalToolObservation};
use eliot_types::{
    AgentCapabilityEnvelope, AgentHostId, AgentId, AgentInvocationRequest, AgentResultEnvelope,
    AgentResultStatus, AgentRole, AgentSessionHostBinding, AgentSessionId, AgentSessionStatus,
    ClaudeSurface, CommandContext, DelegationState, HostIntegrationReceipt, HostLaunchScope,
    HostMode, HostProfileStatus, LifecycleStatus, MAX_SECRET_BOUNDARY_BYTES, ProjectId,
    SecretBoundaryRule, SemanticCommand, SemanticCommandKind, SessionId, TaintClass, TaskContract,
    TaskContractStatus, TaskId, ToolObservationRecordCommand, Visibility, WorkItemId, WorkLease,
    WorkLeaseId, WorktreeLease, WorktreeLeaseId, WorktreeLeaseState, WriteId, WriteReceipt,
    WriteReceiptRef, WriteStatus, inspect_secret_bytes,
};
use jsonc_parser::{
    ParseOptions,
    cst::{CstInputValue, CstRootNode},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command as StdCommand;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::process::Command;
use uuid::Uuid;

const OPENCODE_GLOBAL_MANIFEST: &str = "eliot-global-install.json";
const CLAUDE_GLOBAL_MANIFEST: &str = "INSTALL-MANIFEST.json";
const CLAUDE_LEGACY_GLOBAL_MANIFEST: &str = "eliot-global-install.json";
const CLAUDE_DESKTOP_HOST: &str = "claude-desktop";

mod claude;
mod integration;
mod managed;
#[cfg(test)]
use claude::registry_entry_by_manifest;
use claude::{
    activate_claude_surface, claude_desktop_doctor, claude_desktop_executable,
    claude_desktop_extension_state, claude_desktop_state_is_current, claude_family_doctor,
    claude_global_plugin_path, claude_package_cache_root, claude_plugin_hash,
    claude_surface_selector, install_claude_desktop, is_claude_desktop_host,
    uninstall_claude_desktop,
};
use integration::{install, sha256_file, uninstall};
#[cfg(test)]
use integration::{merge_opencode_mcp_config, parse_opencode_jsonc, remove_opencode_mcp_config};
pub(crate) use managed::load_managed_controller_candidate;
use managed::{
    invocation_status, managed_request_hash, reconcile_existing_managed_invocation,
    run_managed_antigravity,
};
#[cfg(test)]
use managed::{remaining_to_deadline, validate_managed_result_integrity};
const CLAUDE_DESKTOP_MANIFEST: &str = "integrations/claude/claude-desktop/mcpb/manifest.json";
const MAX_MANAGED_LAUNCH_SECONDS: u64 = 900;
const MANAGED_ATTEMPT_SCHEMA_V4: &str = "eliot-managed-host-attempt-v4";
const CONTAINED_ANTIGRAVITY_ATTEMPT_SCHEMA_V1: &str = "eliot-contained-antigravity-attempt-v1";
const MANAGED_LOCK_MAGIC: &str = "ELIOT-MANAGED-LOCK-V2";
const MANAGED_LOCK_STALE_AFTER: Duration = Duration::from_secs(1);
const PROVIDER_START_MARKER: &str = "provider.started";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct OpenCodeGlobalInstallManifest {
    schema_version: String,
    config_path: PathBuf,
    config_existed: bool,
    config_before_hash: Option<String>,
    config_after_hash: String,
    config_backup_ref: Option<PathBuf>,
    #[serde(default = "legacy_mcp_field_existed")]
    mcp_field_existed_before: bool,
    mcp_entry_before: Option<Value>,
    mcp_entry_after: Value,
    #[serde(default)]
    instructions_field_existed_before: bool,
    #[serde(default)]
    instruction_entry_existed_before: bool,
    #[serde(default)]
    instruction_entry_after: String,
    owned_paths: Vec<OpenCodeOwnedPath>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OpenCodeOwnedPath {
    path: PathBuf,
    installed_hash: String,
    backup_ref: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ClaudeGlobalInstallManifest {
    schema_version: String,
    #[serde(default)]
    source_plugin_path: PathBuf,
    #[serde(default)]
    source_bundle_hash: String,
    #[serde(default)]
    target_plugin_path: PathBuf,
    #[serde(default)]
    governor_source_path: PathBuf,
    #[serde(default)]
    governor_sha256: String,
    #[serde(default)]
    installed_governor_path: PathBuf,
    #[serde(default)]
    installed_governor_sha256: String,
    #[serde(default)]
    generated_at: String,
    #[serde(default, alias = "owned_plugin")]
    legacy_owned_plugin: Option<OpenCodeOwnedPath>,
    #[serde(default)]
    legacy_direct_backup: Option<PathBuf>,
    #[serde(default)]
    marketplace_name: String,
    #[serde(default)]
    marketplace_root: PathBuf,
    #[serde(default)]
    plugin_id: String,
    #[serde(default)]
    plugin_version: String,
    #[serde(default)]
    artifact_hash: String,
    #[serde(default)]
    source_commit: String,
    #[serde(default)]
    claude_executable: PathBuf,
    #[serde(default)]
    claude_version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ClaudeDesktopInstallReceipt {
    schema_version: String,
    receipt_id: String,
    surface: String,
    package_path: PathBuf,
    package_hash: String,
    manifest_name: String,
    manifest_version: String,
    manifest_hash: String,
    registry_path: PathBuf,
    registry_before_hash: Option<String>,
    registry_after_hash: String,
    extension_id: String,
    extension_path: PathBuf,
    installed_manifest_hash: String,
    installed_binary_hash: String,
    install_mechanism: String,
    status: String,
    rollback_command: String,
    provider_auth_modified: bool,
    unrelated_config_preserved: bool,
    #[serde(with = "time::serde::rfc3339")]
    verified_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
struct ClaudeDesktopExtensionState {
    extension_id: String,
    version: String,
    source: String,
    enabled: bool,
    registry_hash: String,
    extension_path: PathBuf,
    installed_manifest_hash: Option<String>,
    installed_binary_hash: Option<String>,
}

#[derive(Default)]
struct GlobalInstallOutcome {
    installed_paths: Vec<String>,
    modified_files: Vec<String>,
    backup_refs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ManagedHostAttemptJournal {
    schema_version: String,
    invocation_id: String,
    idempotency_key: String,
    request_hash: String,
    contract_hash: String,
    host: AgentHostId,
    project_id: Option<ProjectId>,
    task_id: Option<TaskId>,
    work_item_id: Option<WorkItemId>,
    agent_session_id: Option<AgentSessionId>,
    role_lease_id: Option<String>,
    work_lease_id: Option<WorkLeaseId>,
    worktree_lease_id: Option<WorktreeLeaseId>,
    cwd_or_worktree: String,
    write_set: Vec<String>,
    tool: String,
    tool_version: String,
    model: Option<String>,
    prompt_hash: String,
    owner_pid: u32,
    authority_hash: String,
    worktree_before: ManagedWorktreeSnapshot,
    launch_boundary: ManagedLaunchBoundaryAttestation,
    broker_job_id: String,
    broker_result_id: String,
    broker_host_session_id: String,
    planned_verifier_ref: String,
    attempt_hash: String,
    attempt_recorded_before_provider_call: bool,
    provider_call_budget_consumed: bool,
    redispatch_allowed: bool,
    #[serde(with = "time::serde::rfc3339")]
    started_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ContainedAntigravityAttemptJournal {
    schema_version: String,
    invocation_id: String,
    idempotency_key: String,
    request_hash: String,
    contract_hash: String,
    host: AgentHostId,
    project_id: Option<ProjectId>,
    task_id: Option<TaskId>,
    agent_session_id: Option<AgentSessionId>,
    role_lease_id: Option<String>,
    permission_profile: String,
    prompt_hash: String,
    owner_pid: u32,
    bounded_auditor_authority_hash: Option<String>,
    launch_boundary: ManagedLaunchBoundaryAttestation,
    attempt_hash: String,
    attempt_recorded_before_provider_call: bool,
    provider_call_budget_consumed: bool,
    redispatch_allowed: bool,
    #[serde(with = "time::serde::rfc3339")]
    started_at: OffsetDateTime,
}

#[derive(Clone, Debug)]
enum ExistingManagedInvocation {
    New,
    Reuse(Value),
    UnknownOutcome,
    InProgress,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ManagedWorktreeSnapshot {
    head: String,
    status_hash: String,
    diff_hash: String,
    untracked_hash: String,
    aggregate_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ManagedSanitizedEnvironment {
    inherited_environment_cleared: bool,
    inherited_environment_allowlist: Vec<String>,
    environment_names: Vec<String>,
    sandbox_root: String,
    isolated_paths: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ManagedLaunchBoundaryAttestation {
    schema_version: String,
    executable_path: String,
    executable_hash: String,
    executable_version: String,
    capability_probe_receipt: String,
    integration_bundle_ref: String,
    integration_bundle_hash: String,
    invocation_root: String,
    environment: ManagedSanitizedEnvironment,
}

#[derive(Clone, Debug)]
struct ManagedCanonicalAuthority {
    task_receipt: WriteReceipt,
    session_receipt: WriteReceipt,
    role_receipt: WriteReceipt,
    host_binding_receipt: WriteReceipt,
    work_receipt: WriteReceipt,
    worktree_receipt: WriteReceipt,
    work_lease: WorkLease,
    worktree_lease: WorktreeLease,
    host_binding: AgentSessionHostBinding,
    authority_hash: String,
}

#[derive(Clone, Debug, Serialize)]
struct BoundedAuditorCanonicalAuthority {
    task_receipt: WriteReceiptRef,
    role_receipt: WriteReceiptRef,
    host_binding_receipt: WriteReceiptRef,
    authority_hash: String,
}

#[derive(Default)]
struct LaunchCanonicalAuthority {
    managed: Option<ManagedCanonicalAuthority>,
    bounded_auditor: Option<BoundedAuditorCanonicalAuthority>,
}

struct ManagedWorkAuthority {
    work_lease: WorkLease,
    work_receipt: WriteReceipt,
    worktree_lease: WorktreeLease,
    worktree_receipt: WriteReceipt,
}

#[derive(Clone, Debug)]
struct ManagedBrokerChain {
    job_id: String,
    result_id: String,
    host_session_id: String,
    planned_verifier_ref: String,
}

struct ManagedBrokerResultRecord<'a> {
    status: AgentResultStatus,
    summary: &'a str,
    candidate_diff_hash: Option<&'a str>,
    evidence_refs: Vec<String>,
    exit_status: Option<i32>,
}

struct ManagedExecutionEvidence {
    stdout_hash: Option<String>,
    stderr_hash: Option<String>,
    candidate_diff_hash: Option<String>,
    secret_boundary_rule: Option<SecretBoundaryRule>,
    worktree_before: ManagedWorktreeSnapshot,
    worktree_after: ManagedWorktreeSnapshot,
    launch_boundary: ManagedLaunchBoundaryAttestation,
    launch_boundary_intact: bool,
    process_tree_terminated: bool,
    broker: ManagedBrokerChain,
}

#[derive(Clone, Debug, Serialize)]
struct ManagedOutputRedactionReceipt {
    redacted: bool,
    markers: Vec<String>,
    original_bytes: usize,
    retained_bytes: usize,
}

struct SanitizedManagedOutput {
    bytes: Vec<u8>,
    receipt: ManagedOutputRedactionReceipt,
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedControllerCandidate {
    pub invocation_id: String,
    pub idempotency_key: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub work_item_id: WorkItemId,
    pub agent_session_id: AgentSessionId,
    pub role_lease_id: String,
    pub work_lease_id: WorkLeaseId,
    pub worktree_lease_id: WorktreeLeaseId,
    pub worktree_path: PathBuf,
    pub allowed_paths: Vec<String>,
    pub provider_host_id: AgentHostId,
    pub provider_host_session_id: String,
    pub broker_job_id: String,
    pub provider_result_id: String,
    pub provider_output_hash: String,
    pub candidate_diff_hash: String,
    pub candidate_diff: Vec<u8>,
    pub planned_verifier_ref: String,
    pub managed_result_receipt: WriteReceiptRef,
    pub completed_at: OffsetDateTime,
}

struct ManagedTerminalRecord<'a> {
    profile: &'a eliot_types::AgentHostRuntimeProfile,
    program: &'a str,
    args: &'a [String],
    invocation_root: &'a Path,
    request_hash: &'a str,
    prompt_hash: &'a str,
    daemon_readiness: &'a Value,
    status: &'a str,
    exit_code: Option<i32>,
    exit_success: Option<bool>,
    outcome_known: bool,
    cancellation_requested: bool,
    reason: &'a str,
    evidence: &'a ManagedExecutionEvidence,
    broker_status: AgentResultStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RoleLeaseAuthorityRecord {
    schema_version: String,
    role_lease_id: String,
    lease_hash: String,
    task_revision: u64,
    canonical_receipt: WriteReceiptRef,
    host_binding_hash: String,
    canonical_host_binding_receipt: WriteReceiptRef,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostRoleGrantInput {
    task: String,
    session: String,
    role: String,
    capability: Vec<String>,
    ttl_minutes: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostObservationInput {
    project_id: ProjectId,
    task_id: TaskId,
    agent_session_id: AgentSessionId,
    key: String,
    receipt_kind: String,
    body: Value,
}

#[derive(Debug, Deserialize, Serialize)]
struct HostObservationOutput {
    canonical_receipt: WriteReceiptRef,
    write_receipt: WriteReceipt,
}

struct HostObservationIdentity {
    invocation_id: String,
    expected_key: String,
    role_lease_id: Option<String>,
    host_id: Option<AgentHostId>,
    requires_persisted_request: bool,
}

struct CanonicalAuthorityBody<'a> {
    label: &'a str,
    task_id: Option<TaskId>,
    scope: &'a str,
    authority: &'a str,
    tool_name: &'a str,
    payload_key: &'a str,
    body: &'a Value,
    normalization: CanonicalBodyNormalization,
}

#[derive(Clone, Copy)]
enum CanonicalBodyNormalization {
    Exact,
    Rfc3339Fields(&'static [&'static str]),
}

struct ManagedInvocationLock {
    path: PathBuf,
    _file: File,
    record_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ManagedInvocationLockRecord {
    owner_pid: u32,
    created_unix_seconds: u64,
}

enum ManagedInvocationLockRecordState {
    Missing,
    Valid(ManagedInvocationLockRecord),
    Malformed { age: Duration },
}

enum ManagedAttemptJournalState {
    Missing,
    Valid(Box<ManagedHostAttemptJournal>),
    Malformed,
}

impl Drop for ManagedInvocationLock {
    fn drop(&mut self) {
        if std::fs::read(&self.path)
            .is_ok_and(|bytes| bytes.as_slice() == self.record_bytes.as_slice())
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn managed_launch_mutex() -> &'static tokio::sync::Mutex<()> {
    static MUTEX: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    MUTEX.get_or_init(|| tokio::sync::Mutex::new(()))
}

const fn legacy_mcp_field_existed() -> bool {
    true
}

include!("host_runtime/event_and_authority.rs");

include!("host_runtime/path_and_package_support.rs");

#[cfg(test)]
mod tests;
