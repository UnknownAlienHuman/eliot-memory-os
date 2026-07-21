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
const CLAUDE_DESKTOP_MANIFEST: &str = "integrations/claude/claude-desktop/mcpb/manifest.json";
const MAX_MANAGED_LAUNCH_SECONDS: u64 = 900;
const MANAGED_ATTEMPT_SCHEMA_V4: &str = "eliot-managed-host-attempt-v4";
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
    owned_plugin: OpenCodeOwnedPath,
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

#[allow(clippy::too_many_lines)]
pub(crate) async fn dispatch(config_path: &Path, command: HostCommand) -> Result<()> {
    match command {
        HostCommand::CognitiveSeal { request, instance } => {
            crate::cognitive_runner::seal(config_path, &request, &instance).await
        }
        HostCommand::CognitiveRun { request, instance } => {
            crate::cognitive_runner::run(config_path, &request, &instance).await
        }
        HostCommand::CognitiveStatus {
            run,
            project,
            task,
            instance,
        } => crate::cognitive_runner::status(config_path, &run, &project, &task, &instance).await,
        HostCommand::Inspect { host } => {
            if is_claude_desktop_host(&host) {
                write_json(&claude_desktop_doctor(config_path)?)
            } else {
                write_json(&inspect(parse_host(&host)?)?)
            }
        }
        HostCommand::Activate {
            host,
            surface,
            dry_run,
        } => {
            let family = parse_host(&host)?;
            anyhow::ensure!(
                family == AgentHostId::Claude,
                "only the Claude host family has selectable surfaces"
            );
            let surface = ClaudeSurface::parse(&surface).with_context(|| {
                format!("unknown Claude surface {surface}; expected `code` or `desktop`")
            })?;
            write_json(&activate_claude_surface(config_path, surface, dry_run)?)
        }
        HostCommand::Doctor { host } => {
            // A surface selector reports that surface; the bare family selector
            // reports both, because whether two are active at once is a fact
            // only the family view can see.
            match claude_surface_selector(&host) {
                Some(ClaudeSurface::ClaudeDesktopMcpb) => {
                    write_json(&claude_desktop_doctor(config_path)?)
                }
                Some(ClaudeSurface::ClaudeCodePlugin) => {
                    write_json(&doctor(config_path, AgentHostId::Claude)?)
                }
                None if parse_host(&host)? == AgentHostId::Claude => {
                    write_json(&claude_family_doctor(config_path)?)
                }
                None => write_json(&doctor(config_path, parse_host(&host)?)?),
            }
        }
        HostCommand::Render {
            host,
            mode,
            cwd,
            model,
            session,
            project,
            agent_session,
            task,
            work_item,
            role_lease,
            work_lease,
            worktree_lease,
            planned_verifier_ref,
            baseline,
            write_path,
        } => {
            let host = parse_host(&host)?;
            let mut scope = parse_launch_scope(
                project,
                agent_session,
                task,
                work_item,
                role_lease,
                work_lease,
                worktree_lease,
                planned_verifier_ref,
                baseline,
                write_path,
            )?;
            let _ = bind_launch_scope(config_path, host, cwd.as_deref(), &mut scope).await?;
            let contract = render_contract(
                config_path,
                host,
                parse_mode(&mode)?,
                cwd,
                model,
                session,
                &scope,
            )?;
            write_json(&contract)
        }
        HostCommand::Launch {
            host,
            mode,
            cwd,
            model,
            session,
            project,
            agent_session,
            task,
            work_item,
            role_lease,
            work_lease,
            worktree_lease,
            planned_verifier_ref,
            baseline,
            write_path,
            prompt,
            idempotency_key,
            timeout_seconds,
            dry_run,
        } => {
            Box::pin(launch(
                config_path,
                parse_host(&host)?,
                parse_mode(&mode)?,
                cwd,
                model,
                session,
                parse_launch_scope(
                    project,
                    agent_session,
                    task,
                    work_item,
                    role_lease,
                    work_lease,
                    worktree_lease,
                    planned_verifier_ref,
                    baseline,
                    write_path,
                )?,
                prompt,
                idempotency_key,
                timeout_seconds,
                dry_run,
            ))
            .await
        }
        HostCommand::InvocationStatus { idempotency_key } => {
            write_json(&invocation_status(config_path, &idempotency_key).await?)
        }
        HostCommand::Install {
            host,
            dry_run,
            wait_seconds,
        } => {
            if is_claude_desktop_host(&host) {
                write_json(&install_claude_desktop(config_path, dry_run, wait_seconds)?)
            } else {
                write_json(&install(config_path, parse_host(&host)?, dry_run)?)
            }
        }
        HostCommand::Uninstall {
            host,
            dry_run,
            wait_seconds,
        } => {
            if is_claude_desktop_host(&host) {
                write_json(&uninstall_claude_desktop(
                    config_path,
                    dry_run,
                    wait_seconds,
                )?)
            } else {
                write_json(&uninstall(config_path, parse_host(&host)?, dry_run)?)
            }
        }
        HostCommand::Event { host, event } => {
            write_json(&record_event(config_path, parse_host(&host)?, &event)?)
        }
        HostCommand::SessionRegister {
            host,
            session,
            client_instance,
        } => write_json(&register_session(
            config_path,
            parse_host(&host)?,
            session,
            client_instance,
        )?),
        HostCommand::RoleGrant {
            task,
            session,
            role,
            capability,
            ttl_minutes,
        } => write_json(
            &grant_role(config_path, &task, &session, &role, capability, ttl_minutes).await?,
        ),
        HostCommand::BrokerStatus => write_json(&broker_status(config_path)?),
        HostCommand::SkillLint => {
            let report = SkillPackService.lint(&repo_root(config_path))?;
            if !report.valid {
                write_json(&report)?;
                bail!("ELIOT skill pack lint failed: {}", report.errors.join("; "));
            }
            write_json(&report)
        }
    }
}

fn inspect(host: AgentHostId) -> Result<Value> {
    let profile = HostProfileService.probe(host)?;
    Ok(json!({
        "schema_version": "eliot-host-inspection-v1",
        "host_identity_is_not_a_role": true,
        "runtime_profile": profile,
    }))
}

fn doctor(config_path: &Path, host: AgentHostId) -> Result<Value> {
    let root = repo_root(config_path);
    let profile = HostProfileService.probe(host)?;
    let skills = SkillPackService.lint(&root)?;
    let bundle = bundle_root(&root, host);
    let (config_ref, lifecycle_ref) = integration_refs(&bundle, host);
    let config_valid =
        serde_json::from_reader::<_, Value>(std::fs::File::open(&config_ref)?).is_ok();
    let lifecycle_valid = lifecycle_ref.is_file();
    let ready = profile.status == HostProfileStatus::Current
        && skills.valid
        && config_valid
        && lifecycle_valid;
    Ok(json!({
        "schema_version": "eliot-host-doctor-v1",
        "ready": ready,
        "host_identity_is_not_a_role": true,
        "profile": profile,
        "skill_pack": skills,
        "bundle": {
            "path": bundle,
            "hash": bundle_hash(&bundle, host)?,
            "config_ref": config_ref,
            "config_valid": config_valid,
            "lifecycle_ref": lifecycle_ref,
            "lifecycle_valid": lifecycle_valid
        }
    }))
}

/// Resolves which Claude surface a `--host` selector names.
///
/// `claude-desktop` was historically a host string of its own, sitting beside
/// `claude` as though Anthropic shipped two unrelated products. It is one host
/// family with two packaged surfaces, so the selector now resolves to a
/// [`ClaudeSurface`] and the family stays [`AgentHostId::Claude`]. The old
/// spellings keep resolving; they are never emitted as the current name.
fn claude_surface_selector(value: &str) -> Option<ClaudeSurface> {
    let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
    match normalized.as_str() {
        // Bare `claude` names the family, not a surface: the caller decides.
        "claude" => None,
        other => ClaudeSurface::parse(other),
    }
}

fn is_claude_desktop_host(value: &str) -> bool {
    claude_surface_selector(value) == Some(ClaudeSurface::ClaudeDesktopMcpb)
}

fn claude_desktop_manifest_info(repo: &Path) -> Result<(PathBuf, String, String)> {
    let path = repo.join(CLAUDE_DESKTOP_MANIFEST);
    let manifest: Value = serde_json::from_reader(
        std::fs::File::open(&path)
            .with_context(|| format!("read Claude Desktop manifest {}", path.display()))?,
    )?;
    let name = manifest
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .context("Claude Desktop manifest name is missing")?
        .to_owned();
    let version = manifest
        .get("version")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .context("Claude Desktop manifest version is missing")?
        .to_owned();
    Ok((path, name, version))
}

fn claude_desktop_registry_path() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("APPDATA").context("APPDATA is not set")?)
            .join("Claude")
            .join("extensions-installations.json"),
    )
}

fn claude_desktop_extensions_root() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("APPDATA").context("APPDATA is not set")?)
            .join("Claude")
            .join("Claude Extensions"),
    )
}

fn claude_desktop_install_receipt_path(config_path: &Path) -> PathBuf {
    runtime_root(config_path)
        .join("reports")
        .join("host-integrations")
        .join("claude-desktop-install.json")
}

fn claude_desktop_package_path(repo: &Path, version: &str) -> PathBuf {
    repo.join("dist")
        .join("claude")
        .join(format!("eliot-{version}-windows-x64.mcpb"))
}

fn claude_desktop_uninstall_receipt_path(config_path: &Path) -> PathBuf {
    runtime_root(config_path)
        .join("reports")
        .join("host-integrations")
        .join("claude-desktop-uninstall.json")
}

fn registry_entry_by_manifest(registry: &Value, manifest_name: &str) -> Option<(String, Value)> {
    registry
        .get("extensions")?
        .as_object()?
        .iter()
        .find(|(_, entry)| {
            entry
                .get("manifest")
                .and_then(|manifest| manifest.get("name"))
                .and_then(Value::as_str)
                == Some(manifest_name)
        })
        .map(|(id, entry)| (id.clone(), entry.clone()))
}

fn claude_desktop_extension_state(
    manifest_name: &str,
) -> Result<Option<ClaudeDesktopExtensionState>> {
    let registry_path = claude_desktop_registry_path()?;
    if !registry_path.is_file() {
        return Ok(None);
    }
    let registry_bytes = std::fs::read(&registry_path)?;
    let registry: Value = serde_json::from_slice(&registry_bytes).with_context(|| {
        format!(
            "parse Claude extension registry {}",
            registry_path.display()
        )
    })?;
    let Some((extension_id, entry)) = registry_entry_by_manifest(&registry, manifest_name) else {
        return Ok(None);
    };
    let root = claude_desktop_extensions_root()?;
    let extension_path = root.join(&extension_id);
    ensure_child(&root, &extension_path)?;
    let installed_manifest = extension_path.join("manifest.json");
    let installed_binary = extension_path.join("server").join("eliot-governor.exe");
    Ok(Some(ClaudeDesktopExtensionState {
        extension_id,
        version: entry
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        source: entry
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned(),
        registry_hash: entry
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        extension_path,
        installed_manifest_hash: installed_manifest
            .is_file()
            .then(|| bundle_hash_single(&installed_manifest))
            .transpose()?,
        installed_binary_hash: installed_binary
            .is_file()
            .then(|| bundle_hash_single(&installed_binary))
            .transpose()?,
    }))
}

fn claude_desktop_state_is_current(
    state: &ClaudeDesktopExtensionState,
    manifest_version: &str,
    running_governor_hash: &str,
) -> bool {
    state.version == manifest_version
        && state.installed_manifest_hash.is_some()
        && state.installed_binary_hash.as_deref() == Some(running_governor_hash)
}

fn claude_desktop_executable() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(override_path) = std::env::var_os("ELIOT_CLAUDE_DESKTOP_EXE") {
            let override_path = PathBuf::from(override_path);
            if override_path.is_file() {
                return Ok(override_path);
            }
            bail!(
                "ELIOT_CLAUDE_DESKTOP_EXE is not a file: {}",
                override_path.display()
            );
        }
        let output = StdCommand::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $package = Get-AppxPackage -Name Claude | Sort-Object Version -Descending | Select-Object -First 1; if ($null -eq $package) { exit 2 }; $package.InstallLocation",
            ])
            .output()
            .context("query the installed Claude Desktop AppX package")?;
        if !output.status.success() {
            bail!("the installed Claude Desktop AppX package was not found");
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let install_location = stdout
            .lines()
            .map(str::trim)
            .find(|value| !value.is_empty())
            .context("the installed Claude Desktop AppX location is empty")?
            .to_owned();
        let executable = PathBuf::from(install_location)
            .join("app")
            .join("Claude.exe");
        if !executable.is_file() {
            bail!(
                "the registered Claude Desktop executable is not a file: {}",
                executable.display()
            );
        }
        Ok(executable)
    }
    #[cfg(not(windows))]
    {
        bail!("Claude Desktop is supported only on Windows")
    }
}

fn open_claude_desktop_package(target: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let executable = claude_desktop_executable()?;
        StdCommand::new(&executable)
            .arg(target)
            .spawn()
            .with_context(|| {
                format!(
                    "open Claude Desktop package {} through {}",
                    target.display(),
                    executable.display()
                )
            })?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = target;
        bail!("Claude Desktop MCPB installation is supported only on Windows")
    }
}

fn open_claude_desktop() -> Result<()> {
    #[cfg(windows)]
    {
        let executable = claude_desktop_executable()?;
        StdCommand::new(&executable)
            .spawn()
            .with_context(|| format!("open Claude Desktop through {}", executable.display()))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        bail!("Claude Desktop is supported only on Windows")
    }
}

fn wait_for_claude_desktop_install(
    manifest_name: &str,
    manifest_version: &str,
    running_governor_hash: &str,
    wait_seconds: u64,
) -> Result<ClaudeDesktopExtensionState> {
    let deadline = Instant::now() + Duration::from_secs(wait_seconds);
    loop {
        if let Some(state) = claude_desktop_extension_state(manifest_name)?
            && claude_desktop_state_is_current(&state, manifest_version, running_governor_hash)
        {
            return Ok(state);
        }
        if Instant::now() >= deadline {
            bail!(
                "Claude Desktop did not finish installing {manifest_name} {manifest_version} within {wait_seconds} seconds"
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn wait_for_claude_desktop_uninstall(manifest_name: &str, wait_seconds: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(wait_seconds);
    loop {
        if claude_desktop_extension_state(manifest_name)?.is_none() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "Claude Desktop did not finish uninstalling {manifest_name} within {wait_seconds} seconds"
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn claude_desktop_doctor(config_path: &Path) -> Result<Value> {
    let repo = repo_root(config_path);
    let (manifest_path, manifest_name, manifest_version) = claude_desktop_manifest_info(&repo)?;
    let package_path = claude_desktop_package_path(&repo, &manifest_version);
    let state = claude_desktop_extension_state(&manifest_name)?;
    let running_governor = std::env::current_exe().context("resolve running Governor")?;
    let running_governor_hash = bundle_hash_single(&running_governor)?;
    let ready = state.as_ref().is_some_and(|installed| {
        claude_desktop_state_is_current(installed, &manifest_version, &running_governor_hash)
    });
    Ok(json!({
        "schema_version": "eliot-claude-desktop-doctor-v1",
        "surface": CLAUDE_DESKTOP_HOST,
        "ready": ready,
        "manifest_path": manifest_path,
        "manifest_name": manifest_name,
        "manifest_version": manifest_version,
        "package_path": package_path,
        "package_exists": package_path.is_file(),
        "extension": state,
        "running_governor_hash": running_governor_hash,
        "install_receipt_path": claude_desktop_install_receipt_path(config_path),
        "install_receipt_exists": claude_desktop_install_receipt_path(config_path).is_file(),
        "provider_auth_read_or_modified": false,
        "manual_claude_config_edit": false
    }))
}

#[allow(clippy::too_many_lines)]
fn install_claude_desktop(config_path: &Path, dry_run: bool, wait_seconds: u64) -> Result<Value> {
    let repo = repo_root(config_path);
    let (manifest_path, manifest_name, manifest_version) = claude_desktop_manifest_info(&repo)?;
    let package_path = claude_desktop_package_path(&repo, &manifest_version);
    if !package_path.is_file() {
        bail!(
            "Claude Desktop package is missing: {}; build it before installation",
            package_path.display()
        );
    }
    let registry_path = claude_desktop_registry_path()?;
    let registry_before_hash = registry_path
        .is_file()
        .then(|| bundle_hash_single(&registry_path))
        .transpose()?;
    let package_hash = bundle_hash_single(&package_path)?;
    let manifest_hash = bundle_hash_single(&manifest_path)?;
    let running_governor = std::env::current_exe().context("resolve running Governor")?;
    let running_governor_hash = bundle_hash_single(&running_governor)?;
    let existing = claude_desktop_extension_state(&manifest_name)?;
    let already_current = existing.as_ref().is_some_and(|state| {
        claude_desktop_state_is_current(state, &manifest_version, &running_governor_hash)
    });
    if dry_run {
        return Ok(json!({
            "schema_version": "eliot-claude-desktop-install-plan-v1",
            "surface": CLAUDE_DESKTOP_HOST,
            "dry_run": true,
            "package_path": package_path,
            "package_hash": package_hash,
            "manifest_name": manifest_name,
            "manifest_version": manifest_version,
            "existing": existing,
            "already_current": already_current,
            "install_mechanism": "Governor invokes the installed Claude Desktop AppX executable with the MCPB path; Claude Desktop owns review, permissions, extraction, and registry mutation",
            "manual_claude_config_edit": false,
            "provider_auth_read_or_modified": false,
            "wait_seconds": wait_seconds
        }));
    }
    let installed = if already_current {
        existing.context("current Claude Desktop extension state disappeared")?
    } else {
        open_claude_desktop_package(&package_path)?;
        wait_for_claude_desktop_install(
            &manifest_name,
            &manifest_version,
            &running_governor_hash,
            wait_seconds,
        )?
    };
    let registry_after_hash = bundle_hash_single(&registry_path)?;
    let installed_manifest_hash = installed
        .installed_manifest_hash
        .clone()
        .context("installed Claude Desktop manifest is missing")?;
    let installed_binary_hash = installed
        .installed_binary_hash
        .clone()
        .context("installed Claude Desktop Governor binary is missing")?;
    let receipt = ClaudeDesktopInstallReceipt {
        schema_version: "eliot-claude-desktop-install-v1".to_owned(),
        receipt_id: format!("host-install:{}", Uuid::new_v4()),
        surface: CLAUDE_DESKTOP_HOST.to_owned(),
        package_path,
        package_hash,
        manifest_name,
        manifest_version,
        manifest_hash,
        registry_path,
        registry_before_hash,
        registry_after_hash,
        extension_id: installed.extension_id,
        extension_path: installed.extension_path,
        installed_manifest_hash,
        installed_binary_hash,
        install_mechanism:
            "Governor invoked Claude Desktop with MCPB path; Claude Desktop verified and installed"
                .to_owned(),
        status: "installed_and_verified".to_owned(),
        rollback_command: format!(
            "\"{}\" host uninstall --host {CLAUDE_DESKTOP_HOST} --wait-seconds {wait_seconds}",
            std::env::current_exe()?.display()
        ),
        provider_auth_modified: false,
        unrelated_config_preserved: true,
        verified_at: OffsetDateTime::now_utc(),
    };
    atomic_write_json(&claude_desktop_install_receipt_path(config_path), &receipt)?;
    Ok(serde_json::to_value(receipt)?)
}

fn uninstall_claude_desktop(config_path: &Path, dry_run: bool, wait_seconds: u64) -> Result<Value> {
    let receipt_path = claude_desktop_install_receipt_path(config_path);
    let receipt: ClaudeDesktopInstallReceipt =
        serde_json::from_reader(std::fs::File::open(&receipt_path).with_context(|| {
            format!(
                "read Claude Desktop install receipt {}",
                receipt_path.display()
            )
        })?)?;
    if receipt.surface != CLAUDE_DESKTOP_HOST {
        bail!("install receipt does not authorize Claude Desktop removal");
    }
    let current = claude_desktop_extension_state(&receipt.manifest_name)?;
    if let Some(state) = &current
        && (state.extension_id != receipt.extension_id
            || state.extension_path != receipt.extension_path)
    {
        bail!("refuse Claude Desktop rollback because the installed extension identity changed");
    }
    if dry_run {
        return Ok(json!({
            "schema_version": "eliot-claude-desktop-uninstall-plan-v1",
            "surface": CLAUDE_DESKTOP_HOST,
            "dry_run": true,
            "authorized_by_receipt": receipt.receipt_id,
            "extension": current,
            "uninstall_mechanism": "Governor opens Claude Desktop; Claude owns the extension removal and Governor waits for verified registry removal",
            "provider_auth_read_or_modified": false,
            "unrelated_config_preserved": true,
            "wait_seconds": wait_seconds
        }));
    }
    let existed = current.is_some();
    if existed {
        open_claude_desktop()?;
        wait_for_claude_desktop_uninstall(&receipt.manifest_name, wait_seconds)?;
    }
    let uninstall_receipt = json!({
        "schema_version": "eliot-claude-desktop-uninstall-v1",
        "receipt_id": format!("host-uninstall:{}", Uuid::new_v4()),
        "surface": CLAUDE_DESKTOP_HOST,
        "authorized_by_receipt": receipt.receipt_id,
        "extension_id": receipt.extension_id,
        "extension_path": receipt.extension_path,
        "existed": existed,
        "removed": existed,
        "provider_auth_modified": false,
        "unrelated_config_preserved": true,
        "verified_at": OffsetDateTime::now_utc()
    });
    atomic_write_json(
        &claude_desktop_uninstall_receipt_path(config_path),
        &uninstall_receipt,
    )?;
    Ok(uninstall_receipt)
}

fn render_contract(
    config_path: &Path,
    host: AgentHostId,
    mode: HostMode,
    cwd: Option<PathBuf>,
    model: Option<String>,
    session: Option<String>,
    scope: &HostLaunchScope,
) -> Result<eliot_types::HostLaunchContract> {
    let root = repo_root(config_path);
    let profile = HostProfileService.probe(host)?;
    let cwd = cwd.unwrap_or_else(|| root.clone());
    Ok(HostLaunchContractService.render(&root, &profile, mode, &cwd, model, session, scope)?)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn launch(
    config_path: &Path,
    host: AgentHostId,
    mode: HostMode,
    cwd: Option<PathBuf>,
    model: Option<String>,
    session: Option<String>,
    mut scope: HostLaunchScope,
    prompt: Option<String>,
    idempotency_key: Option<String>,
    timeout_seconds: Option<u64>,
    dry_run: bool,
) -> Result<()> {
    let canonical_authority =
        bind_launch_scope(config_path, host, cwd.as_deref(), &mut scope).await?;
    let mut contract = render_contract(config_path, host, mode, cwd, model, session, &scope)?;
    if host == AgentHostId::Antigravity {
        finalize_antigravity_contract(&mut contract, idempotency_key.as_deref(), timeout_seconds)?;
        "canonical_readonly_candidate_plan".clone_into(&mut contract.permission_profile);
        contract.contract_hash.clear();
        contract.contract_hash = blake3::hash(&serde_json::to_vec(&contract)?)
            .to_hex()
            .to_string();
    } else if idempotency_key.is_some() || timeout_seconds.is_some() {
        bail!("--idempotency-key and --timeout-seconds are currently managed for Antigravity only");
    }
    let profile = HostProfileService.probe(host)?;
    let root = repo_root(config_path);
    let source_bundle = bundle_root(&root, host);
    let governor = std::env::current_exe().context("resolve running eliot-governor executable")?;
    let governor_env = governor.to_string_lossy().replace('\\', "/");
    let discovered_claude_bundle = if host == AgentHostId::Claude {
        matching_installed_claude_bundle(&source_bundle, &governor)?
    } else {
        None
    };
    let (bundle, attach_session_plugin) = if let Some(installed) = discovered_claude_bundle {
        (installed, false)
    } else if dry_run {
        (source_bundle, host == AgentHostId::Claude)
    } else {
        (
            prepare_launch_bundle(config_path, host, &source_bundle, &governor)?,
            host == AgentHostId::Claude,
        )
    };
    let prompt_hash = format!(
        "blake3:{}",
        blake3::hash(prompt.as_deref().unwrap_or_default().as_bytes()).to_hex()
    );
    let prompt_present = prompt.is_some();
    let (program, args) = launch_argv(
        host,
        &profile.executable_path,
        &bundle,
        attach_session_plugin,
        &contract,
        prompt,
    )?;
    let request_hash = managed_request_hash(&contract, &program, &args)?;
    let invocation_root = invocation_root(config_path, &contract.invocation_id);
    let receipt_args = if prompt_present {
        &args[..args.len().saturating_sub(1)]
    } else {
        args.as_slice()
    };
    let rendered = json!({
        "schema_version": "eliot-host-launch-plan-v1",
        "contract": &contract,
        "program": &program,
        "argv_without_prompt": receipt_args,
        "prompt_hash": &prompt_hash,
        "resolved_integration_bundle_ref": &bundle,
        "session_plugin_override": attach_session_plugin,
        "environment_names": launch_environment_names(host, mode, &contract),
        "daemon_start_policy": {
            "instance": DEFAULT_INSTANCE_NAME,
            "reuse_ready": true,
            "start_if_absent": true,
            "hidden_user_process": true,
            "service_registry_or_admin_mutation": false
        },
        "dry_run": dry_run,
    });
    if dry_run {
        return write_json(&rendered);
    }

    let _managed_guard = if host == AgentHostId::Antigravity {
        Some(managed_launch_mutex().lock().await)
    } else {
        None
    };
    let mut invocation_lock = None;
    if host == AgentHostId::Antigravity {
        match reconcile_existing_managed_invocation(config_path, &invocation_root, &request_hash)
            .await?
        {
            ExistingManagedInvocation::New => {}
            ExistingManagedInvocation::Reuse(receipt) => return write_json(&receipt),
            ExistingManagedInvocation::UnknownOutcome => {
                bail!(
                    "Antigravity invocation has an unknown outcome; inspect `host invocation-status --idempotency-key {}` and do not redispatch",
                    contract.idempotency_key
                );
            }
            ExistingManagedInvocation::InProgress => {
                bail!("Antigravity invocation with this idempotency key is already in progress");
            }
        }
        invocation_lock = Some(ManagedInvocationLock::acquire(&invocation_root)?);
    }

    let daemon_readiness = runtime_bootstrap::ensure_default_daemon_ready(
        config_path,
        &governor,
        named_pipe_ipc::IPC_PROTOCOL_VERSION,
        "host_launch",
    )
    .await?;

    let mut command = Command::new(&program);
    command
        .args(&args)
        .current_dir(&contract.cwd_or_worktree)
        .kill_on_drop(true);
    let managed_environment = if host == AgentHostId::Antigravity {
        Some(configure_antigravity_environment(
            &mut command,
            config_path,
            &contract,
            &governor_env,
        )?)
    } else {
        configure_standard_managed_environment(&mut command, &governor_env);
        None
    };
    if let Some(agent_session_id) = contract.agent_session_id {
        command.env("ELIOT_AGENT_SESSION_ID", agent_session_id.to_string());
    }
    if let Some(project_id) = contract.project_id {
        command.env("ELIOT_PROJECT_ID", project_id.to_string());
    }
    if let Some(task_id) = contract.task_id {
        command.env("ELIOT_TASK_ID", task_id.to_string());
    }
    if let Some(work_item_id) = contract.work_item_id {
        command.env("ELIOT_WORK_ITEM_ID", work_item_id.to_string());
    }
    if let Some(role_lease_id) = &contract.role_lease_id {
        command.env("ELIOT_ROLE_LEASE_ID", role_lease_id);
    }
    if let Some(work_lease_id) = contract.work_lease_id {
        command.env("ELIOT_WORK_LEASE_ID", work_lease_id.to_string());
    }
    if let Some(worktree_lease_id) = contract.worktree_lease_id {
        command.env("ELIOT_WORKTREE_LEASE_ID", worktree_lease_id.to_string());
    }
    if host == AgentHostId::Antigravity {
        command.stdin(Stdio::null());
    }
    if host == AgentHostId::OpenCode {
        command.env("OPENCODE_CONFIG_DIR", &bundle);
        if mode == HostMode::Supervised {
            let isolated_config = runtime_root(config_path)
                .join("host-sandboxes")
                .join("opencode-xdg");
            std::fs::create_dir_all(&isolated_config)?;
            command.env("XDG_CONFIG_HOME", isolated_config);
        }
    }
    if mode == HostMode::Interactive {
        let status = command.status().await?;
        if !status.success() {
            bail!("{} interactive launch exited with {status}", host.as_str());
        }
        return Ok(());
    }

    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let daemon_readiness = serde_json::to_value(daemon_readiness)?;
    if host == AgentHostId::Antigravity {
        let authority = canonical_authority
            .as_ref()
            .context("managed Antigravity launch lost canonical authority")?;
        let launch_boundary = managed_launch_boundary_attestation(
            &profile,
            &program,
            &bundle,
            &invocation_root,
            managed_environment.context("managed Antigravity environment was not prepared")?,
        )?;
        return run_managed_antigravity(
            config_path,
            command,
            &contract,
            &profile,
            &program,
            &args,
            &invocation_root,
            &request_hash,
            &prompt_hash,
            &daemon_readiness,
            authority,
            launch_boundary,
            invocation_lock.context("managed invocation lock was not acquired")?,
        )
        .await;
    }
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(contract.wall_clock_budget_seconds),
        command.output(),
    )
    .await
    .with_context(|| {
        format!(
            "{} exceeded the {} second wall-clock budget; outcome is unknown",
            host.as_str(),
            contract.wall_clock_budget_seconds
        )
    })??;
    let sanitized_stdout = sanitize_managed_output(&output.stdout);
    let sanitized_stderr = sanitize_managed_output(&output.stderr);
    std::fs::create_dir_all(&invocation_root)?;
    std::fs::write(
        invocation_root.join("stdout.jsonl"),
        &sanitized_stdout.bytes,
    )?;
    std::fs::write(invocation_root.join("stderr.log"), &sanitized_stderr.bytes)?;
    atomic_write_json(
        &invocation_root.join("result.json"),
        &json!({
            "schema_version": "eliot-host-launch-result-v1",
            "contract_hash": contract.contract_hash,
            "idempotency_key": contract.idempotency_key,
            "host": host,
            "exit_status": output.status.code(),
            "success": output.status.success(),
            "stdout_ref": invocation_root.join("stdout.jsonl"),
            "stderr_ref": invocation_root.join("stderr.log"),
            "stdout_redaction": sanitized_stdout.receipt,
            "stderr_redaction": sanitized_stderr.receipt,
            "governor_daemon": &daemon_readiness,
            "candidate_only": true
        }),
    )?;
    std::io::stdout().write_all(&sanitized_stdout.bytes)?;
    std::io::stderr().write_all(&sanitized_stderr.bytes)?;
    if !output.status.success() {
        bail!(
            "{} supervised launch exited with {}",
            host.as_str(),
            output.status
        );
    }
    Ok(())
}

fn finalize_antigravity_contract(
    contract: &mut eliot_types::HostLaunchContract,
    idempotency_key: Option<&str>,
    timeout_seconds: Option<u64>,
) -> Result<()> {
    let idempotency_key = idempotency_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context("governed Antigravity launch requires --idempotency-key")?;
    if idempotency_key.len() > 256
        || idempotency_key
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("Antigravity --idempotency-key must be 1..=256 visible non-whitespace characters");
    }
    let timeout_seconds = timeout_seconds.unwrap_or(MAX_MANAGED_LAUNCH_SECONDS);
    if !(1..=MAX_MANAGED_LAUNCH_SECONDS).contains(&timeout_seconds) {
        bail!("Antigravity --timeout-seconds must be between 1 and {MAX_MANAGED_LAUNCH_SECONDS}");
    }
    idempotency_key.clone_into(&mut contract.idempotency_key);
    contract.invocation_id = stable_invocation_id(idempotency_key);
    contract.wall_clock_budget_seconds = timeout_seconds;
    contract.contract_hash.clear();
    contract.contract_hash = blake3::hash(&serde_json::to_vec(contract)?)
        .to_hex()
        .to_string();
    Ok(())
}

fn stable_invocation_id(idempotency_key: &str) -> String {
    format!(
        "host-invocation:{}",
        blake3::hash(idempotency_key.as_bytes()).to_hex()
    )
}

fn invocation_root(config_path: &Path, invocation_id: &str) -> PathBuf {
    runtime_root(config_path)
        .join("reports")
        .join("host-invocations")
        .join(invocation_id.replace(':', "_"))
}

impl ManagedInvocationLock {
    fn acquire(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root)?;
        let path = root.join("dispatch.lock");
        let created_unix_seconds = u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
            .context("managed lock timestamp predates the Unix epoch")?;
        let record_bytes = encode_managed_invocation_lock(ManagedInvocationLockRecord {
            owner_pid: std::process::id(),
            created_unix_seconds,
        });
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| {
                format!(
                    "managed invocation CAS is already owned or unavailable: {}",
                    path.display()
                )
            })?;
        let write_result = (|| -> std::io::Result<()> {
            file.write_all(&record_bytes)?;
            file.flush()?;
            file.sync_all()
        })();
        if let Err(error) = write_result {
            drop(file);
            let _ = std::fs::remove_file(&path);
            return Err(error).context("write durable managed invocation lock");
        }
        Ok(Self {
            path,
            _file: file,
            record_bytes,
        })
    }
}

fn encode_managed_invocation_lock(record: ManagedInvocationLockRecord) -> Vec<u8> {
    let payload = format!(
        "{MANAGED_LOCK_MAGIC}\n{:010}\n{:020}\n",
        record.owner_pid, record.created_unix_seconds
    );
    format!("{payload}{}\n", blake3::hash(payload.as_bytes()).to_hex()).into_bytes()
}

fn decode_managed_invocation_lock(bytes: &[u8]) -> Option<ManagedInvocationLockRecord> {
    let text = std::str::from_utf8(bytes).ok()?.strip_suffix('\n')?;
    let mut lines = text.lines();
    if lines.next()? != MANAGED_LOCK_MAGIC {
        return None;
    }
    let owner = lines.next()?;
    let created = lines.next()?;
    let checksum = lines.next()?;
    if lines.next().is_some()
        || owner.len() != 10
        || created.len() != 20
        || checksum.len() != 64
        || !owner.bytes().all(|byte| byte.is_ascii_digit())
        || !created.bytes().all(|byte| byte.is_ascii_digit())
        || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let payload = format!("{MANAGED_LOCK_MAGIC}\n{owner}\n{created}\n");
    if blake3::hash(payload.as_bytes()).to_hex().as_str() != checksum {
        return None;
    }
    Some(ManagedInvocationLockRecord {
        owner_pid: owner.parse().ok()?,
        created_unix_seconds: created.parse().ok()?,
    })
}

fn invocation_lock_record(root: &Path) -> Result<ManagedInvocationLockRecordState> {
    let path = root.join("dispatch.lock");
    if !path.is_file() {
        return Ok(ManagedInvocationLockRecordState::Missing);
    }
    let bytes = std::fs::read(&path)?;
    if let Some(record) = decode_managed_invocation_lock(&bytes) {
        return Ok(ManagedInvocationLockRecordState::Valid(record));
    }
    let age = std::fs::metadata(path)?
        .modified()?
        .elapsed()
        .unwrap_or(Duration::ZERO);
    Ok(ManagedInvocationLockRecordState::Malformed { age })
}

fn read_managed_attempt(path: &Path) -> Result<ManagedAttemptJournalState> {
    if !path.is_file() {
        return Ok(ManagedAttemptJournalState::Missing);
    }
    let bytes = std::fs::read(path)?;
    Ok(match serde_json::from_slice(&bytes) {
        Ok(attempt) => ManagedAttemptJournalState::Valid(Box::new(attempt)),
        Err(_) => ManagedAttemptJournalState::Malformed,
    })
}

fn provider_start_marker_path(root: &Path) -> PathBuf {
    root.join(PROVIDER_START_MARKER)
}

fn provider_may_have_started(root: &Path, attempt: Option<&ManagedHostAttemptJournal>) -> bool {
    provider_start_marker_path(root).exists()
        || attempt.is_some_and(|journal| journal.schema_version != MANAGED_ATTEMPT_SCHEMA_V4)
}

fn write_provider_start_marker(root: &Path, attempt_hash: &str) -> Result<()> {
    let path = provider_start_marker_path(root);
    if path.exists() {
        bail!("managed provider-start marker already exists");
    }
    atomic_write_bytes(
        &path,
        format!("ELIOT-PROVIDER-START-V1\n{attempt_hash}\n").as_bytes(),
    )
}

fn lock_owner_is_active(state: &ManagedInvocationLockRecordState) -> Result<bool> {
    match state {
        ManagedInvocationLockRecordState::Missing => Ok(false),
        ManagedInvocationLockRecordState::Valid(record) => {
            let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
                .context("managed lock timestamp predates the Unix epoch")?;
            Ok(eliot_windows_ipc::process_is_alive(record.owner_pid)?
                || now.saturating_sub(record.created_unix_seconds)
                    < MANAGED_LOCK_STALE_AFTER.as_secs())
        }
        ManagedInvocationLockRecordState::Malformed { age } => Ok(*age < MANAGED_LOCK_STALE_AFTER),
    }
}

fn clear_pre_provider_journals(root: &Path) -> Result<()> {
    for path in [root.join("attempt.json"), root.join("dispatch.lock")] {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

fn hash_file_content(path: &Path) -> Result<String> {
    Ok(hash_bytes(&std::fs::read(path)?))
}

fn candidate_diff_path(value: &str, prefix: &str, allowed_paths: &[String]) -> Option<String> {
    let path = value.strip_prefix(prefix)?;
    if path.is_empty()
        || path
            .chars()
            .any(|character| matches!(character, '\t' | '\r' | '\n' | '"'))
    {
        return None;
    }
    let normalized = normalize_relative_path(path).ok()?;
    allowed_paths
        .iter()
        .any(|allowed| path_in_scope(&normalized, std::slice::from_ref(allowed)))
        .then_some(normalized)
}

fn candidate_metadata_path(value: &str, allowed_paths: &[String]) -> Option<String> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| matches!(character, '\t' | '\r' | '\n' | '"'))
    {
        return None;
    }
    let normalized = normalize_relative_path(value).ok()?;
    allowed_paths
        .iter()
        .any(|allowed| path_in_scope(&normalized, std::slice::from_ref(allowed)))
        .then_some(normalized)
}

fn valid_git_mode(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|byte| matches!(byte, b'0'..=b'7'))
}

fn valid_index_header(value: &str) -> bool {
    let mut fields = value.split_ascii_whitespace();
    let Some(range) = fields.next() else {
        return false;
    };
    let Some((old, new)) = range.split_once("..") else {
        return false;
    };
    let hashes_are_hex = !old.is_empty()
        && !new.is_empty()
        && old.bytes().all(|byte| byte.is_ascii_hexdigit())
        && new.bytes().all(|byte| byte.is_ascii_hexdigit());
    hashes_are_hex && fields.next().is_none_or(valid_git_mode) && fields.next().is_none()
}

fn valid_similarity_header(value: &str) -> bool {
    value
        .strip_suffix('%')
        .and_then(|percent| percent.parse::<u8>().ok())
        .is_some_and(|percent| percent <= 100)
}

fn parse_hunk_range(value: &str, prefix: char) -> Option<(u64, u64)> {
    let range = value.strip_prefix(prefix)?;
    let (start, count) = range
        .split_once(',')
        .map_or((range, "1"), |(start, count)| (start, count));
    if start.is_empty()
        || count.is_empty()
        || !start.bytes().all(|byte| byte.is_ascii_digit())
        || !count.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let start = start.parse::<u64>().ok()?;
    let count = count.parse::<u64>().ok()?;
    (count == 0 || start > 0).then_some((start, count))
}

fn parse_hunk_header(line: &str) -> Option<(u64, u64, u64, u64)> {
    let rest = line.strip_prefix("@@ ")?;
    let (ranges, section) = rest.split_once(" @@")?;
    if !section.is_empty() && !section.starts_with(' ') {
        return None;
    }
    let mut fields = ranges.split_ascii_whitespace();
    let (old_start, old_count) = parse_hunk_range(fields.next()?, '-')?;
    let (new_start, new_count) = parse_hunk_range(fields.next()?, '+')?;
    fields
        .next()
        .is_none()
        .then_some((old_start, old_count, new_start, new_count))
}

fn consume_hunk_line(line: &str, old_remaining: &mut u64, new_remaining: &mut u64) -> Option<bool> {
    match line.as_bytes().first()? {
        b' ' => {
            *old_remaining = old_remaining.checked_sub(1)?;
            *new_remaining = new_remaining.checked_sub(1)?;
            Some(false)
        }
        b'-' => {
            *old_remaining = old_remaining.checked_sub(1)?;
            Some(true)
        }
        b'+' => {
            *new_remaining = new_remaining.checked_sub(1)?;
            Some(true)
        }
        _ => None,
    }
}

#[derive(Default)]
struct CandidateDiffMetadata {
    seen: BTreeSet<&'static str>,
    rename_from: Option<String>,
    rename_to: Option<String>,
    copy_from: Option<String>,
    copy_to: Option<String>,
}

impl CandidateDiffMetadata {
    fn mark(&mut self, name: &'static str) -> Option<()> {
        self.seen.insert(name).then_some(())
    }
}

fn parse_candidate_metadata_line(
    line: &str,
    metadata: &mut CandidateDiffMetadata,
    allowed_paths: &[String],
) -> Option<()> {
    if let Some(value) = line.strip_prefix("index ") {
        metadata.mark("index")?;
        return valid_index_header(value).then_some(());
    }
    for (prefix, name) in [
        ("new file mode ", "new_file_mode"),
        ("deleted file mode ", "deleted_file_mode"),
        ("old mode ", "old_mode"),
        ("new mode ", "new_mode"),
    ] {
        if let Some(value) = line.strip_prefix(prefix) {
            metadata.mark(name)?;
            return valid_git_mode(value).then_some(());
        }
    }
    for (prefix, name) in [
        ("similarity index ", "similarity"),
        ("dissimilarity index ", "dissimilarity"),
    ] {
        if let Some(value) = line.strip_prefix(prefix) {
            metadata.mark(name)?;
            return valid_similarity_header(value).then_some(());
        }
    }
    let (slot, value) = if let Some(value) = line.strip_prefix("rename from ") {
        (&mut metadata.rename_from, value)
    } else if let Some(value) = line.strip_prefix("rename to ") {
        (&mut metadata.rename_to, value)
    } else if let Some(value) = line.strip_prefix("copy from ") {
        (&mut metadata.copy_from, value)
    } else if let Some(value) = line.strip_prefix("copy to ") {
        (&mut metadata.copy_to, value)
    } else {
        return None;
    };
    slot.replace(candidate_metadata_path(value, allowed_paths)?)
        .is_none()
        .then_some(())
}

fn validate_candidate_metadata(
    metadata: &CandidateDiffMetadata,
    old_path: &str,
    new_path: &str,
) -> Option<()> {
    let valid = metadata.rename_from.is_some() == metadata.rename_to.is_some()
        && metadata.copy_from.is_some() == metadata.copy_to.is_some()
        && !(metadata.rename_from.is_some() && metadata.copy_from.is_some())
        && metadata
            .rename_from
            .as_deref()
            .is_none_or(|path| path == old_path)
        && metadata
            .rename_to
            .as_deref()
            .is_none_or(|path| path == new_path)
        && metadata
            .copy_from
            .as_deref()
            .is_none_or(|path| path == old_path)
        && metadata
            .copy_to
            .as_deref()
            .is_none_or(|path| path == new_path)
        && metadata.seen.contains("old_mode") == metadata.seen.contains("new_mode")
        && !(metadata.seen.contains("new_file_mode")
            && metadata.seen.contains("deleted_file_mode"))
        && !(metadata.seen.contains("similarity") && metadata.seen.contains("dissimilarity"));
    valid.then_some(())
}

fn parse_candidate_file_headers(
    lines: &[&str],
    mut index: usize,
    metadata: &CandidateDiffMetadata,
    old_path: &str,
    new_path: &str,
    allowed_paths: &[String],
) -> Option<usize> {
    let old_header = lines.get(index)?.strip_prefix("--- ")?;
    let old_is_null = old_header == "/dev/null";
    if !old_is_null && candidate_diff_path(old_header, "a/", allowed_paths)? != old_path {
        return None;
    }
    index += 1;
    let new_header = lines.get(index)?.strip_prefix("+++ ")?;
    let new_is_null = new_header == "/dev/null";
    if !new_is_null && candidate_diff_path(new_header, "b/", allowed_paths)? != new_path {
        return None;
    }
    let has_mode_change = metadata.seen.contains("old_mode") || metadata.seen.contains("new_mode");
    let has_move = metadata.rename_from.is_some() || metadata.copy_from.is_some();
    let valid = old_is_null == metadata.seen.contains("new_file_mode")
        && new_is_null == metadata.seen.contains("deleted_file_mode")
        && !(old_is_null && new_is_null)
        && !((old_is_null || new_is_null) && (has_move || has_mode_change));
    valid.then_some(index + 1)
}

fn parse_candidate_hunks(lines: &[&str], mut index: usize) -> Option<usize> {
    let mut hunks = 0_usize;
    let mut section_changed = false;
    let mut prior_old_end = None;
    let mut prior_new_end = None;
    while index < lines.len() && !lines[index].starts_with("diff --git ") {
        let (old_start, mut old_remaining, new_start, mut new_remaining) =
            parse_hunk_header(lines[index])?;
        if prior_old_end.is_some_and(|end| old_start < end)
            || prior_new_end.is_some_and(|end| new_start < end)
        {
            return None;
        }
        prior_old_end = Some(old_start.checked_add(old_remaining)?);
        prior_new_end = Some(new_start.checked_add(new_remaining)?);
        hunks = hunks.checked_add(1)?;
        index += 1;
        let mut saw_data_line = false;
        let mut previous_was_data = false;
        while index < lines.len()
            && !lines[index].starts_with("@@ ")
            && !lines[index].starts_with("diff --git ")
        {
            let line = lines[index];
            if line == "\\ No newline at end of file" {
                if !previous_was_data {
                    return None;
                }
                previous_was_data = false;
            } else {
                section_changed |= consume_hunk_line(line, &mut old_remaining, &mut new_remaining)?;
                saw_data_line = true;
                previous_was_data = true;
            }
            index += 1;
        }
        if !saw_data_line || old_remaining != 0 || new_remaining != 0 {
            return None;
        }
    }
    (hunks > 0 && section_changed).then_some(index)
}

fn parse_candidate_diff_section(
    lines: &[&str],
    mut index: usize,
    allowed_paths: &[String],
) -> Option<usize> {
    let header = lines.get(index)?.strip_prefix("diff --git ")?;
    let mut fields = header.split_ascii_whitespace();
    let old_path = candidate_diff_path(fields.next()?, "a/", allowed_paths)?;
    let new_path = candidate_diff_path(fields.next()?, "b/", allowed_paths)?;
    if fields.next().is_some() {
        return None;
    }
    index += 1;
    let mut metadata = CandidateDiffMetadata::default();
    while index < lines.len() && !lines[index].starts_with("--- ") {
        parse_candidate_metadata_line(lines[index], &mut metadata, allowed_paths)?;
        index += 1;
    }
    validate_candidate_metadata(&metadata, &old_path, &new_path)?;
    index =
        parse_candidate_file_headers(lines, index, &metadata, &old_path, &new_path, allowed_paths)?;
    parse_candidate_hunks(lines, index)
}

fn candidate_unified_diff_hash(bytes: &[u8], allowed_paths: &[String]) -> Option<String> {
    let output = std::str::from_utf8(bytes).ok()?;
    if output.is_empty() || allowed_paths.is_empty() || output.contains("```") {
        return None;
    }
    let lines = output
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect::<Vec<_>>();
    let mut index = 0_usize;
    let mut sections = 0_usize;
    while index < lines.len() {
        index = parse_candidate_diff_section(&lines, index, allowed_paths)?;
        sections = sections.checked_add(1)?;
    }
    (sections > 0).then(|| hash_bytes(bytes))
}

fn managed_attempt_hash(attempt: &ManagedHostAttemptJournal) -> Result<String> {
    let mut material = attempt.clone();
    material.attempt_hash.clear();
    hash_json(&serde_json::to_value(material)?)
}

fn validate_attempt_journal(attempt: &ManagedHostAttemptJournal) -> Result<()> {
    if !matches!(attempt.schema_version.as_str(), MANAGED_ATTEMPT_SCHEMA_V4)
        || !attempt.attempt_recorded_before_provider_call
        || attempt.redispatch_allowed
        || attempt.owner_pid == 0
        || attempt.attempt_hash != managed_attempt_hash(attempt)?
    {
        bail!("managed launch attempt journal is incomplete or tampered");
    }
    Ok(())
}

fn managed_launch_boundary_attestation(
    profile: &eliot_types::AgentHostRuntimeProfile,
    program: &str,
    bundle: &Path,
    invocation_root: &Path,
    environment: ManagedSanitizedEnvironment,
) -> Result<ManagedLaunchBoundaryAttestation> {
    if profile.host_id != AgentHostId::Antigravity {
        bail!("managed launch boundary requires the Antigravity host profile");
    }
    let executable = Path::new(program)
        .canonicalize()
        .context("canonicalize managed agy executable")?;
    let profiled_executable = Path::new(&profile.executable_path)
        .canonicalize()
        .context("canonicalize profiled agy executable")?;
    if executable != profiled_executable {
        bail!("managed agy executable identity differs from the probed host profile");
    }
    let executable_hash = hash_file_content(&executable)?;
    if executable_hash != profile.executable_hash
        || profile.version.trim().is_empty()
        || profile.capability_probe_receipt.trim().is_empty()
    {
        bail!("managed agy executable identity lacks a current hash, version, or probe receipt");
    }

    let bundle = bundle
        .canonicalize()
        .context("canonicalize managed Antigravity integration bundle")?;
    let (manifest, lifecycle) = integration_refs(&bundle, AgentHostId::Antigravity);
    let manifest: Value = serde_json::from_reader(File::open(manifest)?)?;
    if manifest.get("schema_version").and_then(Value::as_str)
        != Some("eliot-antigravity-integration-v1")
        || manifest.get("host").and_then(Value::as_str) != Some("antigravity")
        || !lifecycle.is_file()
    {
        bail!("managed Antigravity integration bundle is incomplete");
    }

    assert_managed_path_is_local_and_private(invocation_root)?;
    let sandbox_root = Path::new(&environment.sandbox_root);
    assert_managed_path_is_local_and_private(sandbox_root)?;
    if !environment.inherited_environment_cleared
        || environment
            .inherited_environment_allowlist
            .iter()
            .any(|name| !matches!(name.as_str(), "SystemRoot" | "WINDIR" | "ComSpec"))
        || environment
            .isolated_paths
            .iter()
            .any(|path| !path_is_within(Path::new(path), sandbox_root).unwrap_or(false))
    {
        bail!("managed Antigravity environment is not isolated under its owned sandbox");
    }

    Ok(ManagedLaunchBoundaryAttestation {
        schema_version: "eliot-managed-launch-boundary-v1".to_owned(),
        executable_path: executable.to_string_lossy().into_owned(),
        executable_hash,
        executable_version: profile.version.clone(),
        capability_probe_receipt: profile.capability_probe_receipt.clone(),
        integration_bundle_ref: bundle.to_string_lossy().into_owned(),
        integration_bundle_hash: bundle_hash(&bundle, AgentHostId::Antigravity)?,
        invocation_root: invocation_root.to_string_lossy().into_owned(),
        environment,
    })
}

fn managed_launch_boundary_is_current(boundary: &ManagedLaunchBoundaryAttestation) -> bool {
    let sandbox_root = Path::new(&boundary.environment.sandbox_root);
    let executable_matches = hash_file_content(Path::new(&boundary.executable_path))
        .is_ok_and(|hash| hash == boundary.executable_hash);
    let bundle_matches = bundle_hash(
        Path::new(&boundary.integration_bundle_ref),
        AgentHostId::Antigravity,
    )
    .is_ok_and(|hash| hash == boundary.integration_bundle_hash);
    executable_matches
        && bundle_matches
        && assert_managed_path_is_local_and_private(Path::new(&boundary.invocation_root)).is_ok()
        && assert_managed_path_is_local_and_private(sandbox_root).is_ok()
        && boundary.environment.inherited_environment_cleared
        && boundary
            .environment
            .isolated_paths
            .iter()
            .all(|path| path_is_within(Path::new(path), sandbox_root).unwrap_or(false))
}

fn managed_worktree_snapshot(root: &Path) -> Result<ManagedWorktreeSnapshot> {
    let head = git_text(root, &["rev-parse", "HEAD"])?;
    let status = git_bytes(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    let diff = git_bytes(root, &["diff", "--binary", "HEAD"])?;
    let untracked = git_bytes(root, &["ls-files", "--others", "--exclude-standard", "-z"])?;
    let mut untracked_hasher = blake3::Hasher::new();
    for name in untracked
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let name = String::from_utf8(name.to_vec())?;
        let relative = normalize_relative_path(&name)?;
        untracked_hasher.update(relative.as_bytes());
        untracked_hasher.update(&[0]);
        untracked_hasher.update(&std::fs::read(root.join(&relative))?);
        untracked_hasher.update(&[0]);
    }
    let status_hash = hash_bytes(&status);
    let diff_hash = hash_bytes(&diff);
    let untracked_hash = format!("blake3:{}", untracked_hasher.finalize().to_hex());
    let aggregate_hash =
        hash_bytes(format!("{head}\n{status_hash}\n{diff_hash}\n{untracked_hash}").as_bytes());
    Ok(ManagedWorktreeSnapshot {
        head,
        status_hash,
        diff_hash,
        untracked_hash,
        aggregate_hash,
    })
}

fn managed_sandbox_root(contract: &eliot_types::HostLaunchContract) -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .context("LOCALAPPDATA is required for managed Antigravity isolation")?;
    let root = local
        .join("Eliot")
        .join("host-sandboxes")
        .join("antigravity")
        .join(contract.invocation_id.replace(':', "_"));
    assert_managed_path_is_local_and_private(&root)?;
    Ok(root)
}

const REDACTED_MANAGED_OUTPUT_LINE: &str = "[REDACTED:SENSITIVE_MANAGED_HOST_OUTPUT]";
const MANAGED_PROVIDER_CREDENTIAL_PREFIXES: &[(&str, &str)] = &[
    ("github_pat_", "provider_credential"),
    ("ghp_", "provider_credential"),
    ("gho_", "provider_credential"),
    ("ghu_", "provider_credential"),
    ("ghs_", "provider_credential"),
    ("ghr_", "provider_credential"),
    ("sk-", "provider_credential"),
    ("sk-proj-", "provider_credential"),
    ("xoxb-", "provider_credential"),
    ("xoxp-", "provider_credential"),
    ("akia", "aws_access_key"),
    ("-----begin private key-----", "private_key"),
    ("-----begin rsa private key-----", "private_key"),
    ("-----begin openssh private key-----", "private_key"),
];
const MANAGED_CREDENTIAL_ASSIGNMENT_KEYS: &[(&str, &str)] = &[
    ("api_key", "api_key"),
    ("api-key", "api_key"),
    ("apikey", "api_key"),
    ("api_token", "api_token"),
    ("api-token", "api_token"),
    ("token", "token"),
    ("password", "password"),
    ("secret", "secret"),
    ("client_secret", "client_secret"),
    ("client-secret", "client_secret"),
    ("access_token", "access_token"),
    ("access-token", "access_token"),
    ("refresh_token", "refresh_token"),
    ("refresh-token", "refresh_token"),
    ("aws_secret_access_key", "aws_secret_access_key"),
];

fn sanitize_managed_output(output: &[u8]) -> SanitizedManagedOutput {
    let text = String::from_utf8_lossy(output);
    let mut retained = String::with_capacity(text.len());
    let mut markers = BTreeSet::new();
    let mut redact_continuation = false;
    for line in text.split_inclusive('\n') {
        let mut line_markers = managed_output_markers(line);
        let is_continuation = line.starts_with(' ') || line.starts_with('\t');
        if redact_continuation && is_continuation {
            line_markers.insert("credential_continuation".to_owned());
        }
        redact_continuation = if is_continuation {
            redact_continuation
        } else {
            managed_header_requires_continuation_redaction(line)
        };
        if line_markers.is_empty() {
            retained.push_str(line);
            continue;
        }
        markers.extend(line_markers);
        retained.push_str(REDACTED_MANAGED_OUTPUT_LINE);
        if line.ends_with('\n') {
            retained.push('\n');
        }
    }
    let bytes = retained.into_bytes();
    SanitizedManagedOutput {
        receipt: ManagedOutputRedactionReceipt {
            redacted: !markers.is_empty(),
            markers: markers.into_iter().collect(),
            original_bytes: output.len(),
            retained_bytes: bytes.len(),
        },
        bytes,
    }
}

fn managed_output_markers(line: &str) -> BTreeSet<String> {
    let lower = line.to_ascii_lowercase();
    let mut markers = MANAGED_PROVIDER_CREDENTIAL_PREFIXES
        .iter()
        .filter(|(prefix, _)| lower.contains(prefix))
        .map(|(_, marker)| (*marker).to_owned())
        .collect::<BTreeSet<_>>();
    if lower.contains("bearer ") {
        markers.insert("bearer".to_owned());
    }
    if lower.contains("basic ") && lower.contains("authorization") {
        markers.insert("basic_authorization".to_owned());
    }
    if contains_compact_jwt(line) {
        markers.insert("jwt".to_owned());
    }
    for (key, marker) in MANAGED_CREDENTIAL_ASSIGNMENT_KEYS {
        let mut remainder = lower.as_str();
        while let Some(index) = remainder.find(key) {
            let after_key = &remainder[index + key.len()..];
            if assigned_credential_value(after_key) {
                markers.insert((*marker).to_owned());
                break;
            }
            remainder = after_key;
        }
    }
    markers
}

fn managed_header_requires_continuation_redaction(line: &str) -> bool {
    let lower = line
        .trim_end_matches(['\r', '\n'])
        .trim_end()
        .to_ascii_lowercase();
    lower.ends_with("authorization:")
        || lower.ends_with("proxy-authorization:")
        || lower.ends_with("api_key:")
        || lower.ends_with("api-token:")
        || lower.ends_with("api_token:")
        || lower.ends_with("password:")
        || lower.ends_with("secret:")
}

fn contains_compact_jwt(text: &str) -> bool {
    text.split(|character: char| {
        character.is_whitespace()
            || matches!(
                character,
                '"' | '\'' | ',' | ':' | ';' | '=' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    })
    .any(|candidate| {
        let mut segments = candidate.split('.');
        let Some(header) = segments.next() else {
            return false;
        };
        let Some(payload) = segments.next() else {
            return false;
        };
        let Some(signature) = segments.next() else {
            return false;
        };
        segments.next().is_none()
            && header.starts_with("eyJ")
            && payload.len() >= 8
            && signature.len() >= 8
            && [header, payload, signature].iter().all(|segment| {
                segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            })
    })
}

fn assigned_credential_value(after_key: &str) -> bool {
    let separator = after_key.trim_start_matches([' ', '\t', '"', '\'']);
    let Some(value) = separator
        .strip_prefix(':')
        .or_else(|| separator.strip_prefix('='))
    else {
        return false;
    };
    let value = value.trim_start_matches([' ', '\t', '"', '\'', '\\']);
    if value.starts_with("null")
        || value.starts_with("none")
        || value.starts_with("redacted")
        || value.starts_with("<redacted")
    {
        return false;
    }
    value
        .chars()
        .take_while(|character| {
            !character.is_whitespace() && !matches!(character, '"' | '\'' | ',' | '}' | ']' | '\\')
        })
        .take(8)
        .count()
        == 8
}

const STANDARD_MANAGED_ENV_ALLOWLIST: &[&str] = &[
    "SystemRoot",
    "WINDIR",
    "ComSpec",
    "PATH",
    "PATHEXT",
    "USERPROFILE",
    "HOME",
    "LOCALAPPDATA",
    "APPDATA",
    "TEMP",
    "TMP",
];

fn configure_standard_managed_environment(command: &mut Command, governor: &str) {
    command.env_clear();
    for name in STANDARD_MANAGED_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("ELIOT_GOVERNOR_EXE", governor);
}

fn configure_antigravity_environment(
    command: &mut Command,
    _config_path: &Path,
    contract: &eliot_types::HostLaunchContract,
    governor: &str,
) -> Result<ManagedSanitizedEnvironment> {
    let sandbox = managed_sandbox_root(contract)?;
    let home = sandbox.join("home");
    let local = sandbox.join("local");
    let roaming = sandbox.join("roaming");
    let temp = sandbox.join("temp");
    let config = sandbox.join("config");
    for path in [&home, &local, &roaming, &temp, &config] {
        std::fs::create_dir_all(path)?;
    }
    command.env_clear();
    let mut inherited_environment_allowlist = Vec::new();
    for name in ["SystemRoot", "WINDIR", "ComSpec"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
            inherited_environment_allowlist.push(name.to_owned());
        }
    }
    command
        .env("USERPROFILE", &home)
        .env("HOME", &home)
        .env("LOCALAPPDATA", &local)
        .env("APPDATA", &roaming)
        .env("XDG_CONFIG_HOME", &config)
        .env("TEMP", &temp)
        .env("TMP", &temp)
        .env("ELIOT_GOVERNOR_EXE", governor)
        .env("AGY_CLI_DISABLE_AUTO_UPDATE", "1")
        .env("AGY_CLI_HIDE_ACCOUNT_INFO", "1");
    let mut environment_names = inherited_environment_allowlist.clone();
    environment_names.extend(
        [
            "USERPROFILE",
            "HOME",
            "LOCALAPPDATA",
            "APPDATA",
            "XDG_CONFIG_HOME",
            "TEMP",
            "TMP",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    environment_names.extend(
        launch_environment_names(AgentHostId::Antigravity, contract.mode, contract)
            .into_iter()
            .map(str::to_owned),
    );
    environment_names.sort();
    environment_names.dedup();
    Ok(ManagedSanitizedEnvironment {
        inherited_environment_cleared: true,
        inherited_environment_allowlist,
        environment_names,
        sandbox_root: sandbox.to_string_lossy().into_owned(),
        isolated_paths: [&home, &local, &roaming, &temp, &config]
            .into_iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
    })
}

fn managed_request_hash(
    contract: &eliot_types::HostLaunchContract,
    program: &str,
    args: &[String],
) -> Result<String> {
    Ok(format!(
        "blake3:{}",
        blake3::hash(&serde_json::to_vec(&json!({
            "contract": contract,
            "program": program,
            "args": args,
        }))?)
        .to_hex()
    ))
}

async fn canonicalize_managed_receipt(
    config_path: &Path,
    project_id: ProjectId,
    task_id: TaskId,
    session_id: AgentSessionId,
    invocation_id: &str,
    base: Value,
) -> Result<Value> {
    let body_hash = hash_json(&base)?;
    let (canonical_receipt, _) = write_canonical_host_observation(
        config_path,
        project_id,
        task_id,
        session_id,
        &format!("managed-host-result:{invocation_id}"),
        "managed_host_launch_result",
        &base,
    )
    .await?;
    let mut result = base;
    result
        .as_object_mut()
        .context("managed receipt must be a JSON object")?
        .insert(
            "canonical_authority".to_owned(),
            json!({
                "receipt": canonical_receipt,
                "body_hash": body_hash,
                "receipt_kind": "managed_host_launch_result",
            }),
        );
    let receipt_hash = hash_json(&result)?;
    result
        .as_object_mut()
        .context("managed receipt must be a JSON object")?
        .insert("receipt_hash".to_owned(), Value::String(receipt_hash));
    Ok(result)
}

fn managed_result_write_id(invocation_id: &str) -> WriteId {
    deterministic_host_write_id(&format!("managed-host-result:{invocation_id}"))
}

async fn exact_canonical_managed_result(
    store: &CanonicalStore,
    project_id: ProjectId,
    task_id: TaskId,
    invocation_id: &str,
    request_hash: &str,
    expected_body: Option<&Value>,
) -> Result<Option<(Value, WriteReceiptRef)>> {
    let write_id = managed_result_write_id(invocation_id);
    let observations = store.tool_observations_by_write_id(&write_id).await?;
    if observations.is_empty() {
        return Ok(None);
    }
    if observations.len() != 1 {
        bail!("managed result write ID does not resolve to exactly one canonical body");
    }
    let observation = observations
        .first()
        .context("canonical managed result observation disappeared")?;
    let body = observation
        .payload
        .get("receipt_body")
        .cloned()
        .context("canonical managed result has no receipt body")?;
    let body_hash = hash_json(&body)?;
    if body.get("invocation_id").and_then(Value::as_str) != Some(invocation_id) {
        bail!("canonical managed result invocation identity differs");
    }
    if body.get("request_hash").and_then(Value::as_str) != Some(request_hash) {
        bail!("canonical managed result request hash differs");
    }
    if let Some(expected) = expected_body
        && expected != &body
    {
        bail!(
            "canonical managed result body differs from the durable result receipt: canonical_hash={} durable_hash={}",
            hash_json(&body)?,
            hash_json(expected)?
        );
    }
    if observation
        .payload
        .get("receipt_kind")
        .and_then(Value::as_str)
        != Some("managed_host_launch_result")
    {
        bail!("canonical managed result receipt kind differs");
    }
    if observation.payload.get("body_hash").and_then(Value::as_str) != Some(body_hash.as_str()) {
        bail!("canonical managed result body hash differs");
    }
    let receipt = store
        .write_receipt_by_id(&write_id)
        .await?
        .context("canonical managed result body has no WriteReceipt")?;
    let reference = WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id,
    };
    let receipt = resolve_canonical_receipt(
        store,
        &reference,
        project_id,
        Some(task_id),
        "managed host result",
    )
    .await?;
    validate_canonical_observation_identity(
        observation,
        &receipt,
        project_id,
        &CanonicalAuthorityBody {
            label: "managed host result",
            task_id: Some(task_id),
            scope: "governed host authority",
            authority: "canonical Eliot host boundary",
            tool_name: "eliot-governor-host",
            payload_key: "receipt_body",
            body: &body,
            normalization: CanonicalBodyNormalization::Exact,
        },
    )?;
    Ok(Some((body, reference)))
}

async fn recover_canonical_managed_receipt(
    config_path: &Path,
    attempt: &ManagedHostAttemptJournal,
) -> Result<Option<Value>> {
    let project_id = attempt
        .project_id
        .context("attempt lost project authority")?;
    let task_id = attempt.task_id.context("attempt lost task authority")?;
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal);
    let Some((base, reference)) = exact_canonical_managed_result(
        &store,
        project_id,
        task_id,
        &attempt.invocation_id,
        &attempt.request_hash,
        None,
    )
    .await?
    else {
        return Ok(None);
    };
    let body_hash = hash_json(&base)?;
    let mut result = base;
    result
        .as_object_mut()
        .context("canonical managed result must be an object")?
        .insert(
            "canonical_authority".to_owned(),
            json!({
                "receipt": reference,
                "body_hash": body_hash,
                "receipt_kind": "managed_host_launch_result",
            }),
        );
    let receipt_hash = hash_json(&result)?;
    result
        .as_object_mut()
        .context("canonical managed result must be an object")?
        .insert("receipt_hash".to_owned(), Value::String(receipt_hash));
    Ok(Some(result))
}

fn broker_chain_from_attempt(attempt: &ManagedHostAttemptJournal) -> ManagedBrokerChain {
    ManagedBrokerChain {
        job_id: attempt.broker_job_id.clone(),
        result_id: attempt.broker_result_id.clone(),
        host_session_id: attempt.broker_host_session_id.clone(),
        planned_verifier_ref: attempt.planned_verifier_ref.clone(),
    }
}

fn broker_status_from_receipt(result: &Value) -> Result<AgentResultStatus> {
    match result.get("status").and_then(Value::as_str) {
        Some("succeeded") => Ok(AgentResultStatus::Succeeded),
        Some("failed" | "failed_before_dispatch" | "failed_immutable_boundary") => {
            Ok(AgentResultStatus::Failed)
        }
        Some("unknown_outcome") => Ok(AgentResultStatus::UnknownOutcome),
        Some(other) => bail!("unknown managed launch result status: {other}"),
        None => bail!("managed launch result has no status"),
    }
}

async fn record_managed_broker_result_from_receipt(
    config_path: &Path,
    root: &Path,
    attempt: &ManagedHostAttemptJournal,
    result: &Value,
) -> Result<()> {
    let summary = result
        .get("reason")
        .and_then(Value::as_str)
        .context("managed launch result has no reason")?;
    let candidate_diff_hash = result
        .get("execution_evidence")
        .and_then(|execution| execution.get("candidate_diff_hash"))
        .and_then(Value::as_str);
    let exit_status = result
        .get("exit_evidence")
        .and_then(|execution| execution.get("code"))
        .and_then(Value::as_i64)
        .map(i32::try_from)
        .transpose()
        .context("managed launch exit status does not fit i32")?;
    record_managed_broker_result(
        config_path,
        &attempt.invocation_id,
        &broker_chain_from_attempt(attempt),
        ManagedBrokerResultRecord {
            status: broker_status_from_receipt(result)?,
            summary,
            candidate_diff_hash,
            evidence_refs: vec![
                root.join("attempt.json").to_string_lossy().into_owned(),
                root.join("result.json").to_string_lossy().into_owned(),
            ],
            exit_status,
        },
    )
    .await
}

fn managed_receipt_base(result: &Value) -> Result<Value> {
    let mut base = result.clone();
    let object = base
        .as_object_mut()
        .context("managed result must be a JSON object")?;
    object.remove("canonical_authority");
    object.remove("receipt_hash");
    Ok(base)
}

fn validate_managed_result_integrity(
    attempt: &ManagedHostAttemptJournal,
    result: &Value,
    request_hash: &str,
) -> Result<()> {
    if result.get("request_hash").and_then(Value::as_str) != Some(request_hash)
        || result.get("contract_hash").and_then(Value::as_str)
            != Some(attempt.contract_hash.as_str())
        || result.get("attempt_hash").and_then(Value::as_str) != Some(attempt.attempt_hash.as_str())
    {
        bail!("managed launch result hashes do not match the exact attempt/request");
    }
    let expected_receipt_hash = result
        .get("receipt_hash")
        .and_then(Value::as_str)
        .context("managed launch result has no receipt hash")?;
    let mut hash_material = result.clone();
    hash_material
        .as_object_mut()
        .context("managed result must be an object")?
        .remove("receipt_hash");
    if hash_json(&hash_material)? != expected_receipt_hash {
        bail!("managed launch result receipt hash is invalid");
    }
    let execution = result
        .get("execution_evidence")
        .context("managed result lacks execution evidence")?;
    for (reference_field, hash_field) in
        [("stdout_ref", "stdout_hash"), ("stderr_ref", "stderr_hash")]
    {
        if let Some(reference) = execution.get(reference_field).and_then(Value::as_str) {
            let expected = execution
                .get(hash_field)
                .and_then(Value::as_str)
                .with_context(|| format!("managed result lacks {hash_field}"))?;
            if hash_file_content(Path::new(reference))? != expected {
                bail!("managed launch result output artifact was modified after completion");
            }
        }
    }
    Ok(())
}

async fn validate_reusable_managed_result(
    config_path: &Path,
    root: &Path,
    request_hash: &str,
) -> Result<Value> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal);
    validate_reusable_managed_result_with_store(&store, root, request_hash).await
}

async fn validate_reusable_managed_result_with_store(
    store: &CanonicalStore,
    root: &Path,
    request_hash: &str,
) -> Result<Value> {
    let attempt: ManagedHostAttemptJournal =
        serde_json::from_reader(File::open(root.join("attempt.json"))?)?;
    validate_attempt_journal(&attempt)?;
    let result: Value = serde_json::from_reader(File::open(root.join("result.json"))?)?;
    validate_managed_result_integrity(&attempt, &result, request_hash)?;
    let execution = result
        .get("execution_evidence")
        .context("managed result lacks execution evidence")?;
    for (reference_field, hash_field) in
        [("stdout_ref", "stdout_hash"), ("stderr_ref", "stderr_hash")]
    {
        if let Some(reference) = execution.get(reference_field).and_then(Value::as_str) {
            let expected = execution
                .get(hash_field)
                .and_then(Value::as_str)
                .with_context(|| format!("managed result lacks {hash_field}"))?;
            if hash_file_content(Path::new(reference))? != expected {
                bail!("managed result output artifact was modified after completion");
            }
        }
    }
    let project_id = attempt
        .project_id
        .context("attempt lost project authority")?;
    let task_id = attempt.task_id.context("attempt lost task authority")?;
    let canonical = result
        .get("canonical_authority")
        .context("managed result lacks canonical authority")?;
    let reference: WriteReceiptRef = serde_json::from_value(
        canonical
            .get("receipt")
            .cloned()
            .context("managed result lacks canonical receipt")?,
    )?;
    let body_hash = canonical
        .get("body_hash")
        .and_then(Value::as_str)
        .context("managed result lacks canonical body hash")?;
    let base = managed_receipt_base(&result)?;
    if hash_json(&base)? != body_hash {
        bail!("managed result differs from its canonical body hash");
    }
    if reference.write_id != managed_result_write_id(&attempt.invocation_id) {
        bail!("managed result canonical receipt uses a non-deterministic write ID");
    }
    let (_, exact_reference) = exact_canonical_managed_result(
        store,
        project_id,
        task_id,
        &attempt.invocation_id,
        request_hash,
        Some(&base),
    )
    .await?
    .context("managed result canonical observation is missing")?;
    if exact_reference != reference {
        bail!("managed result canonical receipt identity differs from the exact write");
    }
    Ok(result)
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn load_managed_controller_candidate(
    runtime_root: &Path,
    store: &CanonicalStore,
    invocation_id: &str,
    expected_provider_output_hash: &str,
) -> Result<ManagedControllerCandidate> {
    let Some(digest) = invocation_id.strip_prefix("host-invocation:") else {
        bail!("managed finalization requires a deterministic host invocation id");
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("managed finalization invocation id is malformed");
    }
    let root = runtime_root
        .join("reports")
        .join("host-invocations")
        .join(invocation_id.replace(':', "_"));
    let preliminary: Value = serde_json::from_reader(File::open(root.join("result.json"))?)?;
    let request_hash = preliminary
        .get("request_hash")
        .and_then(Value::as_str)
        .context("managed result lacks request_hash")?;
    let result = validate_reusable_managed_result_with_store(store, &root, request_hash).await?;
    let attempt: ManagedHostAttemptJournal =
        serde_json::from_reader(File::open(root.join("attempt.json"))?)?;
    if attempt.invocation_id != invocation_id {
        bail!("managed attempt belongs to another invocation");
    }
    if crate::mcp_stdio::RegisteredTaskVerifier::from_reference(&attempt.planned_verifier_ref)
        .is_none()
    {
        bail!("managed attempt planned verifier reference is missing, unregistered, or stale");
    }
    let execution = result
        .get("execution_evidence")
        .context("managed result lacks execution_evidence")?;
    let stdout_ref = execution
        .get("stdout_ref")
        .and_then(Value::as_str)
        .context("managed result lacks captured provider output")?;
    let provider_output_hash = execution
        .get("stdout_hash")
        .and_then(Value::as_str)
        .context("managed result lacks provider output hash")?;
    let candidate_diff_hash = execution
        .get("candidate_diff_hash")
        .and_then(Value::as_str)
        .context("managed result lacks candidate diff hash")?;
    if provider_output_hash != expected_provider_output_hash {
        bail!("controller expected provider output hash does not match the managed result");
    }
    let candidate_diff = std::fs::read(stdout_ref)?;
    if candidate_unified_diff_hash(&candidate_diff, &attempt.write_set).as_deref()
        != Some(candidate_diff_hash)
    {
        bail!("managed provider output is not the exact validated in-scope CandidateDiff");
    }
    if !managed_result_is_controller_finalizable(&result, execution) {
        bail!("managed provider result is not eligible for controller finalization");
    }
    let canonical: WriteReceiptRef = serde_json::from_value(
        result
            .pointer("/canonical_authority/receipt")
            .cloned()
            .context("managed result lost canonical receipt")?,
    )?;
    Ok(ManagedControllerCandidate {
        invocation_id: invocation_id.to_owned(),
        idempotency_key: attempt.idempotency_key,
        project_id: attempt
            .project_id
            .context("attempt lost project authority")?,
        task_id: attempt.task_id.context("attempt lost task authority")?,
        work_item_id: attempt
            .work_item_id
            .context("attempt lost work item authority")?,
        agent_session_id: attempt
            .agent_session_id
            .context("attempt lost agent session authority")?,
        role_lease_id: attempt
            .role_lease_id
            .context("attempt lost TaskRoleLease authority")?,
        work_lease_id: attempt
            .work_lease_id
            .context("attempt lost WorkLease authority")?,
        worktree_lease_id: attempt
            .worktree_lease_id
            .context("attempt lost WorktreeLease authority")?,
        worktree_path: PathBuf::from(attempt.cwd_or_worktree),
        allowed_paths: attempt.write_set,
        provider_host_id: attempt.host,
        provider_host_session_id: attempt.broker_host_session_id,
        broker_job_id: attempt.broker_job_id,
        provider_result_id: attempt.broker_result_id,
        provider_output_hash: provider_output_hash.to_owned(),
        candidate_diff_hash: candidate_diff_hash.to_owned(),
        candidate_diff,
        planned_verifier_ref: attempt.planned_verifier_ref,
        managed_result_receipt: canonical,
        completed_at: OffsetDateTime::parse(
            result
                .get("completed_at")
                .and_then(Value::as_str)
                .context("managed result lacks RFC3339 completed_at")?,
            &time::format_description::well_known::Rfc3339,
        )?,
    })
}

fn managed_result_is_controller_finalizable(result: &Value, execution: &Value) -> bool {
    result.get("status").and_then(Value::as_str) == Some("succeeded")
        && result.get("outcome_known").and_then(Value::as_bool) == Some(true)
        && result
            .pointer("/exit_evidence/success")
            .and_then(Value::as_bool)
            == Some(true)
        && result.get("candidate_only").and_then(Value::as_bool) == Some(true)
        && result.get("truth_promoted").and_then(Value::as_bool) == Some(false)
        && execution.get("worktree_immutable").and_then(Value::as_bool) == Some(true)
        && execution
            .get("launch_boundary_intact")
            .and_then(Value::as_bool)
            == Some(true)
        && execution
            .get("process_tree_terminated")
            .and_then(Value::as_bool)
            == Some(true)
}

fn reconciled_unknown_outcome_base(
    attempt: &ManagedHostAttemptJournal,
    attempt_path: &Path,
    result_path: &Path,
    reason: &str,
) -> Value {
    let broker = broker_chain_from_attempt(attempt);
    json!({
        "schema_version": "eliot-managed-host-launch-result-v1",
        "invocation_id": attempt.invocation_id,
        "idempotency_key": attempt.idempotency_key,
        "request_hash": attempt.request_hash,
        "contract_hash": attempt.contract_hash,
        "attempt_hash": attempt.attempt_hash,
        "authority_hash": attempt.authority_hash,
        "host": attempt.host,
        "status": "unknown_outcome",
        "outcome_known": false,
        "reason": reason,
        "scope": {
            "project_id": attempt.project_id,
            "task_id": attempt.task_id,
            "work_item_id": attempt.work_item_id,
            "agent_session_id": attempt.agent_session_id,
            "role_lease_id": attempt.role_lease_id,
            "work_lease_id": attempt.work_lease_id,
            "worktree_lease_id": attempt.worktree_lease_id,
            "cwd_or_worktree": attempt.cwd_or_worktree,
            "write_set": attempt.write_set,
        },
        "tool_evidence": {
            "tool": attempt.tool,
            "official_cli": true,
            "executable": attempt.launch_boundary.executable_path,
            "executable_hash": attempt.launch_boundary.executable_hash,
            "version": attempt.tool_version,
            "capability_probe_receipt": attempt.launch_boundary.capability_probe_receipt,
            "prompt_hash": attempt.prompt_hash,
        },
        "model_evidence": {
            "selected_model": attempt.model,
            "exact_model_cli_flag": true,
        },
        "exit_evidence": { "code": Value::Null, "success": Value::Null },
        "attempt_ref": attempt_path,
        "result_ref": result_path,
        "execution_evidence": {
            "provider_dispatched": true,
            "stdout_ref": Value::Null,
            "stderr_ref": Value::Null,
            "stdout_hash": Value::Null,
            "stderr_hash": Value::Null,
            "candidate_diff_hash": Value::Null,
            "candidate_diff_ref": Value::Null,
            "worktree_before": attempt.worktree_before,
            "worktree_after": Value::Null,
            "worktree_immutable": Value::Null,
            "launch_boundary": attempt.launch_boundary,
            "launch_boundary_intact": Value::Null,
            "native_process_tree_guard": true,
            "process_tree_terminated": Value::Null,
        },
        "candidate_only": true,
        "truth_promoted": false,
        "disposition": "candidate_unreviewed",
        "cancellation_requested": false,
        "redispatch_allowed": false,
        "reconciliation_required": true,
        "broker_chain": {
            "job_id": broker.job_id,
            "result_id": broker.result_id,
            "job_result_ref": broker.result_id,
            "host_session_id": broker.host_session_id,
            "planned_verifier_ref": broker.planned_verifier_ref,
            "candidate_status": "candidate_only",
            "operation_job_recorded": true,
            "agent_result_recorded": true,
            "controller_disposition_required": true,
            "direct_truth_promotion": false,
        },
        "reconciled_at": OffsetDateTime::now_utc(),
    })
}

async fn reconcile_existing_managed_invocation(
    config_path: &Path,
    root: &Path,
    request_hash: &str,
) -> Result<ExistingManagedInvocation> {
    let attempt_path = root.join("attempt.json");
    let result_path = root.join("result.json");
    let attempt_state = read_managed_attempt(&attempt_path)?;
    if result_path.is_file() {
        if !matches!(&attempt_state, ManagedAttemptJournalState::Valid(_)) {
            return Ok(ExistingManagedInvocation::UnknownOutcome);
        }
        let result = validate_reusable_managed_result(config_path, root, request_hash).await?;
        return match result.get("status").and_then(Value::as_str) {
            Some(
                "succeeded" | "failed" | "failed_before_dispatch" | "failed_immutable_boundary",
            ) => Ok(ExistingManagedInvocation::Reuse(result)),
            Some("unknown_outcome") => Ok(ExistingManagedInvocation::UnknownOutcome),
            Some(other) => bail!("unknown managed launch result status: {other}"),
            None => bail!("managed launch result has no status"),
        };
    }
    let attempt = match attempt_state {
        ManagedAttemptJournalState::Missing => {
            if provider_start_marker_path(root).exists() {
                return Ok(ExistingManagedInvocation::UnknownOutcome);
            }
            let lock = invocation_lock_record(root)?;
            if lock_owner_is_active(&lock)? {
                return Ok(ExistingManagedInvocation::InProgress);
            }
            clear_pre_provider_journals(root)?;
            return Ok(ExistingManagedInvocation::New);
        }
        ManagedAttemptJournalState::Malformed => {
            let lock = invocation_lock_record(root)?;
            if lock_owner_is_active(&lock)? {
                return Ok(ExistingManagedInvocation::InProgress);
            }
            if provider_start_marker_path(root).exists() {
                return Ok(ExistingManagedInvocation::UnknownOutcome);
            }
            clear_pre_provider_journals(root)?;
            return Ok(ExistingManagedInvocation::New);
        }
        ManagedAttemptJournalState::Valid(attempt) => attempt,
    };
    let lock = invocation_lock_record(root)?;
    if lock_owner_is_active(&lock)? {
        return Ok(ExistingManagedInvocation::InProgress);
    }
    if attempt.schema_version != MANAGED_ATTEMPT_SCHEMA_V4 {
        return Ok(ExistingManagedInvocation::UnknownOutcome);
    }
    validate_attempt_journal(&attempt)?;
    if attempt.request_hash != request_hash {
        bail!("Antigravity idempotency key was already used for a different request");
    }
    if !provider_may_have_started(root, Some(attempt.as_ref())) {
        clear_pre_provider_journals(root)?;
        return Ok(ExistingManagedInvocation::New);
    }
    if let Some(result) = recover_canonical_managed_receipt(config_path, &attempt).await? {
        record_managed_broker_result_from_receipt(config_path, root, &attempt, &result).await?;
        atomic_write_json(&result_path, &result)?;
        let result = validate_reusable_managed_result(config_path, root, request_hash).await?;
        return match broker_status_from_receipt(&result)? {
            AgentResultStatus::UnknownOutcome => Ok(ExistingManagedInvocation::UnknownOutcome),
            _ => Ok(ExistingManagedInvocation::Reuse(result)),
        };
    }
    let reason = "attempt journal exists without a terminal provider receipt";
    let base = reconciled_unknown_outcome_base(&attempt, &attempt_path, &result_path, reason);
    let result = canonicalize_managed_receipt(
        config_path,
        attempt
            .project_id
            .context("attempt lost project authority")?,
        attempt.task_id.context("attempt lost task authority")?,
        attempt
            .agent_session_id
            .context("attempt lost session authority")?,
        &attempt.invocation_id,
        base,
    )
    .await?;
    record_managed_broker_result_from_receipt(config_path, root, &attempt, &result).await?;
    atomic_write_json(&result_path, &result)?;
    Ok(ExistingManagedInvocation::UnknownOutcome)
}

fn unknown_invocation_status(invocation_id: &str, idempotency_key: &str) -> Value {
    json!({
        "schema_version": "eliot-managed-host-invocation-status-v1",
        "invocation_id": invocation_id,
        "idempotency_key": idempotency_key,
        "status": "unknown_outcome",
        "outcome_known": false,
        "provider_call_budget_consumed": true,
        "redispatch_allowed": false,
        "reconciliation_required": true,
        "reason": "durable provider-start evidence exists but the attempt journal cannot be trusted",
    })
}

fn not_attempted_invocation_status(invocation_id: &str, idempotency_key: &str) -> Value {
    json!({
        "schema_version": "eliot-managed-host-invocation-status-v1",
        "invocation_id": invocation_id,
        "idempotency_key": idempotency_key,
        "status": "not_attempted",
        "provider_call_budget_consumed": false,
        "redispatch_allowed": true,
    })
}

async fn invocation_status(config_path: &Path, idempotency_key: &str) -> Result<Value> {
    let idempotency_key = idempotency_key.trim();
    if idempotency_key.is_empty() {
        bail!("--idempotency-key must not be empty");
    }
    let invocation_id = stable_invocation_id(idempotency_key);
    let root = invocation_root(config_path, &invocation_id);
    let attempt_path = root.join("attempt.json");
    let attempt_state = read_managed_attempt(&attempt_path)?;
    let attempt_was_valid = matches!(&attempt_state, ManagedAttemptJournalState::Valid(_));
    let request_hash = match &attempt_state {
        ManagedAttemptJournalState::Valid(attempt) => attempt.request_hash.as_str(),
        ManagedAttemptJournalState::Missing | ManagedAttemptJournalState::Malformed => "",
    };
    match reconcile_existing_managed_invocation(config_path, &root, request_hash).await? {
        ExistingManagedInvocation::Reuse(receipt) => Ok(receipt),
        ExistingManagedInvocation::UnknownOutcome => {
            let result_path = root.join("result.json");
            if attempt_was_valid && result_path.is_file() {
                match serde_json::from_reader(std::fs::File::open(result_path)?) {
                    Ok(result) => Ok(result),
                    Err(_) => Ok(unknown_invocation_status(&invocation_id, idempotency_key)),
                }
            } else {
                Ok(unknown_invocation_status(&invocation_id, idempotency_key))
            }
        }
        ExistingManagedInvocation::New => Ok(not_attempted_invocation_status(
            &invocation_id,
            idempotency_key,
        )),
        ExistingManagedInvocation::InProgress => Ok(json!({
            "schema_version": "eliot-managed-host-invocation-status-v1",
            "invocation_id": invocation_id,
            "idempotency_key": idempotency_key,
            "status": "in_progress",
            "provider_call_budget_consumed": true,
            "redispatch_allowed": false,
        })),
    }
}

fn managed_result_id(invocation_id: &str) -> String {
    format!(
        "agent-result:{}",
        blake3::hash(invocation_id.as_bytes()).to_hex()
    )
}

async fn begin_managed_broker_chain(
    config_path: &Path,
    contract: &eliot_types::HostLaunchContract,
    profile: &eliot_types::AgentHostRuntimeProfile,
    authority: &ManagedCanonicalAuthority,
) -> Result<ManagedBrokerChain> {
    let task_id = contract.task_id.context("managed broker task is missing")?;
    let project_id = contract
        .project_id
        .context("managed broker project is missing")?;
    let work_item_id = contract
        .work_item_id
        .context("managed broker work item is missing")?;
    let role_lease_id = contract
        .role_lease_id
        .clone()
        .context("managed broker role lease is missing")?;
    let planned_verifier_ref = contract
        .planned_verifier_ref
        .as_deref()
        .context("managed Antigravity broker chain requires a planned verifier reference")?;
    crate::mcp_stdio::RegisteredTaskVerifier::from_reference(planned_verifier_ref)
        .context("managed Antigravity planned verifier reference is unregistered or stale")?;
    let request = AgentInvocationRequest {
        invocation_id: contract.invocation_id.clone(),
        project_id,
        task_id,
        work_item_id,
        requested_capabilities: vec!["lease_scoped_candidate_implementation".to_owned()],
        role_lease_id,
        work_lease_id: contract.work_lease_id,
        packet_refs: vec![
            authority.task_receipt.receipt_id.to_string(),
            authority.session_receipt.receipt_id.to_string(),
            authority.role_receipt.receipt_id.to_string(),
            authority.host_binding_receipt.receipt_id.to_string(),
            authority.work_receipt.receipt_id.to_string(),
            authority.worktree_receipt.receipt_id.to_string(),
        ],
        expected_result_kind: "candidate_unified_diff".to_owned(),
        verifier_ref: planned_verifier_ref.to_owned(),
        idempotency_key: contract.idempotency_key.clone(),
    };
    let mut state = delegation_runtime::load_state(&runtime_root(config_path))?;
    let job = HostBrokerService.enqueue(
        &mut state,
        &request,
        profile,
        work_lease_is_active(&authority.work_lease),
    )?;
    write_canonical_managed_invocation_request(config_path, &state, &request).await?;
    write_canonical_managed_job(config_path, &state, &job).await?;
    delegation_runtime::save_host_broker_state(&runtime_root(config_path), &state)?;
    Ok(ManagedBrokerChain {
        job_id: job.job_id,
        result_id: managed_result_id(&contract.invocation_id),
        host_session_id: authority
            .host_binding
            .host_identity
            .client_instance_id
            .clone(),
        planned_verifier_ref: planned_verifier_ref.to_owned(),
    })
}

async fn mark_managed_broker_running(config_path: &Path, chain: &ManagedBrokerChain) -> Result<()> {
    let mut state = delegation_runtime::load_state(&runtime_root(config_path))?;
    let job = state
        .operation_jobs
        .iter_mut()
        .find(|candidate| candidate.job_id == chain.job_id)
        .context("managed broker job disappeared before provider dispatch")?;
    if job.state == eliot_types::OperationJobState::Queued {
        HostBrokerService.transition(
            job,
            eliot_types::OperationJobState::Running,
            Some(chain.host_session_id.clone()),
        )?;
    } else if job.state != eliot_types::OperationJobState::Running {
        bail!("managed broker job is not dispatchable");
    }
    let job = state
        .operation_jobs
        .iter()
        .find(|candidate| candidate.job_id == chain.job_id)
        .cloned()
        .context("managed broker job disappeared after running transition")?;
    write_canonical_managed_job(config_path, &state, &job).await?;
    delegation_runtime::save_host_broker_state(&runtime_root(config_path), &state)
}

async fn record_managed_broker_result(
    config_path: &Path,
    invocation_id: &str,
    chain: &ManagedBrokerChain,
    record: ManagedBrokerResultRecord<'_>,
) -> Result<()> {
    let mut state = delegation_runtime::load_state(&runtime_root(config_path))?;
    if let Some(job) = state
        .operation_jobs
        .iter_mut()
        .find(|candidate| candidate.job_id == chain.job_id)
        && job.state == eliot_types::OperationJobState::Queued
    {
        HostBrokerService.transition(
            job,
            eliot_types::OperationJobState::Running,
            Some(chain.host_session_id.clone()),
        )?;
    }
    let artifact_refs = record
        .candidate_diff_hash
        .map(|hash| vec![format!("candidate-unified-diff:{hash}")])
        .unwrap_or_default();
    let mut result = HostBrokerService.record_result(
        &mut state,
        AgentResultEnvelope {
            result_id: chain.result_id.clone(),
            invocation_id: invocation_id.to_owned(),
            host_id: AgentHostId::Antigravity,
            host_session_id: Some(chain.host_session_id.clone()),
            status: record.status,
            summary: record.summary.to_owned(),
            artifact_refs,
            evidence_refs: record.evidence_refs,
            verifier_refs: Vec::new(),
            candidate_only: true,
            exit_status: record.exit_status,
            token_or_cost_telemetry: None,
            unknown_outcome_evidence_refs: if record.status == AgentResultStatus::UnknownOutcome {
                vec!["managed-provider-outcome-reconciliation-required".to_owned()]
            } else {
                Vec::new()
            },
            supersedes_result_id: None,
            provider_output_hash: None,
            canonical_receipt: None,
        },
    )?;
    let (project_id, task_id, agent_session_id) =
        managed_broker_canonical_scope(&state, invocation_id)?;
    if result.canonical_receipt.is_none() {
        let (receipt, _) = write_canonical_host_observation(
            config_path,
            project_id,
            task_id,
            agent_session_id,
            &format!("managed-provider-result:{}", result.result_id),
            "agent_result",
            &serde_json::to_value(&result)?,
        )
        .await?;
        result.canonical_receipt = Some(receipt);
        let stored = state
            .agent_results
            .iter_mut()
            .find(|candidate| candidate.result_id == result.result_id)
            .context("managed provider result disappeared before receipt binding")?;
        *stored = result;
    }
    let job = state
        .operation_jobs
        .iter()
        .find(|candidate| candidate.job_id == chain.job_id)
        .cloned()
        .context("managed broker job disappeared after result")?;
    write_canonical_managed_job(config_path, &state, &job).await?;
    delegation_runtime::save_host_broker_state(&runtime_root(config_path), &state)
}

fn managed_broker_canonical_scope(
    state: &DelegationState,
    invocation_id: &str,
) -> Result<(ProjectId, TaskId, AgentSessionId)> {
    let request = state
        .agent_invocations
        .iter()
        .find(|request| request.invocation_id == invocation_id)
        .context("managed broker request disappeared")?;
    let role = state
        .task_role_leases
        .iter()
        .find(|role| role.role_lease_id == request.role_lease_id)
        .context("managed broker request lost its task role lease")?;
    Ok((request.project_id, request.task_id, role.agent_session_id))
}

async fn write_canonical_managed_job(
    config_path: &Path,
    state: &DelegationState,
    job: &eliot_types::OperationJob,
) -> Result<WriteReceiptRef> {
    let (project_id, task_id, agent_session_id) =
        managed_broker_canonical_scope(state, &job.invocation_id)?;
    let state_key = serde_json::to_string(&job.state)?;
    let (receipt, _) = write_canonical_host_observation(
        config_path,
        project_id,
        task_id,
        agent_session_id,
        &format!(
            "managed-operation-job:{}:{state_key}:{}",
            job.job_id,
            job.result_ref.as_deref().unwrap_or("none")
        ),
        "operation_job",
        &serde_json::to_value(job)?,
    )
    .await?;
    Ok(receipt)
}

async fn write_canonical_managed_invocation_request(
    config_path: &Path,
    state: &DelegationState,
    request: &AgentInvocationRequest,
) -> Result<WriteReceiptRef> {
    let (project_id, task_id, agent_session_id) =
        managed_broker_canonical_scope(state, &request.invocation_id)?;
    let (receipt, _) = write_canonical_host_observation(
        config_path,
        project_id,
        task_id,
        agent_session_id,
        &format!("managed-agent-invocation:{}", request.invocation_id),
        "agent_invocation_request",
        &serde_json::to_value(request)?,
    )
    .await?;
    Ok(receipt)
}

async fn wait_managed_root(child: &eliot_windows_ipc::SuspendedJobChild) -> Result<i32> {
    loop {
        if let Some(code) = child.try_wait()? {
            return Ok(code);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn spawn_managed_pipe_reader(file: File) -> tokio::task::JoinHandle<std::io::Result<Vec<u8>>> {
    tokio::task::spawn_blocking(move || {
        let mut file = file;
        let mut retained = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            let count = file.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            let remaining = MAX_SECRET_BOUNDARY_BYTES
                .saturating_add(1)
                .saturating_sub(retained.len());
            retained.extend_from_slice(&chunk[..count.min(remaining)]);
        }
        Ok(retained)
    })
}

async fn finish_managed_pipe_reads(
    stdout: tokio::task::JoinHandle<std::io::Result<Vec<u8>>>,
    stderr: tokio::task::JoinHandle<std::io::Result<Vec<u8>>>,
    timeout: Duration,
) -> Result<(Vec<u8>, Vec<u8>)> {
    tokio::time::timeout(timeout, async { Ok((stdout.await??, stderr.await??)) })
        .await
        .context("managed provider pipe drain exceeded its bounded deadline")?
}

fn remaining_to_deadline(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_managed_antigravity(
    config_path: &Path,
    command: Command,
    contract: &eliot_types::HostLaunchContract,
    profile: &eliot_types::AgentHostRuntimeProfile,
    program: &str,
    args: &[String],
    invocation_root: &Path,
    request_hash: &str,
    prompt_hash: &str,
    daemon_readiness: &Value,
    authority: &ManagedCanonicalAuthority,
    launch_boundary: ManagedLaunchBoundaryAttestation,
    _invocation_lock: ManagedInvocationLock,
) -> Result<()> {
    std::fs::create_dir_all(invocation_root)?;
    let attempt_path = invocation_root.join("attempt.json");
    let stdout_path = invocation_root.join("stdout.txt");
    let stderr_path = invocation_root.join("stderr.log");
    let worktree_before = managed_worktree_snapshot(Path::new(&contract.cwd_or_worktree))?;
    if worktree_before.head != authority.worktree_lease.base_commit
        || worktree_before.status_hash != hash_bytes(&[])
        || worktree_before.diff_hash != hash_bytes(&[])
    {
        bail!("managed Antigravity requires the clean canonical WorktreeLease baseline");
    }
    let broker = begin_managed_broker_chain(config_path, contract, profile, authority).await?;
    let mut attempt = ManagedHostAttemptJournal {
        schema_version: MANAGED_ATTEMPT_SCHEMA_V4.to_owned(),
        invocation_id: contract.invocation_id.clone(),
        idempotency_key: contract.idempotency_key.clone(),
        request_hash: request_hash.to_owned(),
        contract_hash: contract.contract_hash.clone(),
        host: AgentHostId::Antigravity,
        project_id: contract.project_id,
        task_id: contract.task_id,
        work_item_id: contract.work_item_id,
        agent_session_id: contract.agent_session_id,
        role_lease_id: contract.role_lease_id.clone(),
        work_lease_id: contract.work_lease_id,
        worktree_lease_id: contract.worktree_lease_id,
        cwd_or_worktree: contract.cwd_or_worktree.clone(),
        write_set: contract.allowed_paths.clone(),
        tool: "agy".to_owned(),
        tool_version: profile.version.clone(),
        model: contract.model_route_if_selected.clone(),
        prompt_hash: prompt_hash.to_owned(),
        owner_pid: std::process::id(),
        authority_hash: authority.authority_hash.clone(),
        worktree_before: worktree_before.clone(),
        launch_boundary: launch_boundary.clone(),
        broker_job_id: broker.job_id.clone(),
        broker_result_id: broker.result_id.clone(),
        broker_host_session_id: broker.host_session_id.clone(),
        planned_verifier_ref: broker.planned_verifier_ref.clone(),
        attempt_hash: String::new(),
        attempt_recorded_before_provider_call: true,
        provider_call_budget_consumed: true,
        redispatch_allowed: false,
        started_at: OffsetDateTime::now_utc(),
    };
    attempt.attempt_hash = managed_attempt_hash(&attempt)?;
    if attempt_path.exists() {
        bail!("attempt-before-call CAS already exists");
    }
    atomic_write_json(&attempt_path, &attempt)?;
    mark_managed_broker_running(config_path, &broker).await?;
    write_provider_start_marker(invocation_root, &attempt.attempt_hash)?;

    let mut child = match eliot_windows_ipc::SuspendedJobChild::spawn(command.as_std()) {
        Ok(child) => child,
        Err(error) => {
            let reason = format!("failed to start official agy CLI: {error}");
            let launch_boundary_intact = managed_launch_boundary_is_current(&launch_boundary);
            let evidence = ManagedExecutionEvidence {
                stdout_hash: None,
                stderr_hash: None,
                candidate_diff_hash: None,
                secret_boundary_rule: None,
                worktree_before,
                worktree_after: managed_worktree_snapshot(Path::new(&contract.cwd_or_worktree))?,
                launch_boundary,
                launch_boundary_intact,
                process_tree_terminated: false,
                broker,
            };
            let receipt = finalize_managed_terminal(
                config_path,
                contract,
                ManagedTerminalRecord {
                    profile,
                    program,
                    args,
                    invocation_root,
                    request_hash,
                    prompt_hash,
                    daemon_readiness,
                    status: "failed_before_dispatch",
                    exit_code: None,
                    exit_success: Some(false),
                    outcome_known: true,
                    cancellation_requested: false,
                    reason: &reason,
                    evidence: &evidence,
                    broker_status: AgentResultStatus::Failed,
                },
            )
            .await?;
            write_json(&receipt)?;
            bail!("failed to start managed Antigravity launch");
        }
    };
    let stdout_task = spawn_managed_pipe_reader(
        child
            .take_stdout()
            .context("managed stdout pipe is missing")?,
    );
    let stderr_task = spawn_managed_pipe_reader(
        child
            .take_stderr()
            .context("managed stderr pipe is missing")?,
    );
    let wall_clock = Duration::from_secs(contract.wall_clock_budget_seconds);
    let deadline = Instant::now()
        .checked_add(wall_clock)
        .context("managed launch deadline overflowed")?;
    let root_wait =
        tokio::time::timeout(remaining_to_deadline(deadline), wait_managed_root(&child)).await;
    let root_exit_code = root_wait
        .as_ref()
        .ok()
        .and_then(|result| result.as_ref().ok())
        .copied();
    let root_wait_error = match &root_wait {
        Ok(Err(error)) => Some(format!("provider wait failed: {error}")),
        Err(_) => Some(
            "wall-clock timeout elapsed; the native Job Object terminated the provider process tree"
                .to_owned(),
        ),
        Ok(Ok(_)) => None,
    };
    let terminate_error = child.terminate(1).err();
    let process_wait_error = match child.wait_timeout(remaining_to_deadline(deadline)) {
        Ok(Some(_)) => None,
        Ok(None) => Some("provider process did not signal before the absolute deadline".to_owned()),
        Err(error) => Some(format!("provider termination wait failed: {error}")),
    };
    let drained =
        finish_managed_pipe_reads(stdout_task, stderr_task, remaining_to_deadline(deadline)).await;
    let (mut stdout_bytes, mut stderr_bytes, drain_error) = match drained {
        Ok((stdout, stderr)) => (Some(stdout), Some(stderr), None),
        Err(error) => (None, None, Some(error.to_string())),
    };
    let secret_boundary_rule = stdout_bytes
        .as_deref()
        .and_then(|bytes| inspect_secret_bytes(bytes).err())
        .or_else(|| {
            stderr_bytes
                .as_deref()
                .and_then(|bytes| inspect_secret_bytes(bytes).err())
        })
        .map(|violation| violation.rule);
    if let Some(rule) = secret_boundary_rule {
        if let Some(bytes) = stdout_bytes.as_mut() {
            bytes.fill(0);
        }
        if let Some(bytes) = stderr_bytes.as_mut() {
            bytes.fill(0);
        }
        stdout_bytes = None;
        stderr_bytes = None;
        atomic_write_json(
            &invocation_root.join("secret-boundary-rejection.json"),
            &json!({
                "schema_version": "eliot-secret-boundary-rejection-v1",
                "rule": rule,
                "raw_persisted": false,
                "content_digest_persisted": false,
            }),
        )?;
    }
    let outcome_known = root_wait_error.is_none()
        && terminate_error.is_none()
        && process_wait_error.is_none()
        && drain_error.is_none();
    let process_tree_terminated = terminate_error.is_none() && process_wait_error.is_none();
    let terminate_failure = terminate_error
        .as_ref()
        .map(|error| format!("Job termination failed: {error}"));
    let wait_reason = root_wait_error
        .or(terminate_failure)
        .or(process_wait_error)
        .or(drain_error);
    let cancellation_requested = !outcome_known;
    if let Some(bytes) = &stdout_bytes {
        std::fs::write(&stdout_path, bytes)?;
    }
    if let Some(bytes) = &stderr_bytes {
        std::fs::write(&stderr_path, bytes)?;
    }
    let worktree_after = managed_worktree_snapshot(Path::new(&contract.cwd_or_worktree))?;
    let launch_boundary_intact = managed_launch_boundary_is_current(&launch_boundary);
    let immutable = worktree_before == worktree_after && launch_boundary_intact;
    let exit_success = root_exit_code == Some(0);
    let candidate_diff_hash =
        (outcome_known && immutable && exit_success && secret_boundary_rule.is_none())
            .then(|| {
                stdout_bytes
                    .as_deref()
                    .and_then(|bytes| candidate_unified_diff_hash(bytes, &contract.allowed_paths))
            })
            .flatten();
    let evidence = ManagedExecutionEvidence {
        stdout_hash: stdout_bytes.as_deref().map(hash_bytes),
        stderr_hash: stderr_bytes.as_deref().map(hash_bytes),
        candidate_diff_hash: candidate_diff_hash.clone(),
        secret_boundary_rule,
        worktree_before,
        worktree_after,
        launch_boundary,
        launch_boundary_intact,
        process_tree_terminated,
        broker,
    };
    let (receipt_status, broker_status, reason) = if let Some(rule) = secret_boundary_rule {
        (
            "failed_secret_boundary",
            AgentResultStatus::Failed,
            format!("provider output rejected before persistence or hashing: {rule}"),
        )
    } else if !outcome_known {
        (
            "unknown_outcome",
            AgentResultStatus::UnknownOutcome,
            wait_reason.unwrap_or_else(|| "provider outcome is unknown".to_owned()),
        )
    } else if !immutable {
        (
            "failed_immutable_boundary",
            AgentResultStatus::Failed,
            "provider changed the leased worktree or managed launch boundary; candidate rejected"
                .to_owned(),
        )
    } else if exit_success && candidate_diff_hash.is_some() {
        (
            "succeeded",
            AgentResultStatus::Succeeded,
            "official agy plan exited successfully; immutable candidate diff remains controller-gated".to_owned(),
        )
    } else if exit_success {
        (
            "failed",
            AgentResultStatus::Failed,
            "official agy plan output was not an exact candidate unified diff".to_owned(),
        )
    } else {
        (
            "failed",
            AgentResultStatus::Failed,
            "official agy CLI returned a non-zero exit status".to_owned(),
        )
    };
    let receipt = finalize_managed_terminal(
        config_path,
        contract,
        ManagedTerminalRecord {
            profile,
            program,
            args,
            invocation_root,
            request_hash,
            prompt_hash,
            daemon_readiness,
            status: receipt_status,
            exit_code: root_exit_code,
            exit_success: outcome_known.then_some(exit_success),
            outcome_known,
            cancellation_requested,
            reason: &reason,
            evidence: &evidence,
            broker_status,
        },
    )
    .await?;
    write_json(&receipt)?;
    if receipt_status != "succeeded" {
        bail!("managed Antigravity launch finished as {receipt_status}: {reason}");
    }
    Ok(())
}

async fn finalize_managed_terminal(
    config_path: &Path,
    contract: &eliot_types::HostLaunchContract,
    terminal: ManagedTerminalRecord<'_>,
) -> Result<Value> {
    let result_path = terminal.invocation_root.join("result.json");
    let attempt_path = terminal.invocation_root.join("attempt.json");
    let base = managed_result_receipt(contract, &terminal)?;
    let result = canonicalize_managed_receipt(
        config_path,
        contract.project_id.context("managed result lost project")?,
        contract.task_id.context("managed result lost task")?,
        contract
            .agent_session_id
            .context("managed result lost agent session")?,
        &contract.invocation_id,
        base,
    )
    .await?;
    record_managed_broker_result(
        config_path,
        &contract.invocation_id,
        &terminal.evidence.broker,
        ManagedBrokerResultRecord {
            status: terminal.broker_status,
            summary: terminal.reason,
            candidate_diff_hash: terminal.evidence.candidate_diff_hash.as_deref(),
            evidence_refs: vec![
                attempt_path.to_string_lossy().into_owned(),
                result_path.to_string_lossy().into_owned(),
            ],
            exit_status: terminal.exit_code,
        },
    )
    .await?;
    atomic_write_json(&result_path, &result)?;
    validate_reusable_managed_result(config_path, terminal.invocation_root, terminal.request_hash)
        .await
}

fn managed_result_receipt(
    contract: &eliot_types::HostLaunchContract,
    terminal: &ManagedTerminalRecord<'_>,
) -> Result<Value> {
    let result_ref = terminal.invocation_root.join("result.json");
    let stdout_ref = terminal.invocation_root.join("stdout.txt");
    let stderr_ref = terminal.invocation_root.join("stderr.log");
    let attempt: ManagedHostAttemptJournal =
        serde_json::from_reader(File::open(terminal.invocation_root.join("attempt.json"))?)?;
    validate_attempt_journal(&attempt)?;
    let evidence = terminal.evidence;
    let provider_dispatched = terminal.status != "failed_before_dispatch";
    let output_captured = evidence.stdout_hash.is_some() && evidence.stderr_hash.is_some();
    let scope = json!({
        "project_id": contract.project_id,
        "task_id": contract.task_id,
        "work_item_id": contract.work_item_id,
        "agent_session_id": contract.agent_session_id,
        "role_lease_id": contract.role_lease_id,
        "work_lease_id": contract.work_lease_id,
        "worktree_lease_id": contract.worktree_lease_id,
        "cwd_or_worktree": contract.cwd_or_worktree,
        "baseline_commit": contract.baseline_commit,
        "write_set": contract.allowed_paths,
    });
    let execution_evidence = json!({
        "provider_dispatched": provider_dispatched,
        "stdout_ref": output_captured.then_some(stdout_ref),
        "stderr_ref": output_captured.then_some(stderr_ref),
        "stdout_hash": evidence.stdout_hash,
        "stderr_hash": evidence.stderr_hash,
        "candidate_diff_hash": evidence.candidate_diff_hash,
        "secret_boundary_rule": evidence.secret_boundary_rule,
        "candidate_diff_ref": evidence.candidate_diff_hash.as_ref().map(|hash| format!("candidate-unified-diff:{hash}")),
        "worktree_before": evidence.worktree_before,
        "worktree_after": evidence.worktree_after,
        "worktree_immutable": evidence.worktree_before == evidence.worktree_after,
        "launch_boundary": evidence.launch_boundary,
        "launch_boundary_intact": evidence.launch_boundary_intact,
        "native_process_tree_guard": true,
        "process_tree_terminated": evidence.process_tree_terminated,
    });
    let broker_chain = json!({
        "job_id": evidence.broker.job_id,
        "result_id": evidence.broker.result_id,
        "job_result_ref": evidence.broker.result_id,
        "host_session_id": evidence.broker.host_session_id,
        "planned_verifier_ref": evidence.broker.planned_verifier_ref,
        "candidate_status": "candidate_only",
        "operation_job_recorded": true,
        "agent_result_recorded": true,
        "controller_disposition_required": true,
        "direct_truth_promotion": false,
    });
    Ok(json!({
        "schema_version": "eliot-managed-host-launch-result-v1",
        "invocation_id": contract.invocation_id,
        "idempotency_key": contract.idempotency_key,
        "request_hash": terminal.request_hash,
        "contract_hash": contract.contract_hash,
        "attempt_hash": attempt.attempt_hash,
        "authority_hash": attempt.authority_hash,
        "host": AgentHostId::Antigravity,
        "status": terminal.status,
        "outcome_known": terminal.outcome_known,
        "reason": terminal.reason,
        "scope": scope,
        "tool_evidence": {
            "tool": "agy",
            "official_cli": true,
            "executable": terminal.program,
            "executable_hash": terminal.profile.executable_hash,
            "version": terminal.profile.version,
            "capability_probe_receipt": terminal.profile.capability_probe_receipt,
            "argv_without_prompt": &terminal.args[..terminal.args.len().saturating_sub(1)],
            "prompt_hash": terminal.prompt_hash,
        },
        "model_evidence": {
            "selected_model": contract.model_route_if_selected,
            "exact_model_cli_flag": true,
        },
        "exit_evidence": {
            "code": terminal.exit_code,
            "success": terminal.exit_success,
        },
        "attempt_ref": terminal.invocation_root.join("attempt.json"),
        "result_ref": &result_ref,
        "execution_evidence": execution_evidence,
        "governor_daemon": terminal.daemon_readiness,
        "candidate_only": true,
        "truth_promoted": false,
        "disposition": "candidate_unreviewed",
        "cancellation_requested": terminal.cancellation_requested,
        "redispatch_allowed": false,
        "reconciliation_required": !terminal.outcome_known,
        "broker_chain": broker_chain,
        "completed_at": OffsetDateTime::now_utc(),
    }))
}

fn launch_argv(
    host: AgentHostId,
    executable: &str,
    bundle: &Path,
    attach_session_plugin: bool,
    contract: &eliot_types::HostLaunchContract,
    prompt: Option<String>,
) -> Result<(String, Vec<String>)> {
    let mut args = Vec::new();
    match host {
        AgentHostId::OpenCode => {
            if contract.mode == HostMode::Supervised {
                args.extend(["run".to_owned(), "--format".to_owned(), "json".to_owned()]);
                args.extend([
                    "--agent".to_owned(),
                    if contract.work_lease_id.is_some() || contract.role_lease_id.is_some() {
                        "build".to_owned()
                    } else {
                        "plan".to_owned()
                    },
                ]);
            }
            args.extend(["--dir".to_owned(), contract.cwd_or_worktree.clone()]);
            if let Some(model) = &contract.model_route_if_selected {
                args.extend(["--model".to_owned(), model.clone()]);
            }
            if let Some(session) = &contract.session_id {
                args.extend(["--session".to_owned(), session.clone()]);
            }
        }
        AgentHostId::Claude => {
            // The plugin carries its own `.mcp.json`, whether Claude discovered
            // it as an installed plugin or we point at it with `--plugin-dir`.
            // Handing Claude that same file again through `--mcp-config`
            // attaches ELIOT a second time, which is how one session ended up
            // exposing the tool set under two MCP namespaces with two
            // competing authorities. Exactly one attachment, either way.
            if attach_session_plugin {
                args.extend([
                    "--plugin-dir".to_owned(),
                    bundle.to_string_lossy().into_owned(),
                ]);
            }
            if let Some(model) = &contract.model_route_if_selected {
                args.extend(["--model".to_owned(), model.clone()]);
            }
            if let Some(session) = &contract.session_id {
                args.extend(["--resume".to_owned(), session.clone()]);
            }
            if contract.mode == HostMode::Supervised {
                args.extend([
                    "--print".to_owned(),
                    "--output-format".to_owned(),
                    "stream-json".to_owned(),
                    "--verbose".to_owned(),
                    "--include-hook-events".to_owned(),
                    "--permission-mode".to_owned(),
                    if contract.work_lease_id.is_some() {
                        "default".to_owned()
                    } else {
                        "plan".to_owned()
                    },
                ]);
            }
        }
        AgentHostId::Antigravity => {
            if contract.mode != HostMode::Supervised {
                bail!("Antigravity managed launch is supervised-only");
            }
            if contract.session_id.is_some() {
                bail!("Antigravity managed launch forbids ungoverned conversation resume");
            }
            args.extend([
                "--new-project".to_owned(),
                "--add-dir".to_owned(),
                contract.cwd_or_worktree.clone(),
                "--agent".to_owned(),
                "eliot-agent".to_owned(),
                "--mode".to_owned(),
                "plan".to_owned(),
                "--sandbox".to_owned(),
            ]);
            if let Some(model) = &contract.model_route_if_selected {
                args.extend(["--model".to_owned(), model.clone()]);
            }
            args.extend([
                "--print-timeout".to_owned(),
                format!("{}s", contract.wall_clock_budget_seconds),
                "--print".to_owned(),
            ]);
        }
        AgentHostId::Codex => {
            bail!("{} is not an L7 managed launch target", host.as_str())
        }
    }
    if let Some(prompt) = prompt {
        args.push(if host == AgentHostId::Antigravity {
            format!(
                "READ-ONLY GOVERNED PLAN. Do not create, edit, delete, rename, or commit files. Do not mutate user, global, OneDrive, ProgramData, or provider configuration. Return only a raw git-style candidate unified diff, with no Markdown fences, prose, or summary; the controller will review and apply it later. Exact candidate request: {prompt}"
            )
        } else {
            prompt
        });
    } else if contract.mode == HostMode::Supervised {
        bail!("supervised host launch requires --prompt");
    }
    Ok((executable.to_owned(), args))
}

fn launch_environment_names(
    host: AgentHostId,
    mode: HostMode,
    contract: &eliot_types::HostLaunchContract,
) -> Vec<&'static str> {
    let mut names = vec!["ELIOT_GOVERNOR_EXE"];
    if host != AgentHostId::Antigravity {
        names.extend(STANDARD_MANAGED_ENV_ALLOWLIST.iter().copied());
    }
    if contract.agent_session_id.is_some() {
        names.push("ELIOT_AGENT_SESSION_ID");
    }
    if contract.task_id.is_some() {
        names.push("ELIOT_TASK_ID");
    }
    if contract.work_item_id.is_some() {
        names.push("ELIOT_WORK_ITEM_ID");
    }
    if contract.role_lease_id.is_some() {
        names.push("ELIOT_ROLE_LEASE_ID");
    }
    if contract.work_lease_id.is_some() {
        names.push("ELIOT_WORK_LEASE_ID");
    }
    if contract.project_id.is_some() {
        names.push("ELIOT_PROJECT_ID");
    }
    if contract.worktree_lease_id.is_some() {
        names.push("ELIOT_WORKTREE_LEASE_ID");
    }
    if host == AgentHostId::OpenCode {
        names.push("OPENCODE_CONFIG_DIR");
        if mode == HostMode::Supervised {
            names.push("XDG_CONFIG_HOME");
        }
    }
    if host == AgentHostId::Antigravity {
        names.push("AGY_CLI_DISABLE_AUTO_UPDATE");
        names.push("AGY_CLI_HIDE_ACCOUNT_INFO");
    }
    names
}

#[allow(clippy::too_many_lines)]
fn install(config_path: &Path, host: AgentHostId, dry_run: bool) -> Result<HostIntegrationReceipt> {
    ensure_l7_host(host)?;
    let repo = repo_root(config_path);
    let source = bundle_root(&repo, host);
    let base = install_base()?;
    let target = base.join(host.as_str());
    let staging = base.join(format!(".{}-{}-staging", host.as_str(), Uuid::new_v4()));
    let source_hash = bundle_hash(&source, host)?;
    let governor = std::env::current_exe().context("resolve Eliot integration executable")?;
    let governor_hash = bundle_hash_single(&governor)?;
    let installed_governor = target.join("bin").join("eliot-governor.exe");
    let before_hash = target
        .is_dir()
        .then(|| bundle_hash(&target, host))
        .transpose()?;
    let before_governor_hash = installed_governor
        .is_file()
        .then(|| bundle_hash_single(&installed_governor))
        .transpose()?;
    let previous_global = (host == AgentHostId::OpenCode)
        .then(|| read_opencode_global_manifest(&target))
        .transpose()?
        .flatten();
    let previous_claude_global = (host == AgentHostId::Claude)
        .then(|| read_claude_global_manifest(&target))
        .transpose()?
        .flatten();
    let mut backup_refs = Vec::new();
    let mut modified_files = Vec::new();
    let needs_bundle_update = before_hash.as_deref() != Some(source_hash.as_str())
        || before_governor_hash.as_deref() != Some(governor_hash.as_str());
    if !dry_run && needs_bundle_update {
        std::fs::create_dir_all(&base)?;
        copy_tree(&source, &staging, host)?;
        std::fs::create_dir_all(staging.join("bin"))?;
        std::fs::copy(&governor, staging.join("bin").join("eliot-governor.exe"))?;
        if target.exists() {
            let backup = base.join(format!(
                ".{}-{}-backup",
                host.as_str(),
                OffsetDateTime::now_utc().unix_timestamp()
            ));
            std::fs::rename(&target, &backup)?;
            backup_refs.push(backup.to_string_lossy().into_owned());
        }
        std::fs::rename(&staging, &target)?;
        modified_files.push(target.to_string_lossy().into_owned());
    }
    let mut installed_paths = vec![target.to_string_lossy().into_owned()];
    if host == AgentHostId::OpenCode {
        let global = install_opencode_global(
            &source,
            &target,
            &governor,
            previous_global.as_ref(),
            dry_run,
        )?;
        installed_paths.extend(global.installed_paths);
        modified_files.extend(global.modified_files);
        backup_refs.extend(global.backup_refs);
    } else if host == AgentHostId::Claude {
        let global = install_claude_global(
            &source,
            &target,
            &governor,
            previous_claude_global.as_ref(),
            dry_run,
        )?;
        installed_paths.extend(global.installed_paths);
        modified_files.extend(global.modified_files);
        backup_refs.extend(global.backup_refs);
    }
    let profile = HostProfileService.probe(host)?;
    let skills = SkillPackService.lint(&repo)?;
    let (mcp, lifecycle) = integration_refs(&source, host);
    let mut after_hashes = vec![source_hash.clone(), governor_hash];
    if host == AgentHostId::Claude {
        after_hashes.push(format!("sha256:{}", sha256_file(&governor)?));
    }
    let receipt = HostIntegrationReceipt {
        receipt_id: format!("host-install:{}", Uuid::new_v4()),
        host_id: host,
        host_version: profile.version,
        scope: match host {
            AgentHostId::OpenCode => "user-local Eliot bundle plus additive OpenCode global discovery; provider/auth and unrelated config preserved".to_owned(),
            AgentHostId::Claude => "user-local Eliot bundle plus additive Claude Code skills-dir plugin discovery; provider/auth/settings and unrelated config preserved".to_owned(),
            _ => "user-local Eliot integration bundle; host auth/config untouched".to_owned(),
        },
        installed_paths,
        modified_files,
        before_hashes: before_hash
            .into_iter()
            .chain(before_governor_hash)
            .collect(),
        after_hashes,
        backup_refs,
        integration_bundle_hash: source_hash,
        skill_pack_hash: skills.pack_hash,
        mcp_config_hash: bundle_hash_single(&mcp)?,
        lifecycle_bridge_hash: bundle_hash_single(&lifecycle)?,
        rollback_command: format!(
            "\"{}\" host uninstall --host {}",
            std::env::current_exe()?.display(),
            host.as_str()
        ),
        verified_at: OffsetDateTime::now_utc(),
    };
    if !dry_run {
        atomic_write_json(&install_receipt_path(config_path, host), &receipt)?;
    }
    Ok(receipt)
}

fn read_opencode_global_manifest(target: &Path) -> Result<Option<OpenCodeGlobalInstallManifest>> {
    let path = target.join(OPENCODE_GLOBAL_MANIFEST);
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn read_claude_global_manifest(target: &Path) -> Result<Option<ClaudeGlobalInstallManifest>> {
    let current = target.join(CLAUDE_GLOBAL_MANIFEST);
    let path = if current.is_file() {
        current
    } else {
        target.join(CLAUDE_LEGACY_GLOBAL_MANIFEST)
    };
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

#[allow(clippy::too_many_lines)]
fn install_opencode_global(
    source: &Path,
    target: &Path,
    governor: &Path,
    previous: Option<&OpenCodeGlobalInstallManifest>,
    dry_run: bool,
) -> Result<GlobalInstallOutcome> {
    let root = opencode_global_root()?;
    let config_path = opencode_global_config_path(&root);
    let config_existed_now = config_path.is_file();
    let config_before_bytes = config_existed_now
        .then(|| std::fs::read(&config_path))
        .transpose()?;
    let config_before_hash_now = config_before_bytes.as_deref().map(bytes_hash);
    let config_input = config_before_bytes
        .clone()
        .unwrap_or_else(default_opencode_config_bytes);
    let installed_governor = target
        .join("bin")
        .join("eliot-governor.exe")
        .to_string_lossy()
        .replace('\\', "/");
    let instruction_destination = root.join("instructions").join("eliot-governor.md");
    let instruction_entry_after = instruction_destination.to_string_lossy().replace('\\', "/");
    let mcp_entry_after = json!({
        "type": "local",
        "command": [
            installed_governor,
            "mcp",
            "stdio",
            "--host",
            "opencode",
            "--instance",
            "default"
        ],
        "enabled": true,
        "timeout": 30000
    });
    let merged =
        merge_opencode_mcp_config(&config_input, &mcp_entry_after, &instruction_entry_after)
            .with_context(|| format!("merge Eliot into {}", config_path.display()))?;
    let current_eliot_entry = merged.mcp_entry_before.clone();
    let continuing_owned_config = previous.is_some_and(|manifest| {
        manifest.config_path == config_path
            && current_eliot_entry.as_ref() == Some(&manifest.mcp_entry_after)
            && (manifest.instruction_entry_after.is_empty()
                || (manifest.instruction_entry_after == instruction_entry_after
                    && merged.instruction_entry_existed_before))
    });
    let (
        config_existed,
        config_before_hash,
        config_backup_ref,
        mcp_field_existed_before,
        mcp_entry_before,
        instructions_field_existed_before,
        instruction_entry_existed_before,
    ) = if continuing_owned_config {
        let manifest = previous
            .context("continuing OpenCode ownership requires the previous install manifest")?;
        let instruction_origin = if manifest.instruction_entry_after.is_empty() {
            (
                merged.instructions_field_existed_before,
                merged.instruction_entry_existed_before,
            )
        } else {
            (
                manifest.instructions_field_existed_before,
                manifest.instruction_entry_existed_before,
            )
        };
        (
            manifest.config_existed,
            manifest.config_before_hash.clone(),
            manifest.config_backup_ref.clone(),
            manifest.mcp_field_existed_before,
            manifest.mcp_entry_before.clone(),
            instruction_origin.0,
            instruction_origin.1,
        )
    } else {
        let backup = config_existed_now
            .then(|| global_backup_path("opencode-config", config_path.extension()))
            .transpose()?;
        if !dry_run && let Some(backup) = &backup {
            std::fs::create_dir_all(backup.parent().context("config backup has no parent")?)?;
            std::fs::copy(&config_path, backup)?;
        }
        (
            config_existed_now,
            config_before_hash_now.clone(),
            backup,
            merged.mcp_field_existed_before,
            current_eliot_entry,
            merged.instructions_field_existed_before,
            merged.instruction_entry_existed_before,
        )
    };
    let config_after_bytes = merged.bytes;
    let config_after_hash = bytes_hash(&config_after_bytes);

    let mut outcome = GlobalInstallOutcome::default();
    outcome
        .installed_paths
        .push(config_path.to_string_lossy().into_owned());
    if config_before_bytes.as_deref() != Some(config_after_bytes.as_slice()) {
        outcome
            .modified_files
            .push(config_path.to_string_lossy().into_owned());
        if !dry_run {
            atomic_write_bytes(&config_path, &config_after_bytes)?;
        }
    }
    if let Some(backup) = &config_backup_ref {
        outcome
            .backup_refs
            .push(backup.to_string_lossy().into_owned());
    }

    let install_source = if dry_run { source } else { target };
    let mut owned_paths = Vec::new();
    for entry in std::fs::read_dir(install_source.join("skills"))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let destination = root.join("skills").join(entry.file_name());
        let (owned, changed) = install_owned_path(&entry.path(), &destination, previous, dry_run)?;
        record_owned_outcome(&mut outcome, &owned, &destination, changed);
        owned_paths.push(owned);
    }
    let plugin_source = install_source.join("plugins").join("eliot.js");
    let plugin_destination = root.join("plugins").join("eliot-governor.js");
    let (plugin_owned, plugin_changed) =
        install_owned_path(&plugin_source, &plugin_destination, previous, dry_run)?;
    record_owned_outcome(
        &mut outcome,
        &plugin_owned,
        &plugin_destination,
        plugin_changed,
    );
    owned_paths.push(plugin_owned);
    let instruction_source = install_source.join("instructions").join("eliot.md");
    let (instruction_owned, instruction_changed) = install_owned_path(
        &instruction_source,
        &instruction_destination,
        previous,
        dry_run,
    )?;
    record_owned_outcome(
        &mut outcome,
        &instruction_owned,
        &instruction_destination,
        instruction_changed,
    );
    owned_paths.push(instruction_owned);

    let governor_hash = bundle_hash_single(governor)?;
    let installed_binary = target.join("bin").join("eliot-governor.exe");
    let binary_hash = if dry_run {
        governor_hash
    } else {
        bundle_hash_single(&installed_binary)?
    };
    if binary_hash != bundle_hash_single(governor)? {
        bail!("installed OpenCode Eliot executable hash does not match current release");
    }

    let manifest = OpenCodeGlobalInstallManifest {
        schema_version: "eliot-opencode-global-install-v2".to_owned(),
        config_path,
        config_existed,
        config_before_hash,
        config_after_hash,
        config_backup_ref,
        mcp_field_existed_before,
        mcp_entry_before,
        mcp_entry_after,
        instructions_field_existed_before,
        instruction_entry_existed_before,
        instruction_entry_after,
        owned_paths,
    };
    if !dry_run {
        atomic_write_json(&target.join(OPENCODE_GLOBAL_MANIFEST), &manifest)?;
    }
    Ok(outcome)
}

struct OpenCodeConfigMerge {
    bytes: Vec<u8>,
    mcp_field_existed_before: bool,
    mcp_entry_before: Option<Value>,
    instructions_field_existed_before: bool,
    instruction_entry_existed_before: bool,
}

fn default_opencode_config_bytes() -> Vec<u8> {
    b"{\n  \"$schema\": \"https://opencode.ai/config.json\"\n}\n".to_vec()
}

fn parse_opencode_jsonc(bytes: &[u8]) -> Result<CstRootNode> {
    let text = std::str::from_utf8(bytes).context("OpenCode config must be UTF-8")?;
    CstRootNode::parse(text, &ParseOptions::default()).context("parse OpenCode JSONC config")
}

fn merge_opencode_mcp_config(
    bytes: &[u8],
    entry: &Value,
    instruction_entry: &str,
) -> Result<OpenCodeConfigMerge> {
    let root = parse_opencode_jsonc(bytes)?;
    let root_object = root
        .object_value()
        .context("OpenCode global config root must be an object")?;
    let mcp_field_existed_before = root_object.get("mcp").is_some();
    let mcp = root_object
        .object_value_or_create("mcp")
        .context("OpenCode global config mcp field must be an object")?;
    let mcp_entry_before = mcp
        .get("eliot")
        .and_then(|property| property.to_serde_value());
    match mcp.get("eliot") {
        Some(property) => property.set_value(json_to_cst_input(entry)),
        None => {
            mcp.append("eliot", json_to_cst_input(entry));
        }
    }
    let instructions_field_existed_before = root_object.get("instructions").is_some();
    let instruction_entry_existed_before = root_object
        .get("instructions")
        .and_then(|property| property.to_serde_value())
        .and_then(|value| value.as_array().cloned())
        .is_some_and(|values| {
            values
                .iter()
                .any(|value| value.as_str() == Some(instruction_entry))
        });
    match root_object.get("instructions") {
        Some(property) => {
            let mut instructions = property
                .to_serde_value()
                .and_then(|value| value.as_array().cloned())
                .context("OpenCode global config instructions field must be an array")?;
            if !instruction_entry_existed_before {
                instructions.push(Value::String(instruction_entry.to_owned()));
                property.set_value(json_to_cst_input(&Value::Array(instructions)));
            }
        }
        None => {
            root_object.append(
                "instructions",
                json_to_cst_input(&json!([instruction_entry])),
            );
        }
    }
    Ok(OpenCodeConfigMerge {
        bytes: root.to_string().into_bytes(),
        mcp_field_existed_before,
        mcp_entry_before,
        instructions_field_existed_before,
        instruction_entry_existed_before,
    })
}

fn remove_opencode_mcp_config(
    bytes: &[u8],
    mcp_entry_before: Option<&Value>,
    mcp_field_existed_before: bool,
    instruction_entry: &str,
    instructions_field_existed_before: bool,
    instruction_entry_existed_before: bool,
) -> Result<Vec<u8>> {
    let root = parse_opencode_jsonc(bytes)?;
    let root_object = root
        .object_value()
        .context("OpenCode global config root must be an object")?;
    let mcp_property = root_object
        .get("mcp")
        .context("OpenCode global config mcp field is missing")?;
    let mcp = mcp_property
        .object_value()
        .context("OpenCode global config mcp field is no longer an object")?;
    let eliot = mcp
        .get("eliot")
        .context("OpenCode global config mcp.eliot is missing")?;
    if let Some(before) = mcp_entry_before {
        eliot.set_value(json_to_cst_input(before));
    } else {
        eliot.remove();
        if !mcp_field_existed_before && mcp.properties().is_empty() {
            mcp_property.remove();
        }
    }
    if !instruction_entry.is_empty() && !instruction_entry_existed_before {
        let instructions_property = root_object
            .get("instructions")
            .context("OpenCode global config instructions field is missing")?;
        let mut instructions = instructions_property
            .to_serde_value()
            .and_then(|value| value.as_array().cloned())
            .context("OpenCode global config instructions field is no longer an array")?;
        let before_len = instructions.len();
        instructions.retain(|value| value.as_str() != Some(instruction_entry));
        if instructions.len() == before_len {
            bail!("OpenCode Eliot instruction entry is missing");
        }
        if !instructions_field_existed_before && instructions.is_empty() {
            instructions_property.remove();
        } else {
            instructions_property.set_value(json_to_cst_input(&Value::Array(instructions)));
        }
    }
    Ok(root.to_string().into_bytes())
}

fn json_to_cst_input(value: &Value) -> CstInputValue {
    match value {
        Value::Null => CstInputValue::Null,
        Value::Bool(value) => CstInputValue::Bool(*value),
        Value::Number(value) => CstInputValue::Number(value.to_string()),
        Value::String(value) => CstInputValue::String(value.clone()),
        Value::Array(values) => {
            CstInputValue::Array(values.iter().map(json_to_cst_input).collect())
        }
        Value::Object(values) => CstInputValue::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), json_to_cst_input(value)))
                .collect(),
        ),
    }
}

fn install_owned_path(
    source: &Path,
    destination: &Path,
    previous: Option<&OpenCodeGlobalInstallManifest>,
    dry_run: bool,
) -> Result<(OpenCodeOwnedPath, bool)> {
    let installed_hash = hash_owned_path(source)?;
    let current_hash = destination
        .exists()
        .then(|| hash_owned_path(destination))
        .transpose()?;
    let previous_owned = previous.and_then(|manifest| {
        manifest
            .owned_paths
            .iter()
            .find(|owned| owned.path == destination)
    });
    let continuing_owned = previous_owned
        .is_some_and(|owned| current_hash.as_deref() == Some(owned.installed_hash.as_str()));
    let backup_ref = if continuing_owned {
        previous_owned.and_then(|owned| owned.backup_ref.clone())
    } else if destination.exists() {
        Some(global_backup_path(
            destination
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("opencode-owned-path"),
            destination.extension(),
        )?)
    } else {
        None
    };
    let changed = current_hash.as_deref() != Some(installed_hash.as_str());
    if !dry_run && changed {
        if let Some(backup) = &backup_ref
            && !continuing_owned
        {
            std::fs::create_dir_all(backup.parent().context("backup has no parent")?)?;
            std::fs::rename(destination, backup)?;
        } else if destination.exists() {
            remove_owned_path(destination)?;
        }
        copy_owned_path(source, destination)?;
    }
    Ok((
        OpenCodeOwnedPath {
            path: destination.to_path_buf(),
            installed_hash,
            backup_ref,
        },
        changed,
    ))
}

fn record_owned_outcome(
    outcome: &mut GlobalInstallOutcome,
    owned: &OpenCodeOwnedPath,
    destination: &Path,
    changed: bool,
) {
    outcome
        .installed_paths
        .push(destination.to_string_lossy().into_owned());
    if changed {
        outcome
            .modified_files
            .push(destination.to_string_lossy().into_owned());
    }
    if let Some(backup) = &owned.backup_ref {
        outcome
            .backup_refs
            .push(backup.to_string_lossy().into_owned());
    }
}

fn install_claude_global(
    source: &Path,
    target: &Path,
    governor: &Path,
    previous: Option<&ClaudeGlobalInstallManifest>,
    dry_run: bool,
) -> Result<GlobalInstallOutcome> {
    let destination = claude_global_plugin_path()?;
    let installed_hash = claude_plugin_hash(source, governor)?;
    let current_hash =
        if destination.is_dir() && destination.join("bin").join("eliot-governor.exe").is_file() {
            Some(claude_plugin_hash(
                &destination,
                &destination.join("bin").join("eliot-governor.exe"),
            )?)
        } else if destination.exists() {
            Some(hash_owned_path(&destination)?)
        } else {
            None
        };
    let continuing_owned = previous.is_some_and(|manifest| {
        manifest.owned_plugin.path == destination
            && current_hash.as_deref() == Some(manifest.owned_plugin.installed_hash.as_str())
    });
    let backup_ref = if continuing_owned {
        previous.and_then(|manifest| manifest.owned_plugin.backup_ref.clone())
    } else if destination.exists() {
        Some(global_backup_path("claude-eliot-plugin", None)?)
    } else {
        None
    };
    let changed = current_hash.as_deref() != Some(installed_hash.as_str());

    if !dry_run && changed {
        if let Some(backup) = &backup_ref
            && !continuing_owned
        {
            std::fs::create_dir_all(backup.parent().context("backup has no parent")?)?;
            std::fs::rename(&destination, backup)?;
        } else if destination.exists() {
            remove_owned_path(&destination)?;
        }
        copy_tree(source, &destination, AgentHostId::Claude)?;
        std::fs::create_dir_all(destination.join("bin"))?;
        std::fs::copy(governor, destination.join("bin").join("eliot-governor.exe"))?;
        let actual_hash = claude_plugin_hash(
            &destination,
            &destination.join("bin").join("eliot-governor.exe"),
        )?;
        if actual_hash != installed_hash {
            bail!("installed Claude Eliot plugin hash does not match the source bundle");
        }
    }

    let owned_plugin = OpenCodeOwnedPath {
        path: destination.clone(),
        installed_hash,
        backup_ref,
    };
    if !dry_run {
        let installed_governor = destination.join("bin").join("eliot-governor.exe");
        let manifest = ClaudeGlobalInstallManifest {
            schema_version: "eliot-claude-global-install-v2".to_owned(),
            source_plugin_path: source.to_path_buf(),
            source_bundle_hash: bundle_hash(source, AgentHostId::Claude)?,
            target_plugin_path: destination.clone(),
            governor_source_path: governor.to_path_buf(),
            governor_sha256: sha256_file(governor)?,
            installed_governor_path: installed_governor.clone(),
            installed_governor_sha256: sha256_file(&installed_governor)?,
            generated_at: OffsetDateTime::now_utc().to_string(),
            owned_plugin: owned_plugin.clone(),
        };
        atomic_write_json(&target.join(CLAUDE_GLOBAL_MANIFEST), &manifest)?;
        atomic_write_json(&destination.join(CLAUDE_GLOBAL_MANIFEST), &manifest)?;
    }

    let mut outcome = GlobalInstallOutcome::default();
    outcome
        .installed_paths
        .push(destination.to_string_lossy().into_owned());
    if changed {
        outcome
            .modified_files
            .push(destination.to_string_lossy().into_owned());
    }
    if let Some(backup) = &owned_plugin.backup_ref {
        outcome
            .backup_refs
            .push(backup.to_string_lossy().into_owned());
    }
    Ok(outcome)
}

fn claude_global_plugin_path() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("USERPROFILE").context("USERPROFILE is not set")?)
            .join(".claude")
            .join("skills")
            .join("eliot"),
    )
}

fn claude_user_root() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("USERPROFILE").context("USERPROFILE is not set")?)
            .join(".claude"),
    )
}

/// Every root from which Claude Code could load ELIOT.
///
/// Claude Code discovers plugins from more than one place, and ELIOT has been
/// installed both into a skills directory and registered under the plugin data
/// root. Two roots holding ELIOT is not a cosmetic duplication: each one binds
/// its own MCP server, so a single session gets the tool set twice under
/// competing namespaces. Every root is reported, never just the first found.
fn claude_code_plugin_roots() -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    let skills_install = claude_global_plugin_path()?;
    if skills_install.join(".mcp.json").is_file() || skills_install.join(".claude-plugin").is_dir()
    {
        roots.push(skills_install);
    }
    let plugin_data = claude_user_root()?.join("plugins").join("data");
    if let Ok(entries) = std::fs::read_dir(&plugin_data) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let names_eliot = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.to_ascii_lowercase().contains("eliot"));
            // An empty registration directory is a leftover, not a live root.
            let has_content = std::fs::read_dir(&path).is_ok_and(|mut d| d.next().is_some());
            if names_eliot && has_content {
                roots.push(path);
            }
        }
    }
    Ok(roots)
}

/// Where the selected Claude surface is recorded.
///
/// Runtime state, not source: it describes this machine, so it lives with the
/// other host-integration receipts outside the repository and never in Git.
fn claude_surface_selection_path(config_path: &Path) -> PathBuf {
    runtime_root(config_path)
        .join("reports")
        .join("host-integrations")
        .join("claude-surface-selection.json")
}

fn selected_claude_surface(config_path: &Path) -> Option<ClaudeSurface> {
    let raw = std::fs::read(claude_surface_selection_path(config_path)).ok()?;
    let value: Value = serde_json::from_slice(&raw).ok()?;
    value
        .get("selected_surface")
        .and_then(Value::as_str)
        .and_then(ClaudeSurface::parse)
}

/// Selects the one Claude surface this machine should expose.
///
/// Idempotent by construction: the plan is derived from observed state, so
/// re-running once the machine already matches asks for no actions at all.
/// Only ELIOT-owned integration state is ever named -- unrelated Claude
/// configuration and other vendors' extensions are not this command's business.
fn activate_claude_surface(
    config_path: &Path,
    surface: ClaudeSurface,
    dry_run: bool,
) -> Result<Value> {
    let before = claude_family_doctor(config_path)?;
    let code_active = before
        .pointer("/surfaces/claude_code_plugin/active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let desktop_active = before
        .pointer("/surfaces/claude_desktop_mcpb/active")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let (keep_active, stand_down_active) = match surface {
        ClaudeSurface::ClaudeCodePlugin => (code_active, desktop_active),
        ClaudeSurface::ClaudeDesktopMcpb => (desktop_active, code_active),
    };
    let stand_down = match surface {
        ClaudeSurface::ClaudeCodePlugin => ClaudeSurface::ClaudeDesktopMcpb,
        ClaudeSurface::ClaudeDesktopMcpb => ClaudeSurface::ClaudeCodePlugin,
    };

    let mut actions = Vec::new();
    if !keep_active {
        actions.push(json!({
            "action": "install_surface",
            "surface": surface.as_str(),
            "command": format!("host install --host {}", match surface {
                ClaudeSurface::ClaudeCodePlugin => "claude",
                ClaudeSurface::ClaudeDesktopMcpb => "claude-desktop",
            })
        }));
    }
    if stand_down_active {
        actions.push(json!({
            "action": "stand_down_surface",
            "surface": stand_down.as_str(),
            "command": format!("host uninstall --host {}", match stand_down {
                ClaudeSurface::ClaudeCodePlugin => "claude",
                ClaudeSurface::ClaudeDesktopMcpb => "claude-desktop",
            })
        }));
    }

    let selection_path = claude_surface_selection_path(config_path);
    if !dry_run {
        if let Some(parent) = selection_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        atomic_write_json(
            &selection_path,
            &json!({
                "schema_version": "eliot-claude-surface-selection-v1",
                "host": AgentHostId::Claude.as_str(),
                "selected_surface": surface.as_str(),
                "selected_at": OffsetDateTime::now_utc(),
            }),
        )?;
    }

    Ok(json!({
        "schema_version": "eliot-claude-surface-activation-v1",
        "host": AgentHostId::Claude.as_str(),
        "selected_surface": surface.as_str(),
        "stood_down_surface": stand_down.as_str(),
        "dry_run": dry_run,
        "already_satisfied": actions.is_empty(),
        "pending_actions": actions,
        "selection_receipt": selection_path,
        // A live Claude process keeps the surfaces it started with.
        "claude_restart_required": !actions.is_empty(),
        "supports_lifecycle_hooks": surface.supports_lifecycle_hooks()
    }))
}

/// One doctor for the whole Claude host family.
///
/// `claude` is a single vendor with a single Governor authority behind two
/// packaged surfaces. Reporting them separately is what let both be active at
/// once without anything calling it a fault, so the family view is the one that
/// decides readiness: two active surfaces is a configuration error, not health.
fn claude_family_doctor(config_path: &Path) -> Result<Value> {
    let code_roots = claude_code_plugin_roots()?;
    let desktop = claude_desktop_doctor(config_path)?;
    let desktop_active = desktop
        .get("extension")
        .is_some_and(|state| !state.is_null());
    let code_active = !code_roots.is_empty();

    let mut conflicts = Vec::new();
    if code_roots.len() > 1 {
        conflicts.push(json!({
            "kind": "duplicate_code_plugin_roots",
            "detail": "Claude Code can load ELIOT from more than one root, exposing the tool set twice",
            "roots": &code_roots,
            "remediation": "keep exactly one ELIOT plugin root and remove the others"
        }));
    }
    let selected = selected_claude_surface(config_path);
    if code_active && desktop_active {
        conflicts.push(json!({
            "kind": "dual_active_surface",
            "detail": "the Claude Code plugin and the Claude Desktop MCPB are both active; a Claude Code session hosted in Desktop binds ELIOT twice",
            "remediation": match selected {
                Some(surface) => format!("host activate --host claude --surface {}", match surface {
                    ClaudeSurface::ClaudeCodePlugin => "code",
                    ClaudeSurface::ClaudeDesktopMcpb => "desktop",
                }),
                None => "host activate --host claude --surface code|desktop".to_owned(),
            }
        }));
    }
    // A selection that the machine does not match is drift, not health: the
    // intended surface is recorded but something else is answering.
    if let Some(surface) = selected {
        let selected_is_active = match surface {
            ClaudeSurface::ClaudeCodePlugin => code_active,
            ClaudeSurface::ClaudeDesktopMcpb => desktop_active,
        };
        if !selected_is_active {
            conflicts.push(json!({
                "kind": "selected_surface_inactive",
                "detail": "the selected Claude surface is not active on this machine",
                "selected_surface": surface.as_str(),
                "remediation": "install the selected surface or select the one that is active"
            }));
        }
    }

    Ok(json!({
        "schema_version": "eliot-claude-family-doctor-v1",
        "host": AgentHostId::Claude.as_str(),
        "surfaces": {
            ClaudeSurface::ClaudeCodePlugin.as_str(): {
                "active": code_active,
                "roots": &code_roots,
                "root_count": code_roots.len(),
                "supports_lifecycle_hooks": ClaudeSurface::ClaudeCodePlugin.supports_lifecycle_hooks()
            },
            ClaudeSurface::ClaudeDesktopMcpb.as_str(): {
                "active": desktop_active,
                "supports_lifecycle_hooks": ClaudeSurface::ClaudeDesktopMcpb.supports_lifecycle_hooks(),
                "detail": desktop
            }
        },
        "active_surface_count": usize::from(code_active) + usize::from(desktop_active),
        "selected_surface": selected.map(ClaudeSurface::as_str),
        "selection_receipt": claude_surface_selection_path(config_path),
        "conflicts": conflicts,
        "status": if conflicts.is_empty() {
            if code_active || desktop_active { "ready" } else { "not_installed" }
        } else {
            "conflict"
        }
    }))
}

fn claude_plugin_hash(bundle: &Path, governor: &Path) -> Result<String> {
    Ok(format!(
        "bundle={};governor={}",
        bundle_hash(bundle, AgentHostId::Claude)?,
        bundle_hash_single(governor)?
    ))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("open {} for SHA-256", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn opencode_global_root() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("USERPROFILE").context("USERPROFILE is not set")?)
            .join(".config")
            .join("opencode"),
    )
}

fn opencode_global_config_path(root: &Path) -> PathBuf {
    let jsonc = root.join("opencode.jsonc");
    if jsonc.is_file() {
        jsonc
    } else {
        root.join("opencode.json")
    }
}

fn global_backup_path(label: &str, extension: Option<&std::ffi::OsStr>) -> Result<PathBuf> {
    let mut name = format!(".{label}-{}-backup", Uuid::new_v4());
    if let Some(extension) = extension.and_then(|value| value.to_str()) {
        name.push('.');
        name.push_str(extension);
    }
    Ok(install_base()?.join("global-backups").join(name))
}

fn copy_owned_path(source: &Path, destination: &Path) -> Result<()> {
    if source.is_dir() {
        copy_tree(source, destination, AgentHostId::OpenCode)
    } else {
        std::fs::create_dir_all(destination.parent().context("destination has no parent")?)?;
        std::fs::copy(source, destination)?;
        Ok(())
    }
}

fn remove_owned_path(path: &Path) -> Result<()> {
    if path.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn hash_owned_path(path: &Path) -> Result<String> {
    if path.is_file() {
        return bundle_hash_single(path);
    }
    let mut files = Vec::new();
    collect_owned_files(path, path, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = blake3::Hasher::new();
    for (relative, file) in files {
        hasher.update(relative.as_bytes());
        hasher.update(&[0]);
        hasher.update(&std::fs::read(file)?);
        hasher.update(&[0]);
    }
    Ok(format!("blake3:{}", hasher.finalize().to_hex()))
}

fn collect_owned_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            bail!("OpenCode global integration path may not contain symlinks");
        }
        if kind.is_dir() {
            collect_owned_files(root, &entry.path(), files)?;
        } else if kind.is_file() {
            files.push((
                entry
                    .path()
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/"),
                entry.path(),
            ));
        }
    }
    Ok(())
}

fn bytes_hash(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

fn uninstall_claude_global(manifest: &ClaudeGlobalInstallManifest, dry_run: bool) -> Result<Value> {
    let owned = &manifest.owned_plugin;
    let governor = owned.path.join("bin").join("eliot-governor.exe");
    if !owned.path.is_dir() || !governor.is_file() {
        bail!(
            "refuse Claude rollback because the owned plugin is missing: {}",
            owned.path.display()
        );
    }
    let current_hash = claude_plugin_hash(&owned.path, &governor)?;
    if current_hash != owned.installed_hash {
        bail!(
            "refuse Claude rollback because the owned plugin changed after install: {}",
            owned.path.display()
        );
    }
    if dry_run {
        return Ok(json!({
            "schema_version": "eliot-claude-global-uninstall-v1",
            "dry_run": true,
            "plugin_path": owned.path,
            "provider_auth_modified": false,
            "settings_modified": false,
            "unrelated_config_preserved": true
        }));
    }

    remove_owned_path(&owned.path)?;
    if let Some(backup) = &owned.backup_ref {
        std::fs::create_dir_all(
            owned
                .path
                .parent()
                .context("Claude plugin restore path has no parent")?,
        )?;
        std::fs::rename(backup, &owned.path)?;
    }
    Ok(json!({
        "schema_version": "eliot-claude-global-uninstall-v1",
        "dry_run": false,
        "plugin_path": owned.path,
        "plugin_restored": owned.backup_ref.is_some(),
        "provider_auth_modified": false,
        "settings_modified": false,
        "unrelated_config_preserved": true
    }))
}

#[allow(clippy::too_many_lines)]
fn uninstall_opencode_global(
    manifest: &OpenCodeGlobalInstallManifest,
    dry_run: bool,
) -> Result<Value> {
    for owned in &manifest.owned_paths {
        let current_hash = owned
            .path
            .exists()
            .then(|| hash_owned_path(&owned.path))
            .transpose()?
            .with_context(|| {
                format!(
                    "refuse OpenCode rollback because owned path is missing: {}",
                    owned.path.display()
                )
            })?;
        if current_hash != owned.installed_hash {
            bail!(
                "refuse OpenCode rollback because owned path changed after install: {}",
                owned.path.display()
            );
        }
    }
    let current_bytes = std::fs::read(&manifest.config_path).with_context(|| {
        format!(
            "refuse OpenCode rollback because config is missing: {}",
            manifest.config_path.display()
        )
    })?;
    let current_root = parse_opencode_jsonc(&current_bytes).with_context(|| {
        format!(
            "refuse OpenCode rollback because config is no longer valid JSONC: {}",
            manifest.config_path.display()
        )
    })?;
    let current_eliot = current_root
        .object_value()
        .and_then(|root| root.object_value("mcp"))
        .and_then(|mcp| mcp.get("eliot"))
        .and_then(|property| property.to_serde_value());
    if current_eliot.as_ref() != Some(&manifest.mcp_entry_after) {
        bail!("refuse OpenCode rollback because mcp.eliot changed after install");
    }
    if !manifest.instruction_entry_after.is_empty() {
        let current_instructions = current_root
            .object_value()
            .and_then(|root| root.get("instructions"))
            .and_then(|property| property.to_serde_value())
            .and_then(|value| value.as_array().cloned())
            .context("refuse OpenCode rollback because instructions is missing or invalid")?;
        if !current_instructions
            .iter()
            .any(|value| value.as_str() == Some(manifest.instruction_entry_after.as_str()))
        {
            bail!("refuse OpenCode rollback because the Eliot instruction entry changed");
        }
    }
    if dry_run {
        return Ok(json!({
            "schema_version": "eliot-opencode-global-uninstall-v1",
            "dry_run": true,
            "config_path": manifest.config_path,
            "owned_paths": manifest.owned_paths,
            "provider_auth_modified": false,
            "unrelated_config_preserved": true
        }));
    }

    for owned in &manifest.owned_paths {
        remove_owned_path(&owned.path)?;
        if let Some(backup) = &owned.backup_ref {
            std::fs::create_dir_all(
                owned
                    .path
                    .parent()
                    .context("owned restore path has no parent")?,
            )?;
            std::fs::rename(backup, &owned.path)?;
        }
    }

    let current_hash = bytes_hash(&current_bytes);
    let exact_restore = current_hash == manifest.config_after_hash;
    if exact_restore {
        std::fs::remove_file(&manifest.config_path)?;
        if manifest.config_existed {
            let backup = manifest
                .config_backup_ref
                .as_ref()
                .context("OpenCode config backup is missing from install manifest")?;
            std::fs::create_dir_all(
                manifest
                    .config_path
                    .parent()
                    .context("config restore path has no parent")?,
            )?;
            std::fs::rename(backup, &manifest.config_path)?;
        }
    } else {
        let restored = remove_opencode_mcp_config(
            &current_bytes,
            manifest.mcp_entry_before.as_ref(),
            manifest.mcp_field_existed_before,
            &manifest.instruction_entry_after,
            manifest.instructions_field_existed_before,
            manifest.instruction_entry_existed_before,
        )?;
        atomic_write_bytes(&manifest.config_path, &restored)?;
    }
    Ok(json!({
        "schema_version": "eliot-opencode-global-uninstall-v1",
        "dry_run": false,
        "config_path": manifest.config_path,
        "exact_config_restore": exact_restore,
        "owned_paths_restored": manifest.owned_paths.len(),
        "provider_auth_modified": false,
        "unrelated_config_preserved": true
    }))
}

fn uninstall(config_path: &Path, host: AgentHostId, dry_run: bool) -> Result<Value> {
    ensure_l7_host(host)?;
    let base = install_base()?;
    let target = base.join(host.as_str());
    ensure_child(&base, &target)?;
    let receipt_path = install_receipt_path(config_path, host);
    let recorded: HostIntegrationReceipt = serde_json::from_reader(
        std::fs::File::open(&receipt_path)
            .with_context(|| format!("read install receipt {}", receipt_path.display()))?,
    )?;
    if !recorded
        .installed_paths
        .iter()
        .any(|path| Path::new(path) == target)
    {
        bail!(
            "install receipt does not authorize removal of {}",
            target.display()
        );
    }
    let global_uninstall = match host {
        AgentHostId::OpenCode => {
            let manifest = read_opencode_global_manifest(&target)?.context(
                "OpenCode install receipt predates global discovery ownership; reinstall before uninstall",
            )?;
            Some(uninstall_opencode_global(&manifest, dry_run)?)
        }
        AgentHostId::Claude => {
            let manifest = read_claude_global_manifest(&target)?.context(
                "Claude install receipt predates global discovery ownership; reinstall before uninstall",
            )?;
            Some(uninstall_claude_global(&manifest, dry_run)?)
        }
        _ => None,
    };
    let existed = target.is_dir();
    if existed && !dry_run {
        std::fs::remove_dir_all(&target)?;
    }
    Ok(json!({
        "schema_version": "eliot-host-uninstall-v1",
        "host": host,
        "target": target,
        "existed": existed,
        "removed": existed && !dry_run,
        "dry_run": dry_run,
        "global_uninstall": global_uninstall,
        "provider_auth_modified": false,
        "unrelated_config_preserved": true
    }))
}

fn record_event(config_path: &Path, host: AgentHostId, declared_event: &str) -> Result<Value> {
    ensure_l7_host(host)?;
    let mut raw = Vec::new();
    std::io::stdin().take(64 * 1024 + 1).read_to_end(&mut raw)?;
    let mut envelope = HostEventService.normalize(host, declared_event, &raw)?;
    envelope.task_id = env_parse("ELIOT_TASK_ID")?;
    envelope.work_item_id = env_parse("ELIOT_WORK_ITEM_ID")?;
    let lease: Option<WorkLeaseId> = env_parse("ELIOT_WORK_LEASE_ID")?;
    let attached_mutation = envelope.task_id.is_some()
        && matches!(declared_event, "PreToolUse" | "tool.execute.before");
    let decision = if attached_mutation && lease.is_none() {
        "deny"
    } else if envelope.task_id.is_some() {
        "recorded"
    } else {
        "passive"
    };
    let event_root = runtime_root(config_path)
        .join("reports")
        .join("host-events")
        .join(host.as_str());
    let path = event_root.join(format!("{}.json", Uuid::new_v4()));
    atomic_write_json(&path, &envelope)?;
    atomic_write_json(&event_root.join("latest.json"), &envelope)?;
    if host == AgentHostId::Claude {
        if decision == "deny" {
            return Ok(json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "attached mutating task has no current work lease reference"
                }
            }));
        }
        if declared_event == "SessionStart" {
            return Ok(json!({
                "continue": true,
                "suppressOutput": true,
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": "For a material project task, load the matching eliot:* skill and use ELIOT project identity/current state before broad search or mutation. Skills guide; current task leases and gates authorize."
                }
            }));
        }
        return Ok(json!({
            "continue": true,
            "suppressOutput": true
        }));
    }
    Ok(json!({
        "decision": decision,
        "reason": (decision == "deny").then_some("attached mutating task has no current work lease reference"),
        "event_ref": path,
        "raw_payload_stored": false,
        "host_identity_granted_role": false
    }))
}

fn env_parse<T>(name: &str) -> Result<Option<T>>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .parse()
                .map_err(|error| anyhow::anyhow!("parse {name}: {error}"))
        })
        .transpose()
}

fn parse_host(value: &str) -> Result<AgentHostId> {
    match value.trim().to_ascii_lowercase().as_str() {
        "opencode" => Ok(AgentHostId::OpenCode),
        "claude" | "claude-code" => Ok(AgentHostId::Claude),
        "codex" => Ok(AgentHostId::Codex),
        "antigravity" | "agy" => Ok(AgentHostId::Antigravity),
        other => bail!("unknown agent host: {other}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_launch_scope(
    project: Option<String>,
    agent_session: Option<String>,
    task: Option<String>,
    work_item: Option<String>,
    role_lease: Option<String>,
    work_lease: Option<String>,
    worktree_lease: Option<String>,
    planned_verifier_ref: Option<String>,
    baseline_commit: Option<String>,
    write_paths: Vec<String>,
) -> Result<HostLaunchScope> {
    Ok(HostLaunchScope {
        project_id: project
            .map(|value| ProjectId::from_str(&value).context("parse --project"))
            .transpose()?,
        agent_session_id: agent_session
            .map(|value| AgentSessionId::from_str(&value).context("parse --agent-session"))
            .transpose()?,
        task_id: task
            .map(|value| TaskId::from_str(&value).context("parse --task"))
            .transpose()?,
        work_item_id: work_item
            .map(|value| WorkItemId::from_str(&value).context("parse --work-item"))
            .transpose()?,
        role_lease_id: role_lease,
        work_lease_id: work_lease
            .map(|value| WorkLeaseId::from_str(&value).context("parse --work-lease"))
            .transpose()?,
        worktree_lease_id: worktree_lease
            .map(|value| WorktreeLeaseId::from_str(&value).context("parse --worktree-lease"))
            .transpose()?,
        planned_verifier_ref,
        baseline_commit,
        allowed_paths: write_paths,
        forbidden_paths: Vec::new(),
    })
}

async fn bind_launch_scope(
    config_path: &Path,
    host: AgentHostId,
    cwd: Option<&Path>,
    scope: &mut HostLaunchScope,
) -> Result<Option<ManagedCanonicalAuthority>> {
    if scope.task_id.is_none()
        && scope.role_lease_id.is_none()
        && scope.work_lease_id.is_none()
        && scope.worktree_lease_id.is_none()
    {
        scope.agent_session_id = None;
        return Ok(None);
    }
    let task_id = scope
        .task_id
        .context("scoped host launch requires --task")?;
    let role_lease_id = scope
        .role_lease_id
        .as_deref()
        .context("scoped host launch requires --role-lease")?;
    let state = delegation_runtime::load_state(&runtime_root(config_path))?;
    let now = OffsetDateTime::now_utc();
    let role = state
        .task_role_leases
        .iter()
        .find(|lease| {
            lease.role_lease_id == role_lease_id
                && lease.task_id == task_id
                && lease.expires_at > now
        })
        .context("no active matching TaskRoleLease")?;
    let binding = state
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == role.agent_session_id)
        .context("TaskRoleLease session has no host binding")?;
    if binding.host_identity.host_id != host {
        bail!("TaskRoleLease is bound to a different agent host");
    }
    if scope
        .agent_session_id
        .is_some_and(|session| session != role.agent_session_id)
    {
        bail!("--agent-session does not match TaskRoleLease holder");
    }
    scope.agent_session_id = Some(role.agent_session_id);
    let work_state = delegation_runtime::load_work_state(&runtime_root(config_path))?;
    if let Some(work_lease_id) = scope.work_lease_id {
        let active = work_state.leases.iter().any(|lease| {
            lease.work_lease_id == work_lease_id
                && lease.task_id == task_id
                && lease.agent_session_id == role.agent_session_id
                && work_lease_is_active(lease)
        });
        if !active {
            bail!("no active matching WorkLease for scoped host launch");
        }
    }
    if host == AgentHostId::Antigravity {
        validate_antigravity_scope(&state, &work_state, cwd, scope, now)?;
        return Ok(Some(
            validate_canonical_antigravity_authority(config_path, &state, &work_state, scope)
                .await?,
        ));
    }
    Ok(None)
}

fn validate_antigravity_scope(
    delegation_state: &DelegationState,
    work_state: &WorkState,
    cwd: Option<&Path>,
    scope: &mut HostLaunchScope,
    now: OffsetDateTime,
) -> Result<()> {
    let project_id = scope
        .project_id
        .context("governed Antigravity launch requires --project")?;
    let task_id = scope
        .task_id
        .context("governed Antigravity launch requires --task")?;
    let work_item_id = scope
        .work_item_id
        .context("governed Antigravity launch requires --work-item")?;
    let agent_session_id = scope
        .agent_session_id
        .context("governed Antigravity launch requires --agent-session")?;
    let role_lease_id = scope
        .role_lease_id
        .as_deref()
        .context("governed Antigravity launch requires --role-lease")?;
    let work_lease_id = scope
        .work_lease_id
        .context("governed Antigravity launch requires --work-lease")?;
    let worktree_lease_id = scope
        .worktree_lease_id
        .context("governed Antigravity launch requires --worktree-lease")?;
    let cwd = cwd.context("governed Antigravity launch requires --cwd")?;
    let planned_verifier_ref = scope
        .planned_verifier_ref
        .as_deref()
        .context("governed Antigravity launch requires --planned-verifier-ref")?;
    crate::mcp_stdio::RegisteredTaskVerifier::from_reference(planned_verifier_ref)
        .context("governed Antigravity planned verifier reference is unregistered or stale")?;

    let role = delegation_state
        .task_role_leases
        .iter()
        .find(|lease| lease.role_lease_id == role_lease_id)
        .context("governed Antigravity TaskRoleLease was not found")?;
    if role.task_id != task_id
        || role.agent_session_id != agent_session_id
        || role.expires_at <= now
        || role.role == AgentRole::Controller
    {
        bail!("governed Antigravity TaskRoleLease is expired or scope-mismatched");
    }

    let work = work_state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == work_lease_id)
        .context("governed Antigravity WorkLease was not found")?;
    if !work_lease_is_active(work)
        || work.project_id != project_id
        || work.task_id != task_id
        || work.work_item_id != work_item_id
        || work.agent_session_id != agent_session_id
    {
        bail!("governed Antigravity WorkLease is expired or scope-mismatched");
    }

    let worktree = work_state
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == worktree_lease_id)
        .context("governed Antigravity WorktreeLease was not found")?;
    if worktree.state != WorktreeLeaseState::Active
        || worktree.expires_at <= now
        || worktree.project_id != project_id
        || worktree.task_id != task_id
        || worktree.work_item_id != work_item_id
        || worktree.work_lease_id != work_lease_id
        || worktree.holder_session_id != agent_session_id
    {
        bail!("governed Antigravity WorktreeLease is expired or scope-mismatched");
    }
    let requested_cwd = cwd
        .canonicalize()
        .context("canonicalize governed Antigravity --cwd")?;
    let canonical_worktree = PathBuf::from(&worktree.worktree_path)
        .canonicalize()
        .context("canonicalize governed Antigravity WorktreeLease path")?;
    if requested_cwd != canonical_worktree {
        bail!("--cwd must equal the canonical WorktreeLease path");
    }
    assert_managed_path_is_local_and_private(&canonical_worktree)?;
    let actual_head = git_text(&canonical_worktree, &["rev-parse", "HEAD"])?;
    if actual_head != worktree.base_commit {
        bail!("current worktree HEAD does not match the canonical WorktreeLease baseline");
    }
    scope.baseline_commit = Some(actual_head);

    let requested_write = normalize_write_set(&scope.allowed_paths)?;
    let canonical_write = normalize_write_set(&worktree.allowed_write_set)?;
    if requested_write.is_empty() || requested_write != canonical_write {
        bail!("--write-path set must exactly match the canonical WorktreeLease write set");
    }
    if requested_write
        .iter()
        .any(|path| !path_in_scope(path, &work.scope.write_set))
    {
        bail!("governed Antigravity write set escapes the active WorkLease");
    }
    scope.allowed_paths = requested_write.into_iter().collect();
    Ok(())
}

fn hash_json(value: &Value) -> Result<String> {
    Ok(format!(
        "blake3:{}",
        blake3::hash(&serde_json::to_vec(value)?).to_hex()
    ))
}

fn receipt_ref_from_option(
    value: Option<&WriteReceiptRef>,
    authority: &str,
) -> Result<WriteReceiptRef> {
    value
        .cloned()
        .with_context(|| format!("{authority} lacks a canonical WriteReceipt"))
}

async fn resolve_canonical_receipt(
    store: &CanonicalStore,
    reference: &WriteReceiptRef,
    project_id: ProjectId,
    task_id: Option<TaskId>,
    authority: &str,
) -> Result<WriteReceipt> {
    let receipt = store
        .write_receipt_by_id(&reference.write_id)
        .await?
        .with_context(|| format!("{authority} WriteReceipt does not resolve canonically"))?;
    if receipt.receipt_id != reference.receipt_id
        || receipt.write_id != reference.write_id
        || receipt.project_id != project_id
        || task_id.is_some_and(|expected| receipt.task_id != Some(expected))
        || receipt.status != WriteStatus::Committed
        || receipt.memory_revision.is_none()
        || receipt.project_sequence.is_none()
        || receipt.rejected_reason.is_some()
    {
        bail!("{authority} canonical WriteReceipt is stale, rejected, or scope-mismatched");
    }
    Ok(receipt)
}

fn body_without_local_receipt<T: Serialize>(value: &T) -> Result<Value> {
    let mut body = serde_json::to_value(value)?;
    if let Some(object) = body.as_object_mut()
        && object.contains_key("write_receipt")
    {
        object.insert("write_receipt".to_owned(), Value::Null);
    }
    Ok(body)
}

fn json_difference_paths(expected: &Value, observed: &Value) -> Vec<String> {
    fn collect(expected: &Value, observed: &Value, path: &str, output: &mut Vec<String>) {
        match (expected, observed) {
            (Value::Object(expected), Value::Object(observed)) => {
                let keys = expected
                    .keys()
                    .chain(observed.keys())
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                for key in keys {
                    let child = if path.is_empty() {
                        key.to_owned()
                    } else {
                        format!("{path}.{key}")
                    };
                    match (expected.get(key), observed.get(key)) {
                        (Some(expected), Some(observed)) => {
                            collect(expected, observed, &child, output);
                        }
                        _ => output.push(child),
                    }
                }
            }
            (Value::Array(expected), Value::Array(observed)) => {
                let length = expected.len().max(observed.len());
                for index in 0..length {
                    let child = format!("{path}[{index}]");
                    match (expected.get(index), observed.get(index)) {
                        (Some(expected), Some(observed)) => {
                            collect(expected, observed, &child, output);
                        }
                        _ => output.push(child),
                    }
                }
            }
            _ if expected != observed => output.push(path.to_owned()),
            _ => {}
        }
    }

    let mut output = Vec::new();
    collect(expected, observed, "", &mut output);
    output
}

fn normalize_authority_json(
    value: &Value,
    normalization: CanonicalBodyNormalization,
) -> Result<Value> {
    let CanonicalBodyNormalization::Rfc3339Fields(fields) = normalization else {
        return Ok(value.clone());
    };
    let mut normalized = value.clone();
    let object = normalized
        .as_object_mut()
        .context("timestamp-normalized canonical authority body must be an object")?;
    for field in fields {
        let mut value = &mut *object;
        let mut segments = field.split('.').peekable();
        let leaf = loop {
            let segment = segments
                .next()
                .with_context(|| format!("canonical authority timestamp path {field} is empty"))?;
            let child = value.get_mut(segment).with_context(|| {
                format!("canonical authority body lacks timestamp field {field}")
            })?;
            if segments.peek().is_none() {
                break child;
            }
            value = child.as_object_mut().with_context(|| {
                format!("canonical authority timestamp parent for {field} is not an object")
            })?;
        };
        let value = leaf;
        if value.is_null() {
            continue;
        }
        let raw = value
            .as_str()
            .with_context(|| format!("canonical authority timestamp {field} is not a string"))?;
        let timestamp = OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
            .with_context(|| format!("canonical authority timestamp {field} is not RFC3339"))?;
        *value = Value::String(timestamp.unix_timestamp_nanos().to_string());
    }
    Ok(normalized)
}

fn validate_canonical_observation_identity(
    observation: &CanonicalToolObservation,
    receipt: &WriteReceipt,
    project_id: ProjectId,
    expected: &CanonicalAuthorityBody<'_>,
) -> Result<()> {
    let created_identity = receipt
        .created_records
        .iter()
        .any(|record| record == &observation.observation_id);
    let observed_body = observation.payload.get(expected.payload_key);
    let normalized_observed_body = if expected
        .body
        .get("write_receipt")
        .is_some_and(Value::is_null)
    {
        observed_body.map(body_without_local_receipt).transpose()?
    } else {
        observed_body.cloned()
    };
    let normalized_expected_body = normalize_authority_json(expected.body, expected.normalization)?;
    let normalized_observed_body = normalized_observed_body
        .as_ref()
        .map(|body| normalize_authority_json(body, expected.normalization))
        .transpose()?;
    let body_matches = normalized_observed_body.as_ref() == Some(&normalized_expected_body);
    let expected_revision = receipt.memory_revision.context("missing revision")?;
    let expected_sequence = receipt.project_sequence.context("missing sequence")?;
    let mut differences = Vec::new();
    if receipt.command_kind != SemanticCommandKind::ToolObservationRecord {
        differences.push("command_kind".to_owned());
    }
    if observation.observation_id != receipt.write_id.to_string() {
        differences.push("observation_id".to_owned());
    }
    if observation.write_id != receipt.write_id {
        differences.push("write_id".to_owned());
    }
    if observation.project_id != project_id {
        differences.push("project_id".to_owned());
    }
    if observation.task_id != expected.task_id {
        differences.push("task_id".to_owned());
    }
    if observation.memory_revision != expected_revision {
        differences.push("memory_revision".to_owned());
    }
    if observation.project_sequence != expected_sequence {
        differences.push("project_sequence".to_owned());
    }
    if observation.scope != expected.scope {
        differences.push("scope".to_owned());
    }
    if observation.authority != expected.authority {
        differences.push("authority".to_owned());
    }
    if observation.tool_name != expected.tool_name {
        differences.push("tool_name".to_owned());
    }
    if !created_identity {
        differences.push("created_record_identity".to_owned());
    }
    if !body_matches {
        let observed_hash = normalized_observed_body
            .as_ref()
            .map(hash_json)
            .transpose()?
            .unwrap_or_else(|| "missing".to_owned());
        let body_paths = normalized_observed_body.as_ref().map_or_else(
            || "missing".to_owned(),
            |observed| json_difference_paths(&normalized_expected_body, observed).join("|"),
        );
        differences.push(format!(
            "body(paths={body_paths},expected_hash={},observed_hash={observed_hash})",
            hash_json(&normalized_expected_body)?
        ));
    }
    if !differences.is_empty() {
        bail!(
            "{} canonical observation identity differs: {}",
            expected.label,
            differences.join(",")
        );
    }
    Ok(())
}

async fn resolve_latest_canonical_authority_body(
    store: &CanonicalStore,
    reference: &WriteReceiptRef,
    project_id: ProjectId,
    entity_kind: &str,
    entity_ref: &str,
    expected: CanonicalAuthorityBody<'_>,
) -> Result<WriteReceipt> {
    let observations = store
        .latest_authority_observations_by_entity(
            project_id,
            expected.task_id,
            entity_kind,
            entity_ref,
        )
        .await?;
    let latest = latest_canonical_authority_observation(&observations, reference, expected.label)?;
    let receipt = resolve_canonical_receipt(
        store,
        reference,
        project_id,
        expected.task_id,
        expected.label,
    )
    .await?;
    validate_canonical_observation_identity(latest, &receipt, project_id, &expected)?;
    Ok(receipt)
}

fn latest_canonical_authority_observation<'a>(
    observations: &'a [CanonicalToolObservation],
    reference: &WriteReceiptRef,
    label: &str,
) -> Result<&'a CanonicalToolObservation> {
    let latest = observations
        .first()
        .with_context(|| format!("{label} has no current canonical entity record"))?;
    if observations.get(1).is_some_and(|prior| {
        prior.memory_revision == latest.memory_revision
            && prior.project_sequence == latest.project_sequence
    }) {
        bail!("{label} current canonical entity record is ambiguous");
    }
    if latest.write_id != reference.write_id {
        bail!("{label} local projection is older than the current canonical entity record");
    }
    Ok(latest)
}

async fn current_task_authority(
    store: &CanonicalStore,
    project_id: ProjectId,
    task_id: TaskId,
) -> Result<(TaskContract, WriteReceipt)> {
    let task = store
        .task_contract_by_id(task_id)
        .await?
        .context("managed Antigravity requires a current canonical TaskContract")?;
    if task.project_id != project_id || task.status != TaskContractStatus::Open {
        bail!("managed Antigravity requires the open current TaskContract in the exact project");
    }
    let receipt = store
        .write_receipt_by_id(&task.write_id)
        .await?
        .context("TaskContract canonical WriteReceipt does not resolve")?;
    if receipt.project_id != project_id
        || receipt.task_id != Some(task_id)
        || receipt.command_kind != SemanticCommandKind::TaskContractWrite
        || receipt.status != WriteStatus::Committed
        || receipt.memory_revision != Some(task.memory_revision)
        || !receipt
            .created_records
            .iter()
            .any(|record| record == &task_id.to_string())
        || receipt.rejected_reason.is_some()
    {
        bail!("TaskContract canonical WriteReceipt is stale, rejected, or scope-mismatched");
    }
    Ok((task, receipt))
}

async fn current_session_authority(
    store: &CanonicalStore,
    work_state: &WorkState,
    project_id: ProjectId,
    session_id: AgentSessionId,
) -> Result<WriteReceipt> {
    let session = work_state
        .sessions
        .iter()
        .find(|session| session.agent_session_id == session_id)
        .context("managed Antigravity AgentSession is absent from the current work projection")?;
    if session.project_id != project_id
        || !matches!(
            session.status,
            AgentSessionStatus::Active | AgentSessionStatus::Idle
        )
    {
        bail!("managed Antigravity AgentSession is inactive or project-mismatched");
    }
    let reference = receipt_ref_from_option(session.write_receipt.as_ref(), "AgentSession")?;
    let body = body_without_local_receipt(session)?;
    resolve_latest_canonical_authority_body(
        store,
        &reference,
        project_id,
        "agent_session",
        &session_id.to_string(),
        CanonicalAuthorityBody {
            label: "AgentSession",
            task_id: None,
            scope: "work/agent-session",
            authority: "eliot-work-coordination-service",
            tool_name: "eliot_work_coordination",
            payload_key: "agent_session",
            body: &body,
            normalization: CanonicalBodyNormalization::Rfc3339Fields(&[
                "started_at",
                "last_heartbeat_at",
                "stopped_at",
            ]),
        },
    )
    .await
}

async fn current_role_authority(
    config_path: &Path,
    store: &CanonicalStore,
    delegation_state: &DelegationState,
    project_id: ProjectId,
    task_id: TaskId,
    role_lease_id: &str,
    task_revision: u64,
) -> Result<(u64, WriteReceipt, RoleLeaseAuthorityRecord)> {
    let role = delegation_state
        .task_role_leases
        .iter()
        .find(|role| role.role_lease_id == role_lease_id)
        .context("managed Antigravity TaskRoleLease disappeared")?;
    let role_value = serde_json::to_value(role)?;
    let authority: RoleLeaseAuthorityRecord =
        serde_json::from_reader(File::open(role_authority_path(config_path, role_lease_id))?)?;
    if authority.role_lease_id != role_lease_id
        || authority.lease_hash != hash_json(&role_value)?
        || authority.task_revision != task_revision
    {
        bail!("TaskRoleLease canonical authority is stale or tampered");
    }
    let receipt = resolve_latest_canonical_authority_body(
        store,
        &authority.canonical_receipt,
        project_id,
        "task_role_lease",
        role_lease_id,
        CanonicalAuthorityBody {
            label: "TaskRoleLease",
            task_id: Some(task_id),
            scope: "governed host authority",
            authority: "canonical Eliot host boundary",
            tool_name: "eliot-governor-host",
            payload_key: "receipt_body",
            body: &role_value,
            normalization: CanonicalBodyNormalization::Rfc3339Fields(&["expires_at"]),
        },
    )
    .await?;
    Ok((role.epoch, receipt, authority))
}

async fn current_host_binding_authority(
    store: &CanonicalStore,
    project_id: ProjectId,
    task_id: TaskId,
    binding: &AgentSessionHostBinding,
    authority: &RoleLeaseAuthorityRecord,
) -> Result<WriteReceipt> {
    let body = serde_json::to_value(binding)?;
    if hash_json(&body)? != authority.host_binding_hash {
        bail!("AgentSessionHostBinding local body differs from canonical authority");
    }
    resolve_latest_canonical_authority_body(
        store,
        &authority.canonical_host_binding_receipt,
        project_id,
        "host_binding",
        &binding.agent_session_id.to_string(),
        CanonicalAuthorityBody {
            label: "AgentSessionHostBinding",
            task_id: Some(task_id),
            scope: "governed host authority",
            authority: "canonical Eliot host boundary",
            tool_name: "eliot-governor-host",
            payload_key: "receipt_body",
            body: &body,
            normalization: CanonicalBodyNormalization::Exact,
        },
    )
    .await
}

async fn current_work_authority(
    store: &CanonicalStore,
    work_state: &WorkState,
    project_id: ProjectId,
    task_id: TaskId,
    work_lease_id: WorkLeaseId,
    worktree_lease_id: WorktreeLeaseId,
) -> Result<ManagedWorkAuthority> {
    let work_lease = work_state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == work_lease_id)
        .cloned()
        .context("managed Antigravity WorkLease disappeared")?;
    let work_reference = receipt_ref_from_option(work_lease.write_receipt.as_ref(), "WorkLease")?;
    let work_body = body_without_local_receipt(&work_lease)?;
    let work_receipt = resolve_latest_canonical_authority_body(
        store,
        &work_reference,
        project_id,
        "work_lease",
        &work_lease_id.to_string(),
        CanonicalAuthorityBody {
            label: "WorkLease",
            task_id: Some(task_id),
            scope: "work/work-lease",
            authority: "eliot-work-coordination-service",
            tool_name: "eliot_work_coordination",
            payload_key: "work_lease",
            body: &work_body,
            normalization: CanonicalBodyNormalization::Rfc3339Fields(&[
                "decision.expires_at",
                "granted_at",
                "expires_at",
                "renewed_at",
                "released_at",
                "revoked_at",
            ]),
        },
    )
    .await?;
    let worktree_lease = work_state
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == worktree_lease_id)
        .cloned()
        .context("managed Antigravity WorktreeLease disappeared")?;
    let worktree_reference =
        receipt_ref_from_option(worktree_lease.write_receipt.as_ref(), "WorktreeLease")?;
    let worktree_body = body_without_local_receipt(&worktree_lease)?;
    let worktree_receipt = resolve_latest_canonical_authority_body(
        store,
        &worktree_reference,
        project_id,
        "worktree_lease",
        &worktree_lease_id.to_string(),
        CanonicalAuthorityBody {
            label: "WorktreeLease",
            task_id: Some(task_id),
            scope: "worktree-lease",
            authority: "local-worktree-governor",
            tool_name: "eliot_worktree_governor",
            payload_key: "worktree_lease",
            body: &worktree_body,
            normalization: CanonicalBodyNormalization::Rfc3339Fields(&[
                "issued_at",
                "expires_at",
                "cleaned_at",
            ]),
        },
    )
    .await?;
    Ok(ManagedWorkAuthority {
        work_lease,
        work_receipt,
        worktree_lease,
        worktree_receipt,
    })
}

async fn validate_canonical_antigravity_authority(
    config_path: &Path,
    delegation_state: &DelegationState,
    work_state: &WorkState,
    scope: &HostLaunchScope,
) -> Result<ManagedCanonicalAuthority> {
    let project_id = scope
        .project_id
        .context("missing canonical project scope")?;
    let task_id = scope.task_id.context("missing canonical task scope")?;
    let session_id = scope
        .agent_session_id
        .context("missing canonical session scope")?;
    let role_lease_id = scope
        .role_lease_id
        .as_deref()
        .context("missing canonical role scope")?;
    let work_lease_id = scope
        .work_lease_id
        .context("missing canonical work scope")?;
    let worktree_lease_id = scope
        .worktree_lease_id
        .context("missing canonical worktree scope")?;
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal);
    let (task, task_receipt) = current_task_authority(&store, project_id, task_id).await?;
    let session_receipt =
        current_session_authority(&store, work_state, project_id, session_id).await?;
    let (role_epoch, role_receipt, role_authority) = current_role_authority(
        config_path,
        &store,
        delegation_state,
        project_id,
        task_id,
        role_lease_id,
        task.memory_revision.value(),
    )
    .await?;
    let work = current_work_authority(
        &store,
        work_state,
        project_id,
        task_id,
        work_lease_id,
        worktree_lease_id,
    )
    .await?;
    let host_binding = delegation_state
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == session_id)
        .cloned()
        .context("managed Antigravity host binding disappeared")?;
    let host_binding_receipt =
        current_host_binding_authority(&store, project_id, task_id, &host_binding, &role_authority)
            .await?;
    let authority_material = json!({
        "task_revision": task.memory_revision,
        "task_receipt": task_receipt,
        "session_receipt": session_receipt,
        "role_receipt": role_receipt,
        "host_binding_receipt": host_binding_receipt,
        "work_receipt": work.work_receipt,
        "worktree_receipt": work.worktree_receipt,
        "role_epoch": role_epoch,
        "work_epoch": work.work_lease.epoch,
        "worktree_baseline": work.worktree_lease.base_commit,
        "planned_verifier_ref": scope.planned_verifier_ref,
    });
    Ok(ManagedCanonicalAuthority {
        task_receipt,
        session_receipt,
        role_receipt,
        host_binding_receipt,
        work_receipt: work.work_receipt,
        worktree_receipt: work.worktree_receipt,
        work_lease: work.work_lease,
        worktree_lease: work.worktree_lease,
        host_binding,
        authority_hash: hash_json(&authority_material)?,
    })
}

fn normalize_write_set(paths: &[String]) -> Result<BTreeSet<String>> {
    paths
        .iter()
        .map(|path| normalize_relative_path(path))
        .collect()
}

fn normalize_relative_path(value: &str) -> Result<String> {
    let path = Path::new(value.trim());
    if value.trim().is_empty() || path.is_absolute() {
        bail!("write paths must be non-empty relative paths");
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("write path escapes the governed worktree: {value}");
            }
        }
    }
    if parts.is_empty() {
        bail!("write paths must not resolve to the worktree root");
    }
    Ok(parts.join("/"))
}

fn path_is_within(child: &Path, parent: &Path) -> Result<bool> {
    let normalize = |path: &Path| -> Result<String> {
        let absolute = std::path::absolute(path)?;
        Ok(absolute
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .trim_end_matches(['\\', '/'])
            .replace('/', "\\")
            .to_ascii_lowercase())
    };
    let child = normalize(child)?;
    let parent = normalize(parent)?;
    Ok(child == parent || child.starts_with(&format!("{parent}\\")))
}

fn assert_managed_path_is_local_and_private(path: &Path) -> Result<()> {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .context("LOCALAPPDATA is required for managed Antigravity isolation")?;
    let owned = local.join("Eliot");
    if !path_is_within(path, &owned)? {
        bail!("managed Antigravity worktrees must be caller-owned under LocalAppData/Eliot");
    }
    for forbidden in [
        std::env::var_os("OneDrive").map(PathBuf::from),
        std::env::var_os("OneDriveCommercial").map(PathBuf::from),
        std::env::var_os("ProgramData").map(PathBuf::from),
    ]
    .into_iter()
    .flatten()
    {
        if path_is_within(path, &forbidden)? {
            bail!("managed Antigravity path is inside forbidden global or OneDrive state");
        }
    }
    Ok(())
}

fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = StdCommand::new("git")
        .current_dir(root)
        .args(args)
        .output()?;
    if !output.status.success() {
        bail!(
            "git {:?} failed in {}: {}",
            args,
            root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git_bytes(root, args)?)?.trim().to_owned())
}

fn register_session(
    config_path: &Path,
    host: AgentHostId,
    session: Option<String>,
    client_instance: Option<String>,
) -> Result<Value> {
    let session = session
        .map(|value| AgentSessionId::from_str(&value).context("parse --session"))
        .transpose()?
        .unwrap_or_else(AgentSessionId::new_v7);
    let (implementation_name, capability_envelope) = if host == AgentHostId::Codex {
        (
            "OpenAI Codex (in-process primary host)".to_owned(),
            AgentCapabilityEnvelope {
                capabilities: vec![
                    "delegate".to_owned(),
                    "review".to_owned(),
                    "verify".to_owned(),
                    "controller".to_owned(),
                ],
                structured_output: true,
                resumable: true,
                interactive: true,
                supervised: true,
            },
        )
    } else {
        let profile = HostProfileService.probe(host)?;
        (
            profile.implementation_name,
            AgentCapabilityEnvelope {
                capabilities: profile.launch_capabilities,
                structured_output: profile.protocol_surfaces.structured_output,
                resumable: profile.supported_modes.iter().any(|mode| mode == "resume"),
                interactive: profile
                    .supported_modes
                    .iter()
                    .any(|mode| mode == "interactive_client"),
                supervised: profile
                    .supported_modes
                    .iter()
                    .any(|mode| mode == "supervised_noninteractive"),
            },
        )
    };
    let mut state = delegation_runtime::load_state(&runtime_root(config_path))?;
    let binding = HostBrokerService.register_session(
        &mut state,
        session,
        host,
        implementation_name,
        client_instance.unwrap_or_else(|| session.to_string()),
        capability_envelope,
    )?;
    delegation_runtime::save_host_broker_state(&runtime_root(config_path), &state)?;
    Ok(json!({
        "schema_version": "eliot-host-session-registration-v1",
        "binding": binding,
        "host_identity_granted_role": false
    }))
}

fn deterministic_host_write_id(key: &str) -> WriteId {
    let digest = blake3::hash(key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    WriteId::from_uuid(Uuid::from_bytes(bytes))
}

fn role_authority_path(config_path: &Path, role_lease_id: &str) -> PathBuf {
    role_authority_path_from_root(&runtime_root(config_path), role_lease_id)
}

fn role_authority_path_from_root(root: &Path, role_lease_id: &str) -> PathBuf {
    root.join("reports")
        .join("role-lease-authority")
        .join(format!(
            "{}.json",
            blake3::hash(role_lease_id.as_bytes()).to_hex()
        ))
}

async fn write_canonical_host_observation(
    config_path: &Path,
    project_id: ProjectId,
    task_id: TaskId,
    agent_session_id: AgentSessionId,
    key: &str,
    receipt_kind: &str,
    body: &Value,
) -> Result<(WriteReceiptRef, WriteReceipt)> {
    let response = named_pipe_ipc::host_governor_request(
        &host_governor_instance(config_path)?,
        "host/observation-record",
        json!({
            "project_id": project_id,
            "task_id": task_id,
            "agent_session_id": agent_session_id,
            "key": key,
            "receipt_kind": receipt_kind,
            "body": body,
        }),
    )
    .await
    .context("route managed host observation through the daemon-owned WriterActor")?;
    let output: HostObservationOutput =
        serde_json::from_value(response).context("decode private host observation receipt")?;
    Ok((output.canonical_receipt, output.write_receipt))
}

async fn write_canonical_host_observation_with_writer(
    writer: &WriterHandle,
    project_id: ProjectId,
    task_id: TaskId,
    agent_session_id: AgentSessionId,
    key: &str,
    receipt_kind: &str,
    body: &Value,
) -> Result<(WriteReceiptRef, WriteReceipt)> {
    let write_id = deterministic_host_write_id(key);
    let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id,
            agent_id: AgentId::from_uuid(agent_session_id.as_uuid()),
            session_id: Some(SessionId::from_uuid(agent_session_id.as_uuid())),
            project_id,
            task_id: Some(task_id),
            scope: "governed host authority".to_owned(),
            authority: "canonical Eliot host boundary".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name: "eliot-governor-host".to_owned(),
        observation: format!("canonical {receipt_kind}"),
        payload: json!({
            "receipt_kind": receipt_kind,
            "body_hash": hash_json(body)?,
            "receipt_body": body,
        }),
    });
    let receipt = writer
        .submit(WriteAdmissionService.admit(&command)?)
        .await?;
    let reference = WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    };
    Ok((reference, receipt))
}

async fn grant_role(
    config_path: &Path,
    task: &str,
    session: &str,
    role: &str,
    capability: Vec<String>,
    ttl_minutes: i64,
) -> Result<Value> {
    let instance = host_governor_instance(config_path)?;
    named_pipe_ipc::host_governor_request(
        &instance,
        "host/role-grant",
        json!({
            "task": task,
            "session": session,
            "role": role,
            "capability": capability,
            "ttl_minutes": ttl_minutes,
        }),
    )
    .await
    .context("route host role grant through the daemon-owned WriterActor")
}

fn host_governor_instance(config_path: &Path) -> Result<RuntimeInstance> {
    let default_instance = RuntimeInstance::select(config_path, Some(DEFAULT_INSTANCE_NAME))?;
    let default_matches_config = default_instance
        .read_publication(named_pipe_ipc::IPC_PROTOCOL_VERSION)
        .is_ok_and(|publication| {
            path_identity(&publication.config_path) == path_identity(config_path)
        });
    if default_matches_config {
        Ok(default_instance)
    } else {
        RuntimeInstance::select(config_path, None)
    }
}

pub(crate) async fn grant_role_from_daemon(
    root: &Path,
    store: &CanonicalStore,
    writer: &WriterHandle,
    params: Value,
) -> Result<Value> {
    let input: HostRoleGrantInput =
        serde_json::from_value(params).context("decode private host role grant RPC")?;
    store.migrate_schema().await?;
    grant_role_with_writer(root, store, writer, input).await
}

pub(crate) async fn record_host_observation_from_daemon(
    root: &Path,
    store: &CanonicalStore,
    writer: &WriterHandle,
    params: Value,
) -> Result<Value> {
    let input: HostObservationInput =
        serde_json::from_value(params).context("decode private host observation RPC")?;
    validate_host_observation_authority(root, store, &input).await?;
    let (canonical_receipt, write_receipt) = write_canonical_host_observation_with_writer(
        writer,
        input.project_id,
        input.task_id,
        input.agent_session_id,
        &input.key,
        &input.receipt_kind,
        &input.body,
    )
    .await?;
    Ok(serde_json::to_value(HostObservationOutput {
        canonical_receipt,
        write_receipt,
    })?)
}

async fn validate_host_observation_authority(
    root: &Path,
    store: &CanonicalStore,
    input: &HostObservationInput,
) -> Result<()> {
    let identity = host_observation_identity(input)?;
    if input.key != identity.expected_key {
        bail!("private host observation key is not canonical for its typed receipt body");
    }
    let task = store
        .task_contract_by_id(input.task_id)
        .await?
        .context("private host observation task does not exist")?;
    if task.project_id != input.project_id {
        bail!("private host observation project/task scope mismatch");
    }
    let state = delegation_runtime::load_state(root)?;
    let binding = state
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == input.agent_session_id)
        .context("private host observation session has no host binding")?;
    if identity
        .host_id
        .is_some_and(|host_id| host_id != binding.host_identity.host_id)
    {
        bail!("private host observation body host differs from its session binding");
    }
    let persisted = state
        .agent_invocations
        .iter()
        .find(|request| request.invocation_id == identity.invocation_id);
    if identity.requires_persisted_request && persisted.is_none() {
        bail!("private host observation has no persisted managed invocation request");
    }
    let expected_role_lease_id = identity
        .role_lease_id
        .as_deref()
        .or_else(|| persisted.map(|request| request.role_lease_id.as_str()));
    let role = state
        .task_role_leases
        .iter()
        .find(|role| {
            role.task_id == input.task_id
                && role.agent_session_id == input.agent_session_id
                && expected_role_lease_id.is_none_or(|expected| expected == role.role_lease_id)
        })
        .context("private host observation has no exact task role lease")?;
    if !binding
        .task_role_lease_refs
        .iter()
        .any(|role_lease_id| role_lease_id == &role.role_lease_id)
    {
        bail!("private host observation role lease is absent from its session binding");
    }
    if let Some(request) = persisted
        && (request.project_id != input.project_id
            || request.task_id != input.task_id
            || request.role_lease_id != role.role_lease_id)
    {
        bail!("private host observation differs from persisted managed invocation scope");
    }
    Ok(())
}

fn host_observation_identity(input: &HostObservationInput) -> Result<HostObservationIdentity> {
    match input.receipt_kind.as_str() {
        "agent_invocation_request" => {
            let request: AgentInvocationRequest = serde_json::from_value(input.body.clone())
                .context("decode managed AgentInvocationRequest observation")?;
            if request.project_id != input.project_id || request.task_id != input.task_id {
                bail!("managed AgentInvocationRequest body scope mismatch");
            }
            Ok(HostObservationIdentity {
                expected_key: format!("managed-agent-invocation:{}", request.invocation_id),
                invocation_id: request.invocation_id,
                role_lease_id: Some(request.role_lease_id),
                host_id: None,
                requires_persisted_request: false,
            })
        }
        "operation_job" => {
            let job: eliot_types::OperationJob = serde_json::from_value(input.body.clone())
                .context("decode managed OperationJob observation")?;
            let state_key = serde_json::to_string(&job.state)?;
            Ok(HostObservationIdentity {
                expected_key: format!(
                    "managed-operation-job:{}:{state_key}:{}",
                    job.job_id,
                    job.result_ref.as_deref().unwrap_or("none")
                ),
                invocation_id: job.invocation_id,
                role_lease_id: None,
                host_id: Some(job.host_id),
                requires_persisted_request: job.state != eliot_types::OperationJobState::Queued,
            })
        }
        "agent_result" => {
            let result: AgentResultEnvelope = serde_json::from_value(input.body.clone())
                .context("decode managed AgentResultEnvelope observation")?;
            if result.canonical_receipt.is_some() {
                bail!("managed AgentResultEnvelope observation must be unreceipted");
            }
            Ok(HostObservationIdentity {
                expected_key: format!("managed-provider-result:{}", result.result_id),
                invocation_id: result.invocation_id,
                role_lease_id: None,
                host_id: Some(result.host_id),
                requires_persisted_request: true,
            })
        }
        "managed_host_launch_result" => managed_launch_observation_identity(input),
        _ => bail!("private host observation receipt_kind is not allowlisted"),
    }
}

fn managed_launch_observation_identity(
    input: &HostObservationInput,
) -> Result<HostObservationIdentity> {
    if input.body.get("schema_version").and_then(Value::as_str)
        != Some("eliot-managed-host-launch-result-v1")
    {
        bail!("managed host launch observation has the wrong schema version");
    }
    let invocation_id = input
        .body
        .get("invocation_id")
        .and_then(Value::as_str)
        .context("managed host launch observation has no invocation_id")?;
    for (field, expected) in [
        ("project_id", input.project_id.to_string()),
        ("task_id", input.task_id.to_string()),
        ("agent_session_id", input.agent_session_id.to_string()),
    ] {
        if input
            .body
            .pointer(&format!("/scope/{field}"))
            .and_then(Value::as_str)
            != Some(expected.as_str())
        {
            bail!("managed host launch observation scope field {field} differs");
        }
    }
    let host_id: AgentHostId = serde_json::from_value(
        input
            .body
            .get("host")
            .cloned()
            .context("managed host launch observation has no host")?,
    )?;
    Ok(HostObservationIdentity {
        invocation_id: invocation_id.to_owned(),
        expected_key: format!("managed-host-result:{invocation_id}"),
        role_lease_id: input
            .body
            .pointer("/scope/role_lease_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        host_id: Some(host_id),
        requires_persisted_request: true,
    })
}

async fn grant_role_with_writer(
    root: &Path,
    store: &CanonicalStore,
    writer: &WriterHandle,
    input: HostRoleGrantInput,
) -> Result<Value> {
    let task_id = TaskId::from_str(&input.task).context("parse --task")?;
    let agent_session_id = AgentSessionId::from_str(&input.session).context("parse --session")?;
    let role = parse_role(&input.role)?;
    let task_contract = store
        .task_contract_by_id(task_id)
        .await?
        .context("role grant requires a current canonical TaskContract")?;
    if task_contract.status != TaskContractStatus::Open {
        bail!("role grant requires an open current canonical TaskContract");
    }
    let mut state = delegation_runtime::load_state(root)?;
    let (role_lease, controller_lease) = HostBrokerService.grant_role(
        &mut state,
        task_id,
        agent_session_id,
        role,
        input.capability,
        input.ttl_minutes,
    )?;
    let host_binding = HostBrokerService.bind_session_scope(
        &mut state,
        agent_session_id,
        task_contract.project_id,
        task_id,
    )?;
    let lease_value = serde_json::to_value(&role_lease)?;
    let host_binding_value = serde_json::to_value(&host_binding)?;
    let (canonical_receipt, _) = write_canonical_host_observation_with_writer(
        writer,
        task_contract.project_id,
        task_id,
        agent_session_id,
        &format!("host-role-lease:{}", role_lease.role_lease_id),
        "host_role_lease_authority",
        &lease_value,
    )
    .await?;
    let (canonical_host_binding_receipt, _) = write_canonical_host_observation_with_writer(
        writer,
        task_contract.project_id,
        task_id,
        agent_session_id,
        &format!("host-binding:{}:{task_id}", host_binding.agent_session_id),
        "host_binding_authority",
        &host_binding_value,
    )
    .await?;
    let canonical_controller_lease_receipt = if let Some(controller_lease) = &controller_lease {
        let (receipt, _) = write_canonical_host_observation_with_writer(
            writer,
            task_contract.project_id,
            task_id,
            agent_session_id,
            &format!("controller-lease:{}", controller_lease.controller_lease_id),
            "controller_lease",
            &serde_json::to_value(controller_lease)?,
        )
        .await?;
        Some(receipt)
    } else {
        None
    };
    let authority = RoleLeaseAuthorityRecord {
        schema_version: "eliot-host-role-lease-authority-v1".to_owned(),
        role_lease_id: role_lease.role_lease_id.clone(),
        lease_hash: hash_json(&lease_value)?,
        task_revision: task_contract.memory_revision.value(),
        canonical_receipt: canonical_receipt.clone(),
        host_binding_hash: hash_json(&host_binding_value)?,
        canonical_host_binding_receipt: canonical_host_binding_receipt.clone(),
    };
    atomic_write_json(
        &role_authority_path_from_root(root, &role_lease.role_lease_id),
        &authority,
    )?;
    delegation_runtime::save_host_broker_state(root, &state)?;
    Ok(json!({
        "schema_version": "eliot-task-role-grant-v1",
        "task_role_lease": role_lease,
        "controller_lease": controller_lease,
        "canonical_authority_receipt": canonical_receipt,
        "canonical_host_binding_receipt": canonical_host_binding_receipt,
        "canonical_controller_lease_receipt": canonical_controller_lease_receipt,
        "admin_authority_granted": false
    }))
}

fn broker_status(config_path: &Path) -> Result<Value> {
    let state = delegation_runtime::load_state(&runtime_root(config_path))?;
    Ok(json!({
        "schema_version": "eliot-host-broker-v1",
        "host_sessions": state.agent_host_sessions,
        "task_role_leases": state.task_role_leases,
        "controller_leases": state.controller_leases,
        "agent_invocations": state.agent_invocations,
        "operation_jobs": state.operation_jobs,
        "agent_results": state.agent_results,
        "agent_result_dispositions": state.agent_result_dispositions
    }))
}

fn parse_role(value: &str) -> Result<AgentRole> {
    match value.trim().to_ascii_lowercase().as_str() {
        "controller" => Ok(AgentRole::Controller),
        "worker" | "implementer" => Ok(AgentRole::Implementer),
        "reviewer" => Ok(AgentRole::Reviewer),
        "auditor" => Ok(AgentRole::Auditor),
        "verifier" => Ok(AgentRole::Verifier),
        other => bail!("unknown task role: {other}"),
    }
}

fn parse_mode(value: &str) -> Result<HostMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "interactive" => Ok(HostMode::Interactive),
        "supervised" | "noninteractive" => Ok(HostMode::Supervised),
        other => bail!("unknown host mode: {other}"),
    }
}

fn ensure_l7_host(host: AgentHostId) -> Result<()> {
    if matches!(host, AgentHostId::OpenCode | AgentHostId::Claude) {
        Ok(())
    } else {
        bail!("{} is not an L7 managed integration target", host.as_str())
    }
}

fn repo_root(config_path: &Path) -> PathBuf {
    if let Some(root) = std::env::var_os("ELIOT_GOVERNOR_REPO_ROOT") {
        return PathBuf::from(root);
    }
    if let Ok(current) = std::env::current_dir()
        && let Some(root) = current.ancestors().find(|candidate| {
            candidate.join("Cargo.toml").is_file()
                && candidate.join("integrations/agent-skills").is_dir()
        })
    {
        return root.to_path_buf();
    }
    runtime_root(config_path).parent().map_or_else(
        || std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        Path::to_path_buf,
    )
}

fn runtime_root(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new(".eliot-governor"))
        .to_path_buf()
}

fn integration_refs(bundle: &Path, host: AgentHostId) -> (PathBuf, PathBuf) {
    match host {
        AgentHostId::OpenCode => (
            bundle.join("opencode.json"),
            bundle.join("plugins").join("eliot.js"),
        ),
        AgentHostId::Claude => (
            bundle.join(".mcp.json"),
            bundle.join("hooks").join("hooks.json"),
        ),
        AgentHostId::Antigravity => (bundle.join("integration.json"), bundle.join("README.md")),
        AgentHostId::Codex => (bundle.join("README.md"), bundle.join("README.md")),
    }
}

fn prepare_launch_bundle(
    config_path: &Path,
    host: AgentHostId,
    source: &Path,
    governor: &Path,
) -> Result<PathBuf> {
    let sandbox_root = runtime_root(config_path).join("host-sandboxes");
    let (target_name, staging_prefix) = match host {
        AgentHostId::OpenCode => ("opencode-config-active", ".opencode-config"),
        AgentHostId::Claude => ("claude-plugin-active", ".claude-plugin"),
        _ => return Ok(source.to_path_buf()),
    };
    let target = sandbox_root.join(target_name);
    let staging = sandbox_root.join(format!("{staging_prefix}-{}-staging", Uuid::new_v4()));
    std::fs::create_dir_all(&sandbox_root)?;
    ensure_child(&sandbox_root, &target)?;
    ensure_child(&sandbox_root, &staging)?;
    copy_tree(source, &staging, host)?;
    if host == AgentHostId::Claude {
        let bin = staging.join("bin");
        std::fs::create_dir_all(&bin)?;
        std::fs::copy(governor, bin.join("eliot-governor.exe"))?;
    }
    atomic_write_json(
        &staging.join("eliot-launch-bundle.json"),
        &json!({
            "schema_version": "eliot-host-launch-bundle-v1",
            "host": host,
            "source_bundle_hash": bundle_hash(source, host)?,
            "governor_hash": bundle_hash_single(governor)?,
            "host_auth_or_config_copied": false
        }),
    )?;
    if target.exists() {
        std::fs::remove_dir_all(&target)?;
    }
    std::fs::rename(&staging, &target)?;
    Ok(target)
}

fn matching_installed_claude_bundle(source: &Path, governor: &Path) -> Result<Option<PathBuf>> {
    let installed = claude_global_plugin_path()?;
    let installed_governor = installed.join("bin").join("eliot-governor.exe");
    if !installed.is_dir() || !installed_governor.is_file() {
        return Ok(None);
    }
    let expected = claude_plugin_hash(source, governor)?;
    let actual = claude_plugin_hash(&installed, &installed_governor)?;
    Ok((actual == expected).then_some(installed))
}

fn install_base() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is not set")?)
            .join("Eliot")
            .join("host-integrations"),
    )
}

fn install_receipt_path(config_path: &Path, host: AgentHostId) -> PathBuf {
    runtime_root(config_path)
        .join("reports")
        .join("host-integrations")
        .join(format!("{}-install.json", host.as_str()))
}

fn copy_tree(source: &Path, destination: &Path, host: AgentHostId) -> Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if host_generated_bundle_entry(host, &entry.path()) {
            continue;
        }
        let target = destination.join(entry.file_name());
        if kind.is_symlink() {
            bail!(
                "integration bundle symlink is not allowed: {}",
                entry.path().display()
            );
        } else if kind.is_dir() {
            copy_tree(&entry.path(), &target, host)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn ensure_child(base: &Path, target: &Path) -> Result<()> {
    let base = std::path::absolute(base)?;
    let target = std::path::absolute(target)?;
    if target == base || !target.starts_with(&base) {
        bail!("refuse unsafe integration path {}", target.display());
    }
    Ok(())
}

fn bundle_hash_single(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(format!("blake3:{}", blake3::hash(&bytes).to_hex()))
}

fn write_json<T: serde::Serialize>(value: &T) -> Result<()> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    writeln!(output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalAuthorityBody, CanonicalBodyNormalization, ExistingManagedInvocation,
        MANAGED_ATTEMPT_SCHEMA_V4, ManagedHostAttemptJournal, ManagedInvocationLock,
        ManagedInvocationLockRecord, ManagedLaunchBoundaryAttestation, ManagedSanitizedEnvironment,
        ManagedWorktreeSnapshot, assert_managed_path_is_local_and_private,
        candidate_unified_diff_hash, configure_antigravity_environment,
        configure_standard_managed_environment, encode_managed_invocation_lock, hash_bytes,
        hash_file_content, hash_json, integration_refs, invocation_root, invocation_status,
        is_claude_desktop_host, latest_canonical_authority_observation, launch_argv,
        managed_attempt_hash, managed_launch_boundary_attestation,
        managed_launch_boundary_is_current, managed_sandbox_root, merge_opencode_mcp_config,
        normalize_relative_path, parse_opencode_jsonc, provider_start_marker_path,
        receipt_ref_from_option, reconcile_existing_managed_invocation, registry_entry_by_manifest,
        remaining_to_deadline, remove_opencode_mcp_config, sanitize_managed_output,
        stable_invocation_id, validate_antigravity_scope, validate_attempt_journal,
        validate_canonical_observation_identity, validate_managed_result_integrity,
    };
    use crate::runtime_instance::{atomic_write_bytes, atomic_write_json};
    use eliot_engine::{HostLaunchContractService, WorkState, default_work_scope};
    use eliot_store::CanonicalToolObservation;
    use eliot_types::{
        AgentCapabilityEnvelope, AgentHostId, AgentHostIdentity, AgentHostRuntimeProfile, AgentId,
        AgentRole, AgentSessionHostBinding, AgentSessionId, DelegationState, HostLaunchScope,
        HostMode, HostProfileStatus, HostProtocolSurfaces, MemoryRevision, ProjectId,
        ProjectSequence, ReceiptId, SemanticCommandKind, TaskId, TaskRoleLease, WorkItemId,
        WorkLease, WorkLeaseDecision, WorkLeaseDecisionKind, WorkLeaseDecisionReason, WorkLeaseId,
        WorkLeaseState, WorktreeLease, WorktreeLeaseId, WorktreeLeaseState, WriteId, WriteReceipt,
        WriteReceiptRef, WriteStatus,
    };
    use serde_json::{Value, json};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant};
    use time::OffsetDateTime;

    fn eliot_entry() -> Value {
        json!({
            "type": "local",
            "command": ["C:/Eliot/eliot-governor.exe", "mcp", "stdio"],
            "enabled": true,
            "timeout": 30000
        })
    }

    fn instruction_entry() -> &'static str {
        "C:/Eliot/instructions/eliot-governor.md"
    }

    fn write_stale_managed_lock(root: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(root)?;
        atomic_write_bytes(
            &root.join("dispatch.lock"),
            &encode_managed_invocation_lock(ManagedInvocationLockRecord {
                owner_pid: 0,
                created_unix_seconds: u64::try_from(
                    (OffsetDateTime::now_utc() - time::Duration::minutes(1)).unix_timestamp(),
                )?,
            }),
        )?;
        Ok(())
    }

    struct ScopeFixture {
        root: PathBuf,
        cwd: PathBuf,
        delegation: DelegationState,
        work: WorkState,
        scope: HostLaunchScope,
    }

    #[derive(Clone, Copy)]
    struct ScopeFixtureIds {
        project: ProjectId,
        task: TaskId,
        work_item: WorkItemId,
        session: AgentSessionId,
        work_lease: WorkLeaseId,
        worktree_lease: WorktreeLeaseId,
    }

    const ROLE_LEASE_ID: &str = "role:agy-worker";

    impl Drop for ScopeFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn fixture_delegation(ids: ScopeFixtureIds, now: OffsetDateTime) -> DelegationState {
        let mut delegation = DelegationState::default();
        delegation
            .agent_host_sessions
            .push(AgentSessionHostBinding {
                agent_session_id: ids.session,
                host_identity: AgentHostIdentity {
                    host_id: AgentHostId::Antigravity,
                    implementation_name: "Google Antigravity".to_owned(),
                    client_instance_id: "agy-fixture".to_owned(),
                },
                capability_envelope: AgentCapabilityEnvelope {
                    capabilities: vec!["lease_scoped_candidate_implementation".to_owned()],
                    structured_output: true,
                    supervised: true,
                    ..AgentCapabilityEnvelope::default()
                },
                bound_project_id: Some(ids.project),
                bound_task_id: Some(ids.task),
                task_role_lease_refs: vec![ROLE_LEASE_ID.to_owned()],
            });
        delegation.task_role_leases.push(TaskRoleLease {
            role_lease_id: ROLE_LEASE_ID.to_owned(),
            task_id: ids.task,
            agent_session_id: ids.session,
            role: AgentRole::Implementer,
            capability_scope: vec!["bounded_write".to_owned()],
            expires_at: now + time::Duration::minutes(30),
            epoch: 1,
        });
        delegation
    }

    fn fixture_work(
        ids: ScopeFixtureIds,
        root: &Path,
        cwd: &Path,
        write_set: &[String],
        base_commit: &str,
        now: OffsetDateTime,
    ) -> WorkState {
        let mut work = WorkState::default();
        work.leases.push(WorkLease {
            work_lease_id: ids.work_lease,
            work_item_id: ids.work_item,
            agent_session_id: ids.session,
            agent_id: AgentId::new_v7(),
            project_id: ids.project,
            task_id: ids.task,
            role: AgentRole::Implementer,
            state: WorkLeaseState::Granted,
            epoch: 1,
            scope: default_work_scope(
                root.to_string_lossy(),
                vec!["scripts".to_owned()],
                write_set.to_vec(),
                vec!["cargo test".to_owned()],
            ),
            decision: WorkLeaseDecision {
                kind: WorkLeaseDecisionKind::Granted,
                reason: WorkLeaseDecisionReason::NoConflict,
                message: "fixture".to_owned(),
                work_lease_id: Some(ids.work_lease),
                conflicting_lease_ids: Vec::new(),
                expires_at: Some(now + time::Duration::minutes(30)),
            },
            conflict_refs: Vec::new(),
            granted_at: now,
            expires_at: now + time::Duration::minutes(30),
            renewed_at: None,
            released_at: None,
            revoked_at: None,
            write_receipt: None,
        });
        work.worktree_leases.push(WorktreeLease {
            worktree_lease_id: ids.worktree_lease,
            project_id: ids.project,
            task_id: ids.task,
            work_item_id: ids.work_item,
            work_lease_id: ids.work_lease,
            holder_session_id: ids.session,
            repo_root: root.to_string_lossy().into_owned(),
            worktree_path: cwd.to_string_lossy().into_owned(),
            branch_name: "codex/agy-fixture".to_owned(),
            base_commit: base_commit.to_owned(),
            allowed_read_set: vec!["scripts".to_owned()],
            allowed_write_set: write_set.to_vec(),
            state: WorktreeLeaseState::Active,
            issued_at: now,
            expires_at: now + time::Duration::minutes(30),
            cleaned_at: None,
            write_receipt: None,
        });
        work
    }

    fn scope_fixture() -> anyhow::Result<ScopeFixture> {
        let now = OffsetDateTime::now_utc();
        let local = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("LOCALAPPDATA"))?;
        let root = local
            .join("Eliot")
            .join("tests")
            .join(format!("eliot-agy-host-{}", TaskId::new_v7()));
        let cwd = root.join("worktree");
        std::fs::create_dir_all(&cwd)?;
        std::fs::write(cwd.join("README.md"), "governed fixture\n")?;
        for args in [
            vec!["init"],
            vec!["config", "user.email", "eliot-fixture@example.invalid"],
            vec!["config", "user.name", "Eliot Fixture"],
            vec!["add", "README.md"],
            vec!["commit", "-m", "fixture baseline"],
        ] {
            let output = Command::new("git").current_dir(&cwd).args(args).output()?;
            if !output.status.success() {
                anyhow::bail!(
                    "git fixture setup failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        let output = Command::new("git")
            .current_dir(&cwd)
            .args(["rev-parse", "HEAD"])
            .output()?;
        let base_commit = String::from_utf8(output.stdout)?.trim().to_owned();
        let ids = ScopeFixtureIds {
            project: ProjectId::new_v7(),
            task: TaskId::new_v7(),
            work_item: WorkItemId::new_v7(),
            session: AgentSessionId::new_v7(),
            work_lease: WorkLeaseId::new_v7(),
            worktree_lease: WorktreeLeaseId::new_v7(),
        };
        let write_set = vec!["scripts/phase-l12".to_owned()];
        let delegation = fixture_delegation(ids, now);
        let work = fixture_work(ids, &root, &cwd, &write_set, &base_commit, now);
        Ok(ScopeFixture {
            root,
            cwd,
            delegation,
            work,
            scope: HostLaunchScope {
                project_id: Some(ids.project),
                agent_session_id: Some(ids.session),
                task_id: Some(ids.task),
                work_item_id: Some(ids.work_item),
                role_lease_id: Some(ROLE_LEASE_ID.to_owned()),
                work_lease_id: Some(ids.work_lease),
                worktree_lease_id: Some(ids.worktree_lease),
                planned_verifier_ref: Some(
                    crate::mcp_stdio::RegisteredTaskVerifier::ReceiptResolution.reference(),
                ),
                baseline_commit: Some(base_commit),
                allowed_paths: write_set,
                forbidden_paths: Vec::new(),
            },
        })
    }

    fn require_error<T>(result: anyhow::Result<T>, message: &str) -> anyhow::Result<anyhow::Error> {
        match result {
            Ok(_) => anyhow::bail!(message.to_owned()),
            Err(error) => Ok(error),
        }
    }

    fn antigravity_profile() -> AgentHostRuntimeProfile {
        AgentHostRuntimeProfile {
            host_id: AgentHostId::Antigravity,
            implementation_name: "Google Antigravity".to_owned(),
            executable_path: "C:/Profiles/test/AppData/Local/agy/bin/agy.exe".to_owned(),
            executable_hash: "blake3:fixture".to_owned(),
            version: "1.1.3".to_owned(),
            discovered_at: OffsetDateTime::now_utc(),
            supported_modes: vec!["supervised_noninteractive".to_owned()],
            protocol_surfaces: HostProtocolSurfaces {
                mcp_stdio: true,
                structured_output: true,
                worktree: true,
                permissions: true,
                ..HostProtocolSurfaces::default()
            },
            launch_capabilities: vec!["lease_scoped_candidate_implementation".to_owned()],
            result_capture: vec!["governor_launch_receipt".to_owned()],
            resume_contract: "no blind retry".to_owned(),
            timeout_and_unknown_outcome_contract: "reconcile before retry".to_owned(),
            known_version_constraints: Vec::new(),
            operator_configuration_refs: Vec::new(),
            capability_probe_receipt: "blake3:agy-profile".to_owned(),
            status: HostProfileStatus::Current,
        }
    }

    #[test]
    fn antigravity_scope_denies_missing_expired_and_mismatched_authority_before_call()
    -> anyhow::Result<()> {
        let now = OffsetDateTime::now_utc();

        let mut missing = scope_fixture()?;
        missing.scope.project_id = None;
        let error = require_error(
            validate_antigravity_scope(
                &missing.delegation,
                &missing.work,
                Some(&missing.cwd),
                &mut missing.scope,
                now,
            ),
            "missing project must fail closed",
        )?;
        assert!(error.to_string().contains("--project"));

        let mut missing_verifier = scope_fixture()?;
        missing_verifier.scope.planned_verifier_ref = None;
        let error = require_error(
            validate_antigravity_scope(
                &missing_verifier.delegation,
                &missing_verifier.work,
                Some(&missing_verifier.cwd),
                &mut missing_verifier.scope,
                now,
            ),
            "missing planned verifier must fail closed",
        )?;
        assert!(error.to_string().contains("--planned-verifier-ref"));

        let mut fabricated_verifier = scope_fixture()?;
        fabricated_verifier.scope.planned_verifier_ref =
            Some("eliot/verifier/fabricated@v1#blake3:deadbeef".to_owned());
        let error = require_error(
            validate_antigravity_scope(
                &fabricated_verifier.delegation,
                &fabricated_verifier.work,
                Some(&fabricated_verifier.cwd),
                &mut fabricated_verifier.scope,
                now,
            ),
            "fabricated planned verifier must fail closed",
        )?;
        assert!(error.to_string().contains("unregistered or stale"));

        let mut expired = scope_fixture()?;
        expired.work.worktree_leases[0].expires_at = now - time::Duration::seconds(1);
        let error = require_error(
            validate_antigravity_scope(
                &expired.delegation,
                &expired.work,
                Some(&expired.cwd),
                &mut expired.scope,
                now,
            ),
            "expired worktree lease must fail closed",
        )?;
        assert!(error.to_string().contains("expired or scope-mismatched"));

        let mut mismatched = scope_fixture()?;
        mismatched.scope.agent_session_id = Some(AgentSessionId::new_v7());
        let error = require_error(
            validate_antigravity_scope(
                &mismatched.delegation,
                &mismatched.work,
                Some(&mismatched.cwd),
                &mut mismatched.scope,
                now,
            ),
            "mismatched session must fail closed",
        )?;
        assert!(error.to_string().contains("scope-mismatched"));
        Ok(())
    }

    #[test]
    fn antigravity_scope_denies_worktree_and_write_set_escape() -> anyhow::Result<()> {
        let now = OffsetDateTime::now_utc();
        let mut cwd_escape = scope_fixture()?;
        let outside = cwd_escape.root.join("outside");
        std::fs::create_dir_all(&outside)?;
        let error = require_error(
            validate_antigravity_scope(
                &cwd_escape.delegation,
                &cwd_escape.work,
                Some(&outside),
                &mut cwd_escape.scope,
                now,
            ),
            "cwd outside the lease must fail closed",
        )?;
        assert!(
            error
                .to_string()
                .contains("must equal the canonical WorktreeLease path")
        );

        let mut write_escape = scope_fixture()?;
        write_escape.scope.allowed_paths = vec!["../outside".to_owned()];
        let error = require_error(
            validate_antigravity_scope(
                &write_escape.delegation,
                &write_escape.work,
                Some(&write_escape.cwd),
                &mut write_escape.scope,
                now,
            ),
            "write path traversal must fail closed",
        )?;
        assert!(
            error.to_string().contains("escapes the governed worktree"),
            "unexpected rejection: {error}"
        );
        assert!(normalize_relative_path("C:/outside").is_err());
        Ok(())
    }

    #[test]
    fn antigravity_is_a_scoped_managed_launch_target() -> anyhow::Result<()> {
        let fixture = scope_fixture()?;
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| anyhow::anyhow!("workspace root"))?;
        let contract = HostLaunchContractService.render(
            repo,
            &antigravity_profile(),
            HostMode::Supervised,
            &fixture.cwd,
            Some("gemini-2.5-pro".to_owned()),
            None,
            &fixture.scope,
        )?;
        let (_program, args) = launch_argv(
            AgentHostId::Antigravity,
            "agy.exe",
            &repo.join("integrations/antigravity"),
            false,
            &contract,
            Some("bounded candidate task".to_owned()),
        )?;
        assert!(args.windows(2).any(|pair| pair == ["--mode", "plan"]));
        assert!(!args.iter().any(|argument| argument == "accept-edits"));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--model", "gemini-2.5-pro"])
        );
        assert!(args.iter().any(|arg| arg == "--new-project"));
        assert!(args.iter().any(|arg| arg == "--sandbox"));
        assert!(args.iter().any(|arg| arg == "--print"));
        let prompt = args.last().map(String::as_str).unwrap_or_default();
        assert!(prompt.contains("READ-ONLY GOVERNED PLAN"));
        assert!(prompt.contains("candidate unified diff"));
        assert!(prompt.contains("no Markdown fences, prose, or summary"));
        assert!(prompt.contains("bounded candidate task"));
        assert!(
            candidate_unified_diff_hash(
                b"diff --git a/scripts/a.txt b/scripts/a.txt\n--- a/scripts/a.txt\n+++ b/scripts/a.txt\n@@ -1 +1 @@\n-a\n+b\n",
                &["scripts".to_owned()],
            )
            .is_some()
        );
        assert!(
            candidate_unified_diff_hash(
                b"Here is the requested patch:\n```diff\n",
                &["scripts".to_owned()],
            )
            .is_none()
        );
        assert!(candidate_unified_diff_hash(b"", &["scripts".to_owned()]).is_none());
        assert!(
            candidate_unified_diff_hash(
                b"diff --git a/outside.txt b/outside.txt\n--- a/outside.txt\n+++ b/outside.txt\n@@ -1 +1 @@\n-a\n+b\n",
                &["scripts".to_owned()],
            )
            .is_none()
        );
        Ok(())
    }

    #[test]
    fn opencode_managed_launch_preserves_the_exact_dynamic_model_route() -> anyhow::Result<()> {
        let fixture = scope_fixture()?;
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| anyhow::anyhow!("workspace root"))?;
        let mut profile = antigravity_profile();
        profile.host_id = AgentHostId::OpenCode;
        profile.implementation_name = "OpenCode".to_owned();
        let selected_model = "openai/certification-reader";
        let contract = HostLaunchContractService.render(
            repo,
            &profile,
            HostMode::Supervised,
            &fixture.cwd,
            Some(selected_model.to_owned()),
            None,
            &fixture.scope,
        )?;
        let (_program, args) = launch_argv(
            AgentHostId::OpenCode,
            "opencode-cli.exe",
            &repo.join("integrations/opencode"),
            false,
            &contract,
            Some("sealed reader task".to_owned()),
        )?;
        let model_pairs = args
            .windows(2)
            .filter(|pair| pair[0] == "--model")
            .collect::<Vec<_>>();
        assert_eq!(model_pairs.len(), 1);
        assert_eq!(model_pairs[0][1], selected_model);
        assert!(!args.iter().any(|argument| argument == "--session"));
        assert_eq!(args.last().map(String::as_str), Some("sealed reader task"));
        Ok(())
    }

    /// ELIOT must reach a Claude session exactly once. The plugin already
    /// carries its own `.mcp.json`, so passing that file again through
    /// `--mcp-config` attached the tool set twice under two MCP namespaces,
    /// giving one session two competing ELIOT authorities.
    #[test]
    fn claude_managed_launch_attaches_eliot_exactly_once() -> anyhow::Result<()> {
        let fixture = scope_fixture()?;
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| anyhow::anyhow!("workspace root"))?;
        let mut profile = antigravity_profile();
        profile.host_id = AgentHostId::Claude;
        profile.implementation_name = "Claude Code".to_owned();
        let contract = HostLaunchContractService.render(
            repo,
            &profile,
            HostMode::Supervised,
            &fixture.cwd,
            None,
            None,
            &fixture.scope,
        )?;
        let bundle = repo.join("integrations/claude/eliot");

        let attachments = |args: &[String]| {
            args.iter()
                .filter(|argument| {
                    argument.as_str() == "--plugin-dir" || argument.as_str() == "--mcp-config"
                })
                .count()
        };

        // Canonical path: Claude discovered the installed plugin, so it loads
        // the MCP server itself and the launcher must add nothing.
        let (_program, installed) = launch_argv(
            AgentHostId::Claude,
            "claude.exe",
            &bundle,
            false,
            &contract,
            Some("bounded task".to_owned()),
        )?;
        assert_eq!(
            attachments(&installed),
            0,
            "an installed plugin already provides ELIOT: {installed:?}"
        );

        // Development fallback: no installed plugin, so the bundle is pointed
        // at directly -- still one attachment, never both.
        let (_program, fallback) = launch_argv(
            AgentHostId::Claude,
            "claude.exe",
            &bundle,
            true,
            &contract,
            Some("bounded task".to_owned()),
        )?;
        assert_eq!(
            attachments(&fallback),
            1,
            "the development fallback must attach ELIOT once: {fallback:?}"
        );
        assert!(
            !fallback.iter().any(|argument| argument == "--mcp-config"),
            "--plugin-dir already carries .mcp.json: {fallback:?}"
        );
        Ok(())
    }

    #[test]
    fn antigravity_integration_bundle_is_complete_and_hashable() -> anyhow::Result<()> {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| anyhow::anyhow!("workspace root"))?;
        let bundle = repo.join("integrations/antigravity");
        let (config_ref, lifecycle_ref) = integration_refs(&bundle, AgentHostId::Antigravity);
        let config: Value = serde_json::from_reader(std::fs::File::open(&config_ref)?)?;
        assert_eq!(config["schema_version"], "eliot-antigravity-integration-v1");
        assert!(lifecycle_ref.is_file());
        assert!(!eliot_engine::bundle_hash(&bundle, AgentHostId::Antigravity)?.is_empty());
        Ok(())
    }

    #[test]
    fn candidate_diff_validates_hunk_semantics_and_all_metadata_paths() {
        let allowed = ["scripts".to_owned()];
        let rename = b"diff --git a/scripts/old.txt b/scripts/new.txt\nsimilarity index 90%\nrename from scripts/old.txt\nrename to scripts/new.txt\n--- a/scripts/old.txt\n+++ b/scripts/new.txt\n@@ -1 +1 @@\n-old\n+new\n";
        assert!(candidate_unified_diff_hash(rename, &allowed).is_some());
        let new_file = b"diff --git a/scripts/new.txt b/scripts/new.txt\nnew file mode 100644\n--- /dev/null\n+++ b/scripts/new.txt\n@@ -0,0 +1 @@\n+new\n";
        assert!(candidate_unified_diff_hash(new_file, &allowed).is_some());

        let wrong_counts = b"diff --git a/scripts/a.txt b/scripts/a.txt\n--- a/scripts/a.txt\n+++ b/scripts/a.txt\n@@ -1,2 +1,2 @@\n-old\n+new\n";
        assert!(candidate_unified_diff_hash(wrong_counts, &allowed).is_none());
        let malformed_range = b"diff --git a/scripts/a.txt b/scripts/a.txt\n--- a/scripts/a.txt\n+++ b/scripts/a.txt\n@@ -x +1 @@\n-old\n+new\n";
        assert!(candidate_unified_diff_hash(malformed_range, &allowed).is_none());
        let context_only = b"diff --git a/scripts/a.txt b/scripts/a.txt\n--- a/scripts/a.txt\n+++ b/scripts/a.txt\n@@ -1 +1 @@\n unchanged\n";
        assert!(candidate_unified_diff_hash(context_only, &allowed).is_none());
        let escaped_copy = b"diff --git a/scripts/a.txt b/scripts/b.txt\ncopy from scripts/a.txt\ncopy to outside/b.txt\n--- a/scripts/a.txt\n+++ b/scripts/b.txt\n@@ -1 +1 @@\n-old\n+new\n";
        assert!(candidate_unified_diff_hash(escaped_copy, &allowed).is_none());
        let overlapping = b"diff --git a/scripts/a.txt b/scripts/a.txt\n--- a/scripts/a.txt\n+++ b/scripts/a.txt\n@@ -1 +1 @@\n-old\n+new\n@@ -1 +1 @@\n-old-again\n+new-again\n";
        assert!(candidate_unified_diff_hash(overlapping, &allowed).is_none());
        let fake_new_file = b"diff --git a/scripts/a.txt b/scripts/a.txt\nnew file mode 100644\n--- a/scripts/a.txt\n+++ b/scripts/a.txt\n@@ -1 +1 @@\n-old\n+new\n";
        assert!(candidate_unified_diff_hash(fake_new_file, &allowed).is_none());
    }

    #[tokio::test]
    async fn antigravity_environment_is_allowlisted_and_global_paths_are_denied()
    -> anyhow::Result<()> {
        let fixture = scope_fixture()?;
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| anyhow::anyhow!("workspace root"))?;
        let contract = HostLaunchContractService.render(
            repo,
            &antigravity_profile(),
            HostMode::Supervised,
            &fixture.cwd,
            Some("gemini-2.5-pro".to_owned()),
            None,
            &fixture.scope,
        )?;
        let comspec = std::env::var_os("ComSpec")
            .ok_or_else(|| anyhow::anyhow!("ComSpec is required on Windows"))?;
        let mut command = tokio::process::Command::new(comspec);
        command.args(["/D", "/C", "set"]);
        configure_antigravity_environment(
            &mut command,
            repo,
            &contract,
            "C:/Eliot/eliot-governor.exe",
        )?;
        let output = command.output().await?;
        assert!(output.status.success());
        let environment = String::from_utf8(output.stdout)?.to_ascii_uppercase();
        for forbidden in [
            "ONEDRIVE=",
            "PROGRAMDATA=",
            "PATH=",
            "USERNAME=",
            "USERDOMAIN=",
        ] {
            assert!(
                !environment.lines().any(|line| line.starts_with(forbidden)),
                "forbidden inherited environment variable: {forbidden}"
            );
        }
        let local = PathBuf::from(
            std::env::var_os("LOCALAPPDATA")
                .ok_or_else(|| anyhow::anyhow!("LOCALAPPDATA is required"))?,
        );
        assert_managed_path_is_local_and_private(&local.join("Eliot/private"))?;
        if let Some(program_data) = std::env::var_os("ProgramData") {
            assert!(
                assert_managed_path_is_local_and_private(&PathBuf::from(program_data).join("agy"))
                    .is_err()
            );
        }
        if let Some(one_drive) = std::env::var_os("OneDrive") {
            assert!(
                assert_managed_path_is_local_and_private(&PathBuf::from(one_drive).join("agy"))
                    .is_err()
            );
        }
        std::fs::remove_dir_all(managed_sandbox_root(&contract)?)?;
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn standard_managed_environment_clears_unlisted_secrets() -> anyhow::Result<()> {
        let comspec = std::env::var_os("ComSpec")
            .ok_or_else(|| anyhow::anyhow!("ComSpec is required on Windows"))?;
        let mut command = tokio::process::Command::new(comspec);
        command
            .args(["/D", "/C", "set"])
            .env("ELIOT_SENTINEL_SECRET", "must-not-reach-managed-host");
        configure_standard_managed_environment(&mut command, "C:/Eliot/eliot-governor.exe");
        let output = command.output().await?;
        assert!(output.status.success());
        let environment = String::from_utf8(output.stdout)?.to_ascii_uppercase();
        assert!(!environment.contains("ELIOT_SENTINEL_SECRET="));
        assert!(environment.contains("ELIOT_GOVERNOR_EXE="));
        Ok(())
    }

    #[test]
    fn managed_output_is_redacted_before_persistence() -> anyhow::Result<()> {
        let secret = format!("{}{}{}", "github_", "pat_", "A".repeat(40));
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJlbGlvdCJ9.signaturebytes";
        let output = format!(
            "safe event\napi_key={secret}\n{{\"password\":\"must-not-persist\"}}\napi_token=must-not-persist-either\nAWS_SECRET_ACCESS_KEY=must-not-persist-aws\nAuthorization: Basic must-not-persist-basic\nAuthorization:\n Basic must-not-persist-folded\n second-must-not-persist-folded\nraw={jwt}\ntokens=128\n"
        );
        let sanitized = sanitize_managed_output(output.as_bytes());
        let text = String::from_utf8(sanitized.bytes)?;
        assert!(sanitized.receipt.redacted);
        assert!(!text.contains(&secret));
        assert!(!text.contains("must-not-persist"));
        assert!(!text.contains(jwt));
        assert!(text.contains("safe event"));
        assert!(text.contains("tokens=128"));
        assert!(
            sanitized
                .receipt
                .markers
                .contains(&"provider_credential".to_owned())
        );
        assert!(sanitized.receipt.markers.contains(&"password".to_owned()));
        assert!(sanitized.receipt.markers.contains(&"jwt".to_owned()));
        assert!(
            sanitized
                .receipt
                .markers
                .contains(&"credential_continuation".to_owned())
        );
        Ok(())
    }

    #[tokio::test]
    async fn managed_launch_recovers_stale_lock_before_attempt() -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!("eliot-agy-lock-{}", TaskId::new_v7()));
        let live = root.join("live");
        let live_lock = ManagedInvocationLock::acquire(&live)?;
        assert!(matches!(
            reconcile_existing_managed_invocation(&live, &live, "unused").await?,
            ExistingManagedInvocation::InProgress
        ));
        drop(live_lock);

        let stale = root.join("stale");
        std::fs::create_dir_all(&stale)?;
        let mut exited = Command::new("cmd").args(["/C", "exit", "0"]).spawn()?;
        let exited_pid = exited.id();
        exited.wait()?;
        atomic_write_bytes(
            &stale.join("dispatch.lock"),
            &encode_managed_invocation_lock(ManagedInvocationLockRecord {
                owner_pid: exited_pid,
                created_unix_seconds: u64::try_from(
                    (OffsetDateTime::now_utc() - time::Duration::minutes(1)).unix_timestamp(),
                )?,
            }),
        )?;
        assert!(matches!(
            reconcile_existing_managed_invocation(&stale, &stale, "unused").await?,
            ExistingManagedInvocation::New
        ));
        assert!(!stale.join("dispatch.lock").exists());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn managed_launch_recovers_truncated_pre_provider_journals() -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!("eliot-agy-truncated-{}", TaskId::new_v7()));
        let truncated_lock = root.join("lock");
        std::fs::create_dir_all(&truncated_lock)?;
        std::fs::write(truncated_lock.join("dispatch.lock"), b"ELIOT-MANAGED-LOCK")?;
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert!(matches!(
            reconcile_existing_managed_invocation(&truncated_lock, &truncated_lock, "unused")
                .await?,
            ExistingManagedInvocation::New
        ));

        let truncated_attempt = root.join("attempt");
        write_stale_managed_lock(&truncated_attempt)?;
        std::fs::write(truncated_attempt.join("attempt.json"), b"{\"truncated\":")?;
        assert!(matches!(
            reconcile_existing_managed_invocation(&truncated_attempt, &truncated_attempt, "unused")
                .await?,
            ExistingManagedInvocation::New
        ));
        assert!(!truncated_attempt.join("attempt.json").exists());
        assert!(!truncated_attempt.join("dispatch.lock").exists());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn managed_launch_never_retries_malformed_post_provider_journal() -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!("eliot-agy-post-start-{}", TaskId::new_v7()));
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("attempt.json"), b"{\"truncated\":")?;
        atomic_write_bytes(&provider_start_marker_path(&root), b"provider-started")?;
        assert!(matches!(
            reconcile_existing_managed_invocation(&root, &root, "unused").await?,
            ExistingManagedInvocation::UnknownOutcome
        ));
        assert!(root.join("attempt.json").exists());
        assert!(provider_start_marker_path(&root).exists());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn managed_cleanup_never_resets_an_exhausted_absolute_deadline() {
        let deadline = Instant::now();
        let started = Instant::now();
        let bounded = tokio::time::timeout(
            remaining_to_deadline(deadline),
            std::future::pending::<()>(),
        )
        .await;
        assert!(bounded.is_err());
        assert!(started.elapsed() < Duration::from_millis(100));
        assert_eq!(remaining_to_deadline(deadline), Duration::ZERO);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn managed_launch_cas_blocks_concurrent_spawn_and_attempt_tampering() -> anyhow::Result<()>
    {
        let root = std::env::temp_dir().join(format!("eliot-agy-journal-{}", TaskId::new_v7()));
        std::fs::create_dir_all(&root)?;
        let request_hash = "blake3:request";
        let snapshot = ManagedWorktreeSnapshot {
            head: "head".to_owned(),
            status_hash: hash_bytes(&[]),
            diff_hash: hash_bytes(&[]),
            untracked_hash: hash_bytes(&[]),
            aggregate_hash: "blake3:tree".to_owned(),
        };
        let launch_boundary = ManagedLaunchBoundaryAttestation {
            schema_version: "eliot-managed-launch-boundary-v1".to_owned(),
            executable_path: "C:/fixture/agy.exe".to_owned(),
            executable_hash: "blake3:executable".to_owned(),
            executable_version: "1.1.3".to_owned(),
            capability_probe_receipt: "blake3:agy-profile".to_owned(),
            integration_bundle_ref: "C:/fixture/integrations/antigravity".to_owned(),
            integration_bundle_hash: "blake3:bundle".to_owned(),
            invocation_root: root.to_string_lossy().into_owned(),
            environment: ManagedSanitizedEnvironment {
                inherited_environment_cleared: true,
                inherited_environment_allowlist: Vec::new(),
                environment_names: Vec::new(),
                sandbox_root: root.join("sandbox").to_string_lossy().into_owned(),
                isolated_paths: Vec::new(),
            },
        };
        let mut attempt = ManagedHostAttemptJournal {
            schema_version: MANAGED_ATTEMPT_SCHEMA_V4.to_owned(),
            invocation_id: stable_invocation_id("fixture-key"),
            idempotency_key: "fixture-key".to_owned(),
            request_hash: request_hash.to_owned(),
            contract_hash: "contract".to_owned(),
            host: AgentHostId::Antigravity,
            project_id: Some(ProjectId::new_v7()),
            task_id: Some(TaskId::new_v7()),
            work_item_id: None,
            agent_session_id: Some(AgentSessionId::new_v7()),
            role_lease_id: None,
            work_lease_id: None,
            worktree_lease_id: None,
            cwd_or_worktree: "C:/fixture".to_owned(),
            write_set: vec!["scripts".to_owned()],
            tool: "agy".to_owned(),
            tool_version: "1.1.3".to_owned(),
            model: Some("gemini-2.5-pro".to_owned()),
            prompt_hash: "blake3:prompt".to_owned(),
            owner_pid: std::process::id(),
            authority_hash: "blake3:authority".to_owned(),
            worktree_before: snapshot,
            launch_boundary,
            broker_job_id: "operation-job:fixture".to_owned(),
            broker_result_id: "agent-result:fixture".to_owned(),
            broker_host_session_id: "agy-fixture".to_owned(),
            planned_verifier_ref: crate::mcp_stdio::RegisteredTaskVerifier::ReceiptResolution
                .reference(),
            attempt_hash: String::new(),
            attempt_recorded_before_provider_call: true,
            provider_call_budget_consumed: true,
            redispatch_allowed: false,
            started_at: OffsetDateTime::now_utc(),
        };
        attempt.attempt_hash = managed_attempt_hash(&attempt)?;
        atomic_write_json(&root.join("attempt.json"), &attempt)?;
        let lock = ManagedInvocationLock::acquire(&root)?;
        assert!(ManagedInvocationLock::acquire(&root).is_err());
        assert!(matches!(
            reconcile_existing_managed_invocation(&root, &root, request_hash).await?,
            ExistingManagedInvocation::InProgress
        ));
        let mut tampered = attempt.clone();
        tampered.authority_hash = "blake3:tampered".to_owned();
        assert!(validate_attempt_journal(&tampered).is_err());

        let stdout = root.join("stdout.txt");
        let stderr = root.join("stderr.log");
        std::fs::write(&stdout, "candidate diff")?;
        std::fs::write(&stderr, "")?;
        let mut result = json!({
            "request_hash": request_hash,
            "contract_hash": attempt.contract_hash,
            "attempt_hash": attempt.attempt_hash,
            "reason": "fixture terminal result",
            "execution_evidence": {
                "stdout_ref": stdout,
                "stdout_hash": hash_bytes(b"candidate diff"),
                "stderr_ref": stderr,
                "stderr_hash": hash_bytes(b""),
            },
            "canonical_authority": { "body_hash": "blake3:fixture" },
        });
        let receipt_hash = hash_json(&result)?;
        result
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("fixture result object"))?
            .insert("receipt_hash".to_owned(), Value::String(receipt_hash));
        validate_managed_result_integrity(&attempt, &result, request_hash)?;
        let mut tampered_result = result.clone();
        tampered_result["reason"] = json!("fabricated replacement");
        assert!(
            validate_managed_result_integrity(&attempt, &tampered_result, request_hash).is_err()
        );
        std::fs::write(root.join("stdout.txt"), "mutated output")?;
        assert!(validate_managed_result_integrity(&attempt, &result, request_hash).is_err());
        drop(lock);
        let replacement = ManagedInvocationLock::acquire(&root)?;
        drop(replacement);
        attempt.schema_version = "eliot-managed-host-attempt-v2".to_owned();
        attempt.attempt_hash = managed_attempt_hash(&attempt)?;
        atomic_write_json(&root.join("attempt.json"), &attempt)?;
        atomic_write_bytes(&provider_start_marker_path(&root), b"provider-started")?;
        assert!(matches!(
            reconcile_existing_managed_invocation(&root, &root, request_hash).await?,
            ExistingManagedInvocation::UnknownOutcome
        ));
        assert!(root.join("attempt.json").exists());
        assert!(provider_start_marker_path(&root).exists());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn managed_authority_requires_receipts() {
        assert!(receipt_ref_from_option(None, "WorkLease").is_err());
    }

    #[test]
    fn managed_launch_attestation_does_not_traverse_provider_private_roots() {
        let production = include_str!("host_runtime.rs")
            .split("\n#[cfg(test)]")
            .next()
            .unwrap_or_default();
        for forbidden in [
            "provider_global_state_roots",
            "global_agy_state_snapshot",
            "forbidden_global_state_roots",
            "start_forbidden_state_watch",
            "DirectoryMutationGuard::watch",
        ] {
            assert!(
                !production.contains(forbidden),
                "managed launch must not traverse provider-private state through {forbidden}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn managed_launch_preparation_ignores_unrelated_windows_trailing_dot_files()
    -> anyhow::Result<()> {
        let local_app_data = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("LOCALAPPDATA is required for this Windows test"))?;
        let root = local_app_data
            .join("Eliot")
            .join("tests")
            .join(format!("launch-boundary-{}", TaskId::new_v7()));
        let executable = root.join("bin").join("agy.exe");
        let bundle = root.join("integrations").join("antigravity");
        let invocation = root
            .join("reports")
            .join("host-invocations")
            .join("fixture");
        let sandbox = root.join("sandbox");
        let isolated_paths = [
            sandbox.join("home"),
            sandbox.join("local"),
            sandbox.join("roaming"),
            sandbox.join("temp"),
            sandbox.join("config"),
        ];
        let executable_parent = executable
            .parent()
            .ok_or_else(|| anyhow::anyhow!("fixture executable has no parent"))?;
        std::fs::create_dir_all(executable_parent)?;
        std::fs::create_dir_all(&bundle)?;
        std::fs::create_dir_all(&invocation)?;
        for path in &isolated_paths {
            std::fs::create_dir_all(path)?;
        }
        std::fs::write(&executable, b"fixture agy executable")?;
        atomic_write_json(
            &bundle.join("integration.json"),
            &json!({
                "schema_version": "eliot-antigravity-integration-v1",
                "host": "antigravity",
            }),
        )?;
        std::fs::write(bundle.join("README.md"), b"managed integration fixture")?;

        let unrelated_private_root = root.join("unrelated").join(".gemini");
        std::fs::create_dir_all(&unrelated_private_root)?;
        let logical_trailing_dot = unrelated_private_root.join("credentials.json.");
        let exact_trailing_dot = PathBuf::from(format!(
            r"\\?\{}",
            std::path::absolute(&logical_trailing_dot)?
                .to_string_lossy()
                .replace('/', "\\")
        ));
        std::fs::write(&exact_trailing_dot, b"unrelated provider-private state")?;

        let canonical_executable = executable.canonicalize()?;
        let mut profile = antigravity_profile();
        profile.executable_path = canonical_executable.to_string_lossy().into_owned();
        profile.executable_hash = hash_file_content(&canonical_executable)?;
        let environment = ManagedSanitizedEnvironment {
            inherited_environment_cleared: true,
            inherited_environment_allowlist: Vec::new(),
            environment_names: vec![
                "AGY_CLI_DISABLE_AUTO_UPDATE".to_owned(),
                "AGY_CLI_HIDE_ACCOUNT_INFO".to_owned(),
                "USERPROFILE".to_owned(),
            ],
            sandbox_root: sandbox.to_string_lossy().into_owned(),
            isolated_paths: isolated_paths
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
        };
        let boundary = managed_launch_boundary_attestation(
            &profile,
            canonical_executable
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("fixture executable path is not UTF-8"))?,
            &bundle,
            &invocation,
            environment,
        )?;
        assert!(managed_launch_boundary_is_current(&boundary));
        assert_eq!(boundary.executable_hash, profile.executable_hash);
        assert!(
            !serde_json::to_string(&boundary)?.contains(".gemini"),
            "provider-private roots must not be part of launch attestation"
        );

        std::fs::remove_file(exact_trailing_dot)?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn pre_dispatch_failure_authority_remains_redispatchable_without_provider_call()
    -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!("eliot-pre-dispatch-{}", TaskId::new_v7()));
        let config = root.join("config").join("governor.toml");
        let config_parent = config
            .parent()
            .ok_or_else(|| anyhow::anyhow!("fixture config has no parent"))?;
        std::fs::create_dir_all(config_parent)?;
        let idempotency_key = "fixture-pre-dispatch-failure";
        let invocation_id = stable_invocation_id(idempotency_key);
        let invocation = invocation_root(&config, &invocation_id);
        std::fs::create_dir_all(&invocation)?;
        atomic_write_json(
            &invocation.join("attempt.json"),
            &json!({
                "schema_version": MANAGED_ATTEMPT_SCHEMA_V4,
                "failure_stage": "pre_dispatch",
            }),
        )?;

        let status = invocation_status(&config, idempotency_key).await?;
        assert_eq!(status.get("status"), Some(&json!("not_attempted")));
        assert_eq!(
            status.get("provider_call_budget_consumed"),
            Some(&json!(false))
        );
        assert_eq!(status.get("redispatch_allowed"), Some(&json!(true)));
        assert!(!provider_start_marker_path(&invocation).exists());
        assert!(!invocation.join("attempt.json").exists());

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn canonical_authority_requires_exact_body_and_created_record_identity() -> anyhow::Result<()> {
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let write_id = WriteId::new_v7();
        let revision = MemoryRevision::new(7);
        let sequence = ProjectSequence::new(9);
        let body = json!({
            "work_lease_id": WorkLeaseId::new_v7(),
            "state": "granted",
            "started_at": "2026-07-17T09:15:42.8503046Z",
            "decision": {
                "expires_at": "2026-07-17T10:00:42.8503046Z",
            },
            "write_receipt": Value::Null,
        });
        let mut observed_body = body.clone();
        observed_body["started_at"] = json!("2026-07-17T09:15:42.850304600+00:00");
        observed_body["decision"]["expires_at"] = json!("2026-07-17T10:00:42.850304600+00:00");
        observed_body["write_receipt"] = json!({
            "receipt_id": ReceiptId::new_v7(),
            "write_id": WriteId::new_v7(),
        });
        let receipt = WriteReceipt {
            receipt_id: ReceiptId::new_v7(),
            write_id,
            input_hash: "blake3:input".to_owned(),
            project_id,
            task_id: Some(task_id),
            command_kind: SemanticCommandKind::ToolObservationRecord,
            status: WriteStatus::Committed,
            memory_revision: Some(revision),
            project_sequence: Some(sequence),
            created_records: vec![write_id.to_string()],
            created_relations: Vec::new(),
            weak_records: Vec::new(),
            rejected_reason: None,
            db_operation_id: None,
            created_at: OffsetDateTime::now_utc(),
        };
        let observation = CanonicalToolObservation {
            observation_id: write_id.to_string(),
            project_id,
            task_id: Some(task_id),
            scope: "work/work-lease".to_owned(),
            authority: "eliot-work-coordination-service".to_owned(),
            tool_name: "eliot_work_coordination".to_owned(),
            observation: "WorkLease fixture".to_owned(),
            payload: json!({ "work_lease": observed_body }),
            memory_revision: revision,
            project_sequence: sequence,
            write_id,
        };
        let expected = CanonicalAuthorityBody {
            label: "WorkLease",
            task_id: Some(task_id),
            scope: "work/work-lease",
            authority: "eliot-work-coordination-service",
            tool_name: "eliot_work_coordination",
            payload_key: "work_lease",
            body: &body,
            normalization: CanonicalBodyNormalization::Rfc3339Fields(&[
                "started_at",
                "decision.expires_at",
            ]),
        };
        validate_canonical_observation_identity(&observation, &receipt, project_id, &expected)?;
        let mut tampered_timestamp = observation.clone();
        tampered_timestamp.payload["work_lease"]["decision"]["expires_at"] =
            json!("2026-07-17T10:00:43.8503046Z");
        assert!(
            validate_canonical_observation_identity(
                &tampered_timestamp,
                &receipt,
                project_id,
                &expected,
            )
            .is_err()
        );
        let mut tampered = observation;
        tampered.payload["work_lease"]["state"] = json!("revoked");
        assert!(
            validate_canonical_observation_identity(&tampered, &receipt, project_id, &expected)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn canonical_revocation_before_projection_replace_rejects_old_active_receipt()
    -> anyhow::Result<()> {
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let lease_id = WorkLeaseId::new_v7();
        let old_write = WriteId::new_v7();
        let revoked_write = WriteId::new_v7();
        let observation =
            |write_id: WriteId, revision: u64, state: &str| CanonicalToolObservation {
                observation_id: write_id.to_string(),
                project_id,
                task_id: Some(task_id),
                scope: "work/work-lease".to_owned(),
                authority: "eliot-work-coordination-service".to_owned(),
                tool_name: "eliot_work_coordination".to_owned(),
                observation: format!("WorkLease state {state}"),
                payload: json!({
                    "work_lease": { "work_lease_id": lease_id, "state": state }
                }),
                memory_revision: MemoryRevision::new(revision),
                project_sequence: ProjectSequence::new(revision),
                write_id,
            };
        let latest = observation(revoked_write, 8, "revoked");
        let old = observation(old_write, 7, "granted");
        let old_reference = WriteReceiptRef {
            receipt_id: ReceiptId::new_v7(),
            write_id: old_write,
        };
        assert!(
            latest_canonical_authority_observation(
                &[latest.clone(), old],
                &old_reference,
                "WorkLease",
            )
            .is_err()
        );
        let current_reference = WriteReceiptRef {
            receipt_id: ReceiptId::new_v7(),
            write_id: revoked_write,
        };
        assert_eq!(
            latest_canonical_authority_observation(
                std::slice::from_ref(&latest),
                &current_reference,
                "WorkLease",
            )?
            .write_id,
            revoked_write
        );
        Ok(())
    }

    #[test]
    fn claude_desktop_registry_lookup_uses_manifest_identity() {
        let registry = json!({
            "extensions": {
                "ant.dir.example.other": {
                    "id": "ant.dir.example.other",
                    "version": "9.0.0",
                    "manifest": { "name": "other" }
                },
                "ant.local.eliot-governor": {
                    "id": "ant.local.eliot-governor",
                    "version": "0.1.0",
                    "manifest": { "name": "eliot-governor" }
                }
            }
        });
        let Some((id, entry)) = registry_entry_by_manifest(&registry, "eliot-governor") else {
            panic!("ELIOT registry entry must be discoverable by manifest name");
        };
        assert_eq!(id, "ant.local.eliot-governor");
        assert_eq!(entry["version"], "0.1.0");
        assert!(is_claude_desktop_host("Claude-Desktop"));
        assert!(is_claude_desktop_host("claude_desktop"));
        assert!(!is_claude_desktop_host("claude"));
    }

    #[test]
    fn opencode_jsonc_merge_preserves_comments_and_unrelated_values() -> anyhow::Result<()> {
        let original = br#"{
  // keep this comment
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    // keep this MCP too
    "context7": { "type": "remote", "url": "https://example.test/a//b" },
  },
  "instructions": ["shared.md"],
  "provider": { "name": "unchanged" },
}
"#;
        let merged = merge_opencode_mcp_config(original, &eliot_entry(), instruction_entry())?;
        let text = std::str::from_utf8(&merged.bytes)?;
        assert!(text.contains("// keep this comment"));
        assert!(text.contains("// keep this MCP too"));
        assert!(text.contains("https://example.test/a//b"));
        assert!(merged.mcp_field_existed_before);
        assert!(merged.mcp_entry_before.is_none());
        assert!(merged.instructions_field_existed_before);
        assert!(!merged.instruction_entry_existed_before);

        let root = parse_opencode_jsonc(&merged.bytes)?;
        let root_object = root
            .object_value()
            .ok_or_else(|| anyhow::anyhow!("root object"))?;
        let mcp = root_object
            .object_value("mcp")
            .ok_or_else(|| anyhow::anyhow!("mcp object"))?;
        assert_eq!(
            mcp.get("eliot")
                .and_then(|property| property.to_serde_value()),
            Some(eliot_entry())
        );

        let restored = remove_opencode_mcp_config(
            &merged.bytes,
            None,
            true,
            instruction_entry(),
            true,
            false,
        )?;
        let restored_text = std::str::from_utf8(&restored)?;
        assert!(restored_text.contains("// keep this comment"));
        assert!(restored_text.contains("// keep this MCP too"));
        let restored_root = parse_opencode_jsonc(&restored)?;
        let restored_mcp = restored_root
            .object_value()
            .and_then(|root| root.object_value("mcp"))
            .ok_or_else(|| anyhow::anyhow!("restored mcp object"))?;
        assert!(restored_mcp.get("eliot").is_none());
        assert!(restored_mcp.get("context7").is_some());
        let restored_instructions = restored_root
            .object_value()
            .and_then(|root| root.get("instructions"))
            .and_then(|property| property.to_serde_value());
        assert_eq!(restored_instructions, Some(json!(["shared.md"])));
        Ok(())
    }

    #[test]
    fn opencode_jsonc_rollback_removes_eliot_owned_mcp_container() -> anyhow::Result<()> {
        let original = b"{\n  // untouched\n  \"provider\": { \"name\": \"local\" },\n}\n";
        let merged = merge_opencode_mcp_config(original, &eliot_entry(), instruction_entry())?;
        assert!(!merged.mcp_field_existed_before);
        assert!(!merged.instructions_field_existed_before);
        let restored = remove_opencode_mcp_config(
            &merged.bytes,
            None,
            false,
            instruction_entry(),
            false,
            false,
        )?;
        let root = parse_opencode_jsonc(&restored)?;
        let root_object = root
            .object_value()
            .ok_or_else(|| anyhow::anyhow!("root object"))?;
        assert!(root_object.get("mcp").is_none());
        assert!(root_object.get("instructions").is_none());
        assert!(std::str::from_utf8(&restored)?.contains("// untouched"));
        Ok(())
    }

    #[test]
    fn opencode_jsonc_rollback_restores_preexisting_eliot_entry() -> anyhow::Result<()> {
        let original = br#"{
  "mcp": {
    "eliot": { "type": "remote", "url": "https://old.example/mcp" },
  },
  "instructions": ["C:/Eliot/instructions/eliot-governor.md"],
}
"#;
        let merged = merge_opencode_mcp_config(original, &eliot_entry(), instruction_entry())?;
        let before = merged
            .mcp_entry_before
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("preexisting entry"))?;
        assert!(merged.instruction_entry_existed_before);
        let restored = remove_opencode_mcp_config(
            &merged.bytes,
            Some(before),
            true,
            instruction_entry(),
            true,
            true,
        )?;
        let root = parse_opencode_jsonc(&restored)?;
        let actual = root
            .object_value()
            .and_then(|root| root.object_value("mcp"))
            .and_then(|mcp| mcp.get("eliot"))
            .and_then(|property| property.to_serde_value());
        assert_eq!(actual.as_ref(), Some(before));
        let instructions = root
            .object_value()
            .and_then(|root| root.get("instructions"))
            .and_then(|property| property.to_serde_value());
        assert_eq!(instructions, Some(json!([instruction_entry()])));
        Ok(())
    }
}
