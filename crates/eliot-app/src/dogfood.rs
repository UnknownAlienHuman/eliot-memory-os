use crate::config::load_config;
use crate::named_pipe_ipc::{
    IPC_PROTOCOL_VERSION, pipe_name, restrict_owned_directory_to_current_user,
};
use crate::runtime_instance::{RuntimeInstance, atomic_write_bytes};
use anyhow::{Context, Result, bail};
use eliot_store::{CanonicalStore, SurrealServerSupervisor};
use eliot_types::{
    AgentHostId, CredentialProviderKind, GovernorConfig, ProjectId, ProviderDeclaredBudget,
    ProviderRoutePolicy, SCHEMA_VERSION, SessionId, TaskContract, TaskContractStatus, TaskId,
    WorkItemId, WorkLeaseId, WorktreeLeaseId, WriteId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt as _;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MANIFEST_VERSION: &str = "eliot-dogfood-l3-v1";
const PROVIDER_KILL_SWITCH: &str = "ELIOT_DISABLE_REAL_PROVIDER";
const DOGFOOD_PROVIDER_TIMEOUT: Duration = Duration::from_mins(30);
const DOGFOOD_PROVIDER_OUTPUT_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
const DOGFOOD_CODEX_ENABLED_TOOLS: &[&str] = &[
    "eliot_host_session_status",
    "eliot_project_identity",
    "eliot_task_state",
    "eliot_operator_query",
    "eliot_task_action_request",
    "eliot_task_observation_record",
    "eliot_task_verification_run",
    "eliot_submit_understanding_proof",
    "eliot_submit_completion_proof",
    "eliot_codecortex_scan",
    "eliot_codecortex_latest",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OwnedChild {
    role: String,
    pid: u32,
    executable: PathBuf,
}

struct CodexExecPlan {
    argv_without_prompt: Vec<String>,
    prompt_source_path: PathBuf,
    output_schema_path: PathBuf,
    output_last_message_path: PathBuf,
    jsonl_stdout_path: PathBuf,
}

// Every field is an identity; the shared `_id` suffix is the point, not noise.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug)]
struct DogfoodCodexScope {
    project_id: ProjectId,
    task_id: TaskId,
    session_id: SessionId,
    role_lease_id: String,
    work_item_id: WorkItemId,
    work_lease_id: WorkLeaseId,
    worktree_lease_id: WorktreeLeaseId,
}

#[derive(Clone, Debug, Serialize)]
struct CodexExecutableIdentity {
    path: PathBuf,
    version: String,
    sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum DogfoodCodexOutcome {
    Completed,
    Blocked,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DogfoodCodexFinal {
    schema_version: String,
    outcome: DogfoodCodexOutcome,
    summary: String,
}

struct ValidatedCodexLaunch {
    worktree: PathBuf,
    branch: String,
    commit: String,
    plan: CodexExecPlan,
}

pub(crate) struct PreparedDogfoodWorktreeBinding {
    pub worktree: PathBuf,
    pub branch: String,
    pub commit: String,
    pub managed_root: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DogfoodManifest {
    manifest_version: String,
    runtime_root: PathBuf,
    project_root: PathBuf,
    config_path: PathBuf,
    governor_binary: PathBuf,
    provider_kill_switch: bool,
    state: String,
    children: Vec<OwnedChild>,
}

#[derive(Clone, Debug, Deserialize)]
struct SurrealArtifactLock {
    schema: String,
    artifact: String,
    version: String,
    architecture: String,
    pe_machine: String,
    sha256: String,
}

#[derive(Clone, Debug, Serialize)]
struct SurrealArtifactIdentity {
    path: PathBuf,
    version: String,
    sha256: String,
    pe_machine: String,
}

pub(crate) fn init(root: &Path, project: &Path, surreal_exe: &Path) -> Result<()> {
    let root = validate_explicit_safe_root(root)?;
    if root.exists() && fs::read_dir(&root)?.next().is_some() {
        bail!("dogfood init requires an absent or empty owned runtime root");
    }
    let project = canonical_git_root(project)?;
    let lock = read_surreal_artifact_lock(&project)?;
    let preseed = validate_surreal_preseed(surreal_exe, &lock)?;
    if root.starts_with(&project) || project.starts_with(&root) {
        bail!("dogfood runtime root and repository root must not contain one another");
    }

    fs::create_dir_all(&root)
        .with_context(|| format!("create dogfood runtime root {}", root.display()))?;
    let root = validate_explicit_safe_root(&canonicalize_windows(&root)?)?;
    restrict_owned_directory_to_current_user(&root)?;
    for child in [
        "config", "control", "blobs", "secrets", "runtime", "logs", "reports", "tmp", "codex",
    ] {
        fs::create_dir_all(root.join(child))?;
    }
    let runtime_bin = root.join("runtime").join("bin");
    fs::create_dir_all(&runtime_bin)?;
    restrict_owned_directory_to_current_user(&runtime_bin)?;
    let runtime_surreal = runtime_bin.join("surreal.exe");
    fs::copy(&preseed, &runtime_surreal).with_context(|| {
        format!(
            "copy operator-preseeded SurrealDB executable {} into {}",
            preseed.display(),
            runtime_surreal.display()
        )
    })?;
    validate_surreal_artifact(&runtime_surreal, &lock, Some(&root))?;

    let config_path = root.join("config").join("governor.toml");
    let mut config = GovernorConfig::default();
    let port = reserve_loopback_port()?;
    config.service.instance_id = format!("dogfood-l3-{port}");
    config.db.surreal.bind = format!("127.0.0.1:{port}");
    config.db.surreal.endpoint = format!("ws://127.0.0.1:{port}/rpc");
    config.db.surreal.storage = format!("rocksdb:{}", slash(&root.join("surrealdb-rocks")));
    config.db.surreal.exe = slash(&runtime_surreal);
    config.db.surreal.credential_provider = CredentialProviderKind::WindowsCredentialManager;
    config.db.surreal.credential_id = format!("surreal-runtime/dogfood-l3-{port}");
    config.control_wal.path = slash(&root.join("control").join("control.redb"));
    config.blob_store.root = slash(&root.join("blobs"));
    config.store.surql_dir = slash(&project.join("surql"));
    config.store.migrations_dir = slash(&project.join("migrations"));
    config.validate()?;
    fs::write(&config_path, toml::to_string_pretty(&config)?)?;

    let governor_binary = canonicalize_windows(&env::current_exe()?)?;
    write_codex_config(&root, &governor_binary, &config_path)?;
    let manifest = DogfoodManifest {
        manifest_version: MANIFEST_VERSION.to_owned(),
        runtime_root: root.clone(),
        project_root: project,
        config_path,
        governor_binary,
        provider_kill_switch: true,
        state: "initialized".to_owned(),
        children: Vec::new(),
    };
    write_manifest(&root, &manifest)?;
    write_json(&json!({
        "component": "dogfood_init",
        "status": "initialized",
        "runtime_root": root,
        "runtime_root_safe": true,
        "provider_kill_switch": true
    }))
}

pub(crate) fn prepare_worktree(
    root: &Path,
    destination: &Path,
    branch: &str,
    commit: &str,
) -> Result<()> {
    let root = validate_existing_root(root)?;
    let manifest = read_manifest(&root)?;
    validate_manifest_binding(&root, &manifest)?;
    if !matches!(manifest.state.as_str(), "initialized" | "stopped") {
        bail!("dogfood worktree preparation requires a stopped runtime");
    }
    let source = canonical_git_root(&manifest.project_root)?;
    if !git_stdout(&source, &["status", "--porcelain=v1"])?.is_empty() {
        bail!("dogfood source repository must be clean before cloning");
    }
    let source_head = git_stdout(&source, &["rev-parse", "HEAD"])?;
    let commit_ref = format!("{commit}^{{commit}}");
    let resolved_commit = git_stdout(&source, &["rev-parse", "--verify", &commit_ref])?;
    if commit.len() != 40
        || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !resolved_commit.eq_ignore_ascii_case(commit)
    {
        bail!("dogfood base commit must be an exact 40-character commit id");
    }
    git_success(&source, &["check-ref-format", "--branch", branch])?;

    let destination = create_new_safe_directory(destination, &source)?;
    let prepared = prepare_independent_clone(
        &root,
        &manifest,
        &source,
        &destination,
        branch,
        &resolved_commit,
        &source_head,
    );
    let report = match prepared {
        Ok(report) => report,
        Err(error) => {
            let _ = fs::remove_dir_all(&destination);
            return Err(error);
        }
    };
    let report_dir = root.join("reports").join("dogfood");
    fs::create_dir_all(&report_dir)?;
    fs::write(
        report_dir.join("codex-worktree.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    write_json(&report)
}

// Kept whole: one dogfood scenario: launch, observe, and grade a single live run.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn prepare_independent_clone(
    root: &Path,
    manifest: &DogfoodManifest,
    source: &Path,
    destination: &Path,
    branch: &str,
    commit: &str,
    source_head: &str,
) -> Result<Value> {
    restrict_owned_directory_to_current_user(destination)?;
    git_success(
        destination,
        &[
            "clone",
            "--local",
            "--no-hardlinks",
            "--no-checkout",
            "--",
            &slash(source),
            ".",
        ],
    )?;
    git_success(destination, &["checkout", "-b", branch, commit])?;
    git_success(destination, &["remote", "remove", "origin"])?;

    let git_dir = canonicalize_windows(&destination.join(".git"))?;
    if !git_dir.is_dir() || !path_starts_with_case_insensitive(&git_dir, destination) {
        bail!("dogfood Codex worktree must own its Git metadata inside the sandbox root");
    }
    if git_dir
        .join("objects")
        .join("info")
        .join("alternates")
        .exists()
    {
        bail!("dogfood Codex worktree must not borrow the source object database");
    }

    let hooks_path = root
        .join("reports")
        .join("dogfood")
        .join("codex-hooks.json");
    fs::create_dir_all(hooks_path.parent().context("hooks path has no parent")?)?;
    let hooks = codex_hooks(&manifest.governor_binary, &manifest.config_path);
    let hooks_bytes = serde_json::to_vec_pretty(&hooks)?;
    fs::write(&hooks_path, &hooks_bytes)?;
    let codex_config_overrides = codex_config_overrides(
        &manifest.governor_binary,
        &manifest.config_path,
        destination,
    )?;
    let exec_plan = codex_exec_plan(root, destination, &codex_config_overrides)?;

    let candidate_head = git_stdout(destination, &["rev-parse", "HEAD"])?;
    let candidate_branch = git_stdout(destination, &["branch", "--show-current"])?;
    let candidate_status = git_stdout(destination, &["status", "--porcelain=v1"])?;
    let source_head_after = git_stdout(source, &["rev-parse", "HEAD"])?;
    let source_status_after = git_stdout(source, &["status", "--porcelain=v1"])?;
    if candidate_head != commit
        || candidate_branch != branch
        || !candidate_status.is_empty()
        || source_head_after != source_head
        || !source_status_after.is_empty()
    {
        bail!("dogfood Codex worktree postconditions were not satisfied");
    }

    Ok(json!({
        "component": "dogfood_prepare_worktree",
        "status": "prepared",
        "runtime_root": root,
        "source_repository": source,
        "source_head_unchanged": true,
        "worktree_root": destination,
        "branch": branch,
        "commit": commit,
        "independent_git_metadata": true,
        "git_metadata_root": git_dir,
        "git_metadata_within_worktree": true,
        "borrowed_object_database": false,
        "hooks_path": hooks_path,
        "hooks_blake3": blake3::hash(&hooks_bytes).to_hex().to_string(),
        "hooks_source": "cli_inline_from_hashed_artifact",
        "codex_config_overrides": codex_config_overrides,
        "codex_config_precedence": "cli_overrides",
        "codex_exec_command": "codex",
        "codex_exec_argv_without_prompt": exec_plan.argv_without_prompt,
        "codex_prompt_source_path": exec_plan.prompt_source_path,
        "codex_prompt_via_stdin_required": true,
        "codex_prompt_generated_from_task_contract": true,
        "codex_output_schema_path": exec_plan.output_schema_path,
        "codex_output_schema_generated_from_task_contract": true,
        "codex_output_last_message_path": exec_plan.output_last_message_path,
        "codex_jsonl_stdout_path": exec_plan.jsonl_stdout_path,
        "codex_jsonl_stdout_redirection_required": true,
        "codex_ignore_user_config_required": true,
        "codex_project_trust_required": false,
        "codex_project_config_loaded": false,
        "codex_home_relocation_required": false,
        "codex_hook_trust_bypass_required": true,
        "codex_scope_environment_only": true,
        "codex_role_lease_in_argv": false,
        "bounded_write_roots": [destination],
        "provider_kill_switch": manifest.provider_kill_switch,
        "global_codex_config_mutated": false,
        "source_repository_mutated": false
    }))
}

pub(crate) async fn start(root: &Path) -> Result<()> {
    let root = validate_existing_root(root)?;
    let mut manifest = read_manifest(&root)?;
    validate_manifest_binding(&root, &manifest)?;
    if !manifest.children.is_empty() {
        let running = manifest.children.iter().any(owned_child_is_running);
        if running {
            bail!("dogfood runtime already has a recorded running child");
        }
        manifest.children.clear();
    }
    for pid_path in [
        root.join("runtime").join("daemon.pid"),
        root.join("tmp").join("surreal.pid"),
    ] {
        if read_pid(&pid_path).is_some_and(process_exists) {
            bail!(
                "dogfood runtime contains a live PID outside the owned child manifest: {}",
                pid_path.display()
            );
        }
    }

    let config = load_config(&manifest.config_path)?;
    let lock = read_surreal_artifact_lock(&manifest.project_root)?;
    validate_surreal_artifact(Path::new(&config.db.surreal.exe), &lock, Some(&root))?;
    let supervisor = SurrealServerSupervisor::new(config.db.surreal.clone());
    let db_executable = canonicalize_windows(&supervisor.executable_path()?)
        .context("canonicalize resolved SurrealDB executable")?;
    let server = supervisor.start_or_connect().await?;
    let db_pid = server
        .started_pid()
        .or_else(|| read_pid(&root.join("tmp").join("surreal.pid")))
        .context("SurrealDB reached readiness without an owned PID record")?;
    drop(server);

    manifest.children = vec![OwnedChild {
        role: "surrealdb".to_owned(),
        pid: db_pid,
        executable: db_executable,
    }];
    "starting".clone_into(&mut manifest.state);
    write_manifest(&root, &manifest)?;

    let child = match spawn_daemon(&root, &manifest) {
        Ok(child) => child,
        Err(error) => {
            let _ = SurrealServerSupervisor::new(config.db.surreal).stop().await;
            manifest.children.clear();
            "start_failed".clone_into(&mut manifest.state);
            write_manifest(&root, &manifest)?;
            return Err(error);
        }
    };
    let daemon_pid = child.id();

    manifest.children.push(OwnedChild {
        role: "governor-daemon".to_owned(),
        pid: daemon_pid,
        executable: manifest.governor_binary.clone(),
    });
    write_manifest(&root, &manifest)?;

    let published_ready = wait_until(Duration::from_secs(30), || {
        runtime_publication_marker_ready(&root, daemon_pid)
            && manifest.children.iter().all(owned_child_is_running)
    });
    if !published_ready || !runtime_publication_is_ready(&manifest) {
        let _ = stop(&root).await;
        bail!(
            "dogfood daemon did not reach schema-migrated authenticated IPC readiness within 30 seconds"
        );
    }
    "running".clone_into(&mut manifest.state);
    write_manifest(&root, &manifest)?;
    write_json(&json!({
        "component": "dogfood_start",
        "status": "running",
        "owned_children": manifest.children.iter().map(|child| json!({
            "role": child.role,
            "pid": child.pid,
            "executable": child.executable
        })).collect::<Vec<_>>()
    }))
}

// the call carries the full context it must not re-derive
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn run_codex(
    root: &Path,
    project_id: &str,
    task_id: &str,
    agent_session_id: &str,
    role_lease_id: &str,
    work_item_id: &str,
    work_lease_id: &str,
    worktree_lease_id: &str,
) -> Result<()> {
    let scope = DogfoodCodexScope::parse(
        project_id,
        task_id,
        agent_session_id,
        role_lease_id,
        work_item_id,
        work_lease_id,
        worktree_lease_id,
    )?;
    let root = validate_existing_root(root)?;
    let manifest = read_manifest(&root)?;
    validate_manifest_binding(&root, &manifest)?;
    if manifest.state != "running" || !manifest.provider_kill_switch {
        bail!(
            "dogfood run-codex requires a running owned runtime with its provider kill switch enabled"
        );
    }

    let config = load_config(&manifest.config_path)?;
    let status = machine_status(&root, &manifest, &config).await;
    if !status.daemon_ready || !status.db_ready {
        bail!("dogfood run-codex requires ready owned daemon and database processes");
    }

    let launch = validate_codex_launch_report(&root, &manifest)?;
    let validated_scope = crate::mcp_stdio::validate_codex_controller_scope(
        &manifest.config_path,
        scope.session_id,
        &scope.role_lease_id,
        scope.project_id,
        scope.task_id,
    )?;
    let validated_work_scope = crate::mcp_stdio::validate_codex_work_scope(
        &manifest.config_path,
        &validated_scope,
        scope.work_item_id,
        scope.work_lease_id,
        scope.worktree_lease_id,
        &launch.worktree,
        &launch.branch,
        &launch.commit,
    )?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let task_before = store
        .task_contract_by_id(scope.task_id)
        .await?
        .context("dogfood Codex scope references a missing canonical TaskContract")?;
    if task_before.project_id != scope.project_id {
        bail!("dogfood Codex TaskContract belongs to a different project");
    }
    if !task_status_allows_codex_launch(task_before.status) {
        bail!("dogfood run-codex requires an Open or Active canonical TaskContract");
    }
    let action_provenance_hash_before = task_before
        .action_provenance
        .as_ref()
        .map(|provenance| provenance.hash.clone());
    let preflight_contract_sha256 = materialize_codex_launch_artifacts(
        &root,
        &launch,
        &task_before,
        &validated_scope,
        &validated_work_scope,
    )?;
    require_regular_file(&launch.plan.prompt_source_path, "Codex prompt")?;
    require_regular_file(&launch.plan.output_schema_path, "Codex output schema")?;
    require_safe_optional_output(
        &launch.plan.output_last_message_path,
        "Codex last-message output",
    )?;
    require_safe_optional_output(&launch.plan.jsonl_stdout_path, "Codex JSONL output")?;

    let (codex, process) = run_codex_provider(
        &manifest,
        &launch,
        &validated_scope,
        &validated_work_scope,
        &preflight_contract_sha256,
    )
    .await?;
    fs::write(&launch.plan.jsonl_stdout_path, &process.stdout)
        .context("write planned Codex JSONL stdout path")?;
    let stderr_path = launch.plan.jsonl_stdout_path.with_file_name("stderr.log");
    fs::write(&stderr_path, &process.stderr).context("write Codex stderr log")?;
    let mut blockers = Vec::new();
    if process.worker_error.is_some() || !process.reap_receipt.proves_complete_reap() {
        blockers.push("provider_process_not_completely_reaped".to_owned());
    }
    if process.exit_code != Some(0) || process.timed_out {
        blockers.push("codex_process_not_successful".to_owned());
    }
    if process.stdout_truncated {
        blockers.push("codex_event_stream_truncated".to_owned());
    }
    let model_action_write_ids = if blockers
        .iter()
        .any(|blocker| blocker == "codex_event_stream_truncated")
    {
        Vec::new()
    } else {
        codex_event_task_action_write_ids(&process.stdout).unwrap_or_else(|_| {
            blockers.push("codex_event_stream_invalid".to_owned());
            Vec::new()
        })
    };
    let model_invoked_task_action_request = !model_action_write_ids.is_empty();
    if !model_invoked_task_action_request {
        blockers.push("model_task_action_request_not_observed".to_owned());
    }
    let final_message = validate_codex_final_message(&launch.plan.output_last_message_path)
        .map_or_else(
            |_| {
                blockers.push("codex_final_message_invalid".to_owned());
                None
            },
            Some,
        );
    if final_message
        .as_ref()
        .is_none_or(|message| message.outcome != DogfoodCodexOutcome::Completed)
    {
        blockers.push("codex_final_outcome_not_completed".to_owned());
    }
    let task_after = match store.task_contract_by_id(scope.task_id).await {
        Ok(Some(task)) if task.project_id == scope.project_id => Some(task),
        _ => {
            blockers.push("canonical_task_readback_failed".to_owned());
            None
        }
    };
    let canonical_finish_proven = task_after.as_ref().is_some_and(|task| {
        task.status == TaskContractStatus::DoneVerified
            && task.completion_proof.is_some()
            && !task.verification_ids.is_empty()
            && task.action_provenance.is_some()
    });
    if !canonical_finish_proven {
        blockers.push("canonical_finish_not_proven".to_owned());
    }
    let model_action_bound_to_canonical_state = task_after.as_ref().is_some_and(|task| {
        let Some(provenance) = task.action_provenance.as_ref() else {
            return false;
        };
        let Some(action_write_id) =
            action_write_id_from_provenance_set_id(&provenance.provenance_set_id)
        else {
            return false;
        };
        action_provenance_hash_before.as_deref() != Some(provenance.hash.as_str())
            && model_action_write_ids.contains(&action_write_id)
    });
    if !model_action_bound_to_canonical_state {
        blockers.push("model_task_action_not_bound_to_canonical_state".to_owned());
    }
    let opaque_offer_return_proven = task_after.as_ref().is_some_and(|task| {
        let Some(provenance) = task.action_provenance.as_ref() else {
            return false;
        };
        let Some(action_write_id) =
            action_write_id_from_provenance_set_id(&provenance.provenance_set_id)
        else {
            return false;
        };
        model_action_bound_to_canonical_state
            && !provenance.memory_grant_refs.is_empty()
            && task
                .memory_grant_redemptions
                .iter()
                .any(|redemption| redemption.action_write_id == action_write_id)
    });
    if !opaque_offer_return_proven {
        blockers.push("opaque_memory_offer_return_not_proven".to_owned());
    }
    blockers.sort();
    blockers.dedup();
    let accepted = blockers.is_empty();
    let role_lease_ref_sha256 =
        sha256_hex(format!("eliot-dogfood-role-lease-ref-v1\0{}", scope.role_lease_id).as_bytes());
    let provider_diagnostics = json!({
        "timeout_class": &process.timeout_class,
        "cancelled": process.cancelled,
        "worker_error": process.worker_error.as_deref(),
        "process_started_at": &process.process_started_at,
        "first_output_at": &process.first_output_at,
        "last_output_at": &process.last_output_at,
        "process_exit_at": &process.process_exit_at,
        "cleanup_completed_at": &process.cleanup_completed_at,
        "stdout_total_bytes": process.stdout_total_bytes,
        "stderr_total_bytes": process.stderr_total_bytes,
        "stdout_truncated": process.stdout_truncated,
        "stderr_truncated": process.stderr_truncated,
    });

    let result = json!({
        "component": "dogfood_run_codex",
        "status": if accepted { "completed" } else { "failed" },
        "codex_executable": codex,
        "preflight_contract_sha256": preflight_contract_sha256,
        "project_id": scope.project_id,
        "task_id": scope.task_id,
        "agent_session_id": scope.session_id,
        "role_lease_ref_sha256": role_lease_ref_sha256,
        "role_lease_epoch": validated_scope.role_lease_epoch,
        "role_lease_generation": validated_scope.role_lease_generation,
        "work_item_id": validated_work_scope.work_item_id,
        "work_lease_id": validated_work_scope.work_lease_id,
        "worktree_lease_id": validated_work_scope.worktree_lease_id,
        "worktree_root": launch.worktree,
        "branch": launch.branch,
        "commit": launch.commit,
        "exit_code": process.exit_code,
        "timed_out": process.timed_out,
        "provider_diagnostics": provider_diagnostics,
        "reap_receipt": process.reap_receipt,
        "events_path": launch.plan.jsonl_stdout_path,
        "stderr_path": stderr_path,
        "last_message_path": launch.plan.output_last_message_path,
        "model_summary": final_message.as_ref().map(|message| message.summary.as_str()),
        "model_invoked_task_action_request": model_invoked_task_action_request,
        "model_action_write_ids": model_action_write_ids,
        "model_action_bound_to_canonical_state": model_action_bound_to_canonical_state,
        "opaque_offer_return_proven": opaque_offer_return_proven,
        "canonical_finish_proven": canonical_finish_proven,
        "task_status_before": task_before.status,
        "task_revision_before": task_before.memory_revision,
        "task_revision_after": task_after.as_ref().map(|task| task.memory_revision),
        "blockers": blockers,
        "provider_kill_switch": true
    });
    let latest_path = root.join("reports").join("live-codex").join("latest.json");
    write_json_file_atomic(&latest_path, &result)?;
    write_json(&result)?;
    if !accepted {
        bail!(
            "Codex Product Pulse proof was not accepted; launch result preserved at {}",
            latest_path.display()
        );
    }
    Ok(())
}

// Kept whole: one dogfood scenario end to end.
#[allow(clippy::too_many_lines)]
async fn run_codex_provider(
    manifest: &DogfoodManifest,
    launch: &ValidatedCodexLaunch,
    scope: &crate::mcp_stdio::ValidatedCodexControllerScope,
    work_scope: &crate::mcp_stdio::ValidatedCodexWorkScope,
    preflight_contract_sha256: &str,
) -> Result<(
    CodexExecutableIdentity,
    eliot_engine::ProviderProcessOutcome,
)> {
    let prompt =
        fs::read(&launch.plan.prompt_source_path).context("read generated Codex prompt source")?;
    let codex = find_codex_cli().context("locate installed codex.exe")?;
    let codex = canonicalize_windows(&codex).context("canonicalize installed codex.exe")?;
    if !codex.is_file()
        || !codex
            .file_name()
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("codex.exe"))
    {
        bail!("resolved Codex CLI is not an installed codex.exe regular file");
    }
    let codex_identity = codex_executable_identity(&codex)?;
    let allowed_environment = [
        "APPDATA",
        "CODEX_HOME",
        "COMSPEC",
        "HOME",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    ];
    let mut environment = std::env::vars_os()
        .filter(|(name, _)| {
            allowed_environment
                .iter()
                .any(|allowed| name.eq_ignore_ascii_case(allowed))
        })
        .collect::<Vec<_>>();
    environment.push((PROVIDER_KILL_SWITCH.into(), "1".into()));
    let requested_scope = &scope.requested_scope;
    environment.push((
        "ELIOT_AGENT_SESSION_ID".into(),
        scope.agent_session_id.to_string().into(),
    ));
    environment.push((
        "ELIOT_PROJECT_ID".into(),
        requested_scope.project_id.to_string().into(),
    ));
    environment.push((
        "ELIOT_TASK_ID".into(),
        requested_scope
            .task_id
            .context("validated Codex scope is missing task id")?
            .to_string()
            .into(),
    ));
    let scope_token = crate::mcp_stdio::issue_codex_scope_capability(
        &manifest.config_path,
        scope,
        work_scope,
        preflight_contract_sha256,
    )?;
    environment.push(("ELIOT_CODEX_SCOPE_TOKEN".into(), scope_token.clone().into()));
    let mut args = launch
        .plan
        .argv_without_prompt
        .iter()
        .map(std::ffi::OsString::from)
        .collect::<Vec<_>>();
    args.push("-".into());
    let provider_runtime = crate::host_runtime::ProviderRuntime::production(&manifest.config_path)?;
    let runner = provider_runtime.runner();
    let mut on_spawned = |_| Ok(());
    let process = eliot_engine::ProviderProcessRunner::run(
        runner.as_ref(),
        eliot_engine::ProviderProcessSpec {
            operation_id: format!("dogfood-codex-{}", uuid::Uuid::now_v7()),
            invocation_id: None,
            executable: codex.clone(),
            args,
            cwd: launch.worktree.clone(),
            environment,
            stdin_payload: Some(prompt),
            route_policy: ProviderRoutePolicy::for_route(
                AgentHostId::Codex,
                "dogfood-live-codex",
                ProviderDeclaredBudget::new(
                    u64::try_from(DOGFOOD_PROVIDER_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
                    DOGFOOD_PROVIDER_OUTPUT_LIMIT_BYTES,
                )
                .with_first_output_deadline_ms(None),
            ),
            cancellation: eliot_engine::runtime_supervision::CancellationToken::new(),
            deadline: tokio::time::Instant::now() + DOGFOOD_PROVIDER_TIMEOUT,
            runtime_contract_sha256: Some(preflight_contract_sha256.to_owned()),
            role_lease_id: Some(scope.role_lease_id.clone()),
            role_lease_epoch: Some(scope.role_lease_epoch),
        },
        &mut on_spawned,
    )
    .await;
    let revoke =
        crate::mcp_stdio::revoke_codex_scope_capability(&manifest.config_path, &scope_token);
    let process = process.map_err(|error| anyhow::anyhow!(error.to_string()))?;
    revoke?;
    Ok((codex_identity, process))
}

impl DogfoodCodexScope {
    fn parse(
        project_id: &str,
        task_id: &str,
        agent_session_id: &str,
        role_lease_id: &str,
        work_item_id: &str,
        work_lease_id: &str,
        worktree_lease_id: &str,
    ) -> Result<Self> {
        let role_lease_id = role_lease_id.trim();
        if role_lease_id.is_empty()
            || role_lease_id.len() > 256
            || role_lease_id.chars().any(char::is_control)
        {
            bail!("dogfood Codex role lease id is malformed");
        }
        Ok(Self {
            project_id: ProjectId::from_str(project_id).context("parse dogfood project id")?,
            task_id: TaskId::from_str(task_id).context("parse dogfood task id")?,
            session_id: SessionId::from_str(agent_session_id)
                .context("parse dogfood agent session id")?,
            role_lease_id: role_lease_id.to_owned(),
            work_item_id: WorkItemId::from_str(work_item_id)
                .context("parse dogfood work item id")?,
            work_lease_id: WorkLeaseId::from_str(work_lease_id)
                .context("parse dogfood work lease id")?,
            worktree_lease_id: WorktreeLeaseId::from_str(worktree_lease_id)
                .context("parse dogfood worktree lease id")?,
        })
    }
}

fn materialize_codex_launch_artifacts(
    root: &Path,
    launch: &ValidatedCodexLaunch,
    task: &TaskContract,
    scope: &crate::mcp_stdio::ValidatedCodexControllerScope,
    work_scope: &crate::mcp_stdio::ValidatedCodexWorkScope,
) -> Result<String> {
    let live_report_dir = root.join("reports").join("live-codex");
    fs::create_dir_all(&live_report_dir)?;
    restrict_owned_directory_to_current_user(&live_report_dir)?;
    for (path, label) in [
        (&launch.plan.prompt_source_path, "Codex prompt"),
        (&launch.plan.output_schema_path, "Codex output schema"),
        (
            &launch.plan.output_last_message_path,
            "Codex last-message output",
        ),
        (&launch.plan.jsonl_stdout_path, "Codex JSONL output"),
    ] {
        require_safe_optional_output(path, label)?;
    }
    let stderr_path = launch.plan.jsonl_stdout_path.with_file_name("stderr.log");
    for path in [
        &launch.plan.output_last_message_path,
        &launch.plan.jsonl_stdout_path,
        &stderr_path,
    ] {
        if path.exists() {
            fs::remove_file(path)
                .with_context(|| format!("remove stale Codex output {}", path.display()))?;
        }
    }

    let prompt = render_codex_prompt(task)?;
    validate_handle_free_codex_prompt(&prompt)?;
    let mut schema_bytes = serde_json::to_vec_pretty(&codex_final_message_schema())?;
    schema_bytes.push(b'\n');
    atomic_write_bytes(&launch.plan.prompt_source_path, prompt.as_bytes())?;
    atomic_write_bytes(&launch.plan.output_schema_path, &schema_bytes)?;

    let prompt_sha256 = sha256_hex(prompt.as_bytes());
    let output_schema_sha256 = sha256_hex(&schema_bytes);
    let argv_sha256 = sha256_hex(&serde_json::to_vec(&launch.plan.argv_without_prompt)?);
    let role_lease_ref_sha256 =
        sha256_hex(format!("eliot-dogfood-role-lease-ref-v1\0{}", scope.role_lease_id).as_bytes());
    let contract = json!({
        "schema_version": "eliot-dogfood-codex-preflight-v1",
        "project_id": task.project_id,
        "task_id": task.task_id,
        "task_revision": task.memory_revision,
        "agent_session_id": scope.agent_session_id,
        "role_lease_ref_sha256": role_lease_ref_sha256,
        "role_lease_epoch": scope.role_lease_epoch,
        "role_lease_generation": scope.role_lease_generation,
        "work_item_id": work_scope.work_item_id,
        "work_lease_id": work_scope.work_lease_id,
        "worktree_lease_id": work_scope.worktree_lease_id,
        "worktree_path": work_scope.worktree_path,
        "worktree_baseline_commit": work_scope.baseline_commit,
        "worktree_root": launch.worktree,
        "baseline_commit": launch.commit,
        "prompt_sha256": prompt_sha256,
        "output_schema_sha256": output_schema_sha256,
        "argv_without_prompt_sha256": argv_sha256,
        "prompt_transport": "stdin",
        "scope_transport": "opaque_capability_forwarded_to_mcp_child",
        "role_lease_in_codex_argv": false,
        "model_shell_scope_environment_excluded": true,
        "prompt_contains_exact_memory_handle": false,
        "last_message_is_authoritative_action": false
    });
    let contract_sha256 = sha256_hex(&serde_json::to_vec(&contract)?);
    let preflight = json!({
        "component": "dogfood_codex_preflight",
        "status": "ready",
        "contract": contract,
        "contract_sha256": contract_sha256
    });
    atomic_write_bytes(
        &live_report_dir.join("preflight.json"),
        &serde_json::to_vec_pretty(&preflight)?,
    )?;
    Ok(contract_sha256)
}

fn render_codex_prompt(task: &TaskContract) -> Result<String> {
    let task_data = json!({
        "goal": task.title,
        "acceptance_items": task.acceptance_items.iter().map(|item| json!({
            "item_id": item.item_id,
            "description": item.description,
            "required_evidence": item.required_evidence
        })).collect::<Vec<_>>()
    });
    let task_data = serde_json::to_string_pretty(&task_data)?;
    Ok(format!(
        "# Governed local task\n\n\
Treat the JSON block below as canonical task data. Work only in the current sandboxed Git worktree.\n\
Before changing files, use the available Eliot MCP surface to confirm project identity, the authenticated task scope, and the compact active task view. Decide the smallest reversible action and submit the governed action request yourself; never print or simulate a tool call. Use only the verifier registered in canonical task state, record the resulting observation and verification, and attempt canonical finish. If canonical scope, authority, or verifier evidence is unavailable, do not guess: return a blocked result. Do not inspect or print process environment, authentication material, or secret files.\n\n\
```json\n{task_data}\n```\n\n\
Return only the JSON object required by the supplied output schema.\n"
    ))
}

fn validate_handle_free_codex_prompt(prompt: &str) -> Result<()> {
    let normalized = prompt.to_ascii_lowercase();
    for forbidden in [
        "mg1.",
        "memory_handle",
        "memory_grant",
        "exact_source_handle",
        "experience_case:",
        "experience_pattern:",
        "eliot_recall_l0",
        "eliot_fetch_l2",
        "eliot_task_action_request",
    ] {
        if normalized.contains(forbidden) {
            bail!("generated Codex prompt contains forbidden discovery marker");
        }
    }
    Ok(())
}

fn codex_final_message_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "outcome", "summary"],
        "properties": {
            "schema_version": {"type": "string", "const": "eliot-dogfood-codex-final-v1"},
            "outcome": {"type": "string", "enum": ["completed", "blocked"]},
            "summary": {"type": "string", "minLength": 1, "maxLength": 4096}
        }
    })
}

fn validate_codex_final_message(path: &Path) -> Result<DogfoodCodexFinal> {
    require_regular_file(path, "Codex last-message output")?;
    let message: DogfoodCodexFinal =
        serde_json::from_slice(&fs::read(path)?).context("parse strict Codex final message")?;
    if message.schema_version != "eliot-dogfood-codex-final-v1"
        || message.summary.trim().is_empty()
        || message.summary.len() > 4096
    {
        bail!("Codex final message violates the generated output contract");
    }
    Ok(message)
}

fn task_status_allows_codex_launch(status: TaskContractStatus) -> bool {
    matches!(
        status,
        TaskContractStatus::Open | TaskContractStatus::Active
    )
}

fn action_write_id_from_provenance_set_id(provenance_set_id: &str) -> Option<WriteId> {
    WriteId::from_str(provenance_set_id.strip_prefix("eliot/provenance-set/")?).ok()
}

fn codex_event_task_action_write_ids(bytes: &[u8]) -> Result<Vec<WriteId>> {
    let text = std::str::from_utf8(bytes).context("Codex JSONL event stream is not UTF-8")?;
    let mut write_ids = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let event: Value = serde_json::from_str(line).context("parse Codex JSONL event")?;
        if event.get("type").and_then(Value::as_str) != Some("item.completed") {
            continue;
        }
        let Some(item) = event.get("item").and_then(Value::as_object) else {
            continue;
        };
        let tool = item
            .get("tool")
            .or_else(|| item.get("name"))
            .and_then(Value::as_str);
        let exact_tool = matches!(
            tool,
            Some("eliot_task_action_request" | "mcp__eliot-governor__eliot_task_action_request")
        );
        let exact_server = item
            .get("server")
            .and_then(Value::as_str)
            .is_none_or(|server| server == "eliot-governor");
        let no_error = item.get("error").is_none_or(Value::is_null);
        if item.get("type").and_then(Value::as_str) == Some("mcp_tool_call")
            && exact_tool
            && exact_server
            && no_error
        {
            let raw_arguments = item
                .get("arguments")
                .or_else(|| item.get("input"))
                .context("completed task action MCP event omitted arguments")?;
            let arguments = match raw_arguments {
                Value::String(serialized) => serde_json::from_str(serialized)
                    .context("parse serialized task action MCP arguments")?,
                Value::Object(_) => raw_arguments.clone(),
                _ => bail!("completed task action MCP event has invalid arguments"),
            };
            let write_id = arguments
                .get("write_id")
                .and_then(Value::as_str)
                .context("completed task action MCP event omitted write_id")?;
            let write_id = WriteId::from_str(write_id)
                .context("parse completed task action MCP event write_id")?;
            if !write_ids.contains(&write_id) {
                write_ids.push(write_id);
            }
        }
    }
    Ok(write_ids)
}

fn codex_executable_identity(path: &Path) -> Result<CodexExecutableIdentity> {
    let output = Command::new(path)
        .arg("--version")
        .output()
        .context("query installed Codex CLI version")?;
    if !output.status.success() {
        bail!("installed Codex CLI version probe failed");
    }
    let version = String::from_utf8(output.stdout)
        .context("Codex CLI version output is not UTF-8")?
        .trim()
        .to_owned();
    if version.is_empty() {
        bail!("installed Codex CLI returned an empty version");
    }
    let mut file = File::open(path).context("open installed Codex CLI for hashing")?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(CodexExecutableIdentity {
        path: path.to_path_buf(),
        version,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) async fn status(root: &Path) -> Result<()> {
    let root = validate_existing_root(root)?;
    let manifest = read_manifest(&root)?;
    validate_manifest_binding(&root, &manifest)?;
    let config = load_config(&manifest.config_path)?;
    let db_ready = SurrealServerSupervisor::new(config.db.surreal)
        .status()
        .await
        .unwrap_or(false);
    let children = manifest
        .children
        .iter()
        .map(|child| {
            json!({
                "role": child.role,
                "pid": child.pid,
                "executable": child.executable,
                "identity_matches": owned_child_is_running(child)
            })
        })
        .collect::<Vec<_>>();
    let daemon_ready = manifest
        .children
        .iter()
        .find(|child| child.role == "governor-daemon")
        .is_some_and(owned_child_is_running)
        && root.join("runtime").join("ipc-auth.json").is_file();
    write_json(&json!({
        "component": "dogfood_status",
        "state": manifest.state,
        "daemon_health": if daemon_ready { "ready" } else { "not_ready" },
        "db_health": if db_ready { "ready" } else { "not_ready" },
        "children": children
    }))
}

pub(crate) async fn doctor(root: &Path) -> Result<()> {
    let root = validate_existing_root(root)?;
    let manifest = read_manifest(&root)?;
    validate_manifest_binding(&root, &manifest)?;
    let config = load_config(&manifest.config_path)?;
    let pin = read_surreal_artifact_lock(&manifest.project_root).and_then(|lock| {
        validate_surreal_artifact(Path::new(&config.db.surreal.exe), &lock, Some(&root))
    });
    let status = machine_status(&root, &manifest, &config).await;
    let codex_config = root.join("codex").join("config.toml");
    let codex_config_ok = codex_config.is_file()
        && fs::read_to_string(&codex_config).is_ok_and(|text| {
            text.contains("[mcp_servers.eliot-governor]")
                && text.contains("required = true")
                && !text.contains("SURREAL_PASS")
                && !text.contains("SURREAL_USER")
        });
    let acl_ok = restricted_acl_status(&root);
    let token_present = root.join("runtime").join("ipc-auth.json").is_file();
    let mut blockers = Vec::new();
    if !codex_config_ok {
        blockers.push("project_codex_config_invalid");
    }
    if !acl_ok {
        blockers.push("runtime_root_acl_not_restricted");
    }
    if status.daemon_ready && !token_present {
        blockers.push("authenticated_ipc_token_missing");
    }
    if !manifest.provider_kill_switch {
        blockers.push("provider_kill_switch_disabled");
    }
    if !status.db_ready {
        blockers.push("db_not_ready");
    }
    if !status.daemon_ready {
        blockers.push("daemon_not_ready");
        blockers.push("schema_not_ready_before_daemon_ready");
    }
    if pin.is_err() {
        blockers.push("surrealdb_pin_invalid");
    }
    blockers.sort_unstable();
    blockers.dedup();
    let overall = if blockers.is_empty() {
        "READY"
    } else {
        "BLOCKED"
    };
    let report = json!({
        "component": "dogfood_doctor",
        "status": overall,
        "governor_binary": manifest.governor_binary,
        "protocol_version": IPC_PROTOCOL_VERSION,
        "codex_cli_version": find_codex_cli().map_or(Value::Null, |path| command_version(path, &["--version"])),
        "surrealdb_version": pin.as_ref().map_or(Value::Null, |identity| json!(identity.version)),
        "surrealdb_identity": pin.as_ref().map_or(Value::Null, |identity| json!(identity)),
        "project_root": manifest.project_root,
        "runtime_root": root,
        "runtime_root_safe": acl_ok,
        "pipe_name": pipe_name(&manifest.config_path),
        "pipe_acl_status": if acl_ok { "current_user_and_system_only" } else { "unverified" },
        "token_file_status": if token_present && acl_ok { "present_restricted" } else if token_present { "present_acl_unverified" } else { "absent" },
        "daemon_health": if status.daemon_ready { "ready" } else { "not_ready" },
        "db_health": if status.db_ready { "ready" } else { "not_ready" },
        "schema_health": if status.daemon_ready { "ready" } else { "blocked_by_daemon" },
        "surrealdb_pin_status": if pin.is_ok() { "valid" } else { "invalid" },
        "schema_version": SCHEMA_VERSION,
        "codex_integration_model": "project_mcp_with_native_plugin_available",
        "project_codex_config_status": if codex_config_ok { "valid_disposable_config" } else { "invalid" },
        "provider_kill_switch": manifest.provider_kill_switch,
        "antigravity_ledger_count": antigravity_ledger_count(&manifest.project_root),
        "blockers": blockers,
        "warnings": if status.daemon_ready { Vec::<String>::new() } else { vec!["runtime_not_started".to_owned()] }
    });
    fs::create_dir_all(root.join("reports").join("dogfood"))?;
    fs::write(
        root.join("reports").join("dogfood").join("doctor.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    write_json(&report)?;
    if overall == "BLOCKED" {
        bail!("dogfood doctor BLOCKED")
    }
    Ok(())
}

pub(crate) async fn stop(root: &Path) -> Result<()> {
    let root = validate_existing_root(root)?;
    let mut manifest = read_manifest(&root)?;
    validate_manifest_binding(&root, &manifest)?;
    let config = load_config(&manifest.config_path)?;

    if let Some(daemon) = manifest
        .children
        .iter()
        .find(|child| child.role == "governor-daemon")
    {
        verify_recorded_identity_or_absent(daemon)?;
        if read_pid(&root.join("runtime").join("daemon.pid")).is_some_and(|pid| pid != daemon.pid) {
            bail!("daemon PID file does not match the recorded owned child");
        }
        fs::write(
            root.join("runtime").join("stop.requested"),
            "dogfood stop\n",
        )?;
        if !wait_until(Duration::from_secs(10), || !process_exists(daemon.pid)) {
            verify_recorded_identity_or_absent(daemon)?;
            if process_exists(daemon.pid) {
                stop_exact_pid(daemon.pid)?;
            }
        }
    }

    if let Some(db) = manifest
        .children
        .iter()
        .find(|child| child.role == "surrealdb")
    {
        verify_recorded_identity_or_absent(db)?;
        if process_exists(db.pid) {
            if read_pid(&root.join("tmp").join("surreal.pid")) != Some(db.pid) {
                bail!("SurrealDB PID file does not match the recorded owned child");
            }
            let _ = SurrealServerSupervisor::new(config.db.surreal)
                .stop()
                .await?;
        }
    }
    let all_stopped = wait_until(Duration::from_secs(10), || {
        manifest
            .children
            .iter()
            .all(|child| !process_exists(child.pid))
    });
    if !all_stopped {
        bail!("one or more recorded dogfood child processes did not stop");
    }
    let _ = fs::remove_file(root.join("runtime").join("ipc-auth.json"));
    manifest.children.clear();
    "stopped".clone_into(&mut manifest.state);
    write_manifest(&root, &manifest)?;
    write_json(
        &json!({"component": "dogfood_stop", "status": "stopped", "owned_children_remaining": 0}),
    )
}

struct MachineStatus {
    daemon_ready: bool,
    db_ready: bool,
}

fn runtime_publication_marker_ready(root: &Path, expected_pid: u32) -> bool {
    let publication = fs::read(root.join("runtime").join("publication.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let expected_auth = root.join("runtime").join("ipc-auth.json");
    publication.is_some_and(|publication| {
        publication.get("state").and_then(Value::as_str) == Some("ready")
            && publication.get("protocol_version").and_then(Value::as_str)
                == Some(IPC_PROTOCOL_VERSION)
            && publication.get("daemon_pid").and_then(Value::as_u64)
                == Some(u64::from(expected_pid))
            && publication
                .get("publication_root")
                .and_then(Value::as_str)
                .is_some_and(|path| path_eq_case_insensitive(Path::new(path), root))
            && publication
                .get("auth_ref")
                .and_then(Value::as_str)
                .is_some_and(|path| path_eq_case_insensitive(Path::new(path), &expected_auth))
            && expected_auth.is_file()
    })
}

fn runtime_publication_is_ready(manifest: &DogfoodManifest) -> bool {
    let Some(daemon) = manifest
        .children
        .iter()
        .find(|child| child.role == "governor-daemon")
    else {
        return false;
    };
    if !owned_child_is_running(daemon) {
        return false;
    }
    RuntimeInstance::select(&manifest.config_path, None)
        .ok()
        .and_then(|instance| instance.read_publication(IPC_PROTOCOL_VERSION).ok())
        .is_some_and(|publication| {
            publication.daemon_pid == daemon.pid && publication.auth_ref.is_file()
        })
}

async fn machine_status(
    root: &Path,
    manifest: &DogfoodManifest,
    config: &GovernorConfig,
) -> MachineStatus {
    let daemon_ready = runtime_publication_marker_ready(
        root,
        manifest
            .children
            .iter()
            .find(|child| child.role == "governor-daemon")
            .map_or(0, |child| child.pid),
    ) && runtime_publication_is_ready(manifest);
    let db_ready = SurrealServerSupervisor::new(config.db.surreal.clone())
        .status()
        .await
        .unwrap_or(false);
    MachineStatus {
        daemon_ready,
        db_ready,
    }
}

fn validate_explicit_safe_root(root: &Path) -> Result<PathBuf> {
    if !root.is_absolute() {
        bail!("dogfood runtime root must be explicit and absolute");
    }
    let forbidden_component = root.components().any(|component| {
        let component = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        component.starts_with("onedrive")
            || component == "dropbox"
            || component == "google drive"
            || component == ".git"
    });
    if forbidden_component {
        bail!("dogfood runtime root is lexically inside a forbidden sync or .git path");
    }
    let permitted = [env::var_os("LOCALAPPDATA"), env::var_os("TEMP")]
        .into_iter()
        .flatten()
        .map(PathBuf::from)
        .any(|base| {
            path_starts_with_case_insensitive(root, &base)
                || canonicalize_windows(&base).is_ok_and(|canonical_base| {
                    path_starts_with_case_insensitive(root, &canonical_base)
                })
        });
    if !permitted {
        bail!("dogfood runtime root must descend from LOCALAPPDATA or TEMP");
    }
    Ok(root.to_path_buf())
}

fn read_surreal_artifact_lock(project: &Path) -> Result<SurrealArtifactLock> {
    let path = project
        .join("docs")
        .join("release")
        .join("SURREALDB_WINDOWS_X64.lock.json");
    let lock: SurrealArtifactLock = serde_json::from_slice(
        &fs::read(&path)
            .with_context(|| format!("read SurrealDB release lock {}", path.display()))?,
    )
    .with_context(|| format!("parse SurrealDB release lock {}", path.display()))?;
    if lock.schema != "eliot-external-release-artifact-lock-v1"
        || lock.artifact != "surreal.exe"
        || lock.architecture != "windows-x64"
        || lock.sha256.len() != 64
        || !lock.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        || lock.pe_machine.len() != 4
        || !lock.pe_machine.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("SurrealDB release lock has an invalid artifact identity");
    }
    Ok(lock)
}

fn validate_surreal_preseed(path: &Path, lock: &SurrealArtifactLock) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("operator-preseeded surreal.exe path must be absolute");
    }
    let canonical = canonicalize_regular_non_reparse(path, "operator-preseeded surreal.exe")?;
    if !canonical
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("surreal.exe"))
    {
        bail!("operator-preseeded path must name surreal.exe");
    }
    validate_surreal_artifact(&canonical, lock, None)?;
    Ok(canonical)
}

fn validate_surreal_artifact(
    path: &Path,
    lock: &SurrealArtifactLock,
    runtime_root: Option<&Path>,
) -> Result<SurrealArtifactIdentity> {
    let canonical = canonicalize_regular_non_reparse(path, "SurrealDB executable")?;
    if !canonical
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("surreal.exe"))
    {
        bail!("SurrealDB executable path must name surreal.exe");
    }
    if let Some(root) = runtime_root {
        let expected = canonicalize_windows(&root.join("runtime").join("bin").join("surreal.exe"))
            .context("canonicalize owned dogfood SurrealDB executable")?;
        if !path_eq_case_insensitive(&canonical, &expected) {
            bail!("dogfood SurrealDB executable is not the owned runtime/bin copy");
        }
    }
    let bytes = fs::read(&canonical)
        .with_context(|| format!("read SurrealDB executable {}", canonical.display()))?;
    let observed_sha256 = format!("{:x}", Sha256::digest(&bytes));
    if observed_sha256 != lock.sha256 {
        bail!(
            "SurrealDB executable SHA-256 mismatch: expected {}, observed {}",
            lock.sha256,
            observed_sha256
        );
    }
    let observed_machine = pe_machine(&bytes)?;
    if !observed_machine.eq_ignore_ascii_case(&lock.pe_machine) {
        bail!(
            "SurrealDB PE machine mismatch: expected {}, observed {}",
            lock.pe_machine,
            observed_machine
        );
    }
    let version = Command::new(&canonical)
        .arg("version")
        .output()
        .with_context(|| format!("run surreal version for {}", canonical.display()))?;
    if !version.status.success() {
        bail!("surreal version exited unsuccessfully");
    }
    let version_text = String::from_utf8_lossy(&version.stdout);
    let observed_version = parse_surreal_version(&version_text)?;
    if observed_version != lock.version {
        bail!(
            "SurrealDB version mismatch: expected {}, observed {}",
            lock.version,
            observed_version
        );
    }
    Ok(SurrealArtifactIdentity {
        path: canonical,
        version: observed_version,
        sha256: observed_sha256,
        pe_machine: observed_machine,
    })
}

fn parse_surreal_version(output: &str) -> Result<String> {
    let version = output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .and_then(|line| line.split_whitespace().next())
        .filter(|token| {
            let mut components = token.split('.');
            components.clone().count() == 3
                && components.all(|component| {
                    !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
                })
        })
        .ok_or_else(|| {
            anyhow::anyhow!("surreal version output did not contain a semantic version")
        })?;
    Ok(version.to_owned())
}

fn canonicalize_regular_non_reparse(path: &Path, label: &str) -> Result<PathBuf> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if let Ok(metadata) = fs::symlink_metadata(&current)
            && is_reparse_point(&metadata)
        {
            bail!(
                "{label} path contains a reparse point: {}",
                current.display()
            );
        }
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} at {}", path.display()))?;
    if !metadata.file_type().is_file() || is_reparse_point(&metadata) {
        bail!(
            "{label} must be a regular non-reparse file: {}",
            path.display()
        );
    }
    let canonical = canonicalize_windows(path)
        .with_context(|| format!("canonicalize {label} at {}", path.display()))?;
    let canonical_metadata = fs::symlink_metadata(&canonical)?;
    if !canonical_metadata.file_type().is_file() || is_reparse_point(&canonical_metadata) {
        bail!("canonical {label} is not a regular non-reparse file");
    }
    Ok(canonical)
}

fn canonicalize_directory_non_reparse(path: &Path, label: &str) -> Result<PathBuf> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if let Ok(metadata) = fs::symlink_metadata(&current)
            && (metadata.file_type().is_symlink() || is_reparse_point(&metadata))
        {
            bail!(
                "{label} path contains a reparse point: {}",
                current.display()
            );
        }
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} at {}", path.display()))?;
    if !metadata.file_type().is_dir() || is_reparse_point(&metadata) {
        bail!(
            "{label} must be a directory without reparse points: {}",
            path.display()
        );
    }
    let canonical = canonicalize_windows(path)
        .with_context(|| format!("canonicalize {label} at {}", path.display()))?;
    let canonical_metadata = fs::symlink_metadata(&canonical)?;
    if !canonical_metadata.file_type().is_dir() || is_reparse_point(&canonical_metadata) {
        bail!("canonical {label} is not a plain directory");
    }
    Ok(canonical)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(windows))]
const fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn pe_machine(bytes: &[u8]) -> Result<String> {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        bail!("SurrealDB executable is not a PE image");
    }
    let pe_offset = u32::from_le_bytes(
        bytes[0x3c..0x40]
            .try_into()
            .context("read the PE header offset")?,
    ) as usize;
    if pe_offset.checked_add(6).is_none_or(|end| end > bytes.len())
        || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0"
    {
        bail!("SurrealDB executable has an invalid PE header");
    }
    let machine = u16::from_le_bytes(
        bytes[pe_offset + 4..pe_offset + 6]
            .try_into()
            .context("read the PE machine field")?,
    );
    Ok(format!("{machine:04X}"))
}

fn validate_existing_root(root: &Path) -> Result<PathBuf> {
    let safe = validate_explicit_safe_root(root)?;
    let canonical = canonicalize_windows(&safe)
        .with_context(|| format!("canonicalize initialized dogfood root {}", safe.display()))?;
    validate_explicit_safe_root(&canonical)
}

fn canonical_git_root(project: &Path) -> Result<PathBuf> {
    let canonical = canonicalize_windows(project)
        .with_context(|| format!("canonicalize project root {}", project.display()))?;
    let output = Command::new("git.exe")
        .arg("-C")
        .arg(&canonical)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("resolve exact Git project root")?;
    if !output.status.success() {
        bail!("project is not a Git worktree");
    }
    let reported = canonicalize_windows(Path::new(String::from_utf8(output.stdout)?.trim()))?;
    if reported != canonical {
        bail!("--project must name the exact Git worktree root");
    }
    Ok(canonical)
}

fn validate_manifest_binding(root: &Path, manifest: &DogfoodManifest) -> Result<()> {
    if manifest.manifest_version != MANIFEST_VERSION || manifest.runtime_root != root {
        bail!("dogfood manifest is not bound to the selected canonical runtime root");
    }
    if !manifest.config_path.starts_with(root) {
        bail!("dogfood config escaped the owned runtime root");
    }
    Ok(())
}

fn create_new_safe_directory(destination: &Path, source: &Path) -> Result<PathBuf> {
    validate_explicit_safe_root(destination)?;
    if destination
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        bail!("dogfood Codex worktree path must not contain dot traversal");
    }
    if destination.exists() {
        bail!("dogfood Codex worktree destination must not already exist");
    }
    let parent = destination
        .parent()
        .context("dogfood Codex worktree destination has no parent")?;
    fs::create_dir_all(parent)?;
    let parent = validate_explicit_safe_root(&canonicalize_directory_non_reparse(
        parent,
        "dogfood Codex worktree parent",
    )?)?;
    let file_name = destination
        .file_name()
        .context("dogfood Codex worktree destination has no final component")?;
    let destination = parent.join(file_name);
    validate_explicit_safe_root(&destination)?;
    if path_starts_with_case_insensitive(&destination, source)
        || path_starts_with_case_insensitive(source, &destination)
    {
        bail!("dogfood Codex worktree and source repository must not contain one another");
    }
    fs::create_dir(&destination)?;
    let canonical =
        canonicalize_directory_non_reparse(&destination, "new dogfood Codex worktree directory")?;
    if !path_eq_case_insensitive(&canonical, &destination) {
        let _ = fs::remove_dir(&destination);
        bail!("dogfood Codex worktree canonical path differs from the requested path");
    }
    Ok(canonical)
}

fn git_success(cwd: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .with_context(|| format!("run git {} in {}", args.join(" "), cwd.display()))?;
    if !output.status.success() {
        bail!(
            "git {} failed in {}: {}",
            args.join(" "),
            cwd.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn git_stdout(cwd: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .with_context(|| format!("run git {} in {}", args.join(" "), cwd.display()))?;
    if !output.status.success() {
        bail!(
            "git {} failed in {}: {}",
            args.join(" "),
            cwd.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn codex_hooks(governor_binary: &Path, config_path: &Path) -> Value {
    fn handler(governor_binary: &Path, config_path: &Path, event: &str) -> Value {
        let command = codex_hook_command(governor_binary, config_path, event);
        json!({
            "type": "command",
            "command": command,
            "commandWindows": command
        })
    }

    json!({
        "hooks": {
            "SessionStart": [{
                "hooks": [handler(governor_binary, config_path, "session-start")]
            }],
            "UserPromptSubmit": [{
                "hooks": [handler(governor_binary, config_path, "user-prompt-submit")]
            }],
            "PreToolUse": [{
                "matcher": "^mcp__eliot-governor__.*$",
                "hooks": [handler(governor_binary, config_path, "pre-tool-use")]
            }],
            "PostToolUse": [{
                "matcher": ".*",
                "hooks": [handler(governor_binary, config_path, "post-tool-use")]
            }],
            "Stop": [{
                "hooks": [handler(governor_binary, config_path, "stop")]
            }]
        }
    })
}

fn codex_hook_command(governor_binary: &Path, config_path: &Path, event: &str) -> String {
    format!(
        "\"{}\" --config \"{}\" hook {event}",
        governor_binary.display(),
        config_path.display()
    )
}

fn codex_hook_override(
    name: &str,
    event: &str,
    matcher: Option<&str>,
    governor_binary: &Path,
    governor_config: &Path,
) -> Result<String> {
    let command =
        serde_json::to_string(&codex_hook_command(governor_binary, governor_config, event))?;
    let matcher = if let Some(matcher) = matcher {
        format!("matcher = {}, ", serde_json::to_string(matcher)?)
    } else {
        String::new()
    };
    Ok(format!(
        "hooks.{name}=[{{ {matcher}hooks = [{{ type = \"command\", command = {command}, commandWindows = {command} }}] }}]"
    ))
}

fn codex_config_overrides(
    governor_binary: &Path,
    governor_config: &Path,
    worktree: &Path,
) -> Result<Vec<String>> {
    let command = serde_json::to_string(&slash(governor_binary))?;
    let cwd = serde_json::to_string(&slash(worktree))?;
    let args = serde_json::to_string(&vec![
        "--config".to_owned(),
        slash(governor_config),
        "mcp".to_owned(),
        "stdio".to_owned(),
        "--profile".to_owned(),
        "codex_controller".to_owned(),
        "--host".to_owned(),
        "codex".to_owned(),
    ])?;
    let enabled_tools = serde_json::to_string(DOGFOOD_CODEX_ENABLED_TOOLS)?;
    let shell_excluded_environment = serde_json::to_string(&[
        "ELIOT_AGENT_SESSION_ID",
        "ELIOT_CODEX_SCOPE_TOKEN",
        "ELIOT_PROJECT_ID",
        "ELIOT_TASK_ID",
    ])?;
    let mcp_scope_environment = serde_json::to_string(&["ELIOT_CODEX_SCOPE_TOKEN"])?;
    let mcp_servers = format!(
        "mcp_servers={{ \"eliot-governor\" = {{ command = {command}, args = {args}, cwd = {cwd}, env = {{ ELIOT_DISABLE_REAL_PROVIDER = \"1\" }}, env_vars = {mcp_scope_environment}, enabled = true, required = true, enabled_tools = {enabled_tools}, startup_timeout_sec = 20, tool_timeout_sec = 120, default_tools_approval_mode = \"approve\" }} }}"
    );
    let mut overrides = vec![
        "features.hooks=true".to_owned(),
        "approval_policy=\"never\"".to_owned(),
        "default_permissions=\":workspace\"".to_owned(),
        "permissions={}".to_owned(),
        "windows.sandbox=\"elevated\"".to_owned(),
        "shell_environment_policy.inherit=\"core\"".to_owned(),
        format!("shell_environment_policy.exclude={shell_excluded_environment}"),
        "web_search=\"disabled\"".to_owned(),
        mcp_servers,
    ];
    for (name, event, matcher) in [
        ("SessionStart", "session-start", None),
        ("UserPromptSubmit", "user-prompt-submit", None),
        (
            "PreToolUse",
            "pre-tool-use",
            Some("^mcp__eliot-governor__.*$"),
        ),
        ("PostToolUse", "post-tool-use", Some(".*")),
        ("Stop", "stop", None),
    ] {
        overrides.push(codex_hook_override(
            name,
            event,
            matcher,
            governor_binary,
            governor_config,
        )?);
    }
    Ok(overrides)
}

fn codex_exec_plan(
    root: &Path,
    worktree: &Path,
    config_overrides: &[String],
) -> Result<CodexExecPlan> {
    let live_report_dir = root.join("reports").join("live-codex");
    fs::create_dir_all(&live_report_dir)?;
    let output_schema_path = live_report_dir.join("output-schema.json");
    let output_last_message_path = live_report_dir.join("last-message.json");
    let prompt_source_path = live_report_dir.join("prompt.md");
    let jsonl_stdout_path = live_report_dir.join("events.jsonl");
    let mut argv_without_prompt = vec![
        "--strict-config".to_owned(),
        "exec".to_owned(),
        "--cd".to_owned(),
        slash(worktree),
        "--ignore-user-config".to_owned(),
        "--ignore-rules".to_owned(),
        "--dangerously-bypass-hook-trust".to_owned(),
        "--json".to_owned(),
        "--output-schema".to_owned(),
        slash(&output_schema_path),
        "--output-last-message".to_owned(),
        slash(&output_last_message_path),
    ];
    for config_override in config_overrides {
        argv_without_prompt.push("-c".to_owned());
        argv_without_prompt.push(config_override.clone());
    }
    Ok(CodexExecPlan {
        argv_without_prompt,
        prompt_source_path,
        output_schema_path,
        output_last_message_path,
        jsonl_stdout_path,
    })
}

fn validate_codex_launch_report(
    root: &Path,
    manifest: &DogfoodManifest,
) -> Result<ValidatedCodexLaunch> {
    let report_path = root
        .join("reports")
        .join("dogfood")
        .join("codex-worktree.json");
    require_regular_file(&report_path, "prepared Codex launch report")?;
    let report: Value = serde_json::from_slice(&fs::read(&report_path)?)
        .context("parse prepared Codex launch report")?;
    require_report_value(
        &report,
        "component",
        &Value::String("dogfood_prepare_worktree".to_owned()),
    )?;
    require_report_value(&report, "status", &Value::String("prepared".to_owned()))?;
    require_report_value(&report, "runtime_root", &json!(root))?;
    require_report_value(&report, "source_repository", &json!(&manifest.project_root))?;
    require_report_value(&report, "provider_kill_switch", &Value::Bool(true))?;
    require_report_value(&report, "independent_git_metadata", &Value::Bool(true))?;
    require_report_value(&report, "git_metadata_within_worktree", &Value::Bool(true))?;
    require_report_value(&report, "borrowed_object_database", &Value::Bool(false))?;
    require_report_value(&report, "global_codex_config_mutated", &Value::Bool(false))?;
    require_report_value(&report, "source_repository_mutated", &Value::Bool(false))?;

    let (worktree, branch, commit) = validate_codex_worktree_binding(&report, manifest)?;
    validate_codex_hooks(&report, root, manifest)?;
    let plan = validate_codex_plan(&report, root, manifest, &worktree)?;

    Ok(ValidatedCodexLaunch {
        worktree,
        branch,
        commit,
        plan,
    })
}

pub(crate) fn prepared_worktree_adoption(
    root: &Path,
    expected_config_path: &Path,
) -> Result<PreparedDogfoodWorktreeBinding> {
    let root = validate_existing_root(root)?;
    let manifest = read_manifest(&root)?;
    validate_manifest_binding(&root, &manifest)?;
    let expected_config_path = canonicalize_windows(expected_config_path)?;
    let manifest_config_path = canonicalize_windows(&manifest.config_path)?;
    if !path_eq_case_insensitive(&expected_config_path, &manifest_config_path) {
        bail!("dogfood worktree adoption config differs from the runtime manifest");
    }
    let launch = validate_codex_launch_report(&root, &manifest)?;
    let managed_root = canonicalize_directory_non_reparse(
        &root.join("worktrees"),
        "dogfood managed worktree root",
    )?;
    if launch.worktree.parent() != Some(managed_root.as_path()) {
        bail!("prepared Codex worktree is outside the dogfood managed worktree root");
    }
    Ok(PreparedDogfoodWorktreeBinding {
        worktree: launch.worktree,
        branch: launch.branch,
        commit: launch.commit,
        managed_root,
    })
}

fn validate_codex_worktree_binding(
    report: &Value,
    manifest: &DogfoodManifest,
) -> Result<(PathBuf, String, String)> {
    let reported_worktree = report_path_value(report, "worktree_root")?;
    validate_explicit_safe_root(&reported_worktree)?;
    let worktree = canonicalize_directory_non_reparse(
        &canonical_git_root(&reported_worktree)?,
        "prepared Codex worktree",
    )?;
    if !path_eq_case_insensitive(&worktree, &reported_worktree)
        || path_starts_with_case_insensitive(&worktree, &manifest.project_root)
        || path_starts_with_case_insensitive(&manifest.project_root, &worktree)
    {
        bail!("prepared Codex report is not bound to the exact independent worktree");
    }
    let git_dir =
        canonicalize_directory_non_reparse(&worktree.join(".git"), "prepared Codex Git metadata")?;
    if !git_dir.is_dir()
        || !path_starts_with_case_insensitive(&git_dir, &worktree)
        || git_dir
            .join("objects")
            .join("info")
            .join("alternates")
            .exists()
    {
        bail!("prepared Codex worktree no longer owns independent Git metadata");
    }
    require_report_value(report, "git_metadata_root", &json!(&git_dir))?;

    let branch = report_string(report, "branch")?.to_owned();
    let commit = report_string(report, "commit")?.to_owned();
    if commit.len() != 40
        || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        || git_stdout(&worktree, &["branch", "--show-current"])? != branch
        || !git_stdout(&worktree, &["rev-parse", "HEAD"])?.eq_ignore_ascii_case(&commit)
    {
        bail!("prepared Codex report branch or baseline commit no longer matches the worktree");
    }
    require_report_value(report, "bounded_write_roots", &json!([&worktree]))?;
    Ok((worktree, branch, commit))
}

fn validate_codex_hooks(report: &Value, root: &Path, manifest: &DogfoodManifest) -> Result<()> {
    let hooks_path = root
        .join("reports")
        .join("dogfood")
        .join("codex-hooks.json");
    require_report_value(report, "hooks_path", &json!(&hooks_path))?;
    require_regular_file(&hooks_path, "prepared Codex hooks artifact")?;
    let hooks_bytes = fs::read(&hooks_path)?;
    if hooks_bytes
        != serde_json::to_vec_pretty(&codex_hooks(
            &manifest.governor_binary,
            &manifest.config_path,
        ))?
    {
        bail!("prepared Codex hooks artifact differs from daemon-recomputed hooks");
    }
    require_report_value(
        report,
        "hooks_blake3",
        &Value::String(blake3::hash(&hooks_bytes).to_hex().to_string()),
    )?;
    Ok(())
}

fn validate_codex_plan(
    report: &Value,
    root: &Path,
    manifest: &DogfoodManifest,
    worktree: &Path,
) -> Result<CodexExecPlan> {
    let config_overrides =
        codex_config_overrides(&manifest.governor_binary, &manifest.config_path, worktree)?;
    require_report_value(report, "codex_config_overrides", &json!(&config_overrides))?;
    let plan = codex_exec_plan(root, worktree, &config_overrides)?;
    require_report_value(
        report,
        "codex_exec_command",
        &Value::String("codex".to_owned()),
    )?;
    require_report_value(
        report,
        "codex_exec_argv_without_prompt",
        &json!(&plan.argv_without_prompt),
    )?;
    for (key, expected) in [
        ("codex_prompt_source_path", &plan.prompt_source_path),
        ("codex_output_schema_path", &plan.output_schema_path),
        (
            "codex_output_last_message_path",
            &plan.output_last_message_path,
        ),
        ("codex_jsonl_stdout_path", &plan.jsonl_stdout_path),
    ] {
        require_report_value(report, key, &json!(expected))?;
    }
    for key in [
        "codex_prompt_via_stdin_required",
        "codex_prompt_generated_from_task_contract",
        "codex_output_schema_generated_from_task_contract",
        "codex_jsonl_stdout_redirection_required",
        "codex_ignore_user_config_required",
        "codex_hook_trust_bypass_required",
        "codex_scope_environment_only",
    ] {
        require_report_value(report, key, &Value::Bool(true))?;
    }
    for key in [
        "codex_project_trust_required",
        "codex_project_config_loaded",
        "codex_home_relocation_required",
        "codex_role_lease_in_argv",
    ] {
        require_report_value(report, key, &Value::Bool(false))?;
    }
    require_report_value(
        report,
        "codex_config_precedence",
        &Value::String("cli_overrides".to_owned()),
    )?;
    require_report_value(
        report,
        "hooks_source",
        &Value::String("cli_inline_from_hashed_artifact".to_owned()),
    )?;
    Ok(plan)
}

fn report_string<'a>(report: &'a Value, key: &str) -> Result<&'a str> {
    report
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("prepared Codex report is missing string field {key}"))
}

fn report_path_value(report: &Value, key: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(report_string(report, key)?))
}

fn require_report_value(report: &Value, key: &str, expected: &Value) -> Result<()> {
    if report.get(key) != Some(expected) {
        bail!("prepared Codex report field {key} differs from the bound launch contract");
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect required {label} at {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!(
            "required {label} is not an existing regular file: {}",
            path.display()
        );
    }
    Ok(())
}

fn require_safe_optional_output(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => bail!("planned {label} is not a regular file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect planned {label}")),
    }
}

fn write_json_file_atomic(path: &Path, value: &Value) -> Result<()> {
    let temp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    fs::write(&temp, serde_json::to_vec_pretty(value)?)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temp, path)?;
    Ok(())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("dogfood-manifest.json")
}

fn read_manifest(root: &Path) -> Result<DogfoodManifest> {
    Ok(serde_json::from_slice(&fs::read(manifest_path(root))?)?)
}

fn write_manifest(root: &Path, manifest: &DogfoodManifest) -> Result<()> {
    let path = manifest_path(root);
    let temp = path.with_extension("json.tmp");
    fs::write(&temp, serde_json::to_vec_pretty(manifest)?)?;
    fs::rename(temp, path)?;
    Ok(())
}

fn write_codex_config(root: &Path, binary: &Path, governor_config: &Path) -> Result<()> {
    let text = format!(
        "[mcp_servers.eliot-governor]\ncommand = {binary:?}\nargs = [\"--config\", {config:?}, \"mcp\", \"stdio\"]\nenabled = true\nrequired = true\nstartup_timeout_sec = 30\ntool_timeout_sec = 120\n\n[mcp_servers.eliot-governor.env]\nELIOT_DISABLE_REAL_PROVIDER = \"1\"\n",
        binary = slash(binary),
        config = slash(governor_config)
    );
    fs::write(root.join("codex").join("config.toml"), text)?;
    Ok(())
}

fn reserve_loopback_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn append_log(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().create(true).append(true).open(path)?)
}

fn spawn_daemon(root: &Path, manifest: &DogfoodManifest) -> Result<std::process::Child> {
    let stdout = append_log(&root.join("logs").join("governor-daemon.jsonl"))?;
    let stderr = stdout.try_clone()?;
    let mut command = Command::new(&manifest.governor_binary);
    command
        .arg("--config")
        .arg(&manifest.config_path)
        .args(["daemon", "run"])
        .env(PROVIDER_KILL_SWITCH, "1")
        .env_remove("SURREAL_USER")
        .env_remove("SURREAL_PASS")
        .env_remove("ELIOT_TEST_SURREAL_PASSWORD_FILE")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    command
        .spawn()
        .context("start owned dogfood governor daemon")
}

fn read_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn owned_child_is_running(child: &OwnedChild) -> bool {
    let Some(actual) = process_executable(child.pid) else {
        return false;
    };
    let expected =
        canonicalize_windows(&child.executable).unwrap_or_else(|_| child.executable.clone());
    let actual = canonicalize_windows(&actual).unwrap_or(actual);
    path_eq_case_insensitive(&actual, &expected)
}

fn verify_recorded_identity_or_absent(child: &OwnedChild) -> Result<()> {
    if !process_exists(child.pid) {
        return Ok(());
    }
    if !owned_child_is_running(child) {
        bail!(
            "recorded PID {} no longer belongs to the recorded {} executable",
            child.pid,
            child.role
        );
    }
    Ok(())
}

fn process_exists(pid: u32) -> bool {
    process_executable(pid).is_some()
}

fn process_executable(pid: u32) -> Option<PathBuf> {
    let script = format!("(Get-Process -Id {pid} -ErrorAction SilentlyContinue).Path");
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

fn stop_exact_pid(pid: u32) -> Result<()> {
    let status = Command::new("taskkill.exe")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .status()
        .context("stop exact recorded dogfood PID")?;
    if !status.success() {
        bail!("taskkill failed for exact recorded PID {pid}");
    }
    Ok(())
}

fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    predicate()
}

fn restricted_acl_status(root: &Path) -> bool {
    let output = Command::new("icacls.exe").arg(root).output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    text.contains("system:(oi)(ci)(f)")
        && !text.contains("everyone")
        && !text.contains("builtin\\users")
        && !text.contains("authenticated users")
}

fn command_version(executable: impl AsRef<std::ffi::OsStr>, args: &[&str]) -> Value {
    Command::new(executable)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map_or(Value::Null, |text| Value::String(text.trim().to_owned()))
}

pub(crate) fn find_codex_cli() -> Option<PathBuf> {
    let bin_root = PathBuf::from(env::var_os("LOCALAPPDATA")?)
        .join("OpenAI")
        .join("Codex")
        .join("bin");
    let installed = fs::read_dir(bin_root).ok().and_then(|entries| {
        entries
            .filter_map(Result::ok)
            .map(|entry| entry.path().join("codex.exe"))
            .find(|path| path.is_file())
    });
    if installed.is_some() {
        return installed;
    }
    let where_output = Command::new("where.exe").arg("codex.exe").output().ok()?;
    if where_output.status.success()
        && let Ok(text) = String::from_utf8(where_output.stdout)
        && let Some(first) = text
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.to_ascii_lowercase().contains("windowsapps"))
    {
        return Some(PathBuf::from(first));
    }
    None
}

fn antigravity_ledger_count(project: &Path) -> Value {
    let path = project
        .join(".eliot-governor")
        .join("runtime")
        .join("provider-call-ledger.json");
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.get("reservations").and_then(Value::as_array).cloned())
        .map_or(Value::Null, |reservations| {
            Value::from(
                reservations
                    .iter()
                    .filter(|reservation| {
                        !reservation
                            .get("dispatch_started_at")
                            .is_none_or(Value::is_null)
                    })
                    .count(),
            )
        })
}

fn path_starts_with_case_insensitive(path: &Path, base: &Path) -> bool {
    let path = slash(path).trim_end_matches('/').to_ascii_lowercase();
    let base = slash(base).trim_end_matches('/').to_ascii_lowercase();
    path == base || path.starts_with(&format!("{base}/"))
}

fn path_eq_case_insensitive(left: &Path, right: &Path) -> bool {
    slash(left).eq_ignore_ascii_case(&slash(right))
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn canonicalize_windows(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    let text = canonical.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return Ok(PathBuf::from(format!(r"\\{rest}")));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return Ok(PathBuf::from(rest));
    }
    Ok(canonical)
}

fn write_json(value: &Value) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value)?;
    writeln!(stdout)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn codex_launch_accepts_open_or_active_but_not_terminal_task() {
        assert!(task_status_allows_codex_launch(TaskContractStatus::Open));
        assert!(task_status_allows_codex_launch(TaskContractStatus::Active));
        assert!(!task_status_allows_codex_launch(
            TaskContractStatus::DoneVerified
        ));
    }

    #[test]
    fn codex_event_action_write_id_is_extracted_and_deduplicated() -> Result<()> {
        let write_id = "00000000-0000-0000-0000-000000000001";
        let serialized_arguments = serde_json::to_string(&json!({"write_id": write_id}))?;
        let stream = [
            json!({
                "type": "item.completed",
                "item": {
                    "type": "mcp_tool_call",
                    "server": "eliot-governor",
                    "tool": "eliot_task_action_request",
                    "arguments": {"write_id": write_id}
                }
            }),
            json!({
                "type": "item.completed",
                "item": {
                    "type": "mcp_tool_call",
                    "server": "eliot-governor",
                    "tool": "mcp__eliot-governor__eliot_task_action_request",
                    "arguments": serialized_arguments
                }
            }),
            json!({
                "type": "item.completed",
                "item": {
                    "type": "mcp_tool_call",
                    "server": "eliot-governor",
                    "tool": "eliot_task_action_request",
                    "arguments": {"write_id": "00000000-0000-0000-0000-000000000002"},
                    "error": "denied"
                }
            }),
        ]
        .into_iter()
        .map(|event| serde_json::to_string(&event))
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");

        let observed = codex_event_task_action_write_ids(stream.as_bytes())?;
        assert_eq!(observed, vec![WriteId::from_str(write_id)?]);
        Ok(())
    }

    #[test]
    fn rejects_non_explicit_and_synced_runtime_roots() {
        assert!(validate_explicit_safe_root(Path::new("relative")).is_err());
        let temp = env::temp_dir().join("OneDrive").join("run");
        assert!(validate_explicit_safe_root(&temp).is_err());
        let git = env::temp_dir().join("repo").join(".git").join("run");
        assert!(validate_explicit_safe_root(&git).is_err());
    }

    #[test]
    fn surreal_artifact_lock_supplies_content_identity_to_dogfood() -> Result<()> {
        let project = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
        let lock = read_surreal_artifact_lock(&project)?;
        assert_eq!(lock.artifact, "surreal.exe");
        assert_eq!(lock.version, "3.1.4");
        Ok(())
    }

    #[test]
    fn accepts_canonical_temp_base_when_environment_uses_an_alias() -> Result<()> {
        let canonical_temp = canonicalize_windows(&env::temp_dir())?;
        let candidate = canonical_temp.join("eliot-dogfood-canonical-base");
        assert_eq!(validate_explicit_safe_root(&candidate)?, candidate);
        Ok(())
    }

    #[test]
    fn existing_runtime_root_normalizes_an_equivalent_alias() -> Result<()> {
        let root = env::temp_dir().join(format!(
            "eliot-dogfood-root-alias-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir_all(&root)?;
        let expected = canonicalize_windows(&root)?;

        assert_eq!(validate_existing_root(&root)?, expected);

        fs::remove_dir_all(&expected)?;
        Ok(())
    }

    #[test]
    fn starting_publication_and_token_are_not_schema_ready() -> Result<()> {
        let root = env::temp_dir().join(format!(
            "eliot-dogfood-starting-publication-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let runtime = root.join("runtime");
        fs::create_dir_all(&runtime)?;
        let auth = runtime.join("ipc-auth.json");
        fs::write(&auth, b"{}")?;
        let publication_path = runtime.join("publication.json");
        let pid = std::process::id();
        let mut publication = json!({
            "state": "starting",
            "protocol_version": IPC_PROTOCOL_VERSION,
            "daemon_pid": pid,
            "publication_root": root,
            "auth_ref": auth
        });
        fs::write(&publication_path, serde_json::to_vec_pretty(&publication)?)?;
        assert!(
            !runtime_publication_marker_ready(&root, pid),
            "token plus Starting publication must not satisfy dogfood readiness"
        );

        publication["state"] = Value::String("ready".to_owned());
        fs::write(&publication_path, serde_json::to_vec_pretty(&publication)?)?;
        assert!(runtime_publication_marker_ready(&root, pid));
        assert!(!runtime_publication_marker_ready(&root, pid + 1));

        fs::remove_dir_all(&root)?;
        Ok(())
    }
}
