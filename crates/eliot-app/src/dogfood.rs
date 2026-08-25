use crate::config::load_config;
use crate::named_pipe_ipc::{
    IPC_PROTOCOL_VERSION, pipe_name, restrict_owned_directory_to_current_user,
};
use anyhow::{Context, Result, bail};
use eliot_store::SurrealServerSupervisor;
use eliot_types::{
    AgentHostId, CredentialProviderKind, GovernorConfig, ProviderDeclaredBudget,
    ProviderRoutePolicy, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::net::TcpListener;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
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
    "eliot_task_state",
    "eliot_task_action_request",
    "eliot_task_observation_record",
    "eliot_task_verification_run",
    "eliot_compile_packet_l3",
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
    argv_before_prompt: Vec<String>,
    prompt_source_path: PathBuf,
    output_schema_path: PathBuf,
    output_last_message_path: PathBuf,
    jsonl_stdout_path: PathBuf,
}

struct ValidatedCodexLaunch {
    worktree: PathBuf,
    branch: String,
    commit: String,
    plan: CodexExecPlan,
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

pub(crate) fn init(root: &Path, project: &Path) -> Result<()> {
    let root = validate_explicit_safe_root(root)?;
    if root.exists() && fs::read_dir(&root)?.next().is_some() {
        bail!("dogfood init requires an absent or empty owned runtime root");
    }
    let project = canonical_git_root(project)?;
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

    let config_path = root.join("config").join("governor.toml");
    let mut config = GovernorConfig::default();
    let port = reserve_loopback_port()?;
    config.service.instance_id = format!("dogfood-l3-{port}");
    config.db.surreal.bind = format!("127.0.0.1:{port}");
    config.db.surreal.endpoint = format!("ws://127.0.0.1:{port}/rpc");
    config.db.surreal.storage = format!("rocksdb:{}", slash(&root.join("surrealdb-rocks")));
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
        "codex_exec_argv_before_prompt": exec_plan.argv_before_prompt,
        "codex_prompt_source_path": exec_plan.prompt_source_path,
        "codex_prompt_must_be_final_argument": true,
        "codex_output_schema_path": exec_plan.output_schema_path,
        "codex_output_schema_must_exist_before_launch": true,
        "codex_output_last_message_path": exec_plan.output_last_message_path,
        "codex_jsonl_stdout_path": exec_plan.jsonl_stdout_path,
        "codex_jsonl_stdout_redirection_required": true,
        "codex_ignore_user_config_required": true,
        "codex_project_trust_required": false,
        "codex_project_config_loaded": false,
        "codex_home_relocation_required": false,
        "codex_hook_trust_bypass_required": true,
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

    let ready = wait_until(Duration::from_secs(30), || {
        root.join("runtime").join("ipc-auth.json").is_file()
            && read_pid(&root.join("runtime").join("daemon.pid")) == Some(daemon_pid)
            && manifest.children.iter().all(owned_child_is_running)
    });
    if !ready {
        let _ = stop(&root).await;
        bail!("dogfood daemon did not reach authenticated IPC readiness within 30 seconds");
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

pub(crate) async fn run_codex(root: &Path) -> Result<()> {
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
    require_regular_file(&launch.plan.prompt_source_path, "Codex prompt")?;
    require_regular_file(&launch.plan.output_schema_path, "Codex output schema")?;
    require_safe_optional_output(
        &launch.plan.output_last_message_path,
        "Codex last-message output",
    )?;
    require_safe_optional_output(&launch.plan.jsonl_stdout_path, "Codex JSONL output")?;

    let (codex, process) = run_codex_provider(&manifest, &launch).await?;
    anyhow::ensure!(
        process.worker_error.is_none() && process.reap_receipt.proves_complete_reap(),
        "Codex dogfood process cleanup failed: {:?}",
        process.worker_error
    );
    fs::write(&launch.plan.jsonl_stdout_path, &process.stdout)
        .context("write planned Codex JSONL stdout path")?;
    let stderr_path = launch.plan.jsonl_stdout_path.with_file_name("stderr.log");
    fs::write(&stderr_path, &process.stderr).context("write Codex stderr log")?;
    let child_success = process.exit_code == Some(0) && !process.timed_out;

    let result = json!({
        "component": "dogfood_run_codex",
        "status": if child_success { "completed" } else { "failed" },
        "codex_executable": codex,
        "worktree_root": launch.worktree,
        "branch": launch.branch,
        "commit": launch.commit,
        "exit_code": process.exit_code,
        "timed_out": process.timed_out,
        "reap_receipt": process.reap_receipt,
        "events_path": launch.plan.jsonl_stdout_path,
        "stderr_path": stderr_path,
        "last_message_path": launch.plan.output_last_message_path,
        "provider_kill_switch": true
    });
    let latest_path = root.join("reports").join("live-codex").join("latest.json");
    write_json_file_atomic(&latest_path, &result)?;
    write_json(&result)?;
    if !child_success {
        bail!(
            "Codex exited non-zero; launch result preserved at {}",
            latest_path.display()
        );
    }
    Ok(())
}

async fn run_codex_provider(
    manifest: &DogfoodManifest,
    launch: &ValidatedCodexLaunch,
) -> Result<(PathBuf, eliot_engine::ProviderProcessOutcome)> {
    let prompt = fs::read_to_string(&launch.plan.prompt_source_path)
        .context("read fixed Codex prompt source")?;
    let codex = find_codex_cli().context("locate installed codex.exe")?;
    let codex = canonicalize_windows(&codex).context("canonicalize installed codex.exe")?;
    if !codex.is_file()
        || !codex
            .file_name()
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("codex.exe"))
    {
        bail!("resolved Codex CLI is not an installed codex.exe regular file");
    }
    let blocked_environment = [
        "SURREAL_USER",
        "SURREAL_PASS",
        "ELIOT_TEST_SURREAL_BIND",
        "ELIOT_TEST_SURREAL_ENDPOINT",
        "ELIOT_TEST_SURREAL_PASSWORD_FILE",
        "ELIOT_TEST_SURREAL_STORAGE",
    ];
    let mut environment = std::env::vars_os()
        .filter(|(name, _)| {
            !blocked_environment
                .iter()
                .any(|blocked| name.eq_ignore_ascii_case(blocked))
        })
        .collect::<Vec<_>>();
    environment.push((PROVIDER_KILL_SWITCH.into(), "1".into()));
    let mut args = launch
        .plan
        .argv_before_prompt
        .iter()
        .map(std::ffi::OsString::from)
        .collect::<Vec<_>>();
    args.push(prompt.into());
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
            stdin_payload: None,
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
            runtime_contract_sha256: None,
            role_lease_id: None,
            role_lease_epoch: None,
        },
        &mut on_spawned,
    )
    .await
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok((codex, process))
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
    let report = json!({
        "component": "dogfood_doctor",
        "governor_binary": manifest.governor_binary,
        "protocol_version": IPC_PROTOCOL_VERSION,
        "codex_cli_version": find_codex_cli().map_or(Value::Null, |path| command_version(path, &["--version"])),
        "surrealdb_version": command_version(&config.db.surreal.exe, &["version"]),
        "project_root": manifest.project_root,
        "runtime_root": root,
        "runtime_root_safe": true,
        "pipe_name": pipe_name(&manifest.config_path),
        "pipe_acl_status": if acl_ok { "current_user_and_system_only" } else { "unverified" },
        "token_file_status": if token_present && acl_ok { "present_restricted" } else if token_present { "present_acl_unverified" } else { "absent" },
        "daemon_health": if status.daemon_ready { "ready" } else { "not_ready" },
        "db_health": if status.db_ready { "ready" } else { "not_ready" },
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
    write_json(&report)
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

async fn machine_status(
    root: &Path,
    manifest: &DogfoodManifest,
    config: &GovernorConfig,
) -> MachineStatus {
    let daemon_ready = manifest
        .children
        .iter()
        .find(|child| child.role == "governor-daemon")
        .is_some_and(owned_child_is_running)
        && root.join("runtime").join("ipc-auth.json").is_file();
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
    let parent = validate_explicit_safe_root(&canonicalize_windows(parent)?)?;
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
    let canonical = canonicalize_windows(&destination)?;
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
    ])?;
    let enabled_tools = serde_json::to_string(DOGFOOD_CODEX_ENABLED_TOOLS)?;
    let mcp_servers = format!(
        "mcp_servers={{ \"eliot-governor\" = {{ command = {command}, args = {args}, cwd = {cwd}, env = {{ ELIOT_DISABLE_REAL_PROVIDER = \"1\" }}, enabled = true, required = true, enabled_tools = {enabled_tools}, startup_timeout_sec = 20, tool_timeout_sec = 120, default_tools_approval_mode = \"approve\" }} }}"
    );
    let mut overrides = vec![
        "features.hooks=true".to_owned(),
        "approval_policy=\"never\"".to_owned(),
        "sandbox_mode=\"workspace-write\"".to_owned(),
        "sandbox_workspace_write.network_access=false".to_owned(),
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
    let mut argv_before_prompt = vec![
        "--strict-config".to_owned(),
        "--ask-for-approval".to_owned(),
        "never".to_owned(),
        "exec".to_owned(),
        "--cd".to_owned(),
        slash(worktree),
        "--sandbox".to_owned(),
        "workspace-write".to_owned(),
        "--ignore-user-config".to_owned(),
        "--dangerously-bypass-hook-trust".to_owned(),
        "--json".to_owned(),
        "--output-schema".to_owned(),
        slash(&output_schema_path),
        "--output-last-message".to_owned(),
        slash(&output_last_message_path),
    ];
    for config_override in config_overrides {
        argv_before_prompt.push("-c".to_owned());
        argv_before_prompt.push(config_override.clone());
    }
    Ok(CodexExecPlan {
        argv_before_prompt,
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

fn validate_codex_worktree_binding(
    report: &Value,
    manifest: &DogfoodManifest,
) -> Result<(PathBuf, String, String)> {
    let reported_worktree = report_path_value(report, "worktree_root")?;
    validate_explicit_safe_root(&reported_worktree)?;
    let worktree = canonical_git_root(&reported_worktree)?;
    if !path_eq_case_insensitive(&worktree, &reported_worktree)
        || path_starts_with_case_insensitive(&worktree, &manifest.project_root)
        || path_starts_with_case_insensitive(&manifest.project_root, &worktree)
    {
        bail!("prepared Codex report is not bound to the exact independent worktree");
    }
    let git_dir = canonicalize_windows(&worktree.join(".git"))?;
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
        "codex_exec_argv_before_prompt",
        &json!(&plan.argv_before_prompt),
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
        "codex_prompt_must_be_final_argument",
        "codex_output_schema_must_exist_before_launch",
        "codex_jsonl_stdout_redirection_required",
        "codex_ignore_user_config_required",
        "codex_hook_trust_bypass_required",
    ] {
        require_report_value(report, key, &Value::Bool(true))?;
    }
    for key in [
        "codex_project_trust_required",
        "codex_project_config_loaded",
        "codex_home_relocation_required",
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
mod tests {
    use super::*;

    #[test]
    fn rejects_non_explicit_and_synced_runtime_roots() {
        assert!(validate_explicit_safe_root(Path::new("relative")).is_err());
        let temp = env::temp_dir().join("OneDrive").join("run");
        assert!(validate_explicit_safe_root(&temp).is_err());
        let git = env::temp_dir().join("repo").join(".git").join("run");
        assert!(validate_explicit_safe_root(&git).is_err());
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
}
