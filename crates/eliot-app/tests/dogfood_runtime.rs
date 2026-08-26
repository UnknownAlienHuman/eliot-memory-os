use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
static COMMAND_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct OwnedRoot(PathBuf);

impl Drop for OwnedRoot {
    fn drop(&mut self) {
        if self.0.is_dir() {
            let _ = Command::new(binary())
                .args(["dogfood", "stop", "--root"])
                .arg(&self.0)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if self.0.starts_with(std::env::temp_dir()) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }
}

#[test]
#[ignore = "requires a provisioned SurrealDB executable"]
fn dogfood_runtime_starts_doctors_stops_and_restarts_persistent_state() -> TestResult {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let owned = OwnedRoot(std::env::temp_dir().join(format!(
        "eliot-dogfood-l3-test-{}-{nonce}",
        std::process::id()
    )));
    let root_arg = owned.0.to_string_lossy().into_owned();
    let project = repo_root();
    let project_arg = project.to_string_lossy().into_owned();
    let surreal_exe_arg = surreal_exe_arg()?;

    let initialized = run(&[
        "dogfood",
        "init",
        "--root",
        &root_arg,
        "--project",
        &project_arg,
        "--surreal-exe",
        &surreal_exe_arg,
    ])?;
    assert_eq!(initialized["status"], "initialized");
    assert_eq!(initialized["runtime_root_safe"], true);
    assert!(
        !fs::read_to_string(owned.0.join("codex").join("config.toml"))?.contains("SURREAL_PASS")
    );

    for cycle in 0..2 {
        let started = run(&["dogfood", "start", "--root", &root_arg])?;
        assert_eq!(started["status"], "running", "cycle {cycle}");
        assert_eq!(started["owned_children"].as_array().map(Vec::len), Some(2));

        let doctor = run(&["dogfood", "doctor", "--root", &root_arg])?;
        assert_eq!(doctor["daemon_health"], "ready", "cycle {cycle}");
        assert_eq!(doctor["db_health"], "ready", "cycle {cycle}");
        assert_eq!(
            doctor["codex_integration_model"],
            "project_mcp_with_native_plugin_available"
        );
        assert!(doctor.get("plugin_bundle_status").is_none());
        assert_eq!(
            doctor["project_codex_config_status"],
            "valid_disposable_config"
        );
        assert_eq!(doctor["provider_kill_switch"], true);
        assert!(
            doctor["antigravity_ledger_count"].is_null(),
            "a detached clean worktree has no controller-local historical provider report"
        );
        assert!(doctor["codex_cli_version"].as_str().is_some());
        assert!(doctor["surrealdb_identity"]["path"].as_str().is_some());
        assert!(doctor["surrealdb_identity"]["version"].as_str().is_some());
        assert!(doctor["surrealdb_identity"]["sha256"].as_str().is_some());
        assert!(
            doctor["surrealdb_identity"]["pe_machine"]
                .as_str()
                .is_some()
        );
        assert_eq!(doctor["blockers"].as_array().map(Vec::len), Some(0));

        let status = run(&["dogfood", "status", "--root", &root_arg])?;
        assert_eq!(status["daemon_health"], "ready");
        assert!(status["children"].as_array().is_some_and(|items| {
            items.len() == 2 && items.iter().all(|item| item["identity_matches"] == true)
        }));

        if cycle == 0 {
            let daemon_pid_path = owned.0.join("runtime").join("daemon.pid");
            let daemon_pid = fs::read_to_string(&daemon_pid_path)?;
            fs::write(&daemon_pid_path, "4294967295\n")?;
            let denial = run_failure(&["dogfood", "stop", "--root", &root_arg])?;
            assert!(denial.contains("daemon PID file does not match"));
            fs::write(&daemon_pid_path, daemon_pid)?;
            let still_running = run(&["dogfood", "status", "--root", &root_arg])?;
            assert_eq!(still_running["daemon_health"], "ready");
        }

        let stopped = run(&["dogfood", "stop", "--root", &root_arg])?;
        assert_eq!(stopped["status"], "stopped");
        assert!(!owned.0.join("runtime").join("daemon.pid").exists());
        assert!(!owned.0.join("runtime").join("ipc-auth.json").exists());
        assert!(owned.0.join("surrealdb-rocks").is_dir());
        let doctor_after_stop = run_failure(&["dogfood", "doctor", "--root", &root_arg])?;
        assert!(doctor_after_stop.contains("\"status\": \"BLOCKED\""));
        assert!(doctor_after_stop.contains("db_not_ready"));
        assert!(doctor_after_stop.contains("daemon_not_ready"));
    }

    let manifest_path = owned.0.join("dogfood-manifest.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let governor_binary = manifest["governor_binary"].clone();
    manifest["governor_binary"] = Value::String(
        owned
            .0
            .join("missing-governor.exe")
            .to_string_lossy()
            .into_owned(),
    );
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    let failure = run_failure(&["dogfood", "start", "--root", &root_arg])?;
    assert!(failure.contains("start owned dogfood governor daemon"));
    let mut failed_manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    assert_eq!(failed_manifest["state"], "start_failed");
    assert_eq!(
        failed_manifest["children"].as_array().map(Vec::len),
        Some(0)
    );
    assert!(!owned.0.join("tmp").join("surreal.pid").exists());
    failed_manifest["governor_binary"] = governor_binary;
    fs::write(&manifest_path, serde_json::to_vec_pretty(&failed_manifest)?)?;
    Ok(())
}

#[test]
fn dogfood_prepares_independent_codex_worktree_with_enabled_hooks_contract() -> TestResult {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let owned = OwnedRoot(std::env::temp_dir().join(format!(
        "eliot-dogfood-l3-worktree-test-{}-{nonce}",
        std::process::id()
    )));
    let source = owned.0.join("source");
    let runtime = owned.0.join("runtime");
    let destination = owned.0.join("worktrees").join("candidate");
    fs::create_dir_all(&source)?;
    git(&source, &["init", "-b", "main"])?;
    git(&source, &["config", "user.name", "ELIOT Test"])?;
    git(
        &source,
        &["config", "user.email", "eliot-test@example.invalid"],
    )?;
    fs::write(source.join("README.md"), "isolated dogfood source\n")?;
    let lock_source = repo_root()
        .join("docs")
        .join("release")
        .join("SURREALDB_WINDOWS_X64.lock.json");
    let lock_destination = source
        .join("docs")
        .join("release")
        .join("SURREALDB_WINDOWS_X64.lock.json");
    fs::create_dir_all(lock_destination.parent().ok_or("lock parent missing")?)?;
    fs::copy(lock_source, &lock_destination)?;
    git(
        &source,
        &[
            "add",
            "README.md",
            "docs/release/SURREALDB_WINDOWS_X64.lock.json",
        ],
    )?;
    git(&source, &["commit", "-m", "seed"])?;
    let head = git_stdout(&source, &["rev-parse", "HEAD"])?;

    let runtime_arg = runtime.to_string_lossy().into_owned();
    let source_arg = source.to_string_lossy().into_owned();
    let destination_arg = destination.to_string_lossy().into_owned();
    let surreal_exe_arg = surreal_exe_arg()?;
    run(&[
        "dogfood",
        "init",
        "--root",
        &runtime_arg,
        "--project",
        &source_arg,
        "--surreal-exe",
        &surreal_exe_arg,
    ])?;
    let config = fs::read_to_string(runtime.join("config").join("governor.toml"))?;
    assert!(config.contains("runtime/bin/surreal.exe"));
    assert!(
        runtime
            .join("runtime")
            .join("bin")
            .join("surreal.exe")
            .is_file()
    );
    let report = run(&[
        "dogfood",
        "prepare-worktree",
        "--root",
        &runtime_arg,
        "--destination",
        &destination_arg,
        "--branch",
        "codex/l3-isolated-test",
        "--commit",
        &head,
    ])?;

    assert_eq!(report["status"], "prepared");
    assert_eq!(report["independent_git_metadata"], true);
    assert_eq!(report["git_metadata_within_worktree"], true);
    assert_eq!(report["borrowed_object_database"], false);
    assert_eq!(report["source_repository_mutated"], false);
    assert!(destination.join(".git").is_dir());
    let hooks_path = PathBuf::from(
        report["hooks_path"]
            .as_str()
            .ok_or("missing generated hook artifact path")?,
    );
    assert!(hooks_path.is_file());
    assert!(!hooks_path.starts_with(&destination));
    assert!(!destination.join(".codex").join("hooks.json").exists());
    assert!(
        !destination
            .join(".git")
            .join("objects")
            .join("info")
            .join("alternates")
            .exists()
    );
    assert_eq!(git_stdout(&destination, &["status", "--porcelain=v1"])?, "");
    assert_eq!(git_stdout(&destination, &["rev-parse", "HEAD"])?, head);
    assert_eq!(
        git_stdout(&destination, &["branch", "--show-current"])?,
        "codex/l3-isolated-test"
    );
    assert!(!source.join(".git").join("worktrees").exists());
    assert_codex_launch_contract(&report)?;
    assert_codex_exec_plan(&report, &destination, &runtime)?;

    fs::write(source.join("dirty.txt"), "must fail closed\n")?;
    let rejected_destination = owned.0.join("worktrees").join("rejected");
    let rejected_arg = rejected_destination.to_string_lossy().into_owned();
    let failure = run_failure(&[
        "dogfood",
        "prepare-worktree",
        "--root",
        &runtime_arg,
        "--destination",
        &rejected_arg,
        "--branch",
        "codex/l3-rejected-test",
        "--commit",
        &head,
    ])?;
    assert!(failure.contains("source repository must be clean"));
    assert!(!rejected_destination.exists());
    Ok(())
}

#[test]
fn dogfood_run_codex_is_exposed_and_preflight_fails_before_spawn() -> TestResult {
    let help = Command::new(binary())
        .args(["dogfood", "--help"])
        .output()?;
    assert!(help.status.success());
    assert!(String::from_utf8(help.stdout)?.contains("run-codex"));

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let owned = OwnedRoot(std::env::temp_dir().join(format!(
        "eliot-dogfood-run-codex-preflight-test-{}-{nonce}",
        std::process::id()
    )));
    let root_arg = owned.0.to_string_lossy().into_owned();
    let project = repo_root();
    let project_arg = project.to_string_lossy().into_owned();
    let surreal_exe_arg = surreal_exe_arg()?;
    run(&[
        "dogfood",
        "init",
        "--root",
        &root_arg,
        "--project",
        &project_arg,
        "--surreal-exe",
        &surreal_exe_arg,
    ])?;

    let doctor = run_failure(&["dogfood", "doctor", "--root", &root_arg])?;
    assert!(doctor.contains("\"status\": \"BLOCKED\""));
    assert!(doctor.contains("db_not_ready"));
    assert!(doctor.contains("daemon_not_ready"));
    assert!(doctor.contains("schema_not_ready_before_daemon_ready"));
    assert!(doctor.contains("\"surrealdb_identity\": {"));

    let failure = run_failure(&[
        "dogfood",
        "run-codex",
        "--root",
        &root_arg,
        "--project",
        "00000000-0000-0000-0000-000000000001",
        "--task",
        "00000000-0000-0000-0000-000000000002",
        "--agent-session",
        "00000000-0000-0000-0000-000000000003",
        "--role-lease",
        "dogfood-test-role-lease",
        "--work-item",
        "00000000-0000-0000-0000-000000000004",
        "--work-lease",
        "00000000-0000-0000-0000-000000000005",
        "--worktree-lease",
        "00000000-0000-0000-0000-000000000006",
    ])?;
    assert!(failure.contains("requires a running owned runtime"));
    assert!(!owned.0.join("reports/live-codex/events.jsonl").exists());
    assert!(!owned.0.join("reports/live-codex/latest.json").exists());
    Ok(())
}

#[test]
fn dogfood_init_rejects_relative_surreal_preseed_path() -> TestResult {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "eliot-dogfood-relative-surreal-test-{}-{nonce}",
        std::process::id()
    ));
    let root_arg = root.to_string_lossy().into_owned();
    let project_arg = repo_root().to_string_lossy().into_owned();
    let failure = run_failure(&[
        "dogfood",
        "init",
        "--root",
        &root_arg,
        "--project",
        &project_arg,
        "--surreal-exe",
        "surreal.exe",
    ])?;
    assert!(failure.contains("must be absolute"));
    Ok(())
}

fn assert_codex_launch_contract(report: &Value) -> TestResult {
    let overrides = report["codex_config_overrides"]
        .as_array()
        .ok_or("missing Codex config overrides")?;
    for required in [
        "features.hooks=true",
        "approval_policy=\"never\"",
        "default_permissions=\":workspace\"",
        "permissions={}",
        "windows.sandbox=\"elevated\"",
        "shell_environment_policy.inherit=\"core\"",
        "web_search=\"disabled\"",
    ] {
        assert!(
            overrides.iter().any(|item| item == required),
            "missing required Codex override {required}"
        );
    }
    for event in [
        "hooks.SessionStart=",
        "hooks.UserPromptSubmit=",
        "hooks.PreToolUse=",
        "hooks.PostToolUse=",
        "hooks.Stop=",
    ] {
        assert!(
            overrides
                .iter()
                .filter_map(Value::as_str)
                .any(|item| item.starts_with(event)),
            "missing inline hook override {event}"
        );
    }
    let mcp_servers = overrides
        .iter()
        .filter_map(Value::as_str)
        .find(|item| item.starts_with("mcp_servers={"))
        .ok_or("missing atomic MCP server table override")?;
    for key in [
        "\"eliot-governor\" =",
        "command =",
        "args =",
        "cwd =",
        "env =",
        "env_vars =",
        "enabled = true",
        "required = true",
        "enabled_tools =",
        "default_tools_approval_mode = \"approve\"",
        "--profile",
        "codex_controller",
        "--host",
        "codex",
        "ELIOT_CODEX_SCOPE_TOKEN",
    ] {
        assert!(
            mcp_servers.contains(key),
            "missing complete ELIOT MCP override for {key}"
        );
    }
    for excluded in ["codebase_memory", "context7", "rust_lsp"] {
        assert!(
            !mcp_servers.contains(excluded),
            "atomic dogfood MCP table retained unrelated server {excluded}"
        );
    }
    assert!(
        !mcp_servers.contains("ELIOT_ROLE_LEASE_ID"),
        "raw role lease must not cross the Codex process environment boundary"
    );
    for tool in [
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
    ] {
        assert!(mcp_servers.contains(tool), "missing dogfood tool {tool}");
    }
    for forbidden in [
        "\"eliot_external_review",
        "\"eliot_delegate",
        "\"eliot_antigravity",
        "\"eliot_compile_packet_l3\"",
        "\"eliot_recall_l0\"",
        "\"eliot_fetch_atoms_l2\"",
        "\"raw",
    ] {
        assert!(
            !mcp_servers.contains(forbidden),
            "dogfood MCP allow-list exposed forbidden tool family {forbidden}"
        );
    }
    assert_eq!(report["codex_config_precedence"], "cli_overrides");
    assert_eq!(report["codex_ignore_user_config_required"], true);
    assert_eq!(report["hooks_source"], "cli_inline_from_hashed_artifact");
    assert_eq!(report["codex_project_trust_required"], false);
    assert_eq!(report["codex_project_config_loaded"], false);
    assert_eq!(report["codex_home_relocation_required"], false);
    assert_eq!(report["codex_hook_trust_bypass_required"], true);
    assert_eq!(report["codex_scope_environment_only"], true);
    assert_eq!(report["codex_role_lease_in_argv"], false);
    assert!(!overrides.iter().any(|item| {
        item.as_str().is_some_and(|item| {
            item.starts_with("sandbox_mode=") || item.starts_with("sandbox_workspace_write.")
        })
    }));
    Ok(())
}

fn assert_codex_exec_plan(report: &Value, destination: &Path, runtime: &Path) -> TestResult {
    let argv = report["codex_exec_argv_without_prompt"]
        .as_array()
        .ok_or("missing exact Codex exec argv")?;
    let argv = argv
        .iter()
        .map(|item| item.as_str().ok_or("Codex exec argv item is not a string"))
        .collect::<Result<Vec<_>, _>>()?;
    let destination = canonical_path_text(destination)?;
    let runtime = canonical_path_text(runtime)?;
    let output_schema = format!("{runtime}/reports/live-codex/output-schema.json");
    let last_message = format!("{runtime}/reports/live-codex/last-message.json");
    assert_eq!(
        &argv[..12],
        &[
            "--strict-config",
            "exec",
            "--cd",
            destination.as_str(),
            "--ignore-user-config",
            "--ignore-rules",
            "--dangerously-bypass-hook-trust",
            "--json",
            "--output-schema",
            output_schema.as_str(),
            "--output-last-message",
            last_message.as_str(),
        ]
    );
    let config_argv = &argv[12..];
    assert_eq!(config_argv.len(), 28);
    assert!(config_argv.chunks_exact(2).all(|pair| pair[0] == "-c"));
    assert_eq!(report["codex_exec_command"], "codex");
    assert_eq!(report["codex_prompt_via_stdin_required"], true);
    assert_eq!(report["codex_prompt_generated_from_task_contract"], true);
    assert_eq!(
        report["codex_output_schema_generated_from_task_contract"],
        true
    );
    assert!(
        !argv
            .iter()
            .any(|argument| *argument == "--ask-for-approval")
    );
    assert!(!argv.iter().any(|argument| *argument == "--sandbox"));
    assert_eq!(report["codex_jsonl_stdout_redirection_required"], true);
    assert_eq!(report["codex_home_relocation_required"], false);
    Ok(())
}

fn canonical_path_text(path: &Path) -> TestResult<String> {
    let canonical = fs::canonicalize(path)?;
    let text = canonical.to_string_lossy();
    let text = if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        text.into_owned()
    };
    Ok(text.replace('\\', "/"))
}

fn run(args: &[&str]) -> TestResult<Value> {
    let sequence = COMMAND_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "eliot-dogfood-command-{}-{sequence}",
        std::process::id()
    ));
    let stdout_path = base.with_extension("stdout.json");
    let stderr_path = base.with_extension("stderr.log");
    let stdout = fs::File::create(&stdout_path)?;
    let stderr = fs::File::create(&stderr_path)?;
    let status = Command::new(binary())
        .args(args)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .status()?;
    let stdout = fs::read(&stdout_path)?;
    let stderr = fs::read(&stderr_path)?;
    let _ = fs::remove_file(stdout_path);
    let _ = fs::remove_file(stderr_path);
    if !status.success() {
        return Err(format!(
            "command failed: stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&stdout)?)
}

fn run_failure(args: &[&str]) -> TestResult<String> {
    let output = Command::new(binary()).args(args).output()?;
    if output.status.success() {
        return Err("command unexpectedly succeeded".into());
    }
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_eliot-governor")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn surreal_exe_arg() -> TestResult<String> {
    let path = std::env::var_os("ELIOT_DOGFOOD_SURREAL_EXE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"));
    if !path.is_absolute() || !path.is_file() {
        return Err(format!(
            "focused dogfood test requires an operator-preseeded absolute surreal.exe; set ELIOT_DOGFOOD_SURREAL_EXE (resolved {})",
            path.display()
        )
        .into());
    }
    Ok(path.to_string_lossy().into_owned())
}

fn git(cwd: &std::path::Path, args: &[&str]) -> TestResult {
    let output = Command::new("git").current_dir(cwd).args(args).output()?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

fn git_stdout(cwd: &std::path::Path, args: &[&str]) -> TestResult<String> {
    let output = Command::new("git").current_dir(cwd).args(args).output()?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
