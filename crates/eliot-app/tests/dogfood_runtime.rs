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

    let initialized = run(&[
        "dogfood",
        "init",
        "--root",
        &root_arg,
        "--project",
        &project_arg,
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
    git(&source, &["add", "README.md"])?;
    git(&source, &["commit", "-m", "seed"])?;
    let head = git_stdout(&source, &["rev-parse", "HEAD"])?;

    let runtime_arg = runtime.to_string_lossy().into_owned();
    let source_arg = source.to_string_lossy().into_owned();
    let destination_arg = destination.to_string_lossy().into_owned();
    run(&[
        "dogfood",
        "init",
        "--root",
        &runtime_arg,
        "--project",
        &source_arg,
    ])?;
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
    run(&[
        "dogfood",
        "init",
        "--root",
        &root_arg,
        "--project",
        &project_arg,
    ])?;

    let failure = run_failure(&["dogfood", "run-codex", "--root", &root_arg])?;
    assert!(failure.contains("requires a running owned runtime"));
    assert!(!owned.0.join("reports/live-codex/events.jsonl").exists());
    assert!(!owned.0.join("reports/live-codex/latest.json").exists());
    Ok(())
}

fn assert_codex_launch_contract(report: &Value) -> TestResult {
    let overrides = report["codex_config_overrides"]
        .as_array()
        .ok_or("missing Codex config overrides")?;
    for required in [
        "features.hooks=true",
        "approval_policy=\"never\"",
        "sandbox_mode=\"workspace-write\"",
        "sandbox_workspace_write.network_access=false",
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
        "enabled = true",
        "required = true",
        "enabled_tools =",
        "default_tools_approval_mode = \"approve\"",
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
    for tool in [
        "eliot_task_state",
        "eliot_task_action_request",
        "eliot_task_observation_record",
        "eliot_task_verification_run",
        "eliot_compile_packet_l3",
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
    Ok(())
}

fn assert_codex_exec_plan(report: &Value, destination: &Path, runtime: &Path) -> TestResult {
    let argv = report["codex_exec_argv_before_prompt"]
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
        &argv[..15],
        &[
            "--strict-config",
            "--ask-for-approval",
            "never",
            "exec",
            "--cd",
            destination.as_str(),
            "--sandbox",
            "workspace-write",
            "--ignore-user-config",
            "--dangerously-bypass-hook-trust",
            "--json",
            "--output-schema",
            output_schema.as_str(),
            "--output-last-message",
            last_message.as_str(),
        ]
    );
    let config_argv = &argv[15..];
    assert_eq!(config_argv.len(), 22);
    assert!(config_argv.chunks_exact(2).all(|pair| pair[0] == "-c"));
    assert_eq!(report["codex_exec_command"], "codex");
    assert_eq!(report["codex_prompt_must_be_final_argument"], true);
    assert_eq!(report["codex_output_schema_must_exist_before_launch"], true);
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
