use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn plugin_manifest_exists_and_parses() -> TestResult {
    let manifest = read_json(&plugin_root().join(".codex-plugin").join("plugin.json"))?;
    assert_eq!(
        manifest.get("name").and_then(Value::as_str),
        Some("eliot-governor")
    );
    assert_eq!(
        manifest.get("skills").and_then(Value::as_str),
        Some("./skills/")
    );
    Ok(())
}

#[test]
fn plugin_mcp_config_exists_and_has_governed_server() -> TestResult {
    let mcp = read_json(&plugin_root().join(".mcp.json"))?;
    let servers = mcp.as_object().ok_or("direct MCP server map missing")?;
    assert_eq!(servers.len(), 1);
    let server = servers
        .get("eliot-governor")
        .ok_or("eliot-governor server missing")?;
    assert_eq!(
        server.get("command").and_then(Value::as_str),
        Some("./bin/eliot-governor.exe")
    );
    assert_eq!(server.get("args"), Some(&json!(["mcp", "stdio"])));
    assert_eq!(server.get("cwd").and_then(Value::as_str), Some("."));
    Ok(())
}

#[test]
fn plugin_hooks_config_exists_and_parses() -> TestResult {
    let hooks = read_json(&plugin_root().join("hooks").join("hooks.json"))?;
    let events = hooks
        .get("hooks")
        .and_then(Value::as_object)
        .ok_or("hooks object missing")?;
    for event in [
        "SessionStart",
        "UserPromptSubmit",
        "SubagentStart",
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "PreCompact",
        "PostCompact",
        "SubagentStop",
        "Stop",
    ] {
        assert!(
            events
                .get(event)
                .and_then(Value::as_array)
                .is_some_and(|items| !items.is_empty()),
            "{event} hook is missing"
        );
    }
    Ok(())
}

#[test]
fn plugin_hooks_use_rust_binary_not_python_node() -> TestResult {
    let hooks_path = plugin_root().join("hooks").join("hooks.json");
    let text = fs::read_to_string(hooks_path)?;
    let lowered = text.to_ascii_lowercase();
    for forbidden in ["python", "node", "npx", "bash", "cmd /c", "powershell"] {
        assert!(
            !lowered.contains(forbidden),
            "forbidden hook wrapper: {forbidden}"
        );
    }
    assert!(lowered.contains("eliot-governor.exe"));
    assert!(text.contains("PLUGIN_ROOT"));
    Ok(())
}

#[test]
fn plugin_skills_exist() {
    for skill in [
        "eliot-task-cycle",
        "eliot-code-understanding",
        "eliot-action-verification",
        "eliot-memory-discipline",
    ] {
        assert!(
            plugin_root()
                .join("skills")
                .join(skill)
                .join("SKILL.md")
                .is_file(),
            "{skill} is missing"
        );
    }
}

#[test]
fn hook_session_start_returns_json_context() -> TestResult {
    let output = run_hook(
        "hook-session-start",
        "session-start",
        &json!({ "source": "startup", "session_id": "f0-session" }),
    )?;
    assert_eq!(output.get("continue").and_then(Value::as_bool), Some(true));
    assert_eq!(
        output
            .get("hookSpecificOutput")
            .and_then(|value| value.get("hookEventName"))
            .and_then(Value::as_str),
        Some("SessionStart")
    );
    Ok(())
}

#[test]
fn hook_user_prompt_submit_records_task_candidate() -> TestResult {
    let runtime = runtime_for("hook-user-prompt-submit");
    let output = run_hook_with_runtime(
        &runtime,
        "user-prompt-submit",
        &json!({ "prompt": "Implement Phase F0", "session_id": "f0-prompt" }),
    )?;
    assert_eq!(output.get("continue").and_then(Value::as_bool), Some(true));
    assert!(pending_spool_count(&runtime)? > 0);
    Ok(())
}

#[test]
fn hook_pre_tool_use_denies_unleased_patch() -> TestResult {
    let output = run_hook(
        "hook-pre-tool-deny",
        "pre-tool-use",
        &json!({ "tool_name": "apply_patch" }),
    )?;
    assert_eq!(
        output
            .get("hookSpecificOutput")
            .and_then(|value| value.get("permissionDecision"))
            .and_then(Value::as_str),
        Some("deny")
    );
    Ok(())
}

#[test]
fn hook_pre_tool_use_allows_governed_mcp_read() -> TestResult {
    let output = run_hook(
        "hook-pre-tool-allow",
        "pre-tool-use",
        &json!({ "tool_name": "eliot_codecortex_latest" }),
    )?;
    assert!(output.get("continue").is_none());
    assert_eq!(
        output
            .get("hookSpecificOutput")
            .and_then(|value| value.get("hookEventName"))
            .and_then(Value::as_str),
        Some("PreToolUse")
    );
    Ok(())
}

#[test]
fn hook_post_tool_use_spools_observation() -> TestResult {
    let runtime = runtime_for("hook-post-tool-use");
    let output = run_hook_with_runtime(
        &runtime,
        "post-tool-use",
        &json!({ "tool_name": "eliot_codecortex_latest", "result": "ok" }),
    )?;
    assert!(
        output
            .get("systemMessage")
            .and_then(Value::as_str)
            .is_some()
    );
    assert!(pending_spool_count(&runtime)? > 0);
    Ok(())
}

#[test]
fn hook_pre_compact_flushes_or_blocks() -> TestResult {
    let output = run_hook("hook-pre-compact", "pre-compact", &json!({}))?;
    assert_eq!(output.get("continue").and_then(Value::as_bool), Some(true));
    assert!(
        output
            .get("systemMessage")
            .and_then(Value::as_str)
            .is_some()
    );
    Ok(())
}

#[test]
fn hook_post_compact_returns_context() -> TestResult {
    let output = run_hook("hook-post-compact", "post-compact", &json!({}))?;
    assert_eq!(output.get("continue").and_then(Value::as_bool), Some(true));
    assert!(
        output
            .get("systemMessage")
            .and_then(Value::as_str)
            .is_some()
    );
    Ok(())
}

#[test]
fn hook_stop_blocks_unverified_done() -> TestResult {
    let output = run_hook(
        "hook-stop-block",
        "stop",
        &json!({ "final_status": "DONE" }),
    )?;
    assert_eq!(
        output.get("decision").and_then(Value::as_str),
        Some("block")
    );
    Ok(())
}

#[test]
fn hook_stop_allows_verified_done() -> TestResult {
    let output = run_hook(
        "hook-stop-allow",
        "stop",
        &json!({ "final_status": "DONE_VERIFIED" }),
    )?;
    assert_eq!(output.get("continue").and_then(Value::as_bool), Some(true));
    Ok(())
}

#[test]
fn plugin_verify_report_generated() -> TestResult {
    let output = Command::new(binary())
        .arg("plugin")
        .arg("verify")
        .current_dir(repo_root())
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = read_json(
        &test_runtime_root()
            .join("reports")
            .join("plugin")
            .join("latest.json"),
    )?;
    assert_eq!(
        report.get("final_status").and_then(Value::as_str),
        Some("DONE_VERIFIED")
    );
    Ok(())
}

#[test]
/// The dependency doctor must keep checking for the two crates the workspace
/// deliberately refuses to link. The check lives in the engine's safety module;
/// this only proves nobody quietly deleted it.
fn the_dependency_doctor_still_checks_the_forbidden_crates() -> TestResult {
    let safety = fs::read_to_string(repo_root().join("crates/eliot-engine/src/safety.rs"))?;
    assert!(safety.contains("crate_absent(&self.repo_root, \"surrealdb\")"));
    assert!(safety.contains("crate_absent(&self.repo_root, \"rsa\")"));
    Ok(())
}

fn run_hook(name: &str, hook: &str, payload: &Value) -> TestResult<Value> {
    let runtime = runtime_for(name);
    run_hook_with_runtime(&runtime, hook, payload)
}

fn run_hook_with_runtime(runtime: &Path, hook: &str, payload: &Value) -> TestResult<Value> {
    let config_path = runtime.join("config").join("governor.toml");
    let mut child = Command::new(binary())
        .arg("--config")
        .arg(config_path)
        .arg("hook")
        .arg(hook)
        .current_dir(repo_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        serde_json::to_writer(&mut stdin, &payload)?;
    }
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn pending_spool_count(runtime: &Path) -> TestResult<usize> {
    let pending = runtime.join("hook-spool").join("pending");
    if !pending.is_dir() {
        return Ok(0);
    }
    Ok(fs::read_dir(pending)?.filter_map(Result::ok).count())
}

fn runtime_for(name: &str) -> PathBuf {
    repo_root().join("target").join("phase-f0-hooks").join(name)
}

fn test_runtime_root() -> PathBuf {
    std::env::var_os("ELIOT_GOVERNOR_CONFIG")
        .map(PathBuf::from)
        .and_then(|path| path.parent().and_then(Path::parent).map(Path::to_path_buf))
        .unwrap_or_else(|| repo_root().join(".eliot-governor"))
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_reader(fs::File::open(path)?)?)
}

fn plugin_root() -> PathBuf {
    repo_root().join("plugin").join("eliot-governor")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_eliot-governor"))
}
