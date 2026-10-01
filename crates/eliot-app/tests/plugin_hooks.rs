use eliot_engine::EliotHookService;
use eliot_types::HookEventKind;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn plugin_manifest_exists_and_parses() -> TestResult {
    let manifest = read_json(&plugin_root().join(".claude-plugin").join("plugin.json"))?;
    assert_eq!(manifest.get("name").and_then(Value::as_str), Some("eliot"));
    assert_eq!(manifest.get("license").and_then(Value::as_str), Some("MIT"));
    Ok(())
}

#[test]
fn plugin_mcp_config_exists_and_has_governed_server() -> TestResult {
    let mcp = read_json(&plugin_root().join(".mcp.json"))?;
    let servers = mcp
        .get("mcpServers")
        .and_then(Value::as_object)
        .ok_or("Claude MCP server map missing")?;
    assert_eq!(servers.len(), 1);
    let server = servers.get("eliot").ok_or("eliot server missing")?;
    // The legacy `eliot-governor.exe mcp stdio --host claude --instance default`
    // entry is retired. `docs/release/WINDOWS_X64_RELEASE.md` ("Claude Code
    // front door"): every legacy entrypoint other than the delegated MCP
    // stdio edge "unconditionally refuse[s] with
    // `LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER` plus the canonical-route receipt",
    // and the Bridge "runs `eliot-agent-bridge mcp --profile SPINE_FUNCTIONAL
    // --transport stdio --client-declaration
    // <installation-absolute>/agent-bridge/client-declaration-v2.json`".
    // `docs/integrations/claude/CLAUDE_CODE_PLUGIN.md` ("Front-door
    // selection") records the same argv as the new-path contract, and the
    // migrated edge is registered in
    // `crates/eliot-app/src/disposition.rs::MIGRATED_CONSUMER_EDGES` ("Claude
    // Code plugin MCP server"): `legacy_reference` `"command":
    // "${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe"` must be absent from this
    // file, `current_owner_reference` `"command":
    // "${CLAUDE_PLUGIN_ROOT}/bin/eliot-agent-bridge.exe"` must be present.
    assert_eq!(
        server.get("command").and_then(Value::as_str),
        Some("${CLAUDE_PLUGIN_ROOT}/bin/eliot-agent-bridge.exe")
    );
    assert_eq!(
        server.get("args"),
        Some(&json!([
            "mcp",
            "--profile",
            "SPINE_FUNCTIONAL",
            "--transport",
            "stdio",
            "--client-declaration",
            "${CLAUDE_PLUGIN_ROOT}/bin/agent-bridge/client-declaration-v2.json"
        ]))
    );
    Ok(())
}

#[test]
fn plugin_hooks_config_exists_and_parses() -> TestResult {
    let hooks = read_json(&plugin_root().join("hooks").join("hooks.json"))?;
    let events = hooks
        .get("hooks")
        .and_then(Value::as_object)
        .ok_or("hooks object missing")?;
    // `PostToolUseFailure` and `SessionEnd` are deliberately absent from this
    // edge. `crates/eliot-app/src/disposition.rs::MIGRATED_CONSUMER_EDGES`
    // ("Claude Code plugin lifecycle hooks", evidence field) states: "the two
    // host event --host claude --event rows (PostToolUseFailure, SessionEnd)
    // are removed from this edge because record_event lease-gating plus
    // reports/host-events writes are host-runtime behavior owned by the #77
    // host-request protocol migration and are not servable by the hook intake;
    // host-observable output is unchanged (continue/suppress ack either way)
    // and no current reader consumes reports/host-events". The bridge hook
    // intake serves exactly these seven events
    // (`bins/eliot-agent-bridge/src/hook_intake.rs::parse_hook_event`).
    for event in [
        "SessionStart",
        "PreToolUse",
        "PostToolUse",
        "SubagentStart",
        "SubagentStop",
        "PreCompact",
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
    // The retired host-event rows must stay gone, not merely be unasserted.
    for retired in ["PostToolUseFailure", "SessionEnd"] {
        assert!(
            !events.contains_key(retired),
            "{retired} is a retired host-event row on this edge"
        );
    }
    Ok(())
}

#[test]
fn plugin_hooks_use_rust_binary_not_python_node() -> TestResult {
    let hooks_path = plugin_root().join("hooks").join("hooks.json");
    let hooks = read_json(&hooks_path)?;
    let events = hooks
        .get("hooks")
        .and_then(Value::as_object)
        .ok_or("hooks object missing")?;
    let commands = events
        .values()
        .filter_map(Value::as_array)
        .flatten()
        .filter_map(|entry| entry.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter_map(|hook| hook.get("command").and_then(Value::as_str))
        .collect::<Vec<_>>();

    assert!(!commands.is_empty(), "no hook commands found");
    for command in commands {
        let lowered = command.to_ascii_lowercase();
        for forbidden in ["python", "node", "npx", "bash", "cmd /c", "powershell"] {
            assert!(
                !lowered.contains(forbidden),
                "forbidden hook wrapper: {forbidden}"
            );
        }
        // The current owner is the bridge binary, not the retired facade.
        // `docs/release/WINDOWS_X64_RELEASE.md` ("Claude Code front door"):
        // "Codex ... executes the SHA-256-verified Governor inside that
        // immutable cache" no longer describes the hook route -- it states that
        // "`eliot-governor.exe` ... remains only as an unconditional Bridge
        // redirect/refusal shim for installed entrypoints, and every other
        // entrypoint refuses without serving", and that the bundle stages
        // "`eliot-agent-bridge.exe` at the bundle root next to
        // `eliot-governor.exe`". The migrated hook edge is recorded in
        // `crates/eliot-app/src/disposition.rs::MIGRATED_CONSUMER_EDGES`
        // ("Claude Code plugin lifecycle hooks"), whose `legacy_reference`
        // `"command": "${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe"` must be
        // absent from the tracked hooks file and whose `current_owner_reference`
        // is `"command": "${CLAUDE_PLUGIN_ROOT}/bin/eliot-agent-bridge.exe"`.
        assert!(lowered.ends_with("eliot-agent-bridge.exe"));
        assert!(command.contains("CLAUDE_PLUGIN_ROOT"));
    }
    Ok(())
}

#[test]
fn plugin_skills_exist() -> TestResult {
    let expected = [
        "eliot-work",
        "eliot-remember",
        "eliot-recover",
        "eliot-finish",
    ];
    for skill in expected {
        assert!(
            plugin_root()
                .join("skills")
                .join(skill)
                .join("SKILL.md")
                .is_file(),
            "{skill} is missing"
        );
    }
    let active = fs::read_dir(plugin_root().join("skills"))?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("SKILL.md").is_file())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .collect::<Vec<_>>();
    assert_eq!(active.len(), expected.len());
    assert!(
        expected
            .iter()
            .all(|name| active.iter().any(|item| item == name))
    );
    Ok(())
}

#[test]
fn hooks_cannot_create_model_owned_candidate_or_influence_records() -> TestResult {
    let hook_files = [
        plugin_root().join("hooks/hooks.json"),
        repo_root().join("plugin/eliot-governor/hooks/hooks.json"),
    ];
    for path in hook_files {
        let text = fs::read_to_string(&path)?;
        let lowered = text.to_ascii_lowercase();
        for forbidden in [
            "eliot_agent_candidate_submit",
            "eliot_memory_influence_trace",
            "candidate_submit",
            "influence_trace",
        ] {
            assert!(
                !lowered.contains(forbidden),
                "{} lets a hook own {forbidden}",
                path.display()
            );
        }
    }

    let runtime = runtime_for("hook-cognition-boundary");
    run_hook_with_runtime(
        &runtime,
        "post-tool-use",
        &json!({"tool_name":"Bash","result":"failed fixture"}),
    )?;
    let pending = runtime.join("hook-spool/pending");
    for entry in fs::read_dir(pending)?.filter_map(Result::ok) {
        let text = fs::read_to_string(entry.path())?.to_ascii_lowercase();
        assert!(!text.contains("candidate_submit"));
        assert!(!text.contains("influence_trace"));
    }
    Ok(())
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
        &json!({ "prompt": "Implement canonical host integration", "session_id": "governed-prompt" }),
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

/// The plugin lives at user scope, so this hook fires on every project on the
/// machine. Blocking a patch in a session ELIOT was never asked to govern would
/// make the plugin unusable, so an unbound session must be let through -- and
/// this is the exact payload that gets denied when a task is attached.
#[test]
fn hook_pre_tool_use_defers_outside_an_eliot_session() -> TestResult {
    let output = run_unbound_hook(
        "hook-pre-tool-unbound",
        "pre-tool-use",
        &json!({ "tool_name": "apply_patch" }),
    )?;
    assert_ne!(
        output
            .get("hookSpecificOutput")
            .and_then(|value| value.get("permissionDecision"))
            .and_then(Value::as_str),
        Some("deny"),
        "an unbound session must not be blocked"
    );
    Ok(())
}

/// Same contract for the finish gate: DONE without `DONE_VERIFIED` is only
/// ELIOT's business when the session is attached to an ELIOT task.
#[test]
fn hook_stop_defers_outside_an_eliot_session() -> TestResult {
    let output = run_unbound_hook(
        "hook-stop-unbound",
        "stop",
        &json!({ "final_status": "DONE" }),
    )?;
    assert_ne!(
        output.get("decision").and_then(Value::as_str),
        Some("block"),
        "an unbound session must not be blocked"
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
fn u9_7_hook_blocks_mutation_until_the_packet_gate_is_cleared() -> TestResult {
    let runtime = runtime_for("u9-packet-gate");
    let session_id = "u9-gated-session";
    let gate_dir = runtime.join("reports").join("ul-gates");
    fs::create_dir_all(&gate_dir)?;
    let gate_path = gate_dir.join(format!("{session_id}.json"));
    fs::write(
        &gate_path,
        serde_json::to_vec_pretty(&json!({
            "project_id": "01936000-0000-7000-8000-000000000010",
            "session_id": session_id,
            "task_id": "01936000-0000-7000-8000-000000000011",
            "gate": {
                "status": "require_probe",
                "reason": "blind_subsystem"
            }
        }))?,
    )?;

    let denied = run_hook_with_runtime(
        &runtime,
        "pre-tool-use",
        &json!({"session_id": session_id, "tool_name": "Bash"}),
    )?;
    assert_eq!(
        denied.pointer("/hookSpecificOutput/permissionDecision"),
        Some(&json!("deny"))
    );
    let read_allowed = run_hook_with_runtime(
        &runtime,
        "pre-tool-use",
        &json!({"session_id": session_id, "tool_name": "Read"}),
    )?;
    assert_ne!(
        read_allowed.pointer("/hookSpecificOutput/permissionDecision"),
        Some(&json!("deny"))
    );

    fs::remove_file(gate_path)?;
    let mutation_allowed = run_hook_with_runtime(
        &runtime,
        "pre-tool-use",
        &json!({"session_id": session_id, "tool_name": "Bash"}),
    )?;
    assert_ne!(
        mutation_allowed.pointer("/hookSpecificOutput/permissionDecision"),
        Some(&json!("deny"))
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
/// The dependency doctor must keep checking for the two crates the workspace
/// deliberately refuses to link. The check lives in the engine's safety module;
/// this only proves nobody quietly deleted it.
fn the_dependency_doctor_still_checks_the_forbidden_crates() -> TestResult {
    let safety = fs::read_to_string(repo_root().join("crates/eliot-engine/src/safety.rs"))?;
    assert!(safety.contains("crate_absent(&self.repo_root, \"surrealdb\")"));
    assert!(safety.contains("crate_absent(&self.repo_root, \"rsa\")"));
    Ok(())
}

/// Runs a hook in a session attached to an ELIOT task, which is the only
/// context in which the enforcement points may block.
fn run_hook(name: &str, hook: &str, payload: &Value) -> TestResult<Value> {
    let runtime = runtime_for(name);
    run_hook_with_runtime(&runtime, hook, payload)
}

/// Runs a hook in a session that is not ELIOT's to govern -- the state every
/// unrelated project on the machine is in.
fn run_unbound_hook(name: &str, hook: &str, payload: &Value) -> TestResult<Value> {
    let runtime = runtime_for(name);
    run_hook_inner(&runtime, hook, payload, None)
}

fn run_hook_with_runtime(runtime: &Path, hook: &str, payload: &Value) -> TestResult<Value> {
    run_hook_inner(
        runtime,
        hook,
        payload,
        Some("01936000-0000-7000-8000-000000000001"),
    )
}

fn run_hook_inner(
    runtime: &Path,
    hook: &str,
    payload: &Value,
    task_id: Option<&str>,
) -> TestResult<Value> {
    // `docs/release/WINDOWS_X64_RELEASE.md` ("Claude Code front door"): "every
    // non-stdio entrypoint (`daemon run`, `service run`, `hook`, and the rest),
    // unconditionally refuse with `LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER` plus the
    // canonical-route receipt". Spawning `eliot-governor hook <event>` here
    // therefore tests a retired route, not the hook contract.
    //
    // The documented current owner is the bridge hook intake, which evaluates
    // the host hook JSON through the existing owner
    // `eliot_engine::EliotHookService::for_session().process`
    // (`bins/eliot-agent-bridge/src/hook_intake.rs::run_hook_intake`, recorded
    // in `crates/eliot-app/src/disposition.rs::MIGRATED_CONSUMER_EDGES` for
    // "Claude Code plugin lifecycle hooks"). This suite drives that owner
    // directly with the same three inputs the intake feeds it: the decoded
    // payload, `ELIOT_TASK_ID` attachment, and the same runtime root
    // (`<runtime>/config/governor.toml`'s grandparent under the retired
    // `run_hook` contract). Only the retired transport changed.
    let kind = hook_event_kind(hook)?;
    let service = EliotHookService::for_session(runtime, task_id.is_some());
    Ok(service.process(kind, payload)?.decision.stdout)
}

/// Argv spelling the bridge hook intake accepts for each lifecycle event
/// (`parse_hook_event`, `bins/eliot-agent-bridge/src/hook_intake.rs`); the
/// tracked `integrations/claude/eliot/hooks/hooks.json` rows pass exactly these
/// tokens after `hook`.
fn hook_event_kind(name: &str) -> TestResult<HookEventKind> {
    Ok(match name {
        "session-start" => HookEventKind::SessionStart,
        "user-prompt-submit" => HookEventKind::UserPromptSubmit,
        "subagent-start" => HookEventKind::SubagentStart,
        "pre-tool-use" => HookEventKind::PreToolUse,
        "permission-request" => HookEventKind::PermissionRequest,
        "post-tool-use" => HookEventKind::PostToolUse,
        "pre-compact" => HookEventKind::PreCompact,
        "post-compact" => HookEventKind::PostCompact,
        "subagent-stop" => HookEventKind::SubagentStop,
        "stop" => HookEventKind::Stop,
        other => return Err(format!("unknown hook event: {other}").into()),
    })
}

fn pending_spool_count(runtime: &Path) -> TestResult<usize> {
    let pending = runtime.join("hook-spool").join("pending");
    if !pending.is_dir() {
        return Ok(0);
    }
    Ok(fs::read_dir(pending)?.filter_map(Result::ok).count())
}

fn runtime_for(name: &str) -> PathBuf {
    std::env::temp_dir().join("eliot-hook-tests").join(name)
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_reader(fs::File::open(path)?)?)
}

fn plugin_root() -> PathBuf {
    repo_root()
        .join("integrations")
        .join("claude")
        .join("eliot")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}
