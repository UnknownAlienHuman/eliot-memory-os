use eliot_types::{ProjectId, TaskId, WriteId};
use serde_json::Value;
use std::fs;
use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn fwl_daemon_ready_requires_real_ipc() -> TestResult {
    let runtime = OwnedRuntime::new("daemon-real-ipc")?;
    let config_path = runtime.path().join("config").join("governor.toml");
    write_test_config(runtime.path(), &config_path, free_local_port()?)?;

    let mut daemon = OwnedChild::spawn(
        Command::new(binary())
            .arg("--config")
            .arg(&config_path)
            .arg("daemon")
            .arg("run")
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .env(
                "ELIOT_TEST_SURREAL_PASSWORD_FILE",
                test_password_file(&config_path)?,
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )?;

    let report_path = runtime
        .path()
        .join("reports")
        .join("runtime")
        .join("latest.json");
    let report = wait_for_json(&report_path, Duration::from_secs(10))?;
    let ipc_enabled = report
        .get("status")
        .and_then(|status| status.get("ipc_enabled"))
        .and_then(Value::as_bool);

    let mut facade = McpClient::start(&config_path)?;
    let response = facade.request(
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }),
        Duration::from_secs(10),
    )?;
    let server_name = response
        .get("result")
        .and_then(|result| result.get("serverInfo"))
        .and_then(|info| info.get("name"))
        .and_then(Value::as_str);

    facade.stop()?;
    daemon.stop()?;
    assert_eq!(
        ipc_enabled,
        Some(true),
        "daemon READY must mean a real Windows named-pipe listener is accepting connections"
    );
    assert_eq!(
        server_name,
        Some("eliot-governor"),
        "stdio facade must receive initialize response from daemon over the pipe"
    );
    Ok(())
}

#[test]
fn fwl_static_safety_boundaries_hold() -> TestResult {
    let mcp_source = include_str!("../src/mcp_stdio.rs");
    let relay = mcp_source
        .split_once("pub async fn run(")
        .ok_or("stdio relay entrypoint must exist")?
        .1
        .split_once("pub(crate) struct McpDaemon")
        .ok_or("daemon boundary must follow relay entrypoint")?
        .0;
    assert!(relay.contains("named_pipe_ipc::run_stdio_client"));
    for forbidden in ["CanonicalStore", "ControlWal", "WriterActor", "load_config"] {
        assert!(
            !relay.contains(forbidden),
            "stdio relay must not construct daemon-owned {forbidden}"
        );
    }

    let justfile = include_str!("../../../Justfile");
    let phase_recipe = justfile
        .split_once("phase-l2-focused:")
        .ok_or("phase-l2 recipe must exist")?
        .1
        .split_once("doc-test:")
        .ok_or("phase-l2 recipe must be bounded")?
        .0;
    assert!(phase_recipe.contains("ELIOT_DISABLE_REAL_PROVIDER = '1'"));
    for forbidden in [
        "phase-l1c-provider-once",
        "Get-Service",
        "New-Service",
        "Set-ItemProperty",
        "reg.exe",
        "sc.exe",
    ] {
        assert!(
            !phase_recipe.contains(forbidden),
            "phase-l2 recipe must not contain host/provider action {forbidden}"
        );
    }

    let isolated_tests = include_str!("../../../scripts/run-isolated-tests.ps1");
    assert!(isolated_tests.contains("GetTempPath"));
    assert!(isolated_tests.contains("ELIOT_DISABLE_REAL_PROVIDER = '1'"));
    assert!(isolated_tests.contains("ELIOT_TEST_ALLOW_LEGACY_OPERATOR_CURSOR_KEY_FILE = '1'"));
    assert!(isolated_tests.contains("TcpListener]::new([Net.IPAddress]::Loopback, 0)"));
    assert!(isolated_tests.contains("--bin', 'eliot-process-guardian'"));
    assert!(isolated_tests.contains("'--stop-file', $surrealStopPath"));
    assert!(isolated_tests.contains("[IO.File]::WriteAllText($surrealStopPath, 'stop'"));
    assert!(isolated_tests.contains("$surrealGuardianProcess.WaitForExit(10000)"));
    assert!(isolated_tests.contains("'surrealdb_guardian_fallback'"));
    assert!(isolated_tests.contains("$lower.Contains('onedrive')"));
    assert!(isolated_tests.contains("$lower.Contains('programdata')"));
    assert!(!isolated_tests.contains("$env:LOCALAPPDATA ="));
    assert!(isolated_tests.contains(
        "$passwordConfigPath = \"%LOCALAPPDATA%/Eliot/tests/$runId/secrets/surreal_root_password.txt\""
    ));
    assert!(isolated_tests.contains("$env:ELIOT_TEST_SURREAL_PASSWORD_FILE = $passwordConfigPath"));
    assert!(isolated_tests.contains("Remove-ExactOwnedSecretRoot"));
    assert!(isolated_tests.contains(".eliot-test-owner.json"));
    assert!(!isolated_tests.contains("Remove-Item -LiteralPath $secretTestsRoot -Recurse"));

    let mcp_stdio = include_str!("../src/mcp_stdio.rs");
    let cursor_loader = mcp_stdio
        .split_once("fn load_or_create_operator_cursor_signing_key(")
        .ok_or("operator cursor key loader must exist")?
        .1
        .split_once("impl McpDaemon")
        .ok_or("operator cursor key loader must remain bounded")?
        .0;
    assert!(cursor_loader.contains("LEGACY_OPERATOR_CURSOR_TEST_OVERRIDE"));
    assert!(!cursor_loader.contains("ELIOT_DISABLE_REAL_PROVIDER"));

    let ipc_source = include_str!("../src/named_pipe_ipc.rs");
    assert!(ipc_source.contains("MAX_FRAME_BYTES"));
    assert!(ipc_source.contains("MAX_CONNECTIONS"));
    assert!(ipc_source.contains("reject_database_environment"));
    for forbidden_env in [
        "SURREAL_USER",
        "SURREAL_PASS",
        "ELIOT_TEST_SURREAL_ENDPOINT",
    ] {
        assert!(ipc_source.contains(forbidden_env));
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[allow(clippy::too_many_lines)]
fn l3_pipe_authentication_requires_a_per_start_secret() -> TestResult {
    let runtime = OwnedRuntime::new("l3-auth-red")?;
    let port = free_local_port()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    let auth_path = runtime.path().join("runtime").join("ipc-auth.json");
    let daemon_log = runtime.path().join("reports").join("ipc-auth.log");
    write_test_config(runtime.path(), &config_path, port)?;
    let mut database = start_surreal(runtime.path(), port)?;
    wait_for_tcp(port, Duration::from_secs(15))?;
    let mut daemon = start_daemon_logged(&config_path, &daemon_log)?;
    wait_for_runtime_pid(
        &runtime
            .path()
            .join("reports")
            .join("runtime")
            .join("latest.json"),
        daemon.id(),
        Duration::from_secs(10),
    )?;

    assert!(
        auth_path.is_file(),
        "L3 daemon must create a restricted per-start IPC authentication file"
    );
    let first_auth = wait_for_json(&auth_path, Duration::from_secs(5))?;
    let pipe_name = required_string(&first_auth, "/pipe_name")?;
    let first_runtime = required_string(&first_auth, "/runtime_id")?;
    let first_token = required_string(&first_auth, "/token")?;
    let first_generation = required_string(&first_auth, "/token_generation_id")?;
    assert!(
        first_token.len() >= 64,
        "per-start token must carry at least 256 encoded bits"
    );

    let no_token = raw_pipe_exchange(
        &pipe_name,
        &serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        None,
    )?;
    assert_handshake_rejected(&no_token, "malformed_handshake")?;

    let wrong_token = authenticated_handshake(&first_auth, "wrong-token", "wrong-token-nonce")?;
    assert_handshake_rejected(
        &raw_pipe_exchange(&pipe_name, &wrong_token, None)?,
        "invalid_token",
    )?;

    let wrong_protocol = serde_json::json!({
        "kind": "eliot_ipc_handshake",
        "protocol_version": "eliot-ipc-obsolete",
        "instance_name": required_string(&first_auth, "/instance_name")?,
        "runtime_id": required_string(&first_auth, "/runtime_id")?,
        "token": &first_token,
        "token_generation_id": &first_generation,
        "client_nonce": "wrong-protocol-nonce",
        "profile": "codex_controller"
    });
    assert_handshake_rejected(
        &raw_pipe_exchange(&pipe_name, &wrong_protocol, None)?,
        "protocol_mismatch",
    )?;

    let replay = authenticated_handshake(&first_auth, &first_token, "replay-nonce")?;
    let first_replay_result = raw_pipe_exchange(&pipe_name, &replay, None)?;
    assert_eq!(
        first_replay_result
            .first()
            .and_then(|value| value.get("accepted"))
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_handshake_rejected(
        &raw_pipe_exchange(&pipe_name, &replay, None)?,
        "replayed_handshake",
    )?;

    let oversized = "x".repeat(1_048_577);
    assert_handshake_rejected(
        &raw_pipe_exchange_line(&pipe_name, &oversized, None)?,
        "invalid_handshake_frame",
    )?;

    let valid = authenticated_handshake(&first_auth, &first_token, "valid-relay-nonce")?;
    let initialized = raw_pipe_exchange(
        &pipe_name,
        &valid,
        Some(&serde_json::json!({
            "jsonrpc":"2.0","id":2,"method":"initialize","params":{}
        })),
    )?;
    assert_eq!(
        initialized
            .get(1)
            .and_then(|value| value.pointer("/result/serverInfo/name"))
            .and_then(Value::as_str),
        Some("eliot-governor")
    );

    let unauthenticated_tools = raw_pipe_exchange(
        &pipe_name,
        &serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}),
        None,
    )?;
    assert_handshake_rejected(&unauthenticated_tools, "malformed_handshake")?;

    assert_restricted_runtime_acl(&runtime.path().join("runtime"))?;

    request_daemon_stop(&config_path)?;
    daemon.wait_for_exit(Duration::from_secs(10))?;

    let runtime_report = runtime
        .path()
        .join("reports")
        .join("runtime")
        .join("latest.json");
    fs::remove_file(&runtime_report)?;
    let mut restarted = start_daemon_logged(&config_path, &daemon_log)?;
    wait_for_runtime_pid(&runtime_report, restarted.id(), Duration::from_secs(10))?;
    let second_auth = wait_for_changed_json_string(
        &auth_path,
        "/token_generation_id",
        &first_generation,
        Duration::from_secs(5),
    )?;
    let second_runtime = required_string(&second_auth, "/runtime_id")?;
    let second_token = required_string(&second_auth, "/token")?;
    assert_ne!(
        second_runtime, first_runtime,
        "daemon restart must rotate the runtime identity"
    );
    assert_ne!(
        second_token, first_token,
        "daemon restart must rotate the IPC token"
    );
    let mut stale_generation = replay;
    stale_generation["runtime_id"] = Value::String(second_runtime);
    assert_handshake_rejected(
        &raw_pipe_exchange(&pipe_name, &stale_generation, None)?,
        "stale_token_generation",
    )?;

    request_daemon_stop(&config_path)?;
    restarted.wait_for_exit(Duration::from_secs(10))?;
    let log = fs::read_to_string(&daemon_log)?;
    assert!(log.contains("IPC authentication rejected"));
    assert!(
        !log.contains(&first_token),
        "old token must never enter daemon logs"
    );
    assert!(
        !log.contains(&second_token),
        "new token must never enter daemon logs"
    );
    database.stop()?;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn l3_fabricated_provenance_cannot_authorize_action() -> TestResult {
    let runtime = OwnedRuntime::new("l3-provenance-red")?;
    let port = free_local_port()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    write_test_config(runtime.path(), &config_path, port)?;
    let mut database = start_surreal(runtime.path(), port)?;
    wait_for_tcp(port, Duration::from_secs(15))?;
    let mut daemon = start_daemon(&config_path)?;
    wait_for_runtime_pid(
        &runtime
            .path()
            .join("reports")
            .join("runtime")
            .join("latest.json"),
        daemon.id(),
        Duration::from_secs(10),
    )?;
    let mut facade = McpClient::start(&config_path)?;
    facade.initialize()?;
    let project_id = ProjectId::new_v7().to_string();
    let task_id = TaskId::new_v7().to_string();
    let created = facade.tool_call(
        101,
        "eliot_task_contract_create",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7().to_string(),
            "title": "L3 canonical provenance red boundary",
            "acceptance_items": [
                {"item_id": "observed", "description": "observation", "required_evidence": "observation"},
                {"item_id": "verified", "description": "verification", "required_evidence": "verification"}
            ]
        }),
    )?;
    let same_project_task = TaskId::new_v7().to_string();
    let same_project = facade.tool_call(
        103,
        "eliot_task_contract_create",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": same_project_task,
            "write_id": WriteId::new_v7().to_string(),
            "title": "same project, different task",
            "acceptance_items": [
                {"item_id": "observed", "description": "observation", "required_evidence": "observation"},
                {"item_id": "verified", "description": "verification", "required_evidence": "verification"}
            ]
        }),
    )?;
    let other_project_id = ProjectId::new_v7().to_string();
    let other_project_task = TaskId::new_v7().to_string();
    let other_project = facade.tool_call(
        104,
        "eliot_task_contract_create",
        &serde_json::json!({
            "project_id": other_project_id,
            "task_id": other_project_task,
            "write_id": WriteId::new_v7().to_string(),
            "title": "different project and task",
            "acceptance_items": [
                {"item_id": "observed", "description": "observation", "required_evidence": "observation"},
                {"item_id": "verified", "description": "verification", "required_evidence": "verification"}
            ]
        }),
    )?;
    let packet = facade.tool_call(
        105,
        "eliot_compile_packet_l3",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "resolve adversarial provenance",
            "candidate_handles": [],
            "max_tokens": 1200
        }),
    )?;
    let (verifier_ref, _) = registered_verifier(&packet, "daemon-receipt-resolution")?;
    let created_revision = task_revision(&created)?;
    let denied = facade.tool_call(
        102,
        "eliot_task_action_request",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7().to_string(),
            "expected_revision": created_revision,
            "packet_id": "packet:fabricated",
            "packet_revision_fence": task_revision(&created)?,
            "task_contract_ref": "task:fabricated@999",
            "current_truth_refs": ["task:fabricated@999"],
            "provenance_handles": ["receipt:fabricated"],
            "negative_memory_checked": true,
            "negative_memory_check_ref": "negative-memory:packet:fabricated",
            "planned_action": "attempt action from caller-authored strings",
            "planned_verifier_ref": "verifier:fabricated@1#blake3:fabricated"
        }),
    )?;
    assert_eq!(
        denied.get("status").and_then(Value::as_str),
        Some("denied_invalid_provenance")
    );
    assert!(denied.get("write_receipt").is_some_and(Value::is_null));

    for (id, handle, label) in [
        (
            106,
            receipt_id(&same_project)?,
            "valid receipt from another task",
        ),
        (
            107,
            receipt_id(&other_project)?,
            "valid receipt from another project",
        ),
        (
            108,
            "claim/recalled-candidate".to_owned(),
            "recalled candidate handle",
        ),
    ] {
        let denied = facade.tool_call(
            id,
            "eliot_task_action_request",
            &serde_json::json!({
                "project_id": project_id,
                "task_id": task_id,
                "write_id": WriteId::new_v7().to_string(),
                "expected_revision": created_revision,
                "packet_id": required_string(&packet, "/packet_id")?,
                "packet_revision_fence": required_u64(&packet, "/packet_revision_fence")?,
                "task_contract_ref": required_string(&packet, "/task_contract_ref")?,
                "current_truth_refs": packet.get("current_truth_refs").cloned().ok_or("current truth refs missing")?,
                "provenance_handles": [handle],
                "negative_memory_checked": true,
                "negative_memory_check_ref": required_string(&packet, "/negative_memory_check_ref")?,
                "planned_action": label,
                "planned_verifier_ref": verifier_ref
            }),
        )?;
        assert_eq!(
            denied.get("status").and_then(Value::as_str),
            Some("denied_invalid_provenance"),
            "{label} must not authorize action: {denied}"
        );
    }

    let omitted_negative = facade.tool_call(
        109,
        "eliot_task_action_request",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7().to_string(),
            "expected_revision": created_revision,
            "packet_id": required_string(&packet, "/packet_id")?,
            "packet_revision_fence": required_u64(&packet, "/packet_revision_fence")?,
            "task_contract_ref": required_string(&packet, "/task_contract_ref")?,
            "current_truth_refs": packet.get("current_truth_refs").cloned().ok_or("current truth refs missing")?,
            "provenance_handles": [receipt_id(&created)?],
            "negative_memory_checked": false,
            "negative_memory_check_ref": "",
            "planned_action": "omit negative-memory check",
            "planned_verifier_ref": verifier_ref
        }),
    )?;
    assert_eq!(
        omitted_negative.get("status").and_then(Value::as_str),
        Some("denied_requires_probe")
    );

    facade.stop()?;
    request_daemon_stop(&config_path)?;
    daemon.wait_for_exit(Duration::from_secs(10))?;
    database.stop()?;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn l3_free_text_verifier_scope_cannot_satisfy_acceptance() -> TestResult {
    let runtime = OwnedRuntime::new("l3-verifier-red")?;
    let port = free_local_port()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    write_test_config(runtime.path(), &config_path, port)?;
    let mut database = start_surreal(runtime.path(), port)?;
    wait_for_tcp(port, Duration::from_secs(15))?;
    let mut daemon = start_daemon(&config_path)?;
    wait_for_runtime_pid(
        &runtime
            .path()
            .join("reports")
            .join("runtime")
            .join("latest.json"),
        daemon.id(),
        Duration::from_secs(10),
    )?;
    let mut facade = McpClient::start(&config_path)?;
    facade.initialize()?;
    let project_id = ProjectId::new_v7().to_string();
    let task_id = TaskId::new_v7().to_string();
    let created = facade.tool_call(
        201,
        "eliot_task_contract_create",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7().to_string(),
            "title": "L3 verifier scope red boundary",
            "acceptance_items": [
                {"item_id": "observed", "description": "observation", "required_evidence": "observation"},
                {"item_id": "verified", "description": "verification", "required_evidence": "verification"}
            ]
        }),
    )?;
    let created_revision = task_revision(&created)?;
    let packet = facade.tool_call(
        205,
        "eliot_compile_packet_l3",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "resolve L3 verifier scope",
            "candidate_handles": [],
            "max_tokens": 1200
        }),
    )?;
    let (verifier_ref, _verifier_config_hash) =
        registered_verifier(&packet, "daemon-receipt-resolution")?;
    let action = facade.tool_call(
        202,
        "eliot_task_action_request",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7().to_string(),
            "expected_revision": created_revision,
            "packet_id": required_string(&packet, "/packet_id")?,
            "packet_revision_fence": required_u64(&packet, "/packet_revision_fence")?,
            "task_contract_ref": required_string(&packet, "/task_contract_ref")?,
            "current_truth_refs": packet.get("current_truth_refs").cloned().ok_or("current truth refs missing")?,
            "provenance_handles": [receipt_id(&created)?],
            "negative_memory_checked": true,
            "negative_memory_check_ref": required_string(&packet, "/negative_memory_check_ref")?,
            "planned_action": "record exact observation",
            "planned_verifier_ref": verifier_ref
        }),
    )?;
    let observation = facade.tool_call(
        203,
        "eliot_task_observation_record",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7().to_string(),
            "expected_revision": task_revision(&action)?,
            "action_lease_id": action.pointer("/action_lease/lease_id").and_then(Value::as_str).ok_or("lease id missing")?,
            "item_id": "observed",
            "tool_name": "l3_red_probe",
            "observation": "candidate observation",
            "status": "passed",
            "scope": format!("eliot/task/{task_id}/acceptance/observed"),
            "provenance_handles": [receipt_id(&action)?],
            "provenance_set_hash": required_string(&action, "/action_lease/provenance_set_hash")?
        }),
    )?;
    let denied = facade.tool_call(
        204,
        "eliot_task_verification_run",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7().to_string(),
            "expected_revision": task_revision(&observation)?,
            "item_id": "verified",
            "observation_id": observation.get("observation_id").and_then(Value::as_str).ok_or("observation id missing")?,
            "artifact_scope": "trust me: this is the right worktree",
            "mode": "receipt_resolution"
        }),
    )?;
    assert_eq!(
        denied.get("status").and_then(Value::as_str),
        Some("denied_invalid_verifier_scope")
    );
    assert!(denied.get("write_receipt").is_some_and(Value::is_null));

    facade.stop()?;
    request_daemon_stop(&config_path)?;
    daemon.wait_for_exit(Duration::from_secs(10))?;
    database.stop()?;
    Ok(())
}

#[test]
#[allow(clippy::print_stdout, clippy::too_many_lines)]
fn first_working_loop_end_to_end() -> TestResult {
    assert_eq!(
        std::env::var("ELIOT_DISABLE_REAL_PROVIDER").as_deref(),
        Ok("1")
    );
    let mut runtime = OwnedRuntime::new("first-working-loop")?;
    assert_no_provider_activity(runtime.path())?;
    let port = free_local_port()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    write_test_config(runtime.path(), &config_path, port)?;
    let mut database = start_surreal(runtime.path(), port)?;
    wait_for_tcp(port, Duration::from_secs(15))?;

    let runtime_report = runtime
        .path()
        .join("reports")
        .join("runtime")
        .join("latest.json");
    let mut daemon = start_daemon(&config_path)?;
    wait_for_runtime_pid(&runtime_report, daemon.id(), Duration::from_secs(10))?;
    let daemon_runtime_report = fs::read(&runtime_report)?;
    let mut facade = McpClient::start(&config_path)?;
    facade.initialize()?;
    let runtime_status = facade.tool_call(90, "eliot_runtime_status", &serde_json::json!({}))?;
    assert_eq!(
        runtime_status.get("mode").and_then(Value::as_str),
        Some("daemon")
    );
    assert_eq!(
        runtime_status
            .get("canonical_state_owner")
            .and_then(Value::as_str),
        Some("daemon")
    );
    assert_eq!(
        runtime_status.get("ipc_enabled").and_then(Value::as_bool),
        Some(true)
    );
    let ipc_status = facade.tool_call(91, "eliot_ipc_status", &serde_json::json!({}))?;
    assert_eq!(
        ipc_status.get("transport").and_then(Value::as_str),
        Some("windows-named-pipe")
    );
    assert_eq!(
        ipc_status.get("listening").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        ipc_status
            .get("handshake_required")
            .and_then(Value::as_bool),
        Some(true),
        "authority-facing IPC status must match the authenticated transport contract"
    );
    assert_eq!(
        fs::read(&runtime_report)?,
        daemon_runtime_report,
        "status tools must not overwrite the daemon readiness report"
    );

    let project_id = ProjectId::new_v7().to_string();
    let task_id = TaskId::new_v7().to_string();
    let create_write = WriteId::new_v7().to_string();
    let denied_action_write = WriteId::new_v7().to_string();
    let action_write = WriteId::new_v7().to_string();
    let observation_write = WriteId::new_v7().to_string();
    let wrong_observation_write = WriteId::new_v7().to_string();
    let candidate_write = WriteId::new_v7().to_string();
    let verificationless_completion_write = WriteId::new_v7().to_string();
    let verification_write = WriteId::new_v7().to_string();
    let stale_write = WriteId::new_v7().to_string();
    let completion_write = WriteId::new_v7().to_string();
    let acceptance_ids = vec![
        "observation-recorded".to_owned(),
        "verification-passed".to_owned(),
    ];

    let created = facade.tool_call(
        1,
        "eliot_task_contract_create",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": create_write,
            "title": "Phase L2 deterministic First Working Loop",
            "acceptance_items": [
                {"item_id": acceptance_ids[0], "description": "one scoped observation is receipted", "required_evidence": "observation"},
                {"item_id": acceptance_ids[1], "description": "one trusted verifier result is receipted", "required_evidence": "verification"}
            ]
        }),
    )?;
    let create_revision = task_revision(&created)?;
    let create_receipt = receipt_id(&created)?;

    let current = facade.tool_call(
        2,
        "eliot_current_state",
        &serde_json::json!({"project_id": project_id, "at_least_revision": create_revision}),
    )?;
    assert_eq!(
        current.get("memory_revision").and_then(Value::as_u64),
        Some(create_revision)
    );
    let packet = facade.tool_call(
        3,
        "eliot_compile_packet_l3",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "prove the canonical First Working Loop",
            "candidate_handles": [],
            "max_tokens": 2000
        }),
    )?;
    assert_eq!(
        packet.get("task_truth_status").and_then(Value::as_str),
        Some("current_canonical")
    );
    assert_eq!(
        packet.get("task_revision_fence").and_then(Value::as_u64),
        Some(create_revision)
    );
    let (receipt_verifier_ref, receipt_verifier_config_hash) =
        registered_verifier(&packet, "daemon-receipt-resolution")?;
    let (dogfood_verifier_ref, _) =
        registered_verifier(&packet, "cargo-eliot-store-blob-integrity")?;
    let (workspace_check_verifier_ref, workspace_check_config_hash) =
        registered_verifier(&packet, "cargo-workspace-check")?;
    assert!(workspace_check_verifier_ref.contains(&workspace_check_config_hash));

    let denied_action = facade.tool_call(
        4,
        "eliot_task_action_request",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": denied_action_write,
            "expected_revision": create_revision,
            "current_truth_refs": [],
            "provenance_handles": [],
            "negative_memory_checked": false,
            "planned_action": "",
            "next_verifier": ""
        }),
    )?;
    assert_eq!(
        denied_action.get("status").and_then(Value::as_str),
        Some("denied_requires_probe")
    );
    assert!(
        denied_action
            .get("write_receipt")
            .is_some_and(Value::is_null)
    );

    let allowed_action = facade.tool_call(
        5,
        "eliot_task_action_request",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": action_write,
            "expected_revision": create_revision,
            "packet_id": required_string(&packet, "/packet_id")?,
            "packet_revision_fence": required_u64(&packet, "/packet_revision_fence")?,
            "task_contract_ref": required_string(&packet, "/task_contract_ref")?,
            "current_truth_refs": packet.get("current_truth_refs").cloned().ok_or("current truth refs missing")?,
            "provenance_handles": [create_receipt],
            "negative_memory_checked": true,
            "negative_memory_check_ref": required_string(&packet, "/negative_memory_check_ref")?,
            "planned_action": "record one deterministic observation",
            "planned_verifier_ref": receipt_verifier_ref
        }),
    )?;
    assert_eq!(
        allowed_action.get("status").and_then(Value::as_str),
        Some("allowed_bounded")
    );
    let action_revision = task_revision(&allowed_action)?;
    let action_lease_id = allowed_action
        .pointer("/action_lease/lease_id")
        .and_then(Value::as_str)
        .ok_or("action lease id missing")?
        .to_owned();
    let provenance_set_hash =
        required_string(&allowed_action, "/action_lease/provenance_set_hash")?;

    let stale_packet = facade.tool_call(
        51,
        "eliot_task_action_request",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7().to_string(),
            "expected_revision": action_revision,
            "packet_id": required_string(&packet, "/packet_id")?,
            "packet_revision_fence": required_u64(&packet, "/packet_revision_fence")?,
            "task_contract_ref": required_string(&packet, "/task_contract_ref")?,
            "current_truth_refs": packet.get("current_truth_refs").cloned().ok_or("current truth refs missing")?,
            "provenance_handles": [receipt_id(&allowed_action)?],
            "negative_memory_checked": true,
            "negative_memory_check_ref": required_string(&packet, "/negative_memory_check_ref")?,
            "planned_action": "attempt action from stale packet",
            "planned_verifier_ref": receipt_verifier_ref
        }),
    )?;
    assert_eq!(
        stale_packet.get("status").and_then(Value::as_str),
        Some("denied_invalid_provenance")
    );

    let wrong_evidence_kind = facade.tool_call_response(
        55,
        "eliot_task_observation_record",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": wrong_observation_write,
            "expected_revision": action_revision,
            "action_lease_id": action_lease_id,
            "item_id": acceptance_ids[1],
            "tool_name": "phase_l3_wrong_evidence_kind_probe",
            "observation": "candidate evidence must not satisfy verification acceptance",
            "status": "passed",
            "scope": format!("eliot/task/{task_id}/acceptance/{}", acceptance_ids[1]),
            "provenance_handles": [receipt_id(&allowed_action)?],
            "provenance_set_hash": provenance_set_hash
        }),
    )?;
    assert!(
        wrong_evidence_kind
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("requires verification evidence"))
    );

    let observed = facade.tool_call(
        6,
        "eliot_task_observation_record",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": observation_write,
            "expected_revision": action_revision,
            "action_lease_id": action_lease_id,
            "item_id": acceptance_ids[0],
            "tool_name": "phase_l2_deterministic_probe",
            "observation": "daemon owns the receipted task mutation",
            "status": "passed",
            "scope": format!("eliot/task/{task_id}/acceptance/{}", acceptance_ids[0]),
            "provenance_handles": [receipt_id(&allowed_action)?],
            "provenance_set_hash": provenance_set_hash
        }),
    )?;
    assert_eq!(
        observed.get("status").and_then(Value::as_str),
        Some("observed_candidate")
    );
    let observation_revision = task_revision(&observed)?;
    let observation_id = observed
        .get("observation_id")
        .and_then(Value::as_str)
        .ok_or("observation id missing")?
        .to_owned();

    for (id, verifier_ref, config_hash, worktree_ref, artifact_paths, label) in [
        (
            52,
            dogfood_verifier_ref.clone(),
            receipt_verifier_config_hash.clone(),
            None,
            Vec::<String>::new(),
            "verifier changed after lease",
        ),
        (
            53,
            receipt_verifier_ref.clone(),
            "stale-config-hash".to_owned(),
            None,
            Vec::<String>::new(),
            "stale verifier config",
        ),
        (
            54,
            receipt_verifier_ref.clone(),
            receipt_verifier_config_hash.clone(),
            Some(runtime.path().display().to_string()),
            vec!["wrong-artifact".to_owned()],
            "caller-authored worktree scope",
        ),
    ] {
        let denied = facade.tool_call(
            id,
            "eliot_task_verification_run",
            &serde_json::json!({
                "project_id": project_id,
                "task_id": task_id,
                "write_id": WriteId::new_v7().to_string(),
                "expected_revision": observation_revision,
                "item_id": acceptance_ids[1],
                "observation_id": observation_id,
                "mode": "registered",
                "verifier_ref": verifier_ref,
                "verifier_config_hash": config_hash,
                "provenance_set_hash": provenance_set_hash,
                "worktree_ref": worktree_ref,
                "artifact_paths": artifact_paths,
                "acceptance_item_ids": [acceptance_ids[1]]
            }),
        )?;
        assert_eq!(
            denied.get("status").and_then(Value::as_str),
            Some("denied_invalid_verifier_scope"),
            "{label} must be denied: {denied}"
        );
    }

    let wrong_observation = facade.tool_call_response(
        70,
        "eliot_task_observation_record",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": wrong_observation_write,
            "expected_revision": observation_revision,
            "action_lease_id": action_lease_id,
            "item_id": acceptance_ids[1],
            "tool_name": "phase_l2_candidate_substitution_probe",
            "observation": "candidate evidence must not satisfy a verifier item",
            "status": "passed",
            "scope": format!("eliot/task/{task_id}/acceptance/{}", acceptance_ids[1]),
            "provenance_handles": [receipt_id(&observed)?],
            "provenance_set_hash": provenance_set_hash
        }),
    )?;
    assert!(
        wrong_observation
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("invalidated"))
    );

    let verificationless_completion = facade.tool_call(
        71,
        "eliot_submit_completion_proof",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": verificationless_completion_write,
            "expected_revision": observation_revision,
            "acceptance_item_ids": acceptance_ids,
            "observation_ids": [observation_id],
            "verification_ids": []
        }),
    )?;
    assert_eq!(
        verificationless_completion
            .get("status")
            .and_then(Value::as_str),
        Some("denied_incomplete")
    );
    assert!(
        verificationless_completion
            .get("write_receipt")
            .is_some_and(Value::is_null)
    );

    let candidate_denied = facade.tool_call(
        7,
        "eliot_task_verification_run",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": candidate_write,
            "expected_revision": observation_revision,
            "item_id": acceptance_ids[1],
            "observation_id": observation_id,
            "artifact_scope": format!("task:{task_id}"),
            "mode": "candidate_assertion"
        }),
    )?;
    assert_eq!(
        candidate_denied.get("status").and_then(Value::as_str),
        Some("denied")
    );
    assert!(
        candidate_denied
            .get("write_receipt")
            .is_some_and(Value::is_null)
    );

    let verified = facade.tool_call(
        8,
        "eliot_task_verification_run",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": verification_write,
            "expected_revision": observation_revision,
            "item_id": acceptance_ids[1],
            "observation_id": observation_id,
            "mode": "registered",
            "verifier_ref": receipt_verifier_ref,
            "verifier_config_hash": receipt_verifier_config_hash,
            "provenance_set_hash": provenance_set_hash,
            "acceptance_item_ids": [acceptance_ids[1]],
            "artifact_paths": []
        }),
    )?;
    assert_eq!(
        verified.get("status").and_then(Value::as_str),
        Some("passed"),
        "unexpected verifier result: {verified}"
    );
    let verification_revision = task_revision(&verified)?;
    let verification_id = verified
        .get("verification_id")
        .and_then(Value::as_str)
        .ok_or("verification id missing")?
        .to_owned();

    let stale_response = facade.tool_call_response(
        9,
        "eliot_task_action_request",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": stale_write,
            "expected_revision": action_revision,
            "current_truth_refs": [format!("task:{task_id}@{action_revision}")],
            "provenance_handles": [receipt_id(&observed)?],
            "negative_memory_checked": true,
            "planned_action": "stale transition must not commit",
            "next_verifier": "daemon:receipt_resolution"
        }),
    )?;
    assert!(
        stale_response
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("stale task revision"))
    );

    let incomplete = facade.tool_call(
        10,
        "eliot_submit_completion_proof",
        &serde_json::json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7().to_string(),
            "expected_revision": verification_revision,
            "acceptance_item_ids": [acceptance_ids[0]],
            "observation_ids": [observation_id],
            "verification_ids": [verification_id]
        }),
    )?;
    assert_eq!(
        incomplete.get("status").and_then(Value::as_str),
        Some("denied_incomplete")
    );
    assert!(
        incomplete
            .get("uncovered_items")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
    );

    let completion_arguments = serde_json::json!({
        "project_id": project_id,
        "task_id": task_id,
        "write_id": completion_write,
        "expected_revision": verification_revision,
        "acceptance_item_ids": acceptance_ids,
        "observation_ids": [observation_id],
        "verification_ids": [verification_id]
    });
    let completed = facade.tool_call(11, "eliot_submit_completion_proof", &completion_arguments)?;
    assert_eq!(
        completed.get("decision").and_then(Value::as_str),
        Some("DONE_VERIFIED")
    );
    let final_revision = task_revision(&completed)?;
    let completion_receipt = receipt_id(&completed)?;

    facade.stop()?;
    request_daemon_stop(&config_path)?;
    daemon.wait_for_exit(Duration::from_secs(10))?;

    fs::remove_file(&runtime_report)?;
    let mut restarted_daemon = start_daemon(&config_path)?;
    wait_for_runtime_pid(
        &runtime_report,
        restarted_daemon.id(),
        Duration::from_secs(10),
    )?;
    let mut restarted_facade = McpClient::start(&config_path)?;
    restarted_facade.initialize()?;
    let resumed = restarted_facade.tool_call(
        12,
        "eliot_task_state",
        &serde_json::json!({"project_id": project_id, "task_id": task_id}),
    )?;
    assert_eq!(
        resumed
            .pointer("/task_contract/status")
            .and_then(Value::as_str),
        Some("done_verified")
    );
    assert_eq!(task_revision(&resumed)?, final_revision);

    let replay =
        restarted_facade.tool_call(13, "eliot_submit_completion_proof", &completion_arguments)?;
    assert_eq!(receipt_id(&replay)?, completion_receipt);
    assert_eq!(task_revision(&replay)?, final_revision);

    restarted_facade.stop()?;
    request_daemon_stop(&config_path)?;
    restarted_daemon.wait_for_exit(Duration::from_secs(10))?;
    database.stop()?;

    assert_no_provider_activity(runtime.path())?;
    let evidence = serde_json::json!({
        "scenario_id": "first_working_loop",
        "final_status": "DONE_VERIFIED",
        "project_id": project_id,
        "task_id": task_id,
        "revisions": {
            "created": create_revision,
            "action": action_revision,
            "observation": observation_revision,
            "verification": verification_revision,
            "final": final_revision
        },
        "receipts": {
            "create": create_receipt,
            "action": receipt_id(&allowed_action)?,
            "observation": receipt_id(&observed)?,
            "verification": receipt_id(&verified)?,
            "completion": completion_receipt
        },
        "negative_assertions": {
            "insufficient_action_denied": true,
            "candidate_observation_cannot_satisfy_verifier": true,
            "candidate_verification_denied": true,
            "verificationless_finish_denied": true,
            "stale_revision_denied": true,
            "incomplete_finish_denied": true
        },
        "restart": {"same_task": true, "same_revision": true, "idempotent_replay": true},
        "provider": {"kill_switch": true, "run_owned_artifacts": 0},
        "host_safety": {"temp_root": runtime.path(), "owned_processes_stopped": true}
    });
    println!("PHASE_L2_EVIDENCE={}", serde_json::to_string(&evidence)?);
    let runtime_path = runtime.path().to_path_buf();
    runtime.cleanup()?;
    assert!(
        !runtime_path.exists(),
        "test-owned runtime root must be removed"
    );
    Ok(())
}

struct McpClient {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    responses: Receiver<TestResult<String>>,
    reader: Option<JoinHandle<()>>,
}

impl McpClient {
    fn start(config_path: &Path) -> TestResult<Self> {
        let mut command = Command::new(binary());
        command
            .arg("--config")
            .arg(config_path)
            .arg("mcp")
            .arg("stdio")
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for variable in [
            "SURREAL_USER",
            "SURREAL_PASS",
            "ELIOT_TEST_SURREAL_BIND",
            "ELIOT_TEST_SURREAL_ENDPOINT",
            "ELIOT_TEST_SURREAL_PASSWORD_FILE",
            "ELIOT_TEST_SURREAL_STORAGE",
        ] {
            command.env_remove(variable);
        }
        let mut child = command.spawn()?;
        let stdin = child.stdin.take().ok_or("facade stdin unavailable")?;
        let stdout = child.stdout.take().ok_or("facade stdout unavailable")?;
        let (sender, responses) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut lines = std::io::BufReader::new(stdout).lines();
            loop {
                let message = match lines.next() {
                    Some(Ok(line)) => Ok(line),
                    Some(Err(error)) => Err(error.into()),
                    None => Err("facade stdout closed".into()),
                };
                let stop = message.is_err();
                if sender.send(message).is_err() || stop {
                    break;
                }
            }
        });
        Ok(Self {
            child: Some(child),
            stdin: Some(stdin),
            responses,
            reader: Some(reader),
        })
    }

    fn request(&mut self, request: &Value, timeout: Duration) -> TestResult<Value> {
        let stdin = self.stdin.as_mut().ok_or("facade stdin closed")?;
        serde_json::to_writer(&mut *stdin, &request)?;
        writeln!(stdin)?;
        stdin.flush()?;
        let line = self
            .responses
            .recv_timeout(timeout)
            .map_err(|error| format!("timed out waiting for facade response: {error}"))??;
        Ok(serde_json::from_str(&line)?)
    }

    fn initialize(&mut self) -> TestResult {
        let response = self.request(
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "phase-l2-fwl", "version": "0.1.0"}
                }
            }),
            Duration::from_secs(10),
        )?;
        if response
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str)
            != Some("2025-06-18")
        {
            return Err(format!("MCP initialize failed: {response}").into());
        }
        Ok(())
    }

    fn tool_call_response(&mut self, id: u64, name: &str, arguments: &Value) -> TestResult<Value> {
        self.request(
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments}
            }),
            Duration::from_secs(60),
        )
    }

    fn tool_call(&mut self, id: u64, name: &str, arguments: &Value) -> TestResult<Value> {
        let response = self.tool_call_response(id, name, arguments)?;
        if let Some(error) = response.get("error") {
            return Err(format!("MCP tool {name} failed: {error}").into());
        }
        let result = response.get("result").ok_or("missing MCP tool result")?;
        if result.get("isError").and_then(Value::as_bool) == Some(true) {
            return Err(format!("MCP tool {name} returned error: {result}").into());
        }
        result
            .get("structuredContent")
            .cloned()
            .ok_or_else(|| "missing MCP structuredContent".into())
    }

    fn stop(&mut self) -> TestResult {
        self.stdin.take();
        if let Some(mut child) = self.child.take() {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            let _ = child.wait()?;
        }
        if let Some(reader) = self.reader.take() {
            reader.join().map_err(|_| "facade stdout reader panicked")?;
        }
        Ok(())
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct OwnedChild {
    child: Option<Child>,
}

impl OwnedChild {
    fn spawn(command: &mut Command) -> TestResult<Self> {
        Ok(Self {
            child: Some(command.spawn()?),
        })
    }

    fn stop(&mut self) -> TestResult {
        if let Some(mut child) = self.child.take() {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            let _ = child.wait()?;
        }
        Ok(())
    }

    fn id(&self) -> u32 {
        self.child.as_ref().map_or(0, Child::id)
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> TestResult {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self
                .child
                .as_mut()
                .ok_or("owned child already consumed")?
                .try_wait()?
                .is_some()
            {
                self.child.take();
                return Ok(());
            }
            thread::sleep(Duration::from_millis(25));
        }
        self.stop()?;
        Err("owned child did not stop before deadline".into())
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct OwnedRuntime {
    path: PathBuf,
}

impl OwnedRuntime {
    fn new(label: &str) -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let temp = std::env::temp_dir();
        let path = temp.join(format!(
            "eliot-governor-phase-l2-{label}-{}-{nonce}",
            std::process::id()
        ));
        let lower = path.to_string_lossy().to_ascii_lowercase();
        assert!(path.starts_with(&temp), "runtime must descend from TEMP");
        assert!(!lower.contains("onedrive"), "runtime must not use OneDrive");
        assert!(
            !lower.contains("programdata"),
            "runtime must not use ProgramData"
        );
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn cleanup(&mut self) -> TestResult {
        if self.path.starts_with(std::env::temp_dir()) && self.path.exists() {
            fs::remove_dir_all(&self.path)?;
        }
        Ok(())
    }
}

impl Drop for OwnedRuntime {
    fn drop(&mut self) {
        if self.path.starts_with(std::env::temp_dir()) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn wait_for_json(path: &Path, timeout: Duration) -> TestResult<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.is_file() {
            return Ok(serde_json::from_reader(fs::File::open(path)?)?);
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for {}", path.display()).into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_changed_json_string(
    path: &Path,
    pointer: &str,
    previous: &str,
    timeout: Duration,
) -> TestResult<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.is_file()
            && let Ok(value) = serde_json::from_reader::<_, Value>(fs::File::open(path)?)
            && value.pointer(pointer).and_then(Value::as_str) != Some(previous)
        {
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for changed {pointer} in {}",
                path.display()
            )
            .into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn required_string(value: &Value, pointer: &str) -> TestResult<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing string {pointer} in {value}").into())
}

fn required_u64(value: &Value, pointer: &str) -> TestResult<u64> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing u64 {pointer} in {value}").into())
}

fn registered_verifier(packet: &Value, verifier_id: &str) -> TestResult<(String, String)> {
    let descriptor = packet
        .get("registered_verifiers")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("verifier_id").and_then(Value::as_str) == Some(verifier_id))
        })
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            format!("registered verifier {verifier_id} missing from packet").into()
        })?;
    Ok((
        required_string(descriptor, "/verifier_ref")?,
        required_string(descriptor, "/config_hash")?,
    ))
}

#[cfg(windows)]
fn authenticated_handshake(auth: &Value, token: &str, nonce: &str) -> TestResult<Value> {
    Ok(serde_json::json!({
        "kind": "eliot_ipc_handshake",
        "protocol_version": required_string(auth, "/protocol_version")?,
        "instance_name": required_string(auth, "/instance_name")?,
        "runtime_id": required_string(auth, "/runtime_id")?,
        "token": token,
        "token_generation_id": required_string(auth, "/token_generation_id")?,
        "client_nonce": nonce,
        "profile": "codex_controller"
    }))
}

#[cfg(windows)]
fn raw_pipe_exchange(
    pipe_name: &str,
    handshake: &Value,
    request: Option<&Value>,
) -> TestResult<Vec<Value>> {
    raw_pipe_exchange_line(pipe_name, &serde_json::to_string(handshake)?, request)
}

#[cfg(windows)]
fn raw_pipe_exchange_line(
    pipe_name: &str,
    first_line: &str,
    request: Option<&Value>,
) -> TestResult<Vec<Value>> {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let client = loop {
            match ClientOptions::new().open(pipe_name) {
                Ok(client) => break client,
                Err(error) if tokio::time::Instant::now() < deadline => {
                    let _ = error;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(error.into()),
            }
        };
        let (reader, mut writer) = tokio::io::split(client);
        let mut reader = BufReader::new(reader);
        writer.write_all(first_line.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        let mut responses = Vec::new();
        let mut line = String::new();
        let read = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .map_err(|_| "timed out waiting for raw pipe handshake result")??;
        if read == 0 {
            return Err("raw pipe closed without a handshake result".into());
        }
        responses.push(serde_json::from_str(&line)?);

        if responses
            .first()
            .and_then(|value: &Value| value.get("accepted"))
            .and_then(Value::as_bool)
            == Some(true)
            && let Some(request) = request
        {
            writer
                .write_all(serde_json::to_string(request)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            line.clear();
            let read = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
                .await
                .map_err(|_| "timed out waiting for authenticated pipe response")??;
            if read == 0 {
                return Err("authenticated pipe closed without an MCP response".into());
            }
            responses.push(serde_json::from_str(&line)?);
        }
        Ok(responses)
    })
}

#[cfg(windows)]
fn assert_handshake_rejected(response: &[Value], expected_reason: &str) -> TestResult {
    let result = response.first().ok_or("missing handshake rejection")?;
    assert_eq!(result.get("accepted").and_then(Value::as_bool), Some(false));
    assert_eq!(
        result.get("reason").and_then(Value::as_str),
        Some(expected_reason)
    );
    assert!(result.get("session_id").is_none_or(Value::is_null));
    Ok(())
}

#[cfg(windows)]
fn assert_restricted_runtime_acl(path: &Path) -> TestResult {
    let output = Command::new("icacls.exe").arg(path).output()?;
    if !output.status.success() {
        return Err(format!(
            "icacls failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let acl = String::from_utf8(output.stdout)?.to_ascii_lowercase();
    assert!(
        !acl.contains("(i)"),
        "runtime root must not inherit ambient ACL entries: {acl}"
    );
    for broad_identity in ["everyone", "builtin\\users", "authenticated users"] {
        assert!(
            !acl.contains(broad_identity),
            "runtime ACL must not grant {broad_identity}: {acl}"
        );
    }
    Ok(())
}

fn free_local_port() -> TestResult<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn start_surreal(runtime: &Path, port: u16) -> TestResult<OwnedChild> {
    let storage = format!("rocksdb:{}", slash(&runtime.join("surrealdb-rocks")));
    OwnedChild::spawn(
        Command::new("surreal")
            .env("SURREAL_USER", "root")
            .env("SURREAL_PASS", std::env::var("SURREAL_PASS")?)
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .arg("start")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--log")
            .arg("warn")
            .arg("--deny-all")
            .arg("--allow-funcs")
            .arg("array,string,time,type,math,vector,search")
            .arg("--deny-net")
            .arg("--")
            .arg(storage)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
}

fn wait_for_tcp(port: u16, timeout: Duration) -> TestResult {
    let deadline = Instant::now() + timeout;
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for isolated SurrealDB on port {port}").into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn start_daemon(config_path: &Path) -> TestResult<OwnedChild> {
    OwnedChild::spawn(
        Command::new(binary())
            .arg("--config")
            .arg(config_path)
            .arg("daemon")
            .arg("run")
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .env(
                "ELIOT_TEST_SURREAL_PASSWORD_FILE",
                test_password_file(config_path)?,
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit()),
    )
}

fn start_daemon_logged(config_path: &Path, log_path: &Path) -> TestResult<OwnedChild> {
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    OwnedChild::spawn(
        Command::new(binary())
            .arg("--config")
            .arg(config_path)
            .arg("daemon")
            .arg("run")
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .env(
                "ELIOT_TEST_SURREAL_PASSWORD_FILE",
                test_password_file(config_path)?,
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log)),
    )
}

fn request_daemon_stop(config_path: &Path) -> TestResult {
    let output = Command::new(binary())
        .arg("--config")
        .arg(config_path)
        .arg("daemon")
        .arg("stop")
        .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
        .env(
            "ELIOT_TEST_SURREAL_PASSWORD_FILE",
            test_password_file(config_path)?,
        )
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "daemon stop failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

fn wait_for_runtime_pid(path: &Path, pid: u32, timeout: Duration) -> TestResult<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.is_file()
            && let Ok(value) = serde_json::from_reader::<_, Value>(fs::File::open(path)?)
            && value.pointer("/status/pid").and_then(Value::as_u64) == Some(u64::from(pid))
            && value
                .pointer("/status/ipc_enabled")
                .and_then(Value::as_bool)
                == Some(true)
        {
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Err(
                format!("timed out waiting for daemon runtime report for PID {pid}").into(),
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn task_revision(value: &Value) -> TestResult<u64> {
    value
        .pointer("/task_contract/memory_revision")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("task revision missing from {value}").into())
}

fn receipt_id(value: &Value) -> TestResult<String> {
    value
        .pointer("/write_receipt/receipt_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("write receipt missing from {value}").into())
}

fn assert_no_provider_activity(runtime: &Path) -> TestResult {
    for relative in [
        "runtime/provider-call-ledger.json",
        "runtime/provider-invocations",
        "spool/provider-invocations",
        "reports/phase-l1c-provider-review",
    ] {
        if runtime.join(relative).exists() {
            return Err(
                format!("provider artifact appeared in run-owned runtime: {relative}").into(),
            );
        }
    }
    Ok(())
}

fn test_password_file(_config_path: &Path) -> TestResult<String> {
    Ok(std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE")?)
}

fn write_test_config(runtime: &Path, config_path: &Path, port: u16) -> TestResult {
    fs::create_dir_all(config_path.parent().ok_or("config parent missing")?)?;
    let password_file = std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE")?;
    let storage = slash(&runtime.join("surrealdb-rocks"));
    let wal = slash(&runtime.join("control").join("control.redb"));
    let blobs = slash(&runtime.join("blobs"));
    let repo = repository_root()?;
    let surql = slash(&repo.join("crates/eliot-store/src/surql"));
    let migrations = slash(&repo.join("crates/eliot-store/migrations"));
    let config = format!(
        r#"schema_version = "1"

[service]
service_name = "EliotGovernorPhaseL2"
instance_id = "phase-l2-test"

[db]
mode = "surreal_rpc_server"

[db.surreal]
exe = "surreal"
bind = "127.0.0.1:{port}"
endpoint = "ws://127.0.0.1:{port}/rpc"
storage = "rocksdb:{storage}"
ns = "eliot_phase_l2"
db = "first_working_loop"
user = "root"
credential_provider = "legacy_password_file"
credential_id = "test-only/phase-l2"
password_file = "{password_file}"
log_level = "warn"
query_timeout_ms = 15000
transaction_timeout_ms = 15000
startup_timeout_ms = 20000
restart_backoff_ms = 200
max_restart_backoff_ms = 2000

[db.surreal.capabilities]
deny_all = true
allow_funcs = ["array", "string", "time", "type", "math", "vector", "search"]
allow_net = []
allow_scripting = false
allow_guests = false

[control_wal]
path = "{wal}"

[blob_store]
root = "{blobs}"

[store]
surql_dir = "{surql}"
migrations_dir = "{migrations}"
"#
    );
    fs::write(config_path, config)?;
    Ok(())
}

fn repository_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("repository root missing")?
        .to_path_buf())
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_eliot-governor"))
}
