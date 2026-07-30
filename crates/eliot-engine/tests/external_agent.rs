use eliot_engine::{
    AntigravityCommandInput, ClaudeCodeCommandInput, build_antigravity_command,
    build_claude_code_command, computed_provider_runtime_contract_sha256,
    normalize_provider_runtime_contract, parse_antigravity_output, parse_claude_code_stream,
    seal_provider_runtime_contract, validate_provider_runtime_contract,
};
use eliot_types::{
    AgentHostId, ExternalAgentPurpose, PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION,
    ProviderMcpServerContract, ProviderRuntimeContract, ProviderStructuredOutputMode,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn external_agent_runtime_hash_covers_every_load_bearing_field() -> TestResult {
    let mut contract = fixture();
    seal_provider_runtime_contract(&mut contract)?;
    let original = contract.runtime_contract_sha256.clone();

    contract.requested_model.push_str("-changed");
    assert_ne!(
        computed_provider_runtime_contract_sha256(&contract)?,
        original
    );
    Ok(())
}

#[test]
fn external_agent_runtime_normalizes_sets_but_preserves_argv_order() {
    let mut contract = fixture();
    contract.expected_mcp_tool_names = vec!["z".to_owned(), "a".to_owned(), "a".to_owned()];
    contract.provider_argv = vec!["second".to_owned(), "first".to_owned()];
    normalize_provider_runtime_contract(&mut contract);
    assert_eq!(contract.expected_mcp_tool_names, ["a", "z"]);
    assert_eq!(contract.provider_argv, ["second", "first"]);
}

#[test]
fn external_agent_runtime_rejects_raw_database_and_secret_environment() -> TestResult {
    let mut contract = fixture();
    seal_provider_runtime_contract(&mut contract)?;

    contract.allowed_provider_tools = vec!["mcp__eliot_surrealdb__query".to_owned()];
    assert!(seal_provider_runtime_contract(&mut contract).is_err());

    let mut contract = fixture();
    contract
        .nonsecret_environment
        .insert("API_TOKEN".to_owned(), "redacted".to_owned());
    assert!(seal_provider_runtime_contract(&mut contract).is_err());
    Ok(())
}

#[test]
fn external_agent_runtime_rejects_hash_mismatch() -> TestResult {
    let mut contract = fixture();
    seal_provider_runtime_contract(&mut contract)?;
    contract.provider_argv.push("--changed".to_owned());
    assert!(validate_provider_runtime_contract(&contract).is_err());
    Ok(())
}

#[test]
fn claude_command_and_terminal_parser_are_exact_and_fail_closed() -> TestResult {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["status", "resolved_model"],
        "properties": {
            "status": {"const": "ready"},
            "resolved_model": {"const": "claude-opus-5"}
        }
    });
    let plan = build_claude_code_command(&ClaudeCodeCommandInput {
        requested_model: "claude-opus-5".to_owned(),
        output_schema: schema.clone(),
        mcp_config_path: r"C:\runtime\mcp.json".to_owned(),
        allowed_tools: vec!["mcp__eliot-governor__current_state".to_owned()],
        denied_tools: vec!["Bash".to_owned(), "Write".to_owned()],
        max_turns: 2,
        prompt: "Call current_state once.".to_owned(),
    })?;
    assert_eq!(plan.argv.first().map(String::as_str), Some("-p"));
    assert_eq!(
        plan.argv
            .windows(2)
            .filter(|pair| pair[0] == "--mcp-config")
            .count(),
        1
    );
    assert!(plan.argv.iter().any(|arg| arg == "--strict-mcp-config"));
    assert!(plan.argv.iter().any(|arg| arg == "--disallowedTools"));
    assert!(!plan.argv.iter().any(|arg| arg.contains("Claude.exe")));

    let stream = concat!(
        "{\"type\":\"assistant\",\"output\":{\"status\":\"wrong-intermediate\"}}\n",
        "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,",
        "\"session_id\":\"claude-session-1\",\"model\":\"claude-opus-5\",",
        "\"structured_output\":{\"status\":\"ready\",\"resolved_model\":\"claude-opus-5\"}}\n"
    );
    let parsed = parse_claude_code_stream(stream.as_bytes(), "claude-opus-5", &schema)?;
    assert_eq!(parsed.provider_session_id, "claude-session-1");
    assert!(parse_claude_code_stream(stream.as_bytes(), "claude-opus-5.1", &schema).is_err());
    let unknown = stream.replace("\"success\"", "\"future_terminal\"");
    assert!(parse_claude_code_stream(unknown.as_bytes(), "claude-opus-5", &schema).is_err());
    let wrong_schema = stream.replace("\"ready\"", "\"not-ready\"");
    assert!(parse_claude_code_stream(wrong_schema.as_bytes(), "claude-opus-5", &schema).is_err());
    Ok(())
}

#[test]
fn antigravity_command_and_sentinel_parser_are_exact_and_fail_closed() -> TestResult {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["status", "resolved_model", "provider_session_id"],
        "properties": {
            "status": {"const": "ready"},
            "resolved_model": {"const": "gemini-3.6-flash-high"},
            "provider_session_id": {"type": "string", "minLength": 1}
        }
    });
    let plan = build_antigravity_command(&AntigravityCommandInput {
        requested_model: "gemini-3.6-flash-high".to_owned(),
        workspace: r"C:\worktree".to_owned(),
        output_schema: schema.clone(),
        max_runtime_seconds: 120,
        prompt: "Return readiness.".to_owned(),
        native_json_schema: false,
        read_only: true,
    })?;
    assert!(plan.argv.iter().any(|arg| arg == "--new-project"));
    assert!(plan.argv.iter().any(|arg| arg == "--sandbox"));
    assert!(!plan.argv.iter().any(|arg| arg == "--agent"));
    assert_eq!(
        plan.nonsecret_environment
            .get("AGY_CLI_DISABLE_AUTO_UPDATE")
            .map(String::as_str),
        Some("1")
    );
    let output = concat!(
        "provider log retained outside result\n",
        "BEGIN_ELIOT_RESULT\n",
        "{\"status\":\"ready\",\"resolved_model\":\"gemini-3.6-flash-high\",",
        "\"provider_session_id\":\"agy-session-1\"}\n",
        "END_ELIOT_RESULT\n"
    );
    let parsed = parse_antigravity_output(
        output.as_bytes(),
        "gemini-3.6-flash-high",
        &schema,
        ProviderStructuredOutputMode::SentinelJson,
    )?;
    assert_eq!(parsed.provider_session_id, "agy-session-1");
    assert!(
        parse_antigravity_output(
            b"gemini-3.6-flash-high",
            "gemini-3.6-flash-high",
            &schema,
            ProviderStructuredOutputMode::SentinelJson,
        )
        .is_err()
    );
    let duplicate = format!("{output}{output}");
    assert!(
        parse_antigravity_output(
            duplicate.as_bytes(),
            "gemini-3.6-flash-high",
            &schema,
            ProviderStructuredOutputMode::SentinelJson,
        )
        .is_err()
    );

    let native_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["status", "resolved_model"],
        "properties": {
            "status": {"const": "ready"},
            "resolved_model": {"const": "gemini-3.6-flash-high"}
        }
    });
    let native_stream = concat!(
        "{\"event\":\"init\",\"conversation_id\":\"agy-conversation-1\",",
        "\"init\":{\"model\":\"gemini-3.6-flash-high\"}}\n",
        "{\"event\":\"step_update\",\"step_update\":{\"step_type\":\"tool\",",
        "\"tool_name\":\"call_mcp_tool\",\"tool_info\":{\"parameters\":{",
        "\"ServerName\":\"eliot-governor\",\"ToolName\":\"eliot_current_state\"}}}}\n",
        "{\"event\":\"result\",\"result\":{\"conversation_id\":\"agy-conversation-1\",",
        "\"status\":\"SUCCESS\",\"structured_output\":{\"status\":\"ready\",",
        "\"resolved_model\":\"gemini-3.6-flash-high\"}}}\n"
    );
    let native = parse_antigravity_output(
        native_stream.as_bytes(),
        "gemini-3.6-flash-high",
        &native_schema,
        ProviderStructuredOutputMode::NativeJsonSchema,
    )?;
    assert_eq!(native.provider_session_id, "agy-conversation-1");
    assert_eq!(
        native.observed_tool_names,
        vec!["eliot_current_state".to_owned()]
    );
    Ok(())
}

fn fixture() -> ProviderRuntimeContract {
    ProviderRuntimeContract {
        schema_version: PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION.to_owned(),
        host: AgentHostId::Claude,
        purpose: ExternalAgentPurpose::ExternalAudit,
        provider_executable: r"C:\tools\claude.exe".to_owned(),
        provider_executable_sha256: "a".repeat(64),
        provider_version: "1.0.0".to_owned(),
        requested_model: "opus".to_owned(),
        model_selection_mechanism: "cli_flag".to_owned(),
        provider_cwd: r"C:\work".to_owned(),
        provider_argv: vec![
            "--print".to_owned(),
            "--model".to_owned(),
            "opus".to_owned(),
        ],
        nonsecret_environment: BTreeMap::new(),
        mcp_servers: vec![ProviderMcpServerContract {
            name: "eliot-governor".to_owned(),
            command: r"C:\tools\eliot-governor.exe".to_owned(),
            args: vec!["mcp".to_owned(), "stdio".to_owned()],
            cwd: r"C:\work".to_owned(),
            required: true,
            enabled: true,
            executable_sha256: "b".repeat(64),
            build_source_commit: None,
        }],
        expected_mcp_tool_names: vec!["eliot_host_session_status".to_owned()],
        forbidden_mcp_server_names: vec!["eliot_surrealdb".to_owned()],
        allowed_provider_tools: vec!["mcp__eliot-governor__eliot_host_session_status".to_owned()],
        denied_provider_tools: vec!["raw_shell".to_owned()],
        permission_profile: "external_read_only".to_owned(),
        structured_output_mode: ProviderStructuredOutputMode::NativeJsonSchema,
        output_schema_sha256: "c".repeat(64),
        timeout_profile_ref: "provider-timeout:claude".to_owned(),
        process_containment: "windows_job_object".to_owned(),
        candidate_only: true,
        runtime_contract_sha256: String::new(),
    }
}
