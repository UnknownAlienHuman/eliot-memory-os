use eliot_types::{
    CognitiveProviderRuntimeContract, ExternalAgentPurpose,
    LEGACY_COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION, PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION,
    ProviderMcpServerContract, ProviderRuntimeContract, ProviderStructuredOutputMode,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn external_agent_legacy_cognitive_runtime_remains_readable() -> TestResult {
    let legacy = json!({
        "schema_version": LEGACY_COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION,
        "host": "codex",
        "provider_executable": "C:\\tools\\codex.exe",
        "provider_executable_sha256": "a".repeat(64),
        "provider_cwd": "C:\\work",
        "provider_argv": ["exec"],
        "nonsecret_environment": {},
        "mcp_servers": [],
        "expected_mcp_tool_names": [],
        "forbidden_mcp_server_names": ["eliot_surrealdb"],
        "runtime_contract_sha256": "b".repeat(64)
    });
    let decoded: CognitiveProviderRuntimeContract = serde_json::from_value(legacy)?;
    assert_eq!(
        decoded.schema_version,
        LEGACY_COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION
    );
    Ok(())
}

#[test]
fn external_agent_generic_runtime_serializes_source_owned_schema() -> TestResult {
    let contract = ProviderRuntimeContract {
        schema_version: PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION.to_owned(),
        host: eliot_types::AgentHostId::Claude,
        purpose: ExternalAgentPurpose::ExternalAudit,
        provider_executable: "C:\\tools\\claude.exe".to_owned(),
        provider_executable_sha256: "a".repeat(64),
        provider_version: "1.0.0".to_owned(),
        requested_model: "opus".to_owned(),
        model_selection_mechanism: "cli_flag".to_owned(),
        provider_cwd: "C:\\work".to_owned(),
        provider_argv: vec!["--print".to_owned()],
        nonsecret_environment: BTreeMap::new(),
        mcp_servers: vec![ProviderMcpServerContract {
            name: "eliot-governor".to_owned(),
            command: "C:\\tools\\eliot-governor.exe".to_owned(),
            args: vec!["mcp".to_owned(), "stdio".to_owned()],
            cwd: "C:\\work".to_owned(),
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
        provider_route_policy: eliot_types::ProviderRoutePolicyBinding {
            policy_id: "provider-timeout:claude".to_owned(),
            policy_hash_blake3: "e".repeat(64),
        },
        process_containment: "windows_job_object".to_owned(),
        candidate_only: true,
        runtime_contract_sha256: "d".repeat(64),
    };
    let value = serde_json::to_value(contract)?;
    assert_eq!(
        value["schema_version"],
        PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(value["candidate_only"], true);
    Ok(())
}
