use eliot_engine::{
    computed_provider_runtime_contract_sha256, normalize_provider_runtime_contract,
    seal_provider_runtime_contract, validate_provider_runtime_contract,
};
use eliot_types::{
    AgentHostId, ExternalAgentPurpose, PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION,
    ProviderMcpServerContract, ProviderRuntimeContract, ProviderStructuredOutputMode,
};
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
