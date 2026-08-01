use super::structured_output::{
    exact_requested_model, first_string, json_events, observed_tool_names,
    validate_json_schema_instance,
};
use super::{ProviderCommandPlan, ProviderTerminalResult, rejected};
use crate::EngineError;
use eliot_types::ProviderStructuredOutputMode;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct ClaudeCodeCommandInput {
    pub requested_model: String,
    pub output_schema: Value,
    pub mcp_config_path: String,
    pub allowed_tools: Vec<String>,
    pub denied_tools: Vec<String>,
    pub max_turns: u32,
    pub prompt: String,
}

pub fn build_claude_code_command(
    input: &ClaudeCodeCommandInput,
) -> Result<ProviderCommandPlan, EngineError> {
    if input.requested_model.trim().is_empty()
        || input.mcp_config_path.trim().is_empty()
        || input.max_turns == 0
        || input.prompt.trim().is_empty()
    {
        return rejected("Claude Code command input is incomplete");
    }
    let schema = serde_json::to_string(&input.output_schema)?;
    let mut argv = vec![
        "-p".to_owned(),
        "--model".to_owned(),
        input.requested_model.clone(),
        "--output-format".to_owned(),
        "stream-json".to_owned(),
        "--verbose".to_owned(),
        "--json-schema".to_owned(),
        schema,
        "--mcp-config".to_owned(),
        input.mcp_config_path.clone(),
        "--strict-mcp-config".to_owned(),
    ];
    if !input.allowed_tools.is_empty() {
        argv.extend(["--allowedTools".to_owned(), input.allowed_tools.join(",")]);
    }
    if !input.denied_tools.is_empty() {
        argv.extend(["--disallowedTools".to_owned(), input.denied_tools.join(",")]);
    }
    argv.extend([
        "--max-turns".to_owned(),
        input.max_turns.to_string(),
        "--no-session-persistence".to_owned(),
        "--".to_owned(),
        input.prompt.clone(),
    ]);
    Ok(ProviderCommandPlan {
        argv,
        nonsecret_environment: BTreeMap::new(),
        structured_output_mode: ProviderStructuredOutputMode::NativeJsonSchema,
        model_selection_mechanism: "cli_flag:--model".to_owned(),
    })
}

pub fn parse_claude_code_stream(
    stdout: &[u8],
    requested_model: &str,
    schema: &Value,
) -> Result<ProviderTerminalResult, EngineError> {
    let events = json_events(stdout)?;
    let terminals = events
        .iter()
        .filter(|event| event.get("type").and_then(Value::as_str) == Some("result"))
        .collect::<Vec<_>>();
    if terminals.len() != 1 {
        return rejected(format!(
            "Claude stream must contain exactly one terminal result event, found {}",
            terminals.len()
        ));
    }
    let terminal = terminals[0];
    let subtype = terminal
        .get("subtype")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if subtype != "success" || terminal.get("is_error") == Some(&Value::Bool(true)) {
        return rejected(format!(
            "Claude terminal state is not recognized as success: {subtype}"
        ));
    }
    let structured_output = terminal.get("structured_output").cloned().ok_or_else(|| {
        EngineError::WriteRejected(
            "Claude terminal result has no structured_output field".to_owned(),
        )
    })?;
    validate_json_schema_instance(schema, &structured_output)?;

    let observed_model = terminal
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            terminal
                .get("modelUsage")
                .and_then(Value::as_object)
                .filter(|models| models.len() == 1)
                .and_then(|models| models.keys().next().cloned())
        })
        .or_else(|| first_string(terminal, &["resolved_model", "model_id", "modelId"]));
    let resolved_model = exact_requested_model(observed_model, requested_model)?;
    let provider_session_id =
        first_string(terminal, &["session_id", "sessionId"]).ok_or_else(|| {
            EngineError::WriteRejected(
                "Claude terminal result did not attest a session ID".to_owned(),
            )
        })?;
    let token_or_cost_telemetry = terminal
        .get("usage")
        .or_else(|| terminal.get("modelUsage"))
        .map(serde_json::to_string)
        .transpose()?;
    Ok(ProviderTerminalResult {
        structured_output,
        resolved_model,
        provider_session_id,
        terminal_status: format!("result:{subtype}"),
        observed_tool_names: observed_tool_names(&events),
        token_or_cost_telemetry,
    })
}
