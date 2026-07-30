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
pub struct OpenCodeCommandInput {
    pub requested_model: String,
    pub workspace: String,
    pub prompt: String,
    pub read_only: bool,
}

pub fn build_opencode_command(
    input: &OpenCodeCommandInput,
) -> Result<ProviderCommandPlan, EngineError> {
    if input.requested_model.trim().is_empty()
        || input.workspace.trim().is_empty()
        || input.prompt.trim().is_empty()
    {
        return rejected("OpenCode command input is incomplete");
    }
    let argv = vec![
        "run".to_owned(),
        "--format".to_owned(),
        "json".to_owned(),
        "--agent".to_owned(),
        if input.read_only { "plan" } else { "build" }.to_owned(),
        "--dir".to_owned(),
        input.workspace.clone(),
        "--model".to_owned(),
        input.requested_model.clone(),
        "--".to_owned(),
        input.prompt.clone(),
    ];
    Ok(ProviderCommandPlan {
        argv,
        nonsecret_environment: BTreeMap::new(),
        structured_output_mode: ProviderStructuredOutputMode::NativeJson,
        model_selection_mechanism: "cli_flag:--model".to_owned(),
    })
}

pub fn parse_opencode_stream(
    stdout: &[u8],
    requested_model: &str,
    schema: &Value,
) -> Result<ProviderTerminalResult, EngineError> {
    let events = json_events(stdout)?;
    let session = events
        .iter()
        .find(|event| event.get("type").and_then(Value::as_str) == Some("session.start"))
        .ok_or_else(|| {
            EngineError::WriteRejected("OpenCode stream has no session.start event".to_owned())
        })?;
    let resolved_model = exact_requested_model(
        first_string(session, &["model", "model_id", "modelId"]),
        requested_model,
    )?;
    let provider_session_id =
        first_string(session, &["session_id", "sessionId"]).ok_or_else(|| {
            EngineError::WriteRejected("OpenCode session.start has no session ID".to_owned())
        })?;
    let outputs = events
        .iter()
        .filter_map(|event| {
            (event.get("type").and_then(Value::as_str) == Some("text"))
                .then(|| {
                    event
                        .get("part")
                        .and_then(|part| part.get("text"))
                        .and_then(Value::as_str)
                })
                .flatten()
        })
        .filter_map(|text| serde_json::from_str::<Value>(text).ok())
        .collect::<Vec<_>>();
    if outputs.len() != 1 {
        return rejected(format!(
            "OpenCode stream must contain exactly one structured text result, found {}",
            outputs.len()
        ));
    }
    let structured_output = outputs[0].clone();
    validate_json_schema_instance(schema, &structured_output)?;
    Ok(ProviderTerminalResult {
        structured_output,
        resolved_model,
        provider_session_id,
        terminal_status: "stream_complete".to_owned(),
        observed_tool_names: observed_tool_names(&events),
        token_or_cost_telemetry: None,
    })
}
