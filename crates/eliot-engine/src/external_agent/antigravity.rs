use super::structured_output::{
    exact_requested_model, first_string, json_events, observed_tool_names,
    validate_json_schema_instance,
};
use super::{ProviderCommandPlan, ProviderTerminalResult, rejected};
use crate::EngineError;
use eliot_types::ProviderStructuredOutputMode;
use serde_json::Value;
use std::collections::BTreeMap;

const BEGIN_MARKER: &str = "BEGIN_ELIOT_RESULT";
const END_MARKER: &str = "END_ELIOT_RESULT";

#[derive(Clone, Debug)]
pub struct AntigravityCommandInput {
    pub requested_model: String,
    pub workspace: String,
    pub output_schema: Value,
    pub max_runtime_seconds: u64,
    pub prompt: String,
    pub native_json_schema: bool,
    pub read_only: bool,
}

pub fn build_antigravity_command(
    input: &AntigravityCommandInput,
) -> Result<ProviderCommandPlan, EngineError> {
    if input.requested_model.trim().is_empty()
        || input.workspace.trim().is_empty()
        || input.max_runtime_seconds == 0
        || input.prompt.trim().is_empty()
    {
        return rejected("Antigravity command input is incomplete");
    }
    let mut argv = vec![
        "--new-project".to_owned(),
        "--add-dir".to_owned(),
        input.workspace.clone(),
        "--sandbox".to_owned(),
        "--model".to_owned(),
        input.requested_model.clone(),
        "--print-timeout".to_owned(),
        format!("{}s", input.max_runtime_seconds),
    ];
    if input.read_only {
        argv.extend(["--mode".to_owned(), "plan".to_owned()]);
    } else {
        argv.extend(["--mode".to_owned(), "accept-edits".to_owned()]);
    }
    let structured_output_mode = if input.native_json_schema {
        argv.extend([
            "--output-format".to_owned(),
            "stream-json".to_owned(),
            "--json-schema".to_owned(),
            serde_json::to_string(&input.output_schema)?,
        ]);
        ProviderStructuredOutputMode::NativeJsonSchema
    } else {
        argv.extend(["--output-format".to_owned(), "text".to_owned()]);
        ProviderStructuredOutputMode::SentinelJson
    };
    let prompt = if input.native_json_schema {
        input.prompt.clone()
    } else {
        format!(
            "{}\nReturn exactly one JSON result between marker lines:\n{BEGIN_MARKER}\n<JSON>\n{END_MARKER}",
            input.prompt
        )
    };
    argv.extend(["--print".to_owned(), prompt]);
    let mut nonsecret_environment = BTreeMap::new();
    nonsecret_environment.insert("AGY_CLI_DISABLE_AUTO_UPDATE".to_owned(), "1".to_owned());
    nonsecret_environment.insert("AGY_CLI_HIDE_ACCOUNT_INFO".to_owned(), "1".to_owned());
    if input.read_only {
        nonsecret_environment.insert("ELIOT_PROVIDER_READ_ONLY".to_owned(), "1".to_owned());
    }
    Ok(ProviderCommandPlan {
        argv,
        nonsecret_environment,
        structured_output_mode,
        model_selection_mechanism: "cli_flag:--model".to_owned(),
    })
}

pub fn parse_antigravity_output(
    stdout: &[u8],
    requested_model: &str,
    schema: &Value,
    mode: ProviderStructuredOutputMode,
) -> Result<ProviderTerminalResult, EngineError> {
    let (structured_output, events) = match mode {
        ProviderStructuredOutputMode::SentinelJson => (parse_sentinel(stdout)?, Vec::new()),
        ProviderStructuredOutputMode::NativeJsonSchema
        | ProviderStructuredOutputMode::NativeJson => parse_native(stdout)?,
    };
    validate_json_schema_instance(schema, &structured_output)?;
    let resolved_model = exact_requested_model(
        first_string(
            &structured_output,
            &["resolved_model", "model", "model_id", "modelId"],
        )
        .or_else(|| {
            events
                .iter()
                .find_map(|event| first_string(event, &["model", "model_id", "modelId"]))
        }),
        requested_model,
    )?;
    let provider_session_id = first_string(
        &structured_output,
        &[
            "provider_session_id",
            "host_session_id",
            "session_id",
            "sessionId",
            "conversation_id",
        ],
    )
    .or_else(|| {
        events
            .iter()
            .find_map(|event| first_string(event, &["session_id", "sessionId", "conversation_id"]))
    })
    .ok_or_else(|| {
        EngineError::WriteRejected(
            "Antigravity result did not attest a provider session ID".to_owned(),
        )
    })?;
    Ok(ProviderTerminalResult {
        structured_output,
        resolved_model,
        provider_session_id,
        terminal_status: match mode {
            ProviderStructuredOutputMode::SentinelJson => "sentinel_json".to_owned(),
            _ => "native_json".to_owned(),
        },
        observed_tool_names: observed_tool_names(&events),
        token_or_cost_telemetry: None,
    })
}

fn parse_sentinel(stdout: &[u8]) -> Result<Value, EngineError> {
    let text = std::str::from_utf8(stdout)
        .map_err(|_| EngineError::WriteRejected("Antigravity output is not UTF-8".to_owned()))?;
    let starts = text.match_indices(BEGIN_MARKER).collect::<Vec<_>>();
    let ends = text.match_indices(END_MARKER).collect::<Vec<_>>();
    if starts.len() != 1 || ends.len() != 1 || starts[0].0 >= ends[0].0 {
        return rejected(format!(
            "Antigravity sentinel output requires one ordered marker pair; begin={} end={}",
            starts.len(),
            ends.len()
        ));
    }
    let start = starts[0].0 + BEGIN_MARKER.len();
    let value = serde_json::from_str::<Value>(text[start..ends[0].0].trim())?;
    if !value.is_object() {
        return rejected("Antigravity sentinel payload is not one JSON object");
    }
    Ok(value)
}

fn parse_native(stdout: &[u8]) -> Result<(Value, Vec<Value>), EngineError> {
    let events = json_events(stdout)?;
    let terminal = events
        .iter()
        .rev()
        .find(|event| {
            event
                .get("type")
                .or_else(|| event.get("event"))
                .and_then(Value::as_str)
                .is_some_and(|kind| matches!(kind, "result" | "final" | "message.result"))
                || event.get("structured_output").is_some()
                || event.pointer("/result/structured_output").is_some()
        })
        .ok_or_else(|| {
            EngineError::WriteRejected(
                "Antigravity output has no recognized terminal result".to_owned(),
            )
        })?;
    let status = terminal
        .get("status")
        .or_else(|| terminal.get("subtype"))
        .or_else(|| terminal.pointer("/result/status"))
        .and_then(Value::as_str)
        .unwrap_or("success");
    if !matches!(
        status.to_ascii_lowercase().as_str(),
        "success" | "succeeded" | "completed" | "complete"
    ) {
        return rejected(format!(
            "Antigravity terminal state is not recognized as success: {status}"
        ));
    }
    let output = terminal
        .pointer("/result/structured_output")
        .or_else(|| terminal.get("structured_output"))
        .or_else(|| terminal.get("result"))
        .cloned()
        .unwrap_or_else(|| terminal.clone());
    Ok((output, events))
}
