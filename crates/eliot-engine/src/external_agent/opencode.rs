use super::structured_output::{
    exact_requested_model, first_string, json_events, observed_tool_names,
    validate_json_schema_instance,
};
use super::{ProviderCommandPlan, ProviderTerminalResult, rejected};
use crate::EngineError;
use eliot_types::ProviderStructuredOutputMode;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn parse_structured_text(text: &str) -> Option<Value> {
    let text = text.trim();
    if let Ok(value) = serde_json::from_str(text) {
        return Some(value);
    }
    let fenced = text
        .strip_prefix("```json")
        .or_else(|| text.strip_prefix("```JSON"))?
        .strip_suffix("```")?
        .trim();
    (!fenced.contains("```"))
        .then(|| serde_json::from_str(fenced).ok())
        .flatten()
}

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
    if let Some(error) = events
        .iter()
        .find(|event| event.get("type").and_then(Value::as_str) == Some("error"))
    {
        let message = error
            .get("error")
            .and_then(|error| first_string(error, &["message"]))
            .or_else(|| {
                error
                    .get("error")
                    .and_then(|error| first_string(error, &["name"]))
            })
            .unwrap_or_else(|| "unknown provider error".to_owned());
        return rejected(format!("OpenCode provider error: {message}"));
    }

    let session_ids = events
        .iter()
        .filter_map(|event| {
            event
                .get("sessionID")
                .or_else(|| event.get("session_id"))
                .and_then(Value::as_str)
                .filter(|session| !session.trim().is_empty())
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>();
    if session_ids.len() != 1 {
        return rejected(format!(
            "OpenCode stream must attest exactly one session ID, found {}",
            session_ids.len()
        ));
    }
    let provider_session_id = session_ids.into_iter().next().ok_or_else(|| {
        EngineError::WriteRejected("OpenCode stream has no session ID".to_owned())
    })?;

    let observed_model = events
        .iter()
        .find_map(|event| first_string(event, &["model", "model_id", "modelId"]));
    let resolved_model = if observed_model.is_some() {
        exact_requested_model(observed_model, requested_model)?
    } else {
        // OpenCode's JSON event protocol does not repeat the selected model. The
        // governed command binds the exact provider/model through --model, and
        // the executable, argv and selection mechanism are sealed in the
        // ProviderRuntimeContract before dispatch.
        requested_model.to_owned()
    };
    if !events
        .iter()
        .any(|event| event.get("type").and_then(Value::as_str) == Some("step_start"))
    {
        return rejected("OpenCode stream has no step_start event");
    }
    let terminal_reason = events
        .iter()
        .rev()
        .find(|event| event.get("type").and_then(Value::as_str) == Some("step_finish"))
        .and_then(|event| event.pointer("/part/reason"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            EngineError::WriteRejected(
                "OpenCode stream has no terminal step_finish reason".to_owned(),
            )
        })?;
    if terminal_reason != "stop" {
        return rejected(format!(
            "OpenCode stream ended with nonterminal reason {terminal_reason}"
        ));
    }
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
        .filter_map(parse_structured_text)
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
        terminal_status: "step_finish:stop".to_owned(),
        observed_tool_names: observed_tool_names(&events),
        token_or_cost_telemetry: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_opencode_stream, parse_structured_text};
    use serde_json::json;

    #[test]
    fn current_json_stream_accepts_one_session_and_schema_bound_result() {
        let stdout = concat!(
            "{\"type\":\"step_start\",\"sessionID\":\"ses_123\",\"part\":{\"type\":\"step-start\"}}\n",
            "{\"type\":\"tool_use\",\"sessionID\":\"ses_123\",\"part\":{\"type\":\"tool\",\"tool\":\"eliot_current_state\",\"state\":{\"status\":\"completed\"}}}\n",
            "{\"type\":\"text\",\"sessionID\":\"ses_123\",\"part\":{\"type\":\"text\",\"text\":\"{\\\"memory_revision\\\":3}\",\"time\":{\"end\":1}}}\n",
            "{\"type\":\"step_finish\",\"sessionID\":\"ses_123\",\"part\":{\"type\":\"step-finish\",\"reason\":\"stop\"}}\n",
        );
        let parsed = match parse_opencode_stream(
            stdout.as_bytes(),
            "openai/gpt-5.4",
            &json!({
                "type": "object",
                "properties": {"memory_revision": {"const": 3}},
                "required": ["memory_revision"],
                "additionalProperties": false
            }),
        ) {
            Ok(parsed) => parsed,
            Err(error) => panic!("current OpenCode JSON events should parse: {error}"),
        };

        assert_eq!(parsed.provider_session_id, "ses_123");
        assert_eq!(parsed.resolved_model, "openai/gpt-5.4");
        assert_eq!(parsed.terminal_status, "step_finish:stop");
        assert_eq!(parsed.structured_output, json!({"memory_revision": 3}));
        assert_eq!(parsed.observed_tool_names, vec!["eliot_current_state"]);
    }

    #[test]
    fn current_state_revision_may_advance_after_preflight() {
        let stdout = concat!(
            "{\"type\":\"step_start\",\"sessionID\":\"ses_mimo\",\"part\":{\"type\":\"step-start\"}}\n",
            "{\"type\":\"tool_use\",\"sessionID\":\"ses_mimo\",\"part\":{\"type\":\"tool\",\"tool\":\"eliot-governor_eliot_current_state\",\"state\":{\"status\":\"completed\",\"input\":{\"scope\":\"memory_free_control\"},\"output\":\"{\\\"memory_revision\\\":6}\"}}}\n",
            "{\"type\":\"text\",\"sessionID\":\"ses_mimo\",\"part\":{\"type\":\"text\",\"text\":\"{\\\"memory_revision\\\":6}\"}}\n",
            "{\"type\":\"step_finish\",\"sessionID\":\"ses_mimo\",\"part\":{\"type\":\"step-finish\",\"reason\":\"stop\"}}\n",
        );
        let parsed = match parse_opencode_stream(
            stdout.as_bytes(),
            "opencode/mimo-v2.5-free",
            &json!({
                "type": "object",
                "properties": {
                    "memory_revision": {
                        "type": "integer",
                        "minimum": 3
                    }
                },
                "required": ["memory_revision"],
                "additionalProperties": false
            }),
        ) {
            Ok(parsed) => parsed,
            Err(error) => panic!(
                "revision advanced by governed dispatch bookkeeping must remain admissible: {error}"
            ),
        };

        assert_eq!(parsed.structured_output, json!({"memory_revision": 6}));
        assert_eq!(
            parsed.observed_tool_names,
            vec!["eliot-governor_eliot_current_state"]
        );
    }

    #[test]
    fn provider_error_event_surfaces_the_actual_failure() {
        let stdout = br#"{"type":"error","timestamp":1,"sessionID":"ses_401","error":{"name":"UnknownError","data":{"message":"Token refresh failed: 401"}}}"#;
        let Err(error) = parse_opencode_stream(stdout, "openai/gpt-5.4", &json!(true)) else {
            panic!("provider error must be rejected");
        };

        assert!(
            error
                .to_string()
                .contains("OpenCode provider error: Token refresh failed: 401")
        );
    }

    #[test]
    fn exact_json_fence_is_accepted_but_surrounding_prose_is_not() {
        assert_eq!(
            parse_structured_text("```json\n{\"memory_revision\":3}\n```"),
            Some(json!({"memory_revision": 3}))
        );
        assert_eq!(
            parse_structured_text("result:\n```json\n{\"memory_revision\":3}\n```"),
            None
        );
        assert_eq!(
            parse_structured_text("```json\n{\"memory_revision\":3}\n```\nextra"),
            None
        );
    }
}
