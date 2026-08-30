//! Stable zero-model Codex App Server wire and catalogue parser.
//!
//! This module owns only the diagnostic request/response codec used before a
//! provider attempt. It does not launch Codex, select a model, start a thread,
//! own an ELIOT attempt, or interpret provider output as task completion.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

pub const MAX_JSONL_LINE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MODEL_PAGES: usize = 32;
pub const MAX_MODELS: usize = 4_096;
pub const DEFAULT_MODEL_PAGE_LIMIT: u64 = 100;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StableWireError {
    #[error("Codex App Server JSONL line exceeds the diagnostic limit")]
    LineTooLarge,
    #[error("Codex App Server JSONL is malformed")]
    InvalidJson,
    #[error("Codex App Server message must be a JSON object")]
    NotObject,
    #[error("Codex App Server stable wire must omit the jsonrpc member")]
    JsonRpcHeaderPresent,
    #[error("Codex App Server message shape is invalid: {0}")]
    InvalidShape(&'static str),
    #[error("Codex App Server response id does not match the request")]
    ResponseIdMismatch,
    #[error("Codex App Server returned a typed server error{code}")]
    ServerError { code: ErrorCodeDisplay },
    #[error("Codex model catalogue page is invalid: {0}")]
    InvalidModelPage(&'static str),
    #[error("Codex model catalogue contains duplicate model id {0}")]
    DuplicateModelId(String),
    #[error("Codex model catalogue repeated pagination cursor {0}")]
    CursorLoop(String),
    #[error("Codex model catalogue exceeded the page limit")]
    MaximumPagesExceeded,
    #[error("Codex model catalogue exceeded the model limit")]
    MaximumModelsExceeded,
    #[error("Codex model catalogue is incomplete")]
    IncompleteCatalogue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorCodeDisplay(Option<i64>);

impl std::fmt::Display for ErrorCodeDisplay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(code) => write!(formatter, " ({code})"),
            None => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum IncomingMessage {
    Response { id: Value, result: Value },
    Error { id: Value, code: Option<i64> },
    ServerRequest {
        id: Value,
        method: String,
        params: Value,
    },
    Notification { method: String, params: Value },
}

pub fn initialize_request(
    id: u64,
    client_name: &str,
    client_title: Option<&str>,
    client_version: &str,
) -> Result<Value, StableWireError> {
    validate_non_empty(client_name, "client name")?;
    validate_non_empty(client_version, "client version")?;
    if let Some(title) = client_title {
        validate_non_empty(title, "client title")?;
    }

    let mut client_info = Map::new();
    client_info.insert("name".to_owned(), Value::String(client_name.to_owned()));
    if let Some(title) = client_title {
        client_info.insert("title".to_owned(), Value::String(title.to_owned()));
    }
    client_info.insert(
        "version".to_owned(),
        Value::String(client_version.to_owned()),
    );

    Ok(request(
        id,
        "initialize",
        Value::Object(Map::from_iter([(
            "clientInfo".to_owned(),
            Value::Object(client_info),
        )])),
    ))
}

#[must_use]
pub fn initialized_notification() -> Value {
    Value::Object(Map::from_iter([
        ("method".to_owned(), Value::String("initialized".to_owned())),
        ("params".to_owned(), Value::Object(Map::new())),
    ]))
}

pub fn model_list_request(
    id: u64,
    cursor: Option<&str>,
    limit: u64,
    include_hidden: bool,
) -> Result<Value, StableWireError> {
    if limit == 0 || limit > MAX_MODELS as u64 {
        return Err(StableWireError::InvalidShape("model/list limit"));
    }
    if let Some(cursor) = cursor {
        validate_non_empty(cursor, "model/list cursor")?;
    }

    let params = Map::from_iter([
        (
            "cursor".to_owned(),
            cursor.map_or(Value::Null, |value| Value::String(value.to_owned())),
        ),
        ("limit".to_owned(), Value::from(limit)),
        ("includeHidden".to_owned(), Value::Bool(include_hidden)),
    ]);
    Ok(request(id, "model/list", Value::Object(params)))
}

#[must_use]
fn request(id: u64, method: &str, params: Value) -> Value {
    Value::Object(Map::from_iter([
        ("method".to_owned(), Value::String(method.to_owned())),
        ("id".to_owned(), Value::from(id)),
        ("params".to_owned(), params),
    ]))
}

pub fn encode_jsonl(message: &Value) -> Result<Vec<u8>, StableWireError> {
    validate_outbound(message)?;
    let mut bytes = serde_json::to_vec(message).map_err(|_| StableWireError::InvalidJson)?;
    if bytes.len() + 1 > MAX_JSONL_LINE_BYTES {
        return Err(StableWireError::LineTooLarge);
    }
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate_outbound(message: &Value) -> Result<(), StableWireError> {
    let object = message.as_object().ok_or(StableWireError::NotObject)?;
    if object.contains_key("jsonrpc") {
        return Err(StableWireError::JsonRpcHeaderPresent);
    }
    if object.contains_key("result") || object.contains_key("error") {
        return Err(StableWireError::InvalidShape("outbound result/error"));
    }
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .ok_or(StableWireError::InvalidShape("method"))?;
    validate_non_empty(method, "method")?;
    if !object.get("params").is_some_and(Value::is_object) {
        return Err(StableWireError::InvalidShape("params"));
    }
    if method == "initialized" {
        if object.contains_key("id") {
            return Err(StableWireError::InvalidShape("initialized id"));
        }
    } else if !object.get("id").is_some_and(Value::is_u64) {
        return Err(StableWireError::InvalidShape("request id"));
    }
    Ok(())
}

pub fn parse_incoming(line: &[u8]) -> Result<IncomingMessage, StableWireError> {
    if line.len() > MAX_JSONL_LINE_BYTES {
        return Err(StableWireError::LineTooLarge);
    }
    let value: Value = serde_json::from_slice(line).map_err(|_| StableWireError::InvalidJson)?;
    let object = value.as_object().ok_or(StableWireError::NotObject)?;
    if object.contains_key("jsonrpc") {
        return Err(StableWireError::JsonRpcHeaderPresent);
    }

    let id = object.get("id").cloned();
    let method = object.get("method").and_then(Value::as_str);
    let result = object.get("result").cloned();
    let error = object.get("error");
    if result.is_some() && error.is_some() {
        return Err(StableWireError::InvalidShape("result and error"));
    }

    if let Some(result) = result {
        let id = id.ok_or(StableWireError::InvalidShape("response id"))?;
        return Ok(IncomingMessage::Response { id, result });
    }
    if let Some(error) = error {
        let id = id.ok_or(StableWireError::InvalidShape("error response id"))?;
        let error_object = error
            .as_object()
            .ok_or(StableWireError::InvalidShape("error object"))?;
        let code = error_object.get("code").and_then(Value::as_i64);
        return Ok(IncomingMessage::Error { id, code });
    }
    if let Some(method) = method {
        validate_non_empty(method, "incoming method")?;
        let params = object.get("params").cloned().unwrap_or(Value::Null);
        return match id {
            Some(id) => Ok(IncomingMessage::ServerRequest {
                id,
                method: method.to_owned(),
                params,
            }),
            None => Ok(IncomingMessage::Notification {
                method: method.to_owned(),
                params,
            }),
        };
    }
    Err(StableWireError::InvalidShape("unclassified message"))
}

pub fn response_result(line: &[u8], expected_id: u64) -> Result<Value, StableWireError> {
    match parse_incoming(line)? {
        IncomingMessage::Response { id, result } if id == Value::from(expected_id) => Ok(result),
        IncomingMessage::Error { id, code } if id == Value::from(expected_id) => {
            Err(StableWireError::ServerError {
                code: ErrorCodeDisplay(code),
            })
        }
        IncomingMessage::Response { .. } | IncomingMessage::Error { .. } => {
            Err(StableWireError::ResponseIdMismatch)
        }
        IncomingMessage::ServerRequest { .. } | IncomingMessage::Notification { .. } => {
            Err(StableWireError::InvalidShape("response expected"))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReasoningEffortOption {
    pub reasoning_effort: String,
    pub description: String,
}

impl ReasoningEffortOption {
    fn validate(&self) -> Result<(), StableWireError> {
        validate_non_empty(&self.reasoning_effort, "reasoning effort")?;
        validate_non_empty(&self.description, "reasoning effort description")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexModel {
    pub id: String,
    pub model: String,
    #[serde(default)]
    pub upgrade: Option<String>,
    pub display_name: String,
    pub description: String,
    #[serde(default)]
    pub model_specialty: Option<String>,
    pub hidden: bool,
    pub supported_reasoning_efforts: Vec<ReasoningEffortOption>,
    pub default_reasoning_effort: String,
    pub input_modalities: Vec<String>,
    pub supports_personality: bool,
    pub is_default: bool,
}

impl CodexModel {
    fn validate(&self) -> Result<(), StableWireError> {
        for (value, field) in [
            (&self.id, "model id"),
            (&self.model, "model wire name"),
            (&self.display_name, "model display name"),
            (&self.description, "model description"),
            (&self.default_reasoning_effort, "default reasoning effort"),
        ] {
            validate_non_empty(value, field)?;
        }
        let mut reasoning = BTreeSet::new();
        for option in &self.supported_reasoning_efforts {
            option.validate()?;
            if !reasoning.insert(option.reasoning_effort.as_str()) {
                return Err(StableWireError::InvalidModelPage(
                    "duplicate reasoning effort",
                ));
            }
        }
        if !self.supported_reasoning_efforts.is_empty()
            && !reasoning.contains(self.default_reasoning_effort.as_str())
        {
            return Err(StableWireError::InvalidModelPage(
                "default reasoning effort is not supported",
            ));
        }
        if self.input_modalities.iter().any(|value| value.trim().is_empty()) {
            return Err(StableWireError::InvalidModelPage("empty input modality"));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ModelListPage {
    data: Vec<CodexModel>,
    next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CodexModelCatalogue {
    pub models: Vec<CodexModel>,
    pub pages: usize,
}

#[derive(Debug, Default)]
pub struct ModelCatalogueAccumulator {
    models: Vec<CodexModel>,
    model_ids: BTreeSet<String>,
    returned_cursors: BTreeSet<String>,
    next_cursor: Option<String>,
    pages: usize,
    complete: bool,
}

impl ModelCatalogueAccumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn request(&self, id: u64) -> Result<Value, StableWireError> {
        if self.complete {
            return Err(StableWireError::InvalidShape(
                "model catalogue already complete",
            ));
        }
        model_list_request(
            id,
            self.next_cursor.as_deref(),
            DEFAULT_MODEL_PAGE_LIMIT,
            false,
        )
    }

    pub fn accept_response_line(
        &mut self,
        line: &[u8],
        expected_id: u64,
    ) -> Result<(), StableWireError> {
        if self.complete {
            return Err(StableWireError::InvalidShape(
                "model catalogue already complete",
            ));
        }
        if self.pages >= MAX_MODEL_PAGES {
            return Err(StableWireError::MaximumPagesExceeded);
        }
        let result = response_result(line, expected_id)?;
        let object = result
            .as_object()
            .ok_or(StableWireError::InvalidModelPage("result object"))?;
        if !object.contains_key("data") || !object.contains_key("nextCursor") {
            return Err(StableWireError::InvalidModelPage(
                "data and nextCursor are required",
            ));
        }
        let page: ModelListPage = serde_json::from_value(result)
            .map_err(|_| StableWireError::InvalidModelPage("schema"))?;
        if self.models.len() + page.data.len() > MAX_MODELS {
            return Err(StableWireError::MaximumModelsExceeded);
        }
        for model in page.data {
            model.validate()?;
            if !self.model_ids.insert(model.id.clone()) {
                return Err(StableWireError::DuplicateModelId(model.id));
            }
            self.models.push(model);
        }
        self.pages += 1;
        self.next_cursor = match page.next_cursor {
            Some(cursor) => {
                validate_non_empty(&cursor, "next cursor")?;
                if !self.returned_cursors.insert(cursor.clone()) {
                    return Err(StableWireError::CursorLoop(cursor));
                }
                Some(cursor)
            }
            None => {
                self.complete = true;
                None
            }
        };
        Ok(())
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn finish(self) -> Result<CodexModelCatalogue, StableWireError> {
        if !self.complete {
            return Err(StableWireError::IncompleteCatalogue);
        }
        Ok(CodexModelCatalogue {
            models: self.models,
            pages: self.pages,
        })
    }
}

fn validate_non_empty(value: &str, field: &'static str) -> Result<(), StableWireError> {
    if value.trim().is_empty() {
        Err(StableWireError::InvalidShape(field))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(id: &str, is_default: bool) -> Value {
        serde_json::json!({
            "id": id,
            "model": format!("wire-{id}"),
            "upgrade": null,
            "upgradeInfo": null,
            "availabilityNux": null,
            "displayName": format!("Model {id}"),
            "description": "fixture",
            "modelSpecialty": null,
            "hidden": false,
            "supportedReasoningEfforts": [
                {"reasoningEffort": "low", "description": "Low"},
                {"reasoningEffort": "high", "description": "High"}
            ],
            "defaultReasoningEffort": "low",
            "inputModalities": ["text", "image"],
            "supportsPersonality": true,
            "multiAgentVersion": null,
            "additionalSpeedTiers": [],
            "serviceTiers": [],
            "defaultServiceTier": null,
            "isDefault": is_default
        })
    }

    #[test]
    fn stable_handshake_omits_jsonrpc_protocol_version_and_experimental_api() {
        let initialize = initialize_request(1, "eliot", Some("ELIOT"), "0.1.0")
            .expect("initialize request");
        let encoded = String::from_utf8(encode_jsonl(&initialize).expect("encode initialize"))
            .expect("UTF-8");
        assert!(!encoded.contains("jsonrpc"));
        assert!(!encoded.contains("protocolVersion"));
        assert!(!encoded.contains("experimentalApi"));

        let initialized = initialized_notification();
        assert!(initialized.get("id").is_none());
        assert_eq!(initialized["method"], "initialized");
    }

    #[test]
    fn model_list_request_uses_current_stable_parameter_names() {
        let request = model_list_request(2, Some("cursor-1"), 50, false)
            .expect("model/list request");
        assert_eq!(request["method"], "model/list");
        assert_eq!(request["params"]["cursor"], "cursor-1");
        assert_eq!(request["params"]["limit"], 50);
        assert_eq!(request["params"]["includeHidden"], false);
    }

    #[test]
    fn stale_jsonrpc_and_mismatched_response_id_are_rejected() {
        assert_eq!(
            parse_incoming(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
            Err(StableWireError::JsonRpcHeaderPresent)
        );
        assert_eq!(
            response_result(br#"{"id":7,"result":{}}"#, 8),
            Err(StableWireError::ResponseIdMismatch)
        );
    }

    #[test]
    fn catalogue_preserves_reasoning_order_and_accepts_empty_complete_page() {
        let mut catalogue = ModelCatalogueAccumulator::new();
        let line = serde_json::to_vec(&serde_json::json!({
            "id": 2,
            "result": {"data": [model("a", true)], "nextCursor": null}
        }))
        .expect("fixture");
        catalogue
            .accept_response_line(&line, 2)
            .expect("accept page");
        let catalogue = catalogue.finish().expect("finish catalogue");
        assert_eq!(catalogue.models[0].supported_reasoning_efforts[0].reasoning_effort, "low");
        assert_eq!(catalogue.models[0].supported_reasoning_efforts[1].reasoning_effort, "high");

        let mut empty = ModelCatalogueAccumulator::new();
        empty
            .accept_response_line(br#"{"id":2,"result":{"data":[],"nextCursor":null}}"#, 2)
            .expect("empty page is an honest result");
        assert!(empty.finish().expect("finish empty").models.is_empty());
    }

    #[test]
    fn duplicate_model_and_cursor_loop_fail_closed() {
        let mut duplicate = ModelCatalogueAccumulator::new();
        let line = serde_json::to_vec(&serde_json::json!({
            "id": 2,
            "result": {"data": [model("a", true), model("a", false)], "nextCursor": null}
        }))
        .expect("fixture");
        assert!(matches!(
            duplicate.accept_response_line(&line, 2),
            Err(StableWireError::DuplicateModelId(_))
        ));

        let mut looped = ModelCatalogueAccumulator::new();
        looped
            .accept_response_line(
                br#"{"id":2,"result":{"data":[],"nextCursor":"same"}}"#,
                2,
            )
            .expect("first cursor");
        assert!(matches!(
            looped.accept_response_line(
                br#"{"id":3,"result":{"data":[],"nextCursor":"same"}}"#,
                3,
            ),
            Err(StableWireError::CursorLoop(_))
        ));
    }

    #[test]
    fn server_error_does_not_expose_provider_message() {
        let error = response_result(
            br#"{"id":2,"error":{"code":-32602,"message":"sensitive provider detail"}}"#,
            2,
        )
        .expect_err("server error");
        let rendered = error.to_string();
        assert!(rendered.contains("-32602"));
        assert!(!rendered.contains("sensitive provider detail"));
    }
}
