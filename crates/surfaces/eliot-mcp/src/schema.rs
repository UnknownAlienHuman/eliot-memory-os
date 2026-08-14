//! Deterministic schemas generated from the exact Serde contract types.

use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ActInput, CoordinateInput, FinishAttemptDraft, McpResponse, ObserveInput, PacketInput,
    QueryInput, StateInput, VerifyInput,
};

/// Exact canonical hot-tool names. The compatibility alias is intentionally absent.
pub const CANONICAL_TOOL_NAMES: [&str; 8] = [
    "eliot.state",
    "eliot.packet",
    "eliot.observe",
    "eliot.query",
    "eliot.act",
    "eliot.verify",
    "eliot.coordinate",
    "eliot.finish",
];

/// Generated schema descriptor for one canonical tool.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSchema {
    /// Exact canonical name.
    pub name: String,
    /// Short surface description; deep semantics remain in the schema/resources.
    pub description: String,
    /// Input schema generated from the input contract type.
    pub input_schema: Value,
    /// Output schema generated from [`McpResponse`].
    pub output_schema: Value,
    /// Digest over canonical input and output schema bytes.
    pub schema_sha256: String,
}

/// Schema generation failure.
#[derive(Debug, Error)]
pub enum SchemaError {
    /// Schema serialization failed.
    #[error("schema serialization failed: {0}")]
    Serialization(String),
}

/// Generates the canonical tool catalogue in stable semantic order.
pub fn canonical_tool_schemas() -> Result<Vec<ToolSchema>, SchemaError> {
    Ok(vec![
        descriptor::<StateInput>("eliot.state", "Current task and scope projection")?,
        descriptor::<PacketInput>("eliot.packet", "Compile or refresh active understanding")?,
        descriptor::<ObserveInput>("eliot.observe", "Capture a typed public observation")?,
        descriptor::<QueryInput>("eliot.query", "Run an intent-bearing orientation query")?,
        descriptor::<ActInput>("eliot.act", "Request a governed action frame")?,
        descriptor::<VerifyInput>("eliot.verify", "Run a typed verification intent")?,
        descriptor::<CoordinateInput>("eliot.coordinate", "Use the execution fabric")?,
        descriptor::<FinishAttemptDraft>("eliot.finish", "Submit a candidate finish attempt")?,
    ])
}

/// Generates canonical JSON Schema from the same type used for Serde decoding.
pub fn canonical_schema<T: JsonSchema>() -> Result<Value, SchemaError> {
    let value = serde_json::to_value(schema_for!(T))
        .map_err(|error| SchemaError::Serialization(error.to_string()))?;
    Ok(canonicalize(value))
}

fn descriptor<T: JsonSchema>(name: &str, description: &str) -> Result<ToolSchema, SchemaError> {
    let input_schema = canonical_schema::<T>()?;
    let output_schema = canonical_schema::<McpResponse>()?;
    let bytes = serde_json::to_vec(&(&input_schema, &output_schema))
        .map_err(|error| SchemaError::Serialization(error.to_string()))?;
    Ok(ToolSchema {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema,
        output_schema,
        schema_sha256: hex_digest(&Sha256::digest(bytes)),
    })
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let mut keys = values.into_iter().collect::<Vec<_>>();
            keys.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                keys.into_iter()
                    .map(|(key, value)| (key, canonicalize(value)))
                    .collect::<Map<_, _>>(),
            )
        }
        other => other,
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}
