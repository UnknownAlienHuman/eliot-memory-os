//! Stateless JSON binding codec for the private Surreal query boundary.
//!
//! Surreal 3's JSON RPC decoder interprets string contents as record IDs,
//! UUIDs or datetimes. Send each value as JSON text inside a one-element array
//! (always starting with `[`, never a record-like prefix), then decode it with
//! the RFC 8259 JSON decoder before executing the unchanged named operation.
//! No payload bytes are replaced and no persistent encoding is introduced:
//! `ExactJsonBytes` remains the versioned, digest-bound canonical authority.

use std::fmt::Write;

use serde_json::{Map, Value};

use crate::error::AdapterError;

pub(super) fn encode_bindings(
    statement: &str,
    bindings: Map<String, Value>,
) -> Result<(String, Map<String, Value>, usize), AdapterError> {
    let prefix_len = bindings.len();
    let mut query = String::new();
    let mut encoded = Map::new();
    for (name, value) in bindings {
        // Names come only from private named-operation definitions. Validate
        // before placing them in SQL; values always remain bound parameters.
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || name.as_bytes()[0].is_ascii_digit()
        {
            return Err(AdapterError::Serialization(
                "invalid private query binding name".to_owned(),
            ));
        }
        let text = serde_json::to_string(&[value])
            .map_err(|error| AdapterError::Serialization(error.to_string()))?;
        writeln!(query, "LET ${name} = encoding::json::decode(${name})[0];")
            .map_err(|error| AdapterError::Serialization(error.to_string()))?;
        encoded.insert(name, Value::String(text));
    }
    query.push_str(statement);
    Ok((query, encoded, prefix_len))
}
