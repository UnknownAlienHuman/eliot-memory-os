//! Pure `SurrealDB` JSON-RPC/provider-version parsing cell extracted from `client.rs`.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-AUTH-01, ARCH-SEC-02.
//! Implementation: I5.1, I5.9, I5.22, I2.23.
//! Ownership: pure `RpcResponse` envelope and `surrealdb-3.1`/`3.2` `ProviderVersion` parsing only; no transport, auth, handshake, process-spawn, or lifecycle ownership (see `crates/storage/eliot-store-surreal-adapter/src/client.rs`).

use eliot_types::strict_json_has_no_duplicate_members;
use serde::Deserialize;
use serde_json::Value;

use crate::error::AdapterError;

/// The closed top-level response envelope (#937, #938, #940).
///
/// `surrealdb` `v3.1.4` (the pinned provider, and `v3.2.4` identically) builds
/// every WebSocket response object from `DbResponse::into_value`
/// (`surrealdb/core/src/rpc/response.rs`): a `result` or an `error`, plus `id`
/// when the request carried one, plus `session` when — and only when — the
/// *request* envelope carried a `session`. This crate's `RpcRequest`
/// (`client.rs:203`) serializes only `id`, `method` and `params`, so `session`
/// is never echoed and the admitted member set is exactly `id`/`result`/`error`.
/// An unknown top-level member is refused instead of dropped silently.
///
/// Named boundary: this closure is the envelope only. `result` is a vendor
/// document and `deny_unknown_fields` does not reach inside a `Value` field.
/// `RpcErrorBody` is deliberately NOT closed: the real error object carries
/// `kind` at the same level as `code`/`message` (and optionally `details` and
/// `cause`) — `surrealdb/types/src/error.rs` — so closing it would refuse every
/// genuine provider error frame. Its `data` member is never emitted by this
/// provider; that under-specified shape is a separate, unowned schema question.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RpcResponse {
    pub(super) id: Option<Value>,
    result: Option<Value>,
    error: Option<RpcErrorBody>,
}

#[derive(Debug, Deserialize)]
struct RpcErrorBody {
    code: i64,
    message: String,
    data: Option<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProviderVersion {
    pub(crate) major: u16,
    pub(crate) minor: u16,
    pub(crate) patch: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderVersionObject {
    version: String,
    build: String,
    timestamp: String,
}

pub(crate) fn provider_version_from_rpc(value: &Value) -> Result<ProviderVersion, AdapterError> {
    match value {
        Value::String(version) => {
            let numeric = version
                .strip_prefix("surrealdb-")
                .ok_or_else(|| invalid_provider_version("legacy string lacks surrealdb- prefix"))?;
            let parsed = parse_provider_semver(numeric)?;
            if parsed.major != 3 || parsed.minor != 1 {
                return Err(invalid_provider_version(
                    "legacy string is only valid for the documented 3.1 response",
                ));
            }
            Ok(parsed)
        }
        Value::Object(_) => {
            let response: ProviderVersionObject = serde_json::from_value(value.clone())
                .map_err(|_| invalid_provider_version("3.2 object shape is invalid"))?;
            if response.build.trim().is_empty()
                || response.timestamp.trim().is_empty()
                || response.build.chars().any(char::is_control)
                || response.timestamp.chars().any(char::is_control)
            {
                return Err(invalid_provider_version(
                    "3.2 object build and timestamp must be non-empty text",
                ));
            }
            let parsed = parse_provider_semver(&response.version)?;
            if parsed.major != 3 || parsed.minor != 2 {
                return Err(invalid_provider_version(
                    "object response is only valid for the documented 3.2 response",
                ));
            }
            Ok(parsed)
        }
        _ => Err(invalid_provider_version(
            "result is neither the 3.1 string nor the 3.2 object",
        )),
    }
}

fn parse_provider_semver(value: &str) -> Result<ProviderVersion, AdapterError> {
    let mut parts = value.split('.');
    let major = parse_version_component(parts.next(), "major")?;
    let minor = parse_version_component(parts.next(), "minor")?;
    let patch = parse_version_component(parts.next(), "patch")?;
    if parts.next().is_some() {
        return Err(invalid_provider_version("version has extra components"));
    }
    Ok(ProviderVersion {
        major,
        minor,
        patch,
    })
}

fn parse_version_component(value: Option<&str>, field: &str) -> Result<u16, AdapterError> {
    let value = value.ok_or_else(|| invalid_provider_version(&format!("missing {field}")))?;
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(invalid_provider_version(&format!(
            "{field} component is not canonical decimal"
        )));
    }
    value
        .parse::<u16>()
        .map_err(|_| invalid_provider_version(&format!("{field} component is out of range")))
}

fn invalid_provider_version(reason: &str) -> AdapterError {
    AdapterError::Config(format!(
        "SurrealDB version RPC returned an incompatible fail-closed response: {reason}"
    ))
}

/// Decodes one RPC response frame, refusing a lexical duplicate object member
/// before the response id is read (#937, #938, #940).
///
/// `serde_json::from_str` collapses a repeated member to last-wins the instant
/// raw bytes become a `serde_json::Value`: this workspace builds
/// `serde_json::Map` without the `preserve_order` feature, so `Map` is a
/// `BTreeMap`. The call sites in `client/session.rs:190` and `:198` then compare
/// `response.id` against the request id, so a duplicate-keyed frame was already
/// an admission and routing decision by the time any closed record in this crate
/// could be validated. `provider_version_from_rpc` below inherits that collapse
/// through its `from_value`, so it could not distinguish a duplicate document
/// from its last-wins equivalent either, even for the closed
/// `ProviderVersionObject` shape it validates.
///
/// This is the single raw-ingress gate for both the text and the binary frame
/// path, and it is a thin reuse of the shared `eliot_types::strict_json`
/// decoder. It is not a second parser, and it is not an extra per-call-site
/// check. The typed decode below is unchanged, so a duplicate member is refused
/// and a duplicate-free document keeps every previously accepted byte.
///
/// Named absence: these frames have no ELIOT-owned byte ceiling. Nothing in this
/// crate sets `WebSocketConfig`, `max_message_size` or `max_frame_size`, so only
/// the tokio-tungstenite library default bounds a frame, and the read loop's
/// `timeout` in `client/session.rs:168` is a time bound, not a byte ceiling.
/// This gate therefore uses the shared decoder's no-ceiling entry point rather
/// than inventing a `max_bytes` that no requirement states; the bytes are
/// already received and resident here, so a ceiling at this point could only
/// newly refuse large but legitimate query results. An ELIOT-owned response
/// ceiling remains unowned.
pub(super) fn parse_response(text: &str) -> Result<RpcResponse, AdapterError> {
    strict_json_has_no_duplicate_members(text.as_bytes())
        .map_err(|error| AdapterError::Serialization(error.kind.as_str().to_owned()))?;

    serde_json::from_str(text).map_err(|error| AdapterError::Serialization(error.to_string()))
}

pub(super) fn rpc_result(response: RpcResponse) -> Result<Value, AdapterError> {
    if let Some(error) = response.error {
        let _ = (error.code, error.message, error.data);
        return Err(AdapterError::ProviderUnavailable);
    }
    Ok(response.result.unwrap_or(Value::Null))
}
