//! Pure `SurrealDB` JSON-RPC/provider-version parsing cell extracted from `client.rs`.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-AUTH-01, ARCH-SEC-02.
//! Implementation: I5.1, I5.9, I5.22, I2.23.
//! Ownership: pure `RpcResponse` envelope and `surrealdb-3.1`/`3.2` `ProviderVersion` parsing only; no transport, auth, handshake, process-spawn, or lifecycle ownership (see `crates/storage/eliot-store-surreal-adapter/src/client.rs`).

use std::fmt;

use eliot_types::strict_json_has_no_duplicate_members;
use serde::de::Visitor;
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
/// `RpcErrorBody` is deliberately NOT closed, for the reason given on that type
/// itself: the real error object carries members this client must admit.
///
/// Closure admits *which members are named*; it does not assert that one of
/// them is present. `result` therefore records member presence explicitly
/// (see [`RpcResultMember`]) so [`rpc_result`] can refuse a frame that names
/// neither `result` nor `error`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RpcResponse {
    pub(super) id: Option<Value>,
    #[serde(default)]
    result: RpcResultMember,
    error: Option<RpcErrorBody>,
}

/// The `result` member with its *presence* distinguished from its value.
///
/// `Option<Value>` cannot carry that distinction: `serde_json` reports a JSON
/// `null` through `Deserializer::deserialize_option` as `visit_none`, so a
/// `"result": null` frame — the wire form of a SurrealQL `NONE` value — decodes
/// exactly like a frame carrying no `result` member at all. `#[serde(default)]`
/// is therefore required on the field: an absent member is filled from
/// `Default` (no member), while a present `null` reaches this `Deserialize` impl
/// and is recorded as a present member. Refusing the absent case in
/// [`rpc_result`] depends on that separation; an `Option<Value>` field would
/// refuse a legitimate `NONE` result as well.
#[derive(Debug, Default)]
struct RpcResultMember(Option<Value>);

impl RpcResultMember {
    /// The member's value, or `None` only when the member was absent.
    fn into_present(self) -> Option<Value> {
        self.0
    }
}

impl<'de> Deserialize<'de> for RpcResultMember {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PresentMemberVisitor;

        impl<'de> Visitor<'de> for PresentMemberVisitor {
            type Value = RpcResultMember;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an RPC response result member")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(RpcResultMember(Some(Value::Null)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(RpcResultMember(Some(Value::Null)))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Value::deserialize(deserializer).map(|value| RpcResultMember(Some(value)))
            }
        }

        deserializer.deserialize_option(PresentMemberVisitor)
    }
}

/// The provider's real error object, verified against the pinned `v3.1.4` tag's
/// `surrealdb/types/src/error.rs` rather than inferred.
///
/// That file declares `pub struct Error { code: i64, message: String,
/// #[surreal(flatten)] details: ErrorDetails, cause: Option<Box<Error>> }` and
/// states, verbatim: "The `details` field is flattened into the serialized
/// object, so the wire format contains `kind` (string) and optionally `details`
/// (object) at the same level as `code` and `message`." `ErrorDetails` derives
/// `#[surreal(tag = "kind", content = "details", skip_content_if =
/// "Value::is_empty")]`, so `kind` is emitted on every error frame - only an
/// empty `details` is skipped - and names the failure family
/// (`ErrorDetails::kind_str`): "Validation", "Configuration", "Query",
/// "Serialization", "NotAllowed", "NotFound", "AlreadyExists", "Connection",
/// "Thrown", "Internal", "Context".
///
/// Deliberately NOT closed (`deny_unknown_fields`): `kind` is always present
/// and `details` is present whenever non-empty, so closing this would refuse
/// every genuine provider error frame and turn each auth, query and credential
/// failure into a decode failure that names no cause.
///
/// `cause` is an optional nested error object there; it is admitted and ignored
/// rather than decoded, because it is a recursive vendor chain of unbounded
/// prose that no path in this crate consumes. The previously declared `data`
/// member is gone: the provider emits no `data`, so it could never be set.
#[derive(Debug, Deserialize)]
struct RpcErrorBody {
    code: i64,
    message: String,
    // `kind` is unconditional upstream, but an unrecognised frame must still
    // be refused as the provider's own refusal rather than as a decode
    // failure, so absence is admitted and read as "no family stated".
    kind: Option<String>,
    // The flattened `details` object. A vendor document: read only to prove it
    // was received, never inspected and never echoed into a message.
    details: Option<Value>,
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

/// Reduces one admitted RPC envelope to the outcome it actually reports
/// (#937, #938, #940).
///
/// A provider outcome is one of three observable states, and this maps each to
/// exactly one result:
///
/// * `error` present — refused as [`AdapterError::ProviderUnavailable`],
///   unchanged. The provider's `code`, `message`, `kind` and `details` are the
///   provider's own words and stay unread: nothing in this crate turns any of
///   them into a message, and [`AdapterError::ProviderUnavailable`] carries no
///   payload to carry them in. Surfacing the provider's `kind` at this
///   boundary therefore needs a payload-bearing variant in `crate::error` and a
///   mapping in `AdapterError::into_store_error`, which this cell does not own.
/// * `result` member present — that member's value, including a real JSON
///   `null`, which is how a SurrealQL `NONE` value arrives on the wire. A
///   genuine null payload is therefore an admitted `Ok(Value::Null)` here and
///   stays distinguishable from the refused case below before any caller
///   inspects the value.
/// * neither member present — refused. `DbResponse::into_value` builds `result`
///   or `error`, so the pinned provider emits no such frame; a frame that
///   reports neither carries no outcome at all, and returning
///   `unwrap_or(Value::Null)` for it would promote "unknown" into "a successful
///   null" at a call site that cannot tell the two apart: `signin` and `use`
///   discard the value with `.map(|_| ())`
///   (`client/session.rs:98` and `:108`), so a refusal-as-default would read as
///   a completed authentication. This is refused as a bounded
///   [`AdapterError::Serialization`] with static text — the same disposition as
///   every other malformed-response refusal in this cell (`parse_response`
///   above, `RpcResults::from_value` in `client.rs:161`) — so it stays a
///   deterministic decode-class failure rather than a retryable or reconciling
///   outcome the frame itself never earned. The response body is never echoed.
pub(super) fn rpc_result(response: RpcResponse) -> Result<Value, AdapterError> {
    if let Some(error) = response.error {
        let _ = (error.code, error.message, error.kind, error.details);
        return Err(AdapterError::ProviderUnavailable);
    }
    response.result.into_present().ok_or_else(|| {
        AdapterError::Serialization(
            "provider RPC response carried neither a result nor an error".to_owned(),
        )
    })
}
