//! Pure `SurrealDB` JSON-RPC/provider-version parsing cell extracted from `client.rs`.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-AUTH-01, ARCH-SEC-02.
//! Implementation: I5.1, I5.9, I5.22, I2.23.
//! Ownership: pure `RpcResponse` envelope and `surrealdb-3.1`/`3.2` `ProviderVersion` parsing only; no transport, auth, handshake, process-spawn, or lifecycle ownership (see `crates/storage/eliot-store-surreal-adapter/src/client.rs`).

use std::fmt;

use eliot_types::strict_json_has_no_duplicate_members;
use serde::Deserialize;
use serde::de::Visitor;
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
/// * `error` present — refused as [`AdapterError::ProviderRefused`], which
///   retains the bounded, non-content-bearing facts the provider stated: its
///   `kind` (its own failure family, `None` when the frame names none) and its
///   numeric `code`. `message` and `details` are dropped at this mapping site
///   and reach no payload, no message and no log; `details` is unbounded vendor
///   prose and `AdapterError::provider_refused` accepts no argument that could
///   carry it. This is a distinct refusal from
///   [`AdapterError::ProviderUnavailable`], which every local transport, pool
///   and health condition in this crate also produces and for which no provider
///   frame exists to state a cause, and an absent `kind` stays absent: it is
///   never promoted to an authentication, validation, query or internal
///   verdict.
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
        // `message` and `details` are dropped here and are unretainable by
        // construction: `provider_refused` has no parameter that could carry
        // them. What the provider stated as a fact — its failure family and its
        // numeric code — crosses as the provider's own words, `None` included,
        // so an absent family is never a verdict.
        let _ = (error.message, error.details);
        return Err(AdapterError::provider_refused(
            error.code,
            error.kind.as_deref(),
        ));
    }
    response.result.into_present().ok_or_else(|| {
        AdapterError::Serialization(
            "provider RPC response carried neither a result nor an error".to_owned(),
        )
    })
}

#[cfg(test)]
mod tests {
    use eliot_types::StrictJsonErrorKind;
    use serde_json::json;

    use super::*;

    /// Decodes one wire frame from its raw bytes, exactly as the ingress does.
    ///
    /// Every fixture below is a byte literal. A `serde_json::Value` fixture is
    /// already the collapsed projection of those bytes, so it cannot observe
    /// the lexical facts the duplicate-member tests exist to pin.
    fn admitted(frame: &[u8]) -> Result<RpcResponse, AdapterError> {
        let text = std::str::from_utf8(frame)
            .map_err(|error| AdapterError::Serialization(error.to_string()))?;
        parse_response(text)
    }

    /// The outcome one admitted frame reports.
    fn outcome(frame: &[u8]) -> Result<Value, AdapterError> {
        rpc_result(admitted(frame)?)
    }

    #[test]
    fn a_present_null_result_is_admitted_as_value_null() -> Result<(), AdapterError> {
        // At the pinned `v3.1.4` tag `attach`, `detach`, `ping`, `authenticate`,
        // `invalidate`, `revoke` and `reset` all answer `PublicValue::None`,
        // which serialises as JSON `null`. `serde_json` reports that through
        // `visit_none`, so the frame is byte-identical to one carrying no
        // `result` member unless presence is tracked: a genuine `null` result is
        // a success, and it must not be refused as an absent member.
        assert_eq!(outcome(br#"{"id":7,"result":null}"#)?, Value::Null);
        Ok(())
    }

    #[test]
    fn a_frame_naming_no_outcome_member_is_refused() -> Result<(), AdapterError> {
        let frame = br#"{"id":7}"#;
        // Both the raw gate and the closed envelope admit these bytes, so the
        // missing `result` member is attributable as the whole cause: this is
        // not a lexical refusal and not an unknown-member refusal.
        assert!(admitted(frame).is_ok());
        assert!(matches!(
            outcome(frame),
            Err(AdapterError::Serialization(_))
        ));
        Ok(())
    }

    #[test]
    fn repeated_result_member_is_refused_by_the_raw_gate() -> Result<(), AdapterError> {
        let single = br#"{"id":7,"result":"last"}"#;
        let twice = br#"{"id":7,"result":"first","result":"last"}"#;
        let gate =
            AdapterError::Serialization(StrictJsonErrorKind::DuplicateKey.as_str().to_owned());
        // The last-wins projection of the twice-written frame decodes fine, so
        // only the lexical duplicate can be what refuses the pair of frames.
        assert_eq!(outcome(single)?, Value::String("last".to_owned()));
        assert_eq!(outcome(twice), Err(gate));
        Ok(())
    }

    #[test]
    fn an_unknown_top_level_member_is_refused_but_result_interior_members_are_not()
    -> Result<(), AdapterError> {
        let frame = br#"{"id":7,"result":{"unmodelled":{"kind":"Thing","rows":[1,2]}}}"#;
        let expected = json!({
            "unmodelled": {
                "kind": "Thing",
                "rows": [1, 2],
            }
        });
        // `deny_unknown_fields` closes the envelope and stops at the member
        // boundary: `result` stays a vendor document, so the interior members
        // it carries survive untouched. That asymmetry is the whole reason the
        // envelope is safe to close against a `Value`-typed result.
        assert_eq!(outcome(frame)?, expected);
        // The same frame without the unknown member is admitted, so the
        // `session` member is attributable as the cause of the refusal.
        assert!(admitted(br#"{"id":7,"result":null}"#).is_ok());
        assert!(admitted(br#"{"id":7,"session":"s","result":null}"#).is_err());
        Ok(())
    }

    #[test]
    fn provider_error_frame_is_refused_not_read_as_a_null_success() -> Result<(), AdapterError> {
        let frame = br#"{"id":7,"error":{"code":-32000,"message":"boom","kind":"Query"}}"#;
        // The vendor error object is admitted by the closed envelope, and this
        // frame names no `result` member at all, so the refusal below cannot be
        // the absent-outcome refusal wearing a null success.
        assert!(admitted(frame).is_ok());
        // The provider's own family and code cross, and the vendor prose
        // members cannot: `message` and `details` are dropped at the mapping
        // site, so the equality below is exact.
        assert_eq!(
            outcome(frame),
            Err(AdapterError::ProviderRefused {
                kind: Some("Query".to_owned()),
                code: -32000,
            })
        );
        Ok(())
    }
}
