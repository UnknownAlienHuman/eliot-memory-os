use crate::StoreError;
use eliot_types::{SurrealServerConfig, strict_json_has_no_duplicate_members};
use futures_util::{SinkExt, StreamExt};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use uuid::Uuid;

type RpcSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug)]
pub struct SurrealRpcTransport {
    socket: Mutex<RpcSocket>,
    request_timeout: Duration,
}

#[derive(Debug, Serialize)]
struct RpcRequest<'a> {
    id: String,
    method: &'a str,
    params: Value,
}

// Closed against unknown top-level members, so a response carrying a member this
// client does not know is refused rather than silently dropped. Safe for every
// method this client issues: SurrealDB's `DbResponse::into_value` emits only
// `result`/`error`, plus `id` when the client sent one, plus `session` only when
// the REQUEST carried a session - and this client's request type has exactly
// `id`, `method` and `params`, so `session` can never reach this decoder. The
// unprompted `session` only appears on the live-query notification path, and
// this client never issues `live`. SurrealDB's RPC is JSON-RPC-shaped, not
// JSON-RPC-2.0-enveloped, so there is no `jsonrpc` member to allow for.
//
// Exactly one outcome member is required, and the `result` member is decoded as
// `Option<Option<Value>>` rather than `Option<Value>` because serde maps an
// explicit JSON `null` onto `None` for any `Option<T>` field: with a bare
// `Option<Value>` an absent `result` and a present `"result": null` are the same
// value here, and SurrealDB sends the second one for real. At the pinned
// `v3.1.4` tag `surrealdb/core/src/rpc/response.rs` builds the response from
// `pub result: Result<DbResult, TypesError>`, so `into_value` always emits
// `result` or `error` and never neither; that tag's own
// `surrealdb/core/src/rpc/protocol.rs` returns `DbResult::Other(PublicValue::None)`
// for `attach`/`detach` (lines 133/139), `ping` (275), `authenticate` (656),
// `invalidate` (740), `revoke` (783) and `reset` (795), which serializes as
// `"result": null`. `DbResponse::from_value` in that same file answers a frame
// carrying neither member with the internal error "DbResponse must have either
// 'result' or 'error' field", so upstream names the neither-case invalid and
// this client refuses it in `rpc_result` instead of defaulting it to a null
// success.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcResponse {
    id: Option<Value>,
    #[serde(default, deserialize_with = "present_member")]
    result: Option<Option<Value>>,
    error: Option<RpcErrorBody>,
}

// The provider's real error object, verified against the pinned `v3.1.4` tag's
// `surrealdb/types/src/error.rs` rather than inferred:
//
//   pub struct Error {
//       #[surreal(default = "default_code")] code: i64,
//       message: String,
//       #[surreal(flatten)] details: ErrorDetails,
//       #[surreal(default)] cause: Option<Box<Error>>,
//   }
//
// and that file's own doc comment, verbatim: "The `details` field is flattened
// into the serialized object, so the wire format contains `kind` (string) and
// optionally `details` (object) at the same level as `code` and `message`."
// `ErrorDetails` derives `#[surreal(tag = "kind", content = "details",
// skip_content_if = "Value::is_empty")]`, so `kind` is emitted on EVERY error
// (only an empty `details` is skipped) and carries one of the eleven variant
// tags `ErrorDetails::kind_str` returns: "Validation", "Configuration",
// "Query", "Serialization", "NotAllowed", "NotFound", "AlreadyExists",
// "Connection", "Thrown", "Internal", "Context".
//
// Deliberately NOT closed (`deny_unknown_fields`): with `kind` always present
// and `details` present whenever it is non-empty, closing this would refuse
// every genuine provider error frame and turn each auth, query and credential
// failure into a decode failure that names no cause at all.
//
// `cause` is an optional nested error object there, and it is accepted and
// ignored here rather than decoded: it is a recursive vendor chain of
// unbounded prose that no ELIOT path consumes, so reading it into a `Value`
// would retain that whole chain for nothing. The previously declared `data`
// member is gone because the provider emits no such member at all - it was
// carried by every error frame while nothing could ever set it.
#[derive(Debug, Deserialize)]
struct RpcErrorBody {
    code: i64,
    message: String,
    // Upstream emits `kind` unconditionally, but an unrecognised frame must
    // still reach an operator as the provider's own code and message rather
    // than as a decode failure, so absence is admitted here and read as "the
    // provider stated no kind" - never as a more specific verdict.
    kind: Option<String>,
    // The flattened `details` object, decoded as a vendor document: read only
    // for the `kind` tag it carries (see `refused_authentication`) and never
    // echoed into any message.
    details: Option<Value>,
}

impl RpcErrorBody {
    /// Whether the provider itself attributed this refusal to authentication.
    ///
    /// At the pinned tag a credential or permission refusal arrives as
    /// `kind == "NotAllowed"` - upstream's `ErrorDetails::NotAllowed` tag - with
    /// `details` carrying `{"kind": "Auth", ...}`, upstream's
    /// `NotAllowedError::Auth` tag. A method, scripting, function or target
    /// denial is the same top-level `kind` with a different `details.kind`, and
    /// every other failure family carries a different top-level `kind`. So this
    /// answers true only for the refusals the provider labelled `Auth`: an
    /// absent `kind`, an absent `details`, a `details` that is not an object,
    /// and any kind this client does not know are all NOT authentication. Only
    /// the tag is read; no detail content is inspected or echoed.
    fn refused_authentication(&self) -> bool {
        self.kind.as_deref() == Some("NotAllowed")
            && matches!(
                &self.details,
                Some(Value::Object(details))
                    if details.get("kind").and_then(Value::as_str) == Some("Auth")
            )
    }
}

impl SurrealRpcTransport {
    pub async fn connect(
        config: &SurrealServerConfig,
        connect_timeout_ms: u64,
    ) -> Result<Self, StoreError> {
        let connect_timeout = millis(connect_timeout_ms);
        let mut request = config
            .endpoint
            .as_str()
            .into_client_request()
            .map_err(|error| StoreError::WebSocket(error.to_string()))?;
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("json"));
        let connect = connect_async(request);
        let (socket, _response) = timeout(connect_timeout, connect)
            .await
            .map_err(|_| StoreError::Timeout {
                op: "surreal rpc connect".to_owned(),
                ms: connect_timeout_ms,
            })?
            .map_err(|error| StoreError::WebSocket(error.to_string()))?;

        Ok(Self {
            socket: Mutex::new(socket),
            request_timeout: millis(config.query_timeout_ms),
        })
    }

    /// Signs in on this transport.
    ///
    /// No verdict is asserted here. A provider refusal on this path becomes
    /// [`StoreError::ServerAuthFailed`] only when the provider itself labelled
    /// the refusal an authentication one; the single mapping site is
    /// `provider_error`. Every other provider refusal keeps the provider's own
    /// code and message as [`StoreError::RpcError`], so an operator is not told
    /// the credentials failed when the provider said something else.
    pub async fn signin(&self, user: &str, password: &SecretString) -> Result<(), StoreError> {
        self.request(
            "signin",
            json!([{
                "user": user,
                "pass": password.expose_secret(),
            }]),
        )
        .await
        .map(|_| ())
    }

    pub async fn use_ns_db(&self, ns: &str, db: &str) -> Result<(), StoreError> {
        self.request("use", json!([ns, db])).await.map(|_| ())
    }

    pub async fn version(&self) -> Result<Value, StoreError> {
        self.request("version", Value::Array(Vec::new())).await
    }

    pub async fn query(&self, sql: &str, vars: Value) -> Result<Value, StoreError> {
        let bound_vars = if vars.is_null() {
            Value::Object(serde_json::Map::new())
        } else {
            vars
        };
        self.request("query", json!([sql, bound_vars])).await
    }

    pub async fn close(&self) -> Result<(), StoreError> {
        timeout(self.request_timeout, async {
            self.socket
                .lock()
                .await
                .send(Message::Close(None))
                .await
                .map_err(|error| StoreError::WebSocket(error.to_string()))
        })
        .await
        .map_err(|_| StoreError::Timeout {
            op: "surreal rpc close".to_owned(),
            ms: millis_u64(self.request_timeout),
        })?
    }

    async fn request(&self, method: &str, params: Value) -> Result<Value, StoreError> {
        let id = Uuid::new_v4().to_string();
        let expected_id = Value::String(id.clone());
        let payload = serde_json::to_string(&RpcRequest { id, method, params })
            .map_err(|error| StoreError::Decode(error.to_string()))?;

        timeout(self.request_timeout, async {
            let mut socket = self.socket.lock().await;
            socket
                .send(Message::text(payload))
                .await
                .map_err(|error| StoreError::WebSocket(error.to_string()))?;

            loop {
                let message = socket.next().await.ok_or(StoreError::ConnectionClosed)?;
                let message = message.map_err(|error| StoreError::WebSocket(error.to_string()))?;

                match message {
                    Message::Text(text) => {
                        let response = parse_response(text.as_str())?;
                        if response.id.as_ref() == Some(&expected_id) {
                            return rpc_result(method, response);
                        }
                    }
                    Message::Binary(bytes) => {
                        let text = String::from_utf8(bytes.to_vec())
                            .map_err(|error| StoreError::Decode(error.to_string()))?;
                        let response = parse_response(&text)?;
                        if response.id.as_ref() == Some(&expected_id) {
                            return rpc_result(method, response);
                        }
                    }
                    Message::Ping(payload) => socket
                        .send(Message::Pong(payload))
                        .await
                        .map_err(|error| StoreError::WebSocket(error.to_string()))?,
                    Message::Pong(_) | Message::Frame(_) => {}
                    Message::Close(_) => return Err(StoreError::ConnectionClosed),
                }
            }
        })
        .await
        .map_err(|_| StoreError::Timeout {
            op: format!("surreal rpc {method}"),
            ms: millis_u64(self.request_timeout),
        })?
    }
}

/// Decodes one RPC response frame, refusing a lexical duplicate object member
/// before the response id is read (#937, #938, #940).
///
/// `serde_json::from_str` collapses a repeated member to last-wins the instant
/// raw bytes become a `serde_json::Value`: this workspace builds
/// `serde_json::Map` without the `preserve_order` feature, so `Map` is a
/// `BTreeMap`. The call sites above then compare `response.id` against the
/// request id, so a duplicate-keyed frame was already an admission and routing
/// decision by the time any closed record in this crate could be validated.
/// Every decoder downstream therefore could not distinguish a duplicate
/// document from its last-wins equivalent, including the
/// `deny_unknown_fields` activation-graph rows that name this function as the
/// transport ingress owner whose byte-level guarantee they deliberately do not
/// claim (`crates/eliot-store/src/canonical_activation_graph_models.rs`).
///
/// This is the single raw-ingress gate for both the text and the binary frame
/// path, and it is a thin reuse of the shared `eliot_types::strict_json`
/// decoder — the same implementation `canonical_record.rs` consumes. It is not
/// a second parser, and it is not an extra per-call-site check. The typed decode
/// below is unchanged, so a duplicate member is refused and a duplicate-free
/// document keeps every previously accepted byte.
///
/// Named absence: these frames have no ELIOT-owned byte ceiling. Nothing in this
/// crate sets `WebSocketConfig`, `max_message_size` or `max_frame_size`, so only
/// the tungstenite library default bounds a frame. This gate therefore uses the
/// shared decoder's no-ceiling entry point rather than inventing a `max_bytes`
/// that no requirement states; the bytes are already received and resident
/// here, so a ceiling at this point could only newly refuse large but
/// legitimate query results. An ELIOT-owned response ceiling remains unowned.
fn parse_response(text: &str) -> Result<RpcResponse, StoreError> {
    strict_json_has_no_duplicate_members(text.as_bytes())
        .map_err(|error| StoreError::Decode(error.kind.as_str().to_owned()))?;

    serde_json::from_str(text).map_err(|error| StoreError::Decode(error.to_string()))
}

/// Keeps a present-but-null member distinguishable from an absent one.
///
/// A derived `Option<T>` field calls `deserialize_option`, which serde's
/// `Deserializer` answers with `visit_none` for an explicit `null`; so
/// `result: Option<Value>` cannot tell `{}` from `{"result": null}`. This
/// wrapper re-wraps the member's own `Option` decode, so absent stays `None`
/// (the field `default`), an explicit `null` becomes `Some(None)` and any other
/// value becomes `Some(Some(value))`.
fn present_member<'de, D>(deserializer: D) -> Result<Option<Option<Value>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Value>::deserialize(deserializer).map(Some)
}

/// Reduces one admitted RPC envelope to the outcome it actually reports.
///
/// `method` is the method this client asked for, and it earns a refusal exactly
/// one typed verdict: a provider error object names its own family in `kind`,
/// so the mapping below is driven by what the provider stated, not by which
/// operation happened to fail.
fn rpc_result(method: &str, response: RpcResponse) -> Result<Value, StoreError> {
    if let Some(error) = response.error {
        return Err(provider_error(method, error));
    }

    match response.result {
        Some(Some(result)) => Ok(result),
        // A present `result` member holding SurrealDB's own "no payload" null.
        Some(None) => Ok(Value::Null),
        // No outcome member at all. SurrealDB's `DbResponse::into_value` emits
        // `result` or `error` and never neither, so this frame is refused
        // instead of being answered with a default null success. The message
        // names the missing members and nothing else: no response body is
        // echoed into the error.
        None => Err(StoreError::Decode(
            "surreal rpc response carried neither a result nor an error member".to_owned(),
        )),
    }
}

/// Maps one provider error object onto the store error this operation earns.
///
/// The credential verdict is read from the wire, never inferred from the
/// operation. [`RpcErrorBody::refused_authentication`] is consulted only when
/// `method` is `signin`, and only a provider object that labelled the refusal
/// itself answers true, so a malformed request, a query failure, an internal
/// fault, or a frame with no `kind` all stay [`StoreError::RpcError`] - whose
/// `Display` names the provider's own `code` and `message` - instead of being
/// reported to an operator as a credential failure.
fn provider_error(method: &str, error: RpcErrorBody) -> StoreError {
    let refused_authentication = method == "signin" && error.refused_authentication();
    let rejection = StoreError::RpcError {
        code: error.code,
        message: error.message,
        // `StoreError::RpcError::data` is not a member of the provider's error
        // object, so there is nothing to put here: the provider emits no
        // `data`, and no code in this workspace reads the member. It is filled
        // with `None` deliberately rather than with the vendor `details` blob,
        // which is free-form provider prose that must not be retained in a
        // public error member. Removing the member is a coordinated edit to
        // `crates/eliot-store/src/error.rs` and its readers, not a local one.
        data: None,
    };

    if refused_authentication {
        // Byte-identical to the string this path produced before the provider's
        // kind was modelled, so a genuine credential refusal still reads
        // "SurrealDB authentication failed: SurrealDB RPC error -32002: <the
        // provider's own message>" (upstream's `INVALID_AUTH`).
        StoreError::ServerAuthFailed(rejection.to_string())
    } else {
        rejection
    }
}

const fn millis(ms: u64) -> Duration {
    Duration::from_millis(if ms == 0 { 1 } else { ms })
}

fn millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use eliot_types::StrictJsonErrorKind;
    use serde_json::json;

    use super::*;

    /// Decodes one wire frame from its raw bytes, exactly as the read loop does.
    ///
    /// Every fixture below is a byte literal. A `serde_json::Value` fixture is
    /// already the collapsed projection of those bytes, so it cannot observe
    /// the lexical facts the duplicate-member tests exist to pin.
    fn admitted(frame: &[u8]) -> Result<RpcResponse, StoreError> {
        let text = std::str::from_utf8(frame)
            .map_err(|error| StoreError::Decode(error.to_string()))?;
        parse_response(text)
    }

    /// The outcome one admitted frame reports for `method`.
    fn outcome(method: &str, frame: &[u8]) -> Result<Value, StoreError> {
        rpc_result(method, admitted(frame)?)
    }

    #[test]
    fn a_present_null_result_is_admitted_as_value_null() -> Result<(), StoreError> {
        // At the pinned `v3.1.4` tag `attach`, `detach`, `ping`, `authenticate`,
        // `invalidate`, `revoke` and `reset` all answer `PublicValue::None`,
        // which serialises as JSON `null`. `serde_json` reports that through
        // `visit_none`, so `{}` and `{"result": null}` are the same value for any
        // derived `Option<Value>` field: the `present_member` wrapper is the only
        // thing that keeps a genuine null result a success.
        assert_eq!(outcome("ping", br#"{"id":"r-1","result":null}"#)?, Value::Null);
        Ok(())
    }

    #[test]
    fn a_frame_naming_no_outcome_member_is_refused() -> Result<(), StoreError> {
        let frame = br#"{"id":"r-1"}"#;
        // Both the raw gate and the closed envelope admit these bytes, so the
        // missing `result` member is attributable as the whole cause: this is
        // not a lexical refusal and not an unknown-member refusal. It matters
        // most for `signin` and `use`, which discard the value, so a null
        // default here would read as a completed authentication.
        assert!(admitted(frame).is_ok());
        assert!(matches!(outcome("signin", frame), Err(StoreError::Decode(_))));
        Ok(())
    }

    #[test]
    fn repeated_result_member_is_refused_by_the_raw_gate() -> Result<(), StoreError> {
        let single = br#"{"id":"r-1","result":"last"}"#;
        let twice = br#"{"id":"r-1","result":"first","result":"last"}"#;
        // The last-wins projection of the twice-written frame decodes fine, so
        // only the lexical duplicate can be what refuses the pair of frames, and
        // it refuses them before the response id is read for routing.
        assert_eq!(outcome("query", single)?, Value::String("last".to_owned()));
        assert!(matches!(
            outcome("query", twice),
            Err(StoreError::Decode(reason)) if reason == StrictJsonErrorKind::DuplicateKey.as_str()
        ));
        Ok(())
    }

    #[test]
    fn an_unknown_top_level_member_is_refused_but_result_interior_members_are_not()
    -> Result<(), StoreError> {
        let frame = br#"{"id":"r-1","result":{"unmodelled":{"kind":"Thing","rows":[1,2]}}}"#;
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
        assert_eq!(outcome("query", frame)?, expected);
        // The same frame without the unknown member is admitted, so the
        // `session` member is attributable as the cause of the refusal.
        assert!(admitted(br#"{"id":"r-1","result":null}"#).is_ok());
        assert!(admitted(br#"{"id":"r-1","session":"s","result":null}"#).is_err());
        Ok(())
    }

    #[test]
    fn provider_error_frame_is_refused_not_read_as_a_null_success() -> Result<(), StoreError> {
        let frame = br#"{"id":"r-1","error":{"code":-32000,"message":"boom","kind":"Query"}}"#;
        // The vendor error object is admitted by the closed envelope, and this
        // frame names no `result` member at all, so the refusal below is the
        // provider's own refusal and never the absent-outcome refusal wearing a
        // null success.
        assert!(admitted(frame).is_ok());
        assert!(matches!(outcome("query", frame), Err(StoreError::RpcError { .. })));
        Ok(())
    }
}
