use crate::StoreError;
use eliot_types::{SurrealServerConfig, strict_json_has_no_duplicate_members};
use futures_util::{SinkExt, StreamExt};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Deserialize)]
struct RpcResponse {
    id: Option<Value>,
    result: Option<Value>,
    error: Option<RpcErrorBody>,
}

#[derive(Debug, Deserialize)]
struct RpcErrorBody {
    code: i64,
    message: String,
    data: Option<Value>,
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
        .map_err(|error| match error {
            StoreError::RpcError { .. } => StoreError::ServerAuthFailed(error.to_string()),
            other => other,
        })
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
                            return rpc_result(response);
                        }
                    }
                    Message::Binary(bytes) => {
                        let text = String::from_utf8(bytes.to_vec())
                            .map_err(|error| StoreError::Decode(error.to_string()))?;
                        let response = parse_response(&text)?;
                        if response.id.as_ref() == Some(&expected_id) {
                            return rpc_result(response);
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

fn rpc_result(response: RpcResponse) -> Result<Value, StoreError> {
    if let Some(error) = response.error {
        return Err(StoreError::RpcError {
            code: error.code,
            message: error.message,
            data: error.data,
        });
    }

    Ok(response.result.unwrap_or(Value::Null))
}

const fn millis(ms: u64) -> Duration {
    Duration::from_millis(if ms == 0 { 1 } else { ms })
}

fn millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
