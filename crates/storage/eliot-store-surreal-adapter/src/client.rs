//! Private versioned named-operation WebSocket/RPC transport.
//!
//! This module owns the credential-bearing socket and the wire codec.  It is
//! intentionally independent of a `SurrealDB` SDK: the provider is reached only
//! through the server's JSON WebSocket endpoint, while the adapter supplies a
//! closed operation name and parameter map for every request.  No transport,
//! RPC response or provider type crosses the S-03 boundary.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use uuid::Uuid;

use crate::config::SurrealAdapterConfig;
use crate::error::AdapterError;

/// Wire revision for all S-03 requests.  The operation name is included in
/// every request identifier so traces cannot silently mix protocol revisions
/// or named operation families.
pub(crate) const RPC_PROTOCOL_VERSION: &str = "eliot.s03.rpc.v1";

type RpcSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// One authenticated provider session.  The socket mutex is also the request
/// ordering boundary: only one request may be in flight on a session, which
/// keeps response correlation deterministic and avoids a second writer.
#[derive(Debug)]
pub(crate) struct RpcTransport {
    socket: Mutex<RpcSocket>,
    request_timeout: Duration,
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

#[derive(Debug, Deserialize)]
struct SurrealVersionResponse {
    version: String,
}

/// Decoded results of one parameterized provider query.  Each entry is the
/// `result` member of one statement in order; provider `ERR` statuses remain
/// observable to the caller so write paths can classify them as unknown.
#[derive(Debug)]
pub(crate) struct RpcResults {
    values: Vec<Value>,
    errors: Vec<String>,
}

/// Dispatches one closed S-03 operation over the authenticated transport.
/// `config` remains an explicit argument at this seam so timeout and
/// credential policy cannot accidentally be supplied by a call-site value;
/// the transport already captured the validated timeout at connection time.
pub(crate) async fn query(
    transport: &RpcTransport,
    _config: &SurrealAdapterConfig,
    operation: &'static str,
    statement: &str,
    bindings: serde_json::Map<String, Value>,
) -> Result<RpcResults, AdapterError> {
    transport.query(operation, statement, bindings).await
}

impl RpcResults {
    fn from_value(value: &Value) -> Result<Self, AdapterError> {
        let statements = value.as_array().ok_or_else(|| {
            AdapterError::Serialization("RPC query result was not an array".to_owned())
        })?;
        let mut values = Vec::with_capacity(statements.len());
        let mut errors = Vec::new();
        for statement in statements {
            let status = statement.get("status").and_then(Value::as_str);
            let result = statement.get("result").cloned().unwrap_or(Value::Null);
            if status == Some("ERR") {
                errors.push(result.to_string());
            }
            values.push(result);
        }
        Ok(Self { values, errors })
    }

    pub(crate) fn take<T: DeserializeOwned>(&mut self, index: usize) -> Result<T, AdapterError> {
        let value = self.values.get(index).cloned().ok_or_else(|| {
            AdapterError::Serialization(format!("missing RPC statement result at index {index}"))
        })?;
        serde_json::from_value(value)
            .map_err(|error| AdapterError::Serialization(error.to_string()))
    }

    pub(crate) fn take_errors(&mut self) -> Vec<String> {
        std::mem::take(&mut self.errors)
    }
}

#[derive(Debug, serde::Serialize)]
struct RpcRequest<'a> {
    id: String,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
}

impl RpcTransport {
    /// Establishes one socket.  Authentication and namespace/database
    /// selection complete before the transport is returned to the adapter.
    pub(crate) async fn connect(config: &SurrealAdapterConfig) -> Result<Self, AdapterError> {
        config
            .validate()
            .map_err(|error| AdapterError::Config(error.to_string()))?;
        let connect_timeout = millis(config.connect_timeout_ms);
        let mut request = config
            .endpoint
            .as_str()
            .into_client_request()
            .map_err(|_| AdapterError::ProviderUnavailable)?;
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("json"));
        let (socket, _) = timeout(connect_timeout, connect_async(request))
            .await
            .map_err(|_| AdapterError::ProviderUnavailable)?
            .map_err(|_| AdapterError::ProviderUnavailable)?;

        let transport = Self {
            socket: Mutex::new(socket),
            request_timeout: millis(config.query_timeout_ms),
        };
        timeout(connect_timeout, async {
            transport.signin(&config.username, &config.password).await?;
            transport
                .use_ns_db(&config.namespace, &config.database)
                .await?;
            transport
                .verify_provider_version(config.expected_provider_major)
                .await
        })
        .await
        .map_err(|_| AdapterError::ProviderUnavailable)??;
        Ok(transport)
    }

    async fn signin(&self, username: &str, password: &SecretString) -> Result<(), AdapterError> {
        self.request(
            "auth.signin",
            "signin",
            json!([{
                "user": username,
                "pass": password.expose_secret(),
            }]),
        )
        .await
        .map(|_| ())
    }

    async fn use_ns_db(&self, namespace: &str, database: &str) -> Result<(), AdapterError> {
        self.request(
            "auth.select_namespace_database",
            "use",
            json!([namespace, database]),
        )
        .await
        .map(|_| ())
    }

    async fn verify_provider_version(&self, expected_major: u16) -> Result<(), AdapterError> {
        let value = self
            .request_without_params("provider.version", "version")
            .await
            .map_err(|error| match error {
                AdapterError::ProviderUnavailable => AdapterError::Config(
                    "SurrealDB version RPC is required for the pinned 3.x compatibility gate"
                        .to_owned(),
                ),
                error => error,
            })?;
        let response: SurrealVersionResponse = serde_json::from_value(value).map_err(|error| {
            AdapterError::Serialization(format!("invalid SurrealDB version RPC result: {error}"))
        })?;
        let major = response
            .version
            .split('.')
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| {
                AdapterError::Config(format!(
                    "SurrealDB version RPC returned an invalid version: {}",
                    response.version
                ))
            })?;
        if major != expected_major {
            return Err(AdapterError::Config(format!(
                "SurrealDB server major {major} is incompatible with pinned major {expected_major}"
            )));
        }
        Ok(())
    }

    /// Executes one closed named operation using `SurrealDB`'s parameterized
    /// `query` RPC.  The statement is private schema data; callers provide a
    /// name and bindings rather than a provider client or query result type.
    pub(crate) async fn query(
        &self,
        operation: &'static str,
        statement: &str,
        bindings: serde_json::Map<String, Value>,
    ) -> Result<RpcResults, AdapterError> {
        let value = self
            .request(
                operation,
                "query",
                json!([statement, Value::Object(bindings)]),
            )
            .await?;
        RpcResults::from_value(&value)
    }

    async fn request(
        &self,
        operation: &'static str,
        method: &'static str,
        params: Value,
    ) -> Result<Value, AdapterError> {
        let id = format!("{RPC_PROTOCOL_VERSION}:{operation}:{}", Uuid::new_v4());
        let expected_id = Value::String(id.clone());
        let payload = serde_json::to_string(&RpcRequest {
            id,
            method,
            params: Some(params),
        })
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;

        self.request_payload(payload, expected_id).await
    }

    async fn request_without_params(
        &self,
        operation: &'static str,
        method: &'static str,
    ) -> Result<Value, AdapterError> {
        let id = format!("{RPC_PROTOCOL_VERSION}:{operation}:{}", Uuid::new_v4());
        let expected_id = Value::String(id.clone());
        let payload = serde_json::to_string(&RpcRequest {
            id,
            method,
            params: None,
        })
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;

        self.request_payload(payload, expected_id).await
    }

    async fn request_payload(
        &self,
        payload: String,
        expected_id: Value,
    ) -> Result<Value, AdapterError> {
        timeout(self.request_timeout, async {
            let mut socket = self.socket.lock().await;
            socket
                .send(Message::Text(payload.into()))
                .await
                .map_err(|_| AdapterError::ProviderUnavailable)?;

            loop {
                let message = socket
                    .next()
                    .await
                    .ok_or(AdapterError::ProviderUnavailable)?
                    .map_err(|_| AdapterError::ProviderUnavailable)?;
                match message {
                    Message::Text(text) => {
                        let response = parse_response(text.as_str())?;
                        if response.id.as_ref() == Some(&expected_id) {
                            return rpc_result(response);
                        }
                    }
                    Message::Binary(bytes) => {
                        let text = String::from_utf8(bytes.to_vec())
                            .map_err(|error| AdapterError::Serialization(error.to_string()))?;
                        let response = parse_response(&text)?;
                        if response.id.as_ref() == Some(&expected_id) {
                            return rpc_result(response);
                        }
                    }
                    Message::Ping(payload) => socket
                        .send(Message::Pong(payload))
                        .await
                        .map_err(|_| AdapterError::ProviderUnavailable)?,
                    Message::Pong(_) | Message::Frame(_) => {}
                    Message::Close(_) => return Err(AdapterError::ProviderUnavailable),
                }
            }
        })
        .await
        .map_err(|_| AdapterError::ProviderUnavailable)?
    }
}

fn parse_response(text: &str) -> Result<RpcResponse, AdapterError> {
    serde_json::from_str(text).map_err(|error| AdapterError::Serialization(error.to_string()))
}

fn rpc_result(response: RpcResponse) -> Result<Value, AdapterError> {
    if let Some(error) = response.error {
        let _ = (error.code, error.message, error.data);
        return Err(AdapterError::ProviderUnavailable);
    }
    Ok(response.result.unwrap_or(Value::Null))
}

const fn millis(ms: u64) -> Duration {
    Duration::from_millis(if ms == 0 { 1 } else { ms })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn query_results_keep_statement_order_and_errors() {
        let mut results = RpcResults::from_value(&json!([
            {"status": "OK", "result": [1, 2]},
            {"status": "ERR", "result": "cas failed"}
        ]))
        .expect("valid result envelope");
        assert_eq!(
            results.take::<Vec<u8>>(0).expect("first result"),
            vec![1, 2]
        );
        assert_eq!(results.take_errors(), vec!["\"cas failed\""]);
    }

    #[test]
    fn request_ids_are_versioned_by_construction() {
        let id = format!("{RPC_PROTOCOL_VERSION}:named-operation:request");
        assert!(id.starts_with("eliot.s03.rpc.v1:named-operation:"));
    }
}
