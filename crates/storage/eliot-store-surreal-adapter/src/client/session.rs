//! An authenticated socket and its closed request lifetime. Never starts or stops a process.
use super::provider_owner::{
    ProviderOwner, require_listener_owner, require_unchanged_identity, validate_child_process,
};
use super::rpc_parse::{parse_response, provider_version_from_rpc, rpc_result};
use super::{RPC_PROTOCOL_VERSION, RpcRequest, RpcSocket, millis};
use crate::config::SurrealAdapterConfig;
use crate::error::AdapterError;
use eliot_platform_windows::{
    ProcessIdentity, RetainedProcessPathLease, observe_loopback_tcp_listener_owner,
};
use futures_util::{SinkExt, StreamExt};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::process::Child;
use tokio::sync::Mutex;
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest, http::HeaderValue},
};
use uuid::Uuid;

pub(super) struct RpcSession {
    socket: Mutex<RpcSocket>,
    request_timeout: Duration,
    // A session neither prolongs process ownership nor becomes a replacement owner.
    owner: Weak<ProviderOwner>,
}
impl fmt::Debug for RpcSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpcSession")
            .field("socket", &"private")
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}
impl RpcSession {
    pub(super) async fn connect(
        owner: &Arc<ProviderOwner>,
        deadline: Instant,
    ) -> Result<Self, AdapterError> {
        let mut child = owner.provider_child.lock().await;
        let before = validate_child_process(
            &owner.config,
            &owner.process_lease,
            &mut child,
            owner.provider_process_id,
        )?;
        require_unchanged_identity(
            &owner.provider_process_identity,
            &before,
            "session connection precheck",
        )?;
        let (socket, before_auth) = connect_started_provider(
            &owner.config,
            &owner.process_lease,
            &mut child,
            owner.provider_process_id,
            &before,
            deadline,
        )
        .await?;
        drop(child);
        let session = Self {
            socket: Mutex::new(socket),
            request_timeout: millis(owner.config.query_timeout_ms),
            owner: Arc::downgrade(owner),
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        timeout(remaining, authenticate_provider(&session, &owner.config))
            .await
            .map_err(|_| AdapterError::ProviderUnavailable)??;
        owner.validate_owned().await?;
        require_unchanged_identity(
            &before_auth,
            &owner.provider_process_identity,
            "authentication",
        )?;
        Ok(session)
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

    pub(super) async fn request(
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
        let _owner = self
            .owner
            .upgrade()
            .ok_or(AdapterError::ProviderUnavailable)?;
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

#[allow(async_fn_in_trait)]
pub(super) trait ProviderAuthentication {
    async fn version(&self) -> Result<Value, AdapterError>;
    async fn signin(&self, username: &str, password: &SecretString) -> Result<(), AdapterError>;
    async fn select_namespace_database(
        &self,
        namespace: &str,
        database: &str,
    ) -> Result<(), AdapterError>;
}

impl ProviderAuthentication for RpcSession {
    async fn version(&self) -> Result<Value, AdapterError> {
        self.request_without_params("provider.version", "version")
            .await
            .map_err(|error| match error {
                AdapterError::ProviderUnavailable => AdapterError::Config(
                    "SurrealDB version RPC is required before authentication".to_owned(),
                ),
                error => error,
            })
    }

    async fn signin(&self, username: &str, password: &SecretString) -> Result<(), AdapterError> {
        RpcSession::signin(self, username, password).await
    }

    async fn select_namespace_database(
        &self,
        namespace: &str,
        database: &str,
    ) -> Result<(), AdapterError> {
        self.use_ns_db(namespace, database).await
    }
}

pub(super) async fn authenticate_provider<T: ProviderAuthentication>(
    transport: &T,
    config: &SurrealAdapterConfig,
) -> Result<(), AdapterError> {
    let version = provider_version_from_rpc(&transport.version().await?)?;
    if version.major != config.expected_provider_major {
        return Err(AdapterError::Config(format!(
            "SurrealDB server major {} is incompatible with pinned major {}",
            version.major, config.expected_provider_major
        )));
    }
    transport.signin(&config.username, &config.password).await?;
    transport
        .select_namespace_database(&config.namespace, &config.database)
        .await
}

async fn connect_started_provider(
    config: &SurrealAdapterConfig,
    provider_process_lease: &RetainedProcessPathLease,
    child: &mut Child,
    provider_process_id: u32,
    identity_before_listener: &ProcessIdentity,
    deadline: Instant,
) -> Result<(RpcSocket, ProcessIdentity), AdapterError> {
    loop {
        if child
            .try_wait()
            .map_err(|_| AdapterError::ProviderUnavailable)?
            .is_some()
        {
            return Err(AdapterError::Config(
                "canonical provider exited before accepting its bound endpoint".to_owned(),
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(AdapterError::ProviderUnavailable);
        }
        let mut request = config
            .endpoint
            .as_str()
            .into_client_request()
            .map_err(|_| AdapterError::ProviderUnavailable)?;
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("json"));
        let attempt = timeout(
            remaining.min(Duration::from_millis(100)),
            connect_async(request),
        );
        if let Ok(Ok((socket, _))) = attempt.await {
            let endpoint = config
                .provider_bind_address
                .parse::<SocketAddr>()
                .map_err(|_| {
                    AdapterError::Config(
                        "provider bind address is not an exact loopback socket".to_owned(),
                    )
                })?;
            let owner = observe_loopback_tcp_listener_owner(endpoint).map_err(|_| {
                AdapterError::Config(
                    "canonical provider listener ownership could not be proven".to_owned(),
                )
            })?;
            require_listener_owner(provider_process_id, owner.process_id())?;
            let identity_after_listener =
                validate_child_process(config, provider_process_lease, child, provider_process_id)?;
            require_unchanged_identity(
                identity_before_listener,
                &identity_after_listener,
                "listener observation",
            )?;
            return Ok((socket, identity_after_listener));
        }
        sleep(remaining.min(Duration::from_millis(25))).await;
    }
}
