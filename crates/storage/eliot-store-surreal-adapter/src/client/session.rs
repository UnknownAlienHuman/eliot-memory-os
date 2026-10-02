//! An authenticated socket and its closed request lifetime. Never starts or stops a process.
use super::provider_owner::{
    ProviderOwner, require_listener_owner, require_unchanged_identity, validate_child_process,
};
use super::rpc_parse::{
    ResponseCeiling, parse_response, parse_response_bounded, provider_version_from_rpc,
    response_ceiling_refusal, rpc_result,
};
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
    MaybeTlsStream, connect_async_with_config,
    tungstenite::{
        Message,
        client::IntoClientRequest,
        error::{CapacityError, Error as TransportError},
        http::HeaderValue,
        protocol::WebSocketConfig,
    },
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
            ResponseCeiling::session_wide(),
        )
        .await?;
        drop(child);
        let session = Self {
            socket: Mutex::new(socket),
            request_timeout: millis(owner.config.query_timeout_ms),
            owner: Arc::downgrade(owner),
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        let version = timeout(remaining, authenticate_provider(&session, &owner.config))
            .await
            .map_err(|_| AdapterError::ProviderUnavailable)??;
        owner.validate_owned().await?;
        require_unchanged_identity(
            &before_auth,
            &owner.provider_process_identity,
            "authentication",
        )?;
        owner.record_authenticated_version(version);
        Ok(session)
    }
    async fn signin(&self, username: &str, password: &SecretString) -> Result<(), AdapterError> {
        self.request_with_guard(
            "auth.signin",
            "signin",
            json!([{
                "user": username,
                "pass": password.expose_secret(),
            }]),
            true,
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
        self.request_with_guard(operation, method, params, false)
            .await
    }

    /// Issues one request whose response is admitted under `ceiling`.
    ///
    /// This is the bounded-capture entry point of the accepted transport
    /// (issue #951). It differs from [`RpcSession::request`] in exactly one way:
    /// each frame the response arrives in is charged against `ceiling` before
    /// the binary arm copies it and before any JSON `Value` is constructed. The
    /// session's own socket was already constructed under the ELIOT-issued
    /// transport bound (see [`response_bound_config`]), which is at or above
    /// this one, so an oversize frame is refused there while it is still a
    /// network frame. Everything else — the versioned request id, the deadline,
    /// the owner-liveness check, the connection-peer proof — is unchanged, so a
    /// bounded capture cannot acquire a different transport, a different
    /// operation identity or a weaker time bound than any other named
    /// operation.
    pub(super) async fn request_bounded(
        &self,
        operation: &'static str,
        method: &'static str,
        params: Value,
        ceiling: ResponseCeiling,
    ) -> Result<Value, AdapterError> {
        let id = format!("{RPC_PROTOCOL_VERSION}:{operation}:{}", Uuid::new_v4());
        let expected_id = Value::String(id.clone());
        let payload = serde_json::to_string(&RpcRequest {
            id,
            method,
            params: Some(params),
        })
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;

        self.request_payload(payload, expected_id, false, Some(ceiling))
            .await
    }

    async fn request_with_guard(
        &self,
        operation: &'static str,
        method: &'static str,
        params: Value,
        prove_connection_owner: bool,
    ) -> Result<Value, AdapterError> {
        let id = format!("{RPC_PROTOCOL_VERSION}:{operation}:{}", Uuid::new_v4());
        let expected_id = Value::String(id.clone());
        let payload = serde_json::to_string(&RpcRequest {
            id,
            method,
            params: Some(params),
        })
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;

        self.request_payload(payload, expected_id, prove_connection_owner, None)
            .await
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

        self.request_payload(payload, expected_id, true, None).await
    }

    /// Sends one payload and reads its response under the accepted transport's
    /// time bound, plus an optional ELIOT-owned response byte ceiling.
    ///
    /// `ceiling` is `Some` exactly for the bounded capture path, and it is
    /// charged **per received frame**, not per request: the loop below keeps
    /// reading while the response id does not match, and each frame it reads is
    /// charged against the same ceiling independently. The aggregate number of
    /// frames one request may read is therefore bounded by the request deadline,
    /// not by the ceiling. Nothing here is a per-request aggregate byte bound;
    /// the capture's own admitted `max_bytes` is the aggregate bound, and it is
    /// charged in `backup_snapshot::read_enumeration`.
    ///
    /// Two positions bound the response, and the order between them is the point:
    ///
    /// * the *transport* bound was fixed when this session's socket was
    ///   constructed (see [`response_bound_config`]), from
    ///   [`ResponseCeiling::session_wide`] and the owner-issued
    ///   `MAX_SNAPSHOT_BYTES`. The provider library refuses a frame or message
    ///   above it while the payload is still a network frame: its frame codec
    ///   reads the declared length, compares it with `max_frame_size` and
    ///   refuses before the payload is buffered at all, and it compares a
    ///   complete message with `max_message_size` before a text payload is
    ///   validated as UTF-8. An oversize response is therefore never
    ///   materialised, for either arm, and that is what the ELIOT bound buys.
    /// * this function then charges each frame it is handed against the
    ///   *capture's own* ceiling, which is at or below the transport bound. That
    ///   charge is what keeps the two positions in agreement and what refuses a
    ///   frame the session-wide bound would admit but this capture's smaller
    ///   admitted budget does not. It happens before the binary arm copies the
    ///   frame and before any `Value` is built.
    ///
    /// Both positions, including the refusal the transport itself raises (see
    /// [`transport_read_error`]), produce the same typed
    /// `StoreError::PayloadTooLarge`. When `ceiling` is `None` the previous
    /// unbounded read is unchanged: the ceiling is a property of an admitted
    /// capture budget, and no other named operation has one.
    async fn request_payload(
        &self,
        payload: String,
        expected_id: Value,
        prove_connection_owner: bool,
        ceiling: Option<ResponseCeiling>,
    ) -> Result<Value, AdapterError> {
        let owner = self
            .owner
            .upgrade()
            .ok_or(AdapterError::ProviderUnavailable)?;
        let read_response = async {
            let mut socket = self.socket.lock().await;
            if prove_connection_owner {
                let (client_local_endpoint, peer_endpoint) =
                    connected_tcp_endpoints(socket.get_ref())?;
                owner
                    .validate_connected_peer(client_local_endpoint, peer_endpoint)
                    .await?;
            }
            socket
                .send(Message::Text(payload.into()))
                .await
                .map_err(|_| AdapterError::ProviderUnavailable)?;

            loop {
                let message = socket
                    .next()
                    .await
                    .ok_or(AdapterError::ProviderUnavailable)?
                    .map_err(|error| transport_read_error(&error))?;
                match message {
                    Message::Text(text) => {
                        let response = match ceiling {
                            Some(ceiling) => {
                                parse_response_bounded(text.as_str().as_bytes(), ceiling)?
                            }
                            None => parse_response(text.as_str())?,
                        };
                        if response.id.as_ref() == Some(&expected_id) {
                            return rpc_result(response);
                        }
                    }
                    Message::Binary(bytes) => {
                        // The bounded arm reads the frame in place: the ceiling
                        // is charged against the borrowed slice, so the second
                        // copy the unbounded arm makes is never taken.
                        let response = if let Some(ceiling) = ceiling {
                            parse_response_bounded(&bytes, ceiling)?
                        } else {
                            let text = String::from_utf8(bytes.to_vec())
                                .map_err(|error| AdapterError::Serialization(error.to_string()))?;
                            parse_response(&text)?
                        };
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
        };
        // The deadline maps only its own expiry onto a transport loss. A
        // response-size refusal is an exact, typed outcome of the admitted
        // budget and is returned unchanged: folding it into
        // `ProviderUnavailable` would report an over-budget source as a lost
        // provider and let a bounded refusal read as retryable.
        timeout(self.request_timeout, read_response)
            .await
            .map_err(|_| AdapterError::ProviderUnavailable)?
    }
}

/// Builds the transport response bound every socket this session owns is
/// constructed with.
///
/// This is where the ELIOT-issued bound reaches the WebSocket layer, and it is
/// deliberately not an `Option`: [`tokio_tungstenite::connect_async`] resolves a
/// `None` configuration to the provider library's incidental defaults (16 MiB per
/// frame, 64 MiB per message), and a socket built under those defaults refuses a
/// single-frame response between them *inside the library* — before any ELIOT
/// code runs — with a capacity error that would otherwise be indistinguishable
/// from a lost provider.
///
/// The bound is derived from [`ResponseCeiling::session_wide`], which is itself
/// derived from the owner-issued `MAX_SNAPSHOT_BYTES` every admitted capture
/// budget is checked against, so the transport bound is never weaker than the
/// bound the largest admissible capture needs and cannot refuse a capture its own
/// admitted budget allows.
///
/// Every other configuration field is left at the library default, so this
/// narrows the frame and message bounds and changes nothing else about the
/// transport. `tungstenite` accepts this configuration once, at connect: it
/// exposes no way to change a live socket's bounds, which is why the transport
/// bound is the session-wide issue and the per-capture ceiling is charged per
/// frame in [`RpcSession::request_payload`].
fn response_bound_config(ceiling: ResponseCeiling) -> Result<WebSocketConfig, AdapterError> {
    let bound = usize::try_from(ceiling.max_bytes()).map_err(|_| response_ceiling_refusal())?;
    Ok(WebSocketConfig::default()
        .max_frame_size(Some(bound))
        .max_message_size(Some(bound)))
}

/// Maps one transport read failure onto the adapter's error model.
///
/// A capacity error means the provider answered with a frame or message the
/// ELIOT-issued transport bound does not admit, so it becomes the *same* typed
/// bounded refusal [`response_ceiling_refusal`] raises at the frame charge and
/// in the bounded decoder. It is deliberately not
/// [`AdapterError::ProviderUnavailable`]: the source answered, and
/// `StoreError::Unavailable` is retryable, so folding this into a transport loss
/// would let a bounded refusal masquerade as a lost provider and be resolved away
/// as a transient read.
///
/// Every other read failure — a closed or reset connection, a protocol
/// violation, an I/O error — stays a transport loss.
fn transport_read_error(error: &TransportError) -> AdapterError {
    if matches!(
        *error,
        TransportError::Capacity(CapacityError::MessageTooLong { .. })
    ) {
        response_ceiling_refusal()
    } else {
        AdapterError::ProviderUnavailable
    }
}

fn connected_tcp_endpoints(
    stream: &MaybeTlsStream<tokio::net::TcpStream>,
) -> Result<(SocketAddr, SocketAddr), AdapterError> {
    match stream {
        MaybeTlsStream::Plain(stream) => {
            let client_local_endpoint = stream
                .local_addr()
                .map_err(|_| AdapterError::ProviderUnavailable)?;
            let peer_endpoint = stream
                .peer_addr()
                .map_err(|_| AdapterError::ProviderUnavailable)?;
            Ok((client_local_endpoint, peer_endpoint))
        }
        _ => Err(AdapterError::Config(
            "provider WebSocket transport does not expose its TCP peer".to_owned(),
        )),
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
) -> Result<super::rpc_parse::ProviderVersion, AdapterError> {
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
        .await?;
    Ok(version)
}

/// Opens one authenticated-capable socket to the owned provider process.
///
/// `response_bound` is required, not optional: it is the ELIOT-issued transport
/// bound the socket is constructed with (see [`response_bound_config`]), so a
/// socket that reached the provider under the provider library's incidental
/// defaults cannot be expressed at this seam.
async fn connect_started_provider(
    config: &SurrealAdapterConfig,
    provider_process_lease: &RetainedProcessPathLease,
    child: &mut Child,
    provider_process_id: u32,
    identity_before_listener: &ProcessIdentity,
    deadline: Instant,
    response_bound: ResponseCeiling,
) -> Result<(RpcSocket, ProcessIdentity), AdapterError> {
    // Decided once, before the first attempt, so every socket this connect
    // produces is built under the same ELIOT-issued response bound.
    let response_config = response_bound_config(response_bound)?;
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
            connect_async_with_config(request, Some(response_config), false),
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

#[cfg(all(test, windows))]
mod ownership_tests {
    #![allow(clippy::expect_used, clippy::print_stdout, clippy::large_futures)]
    use super::super::provider_owner::{configure_provider_command, provider_environment};
    use super::*;
    use crate::{SchemaGeneration, SurrealStoreAdapter};
    use eliot_platform_windows::WindowsPlatform;
    use eliot_store_api::sha256_hex;
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use tokio::net::TcpStream;
    use tokio::process::Command;

    use super::super::payload_tests::test_readiness::connect_with_readiness_retry;

    struct Harness {
        root: PathBuf,
        config: SurrealAdapterConfig,
        adapter: Option<SurrealStoreAdapter>,
    }
    impl Harness {
        async fn provision() -> Self {
            let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve loopback");
            let port = reservation.local_addr().expect("address").port();
            let root = std::env::temp_dir().join(format!("eliot-986-{}", Uuid::new_v4()));
            let exe = root.join("bin/surreal.exe");
            for path in [
                root.join("bin"),
                root.join("store/data"),
                root.join("store/work"),
                root.join("store/tmp"),
            ] {
                std::fs::create_dir_all(path).expect("isolated directory");
            }
            let provider = std::env::var_os("ELIOT_TEST_SURREAL_EXE").map_or_else(
                || PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
                PathBuf::from,
            );
            std::fs::copy(provider, &exe).expect("stage provider");
            let bind = format!("127.0.0.1:{port}");
            let mut config = SurrealAdapterConfig {
                endpoint: format!("ws://{bind}/rpc"),
                namespace: "ownership986".into(),
                database: "selected986".into(),
                username: "ownership986-user".into(),
                password: SecretString::new(format!("test-{}", Uuid::new_v4()).into()),
                provider_bootstrap_username: "provider-bootstrap-fixture".to_owned(),
                provider_bootstrap_password: SecretString::new(
                    "provider-bootstrap-fixture-secret".into(),
                ),
                provider_bind_address: bind,
                installation_id: "ownership986".into(),
                installation_profile: "portable_dev".into(),
                runtime_state_roots_digest: "a".repeat(64),
                provider_executable_path: exe.to_string_lossy().into_owned(),
                provider_artifact_digest: sha256_hex(&std::fs::read(&exe).expect("provider bytes")),
                provider_arguments: Vec::new(),
                store_data_root: root.join("store/data").to_string_lossy().into_owned(),
                store_work_root: root.join("store/work").to_string_lossy().into_owned(),
                store_temp_root: root.join("store/tmp").to_string_lossy().into_owned(),
                connect_timeout_ms: 30_000,
                query_timeout_ms: 30_000,
                expected_provider_major: crate::PINNED_SURREALDB_MAJOR,
                expected_schema_generation: SchemaGeneration::v2(),
            };
            config.provider_arguments = config.expected_provider_arguments();
            let mut command = Command::new(&exe);
            configure_provider_command(
                &mut command,
                &config,
                &provider_environment(&config).expect("environment"),
            );
            command
                .env("SURREAL_USER", &config.username)
                .env("SURREAL_PASS", config.password.expose_secret());
            drop(reservation);
            let mut child = command.spawn().expect("bootstrap child");
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                assert!(
                    child.try_wait().expect("bootstrap state").is_none(),
                    "bootstrap exited"
                );
                if TcpStream::connect(&config.provider_bind_address)
                    .await
                    .is_ok()
                {
                    break;
                }
                assert!(Instant::now() < deadline, "bootstrap timed out");
                sleep(Duration::from_millis(50)).await;
            }
            child.kill().await.expect("stop bootstrap");
            child.wait().await.expect("reap bootstrap");
            Self {
                root,
                config,
                adapter: None,
            }
        }
        fn construct(&mut self) {
            let platform = WindowsPlatform::new(self.root.clone()).expect("platform");
            let lease = platform
                .retain_process_path_lease(
                    Path::new(&self.config.provider_executable_path),
                    Path::new(&self.config.store_work_root),
                    &self.config.provider_artifact_digest,
                )
                .expect("retained lease");
            self.adapter =
                Some(SurrealStoreAdapter::new(self.config.clone(), lease).expect("adapter"));
        }
        async fn start() -> Self {
            let mut harness = Self::provision().await;
            // Bounded readiness retry (PR #1488 pattern): slow provider
            // authentication waits up to ~30s with 100ms backoff instead of
            // failing on the first attempt. Last error is preserved on timeout.
            // Shared helper lives in `payload_tests::test_readiness` (test-only,
            // single definition) to avoid duplicating the retry loop.
            connect_with_readiness_retry(&harness.root, &harness.config, &mut harness.adapter)
                .await;
            harness
        }
        fn adapter(&self) -> &SurrealStoreAdapter {
            self.adapter.as_ref().expect("adapter")
        }
        fn transport(&self) -> &super::super::RpcTransport {
            self.adapter()
                .client
                .get()
                .expect("initialized")
                .as_ref()
                .expect("connected")
        }
        async fn second(&self) -> RpcSession {
            RpcSession::connect(
                &self.transport().provider,
                Instant::now() + Duration::from_secs(30),
            )
            .await
            .expect("second session")
        }
        async fn stop_child(&self) {
            if let Some(Ok(transport)) = self.adapter().client.get() {
                let mut child = transport.provider.provider_child.lock().await;
                child.kill().await.expect("stop exact child");
                child.wait().await.expect("reap exact child");
            }
        }
        async fn cleanup(mut self) {
            self.stop_child().await;
            self.adapter.take();
            remove_fixture(&self.root).await;
        }
        fn observed_identity(&self) -> ProcessIdentity {
            WindowsPlatform::new(self.root.clone())
                .expect("platform")
                .process_identity(self.transport().provider.provider_process_id)
                .expect("observed identity")
        }
    }
    async fn remove_fixture(root: &Path) {
        // Windows can keep an exiting image mapped briefly after its process
        // becomes unqueryable. A failed delete is not proof of resource release.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match std::fs::remove_dir_all(root) {
                Ok(()) => return,
                Err(error)
                    if matches!(error.raw_os_error(), Some(5 | 32))
                        && Instant::now() < deadline =>
                {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("isolated fixture cleanup failed: {error}"),
            }
        }
    }
    async fn selected(session: &RpcSession) -> Value {
        session
            .request(
                "proof.986.selected",
                "query",
                json!(["RETURN [session::ns(), session::db()];", {}]),
            )
            .await
            .expect("selected session query")
    }
    fn assert_selected(value: &Value) {
        assert_eq!(value[0]["status"], "OK");
        assert_eq!(value[0]["result"], json!(["ownership986", "selected986"]));
    }

    // WORK_UNIT_CASE: 986/2
    #[tokio::test]
    async fn first_adapter_connection_retains_one_exact_provider() {
        let h = Harness::start().await;
        let expected = h.observed_identity();
        assert_eq!(expected, h.transport().provider.provider_process_identity);
        h.adapter().connect().await.expect("same lazy session");
        assert_eq!(expected, h.observed_identity());
        assert!(crate::config::StoreDataRootLease::claim(&h.config.store_data_root).is_err());
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 986/3
    #[tokio::test]
    async fn second_session_uses_the_same_provider_and_root() {
        let h = Harness::start().await;
        let before = h.observed_identity();
        let second = h.second().await;
        assert!(Weak::ptr_eq(&h.transport().session.owner, &second.owner));
        assert_eq!(before, h.observed_identity());
        assert_selected(&selected(&h.transport().session).await);
        assert_selected(&selected(&second).await);
        drop(second);
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 986/4
    #[tokio::test]
    async fn dropping_a_session_preserves_other_session_and_process() {
        let h = Harness::start().await;
        let before = h.observed_identity();
        let second = h.second().await;
        drop(second);
        h.transport()
            .provider
            .validate_owned()
            .await
            .expect("owner remains live");
        assert_eq!(before, h.observed_identity());
        assert_selected(&selected(&h.transport().session).await);
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 986/5
    #[tokio::test]
    async fn failed_partial_session_does_not_stop_the_owned_provider() {
        let h = Harness::start().await;
        let before = h.observed_identity();
        let result = RpcSession::connect(&h.transport().provider, Instant::now()).await;
        assert!(result.is_err(), "expired connection cannot become ready");
        // Authentication failure on a separate real socket cannot alter the first session.
        let partial = h.second().await;
        let bad = SecretString::new("incorrect-password-986".into());
        assert!(partial.signin(&h.config.username, &bad).await.is_err());
        drop(partial);
        assert_eq!(before, h.observed_identity());
        assert_selected(&selected(&h.transport().session).await);
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 986/6
    #[tokio::test]
    async fn retained_lease_executable_and_root_mismatches_are_refused() {
        let mut h = Harness::provision().await;
        h.construct();
        let lease = Arc::clone(&h.adapter().provider_process_lease);
        for field in ["digest", "work", "data"] {
            let mut wrong = h.config.clone();
            match field {
                "digest" => wrong.provider_artifact_digest = "0".repeat(64),
                "work" => {
                    wrong.store_work_root =
                        h.root.join("other-work").to_string_lossy().into_owned();
                    std::fs::create_dir_all(&wrong.store_work_root).expect("other work");
                    wrong.provider_arguments = wrong.expected_provider_arguments();
                }
                "data" => wrong.store_data_root = wrong.store_work_root.clone(),
                _ => unreachable!(),
            }
            assert!(
                ProviderOwner::start(&wrong, Arc::clone(&lease))
                    .await
                    .is_err(),
                "accepted {field}"
            );
        }
        drop(lease);
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 986/7
    #[tokio::test]
    async fn a_foreign_listener_is_never_adopted() {
        let mut h = Harness::provision().await;
        let listener =
            TcpListener::bind(&h.config.provider_bind_address).expect("foreign listener");
        h.construct();
        let error = h.adapter().connect().await.expect_err("foreign occupancy");
        assert!(matches!(error, AdapterError::Config(ref message) if message.contains("occupied")));
        assert_eq!(
            observe_loopback_tcp_listener_owner(listener.local_addr().expect("address"))
                .expect("owner")
                .process_id(),
            std::process::id()
        );
        drop(listener);
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 986/8
    #[tokio::test]
    async fn replacement_identity_cannot_be_adopted_by_an_old_session() {
        let h = Harness::start().await;
        let before = h.observed_identity();
        let after = ProcessIdentity {
            start_time_100ns: before.start_time_100ns + 1,
            ..before.clone()
        };
        assert!(
            require_unchanged_identity(&before, &after, "session connection precheck").is_err()
        );
        h.stop_child().await;
        assert!(h.transport().provider.validate_owned().await.is_err());
        assert!(
            h.transport()
                .session
                .request("proof.986.dead", "version", json!([]))
                .await
                .is_err()
        );
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 986/10
    #[tokio::test]
    async fn a_retired_owner_cannot_create_a_current_session() {
        let h = Harness::start().await;
        h.stop_child().await;
        let result = RpcSession::connect(
            &h.transport().provider,
            Instant::now() + Duration::from_secs(2),
        )
        .await;
        assert!(result.is_err());
        // Creation is confined to the owner's immutable profile; no caller endpoint/config exists.
        assert_eq!(
            h.transport().provider.config.expected_schema_generation,
            h.config.expected_schema_generation
        );
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 986/11
    #[tokio::test]
    async fn final_owner_drop_does_not_turn_session_lifetime_into_process_ownership() {
        let mut h = Harness::start().await;
        let session = h.second().await;
        let identity = h.observed_identity();
        let platform = WindowsPlatform::new(h.root.clone()).expect("platform");
        h.adapter.take();
        assert!(session.owner.upgrade().is_none());
        assert!(
            session
                .request("proof.986.retired", "version", json!([]))
                .await
                .is_err()
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if platform.process_identity(identity.process_id).is_err() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "forced drop did not produce observed process exit"
            );
            sleep(Duration::from_millis(20)).await;
        }
        assert!(
            observe_loopback_tcp_listener_owner(
                h.config.provider_bind_address.parse().expect("address")
            )
            .is_err()
        );
        drop(session);
        // This is observed forced exit only; no clean-shutdown status or receipt is produced.
        drop(platform);
        remove_fixture(&h.root).await;
    }

    // WORK_UNIT_CASE: 986/12
    #[tokio::test]
    async fn failed_startup_is_cached_without_retry_or_success_invention() {
        let mut h = Harness::provision().await;
        h.config.password = SecretString::new("wrong-startup-credential-986".into());
        h.construct();
        let first = h
            .adapter()
            .connect()
            .await
            .expect_err("authentication must fail");
        let cached = h.adapter().client.get().expect("recorded outcome");
        assert!(cached.is_err());
        let second = h.adapter().connect().await.expect_err("cached refusal");
        assert_eq!(first, second);
        assert!(std::ptr::eq(
            cached,
            h.adapter().client.get().expect("same outcome")
        ));
        // Await disappearance; a failed constructor or socket drop alone is not exit proof.
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(&h.config.provider_bind_address)
            .await
            .is_ok()
        {
            assert!(Instant::now() < deadline, "failed startup retains listener");
            sleep(Duration::from_millis(20)).await;
        }
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 986/13
    #[tokio::test]
    async fn named_operation_results_errors_correlation_and_deadline_are_preserved() {
        let h = Harness::start().await;
        let mut result = super::super::query(
            h.transport(),
            &h.config,
            "proof.986.named",
            "RETURN $value;",
            serde_json::Map::from_iter([("value".into(), json!("scope:record"))]),
        )
        .await
        .expect("named result");
        assert!(result.take_errors().is_empty());
        assert_eq!(result.take::<String>(0).expect("string"), "scope:record");
        let mut errors = super::super::query(
            h.transport(),
            &h.config,
            "proof.986.error",
            "THROW 'bounded-test-error';",
            serde_json::Map::new(),
        )
        .await
        .expect("statement response");
        assert_eq!(errors.take_errors().len(), 1);
        let mut bounded = h.second().await;
        bounded.request_timeout = Duration::from_millis(50);
        let started = Instant::now();
        assert_eq!(
            bounded
                .request(
                    "proof.986.timeout",
                    "query",
                    json!(["SLEEP 1s; RETURN 1;", {}])
                )
                .await
                .expect_err("bounded timeout"),
            AdapterError::ProviderUnavailable
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        // An uncertain session is discarded, never reconnected or replayed here.
        drop(bounded);
        assert_selected(&selected(&h.transport().session).await);
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 986/14
    #[tokio::test]
    async fn process_session_and_adapter_debug_redact_sensitive_canaries() {
        let h = Harness::start().await;
        let rendered = format!(
            "{:?} {:?} {:?}",
            h.adapter(),
            h.transport().provider,
            h.transport().session
        );
        for canary in [
            &h.config.username,
            h.config.password.expose_secret(),
            &h.config.provider_executable_path,
            &h.config.store_data_root,
            &h.config.store_work_root,
            &h.config.store_temp_root,
            "--temporary-directory",
        ] {
            assert!(!rendered.contains(canary), "sensitive diagnostic field");
        }
        assert!(!rendered.contains("scope:record"));
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 986/15
    #[tokio::test]
    async fn windows_two_session_process_identity_and_cleanup_smoke() {
        let h = Harness::start().await;
        let second = h.second().await;
        let identity = h.observed_identity();
        let listener = observe_loopback_tcp_listener_owner(
            h.config.provider_bind_address.parse().expect("endpoint"),
        )
        .expect("listener");
        assert_eq!(listener.process_id(), identity.process_id);
        assert_eq!(identity, h.transport().provider.provider_process_identity);
        assert_selected(&selected(&h.transport().session).await);
        assert_selected(&selected(&second).await);
        println!(
            "986/15 provider_sha256={} process_id={} start={} root={} session_sockets=2 version={}",
            h.config.provider_artifact_digest,
            identity.process_id,
            identity.start_time_100ns,
            h.root.display(),
            h.transport().session.version().await.expect("version")
        );
        drop(second);
        assert_eq!(identity, h.observed_identity());
        let root = h.root.clone();
        let platform = WindowsPlatform::new(root.clone()).expect("platform");
        h.stop_child().await;
        assert!(platform.process_identity(identity.process_id).is_err());
        drop(platform);
        h.cleanup().await;
        assert!(!root.exists());
        println!("986/15 forced child stop awaited; process exit observed; isolated root removed");
    }
}

/// The ELIOT-issued transport response bound, exercised against the real
/// provider-library frame codec.
///
/// These cases need no provider process: `tungstenite`'s own
/// `WebSocketContext` is the same codec the session socket runs, and
/// [`response_bound_config`] is the exact configuration
/// `connect_started_provider` hands to `connect_async_with_config`. So the
/// transport refusal they observe is the one an oversize snapshot response would
/// produce in production, and the mapping they then apply is the production
/// [`transport_read_error`].
#[cfg(test)]
mod transport_response_bound_tests {
    #![allow(clippy::expect_used)]

    use eliot_store_api::{MAX_SNAPSHOT_BYTES, StoreError};
    use tokio_tungstenite::tungstenite::protocol::Role;

    use super::*;

    /// The provider library's incidental defaults, restated so the "never
    /// widened" property is an assertion about the library's own numbers and
    /// not about whatever they happen to be today.
    const INCIDENTAL_FRAME_BYTES: usize = 16 << 20;
    const INCIDENTAL_MESSAGE_BYTES: usize = 64 << 20;

    /// One unmasked server-to-client binary frame declaring `declared_len`
    /// payload bytes, followed by `payload_len` of them.
    ///
    /// The header is written by hand so the declared length and the delivered
    /// length can differ: the frame codec compares the declared length with
    /// `max_frame_size` *before* it reads or reserves any payload, so a frame
    /// one byte over the bound is refused without the payload ever existing.
    /// This is exactly the "one oversized row forces the complete WebSocket
    /// message" shape, and it is unreachable through a fake decoded value.
    fn server_binary_frame(declared_len: u64, payload_len: usize) -> Vec<u8> {
        let mut frame = Vec::with_capacity(10 + payload_len);
        // FIN + binary opcode, unmasked, 64-bit extended length.
        frame.push(0x82);
        frame.push(0x7F);
        frame.extend_from_slice(&declared_len.to_be_bytes());
        frame.resize(10 + payload_len, b'r');
        frame
    }

    /// The session-wide ELIOT response bound, as a `usize`.
    fn session_bound_bytes() -> usize {
        usize::try_from(ResponseCeiling::session_wide().max_bytes())
            .expect("the session response bound fits a usize")
    }

    /// The context the session socket's codec is configured with.
    fn bounded_context() -> tokio_tungstenite::tungstenite::protocol::WebSocketContext {
        let config = response_bound_config(ResponseCeiling::session_wide())
            .expect("the session response bound fits a usize");
        tokio_tungstenite::tungstenite::protocol::WebSocketContext::new(Role::Client, Some(config))
    }

    /// The ELIOT-issued bound reaches the transport, and it narrows the
    /// library's incidental defaults rather than widening them.
    ///
    /// Both bounds are asserted, because the hole this repairs is a *frame* above
    /// 16 MiB as much as a message above 64 MiB. Setting either field back to
    /// `None`, or to the incidental default, fails here.
    #[test]
    fn the_transport_bound_narrows_the_incidental_provider_defaults() {
        let config = response_bound_config(ResponseCeiling::session_wide())
            .expect("the session response bound fits a usize");
        let expected = session_bound_bytes();
        assert_eq!(config.max_frame_size, Some(expected));
        assert_eq!(config.max_message_size, Some(expected));
        assert!(
            expected < INCIDENTAL_FRAME_BYTES,
            "the frame bound must narrow the provider library's incidental default"
        );
        assert!(
            expected < INCIDENTAL_MESSAGE_BYTES,
            "the message bound must narrow the provider library's incidental default"
        );
        // The transport can never refuse a capture the owner admits.
        assert!(
            expected >= usize::try_from(MAX_SNAPSHOT_BYTES).expect("owner ceiling fits a usize")
        );
    }

    /// Refusal case at the transport: a single frame one byte over the
    /// ELIOT-issued bound is refused *inside the provider library*, with no
    /// payload delivered, and the production mapping turns that into the typed
    /// bounded refusal rather than a lost provider.
    ///
    /// Dropping the bound from [`response_bound_config`] — the exact defect this
    /// repairs — makes the frame decode, and retyping the capacity error as a
    /// transport loss makes both assertions fail.
    #[test]
    fn an_oversize_single_frame_is_refused_by_the_transport_as_a_bounded_refusal() {
        let bound = session_bound_bytes();
        let declared = u64::try_from(bound + 1).expect("declared length fits a u64");
        // Nothing of the oversize payload is on the wire at all.
        let mut wire = std::io::Cursor::new(server_binary_frame(declared, 0));
        let mut context = bounded_context();
        let failure = context
            .read(&mut wire)
            .expect_err("a frame above the ELIOT bound is refused by the transport");
        assert!(
            matches!(
                failure,
                TransportError::Capacity(CapacityError::MessageTooLong { .. })
            ),
            "the provider library refuses an oversize frame with a capacity error: {failure:?}"
        );
        let refusal = transport_read_error(&failure);
        assert_eq!(refusal, AdapterError::Store(StoreError::PayloadTooLarge));
        assert_eq!(
            refusal.into_store_error(),
            StoreError::PayloadTooLarge,
            "an oversize response reaches the store boundary as a bounded refusal, not as a retryable unavailable provider"
        );
        assert_ne!(
            transport_read_error(&TransportError::ConnectionClosed),
            AdapterError::Store(StoreError::PayloadTooLarge),
            "a genuinely lost provider is a different outcome and must stay one"
        );
    }

    /// Positive case at the transport: a frame exactly at the ELIOT-issued bound
    /// is delivered whole, so the bound refuses oversize responses without
    /// narrowing the ones an admissible capture needs.
    #[test]
    fn a_frame_at_the_transport_bound_is_delivered() {
        let bound = session_bound_bytes();
        let declared = u64::try_from(bound).expect("declared length fits a u64");
        let mut wire = std::io::Cursor::new(server_binary_frame(declared, bound));
        let mut context = bounded_context();
        let message = context
            .read(&mut wire)
            .expect("a frame at the ELIOT bound is delivered");
        assert!(
            matches!(message, Message::Binary(bytes) if bytes.len() == bound),
            "the whole in-bound frame arrives"
        );
    }
}
