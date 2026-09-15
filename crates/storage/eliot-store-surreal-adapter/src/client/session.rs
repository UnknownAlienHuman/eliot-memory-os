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

    #[path = "test_readiness.rs"]
    mod test_readiness;

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
            test_readiness::connect_with_readiness_retry(
                &harness.root,
                &harness.config,
                &mut harness.adapter,
            )
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
