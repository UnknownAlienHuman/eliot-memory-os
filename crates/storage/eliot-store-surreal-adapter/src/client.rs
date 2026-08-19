//! Private versioned named-operation WebSocket/RPC transport.
//!
//! This module owns the credential-bearing socket and the wire codec.  It is
//! intentionally independent of a `SurrealDB` SDK: the provider is reached only
//! through the server's JSON WebSocket endpoint, while the adapter supplies a
//! closed operation name and parameter map for every request.  No transport,
//! RPC response or provider type crosses the S-03 boundary.

use std::ffi::OsString;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use uuid::Uuid;

use crate::config::SurrealAdapterConfig;
use crate::error::AdapterError;
use eliot_platform_windows::{
    ProcessIdentity, RetainedProcessPathLease, observe_loopback_tcp_listener_owner,
};

/// Wire revision for all S-03 requests.  The operation name is included in
/// every request identifier so traces cannot silently mix protocol revisions
/// or named operation families.
pub(crate) const RPC_PROTOCOL_VERSION: &str = "eliot.s03.rpc.v1";

type RpcSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// One authenticated provider session.  The socket mutex is also the request
/// ordering boundary: only one request may be in flight on a session, which
/// keeps response correlation deterministic and avoids a second writer.
pub(crate) struct RpcTransport {
    socket: Mutex<RpcSocket>,
    request_timeout: Duration,
    provider_child: Mutex<Child>,
}

impl fmt::Debug for RpcTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RpcTransport")
            .field("socket", &"private")
            .field("request_timeout", &self.request_timeout)
            .field("provider_child", &"retained")
            .finish()
    }
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
    pub(crate) async fn connect(
        config: &SurrealAdapterConfig,
        provider_process_lease: &RetainedProcessPathLease,
    ) -> Result<Self, AdapterError> {
        config
            .validate()
            .map_err(|error| AdapterError::Config(error.to_string()))?;
        let connect_timeout = millis(config.connect_timeout_ms);
        provider_process_lease
            .validate(
                Path::new(&config.provider_executable_path),
                Path::new(&config.store_work_root),
                &config.provider_artifact_digest,
            )
            .map_err(|_| {
                AdapterError::Config(
                    "canonical provider process lease failed identity validation".to_owned(),
                )
            })?;
        reject_occupied_endpoint(config, connect_timeout).await?;
        let mut provider_child = spawn_provider(config)?;
        let provider_process_id = provider_child.id().ok_or_else(|| {
            AdapterError::Config("canonical provider child PID is unavailable".to_owned())
        })?;
        let identity_before_listener = validate_child_process(
            config,
            provider_process_lease,
            &mut provider_child,
            provider_process_id,
        )?;
        let deadline = Instant::now() + connect_timeout;
        let (socket, identity_before_auth) = connect_started_provider(
            config,
            provider_process_lease,
            &mut provider_child,
            provider_process_id,
            &identity_before_listener,
            deadline,
        )
        .await?;

        let transport = Self {
            socket: Mutex::new(socket),
            request_timeout: millis(config.query_timeout_ms),
            provider_child: Mutex::new(provider_child),
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        timeout(remaining, authenticate_provider(&transport, config))
            .await
            .map_err(|_| AdapterError::ProviderUnavailable)??;
        {
            let mut child = transport.provider_child.lock().await;
            let identity_after_auth = validate_child_process(
                config,
                provider_process_lease,
                &mut child,
                provider_process_id,
            )?;
            require_unchanged_identity(
                &identity_before_auth,
                &identity_after_auth,
                "authentication",
            )?;
        }
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

#[allow(async_fn_in_trait)]
trait ProviderAuthentication {
    async fn version(&self) -> Result<Value, AdapterError>;
    async fn signin(&self, username: &str, password: &SecretString) -> Result<(), AdapterError>;
    async fn select_namespace_database(
        &self,
        namespace: &str,
        database: &str,
    ) -> Result<(), AdapterError>;
}

impl ProviderAuthentication for RpcTransport {
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
        RpcTransport::signin(self, username, password).await
    }

    async fn select_namespace_database(
        &self,
        namespace: &str,
        database: &str,
    ) -> Result<(), AdapterError> {
        self.use_ns_db(namespace, database).await
    }
}

async fn authenticate_provider<T: ProviderAuthentication>(
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

async fn reject_occupied_endpoint(
    config: &SurrealAdapterConfig,
    connect_timeout: Duration,
) -> Result<(), AdapterError> {
    let probe_timeout = connect_timeout.min(Duration::from_millis(100));
    if matches!(
        timeout(
            probe_timeout,
            TcpStream::connect(&config.provider_bind_address)
        )
        .await,
        Ok(Ok(_))
    ) {
        return Err(AdapterError::Config(
            "provider endpoint was occupied before the canonical child launch".to_owned(),
        ));
    }
    Ok(())
}

fn spawn_provider(config: &SurrealAdapterConfig) -> Result<Child, AdapterError> {
    let environment = provider_environment(config)?;
    let mut command = Command::new(&config.provider_executable_path);
    configure_provider_command(&mut command, config, &environment);
    command
        .spawn()
        .map_err(|_| AdapterError::Config("canonical provider process launch failed".to_owned()))
}

trait ProviderCommand {
    fn arguments(&mut self, arguments: &[String]);
    fn working_directory(&mut self, path: &str);
    fn clear_environment(&mut self);
    fn environment(&mut self, entries: &[(OsString, OsString)]);
    fn close_standard_io(&mut self);
    fn terminate_on_drop(&mut self);
}

impl ProviderCommand for Command {
    fn arguments(&mut self, arguments: &[String]) {
        self.args(arguments);
    }

    fn working_directory(&mut self, path: &str) {
        self.current_dir(path);
    }

    fn clear_environment(&mut self) {
        self.env_clear();
    }

    fn environment(&mut self, entries: &[(OsString, OsString)]) {
        self.envs(entries.iter().cloned());
    }

    fn close_standard_io(&mut self) {
        self.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }

    fn terminate_on_drop(&mut self) {
        self.kill_on_drop(true);
    }
}

fn configure_provider_command<T: ProviderCommand>(
    command: &mut T,
    config: &SurrealAdapterConfig,
    environment: &ProviderEnvironment,
) {
    command.arguments(&config.provider_arguments);
    command.working_directory(&config.store_work_root);
    command.clear_environment();
    command.environment(&environment.entries);
    command.close_standard_io();
    command.terminate_on_drop();
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

fn validate_child_process(
    config: &SurrealAdapterConfig,
    provider_process_lease: &RetainedProcessPathLease,
    child: &mut Child,
    expected_process_id: u32,
) -> Result<ProcessIdentity, AdapterError> {
    let child_process_id = child.id();
    let child_exited = child
        .try_wait()
        .map_err(|_| AdapterError::ProviderUnavailable)?
        .is_some();
    require_live_child(child_process_id, expected_process_id, child_exited)?;
    provider_process_lease
        .validate_process_identity(
            expected_process_id,
            Path::new(&config.provider_executable_path),
            Path::new(&config.store_work_root),
            &config.provider_artifact_digest,
        )
        .map_err(|_| {
            AdapterError::Config(
                "canonical provider process path, digest, or live identity mismatch".to_owned(),
            )
        })
}

fn require_live_child(
    child_process_id: Option<u32>,
    expected_process_id: u32,
    child_exited: bool,
) -> Result<(), AdapterError> {
    if child_process_id != Some(expected_process_id) || child_exited {
        return Err(AdapterError::Config(
            "canonical provider child identity is unavailable".to_owned(),
        ));
    }
    Ok(())
}

fn require_listener_owner(expected: u32, observed: u32) -> Result<(), AdapterError> {
    if expected == 0 || observed != expected {
        return Err(AdapterError::Config(
            "provider listener is not owned by the retained canonical child".to_owned(),
        ));
    }
    Ok(())
}

fn require_unchanged_identity(
    before: &ProcessIdentity,
    after: &ProcessIdentity,
    phase: &str,
) -> Result<(), AdapterError> {
    if before != after {
        return Err(AdapterError::Config(format!(
            "canonical provider process identity changed during {phase}"
        )));
    }
    Ok(())
}

struct ProviderEnvironment {
    entries: Vec<(OsString, OsString)>,
}

fn provider_environment(
    config: &SurrealAdapterConfig,
) -> Result<ProviderEnvironment, AdapterError> {
    let system_root = std::env::var_os("SystemRoot")
        .filter(|value| Path::new(value).is_absolute())
        .ok_or_else(|| {
            AdapterError::Config("required Windows SystemRoot is unavailable".to_owned())
        })?;
    Ok(ProviderEnvironment {
        entries: vec![
            ("SystemRoot".into(), system_root.clone()),
            ("WINDIR".into(), system_root),
            ("TEMP".into(), config.store_temp_root.clone().into()),
            ("TMP".into(), config.store_temp_root.clone().into()),
        ],
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProviderVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderVersionObject {
    version: String,
    build: String,
    timestamp: String,
}

fn provider_version_from_rpc(value: &Value) -> Result<ProviderVersion, AdapterError> {
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

    use secrecy::SecretString;
    use std::sync::Mutex as SyncMutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    fn config() -> SurrealAdapterConfig {
        SurrealAdapterConfig {
            endpoint: "ws://127.0.0.1:18000/rpc".to_owned(),
            namespace: "eliot".to_owned(),
            database: "eliot".to_owned(),
            username: "provider-user".to_owned(),
            password: SecretString::new("provider-password".into()),
            provider_bind_address: "127.0.0.1:18000".to_owned(),
            installation_id: "installation-test".to_owned(),
            installation_profile: "portable_dev".to_owned(),
            runtime_state_roots_digest: "a".repeat(64),
            provider_executable_path: r"C:\eliot\surreal.exe".to_owned(),
            provider_artifact_digest: "b".repeat(64),
            provider_arguments: vec![
                "start".to_owned(),
                "--no-banner".to_owned(),
                "--bind".to_owned(),
                "127.0.0.1:18000".to_owned(),
                "--temporary-directory".to_owned(),
                r"C:\eliot\store\tmp".to_owned(),
                "--log-file-enabled".to_owned(),
                "--log-file-path".to_owned(),
                r"C:\eliot\store\work".to_owned(),
                "--log-file-name".to_owned(),
                "surrealdb.log".to_owned(),
                "surrealkv://C:/eliot/store/data".to_owned(),
            ],
            store_data_root: r"C:\eliot\store\data".to_owned(),
            store_work_root: r"C:\eliot\store\work".to_owned(),
            store_temp_root: r"C:\eliot\store\tmp".to_owned(),
            connect_timeout_ms: 1_000,
            query_timeout_ms: 1_000,
            expected_provider_major: crate::PINNED_SURREALDB_MAJOR,
            expected_schema_generation: crate::SchemaGeneration::new("1.0.0")
                .expect("valid generation"),
        }
    }

    struct AuthenticationSpy {
        version: Value,
        events: SyncMutex<Vec<&'static str>>,
        credentials_seen: AtomicBool,
    }

    impl AuthenticationSpy {
        fn compatible(version: Value) -> Self {
            Self {
                version,
                events: SyncMutex::new(Vec::new()),
                credentials_seen: AtomicBool::new(false),
            }
        }
    }

    impl ProviderAuthentication for AuthenticationSpy {
        async fn version(&self) -> Result<Value, AdapterError> {
            self.events.lock().expect("events").push("version");
            Ok(self.version.clone())
        }

        async fn signin(
            &self,
            _username: &str,
            _password: &SecretString,
        ) -> Result<(), AdapterError> {
            self.credentials_seen.store(true, Ordering::SeqCst);
            self.events.lock().expect("events").push("signin");
            Ok(())
        }

        async fn select_namespace_database(
            &self,
            _namespace: &str,
            _database: &str,
        ) -> Result<(), AdapterError> {
            self.events.lock().expect("events").push("use");
            Ok(())
        }
    }

    #[derive(Default)]
    struct CommandSpy {
        events: Vec<&'static str>,
        arguments: Vec<String>,
        environment_names: Vec<String>,
    }

    impl ProviderCommand for CommandSpy {
        fn arguments(&mut self, arguments: &[String]) {
            self.events.push("arguments");
            self.arguments = arguments.to_vec();
        }

        fn working_directory(&mut self, _path: &str) {
            self.events.push("working_directory");
        }

        fn clear_environment(&mut self) {
            self.events.push("env_clear");
        }

        fn environment(&mut self, entries: &[(OsString, OsString)]) {
            self.events.push("environment");
            self.environment_names = entries
                .iter()
                .map(|(name, _)| name.to_string_lossy().into_owned())
                .collect();
        }

        fn close_standard_io(&mut self) {
            self.events.push("stdio_null");
        }

        fn terminate_on_drop(&mut self) {
            self.events.push("kill_on_drop");
        }
    }

    #[tokio::test]
    async fn version_gate_precedes_authentication_and_selection() {
        let spy = AuthenticationSpy::compatible(json!("surrealdb-3.1.4"));
        authenticate_provider(&spy, &config())
            .await
            .expect("compatible provider");
        assert_eq!(
            *spy.events.lock().expect("events"),
            ["version", "signin", "use"]
        );
        assert!(spy.credentials_seen.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn incompatible_provider_never_receives_credentials() {
        let spy = AuthenticationSpy::compatible(json!({
            "version": "4.0.0",
            "build": "other",
            "timestamp": "2026-08-19T00:00:00Z"
        }));
        assert!(authenticate_provider(&spy, &config()).await.is_err());
        assert_eq!(*spy.events.lock().expect("events"), ["version"]);
        assert!(!spy.credentials_seen.load(Ordering::SeqCst));
    }

    #[cfg(windows)]
    #[test]
    fn command_spy_proves_env_clear_before_the_closed_allowlist() {
        let config = config();
        let environment = provider_environment(&config).expect("provider environment");
        let mut spy = CommandSpy::default();
        configure_provider_command(&mut spy, &config, &environment);
        assert_eq!(
            spy.events,
            [
                "arguments",
                "working_directory",
                "env_clear",
                "environment",
                "stdio_null",
                "kill_on_drop"
            ]
        );
        assert_eq!(spy.arguments, config.provider_arguments);
        assert_eq!(
            spy.environment_names,
            ["SystemRoot", "WINDIR", "TEMP", "TMP"]
        );
    }

    #[tokio::test]
    async fn preoccupied_endpoint_is_rejected_before_launch() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let port = listener.local_addr().expect("address").port();
        let mut config = config();
        config.provider_bind_address = format!("127.0.0.1:{port}");
        config.endpoint = format!("ws://{}/rpc", config.provider_bind_address);
        config.provider_arguments[3] = config.provider_bind_address.clone();
        assert!(
            reject_occupied_endpoint(&config, Duration::from_millis(250))
                .await
                .is_err()
        );
    }

    #[test]
    fn launch_identity_spies_reject_wrong_owner_exit_and_identity_change() {
        assert!(require_listener_owner(41, 42).is_err());
        assert!(require_live_child(Some(41), 41, true).is_err());
        assert!(require_live_child(Some(42), 41, false).is_err());
        let before = ProcessIdentity {
            process_id: 41,
            start_time_100ns: 100,
            image_path: r"C:\eliot\surreal.exe".to_owned(),
        };
        let after = ProcessIdentity {
            start_time_100ns: 101,
            ..before.clone()
        };
        assert!(require_unchanged_identity(&before, &after, "test").is_err());
    }

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

    #[test]
    fn provider_version_rpc_supports_only_documented_3_1_and_3_2_shapes() {
        assert_eq!(
            provider_version_from_rpc(&json!("surrealdb-3.1.4")).expect("canonical 3.1 response"),
            ProviderVersion {
                major: 3,
                minor: 1,
                patch: 4,
            }
        );
        assert_eq!(
            provider_version_from_rpc(&json!({
                "version": "3.2.0",
                "build": "abc123",
                "timestamp": "2026-08-19T00:00:00Z"
            }))
            .expect("canonical 3.2 response"),
            ProviderVersion {
                major: 3,
                minor: 2,
                patch: 0,
            }
        );
        for rejected in [
            json!({"version": "3.1.4", "build": "abc", "timestamp": "now"}),
            json!("surrealdb-3.2.0"),
            json!("surrealdb-03.1.4"),
            json!("surrealdb-3.1"),
            json!("surrealdb-3.1.4+build"),
            json!({"version": 3.2, "build": "abc", "timestamp": "now"}),
            json!({"version": "3.2.0", "build": "abc"}),
            json!({"version": "3.2.0", "build": "abc", "timestamp": "now", "extra": true}),
        ] {
            assert!(
                provider_version_from_rpc(&rejected).is_err(),
                "accepted {rejected}"
            );
        }
    }

    #[test]
    fn provider_argv_routes_exact_roots_without_credentials() {
        let config = config();
        let args = config.provider_arguments.clone();
        assert!(args.iter().any(|value| value == &config.store_work_root));
        assert!(args.iter().any(|value| value == &config.store_temp_root));
        assert!(
            args.iter().any(|value| value
                == &format!("surrealkv://{}", config.store_data_root.replace('\\', "/")))
        );
        assert!(!args.iter().any(|value| value == &config.username));
        assert!(
            !args
                .iter()
                .any(|value| value == config.password.expose_secret())
        );
    }

    #[cfg(windows)]
    #[test]
    fn provider_environment_is_closed_and_credentials_never_enter_argv() {
        let config = config();
        let environment = provider_environment(&config).expect("explicit environment");
        let names = environment
            .entries
            .iter()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, ["SystemRoot", "WINDIR", "TEMP", "TMP"]);
        for inherited_runtime_name in ["PATH", "RUST_LOG", "SURREAL_PATH", "SURREAL_BIND"] {
            assert!(!names.iter().any(|name| name == inherited_runtime_name));
        }
        let arguments = &config.provider_arguments;
        assert!(
            !arguments
                .iter()
                .any(|argument| argument == &config.username)
        );
        assert!(
            !arguments
                .iter()
                .any(|argument| argument == config.password.expose_secret())
        );
        assert!(!environment.entries.iter().any(|(_, value)| {
            value == config.username.as_str() || value == config.password.expose_secret()
        }));
    }
}
