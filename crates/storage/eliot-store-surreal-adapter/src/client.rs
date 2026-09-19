//! Private named-operation facade over one process owner and one authenticated session.
//! Later bounded client sets consume the session seam without repeating process launch.
use crate::config::SurrealAdapterConfig;
use crate::error::AdapterError;
use crate::schema;
use eliot_platform_windows::RetainedProcessPathLease;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
mod json_codec;
#[cfg(all(test, windows))]
mod payload_tests;
mod provider_owner;
mod rpc_parse;
mod session;
pub(crate) mod session_pool;
use provider_owner::ProviderOwner;
use session::RpcSession;
use session_pool::{SessionPool, SessionRole};

pub(crate) const RPC_PROTOCOL_VERSION: &str = "eliot.s03.rpc.v1";
type RpcSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub(crate) struct RpcTransport {
    session: RpcSession,
    provider: Arc<ProviderOwner>,
    pool: SessionPool,
}
impl fmt::Debug for RpcTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpcTransport")
            .field("provider", &self.provider)
            .field("session", &self.session)
            .field("pool", &self.pool)
            .finish()
    }
}
// Existing private native fixtures stop and await this exact child. Keep their
// field projection test-only; production sessions never receive process control.
#[cfg(test)]
impl std::ops::Deref for RpcTransport {
    type Target = ProviderOwner;
    fn deref(&self) -> &Self::Target {
        &self.provider
    }
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

/// Classifies one provider statement error from a Dreamer ledger transaction.
///
/// The Dreamer CAS marker plus Surreal duplicate/unique/exists observations
/// mean a concurrent winner committed first (deterministic conflict, safe to
/// re-read and classify as replay vs stale). Any other statement error leaves
/// the commit outcome ambiguous. Transport loss itself never reaches here; it
/// surfaces as `ProviderUnavailable` from `query`.
#[must_use]
pub(crate) fn is_dreamer_conflict(error: &str) -> bool {
    const DUPLICATE_MARKERS: &[&str] = &[
        "already exists",
        "alreadyexists",
        "duplicate",
        "unique",
        "rj_namespace_key",
    ];
    let folded = error.to_ascii_lowercase();
    if folded.contains(&schema::dreamer::CAS_CONFLICT.to_ascii_lowercase()) {
        return true;
    }
    DUPLICATE_MARKERS
        .iter()
        .any(|marker| folded.contains(&marker.to_ascii_lowercase()))
}

/// Reports whether a provider statement error observes an absent table.
///
/// `SurrealDB` answers reads against never-defined tables with a per-statement
/// `ERR` ("The table '...' does not exist") rather than an empty result.
/// Preflight reads translate exactly this observation into `None` (not yet
/// migrated), restoring the designed `Empty`/`MigrationRequired` paths; every
/// other error class keeps its existing disposition.
#[must_use]
pub(crate) fn is_absent_table(error: &str) -> bool {
    let folded = error.to_ascii_lowercase();
    folded.contains("does not exist") && folded.contains("table")
}

impl RpcResults {
    pub(super) fn from_value(value: &Value) -> Result<Self, AdapterError> {
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

    /// Number of decoded statement results. The pool dispatch uses this to
    /// preserve the binding-prefix contract owned by [`RpcTransport::query`].
    pub(super) fn values_len(&self) -> usize {
        self.values.len()
    }

    /// Drops the leading binding-decode results, preserving the original
    /// operation's statement indexes for its existing consumer.
    pub(super) fn drain_prefix(&mut self, prefix_len: usize) {
        self.values.drain(..prefix_len);
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
    #[cfg(test)]
    async fn version(&self) -> Result<Value, AdapterError> {
        self.session.version().await
    }

    #[cfg(test)]
    async fn request(
        &self,
        operation: &'static str,
        method: &'static str,
        params: Value,
    ) -> Result<Value, AdapterError> {
        self.session.request(operation, method, params).await
    }

    /// Establishes the provider owner, its first authenticated session, and
    /// the fixed bounded session set for `limits`. The pool shares the same
    /// single provider generation; it never starts a second process.
    /// Callers that held no explicit profile pass
    /// [`ClientSetLimits::compatibility`](crate::config::ClientSetLimits::compatibility),
    /// which preserves the pre-pool facade exactly.
    pub(crate) async fn connect_with_limits(
        config: &SurrealAdapterConfig,
        process_lease: &Arc<RetainedProcessPathLease>,
        limits: crate::config::ClientSetLimits,
    ) -> Result<Self, AdapterError> {
        let (provider, deadline) = ProviderOwner::start(config, Arc::clone(process_lease)).await?;
        let session = RpcSession::connect(&provider, deadline).await?;
        let pool = SessionPool::new(Arc::clone(&provider), limits);
        Ok(Self {
            session,
            provider,
            pool,
        })
    }
    pub(crate) async fn validate_liveness(
        &self,
        config: &SurrealAdapterConfig,
        process_lease: &RetainedProcessPathLease,
    ) -> Result<(), AdapterError> {
        self.provider.validate_liveness(config, process_lease).await
    }
    /// Executes one closed named operation using `SurrealDB`'s parameterized
    /// `query` RPC.  The statement is private schema data; callers provide a
    /// name and bindings rather than a provider client or query result type.
    ///
    /// Fixed dispatch (S-CONC-CLIENTS, issue #987): pure-read operations run
    /// on a pooled read-lane session so independent reads no longer
    /// serialize on the facade socket. Every other operation keeps the
    /// facade session: the compatibility write path is unchanged, reserved
    /// writes run on the pooled normal-write lane through the #993
    /// execution, and migrations keep their explicit entrypoints.
    pub(crate) async fn query(
        &self,
        operation: &'static str,
        statement: &str,
        bindings: serde_json::Map<String, Value>,
    ) -> Result<RpcResults, AdapterError> {
        if is_pool_read_operation(operation) {
            return self.query_read(operation, statement, bindings).await;
        }
        self.query_facade(operation, statement, bindings).await
    }

    /// Executes one closed named operation on the pre-pool facade session.
    /// Compatibility path for writes, migrations, and any operation outside
    /// the closed pooled-read mapping below.
    async fn query_facade(
        &self,
        operation: &'static str,
        statement: &str,
        bindings: serde_json::Map<String, Value>,
    ) -> Result<RpcResults, AdapterError> {
        let (statement, bindings, prefix_len) = json_codec::encode_bindings(statement, bindings)?;
        let value = self
            .session
            .request(
                operation,
                "query",
                json!([statement, Value::Object(bindings)]),
            )
            .await?;
        let mut results = RpcResults::from_value(&value)?;
        if results.values.len() < prefix_len {
            return Err(AdapterError::Serialization(
                "RPC query omitted binding decode results".to_owned(),
            ));
        }
        // Keep every error, including decode failures, while preserving the
        // original operation's statement indexes for its existing consumer.
        results.values.drain(..prefix_len);
        Ok(results)
    }

    /// Returns the fixed bounded session set under this transport's provider
    /// generation. Test/diagnostic evidence until the scheduler (#988) and
    /// runtime (#993) children consume it for role dispatch.
    #[cfg(test)]
    pub(crate) fn session_pool(&self) -> &SessionPool {
        &self.pool
    }

    /// Executes one closed named read operation on a pooled read-lane
    /// session instead of the facade session, so independent reads no longer
    /// serialize on one socket.
    ///
    /// Private to this module: the pooled read lane is entered only through
    /// [`RpcTransport::query`]'s closed allowlist below. The allowlist is
    /// re-validated here at the lane boundary so a future in-module caller
    /// cannot place an unlisted operation on the read lane by accident;
    /// unlisted names fall back to the facade session.
    async fn query_read(
        &self,
        operation: &'static str,
        statement: &str,
        bindings: serde_json::Map<String, Value>,
    ) -> Result<RpcResults, AdapterError> {
        if !is_pool_read_operation(operation) {
            return self.query_facade(operation, statement, bindings).await;
        }
        self.pool
            .query(SessionRole::Read, operation, statement, bindings)
            .await
    }

    /// Executes one closed named normal-write operation on a pooled
    /// write-lane session. Store transaction semantics are unchanged; the
    /// reserved-write execution (#993) runs canonical transactions here so
    /// concurrent tasks execute on separate sessions, while the
    /// compatibility path keeps the facade session.
    pub(crate) async fn query_write(
        &self,
        operation: &'static str,
        statement: &str,
        bindings: serde_json::Map<String, Value>,
    ) -> Result<RpcResults, AdapterError> {
        self.pool
            .query(SessionRole::NormalWrite, operation, statement, bindings)
            .await
    }

    /// Executes one protected health/admin operation on the isolated admin
    /// lane, outside normal read/write admission. Staged for the wire child
    /// (#991); test-only until it arrives.
    #[cfg(test)]
    pub(crate) async fn query_admin(
        &self,
        operation: &'static str,
        statement: &str,
        bindings: serde_json::Map<String, Value>,
    ) -> Result<RpcResults, AdapterError> {
        self.pool
            .query(SessionRole::HealthAdmin, operation, statement, bindings)
            .await
    }
}

/// Reports whether a closed named operation is a pure read admitted to the
/// pooled read lane.
///
/// Closed allowlist (S-CONC-CLIENTS, issue #987): exactly the pure-read
/// operations the adapter's production paths issue today — the canonical
/// head/schema preflight reads (`read.*`) and the receipt/outbox readback
/// (`recovery.snapshot`). Writes (`migration.apply`, canonical
/// transactions), health probes, Dreamer rows (`dreamer.read_row`), test
/// operations, and any unlisted operation stay on the facade session by
/// default. A newly introduced or typoed `read.*`/`recovery.*` name is NOT
/// admitted by naming convention: extending this mapping is the runtime
/// integration's (#993) explicit decision, recorded here as a new entry, not
/// a silent local widening.
const POOL_READ_OPERATIONS: &[&str] = &[
    "read.all_ordering_heads",
    "read.all_revision_heads",
    "read.authority_records",
    "read.canonical_fence",
    "read.epistemic_position",
    "read.erasure_outcome",
    "read.evidence_records",
    "read.ordering_heads",
    "read.ordering_heads_inner",
    "read.receipt_by_operation",
    "read.receipt_idempotency",
    "read.revision_heads",
    "read.revision_heads_inner",
    "read.schema_generation",
    "read.schema_meta",
    "read.validation_snapshot",
    "recovery.snapshot",
];

fn is_pool_read_operation(operation: &str) -> bool {
    POOL_READ_OPERATIONS.contains(&operation)
}

const fn millis(ms: u64) -> Duration {
    Duration::from_millis(if ms == 0 { 1 } else { ms })
}

#[cfg(test)]
use provider_owner::{
    ProviderCommand, configure_provider_command, provider_environment, reject_occupied_endpoint,
    require_listener_owner, require_live_child, require_unchanged_identity,
};
#[cfg(test)]
use session::{ProviderAuthentication, authenticate_provider};
#[cfg(test)]
use {
    eliot_platform_windows::ProcessIdentity,
    secrecy::{ExposeSecret, SecretString},
    std::{ffi::OsString, path::Path, process::Stdio},
    tokio::{
        process::Command,
        time::{Instant, sleep, timeout},
    },
    uuid::Uuid,
};

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use secrecy::SecretString;
    use std::sync::Mutex as SyncMutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::rpc_parse::{ProviderVersion, provider_version_from_rpc};
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

    // WORK_UNIT_CASE: 986/9
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
    fn pooled_read_lane_is_a_closed_allowlist() {
        // The allowlist is exact: every production pure-read operation the
        // adapter issues is admitted, and the set is pinned here so adding
        // or dropping an entry is an explicit reviewable decision.
        let admitted = POOL_READ_OPERATIONS.to_vec();
        assert_eq!(
            admitted,
            [
                "read.all_ordering_heads",
                "read.all_revision_heads",
                "read.authority_records",
                "read.canonical_fence",
                "read.epistemic_position",
                "read.erasure_outcome",
                "read.evidence_records",
                "read.ordering_heads",
                "read.ordering_heads_inner",
                "read.receipt_by_operation",
                "read.receipt_idempotency",
                "read.revision_heads",
                "read.revision_heads_inner",
                "read.schema_generation",
                "read.schema_meta",
                "read.validation_snapshot",
                "recovery.snapshot",
            ]
        );
        for operation in admitted {
            assert!(
                is_pool_read_operation(operation),
                "lost pooled read: {operation}"
            );
        }
        // Writes, probes, Dreamer rows, test labels, and any unlisted name
        // — including typoed or future `read.*`/`recovery.*` names — stay on
        // the facade session until explicitly admitted above.
        for refused in [
            "migration.apply",
            "transaction.apply",
            "transaction.erasure",
            "genesis.preflight",
            "genesis.initialize",
            "dreamer.read_row",
            "dreamer.submit",
            "dreamer.lease_exact",
            "test.install_read_fence",
            "proof.987.pooled",
            "apply.prepared",
            "",
            "read.",
            "read.refresh_materialized_state",
            "read.schema_generation_v2",
            "read.schema-generation",
            "READ.schema_generation",
            "recovery.anything_new",
            "recovery.snapshot_extra",
        ] {
            assert!(
                !is_pool_read_operation(refused),
                "read lane widened: {refused}"
            );
        }
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
