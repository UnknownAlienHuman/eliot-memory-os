use crate::{ConfigError, CredentialProviderKind, SCHEMA_VERSION};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Decoder: derived, no `flatten`, no tagging. Unknown member keys are refused
/// and duplicate member keys are already refused by the derived `MapAccess`;
/// nested section structs are closed too. `supervision`,
/// `delegation_calibration` and `ul` stay `#[serde(default)]`: approved
/// operational sections for this legacy decoder, still enforced afterwards
/// by `GovernorConfig::validate`. These defaults do not grant current runtime
/// configuration authority.
/// Legacy ingress: decoded directly from TOML bytes by
/// `crates/eliot-app/src/config.rs::load_config` (`toml::from_str`, which
/// rejects duplicate keys itself) and then `validate`d; there is no `Value`
/// hop in this causal chain.
/// Invalidate-on-change: if `load_config` gains a pre-parse/`Value` step,
/// re-verify duplicate-key refusal.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorConfig {
    pub schema_version: String,
    pub service: ServiceConfig,
    pub db: DbConfig,
    pub control_wal: ControlWalConfig,
    pub blob_store: BlobStoreConfig,
    pub store: StoreConfig,
    #[serde(default)]
    pub supervision: RuntimeSupervisionConfig,
    #[serde(default)]
    pub delegation_calibration: DelegationCalibrationConfig,
    #[serde(default)]
    pub ul: UlConfig,
}

/// Decoder: derived, no `flatten`, no tagging. Unknown member keys are refused
/// and duplicate member keys are already refused by the derived `MapAccess`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSupervisionConfig {
    pub watchdog_interval_ms: u64,
}

impl Default for RuntimeSupervisionConfig {
    fn default() -> Self {
        Self {
            watchdog_interval_ms: 2_000,
        }
    }
}

/// Decoder: derived, no `flatten`, no tagging. Unknown member keys are refused
/// and duplicate member keys are already refused by the derived `MapAccess`;
/// nested `UlActivationConfig` is closed too.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UlConfig {
    #[serde(default)]
    pub activation: UlActivationConfig,
}

/// Decoder: derived, no `flatten`, no tagging. Unknown member keys are refused
/// and duplicate member keys are already refused by the derived `MapAccess`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UlActivationConfig {
    pub enable_min_edges: u32,
}

impl Default for UlActivationConfig {
    fn default() -> Self {
        Self {
            enable_min_edges: 500,
        }
    }
}

/// Decoder: derived, no `flatten`, no tagging. Unknown member keys are refused
/// and duplicate member keys are already refused by the derived `MapAccess`.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationCalibrationConfig {
    pub minimum_real_tasks_total: u32,
    pub minimum_real_tasks_per_family: u32,
    pub minimum_executed_reviews_total: u32,
    pub minimum_executed_reviews_per_candidate_family: u32,
    pub minimum_complete_outcome_fraction: f64,
    pub minimum_shadow_tasks_total: u32,
    pub require_zero_authority_violations: bool,
    pub require_zero_live_tree_violations: bool,
    pub require_zero_recursive_executions: bool,
}

impl Default for DelegationCalibrationConfig {
    fn default() -> Self {
        Self {
            minimum_real_tasks_total: 12,
            minimum_real_tasks_per_family: 5,
            minimum_executed_reviews_total: 4,
            minimum_executed_reviews_per_candidate_family: 3,
            minimum_complete_outcome_fraction: 0.80,
            minimum_shadow_tasks_total: 12,
            require_zero_authority_violations: true,
            require_zero_live_tree_violations: true,
            require_zero_recursive_executions: true,
        }
    }
}

/// Decoder: derived, no `flatten`, no tagging. Unknown member keys are refused
/// and duplicate member keys are already refused by the derived `MapAccess`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub service_name: String,
    pub instance_id: String,
}

/// Decoder: derived, no `flatten`, no tagging. Unknown member keys are refused
/// and duplicate member keys are already refused by the derived `MapAccess`;
/// nested `SurrealServerConfig` is closed too.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbConfig {
    pub mode: DbMode,
    pub surreal: SurrealServerConfig,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbMode {
    SurrealRpcServer,
    SurrealMcpChild,
    SurrealSqlCli,
    SurrealSdkExperimental,
}

/// Decoder: derived, no `flatten`, no tagging. Unknown member keys are refused
/// and duplicate member keys are already refused by the derived `MapAccess`;
/// nested `SurrealCapabilities` is closed too. The credential
/// `#[serde(default)]`s stay: the approved secure authority
/// (`WindowsCredentialManager`, never the legacy file) is what an unspecified
/// config resolves to, pinned by
/// `an_unspecified_credential_provider_resolves_to_the_windows_credential_manager`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurrealServerConfig {
    pub exe: String,
    pub bind: String,
    pub endpoint: String,
    pub storage: String,
    pub ns: String,
    pub db: String,
    pub user: String,
    #[serde(default = "default_surreal_credential_provider")]
    pub credential_provider: CredentialProviderKind,
    #[serde(default = "default_surreal_credential_id")]
    pub credential_id: String,
    #[serde(default = "default_surreal_password_file")]
    pub password_file: String,
    pub log_level: String,
    pub query_timeout_ms: u64,
    pub transaction_timeout_ms: u64,
    pub startup_timeout_ms: u64,
    pub restart_backoff_ms: u64,
    pub max_restart_backoff_ms: u64,
    pub capabilities: SurrealCapabilities,
}

/// Decoder: derived, no `flatten`, no tagging. Unknown member keys are refused
/// and duplicate member keys are already refused by the derived `MapAccess`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurrealCapabilities {
    pub deny_all: bool,
    pub allow_funcs: Vec<String>,
    pub allow_net: Vec<String>,
    pub allow_scripting: bool,
    pub allow_guests: bool,
}

/// Decoder: derived, no `flatten`, no tagging. Unknown member keys are refused
/// and duplicate member keys are already refused by the derived `MapAccess`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlWalConfig {
    pub path: String,
}

/// Decoder: derived, no `flatten`, no tagging. Unknown member keys are refused
/// and duplicate member keys are already refused by the derived `MapAccess`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobStoreConfig {
    pub root: String,
}

/// Decoder: derived, no `flatten`, no tagging. Unknown member keys are refused
/// and duplicate member keys are already refused by the derived `MapAccess`.
///
/// `migrations_dir` is deleted (issue #1221, work item W4). It was the only
/// current configuration key that named a legacy migration root: its default
/// was `crates/eliot-store/migrations`, and `eliot-governor daemon
/// init-default` resolved it and staged that root into the installed runtime
/// resources. The current Store schema-generation owner
/// (`eliot-store-surreal-adapter`) embeds its own migration graph and resolves
/// nothing from the filesystem, so current configuration can no longer select a
/// root or legacy migration root. `deny_unknown_fields` keeps a document that
/// still carries `migrations_dir` a refusal rather than a silent default.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    pub surql_dir: String,
}

impl GovernorConfig {
    /// Returns true when this configuration can claim the reserved store by
    /// endpoint/namespace or by bind/namespace.
    #[must_use]
    pub fn collides_with_store(&self, bind: &str, endpoint: &str, namespace: &str) -> bool {
        self.db
            .surreal
            .collides_with_store(bind, endpoint, namespace)
    }

    /// Rejects a reserved store identity before any writer, database, or child
    /// process can be started.
    pub fn reject_store_collision(
        &self,
        bind: &str,
        endpoint: &str,
        namespace: &str,
    ) -> Result<(), ConfigError> {
        self.db
            .surreal
            .reject_store_collision(bind, endpoint, namespace)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedSchemaVersion {
                expected: SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }

        require_non_empty("service.service_name", &self.service.service_name)?;
        require_non_empty("service.instance_id", &self.service.instance_id)?;
        require_non_empty("db.surreal.exe", &self.db.surreal.exe)?;
        require_non_empty("db.surreal.bind", &self.db.surreal.bind)?;
        require_non_empty("db.surreal.endpoint", &self.db.surreal.endpoint)?;
        require_non_empty("db.surreal.storage", &self.db.surreal.storage)?;
        require_non_empty("db.surreal.ns", &self.db.surreal.ns)?;
        require_non_empty("db.surreal.db", &self.db.surreal.db)?;
        require_non_empty("db.surreal.user", &self.db.surreal.user)?;
        match self.db.surreal.credential_provider {
            CredentialProviderKind::WindowsCredentialManager => {
                require_non_empty("db.surreal.credential_id", &self.db.surreal.credential_id)?;
            }
            CredentialProviderKind::LegacyPasswordFile => {
                require_non_empty("db.surreal.password_file", &self.db.surreal.password_file)?;
            }
            provider => {
                return Err(ConfigError::UnsupportedCredentialProvider {
                    provider: format!("{provider:?}"),
                });
            }
        }
        require_non_empty("db.surreal.log_level", &self.db.surreal.log_level)?;
        require_non_empty("control_wal.path", &self.control_wal.path)?;
        require_non_empty("blob_store.root", &self.blob_store.root)?;
        require_non_empty("store.surql_dir", &self.store.surql_dir)?;
        if self.supervision.watchdog_interval_ms == 0 {
            return Err(ConfigError::ZeroField {
                field: "supervision.watchdog_interval_ms",
            });
        }

        // #3980: one whole-grammar predicate, shared with the supervisor and the
        // RPC transport, runs here before the storage/capability effects below.
        self.db.surreal.validate_local_rpc_endpoint()?;

        let storage = self.db.surreal.storage.to_ascii_lowercase();
        if !storage.starts_with("rocksdb:") || storage.starts_with("rocksdb://") {
            return Err(ConfigError::ForbiddenDbStorage {
                storage: self.db.surreal.storage.clone(),
            });
        }

        if !self.db.surreal.capabilities.deny_all {
            return Err(ConfigError::ForbiddenCapability {
                field: "db.surreal.capabilities.deny_all",
                value: "false".to_owned(),
            });
        }
        if self.db.surreal.capabilities.allow_scripting {
            return Err(ConfigError::ForbiddenCapability {
                field: "db.surreal.capabilities.allow_scripting",
                value: "true".to_owned(),
            });
        }
        if self.db.surreal.capabilities.allow_guests {
            return Err(ConfigError::ForbiddenCapability {
                field: "db.surreal.capabilities.allow_guests",
                value: "true".to_owned(),
            });
        }
        if !self.db.surreal.capabilities.allow_net.is_empty() {
            return Err(ConfigError::ForbiddenCapability {
                field: "db.surreal.capabilities.allow_net",
                value: self.db.surreal.capabilities.allow_net.join(","),
            });
        }

        Ok(())
    }
}

impl SurrealServerConfig {
    /// Returns true when this server configuration can claim the reserved
    /// store by endpoint/namespace or by bind/namespace.
    #[must_use]
    pub fn collides_with_store(&self, bind: &str, endpoint: &str, namespace: &str) -> bool {
        self.ns == namespace
            && (self.endpoint == endpoint
                || same_loopback_port(&self.endpoint, endpoint)
                || self.bind == bind
                || same_loopback_port(&self.bind, bind))
    }

    /// Rejects a reserved store identity before a server or writer starts.
    pub fn reject_store_collision(
        &self,
        bind: &str,
        endpoint: &str,
        namespace: &str,
    ) -> Result<(), ConfigError> {
        if self.collides_with_store(bind, endpoint, namespace) {
            return Err(ConfigError::RuntimeLiveStoreCollision {
                bind: self.bind.clone(),
                endpoint: self.endpoint.clone(),
                namespace: self.ns.clone(),
            });
        }
        Ok(())
    }

    /// #3980: the closed local-only grammar for `bind` and `endpoint`. This is
    /// the single owner of the allowed form, and it parses the **whole** input
    /// rather than matching a prefix and a suffix.
    ///
    /// The accepted grammar is exactly:
    ///
    /// * `bind` == `127.0.0.1:<port>`
    /// * `endpoint` == `ws://127.0.0.1:<port>/rpc`
    ///
    /// where `<port>` is a non-empty run of ASCII digits `0`..=`9` that parses
    /// as `u16` (leading zeros are an accepted encoding; `0` is a valid port;
    /// runs that overflow `u16` are out of range). Nothing remains after the
    /// literal `/rpc`, so userinfo/`@`, any other address or hostname, extra
    /// path components, a query, a fragment, whitespace or control characters,
    /// and an empty/non-numeric/signed port are all refused rather than
    /// normalised. A rejected external address is never rewritten to loopback:
    /// this repair adds no DNS, no alternate loopback alias, and no second
    /// transport.
    ///
    /// Declared accepted compatibility, preserved exactly and not broadened:
    /// the grammar is matched against an ASCII-lowercased copy, so `WS://`
    /// and `/RPC` spellings remain accepted exactly as the previous
    /// lowercasing check accepted them.
    ///
    /// The rejected value is never echoed (a refused userinfo component can
    /// carry secret material), so the two variants are payload-free.
    pub fn validate_local_rpc_endpoint(&self) -> Result<(), ConfigError> {
        if local_bind_port(&self.bind).is_none() {
            return Err(ConfigError::ForbiddenDbBind);
        }
        if local_rpc_endpoint_port(&self.endpoint).is_none() {
            return Err(ConfigError::ForbiddenDbEndpoint);
        }
        Ok(())
    }

    /// #3980: the port this endpoint actually names, when it satisfies
    /// `validate_local_rpc_endpoint`; `None` otherwise. Single owner of the
    /// grammar's parse, so the transport never re-parses it.
    #[must_use]
    pub fn local_rpc_port(&self) -> Option<u16> {
        local_rpc_endpoint_port(&self.endpoint)
    }
}

/// The one literal IPv4 socket address the grammar admits. A hostname, another
/// loopback alias, or any other address is not resolved and not substituted.
const LOCAL_BIND_ADDRESS: &str = "127.0.0.1";

/// #3980: the single `<port>` grammar both shapes share: a non-empty run of
/// ASCII digits that also parses as `u16`.
fn local_port(port: &str) -> Option<u16> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    port.parse().ok()
}

/// #3980: parses `127.0.0.1:<port>` and returns the port. The address must be
/// the whole literal prefix, so `127.0.0.1.example.com`, `127.0.0.2`,
/// `[::1]`, a scheme, and userinfo all fail here rather than being normalised.
fn local_bind_port(bind: &str) -> Option<u16> {
    let bind = bind.to_ascii_lowercase();
    let port = bind.strip_prefix(LOCAL_BIND_ADDRESS)?.strip_prefix(':')?;
    local_port(port)
}

/// #3980: parses `ws://127.0.0.1:<port>/rpc` and returns the port. The scheme
/// and address are consumed, then the exact final `/rpc` is consumed with no
/// permitted remainder, so a query, a fragment, extra path components, and any
/// userinfo before the address are all refused.
fn local_rpc_endpoint_port(endpoint: &str) -> Option<u16> {
    let endpoint = endpoint.to_ascii_lowercase();
    let rest = endpoint.strip_prefix("ws://")?;
    let port = rest
        .strip_prefix(LOCAL_BIND_ADDRESS)?
        .strip_prefix(':')?
        .strip_suffix("/rpc")?;
    local_port(port)
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            service: ServiceConfig {
                service_name: "EliotGovernor".to_owned(),
                instance_id: "local-dev".to_owned(),
            },
            db: DbConfig {
                mode: DbMode::SurrealRpcServer,
                surreal: SurrealServerConfig {
                    exe: "surreal".to_owned(),
                    bind: "127.0.0.1:18000".to_owned(),
                    endpoint: "ws://127.0.0.1:18000/rpc".to_owned(),
                    storage: "rocksdb:.eliot-governor/surrealdb-rocks".to_owned(),
                    ns: "eliot".to_owned(),
                    db: "system".to_owned(),
                    user: "root".to_owned(),
                    credential_provider: CredentialProviderKind::WindowsCredentialManager,
                    credential_id: default_surreal_credential_id(),
                    password_file: default_surreal_password_file(),
                    log_level: "warn".to_owned(),
                    query_timeout_ms: 15_000,
                    transaction_timeout_ms: 15_000,
                    startup_timeout_ms: 20_000,
                    restart_backoff_ms: 200,
                    max_restart_backoff_ms: 2_000,
                    capabilities: SurrealCapabilities {
                        deny_all: true,
                        allow_funcs: vec![
                            "array".to_owned(),
                            "string".to_owned(),
                            "time".to_owned(),
                            "type".to_owned(),
                            "math".to_owned(),
                            "vector".to_owned(),
                            "search".to_owned(),
                        ],
                        allow_net: Vec::new(),
                        allow_scripting: false,
                        allow_guests: false,
                    },
                },
            },
            control_wal: ControlWalConfig {
                path: ".eliot-governor/control/control.redb".to_owned(),
            },
            blob_store: BlobStoreConfig {
                root: ".eliot-governor/blobs".to_owned(),
            },
            store: StoreConfig {
                surql_dir: "crates/eliot-store/src/surql".to_owned(),
            },
            supervision: RuntimeSupervisionConfig::default(),
            delegation_calibration: DelegationCalibrationConfig::default(),
            ul: UlConfig::default(),
        }
    }
}

/// A configuration that says nothing about credential storage gets the secure
/// authority, not the legacy one. Selecting the password file is a deliberate,
/// gated migration step and must be written out explicitly.
fn default_surreal_credential_provider() -> CredentialProviderKind {
    CredentialProviderKind::WindowsCredentialManager
}

fn default_surreal_credential_id() -> String {
    "surreal-runtime/local-dev".to_owned()
}

fn default_surreal_password_file() -> String {
    "%LOCALAPPDATA%/Eliot/secrets/surreal_root_password.txt".to_owned()
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        Err(ConfigError::EmptyField { field })
    } else {
        Ok(())
    }
}

fn same_loopback_port(left: &str, right: &str) -> bool {
    match (loopback_port(left), loopback_port(right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn loopback_port(value: &str) -> Option<u16> {
    let value = value.to_ascii_lowercase();
    let port = value
        .strip_prefix("127.0.0.1:")
        .or_else(|| value.strip_prefix("ws://127.0.0.1:"))
        .and_then(|value| value.strip_suffix("/rpc").or(Some(value)))?;
    port.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{ConfigError, CredentialProviderKind, GovernorConfig, SurrealServerConfig};

    #[test]
    fn default_config_is_valid() -> Result<(), ConfigError> {
        GovernorConfig::default().validate()
    }

    #[test]
    fn exact_runtime_live_identity_is_a_collision_but_other_config_is_parseable() {
        let mut colliding = GovernorConfig::default();
        colliding.db.surreal.bind = "127.0.0.1:8000".to_owned();
        colliding.db.surreal.endpoint = "ws://127.0.0.1:8000/rpc".to_owned();
        colliding.db.surreal.ns = "eliot".to_owned();
        assert!(colliding.collides_with_store(
            "127.0.0.1:8000",
            "ws://127.0.0.1:8000/rpc",
            "eliot"
        ));
        assert!(matches!(
            colliding.reject_store_collision("127.0.0.1:8000", "ws://127.0.0.1:8000/rpc", "eliot"),
            Err(ConfigError::RuntimeLiveStoreCollision { .. })
        ));

        let mut different = colliding.clone();
        different.db.surreal.endpoint = "ws://127.0.0.1:8001/rpc".to_owned();
        different.db.surreal.bind = "127.0.0.1:18001".to_owned();
        assert!(!different.collides_with_store(
            "127.0.0.1:8000",
            "ws://127.0.0.1:8000/rpc",
            "eliot"
        ));
        assert!(different.validate().is_ok());

        let mut alternate_bind = colliding.clone();
        alternate_bind.db.surreal.bind = "127.0.0.1:18001".to_owned();
        assert!(alternate_bind.collides_with_store(
            "127.0.0.1:8000",
            "ws://127.0.0.1:8000/rpc",
            "eliot"
        ));

        let mut alternate_endpoint = colliding.clone();
        alternate_endpoint.db.surreal.endpoint = "WS://127.0.0.1:08000/rpc".to_owned();
        alternate_endpoint.db.surreal.bind = "127.0.0.1:18001".to_owned();
        assert!(alternate_endpoint.collides_with_store(
            "127.0.0.1:8000",
            "ws://127.0.0.1:8000/rpc",
            "eliot"
        ));

        let mut alternate_namespace = colliding;
        alternate_namespace.db.surreal.ns = "other".to_owned();
        assert!(!alternate_namespace.collides_with_store(
            "127.0.0.1:8000",
            "ws://127.0.0.1:8000/rpc",
            "eliot"
        ));
    }

    /// Omitting `credential_provider` must not silently select the plaintext
    /// password file. Storing the secret in Windows Credential Manager is the
    /// production authority, so it is what an unspecified config resolves to.
    #[test]
    fn an_unspecified_credential_provider_resolves_to_the_windows_credential_manager()
    -> Result<(), serde_json::Error> {
        let surreal: SurrealServerConfig = serde_json::from_str(
            r#"{
                "exe": "surreal",
                "bind": "127.0.0.1:18000",
                "endpoint": "ws://127.0.0.1:18000/rpc",
                "storage": "rocksdb:data/surrealdb-rocks",
                "ns": "eliot",
                "db": "eliot",
                "user": "root",
                "log_level": "warn",
                "query_timeout_ms": 5000,
                "transaction_timeout_ms": 5000,
                "startup_timeout_ms": 20000,
                "restart_backoff_ms": 200,
                "max_restart_backoff_ms": 2000,
                "capabilities": {
                    "deny_all": true,
                    "allow_funcs": [],
                    "allow_net": [],
                    "allow_scripting": false,
                    "allow_guests": false
                }
            }"#,
        )?;

        assert_eq!(
            surreal.credential_provider,
            CredentialProviderKind::WindowsCredentialManager
        );
        Ok(())
    }

    /// The legacy provider remains reachable, but only by naming it.
    #[test]
    fn the_legacy_password_file_provider_must_be_requested_explicitly()
    -> Result<(), serde_json::Error> {
        let explicit: CredentialProviderKind = serde_json::from_str("\"legacy_password_file\"")?;
        assert_eq!(explicit, CredentialProviderKind::LegacyPasswordFile);
        Ok(())
    }

    /// #3980 fixture: the default local socket pair with only `bind` and
    /// `endpoint` substituted, so each case below varies one field and nothing
    /// else.
    fn local_server_config(bind: &str, endpoint: &str) -> SurrealServerConfig {
        let mut config = GovernorConfig::default();
        config.db.surreal.bind = bind.to_owned();
        config.db.surreal.endpoint = endpoint.to_owned();
        config.db.surreal
    }

    const ACCEPTED_BIND: &str = "127.0.0.1:18000";

    #[test]
    fn local_endpoint_grammar_accepts_the_documented_literal_forms() {
        // The `Default` pair, the leading-zero encoding the existing
        // `loopback_port` already admitted, and port `0`, which is inside
        // `u16` and is deliberately not a new rejection.
        for (bind, endpoint, port) in [
            ("127.0.0.1:18000", "ws://127.0.0.1:18000/rpc", 18000),
            ("127.0.0.1:08000", "ws://127.0.0.1:08000/rpc", 8000),
            ("127.0.0.1:0", "ws://127.0.0.1:0/rpc", 0),
        ] {
            let config = local_server_config(bind, endpoint);
            assert!(
                config.validate_local_rpc_endpoint().is_ok(),
                "{bind} / {endpoint} must stay accepted"
            );
            assert_eq!(
                config.local_rpc_port(),
                Some(port),
                "{endpoint} names {port}"
            );
        }

        assert!(
            GovernorConfig::default()
                .db
                .surreal
                .validate_local_rpc_endpoint()
                .is_ok()
        );
    }

    #[test]
    fn local_endpoint_grammar_preserves_the_declared_case_compatibility() {
        // The previous check lowercased before matching, so `WS://` and `/RPC`
        // were accepted. That exact case set is preserved and nothing is
        // broadened: casing only, never extra structure.
        let mixed = local_server_config(ACCEPTED_BIND, "WS://127.0.0.1:18000/RPC");
        assert!(mixed.validate_local_rpc_endpoint().is_ok());
        assert_eq!(mixed.local_rpc_port(), Some(18000));

        assert!(matches!(
            local_server_config(ACCEPTED_BIND, "WS://127.0.0.1:18000/RPC?a=1")
                .validate_local_rpc_endpoint(),
            Err(ConfigError::ForbiddenDbEndpoint)
        ));
        assert!(matches!(
            local_server_config(ACCEPTED_BIND, "WS://127.0.0.1:18000/RP")
                .validate_local_rpc_endpoint(),
            Err(ConfigError::ForbiddenDbEndpoint)
        ));
    }

    /// The issue's counterexample: `ws://127.0.0.1:18000@192.0.2.1:18000/rpc`
    /// satisfied both the old prefix check and the old suffix check while
    /// naming a foreign host after an `@`. It must now fail, and the failure
    /// must not echo the rejected input back into diagnostics.
    #[test]
    fn userinfo_in_the_authority_is_not_a_loopback_endpoint() {
        for endpoint in [
            "ws://127.0.0.1:18000@192.0.2.1:18000/rpc",
            "ws://user:pass@127.0.0.1:18000/rpc",
            "ws://127.0.0.1@192.0.2.1/rpc",
            "ws://127.0.0.1:18000@192.0.2.1/rpc",
        ] {
            let Err(error) =
                local_server_config(ACCEPTED_BIND, endpoint).validate_local_rpc_endpoint()
            else {
                panic!("{endpoint} must be refused");
            };
            assert!(
                matches!(error, ConfigError::ForbiddenDbEndpoint),
                "{endpoint} must be refused as an endpoint"
            );
            assert!(
                !error.to_string().contains("pass"),
                "{endpoint} must not be echoed into diagnostics"
            );
        }
    }

    #[test]
    fn a_different_address_or_hostname_is_refused() {
        for endpoint in [
            "ws://192.0.2.1:18000/rpc",
            "ws://localhost:18000/rpc",
            "ws://127.0.0.2:18000/rpc",
            "ws://[::1]:18000/rpc",
            "ws://0.0.0.0:18000/rpc",
            "ws://127.0.0.1.example.com:18000/rpc",
        ] {
            assert!(
                matches!(
                    local_server_config(ACCEPTED_BIND, endpoint).validate_local_rpc_endpoint(),
                    Err(ConfigError::ForbiddenDbEndpoint)
                ),
                "{endpoint} must be refused, never normalised to loopback"
            );
        }

        for bind in [
            "192.0.2.1:18000",
            "localhost:18000",
            "127.0.0.2:18000",
            "[::1]:18000",
            "0.0.0.0:18000",
            "127.0.0.1.example.com:18000",
        ] {
            assert!(
                matches!(
                    local_server_config(bind, "ws://127.0.0.1:18000/rpc")
                        .validate_local_rpc_endpoint(),
                    Err(ConfigError::ForbiddenDbBind)
                ),
                "{bind} must be refused, never normalised to loopback"
            );
        }
    }

    #[test]
    fn extra_path_components_are_refused() {
        for endpoint in [
            "ws://127.0.0.1:18000/rpc/extra",
            "ws://127.0.0.1:18000/extra/rpc",
            "ws://127.0.0.1:18000/",
            "ws://127.0.0.1:18000/rpcrpc",
        ] {
            assert!(
                matches!(
                    local_server_config(ACCEPTED_BIND, endpoint).validate_local_rpc_endpoint(),
                    Err(ConfigError::ForbiddenDbEndpoint)
                ),
                "{endpoint} must leave no permitted remainder after /rpc"
            );
        }
    }

    #[test]
    fn query_and_fragment_are_refused() {
        for endpoint in [
            "ws://127.0.0.1:18000/rpc?a=1",
            "ws://127.0.0.1:18000?a=1/rpc",
            "ws://127.0.0.1:18000/rpc#f",
            "ws://127.0.0.1:18000#f/rpc",
        ] {
            assert!(
                matches!(
                    local_server_config(ACCEPTED_BIND, endpoint).validate_local_rpc_endpoint(),
                    Err(ConfigError::ForbiddenDbEndpoint)
                ),
                "{endpoint} must be refused"
            );
        }
    }

    #[test]
    fn control_characters_and_whitespace_are_refused() {
        for endpoint in [
            "ws://127.0.0.1:18000 /rpc",
            "ws://127.0.0.1:18000/rpc\n",
            "ws://127.0.0.1: 18000/rpc",
            "ws://127.0.0.1:18000/rpc\u{0}",
            "ws://127.0.0.1:18000\t/rpc",
            " ws://127.0.0.1:18000/rpc",
        ] {
            assert!(
                matches!(
                    local_server_config(ACCEPTED_BIND, endpoint).validate_local_rpc_endpoint(),
                    Err(ConfigError::ForbiddenDbEndpoint)
                ),
                "{endpoint:?} must be refused"
            );
        }

        for bind in [
            "127.0.0.1: 18000",
            "127.0.0.1:18000 ",
            "127.0.0.1:18000\n",
            "127.0.0.1:\u{0}18000",
        ] {
            assert!(
                matches!(
                    local_server_config(bind, "ws://127.0.0.1:18000/rpc")
                        .validate_local_rpc_endpoint(),
                    Err(ConfigError::ForbiddenDbBind)
                ),
                "{bind:?} must be refused"
            );
        }
    }

    #[test]
    fn a_missing_nonnumeric_signed_or_out_of_range_port_is_refused() {
        for endpoint in [
            "ws://127.0.0.1:/rpc",
            "ws://127.0.0.1:abc/rpc",
            "ws://127.0.0.1:+18000/rpc",
            "ws://127.0.0.1:-1/rpc",
            "ws://127.0.0.1:65536/rpc",
            "ws://127.0.0.1:99999/rpc",
            "ws://127.0.0.1:123456/rpc",
        ] {
            assert!(
                matches!(
                    local_server_config(ACCEPTED_BIND, endpoint).validate_local_rpc_endpoint(),
                    Err(ConfigError::ForbiddenDbEndpoint)
                ),
                "{endpoint} must be refused"
            );
        }

        for bind in [
            "127.0.0.1:",
            "127.0.0.1:abc",
            "127.0.0.1:+18000",
            "127.0.0.1:-1",
            "127.0.0.1:65536",
            "127.0.0.1:99999",
        ] {
            assert!(
                matches!(
                    local_server_config(bind, "ws://127.0.0.1:18000/rpc")
                        .validate_local_rpc_endpoint(),
                    Err(ConfigError::ForbiddenDbBind)
                ),
                "{bind} must be refused"
            );
        }
    }

    #[test]
    fn an_unsupported_scheme_or_a_scheme_on_bind_is_refused() {
        for endpoint in [
            "http://127.0.0.1:18000/rpc",
            "wss://127.0.0.1:18000/rpc",
            "ws:/127.0.0.1:18000/rpc",
            "//127.0.0.1:18000/rpc",
            "ws://127.0.0.1:18000",
        ] {
            assert!(
                matches!(
                    local_server_config(ACCEPTED_BIND, endpoint).validate_local_rpc_endpoint(),
                    Err(ConfigError::ForbiddenDbEndpoint)
                ),
                "{endpoint} must be refused"
            );
        }

        for bind in [
            "ws://127.0.0.1:18000",
            "wss://127.0.0.1:18000",
            "http:127.0.0.1:18000",
        ] {
            assert!(
                matches!(
                    local_server_config(bind, "ws://127.0.0.1:18000/rpc")
                        .validate_local_rpc_endpoint(),
                    Err(ConfigError::ForbiddenDbBind)
                ),
                "{bind} must be refused"
            );
        }
    }

    /// Both fields are checked by the one predicate, and `bind` is refused
    /// first so a caller cannot smuggle a non-local socket behind a
    /// well-formed endpoint.
    #[test]
    fn validate_local_rpc_endpoint_checks_both_bind_and_endpoint() {
        assert!(matches!(
            local_server_config("192.0.2.1:18000", "ws://192.0.2.1:18000/rpc")
                .validate_local_rpc_endpoint(),
            Err(ConfigError::ForbiddenDbBind)
        ));
        assert!(matches!(
            local_server_config(ACCEPTED_BIND, "ws://192.0.2.1:18000/rpc")
                .validate_local_rpc_endpoint(),
            Err(ConfigError::ForbiddenDbEndpoint)
        ));
        assert!(
            local_server_config(ACCEPTED_BIND, "ws://127.0.0.1:18000/rpc")
                .validate_local_rpc_endpoint()
                .is_ok()
        );
    }

    #[test]
    fn local_rpc_port_reports_the_validated_port_and_none_otherwise() {
        assert_eq!(
            local_server_config(ACCEPTED_BIND, "ws://127.0.0.1:18000/rpc").local_rpc_port(),
            Some(18000)
        );
        // Leading zeros parse to the port they name.
        assert_eq!(
            local_server_config(ACCEPTED_BIND, "ws://127.0.0.1:08000/rpc").local_rpc_port(),
            Some(8000)
        );
        assert_eq!(
            local_server_config("127.0.0.1:0", "ws://127.0.0.1:0/rpc").local_rpc_port(),
            Some(0)
        );
        // Anything outside the grammar reports nothing rather than a guess,
        // and the two agree because one function owns the parse.
        for endpoint in [
            "ws://127.0.0.1:18000@192.0.2.1:18000/rpc",
            "ws://127.0.0.1:/rpc",
            "ws://127.0.0.1:18000/rpc?a=1",
            "ws://localhost:18000/rpc",
            "wss://127.0.0.1:18000/rpc",
            "ws://127.0.0.1:65536/rpc",
        ] {
            let config = local_server_config(ACCEPTED_BIND, endpoint);
            assert!(config.validate_local_rpc_endpoint().is_err());
            assert_eq!(config.local_rpc_port(), None, "{endpoint} names no port");
        }
    }

    /// The loader path reaches the predicate: the counterexample endpoint is
    /// refused by `GovernorConfig::validate` itself, in the bind/endpoint
    /// position, before the storage and capability checks.
    #[test]
    fn the_loader_refuses_a_userinfo_endpoint_before_any_credential_or_path_effect() {
        let mut config = GovernorConfig::default();
        config.db.surreal.endpoint = "ws://127.0.0.1:18000@192.0.2.1:18000/rpc".to_owned();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ForbiddenDbEndpoint)
        ));

        let mut bad_bind = GovernorConfig::default();
        bad_bind.db.surreal.bind = "192.0.2.1:18000".to_owned();
        assert!(matches!(
            bad_bind.validate(),
            Err(ConfigError::ForbiddenDbBind)
        ));
    }
}
