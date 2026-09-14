#![forbid(unsafe_code)]
//! Frozen private legacy Governor config decoder for the Windows canary gate.
//!
//! This module is a private, frozen copy of the exact decoding/validation
//! semantics previously taken from `eliot-types` for the two canary callers in
//! `main.rs` (`observe_legacy_governor_config` / `revalidate_legacy_governor_gate`).
//! It confers no new authority: read-only TOML decode + validate +
//! runtime-live Store collision check before any writer, database, or child
//! process. No credentials are read or used here.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub(super) const SCHEMA_VERSION: &str = "1";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct GovernorConfig {
    pub(super) schema_version: String,
    pub(super) service: ServiceConfig,
    pub(super) db: DbConfig,
    pub(super) control_wal: ControlWalConfig,
    pub(super) blob_store: BlobStoreConfig,
    pub(super) store: StoreConfig,
    #[serde(default)]
    pub(super) supervision: RuntimeSupervisionConfig,
    #[serde(default)]
    pub(super) delegation_calibration: DelegationCalibrationConfig,
    #[serde(default)]
    pub(super) ul: UlConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct RuntimeSupervisionConfig {
    pub(super) watchdog_interval_ms: u64,
}

impl Default for RuntimeSupervisionConfig {
    fn default() -> Self {
        Self {
            watchdog_interval_ms: 2_000,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct UlConfig {
    #[serde(default)]
    pub(super) activation: UlActivationConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct UlActivationConfig {
    pub(super) enable_min_edges: u32,
}

impl Default for UlActivationConfig {
    fn default() -> Self {
        Self {
            enable_min_edges: 500,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct DelegationCalibrationConfig {
    pub(super) minimum_real_tasks_total: u32,
    pub(super) minimum_real_tasks_per_family: u32,
    pub(super) minimum_executed_reviews_total: u32,
    pub(super) minimum_executed_reviews_per_candidate_family: u32,
    pub(super) minimum_complete_outcome_fraction: f64,
    pub(super) minimum_shadow_tasks_total: u32,
    pub(super) require_zero_authority_violations: bool,
    pub(super) require_zero_live_tree_violations: bool,
    pub(super) require_zero_recursive_executions: bool,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct ServiceConfig {
    pub(super) service_name: String,
    pub(super) instance_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct DbConfig {
    pub(super) mode: DbMode,
    pub(super) surreal: SurrealServerConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "frozen legacy wire variants preserved exactly; renaming would change TOML semantics"
)]
pub(super) enum DbMode {
    SurrealRpcServer,
    SurrealMcpChild,
    SurrealSqlCli,
    SurrealSdkExperimental,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct SurrealServerConfig {
    pub(super) exe: String,
    pub(super) bind: String,
    pub(super) endpoint: String,
    pub(super) storage: String,
    pub(super) ns: String,
    pub(super) db: String,
    pub(super) user: String,
    #[serde(default = "default_surreal_credential_provider")]
    pub(super) credential_provider: CredentialProviderKind,
    #[serde(default = "default_surreal_credential_id")]
    pub(super) credential_id: String,
    #[serde(default = "default_surreal_password_file")]
    pub(super) password_file: String,
    pub(super) log_level: String,
    pub(super) query_timeout_ms: u64,
    pub(super) transaction_timeout_ms: u64,
    pub(super) startup_timeout_ms: u64,
    pub(super) restart_backoff_ms: u64,
    pub(super) max_restart_backoff_ms: u64,
    pub(super) capabilities: SurrealCapabilities,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct SurrealCapabilities {
    pub(super) deny_all: bool,
    pub(super) allow_funcs: Vec<String>,
    pub(super) allow_net: Vec<String>,
    pub(super) allow_scripting: bool,
    pub(super) allow_guests: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct ControlWalConfig {
    pub(super) path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct BlobStoreConfig {
    pub(super) root: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct StoreConfig {
    pub(super) surql_dir: String,
    pub(super) migrations_dir: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CredentialProviderKind {
    WindowsCredentialManager,
    DpapiProtectedFile,
    ServiceEnvironment,
    TestInMemory,
    LegacyPasswordFile,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub(super) enum ConfigError {
    #[error("schema_version must be {expected}, got {actual}")]
    UnsupportedSchemaVersion {
        expected: &'static str,
        actual: String,
    },

    #[error("{field} must not be empty")]
    EmptyField { field: &'static str },

    #[error("{field} must be non-zero")]
    ZeroField { field: &'static str },

    #[error("SurrealDB bind address must stay on 127.0.0.1, got {bind}")]
    ForbiddenDbBind { bind: String },

    #[error("SurrealDB endpoint must be ws://127.0.0.1:<port>/rpc, got {endpoint}")]
    ForbiddenDbEndpoint { endpoint: String },

    #[error("SurrealDB storage must be a local rocksdb:<path> URI, got {storage}")]
    ForbiddenDbStorage { storage: String },

    #[error("forbidden SurrealDB capability {field}={value}")]
    ForbiddenCapability { field: &'static str, value: String },

    #[error("unsupported SurrealDB credential provider: {provider}")]
    UnsupportedCredentialProvider { provider: String },

    #[error(
        "configuration collides with the reserved runtime-live store: bind={bind}, endpoint={endpoint}, namespace={namespace}"
    )]
    RuntimeLiveStoreCollision {
        bind: String,
        endpoint: String,
        namespace: String,
    },
}

impl GovernorConfig {
    /// Returns true when this configuration can claim the reserved store by
    /// endpoint/namespace or by bind/namespace.
    #[allow(
        dead_code,
        reason = "frozen GovernorConfig wrapper retained for exact legacy parity; gate calls via db.surreal"
    )]
    #[must_use]
    pub(super) fn collides_with_store(&self, bind: &str, endpoint: &str, namespace: &str) -> bool {
        self.db
            .surreal
            .collides_with_store(bind, endpoint, namespace)
    }

    /// Rejects a reserved store identity before any writer, database, or child
    /// process can be started.
    #[allow(
        dead_code,
        reason = "frozen GovernorConfig wrapper retained for exact legacy parity; gate calls via db.surreal"
    )]
    pub(super) fn reject_store_collision(
        &self,
        bind: &str,
        endpoint: &str,
        namespace: &str,
    ) -> Result<(), ConfigError> {
        self.db
            .surreal
            .reject_store_collision(bind, endpoint, namespace)
    }

    pub(super) fn validate(&self) -> Result<(), ConfigError> {
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
        require_non_empty("store.migrations_dir", &self.store.migrations_dir)?;

        let bind = self.db.surreal.bind.to_ascii_lowercase();
        if !bind.starts_with("127.0.0.1:") {
            return Err(ConfigError::ForbiddenDbBind {
                bind: self.db.surreal.bind.clone(),
            });
        }

        let endpoint = self.db.surreal.endpoint.to_ascii_lowercase();
        if !endpoint.starts_with("ws://127.0.0.1:") || !endpoint.ends_with("/rpc") {
            return Err(ConfigError::ForbiddenDbEndpoint {
                endpoint: self.db.surreal.endpoint.clone(),
            });
        }

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
    pub(super) fn collides_with_store(&self, bind: &str, endpoint: &str, namespace: &str) -> bool {
        self.ns == namespace
            && (self.endpoint == endpoint
                || same_loopback_port(&self.endpoint, endpoint)
                || self.bind == bind
                || same_loopback_port(&self.bind, bind))
    }

    /// Rejects a reserved store identity before a server or writer starts.
    pub(super) fn reject_store_collision(
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
                migrations_dir: "crates/eliot-store/migrations".to_owned(),
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
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "frozen-decoder unit tests assert exact fail-closed TOML shapes with real parse results"
)]
mod tests {
    use super::{ConfigError, CredentialProviderKind, GovernorConfig};

    const RUNTIME_BIND: &str = "127.0.0.1:8000";
    const RUNTIME_ENDPOINT: &str = "ws://127.0.0.1:8000/rpc";
    const RUNTIME_NAMESPACE: &str = "eliot";

    fn valid_non_colliding_toml() -> String {
        concat!(
            "schema_version = \"1\"\n",
            "\n",
            "[service]\n",
            "service_name = \"EliotGovernor\"\n",
            "instance_id = \"local-dev\"\n",
            "\n",
            "[db]\n",
            "mode = \"surreal_rpc_server\"\n",
            "\n",
            "[db.surreal]\n",
            "exe = \"surreal\"\n",
            "bind = \"127.0.0.1:18000\"\n",
            "endpoint = \"ws://127.0.0.1:18000/rpc\"\n",
            "storage = \"rocksdb:.eliot-governor/surrealdb-rocks\"\n",
            "ns = \"eliot\"\n",
            "db = \"system\"\n",
            "user = \"root\"\n",
            "log_level = \"warn\"\n",
            "query_timeout_ms = 15000\n",
            "transaction_timeout_ms = 15000\n",
            "startup_timeout_ms = 20000\n",
            "restart_backoff_ms = 200\n",
            "max_restart_backoff_ms = 2000\n",
            "\n",
            "[db.surreal.capabilities]\n",
            "deny_all = true\n",
            "allow_funcs = [\"array\", \"string\", \"time\", \"type\", \"math\", \"vector\", \"search\"]\n",
            "allow_net = []\n",
            "allow_scripting = false\n",
            "allow_guests = false\n",
            "\n",
            "[control_wal]\n",
            "path = \".eliot-governor/control/control.redb\"\n",
            "\n",
            "[blob_store]\n",
            "root = \".eliot-governor/blobs\"\n",
            "\n",
            "[store]\n",
            "surql_dir = \"crates/eliot-store/src/surql\"\n",
            "migrations_dir = \"crates/eliot-store/migrations\"\n",
        )
        .to_owned()
    }

    fn decode(text: &str) -> Result<GovernorConfig, String> {
        toml::from_str::<GovernorConfig>(text).map_err(|error| format!("malformed: {error}"))
    }

    #[test]
    fn valid_non_colliding_config_passes_including_defaults() {
        let config = decode(&valid_non_colliding_toml()).expect("valid TOML decodes");
        // #[serde(default)] sections omitted above must resolve to the frozen defaults.
        assert_eq!(config.supervision.watchdog_interval_ms, 2_000);
        assert_eq!(config.ul.activation.enable_min_edges, 500);
        assert_eq!(config.delegation_calibration.minimum_real_tasks_total, 12);
        assert_eq!(
            config.delegation_calibration.minimum_real_tasks_per_family,
            5
        );
        assert_eq!(
            config.delegation_calibration.minimum_executed_reviews_total,
            4
        );
        assert_eq!(
            config
                .delegation_calibration
                .minimum_executed_reviews_per_candidate_family,
            3
        );
        assert_eq!(
            config
                .delegation_calibration
                .minimum_complete_outcome_fraction
                .to_bits(),
            0.80_f64.to_bits()
        );
        assert_eq!(config.delegation_calibration.minimum_shadow_tasks_total, 12);
        assert!(
            config
                .delegation_calibration
                .require_zero_authority_violations
        );
        assert!(
            config
                .delegation_calibration
                .require_zero_live_tree_violations
        );
        assert!(
            config
                .delegation_calibration
                .require_zero_recursive_executions
        );
        assert_eq!(
            config.db.surreal.credential_provider,
            CredentialProviderKind::WindowsCredentialManager
        );
        assert_eq!(config.db.surreal.credential_id, "surreal-runtime/local-dev");
        assert_eq!(
            config.db.surreal.password_file,
            "%LOCALAPPDATA%/Eliot/secrets/surreal_root_password.txt"
        );
        config.validate().expect("valid config validates");
        assert!(!config.collides_with_store(RUNTIME_BIND, RUNTIME_ENDPOINT, RUNTIME_NAMESPACE));
        config
            .reject_store_collision(RUNTIME_BIND, RUNTIME_ENDPOINT, RUNTIME_NAMESPACE)
            .expect("non-colliding config passes collision gate");
        // Default-constructed config carries the same frozen non-colliding identity.
        let defaults = GovernorConfig::default();
        defaults.validate().expect("default config validates");
        assert!(!defaults.collides_with_store(RUNTIME_BIND, RUNTIME_ENDPOINT, RUNTIME_NAMESPACE));
    }

    #[test]
    fn exact_collision_rejects_with_collides_prefix() {
        let mut config = decode(&valid_non_colliding_toml()).expect("valid TOML decodes");
        config.db.surreal.bind = RUNTIME_BIND.to_owned();
        config.db.surreal.endpoint = RUNTIME_ENDPOINT.to_owned();
        config.db.surreal.ns = RUNTIME_NAMESPACE.to_owned();
        assert!(config.collides_with_store(RUNTIME_BIND, RUNTIME_ENDPOINT, RUNTIME_NAMESPACE));
        let error = config
            .reject_store_collision(RUNTIME_BIND, RUNTIME_ENDPOINT, RUNTIME_NAMESPACE)
            .expect_err("exact runtime-live identity must collide");
        assert!(
            matches!(error, ConfigError::RuntimeLiveStoreCollision { .. }),
            "unexpected error: {error}"
        );
        let display = format!("{error}");
        assert!(
            display.contains("collides with the reserved runtime-live store"),
            "unexpected display: {display}"
        );
    }

    #[test]
    fn loopback_port_alias_collision_rejects() {
        let mut config = decode(&valid_non_colliding_toml()).expect("valid TOML decodes");
        // Same numeric port through a different spelling still claims the store.
        config.db.surreal.bind = "127.0.0.1:18001".to_owned();
        config.db.surreal.endpoint = "WS://127.0.0.1:08000/rpc".to_owned();
        config.db.surreal.ns = RUNTIME_NAMESPACE.to_owned();
        assert!(config.collides_with_store(RUNTIME_BIND, RUNTIME_ENDPOINT, RUNTIME_NAMESPACE));
        assert!(
            config
                .reject_store_collision(RUNTIME_BIND, RUNTIME_ENDPOINT, RUNTIME_NAMESPACE)
                .is_err()
        );
    }

    #[test]
    fn bind_only_collision_rejects() {
        let mut config = decode(&valid_non_colliding_toml()).expect("valid TOML decodes");
        config.db.surreal.bind = RUNTIME_BIND.to_owned();
        config.db.surreal.endpoint = "ws://127.0.0.1:18001/rpc".to_owned();
        config.db.surreal.ns = RUNTIME_NAMESPACE.to_owned();
        assert!(config.collides_with_store(RUNTIME_BIND, RUNTIME_ENDPOINT, RUNTIME_NAMESPACE));
        assert!(
            config
                .reject_store_collision(RUNTIME_BIND, RUNTIME_ENDPOINT, RUNTIME_NAMESPACE)
                .is_err()
        );
    }

    #[test]
    fn malformed_toml_is_malformed_not_invalid() {
        let error = decode("schema_version = [unclosed").expect_err("must fail to decode");
        assert!(error.starts_with("malformed:"), "unexpected: {error}");
    }

    #[test]
    fn invalid_variants_are_invalid() {
        let base = valid_non_colliding_toml();
        // schema mismatch
        let config: GovernorConfig =
            toml::from_str(&base.replace("schema_version = \"1\"", "schema_version = \"2\""))
                .expect("schema TOML decodes");
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedSchemaVersion { .. })
        ));
        // empty required field
        let mut config: GovernorConfig = toml::from_str(&base).expect("valid TOML decodes");
        config.service.service_name = "   ".to_owned();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::EmptyField { .. })
        ));
        // watchdog zero
        let mut config: GovernorConfig = toml::from_str(&base).expect("valid TOML decodes");
        config.supervision.watchdog_interval_ms = 0;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ZeroField { .. })
        ));
        // non-loopback bind
        let mut config: GovernorConfig = toml::from_str(&base).expect("valid TOML decodes");
        config.db.surreal.bind = "0.0.0.0:18000".to_owned();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ForbiddenDbBind { .. })
        ));
        // endpoint shape
        let mut config: GovernorConfig = toml::from_str(&base).expect("valid TOML decodes");
        config.db.surreal.endpoint = "http://127.0.0.1:18000/rpc".to_owned();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ForbiddenDbEndpoint { .. })
        ));
        // storage scheme
        let mut config: GovernorConfig = toml::from_str(&base).expect("valid TOML decodes");
        config.db.surreal.storage = "rocksdb://data".to_owned();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ForbiddenDbStorage { .. })
        ));
        // capabilities: deny_all false
        let mut config: GovernorConfig = toml::from_str(&base).expect("valid TOML decodes");
        config.db.surreal.capabilities.deny_all = false;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ForbiddenCapability { .. })
        ));
        // capabilities: scripting true
        let mut config: GovernorConfig = toml::from_str(&base).expect("valid TOML decodes");
        config.db.surreal.capabilities.allow_scripting = true;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ForbiddenCapability { .. })
        ));
        // capabilities: guests true
        let mut config: GovernorConfig = toml::from_str(&base).expect("valid TOML decodes");
        config.db.surreal.capabilities.allow_guests = true;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ForbiddenCapability { .. })
        ));
        // capabilities: allow_net non-empty
        let mut config: GovernorConfig = toml::from_str(&base).expect("valid TOML decodes");
        config.db.surreal.capabilities.allow_net = vec!["example.com".to_owned()];
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ForbiddenCapability { .. })
        ));
        // unsupported credential provider (only the two gated providers validate)
        let mut config: GovernorConfig = toml::from_str(&base).expect("valid TOML decodes");
        config.db.surreal.credential_provider = CredentialProviderKind::DpapiProtectedFile;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsupportedCredentialProvider { .. })
        ));
        // legacy provider requires an explicit non-empty password file
        let mut config: GovernorConfig = toml::from_str(&base).expect("valid TOML decodes");
        config.db.surreal.credential_provider = CredentialProviderKind::LegacyPasswordFile;
        config.db.surreal.password_file = String::new();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::EmptyField { .. })
        ));
    }
}
