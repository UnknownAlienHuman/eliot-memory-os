use crate::{ConfigError, CredentialProviderKind, SCHEMA_VERSION};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct GovernorConfig {
    pub schema_version: String,
    pub service: ServiceConfig,
    pub db: DbConfig,
    pub control_wal: ControlWalConfig,
    pub blob_store: BlobStoreConfig,
    pub store: StoreConfig,
    #[serde(default)]
    pub delegation_calibration: DelegationCalibrationConfig,
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub service_name: String,
    pub instance_id: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct SurrealCapabilities {
    pub deny_all: bool,
    pub allow_funcs: Vec<String>,
    pub allow_net: Vec<String>,
    pub allow_scripting: bool,
    pub allow_guests: bool,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ControlWalConfig {
    pub path: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct BlobStoreConfig {
    pub root: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct StoreConfig {
    pub surql_dir: String,
    pub migrations_dir: String,
}

impl GovernorConfig {
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
            delegation_calibration: DelegationCalibrationConfig::default(),
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

#[cfg(test)]
mod tests {
    use super::{ConfigError, CredentialProviderKind, GovernorConfig, SurrealServerConfig};

    #[test]
    fn default_config_is_valid() -> Result<(), ConfigError> {
        GovernorConfig::default().validate()
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
    fn the_legacy_password_file_provider_must_be_requested_explicitly() {
        let explicit: CredentialProviderKind =
            serde_json::from_str("\"legacy_password_file\"").expect("legacy variant still parses");
        assert_eq!(explicit, CredentialProviderKind::LegacyPasswordFile);
    }
}
