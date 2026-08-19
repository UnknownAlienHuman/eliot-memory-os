//! Connection, credential and schema-generation configuration for the `SurrealDB`
//! store bridge.
//!
//! The credential is held as a [`secrecy::SecretString`] and is never placed in
//! debug output, logs, reports, canonical memory or a serialized form. The
//! config is assembled programmatically by the composition owner (the store
//! bridge); it is not a TOML/JSON projection.

use std::fmt;
use std::path::{Component, Path};

use secrecy::SecretString;

/// Stable identity of this adapter surface.
pub const ADAPTER_NAME: &str = "eliot.storage.store-surreal-adapter";
/// `SurrealDB` major version admitted by the pinned adapter/query surface.
pub const PINNED_SURREALDB_MAJOR: u16 = 3;

/// Non-blank, non-control-character schema generation identifier.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct SchemaGeneration(String);

impl SchemaGeneration {
    /// Constructs a valid schema generation identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, SchemaGenerationError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(SchemaGenerationError::Invalid);
        }
        Ok(Self(value))
    }

    /// Returns the stable generation identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SchemaGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Failure to construct a [`SchemaGeneration`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SchemaGenerationError {
    #[error("schema generation must be non-blank and contain no control characters")]
    Invalid,
}

/// Connection and credential settings for the sole `SurrealDB` client owner.
///
/// The password is the only credential value held by this crate. It is redacted
/// by [`secrecy::SecretString`] in debug formatting and is never serialized.
#[derive(Clone)]
pub struct SurrealAdapterConfig {
    /// `SurrealDB` WebSocket endpoint, for example `ws://127.0.0.1:18000/rpc`.
    pub endpoint: String,
    /// `SurrealDB` namespace.
    pub namespace: String,
    /// `SurrealDB` database.
    pub database: String,
    /// `SurrealDB` username used for sign-in.
    pub username: String,
    /// `SurrealDB` password credential, held opaque and redacted.
    pub password: SecretString,
    /// Exact loopback address owned by this adapter's provider child.
    pub provider_bind_address: String,
    /// Canonical installation identity that owns the provider roots.
    pub installation_id: String,
    /// Canonical installation profile (`system_service`, `user_mode`, or
    /// `portable_dev`).
    pub installation_profile: String,
    /// Digest of the complete canonical `RuntimeStateRoots` projection.
    pub runtime_state_roots_digest: String,
    /// Installation-approved canonical `surreal.exe` path.
    pub provider_executable_path: String,
    /// Installation-approved SHA-256 of the canonical provider executable.
    pub provider_artifact_digest: String,
    /// Descriptor-bound canonical provider argv, excluding argv[0].
    pub provider_arguments: Vec<String>,
    /// Canonical `SurrealKV` data root.
    pub store_data_root: String,
    /// Canonical provider working/log root.
    pub store_work_root: String,
    /// Canonical provider temporary-file root.
    pub store_temp_root: String,
    /// Connect deadline in milliseconds.
    pub connect_timeout_ms: u64,
    /// Query deadline in milliseconds.
    pub query_timeout_ms: u64,
    /// `SurrealDB` server major version required by the pinned query surface.
    pub expected_provider_major: u16,
    /// Schema generation this bridge expects the database to be migrated to.
    pub expected_schema_generation: SchemaGeneration,
}

impl fmt::Debug for SurrealAdapterConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SurrealAdapterConfig")
            .field("endpoint", &self.endpoint)
            .field("namespace", &self.namespace)
            .field("database", &self.database)
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("provider_bind_address", &self.provider_bind_address)
            .field("installation_id", &self.installation_id)
            .field("installation_profile", &self.installation_profile)
            .field(
                "runtime_state_roots_digest",
                &self.runtime_state_roots_digest,
            )
            .field("provider_executable_path", &self.provider_executable_path)
            .field("provider_artifact_digest", &self.provider_artifact_digest)
            .field("provider_arguments", &self.provider_arguments)
            .field("store_data_root", &self.store_data_root)
            .field("store_work_root", &self.store_work_root)
            .field("store_temp_root", &self.store_temp_root)
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("query_timeout_ms", &self.query_timeout_ms)
            .field("expected_provider_major", &self.expected_provider_major)
            .field(
                "expected_schema_generation",
                &self.expected_schema_generation,
            )
            .finish()
    }
}

impl SurrealAdapterConfig {
    /// Validates the non-secret configuration fields without inspecting the
    /// credential value.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let endpoint = self.endpoint.trim();
        validate_provider_bind_address(&self.provider_bind_address)?;
        if endpoint != format!("ws://{}/rpc", self.provider_bind_address) {
            return Err(ConfigError::InvalidEndpoint);
        }
        validate_name(&self.namespace, "namespace")?;
        validate_name(&self.database, "database")?;
        validate_name(&self.username, "username")?;
        validate_name(&self.installation_id, "installation_id")?;
        if !matches!(
            self.installation_profile.as_str(),
            "system_service" | "user_mode" | "portable_dev"
        ) {
            return Err(ConfigError::InvalidField {
                field: "installation_profile",
            });
        }
        validate_digest(
            &self.runtime_state_roots_digest,
            "runtime_state_roots_digest",
        )?;
        validate_digest(&self.provider_artifact_digest, "provider_artifact_digest")?;
        let executable = Path::new(&self.provider_executable_path);
        if !executable.is_absolute()
            || executable
                .file_name()
                .and_then(|name| name.to_str())
                .is_none_or(|name| !name.eq_ignore_ascii_case("surreal.exe"))
        {
            return Err(ConfigError::InvalidField {
                field: "provider_executable_path",
            });
        }
        let roots = [
            ("store_data_root", self.store_data_root.as_str()),
            ("store_work_root", self.store_work_root.as_str()),
            ("store_temp_root", self.store_temp_root.as_str()),
        ];
        for (field, value) in roots {
            validate_root(value, field)?;
        }
        let normalized = roots.map(|(_, value)| normalize_root(value));
        if normalized[0] == normalized[1]
            || normalized[0] == normalized[2]
            || normalized[1] == normalized[2]
        {
            return Err(ConfigError::AliasedRuntimeRoots);
        }
        if self.provider_arguments != self.expected_provider_arguments() {
            return Err(ConfigError::InvalidField {
                field: "provider_arguments",
            });
        }
        if self.connect_timeout_ms == 0 || self.query_timeout_ms == 0 {
            return Err(ConfigError::InvalidTimeout);
        }
        if self.expected_provider_major != PINNED_SURREALDB_MAJOR {
            return Err(ConfigError::UnsupportedProviderMajor {
                expected: PINNED_SURREALDB_MAJOR,
            });
        }
        Ok(())
    }

    /// Returns the one canonical provider argv implied by the validated Store
    /// roots and loopback bind address.
    #[must_use]
    pub fn expected_provider_arguments(&self) -> Vec<String> {
        vec![
            "start".to_owned(),
            "--no-banner".to_owned(),
            "--bind".to_owned(),
            self.provider_bind_address.clone(),
            "--temporary-directory".to_owned(),
            self.store_temp_root.clone(),
            "--log-file-enabled".to_owned(),
            "--log-file-path".to_owned(),
            self.store_work_root.clone(),
            "--log-file-name".to_owned(),
            "surrealdb.log".to_owned(),
            format!("surrealkv://{}", self.store_data_root.replace('\\', "/")),
        ]
    }
}

fn validate_name(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ConfigError::InvalidField { field });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ConfigError::InvalidField { field });
    }
    Ok(())
}

fn validate_provider_bind_address(value: &str) -> Result<(), ConfigError> {
    let port = value
        .strip_prefix("127.0.0.1:")
        .or_else(|| value.strip_prefix("[::1]:"))
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0);
    if port.is_none() {
        return Err(ConfigError::InvalidField {
            field: "provider_bind_address",
        });
    }
    Ok(())
}

fn validate_root(value: &str, field: &'static str) -> Result<(), ConfigError> {
    validate_name(value, field)?;
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ConfigError::InvalidField { field });
    }
    Ok(())
}

fn normalize_root(value: &str) -> String {
    value
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

/// Configuration failure without exposing the credential value.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConfigError {
    #[error("endpoint must exactly match the explicit loopback provider bind address")]
    InvalidEndpoint,
    #[error("timeouts must be non-zero")]
    InvalidTimeout,
    #[error("provider major version must be the pinned SurrealDB {expected}.x line")]
    UnsupportedProviderMajor { expected: u16 },
    #[error("invalid field {field}")]
    InvalidField { field: &'static str },
    #[error("Store data, work, and temp roots must be distinct")]
    AliasedRuntimeRoots,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use secrecy::SecretString;

    use super::*;

    fn config(endpoint: &str) -> SurrealAdapterConfig {
        SurrealAdapterConfig {
            endpoint: endpoint.to_owned(),
            namespace: "eliot".to_owned(),
            database: "eliot".to_owned(),
            username: "provider-user".to_owned(),
            password: SecretString::new("test-secret".into()),
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
            expected_provider_major: PINNED_SURREALDB_MAJOR,
            expected_schema_generation: SchemaGeneration::new("1.0.0").expect("valid generation"),
        }
    }

    #[test]
    fn schema_generation_rejects_blank_and_control() {
        assert!(SchemaGeneration::new("").is_err());
        assert!(SchemaGeneration::new("  ").is_err());
        assert!(SchemaGeneration::new("bad\nvalue").is_err());
        assert!(SchemaGeneration::new("1.0.0").is_ok());
    }

    #[test]
    fn config_validates_endpoint_and_names() {
        assert!(config("ws://127.0.0.1:18000/rpc").validate().is_ok());
        assert!(config("http://example.com").validate().is_err());
        assert!(config("nonsense").validate().is_err());
        let mut mismatched = config("ws://127.0.0.1:18000/rpc");
        mismatched.provider_bind_address = "127.0.0.1:19000".to_owned();
        assert!(mismatched.validate().is_err());
    }

    #[test]
    fn debug_output_redacts_the_password() {
        let rendered = format!("{:?}", config("ws://127.0.0.1:18000/rpc"));
        assert!(!rendered.contains("test-secret"));
        assert!(!rendered.contains("provider-user"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn config_rejects_root_aliases_relative_roots_and_bad_digests() {
        let mut aliased = config("ws://127.0.0.1:18000/rpc");
        aliased.store_temp_root = aliased.store_data_root.clone();
        assert_eq!(aliased.validate(), Err(ConfigError::AliasedRuntimeRoots));

        let mut relative = config("ws://127.0.0.1:18000/rpc");
        relative.store_work_root = r"store\work".to_owned();
        assert!(relative.validate().is_err());

        let mut bad_digest = config("ws://127.0.0.1:18000/rpc");
        bad_digest.runtime_state_roots_digest = "unknown".to_owned();
        assert!(bad_digest.validate().is_err());
    }
}
