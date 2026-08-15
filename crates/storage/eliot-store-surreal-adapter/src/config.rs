//! Connection, credential and schema-generation configuration for the SurrealDB
//! store bridge.
//!
//! The credential is held as a [`secrecy::SecretString`] and is never placed in
//! debug output, logs, reports, canonical memory or a serialized form. The
//! config is assembled programmatically by the composition owner (the store
//! bridge); it is not a TOML/JSON projection.

use std::fmt;

use secrecy::SecretString;

/// Stable identity of this adapter surface.
pub const ADAPTER_NAME: &str = "eliot.storage.store-surreal-adapter";
/// SurrealDB major version admitted by the pinned adapter/query surface.
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

/// Connection and credential settings for the sole SurrealDB client owner.
///
/// The password is the only credential value held by this crate. It is redacted
/// by [`secrecy::SecretString`] in debug formatting and is never serialized.
#[derive(Clone)]
pub struct SurrealAdapterConfig {
    /// SurrealDB WebSocket endpoint, for example `ws://127.0.0.1:18000/rpc`.
    pub endpoint: String,
    /// SurrealDB namespace.
    pub namespace: String,
    /// SurrealDB database.
    pub database: String,
    /// SurrealDB username used for sign-in.
    pub username: String,
    /// SurrealDB password credential, held opaque and redacted.
    pub password: SecretString,
    /// Connect deadline in milliseconds.
    pub connect_timeout_ms: u64,
    /// Query deadline in milliseconds.
    pub query_timeout_ms: u64,
    /// SurrealDB server major version required by the pinned query surface.
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
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
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
        if !endpoint.starts_with("ws://") && !endpoint.starts_with("wss://") {
            return Err(ConfigError::InvalidEndpoint);
        }
        validate_name(&self.namespace, "namespace")?;
        validate_name(&self.database, "database")?;
        validate_name(&self.username, "username")?;
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
}

fn validate_name(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ConfigError::InvalidField { field });
    }
    Ok(())
}

/// Configuration failure without exposing the credential value.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConfigError {
    #[error("endpoint must start with ws:// or wss://")]
    InvalidEndpoint,
    #[error("timeouts must be non-zero")]
    InvalidTimeout,
    #[error("provider major version must be the pinned SurrealDB {expected}.x line")]
    UnsupportedProviderMajor { expected: u16 },
    #[error("invalid field {field}")]
    InvalidField { field: &'static str },
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    fn config(endpoint: &str) -> SurrealAdapterConfig {
        SurrealAdapterConfig {
            endpoint: endpoint.to_owned(),
            namespace: "eliot".to_owned(),
            database: "eliot".to_owned(),
            username: "root".to_owned(),
            password: SecretString::new("test-secret".into()),
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
        assert!(config("wss://example.com/rpc").validate().is_ok());
        assert!(config("http://example.com").validate().is_err());
        assert!(config("nonsense").validate().is_err());
    }

    #[test]
    fn debug_output_redacts_the_password() {
        let rendered = format!("{:?}", config("ws://127.0.0.1:18000/rpc"));
        assert!(!rendered.contains("test-secret"));
        assert!(rendered.contains("REDACTED"));
    }
}
