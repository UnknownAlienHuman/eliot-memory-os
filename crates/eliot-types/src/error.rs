use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
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
}
