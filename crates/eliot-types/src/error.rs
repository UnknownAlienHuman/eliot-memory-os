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

    // #3980: the rejected value can itself be secret-bearing userinfo, and per
    // docs/architecture/I15-04-secrets.md diagnostics record the reference, never the value.
    #[error("SurrealDB bind address must be the literal loopback socket 127.0.0.1:<port>")]
    ForbiddenDbBind,

    // #3980: the rejected URI can itself be secret-bearing userinfo, and per
    // docs/architecture/I15-04-secrets.md diagnostics record the reference, never the value.
    #[error("SurrealDB endpoint must be exactly ws://127.0.0.1:<port>/rpc")]
    ForbiddenDbEndpoint,

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
