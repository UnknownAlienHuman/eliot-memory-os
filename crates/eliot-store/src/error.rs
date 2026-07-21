use serde_json::Value;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Config(#[from] eliot_types::ConfigError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    RedbCommit(#[from] redb::CommitError),

    #[error(transparent)]
    RedbDatabase(#[from] redb::DatabaseError),

    #[error(transparent)]
    RedbStorage(#[from] redb::StorageError),

    #[error(transparent)]
    RedbTable(#[from] redb::TableError),

    #[error(transparent)]
    RedbTransaction(#[from] redb::TransactionError),

    #[error("blob is too large to record size as u64")]
    BlobTooLarge,

    #[error("store configuration error: {0}")]
    ConfigMessage(String),

    #[error("SurrealDB executable not found at {0}")]
    ServerNotFound(PathBuf),

    #[error("SurrealDB server start failed: {0}")]
    ServerStartFailed(String),

    #[error("SurrealDB authentication failed: {0}")]
    ServerAuthFailed(String),

    #[error("SurrealDB WebSocket connection closed")]
    ConnectionClosed,

    #[error("{op} timed out after {ms}ms")]
    Timeout { op: String, ms: u64 },

    #[error("SurrealDB RPC error {code}: {message}")]
    RpcError {
        code: i64,
        message: String,
        data: Option<Value>,
    },

    #[error("SurrealDB query {op} failed: {message}")]
    QueryFailed {
        op: String,
        message: String,
        raw: Value,
    },

    #[error("SurrealDB result is too large: {bytes} bytes > {limit} bytes")]
    ResultTooLarge { bytes: usize, limit: usize },

    #[error("failed to decode SurrealDB response: {0}")]
    Decode(String),

    #[error("SurrealDB transport policy violation: {0}")]
    PolicyViolation(String),

    #[error("WebSocket transport error: {0}")]
    WebSocket(String),

    #[error("process control error: {0}")]
    Process(String),
}
