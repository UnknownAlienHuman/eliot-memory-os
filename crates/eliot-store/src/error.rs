use serde_json::Value;
use std::fmt;
use std::io;
use std::path::PathBuf;
use thiserror::Error;

/// Filesystem stage at which a legacy blob operation observed capacity loss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageExhaustedStage {
    /// Creation of the configured root or its parent was attempted.
    RootCreate,
    /// Canonicalization of the configured root was attempted after creation.
    RootCanonicalize,
    /// Creation of the content-addressed parent directory was attempted.
    ParentCreate,
    /// Creation of the per-attempt staging file was attempted.
    TempCreate,
    /// Payload bytes were offered to the staging file.
    PayloadWrite,
    /// Synchronization of the staging file was attempted.
    PayloadSync,
    /// Renaming the staging file to its content-addressed destination was attempted.
    Rename,
}

/// What the legacy store can safely say about publication after a capacity error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageExhaustedEffect {
    /// An operation was attempted, but no canonical publication was observed.
    AttemptedNoPublication,
    /// Staged bytes or durability may be partial or unknown.
    StagedUnknown,
    /// Rename may have published the destination and requires reconciliation.
    PossiblePublication,
}

/// Capacity failures require external revalidation before the same operation is retried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageExhaustedRetry {
    /// No automatic retry is safe until capacity and the original operation are reconciled.
    CapacityRevalidationRequired,
}

/// Redacted native I/O evidence retained by a typed capacity failure.
pub struct StorageIoCause {
    error: io::Error,
    namespace: &'static str,
}

impl StorageIoCause {
    pub(crate) fn new(error: io::Error, namespace: &'static str) -> Self {
        Self { error, namespace }
    }

    /// The native error kind, without exposing platform paths or payload text.
    #[must_use]
    pub fn kind(&self) -> io::ErrorKind {
        self.error.kind()
    }

    /// The native OS code when the platform supplied one.
    #[must_use]
    pub fn raw_os_error(&self) -> Option<i32> {
        self.error.raw_os_error()
    }

    /// Native namespace associated with the captured OS code.
    #[must_use]
    pub fn namespace(&self) -> &'static str {
        self.namespace
    }
}

impl fmt::Debug for StorageIoCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageIoCause")
            .field("kind", &self.kind())
            .field("raw_os_error", &self.raw_os_error())
            .field("namespace", &self.namespace())
            .finish()
    }
}

impl fmt::Display for StorageIoCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "native {:?}", self.kind())
    }
}

impl std::error::Error for StorageIoCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Keep the native error private while exposing only bounded kind/code
        // accessors; native messages can contain configured paths or payloads.
        None
    }
}

/// Cleanup state retained alongside the primary capacity failure.
#[derive(Debug)]
pub enum StorageCleanup {
    /// The attempt did not own a staging path to remove.
    NotAttempted,
    /// The staging path was removed successfully.
    Removed,
    /// The staging path was already absent when cleanup ran.
    Absent,
    /// Cleanup was attempted but its native result was not successful.
    Failed(StorageIoCause),
}

/// Typed legacy storage-capacity failure.
///
/// The operation name is a local package operation, while `local_attempt_id`
/// is only the staging-file attempt token. Neither is a canonical operation
/// receipt or an admission claim. Display and Debug remain bounded and never
/// include raw configured paths, payloads, or native error text.
pub struct StorageExhausted {
    /// Local operation name, such as `blob.put_bytes` or `blob.open`.
    pub operation: &'static str,
    /// Filesystem stage that observed the capacity failure.
    pub stage: StorageExhaustedStage,
    /// Redacted hash of the configured storage-root identity.
    pub storage_identity: String,
    /// Per-attempt staging token when one exists.
    pub local_attempt_id: Option<String>,
    /// Buffer bytes offered to the write call, not committed bytes.
    pub attempted_bytes: Option<u64>,
    /// Last confirmed or possible external-effect state.
    pub effect: StorageExhaustedEffect,
    /// Required retry/reconciliation policy.
    pub retry: StorageExhaustedRetry,
    /// Explicit cleanup observation for the staging artifact.
    pub cleanup: StorageCleanup,
    /// Redacted native primary cause.
    pub cause: StorageIoCause,
}

impl fmt::Debug for StorageExhausted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageExhausted")
            .field("operation", &self.operation)
            .field("stage", &self.stage)
            .field("storage_identity", &self.storage_identity)
            .field("local_attempt_id", &self.local_attempt_id)
            .field("attempted_bytes", &self.attempted_bytes)
            .field("effect", &self.effect)
            .field("retry", &self.retry)
            .field("cleanup", &self.cleanup)
            .field("cause", &self.cause)
            .finish()
    }
}

impl fmt::Display for StorageExhausted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "legacy storage capacity exhausted during {} at {:?} ({:?})",
            self.operation, self.stage, self.effect
        )
    }
}

impl std::error::Error for StorageExhausted {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Config(#[from] eliot_types::ConfigError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A legacy local blob operation observed native storage exhaustion.
    #[error(transparent)]
    StorageExhausted(#[from] Box<StorageExhausted>),

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

    #[error("SurrealDB client set is shutting down")]
    ClientSetShuttingDown,

    #[error("SurrealDB client set startup failed: {0}")]
    ClientSetStartupFailed(String),

    #[error("SurrealDB client set shutdown failed: {0}")]
    ClientSetShutdownFailed(String),

    #[error("observability write_id conflicts with a different payload")]
    ObservabilityConflict,

    #[error("WebSocket transport error: {0}")]
    WebSocket(String),

    #[error("process control error: {0}")]
    Process(String),
}

impl StoreError {
    /// A fatal transport error makes the RPC session unusable. The current
    /// operation is never replayed; its slot reconnects only when a later
    /// operation acquires it.
    pub(crate) const fn invalidates_rpc_transport(&self) -> bool {
        matches!(
            self,
            Self::ConnectionClosed | Self::Timeout { .. } | Self::Decode(_) | Self::WebSocket(_)
        )
    }
}
