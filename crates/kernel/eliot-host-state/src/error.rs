use eliot_platform::{PlatformHandle, ProviderError, UnknownReason};
use thiserror::Error;

/// Persistence failure. `Unknown` is never converted to a retryable error.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum BackendError {
    #[error("host-state backend is unavailable")]
    Unavailable,
    #[error("host-state backend outcome is unknown: {0}")]
    Unknown(UnknownReason),
    #[error("host-state backend transaction identity conflicts")]
    Conflict,
    #[error("host-state backend provider error: {0:?}")]
    Provider(ProviderError),
    #[error("host-state dependency is not available in this composition: {dependency}")]
    PlanGap { dependency: &'static str },
    #[error("host-state backend failed: {0}")]
    Failed(String),
}

/// Result of reconciling one stable append transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileOutcome {
    Committed,
    NotCommitted,
    StillUnknown,
}

/// P-05 rejects malformed, stale, conflicted, or indeterminate mutations.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum JournalError {
    #[error("backend: {0}")]
    Backend(BackendError),
    #[error("PLAN_GAP: required dependency is unavailable: {dependency}")]
    PlanGap { dependency: &'static str },
    #[error("journal is torn at byte {offset}")]
    Torn { offset: usize },
    #[error("journal checksum mismatch at sequence {sequence}")]
    Checksum { sequence: u64 },
    #[error("journal schema version {version} is unsupported")]
    UnknownVersion { version: u16 },
    #[error("journal record is invalid: {0}")]
    Invalid(String),
    #[error("journal sequence overflow or discontinuity")]
    Sequence,
    #[error("stale host, activation, or drain fence")]
    StaleFence,
    #[error("epoch lineage or parent relationship conflicts")]
    EpochLineageConflict,
    #[error("recovery requires an exact new child host epoch")]
    RecoveryRequiresNewEpoch,
    #[error("illegal {machine} transition from {from} to {to}")]
    IllegalTransition {
        machine: &'static str,
        from: String,
        to: String,
    },
    #[error("idempotency identity conflicts with a different record")]
    IdempotencyConflict,
    #[error("durable outcome is unknown for transaction {transaction_id}")]
    OutcomeUnknown { transaction_id: PlatformHandle },
    #[error("journal writer synchronization failed")]
    Synchronization,
}
