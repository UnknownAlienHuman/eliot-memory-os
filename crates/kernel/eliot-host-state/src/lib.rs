//! P-05 Host-local operational state and durable journal contract.
//!
//! This crate owns no Windows, redb, process-launch, semantic, or authority
//! implementation. It validates and serializes the one-writer Host journal.

#![forbid(unsafe_code)]

mod backend;
mod error;
mod journal;
mod model;

pub use backend::{
    BackendReconcileState, CommittedAppend, DurableImage, FaultPoint, JournalBackend,
    MemoryBackend, PreparedAppend, StoredEpoch,
};
pub use error::{BackendError, JournalError, ReconcileOutcome};
pub use journal::{
    AppendDisposition, AppendReceipt, HostStateJournal, JOURNAL_MAGIC, JOURNAL_VERSION,
    record_checksum,
};
pub use model::{
    ActivationState, AppliedOperation, CleanMarker, DependencyLifecycleBudget, DependencyRecord,
    DependencyState, DrainCommitRecord, DrainRecord, DrainState, EliotActivationRecord,
    EpochEvidence, EpochIdentity, EpochRetirementRecord, EpochTransition, FailureRecoveryDirective,
    HostInstallationEpoch, HostKernelStoreLineage, HostObservationRecord, HostState,
    HostStateRecord, IdempotencyIdentity, ImmutableProcessManifest, JournalManifest, KernelRecord,
    LifecycleTimestamps, NonceState, OneTimeNonceState, ReadinessEvidence, RecordFence,
    RecoveryLineageEvidence, RecoveryLineageReason, ServiceSafetyClass, WakeDisposition,
    WakeRecord,
};

#[cfg(test)]
mod tests;
