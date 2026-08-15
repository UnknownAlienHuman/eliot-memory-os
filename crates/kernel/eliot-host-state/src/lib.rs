//! P-05 Host-local operational state and durable journal contract.
//!
//! This crate owns the platform-neutral journal state machine and backend
//! contract. It owns no global storage, process-launch, semantic, or authority
//! implementation.

#![forbid(unsafe_code)]

mod backend;
mod error;
mod journal;
mod model;
mod redb_store;

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
    DependencyResourceBudget, DependencyState, DrainCommitRecord, DrainRecord, DrainState,
    EliotActivationRecord, EpochEvidence, EpochIdentity, EpochRetirementRecord, EpochTransition,
    FailureRecoveryDirective, HostInstallationEpoch, HostKernelStoreLineage, HostObservationRecord,
    HostState, HostStateRecord, IdempotencyIdentity, ImmutableProcessManifest, JournalManifest,
    KernelRecord, LifecycleTimestamps, NonceState, OneTimeNonceState, ReadinessEvidence,
    RecordFence, RecoveryLineageEvidence, RecoveryLineageReason, ServiceSafetyClass,
    WakeDisposition, WakeRecord,
};
pub use redb_store::{HostAdmissionState, RedbHostStateStore};
#[cfg(test)]
mod tests;
