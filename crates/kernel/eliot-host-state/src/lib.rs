//! P-05 Host-local operational state and durable journal contract.
//!
//! This crate owns the platform-neutral journal state machine and backend
//! contract. It owns no global storage, process-launch, semantic, or authority
//! implementation.

#![forbid(unsafe_code)]

pub use eliot_platform::{HostProcessNonce, KernelActivationNonce};

mod backend;
mod error;
mod journal;
mod legacy;
mod model;
mod redb_journal;
mod redb_store;
mod service;

pub use backend::{
    BackendReconcileState, CommittedAppend, DurableImage, FaultPoint, JournalBackend,
    MemoryBackend, PreparedAppend, StoredEpoch,
};
pub use error::{BackendError, JournalError, ReconcileOutcome};
pub use journal::{
    AppendDisposition, AppendReceipt, HostStateJournal, JOURNAL_MAGIC, JOURNAL_VERSION,
    readonly_project_host_state, record_checksum,
};
pub use legacy::{LegacyHostStateImporter, LegacyHostStateSnapshot};
pub use model::{
    ActivationState, AppliedOperation, CleanMarker, DependencyLifecycleBudget, DependencyRecord,
    DependencyResourceBudget, DependencyState, DrainCommitRecord, DrainRecord, DrainState,
    EliotActivationRecord, EpochEvidence, EpochIdentity, EpochRetirementRecord, EpochTransition,
    FailureRecoveryDirective, HostInstallationEpoch, HostKernelStoreLineage, HostObservationRecord,
    HostState, HostStateRecord, IdempotencyIdentity, ImmutableProcessManifest, JournalManifest,
    KernelJobBinding, KernelReadinessObservationRecord, KernelRecord, LifecycleTimestamps,
    NonceState, OneTimeNonceState, PriorKernelDisposition, PriorKernelSource,
    ReadinessApprovedContour, ReadinessEvidence, RecordFence, RecoveryLineageEvidence,
    RecoveryLineageReason, ServiceSafetyClass, WakeDisposition, WakeRecord,
};
pub use redb_journal::{RedbJournalBackend, RedbJournalInspection};
pub use redb_store::{
    HostAdmissionState, HostRecoverySnapshot, RedbHostReleaseToken, RedbHostStateInspection,
    RedbHostStateStore,
};
pub use service::{HostStateJournalService, ProductionHostStateJournal};
#[cfg(test)]
mod tests;
