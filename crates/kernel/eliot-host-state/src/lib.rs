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
mod reactive_context;
mod redb_journal;
mod redb_store;
mod scm_operation_store;
mod service;
mod supervision;

pub use backend::{
    BackendReconcileState, CommittedAppend, DurableImage, FaultPoint, JournalBackend,
    MemoryBackend, PreparedAppend, StoredEpoch,
};
/// Compatibility alias for the canonical [`EpochId`]. Host code that names
/// the historical `EpochIdentity` type keeps compiling against the one
/// canonical lineage-aware identity; no parallel implementation remains.
pub use eliot_contracts::EpochId as EpochIdentity;
pub use eliot_contracts::{EpochId, EpochLineageId, EpochTransition};
pub use error::{BackendError, JournalError, ReconcileOutcome};
pub use journal::{
    AppendDisposition, AppendReceipt, HostStateJournal, JOURNAL_MAGIC, JOURNAL_VERSION,
    readonly_project_host_state, record_checksum,
};
pub use legacy::{LegacyHostStateImporter, LegacyHostStateSnapshot};
pub use model::{
    ActivationState, AppliedOperation, CleanMarker, DependencyLifecycleBudget, DependencyRecord,
    DependencyResourceBudget, DependencyState, DrainCommitRecord, DrainRecord, DrainState,
    EliotActivationRecord, EpochEvidence, EpochRetirementRecord, FailureRecoveryDirective,
    HostInstallationEpoch, HostKernelStoreLineage, HostObservationRecord, HostState,
    HostStateRecord, IdempotencyIdentity, ImmutableProcessManifest, JournalManifest,
    KernelJobBinding, KernelReadinessObservationRecord, KernelRecord, LifecycleTimestamps,
    NonceState, OneTimeNonceState, PriorKernelDisposition, PriorKernelSource,
    ReadinessApprovedContour, ReadinessEvidence, RecordFence, RecoveryLineageEvidence,
    RecoveryLineageReason, ServiceSafetyClass, StoreRebindRecord, StoreRebindState,
    WakeCancellationBatchEntry, WakeCancellationBatchRecord, WakeDisposition, WakeRecord,
    host_owner_epoch_digest,
};
pub use reactive_context::{
    DEFAULT_REACTIVE_CONTEXT_MAX_ATTEMPT_ITEMS, DEFAULT_REACTIVE_CONTEXT_MAX_BYTES,
    DEFAULT_REACTIVE_CONTEXT_MAX_ITEMS, DEFAULT_REACTIVE_CONTEXT_MAX_PAGE_ITEMS,
    MAX_REACTIVE_CONTEXT_REASON_BYTES, REACTIVE_CONTEXT_QUEUE_SCHEMA_VERSION,
    ReactiveContextEnqueueReceipt, ReactiveContextJournalAction, ReactiveContextOperationQuery,
    ReactiveContextPrepareRequest, ReactiveContextPrepareResult, ReactiveContextPreparedEnqueue,
    ReactiveContextQueueCursor, ReactiveContextQueueEntry, ReactiveContextQueueError,
    ReactiveContextQueueLimits, ReactiveContextQueuePort, ReactiveContextQueueQuery,
    ReactiveContextQueueSnapshot, ReactiveContextQueueState, ReactiveContextReconcileOutcome,
    ReactiveContextReconcileRequest, ReactiveContextRecord, ReactiveContextStreamCursor,
    ReactiveContextTransition, ReactiveContextTransitionEvidence, ReactiveContextTransitionReceipt,
};
pub use redb_journal::{RedbJournalBackend, RedbJournalInspection};
pub use redb_store::{
    HostAdmissionState, HostRecoverySnapshot, RedbHostReleaseToken, RedbHostStateInspection,
    RedbHostStateStore,
};
pub use scm_operation_store::{
    ScmOperationCoordinator, ScmOperationIdentity, ScmOperationRecord, ScmOperationState,
    ScmOperationStore, ScmOperationStoreError,
};
pub use service::{HostStateJournalService, ProductionHostStateJournal};
pub use supervision::reconstruct_current_supervision_incarnation;
#[cfg(test)]
mod tests;
