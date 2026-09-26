//! P-06 durable, non-semantic Operational Recovery State (ORS).
//!
//! ORS stores opaque encrypted bytes or immutable locators plus the minimum
//! operational metadata needed to recover ordering and reconcile canonical
//! receipts. It never parses payload meaning, grants authority, or advances a
//! canonical ordering head.

#![forbid(unsafe_code)]

mod backup_snapshot;
mod cutover_ownership;
mod doctor;
mod model;
mod process_stream_recovery;
mod reservation_model;
mod restore_journal;
mod snapshot_model;
mod status;
mod status_projection;
mod store;
mod versioned_artifact;

#[cfg(feature = "test-support")]
pub mod test_support;

pub use backup_snapshot::{
    BACKUP_SNAPSHOT_SCHEMA_VERSION, BackupCompleteness, MAX_BACKUP_BYTES, MAX_BACKUP_ID_LEN,
    MAX_BACKUP_PAGE_ENTRIES, MAX_BACKUP_PAGES, OrsBackupDestination, OrsBackupEntry,
    OrsBackupFence, OrsBackupImportReceipt, OrsBackupImportRequest, OrsBackupPage,
    OrsBackupRequest, OrsBackupSnapshot, OrsBackupSourceIdentity, PerEntryOutcome, RowDisposition,
    RowFamilyDisposition, RowFamilyKind, StoredEffectClass,
};
pub use cutover_ownership::{
    CapabilityRouteScope, CutoverAdmission, CutoverRouteEntry, CutoverRouteSnapshot,
    CutoverRouteTable, GenerationCutoverOwnership, GenerationCutoverOwnershipReceipt,
    InFlightDisposition, InFlightDispositionKind, MAX_CUTOVER_IN_FLIGHT,
    MAX_CUTOVER_UNRESOLVED_SCOPES, ModuleArtifactIdentity, StateMigrationDecision,
};
pub use doctor::*;
pub use model::ProviderCapabilityLookup;
pub use model::*;
pub use process_stream_recovery::{
    MAX_STREAM_RECOVERY_GAPS, MAX_STREAM_RECOVERY_OMITTED_RANGES,
    ProcessStreamRecoveryBinding, ProcessStreamRecoveryFence, ProcessStreamRecoveryLoadError,
    ProcessStreamRecoveryProjection, ProcessStreamRecoveryRefusal,
    ProcessStreamRecoveryRevalidation, ProcessStreamRecoveryWriteOutcome,
    ProcessStreamRetirementProof, ProcessStreamSourceReadback, ProcessStreamSourceResolution,
    ProcessStreamSourceResolver, StreamRecoveryActivation, StreamRecoveryAvailability,
    StreamRecoveryCoverage, StreamRecoveryEvidenceScope, StreamRecoveryPreview, StreamRecoveryRange,
    StreamRecoveryReconciliation, StreamRecoveryReconciliationState, StreamRecoverySourceFault,
};
pub use reservation_model::{
    ReservationRecord, ReservationRequest, ReservationState, ReservedScope,
    ScopeReservationRequest, WriterReservationToken,
};
pub use restore_journal::{
    JournalPredecessor, MAX_JOURNAL_PAGE_ENTRIES, MAX_JOURNAL_PAYLOAD_BYTES,
    MAX_JOURNAL_STREAM_KEY_BYTES, MIN_RETAINED_RESOLVED_MEMBERS, RESTORE_JOURNAL_RECORD_SCHEMA,
    RESTORE_JOURNAL_SCHEMA_VERSION, RETENTION_RECLAIM_FROM_MEMBERS, RestoreJournalAppendReceipt,
    RestoreJournalArchiveClass, RestoreJournalCompleteness, RestoreJournalEntry,
    RestoreJournalMemberDenominator, RestoreJournalOperation, RestoreJournalReadback,
    RestoreJournalReadbackRequest, RestoreJournalResult, RestoreJournalRetentionDisposition,
    RestoreJournalRetentionFrontier, RestoreJournalRetentionPolicy, RestoreJournalRetentionRecord,
    RestoreJournalRetentionReport, RestoreJournalStreamBinding,
};
pub use snapshot_model::{OrsSnapshotReceipt, OrsSnapshotRequest};
pub use status::{
    observe_supervision_status, open_existing_read_only, read_current_supervision_lease_read_only,
};
pub use status_projection::{
    OrsSupervisionStatusError, ProcessStreamRecoveryStatusProjection,
    SupervisionStatusProjection, SupervisionStatusReason,
};
pub use store::{
    CanonicalEvidenceProvider, OperationalRecoveryStore, OrsCoordinator, RedbRecoveryStore,
};
pub use versioned_artifact::{
    ArtifactGenerationState, CompatibilityEvidence, VersionedArtifact,
    VersionedArtifactCutoverRecord, VersionedArtifactRegistry, VersionedArtifactRetirement,
    VersionedArtifactStatus,
};

/// Stable wire/storage contract version for this crate.
pub const CONTRACT_VERSION: u16 = 1;
/// Hard ceiling for one recovery page.
pub const MAX_RECOVERY_PAGE: u16 = 256;
/// Hard ceiling for one worker-replay suffix page and for the retained
/// terminal-event window (T9-03 owner-backed replay).
///
/// Mirrors the [`MAX_RECOVERY_PAGE`] precedent: a replay suffix longer than
/// this bound is rejected with [`OrsError::ProjectionLimitExceeded`] instead
/// of being silently truncated, and retention pruning keeps at most this many
/// terminally-acknowledged newest events.
pub const MAX_REPLAY_PAGE: u16 = 256;
/// Hard ceiling for one operation's retained process-evidence history.
pub const MAX_PROCESS_EVIDENCE_READBACK: u16 = 256;
/// Hard ceiling for ciphertext held inline by one ORS record.
pub const MAX_INLINE_RECOVERY_BYTES: u64 = 4 * 1024 * 1024;
/// Hard ceiling for one detached inbox signature.
pub const MAX_INBOX_SIGNATURE_BYTES: usize = 64 * 1024;

#[cfg(test)]
mod tests;
