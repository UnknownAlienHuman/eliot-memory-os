//! Host-accepted backup owner-method registration table.
//!
//! This module owns only the accepted owner-method table for the Host
//! runtime-control endpoint: which backup operations the Host serves and
//! which of those require a separate cutover admission. It performs no
//! ACL/auth/transport work, opens no pipe, touches no database, and
//! imports no binary crate.
//!
//! The wire contract and request/response envelope remain owned by the
//! canonical `#954` vocabulary (`eliot-protocol/src/backup.rs`) and the
//! envelope mapping owned alongside `runtime_control.rs`. The operation
//! names and wire-ID strings below are pinned copies of those canonical
//! values, not a new operation family and not a new pipe family.

/// Closed backup operation vocabulary, pinned by value to the canonical
/// `#954` `BackupOperationKind` (`eliot-protocol/src/backup.rs`).
///
/// Kept local because this cell takes no new Cargo dependency; variant
/// names, `as_str` spellings, and `wire_id` strings must match the
/// canonical vocabulary exactly.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackupOperationKind {
    RequestCapture,
    ReadSnapshotPage,
    VerifyArchive,
    PrepareIsolatedRestore,
    RestoreStep,
    ReconcileRestore,
    RestoreStatus,
    CompleteRehearsal,
    AdmitCutover,
}

impl BackupOperationKind {
    /// Returns the stable wire name of this operation, pinned to `#954`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestCapture => "REQUEST_CAPTURE",
            Self::ReadSnapshotPage => "READ_SNAPSHOT_PAGE",
            Self::VerifyArchive => "VERIFY_ARCHIVE",
            Self::PrepareIsolatedRestore => "PREPARE_ISOLATED_RESTORE",
            Self::RestoreStep => "RESTORE_STEP",
            Self::ReconcileRestore => "RECONCILE_RESTORE",
            Self::RestoreStatus => "RESTORE_STATUS",
            Self::CompleteRehearsal => "COMPLETE_REHEARSAL",
            Self::AdmitCutover => "ADMIT_CUTOVER",
        }
    }

    /// Returns the stable wire ID of this operation, pinned to `#954`.
    #[must_use]
    pub const fn wire_id(self) -> &'static str {
        match self {
            Self::RequestCapture => "eliot.protocol.backup.capture-request",
            Self::ReadSnapshotPage => "eliot.protocol.backup.snapshot-page-read",
            Self::VerifyArchive => "eliot.protocol.backup.archive-verification",
            Self::PrepareIsolatedRestore => "eliot.protocol.backup.isolated-restore-prepare",
            Self::RestoreStep => "eliot.protocol.backup.restore-step",
            Self::ReconcileRestore => "eliot.protocol.backup.restore-reconcile",
            Self::RestoreStatus => "eliot.protocol.backup.restore-status",
            Self::CompleteRehearsal => "eliot.protocol.backup.rehearsal-complete",
            Self::AdmitCutover => "eliot.protocol.backup.cutover-admission",
        }
    }
}

/// One Host-accepted backup owner method.
///
/// `wire_id` is the canonical `#954` wire ID for `op`; a payload claim
/// can never override it (see [`authority_matches`]).
/// `needs_cutover_admission` is true only for methods that require a
/// separate installation-authority cutover admission before effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedOwnerMethod {
    pub op: BackupOperationKind,
    pub wire_id: &'static str,
    pub needs_cutover_admission: bool,
}

/// Host-supported subset only: isolated-restore preparation, separately
/// admitted cutover, and restore status/reconciliation reads. Capture
/// operations (`RequestCapture`, `ReadSnapshotPage`, `VerifyArchive`),
/// owner phase steps (`RestoreStep`), and rehearsal completion
/// (`CompleteRehearsal`) are not owned by the Host and are excluded.
const ACCEPTED_HOST_BACKUP_METHODS: &[AcceptedOwnerMethod] = &[
    AcceptedOwnerMethod {
        op: BackupOperationKind::PrepareIsolatedRestore,
        wire_id: "eliot.protocol.backup.isolated-restore-prepare",
        needs_cutover_admission: false,
    },
    AcceptedOwnerMethod {
        op: BackupOperationKind::AdmitCutover,
        wire_id: "eliot.protocol.backup.cutover-admission",
        needs_cutover_admission: true,
    },
    AcceptedOwnerMethod {
        op: BackupOperationKind::RestoreStatus,
        wire_id: "eliot.protocol.backup.restore-status",
        needs_cutover_admission: false,
    },
    AcceptedOwnerMethod {
        op: BackupOperationKind::ReconcileRestore,
        wire_id: "eliot.protocol.backup.restore-reconcile",
        needs_cutover_admission: false,
    },
];

/// Returns the Host-supported backup owner-method table.
#[must_use]
pub const fn accepted_host_backup_methods() -> &'static [AcceptedOwnerMethod] {
    ACCEPTED_HOST_BACKUP_METHODS
}

/// Alias for the Host-supported backup owner-method table.
#[must_use]
pub const fn register_backup_methods() -> &'static [AcceptedOwnerMethod] {
    ACCEPTED_HOST_BACKUP_METHODS
}

/// Returns whether the Host serves `op`. Unsupported operations fail
/// before effects; see [`requires_cutover_admission`].
#[must_use]
pub const fn is_supported(op: BackupOperationKind) -> bool {
    match op {
        BackupOperationKind::PrepareIsolatedRestore
        | BackupOperationKind::AdmitCutover
        | BackupOperationKind::RestoreStatus
        | BackupOperationKind::ReconcileRestore => true,
        BackupOperationKind::RequestCapture
        | BackupOperationKind::ReadSnapshotPage
        | BackupOperationKind::VerifyArchive
        | BackupOperationKind::RestoreStep
        | BackupOperationKind::CompleteRehearsal => false,
    }
}

/// Returns whether `op` requires a separate cutover admission, or `None`
/// when `op` is unsupported (unsupported fails before effects).
#[must_use]
pub const fn requires_cutover_admission(op: BackupOperationKind) -> Option<bool> {
    match op {
        BackupOperationKind::AdmitCutover => Some(true),
        BackupOperationKind::PrepareIsolatedRestore
        | BackupOperationKind::RestoreStatus
        | BackupOperationKind::ReconcileRestore => Some(false),
        BackupOperationKind::RequestCapture
        | BackupOperationKind::ReadSnapshotPage
        | BackupOperationKind::VerifyArchive
        | BackupOperationKind::RestoreStep
        | BackupOperationKind::CompleteRehearsal => None,
    }
}

/// Returns whether a payload-claimed wire ID matches the authenticated
/// operation's canonical wire ID. The payload can never override the
/// authenticated operation: only exact equality passes.
#[must_use]
pub const fn authority_matches(
    authenticated_op: BackupOperationKind,
    payload_claimed_wire_id: &str,
) -> bool {
    let expected = authenticated_op.wire_id().as_bytes();
    let claimed = payload_claimed_wire_id.as_bytes();
    if expected.len() != claimed.len() {
        return false;
    }
    let mut index = 0;
    while index < expected.len() {
        if expected[index] != claimed[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Rehearsal (`CompleteRehearsal`) never resolves to cutover admission:
/// it is excluded from the accepted table and carries a distinct wire ID.
/// Always returns false; the debug assertions pin the exclusion.
pub fn rehearsal_resolves_cutover() -> bool {
    debug_assert!(!is_supported(BackupOperationKind::CompleteRehearsal));
    debug_assert!(requires_cutover_admission(BackupOperationKind::CompleteRehearsal).is_none());
    debug_assert!(!authority_matches(
        BackupOperationKind::CompleteRehearsal,
        BackupOperationKind::AdmitCutover.wire_id(),
    ));
    false
}
