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
//! envelope mapping owned alongside `runtime_control.rs`. This module
//! consumes that vocabulary instead of restating it: the operation family,
//! its `as_str()` spellings and its operation-to-wire identities are used
//! from their single owner, so this registration table cannot drift into a
//! second operation family or a second pipe family.

/// The closed backup operation vocabulary, consumed from its canonical
/// `#954` owner (`eliot-protocol/src/backup.rs`).
///
/// This cell takes a direct `eliot-protocol` dependency precisely so the
/// operation names and wire identities are never pinned copies: variant
/// names, `as_str()` spellings and [`BackupOperationKind::wire_id`] are the
/// owner's own definitions, and a new canonical variant becomes a compile
/// error here until this registration table has reviewed it.
pub use eliot_protocol::backup::BackupOperationKind;

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

impl AcceptedOwnerMethod {
    /// Binds one accepted operation to its canonical wire identity.
    ///
    /// The wire identity is always [`BackupOperationKind::wire_id`] of `op`,
    /// so a registered row can never carry a copied or drifted literal.
    const fn new(op: BackupOperationKind, needs_cutover_admission: bool) -> Self {
        Self {
            op,
            wire_id: op.wire_id(),
            needs_cutover_admission,
        }
    }
}

/// Host-supported subset only: isolated-restore preparation, separately
/// admitted cutover, and restore status/reconciliation reads. Capture
/// operations (`RequestCapture`, `ReadSnapshotPage`, `VerifyArchive`),
/// owner phase steps (`RestoreStep`), and rehearsal completion
/// (`CompleteRehearsal`) are not owned by the Host and are excluded.
const ACCEPTED_HOST_BACKUP_METHODS: &[AcceptedOwnerMethod] = &[
    AcceptedOwnerMethod::new(BackupOperationKind::PrepareIsolatedRestore, false),
    AcceptedOwnerMethod::new(BackupOperationKind::AdmitCutover, true),
    AcceptedOwnerMethod::new(BackupOperationKind::RestoreStatus, false),
    AcceptedOwnerMethod::new(BackupOperationKind::ReconcileRestore, false),
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
