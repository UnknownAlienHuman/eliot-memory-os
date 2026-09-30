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

use std::sync::Arc;

use eliot_host_service::runtime_control::{BackupOwnerOutcome, BackupRuntimeControlRequest};

/// The closed backup operation vocabulary, consumed from its canonical
/// `#954` owner (`eliot-protocol/src/backup.rs`).
///
/// This cell takes a direct `eliot-protocol` dependency precisely so the
/// operation names and wire identities are never pinned copies: variant
/// names, `as_str()` spellings and [`BackupOperationKind::wire_id`] are the
/// owner's own definitions, and a new canonical variant becomes a compile
/// error here until this registration table has reviewed it.
pub use eliot_protocol::backup::{BackupOperationKind, BackupRole};

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
    /// Public so a composition registers its own owner operations with the
    /// same row type instead of a second table shape.
    #[must_use]
    pub const fn new(op: BackupOperationKind, needs_cutover_admission: bool) -> Self {
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

// ---------------------------------------------------------------------------
// Owner registration seam (#962).
//
// The endpoint owns only this seam: the closed accepted method table above
// decides admission, and the registered owner below performs the one owner
// operation an admitted request resolved to. Neither the seam nor the owner
// opens a pipe, decodes a frame, authenticates a peer, or admits authority;
// those stay with the endpoint transport and the composition that owns the
// effect. An absent owner is a fail-closed refusal, never a no-op success.
// ---------------------------------------------------------------------------

/// Bounded, redacted **pre-effect** refusal of one admitted backup control
/// request.
///
/// The refusal names the operation it applies to and a stable reason class.
/// It carries no payload text, no owner internals and no secret, and it is
/// produced *before any owner effect*, so a refused request can never be
/// answered with a success frame and never leaves an unresolved effect
/// behind.
///
/// This type is therefore not a general failure channel for the owner
/// callback. An owner that has already crossed an effect boundary and cannot
/// say whether the effect committed must return
/// [`BackupOwnerOutcome::PossibleEffect`] instead of a refusal: I14.21 keeps
/// such an operation reconciling, and a refusal would falsely report that no
/// effect happened. The endpoint's own admission gates, which all run before
/// the owner is called, keep returning this type unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupDispatchRefusal {
    /// The operation whose request was refused.
    pub operation: BackupOperationKind,
    /// Stable bounded refusal class.
    pub reason: &'static str,
}

impl BackupDispatchRefusal {
    /// Binds one refusal to its operation and reason class.
    #[must_use]
    pub const fn new(operation: BackupOperationKind, reason: &'static str) -> Self {
        Self { operation, reason }
    }
}

impl std::fmt::Display for BackupDispatchRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "backup {} refused: {}",
            self.operation, self.reason
        )
    }
}

impl std::error::Error for BackupDispatchRefusal {}

/// The registered Host backup owner for the canonical Host runtime-control
/// pipe.
///
/// One admitted request routes to exactly one owner operation, and the owner
/// answers with the outcome that operation actually reached. The four states
/// stay distinct across the seam and are never collapsed into one:
///
/// - **pre-effect rejection** — [`BackupDispatchRefusal`], produced before
///   the owner did anything, so no effect is outstanding;
/// - **admitted / pending** — [`BackupOwnerOutcome::Admitted`], the exact
///   operation is retained and still running, with no stage claimed and no
///   receipt issued;
/// - **completed owner result** — [`BackupOwnerOutcome::Completed`], the
///   owner performed the operation and issued its own phase attestation,
///   optionally with the prepared destination as a bounded immutable handle;
/// - **possible-effect / unknown** — [`BackupOwnerOutcome::PossibleEffect`],
///   the operation is retained but the effect may or may not have committed,
///   so the original operation is reconciled instead of retried.
///
/// The endpoint never reports a transport acknowledgement as backup semantic
/// success: only the owner's own outcome reaches the wire, and it is
/// re-validated against the admitted request before delivery.
pub trait HostBackupOwner: Send + Sync {
    /// Performs the one owner operation the closed accepted table and the
    /// registered dispatch resolved for `request`, and reports the outcome
    /// that operation reached.
    ///
    /// # Errors
    ///
    /// Returns [`BackupDispatchRefusal`] only when the request was refused
    /// **before** any owner effect: this owner has no operation for it, the
    /// request lacks the separate admission its operation requires, or
    /// admission of the exact operation failed closed. Once an effect may
    /// have happened, the owner must return
    /// [`BackupOwnerOutcome::PossibleEffect`] with the retained operation
    /// instead, so the outcome remains reconciling.
    fn dispatch_backup_operation(
        &self,
        request: &BackupRuntimeControlRequest,
    ) -> Result<BackupOwnerOutcome, BackupDispatchRefusal>;
}

/// The registered backup owner together with the exact closed dispatch table
/// the composition admitted for it.
///
/// `methods` is the composition's own accepted prepare/cutover table, in the
/// same [`AcceptedOwnerMethod`] shape as
/// [`accepted_host_backup_methods`]. It is the registration: an operation
/// the endpoint accepts but this table does not carry has no owner operation
/// and fails before effects, so the endpoint's broader accepted table can
/// never route a status or reconcile read into a preparation or cutover
/// effect.
pub struct HostBackupOwnerRegistration {
    methods: &'static [AcceptedOwnerMethod],
    owner: Arc<dyn HostBackupOwner>,
}

impl HostBackupOwnerRegistration {
    /// Binds one closed dispatch table to its owner. The table is the
    /// registration; the owner is only reachable through it.
    #[must_use]
    pub const fn new(
        methods: &'static [AcceptedOwnerMethod],
        owner: Arc<dyn HostBackupOwner>,
    ) -> Self {
        Self { methods, owner }
    }

    /// Returns the exact closed dispatch table registered for this owner.
    #[must_use]
    pub const fn methods(&self) -> &'static [AcceptedOwnerMethod] {
        self.methods
    }

    /// Returns the registered row for `op`, or `None` when this owner has no
    /// operation for it.
    #[must_use]
    pub fn registered_method(
        &self,
        op: BackupOperationKind,
    ) -> Option<&'static AcceptedOwnerMethod> {
        self.methods.iter().find(|method| method.op == op)
    }

    /// Routes one already-admitted request to the registered owner.
    ///
    /// The owner's outcome is returned unchanged. It is not flattened into a
    /// success, and a pre-effect refusal is not confused with an outcome
    /// whose effect is merely unknown.
    ///
    /// # Errors
    ///
    /// Returns the owner's pre-effect [`BackupDispatchRefusal`] unchanged.
    pub fn dispatch(
        &self,
        request: &BackupRuntimeControlRequest,
    ) -> Result<BackupOwnerOutcome, BackupDispatchRefusal> {
        self.owner.dispatch_backup_operation(request)
    }
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
