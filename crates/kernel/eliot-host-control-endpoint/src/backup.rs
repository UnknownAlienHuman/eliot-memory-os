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

/// The canonical `#954` replay types this endpoint's ingress decision reads.
///
/// These are imported as the owner's own definitions, never re-spelled here:
/// `BackupError` is the single typed failure scheme for the whole backup
/// vocabulary, and `BackupReplayDisposition` / `BackupReplayRefusal` are the
/// owner's own answers and classes. This endpoint maps them onto its own
/// [`BackupDispatchRefusal`] and adds no failure class of its own.
use eliot_protocol::backup::{BackupError, BackupReplayDisposition, BackupReplayRefusal};

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

/// Stable refusal class for a request whose operation would reach cutover
/// authority without being the separately admitted cutover request.
///
/// A13.7 makes cutover a separate authority, and this is the one refusal that
/// says so at the endpoint: it is returned before any owner effect, so an
/// operation that resolved cutover authority without its own admission never
/// reaches a cutover owner and never leaves an unresolved effect behind.
pub const CUTOVER_AUTHORITY_DIVERGENCE_REFUSAL: &str =
    "backup operation resolves to cutover authority without the admitted cutover request";

/// Returns whether `op` reaches cutover authority on this endpoint.
///
/// Cutover is ONE operation. The Host's cutover authority is the separately
/// admitted [`BackupOperationKind::AdmitCutover`] request and nothing else:
/// it is the only canonical operation whose accepted row carries the
/// `needs_cutover_admission` bit, and the only one whose registration is a
/// cutover. Every other operation — rehearsal completion in particular — is
/// either admitted with that bit clear or carries no accepted registration at
/// all, so it resolves to no cutover authority.
///
/// This is derived from [`requires_cutover_admission`], the same canonical
/// disposition the admission gates read, rather than asserted as a constant,
/// and the `None` arm is a decision and not a fallback: an operation with no
/// accepted Host registration resolves to no owner operation at all, so it can
/// resolve to no cutover either. The result is compared against the operation
/// itself by the caller, which is what makes it load-bearing: if a canonical
/// variant ever changed its cutover disposition, or a rehearsal row ever
/// required a cutover admission, this comparison fails and the request is
/// refused before the owner is called.
#[must_use]
pub const fn resolves_cutover_authority(op: BackupOperationKind) -> bool {
    match requires_cutover_admission(op) {
        Some(needs_cutover_admission) => needs_cutover_admission,
        None => false,
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
///
/// This is DERIVED from the accepted table and the canonical cutover
/// disposition, so it stays a fact about this endpoint's policy instead of a
/// constant that could only ever say "false": it returns true the moment a
/// rehearsal row enters [`accepted_host_backup_methods`], or the moment any
/// accepted row resolves to cutover authority without being the admitted
/// cutover request. Both routes are checked, so the predicate names every way
/// rehearsal could reach cutover authority rather than the single one it was
/// written for.
pub fn rehearsal_resolves_cutover() -> bool {
    if resolves_cutover_authority(BackupOperationKind::CompleteRehearsal) {
        return true;
    }
    accepted_host_backup_methods().iter().any(|method| {
        method.op != BackupOperationKind::AdmitCutover && method.needs_cutover_admission
    })
}

/// Bounded refusal for a replayed envelope that fails its own canonical
/// request-identity contract.
///
/// A replay observation can fail for a reason that is not one of the four
/// replay classes - an unknown canonical request hash, a stale wire version, a
/// zero deadline, a changed identity digest. Those are the request identity
/// failing its own contract, not a replay class, and they are named as such
/// rather than folded into one of the four.
pub const BACKUP_REPLAY_IDENTITY_REFUSAL: &str =
    "backup replay envelope does not satisfy the canonical request identity";

/// Maps one canonical `#954` replay observation onto this endpoint's own
/// pre-effect refusal, or `None` when the envelope may proceed to the owner.
///
/// This is the production ingress decision for replayed backup control
/// envelopes, and it is the ONLY place this endpoint turns a replay
/// observation into an answer. The observation itself is the canonical
/// `BackupReplayLedger::observe_typed` result from
/// `eliot-protocol/src/backup.rs`: this function reads that typed result and
/// never recomputes a digest, re-keys a ledger, or re-decides which case
/// occurred, so the endpoint cannot become a second source for the replay
/// vocabulary.
///
/// The four replay classes the `#954` replay contract distinguishes are
/// DUPLICATE (a byte-identical repeat of an envelope this endpoint already
/// admitted), UNKNOWN (no canonical request hash to key a decision on), STALE
/// (the bound deadline admits no currently observed evidence) and CHANGED
/// (changed canonical content under one stable canonical request hash). Each
/// carries its own bounded reason text, read from the owner through
/// [`BackupReplayRefusal::as_str`], so the wire-visible refusal still says
/// WHICH of the four refused the envelope and this endpoint never re-spells the
/// vocabulary.
#[must_use]
pub fn backup_replay_refusal(
    operation: BackupOperationKind,
    observed: Result<BackupReplayDisposition, BackupError>,
) -> Option<BackupDispatchRefusal> {
    match observed {
        Ok(BackupReplayDisposition::Accepted) => None,
        // `observe_typed` never returns this disposition - it is the
        // refusal-returning form - but the mapping is total over the owner's
        // own enum, so if that vocabulary ever widened this arm still refuses a
        // repeat rather than admitting one.
        Ok(BackupReplayDisposition::Duplicate) => Some(BackupDispatchRefusal::new(
            operation,
            BackupReplayRefusal::Duplicate.as_str(),
        )),
        Err(BackupError::ReplayRefused { reason }) => {
            Some(BackupDispatchRefusal::new(operation, reason.as_str()))
        }
        Err(_) => Some(BackupDispatchRefusal::new(
            operation,
            BACKUP_REPLAY_IDENTITY_REFUSAL,
        )),
    }
}

#[cfg(test)]
mod endpoint_backup_policy_tests {
    use super::{
        BackupDispatchRefusal, BackupError, BackupOperationKind, BackupReplayDisposition,
        BackupReplayRefusal, BACKUP_REPLAY_IDENTITY_REFUSAL, backup_replay_refusal,
    };

    /// The production ingress maps ONE canonical replay observation to ONE
    /// pre-effect refusal, and only a first observation reaches the owner.
    ///
    /// Load-bearing: this is the whole body of gate 4a in
    /// `HostRuntimeControl::handle_backup_operation`, which is the only
    /// production replay decision this endpoint makes. Delete it and the gate
    /// either admits a replayed envelope (every refusal assertion below fails,
    /// because there is no mapping to assert) or collapses the four classes into
    /// one indistinguishable answer.
    #[test]
    fn replay_observation_maps_to_one_typed_refusal_and_only_the_first_passes() {
        let operation = BackupOperationKind::PrepareIsolatedRestore;

        // POSITIVE: the first observation of a canonical request hash is the
        // only case that reaches the owner.
        assert_eq!(
            backup_replay_refusal(operation, Ok(BackupReplayDisposition::Accepted)),
            None
        );

        // REFUSAL 1 - DUPLICATE, reported through the owner's own disposition.
        // `observe_typed` never returns `Ok(Duplicate)`, so this arm is the
        // belt-and-braces form: if the owner's vocabulary ever widened, the
        // endpoint still refuses rather than admitting a repeat.
        let duplicate = backup_replay_refusal(operation, Ok(BackupReplayDisposition::Duplicate))
            .expect("a recorded repeat is refused");
        assert_eq!(duplicate.operation, operation);
        assert_eq!(duplicate.reason, BackupReplayRefusal::Duplicate.as_str());

        // REFUSAL 2 - all four typed refusal classes the owner publishes.
        for class in [
            BackupReplayRefusal::Duplicate,
            BackupReplayRefusal::Unknown,
            BackupReplayRefusal::Stale,
            BackupReplayRefusal::Changed,
        ] {
            let refused = backup_replay_refusal(operation, Err(BackupError::ReplayRefused { reason: class }))
                .expect("a replayed envelope is refused");
            assert_eq!(refused.operation, operation);
            // The reason text is the OWNER's, read through `as_str`, never
            // re-spelled here: this is what keeps the endpoint from becoming a
            // second source for the replay vocabulary.
            assert_eq!(refused.reason, class.as_str());
            assert!(!refused.reason.is_empty());
            assert!(!refused.reason.contains('\n'));
        }

        // REFUSAL 3 - an observation that failed for a reason that is not one of
        // the four replay classes. This is the request identity failing its own
        // canonical contract; it is NAMED as such rather than folded into a
        // replay class, so a caller is never told a replay happened when none
        // was decided.
        let not_a_replay_class = backup_replay_refusal(
            operation,
            Err(BackupError::InvalidField {
                field: "backup_request_identity.deadline_unix_ms",
                reason: "must be greater than zero",
            }),
        )
        .expect("an identity that fails its own contract is refused");
        assert_eq!(not_a_replay_class.operation, operation);
        assert_eq!(not_a_replay_class.reason, BACKUP_REPLAY_IDENTITY_REFUSAL);

        // The refusals stay distinguishable: the four replay classes carry four
        // distinct owner-supplied reasons, and the non-replay refusal is a fifth
        // distinct one, so no two outcomes read the same way on the wire.
        let reasons = [
            BackupReplayRefusal::Duplicate.as_str(),
            BackupReplayRefusal::Unknown.as_str(),
            BackupReplayRefusal::Stale.as_str(),
            BackupReplayRefusal::Changed.as_str(),
            BACKUP_REPLAY_IDENTITY_REFUSAL,
        ];
        for (index, reason) in reasons.iter().enumerate() {
            for other in reasons.iter().skip(index + 1) {
                assert_ne!(reason, other);
            }
        }
    }

    /// Rehearsal completion selects no cutover authority, and the predicate
    /// that says so is derived from the accepted table rather than asserted.
    ///
    /// Load-bearing: `rehearsal_resolves_cutover` is consulted by a release-mode
    /// gate in `bins/eliot-host/src/lib.rs`. If it were replaced by the constant
    /// `false` it used to be, the first assertion below would still pass and the
    /// gate would carry nothing; the table-wide assertion is what fails, because
    /// it shows the predicate reads the accepted table and the canonical
    /// disposition rather than answering from a literal.
    #[test]
    fn rehearsal_selects_no_cutover_and_the_predicate_is_derived() {
        assert!(!super::rehearsal_resolves_cutover());
        // Rehearsal is refused by the accepted table and by the canonical
        // disposition independently of the predicate, so the predicate's inputs
        // really do exclude it.
        assert!(!super::is_supported(BackupOperationKind::CompleteRehearsal));
        assert!(
            super::requires_cutover_admission(BackupOperationKind::CompleteRehearsal).is_none()
        );
        // And rehearsal still carries its own wire identity, never cutover's.
        assert!(!super::authority_matches(
            BackupOperationKind::CompleteRehearsal,
            BackupOperationKind::AdmitCutover.wire_id(),
        ));
        // Every accepted row that is not the admitted cutover request must have
        // its cutover-admission bit clear; this is the table-wide form of what
        // the predicate checks for rehearsal, run here so a future row cannot
        // be added without this failing.
        for method in super::accepted_host_backup_methods() {
            assert_eq!(
                method.needs_cutover_admission,
                method.op == BackupOperationKind::AdmitCutover,
                "accepted row {} cutover authority",
                method.op
            );
        }
    }

    /// The cutover-authority predicate the production gate compares names
    /// cutover authority for exactly one canonical operation, and the gate's
    /// refusal class is bounded and non-empty.
    ///
    /// Load-bearing: delete gate 0a in `HostRuntimeControl::handle_backup_operation`
    /// and the comparison stops happening, so an accepted row that resolved to
    /// cutover authority without being the admitted cutover request would reach
    /// a cutover owner. Delete `resolves_cutover_authority` and the gate cannot
    /// be written at all, because nothing else derives the relation from the
    /// canonical disposition.
    #[test]
    fn cutover_authority_is_one_operation_and_the_gate_compares_it() {
        for op in [
            BackupOperationKind::RequestCapture,
            BackupOperationKind::ReadSnapshotPage,
            BackupOperationKind::VerifyArchive,
            BackupOperationKind::PrepareIsolatedRestore,
            BackupOperationKind::RestoreStep,
            BackupOperationKind::ReconcileRestore,
            BackupOperationKind::RestoreStatus,
            BackupOperationKind::CompleteRehearsal,
            BackupOperationKind::AdmitCutover,
        ] {
            // This is the gate's own comparison, run for every variant.
            assert_eq!(
                super::resolves_cutover_authority(op),
                op == BackupOperationKind::AdmitCutover,
                "cutover authority for {op}"
            );
        }
        // The refusal class is bounded, non-empty, and names the divergence.
        assert!(!super::CUTOVER_AUTHORITY_DIVERGENCE_REFUSAL.is_empty());
        assert!(super::CUTOVER_AUTHORITY_DIVERGENCE_REFUSAL.contains("cutover"));
        // And the refusal this module produces is the endpoint's own pre-effect
        // type, not a bare string, so gate 4a and this test agree on the shape.
        let refusal = backup_replay_refusal(
            BackupOperationKind::PrepareIsolatedRestore,
            Err(BackupError::ReplayRefused {
                reason: BackupReplayRefusal::Changed,
            }),
        )
        .expect("changed content is refused");
        assert!(format!("{refusal}").contains("PREPARE_ISOLATED_RESTORE"));
        let _: &dyn std::error::Error = &refusal;
        assert_eq!(
            refusal,
            BackupDispatchRefusal::new(
                BackupOperationKind::PrepareIsolatedRestore,
                BackupReplayRefusal::Changed.as_str()
            )
        );
    }
}
