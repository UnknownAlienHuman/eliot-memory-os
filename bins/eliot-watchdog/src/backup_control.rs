//! Authenticated Watchdog backup owner channel and its bounded request dispatch.
//!
//! Responsibility: bind the closed Watchdog backup method table to the
//! owner-bound [`WatchdogBackupPort`] that the composition reaches through its
//! own kernel port, admit exactly one request per operation against a
//! non-caller-constructible authenticated context, run that operation against
//! the exact owner that holds it, and retain the owner's own result so a
//! repeated or reconnected presentation of the same operation reconciles
//! instead of taking a second effect. No pipe is opened, no ACL or transport is
//! implemented, no archive bytes are interpreted, no authority is minted, and no
//! domain algorithm runs here. All spool effects belong to the owning spool
//! port; this module only admits, routes, and retains.
//!
//! The authenticated context ([`WatchdogBackupAdmission`]) is the answer to the
//! defect that a method table cannot authenticate itself. It is built by
//! [`register_backup_control`] and re-observed by [`start_backup_control`] from
//! the composition's own retained readiness identity and from the live owner
//! port's retained installation identity and generation. It has no public
//! constructor, so a caller cannot supply the values it is later compared
//! against, and every comparison in [`BackupControlHandle::admit`] is against
//! those owner-held values or against the `#954` owner's own tables — never
//! against a value carried in the presented request.
//!
//! Supported subset (closed, four operations, explicitly reviewed here):
//! `READ_SNAPSHOT_PAGE`, `VERIFY_ARCHIVE`, `RESTORE_STATUS` and
//! `RECONCILE_RESTORE`. That narrowing is THIS endpoint's own reviewed request
//! shape and dispatch policy. It is deliberately not derived from the `#954`
//! role and attester matrix: that matrix is a necessary authority check, applied
//! separately to each admitted request, and it never generates concrete endpoint
//! membership.
//!
//! Two of the four are executable owner contours, over the owners this process
//! actually holds. `READ_SNAPSHOT_PAGE` reaches the `#955` spool capture owner
//! ([`WatchdogBackupPort::snapshot`]) and then reads the requested page from the
//! fence that owner retained. `RECONCILE_RESTORE` reaches the isolated-restore
//! owner ([`WatchdogBackupPort::import_isolated`]) against an externally
//! admitted isolated destination, with every presented step bound to this
//! operation's own stable mutation identity.
//!
//! `VERIFY_ARCHIVE` and `RESTORE_STATUS` are recognized so an absent method
//! fails with an explicit typed refusal instead of vanishing, and are refused
//! before any owner effect: Watchdog owns no archive verifier and no
//! restore-status projection. `RESTORE_STEP`, `REQUEST_CAPTURE`,
//! `PREPARE_ISOLATED_RESTORE`, `COMPLETE_REHEARSAL` and `ADMIT_CUTOVER` are
//! never registered here: preparation and cutover are the Host owner's
//! separately admitted operations, and rehearsal completion never maps to
//! cutover.
//!
//! Typed ingress: each of those four operations has its own typed request on
//! this endpoint's closed ingress surface (`WatchdogBackupRequest`), each
//! carrying its own canonical `#954` request type and validated by that type's
//! own contract check. No operation is reachable by re-typing another
//! operation's request shape, and a new canonical operation forces a reviewed
//! arm in the executable-policy match instead of silently widening this set.
//!
//! Capture and preparation are therefore two separately admitted operations
//! reaching two different owners, and are never merged into one admission.
//!
//! Before-send versus possible-effect-after-send: an admission refusal happens
//! before the owner is entered, so no effect exists and a retry is safe. Once
//! the owner has been entered for an operation, that operation is retained
//! before the owner's answer is known, so an owner failure leaves the operation
//! retained as unresolved and possible-effected; a repeated presentation
//! reconciles against that record and never re-enters the owner. There is no
//! blind retry of a possible effect and no eviction of a retained record.
//!
//! Supervision priority: this channel holds no supervision task, never runs on
//! the heartbeat tick, and spends a bounded composition-scoped work budget: one
//! bounded retained-operation table that refuses rather than grows.
//!
//! Production lifecycle: the Watchdog's own startup path registers, starts, and
//! stops this channel, and the canonical signals listener is started from the
//! same started handle and stopped with it. Registration binds the
//! composition's real owner spool and proves that owner resource is live by
//! reading its own durable high-water sequence; start re-reads it and
//! re-observes the authenticated context as a second, independent observation;
//! stop releases the bounded registration slot and reports the operations this
//! composition still holds unresolved. A refusal at either step is bounded to
//! this one capability: it is typed, it happens on a path where readiness is
//! already published, and the process creates no listener, task, slot, or
//! authority on either side of it.
//!
//! The transport peer is proved by the OS, not by this module. The canonical
//! signals server module binds `EliotPipeName::watchdog_signals` through the
//! existing `eliot-ipc` server, which authenticates the connected client from the
//! live pipe handle — impersonated token, SID, session id, and process image with
//! its no-follow file identity — against an expectation pinned to the
//! installer-approved Kernel image, and refuses before a single frame is read when
//! that proof does not hold. Only an authenticated frame from such a peer reaches
//! this handle, so the gates below compare each request against this composition's
//! retained admission state and against the `#954` owner's own tables, and never
//! against a peer identity the request itself carried.
//!
//! Lifecycle scope: the bounded registration table belongs to ONE composition
//! lifecycle and is opened when that composition starts. Starting supervision
//! never closes it, only that same composition's own shutdown does, and a
//! second composition in the same process opens its own open table — so
//! supervision start can never latch backup control closed for the remaining
//! life of the process. The retained-operation table is scoped the same way: a
//! reconnecting requester in one composition reconciles against that
//! composition's retained owner results, and a fresh composition starts empty
//! rather than inheriting another lifecycle's records.
//!
//! What the retained table is NOT: it is not the recovery authority after a
//! restart. It is process memory and dies with the composition, so a restarted
//! owner cannot consult it and must not pretend it still exists. The durable
//! decision for `RECONCILE_RESTORE` is read by the owner itself from the admitted
//! destination installation's own retained spool records, and `READ_SNAPSHOT_PAGE`
//! is a pure owner read re-observed live from the owner's own `watchdog.redb`.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use thiserror::Error;

use eliot_protocol::backup::{
    BackupArchiveVerification, BackupError, BackupRequestIdentity, BackupRestoreReconcile,
    BackupRestoreStatus, BackupRole, BackupSnapshotPageRead, BackupStage, attesting_roles,
    operation_for_phase,
};

use crate::{
    AdmittedIsolatedDestination, CaptureFenceParams, CompositionError, PROTOCOL_VERSION,
    SERVICE_NAME, SpoolError, SpoolRestoreDisposition, SpoolRestoreStep, WatchdogBackupPort,
    WatchdogComposition, WatchdogRuntimeBinding, WatchdogSpoolBackupLimits, WatchdogSpoolFence,
    WatchdogSpoolSnapshotPage,
};

/// Upper bound for concurrently registered backup control handles per
/// composition lifecycle.
///
/// Registration is a bounded, composition-scoped slot table, not a listener
/// and not a task: the Watchdog opens no backup listener and spawns no backup
/// task, so the receipt names only the registration slot it occupies.
/// Registration fails closed past this bound instead of growing an unbounded
/// set. The bound is per composition lifecycle, not per process: each
/// composition opens its own table, so a second composition in the same
/// process is not refused by the first one's registrations.
pub const MAX_BACKUP_CONTROL_HANDLES: u64 = 8;

/// Upper bound for the operations one composition lifecycle retains.
///
/// The retained-operation table is what makes a repeated or reconnected
/// presentation of the same operation reconcile instead of taking a second
/// owner effect, so it refuses a new operation past this bound rather than
/// evicting an older record: an evicted record would make an operation that
/// already ran look never-run, which is exactly the duplicate effect this
/// table exists to prevent. There is no blind retry and no silent loss.
pub const MAX_RETAINED_BACKUP_OPERATIONS: usize = 64;

/// Reported unresolved-operation count when the composition's own bounded table
/// cannot be read at all.
///
/// A distinct sentinel rather than zero, because "the table was unreadable" and
/// "this composition ran no unresolved operation" are different facts and only
/// the second one is a clean shutdown.
const UNRESOLVED_COUNT_UNREADABLE: usize = usize::MAX;

/// Number of bounded registration slots, derived from the declared ceiling.
///
/// Declared as its own literal rather than a truncating cast of the `u64`
/// ceiling, and pinned equal to it by the compile-time assertion below, so the
/// array length and the public bound can never disagree.
const REGISTRATION_SLOT_COUNT: usize = 8;

const _: () = assert!(REGISTRATION_SLOT_COUNT as u64 == MAX_BACKUP_CONTROL_HANDLES);

/// Bounded registration state of exactly one composition lifecycle.
///
/// One `true` entry is one occupied slot. The state holds no authority, no
/// handle to a live resource, and no caller-supplied value: it exists so
/// a registration receipt names a real bounded allocation instead of a
/// constant, and so `stop_backup_control` and composition shutdown release
/// exactly what was taken.
#[derive(Debug)]
struct BackupControlSlots {
    /// Whether this composition lifecycle has closed backup control.
    closed: bool,
    /// Occupancy of this composition's bounded slot table.
    occupied: [bool; REGISTRATION_SLOT_COUNT],
    /// The owner results this composition lifecycle has retained, keyed by the
    /// admitted operation's own stable mutation binding.
    retained: BTreeMap<String, RetainedBackupOperation>,
}

/// One owner-retained operation of this composition lifecycle.
///
/// The record is written BEFORE the owner is entered, so a repeated or
/// reconnected presentation of the same operation finds it whatever happened
/// to the owner's answer. `outcome` is `None` exactly when the owner was
/// entered and its result is not known: that operation may have taken effect,
/// so it is never re-entered and is reported as unresolved at shutdown.
#[derive(Clone, Debug)]
struct RetainedBackupOperation {
    /// The operation this record was admitted for.
    operation: BackupOperationKind,
    /// The canonical identity digest the owner committed to for this
    /// operation. A repeat that presents a different digest under the same
    /// mutation binding is a conflict, not a new operation.
    identity_digest: String,
    /// The owner's own retained outcome, or `None` while it is unknown.
    outcome: Option<WatchdogBackupChannelOutcome>,
}

impl RetainedBackupOperation {
    /// Returns whether this operation was entered at the owner and its result
    /// is not known, so its effect is possible rather than absent.
    const fn is_unresolved(&self) -> bool {
        self.outcome.is_none()
    }
}

/// Composition-scoped backup control registration and retained-operation table.
///
/// The table belongs to one composition lifecycle, not to the process: a
/// composition opens exactly one of these at start, registration is therefore
/// open for that composition's whole supervised lifetime, and only that same
/// composition's [`close`](Self::close) closes it. Nothing on the
/// supervision-**start** path touches this cell, so starting supervision can
/// never latch backup control closed; one composition's shutdown cannot close
/// another composition's table; and a fresh composition in the same process
/// always starts open with an empty table instead of inheriting a latched
/// refusal from an earlier lifecycle.
///
/// The cell is cloned into every [`BackupControlHandle`], so a handle checks
/// and releases its own composition's bounded table and no other. It carries no
/// registration identity of its own: the composition that created it is the
/// only owner, which is what makes the scope exact rather than claimed.
#[derive(Clone, Debug)]
pub struct BackupControlRegistration {
    /// Bounded occupancy, lifecycle flag, and retained operations of one
    /// composition.
    slots: std::sync::Arc<Mutex<BackupControlSlots>>,
}

impl BackupControlRegistration {
    /// Opens an empty, open registration table for one composition lifecycle.
    #[must_use]
    pub fn open() -> Self {
        Self {
            slots: std::sync::Arc::new(Mutex::new(BackupControlSlots {
                closed: false,
                occupied: [false; REGISTRATION_SLOT_COUNT],
                retained: BTreeMap::new(),
            })),
        }
    }

    /// Closes backup control for this composition lifecycle.
    ///
    /// Every bounded slot of THIS table is released, so no registration
    /// outlives the composition and any later registration against this
    /// composition fails closed. Other compositions keep their own tables and
    /// stay open. Shutdown stays bounded: there is no task to join and this
    /// never blocks supervision teardown.
    ///
    /// The retained operations are deliberately NOT dropped here: they are the
    /// evidence this composition ran, and
    /// [`BackupControlHandle::unresolved_operations`] reads them after this
    /// call. Nothing can add another one, because every later reserve and
    /// retain is refused once the table is closed.
    pub fn close(&self) {
        if let Ok(mut slots) = self.slots.lock() {
            slots.closed = true;
            slots.occupied.fill(false);
        }
    }

    /// Reserves the lowest free bounded slot of this table, or fails closed.
    fn reserve(&self) -> Result<u64, CompositionError> {
        let mut slots = self.lock()?;
        if slots.closed {
            return Err(CompositionError::InvalidConfiguration(
                "watchdog backup control is closed for this composition lifecycle".to_owned(),
            ));
        }
        for (index, occupied) in slots.occupied.iter_mut().enumerate() {
            if !*occupied {
                *occupied = true;
                return u64::try_from(index + 1).map_err(|_| {
                    CompositionError::InvalidConfiguration(
                        "watchdog backup control slot index exceeds the bounded counter".to_owned(),
                    )
                });
            }
        }
        Err(CompositionError::InvalidConfiguration(
            "watchdog backup control exceeds its bounded registration table".to_owned(),
        ))
    }

    /// Returns whether one bounded slot of this table is reserved.
    fn is_registered(&self, slot: u64) -> bool {
        if slot == 0 || slot > MAX_BACKUP_CONTROL_HANDLES {
            return false;
        }
        let Ok(index) = usize::try_from(slot - 1) else {
            return false;
        };
        self.lock()
            .is_ok_and(|slots| slots.occupied.get(index).copied().unwrap_or(false))
    }

    /// Releases one bounded slot of this table; releasing a free slot is a no-op.
    fn release(&self, slot: u64) {
        let Ok(index) = usize::try_from(slot.saturating_sub(1)) else {
            return;
        };
        if let Ok(mut slots) = self.slots.lock()
            && let Some(occupied) = slots.occupied.get_mut(index)
        {
            *occupied = false;
        }
    }

    /// Locks this table's bounded state, failing closed on a poisoned lock.
    fn lock(&self) -> Result<MutexGuard<'_, BackupControlSlots>, CompositionError> {
        self.slots.lock().map_err(|_| {
            CompositionError::InvalidConfiguration(
                "watchdog backup control cannot read its bounded registration table".to_owned(),
            )
        })
    }

    /// Returns the operation this composition already retained under `binding`,
    /// or `None` when it has never run one.
    fn retained(&self, binding: &str) -> Result<Option<RetainedBackupOperation>, CompositionError> {
        Ok(self.lock()?.retained.get(binding).cloned())
    }

    /// Claims the admission of one operation under its own mutation binding.
    ///
    /// Refuses when the table is closed or when the bounded retained-operation
    /// table is full. It never replaces an existing record: an operation that
    /// already has one is reconciled against that record instead, so this
    /// cannot be used to re-enter an owner for an operation that already ran.
    fn claim(
        &self,
        binding: &str,
        operation: BackupOperationKind,
        digest: &str,
    ) -> Result<(), CompositionError> {
        let mut slots = self.lock()?;
        if slots.closed {
            return Err(CompositionError::InvalidConfiguration(
                "watchdog backup control is closed for this composition lifecycle".to_owned(),
            ));
        }
        if slots.retained.contains_key(binding) {
            return Err(CompositionError::InvalidConfiguration(
                "watchdog backup control cannot claim an operation it already retained".to_owned(),
            ));
        }
        if slots.retained.len() >= MAX_RETAINED_BACKUP_OPERATIONS {
            return Err(CompositionError::InvalidConfiguration(
                "watchdog backup control exceeds its bounded retained-operation table".to_owned(),
            ));
        }
        slots.retained.insert(
            binding.to_owned(),
            RetainedBackupOperation {
                operation,
                identity_digest: digest.to_owned(),
                outcome: None,
            },
        );
        Ok(())
    }

    /// Stores the owner's own result for an operation this composition already
    /// claimed. An operation claimed under a different canonical identity is
    /// left unresolved rather than overwritten.
    fn settle(
        &self,
        binding: &str,
        digest: &str,
        outcome: WatchdogBackupChannelOutcome,
    ) -> Result<(), CompositionError> {
        let mut slots = self.lock()?;
        let Some(record) = slots.retained.get_mut(binding) else {
            return Err(CompositionError::InvalidConfiguration(
                "watchdog backup control cannot settle an operation it did not claim".to_owned(),
            ));
        };
        if record.identity_digest == digest {
            record.outcome = Some(outcome);
        }
        Ok(())
    }

    /// Returns how many operations this composition entered at the owner and
    /// still holds without a known result. Absent observation is never
    /// reported as zero: this counts the composition's own retained records.
    fn unresolved(&self) -> Result<usize, CompositionError> {
        Ok(self
            .lock()?
            .retained
            .values()
            .filter(|record| record.is_unresolved())
            .count())
    }
}

/// The closed backup operation vocabulary, consumed from its canonical owner.
///
/// The nine-variant operation family, its `as_str()` spellings and its
/// operation-to-wire mapping are owned by `eliot-protocol`
/// (`crates/foundation/eliot-protocol/src/backup.rs`). This composition root
/// already depends on that crate, so the vocabulary is re-exported rather than
/// mirrored: the Watchdog owns only which operations it *recognizes* and what
/// it does with each one, never a second spelling of the family.
pub use eliot_protocol::backup::BackupOperationKind;

/// The closed backup lifecycle stage vocabulary.
///
/// This is a domain enumeration, not a policy table: it exists only to invert
/// the owner function [`operation_for_phase`] and, through it, to read the
/// owner's own [`attesting_roles`] authority check and to draw the canonical
/// operation family that registration completeness is measured against. No
/// accept/reject decision is generated from it: the registered set and the
/// executable set are this endpoint's own explicit, reviewed narrowing, so a
/// change to the owner's role matrix can only REFUSE an already registered
/// operation — it can never add an ingress method here.
const BACKUP_STAGES: [BackupStage; 8] = [
    BackupStage::Requested,
    BackupStage::Captured,
    BackupStage::Verified,
    BackupStage::RestorePrepared,
    BackupStage::RestoreStepApplied,
    BackupStage::Reconciled,
    BackupStage::RehearsalComplete,
    BackupStage::CutoverAdmitted,
];

/// The backup owner roles this Watchdog process actually holds.
///
/// A factual claim about what this process is, not an admission policy: the
/// Watchdog is the capture owner for its own bounded spool snapshot and the
/// spool owner for the isolated restore it imports. Which OPERATIONS those
/// roles may attest is not decided here — it is read from the `#954` owner's
/// own [`attesting_roles`] table, so this list can never widen the Watchdog's
/// registered or accepted operations on its own. It is an ADDITIONAL authority
/// check applied per admitted request, on top of this endpoint's own explicit
/// registered subset.
const WATCHDOG_OWNER_ROLES: [BackupRole; 2] = [BackupRole::CaptureOwner, BackupRole::SpoolOwner];

/// Returns the lifecycle stage the `#954` owner maps `operation` to.
///
/// Derived by inverting the owner's own [`operation_for_phase`] over the closed
/// stage vocabulary above, so no second operation-to-stage table is written
/// here and a new canonical operation reaches this module through the owner's
/// own exhaustive match.
fn owner_stage(operation: BackupOperationKind) -> Option<BackupStage> {
    BACKUP_STAGES
        .into_iter()
        .find(|stage| operation_for_phase(*stage) == operation)
}

/// Returns the role the `#954` owner table names as an attester of `operation`
/// among the roles this owner actually holds.
///
/// `None` means the owner's own table attributes `operation` either to no
/// attester at all or to a role this process does not hold. That is the whole
/// authority decision for the owner side of an admission, and it is read from
/// the owner rather than from a list any caller supplies.
fn watchdog_attesting_role(operation: BackupOperationKind) -> Option<BackupRole> {
    let stage = owner_stage(operation)?;
    attesting_roles(stage)
        .iter()
        .copied()
        .find(|role| WATCHDOG_OWNER_ROLES.contains(role))
}

/// One Watchdog-registered backup method: wire identity and closed operation.
///
/// [`wire_id`](Self::wire_id) is always the canonical wire identity of
/// [`op`](Self::op), taken from the owner's total
/// [`BackupOperationKind::wire_id`] lookup, so the record can never carry a
/// copied or drifted literal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedWatchdogBackupMethod {
    /// Stable protocol wire identity, derived from `op`.
    pub wire_id: &'static str,
    /// Closed operation bound to the wire identity.
    pub op: BackupOperationKind,
}

impl AcceptedWatchdogBackupMethod {
    /// Binds one operation to its canonical wire identity.
    const fn new(op: BackupOperationKind) -> Self {
        Self {
            wire_id: op.wire_id(),
            op,
        }
    }
}

/// Closed Watchdog-registered backup method table.
///
/// Membership is the registration, and it is an explicit, reviewed narrowing of
/// the canonical operation vocabulary rather than a projection of the `#954`
/// role and attester matrix: that matrix is a necessary authority check applied
/// per admitted request, never the generator of this concrete endpoint's
/// membership. The expected set that completeness is checked against is
/// derived independently by `verify_registration_is_complete` from
/// `registers_watchdog_operation`, not from this same list.
///
/// [`BackupOperationKind::ReadSnapshotPage`] and
/// [`BackupOperationKind::ReconcileRestore`] are the executable owner contours;
/// [`BackupOperationKind::VerifyArchive`] and
/// [`BackupOperationKind::RestoreStatus`] are registered so an absent method
/// fails with an explicit typed refusal instead of vanishing from the closed
/// table.
static ACCEPTED_WATCHDOG_BACKUP_METHODS: [AcceptedWatchdogBackupMethod; 4] = [
    AcceptedWatchdogBackupMethod::new(BackupOperationKind::ReadSnapshotPage),
    AcceptedWatchdogBackupMethod::new(BackupOperationKind::VerifyArchive),
    AcceptedWatchdogBackupMethod::new(BackupOperationKind::RestoreStatus),
    AcceptedWatchdogBackupMethod::new(BackupOperationKind::ReconcileRestore),
];

/// Returns the closed Watchdog-registered backup method table.
#[must_use]
pub fn accepted_watchdog_backup_methods() -> &'static [AcceptedWatchdogBackupMethod] {
    &ACCEPTED_WATCHDOG_BACKUP_METHODS
}

/// Returns whether this endpoint registers `operation` as an accepted method.
///
/// This is the endpoint's own reviewed narrowing of the canonical vocabulary,
/// matched exhaustively over every variant so a new canonical operation is a
/// compile error here until its request shape and disposition are reviewed,
/// instead of silently widening the registered set. It reads no role or
/// attester matrix: [`watchdog_attesting_role`] is the separate authority check
/// applied to each admitted request, and it can neither add nor remove a row
/// here.
const fn registers_watchdog_operation(operation: BackupOperationKind) -> bool {
    match operation {
        BackupOperationKind::ReadSnapshotPage
        | BackupOperationKind::VerifyArchive
        | BackupOperationKind::RestoreStatus
        | BackupOperationKind::ReconcileRestore => true,
        BackupOperationKind::RequestCapture
        | BackupOperationKind::RestoreStep
        | BackupOperationKind::PrepareIsolatedRestore
        | BackupOperationKind::CompleteRehearsal
        | BackupOperationKind::AdmitCutover => false,
    }
}

/// Returns every canonical backup operation, as the independent denominator the
/// registered table is checked against.
///
/// Derived by inverting the `#954` owner's own [`operation_for_phase`] over the
/// closed stage vocabulary, plus the one canonical operation that establishes
/// no lifecycle stage, so completeness is compared against the owner's own
/// operation family rather than against a second copy of the registered list.
fn canonical_backup_operations() -> Vec<BackupOperationKind> {
    BACKUP_STAGES
        .into_iter()
        .map(operation_for_phase)
        .chain(std::iter::once(BackupOperationKind::RestoreStatus))
        .collect()
}

/// Returns whether the registered table is exactly this endpoint's reviewed
/// registered subset, and covers nothing else.
///
/// The expected set comes from `registers_watchdog_operation`, an independent
/// explicit narrowing, and every operation is drawn from the canonical family
/// itself: an operation this endpoint reviews as registered but has no row for
/// is an incomplete registration, and a row for an operation this endpoint does
/// not register is a method this owner never claimed.
#[must_use]
pub fn verify_registration_is_complete() -> bool {
    let registered = accepted_watchdog_backup_methods();
    canonical_backup_operations().into_iter().all(|op| {
        registered.iter().any(|method| method.op == op) == registers_watchdog_operation(op)
    }) && registered
        .iter()
        .all(|method| registers_watchdog_operation(method.op))
}

/// Resolves a wire id to its registered method before any owner effect runs.
///
/// Unsupported methods — including `ADMIT_CUTOVER`,
/// `PREPARE_ISOLATED_RESTORE`, rehearsal-to-cutover mappings, and unknown
/// wire ids — fail here, before any owner effect runs.
///
/// # Errors
///
/// Returns [`BackupControlError::Contract`] for any wire identity this owner
/// does not register.
pub fn resolve_accepted_method(
    wire_id: &str,
) -> Result<&'static AcceptedWatchdogBackupMethod, BackupControlError> {
    accepted_watchdog_backup_methods()
        .iter()
        .find(|method| method.wire_id == wire_id)
        .ok_or(BackupControlError::Contract(BackupError::InvalidField {
            field: "watchdog_backup.method",
            reason: "unsupported backup wire identity for this owner",
        }))
}

/// Returns `Ok(())` when this owner can actually execute `operation`, or the
/// typed pre-effect refusal when it cannot.
///
/// The distinction is the whole point of the function. A method this owner
/// registers but holds no owner method for is RECOGNIZED AND UNAVAILABLE, not
/// supported: the refusal names the exact missing owner method, happens before
/// the operation is claimed or the owner is entered, and therefore can never be
/// recorded as an unresolved operation or reported as a possible effect. An
/// operation outside this owner's registered table is rejected for the same
/// reason, which is what keeps preparation and cutover unreachable here: they
/// are the Host owner's separately admitted operations, and a rehearsal
/// completion never resolves to cutover.
///
/// Matched exhaustively over the canonical vocabulary, so a new canonical
/// operation is a compile error here until its owner contour or its explicit
/// refusal has been reviewed; it never inherits a default.
fn executable_owner_method(operation: BackupOperationKind) -> Result<(), SpoolError> {
    match operation {
        BackupOperationKind::ReadSnapshotPage | BackupOperationKind::ReconcileRestore => Ok(()),
        BackupOperationKind::VerifyArchive => Err(SpoolError::Corrupt(
            "watchdog backup control refuses VERIFY_ARCHIVE; this owner holds no archive verifier and never interprets archive bytes, and a transport acknowledgement never establishes success"
                .to_owned(),
        )),
        BackupOperationKind::RestoreStatus => Err(SpoolError::Corrupt(
            "watchdog backup control refuses RESTORE_STATUS; this owner holds no restore-status projection, and a transport acknowledgement never establishes success"
                .to_owned(),
        )),
        BackupOperationKind::RequestCapture
        | BackupOperationKind::RestoreStep
        | BackupOperationKind::PrepareIsolatedRestore
        | BackupOperationKind::CompleteRehearsal
        | BackupOperationKind::AdmitCutover => Err(SpoolError::Corrupt(format!(
            "watchdog backup control rejects {operation}; it is outside this owner's registered table and fails before any owner effect"
        ))),
    }
}

/// The authenticated context one admitted request is checked against.
///
/// Built only by [`WatchdogBackupAdmission::observe`], which reads the
/// composition's own retained readiness identity and the live owner port's own
/// retained installation identity and generation. There is no public
/// constructor and no setter, so a caller cannot supply the values an admitted
/// request is later compared against — which is what makes the comparisons in
/// [`BackupControlHandle::admit`] independent of the request rather than two
/// copies of one payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogBackupAdmission {
    /// The admitted launch session identity this composition was started
    /// under, observed from the composition's own readiness projection.
    session_id: String,
    /// The installation identity the live owner port is bound to.
    owner_installation: String,
    /// The watchdog generation the live owner port is bound to.
    owner_generation: u64,
}

impl WatchdogBackupAdmission {
    /// Observes the authenticated context from the live composition and its
    /// live owner port.
    ///
    /// The readiness projection and the owner port are the composition's own
    /// retained state, read here rather than supplied by a request, so the
    /// values every admission is checked against cannot come from the payload
    /// that admission is judging.
    ///
    /// # Errors
    ///
    /// Returns [`BackupControlError::Composition`] when the composition
    /// identity is unexpected or its retained launch session identity is
    /// unusable.
    fn observe(
        composition: &WatchdogComposition,
        port: &WatchdogBackupPort,
    ) -> Result<Self, BackupControlError> {
        let readiness = composition.readiness();
        if readiness.service != SERVICE_NAME || readiness.protocol != PROTOCOL_VERSION {
            return Err(BackupControlError::Composition(
                CompositionError::InvalidConfiguration(
                    "watchdog backup control refuses an unrecognized composition identity"
                        .to_owned(),
                ),
            ));
        }
        if readiness.service_instance_guid.trim().is_empty() {
            return Err(BackupControlError::Composition(
                CompositionError::InvalidConfiguration(
                    "watchdog backup control refuses a composition with no admitted launch session"
                        .to_owned(),
                ),
            ));
        }
        Ok(Self {
            session_id: readiness.service_instance_guid,
            owner_installation: port.source_installation().to_owned(),
            owner_generation: port.watchdog_generation(),
        })
    }

    /// Returns this context bound to a freshly observed owner port.
    ///
    /// The session identity is a launch-scoped value, so it is carried across
    /// the re-observation unchanged; the installation identity and generation
    /// are read from the port again, so a start that follows a fence movement
    /// on the owner is refused rather than admitted against a stale generation.
    fn reobserved(&self, port: &WatchdogBackupPort) -> Self {
        Self {
            session_id: self.session_id.clone(),
            owner_installation: port.source_installation().to_owned(),
            owner_generation: port.watchdog_generation(),
        }
    }
}

/// One typed request on this endpoint's closed backup ingress surface.
///
/// A closed enum over exactly the four canonical `#954` request shapes this
/// endpoint registers, so every registered operation has a real typed
/// admission path and none of them is reachable only by re-typing another
/// operation's DTO. Each variant carries its own canonical request type, which
/// validates its own wire identity, operation, bindings, bounds and digest; no
/// variant is coerced through [`BackupSnapshotPageRead`].
///
/// The reconcile variant additionally carries the owner-side inputs the
/// isolated-restore owner consumes and the canonical reconcile request does
/// not: the externally admitted isolated destination and this owner's own
/// retained runtime admission (the ACTIVE installation the import must not
/// reuse). Neither is a string a request may choose freely — the destination is
/// owner-issued by [`crate::admit_isolated_destination`] and proved isolated by
/// the owner at import — and both are compared with the canonical request's own
/// `dest_installation` before the owner is entered.
#[derive(Clone, Copy)]
pub enum WatchdogBackupRequest<'a> {
    /// Bounded page read of an owner snapshot.
    SnapshotPageRead(&'a BackupSnapshotPageRead),
    /// Archive verification of an immutable archive handle.
    ///
    /// Present so the registered `VERIFY_ARCHIVE` row has a real typed request
    /// and an explicit refusal, not a silent drop: this owner holds no archive
    /// verifier, so the request never reaches an owner.
    ArchiveVerification(&'a BackupArchiveVerification),
    /// Read-only restore-status query.
    ///
    /// Present so the registered `RESTORE_STATUS` row has a real typed request
    /// and an explicit refusal: this owner holds no restore-status projection,
    /// so the request never reaches an owner.
    RestoreStatus(&'a BackupRestoreStatus),
    /// Bounded restore reconciliation toward an admitted isolated destination.
    RestoreReconcile {
        /// Canonical reconcile request: the only authority-bearing payload.
        request: &'a BackupRestoreReconcile,
        /// Externally admitted isolated destination installation.
        destination: &'a AdmittedIsolatedDestination,
        /// This owner's own retained runtime admission, read from the owner.
        active: &'a WatchdogRuntimeBinding,
        /// Bounded, operation-bound restore step chain to reconcile.
        steps: &'a [SpoolRestoreStep],
    },
}

impl std::fmt::Debug for WatchdogBackupRequest<'_> {
    /// Renders only the closed variant and its canonical operation, never
    /// request, identity, lease, or installation material.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("WatchdogBackupRequest")
            .field(&self.operation())
            .finish()
    }
}

impl<'a> WatchdogBackupRequest<'a> {
    /// Returns the canonical operation this variant is typed for.
    ///
    /// Matched exhaustively over this closed surface, so a new variant is a
    /// compile error here until its operation, validation, and dispatch are
    /// supplied for it.
    pub const fn operation(self) -> BackupOperationKind {
        match self {
            Self::SnapshotPageRead(_) => BackupOperationKind::ReadSnapshotPage,
            Self::ArchiveVerification(_) => BackupOperationKind::VerifyArchive,
            Self::RestoreStatus(_) => BackupOperationKind::RestoreStatus,
            Self::RestoreReconcile { .. } => BackupOperationKind::ReconcileRestore,
        }
    }

    /// Returns the bound request identity every admission gate compares against.
    ///
    /// Shared by all four canonical request types, so no gate has to reach into
    /// a variant to read the one identity the operation is bound to. The borrow
    /// is the variant's own `'a` borrow, not a borrow of this `Copy` value, so
    /// the identity outlives the call.
    const fn identity(self) -> &'a BackupRequestIdentity {
        match self {
            Self::SnapshotPageRead(page_read) => &page_read.identity,
            Self::ArchiveVerification(verification) => &verification.identity,
            Self::RestoreStatus(status) => &status.identity,
            Self::RestoreReconcile {
                request: reconcile, ..
            } => &reconcile.identity,
        }
    }

    /// Runs the canonical contract's own validation for THIS variant's own
    /// request type.
    ///
    /// # Errors
    ///
    /// Returns the `#954` contract's own typed [`BackupError`] unchanged, so a
    /// wire-identity, operation, binding, bound, or digest rejection stays
    /// distinguishable from every other refusal on this path.
    fn validate(self) -> Result<(), BackupError> {
        match self {
            Self::SnapshotPageRead(page_read) => BackupSnapshotPageRead::validate(page_read),
            Self::ArchiveVerification(verification) => {
                BackupArchiveVerification::validate(verification)
            }
            Self::RestoreStatus(status) => BackupRestoreStatus::validate(status),
            Self::RestoreReconcile {
                request: reconcile, ..
            } => BackupRestoreReconcile::validate(reconcile),
        }
    }
}

/// One request this owner admitted, resolved to its exact method.
///
/// Its fields are private and the only constructor is
/// [`BackupControlHandle::admit`], so it cannot be built by a caller that
/// skipped admission: the payload's own operation string is never what selects
/// the owner operation, and the owner operation is never what grants the
/// payload authority.
#[derive(Clone, Debug)]
pub struct AdmittedWatchdogBackupRequest<'a> {
    method: &'static AcceptedWatchdogBackupMethod,
    request: WatchdogBackupRequest<'a>,
}

/// The owner's own retained result for one admitted operation.
///
/// Every variant carries the owner's own values, read from the owner that
/// produced them, never a value copied out of the request that asked for them.
#[derive(Clone, Debug)]
pub enum WatchdogBackupChannelOutcome {
    /// The `#955` spool capture owner produced one bounded fence for this exact
    /// operation, and the requested page was read from that retained fence.
    ///
    /// Both owner values are boxed because they each carry a retained entry
    /// vector, while the `Restore` disposition below is a single field. Holding
    /// the two shapes in one enum unboxed would make every `Restore` answer as
    /// large as a whole retained spool fence and its page, which is a cost the
    /// reconcile contour — the one that actually answers — would pay for the
    /// capture contour's data. The content is unchanged; only its placement is.
    Capture {
        /// The fence the capture owner retained for this operation.
        fence: Box<WatchdogSpoolFence>,
        /// The bounded page read from that retained fence.
        page: Box<WatchdogSpoolSnapshotPage>,
    },
    /// The isolated-restore owner's own disposition for the bounded step chain
    /// of this exact operation.
    Restore(SpoolRestoreDisposition),
}

/// Bounded failure of one admitted backup request, or of one backup-control
/// lifecycle step.
///
/// The owner's own typed [`SpoolError`] and the `#954` contract's own typed
/// [`BackupError`] are each carried as a typed source and never restated as a
/// string, so a caller can always tell an owner refusal apart from a contract
/// rejection, a policy refusal, and a composition refusal.
#[derive(Debug, Error)]
pub enum BackupControlError {
    /// The request is outside the closed admitted subset, or the handle
    /// cannot currently dispatch, or the request presented an operation whose
    /// authority this owner does not hold.
    #[error("watchdog backup control rejects the request: {0}")]
    Rejected(String),
    /// The `#954` backup contract refused the presented request, or the
    /// operation has already taken effect and must be reconciled rather than
    /// run again.
    #[error("watchdog backup control refuses the contract: {0}")]
    Contract(#[source] BackupError),
    /// The owner refused the request, or the owner-bound resource behind a
    /// registration or start step could not be read; the owner's own bounded
    /// reason travels verbatim and is never restated as success.
    #[error("watchdog spool owner refused the backup request: {0}")]
    OwnerRefused(#[source] SpoolError),
    /// A registration or start step was refused by the composition itself: an
    /// unrecognized composition identity, no owner-bound spool port, a bounded
    /// registration or retained-operation table that is exhausted or already
    /// closed, or a lifecycle state that does not admit this step.
    #[error("watchdog backup control lifecycle is refused: {0}")]
    Composition(#[source] CompositionError),
}

/// Lifecycle state of one registered backup-control handle.
///
/// Closed over the whole lifecycle so no combination of independent booleans can
/// describe a state the code does not implement. Every variant is reachable and
/// every variant is read: `Registered` is what [`register_backup_control`]
/// returns, `Started` is what [`start_backup_control`] produces, and `Released`
/// is what [`stop_backup_control`] leaves behind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackupControlState {
    /// The bounded slot is reserved and the owner resource was proven
    /// reachable at registration, but dispatch is not admitted yet.
    Registered,
    /// Dispatch is admitted against the same owner binding.
    Started,
    /// The bounded slot has been released; this handle can no longer dispatch
    /// and can no longer be started.
    Released,
}

impl BackupControlState {
    /// Returns whether this state admits dispatch.
    const fn admits_dispatch(self) -> bool {
        matches!(self, Self::Started)
    }
}

/// One real, owner-bound backup-control registration record.
///
/// Recorded by [`register_backup_control`] and by [`start_backup_control`] from
/// the LIVE owner resource the handle is bound to, through
/// [`WatchdogBackupPort::owner_spool_high_water`]: a real read transaction
/// against the owner's own `watchdog.redb`, taken through the same owner handle
/// every heartbeat and gap record is appended through. The recorded sequence is
/// therefore the owner's own durable value at the moment of registration or
/// start, and it is a real observation of a real resource — not a constant, not
/// a placeholder, and not a copy of a value supplied by the caller.
///
/// It exists because "a slot number was handed out" is not a registration: it
/// is the evidence that the resource behind this handle was genuinely reachable
/// when the handle was admitted. The two observations are deliberately separate
/// reads, so a start can still be refused when the owner became unreachable
/// after registration succeeded. It grants no authority, mints no identity, and
/// is compared against nothing — a self-comparison of immutable fields could
/// never fail and would prove nothing, so this record is retained and reported
/// instead of being re-verified against itself.
///
/// It carries no copy of the owner installation identity: that value is
/// immutable on the bound port and is already read live through
/// [`BackupControlHandle::owner_installation`], so a second copy here would be
/// written and never read.
#[derive(Debug)]
struct BackupOwnerBinding {
    /// The owner's own durable high-water sequence as observed live.
    owner_spool_high_water: u64,
    /// The owner-held watchdog generation this handle is bound to.
    owner_generation: u64,
    /// The composition identity admitted at registration.
    service: &'static str,
    /// The protocol identity admitted at registration.
    protocol: &'static str,
}

impl BackupOwnerBinding {
    /// Observes the live owner resource this handle would bind.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the owner-bound spool cannot be read.
    fn observe(
        port: &WatchdogBackupPort,
        service: &'static str,
        protocol: &'static str,
    ) -> Result<Self, SpoolError> {
        Ok(Self {
            owner_spool_high_water: port.owner_spool_high_water()?,
            owner_generation: port.watchdog_generation(),
            service,
            protocol,
        })
    }
}

/// One real, owner-bound backup-control registration record.
///
/// Carries the bounded registration slot, a real [`BackupOwnerBinding`] observed
/// from the live owner spool, the non-caller-constructible
/// [`WatchdogBackupAdmission`] observed from the same live composition and
/// owner, and the owner-bound backup port itself, so an admitted request
/// dispatches to the real owner instead of to a receipt alone. There is
/// intentionally no kill-by-name (no string handle, no PID, no service-name
/// targeting) and no listener or task identity: this process opens neither.
///
/// The slot is released by [`stop_backup_control`] and by its own
/// composition's [`BackupControlRegistration::close`]. A handle dropped
/// without either holds its slot until the composition shuts down, which is
/// bounded and fails closed at [`MAX_BACKUP_CONTROL_HANDLES`] rather than
/// growing an unbounded set.
pub struct BackupControlHandle {
    slot: u64,
    state: BackupControlState,
    /// Real owner-bound registration record, observed live.
    binding: BackupOwnerBinding,
    /// The authenticated context admitted requests are checked against.
    admission: WatchdogBackupAdmission,
    port: std::sync::Arc<WatchdogBackupPort>,
    /// The registering composition's own bounded table. Kept per handle so a
    /// handle is never evaluated against another lifecycle's slots or
    /// retained operations.
    registration: BackupControlRegistration,
}

impl std::fmt::Debug for BackupControlHandle {
    /// Renders only the bounded registration facts, never the owner's spool
    /// internals or any identity material.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackupControlHandle")
            .field("registration_slot", &self.slot)
            .field("state", &self.state)
            .field(
                "owner_spool_high_water",
                &self.binding.owner_spool_high_water,
            )
            .field("service", &self.binding.service)
            .field("protocol", &self.binding.protocol)
            .finish_non_exhaustive()
    }
}

impl BackupControlHandle {
    /// Returns the bounded registration slot this handle occupies.
    #[must_use]
    pub fn registration_slot(&self) -> u64 {
        self.slot
    }

    /// Returns whether the handle admits dispatch.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state.admits_dispatch()
    }

    /// Returns whether this owner registers `operation` yet holds no method for it.
    ///
    /// Recognition is not availability: this reads the endpoint's OWN two tables
    /// — the registered method set and the executable owner contour — through
    /// this module's own `executable_owner_method`, so no second table exists
    /// anywhere else. It is what makes a registered-but-uninvokable method
    /// answerable as an explicit typed refusal on the canonical transport
    /// instead of vanishing or looking like an admission failure.
    #[must_use]
    pub fn is_recognized_without_owner_method(&self, operation: BackupOperationKind) -> bool {
        accepted_watchdog_backup_methods()
            .iter()
            .any(|method| method.op == operation)
            && executable_owner_method(operation).is_err()
    }

    /// Returns the owner's own durable spool sequence, observed live from the
    /// bound owner resource when this handle was registered and re-observed
    /// when it was started.
    ///
    /// This is a real read of the owner's `watchdog.redb` high-water metadata
    /// through the same owner handle the supervision path appends through. It
    /// is reported evidence that the bound resource was reachable at admission,
    /// and it is not an authority, fence, or health verdict.
    #[must_use]
    pub const fn owner_spool_high_water(&self) -> u64 {
        self.binding.owner_spool_high_water
    }

    /// Returns the owner-held watchdog generation observed at registration.
    #[must_use]
    pub const fn owner_generation(&self) -> u64 {
        self.binding.owner_generation
    }

    /// Returns the owner-held installation identity this handle is bound to.
    #[must_use]
    pub fn owner_installation(&self) -> &str {
        self.port.source_installation()
    }

    /// Returns this owner's own retained ACTIVE installation admission, or
    /// `Err` when the bound owner port retains none.
    ///
    /// The ACTIVE side of an isolated-restore isolation proof is read from the
    /// admission this owner's spool was opened from, never from the reconcile
    /// request. A request that presented its own "active" identity would turn
    /// the isolation comparison into a comparison of that claim with itself, so
    /// an owner holding no retained admission refuses the import instead of
    /// falling back to any active identity.
    ///
    /// # Errors
    ///
    /// Returns [`BackupControlError::OwnerRefused`] when the bound owner port
    /// retains no ACTIVE admission, because an import cannot then be proved
    /// isolated from anything.
    pub fn active_runtime_binding(&self) -> Result<&WatchdogRuntimeBinding, BackupControlError> {
        self.port
            .active_runtime_binding()
            .ok_or_else(|| BackupControlError::OwnerRefused(SpoolError::InvalidLease(
                "watchdog backup control refuses an isolated reconcile: this owner retains no ACTIVE installation admission to prove isolation against"
                    .to_owned(),
            )))
    }

    /// Returns how many operations this composition entered at the owner and
    /// still holds without a known result.
    ///
    /// This is the composition's own retained evidence, counted from its
    /// records. It is never a constant and never a fresh zero: a composition
    /// that entered the owner for an operation whose answer was lost reports it
    /// here, and at least one is exactly what must survive a shutdown report.
    ///
    /// # Errors
    ///
    /// Returns [`BackupControlError::Composition`] when the composition's
    /// bounded table cannot be read.
    pub fn unresolved_operations(&self) -> Result<usize, BackupControlError> {
        self.registration
            .unresolved()
            .map_err(BackupControlError::Composition)
    }

    /// Refuses dispatch unless this handle is started and still holds its live
    /// bounded registration slot.
    fn require_dispatchable(&self) -> Result<(), BackupControlError> {
        if !self.state.admits_dispatch() {
            return Err(BackupControlError::Rejected(
                "watchdog backup control cannot dispatch before it is started, or after it is released"
                    .to_owned(),
            ));
        }
        if !self.registration.is_registered(self.slot) {
            return Err(BackupControlError::Rejected(
                "watchdog backup control cannot dispatch after its registration was released"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Admits exactly one backup request against the authenticated context.
    ///
    /// Accepts one closed typed request ([`WatchdogBackupRequest`]), so every
    /// registered operation reaches admission through its own canonical request
    /// type rather than through one operation's DTO.
    ///
    /// Every gate below runs before the owner is entered, so a refused request
    /// has provably taken no effect. None of them compares the request against
    /// itself, and none of them reads an owner or a policy out of the payload:
    ///
    /// 1. the handle is started and still holds its bounded registration slot;
    /// 2. the `#954` contract validates the presented request through that
    ///    variant's OWN canonical validator, which re-derives its own digests,
    ///    bounds, fence exactness and operation binding;
    /// 3. the request's operation resolves to a row of this owner's closed
    ///    registered table, and the row's own operation must equal the
    ///    operation the request typed — a self-consistent payload can never
    ///    substitute another operation's wire identity;
    /// 4. the request's authenticated session must be the launch session this
    ///    composition was actually started under, read from the composition's
    ///    own readiness projection;
    /// 5. the request's fence generation must be the generation the live owner
    ///    port is bound to, so a stale generation is refused rather than
    ///    captured against;
    /// 6. the request's source installation must be the installation the live
    ///    owner port is bound to;
    /// 7. the `#954` owner table must attribute this operation to a role this
    ///    owner actually holds, so a request naming an operation this owner has
    ///    no authority over is refused;
    /// 8. a reconcile request's destination must be the installation its own
    ///    bound identity names, and the destination is the owner-issued admitted
    ///    isolated installation rather than a requester-chosen string.
    ///
    /// The role matrix is an ADDITIONAL authority check here, never the source
    /// of the registered set: an operation this owner has no authority to
    /// attest is refused even though a narrower registered row may exist for it.
    ///
    /// # Errors
    ///
    /// Returns [`BackupControlError::Rejected`] for a handle that cannot
    /// dispatch, an operation this owner has no registered row for, a request
    /// whose operation and registered row disagree, or any gate 4 to 8
    /// failure. Returns [`BackupControlError::Contract`] when the `#954`
    /// contract refuses the presented request.
    pub fn admit<'a>(
        &self,
        request: WatchdogBackupRequest<'a>,
    ) -> Result<AdmittedWatchdogBackupRequest<'a>, BackupControlError> {
        self.require_dispatchable()?;
        request.validate().map_err(BackupControlError::Contract)?;
        let identity = request.identity();
        let operation = request.operation();
        let method = resolve_accepted_method(operation.wire_id())?;
        if method.op != operation {
            return Err(BackupControlError::Rejected(format!(
                "watchdog backup control rejects a {operation} request dispatched as {}",
                method.op
            )));
        }
        if identity.principal.session_id != self.admission.session_id {
            return Err(BackupControlError::Rejected(
                "watchdog backup control rejects a request for a foreign admitted session"
                    .to_owned(),
            ));
        }
        if identity.fence.resource_generation.value() != self.admission.owner_generation {
            return Err(BackupControlError::Rejected(
                "watchdog backup control rejects a request for a stale generation fence".to_owned(),
            ));
        }
        if identity.source_installation != self.admission.owner_installation {
            return Err(BackupControlError::Rejected(
                "watchdog backup control rejects a request for a foreign source installation"
                    .to_owned(),
            ));
        }
        if let WatchdogBackupRequest::RestoreReconcile {
            request,
            destination,
            ..
        } = request
            && destination.installation() != request.identity.dest_installation.as_str()
        {
            return Err(BackupControlError::Rejected(format!(
                "watchdog backup control rejects a reconcile request for {} against an admitted destination {}",
                request.identity.dest_installation,
                destination.installation()
            )));
        }
        if watchdog_attesting_role(operation).is_none() {
            return Err(BackupControlError::Rejected(format!(
                "watchdog backup control rejects {operation}; no backup owner role this process holds attests it"
            )));
        }
        Ok(AdmittedWatchdogBackupRequest { method, request })
    }

    /// Runs one admitted request against the exact owner operation it resolved
    /// to, once per admitted operation.
    ///
    /// The operation's own stable mutation binding is claimed in this
    /// composition's retained table BEFORE the owner is entered, so a repeated
    /// or reconnected presentation of the same operation reconciles against
    /// that record instead of entering the owner again:
    ///
    /// - a retained record with the same canonical identity and a known owner
    ///   result returns that owner result and performs no owner call;
    /// - a retained record with the same canonical identity and no known owner
    ///   result is an operation the owner was already entered for, whose effect
    ///   is therefore possible rather than absent. It is reported as needing
    ///   reconciliation and is never re-entered, so there is no blind retry of
    ///   a possible effect;
    /// - a retained record under the same mutation binding but a different
    ///   canonical identity is a replay conflict, not a new operation.
    ///
    /// The admitted operation is then routed to its one owner method. The
    /// owner's own result is validated against THIS operation before it is
    /// retained or returned: the capture fence must name this owner's
    /// installation, this owner's generation, the admitted requester's
    /// principal, and this operation's own mutation binding, and the page must
    /// be the page this operation asked for. An owner result that fails any of
    /// those is refused, never returned as success.
    ///
    /// An owner failure leaves the operation retained without a result, which
    /// is what makes the before-send refusal and the possible-effect-after-send
    /// case distinct instead of one "timed out".
    ///
    /// # Errors
    ///
    /// Returns [`BackupControlError::Rejected`] when the handle cannot
    /// dispatch, when the operation has no executable owner method on this
    /// owner, or when the owner's result does not match this operation.
    /// Returns [`BackupControlError::Composition`] when the composition's
    /// bounded retained-operation table is closed or exhausted.
    /// Returns [`BackupControlError::OwnerRefused`] with the owner's own typed
    /// reason when the owner rejects the bounded request.
    pub fn execute(
        &self,
        admitted: &AdmittedWatchdogBackupRequest<'_>,
    ) -> Result<WatchdogBackupChannelOutcome, BackupControlError> {
        self.require_dispatchable()?;
        // A method this owner registers but cannot execute is refused BEFORE
        // the operation is claimed, so it is never recorded as an operation the
        // owner was entered for and can never be reported as a possible effect.
        // Recognition is not availability, and an unavailable method is a
        // pre-effect refusal, not an unresolved one.
        if let Err(refusal) = executable_owner_method(admitted.method.op) {
            return Err(BackupControlError::OwnerRefused(refusal));
        }
        let identity = admitted.request.identity();
        let binding = identity.mutation.canonical_request_hash.as_str();
        let digest = identity
            .compute_digest()
            .map_err(BackupControlError::Contract)?;
        if let Some(record) = self
            .registration
            .retained(binding)
            .map_err(BackupControlError::Composition)?
        {
            // Both halves of the retained record are compared with THIS
            // operation: a different canonical identity under the same binding
            // is a replay conflict, and a different operation under the same
            // identity is a binding that does not own what it names.
            if record.identity_digest != digest || record.operation != admitted.method.op {
                return Err(BackupControlError::Contract(BackupError::ReplayConflict));
            }
            return match record.outcome {
                Some(outcome) => Ok(outcome),
                None => Err(BackupControlError::Rejected(format!(
                    "watchdog backup control reconciles {} against its retained record; this operation was already entered at the owner and is never run twice",
                    admitted.method.op
                ))),
            };
        }
        self.registration
            .claim(binding, admitted.method.op, &digest)
            .map_err(BackupControlError::Composition)?;
        let outcome = self
            .run_owner_operation(admitted)
            .map_err(BackupControlError::OwnerRefused)?;
        self.check_outcome_matches_operation(admitted, &outcome)?;
        self.registration
            .settle(binding, &digest, outcome.clone())
            .map_err(BackupControlError::Composition)?;
        Ok(outcome)
    }

    /// Runs the one owner method this operation resolved to.
    ///
    /// The executable set is decided by `executable_owner_method`, which runs
    /// before the operation is claimed, so this match has exactly the two
    /// reachable owner calls and every other arm is the same pre-effect
    /// refusal.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when this owner has no executable method for the
    /// admitted operation, when the admitted request's shape is not the one its
    /// own operation registered, when a presented reconcile step is not bound to
    /// this operation, or when the owner itself refuses the bounded request.
    fn run_owner_operation(
        &self,
        admitted: &AdmittedWatchdogBackupRequest<'_>,
    ) -> Result<WatchdogBackupChannelOutcome, SpoolError> {
        match admitted.method.op {
            BackupOperationKind::ReadSnapshotPage => {
                let WatchdogBackupRequest::SnapshotPageRead(request) = admitted.request else {
                    return Err(SpoolError::Corrupt(
                        "watchdog backup control reached READ_SNAPSHOT_PAGE with a request shape it does not own"
                            .to_owned(),
                    ));
                };
                // The `#955` capture owner is reached here: the fence is
                // produced by the owner itself from the admitted operation's
                // own bindings, and the page is then read from that retained
                // fence. Nothing is taken from the payload but the operation
                // identity and the requester the operation was admitted for.
                //
                // Cross-owner coherence is NOT claimed here. This wire layer
                // cannot infer a global transaction from a message, so the
                // capture declares no canonical or ORS reference and no
                // fence-protocol equality rather than asserting one.
                let fence = self.port.snapshot(
                    CaptureFenceParams {
                        source_installation: request.identity.source_installation.clone(),
                        watchdog_generation: self.admission.owner_generation,
                        requester_principal: request.identity.principal.principal.clone(),
                        snapshot_operation_id: request
                            .identity
                            .mutation
                            .canonical_request_hash
                            .clone(),
                        canonical_ref: None,
                        ors_ref: None,
                        coherence_fence_equal: false,
                    },
                    WatchdogSpoolBackupLimits::default(),
                )?;
                let page = self.port.read_page(&fence, request.page.page_index)?;
                Ok(WatchdogBackupChannelOutcome::Capture {
                    fence: Box::new(fence),
                    page: Box::new(page),
                })
            }
            BackupOperationKind::ReconcileRestore => {
                let WatchdogBackupRequest::RestoreReconcile {
                    request,
                    destination,
                    active,
                    steps,
                } = admitted.request
                else {
                    return Err(SpoolError::Corrupt(
                        "watchdog backup control reached RECONCILE_RESTORE with a request shape it does not own"
                            .to_owned(),
                    ));
                };
                // The isolated-restore owner is reached here. Every step must be
                // bound to THIS operation's own stable mutation identity: a step
                // carried under another operation's identity would reconcile
                // another operation's retained evidence under this one, and
                // existence of a well-formed chain proves nothing about whose it
                // is. The requester's believed digest must be the retained digest
                // the chain ends at, which is what makes the query's
                // distinguishing field load-bearing instead of decorative.
                let operation_id = request
                    .identity
                    .mutation
                    .canonical_request_hash
                    .as_str();
                for step in steps {
                    if step.operation_id.as_str() != operation_id {
                        return Err(SpoolError::Corrupt(
                            "watchdog backup control refuses a reconcile step bound to another operation"
                                .to_owned(),
                        ));
                    }
                }
                if steps.last().map(|step| step.step_digest.as_str())
                    != Some(request.believed_digest.as_str())
                {
                    return Err(SpoolError::Corrupt(
                        "watchdog backup control refuses a reconcile request whose believed digest is not the retained digest this operation's chain ends at"
                            .to_owned(),
                    ));
                }
                let disposition = self.port.import_isolated(
                    &request.identity.source_installation,
                    Some(destination),
                    active,
                    steps,
                )?;
                Ok(WatchdogBackupChannelOutcome::Restore(disposition))
            }
            _ => match executable_owner_method(admitted.method.op) {
                Ok(()) => Err(SpoolError::Corrupt(
                    "watchdog backup control reached an owner arm its executable set does not admit"
                        .to_owned(),
                )),
                Err(refusal) => Err(refusal),
            },
        }
    }

    /// Compares the owner's own result against THIS admitted operation.
    ///
    /// This is a content comparison, not an existence or shape check: each
    /// value is the one the owner itself produced, compared with the operation
    /// that asked for it, so a result that belongs to a different principal,
    /// installation, generation, operation, or page can never be delivered as
    /// this operation's answer.
    ///
    /// The restore contour's owner contract returns a disposition rather than an
    /// evidence handle, so its per-operation binding is established before the
    /// owner is entered — source installation, admitted destination, and every
    /// step bound to this operation's own mutation identity — and the guard here
    /// refuses to deliver an unresolved disposition as this operation's answer.
    ///
    /// # Errors
    ///
    /// Returns [`BackupControlError::Rejected`] when any compared value
    /// diverges from the admitted operation or from the authenticated context.
    fn check_outcome_matches_operation(
        &self,
        admitted: &AdmittedWatchdogBackupRequest<'_>,
        outcome: &WatchdogBackupChannelOutcome,
    ) -> Result<(), BackupControlError> {
        let identity = admitted.request.identity();
        let (fence, page) = match outcome {
            WatchdogBackupChannelOutcome::Capture { fence, page } => {
                (fence.as_ref(), page.as_ref())
            }
            WatchdogBackupChannelOutcome::Restore(disposition) => {
                if *disposition == SpoolRestoreDisposition::Unknown {
                    return Err(BackupControlError::Rejected(format!(
                        "watchdog backup control refuses the unresolved {} disposition as this operation's answer",
                        admitted.method.op
                    )));
                }
                return Ok(());
            }
        };
        let WatchdogBackupRequest::SnapshotPageRead(request) = admitted.request else {
            return Err(BackupControlError::Rejected(format!(
                "watchdog backup control received a {} outcome for a request shape it does not own",
                admitted.method.op
            )));
        };
        if fence.source_installation != self.admission.owner_installation
            || fence.watchdog_generation != self.admission.owner_generation
        {
            return Err(BackupControlError::Rejected(
                "watchdog backup control refuses an owner result that names a foreign owner"
                    .to_owned(),
            ));
        }
        if fence.requester_principal != identity.principal.principal {
            return Err(BackupControlError::Rejected(
                "watchdog backup control refuses an owner result captured for another requester"
                    .to_owned(),
            ));
        }
        if fence.snapshot_operation_id != identity.mutation.canonical_request_hash {
            return Err(BackupControlError::Rejected(
                "watchdog backup control refuses an owner result belonging to another operation"
                    .to_owned(),
            ));
        }
        if page.page_index != request.page.page_index {
            return Err(BackupControlError::Rejected(
                "watchdog backup control refuses an owner result for another page of this operation"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Registers Watchdog backup control against a live composition.
///
/// Validates the composition readiness identity (`SERVICE_NAME` /
/// `PROTOCOL_VERSION`), takes the owner-bound backup port from the
/// composition's own kernel port — the same owner that appends every heartbeat
/// and gap record, so no second database handle is opened — proves that bound
/// owner resource is live by reading its own durable high-water sequence,
/// observes the non-caller-constructible
/// [`WatchdogBackupAdmission`] from the same live composition and owner, and
/// reserves one bounded slot in the registering composition's own
/// [`BackupControlRegistration`] table. A composition whose kernel port owns no
/// spool admits no backup control: there is exactly one construction path and
/// no substitute.
///
/// The owner proof runs BEFORE the reservation, so a refusal here consumes no
/// bounded slot. The returned handle is therefore not a bare slot number: it
/// carries the real owner-bound registration record observed from the live owner
/// spool, the authenticated context every admission is checked against, and the
/// owner port itself, and it is refused rather than returned when that resource
/// is not readable.
///
/// No listener is opened and no task is spawned by this function; the canonical
/// signals listener is started from the STARTED handle by the composition, and
/// the owning [`crate::KernelWatchdogPort`] implementation keeps all effects.
/// The handle is registered-but-not-yet-started; [`start_backup_control`] admits
/// dispatch.
///
/// # Errors
///
/// Returns [`BackupControlError::Composition`] when the composition identity is
/// unexpected, when the composition exposes no owner-bound spool port, or when
/// that composition's bounded registration table is exhausted or already
/// closed. Returns [`BackupControlError::OwnerRefused`] with the owner's own
/// typed reason when the bound owner spool cannot be read.
pub fn register_backup_control(
    composition: &WatchdogComposition,
) -> Result<BackupControlHandle, BackupControlError> {
    let readiness = composition.readiness();
    if readiness.service != SERVICE_NAME || readiness.protocol != PROTOCOL_VERSION {
        return Err(BackupControlError::Composition(
            CompositionError::InvalidConfiguration(
                "watchdog backup control refuses an unrecognized composition identity".to_owned(),
            ),
        ));
    }
    let port = composition.owner_backup_port().ok_or_else(|| {
        BackupControlError::Composition(CompositionError::InvalidConfiguration(
            "watchdog backup control refuses registration without an owner-held spool port"
                .to_owned(),
        ))
    })?;
    // The registration must cover exactly this endpoint's reviewed registered
    // subset. The expected set is re-derived here from the endpoint's own
    // explicit narrowing and from the canonical operation family, not from the
    // role matrix and not from the registered list itself, so a table that
    // dropped a method or added one this owner never claimed refuses instead of
    // serving a partial or over-broad registration.
    if !verify_registration_is_complete() {
        return Err(BackupControlError::Composition(
            CompositionError::InvalidConfiguration(
                "watchdog backup control refuses a registration that does not match the owner's accepted method table"
                    .to_owned(),
            ),
        ));
    }
    let binding = BackupOwnerBinding::observe(&port, SERVICE_NAME, PROTOCOL_VERSION)
        .map_err(BackupControlError::OwnerRefused)?;
    let admission = WatchdogBackupAdmission::observe(composition, &port)?;
    let registration = composition.backup_control_registration();
    let slot = registration
        .reserve()
        .map_err(BackupControlError::Composition)?;
    Ok(BackupControlHandle {
        slot,
        state: BackupControlState::Registered,
        binding,
        admission,
        port,
        registration,
    })
}

/// Starts a registered backup control handle.
///
/// Re-reads the bound owner resource and re-observes the authenticated context
/// — a second, independent live read, not a re-check of the values captured at
/// registration — and admits dispatch only when both succeed. A start can
/// therefore be refused after a successful registration, when the owner became
/// unreachable or the composition's identity moved in between; the newly
/// observed values replace the registration ones on the handle.
///
/// Fails closed when the handle is already started, when the handle was already
/// released by [`stop_backup_control`], when the composition has closed backup
/// control, or when the handle no longer holds a live bounded slot, so a second
/// registration can never be admitted past the bound and a released handle can
/// never be revived.
///
/// # Errors
///
/// Returns [`BackupControlError::Composition`] when the handle is already
/// started, when it was already released, or when its slot is no longer
/// registered. Returns [`BackupControlError::OwnerRefused`] with the owner's own
/// typed reason when the bound owner spool cannot be read.
pub fn start_backup_control(handle: &mut BackupControlHandle) -> Result<(), BackupControlError> {
    match handle.state {
        BackupControlState::Started => {
            return Err(BackupControlError::Composition(
                CompositionError::InvalidConfiguration(
                    "watchdog backup control is already started".to_owned(),
                ),
            ));
        }
        BackupControlState::Released => {
            return Err(BackupControlError::Composition(
                CompositionError::InvalidConfiguration(
                    "watchdog backup control cannot start a released registration".to_owned(),
                ),
            ));
        }
        BackupControlState::Registered => {}
    }
    if !handle.registration.is_registered(handle.slot) {
        return Err(BackupControlError::Composition(
            CompositionError::InvalidConfiguration(
                "watchdog backup control handle does not hold a live bounded registration slot"
                    .to_owned(),
            ),
        ));
    }
    handle.binding = BackupOwnerBinding::observe(
        &handle.port,
        handle.binding.service,
        handle.binding.protocol,
    )
    .map_err(BackupControlError::OwnerRefused)?;
    handle.admission = handle.admission.reobserved(&handle.port);
    handle.state = BackupControlState::Started;
    Ok(())
}

/// Releases one SHARED, started backup-control registration.
///
/// Same release as [`stop_backup_control`] — it releases the bounded slot in the
/// registering composition's own table and reports the operations this
/// composition still holds unresolved — but it borrows instead of consuming, so a
/// supervised ingress task and the composition's release point can share ONE
/// handle rather than the listener holding a registration the release path cannot
/// see. Releasing an already-released slot is a no-op and a second call is
/// therefore harmless, while a handle whose slot is released can no longer
/// dispatch: `require_dispatchable` re-checks the live slot on every request.
pub fn release_shared_backup_control(handle: &std::sync::Arc<BackupControlHandle>) {
    let unresolved = handle
        .registration
        .unresolved()
        .unwrap_or(UNRESOLVED_COUNT_UNREADABLE);
    // Bounded, redacted diagnostics: two integers and the slot, never payload text,
    // owner internals, or identity material.
    tracing::warn!(
        event = "watchdog.backup_control_stopped",
        registration_slot = handle.slot,
        unresolved_operations = unresolved,
        retained_operation_bound = MAX_RETAINED_BACKUP_OPERATIONS,
        "watchdog backup control released; unresolved owner operations remain retained"
    );
    handle.registration.release(handle.slot);
}

/// Stops backup control with bounded cleanup.
///
/// Consumes the handle, releases its bounded registration slot in the
/// registering composition's table, and reports the operations this composition
/// still holds unresolved — the ones it entered at the owner without a known
/// result. That count is read from the composition's own retained records, so
/// a shutdown reports real unresolved work; it is never a constant and never a
/// fresh zero. A released handle can no longer dispatch and can no longer be
/// started, so a later stop is a no-op rather than a double release and a
/// stopped handle cannot be revived. Releasing an already-released slot is
/// itself a no-op. There is no background work to join because registration
/// never spawned any.
pub fn stop_backup_control(handle: BackupControlHandle) -> BackupControlHandle {
    let unresolved = handle
        .registration
        .unresolved()
        .unwrap_or(UNRESOLVED_COUNT_UNREADABLE);
    // Bounded, redacted shutdown diagnostics: two integers and the slot, never
    // payload text, owner internals or identity material. It reports the
    // composition's retained evidence and cannot alter the release below.
    tracing::warn!(
        event = "watchdog.backup_control_stopped",
        registration_slot = handle.slot,
        unresolved_operations = unresolved,
        retained_operation_bound = MAX_RETAINED_BACKUP_OPERATIONS,
        "watchdog backup control released; unresolved owner operations remain retained"
    );
    handle.registration.release(handle.slot);
    BackupControlHandle {
        slot: handle.slot,
        state: BackupControlState::Released,
        binding: handle.binding,
        admission: handle.admission,
        port: handle.port,
        registration: handle.registration,
    }
}
