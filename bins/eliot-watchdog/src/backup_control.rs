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
//! Supported subset (closed): the methods the `#954` owner table attributes to
//! a backup owner role this process actually holds. `READ_SNAPSHOT_PAGE` is the
//! one executable method: it reaches the `#955` spool capture owner
//! ([`WatchdogBackupPort::snapshot`]) and then reads the requested page from the
//! fence that owner retained. `RESTORE_STEP`, `RECONCILE_RESTORE`,
//! `VERIFY_ARCHIVE` and `RESTORE_STATUS` are recognized so an absent method
//! fails with an explicit typed refusal instead of vanishing, and are refused
//! before any owner effect. `ADMIT_CUTOVER` and `PREPARE_ISOLATED_RESTORE` are
//! never accepted here: preparation and cutover are the Host owner's
//! separately admitted operations, and rehearsal completion never maps to
//! cutover.
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
//! stops this channel. Registration binds the composition's real owner spool
//! and proves that owner resource is live by reading its own durable high-water
//! sequence; start re-reads it and re-observes the authenticated context as a
//! second, independent observation; stop releases the bounded registration slot
//! and reports the operations this composition still holds unresolved. A
//! refusal at either step is bounded to this one capability: it is typed, it
//! happens on a path where readiness is already published, and the process
//! creates no listener, task, slot, or authority on either side of it.
//!
//! What that lifecycle does NOT establish, stated plainly so the claims are
//! never read wider than the code: this process still opens no backup listener
//! and spawns no backup task.
//!
//! The reason is no longer a missing dependency. `eliot-watchdog` DOES declare
//! the `eliot-ipc` edge and DOES use its bounded framed codec on the path that
//! already exists here — the outbound Kernel front-door intent exchange in
//! `watchdog_spool::export_driver`. What is still absent is the *server* side:
//! no process in this repository creates the canonical
//! `\\.\pipe\eliot\watchdog\signals` server. `EliotPipeName::watchdog_signals`
//! names the pipe and `bins/eliot-kernel/src/backup_owner_clients.rs` names it
//! as the client endpoint, but nothing binds or serves it, and this crate is
//! only ever the *client* of the Kernel front door. There is therefore no
//! existing canonical signals-transport message arm for a backup request to be
//! added beside, and the typed backup request/response carrier this arm would
//! have to reuse lives in `eliot-host-service`, which this crate does not
//! depend on.
//!
//! So the authenticated context above is derived from this composition's
//! retained admission state rather than from a live transport peer observation,
//! and the transport peer SID, service, nonce, and session checks belong to a
//! listener that does not exist yet — not to this module. Adding that listener
//! is a separate prerequisite, and until it exists no backup request can reach
//! this handle over any transport at all.
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

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use thiserror::Error;

use eliot_protocol::backup::{
    BackupError, BackupRole, BackupSnapshotPageRead, BackupStage, attesting_roles,
    operation_for_phase,
};

use crate::{
    CaptureFenceParams, CompositionError, PROTOCOL_VERSION, SERVICE_NAME, SpoolError,
    WatchdogBackupPort, WatchdogComposition, WatchdogSpoolBackupLimits, WatchdogSpoolFence,
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
/// the owner function [`operation_for_phase`]. Every accept/reject decision
/// below is taken from the owner's own [`operation_for_phase`] and
/// [`attesting_roles`] functions, so a new canonical stage or a change to the
/// owner's role matrix reaches this module without any edit here.
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
/// accepted operations on its own.
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
/// Membership is the registration, and it is complete against the `#954`
/// owner's own table: every operation that owner's `attesting_roles` matrix
/// attributes to a role this process holds has exactly one row here, and no
/// operation outside that set does. `verify_registration_is_complete` re-derives
/// that expected set from the owner on every call, so the check compares
/// against an independent source rather than against this same list.
///
/// Only [`BackupOperationKind::ReadSnapshotPage`] is executable on this owner;
/// the remaining rows exist so an absent method fails with an explicit typed
/// refusal instead of vanishing from the closed table.
static ACCEPTED_WATCHDOG_BACKUP_METHODS: [AcceptedWatchdogBackupMethod; 5] = [
    AcceptedWatchdogBackupMethod::new(BackupOperationKind::ReadSnapshotPage),
    AcceptedWatchdogBackupMethod::new(BackupOperationKind::RestoreStep),
    AcceptedWatchdogBackupMethod::new(BackupOperationKind::ReconcileRestore),
    AcceptedWatchdogBackupMethod::new(BackupOperationKind::VerifyArchive),
    AcceptedWatchdogBackupMethod::new(BackupOperationKind::RestoreStatus),
];

/// Returns the closed Watchdog-registered backup method table.
#[must_use]
pub fn accepted_watchdog_backup_methods() -> &'static [AcceptedWatchdogBackupMethod] {
    &ACCEPTED_WATCHDOG_BACKUP_METHODS
}

/// The operations the `#954` owner's own role matrix attributes to a backup
/// owner role this Watchdog process holds.
///
/// Derived by inverting the owner's own [`operation_for_phase`] and consulting
/// its own [`attesting_roles`]; it is never a list a caller supplies, so
/// comparing the registered table against it proves completeness against the
/// owner rather than against a second copy of itself.
fn owner_table_operations() -> Vec<BackupOperationKind> {
    BACKUP_STAGES
        .into_iter()
        .filter(|stage| {
            attesting_roles(*stage)
                .iter()
                .any(|role| WATCHDOG_OWNER_ROLES.contains(role))
        })
        .map(operation_for_phase)
        .collect()
}

/// Returns whether the registered table covers the owner's complete accepted
/// method set for the roles this owner holds, and covers nothing else.
///
/// Two independent comparisons, both against the owner: every operation the
/// owner attributes to a held role must have a registered row, and every
/// registered row must be an operation the owner attributes to a held role.
/// A missing row is an incomplete registration; an extra row is an operation
/// this owner never claimed.
#[must_use]
pub fn verify_registration_is_complete() -> bool {
    let expected = owner_table_operations();
    let registered = accepted_watchdog_backup_methods();
    expected
        .iter()
        .all(|op| registered.iter().any(|method| method.op == *op))
        && registered
            .iter()
            .all(|method| expected.contains(&method.op))
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
fn executable_owner_method(operation: BackupOperationKind) -> Result<(), SpoolError> {
    match operation {
        BackupOperationKind::ReadSnapshotPage => Ok(()),
        BackupOperationKind::RestoreStep => Err(SpoolError::Corrupt(
            "watchdog backup control recognizes RESTORE_STEP but holds no restore-step owner method; it is advertised as unavailable rather than supported"
                .to_owned(),
        )),
        BackupOperationKind::ReconcileRestore => Err(SpoolError::Corrupt(
            "watchdog backup control recognizes RECONCILE_RESTORE but the canonical reconcile request carries no source, destination, active-installation or step body this owner could consume; it is advertised as unavailable rather than supported"
                .to_owned(),
        )),
        BackupOperationKind::VerifyArchive => Err(SpoolError::Corrupt(
            "watchdog backup control refuses VERIFY_ARCHIVE; this owner holds no archive verifier and never interprets archive bytes, and a transport acknowledgement never establishes success"
                .to_owned(),
        )),
        BackupOperationKind::RestoreStatus => Err(SpoolError::Corrupt(
            "watchdog backup control refuses RESTORE_STATUS; this owner holds no restore-status projection, and a transport acknowledgement never establishes success"
                .to_owned(),
        )),
        BackupOperationKind::RequestCapture
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

/// One request this owner admitted, resolved to its exact method.
///
/// Its fields are private and the only constructor is
/// [`BackupControlHandle::admit`], so it cannot be built by a caller that
/// skipped admission: the payload's own operation string is never what selects
/// the owner operation, and the owner operation is never what grants the
/// payload authority.
#[derive(Clone, Debug)]
pub struct AdmittedWatchdogBackupRequest {
    method: &'static AcceptedWatchdogBackupMethod,
    request: BackupSnapshotPageRead,
}

/// The owner's own retained result for one admitted operation.
///
/// Every variant carries the owner's own values, read from the owner that
/// produced them, never a value copied out of the request that asked for them.
#[derive(Clone, Debug)]
pub enum WatchdogBackupChannelOutcome {
    /// The `#955` spool capture owner produced one bounded fence for this exact
    /// operation, and the requested page was read from that retained fence.
    Capture {
        /// The fence the capture owner retained for this operation.
        fence: WatchdogSpoolFence,
        /// The bounded page read from that retained fence.
        page: WatchdogSpoolSnapshotPage,
    },
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
    /// Every gate below runs before the owner is entered, so a refused request
    /// has provably taken no effect. None of them compares the request against
    /// itself, and none of them reads an owner or a policy out of the payload:
    ///
    /// 1. the handle is started and still holds its bounded registration slot;
    /// 2. the `#954` contract validates the presented request, which re-derives
    ///    its own digests, bounds, fence exactness and role/capability matrix
    ///    through the owner's own [`BackupSnapshotPageRead::validate`];
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
    ///    no authority over is refused.
    ///
    /// # Errors
    ///
    /// Returns [`BackupControlError::Rejected`] for a handle that cannot
    /// dispatch, an operation this owner has no registered row for, a request
    /// whose operation and registered row disagree, or any gate 4 to 7
    /// failure. Returns [`BackupControlError::Contract`] when the `#954`
    /// contract refuses the presented request.
    pub fn admit(
        &self,
        request: &BackupSnapshotPageRead,
    ) -> Result<AdmittedWatchdogBackupRequest, BackupControlError> {
        self.require_dispatchable()?;
        request.validate().map_err(BackupControlError::Contract)?;
        let method = resolve_accepted_method(request.operation.wire_id())?;
        if method.op != request.operation {
            return Err(BackupControlError::Rejected(format!(
                "watchdog backup control rejects a {} request dispatched as {}",
                request.operation, method.op
            )));
        }
        if request.identity.principal.session_id != self.admission.session_id {
            return Err(BackupControlError::Rejected(
                "watchdog backup control rejects a request for a foreign admitted session"
                    .to_owned(),
            ));
        }
        if request.identity.fence.resource_generation.value() != self.admission.owner_generation {
            return Err(BackupControlError::Rejected(
                "watchdog backup control rejects a request for a stale generation fence".to_owned(),
            ));
        }
        if request.identity.source_installation != self.admission.owner_installation {
            return Err(BackupControlError::Rejected(
                "watchdog backup control rejects a request for a foreign source installation"
                    .to_owned(),
            ));
        }
        if watchdog_attesting_role(request.operation).is_none() {
            return Err(BackupControlError::Rejected(format!(
                "watchdog backup control rejects {}; no backup owner role this process holds attests it",
                request.operation
            )));
        }
        Ok(AdmittedWatchdogBackupRequest {
            method,
            request: request.clone(),
        })
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
        admitted: &AdmittedWatchdogBackupRequest,
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
        let identity = &admitted.request.identity;
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
    /// The executable set is decided by [`executable_owner_method`], which runs
    /// before the operation is claimed, so this match has exactly one reachable
    /// owner call and every other arm is the same pre-effect refusal.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when this owner has no executable method for the
    /// admitted operation, or when the owner itself refuses the bounded read.
    fn run_owner_operation(
        &self,
        admitted: &AdmittedWatchdogBackupRequest,
    ) -> Result<WatchdogBackupChannelOutcome, SpoolError> {
        match admitted.method.op {
            BackupOperationKind::ReadSnapshotPage => {
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
                let identity = &admitted.request.identity;
                let fence = self.port.snapshot(
                    CaptureFenceParams {
                        source_installation: identity.source_installation.clone(),
                        watchdog_generation: self.admission.owner_generation,
                        requester_principal: identity.principal.principal.clone(),
                        snapshot_operation_id: identity.mutation.canonical_request_hash.clone(),
                        canonical_ref: None,
                        ors_ref: None,
                        coherence_fence_equal: false,
                    },
                    WatchdogSpoolBackupLimits::default(),
                )?;
                let page = self
                    .port
                    .read_page(&fence, admitted.request.page.page_index)?;
                Ok(WatchdogBackupChannelOutcome::Capture { fence, page })
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
    /// # Errors
    ///
    /// Returns [`BackupControlError::Rejected`] when any compared value
    /// diverges from the admitted operation or from the authenticated context.
    fn check_outcome_matches_operation(
        &self,
        admitted: &AdmittedWatchdogBackupRequest,
        outcome: &WatchdogBackupChannelOutcome,
    ) -> Result<(), BackupControlError> {
        let identity = &admitted.request.identity;
        let (fence, page) = match outcome {
            WatchdogBackupChannelOutcome::Capture { fence, page } => (fence, page),
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
        if page.page_index != admitted.request.page.page_index {
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
/// No listener is opened, no task is spawned, and no authority is minted; the
/// owning [`crate::KernelWatchdogPort`] implementation keeps all effects. The
/// handle is registered-but-not-yet-started; [`start_backup_control`] admits
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
    // The registration must cover the complete method set the `#954` owner
    // attributes to a role this process holds. The expected set is re-derived
    // from the owner's own role matrix here, so a table that dropped a method
    // or added one this owner never claimed refuses instead of serving a
    // partial or over-broad registration.
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
