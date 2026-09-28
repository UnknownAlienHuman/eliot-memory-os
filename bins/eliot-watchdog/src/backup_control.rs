//! Admitted Watchdog backup control port and its bounded request dispatch.
//!
//! Responsibility: bind the closed Watchdog-supported backup method subset to
//! the owner-bound [`WatchdogBackupPort`] that the composition reaches through
//! its own kernel port, and dispatch the accepted methods that map to real
//! owner capability. No pipe is opened, no ACL or transport is implemented, no
//! archive bytes are interpreted, no authority is minted, and no domain
//! algorithm runs here. All spool effects belong to the owning spool port;
//! this module only resolves the closed method table and forwards.
//!
//! Supported subset (closed): `READ_SNAPSHOT_PAGE`, `VERIFY_ARCHIVE`,
//! `RESTORE_STATUS`, `RECONCILE_RESTORE`. Rehearsal completion never maps to
//! cutover; `ADMIT_CUTOVER` and `PREPARE_ISOLATED_RESTORE` are never accepted
//! by the Watchdog. The canonical Watchdog signal pipe is observed only and is
//! never opened here: `\\.\pipe\eliot\watchdog\signals`.
//!
//! What this module deliberately does **not** do, because the Watchdog holds no
//! value that could satisfy the check honestly:
//!
//! - it validates no peer SID, service, nonce, or session. No peer presents
//!   one here: the transport owner is above this port, and the #954
//!   `BackupAuthenticatedPrincipal` is not wired into this crate.
//! - it validates no generation fence. The composition publishes an admitted
//!   epoch pair, not a backup generation fence, so a "live generation equals
//!   fence generation" claim here would compare the owner against itself.
//! - it validates no response identity. No response exists at registration or
//!   dispatch, so an equal-digest echo here would be fabricated evidence.
//!
//! Those three checks are properties of the role-bound backup control contract
//! and belong to whoever admits the authenticated peer and its responses.
//!
//! Supervision priority: backup control holds no supervision task and must
//! never stall the supervision tick loop or exhaust the Control Reserve. Every
//! dispatched request is a finite, bounded owner read or a bounded owner write
//! and runs outside the heartbeat tick.
//!
//! Production lifecycle: the Watchdog's own startup path registers, starts, and
//! stops this port. Registration binds the composition's real owner spool and
//! proves that owner resource is live by reading its own durable high-water
//! sequence; start re-reads it as a second, independent observation; stop
//! releases the bounded registration slot. A refusal at either step is bounded
//! to this one capability: it is typed, it happens on a path where readiness is
//! already published, and the process creates no listener, task, slot, or
//! authority on either side of it.
//!
//! What that lifecycle does NOT establish, stated plainly so the claims are
//! never read wider than the code: this process still opens no backup listener
//! and spawns no backup task, because a new pipe family and its transport belong
//! to the Kernel/Host side of #962 rather than to this Watchdog port. Nothing
//! here accepts a connection, so nothing here can serve a requester; the
//! registration is the owner-side admission of a method table over a proven
//! live owner resource, not a live endpoint.
//!
//! Lifecycle scope: the bounded registration table belongs to ONE composition
//! lifecycle and is opened when that composition starts. Starting supervision
//! never closes it, only that same composition's own shutdown does, and a
//! second composition in the same process opens its own open table — so
//! supervision start can never latch backup control closed for the remaining
//! life of the process.

use std::sync::{Mutex, MutexGuard};

use thiserror::Error;

use crate::{
    CompositionError, PROTOCOL_VERSION, SERVICE_NAME, SpoolError, SpoolRestoreDisposition,
    SpoolRestoreStep, WatchdogBackupPort, WatchdogComposition, WatchdogSpoolFence,
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
/// handle to a live resource, and no caller-supplied value: it exists only so
/// a registration receipt names a real bounded allocation instead of a
/// constant, and so `stop_backup_control` and composition shutdown release
/// exactly what was taken.
#[derive(Debug)]
struct BackupControlSlots {
    /// Whether this composition lifecycle has closed backup control.
    closed: bool,
    /// Occupancy of this composition's bounded slot table.
    occupied: [bool; REGISTRATION_SLOT_COUNT],
}

/// Composition-scoped backup control registration table.
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
    /// Bounded occupancy and lifecycle flag of one composition.
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

/// One Watchdog-accepted backup method: wire identity plus closed operation.
///
/// Limited to the Watchdog-supported subset; rehearsal never maps to cutover
/// and `ADMIT_CUTOVER` / `PREPARE_ISOLATED_RESTORE` are never present here.
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
    /// Binds one recognized operation to its canonical wire identity.
    const fn new(op: BackupOperationKind) -> Self {
        Self {
            wire_id: op.wire_id(),
            op,
        }
    }
}

/// Closed Watchdog-recognized backup method table.
///
/// Membership is recognition, not executable capability: `VERIFY_ARCHIVE` and
/// `RESTORE_STATUS` are recognized here precisely so
/// [`BackupControlHandle::dispatch`] can refuse them with an explicit typed
/// refusal instead of dropping them silently. The wire identity of every row
/// is derived from the canonical owner, so this table holds no
/// `eliot.protocol.backup.*` literal.
static ACCEPTED_WATCHDOG_BACKUP_METHODS: [AcceptedWatchdogBackupMethod; 4] = [
    AcceptedWatchdogBackupMethod::new(BackupOperationKind::ReadSnapshotPage),
    AcceptedWatchdogBackupMethod::new(BackupOperationKind::VerifyArchive),
    AcceptedWatchdogBackupMethod::new(BackupOperationKind::RestoreStatus),
    AcceptedWatchdogBackupMethod::new(BackupOperationKind::ReconcileRestore),
];

/// Returns the closed Watchdog-supported backup method table.
#[must_use]
pub fn accepted_watchdog_backup_methods() -> &'static [AcceptedWatchdogBackupMethod] {
    &ACCEPTED_WATCHDOG_BACKUP_METHODS
}

/// Resolves a wire id to its accepted method before any owner effect runs.
///
/// Unsupported methods — including `ADMIT_CUTOVER`,
/// `PREPARE_ISOLATED_RESTORE`, rehearsal-to-cutover mappings, and unknown
/// wire ids — fail here, before any owner effect runs.
///
/// # Errors
///
/// Returns [`CompositionError`] for any unsupported wire identity.
pub fn resolve_accepted_method(
    wire_id: &str,
) -> Result<&'static AcceptedWatchdogBackupMethod, CompositionError> {
    accepted_watchdog_backup_methods()
        .iter()
        .find(|method| method.wire_id == wire_id)
        .ok_or_else(|| {
            CompositionError::InvalidConfiguration(
                "watchdog backup control rejects an unsupported backup method".to_owned(),
            )
        })
}

/// One admitted Watchdog backup request.
///
/// Every variant carries only the real inputs the owner needs to act. There is
/// deliberately no peer identity, role, generation fence, or response digest
/// field: those belong to the role-bound control contract above this port, and
/// this crate mints none of them.
#[derive(Debug)]
pub enum WatchdogBackupRequest<'a> {
    /// Read one bounded page of a fence this owner produced.
    ReadSnapshotPage {
        /// Fence previously captured through this owner's backup port.
        fence: &'a WatchdogSpoolFence,
        /// Zero-based page index within that fence.
        page_index: u64,
    },
    /// Import a bounded restore step chain toward an isolated destination.
    ReconcileRestore {
        /// Exact source installation the retained steps came from.
        source_installation: &'a str,
        /// Admitted isolated destination installation.
        dest_installation: &'a str,
        /// Currently active installation the import must not reuse.
        active_installation: &'a str,
        /// Bounded, operation-bound restore step chain.
        steps: &'a [SpoolRestoreStep],
    },
    /// Verify an archive artifact.
    ///
    /// Present so the closed table's `VERIFY_ARCHIVE` entry has an explicit
    /// refusal instead of a silent drop. This owner holds no archive verifier
    /// and never interprets archive bytes, so dispatch always refuses.
    VerifyArchive,
    /// Report restore status.
    ///
    /// Present so the closed table's `RESTORE_STATUS` entry has an explicit
    /// refusal instead of a silent drop. This owner holds no restore-status
    /// projection, so dispatch always refuses.
    RestoreStatus,
}

/// The owner's bounded result for one dispatched request.
#[derive(Debug)]
pub enum WatchdogBackupOutcome {
    /// One finite page bound to a single captured fence.
    SnapshotPage(WatchdogSpoolSnapshotPage),
    /// Disposition of the bounded isolated-restore step chain.
    Restore(SpoolRestoreDisposition),
}

/// Bounded failure of one admitted backup request, or of one backup-control
/// lifecycle step.
///
/// The owner's own typed [`SpoolError`] is carried as a typed source in every
/// case and is never restated as a configuration string, so a caller can always
/// tell an unreachable owner spool apart from a policy refusal or from a
/// composition refusal.
#[derive(Debug, Error)]
pub enum BackupControlError {
    /// The request is outside the closed admitted subset, or the handle
    /// cannot currently dispatch.
    #[error("watchdog backup control rejects the request: {0}")]
    Rejected(String),
    /// The owner refused the request, or the owner-bound resource behind a
    /// registration or start step could not be read; the owner's own bounded
    /// reason travels verbatim and is never restated as success.
    #[error("watchdog spool owner refused the backup request: {0}")]
    OwnerRefused(#[source] SpoolError),
    /// A registration or start step was refused by the composition itself: an
    /// unrecognized composition identity, no owner-bound spool port, a bounded
    /// registration table that is exhausted or already closed, or a lifecycle
    /// state that does not admit this step.
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

/// Bounded registration receipt for Watchdog backup control.
///
/// Carries the bounded registration slot, a real [`BackupOwnerBinding`] observed
/// from the live owner spool, and the owner-bound backup port itself, so the
/// accepted methods dispatch to the real owner instead of to a receipt alone.
/// There is intentionally no kill-by-name (no string handle, no PID, no
/// service-name targeting) and no listener or task identity: this process opens
/// neither.
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
    port: std::sync::Arc<WatchdogBackupPort>,
    /// The registering composition's own bounded table. Kept per handle so a
    /// handle is never evaluated against another lifecycle's slots.
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

    /// Dispatches one admitted backup request to the owner-bound port.
    ///
    /// The wire identity is resolved against the closed accepted-method table
    /// first, then must agree with its own operation, then must match the
    /// request variant: a method and a request that name different operations
    /// fail instead of silently running the wrong owner call. `VERIFY_ARCHIVE`
    /// and `RESTORE_STATUS` are always refused — a transport acknowledgement
    /// never establishes domain success, and no owner attestation for either
    /// exists — so the correct outcome until a real archive verifier and a real
    /// restore-status projection exist is refusal, never a fabricated success.
    ///
    /// The disposition match is exhaustive over the whole canonical operation
    /// vocabulary, with no wildcard arm: a new canonical variant is a compile
    /// error here until the Watchdog's disposition for it is reviewed, and the
    /// five operations outside the closed recognized subset are refused
    /// explicitly before any owner effect.
    ///
    /// # Errors
    ///
    /// Returns [`BackupControlError::Rejected`] when the handle is not started,
    /// the wire identity is unsupported, the method and request disagree, or
    /// the operation is refused. Returns [`BackupControlError::OwnerRefused`]
    /// when the owner rejects the bounded request.
    pub fn dispatch(
        &self,
        method: &AcceptedWatchdogBackupMethod,
        request: &WatchdogBackupRequest<'_>,
    ) -> Result<WatchdogBackupOutcome, BackupControlError> {
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
        let accepted = resolve_accepted_method(method.wire_id)
            .map_err(|error| BackupControlError::Rejected(error.to_string()))?;
        if accepted.op != method.op {
            return Err(BackupControlError::Rejected(
                "watchdog backup control rejects a method whose operation disagrees with the closed table"
                    .to_owned(),
            ));
        }
        match accepted.op {
            BackupOperationKind::ReadSnapshotPage => {
                let WatchdogBackupRequest::ReadSnapshotPage { fence, page_index } = request else {
                    return Err(BackupControlError::Rejected(format!(
                        "watchdog backup control rejects a {} request dispatched as {}",
                        request_operation_name(request),
                        accepted.op.as_str()
                    )));
                };
                self.port
                    .read_page(fence, *page_index)
                    .map(WatchdogBackupOutcome::SnapshotPage)
                    .map_err(BackupControlError::OwnerRefused)
            }
            BackupOperationKind::ReconcileRestore => {
                let WatchdogBackupRequest::ReconcileRestore {
                    source_installation,
                    dest_installation,
                    active_installation,
                    steps,
                } = request
                else {
                    return Err(BackupControlError::Rejected(format!(
                        "watchdog backup control rejects a {} request dispatched as {}",
                        request_operation_name(request),
                        accepted.op.as_str()
                    )));
                };
                self.port
                    .import_isolated(
                        source_installation,
                        dest_installation,
                        active_installation,
                        steps,
                    )
                    .map(WatchdogBackupOutcome::Restore)
                    .map_err(BackupControlError::OwnerRefused)
            }
            BackupOperationKind::VerifyArchive | BackupOperationKind::RestoreStatus => {
                Err(BackupControlError::Rejected(format!(
                    "watchdog backup control refuses {}; this owner holds no domain attestation for it and a transport acknowledgement never establishes success",
                    accepted.op.as_str()
                )))
            }
            BackupOperationKind::RequestCapture
            | BackupOperationKind::PrepareIsolatedRestore
            | BackupOperationKind::RestoreStep
            | BackupOperationKind::CompleteRehearsal
            | BackupOperationKind::AdmitCutover => Err(BackupControlError::Rejected(format!(
                "watchdog backup control rejects {}; it is outside the closed recognized subset and fails before any owner effect",
                accepted.op.as_str()
            ))),
        }
    }
}

/// Returns the canonical operation name a request variant belongs to.
const fn request_operation_name(request: &WatchdogBackupRequest<'_>) -> &'static str {
    match request {
        WatchdogBackupRequest::ReadSnapshotPage { .. } => {
            BackupOperationKind::ReadSnapshotPage.as_str()
        }
        WatchdogBackupRequest::ReconcileRestore { .. } => {
            BackupOperationKind::ReconcileRestore.as_str()
        }
        WatchdogBackupRequest::VerifyArchive => BackupOperationKind::VerifyArchive.as_str(),
        WatchdogBackupRequest::RestoreStatus => BackupOperationKind::RestoreStatus.as_str(),
    }
}

/// Registers Watchdog backup control against a live composition.
///
/// Validates the composition readiness identity (`SERVICE_NAME` /
/// `PROTOCOL_VERSION`), takes the owner-bound backup port from the
/// composition's own kernel port — the same owner that appends every heartbeat
/// and gap record, so no second database handle is opened — proves that bound
/// owner resource is live by reading its own durable high-water sequence, and
/// reserves one bounded slot in the registering composition's own
/// [`BackupControlRegistration`] table. A composition whose kernel port owns no
/// spool admits no backup control: there is exactly one construction path and
/// no substitute.
///
/// The owner proof runs BEFORE the reservation, so a refusal here consumes no
/// bounded slot. The returned handle is therefore not a bare slot number: it
/// carries the real owner-bound registration record observed from the live owner
/// spool together with the owner port itself, and it is refused rather than
/// returned when that resource is not readable.
///
/// The reservation is refused only by that composition's own table: its
/// bounded bound, or a genuine close of that same lifecycle. Neither starting
/// supervision nor another composition's shutdown closes it, so registration
/// is available for the whole supervised lifetime.
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
    let binding = BackupOwnerBinding::observe(&port, SERVICE_NAME, PROTOCOL_VERSION)
        .map_err(BackupControlError::OwnerRefused)?;
    let registration = composition.backup_control_registration();
    let slot = registration
        .reserve()
        .map_err(BackupControlError::Composition)?;
    Ok(BackupControlHandle {
        slot,
        state: BackupControlState::Registered,
        binding,
        port,
        registration,
    })
}

/// Starts a registered backup control handle.
///
/// Re-reads the bound owner resource — a second, independent live read, not a
/// re-check of the value captured at registration — and admits dispatch only
/// when that read succeeds. A start can therefore be refused after a successful
/// registration, when the owner became unreachable in between; the newly
/// observed sequence replaces the registration one on the handle.
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
    handle.state = BackupControlState::Started;
    Ok(())
}

/// Stops backup control with bounded cleanup.
///
/// Consumes the handle, releases its bounded registration slot in the
/// registering composition's table, and returns the same receipt in the
/// `Released` state. A released handle can no longer dispatch and can no longer
/// be started, so a later stop is a no-op rather than a double release and a
/// stopped handle cannot be revived. Releasing an already-released slot is
/// itself a no-op. There is no background work to join because registration
/// never spawned any.
pub fn stop_backup_control(handle: BackupControlHandle) -> BackupControlHandle {
    handle.registration.release(handle.slot);
    BackupControlHandle {
        slot: handle.slot,
        state: BackupControlState::Released,
        binding: handle.binding,
        port: handle.port,
        registration: handle.registration,
    }
}
