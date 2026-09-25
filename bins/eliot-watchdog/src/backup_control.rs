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

use std::sync::Mutex;

use thiserror::Error;

use crate::{
    CompositionError, PROTOCOL_VERSION, SERVICE_NAME, SpoolError, SpoolRestoreDisposition,
    SpoolRestoreStep, WatchdogBackupPort, WatchdogComposition, WatchdogSpoolFence,
    WatchdogSpoolSnapshotPage,
};

/// Upper bound for concurrently registered backup control handles per process.
///
/// Registration is a bounded process-local slot, not a listener and not a
/// task: the Watchdog opens no backup listener and spawns no backup task, so
/// the receipt names only the registration slot it occupies. Registration
/// fails closed past this bound instead of growing an unbounded set.
pub const MAX_BACKUP_CONTROL_HANDLES: u64 = 8;

/// Number of bounded registration slots, derived from the declared ceiling.
///
/// Declared as its own literal rather than a truncating cast of the `u64`
/// ceiling, and pinned equal to it by the compile-time assertion below, so the
/// array length and the public bound can never disagree.
const REGISTRATION_SLOT_COUNT: usize = 8;

const _: () = assert!(REGISTRATION_SLOT_COUNT as u64 == MAX_BACKUP_CONTROL_HANDLES);

/// Bounded process-local registration table.
///
/// One `true` entry is one occupied slot. The table holds no authority, no
/// handle to a live resource, and no caller-supplied value: it exists only so
/// a registration receipt names a real bounded allocation instead of a
/// constant, and so `stop_backup_control` and composition shutdown release
/// exactly what was taken.
static REGISTRATION_SLOTS: Mutex<[bool; REGISTRATION_SLOT_COUNT]> =
    Mutex::new([false; REGISTRATION_SLOT_COUNT]);

/// Whether the composition has already closed backup control.
static REGISTRATION_CLOSED: Mutex<bool> = Mutex::new(false);

/// Closed backup operation vocabulary mirrored from the protocol wire
/// (`crates/foundation/eliot-protocol/src/backup.rs`, `BackupOperationKind`).
///
/// Local mirror so this composition root adds no new Cargo dependency and no
/// transport semantics; wire names match the protocol exactly.
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
    /// Returns the stable wire name of this operation.
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
}

/// One Watchdog-accepted backup method: wire identity plus closed operation.
///
/// Limited to the Watchdog-supported subset; rehearsal never maps to cutover
/// and `ADMIT_CUTOVER` / `PREPARE_ISOLATED_RESTORE` are never present here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedWatchdogBackupMethod {
    /// Stable protocol wire identity (mirrors `BACKUP_*_WIRE_ID`).
    pub wire_id: &'static str,
    /// Closed operation bound to the wire identity.
    pub op: BackupOperationKind,
}

/// Closed Watchdog-supported backup method table.
static ACCEPTED_WATCHDOG_BACKUP_METHODS: [AcceptedWatchdogBackupMethod; 4] = [
    AcceptedWatchdogBackupMethod {
        wire_id: "eliot.protocol.backup.snapshot-page-read",
        op: BackupOperationKind::ReadSnapshotPage,
    },
    AcceptedWatchdogBackupMethod {
        wire_id: "eliot.protocol.backup.archive-verification",
        op: BackupOperationKind::VerifyArchive,
    },
    AcceptedWatchdogBackupMethod {
        wire_id: "eliot.protocol.backup.restore-status",
        op: BackupOperationKind::RestoreStatus,
    },
    AcceptedWatchdogBackupMethod {
        wire_id: "eliot.protocol.backup.restore-reconcile",
        op: BackupOperationKind::ReconcileRestore,
    },
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

/// Bounded failure of one admitted backup request.
#[derive(Debug, Error)]
pub enum BackupControlError {
    /// The request is outside the closed admitted subset, or the handle
    /// cannot currently dispatch.
    #[error("watchdog backup control rejects the request: {0}")]
    Rejected(String),
    /// The owner refused the request; the owner's own bounded reason travels
    /// verbatim and is never restated as success.
    #[error("watchdog spool owner refused the backup request: {0}")]
    OwnerRefused(#[source] SpoolError),
}

/// Bounded registration receipt for Watchdog backup control.
///
/// Carries the bounded registration slot and the owner-bound backup port, so
/// the accepted methods dispatch to the real owner instead of a receipt alone.
/// There is intentionally no kill-by-name (no string handle, no PID, no
/// service-name targeting) and no listener or task identity: this process opens
/// neither.
///
/// The slot is released by [`stop_backup_control`] and by
/// [`on_composition_shutdown`]. A handle dropped without either holds its slot
/// until the composition shuts down, which is bounded and fails closed at
/// [`MAX_BACKUP_CONTROL_HANDLES`] rather than growing an unbounded set.
pub struct BackupControlHandle {
    slot: u64,
    active: bool,
    port: std::sync::Arc<WatchdogBackupPort>,
}

impl std::fmt::Debug for BackupControlHandle {
    /// Renders only the bounded registration facts, never the owner's spool
    /// internals or any identity material.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackupControlHandle")
            .field("registration_slot", &self.slot)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl BackupControlHandle {
    /// Returns the bounded registration slot this handle occupies.
    #[must_use]
    pub fn registration_slot(&self) -> u64 {
        self.slot
    }

    /// Returns whether the handle is started.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
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
        if !self.active {
            return Err(BackupControlError::Rejected(
                "watchdog backup control cannot dispatch before it is started".to_owned(),
            ));
        }
        if !slot_is_registered(self.slot) {
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
        match (accepted.op, request) {
            (
                BackupOperationKind::ReadSnapshotPage,
                WatchdogBackupRequest::ReadSnapshotPage { fence, page_index },
            ) => self
                .port
                .read_page(fence, *page_index)
                .map(WatchdogBackupOutcome::SnapshotPage)
                .map_err(BackupControlError::OwnerRefused),
            (
                BackupOperationKind::ReconcileRestore,
                WatchdogBackupRequest::ReconcileRestore {
                    source_installation,
                    dest_installation,
                    active_installation,
                    steps,
                },
            ) => self
                .port
                .import_isolated(
                    source_installation,
                    dest_installation,
                    active_installation,
                    steps,
                )
                .map(WatchdogBackupOutcome::Restore)
                .map_err(BackupControlError::OwnerRefused),
            (BackupOperationKind::VerifyArchive | BackupOperationKind::RestoreStatus, _) => {
                Err(BackupControlError::Rejected(format!(
                    "watchdog backup control refuses {}; this owner holds no domain attestation for it and a transport acknowledgement never establishes success",
                    accepted.op.as_str()
                )))
            }
            _ => Err(BackupControlError::Rejected(format!(
                "watchdog backup control rejects a {} request dispatched as {}",
                request_operation_name(request),
                accepted.op.as_str()
            ))),
        }
    }
}

/// Returns the closed operation name a request variant belongs to.
const fn request_operation_name(request: &WatchdogBackupRequest<'_>) -> &'static str {
    match request {
        WatchdogBackupRequest::ReadSnapshotPage { .. } => "READ_SNAPSHOT_PAGE",
        WatchdogBackupRequest::ReconcileRestore { .. } => "RECONCILE_RESTORE",
        WatchdogBackupRequest::VerifyArchive => "VERIFY_ARCHIVE",
        WatchdogBackupRequest::RestoreStatus => "RESTORE_STATUS",
    }
}

/// Registers Watchdog backup control against a live composition.
///
/// Validates the composition readiness identity (`SERVICE_NAME` /
/// `PROTOCOL_VERSION`), takes the owner-bound backup port from the
/// composition's own kernel port — the same owner that appends every heartbeat
/// and gap record, so no second database handle is opened — and reserves one
/// bounded registration slot. A composition whose kernel port owns no spool
/// admits no backup control: there is exactly one construction path and no
/// substitute.
///
/// No listener is opened, no task is spawned, and no authority is minted; the
/// owning [`crate::KernelWatchdogPort`] implementation keeps all effects.
///
/// # Errors
///
/// Returns [`CompositionError`] when the composition identity is unexpected,
/// when the composition exposes no owner-bound spool port, or when the bounded
/// registration table is exhausted or already closed.
pub fn register_backup_control(
    composition: &WatchdogComposition,
) -> Result<BackupControlHandle, CompositionError> {
    let readiness = composition.readiness();
    if readiness.service != SERVICE_NAME || readiness.protocol != PROTOCOL_VERSION {
        return Err(CompositionError::InvalidConfiguration(
            "watchdog backup control refuses an unrecognized composition identity".to_owned(),
        ));
    }
    let port = composition.owner_backup_port().ok_or_else(|| {
        CompositionError::InvalidConfiguration(
            "watchdog backup control refuses registration without an owner-held spool port"
                .to_owned(),
        )
    })?;
    let slot = reserve_registration_slot()?;
    Ok(BackupControlHandle {
        slot,
        active: false,
        port,
    })
}

/// Starts a registered backup control handle.
///
/// Marks the handle active so the accepted methods can be dispatched. Fails
/// closed when already active, when the composition has closed backup control,
/// or when the handle no longer holds a live bounded slot, so a second
/// registration can never be admitted past the bound.
///
/// # Errors
///
/// Returns [`CompositionError`] when the handle is already active or its slot
/// is no longer registered.
pub fn start_backup_control(handle: &mut BackupControlHandle) -> Result<(), CompositionError> {
    if handle.active {
        return Err(CompositionError::InvalidConfiguration(
            "watchdog backup control is already started".to_owned(),
        ));
    }
    if !slot_is_registered(handle.slot) {
        return Err(CompositionError::InvalidConfiguration(
            "watchdog backup control handle does not hold a live bounded registration slot"
                .to_owned(),
        ));
    }
    handle.active = true;
    Ok(())
}

/// Stops backup control with bounded cleanup.
///
/// Consumes the handle, releases its bounded registration slot, and returns
/// the same receipt marked stopped. The returned receipt is already released
/// and can no longer dispatch, so a later stop is a no-op rather than a double
/// release. There is no background work to join because registration never
/// spawned any.
pub fn stop_backup_control(handle: BackupControlHandle) -> BackupControlHandle {
    release_registration_slot(handle.slot);
    BackupControlHandle {
        slot: handle.slot,
        active: false,
        port: handle.port,
    }
}

/// Closes backup control during composition shutdown.
///
/// Every bounded registration slot is released, so no abandoned registration
/// outlives the composition, and any later registration fails closed. Shutdown
/// stays bounded: there is no task to join and this never blocks supervision
/// teardown.
pub fn on_composition_shutdown() {
    if let Ok(mut closed) = REGISTRATION_CLOSED.lock() {
        *closed = true;
    }
    if let Ok(mut slots) = REGISTRATION_SLOTS.lock() {
        slots.fill(false);
    }
}

/// Reserves the lowest free bounded registration slot, or fails closed.
fn reserve_registration_slot() -> Result<u64, CompositionError> {
    if *lock_closed()? {
        return Err(CompositionError::InvalidConfiguration(
            "watchdog backup control is closed for this composition lifecycle".to_owned(),
        ));
    }
    let mut slots = lock_slots()?;
    for (index, occupied) in slots.iter_mut().enumerate() {
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

/// Returns whether one bounded slot is currently reserved.
fn slot_is_registered(slot: u64) -> bool {
    if slot == 0 || slot > MAX_BACKUP_CONTROL_HANDLES {
        return false;
    }
    let Ok(index) = usize::try_from(slot - 1) else {
        return false;
    };
    lock_slots().is_ok_and(|slots| slots.get(index).copied().unwrap_or(false))
}

/// Releases one bounded registration slot; releasing a free slot is a no-op.
fn release_registration_slot(slot: u64) {
    let Ok(index) = usize::try_from(slot.saturating_sub(1)) else {
        return;
    };
    if let Ok(mut slots) = lock_slots()
        && let Some(occupied) = slots.get_mut(index)
    {
        *occupied = false;
    }
}

fn lock_slots()
-> Result<std::sync::MutexGuard<'static, [bool; REGISTRATION_SLOT_COUNT]>, CompositionError> {
    REGISTRATION_SLOTS.lock().map_err(|_| {
        CompositionError::InvalidConfiguration(
            "watchdog backup control cannot read its bounded registration table".to_owned(),
        )
    })
}

fn lock_closed() -> Result<std::sync::MutexGuard<'static, bool>, CompositionError> {
    REGISTRATION_CLOSED.lock().map_err(|_| {
        CompositionError::InvalidConfiguration(
            "watchdog backup control cannot read its lifecycle state".to_owned(),
        )
    })
}
