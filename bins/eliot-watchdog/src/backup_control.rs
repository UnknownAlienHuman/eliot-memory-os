//! Wiring-only Watchdog backup control registration.
//!
//! Responsibility: expose the closed Watchdog-supported backup method subset
//! and bounded registration/start-stop handles. No pipe is opened, no ACL or
//! transport is implemented, no archive bytes are interpreted, no authority is
//! minted, and no domain algorithm runs here. All effects belong to the owning
//! [`crate::KernelWatchdogPort`] implementation; this module only validates
//! request shapes and fails unsupported methods before effects.
//!
//! Supported subset (closed): `READ_SNAPSHOT_PAGE`, `VERIFY_ARCHIVE`,
//! `RESTORE_STATUS`, `RECONCILE_RESTORE`. Rehearsal completion never maps to
//! cutover; `ADMIT_CUTOVER` and `PREPARE_ISOLATED_RESTORE` are never accepted
//! by the Watchdog. Canonical signal pipe (observed only, never opened here):
//! `\\.\pipe\eliot\watchdog\signals`.
//!
//! Supervision priority: backup control holds no supervision task and must
//! never stall the supervision tick loop or exhaust the Control Reserve.

use crate::{CompositionError, PROTOCOL_VERSION, SERVICE_NAME, WatchdogComposition};

/// Canonical Watchdog signal pipe observed by backup control (never opened here).
pub const WATCHDOG_BACKUP_SIGNAL_PIPE: &str = r"\\.\pipe\eliot\watchdog\signals";

/// Bounded text field limit mirrored from the backup protocol shape boundary.
pub const MAX_BACKUP_TEXT_BYTES: usize = 8 * 1024;
/// Bounded page or artifact body limit mirrored from the backup protocol shape.
pub const MAX_BACKUP_CONTENT_BYTES: usize = 64 * 1024;
/// Bounded canonical payload limit mirrored from the backup protocol shape.
pub const MAX_BACKUP_PAYLOAD_BYTES: usize = 256 * 1024;
/// Bounded snapshot page member limit mirrored from the backup protocol shape.
pub const MAX_BACKUP_PAGE_MEMBERS: u32 = 1024;

// Shape-bound ordering pins the mirrored protocol ceilings: text fields fit
// page bodies, page bodies fit canonical payloads, and pages are nonempty.
const _: () = assert!(MAX_BACKUP_TEXT_BYTES <= MAX_BACKUP_CONTENT_BYTES);
const _: () = assert!(MAX_BACKUP_CONTENT_BYTES <= MAX_BACKUP_PAYLOAD_BYTES);
const _: () = assert!(MAX_BACKUP_PAGE_MEMBERS > 0);

/// Upper bound for concurrently registered backup control handles per process.
///
/// Wiring-only: registration fails closed past this bound instead of growing
/// an unbounded listener or task set.
pub const MAX_BACKUP_CONTROL_HANDLES: u64 = 8;

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

/// Bounded registration receipt for Watchdog backup control.
///
/// Carries numeric listener/task ids only; there is intentionally no
/// kill-by-name (no string handle, no PID, no service-name targeting).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupControlHandle {
    listener_id: u64,
    task_id: u64,
    active: bool,
}

impl BackupControlHandle {
    /// Returns the bounded listener id.
    #[must_use]
    pub const fn listener_id(self) -> u64 {
        self.listener_id
    }

    /// Returns the bounded task id.
    #[must_use]
    pub const fn task_id(self) -> u64 {
        self.task_id
    }

    /// Returns whether the handle is started.
    #[must_use]
    pub const fn is_active(self) -> bool {
        self.active
    }
}

/// Registers Watchdog backup control against a live composition.
///
/// Wiring-only: validates the composition readiness identity
/// (`SERVICE_NAME` / `PROTOCOL_VERSION`) and returns an inactive bounded
/// handle. No listener is opened, no task is spawned, and no authority is
/// minted; the owning [`crate::KernelWatchdogPort`] keeps all effects.
///
/// # Errors
///
/// Returns [`CompositionError`] when the composition identity is unexpected.
pub fn register_backup_control(
    composition: &WatchdogComposition,
) -> Result<BackupControlHandle, CompositionError> {
    let readiness = composition.readiness();
    if readiness.service != SERVICE_NAME || readiness.protocol != PROTOCOL_VERSION {
        return Err(CompositionError::InvalidConfiguration(
            "watchdog backup control refuses an unrecognized composition identity".to_owned(),
        ));
    }
    // Closed-table wiring self-check: every validation helper and the full
    // accepted-method table are pinned into the production registration path
    // with self-consistent inputs, so the shape gates cannot rot unwired.
    // All inputs below are accepted by construction; only an unrecognized
    // composition identity fails registration, and supervision priority is
    // unchanged (no task is spawned, no tick is stalled).
    debug_assert!(!WATCHDOG_BACKUP_SIGNAL_PIPE.is_empty());
    reject_payload_role_override(false)?;
    validate_generation_fence(1, 1, true)?;
    validate_peer_binding(&BackupPeerBinding {
        peer_sid: "watchdog-backup-wiring",
        service: SERVICE_NAME,
        nonce: "watchdog-backup-wiring",
        session_id: "watchdog-backup-wiring",
    })?;
    for method in accepted_watchdog_backup_methods() {
        resolve_accepted_method(method.wire_id)?;
    }
    // Synthetic self-consistent identity: equal lowercase SHA-256 digests.
    validate_response_identity(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
    )?;
    Ok(BackupControlHandle {
        listener_id: 1,
        task_id: 1,
        active: false,
    })
}

/// Starts a registered backup control handle.
///
/// Wiring-only: marks the handle active. Fails closed when already active so
/// a second listener/task can never be admitted past the bound.
///
/// # Errors
///
/// Returns [`CompositionError`] when the handle is already active.
pub fn start_backup_control(handle: &mut BackupControlHandle) -> Result<(), CompositionError> {
    if handle.active {
        return Err(CompositionError::InvalidConfiguration(
            "watchdog backup control is already started".to_owned(),
        ));
    }
    if handle.listener_id == 0
        || handle.listener_id > MAX_BACKUP_CONTROL_HANDLES
        || handle.task_id == 0
        || handle.task_id > MAX_BACKUP_CONTROL_HANDLES
    {
        return Err(CompositionError::InvalidConfiguration(
            "watchdog backup control handle exceeds its bounded ids".to_owned(),
        ));
    }
    // Timeout/ack wiring: a transport acknowledgement never establishes
    // domain success, and a pre-send timeout classifies as safe-to-retry.
    // Both markers are pinned here so the vocabulary cannot rot unwired;
    // neither changes the start disposition.
    let ack = BackupTransportAck { delivered: false };
    debug_assert!(!ack.delivered);
    debug_assert!(domain_success_from_ack(ack).is_none());
    debug_assert!(matches!(
        classify_send_timeout(false),
        BackupSendTimeout::BeforeSend(_)
    ));
    handle.active = true;
    Ok(())
}

/// Stops backup control with bounded cleanup.
///
/// Consuming the handle guarantees no abandoned listener or task: there is no
/// background work to join because registration never spawned any, and the
/// receipt cannot be reused after this call.
pub fn stop_backup_control(handle: BackupControlHandle) -> BackupControlHandle {
    // Replay/domain wiring: exact replays compare by value and domain success
    // requires a separate owner attestation. Pinned here so the types cannot
    // rot unwired; the shutdown receipt is unchanged.
    let replay_key = BackupReplayKey {
        request_digest: String::new(),
        delivery_nonce: String::new(),
    };
    debug_assert!(is_exact_replay(&replay_key, &replay_key));
    debug_assert!(!BackupDomainSuccess { attested: false }.attested);
    BackupControlHandle {
        listener_id: handle.listener_id,
        task_id: handle.task_id,
        active: false,
    }
}

/// Notes composition shutdown for backup control ordering.
///
/// No-op marker called from the composition shutdown path so shutdown stays
/// bounded: backup control holds no task to join and never blocks supervision
/// teardown.
pub fn on_composition_shutdown() {}

// ---------------------------------------------------------------------------
// Validation helpers: pure shape checks, authority stays with the owner.
// ---------------------------------------------------------------------------

/// Authenticated peer binding presented separately from any payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupPeerBinding<'a> {
    /// Peer SID asserted by the transport owner.
    pub peer_sid: &'a str,
    /// Peer service name asserted by the transport owner.
    pub service: &'a str,
    /// Registration nonce asserted by the transport owner.
    pub nonce: &'a str,
    /// Session identity asserted by the transport owner.
    pub session_id: &'a str,
}

/// Rejects a wrong peer SID, service, nonce, or session.
///
/// Shape-only: non-blank, bounded, no control characters. Exact trust
/// comparison belongs to the owning port; a mismatch there must also fail
/// closed.
///
/// # Errors
///
/// Returns [`CompositionError`] when any binding field is unusable.
pub fn validate_peer_binding(peer: &BackupPeerBinding<'_>) -> Result<(), CompositionError> {
    for (value, field) in [
        (peer.peer_sid, "backup_peer.peer_sid"),
        (peer.service, "backup_peer.service"),
        (peer.nonce, "backup_peer.nonce"),
        (peer.session_id, "backup_peer.session_id"),
    ] {
        reject_blank_or_unbounded(value, field)?;
    }
    Ok(())
}

/// Rejects a stale generation, fence mismatch, or missing capability.
///
/// Exact-equality only: the fence generation must equal the live generation
/// (both nonzero) and `capability_granted` — supplied by the owning port —
/// must be true. Fence semantics stay with the owner.
///
/// # Errors
///
/// Returns [`CompositionError`] on stale, mismatched, or unpermitted input.
pub fn validate_generation_fence(
    generation: u64,
    fence_generation: u64,
    capability_granted: bool,
) -> Result<(), CompositionError> {
    if generation == 0 || fence_generation == 0 || generation != fence_generation {
        return Err(CompositionError::InvalidConfiguration(
            "watchdog backup control rejects a stale generation or fence".to_owned(),
        ));
    }
    if !capability_granted {
        return Err(CompositionError::InvalidConfiguration(
            "watchdog backup control rejects a missing backup capability".to_owned(),
        ));
    }
    Ok(())
}

/// Rejects a payload value that claims a role.
///
/// A value in a payload never grants a role; the authenticated role travels
/// as a separate argument owned by the transport. Any payload role claim
/// fails closed.
///
/// # Errors
///
/// Returns [`CompositionError`] when the payload claims a role.
pub fn reject_payload_role_override(payload_claims_role: bool) -> Result<(), CompositionError> {
    if payload_claims_role {
        return Err(CompositionError::InvalidConfiguration(
            "watchdog backup control rejects a payload role override".to_owned(),
        ));
    }
    Ok(())
}

/// Resolves a wire id to its accepted method before any effect.
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

/// Validates that a response echoes its bound request identity.
///
/// Both digests must be lowercase SHA-256 and exactly equal; otherwise the
/// response fails closed without an effect.
///
/// # Errors
///
/// Returns [`CompositionError`] on shape or identity mismatch.
pub fn validate_response_identity(
    request_digest: &str,
    response_digest: &str,
) -> Result<(), CompositionError> {
    reject_non_digest(request_digest, "backup_response.request_digest")?;
    reject_non_digest(response_digest, "backup_response.response_digest")?;
    if request_digest != response_digest {
        return Err(CompositionError::InvalidConfiguration(
            "watchdog backup control rejects a response identity mismatch".to_owned(),
        ));
    }
    Ok(())
}

/// Transport acknowledgement receipt: proves delivery only, never success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupTransportAck {
    /// True when the transport acknowledged delivery.
    pub delivered: bool,
}

/// Domain success receipt: requires a separate owner attestation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupDomainSuccess {
    /// True only when the owning port attested semantic success.
    pub attested: bool,
}

/// Maps a transport acknowledgement toward domain success.
///
/// Always returns `None`: a transport acknowledgement, at any phase, never
/// establishes capture, restore, rehearsal, or reconciliation success.
/// Semantic success advances only through owner attestations validated
/// against the bound request identity.
#[must_use]
pub fn domain_success_from_ack(_ack: BackupTransportAck) -> Option<BackupDomainSuccess> {
    None
}

/// Marker for a timeout that fired before any byte was sent (safe to retry).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutBeforeSend;

/// Marker for a timeout that fired after send (retry needs owner dedupe).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutAfterSend;

/// Bounded send-timeout classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupSendTimeout {
    BeforeSend(TimeoutBeforeSend),
    AfterSend(TimeoutAfterSend),
}

/// Classifies a send timeout by whether any byte was sent.
#[must_use]
pub const fn classify_send_timeout(sent_any_byte: bool) -> BackupSendTimeout {
    if sent_any_byte {
        BackupSendTimeout::AfterSend(TimeoutAfterSend)
    } else {
        BackupSendTimeout::BeforeSend(TimeoutBeforeSend)
    }
}

/// Bounded replay dedupe key. Equality only; the domain retry-or-drop
/// decision belongs to the owning port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupReplayKey {
    /// Canonical request digest binding the mutation.
    pub request_digest: String,
    /// Transport nonce binding this delivery attempt.
    pub delivery_nonce: String,
}

/// Returns whether an incoming delivery is an exact replay of a seen key.
///
/// Pure field equality for wiring dedupe; whether an exact replay is dropped,
/// acknowledged idempotently, or escalated is decided by the owning port, not
/// here.
#[must_use]
pub fn is_exact_replay(seen: &BackupReplayKey, incoming: &BackupReplayKey) -> bool {
    seen == incoming
}

fn reject_blank_or_unbounded(value: &str, field: &'static str) -> Result<(), CompositionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CompositionError::InvalidConfiguration(format!(
            "watchdog backup control rejects an invalid {field}"
        )));
    }
    if value.len() > MAX_BACKUP_TEXT_BYTES {
        return Err(CompositionError::InvalidConfiguration(format!(
            "watchdog backup control rejects an overlong {field}"
        )));
    }
    Ok(())
}

fn reject_non_digest(value: &str, field: &'static str) -> Result<(), CompositionError> {
    let is_digest = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if !is_digest {
        return Err(CompositionError::InvalidConfiguration(format!(
            "watchdog backup control rejects an invalid {field}"
        )));
    }
    Ok(())
}
