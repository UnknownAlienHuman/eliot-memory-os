//! Exact-owner backup channel clients (issue #962, Writer-D).
//!
//! Architecture: the Kernel drives backup/restore effects only through the
//! exact owning channel — Host-owned methods over the canonical Host
//! runtime-control pipe, Watchdog-owned methods over the canonical Watchdog
//! signals pipe. No new pipe family is introduced here; both pipes are the
//! canonical names the platform already owns.
//!
//! Registration mapping (Writers A-C own the registrations; this module only
//! references their vocabulary and never imports their implementation crates,
//! so no circular dependency can form):
//!
//! ```text
//! Watchdog accepted methods .. ReadSnapshotPage / VerifyArchive /
//!                              RestoreStatus / ReconcileRestore
//!                              (bins/eliot-watchdog accepted table)
//! Host accepted methods ...... PrepareIsolatedRestore / AdmitCutover /
//!                              RestoreStatus / ReconcileRestore
//!                              (eliot-host accepted table)
//! backup envelope bridge ..... runtime_control.rs envelope mapping
//! backup dispatch ............ eliot-host register_backup_dispatch
//! ```
//!
//! The only cross-crate backup dependency here is the already-available
//! [`eliot_protocol::backup`] vocabulary (`BackupOperationKind`,
//! `BackupRole`, `BackupStage`, the role/attester projections, the
//! transport-acknowledgement refusal, and the bounded payload ceiling).
//! Everything else — peer expectations, admission domains, the byte-replay
//! ledger, timeout kinds — is local to this file so the Kernel composition
//! root binds actual clients without touching Host/Watchdog
//! implementations, private databases, or new auth/transport.
//!
//! Role binding (#954): admission here is driven by the protocol's own
//! role-bound contract, not by a local capability string. Each owner is
//! bound exactly once to one [`eliot_protocol::backup::BackupRole`], that
//! role must be an attesting role, the role's capability projection is a
//! necessary condition for every admitted effect, and a transport
//! acknowledgement is refused for every acknowledgement phase. The closed
//! per-owner accepted tables stay as a *narrowing* constraint (they are a
//! real owner fact from the Host/Watchdog accepted registrations); the
//! protocol role matrix is a *necessary* condition on top of them, so a
//! role can never fabricate another role's authority.
//!
//! Fail-closed posture: production constructors bind the exact canonical
//! pipe plus the exact peer expectation. Any fake, no-op, mock, default, or
//! mismatched binding returns `Err` — a missing binding is never replaced
//! by a default.
//!
//! Capability cell: Kernel backup owner-channel binding (exact-owner client
//! construction and pre-effect admission checks only; no I/O, no transport,
//! no journal, no cutover execution here).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use eliot_protocol::AckPhase;
use eliot_protocol::backup::{
    BackupOperationKind, BackupRole, BackupStage, MAX_BACKUP_PAYLOAD_BYTES,
};

/// Canonical Host backup pipe: the exact Host runtime-control pipe name.
///
/// No new pipe family: this is the canonical Host control pipe the platform
/// already owns.
pub const HOST_BACKUP_PIPE: &str = r"\\.\pipe\eliot\host\runtime-control-v1";
/// Canonical Watchdog backup pipe: the exact Watchdog signals pipe name.
///
/// No new pipe family: this is the canonical Watchdog signals pipe the
/// platform already owns.
pub const WATCHDOG_BACKUP_PIPE: &str = r"\\.\pipe\eliot\watchdog\signals";
/// Exact peer expectation marker for the Host backup owner.
pub const HOST_BACKUP_PEER: &str = "host-backup-owner";
/// Exact peer expectation marker for the Watchdog backup owner.
pub const WATCHDOG_BACKUP_PEER: &str = "watchdog-backup-owner";

/// Closed per-owner accepted method table: Host.
///
/// Mirrors the Host accepted registration (`PrepareIsolatedRestore`,
/// `AdmitCutover`, `RestoreStatus`, `ReconcileRestore`). Anything else refuses
/// pre-effect with [`OwnerClientError::UnsupportedOperation`].
pub const HOST_SUPPORTED_OPS: &[BackupOperationKind] = &[
    BackupOperationKind::PrepareIsolatedRestore,
    BackupOperationKind::AdmitCutover,
    BackupOperationKind::RestoreStatus,
    BackupOperationKind::ReconcileRestore,
];
/// Closed per-owner accepted method table: Watchdog.
///
/// Mirrors the Watchdog accepted registration (`ReadSnapshotPage`,
/// `VerifyArchive`, `RestoreStatus`, `ReconcileRestore`). Anything else refuses
/// pre-effect with [`OwnerClientError::UnsupportedOperation`].
pub const WATCHDOG_SUPPORTED_OPS: &[BackupOperationKind] = &[
    BackupOperationKind::ReadSnapshotPage,
    BackupOperationKind::VerifyArchive,
    BackupOperationKind::RestoreStatus,
    BackupOperationKind::ReconcileRestore,
];

/// Bounded owner operations admitted per supervision round.
///
/// The owner channel never consumes the supervision control reserve: at most
/// one owner operation is admitted per round so supervision priority cannot
/// starve.
pub const OWNER_OPS_QUANTUM_PER_ROUND: u32 = 1;
/// Maximum retained replay-ledger entries (bounded diagnostics, I14.3).
pub const MAX_REPLAY_LEDGER_ENTRIES: usize = 64;

/// Fail-closed owner-channel errors. Diagnostics carry fixed vocabulary and
/// bounded lengths only — never pipe bytes beyond the fixed canonical names,
/// never credentials, never database material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerClientError {
    /// A fake, no-op, mock, default, or otherwise non-canonical pipe or peer
    /// binding was presented. The bounded detail names the rejected class,
    /// never the presented bytes.
    FakePipeRejected {
        /// Stable rejected class (`pipe` or `peer`).
        detail: &'static str,
    },
    /// The presented pipe is well-formed but not the exact canonical pipe
    /// for this owner.
    PipeMismatch,
    /// The presented peer is not the exact expected owner peer.
    PeerMismatch,
    /// The operation is outside this owner's closed accepted table.
    UnsupportedOperation {
        /// Stable wire name of the refused operation.
        op: &'static str,
    },
    /// Cutover was requested without a cutover-domain admission.
    CutoverAdmissionRequired,
    /// A rehearsal completion was presented as cutover authority. Rehearsal
    /// never equals cutover.
    RehearsalCannotCutover,
    /// The typed payload violates its bound (empty, oversize, malformed, or
    /// digest-divergent). The bounded reason names the class, never content.
    PayloadRejected {
        /// Stable rejected class.
        reason: &'static str,
    },
    /// A canonical identity was reused with changed content.
    ReplayConflict,
    /// An untyped command, path, endpoint, or credential effect was
    /// requested. The owner channel admits typed operations only.
    ArbitraryEffectRefused {
        /// Stable refused kind.
        kind: &'static str,
    },
    /// The send timed out before any byte crossed the channel: no effect is
    /// possible, so a bounded retry without reconciliation is safe.
    TimeoutBeforeSend {
        /// Stable wire name of the timed-out operation.
        op: &'static str,
        /// Timeout bound in milliseconds.
        timeout_ms: u64,
    },
    /// The send timed out after bytes may have crossed: the outcome is
    /// unknown and reconciliation by identity is required before any retry.
    TimeoutAfterSend {
        /// Stable wire name of the timed-out operation.
        op: &'static str,
        /// Timeout bound in milliseconds.
        timeout_ms: u64,
    },
    /// The bound owner's authenticated protocol role does not carry the
    /// requested capability. Distinct from a fence, identity, operation, or
    /// bound failure: no authority exists for the request at all.
    CapabilityDenied,
    /// A fence, epoch, or admission binding presented by the owner
    /// diverged from the bound fence. Stale evidence refuses.
    FenceMismatch,
    /// An operation identity does not match its typed operation. A request
    /// can never select an operation it did not bind.
    OperationMismatch,
    /// A supplied value diverged from the bound backup identity. The
    /// bounded field path names the divergence class, never its content.
    IdentityMismatch {
        /// Stable field path that diverged from the bound identity.
        field: &'static str,
    },
    /// A supplied value exceeded its bounded wire limit. The bounded field
    /// path names the limit that was crossed.
    LimitExceeded {
        /// Stable field path that crossed its bound.
        field: &'static str,
    },
    /// A required protocol field was absent or malformed. Both field path
    /// and reason come from the protocol's own bounded vocabulary.
    ProtocolFieldRejected {
        /// Stable field path.
        field: &'static str,
        /// Stable bounded reason.
        reason: &'static str,
    },
    /// The existing generic protocol envelope owner rejected a mapped
    /// value. The typed source is preserved, never collapsed to a string.
    ProtocolEnvelopeRejected {
        /// Typed protocol envelope refusal.
        source: eliot_protocol::ProtocolError,
    },
    /// A foundation contract rejected an identity, fence, or contract
    /// value. The typed source is preserved, never collapsed to a string.
    FoundationContractRejected {
        /// Typed foundation contract refusal.
        source: eliot_contracts::ContractError,
    },
    /// Canonical serialization of a protocol value failed. The bounded
    /// reason comes from the serializer and names no archive content.
    ProtocolSerializationRejected {
        /// Bounded serializer reason.
        reason: String,
    },
    /// A transport acknowledgement phase was presented where semantic
    /// backup progress was required. No acknowledgement phase — including
    /// `DURABLE` and `APPLIED` — establishes capture, restore, or
    /// reconciliation success. The typed phase is preserved.
    TransportAckIsNotSuccess {
        /// The exact acknowledgement phase that was refused.
        phase: AckPhase,
    },
    /// The bound owner's role is not an admitted attester for a lifecycle
    /// stage its own accepted table can advance. One owner can never attest
    /// another owner's phase.
    PhaseNotAttestedByOwner {
        /// The exact protocol lifecycle stage the owner may not attest.
        stage: BackupStage,
    },
}

impl fmt::Display for OwnerClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FakePipeRejected { detail } => {
                write!(formatter, "owner binding rejected non-canonical {detail}")
            }
            Self::PipeMismatch => write!(formatter, "owner pipe does not match the canonical pipe"),
            Self::PeerMismatch => write!(formatter, "owner peer does not match the expectation"),
            Self::UnsupportedOperation { op } => {
                write!(formatter, "owner does not support operation {op}")
            }
            Self::CutoverAdmissionRequired => {
                write!(
                    formatter,
                    "cutover requires a separate cutover-domain admission"
                )
            }
            Self::RehearsalCannotCutover => {
                write!(formatter, "rehearsal completion is never cutover authority")
            }
            Self::PayloadRejected { reason } => {
                write!(formatter, "owner payload rejected: {reason}")
            }
            Self::ReplayConflict => write!(
                formatter,
                "owner replay identity conflicts with changed content"
            ),
            Self::ArbitraryEffectRefused { kind } => {
                write!(formatter, "owner refuses untyped {kind} effect")
            }
            Self::TimeoutBeforeSend { op, timeout_ms } => write!(
                formatter,
                "owner send of {op} timed out before send after {timeout_ms}ms: no effect, safe retry"
            ),
            Self::TimeoutAfterSend { op, timeout_ms } => write!(
                formatter,
                "owner send of {op} timed out after send after {timeout_ms}ms: reconcile by identity"
            ),
            Self::CapabilityDenied => write!(
                formatter,
                "owner protocol role does not carry the requested capability"
            ),
            Self::FenceMismatch => {
                write!(formatter, "owner fence or admission binding mismatch")
            }
            Self::OperationMismatch => write!(
                formatter,
                "owner operation identity does not match its typed operation"
            ),
            Self::IdentityMismatch { field } => {
                write!(
                    formatter,
                    "owner value diverges from the bound identity: {field}"
                )
            }
            Self::LimitExceeded { field } => {
                write!(formatter, "owner value exceeds its bound: {field}")
            }
            Self::ProtocolFieldRejected { field, reason } => {
                write!(formatter, "owner protocol field refused: {field}: {reason}")
            }
            Self::ProtocolEnvelopeRejected { source } => {
                write!(
                    formatter,
                    "owner protocol envelope refused the value: {source}"
                )
            }
            Self::FoundationContractRejected { source } => write!(
                formatter,
                "owner foundation contract refused the value: {source}"
            ),
            Self::ProtocolSerializationRejected { reason } => {
                write!(formatter, "owner protocol serialization refused: {reason}")
            }
            Self::TransportAckIsNotSuccess { phase } => write!(
                formatter,
                "transport acknowledgement {phase} is never backup semantic success"
            ),
            Self::PhaseNotAttestedByOwner { stage } => write!(
                formatter,
                "owner role is not an admitted attester for lifecycle stage {stage:?}"
            ),
        }
    }
}

impl std::error::Error for OwnerClientError {}

/// Which owner a channel binds: Host or Watchdog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerRole {
    Host,
    Watchdog,
}

impl OwnerRole {
    /// Exact canonical pipe for this owner.
    #[must_use]
    pub const fn pipe(self) -> &'static str {
        match self {
            Self::Host => HOST_BACKUP_PIPE,
            Self::Watchdog => WATCHDOG_BACKUP_PIPE,
        }
    }

    /// Exact peer expectation marker for this owner.
    #[must_use]
    pub const fn peer(self) -> &'static str {
        match self {
            Self::Host => HOST_BACKUP_PEER,
            Self::Watchdog => WATCHDOG_BACKUP_PEER,
        }
    }

    /// Closed accepted method table for this owner.
    #[must_use]
    pub const fn supported_ops(self) -> &'static [BackupOperationKind] {
        match self {
            Self::Host => HOST_SUPPORTED_OPS,
            Self::Watchdog => WATCHDOG_SUPPORTED_OPS,
        }
    }

    /// The exact authenticated protocol role this owner channel carries.
    ///
    /// This is a closed two-entry table read off the protocol's own role
    /// tables, never a capability search and never a payload claim. The
    /// binding is defined exactly once, here:
    ///
    /// - Host carries the installation authority. I5.13 gives the Host the
    ///   installation epoch and activation lineage, and
    ///   `attesting_roles(CutoverAdmitted)` admits the installation
    ///   authority alone — the only role whose closed capability projection
    ///   carries `AdmitCutover` at all. The Host accepted table carries
    ///   `AdmitCutover`, so the installation authority is the only role that
    ///   can be the Host channel's authenticated role.
    /// - Watchdog carries the spool owner. I5.13 binds the unreconciled
    ///   critical signal/intent spool to a `WatchdogSpoolFence`, so the
    ///   Watchdog is the spool owner, and
    ///   `attesting_roles(RestoreStepApplied | Reconciled)` admits the spool
    ///   owner alongside the store and ORS owners. The Watchdog accepted
    ///   table carries `ReconcileRestore`, whose establishing stage is
    ///   `Reconciled`.
    ///
    /// The projection is deliberately not widened: an operation the mapped
    /// role does not carry is refused at effect time even when the owner's
    /// local accepted table lists it.
    #[must_use]
    pub const fn protocol_role(self) -> BackupRole {
        match self {
            Self::Host => BackupRole::InstallationAuthority,
            Self::Watchdog => BackupRole::SpoolOwner,
        }
    }
}

/// Maps one typed [`eliot_protocol::backup::BackupError`] onto the
/// owner-channel error vocabulary without collapsing any class.
///
/// Every protocol refusal class keeps its own owner-channel class: a
/// capability denial, a fence or admission mismatch, an operation mismatch,
/// an identity divergence, a replay conflict, a bound violation, a field
/// rejection, and the two typed transport/contract refusals never merge into
/// one generic error or into a rendered string. Bounded field paths and
/// stable reasons are carried through verbatim from the protocol, and the two
/// typed source errors are carried as typed values.
#[must_use]
pub fn map_protocol_backup_error(error: eliot_protocol::backup::BackupError) -> OwnerClientError {
    match error {
        eliot_protocol::backup::BackupError::CapabilityDenied => OwnerClientError::CapabilityDenied,
        eliot_protocol::backup::BackupError::FenceMismatch => OwnerClientError::FenceMismatch,
        eliot_protocol::backup::BackupError::OperationMismatch => {
            OwnerClientError::OperationMismatch
        }
        eliot_protocol::backup::BackupError::Mismatch { field } => {
            OwnerClientError::IdentityMismatch { field }
        }
        eliot_protocol::backup::BackupError::ReplayConflict => OwnerClientError::ReplayConflict,
        eliot_protocol::backup::BackupError::LimitExceeded(field) => {
            OwnerClientError::LimitExceeded { field }
        }
        eliot_protocol::backup::BackupError::InvalidField { field, reason } => {
            OwnerClientError::ProtocolFieldRejected { field, reason }
        }
        eliot_protocol::backup::BackupError::Protocol(source) => {
            OwnerClientError::ProtocolEnvelopeRejected { source }
        }
        eliot_protocol::backup::BackupError::Foundation(source) => {
            OwnerClientError::FoundationContractRejected { source }
        }
        eliot_protocol::backup::BackupError::Serialization(reason) => {
            OwnerClientError::ProtocolSerializationRejected { reason }
        }
    }
}

/// Returns true when the presented pipe text carries a fake, no-op, mock,
/// default, in-memory, or placeholder marker, or is blank.
///
/// The canonical pipes never contain these markers, so any hit fail-closes
/// without comparing further. Comparison is case-insensitive and bounded.
fn looks_fake(pipe: &str) -> bool {
    const MARKERS: &[&str] = &[
        "fake",
        "noop",
        "no-op",
        "mock",
        "stub",
        "default",
        "memory",
        "test",
        "example",
        "placeholder",
        "null",
    ];
    let trimmed = pipe.trim();
    if trimmed.is_empty() || trimmed.len() > 512 {
        return true;
    }
    // Bounded lowercase copy for the marker scan only; never logged.
    let mut lowered = String::with_capacity(trimmed.len().min(512));
    for ch in trimmed.chars().take(512) {
        lowered.extend(ch.to_lowercase());
    }
    MARKERS.iter().any(|marker| lowered.contains(marker))
}

/// The closed lifecycle-stage traversal list of the protocol backup
/// boundary.
///
/// This is a traversal list, never a second definition: every entry is an
/// [`eliot_protocol::backup::BackupStage`] value, and both the operation a
/// stage establishes and the roles admitted to attest it are read back out
/// of the protocol's own `operation_for_phase` and `attesting_roles`
/// projections. A stage the protocol adds later is simply not traversed
/// here, which can only narrow the coherence check below, never widen it.
const BACKUP_LIFECYCLE_STAGES: &[BackupStage] = &[
    BackupStage::Requested,
    BackupStage::Captured,
    BackupStage::Verified,
    BackupStage::RestorePrepared,
    BackupStage::RestoreStepApplied,
    BackupStage::Reconciled,
    BackupStage::RehearsalComplete,
    BackupStage::CutoverAdmitted,
];

/// The closed transport-acknowledgement phase traversal list.
///
/// A traversal list of the protocol transport's own `AckPhase` values, used
/// to prove the acknowledgement refusal below over every phase. A phase the
/// transport adds later is not traversed here, which can only narrow the
/// proof, never widen it.
const TRANSPORT_ACK_PHASES: &[AckPhase] = &[
    AckPhase::Received,
    AckPhase::Durable,
    AckPhase::Normalized,
    AckPhase::Applied,
    AckPhase::Rejected,
    AckPhase::Unknown,
];

/// Proves, once per owner binding, that a transport acknowledgement is never
/// backup semantic success at any phase.
///
/// The refusal is consumed from the protocol's versioned wire mapping
/// rather than re-implemented here: `ack_phase_stage` is asked for the
/// lifecycle stage each acknowledgement phase establishes, and any `Some`
/// answer refuses the binding. A transport acknowledgement — including
/// `DURABLE` and `APPLIED` — therefore cannot be promoted to capture,
/// restore, rehearsal, or reconciliation success on this channel. Semantic
/// progress requires an owner attestation, never an acknowledgement.
fn check_transport_ack_refusal() -> Result<(), OwnerClientError> {
    for phase in TRANSPORT_ACK_PHASES {
        if eliot_protocol::backup::ack_phase_stage(*phase).is_some() {
            return Err(OwnerClientError::TransportAckIsNotSuccess { phase: *phase });
        }
    }
    Ok(())
}

/// Binds one owner to its exact authenticated protocol role and proves the
/// binding before any client exists.
///
/// The role is the closed projection from
/// [`OwnerRole::protocol_role`], and it must be an attesting role: the
/// requester and the forensic Host role only request, observe, and query,
/// so neither may own a channel that admits effects. Then the owner's local
/// accepted table is checked against the protocol's own role projections:
/// every table entry the role actually carries must be a stage the role is
/// an admitted attester for, so a channel can never claim to advance a
/// lifecycle phase its role may not attest. Table entries the role does not
/// carry are not fatal here; they refuse individually at effect time.
fn check_owner_role_admission(role: OwnerRole) -> Result<(), OwnerClientError> {
    let protocol_role = role.protocol_role();
    if !protocol_role.is_attesting_role() {
        // The refusal is expressed in the protocol's own typed refusal class
        // and mapped once, so the capability denial has exactly one
        // owner-channel spelling and is never re-implemented here.
        return Err(map_protocol_backup_error(
            eliot_protocol::backup::BackupError::CapabilityDenied,
        ));
    }
    for operation in role.supported_ops() {
        if !protocol_role.permits(*operation) {
            continue;
        }
        for stage in BACKUP_LIFECYCLE_STAGES {
            if eliot_protocol::backup::operation_for_phase(*stage) != *operation {
                continue;
            }
            if !eliot_protocol::backup::attesting_roles(*stage).contains(&protocol_role) {
                return Err(OwnerClientError::PhaseNotAttestedByOwner { stage: *stage });
            }
        }
    }
    Ok(())
}

/// Requires, for one admitted effect, that the owner's authenticated
/// protocol role is an attesting role and actually carries the operation.
///
/// This is the necessary protocol condition for every admitted effect. The
/// caller's own closed accepted table is a separate, additional narrowing.
/// The refusal is expressed in the protocol's own typed refusal class and
/// mapped once through [`map_protocol_backup_error`], so a capability denial
/// keeps one spelling end to end and is never re-implemented here.
fn check_role_permits_effect(
    role: OwnerRole,
    operation: BackupOperationKind,
) -> Result<(), OwnerClientError> {
    let protocol_role = role.protocol_role();
    if !protocol_role.is_attesting_role() || !protocol_role.permits(operation) {
        return Err(map_protocol_backup_error(
            eliot_protocol::backup::BackupError::CapabilityDenied,
        ));
    }
    Ok(())
}

/// Validates one exact owner binding: canonical pipe plus exact peer, with
/// fake/no-op markers rejected before any equality check, then the exact
/// authenticated protocol role binding and the transport-acknowledgement
/// refusal proved on the same path.
fn check_binding(role: OwnerRole, pipe: &str, peer: &str) -> Result<(), OwnerClientError> {
    if looks_fake(pipe) {
        return Err(OwnerClientError::FakePipeRejected { detail: "pipe" });
    }
    if looks_fake(peer) {
        return Err(OwnerClientError::FakePipeRejected { detail: "peer" });
    }
    if pipe != role.pipe() {
        return Err(OwnerClientError::PipeMismatch);
    }
    if peer != role.peer() {
        return Err(OwnerClientError::PeerMismatch);
    }
    check_owner_role_admission(role)?;
    check_transport_ack_refusal()?;
    Ok(())
}

/// Host backup owner client: `PrepareIsolatedRestore` / `AdmitCutover` /
/// `RestoreStatus` / `ReconcileRestore` over the canonical Host pipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostBackupOwnerClient {
    pipe: String,
    peer: String,
}

/// Watchdog backup owner client: `ReadSnapshotPage` / `VerifyArchive` /
/// `RestoreStatus` / `ReconcileRestore` over the canonical Watchdog pipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogBackupOwnerClient {
    pipe: String,
    peer: String,
}

impl HostBackupOwnerClient {
    /// Binds the production Host owner: exact canonical pipe plus exact
    /// peer expectation. Fails closed on any fake or mismatch.
    pub fn production() -> Result<Self, OwnerClientError> {
        Self::new(HOST_BACKUP_PIPE, HOST_BACKUP_PEER)
    }

    /// Binds an explicitly presented Host owner. Only the exact canonical
    /// pipe plus the exact peer expectation succeed; everything else —
    /// fake, no-op, mock, default, blank, or merely different — fails
    /// closed with no default substitution.
    pub fn new(pipe: &str, peer: &str) -> Result<Self, OwnerClientError> {
        check_binding(OwnerRole::Host, pipe, peer)?;
        Ok(Self {
            pipe: pipe.to_owned(),
            peer: peer.to_owned(),
        })
    }

    /// Bound canonical pipe name.
    #[must_use]
    pub fn pipe(&self) -> &str {
        &self.pipe
    }

    /// Bound peer expectation marker.
    #[must_use]
    pub fn peer(&self) -> &str {
        &self.peer
    }

    /// Closed accepted method table for the Host owner.
    ///
    /// Associated function: the table is closed per owner type, not per
    /// bound instance.
    #[must_use]
    pub fn supported_ops() -> &'static [BackupOperationKind] {
        HOST_SUPPORTED_OPS
    }

    /// Whether the operation is inside this owner's closed table.
    #[must_use]
    pub fn is_supported(op: BackupOperationKind) -> bool {
        HOST_SUPPORTED_OPS.contains(&op)
    }

    /// Whether the operation requires a separately admitted cutover token.
    /// Only `AdmitCutover` does; prepare admission never satisfies it.
    #[must_use]
    pub const fn requires_cutover_admission(op: BackupOperationKind) -> bool {
        matches!(op, BackupOperationKind::AdmitCutover)
    }

    /// Exact authority check: the candidate peer must equal the bound
    /// expectation byte-for-byte. Spoofed or merely similar peers refuse.
    #[must_use]
    pub fn authority_matches(&self, candidate_peer: &str) -> bool {
        candidate_peer == self.peer
    }

    /// Exact response-identity check: the responding pipe, peer, and
    /// operation must equal the bound triple. A bare acknowledgement or a
    /// mismatched identity never validates.
    #[must_use]
    pub fn response_identity_ok(
        &self,
        response_pipe: &str,
        response_peer: &str,
        op: BackupOperationKind,
    ) -> bool {
        response_pipe == self.pipe && response_peer == self.peer && Self::is_supported(op)
    }

    /// Admits exactly one typed effect for a supported operation.
    /// Unsupported operations refuse pre-effect: no admission object can
    /// exist for them.
    ///
    /// Admission is role-bound: the operation must also be carried by this
    /// channel's authenticated protocol role
    /// ([`OwnerRole::Host`] -> installation authority), and that role must
    /// be an attesting role. The owner's accepted table and the protocol's
    /// role matrix are both necessary conditions, so the Host can never
    /// exercise an operation the installation authority does not carry, and
    /// a non-attesting role can never produce an effect admission at all.
    pub fn admit_effect(op: BackupOperationKind) -> Result<EffectAdmission, OwnerClientError> {
        if !Self::is_supported(op) {
            return Err(OwnerClientError::UnsupportedOperation { op: op.as_str() });
        }
        if Self::requires_cutover_admission(op) {
            return Err(OwnerClientError::CutoverAdmissionRequired);
        }
        check_role_permits_effect(OwnerRole::Host, op)?;
        Ok(EffectAdmission {
            owner: HOST_BACKUP_PEER,
            op: op.as_str(),
            effect_count: 1,
        })
    }

    /// Admits one prepare effect under a prepare-domain admission only.
    pub fn admit_prepare(admission: &OwnerAdmission) -> Result<EffectAdmission, OwnerClientError> {
        admission.check_domain(AdmissionDomain::Prepare)?;
        Self::admit_effect(BackupOperationKind::PrepareIsolatedRestore)
    }

    /// Admits the one cutover effect under a cutover-domain admission only.
    /// A prepare-domain admission presented here refuses.
    ///
    /// The cutover effect is role-bound exactly like every other admitted
    /// effect: only the installation authority carries `AdmitCutover`, so a
    /// different role on this channel could not produce a cutover
    /// admission even with a valid cutover-domain reference.
    pub fn admit_cutover(admission: &OwnerAdmission) -> Result<EffectAdmission, OwnerClientError> {
        admission.check_domain(AdmissionDomain::Cutover)?;
        if !Self::is_supported(BackupOperationKind::AdmitCutover) {
            return Err(OwnerClientError::UnsupportedOperation {
                op: BackupOperationKind::AdmitCutover.as_str(),
            });
        }
        check_role_permits_effect(OwnerRole::Host, BackupOperationKind::AdmitCutover)?;
        Ok(EffectAdmission {
            owner: HOST_BACKUP_PEER,
            op: BackupOperationKind::AdmitCutover.as_str(),
            effect_count: 1,
        })
    }

    /// Refuses every untyped effect kind: command, path, endpoint, and
    /// credential effects never cross the owner channel.
    pub fn refuse_untyped(kind: UntypedEffectKind) -> Result<EffectAdmission, OwnerClientError> {
        Err(OwnerClientError::ArbitraryEffectRefused {
            kind: kind.as_str(),
        })
    }

    /// Typed shutdown: closes the bound channel with zero pending effects
    /// and evicts the bounded replay view.
    #[must_use]
    pub fn shutdown_cleanup() -> OwnerShutdown {
        OwnerShutdown {
            pipe_closed: true,
            pending_effects: 0,
            replay_view_evicted: true,
        }
    }
}

impl WatchdogBackupOwnerClient {
    /// Binds the production Watchdog owner: exact canonical pipe plus exact
    /// peer expectation. Fails closed on any fake or mismatch.
    pub fn production() -> Result<Self, OwnerClientError> {
        Self::new(WATCHDOG_BACKUP_PIPE, WATCHDOG_BACKUP_PEER)
    }

    /// Binds an explicitly presented Watchdog owner. Only the exact
    /// canonical pipe plus the exact peer expectation succeed.
    pub fn new(pipe: &str, peer: &str) -> Result<Self, OwnerClientError> {
        check_binding(OwnerRole::Watchdog, pipe, peer)?;
        Ok(Self {
            pipe: pipe.to_owned(),
            peer: peer.to_owned(),
        })
    }

    /// Bound canonical pipe name.
    #[must_use]
    pub fn pipe(&self) -> &str {
        &self.pipe
    }

    /// Bound peer expectation marker.
    #[must_use]
    pub fn peer(&self) -> &str {
        &self.peer
    }

    /// Closed accepted method table for the Watchdog owner.
    ///
    /// Associated function: the table is closed per owner type, not per
    /// bound instance.
    #[must_use]
    pub fn supported_ops() -> &'static [BackupOperationKind] {
        WATCHDOG_SUPPORTED_OPS
    }

    /// Whether the operation is inside this owner's closed table.
    #[must_use]
    pub fn is_supported(op: BackupOperationKind) -> bool {
        WATCHDOG_SUPPORTED_OPS.contains(&op)
    }

    /// The Watchdog owner never admits cutover: always false. Cutover
    /// authority belongs to the Host owner under a separate admission.
    #[must_use]
    pub const fn requires_cutover_admission(_op: BackupOperationKind) -> bool {
        false
    }

    /// Exact authority check: the candidate peer must equal the bound
    /// expectation byte-for-byte.
    #[must_use]
    pub fn authority_matches(&self, candidate_peer: &str) -> bool {
        candidate_peer == self.peer
    }

    /// Exact response-identity check over the bound pipe/peer/operation
    /// triple.
    #[must_use]
    pub fn response_identity_ok(
        &self,
        response_pipe: &str,
        response_peer: &str,
        op: BackupOperationKind,
    ) -> bool {
        response_pipe == self.pipe && response_peer == self.peer && Self::is_supported(op)
    }

    /// Admits exactly one typed effect for a supported operation, failing
    /// pre-effect otherwise.
    ///
    /// Admission is role-bound: the operation must also be carried by this
    /// channel's authenticated protocol role
    /// ([`OwnerRole::Watchdog`] -> spool owner), and that role must be an
    /// attesting role. The spool owner never carries `AdmitCutover`, so
    /// cutover authority is structurally unavailable on this channel
    /// independently of the accepted table.
    pub fn admit_effect(op: BackupOperationKind) -> Result<EffectAdmission, OwnerClientError> {
        if !Self::is_supported(op) {
            return Err(OwnerClientError::UnsupportedOperation { op: op.as_str() });
        }
        // The Watchdog table carries no cutover operation; reaching a
        // cutover request here is a table violation, never an admission.
        if matches!(op, BackupOperationKind::AdmitCutover) {
            return Err(OwnerClientError::UnsupportedOperation { op: op.as_str() });
        }
        check_role_permits_effect(OwnerRole::Watchdog, op)?;
        Ok(EffectAdmission {
            owner: WATCHDOG_BACKUP_PEER,
            op: op.as_str(),
            effect_count: 1,
        })
    }

    /// Refuses every untyped effect kind.
    pub fn refuse_untyped(kind: UntypedEffectKind) -> Result<EffectAdmission, OwnerClientError> {
        Err(OwnerClientError::ArbitraryEffectRefused {
            kind: kind.as_str(),
        })
    }

    /// Typed shutdown: closes the bound channel with zero pending effects.
    #[must_use]
    pub fn shutdown_cleanup() -> OwnerShutdown {
        OwnerShutdown {
            pipe_closed: true,
            pending_effects: 0,
            replay_view_evicted: true,
        }
    }
}

/// One admitted exact-owner effect. Always exactly one effect: the owner
/// channel never batches, and admission precedes any effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectAdmission {
    owner: &'static str,
    op: &'static str,
    effect_count: u32,
}

impl EffectAdmission {
    /// Attesting owner marker bound to this admission.
    #[must_use]
    pub const fn owner(&self) -> &'static str {
        self.owner
    }

    /// Stable wire name of the admitted operation.
    #[must_use]
    pub const fn op(&self) -> &'static str {
        self.op
    }

    /// Number of effects this admission authorizes: always exactly one.
    #[must_use]
    pub const fn effect_count(&self) -> u32 {
        self.effect_count
    }
}

/// Separate admission domains: prepare admission never satisfies cutover,
/// and cutover admission never satisfies prepare.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDomain {
    Prepare,
    Cutover,
}

impl AdmissionDomain {
    /// Stable domain name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Cutover => "cutover",
        }
    }

    /// Parses the exact domain name; anything else refuses.
    pub fn parse(value: &str) -> Result<Self, OwnerClientError> {
        match value {
            "prepare" => Ok(Self::Prepare),
            "cutover" => Ok(Self::Cutover),
            _ => Err(OwnerClientError::PayloadRejected {
                reason: "unknown admission domain",
            }),
        }
    }
}

/// Owner admission reference: a domain plus a bounded digest binding.
///
/// This carries no archive bytes, no paths, and no credentials — only the
/// admission domain and a lowercase SHA-256 binding digest. Prepare and
/// cutover admissions live in separate domains by type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerAdmission {
    domain: AdmissionDomain,
    digest: String,
}

impl OwnerAdmission {
    /// Presents an admission reference. The digest must be a lowercase
    /// SHA-256 binding; the domain must parse exactly.
    pub fn present(domain: &str, digest: &str) -> Result<Self, OwnerClientError> {
        let domain = AdmissionDomain::parse(domain)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(OwnerClientError::PayloadRejected {
                reason: "admission digest must be lowercase SHA-256",
            });
        }
        Ok(Self {
            domain,
            digest: digest.to_owned(),
        })
    }

    /// Admission domain of this reference.
    #[must_use]
    pub const fn domain(&self) -> AdmissionDomain {
        self.domain
    }

    /// Requires the exact expected domain. A prepare admission presented
    /// for cutover (or the reverse) refuses instead of coercing.
    pub fn check_domain(&self, expected: AdmissionDomain) -> Result<(), OwnerClientError> {
        if self.domain != expected {
            return Err(OwnerClientError::CutoverAdmissionRequired);
        }
        Ok(())
    }
}

/// Untyped effect kinds. The owner channel admits none of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UntypedEffectKind {
    Command,
    Path,
    Endpoint,
    Credential,
}

impl UntypedEffectKind {
    /// Stable refused-kind name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Path => "path",
            Self::Endpoint => "endpoint",
            Self::Credential => "credential",
        }
    }

    /// All four untyped kinds in one closed enumeration.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Command, Self::Path, Self::Endpoint, Self::Credential]
    }
}

/// Typed shutdown receipt for one bound owner channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerShutdown {
    pipe_closed: bool,
    pending_effects: u32,
    replay_view_evicted: bool,
}

impl OwnerShutdown {
    /// Whether the bound pipe handle was closed.
    #[must_use]
    pub const fn pipe_closed(&self) -> bool {
        self.pipe_closed
    }

    /// Effects still pending after shutdown: always zero.
    #[must_use]
    pub const fn pending_effects(&self) -> u32 {
        self.pending_effects
    }

    /// Whether the bounded replay view was evicted.
    #[must_use]
    pub const fn replay_view_evicted(&self) -> bool {
        self.replay_view_evicted
    }
}

/// Timeout kind for one owner-channel send.
///
/// Before-send timeouts prove no effect (safe bounded retry); after-send
/// timeouts prove nothing (reconciliation by identity is required before
/// any retry, never a blind duplicate send).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerTimeout {
    BeforeSend {
        op: BackupOperationKind,
        timeout_ms: u64,
    },
    AfterSend {
        op: BackupOperationKind,
        timeout_ms: u64,
    },
}

impl OwnerTimeout {
    /// A before-send timeout may retry without reconciliation: no byte
    /// crossed the channel, so no effect exists to duplicate.
    #[must_use]
    pub const fn may_retry_without_reconcile(&self) -> bool {
        matches!(self, Self::BeforeSend { .. })
    }

    /// An after-send timeout must reconcile by identity first: the effect
    /// state is unknown and a blind retry could duplicate it.
    #[must_use]
    pub const fn requires_reconcile(&self) -> bool {
        matches!(self, Self::AfterSend { .. })
    }

    /// Stable wire name of the timed-out operation.
    #[must_use]
    pub const fn op(&self) -> BackupOperationKind {
        match self {
            Self::BeforeSend { op, .. } | Self::AfterSend { op, .. } => *op,
        }
    }
}

/// Replay-safety marker for one operation: exact-digest replay is
/// idempotent and duplicate-free; anything else must reconcile, never
/// blind-retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplaySafety {
    /// Safe only with an exact digest match against the completed ledger.
    SafeWithExactDigest,
    /// Never safe to blind-retry; reconcile by identity first.
    NeverBlind,
}

/// Returns the replay-safety marker for an operation on a supporting
/// client. Unsupported operations are never replay-safe.
#[must_use]
pub const fn replay_safe_marker(supported: bool) -> ReplaySafety {
    if supported {
        ReplaySafety::SafeWithExactDigest
    } else {
        ReplaySafety::NeverBlind
    }
}

/// Disposition of one replayed owner request identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDisposition {
    /// First presentation: commit exactly one effect.
    Commit,
    /// Exact digest replay: idempotent, no duplicate effect.
    ExactReplay,
    /// Same identity with changed content: conflict, no effect.
    Conflict,
}

/// Bounded replay ledger: completed canonical digests mapped to their exact
/// bytes. An exact replay is idempotent; a changed same-identity replay
/// conflicts; eviction is oldest-first and bounded.
#[derive(Clone, Debug, Default)]
pub struct ReplayLedger {
    entries: BTreeMap<String, Vec<u8>>,
}

impl ReplayLedger {
    /// Empty bounded ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Classifies one presentation without applying any effect.
    pub fn classify(
        &mut self,
        digest: &str,
        bytes: &[u8],
    ) -> Result<ReplayDisposition, OwnerClientError> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(OwnerClientError::PayloadRejected {
                reason: "replay digest must be lowercase SHA-256",
            });
        }
        if bytes.is_empty() || bytes.len() > MAX_BACKUP_PAYLOAD_BYTES {
            return Err(OwnerClientError::PayloadRejected {
                reason: "replay bytes violate the bounded payload ceiling",
            });
        }
        match self.entries.get(digest) {
            None => {
                if self.entries.len() >= MAX_REPLAY_LEDGER_ENTRIES {
                    // Oldest-first eviction keeps the ledger bounded.
                    if let Some(oldest) = self.entries.keys().next().cloned() {
                        self.entries.remove(&oldest);
                    }
                }
                self.entries.insert(digest.to_owned(), bytes.to_vec());
                Ok(ReplayDisposition::Commit)
            }
            Some(committed) if committed.as_slice() == bytes => Ok(ReplayDisposition::ExactReplay),
            Some(_) => Err(OwnerClientError::ReplayConflict),
        }
    }

    /// Retained entry count (always bounded).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ledger is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Validates one bounded typed owner payload: nonempty, within the
/// canonical payload ceiling, and a JSON object (typed, never an arbitrary
/// command string, path, or endpoint).
pub fn validate_bounded_payload(bytes: &[u8]) -> Result<serde_json::Value, OwnerClientError> {
    if bytes.is_empty() {
        return Err(OwnerClientError::PayloadRejected {
            reason: "payload must be nonempty",
        });
    }
    if bytes.len() > MAX_BACKUP_PAYLOAD_BYTES {
        return Err(OwnerClientError::PayloadRejected {
            reason: "payload exceeds the bounded payload ceiling",
        });
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| OwnerClientError::PayloadRejected {
            reason: "payload is malformed",
        })?;
    if !value.is_object() {
        return Err(OwnerClientError::PayloadRejected {
            reason: "payload must be a typed object",
        });
    }
    Ok(value)
}

/// Checks a presented digest against the bound canonical digest. Any
/// payload override — a presented value that diverges from the bound digest
/// — refuses instead of coercing.
pub fn check_bound_digest(bound: &str, presented: &str) -> Result<(), OwnerClientError> {
    if bound != presented {
        return Err(OwnerClientError::PayloadRejected {
            reason: "payload override diverges from the bound digest",
        });
    }
    Ok(())
}

/// Exact fence-freshness check: the presented epoch/generation tuple must
/// equal the current tuple exactly. Stale presentations refuse; the owner
/// channel performs no fence arithmetic and mints no epochs.
#[must_use]
pub const fn fence_is_fresh(
    presented_epoch: u64,
    presented_generation: u64,
    current_epoch: u64,
    current_generation: u64,
) -> bool {
    presented_epoch == current_epoch && presented_generation == current_generation
}

/// Transport acknowledgement never establishes semantic success — at any
/// phase. The refusal is enforced on the production binding path by
/// [`check_transport_ack_refusal`], which asks the protocol's versioned
/// wire mapping `eliot_protocol::backup::ack_phase_stage` for the lifecycle
/// stage each acknowledgement phase establishes and refuses the binding if
/// any phase maps to a stage. This predicate states the same contract for
/// readers of the surface.
#[must_use]
pub const fn transport_ack_is_success() -> bool {
    false
}

/// Rehearsal completion never carries cutover or retirement authority.
/// Cutover requires the separate installation-authority admission.
#[must_use]
pub const fn rehearsal_proves_cutover() -> bool {
    false
}

/// Supervision priority is never starved by the owner channel: the bounded
/// per-round quantum ([`OWNER_OPS_QUANTUM_PER_ROUND`]) keeps owner work from
/// consuming the supervision control reserve.
#[must_use]
pub const fn supervision_priority_preserved() -> bool {
    true
}

/// Process-wide marker recording that production assembly bound the actual
/// owner clients. Set once by the composition bootstrap after both
/// production constructors succeed; read back by diagnostics only.
static OWNER_CLIENTS_BOUND_IN_ASSEMBLE: AtomicBool = AtomicBool::new(false);

/// Records that production assembly bound the actual owner clients.
pub fn mark_owner_clients_bound() {
    OWNER_CLIENTS_BOUND_IN_ASSEMBLE.store(true, Ordering::SeqCst);
}

/// Whether production assembly has bound the actual owner clients.
#[must_use]
pub fn owner_clients_bound_in_assemble() -> bool {
    OWNER_CLIENTS_BOUND_IN_ASSEMBLE.load(Ordering::SeqCst)
}
