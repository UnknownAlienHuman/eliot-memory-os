//! Role-bound backup and isolated-restore control contracts.
//!
//! This module is a shape and transition boundary for backup capture, bounded
//! snapshot reads, archive verification, isolated restore preparation,
//! operation-bound restore steps, restore reconciliation and status, rehearsal
//! completion, and separately admitted installation cutover. It performs no
//! I/O, opens no transport, persists nothing, admits nothing, dispatches
//! nothing, mints no authority, and interprets no archive bytes. Every value
//! here is a pure validated shape: digests, identities, fences, bounds, and
//! role bindings only. Archive interpretation, storage effects, and authority
//! decisions belong to the owning Store, capture, verifier, and installation
//! authority crates.
//!
//! The authenticated [`BackupRole`] always travels as a separate function
//! argument, never as a payload claim. A value in a payload never grants a
//! role. Owner receipts bind the attesting owner and phase; rehearsal
//! completion never carries cutover or retirement; installation cutover
//! requires a separate installation authority admission. Transport
//! acknowledgement is never semantic success.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use eliot_contracts::{
    ArtifactId, ContractError, ContractIdentity, ContractVersion, EpochId, ReceiptId,
    ResourceGeneration, StateFence, canonical_json_bytes, fences_match_exact, sha256_hex,
};
use eliot_receipts::{AuthorityBinding, WorkScopeBinding};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AckPhase, DeliveryClass, EventEnvelope, EventPayload, ProtocolError};

// ---------------------------------------------------------------------------
// Contract identity and wire bounds.
// ---------------------------------------------------------------------------

/// Stable identity of the backup control family.
pub const BACKUP_CONTRACT_NAME: &str = "eliot.foundation.backup";
/// Current semantic revision of the backup control family.
pub const BACKUP_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Versioned namespace used for canonical backup digests.
pub const BACKUP_CANONICAL_ENCODING: &str = "eliot.backup.canonical.v1";
/// Exact generic event payload discriminator for mapped backup envelopes.
pub const BACKUP_PAYLOAD_TYPE: &str = "backup/v1";
/// Producer identity used by the pure envelope mapping.
pub const BACKUP_PRODUCER_ID: &str = "eliot-backup-control";
/// Maximum bytes for one bounded text field.
pub const MAX_BACKUP_TEXT_BYTES: usize = 8 * 1024;
/// Maximum bytes for one bounded artifact or page body.
pub const MAX_BACKUP_CONTENT_BYTES: usize = 64 * 1024;
/// Maximum canonical JSON bytes accepted for one typed backup payload.
pub const MAX_BACKUP_PAYLOAD_BYTES: usize = 256 * 1024;
/// Maximum members carried by one snapshot page reference.
pub const MAX_BACKUP_PAGE_MEMBERS: u32 = 1024;
/// Maximum observed dispositions carried by one forensic audit reference.
pub const MAX_BACKUP_OBSERVED_DISPOSITIONS: usize = 32;

/// Stable wire identity for a backup request identity.
pub const BACKUP_REQUEST_IDENTITY_WIRE_ID: &str = "eliot.protocol.backup.request-identity";
/// Current backup request identity wire version.
pub const BACKUP_REQUEST_IDENTITY_WIRE_VERSION: u16 = 1;
/// Stable wire identity for a backup capture request.
pub const BACKUP_CAPTURE_REQUEST_WIRE_ID: &str = "eliot.protocol.backup.capture-request";
/// Current backup capture request wire version.
pub const BACKUP_CAPTURE_REQUEST_WIRE_VERSION: u16 = 1;
/// Stable wire identity for a bounded snapshot page read.
pub const BACKUP_SNAPSHOT_PAGE_READ_WIRE_ID: &str = "eliot.protocol.backup.snapshot-page-read";
/// Current snapshot page read wire version.
pub const BACKUP_SNAPSHOT_PAGE_READ_WIRE_VERSION: u16 = 1;
/// Stable wire identity for an archive verification request.
pub const BACKUP_ARCHIVE_VERIFICATION_WIRE_ID: &str = "eliot.protocol.backup.archive-verification";
/// Current archive verification wire version.
pub const BACKUP_ARCHIVE_VERIFICATION_WIRE_VERSION: u16 = 1;
/// Stable wire identity for an isolated restore preparation.
pub const BACKUP_ISOLATED_RESTORE_PREPARE_WIRE_ID: &str =
    "eliot.protocol.backup.isolated-restore-prepare";
/// Current isolated restore preparation wire version.
pub const BACKUP_ISOLATED_RESTORE_PREPARE_WIRE_VERSION: u16 = 1;
/// Stable wire identity for one operation-bound restore step.
pub const BACKUP_RESTORE_STEP_WIRE_ID: &str = "eliot.protocol.backup.restore-step";
/// Current restore step wire version.
pub const BACKUP_RESTORE_STEP_WIRE_VERSION: u16 = 1;
/// Stable wire identity for a restore reconcile query.
pub const BACKUP_RESTORE_RECONCILE_WIRE_ID: &str = "eliot.protocol.backup.restore-reconcile";
/// Current restore reconcile wire version.
pub const BACKUP_RESTORE_RECONCILE_WIRE_VERSION: u16 = 1;
/// Stable wire identity for a restore status query.
pub const BACKUP_RESTORE_STATUS_WIRE_ID: &str = "eliot.protocol.backup.restore-status";
/// Current restore status wire version.
pub const BACKUP_RESTORE_STATUS_WIRE_VERSION: u16 = 1;
/// Stable wire identity for a rehearsal completion record.
pub const BACKUP_REHEARSAL_COMPLETE_WIRE_ID: &str = "eliot.protocol.backup.rehearsal-complete";
/// Current rehearsal completion wire version.
pub const BACKUP_REHEARSAL_COMPLETE_WIRE_VERSION: u16 = 1;
/// Stable wire identity for an installation cutover admission.
pub const BACKUP_CUTOVER_ADMISSION_WIRE_ID: &str = "eliot.protocol.backup.cutover-admission";
/// Current cutover admission wire version.
pub const BACKUP_CUTOVER_ADMISSION_WIRE_VERSION: u16 = 1;
/// Stable wire identity for a capture receipt.
pub const BACKUP_CAPTURE_RECEIPT_WIRE_ID: &str = "eliot.protocol.backup.capture-receipt";
/// Current capture receipt wire version.
pub const BACKUP_CAPTURE_RECEIPT_WIRE_VERSION: u16 = 1;
/// Stable wire identity for a phase attestation.
pub const BACKUP_PHASE_ATTESTATION_WIRE_ID: &str = "eliot.protocol.backup.phase-attestation";
/// Current phase attestation wire version.
pub const BACKUP_PHASE_ATTESTATION_WIRE_VERSION: u16 = 1;
/// Stable wire identity for an archive validity attestation.
pub const BACKUP_ARCHIVE_VALIDITY_ATTESTATION_WIRE_ID: &str =
    "eliot.protocol.backup.archive-validity-attestation";
/// Current archive validity attestation wire version.
pub const BACKUP_ARCHIVE_VALIDITY_ATTESTATION_WIRE_VERSION: u16 = 1;
/// Stable wire identity for a cutover receipt.
pub const BACKUP_CUTOVER_RECEIPT_WIRE_ID: &str = "eliot.protocol.backup.cutover-receipt";
/// Current cutover receipt wire version.
pub const BACKUP_CUTOVER_RECEIPT_WIRE_VERSION: u16 = 1;
/// Stable wire identity for the closed cutover payload contract.
pub const BACKUP_CUTOVER_PAYLOAD_WIRE_ID: &str = "eliot.protocol.backup.cutover-payload";
/// Current cutover payload wire version.
pub const BACKUP_CUTOVER_PAYLOAD_WIRE_VERSION: u16 = 1;
/// Exact payload-schema identity that an admitted cutover
/// [`crate::HostRequestEnvelope`] must carry in
/// [`crate::HostRequestIdentity::payload_schema_id`].
///
/// The admitted envelope's `payload_sha256` is a digest over the opaque
/// payload bytes. This constant names the one schema identity for which those
/// bytes are a [`BackupCutoverPayload`],
/// [`BackupCutoverPayload::validate_admitted_payload`] is the only check that
/// compares an admitted envelope against that constant and against a body,
/// and it refuses an envelope admitted under any other schema. It is a schema
/// identity only: naming it is not admission, and admission of an envelope is
/// resolved through the authenticated owner/readback path, never by this
/// string alone. It is deliberately distinct from
/// [`BACKUP_CUTOVER_PAYLOAD_WIRE_ID`], which is the in-payload wire identity,
/// and from the operation request digest domain.
pub const BACKUP_CUTOVER_PAYLOAD_SCHEMA_ID: &str = "eliot.protocol.backup.cutover-payload.v1";
/// Domain of the cutover payload content digest.
///
/// This is a domain name, not a digest input: the content digest is taken over
/// canonical payload bytes only, so the domain travels as the payload's
/// `wire_id` field rather than as an extra hashed prefix. The value is
/// distinct from [`BACKUP_CUTOVER_OPERATION_REQUEST_DOMAIN`], so a
/// payload-content digest and an operation-identity request digest are never
/// the same digest and are never compared as if they were.
pub const BACKUP_CUTOVER_PAYLOAD_CONTENT_DOMAIN: &str = "eliot.backup.cutover-content.v1";
/// Domain separator of the cutover operation-identity request digest.
///
/// The operation request digest is the idempotency domain of the semantic
/// cutover operation ([`crate::HostRequestKind::Invocation`] request
/// correlation, the operation's own mutation identity, and the journal's
/// per-phase mutation identities are distinct). It is derived under this
/// separator and never equals a content digest; sharing a SHA-256 alphabet
/// does not make two digest domains interchangeable.
pub const BACKUP_CUTOVER_OPERATION_REQUEST_DOMAIN: &str = "eliot.backup.cutover-operation.v1";

/// Returns the deterministic identity of the backup control family.
pub fn contract_identity() -> Result<ContractIdentity, BackupError> {
    let shape = serde_json::json!({
        "contract": BACKUP_CONTRACT_NAME,
        "version": BACKUP_CONTRACT_VERSION,
        "encoding": BACKUP_CANONICAL_ENCODING,
        "operations": [
            "REQUEST_CAPTURE",
            "READ_SNAPSHOT_PAGE",
            "VERIFY_ARCHIVE",
            "PREPARE_ISOLATED_RESTORE",
            "RESTORE_STEP",
            "RECONCILE_RESTORE",
            "RESTORE_STATUS",
            "COMPLETE_REHEARSAL",
            "ADMIT_CUTOVER",
        ],
        "roles": [
            "REQUESTER",
            "CAPTURE_OWNER",
            "STORE_OWNER",
            "ORS_OWNER",
            "SPOOL_OWNER",
            "VERIFIER",
            "INSTALLATION_AUTHORITY",
            "HOST_FORENSIC",
        ],
        "classes": ["FULL_RECOVERY", "CANONICAL_ONLY_DEGRADED", "SCOPE_EXPORT"],
    });
    eliot_contracts::contract_identity(BACKUP_CONTRACT_NAME, BACKUP_CONTRACT_VERSION, &shape)
        .map_err(BackupError::Foundation)
}

// ---------------------------------------------------------------------------
// Error and bounded primitives.
// ---------------------------------------------------------------------------

/// Pure validation failures for the backup control boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BackupError {
    /// The existing generic protocol owner rejected a mapped value.
    #[error("protocol: {0}")]
    Protocol(#[from] ProtocolError),
    /// A foundation contract rejected an identity, fence, or contract value.
    #[error("foundation contract: {0}")]
    Foundation(#[from] ContractError),
    /// A required backup field is absent or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Stable bounded reason.
        reason: &'static str,
    },
    /// A supplied value does not match the bound request identity.
    #[error("{field} does not match the bound backup identity")]
    Mismatch {
        /// Field path that diverged.
        field: &'static str,
    },
    /// A canonical identity was reused with changed content.
    #[error("backup replay identity conflicts with changed content")]
    ReplayConflict,
    /// The authenticated role lacks the requested capability.
    #[error("role does not have the requested backup capability")]
    CapabilityDenied,
    /// A fence, epoch, or admission binding does not match.
    #[error("backup fence or admission binding mismatch")]
    FenceMismatch,
    /// An operation identity does not match its typed operation.
    #[error("backup operation identity does not match its typed operation")]
    OperationMismatch,
    /// A supplied value exceeds its bounded wire limit.
    #[error("backup field exceeds the bounded wire limit: {0}")]
    LimitExceeded(&'static str),
    /// Canonical serialization failed.
    #[error("backup canonical serialization failed: {0}")]
    Serialization(String),
}

fn bounded_text(value: &str, field: &'static str, maximum_bytes: usize) -> Result<(), BackupError> {
    if value.trim().is_empty() {
        return Err(BackupError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(BackupError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > maximum_bytes {
        return Err(BackupError::LimitExceeded(field));
    }
    Ok(())
}

fn lowercase_sha256(value: &str, field: &'static str) -> Result<(), BackupError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(BackupError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

fn check_wire(
    wire_id: &str,
    wire_version: u16,
    expected_id: &str,
    expected_version: u16,
    field: &'static str,
) -> Result<(), BackupError> {
    if wire_id != expected_id || wire_version != expected_version {
        return Err(BackupError::InvalidField {
            field,
            reason: "unsupported backup wire identity or version",
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Closed operation, role, class, disposition, and stage vocabularies.
// ---------------------------------------------------------------------------

/// Closed operation vocabulary for the backup control surface.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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

impl fmt::Display for BackupOperationKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Operation capability projection used for local shape checks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupCapability {
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

/// Authenticated role projection. A value in a payload never grants this role.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupRole {
    Requester,
    CaptureOwner,
    StoreOwner,
    OrsOwner,
    SpoolOwner,
    Verifier,
    InstallationAuthority,
    HostForensic,
}

impl BackupRole {
    /// Returns the closed capability projection for the role.
    #[must_use]
    pub const fn capabilities(self) -> &'static [BackupCapability] {
        match self {
            Self::Requester => &[
                BackupCapability::RequestCapture,
                BackupCapability::ReadSnapshotPage,
                BackupCapability::VerifyArchive,
                BackupCapability::PrepareIsolatedRestore,
                BackupCapability::RestoreStatus,
                BackupCapability::ReconcileRestore,
            ],
            Self::CaptureOwner => &[
                BackupCapability::ReadSnapshotPage,
                BackupCapability::RestoreStatus,
                BackupCapability::ReconcileRestore,
            ],
            Self::StoreOwner | Self::OrsOwner | Self::SpoolOwner => &[
                BackupCapability::RestoreStep,
                BackupCapability::RestoreStatus,
                BackupCapability::ReconcileRestore,
            ],
            Self::Verifier => &[
                BackupCapability::VerifyArchive,
                BackupCapability::CompleteRehearsal,
                BackupCapability::RestoreStatus,
            ],
            Self::InstallationAuthority => &[
                BackupCapability::PrepareIsolatedRestore,
                BackupCapability::AdmitCutover,
                BackupCapability::RestoreStatus,
            ],
            Self::HostForensic => &[BackupCapability::RestoreStatus],
        }
    }

    /// Returns whether the role may invoke the operation.
    #[must_use]
    pub fn permits(self, operation: BackupOperationKind) -> bool {
        let capability = match operation {
            BackupOperationKind::RequestCapture => BackupCapability::RequestCapture,
            BackupOperationKind::ReadSnapshotPage => BackupCapability::ReadSnapshotPage,
            BackupOperationKind::VerifyArchive => BackupCapability::VerifyArchive,
            BackupOperationKind::PrepareIsolatedRestore => BackupCapability::PrepareIsolatedRestore,
            BackupOperationKind::RestoreStep => BackupCapability::RestoreStep,
            BackupOperationKind::ReconcileRestore => BackupCapability::ReconcileRestore,
            BackupOperationKind::RestoreStatus => BackupCapability::RestoreStatus,
            BackupOperationKind::CompleteRehearsal => BackupCapability::CompleteRehearsal,
            BackupOperationKind::AdmitCutover => BackupCapability::AdmitCutover,
        };
        self.capabilities().contains(&capability)
    }

    /// Returns whether the role may issue owner attestations at all.
    ///
    /// Requesters only request, observe status, and reconcile queries; the
    /// forensic role only observes. Neither may issue success receipts.
    #[must_use]
    pub const fn is_attesting_role(self) -> bool {
        match self {
            Self::Requester | Self::HostForensic => false,
            Self::CaptureOwner
            | Self::StoreOwner
            | Self::OrsOwner
            | Self::SpoolOwner
            | Self::Verifier
            | Self::InstallationAuthority => true,
        }
    }
}

/// Closed backup class vocabulary. Classes never silently change.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupClassWire {
    FullRecovery,
    CanonicalOnlyDegraded,
    ScopeExport,
}

impl BackupClassWire {
    /// Validates a declared-to-evidenced class relation.
    ///
    /// Any change, downgrade or upgrade, is rejected: the evidenced class
    /// must equal the declared class exactly.
    pub fn validate_transition(declared: Self, evidenced: Self) -> Result<(), BackupError> {
        if declared != evidenced {
            return Err(BackupError::InvalidField {
                field: "backup.class",
                reason: "backup class cannot change between declaration and evidence",
            });
        }
        Ok(())
    }
}

/// Closed per-item disposition vocabulary, preserved separately, never a bool.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupDisposition {
    NotAttempted,
    Unsupported,
    Invalid,
    Partial,
    Unknown,
    Accepted,
    Observed,
    Durable,
    Reconciled,
}

/// Closed backup lifecycle labels, kept separate from transport acknowledgement.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupStage {
    Requested,
    Captured,
    Verified,
    RestorePrepared,
    RestoreStepApplied,
    Reconciled,
    RehearsalComplete,
    CutoverAdmitted,
}

impl BackupStage {
    /// Checks one legal lifecycle edge. Replaying the same stage is valid.
    #[must_use]
    pub fn can_advance(from: Self, to: Self) -> bool {
        if from == to {
            return true;
        }
        match from {
            Self::Requested => matches!(to, Self::Captured),
            Self::Captured => matches!(to, Self::Verified),
            Self::Verified => matches!(to, Self::RestorePrepared),
            Self::RestorePrepared => matches!(to, Self::RestoreStepApplied),
            Self::RestoreStepApplied => matches!(to, Self::Reconciled),
            Self::Reconciled => matches!(to, Self::RehearsalComplete),
            Self::RehearsalComplete => matches!(to, Self::CutoverAdmitted),
            Self::CutoverAdmitted => false,
        }
    }

    /// Validates a stage advance without changing any state.
    pub fn validate_advance(from: Self, to: Self) -> Result<(), BackupError> {
        if Self::can_advance(from, to) {
            Ok(())
        } else {
            Err(BackupError::InvalidField {
                field: "backup.stage",
                reason: "illegal backup lifecycle transition",
            })
        }
    }
}

/// Returns the operation that establishes a lifecycle stage.
#[must_use]
pub const fn operation_for_phase(stage: BackupStage) -> BackupOperationKind {
    match stage {
        BackupStage::Requested => BackupOperationKind::RequestCapture,
        BackupStage::Captured => BackupOperationKind::ReadSnapshotPage,
        BackupStage::Verified => BackupOperationKind::VerifyArchive,
        BackupStage::RestorePrepared => BackupOperationKind::PrepareIsolatedRestore,
        BackupStage::RestoreStepApplied => BackupOperationKind::RestoreStep,
        BackupStage::Reconciled => BackupOperationKind::ReconcileRestore,
        BackupStage::RehearsalComplete => BackupOperationKind::CompleteRehearsal,
        BackupStage::CutoverAdmitted => BackupOperationKind::AdmitCutover,
    }
}

/// Returns the closed set of roles that may attest a lifecycle stage.
///
/// An empty set means no attestation exists for the stage: requests are not
/// receipts, so [`BackupStage::Requested`] admits no attester.
#[must_use]
pub const fn attesting_roles(stage: BackupStage) -> &'static [BackupRole] {
    match stage {
        BackupStage::Requested => &[],
        BackupStage::Captured => &[BackupRole::CaptureOwner],
        BackupStage::Verified | BackupStage::RehearsalComplete => &[BackupRole::Verifier],
        BackupStage::RestorePrepared => {
            &[BackupRole::StoreOwner, BackupRole::InstallationAuthority]
        }
        BackupStage::RestoreStepApplied | BackupStage::Reconciled => &[
            BackupRole::StoreOwner,
            BackupRole::OrsOwner,
            BackupRole::SpoolOwner,
        ],
        BackupStage::CutoverAdmitted => &[BackupRole::InstallationAuthority],
    }
}

/// Maps a transport acknowledgement phase to a backup lifecycle stage.
///
/// Always returns `None`: a transport acknowledgement, at any phase including
/// `DURABLE` or `APPLIED`, never establishes capture, restore, rehearsal, or
/// reconciliation success. Semantic stages advance only through owner
/// attestations validated against the bound request identity.
#[must_use]
pub const fn ack_phase_stage(_phase: AckPhase) -> Option<BackupStage> {
    None
}

// ---------------------------------------------------------------------------
// Identity, admission, handle, page, denominator, and forensic primitives.
// ---------------------------------------------------------------------------

/// Authenticated principal bound separately from the payload.
///
/// The role carried here is the authenticated projection supplied by the
/// transport owner. Validators always compare it against a separately passed
/// role argument; a payload value never grants a role.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupAuthenticatedPrincipal {
    /// Authenticated principal identity text.
    pub principal: String,
    /// Authenticated session identity text.
    pub session_id: String,
    /// Authenticated role projection.
    pub role: BackupRole,
    /// Authority epoch observed for the principal.
    pub authority_epoch: EpochId,
}

impl BackupAuthenticatedPrincipal {
    /// Validates principal shape without granting authority.
    pub fn validate(&self) -> Result<(), BackupError> {
        bounded_text(
            &self.principal,
            "backup_principal.principal",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        bounded_text(
            &self.session_id,
            "backup_principal.session_id",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        Ok(())
    }
}

/// Stable mutation binding: the operation plus its canonical request digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupMutationBinding {
    /// Closed backup operation bound by this mutation.
    pub operation: BackupOperationKind,
    /// Lowercase SHA-256 over the canonical mutation bytes.
    pub canonical_request_hash: String,
}

impl BackupMutationBinding {
    /// Validates the mutation binding shape.
    pub fn validate(&self) -> Result<(), BackupError> {
        lowercase_sha256(
            &self.canonical_request_hash,
            "backup_mutation.canonical_request_hash",
        )?;
        Ok(())
    }
}

/// Admission reference supplied by the owning authority boundary.
///
/// This is a reference only: authority, scope, capability, and receipt digest.
/// It carries no archive bytes, no state values, and no destination override.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupAdmissionRef {
    /// Authority that issued the admission.
    pub authority: AuthorityBinding,
    /// Scope admitted by the authority.
    pub scope: WorkScopeBinding,
    /// Capability admitted by the authority.
    pub capability: String,
    /// Owner-issued admission receipt reference.
    pub admission_receipt: ReceiptId,
}

impl BackupAdmissionRef {
    /// Validates authority/scope exactness with exact-tuple epoch equality.
    pub fn validate(&self) -> Result<(), BackupError> {
        bounded_text(
            &self.authority.authority_owner,
            "backup_admission.authority.authority_owner",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        self.authority
            .state_fence
            .validate()
            .map_err(BackupError::Foundation)?;
        self.scope
            .state_fence
            .validate()
            .map_err(BackupError::Foundation)?;
        if !self
            .authority
            .state_fence
            .authority_epoch
            .is_same_authority(&self.authority.authority_epoch)
        {
            return Err(BackupError::FenceMismatch);
        }
        if self.scope.resource_generation != self.scope.state_fence.resource_generation {
            return Err(BackupError::FenceMismatch);
        }
        if self.scope.state_fence != self.authority.state_fence {
            return Err(BackupError::FenceMismatch);
        }
        bounded_text(
            &self.capability,
            "backup_admission.capability",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        Ok(())
    }
}

/// Immutable bounded artifact handle. Never a path, URL, or inline body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupArtifactHandle {
    /// Exact owner contract identity of the referenced content.
    pub contract: ContractIdentity,
    /// Owner revision of the referenced content.
    pub source_revision: String,
    /// Canonical digest of the complete referenced content.
    pub content_sha256: String,
    /// Exact byte length; always greater than zero and bounded.
    pub byte_length: u64,
    /// Required immutable artifact handle.
    pub artifact_id: ArtifactId,
}

impl BackupArtifactHandle {
    /// Validates the bounded immutable handle.
    pub fn validate(&self, field: &'static str) -> Result<(), BackupError> {
        self.contract.validate().map_err(BackupError::Foundation)?;
        bounded_text(
            &self.source_revision,
            "backup_artifact.source_revision",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        lowercase_sha256(&self.content_sha256, "backup_artifact.content_sha256")?;
        if self.byte_length == 0 || self.byte_length > MAX_BACKUP_CONTENT_BYTES as u64 {
            return Err(BackupError::InvalidField {
                field,
                reason: "byte_length must be nonzero and within the bounded wire length",
            });
        }
        Ok(())
    }
}

/// Immutable bounded snapshot page reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupPageRef {
    /// Canonical digest of the complete page content.
    pub page_digest: String,
    /// Zero-based page index within the bounded snapshot.
    pub page_index: u64,
    /// Members carried by the page; always nonzero and bounded.
    pub member_count: u32,
}

impl BackupPageRef {
    /// Validates the bounded page reference.
    pub fn validate(&self) -> Result<(), BackupError> {
        lowercase_sha256(&self.page_digest, "backup_page.page_digest")?;
        if self.member_count == 0 || self.member_count > MAX_BACKUP_PAGE_MEMBERS {
            return Err(BackupError::InvalidField {
                field: "backup_page.member_count",
                reason: "member_count must be nonzero and bounded",
            });
        }
        Ok(())
    }
}

/// Explicit coverage denominator. A zero count requires a complete denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Denominator {
    /// True when the denominator is completely known.
    pub complete: bool,
    /// Total items in the denominator.
    pub total: u64,
}

impl Denominator {
    /// Validates an observed count against this denominator.
    ///
    /// A zero observed count validates only when the denominator is complete;
    /// a complete denominator must equal the observed count exactly; the
    /// observed count can never exceed the denominator total.
    pub fn validate_for_count(&self, observed: u64) -> Result<(), BackupError> {
        if observed > self.total {
            return Err(BackupError::InvalidField {
                field: "backup_denominator.total",
                reason: "observed count cannot exceed the denominator total",
            });
        }
        if observed == 0 && !self.complete {
            return Err(BackupError::InvalidField {
                field: "backup_denominator.complete",
                reason: "a zero count requires a complete denominator",
            });
        }
        if self.complete && observed != self.total {
            return Err(BackupError::InvalidField {
                field: "backup_denominator.total",
                reason: "a complete denominator must equal the observed count",
            });
        }
        Ok(())
    }
}

/// Forensic-only Host audit reference: digests and dispositions, never state.
///
/// Host evidence carried here can never become active authority, fence,
/// epoch, session, or admission input. Structurally there are no such fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostAuditRef {
    /// Forensic audit identity text.
    pub audit_id: String,
    /// Lineage digest of the observed Host evidence chain.
    pub lineage_digest: String,
    /// Deduplicated observed dispositions, bounded.
    pub observed_dispositions: Vec<BackupDisposition>,
}

impl HostAuditRef {
    /// Validates the forensic reference shape.
    pub fn validate(&self) -> Result<(), BackupError> {
        bounded_text(&self.audit_id, "host_audit.audit_id", MAX_BACKUP_TEXT_BYTES)?;
        lowercase_sha256(&self.lineage_digest, "host_audit.lineage_digest")?;
        if self.observed_dispositions.len() > MAX_BACKUP_OBSERVED_DISPOSITIONS {
            return Err(BackupError::LimitExceeded(
                "host_audit.observed_dispositions",
            ));
        }
        let mut seen = BTreeSet::new();
        for disposition in &self.observed_dispositions {
            if !seen.insert(*disposition) {
                return Err(BackupError::InvalidField {
                    field: "host_audit.observed_dispositions",
                    reason: "must not contain duplicate dispositions",
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Request identity: the shared denominator of every backup operation.
// ---------------------------------------------------------------------------

/// Shared request identity bound by every backup operation.
///
/// Binds the authenticated principal, fresh transport request identity,
/// stable mutation binding, archive and contract digests, source and
/// destination installations, class, fence, snapshot and member digests,
/// bounds, deadline, cancellation, and the external admission reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupRequestIdentity {
    /// Must equal [`BACKUP_REQUEST_IDENTITY_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_REQUEST_IDENTITY_WIRE_VERSION`].
    pub wire_version: u16,
    /// Authenticated principal, separate from the payload.
    pub principal: BackupAuthenticatedPrincipal,
    /// Fresh transport correlation owned by the parent protocol.
    pub request: super::RequestIdentity,
    /// Stable mutation operation binding and canonical digest.
    pub mutation: BackupMutationBinding,
    /// Archive identity text.
    pub archive_id: String,
    /// Exact archive owner contract identity.
    pub archive_contract: ContractIdentity,
    /// Canonical digest of the archive descriptor.
    pub archive_digest: String,
    /// Exact attesting owner contract identity.
    pub owner_contract: ContractIdentity,
    /// Canonical digest of the admitted schema.
    pub schema_digest: String,
    /// Canonical digest of the admitted build.
    pub build_digest: String,
    /// Source installation identity; never equal to the destination.
    pub source_installation: String,
    /// Destination installation identity; isolated from the source.
    pub dest_installation: String,
    /// Declared backup class; cannot silently change.
    pub class: BackupClassWire,
    /// Exact state fence observed for the request.
    pub fence: StateFence,
    /// Canonical digest of the owner snapshot.
    pub snapshot_digest: String,
    /// Canonical digest of the snapshot membership.
    pub member_digest: String,
    /// Maximum members admitted per page; nonzero and bounded.
    pub max_page_members: u32,
    /// Maximum canonical payload bytes admitted; nonzero and bounded.
    pub max_payload_bytes: u32,
    /// Absolute deadline in Unix milliseconds; nonzero.
    pub deadline_unix_ms: u64,
    /// Cancellation identity for the request lifecycle.
    pub cancellation_id: String,
    /// External admission reference from the owning authority.
    pub admission: BackupAdmissionRef,
    /// Canonical digest over every field except this field.
    pub identity_digest: String,
}

impl BackupRequestIdentity {
    /// Current request identity contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_REQUEST_IDENTITY_WIRE_VERSION;

    /// Returns deterministic bytes covered by `identity_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.identity_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical identity digest.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical identity digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.identity_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates wire identity, bounds, digests, exact bindings, and digest.
    #[allow(
        clippy::too_many_lines,
        reason = "the request-identity validator keeps the wire-to-semantic check order in one auditable sequence"
    )]
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_REQUEST_IDENTITY_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_request_identity.wire",
        )?;
        bounded_text(
            &self.archive_id,
            "backup_request_identity.archive_id",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        bounded_text(
            &self.source_installation,
            "backup_request_identity.source_installation",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        bounded_text(
            &self.dest_installation,
            "backup_request_identity.dest_installation",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        bounded_text(
            &self.cancellation_id,
            "backup_request_identity.cancellation_id",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        for (value, field) in [
            (
                self.archive_digest.as_str(),
                "backup_request_identity.archive_digest",
            ),
            (
                self.schema_digest.as_str(),
                "backup_request_identity.schema_digest",
            ),
            (
                self.build_digest.as_str(),
                "backup_request_identity.build_digest",
            ),
            (
                self.snapshot_digest.as_str(),
                "backup_request_identity.snapshot_digest",
            ),
            (
                self.member_digest.as_str(),
                "backup_request_identity.member_digest",
            ),
            (
                self.mutation.canonical_request_hash.as_str(),
                "backup_request_identity.canonical_request_hash",
            ),
        ] {
            lowercase_sha256(value, field)?;
        }
        if self.max_page_members == 0 || self.max_page_members > MAX_BACKUP_PAGE_MEMBERS {
            return Err(BackupError::InvalidField {
                field: "backup_request_identity.max_page_members",
                reason: "must be nonzero and bounded",
            });
        }
        if self.max_payload_bytes == 0 || self.max_payload_bytes as usize > MAX_BACKUP_PAYLOAD_BYTES
        {
            return Err(BackupError::InvalidField {
                field: "backup_request_identity.max_payload_bytes",
                reason: "must be nonzero and bounded",
            });
        }
        if self.deadline_unix_ms == 0 {
            return Err(BackupError::InvalidField {
                field: "backup_request_identity.deadline_unix_ms",
                reason: "must be greater than zero",
            });
        }
        self.principal.validate()?;
        self.request.validate()?;
        self.mutation.validate()?;
        self.fence.validate().map_err(BackupError::Foundation)?;
        if self.fence != self.request.request.state_fence {
            return Err(BackupError::FenceMismatch);
        }
        if !self
            .principal
            .authority_epoch
            .is_same_authority(&self.fence.authority_epoch)
        {
            return Err(BackupError::FenceMismatch);
        }
        self.archive_contract
            .validate()
            .map_err(BackupError::Foundation)?;
        self.owner_contract
            .validate()
            .map_err(BackupError::Foundation)?;
        if self.source_installation == self.dest_installation {
            return Err(BackupError::InvalidField {
                field: "backup_request_identity.dest_installation",
                reason: "destination must be isolated from the source",
            });
        }
        self.admission.validate()?;
        if self.admission.scope.state_fence != self.fence {
            return Err(BackupError::FenceMismatch);
        }
        if !self
            .admission
            .authority
            .authority_epoch
            .is_same_authority(&self.fence.authority_epoch)
        {
            return Err(BackupError::FenceMismatch);
        }
        lowercase_sha256(
            &self.identity_digest,
            "backup_request_identity.identity_digest",
        )?;
        if self.identity_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_request_identity.identity_digest",
                reason: "identity digest mismatch",
            });
        }
        Ok(())
    }

    /// Requires the separately authenticated role to equal the bound principal.
    pub fn check_authenticated_role(
        &self,
        authenticated_role: BackupRole,
    ) -> Result<(), BackupError> {
        if authenticated_role != self.principal.role {
            return Err(BackupError::CapabilityDenied);
        }
        Ok(())
    }

    /// Map to the existing generic envelope using an immutable content handle.
    /// This constructs no queue entry and is not a delivery receipt.
    pub fn to_event_envelope(
        &self,
        stream_id: &str,
        producer_generation: ResourceGeneration,
        sequence: u64,
    ) -> Result<EventEnvelope, BackupError> {
        self.validate()?;
        bounded_text(
            stream_id,
            "backup_envelope.stream_id",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        let envelope = EventEnvelope {
            stream_id: stream_id.to_owned(),
            producer_id: BACKUP_PRODUCER_ID.to_owned(),
            producer_generation,
            authority_epoch: self.fence.authority_epoch.clone(),
            event_id: format!(
                "backup:{}:{}",
                self.mutation.operation.as_str(),
                self.identity_digest
            ),
            sequence,
            causal_predecessor_refs: Vec::new(),
            delivery_class: DeliveryClass::DurableControl,
            ack_required: true,
            payload_type: BACKUP_PAYLOAD_TYPE.to_owned(),
            payload_or_blob_ref: EventPayload::BlobRef(format!(
                "backup/sha256/{}",
                self.identity_digest
            )),
            state_fence: self.fence.clone(),
            trace_context: std::collections::BTreeMap::default(),
        };
        envelope.validate()?;
        Ok(envelope)
    }
}

// ---------------------------------------------------------------------------
// Per-operation request shapes. One closed type per operation.
// ---------------------------------------------------------------------------

/// Request for a bounded capture owned by the capture owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupCaptureRequest {
    /// Must equal [`BACKUP_CAPTURE_REQUEST_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_CAPTURE_REQUEST_WIRE_VERSION`].
    pub wire_version: u16,
    /// Bound request identity.
    pub identity: BackupRequestIdentity,
    /// Must be [`BackupOperationKind::RequestCapture`].
    pub operation: BackupOperationKind,
    /// Maximum snapshot bytes admitted for the capture.
    pub max_snapshot_bytes: u64,
    /// Canonical digest over every field except this field.
    pub request_digest: String,
}

impl BackupCaptureRequest {
    /// Current capture request contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_CAPTURE_REQUEST_WIRE_VERSION;

    /// Returns deterministic bytes covered by `request_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.request_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical request digest.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical request digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.request_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates wire identity, bindings, operation, bounds, and digest.
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_CAPTURE_REQUEST_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_capture_request.wire",
        )?;
        self.identity.validate()?;
        if self.operation != BackupOperationKind::RequestCapture
            || self.identity.mutation.operation != BackupOperationKind::RequestCapture
        {
            return Err(BackupError::OperationMismatch);
        }
        if self.max_snapshot_bytes == 0 || self.max_snapshot_bytes > MAX_BACKUP_PAYLOAD_BYTES as u64
        {
            return Err(BackupError::InvalidField {
                field: "backup_capture_request.max_snapshot_bytes",
                reason: "must be nonzero and bounded",
            });
        }
        lowercase_sha256(
            &self.request_digest,
            "backup_capture_request.request_digest",
        )?;
        if self.request_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_capture_request.request_digest",
                reason: "request digest mismatch",
            });
        }
        Ok(())
    }
}

/// Bounded page read of an owner snapshot via an opaque handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupSnapshotPageRead {
    /// Must equal [`BACKUP_SNAPSHOT_PAGE_READ_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_SNAPSHOT_PAGE_READ_WIRE_VERSION`].
    pub wire_version: u16,
    /// Bound request identity.
    pub identity: BackupRequestIdentity,
    /// Must be [`BackupOperationKind::ReadSnapshotPage`].
    pub operation: BackupOperationKind,
    /// Immutable artifact handle of the owner snapshot.
    pub handle: BackupArtifactHandle,
    /// Bounded page reference within the snapshot.
    pub page: BackupPageRef,
    /// Exact page body byte length; nonzero and bounded.
    pub page_byte_length: u64,
    /// Canonical digest over every field except this field.
    pub request_digest: String,
}

impl BackupSnapshotPageRead {
    /// Current page read contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_SNAPSHOT_PAGE_READ_WIRE_VERSION;

    /// Returns deterministic bytes covered by `request_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.request_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical request digest.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical request digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.request_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates wire identity, bindings, handle, page, bounds, and digest.
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_SNAPSHOT_PAGE_READ_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_snapshot_page_read.wire",
        )?;
        self.identity.validate()?;
        if self.operation != BackupOperationKind::ReadSnapshotPage
            || self.identity.mutation.operation != BackupOperationKind::ReadSnapshotPage
        {
            return Err(BackupError::OperationMismatch);
        }
        self.handle.validate("backup_snapshot_page_read.handle")?;
        self.page.validate()?;
        if self.page_byte_length == 0 || self.page_byte_length > MAX_BACKUP_CONTENT_BYTES as u64 {
            return Err(BackupError::InvalidField {
                field: "backup_snapshot_page_read.page_byte_length",
                reason: "must be nonzero and bounded",
            });
        }
        if self.page.member_count > self.identity.max_page_members {
            return Err(BackupError::InvalidField {
                field: "backup_snapshot_page_read.page.member_count",
                reason: "page exceeds the admitted page bound",
            });
        }
        lowercase_sha256(
            &self.request_digest,
            "backup_snapshot_page_read.request_digest",
        )?;
        if self.request_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_snapshot_page_read.request_digest",
                reason: "request digest mismatch",
            });
        }
        Ok(())
    }
}

/// Archive verification request answered by the verifier alone.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupArchiveVerification {
    /// Must equal [`BACKUP_ARCHIVE_VERIFICATION_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_ARCHIVE_VERIFICATION_WIRE_VERSION`].
    pub wire_version: u16,
    /// Bound request identity.
    pub identity: BackupRequestIdentity,
    /// Must be [`BackupOperationKind::VerifyArchive`].
    pub operation: BackupOperationKind,
    /// Immutable artifact handle of the archive under verification.
    pub handle: BackupArtifactHandle,
    /// Believed archive digest; must equal the bound archive digest.
    pub believed_archive_digest: String,
    /// Canonical digest over every field except this field.
    pub request_digest: String,
}

impl BackupArchiveVerification {
    /// Current archive verification contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_ARCHIVE_VERIFICATION_WIRE_VERSION;

    /// Returns deterministic bytes covered by `request_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.request_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical request digest.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical request digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.request_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates wire identity, bindings, handle, digest exactness, and digest.
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_ARCHIVE_VERIFICATION_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_archive_verification.wire",
        )?;
        self.identity.validate()?;
        if self.operation != BackupOperationKind::VerifyArchive
            || self.identity.mutation.operation != BackupOperationKind::VerifyArchive
        {
            return Err(BackupError::OperationMismatch);
        }
        self.handle.validate("backup_archive_verification.handle")?;
        lowercase_sha256(
            &self.believed_archive_digest,
            "backup_archive_verification.believed_archive_digest",
        )?;
        if self.believed_archive_digest != self.identity.archive_digest {
            return Err(BackupError::Mismatch {
                field: "backup_archive_verification.believed_archive_digest",
            });
        }
        lowercase_sha256(
            &self.request_digest,
            "backup_archive_verification.request_digest",
        )?;
        if self.request_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_archive_verification.request_digest",
                reason: "request digest mismatch",
            });
        }
        Ok(())
    }
}

/// Isolated restore preparation. Destination only; there is no source field
/// and therefore no source override.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupIsolatedRestorePrepare {
    /// Must equal [`BACKUP_ISOLATED_RESTORE_PREPARE_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_ISOLATED_RESTORE_PREPARE_WIRE_VERSION`].
    pub wire_version: u16,
    /// Bound request identity.
    pub identity: BackupRequestIdentity,
    /// Must be [`BackupOperationKind::PrepareIsolatedRestore`].
    pub operation: BackupOperationKind,
    /// Destination installation; must equal the bound destination.
    pub destination_installation: String,
    /// Maximum restore bytes admitted for the isolated destination.
    pub max_restore_bytes: u64,
    /// Canonical digest over every field except this field.
    pub request_digest: String,
}

impl BackupIsolatedRestorePrepare {
    /// Current restore preparation contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_ISOLATED_RESTORE_PREPARE_WIRE_VERSION;

    /// Returns deterministic bytes covered by `request_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.request_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical request digest.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical request digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.request_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates wire identity, destination exactness, bounds, and digest.
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_ISOLATED_RESTORE_PREPARE_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_isolated_restore_prepare.wire",
        )?;
        self.identity.validate()?;
        if self.operation != BackupOperationKind::PrepareIsolatedRestore
            || self.identity.mutation.operation != BackupOperationKind::PrepareIsolatedRestore
        {
            return Err(BackupError::OperationMismatch);
        }
        bounded_text(
            &self.destination_installation,
            "backup_isolated_restore_prepare.destination_installation",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        if self.destination_installation != self.identity.dest_installation {
            return Err(BackupError::Mismatch {
                field: "backup_isolated_restore_prepare.destination_installation",
            });
        }
        if self.max_restore_bytes == 0 || self.max_restore_bytes > MAX_BACKUP_PAYLOAD_BYTES as u64 {
            return Err(BackupError::InvalidField {
                field: "backup_isolated_restore_prepare.max_restore_bytes",
                reason: "must be nonzero and bounded",
            });
        }
        lowercase_sha256(
            &self.request_digest,
            "backup_isolated_restore_prepare.request_digest",
        )?;
        if self.request_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_isolated_restore_prepare.request_digest",
                reason: "request digest mismatch",
            });
        }
        Ok(())
    }
}

/// One operation-bound restore step executed by the owning phase owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupRestoreStep {
    /// Must equal [`BACKUP_RESTORE_STEP_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_RESTORE_STEP_WIRE_VERSION`].
    pub wire_version: u16,
    /// Bound request identity.
    pub identity: BackupRequestIdentity,
    /// Must be [`BackupOperationKind::RestoreStep`].
    pub operation: BackupOperationKind,
    /// Zero-based step index within the admitted restore.
    pub step_index: u64,
    /// Canonical digest of the step content retained by the owner.
    pub step_digest: String,
    /// Digest of the predecessor step, or the preparation digest for step zero.
    pub predecessor_digest: String,
    /// Canonical digest over every field except this field.
    pub request_digest: String,
}

impl BackupRestoreStep {
    /// Current restore step contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_RESTORE_STEP_WIRE_VERSION;

    /// Returns deterministic bytes covered by `request_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.request_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical request digest.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical request digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.request_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates wire identity, bindings, step linkage, and digest.
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_RESTORE_STEP_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_restore_step.wire",
        )?;
        self.identity.validate()?;
        if self.operation != BackupOperationKind::RestoreStep
            || self.identity.mutation.operation != BackupOperationKind::RestoreStep
        {
            return Err(BackupError::OperationMismatch);
        }
        lowercase_sha256(&self.step_digest, "backup_restore_step.step_digest")?;
        lowercase_sha256(
            &self.predecessor_digest,
            "backup_restore_step.predecessor_digest",
        )?;
        lowercase_sha256(&self.request_digest, "backup_restore_step.request_digest")?;
        if self.request_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_restore_step.request_digest",
                reason: "request digest mismatch",
            });
        }
        Ok(())
    }
}

/// Restore reconcile query answered from retained digests only, never by
/// recomputing semantics. Carries no content, only the believed digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupRestoreReconcile {
    /// Must equal [`BACKUP_RESTORE_RECONCILE_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_RESTORE_RECONCILE_WIRE_VERSION`].
    pub wire_version: u16,
    /// Bound request identity.
    pub identity: BackupRequestIdentity,
    /// Must be [`BackupOperationKind::ReconcileRestore`].
    pub operation: BackupOperationKind,
    /// Retained digest the requester believes was recorded.
    pub believed_digest: String,
    /// Canonical digest over every field except this field.
    pub request_digest: String,
}

impl BackupRestoreReconcile {
    /// Current restore reconcile contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_RESTORE_RECONCILE_WIRE_VERSION;

    /// Returns deterministic bytes covered by `request_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.request_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical request digest.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical request digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.request_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates wire identity, bindings, retained digest, and digest.
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_RESTORE_RECONCILE_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_restore_reconcile.wire",
        )?;
        self.identity.validate()?;
        if self.operation != BackupOperationKind::ReconcileRestore
            || self.identity.mutation.operation != BackupOperationKind::ReconcileRestore
        {
            return Err(BackupError::OperationMismatch);
        }
        lowercase_sha256(
            &self.believed_digest,
            "backup_restore_reconcile.believed_digest",
        )?;
        lowercase_sha256(
            &self.request_digest,
            "backup_restore_reconcile.request_digest",
        )?;
        if self.request_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_restore_reconcile.request_digest",
                reason: "request digest mismatch",
            });
        }
        Ok(())
    }
}

/// Read-only restore status query within the requester authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupRestoreStatus {
    /// Must equal [`BACKUP_RESTORE_STATUS_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_RESTORE_STATUS_WIRE_VERSION`].
    pub wire_version: u16,
    /// Bound request identity.
    pub identity: BackupRequestIdentity,
    /// Must be [`BackupOperationKind::RestoreStatus`].
    pub operation: BackupOperationKind,
    /// Last stage observed by the requester; advisory only.
    pub observed_stage: BackupStage,
    /// Canonical digest over every field except this field.
    pub request_digest: String,
}

impl BackupRestoreStatus {
    /// Current restore status contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_RESTORE_STATUS_WIRE_VERSION;

    /// Returns deterministic bytes covered by `request_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.request_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical request digest.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical request digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.request_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates wire identity, bindings, and digest. Read-only: no mutation.
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_RESTORE_STATUS_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_restore_status.wire",
        )?;
        self.identity.validate()?;
        if self.operation != BackupOperationKind::RestoreStatus
            || self.identity.mutation.operation != BackupOperationKind::RestoreStatus
        {
            return Err(BackupError::OperationMismatch);
        }
        lowercase_sha256(&self.request_digest, "backup_restore_status.request_digest")?;
        if self.request_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_restore_status.request_digest",
                reason: "request digest mismatch",
            });
        }
        Ok(())
    }
}

/// Rehearsal completion record. Never carries cutover or retirement: there
/// are no such fields, so a rehearsal cannot select them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupRehearsalComplete {
    /// Must equal [`BACKUP_REHEARSAL_COMPLETE_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_REHEARSAL_COMPLETE_WIRE_VERSION`].
    pub wire_version: u16,
    /// Bound request identity.
    pub identity: BackupRequestIdentity,
    /// Must be [`BackupOperationKind::CompleteRehearsal`].
    pub operation: BackupOperationKind,
    /// Canonical digest of the rehearsal evidence retained by the owner.
    pub rehearsal_digest: String,
    /// Evidenced class; must equal the declared class exactly.
    pub observed_class: BackupClassWire,
    /// Canonical digest over every field except this field.
    pub request_digest: String,
}

impl BackupRehearsalComplete {
    /// Current rehearsal completion contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_REHEARSAL_COMPLETE_WIRE_VERSION;

    /// Returns deterministic bytes covered by `request_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.request_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical request digest.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical request digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.request_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates wire identity, bindings, class exactness, and digest.
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_REHEARSAL_COMPLETE_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_rehearsal_complete.wire",
        )?;
        self.identity.validate()?;
        if self.operation != BackupOperationKind::CompleteRehearsal
            || self.identity.mutation.operation != BackupOperationKind::CompleteRehearsal
        {
            return Err(BackupError::OperationMismatch);
        }
        lowercase_sha256(
            &self.rehearsal_digest,
            "backup_rehearsal_complete.rehearsal_digest",
        )?;
        BackupClassWire::validate_transition(self.identity.class, self.observed_class)?;
        lowercase_sha256(
            &self.request_digest,
            "backup_rehearsal_complete.request_digest",
        )?;
        if self.request_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_rehearsal_complete.request_digest",
                reason: "request digest mismatch",
            });
        }
        Ok(())
    }

    /// Validates rehearsal completion against the bound request.
    ///
    /// Only the verifier completes rehearsals; rehearsal evidence never
    /// admits cutover or retirement because no such binding exists.
    pub fn validate_against(
        &self,
        request: &BackupRequestIdentity,
        authenticated_role: BackupRole,
    ) -> Result<(), BackupError> {
        self.validate()?;
        request.validate()?;
        self.identity.check_authenticated_role(authenticated_role)?;
        if authenticated_role != BackupRole::Verifier {
            return Err(BackupError::CapabilityDenied);
        }
        if !authenticated_role.permits(BackupOperationKind::CompleteRehearsal) {
            return Err(BackupError::CapabilityDenied);
        }
        if self.identity.archive_id != request.archive_id
            || self.identity.identity_digest != request.identity_digest
        {
            return Err(BackupError::Mismatch {
                field: "backup_rehearsal_complete.identity",
            });
        }
        Ok(())
    }
}

/// Explicit separately admitted installation cutover.
///
/// Cutover is never selectable from a restore-test request: this type binds a
/// distinct operation and requires a separate installation authority
/// admission validated against the known installation authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupCutoverAdmission {
    /// Must equal [`BACKUP_CUTOVER_ADMISSION_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_CUTOVER_ADMISSION_WIRE_VERSION`].
    pub wire_version: u16,
    /// Bound request identity.
    pub identity: BackupRequestIdentity,
    /// Must be [`BackupOperationKind::AdmitCutover`].
    pub operation: BackupOperationKind,
    /// Separate installation authority admission for the cutover.
    pub installation_admission: BackupAdmissionRef,
    /// Canonical digest of the admitted cutover plan.
    pub cutover_plan_digest: String,
    /// Canonical digest over every field except this field.
    pub request_digest: String,
}

impl BackupCutoverAdmission {
    /// Current cutover admission contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_CUTOVER_ADMISSION_WIRE_VERSION;

    /// Returns deterministic bytes covered by `request_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.request_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical request digest.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical request digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.request_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates wire identity, bindings, admission shape, and digest.
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_CUTOVER_ADMISSION_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_cutover_admission.wire",
        )?;
        self.identity.validate()?;
        if self.operation != BackupOperationKind::AdmitCutover
            || self.identity.mutation.operation != BackupOperationKind::AdmitCutover
        {
            return Err(BackupError::OperationMismatch);
        }
        self.installation_admission.validate()?;
        lowercase_sha256(
            &self.cutover_plan_digest,
            "backup_cutover_admission.cutover_plan_digest",
        )?;
        lowercase_sha256(
            &self.request_digest,
            "backup_cutover_admission.request_digest",
        )?;
        if self.request_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_cutover_admission.request_digest",
                reason: "request digest mismatch",
            });
        }
        Ok(())
    }

    /// Validates cutover against the bound request and the known installation
    /// authority, passed separately from the payload.
    ///
    /// Only the installation authority admits cutover. The carried admission
    /// must name the exact installation authority identity, share its exact
    /// authority lineage, and name the bound destination installation.
    pub fn validate_against(
        &self,
        request: &BackupRequestIdentity,
        authenticated_role: BackupRole,
        installation_authority: &AuthorityBinding,
    ) -> Result<(), BackupError> {
        self.validate()?;
        request.validate()?;
        self.identity.check_authenticated_role(authenticated_role)?;
        if authenticated_role != BackupRole::InstallationAuthority {
            return Err(BackupError::CapabilityDenied);
        }
        if self.identity.archive_id != request.archive_id
            || self.identity.identity_digest != request.identity_digest
        {
            return Err(BackupError::Mismatch {
                field: "backup_cutover_admission.identity",
            });
        }
        if self.installation_admission.authority.authority_id != installation_authority.authority_id
        {
            return Err(BackupError::Mismatch {
                field: "backup_cutover_admission.installation_admission.authority",
            });
        }
        if !self
            .installation_admission
            .authority
            .authority_epoch
            .is_same_authority(&installation_authority.authority_epoch)
        {
            return Err(BackupError::FenceMismatch);
        }
        if self.installation_admission.authority.authority_owner != request.dest_installation {
            return Err(BackupError::Mismatch {
                field: "backup_cutover_admission.installation_admission.authority_owner",
            });
        }
        if self.installation_admission.scope.state_fence != request.fence {
            return Err(BackupError::FenceMismatch);
        }
        Ok(())
    }

    /// Binds an admitted cutover to the exact payload body it admits.
    ///
    /// [`BackupCutoverAdmission::cutover_plan_digest`] is otherwise only
    /// shape-validated. This is the single check that gives that field
    /// meaning: the admitted plan digest must equal the canonical content
    /// digest of the presented body. A changed body carrying the old claimed
    /// digest, a receipt that is internally self-consistent but describes a
    /// different body, and a body that never passed admission all refuse here
    /// with [`BackupError::Mismatch`] on
    /// `backup_cutover_admission.cutover_plan_digest`, before any journal
    /// mutation, effect, or CAS. The admission is validated first, so an
    /// unvalidated admission never reaches the comparison.
    pub fn validate_against_payload(
        &self,
        payload: &BackupCutoverPayload,
    ) -> Result<(), BackupError> {
        self.validate()?;
        payload.validate()?;
        if self.cutover_plan_digest != payload.compute_digest()? {
            return Err(BackupError::Mismatch {
                field: "backup_cutover_admission.cutover_plan_digest",
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Closed cutover payload contract.
// ---------------------------------------------------------------------------

/// Closed, versioned cutover payload: the body an admitted cutover commits to.
///
/// This is the effect-relevant body of an installation cutover and the only
/// schema in this family whose content is admitted by digest. Every field
/// that can change an effect is bound here, so a body cannot be edited after
/// admission without changing its content digest.
///
/// # Three identities, three domains
///
/// ```text
/// HostRequestIdentity::payload_sha256      envelope payload domain
/// BackupCutoverPayload::content_digest      payload content domain
/// BackupCutoverPayload::operation_request_digest  operation identity domain
/// ```
///
/// The first is a digest over opaque bytes the host request carried. The
/// second is a digest over this contract's canonical bytes. The third is
/// derived from the second under
/// [`BACKUP_CUTOVER_OPERATION_REQUEST_DOMAIN`], so it can never equal the
/// content digest, and the first is never assumed equal to either: a SHA-256
/// string is not a shared domain. The journal's per-phase mutation identities
/// ([`BackupMutationBinding::canonical_request_hash`]) remain a further,
/// distinct set; a phase mutation binds the phase, not this body, and nothing
/// here requires those identities to be equal to one another. I5.27 keeps
/// database idempotency and external-effect idempotency separate; this type
/// keeps payload content, envelope payload, operation identity, and per-phase
/// mutation identity separate in the same way. Retries and request
/// correlations that legitimately repeat a body keep the same content digest
/// and the same derived operation request digest.
///
/// # Non-circular encoding
///
/// [`BackupCutoverPayload::canonical_unsigned_bytes`] clears `content_digest`
/// before encoding, so the digest never covers itself. The bytes cover no
/// [`BackupCutoverAdmission`], no receipt, and no admission reference: the
/// admission refers to the body, never the reverse, so the content digest
/// cannot be defined in terms of the admission that admits it.
///
/// # Class vocabulary
///
/// The class is this module's closed [`BackupClassWire`] vocabulary. The real
/// `eliot_backup::BackupClass` owner lives in the backup storage crate, which
/// this protocol crate deliberately does not depend on; an owner readback maps
/// between them, and this contract never carries a parallel class
/// vocabulary of its own.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupCutoverPayload {
    /// Must equal [`BACKUP_CUTOVER_PAYLOAD_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_CUTOVER_PAYLOAD_WIRE_VERSION`].
    pub wire_version: u16,
    /// Installation identity the cutover runs under.
    pub installation_id: String,
    /// Source installation identity; never equal to the destination.
    pub source_installation: String,
    /// Destination installation identity; isolated from the source.
    pub dest_installation: String,
    /// Semantic cutover operation identity.
    pub operation_id: String,
    /// Canonical digest of the archive under cutover.
    pub archive_digest: String,
    /// Declared archive class; cannot silently change.
    pub archive_class: BackupClassWire,
    /// Explicit canonical-only/degraded policy reference; required when the
    /// class is [`BackupClassWire::CanonicalOnlyDegraded`].
    pub canonical_only_policy: Option<String>,
    /// Exact approved target generation to activate.
    pub target_generation: String,
    /// Canonical digest of the approved target build.
    pub target_build_digest: String,
    /// Canonical digest of the approved target configuration.
    pub target_config_digest: String,
    /// Exact active predecessor generation expected at commit time.
    pub expected_predecessor: String,
    /// Owner-issued activation fence for the target generation.
    pub activation_fence: StateFence,
    /// Owner-issued `UserBroker` reference for the destination generation.
    pub user_broker_ref: String,
    /// Canonical digest over every field except this field.
    pub content_digest: String,
}

impl BackupCutoverPayload {
    /// Current cutover payload contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_CUTOVER_PAYLOAD_WIRE_VERSION;

    /// Returns deterministic bytes covered by `content_digest`.
    ///
    /// `content_digest` is cleared before canonical encoding, so the digest
    /// never covers itself. The bytes carry no admission and no receipt.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.content_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical payload content digest.
    ///
    /// This digest belongs to the payload content domain. It is the value
    /// [`BackupCutoverPayload::validate_admitted_payload`] compares with an
    /// admitted [`crate::HostRequestIdentity::payload_sha256`] for the
    /// [`BACKUP_CUTOVER_PAYLOAD_SCHEMA_ID`] schema, and the value a
    /// [`BackupCutoverAdmission::cutover_plan_digest`] must equal. Computing
    /// it proves nothing on its own; it is not an operation request digest,
    /// not a per-phase mutation identity, and not evidence of issuance.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical payload content digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.content_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Returns the claimed payload content digest after checking the body.
    ///
    /// Returns the stored `content_digest` once [`BackupCutoverPayload::validate`]
    /// has proved it equals [`BackupCutoverPayload::compute_digest`], so the
    /// returned value is always the checked content digest of the retained
    /// body. This is a self-consistency check of one record only: it proves
    /// the digest matches the body beside it, never that any other record
    /// admitted that body. Use
    /// [`BackupCutoverPayload::validate_admitted_payload`] to join this body
    /// to an admitted [`crate::HostRequestEnvelope`], and
    /// [`BackupCutoverPayload::operation_request_digest`] for the operation
    /// identity domain.
    pub fn checked_content_digest(&self) -> Result<String, BackupError> {
        self.validate()?;
        Ok(self.content_digest.clone())
    }

    /// Derives the operation-identity request digest from the content digest.
    ///
    /// This is the only construction of the operation identity domain: the
    /// canonical bytes of this payload, the payload content domain, and
    /// [`BACKUP_CUTOVER_OPERATION_REQUEST_DOMAIN`] are hashed together. It is
    /// therefore a function of the body and never equal to a content digest.
    /// The result is the semantic cutover operation identity; it is not the
    /// host request correlation and not a per-phase journal mutation
    /// identity.
    pub fn operation_request_digest(&self) -> Result<String, BackupError> {
        let unsigned = self.canonical_unsigned_bytes()?;
        let mut framed = Vec::new();
        framed.extend_from_slice(BACKUP_CUTOVER_PAYLOAD_CONTENT_DOMAIN.as_bytes());
        framed.push(0);
        framed.extend_from_slice(BACKUP_CUTOVER_OPERATION_REQUEST_DOMAIN.as_bytes());
        framed.push(0);
        framed.extend_from_slice(&unsigned);
        Ok(sha256_hex(&framed))
    }

    /// Validates wire identity, bounds, class policy, fence, and digest.
    #[allow(
        clippy::too_many_lines,
        reason = "the cutover-payload validator keeps the wire-to-semantic check order in one auditable sequence"
    )]
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_CUTOVER_PAYLOAD_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_cutover_payload.wire",
        )?;
        for (value, field) in [
            (
                self.installation_id.as_str(),
                "backup_cutover_payload.installation_id",
            ),
            (
                self.source_installation.as_str(),
                "backup_cutover_payload.source_installation",
            ),
            (
                self.dest_installation.as_str(),
                "backup_cutover_payload.dest_installation",
            ),
            (
                self.operation_id.as_str(),
                "backup_cutover_payload.operation_id",
            ),
            (
                self.target_generation.as_str(),
                "backup_cutover_payload.target_generation",
            ),
            (
                self.expected_predecessor.as_str(),
                "backup_cutover_payload.expected_predecessor",
            ),
            (
                self.user_broker_ref.as_str(),
                "backup_cutover_payload.user_broker_ref",
            ),
        ] {
            bounded_text(value, field, MAX_BACKUP_TEXT_BYTES)?;
        }
        if let Some(policy) = &self.canonical_only_policy {
            bounded_text(
                policy,
                "backup_cutover_payload.canonical_only_policy",
                MAX_BACKUP_TEXT_BYTES,
            )?;
        }
        for (value, field) in [
            (
                self.archive_digest.as_str(),
                "backup_cutover_payload.archive_digest",
            ),
            (
                self.target_build_digest.as_str(),
                "backup_cutover_payload.target_build_digest",
            ),
            (
                self.target_config_digest.as_str(),
                "backup_cutover_payload.target_config_digest",
            ),
            (
                self.content_digest.as_str(),
                "backup_cutover_payload.content_digest",
            ),
        ] {
            lowercase_sha256(value, field)?;
        }
        if self.source_installation == self.dest_installation {
            return Err(BackupError::InvalidField {
                field: "backup_cutover_payload.dest_installation",
                reason: "destination must be isolated from the source",
            });
        }
        if self.target_generation == self.expected_predecessor {
            return Err(BackupError::InvalidField {
                field: "backup_cutover_payload.target_generation",
                reason: "target generation must differ from the expected predecessor",
            });
        }
        if matches!(self.archive_class, BackupClassWire::ScopeExport) {
            return Err(BackupError::InvalidField {
                field: "backup_cutover_payload.archive_class",
                reason: "a scope export is not an installation cutover body",
            });
        }
        if matches!(self.archive_class, BackupClassWire::CanonicalOnlyDegraded)
            && self.canonical_only_policy.is_none()
        {
            return Err(BackupError::InvalidField {
                field: "backup_cutover_payload.canonical_only_policy",
                reason: "canonical-only class requires an explicit degraded policy reference",
            });
        }
        self.activation_fence
            .validate()
            .map_err(BackupError::Foundation)?;
        if self.content_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_cutover_payload.content_digest",
                reason: "content digest mismatch",
            });
        }
        Ok(())
    }

    /// Joins this body to the [`BackupRequestIdentity`] that carries it.
    ///
    /// Source installation, destination installation, class, fence, archive
    /// digest, and admitted build digest are joined here, because a cutover
    /// body that names a different archive, class, fence, or build than the
    /// identity admitting it is not the admitted body. `Mismatch` names the
    /// exact diverging field instead of reporting one generic identity
    /// mismatch.
    pub fn validate_against_identity(
        &self,
        identity: &BackupRequestIdentity,
    ) -> Result<(), BackupError> {
        self.validate()?;
        identity.validate()?;
        if self.source_installation != identity.source_installation {
            return Err(BackupError::Mismatch {
                field: "backup_cutover_payload.source_installation",
            });
        }
        if self.dest_installation != identity.dest_installation {
            return Err(BackupError::Mismatch {
                field: "backup_cutover_payload.dest_installation",
            });
        }
        if self.archive_class != identity.class {
            return Err(BackupError::Mismatch {
                field: "backup_cutover_payload.archive_class",
            });
        }
        if !fences_match_exact(&self.activation_fence, &identity.fence) {
            return Err(BackupError::Mismatch {
                field: "backup_cutover_payload.activation_fence",
            });
        }
        if self.archive_digest != identity.archive_digest {
            return Err(BackupError::Mismatch {
                field: "backup_cutover_payload.archive_digest",
            });
        }
        if self.target_build_digest != identity.build_digest {
            return Err(BackupError::Mismatch {
                field: "backup_cutover_payload.target_build_digest",
            });
        }
        Ok(())
    }

    /// Joins this body to the admitted [`crate::HostRequestEnvelope`] that
    /// commits to it.
    ///
    /// This is the cross-record comparison the cutover boundary needs: the
    /// left side is this body, the right side is
    /// `envelope.identity.payload_sha256`, the opaque commitment the owner
    /// admitted for payload bytes this process never re-reads. It is never a
    /// self-comparison, and it is not a comparison of two fields of the same
    /// record. The envelope is validated by its own owner validator first, so
    /// the commitment compared against is itself a checked record rather than
    /// a self-consistent serialized claim.
    ///
    /// # Why the schema id, not a new `HostRequestKind`, is the discriminator
    ///
    /// [`crate::HostRequestKind`] is a closed five-value wire vocabulary
    /// (`ACTIVATION`, `INVOCATION`, `CANCELLATION`, `STATUS`,
    /// `RECONCILIATION`) with no cutover kind, and that wire is closed, so a
    /// cutover cannot acquire a kind of its own. What separates a cutover body
    /// from `eliot.query` or `eliot.state` is therefore not the kind but the
    /// exact payload schema the owner admitted, which is
    /// [`BACKUP_CUTOVER_PAYLOAD_SCHEMA_ID`]. An unrelated but perfectly valid
    /// admitted `INVOCATION` under any other schema refuses here. The kind
    /// check that follows uses only the existing closed vocabulary: a cutover
    /// body is executed as an `INVOCATION`, so a `CANCELLATION`, `STATUS`,
    /// `RECONCILIATION`, or `ACTIVATION` envelope that happens to carry the
    /// cutover schema id still refuses.
    ///
    /// # Order
    ///
    /// Fail-closed at the first divergence: this body, then the envelope,
    /// then the admitted schema, then the admitted content commitment, then
    /// the kind.
    pub fn validate_admitted_payload(
        &self,
        envelope: &crate::HostRequestEnvelope,
    ) -> Result<(), BackupError> {
        self.validate()?;
        envelope.validate()?;
        if envelope.identity.payload_schema_id != BACKUP_CUTOVER_PAYLOAD_SCHEMA_ID {
            return Err(BackupError::Mismatch {
                field: "host_request.payload_schema_id",
            });
        }
        if self.compute_digest()? != envelope.identity.payload_sha256 {
            return Err(BackupError::Mismatch {
                field: "host_request.payload_sha256",
            });
        }
        if envelope.kind != crate::HostRequestKind::Invocation {
            return Err(BackupError::Mismatch {
                field: "host_request.kind",
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Owner receipts and attestations.
// ---------------------------------------------------------------------------

/// Capture receipt issued by the capture owner for its own bounded snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupCaptureReceipt {
    /// Must equal [`BACKUP_CAPTURE_RECEIPT_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_CAPTURE_RECEIPT_WIRE_VERSION`].
    pub wire_version: u16,
    /// Archive identity text; must equal the bound archive.
    pub archive_id: String,
    /// Snapshot digest attested by the capture owner.
    pub snapshot_digest: String,
    /// Membership digest attested by the capture owner.
    pub member_digest: String,
    /// Captured bytes; nonzero and bounded.
    pub captured_bytes: u64,
    /// Captured members; nonzero and bounded.
    pub captured_members: u32,
    /// Evidenced class; must equal the declared class.
    pub class: BackupClassWire,
    /// Identity text of the attesting capture owner.
    pub attesting_owner: String,
    /// Owner-issued immutable receipt reference.
    pub owner_receipt: ReceiptId,
    /// Exact fence under which the capture was observed.
    pub fence: StateFence,
    /// Observation time in Unix milliseconds; nonzero.
    pub observed_at_unix_ms: u64,
    /// Canonical digest over every field except this field.
    pub receipt_digest: String,
}

impl BackupCaptureReceipt {
    /// Current capture receipt contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_CAPTURE_RECEIPT_WIRE_VERSION;

    /// Returns deterministic bytes covered by `receipt_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.receipt_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical receipt digest.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical receipt digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.receipt_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates wire identity, bounds, digests, fence, and digest.
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_CAPTURE_RECEIPT_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_capture_receipt.wire",
        )?;
        bounded_text(
            &self.archive_id,
            "backup_capture_receipt.archive_id",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        bounded_text(
            &self.attesting_owner,
            "backup_capture_receipt.attesting_owner",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        lowercase_sha256(
            &self.snapshot_digest,
            "backup_capture_receipt.snapshot_digest",
        )?;
        lowercase_sha256(&self.member_digest, "backup_capture_receipt.member_digest")?;
        if self.captured_bytes == 0 || self.captured_bytes > MAX_BACKUP_PAYLOAD_BYTES as u64 {
            return Err(BackupError::InvalidField {
                field: "backup_capture_receipt.captured_bytes",
                reason: "must be nonzero and bounded",
            });
        }
        if self.captured_members == 0 || self.captured_members > MAX_BACKUP_PAGE_MEMBERS {
            return Err(BackupError::InvalidField {
                field: "backup_capture_receipt.captured_members",
                reason: "must be nonzero and bounded",
            });
        }
        self.fence.validate().map_err(BackupError::Foundation)?;
        if self.observed_at_unix_ms == 0 {
            return Err(BackupError::InvalidField {
                field: "backup_capture_receipt.observed_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        lowercase_sha256(
            &self.receipt_digest,
            "backup_capture_receipt.receipt_digest",
        )?;
        if self.receipt_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_capture_receipt.receipt_digest",
                reason: "receipt digest mismatch",
            });
        }
        Ok(())
    }

    /// Validates the capture receipt against the bound request.
    ///
    /// Only the capture owner attests its own bounded snapshot; the
    /// attested digests, class, and fence must equal the bound request.
    pub fn validate_against(
        &self,
        request: &BackupRequestIdentity,
        authenticated_role: BackupRole,
    ) -> Result<(), BackupError> {
        self.validate()?;
        request.validate()?;
        request.check_authenticated_role(authenticated_role)?;
        if authenticated_role != BackupRole::CaptureOwner {
            return Err(BackupError::CapabilityDenied);
        }
        if self.archive_id != request.archive_id
            || self.snapshot_digest != request.snapshot_digest
            || self.member_digest != request.member_digest
        {
            return Err(BackupError::Mismatch {
                field: "backup_capture_receipt.identity",
            });
        }
        BackupClassWire::validate_transition(request.class, self.class)?;
        if self.fence != request.fence {
            return Err(BackupError::Mismatch {
                field: "backup_capture_receipt.fence",
            });
        }
        if self.observed_at_unix_ms > request.deadline_unix_ms {
            return Err(BackupError::InvalidField {
                field: "backup_capture_receipt.observed_at_unix_ms",
                reason: "capture evidence is no longer current",
            });
        }
        Ok(())
    }
}

/// Phase attestation issued by exactly one phase owner for its own phase.
///
/// The attesting owner and owner role are bound explicitly; the separately
/// authenticated role must equal the claimed owner role, and the owner role
/// must be admitted for the attested phase. One owner can never attest
/// another phase.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupPhaseAttestation {
    /// Must equal [`BACKUP_PHASE_ATTESTATION_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_PHASE_ATTESTATION_WIRE_VERSION`].
    pub wire_version: u16,
    /// Identity text of the attesting owner.
    pub attesting_owner: String,
    /// Role of the attesting owner.
    pub owner_role: BackupRole,
    /// Lifecycle stage being attested.
    pub phase: BackupStage,
    /// Owner-issued immutable receipt reference.
    pub owner_receipt: ReceiptId,
    /// Canonical digest of the evidenced phase content.
    pub payload_digest: String,
    /// Archive identity text; must equal the bound archive.
    pub archive_id: String,
    /// Exact fence under which the phase was observed.
    pub fence: StateFence,
    /// Observation time in Unix milliseconds; nonzero.
    pub observed_at_unix_ms: u64,
    /// Canonical digest over every field except this field.
    pub attestation_digest: String,
}

impl BackupPhaseAttestation {
    /// Current phase attestation contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_PHASE_ATTESTATION_WIRE_VERSION;

    /// Returns deterministic bytes covered by `attestation_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.attestation_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical attestation digest.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical attestation digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.attestation_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates wire identity, bounds, digests, fence, and digest.
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_PHASE_ATTESTATION_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_phase_attestation.wire",
        )?;
        bounded_text(
            &self.attesting_owner,
            "backup_phase_attestation.attesting_owner",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        bounded_text(
            &self.archive_id,
            "backup_phase_attestation.archive_id",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        lowercase_sha256(
            &self.payload_digest,
            "backup_phase_attestation.payload_digest",
        )?;
        self.fence.validate().map_err(BackupError::Foundation)?;
        if self.observed_at_unix_ms == 0 {
            return Err(BackupError::InvalidField {
                field: "backup_phase_attestation.observed_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        lowercase_sha256(
            &self.attestation_digest,
            "backup_phase_attestation.attestation_digest",
        )?;
        if self.attestation_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_phase_attestation.attestation_digest",
                reason: "attestation digest mismatch",
            });
        }
        Ok(())
    }

    /// Validates the attestation against the bound request and role.
    ///
    /// The separately authenticated role must equal the claimed owner role;
    /// the owner role must be an attesting role admitted for the phase; the
    /// archive and fence must equal the bound request; the evidence must be
    /// current against the request deadline.
    pub fn validate_against(
        &self,
        request: &BackupRequestIdentity,
        authenticated_role: BackupRole,
    ) -> Result<(), BackupError> {
        self.validate()?;
        request.validate()?;
        request.check_authenticated_role(authenticated_role)?;
        if authenticated_role != self.owner_role {
            return Err(BackupError::CapabilityDenied);
        }
        if !self.owner_role.is_attesting_role() {
            return Err(BackupError::CapabilityDenied);
        }
        if !attesting_roles(self.phase).contains(&self.owner_role) {
            return Err(BackupError::CapabilityDenied);
        }
        if !self.owner_role.permits(operation_for_phase(self.phase)) {
            return Err(BackupError::CapabilityDenied);
        }
        if self.archive_id != request.archive_id {
            return Err(BackupError::Mismatch {
                field: "backup_phase_attestation.archive_id",
            });
        }
        if self.fence != request.fence {
            return Err(BackupError::Mismatch {
                field: "backup_phase_attestation.fence",
            });
        }
        if self.observed_at_unix_ms > request.deadline_unix_ms {
            return Err(BackupError::InvalidField {
                field: "backup_phase_attestation.observed_at_unix_ms",
                reason: "phase evidence is no longer current",
            });
        }
        Ok(())
    }
}

/// Archive validity attestation issued by the verifier alone.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupArchiveValidityAttestation {
    /// Must equal [`BACKUP_ARCHIVE_VALIDITY_ATTESTATION_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_ARCHIVE_VALIDITY_ATTESTATION_WIRE_VERSION`].
    pub wire_version: u16,
    /// Archive identity text; must equal the bound archive.
    pub archive_id: String,
    /// Archive digest verified by the verifier.
    pub archive_digest: String,
    /// Closed validity verdict; never a bool.
    pub verdict: BackupDisposition,
    /// Identity text of the attesting verifier.
    pub attesting_owner: String,
    /// Owner-issued immutable receipt reference.
    pub owner_receipt: ReceiptId,
    /// Exact fence under which validity was observed.
    pub fence: StateFence,
    /// Observation time in Unix milliseconds; nonzero.
    pub observed_at_unix_ms: u64,
    /// Canonical digest over every field except this field.
    pub attestation_digest: String,
}

impl BackupArchiveValidityAttestation {
    /// Current validity attestation contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_ARCHIVE_VALIDITY_ATTESTATION_WIRE_VERSION;

    /// Returns deterministic bytes covered by `attestation_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.attestation_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical attestation digest.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical attestation digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.attestation_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates wire identity, bounds, digests, fence, and digest.
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_ARCHIVE_VALIDITY_ATTESTATION_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_archive_validity_attestation.wire",
        )?;
        bounded_text(
            &self.archive_id,
            "backup_archive_validity_attestation.archive_id",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        bounded_text(
            &self.attesting_owner,
            "backup_archive_validity_attestation.attesting_owner",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        lowercase_sha256(
            &self.archive_digest,
            "backup_archive_validity_attestation.archive_digest",
        )?;
        self.fence.validate().map_err(BackupError::Foundation)?;
        if self.observed_at_unix_ms == 0 {
            return Err(BackupError::InvalidField {
                field: "backup_archive_validity_attestation.observed_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        lowercase_sha256(
            &self.attestation_digest,
            "backup_archive_validity_attestation.attestation_digest",
        )?;
        if self.attestation_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_archive_validity_attestation.attestation_digest",
                reason: "attestation digest mismatch",
            });
        }
        Ok(())
    }

    /// Validates the validity attestation against the bound request.
    ///
    /// Only the verifier attests archive validity; the attested archive
    /// digest and fence must equal the bound request.
    pub fn validate_against(
        &self,
        request: &BackupRequestIdentity,
        authenticated_role: BackupRole,
    ) -> Result<(), BackupError> {
        self.validate()?;
        request.validate()?;
        request.check_authenticated_role(authenticated_role)?;
        if authenticated_role != BackupRole::Verifier {
            return Err(BackupError::CapabilityDenied);
        }
        if self.archive_id != request.archive_id || self.archive_digest != request.archive_digest {
            return Err(BackupError::Mismatch {
                field: "backup_archive_validity_attestation.identity",
            });
        }
        if self.fence != request.fence {
            return Err(BackupError::Mismatch {
                field: "backup_archive_validity_attestation.fence",
            });
        }
        if self.observed_at_unix_ms > request.deadline_unix_ms {
            return Err(BackupError::InvalidField {
                field: "backup_archive_validity_attestation.observed_at_unix_ms",
                reason: "validity evidence is no longer current",
            });
        }
        Ok(())
    }
}

/// Cutover receipt issued by the installation authority alone.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupCutoverReceipt {
    /// Must equal [`BACKUP_CUTOVER_RECEIPT_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`BACKUP_CUTOVER_RECEIPT_WIRE_VERSION`].
    pub wire_version: u16,
    /// Archive identity text; must equal the bound archive.
    pub archive_id: String,
    /// Destination installation admitted for cutover.
    pub dest_installation: String,
    /// Identity text of the attesting installation authority.
    pub attesting_owner: String,
    /// Owner-issued immutable receipt reference.
    pub owner_receipt: ReceiptId,
    /// Separate installation admission receipt reference.
    pub admission_receipt: ReceiptId,
    /// Exact fence under which cutover was admitted.
    pub fence: StateFence,
    /// Observation time in Unix milliseconds; nonzero.
    pub observed_at_unix_ms: u64,
    /// Canonical digest over every field except this field.
    pub receipt_digest: String,
}

impl BackupCutoverReceipt {
    /// Current cutover receipt contract version.
    pub const CONTRACT_VERSION: u16 = BACKUP_CUTOVER_RECEIPT_WIRE_VERSION;

    /// Returns deterministic bytes covered by `receipt_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut unsigned = self.clone();
        unsigned.receipt_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Computes the canonical receipt digest.
    pub fn compute_digest(&self) -> Result<String, BackupError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical receipt digest.
    pub fn with_computed_digest(mut self) -> Result<Self, BackupError> {
        self.receipt_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates wire identity, bounds, fence, and digest.
    pub fn validate(&self) -> Result<(), BackupError> {
        check_wire(
            &self.wire_id,
            self.wire_version,
            BACKUP_CUTOVER_RECEIPT_WIRE_ID,
            Self::CONTRACT_VERSION,
            "backup_cutover_receipt.wire",
        )?;
        bounded_text(
            &self.archive_id,
            "backup_cutover_receipt.archive_id",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        bounded_text(
            &self.dest_installation,
            "backup_cutover_receipt.dest_installation",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        bounded_text(
            &self.attesting_owner,
            "backup_cutover_receipt.attesting_owner",
            MAX_BACKUP_TEXT_BYTES,
        )?;
        self.fence.validate().map_err(BackupError::Foundation)?;
        if self.observed_at_unix_ms == 0 {
            return Err(BackupError::InvalidField {
                field: "backup_cutover_receipt.observed_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        lowercase_sha256(
            &self.receipt_digest,
            "backup_cutover_receipt.receipt_digest",
        )?;
        if self.receipt_digest != self.compute_digest()? {
            return Err(BackupError::InvalidField {
                field: "backup_cutover_receipt.receipt_digest",
                reason: "receipt digest mismatch",
            });
        }
        Ok(())
    }

    /// Validates the cutover receipt against the bound request.
    ///
    /// Only the installation authority admits cutover. The known
    /// installation authority, passed separately from the payload, must
    /// share the exact authority lineage of the bound fence and must name
    /// the bound destination installation.
    pub fn validate_against(
        &self,
        request: &BackupRequestIdentity,
        authenticated_role: BackupRole,
        installation_authority: &AuthorityBinding,
    ) -> Result<(), BackupError> {
        self.validate()?;
        request.validate()?;
        request.check_authenticated_role(authenticated_role)?;
        if authenticated_role != BackupRole::InstallationAuthority {
            return Err(BackupError::CapabilityDenied);
        }
        if self.archive_id != request.archive_id
            || self.dest_installation != request.dest_installation
        {
            return Err(BackupError::Mismatch {
                field: "backup_cutover_receipt.identity",
            });
        }
        if self.fence != request.fence {
            return Err(BackupError::Mismatch {
                field: "backup_cutover_receipt.fence",
            });
        }
        if !installation_authority
            .authority_epoch
            .is_same_authority(&request.fence.authority_epoch)
        {
            return Err(BackupError::FenceMismatch);
        }
        if installation_authority.authority_owner != request.dest_installation {
            return Err(BackupError::Mismatch {
                field: "backup_cutover_receipt.installation_authority",
            });
        }
        if self.observed_at_unix_ms > request.deadline_unix_ms {
            return Err(BackupError::InvalidField {
                field: "backup_cutover_receipt.observed_at_unix_ms",
                reason: "cutover evidence is no longer current",
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pure replay ledger keyed by the stable mutation digest.
// ---------------------------------------------------------------------------

/// Idempotent disposition returned by the pure replay ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupReplayDisposition {
    Accepted,
    Duplicate,
}

/// A pure replay identity ledger for backup request identities.
///
/// Keyed by the stable `canonical_request_hash`; a byte-identical digest
/// observes `Duplicate`, while changed content under the same identity
/// returns `ReplayConflict` before any semantic handling.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BackupReplayLedger {
    entries: BTreeMap<String, String>,
}

impl BackupReplayLedger {
    /// Creates an empty replay ledger. It is not durable storage.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Records a request identity and returns its idempotent disposition.
    pub fn observe(
        &mut self,
        identity: &BackupRequestIdentity,
    ) -> Result<BackupReplayDisposition, BackupError> {
        identity.validate()?;
        let bytes = canonical_json_bytes(identity)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let digest = sha256_hex(&bytes);
        if let Some(previous) = self.entries.get(&identity.mutation.canonical_request_hash) {
            if previous == &digest {
                return Ok(BackupReplayDisposition::Duplicate);
            }
            return Err(BackupError::ReplayConflict);
        }
        self.entries
            .insert(identity.mutation.canonical_request_hash.clone(), digest);
        Ok(BackupReplayDisposition::Accepted)
    }

    /// Returns the number of identities currently held by this pure ledger.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether this pure ledger has no identities.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
