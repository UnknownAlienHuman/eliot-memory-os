use std::collections::BTreeSet;

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence, canonical_json_bytes};
use eliot_platform::{PlatformHandle, SecretReference};
use eliot_receipts::ReceiptEnvelope;
use eliot_runtime_contracts::{
    GenerationCutoverRecord as RuntimeGenerationCutoverRecord, LeaseState, SignedSupervisionLease,
    SupervisionGenerationBinding, SupervisionLease, SupervisionLeaseTerminalDisposition,
    SupervisionObservationScope, SupervisionOrsMirrorBinding, VerifiedSupervisionLease,
    VerifiedSupervisionLeaseTerminalTransition,
};
use eliot_security_contracts::PrivacyClass;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{CONTRACT_VERSION, MAX_RECOVERY_PAGE};

/// A validated opaque label that carries no semantic authority.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OpaqueLabel(String);

impl OpaqueLabel {
    /// Constructs a non-blank, non-control label.
    pub fn new(value: impl Into<String>) -> Result<Self, OrsError> {
        let value = value.into();
        validate_text(&value, "opaque_label")?;
        Ok(Self(value))
    }

    /// Returns the wire value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for OpaqueLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Caller-defined visibility policy label preserved without interpretation.
pub type VisibilityClass = OpaqueLabel;
/// Stable ordering-scope identity preserved without interpreting its prefix.
pub type OrderingScope = OpaqueLabel;
/// Recovery owner identity preserved without granting it authority.
pub type RecoveryOwner = OpaqueLabel;
/// Operation/checkpoint identity preserved without creating an authority owner.
pub type OperationIdentity = OpaqueLabel;

/// Operation reserved by ORS for one authenticated supervision-lease revision.
///
/// The operation is deliberately separate from the lifecycle state.  ORS
/// decides which transitions are legal; the Kernel supplies the signed
/// envelope only after the ticket has been durably reserved.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupervisionLeaseOperation {
    /// Create the first active revision for a lease.
    Commit,
    /// Replace an active/expiring revision with a fresh active revision.
    Renew,
    /// Fence a revision by an explicit revocation.
    Revoke,
    /// Record that the revision reached its expiry boundary.
    Expire,
    /// Fence the revision because a newer activation superseded it.
    Supersede,
    /// Close an expiring or reconciling revision.
    Close,
}

impl SupervisionLeaseOperation {
    /// Returns the only target lifecycle state admitted for this operation.
    pub const fn target_state(self) -> LeaseState {
        match self {
            Self::Commit | Self::Renew => LeaseState::Active,
            Self::Revoke => LeaseState::Revoked,
            Self::Expire => LeaseState::Expired,
            Self::Supersede => LeaseState::Superseded,
            Self::Close => LeaseState::Closed,
        }
    }

    /// Checks the operation against an existing ORS lifecycle state.
    pub const fn allowed_from(self, prior: Option<LeaseState>) -> bool {
        matches!(
            (self, prior),
            (Self::Commit, None)
                | (Self::Renew, Some(LeaseState::Active | LeaseState::Expiring))
                | (
                    Self::Revoke,
                    Some(
                        LeaseState::Requested
                            | LeaseState::Active
                            | LeaseState::Expiring
                            | LeaseState::Reconciling,
                    ),
                )
                | (
                    Self::Expire,
                    Some(LeaseState::Active | LeaseState::Expiring | LeaseState::Reconciling),
                )
                | (Self::Supersede, Some(LeaseState::Active))
                | (
                    Self::Close,
                    Some(LeaseState::Expiring | LeaseState::Reconciling)
                )
        )
    }
}

/// Active/terminal projection of a committed ORS supervision-lease revision.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupervisionLeaseProjection {
    /// A ticket has been reserved, but no signed envelope has committed it.
    Staged,
    /// The committed revision is the currently admitted revision.
    Active,
    /// The committed revision is fenced and cannot be resurrected.
    Terminal,
}

impl SupervisionLeaseProjection {
    pub const fn for_state(state: LeaseState) -> Self {
        match state {
            LeaseState::Active => Self::Active,
            LeaseState::Requested
            | LeaseState::Expiring
            | LeaseState::Released
            | LeaseState::Expired
            | LeaseState::Revoked
            | LeaseState::Superseded
            | LeaseState::Reconciling
            | LeaseState::Closed => Self::Terminal,
        }
    }
}

/// The non-secret identity and state fence ORS reserves before signing.
///
/// This is intentionally a value object rather than a second signed-envelope
/// contract.  `to_payload` materializes the existing
/// [`eliot_runtime_contracts::SupervisionLease`] after ORS assigns the
/// revision and the reserved receipt/ticket digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionLeaseBinding {
    pub scope_ref: OpaqueLabel,
    pub observation_scope: SupervisionObservationScope,
    pub installation_id: OpaqueLabel,
    pub host_epoch: AuthorityEpoch,
    pub activation_id: OpaqueLabel,
    pub activation_generation: ResourceGeneration,
    pub kernel_epoch: AuthorityEpoch,
    pub watchdog_epoch: AuthorityEpoch,
    pub generation_binding: SupervisionGenerationBinding,
    pub state_fence: StateFence,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub renew_before_ms: u64,
    pub wake_policy: eliot_runtime_contracts::RegisteredActivityWakePolicy,
    pub state: LeaseState,
    pub terminal_disposition: Option<SupervisionLeaseTerminalDisposition>,
    pub revocation_reason: Option<String>,
    pub revocation_id: Option<String>,
    pub revocation_epoch: Option<AuthorityEpoch>,
}

impl SupervisionLeaseBinding {
    pub(crate) fn same_lineage_as(&self, successor: &Self) -> bool {
        self.scope_ref == successor.scope_ref
            && self.observation_scope == successor.observation_scope
            && self.installation_id == successor.installation_id
            && self.host_epoch == successor.host_epoch
            && self.activation_id == successor.activation_id
            && self.activation_generation == successor.activation_generation
            && self.kernel_epoch == successor.kernel_epoch
            && self.watchdog_epoch == successor.watchdog_epoch
            && self.generation_binding == successor.generation_binding
            && self.state_fence == successor.state_fence
            && self.wake_policy == successor.wake_policy
    }

    fn to_payload(
        &self,
        lease_id: &OperationIdentity,
        record_id: &OperationIdentity,
        revision: u64,
        ticket_sha256: &str,
        previous_receipt_sha256: Option<String>,
    ) -> Result<SupervisionLease, OrsError> {
        let payload = SupervisionLease {
            schema: eliot_runtime_contracts::SUPERVISION_LEASE_SCHEMA.to_owned(),
            contract_name: eliot_runtime_contracts::SUPERVISION_LEASE_CONTRACT_NAME.to_owned(),
            contract_version: eliot_runtime_contracts::SUPERVISION_LEASE_CONTRACT_VERSION,
            lease_id: lease_id.as_str().to_owned(),
            scope_ref: self.scope_ref.as_str().to_owned(),
            observation_scope: self.observation_scope.clone(),
            installation_id: self.installation_id.as_str().to_owned(),
            host_epoch: self.host_epoch,
            activation_id: self.activation_id.as_str().to_owned(),
            activation_generation: self.activation_generation,
            kernel_epoch: self.kernel_epoch,
            watchdog_epoch: self.watchdog_epoch,
            generation_binding: self.generation_binding.clone(),
            state_fence: self.state_fence.clone(),
            ors_mirror: SupervisionOrsMirrorBinding {
                record_id: record_id.as_str().to_owned(),
                subject_lease_id: lease_id.as_str().to_owned(),
                lease_revision: revision,
                // The signed payload binds the reservation which existed
                // before the signature, avoiding a cycle through the final
                // envelope and receipt digests.
                ticket_sha256: ticket_sha256.to_owned(),
                previous_receipt_sha256,
            },
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
            renew_before_ms: self.renew_before_ms,
            wake_policy: self.wake_policy.clone(),
            state: self.state,
            terminal_disposition: self.terminal_disposition,
            revocation_reason: self.revocation_reason.clone(),
            revocation_id: self.revocation_id.clone(),
            revocation_epoch: self.revocation_epoch,
        };
        payload
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        Ok(payload)
    }
}

/// Caller request for a one-time ORS lease ticket.  No revision or operation
/// order is accepted from the caller; both are assigned in the ORS write.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionLeasePrepareRequest {
    pub ticket_id: OperationIdentity,
    pub operation_id: OperationIdentity,
    pub lease_id: OperationIdentity,
    pub expected_revision: Option<u64>,
    pub operation: SupervisionLeaseOperation,
    pub binding: SupervisionLeaseBinding,
}

impl SupervisionLeasePrepareRequest {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        validate_text(self.ticket_id.as_str(), "supervision_ticket_id")?;
        validate_text(self.operation_id.as_str(), "supervision_operation_id")?;
        validate_text(self.lease_id.as_str(), "supervision_lease_id")?;
        if self.expected_revision.is_some_and(|revision| revision == 0) {
            return Err(OrsError::InvalidField {
                field: "supervision_expected_revision",
                reason: "must be absent or greater than zero",
            });
        }
        if self.binding.state != self.operation.target_state() {
            return Err(OrsError::InvalidField {
                field: "supervision_binding.state",
                reason: "does not match the operation target state",
            });
        }
        self.binding
            .state_fence
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        Ok(())
    }
}

/// Immutable ORS reservation.  Its canonical digest is the value the
/// Kernel must place in `SupervisionOrsMirrorBinding.ticket_sha256`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionLeaseCommitTicket {
    pub ticket_id: OperationIdentity,
    pub operation_id: OperationIdentity,
    pub lease_id: OperationIdentity,
    pub record_id: OperationIdentity,
    pub expected_revision: Option<u64>,
    pub revision: u64,
    pub operation: SupervisionLeaseOperation,
    pub binding: SupervisionLeaseBinding,
    pub previous_receipt_sha256: Option<String>,
    pub reservation_order: u64,
}

impl SupervisionLeaseCommitTicket {
    fn validate_basic(&self) -> Result<(), OrsError> {
        validate_text(self.ticket_id.as_str(), "supervision_ticket_id")?;
        validate_text(self.operation_id.as_str(), "supervision_operation_id")?;
        validate_text(self.lease_id.as_str(), "supervision_lease_id")?;
        validate_text(self.record_id.as_str(), "supervision_record_id")?;
        if self.revision == 0 || self.reservation_order == 0 {
            return Err(OrsError::InvalidField {
                field: "supervision_ticket_sequence",
                reason: "revision and reservation order must be greater than zero",
            });
        }
        if self.revision
            != self
                .expected_revision
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "supervision_lease_ticket",
                    reason: "revision counter exhausted".to_owned(),
                })?
        {
            return Err(OrsError::SupervisionLeaseStaleRevision);
        }
        if self.expected_revision.is_some() != self.previous_receipt_sha256.is_some() {
            return Err(OrsError::IntegrityProblem {
                record_type: "supervision_lease_ticket",
                reason: "only successor tickets must carry a predecessor receipt digest".to_owned(),
            });
        }
        if let Some(previous) = &self.previous_receipt_sha256 {
            validate_digest(previous, "supervision_previous_receipt_sha256")?;
        }
        if self.binding.state != self.operation.target_state() {
            return Err(OrsError::InvalidField {
                field: "supervision_binding.state",
                reason: "does not match the operation target state",
            });
        }
        self.binding
            .state_fence
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        Ok(())
    }

    /// Computes the canonical digest before a signature exists.
    pub fn ticket_sha256(&self) -> Result<String, OrsError> {
        self.validate_basic()?;
        let bytes =
            canonical_json_bytes(self).map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    /// Materializes the exact payload that the Kernel must sign.
    pub fn expected_payload(&self) -> Result<SupervisionLease, OrsError> {
        let ticket_sha256 = self.ticket_sha256()?;
        self.binding.to_payload(
            &self.lease_id,
            &self.record_id,
            self.revision,
            &ticket_sha256,
            self.previous_receipt_sha256.clone(),
        )
    }

    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        self.expected_payload()?;
        Ok(())
    }
}

/// Durable stage projection returned before the Kernel signs.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionLeaseStageReceipt {
    pub ticket: SupervisionLeaseCommitTicket,
    pub ticket_sha256: String,
    pub projection: SupervisionLeaseProjection,
}

impl SupervisionLeaseStageReceipt {
    pub fn ticket(&self) -> &SupervisionLeaseCommitTicket {
        &self.ticket
    }

    pub fn ticket_sha256(&self) -> &str {
        &self.ticket_sha256
    }

    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        let expected = self.ticket.ticket_sha256()?;
        if self.ticket_sha256 != expected || self.projection != SupervisionLeaseProjection::Staged {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        Ok(())
    }
}

pub(crate) fn signed_supervision_lease_from_verified(
    verified: &VerifiedSupervisionLease,
) -> Result<SignedSupervisionLease, OrsError> {
    let envelope = SignedSupervisionLease {
        payload: verified.payload().clone(),
        payload_sha256: verified
            .payload_digest()
            .map_err(|error| OrsError::Contract(error.to_string()))?,
        signer_id: verified.signer_id().to_owned(),
        key_id: verified.key_id().to_owned(),
        algorithm: verified.algorithm().to_owned(),
        signature: verified.signature().to_owned(),
    };
    envelope
        .validate()
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    let envelope_digest = envelope
        .envelope_digest()
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    if envelope_digest != verified.envelope_digest() {
        return Err(OrsError::SupervisionLeaseBindingMismatch);
    }
    Ok(envelope)
}

pub(crate) fn signed_terminal_supervision_lease_from_verified(
    verified: &VerifiedSupervisionLeaseTerminalTransition,
) -> Result<SignedSupervisionLease, OrsError> {
    let envelope = verified.envelope().clone();
    envelope
        .validate()
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    Ok(envelope)
}

/// Canonical receipt issued at the ORS commit linearization point.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionLeaseReceipt {
    pub ticket_id: OperationIdentity,
    pub operation_id: OperationIdentity,
    pub record_id: OperationIdentity,
    pub lease_id: OperationIdentity,
    pub revision: u64,
    pub operation: SupervisionLeaseOperation,
    pub state: LeaseState,
    pub projection: SupervisionLeaseProjection,
    pub operation_order: u64,
    pub ticket_sha256: String,
    pub artifact_sha256: String,
    pub previous_receipt_sha256: Option<String>,
    pub receipt_sha256: String,
}

#[derive(Serialize)]
struct SupervisionLeaseReceiptCore<'a> {
    ticket_id: &'a OperationIdentity,
    operation_id: &'a OperationIdentity,
    record_id: &'a OperationIdentity,
    lease_id: &'a OperationIdentity,
    revision: u64,
    operation: SupervisionLeaseOperation,
    state: LeaseState,
    projection: SupervisionLeaseProjection,
    operation_order: u64,
    ticket_sha256: &'a str,
    artifact_sha256: &'a str,
    previous_receipt_sha256: Option<&'a str>,
}

pub(crate) struct SupervisionLeaseReceiptInput {
    pub(crate) ticket_id: OperationIdentity,
    pub(crate) operation_id: OperationIdentity,
    pub(crate) record_id: OperationIdentity,
    pub(crate) lease_id: OperationIdentity,
    pub(crate) revision: u64,
    pub(crate) operation: SupervisionLeaseOperation,
    pub(crate) state: LeaseState,
    pub(crate) operation_order: u64,
    pub(crate) ticket_sha256: String,
    pub(crate) artifact_sha256: String,
    pub(crate) previous_receipt_sha256: Option<String>,
}

impl SupervisionLeaseReceipt {
    fn core(&self) -> SupervisionLeaseReceiptCore<'_> {
        SupervisionLeaseReceiptCore {
            ticket_id: &self.ticket_id,
            operation_id: &self.operation_id,
            record_id: &self.record_id,
            lease_id: &self.lease_id,
            revision: self.revision,
            operation: self.operation,
            state: self.state,
            projection: self.projection,
            operation_order: self.operation_order,
            ticket_sha256: &self.ticket_sha256,
            artifact_sha256: &self.artifact_sha256,
            previous_receipt_sha256: self.previous_receipt_sha256.as_deref(),
        }
    }

    pub(crate) fn issue(input: SupervisionLeaseReceiptInput) -> Result<Self, OrsError> {
        if input.operation_order == 0 || input.revision == 0 {
            return Err(OrsError::InvalidField {
                field: "supervision_receipt_sequence",
                reason: "revision and operation order must be greater than zero",
            });
        }
        validate_digest(&input.ticket_sha256, "supervision_ticket_sha256")?;
        validate_digest(&input.artifact_sha256, "supervision_artifact_sha256")?;
        if let Some(previous) = &input.previous_receipt_sha256 {
            validate_digest(previous, "supervision_previous_receipt_sha256")?;
        }
        if (input.revision == 1) != input.previous_receipt_sha256.is_none() {
            return Err(OrsError::IntegrityProblem {
                record_type: "supervision_lease_receipt",
                reason: "only successor receipts must bind a predecessor receipt".to_owned(),
            });
        }
        let projection = SupervisionLeaseProjection::for_state(input.state);
        let mut receipt = Self {
            ticket_id: input.ticket_id,
            operation_id: input.operation_id,
            record_id: input.record_id,
            lease_id: input.lease_id,
            revision: input.revision,
            operation: input.operation,
            state: input.state,
            projection,
            operation_order: input.operation_order,
            ticket_sha256: input.ticket_sha256,
            artifact_sha256: input.artifact_sha256,
            previous_receipt_sha256: input.previous_receipt_sha256,
            receipt_sha256: String::new(),
        };
        let bytes = canonical_json_bytes(&receipt.core())
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        receipt.receipt_sha256 = sha256_hex(&bytes);
        Ok(receipt)
    }

    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        validate_text(self.ticket_id.as_str(), "supervision_receipt_ticket_id")?;
        validate_text(
            self.operation_id.as_str(),
            "supervision_receipt_operation_id",
        )?;
        validate_text(self.record_id.as_str(), "supervision_receipt_record_id")?;
        validate_text(self.lease_id.as_str(), "supervision_receipt_lease_id")?;
        if self.revision == 0 || self.operation_order == 0 {
            return Err(OrsError::InvalidField {
                field: "supervision_receipt_sequence",
                reason: "revision and operation order must be greater than zero",
            });
        }
        validate_digest(&self.ticket_sha256, "supervision_ticket_sha256")?;
        validate_digest(&self.artifact_sha256, "supervision_artifact_sha256")?;
        validate_digest(&self.receipt_sha256, "supervision_receipt_sha256")?;
        if let Some(previous) = &self.previous_receipt_sha256 {
            validate_digest(previous, "supervision_previous_receipt_sha256")?;
        }
        if (self.revision == 1) != self.previous_receipt_sha256.is_none() {
            return Err(OrsError::IntegrityProblem {
                record_type: "supervision_lease_receipt",
                reason: "only successor receipts must bind a predecessor receipt".to_owned(),
            });
        }
        if self.projection != SupervisionLeaseProjection::for_state(self.state) {
            return Err(OrsError::IntegrityProblem {
                record_type: "supervision_lease_receipt",
                reason: "projection does not match lifecycle state".to_owned(),
            });
        }
        let bytes = canonical_json_bytes(&self.core())
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        if sha256_hex(&bytes) != self.receipt_sha256 {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        Ok(())
    }
}

/// Authoritative current/history projection returned after a commit.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionLeaseRecord {
    pub ticket_id: OperationIdentity,
    pub operation_id: OperationIdentity,
    pub record_id: OperationIdentity,
    pub lease_id: OperationIdentity,
    pub revision: u64,
    pub operation: SupervisionLeaseOperation,
    pub state: LeaseState,
    pub projection: SupervisionLeaseProjection,
    pub binding: SupervisionLeaseBinding,
    pub previous_receipt_sha256: Option<String>,
    pub ticket_sha256: String,
    pub operation_order: u64,
    pub artifact: SignedSupervisionLease,
    pub receipt_sha256: String,
}

impl SupervisionLeaseRecord {
    fn validate(&self, receipt: &SupervisionLeaseReceipt) -> Result<(), OrsError> {
        validate_text(self.ticket_id.as_str(), "supervision_ticket_id")?;
        validate_text(self.operation_id.as_str(), "supervision_operation_id")?;
        validate_text(self.record_id.as_str(), "supervision_record_id")?;
        validate_text(self.lease_id.as_str(), "supervision_lease_id")?;
        if self.revision == 0 || self.operation_order == 0 {
            return Err(OrsError::InvalidField {
                field: "supervision_record_sequence",
                reason: "revision and operation order must be greater than zero",
            });
        }
        validate_digest(&self.ticket_sha256, "supervision_ticket_sha256")?;
        if let Some(previous) = &self.previous_receipt_sha256 {
            validate_digest(previous, "supervision_previous_receipt_sha256")?;
        }
        if (self.revision == 1) != self.previous_receipt_sha256.is_none() {
            return Err(OrsError::IntegrityProblem {
                record_type: "supervision_lease_record",
                reason: "only successor records must bind a predecessor receipt".to_owned(),
            });
        }
        self.binding
            .state_fence
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        if self.state != self.binding.state
            || self.projection != SupervisionLeaseProjection::for_state(self.state)
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "supervision_lease_record",
                reason: "state or projection does not match the binding".to_owned(),
            });
        }
        let expected = self.binding.to_payload(
            &self.lease_id,
            &self.record_id,
            self.revision,
            &self.ticket_sha256,
            self.previous_receipt_sha256.clone(),
        )?;
        if self.artifact.payload != expected {
            return Err(OrsError::SupervisionLeaseBindingMismatch);
        }
        let artifact_digest = self
            .artifact
            .envelope_digest()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        receipt.validate()?;
        if receipt.ticket_id != self.ticket_id
            || receipt.operation_id != self.operation_id
            || receipt.record_id != self.record_id
            || receipt.lease_id != self.lease_id
            || receipt.revision != self.revision
            || receipt.operation != self.operation
            || receipt.state != self.state
            || receipt.projection != self.projection
            || receipt.operation_order != self.operation_order
            || receipt.ticket_sha256 != self.ticket_sha256
            || receipt.artifact_sha256 != artifact_digest
            || receipt.previous_receipt_sha256 != self.previous_receipt_sha256
            || receipt.receipt_sha256 != self.receipt_sha256
        {
            return Err(OrsError::SupervisionLeaseBindingMismatch);
        }
        Ok(())
    }
}

/// Paired current/history record and its canonical receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionLeaseSnapshot {
    pub record: SupervisionLeaseRecord,
    pub receipt: SupervisionLeaseReceipt,
}

impl SupervisionLeaseSnapshot {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        self.record.validate(&self.receipt)
    }

    pub fn record(&self) -> &SupervisionLeaseRecord {
        &self.record
    }

    pub fn receipt(&self) -> &SupervisionLeaseReceipt {
        &self.receipt
    }
}

/// Durable one-shot process-start replay state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStartReplayRecord {
    pub operation_id: OperationIdentity,
    pub admission_digest: String,
    pub owner: eliot_process::ProcessOwnerBinding,
    pub state: ProcessStartReplayState,
    pub receipt: Option<eliot_process::ProcessStartReceipt>,
}

/// Durable result of compare-and-deleting a pre-effect process reservation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq)]
pub enum ProcessStartReplayAbort {
    Released,
    NotReleased,
}

impl ProcessStartReplayRecord {
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(self.operation_id.as_str(), "process_start_operation_id")?;
        validate_digest(&self.admission_digest, "process_start_admission_digest")?;
        eliot_process::ProcessOwnerBinding::new(
            self.owner.module_id(),
            self.owner.principal_digest(),
            self.owner.authority_epoch(),
            self.owner.generation(),
        )
        .map_err(|error| OrsError::IntegrityProblem {
            record_type: "process_start_replay",
            reason: error.to_string(),
        })?;
        match (&self.state, &self.receipt) {
            (ProcessStartReplayState::Completed, Some(receipt)) => {
                receipt
                    .validate()
                    .map_err(|error| OrsError::IntegrityProblem {
                        record_type: "process_start_replay",
                        reason: error.to_string(),
                    })?;
                if receipt.operation_id().as_str() != self.operation_id.as_str() {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "process_start_replay",
                        reason: "completion receipt does not bind the reserved operation"
                            .to_owned(),
                    });
                }
            }
            (ProcessStartReplayState::Completed, None)
            | (ProcessStartReplayState::Reserved | ProcessStartReplayState::Unknown, Some(_)) => {
                return Err(OrsError::IntegrityProblem {
                    record_type: "process_start_replay",
                    reason: "state and receipt combination is invalid".to_owned(),
                });
            }
            (ProcessStartReplayState::Reserved | ProcessStartReplayState::Unknown, None) => {}
        }
        Ok(())
    }
}

/// Process-start replay disposition persisted by ORS.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessStartReplayState {
    Reserved,
    Completed,
    Unknown,
}

/// Durable one-shot authority handoff disposition.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityHandoffState {
    Reserved,
    Consumed,
    Unknown,
}

/// Secret-free identity and outcome record for one authority handoff.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHandoffRecord {
    pub contract_version: u16,
    pub handoff_id: OperationIdentity,
    pub descriptor_digest: String,
    pub authority_id: OpaqueLabel,
    pub snapshot_record_id: OperationIdentity,
    pub snapshot_binding_digest: String,
    pub authority_epoch: u64,
    pub generation: u64,
    pub state_fence_digest: String,
    pub secret_reference_identity_digest: String,
    pub state: AuthorityHandoffState,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub consumed_at_ms: Option<i64>,
    pub reconciliation_evidence: Option<OpaqueLabel>,
}

impl AuthorityHandoffRecord {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        validate_text(self.handoff_id.as_str(), "authority_handoff_id")?;
        validate_text(self.authority_id.as_str(), "authority_handoff_authority_id")?;
        validate_text(
            self.snapshot_record_id.as_str(),
            "authority_handoff_snapshot_record_id",
        )?;
        for (value, field) in [
            (
                &self.descriptor_digest,
                "authority_handoff_descriptor_digest",
            ),
            (
                &self.snapshot_binding_digest,
                "authority_handoff_binding_digest",
            ),
            (
                &self.state_fence_digest,
                "authority_handoff_state_fence_digest",
            ),
            (
                &self.secret_reference_identity_digest,
                "authority_handoff_secret_reference_digest",
            ),
        ] {
            validate_digest(value, field)?;
        }
        if self.authority_epoch == 0 || self.generation == 0 {
            return Err(OrsError::InvalidField {
                field: "authority_handoff_identity",
                reason: "authority epoch and generation must be non-zero",
            });
        }
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(OrsError::InvalidExpiry);
        }
        match (
            &self.state,
            self.consumed_at_ms,
            &self.reconciliation_evidence,
        ) {
            (AuthorityHandoffState::Reserved, None, None)
            | (AuthorityHandoffState::Unknown, None, Some(_)) => {}
            // `expires_at_ms` bounds fresh admission, not recovery of an
            // already activated authority.  A crash may leave the exact
            // Reserved handoff and replay snapshot durable while the
            // one-shot admission interval elapses; Kernel then records the
            // terminal Consumed state during restart reconciliation.
            (AuthorityHandoffState::Consumed, Some(consumed), None)
                if consumed >= self.issued_at_ms => {}
            _ => {
                return Err(OrsError::IntegrityProblem {
                    record_type: "authority_handoff",
                    reason: "state and outcome evidence combination is invalid".to_owned(),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        self.handoff_id == other.handoff_id
            && self.descriptor_digest == other.descriptor_digest
            && self.authority_id == other.authority_id
            && self.snapshot_record_id == other.snapshot_record_id
            && self.snapshot_binding_digest == other.snapshot_binding_digest
            && self.authority_epoch == other.authority_epoch
            && self.generation == other.generation
            && self.state_fence_digest == other.state_fence_digest
            && self.secret_reference_identity_digest == other.secret_reference_identity_digest
            && self.issued_at_ms == other.issued_at_ms
            && self.expires_at_ms == other.expires_at_ms
    }
}

/// Result of the atomic one-shot handoff reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum AuthorityHandoffBegin {
    Acquired,
    Existing(AuthorityHandoffRecord),
}

/// Observation-only process evidence retained by ORS.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEvidenceRecord {
    pub contract_version: u16,
    pub operation_id: OperationIdentity,
    pub request_digest: String,
    pub process_tree_id: OpaqueLabel,
    pub job_id: OpaqueLabel,
    pub image_id: OpaqueLabel,
    pub session_id: OpaqueLabel,
    pub owner: eliot_process::ProcessOwnerBinding,
    pub authority_epoch: u64,
    pub generation: u64,
    pub state_fence_digest: String,
    pub binding_digest: String,
    pub evidence_digest: String,
    pub observed_at_ms: i64,
    pub evidence: eliot_process::ProcessEvidence,
}

#[derive(Serialize)]
struct ProcessEvidenceRecordIdentity<'a> {
    operation_id: &'a str,
    process_tree_id: &'a str,
    job_id: &'a str,
    image_id: &'a str,
    session_id: &'a str,
    evidence_digest: &'a str,
    observed_at_ms: i64,
}

impl ProcessEvidenceRecord {
    pub fn from_evidence(
        evidence: eliot_process::ProcessEvidence,
        owner: eliot_process::ProcessOwnerBinding,
        observed_at_ms: i64,
    ) -> Result<Self, OrsError> {
        let binding = evidence.binding();
        let binding_bytes =
            serde_json::to_vec(binding).map_err(|error| OrsError::Encoding(error.to_string()))?;
        let state_fence_bytes = serde_json::to_vec(binding.state_fence())
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        let evidence_bytes =
            serde_json::to_vec(&evidence).map_err(|error| OrsError::Encoding(error.to_string()))?;
        let record = Self {
            contract_version: CONTRACT_VERSION,
            operation_id: OperationIdentity::new(binding.operation_id().as_str())?,
            request_digest: binding.request_digest().to_owned(),
            process_tree_id: OpaqueLabel::new(binding.process_tree_id().as_str())?,
            job_id: OpaqueLabel::new(binding.job_id().as_str())?,
            image_id: OpaqueLabel::new(binding.image_id().as_str())?,
            session_id: OpaqueLabel::new(binding.session_id().as_str())?,
            authority_epoch: owner.authority_epoch(),
            generation: owner.generation().get(),
            owner,
            state_fence_digest: sha256_hex(&state_fence_bytes),
            binding_digest: sha256_hex(&binding_bytes),
            evidence_digest: sha256_hex(&evidence_bytes),
            observed_at_ms,
            evidence,
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns the canonical immutable key for this one observation.
    pub fn record_key(&self) -> Result<String, OrsError> {
        self.validate()?;
        let identity = ProcessEvidenceRecordIdentity {
            operation_id: self.operation_id.as_str(),
            process_tree_id: self.process_tree_id.as_str(),
            job_id: self.job_id.as_str(),
            image_id: self.image_id.as_str(),
            session_id: self.session_id.as_str(),
            evidence_digest: &self.evidence_digest,
            observed_at_ms: self.observed_at_ms,
        };
        let identity_bytes =
            serde_json::to_vec(&identity).map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(format!(
            "{}::{:}",
            self.operation_id.as_str(),
            sha256_hex(&identity_bytes)
        ))
    }

    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        validate_text(self.operation_id.as_str(), "process_evidence_operation_id")?;
        validate_digest(&self.request_digest, "process_evidence_request_digest")?;
        for (value, field) in [
            (&self.process_tree_id, "process_evidence_process_tree_id"),
            (&self.job_id, "process_evidence_job_id"),
            (&self.image_id, "process_evidence_image_id"),
            (&self.session_id, "process_evidence_session_id"),
        ] {
            validate_text(value.as_str(), field)?;
        }
        validate_digest(
            &self.state_fence_digest,
            "process_evidence_state_fence_digest",
        )?;
        validate_digest(&self.binding_digest, "process_evidence_binding_digest")?;
        validate_digest(&self.evidence_digest, "process_evidence_digest")?;
        if self.authority_epoch == 0 || self.generation == 0 || self.observed_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "process_evidence_identity",
                reason: "epoch, generation, and observation time must be positive",
            });
        }
        let axes = self.evidence.axes();
        let axes =
            serde_json::to_value(axes).map_err(|error| OrsError::Encoding(error.to_string()))?;
        if axes.get("status").and_then(Value::as_str) != Some("OBSERVED")
            || axes.get("assertability").and_then(Value::as_str)
                != Some("NON_ASSERTABLE_UNVERIFIED")
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "process_evidence",
                reason: "process evidence is not observation-only C0 evidence".to_owned(),
            });
        }
        let owner = eliot_process::ProcessOwnerBinding::new(
            self.owner.module_id(),
            self.owner.principal_digest(),
            self.owner.authority_epoch(),
            self.owner.generation(),
        )
        .map_err(|error| OrsError::IntegrityProblem {
            record_type: "process_evidence",
            reason: error.to_string(),
        })?;
        if owner != self.owner
            || self.authority_epoch != self.owner.authority_epoch()
            || self.generation != self.owner.generation().get()
            || self.operation_id.as_str() != self.evidence.operation_id().as_str()
            || self.request_digest != self.evidence.request_digest()
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "process_evidence",
                reason: "evidence identity does not match its durable projection".to_owned(),
            });
        }
        let binding = self.evidence.binding();
        let binding_bytes =
            serde_json::to_vec(binding).map_err(|error| OrsError::Encoding(error.to_string()))?;
        let state_fence_bytes = serde_json::to_vec(binding.state_fence())
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        let evidence_bytes = serde_json::to_vec(&self.evidence)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        if sha256_hex(&binding_bytes) != self.binding_digest
            || sha256_hex(&state_fence_bytes) != self.state_fence_digest
            || sha256_hex(&evidence_bytes) != self.evidence_digest
        {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        let fence: Value = serde_json::from_slice(&state_fence_bytes)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        let fence_epoch = fence
            .get("authority_epoch")
            .and_then(Value::as_u64)
            .ok_or(OrsError::FenceMismatch)?;
        let fence_generation = fence
            .get("generation")
            .and_then(Value::as_u64)
            .ok_or(OrsError::FenceMismatch)?;
        if fence_epoch != self.authority_epoch || fence_generation != self.generation {
            return Err(OrsError::FenceMismatch);
        }
        Ok(())
    }
}

/// Exact canonical snapshot of a provider-owned State Fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateFenceSnapshot {
    pub canonical_json: String,
    pub sha256: String,
    pub observed_authority_epoch: u64,
}

impl StateFenceSnapshot {
    /// Captures any serializable provider fence without redefining its fields.
    pub fn capture<T: Serialize>(
        provider_fence: &T,
        observed_authority_epoch: u64,
    ) -> Result<Self, OrsError> {
        if observed_authority_epoch == 0 {
            return Err(OrsError::InvalidField {
                field: "observed_authority_epoch",
                reason: "must be greater than zero",
            });
        }
        let value = serde_json::to_value(provider_fence)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        let canonical_json = serde_json::to_string(&canonicalize(value))
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        let sha256 = sha256_hex(canonical_json.as_bytes());
        Ok(Self {
            canonical_json,
            sha256,
            observed_authority_epoch,
        })
    }

    pub fn validate(&self) -> Result<(), OrsError> {
        validate_digest(&self.sha256, "state_fence_sha256")?;
        if self.observed_authority_epoch == 0
            || sha256_hex(self.canonical_json.as_bytes()) != self.sha256
        {
            return Err(OrsError::FenceMismatch);
        }
        let parsed: Value = serde_json::from_str(&self.canonical_json)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        if serde_json::to_string(&canonicalize(parsed))
            .map_err(|error| OrsError::Encoding(error.to_string()))?
            != self.canonical_json
        {
            return Err(OrsError::FenceMismatch);
        }
        Ok(())
    }
}

/// Exact epoch identity, including its lineage namespace.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochIdentity {
    pub lineage_id: OpaqueLabel,
    pub epoch: u64,
}

/// One current epoch plus the exact predecessor that authorizes its succession.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochLineage {
    pub current: EpochIdentity,
    pub predecessor: Option<EpochIdentity>,
}

impl EpochLineage {
    /// Validates the explicit lineage edge.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.current.validate()?;
        if let Some(predecessor) = &self.predecessor {
            predecessor.validate()?;
        }
        if let Some(predecessor) = &self.predecessor
            && predecessor.lineage_id == self.current.lineage_id
            && predecessor.epoch >= self.current.epoch
        {
            return Err(OrsError::InvalidEpochLineage);
        }
        Ok(())
    }

    pub(crate) fn succeeds(&self, prior: &EpochIdentity) -> bool {
        self.current == *prior
            || self
                .predecessor
                .as_ref()
                .is_some_and(|value| value == prior)
    }
}

impl EpochIdentity {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        if self.epoch == 0 {
            return Err(OrsError::InvalidEpochLineage);
        }
        Ok(())
    }
}

/// Opaque payload representation. ORS owns neither keys nor locator contents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum RecoveryPayload {
    Encrypted {
        key: SecretReference,
        ciphertext: Vec<u8>,
    },
    ImmutableLocator {
        locator: PlatformHandle,
    },
}

/// Required privacy and visibility metadata that travels with a pending value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAccessClass {
    pub privacy: PrivacyClass,
    pub visibility: VisibilityClass,
}

/// Versioned opaque recovery envelope required at the ORS boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPayloadEnvelope {
    pub contract_version: u16,
    pub operation_or_checkpoint_id: OperationIdentity,
    pub privacy_and_visibility_class: RecoveryAccessClass,
    pub payload: RecoveryPayload,
    pub payload_sha256: String,
    pub payload_length: u64,
    pub authority_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub created_at_ms: i64,
    pub known_at_ms: i64,
    pub expires_at_ms: Option<i64>,
}

/// Metadata shared by encrypted and immutable-locator recovery envelopes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryEnvelopeContext {
    pub operation_or_checkpoint_id: OperationIdentity,
    pub privacy_and_visibility_class: RecoveryAccessClass,
    pub authority_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub created_at_ms: i64,
    pub known_at_ms: i64,
    pub expires_at_ms: Option<i64>,
}

impl RecoveryPayloadEnvelope {
    /// Constructs an encrypted envelope and binds its exact ciphertext bytes.
    pub fn encrypted(
        context: RecoveryEnvelopeContext,
        key: SecretReference,
        ciphertext: Vec<u8>,
    ) -> Result<Self, OrsError> {
        let payload_length =
            u64::try_from(ciphertext.len()).map_err(|_| OrsError::PayloadTooLarge)?;
        let payload_sha256 = sha256_hex(&ciphertext);
        let envelope = Self {
            contract_version: CONTRACT_VERSION,
            operation_or_checkpoint_id: context.operation_or_checkpoint_id,
            privacy_and_visibility_class: context.privacy_and_visibility_class,
            payload: RecoveryPayload::Encrypted { key, ciphertext },
            payload_sha256,
            payload_length,
            authority_epoch: context.authority_epoch,
            state_fence: context.state_fence,
            created_at_ms: context.created_at_ms,
            known_at_ms: context.known_at_ms,
            expires_at_ms: context.expires_at_ms,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Constructs a locator envelope. The caller supplies the immutable object's binding.
    pub fn immutable_locator(
        context: RecoveryEnvelopeContext,
        locator: PlatformHandle,
        payload_sha256: String,
        payload_length: u64,
    ) -> Result<Self, OrsError> {
        let envelope = Self {
            contract_version: CONTRACT_VERSION,
            operation_or_checkpoint_id: context.operation_or_checkpoint_id,
            privacy_and_visibility_class: context.privacy_and_visibility_class,
            payload: RecoveryPayload::ImmutableLocator { locator },
            payload_sha256,
            payload_length,
            authority_epoch: context.authority_epoch,
            state_fence: context.state_fence,
            created_at_ms: context.created_at_ms,
            known_at_ms: context.known_at_ms,
            expires_at_ms: context.expires_at_ms,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validates version, integrity bindings, fence, epoch lineage, and time bounds.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        validate_digest(&self.payload_sha256, "payload_sha256")?;
        if self.payload_length == 0 {
            return Err(OrsError::InvalidField {
                field: "payload_length",
                reason: "must be greater than zero",
            });
        }
        self.authority_epoch.validate()?;
        self.state_fence.validate()?;
        if self.state_fence.observed_authority_epoch != self.authority_epoch.current.epoch {
            return Err(OrsError::FenceMismatch);
        }
        if self.known_at_ms < self.created_at_ms {
            return Err(OrsError::InvalidExpiry);
        }
        if let Some(expires) = self.expires_at_ms
            && expires <= self.created_at_ms
        {
            return Err(OrsError::InvalidExpiry);
        }
        match &self.payload {
            RecoveryPayload::Encrypted { key, ciphertext } => {
                validate_text(key.provider.as_str(), "secret_provider")?;
                validate_text(key.key.as_str(), "secret_key")?;
                let length =
                    u64::try_from(ciphertext.len()).map_err(|_| OrsError::PayloadTooLarge)?;
                if length > crate::MAX_INLINE_RECOVERY_BYTES {
                    return Err(OrsError::PayloadTooLarge);
                }
                if length != self.payload_length || sha256_hex(ciphertext) != self.payload_sha256 {
                    return Err(OrsError::PayloadIntegrityMismatch);
                }
            }
            RecoveryPayload::ImmutableLocator { locator } => {
                validate_text(locator.as_str(), "immutable_locator")?;
            }
        }
        Ok(())
    }
}

/// Canonical head expected before a transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedOrderingHead {
    pub sequence: u64,
    pub head_sha256: String,
    pub revision_head: Option<String>,
}

impl ExpectedOrderingHead {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        validate_digest(&self.head_sha256, "head_sha256")?;
        if let Some(revision) = &self.revision_head {
            validate_text(revision, "revision_head")?;
        }
        Ok(())
    }
}

/// One requested scope and the canonical head it must extend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeReservationRequest {
    pub scope: OrderingScope,
    pub expected_head: ExpectedOrderingHead,
}

/// Atomic reservation request. All scopes are reserved or none are.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRequest {
    pub reservation_id: OperationIdentity,
    pub envelope: RecoveryPayloadEnvelope,
    pub writer_epoch: EpochLineage,
    pub scopes: Vec<ScopeReservationRequest>,
    pub prepared_transition_sha256: String,
    pub expires_at_ms: i64,
    pub recovery_owner: RecoveryOwner,
}

impl ReservationRequest {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        self.envelope.validate()?;
        self.writer_epoch.validate()?;
        validate_digest(
            &self.prepared_transition_sha256,
            "prepared_transition_sha256",
        )?;
        if self.writer_epoch.current != self.envelope.authority_epoch.current {
            return Err(OrsError::EpochMismatch);
        }
        if self.scopes.is_empty() {
            return Err(OrsError::EmptyScopeSet);
        }
        if self.scopes.len() > usize::from(MAX_RECOVERY_PAGE) {
            return Err(OrsError::InvalidCursorLimit);
        }
        let mut seen = BTreeSet::new();
        for scope in &self.scopes {
            scope.expected_head.validate()?;
            if !seen.insert(scope.scope.clone()) {
                return Err(OrsError::DuplicateScope);
            }
        }
        if self.expires_at_ms <= self.envelope.created_at_ms {
            return Err(OrsError::InvalidExpiry);
        }
        Ok(())
    }
}

/// One scope sequence allocated by the coordinator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedScope {
    pub scope: OrderingScope,
    pub reserved_sequence: u64,
    pub expected_head: ExpectedOrderingHead,
}

/// Immutable token checked throughout the writer lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterReservationToken {
    pub reservation_id: OperationIdentity,
    pub operation_id: OperationIdentity,
    pub writer_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub reservation_order: u64,
    pub scopes: Vec<ReservedScope>,
    pub prepared_transition_sha256: String,
    pub expires_at_ms: i64,
    pub recovery_owner: RecoveryOwner,
}

/// Durable reservation lifecycle. Terminal states never become executable again.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReservationState {
    Reserved,
    Eligible,
    Executing,
    Reconciling,
    Finalized,
    Released,
}

impl ReservationState {
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Released)
    }
}

/// Durable reservation record recovered after restart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRecord {
    pub token: WriterReservationToken,
    pub state: ReservationState,
    pub unknown_reason: Option<OpaqueLabel>,
    pub terminal_receipt_id: Option<OpaqueLabel>,
}

/// Bounded restart-recovery cursor. `after_order` is exclusive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryCursor {
    pub after_order: u64,
    pub limit: u16,
}

impl RecoveryCursor {
    /// Constructs a cursor under the hard page ceiling.
    pub fn new(after_order: u64, limit: u16) -> Result<Self, OrsError> {
        if limit == 0 || limit > MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        Ok(Self { after_order, limit })
    }
}

/// One bounded recovery page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPage {
    pub records: Vec<ReservationRecord>,
    pub next_after_order: Option<u64>,
}

/// Canonical head observation supplied alongside a receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalScopeObservation {
    pub scope: OrderingScope,
    pub prior_head: ExpectedOrderingHead,
    pub committed_sequence: u64,
    pub committed_head_sha256: String,
    pub committed_revision_head: Option<String>,
    pub receipt_id: OpaqueLabel,
}

/// Terminal disposition established by the canonical owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonicalDisposition {
    Committed,
    Rejected,
}

/// Exact receipt/read-back evidence used to close one ORS reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalReconciliation {
    pub reservation_id: OperationIdentity,
    pub operation_id: OperationIdentity,
    pub reservation_order: u64,
    pub state_fence: StateFenceSnapshot,
    pub recovery_owner: RecoveryOwner,
    pub scopes: Vec<CanonicalScopeObservation>,
    pub receipt: ReceiptEnvelope,
    pub disposition: CanonicalDisposition,
}

/// One provider-neutral opaque operational input. The bytes are never interpreted by ORS.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalRecordInput {
    pub record_id: OperationIdentity,
    pub subject_id: OperationIdentity,
    pub authority_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub payload: RecoveryPayload,
    pub payload_sha256: String,
    pub payload_length: u64,
    pub created_at_ms: i64,
    pub cleanup_after_ms: Option<i64>,
}

/// Metadata shared by encrypted and immutable-locator operational records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalRecordContext {
    pub record_id: OperationIdentity,
    pub subject_id: OperationIdentity,
    pub authority_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub created_at_ms: i64,
    pub cleanup_after_ms: Option<i64>,
}

impl OperationalRecordInput {
    /// Creates an encrypted integrity-bound operational input.
    pub fn encrypted(
        context: OperationalRecordContext,
        key: SecretReference,
        ciphertext: Vec<u8>,
    ) -> Result<Self, OrsError> {
        let payload_length =
            u64::try_from(ciphertext.len()).map_err(|_| OrsError::PayloadTooLarge)?;
        let payload_sha256 = sha256_hex(&ciphertext);
        let value = Self {
            record_id: context.record_id,
            subject_id: context.subject_id,
            authority_epoch: context.authority_epoch,
            state_fence: context.state_fence,
            payload: RecoveryPayload::Encrypted { key, ciphertext },
            payload_sha256,
            payload_length,
            created_at_ms: context.created_at_ms,
            cleanup_after_ms: context.cleanup_after_ms,
        };
        value.validate()?;
        Ok(value)
    }

    /// Creates an integrity-bound immutable-locator operational input.
    pub fn immutable_locator(
        context: OperationalRecordContext,
        locator: PlatformHandle,
        payload_sha256: String,
        payload_length: u64,
    ) -> Result<Self, OrsError> {
        let value = Self {
            record_id: context.record_id,
            subject_id: context.subject_id,
            authority_epoch: context.authority_epoch,
            state_fence: context.state_fence,
            payload: RecoveryPayload::ImmutableLocator { locator },
            payload_sha256,
            payload_length,
            created_at_ms: context.created_at_ms,
            cleanup_after_ms: context.cleanup_after_ms,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        self.authority_epoch.validate()?;
        self.state_fence.validate()?;
        if self.authority_epoch.current.epoch != self.state_fence.observed_authority_epoch {
            return Err(OrsError::FenceMismatch);
        }
        validate_digest(&self.payload_sha256, "operational_payload_sha256")?;
        if self.payload_length == 0 {
            return Err(OrsError::InvalidField {
                field: "operational_payload_length",
                reason: "must be greater than zero",
            });
        }
        match &self.payload {
            RecoveryPayload::Encrypted { key, ciphertext } => {
                validate_text(key.provider.as_str(), "operational_secret_provider")?;
                validate_text(key.key.as_str(), "operational_secret_key")?;
                let length =
                    u64::try_from(ciphertext.len()).map_err(|_| OrsError::PayloadTooLarge)?;
                if length > crate::MAX_INLINE_RECOVERY_BYTES {
                    return Err(OrsError::PayloadTooLarge);
                }
                if length != self.payload_length || sha256_hex(ciphertext) != self.payload_sha256 {
                    return Err(OrsError::PayloadIntegrityMismatch);
                }
            }
            RecoveryPayload::ImmutableLocator { locator } => {
                validate_text(locator.as_str(), "operational_immutable_locator")?;
            }
        }
        if self
            .cleanup_after_ms
            .is_some_and(|cleanup_after| cleanup_after <= self.created_at_ms)
        {
            return Err(OrsError::InvalidExpiry);
        }
        Ok(())
    }
}

macro_rules! operational_input {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub OperationalRecordInput);

        impl $name {
            pub fn new(record: OperationalRecordInput) -> Result<Self, OrsError> {
                record.validate()?;
                Ok(Self(record))
            }

            pub fn record(&self) -> &OperationalRecordInput {
                &self.0
            }
        }
    };
}

operational_input!(StagedOperation);
operational_input!(RetryState);
operational_input!(JobCheckpoint);
operational_input!(DeliveryCursorState);
operational_input!(DeliveryAcknowledgement);
operational_input!(AdmissionReservation);
operational_input!(AdmissionReservationActivation);
operational_input!(AdmissionReservationRelease);
operational_input!(GenerationTransition);
operational_input!(GenerationCutoverRecord);
operational_input!(ActiveSessionBinding);
operational_input!(SessionDetach);
operational_input!(UserBrokerRegistration);
operational_input!(UserBrokerFence);
operational_input!(KernelAuthoritySnapshot);
operational_input!(AuthorityRevocation);
operational_input!(CapabilityGrantActivation);
operational_input!(CapabilityGrantRevocation);
operational_input!(CapabilityIntroductionActivation);
operational_input!(CapabilityIntroductionFence);

/// Read-only ORS evidence for one Kernel generation transition or committed
/// cutover.  The runtime contract and its integrity-bound ORS receipt are
/// projected from the canonical operational current/history tables; ORS does
/// not grant authority or interpret the route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GenerationCutoverSnapshot {
    /// The validated transition/cutover contract.
    pub record: RuntimeGenerationCutoverRecord,
    /// Monotonic ORS order at which this value was written.
    pub operation_order: u64,
    /// Receipt over the exact canonical operational record.
    pub receipt: GenerationCutoverReceipt,
}

impl GenerationCutoverSnapshot {
    pub(crate) fn new(
        record: RuntimeGenerationCutoverRecord,
        operation_order: u64,
        receipt: GenerationCutoverReceipt,
    ) -> Self {
        Self {
            record,
            operation_order,
            receipt,
        }
    }

    /// Returns the typed generation/cutover contract.
    pub const fn record(&self) -> &RuntimeGenerationCutoverRecord {
        &self.record
    }

    /// Returns the ORS ordering value for this evidence.
    pub const fn operation_order(&self) -> u64 {
        self.operation_order
    }

    /// Returns the integrity-bound receipt for this canonical record.
    pub const fn receipt(&self) -> &GenerationCutoverReceipt {
        &self.receipt
    }
}

/// Persisted non-semantic phase for a P.4 operational subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationalPhase {
    Staged,
    Applying,
    Active,
    Suspended,
    Reconciling,
    Terminal,
    Released,
    Fenced,
}

/// Integrity-bound receipt created only by the durable store implementation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationalMutationReceipt {
    record_id: OperationIdentity,
    subject_id: OperationIdentity,
    operation_order: u64,
    phase: OperationalPhase,
    state_sha256: String,
}

impl OperationalMutationReceipt {
    pub fn record_id(&self) -> &OperationIdentity {
        &self.record_id
    }

    pub fn subject_id(&self) -> &OperationIdentity {
        &self.subject_id
    }

    pub const fn operation_order(&self) -> u64 {
        self.operation_order
    }

    pub const fn phase(&self) -> OperationalPhase {
        self.phase
    }

    pub fn state_sha256(&self) -> &str {
        &self.state_sha256
    }

    pub(crate) fn issue(
        record_id: OperationIdentity,
        subject_id: OperationIdentity,
        operation_order: u64,
        phase: OperationalPhase,
        state_sha256: String,
    ) -> Result<Self, OrsError> {
        if operation_order == 0 {
            return Err(OrsError::IntegrityProblem {
                record_type: "operational_receipt",
                reason: "operation order is zero".to_owned(),
            });
        }
        validate_digest(&state_sha256, "operational_state_sha256")?;
        Ok(Self {
            record_id,
            subject_id,
            operation_order,
            phase,
            state_sha256,
        })
    }
}

macro_rules! operational_receipt {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(OperationalMutationReceipt);

        impl $name {
            pub fn receipt(&self) -> &OperationalMutationReceipt {
                &self.0
            }

            pub(crate) const fn from_receipt(receipt: OperationalMutationReceipt) -> Self {
                Self(receipt)
            }
        }
    };
}

operational_receipt!(StageReceipt);
operational_receipt!(DeliveryCursorReceipt);
operational_receipt!(AdmissionReservationReceipt);
operational_receipt!(GenerationTransitionReceipt);
operational_receipt!(GenerationCutoverReceipt);
operational_receipt!(SessionBindingReceipt);
operational_receipt!(UserBrokerRegistrationReceipt);
operational_receipt!(AuthoritySnapshotReceipt);
operational_receipt!(AuthorityRevocationReceipt);
operational_receipt!(AuthorityActivationReceipt);
operational_receipt!(CapabilityIntroductionReceipt);

/// Integrity-checked active authority snapshot read back from ORS.
///
/// This value proves only that P-06 recovered the exact opaque record it had
/// durably committed. ORS never decrypts or interprets the payload and this
/// value grants no Kernel or process authority. The P-07 owner must resolve
/// the payload through its platform secret/artifact port and revalidate the
/// decoded authority state against the expected active identity and fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveredAuthoritySnapshot {
    snapshot: KernelAuthoritySnapshot,
    operation_order: u64,
    receipt: AuthoritySnapshotReceipt,
}

impl RecoveredAuthoritySnapshot {
    pub(crate) const fn from_store(
        snapshot: KernelAuthoritySnapshot,
        operation_order: u64,
        receipt: AuthoritySnapshotReceipt,
    ) -> Self {
        Self {
            snapshot,
            operation_order,
            receipt,
        }
    }

    /// Returns the validated opaque authority-snapshot record.
    pub const fn snapshot(&self) -> &KernelAuthoritySnapshot {
        &self.snapshot
    }

    /// Returns the monotonic ORS operation order at which it became active.
    pub const fn operation_order(&self) -> u64 {
        self.operation_order
    }

    /// Returns the store-issued integrity receipt for the recovered record.
    pub const fn receipt(&self) -> &AuthoritySnapshotReceipt {
        &self.receipt
    }
}

/// Signed/hashed recovery-inbox item. ORS verifies bindings and delegates signer trust.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryInboxItem {
    pub item_id: OperationIdentity,
    pub signer_id: OpaqueLabel,
    pub envelope: RecoveryPayloadEnvelope,
    pub envelope_sha256: String,
    pub signature: Vec<u8>,
    pub signature_sha256: String,
    pub arrived_at_ms: i64,
}

impl RecoveryInboxItem {
    pub fn bind(
        item_id: OperationIdentity,
        signer_id: OpaqueLabel,
        envelope: RecoveryPayloadEnvelope,
        signature: Vec<u8>,
        arrived_at_ms: i64,
    ) -> Result<Self, OrsError> {
        let envelope_bytes =
            serde_json::to_vec(&envelope).map_err(|error| OrsError::Encoding(error.to_string()))?;
        let value = Self {
            item_id,
            signer_id,
            envelope,
            envelope_sha256: sha256_hex(&envelope_bytes),
            signature_sha256: sha256_hex(&signature),
            signature,
            arrived_at_ms,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        self.envelope.validate()?;
        validate_digest(&self.envelope_sha256, "inbox_envelope_sha256")?;
        validate_digest(&self.signature_sha256, "inbox_signature_sha256")?;
        if self.signature.is_empty()
            || self.signature.len() > crate::MAX_INBOX_SIGNATURE_BYTES
            || sha256_hex(&self.signature) != self.signature_sha256
            || sha256_hex(
                &serde_json::to_vec(&self.envelope)
                    .map_err(|error| OrsError::Encoding(error.to_string()))?,
            ) != self.envelope_sha256
        {
            return Err(OrsError::InboxIntegrityMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryInboxDisposition {
    Imported,
    Applied,
    Rejected,
    DeadLetter,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryInboxReceipt(OperationalMutationReceipt);

impl RecoveryInboxReceipt {
    pub fn receipt(&self) -> &OperationalMutationReceipt {
        &self.0
    }

    pub(crate) const fn from_receipt(receipt: OperationalMutationReceipt) -> Self {
        Self(receipt)
    }
}

/// Bounded logical ORS export request. It never copies a live redb file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrsSnapshotRequest {
    pub after_order: u64,
    pub limit: u16,
    pub snapshot_at_ms: i64,
}

impl OrsSnapshotRequest {
    pub fn new(after_order: u64, limit: u16, snapshot_at_ms: i64) -> Result<Self, OrsError> {
        if limit == 0 || limit > MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        Ok(Self {
            after_order,
            limit,
            snapshot_at_ms,
        })
    }
}

/// Store-issued logical snapshot receipt with retained evidence bindings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsSnapshotReceipt {
    snapshot_at_ms: i64,
    entry_refs: Vec<String>,
    snapshot_sha256: String,
    next_after_order: Option<u64>,
}

impl OrsSnapshotReceipt {
    pub const fn snapshot_at_ms(&self) -> i64 {
        self.snapshot_at_ms
    }

    pub fn entry_refs(&self) -> &[String] {
        &self.entry_refs
    }

    pub fn snapshot_sha256(&self) -> &str {
        &self.snapshot_sha256
    }

    pub const fn next_after_order(&self) -> Option<u64> {
        self.next_after_order
    }

    pub(crate) fn issue(
        snapshot_at_ms: i64,
        entry_refs: Vec<String>,
        snapshot_sha256: String,
        next_after_order: Option<u64>,
    ) -> Result<Self, OrsError> {
        validate_digest(&snapshot_sha256, "ors_snapshot_sha256")?;
        Ok(Self {
            snapshot_at_ms,
            entry_refs,
            snapshot_sha256,
            next_after_order,
        })
    }
}

/// Exact terminal reservation sequence disposition retained for gap/readback proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeTerminalReceipt {
    pub scope: OrderingScope,
    pub reserved_sequence: u64,
    pub disposition: CanonicalDisposition,
    pub gap: bool,
    pub receipt_id: OpaqueLabel,
    pub receipt_sha256: String,
}

/// Read-only terminal/gap evidence; it has no public constructor or deserializer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScopeTerminalView {
    scope: OrderingScope,
    reserved_sequence: u64,
    disposition: CanonicalDisposition,
    gap: bool,
    receipt_id: OpaqueLabel,
    receipt_sha256: String,
}

impl ScopeTerminalView {
    pub fn scope(&self) -> &OrderingScope {
        &self.scope
    }

    pub const fn reserved_sequence(&self) -> u64 {
        self.reserved_sequence
    }

    pub const fn disposition(&self) -> CanonicalDisposition {
        self.disposition
    }

    pub const fn is_gap(&self) -> bool {
        self.gap
    }

    pub fn receipt_id(&self) -> &OpaqueLabel {
        &self.receipt_id
    }

    pub fn receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }

    pub(crate) fn from_persisted(value: &ScopeTerminalReceipt) -> Self {
        Self {
            scope: value.scope.clone(),
            reserved_sequence: value.reserved_sequence,
            disposition: value.disposition,
            gap: value.gap,
            receipt_id: value.receipt_id.clone(),
            receipt_sha256: value.receipt_sha256.clone(),
        }
    }
}

/// Bounded alias matching Appendix P.4 terminology.
pub type PendingOperationPage = RecoveryPage;

/// Bounded non-authoritative control projection rebuilt from validated durable records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalControlProjection {
    pub authority_lineage: EpochLineage,
    pub pending_operation_refs: Vec<String>,
    pub active_generation_refs: Vec<String>,
    pub active_session_refs: Vec<String>,
    pub active_user_broker_refs: Vec<String>,
    pub active_capability_refs: Vec<String>,
    pub job_checkpoint_refs: Vec<String>,
    pub delivery_cursor_refs: Vec<String>,
    pub recovery_inbox_refs: Vec<String>,
}

/// Typed ORS failures. None grants semantic or completion authority.
#[derive(Debug, Error)]
pub enum OrsError {
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("foundation contract rejected ORS input: {0}")]
    Contract(String),
    #[error("unsupported recovery envelope contract version {0}")]
    UnsupportedContractVersion(u16),
    #[error("payload length exceeds the supported counter")]
    PayloadTooLarge,
    #[error("payload bytes do not match their declared length and SHA-256")]
    PayloadIntegrityMismatch,
    #[error("authority epoch does not match the State Fence")]
    FenceMismatch,
    #[error("authority epoch does not match the recovery envelope")]
    EpochMismatch,
    #[error("epoch lineage does not strictly advance its same-lineage predecessor")]
    InvalidEpochLineage,
    #[error("expiry must be strictly later than creation")]
    InvalidExpiry,
    #[error("authority handoff is not fresh at its reservation linearization point")]
    AuthorityHandoffNotFresh,
    #[error("at least one Ordering Scope is required")]
    EmptyScopeSet,
    #[error("an Ordering Scope occurs more than once")]
    DuplicateScope,
    #[error("recovery cursor limit must be between 1 and {MAX_RECOVERY_PAGE}")]
    InvalidCursorLimit,
    #[error("duplicate identity conflicts with durable ORS state")]
    DuplicateConflict,
    #[error("reservation was not found")]
    ReservationNotFound,
    #[error("reservation lifecycle transition is invalid")]
    InvalidTransition,
    #[error("writer epoch is stale or does not own the reservation")]
    StaleWriterEpoch,
    #[error("an earlier reservation blocks this scope")]
    PredecessorPending,
    #[error("scope requires receipt reconciliation before new allocation")]
    ScopeRecoveryRequired,
    #[error("recovery owner does not match the token")]
    RecoveryOwnerMismatch,
    #[error("active or unknown work cannot expire without canonical reconciliation")]
    UnsafeExpiry,
    #[error(
        "canonical reconciliation does not exactly bind receipt, operation, scopes, order, heads, and fence"
    )]
    ReconciliationMismatch,
    #[error("an UNKNOWN receipt cannot resolve an unknown operation")]
    UnknownReceiptCannotResolve,
    #[error("canonical evidence provider rejected or could not authenticate evidence: {0}")]
    CanonicalEvidence(String),
    #[error("canonical ordering head does not match durable ORS state")]
    OrderingHeadMismatch,
    #[error("recovery inbox signature or envelope binding is invalid")]
    InboxIntegrityMismatch,
    #[error("active authority snapshot is unavailable")]
    AuthoritySnapshotUnavailable,
    #[error("operational projection exceeds its declared bound")]
    ProjectionLimitExceeded,
    #[error("supervision-lease revision is stale or does not match the current ORS head")]
    SupervisionLeaseStaleRevision,
    #[error("supervision-lease ticket or commit artifact conflicts with durable ORS state")]
    SupervisionLeaseTicketConflict,
    #[error("supervision-lease commit artifact does not bind the staged ticket exactly")]
    SupervisionLeaseBindingMismatch,
    #[error("supervision-lease ticket is neither staged nor durably committed")]
    SupervisionLeaseTicketNotStaged,
    #[error("supervision-lease history limit must be between 1 and {MAX_RECOVERY_PAGE}")]
    InvalidSupervisionLeaseHistoryLimit,
    #[error("durable ORS integrity problem in {record_type}: {reason}")]
    IntegrityProblem {
        record_type: &'static str,
        reason: String,
    },
    #[error("durable ORS storage failed: {0}")]
    Storage(String),
    #[error("durable ORS encoding failed: {0}")]
    Encoding(String),
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreRebindReplayState {
    Pending,
    Committed,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRebindReplayRecord {
    pub operation_id: OperationIdentity,
    pub request_digest: String,
    pub candidate_binding_digest: String,
    pub store_fence: String,
    pub requirement_digest: String,
    pub process_id: u32,
    pub process_start_time_100ns: u64,
    pub process_image_path: String,
    pub job_name: String,
    pub generation: u64,
    pub authority_epoch: u64,
    pub state: StoreRebindReplayState,
    pub receipt: Option<String>,
}

impl StoreRebindReplayRecord {
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(self.operation_id.as_str(), "store_rebind_operation_id")?;
        validate_digest(&self.request_digest, "store_rebind_request_digest")?;
        validate_digest(&self.candidate_binding_digest, "store_rebind_candidate_digest")?;
        validate_digest(&self.store_fence, "store_rebind_store_fence")?;
        validate_digest(&self.requirement_digest, "store_rebind_requirement_digest")?;
        if self.process_id == 0 || self.process_start_time_100ns == 0 {
            return Err(OrsError::InvalidField {
                field: "store_rebind_process",
                reason: "must be non-zero",
            });
        }
        validate_text(&self.process_image_path, "store_rebind_image")?;
        validate_text(&self.job_name, "store_rebind_job")?;
        if self.generation == 0 || self.authority_epoch == 0 {
            return Err(OrsError::InvalidField {
                field: "store_rebind_epoch",
                reason: "must be non-zero",
            });
        }
        if let Some(receipt) = &self.receipt {
            validate_digest(receipt, "store_rebind_receipt")?;
            if self.state != StoreRebindReplayState::Committed {
                return Err(OrsError::InvalidField {
                    field: "store_rebind_state",
                    reason: "receipt only for committed",
                });
            }
        } else if self.state == StoreRebindReplayState::Committed {
            return Err(OrsError::InvalidField {
                field: "store_rebind_receipt",
                reason: "committed requires receipt",
            });
        }
        Ok(())
    }
}

pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), OrsError> {
    if value.trim().is_empty() {
        return Err(OrsError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(OrsError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > 1_024 {
        return Err(OrsError::InvalidField {
            field,
            reason: "must not exceed 1024 UTF-8 bytes",
        });
    }
    Ok(())
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<(), OrsError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(OrsError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize).collect()),
        Value::Object(object) => {
            let mut sorted = Map::new();
            let mut entries: Vec<_> = object.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (key, value) in entries {
                sorted.insert(key, canonicalize(value));
            }
            Value::Object(sorted)
        }
        scalar => scalar,
    }
}
