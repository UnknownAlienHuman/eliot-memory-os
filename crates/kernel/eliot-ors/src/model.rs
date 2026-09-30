use eliot_contracts::{
    AuthorityEpoch, BridgeEventCapacityPressure, EpochId, ResourceGeneration, StateFence,
    canonical_json_bytes,
};
use eliot_platform::{PlatformHandle, SecretReference};
use eliot_process::ProcessStreamKind;
use eliot_receipts::{
    AuthorityBinding, GrantClosureAuthorityReceiptRef, GrantClosureDeclaration, ProofCeiling,
    ReceiptDisposition, ReceiptEnvelope, ReceiptIdentity,
};
pub use eliot_receipts::{
    GRANT_CLOSURE_SCHEMA, GRANT_CLOSURE_VERSION, GrantClosureAlternatePath,
    GrantClosureMemberDeclaration, GrantClosureReceipt, GrantClosureState,
};
use eliot_runtime_contracts::{
    GenerationCutoverRecord as RuntimeGenerationCutoverRecord, LeaseState, SignedSupervisionLease,
    SupervisionGenerationBinding, SupervisionLease, SupervisionLeaseActiveStateBinding,
    SupervisionLeaseTerminalDisposition, SupervisionLeaseVerificationContext,
    SupervisionObservationScope, SupervisionOrsMirrorBinding, VerifiedSupervisionLease,
    VerifiedSupervisionLeaseTerminalTransition,
};
use eliot_security_contracts::{
    InfluenceState, InstructionTaint, NativeResourceSelection, PolicyFence, PrivacyClass,
    TransformationLineage,
};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::process_stream_recovery::ProcessStreamObservation;
use crate::reservation_model::ReservationRecord;
use crate::{CONTRACT_VERSION, MAX_INLINE_RECOVERY_BYTES, MAX_RECOVERY_PAGE};

/// `HostRequest` rows written with this send-claim protocol persist a durable
/// pre-transport fence and typed custody evidence. Zero remains the legacy
/// wire value and is classified conservatively during restart recovery.
pub const HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION: u16 = 1;

/// Current version of the encrypted executable-input carrier on a host request.
pub const HOST_REQUEST_EXECUTABLE_INPUT_CONTRACT_VERSION: u16 = 1;

/// Shared schema identity for the canonical ToolRequest byte stream.
pub const HOST_REQUEST_TOOL_REQUEST_SCHEMA_ID: &str = "eliot.mcp.tool-request.v1";

/// Hard ceiling for one complete retained executable ToolRequest.
pub const MAX_HOST_REQUEST_EXECUTABLE_INPUT_BYTES: u64 = 64 * 1024;

/// Maximum canonical owner-binding bytes retained beside one executable host
/// request. Payload bytes are separately protected and use their own cap.
pub const MAX_HOST_REQUEST_APPLICATION_BINDING_BYTES: usize = 256 * 1024;

/// This issue allows one original send attempt plus one proven-not-sent retry.
pub const MAX_HOST_REQUEST_SEND_ATTEMPTS: usize = 2;

/// Maximum active claim lifetime for one authenticated `UserAutomation` send.
/// This follows the Host Control Endpoint's existing 30-second queue-response
/// timeout; expiry moves an uncertain claim to reconciliation and never frees
/// it for another send.
pub const HOST_REQUEST_SEND_CLAIM_LEASE_MS: u64 = 30_000;
use std::collections::{BTreeMap, BTreeSet};

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

/// Current explicit version of the authenticated bridge event owner namespace.
///
/// The version is fixed by the ORS contract and is included in the canonical
/// namespace digest; callers cannot select an older or weaker encoding.
pub const BRIDGE_EVENT_OWNER_NAMESPACE_VERSION: u16 = 3;

/// Authenticated semantic scope retained for a bridge event owner.
///
/// `UnboundObservation` is a task-free, owner-issued observation scope. It is
/// not a caller-selected task, and the `producer_id` on
/// [`BridgeEventOwnerNamespace`] still identifies the admitted producer
/// occurrence. Neither variant is authentication evidence by itself: Kernel
/// must derive it from its retained owner state and ORS must compare the whole
/// value against the expected stored owner revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BridgeEventOwnerScope {
    /// A semantic application Session, optionally narrowed to one Attempt.
    ApplicationSession {
        session_id: OpaqueLabel,
        attempt_id: Option<OpaqueLabel>,
    },
    /// An explicitly unbound observation scope with no task or Attempt claim.
    UnboundObservation { observation_scope_id: OpaqueLabel },
}

/// Resource name and store-issued incarnation within a bridge owner namespace.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BridgeEventOwnerResource {
    /// A durable event stream. Its incarnation is assigned by ORS on first
    /// binding and changes only through the store's checked owner transition.
    Stream {
        local_stream: OpaqueLabel,
        incarnation: u64,
    },
    /// A connection-level coverage gap for which no stream is known.
    UnscopedGap { local_gap_id: OpaqueLabel },
}

/// Typed, versioned identity for one authenticated bridge event owner.
///
/// This is an identity value, not a capability. The installation, principal,
/// producer, semantic scope, authority lineage and stream incarnation must
/// come from Kernel-owned admission state. Connection ID and producer
/// generation remain observation metadata and are deliberately absent here.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeEventOwnerNamespace {
    /// Stable authenticated installation identity from the Host binding.
    pub installation_id: OpaqueLabel,
    /// Authority lineage retained by the admission owner.
    pub authority_lineage: OpaqueLabel,
    /// Authenticated semantic principal; never an operating-system user name.
    pub principal: OpaqueLabel,
    /// Admitted producer identity for this stream or unscoped gap.
    pub producer_id: OpaqueLabel,
    /// Application-session or explicit owner-issued unbound observation scope.
    pub owner_scope: BridgeEventOwnerScope,
    /// Local resource identity and store-assigned incarnation, when applicable.
    pub resource: BridgeEventOwnerResource,
}

impl BridgeEventOwnerNamespace {
    /// Checks identity component shape without authenticating the source.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_bridge_event_owner_component(&self.installation_id, "installation_id")?;
        validate_bridge_event_owner_component(&self.authority_lineage, "authority_lineage")?;
        validate_bridge_event_owner_component(&self.principal, "principal")?;
        validate_bridge_event_owner_component(&self.producer_id, "producer_id")?;
        match &self.owner_scope {
            BridgeEventOwnerScope::ApplicationSession {
                session_id,
                attempt_id,
            } => {
                validate_bridge_event_owner_component(session_id, "session_id")?;
                if let Some(attempt_id) = attempt_id {
                    validate_bridge_event_owner_component(attempt_id, "attempt_id")?;
                }
            }
            BridgeEventOwnerScope::UnboundObservation {
                observation_scope_id,
            } => {
                validate_bridge_event_owner_component(
                    observation_scope_id,
                    "observation_scope_id",
                )?;
            }
        }
        match &self.resource {
            BridgeEventOwnerResource::Stream {
                local_stream,
                incarnation,
            } => {
                validate_bridge_event_owner_component(local_stream, "local_stream")?;
                if *incarnation == 0 {
                    return Err(OrsError::InvalidField {
                        field: "stream_incarnation",
                        reason: "bridge stream incarnation is store-assigned and nonzero",
                    });
                }
            }
            BridgeEventOwnerResource::UnscopedGap { local_gap_id } => {
                validate_bridge_event_owner_component(local_gap_id, "local_gap_id")?;
            }
        }
        Ok(())
    }

    /// Returns the canonical SHA-256 namespace digest for this exact owner.
    ///
    /// Canonical JSON keeps labels unambiguous without delimiter-based key
    /// construction. The fixed domain includes namespace version 3. This
    /// digest selects a candidate row only; the store must still compare every
    /// field and the expected owner revision in the same write transaction.
    pub fn namespace_digest(&self) -> Result<String, OrsError> {
        self.validate()?;
        let bytes = canonical_json_bytes(&BridgeEventOwnerNamespacePreimage {
            domain: "eliot.bridge-event-owner",
            version: BRIDGE_EVENT_OWNER_NAMESPACE_VERSION,
            installation_id: self.installation_id.as_str(),
            authority_lineage: self.authority_lineage.as_str(),
            principal: self.principal.as_str(),
            producer_id: self.producer_id.as_str(),
            owner_scope: &self.owner_scope,
            resource: &self.resource,
        })
        .map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

#[derive(Serialize)]
struct BridgeEventOwnerNamespacePreimage<'a> {
    domain: &'static str,
    version: u16,
    installation_id: &'a str,
    authority_lineage: &'a str,
    principal: &'a str,
    producer_id: &'a str,
    owner_scope: &'a BridgeEventOwnerScope,
    resource: &'a BridgeEventOwnerResource,
}

fn validate_bridge_event_owner_component(
    label: &OpaqueLabel,
    field: &'static str,
) -> Result<(), OrsError> {
    validate_text(label.as_str(), field)?;
    if label.as_str().contains("::") {
        return Err(OrsError::InvalidField {
            field,
            reason: "owner identity components must not contain the key separator",
        });
    }
    if label.as_str() == "-" {
        return Err(OrsError::InvalidField {
            field,
            reason: "owner identity components must not equal the unbound marker",
        });
    }
    Ok(())
}

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
    pub kernel_epoch: EpochId,
    pub kernel_front_door_server_sid: String,
    pub kernel_front_door_session_id: u32,
    pub kernel_front_door_artifact_sha256: String,
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
            && self.kernel_front_door_server_sid == successor.kernel_front_door_server_sid
            && self.kernel_front_door_session_id == successor.kernel_front_door_session_id
            && self.kernel_front_door_artifact_sha256 == successor.kernel_front_door_artifact_sha256
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
            kernel_epoch: self.kernel_epoch.clone(),
            kernel_front_door_server_sid: self.kernel_front_door_server_sid.clone(),
            kernel_front_door_session_id: self.kernel_front_door_session_id,
            kernel_front_door_artifact_sha256: self.kernel_front_door_artifact_sha256.clone(),
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

/// Durable terminal disposition for a supervision ticket which never crossed
/// the signed-lease commit linearization point.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupervisionLeaseStageResolutionDisposition {
    /// The active ticket's signed validity window elapsed before ORS commit.
    Expired,
    /// An explicit pre-commit abort released the exact staged ticket.
    Aborted,
}

/// Exact durable state observed while reconciling one supervision ticket.
///
/// This is a read/recovery projection, not a second authority record. Each
/// variant retains the authoritative ORS value which caused the decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupervisionLeaseTicketReconciliation {
    /// The exact ticket remains staged and must be resumed with the same
    /// signer authority.
    Staged(SupervisionLeaseStageReceipt),
    /// The exact ticket already crossed the ORS commit linearization point.
    Committed(Box<SupervisionLeaseSnapshot>),
    /// The exact ticket was durably released without publishing authority.
    Resolved(SupervisionLeaseStageResolution),
}

/// Immutable ORS evidence that one exact staged ticket was released without
/// publishing lease authority.
///
/// A resolution is keyed by `ticket_id`, retains the full ticket and its
/// canonical digest, and is written atomically with stage removal.  Its
/// presence therefore prevents a missing staged row from being interpreted as
/// permission to retry or replace an unknown authority operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionLeaseStageResolution {
    pub ticket: SupervisionLeaseCommitTicket,
    pub ticket_sha256: String,
    pub disposition: SupervisionLeaseStageResolutionDisposition,
    pub resolved_at_ms: u64,
    pub resolution_order: u64,
    pub reason: OpaqueLabel,
    pub resolution_sha256: String,
}

#[derive(Serialize)]
struct SupervisionLeaseStageResolutionCore<'a> {
    ticket: &'a SupervisionLeaseCommitTicket,
    ticket_sha256: &'a str,
    disposition: SupervisionLeaseStageResolutionDisposition,
    resolved_at_ms: u64,
    resolution_order: u64,
    reason: &'a OpaqueLabel,
}

impl SupervisionLeaseStageResolution {
    fn core(&self) -> SupervisionLeaseStageResolutionCore<'_> {
        SupervisionLeaseStageResolutionCore {
            ticket: &self.ticket,
            ticket_sha256: &self.ticket_sha256,
            disposition: self.disposition,
            resolved_at_ms: self.resolved_at_ms,
            resolution_order: self.resolution_order,
            reason: &self.reason,
        }
    }

    pub(crate) fn issue(
        ticket: SupervisionLeaseCommitTicket,
        disposition: SupervisionLeaseStageResolutionDisposition,
        resolved_at_ms: u64,
        resolution_order: u64,
        reason: OpaqueLabel,
    ) -> Result<Self, OrsError> {
        let ticket_sha256 = ticket.ticket_sha256()?;
        let mut resolution = Self {
            ticket,
            ticket_sha256,
            disposition,
            resolved_at_ms,
            resolution_order,
            reason,
            resolution_sha256: String::new(),
        };
        resolution.validate_core()?;
        let bytes = canonical_json_bytes(&resolution.core())
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        resolution.resolution_sha256 = sha256_hex(&bytes);
        Ok(resolution)
    }

    fn validate_core(&self) -> Result<(), OrsError> {
        self.ticket.validate()?;
        if self.ticket_sha256 != self.ticket.ticket_sha256()? {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        if self.resolved_at_ms == 0 || self.resolution_order <= self.ticket.reservation_order {
            return Err(OrsError::InvalidField {
                field: "supervision_stage_resolution_sequence",
                reason: "resolution time must be positive and order must follow reservation",
            });
        }
        if self.disposition == SupervisionLeaseStageResolutionDisposition::Expired
            && (!matches!(
                self.ticket.operation,
                SupervisionLeaseOperation::Commit | SupervisionLeaseOperation::Renew
            ) || self.resolved_at_ms < self.ticket.binding.expires_at_ms)
        {
            return Err(OrsError::InvalidField {
                field: "supervision_stage_resolution_expiry",
                reason: "only an elapsed active ticket may be resolved as expired",
            });
        }
        if self.disposition == SupervisionLeaseStageResolutionDisposition::Expired
            && self.reason.as_str() != "active-ticket-window-elapsed"
        {
            return Err(OrsError::InvalidField {
                field: "supervision_stage_resolution_reason",
                reason: "expired tickets require the canonical elapsed-window reason",
            });
        }
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        self.validate_core()?;
        validate_digest(
            &self.resolution_sha256,
            "supervision_stage_resolution_sha256",
        )?;
        let bytes = canonical_json_bytes(&self.core())
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        if sha256_hex(&bytes) != self.resolution_sha256 {
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
    /// Validates the complete current/history record and canonical receipt.
    ///
    /// This is public so an authenticated IPC consumer can validate a snapshot
    /// before comparing it with the exact durable ORS head. Validation grants
    /// no lease authority and performs no signature verification.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.record.validate(&self.receipt)
    }

    /// Constructs the verifier context from the validated pre-sign ORS
    /// binding, never from caller-authored admission values or by copying the
    /// signed payload. Only an active current snapshot can produce a context.
    pub fn active_verification_context(
        &self,
        public_key_fingerprint: impl Into<String>,
        now_ms: u64,
    ) -> Result<SupervisionLeaseVerificationContext, OrsError> {
        self.validate()?;
        if self.record.state != LeaseState::Active
            || self.record.projection != SupervisionLeaseProjection::Active
        {
            return Err(OrsError::SupervisionLeaseBindingMismatch);
        }
        let binding = &self.record.binding;
        let generation = &binding.generation_binding;
        let context = SupervisionLeaseVerificationContext {
            now_ms,
            lease_id: self.record.lease_id.as_str().to_owned(),
            host_epoch: binding.host_epoch,
            activation_id: binding.activation_id.as_str().to_owned(),
            activation_generation: binding.activation_generation,
            kernel_epoch: binding.kernel_epoch.clone(),
            watchdog_epoch: binding.watchdog_epoch,
            state_fence: binding.state_fence.clone(),
            scope_ref: binding.scope_ref.as_str().to_owned(),
            observation_scope: binding.observation_scope.clone(),
            target_id: generation.target_id.clone(),
            module_id: generation.module_id.clone(),
            process_id: generation.process_id.clone(),
            target_generation: generation.target_generation,
            module_generation: generation.module_generation,
            process_generation: generation.process_generation,
            public_key_fingerprint: public_key_fingerprint.into(),
            ors_mirror: SupervisionOrsMirrorBinding {
                record_id: self.record.record_id.as_str().to_owned(),
                subject_lease_id: self.record.lease_id.as_str().to_owned(),
                lease_revision: self.record.revision,
                ticket_sha256: self.record.ticket_sha256.clone(),
                previous_receipt_sha256: self.record.previous_receipt_sha256.clone(),
            },
            active_state: SupervisionLeaseActiveStateBinding {
                state: binding.state,
                revocation_id: binding.revocation_id.clone(),
                revocation_epoch: binding.revocation_epoch,
            },
        };
        context
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        Ok(context)
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
            self.owner.authority_epoch().clone(),
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

/// ORS wire/storage revision of the byte-free process-evidence observation row
/// (issue #269, A1).
///
/// Rows written before this revision existed carry the accepted
/// `ProcessEvidence` value inline, bounded preview bytes included. The codec
/// dispatches on the row's `observation_schema_version` field: a row that
/// carries this value is decoded as a byte-free observation, a row that does not
/// carry the field at all is a pre-#269 row and is dispositioned, and a row that
/// carries a different value is refused as a typed codec-version mismatch. No
/// pre-#269 row is rewritten, stripped or deleted.
pub const PROCESS_EVIDENCE_OBSERVATION_SCHEMA: &str = "eliot-ors-process-observation-v2";

/// Byte-free ORS observation of one `ProcessEvidence` value (issue #269, A1).
///
/// This is the observation ORS retains. It keeps the byte-free process execution
/// view, the C0-05 observation-only axes, and one byte-free
/// [`ProcessStreamObservation`] per observed physical stream, so the evidence
/// identity, the immutable locator plus ready receipt and the exact digests and
/// counts survive and a reader can revalidate them against the Blob owner.
///
/// It holds no stdout/stderr payload. The digest over the ORIGINAL observed
/// bytes is not here and is not recomputed: it stays on the record as
/// `evidence_digest`, taken once at the write boundary over the bytes the
/// executor actually produced, so a reader revalidates that digest against the
/// Blob owner rather than against a payload ORS must not keep.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEvidenceObservation {
    /// Accepted reconciliation-evidence contract revision `evidence_digest` was
    /// computed over. A move of this string is refused, never reinterpreted.
    pub evidence_schema_version: String,
    /// Byte-free process execution view of the observation.
    pub view: eliot_process::ProcessExecutionView,
    /// C0-05 observation-only evidence axes, retained verbatim.
    ///
    /// Held as the accepted evidence contract's own JSON projection rather than
    /// as a re-declared ORS enum, so the retained axes are exactly the ones the
    /// producer emitted and ORS adds no second spelling of a C0-05 axis. It
    /// carries no payload.
    pub axes: Value,
    /// Byte-free stdout observation, when one was observed.
    pub stdout: Option<ProcessStreamObservation>,
    /// Byte-free stderr observation, when one was observed.
    pub stderr: Option<ProcessStreamObservation>,
}

impl ProcessEvidenceObservation {
    /// Reduces one accepted evidence value to its byte-free ORS observation.
    ///
    /// `evidence` is read, never copied: its bounded inline preview bytes are
    /// deliberately not retained, and nothing here re-derives a digest over them.
    pub fn from_evidence(evidence: &eliot_process::ProcessEvidence) -> Result<Self, OrsError> {
        let observation = Self {
            evidence_schema_version: evidence.schema_version().to_owned(),
            view: evidence.view().clone(),
            axes: serde_json::to_value(evidence.axes())
                .map_err(|error| OrsError::Encoding(error.to_string()))?,
            stdout: evidence
                .stdout()
                .map(ProcessStreamObservation::from_stream_evidence)
                .transpose()?,
            stderr: evidence
                .stderr()
                .map(ProcessStreamObservation::from_stream_evidence)
                .transpose()?,
        };
        observation.validate()?;
        Ok(observation)
    }

    fn validate(&self) -> Result<(), OrsError> {
        if self.evidence_schema_version != eliot_process::PROCESS_EVIDENCE_SCHEMA_VERSION {
            return Err(OrsError::Contract(format!(
                "process evidence observation is bound to evidence contract revision {}, \
                 not the accepted revision {}",
                self.evidence_schema_version,
                eliot_process::PROCESS_EVIDENCE_SCHEMA_VERSION
            )));
        }
        // Observation-only C0-05 axes, the same judgement the byte-bearing row
        // made and the reason it existed: ORS retains no authority claim, so a
        // row that escalates is refused instead of stored. The literals are the
        // accepted evidence contract's own spellings.
        if self.axes.get("status").and_then(Value::as_str) != Some("OBSERVED")
            || self.axes.get("assertability").and_then(Value::as_str)
                != Some("NON_ASSERTABLE_UNVERIFIED")
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "process_evidence",
                reason: "process evidence is not observation-only C0 evidence".to_owned(),
            });
        }
        for observation in [self.stdout.as_ref(), self.stderr.as_ref()]
            .into_iter()
            .flatten()
        {
            observation.validate()?;
        }
        Ok(())
    }
}

/// Observation-only process evidence retained by ORS.
///
/// The authority epoch is the lineage-aware [`EpochId`] exact tuple
/// (Implements #64, donor precedent `origin/work/100-process-epoch-v4-F`).
/// It is bound from the owner's canonical epoch at admission; scalar-only
/// owners without canonical lineage evidence cannot produce active authority
/// and fail closed. Adjacent `AuthorityHandoffRecord` u64 contours are
/// intentionally not widened here (flagged residual).
///
/// Issue #269 removed the raw payload from this row. It is the byte-free
/// [`ProcessEvidenceObservation`] plus the owner's identity, the digests that
/// bind it, and the observation time; the bounded inline preview bytes the
/// executor produced are not stored here. `evidence_digest` is therefore the
/// digest over the ORIGINAL observed bytes, taken once at the write boundary,
/// and it is the proof a reader revalidates against the Blob owner. It is not
/// re-derivable from the retained row, and pretending otherwise is exactly the
/// "strip the bytes and keep the digest" failure this revision removes, so
/// [`validate`](Self::validate) checks its shape and its cross-field bindings,
/// never a recomputation over absent bytes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEvidenceRecord {
    pub contract_version: u16,
    /// ORS process-evidence observation revision of this row; see
    /// [`PROCESS_EVIDENCE_OBSERVATION_SCHEMA`].
    pub observation_schema_version: String,
    pub operation_id: OperationIdentity,
    pub request_digest: String,
    pub process_tree_id: OpaqueLabel,
    pub job_id: OpaqueLabel,
    pub image_id: OpaqueLabel,
    pub session_id: OpaqueLabel,
    pub owner: eliot_process::ProcessOwnerBinding,
    pub authority_epoch: EpochId,
    pub generation: u64,
    pub state_fence_digest: String,
    pub binding_digest: String,
    pub evidence_digest: String,
    pub observed_at_ms: i64,
    pub evidence: ProcessEvidenceObservation,
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
        evidence: &eliot_process::ProcessEvidence,
        owner: eliot_process::ProcessOwnerBinding,
        observed_at_ms: i64,
    ) -> Result<Self, OrsError> {
        let binding = evidence.binding();
        let binding_bytes =
            serde_json::to_vec(binding).map_err(|error| OrsError::Encoding(error.to_string()))?;
        let state_fence_bytes = serde_json::to_vec(binding.state_fence())
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        // Taken over the ORIGINAL observation-only evidence value, bounded
        // preview bytes included; the bytes are then dropped. This digest is the
        // retained proof of which bytes were observed and is never recomputed
        // from a byte-free row.
        let evidence_bytes =
            serde_json::to_vec(evidence).map_err(|error| OrsError::Encoding(error.to_string()))?;
        // Lineage-aware binding (Implements #64): the active epoch comes only
        // from the owner's canonical `EpochId` via `authority_epoch`.
        // No scalar-to-authority coercion exists.
        let authority_epoch = owner.authority_epoch().clone();
        let record = Self {
            contract_version: CONTRACT_VERSION,
            observation_schema_version: PROCESS_EVIDENCE_OBSERVATION_SCHEMA.to_owned(),
            operation_id: OperationIdentity::new(binding.operation_id().as_str())?,
            request_digest: binding.request_digest().to_owned(),
            process_tree_id: OpaqueLabel::new(binding.process_tree_id().as_str())?,
            job_id: OpaqueLabel::new(binding.job_id().as_str())?,
            image_id: OpaqueLabel::new(binding.image_id().as_str())?,
            session_id: OpaqueLabel::new(binding.session_id().as_str())?,
            authority_epoch,
            generation: owner.generation().get(),
            owner,
            state_fence_digest: sha256_hex(&state_fence_bytes),
            binding_digest: sha256_hex(&binding_bytes),
            evidence_digest: sha256_hex(&evidence_bytes),
            observed_at_ms,
            evidence: ProcessEvidenceObservation::from_evidence(evidence)?,
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns the canonical immutable key for this one observation.
    pub fn record_key(&self) -> Result<String, OrsError> {
        self.validate()?;
        Ok(self.canonical_record_key())
    }

    /// The canonical durable key implied by this row's own identity fields.
    ///
    /// Split out from [`record_key`](Self::record_key) so the store's readback
    /// can compare a decoded row against its durable key without re-running the
    /// whole fail-closed validation.
    pub(crate) fn canonical_record_key(&self) -> String {
        let identity = ProcessEvidenceRecordIdentity {
            operation_id: self.operation_id.as_str(),
            process_tree_id: self.process_tree_id.as_str(),
            job_id: self.job_id.as_str(),
            image_id: self.image_id.as_str(),
            session_id: self.session_id.as_str(),
            evidence_digest: &self.evidence_digest,
            observed_at_ms: self.observed_at_ms,
        };
        let identity_bytes = serde_json::to_vec(&identity).unwrap_or_default();
        format!(
            "{}::{}",
            self.operation_id.as_str(),
            sha256_hex(&identity_bytes)
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "fail-closed ORS validation is kept together"
    )]
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        if self.observation_schema_version != PROCESS_EVIDENCE_OBSERVATION_SCHEMA {
            return Err(OrsError::Contract(format!(
                "process evidence observation revision {:?} is not the current ORS observation revision {PROCESS_EVIDENCE_OBSERVATION_SCHEMA}",
                self.observation_schema_version
            )));
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
        // `EpochId` is always a validated non-zero tuple; only generation and
        // observation time retain scalar positivity checks.
        if self.generation == 0 || self.observed_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "process_evidence_identity",
                reason: "epoch, generation, and observation time must be positive",
            });
        }
        self.evidence.validate()?;
        let owner = eliot_process::ProcessOwnerBinding::new(
            self.owner.module_id(),
            self.owner.principal_digest(),
            self.owner.authority_epoch().clone(),
            self.owner.generation(),
        )
        .map_err(|error| OrsError::IntegrityProblem {
            record_type: "process_evidence",
            reason: error.to_string(),
        })?;
        // Exact-tuple lineage check (Implements #64): the record epoch must be
        // the same `(lineage_id, sequence)` as the owner's canonical epoch
        // via `authority_epoch`; equal sequences from different lineages are
        // unrelated.
        let owner_canonical = self.owner.authority_epoch();
        if owner != self.owner
            || !self.authority_epoch.is_same_authority(owner_canonical)
            || self.generation != self.owner.generation().get()
            || self.operation_id.as_str() != self.evidence.view.operation_id().as_str()
            || self.request_digest != self.evidence.view.request_digest()
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "process_evidence",
                reason: "evidence identity does not match its durable projection".to_owned(),
            });
        }
        let binding = self.evidence.view.binding();
        if self.process_tree_id.as_str() != binding.process_tree_id().as_str()
            || self.job_id.as_str() != binding.job_id().as_str()
            || self.image_id.as_str() != binding.image_id().as_str()
            || self.session_id.as_str() != binding.session_id().as_str()
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "process_evidence",
                reason: "evidence identity does not match its durable projection".to_owned(),
            });
        }
        // Both digests are re-derived from the retained byte-free view's own
        // binding, so a row cannot claim a fence or binding its retained view
        // does not carry. `evidence_digest` is deliberately NOT re-derived: the
        // bytes it covers are the ones this revision stopped retaining.
        let binding_bytes =
            serde_json::to_vec(binding).map_err(|error| OrsError::Encoding(error.to_string()))?;
        let state_fence_bytes = serde_json::to_vec(binding.state_fence())
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        if sha256_hex(&binding_bytes) != self.binding_digest
            || sha256_hex(&state_fence_bytes) != self.state_fence_digest
        {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        let fence: Value = serde_json::from_slice(&state_fence_bytes)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        // Lineage-aware fence binding (Implements #64): the P-03 execution
        // fence carries its canonical `EpochId`; authorization uses
        // exact-tuple `is_same_authority`.
        let fence_canonical = binding.state_fence().authority_epoch();
        if !fence_canonical.is_same_authority(&self.authority_epoch) {
            return Err(OrsError::FenceMismatch);
        }
        let fence_generation = fence
            .get("generation")
            .and_then(Value::as_u64)
            .ok_or(OrsError::FenceMismatch)?;
        if fence_generation != self.generation {
            return Err(OrsError::FenceMismatch);
        }
        // Stdout and stderr stay independent and exact: each observation must sit
        // under its own stream field, so one can never be read back as the other.
        for (observation, expected) in [
            (self.evidence.stdout.as_ref(), ProcessStreamKind::Stdout),
            (self.evidence.stderr.as_ref(), ProcessStreamKind::Stderr),
        ] {
            if let Some(observation) = observation
                && observation.stream != expected
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: "process_evidence",
                    reason: "a stream observation does not sit under its own stream field"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Explicit read disposition of one pre-#269 `ors_process_evidence_v1` row.
///
/// Issue #269, A1. The row still holds the accepted `ProcessEvidence` value
/// inline, bounded preview bytes included. ORS no longer retains that payload
/// and no longer has a writer for it, so the row is reported, never rewritten
/// and never deleted.
///
/// The reported `evidence_digest` is UNVERIFIED on purpose: ORS cannot revalidate
/// a digest over the very bytes it must not keep, and revalidating it and then
/// dropping the bytes would be indistinguishable from stripping them. A row in
/// this disposition therefore can never be read back as a complete observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessInlineEvidenceRow {
    /// Canonical durable key the row is stored under.
    pub record_key: String,
    /// Operation the row observes.
    pub operation_id: OperationIdentity,
    /// Accepted evidence contract revision the row was written under.
    pub evidence_schema_version: String,
    /// The row's own digest over the original observed bytes; UNVERIFIED, see
    /// the type documentation.
    pub evidence_digest: String,
    /// Observation time in Unix milliseconds.
    pub observed_at_ms: i64,
    /// Which physical streams the row still carries inline payload for.
    pub inline_streams: Vec<ProcessStreamKind>,
}

/// One durable process-evidence row as ORS reads it back (issue #269, A1).
///
/// The two variants ARE the codec's explicit version transition. A byte-free
/// observation row is [`Observation`](Self::Observation); a pre-#269 row
/// carrying the inline payload is
/// [`InlinePayloadNotRetained`](Self::InlinePayloadNotRetained) and is
/// dispositioned rather than reinterpreted. Nothing else decodes.
///
/// The current row is boxed because it is two orders of magnitude larger than
/// the disposition, and a readback of one operation's history carries both
/// shapes: sizing the enum to the row would make the common legacy-disposition
/// read pay for a row it will never hold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessEvidenceReadback {
    /// Current byte-free observation row.
    Observation(Box<ProcessEvidenceRecord>),
    /// A pre-#269 row that still holds the inline stdout/stderr payload.
    InlinePayloadNotRetained(ProcessInlineEvidenceRow),
}

impl ProcessEvidenceReadback {
    /// Observation time, so a readback can be ordered in observation order.
    pub fn observed_at_ms(&self) -> i64 {
        match self {
            Self::Observation(record) => record.observed_at_ms,
            Self::InlinePayloadNotRetained(row) => row.observed_at_ms,
        }
    }

    /// The row's digest over the original observed bytes.
    pub fn evidence_digest(&self) -> &str {
        match self {
            Self::Observation(record) => &record.evidence_digest,
            Self::InlinePayloadNotRetained(row) => &row.evidence_digest,
        }
    }

    /// Canonical durable key of the row.
    pub fn record_key(&self) -> String {
        match self {
            Self::Observation(record) => record.canonical_record_key(),
            Self::InlinePayloadNotRetained(row) => row.record_key.clone(),
        }
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

    /// Lineage-bound validation against an [`EpochLineage`] gate (Implements #64, T6-E4-C).
    ///
    /// The `u64` contour is intentionally retained (donor precedent: no silent
    /// widening without a migration receipt). This check requires the
    /// snapshot's observed sequence to equal the lineage's current epoch AND,
    /// when the canonical JSON binds an `authority_epoch` lineage tuple, that
    /// tuple to agree exactly: equal sequences from different lineages are
    /// unrelated and fail as `FenceMismatch`. Legacy scalar fences without a
    /// bound lineage tuple keep the sequence-only check as a residual; callers
    /// holding a canonical [`EpochId`] must use [`Self::validate_against_epoch`]
    /// for exact-tuple `is_same_authority` enforcement at their own boundary.
    pub fn validate_against_lineage(&self, lineage: &EpochLineage) -> Result<(), OrsError> {
        self.validate()?;
        lineage.validate()?;
        if self.observed_authority_epoch != lineage.current.epoch {
            return Err(OrsError::FenceMismatch);
        }
        let (bound_lineage, bound_sequence) = self.fence_epoch_tuple()?;
        if let Some(bound_sequence) = bound_sequence
            && bound_sequence != self.observed_authority_epoch
        {
            return Err(OrsError::FenceMismatch);
        }
        if let Some(bound_lineage) = bound_lineage
            && bound_lineage != lineage.current.lineage_id.as_str()
        {
            return Err(OrsError::FenceMismatch);
        }
        Ok(())
    }

    /// Exact-tuple validation against a canonical [`EpochId`] (Implements #64, T6-E4-C).
    ///
    /// Requires `observed_authority_epoch == expected.sequence.get()` AND the
    /// canonical JSON's bound `authority_epoch.lineage_id` to equal
    /// `expected.lineage_id`: the `is_same_authority` spelling across the
    /// `u64` contour boundary. Legacy scalar fences without a bound lineage
    /// tuple fail closed here; use [`Self::validate_against_lineage`] only for
    /// the residual contour path.
    pub fn validate_against_epoch(&self, expected: &EpochId) -> Result<(), OrsError> {
        self.validate()?;
        if self.observed_authority_epoch != expected.sequence.get() {
            return Err(OrsError::FenceMismatch);
        }
        let (bound_lineage, bound_sequence) = self.fence_epoch_tuple()?;
        match (bound_lineage, bound_sequence) {
            (Some(lineage_id), Some(sequence))
                if lineage_id == expected.lineage_id.as_str()
                    && sequence == expected.sequence.get() => {}
            _ => return Err(OrsError::FenceMismatch),
        }
        Ok(())
    }

    /// Extracts the bound `(lineage_id, sequence)` tuple from the canonical
    /// fence JSON when it carries the migrated `EpochId` object shape.
    ///
    /// Returns `(None, None)` for legacy scalar fences
    /// (`{"authority_epoch": N}`) or fences without an `authority_epoch`
    /// member; those stay readable through [`Self::validate_against_lineage`]
    /// but never satisfy [`Self::validate_against_epoch`].
    fn fence_epoch_tuple(&self) -> Result<(Option<String>, Option<u64>), OrsError> {
        let parsed: Value = serde_json::from_str(&self.canonical_json)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        let Some(authority) = parsed.get("authority_epoch") else {
            return Ok((None, None));
        };
        if let Some(sequence) = authority.as_u64() {
            return Ok((None, Some(sequence)));
        }
        if let Some(object) = authority.as_object() {
            let lineage_id = object
                .get("lineage_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let sequence = object.get("sequence").and_then(Value::as_u64);
            return Ok((lineage_id, sequence));
        }
        Ok((None, None))
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
    /// Validates the explicit lineage edge (Implements #64, T6-E4-C).
    ///
    /// Same-lineage succession requires the exact direct-child step
    /// (`current.epoch == predecessor.epoch + 1`, overflow-closed via
    /// `checked_add`): a same-lineage jump of `+2` or more, a stall, or a
    /// backward step fails as `InvalidEpochLineage`. This mirrors the
    /// canonical `EpochId::is_direct_child_of` / `EpochTransition::validate`
    /// one-step rule without naming the canonical `EpochLineageId` contour
    /// (this contour keeps `OpaqueLabel` labels, so it cannot delegate
    /// directly). Cross-lineage predecessors stay allowed with no numeric
    /// ordering: restore / break-glass mints a new lineage whose predecessor
    /// names the fenced old tuple, and equal sequences across lineages stay
    /// unrelated.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.current.validate()?;
        if let Some(predecessor) = &self.predecessor {
            predecessor.validate()?;
        }
        if let Some(predecessor) = &self.predecessor
            && predecessor.lineage_id == self.current.lineage_id
        {
            let expected = predecessor
                .epoch
                .checked_add(1)
                .ok_or(OrsError::InvalidEpochLineage)?;
            if self.current.epoch != expected {
                return Err(OrsError::InvalidEpochLineage);
            }
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
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum RecoveryPayload {
    Encrypted {
        key: SecretReference,
        ciphertext: Vec<u8>,
    },
    ImmutableLocator {
        locator: PlatformHandle,
    },
    /// Exact versioned canonical bytes for one root-transition commit. ORS
    /// stores and hashes these bytes without interpreting their meaning.
    CanonicalRequest {
        contract_version: u16,
        bytes: Vec<u8>,
    },
}

/// Version of the opaque canonical request bytes accepted for a root transition.
pub const ROOT_TRANSITION_REQUEST_VERSION: u16 = 1;

/// Required privacy, visibility and taint metadata that travels with a
/// pending value (I5.2, I5.5, I5.6).
///
/// I5.2 requires that "original privacy, visibility, taint and retention travel
/// with the pending payload", I5.5 names `instruction_taint` beside
/// `privacy_class` on the write envelope, and I5.6 step 8 attaches "instruction
/// taint/origin/disclosure metadata" before staging. Taint therefore belongs to
/// the same carried access aggregate as privacy and visibility rather than to a
/// new top-level envelope key: I5.2's authoritative `RecoveryPayloadEnvelope`
/// field list admits no separate taint key, and ORS adds none.
///
/// `instruction_taint` is a closed scalar, never a set: the reduction from a
/// transition's per-source assurance is the admission owner's decision, made
/// before ORS is reached, so this struct records the admitted verdict and never
/// re-derives or downgrades it. `PrivacyClass` and `InstructionTaint` are
/// closed enums, so an unknown variant cannot be constructed or deserialized;
/// the field is required on the wire by `deny_unknown_fields`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAccessClass {
    /// Admitted privacy class of the pending payload (I5.5 `privacy_class`).
    pub privacy: PrivacyClass,
    /// Opaque visibility label; ORS records it without interpretation.
    pub visibility: VisibilityClass,
    /// Admitted instruction taint of the pending payload (I5.5
    /// `instruction_taint`, I5.6 `privacy_origin_taint_metadata`).
    pub instruction_taint: InstructionTaint,
}

impl RecoveryAccessClass {
    /// Validates the carried access metadata as one complete aggregate.
    ///
    /// Runs the same non-blank/non-control `validate_text` check over the
    /// wire label that [`RecoveryPayloadEnvelope::validate`] already runs over
    /// `secret_provider` and `immutable_locator`, so a re-read envelope cannot
    /// present a partially-validated access class. The two closed enums carry no
    /// invalid variant to reject; their soundness is closed at deserialization.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(
            self.visibility.as_str(),
            "privacy_and_visibility_class.visibility",
        )
    }
}

/// Admitted write identity retained beside its opaque recovery payload.
///
/// This binds the versioned write submission to the prepared transition and
/// the reservation without making ORS an interpreter of either value. The
/// operation identity is repeated deliberately: it is checked against the
/// envelope key and survives as part of the token and poll identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryWriteBinding {
    /// Version of the admitted `VersionedWriteSubmission` protocol.
    pub write_envelope_protocol_version: u32,
    /// Contract version of the exact staged recovery envelope.
    pub recovery_envelope_contract_version: u16,
    /// Privacy, visibility, and instruction-taint aggregate of that envelope.
    pub recovery_access_class: RecoveryAccessClass,
    /// Exact recovery-envelope retention timestamps retained after payload cleanup.
    pub payload_created_at_ms: i64,
    pub payload_known_at_ms: i64,
    pub payload_expires_at_ms: Option<i64>,
    /// Globally unique operation identity of this submitted transition.
    pub operation_id: OperationIdentity,
    /// Stable logical intent carried across correction/retry submissions.
    pub write_intent_id: OpaqueLabel,
    /// Retry identity from the admitted canonical write envelope.
    pub idempotency_key: OpaqueLabel,
    /// Canonical request digest computed by the canonical write-envelope owner.
    pub canonical_request_sha256: String,
    /// Digest of the exact admitted prepared transition.
    pub prepared_transition_sha256: String,
    /// Complete ordering-scope set declared by the prepared transition.
    pub ordering_scopes: Vec<OrderingScope>,
    /// Admitted contract-set digest.
    pub admission_contract_set_digest: String,
    /// Exact operation-manifest identity admitted for the transition.
    pub operation_manifest_digest: OpaqueLabel,
    /// Exact authority epoch admitted for the transition.
    pub authority_epoch: EpochLineage,
    /// Exact state fence admitted for the transition.
    pub state_fence: StateFenceSnapshot,
    /// Digest of the exact protected payload bytes staged in the envelope.
    pub protected_payload_sha256: String,
    /// Length of the exact protected payload bytes staged in the envelope.
    pub protected_payload_length: u64,
    /// Provider-owned key reference used to protect those exact bytes.
    pub payload_key_reference: SecretReference,
}

impl RecoveryWriteBinding {
    /// Validates the retained, provider-neutral write identity.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.write_envelope_protocol_version == 0 {
            return Err(OrsError::InvalidField {
                field: "write_envelope_protocol_version",
                reason: "must be greater than zero",
            });
        }
        if self.recovery_envelope_contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(
                self.recovery_envelope_contract_version,
            ));
        }
        self.recovery_access_class.validate()?;
        if self.payload_known_at_ms < self.payload_created_at_ms
            || self
                .payload_expires_at_ms
                .is_some_and(|expires| expires <= self.payload_created_at_ms)
        {
            return Err(OrsError::InvalidExpiry);
        }
        validate_digest(&self.canonical_request_sha256, "canonical_request_sha256")?;
        validate_digest(
            &self.prepared_transition_sha256,
            "prepared_transition_sha256",
        )?;
        validate_digest(
            &self.admission_contract_set_digest,
            "admission_contract_set_digest",
        )?;
        validate_text(
            self.operation_manifest_digest.as_str(),
            "operation_manifest_digest",
        )?;
        self.authority_epoch.validate()?;
        self.state_fence.validate()?;
        if self.state_fence.observed_authority_epoch != self.authority_epoch.current.epoch {
            return Err(OrsError::FenceMismatch);
        }
        validate_digest(&self.protected_payload_sha256, "protected_payload_sha256")?;
        if self.protected_payload_length == 0
            || self.protected_payload_length > MAX_INLINE_RECOVERY_BYTES
        {
            return Err(OrsError::InvalidField {
                field: "protected_payload_length",
                reason: "must be greater than zero and within the inline recovery bound",
            });
        }
        validate_text(
            self.payload_key_reference.provider.as_str(),
            "payload_key_reference.provider",
        )?;
        validate_text(
            self.payload_key_reference.key.as_str(),
            "payload_key_reference.key",
        )?;
        if self.ordering_scopes.is_empty() {
            return Err(OrsError::EmptyScopeSet);
        }
        let mut seen = BTreeSet::new();
        if self
            .ordering_scopes
            .iter()
            .any(|scope| !seen.insert(scope.as_str()))
        {
            return Err(OrsError::DuplicateScope);
        }
        Ok(())
    }

    /// Compares a retried submission to this retained canonical identity.
    pub(crate) fn same_retry_identity(&self, other: &Self) -> bool {
        self.write_envelope_protocol_version == other.write_envelope_protocol_version
            && self.recovery_envelope_contract_version == other.recovery_envelope_contract_version
            && self.recovery_access_class == other.recovery_access_class
            && self.payload_created_at_ms == other.payload_created_at_ms
            && self.payload_known_at_ms == other.payload_known_at_ms
            && self.payload_expires_at_ms == other.payload_expires_at_ms
            && self.operation_id == other.operation_id
            && self.write_intent_id == other.write_intent_id
            && self.idempotency_key == other.idempotency_key
            && self.canonical_request_sha256 == other.canonical_request_sha256
            && self.prepared_transition_sha256 == other.prepared_transition_sha256
            && self.ordering_scopes == other.ordering_scopes
            && self.admission_contract_set_digest == other.admission_contract_set_digest
            && self.operation_manifest_digest == other.operation_manifest_digest
            && self.authority_epoch == other.authority_epoch
            && self.state_fence == other.state_fence
            && self.protected_payload_sha256 == other.protected_payload_sha256
            && self.protected_payload_length == other.protected_payload_length
            && self.payload_key_reference == other.payload_key_reference
    }
}

/// Versioned opaque recovery envelope required at the ORS boundary (I5.2).
///
/// The I5.2 envelope fields retain contract version, operation/checkpoint
/// identity, privacy and visibility class, encrypted payload or immutable
/// locator, payload hash and length, authority epoch and state fence, and the
/// created/expiry times. Canonical write reservations additionally carry the
/// optional [`RecoveryWriteBinding`] that joins the versioned submission and
/// prepared transition to this payload. Other recovery envelopes leave it
/// absent. Authority epoch and state fence are bound to each other by
/// [`Self::validate`], so a staged envelope is never replayable under a foreign
/// epoch or fence.
///
/// Retention is carried by `expires_at_ms` alone. I5.2 requires that original
/// retention travel with the pending payload, and it names no distinct
/// retention class, type or field beyond `created_at_and_expires_at`; a separate
/// retention member would be an invented field, so none is added and
/// `expires_at_ms` remains the single cleanup horizon.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPayloadEnvelope {
    pub contract_version: u16,
    pub operation_or_checkpoint_id: OperationIdentity,
    pub privacy_and_visibility_class: RecoveryAccessClass,
    pub payload: RecoveryPayload,
    /// Admitted write identity when this envelope stages a canonical write.
    /// Missing on older retained records and non-write recovery envelopes.
    #[serde(default)]
    pub write_binding: Option<RecoveryWriteBinding>,
    pub payload_sha256: String,
    pub payload_length: u64,
    pub authority_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub created_at_ms: i64,
    pub known_at_ms: i64,
    pub expires_at_ms: Option<i64>,
}

/// Metadata shared by encrypted and immutable-locator recovery envelopes.
///
/// Mirrors [`RecoveryPayloadEnvelope`] minus the payload and its derived
/// digests, so the admitted access aggregate — privacy, visibility and
/// instruction taint — reaches both constructors unchanged and is validated
/// once, on the envelope it produces.
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
            write_binding: None,
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
            write_binding: None,
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

    /// Binds a canonical write identity to this exact recovery envelope.
    pub fn with_write_binding(
        mut self,
        write_binding: RecoveryWriteBinding,
    ) -> Result<Self, OrsError> {
        self.write_binding = Some(write_binding);
        self.validate()?;
        Ok(self)
    }

    /// Validates version, integrity bindings, carried access class, fence,
    /// epoch lineage, and time bounds.
    ///
    /// The access aggregate is checked as one unit so the admitted instruction
    /// taint travels under the same gate as privacy and visibility (I5.2,
    /// I5.5 `instruction_taint`, I5.6 `privacy_origin_taint_metadata`): an
    /// envelope is refused rather than staged with a partially-validated
    /// access class. `expires_at_ms` is checked as the retention horizon only
    /// (I5.2 "cleanup horizon"); no separate retention class exists to check.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        self.privacy_and_visibility_class.validate()?;
        if let Some(write_binding) = &self.write_binding {
            write_binding.validate()?;
            if write_binding.operation_id != self.operation_or_checkpoint_id
                || write_binding.recovery_envelope_contract_version != self.contract_version
                || write_binding.recovery_access_class != self.privacy_and_visibility_class
                || write_binding.payload_created_at_ms != self.created_at_ms
                || write_binding.payload_known_at_ms != self.known_at_ms
                || write_binding.payload_expires_at_ms != self.expires_at_ms
                || write_binding.authority_epoch != self.authority_epoch
                || write_binding.state_fence != self.state_fence
                || write_binding.protected_payload_sha256 != self.payload_sha256
                || write_binding.protected_payload_length != self.payload_length
                || !matches!(
                    &self.payload,
                    RecoveryPayload::Encrypted { key, .. }
                        if key == &write_binding.payload_key_reference
                )
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: "recovery_envelope",
                    reason: "write binding operation, epoch, fence, or protected payload differs from the envelope".to_owned(),
                });
            }
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
            RecoveryPayload::CanonicalRequest { .. } => {
                return Err(OrsError::InvalidField {
                    field: "recovery_payload",
                    reason: "canonical requests are only valid for root-transition commits",
                });
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

// Mechanical split: reservation data-contracts moved to `reservation_model.rs`
// (`model.rs:1524-1627`, parent `07a391d`). Data contracts only; no canonical
// authority or recovery logic — see `reservation_model.rs` header.

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

/// Independently revisioned sources in the Kernel startup recovery inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryInventorySource {
    Reservations,
    OperationalCurrent,
    RecoveryInbox,
    RecoveryProblems,
    WriteIdempotency,
}

/// Cross-source revision captured atomically before a bounded startup scan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryInventorySnapshot {
    pub reservation_revision: u64,
    pub operational_current_revision: u64,
    pub recovery_inbox_revision: u64,
    pub recovery_problem_revision: u64,
    pub write_idempotency_revision: u64,
    pub snapshot_sha256: String,
}

impl RecoveryInventorySnapshot {
    pub(crate) fn from_revisions(
        reservation_revision: u64,
        operational_current_revision: u64,
        recovery_inbox_revision: u64,
        recovery_problem_revision: u64,
        write_idempotency_revision: u64,
    ) -> Self {
        let mut snapshot = Self {
            reservation_revision,
            operational_current_revision,
            recovery_inbox_revision,
            recovery_problem_revision,
            write_idempotency_revision,
            snapshot_sha256: String::new(),
        };
        snapshot.snapshot_sha256 = snapshot.calculate_sha256();
        snapshot
    }

    /// Validates that the stable snapshot digest covers every source revision.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_digest(&self.snapshot_sha256, "recovery_inventory_snapshot_sha256")?;
        if self.snapshot_sha256 != self.calculate_sha256() {
            return Err(OrsError::IntegrityProblem {
                record_type: "recovery_inventory_snapshot",
                reason: "snapshot digest does not bind the declared source revisions".to_owned(),
            });
        }
        Ok(())
    }

    pub const fn revision_for(&self, source: RecoveryInventorySource) -> u64 {
        match source {
            RecoveryInventorySource::Reservations => self.reservation_revision,
            RecoveryInventorySource::OperationalCurrent => self.operational_current_revision,
            RecoveryInventorySource::RecoveryInbox => self.recovery_inbox_revision,
            RecoveryInventorySource::RecoveryProblems => self.recovery_problem_revision,
            RecoveryInventorySource::WriteIdempotency => self.write_idempotency_revision,
        }
    }

    fn calculate_sha256(&self) -> String {
        sha256_hex(
            format!(
                "eliot.ors.recovery-inventory.v1\nreservations={}\noperational_current={}\nrecovery_inbox={}\nrecovery_problems={}\nwrite_idempotency={}",
                self.reservation_revision,
                self.operational_current_revision,
                self.recovery_inbox_revision,
                self.recovery_problem_revision,
                self.write_idempotency_revision,
            )
            .as_bytes(),
        )
    }
}

macro_rules! define_key_scan_cursor {
    ($name:ident, $source:expr, $after:ty, $revision_field:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        pub struct $name {
            pub(crate) source: RecoveryInventorySource,
            pub(crate) after: Option<$after>,
            pub(crate) source_revision: u64,
            pub(crate) snapshot: RecoveryInventorySnapshot,
            pub(crate) limit: u16,
        }

        impl $name {
            pub fn start(
                snapshot: RecoveryInventorySnapshot,
                limit: u16,
            ) -> Result<Self, OrsError> {
                let value = Self {
                    source: $source,
                    after: None,
                    source_revision: snapshot.$revision_field,
                    snapshot,
                    limit,
                };
                value.validate()?;
                Ok(value)
            }

            pub(crate) fn continue_after(&self, after: $after) -> Self {
                Self {
                    source: $source,
                    after: Some(after),
                    source_revision: self.source_revision,
                    snapshot: self.snapshot.clone(),
                    limit: self.limit,
                }
            }

            pub(crate) fn validate(&self) -> Result<(), OrsError> {
                self.snapshot.validate()?;
                if self.source != $source || self.source_revision != self.snapshot.$revision_field {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "recovery_inventory_cursor",
                        reason: "typed source or source revision differs from its snapshot"
                            .to_owned(),
                    });
                }
                if self.limit == 0 || self.limit > MAX_RECOVERY_PAGE {
                    return Err(OrsError::InvalidCursorLimit);
                }
                Ok(())
            }
        }
    };
}

define_key_scan_cursor!(
    OperationalCurrentRecoveryCursor,
    RecoveryInventorySource::OperationalCurrent,
    OpaqueLabel,
    operational_current_revision
);
define_key_scan_cursor!(
    RecoveryInboxRecoveryCursor,
    RecoveryInventorySource::RecoveryInbox,
    OpaqueLabel,
    recovery_inbox_revision
);
define_key_scan_cursor!(
    RecoveryProblemRecoveryCursor,
    RecoveryInventorySource::RecoveryProblems,
    OpaqueLabel,
    recovery_problem_revision
);
define_key_scan_cursor!(
    WriteIdempotencyRecoveryCursor,
    RecoveryInventorySource::WriteIdempotency,
    OpaqueLabel,
    write_idempotency_revision
);

/// Bounded phases that cover the primary reservation table and every
/// reservation identity index without treating an index as the denominator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WriteReservationRecoveryPhase {
    Reservations,
    ReservationOrders,
    Operations,
}

/// Typed continuation across the primary reservation rows and their durable
/// order/operation indexes. `after` is exclusive within the selected phase.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WriteReservationRecoveryCursor {
    pub(crate) source: RecoveryInventorySource,
    pub(crate) phase: WriteReservationRecoveryPhase,
    pub(crate) after: Option<OpaqueLabel>,
    pub(crate) source_revision: u64,
    pub(crate) snapshot: RecoveryInventorySnapshot,
    pub(crate) limit: u16,
}

impl WriteReservationRecoveryCursor {
    pub fn start(snapshot: RecoveryInventorySnapshot, limit: u16) -> Result<Self, OrsError> {
        let value = Self {
            source: RecoveryInventorySource::Reservations,
            phase: WriteReservationRecoveryPhase::Reservations,
            after: None,
            source_revision: snapshot.reservation_revision,
            snapshot,
            limit,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn continue_after(&self, after: OpaqueLabel) -> Self {
        Self {
            source: self.source,
            phase: self.phase,
            after: Some(after),
            source_revision: self.source_revision,
            snapshot: self.snapshot.clone(),
            limit: self.limit,
        }
    }

    pub(crate) fn continue_in_phase(&self, phase: WriteReservationRecoveryPhase) -> Self {
        Self {
            source: self.source,
            phase,
            after: None,
            source_revision: self.source_revision,
            snapshot: self.snapshot.clone(),
            limit: self.limit,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        self.snapshot.validate()?;
        if self.source != RecoveryInventorySource::Reservations
            || self.source_revision != self.snapshot.reservation_revision
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "recovery_inventory_cursor",
                reason: "typed reservation source or revision differs from its snapshot".to_owned(),
            });
        }
        if self.limit == 0 || self.limit > MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        Ok(())
    }
}

/// Safe, payload-free summary of one operational-current obligation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalCurrentRecoveryEntry {
    pub storage_key: OpaqueLabel,
    pub kind: OpaqueLabel,
    pub record_id: OperationIdentity,
    pub subject_id: OperationIdentity,
    pub phase: OperationalPhase,
    pub operation_order: u64,
    pub authority_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub payload_sha256: String,
    pub payload_length: u64,
    pub created_at_ms: i64,
    pub cleanup_after_ms: Option<i64>,
    pub record_sha256: String,
}

/// Safe, payload-free summary of one imported recovery-inbox obligation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryInboxRecoveryEntry {
    pub item_id: OperationIdentity,
    pub operation_id: OperationIdentity,
    pub signer_id: OpaqueLabel,
    pub disposition: RecoveryInboxDisposition,
    pub operation_order: u64,
    pub contract_version: u16,
    pub privacy_and_visibility_class: RecoveryAccessClass,
    pub payload_sha256: String,
    pub payload_length: u64,
    pub authority_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub created_at_ms: i64,
    pub known_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub envelope_sha256: String,
    pub signature_sha256: String,
    pub record_sha256: String,
}

/// Verified durable idempotency index entry, including terminal operations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteIdempotencyRecoveryEntry {
    pub idempotency_key_sha256: String,
    pub operation_id: OperationIdentity,
    pub reservation_id: OperationIdentity,
    pub write_binding: RecoveryWriteBinding,
}

macro_rules! define_recovery_inventory_page {
    ($name:ident, $cursor:ident, $record:ty) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        pub struct $name {
            pub source_revision: u64,
            pub snapshot_sha256: String,
            pub records: Vec<$record>,
            pub next_cursor: Option<$cursor>,
            pub complete: bool,
        }
    };
}

define_recovery_inventory_page!(
    WriteReservationRecoveryPage,
    WriteReservationRecoveryCursor,
    ReservationRecord
);
define_recovery_inventory_page!(
    OperationalCurrentRecoveryPage,
    OperationalCurrentRecoveryCursor,
    OperationalCurrentRecoveryEntry
);
define_recovery_inventory_page!(
    RecoveryInboxRecoveryPage,
    RecoveryInboxRecoveryCursor,
    RecoveryInboxRecoveryEntry
);
define_recovery_inventory_page!(
    RecoveryProblemRecoveryPage,
    RecoveryProblemRecoveryCursor,
    RecoveryProblem
);
define_recovery_inventory_page!(
    WriteIdempotencyRecoveryPage,
    WriteIdempotencyRecoveryCursor,
    WriteIdempotencyRecoveryEntry
);

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

    fn canonical_request(
        context: OperationalRecordContext,
        bytes: Vec<u8>,
        payload_sha256: String,
    ) -> Result<Self, OrsError> {
        let payload_length = u64::try_from(bytes.len()).map_err(|_| OrsError::PayloadTooLarge)?;
        let value = Self {
            record_id: context.record_id,
            subject_id: context.subject_id,
            authority_epoch: context.authority_epoch,
            state_fence: context.state_fence,
            payload: RecoveryPayload::CanonicalRequest {
                contract_version: ROOT_TRANSITION_REQUEST_VERSION,
                bytes,
            },
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
            RecoveryPayload::CanonicalRequest {
                contract_version,
                bytes,
            } => {
                if *contract_version != ROOT_TRANSITION_REQUEST_VERSION {
                    return Err(OrsError::UnsupportedContractVersion(*contract_version));
                }
                let length = u64::try_from(bytes.len()).map_err(|_| OrsError::PayloadTooLarge)?;
                if length > crate::MAX_INLINE_RECOVERY_BYTES {
                    return Err(OrsError::PayloadTooLarge);
                }
                if length != self.payload_length || sha256_hex(bytes) != self.payload_sha256 {
                    return Err(OrsError::PayloadIntegrityMismatch);
                }
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

/// Immutable canonical root-transition request bytes presented by the
/// authenticated Kernel boundary. ORS checks their digest and identity
/// metadata, persists them opaquely, and grants no semantic authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RootTransitionCommit(OperationalRecordInput);

impl RootTransitionCommit {
    /// Validates and binds one exact canonical request to its operation and
    /// transition identities, authority epoch, and State Fence metadata.
    pub fn new(
        context: OperationalRecordContext,
        canonical_request_bytes: Vec<u8>,
        canonical_request_sha256: String,
    ) -> Result<Self, OrsError> {
        validate_digest(&canonical_request_sha256, "root_transition_request_sha256")?;
        let input = OperationalRecordInput::canonical_request(
            context,
            canonical_request_bytes,
            canonical_request_sha256,
        )?;
        Ok(Self(input))
    }

    pub(crate) fn from_record(record: OperationalRecordInput) -> Result<Self, OrsError> {
        let commit = Self(record);
        commit.validate()?;
        Ok(commit)
    }

    /// Returns the stable operation identity bound to this request.
    pub const fn operation_id(&self) -> &OperationIdentity {
        &self.0.record_id
    }

    /// Returns the transition identity supplied by the authenticated caller.
    pub const fn transition_id(&self) -> &OperationIdentity {
        &self.0.subject_id
    }

    /// Returns the exact opaque request bytes supplied to ORS.
    pub fn canonical_request_bytes(&self) -> Option<&[u8]> {
        match &self.0.payload {
            RecoveryPayload::CanonicalRequest { bytes, .. } => Some(bytes),
            RecoveryPayload::Encrypted { .. } | RecoveryPayload::ImmutableLocator { .. } => None,
        }
    }

    /// Returns the SHA-256 digest that ORS validated against the request bytes.
    pub fn canonical_request_sha256(&self) -> &str {
        &self.0.payload_sha256
    }

    /// Returns the exact metadata and opaque payload persisted for this commit.
    pub const fn record(&self) -> &OperationalRecordInput {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        self.0.validate()?;
        if !matches!(&self.0.payload, RecoveryPayload::CanonicalRequest { .. }) {
            return Err(OrsError::InvalidField {
                field: "root_transition_commit",
                reason: "must contain canonical request bytes",
            });
        }
        if self.0.cleanup_after_ms.is_some() {
            return Err(OrsError::InvalidField {
                field: "root_transition_cleanup_after_ms",
                reason: "committed root-transition results cannot expire",
            });
        }
        Ok(())
    }
}

/// Exact owner readback of one immutable root-transition commit. The store
/// receipt and ordering are operational evidence, not transition authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RootTransitionCommitProjection {
    commit: RootTransitionCommit,
    operation_order: u64,
    receipt: OperationalMutationReceipt,
}

impl RootTransitionCommitProjection {
    pub(crate) fn from_store(
        commit: RootTransitionCommit,
        operation_order: u64,
        receipt: OperationalMutationReceipt,
    ) -> Self {
        Self {
            commit,
            operation_order,
            receipt,
        }
    }

    /// Returns the exact canonical commit read back from the durable owner.
    pub const fn commit(&self) -> &RootTransitionCommit {
        &self.commit
    }

    /// Returns the monotonic ORS order assigned to the committed row.
    pub const fn operation_order(&self) -> u64 {
        self.operation_order
    }

    /// Returns the store-issued integrity receipt for the persisted row.
    pub const fn receipt(&self) -> &OperationalMutationReceipt {
        &self.receipt
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
                if matches!(&record.payload, RecoveryPayload::CanonicalRequest { .. }) {
                    return Err(OrsError::InvalidField {
                        field: "operational_payload",
                        reason: "canonical requests are reserved for root-transition commits",
                    });
                }
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
operational_input!(DaemonCutoverRecord);
operational_input!(ActiveSessionBinding);
operational_input!(SessionDetach);
operational_input!(UserBrokerRegistration);
operational_input!(UserBrokerFence);

/// Exact Kernel-issued native resource selection retained as User Broker
/// currentness evidence. The selection carries the candidate, operation,
/// resource, registration, epoch, fence, and consumer generation bindings;
/// the additional deadlines preserve the grant and its enclosing lease
/// ceilings without deriving them from a later caller echo. Currentness must
/// stop at the earliest of the selection, grant, launch lease, introduction,
/// or registration expiry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserBrokerResourceSelection {
    /// Exact typed selection that was issued by Kernel for one candidate.
    pub selection: NativeResourceSelection,
    /// Expiration of the containing Kernel launch grant.
    pub grant_expires_at: u64,
    /// Expiration of the admitted launch operation lease.
    pub launch_lease_expires_at: u64,
    /// Expiration of the capability introduction that names this resource.
    pub introduction_expires_at: u64,
    /// Expiration of the authenticated User Broker registration.
    pub registration_expires_at: u64,
}

impl UserBrokerResourceSelection {
    /// Creates validated, owner-issued selection evidence with its exact
    /// enclosing expiry limits.
    pub fn new(
        selection: NativeResourceSelection,
        grant_expires_at: u64,
        launch_lease_expires_at: u64,
        introduction_expires_at: u64,
        registration_expires_at: u64,
    ) -> Result<Self, OrsError> {
        let value = Self {
            selection,
            grant_expires_at,
            launch_lease_expires_at,
            introduction_expires_at,
            registration_expires_at,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates the nested selection and the exact grant/lease/registration
    /// expiry inequalities enforced by the User Broker launch boundary.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.selection
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        if self.grant_expires_at <= self.selection.issued_at
            || self.grant_expires_at > self.launch_lease_expires_at
            || self.grant_expires_at > self.introduction_expires_at
            || self.grant_expires_at > self.registration_expires_at
            || self.selection.expires_at < self.grant_expires_at
            || self.selection.expires_at > self.registration_expires_at
        {
            return Err(OrsError::InvalidField {
                field: "user_broker_resource_selection_expiry",
                reason: "selection, grant, registration, launch, and introduction deadlines are inconsistent",
            });
        }
        Ok(())
    }

    /// Returns the Broker-owned candidate identity for this exact selected
    /// resource. The resolver issues a fresh reference per retained selection.
    pub fn record_id(&self) -> Result<OperationIdentity, OrsError> {
        self.validate()?;
        OpaqueLabel::new(self.selection.candidate_ref.clone())
    }

    /// Returns the exact effect operation identity that owns this selected
    /// resource.
    pub fn subject_id(&self) -> Result<OperationIdentity, OrsError> {
        self.validate()?;
        OpaqueLabel::new(self.selection.operation_ref.clone())
    }
}

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
///
/// `Deserialize` (M2 integration adaptation, mirroring every neighboring
/// row type) is transport only; issuance stays store-owned.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

/// Read-only projection of one capability-grant row in ORS.
///
/// The record remains opaque to ORS. The phase, ordering, and store-issued
/// receipt are operational evidence only; this projection grants no
/// capability and does not interpret the payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityGrantProjection {
    record: OperationalRecordInput,
    phase: OperationalPhase,
    operation_order: u64,
    receipt: OperationalMutationReceipt,
}

impl CapabilityGrantProjection {
    pub(crate) fn from_store(
        record: OperationalRecordInput,
        phase: OperationalPhase,
        operation_order: u64,
        receipt: OperationalMutationReceipt,
    ) -> Self {
        Self {
            record,
            phase,
            operation_order,
            receipt,
        }
    }

    /// Returns the exact opaque operational input read from ORS.
    pub const fn record(&self) -> &OperationalRecordInput {
        &self.record
    }

    /// Returns the non-semantic ORS lifecycle phase.
    pub const fn phase(&self) -> OperationalPhase {
        self.phase
    }

    /// Returns the monotonic ORS order of this row.
    pub const fn operation_order(&self) -> u64 {
        self.operation_order
    }

    /// Returns the store-issued integrity receipt for this row.
    pub const fn receipt(&self) -> &OperationalMutationReceipt {
        &self.receipt
    }
}

/// Read-only ORS evidence for one capability-introduction row (issue #1110).
///
/// Introductions never reactivate: only an `Active` row carries usable
/// authority and only a `Fenced` row carries fence evidence. Any other phase
/// under this kind is an integrity problem, never a third lifecycle state.
///
/// `Deserialize` (M2 integration adaptation, mirroring every neighboring
/// row type) lets the admitted-cutover console envelope carry exact
/// owner-shaped readback rows; it grants no authority and changes no row
/// semantics.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct CapabilityIntroductionProjection {
    record: OperationalRecordInput,
    phase: OperationalPhase,
    operation_order: u64,
    receipt: OperationalMutationReceipt,
}

impl CapabilityIntroductionProjection {
    pub(crate) fn from_store(
        record: OperationalRecordInput,
        phase: OperationalPhase,
        operation_order: u64,
        receipt: OperationalMutationReceipt,
    ) -> Self {
        Self {
            record,
            phase,
            operation_order,
            receipt,
        }
    }

    /// Returns the exact opaque operational input read from ORS.
    pub const fn record(&self) -> &OperationalRecordInput {
        &self.record
    }

    /// Returns the non-semantic ORS lifecycle phase.
    pub const fn phase(&self) -> OperationalPhase {
        self.phase
    }

    /// Returns the monotonic ORS order of this row.
    pub const fn operation_order(&self) -> u64 {
        self.operation_order
    }

    /// Returns the store-issued integrity receipt for this row.
    pub const fn receipt(&self) -> &OperationalMutationReceipt {
        &self.receipt
    }
}

/// The authoritative receipt contract is defined in `eliot-receipts`; ORS
/// persists that exact versioned shape rather than defining a second wire
/// contract.
pub type GrantClosureCommit = GrantClosureReceipt;

/// Compatibility spelling for the authoritative alternate-path declaration.
pub type GrantClosurePreserved = GrantClosureAlternatePath;

/// Maps the authoritative closure state to ORS's non-semantic operational
/// phase without inventing a second lifecycle state.
pub(crate) const fn grant_closure_phase(state: GrantClosureState) -> OperationalPhase {
    match state {
        GrantClosureState::Active => OperationalPhase::Active,
        GrantClosureState::Revoked => OperationalPhase::Fenced,
    }
}

/// Validates the authoritative versioned closure receipt before it crosses the
/// ORS persistence boundary. The contract remains owned by `eliot-receipts`.
pub(crate) fn validate_grant_closure_contract(commit: &GrantClosureCommit) -> Result<(), OrsError> {
    commit
        .validate()
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    if let Some(receipt) = &commit.canonical_receipt {
        validate_grant_closure_canonical_receipt(receipt)?;
    }
    Ok(())
}

/// Validates one complete canonical second-phase receipt identity.
///
/// A pending first phase legitimately has no identity. Once an identity is
/// present, both the receipt id and its canonical digest must be complete and
/// bounded before ORS can persist or return the link.
pub(crate) fn validate_grant_closure_canonical_receipt(
    receipt: &ReceiptIdentity,
) -> Result<(), OrsError> {
    validate_text(
        receipt.receipt_id.as_str(),
        "grant_closure_canonical_receipt_id",
    )?;
    validate_digest(
        &receipt.canonical_sha256,
        "grant_closure_canonical_receipt_sha256",
    )
}

/// Validates an opaque ORS record against the exact authority/fence contour
/// carried by the authoritative closure receipt.
pub(crate) fn validate_grant_closure_input(
    authority: &AuthorityBinding,
    input: &OperationalRecordInput,
) -> Result<(), OrsError> {
    input.validate()?;
    authority
        .state_fence
        .validate()
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    if authority.state_fence.authority_epoch != authority.authority_epoch {
        return Err(OrsError::FenceMismatch);
    }
    let expected_fence = StateFenceSnapshot::capture(
        &authority.state_fence,
        authority.authority_epoch.sequence.get(),
    )?;
    if input.state_fence != expected_fence
        || input.authority_epoch.current.epoch != authority.authority_epoch.sequence.get()
        || input.authority_epoch.current.lineage_id.as_str()
            != authority.authority_epoch.lineage_id.as_str()
    {
        return Err(OrsError::FenceMismatch);
    }
    Ok(())
}

/// Read-only projection of one committed grant-closure row in ORS.
///
/// The commit bytes, phase, ordering, and store-issued receipt are
/// operational evidence only; this projection grants no capability and does
/// not interpret the closure. The second-phase receipt link is optional while
/// canonical reconciliation is pending.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GrantClosureProjection {
    commit: GrantClosureCommit,
    phase: OperationalPhase,
    operation_order: u64,
    receipt: GrantClosureCommitReceipt,
    second_phase: Option<ReceiptIdentity>,
}

impl GrantClosureProjection {
    pub(crate) fn from_store(
        commit: GrantClosureCommit,
        phase: OperationalPhase,
        operation_order: u64,
        receipt: GrantClosureCommitReceipt,
        second_phase: Option<ReceiptIdentity>,
    ) -> Self {
        Self {
            commit,
            phase,
            operation_order,
            receipt,
            second_phase,
        }
    }

    /// Returns the exact committed closure input read from ORS.
    pub const fn commit(&self) -> &GrantClosureCommit {
        &self.commit
    }

    /// Returns the non-semantic ORS lifecycle phase.
    pub const fn phase(&self) -> OperationalPhase {
        self.phase
    }

    /// Returns the monotonic ORS order of this row.
    pub const fn operation_order(&self) -> u64 {
        self.operation_order
    }

    /// Returns the store-issued integrity receipt for this row.
    pub const fn receipt(&self) -> &GrantClosureCommitReceipt {
        &self.receipt
    }

    /// Returns the durable canonical second-phase receipt link, if the
    /// immutable first-phase commit has already been linked.
    ///
    /// This is deliberately separate from [`Self::commit`]. The first-phase
    /// `GrantClosureCommit` bytes are never rewritten when this link is
    /// recorded.
    pub const fn second_phase(&self) -> Option<&ReceiptIdentity> {
        self.second_phase.as_ref()
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AdmissionReservationReceipt(OperationalMutationReceipt);

impl AdmissionReservationReceipt {
    pub fn receipt(&self) -> &OperationalMutationReceipt {
        &self.0
    }
}

operational_receipt!(GenerationTransitionReceipt);
operational_receipt!(GenerationCutoverReceipt);
operational_receipt!(SessionBindingReceipt);
operational_receipt!(UserBrokerRegistrationReceipt);
operational_receipt!(UserBrokerResourceSelectionReceipt);
operational_receipt!(AuthoritySnapshotReceipt);
operational_receipt!(AuthorityRevocationReceipt);
operational_receipt!(AuthorityActivationReceipt);
operational_receipt!(CapabilityIntroductionReceipt);
operational_receipt!(GrantClosureCommitReceipt);

/// One complete owner-presented revocation request for the atomic ORS fence.
///
/// The declaration and authority binding are the authoritative contract
/// values. The two record vectors are opaque ORS inputs supplied by Kernel;
/// ORS never derives semantic lineage or completeness from process memory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantClosureFenceRequest {
    /// Closed grant-closure schema identity.
    pub schema: String,
    /// Closed grant-closure schema version.
    pub version: u16,
    /// Closure operation identity.
    pub operation_id: String,
    /// Canonical digest of the complete idempotent closure request.
    pub idempotency_digest: String,
    /// Complete parent-before-child owner declaration at one graph revision.
    pub declaration: GrantClosureDeclaration,
    /// Exact authority owner, State Fence, Authority Epoch, and ceilings.
    pub authority: AuthorityBinding,
    /// Exact reference to the typed Kernel activation/revocation receipt.
    pub authority_receipt: GrantClosureAuthorityReceiptRef,
    /// Strongest proof interpretation recorded by the closure.
    pub proof_ceiling: ProofCeiling,
    /// Optional canonical store receipt linked after reconciliation.
    pub canonical_receipt: Option<ReceiptIdentity>,
    /// The atomic path is revocation-only; activation uses the simple row path.
    pub state: GrantClosureState,
    /// Introduction identities whose dependent fences are presented.
    pub fenced_introductions: Vec<OperationIdentity>,
    /// Exact capability-grant revocation records, one per declared member.
    pub grant_revocations: Vec<CapabilityGrantRevocation>,
    /// Exact capability-introduction fence records presented by Kernel.
    pub introduction_fences: Vec<CapabilityIntroductionFence>,
}

impl GrantClosureFenceRequest {
    /// Validates the authoritative declaration and the mechanical
    /// closure/request correspondence before ORS opens its write transaction.
    #[allow(
        clippy::too_many_lines,
        reason = "the request validator keeps the owner declaration, authority receipt, and every ORS transition mechanically aligned"
    )]
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.schema != GRANT_CLOSURE_SCHEMA || self.version != GRANT_CLOSURE_VERSION {
            return Err(OrsError::InvalidField {
                field: "grant_closure_schema",
                reason: "unsupported grant-closure request schema or version",
            });
        }
        validate_text(&self.operation_id, "grant_closure_operation_id")?;
        validate_digest(&self.idempotency_digest, "grant_closure_idempotency_digest")?;
        self.declaration
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        if self.state != GrantClosureState::Revoked {
            return Err(OrsError::InvalidField {
                field: "grant_closure_state",
                reason: "atomic fencing requires a Revoked closure",
            });
        }
        self.authority
            .state_fence
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        if self.authority.state_fence.authority_epoch != self.authority.authority_epoch {
            return Err(OrsError::FenceMismatch);
        }
        validate_text(
            self.authority.authority_owner.as_str(),
            "grant_closure_authority_owner",
        )?;
        if self.proof_ceiling > self.authority.proof_ceiling
            || self.proof_ceiling > self.declaration.proof_ceiling
        {
            return Err(OrsError::InvalidField {
                field: "grant_closure_proof_ceiling",
                reason: "closure proof ceiling exceeds its authority or declaration",
            });
        }
        validate_text(
            self.authority_receipt.receipt_id.as_str(),
            "grant_closure_authority_receipt_id",
        )?;
        validate_text(
            self.authority_receipt.snapshot_id.as_str(),
            "grant_closure_authority_snapshot_id",
        )?;
        if self.authority_receipt.authority_epoch != self.authority.authority_epoch
            || self.authority_receipt.state != self.state
            || self.authority_receipt.receipt_id != format!("revocation-{}", self.operation_id)
        {
            return Err(OrsError::FenceMismatch);
        }
        if let Some(receipt) = &self.canonical_receipt {
            validate_grant_closure_canonical_receipt(receipt)?;
        }

        let declared_members = self
            .declaration
            .members
            .iter()
            .map(|member| member.grant_id.as_str())
            .collect::<Vec<_>>();
        let declared_member_set = declared_members
            .iter()
            .map(|member| (*member).to_owned())
            .collect::<BTreeSet<_>>();
        let mut grant_subjects = BTreeSet::new();
        let mut grant_records = BTreeSet::new();
        for (revocation, declared_member) in self.grant_revocations.iter().zip(&declared_members) {
            let input = revocation.record();
            validate_grant_closure_input(&self.authority, input)?;
            let subject = input.subject_id.as_str();
            let record_id = input.record_id.as_str();
            if subject != *declared_member
                || !grant_subjects.insert(subject.to_owned())
                || !grant_records.insert(record_id.to_owned())
            {
                return Err(OrsError::InvalidField {
                    field: "grant_closure_revocations",
                    reason: "grant revocations must follow and exactly match the declaration",
                });
            }
        }
        if self.grant_revocations.len() != declared_members.len()
            || grant_subjects != declared_member_set
        {
            return Err(OrsError::InvalidField {
                field: "grant_closure_revocations",
                reason: "presented revocations must exactly match the declared closure members",
            });
        }

        if self
            .fenced_introductions
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(OrsError::InvalidField {
                field: "grant_closure_fenced_introductions",
                reason: "fenced introduction identities must be sorted and unique",
            });
        }
        let declared_introductions: BTreeSet<String> = self
            .fenced_introductions
            .iter()
            .map(|identity| identity.as_str().to_owned())
            .collect();
        let mut introduction_subjects = BTreeSet::new();
        let mut introduction_records = BTreeSet::new();
        let mut previous_subject: Option<&str> = None;
        for fence in &self.introduction_fences {
            let input = fence.record();
            validate_grant_closure_input(&self.authority, input)?;
            let subject = input.subject_id.as_str();
            let record_id = input.record_id.as_str();
            if previous_subject.is_some_and(|previous| previous >= subject) {
                return Err(OrsError::InvalidField {
                    field: "grant_closure_introduction_fences",
                    reason: "introduction fences must be sorted by subject",
                });
            }
            previous_subject = Some(subject);
            if !introduction_subjects.insert(subject.to_owned())
                || !introduction_records.insert(record_id.to_owned())
            {
                return Err(OrsError::InvalidField {
                    field: "grant_closure_introduction_fences",
                    reason: "introduction subject and ORS record identities must be unique",
                });
            }
        }
        if introduction_subjects != declared_introductions
            || introduction_records.len() != self.introduction_fences.len()
            || !grant_subjects.is_disjoint(&introduction_subjects)
            || !grant_records.is_disjoint(&introduction_records)
        {
            return Err(OrsError::InvalidField {
                field: "grant_closure_introduction_fences",
                reason: "presented fences must be disjoint and exactly match the declared introductions",
            });
        }
        let mut operation_ids = grant_records.clone();
        operation_ids.extend(introduction_records);
        if self
            .declaration
            .preserved
            .iter()
            .any(|alternate| operation_ids.contains(&alternate.operation_id))
        {
            return Err(OrsError::InvalidField {
                field: "grant_closure_preserved",
                reason: "alternate-path operation identity collides with a member operation",
            });
        }
        Ok(())
    }
}

/// Receipts returned by the single atomic closure-fence transaction.
///
/// The authoritative closure projection and every store-issued member
/// reference are returned from the committed transaction, so exact replay
/// returns the same values without another transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GrantClosureFenceReceipt {
    commit: GrantClosureCommit,
    closure_receipt: GrantClosureCommitReceipt,
    member_receipts: Vec<AuthorityRevocationReceipt>,
    introduction_receipts: Vec<CapabilityIntroductionReceipt>,
}

impl GrantClosureFenceReceipt {
    pub(crate) fn from_parts(
        commit: GrantClosureCommit,
        closure_receipt: GrantClosureCommitReceipt,
        member_receipts: Vec<AuthorityRevocationReceipt>,
        introduction_receipts: Vec<CapabilityIntroductionReceipt>,
    ) -> Self {
        Self {
            commit,
            closure_receipt,
            member_receipts,
            introduction_receipts,
        }
    }

    /// Returns the authoritative durable closure projection.
    pub const fn commit(&self) -> &GrantClosureCommit {
        &self.commit
    }

    /// Returns the ORS closure-row receipt.
    pub const fn closure_receipt(&self) -> &GrantClosureCommitReceipt {
        &self.closure_receipt
    }

    /// Returns the exact ORS member receipts in declaration order.
    pub fn member_receipts(&self) -> &[AuthorityRevocationReceipt] {
        &self.member_receipts
    }

    /// Returns the exact ORS introduction-fence receipts in declaration order.
    pub fn introduction_receipts(&self) -> &[CapabilityIntroductionReceipt] {
        &self.introduction_receipts
    }
}

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

/// Durable cause for one staged opaque operation that cannot be decoded or
/// trusted (issue #1925, I5.2/I5.6).
///
/// ORS owns neither keys nor locator contents, so it never attempts
/// decryption and never stores plaintext or ciphertext here: the problem
/// carries only integrity digests plus the epoch/fence/owner binding needed
/// to reconcile or dispose the staged operation by identity. A retained
/// problem is visible until an explicit canonical receipt or owner
/// disposition resolves it; silent deletion and plaintext fallback are
/// forbidden, and unresolved problems never expire automatically.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryProblemKind {
    HashMismatch,
    EnvelopeIntegrity,
    MissingKey,
    DecryptionFailure,
    /// A staged `PreparedTransition` the current Kernel/store bridge no
    /// longer supports, so it was refused rather than executed (issue #1927,
    /// I05-06).
    ///
    /// I05-06: a staged plan remains executable after daemon replacement only
    /// when the replacement Kernel/store bridge still supports the exact
    /// recorded contract/manifests; "otherwise it stays staged and enters
    /// visible recovery instead of being reinterpreted by newer code". This
    /// kind is that visible recovery: the refusal becomes a retained durable
    /// record keyed by the staged operation identity instead of a transient
    /// error string that leaves no trace once the reservation is released.
    /// It records no payload bytes, and the refused plan is never translated,
    /// widened or re-derived under the new code.
    UnsupportedPreparedTransition,
}

/// Visible durable Recovery Problem for one staged opaque operation.
///
/// The record is keyed by `operation_or_checkpoint_id` and reconciled by that
/// same identity into either the canonical receipt (via the reservation path)
/// or an explicit problem disposition. It carries no payload bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryProblem {
    pub contract_version: u16,
    pub operation_or_checkpoint_id: OperationIdentity,
    pub reservation_id: Option<OperationIdentity>,
    pub kind: RecoveryProblemKind,
    /// Bounded operator-visible cause. Never carries payload plaintext.
    pub detail: OpaqueLabel,
    pub envelope_sha256: Option<String>,
    pub payload_sha256: Option<String>,
    pub authority_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub recovery_owner: RecoveryOwner,
    pub created_at_ms: i64,
    pub terminal_receipt_id: Option<OpaqueLabel>,
}

impl RecoveryProblem {
    /// Binds a new unresolved problem to its authority epoch and state fence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_or_checkpoint_id: OperationIdentity,
        reservation_id: Option<OperationIdentity>,
        kind: RecoveryProblemKind,
        detail: OpaqueLabel,
        envelope_sha256: Option<String>,
        payload_sha256: Option<String>,
        authority_epoch: EpochLineage,
        state_fence: StateFenceSnapshot,
        recovery_owner: RecoveryOwner,
        created_at_ms: i64,
    ) -> Result<Self, OrsError> {
        let value = Self {
            contract_version: CONTRACT_VERSION,
            operation_or_checkpoint_id,
            reservation_id,
            kind,
            detail,
            envelope_sha256,
            payload_sha256,
            authority_epoch,
            state_fence,
            recovery_owner,
            created_at_ms,
            terminal_receipt_id: None,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns true once an explicit canonical receipt or owner disposition
    /// has closed the problem. Only resolved problems may be dispositioned;
    /// unresolved problems never expire automatically.
    pub const fn is_resolved(&self) -> bool {
        self.terminal_receipt_id.is_some()
    }

    /// Validates version, digest bindings, epoch/fence agreement, and the
    /// resolved marker. Never touches payload semantics.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        if let Some(digest) = &self.envelope_sha256 {
            validate_digest(digest, "recovery_problem_envelope_sha256")?;
        }
        if let Some(digest) = &self.payload_sha256 {
            validate_digest(digest, "recovery_problem_payload_sha256")?;
        }
        self.authority_epoch.validate()?;
        self.state_fence.validate()?;
        if self.state_fence.observed_authority_epoch != self.authority_epoch.current.epoch {
            return Err(OrsError::FenceMismatch);
        }
        Ok(())
    }
}

/// Durable-staging gate outcome for one `accept_after_stage` request
/// (issue #1925, I5.5/I5.6).
///
/// `ACCEPTED_PENDING` proves only that the complete opaque operation was
/// durably staged under the same operation identity: the envelope was
/// committed atomically with the Ordering Scope reservations, read back,
/// hash-validated, and enumerated by identity. It never implies canonical
/// commit or exactly-once external effect; the caller should poll/subscribe.
/// An exact duplicate is resolved to the original identity and never creates
/// another reservation or replaces the retained payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedPending {
    pub operation_id: OperationIdentity,
    pub reservation_id: OperationIdentity,
    pub reservation_order: u64,
    pub prepared_transition_sha256: String,
    /// Original admitted write identity used to poll and reconcile this stage.
    pub write_binding: RecoveryWriteBinding,
}

impl AcceptedPending {
    /// Validates the complete poll/reconciliation identity carried over the
    /// daemon wire. Call after deserialization before treating it as a handle.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.write_binding.validate()?;
        if self.reservation_order == 0
            || self.operation_id != self.write_binding.operation_id
            || self.prepared_transition_sha256 != self.write_binding.prepared_transition_sha256
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "accepted_pending",
                reason: "poll handle differs from its admitted write binding".to_owned(),
            });
        }
        Ok(())
    }
}

/// Original write identity returned when an idempotent retry finds terminal
/// ORS state. The Kernel uses this identity to query and authenticate the
/// original canonical receipt; it must not be surfaced as pending work.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlreadyTerminalWrite {
    /// Original operation identity used for receipt lookup.
    pub operation_id: OperationIdentity,
    /// Original durable ORS reservation identity.
    pub reservation_id: OperationIdentity,
    /// Receipt identity when retained terminal evidence names one. `None`
    /// represents terminal ORS state with unresolved receipt disposition.
    pub terminal_receipt_id: Option<OpaqueLabel>,
}

impl AcceptedPending {
    /// Response-mode label emitted alongside this outcome.
    pub const fn outcome_label() -> &'static str {
        "ACCEPTED_PENDING"
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

/// Maximum number of Kernel activation results retained by ORS.
pub const MAX_ACTIVATION_RESULT_RETENTION_RECORDS: usize = 64;
/// Maximum combined ticket/result payload size for one retained activation result.
pub const MAX_ACTIVATION_RESULT_PAYLOAD_BYTES: usize = 128 * 1024;
/// Maximum combined ticket/result payload size for the retention table.
pub const MAX_ACTIVATION_RESULT_TOTAL_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Mechanical phase of one retained Kernel activation result.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActivationResultRetentionPhase {
    /// The activation reached a terminal accepted/negative result.
    AcceptedTerminal,
    /// The activation was deferred because the named dependency was not ready.
    DeferredNotReady,
}

/// Opaque Kernel activation result retained by ORS for restart and exact replay.
///
/// ORS validates identity shape and bounds only. It does not deserialize either
/// payload, create a Session, or restore authority, transport, or connection
/// state. `connection_id` and `state_fence` are retained as opaque identity
/// evidence; they are never restored as live connection or authority state.
/// `retention_order` is assigned by the ORS write transaction when a new record
/// is retained; zero is therefore valid only before persistence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationResultRetentionRecord {
    pub ticket_id: String,
    pub ticket_sha256: String,
    pub ticket_payload: String,
    pub result_sha256: String,
    pub result_payload: String,
    pub connection_id: String,
    pub state_fence: String,
    pub phase: ActivationResultRetentionPhase,
    #[serde(default)]
    pub retention_order: u64,
}

impl ActivationResultRetentionRecord {
    /// Validates one incoming or persisted record without interpreting payloads.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.ticket_id, "activation_result_ticket_id")?;
        validate_digest(&self.ticket_sha256, "activation_result_ticket_sha256")?;
        validate_digest(&self.result_sha256, "activation_result_result_sha256")?;
        validate_text(&self.connection_id, "activation_result_connection_id")?;
        validate_text(&self.state_fence, "activation_result_state_fence")?;
        if self.payload_bytes() > MAX_ACTIVATION_RESULT_PAYLOAD_BYTES {
            return Err(OrsError::InvalidField {
                field: "activation_result_payload",
                reason: "ticket and result payloads exceed the per-record bound",
            });
        }
        Ok(())
    }

    /// Returns the exact durable key for this ticket.
    pub fn record_key(&self) -> &str {
        &self.ticket_id
    }

    /// Returns the payload bytes counted against retention bounds.
    pub fn payload_bytes(&self) -> usize {
        self.ticket_payload
            .len()
            .saturating_add(self.result_payload.len())
    }

    /// Compares the immutable ticket/result identity and payload binding.
    ///
    /// ORS order is progression assigned by the store, so it is deliberately
    /// excluded from exact-replay comparison.
    pub fn same_identity(&self, other: &Self) -> bool {
        self.ticket_id == other.ticket_id
            && self.ticket_sha256 == other.ticket_sha256
            && self.ticket_payload == other.ticket_payload
            && self.result_sha256 == other.result_sha256
            && self.result_payload == other.result_payload
            && self.connection_id == other.connection_id
            && self.state_fence == other.state_fence
            && self.phase == other.phase
    }
}

/// Maximum number of Kernel activation lifecycle rows retained by ORS.
pub const MAX_ACTIVATION_LIFECYCLE_RECORDS: usize = 64;
/// Maximum ticket payload retained for one activation lifecycle row.
pub const MAX_ACTIVATION_LIFECYCLE_PAYLOAD_BYTES: usize = 128 * 1024;

/// Durable mechanical lifecycle of one Kernel activation ticket.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActivationLifecycleState {
    /// Ticket is durably staged but no daemon claim is active.
    Pending,
    /// The authenticated daemon owns the bounded semantic-resolution claim.
    Claimed,
    /// An immutable `NotReady` result is retained and may later mint one
    /// successor ticket after its due time and dependency-revision gate.
    DeferredNotReady,
    /// An immutable terminal result is retained.
    ResultAccepted,
    /// The ticket was cancelled before any result-bearing claim.
    Cancelled,
    /// The Kernel deadline linearized before any result was accepted.
    Expired,
    /// Outcome or ownership is uncertain and must not be replayed blindly.
    Reconciling,
}

impl ActivationLifecycleState {
    /// Returns whether this state can never accept a new semantic result.
    #[must_use]
    pub const fn is_terminal_or_reconciling(self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::Expired | Self::Reconciling | Self::ResultAccepted
        )
    }
}

/// Immutable durable predecessor binding for one successor activation ticket.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationSuccessorBinding {
    pub predecessor_ticket_id: String,
    pub predecessor_ticket_sha256: String,
    pub predecessor_result_sha256: String,
    pub dependency_ref: String,
    pub observed_dependency_revision: String,
    pub not_before_unix_ms: u64,
}

impl ActivationSuccessorBinding {
    fn validate(&self) -> Result<(), OrsError> {
        validate_text(
            &self.predecessor_ticket_id,
            "activation_predecessor_ticket_id",
        )?;
        validate_digest(
            &self.predecessor_ticket_sha256,
            "activation_predecessor_ticket_sha256",
        )?;
        validate_digest(
            &self.predecessor_result_sha256,
            "activation_predecessor_result_sha256",
        )?;
        validate_text(&self.dependency_ref, "activation_dependency_ref")?;
        validate_text(
            &self.observed_dependency_revision,
            "activation_observed_dependency_revision",
        )?;
        if self.not_before_unix_ms == 0 {
            return Err(OrsError::InvalidField {
                field: "activation_not_before_unix_ms",
                reason: "successor due time must be greater than zero",
            });
        }
        Ok(())
    }
}

/// One durable Kernel activation ticket lifecycle and result binding.
///
/// ORS treats `ticket_payload` as opaque bytes and validates only bounded
/// identity shape. Kernel owns typed ticket/result semantics. A lifecycle row
/// is the sole terminal/reconciling fence: result retention alone never
/// cancels, expires, or completes a ticket.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationLifecycleRecord {
    pub ticket_id: String,
    pub ticket_sha256: String,
    pub ticket_payload: String,
    pub activation_request_id: String,
    pub activation_request_sha256: String,
    pub connection_id: String,
    pub state_fence: String,
    pub kernel_deadline_unix_ms: u64,
    pub cancellation_id: String,
    pub state: ActivationLifecycleState,
    #[serde(default)]
    pub lifecycle_order: u64,
    #[serde(default)]
    pub result_sha256: Option<String>,
    #[serde(default)]
    pub claim_owner: Option<String>,
    #[serde(default)]
    pub claim_expires_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub successor_of: Option<ActivationSuccessorBinding>,
    #[serde(default)]
    pub successor_ticket_id: Option<String>,
    #[serde(default)]
    pub terminal_reason: Option<String>,
}

impl ActivationLifecycleRecord {
    /// Validates one incoming or persisted activation lifecycle row.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.ticket_id, "activation_lifecycle_ticket_id")?;
        validate_digest(&self.ticket_sha256, "activation_lifecycle_ticket_sha256")?;
        if self.ticket_payload.len() > MAX_ACTIVATION_LIFECYCLE_PAYLOAD_BYTES {
            return Err(OrsError::InvalidField {
                field: "activation_lifecycle_ticket_payload",
                reason: "ticket payload exceeds the per-record bound",
            });
        }
        validate_text(
            &self.activation_request_id,
            "activation_lifecycle_request_id",
        )?;
        validate_digest(
            &self.activation_request_sha256,
            "activation_lifecycle_request_sha256",
        )?;
        validate_text(&self.connection_id, "activation_lifecycle_connection_id")?;
        validate_text(&self.state_fence, "activation_lifecycle_state_fence")?;
        if self.kernel_deadline_unix_ms == 0 {
            return Err(OrsError::InvalidField {
                field: "activation_lifecycle_deadline",
                reason: "deadline must be greater than zero",
            });
        }
        validate_text(
            &self.cancellation_id,
            "activation_lifecycle_cancellation_id",
        )?;
        if let Some(result_sha256) = &self.result_sha256 {
            validate_digest(result_sha256, "activation_lifecycle_result_sha256")?;
        }
        if let Some(claim_owner) = &self.claim_owner {
            validate_text(claim_owner, "activation_lifecycle_claim_owner")?;
        }
        if let Some(successor_of) = &self.successor_of {
            successor_of.validate()?;
        }
        if let Some(successor_ticket_id) = &self.successor_ticket_id {
            validate_text(successor_ticket_id, "activation_successor_ticket_id")?;
        }
        if let Some(reason) = &self.terminal_reason {
            validate_text(reason, "activation_lifecycle_terminal_reason")?;
        }
        let claim_fields_match =
            self.claim_owner.is_some() == self.claim_expires_at_unix_ms.is_some();
        if !claim_fields_match {
            return Err(OrsError::InvalidField {
                field: "activation_lifecycle_claim",
                reason: "claim owner and expiry must be present together",
            });
        }
        if self.state == ActivationLifecycleState::Claimed
            && (self.claim_owner.is_none() || self.result_sha256.is_some())
        {
            return Err(OrsError::InvalidField {
                field: "activation_lifecycle_claim",
                reason: "claimed state requires a claim owner and no result",
            });
        }
        if matches!(
            self.state,
            ActivationLifecycleState::DeferredNotReady | ActivationLifecycleState::ResultAccepted
        ) && self.result_sha256.is_none()
        {
            return Err(OrsError::InvalidField {
                field: "activation_lifecycle_result",
                reason: "result-bearing state requires the retained result digest",
            });
        }
        if matches!(
            self.state,
            ActivationLifecycleState::Pending
                | ActivationLifecycleState::Cancelled
                | ActivationLifecycleState::Expired
        ) && self.result_sha256.is_some()
        {
            return Err(OrsError::InvalidField {
                field: "activation_lifecycle_result",
                reason: "resultless state cannot retain a semantic result",
            });
        }
        if self.state != ActivationLifecycleState::Claimed && self.claim_owner.is_some() {
            return Err(OrsError::InvalidField {
                field: "activation_lifecycle_claim",
                reason: "only claimed state retains claim ownership",
            });
        }
        Ok(())
    }

    /// Returns the exact durable key for this ticket.
    pub fn record_key(&self) -> &str {
        &self.ticket_id
    }

    /// Compares immutable ticket/request/cancellation identity while ignoring
    /// mutable lifecycle state and ORS-assigned order.
    pub fn same_immutable_identity(&self, other: &Self) -> bool {
        self.ticket_id == other.ticket_id
            && self.ticket_sha256 == other.ticket_sha256
            && self.ticket_payload == other.ticket_payload
            && self.activation_request_id == other.activation_request_id
            && self.activation_request_sha256 == other.activation_request_sha256
            && self.connection_id == other.connection_id
            && self.state_fence == other.state_fence
            && self.kernel_deadline_unix_ms == other.kernel_deadline_unix_ms
            && self.cancellation_id == other.cancellation_id
            && self.successor_of == other.successor_of
    }
}

/// Coherent one-read activation recovery projection from ORS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationRecoverySnapshot {
    pub lifecycles: Vec<ActivationLifecycleRecord>,
    pub results: Vec<ActivationResultRetentionRecord>,
}

/// Typed ORS failures. None grants semantic or completion authority.
#[derive(Debug, Error)]
pub enum OrsError {
    #[error("bridge event capacity exhausted: {0:?}")]
    BridgeEventCapacityExceeded(BridgeEventCapacityPressure),
    #[error("bridge recovery window capacity exhausted")]
    BridgeRecoveryWindowCapacityExceeded,
    #[error("bridge recovery cut capacity exhausted")]
    BridgeRecoveryCutCapacityExceeded,
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("foundation contract rejected ORS input: {0}")]
    Contract(String),
    #[error("Store contract rejected ORS input: {0}")]
    StoreContract(#[from] Box<eliot_store_api::StoreError>),
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
    #[error(
        "recovery inventory source {inventory_source:?} moved from revision {expected_revision} to {observed_revision}"
    )]
    RecoverySnapshotMoved {
        inventory_source: RecoveryInventorySource,
        expected_revision: u64,
        observed_revision: u64,
    },
    #[error("duplicate identity conflicts with durable ORS state")]
    DuplicateConflict,
    #[error("idempotent write already has terminal ORS state")]
    AlreadyTerminalWrite(AlreadyTerminalWrite),
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
    /// A `HostRequest` exhausted its original send attempt and its one
    /// proven-not-sent same-identity retry; its existing claim remains retained.
    #[error("HostRequest send-attempt bound is exhausted; reconcile the retained operation")]
    HostRequestAttemptLimitExceeded,
    /// A durable send claim expired before transport dispatch. The exact
    /// operation remains in reconciliation and is never reissued by expiry.
    #[error("HostRequest send claim expired before transport dispatch")]
    HostRequestAttemptExpired,
    /// The process-stream recovery family moved while a backup continuation
    /// held it frozen (issue #2884).
    ///
    /// This is the movement/restart disposition, never a truncation: a family
    /// row was inserted, advanced or retired after the backup froze the family,
    /// so the pages already emitted and the pages still owed can no longer be
    /// one snapshot. The disposition is to restart the family export from a
    /// freshly opened family snapshot; the exact frozen and observed revisions,
    /// both content roots and the last emitted key are carried so the operator
    /// sees which window moved. It never grants authority and never retires
    /// anything.
    #[error(
        "process-stream recovery family moved under the frozen backup snapshot: revision {observed_revision} root {observed_root_digest} observed, revision {frozen_revision} root {frozen_root_digest} frozen, after key {after_key:?}; restart the family export from a freshly opened family snapshot"
    )]
    ProcessStreamRecoveryFamilyMoved {
        /// Durable family revision the backup froze.
        frozen_revision: u64,
        /// Durable family revision observed when the page was read.
        observed_revision: u64,
        /// Streamed family content root the backup froze.
        frozen_root_digest: String,
        /// Streamed family content root observed when the page was read.
        observed_root_digest: String,
        /// Last durable key the backup had already emitted.
        after_key: String,
    },
    /// A presented process-stream recovery family cursor does not name the
    /// durable-key prefix the owner already emitted (issue #2884).
    ///
    /// The boundary is re-derived from durable state, so a caller cannot choose
    /// which family rows a page covers: presenting a different key or a
    /// different offset than the owner's own prefix is refused here instead of
    /// letting a row leave the denominator silently.
    #[error(
        "process-stream recovery family cursor does not name the owner-emitted prefix: presented key {presented_after_key:?} at row {presented_emitted_rows}, durable key {expected_after_key:?} at row {expected_emitted_rows}"
    )]
    ProcessStreamRecoveryFamilyCursorMismatch {
        /// Key the caller presented as the boundary.
        presented_after_key: String,
        /// Emitted row count the caller presented.
        presented_emitted_rows: u64,
        /// Key durable state actually holds at that offset.
        expected_after_key: String,
        /// Emitted row count durable state actually holds.
        expected_emitted_rows: u64,
    },
    #[error("supervision-lease revision is stale or does not match the current ORS head")]
    SupervisionLeaseStaleRevision,
    #[error("supervision-lease ticket or commit artifact conflicts with durable ORS state")]
    SupervisionLeaseTicketConflict,
    #[error("supervision-lease commit artifact does not bind the staged ticket exactly")]
    SupervisionLeaseBindingMismatch,
    #[error("supervision-lease ticket is neither staged nor durably committed")]
    SupervisionLeaseTicketNotStaged,
    #[error("supervision-lease ticket was durably resolved without a lease commit")]
    SupervisionLeaseTicketResolved,
    #[error("supervision-lease ticket is not yet eligible for durable expiry")]
    SupervisionLeaseTicketNotExpired,
    #[error("supervision-lease ticket validity window elapsed before staging")]
    SupervisionLeaseTicketExpired,
    #[error("supervision-lease ticket is already durably committed")]
    SupervisionLeaseTicketAlreadyCommitted,
    #[error("supervision-lease history limit must be between 1 and {MAX_RECOVERY_PAGE}")]
    InvalidSupervisionLeaseHistoryLimit,
    #[error("durable ORS schema migration required: {reason}")]
    MigrationRequired { reason: String },
    #[error("durable ORS integrity problem in {record_type}: {reason}")]
    IntegrityProblem {
        record_type: &'static str,
        reason: String,
    },
    #[error(
        "host request {operation_id} with digest {request_digest} conflicts with durable ORS state: IDENTITY_CONFLICT"
    )]
    HostRequestIdentityConflict {
        operation_id: String,
        request_digest: String,
    },
    #[error("legacy host-request correlation cannot be resolved to a typed identity")]
    HostRequestLegacyCorrelationUnresolved,
    #[error("content-addressed campaign view {view_id} conflicts with retained ORS bytes")]
    CampaignLearningStateViewConflict { view_id: String },
    #[error("campaign source publication for {key} conflicts with its current owner head")]
    CampaignSourcePublicationConflict { key: String },
    #[error(
        "activation result ticket {ticket_id} conflicts with durable ORS state: IDENTITY_CONFLICT"
    )]
    ActivationResultRetentionIdentityConflict { ticket_id: String },
    #[error(
        "activation lifecycle ticket {ticket_id} conflicts with durable ORS state: IDENTITY_CONFLICT"
    )]
    ActivationLifecycleIdentityConflict { ticket_id: String },
    #[error("activation ticket {ticket_id} expired before result admission")]
    ActivationLifecycleExpired { ticket_id: String },
    #[error("activation ticket {ticket_id} is in durable state {state:?}, not {expected:?}")]
    ActivationLifecycleStateConflict {
        ticket_id: String,
        state: ActivationLifecycleState,
        expected: ActivationLifecycleState,
    },
    #[error("native-worker claim {claim_id} conflicts with durable ORS state: IDENTITY_CONFLICT")]
    NativeWorkerClaimIdentityConflict { claim_id: String },
    #[error(
        "worker replay stream {stream_id} request {request_id} conflicts with durable ORS state: IDENTITY_CONFLICT"
    )]
    WorkerReplayIdentityConflict {
        stream_id: String,
        request_id: String,
    },
    #[error(
        "worker replay stream {stream_id} has no bound claim or a stale generation/epoch/fence"
    )]
    WorkerReplayStaleStream { stream_id: String },
    #[error(
        "worker replay acknowledgement does not bind its durable event on stream {stream_id} at sequence {sequence}"
    )]
    WorkerReplayAckMismatch { stream_id: String, sequence: u64 },
    #[error(
        "worker replay suffix on stream {stream_id} is incomplete after sequence {after_sequence}"
    )]
    WorkerReplayIncomplete {
        stream_id: String,
        after_sequence: u64,
    },
    #[error("versioned artifact conflicts with durable generation state")]
    VersionedArtifactConflict,
    #[error("in-place replacement of an active executable is rejected")]
    ActiveExecutableReplacement,
    #[error("versioned artifact generation was not found")]
    VersionedArtifactNotFound,
    #[error("generation must drain before it can retire")]
    VersionedArtifactNotDrained,
    #[error("candidate artifact is incompatible with durable formats or epoch lineage")]
    IncompatibleArtifact,
    #[error("durable ORS storage failed: {0}")]
    Storage(String),
    #[error("durable ORS encoding failed: {0}")]
    Encoding(String),
    #[error("opaque operation could not be durably staged, ACCEPTED_PENDING is forbidden: {0}")]
    StagingNotDurable(String),
    #[error(
        "redb commit outcome is unresolved for operation {operation_id:?} and reservation {reservation_id:?}; commit error: {commit_error}; readback error: {readback_error:?}"
    )]
    StagingCommitOutcomeUnknown {
        operation_id: OperationIdentity,
        reservation_id: OperationIdentity,
        commit_error: Box<OrsError>,
        readback_error: Option<Box<OrsError>>,
    },
    #[error(
        "Recovery Problem could not be persisted for operation {operation_id:?} and reservation {reservation_id:?}; original cause: {original}; recorder failure: {recorder}"
    )]
    RecoveryProblemRecordFailed {
        operation_id: OperationIdentity,
        reservation_id: OperationIdentity,
        original: Box<OrsError>,
        recorder: Box<OrsError>,
    },
    #[error(
        "staged opaque payload for operation {operation_id} failed validation; a durable Recovery Problem is retained for disposition, plaintext fallback and silent deletion are forbidden"
    )]
    RecoveryProblemRetained { operation_id: String },
}

impl From<eliot_store_api::StoreError> for OrsError {
    fn from(source: eliot_store_api::StoreError) -> Self {
        Self::StoreContract(Box::new(source))
    }
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
    /// Monotonic ORS order assigned atomically when this operation becomes
    /// committed.  Zero is retained for legacy records written before the
    /// ordering field existed; new committed records are assigned a non-zero
    /// value by `RedbRecoveryStore::persist_store_rebind`.
    #[serde(default)]
    pub commit_order: u64,
}

impl StoreRebindReplayRecord {
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(self.operation_id.as_str(), "store_rebind_operation_id")?;
        validate_digest(&self.request_digest, "store_rebind_request_digest")?;
        validate_digest(
            &self.candidate_binding_digest,
            "store_rebind_candidate_digest",
        )?;
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
            if receipt != &self.request_digest {
                return Err(OrsError::InvalidField {
                    field: "store_rebind_receipt",
                    reason: "committed receipt must bind the exact request digest",
                });
            }
        } else if self.state == StoreRebindReplayState::Committed {
            return Err(OrsError::InvalidField {
                field: "store_rebind_receipt",
                reason: "committed requires receipt",
            });
        }
        if self.state == StoreRebindReplayState::Pending && self.commit_order != 0 {
            return Err(OrsError::InvalidField {
                field: "store_rebind_commit_order",
                reason: "pending must not carry a commit order",
            });
        }
        Ok(())
    }
}

/// Durable retention of one closed typed Store failure bound to the exact
/// admitted Store operation it reports on.
///
/// ORS preserves the owner `eliot_store_api::StoreFailure` envelope
/// opaquely: the envelope is validated by the owner contract, pinned to the
/// exact operation/request/fence/binding identity, and returned verbatim on
/// readback. ORS never interprets disposition, retry, recovery, or
/// human-detail prose for control decisions, and never re-derives retry or
/// terminality from provider text: the retained typed envelope alone carries
/// control meaning.
///
/// A retained `UNKNOWN_OUTCOME` failure with no reconciling receipt is the
/// reconciling state: it is neither committed nor terminal, it is never
/// reported as unavailable, failed, absent, or safe-to-retry, and only
/// `crate::RedbRecoveryStore::mark_store_failure_reconciled` may bind the
/// exact reconciling receipt afterwards. Terminal dispositions are retained
/// as terminal evidence and can never become reconciled.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreFailureRetentionRecord {
    pub operation_id: OperationIdentity,
    pub request_digest: String,
    pub store_fence: String,
    pub candidate_binding_digest: String,
    pub requirement_digest: String,
    pub failure: eliot_store_api::StoreFailure,
    /// Digest of the reconciling `WriteReceipt` bound after the exact
    /// retained operation was reconciled following a possible
    /// commit/effect. `None` while the retained failure is unresolved.
    pub reconciled_receipt: Option<String>,
}

impl StoreFailureRetentionRecord {
    /// Returns the durable key binding one operation to one exact request.
    pub fn record_key(&self) -> String {
        format!("{}::{}", self.operation_id.as_str(), self.request_digest)
    }

    /// Returns whether two records carry the exact same admitted binding.
    ///
    /// The retained failure envelope and the reconciling receipt are
    /// excluded: they are retained Store evidence and ORS-owned
    /// reconciliation progression, not caller binding.
    pub fn same_binding(&self, other: &Self) -> bool {
        self.operation_id == other.operation_id
            && self.request_digest == other.request_digest
            && self.store_fence == other.store_fence
            && self.candidate_binding_digest == other.candidate_binding_digest
            && self.requirement_digest == other.requirement_digest
    }

    /// Validates shape, owner envelope, and identity binding without
    /// interpreting Store semantic policy.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(self.operation_id.as_str(), "store_failure_operation_id")?;
        validate_digest(&self.request_digest, "store_failure_request_digest")?;
        validate_digest(&self.store_fence, "store_failure_store_fence")?;
        validate_digest(
            &self.candidate_binding_digest,
            "store_failure_candidate_digest",
        )?;
        validate_digest(&self.requirement_digest, "store_failure_requirement_digest")?;
        // The owner contract alone decides envelope validity. Owner prose
        // is never propagated: ORS reports a fixed field/reason pair so
        // provider text cannot change control meaning.
        self.failure
            .validate()
            .map_err(|_| OrsError::InvalidField {
                field: "store_failure_envelope",
                reason: "owner contract rejected the retained Store failure",
            })?;
        // The retained disposition must report on this exact operation. A
        // failure carrying another operation identity is a binding
        // mismatch, never a candidate for quiet adoption.
        if let Some(operation_id) = self.failure.operation_id.as_ref()
            && operation_id.as_str() != self.operation_id.as_str()
        {
            return Err(OrsError::InvalidField {
                field: "store_failure_operation_id",
                reason: "retained failure must bind the exact retained operation",
            });
        }
        if let Some(receipt) = &self.reconciled_receipt {
            validate_digest(receipt, "store_failure_reconciled_receipt")?;
            // Only a possible commit/effect reconciles: terminal
            // dispositions are retained as terminal evidence and can never
            // become reconciled.
            if self.failure.disposition != eliot_store_api::StoreFailureDisposition::UnknownOutcome
            {
                return Err(OrsError::InvalidField {
                    field: "store_failure_reconciled_receipt",
                    reason: "only unknown-outcome retention reconciles",
                });
            }
        }
        Ok(())
    }
}

/// Terminal outcome of one Kernel-owned unknown-commit recovery record.
///
/// The outcome names what evidence proved, never a retry policy: a resolved
/// record is immutable terminal evidence. `RolledBack` covers every terminal
/// non-committed receipt (rejected, cancelled) whose digest is bound as
/// evidence; `DeadLetter` and `NewIdentityRequired` keep their distinct
/// Store-reported meanings so no caller can mistake them for a safe
/// same-identity retry.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownCommitOutcome {
    Committed,
    RolledBack,
    DeadLetter,
    NewIdentityRequired,
}

/// Durable Kernel-owned unknown-commit recovery record (I14.21, issue #1690).
///
/// The Kernel stages one record per canonical write attempt keyed by the
/// admitted operation idempotency key before the commit send, and resolves
/// it exactly once when receipt evidence arrives. While a record is open,
/// its ordering scopes are paused: no dependent mutation in those scopes is
/// admitted until an evidence-backed disposition resolves it. ORS stores the
/// record verbatim and never interprets commit, retry, or problem semantics.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownCommitRecord {
    /// Durable write-attempt identity: the admitted idempotency key.
    pub idempotency_key: String,
    /// Exact admitted operation identity bound to the attempt.
    pub operation_id: OperationIdentity,
    /// Digest of the exact canonical request bytes admitted for the attempt.
    pub canonical_request_hash: String,
    /// Ordering scopes paused while this record is open. Empty only for
    /// scopeless commits (genesis); a scoped commit always names its scopes.
    pub ordering_scopes: Vec<String>,
    /// `None` while the commit outcome is unknown; the terminal outcome once
    /// receipt evidence resolved it. A resolved record never reopens.
    pub outcome: Option<UnknownCommitOutcome>,
    /// Digest of the resolving `WriteReceipt` bound at disposition. `None`
    /// while open; required once resolved.
    pub evidence_receipt_digest: Option<String>,
}

impl UnknownCommitRecord {
    /// Returns the durable key binding one write attempt to its idempotency key.
    #[must_use]
    pub fn record_key(&self) -> String {
        self.idempotency_key.clone()
    }

    /// Returns whether two records carry the exact same admitted binding.
    ///
    /// Outcome and evidence are excluded: they are ORS-owned reconciliation
    /// progression, not caller binding.
    #[must_use]
    pub fn same_binding(&self, other: &Self) -> bool {
        self.idempotency_key == other.idempotency_key
            && self.operation_id == other.operation_id
            && self.canonical_request_hash == other.canonical_request_hash
            && self.ordering_scopes == other.ordering_scopes
    }

    /// Returns true while the commit outcome is still unknown.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.outcome.is_none()
    }

    /// Validates shape and identity binding without interpreting commit
    /// semantics. An open record carries no evidence; a resolved record
    /// always binds its resolving receipt digest.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.idempotency_key, "unknown_commit_idempotency_key")?;
        validate_text(self.operation_id.as_str(), "unknown_commit_operation_id")?;
        validate_digest(
            &self.canonical_request_hash,
            "unknown_commit_canonical_request_hash",
        )?;
        for scope in &self.ordering_scopes {
            validate_text(scope, "unknown_commit_ordering_scope")?;
        }
        match (&self.outcome, &self.evidence_receipt_digest) {
            (None, None) => Ok(()),
            (None, Some(_)) => Err(OrsError::InvalidField {
                field: "unknown_commit_evidence_receipt_digest",
                reason: "an open unknown-commit record carries no evidence",
            }),
            (Some(_), Some(digest)) => {
                validate_digest(digest, "unknown_commit_evidence_receipt_digest")?;
                Ok(())
            }
            (Some(_), None) => Err(OrsError::InvalidField {
                field: "unknown_commit_evidence_receipt_digest",
                reason: "a resolved unknown-commit record binds its receipt evidence",
            }),
        }
    }
}

/// Stable ORS record-type name of one durable backup-verification result.
///
/// It is published rather than spelled as a literal at the call site so the
/// Kernel verify route can name the I5.27 identity-conflict signal by this
/// contract instead of by a second copy of the same string.
pub const BACKUP_VERIFICATION_RESULT_RECORD_TYPE: &str = "backup_verification_result";

/// Durable REFERENCE to the immutable archive handle one verification resolved
/// through the accepted artifact/publication owner (issue #2862 instruction 1).
///
/// It is a reference, not a request and not a second artifact identity: it is
/// the durable projection of `eliot_protocol::backup::BackupArtifactHandle`
/// into this store's own owner-text spelling, exactly as
/// [`BackupVerifyRequestIdentity::archive_owner_contract`] already is for the
/// handle's contract identity. A path, a URL and an inline `bundle_hex` are
/// none of them: none of the three can be produced here, and the issue forbids
/// inventing an in-memory handle to make a route green.
///
/// It is DIGEST-BOUND in [`BackupVerifyIdentityPreimage`], which is what makes
/// "the same operation identity presented with a different retained handle" an
/// I5.27 identity conflict rather than a second answer — acceptance clause 3's
/// `handle` term. `content_sha256` is the handle's own recorded content digest
/// and is NOT recomputed here: a stored row proves which handle was bound, and
/// proving the handle still resolves to those bytes is the artifact owner's
/// question, not ORS's.
///
/// `None` is the owner's own answer on a path where no artifact owner resolved
/// a handle — the same absence `capture_receipt` and `target_compatibility`
/// already record, and never a placeholder.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupVerifyArchiveHandleRef {
    /// Owner-issued identity of the retained artifact.
    pub artifact_id: String,
    /// Exact owner contract identity of the retained artifact, in this store's
    /// own owner-text spelling (the same spelling as
    /// [`BackupVerifyRequestIdentity::archive_owner_contract`]).
    pub owner_contract: String,
    /// Owner revision of the retained content.
    pub source_revision: String,
    /// Canonical content digest recorded by the owner on the handle.
    pub content_sha256: String,
    /// Exact byte length recorded by the owner on the handle; nonzero.
    pub byte_length: u64,
}

impl BackupVerifyArchiveHandleRef {
    /// Validates the bounded handle reference.
    ///
    /// Deliberately shape-only, like every other owner answer on this record:
    /// ORS stores the owner's handle and interprets no archive, class or
    /// provenance meaning. `byte_length` is required nonzero because the
    /// protocol's own handle bounds it the same way, and a zero-length artifact
    /// is not a retained archive.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.artifact_id, "backup_verify_artifact_artifact_id")?;
        validate_text(
            &self.owner_contract,
            "backup_verify_artifact_owner_contract",
        )?;
        validate_text(
            &self.source_revision,
            "backup_verify_artifact_source_revision",
        )?;
        validate_digest(
            &self.content_sha256,
            "backup_verify_artifact_content_sha256",
        )?;
        if self.byte_length == 0 {
            return Err(OrsError::InvalidField {
                field: "backup_verify_artifact_byte_length",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

/// Outcome of staging one durable backup-verification result.
///
/// The disposition names what the durable row says about the request, never a
/// retry policy: `AlreadyBound` is the exact-replay answer for one operation
/// identity, and the durable winner it carries is the record the caller must
/// answer from. The winner is boxed so this shape stays small next to `Stored`
/// instead of being sized by the record it may carry.
///
/// [`ForeignOperation`](Self::ForeignOperation) is a **unit** variant on purpose.
/// It carries no record, no key and no reason, so a foreign caller's stored
/// metadata has no field to travel through and cannot reach a route even if the
/// route wanted it. Naming the *class* of a refusal is the whole of what ORS is
/// allowed to say about a row it did not certify; the bound principal, the stored
/// identity digest and the stored owner answers stay inside the store.
///
/// `ForeignOperation` is the only refusal-class variant STAGING produces, and its
/// real trigger is a CROSS-SCOPE row, not a corrupted one. `scope_id` is
/// deliberately not a key component — a changed scope must surface as the identity
/// conflict on one key — so two sessions of one principal, on one lineage, with one
/// `operation_id` and one archive but different `WorkScope`s produce the SAME key,
/// and a load-then-stage race between them lands the second writer on the first's
/// row here. A different PRINCIPAL at the same key would be a SHA-256 collision and
/// is not reachable through the route; that narrower case is what this also covers,
/// on a hand-edited row. In both cases the row is answered with a typed class
/// instead of being silently overwritten or answered as if it were the candidate's
/// own. The route's own cross-PRINCIPAL refusal is NOT this variant: it is the
/// `backup.verify` foreign-operation refusal, which is the same sentence.
///
/// There is deliberately NO legacy variant here. The pre-#2883 class is classified
/// at LOAD time and is a different type,
/// [`LegacyUnscopedBackupVerificationClass`], because a legacy row's key was the
/// caller's own text while a staged key is always a 64-hex namespace digest — so
/// staging can never be where one is found, and a same-named variant on this
/// disposition would have no producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackupVerificationDisposition {
    /// This candidate is now the durable row under its operation identity.
    Stored,
    /// An already-durable row owns this operation identity under the same
    /// request binding. The carried record is the durable winner: the stored
    /// answers, not the caller's fresh ones, decide the reply.
    AlreadyBound(Box<BackupVerificationResultRecord>),
    /// A durable row occupies the staged key but its stored owner-bearing
    /// identity contradicts the candidate's. This is a store-side integrity
    /// class, not the route's cross-principal answer: see the type doc. ORS names
    /// the class only, never returns the stored row, and therefore lets no stored
    /// projection, principal, or digest leave the store.
    ForeignOperation,
}

/// What the durable key a legacy probe was pointed at actually holds.
///
/// Three-valued on purpose. A two-valued answer could not tell "nothing is stored
/// under this key" from "something is stored there and it is not readable as
/// either shape", and only the first of those may lead to a new row: the second is
/// an unreadable durable row, and treating it as absent is the fail-OPEN outcome
/// instruction 9 and acceptance clause 6 exist to prevent. The recogniser that
/// produces it lives in the store; the classification is declared here because it
/// is a durable-state contract the route branches on, not a storage detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyUnscopedBackupVerificationClass {
    /// No bytes at all under the probed key. The key is genuinely free, so a fresh
    /// scoped row may be staged under it.
    Absent,
    /// Bytes are present and decode as the pre-#2883 unscoped shape. Legacy
    /// evidence: never certified to, re-keyed for, or projected to any principal.
    Legacy,
    /// Bytes are present and decode as NEITHER the current contract nor the
    /// pre-#2883 shape — corruption, a partial write, or a shape from a future
    /// contract. The durable row is unreadable, so the caller must fail closed and
    /// answer no verification result at all; it must not read this as "absent" and
    /// stage a new row over evidence that is still on disk.
    Unreadable,
}

/// Classifies stored bytes against a raw caller key: absent, a recognised
/// pre-#2883 legacy row, or bytes that are neither shape.
///
/// A current-contract row at the key classifies as
/// [`LegacyUnscopedBackupVerificationClass::Unreadable`] on purpose: this
/// function exists to classify the RAW caller key, which a current-contract row can
/// only occupy if a caller literally chose a 64-hex idempotency text before #2883.
/// A caller that holds a real scoped row reaches it through
/// `load_backup_verification_result` and its own key assertion, never through here.
pub(crate) fn classify_backup_verification_key(
    bytes: &str,
    raw_key: &str,
) -> LegacyUnscopedBackupVerificationClass {
    if serde_json::from_str::<BackupVerificationResultRecord>(bytes).is_ok() {
        return LegacyUnscopedBackupVerificationClass::Unreadable;
    }
    if is_legacy_unscoped_backup_verification_row(bytes, raw_key) {
        return LegacyUnscopedBackupVerificationClass::Legacy;
    }
    LegacyUnscopedBackupVerificationClass::Unreadable
}

/// What a durable key holds when the row there was written under the PRE-#2863
/// two-value archived-fence vocabulary (#2863).
///
/// This is a SEPARATE type from [`LegacyUnscopedBackupVerificationClass`] on
/// purpose. The pre-#2883 class is about a row keyed by CALLER TEXT; this one is
/// about a row correctly keyed by its scoped namespace digest under verify
/// profile `v1`, which is a materially better row that this change must still
/// refuse to reinterpret. Collapsing the two would make a well-formed v1 row
/// indistinguishable from a pre-#2883 text-keyed one and would lose the fact
/// that the v1 row is addressable, isolated and readable — just not under the new
/// semantics.
///
/// Three-valued for the same reason its sibling is: only the first may lead to a
/// new row. `Unreadable` means bytes are present that decode as neither shape,
/// which is an unreadable durable row and must fail CLOSED rather than read as
/// "absent" and be staged over.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyTwoValueRelationBackupVerificationClass {
    /// No bytes at all under the probed `v1` key. The pre-#2863 key is free, and
    /// the current profile's own key was already found empty by the caller, so
    /// nothing is quarantined here.
    Absent,
    /// Bytes are present and decode as a `v1`-profile row: a properly scoped,
    /// isolated, replayable verification result whose archived-fence answer is
    /// `current-session` or `historical-authority`. It is LEGACY UNQUALIFIED
    /// EVIDENCE: replayable as a legacy answer, never upgraded, never
    /// reinterpreted under the new vocabulary, and never a source of a
    /// current-profile answer.
    LegacyUnqualified,
    /// Bytes are present and decode as neither the current record nor the `v1`
    /// shape. The durable row is unreadable, so no verification result may be
    /// answered at all.
    Unreadable,
}

/// Pre-#2863 `v1`-profile row shape, read only far enough to recognise it.
///
/// It is deliberately NOT a full second copy of the old record, for the same
/// reason [`LegacyUnscopedBackupVerificationRow`] is not: its only job is to
/// recognise a shape the current record cannot decode, and a partial shape cannot
/// drift into a second source of truth for old fields. The discriminator is the
/// pair (`profile_version == 1`, a `target_compatibility` value in the legacy
/// two-value vocabulary) together with the `v1` idempotency namespace, which no
/// current row carries.
///
/// Unknown fields are TOLERATED on purpose. The `v1` row carried more fields than
/// these three, and denying them would reject a genuine legacy row and turn it
/// into `Unreadable`, which is the fail-CLOSED-but-wrong answer: it would report
/// corruption for evidence that is perfectly intact and merely old.
#[derive(Deserialize)]
struct LegacyTwoValueRelationBackupVerificationRow {
    /// The `v1` profile version the row was written under.
    profile_version: u16,
    /// The `v1` row's idempotency namespace, which pins the row to the old
    /// vocabulary independently of the profile version number.
    idempotency_namespace: String,
    /// The legacy two-value answer, present in both legacy spellings.
    target_compatibility: String,
}

/// Returns whether stored bytes are a pre-#2863 two-value scoped row.
///
/// It is the recogniser half of
/// [`classify_backup_verification_two_value_key`], which is its only caller, so
/// there is exactly one place that decides the legacy shape. See
/// [`LegacyTwoValueRelationBackupVerificationClass`] for why the surrounding
/// classification is three-valued.
fn is_legacy_two_value_backup_verification_row(bytes: &str) -> bool {
    let Ok(row) = serde_json::from_str::<LegacyTwoValueRelationBackupVerificationRow>(bytes) else {
        return false;
    };
    row.profile_version == 1
        && row.idempotency_namespace == LEGACY_BACKUP_VERIFY_IDEMPOTENCY_NAMESPACE
        && matches!(
            row.target_compatibility.as_str(),
            LEGACY_TWO_VALUE_FENCE_RELATION_CURRENT_SESSION
                | LEGACY_TWO_VALUE_FENCE_RELATION_HISTORICAL_AUTHORITY
        )
}

/// `current-session`: the pre-#2863 spelling that the current profile no longer
/// emits, because that vocabulary reported an authority-epoch-only relation as if
/// it were target compatibility.
pub const LEGACY_TWO_VALUE_FENCE_RELATION_CURRENT_SESSION: &str = "current-session";
/// `historical-authority`: the other pre-#2863 spelling. See
/// [`LEGACY_TWO_VALUE_FENCE_RELATION_CURRENT_SESSION`].
pub const LEGACY_TWO_VALUE_FENCE_RELATION_HISTORICAL_AUTHORITY: &str = "historical-authority";

/// Classifies stored bytes at a probed pre-#2863 key as absent, a recognised
/// legacy two-value row, or bytes that are neither shape (#2863).
///
/// A current-contract row cannot appear at a `v1` key, and a `v1` row cannot
/// decode as a current record (its `target_compatibility` field is unknown to the
/// current shape and its two new fence-digest fields are absent, both of which
/// `deny_unknown_fields`/required-field decoding reject), so this classifier is
/// disjoint from the current one by construction rather than by convention.
pub(crate) fn classify_backup_verification_two_value_key(
    bytes: &str,
) -> LegacyTwoValueRelationBackupVerificationClass {
    if serde_json::from_str::<BackupVerificationResultRecord>(bytes).is_ok() {
        return LegacyTwoValueRelationBackupVerificationClass::Unreadable;
    }
    if is_legacy_two_value_backup_verification_row(bytes) {
        return LegacyTwoValueRelationBackupVerificationClass::LegacyUnqualified;
    }
    LegacyTwoValueRelationBackupVerificationClass::Unreadable
}

/// What a durable key holds when the row there was written under the PRE-#2862
/// fence-bound verify profile, which carried NO owner-evidence commitments
/// (#2862).
///
/// This is a SEPARATE type from
/// [`LegacyTwoValueRelationBackupVerificationClass`] and from
/// [`LegacyUnscopedBackupVerificationClass`] on purpose. The pre-#2883 class is
/// about a row keyed by CALLER TEXT; the pre-#2863 class is about the two-value
/// archived-fence vocabulary; and this one is about a correctly scoped,
/// isolated, fully replayable row that simply predates the retained-handle,
/// capture-receipt and validity-attestation references. Collapsing any two of
/// them would lose a fact the route branches on: which legacy answer it is
/// refusing, and therefore what the caller must do next.
///
/// Three-valued for the same reason both siblings are: only the first may lead
/// to a new row. `Unreadable` means bytes are present that decode as neither
/// shape, which is an unreadable durable row and must fail CLOSED rather than
/// read as "absent" and be staged over.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyFenceBoundBackupVerificationClass {
    /// No bytes at all under the probed `v2` key. The pre-#2862 key is free, and
    /// the current profile's own key was already found empty by the caller, so
    /// nothing is quarantined here.
    Absent,
    /// Bytes are present and decode as a `v2`-profile row: a properly scoped,
    /// isolated, replayable structural-candidate verification result with no
    /// owner-evidence reference of any kind. It is LEGACY UNQUALIFIED EVIDENCE:
    /// replayable as a legacy answer by its own owner, never upgraded, never
    /// reinterpreted as provenance-bound, and never a source of a current-profile
    /// answer. A code upgrade does not and cannot make it provenance-bound —
    /// there is no receipt or attestation in it to read one from.
    LegacyUnqualified,
    /// Bytes are present and decode as neither the current record nor the `v2`
    /// shape. The durable row is unreadable, so no verification result may be
    /// answered at all.
    Unreadable,
}

/// PRE-#2862 `v2`-profile row shape, read only far enough to recognise it.
///
/// It is deliberately NOT a full second copy of the old record, for the same
/// reason its two siblings are not: its only job is to recognise a shape the
/// current record cannot decode, and a partial shape cannot drift into a second
/// source of truth for old fields. It is a partial copy for a second, sharper
/// reason too: a `v2` row's three owner-evidence fields are ABSENT from it, and
/// naming them here would create a second claim about what such a row carried.
///
/// The discriminator is the NESTED `identity.profile_version == 2` together
/// with the `v2` idempotency namespace. The version is read from `identity`
/// rather than from a flat field because that is where
/// [`BackupVerifyRequestIdentity`] has carried it since #2883 and where the `v2`
/// profile put it; a flat read would be a guess about a shape this struct does
/// not model, and a guess that silently never matches is the fail-WRONG answer
/// the probe exists to avoid.
///
/// Unknown fields are TOLERATED on purpose. The `v2` row carried more fields
/// than these, and denying them would reject a genuine legacy row and turn it
/// into `Unreadable` — reporting corruption for evidence that is intact and
/// merely old.
#[derive(Deserialize)]
struct LegacyFenceBoundBackupVerificationRow {
    /// The nested request identity, read only far enough to pin the row to the
    /// pre-#2862 profile.
    identity: LegacyFenceBoundBackupVerificationIdentity,
}

/// Nested identity terms of one pre-#2862 row. See
/// [`LegacyFenceBoundBackupVerificationRow`].
#[derive(Deserialize)]
struct LegacyFenceBoundBackupVerificationIdentity {
    /// The `v2` profile version the row was written under.
    profile_version: u16,
    /// The `v2` row's idempotency namespace, which pins the row to the old
    /// profile independently of the version number.
    idempotency_namespace: String,
}

/// Returns whether stored bytes are a pre-#2862 fence-bound scoped row.
///
/// It is the recogniser half of
/// [`classify_backup_verification_fence_bound_key`], which is its only caller,
/// so there is exactly one place that decides this legacy shape.
fn is_legacy_fence_bound_backup_verification_row(bytes: &str) -> bool {
    let Ok(row) = serde_json::from_str::<LegacyFenceBoundBackupVerificationRow>(bytes) else {
        return false;
    };
    row.identity.profile_version == 2
        && row.identity.idempotency_namespace
            == PRE_OWNER_EVIDENCE_BACKUP_VERIFY_IDEMPOTENCY_NAMESPACE
}

/// Classifies stored bytes at a probed pre-#2862 key as absent, a recognised
/// legacy fence-bound row, or bytes that are neither shape (#2862).
///
/// A current-contract row cannot appear at a `v2` key, and a `v2` row cannot
/// decode as a current record — its three owner-evidence fields are absent and
/// the current shape requires them — so this classifier is disjoint from the
/// current one by construction rather than by convention.
pub(crate) fn classify_backup_verification_fence_bound_key(
    bytes: &str,
) -> LegacyFenceBoundBackupVerificationClass {
    if serde_json::from_str::<BackupVerificationResultRecord>(bytes).is_ok() {
        return LegacyFenceBoundBackupVerificationClass::Unreadable;
    }
    if is_legacy_fence_bound_backup_verification_row(bytes) {
        return LegacyFenceBoundBackupVerificationClass::LegacyUnqualified;
    }
    LegacyFenceBoundBackupVerificationClass::Unreadable
}

/// Returns whether stored bytes are a pre-#2883 unscoped row occupying `raw_key`.
///
/// It is the recogniser half of [`classify_backup_verification_key`], which is its
/// only caller, so there is exactly one place that decides the legacy shape. See
/// [`LegacyUnscopedBackupVerificationClass`] for why the surrounding
/// classification is three-valued rather than boolean.
fn is_legacy_unscoped_backup_verification_row(bytes: &str, raw_key: &str) -> bool {
    let Ok(row) = serde_json::from_str::<LegacyUnscopedBackupVerificationRow>(bytes) else {
        return false;
    };
    row.idempotency_key == raw_key && !row.request_digest.is_empty()
}

/// Pre-#2883 unscoped `backup.verify` row shape, read only far enough to prove
/// that a raw caller key is occupied by one.
///
/// It is deliberately NOT a full second copy of the old record: its only job is
/// to recognise the shape the current record cannot decode, and a partial shape
/// cannot drift into a second source of truth for the old fields. The presence of
/// `idempotency_key` is the whole discriminator, because a current-contract row
/// carries a nested `identity` and no `idempotency_key` at all, so this shape is
/// unreachable for any row written since #2883. No ORS `contract_version` is
/// required: the two shapes deliberately SHARE one contract version and one table
/// name, so pinning the recogniser to the current version would make a future
/// version bump silently stop recognising legacy rows — precisely the "silently
/// ignoring" outcome the probe exists to prevent. The shape itself is the
/// discriminator, not the version.
///
/// Unknown fields are tolerated (not denied) on purpose: the pre-#2883 record
/// carried fourteen fields, twelve of them beyond the two read here, and rejecting
/// them would make a genuine legacy row unrecognisable.
#[derive(serde::Deserialize)]
struct LegacyUnscopedBackupVerificationRow {
    /// The raw caller text that WAS the durable key before #2883.
    idempotency_key: String,
    /// The legacy row's request digest, kept only to prove the row is a complete
    /// pre-#2883 verification answer rather than a partial write.
    request_digest: String,
}

/// Durable owner-backed result of one `backup.verify` operation (issue #2802,
/// rescoped by #2883).
///
/// I5.27 makes idempotency a property of canonical request bytes and I14.21
/// makes the answer a query by idempotency key. This record is that durable
/// answer: one row per SCOPED verification operation identity, holding exactly
/// the values the verification owner proved. An exact replay by the owning
/// identity therefore reads the same owner-backed result back instead of a
/// freshly derived, differently-fenced one, and a changed archive under the same
/// operation identity is a conflict rather than a second answer. ORS stores the
/// row verbatim and interprets no archive, class, fence or recovery meaning.
///
/// The "same result" holds across a Kernel restart and across an Authority Epoch
/// rotation, because neither is in the durable key or in the canonical request
/// hash: both are recorded as the ambient context the answer was observed under
/// (see [`BackupVerifyRequestIdentity`]'s ambient note), so the I14.21
/// post-rotation query by idempotency key resolves to the row that was already
/// committed instead of silently staging a second one.
///
/// It is deliberately not an unknown-commit record: a read-only verification is
/// not a canonical write attempt, so it has its own table and its own single
/// writer rather than a semantic reuse of another owner's table.
///
/// #2883 replaced the flat `idempotency_key: String` with the nested
/// [`BackupVerifyRequestIdentity`]. The key used to be the caller's own text, so
/// two principals that happened to pick the same human string read, conflicted
/// with, or inherited each other's verification result. The identity is nested
/// rather than flattened precisely so there is exactly one request identity and one request digest on the row: `record_key()` and
/// `same_binding()` can no longer disagree about which request a stored answer
/// belongs to.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupVerificationResultRecord {
    /// ORS wire/storage contract version of this row. A row written under
    /// another version fails its read closed instead of being reinterpreted as
    /// the same answer.
    pub contract_version: u16,
    /// The accepted request identity of this verification, as the versioned
    /// read-only verify profile. It carries the authenticated principal, the
    /// admitted capability, the `WorkScope` owner value, the caller's
    /// `operation_id`, the authority lineage and the archive source/provenance
    /// the owner declared, and it is the *only* thing the durable key and the
    /// request digest are derived from. It additionally records the ambient
    /// observation context — the `session_id`, `resource_generation` and
    /// `authority_epoch` in force when the answer was produced — which is in
    /// neither digest. The route never mints a second identity such as a
    /// `verify-only-` name for the same operation.
    pub identity: BackupVerifyRequestIdentity,
    /// Digest of the canonical request bytes this operation was admitted with.
    /// Reusing the key with a different value is an identity conflict, never a
    /// silent overwrite of the bound row. It is the same value as
    /// `identity.identity_digest`; `validate()` requires the two to agree so the
    /// retained wire/storage field can never drift from the nested identity.
    pub request_digest: String,
    /// The verification owner's own digest of the complete encoded archive. It
    /// is the owner-proved input to `identity.archive_sha256`, so the same bytes
    /// re-spelled by a caller under the same key still resolve to one
    /// operation while different bytes do not.
    pub archive_sha256: String,
    /// Archive identity the owner proved.
    pub backup_id: String,
    /// Evidenced archive class, in the ROUTE's closed wire spelling
    /// (`full_recovery` / `canonical_only_degraded` / `scope_export`) read through
    /// the route's own `class_name` mapping from the owner's typed class. The
    /// protocol enum's own serde spelling is `SCREAMING_SNAKE` and is deliberately not
    /// what a durable row stores, so a rename of the wire spelling cannot silently
    /// reinterpret a retained row. Compare `identity.evidenced_class`, which is the
    /// same value and the copy `validate()` drift-checks.
    pub class: String,
    /// Exact class-specific restore proof ceiling in the owner's own spelling.
    /// I5.13 keeps a degraded class from ever being advertised as operational
    /// recovery, so the ceiling is retained beside the class it bounds.
    pub class_ceiling: String,
    /// Evidence level the owner proved for this archive, in its own spelling.
    pub verification_level: String,
    /// STRUCTURAL relation of the archive's own COMPLETE fence value to the
    /// verifying target, in the owner's own spelling. Retained verbatim so a
    /// replay after an epoch rotation reports the relation that was observed
    /// instead of re-deriving one against whatever generation happens to be live.
    /// Instruction 7 of #2883 and #2863: this is HISTORICAL archive-fence
    /// evidence and stays separate from `identity.authority_epoch`, which is the
    /// CURRENT request authority.
    ///
    /// #2863 renamed this field from `target_compatibility` and widened its
    /// vocabulary. It is a relation over fence VALUES, and it is NOT target
    /// compatibility: no schema/build/key/purge/import/epoch compatibility check
    /// runs on the verify path, so the old name was a category error that the
    /// front door then rendered to an operator as a compatibility verdict.
    pub archive_fence_relation: String,
    /// PROVENANCE qualifier for [`Self::archive_fence_relation`], in the owner's
    /// own spelling, and a SEPARATE axis from the relation. `structural-only` is
    /// the only value a verify answer can carry until an owner issues a capture
    /// receipt, and it is what keeps an exact or same-lineage structural match
    /// from being described as proven installation history.
    pub archive_fence_proof: String,
    /// Bounded tokens naming the claims this stored answer does NOT make, from
    /// the owner's [`archive_fence_restrictions`]. Retained beside the relation
    /// so a replayed row carries the same ceiling the fresh answer did, and so a
    /// reader cannot read a relation as compatibility, currentness or readiness.
    pub archive_fence_restrictions: Vec<String>,
    /// Contract version of the relation vocabulary and classifier that produced
    /// [`Self::archive_fence_relation`]. ORS stores and validates it without
    /// interpreting it, exactly as it stores the class ceiling and the evidence
    /// level; it exists so a vocabulary change is a NEW row contract rather than a
    /// silent reinterpretation of a retained one.
    pub archive_fence_relation_contract_version: u16,
    /// TARGET COMPATIBILITY IS ABSENT, NOT UNKNOWN-AND-FILLED-IN. This field is
    /// `None` on every row this owner writes, because A13.7 keeps schema/build/
    /// key/purge/import/epoch compatibility, Authority Epoch monotonicity and
    /// cutover with the isolated restore owner and no such owner issues a typed
    /// result on the verify path. It is retained as an explicit `Option` rather
    /// than deleted so the absence is a recorded field, not a gap a later reader
    /// could fill in by inference. There is no `serde(default)`: a row that
    /// omits it is unreadable rather than silently upgraded to "absent".
    pub target_compatibility: Option<String>,
    /// Canonical-member denominator in the owner's own dispositions.
    pub event_count: u64,
    /// Receipt-obligation member denominator in the owner's own dispositions.
    pub receipt_count: u64,
    /// Sealed-blob obligation member denominator in the owner's own
    /// dispositions. Equal bytes under different obligations stay distinct
    /// counts here rather than being coalesced.
    pub blob_count: u64,
    /// Owner-issued publication receipt identity. `None` is the owner's own
    /// answer on a path where no retained-artifact owner issues one; an absent
    /// receipt is never replaced by a placeholder identity.
    pub capture_receipt: Option<String>,
    /// #2862: the retained immutable archive handle this answer was produced
    /// against, retained BOTH flat here and nested in
    /// [`Self::identity::archive_handle`](BackupVerifyRequestIdentity::archive_handle)
    /// and cross-checked in [`Self::validate`], for the same reason the other
    /// four duplicated fields are: without the check a bit-rotted row could
    /// project a handle the accepted request identity never vouched for.
    ///
    /// `None` on every row this owner writes today, because no production
    /// artifact/publication owner resolves a handle on this path. That absence
    /// is the owner's own answer and is never a placeholder.
    pub archive_handle: Option<BackupVerifyArchiveHandleRef>,
    /// #2862: canonical digest of the owner-issued capture receipt this answer
    /// relied on, cross-checked against the nested identity. `None` wherever
    /// `capture_receipt` is `None`: a free-text receipt identity and the
    /// receipt's own recorded digest are two different values, and the digest is
    /// the one that is digest-bound and therefore conflict-detecting.
    pub capture_receipt_digest: Option<String>,
    /// #2862: canonical digest of the verifier-issued archive validity
    /// attestation this answer relied on, cross-checked against the nested
    /// identity. `None` on every row this owner writes today, because no
    /// `BackupRole::Verifier` session issues one on this product.
    pub validity_attestation_digest: Option<String>,
    /// Digest over the exact reply body this operation projects. A replay
    /// recomputes it, so a row that cannot rebuild the answer it claims to hold
    /// fails closed instead of projecting one it never produced.
    pub reply_digest: String,
}

impl BackupVerificationResultRecord {
    /// Returns the durable key binding one result to its operation identity.
    ///
    /// The key is [`BackupVerifyRequestIdentity::namespace_digest`], so this
    /// function does not restate it: that is the ONE place the key preimage is
    /// enumerated — principal, authority lineage, operation id and the four profile
    /// constants — and it is always 64 lowercase hex characters, never the caller's
    /// own idempotency text. "Within one installation" is STRUCTURAL, not an in-band
    /// field: a row is only ever read out of the ORS file that owns it. That is what
    /// makes two principals who pick the same human key land on two different durable
    /// rows so neither can read, conflict with, or inherit the other's stored answer.
    pub fn record_key(&self) -> Result<String, OrsError> {
        self.identity.namespace_digest()
    }

    /// Returns whether two records describe the same admitted operation.
    ///
    /// The comparison is the canonical request hash, which covers the whole
    /// accepted request identity MINUS the three ambient observation fields
    /// (`session_id`, `resource_generation`, `authority_epoch`) — that is the
    /// authoritative field list, [`BackupVerifyIdentityPreimage`], and it is not
    /// restated here. A changed archive, declared source, class, scope or admitted
    /// capability under one bound key is a different request hash, so it conflicts
    /// instead of reading as a replay, and nothing is stored.
    ///
    /// A changed authority LINEAGE is NOT one of those, and cannot be: the lineage
    /// is a KEY component, so a lineage change moves the key and stages a new row
    /// rather than conflicting on the old one. That is deliberate and disclosed at
    /// [`BackupVerifyRequestIdentity::namespace_digest`]; cross-authority
    /// separation is worth more than cross-lineage conflict detection.
    ///
    /// The recorded `session_id`, `resource_generation` and `authority_epoch` are
    /// deliberately NOT in the comparison. They are the ambient context the
    /// answer was observed under, so the same operation retried on a new session,
    /// under a new resource generation, or after an Authority Epoch rotation is
    /// the SAME operation and must replay, not conflict. That is exactly what
    /// makes an I14.21 reconcile-by-key after a restart find this row.
    ///
    /// The archive's stored answers (archived-fence relation and the three member
    /// denominators) are excluded too, and for a different reason: they are
    /// answers to the *same* request under a different verifying target, so
    /// re-answering them is not a second operation and must not read as one.
    #[must_use]
    pub fn same_binding(&self, other: &Self) -> bool {
        self.contract_version == other.contract_version
            && self.identity.identity_digest == other.identity.identity_digest
    }

    /// Returns whether a stored row's owner-bearing identity contradicts the
    /// presented candidate.
    ///
    /// It compares `principal` and `scope_id`, and those two are NOT equally
    /// reachable. A different `principal` at the same durable key is a SHA-256
    /// collision over the key preimage and is not reachable through the route; it
    /// is here for a hand-edited row. A different `scope_id` IS reachable on an
    /// ordinary uncorrupted row, because `scope_id` is deliberately not a key
    /// component: two sessions of one principal on one lineage with one
    /// `operation_id` and one archive but different `WorkScope`s share one key, and
    /// a load-then-stage race between them lands the second writer on the first's
    /// row here.
    ///
    /// In both cases the answer is a typed class rather than a silent overwrite or
    /// a mis-answer. ORS compares the owner fields itself and never returns the row
    /// on this path, so nothing of the stored row leaves the store.
    ///
    /// The recorded `session_id` is deliberately not compared: it is ambient
    /// observation context, so a legitimate same-operation retry on a new session
    /// must not be classified as a foreign operation.
    #[must_use]
    pub fn foreign_to(&self, candidate: &Self) -> bool {
        self.identity.principal != candidate.identity.principal
            || self.identity.scope_id != candidate.identity.scope_id
    }

    /// Validates shape, digests, the owner-produced spellings, and every
    /// duplication between the flat answer fields and the nested identity.
    ///
    /// The nested [`BackupVerifyRequestIdentity`] is validated first, so a row
    /// can never be read back with an unvalidated request identity behind it.
    /// Every remaining string is a closed owner spelling, so each is checked for
    /// shape only: ORS does not interpret class, ceiling, evidence level or
    /// fence meaning. The three member denominators are the archive's own
    /// declared counts and carry no presence flag, because a real count of zero
    /// is a real answer and an absent one is not representable.
    ///
    /// Seven fields are retained BOTH flat on the row and inside the nested
    /// identity, and all seven are cross-checked here. `request_digest` against
    /// `identity.identity_digest` existed from the start; `archive_sha256`
    /// against `identity.archive_sha256`, `class` against
    /// `identity.evidenced_class`, and `capture_receipt` against
    /// `identity.capture_receipt` are checked for the same reason and were the
    /// gap this closes. #2862 added the fourth group the same way:
    /// `archive_handle` against `identity.archive_handle`, and
    /// `capture_receipt_digest` / `validity_attestation_digest` against their
    /// identity siblings, because those three are the owner-evidence references
    /// a provenance-qualified answer would rest on and a row that carried a
    /// different reference flat than nested would project one the accepted
    /// request identity never vouched for. Without these checks a bit-rotted row
    /// could carry `identity.archive_sha256 = X` next to `archive_sha256 = Y`,
    /// pass every
    /// other check, pass the reconciliation archive comparison — which reads the
    /// IDENTITY side — and then project `integrity_sha256 = Y`, a digest the
    /// accepted request identity never vouched for. These checks strictly
    /// strengthen: the route always writes each flat field from the same identity
    /// value, so nothing the route produces can be rejected by them.
    ///
    /// The four checks are written out rather than looped because their types
    /// differ (`String` vs `Option<String>`) and a loop would need a cast that
    /// would hide the shape of each comparison. They share one reason string
    /// naming the field pair, declared before the first of them.
    pub fn validate(&self) -> Result<(), OrsError> {
        /// One shared reason string for every drift check, naming the
        /// relationship rather than the values so no stored value can leak.
        const DRIFT: &str = "flat field must equal the same field in the nested request identity";
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        self.identity.validate()?;
        if self.request_digest != self.identity.identity_digest {
            return Err(OrsError::InvalidField {
                field: "backup_verification_request_digest",
                reason: DRIFT,
            });
        }
        if self.archive_sha256 != self.identity.archive_sha256 {
            return Err(OrsError::InvalidField {
                field: "backup_verification_archive_sha256",
                reason: DRIFT,
            });
        }
        if self.class != self.identity.evidenced_class {
            return Err(OrsError::InvalidField {
                field: "backup_verification_class",
                reason: DRIFT,
            });
        }
        if self.capture_receipt != self.identity.capture_receipt {
            return Err(OrsError::InvalidField {
                field: "backup_verification_capture_receipt",
                reason: DRIFT,
            });
        }
        // #2862: the three owner-evidence references are duplicated for the same
        // reason as the four above, and the check is against the ORIGINAL
        // RECORDED value in the nested identity — never a recomputation over
        // what the flat field happens to hold. `archive_handle` compares by
        // `PartialEq` on the whole reference, so a row cannot carry one handle
        // flat and a different one nested.
        if self.archive_handle != self.identity.archive_handle {
            return Err(OrsError::InvalidField {
                field: "backup_verification_archive_handle",
                reason: DRIFT,
            });
        }
        if self.capture_receipt_digest != self.identity.capture_receipt_digest {
            return Err(OrsError::InvalidField {
                field: "backup_verification_capture_receipt_digest",
                reason: DRIFT,
            });
        }
        if self.validity_attestation_digest != self.identity.validity_attestation_digest {
            return Err(OrsError::InvalidField {
                field: "backup_verification_validity_attestation_digest",
                reason: DRIFT,
            });
        }
        if let Some(handle) = &self.archive_handle {
            handle.validate()?;
        }
        if let Some(digest) = &self.capture_receipt_digest {
            validate_digest(digest, "backup_verification_capture_receipt_digest")?;
        }
        if let Some(digest) = &self.validity_attestation_digest {
            validate_digest(digest, "backup_verification_validity_attestation_digest")?;
        }
        validate_digest(&self.request_digest, "backup_verification_request_digest")?;
        validate_digest(&self.archive_sha256, "backup_verification_archive_sha256")?;
        validate_digest(&self.reply_digest, "backup_verification_reply_digest")?;
        validate_text(&self.backup_id, "backup_verification_backup_id")?;
        validate_text(&self.class, "backup_verification_class")?;
        validate_text(&self.class_ceiling, "backup_verification_class_ceiling")?;
        validate_text(
            &self.verification_level,
            "backup_verification_verification_level",
        )?;
        validate_text(
            &self.archive_fence_relation,
            "backup_verification_archive_fence_relation",
        )?;
        validate_text(
            &self.archive_fence_proof,
            "backup_verification_archive_fence_proof",
        )?;
        // The restriction tokens are a CLOSED set the owner emits and ORS does not
        // interpret, so each is shape-checked. The list may be empty only if the
        // owner emitted none, which is its own answer; the field itself is
        // required, so a row that omits the list does not decode.
        for restriction in &self.archive_fence_restrictions {
            validate_text(restriction, "backup_verification_archive_fence_restriction")?;
        }
        if self.archive_fence_relation_contract_version == 0 {
            return Err(OrsError::InvalidField {
                field: "backup_verification_archive_fence_relation_contract_version",
                reason: "relation contract version must be a declared non-zero version",
            });
        }
        if let Some(compatibility) = &self.target_compatibility {
            validate_text(compatibility, "backup_verification_target_compatibility")?;
        }
        if let Some(receipt) = &self.capture_receipt {
            validate_text(receipt, "backup_verification_capture_receipt")?;
        }
        Ok(())
    }
}

/// Stable profile id of the read-only backup-verify request identity (I5.27).
///
/// It is published rather than spelled as a literal at a call site so the Kernel
/// verify route and this record agree on one versioned profile name instead of
/// two independently edited strings.
pub const BACKUP_VERIFY_PROFILE_ID: &str = "eliot.kernel.backup-verify.read-only";
/// Version of the read-only backup-verify request identity profile.
///
/// This is the single place a future change to the field set of
/// [`BackupVerifyRequestIdentity`] must be made, exactly as I5.27's
/// `canonical_encoding_version` is: a new field is a new profile version, never
/// a silent reinterpretation of a retained one.
///
/// Be precise about what a bump does to a RETAINED row, because it is weaker than
/// "keeps its own namespace": `BackupVerifyRequestIdentity::validate` pins this
/// version and returns [`OrsError::UnsupportedContractVersion`] for anything
/// else, so a row written under an older profile version is NOT re-keyed and NOT
/// reinterpreted — it becomes UNREADABLE, and a lookup for it fails closed rather
/// than answering. The new version does get its own `idempotency_namespace`, so the
/// two versions can never share a key; what the old version does not get is a
/// read path. Retention and any migration of old rows belong to the ORS
/// operational retention owner, not here.
pub const BACKUP_VERIFY_PROFILE_VERSION: u16 = 3;
/// I5.27 `idempotency_namespace` the PRE-#2863 (`v1`) verify profile used, and
/// the ONLY thing #2863 changed about the durable key preimage.
///
/// #2863 bumped [`BACKUP_VERIFY_PROFILE_VERSION`] to 2 because the identity
/// gained `archived_fence_digest` and `observed_fence_digest` and the stored
/// answer gained the closed relation/proof/restriction vocabulary. A bump is a
/// new namespace by construction, so a `v1` row is neither re-keyed nor
/// reinterpreted. It is also, on its own, not enough: a new namespace means a
/// `v1` row simply becomes unreachable, and an unreachable row read as "absent"
/// would be the fail-OPEN outcome (a caller would re-run a key that already has
/// an answer and stage a second row beside it).
///
/// This constant is what lets the route ADDRESS the row a pre-#2863 install
/// actually wrote, so it can be recognised and reported as legacy UNQUALIFIED
/// evidence instead. See
/// [`BackupVerifyRequestIdentity::legacy_two_value_namespace_digest`] for the
/// probe and
/// [`LegacyTwoValueRelationBackupVerificationClass`] for the three-valued answer.
pub const LEGACY_BACKUP_VERIFY_IDEMPOTENCY_NAMESPACE: &str =
    "eliot.kernel.backup-verify.read-only/v1";
/// I5.27 `idempotency_namespace` the PRE-#2862 (`v2`) verify profile used.
///
/// #2862 bumped [`BACKUP_VERIFY_PROFILE_VERSION`] to 3 because the identity
/// gained the three OWNER-EVIDENCE commitments — the retained
/// [`BackupVerifyArchiveHandleRef`], the capture-receipt digest and the
/// validity-attestation digest — and the stored answer gained the same three
/// references. Those three are in [`BackupVerifyIdentityPreimage`], so the
/// canonical request hash of an otherwise identical request MOVED: a `v2` row is
/// therefore not the same operation as the `v3` row a caller now produces, and
/// reusing one key for the other is exactly the silent reinterpretation I5.27
/// forbids. A bump is a new namespace by construction, so the two versions can
/// never share a key.
///
/// A new namespace alone is not enough, for the same reason #2863 stated: a `v2`
/// row simply becomes unreachable, and an unreachable row read as "absent" is the
/// fail-OPEN outcome — the caller would re-run a key that already holds a stored
/// answer and stage a second row beside it. This constant is what lets the route
/// ADDRESS the row a pre-#2862 install actually wrote, so it can be recognised
/// and reported as legacy UNQUALIFIED evidence instead. See
/// [`BackupVerifyRequestIdentity::legacy_fence_bound_namespace_digest`] and
/// [`LegacyFenceBoundBackupVerificationClass`].
///
/// The migration rule is exactly the one #2863 already established, and it is
/// deliberately a QUARANTINE rather than a conversion: nothing here re-keys,
/// rewrites, upgrades, backfills or projects a `v2` row. A `v2` row stays the
/// exact historical structural-candidate result it was — it does not become
/// provenance-bound by a code upgrade, because ORS never reads its level as
/// anything but what its own owner recorded. A caller that wants the stronger
/// level submits a NEW explicit verification operation, which is a new
/// `operation_id` and therefore a different legacy key that reads `Absent`.
pub const PRE_OWNER_EVIDENCE_BACKUP_VERIFY_IDEMPOTENCY_NAMESPACE: &str =
    "eliot.kernel.backup-verify.read-only/v2";
/// Retention/collision window this durable table is now a member of (I5.27
/// `retention_and_collision_window`).
///
/// It is a *name*, not a duration: it names the existing ORS operational
/// retention/export contract that owns the lifecycle and retirement rule for
/// [`RowFamilyKind::BackupVerificationResults`](crate::RowFamilyKind::BackupVerificationResults)
/// rows, and that family is now DECLARED in that contract's denominator list.
/// Be precise about what that declaration is worth: the denominator function
/// (`RedbRecoveryStore::backup_row_family_denominator`) has NO production reader in
/// this tree, on this branch and on `origin/main`, so nothing yet COUNTS the family
/// and nothing bounds it. Its real cardinality is one row per distinct
/// `(principal, authority lineage, operation id)` within one installation's ORS
/// file, PLUS one quarantined row per pre-#2883 caller key. #2883 deliberately adds
/// no eviction, no TTL, no cap and no deletion here, because a second retention
/// rule beside the ORS operational one is exactly the unbounded growth instruction
/// 10 forbids. The bounded-retirement work stays with the separate ORS retention
/// owner.
pub const BACKUP_VERIFY_RETENTION_WINDOW: &str = "eliot.ors.backup-verification/v1";

/// Accepted request identity of one read-only `backup.verify` operation
/// (issue #2883, instructions 1 and 2).
///
/// This is the whole answer to "what request was admitted, by whom, under which
/// authority, and against which archive". It is a **versioned verify profile** of
/// `BackupRequestIdentity` (`crates/foundation/eliot-protocol/src/backup.rs:837`),
/// carrying field by field:
///
/// - `profile_id` + `profile_version` are this profile's I5.27
///   `idempotency_namespace` + `canonical_encoding_version` pair.
/// - `principal` replaces `BackupRequestIdentity::principal`'s
///   `BackupAuthenticatedPrincipal::principal` (`:581`), taken from the
///   authenticated peer and never from the payload. `session_id` replaces the
///   sibling `session_id` there, but is AMBIENT context rather than identity —
///   see the ambient note below.
/// - `capability` is the I15.2 "capability token" this frame actually admitted;
///   it is the only role evidence available here (see the ambient note).
/// - `scope_id` + `resource_generation` are the `WorkScope` owner tuple, i.e. the
///   part of `BackupAdmissionRef::scope`'s `WorkScopeBinding` (`:636`) this frame
///   actually holds. `resource_generation` is ambient; `scope_id` is identity.
/// - `authority_epoch` is the CURRENT request authority (I5.2/I15.2) and is
///   AMBIENT context, deliberately separated from the archive's own historical
///   fence evidence in `archive_export_fence_digest` — that separation is
///   instruction 7.
/// - `operation_id` replaces `BackupRequestIdentity::request`'s caller-provided
///   `RequestIdentity::idempotency_key`
///   (`crates/foundation/eliot-protocol/src/lib.rs:505`). It is the ONLY
///   caller-authored value in the whole struct, and it is namespaced: it is never
///   used alone as a key.
/// - `domain_separator`, `canonical_encoding_version` and `semantic_command_kind`
///   replace `BackupMutationBinding` (`:612`), pinning which operation and which
///   digest contract this identity belongs to.
/// - `archive_source_installation` carries `BackupRequestIdentity::source_installation`,
///   and it is the archive's own DECLARED source installation read out of the
///   presented bytes — an ANSWER bound in the request hash, never a key
///   component. There is deliberately no `installation_id` field: see the
///   cross-installation note below.
/// - `archive_sha256` replaces `BackupRequestIdentity::archive_digest`;
///   `archive_owner_contract` replaces `owner_contract`; and
///   `archive_export_fence_digest` + `evidenced_class` + `capture_receipt` carry
///   the archive's declared fence, class and publication receipt (I5.27: "archive
///   SHA-256 alone is content integrity, not the source/capture operation
///   identity").
///
/// # CROSS-INSTALLATION SEPARATION IS STRUCTURAL, NOT IN-BAND. There is no
/// verifying-installation field here and there is no in-band way to fake one: a
/// durable row is only ever read out of the ORS file that owns it, so another
/// installation's verification rows are simply not in this table and no digest
/// pair can name them. The first real platform-independent
/// verifying-installation identifier is where an in-band field check would belong;
/// inventing a value here would mean inventing an owner answer. The archive's
/// declared source is NOT that substitute — it is caller-presented text, which is
/// exactly why it is an ANSWER in the request hash and never a key component.
/// Relatedly, the ARCHIVE-DECLARED members below (`archive_sha256`,
/// `archive_owner_contract`, `archive_source_installation`, `evidenced_class`,
/// `capture_receipt`) are read out of the decoded bundle and are never proved
/// against a capture owner, because none exists on this verify path;
/// `archive_export_fence_digest` is the one exception and IS re-derived by the
/// archive format on every decode. This note is what those field docs point at.
///
/// The full `BackupRequestIdentity` is deliberately NOT constructed on this
/// frame, and that is a property of the profile rather than an omission: its
/// `BackupAdmissionRef::admission_receipt` needs an owner-issued `ReceiptId` and
/// its `WorkScopeBinding` needs an owner-issued scope admission, and no owner
/// issues either for a read-only verify — the retained-artifact capture owner is
/// still open (`backup-capture-owner (#959)`) and the restore-admission owner
/// (`#962`) is a different operation. Inventing either value here would
/// fabricate authority.
///
/// The following `BackupRequestIdentity` members are therefore NOT carried. This
/// is the set this profile version DECLARES, listed exhaustively, and each entry
/// states why: `wire_id` and `wire_version` (this profile's own `profile_id` and
/// `profile_version` are the version pins, and duplicating them would create two
/// spellings of one contract pin); `dest_installation` (a verify mutates no
/// installation and A13.7 keeps "Cutover requires separate authority");
/// `snapshot_digest` and `member_digest` (no snapshot is read; the archive's own
/// declared per-domain member dispositions are the reported denominators);
/// `max_page_members` and `max_payload_bytes` (no paged effect is admitted; the
/// route's own bounded inline byte limit is enforced before the frame reaches
/// here); `deadline_unix_ms` and `cancellation_id` (a verify performs no effect to
/// cancel and carries no owner-minted lifecycle identity); `schema_digest` and
/// `build_digest` (the verifying Kernel admits no build or schema for a read-only
/// compare; the archive's own declared manifest commitments are carried by
/// `archive_owner_contract` and `archive_export_fence_digest` instead); and
/// `archive_id`/`archive_contract` (the archive's identity and contract are
/// reported as the row's own answers, and duplicating them into the request
/// identity would create two spellings of one answer).
///
/// The `fence` member is carried only in part. Its `authority_epoch` is present
/// but ambient, and its three REVISION members — `task_revision`,
/// `policy_revision` and `integration_revision` — are NOT bound at all. Be precise
/// about what that means: they ARE authority-scope facts, and this profile does
/// not bind them. A read-only verify does not act on them — it admits no task, no
/// policy and no integration, and it writes no revision — but that is a DECLARED
/// property of `BACKUP_VERIFY_PROFILE_VERSION` v1, not a claim that they are
/// irrelevant to authority. A future verify that DID admit a task, a policy or an
/// integration revision would have to add them, which is exactly what a profile
/// version bump is for.
///
/// Because this is a declared, versioned profile, none of that is a silent
/// omission: I5.27 forbids omitting or defaulting a field that affects
/// authority, scope, ordering, privacy or effect, and the list above is the
/// declaration of which members this version does not bind and why.
/// `BACKUP_VERIFY_PROFILE_VERSION` is the single place a future change must be
/// made, and a bump is a new namespace, so a retained row is never reinterpreted
/// under new semantics.
///
/// # AMBIENT CONTEXT vs. OPERATION IDENTITY. Three recorded fields —
/// `session_id`, `resource_generation` and `authority_epoch` — describe the
/// context in which an answer was OBSERVED and are deliberately excluded from
/// BOTH the durable lookup key ([`namespace_digest`]) and the canonical request
/// hash ([`compute_digest`]). They are still validated, because they are real
/// observed values and not placeholders; they are simply not part of "which
/// operation is this".
///
/// The reason is I14.21. A retry after a lost response necessarily arrives on a
/// NEW session, because the old one is gone; I14.21 requires that retry to
/// "query `WriteReceipt` by idempotency key" and "reconcile ORS" to the result
/// that was already committed. A durable key that moved with the session, the
/// module generation, or the Authority Epoch would make every such retry miss the
/// committed row, read as absent, and stage a SECOND row under a different key —
/// which is a silent duplicate effect, the exact outcome I14.21 forbids and
/// I5.27's "reusing an idempotency key with a different canonical request hash
/// returns `IDENTITY_CONFLICT`" turned inside out. A module re-registration at a
/// new resource generation is likewise the same operation observed later, not a
/// second operation, and an Authority Epoch rotation changes the current
/// authority without changing which archive was verified.
///
/// # `session_id` AMBIENT IS A STATED READING, AND IT IS THE REQUIRED ONE. The
/// durable operation identity is the authenticated PRINCIPAL together with its
/// `WorkScope`. A reconnect, or any new session, by that same principal in that
/// same scope, presenting the same `operation_id` and the same archive, is the
/// SAME operation and MUST replay the stored answer — with no `successor_of`
/// evidence at all. That is demanded twice over: acceptance clause 2 ("exact
/// replay by the OWNING IDENTITY returns the same durable result after restart")
/// and I14.21, whose retry cannot reach the committed row at all if the key moved
/// with the session. Binding `session_id` would make every I14.21 reconciliation a
/// silent second row, which is the defect this rework removed.
///
/// The consequence is stated here rather than left implicit: a second session of
/// one principal replays that principal's stored verification without presenting
/// succession evidence. That is a RETRY OF THE PRINCIPAL'S OWN OPERATION, not a
/// reconciliation of somebody else's, which is what instruction 4 and acceptance
/// clause 3 govern. Issue #2883's clause 1 says "two authenticated principals OR
/// SESSIONS", and that phrase is genuinely ambiguous; this implementation reads it
/// as per-PRINCIPAL isolation because clause 2 and I14.21 cannot be satisfied any
/// other way. The reading is disclosed here for the owner to settle; it is not
/// resolved in code, and no code change here could resolve it without breaking
/// clause 2. Note also that in this codebase `CaptureCallerAuth::principal` is
/// `format!("{user_identity}@{session_identity}")`, so "principal/session" is
/// already one composite string at the capture owner — see
/// `request_dispatch.rs::authenticated_backup_principal` for the two values this
/// identity binds separately.
///
/// The reconciliation evidence (`successor_of`) therefore exists for exactly one
/// case: a caller that is NOT the principal owning the operation, which the
/// namespace key cannot otherwise separate. That is the only case it is for.
///
/// That is also why the transport `launch_nonce` is not a field of this identity
/// at all, not even as recorded context. The protocol states it outright:
/// "`launch_nonce` is correlation-only connection data. It is deliberately
/// absent from this declaration and therefore cannot change its digest or act as
/// an authority-bearing identity"
/// (`crates/foundation/eliot-protocol/src/lib.rs`). Binding it here would make a
/// reconnect silently re-key a committed operation, which is instruction 4's
/// "keep fresh transport correlation distinct from stable replay identity"
/// inverted, and would let a per-connection value act as identity that the
/// protocol forbids.
///
/// The authority LINEAGE, by contrast, IS identity, and it is the one authority
/// fact the key binds: it comes from the recorded `authority_epoch` but only its
/// `lineage_id`, never its `sequence`. A rotation to a new sequence on the same
/// lineage keeps one row addressable, while a different authority lineage is a
/// different authority and gets a different key.
///
/// # DISCLOSED DEVIATION FROM INSTRUCTION 3 — the owner's call to make. Instruction
/// 3 asks the key to "preserve principal/session/scope/fence ownership". This
/// profile binds `principal`, authority LINEAGE and `operation_id`, and moves
/// `session_id` and `scope_id` into the conflict rule and the fence's epoch sequence
/// into the ambient set. Session cannot be in the key without breaking acceptance
/// clause 2 and I14.21 together; scope and the fence's sequence are argued case by
/// case at [`namespace_digest`]. That is a deviation from the instruction's LETTER,
/// not from its intent, recorded here for the owner to accept or reject rather than
/// resolved in code.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupVerifyRequestIdentity {
    /// Must equal [`BACKUP_VERIFY_PROFILE_ID`].
    pub profile_id: String,
    /// Must equal [`BACKUP_VERIFY_PROFILE_VERSION`].
    pub profile_version: u16,
    /// Digest domain separator of this profile, so no other operation's digest
    /// over the same bytes can collide with it.
    pub domain_separator: String,
    /// I5.27 `idempotency_namespace`. It is a constant derived from the profile
    /// id and version, never caller text.
    pub idempotency_namespace: String,
    /// I5.27 `canonical_encoding_version` of this profile's digest contract.
    pub canonical_encoding_version: u16,
    /// I5.27 `semantic_command_kind`: the closed operation this identity is for.
    pub semantic_command_kind: String,
    /// Authenticated principal, separate from the payload (I15.2, A12.2).
    pub principal: String,
    /// AMBIENT observation context: the authenticated session this answer was
    /// produced under, recorded verbatim. It is deliberately excluded from the
    /// operation identity and from the canonical request hash, because the durable
    /// operation identity is the PRINCIPAL and its `WorkScope`: a retry after a
    /// lost response necessarily arrives on a new session and I14.21 requires that
    /// retry to reconcile to the already-committed result, and acceptance clause 2
    /// requires the owning identity's replay to work after a restart. See the type's
    /// ambient note for the disclosed reading of the issue's "principals or
    /// sessions" phrase.
    pub session_id: String,
    /// The one capability this session was admitted with. This is the ONLY role
    /// evidence this frame holds: no `BackupRole` projection is constructed or
    /// compared on the verify route, because no owner issues one for a read-only
    /// verify, and the admitted single front-door capability is what actually
    /// gated this call.
    pub capability: String,
    /// `WorkScope` owner value this request was admitted under (A12.2). This is
    /// OPERATION identity: a changed scope is a different request and must
    /// conflict on the one key rather than open a second row.
    pub scope_id: String,
    /// AMBIENT observation context: the resource generation the admitted
    /// `WorkScope` was fenced at when this answer was produced. It is excluded
    /// from the operation identity and from the canonical request hash, because a
    /// module re-registration at a new generation is the same operation observed
    /// later and not a second operation. Its non-zero shape is enforced by the
    /// type's own deserializer and by the session's contract validation.
    pub resource_generation: ResourceGeneration,
    /// AMBIENT observation context: the CURRENT request authority (I5.2/I15.2)
    /// observed when this answer was produced, kept deliberately separate from
    /// the archive's own historical fence evidence in
    /// `archive_export_fence_digest` and from the recorded `target_compatibility`
    /// answer — that separation is instruction 7. It is excluded from the
    /// operation identity and from the canonical request hash because an epoch
    /// rotation changes the current authority without changing which archive was
    /// verified, and I14.21 requires a post-rotation retry to reconcile to the
    /// committed result. The LINEAGE it belongs to IS identity and is bound by
    /// the key; only the sequence is ambient.
    pub authority_epoch: EpochId,
    /// The caller-provided idempotency text. The only caller-authored value in
    /// this struct, and never a key on its own.
    pub operation_id: String,
    /// Content digest of the complete encoded archive, COMPUTED by the archive
    /// format itself: the capture owner calls `BackupBundle::bundle_sha256` on the
    /// decoded bundle, so it is a derived answer and not caller text. It is still
    /// not an owner-PROVED value, because no capture owner exists on the verify
    /// path to prove it against; see the type's cross-installation note.
    pub archive_sha256: String,
    /// ARCHIVE-DECLARED capture/owner contract identity, read from the decoded
    /// manifest's producing `source_adapter` — the producer the archive declares
    /// about itself, not one proved against a capture owner.
    pub archive_owner_contract: String,
    /// ARCHIVE-DECLARED source installation, read from the decoded export fence's
    /// `export_id`. It is free text INSIDE the caller-presented `bundle_hex`, which
    /// is exactly why it is an answer in the request hash and never a key
    /// component: see [`Self::namespace_digest`].
    pub archive_source_installation: String,
    /// The archive's own export-fence digest, RE-DERIVED rather than merely
    /// declared: the archive format computes the manifest's `export_fence_sha256`
    /// at build and `BackupBundle::validate` recomputes it from the decoded fence
    /// and re-binds the manifest on every decode, so a mismatch refuses before this
    /// value is read. It is HISTORICAL archive-fence evidence and is deliberately
    /// not the same value as `authority_epoch`, which is the current request
    /// authority.
    pub archive_export_fence_digest: String,
    /// Digest over the COMPLETE archived `StateFence` VALUE, computed by the
    /// capture owner from the fence it decoded out of the archive. It is a
    /// dedicated digest over that value's canonical encoding, so it is NOT the
    /// manifest's `archive_export_fence_digest` and not any plan or approval
    /// digest: reusing one of those as a fence identity would make an unrelated
    /// contract's change move this identity.
    ///
    /// #2863 added it and it is DIGEST-BOUND. The archived fence is evidence the
    /// caller presented, and it is half of what the relation is a relation
    /// BETWEEN, so a different complete fence value under one operation identity
    /// must be an I5.27 identity conflict, not a second answer.
    pub archived_fence_digest: String,
    /// AMBIENT observation context: digest over the COMPLETE CURRENT
    /// `StateFence` the relation was observed against — the live session's own
    /// fence. It is recorded and shape-validated, and it is DELIBERATELY NOT in
    /// the canonical request hash and NOT in the durable key, for the same reason
    /// `resource_generation` and the epoch sequence are ambient: a retry after a
    /// lost response, a module re-registration and an Authority Epoch rotation
    /// all change the current fence while remaining the SAME operation, and
    /// binding it would turn every I14.21 reconcile-by-key and every
    /// post-rotation replay into an identity conflict instead of a replay.
    ///
    /// #2863 disclosed consequence, stated rather than left implicit: because the
    /// observed fence is ambient, the same operation replayed after the live
    /// fence moved CAN derive a different relation than the stored one, and that
    /// is answered from the STORED relation, not re-derived — the row is the
    /// record of the answer that was produced under the fence recorded in
    /// `observed_fence_digest`. Re-deriving on replay is the drift this durable
    /// row exists to prevent.
    pub observed_fence_digest: String,
    /// ARCHIVE-DECLARED evidenced class, in the ROUTE's closed wire spelling
    /// (`full_recovery` / `canonical_only_degraded` / `scope_export`) read through
    /// the owner's typed `BackupClass` by the route's own `class_name` mapping. The
    /// protocol enum's own serde spelling is `SCREAMING_SNAKE` and is deliberately
    /// not what a durable row stores, so a rename of the wire spelling cannot
    /// silently reinterpret a retained row.
    pub evidenced_class: String,
    /// Owner-issued publication receipt identity, explicitly absent when the owner
    /// issued none. Absence is the owner's own answer, never a placeholder.
    pub capture_receipt: Option<String>,
    /// #2862: the retained immutable archive handle this verification resolved
    /// through the accepted artifact/publication owner, or `None` when no such
    /// owner resolved one on this path.
    ///
    /// It is DIGEST-BOUND (it is in [`BackupVerifyIdentityPreimage`]) so a
    /// different handle under one operation identity is the I5.27 conflict
    /// acceptance clause 3 names, not a second answer. It is an ANSWER, never a
    /// key component: a handle is a content reference, and a caller-movable key
    /// component would be a caller-movable durable namespace. See
    /// [`BackupVerifyArchiveHandleRef`].
    pub archive_handle: Option<BackupVerifyArchiveHandleRef>,
    /// #2862: canonical digest of the owner-issued `BackupCaptureReceipt` that
    /// proves the retained capture, or `None` when the capture owner issued
    /// none. DIGEST-BOUND for the same reason.
    ///
    /// It is the RECORDED digest of the owner's own receipt, not a digest ORS
    /// recomputed: the receipt is the capture owner's contract and ORS never
    /// parses one. It is a reference, and reference equality is what makes
    /// "a receipt for another archive, class, source, fence or owner" a
    /// conflict on this key instead of a silently accepted answer.
    pub capture_receipt_digest: Option<String>,
    /// #2862: canonical digest of the verifier-issued
    /// `BackupArchiveValidityAttestation` for this archive, or `None` when no
    /// `BackupRole::Verifier` session issued one. DIGEST-BOUND for the same
    /// reason, and it is the RECORDED digest, never a recomputed one.
    pub validity_attestation_digest: Option<String>,
    /// I5.27 `retention_and_collision_window`: the named ORS operational
    /// retention/export contract this durable row is a member of.
    pub retention_and_collision_window: String,
    /// Canonical digest over every field except this one.
    pub identity_digest: String,
}

impl BackupVerifyRequestIdentity {
    /// Returns the deterministic bytes covered by `identity_digest`.
    ///
    /// The preimage is a dedicated [`BackupVerifyIdentityPreimage`] rather than the
    /// full identity with fields blanked. What that buys is precise in ONE
    /// direction and not the other, and both halves matter:
    ///
    /// - It IS structural that an AMBIENT field cannot start changing the hash: the
    ///   preimage does not mention `session_id`, `resource_generation` or
    ///   `authority_epoch` at all, so no edit to those fields can move the digest.
    /// - It is NOT structural that an IDENTITY field is automatically included: the
    ///   preimage's field list is a hand-written projection, so a newly added
    ///   identity field would compile cleanly and be SILENTLY omitted from the hash
    ///   until someone updates it. Nothing in the type system or in `validate()`
    ///   catches that. What catches it is the human process — this list, and
    ///   `BACKUP_VERIFY_PROFILE_VERSION` as the bump point, since a bump is a new
    ///   namespace and a preimage left behind cannot be reinterpreted silently.
    ///
    /// So the honest statement is "the preimage is complete and exact TODAY, and
    /// the profile version plus this doc is the review that keeps it so" — not
    /// "an identity field cannot be forgotten". The property that would make it
    /// mechanical — one test that perturbs each field and asserts the digest moves
    /// for identity fields and does NOT move for the three ambient ones — is
    /// deferred to the test phase by the owner's 2026-09-25 test order and is NOT
    /// present in this cut.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, OrsError> {
        canonical_json_bytes(&BackupVerifyIdentityPreimage::from(self)).map_err(|_| {
            OrsError::InvalidField {
                field: "backup_verify_identity",
                reason: "canonical identity bytes are not serializable",
            }
        })
    }

    /// Computes the canonical identity digest (I5.27 `canonical_request_hash`).
    ///
    /// The digest is taken over [`Self::canonical_unsigned_bytes`], which PROJECTS
    /// this identity into a [`BackupVerifyIdentityPreimage`] rather than blanking
    /// fields: the preimage is that struct's field list, and it omits exactly
    /// `identity_digest` and the ambient observation set `session_id`,
    /// `resource_generation`, `authority_epoch`. The ambient set is enumerated in
    /// both places, and neither is a silent omission: those three are recorded,
    /// shape-validated facts about when the answer was observed, not facts about
    /// which operation was requested, and binding them would make every I14.21
    /// reconcile-by-key and every post-rotation replay a second stored row.
    ///
    /// Be precise about what the projection buys. It IS structural in one
    /// direction: an ambient field cannot start changing the hash, because the
    /// preimage does not mention it at all. It is NOT structural in the other: a
    /// newly added IDENTITY field would be silently omitted from the hash until
    /// someone updates the preimage, and nothing in the type system or the
    /// validator catches that. What catches it is the human process —
    /// `BACKUP_VERIFY_PROFILE_VERSION` is the bump point, and a bump is a new
    /// namespace, so a preimage left behind cannot be reinterpreted silently. The
    /// property that would make this mechanical — one test that perturbs each
    /// field and asserts the digest moves for identity fields and does NOT move
    /// for `session_id` / `resource_generation` / `authority_epoch` — is deferred to
    /// the test phase by the owner's 2026-09-25 test order and is NOT present in
    /// this cut.
    pub fn compute_digest(&self) -> Result<String, OrsError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical identity digest.
    pub fn with_computed_digest(mut self) -> Result<Self, OrsError> {
        self.identity_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Computes the durable lookup key preimage digest for this identity
    /// (instruction 3).
    ///
    /// The preimage contains EXACTLY these eight entries and nothing else:
    /// `domain_separator`, `idempotency_namespace`, `canonical_encoding_version`,
    /// `semantic_command_kind`, `principal`, `authority_lineage_id`, `operation_id`
    /// and `retention_and_collision_window`. This function is the ONE place in the
    /// whole #2883 change that enumerates the key; every other site links here.
    ///
    /// What each one is doing there:
    /// - the four profile/digest constants pin which contract this key belongs to,
    ///   so no other operation's key can collide with it (I5.27 `domain_separator` +
    ///   `idempotency_namespace` + `canonical_encoding_version` +
    ///   `semantic_command_kind`);
    /// - `principal` is what makes two principals who pick the same human
    ///   idempotency text land on two different rows, so neither can read,
    ///   conflict with, or inherit the other's verification result (acceptance
    ///   clause 1). This is the whole privacy argument for the key, and it is why
    ///   the key can be caller-text-adjacent without being caller text;
    /// - `authority_lineage_id` is the authority LINEAGE only, taken from
    ///   `EpochId::lineage_id` and never from its `sequence`, so a rotation to a
    ///   new sequence on the same lineage keeps one row addressable while a
    ///   different authority lineage is a different authority with a different
    ///   key. I14.21 requires the post-rotation query by idempotency key to
    ///   resolve;
    /// - `operation_id` is the caller's text, always namespaced by everything
    ///   above so it is never a key on its own;
    /// - `retention_and_collision_window` binds the key to its retention owner,
    ///   so two windows can never share one key.
    ///
    /// A change of AUTHORITY LINEAGE therefore MOVES the key: a lineage rotation
    /// stages a new row rather than conflicting on the old one. That is a
    /// deliberate, disclosed consequence of keeping the lineage in the key, not an
    /// oversight. Cross-authority separation is worth more than cross-lineage
    /// conflict detection, and the lineage is what I5.27's `principal_and_scope`
    /// term needs in order to be an authority statement at all; a caller on a new
    /// lineage is a different authority, so a fresh verification of the same
    /// archive there is a genuinely new operation, not a replay of the old one.
    ///
    /// # DISCLOSED DEVIATION FROM INSTRUCTION 3 — the owner's call to make. Instruction
    /// 3 asks the key to "preserve principal/session/scope/fence ownership". This
    /// profile binds `principal`, authority LINEAGE and `operation_id`, and
    /// deliberately moves `session_id` and `scope_id` out of the key into the
    /// conflict rule, and the fence's epoch sequence out of both into the ambient
    /// set. Session cannot be in the key at all without breaking acceptance clause 2
    /// and I14.21 together (a retry after a lost response arrives on a NEW session);
    /// scope and the fence's sequence are argued case by case above. That is a
    /// deviation from the instruction's LETTER, not from its intent, and it is
    /// recorded here rather than resolved in code because only the owner can decide
    /// whether the intent survives the move. No field was added or removed to
    /// satisfy it.
    ///
    /// Be equally precise about what the key is free of, because caller input does
    /// enter it: the ONE caller-authored value in the preimage is `operation_id`,
    /// and it is never a key on its own — every other entry either pins the profile
    /// or is an authenticated/authority-derived value. What the key is free of is
    /// caller-controlled ANSWER and ARCHIVE content: no digest, declared source,
    /// owner contract, export-fence digest, evidenced class or capture receipt
    /// reaches it, and the ambient set keeps observation context out of it too. That
    /// is the property clause 4 needs, and it is not a claim that the key is
    /// caller-proof.
    ///
    /// What is deliberately NOT in the key:
    /// - `scope_id` and `capability` — a changed scope or admission must be the
    ///   identity CONFLICT on one key that acceptance clause 4 names, not a second
    ///   row. This is also why two sessions of one principal in two different
    ///   `WorkScope`s share one key: the cross-scope case is decided by the
    ///   conflict, and the store's `ForeignOperation` class is the race-time
    ///   backstop for it.
    /// - the ambient set (`session_id`, `resource_generation`, `authority_epoch`) —
    ///   a value that changes when the same operation is observed again must not
    ///   change the key, or every I14.21 reconcile-by-key becomes a second row.
    /// - EVERY answer, and that includes `archive_sha256`,
    ///   `archive_owner_contract`, `archive_export_fence_digest`,
    ///   `evidenced_class`, `capture_receipt` — and, most importantly,
    ///   `archive_source_installation`. The archive's declared source is
    ///   caller-presented text: it is a free string inside the `bundle_hex` the
    ///   caller supplied, checked only for non-blank shape. A caller-movable KEY
    ///   COMPONENT is a caller-movable durable namespace: if it were here, two
    ///   archives declaring different `export_id`s under one human key would land
    ///   on two rows and both would be answered `ok` with no identity conflict,
    ///   which is exactly what acceptance clause 4's `source` term forbids. So the
    ///   declared source is an ANSWER, bound in `identity_digest` and nowhere
    ///   else, and a changed declared source on one key is the conflict clause 4
    ///   requires.
    ///
    /// There is NO in-band installation component, and that is structural rather
    /// than a missing field: a durable row is only ever read out of the ORS file
    /// that owns it, so another installation's verification rows are not in this
    /// table at all and no digest pair can name them. The first real
    /// platform-independent verifying-installation identifier is where an in-band
    /// field check would belong; inventing one now would mean inventing a value.
    ///
    /// The result is always 64 lowercase hex characters, so the durable key can
    /// never be caller text alone.
    pub fn namespace_digest(&self) -> Result<String, OrsError> {
        let preimage = serde_json::json!({
            "authority_lineage_id": self.authority_epoch.lineage_id.as_str(),
            "canonical_encoding_version": self.canonical_encoding_version,
            "domain_separator": self.domain_separator.as_str(),
            "idempotency_namespace": self.idempotency_namespace.as_str(),
            "operation_id": self.operation_id.as_str(),
            "principal": self.principal.as_str(),
            "retention_and_collision_window": self.retention_and_collision_window.as_str(),
            "semantic_command_kind": self.semantic_command_kind.as_str(),
        });
        let bytes = canonical_json_bytes(&preimage).map_err(|_| OrsError::InvalidField {
            field: "backup_verify_identity_namespace",
            reason: "canonical namespace bytes are not serializable",
        })?;
        Ok(sha256_hex(&bytes))
    }

    /// Computes the durable key a PRE-#2863 install would have written for this
    /// same operation (#2863).
    ///
    /// It reuses this identity's own key preimage verbatim — the same eight
    /// entries, in the same order, over the same components — and changes exactly
    /// ONE of them: `idempotency_namespace`, forced to
    /// [`LEGACY_BACKUP_VERIFY_IDEMPOTENCY_NAMESPACE`]. That is sound because
    /// #2863 changed no other key component: `domain_separator`,
    /// `canonical_encoding_version`, `semantic_command_kind`, `principal`, the
    /// authority LINEAGE, `operation_id` and `retention_and_collision_window` are
    /// byte-identical across the two profile versions, and the two new fence
    /// digests are answers/evidence rather than key components. So this is a
    /// reconstruction of the exact key the old row occupies, not a guess at one.
    ///
    /// It exists so the route can ask a scoped question about a legacy row rather
    /// than letting the version bump quietly turn it into "absent". What it may
    /// be used for is bounded: it locates a row to be CLASSIFIED as legacy
    /// unqualified evidence. Nothing here re-keys, rewrites, upgrades or projects
    /// a legacy row — the answer is a refusal naming the version, and a new
    /// verification operation is what produces a row under the current profile.
    pub fn legacy_two_value_namespace_digest(&self) -> Result<String, OrsError> {
        let preimage = serde_json::json!({
            "authority_lineage_id": self.authority_epoch.lineage_id.as_str(),
            "canonical_encoding_version": self.canonical_encoding_version,
            "domain_separator": self.domain_separator.as_str(),
            "idempotency_namespace": LEGACY_BACKUP_VERIFY_IDEMPOTENCY_NAMESPACE,
            "operation_id": self.operation_id.as_str(),
            "principal": self.principal.as_str(),
            "retention_and_collision_window": self.retention_and_collision_window.as_str(),
            "semantic_command_kind": self.semantic_command_kind.as_str(),
        });
        let bytes = canonical_json_bytes(&preimage).map_err(|_| OrsError::InvalidField {
            field: "backup_verify_legacy_namespace",
            reason: "canonical legacy namespace bytes are not serializable",
        })?;
        Ok(sha256_hex(&bytes))
    }

    /// Computes the durable key a PRE-#2862 install would have written for this
    /// same operation (#2862).
    ///
    /// It is the same construction as
    /// [`Self::legacy_two_value_namespace_digest`] and changes exactly ONE
    /// preimage entry: `idempotency_namespace`, forced to
    /// [`PRE_OWNER_EVIDENCE_BACKUP_VERIFY_IDEMPOTENCY_NAMESPACE`]. That is sound
    /// because #2862 changed no KEY component: `domain_separator`,
    /// `canonical_encoding_version`, `semantic_command_kind`, `principal`, the
    /// authority LINEAGE, `operation_id` and `retention_and_collision_window`
    /// are byte-identical across the two profile versions. The three terms #2862
    /// added (`archive_handle`, `capture_receipt_digest`,
    /// `validity_attestation_digest`) are ANSWERS and reach neither the key nor
    /// this reconstruction — which is the whole point: a row stored under `v2`
    /// carries no owner-evidence commitment at all, and reconstructing its key
    /// from a `v3` request is a reconstruction of a DIFFERENT request's key for
    /// the eight components the two profiles share.
    ///
    /// It exists so the route can ask a scoped question about a `v2` row rather
    /// than letting the version bump quietly turn it into "absent". What it may
    /// be used for is bounded: it locates a row to be CLASSIFIED as legacy
    /// unqualified evidence. Nothing here re-keys, rewrites, upgrades or projects
    /// a legacy row, and a caller that wants the owner-evidence level submits a
    /// NEW operation id, which is a different key that reads `Absent`.
    pub fn legacy_fence_bound_namespace_digest(&self) -> Result<String, OrsError> {
        let preimage = serde_json::json!({
            "authority_lineage_id": self.authority_epoch.lineage_id.as_str(),
            "canonical_encoding_version": self.canonical_encoding_version,
            "domain_separator": self.domain_separator.as_str(),
            "idempotency_namespace": PRE_OWNER_EVIDENCE_BACKUP_VERIFY_IDEMPOTENCY_NAMESPACE,
            "operation_id": self.operation_id.as_str(),
            "principal": self.principal.as_str(),
            "retention_and_collision_window": self.retention_and_collision_window.as_str(),
            "semantic_command_kind": self.semantic_command_kind.as_str(),
        });
        let bytes = canonical_json_bytes(&preimage).map_err(|_| OrsError::InvalidField {
            field: "backup_verify_legacy_fence_bound_namespace",
            reason: "canonical legacy namespace bytes are not serializable",
        })?;
        Ok(sha256_hex(&bytes))
    }

    /// Validates the profile pins, the owner/authenticated text shapes, the
    /// digest shapes and the self-consistent digest.
    ///
    /// Every field name is unique and prefixed `backup_verify_identity_` so a
    /// refusal names exactly the field that failed. `identity_digest` is
    /// recomputed here rather than trusted, because a stored row's own digest is
    /// the only thing that proves its identity was not rewritten in place.
    ///
    /// The ambient fields ARE validated for shape — `session_id` through
    /// `validate_text`, and `resource_generation` / `authority_epoch` through
    /// their own non-zero and canonical-lineage deserializers — because they are
    /// real observed values and not placeholders, and a row that recorded a blank
    /// session is corrupt. They are deliberately NOT required into the digest:
    /// `validate()` compares `identity_digest` against
    /// [`Self::compute_digest`], which excludes exactly that ambient set.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.profile_id != BACKUP_VERIFY_PROFILE_ID {
            return Err(OrsError::InvalidField {
                field: "backup_verify_identity_profile_id",
                reason: "must equal BACKUP_VERIFY_PROFILE_ID",
            });
        }
        if self.profile_version != BACKUP_VERIFY_PROFILE_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.profile_version));
        }
        for (value, field) in [
            (
                self.domain_separator.as_str(),
                "backup_verify_identity_domain_separator",
            ),
            (
                self.idempotency_namespace.as_str(),
                "backup_verify_identity_idempotency_namespace",
            ),
            (
                self.semantic_command_kind.as_str(),
                "backup_verify_identity_semantic_command_kind",
            ),
            (self.principal.as_str(), "backup_verify_identity_principal"),
            // Ambient: shape-checked because it is a real observed session, and
            // deliberately not part of the digest.
            (
                self.session_id.as_str(),
                "backup_verify_identity_session_id",
            ),
            (
                self.capability.as_str(),
                "backup_verify_identity_capability",
            ),
            (self.scope_id.as_str(), "backup_verify_identity_scope_id"),
            (
                self.operation_id.as_str(),
                "backup_verify_identity_operation_id",
            ),
            (
                self.archive_owner_contract.as_str(),
                "backup_verify_identity_archive_owner_contract",
            ),
            (
                self.archive_source_installation.as_str(),
                "backup_verify_identity_archive_source_installation",
            ),
            (
                self.evidenced_class.as_str(),
                "backup_verify_identity_evidenced_class",
            ),
            (
                self.retention_and_collision_window.as_str(),
                "backup_verify_identity_retention_and_collision_window",
            ),
        ] {
            validate_text(value, field)?;
        }
        for (value, field) in [
            (
                self.archive_sha256.as_str(),
                "backup_verify_identity_archive_sha256",
            ),
            (
                self.archive_export_fence_digest.as_str(),
                "backup_verify_identity_archive_export_fence_digest",
            ),
            // Digest-bound (#2863): the archived complete fence value.
            (
                self.archived_fence_digest.as_str(),
                "backup_verify_identity_archived_fence_digest",
            ),
            // Ambient: shape-checked because it is a real observed fence, and
            // deliberately not part of the digest, for the I14.21 reason its own
            // field doc states.
            (
                self.observed_fence_digest.as_str(),
                "backup_verify_identity_observed_fence_digest",
            ),
            (
                self.identity_digest.as_str(),
                "backup_verify_identity_identity_digest",
            ),
        ] {
            validate_digest(value, field)?;
        }
        if let Some(receipt) = &self.capture_receipt {
            validate_text(receipt, "backup_verify_identity_capture_receipt")?;
        }
        // #2862: the three owner-evidence commitments. Each is shape-checked and
        // each is DIGEST-BOUND, so a present value cannot be edited in place
        // without moving `identity_digest` and failing the check below.
        if let Some(handle) = &self.archive_handle {
            handle.validate()?;
        }
        if let Some(digest) = &self.capture_receipt_digest {
            validate_digest(digest, "backup_verify_identity_capture_receipt_digest")?;
        }
        if let Some(digest) = &self.validity_attestation_digest {
            validate_digest(digest, "backup_verify_identity_validity_attestation_digest")?;
        }
        if self.identity_digest != self.compute_digest()? {
            return Err(OrsError::InvalidField {
                field: "backup_verify_identity_identity_digest",
                reason: "identity digest mismatch",
            });
        }
        Ok(())
    }
}

/// Exact preimage of one `backup.verify` canonical request hash (I5.27
/// `canonical_request_hash`).
///
/// This is a dedicated borrowed preimage rather than the full identity with
/// fields blanked, and that choice is what makes "which fields are identity and
/// which are ambient" a single reviewable list instead of a convention spread over
/// mutation calls. The same shape `ProcessEvidenceRecordIdentity` uses for the
/// same reason.
///
/// The excluded set is exactly `identity_digest` plus the three ambient
/// observation fields `session_id`, `resource_generation` and `authority_epoch`, and
/// the authority LINEAGE is in here while the sequence is not — the lineage is
/// identity and the sequence is ambient, and the lineage is read from
/// `authority_epoch.lineage_id` so the recorded epoch is still the single source.
///
/// Be honest about the limit of that: the field list below is complete and exact
/// today, and an ambient field cannot start moving the hash because it is not
/// mentioned here, but a NEWLY ADDED identity field would be silently omitted until
/// someone adds it to this list. Nothing enforces the completeness. See
/// [`BackupVerifyRequestIdentity::compute_digest`] for what does catch it and what
/// is deferred to the test phase.
#[derive(Serialize)]
struct BackupVerifyIdentityPreimage<'a> {
    profile_id: &'a str,
    profile_version: u16,
    domain_separator: &'a str,
    idempotency_namespace: &'a str,
    canonical_encoding_version: u16,
    semantic_command_kind: &'a str,
    principal: &'a str,
    capability: &'a str,
    scope_id: &'a str,
    operation_id: &'a str,
    authority_lineage_id: &'a str,
    archive_sha256: &'a str,
    archive_owner_contract: &'a str,
    archive_source_installation: &'a str,
    archive_export_fence_digest: &'a str,
    archived_fence_digest: &'a str,
    evidenced_class: &'a str,
    capture_receipt: &'a Option<String>,
    /// #2862: the three OWNER-EVIDENCE commitments. All three are digest-bound,
    /// which is what makes a changed handle, a changed capture receipt and a
    /// changed validity attestation each an I5.27 identity conflict under one
    /// operation identity rather than a second answer.
    archive_handle: &'a Option<BackupVerifyArchiveHandleRef>,
    capture_receipt_digest: &'a Option<String>,
    validity_attestation_digest: &'a Option<String>,
    retention_and_collision_window: &'a str,
}

impl<'a> From<&'a BackupVerifyRequestIdentity> for BackupVerifyIdentityPreimage<'a> {
    fn from(identity: &'a BackupVerifyRequestIdentity) -> Self {
        Self {
            profile_id: identity.profile_id.as_str(),
            profile_version: identity.profile_version,
            domain_separator: identity.domain_separator.as_str(),
            idempotency_namespace: identity.idempotency_namespace.as_str(),
            canonical_encoding_version: identity.canonical_encoding_version,
            semantic_command_kind: identity.semantic_command_kind.as_str(),
            principal: identity.principal.as_str(),
            capability: identity.capability.as_str(),
            scope_id: identity.scope_id.as_str(),
            operation_id: identity.operation_id.as_str(),
            authority_lineage_id: identity.authority_epoch.lineage_id.as_str(),
            archive_sha256: identity.archive_sha256.as_str(),
            archive_owner_contract: identity.archive_owner_contract.as_str(),
            archive_source_installation: identity.archive_source_installation.as_str(),
            archive_export_fence_digest: identity.archive_export_fence_digest.as_str(),
            // #2863: the archived complete fence is caller-presented evidence and
            // is digest-bound. `observed_fence_digest` is deliberately NOT here —
            // it is ambient with `resource_generation` and `authority_epoch`, and
            // the field's own doc states that consequence.
            archived_fence_digest: identity.archived_fence_digest.as_str(),
            evidenced_class: identity.evidenced_class.as_str(),
            capture_receipt: &identity.capture_receipt,
            archive_handle: &identity.archive_handle,
            capture_receipt_digest: &identity.capture_receipt_digest,
            validity_attestation_digest: &identity.validity_attestation_digest,
            retention_and_collision_window: identity.retention_and_collision_window.as_str(),
        }
    }
}

/// Closed P-04 host-request kinds preserved by ORS without interpretation.
///
/// The kind is an opaque routing label. ORS never interprets task, scope,
/// payload, or semantic meaning from it; it only enforces that one operation
/// identity is never rebound across kinds or bindings.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostRequestKind {
    Activation,
    Invocation,
    Cancellation,
    Status,
    Reconciliation,
}

/// Durable P-04 host-request operation state.
///
/// `PossiblyEffected` is the anti-blind-retry fence: once an operation may
/// have produced an external or canonical effect it can only move forward to
/// `ResultReceived` through reconciliation evidence, or to `Unknown` /
/// `Reconciling`. It can never return to `Routed` or `Submitted`.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostRequestState {
    Requested,
    Admitted,
    Routed,
    Submitted,
    PossiblyEffected,
    ResultReceived,
    Cancelled,
    Expired,
    Conflicted,
    Unknown,
    Reconciling,
    Terminal,
}

/// Durable owner for one daemon attempt at an admitted host request.
///
/// The attempt is stored on the same ORS row as the operation and its State
/// Fence. A competing v1 claimant receives the durable winner unchanged. An
/// expired possible-effect claim moves the row to `Unknown` while retaining
/// this owner binding for reconciliation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequestAttempt {
    pub attempt_id: OpaqueLabel,
    pub generation: u64,
    /// Absolute lease expiry for this claim, present only in the v1 custody
    /// protocol. Expiry is reconciliation evidence, never permission to resend.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_expires_at_unix_ms: Option<u64>,
    pub fence_digest: String,
    pub owner_connection_ref: OpaqueLabel,
    pub owner_launch_nonce: OpaqueLabel,
    pub owner_session_epoch: u64,
    pub phase: HostRequestAttemptPhase,
    /// Commitment to the exact retained executable ToolRequest and its
    /// protected recovery envelope. Absent only on legacy attempts.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_commitment_sha256: Option<String>,
    /// Authenticated Host channel committed at claim acquisition. Legacy
    /// protocol-zero attempts have no channel binding.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_binding_sha256: Option<String>,
    /// Bounded, append-only custody observations for this exact claim.
    ///
    /// Empty only on a legacy row or a freshly claimed attempt. ORS owns the
    /// monotonic append sequence; callers cannot replace earlier evidence.
    #[serde(default)]
    pub transport_observations: Vec<HostRequestTransportObservation>,
    /// Cross-restart exact owner readback, authenticated on its own channel.
    /// This is separate from the original send-channel observation history.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_readback: Option<HostRequestOwnerReadbackEvidence>,
}

/// The exact parent attempt observed when one durable cancellation operation
/// first records its intent. `None` represents an explicit observation that
/// the parent had no claimed attempt in the same ORS transaction.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequestCancellationAttempt {
    pub attempt_id: OpaqueLabel,
    pub generation: u64,
}

/// The parent target and observed disposition durably bound to one
/// cancellation operation row. The operation row itself supplies the
/// cancellation operation identity and request digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequestCancellationTarget {
    pub parent_operation_id: OperationIdentity,
    pub parent_request_digest: String,
    pub attempt: Option<HostRequestCancellationAttempt>,
    pub parent_disposition: HostRequestState,
}

impl HostRequestCancellationTarget {
    fn validate(&self) -> Result<(), OrsError> {
        validate_text(
            self.parent_operation_id.as_str(),
            "host_request_cancellation_parent_operation_id",
        )?;
        validate_digest(
            &self.parent_request_digest,
            "host_request_cancellation_parent_request_digest",
        )?;
        if let Some(attempt) = &self.attempt {
            validate_text(
                attempt.attempt_id.as_str(),
                "host_request_cancellation_attempt_id",
            )?;
            if attempt.generation == 0 {
                return Err(OrsError::InvalidField {
                    field: "host_request_cancellation_attempt_generation",
                    reason: "must be non-zero",
                });
            }
        }
        Ok(())
    }
}

/// Durable transport custody of a daemon attempt.
///
/// These values live in the existing attempt slot so they remain bound to the
/// exact claim without a parallel queue or process-local status. `Claimed` is
/// the pre-dispatch state; the remaining variants are owner-observed transport
/// boundaries and never derive from error prose.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostRequestAttemptPhase {
    /// Claim was persisted, but no transport boundary has been observed yet.
    Claimed,
    /// The owner durably fenced the attempt before entering the transport.
    /// A restart treats this as possible delivery, never as no-effect proof.
    DispatchStarted,
    /// The exact request was proven not to have been sent.
    DefinitelyNotSent,
    /// The transport could not determine whether the request reached the Host.
    DeliveryOutcomeUnknown,
    /// The request was delivered over the authenticated Host channel.
    DeliveredToAuthenticatedHost,
    /// A complete response was received; its result body may still be unretained.
    ResponseReceived,
    /// Compatibility disposition for an older explicit no-effect deferral.
    DeferredNoEffect,
}

/// Typed transport-custody state exposed to the request owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostRequestTransportCustody {
    /// The authenticated Host transport proves no request bytes were sent.
    DefinitelyNotSent,
    /// The transport crossed an uncertainty boundary without a delivery proof.
    DeliveryOutcomeUnknown,
    /// The request bytes were delivered to the authenticated Host owner.
    DeliveredToAuthenticatedHost,
    /// A complete, identity-validated response was received from the Host.
    ResponseReceived,
}

/// Last durable transport boundary retained under one exact `HostRequest` claim.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostRequestTransportBoundary {
    /// The durable pre-send fence was written before calling the transport.
    DispatchStarted,
    /// A typed local/transport proof establishes that no request bytes were sent.
    DefinitelyNotSent,
    /// The transport owner could not determine whether the request was sent.
    DeliveryOutcomeUnknown,
    /// The authenticated Host channel reported a complete frame write.
    DeliveredToAuthenticatedHost,
    /// An identity-validated Host response or exact owner readback was received.
    ResponseReceived,
}

/// Closed source class for a typed no-send proof. Free-form error text is not
/// retained or interpreted as transport custody.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostRequestNoSendProof {
    /// Request/frame validation failed before the named-pipe write boundary.
    RequestRejectedBeforeWrite,
    /// The authenticated transport rejected peer/frame preflight before write.
    AuthenticatedTransportPreflightRejected,
}

/// Existing named-pipe delivery observation, transcribed without upgrading it
/// to an application commit receipt.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostRequestDeliveryReceipt {
    /// IPC `DeliveryOutcome::Delivered`: the complete frame was written.
    Delivered,
    /// IPC `DeliveryOutcome::UnknownOutcome`: bytes may have reached the peer.
    UnknownOutcome,
}

/// Provenance of a response commitment retained for this operation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostRequestResponseSource {
    /// Response came from the in-flight authenticated transport exchange.
    AuthenticatedTransport,
}

/// One immutable, identity-bound transport observation retained on its claim.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequestTransportObservation {
    /// Parent ORS operation this observation belongs to.
    pub operation_id: OperationIdentity,
    /// Exact parent request digest this observation belongs to.
    pub request_digest: String,
    /// Exact attempt identity this observation belongs to.
    pub attempt_id: OpaqueLabel,
    /// Exact attempt generation this observation belongs to.
    pub attempt_generation: u64,
    /// Last source-backed boundary observed by the authenticated client.
    pub boundary: HostRequestTransportBoundary,
    /// Digest of the existing authenticated Host channel binding.
    pub channel_binding_sha256: String,
    /// Digest of the exact typed transport request carrier sent on that
    /// authenticated channel. Every observation in this claim repeats it.
    pub transport_request_sha256: String,
    /// Exact retained `HostRequest` operation commitment.
    pub request_commitment_sha256: String,
    /// Exact retained `HostRequest` payload commitment from the admitted row.
    pub payload_commitment_sha256: String,
    /// Present only when the named-pipe send boundary returned an outcome.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_receipt: Option<HostRequestDeliveryReceipt>,
    /// Present only when a complete response body was identity-validated.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_commitment_sha256: Option<String>,
    /// Source that supplied the response commitment.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_source: Option<HostRequestResponseSource>,
    /// Present only for a typed proof that the write did not occur.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_send_proof: Option<HostRequestNoSendProof>,
}

impl HostRequestTransportObservation {
    #[allow(
        clippy::too_many_lines,
        reason = "the exact observation identity and custody fields are validated as one boundary"
    )]
    pub(crate) fn validate_for(
        &self,
        record: &HostRequestRecord,
        attempt: &HostRequestAttempt,
    ) -> Result<(), OrsError> {
        if self.operation_id != record.operation_id
            || self.request_digest != record.request_digest
            || self.attempt_id != attempt.attempt_id
            || self.attempt_generation != attempt.generation
        {
            return Err(OrsError::HostRequestIdentityConflict {
                operation_id: record.operation_id.as_str().to_owned(),
                request_digest: record.request_digest.clone(),
            });
        }
        validate_digest(
            &self.channel_binding_sha256,
            "host_request_transport_channel_binding_sha256",
        )?;
        validate_digest(
            &self.transport_request_sha256,
            "host_request_transport_request_sha256",
        )?;
        validate_digest(
            &self.request_commitment_sha256,
            "host_request_transport_request_commitment_sha256",
        )?;
        validate_digest(
            &self.payload_commitment_sha256,
            "host_request_transport_payload_commitment_sha256",
        )?;
        if self.request_commitment_sha256 != record.request_digest
            || self.payload_commitment_sha256 != record.payload_digest
            || record.transport_channel_binding_sha256.as_deref()
                != Some(self.channel_binding_sha256.as_str())
            || attempt.channel_binding_sha256.as_deref()
                != Some(self.channel_binding_sha256.as_str())
            || attempt.transport_observations.first().is_some_and(|first| {
                first.channel_binding_sha256 != self.channel_binding_sha256
                    || first.transport_request_sha256 != self.transport_request_sha256
            })
        {
            return Err(OrsError::HostRequestIdentityConflict {
                operation_id: record.operation_id.as_str().to_owned(),
                request_digest: record.request_digest.clone(),
            });
        }
        match self.boundary {
            HostRequestTransportBoundary::DispatchStarted => {
                if self.delivery_receipt.is_some()
                    || self.response_commitment_sha256.is_some()
                    || self.response_source.is_some()
                    || self.no_send_proof.is_some()
                {
                    return Err(OrsError::InvalidField {
                        field: "host_request_transport_observation",
                        reason: "dispatch-started evidence cannot carry a send result or response",
                    });
                }
            }
            HostRequestTransportBoundary::DefinitelyNotSent => {
                if self.no_send_proof.is_none()
                    || self.delivery_receipt.is_some()
                    || self.response_commitment_sha256.is_some()
                    || self.response_source.is_some()
                {
                    return Err(OrsError::InvalidField {
                        field: "host_request_transport_observation",
                        reason: "no-send evidence requires a typed proof and no send/response receipt",
                    });
                }
            }
            HostRequestTransportBoundary::DeliveryOutcomeUnknown => {
                if self.delivery_receipt != Some(HostRequestDeliveryReceipt::UnknownOutcome)
                    || self.response_commitment_sha256.is_some()
                    || self.response_source.is_some()
                    || self.no_send_proof.is_some()
                {
                    return Err(OrsError::InvalidField {
                        field: "host_request_transport_observation",
                        reason: "unknown delivery requires the matching typed IPC outcome only",
                    });
                }
            }
            HostRequestTransportBoundary::DeliveredToAuthenticatedHost => {
                if self.delivery_receipt != Some(HostRequestDeliveryReceipt::Delivered)
                    || self.response_commitment_sha256.is_some()
                    || self.response_source.is_some()
                    || self.no_send_proof.is_some()
                {
                    return Err(OrsError::InvalidField {
                        field: "host_request_transport_observation",
                        reason: "delivery requires the matching typed IPC outcome only",
                    });
                }
            }
            HostRequestTransportBoundary::ResponseReceived => {
                let Some(response_commitment) = self.response_commitment_sha256.as_deref() else {
                    return Err(OrsError::InvalidField {
                        field: "host_request_transport_response_commitment",
                        reason: "response observation requires its exact response commitment",
                    });
                };
                validate_digest(
                    response_commitment,
                    "host_request_transport_response_commitment_sha256",
                )?;
                if self.response_source != Some(HostRequestResponseSource::AuthenticatedTransport)
                    || self.no_send_proof.is_some()
                {
                    return Err(OrsError::InvalidField {
                        field: "host_request_transport_observation",
                        reason: "response observation requires authenticated transport source and no no-send proof",
                    });
                }
            }
        }
        Ok(())
    }
}

/// Exact authenticated Host owner receipt retained for cross-restart
/// reconciliation. This evidence does not replace or rewrite the original
/// transport channel observations.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequestOwnerReadbackEvidence {
    /// Original ORS operation identity being reconciled.
    pub operation_id: OperationIdentity,
    /// Original ORS request commitment being reconciled.
    pub request_digest: String,
    /// Original exact admitted payload commitment.
    pub payload_digest: String,
    /// Original send attempt being reconciled.
    pub attempt_id: OpaqueLabel,
    /// Original send attempt generation being reconciled.
    pub attempt_generation: u64,
    /// New authenticated channel that returned the exact owner receipt.
    pub readback_channel_binding_sha256: String,
    /// Canonical commitment of the exact owner record and journal receipt.
    pub owner_receipt_commitment_sha256: String,
    /// Canonical commitment of the exact result projected to the caller.
    pub result_commitment_sha256: String,
}

impl HostRequestOwnerReadbackEvidence {
    pub(crate) fn validate_for(
        &self,
        record: &HostRequestRecord,
        attempt: &HostRequestAttempt,
    ) -> Result<(), OrsError> {
        if self.operation_id != record.operation_id
            || self.request_digest != record.request_digest
            || self.payload_digest != record.payload_digest
            || self.attempt_id != attempt.attempt_id
            || self.attempt_generation != attempt.generation
        {
            return Err(OrsError::HostRequestIdentityConflict {
                operation_id: record.operation_id.as_str().to_owned(),
                request_digest: record.request_digest.clone(),
            });
        }
        for (digest, field) in [
            (
                self.readback_channel_binding_sha256.as_str(),
                "host_request_owner_readback_channel_binding_sha256",
            ),
            (
                self.owner_receipt_commitment_sha256.as_str(),
                "host_request_owner_receipt_commitment_sha256",
            ),
            (
                self.result_commitment_sha256.as_str(),
                "host_request_owner_readback_result_commitment_sha256",
            ),
        ] {
            validate_digest(digest, field)?;
        }
        Ok(())
    }
}

impl HostRequestAttemptPhase {
    /// Returns the durable custody observation, if this phase carries one.
    pub const fn transport_custody(self) -> Option<HostRequestTransportCustody> {
        match self {
            Self::Claimed | Self::DispatchStarted | Self::DeliveryOutcomeUnknown => {
                Some(HostRequestTransportCustody::DeliveryOutcomeUnknown)
            }
            Self::DefinitelyNotSent | Self::DeferredNoEffect => {
                Some(HostRequestTransportCustody::DefinitelyNotSent)
            }
            Self::DeliveredToAuthenticatedHost => {
                Some(HostRequestTransportCustody::DeliveredToAuthenticatedHost)
            }
            Self::ResponseReceived => Some(HostRequestTransportCustody::ResponseReceived),
        }
    }
}

impl HostRequestAttempt {
    /// Compares one attempt's immutable claim identity, excluding the mutable
    /// transport-custody phase.
    pub(crate) fn same_claim(&self, other: &Self) -> bool {
        self.attempt_id == other.attempt_id
            && self.generation == other.generation
            && self.claim_expires_at_unix_ms == other.claim_expires_at_unix_ms
            && self.fence_digest == other.fence_digest
            && self.owner_connection_ref == other.owner_connection_ref
            && self.owner_launch_nonce == other.owner_launch_nonce
            && self.owner_session_epoch == other.owner_session_epoch
            && self.input_commitment_sha256 == other.input_commitment_sha256
            && self.channel_binding_sha256 == other.channel_binding_sha256
    }

    pub(crate) fn validate(&self, fence_digest: &str) -> Result<(), OrsError> {
        validate_text(self.attempt_id.as_str(), "host_request_attempt_id")?;
        validate_text(
            self.owner_connection_ref.as_str(),
            "host_request_attempt_connection",
        )?;
        validate_text(
            self.owner_launch_nonce.as_str(),
            "host_request_attempt_launch_nonce",
        )?;
        if self.generation == 0 || self.owner_session_epoch == 0 {
            return Err(OrsError::InvalidField {
                field: "host_request_attempt_generation",
                reason: "generation and session epoch must be non-zero",
            });
        }
        if self.claim_expires_at_unix_ms == Some(0) {
            return Err(OrsError::InvalidField {
                field: "host_request_attempt_claim_expiry",
                reason: "claim expiry must be greater than zero",
            });
        }
        validate_digest(&self.fence_digest, "host_request_attempt_fence_digest")?;
        if let Some(channel_binding_sha256) = &self.channel_binding_sha256 {
            validate_digest(
                channel_binding_sha256,
                "host_request_attempt_channel_binding_sha256",
            )?;
        }
        if let Some(input_commitment_sha256) = &self.input_commitment_sha256 {
            validate_digest(input_commitment_sha256, "host_request_attempt_input_commitment")?;
        }
        if self.fence_digest != fence_digest {
            return Err(OrsError::FenceMismatch);
        }
        Ok(())
    }
}

impl HostRequestState {
    /// Returns whether the state closes the operation.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ResultReceived
                | Self::Cancelled
                | Self::Expired
                | Self::Conflicted
                | Self::Terminal
        )
    }

    /// Validates one mechanical state advance without interpreting meaning.
    pub fn transition_to(self, next: Self) -> Result<Self, OrsError> {
        let legal = matches!(
            (self, next),
            (
                Self::Requested,
                Self::Admitted | Self::Expired | Self::Conflicted | Self::Unknown
            ) | (
                Self::Admitted,
                Self::Routed | Self::Cancelled | Self::Expired | Self::Conflicted | Self::Unknown
            ) | (
                Self::Routed,
                Self::Submitted
                    | Self::Cancelled
                    | Self::Expired
                    | Self::Conflicted
                    | Self::Unknown
            ) | (
                Self::Submitted,
                Self::PossiblyEffected
                    | Self::ResultReceived
                    | Self::Cancelled
                    | Self::Expired
                    | Self::Conflicted
                    | Self::Unknown
            ) | (
                Self::PossiblyEffected,
                Self::ResultReceived | Self::Unknown | Self::Reconciling
            ) | (
                Self::Unknown,
                Self::Reconciling | Self::ResultReceived | Self::Cancelled | Self::Expired
            ) | (
                Self::Reconciling,
                Self::ResultReceived
                    | Self::Cancelled
                    | Self::Expired
                    | Self::Unknown
                    | Self::Conflicted
            ) | (
                Self::ResultReceived | Self::Cancelled | Self::Expired | Self::Conflicted,
                Self::Terminal
            )
        );
        legal.then_some(next).ok_or(OrsError::InvalidTransition)
    }
}

/// Executor-observed effect and evidence references retained with one
/// host-request completion (issue #1853 W2).
///
/// Every value is opaque to ORS exactly like the rest of the host-request row:
/// ORS stores the references the executing leg observed, never interprets a
/// route, an executor, or a side effect, and never grants authority from them.
///
/// The three identity fields are what makes the reference BOUND rather than
/// merely present. [`HostRequestEffectEvidence::validate`] compares the
/// originally recorded values against the owning row — not against a freshly
/// recomputed checksum of whatever the reader happens to hold — so evidence
/// recorded for one operation can never be read back as proof about another:
///
/// * `operation_id` must be this row's own operation identity;
/// * `input_handle` must be this row's `request_digest`, the admitted envelope
///   digest the evidence observed as its immutable input;
/// * `output_handle` must be this row's `result_digest`, the canonical result
///   digest the evidence observed as its immutable output.
///
/// The observation slots are optional because a leg reports exactly what it
/// observed; an absent slot stays absent and is never invented here.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequestEffectEvidence {
    /// Exact `hostreq:<sha>` operation handle this evidence observes.
    pub operation_id: OpaqueLabel,
    /// Immutable input handle observed by the executor: the envelope digest.
    pub input_handle: Option<String>,
    /// Immutable output handle observed by the executor: the result digest.
    pub output_handle: Option<String>,
    /// Observed side-effect declaration, or the reference to the effect.
    pub side_effects: Option<String>,
    /// Actual route taken, as observed by the executor.
    pub actual_route: Option<String>,
    /// Invoked local-port operation.
    pub invoked_operation: Option<String>,
    /// Presenting transport adapter instance.
    pub adapter_identity: Option<String>,
    /// Executing-process identity.
    pub executor_identity: Option<String>,
}

impl HostRequestEffectEvidence {
    /// Binds this evidence to the one operation and result that own it.
    ///
    /// `operation_id`, `request_digest`, and `result_digest` are the values
    /// read back from the durable row. Every comparison below uses the
    /// originally recorded value on this struct; nothing is re-derived here,
    /// so a reader that lost the original bytes cannot pass this check with a
    /// fresh checksum over the wrong subject.
    pub(crate) fn validate(
        &self,
        operation_id: &OperationIdentity,
        request_digest: &str,
        result_digest: &str,
    ) -> Result<(), OrsError> {
        if self.operation_id != *operation_id {
            return Err(OrsError::InvalidField {
                field: "host_request_effect_evidence_operation_id",
                reason: "retained evidence does not observe this operation",
            });
        }
        if let Some(input_handle) = &self.input_handle {
            validate_digest(input_handle, "host_request_effect_evidence_input_handle")?;
            if input_handle != request_digest {
                return Err(OrsError::InvalidField {
                    field: "host_request_effect_evidence_input_handle",
                    reason: "retained input handle does not bind the admitted envelope digest",
                });
            }
        }
        if let Some(output_handle) = &self.output_handle {
            validate_digest(output_handle, "host_request_effect_evidence_output_handle")?;
            if output_handle != result_digest {
                return Err(OrsError::InvalidField {
                    field: "host_request_effect_evidence_output_handle",
                    reason: "retained output handle does not bind the retained result digest",
                });
            }
        }
        for (reference, field) in [
            (
                &self.side_effects,
                "host_request_effect_evidence_side_effects",
            ),
            (
                &self.actual_route,
                "host_request_effect_evidence_actual_route",
            ),
            (
                &self.invoked_operation,
                "host_request_effect_evidence_invoked_operation",
            ),
            (
                &self.adapter_identity,
                "host_request_effect_evidence_adapter_identity",
            ),
            (
                &self.executor_identity,
                "host_request_effect_evidence_executor_identity",
            ),
        ] {
            if let Some(reference) = reference {
                validate_text(reference, field)?;
            }
        }
        Ok(())
    }
}

/// Default for a retained result lineage that omits its influence state.
///
/// Fail-closed, exactly as on the wire contract: a lineage that does not name
/// its influence is `Unknown`, never `Active`.
const fn unknown_retained_influence() -> InfluenceState {
    InfluenceState::Unknown
}

/// ORS-retained source revision head observed for one local read.
///
/// Mirrors the wire contract's source-revision shape field for field. It exists
/// only because `eliot-ors` deliberately holds no edge to the wire crate, so it
/// changes no field's type or meaning: `revision` is the same non-zero observed
/// revision, `state_fence` is the same [`eliot_contracts::StateFence`], and
/// `key` is the same opaque source revision key.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequestRetainedSourceRevision {
    /// Exact opaque source revision key.
    pub key: String,
    /// Nonzero revision observed for `key`.
    pub revision: u64,
    /// Fence attached to this particular revision head.
    pub state_fence: StateFence,
}

/// ORS-retained result lineage for one completed host request (issue #1853 W2).
///
/// This is the durable retention envelope for the result-side lineage the
/// read owner submitted with the result. It carries claims and references
/// only, with the wire contract's own meaning unchanged: it does not
/// authenticate an origin, establish semantic truth, or promote a model
/// result, and ORS never interprets any field. Every optional field keeps the
/// wire meaning of `None` — **unknown or unavailable, never clean** — which is
/// why `influence_state` defaults to [`InfluenceState::Unknown`] instead of an
/// active or cleared state.
///
/// Retaining it beside the result is what lets a replayer read the result's
/// provenance back off the row instead of losing it at the authority boundary.
/// See [`Self::validate`] for the binding that makes the retained lineage
/// attributable to one operation rather than merely present.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequestRetainedLineage {
    /// Optional immutable artifact handle for the exact output bytes.
    pub output_artifact_ref: Option<String>,
    /// SHA-256 of the exact parent response bytes. Bound to this row's own
    /// `result_digest` by [`Self::validate`].
    pub output_digest: String,
    /// Authenticated producer principal/service reference, when available.
    pub producer_ref: Option<String>,
    /// Exact source revision heads. `None` means source revision coverage is
    /// unknown; each known head retains its own fence.
    pub source_revisions: Option<Vec<HostRequestRetainedSourceRevision>>,
    /// Fence bound to the named read itself, distinct from per-head fences.
    pub source_state_fence: Option<StateFence>,
    /// Exact source or intermediate input references, when available.
    pub input_refs: Option<Vec<String>>,
    /// Existing typed transformation/taint lineage, in source-to-output order.
    pub transformation_lineage: Option<Vec<TransformationLineage>>,
    /// Inherited disclosure/taint closure references, when available.
    pub closure_refs: Option<Vec<String>>,
    /// Applicable policy snapshot and its exact fence, when available.
    pub policy_fence: Option<PolicyFence>,
    /// References to origin-authentication evidence; presence is not itself
    /// authentication because the referenced evidence must be verified by its
    /// owner. A reference never qualifies the record: only
    /// [`Self::semantic_receipt_ref`] does, and only for
    /// [`HostRequestRetainedResultClass::CanonicalWriteReceipt`].
    pub origin_evidence_refs: Option<Vec<String>>,
    /// Exact admitted semantic receipt this record repeats. `Some` only for
    /// [`HostRequestRetainedResultClass::CanonicalWriteReceipt`], so a retained
    /// read, candidate or delivery row can never be read back as an admitted
    /// semantic record.
    pub semantic_receipt_ref: Option<String>,
    /// Which kind of record these retained bytes are. `Unclassified` for rows
    /// written before the field existed: an explicit unknown that ORS never
    /// upgrades.
    #[serde(default = "unclassified_retained_result_class")]
    pub result_class: HostRequestRetainedResultClass,
    /// Maximum receipt interpretation, not a semantic truth/admission status.
    pub proof_ceiling: Option<ProofCeiling>,
    /// Influence is fail-closed when omitted.
    #[serde(default = "unknown_retained_influence")]
    pub influence_state: InfluenceState,
    /// Instruction/data taint. `None` means unknown, not cleared.
    pub instruction_taint: Option<InstructionTaint>,
}

/// The distinct result classes a retained host-request result can actually be.
///
/// Field for field the same classes the wire carrier admits, mirrored rather
/// than redefined because `eliot-ors` holds no edge to the wire crate. The
/// meaning is identical, and `eliot-ors` interprets no field of it: a stored
/// row keeps the class its producer claimed, and the only check is that a
/// class is not stronger than the receipt the row carries.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostRequestRetainedResultClass {
    /// A stored row that predates the class field, or a producer that named
    /// none. Unknown provenance; never an admitted class.
    Unclassified,
    /// A read of already-retained canonical evidence, served with its actual
    /// revision and provenance. It creates no new semantic record.
    ExistingEvidenceRead,
    /// Newly produced model or untrusted output. Candidate only.
    NewCandidate,
    /// A verifier or reconciliation observation about a completion.
    VerifierObservation,
    /// A canonical `WriteReceipt`-backed semantic record.
    CanonicalWriteReceipt,
    /// A retained response or delivery record for an already-completed
    /// operation. It records that bytes were sent; it admits nothing.
    RetainedDeliveryRecord,
}

const fn unclassified_retained_result_class() -> HostRequestRetainedResultClass {
    HostRequestRetainedResultClass::Unclassified
}

impl HostRequestRetainedLineage {
    /// Binds this retained lineage to the one result it describes.
    ///
    /// `result_digest` is read back from the durable row. The comparison below
    /// uses the ORIGINALLY RECORDED `output_digest` and nothing is re-derived
    /// here, so a reader cannot pass this check with a fresh checksum taken
    /// over whatever it happens to be holding.
    ///
    /// Scope of the binding, stated exactly: `output_digest` is the only
    /// lineage field with a counterpart recorded on
    /// [`HostRequestRecord`]. Every other retained field describes content the
    /// row does not record — a source revision head, a policy snapshot, a
    /// transformation — so binding it would require either inventing a value on
    /// the row or re-deriving one. Both are forbidden, so neither is done; those
    /// fields are retained and bounded, and their meaning stays owned by
    /// [`eliot_security_contracts::TransformationLineage::validate`] and the
    /// wire contract's own lineage validation at the submission boundary.
    pub(crate) fn validate(&self, result_digest: &str) -> Result<(), OrsError> {
        validate_digest(
            &self.output_digest,
            "host_request_retained_lineage_output_digest",
        )?;
        if self.output_digest != result_digest {
            return Err(OrsError::InvalidField {
                field: "host_request_retained_lineage_output_digest",
                reason: "retained lineage does not bind the retained result digest",
            });
        }
        for (reference, field) in [
            (
                &self.output_artifact_ref,
                "host_request_retained_lineage_output_artifact_ref",
            ),
            (
                &self.producer_ref,
                "host_request_retained_lineage_producer_ref",
            ),
        ] {
            if let Some(reference) = reference {
                validate_text(reference, field)?;
            }
        }
        for (references, field) in [
            (&self.input_refs, "host_request_retained_lineage_input_refs"),
            (
                &self.closure_refs,
                "host_request_retained_lineage_closure_refs",
            ),
            (
                &self.origin_evidence_refs,
                "host_request_retained_lineage_origin_evidence_refs",
            ),
        ] {
            if let Some(references) = references {
                validate_unique_texts(references, field)?;
            }
        }
        if let Some(fence) = &self.source_state_fence {
            fence.validate().map_err(|_| OrsError::InvalidField {
                field: "host_request_retained_lineage_source_state_fence",
                reason: "retained source fence is not a valid state fence",
            })?;
        }
        if let Some(revisions) = &self.source_revisions {
            let mut keys = BTreeSet::new();
            for revision in revisions {
                validate_text(
                    &revision.key,
                    "host_request_retained_lineage_source_revision_key",
                )?;
                if !keys.insert(&revision.key) {
                    return Err(OrsError::InvalidField {
                        field: "host_request_retained_lineage_source_revision_keys",
                        reason: "retained source revision keys must be unique",
                    });
                }
                if revision.revision == 0 {
                    return Err(OrsError::InvalidField {
                        field: "host_request_retained_lineage_source_revision",
                        reason: "retained source revision must be non-zero",
                    });
                }
                revision
                    .state_fence
                    .validate()
                    .map_err(|_| OrsError::InvalidField {
                        field: "host_request_retained_lineage_source_revision_state_fence",
                        reason: "retained source revision fence is not a valid state fence",
                    })?;
            }
        }
        if let Some(policy_fence) = &self.policy_fence {
            validate_text(
                &policy_fence.policy_snapshot_id,
                "host_request_retained_lineage_policy_snapshot_id",
            )?;
            policy_fence
                .state_fence
                .validate()
                .map_err(|_| OrsError::InvalidField {
                    field: "host_request_retained_lineage_policy_state_fence",
                    reason: "retained policy fence is not a valid state fence",
                })?;
        }
        if let Some(transformations) = &self.transformation_lineage {
            for transformation in transformations {
                transformation
                    .validate()
                    .map_err(|_| OrsError::InvalidField {
                        field: "host_request_retained_lineage_transformation",
                        reason: "retained transformation lineage did not validate",
                    })?;
            }
        }
        self.validate_taint_claim()?;
        self.validate_class()?;
        Ok(())
    }

    /// Refuses a retained CLEAN instruction-taint claim no named transformation
    /// supports (issue #1809 item 2).
    ///
    /// The wire carrier's rule, mirrored rather than reinterpreted so a row
    /// cannot be retained that the submission gate would have refused, and so a
    /// replayer reads back the same refusal. `None` keeps its documented
    /// meaning — unknown, not cleared — and every current producer submits it.
    ///
    /// The check stays one-directional: it does not decide any real result's
    /// taint, and it never mints a clearance. It refuses only an affirmative
    /// clean claim whose own final named transformation does not end cleared,
    /// which is the retained form of the rule that a metadata field, a
    /// sanitizer reference or a successful serialization is not a verified
    /// declassification (I15.6, I15.12).
    fn validate_taint_claim(&self) -> Result<(), OrsError> {
        if !matches!(self.instruction_taint, Some(InstructionTaint::Cleared)) {
            return Ok(());
        }
        let cleared_by_named_transformation =
            self.transformation_lineage
                .as_ref()
                .is_some_and(|transformations| {
                    transformations
                        .last()
                        .is_some_and(|last| last.output_taint == InstructionTaint::Cleared)
                });
        if !cleared_by_named_transformation {
            return Err(OrsError::InvalidField {
                field: "host_request_retained_lineage_instruction_taint",
                reason: "a retained cleared taint claim must name its final transformation",
            });
        }
        Ok(())
    }

    /// Refuses a retained class the row's own evidence does not support.
    ///
    /// One-directional, exactly like the wire contract: this can only withhold
    /// a class the record cannot prove and never mints one. `output_digest`,
    /// the origin references and the proof ceiling are deliberately not
    /// consulted — a matching digest proves byte identity and a reference
    /// proves that some evidence exists, and neither is the admitted semantic
    /// receipt (I15.19, I15.6).
    fn validate_class(&self) -> Result<(), OrsError> {
        let unsupported = |reason: &'static str| OrsError::InvalidField {
            field: "host_request_retained_lineage_result_class",
            reason,
        };
        if self.result_class == HostRequestRetainedResultClass::CanonicalWriteReceipt
            && self.semantic_receipt_ref.is_none()
        {
            return Err(unsupported(
                "a canonical write receipt result requires its exact admitted semantic receipt",
            ));
        }
        if self.result_class != HostRequestRetainedResultClass::CanonicalWriteReceipt
            && self.semantic_receipt_ref.is_some()
        {
            return Err(unsupported(
                "only a canonical write receipt result may carry a semantic receipt reference",
            ));
        }
        if let Some(receipt) = &self.semantic_receipt_ref {
            validate_text(
                receipt,
                "host_request_retained_lineage_semantic_receipt_ref",
            )?;
        }
        Ok(())
    }
}

/// Validates a retained bounded reference list: non-blank, control-free,
/// length-bounded, and free of duplicates.
fn validate_unique_texts(values: &[String], field: &'static str) -> Result<(), OrsError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_text(value, field)?;
        if !seen.insert(value) {
            return Err(OrsError::InvalidField {
                field,
                reason: "retained references must not contain duplicates",
            });
        }
    }
    Ok(())
}

/// Exact authenticated application decision resolved for an executable host
/// request. ORS validates internal digests and joins the opaque values to the
/// host-request row; it does not interpret activation, task, scope, or policy
/// semantics.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequestApplicationBinding {
    /// Application-binding wire version.
    pub wire_version: u16,
    /// Exact original HostRequestIdentity serialized by the Kernel owner.
    pub request_identity: Value,
    /// Canonical digest of `request_identity`.
    pub request_identity_sha256: String,
    /// Authenticated principal resolved from retained application binding.
    pub principal_ref: OpaqueLabel,
    /// Resolved durable Session.
    pub session_ref: OpaqueLabel,
    /// Resolved task, if one is selected.
    pub task_ref: Option<OpaqueLabel>,
    /// Resolved WorkScope, if one is selected.
    pub scope_ref: Option<OpaqueLabel>,
    /// Exact TaskContract revision, absent for task-free application scope.
    pub task_revision: Option<u64>,
    /// Exact activation State Fence retained by the application owner.
    pub state_fence: StateFence,
    /// Full resolved activation binding as an opaque typed-owner projection.
    pub resolved_application_binding: Option<Value>,
    /// Canonical digest of `resolved_application_binding`.
    pub resolved_application_binding_sha256: Option<String>,
    /// Full authenticated activation owner evidence as an opaque projection.
    pub activation_owner_evidence: Option<Value>,
    /// Canonical digest of `activation_owner_evidence`.
    pub activation_owner_evidence_sha256: Option<String>,
    /// Exact Governor-owned observation-policy binding, including its
    /// persisted Setting and PolicyOwner revision/fence evidence.
    pub observation_policy_binding: Value,
    /// Canonical digest of the exact Governor policy-owner projection.
    pub observation_policy_binding_sha256: String,
    /// Exact retained activation result digest.
    pub activation_result_sha256: Option<String>,
    /// P07 owner revision captured by the admission owner.
    pub p07_revision: Option<u64>,
    /// Exact P07 bundle digest captured by the admission owner.
    pub p07_bundle_sha256: Option<String>,
    /// Clock reading captured at admission and passed unchanged to the daemon.
    pub clock_reading: eliot_contracts::ClockReading,
    /// Kernel-observed admission time in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
}

impl HostRequestApplicationBinding {
    /// Returns the canonical commitment to this exact retained binding.
    pub fn commitment_sha256(&self) -> Result<String, OrsError> {
        let bytes = canonical_json_bytes(self)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    /// Validates this binding against its retained host-request identity.
    pub fn validate_for(&self, record: &HostRequestRecord) -> Result<(), OrsError> {
        if self.wire_version != HOST_REQUEST_EXECUTABLE_INPUT_CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.wire_version));
        }
        let binding_bytes = canonical_json_bytes(self)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        if binding_bytes.len() > MAX_HOST_REQUEST_APPLICATION_BINDING_BYTES {
            return Err(OrsError::PayloadTooLarge);
        }
        self.validate_owner_projections()?;
        self.validate_resolved_binding_fields()?;
        self.validate_clock_and_revisions()?;
        self.validate_fence_binding(record)?;
        self.validate_observation_policy_binding(record)?;
        self.validate_request_identity(record)
    }

    fn validate_owner_projections(&self) -> Result<(), OrsError> {
        Self::validate_projection(
            Some(&self.request_identity),
            Some(&self.request_identity_sha256),
            "host_request_owner_identity",
        )?;
        Self::validate_projection(
            self.resolved_application_binding.as_ref(),
            self.resolved_application_binding_sha256.as_ref(),
            "host_request_resolved_application_binding",
        )?;
        Self::validate_projection(
            self.activation_owner_evidence.as_ref(),
            self.activation_owner_evidence_sha256.as_ref(),
            "host_request_activation_owner_evidence",
        )?;
        Self::validate_projection(
            Some(&self.observation_policy_binding),
            Some(&self.observation_policy_binding_sha256),
            "host_request_observation_policy_binding",
        )?;
        if let Some(digest) = &self.activation_result_sha256 {
            validate_digest(digest, "host_request_activation_result_sha256")?;
        }
        if let Some(digest) = &self.p07_bundle_sha256 {
            validate_digest(digest, "host_request_p07_bundle_sha256")?;
        }
        validate_text(self.principal_ref.as_str(), "host_request_principal_ref")?;
        validate_text(self.session_ref.as_str(), "host_request_resolved_session_ref")?;
        self.validate_activation_projection()?;
        Ok(())
    }

    fn validate_projection(
        value: Option<&Value>,
        digest: Option<&String>,
        field: &'static str,
    ) -> Result<(), OrsError> {
        match (value, digest) {
            (Some(value), Some(digest)) if value.is_object() => {
                let bytes = canonical_json_bytes(value)
                    .map_err(|error| OrsError::Encoding(error.to_string()))?;
                validate_digest(digest, field)?;
                if sha256_hex(&bytes) != *digest {
                    return Err(OrsError::PayloadIntegrityMismatch);
                }
                Ok(())
            }
            (None, None) => Ok(()),
            _ => Err(OrsError::InvalidField {
                field,
                reason: "retained owner projection and digest must be complete together",
            }),
        }
    }

    fn validate_activation_projection(&self) -> Result<(), OrsError> {
        match (
            self.resolved_application_binding.as_ref(),
            self.resolved_application_binding_sha256.as_ref(),
            self.activation_owner_evidence.as_ref(),
            self.activation_owner_evidence_sha256.as_ref(),
            self.activation_result_sha256.as_ref(),
            self.p07_revision,
            self.p07_bundle_sha256.as_ref(),
        ) {
            (Some(binding), Some(binding_sha), Some(owner), Some(_), Some(result), Some(revision), Some(p07)) => {
                let expected_fence = serde_json::to_value(&self.state_fence)
                    .map_err(|error| OrsError::Encoding(error.to_string()))?;
                if owner.get("binding") != Some(binding)
                    || owner.get("binding_sha256").and_then(Value::as_str)
                        != Some(binding_sha.as_str())
                    || owner.get("state_fence") != Some(&expected_fence)
                    || owner
                        .get("owner_revision")
                        .and_then(Value::as_u64)
                        .is_none_or(|owner_revision| owner_revision == 0)
                    || revision == 0
                    || result.is_empty()
                    || p07.is_empty()
                {
                    return Err(OrsError::FenceMismatch);
                }
                validate_digest(result, "host_request_activation_result_sha256")?;
                validate_digest(p07, "host_request_p07_bundle_sha256")?;
                validate_digest(
                    owner
                        .get("evidence_sha256")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    "host_request_activation_owner_evidence_digest",
                )
            }
            (None, None, None, None, None, None, None) if self.task_ref.is_none() => Ok(()),
            _ => Err(OrsError::InvalidField {
                field: "host_request_activation_binding",
                reason: "task activation evidence must be complete together, and absent only for task-free requests",
            }),
        }
    }

    fn validate_clock_and_revisions(&self) -> Result<(), OrsError> {
        let admitted_at_ms = i64::try_from(self.admitted_at_unix_ms).ok();
        if self.admitted_at_unix_ms == 0
            || self.clock_reading.valid_time_ms.is_some()
            || self.clock_reading.known_time_ms != admitted_at_ms
            || self.clock_reading.transaction_sequence.is_some()
            || self.clock_reading.monotonic_ns.is_some()
        {
            return Err(OrsError::InvalidField {
                field: "host_request_application_admission_clock",
                reason: "the measured admission timestamp must be retained as the known-time-only clock reading",
            });
        }
        self.clock_reading
            .validate()
            .map_err(|_| OrsError::InvalidField {
                field: "host_request_application_clock",
                reason: "admission clock reading is invalid",
            })?;
        Ok(())
    }

    fn validate_resolved_binding_fields(&self) -> Result<(), OrsError> {
        let Some(binding) = self.resolved_application_binding.as_ref() else {
            return if self.task_ref.is_none() {
                Ok(())
            } else {
                Err(OrsError::InvalidField {
                    field: "host_request_application_binding",
                    reason: "task-bound requests require the original activation binding",
                })
            };
        };
        for (field, value, expected) in [
            (
                "host_request_application_principal",
                binding.get("principal_id").and_then(Value::as_str),
                Some(self.principal_ref.as_str()),
            ),
            (
                "host_request_application_session",
                binding.get("session_id").and_then(Value::as_str),
                Some(self.session_ref.as_str()),
            ),
            (
                "host_request_application_task",
                binding.get("task_id").and_then(Value::as_str),
                self.task_ref.as_ref().map(OpaqueLabel::as_str),
            ),
            (
                "host_request_application_scope",
                binding.get("work_scope_id").and_then(Value::as_str),
                self.scope_ref.as_ref().map(OpaqueLabel::as_str),
            ),
        ] {
            if value != expected {
                return Err(OrsError::FenceMismatch);
            }
        }
        let task_revision = binding
            .get("task_revision")
            .and_then(Value::as_str)
            .and_then(|revision| revision.parse::<u64>().ok());
        if task_revision != self.task_revision {
            return Err(OrsError::FenceMismatch);
        }
        Ok(())
    }

    fn validate_fence_binding(&self, record: &HostRequestRecord) -> Result<(), OrsError> {
        self.state_fence
            .validate()
            .map_err(|_| OrsError::FenceMismatch)?;
        let fence_bytes = serde_json::to_vec(&self.state_fence)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        if sha256_hex(&fence_bytes) != record.fence_digest
            || self.state_fence.authority_epoch != record.authority_epoch
            || self.state_fence.resource_generation.value() != record.generation
            || self.session_ref.as_str()
                != record
                    .session_ref
                    .as_ref()
                    .map(OpaqueLabel::as_str)
                    .unwrap_or_default()
            || self.task_ref.as_ref().map(OpaqueLabel::as_str)
                != record.task_ref.as_ref().map(OpaqueLabel::as_str)
            || self.scope_ref.as_ref().map(OpaqueLabel::as_str)
                != record.scope_ref.as_ref().map(OpaqueLabel::as_str)
        {
            return Err(OrsError::FenceMismatch);
        }
        match (self.task_ref.as_ref(), self.task_revision, self.state_fence.task_revision) {
            (Some(_), Some(revision), Some(fence_revision))
                if revision != 0 && revision == fence_revision.value() => {}
            (None, None, None) => {}
            _ => {
                return Err(OrsError::InvalidField {
                    field: "host_request_application_task_binding",
                    reason:
                        "task, task revision, and fenced revision must be present and equal together",
                });
            }
        }
        Ok(())
    }

    fn validate_observation_policy_binding(
        &self,
        record: &HostRequestRecord,
    ) -> Result<(), OrsError> {
        let policy = &self.observation_policy_binding;
        for (field, value, expected) in [
            (
                "host_request_observation_policy_principal",
                policy
                    .get("authenticated_principal_ref")
                    .and_then(Value::as_str),
                Some(self.principal_ref.as_str()),
            ),
            (
                "host_request_observation_policy_session",
                policy
                    .get("authenticated_session_ref")
                    .and_then(Value::as_str),
                Some(self.session_ref.as_str()),
            ),
            (
                "host_request_observation_policy_scope",
                policy
                    .get("authenticated_scope_ref")
                    .and_then(Value::as_str),
                self.scope_ref.as_ref().map(OpaqueLabel::as_str),
            ),
            (
                "host_request_observation_policy_task",
                policy
                    .get("authenticated_task_ref")
                    .and_then(Value::as_str),
                self.task_ref.as_ref().map(OpaqueLabel::as_str),
            ),
        ] {
            if value != expected {
                return Err(OrsError::FenceMismatch);
            }
        }
        let policy_fence = policy.get("state_fence").cloned().unwrap_or(Value::Null);
        let expected_fence =
            serde_json::to_value(&self.state_fence).map_err(|error| OrsError::Encoding(error.to_string()))?;
        if policy_fence != expected_fence {
            return Err(OrsError::FenceMismatch);
        }
        for field in [
            "policy_named_read_digest",
            "config_policy_snapshot_sha256",
            "work_scope_canonical_read_digest",
            "work_scope_binding_sha256",
        ] {
            let digest = policy
                .get(field)
                .and_then(Value::as_str)
                .ok_or(OrsError::InvalidField {
                    field: "host_request_observation_policy_digest",
                    reason: "retained policy and scope evidence is missing a source digest",
                })?;
            validate_digest(digest, "host_request_observation_policy_digest")?;
        }
        for field in ["policy_read_fence", "work_scope_read_fence"] {
            let fence: StateFence = serde_json::from_value(
                policy.get(field).cloned().unwrap_or(Value::Null),
            )
            .map_err(|_| OrsError::FenceMismatch)?;
            if fence != self.state_fence {
                return Err(OrsError::FenceMismatch);
            }
        }
        for field in ["config_policy_snapshot", "work_scope_binding"] {
            if !policy.get(field).is_some_and(Value::is_object) {
                return Err(OrsError::InvalidField {
                    field: "host_request_observation_policy_snapshot",
                    reason: "retained policy and scope source snapshots must be complete objects",
                });
            }
        }
        if policy.get("policy").is_none() {
            return Err(OrsError::InvalidField {
                field: "host_request_observation_policy_value",
                reason: "retained observation policy value is required",
            });
        }
        for field in [
            "ingress_setting_key",
            "ingress_setting_value_ref",
            "ingress_setting_owner_ref",
        ] {
            validate_text(
                policy.get(field).and_then(Value::as_str).unwrap_or_default(),
                "host_request_observation_policy_setting_ref",
            )?;
        }
        for field in [
            "policy_owner_revision",
            "policy_read_revision",
            "work_scope_owner_revision",
            "work_scope_read_revision",
        ] {
            if policy.get(field).and_then(Value::as_u64).is_none_or(|revision| revision == 0) {
                return Err(OrsError::InvalidField {
                    field: "host_request_observation_policy_revision",
                    reason: "retained policy and scope owner revisions must be non-zero",
                });
            }
        }
        if record.scope_ref.as_ref().map(OpaqueLabel::as_str)
            != self.scope_ref.as_ref().map(OpaqueLabel::as_str)
        {
            return Err(OrsError::FenceMismatch);
        }
        Ok(())
    }

    fn validate_request_identity(&self, record: &HostRequestRecord) -> Result<(), OrsError> {
        if self.request_identity.get("request_id").and_then(Value::as_str)
            != Some(record.request_id.as_str())
            || self.request_identity.get("idempotency_key").and_then(Value::as_str)
                != Some(record.idempotency_key.as_str())
            || self.request_identity.get("cancellation_id").and_then(Value::as_str)
                != Some(record.cancellation_id.as_str())
        {
            return Err(OrsError::HostRequestIdentityConflict {
                operation_id: record.operation_id.as_str().to_owned(),
                request_digest: record.request_digest.clone(),
            });
        }
        for (field, value, expected) in [
            (
                "host_request_owner_session",
                self.request_identity.get("session_id").and_then(Value::as_str),
                record.session_ref.as_ref().map(OpaqueLabel::as_str),
            ),
            (
                "host_request_owner_task",
                self.request_identity.get("task_id").and_then(Value::as_str),
                record.task_ref.as_ref().map(OpaqueLabel::as_str),
            ),
            (
                "host_request_owner_scope",
                self.request_identity
                    .get("work_scope_id")
                    .and_then(Value::as_str),
                record.scope_ref.as_ref().map(OpaqueLabel::as_str),
            ),
        ] {
            if value != expected {
                return Err(OrsError::InvalidField {
                    field,
                    reason: "original request selectors diverge from the retained row",
                });
            }
        }
        let request_correlation = self
            .request_identity
            .get("correlation_projection")
            .cloned()
            .unwrap_or(Value::Null);
        let retained_correlation = serde_json::to_value(&record.correlation_projection)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        let parent_operation_id = record
            .parent_operation_id
            .as_ref()
            .map(OpaqueLabel::as_str);
        if self.request_identity.get("parent_operation_id").and_then(Value::as_str)
            != parent_operation_id
            || self.request_identity.get("deadline_unix_ms").and_then(Value::as_u64)
                != Some(record.deadline_unix_ms)
            || self.request_identity.get("capability").and_then(Value::as_str)
                != Some(record.capability_ref.as_str())
            || self.request_identity.get("payload_sha256").and_then(Value::as_str)
                != Some(record.payload_digest.as_str())
            || self.request_identity.get("payload_schema_id").and_then(Value::as_str)
                != record.payload_schema_id.as_ref().map(OpaqueLabel::as_str)
            || request_correlation != retained_correlation
        {
            return Err(OrsError::HostRequestIdentityConflict {
                operation_id: record.operation_id.as_str().to_owned(),
                request_digest: record.request_digest.clone(),
            });
        }
        Ok(())
    }
}

/// Encoding required for an executable ToolRequest byte stream.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostRequestExecutableInputEncoding {
    /// Shared canonical JSON representation of the typed ToolRequest.
    CanonicalJsonV1,
}

/// Exact executable ToolRequest input retained under the existing protected
/// recovery payload contract. The plaintext is never stored in this type.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequestExecutableInput {
    /// Executable-input wire version.
    pub contract_version: u16,
    /// Exact shared ToolRequest schema identity.
    pub schema_id: OpaqueLabel,
    /// Encoding used for the original typed ToolRequest.
    pub encoding: HostRequestExecutableInputEncoding,
    /// Digest of the original canonical ToolRequest bytes.
    pub payload_sha256: String,
    /// Byte length of the original canonical ToolRequest bytes.
    pub payload_length: u64,
    /// SID observed by Kernel for the admitted bridge peer.
    pub authenticated_principal_ref: OpaqueLabel,
    /// Windows interactive session observed on the admitted peer token.
    pub authenticated_host_session_id: u32,
    /// Exact current daemon descriptor commitment.
    pub descriptor_sha256: String,
    /// Exact peer-admission receipt commitment from the Host owner.
    pub peer_admission_receipt_sha256: String,
    /// Exact activation selection and Governor policy owner projections.
    pub application_binding: HostRequestApplicationBinding,
    /// Stable commitment over the original request, owner binding and
    /// protected envelope metadata.
    pub commitment_sha256: String,
    /// Existing protected-recovery envelope holding the original DPAPI
    /// ciphertext and its owner-supplied access/fence metadata.
    pub protected_envelope: RecoveryPayloadEnvelope,
}

#[derive(Serialize)]
struct HostRequestExecutableInputCommitment<'a> {
    domain: &'static str,
    contract_version: u16,
    operation_id: &'a OperationIdentity,
    kind: &'a HostRequestKind,
    request_id: &'a OpaqueLabel,
    correlation_projection: &'a Option<eliot_contracts::HostCorrelationProjection>,
    idempotency_key: &'a OpaqueLabel,
    cancellation_id: &'a OpaqueLabel,
    parent_operation_id: &'a Option<OpaqueLabel>,
    request_digest: &'a str,
    payload_digest: &'a str,
    connection_ref: &'a OpaqueLabel,
    session_ref: &'a Option<OpaqueLabel>,
    task_ref: &'a Option<OpaqueLabel>,
    scope_ref: &'a Option<OpaqueLabel>,
    capability_ref: &'a OpaqueLabel,
    fence_digest: &'a str,
    authority_epoch: &'a EpochId,
    generation: u64,
    deadline_unix_ms: u64,
    schema_id: &'a OpaqueLabel,
    encoding: HostRequestExecutableInputEncoding,
    payload_length: u64,
    payload_sha256: &'a str,
    authenticated_principal_ref: &'a OpaqueLabel,
    authenticated_host_session_id: u32,
    descriptor_sha256: &'a str,
    peer_admission_receipt_sha256: &'a str,
    application_binding_sha256: String,
    privacy_and_visibility_class: &'a RecoveryAccessClass,
    protected_payload_contract_version: u16,
    protected_payload_sha256: &'a str,
    protected_payload_length: u64,
    protected_payload_authority_epoch: &'a EpochLineage,
    protected_payload_state_fence_sha256: &'a str,
    protected_payload_key: &'a SecretReference,
    protected_payload_created_at_ms: i64,
    protected_payload_known_at_ms: i64,
    protected_payload_expires_at_ms: Option<i64>,
}

impl HostRequestExecutableInput {
    /// Computes the stable commitment over this input and its exact request
    /// owner row; the stored ciphertext is represented by its original digest.
    pub fn computed_commitment_sha256(
        &self,
        record: &HostRequestRecord,
    ) -> Result<String, OrsError> {
        let RecoveryPayload::Encrypted { key, .. } = &self.protected_envelope.payload else {
            return Err(OrsError::InvalidField {
                field: "host_request_executable_input_payload",
                reason: "executable input requires an encrypted recovery payload",
            });
        };
        let material = HostRequestExecutableInputCommitment {
            domain: "eliot.host-request.executable-input.v1",
            contract_version: self.contract_version,
            operation_id: &record.operation_id,
            kind: &record.kind,
            request_id: &record.request_id,
            correlation_projection: &record.correlation_projection,
            idempotency_key: &record.idempotency_key,
            cancellation_id: &record.cancellation_id,
            parent_operation_id: &record.parent_operation_id,
            request_digest: &record.request_digest,
            payload_digest: &record.payload_digest,
            connection_ref: &record.connection_ref,
            session_ref: &record.session_ref,
            task_ref: &record.task_ref,
            scope_ref: &record.scope_ref,
            capability_ref: &record.capability_ref,
            fence_digest: &record.fence_digest,
            authority_epoch: &record.authority_epoch,
            generation: record.generation,
            deadline_unix_ms: record.deadline_unix_ms,
            schema_id: &self.schema_id,
            encoding: self.encoding,
            payload_length: self.payload_length,
            payload_sha256: &self.payload_sha256,
            authenticated_principal_ref: &self.authenticated_principal_ref,
            authenticated_host_session_id: self.authenticated_host_session_id,
            descriptor_sha256: &self.descriptor_sha256,
            peer_admission_receipt_sha256: &self.peer_admission_receipt_sha256,
            application_binding_sha256: self.application_binding.commitment_sha256()?,
            privacy_and_visibility_class: &self.protected_envelope.privacy_and_visibility_class,
            protected_payload_contract_version: self.protected_envelope.contract_version,
            protected_payload_sha256: &self.protected_envelope.payload_sha256,
            protected_payload_length: self.protected_envelope.payload_length,
            protected_payload_authority_epoch: &self.protected_envelope.authority_epoch,
            protected_payload_state_fence_sha256: &self.protected_envelope.state_fence.sha256,
            protected_payload_key: key,
            protected_payload_created_at_ms: self.protected_envelope.created_at_ms,
            protected_payload_known_at_ms: self.protected_envelope.known_at_ms,
            protected_payload_expires_at_ms: self.protected_envelope.expires_at_ms,
        };
        let bytes = canonical_json_bytes(&material)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    /// Validates exact input, protection, owner and row bindings.
    pub fn validate_for(&self, record: &HostRequestRecord) -> Result<(), OrsError> {
        if self.contract_version != HOST_REQUEST_EXECUTABLE_INPUT_CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        self.application_binding.validate_for(record)?;
        self.validate_payload_and_peer(record)?;
        self.validate_protected_envelope(record)?;
        if self.computed_commitment_sha256(record)? != self.commitment_sha256 {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        Ok(())
    }

    fn validate_payload_and_peer(&self, record: &HostRequestRecord) -> Result<(), OrsError> {
        validate_digest(&self.payload_sha256, "host_request_executable_payload_sha256")?;
        if self.schema_id.as_str() != HOST_REQUEST_TOOL_REQUEST_SCHEMA_ID
            || self.encoding != HostRequestExecutableInputEncoding::CanonicalJsonV1
            || self.payload_length == 0
            || self.payload_length > MAX_HOST_REQUEST_EXECUTABLE_INPUT_BYTES
            || self.payload_sha256 != record.payload_digest
            || self.schema_id.as_str()
                != record
                    .payload_schema_id
                    .as_ref()
                    .map(OpaqueLabel::as_str)
                    .unwrap_or_default()
        {
            return Err(OrsError::HostRequestIdentityConflict {
                operation_id: record.operation_id.as_str().to_owned(),
                request_digest: record.request_digest.clone(),
            });
        }
        validate_text(
            self.authenticated_principal_ref.as_str(),
            "host_request_executable_input_principal",
        )?;
        validate_digest(
            &self.descriptor_sha256,
            "host_request_executable_input_descriptor_sha256",
        )?;
        validate_digest(
            &self.peer_admission_receipt_sha256,
            "host_request_executable_input_peer_receipt_sha256",
        )?;
        validate_digest(
            &self.commitment_sha256,
            "host_request_executable_input_commitment_sha256",
        )?;
        Ok(())
    }

    fn validate_protected_envelope(&self, record: &HostRequestRecord) -> Result<(), OrsError> {
        self.protected_envelope.validate()?;
        let policy_access: RecoveryAccessClass = serde_json::from_value(
            self.application_binding
                .observation_policy_binding
                .get("access")
                .cloned()
                .unwrap_or(Value::Null),
        )
        .map_err(|_| OrsError::InvalidField {
            field: "host_request_observation_policy_access",
            reason: "policy owner must carry its exact typed recovery access class",
        })?;
        if self.protected_envelope.operation_or_checkpoint_id != record.operation_id
            || self.protected_envelope.privacy_and_visibility_class != policy_access
            || !matches!(
                &self.protected_envelope.payload,
                RecoveryPayload::Encrypted { .. }
            )
            || self.protected_envelope.state_fence
                != StateFenceSnapshot::capture(
                    &self.application_binding.state_fence,
                    self.application_binding.state_fence.authority_epoch.sequence.get(),
                )?
            || self.protected_envelope.authority_epoch.current.lineage_id.as_str()
                != self.application_binding.state_fence.authority_epoch.lineage_id.as_str()
            || self.protected_envelope.authority_epoch.current.epoch
                != self.application_binding.state_fence.authority_epoch.sequence.get()
        {
            return Err(OrsError::FenceMismatch);
        }
        Ok(())
    }
}

/// Durable P-04 host-request operation record.
///
/// Every identity is opaque to ORS: Session, task, scope, capability, fence,
/// and payload values are preserved as exact bytes/digests for replay
/// comparison and are never interpreted. The Kernel admission gate owns fence,
/// capability, and Session validation; ORS owns durable identity continuity:
/// an exact replay returns the same state and result, while a changed
/// payload or binding under the same identity is rejected as
/// `HostRequestIdentityConflict`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequestRecord {
    pub contract_version: u16,
    /// Send-claim protocol version. Zero denotes rows written before the
    /// durable pre-send fence existed and is reconciled conservatively.
    #[serde(default)]
    pub send_claim_protocol_version: u16,
    /// Authenticated Host channel receipt committed with a versioned
    /// `UserAutomation` transport operation before its send claim. Legacy rows
    /// omit it.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_channel_binding_sha256: Option<String>,
    pub operation_id: OperationIdentity,
    pub kind: HostRequestKind,
    pub request_id: OpaqueLabel,
    /// Explicit typed host-correlation identity; absent only on historical rows.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_projection: Option<eliot_contracts::HostCorrelationProjection>,
    pub idempotency_key: OpaqueLabel,
    pub cancellation_id: OpaqueLabel,
    pub parent_operation_id: Option<OpaqueLabel>,
    pub request_digest: String,
    pub payload_digest: String,
    /// Schema identity of the staged payload (issue #1739 W2).
    ///
    /// Bound at stage time from the admitted envelope, so execution after a
    /// restart resolves the exact typed bytes against the exact schema. `None`
    /// only on rows staged before this binding existed.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_schema_id: Option<OpaqueLabel>,
    /// Exact bounded typed payload bytes bound to `payload_digest` (issue
    /// #1739 W2).
    ///
    /// Opaque to ORS: the Kernel binder stores the canonical tool JSON here
    /// before the observe claim is handed out, and execution after a restart
    /// reads it off the row instead of relying on the digest alone. Excluded
    /// from [`HostRequestRecord::same_binding`] as ORS-owned progression (the
    /// binding arrives after staging): `validate` re-checks the
    /// digest equality on every read, so sameness is implied by the compared
    /// `payload_digest`. `None` until bound; never cleared or replaced once
    /// set. Bounded to the same structured ceiling as
    /// [`MAX_HOST_REQUEST_RESULT_RESPONSE_BYTES`].
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_body: Option<Value>,
    /// Protected original ToolRequest bytes and their schema/digest binding.
    /// Optional only for historical or non-executable rows.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_input: Option<HostRequestExecutableInput>,
    pub connection_ref: OpaqueLabel,
    pub session_ref: Option<OpaqueLabel>,
    pub task_ref: Option<OpaqueLabel>,
    pub scope_ref: Option<OpaqueLabel>,
    pub capability_ref: OpaqueLabel,
    pub fence_digest: String,
    /// Lineage-aware authority epoch (Implements #64).
    ///
    /// Widened from the `u64` contour because `host_request_binding`
    /// (owned Split B path) binds it directly from the migrated `StateFence`
    /// `EpochId`; a scalar contour would require a forbidden
    /// `.sequence.get()` adapter. `AuthorityHandoffRecord` u64 contours remain
    /// flagged adjacent residuals.
    pub authority_epoch: EpochId,
    pub generation: u64,
    pub deadline_unix_ms: u64,
    pub state: HostRequestState,
    /// The current daemon attempt, written atomically with the transition to
    /// `Routed` before the claim is returned. Retained on `Unknown` so a
    /// replacement cannot free ownership by losing its local queue entry.
    #[serde(default)]
    pub attempt: Option<HostRequestAttempt>,
    /// Retired definitely-not-sent attempts retained for same-operation retry.
    /// The current issue contract permits at most one retry, so the original
    /// and its single successor remain a bounded pair.
    #[serde(default)]
    pub attempt_history: Vec<HostRequestAttempt>,
    /// Set exactly once by ORS when this Cancellation operation is first
    /// applied to its parent. It binds retries to the same parent digest and
    /// attempt observation, so replay cannot cancel a later attempt.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancellation_target: Option<HostRequestCancellationTarget>,
    pub result_digest: Option<String>,
    /// Exact bounded result body for `ResultReceived`/`Terminal` readback
    /// (Implements #18: local read result).
    ///
    /// Opaque to ORS: the Kernel binder stores the canonical bounded
    /// `McpResponse` JSON here (payload plus revision carried inside its
    /// content by the read owner) and serves it verbatim on exact replay
    /// without re-dispatch. Excluded from [`HostRequestRecord::same_binding`]
    /// like `result_digest`: ORS-owned progression, not caller binding.
    /// `None` while no result was received; `Some` exactly when
    /// `result_digest` is `Some`. Bounded to the protocol structured-response
    /// ceiling (256 KiB, mirrors `eliot-protocol::HARD_STRUCTURED_RESPONSE_BYTES`
    /// without adding a layering edge from durable state to the wire crate).
    #[serde(default)]
    pub result_response: Option<Value>,
    /// Executor-observed effect and evidence references retained with the
    /// completion (issue #1853 W2).
    ///
    /// Written atomically with [`Self::result_digest`] and
    /// [`Self::result_response`] in the same owner transaction, so the durable
    /// evidence for an operation is never separable from the result it
    /// describes, and a replayer reads the original observation off the row
    /// instead of re-executing the operation to find out what already
    /// happened. Once written the field is never cleared or replaced: an
    /// at-least-once replay of the same result cannot rewrite or erase it.
    ///
    /// Scope of the claim, stated exactly: `ResultReceived` is terminal in
    /// [`HostRequestState::transition_to`], so a row that reaches `Unknown`
    /// never carried a result and therefore never carried this field. An
    /// unresolved operation retains its claimed attempt identity in
    /// [`Self::attempt`] instead, and the honest disposition for it stays
    /// unknown rather than becoming a clean observation.
    ///
    /// `None` for rows that carry no completion, and for stored rows written
    /// before this field existed; absence means unknown, never clean, and is
    /// re-checked against this row on every read by [`Self::validate`].
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_evidence: Option<HostRequestEffectEvidence>,
    /// Result-side lineage retained with the completion (issue #1853 W2).
    ///
    /// The claims and references the read owner submitted alongside the result,
    /// written in the same owner transaction as
    /// [`Self::result_digest`] and [`Self::result_response`] so provenance can
    /// never be separated from the result it describes. Once written it is
    /// never cleared or replaced, exactly like [`Self::result_evidence`].
    ///
    /// `None` for rows that carry no completion, and for stored rows written
    /// before this field existed. Absence means the lineage is unknown or
    /// unavailable, never clean: ORS records no lineage of its own and never
    /// infers one, so an absent field grants no provenance and no influence.
    /// Every present field is re-bound to this row by [`Self::validate`].
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_lineage: Option<HostRequestRetainedLineage>,
    /// Monotonic ORS order assigned atomically when the operation first
    /// reaches a terminal state. Zero while non-terminal.
    #[serde(default)]
    pub commit_order: u64,
}

impl HostRequestRecord {
    /// Returns the durable key binding one operation to one exact request.
    pub fn record_key(&self) -> String {
        format!("{}::{}", self.operation_id.as_str(), self.request_digest)
    }

    /// Returns whether two records carry the exact same request binding.
    ///
    /// State, result, commit order, and the post-stage payload body are
    /// excluded: they are ORS-owned progression, not caller binding. The body
    /// stays implied by the compared `payload_digest` because `validate`
    /// re-checks body/digest equality on every read.
    pub fn same_binding(&self, other: &Self) -> bool {
        self.operation_id == other.operation_id
            && self.kind == other.kind
            && self.request_id == other.request_id
            && self.correlation_projection == other.correlation_projection
            && self.idempotency_key == other.idempotency_key
            && self.cancellation_id == other.cancellation_id
            && self.parent_operation_id == other.parent_operation_id
            && self.request_digest == other.request_digest
            && self.payload_digest == other.payload_digest
            && Self::same_payload_schema(
                self.payload_schema_id.as_ref(),
                other.payload_schema_id.as_ref(),
            )
            && self.executable_input == other.executable_input
            && self.connection_ref == other.connection_ref
            && self.session_ref == other.session_ref
            && self.task_ref == other.task_ref
            && self.scope_ref == other.scope_ref
            && self.capability_ref == other.capability_ref
            && self.fence_digest == other.fence_digest
            && self.authority_epoch == other.authority_epoch
            && self.generation == other.generation
            && self.deadline_unix_ms == other.deadline_unix_ms
            && self.transport_channel_binding_sha256 == other.transport_channel_binding_sha256
    }

    /// Returns whether two staged payload-schema bindings agree.
    ///
    /// A missing schema on either side is a row staged before the issue #1739
    /// W2 binding existed, never a changed schema: only two present but
    /// different schemas disagree.
    fn same_payload_schema(left: Option<&OpaqueLabel>, right: Option<&OpaqueLabel>) -> bool {
        match (left, right) {
            (Some(left), Some(right)) => left == right,
            _ => true,
        }
    }

    /// Validates identity shape and state/result coherence.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.validate_identity_and_cancellation_binding()?;
        self.validate_execution_binding()?;
        validate_text(self.connection_ref.as_str(), "host_request_connection_ref")?;
        for (value, field) in [
            (self.session_ref.as_ref(), "host_request_session_ref"),
            (self.task_ref.as_ref(), "host_request_task_ref"),
            (self.scope_ref.as_ref(), "host_request_scope_ref"),
        ] {
            if let Some(identity) = value {
                validate_text(identity.as_str(), field)?;
            }
        }
        validate_text(self.capability_ref.as_str(), "host_request_capability_ref")?;
        validate_digest(&self.fence_digest, "host_request_fence_digest")?;
        // `EpochId` is always validated; only generation retains a scalar check.
        if self.generation == 0 {
            return Err(OrsError::InvalidField {
                field: "host_request_epoch",
                reason: "must be non-zero",
            });
        }
        if !matches!(
            self.send_claim_protocol_version,
            0 | HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
        ) {
            return Err(OrsError::InvalidField {
                field: "host_request_send_claim_protocol_version",
                reason: "unsupported send-claim protocol version",
            });
        }
        if self.send_claim_protocol_version == HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
            && self.attempt_history.len() >= MAX_HOST_REQUEST_SEND_ATTEMPTS
        {
            return Err(OrsError::InvalidField {
                field: "host_request_attempt_history",
                reason: "at most one same-operation retry is retained",
            });
        }
        if self.send_claim_protocol_version == 0 && !self.attempt_history.is_empty() {
            return Err(OrsError::InvalidField {
                field: "host_request_attempt_history",
                reason: "legacy rows cannot carry current-protocol retry history",
            });
        }
        if self.deadline_unix_ms == 0 {
            return Err(OrsError::InvalidField {
                field: "host_request_deadline",
                reason: "must be greater than zero",
            });
        }
        // Issue #1739 W2: a bound body always proves it is the admitted
        // payload. Absence stays readable (rows bound before the claim, or
        // staged before this binding existed); a present body that is not the
        // digest-bound bytes is refused on read rather than trusted.
        if let Some(body) = &self.payload_body {
            validate_payload_body(body, &self.payload_digest)?;
        }
        match (&self.state, &self.result_digest, &self.result_response) {
            (
                HostRequestState::ResultReceived | HostRequestState::Terminal,
                Some(result),
                Some(body),
            ) => {
                validate_digest(result, "host_request_result_digest")?;
                validate_result_response(body)?;
            }
            // Legacy digest-only row (produced by the digest-only advance
            // before the bounded body existed): loads for compatibility but
            // is never served as a body until completed by an exact-digest
            // persist. Digests in any other state remain rejected as before.
            (HostRequestState::ResultReceived | HostRequestState::Terminal, Some(result), None) => {
                validate_digest(result, "host_request_result_digest")?;
            }
            (_, None, None) => {}
            (_, Some(_), _) | (_, None, Some(_)) => {
                return Err(OrsError::InvalidField {
                    field: "host_request_result_digest",
                    reason: "result digest and body must be present together, only for received or terminal states",
                });
            }
        }
        // Issue #1853 W2: retained evidence exists only for a row that carries
        // the completion it observes, and it must bind THIS row. The check
        // compares the originally recorded values, so evidence for another
        // operation is refused on read rather than trusted. A pre-W2 completed
        // row carries no evidence at all: that absence stays readable and stays
        // unknown, and is never upgraded into a clean observation here.
        if let Some(evidence) = &self.result_evidence {
            let result_digest = self
                .result_digest
                .as_deref()
                .ok_or(OrsError::InvalidField {
                    field: "host_request_result_evidence",
                    reason: "retained evidence must observe a retained result",
                })?;
            evidence.validate(&self.operation_id, &self.request_digest, result_digest)?;
        }
        // Issue #1853 W2: retained lineage describes the result, so it is bound
        // to the same retained result. Same discipline as the effect evidence
        // above: the originally recorded `output_digest` is compared with this
        // row's own recorded `result_digest`, and nothing is re-derived.
        if let Some(lineage) = &self.result_lineage {
            let result_digest = self
                .result_digest
                .as_deref()
                .ok_or(OrsError::InvalidField {
                    field: "host_request_result_lineage",
                    reason: "retained lineage must describe a retained result",
                })?;
            lineage.validate(result_digest)?;
        }
        if !self.state.is_terminal() && self.commit_order != 0 {
            return Err(OrsError::InvalidField {
                field: "host_request_commit_order",
                reason: "non-terminal states must not carry a commit order",
            });
        }
        Ok(())
    }

    fn validate_execution_binding(&self) -> Result<(), OrsError> {
        if let Some(executable_input) = &self.executable_input {
            if self.kind != HostRequestKind::Invocation
                || self.capability_ref.as_str() != "eliot.observe"
                || self.payload_body.is_some()
            {
                return Err(OrsError::InvalidField {
                    field: "host_request_executable_input",
                    reason:
                        "protected execution requires an Observe invocation with no plaintext payload body",
                });
            }
            executable_input.validate_for(self)?;
        }
        Ok(())
    }

    fn validate_attempt_execution_binding(
        &self,
        attempt: &HostRequestAttempt,
    ) -> Result<(), OrsError> {
        match self.executable_input.as_ref() {
            None if attempt.input_commitment_sha256.is_none() => Ok(()),
            Some(input)
                if attempt.input_commitment_sha256.as_deref()
                    == Some(&input.commitment_sha256) =>
            {
                Ok(())
            }
            _ => Err(OrsError::InvalidField {
                field: "host_request_attempt_execution_binding",
                reason: "attempt commitment must exactly bind the retained executable input",
            }),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the retained request and cancellation identities share one validation boundary"
    )]
    fn validate_identity_and_cancellation_binding(&self) -> Result<(), OrsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        validate_text(self.operation_id.as_str(), "host_request_operation_id")?;
        validate_text(self.request_id.as_str(), "host_request_request_id")?;
        self.validate_correlation_projection()?;
        validate_text(
            self.idempotency_key.as_str(),
            "host_request_idempotency_key",
        )?;
        validate_text(
            self.cancellation_id.as_str(),
            "host_request_cancellation_id",
        )?;
        if let Some(parent) = &self.parent_operation_id {
            validate_text(parent.as_str(), "host_request_parent_operation_id")?;
            if parent == &self.operation_id {
                return Err(OrsError::InvalidField {
                    field: "host_request_parent_operation_id",
                    reason: "must not reference the enclosing operation",
                });
            }
        }
        validate_digest(&self.request_digest, "host_request_request_digest")?;
        validate_digest(&self.payload_digest, "host_request_payload_digest")?;
        if let Some(schema) = &self.payload_schema_id {
            validate_text(schema.as_str(), "host_request_payload_schema_id")?;
        }
        match (
            self.send_claim_protocol_version,
            self.transport_channel_binding_sha256.as_deref(),
        ) {
            (HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION, Some(digest)) => {
                validate_digest(digest, "host_request_transport_channel_binding_sha256")?;
            }
            (HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION, None) => {
                return Err(OrsError::InvalidField {
                    field: "host_request_transport_channel_binding_sha256",
                    reason: "versioned send rows require the authenticated channel committed at staging",
                });
            }
            (0, Some(_)) => {
                return Err(OrsError::InvalidField {
                    field: "host_request_transport_channel_binding_sha256",
                    reason: "legacy rows do not carry versioned transport channel custody",
                });
            }
            _ => {}
        }
        for (index, attempt) in self.attempt_history.iter().enumerate() {
            attempt.validate(&self.fence_digest)?;
            self.validate_attempt_execution_binding(attempt)?;
            if self.send_claim_protocol_version == HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
                && attempt.claim_expires_at_unix_ms.is_none()
            {
                return Err(OrsError::InvalidField {
                    field: "host_request_attempt_claim_expiry",
                    reason: "versioned send attempts require their retained claim expiry",
                });
            }
            if self.send_claim_protocol_version == 0 && attempt.claim_expires_at_unix_ms.is_some() {
                return Err(OrsError::InvalidField {
                    field: "host_request_attempt_claim_expiry",
                    reason: "legacy send attempts do not carry claim expiry",
                });
            }
            if self.send_claim_protocol_version == HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
                && attempt.channel_binding_sha256.is_none()
            {
                return Err(OrsError::InvalidField {
                    field: "host_request_attempt_channel_binding_sha256",
                    reason: "versioned send attempts require the authenticated channel committed at claim time",
                });
            }
            if self.send_claim_protocol_version == 0 && attempt.channel_binding_sha256.is_some() {
                return Err(OrsError::InvalidField {
                    field: "host_request_attempt_channel_binding_sha256",
                    reason: "legacy send attempts do not carry versioned channel custody",
                });
            }
            if self.send_claim_protocol_version == HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
                && index == 0
                && attempt.generation != 1
            {
                return Err(OrsError::InvalidField {
                    field: "host_request_attempt_history",
                    reason: "first retained send attempt must use generation one",
                });
            }
            if self.send_claim_protocol_version == HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
                && attempt.phase != HostRequestAttemptPhase::DefinitelyNotSent
                && attempt.phase != HostRequestAttemptPhase::DeferredNoEffect
            {
                return Err(OrsError::InvalidField {
                    field: "host_request_attempt_history",
                    reason: "retired attempts require retained no-send proof",
                });
            }
            if self.send_claim_protocol_version == HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
                && index > 0
                && attempt.generation
                    != self.attempt_history[index - 1]
                        .generation
                        .checked_add(1)
                        .ok_or(OrsError::InvalidTransition)?
            {
                return Err(OrsError::InvalidField {
                    field: "host_request_attempt_history",
                    reason: "attempt history generations must be contiguous",
                });
            }
            self.validate_attempt_observations(attempt)?;
        }
        if self.send_claim_protocol_version == HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
            && !self.attempt_history.is_empty()
            && self.attempt.is_none()
        {
            return Err(OrsError::InvalidField {
                field: "host_request_attempt_history",
                reason: "retired attempts require the current retained attempt",
            });
        }
        if let Some(attempt) = &self.attempt {
            attempt.validate(&self.fence_digest)?;
            self.validate_attempt_execution_binding(attempt)?;
            if self.send_claim_protocol_version == HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
                && attempt.claim_expires_at_unix_ms.is_none()
            {
                return Err(OrsError::InvalidField {
                    field: "host_request_attempt_claim_expiry",
                    reason: "versioned send attempts require their retained claim expiry",
                });
            }
            if self.send_claim_protocol_version == 0 && attempt.claim_expires_at_unix_ms.is_some() {
                return Err(OrsError::InvalidField {
                    field: "host_request_attempt_claim_expiry",
                    reason: "legacy send attempts do not carry claim expiry",
                });
            }
            if self.send_claim_protocol_version == HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
                && attempt.channel_binding_sha256.is_none()
            {
                return Err(OrsError::InvalidField {
                    field: "host_request_attempt_channel_binding_sha256",
                    reason: "versioned send attempts require the authenticated channel committed at claim time",
                });
            }
            if self.send_claim_protocol_version == 0 && attempt.channel_binding_sha256.is_some() {
                return Err(OrsError::InvalidField {
                    field: "host_request_attempt_channel_binding_sha256",
                    reason: "legacy send attempts do not carry versioned channel custody",
                });
            }
            if self.send_claim_protocol_version == HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION {
                let expected_generation = match self.attempt_history.last() {
                    Some(previous) => previous
                        .generation
                        .checked_add(1)
                        .ok_or(OrsError::InvalidTransition)?,
                    None => 1,
                };
                if attempt.generation != expected_generation {
                    return Err(OrsError::InvalidField {
                        field: "host_request_attempt_generation",
                        reason: "active attempt must follow the retained attempt history",
                    });
                }
                if self
                    .attempt_history
                    .iter()
                    .any(|previous| previous.attempt_id == attempt.attempt_id)
                {
                    return Err(OrsError::InvalidField {
                        field: "host_request_attempt_id",
                        reason: "attempt identity must be unique within its retained history",
                    });
                }
            }
            self.validate_attempt_observations(attempt)?;
        }
        if let Some(target) = &self.cancellation_target {
            if self.kind != HostRequestKind::Cancellation
                || self.state == HostRequestState::Requested
                || self.parent_operation_id.as_ref().map(OpaqueLabel::as_str)
                    != Some(target.parent_operation_id.as_str())
            {
                return Err(OrsError::InvalidField {
                    field: "host_request_cancellation_target",
                    reason: "must be ORS progression on a Cancellation row linked to the same parent operation",
                });
            }
            target.validate()?;
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the monotonic observation sequence and original commitments validate together"
    )]
    fn validate_attempt_observations(&self, attempt: &HostRequestAttempt) -> Result<(), OrsError> {
        if self.send_claim_protocol_version == 0 && !attempt.transport_observations.is_empty() {
            return Err(OrsError::InvalidField {
                field: "host_request_transport_observations",
                reason: "legacy send-claim rows cannot carry current protocol observations",
            });
        }
        if attempt.transport_observations.len() > 3 {
            return Err(OrsError::InvalidField {
                field: "host_request_transport_observations",
                reason: "bounded transport custody history exceeded",
            });
        }
        for observation in &attempt.transport_observations {
            observation.validate_for(self, attempt)?;
        }
        if let Some(readback) = &attempt.owner_readback {
            readback.validate_for(self, attempt)?;
            if attempt.phase != HostRequestAttemptPhase::ResponseReceived
                || attempt.transport_observations.is_empty()
                || !matches!(
                    attempt
                        .transport_observations
                        .last()
                        .map(|item| item.boundary),
                    Some(
                        HostRequestTransportBoundary::DispatchStarted
                            | HostRequestTransportBoundary::DeliveryOutcomeUnknown
                            | HostRequestTransportBoundary::DeliveredToAuthenticatedHost
                            | HostRequestTransportBoundary::ResponseReceived
                    )
                )
            {
                return Err(OrsError::InvalidField {
                    field: "host_request_owner_readback",
                    reason: "owner readback must resolve the exact active transport attempt",
                });
            }
        }
        if let Some(first) = attempt.transport_observations.first() {
            for observation in attempt.transport_observations.iter().skip(1) {
                if observation.request_commitment_sha256 != first.request_commitment_sha256
                    || observation.payload_commitment_sha256 != first.payload_commitment_sha256
                    || observation.channel_binding_sha256 != first.channel_binding_sha256
                {
                    return Err(OrsError::InvalidField {
                        field: "host_request_transport_observations",
                        reason: "later custody evidence changed the admitted request/payload or changed channel without an explicit owner readback",
                    });
                }
            }
        }
        let boundaries = attempt
            .transport_observations
            .iter()
            .map(|observation| observation.boundary)
            .collect::<Vec<_>>();
        let legal = matches!(
            boundaries.as_slice(),
            [] | [HostRequestTransportBoundary::DispatchStarted
                | HostRequestTransportBoundary::DefinitelyNotSent]
                | [
                    HostRequestTransportBoundary::DispatchStarted,
                    HostRequestTransportBoundary::DefinitelyNotSent
                        | HostRequestTransportBoundary::DeliveryOutcomeUnknown
                        | HostRequestTransportBoundary::DeliveredToAuthenticatedHost
                        | HostRequestTransportBoundary::ResponseReceived
                ]
                | [
                    HostRequestTransportBoundary::DispatchStarted,
                    HostRequestTransportBoundary::DeliveryOutcomeUnknown
                        | HostRequestTransportBoundary::DeliveredToAuthenticatedHost,
                    HostRequestTransportBoundary::ResponseReceived
                ]
        );
        if !legal {
            return Err(OrsError::InvalidField {
                field: "host_request_transport_observations",
                reason: "transport observations do not follow an allowed monotonic boundary sequence",
            });
        }
        let last_boundary = boundaries.last().copied();
        let phase_matches = match attempt.phase {
            HostRequestAttemptPhase::Claimed => last_boundary.is_none(),
            HostRequestAttemptPhase::DispatchStarted => {
                last_boundary == Some(HostRequestTransportBoundary::DispatchStarted)
            }
            HostRequestAttemptPhase::DefinitelyNotSent => {
                last_boundary == Some(HostRequestTransportBoundary::DefinitelyNotSent)
            }
            HostRequestAttemptPhase::DeferredNoEffect => boundaries.is_empty(),
            HostRequestAttemptPhase::DeliveryOutcomeUnknown => {
                last_boundary == Some(HostRequestTransportBoundary::DeliveryOutcomeUnknown)
            }
            HostRequestAttemptPhase::DeliveredToAuthenticatedHost => {
                last_boundary == Some(HostRequestTransportBoundary::DeliveredToAuthenticatedHost)
            }
            HostRequestAttemptPhase::ResponseReceived => {
                if attempt.owner_readback.is_some() {
                    matches!(
                        last_boundary,
                        Some(
                            HostRequestTransportBoundary::DispatchStarted
                                | HostRequestTransportBoundary::DeliveryOutcomeUnknown
                                | HostRequestTransportBoundary::DeliveredToAuthenticatedHost
                                | HostRequestTransportBoundary::ResponseReceived
                        )
                    )
                } else {
                    last_boundary == Some(HostRequestTransportBoundary::ResponseReceived)
                }
            }
        };
        if !phase_matches {
            return Err(OrsError::InvalidField {
                field: "host_request_transport_observations",
                reason: "last retained boundary must match the attempt custody phase",
            });
        }
        if let (Some(result_digest), Some(observation)) = (
            self.result_digest.as_deref(),
            attempt.transport_observations.last(),
        ) && observation.boundary == HostRequestTransportBoundary::ResponseReceived
            && observation.response_commitment_sha256.as_deref() != Some(result_digest)
        {
            return Err(OrsError::InvalidField {
                field: "host_request_transport_response_commitment",
                reason: "retained result must equal the original response observation",
            });
        }
        if let (Some(result_digest), Some(readback)) = (
            self.result_digest.as_deref(),
            attempt.owner_readback.as_ref(),
        ) && readback.result_commitment_sha256 != result_digest
        {
            return Err(OrsError::InvalidField {
                field: "host_request_owner_readback_result_commitment",
                reason: "retained result must equal the original owner readback commitment",
            });
        }
        if let (Some(readback), Some(response_observation)) = (
            attempt.owner_readback.as_ref(),
            attempt.transport_observations.last().filter(|observation| {
                observation.boundary == HostRequestTransportBoundary::ResponseReceived
            }),
        ) && response_observation.response_commitment_sha256.as_deref()
            != Some(readback.result_commitment_sha256.as_str())
        {
            return Err(OrsError::InvalidField {
                field: "host_request_owner_readback_result_commitment",
                reason: "owner readback must confirm the exact observed response commitment",
            });
        }
        Ok(())
    }

    fn validate_correlation_projection(&self) -> Result<(), OrsError> {
        let Some(projection) = &self.correlation_projection else {
            return Ok(());
        };
        projection.validate().map_err(|_| OrsError::InvalidField {
            field: "host_request_correlation_projection",
            reason: "must be a bounded explicit correlation projection",
        })?;
        if projection.occurrence_text() != self.request_id.as_str() {
            return Err(OrsError::InvalidField {
                field: "host_request_correlation_projection",
                reason: "must encode the exact request_id text",
            });
        }
        if self.request_id.as_str().len() > 512 {
            return Err(OrsError::InvalidField {
                field: "host_request_request_id",
                reason: "marked correlation must fit the bounded host-correlation text limit",
            });
        }
        let domain_matches = matches!(
            (self.kind, projection.domain()),
            (
                HostRequestKind::Invocation,
                eliot_contracts::HostCorrelationDomain::Request
            ) | (
                HostRequestKind::Cancellation,
                eliot_contracts::HostCorrelationDomain::Cancellation
            )
        );
        if !domain_matches {
            return Err(OrsError::InvalidField {
                field: "host_request_correlation_projection",
                reason: "must match the host-request kind domain",
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

/// Bounded size of one stored host-request result body (Implements #18).
///
/// Mirrors `eliot-protocol::HARD_STRUCTURED_RESPONSE_BYTES` without adding a
/// wire-crate edge to durable state.
pub const MAX_HOST_REQUEST_RESULT_RESPONSE_BYTES: usize = 256 * 1024;

/// Bounded size of one stored host-request payload body (issue #1739 W2).
///
/// Mirrors `eliot-protocol::HARD_STRUCTURED_RESPONSE_BYTES` like the result
/// body: the staged tool bytes are bounded structured JSON.
pub const MAX_HOST_REQUEST_PAYLOAD_BODY_BYTES: usize = 256 * 1024;

/// Validates exact staged payload bytes against their admitted digest.
///
/// The body must be a bounded JSON object whose canonical digest (the shared
/// `eliot_contracts::canonical_json_bytes` recipe, identical to the protocol
/// invoke-read carrier check) equals the staged `payload_digest`. Shape and
/// bound are checked before the digest so oversized or malformed bodies fail
/// with their own reason.
pub(crate) fn validate_payload_body(body: &Value, payload_digest: &str) -> Result<(), OrsError> {
    if !body.is_object() {
        return Err(OrsError::InvalidField {
            field: "host_request_payload_body",
            reason: "payload body must be a bounded JSON object",
        });
    }
    let encoded = serde_json::to_vec(body).map_err(|_| OrsError::InvalidField {
        field: "host_request_payload_body",
        reason: "payload body must serialize to bounded JSON",
    })?;
    if encoded.len() > MAX_HOST_REQUEST_PAYLOAD_BODY_BYTES {
        return Err(OrsError::InvalidField {
            field: "host_request_payload_body",
            reason: "payload body exceeds the bounded payload ceiling",
        });
    }
    let canonical =
        canonical_json_bytes(body).map_err(|error| OrsError::Encoding(error.to_string()))?;
    if sha256_hex(&canonical) != payload_digest {
        return Err(OrsError::InvalidField {
            field: "host_request_payload_body",
            reason: "payload body does not match the admitted payload digest",
        });
    }
    Ok(())
}

pub(crate) fn validate_result_response(body: &Value) -> Result<(), OrsError> {
    if !body.is_object() {
        return Err(OrsError::InvalidField {
            field: "host_request_result_response",
            reason: "result body must be a bounded JSON object",
        });
    }
    let encoded = serde_json::to_vec(body).map_err(|_| OrsError::InvalidField {
        field: "host_request_result_response",
        reason: "result body must serialize to bounded JSON",
    })?;
    if encoded.len() > MAX_HOST_REQUEST_RESULT_RESPONSE_BYTES {
        return Err(OrsError::InvalidField {
            field: "host_request_result_response",
            reason: "result body exceeds the bounded response ceiling",
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

/// Durable native-worker claim operation state (Wave B, issue #872).
///
/// `Terminal` is absorbing: once a claim is terminal it never leaves that
/// state, so restart rehydrates the terminal outcome instead of downgrading
/// the unit to unclaimed. `Unknown` may only move to `Reconciling`, and
/// neither `Unknown` nor `Reconciling` may return to `Requested`: an
/// uncertain outcome is reconciled under the original claim, never
/// blind-retried as new work. `Ready` is reachable only from `Admitted` or
/// from `Reconciling` as the resolution of previously admitted work; a
/// direct `Requested -> Ready` or `Unknown -> Ready` skip is forbidden, so
/// transport liveness alone can never manufacture readiness.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeWorkerClaimState {
    Requested,
    Admitted,
    Ready,
    Active,
    Cancelling,
    Submitted,
    Unknown,
    Reconciling,
    Terminal,
}

impl NativeWorkerClaimState {
    /// Returns whether the state closes the claim.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }

    /// Validates one mechanical state advance without interpreting meaning.
    pub fn transition_to(self, next: Self) -> Result<Self, OrsError> {
        let legal = matches!(
            (self, next),
            (Self::Requested, Self::Admitted | Self::Unknown)
                | (
                    Self::Admitted,
                    Self::Ready | Self::Cancelling | Self::Unknown
                )
                | (Self::Ready, Self::Active | Self::Cancelling | Self::Unknown)
                | (
                    Self::Active,
                    Self::Cancelling | Self::Submitted | Self::Unknown
                )
                | (
                    Self::Cancelling,
                    Self::Submitted | Self::Unknown | Self::Terminal
                )
                | (Self::Submitted, Self::Terminal | Self::Unknown)
                | (Self::Unknown, Self::Reconciling)
                | (
                    Self::Reconciling,
                    Self::Ready | Self::Active | Self::Submitted | Self::Terminal | Self::Unknown
                )
        );
        legal.then_some(next).ok_or(OrsError::InvalidTransition)
    }
}

/// Durable native-worker claim intent and admission record (Wave B, issue
/// #872).
///
/// Every identity is opaque to ORS: the parent Durable-Job, task, scope,
/// decision, attempt, and operation ids, the route/provider-class label, and
/// the budget/fence/resource digests are preserved as exact bytes for replay
/// comparison and are never interpreted. The Kernel admission gate owns
/// registration currency, epoch/fence, deadline, and readiness validation;
/// ORS owns durable identity continuity: an exact replay under the same
/// claim identity returns the same receipt identity, while changed work,
/// generation, route, budget, schema, fence, or predecessor under one claim
/// identity is rejected as
/// [`OrsError::NativeWorkerClaimIdentityConflict`] and never overwrites the
/// durable binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerClaimRecord {
    pub contract_version: u16,
    /// Distinct claim operation identity; the durable key. At most one live
    /// claim exists per id.
    pub claim_id: OperationIdentity,
    /// Registration the claim was presented under; opaque reference only.
    pub registration_id: OpaqueLabel,
    /// Claiming worker generation; stale generations cannot claim.
    pub worker_generation: u64,
    /// Kernel-owned parent Durable-Job identity; opaque to ORS.
    pub parent_job_id: OpaqueLabel,
    /// Governed task identity; opaque to ORS.
    pub task_id: OpaqueLabel,
    /// Task `WorkScope` identity; opaque to ORS.
    pub work_scope_id: OpaqueLabel,
    /// Logical decision identity; opaque to ORS.
    pub decision_id: OpaqueLabel,
    /// Attempt identity bound to this claim; opaque to ORS.
    pub attempt_id: OpaqueLabel,
    /// Exact external-effect operation identity; opaque to ORS.
    pub operation_id: OpaqueLabel,
    /// Admitted route/provider-class label. Selection stays with #874; ORS
    /// compares it byte-wise and never interprets it.
    pub route_class: OpaqueLabel,
    /// Opaque digest of the claim budget envelope.
    pub budget_digest: String,
    /// Claim deadline in Unix milliseconds.
    pub deadline_unix_ms: u64,
    /// Opaque digest of the exact immutable fence paired with the
    /// generation and epoch.
    pub fence_digest: String,
    /// Current authority epoch at admission time.
    pub authority_epoch: u64,
    /// Canonical digest over every bound work field.
    pub binding_digest: String,
    /// Canonical digest over the presenting request envelope.
    pub request_digest: String,
    /// Owner-verified executable-binding digest retained at stage.
    ///
    /// Copied from the Kernel-gated v2 executable join
    /// (`NativeWorkerExecutableBinding.executable_binding_digest`) when the
    /// claim stages, never recomputed here: ORS compares it byte-wise and
    /// never interprets it. A changed executable binding under one claim
    /// identity is rejected as
    /// [`OrsError::NativeWorkerClaimIdentityConflict`] and never overwrites
    /// the durable binding.
    ///
    /// Absent (empty) in rows staged before this column and in joinless
    /// claims; decodes as empty and never verifies.
    #[serde(default)]
    pub executable_binding_digest: String,
    /// Supported execution-unit schema version.
    pub execution_unit_schema_version: u16,
    /// Predecessor revision this claim continues from; opaque to ORS.
    pub predecessor_revision: OpaqueLabel,
    /// Opaque digest of the presenting worker generation's resource
    /// envelope (installation, artifact, and configuration identity).
    pub resource_envelope_digest: String,
    /// Functional capability cell selected by the owner-validated
    /// executable join, absent only for legacy requests without that join.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_cell: Option<OpaqueLabel>,
    /// Registry digest bound to `capability_cell` by the executable join.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_cell_registry_digest: Option<String>,
    /// Durable claim state.
    pub state: NativeWorkerClaimState,
    /// Canonical digest of the immutable admission receipt. `None` while
    /// the intent is only requested; `Some` once Kernel admits the claim.
    /// The receipt identity never changes afterwards: exact replay returns
    /// this same digest.
    pub receipt_digest: Option<String>,
    /// Admission time in Unix milliseconds. `None` while requested.
    pub admitted_at_unix_ms: Option<u64>,
    /// Monotonic ORS order assigned atomically when the claim first reaches
    /// its terminal state. Zero while non-terminal.
    #[serde(default)]
    pub commit_order: u64,
}

impl NativeWorkerClaimRecord {
    /// Returns the durable key binding one claim identity to one exact row.
    pub fn record_key(&self) -> String {
        self.claim_id.as_str().to_owned()
    }

    /// Returns whether two records carry the exact same admitted binding.
    ///
    /// State, receipt, admission time, and commit order are excluded: they
    /// are ORS-owned progression, not caller binding. Mirrors
    /// [`HostRequestRecord::same_binding`].
    pub fn same_binding(&self, other: &Self) -> bool {
        self.claim_id == other.claim_id
            && self.registration_id == other.registration_id
            && self.worker_generation == other.worker_generation
            && self.parent_job_id == other.parent_job_id
            && self.task_id == other.task_id
            && self.work_scope_id == other.work_scope_id
            && self.decision_id == other.decision_id
            && self.attempt_id == other.attempt_id
            && self.operation_id == other.operation_id
            && self.route_class == other.route_class
            && self.budget_digest == other.budget_digest
            && self.deadline_unix_ms == other.deadline_unix_ms
            && self.fence_digest == other.fence_digest
            && self.authority_epoch == other.authority_epoch
            && self.binding_digest == other.binding_digest
            && self.request_digest == other.request_digest
            && self.executable_binding_digest == other.executable_binding_digest
            && self.execution_unit_schema_version == other.execution_unit_schema_version
            && self.predecessor_revision == other.predecessor_revision
            && self.resource_envelope_digest == other.resource_envelope_digest
            && self.capability_cell == other.capability_cell
            && self.capability_cell_registry_digest == other.capability_cell_registry_digest
    }

    /// Validates identity shape and state/receipt coherence.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        validate_text(self.claim_id.as_str(), "native_worker_claim_id")?;
        for (value, field) in [
            (&self.registration_id, "native_worker_claim_registration_id"),
            (&self.parent_job_id, "native_worker_claim_parent_job_id"),
            (&self.task_id, "native_worker_claim_task_id"),
            (&self.work_scope_id, "native_worker_claim_work_scope_id"),
            (&self.decision_id, "native_worker_claim_decision_id"),
            (&self.attempt_id, "native_worker_claim_attempt_id"),
            (&self.operation_id, "native_worker_claim_operation_id"),
            (&self.route_class, "native_worker_claim_route_class"),
            (
                &self.predecessor_revision,
                "native_worker_claim_predecessor_revision",
            ),
        ] {
            validate_text(value.as_str(), field)?;
        }
        for (value, field) in [
            (&self.budget_digest, "native_worker_claim_budget_digest"),
            (&self.fence_digest, "native_worker_claim_fence_digest"),
            (&self.binding_digest, "native_worker_claim_binding_digest"),
            (&self.request_digest, "native_worker_claim_request_digest"),
            (
                &self.resource_envelope_digest,
                "native_worker_claim_resource_envelope_digest",
            ),
        ] {
            validate_digest(value, field)?;
        }
        // Absent (pre-column or joinless) bindings decode as empty and never
        // verify; a retained binding must be an exact digest.
        if !self.executable_binding_digest.is_empty() {
            validate_digest(
                &self.executable_binding_digest,
                "native_worker_claim_executable_binding_digest",
            )?;
        }
        match (&self.capability_cell, &self.capability_cell_registry_digest) {
            (Some(cell), Some(registry_digest)) => {
                validate_text(cell.as_str(), "native_worker_claim_capability_cell")?;
                validate_digest(
                    registry_digest,
                    "native_worker_claim_capability_cell_registry_digest",
                )?;
            }
            (None, None) => {}
            _ => {
                return Err(OrsError::InvalidField {
                    field: "native_worker_claim_capability_cell_binding",
                    reason: "cell identity and registry digest must be bound together",
                });
            }
        }
        if self.worker_generation == 0
            || self.deadline_unix_ms == 0
            || self.authority_epoch == 0
            || self.execution_unit_schema_version == 0
        {
            return Err(OrsError::InvalidField {
                field: "native_worker_claim_bounded_fields",
                reason: "generation, deadline, epoch, and schema version must be non-zero",
            });
        }
        match (&self.state, &self.receipt_digest, self.admitted_at_unix_ms) {
            (NativeWorkerClaimState::Requested, None, None) => {}
            (NativeWorkerClaimState::Requested, _, _) => {
                return Err(OrsError::InvalidField {
                    field: "native_worker_claim_receipt",
                    reason: "a requested intent carries no admission receipt",
                });
            }
            (_, Some(receipt), Some(admitted_at)) => {
                validate_digest(receipt, "native_worker_claim_receipt_digest")?;
                if admitted_at == 0 {
                    return Err(OrsError::InvalidField {
                        field: "native_worker_claim_admitted_at",
                        reason: "admission time must be greater than zero",
                    });
                }
            }
            _ => {
                return Err(OrsError::InvalidField {
                    field: "native_worker_claim_receipt",
                    reason: "an admitted claim carries its immutable receipt identity",
                });
            }
        }
        if !self.state.is_terminal() && self.commit_order != 0 {
            return Err(OrsError::InvalidField {
                field: "native_worker_claim_commit_order",
                reason: "non-terminal states must not carry a commit order",
            });
        }
        Ok(())
    }

    /// Returns the retained owner-verified executable-binding digest for one
    /// presented proof (issue #2567).
    ///
    /// The verified lookup: the attempt and operation must equal the retained
    /// row exactly, the claim must carry its immutable admission receipt (an
    /// unadmitted intent verifies nothing), and the retained digest itself
    /// must be well-formed and equal the presented digest. Anything else is
    /// rejected and never resolved to the caller's value: the returned
    /// reference always points at the durable row, never at the presentation.
    pub fn verified_executable_binding_digest(
        &self,
        attempt_id: &str,
        operation_id: &str,
        presented_digest: &str,
    ) -> Result<&str, OrsError> {
        if self.attempt_id.as_str() != attempt_id || self.operation_id.as_str() != operation_id {
            return Err(OrsError::NativeWorkerClaimIdentityConflict {
                claim_id: self.claim_id.as_str().to_owned(),
            });
        }
        if self.state == NativeWorkerClaimState::Requested
            || self.receipt_digest.is_none()
            || self.admitted_at_unix_ms.is_none()
        {
            return Err(OrsError::InvalidField {
                field: "native_worker_claim_receipt",
                reason: "an unadmitted claim carries no verifiable executable binding",
            });
        }
        validate_digest(
            &self.executable_binding_digest,
            "native_worker_claim_executable_binding_digest",
        )?;
        if self.executable_binding_digest != presented_digest {
            return Err(OrsError::NativeWorkerClaimIdentityConflict {
                claim_id: self.claim_id.as_str().to_owned(),
            });
        }
        Ok(&self.executable_binding_digest)
    }
}

/// Admission evidence bound when a requested claim becomes admitted.
///
/// Carried only by the `Requested -> Admitted` transition (and accepted
/// unchanged on an exact `Admitted -> Admitted` replay); it is never
/// overwritten once bound, so one claim identity keeps one receipt identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerClaimAdmission {
    pub receipt_digest: String,
    pub admitted_at_unix_ms: u64,
}

impl NativeWorkerClaimAdmission {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        validate_digest(&self.receipt_digest, "native_worker_claim_receipt_digest")?;
        if self.admitted_at_unix_ms == 0 {
            return Err(OrsError::InvalidField {
                field: "native_worker_claim_admitted_at",
                reason: "admission time must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Result of the atomic claim-staging write.
///
/// `Stored` is a newly persisted intent; `Existing` is an exact replay
/// carrying the same receipt identity. A changed binding under the same
/// claim identity is not a variant here: staging fails with
/// [`OrsError::NativeWorkerClaimIdentityConflict`] and never overwrites.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeWorkerClaimStageOutcome {
    Stored(NativeWorkerClaimRecord),
    Existing(NativeWorkerClaimRecord),
}

impl NativeWorkerClaimStageOutcome {
    /// Returns the durable record regardless of how the write resolved.
    pub fn record(&self) -> &NativeWorkerClaimRecord {
        match self {
            Self::Stored(record) | Self::Existing(record) => record,
        }
    }
}

// ---------------------------------------------------------------------------
// T9-03 owner-backed durable replay stream (issue #22, M3).
//
// Kernel/ORS owns the stream. The stream id is the exact `(claim id, worker
// generation)` pair rendered as `"{claim_id}/{generation}"` (two-part shape
// precedent: the T9-02 fixture `stream-claim-t9-02-1/gen-1`). The sequence is
// a monotonic `u64` per stream persisted in ORS. The producer cursor advances
// at DURABLE, the consumer cursor advances at APPLIED or REJECTED, and
// UNKNOWN never advances a cursor: an unknown outcome stays reconciling under
// its original identity. Retention holds every event until APPLIED/REJECTED,
// plus a bounded newest window of [`crate::MAX_REPLAY_PAGE`] terminal events. A new
// generation may read retained history but never acquires, appends, or
// acknowledges under a stale binding. Semantic observation ownership stays
// with its owner: ORS preserves the opaque envelope bytes, the owner receipt
// disposition, and the mechanical delivery class without interpreting them.
// The Kernel admission owner validates identity/epoch/fence; ORS compares the
// presented binding for exact equality against the bound claim record
// (read-only) and never re-derives authority.
//
// Wire revision is the kernel-service (W-B) adapter's business: W-B projects
// the worker `EpochId`/`StateFence` bindings onto the `u64` epoch sequence
// and fence digest the claim record already binds, exactly as the existing
// claim contour does (`authority_epoch` is the epoch sequence, `fence_digest`
// the opaque fence binding).
// ---------------------------------------------------------------------------

/// Maximum opaque causal-predecessor references retained on one replay event.
const MAX_REPLAY_EVENT_REFS: usize = 64;
/// Maximum trace-context entries retained on one replay event.
const MAX_REPLAY_TRACE_ENTRIES: usize = 64;

/// Builds the durable replay stream identity for one claim generation.
///
/// The stream id is `"{claim_id}/gen-{generation}"` with a nonzero generation,
/// matching the T9-02 executable-binding fixture (`stream-claim-t9-02-1/gen-1`)
/// and the kernel-service replay wire constructor. The claim identity is
/// already validated by construction; only the generation bound is checked
/// here.
pub fn replay_stream_id(claim_id: &OperationIdentity, generation: u64) -> Result<String, OrsError> {
    if generation == 0 {
        return Err(OrsError::InvalidField {
            field: "worker_replay_generation",
            reason: "generation must be greater than zero",
        });
    }
    Ok(format!("{}/gen-{}", claim_id.as_str(), generation))
}

/// Splits a replay stream identity back into its claim and generation halves.
///
/// The split is at the last `/` so a claim identity containing `/` still
/// round-trips through [`replay_stream_id`]. The generation half must be
/// `gen-{nonzero integer}`; owner-shaped strings without the `gen-` prefix
/// are rejected as malformed (fail closed) and must be mapped through
/// [`replay_stream_id`] by the kernel-service adapter before reaching ORS.
pub fn parse_replay_stream_id(stream_id: &str) -> Result<(OperationIdentity, u64), OrsError> {
    let (claim_part, generation_part) =
        stream_id.rsplit_once('/').ok_or(OrsError::InvalidField {
            field: "worker_replay_stream_id",
            reason: "stream identity must be \"{claim_id}/gen-{generation}\"",
        })?;
    let claim_id = OperationIdentity::new(claim_part).map_err(|_| OrsError::InvalidField {
        field: "worker_replay_stream_id",
        reason: "stream claim identity must be non-blank",
    })?;
    let generation: u64 = generation_part
        .strip_prefix("gen-")
        .and_then(|digits| digits.parse().ok())
        .filter(|generation| *generation > 0)
        .ok_or(OrsError::InvalidField {
            field: "worker_replay_stream_id",
            reason: "stream generation must be gen-{nonzero integer}",
        })?;
    Ok((claim_id, generation))
}

/// Explicit cursor phase for one replay acknowledgement.
///
/// Mirrors the worker acknowledgement phases mechanically: ORS routes cursors
/// from this value and never lets transport receipt impersonate application
/// outcome.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkerReplayPhase {
    Received,
    Durable,
    Normalized,
    Applied,
    Rejected,
    Unknown,
}

impl WorkerReplayPhase {
    /// M3 producer rule: only a DURABLE acknowledgement advances the producer
    /// cursor.
    pub const fn advances_producer_cursor(self) -> bool {
        matches!(self, Self::Durable)
    }

    /// M3 consumer rule: only APPLIED or REJECTED advances the consumer
    /// cursor. UNKNOWN (and the non-terminal phases) never advance a cursor.
    pub const fn advances_consumer_cursor(self) -> bool {
        matches!(self, Self::Applied | Self::Rejected)
    }
}

/// Mechanical delivery class preserved opaquely on one replay event.
///
/// This is delivery mechanics only: ORS never interprets payload meaning from
/// it, and semantic observation ownership stays with its owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkerReplayDeliveryClass {
    DurableControl,
    DurableObservation,
    BestEffortTelemetry,
}

/// Acquisition request for one durable replay request identity.
///
/// Lookup with this identity acquires nothing; begin atomically acquires or
/// reports the durable conflict. The numeric binding travels with the request
/// so the store can reject a stale generation/epoch/fence against the bound
/// claim without trusting the caller.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReplayBegin {
    pub stream_id: String,
    pub request_id: String,
    pub fingerprint: String,
    pub producer_generation: u64,
    pub authority_epoch: u64,
    pub fence_digest: String,
}

impl WorkerReplayBegin {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        parse_replay_stream_id(&self.stream_id)?;
        validate_text(&self.request_id, "worker_replay_request_id")?;
        validate_text(&self.fingerprint, "worker_replay_fingerprint")?;
        if self.producer_generation == 0 || self.authority_epoch == 0 {
            return Err(OrsError::InvalidField {
                field: "worker_replay_epoch",
                reason: "generation and epoch must be greater than zero",
            });
        }
        validate_digest(&self.fence_digest, "worker_replay_fence_digest")?;
        Ok(())
    }
}

/// Exact event content handed to the durable replay owner.
///
/// Every identity is opaque to ORS: the producer, request, payload label, and
/// payload bytes are preserved exactly for replay comparison and never
/// interpreted. The owner receipt disposition is preserved opaquely; the
/// Kernel admission owner validates it and ORS never re-derives control
/// meaning from it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReplayDraft {
    pub stream_id: String,
    pub producer_id: String,
    pub producer_generation: u64,
    pub authority_epoch: u64,
    pub fence_digest: String,
    pub request_id: String,
    pub causal_predecessor_refs: Vec<String>,
    pub delivery_class: WorkerReplayDeliveryClass,
    pub ack_required: bool,
    pub payload_type: String,
    pub payload: String,
    pub disposition: ReceiptDisposition,
    pub trace_context: BTreeMap<String, String>,
}

impl WorkerReplayDraft {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        parse_replay_stream_id(&self.stream_id)?;
        validate_text(&self.producer_id, "worker_replay_producer_id")?;
        validate_text(&self.request_id, "worker_replay_request_id")?;
        if self.producer_generation == 0 || self.authority_epoch == 0 {
            return Err(OrsError::InvalidField {
                field: "worker_replay_epoch",
                reason: "generation and epoch must be greater than zero",
            });
        }
        validate_digest(&self.fence_digest, "worker_replay_fence_digest")?;
        validate_text(&self.payload_type, "worker_replay_payload_type")?;
        let payload_len =
            u64::try_from(self.payload.len()).map_err(|_| OrsError::PayloadTooLarge)?;
        if payload_len > MAX_INLINE_RECOVERY_BYTES {
            return Err(OrsError::PayloadTooLarge);
        }
        if self.causal_predecessor_refs.len() > MAX_REPLAY_EVENT_REFS {
            return Err(OrsError::InvalidField {
                field: "worker_replay_causal_predecessor_refs",
                reason: "causal predecessor references exceed the retained bound",
            });
        }
        for reference in &self.causal_predecessor_refs {
            validate_text(reference, "worker_replay_causal_predecessor_ref")?;
        }
        if self.trace_context.len() > MAX_REPLAY_TRACE_ENTRIES {
            return Err(OrsError::InvalidField {
                field: "worker_replay_trace_context",
                reason: "trace context exceeds the retained bound",
            });
        }
        for (key, value) in &self.trace_context {
            validate_text(key, "worker_replay_trace_key")?;
            validate_text(value, "worker_replay_trace_value")?;
        }
        Ok(())
    }

    /// Canonical digest over the exact draft binding used for append
    /// idempotency: an identical draft replays the same durable identity and
    /// sequence instead of duplicating the event.
    pub(crate) fn draft_digest(&self) -> Result<String, OrsError> {
        let canonical = serde_json::json!({
            "ack_required": self.ack_required,
            "authority_epoch": self.authority_epoch,
            "causal_predecessor_refs": self.causal_predecessor_refs,
            "delivery_class": self.delivery_class,
            "disposition": self.disposition,
            "fence_digest": self.fence_digest,
            "payload": self.payload,
            "payload_type": self.payload_type,
            "producer_generation": self.producer_generation,
            "producer_id": self.producer_id,
            "request_id": self.request_id,
            "stream_id": self.stream_id,
            "trace_context": self.trace_context,
        });
        let bytes = canonical_json_bytes(&canonical)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// Durable replay event envelope returned by the replay owner.
///
/// The `event_id` and `sequence` are assigned atomically by ORS on append:
/// the sequence is monotonic per stream starting at 1, and the identity is
/// stable across close/reopen. The `fingerprint` is the request fingerprint
/// bound at acquisition, copied here for locality.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReplayEvent {
    pub contract_version: u16,
    pub stream_id: String,
    pub event_id: String,
    pub sequence: u64,
    pub request_id: String,
    pub fingerprint: String,
    pub producer_id: String,
    pub producer_generation: u64,
    pub authority_epoch: u64,
    pub fence_digest: String,
    pub causal_predecessor_refs: Vec<String>,
    pub delivery_class: WorkerReplayDeliveryClass,
    pub ack_required: bool,
    pub payload_type: String,
    pub payload: String,
    pub disposition: ReceiptDisposition,
    pub trace_context: BTreeMap<String, String>,
    pub draft_digest: String,
    pub durable_at_unix_ms: u64,
}

impl WorkerReplayEvent {
    /// Returns the durable key binding one stream to one exact sequence.
    /// The separator is a control character that validated identities can
    /// never contain, so composite keys cannot collide.
    pub fn record_key(&self) -> String {
        Self::key_for(&self.stream_id, self.sequence)
    }

    pub(crate) fn key_for(stream_id: &str, sequence: u64) -> String {
        format!("{stream_id}\u{1f}{sequence:020}")
    }

    pub(crate) fn key_prefix_for(stream_id: &str) -> String {
        format!("{stream_id}\u{1f}")
    }

    /// Validates identity shape and stream/binding coherence.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        let (_, stream_generation) = parse_replay_stream_id(&self.stream_id)?;
        validate_text(&self.event_id, "worker_replay_event_id")?;
        validate_text(&self.request_id, "worker_replay_request_id")?;
        validate_text(&self.fingerprint, "worker_replay_fingerprint")?;
        validate_text(&self.producer_id, "worker_replay_producer_id")?;
        validate_text(&self.payload_type, "worker_replay_payload_type")?;
        if self.sequence == 0 {
            return Err(OrsError::InvalidField {
                field: "worker_replay_sequence",
                reason: "sequence must be greater than zero",
            });
        }
        if self.producer_generation == 0 || self.authority_epoch == 0 {
            return Err(OrsError::InvalidField {
                field: "worker_replay_epoch",
                reason: "generation and epoch must be greater than zero",
            });
        }
        if stream_generation != self.producer_generation {
            return Err(OrsError::InvalidField {
                field: "worker_replay_generation",
                reason: "stream generation and producer generation must agree",
            });
        }
        validate_digest(&self.fence_digest, "worker_replay_fence_digest")?;
        validate_digest(&self.draft_digest, "worker_replay_draft_digest")?;
        let payload_len =
            u64::try_from(self.payload.len()).map_err(|_| OrsError::PayloadTooLarge)?;
        if payload_len > MAX_INLINE_RECOVERY_BYTES {
            return Err(OrsError::PayloadTooLarge);
        }
        if self.causal_predecessor_refs.len() > MAX_REPLAY_EVENT_REFS {
            return Err(OrsError::InvalidField {
                field: "worker_replay_causal_predecessor_refs",
                reason: "causal predecessor references exceed the retained bound",
            });
        }
        for reference in &self.causal_predecessor_refs {
            validate_text(reference, "worker_replay_causal_predecessor_ref")?;
        }
        if self.trace_context.len() > MAX_REPLAY_TRACE_ENTRIES {
            return Err(OrsError::InvalidField {
                field: "worker_replay_trace_context",
                reason: "trace context exceeds the retained bound",
            });
        }
        for (key, value) in &self.trace_context {
            validate_text(key, "worker_replay_trace_key")?;
            validate_text(value, "worker_replay_trace_value")?;
        }
        if self.durable_at_unix_ms == 0 {
            return Err(OrsError::InvalidField {
                field: "worker_replay_durable_at",
                reason: "durability time must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Durable per-stream replay head: cursors plus the next sequence.
///
/// The producer cursor is the newest DURABLE sequence, the consumer cursor
/// the newest APPLIED-or-REJECTED sequence, and `next_sequence` the sequence
/// the next append assigns. All three survive close/reopen in redb.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReplayStreamRecord {
    pub contract_version: u16,
    pub stream_id: String,
    pub claim_id: OperationIdentity,
    pub worker_generation: u64,
    pub producer_cursor: u64,
    pub consumer_cursor: u64,
    pub next_sequence: u64,
}

impl WorkerReplayStreamRecord {
    /// Validates identity shape and cursor/sequence coherence.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        let (claim_id, stream_generation) = parse_replay_stream_id(&self.stream_id)?;
        if claim_id != self.claim_id || stream_generation != self.worker_generation {
            return Err(OrsError::InvalidField {
                field: "worker_replay_stream_binding",
                reason: "stream identity must bind its claim and generation",
            });
        }
        if self.worker_generation == 0 {
            return Err(OrsError::InvalidField {
                field: "worker_replay_generation",
                reason: "generation must be greater than zero",
            });
        }
        if self.next_sequence == 0 {
            return Err(OrsError::InvalidField {
                field: "worker_replay_next_sequence",
                reason: "next sequence must be greater than zero",
            });
        }
        if self.producer_cursor >= self.next_sequence || self.consumer_cursor >= self.next_sequence
        {
            return Err(OrsError::InvalidField {
                field: "worker_replay_cursor",
                reason: "cursors must stay below the next sequence",
            });
        }
        Ok(())
    }
}

/// Durable acquisition of one `(stream, request)` identity.
///
/// The first writer wins: the fingerprint bound here rejects every later
/// changed binding under the same identity without overwriting.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReplayRequestRecord {
    pub stream_id: String,
    pub request_id: String,
    pub fingerprint: String,
    pub producer_generation: u64,
    pub authority_epoch: u64,
    pub fence_digest: String,
    pub acquired_at_unix_ms: u64,
}

impl WorkerReplayRequestRecord {
    /// Returns the durable key binding one stream to one exact request.
    pub fn record_key(&self) -> String {
        Self::key_for(&self.stream_id, &self.request_id)
    }

    pub(crate) fn key_for(stream_id: &str, request_id: &str) -> String {
        format!("{stream_id}\u{1f}{request_id}")
    }

    /// Validates identity shape and binding coherence.
    pub fn validate(&self) -> Result<(), OrsError> {
        let (_, stream_generation) = parse_replay_stream_id(&self.stream_id)?;
        validate_text(&self.request_id, "worker_replay_request_id")?;
        validate_text(&self.fingerprint, "worker_replay_fingerprint")?;
        if self.producer_generation == 0 || self.authority_epoch == 0 {
            return Err(OrsError::InvalidField {
                field: "worker_replay_epoch",
                reason: "generation and epoch must be greater than zero",
            });
        }
        if stream_generation != self.producer_generation {
            return Err(OrsError::InvalidField {
                field: "worker_replay_generation",
                reason: "stream generation and producer generation must agree",
            });
        }
        validate_digest(&self.fence_digest, "worker_replay_fence_digest")?;
        if self.acquired_at_unix_ms == 0 {
            return Err(OrsError::InvalidField {
                field: "worker_replay_acquired_at",
                reason: "acquisition time must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Acknowledgement of one durable replay event.
///
/// Every field must bind the stored event exactly: a foreign acknowledgement
/// (wrong stream, event, generation, epoch, or fence) is rejected and never
/// moves a cursor.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReplayAck {
    pub stream_id: String,
    pub event_id: String,
    pub sequence: u64,
    pub producer_generation: u64,
    pub authority_epoch: u64,
    pub fence_digest: String,
    pub phase: WorkerReplayPhase,
}

impl WorkerReplayAck {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        let (_, stream_generation) = parse_replay_stream_id(&self.stream_id)?;
        validate_text(&self.event_id, "worker_replay_event_id")?;
        if self.sequence == 0 {
            return Err(OrsError::InvalidField {
                field: "worker_replay_sequence",
                reason: "sequence must be greater than zero",
            });
        }
        if self.producer_generation == 0 || self.authority_epoch == 0 {
            return Err(OrsError::InvalidField {
                field: "worker_replay_epoch",
                reason: "generation and epoch must be greater than zero",
            });
        }
        if stream_generation != self.producer_generation {
            return Err(OrsError::InvalidField {
                field: "worker_replay_generation",
                reason: "stream generation and producer generation must agree",
            });
        }
        validate_digest(&self.fence_digest, "worker_replay_fence_digest")?;
        Ok(())
    }
}

/// Durable per-event acknowledgement fact.
///
/// One record per acknowledged `(stream, sequence)`, keyed exactly like its
/// event. Later phases overwrite the retained phase (DURABLE then APPLIED is
/// the normal lifecycle across two acknowledgements); cursors only move
/// forward under the phase rule, so reordering never regresses them.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReplayAckRecord {
    pub stream_id: String,
    pub event_id: String,
    pub sequence: u64,
    pub phase: WorkerReplayPhase,
    pub acknowledged_at_unix_ms: u64,
}

impl WorkerReplayAckRecord {
    /// Returns the durable key binding one acknowledgement to its event.
    pub fn record_key(&self) -> String {
        WorkerReplayEvent::key_for(&self.stream_id, self.sequence)
    }

    /// Validates identity shape.
    pub fn validate(&self) -> Result<(), OrsError> {
        parse_replay_stream_id(&self.stream_id)?;
        validate_text(&self.event_id, "worker_replay_event_id")?;
        if self.sequence == 0 {
            return Err(OrsError::InvalidField {
                field: "worker_replay_sequence",
                reason: "sequence must be greater than zero",
            });
        }
        if self.acknowledged_at_unix_ms == 0 {
            return Err(OrsError::InvalidField {
                field: "worker_replay_acknowledged_at",
                reason: "acknowledgement time must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Result of a replay-request lookup or atomic acquisition.
///
/// `New` carries no durable state: lookup acquired nothing and begin durably
/// acquired for the first time. `Replay` carries the request's retained
/// events in sequence order, so a retained acquisition after a crash is never
/// mistaken for a fresh request. `Conflict` reports a changed fingerprint
/// under a retained identity without overwriting it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerReplayRequestDecision {
    New,
    Replay(Vec<WorkerReplayEvent>),
    Conflict,
}

/// Durable per-stream cursor projection returned by acknowledgement.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReplayCursors {
    pub stream_id: String,
    pub producer_cursor: u64,
    pub consumer_cursor: u64,
}

/// Requires the presented stream binding to equal the bound claim.
///
/// The stream suffix, the presented generation, the claim's bound generation,
/// the presented epoch, the claim's bound epoch, and the fence binding must
/// all agree exactly. Reads never call this; every mutating replay path does,
/// against the existing claim record, read-only. A missing claim, a rotated
/// generation, or a disagreeing epoch/fence fails closed: the caller never
/// executes under a stale epoch.
pub(crate) fn require_replay_claim_binding(
    stream_id: &str,
    producer_generation: u64,
    authority_epoch: u64,
    fence_digest: &str,
    claim: &NativeWorkerClaimRecord,
) -> Result<(), OrsError> {
    let (claim_id, stream_generation) = parse_replay_stream_id(stream_id)?;
    if claim.claim_id != claim_id
        || stream_generation != producer_generation
        || producer_generation != claim.worker_generation
        || authority_epoch != claim.authority_epoch
        || fence_digest != claim.fence_digest
    {
        return Err(OrsError::WorkerReplayStaleStream {
            stream_id: stream_id.to_owned(),
        });
    }
    Ok(())
}

/// Returns true when an acknowledgement phase makes an event eligible for
/// retention pruning. Only APPLIED or REJECTED events prune; UNKNOWN stays
/// reconciling under its original identity.
pub(crate) const fn is_replay_terminal_phase(phase: WorkerReplayPhase) -> bool {
    phase.advances_consumer_cursor()
}

// ---------------------------------------------------------------------------
// T9-04 provider-capability read projection (issue #1108, M2 supplier core).
//
// Read-only lookup identity for resolving one durable claim row from the
// exact claim/attempt/operation triple carried by a provider-capability
// proof. This adds no new authority table and no write path: the claim row
// stays the single durable binding, and this projection only names the row a
// reverse scan must agree with byte-for-byte.
//
// The lookup carries identity only: there is deliberately no
// `executable_binding_digest` column on this projection. The durable claim
// row retains the owner-verified digest (issue #2567, populated at stage
// from the Kernel-gated v2 join); the executable digest is presented per
// call and compared against the retained row by
// [`NativeWorkerClaimRecord::verified_executable_binding_digest`] — never
// trusted by value — exactly like the T9-02 presented-expectation pattern.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapabilityLookup {
    /// Durable claim identity under which the proof is presented.
    pub claim_id: String,
    /// Attempt identity the proof claims to bind.
    pub attempt_id: String,
    /// Exact external-effect operation identity the proof claims to bind.
    pub operation_id: String,
}

impl ProviderCapabilityLookup {
    /// Validates the bounded lookup shape without consulting any authority.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.claim_id, "provider_capability_claim_id")?;
        validate_text(&self.attempt_id, "provider_capability_attempt_id")?;
        validate_text(&self.operation_id, "provider_capability_operation_id")?;
        Ok(())
    }

    /// Returns true only when a durable claim row carries exactly this
    /// claim/attempt/operation identity.
    ///
    /// All three comparisons are exact strings: attempt and operation labels
    /// are opaque to ORS (same opacity as on the claim row), so a foreign
    /// attempt or operation under a known claim identity never matches.
    pub fn matches(&self, record: &NativeWorkerClaimRecord) -> bool {
        record.claim_id.as_str() == self.claim_id
            && record.attempt_id.as_str() == self.attempt_id
            && record.operation_id.as_str() == self.operation_id
    }
}

/// Stable ORS record-type name of one durable scan disclosure record.
///
/// It is published rather than spelled as a literal at the call site so the
/// Governor scan-disclosure adapter can name the I5.27 identity-conflict
/// signal by this contract instead of by a second copy of the same string.
pub const SCAN_DISCLOSURE_RECORD_TYPE: &str = "scan_disclosure";

/// Bounded canonical receipt payload of one scan disclosure record.
///
/// Scan disclosure receipts carry bounded references and class dispositions
/// only (I4.3.1 intake shapes); 64 KiB is a hard ceiling, never a target.
pub const MAX_SCAN_DISCLOSURE_RECEIPT_BYTES: usize = 64 * 1024;

/// Bounded page size for historical scan disclosure reads.
pub const MAX_SCAN_DISCLOSURE_PAGE: u16 = 64;

/// Lifecycle of one durable scan disclosure record.
///
/// `Prepared` is the atomic-stage state: durable but not yet published at the
/// final content address. A crash between stage and commit leaves `Prepared`,
/// which reconciles the original operation instead of poisoning the key.
/// `Committed` is the final addressable answer. `Retired` and `Superseded`
/// mark retention without deleting evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanDisclosureRecordState {
    Prepared,
    Committed,
    Retired,
    Superseded,
}

/// Outcome of staging one durable scan disclosure record.
///
/// The disposition names what the durable row says about the request, never a
/// retry policy: `AlreadyBound` is the exact-replay answer for one operation
/// identity, and the durable winner it carries is the record the caller must
/// answer from. The winner is boxed so this two-variant disposition stays
/// small next to `Stored` instead of being sized by the record it may carry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanDisclosureStageOutcome {
    /// This candidate is now the durable `Prepared` row under its key.
    Stored,
    /// An already-durable row owns this operation key under the same
    /// binding. The carried record is the durable winner.
    AlreadyBound(Box<ScanDisclosureOrsRecord>),
}

/// One durable scan disclosure record (issue #2900).
///
/// ORS stores the owner-admitted write identity and the exact canonical
/// receipt bytes verbatim and interprets no scan, class, fence or recovery
/// meaning: every binding field is an opaque shape-admitted string, and the
/// receipt bytes are re-hashed against their digest on every read. A changed
/// privacy boundary, governing-source generation, root identity or scanner
/// schema arrives as a new operation key; this row is never mutated into a
/// different answer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanDisclosureOrsRecord {
    /// ORS wire/storage contract version of this row. A row written under
    /// another version fails its read closed instead of being reinterpreted
    /// as the same answer.
    pub contract_version: u16,
    /// Durable key: `scan-disclosure:<installation>:<operation>`.
    pub operation_key: String,
    /// Idempotency key admitted with this write.
    pub idempotency_key: String,
    /// Canonical request hash binding the exact receipt bytes to this write
    /// identity (I5.27). Reusing the key with a different value is an
    /// identity conflict, never a silent overwrite of the bound row.
    pub request_hash: String,
    /// Installation that owns the storage contour.
    pub installation_id: String,
    /// Principal the write is bound to (Kernel-issued, never self-declared).
    pub principal_ref: String,
    /// Session the write is bound to.
    pub session_ref: String,
    /// Host generation the write is bound to.
    pub host_generation_ref: String,
    /// Discovery lease identity this scan consumed.
    pub lease_ref: String,
    /// Discovery lease consumption units already consumed when the owner
    /// issued the write binding: the lease operation window this write rode
    /// on. Part of the canonical request hash, so the same key with a
    /// different consumption window conflicts.
    pub lease_consumed: u64,
    /// Candidate root this scan covered.
    pub candidate_root_ref: String,
    /// Privacy boundary admitted for this scan.
    pub privacy_boundary_ref: String,
    /// `StateFence` reference where available before `WorkScope` creation.
    pub state_fence_ref: Option<String>,
    /// `AuthorityEpoch` reference where available before creation.
    pub authority_epoch_ref: Option<String>,
    /// Policy revision admitted with this write.
    pub policy_revision: u64,
    /// Deadline admitted with this write.
    pub deadline: u64,
    /// Digest of the exact canonical receipt bytes.
    pub receipt_digest: String,
    /// Write-identity schema version of this row.
    pub schema_version: u32,
    /// Exact canonical receipt bytes (canonical JSON).
    pub receipt_bytes: String,
    /// Owner write receipt bound at commit; empty while `Prepared`.
    pub writer_receipt: String,
    /// Lifecycle state of this row.
    pub state: ScanDisclosureRecordState,
    /// Successor operation key when superseded; otherwise `None`.
    pub supersedes_ref: Option<String>,
    /// Policy revision that retired this row; otherwise `None`.
    pub retired_by_policy: Option<u64>,
}

impl ScanDisclosureOrsRecord {
    /// Returns whether two records carry the exact same admitted binding.
    ///
    /// ORS-owned reconciliation progression (`state`, `writer_receipt`,
    /// `supersedes_ref`, `retired_by_policy`) is excluded: it is durable
    /// progression, not caller binding.
    #[must_use]
    pub fn same_binding(&self, other: &Self) -> bool {
        self.operation_key == other.operation_key
            && self.idempotency_key == other.idempotency_key
            && self.request_hash == other.request_hash
            && self.installation_id == other.installation_id
            && self.principal_ref == other.principal_ref
            && self.session_ref == other.session_ref
            && self.host_generation_ref == other.host_generation_ref
            && self.lease_ref == other.lease_ref
            && self.lease_consumed == other.lease_consumed
            && self.candidate_root_ref == other.candidate_root_ref
            && self.privacy_boundary_ref == other.privacy_boundary_ref
            && self.state_fence_ref == other.state_fence_ref
            && self.authority_epoch_ref == other.authority_epoch_ref
            && self.policy_revision == other.policy_revision
            && self.deadline == other.deadline
            && self.receipt_digest == other.receipt_digest
            && self.schema_version == other.schema_version
            && self.receipt_bytes == other.receipt_bytes
    }

    /// Validates shape and identity binding without interpreting scan
    /// semantics. A `Prepared` row carries no writer receipt; any other state
    /// always binds one. Retirement markers appear only on retired rows.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != crate::CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        validate_text(&self.operation_key, "scan_disclosure_operation_key")?;
        validate_text(&self.idempotency_key, "scan_disclosure_idempotency_key")?;
        validate_digest(&self.request_hash, "scan_disclosure_request_hash")?;
        validate_text(&self.installation_id, "scan_disclosure_installation_id")?;
        validate_text(&self.principal_ref, "scan_disclosure_principal_ref")?;
        validate_text(&self.session_ref, "scan_disclosure_session_ref")?;
        validate_text(
            &self.host_generation_ref,
            "scan_disclosure_host_generation_ref",
        )?;
        validate_text(&self.lease_ref, "scan_disclosure_lease_ref")?;
        validate_text(
            &self.candidate_root_ref,
            "scan_disclosure_candidate_root_ref",
        )?;
        validate_text(
            &self.privacy_boundary_ref,
            "scan_disclosure_privacy_boundary_ref",
        )?;
        if let Some(fence) = &self.state_fence_ref {
            validate_text(fence, "scan_disclosure_state_fence_ref")?;
        }
        if let Some(epoch) = &self.authority_epoch_ref {
            validate_text(epoch, "scan_disclosure_authority_epoch_ref")?;
        }
        if self.policy_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "scan_disclosure_policy_revision",
                reason: "policy revision must be non-zero",
            });
        }
        if self.deadline == 0 {
            return Err(OrsError::InvalidField {
                field: "scan_disclosure_deadline",
                reason: "deadline must be non-zero",
            });
        }
        validate_digest(&self.receipt_digest, "scan_disclosure_receipt_digest")?;
        if self.schema_version == 0 {
            return Err(OrsError::InvalidField {
                field: "scan_disclosure_schema_version",
                reason: "schema version must be non-zero",
            });
        }
        if self.receipt_bytes.is_empty()
            || self.receipt_bytes.len() > MAX_SCAN_DISCLOSURE_RECEIPT_BYTES
        {
            return Err(OrsError::InvalidField {
                field: "scan_disclosure_receipt_bytes",
                reason: "receipt bytes must be non-empty and bounded",
            });
        }
        serde_json::from_str::<Value>(&self.receipt_bytes).map_err(|_| OrsError::InvalidField {
            field: "scan_disclosure_receipt_bytes",
            reason: "receipt bytes must be JSON",
        })?;
        match self.state {
            ScanDisclosureRecordState::Prepared => {
                if !self.writer_receipt.is_empty() {
                    return Err(OrsError::InvalidField {
                        field: "scan_disclosure_writer_receipt",
                        reason: "a prepared record carries no writer receipt",
                    });
                }
            }
            ScanDisclosureRecordState::Committed
            | ScanDisclosureRecordState::Retired
            | ScanDisclosureRecordState::Superseded => {
                validate_text(&self.writer_receipt, "scan_disclosure_writer_receipt")?;
            }
        }
        if let Some(successor) = &self.supersedes_ref {
            if self.state != ScanDisclosureRecordState::Superseded {
                return Err(OrsError::InvalidField {
                    field: "scan_disclosure_supersedes_ref",
                    reason: "only a superseded record names its successor",
                });
            }
            validate_text(successor, "scan_disclosure_supersedes_ref")?;
        }
        let retired_row = matches!(
            self.state,
            ScanDisclosureRecordState::Retired | ScanDisclosureRecordState::Superseded
        );
        if self.retired_by_policy.is_some() != retired_row {
            return Err(OrsError::InvalidField {
                field: "scan_disclosure_retired_by_policy",
                reason: "retirement markers appear only on retired rows",
            });
        }
        Ok(())
    }
}

/// Stable ORS record-type name for durable cold-start readiness ownership.
pub const COLD_START_READINESS_RECORD_TYPE: &str = "cold_start_readiness";

/// Exact identity and governing-source fence for one cold-start readiness key.
///
/// ORS retains the typed identity inputs and recomputes both key digests on
/// every read. The boundary reference is supplied by the authenticated owner
/// route; a privacy class by itself is not treated as a boundary identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdStartReadinessOwnerKey {
    pub installation_id: String,
    pub lineage_candidate_ref: String,
    pub workspace_instance_candidate_ref: String,
    pub filesystem_identity_ref: String,
    pub vcs_identity_ref: Option<String>,
    pub privacy_boundary_ref: String,
    pub privacy_class: PrivacyClass,
    pub governing_source_set_ref: String,
    pub governing_source_generation: u64,
    pub governing_source_digests: Vec<String>,
    pub dirty_summary_ref: Option<String>,
    pub state_fence: StateFence,
}

impl ColdStartReadinessOwnerKey {
    /// Validates identity and fence fields without resolving authority.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.installation_id, "cold_start_installation_id")?;
        validate_text(
            &self.lineage_candidate_ref,
            "cold_start_lineage_candidate_ref",
        )?;
        validate_text(
            &self.workspace_instance_candidate_ref,
            "cold_start_workspace_instance_ref",
        )?;
        validate_text(
            &self.filesystem_identity_ref,
            "cold_start_filesystem_identity_ref",
        )?;
        if let Some(vcs_identity) = &self.vcs_identity_ref {
            validate_text(vcs_identity, "cold_start_vcs_identity_ref")?;
        }
        validate_text(
            &self.privacy_boundary_ref,
            "cold_start_privacy_boundary_ref",
        )?;
        validate_text(
            &self.governing_source_set_ref,
            "cold_start_governing_source_set_ref",
        )?;
        if self.governing_source_generation == 0 {
            return Err(OrsError::InvalidField {
                field: "cold_start_governing_source_generation",
                reason: "governing-source generation must be non-zero",
            });
        }
        let mut previous: Option<&str> = None;
        for digest in &self.governing_source_digests {
            validate_digest(digest, "cold_start_governing_source_digest")?;
            if previous.is_some_and(|observed| observed >= digest.as_str()) {
                return Err(OrsError::InvalidField {
                    field: "cold_start_governing_source_digests",
                    reason: "source digest set must be sorted and unique",
                });
            }
            previous = Some(digest);
        }
        if let Some(dirty_summary) = &self.dirty_summary_ref {
            validate_text(dirty_summary, "cold_start_dirty_summary_ref")?;
        }
        self.state_fence
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))
    }

    fn base_identity_digest(&self) -> Result<String, OrsError> {
        let preimage = ColdStartReadinessBaseIdentityPreimage {
            installation_id: &self.installation_id,
            lineage_candidate_ref: &self.lineage_candidate_ref,
            workspace_instance_candidate_ref: &self.workspace_instance_candidate_ref,
            filesystem_identity_ref: &self.filesystem_identity_ref,
            vcs_identity_ref: self.vcs_identity_ref.as_deref(),
            privacy_boundary_ref: &self.privacy_boundary_ref,
            privacy_class: self.privacy_class,
        };
        let bytes = canonical_json_bytes(&preimage)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    fn binding_digest(&self) -> Result<String, OrsError> {
        let base_identity_digest = self.base_identity_digest()?;
        let preimage = ColdStartReadinessBindingPreimage {
            base_identity_digest: &base_identity_digest,
            governing_source_set_ref: &self.governing_source_set_ref,
            governing_source_generation: self.governing_source_generation,
            governing_source_digests: &self.governing_source_digests,
            dirty_summary_ref: self.dirty_summary_ref.as_deref(),
            state_fence: &self.state_fence,
        };
        let bytes = canonical_json_bytes(&preimage)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

#[derive(Serialize)]
struct ColdStartReadinessBaseIdentityPreimage<'a> {
    installation_id: &'a str,
    lineage_candidate_ref: &'a str,
    workspace_instance_candidate_ref: &'a str,
    filesystem_identity_ref: &'a str,
    vcs_identity_ref: Option<&'a str>,
    privacy_boundary_ref: &'a str,
    privacy_class: PrivacyClass,
}

#[derive(Serialize)]
struct ColdStartReadinessBindingPreimage<'a> {
    base_identity_digest: &'a str,
    governing_source_set_ref: &'a str,
    governing_source_generation: u64,
    governing_source_digests: &'a [String],
    dirty_summary_ref: Option<&'a str>,
    state_fence: &'a StateFence,
}

/// Candidate lease claim submitted to the canonical ORS readiness owner.
///
/// The lease bytes are canonical JSON and contain no task or authority
/// binding. Repeated claims with the same computed binding digest share the
/// first retained lease, even when a caller proposes a different lease ref.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdStartReadinessClaim {
    pub contract_version: u16,
    pub base_identity_digest: String,
    pub binding_digest: String,
    pub key: ColdStartReadinessOwnerKey,
    pub lease_ref: String,
    pub lease_deadline: u64,
    pub lease_digest: String,
    pub lease_bytes: String,
}

impl ColdStartReadinessClaim {
    /// Constructs and validates a lease claim with owner-derived identity hashes.
    #[allow(
        clippy::too_many_arguments,
        reason = "the canonical lease claim binds its full identity, generation, fence, and exact serialized lease in one constructor"
    )]
    pub fn new(
        key: ColdStartReadinessOwnerKey,
        lease_ref: String,
        lease_deadline: u64,
        lease_bytes: String,
    ) -> Result<Self, OrsError> {
        key.validate()?;
        let base_identity_digest = key.base_identity_digest()?;
        let binding_digest = key.binding_digest()?;
        let lease_digest = sha256_hex(lease_bytes.as_bytes());
        let claim = Self {
            contract_version: CONTRACT_VERSION,
            base_identity_digest,
            binding_digest,
            key,
            lease_ref,
            lease_deadline,
            lease_digest,
            lease_bytes,
        };
        claim.validate()?;
        Ok(claim)
    }

    /// Validates canonical payload bytes and recomputes every durable key.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        self.key.validate()?;
        validate_digest(
            &self.base_identity_digest,
            "cold_start_base_identity_digest",
        )?;
        validate_digest(&self.binding_digest, "cold_start_binding_digest")?;
        if self.key.base_identity_digest()? != self.base_identity_digest
            || self.key.binding_digest()? != self.binding_digest
        {
            return Err(OrsError::IntegrityProblem {
                record_type: COLD_START_READINESS_RECORD_TYPE,
                reason: "cold-start key digest does not match its exact identity and fence"
                    .to_owned(),
            });
        }
        validate_text(&self.lease_ref, "cold_start_lease_ref")?;
        if self.lease_deadline == 0 {
            return Err(OrsError::InvalidField {
                field: "cold_start_lease_deadline",
                reason: "lease deadline must be non-zero",
            });
        }
        validate_digest(&self.lease_digest, "cold_start_lease_digest")?;
        if self.lease_bytes.is_empty() {
            return Err(OrsError::InvalidField {
                field: "cold_start_lease_bytes",
                reason: "lease bytes must be non-empty",
            });
        }
        if sha256_hex(self.lease_bytes.as_bytes()) != self.lease_digest {
            return Err(OrsError::IntegrityProblem {
                record_type: COLD_START_READINESS_RECORD_TYPE,
                reason: "cold-start lease bytes do not match their digest".to_owned(),
            });
        }
        let value: Value =
            serde_json::from_str(&self.lease_bytes).map_err(|_| OrsError::InvalidField {
                field: "cold_start_lease_bytes",
                reason: "lease bytes must be JSON",
            })?;
        let canonical =
            canonical_json_bytes(&value).map_err(|error| OrsError::Encoding(error.to_string()))?;
        if canonical.as_slice() != self.lease_bytes.as_bytes() {
            return Err(OrsError::InvalidField {
                field: "cold_start_lease_bytes",
                reason: "lease bytes must use canonical JSON encoding",
            });
        }
        let expected_privacy = serde_json::to_value(self.key.privacy_class)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        if value.get("lease_ref").and_then(Value::as_str) != Some(self.lease_ref.as_str())
            || value.get("lineage_candidate_ref").and_then(Value::as_str)
                != Some(self.key.lineage_candidate_ref.as_str())
            || value
                .get("workspace_instance_candidate_ref")
                .and_then(Value::as_str)
                != Some(self.key.workspace_instance_candidate_ref.as_str())
            || value.get("privacy_class") != Some(&expected_privacy)
            || value
                .get("governing_source_generation")
                .and_then(Value::as_u64)
                != Some(self.key.governing_source_generation)
            || value.get("deadline").and_then(Value::as_u64) != Some(self.lease_deadline)
        {
            return Err(OrsError::IntegrityProblem {
                record_type: COLD_START_READINESS_RECORD_TYPE,
                reason: "serialized cold-start lease disagrees with its owner key".to_owned(),
            });
        }
        Ok(())
    }

    pub(crate) fn same_key(&self, other: &Self) -> bool {
        self.base_identity_digest == other.base_identity_digest
            && self.binding_digest == other.binding_digest
            && self.key == other.key
    }
}

/// Terminal disposition of one immutable readiness receipt revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColdStartReadinessTerminalDisposition {
    Ready,
    Ambiguous,
    Failed,
}

/// Exact canonical terminal receipt retained with its lease revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdStartReadinessTerminalReceipt {
    pub disposition: ColdStartReadinessTerminalDisposition,
    pub receipt_ref: String,
    pub receipt_revision: u64,
    pub receipt_digest: String,
    pub receipt_bytes: String,
}

/// One durable cold-start lease or immutable terminal readiness revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdStartReadinessOrsRecord {
    pub contract_version: u16,
    pub record_key: String,
    pub record_revision: u64,
    pub claim: ColdStartReadinessClaim,
    pub terminal: Option<ColdStartReadinessTerminalReceipt>,
}

impl ColdStartReadinessOrsRecord {
    pub(crate) fn leased(claim: ColdStartReadinessClaim, record_revision: u64) -> Self {
        Self {
            contract_version: CONTRACT_VERSION,
            record_key: cold_start_readiness_record_key(
                &claim.base_identity_digest,
                record_revision,
            ),
            record_revision,
            claim,
            terminal: None,
        }
    }

    /// Revalidates the exact row key and any terminal receipt bytes.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        self.claim.validate()?;
        self.validate_row_identity()?;
        if let Some(terminal) = &self.terminal {
            self.validate_terminal_receipt(terminal)?;
        }
        Ok(())
    }

    fn validate_row_identity(&self) -> Result<(), OrsError> {
        if self.record_revision == 0
            || self.record_key
                != cold_start_readiness_record_key(
                    &self.claim.base_identity_digest,
                    self.record_revision,
                )
        {
            return Err(OrsError::IntegrityProblem {
                record_type: COLD_START_READINESS_RECORD_TYPE,
                reason: "cold-start row key does not match its durable revision".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_terminal_receipt(
        &self,
        terminal: &ColdStartReadinessTerminalReceipt,
    ) -> Result<(), OrsError> {
        let value = self.canonical_terminal_value(terminal)?;
        self.validate_terminal_binding(terminal, &value)?;
        Self::validate_terminal_disposition(terminal, &value)
    }

    fn canonical_terminal_value(
        &self,
        terminal: &ColdStartReadinessTerminalReceipt,
    ) -> Result<Value, OrsError> {
        validate_text(&terminal.receipt_ref, "cold_start_receipt_ref")?;
        validate_digest(&terminal.receipt_digest, "cold_start_receipt_digest")?;
        if terminal.receipt_revision != self.record_revision {
            return Err(OrsError::IntegrityProblem {
                record_type: COLD_START_READINESS_RECORD_TYPE,
                reason: "terminal readiness revision does not match its lease revision".to_owned(),
            });
        }
        if terminal.receipt_bytes.is_empty() {
            return Err(OrsError::InvalidField {
                field: "cold_start_receipt_bytes",
                reason: "terminal receipt bytes must be non-empty",
            });
        }
        if sha256_hex(terminal.receipt_bytes.as_bytes()) != terminal.receipt_digest {
            return Err(OrsError::IntegrityProblem {
                record_type: COLD_START_READINESS_RECORD_TYPE,
                reason: "terminal receipt bytes do not match their digest".to_owned(),
            });
        }
        let value: Value =
            serde_json::from_str(&terminal.receipt_bytes).map_err(|_| OrsError::InvalidField {
                field: "cold_start_receipt_bytes",
                reason: "terminal receipt bytes must be JSON",
            })?;
        let canonical =
            canonical_json_bytes(&value).map_err(|error| OrsError::Encoding(error.to_string()))?;
        if canonical.as_slice() != terminal.receipt_bytes.as_bytes() {
            return Err(OrsError::InvalidField {
                field: "cold_start_receipt_bytes",
                reason: "terminal receipt bytes must use canonical JSON encoding",
            });
        }
        Ok(value)
    }

    fn validate_terminal_binding(
        &self,
        terminal: &ColdStartReadinessTerminalReceipt,
        value: &Value,
    ) -> Result<(), OrsError> {
        let expected_fence = serde_json::to_value(&self.claim.key.state_fence)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        let expected_lineage = Value::String(self.claim.key.lineage_candidate_ref.clone());
        let expected_vcs = serde_json::to_value(&self.claim.key.vcs_identity_ref)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        let scope = value.get("scope");
        let instance = value.get("instance");
        let identity_matches = value.get("receipt_ref").and_then(Value::as_str)
            == Some(terminal.receipt_ref.as_str())
            && value.get("lease_ref").and_then(Value::as_str)
                == Some(self.claim.lease_ref.as_str())
            && value.get("receipt_revision").and_then(Value::as_u64) == Some(self.record_revision)
            && value
                .get("governing_source_generation")
                .and_then(Value::as_u64)
                == Some(self.claim.key.governing_source_generation)
            && value
                .get("governing_source_set_ref")
                .and_then(Value::as_str)
                == Some(self.claim.key.governing_source_set_ref.as_str())
            && value.get("state_fence") == Some(&expected_fence)
            && scope.and_then(|scope| scope.get("lineage_ref")) == Some(&expected_lineage)
            && scope
                .and_then(|scope| scope.get("instance_ref"))
                .and_then(Value::as_str)
                == Some(self.claim.key.workspace_instance_candidate_ref.as_str())
            && scope
                .and_then(|scope| scope.get("root_identity"))
                .and_then(Value::as_str)
                == Some(self.claim.key.filesystem_identity_ref.as_str())
            && instance
                .and_then(|instance| instance.get("instance_ref"))
                .and_then(Value::as_str)
                == Some(self.claim.key.workspace_instance_candidate_ref.as_str())
            && instance
                .and_then(|instance| instance.get("root_identity"))
                .and_then(Value::as_str)
                == Some(self.claim.key.filesystem_identity_ref.as_str())
            && instance.and_then(|instance| instance.get("vcs_identity_ref"))
                == Some(&expected_vcs)
            && value.get("expiry_tick").and_then(Value::as_u64) == Some(self.claim.lease_deadline);
        if !identity_matches {
            return Err(OrsError::IntegrityProblem {
                record_type: COLD_START_READINESS_RECORD_TYPE,
                reason: "terminal receipt disagrees with its lease, identity, or fence".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_terminal_disposition(
        terminal: &ColdStartReadinessTerminalReceipt,
        value: &Value,
    ) -> Result<(), OrsError> {
        let readiness = value.get("readiness").and_then(Value::as_str);
        let task_disposition = value
            .get("task_binding")
            .and_then(|binding| binding.get("disposition"))
            .and_then(Value::as_str);
        let receipt_disposition = match readiness {
            Some("READY_MATERIAL" | "READY_READ_ONLY") => {
                ColdStartReadinessTerminalDisposition::Ready
            }
            Some("NEEDS_TASK") if task_disposition == Some("ambiguous") => {
                ColdStartReadinessTerminalDisposition::Ambiguous
            }
            _ => ColdStartReadinessTerminalDisposition::Failed,
        };
        if terminal.disposition != receipt_disposition {
            return Err(OrsError::IntegrityProblem {
                record_type: COLD_START_READINESS_RECORD_TYPE,
                reason: "terminal disposition disagrees with the readiness receipt".to_owned(),
            });
        }
        Ok(())
    }
}

/// Outcome of one atomic durable cold-start lease claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ColdStartReadinessStageOutcome {
    /// This caller atomically created the active lease revision.
    Stored {
        record: Box<ColdStartReadinessOrsRecord>,
    },
    /// An earlier durable lease or terminal receipt owns the same exact key.
    AlreadyBound {
        record: Box<ColdStartReadinessOrsRecord>,
    },
}

fn cold_start_readiness_record_key(base_identity_digest: &str, revision: u64) -> String {
    format!("cold-start-readiness:{base_identity_digest}:{revision:020}")
}
