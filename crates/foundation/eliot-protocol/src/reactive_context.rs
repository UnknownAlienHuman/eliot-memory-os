//! Pure outbound reactive Context contracts.
//!
//! This module binds the typed Context packet to the existing protocol event
//! and acknowledgement owners.  It does not enqueue, persist, deliver,
//! authenticate, observe a model, or grant authority.  The generic event
//! envelope carries an immutable content handle because adding a second
//! generic payload owner would split replay identity and lifecycle ownership.

use std::collections::BTreeSet;

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, ContractIdentity, ContractVersion, OperationId, RequestId, ResourceGeneration,
    SessionId, StateFence, TaskId, canonical_json_bytes, contract_identity, sha256_hex,
};
use eliot_receipts::{ProofCeiling, WorkScopeBinding};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AckPhase, DeliveryClass, EventAckReceipt, EventDisposition, EventEnvelope, EventPayload,
    ProtocolError,
};

/// Stable identity of the reactive Context contract.
pub const REACTIVE_CONTEXT_CONTRACT_NAME: &str = "eliot.foundation.reactive-context";
/// Current semantic contract revision.
pub const REACTIVE_CONTEXT_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Exact generic event payload discriminator.
pub const REACTIVE_CONTEXT_PAYLOAD_TYPE: &str = "reactive-context/v1";
/// Producer identity used by the pure mapping.
pub const REACTIVE_CONTEXT_PRODUCER_ID: &str = "eliot-reactive-context";
/// Maximum bytes for one bounded text field.
pub const MAX_REACTIVE_CONTEXT_TEXT_BYTES: usize = 8 * 1024;
/// Maximum bytes for one opaque serialized reference.
pub const MAX_REACTIVE_CONTEXT_CONTENT_BYTES: usize = 64 * 1024;
/// Maximum canonical JSON bytes accepted for one typed outbound payload.
pub const MAX_REACTIVE_CONTEXT_PAYLOAD_BYTES: usize = 256 * 1024;
/// Maximum number of causal predecessors in the outbound packet.
pub const MAX_REACTIVE_CONTEXT_PREDECESSORS: usize = 32;
/// Maximum acknowledgement receipts retained by the in-memory replay ledger.
pub const MAX_REACTIVE_CONTEXT_ACK_HISTORY: usize = 64;

/// Return the content-addressed identity of the current reactive Context
/// contract shape.
pub fn reactive_context_contract_identity() -> Result<ContractIdentity, ReactiveContextError> {
    let shape = schemars::schema_for!(ReactiveContextPayload);
    contract_identity(
        REACTIVE_CONTEXT_CONTRACT_NAME,
        REACTIVE_CONTEXT_CONTRACT_VERSION,
        &shape,
    )
    .map_err(|_| ReactiveContextError::InvalidField {
        field: "contract",
        reason: "cannot derive contract identity",
    })
}

/// Errors returned by the pure reactive Context contract.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ReactiveContextError {
    /// The existing generic protocol owner rejected a mapped value.
    #[error("protocol: {0}")]
    Protocol(#[from] ProtocolError),
    /// A dependent owner rejected an identity, fence, receipt, or contract.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Stable bounded reason.
        reason: &'static str,
    },
    /// A supplied value does not match the payload or event being evidenced.
    #[error("{field} does not match the reactive Context event")]
    Mismatch {
        /// Field path that diverged.
        field: &'static str,
    },
    /// A canonical identity was reused with changed content.
    #[error("reactive Context replay identity conflicts with changed content")]
    ReplayConflict,
    /// A stream sequence is missing its exact successor.
    #[error("sequence gap: expected {expected}, observed {observed}")]
    SequenceGap {
        /// Required next sequence.
        expected: u64,
        /// Supplied sequence.
        observed: u64,
    },
    /// A stream sequence moved backwards.
    #[error("sequence regression: previous {previous}, observed {observed}")]
    SequenceRegression {
        /// Prior sequence.
        previous: u64,
        /// Supplied sequence.
        observed: u64,
    },
    /// A generic acknowledgement phase skipped its owner-defined predecessor.
    #[error("invalid acknowledgement transition from {from} to {to}")]
    InvalidAckTransition {
        /// Prior phase.
        from: AckPhase,
        /// Supplied phase.
        to: AckPhase,
    },
    /// The supplied acknowledgement is an exact historical replay.
    #[error("duplicate historical acknowledgement")]
    DuplicateHistorical,
    /// A deadline or invalidation makes the supplied evidence non-current.
    #[error("reactive Context evidence is no longer current")]
    NotCurrent,
    /// The supplied stage cannot be established by the generic acknowledgement.
    #[error("generic acknowledgement does not support this Context stage")]
    UnsupportedStage,
    /// Canonical serialization failed.
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
}

fn text(value: &str, field: &'static str, maximum: usize) -> Result<(), ReactiveContextError> {
    if value.trim().is_empty() {
        return Err(ReactiveContextError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ReactiveContextError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > maximum {
        return Err(ReactiveContextError::InvalidField {
            field,
            reason: "exceeds bounded UTF-8 bytes",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), ReactiveContextError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ReactiveContextError::InvalidField {
            field,
            reason: "must be lowercase SHA-256",
        });
    }
    Ok(())
}

fn contract(value: &ContractIdentity, field: &'static str) -> Result<(), ReactiveContextError> {
    value
        .validate()
        .map_err(|_| ReactiveContextError::InvalidField {
            field,
            reason: "invalid contract identity",
        })
}

/// An immutable, bounded reference to a planner, view, recipe, measurement,
/// receipt, serialized payload, or other owner-produced contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextContentRef {
    /// Exact owner contract identity and shape digest.
    pub contract: ContractIdentity,
    /// Owner revision of the referenced content.
    pub source_revision: String,
    /// Canonical digest of the complete referenced content.
    pub content_sha256: String,
    /// Exact serialized byte length when measured; `None` remains unknown.
    pub byte_length: Option<u64>,
    /// Optional immutable artifact handle.
    pub artifact_id: Option<ArtifactId>,
}

impl ReactiveContextContentRef {
    /// Validate the bounded immutable reference.
    pub fn validate(&self) -> Result<(), ReactiveContextError> {
        contract(&self.contract, "content.contract")?;
        text(
            &self.source_revision,
            "content.source_revision",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        digest(&self.content_sha256, "content.content_sha256")?;
        if self
            .byte_length
            .is_some_and(|length| length > MAX_REACTIVE_CONTEXT_CONTENT_BYTES as u64)
        {
            return Err(ReactiveContextError::InvalidField {
                field: "content.byte_length",
                reason: "exceeds bounded bytes",
            });
        }
        Ok(())
    }
}

/// Exact planner request, decision, and receipt references.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextPlannerBinding {
    /// Planner request contract.
    pub request: ReactiveContextContentRef,
    /// Planner decision contract.
    pub decision: ReactiveContextContentRef,
    /// Planner receipt contract.
    pub receipt: ReactiveContextContentRef,
}

impl ReactiveContextPlannerBinding {
    /// Validate each planner owner reference.
    pub fn validate(&self) -> Result<(), ReactiveContextError> {
        self.request.validate()?;
        self.decision.validate()?;
        self.receipt.validate()?;
        Ok(())
    }
}

/// Recipient endpoint supplied by the owner that owns runtime/session facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextRecipient {
    /// Exact recipient session identity.
    pub session_id: SessionId,
    /// Opaque runtime identity.
    pub runtime_id: String,
    /// Runtime generation used to fence replacement.
    pub runtime_generation: ResourceGeneration,
    /// Route fingerprint or route identity.
    pub route: String,
}

impl ReactiveContextRecipient {
    /// Validate supplied recipient identity without authenticating it.
    pub fn validate(&self) -> Result<(), ReactiveContextError> {
        text(
            self.session_id.as_str(),
            "recipient.session_id",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        text(
            &self.runtime_id,
            "recipient.runtime_id",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        text(
            &self.route,
            "recipient.route",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        if self.runtime_generation.value() == 0 {
            return Err(ReactiveContextError::InvalidField {
                field: "recipient.runtime_generation",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

/// View, admitted-set, recipe, assembly, content, and measurement bindings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextViewBinding {
    /// Exact immutable view identity.
    pub view_id: ArtifactId,
    /// View generation used to reject stale projections.
    pub view_generation: ResourceGeneration,
    /// Admitted set used by the view.
    pub admitted_set: ReactiveContextContentRef,
    /// Recipe used to assemble the view.
    pub recipe: ReactiveContextContentRef,
    /// Assembly receipt for the exact view.
    pub assembly_receipt: ReactiveContextContentRef,
    /// Serialized bounded representation or immutable artifact reference.
    pub representation: ReactiveContextContentRef,
    /// Serializer/tokenizer and measured lengths.
    pub measurement: ReactiveContextMeasurement,
}

impl ReactiveContextViewBinding {
    /// Validate all view and assembly references.
    pub fn validate(&self) -> Result<(), ReactiveContextError> {
        text(
            self.view_id.as_str(),
            "view.view_id",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        if self.view_generation.value() == 0 {
            return Err(ReactiveContextError::InvalidField {
                field: "view.view_generation",
                reason: "must be non-zero",
            });
        }
        self.admitted_set.validate()?;
        self.recipe.validate()?;
        self.assembly_receipt.validate()?;
        self.representation.validate()?;
        self.measurement.validate()
    }
}

/// Measurement identity supplied by an instrumentation owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextMeasurement {
    /// Serializer contract and options reference.
    pub serializer: ReactiveContextContentRef,
    /// Tokenizer contract and version reference.
    pub tokenizer: ReactiveContextContentRef,
    /// Exact serialized representation length.
    pub serialized_byte_length: u64,
    /// Actual tokenizer token count when exposed by the owner.
    pub token_count: Option<u64>,
}

impl ReactiveContextMeasurement {
    /// Validate explicit measurement dimensions and bounded values.
    pub fn validate(&self) -> Result<(), ReactiveContextError> {
        self.serializer.validate()?;
        self.tokenizer.validate()?;
        if self.serialized_byte_length > MAX_REACTIVE_CONTEXT_CONTENT_BYTES as u64 {
            return Err(ReactiveContextError::InvalidField {
                field: "measurement.serialized_byte_length",
                reason: "must be within the bounded non-zero range",
            });
        }
        Ok(())
    }
}

/// Privacy and proof ceiling supplied for the packet's safety floor.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReactiveContextPrivacy {
    Public,
    Internal,
    Sensitive,
    Restricted,
}

/// Explicit disclosure/proof binding; it never grants authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextSafetyFloor {
    /// Owner contract that defines the floor.
    pub owner: ReactiveContextContentRef,
    /// Privacy class of the delivered projection.
    pub privacy: ReactiveContextPrivacy,
    /// Disclosure dependency closure reference.
    pub disclosure_closure: ReactiveContextContentRef,
    /// Highest proof interpretation supported by this packet.
    pub proof_ceiling: ProofCeiling,
}

impl ReactiveContextSafetyFloor {
    /// Validate privacy, disclosure, and proof bindings.
    pub fn validate(&self) -> Result<(), ReactiveContextError> {
        self.owner.validate()?;
        self.disclosure_closure.validate()
    }
}

/// Ordered reactive stream sequence and predecessor cursor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextSequence {
    /// Stable stream identity.
    pub stream_id: String,
    /// Exact event sequence in that stream.
    pub sequence: u64,
    /// Exact predecessor event IDs, in causal order.
    pub predecessor_event_ids: Vec<String>,
    /// Source cursor associated with the sequence.
    pub cursor: u64,
}

impl ReactiveContextSequence {
    /// Validate local sequence shape; successor checks use `validate_successor`.
    pub fn validate(&self) -> Result<(), ReactiveContextError> {
        text(
            &self.stream_id,
            "sequence.stream_id",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        if self.sequence == 0 {
            return Err(ReactiveContextError::InvalidField {
                field: "sequence.sequence",
                reason: "must be non-zero",
            });
        }
        if self.predecessor_event_ids.len() > MAX_REACTIVE_CONTEXT_PREDECESSORS {
            return Err(ReactiveContextError::InvalidField {
                field: "sequence.predecessor_event_ids",
                reason: "exceeds bounded predecessor count",
            });
        }
        let mut seen = BTreeSet::new();
        for predecessor in &self.predecessor_event_ids {
            text(
                predecessor,
                "sequence.predecessor_event_ids.item",
                MAX_REACTIVE_CONTEXT_TEXT_BYTES,
            )?;
            if !seen.insert(predecessor) {
                return Err(ReactiveContextError::InvalidField {
                    field: "sequence.predecessor_event_ids",
                    reason: "must not contain duplicates",
                });
            }
        }
        if self.sequence == 1 && !self.predecessor_event_ids.is_empty() {
            return Err(ReactiveContextError::InvalidField {
                field: "sequence.predecessor_event_ids",
                reason: "first event cannot have a predecessor",
            });
        }
        if self.cursor == 0 {
            return Err(ReactiveContextError::InvalidField {
                field: "sequence.cursor",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }

    /// Validate the exact successor relationship to an earlier packet.
    pub fn validate_successor(
        &self,
        previous: &Self,
        previous_event_id: &str,
    ) -> Result<(), ReactiveContextError> {
        self.validate()?;
        previous.validate()?;
        if self.stream_id != previous.stream_id {
            return Err(ReactiveContextError::Mismatch {
                field: "sequence.stream_id",
            });
        }
        if self.sequence <= previous.sequence {
            return Err(ReactiveContextError::SequenceRegression {
                previous: previous.sequence,
                observed: self.sequence,
            });
        }
        if self.sequence != previous.sequence + 1 {
            return Err(ReactiveContextError::SequenceGap {
                expected: previous.sequence + 1,
                observed: self.sequence,
            });
        }
        if !self
            .predecessor_event_ids
            .iter()
            .any(|id| id == previous_event_id)
        {
            return Err(ReactiveContextError::Mismatch {
                field: "sequence.predecessor_event_ids",
            });
        }
        Ok(())
    }
}

/// Explicit cancellation/expiry/invalidation state of an outbound packet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum ReactiveContextValidity {
    /// Packet is current under the supplied fence.
    Current,
    /// Packet was cancelled by its owner.
    Cancelled { reason: String },
    /// Packet was retracted before recipient use could be considered.
    Retracted { reason: String },
    /// Packet was superseded by a newer view/generation.
    Superseded { replacement: ArtifactId },
}

impl ReactiveContextValidity {
    fn validate(&self) -> Result<(), ReactiveContextError> {
        match self {
            Self::Current => Ok(()),
            Self::Cancelled { reason } | Self::Retracted { reason } => {
                text(reason, "validity.reason", MAX_REACTIVE_CONTEXT_TEXT_BYTES)
            }
            Self::Superseded { replacement } => text(
                replacement.as_str(),
                "validity.replacement",
                MAX_REACTIVE_CONTEXT_TEXT_BYTES,
            ),
        }
    }
}

/// The single typed outbound reactive Context payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextPayload {
    /// Context contract identity.
    pub contract: ContractIdentity,
    /// Canonical operation identity.
    pub operation_id: OperationId,
    /// Request identity for this operation.
    pub request_id: RequestId,
    /// Caller idempotency key.
    pub idempotency_key: String,
    /// Durable task and attempt identity.
    pub task_id: TaskId,
    /// Agent attempt identity.
    pub attempt_id: AgentAttemptId,
    /// Producer generation that owns this event stream.
    pub producer_generation: ResourceGeneration,
    /// Exact work scope and state fence.
    pub work_scope: WorkScopeBinding,
    /// Planner-owned request/decision/receipt references.
    pub planner: ReactiveContextPlannerBinding,
    /// Recipient runtime/session binding.
    pub recipient: ReactiveContextRecipient,
    /// Exact view and measurement binding.
    pub view: ReactiveContextViewBinding,
    /// Decision Safety Floor binding.
    pub safety_floor: ReactiveContextSafetyFloor,
    /// Ordered stream sequence.
    pub sequence: ReactiveContextSequence,
    /// Acknowledgement deadline in Unix milliseconds.
    pub acknowledgement_deadline_unix_ms: u64,
    /// Cancellation identity.
    pub cancellation_id: String,
    /// Explicit expiry, when the owner supplied one.
    pub expires_at_unix_ms: Option<u64>,
    /// Current/invalidation state.
    pub validity: ReactiveContextValidity,
}

impl ReactiveContextPayload {
    /// Validate all intrinsic identity, reference, bound, and fence relations.
    pub fn validate(&self) -> Result<(), ReactiveContextError> {
        contract(&self.contract, "contract")?;
        if self.contract != reactive_context_contract_identity()? {
            return Err(ReactiveContextError::InvalidField {
                field: "contract",
                reason: "wrong reactive Context contract identity",
            });
        }
        text(
            self.operation_id.as_str(),
            "operation_id",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        text(
            self.request_id.as_str(),
            "request_id",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        text(
            &self.idempotency_key,
            "idempotency_key",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        text(
            self.task_id.as_str(),
            "task_id",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        text(
            self.attempt_id.as_str(),
            "attempt_id",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        text(
            self.work_scope.scope_id.as_str(),
            "work_scope.scope_id",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        text(
            self.work_scope.product_id.as_str(),
            "work_scope.product_id",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        if self.producer_generation.value() == 0 {
            return Err(ReactiveContextError::InvalidField {
                field: "producer_generation",
                reason: "must be non-zero",
            });
        }
        self.work_scope
            .state_fence
            .validate()
            .map_err(|_| ReactiveContextError::InvalidField {
                field: "work_scope.state_fence",
                reason: "invalid state fence",
            })?;
        if self.work_scope.state_fence.resource_generation != self.work_scope.resource_generation {
            return Err(ReactiveContextError::Mismatch {
                field: "work_scope.resource_generation",
            });
        }
        self.planner.validate()?;
        self.recipient.validate()?;
        self.view.validate()?;
        if self.view.representation.byte_length
            != Some(self.view.measurement.serialized_byte_length)
        {
            return Err(ReactiveContextError::Mismatch {
                field: "measurement.serialized_byte_length",
            });
        }
        self.safety_floor.validate()?;
        self.sequence.validate()?;
        if self.acknowledgement_deadline_unix_ms == 0 {
            return Err(ReactiveContextError::InvalidField {
                field: "acknowledgement_deadline_unix_ms",
                reason: "must be non-zero",
            });
        }
        if self
            .expires_at_unix_ms
            .is_some_and(|expiry| expiry < self.acknowledgement_deadline_unix_ms)
        {
            return Err(ReactiveContextError::InvalidField {
                field: "expires_at_unix_ms",
                reason: "cannot precede acknowledgement deadline",
            });
        }
        text(
            &self.cancellation_id,
            "cancellation_id",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        self.validity.validate()
    }

    /// Compute the canonical digest of the complete typed payload.
    pub fn payload_sha256(&self) -> Result<String, ReactiveContextError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    /// Serialize the validated payload using canonical bytes and enforce the
    /// bounded wire representation.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReactiveContextError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)
            .map_err(|error| ReactiveContextError::Serialization(error.to_string()))?;
        if bytes.len() > MAX_REACTIVE_CONTEXT_PAYLOAD_BYTES {
            return Err(ReactiveContextError::InvalidField {
                field: "payload",
                reason: "exceeds bounded canonical bytes",
            });
        }
        Ok(bytes)
    }

    /// Decode one complete closed JSON payload from raw bytes.
    ///
    /// Serde decodes directly into the closed typed structs, so duplicate and
    /// unknown fields are rejected before any generic `Value` is involved.
    pub fn decode(bytes: &[u8]) -> Result<Self, ReactiveContextError> {
        if bytes.is_empty() || bytes.len() > MAX_REACTIVE_CONTEXT_PAYLOAD_BYTES {
            return Err(ReactiveContextError::InvalidField {
                field: "payload.bytes",
                reason: "outside bounded wire length",
            });
        }
        let payload: Self = serde_json::from_slice(bytes)
            .map_err(|error| ReactiveContextError::Serialization(error.to_string()))?;
        payload.validate()?;
        Ok(payload)
    }

    /// Stable event identity for operation replay.  Payload changes retain the
    /// event key and are therefore surfaced as replay conflicts by consumers.
    pub fn event_id(&self) -> Result<String, ReactiveContextError> {
        self.validate()?;
        Ok(format!("reactive-context:{}", self.operation_id))
    }

    /// Map to the existing generic envelope using an immutable content handle.
    /// This constructs no queue entry and is not a delivery receipt.
    pub fn to_event_envelope(&self) -> Result<EventEnvelope, ReactiveContextError> {
        let payload_digest = self.payload_sha256()?;
        let event_id = self.event_id()?;
        let envelope = EventEnvelope {
            stream_id: self.sequence.stream_id.clone(),
            producer_id: REACTIVE_CONTEXT_PRODUCER_ID.to_owned(),
            producer_generation: self.producer_generation,
            authority_epoch: self.work_scope.state_fence.authority_epoch,
            event_id,
            sequence: self.sequence.sequence,
            causal_predecessor_refs: self.sequence.predecessor_event_ids.clone(),
            delivery_class: DeliveryClass::DurableControl,
            ack_required: true,
            payload_type: REACTIVE_CONTEXT_PAYLOAD_TYPE.to_owned(),
            payload_or_blob_ref: EventPayload::BlobRef(format!(
                "reactive-context/sha256/{payload_digest}"
            )),
            state_fence: self.work_scope.state_fence.clone(),
            trace_context: std::collections::BTreeMap::default(),
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validate an exact first/successor stream relationship.
    pub fn validate_successor(&self, previous: &Self) -> Result<(), ReactiveContextError> {
        self.sequence
            .validate_successor(&previous.sequence, &previous.event_id()?)
    }
}

/// Closed lifecycle labels retained separately from generic acknowledgement.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReactiveContextStage {
    ValidatedNotEnqueued,
    RejectedNotAttempted,
    EnqueuedPersisted,
    DeliveryAttempted,
    UnknownDelivery,
    DeliveredToExactEndpoint,
    RecipientReceived,
    RecipientDurable,
    NormalizedProjection,
    AppliedProjection,
    AcknowledgementRejected,
    AcknowledgementUnknown,
    ExpiredBeforeAck,
    CancelledRetracted,
    StaleSuperseded,
    UnavailableFenced,
    InvalidAcknowledgement,
}

/// Supplied stage evidence, with no claim beyond its owner receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextLifecycleEvidence {
    /// Stage being reported.
    pub stage: ReactiveContextStage,
    /// Required predecessor when the stage has one.
    pub predecessor: Option<ReactiveContextStage>,
    /// Owner-issued immutable receipt reference.
    pub owner_receipt: Option<ReactiveContextContentRef>,
}

impl ReactiveContextLifecycleEvidence {
    /// Validate stage predecessor and evidence requirements.
    pub fn validate(&self) -> Result<(), ReactiveContextError> {
        let expected = match self.stage {
            ReactiveContextStage::ValidatedNotEnqueued
            | ReactiveContextStage::ExpiredBeforeAck
            | ReactiveContextStage::CancelledRetracted
            | ReactiveContextStage::StaleSuperseded
            | ReactiveContextStage::UnavailableFenced
            | ReactiveContextStage::InvalidAcknowledgement
            | ReactiveContextStage::RecipientReceived
            | ReactiveContextStage::AcknowledgementRejected
            | ReactiveContextStage::AcknowledgementUnknown => None,
            ReactiveContextStage::RejectedNotAttempted
            | ReactiveContextStage::EnqueuedPersisted => {
                Some(ReactiveContextStage::ValidatedNotEnqueued)
            }
            ReactiveContextStage::DeliveryAttempted => {
                Some(ReactiveContextStage::EnqueuedPersisted)
            }
            ReactiveContextStage::UnknownDelivery
            | ReactiveContextStage::DeliveredToExactEndpoint => {
                Some(ReactiveContextStage::DeliveryAttempted)
            }
            ReactiveContextStage::RecipientDurable => Some(ReactiveContextStage::RecipientReceived),
            ReactiveContextStage::NormalizedProjection => {
                Some(ReactiveContextStage::RecipientDurable)
            }
            ReactiveContextStage::AppliedProjection => {
                Some(ReactiveContextStage::NormalizedProjection)
            }
        };
        if self.predecessor != expected {
            return Err(ReactiveContextError::InvalidField {
                field: "lifecycle.predecessor",
                reason: "does not match the closed stage relation",
            });
        }
        if matches!(
            self.stage,
            ReactiveContextStage::DeliveredToExactEndpoint
                | ReactiveContextStage::AppliedProjection
        ) && self.owner_receipt.is_none()
        {
            return Err(ReactiveContextError::InvalidField {
                field: "lifecycle.owner_receipt",
                reason: "owner evidence is required",
            });
        }
        if let Some(receipt) = &self.owner_receipt {
            receipt.validate()?;
        }
        Ok(())
    }
}

/// Disposition of supplied acknowledgement evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReactiveContextAckDisposition {
    Accepted,
    DuplicateHistorical,
    Conflict,
    Rejected,
    Unknown,
}

/// Recipient-supplied evidence bound to the actual generic acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextAckEvidence {
    /// Actual generic acknowledgement receipt.
    pub receipt: EventAckReceipt,
    /// Operation identity carried by the acknowledged payload.
    pub operation_id: OperationId,
    /// Exact task and attempt binding.
    pub task_id: TaskId,
    /// Exact recipient identity.
    pub attempt_id: AgentAttemptId,
    pub session_id: SessionId,
    pub runtime_id: String,
    pub runtime_generation: ResourceGeneration,
    /// Exact route supplied by the recipient owner.
    pub route: String,
    /// Work scope and fence under which evidence was observed.
    pub work_scope: WorkScopeBinding,
    pub state_fence: StateFence,
    /// Exact view and payload digest observed.
    pub view_id: ArtifactId,
    pub view_generation: ResourceGeneration,
    pub payload_sha256: String,
    /// Expected and actual generic phases.
    pub expected_phase: AckPhase,
    pub observed_phase: AckPhase,
    /// Owner and issuer references; these authenticate nothing by themselves.
    pub owner_ref: ReactiveContextContentRef,
    pub issuer_ref: ReactiveContextContentRef,
    /// Receive sequence and cursor supplied by the recipient.
    pub receive_sequence: u64,
    pub receive_cursor: u64,
    /// Observation time and freshness/deadline evidence.
    pub observed_at_unix_ms: u64,
    pub freshness_ref: Option<ReactiveContextContentRef>,
    /// Explicit duplicate/conflict classification.
    pub disposition: ReactiveContextAckDisposition,
    /// Bounded proof digest for this evidence record.
    pub proof_sha256: String,
    /// Closed lifecycle evidence associated with the phase.
    pub lifecycle: ReactiveContextLifecycleEvidence,
}

impl ReactiveContextAckEvidence {
    /// Validate supplied evidence against the exact outbound payload and event.
    #[allow(clippy::too_many_lines)]
    pub fn validate_against(
        &self,
        payload: &ReactiveContextPayload,
    ) -> Result<(), ReactiveContextError> {
        payload.validate()?;
        self.receipt.validate()?;
        let envelope = payload.to_event_envelope()?;
        if self.receipt.stream_id != envelope.stream_id {
            return Err(ReactiveContextError::Mismatch {
                field: "receipt.stream_id",
            });
        }
        if self.receipt.event_id != envelope.event_id {
            return Err(ReactiveContextError::Mismatch {
                field: "receipt.event_id",
            });
        }
        if self.operation_id != payload.operation_id {
            return Err(ReactiveContextError::Mismatch {
                field: "operation_id",
            });
        }
        let core = &self.receipt.receipt.core;
        if core.work_scope != payload.work_scope
            || core.operation.operation_id != payload.operation_id
            || core.operation.request_id != payload.request_id
            || core.operation.idempotency_key != payload.idempotency_key
            || core
                .coordination
                .as_ref()
                .is_none_or(|coordination| coordination.idempotency_key != payload.idempotency_key)
            || core.request.metadata.request_id != payload.request_id
            || core.request.metadata.task_id.as_ref() != Some(&payload.task_id)
            || core.request.metadata.session_id.as_ref() != Some(&payload.recipient.session_id)
            || core
                .task
                .as_ref()
                .is_none_or(|task| task.task_id != payload.task_id)
            || core
                .session
                .as_ref()
                .is_none_or(|session| session.session_id != payload.recipient.session_id)
            || core.request.state_fence != payload.work_scope.state_fence
            || core.operation.state_fence != payload.work_scope.state_fence
            || core.authority.state_fence != payload.work_scope.state_fence
            || core.causal.state_fence != payload.work_scope.state_fence
        {
            return Err(ReactiveContextError::Mismatch {
                field: "receipt.core.binding",
            });
        }
        if self.task_id != payload.task_id || self.attempt_id != payload.attempt_id {
            return Err(ReactiveContextError::Mismatch {
                field: "task_or_attempt",
            });
        }
        if self.session_id != payload.recipient.session_id
            || self.runtime_generation != payload.recipient.runtime_generation
            || self.runtime_id != payload.recipient.runtime_id
            || self.route != payload.recipient.route
        {
            return Err(ReactiveContextError::Mismatch { field: "recipient" });
        }
        if self.work_scope != payload.work_scope
            || self.state_fence != payload.work_scope.state_fence
        {
            return Err(ReactiveContextError::Mismatch {
                field: "state_fence_or_work_scope",
            });
        }
        if self.view_id != payload.view.view_id
            || self.view_generation != payload.view.view_generation
        {
            return Err(ReactiveContextError::Mismatch { field: "view" });
        }
        if self.payload_sha256 != payload.payload_sha256()? {
            return Err(ReactiveContextError::Mismatch {
                field: "payload_sha256",
            });
        }
        if self.observed_phase != self.receipt.phase {
            return Err(ReactiveContextError::Mismatch {
                field: "observed_phase",
            });
        }
        if self.receive_sequence != envelope.sequence {
            return Err(ReactiveContextError::Mismatch {
                field: "receive_sequence",
            });
        }
        if self.receive_cursor == 0 || self.observed_at_unix_ms == 0 {
            return Err(ReactiveContextError::InvalidField {
                field: "receive_cursor_or_observed_at",
                reason: "must be non-zero",
            });
        }
        if self.receive_cursor != payload.sequence.cursor {
            return Err(ReactiveContextError::Mismatch {
                field: "receive_cursor",
            });
        }
        digest(&self.payload_sha256, "payload_sha256")?;
        digest(&self.proof_sha256, "proof_sha256")?;
        text(
            &self.runtime_id,
            "runtime_id",
            MAX_REACTIVE_CONTEXT_TEXT_BYTES,
        )?;
        text(&self.route, "route", MAX_REACTIVE_CONTEXT_TEXT_BYTES)?;
        self.owner_ref.validate()?;
        self.issuer_ref.validate()?;
        if let Some(freshness) = &self.freshness_ref {
            freshness.validate()?;
        }
        self.lifecycle.validate()?;
        if self.observed_at_unix_ms > payload.acknowledgement_deadline_unix_ms
            || payload
                .expires_at_unix_ms
                .is_some_and(|expiry| self.observed_at_unix_ms > expiry)
            || !matches!(payload.validity, ReactiveContextValidity::Current)
        {
            return Err(ReactiveContextError::NotCurrent);
        }
        let expected_disposition = match self.observed_phase {
            AckPhase::Rejected => EventDisposition::Rejected,
            AckPhase::Unknown => EventDisposition::Accepted,
            AckPhase::Received | AckPhase::Durable | AckPhase::Normalized | AckPhase::Applied => {
                EventDisposition::Accepted
            }
        };
        let generic_disposition_valid = self.receipt.disposition == expected_disposition;
        if !generic_disposition_valid {
            return Err(ReactiveContextError::Mismatch {
                field: "receipt.disposition",
            });
        }
        let evidence_disposition_valid = match self.observed_phase {
            AckPhase::Rejected => self.disposition == ReactiveContextAckDisposition::Rejected,
            AckPhase::Unknown => self.disposition == ReactiveContextAckDisposition::Unknown,
            AckPhase::Received | AckPhase::Durable | AckPhase::Normalized | AckPhase::Applied => {
                self.disposition == ReactiveContextAckDisposition::Accepted
            }
        };
        if !evidence_disposition_valid {
            return Err(ReactiveContextError::Mismatch {
                field: "disposition",
            });
        }
        let expected_stage = match self.observed_phase {
            AckPhase::Received => ReactiveContextStage::RecipientReceived,
            AckPhase::Durable => ReactiveContextStage::RecipientDurable,
            AckPhase::Normalized => ReactiveContextStage::NormalizedProjection,
            AckPhase::Applied => ReactiveContextStage::AppliedProjection,
            AckPhase::Rejected => ReactiveContextStage::AcknowledgementRejected,
            AckPhase::Unknown => ReactiveContextStage::AcknowledgementUnknown,
        };
        if self.lifecycle.stage != expected_stage {
            return Err(ReactiveContextError::UnsupportedStage);
        }
        if !core
            .artifacts
            .iter()
            .any(|artifact| artifact.sha256 == self.payload_sha256)
        {
            return Err(ReactiveContextError::Mismatch {
                field: "receipt.core.artifacts",
            });
        }
        if self.expected_phase != self.observed_phase {
            EventAckReceipt::validate_advance(self.expected_phase, self.observed_phase)?;
        }
        Ok(())
    }
}

/// In-memory replay state for one exact event identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextAckLedger {
    /// Stable event identity.
    pub event_id: String,
    /// Immutable payload digest first observed for this event.
    pub payload_sha256: String,
    /// Maximum accepted generic phase.
    pub maximum_phase: Option<AckPhase>,
    /// Last accepted phase, including terminal `REJECTED` or `UNKNOWN`.
    pub current_phase: Option<AckPhase>,
    /// Exact acknowledgement receipt digests already observed.
    pub receipt_digests: Vec<String>,
    /// Exact evidence digests paired with `receipt_digests`.
    pub evidence_digests: Vec<String>,
}

impl ReactiveContextAckLedger {
    /// Create empty replay state for a payload.
    pub fn new(payload: &ReactiveContextPayload) -> Result<Self, ReactiveContextError> {
        Ok(Self {
            event_id: payload.event_id()?,
            payload_sha256: payload.payload_sha256()?,
            maximum_phase: None,
            current_phase: None,
            receipt_digests: Vec::new(),
            evidence_digests: Vec::new(),
        })
    }

    /// Record supplied evidence without lowering the accepted maximum phase.
    pub fn record(
        &mut self,
        evidence: &ReactiveContextAckEvidence,
        payload: &ReactiveContextPayload,
    ) -> Result<ReactiveContextAckDisposition, ReactiveContextError> {
        evidence.validate_against(payload)?;
        if evidence.receipt.event_id != self.event_id
            || evidence.payload_sha256 != self.payload_sha256
        {
            return Err(ReactiveContextError::ReplayConflict);
        }
        let receipt_bytes = canonical_json_bytes(&evidence.receipt)
            .map_err(|error| ReactiveContextError::Serialization(error.to_string()))?;
        let receipt_digest = sha256_hex(&receipt_bytes);
        let evidence_bytes = canonical_json_bytes(evidence)
            .map_err(|error| ReactiveContextError::Serialization(error.to_string()))?;
        let evidence_digest = sha256_hex(&evidence_bytes);
        if let Some(index) = self
            .receipt_digests
            .iter()
            .position(|seen| seen == &receipt_digest)
        {
            if self.evidence_digests.get(index) == Some(&evidence_digest) {
                return Ok(ReactiveContextAckDisposition::DuplicateHistorical);
            }
            return Err(ReactiveContextError::ReplayConflict);
        }
        if self.receipt_digests.len() >= MAX_REACTIVE_CONTEXT_ACK_HISTORY {
            return Err(ReactiveContextError::InvalidField {
                field: "receipt_digests",
                reason: "exceeds bounded history",
            });
        }
        match self.current_phase {
            None if evidence.observed_phase != AckPhase::Received => {
                return Err(ReactiveContextError::InvalidAckTransition {
                    from: AckPhase::Received,
                    to: evidence.observed_phase,
                });
            }
            None => {
                self.current_phase = Some(AckPhase::Received);
                self.maximum_phase = Some(AckPhase::Received);
            }
            Some(current) => {
                EventAckReceipt::validate_advance(current, evidence.observed_phase)?;
                self.current_phase = Some(evidence.observed_phase);
                if phase_advances(current, evidence.observed_phase) {
                    self.maximum_phase = Some(evidence.observed_phase);
                }
            }
        }
        self.receipt_digests.push(receipt_digest);
        self.evidence_digests.push(evidence_digest);
        Ok(evidence.disposition)
    }
}

fn phase_advances(from: AckPhase, to: AckPhase) -> bool {
    match from {
        AckPhase::Received => matches!(to, AckPhase::Durable),
        AckPhase::Durable => matches!(to, AckPhase::Normalized),
        AckPhase::Normalized => matches!(to, AckPhase::Applied),
        AckPhase::Applied | AckPhase::Rejected | AckPhase::Unknown => false,
    }
}
