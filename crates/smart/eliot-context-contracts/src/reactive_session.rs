//! Immutable owner-issued session and delivery history for reactive planning.

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    OperationId, RequestId, ResourceGeneration, SessionId, SourceId, StateFence, TaskId,
};
use eliot_evidence::EvidenceEnvelope;
use eliot_protocol::{
    AckPhase, EventEnvelope, ReactiveContextAckEvidence, ReactiveContextError,
    ReactiveContextLifecycleEvidence, ReactiveContextPayload, ReactiveContextStage,
    ReactiveContextValidity,
};
use eliot_receipts::{ReceiptEnvelope, WorkScopeId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ContextPlanningView, ReactiveInputError, bounded_preflight, canonical_planning_digest,
};

const MAX_RECORDS: usize = 256;
const MAX_CLOSURE_ITEMS: usize = 128;
const DELIVERY_CLAIM_DOMAIN: &str = "eliot.context-contracts.reactive.delivery-stage";
const DELIVERY_CLAIM_VERSION: u16 = 1;

#[derive(Serialize)]
struct CanonicalSession<'a> {
    owner_id: &'a str,
    source_id: &'a SourceId,
    source_revision: &'a str,
    snapshot_revision: &'a str,
    session_id: &'a SessionId,
    principal_id: &'a str,
    recipient_id: &'a str,
    runtime_id: &'a str,
    host_id: &'a str,
    runtime_generation: &'a ResourceGeneration,
    host_generation: &'a ResourceGeneration,
    task_id: &'a TaskId,
    attempt_id: &'a AgentAttemptId,
    scope_id: &'a WorkScopeId,
    state_fence: &'a StateFence,
    denominator: &'a SnapshotDenominator,
    records: &'a [PriorDeliveryBinding],
}

#[derive(Serialize)]
struct CanonicalDeliveryClaim<'a> {
    domain: &'static str,
    version: u16,
    stage: &'a ReactiveContextStage,
    validity: &'a ReactiveContextValidity,
    delivery_owner_id: &'a str,
    payload_sha256: &'a str,
    profile: &'a eliot_protocol::ReactiveContextContentRef,
    operation_id: &'a OperationId,
    request_id: &'a RequestId,
    idempotency_key: &'a str,
    task_id: &'a TaskId,
    attempt_id: &'a AgentAttemptId,
    session_id: &'a SessionId,
    runtime_id: &'a str,
    runtime_generation: &'a ResourceGeneration,
    host_generation: &'a ResourceGeneration,
    route: &'a str,
    scope_id: &'a WorkScopeId,
    state_fence: &'a StateFence,
}

fn text(value: &str, field: &'static str) -> Result<(), ReactiveInputError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ReactiveInputError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

/// Explicit completeness of a session owner denominator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SnapshotCompleteness {
    Complete,
    Partial,
    Unknown,
}

/// Observed/expected counts remain separate from evidence completeness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDenominator {
    pub observed: u32,
    pub expected: Option<u32>,
    pub completeness: SnapshotCompleteness,
}

impl SnapshotDenominator {
    /// Validate count ordering while preserving incomplete evidence.
    pub fn validate(&self) -> Result<(), ReactiveInputError> {
        if self
            .expected
            .is_some_and(|expected| self.observed > expected)
            || matches!(self.completeness, SnapshotCompleteness::Complete)
                && self.expected != Some(self.observed)
        {
            return Err(ReactiveInputError::InvalidField {
                field: "session.denominator",
                reason: "counts do not reconcile with declared completeness",
            });
        }
        Ok(())
    }
}

/// Actual canonical event/payload/receipt/evidence closure retained from the owner.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryEvidenceClosure {
    /// The original owner-issued Context view retained alongside the protocol
    /// payload; this is the source of semantic item identity for deduplication.
    pub context_view: ContextPlanningView,
    /// The exact owner-issued delivery profile reference used for this event.
    pub profile: eliot_protocol::ReactiveContextContentRef,
    /// Optional owner-issued claim used only when a delivery stage has no
    /// qualifying current recipient acknowledgement.
    pub delivery_claim: Option<eliot_protocol::ReactiveContextContentRef>,
    /// Explicit owner identity for an owner-issued delivery-stage claim.
    pub delivery_owner_id: Option<String>,
    /// The original assembly receipt; its operation is historical and remains
    /// distinct from the delivery operation carried by `payload`.
    pub assembly_receipt: ReceiptEnvelope,
    pub payload: ReactiveContextPayload,
    pub event: EventEnvelope,
    pub acknowledgements: Vec<ReactiveContextAckEvidence>,
    pub receipts: Vec<ReceiptEnvelope>,
    pub evidence: Vec<EvidenceEnvelope>,
}

impl DeliveryEvidenceClosure {
    fn validate_assembly_receipt(&self) -> Result<(), ReactiveInputError> {
        self.assembly_receipt
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "delivery.assembly_receipt",
                reason: "invalid retained assembly ReceiptEnvelope",
            })?;
        if self.payload.view.assembly_receipt.content_sha256
            != self.assembly_receipt.identity.canonical_sha256
            || self.assembly_receipt.core.work_scope.scope_id
                != self.context_view.view.binding.scope_id
            || self.assembly_receipt.core.work_scope.state_fence
                != self.context_view.view.binding.state_fence
            || self
                .assembly_receipt
                .core
                .task
                .as_ref()
                .is_none_or(|task| task.task_id != self.context_view.view.binding.task_id)
            || self
                .context_view
                .view
                .binding
                .operation_id
                .as_ref()
                .is_some_and(|operation| {
                    self.assembly_receipt.core.operation.operation_id != *operation
                })
            || !self.assembly_receipt.core.artifacts.iter().any(|artifact| {
                artifact.artifact_id == self.context_view.view_id
                    && artifact.sha256 == self.context_view.canonical_sha256
            })
        {
            return Err(ReactiveInputError::BindingMismatch {
                field: "delivery.assembly_receipt",
            });
        }
        Ok(())
    }

    fn validate_view_join(&self) -> Result<(), ReactiveInputError> {
        if self.payload.view.view_id != self.context_view.view_id
            || self.payload.view.admitted_set.content_sha256
                != self.context_view.admitted_canonical_sha256
            || self.payload.view.admitted_set.byte_length
                != Some(self.context_view.admitted_canonical_bytes.len() as u64)
            || self.payload.view.recipe.content_sha256 != self.context_view.view.recipe_digest
            || self.payload.view.measurement.serialized_byte_length
                != self.context_view.view.measurement.rendered_utf8_bytes
            || self.payload.view.representation.byte_length
                != Some(self.context_view.view.measurement.rendered_utf8_bytes)
            || self.payload.view.representation.content_sha256 != self.context_view.canonical_sha256
        {
            return Err(ReactiveInputError::BindingMismatch {
                field: "delivery.context_view",
            });
        }
        Ok(())
    }

    fn validate_acknowledgements(&self) -> Result<(), ReactiveInputError> {
        for acknowledgement in &self.acknowledgements {
            match acknowledgement.validate_against(&self.payload) {
                // Keep historical non-current acknowledgements in the
                // immutable vector, but they provide no delivery qualification.
                Ok(()) | Err(ReactiveContextError::NotCurrent) => {}
                Err(_) => {
                    return Err(ReactiveInputError::InvalidField {
                        field: "delivery.acknowledgements",
                        reason: "acknowledgement is not bound to its retained payload",
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_receipts(&self) -> Result<(), ReactiveInputError> {
        for receipt in &self.receipts {
            receipt
                .validate()
                .map_err(|_| ReactiveInputError::InvalidField {
                    field: "delivery.receipts",
                    reason: "invalid retained ReceiptEnvelope",
                })?;
            if receipt.core.work_scope != self.payload.work_scope
                || receipt.core.operation.operation_id != self.payload.operation_id
                || receipt.core.operation.request_id != self.payload.request_id
                || receipt.core.operation.idempotency_key != self.payload.idempotency_key
                || receipt
                    .core
                    .task
                    .as_ref()
                    .is_none_or(|task| task.task_id != self.payload.task_id)
                || receipt
                    .core
                    .session
                    .as_ref()
                    .is_none_or(|session| session.session_id != self.payload.recipient.session_id)
                || receipt.core.request.metadata.request_id != self.payload.request_id
                || receipt.core.request.metadata.task_id.as_ref() != Some(&self.payload.task_id)
                || receipt.core.request.metadata.session_id.as_ref()
                    != Some(&self.payload.recipient.session_id)
                || !receipt.core.artifacts.iter().any(|artifact| {
                    Some(&artifact.artifact_id)
                        == self.payload.view.representation.artifact_id.as_ref()
                        && artifact.sha256 == self.payload.view.representation.content_sha256
                        && artifact.source_revision.as_deref()
                            == Some(self.payload.view.representation.source_revision.as_str())
                })
                || !receipt.core.artifacts.iter().any(|artifact| {
                    Some(&artifact.artifact_id) == self.profile.artifact_id.as_ref()
                        && artifact.sha256 == self.profile.content_sha256
                        && artifact.source_revision.as_deref()
                            == Some(self.profile.source_revision.as_str())
                })
            {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "delivery.receipt_binding",
                });
            }
        }
        Ok(())
    }

    /// Validate the actual owner closure and its canonical protocol joins.
    pub fn validate(&self) -> Result<(), ReactiveInputError> {
        bounded_preflight(self, "delivery.closure")?;
        if self.acknowledgements.len() > MAX_CLOSURE_ITEMS
            || self.receipts.len() > MAX_CLOSURE_ITEMS
            || self.evidence.len() > MAX_CLOSURE_ITEMS
        {
            return Err(ReactiveInputError::InvalidField {
                field: "delivery.closure",
                reason: "closure exceeds bounded collection size",
            });
        }
        self.payload
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "delivery.payload",
                reason: "invalid ReactiveContextPayload",
            })?;
        self.context_view.validate()?;
        self.profile
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "delivery.profile",
                reason: "invalid delivery profile binding",
            })?;
        if let Some(claim) = &self.delivery_claim {
            claim
                .validate()
                .map_err(|_| ReactiveInputError::InvalidField {
                    field: "delivery.delivery_claim",
                    reason: "invalid delivery-stage claim binding",
                })?;
        }
        if let Some(owner_id) = &self.delivery_owner_id
            && (owner_id.trim().is_empty() || owner_id.chars().any(char::is_control))
        {
            return Err(ReactiveInputError::InvalidField {
                field: "delivery.delivery_owner_id",
                reason: "delivery owner must be non-blank and free of control characters",
            });
        }
        self.validate_assembly_receipt()?;
        self.validate_view_join()?;
        self.event
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "delivery.event",
                reason: "invalid EventEnvelope",
            })?;
        let expected =
            self.payload
                .to_event_envelope()
                .map_err(|_| ReactiveInputError::InvalidField {
                    field: "delivery.event",
                    reason: "payload cannot derive its canonical EventEnvelope",
                })?;
        if self.event != expected {
            return Err(ReactiveInputError::BindingMismatch {
                field: "delivery.event_payload",
            });
        }
        self.validate_acknowledgements()?;
        self.validate_receipts()?;
        for evidence in &self.evidence {
            evidence
                .validate()
                .map_err(|_| ReactiveInputError::InvalidField {
                    field: "delivery.evidence",
                    reason: "invalid retained EvidenceEnvelope",
                })?;
        }
        Ok(())
    }
}

/// One historical delivery record with original operation and source identity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PriorDeliveryBinding {
    pub record_id: String,
    pub operation_id: OperationId,
    pub request_id: RequestId,
    pub idempotency_key: String,
    pub item_id: String,
    pub content: eliot_protocol::ReactiveContextContentRef,
    pub source: eliot_protocol::ReactiveContextContentRef,
    pub profile: eliot_protocol::ReactiveContextContentRef,
    pub validity: ReactiveContextValidity,
    pub lifecycle: ReactiveContextLifecycleEvidence,
    pub stage: ReactiveContextStage,
    pub acknowledgement_phase: Option<AckPhase>,
    pub predecessor_ids: Vec<String>,
    pub replay_identity: String,
    pub session_id: SessionId,
    pub runtime_id: String,
    pub runtime_generation: ResourceGeneration,
    pub host_generation: ResourceGeneration,
    pub task_id: TaskId,
    pub attempt_id: AgentAttemptId,
    pub scope_id: WorkScopeId,
    pub state_fence: StateFence,
    pub closure: Option<DeliveryEvidenceClosure>,
}

impl PriorDeliveryBinding {
    fn validate_identity(&self) -> Result<(), ReactiveInputError> {
        for (value, field) in [
            (self.record_id.as_str(), "delivery.record_id"),
            (self.operation_id.as_str(), "delivery.operation_id"),
            (self.request_id.as_str(), "delivery.request_id"),
            (self.idempotency_key.as_str(), "delivery.idempotency_key"),
            (self.item_id.as_str(), "delivery.item_id"),
            (self.replay_identity.as_str(), "delivery.replay_identity"),
            (self.session_id.as_str(), "delivery.session_id"),
            (self.runtime_id.as_str(), "delivery.runtime_id"),
            (self.task_id.as_str(), "delivery.task_id"),
            (self.attempt_id.as_str(), "delivery.attempt_id"),
            (self.scope_id.as_str(), "delivery.scope_id"),
        ] {
            text(value, field)?;
        }
        if self.runtime_generation.value() == 0 || self.host_generation.value() == 0 {
            return Err(ReactiveInputError::InvalidField {
                field: "delivery.generation",
                reason: "generation must be non-zero",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "delivery.state_fence",
                reason: "invalid State Fence",
            })
    }

    /// Compute a full-payload owner claim for a delivery-stage assertion.
    /// Semantic item/source joins remain validated separately on the record.
    pub fn canonical_delivery_claim_digest(
        &self,
        closure: &DeliveryEvidenceClosure,
    ) -> Result<String, ReactiveInputError> {
        let delivery_owner_id =
            closure
                .delivery_owner_id
                .as_deref()
                .ok_or(ReactiveInputError::BindingMismatch {
                    field: "delivery.delivery_owner_id",
                })?;
        let payload_sha256 =
            closure
                .payload
                .payload_sha256()
                .map_err(|_| ReactiveInputError::InvalidField {
                    field: "delivery.payload",
                    reason: "payload digest cannot be computed",
                })?;
        canonical_planning_digest(&CanonicalDeliveryClaim {
            domain: DELIVERY_CLAIM_DOMAIN,
            version: DELIVERY_CLAIM_VERSION,
            stage: &self.stage,
            validity: &self.validity,
            delivery_owner_id,
            payload_sha256: &payload_sha256,
            profile: &closure.profile,
            operation_id: &closure.payload.operation_id,
            request_id: &closure.payload.request_id,
            idempotency_key: &closure.payload.idempotency_key,
            task_id: &closure.payload.task_id,
            attempt_id: &closure.payload.attempt_id,
            session_id: &closure.payload.recipient.session_id,
            runtime_id: &closure.payload.recipient.runtime_id,
            runtime_generation: &closure.payload.recipient.runtime_generation,
            host_generation: &self.host_generation,
            route: &closure.payload.recipient.route,
            scope_id: &closure.payload.work_scope.scope_id,
            state_fence: &closure.payload.work_scope.state_fence,
        })
    }

    fn validate_delivery_claim(
        &self,
        closure: &DeliveryEvidenceClosure,
    ) -> Result<(), ReactiveInputError> {
        let claim = closure
            .delivery_claim
            .as_ref()
            .ok_or(ReactiveInputError::BindingMismatch {
                field: "delivery.delivery_claim",
            })?;
        let delivery_owner_id =
            closure
                .delivery_owner_id
                .as_deref()
                .ok_or(ReactiveInputError::BindingMismatch {
                    field: "delivery.delivery_owner_id",
                })?;
        claim
            .artifact_id
            .as_ref()
            .ok_or(ReactiveInputError::BindingMismatch {
                field: "delivery.delivery_claim",
            })?;
        if claim.content_sha256 != self.canonical_delivery_claim_digest(closure)? {
            return Err(ReactiveInputError::DigestMismatch {
                field: "delivery.delivery_claim",
            });
        }
        if !closure.receipts.iter().any(|receipt| {
            matches!(
                &receipt.core.disposition,
                eliot_receipts::ReceiptDisposition::Success { .. }
            ) && receipt.core.authority.authority_owner == delivery_owner_id
                && receipt.core.artifacts.iter().any(|artifact| {
                    claim.artifact_id.as_ref() == Some(&artifact.artifact_id)
                        && artifact.sha256 == claim.content_sha256
                        && artifact.source_revision.as_deref()
                            == Some(claim.source_revision.as_str())
                })
        }) {
            return Err(ReactiveInputError::BindingMismatch {
                field: "delivery.delivery_claim_receipt",
            });
        }
        Ok(())
    }

    fn has_qualified_delivery(&self, closure: &DeliveryEvidenceClosure) -> bool {
        if !matches!(self.validity, ReactiveContextValidity::Current)
            || !matches!(closure.payload.validity, ReactiveContextValidity::Current)
        {
            return false;
        }
        let current_ack = closure.acknowledgements.iter().any(|ack| {
            ack.validate_against(&closure.payload).is_ok()
                && matches!(
                    ack.observed_phase,
                    eliot_protocol::AckPhase::Received
                        | eliot_protocol::AckPhase::Durable
                        | eliot_protocol::AckPhase::Normalized
                        | eliot_protocol::AckPhase::Applied
                )
        });
        current_ack || self.validate_delivery_claim(closure).is_ok()
    }

    fn validate_closure(
        &self,
        closure: &DeliveryEvidenceClosure,
    ) -> Result<(), ReactiveInputError> {
        closure.validate()?;
        if let Some(owner_ref) = &self.lifecycle.owner_receipt {
            let receipt_matches = closure
                .receipts
                .iter()
                .any(|receipt| receipt.identity.canonical_sha256 == owner_ref.content_sha256)
                || closure.acknowledgements.iter().any(|ack| {
                    ack.receipt.receipt.identity.canonical_sha256 == owner_ref.content_sha256
                });
            if !receipt_matches {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "delivery.lifecycle_owner_receipt",
                });
            }
        }
        if closure.payload.operation_id != self.operation_id
            || closure.payload.request_id != self.request_id
            || closure.payload.idempotency_key != self.idempotency_key
        {
            return Err(ReactiveInputError::BindingMismatch {
                field: "delivery.operation_payload",
            });
        }
        if self.profile != closure.profile {
            return Err(ReactiveInputError::BindingMismatch {
                field: "delivery.profile",
            });
        }
        if self.validity != closure.payload.validity {
            return Err(ReactiveInputError::BindingMismatch {
                field: "delivery.validity",
            });
        }
        let required_phase = match self.stage {
            ReactiveContextStage::RecipientReceived => Some(AckPhase::Received),
            ReactiveContextStage::RecipientDurable => Some(AckPhase::Durable),
            ReactiveContextStage::NormalizedProjection => Some(AckPhase::Normalized),
            ReactiveContextStage::AppliedProjection => Some(AckPhase::Applied),
            _ => None,
        };
        if let Some(required_phase) = required_phase
            && !closure.acknowledgements.iter().any(|ack| {
                ack.observed_phase == required_phase
                    && ack.validate_against(&closure.payload).is_ok()
            })
        {
            return Err(ReactiveInputError::BindingMismatch {
                field: "delivery.stage_acknowledgement",
            });
        }
        let item = closure
            .context_view
            .view
            .rendered
            .iter()
            .find(|item| item.atom_id.as_str() == self.item_id)
            .ok_or(ReactiveInputError::BindingMismatch {
                field: "delivery.item_id",
            })?;
        if self.content.content_sha256 != canonical_planning_digest(&item.representation)?
            || self.content.source_revision != item.source_revision
            || self.content.artifact_id.as_ref() != Some(&item.atom_id)
            || self.source.source_revision != item.source_revision
            || self.source.content_sha256 != item.source_digest
            || self.source.artifact_id.as_ref() != Some(&item.source_id)
        {
            return Err(ReactiveInputError::BindingMismatch {
                field: "delivery.item_content",
            });
        }
        if closure.payload.recipient.session_id != self.session_id
            || closure.payload.recipient.runtime_id != self.runtime_id
            || closure.payload.recipient.runtime_generation != self.runtime_generation
            || closure.payload.task_id != self.task_id
            || closure.payload.attempt_id != self.attempt_id
            || closure.payload.work_scope.scope_id != self.scope_id
            || closure.payload.work_scope.state_fence != self.state_fence
        {
            return Err(ReactiveInputError::BindingMismatch {
                field: "delivery.owner_binding",
            });
        }
        if let Some(phase) = self.acknowledgement_phase
            && !closure.acknowledgements.iter().any(|ack| {
                ack.observed_phase == phase && ack.validate_against(&closure.payload).is_ok()
            })
        {
            return Err(ReactiveInputError::BindingMismatch {
                field: "delivery.acknowledgement_phase",
            });
        }
        Ok(())
    }

    /// Validate a historical binding without rewriting its original operation.
    pub fn validate(&self) -> Result<(), ReactiveInputError> {
        bounded_preflight(self, "delivery.record")?;
        self.validate_identity()?;
        self.content
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "delivery.content",
                reason: "invalid content binding",
            })?;
        self.source
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "delivery.source",
                reason: "invalid source binding",
            })?;
        self.profile
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "delivery.profile",
                reason: "invalid delivery profile binding",
            })?;
        match &self.validity {
            ReactiveContextValidity::Current => {}
            ReactiveContextValidity::Cancelled { reason }
            | ReactiveContextValidity::Retracted { reason } => {
                text(reason, "delivery.validity.reason")?;
            }
            ReactiveContextValidity::Superseded { replacement } => {
                text(replacement.as_str(), "delivery.validity.replacement")?;
            }
        }
        self.lifecycle
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "delivery.lifecycle",
                reason: "invalid lifecycle predecessor/evidence",
            })?;
        if self.stage != self.lifecycle.stage {
            return Err(ReactiveInputError::BindingMismatch {
                field: "delivery.stage",
            });
        }
        if self.predecessor_ids.len() > MAX_CLOSURE_ITEMS {
            return Err(ReactiveInputError::InvalidField {
                field: "delivery.predecessor_ids",
                reason: "too many predecessors",
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for predecessor in &self.predecessor_ids {
            text(predecessor, "delivery.predecessor_ids.item")?;
            if !seen.insert(predecessor) {
                return Err(ReactiveInputError::InvalidField {
                    field: "delivery.predecessor_ids",
                    reason: "duplicate predecessor",
                });
            }
        }
        let stage_requires_ack = matches!(
            self.stage,
            ReactiveContextStage::RecipientReceived
                | ReactiveContextStage::RecipientDurable
                | ReactiveContextStage::NormalizedProjection
                | ReactiveContextStage::AppliedProjection
        );
        if (self.stage == ReactiveContextStage::DeliveredToExactEndpoint
            || stage_requires_ack
            || self.acknowledgement_phase.is_some())
            && self.closure.as_ref().is_none_or(|closure| {
                closure.receipts.is_empty() && closure.acknowledgements.is_empty()
            })
        {
            return Err(ReactiveInputError::InvalidField {
                field: "delivery.closure",
                reason: "delivered or acknowledged state needs actual owner closure",
            });
        }
        if let Some(closure) = &self.closure {
            self.validate_closure(closure)?;
            if self.stage == ReactiveContextStage::DeliveredToExactEndpoint
                && !self.has_qualified_delivery(closure)
            {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "delivery.qualification",
                });
            }
        }
        Ok(())
    }
}

/// Immutable, owner-issued delivery history for one exact session snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionDeliverySnapshot {
    pub owner_id: String,
    pub source_id: SourceId,
    pub source_revision: String,
    pub snapshot_revision: String,
    pub snapshot_digest: String,
    pub session_id: SessionId,
    pub principal_id: String,
    pub recipient_id: String,
    pub runtime_id: String,
    pub host_id: String,
    pub runtime_generation: ResourceGeneration,
    pub host_generation: ResourceGeneration,
    pub task_id: TaskId,
    pub attempt_id: AgentAttemptId,
    pub scope_id: WorkScopeId,
    pub state_fence: StateFence,
    pub denominator: SnapshotDenominator,
    pub records: Vec<PriorDeliveryBinding>,
}

impl SessionDeliverySnapshot {
    fn validate_records(&self) -> Result<(), ReactiveInputError> {
        let mut record_ids = std::collections::BTreeSet::new();
        let mut item_ids = std::collections::BTreeSet::new();
        let mut operation_ids = std::collections::BTreeSet::new();
        let mut replay_ids = std::collections::BTreeSet::new();
        for record in &self.records {
            record.validate()?;
            if record.state_fence != self.state_fence
                && matches!(record.validity, ReactiveContextValidity::Current)
            {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "session.record_historical_fence",
                });
            }
            if record.session_id != self.session_id
                || record.runtime_id != self.runtime_id
                || record.runtime_generation != self.runtime_generation
                || record.host_generation != self.host_generation
                || record.task_id != self.task_id
                || record.attempt_id.as_str() != self.attempt_id.as_str()
                || record.scope_id != self.scope_id
            {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "session.record_binding",
                });
            }
            if !record_ids.insert(&record.record_id)
                || !item_ids.insert(&record.item_id)
                || !operation_ids.insert(&record.operation_id)
                || !replay_ids.insert(&record.replay_identity)
            {
                return Err(ReactiveInputError::InvalidField {
                    field: "session.records",
                    reason: "duplicate record, item, operation, or replay identity",
                });
            }
        }
        Ok(())
    }

    /// Compute the digest over every safety-relevant snapshot field.
    pub fn canonical_digest(&self) -> Result<String, ReactiveInputError> {
        canonical_planning_digest(&CanonicalSession {
            owner_id: &self.owner_id,
            source_id: &self.source_id,
            source_revision: &self.source_revision,
            snapshot_revision: &self.snapshot_revision,
            session_id: &self.session_id,
            principal_id: &self.principal_id,
            recipient_id: &self.recipient_id,
            runtime_id: &self.runtime_id,
            host_id: &self.host_id,
            runtime_generation: &self.runtime_generation,
            host_generation: &self.host_generation,
            task_id: &self.task_id,
            attempt_id: &self.attempt_id,
            scope_id: &self.scope_id,
            state_fence: &self.state_fence,
            denominator: &self.denominator,
            records: &self.records,
        })
    }

    /// Validate owner identity, denominator, historical records, and digest.
    pub fn validate(&self) -> Result<(), ReactiveInputError> {
        bounded_preflight(self, "session.preflight")?;
        text(&self.owner_id, "session.owner_id")?;
        text(&self.source_revision, "session.source_revision")?;
        text(&self.snapshot_revision, "session.snapshot_revision")?;
        text(&self.principal_id, "session.principal_id")?;
        text(&self.recipient_id, "session.recipient_id")?;
        text(&self.runtime_id, "session.runtime_id")?;
        text(&self.host_id, "session.host_id")?;
        text(self.session_id.as_str(), "session.session_id")?;
        text(self.task_id.as_str(), "session.task_id")?;
        text(self.attempt_id.as_str(), "session.attempt_id")?;
        text(self.scope_id.as_str(), "session.scope_id")?;
        if self.runtime_generation.value() == 0 || self.host_generation.value() == 0 {
            return Err(ReactiveInputError::InvalidField {
                field: "session.generation",
                reason: "generation must be non-zero",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "session.state_fence",
                reason: "invalid State Fence",
            })?;
        self.denominator.validate()?;
        if self.denominator.observed as usize != self.records.len() {
            return Err(ReactiveInputError::BindingMismatch {
                field: "session.denominator.observed",
            });
        }
        if self.records.len() > MAX_RECORDS
            || self
                .denominator
                .expected
                .is_some_and(|n| (n as usize) < self.records.len())
        {
            return Err(ReactiveInputError::InvalidField {
                field: "session.records",
                reason: "records exceed bounded denominator",
            });
        }
        self.validate_records()?;
        let expected = self.canonical_digest()?;
        if self.snapshot_digest != expected {
            return Err(ReactiveInputError::DigestMismatch {
                field: "session.snapshot_digest",
            });
        }
        Ok(())
    }
}
