//! Store-neutral wire contract for durable typed blackboard candidates.
//!
//! Kernel owns semantic admission. Store retains supplied producer evidence,
//! binds each immutable revision to its exact predecessor, and enforces the
//! conservative lifecycle edges represented by the shared lifecycle type.

use std::collections::BTreeMap;

use eliot_contracts::{BoardEntryState, PeerBoardKind, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    DurableRecordHandle, NamedMutationOperation, NamedMutationRequest, NamedReadOperation,
    NamedReadRequest, ReadConsistency, ScopeId, StateFence, StoreError, canonical_json_bytes,
    validate_text,
};

/// Schema identifier for persisted candidate records.
pub const BLACKBOARD_ITEM_SCHEMA_V1: &str = "eliot.blackboard.item.v1";
/// Stable named mutation used for candidate admission and lifecycle changes.
pub const BLACKBOARD_ITEM_MUTATION_NAME: &str = "ApplyBlackboardItem";
/// Stable named read used for exact task/item readback.
pub const BLACKBOARD_ITEM_READ_NAME: &str = "GetBlackboardItem";

/// One immutable, task-scoped typed candidate revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlackboardItemRecord {
    /// Stable identity across revisions of this candidate.
    pub item_id: String,
    /// Task that owns the collaboration context.
    pub task_id: TaskId,
    /// Closed I10.18 item category.
    pub kind: PeerBoardKind,
    /// Authenticated author principal established by Kernel admission.
    pub author_principal: String,
    /// Producer lineage evidence supplied by the semantic producer. Store
    /// retains this evidence but does not authenticate its provenance.
    pub producer_lineage: String,
    /// Fence at which this candidate was admitted.
    pub state_fence: StateFence,
    /// Existing board lifecycle vocabulary. A candidate revision may start
    /// Current, advance from Current to Current, or become terminally
    /// Retracted. Supersession is represented by an immutable successor and
    /// is not written as a new head state.
    pub lifecycle: BoardEntryState,
    /// Monotonic immutable item revision.
    pub revision: u64,
    /// Durable handle to the item's payload.
    pub payload_handle: DurableRecordHandle,
    /// Durable evidence handles cited by the candidate.
    pub evidence_handles: Vec<DurableRecordHandle>,
    /// Additional durable records referenced by the candidate.
    pub durable_references: Vec<DurableRecordHandle>,
}

impl BlackboardItemRecord {
    /// Validates the closed persisted record without assigning candidate
    /// semantics or granting any decision/effect authority. Every required
    /// handle is re-validated through its canonical constructor, so the
    /// semantic gate enforces the same bound the handle type guarantees.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.item_id, "blackboard.item_id")?;
        validate_text(&self.author_principal, "blackboard.author_principal")?;
        validate_text(&self.producer_lineage, "blackboard.producer_lineage")?;
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        validate_handle(&self.payload_handle, "blackboard.payload_handle")?;
        for handle in &self.evidence_handles {
            validate_handle(handle, "blackboard.evidence_handle")?;
        }
        for handle in &self.durable_references {
            validate_handle(handle, "blackboard.durable_reference")?;
        }
        if self.revision == 0 || self.revision > i64::MAX as u64 {
            return Err(StoreError::InvalidField {
                field: "blackboard.revision",
                reason: "must fit a positive Surreal integer",
            });
        }
        match &self.lifecycle {
            BoardEntryState::Current => {}
            BoardEntryState::Superseded { by_revision } => {
                if *by_revision <= self.revision {
                    return Err(StoreError::InvalidField {
                        field: "blackboard.lifecycle.by_revision",
                        reason: "must point to a later immutable revision",
                    });
                }
            }
            BoardEntryState::Retracted { by_session, .. } => {
                validate_text(by_session, "blackboard.lifecycle.by_session")?;
            }
        }
        Ok(())
    }
}

/// Re-validates one durable handle through its canonical constructor.
fn validate_handle(handle: &DurableRecordHandle, field: &'static str) -> Result<(), StoreError> {
    DurableRecordHandle::new(handle.as_str()).map_err(|_| StoreError::InvalidField {
        field,
        reason: "must be a bounded durable record handle",
    })?;
    Ok(())
}

/// One item revision and the exact current revision expected at its head.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlackboardItemRevision {
    /// Complete immutable candidate revision.
    pub record: BlackboardItemRecord,
    /// Exact immutable head observed by Kernel; absent only for first admission.
    pub expected_predecessor: Option<BlackboardItemRecord>,
}

impl BlackboardItemRevision {
    /// Validates immutable revision sequencing and record shape.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.record.validate()?;
        let expected_revision = if let Some(predecessor) = &self.expected_predecessor {
            predecessor.validate()?;
            if predecessor.task_id != self.record.task_id
                || predecessor.item_id != self.record.item_id
                || predecessor.kind != self.record.kind
                || predecessor.author_principal != self.record.author_principal
                || predecessor.producer_lineage != self.record.producer_lineage
            {
                return Err(StoreError::InvalidField {
                    field: "blackboard.expected_predecessor",
                    reason: "task, item, kind, author, and producer lineage must remain bound",
                });
            }
            if !matches!(&predecessor.lifecycle, BoardEntryState::Current) {
                return Err(StoreError::InvalidField {
                    field: "blackboard.expected_predecessor.lifecycle",
                    reason: "only a current head may advance",
                });
            }
            if !matches!(
                &self.record.lifecycle,
                BoardEntryState::Current | BoardEntryState::Retracted { .. }
            ) {
                return Err(StoreError::InvalidField {
                    field: "blackboard.lifecycle",
                    reason: "a new head must be current or terminally retracted",
                });
            }
            predecessor
                .revision
                .checked_add(1)
                .ok_or(StoreError::InvalidField {
                    field: "blackboard.expected_predecessor.revision",
                    reason: "revision overflow",
                })?
        } else {
            if !matches!(&self.record.lifecycle, BoardEntryState::Current) {
                return Err(StoreError::InvalidField {
                    field: "blackboard.lifecycle",
                    reason: "first admission must be current",
                });
            }
            1
        };
        if expected_revision > i64::MAX as u64 {
            return Err(StoreError::InvalidField {
                field: "blackboard.expected_predecessor.revision",
                reason: "must fit a positive Surreal integer",
            });
        }
        if self.record.revision != expected_revision {
            return Err(StoreError::InvalidField {
                field: "blackboard.revision",
                reason: "must immediately follow the expected predecessor",
            });
        }
        Ok(())
    }

    /// Returns canonical JSON used as the immutable durable revision body.
    pub fn canonical_record_json(&self) -> Result<String, StoreError> {
        let bytes = canonical_json_bytes(&self.record)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        String::from_utf8(bytes).map_err(|error| StoreError::Serialization(error.to_string()))
    }
}

/// Builds the closed named mutation for one candidate revision.
pub fn blackboard_item_request(
    revision: BlackboardItemRevision,
) -> Result<NamedMutationRequest, StoreError> {
    revision.validate()?;
    let parameters = BTreeMap::from([(
        "revision".to_owned(),
        serde_json::to_value(revision)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    )]);
    Ok(NamedMutationRequest {
        operation: NamedMutationOperation::ApplyBlackboardItem,
        parameters,
    })
}

/// Decodes and validates one closed candidate mutation.
pub fn decode_blackboard_item(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<BlackboardItemRevision, StoreError> {
    if operation != NamedMutationOperation::ApplyBlackboardItem {
        return Err(StoreError::UnknownOperation);
    }
    crate::operation_parameters::validate_typed_mutation_parameters(operation, parameters)?;
    let revision: BlackboardItemRevision =
        serde_json::from_value(parameters.get("revision").cloned().ok_or(
            StoreError::InvalidField {
                field: "blackboard.revision",
                reason: "is required",
            },
        )?)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    revision.validate()?;
    Ok(revision)
}

/// Builds an exact task/item read request. Readback returns the typed record;
/// peer messages can reference its item ID without copying its content.
pub fn blackboard_item_read_request(
    task_id: TaskId,
    item_id: impl Into<String>,
    state_fence: StateFence,
) -> Result<NamedReadRequest, StoreError> {
    let item_id = item_id.into();
    validate_text(&item_id, "blackboard.item_id")?;
    let parameters = BTreeMap::from([
        (
            "task_id".to_owned(),
            serde_json::to_value(task_id)
                .map_err(|error| StoreError::Serialization(error.to_string()))?,
        ),
        ("item_id".to_owned(), Value::String(item_id)),
    ]);
    Ok(NamedReadRequest {
        operation: NamedReadOperation::GetBlackboardItem,
        scope_id: None::<ScopeId>,
        consistency: ReadConsistency::ExactFence,
        state_fence,
        parameters,
    })
}
