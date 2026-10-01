//! Canonical budget-ledger consumption CAS (#1912).
//!
//! Store persists the exact Governor-owned Budget snapshot and one immutable
//! attribution row in a single named transition. It does not interpret usage
//! or manufacture a budget receipt; Governor validates the committed snapshot
//! and readback against its existing `BudgetLedger` owner.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    NamedMutationOperation, OperationId, OperationManifestDigest,
    OrderingHeadExpectation, PreparedTransition, RequestMeta,
    RevisionHeadExpectation, StateFence, StoreError, TransitionClass, WriteReceipt,
    WriteReceiptStatus, canonical_json_bytes, sha256_hex, validate_digest, validate_text,
};

pub const BUDGET_CONSUMPTION_SCHEMA_V1: &str = "eliot.storage.budget-consumption.v1";
pub const BUDGET_CONSUMPTION_RECORD_NAMESPACE: &str = "budget-consumption-v1";

/// Governor-produced correlation row for one committed ledger consumption.
/// The measured usage and reservation receipt are retained exactly as emitted
/// by the existing `BudgetLedger`; their semantics remain Governor-owned.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetConsumptionRecord {
    pub schema: String,
    /// Stable record key, normally the exact provider operation identity.
    pub consumption_id: String,
    pub state_fence: StateFence,
    pub session_id: String,
    pub task_id: String,
    pub work_id: String,
    pub work_scope_id: String,
    pub attempt_id: String,
    /// Original native-worker claim dispatch operation.
    pub admitted_operation_id: OperationId,
    /// Child-process/provider operation, distinct from the canonical commit.
    pub provider_operation_id: OperationId,
    /// Exact canonical ADMITTED row key and bytes digest.
    pub admission_record_key: String,
    pub admission_record_sha256: String,
    /// Exact existing Budget reservation identity.
    pub reservation_id: String,
    pub reservation_idempotency_key: String,
    pub provider_ref: String,
    pub tool_ref: String,
    /// Compact canonical JSON emitted by BudgetLedger after measured usage
    /// was committed/reconciled; this is not provider input.
    pub reservation_receipt_json: String,
    pub reservation_receipt_sha256: String,
    pub measured_usage_json: String,
    pub measured_usage_sha256: String,
    /// Revision/digest of the current durable Budget owner image observed
    /// before preparation. Exact CAS uses both values.
    pub expected_budget_owner_revision: u64,
    pub expected_budget_owner_sha256: String,
    /// Revision/digest of the exact next Budget owner image.
    pub committed_budget_owner_revision: u64,
    pub committed_budget_owner_sha256: String,
    /// Original canonical operation identity of this Store transition.
    pub canonical_operation_id: OperationId,
    pub canonical_idempotency_key: String,
}

impl BudgetConsumptionRecord {
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.schema != BUDGET_CONSUMPTION_SCHEMA_V1 {
            return Err(StoreError::UnknownOperation);
        }
        for (field, value) in [
            ("budget_consumption.consumption_id", self.consumption_id.as_str()),
            ("budget_consumption.task_id", self.task_id.as_str()),
            ("budget_consumption.session_id", self.session_id.as_str()),
            ("budget_consumption.work_id", self.work_id.as_str()),
            ("budget_consumption.work_scope_id", self.work_scope_id.as_str()),
            ("budget_consumption.attempt_id", self.attempt_id.as_str()),
            ("budget_consumption.admission_record_key", self.admission_record_key.as_str()),
            ("budget_consumption.reservation_id", self.reservation_id.as_str()),
            ("budget_consumption.reservation_idempotency_key", self.reservation_idempotency_key.as_str()),
            ("budget_consumption.provider_ref", self.provider_ref.as_str()),
            ("budget_consumption.tool_ref", self.tool_ref.as_str()),
            ("budget_consumption.canonical_idempotency_key", self.canonical_idempotency_key.as_str()),
        ] {
            validate_text(value, field)?;
        }
        self.state_fence.validate().map_err(StoreError::Foundation)?;
        validate_digest(&self.admission_record_sha256, "budget_consumption.admission_record_sha256")?;
        validate_digest(&self.reservation_receipt_sha256, "budget_consumption.reservation_receipt_sha256")?;
        validate_digest(&self.measured_usage_sha256, "budget_consumption.measured_usage_sha256")?;
        validate_digest(&self.expected_budget_owner_sha256, "budget_consumption.expected_budget_owner_sha256")?;
        validate_digest(&self.committed_budget_owner_sha256, "budget_consumption.committed_budget_owner_sha256")?;
        for (field, operation_id) in [
            ("budget_consumption.admitted_operation_id", &self.admitted_operation_id),
            ("budget_consumption.provider_operation_id", &self.provider_operation_id),
            ("budget_consumption.canonical_operation_id", &self.canonical_operation_id),
        ] {
            if OperationId::new(operation_id.as_str())? != *operation_id {
                return Err(StoreError::InvalidField {
                    field,
                    reason: "must preserve the original typed operation identity",
                });
            }
        }
        if self.reservation_receipt_json.is_empty()
            || self.reservation_receipt_json.len() > crate::MAX_RECOVERY_RECORD_BYTES
            || self.measured_usage_json.is_empty()
            || self.measured_usage_json.len() > crate::MAX_RECOVERY_RECORD_BYTES
            || self.expected_budget_owner_revision == 0
            || self.expected_budget_owner_revision.checked_add(1)
                != Some(self.committed_budget_owner_revision)
            || self.canonical_operation_id == self.provider_operation_id
            || self.admitted_operation_id == self.provider_operation_id
        {
            return Err(StoreError::InvalidField {
                field: "budget_consumption.owner_commitment",
                reason: "must bind bounded usage bytes, distinct provider identity, and one exact next Budget owner revision",
            });
        }
        if sha256_hex(self.reservation_receipt_json.as_bytes()) != self.reservation_receipt_sha256
            || sha256_hex(self.measured_usage_json.as_bytes()) != self.measured_usage_sha256
        {
            return Err(StoreError::InvalidField {
                field: "budget_consumption.usage_digest",
                reason: "must cover the exact canonical receipt and measured-usage bytes",
            });
        }
        let receipt: serde_json::Value = serde_json::from_str(&self.reservation_receipt_json)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let receipt_bytes = canonical_json_bytes(&receipt)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let usage: serde_json::Value = serde_json::from_str(&self.measured_usage_json)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let usage_bytes = canonical_json_bytes(&usage)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        if String::from_utf8(receipt_bytes).ok().as_deref()
                != Some(self.reservation_receipt_json.as_str())
            || String::from_utf8(usage_bytes).ok().as_deref()
                != Some(self.measured_usage_json.as_str())
        {
            return Err(StoreError::InvalidField {
                field: "budget_consumption.usage_json",
                reason: "must use canonical JSON bytes",
            });
        }
        let receipt_value = serde_json::from_str::<serde_json::Value>(&self.reservation_receipt_json)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        if receipt_value.get("reservation_id").and_then(serde_json::Value::as_str)
                != Some(self.reservation_id.as_str())
            || receipt_value.get("state").and_then(serde_json::Value::as_str)
                != Some("RELEASED")
            || receipt_value.get("idempotency_key").and_then(serde_json::Value::as_str)
                != Some(self.reservation_idempotency_key.as_str())
            || receipt_value.pointer("/operation/operation_id").and_then(serde_json::Value::as_str)
                != Some(self.provider_operation_id.as_str())
            || receipt_value.get("provider_tool").and_then(|value| value.get("provider_ref"))
                .and_then(serde_json::Value::as_str) != Some(self.provider_ref.as_str())
            || receipt_value.get("provider_tool").and_then(|value| value.get("tool_ref"))
                .and_then(serde_json::Value::as_str) != Some(self.tool_ref.as_str())
            || receipt_value.get("committed_usage") != Some(&usage)
        {
            return Err(StoreError::InvalidField {
                field: "budget_consumption.reservation_receipt_json",
                reason: "must retain the exact measured reservation receipt for this provider operation and route",
            });
        }
        Ok(())
    }
}

/// Independently retained commit expectation copied from the original
/// prepared transition. Receipt validation never derives these values from the
/// returned receipt itself.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedBudgetConsumptionCommitment {
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub canonical_request_hash: String,
    pub state_fence: StateFence,
    pub transition_class: TransitionClass,
    pub operation_manifest_digest: OperationManifestDigest,
    pub admission_digest: String,
    pub mutation_plan_digest: String,
    pub semantic_source_revisions: Vec<String>,
    pub consumption_id: String,
    pub budget_owner_revision: u64,
    pub budget_owner_sha256: String,
}

impl ExpectedBudgetConsumptionCommitment {
    pub fn from_prepared(transition: &PreparedTransition) -> Result<Self, StoreError> {
        validate_budget_consumption_transition(transition)?;
        let record = decode_budget_consumption_record(&transition.named_operations[0].parameters)?;
        Ok(Self {
            operation_id: transition.identity.operation_id.clone(),
            idempotency_key: transition.identity.idempotency_key.clone(),
            canonical_request_hash: transition.identity.canonical_request_hash.clone(),
            state_fence: transition.state_fence.clone(),
            transition_class: transition.transition_class,
            operation_manifest_digest: transition.operation_manifest_digest.clone(),
            admission_digest: transition.admission_digest.clone(),
            mutation_plan_digest: transition.mutation_plan_digest.clone(),
            semantic_source_revisions: transition.semantic_source_revisions.clone(),
            consumption_id: record.consumption_id,
            budget_owner_revision: record.committed_budget_owner_revision,
            budget_owner_sha256: record.committed_budget_owner_sha256,
        })
    }

    pub fn matches_receipt(&self, receipt: &WriteReceipt) -> Result<(), StoreError> {
        receipt.validate()?;
        if receipt.status != WriteReceiptStatus::Committed
            || receipt.operation_id != self.operation_id
            || receipt.idempotency_key != self.idempotency_key
            || receipt.canonical_request_hash != self.canonical_request_hash
            || receipt.state_fence != self.state_fence
            || receipt.transition_class != self.transition_class
            || receipt.operation_manifest_digest != self.operation_manifest_digest
            || receipt.admission_digest != self.admission_digest
            || receipt.mutation_plan_digest != self.mutation_plan_digest
            || receipt.semantic_source_revisions != self.semantic_source_revisions
            || !receipt.outbox_refs.is_empty()
        {
            return Err(StoreError::InvalidReceipt);
        }
        Ok(())
    }
}

/// Prepared, authenticated Store API operation and original receipt contract.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetConsumptionSubmission {
    pub request: RequestMeta,
    pub prepared_transition: PreparedTransition,
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
    pub expected: ExpectedBudgetConsumptionCommitment,
}

impl BudgetConsumptionSubmission {
    pub fn new(
        request: RequestMeta,
        prepared_transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<Self, StoreError> {
        request.validate().map_err(StoreError::Foundation)?;
        validate_budget_consumption_transition(&prepared_transition)?;
        let record = decode_budget_consumption_record(
            &prepared_transition.named_operations[0].parameters,
        )?;
        if request.state_fence != prepared_transition.state_fence
            || request.task_id.as_ref().map(|value| value.as_str()) != Some(record.task_id.as_str())
            || request.session_id.as_ref().map(|value| value.as_str()) != Some(record.session_id.as_str())
            || request.source_id.as_str() != "source-eliotd"
            || prepared_transition.identity.operation_id != record.canonical_operation_id
            || prepared_transition.identity.idempotency_key != record.canonical_idempotency_key
        {
            return Err(StoreError::InvalidField {
                field: "budget_consumption.request_metadata",
                reason: "must retain the original authenticated task/session and canonical operation identity",
            });
        }
        for head in &expected_revision_heads {
            head.validate()?;
            if head.state_fence != prepared_transition.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        for head in &expected_ordering_heads {
            head.validate()?;
            if head.state_fence != prepared_transition.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        let expected = ExpectedBudgetConsumptionCommitment::from_prepared(&prepared_transition)?;
        Ok(Self { request, prepared_transition, expected_revision_heads, expected_ordering_heads, expected })
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        self.request.validate().map_err(StoreError::Foundation)?;
        validate_budget_consumption_transition(&self.prepared_transition)?;
        let record = decode_budget_consumption_record(&self.prepared_transition.named_operations[0].parameters)?;
        if self.request.state_fence != self.prepared_transition.state_fence
            || self.request.task_id.as_ref().map(|value| value.as_str()) != Some(record.task_id.as_str())
            || self.request.session_id.as_ref().map(|value| value.as_str()) != Some(record.session_id.as_str())
            || self.request.source_id.as_str() != "source-eliotd"
            || self.prepared_transition.identity.operation_id != record.canonical_operation_id
            || self.prepared_transition.identity.idempotency_key != record.canonical_idempotency_key
            || self.expected != ExpectedBudgetConsumptionCommitment::from_prepared(&self.prepared_transition)?
        {
            return Err(StoreError::InvalidReceipt);
        }
        for head in &self.expected_revision_heads {
            head.validate()?;
            if head.state_fence != self.prepared_transition.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        for head in &self.expected_ordering_heads {
            head.validate()?;
            if head.state_fence != self.prepared_transition.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        Ok(())
    }

    pub fn validate_receipt(&self, receipt: &WriteReceipt) -> Result<(), StoreError> {
        self.validate()?;
        self.expected.matches_receipt(receipt)
    }
}

pub fn decode_budget_consumption_record(
    parameters: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<BudgetConsumptionRecord, StoreError> {
    let value = parameters.get("consumption").ok_or(StoreError::InvalidField {
        field: "budget_consumption.consumption",
        reason: "the exact attributed consumption record is required",
    })?;
    let record: BudgetConsumptionRecord = serde_json::from_value(value.clone())
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    record.validate()?;
    Ok(record)
}

/// Validates the exact owner CAS and record carried by this named mutation.
pub fn validate_budget_consumption_transition(
    transition: &PreparedTransition,
) -> Result<(), StoreError> {
    if transition.transition_class != TransitionClass::RecoverySchema
        || transition.requested_effect_ceiling != crate::EffectClass::ReversibleMutation
        || transition.named_operations.len() != 1
        || transition.named_operations[0].operation != NamedMutationOperation::CommitBudgetConsumption
    {
        return Err(StoreError::TransitionClassExceeded);
    }
    crate::validate_typed_mutation_parameters(
        NamedMutationOperation::CommitBudgetConsumption,
        &transition.named_operations[0].parameters,
    )?;
    let record = decode_budget_consumption_record(&transition.named_operations[0].parameters)?;
    let expected_revision = transition.named_operations[0].parameters
        .get("expected_budget_owner_revision")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse::<u64>().ok());
    let expected_digest = transition.named_operations[0].parameters
        .get("expected_budget_owner_digest")
        .and_then(serde_json::Value::as_str);
    let snapshot_json = transition.named_operations[0].parameters
        .get("budget_owner_snapshot_json")
        .and_then(serde_json::Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "budget_consumption.budget_owner_snapshot_json",
            reason: "the exact next Budget owner image is required",
        })?;
    if transition.state_fence != record.state_fence
        || transition.task_id.as_deref() != Some(record.task_id.as_str())
        || transition.scope_id.as_str() != record.work_scope_id
        || transition.identity.operation_id != record.canonical_operation_id
        || transition.identity.idempotency_key != record.canonical_idempotency_key
        || expected_revision != Some(record.expected_budget_owner_revision)
        || expected_digest != Some(record.expected_budget_owner_sha256.as_str())
        || snapshot_json.is_empty()
        || snapshot_json.len() > crate::MAX_RECOVERY_RECORD_BYTES
        || sha256_hex(snapshot_json.as_bytes()) != record.committed_budget_owner_sha256
    {
        return Err(StoreError::InvalidField {
            field: "budget_consumption.owner_cas",
            reason: "must bind the original transition, exact previous Budget owner, and exact next owner bytes",
        });
    }
    let snapshot: serde_json::Value = serde_json::from_str(snapshot_json)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let snapshot_bytes = canonical_json_bytes(&snapshot)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let expected_fence = serde_json::to_value(&record.state_fence)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if String::from_utf8(snapshot_bytes).ok().as_deref() != Some(snapshot_json)
        || snapshot.get("schema").and_then(serde_json::Value::as_str)
            != Some("eliot.governor.budget-owner.v1")
        || snapshot.get("version").and_then(serde_json::Value::as_u64) != Some(1)
        || snapshot.get("revision").and_then(serde_json::Value::as_u64)
            != Some(record.committed_budget_owner_revision)
        || snapshot.get("state_fence") != Some(&expected_fence)
        || snapshot.pointer("/state/kind").and_then(serde_json::Value::as_str)
            != Some("configured")
        || snapshot.pointer("/state/ledger").and_then(serde_json::Value::as_object).is_none()
    {
        return Err(StoreError::InvalidField {
            field: "budget_consumption.budget_owner_snapshot_json",
            reason: "must be exact canonical bytes at the same fence and next revision",
        });
    }
    Ok(())
}

/// Builds the closed named mutation after Governor has committed measured
/// usage to the existing BudgetLedger and prepared its next owner snapshot.
pub fn commit_budget_consumption_operation(
    record: BudgetConsumptionRecord,
    budget_owner_snapshot_json: String,
) -> Result<crate::NamedMutationRequest, StoreError> {
    record.validate()?;
    let operation = crate::NamedMutationRequest {
        operation: NamedMutationOperation::CommitBudgetConsumption,
        parameters: std::collections::BTreeMap::from([
            ("consumption".to_owned(), serde_json::to_value(&record)
                .map_err(|error| StoreError::Serialization(error.to_string()))?),
            ("expected_budget_owner_revision".to_owned(), serde_json::Value::String(
                record.expected_budget_owner_revision.to_string(),
            )),
            ("expected_budget_owner_digest".to_owned(), serde_json::Value::String(
                record.expected_budget_owner_sha256,
            )),
            ("budget_owner_snapshot_json".to_owned(), serde_json::Value::String(
                budget_owner_snapshot_json,
            )),
        ]),
    };
    operation.validate()?;
    Ok(operation)
}
