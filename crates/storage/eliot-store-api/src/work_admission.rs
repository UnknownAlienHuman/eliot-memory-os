//! Closed canonical work-admission record and receipt join (#1678, I14.6/I10.15).
//!
//! The record is the Governor-owned semantic ADMITTED decision. It binds the
//! original durable-work semantics to the exact ORS reservation, attempt,
//! claims, fence, epoch, semantic revision, canonical operation and the
//! launch-outbox row committed by that same operation. It does not interpret
//! claim references or mint policy ceilings.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    NamedMutationOperation, OperationIdentity, OperationId, OutboxId, OutboxIntentKind,
    OrderingHeadExpectation, PreparedTransition, RequestMeta, RevisionHeadExpectation,
    StateFence, StoreError, TransitionClass, WriteReceipt, WriteReceiptStatus, canonical_json_bytes,
    sha256_hex, validate_digest, validate_text,
};

pub const WORK_ADMISSION_SCHEMA_V1: &str = "eliot.storage.work-admission.v1";
pub const WORK_ADMISSION_RECORD_NAMESPACE: &str = "work-admission-v1";

/// Original semantic revision key and revision that admitted this work.
///
/// The revision is copied from its defining owner. It is not a digest of the
/// work payload or a value reconstructed from the receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionSemanticRevision {
    pub key: String,
    pub revision: String,
}

impl WorkAdmissionSemanticRevision {
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.key, "work_admission.semantic_revision.key")?;
        validate_text(&self.revision, "work_admission.semantic_revision.revision")?;
        let revision = self.revision.parse::<u64>().map_err(|_| StoreError::InvalidField {
            field: "work_admission.semantic_revision.revision",
            reason: "must be a canonical positive owner revision",
        })?;
        if revision == 0 || revision.to_string() != self.revision {
            return Err(StoreError::InvalidField {
                field: "work_admission.semantic_revision.revision",
                reason: "must be a canonical positive owner revision",
            });
        }
        Ok(())
    }
}

/// One owner-issued dependency that must already carry accepted evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionDependency {
    pub work_id: String,
    pub evidence_digest: String,
}

impl WorkAdmissionDependency {
    fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.work_id, "work_admission.dependency.work_id")?;
        validate_digest(&self.evidence_digest, "work_admission.dependency.evidence_digest")
    }
}

/// Closed dimensions copied from the admitted durable-work definition.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkAdmissionBudgetDimension {
    ComputeSteps,
    CostMicrounits,
    EvidenceBytes,
}

/// One explicit budget limit from the admitted work definition.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionBudget {
    pub dimension: WorkAdmissionBudgetDimension,
    pub limit: u64,
}

/// Immutable owner-defined claim identity and exact content digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionClaimRef {
    pub reference: String,
    pub sha256: String,
}

impl WorkAdmissionClaimRef {
    fn validate(&self, field: &'static str) -> Result<(), StoreError> {
        validate_text(&self.reference, field)?;
        validate_digest(&self.sha256, "work_admission.claim.sha256")
    }
}

/// Complete resource, lane, environment, effects, and quota claim set.
///
/// These are opaque owner references, not admitted ceilings. Each original
/// claim digest is retained verbatim for the Kernel reservation join.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionClaims {
    pub resources: WorkAdmissionClaimRef,
    pub lane: WorkAdmissionClaimRef,
    pub environment: WorkAdmissionClaimRef,
    pub effects: WorkAdmissionClaimRef,
    pub quota_view: WorkAdmissionClaimRef,
}

impl WorkAdmissionClaims {
    pub fn validate(&self) -> Result<(), StoreError> {
        let claims = [
            (&self.resources, "work_admission.claim.resources"),
            (&self.lane, "work_admission.claim.lane"),
            (&self.environment, "work_admission.claim.environment"),
            (&self.effects, "work_admission.claim.effects"),
            (&self.quota_view, "work_admission.claim.quota_view"),
        ];
        let mut seen = std::collections::BTreeMap::new();
        for (claim, field) in claims {
            claim.validate(field)?;
            if let Some(prior) = seen.insert(claim.reference.as_str(), claim.sha256.as_str())
                && prior != claim.sha256.as_str()
            {
                return Err(StoreError::Duplicate { field: "work_admission.claims" });
            }
        }
        Ok(())
    }
}

/// Canonical state of this immutable admission row.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkAdmissionState {
    Admitted,
}

/// Governor-owned canonical ADMITTED decision for one exact reservation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionRecord {
    pub schema: String,
    pub state: WorkAdmissionState,
    /// Durable work identity from the owner-issued admitted definition.
    pub work_id: String,
    pub parent_task_id: String,
    pub task_id: String,
    pub session_id: String,
    pub task_revision: String,
    pub cell_id: String,
    pub payload_digest: String,
    pub input_revision: String,
    pub scope_id: String,
    pub term: u64,
    pub dependencies: Vec<WorkAdmissionDependency>,
    pub budgets: Vec<WorkAdmissionBudget>,
    pub route_class: String,
    pub max_retries: u32,
    pub max_children: u32,
    pub max_depth: u32,
    pub max_pending_reviews: u32,
    pub evidence_required: bool,
    pub receipt_contract_revision: String,
    /// Exact identity tuple of the staged ORS reservation.
    pub reservation_id: OperationIdentity,
    pub work_item_id: OperationIdentity,
    pub proposed_attempt_id: OperationIdentity,
    pub stage_operation_id: OperationIdentity,
    pub claims: WorkAdmissionClaims,
    pub authority_epoch: eliot_contracts::EpochId,
    pub state_fence: StateFence,
    pub expires_at_ms: i64,
    /// Original semantic-owner revision, stored first-class.
    pub semantic_admission_revision: WorkAdmissionSemanticRevision,
    /// Owner-observed predecessor of the proposed semantic admission revision.
    /// The canonical commit compares this exact value before advancing it.
    pub semantic_admission_predecessor_revision: u64,
    /// Canonical operation whose transaction commits this ADMITTED row.
    pub canonical_operation_id: OperationId,
    /// Exact idempotency key from the original canonical submission.
    /// Retries and restart reconciliation reuse this value unchanged.
    pub canonical_idempotency_key: String,
    /// Exact launch outbox row written by that same canonical operation.
    pub launch_outbox_id: OutboxId,
}

impl WorkAdmissionRecord {
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.schema != WORK_ADMISSION_SCHEMA_V1 {
            return Err(StoreError::UnknownOperation);
        }
        if self.state != WorkAdmissionState::Admitted {
            return Err(StoreError::InvalidField {
                field: "work_admission.state",
                reason: "canonical work admission must be ADMITTED",
            });
        }
        for (field, value) in [
            ("work_admission.work_id", self.work_id.as_str()),
            ("work_admission.parent_task_id", self.parent_task_id.as_str()),
            ("work_admission.task_id", self.task_id.as_str()),
            ("work_admission.session_id", self.session_id.as_str()),
            ("work_admission.task_revision", self.task_revision.as_str()),
            ("work_admission.cell_id", self.cell_id.as_str()),
            ("work_admission.input_revision", self.input_revision.as_str()),
            ("work_admission.scope_id", self.scope_id.as_str()),
            ("work_admission.route_class", self.route_class.as_str()),
            (
                "work_admission.receipt_contract_revision",
                self.receipt_contract_revision.as_str(),
            ),
            (
                "work_admission.canonical_idempotency_key",
                self.canonical_idempotency_key.as_str(),
            ),
        ] {
            validate_text(value, field)?;
        }
        validate_digest(&self.payload_digest, "work_admission.payload_digest")?;
        self.reservation_id.validate()?;
        self.work_item_id.validate()?;
        self.proposed_attempt_id.validate()?;
        self.stage_operation_id.validate()?;
        self.claims.validate()?;
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if self.authority_epoch != self.state_fence.authority_epoch {
            return Err(StoreError::FenceMismatch);
        }
        if self.expires_at_ms <= 0 {
            return Err(StoreError::InvalidField {
                field: "work_admission.expires_at_ms",
                reason: "must be a positive owner-issued expiry",
            });
        }
        self.semantic_admission_revision.validate()?;
        if self
            .semantic_admission_predecessor_revision
            .checked_add(1)
            != self
                .semantic_admission_revision
                .revision
                .parse::<u64>()
                .ok()
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.semantic_admission_predecessor_revision",
                reason: "must be the exact predecessor of the owner-issued admission revision",
            });
        }
        let mut dependency_ids = std::collections::BTreeSet::new();
        for dependency in &self.dependencies {
            dependency.validate()?;
            if !dependency_ids.insert(dependency.work_id.as_str()) {
                return Err(StoreError::Duplicate {
                    field: "work_admission.dependencies",
                });
            }
        }
        let mut budget_dimensions = std::collections::BTreeSet::new();
        for budget in &self.budgets {
            if !budget_dimensions.insert(budget.dimension) {
                return Err(StoreError::Duplicate {
                    field: "work_admission.budgets",
                });
            }
        }
        let expected_launch = OutboxIntentKind::Launch
            .outbox_id(self.canonical_operation_id.as_str(), 0)?;
        if self.launch_outbox_id != expected_launch {
            return Err(StoreError::InvalidField {
                field: "work_admission.launch_outbox_id",
                reason: "must be the launch row derived from the canonical operation identity",
            });
        }
        Ok(())
    }

    /// Key shared by the canonical row and its exact readback.
    pub fn record_key(&self) -> String {
        format!("{}:{}", self.work_id, self.proposed_attempt_id.operation_id)
    }
}

/// Independently retained expected values copied from the original prepared
/// transition, never derived from a receipt or a receipt-shaped transport body.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedWorkAdmissionCommitment {
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub canonical_request_hash: String,
    pub state_fence: StateFence,
    pub transition_class: TransitionClass,
    pub operation_manifest_digest: crate::OperationManifestDigest,
    pub admission_digest: String,
    pub mutation_plan_digest: String,
    pub semantic_source_revisions: Vec<String>,
    pub launch_outbox_id: OutboxId,
}

impl ExpectedWorkAdmissionCommitment {
    pub fn from_prepared(transition: &PreparedTransition) -> Result<Self, StoreError> {
        validate_work_admission_transition(transition)?;
        let record = decode_work_admission_record(&transition.named_operations[0].parameters)?;
        let expected = Self {
            operation_id: transition.identity.operation_id.clone(),
            idempotency_key: transition.identity.idempotency_key.clone(),
            canonical_request_hash: transition.identity.canonical_request_hash.clone(),
            state_fence: transition.state_fence.clone(),
            transition_class: transition.transition_class,
            operation_manifest_digest: transition.operation_manifest_digest.clone(),
            admission_digest: transition.admission_digest.clone(),
            mutation_plan_digest: transition.mutation_plan_digest.clone(),
            semantic_source_revisions: transition.semantic_source_revisions.clone(),
            launch_outbox_id: record.launch_outbox_id,
        };
        Ok(expected)
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
        {
            return Err(StoreError::InvalidReceipt);
        }
        let launches: Vec<&OutboxId> = receipt
            .outbox_refs
            .iter()
            .filter(|id| OutboxIntentKind::of(id) == Some(OutboxIntentKind::Launch))
            .collect();
        if launches.len() != 1 || launches[0] != &self.launch_outbox_id {
            return Err(StoreError::InvalidReceipt);
        }
        Ok(())
    }
}

/// Kernel-ready owner output retaining the exact authenticated request,
/// prepared transition and compare-and-swap heads used to create it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionSubmission {
    pub request: RequestMeta,
    pub prepared_transition: PreparedTransition,
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
    pub expected: ExpectedWorkAdmissionCommitment,
}

impl WorkAdmissionSubmission {
    pub fn new(
        request: RequestMeta,
        prepared_transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<Self, StoreError> {
        request.validate().map_err(StoreError::Foundation)?;
        validate_work_admission_transition(&prepared_transition)?;
        if request.state_fence != prepared_transition.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        let record = decode_work_admission_record(
            &prepared_transition.named_operations[0].parameters,
        )?;
        if prepared_transition.identity.idempotency_key != record.canonical_idempotency_key {
            return Err(StoreError::InvalidField {
                field: "work_admission.canonical_idempotency_key",
                reason: "must match the original prepared transition identity",
            });
        }
        if request.task_id.as_ref().map(|task| task.as_str()) != Some(record.task_id.as_str())
            || request.session_id.as_ref().map(|session| session.as_str())
                != Some(record.session_id.as_str())
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.request_metadata",
                reason: "authenticated task and session must match admitted work",
            });
        }
        for head in &expected_revision_heads {
            head.validate()?;
            if head.state_fence != prepared_transition.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        validate_work_admission_predecessor_heads(
            &record,
            &prepared_transition.state_fence,
            &expected_revision_heads,
        )?;
        for head in &expected_ordering_heads {
            head.validate()?;
            if head.state_fence != prepared_transition.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        let expected = ExpectedWorkAdmissionCommitment::from_prepared(&prepared_transition)?;
        Ok(Self {
            request,
            prepared_transition,
            expected_revision_heads,
            expected_ordering_heads,
            expected,
        })
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        self.request.validate().map_err(StoreError::Foundation)?;
        validate_work_admission_transition(&self.prepared_transition)?;
        let record = decode_work_admission_record(
            &self.prepared_transition.named_operations[0].parameters,
        )?;
        if self.request.state_fence != self.prepared_transition.state_fence
            || self.expected
                != ExpectedWorkAdmissionCommitment::from_prepared(&self.prepared_transition)?
            || self.request.task_id.as_ref().map(|task| task.as_str())
                != Some(record.task_id.as_str())
            || self.request.session_id.as_ref().map(|session| session.as_str())
                != Some(record.session_id.as_str())
            || self.prepared_transition.identity.idempotency_key
                != record.canonical_idempotency_key
        {
            return Err(StoreError::InvalidReceipt);
        }
        for head in &self.expected_revision_heads {
            head.validate()?;
            if head.state_fence != self.prepared_transition.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        validate_work_admission_predecessor_heads(
            &record,
            &self.prepared_transition.state_fence,
            &self.expected_revision_heads,
        )?;
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

/// Decodes the sole `record` parameter under the closed work-admission schema.
pub fn decode_work_admission_record(
    parameters: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<WorkAdmissionRecord, StoreError> {
    let value = parameters.get("record").ok_or(StoreError::InvalidField {
        field: "work_admission.record",
        reason: "required canonical record is missing",
    })?;
    let record: WorkAdmissionRecord = serde_json::from_value(value.clone())
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    record.validate()?;
    Ok(record)
}

/// Validates the original prepared `AdmitWork` transition and its independent
/// semantic revision binding.
pub fn validate_work_admission_transition(
    transition: &PreparedTransition,
) -> Result<(), StoreError> {
    if transition.transition_class != TransitionClass::TaskControl
        || transition.requested_effect_ceiling != crate::EffectClass::ReversibleMutation
        || transition.named_operations.len() != 1
        || transition.named_operations[0].operation != NamedMutationOperation::AdmitWork
    {
        return Err(StoreError::TransitionClassExceeded);
    }
    let record = decode_work_admission_record(&transition.named_operations[0].parameters)?;
    let task = transition.task_id.as_deref();
    if task != Some(record.task_id.as_str())
        || transition.scope_id.as_str() != record.scope_id
        || transition.state_fence != record.state_fence
        || transition.identity.operation_id != record.canonical_operation_id
        || transition.identity.idempotency_key != record.canonical_idempotency_key
    {
        return Err(StoreError::FenceMismatch);
    }
    let expected_revision = format!(
        "{}@{}",
        record.semantic_admission_revision.key,
        record.semantic_admission_predecessor_revision
    );
    if !transition
        .semantic_source_revisions
        .iter()
        .any(|revision| revision == &expected_revision)
    {
        return Err(StoreError::InvalidField {
            field: "work_admission.semantic_admission_revision",
            reason: "the original owner revision must be retained by the prepared transition",
        });
    }
    if record.launch_outbox_id
        != OutboxIntentKind::Launch.outbox_id(
            transition.identity.operation_id.as_str(),
            0,
        )?
    {
        return Err(StoreError::InvalidReceipt);
    }
    Ok(())
}

fn validate_work_admission_predecessor_heads(
    record: &WorkAdmissionRecord,
    state_fence: &StateFence,
    expected_revision_heads: &[RevisionHeadExpectation],
) -> Result<(), StoreError> {
    let mut matching = expected_revision_heads.iter().filter(|head| {
        head.key.as_str() == record.semantic_admission_revision.key
    });
    let Some(head) = matching.next() else {
        return Err(StoreError::InvalidField {
            field: "work_admission.semantic_admission_predecessor_revision",
            reason: "the original owner CAS predecessor must be retained in the submission",
        });
    };
    if matching.next().is_some()
        || head.expected_revision != record.semantic_admission_predecessor_revision
        || head.state_fence != *state_fence
    {
        return Err(StoreError::InvalidField {
            field: "work_admission.semantic_admission_predecessor_revision",
            reason: "the submission must retain exactly the owner-observed CAS predecessor",
        });
    }
    Ok(())
}

/// Confirms the transition's closed one-command contract before it is passed
/// to the normal admission gate. Kept separate so callers cannot bypass the
/// registered operation catalogue.
pub fn validate_admit_work_command(
    operation: &crate::NamedMutationRequest,
) -> Result<WorkAdmissionRecord, StoreError> {
    if operation.operation != NamedMutationOperation::AdmitWork {
        return Err(StoreError::UnknownOperation);
    }
    decode_work_admission_record(&operation.parameters)
}

/// Builds the closed named mutation consumed by the canonical Store API.
pub fn admit_work_operation(record: WorkAdmissionRecord) -> Result<crate::NamedMutationRequest, StoreError> {
    record.validate()?;
    let record_value = serde_json::to_value(record)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let parameters = std::collections::BTreeMap::from([("record".to_owned(), record_value)]);
    let operation = crate::NamedMutationRequest {
        operation: NamedMutationOperation::AdmitWork,
        parameters,
    };
    operation.validate()?;
    Ok(operation)
}

/// Computes the existing SHA-256 over canonical record bytes for the adapter's
/// `RecoveryRecord::value_digest`; no second digest format is introduced.
pub fn work_admission_value_digest(record: &WorkAdmissionRecord) -> Result<String, StoreError> {
    let bytes = canonical_json_bytes(record)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}
