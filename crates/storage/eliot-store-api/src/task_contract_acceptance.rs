//! Store-neutral wire contract for the owner-persisted `TaskContract`
//! acceptance-item set (issue #325 P1, I7.9).
//!
//! I7.9 requires the Finish service to rehydrate "the current
//! `TaskContract`, acceptance items, exact artifacts, current State Fence,
//! executed verifier runs and effect outcomes". Only the owner that holds the
//! `TaskContract` can say which obligations exist, so the acceptance
//! denominator has to be a durable owner record inside the governed store and
//! not a projection of the verifier plan being checked against it. This module
//! is the write half of that record;
//! [`crate::task_contract_acceptance_read_request`] /
//! [`crate::decode_task_contract_acceptance_set`] are the closed read half and
//! [`crate::NamedReadOperation::GetTaskContractAcceptanceSet`] serves it.
//!
//! # Why a separate owner record and not the legacy `task_contract` table
//!
//! The governed adapter's schema inventory classifies the legacy
//! `task_contract` table as `LegacyTableDisposition::ArchiveOnly`, i.e. it is
//! archived away during legacy migration rather than adopted as a live
//! governed table. Reading it is therefore not available and must not be
//! assumed. The accepted pattern for a store-owned durable typed record in this
//! catalogue is a versioned namespace of the existing `recovery_owner` table
//! (issue #1822 blackboard items, #1773 capability evidence), so this record
//! uses exactly that mechanism and adds no table, no second identity scheme and
//! no second acceptance vocabulary.
//!
//! # Keying and immutability
//!
//! The row is addressed by the exact `(task_id, task_revision)` pair the read
//! asks for, so the read is a point lookup and never a "current row" scan. That
//! is what I5.5 already requires as the task-bound write precondition: the exact
//! `TaskContract` revision is an admission input, not something the reader may
//! widen. Each row is create-only: the owner cannot rewrite one task revision's
//! obligation set after it is durable, so a finish decision rehydrated at
//! revision *N* can never be answered with the set the owner published for
//! revision *M* or with a set narrowed after the fact.
//!
//! # Absent is a refusal, never an empty set
//!
//! An absent row, a row bound to another task or revision, a stale fence, a
//! digest that does not bind the stored bytes, or an obligation list that does
//! not validate is an error. None of them can produce an empty acceptance set,
//! because an empty set that satisfies the completion gate is the exact defect
//! this record exists to close.

use std::collections::BTreeMap;

use eliot_contracts::TaskId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    NamedMutationOperation, NamedMutationRequest, RecoveryRecordKey, StateFence, StoreError,
    TASK_CONTRACT_ACCEPTANCE_SET_SCHEMA_V1, TaskContractAcceptanceItem, TaskContractAcceptanceSet,
    canonical_json_bytes, sha256_hex, validate_text,
};

/// Schema identifier of the persisted owner acceptance-set record.
///
/// Distinct from [`TASK_CONTRACT_ACCEPTANCE_SET_SCHEMA_V1`], which names the
/// neutral read payload: this one names the durable record the owner writes.
/// Both are carried so a row cannot be read back under the wrong contract.
pub const TASK_CONTRACT_ACCEPTANCE_RECORD_SCHEMA_V1: &str =
    "eliot.task-contract.acceptance-record.v1";

/// Versioned `recovery_owner` namespace holding the owner acceptance-set rows.
///
/// One row per `(task_id, task_revision)`. The namespace is a peer of the
/// existing store-owned record namespaces, not a new table.
pub const TASK_CONTRACT_ACCEPTANCE_RECORD_NAMESPACE: &str = "task-contract-acceptance-v1";

/// Stable named mutation that persists one owner acceptance-set record.
pub const TASK_CONTRACT_ACCEPTANCE_RECORD_MUTATION_NAME: &str = "RecordTaskContractAcceptanceSet";

/// Stable named read that serves the owner acceptance set.
pub const TASK_CONTRACT_ACCEPTANCE_SET_READ_NAME: &str = "GetTaskContractAcceptanceSet";

/// One owner-persisted `TaskContract` acceptance obligation set.
///
/// This is the owner's own record, not a copy of anybody's coverage claim. The
/// retained `acceptance_digest` is the owner's OWN recorded acceptance identity
/// for this enumeration; it is never recomputed here and never accepted from a
/// reader, so the existing
/// [`crate::TaskContractAcceptanceSet::validate`] can prove it against the
/// enumeration retained beside it rather than a list the same party also
/// supplied.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskContractAcceptanceRecord {
    /// Task whose contract owns this obligation set.
    pub task_id: TaskId,
    /// Exact `TaskContract` revision this set was issued for.
    pub task_revision: u64,
    /// The owner's own recorded acceptance identity for this enumeration.
    pub acceptance_digest: String,
    /// Every obligation the contract requires at that revision, in owner order.
    pub items: Vec<TaskContractAcceptanceItem>,
    /// Exact `State Fence` the owner issued this set under.
    pub state_fence: StateFence,
}

impl TaskContractAcceptanceRecord {
    /// Projects this durable record into the closed neutral read payload read
    /// under `read_state_fence`.
    ///
    /// The projection is a faithful re-spelling of the retained owner bytes,
    /// not a rebuild: no field is defaulted, derived or re-ordered, so the
    /// neutral payload cannot say anything the owner did not persist.
    #[must_use]
    pub fn acceptance_set(&self, read_state_fence: &StateFence) -> TaskContractAcceptanceSet {
        TaskContractAcceptanceSet {
            schema: TASK_CONTRACT_ACCEPTANCE_SET_SCHEMA_V1.to_owned(),
            read_state_fence: read_state_fence.clone(),
            task_id: self.task_id.clone(),
            task_revision: self.task_revision,
            acceptance_digest: self.acceptance_digest.clone(),
            items: self.items.clone(),
        }
    }

    /// Validates the closed owner record through the existing neutral contract.
    ///
    /// There is deliberately no second rule set here: the record is refused
    /// exactly when the payload the read will serve would be refused, so a
    /// durable record cannot pass a weaker check than the set it projects into.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.acceptance_set(&self.state_fence).validate()
    }

    /// Returns the deterministic durable address of this record.
    #[must_use]
    pub fn record_key(&self) -> RecoveryRecordKey {
        task_contract_acceptance_record_key(self.task_id.as_str(), self.task_revision)
    }

    /// Returns the canonical record bytes the durable row retains.
    pub fn canonical_record_json(&self) -> Result<String, StoreError> {
        let bytes = canonical_json_bytes(self)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        String::from_utf8(bytes).map_err(|error| StoreError::Serialization(error.to_string()))
    }
}

/// Derives the deterministic `recovery_owner` address of one owner's acceptance
/// set.
///
/// The key is derived from the exact `(task_id, task_revision)` pair alone, so
/// the read that asks for that pair can address the row without a scan, and two
/// different task revisions can never collide on one row.
#[must_use]
pub fn task_contract_acceptance_record_key(task_id: &str, task_revision: u64) -> RecoveryRecordKey {
    let identity = canonical_json_bytes(&(task_id, task_revision))
        .unwrap_or_else(|_| panic!("(&str, u64) is always canonically encodable"));
    RecoveryRecordKey::new(
        TASK_CONTRACT_ACCEPTANCE_RECORD_NAMESPACE,
        format!("acceptance_{}", sha256_hex(&identity)),
    )
    .unwrap_or_else(|_| panic!("derived task-contract acceptance key is always well formed"))
}

/// Builds the closed named mutation that persists one owner acceptance-set
/// record.
///
/// The record travels as the single `record` parameter, the same shape the
/// other owner-record writes use, so no second parameter encoding is introduced.
///
/// The builder borrows rather than takes the record: it validates the record and
/// serializes it into the request's owned `record` parameter, and the returned
/// `NamedMutationRequest` carries those closed bytes, not the record itself. No
/// field of the record is stored into the request by move, so consuming the
/// owner's record here would only strip the owner of a value the store never
/// mutates. The request is therefore built from exactly the bytes the record
/// was validated against.
pub fn task_contract_acceptance_record_request(
    record: &TaskContractAcceptanceRecord,
) -> Result<NamedMutationRequest, StoreError> {
    record.validate()?;
    let parameters = BTreeMap::from([(
        "record".to_owned(),
        serde_json::to_value(record)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    )]);
    Ok(NamedMutationRequest {
        operation: NamedMutationOperation::RecordTaskContractAcceptanceSet,
        parameters,
    })
}

/// Decodes and validates one owner acceptance-set record from a closed mutation
/// parameter map.
///
/// The presented operation must be this exact mutation and the parameters must
/// satisfy the owner-approved typed declaration, so a record cannot be smuggled
/// in under another operation or with extra fields. The returned record is
/// validated, never repaired.
pub fn decode_task_contract_acceptance_record(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<TaskContractAcceptanceRecord, StoreError> {
    if operation != NamedMutationOperation::RecordTaskContractAcceptanceSet {
        return Err(StoreError::UnknownOperation);
    }
    crate::operation_parameters::validate_typed_mutation_parameters(operation, parameters)?;
    let record: TaskContractAcceptanceRecord =
        serde_json::from_value(parameters.get("record").cloned().ok_or(
            StoreError::InvalidField {
                field: "task_contract_acceptance.record",
                reason: "is required",
            },
        )?)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    record.validate()?;
    Ok(record)
}

/// Validates the exact owner identity text carried by one durable address.
///
/// A read is refused rather than repaired when the selected row is not this
/// task's row, so a digest collision or a stale row can never answer for a
/// different task.
pub fn validate_acceptance_record_identity(
    task_id: &str,
    task_revision: u64,
) -> Result<(), StoreError> {
    validate_text(task_id, "task_contract_acceptance.task_id")?;
    if task_revision == 0 {
        return Err(StoreError::InvalidField {
            field: "task_contract_acceptance.task_revision",
            reason: "must be a non-zero task revision",
        });
    }
    Ok(())
}
