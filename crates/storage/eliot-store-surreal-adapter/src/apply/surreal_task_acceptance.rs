//! Durable Surreal transaction leg for the owner-issued `TaskContract`
//! acceptance-set record (issue #325 P1, I7.9).
//!
//! I7.9 requires the Finish service to rehydrate the current `TaskContract`
//! and its acceptance items. A plan's declared test list is not that
//! enumeration, so the set has to be a durable record of the owner that holds
//! the contract. This leg persists exactly that record and nothing else: the
//! create-only row, its payload bytes and the canonical receipt commit in the
//! same prepared transaction as every other owner row.
//!
//! The row lives in its own namespace of the existing `recovery_owner` table,
//! the same mechanism the blackboard item record (issue #1822) and the
//! capability-evidence record (issue #1773) use, so this adds no table and no
//! second durable identity scheme. It is addressed by `(task_id,
//! task_revision)`, which is what makes the paired
//! `GetTaskContractAcceptanceSet` read a point lookup at one exact contract
//! revision instead of a scan for "whatever is current".
//!
//! The row is create-only. A second commit for the same `(task_id,
//! task_revision)` is refused rather than overwritten, so the owner cannot
//! narrow or widen the obligation set a finish decision is later rehydrated
//! against; issuing a different set means a new task revision, which is the
//! same precondition I5.5 already states for task-bound writes.
//!
//! The governed adapter classifies the legacy `task_contract` table as
//! `LegacyTableDisposition::ArchiveOnly`, so it is archived away during legacy
//! migration rather than adopted; reading it is not available and this leg does
//! not depend on it.

use std::fmt::Write as _;

use eliot_store_api::{
    NamedMutationOperation, PreparedTransition, RecoveryRecord, StoreError,
    TASK_CONTRACT_ACCEPTANCE_RECORD_NAMESPACE, TASK_CONTRACT_ACCEPTANCE_RECORD_SCHEMA_V1,
    TaskContractAcceptanceRecord, decode_task_contract_acceptance_record, sha256_hex,
};
use serde_json::{Map, Value, json};

use crate::error::AdapterError;
use crate::schema;

const REVISION_CONFLICT: &str = "task_contract_acceptance_revision_conflict";

/// Renders one admitted owner acceptance-set record into the caller's canonical
/// transaction.
///
/// Returns an empty fragment when the transition names no such operation, so a
/// transition for another owner writes exactly the rows it declared.
pub(crate) fn task_contract_acceptance_statements(
    transition: &PreparedTransition,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let mut matching = transition
        .named_operations
        .iter()
        .filter(|command| {
            command.operation == NamedMutationOperation::RecordTaskContractAcceptanceSet
        });
    let Some(command) = matching.next() else {
        return Ok((String::new(), Map::new()));
    };
    if matching.next().is_some() {
        return Err(AdapterError::Store(StoreError::Duplicate {
            field: "task_contract_acceptance.named_operations",
        }));
    }
    if transition.transition_class != eliot_store_api::TransitionClass::TaskControl {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let record = decode_task_contract_acceptance_record(command.operation, &command.parameters)
        .map_err(AdapterError::Store)?;
    // Defence in depth beside the catalogue gate: the durable row and the
    // receipt must describe one task at one live fence, and a record carrying
    // another task's identity never reaches the provider at all.
    if record.state_fence != transition.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    if transition.task_id.as_deref() != Some(record.task_id.as_str()) {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "task_contract_acceptance.task_id",
            reason: "must match the prepared transition task",
        }));
    }
    record_write(&record)
}

fn record_write(
    record: &TaskContractAcceptanceRecord,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let key = record.record_key();
    let record_id = super::surreal_blackboard::recovery_owner_id(&key)?;
    let record_json = record.canonical_record_json().map_err(AdapterError::Store)?;
    let row = RecoveryRecord {
        namespace: TASK_CONTRACT_ACCEPTANCE_RECORD_NAMESPACE.to_owned(),
        key: key.key.clone(),
        state_fence: record.state_fence.clone(),
        // The durable row revision IS the contract revision the owner issued
        // the set for. It is not a store sequence: the read asks for one exact
        // contract revision, so the row must answer at that revision or not at
        // all.
        revision: record.task_revision,
        schema: TASK_CONTRACT_ACCEPTANCE_RECORD_SCHEMA_V1.to_owned(),
        payload: record_json.as_bytes().to_vec(),
        value_digest: sha256_hex(record_json.as_bytes()),
    };

    let mut sql = String::new();
    write!(
        sql,
        "LET $acceptance_record_current = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($acceptance_table, $acceptance_record_id)); IF type::is_object($acceptance_record_current) {{ THROW '{REVISION_CONFLICT}'; }} ELSE {{ CREATE type::record($acceptance_table, $acceptance_record_id) CONTENT {{ namespace: $acceptance_record.namespace, key: $acceptance_record.key, state_fence: $acceptance_record.state_fence, revision: $acceptance_record.revision, schema: $acceptance_record.schema, payload: <bytes>$acceptance_record.payload, value_digest: $acceptance_record.value_digest }}; }};"
    )
    .map_err(|error| AdapterError::Serialization(error.to_string()))?;

    let bindings = Map::from_iter([
        (
            "acceptance_table".to_owned(),
            json!(schema::table::RECOVERY_OWNER),
        ),
        ("acceptance_record_id".to_owned(), json!(record_id)),
        ("acceptance_record".to_owned(), json!(row)),
    ]);
    Ok((sql, bindings))
}