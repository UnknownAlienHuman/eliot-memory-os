//! Durable Surreal row for the Governor-owned canonical work ADMITTED record
//! (#1678, I14.6/I10.15).
//!
//! The record and canonical receipt are appended to one prepared store
//! transaction. The adapter persists the owner record verbatim, arbitrates a
//! create-only `(work_id, proposed_attempt_id)` key, and does not interpret
//! claim references or derive work semantics.

use std::fmt::Write as _;

use eliot_store_api::{
    NamedMutationOperation, PreparedTransition, RecoveryRecord, RecoveryRecordKey,
    WORK_ADMISSION_RECORD_NAMESPACE, WORK_ADMISSION_SCHEMA_V1, WorkAdmissionRecord,
    StoreError, canonical_json_bytes, decode_work_admission_record, sha256_hex,
    validate_work_admission_owner_cas, validate_work_admission_transition,
};
use serde_json::{Map, Value, json};

use crate::error::AdapterError;
use crate::schema;

const EXISTING_RECORD: &str = "work_admission_already_exists";

/// Renders the single typed work-admission row into its canonical write.
///
/// An unrelated transition receives an empty fragment. A malformed or
/// mismatched admission refuses before provider I/O.
pub(crate) fn work_admission_statements(
    transition: &PreparedTransition,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let mut matching = transition
        .named_operations
        .iter()
        .filter(|command| command.operation == NamedMutationOperation::AdmitWork);
    let Some(command) = matching.next() else {
        return Ok((String::new(), Map::new()));
    };
    if matching.next().is_some() {
        return Err(AdapterError::Store(StoreError::Duplicate {
            field: "work_admission.named_operations",
        }));
    }
    validate_work_admission_transition(transition).map_err(AdapterError::Store)?;
    let record = decode_work_admission_record(&command.parameters).map_err(AdapterError::Store)?;
    if transition.task_id.as_deref() != Some(record.task_id.as_str()) {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "work_admission.task_id",
            reason: "must match the prepared transition task",
        }));
    }
    let (mut sql, mut bindings) = record_write(&record)?;
    validate_work_admission_owner_cas(&record, &command.parameters)
        .map_err(AdapterError::Store)?;
    let expected_revision = command.parameters["expected_canonical_revision"]
        .as_str()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "work_admission.expected_canonical_revision",
            reason: "must be the original canonical-owner predecessor",
        }))?;
    let snapshot_json = command.parameters["canonical_owner_snapshot_json"]
        .as_str()
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "work_admission.canonical_owner_snapshot_json",
            reason: "must be the proposed canonical-owner snapshot",
        }))?;
    let canonical_key = RecoveryRecordKey::new("owner", "canonical")
        .map_err(AdapterError::Store)?;
    let canonical_id = crate::apply::surreal_blackboard::recovery_owner_id(&canonical_key)?;
    let canonical_payload = snapshot_json.as_bytes();
    let canonical_revision = expected_revision.checked_add(1).ok_or(
        AdapterError::Store(StoreError::InvalidField {
            field: "work_admission.expected_canonical_revision",
            reason: "canonical owner revision overflow",
        }),
    )?;
    let canonical_record = RecoveryRecord {
        namespace: canonical_key.namespace,
        key: canonical_key.key,
        state_fence: record.state_fence.clone(),
        revision: canonical_revision,
        schema: eliot_store_api::OWNER_SNAPSHOT_SCHEMA.to_owned(),
        value_digest: sha256_hex(canonical_payload),
        payload: canonical_payload.to_vec(),
    };
    sql.push_str(schema::TX_CANONICAL_OWNER);
    bindings.insert(
        "canonical_owner_table".to_owned(),
        json!(schema::table::RECOVERY_OWNER),
    );
    bindings.insert("canonical_owner_id".to_owned(), json!(canonical_id));
    bindings.insert(
        "canonical_expected_state_fence".to_owned(),
        json!(&record.state_fence),
    );
    bindings.insert(
        "canonical_expected_revision".to_owned(),
        json!(expected_revision),
    );
    bindings.insert(
        "canonical_owner_record".to_owned(),
        json!(canonical_record),
    );
    Ok((sql, bindings))
}

fn record_write(
    record: &WorkAdmissionRecord,
) -> Result<(String, Map<String, Value>), AdapterError> {
    record.validate().map_err(AdapterError::Store)?;
    let key = RecoveryRecordKey::new(
        WORK_ADMISSION_RECORD_NAMESPACE,
        record.record_key(),
    )
    .map_err(AdapterError::Store)?;
    let record_id = crate::apply::surreal_blackboard::recovery_owner_id(&key)?;
    let payload = canonical_json_bytes(record)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let row = RecoveryRecord {
        namespace: key.namespace.clone(),
        key: key.key.clone(),
        state_fence: record.state_fence.clone(),
        revision: 1,
        schema: WORK_ADMISSION_SCHEMA_V1.to_owned(),
        value_digest: sha256_hex(&payload),
        payload,
    };

    let mut sql = String::new();
    write!(
        sql,
        "LET $work_admission_current = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($work_admission_table, $work_admission_id)); IF type::is_object($work_admission_current) {{ THROW '{EXISTING_RECORD}'; }} ELSE {{ CREATE type::record($work_admission_table, $work_admission_id) CONTENT {{ namespace: $work_admission_record.namespace, key: $work_admission_record.key, state_fence: $work_admission_record.state_fence, revision: $work_admission_record.revision, schema: $work_admission_record.schema, payload: <bytes>$work_admission_record.payload, value_digest: $work_admission_record.value_digest }}; }};"
    )
    .map_err(|error| AdapterError::Serialization(error.to_string()))?;

    let bindings = Map::from_iter([
        (
            "work_admission_table".to_owned(),
            json!(schema::table::RECOVERY_OWNER),
        ),
        ("work_admission_id".to_owned(), json!(record_id)),
        ("work_admission_record".to_owned(), json!(row)),
    ]);
    Ok((sql, bindings))
}

#[cfg(test)]
#[path = "work_admission_tests.rs"]
mod tests;
