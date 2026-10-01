//! Atomic persistence of selected-source ProposedAttempt owner records.

use std::fmt::Write as _;

use eliot_store_api::{
    NamedMutationOperation, PreparedTransition, RecoveryRecord, StoreError,
    decode_proposed_attempt_record, sha256_hex,
};
use serde_json::{Map, json};

use crate::error::AdapterError;
use crate::schema;

const IDENTITY_CONFLICT: &str = "proposed_attempt_identity_conflict";

pub(crate) fn proposed_attempt_statements(
    transition: &PreparedTransition,
) -> Result<(String, Map<String, serde_json::Value>), AdapterError> {
    let mut matching = transition.named_operations.iter().filter(|command| {
        command.operation == NamedMutationOperation::AdmitProposedAttempt
    });
    let Some(command) = matching.next() else {
        return Ok((String::new(), Map::new()));
    };
    if matching.next().is_some() {
        return Err(AdapterError::Store(StoreError::Duplicate {
            field: "proposed_attempt.named_operations",
        }));
    }
    if transition.transition_class != eliot_store_api::TransitionClass::TaskControl {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let record = decode_proposed_attempt_record(command.operation, &command.parameters)
        .map_err(AdapterError::Store)?;
    if record.state_fence != transition.state_fence
        || transition.task_id.as_deref() != Some(record.task_id.as_str())
    {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    let key = record.record_key();
    let record_id = super::surreal_blackboard::recovery_owner_id(&key)?;
    let payload = record
        .canonical_record_json()
        .map_err(AdapterError::Store)?
        .into_bytes();
    let recovery = RecoveryRecord {
        namespace: key.namespace,
        key: key.key,
        state_fence: record.state_fence.clone(),
        revision: 1,
        schema: eliot_store_api::PROPOSED_ATTEMPT_RECORD_SCHEMA_V1.to_owned(),
        value_digest: sha256_hex(&payload),
        payload,
    };
    recovery.validate().map_err(AdapterError::Store)?;

    let mut sql = String::new();
    write!(
        sql,
        "LET $proposed_attempt_current = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($proposed_attempt_table, $proposed_attempt_id)); IF type::is_object($proposed_attempt_current) {{ THROW '{IDENTITY_CONFLICT}'; }} ELSE {{ CREATE type::record($proposed_attempt_table, $proposed_attempt_id) CONTENT {{ namespace: $proposed_attempt.namespace, key: $proposed_attempt.key, state_fence: $proposed_attempt.state_fence, revision: $proposed_attempt.revision, schema: $proposed_attempt.schema, payload: <bytes>$proposed_attempt.payload, value_digest: $proposed_attempt.value_digest }}; }};"
    )
    .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let bindings = Map::from_iter([
        (
            "proposed_attempt_table".to_owned(),
            json!(schema::table::RECOVERY_OWNER),
        ),
        ("proposed_attempt_id".to_owned(), json!(record_id)),
        ("proposed_attempt".to_owned(), json!(recovery)),
    ]);
    Ok((sql, bindings))
}
