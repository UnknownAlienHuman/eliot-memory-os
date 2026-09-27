//! Durable Surreal transaction leg for Kernel-admitted blackboard items.

use std::fmt::Write as _;

use eliot_store_api::{
    BLACKBOARD_ITEM_SCHEMA_V1, BlackboardItemRevision, NamedMutationOperation, PreparedTransition,
    RecoveryRecord, RecoveryRecordKey, StoreError, canonical_json_bytes, decode_blackboard_item,
    sha256_hex,
};
use serde_json::{Map, Value, json};

use crate::error::AdapterError;
use crate::schema;

const REVISION_CONFLICT: &str = "blackboard_item_revision_conflict";
const ITEM_NAMESPACE: &str = "blackboard-item-v1";
const HEAD_NAMESPACE: &str = "blackboard-item-head-v1";

/// Renders one admitted item revision into the caller's canonical transaction.
pub(crate) fn blackboard_item_statements(
    transition: &PreparedTransition,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let mut matching = transition
        .named_operations
        .iter()
        .filter(|command| command.operation == NamedMutationOperation::ApplyBlackboardItem);
    let Some(command) = matching.next() else {
        return Ok((String::new(), Map::new()));
    };
    if matching.next().is_some() {
        return Err(AdapterError::Store(StoreError::Duplicate {
            field: "blackboard.named_operations",
        }));
    }
    if transition.transition_class != eliot_store_api::TransitionClass::CaptureCandidate {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let revision = decode_blackboard_item(command.operation, &command.parameters)
        .map_err(AdapterError::Store)?;
    if revision.record.state_fence != transition.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    if transition.task_id.as_deref() != Some(revision.record.task_id.as_str()) {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "blackboard.task_id",
            reason: "must match the prepared transition task",
        }));
    }
    let (statement, bindings) = revision_write(&revision)?;
    Ok((statement, bindings))
}

fn revision_write(
    revision: &BlackboardItemRevision,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let record = &revision.record;
    let record_key = item_revision_key(
        &record.task_id.to_string(),
        &record.item_id,
        record.revision,
    )?;
    let head_key = item_head_key(&record.task_id.to_string(), &record.item_id)?;
    let expected = revision
        .expected_predecessor
        .as_ref()
        .map_or(0, |predecessor| predecessor.revision);
    let previous_key = item_revision_key(&record.task_id.to_string(), &record.item_id, expected)?;
    let record_id = recovery_owner_id(&record_key)?;
    let head_id = recovery_owner_id(&head_key)?;
    let previous_id = recovery_owner_id(&previous_key)?;
    let record_json = revision
        .canonical_record_json()
        .map_err(AdapterError::Store)?;
    let payload = record_json.as_bytes();
    let digest = sha256_hex(payload);
    let (expected_previous_payload, expected_previous_digest, expected_previous_state_fence) =
        if let Some(predecessor) = &revision.expected_predecessor {
            let bytes = canonical_json_bytes(predecessor)
                .map_err(|error| AdapterError::Serialization(error.to_string()))?;
            let digest = sha256_hex(&bytes);
            (bytes, digest, json!(predecessor.state_fence))
        } else {
            (Vec::new(), String::new(), Value::Null)
        };
    let immutable = RecoveryRecord {
        namespace: record_key.namespace.clone(),
        key: record_key.key.clone(),
        state_fence: record.state_fence.clone(),
        revision: record.revision,
        schema: BLACKBOARD_ITEM_SCHEMA_V1.to_owned(),
        payload: payload.to_vec(),
        value_digest: digest.clone(),
    };
    let head = RecoveryRecord {
        namespace: head_key.namespace.clone(),
        key: head_key.key.clone(),
        state_fence: record.state_fence.clone(),
        revision: record.revision,
        schema: BLACKBOARD_ITEM_SCHEMA_V1.to_owned(),
        payload: payload.to_vec(),
        value_digest: digest,
    };

    let mut sql = String::new();
    write!(
        sql,
        "LET $blackboard_previous = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($blackboard_table, $blackboard_previous_id)); LET $blackboard_head_current = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($blackboard_table, $blackboard_head_id)); IF $blackboard_expected_revision = 0 {{ IF type::is_object($blackboard_previous) OR type::is_object($blackboard_head_current) {{ THROW '{REVISION_CONFLICT}'; }}; }} ELSE {{ IF !type::is_object($blackboard_previous) OR !type::is_object($blackboard_head_current) OR $blackboard_previous.namespace != $blackboard_record.namespace OR $blackboard_previous.key != $blackboard_previous_key OR $blackboard_previous.revision != $blackboard_expected_revision OR $blackboard_previous.schema != $blackboard_record.schema OR $blackboard_previous.value_digest != $blackboard_expected_previous_digest OR $blackboard_previous.payload != <bytes>$blackboard_expected_previous_payload OR $blackboard_previous.state_fence != $blackboard_expected_previous_state_fence OR $blackboard_head_current.namespace != $blackboard_head.namespace OR $blackboard_head_current.key != $blackboard_head.key OR $blackboard_head_current.revision != $blackboard_expected_revision OR $blackboard_head_current.schema != $blackboard_head.schema OR $blackboard_head_current.value_digest != $blackboard_expected_previous_digest OR $blackboard_head_current.payload != <bytes>$blackboard_expected_previous_payload OR $blackboard_head_current.state_fence != $blackboard_expected_previous_state_fence OR $blackboard_head_current.value_digest != $blackboard_previous.value_digest OR $blackboard_head_current.payload != $blackboard_previous.payload OR $blackboard_head_current.state_fence != $blackboard_previous.state_fence {{ THROW '{REVISION_CONFLICT}'; }}; }}; LET $blackboard_record_current = (SELECT VALUE {{ namespace: namespace, key: key, revision: revision, schema: schema, value_digest: value_digest }} FROM ONLY type::record($blackboard_table, $blackboard_record_id)); IF type::is_object($blackboard_record_current) {{ THROW '{REVISION_CONFLICT}'; }} ELSE {{ CREATE type::record($blackboard_table, $blackboard_record_id) CONTENT {{ namespace: $blackboard_record.namespace, key: $blackboard_record.key, state_fence: $blackboard_record.state_fence, revision: $blackboard_record.revision, schema: $blackboard_record.schema, payload: <bytes>$blackboard_record.payload, value_digest: $blackboard_record.value_digest }}; }}; IF type::is_object($blackboard_head_current) {{ LET $blackboard_head_updated = (UPDATE type::record($blackboard_table, $blackboard_head_id) CONTENT {{ namespace: $blackboard_head.namespace, key: $blackboard_head.key, state_fence: $blackboard_head.state_fence, revision: $blackboard_head.revision, schema: $blackboard_head.schema, payload: <bytes>$blackboard_head.payload, value_digest: $blackboard_head.value_digest }} WHERE revision = $blackboard_expected_revision AND value_digest = $blackboard_expected_previous_digest AND payload = <bytes>$blackboard_expected_previous_payload AND state_fence = $blackboard_expected_previous_state_fence RETURN AFTER); IF array::len($blackboard_head_updated) != 1 {{ THROW '{REVISION_CONFLICT}'; }}; }} ELSE {{ IF $blackboard_expected_revision != 0 {{ THROW '{REVISION_CONFLICT}'; }} ELSE {{ CREATE type::record($blackboard_table, $blackboard_head_id) CONTENT {{ namespace: $blackboard_head.namespace, key: $blackboard_head.key, state_fence: $blackboard_head.state_fence, revision: $blackboard_head.revision, schema: $blackboard_head.schema, payload: <bytes>$blackboard_head.payload, value_digest: $blackboard_head.value_digest }}; }}; }};"
    )
    .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let bindings = Map::from_iter([
        (
            "blackboard_table".to_owned(),
            json!(schema::table::RECOVERY_OWNER),
        ),
        ("blackboard_record_id".to_owned(), json!(record_id)),
        ("blackboard_head_id".to_owned(), json!(head_id)),
        ("blackboard_previous_id".to_owned(), json!(previous_id)),
        (
            "blackboard_previous_key".to_owned(),
            json!(previous_key.key),
        ),
        ("blackboard_expected_revision".to_owned(), json!(expected)),
        (
            "blackboard_expected_previous_payload".to_owned(),
            json!(expected_previous_payload),
        ),
        (
            "blackboard_expected_previous_digest".to_owned(),
            json!(expected_previous_digest),
        ),
        (
            "blackboard_expected_previous_state_fence".to_owned(),
            expected_previous_state_fence,
        ),
        ("blackboard_record".to_owned(), json!(immutable)),
        ("blackboard_head".to_owned(), json!(head)),
    ]);
    Ok((sql, bindings))
}

/// Deterministic key for one immutable task/item/revision record.
pub(crate) fn item_revision_key(
    task_id: &str,
    item_id: &str,
    revision: u64,
) -> Result<RecoveryRecordKey, AdapterError> {
    let identity = canonical_json_bytes(&(task_id, item_id, revision))
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    RecoveryRecordKey::new(ITEM_NAMESPACE, format!("item_{}", sha256_hex(&identity)))
        .map_err(AdapterError::Store)
}

/// Deterministic key for the mutable task/item revision head.
pub(crate) fn item_head_key(
    task_id: &str,
    item_id: &str,
) -> Result<RecoveryRecordKey, AdapterError> {
    let identity = canonical_json_bytes(&(task_id, item_id))
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    RecoveryRecordKey::new(HEAD_NAMESPACE, format!("head_{}", sha256_hex(&identity)))
        .map_err(AdapterError::Store)
}

pub(crate) fn recovery_owner_id(key: &RecoveryRecordKey) -> Result<String, AdapterError> {
    let bytes = canonical_json_bytes(key)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}
