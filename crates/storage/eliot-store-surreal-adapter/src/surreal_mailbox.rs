//! Durable Surreal transaction leg for Kernel-admitted mailbox messages.
//!
//! Mirrors the blackboard leg: one admitted message renders into the caller's
//! canonical transaction as an immutable identity row plus a stream-head
//! compare-and-set, both in the shared recovery-owner table, so no second
//! store, scheduler, table, or migration is introduced. A reused message
//! identity carrying identical bytes converges without a second row; a reused
//! identity carrying different bytes refuses with the identity marker; a stale
//! stream head refuses with the admission marker.

use std::fmt::Write as _;

use eliot_store_api::{
    MAILBOX_ITEM_SCHEMA_V1, MailboxItemAdmission, NamedMutationOperation, PreparedTransition,
    RecoveryRecord, RecoveryRecordKey, StoreError, canonical_json_bytes, decode_mailbox_item,
    sha256_hex,
};
use serde_json::{Map, Value, json};

use crate::apply::surreal_blackboard::recovery_owner_id;
use crate::error::AdapterError;
use crate::schema;

const IDENTITY_CONFLICT: &str = "mailbox_item_identity_conflict";
const ADMISSION_CONFLICT: &str = "mailbox_item_admission_conflict";
const ITEM_NAMESPACE: &str = "mailbox-item-v1";
const HEAD_NAMESPACE: &str = "mailbox-stream-head-v1";

/// Renders one admitted message into the caller's canonical transaction.
pub(crate) fn mailbox_item_statements(
    transition: &PreparedTransition,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let mut matching = transition
        .named_operations
        .iter()
        .filter(|command| command.operation == NamedMutationOperation::AdmitMailboxMessage);
    let Some(command) = matching.next() else {
        return Ok((String::new(), Map::new()));
    };
    if matching.next().is_some() {
        return Err(AdapterError::Store(StoreError::Duplicate {
            field: "mailbox.named_operations",
        }));
    }
    if transition.transition_class != eliot_store_api::TransitionClass::CaptureCandidate {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let admission = decode_mailbox_item(command.operation, &command.parameters)
        .map_err(AdapterError::Store)?;
    if admission.record.state_fence != transition.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    if transition.task_id.as_deref() != Some(admission.record.task_id.as_str()) {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "mailbox.task_id",
            reason: "must match the prepared transition task",
        }));
    }
    let (statement, bindings) = admission_write(&admission)?;
    Ok((statement, bindings))
}

fn admission_write(
    admission: &MailboxItemAdmission,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let record = &admission.record;
    let record_key = item_identity_key(&record.message_id)?;
    let head_key = stream_head_key(&record.recipient_id, &record.task_id.to_string())?;
    let expected = admission
        .expected_head
        .as_ref()
        .map_or(0, |head| head.sequence);
    let record_id = recovery_owner_id(&record_key)?;
    let head_id = recovery_owner_id(&head_key)?;
    let record_json = admission
        .canonical_record_json()
        .map_err(AdapterError::Store)?;
    let payload = record_json.as_bytes();
    let digest = sha256_hex(payload);
    let (expected_head_payload, expected_head_digest, expected_head_state_fence) =
        if let Some(head) = &admission.expected_head {
            let bytes = canonical_json_bytes(head)
                .map_err(|error| AdapterError::Serialization(error.to_string()))?;
            let digest = sha256_hex(&bytes);
            (bytes, digest, json!(head.state_fence))
        } else {
            (Vec::new(), String::new(), Value::Null)
        };
    let immutable = RecoveryRecord {
        namespace: record_key.namespace.clone(),
        key: record_key.key.clone(),
        state_fence: record.state_fence.clone(),
        revision: record.sequence,
        schema: MAILBOX_ITEM_SCHEMA_V1.to_owned(),
        payload: payload.to_vec(),
        value_digest: digest.clone(),
    };
    let head = RecoveryRecord {
        namespace: head_key.namespace.clone(),
        key: head_key.key.clone(),
        state_fence: record.state_fence.clone(),
        revision: record.sequence,
        schema: MAILBOX_ITEM_SCHEMA_V1.to_owned(),
        payload: payload.to_vec(),
        value_digest: digest,
    };

    let mut sql = String::new();
    write!(
        sql,
        "LET $mailbox_identity_current = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($mailbox_table, $mailbox_record_id)); LET $mailbox_head_current = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($mailbox_table, $mailbox_head_id)); IF type::is_object($mailbox_identity_current) {{ IF $mailbox_identity_current.namespace != $mailbox_record.namespace OR $mailbox_identity_current.key != $mailbox_record.key OR $mailbox_identity_current.revision != $mailbox_record.revision OR $mailbox_identity_current.schema != $mailbox_record.schema OR $mailbox_identity_current.value_digest != $mailbox_record.value_digest OR $mailbox_identity_current.payload != <bytes>$mailbox_record.payload OR $mailbox_identity_current.state_fence != $mailbox_record.state_fence {{ THROW '{IDENTITY_CONFLICT}'; }}; }} ELSE {{ IF $mailbox_expected_revision = 0 {{ IF type::is_object($mailbox_head_current) {{ THROW '{ADMISSION_CONFLICT}'; }}; }} ELSE {{ IF !type::is_object($mailbox_head_current) OR $mailbox_head_current.namespace != $mailbox_head.namespace OR $mailbox_head_current.key != $mailbox_head.key OR $mailbox_head_current.revision != $mailbox_expected_revision OR $mailbox_head_current.schema != $mailbox_head.schema OR $mailbox_head_current.value_digest != $mailbox_expected_head_digest OR $mailbox_head_current.payload != <bytes>$mailbox_expected_head_payload OR $mailbox_head_current.state_fence != $mailbox_expected_head_state_fence {{ THROW '{ADMISSION_CONFLICT}'; }}; }}; CREATE type::record($mailbox_table, $mailbox_record_id) CONTENT {{ namespace: $mailbox_record.namespace, key: $mailbox_record.key, state_fence: $mailbox_record.state_fence, revision: $mailbox_record.revision, schema: $mailbox_record.schema, payload: <bytes>$mailbox_record.payload, value_digest: $mailbox_record.value_digest }}; IF type::is_object($mailbox_head_current) {{ LET $mailbox_head_updated = (UPDATE type::record($mailbox_table, $mailbox_head_id) CONTENT {{ namespace: $mailbox_head.namespace, key: $mailbox_head.key, state_fence: $mailbox_head.state_fence, revision: $mailbox_head.revision, schema: $mailbox_head.schema, payload: <bytes>$mailbox_head.payload, value_digest: $mailbox_head.value_digest }} WHERE revision = $mailbox_expected_revision AND value_digest = $mailbox_expected_head_digest AND payload = <bytes>$mailbox_expected_head_payload AND state_fence = $mailbox_expected_head_state_fence RETURN AFTER); IF array::len($mailbox_head_updated) != 1 {{ THROW '{ADMISSION_CONFLICT}'; }}; }} ELSE {{ IF $mailbox_expected_revision != 0 {{ THROW '{ADMISSION_CONFLICT}'; }} ELSE {{ CREATE type::record($mailbox_table, $mailbox_head_id) CONTENT {{ namespace: $mailbox_head.namespace, key: $mailbox_head.key, state_fence: $mailbox_head.state_fence, revision: $mailbox_head.revision, schema: $mailbox_head.schema, payload: <bytes>$mailbox_head.payload, value_digest: $mailbox_head.value_digest }}; }}; }}; }};"
    )
    .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let bindings = Map::from_iter([
        (
            "mailbox_table".to_owned(),
            json!(schema::table::RECOVERY_OWNER),
        ),
        ("mailbox_record_id".to_owned(), json!(record_id)),
        ("mailbox_head_id".to_owned(), json!(head_id)),
        ("mailbox_expected_revision".to_owned(), json!(expected)),
        (
            "mailbox_expected_head_payload".to_owned(),
            json!(expected_head_payload),
        ),
        (
            "mailbox_expected_head_digest".to_owned(),
            json!(expected_head_digest),
        ),
        (
            "mailbox_expected_head_state_fence".to_owned(),
            expected_head_state_fence,
        ),
        ("mailbox_record".to_owned(), json!(immutable)),
        ("mailbox_head".to_owned(), json!(head)),
    ]);
    Ok((sql, bindings))
}

/// Deterministic key for one immutable message-identity record.
pub(crate) fn item_identity_key(message_id: &str) -> Result<RecoveryRecordKey, AdapterError> {
    let identity = canonical_json_bytes(&message_id)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    RecoveryRecordKey::new(ITEM_NAMESPACE, format!("item_{}", sha256_hex(&identity)))
        .map_err(AdapterError::Store)
}

/// Deterministic key for the mutable recipient/task stream head.
pub(crate) fn stream_head_key(
    recipient_id: &str,
    task_id: &str,
) -> Result<RecoveryRecordKey, AdapterError> {
    let identity = canonical_json_bytes(&(recipient_id, task_id))
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    RecoveryRecordKey::new(HEAD_NAMESPACE, format!("head_{}", sha256_hex(&identity)))
        .map_err(AdapterError::Store)
}
