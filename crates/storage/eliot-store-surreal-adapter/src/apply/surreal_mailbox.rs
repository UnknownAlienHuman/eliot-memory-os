//! Durable Surreal transaction legs for Kernel-admitted mailbox delivery.
//!
//! Admission arbitrates per-stream ordering through a compare-and-set on the
//! stream head and converges identical message-identity replays; delivery,
//! acknowledgement, and expiry legs advance the exact expected message head.
//! All rows reuse the existing recovery-owner table, so no new table and no
//! migration chain is introduced.

use std::fmt::Write as _;

use eliot_store_api::{
    MAILBOX_ITEM_SCHEMA_V1, MAILBOX_STREAM_HEAD_SCHEMA_V1, MailboxItemRecord, MailboxStreamHead,
    NamedMutationOperation, PreparedTransition, RecoveryRecord, RecoveryRecordKey, StoreError,
    TransitionClass, canonical_json_bytes, decode_mailbox_ack, decode_mailbox_delivery,
    decode_mailbox_expiry, decode_mailbox_item, sha256_hex,
};
use serde_json::{Map, Value, json};

use crate::error::AdapterError;
use crate::schema;

const REVISION_CONFLICT: &str = "mailbox_item_conflict";
const ITEM_NAMESPACE: &str = "mailbox-item-v1";
const HEAD_NAMESPACE: &str = "mailbox-item-head-v1";
const STREAM_NAMESPACE: &str = "mailbox-stream-head-v1";

fn is_mailbox_operation(operation: NamedMutationOperation) -> bool {
    matches!(
        operation,
        NamedMutationOperation::AdmitMailboxItem
            | NamedMutationOperation::RecordMailboxDelivery
            | NamedMutationOperation::AcknowledgeMailboxItem
            | NamedMutationOperation::ExpireMailboxItem
    )
}

/// Renders admitted mailbox legs into the caller's canonical transaction.
pub(crate) fn mailbox_statements(
    transition: &PreparedTransition,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let mut matching = transition
        .named_operations
        .iter()
        .filter(|command| is_mailbox_operation(command.operation));
    let Some(command) = matching.next() else {
        return Ok((String::new(), Map::new()));
    };
    if matching.next().is_some() {
        return Err(AdapterError::Store(StoreError::Duplicate {
            field: "mailbox.named_operations",
        }));
    }
    if transition.transition_class != TransitionClass::CaptureCandidate {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    match command.operation {
        NamedMutationOperation::AdmitMailboxItem => {
            let revision = decode_mailbox_item(command.operation, &command.parameters)
                .map_err(AdapterError::Store)?;
            if revision.record.state_fence != transition.state_fence {
                return Err(AdapterError::Store(StoreError::FenceMismatch));
            }
            if transition.task_id.as_deref() != Some(revision.record.task_id.as_str()) {
                return Err(AdapterError::Store(StoreError::InvalidField {
                    field: "mailbox.task_id",
                    reason: "must match the prepared transition task",
                }));
            }
            admission_write(&revision.record, revision.expected_predecessor.as_ref())
        }
        NamedMutationOperation::RecordMailboxDelivery => {
            let advance = decode_mailbox_delivery(command.operation, &command.parameters)
                .map_err(AdapterError::Store)?;
            check_advance_binding(transition, advance.task_id.as_str(), &advance.expected_head)?;
            let next = advance.applied_head().map_err(AdapterError::Store)?;
            advance_write(&advance.expected_head, &next)
        }
        NamedMutationOperation::AcknowledgeMailboxItem => {
            let advance = decode_mailbox_ack(command.operation, &command.parameters)
                .map_err(AdapterError::Store)?;
            check_advance_binding(transition, advance.task_id.as_str(), &advance.expected_head)?;
            let next = advance.applied_head().map_err(AdapterError::Store)?;
            advance_write(&advance.expected_head, &next)
        }
        NamedMutationOperation::ExpireMailboxItem => {
            let advance = decode_mailbox_expiry(command.operation, &command.parameters)
                .map_err(AdapterError::Store)?;
            check_advance_binding(transition, advance.task_id.as_str(), &advance.expected_head)?;
            let next = advance.applied_head().map_err(AdapterError::Store)?;
            advance_write(&advance.expected_head, &next)
        }
        _ => Err(AdapterError::Store(StoreError::UnknownOperation)),
    }
}

fn check_advance_binding(
    transition: &PreparedTransition,
    task_id: &str,
    expected_head: &MailboxItemRecord,
) -> Result<(), AdapterError> {
    if expected_head.state_fence != transition.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    if transition.task_id.as_deref() != Some(task_id) {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "mailbox.task_id",
            reason: "must match the prepared transition task",
        }));
    }
    Ok(())
}

fn admission_write(
    record: &MailboxItemRecord,
    predecessor: Option<&MailboxItemRecord>,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let task_id = record.task_id.to_string();
    let record_key = item_revision_key(&task_id, &record.message_id, record.revision)?;
    let head_key = item_head_key(&task_id, &record.message_id)?;
    let stream_key = stream_head_key(
        &task_id,
        &record.stream.recipient_session_id,
        &record.stream.work_item_id,
    )?;
    let record_id = recovery_owner_id(&record_key)?;
    let head_id = recovery_owner_id(&head_key)?;
    let stream_id = recovery_owner_id(&stream_key)?;
    let record_json = record
        .canonical_record_json()
        .map_err(AdapterError::Store)?;
    let digest = sha256_hex(record_json.as_bytes());
    let (expected_stream_payload, expected_stream_digest, expected_stream_fence) = match predecessor
    {
        Some(previous) => {
            let head = MailboxStreamHead {
                stream: previous.stream.clone(),
                seq: previous.stream_seq,
                message_id: previous.message_id.clone(),
            };
            let bytes = canonical_json_bytes(&head)
                .map_err(|error| AdapterError::Serialization(error.to_string()))?;
            let expected_digest = sha256_hex(&bytes);
            (bytes, expected_digest, json!(previous.state_fence))
        }
        None => (Vec::new(), String::new(), Value::Null),
    };
    let expected_seq = predecessor.map_or(0, |previous| previous.stream_seq);
    let stream_payload = stream_head_payload(record)?;
    let stream_digest = sha256_hex(&stream_payload);
    let immutable = RecoveryRecord {
        namespace: record_key.namespace.clone(),
        key: record_key.key.clone(),
        state_fence: record.state_fence.clone(),
        revision: record.revision,
        schema: MAILBOX_ITEM_SCHEMA_V1.to_owned(),
        payload: record_json.as_bytes().to_vec(),
        value_digest: digest.clone(),
    };
    let head = RecoveryRecord {
        namespace: head_key.namespace.clone(),
        key: head_key.key.clone(),
        state_fence: record.state_fence.clone(),
        revision: record.advance_seq,
        schema: MAILBOX_ITEM_SCHEMA_V1.to_owned(),
        payload: record_json.as_bytes().to_vec(),
        value_digest: digest.clone(),
    };
    let stream = RecoveryRecord {
        namespace: stream_key.namespace.clone(),
        key: stream_key.key.clone(),
        state_fence: record.state_fence.clone(),
        revision: record.stream_seq,
        schema: MAILBOX_STREAM_HEAD_SCHEMA_V1.to_owned(),
        payload: stream_payload,
        value_digest: stream_digest,
    };

    // Identical message-identity replays converge silently; divergent
    // same-identity rows and stream-ordering races abort with the mailbox
    // conflict marker so the caller retries from fresh heads.
    let mut sql = String::new();
    write!(
        sql,
        "LET $mailbox_existing = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($mailbox_table, $mailbox_head_id)); IF type::is_object($mailbox_existing) {{ IF $mailbox_existing.value_digest != $mailbox_record_digest {{ THROW '{REVISION_CONFLICT}'; }}; }} ELSE {{ LET $mailbox_stream_current = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($mailbox_table, $mailbox_stream_id)); IF $mailbox_expected_seq = 0 {{ IF type::is_object($mailbox_stream_current) {{ THROW '{REVISION_CONFLICT}'; }}; }} ELSE {{ IF !type::is_object($mailbox_stream_current) OR $mailbox_stream_current.namespace != $mailbox_stream.namespace OR $mailbox_stream_current.key != $mailbox_stream.key OR $mailbox_stream_current.revision != $mailbox_expected_seq OR $mailbox_stream_current.schema != $mailbox_stream_schema OR $mailbox_stream_current.value_digest != $mailbox_expected_stream_digest OR $mailbox_stream_current.payload != <bytes>$mailbox_expected_stream_payload OR $mailbox_stream_current.state_fence != $mailbox_expected_stream_fence {{ THROW '{REVISION_CONFLICT}'; }}; }}; LET $mailbox_record_current = (SELECT VALUE {{ namespace: namespace, key: key, revision: revision, schema: schema, value_digest: value_digest }} FROM ONLY type::record($mailbox_table, $mailbox_record_id)); IF type::is_object($mailbox_record_current) {{ THROW '{REVISION_CONFLICT}'; }} ELSE {{ CREATE type::record($mailbox_table, $mailbox_record_id) CONTENT {{ namespace: $mailbox_record.namespace, key: $mailbox_record.key, state_fence: $mailbox_record.state_fence, revision: $mailbox_record.revision, schema: $mailbox_record.schema, payload: <bytes>$mailbox_record.payload, value_digest: $mailbox_record.value_digest }}; }}; CREATE type::record($mailbox_table, $mailbox_head_id) CONTENT {{ namespace: $mailbox_head.namespace, key: $mailbox_head.key, state_fence: $mailbox_head.state_fence, revision: $mailbox_head.revision, schema: $mailbox_head.schema, payload: <bytes>$mailbox_head.payload, value_digest: $mailbox_head.value_digest }}; IF type::is_object($mailbox_stream_current) {{ LET $mailbox_stream_updated = (UPDATE type::record($mailbox_table, $mailbox_stream_id) CONTENT {{ namespace: $mailbox_stream.namespace, key: $mailbox_stream.key, state_fence: $mailbox_stream.state_fence, revision: $mailbox_stream.revision, schema: $mailbox_stream.schema, payload: <bytes>$mailbox_stream.payload, value_digest: $mailbox_stream.value_digest }} WHERE revision = $mailbox_expected_seq AND value_digest = $mailbox_expected_stream_digest AND payload = <bytes>$mailbox_expected_stream_payload AND state_fence = $mailbox_expected_stream_fence RETURN AFTER); IF array::len($mailbox_stream_updated) != 1 {{ THROW '{REVISION_CONFLICT}'; }}; }} ELSE {{ CREATE type::record($mailbox_table, $mailbox_stream_id) CONTENT {{ namespace: $mailbox_stream.namespace, key: $mailbox_stream.key, state_fence: $mailbox_stream.state_fence, revision: $mailbox_stream.revision, schema: $mailbox_stream.schema, payload: <bytes>$mailbox_stream.payload, value_digest: $mailbox_stream.value_digest }}; }}; }};"
    )
    .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let bindings = Map::from_iter([
        (
            "mailbox_table".to_owned(),
            json!(schema::table::RECOVERY_OWNER),
        ),
        ("mailbox_record_id".to_owned(), json!(record_id)),
        ("mailbox_head_id".to_owned(), json!(head_id)),
        ("mailbox_stream_id".to_owned(), json!(stream_id)),
        ("mailbox_expected_seq".to_owned(), json!(expected_seq)),
        ("mailbox_record_digest".to_owned(), json!(digest)),
        (
            "mailbox_expected_stream_payload".to_owned(),
            json!(expected_stream_payload),
        ),
        (
            "mailbox_expected_stream_digest".to_owned(),
            json!(expected_stream_digest),
        ),
        (
            "mailbox_expected_stream_fence".to_owned(),
            expected_stream_fence,
        ),
        (
            "mailbox_stream_schema".to_owned(),
            json!(MAILBOX_STREAM_HEAD_SCHEMA_V1),
        ),
        ("mailbox_record".to_owned(), json!(immutable)),
        ("mailbox_head".to_owned(), json!(head)),
        ("mailbox_stream".to_owned(), json!(stream)),
    ]);
    Ok((sql, bindings))
}

fn advance_write(
    expected: &MailboxItemRecord,
    next: &MailboxItemRecord,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let task_id = expected.task_id.to_string();
    let head_key = item_head_key(&task_id, &expected.message_id)?;
    let head_id = recovery_owner_id(&head_key)?;
    let expected_json = expected
        .canonical_record_json()
        .map_err(AdapterError::Store)?;
    let expected_digest = sha256_hex(expected_json.as_bytes());
    let next_json = next.canonical_record_json().map_err(AdapterError::Store)?;
    let next_digest = sha256_hex(next_json.as_bytes());
    let head = RecoveryRecord {
        namespace: head_key.namespace.clone(),
        key: head_key.key.clone(),
        state_fence: next.state_fence.clone(),
        revision: next.advance_seq,
        schema: MAILBOX_ITEM_SCHEMA_V1.to_owned(),
        payload: next_json.as_bytes().to_vec(),
        value_digest: next_digest,
    };

    // The head must still be exactly the expected bytes; a converged
    // replay (identical successor) verifies without writing, every other
    // advance compare-and-sets the head forward.
    let mut sql = String::new();
    if expected_json == next_json {
        write!(
            sql,
            "LET $mailbox_head_current = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($mailbox_table, $mailbox_head_id)); IF !type::is_object($mailbox_head_current) OR $mailbox_head_current.namespace != $mailbox_head.namespace OR $mailbox_head_current.key != $mailbox_head.key OR $mailbox_head_current.revision != $mailbox_expected_advance OR $mailbox_head_current.schema != $mailbox_item_schema OR $mailbox_head_current.value_digest != $mailbox_expected_digest OR $mailbox_head_current.payload != <bytes>$mailbox_expected_payload OR $mailbox_head_current.state_fence != $mailbox_expected_fence {{ THROW '{REVISION_CONFLICT}'; }};"
        )
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    } else {
        write!(
            sql,
            "LET $mailbox_head_current = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($mailbox_table, $mailbox_head_id)); IF !type::is_object($mailbox_head_current) OR $mailbox_head_current.namespace != $mailbox_head.namespace OR $mailbox_head_current.key != $mailbox_head.key OR $mailbox_head_current.revision != $mailbox_expected_advance OR $mailbox_head_current.schema != $mailbox_item_schema OR $mailbox_head_current.value_digest != $mailbox_expected_digest OR $mailbox_head_current.payload != <bytes>$mailbox_expected_payload OR $mailbox_head_current.state_fence != $mailbox_expected_fence {{ THROW '{REVISION_CONFLICT}'; }}; LET $mailbox_head_updated = (UPDATE type::record($mailbox_table, $mailbox_head_id) CONTENT {{ namespace: $mailbox_head.namespace, key: $mailbox_head.key, state_fence: $mailbox_head.state_fence, revision: $mailbox_head.revision, schema: $mailbox_head.schema, payload: <bytes>$mailbox_head.payload, value_digest: $mailbox_head.value_digest }} WHERE revision = $mailbox_expected_advance AND value_digest = $mailbox_expected_digest AND payload = <bytes>$mailbox_expected_payload AND state_fence = $mailbox_expected_fence RETURN AFTER); IF array::len($mailbox_head_updated) != 1 {{ THROW '{REVISION_CONFLICT}'; }};"
        )
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    }
    let bindings = Map::from_iter([
        (
            "mailbox_table".to_owned(),
            json!(schema::table::RECOVERY_OWNER),
        ),
        ("mailbox_head_id".to_owned(), json!(head_id)),
        (
            "mailbox_expected_advance".to_owned(),
            json!(expected.advance_seq),
        ),
        (
            "mailbox_expected_payload".to_owned(),
            json!(expected_json.as_bytes()),
        ),
        ("mailbox_expected_digest".to_owned(), json!(expected_digest)),
        (
            "mailbox_expected_fence".to_owned(),
            json!(expected.state_fence),
        ),
        (
            "mailbox_item_schema".to_owned(),
            json!(MAILBOX_ITEM_SCHEMA_V1),
        ),
        ("mailbox_head".to_owned(), json!(head)),
    ]);
    Ok((sql, bindings))
}

fn stream_head_payload(record: &MailboxItemRecord) -> Result<Vec<u8>, AdapterError> {
    let head = MailboxStreamHead {
        stream: record.stream.clone(),
        seq: record.stream_seq,
        message_id: record.message_id.clone(),
    };
    canonical_json_bytes(&head).map_err(|error| AdapterError::Serialization(error.to_string()))
}

/// Deterministic key for one immutable task/message/revision record.
pub(crate) fn item_revision_key(
    task_id: &str,
    message_id: &str,
    revision: u64,
) -> Result<RecoveryRecordKey, AdapterError> {
    let identity = canonical_json_bytes(&(task_id, message_id, revision))
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    RecoveryRecordKey::new(ITEM_NAMESPACE, format!("item_{}", sha256_hex(&identity)))
        .map_err(AdapterError::Store)
}

/// Deterministic key for the mutable task/message delivery head.
pub(crate) fn item_head_key(
    task_id: &str,
    message_id: &str,
) -> Result<RecoveryRecordKey, AdapterError> {
    let identity = canonical_json_bytes(&(task_id, message_id))
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    RecoveryRecordKey::new(HEAD_NAMESPACE, format!("head_{}", sha256_hex(&identity)))
        .map_err(AdapterError::Store)
}

/// Deterministic key for the mutable per-stream ordering head.
pub(crate) fn stream_head_key(
    task_id: &str,
    recipient_session_id: &str,
    work_item_id: &str,
) -> Result<RecoveryRecordKey, AdapterError> {
    let identity = canonical_json_bytes(&(task_id, recipient_session_id, work_item_id))
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    RecoveryRecordKey::new(
        STREAM_NAMESPACE,
        format!("stream_{}", sha256_hex(&identity)),
    )
    .map_err(AdapterError::Store)
}

pub(crate) fn recovery_owner_id(key: &RecoveryRecordKey) -> Result<String, AdapterError> {
    let bytes = canonical_json_bytes(key)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}
