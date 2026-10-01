//! Atomic Store row writer for process-source admission and Ready attachment.

use serde_json::{Map, Value, json};

use crate::error::AdapterError;
use crate::schema;
use eliot_store_api::{
    BLOB_PROCESS_SOURCE_ADMISSION_ROW_SCHEMA, BlobProcessSourceAdmission,
    BlobProcessSourceAdmissionPhase, NamedMutationOperation, PreparedTransition, StoreError,
    TransitionClass, canonical_json_bytes, sha256_hex,
};

pub(super) fn append_blob_process_source_admission(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    transition: &PreparedTransition,
) -> Result<(), AdapterError> {
    let mut commands = transition.named_operations.iter().filter(|command| {
        command.operation == NamedMutationOperation::RecordBlobProcessSourceAdmission
    });
    let Some(command) = commands.next() else {
        return Ok(());
    };
    if commands.next().is_some() {
        return Err(AdapterError::Store(StoreError::Duplicate {
            field: "blob_process_source.named_operations",
        }));
    }
    if transition.transition_class != TransitionClass::RecoverySchema {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let text_param = |name: &'static str| {
        command
            .parameters
            .get(name)
            .and_then(Value::as_str)
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "blob_process_source.parameter",
                reason: "missing required text parameter",
            }))
    };
    let admission_ref = text_param("admission_ref")?;
    let expected_revision = text_param("expected_revision")?
        .parse::<u64>()
        .map_err(|_| {
            AdapterError::Store(StoreError::InvalidField {
                field: "blob_process_source.expected_revision",
                reason: "must be a decimal revision",
            })
        })?;
    let expected_digest = text_param("expected_digest")?;
    let snapshot_json = text_param("snapshot_json")?;
    if snapshot_json.is_empty() || snapshot_json.len() > eliot_store_api::MAX_RECOVERY_RECORD_BYTES
    {
        return Err(AdapterError::Store(StoreError::PayloadTooLarge));
    }
    let admission: BlobProcessSourceAdmission = serde_json::from_str(snapshot_json)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    admission.validate().map_err(AdapterError::Store)?;
    if admission.state_fence != transition.state_fence
        || admission.admission_ref().map_err(AdapterError::Store)? != admission_ref
    {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    match (
        expected_revision,
        expected_digest,
        admission.phase,
        admission.owner_revision,
    ) {
        (0, "absent", BlobProcessSourceAdmissionPhase::Pending, 1) => {}
        (1, digest, BlobProcessSourceAdmissionPhase::Ready, 2)
            if valid_sha256(digest)
                && admission
                    .ready
                    .as_ref()
                    .is_some_and(|ready| ready.pending_admission_sha256 == digest) => {}
        _ => {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "blob_process_source.transition",
                reason: "only absent→Pending and exact revision-1 Pending→Ready CAS are supported",
            }));
        }
    }
    let canonical = canonical_json_bytes(&admission)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    if canonical != snapshot_json.as_bytes() {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "blob_process_source.snapshot_json",
            reason: "must be the exact canonical typed admission object",
        }));
    }
    let key = admission
        .identity
        .record_key()
        .map_err(AdapterError::Store)?;
    let key_json = canonical_json_bytes(&key)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let row_id = sha256_hex(&key_json);
    let payload_digest = sha256_hex(&canonical);
    let record_revision = admission.owner_revision;
    let record = serde_json::json!({
        "namespace": key.namespace,
        "key": key.key,
        "state_fence": admission.state_fence,
        "revision": record_revision,
        "schema": BLOB_PROCESS_SOURCE_ADMISSION_ROW_SCHEMA,
        "payload": canonical,
        "value_digest": payload_digest,
    });
    let record = record.as_object().cloned().ok_or_else(|| {
        AdapterError::Serialization("Blob source admission row is not an object".to_owned())
    })?;

    sql.push_str(schema::TX_BLOB_PROCESS_SOURCE_ADMISSION);
    bindings.insert(
        "blob_process_source_table".to_owned(),
        json!(schema::table::RECOVERY_OWNER),
    );
    bindings.insert("blob_process_source_id".to_owned(), json!(row_id));
    bindings.insert(
        "blob_process_source_expected_namespace".to_owned(),
        json!(key.namespace),
    );
    bindings.insert(
        "blob_process_source_expected_key".to_owned(),
        json!(key.key),
    );
    bindings.insert(
        "blob_process_source_expected_state_fence".to_owned(),
        json!(&transition.state_fence),
    );
    bindings.insert(
        "blob_process_source_expected_revision".to_owned(),
        json!(expected_revision),
    );
    bindings.insert(
        "blob_process_source_expected_digest".to_owned(),
        json!(expected_digest),
    );
    bindings.insert(
        "blob_process_source_record".to_owned(),
        Value::Object(record),
    );
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
