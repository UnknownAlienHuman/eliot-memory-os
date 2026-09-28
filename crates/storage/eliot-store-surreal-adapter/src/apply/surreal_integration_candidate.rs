//! Durable Surreal transaction leg for Kernel-admitted integration candidates.

use std::fmt::Write as _;

use eliot_store_api::{
    INTEGRATION_CANDIDATE_SCHEMA_V1, IntegrationCandidateRevision, NamedMutationOperation,
    PreparedTransition, RecoveryRecord, RecoveryRecordKey, StoreError, canonical_json_bytes,
    decode_integration_candidate, sha256_hex,
};
use serde_json::{Map, Value, json};

use crate::error::AdapterError;
use crate::schema;

const REVISION_CONFLICT: &str = "integration_candidate_revision_conflict";
const CANDIDATE_NAMESPACE: &str = "integration-candidate-v1";
const HEAD_NAMESPACE: &str = "integration-candidate-head-v1";

/// Renders one admitted manifest revision into the caller's canonical transaction.
pub(crate) fn integration_candidate_statements(
    transition: &PreparedTransition,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let mut matching = transition
        .named_operations
        .iter()
        .filter(|command| command.operation == NamedMutationOperation::ApplyIntegrationCandidate);
    let Some(command) = matching.next() else {
        return Ok((String::new(), Map::new()));
    };
    if matching.next().is_some() {
        return Err(AdapterError::Store(StoreError::Duplicate {
            field: "integration_candidate.named_operations",
        }));
    }
    if transition.transition_class != eliot_store_api::TransitionClass::CaptureCandidate {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let revision = decode_integration_candidate(command.operation, &command.parameters)
        .map_err(AdapterError::Store)?;
    if revision.record.state_fence != transition.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    if transition.task_id.as_deref() != Some(revision.record.task_id.as_str()) {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "integration_candidate.task_id",
            reason: "must match the prepared transition task",
        }));
    }
    let (statement, bindings) = revision_write(&revision)?;
    Ok((statement, bindings))
}

fn revision_write(
    revision: &IntegrationCandidateRevision,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let record = &revision.record;
    let record_key = candidate_revision_key(
        &record.task_id.to_string(),
        &record.candidate_id,
        record.revision,
    )?;
    let head_key = candidate_head_key(&record.task_id.to_string(), &record.candidate_id)?;
    let expected = revision
        .expected_predecessor
        .as_ref()
        .map_or(0, |predecessor| predecessor.revision);
    let previous_key =
        candidate_revision_key(&record.task_id.to_string(), &record.candidate_id, expected)?;
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
        schema: INTEGRATION_CANDIDATE_SCHEMA_V1.to_owned(),
        payload: payload.to_vec(),
        value_digest: digest.clone(),
    };
    let head = RecoveryRecord {
        namespace: head_key.namespace.clone(),
        key: head_key.key.clone(),
        state_fence: record.state_fence.clone(),
        revision: record.revision,
        schema: INTEGRATION_CANDIDATE_SCHEMA_V1.to_owned(),
        payload: payload.to_vec(),
        value_digest: digest,
    };

    let mut sql = String::new();
    write!(
        sql,
        "LET $integration_candidate_previous = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($integration_candidate_table, $integration_candidate_previous_id)); LET $integration_candidate_head_current = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($integration_candidate_table, $integration_candidate_head_id)); IF $integration_candidate_expected_revision = 0 {{ IF type::is_object($integration_candidate_previous) OR type::is_object($integration_candidate_head_current) {{ THROW '{REVISION_CONFLICT}'; }}; }} ELSE {{ IF !type::is_object($integration_candidate_previous) OR !type::is_object($integration_candidate_head_current) OR $integration_candidate_previous.namespace != $integration_candidate_record.namespace OR $integration_candidate_previous.key != $integration_candidate_previous_key OR $integration_candidate_previous.revision != $integration_candidate_expected_revision OR $integration_candidate_previous.schema != $integration_candidate_record.schema OR $integration_candidate_previous.value_digest != $integration_candidate_expected_previous_digest OR $integration_candidate_previous.payload != <bytes>$integration_candidate_expected_previous_payload OR $integration_candidate_previous.state_fence != $integration_candidate_expected_previous_state_fence OR $integration_candidate_head_current.namespace != $integration_candidate_head.namespace OR $integration_candidate_head_current.key != $integration_candidate_head.key OR $integration_candidate_head_current.revision != $integration_candidate_expected_revision OR $integration_candidate_head_current.schema != $integration_candidate_head.schema OR $integration_candidate_head_current.value_digest != $integration_candidate_expected_previous_digest OR $integration_candidate_head_current.payload != <bytes>$integration_candidate_expected_previous_payload OR $integration_candidate_head_current.state_fence != $integration_candidate_expected_previous_state_fence OR $integration_candidate_head_current.value_digest != $integration_candidate_previous.value_digest OR $integration_candidate_head_current.payload != $integration_candidate_previous.payload OR $integration_candidate_head_current.state_fence != $integration_candidate_previous.state_fence {{ THROW '{REVISION_CONFLICT}'; }}; }}; LET $integration_candidate_record_current = (SELECT VALUE {{ namespace: namespace, key: key, revision: revision, schema: schema, value_digest: value_digest }} FROM ONLY type::record($integration_candidate_table, $integration_candidate_record_id)); IF type::is_object($integration_candidate_record_current) {{ THROW '{REVISION_CONFLICT}'; }} ELSE {{ CREATE type::record($integration_candidate_table, $integration_candidate_record_id) CONTENT {{ namespace: $integration_candidate_record.namespace, key: $integration_candidate_record.key, state_fence: $integration_candidate_record.state_fence, revision: $integration_candidate_record.revision, schema: $integration_candidate_record.schema, payload: <bytes>$integration_candidate_record.payload, value_digest: $integration_candidate_record.value_digest }}; }}; IF type::is_object($integration_candidate_head_current) {{ LET $integration_candidate_head_updated = (UPDATE type::record($integration_candidate_table, $integration_candidate_head_id) CONTENT {{ namespace: $integration_candidate_head.namespace, key: $integration_candidate_head.key, state_fence: $integration_candidate_head.state_fence, revision: $integration_candidate_head.revision, schema: $integration_candidate_head.schema, payload: <bytes>$integration_candidate_head.payload, value_digest: $integration_candidate_head.value_digest }} WHERE revision = $integration_candidate_expected_revision AND value_digest = $integration_candidate_expected_previous_digest AND payload = <bytes>$integration_candidate_expected_previous_payload AND state_fence = $integration_candidate_expected_previous_state_fence RETURN AFTER); IF array::len($integration_candidate_head_updated) != 1 {{ THROW '{REVISION_CONFLICT}'; }}; }} ELSE {{ IF $integration_candidate_expected_revision != 0 {{ THROW '{REVISION_CONFLICT}'; }} ELSE {{ CREATE type::record($integration_candidate_table, $integration_candidate_head_id) CONTENT {{ namespace: $integration_candidate_head.namespace, key: $integration_candidate_head.key, state_fence: $integration_candidate_head.state_fence, revision: $integration_candidate_head.revision, schema: $integration_candidate_head.schema, payload: <bytes>$integration_candidate_head.payload, value_digest: $integration_candidate_head.value_digest }}; }}; }};"
    )
    .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let bindings = Map::from_iter([
        (
            "integration_candidate_table".to_owned(),
            json!(schema::table::RECOVERY_OWNER),
        ),
        (
            "integration_candidate_record_id".to_owned(),
            json!(record_id),
        ),
        ("integration_candidate_head_id".to_owned(), json!(head_id)),
        (
            "integration_candidate_previous_id".to_owned(),
            json!(previous_id),
        ),
        (
            "integration_candidate_previous_key".to_owned(),
            json!(previous_key.key),
        ),
        (
            "integration_candidate_expected_revision".to_owned(),
            json!(expected),
        ),
        (
            "integration_candidate_expected_previous_payload".to_owned(),
            json!(expected_previous_payload),
        ),
        (
            "integration_candidate_expected_previous_digest".to_owned(),
            json!(expected_previous_digest),
        ),
        (
            "integration_candidate_expected_previous_state_fence".to_owned(),
            expected_previous_state_fence,
        ),
        ("integration_candidate_record".to_owned(), json!(immutable)),
        ("integration_candidate_head".to_owned(), json!(head)),
    ]);
    Ok((sql, bindings))
}

/// Deterministic key for one immutable task/candidate/revision record.
pub(crate) fn candidate_revision_key(
    task_id: &str,
    candidate_id: &str,
    revision: u64,
) -> Result<RecoveryRecordKey, AdapterError> {
    let identity = canonical_json_bytes(&(task_id, candidate_id, revision))
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    RecoveryRecordKey::new(
        CANDIDATE_NAMESPACE,
        format!("candidate_{}", sha256_hex(&identity)),
    )
    .map_err(AdapterError::Store)
}

/// Deterministic key for the mutable task/candidate revision head.
pub(crate) fn candidate_head_key(
    task_id: &str,
    candidate_id: &str,
) -> Result<RecoveryRecordKey, AdapterError> {
    let identity = canonical_json_bytes(&(task_id, candidate_id))
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    RecoveryRecordKey::new(HEAD_NAMESPACE, format!("head_{}", sha256_hex(&identity)))
        .map_err(AdapterError::Store)
}

pub(crate) fn recovery_owner_id(key: &RecoveryRecordKey) -> Result<String, AdapterError> {
    let bytes = canonical_json_bytes(key)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}
