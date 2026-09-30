//! Canonical Store transaction leg for immutable swarm owner revisions.
//!
//! The Store persists complete owner records in distinct versioned namespaces
//! of the existing `recovery_owner` table. Per-owner revision rows are
//! create-only; each owner stream has a separately keyed compare-and-set head.
//! The rows, head advances and canonical receipt are emitted by the same
//! prepared Store transaction. ORS staging/activation remains outside this
//! module and is not described as atomic with Store.
//!
//! Issue #1702: the operation is ACTIVATED in the catalogue and its
//! owner-specific authorization evidence is verified inside
//! `PreparedTransition::validate` before this handler runs, so a cross-owner or
//! stale-lease presentation never reaches these statements. This handler
//! persists exactly the row the authorized transition names; it grants no
//! admission, dispatch or lifecycle change of its own.

use std::fmt::Write as _;

use eliot_store_api::{
    NamedMutationOperation, PreparedTransition, RecoveryRecordKey, StoreError, SwarmOwnerRevision,
    SwarmSemanticOwnerKind, canonical_json_bytes, decode_swarm_owner_revisions, sha256_hex,
};
use serde_json::{Map, Value, json};

use crate::error::AdapterError;
use crate::schema;

const REVISION_CONFLICT: &str = "swarm_owner_revision_conflict";

/// Renders the exact owner-revision writes embedded in one admitted transition.
pub(crate) fn swarm_owner_revision_statements(
    transition: &PreparedTransition,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let Some(command) = transition
        .named_operations
        .iter()
        .find(|command| command.operation == NamedMutationOperation::ApplySwarmOwnerRevisions)
    else {
        return Ok((String::new(), Map::new()));
    };
    if transition.transition_class != eliot_store_api::TransitionClass::TaskControl {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let batch = decode_swarm_owner_revisions(command.operation, &command.parameters)
        .map_err(AdapterError::Store)?;
    let mut sql = String::new();
    let mut bindings = Map::new();
    append_owner_revision(
        &mut sql,
        &mut bindings,
        &batch.record,
        &transition.state_fence,
    )?;
    Ok((sql, bindings))
}

fn append_owner_revision(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    revision: &SwarmOwnerRevision,
    state_fence: &eliot_store_api::StateFence,
) -> Result<(), AdapterError> {
    let namespace = match revision.owner_kind {
        SwarmSemanticOwnerKind::TaskController => eliot_store_api::SWARM_DEFINITION_OWNER_NAMESPACE,
        SwarmSemanticOwnerKind::Governor => eliot_store_api::SWARM_ADMISSION_OWNER_NAMESPACE,
        SwarmSemanticOwnerKind::AgentCoordinator => {
            eliot_store_api::SWARM_EXECUTION_OWNER_NAMESPACE
        }
    };
    let payload = revision.record_json.as_bytes();
    let record_key = recovery_record_key(namespace, &revision.owner_id, revision.revision)?;
    let owner_key = recovery_record_key(
        eliot_store_api::SWARM_OWNER_HEAD_NAMESPACE,
        &format!(
            "{}:{}",
            revision.owner_kind.scope_component(),
            revision.owner_id
        ),
        0,
    )?;
    let record_id = recovery_owner_id(&record_key)?;
    let head_id = recovery_owner_id(&owner_key)?;
    let suffix = "owner";
    let record_schema = owner_record_schema(revision.owner_kind);
    let record = json!({
        "namespace": namespace,
        "key": record_key.key,
        "state_fence": state_fence,
        "revision": revision.revision,
        "schema": record_schema,
        "payload": payload,
        "value_digest": revision.content_digest,
    });
    let head = json!({
        "namespace": eliot_store_api::SWARM_OWNER_HEAD_NAMESPACE,
        "key": owner_key.key,
        "state_fence": state_fence,
        "revision": revision.revision,
        "schema": eliot_store_api::SWARM_OWNER_HEAD_SCHEMA,
        // The head retains the exact semantic bytes it currently points to;
        // its digest therefore has the same meaning as the immutable history.
        "payload": payload,
        "value_digest": revision.content_digest,
    });
    let expected = revision.expected_predecessor.unwrap_or(0);
    let previous_key = recovery_record_key(namespace, &revision.owner_id, expected)?;
    let previous_id = recovery_owner_id(&previous_key)?;
    write!(
        sql,
        "LET $swarm_previous_{suffix} = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($swarm_table_{suffix}, $swarm_previous_id_{suffix})); IF $swarm_expected_revision_{suffix} = 0 {{ IF type::is_object($swarm_previous_{suffix}) {{ THROW '{REVISION_CONFLICT}'; }}; }} ELSE {{ IF NOT type::is_object($swarm_previous_{suffix}) OR $swarm_previous_{suffix}.namespace != $swarm_record_{suffix}.namespace OR $swarm_previous_{suffix}.key != $swarm_previous_key_{suffix} OR $swarm_previous_{suffix}.revision != $swarm_expected_revision_{suffix} OR $swarm_previous_{suffix}.schema != $swarm_record_{suffix}.schema {{ THROW '{REVISION_CONFLICT}'; }}; }}; LET $swarm_head_current_{suffix} = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($swarm_table_{suffix}, $swarm_head_id_{suffix})); IF type::is_object($swarm_head_current_{suffix}) {{ IF $swarm_expected_revision_{suffix} = 0 OR $swarm_head_current_{suffix}.namespace != $swarm_head_{suffix}.namespace OR $swarm_head_current_{suffix}.key != $swarm_head_{suffix}.key OR $swarm_head_current_{suffix}.schema != $swarm_head_{suffix}.schema OR $swarm_head_current_{suffix}.revision != $swarm_expected_revision_{suffix} OR $swarm_head_current_{suffix}.value_digest != $swarm_previous_{suffix}.value_digest OR $swarm_head_current_{suffix}.payload != $swarm_previous_{suffix}.payload OR $swarm_head_current_{suffix}.state_fence != $swarm_previous_{suffix}.state_fence {{ THROW '{REVISION_CONFLICT}'; }}; LET $swarm_head_updated_{suffix} = (UPDATE type::record($swarm_table_{suffix}, $swarm_head_id_{suffix}) CONTENT {{ namespace: $swarm_head_{suffix}.namespace, key: $swarm_head_{suffix}.key, state_fence: $swarm_head_{suffix}.state_fence, revision: $swarm_head_{suffix}.revision, schema: $swarm_head_{suffix}.schema, payload: <bytes>$swarm_head_{suffix}.payload, value_digest: $swarm_head_{suffix}.value_digest }} WHERE revision = $swarm_expected_revision_{suffix} RETURN AFTER); IF array::len($swarm_head_updated_{suffix}) != 1 {{ THROW '{REVISION_CONFLICT}'; }}; }} ELSE {{ IF $swarm_expected_revision_{suffix} != 0 {{ THROW '{REVISION_CONFLICT}'; }} ELSE {{ CREATE type::record($swarm_table_{suffix}, $swarm_head_id_{suffix}) CONTENT {{ namespace: $swarm_head_{suffix}.namespace, key: $swarm_head_{suffix}.key, state_fence: $swarm_head_{suffix}.state_fence, revision: $swarm_head_{suffix}.revision, schema: $swarm_head_{suffix}.schema, payload: <bytes>$swarm_head_{suffix}.payload, value_digest: $swarm_head_{suffix}.value_digest }}; }}; }}; LET $swarm_record_current_{suffix} = (SELECT VALUE {{ namespace: namespace, key: key, revision: revision, schema: schema, value_digest: value_digest }} FROM ONLY type::record($swarm_table_{suffix}, $swarm_record_id_{suffix})); IF type::is_object($swarm_record_current_{suffix}) {{ THROW '{REVISION_CONFLICT}'; }} ELSE {{ CREATE type::record($swarm_table_{suffix}, $swarm_record_id_{suffix}) CONTENT {{ namespace: $swarm_record_{suffix}.namespace, key: $swarm_record_{suffix}.key, state_fence: $swarm_record_{suffix}.state_fence, revision: $swarm_record_{suffix}.revision, schema: $swarm_record_{suffix}.schema, payload: <bytes>$swarm_record_{suffix}.payload, value_digest: $swarm_record_{suffix}.value_digest }}; }};"
    )
    .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    for (name, value) in [
        (
            format!("swarm_table_{suffix}"),
            json!(schema::table::RECOVERY_OWNER),
        ),
        (format!("swarm_record_id_{suffix}"), json!(record_id)),
        (format!("swarm_head_id_{suffix}"), json!(head_id)),
        (format!("swarm_previous_id_{suffix}"), json!(previous_id)),
        (
            format!("swarm_previous_key_{suffix}"),
            json!(previous_key.key),
        ),
        (format!("swarm_expected_revision_{suffix}"), json!(expected)),
        (format!("swarm_record_{suffix}"), record),
        (format!("swarm_head_{suffix}"), head),
    ] {
        if bindings.insert(name, value).is_some() {
            return Err(AdapterError::Serialization(
                "swarm binding collided with a canonical binding".to_owned(),
            ));
        }
    }
    Ok(())
}

fn owner_record_schema(owner: SwarmSemanticOwnerKind) -> &'static str {
    match owner {
        SwarmSemanticOwnerKind::TaskController => eliot_store_api::SWARM_DEFINITION_OWNER_SCHEMA,
        SwarmSemanticOwnerKind::Governor => eliot_store_api::SWARM_ADMISSION_OWNER_SCHEMA,
        SwarmSemanticOwnerKind::AgentCoordinator => eliot_store_api::SWARM_EXECUTION_OWNER_SCHEMA,
    }
}

fn recovery_record_key(
    namespace: &str,
    owner_id: &str,
    revision: u64,
) -> Result<RecoveryRecordKey, AdapterError> {
    let identity = canonical_json_bytes(&(owner_id, revision))
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    RecoveryRecordKey::new(namespace, format!("swarm_{}", sha256_hex(&identity)))
        .map_err(AdapterError::Store)
}

fn recovery_owner_id(key: &RecoveryRecordKey) -> Result<String, AdapterError> {
    let bytes = canonical_json_bytes(key)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}
