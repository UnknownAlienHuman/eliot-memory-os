//! Atomic CAS persistence for Governor's existing Budget owner snapshot and
//! one measured-use attribution row. The owner image must already exist: this
//! path never initializes or substitutes an unavailable Budget ledger.

use eliot_store_api::{
    BUDGET_CONSUMPTION_RECORD_NAMESPACE, BUDGET_CONSUMPTION_SCHEMA_V1,
    NamedMutationOperation, OWNER_SNAPSHOT_SCHEMA, PreparedTransition, RecoveryRecord,
    RecoveryRecordKey, StoreError, canonical_json_bytes, decode_budget_consumption_record,
    sha256_hex, validate_budget_consumption_transition,
};
use serde_json::{Map, Value, json};

use crate::{error::AdapterError, schema};

const BUDGET_OWNER_CAS_CONFLICT: &str = "budget_owner_cas_conflict";
const BUDGET_CONSUMPTION_EXISTS: &str = "budget_consumption_already_exists";

/// Renders the single Governor-owned `CommitBudgetConsumption` mutation.
/// Unrelated transitions receive an empty fragment; malformed mutations fail
/// before any database request is sent.
pub(crate) fn budget_consumption_statements(
    transition: &PreparedTransition,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let mut matching = transition
        .named_operations
        .iter()
        .filter(|command| command.operation == NamedMutationOperation::CommitBudgetConsumption);
    let Some(command) = matching.next() else {
        return Ok((String::new(), Map::new()));
    };
    if matching.next().is_some() {
        return Err(AdapterError::Store(StoreError::Duplicate {
            field: "budget_consumption.named_operations",
        }));
    }
    validate_budget_consumption_transition(transition).map_err(AdapterError::Store)?;
    let record = decode_budget_consumption_record(&command.parameters)
        .map_err(AdapterError::Store)?;
    if transition.task_id.as_deref() != Some(record.task_id.as_str())
        || transition.scope_id.as_str() != record.work_scope_id
    {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "budget_consumption.transition_binding",
            reason: "must retain the exact task and work scope of the measured usage",
        }));
    }

    let expected_revision = command.parameters["expected_budget_owner_revision"]
        .as_str()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "budget_consumption.expected_budget_owner_revision",
            reason: "must be the original durable Budget owner predecessor",
        }))?;
    let expected_digest = command.parameters["expected_budget_owner_digest"]
        .as_str()
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "budget_consumption.expected_budget_owner_digest",
            reason: "must be the original durable Budget owner payload digest",
        }))?;
    let next_snapshot = command.parameters["budget_owner_snapshot_json"]
        .as_str()
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "budget_consumption.budget_owner_snapshot_json",
            reason: "must be the exact next configured Budget owner image",
        }))?;

    let owner_key = RecoveryRecordKey::new("owner", "budget").map_err(AdapterError::Store)?;
    let owner_id = crate::apply::surreal_blackboard::recovery_owner_id(&owner_key)?;
    let next_owner_revision = expected_revision.checked_add(1).ok_or(
        AdapterError::Store(StoreError::InvalidField {
            field: "budget_consumption.expected_budget_owner_revision",
            reason: "durable Budget owner revision overflow",
        }),
    )?;
    let next_owner = RecoveryRecord {
        namespace: owner_key.namespace.clone(),
        key: owner_key.key.clone(),
        state_fence: record.state_fence.clone(),
        revision: next_owner_revision,
        schema: OWNER_SNAPSHOT_SCHEMA.to_owned(),
        value_digest: sha256_hex(next_snapshot.as_bytes()),
        payload: next_snapshot.as_bytes().to_vec(),
    };

    let consumption_key = RecoveryRecordKey::new(
        BUDGET_CONSUMPTION_RECORD_NAMESPACE,
        record.consumption_id.clone(),
    )
    .map_err(AdapterError::Store)?;
    let consumption_id = crate::apply::surreal_blackboard::recovery_owner_id(&consumption_key)?;
    let consumption_payload = canonical_json_bytes(&record)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let consumption = RecoveryRecord {
        namespace: consumption_key.namespace,
        key: consumption_key.key,
        state_fence: record.state_fence.clone(),
        revision: 1,
        schema: BUDGET_CONSUMPTION_SCHEMA_V1.to_owned(),
        value_digest: sha256_hex(&consumption_payload),
        payload: consumption_payload,
    };

    let sql = format!(
        "LET $budget_owner_current = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($budget_owner_table, $budget_owner_id)); IF NOT type::is_object($budget_owner_current) OR $budget_owner_current.namespace != 'owner' OR $budget_owner_current.key != 'budget' OR $budget_owner_current.schema != '{owner_schema}' OR $budget_owner_current.revision != $budget_expected_revision OR $budget_owner_current.value_digest != $budget_expected_digest OR $budget_owner_current.state_fence != $budget_expected_fence {{ THROW '{BUDGET_OWNER_CAS_CONFLICT}'; }}; LET $budget_consumption_current = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, value_digest: value_digest }} FROM ONLY type::record($budget_consumption_table, $budget_consumption_id)); IF type::is_object($budget_consumption_current) {{ THROW '{BUDGET_CONSUMPTION_EXISTS}'; }}; LET $budget_owner_updated = (UPDATE type::record($budget_owner_table, $budget_owner_id) CONTENT $budget_next_owner WHERE namespace = 'owner' AND key = 'budget' AND schema = '{owner_schema}' AND state_fence = $budget_expected_fence AND revision = $budget_expected_revision AND value_digest = $budget_expected_digest RETURN AFTER); IF array::len($budget_owner_updated ?? []) != 1 {{ THROW '{BUDGET_OWNER_CAS_CONFLICT}'; }}; CREATE type::record($budget_consumption_table, $budget_consumption_id) CONTENT {{ namespace: $budget_consumption.namespace, key: $budget_consumption.key, state_fence: $budget_consumption.state_fence, revision: $budget_consumption.revision, schema: $budget_consumption.schema, payload: <bytes>$budget_consumption.payload, value_digest: $budget_consumption.value_digest }};",
        owner_schema = OWNER_SNAPSHOT_SCHEMA,
    );
    let bindings = Map::from_iter([
        (
            "budget_owner_table".to_owned(),
            json!(schema::table::RECOVERY_OWNER),
        ),
        ("budget_owner_id".to_owned(), json!(owner_id)),
        ("budget_expected_revision".to_owned(), json!(expected_revision)),
        ("budget_expected_digest".to_owned(), json!(expected_digest)),
        ("budget_expected_fence".to_owned(), json!(&record.state_fence)),
        ("budget_next_owner".to_owned(), json!(next_owner)),
        (
            "budget_consumption_table".to_owned(),
            json!(schema::table::RECOVERY_OWNER),
        ),
        ("budget_consumption_id".to_owned(), json!(consumption_id)),
        ("budget_consumption".to_owned(), json!(consumption)),
    ]);
    Ok((sql, bindings))
}

#[cfg(test)]
#[path = "budget_consumption_tests.rs"]
mod tests;
