//! Fenced named recovery-owner updates committed with the canonical write receipt.
//!
//! The WorkScope payload remains Governor-owned and opaque here. This narrow
//! adapter accepts only `RecordWorkScopeSnapshot`, checks the original owner
//! revision/digest and the canonical payload encoding, then appends the single
//! CAS statement to the same Surreal transaction as its `WriteReceipt`.

use serde_json::{Map, Value, json};

use crate::error::AdapterError;
use crate::schema;
use eliot_store_api::{NamedMutationOperation, PreparedTransition, StoreError, TransitionClass};

/// Appends the exact Governor-produced WorkScope owner image after validating
/// its prior durable revision and original content digest. Store interprets
/// only the record key, state fence, revision, and digest.
pub(super) fn append_work_scope_owner_statement(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    transition: &PreparedTransition,
) -> Result<(), AdapterError> {
    let Some(command) = transition
        .named_operations
        .iter()
        .find(|command| command.operation == NamedMutationOperation::RecordWorkScopeSnapshot)
    else {
        return Ok(());
    };
    if transition.transition_class != TransitionClass::RecoverySchema {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let text_param = |name: &'static str| {
        command
            .parameters
            .get(name)
            .and_then(Value::as_str)
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "missing required parameter",
            }))
    };
    let expected_revision = text_param("expected_work_scope_revision")?
        .parse::<u64>()
        .map_err(|_| {
            AdapterError::Store(StoreError::InvalidField {
                field: "work_scope.owner_revision",
                reason: "expected revision must be a decimal revision",
            })
        })?;
    let expected_value_digest = text_param("expected_work_scope_digest")?;
    if expected_revision == 0 {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "work_scope.owner_revision",
            reason: "initial binding must replace the exact named empty-owner revision",
        }));
    }
    if expected_value_digest.len() != 64
        || expected_value_digest
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "work_scope.owner_digest",
            reason: "expected digest must be lowercase SHA-256",
        }));
    }
    let snapshot_json = text_param("snapshot_json")?;
    if snapshot_json.is_empty() || snapshot_json.len() > eliot_store_api::MAX_RECOVERY_RECORD_BYTES
    {
        return Err(AdapterError::Store(if snapshot_json.is_empty() {
            StoreError::Empty {
                field: "work_scope.snapshot_json",
            }
        } else {
            StoreError::PayloadTooLarge
        }));
    }
    let snapshot_value: Value = serde_json::from_str(snapshot_json).map_err(|_| {
        AdapterError::Store(StoreError::InvalidField {
            field: "work_scope.snapshot_json",
            reason: "must be canonical JSON",
        })
    })?;
    if !snapshot_value.is_object()
        || eliot_store_api::canonical_json_bytes(&snapshot_value)
            .map_err(|error| AdapterError::Serialization(error.to_string()))?
            != snapshot_json.as_bytes()
    {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "work_scope.snapshot_json",
            reason: "must be a canonical JSON object",
        }));
    }
    let next_revision = expected_revision.checked_add(1).ok_or({
        AdapterError::Store(StoreError::InvalidField {
            field: "work_scope.owner_revision",
            reason: "revision overflow",
        })
    })?;
    // This is the exact key selected by Governor's RecoveryOwner::WorkScope
    // (`as_str() == "work_scope"`), not a new owner namespace.
    let key = eliot_store_api::RecoveryRecordKey::new("owner", "work_scope")
        .map_err(AdapterError::Store)?;
    let key_json = eliot_store_api::canonical_json_bytes(&key)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let owner_id = eliot_store_api::sha256_hex(&key_json);
    let payload = snapshot_json.as_bytes();
    let mut record = Map::new();
    record.insert("namespace".to_owned(), json!(key.namespace));
    record.insert("key".to_owned(), json!(key.key));
    record.insert("state_fence".to_owned(), json!(&transition.state_fence));
    record.insert("revision".to_owned(), json!(next_revision));
    record.insert(
        "schema".to_owned(),
        json!(eliot_store_api::OWNER_SNAPSHOT_SCHEMA),
    );
    record.insert("payload".to_owned(), json!(payload));
    record.insert(
        "value_digest".to_owned(),
        json!(eliot_store_api::sha256_hex(payload)),
    );

    sql.push_str(schema::TX_WORK_SCOPE_OWNER);
    bindings.insert(
        "work_scope_owner_table".to_owned(),
        json!(schema::table::RECOVERY_OWNER),
    );
    bindings.insert("work_scope_owner_id".to_owned(), json!(owner_id));
    bindings.insert(
        "work_scope_expected_state_fence".to_owned(),
        json!(&transition.state_fence),
    );
    bindings.insert(
        "work_scope_expected_revision".to_owned(),
        json!(expected_revision),
    );
    bindings.insert(
        "work_scope_expected_value_digest".to_owned(),
        json!(expected_value_digest),
    );
    bindings.insert("work_scope_owner_record".to_owned(), Value::Object(record));
    Ok(())
}

/// Appends the exact Governor-produced Policy owner image after validating
/// its prior durable revision and original content digest. Store does not
/// verify signature semantics; it commits the complete signed envelope as
/// part of the same normal WriteReceipt transaction.
pub(super) fn append_policy_owner_statement(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    transition: &PreparedTransition,
) -> Result<(), AdapterError> {
    let Some(command) = transition
        .named_operations
        .iter()
        .find(|command| command.operation == NamedMutationOperation::RecordPolicySnapshot)
    else {
        return Ok(());
    };
    if transition.transition_class != TransitionClass::RecoverySchema {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let text_param = |name: &'static str| {
        command
            .parameters
            .get(name)
            .and_then(Value::as_str)
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "missing required parameter",
            }))
    };
    let optional_text = |name: &'static str| {
        command
            .parameters
            .get(name)
            .map(|value| {
                value.as_str().ok_or(AdapterError::Store(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "optional policy parameter must be text",
                }))
            })
            .transpose()
    };
    let expected_state = text_param("expected_policy_state")?;
    let (expected_revision, expected_value_digest, create_if_absent) = match expected_state {
        "physical_absence" => {
            if optional_text("expected_policy_revision")?.is_some()
                || optional_text("expected_policy_digest")?.is_some()
            {
                return Err(AdapterError::Store(StoreError::InvalidField {
                    field: "policy.expected_state",
                    reason: "physical absence cannot use revision or digest sentinels",
                }));
            }
            let response_json = optional_text("absence_read_response_json")?.ok_or(
                AdapterError::Store(StoreError::InvalidField {
                    field: "policy.absence_read_response_json",
                    reason: "physical absence requires its exact named-read response",
                }),
            )?;
            let response_sha = optional_text("absence_read_response_sha256")?.ok_or(
                AdapterError::Store(StoreError::InvalidField {
                    field: "policy.absence_read_response_sha256",
                    reason: "physical absence requires its response digest",
                }),
            )?;
            if response_sha.len() != 64
                || response_sha.bytes().any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                || eliot_store_api::sha256_hex(response_json.as_bytes()) != response_sha
            {
                return Err(AdapterError::Store(StoreError::InvalidField {
                    field: "policy.absence_read_response_sha256",
                    reason: "must bind the exact absence named-read response",
                }));
            }
            let response_value: Value = serde_json::from_str(response_json).map_err(|_| {
                AdapterError::Store(StoreError::InvalidField {
                    field: "policy.absence_read_response_json",
                    reason: "must be a canonical named-read response",
                })
            })?;
            if eliot_store_api::canonical_json_bytes(&response_value)
                .map_err(|error| AdapterError::Serialization(error.to_string()))?
                != response_json.as_bytes()
            {
                return Err(AdapterError::Store(StoreError::InvalidField {
                    field: "policy.absence_read_response_json",
                    reason: "must be canonical JSON",
                }));
            }
            let response: eliot_store_api::NamedReadResponse =
                serde_json::from_value(response_value).map_err(|_| {
                    AdapterError::Store(StoreError::InvalidField {
                        field: "policy.absence_read_response_json",
                        reason: "must be a closed named-read response",
                    })
                })?;
            if response.operation != eliot_store_api::NamedReadOperation::GetPolicyOwnerSnapshot
                || response.state_fence != transition.state_fence
            {
                return Err(AdapterError::Store(StoreError::InvalidField {
                    field: "policy.absence_read_response_json",
                    reason: "must be the policy owner read under the transition fence",
                }));
            }
            let absence: eliot_store_api::PolicyOwnerSnapshotReadResult =
                serde_json::from_value(response.payload).map_err(|_| {
                    AdapterError::Store(StoreError::InvalidField {
                        field: "policy.absence_read_response_json",
                        reason: "must carry the typed policy-owner result",
                    })
                })?;
            absence.validate(&transition.state_fence).map_err(AdapterError::Store)?;
            if !matches!(absence, eliot_store_api::PolicyOwnerSnapshotReadResult::Absent { .. }) {
                return Err(AdapterError::Store(StoreError::InvalidField {
                    field: "policy.absence_read_response_json",
                    reason: "must prove physical policy-row absence",
                }));
            }
            (None, None, true)
        }
        "existing" => {
            if optional_text("absence_read_response_json")?.is_some()
                || optional_text("absence_read_response_sha256")?.is_some()
            {
                return Err(AdapterError::Store(StoreError::InvalidField {
                    field: "policy.expected_state",
                    reason: "existing-row CAS cannot carry absence proof",
                }));
            }
            let revision = text_param("expected_policy_revision")?.parse::<u64>().map_err(|_| {
                AdapterError::Store(StoreError::InvalidField {
                    field: "policy.owner_revision",
                    reason: "expected revision must be a decimal revision",
                })
            })?;
            if revision == 0 {
                return Err(AdapterError::Store(StoreError::InvalidField {
                    field: "policy.owner_revision",
                    reason: "Policy CAS requires a nonzero named-read revision",
                }));
            }
            let digest = text_param("expected_policy_digest")?;
            if digest.len() != 64
                || digest.bytes().any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(AdapterError::Store(StoreError::InvalidField {
                    field: "policy.owner_digest",
                    reason: "expected digest must be lowercase SHA-256",
                }));
            }
            (Some(revision), Some(digest.to_owned()), false)
        }
        _ => {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "policy.expected_state",
                reason: "must select physical_absence or existing",
            }));
        }
    };
    let snapshot_json = text_param("snapshot_json")?;
    if snapshot_json.is_empty() || snapshot_json.len() > eliot_store_api::MAX_RECOVERY_RECORD_BYTES
    {
        return Err(AdapterError::Store(if snapshot_json.is_empty() {
            StoreError::Empty {
                field: "policy.snapshot_json",
            }
        } else {
            StoreError::PayloadTooLarge
        }));
    }
    let snapshot_value: Value = serde_json::from_str(snapshot_json).map_err(|_| {
        AdapterError::Store(StoreError::InvalidField {
            field: "policy.snapshot_json",
            reason: "must be canonical JSON",
        })
    })?;
    if !snapshot_value.is_object()
        || eliot_store_api::canonical_json_bytes(&snapshot_value)
            .map_err(|error| AdapterError::Serialization(error.to_string()))?
            != snapshot_json.as_bytes()
    {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "policy.snapshot_json",
            reason: "must be a canonical JSON object",
        }));
    }
    let next_revision = match expected_revision {
        Some(revision) => revision.checked_add(1).ok_or({
            AdapterError::Store(StoreError::InvalidField {
                field: "policy.owner_revision",
                reason: "revision overflow",
            })
        })?,
        None if create_if_absent => 1,
        None => {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "policy.owner_revision",
                reason: "existing-row update omitted its exact revision",
            }));
        }
    };
    let key = eliot_store_api::RecoveryRecordKey::new("owner", "policy")
        .map_err(AdapterError::Store)?;
    let key_json = eliot_store_api::canonical_json_bytes(&key)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let owner_id = eliot_store_api::sha256_hex(&key_json);
    let payload = snapshot_json.as_bytes();
    let mut record = Map::new();
    record.insert("namespace".to_owned(), json!(key.namespace));
    record.insert("key".to_owned(), json!(key.key));
    record.insert("state_fence".to_owned(), json!(&transition.state_fence));
    record.insert("revision".to_owned(), json!(next_revision));
    record.insert(
        "schema".to_owned(),
        json!(eliot_store_api::OWNER_SNAPSHOT_SCHEMA),
    );
    record.insert("payload".to_owned(), json!(payload));
    record.insert(
        "value_digest".to_owned(),
        json!(eliot_store_api::sha256_hex(payload)),
    );
    sql.push_str(schema::TX_POLICY_OWNER);
    bindings.insert(
        "policy_owner_table".to_owned(),
        json!(schema::table::RECOVERY_OWNER),
    );
    bindings.insert("policy_owner_id".to_owned(), json!(owner_id));
    bindings.insert(
        "policy_expected_state_fence".to_owned(),
        json!(&transition.state_fence),
    );
    bindings.insert(
        "policy_expected_revision".to_owned(),
        json!(expected_revision),
    );
    bindings.insert(
        "policy_expected_value_digest".to_owned(),
        json!(expected_value_digest),
    );
    bindings.insert("policy_create_if_absent".to_owned(), json!(create_if_absent));
    bindings.insert("policy_owner_record".to_owned(), Value::Object(record));
    Ok(())
}
