//! Canonical notification-state execution for the `SurrealDB` bridge
//! (issue #1780).
//!
//! Mirrors the reference contour's closed legs through the shared
//! kernel-core transition model, persisted in the `notification_record`
//! table: one row per dedup key carrying the current record, the ordered
//! admitted leg history, the owner revision, and the admission fence.
//! Rehydration replays the stored history through a fresh model, so the
//! transition logic has exactly one implementation. Concurrent writers
//! arbitrate through the in-transaction revision compare-and-set inside the
//! canonical transaction; retries recompute from fresh rows, never from
//! stale reads. Record rows commit inside the canonical transaction beside
//! the receipt and outbox rows, so record, receipt, and outbox stay atomic.

use eliot_kernel_core::{
    DeliveryChannel, DeliveryState, NotificationDraft, NotificationError, NotificationStore,
    ResolutionAuthorization,
};
use eliot_store_api::{
    DecodedNotificationMutation, NamedMutationOperation, ReceiptEnvelope, StateFence, StoreError,
    TransitionClass, decode_notification_mutation,
};
use serde_json::{Map, Value, json};

use crate::SurrealAdapterConfig;
use crate::client::{self, RpcTransport};
use crate::error::AdapterError;
use crate::schema;

/// One computed notification row write for the canonical transaction.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SurrealNotificationWrite {
    /// Deduplication index key (record id within the table).
    pub dedup_key: String,
    /// Current canonical record JSON after the admitted legs.
    pub record: Value,
    /// Ordered admitted leg history JSON (raw params maps for replay).
    pub history: Value,
    /// Owner revision after the admitted legs.
    pub revision: u64,
    /// Admission fence of the transition.
    pub state_fence: StateFence,
    /// Revision observed at pre-transaction read (`None` for creates).
    pub expected_revision: Option<u64>,
}

/// Stored notification row shape as projected by reads.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StoredNotificationRow {
    /// Deduplication index key.
    pub dedup_key: String,
    /// Current canonical record JSON.
    pub record: Value,
    /// Ordered admitted leg history JSON.
    pub history: Vec<Value>,
    /// Owner revision.
    pub revision: u64,
    /// Admission fence.
    pub state_fence: StateFence,
}

/// Ensures the notification record table exists (idempotent).
///
/// Schemaless tables auto-create on write, but reads and the
/// in-transaction compare-and-set fail closed on a missing table. This
/// one-shot definition keeps first use on a fresh database exact; it
/// changes no migration chain and carries no data.
async fn ensure_notification_table(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<(), AdapterError> {
    let sql = format!(
        "DEFINE TABLE IF NOT EXISTS {} SCHEMALESS;",
        crate::schema::table::NOTIFICATION_RECORD
    );
    let mut response =
        client::query(db, config, "notification.ensure_table", &sql, Map::new()).await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}

/// Computes notification row writes for one admitted transition.
///
/// Reads current rows, rehydrates the shared model per key by replaying the
/// stored leg history, applies the new legs, and returns the resulting rows
/// with their expected revisions for the in-transaction compare-and-set.
/// Transitions without notification operations yield no writes. Pure reads
/// plus pure compute: rows are written only by the canonical transaction.
pub(crate) async fn prepare_notification_writes(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<Vec<SurrealNotificationWrite>, AdapterError> {
    let mut commands = Vec::new();
    for command in &transition.named_operations {
        if command.operation == NamedMutationOperation::ApplyNotificationState {
            commands.push(command);
        }
    }
    if commands.is_empty() {
        return Ok(Vec::new());
    }
    if transition.transition_class != TransitionClass::NotificationState {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    // The table is schemaless and auto-creates on write, but reads and the
    // in-transaction compare-and-set fail closed on a missing table instead
    // of reading empty. Ensuring it here (idempotent) keeps first use on a
    // fresh database exact without a schema-migration bump.
    ensure_notification_table(db, config).await?;
    let mut writes = Vec::with_capacity(commands.len());
    for command in commands {
        let decoded =
            decode_notification_mutation(&command.parameters).map_err(AdapterError::Store)?;
        writes.push(
            apply_notification_command(db, config, transition, &command.parameters, decoded)
                .await?,
        );
    }
    Ok(writes)
}

async fn apply_notification_command(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    transition: &eliot_store_api::PreparedTransition,
    parameters: &std::collections::BTreeMap<String, Value>,
    decoded: DecodedNotificationMutation,
) -> Result<SurrealNotificationWrite, AdapterError> {
    let history_entry = Value::Object(
        parameters
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    );
    match decoded {
        DecodedNotificationMutation::Upsert {
            dedup_key,
            record_json,
            source_receipt_json,
        } => {
            let draft: NotificationDraft =
                serde_json::from_value(record_json).map_err(|error| {
                    AdapterError::Store(StoreError::Serialization(error.to_string()))
                })?;
            if draft.state_fence != transition.state_fence {
                return Err(AdapterError::Store(StoreError::FenceMismatch));
            }
            let source_receipt: ReceiptEnvelope = serde_json::from_value(source_receipt_json)
                .map_err(|error| {
                    AdapterError::Store(StoreError::Serialization(error.to_string()))
                })?;
            source_receipt
                .validate()
                .map_err(|_| AdapterError::Store(StoreError::InvalidReceipt))?;
            let current = read_notification_row(db, config, &dedup_key).await?;
            let mut store = rehydrate(current.as_ref())?;
            let record = store
                .upsert(draft)
                .map_err(|error| model_error(&error))?
                .clone();
            let mut history = current
                .as_ref()
                .map_or(Vec::new(), |row| row.history.clone());
            history.push(history_entry);
            Ok(write_for(
                &dedup_key,
                &record,
                history,
                &transition.state_fence,
                current.as_ref().map(|row| row.revision),
            ))
        }
        DecodedNotificationMutation::Delivery {
            notification_id,
            channel,
            delivery_json,
        } => {
            let channel_typed: DeliveryChannel = serde_json::from_value(Value::String(channel))
                .map_err(|error| {
                    AdapterError::Store(StoreError::Serialization(error.to_string()))
                })?;
            let delivery: DeliveryState =
                serde_json::from_value(delivery_json).map_err(|error| {
                    AdapterError::Store(StoreError::Serialization(error.to_string()))
                })?;
            let (dedup_key, mut store, current) =
                resolve_current_for_leg(db, config, &transition.state_fence, &notification_id)
                    .await?;
            let existing =
                store
                    .get(&dedup_key)
                    .ok_or(AdapterError::Store(StoreError::InvalidField {
                        field: "notification.notification_id",
                        reason: "unknown notification",
                    }))?;
            if !existing.delivery_channels.contains(&channel_typed) {
                return Err(AdapterError::Store(StoreError::InvalidField {
                    field: "notification.channel",
                    reason: "channel is not declared on the record",
                }));
            }
            let record = store
                .record_delivery(&dedup_key, delivery)
                .map_err(|error| model_error(&error))?
                .clone();
            let mut history = current.history.clone();
            history.push(history_entry);
            Ok(write_for(
                &dedup_key,
                &record,
                history,
                &transition.state_fence,
                Some(current.revision),
            ))
        }
        DecodedNotificationMutation::Acknowledge {
            notification_id,
            principal,
        } => {
            let (dedup_key, mut store, current) =
                resolve_current_for_leg(db, config, &transition.state_fence, &notification_id)
                    .await?;
            let record = store
                .acknowledge(&dedup_key, &principal)
                .map_err(|error| model_error(&error))?
                .clone();
            let mut history = current.history.clone();
            history.push(history_entry);
            Ok(write_for(
                &dedup_key,
                &record,
                history,
                &transition.state_fence,
                Some(current.revision),
            ))
        }
        DecodedNotificationMutation::Resolve {
            notification_id,
            disposition,
            authorization_json,
        } => {
            let (dedup_key, mut store, current) =
                resolve_current_for_leg(db, config, &transition.state_fence, &notification_id)
                    .await?;
            let authorization: ResolutionAuthorization = serde_json::from_value(authorization_json)
                .map_err(|error| {
                    AdapterError::Store(StoreError::Serialization(error.to_string()))
                })?;
            let record = store
                .resolve(&dedup_key, &disposition, &authorization)
                .map_err(|error| model_error(&error))?
                .clone();
            let mut history = current.history.clone();
            history.push(history_entry);
            Ok(write_for(
                &dedup_key,
                &record,
                history,
                &transition.state_fence,
                Some(current.revision),
            ))
        }
    }
}

/// Resolves the stored row for a lifecycle leg: identity lookup, model
/// rehydration, and admission-fence agreement. Unknown identities and
/// fenced-out rows fail closed here, never inside the model.
async fn resolve_current_for_leg(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    fence: &StateFence,
    notification_id: &str,
) -> Result<(String, NotificationStore, StoredNotificationRow), AdapterError> {
    let current = read_row_by_notification_id(db, config, notification_id)
        .await?
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "notification.notification_id",
            reason: "unknown notification",
        }))?;
    let store = rehydrate(Some(&current))?;
    let existing =
        store
            .get(&current.dedup_key)
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "notification.notification_id",
                reason: "unknown notification",
            }))?;
    if existing.state_fence != *fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    Ok((current.dedup_key.clone(), store, current))
}

/// Rehydrates the shared model by replaying the stored leg history.
///
/// Deterministic: replaying the exact admitted legs through a fresh model
/// reproduces occurrences, revisions, delivery, acknowledgement, and
/// resolution exactly, so the single transition implementation serves both
/// the reference contour and this bridge. Admission-time checks (fences,
/// channels, receipt validity) are enforced by the admitting path and are
/// not re-decided here; replay fails closed on any undecodable leg.
fn rehydrate(current: Option<&StoredNotificationRow>) -> Result<NotificationStore, AdapterError> {
    use eliot_store_api::DecodedNotificationMutation as Leg;

    let mut store = NotificationStore::new();
    let Some(row) = current else {
        return Ok(store);
    };
    for leg in &row.history {
        let params = leg
            .as_object()
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "notification.history",
                reason: "stored leg must be a parameter map",
            }))?;
        let decoded = decode_notification_mutation(
            &params.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        )
        .map_err(AdapterError::Store)?;
        match decoded {
            Leg::Upsert {
                record_json,
                source_receipt_json,
                ..
            } => {
                let draft: NotificationDraft =
                    serde_json::from_value(record_json).map_err(|error| {
                        AdapterError::Store(StoreError::Serialization(error.to_string()))
                    })?;
                let source_receipt: ReceiptEnvelope = serde_json::from_value(source_receipt_json)
                    .map_err(|error| {
                    AdapterError::Store(StoreError::Serialization(error.to_string()))
                })?;
                source_receipt
                    .validate()
                    .map_err(|_| AdapterError::Store(StoreError::InvalidReceipt))?;
                store.upsert(draft).map_err(|error| model_error(&error))?;
            }
            Leg::Delivery {
                notification_id,
                delivery_json,
                ..
            } => {
                let key = notification_key_for(&store, &notification_id)?;
                let delivery: eliot_kernel_core::DeliveryState =
                    serde_json::from_value(delivery_json).map_err(|error| {
                        AdapterError::Store(StoreError::Serialization(error.to_string()))
                    })?;
                store
                    .record_delivery(&key, delivery)
                    .map_err(|error| model_error(&error))?;
            }
            Leg::Acknowledge {
                notification_id,
                principal,
            } => {
                let key = notification_key_for(&store, &notification_id)?;
                store
                    .acknowledge(&key, &principal)
                    .map_err(|error| model_error(&error))?;
            }
            Leg::Resolve {
                notification_id,
                disposition,
                authorization_json,
            } => {
                let key = notification_key_for(&store, &notification_id)?;
                let authorization: ResolutionAuthorization =
                    serde_json::from_value(authorization_json).map_err(|error| {
                        AdapterError::Store(StoreError::Serialization(error.to_string()))
                    })?;
                store
                    .resolve(&key, &disposition, &authorization)
                    .map_err(|error| model_error(&error))?;
            }
        }
    }
    Ok(store)
}

fn notification_key_for(
    store: &NotificationStore,
    notification_id: &str,
) -> Result<String, AdapterError> {
    store
        .iter()
        .find(|record| record.notification_id.as_str() == notification_id)
        .map(|record| record.dedup_key.clone())
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "notification.notification_id",
            reason: "unknown notification",
        }))
}

fn write_for(
    dedup_key: &str,
    record: &eliot_kernel_core::Notification,
    history: Vec<Value>,
    fence: &StateFence,
    expected_revision: Option<u64>,
) -> SurrealNotificationWrite {
    let record_value = serde_json::to_value(record).unwrap_or(Value::Null);
    SurrealNotificationWrite {
        dedup_key: dedup_key.to_owned(),
        record: record_value,
        history: Value::Array(history),
        revision: record.revision,
        state_fence: fence.clone(),
        expected_revision,
    }
}

fn model_error(error: &NotificationError) -> AdapterError {
    use eliot_kernel_core::NotificationError;
    match error {
        NotificationError::InvalidField(field) => AdapterError::Store(StoreError::InvalidField {
            field,
            reason: "shared model rejected the notification",
        }),
        NotificationError::UnknownNotification => AdapterError::Store(StoreError::InvalidField {
            field: "notification.dedup_key",
            reason: "unknown notification",
        }),
        NotificationError::IdentityConflict => AdapterError::Store(StoreError::IdentityConflict),
        NotificationError::AlreadyResolved => AdapterError::Store(StoreError::InvalidField {
            field: "notification.resolution",
            reason: "record is already resolved",
        }),
        NotificationError::ResolutionRequiresEvidence => {
            AdapterError::Store(StoreError::InvalidField {
                field: "notification.evidence_handles",
                reason: "resolution requires evidence",
            })
        }
        NotificationError::ResolutionRequiresAuthorization
        | NotificationError::InvalidResolutionReceipt => {
            AdapterError::Store(StoreError::InvalidReceipt)
        }
        NotificationError::ResolutionAuthorityInsufficient => {
            AdapterError::Store(StoreError::EffectCeilingExceeded)
        }
        NotificationError::ResolutionEvidenceUnbound => {
            AdapterError::Store(StoreError::InvalidField {
                field: "notification.evidence_handles",
                reason: "resolution evidence is not bound by the authority receipt",
            })
        }
        NotificationError::ResolutionFenceMismatch => {
            AdapterError::Store(StoreError::FenceMismatch)
        }
    }
}

async fn read_notification_row(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    dedup_key: &str,
) -> Result<Option<StoredNotificationRow>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "notify_table".to_owned(),
        json!(crate::schema::table::NOTIFICATION_RECORD),
    );
    bindings.insert("notify_key".to_owned(), json!(dedup_key));
    let statement = "SELECT * FROM ONLY type::record($notify_table, $notify_key);";
    let mut response =
        client::query(db, config, "notification.read_row", statement, bindings).await?;
    let errors = response.take_errors();
    if missing_notification_table(&errors) {
        return Ok(None);
    }
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let row: Option<Value> = response.take(0)?;
    row.as_ref().map(decode_notification_row).transpose()
}

/// Reports whether provider errors prove only that the notification table
/// has no rows yet (fresh database, no migration): a missing table carries
/// no rows, so empty is exact truth here rather than an inference. Any
/// other error stays a partial outcome.
pub(crate) fn missing_notification_table(errors: &[String]) -> bool {
    !errors.is_empty()
        && errors
            .iter()
            .all(|error| error.contains("notification_record") && error.contains("does not exist"))
}

async fn read_row_by_notification_id(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    notification_id: &str,
) -> Result<Option<StoredNotificationRow>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "notify_table".to_owned(),
        json!(crate::schema::table::NOTIFICATION_RECORD),
    );
    bindings.insert("notify_identity".to_owned(), json!(notification_id));
    let statement =
        "SELECT * FROM notification_record WHERE record.notification_id = $notify_identity;";
    let mut response = client::query(
        db,
        config,
        "notification.resolve_identity",
        statement,
        bindings,
    )
    .await?;
    let errors = response.take_errors();
    if missing_notification_table(&errors) {
        return Ok(None);
    }
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let rows: Vec<Value> = response.take(0)?;
    let mut rows = rows.iter();
    let first = rows.next().map(decode_notification_row).transpose()?;
    if rows.next().is_some() {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    Ok(first)
}

fn decode_notification_row(value: &Value) -> Result<StoredNotificationRow, AdapterError> {
    let object = value
        .as_object()
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "notification.row",
            reason: "notification row must be an object",
        }))?;
    let text_field = |name: &str| -> Result<String, AdapterError> {
        object
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "notification.row",
                reason: "notification row is missing a text field",
            }))
    };
    let dedup_key = text_field("dedup_key")?;
    let record = object.get("record").cloned().unwrap_or(Value::Null);
    let history = object
        .get("history")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let revision = object.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let state_fence: StateFence =
        serde_json::from_value(object.get("state_fence").cloned().unwrap_or(Value::Null))
            .map_err(|error| AdapterError::Store(StoreError::Serialization(error.to_string())))?;
    Ok(StoredNotificationRow {
        dedup_key,
        record,
        history,
        revision,
        state_fence,
    })
}

/// Builds the canonical-transaction fragment persisting notification rows.
///
/// One compare-and-set per write: creates refuse when a row already exists,
/// updates refuse on missing rows or revision drift. Drift classifies as
/// allocation contention so the apply loop recomputes from fresh rows.
pub(crate) fn notification_write_statements(
    writes: &[SurrealNotificationWrite],
) -> (String, Map<String, Value>) {
    let mut sql = String::new();
    let mut bindings = Map::new();
    for (index, write) in writes.iter().enumerate() {
        let suffix = index.to_string();
        if write.expected_revision.is_some() {
            sql.push_str(
                "LET $notify_current_{s} = (SELECT revision FROM ONLY type::record($notify_table_{s}, $notify_key_{s})); IF type::is_object($notify_current_{s}) { IF $notify_current_{s}.revision != $notify_expected_{s} { THROW 'notification_revision_conflict'; } ELSE { UPDATE type::record($notify_table_{s}, $notify_key_{s}) CONTENT $notify_record_{s}; }; } ELSE { THROW 'notification_revision_conflict'; };"
                    .replace("{s}", &suffix)
                    .as_str(),
            );
        } else {
            sql.push_str(
                "LET $notify_current_{s} = (SELECT revision FROM ONLY type::record($notify_table_{s}, $notify_key_{s})); IF type::is_object($notify_current_{s}) { THROW 'notification_revision_conflict'; } ELSE { CREATE type::record($notify_table_{s}, $notify_key_{s}) CONTENT $notify_record_{s}; };"
                    .replace("{s}", &suffix)
                    .as_str(),
            );
        }
        bindings.insert(
            format!("notify_table_{suffix}"),
            json!(schema::table::NOTIFICATION_RECORD),
        );
        bindings.insert(format!("notify_key_{suffix}"), json!(&write.dedup_key));
        bindings.insert(
            format!("notify_expected_{suffix}"),
            json!(write.expected_revision),
        );
        bindings.insert(
            format!("notify_record_{suffix}"),
            json!({
                "dedup_key": write.dedup_key,
                "record": write.record,
                "history": write.history,
                "revision": write.revision,
                "state_fence": write.state_fence,
            }),
        );
    }
    (sql, bindings)
}

#[cfg(test)]
mod template_tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use std::num::NonZeroU64;

    fn test_fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
                NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn write(key: &str, expected: Option<u64>) -> SurrealNotificationWrite {
        SurrealNotificationWrite {
            dedup_key: key.to_owned(),
            record: json!({"dedup_key": key}),
            history: Value::Array(Vec::new()),
            revision: 1,
            state_fence: test_fence(),
            expected_revision: expected,
        }
    }

    #[test]
    fn create_and_update_fragments_carry_cas_guards() {
        let (sql, bindings) =
            notification_write_statements(&[write("new-key", None), write("old-key", Some(3))]);
        assert!(
            sql.contains("THROW 'notification_revision_conflict'"),
            "both legs guard revision drift"
        );
        assert!(
            sql.contains("CREATE type::record($notify_table_0"),
            "create leg creates"
        );
        assert!(
            sql.contains("UPDATE type::record($notify_table_1"),
            "update leg updates"
        );
        for name in [
            "notify_table_0",
            "notify_key_0",
            "notify_record_0",
            "notify_table_1",
            "notify_key_1",
            "notify_expected_1",
            "notify_record_1",
        ] {
            assert!(bindings.contains_key(name), "binding travels: {name}");
        }
        assert_eq!(
            bindings.get("notify_key_0"),
            Some(&json!("new-key")),
            "create leg keys the dedup index"
        );
    }
}
