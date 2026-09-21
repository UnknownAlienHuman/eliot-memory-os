//! Canonical reactive-state execution for the `SurrealDB` bridge
//! (issue #1941 C4).
//!
//! Mirrors the reference contour's closed operations through the
//! store-api wire contract, persisted in two tables: `reactive_session`
//! holds one row per session carrying the verbatim bridge ledger snapshot,
//! the owner revision, and the admission fence with task-binding
//! provenance; `resource_snapshot` holds one row per canonical URI
//! carrying the content digest, the verbatim base64 bytes, the owner
//! revision, and the admission fence. Concurrent ledger writers arbitrate
//! through the in-transaction revision compare-and-set inside the
//! canonical transaction; retries recompute from fresh rows, never from
//! stale reads. Snapshot rows are immutable: a rewrite with different
//! bytes fails closed before the transaction, and a create race converges
//! through the same contention retry. Row writes commit inside the
//! canonical transaction beside the receipt and outbox rows, so rows,
//! receipt, and outbox stay atomic.

use eliot_store_api::{
    DecodedReactiveMutation, NamedMutationOperation, StateFence, StoreError, TransitionClass,
    decode_reactive_mutation,
};
use serde_json::{Map, Value, json};

use crate::SurrealAdapterConfig;
use crate::client::{self, RpcTransport};
use crate::error::AdapterError;
use crate::schema;

/// One computed reactive-session row write for the canonical transaction.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ReactiveSessionWrite {
    /// Kernel-owned activation-sealed session binding (record id).
    pub session_id: String,
    /// Verbatim canonical ledger-snapshot JSON.
    pub ledger_json: String,
    /// Owner revision after this write.
    pub revision: u64,
    /// Admission fence of the transition.
    pub state_fence: StateFence,
    /// Scope provenance from the transition envelope.
    pub scope_id: String,
    /// Task-binding provenance from the transition envelope, when bound.
    pub task_id: Option<String>,
    /// Revision observed at pre-transaction read (`None` for creates).
    pub expected_revision: Option<u64>,
}

/// One computed resource-snapshot row write for the canonical transaction.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ResourceSnapshotWrite {
    /// Canonical `eliot://` resource identity (record id).
    pub uri: String,
    /// Lowercase SHA-256 hex of the exact snapshot bytes.
    pub content_sha256: String,
    /// Verbatim base64 snapshot bytes.
    pub content_base64: String,
    /// Owner revision (1 on create; unchanged on convergent re-apply).
    pub revision: u64,
    /// Admission fence of the transition.
    pub state_fence: StateFence,
    /// Scope provenance from the transition envelope.
    pub scope_id: String,
    /// Task-binding provenance from the transition envelope, when bound.
    pub task_id: Option<String>,
}

/// Computed reactive row writes for one admitted transition.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ReactiveWrites {
    /// Ledger upserts in admitted command order.
    pub sessions: Vec<ReactiveSessionWrite>,
    /// Snapshot creates in admitted command order.
    pub snapshots: Vec<ResourceSnapshotWrite>,
}

/// Stored reactive-session row shape as projected by reads.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StoredReactiveSession {
    /// Kernel-owned activation-sealed session binding.
    pub session_id: String,
    /// Verbatim canonical ledger-snapshot JSON.
    pub ledger_json: String,
    /// Owner revision.
    pub revision: u64,
    /// Admission fence.
    pub state_fence: StateFence,
}

/// Stored resource-snapshot row shape as projected by reads.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StoredResourceSnapshot {
    /// Canonical `eliot://` resource identity.
    pub uri: String,
    /// Lowercase SHA-256 hex of the exact snapshot bytes.
    pub content_sha256: String,
    /// Verbatim base64 snapshot bytes.
    pub content_base64: String,
    /// Owner revision.
    pub revision: u64,
    /// Admission fence.
    pub state_fence: StateFence,
}

/// Ensures the reactive tables exist (idempotent).
///
/// Schemaless tables auto-create on write, but reads and the
/// in-transaction compare-and-set fail closed on missing tables. This
/// one-shot definition keeps first use on a fresh database exact; it
/// changes no migration chain and carries no data.
async fn ensure_reactive_tables(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<(), AdapterError> {
    let sql = format!(
        "DEFINE TABLE IF NOT EXISTS {} SCHEMALESS; DEFINE TABLE IF NOT EXISTS {} SCHEMALESS;",
        crate::schema::table::REACTIVE_SESSION,
        crate::schema::table::RESOURCE_SNAPSHOT
    );
    let mut response =
        client::query(db, config, "reactive.ensure_tables", &sql, Map::new()).await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}

/// Computes reactive row writes for one admitted transition.
///
/// Reads current rows, validates every command through the shared wire
/// contract (contract stamp, bounds, URI grammar, digest agreement), and
/// returns the resulting writes with their expected revisions for the
/// in-transaction compare-and-set. Transitions without reactive
/// operations yield no writes. Pure reads plus pure compute: rows are
/// written only by the canonical transaction.
pub(crate) async fn prepare_reactive_writes(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<ReactiveWrites, AdapterError> {
    let mut writes = ReactiveWrites::default();
    let mut commanded = false;
    for command in &transition.named_operations {
        if matches!(
            command.operation,
            NamedMutationOperation::ApplyReactiveInjectionState
                | NamedMutationOperation::ApplyResourceSnapshot
        ) {
            commanded = true;
        }
    }
    if !commanded {
        return Ok(writes);
    }
    if transition.transition_class != TransitionClass::ReactiveState {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    // The tables are schemaless and auto-create on write, but reads and
    // the in-transaction compare-and-set fail closed on missing tables
    // instead of reading empty. Ensuring them here (idempotent) keeps
    // first use on a fresh database exact without a schema-migration bump.
    ensure_reactive_tables(db, config).await?;
    for command in &transition.named_operations {
        let decoded = match command.operation {
            NamedMutationOperation::ApplyReactiveInjectionState
            | NamedMutationOperation::ApplyResourceSnapshot => {
                decode_reactive_mutation(command.operation, &command.parameters)
                    .map_err(AdapterError::Store)?
            }
            _ => continue,
        };
        match decoded {
            DecodedReactiveMutation::ApplyLedger {
                session_id,
                ledger_json,
            } => {
                let current = read_reactive_row(db, config, &session_id).await?;
                if let Some(row) = &current
                    && row.state_fence != transition.state_fence
                {
                    return Err(AdapterError::Store(StoreError::FenceMismatch));
                }
                let expected_revision = current.as_ref().map(|row| row.revision);
                let revision = checked_revision(expected_revision)?;
                writes.sessions.push(ReactiveSessionWrite {
                    session_id,
                    ledger_json,
                    revision,
                    state_fence: transition.state_fence.clone(),
                    scope_id: transition.scope_id.to_string(),
                    task_id: transition.task_id.clone(),
                    expected_revision,
                });
            }
            DecodedReactiveMutation::ApplySnapshot {
                uri,
                content_sha256,
                content_base64,
            } => {
                // The wire contract already proved digest agreement; the
                // decoded bytes are re-checked here so the row write never
                // trusts a presented digest it did not recompute.
                let bytes =
                    eliot_store_api::decode_resource_content(&content_base64, &content_sha256)
                        .map_err(AdapterError::Store)?;
                debug_assert_eq!(eliot_store_api::sha256_hex(&bytes), content_sha256);
                match read_snapshot_row(db, config, &uri).await? {
                    None => writes.snapshots.push(ResourceSnapshotWrite {
                        uri,
                        content_sha256,
                        content_base64,
                        revision: 1,
                        state_fence: transition.state_fence.clone(),
                        scope_id: transition.scope_id.to_string(),
                        task_id: transition.task_id.clone(),
                    }),
                    Some(row) if row.state_fence != transition.state_fence => {
                        return Err(AdapterError::Store(StoreError::FenceMismatch));
                    }
                    Some(row) if row.content_sha256 != content_sha256 => {
                        return Err(AdapterError::Store(StoreError::IdentityConflict));
                    }
                    // Convergent re-apply of identical bytes: the row write
                    // below still guards the digest in-transaction, so a
                    // racing divergent commit surfaces as contention and
                    // retries into the deterministic conflict above instead
                    // of committing over changed bytes.
                    Some(row) => writes.snapshots.push(ResourceSnapshotWrite {
                        uri,
                        content_sha256,
                        content_base64,
                        revision: row.revision,
                        state_fence: transition.state_fence.clone(),
                        scope_id: transition.scope_id.to_string(),
                        task_id: transition.task_id.clone(),
                    }),
                }
            }
        }
    }
    Ok(writes)
}

fn checked_revision(expected: Option<u64>) -> Result<u64, AdapterError> {
    match expected {
        None => Ok(1),
        Some(current) => {
            current
                .checked_add(1)
                .ok_or(AdapterError::Store(StoreError::InvalidField {
                    field: "reactive.revision",
                    reason: "owner revision overflow",
                }))
        }
    }
}

async fn read_reactive_row(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    session_id: &str,
) -> Result<Option<StoredReactiveSession>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "reactive_table".to_owned(),
        json!(crate::schema::table::REACTIVE_SESSION),
    );
    bindings.insert("reactive_key".to_owned(), json!(session_id));
    let statement = "SELECT * FROM ONLY type::record($reactive_table, $reactive_key);";
    let mut response = client::query(db, config, "reactive.read_row", statement, bindings).await?;
    let errors = response.take_errors();
    if missing_reactive_table(&errors) {
        return Ok(None);
    }
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let row: Option<Value> = response.take(0)?;
    row.as_ref().map(decode_reactive_row).transpose()
}

async fn read_snapshot_row(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    uri: &str,
) -> Result<Option<StoredResourceSnapshot>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "snapshot_table".to_owned(),
        json!(crate::schema::table::RESOURCE_SNAPSHOT),
    );
    bindings.insert("snapshot_key".to_owned(), json!(uri));
    let statement = "SELECT * FROM ONLY type::record($snapshot_table, $snapshot_key);";
    let mut response =
        client::query(db, config, "reactive.read_snapshot", statement, bindings).await?;
    let errors = response.take_errors();
    if missing_reactive_table(&errors) {
        return Ok(None);
    }
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let row: Option<Value> = response.take(0)?;
    row.as_ref().map(decode_snapshot_row).transpose()
}

/// Reports whether provider errors prove only that a reactive table has
/// no rows yet (fresh database, no migration): a missing table carries
/// no rows, so empty is exact truth here rather than an inference. Any
/// other error stays a partial outcome.
pub(crate) fn missing_reactive_table(errors: &[String]) -> bool {
    !errors.is_empty()
        && errors.iter().all(|error| {
            error.contains("does not exist")
                && (error.contains(schema::table::REACTIVE_SESSION)
                    || error.contains(schema::table::RESOURCE_SNAPSHOT))
        })
}

fn text_row_field(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<String, AdapterError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "reactive.row",
            reason: "reactive row is missing a text field",
        }))
}

fn decode_reactive_row(value: &Value) -> Result<StoredReactiveSession, AdapterError> {
    let object = value
        .as_object()
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "reactive.row",
            reason: "reactive row must be an object",
        }))?;
    let session_id = text_row_field(object, "session_id")?;
    let ledger_json = text_row_field(object, "ledger_json")?;
    let revision = object.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let state_fence: StateFence =
        serde_json::from_value(object.get("state_fence").cloned().unwrap_or(Value::Null))
            .map_err(|error| AdapterError::Store(StoreError::Serialization(error.to_string())))?;
    Ok(StoredReactiveSession {
        session_id,
        ledger_json,
        revision,
        state_fence,
    })
}

fn decode_snapshot_row(value: &Value) -> Result<StoredResourceSnapshot, AdapterError> {
    let object = value
        .as_object()
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "reactive.row",
            reason: "snapshot row must be an object",
        }))?;
    let uri = text_row_field(object, "uri")?;
    let content_sha256 = text_row_field(object, "content_sha256")?;
    let content_base64 = text_row_field(object, "content_base64")?;
    let revision = object.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let state_fence: StateFence =
        serde_json::from_value(object.get("state_fence").cloned().unwrap_or(Value::Null))
            .map_err(|error| AdapterError::Store(StoreError::Serialization(error.to_string())))?;
    Ok(StoredResourceSnapshot {
        uri,
        content_sha256,
        content_base64,
        revision,
        state_fence,
    })
}

/// Builds the canonical-transaction fragment persisting reactive rows.
///
/// One compare-and-set per session write: creates refuse when a row
/// already exists, updates refuse on missing rows or revision drift.
/// Snapshot writes are create-or-converge: missing rows create, identical
/// rows pass silently, divergent rows abort the transaction (a create race
/// converges through retry into the deterministic pre-transaction
/// conflict). Drift surfaces the `reactive_session_conflict` /
/// `reactive_snapshot_conflict` markers so the apply loop retries with
/// fresh rows. Rows commit in the same transaction as the receipt and
/// outbox rows, so rows, receipt, and outbox stay atomic.
pub(crate) fn reactive_write_statements(writes: &ReactiveWrites) -> (String, Map<String, Value>) {
    let mut sql = String::new();
    let mut bindings = Map::new();
    for (index, write) in writes.sessions.iter().enumerate() {
        let suffix = format!("session_{index}");
        if write.expected_revision.is_some() {
            sql.push_str(
                "LET $reactive_current_{s} = (SELECT revision FROM ONLY type::record($reactive_table_{s}, $reactive_key_{s})); IF type::is_object($reactive_current_{s}) { IF $reactive_current_{s}.revision != $reactive_expected_{s} { THROW 'reactive_session_conflict'; } ELSE { UPDATE type::record($reactive_table_{s}, $reactive_key_{s}) CONTENT $reactive_record_{s}; }; } ELSE { THROW 'reactive_session_conflict'; };"
                    .replace("{s}", &suffix)
                    .as_str(),
            );
        } else {
            sql.push_str(
                "LET $reactive_current_{s} = (SELECT revision FROM ONLY type::record($reactive_table_{s}, $reactive_key_{s})); IF type::is_object($reactive_current_{s}) { THROW 'reactive_session_conflict'; } ELSE { CREATE type::record($reactive_table_{s}, $reactive_key_{s}) CONTENT $reactive_record_{s}; };"
                    .replace("{s}", &suffix)
                    .as_str(),
            );
        }
        bindings.insert(
            format!("reactive_table_{suffix}"),
            json!(schema::table::REACTIVE_SESSION),
        );
        bindings.insert(format!("reactive_key_{suffix}"), json!(&write.session_id));
        bindings.insert(
            format!("reactive_expected_{suffix}"),
            json!(write.expected_revision),
        );
        bindings.insert(
            format!("reactive_record_{suffix}"),
            json!({
                "session_id": write.session_id,
                "ledger_json": write.ledger_json,
                "revision": write.revision,
                "state_fence": write.state_fence,
                "scope_id": write.scope_id,
                "task_id": write.task_id,
            }),
        );
    }
    for (index, write) in writes.snapshots.iter().enumerate() {
        let suffix = format!("snapshot_{index}");
        sql.push_str(
            "LET $snapshot_current_{s} = (SELECT content_sha256 FROM ONLY type::record($snapshot_table_{s}, $snapshot_key_{s})); IF type::is_object($snapshot_current_{s}) { IF $snapshot_current_{s}.content_sha256 != $snapshot_expected_{s} { THROW 'reactive_snapshot_conflict'; }; } ELSE { CREATE type::record($snapshot_table_{s}, $snapshot_key_{s}) CONTENT $snapshot_record_{s}; };"
                .replace("{s}", &suffix)
                .as_str(),
        );
        bindings.insert(
            format!("snapshot_table_{suffix}"),
            json!(schema::table::RESOURCE_SNAPSHOT),
        );
        bindings.insert(format!("snapshot_key_{suffix}"), json!(&write.uri));
        bindings.insert(
            format!("snapshot_expected_{suffix}"),
            json!(&write.content_sha256),
        );
        bindings.insert(
            format!("snapshot_record_{suffix}"),
            json!({
                "uri": write.uri,
                "content_sha256": write.content_sha256,
                "content_base64": write.content_base64,
                "revision": write.revision,
                "state_fence": write.state_fence,
                "scope_id": write.scope_id,
                "task_id": write.task_id,
            }),
        );
    }
    (sql, bindings)
}

/// Reads one reactive-session row for the ledger read path.
pub(crate) async fn read_session_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    session_id: &str,
) -> Result<Option<StoredReactiveSession>, AdapterError> {
    read_reactive_row(db, config, session_id).await
}

/// Reads one resource-snapshot row for the snapshot read path.
pub(crate) async fn read_snapshot_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    uri: &str,
) -> Result<Option<StoredResourceSnapshot>, AdapterError> {
    read_snapshot_row(db, config, uri).await
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

    fn writes() -> ReactiveWrites {
        ReactiveWrites {
            sessions: vec![
                ReactiveSessionWrite {
                    session_id: "session-new".to_owned(),
                    ledger_json:
                        r#"{"contract":"eliot.agent-bridge.reactive-injection-receipts/v1"}"#
                            .to_owned(),
                    revision: 1,
                    state_fence: test_fence(),
                    scope_id: "scope-1".to_owned(),
                    task_id: None,
                    expected_revision: None,
                },
                ReactiveSessionWrite {
                    session_id: "session-old".to_owned(),
                    ledger_json:
                        r#"{"contract":"eliot.agent-bridge.reactive-injection-receipts/v1"}"#
                            .to_owned(),
                    revision: 4,
                    state_fence: test_fence(),
                    scope_id: "scope-1".to_owned(),
                    task_id: Some("task-1".to_owned()),
                    expected_revision: Some(3),
                },
            ],
            snapshots: vec![ResourceSnapshotWrite {
                uri: "eliot://report/r-1".to_owned(),
                content_sha256: "a".repeat(64),
                content_base64: "Ynl0ZXM=".to_owned(),
                revision: 1,
                state_fence: test_fence(),
                scope_id: "scope-1".to_owned(),
                task_id: None,
            }],
        }
    }

    #[test]
    fn fragments_carry_cas_guards_and_verbatim_rows() {
        let (sql, bindings) = reactive_write_statements(&writes());
        assert!(
            sql.contains("THROW 'reactive_session_conflict'"),
            "session legs guard revision drift"
        );
        assert!(
            sql.contains("THROW 'reactive_snapshot_conflict'"),
            "snapshot legs guard create races"
        );
        assert!(
            sql.contains("CREATE type::record($reactive_table_session_0"),
            "session create leg creates"
        );
        assert!(
            sql.contains("UPDATE type::record($reactive_table_session_1"),
            "session update leg updates"
        );
        assert!(
            sql.contains("CREATE type::record($snapshot_table_snapshot_0"),
            "snapshot leg creates"
        );
        for name in [
            "reactive_table_session_0",
            "reactive_key_session_0",
            "reactive_record_session_0",
            "reactive_table_session_1",
            "reactive_key_session_1",
            "reactive_record_session_1",
            "reactive_expected_session_1",
            "snapshot_table_snapshot_0",
            "snapshot_key_snapshot_0",
            "snapshot_record_snapshot_0",
            "snapshot_expected_snapshot_0",
        ] {
            assert!(bindings.contains_key(name), "binding travels: {name}");
        }
        assert_eq!(
            bindings.get("reactive_key_session_0"),
            Some(&json!("session-new")),
            "create leg keys the session index"
        );
        // The snapshot create refuses a divergent rewrite in-transaction:
        // same bytes pass silently, different bytes abort the transaction.
        assert!(
            sql.contains(
                "$snapshot_current_snapshot_0.content_sha256 != $snapshot_expected_snapshot_0"
            ),
            "snapshot create converges on identical bytes only"
        );
    }

    #[test]
    fn missing_table_errors_are_exact() {
        assert!(
            missing_reactive_table(&["table reactive_session does not exist".to_owned()]),
            "session table absence reads empty"
        );
        assert!(
            missing_reactive_table(&["table resource_snapshot does not exist".to_owned()]),
            "snapshot table absence reads empty"
        );
        assert!(
            !missing_reactive_table(&["table write_receipt does not exist".to_owned()]),
            "foreign table absence is not reactive evidence"
        );
        assert!(
            !missing_reactive_table(&["boom".to_owned()]),
            "unrelated errors stay partial outcomes"
        );
        assert!(!missing_reactive_table(&[]), "empty sets never classify");
    }
}
