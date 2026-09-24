//! Canonical learning-record execution for the `SurrealDB` bridge
//! (issue #1868).
//!
//! Mirrors the experience contour's closed leg through the store-api wire
//! contract, persisted in one table: `learning_record` holds one
//! immutable row per complete kind/handle/record-digest/scope/fence/expiry
//! identity carrying the verbatim learning-record document. Documents stay
//! opaque: lineage, sequencing, and digest re-proof are Governor-owned, and
//! this module arbitrates keys and immutability only. Concurrent writers arbitrate
//! through the in-transaction compare-and-set inside the canonical
//! transaction; retries recompute from fresh rows, never from stale
//! reads. Rows commit inside the canonical transaction beside the receipt
//! and outbox rows, so rows, receipt, and outbox stay atomic.
//!
//! Rows are addressed by a joined immutable identity containing the closed
//! record kind, handle, record digest, exact scope identity and digest,
//! exact State Fence digest, and expiry deadline. The join is
//! collision-free by construction: the wire contract admits closed
//! record-kind and fixed-shape digest values and rejects control characters
//! in text parts, so the unit separator can never occur inside a part. The
//! parts also travel as separate row fields, so no reader parses the address.
//!
//! A new complete identity is a new row, never an in-place rewrite;
//! identical replays converge and divergent same-key rewrites fail closed.

use eliot_store_api::{
    DecodedLearningMutation, NamedMutationOperation, StateFence, StoreError, TransitionClass,
    decode_learning_mutation, learning_fence_digest, learning_scope_digest,
};
use serde_json::{Map, Value, json};

use crate::SurrealAdapterConfig;
use crate::client::{self, RpcTransport};
use crate::error::AdapterError;
use crate::schema;

/// Joins one learning row address. Scope, fence digest, and expiry are part
/// of the immutable identity so a same-digest record cannot cross owner
/// contours by address reuse.
fn learning_row_key(
    record_kind: &str,
    handle: &str,
    record_digest: &str,
    scope_id: &str,
    scope_digest: &str,
    fence_digest: &str,
    expires_at_unix_ms: u64,
) -> String {
    format!(
        "{record_kind}\x1f{handle}\x1f{record_digest}\x1f{scope_id}\x1f{scope_digest}\x1f{fence_digest}\x1f{expires_at_unix_ms}"
    )
}

/// One computed learning-record row write for the canonical transaction.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LearningRecordWrite {
    /// Closed record-kind discriminator of the record.
    pub record_kind: String,
    /// Exact canonical handle of the record.
    pub handle: String,
    /// Verbatim canonical record document.
    pub record_json: String,
    /// Presented digest of the record bytes; part of the immutable identity.
    pub record_digest: String,
    /// Exact scope digest carried by the closed mutation.
    pub scope_digest: String,
    /// Exact fence digest carried by the closed mutation.
    pub fence_digest: String,
    /// Absolute expiry deadline.
    pub expires_at_unix_ms: u64,
    /// Admission fence of the transition.
    pub state_fence: StateFence,
    /// Scope provenance from the transition envelope.
    pub scope_id: String,
    /// Task-binding provenance from the transition envelope, when bound.
    pub task_id: Option<String>,
}

/// Computed learning row writes for one admitted transition.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct LearningWrites {
    /// Record-row creates in admitted command order.
    pub records: Vec<LearningRecordWrite>,
}

/// Stored learning row shape as projected by reads.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StoredLearningRecord {
    /// Closed record-kind discriminator of the record.
    pub record_kind: String,
    /// Exact canonical handle of the record.
    pub handle: String,
    /// Verbatim canonical record document.
    pub record_json: String,
    /// Presented digest of the record bytes.
    pub record_digest: String,
    /// Exact scope digest.
    pub scope_digest: String,
    /// Exact fence digest.
    pub fence_digest: String,
    /// Absolute expiry deadline.
    pub expires_at_unix_ms: u64,
    /// Admission fence.
    pub state_fence: StateFence,
    /// Exact scope identity carried by the immutable row.
    pub scope_id: String,
}

/// Ensures the learning table exists (idempotent).
///
/// A schemaless table auto-creates on write, but reads and the
/// in-transaction compare-and-set fail closed on a missing table. This
/// one-shot definition keeps first use on a fresh database exact; it
/// changes no migration chain and carries no data.
async fn ensure_learning_tables(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<(), AdapterError> {
    let sql = format!(
        "DEFINE TABLE IF NOT EXISTS {} SCHEMALESS;",
        crate::schema::table::LEARNING_RECORD
    );
    let mut response =
        client::query(db, config, "learning.ensure_tables", &sql, Map::new()).await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}

/// Computes learning row writes for one admitted transition.
///
/// Reads no rows: learning rows are create-or-converge keyed by joined
/// record kind, handle, and digest, so the in-transaction
/// compare-and-set arbitrates concurrent writers without
/// pre-transaction reads. Transitions without learning operations yield
/// no writes. The table is ensured (idempotent) so first use on a fresh
/// database is exact.
pub(crate) async fn prepare_learning_writes(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<LearningWrites, AdapterError> {
    let mut commanded = false;
    for command in &transition.named_operations {
        if command.operation == NamedMutationOperation::RecordLearningRecord {
            commanded = true;
        }
    }
    if !commanded {
        return Ok(LearningWrites::default());
    }
    if transition.transition_class != TransitionClass::CaptureCandidate {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    ensure_learning_tables(db, config).await?;
    let mut writes = LearningWrites::default();
    for command in &transition.named_operations {
        let decoded = match command.operation {
            NamedMutationOperation::RecordLearningRecord => {
                decode_learning_mutation(command.operation, &command.parameters)
                    .map_err(AdapterError::Store)?
            }
            _ => continue,
        };
        let DecodedLearningMutation {
            record_kind,
            handle,
            record_json,
            record_digest,
            scope_digest,
            fence_digest,
            idempotency_key: _,
            expires_at_unix_ms,
        } = decoded;
        let expected_scope_digest = learning_scope_digest(transition.scope_id.as_str())?;
        let expected_fence_digest = learning_fence_digest(&transition.state_fence)?;
        if scope_digest != expected_scope_digest || fence_digest != expected_fence_digest {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "learning.scope_fence_binding",
                reason: "learning row digest does not match the canonical transition",
            }));
        }
        writes.records.push(LearningRecordWrite {
            record_kind: record_kind.as_str().to_owned(),
            handle,
            record_json,
            record_digest,
            scope_digest,
            fence_digest,
            expires_at_unix_ms,
            state_fence: transition.state_fence.clone(),
            scope_id: transition.scope_id.to_string(),
            task_id: transition.task_id.clone(),
        });
    }
    Ok(writes)
}

/// Builds the canonical-transaction fragment persisting learning rows.
///
/// Row writes are create-or-converge: missing rows create, identical rows
/// pass silently, divergent rows abort the transaction. Drift surfaces
/// the `learning_record_conflict` marker so the apply loop retries with
/// fresh rows. Rows commit in the same transaction as the receipt and
/// outbox rows, so rows, receipt, and outbox stay atomic.
pub(crate) fn learning_write_statements(writes: &LearningWrites) -> (String, Map<String, Value>) {
    let mut sql = String::new();
    let mut bindings = Map::new();
    for (index, write) in writes.records.iter().enumerate() {
        append_record_statement(&mut sql, &mut bindings, index, write);
    }
    (sql, bindings)
}

/// Appends one learning-row create-or-converge fragment.
fn append_record_statement(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    index: usize,
    write: &LearningRecordWrite,
) {
    let suffix = format!("learning_{index}");
    sql.push_str(
            "LET $learning_current_{s} = (SELECT record_json FROM ONLY type::record($learning_table_{s}, $learning_key_{s})); IF type::is_object($learning_current_{s}) { IF $learning_current_{s}.record_json != $learning_expected_{s} { THROW 'learning_record_conflict'; }; } ELSE { CREATE type::record($learning_table_{s}, $learning_key_{s}) CONTENT $learning_record_{s}; };"
                .replace("{s}", &suffix)
                .as_str(),
        );
    bindings.insert(
        format!("learning_table_{suffix}"),
        json!(schema::table::LEARNING_RECORD),
    );
    bindings.insert(
        format!("learning_key_{suffix}"),
        json!(learning_row_key(
            &write.record_kind,
            &write.handle,
            &write.record_digest,
            &write.scope_id,
            &write.scope_digest,
            &write.fence_digest,
            write.expires_at_unix_ms,
        )),
    );
    bindings.insert(
        format!("learning_expected_{suffix}"),
        json!(&write.record_json),
    );
    bindings.insert(
        format!("learning_record_{suffix}"),
        json!({
            "record_kind": write.record_kind,
            "handle": write.handle,
            "record_json": write.record_json,
            "record_digest": write.record_digest,
            "scope_digest": write.scope_digest,
            "fence_digest": write.fence_digest,
            "expires_at_unix_ms": write.expires_at_unix_ms,
            "state_fence": write.state_fence,
            "scope_id": write.scope_id,
            "task_id": write.task_id,
        }),
    );
}

/// Reports whether a provider statement error observes a missing
/// learning table. A missing table reads as empty, never as failure:
/// every error must narrate a nonexistent table naming the learning
/// table.
pub(crate) fn missing_learning_table(errors: &[String]) -> bool {
    !errors.is_empty()
        && errors.iter().all(|error| {
            error.contains("does not exist") && error.contains(schema::table::LEARNING_RECORD)
        })
}

fn text_row_field(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<String, AdapterError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field,
            reason: "learning row field must be present text",
        }))
}

fn expiry_row_field(object: &serde_json::Map<String, Value>) -> Result<u64, AdapterError> {
    object
        .get("expires_at_unix_ms")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "learning.expires_at_unix_ms",
            reason: "learning row expiry must be a positive integer",
        }))
}

fn fence_row_field(object: &serde_json::Map<String, Value>) -> Result<StateFence, AdapterError> {
    serde_json::from_value(
        object
            .get("state_fence")
            .cloned()
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "state_fence",
                reason: "learning row field must be present",
            }))?,
    )
    .map_err(|_| {
        AdapterError::Store(StoreError::InvalidField {
            field: "state_fence",
            reason: "learning row fence must decode",
        })
    })
}

fn decode_record_row(
    object: &serde_json::Map<String, Value>,
) -> Result<StoredLearningRecord, AdapterError> {
    Ok(StoredLearningRecord {
        record_kind: text_row_field(object, "record_kind")?,
        handle: text_row_field(object, "handle")?,
        record_json: text_row_field(object, "record_json")?,
        record_digest: text_row_field(object, "record_digest")?,
        scope_digest: text_row_field(object, "scope_digest")?,
        fence_digest: text_row_field(object, "fence_digest")?,
        expires_at_unix_ms: expiry_row_field(object)?,
        state_fence: fence_row_field(object)?,
        scope_id: text_row_field(object, "scope_id")?,
    })
}

/// Reads learning rows for the current query in key order.
///
/// Rows are scope-gated in the query; the optional kind filter narrows
/// to one closed record kind. The admission fence is arbitrated by the
/// caller in Rust, mirroring the experience reads.
pub(crate) async fn read_learning_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    scope_id: &str,
    kind_filter: Option<&str>,
    limit: usize,
) -> Result<Vec<StoredLearningRecord>, AdapterError> {
    let sql = if kind_filter.is_some() {
        format!(
            "SELECT * FROM {} WHERE scope_id = $learning_scope AND record_kind = $learning_kind ORDER BY record_kind, handle, record_digest, scope_digest, fence_digest, expires_at_unix_ms LIMIT {limit};",
            schema::table::LEARNING_RECORD
        )
    } else {
        format!(
            "SELECT * FROM {} WHERE scope_id = $learning_scope ORDER BY record_kind, handle, record_digest, scope_digest, fence_digest, expires_at_unix_ms LIMIT {limit};",
            schema::table::LEARNING_RECORD
        )
    };
    let mut bindings = Map::new();
    bindings.insert("learning_scope".to_owned(), json!(scope_id));
    if let Some(kind) = kind_filter {
        bindings.insert("learning_kind".to_owned(), json!(kind));
    }
    let mut response = client::query(db, config, "learning.read_records", &sql, bindings).await?;
    let errors = response.take_errors();
    if missing_learning_table(&errors) {
        return Ok(Vec::new());
    }
    if !errors.is_empty() {
        return Err(AdapterError::Store(StoreError::Serialization(
            "learning record snapshot query failed".to_owned(),
        )));
    }
    let rows: Vec<Value> = response.take(0)?;
    rows.into_iter()
        .map(|row| {
            row.as_object()
                .ok_or(AdapterError::Store(StoreError::InvalidField {
                    field: "learning.row",
                    reason: "learning record row must be an object",
                }))
                .and_then(decode_record_row)
        })
        .collect()
}
