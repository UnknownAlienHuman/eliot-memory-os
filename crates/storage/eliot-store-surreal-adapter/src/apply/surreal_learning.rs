//! Canonical learning-record execution for the `SurrealDB` bridge
//! (issue #1868).
//!
//! Mirrors the experience contour's closed leg through the store-api wire
//! contract, persisted in one table: `learning_record` holds one
//! immutable row per `(record_kind, handle, record_digest)` carrying the
//! verbatim learning-record document. Documents stay opaque: lineage,
//! sequencing, and digest re-proof are Governor-owned, and this module
//! arbitrates keys and immutability only. Concurrent writers arbitrate
//! through the in-transaction compare-and-set inside the canonical
//! transaction; retries recompute from fresh rows, never from stale
//! reads. Rows commit inside the canonical transaction beside the receipt
//! and outbox rows, so rows, receipt, and outbox stay atomic.
//!
//! Rows are addressed by a joined record id
//! (`record_kind` + `\x1f` + `handle` + `\x1f` + `record_digest`). The
//! join is collision-free by construction: the wire contract admits a
//! closed `record_kind` set with no control characters, rejects control
//! characters in the handle, and the digest is fixed-shape hex, so the
//! unit separator can never occur inside any part. The parts also travel
//! as separate row fields, so no reader ever parses the address.
//!
//! The digest IS the immutable revision identity: a new digest is a new
//! row, never an in-place rewrite; identical replays converge
//! (`IdentityConflict` on divergent rewrite).

use eliot_store_api::{
    DecodedLearningMutation, NamedMutationOperation, StateFence, StoreError, TransitionClass,
    decode_learning_mutation,
};
use serde_json::{Map, Value, json};

use crate::SurrealAdapterConfig;
use crate::client::{self, RpcTransport};
use crate::error::AdapterError;
use crate::schema;

/// Joins one learning row address. Collision-free: the record kind is a
/// closed discriminator without control characters, the handle may not
/// contain control characters per the wire contract, and the digest is
/// fixed-shape hex.
fn learning_row_key(record_kind: &str, handle: &str, record_digest: &str) -> String {
    format!("{record_kind}\x1f{handle}\x1f{record_digest}")
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
    /// Presented digest of the record bytes; the immutable revision identity.
    pub record_digest: String,
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
    /// Admission fence.
    pub state_fence: StateFence,
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
            ..
        } = decoded;
        writes.records.push(LearningRecordWrite {
            record_kind: record_kind.as_str().to_owned(),
            handle,
            record_json,
            record_digest,
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
            &write.record_digest
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
        state_fence: fence_row_field(object)?,
    })
}

/// One bounded page of the current-fence learning eligible set.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LearningReadPage {
    /// Eligible rows past the skip window, never more than the page limit.
    pub records: Vec<StoredLearningRecord>,
    /// True only when a further eligible row exists beyond `records`;
    /// the eligible set was traversed until it ended, never truncated
    /// by an unexamined suffix.
    pub more: bool,
}

/// Reads the eligible learning rows for the current query in key order.
///
/// The complete scope / kind / fence predicate is applied IN THE QUERY,
/// before `ORDER BY` and `LIMIT`, so the page limit bounds eligible rows
/// and a current-fence row is never hidden behind an other-fence prefix.
/// The fence binds as the same `state_fence` value the canonical
/// transaction compares against, so the predicate is exact.
///
/// `skip` counts eligible rows already consumed by earlier pages. It is
/// served by keyset continuation: each round fetches at most
/// `limit + 1` eligible rows after the last row actually returned, so a
/// continuation never re-materializes the consumed prefix. The scan ends
/// only when a round returns no further eligible row, so an empty page is
/// an authoritative empty eligible set, not an unexamined suffix.
pub(crate) async fn read_learning_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    scope_id: &str,
    kind_filter: Option<&str>,
    fence: &StateFence,
    skip: u64,
    limit: usize,
) -> Result<LearningReadPage, AdapterError> {
    let probe = limit.saturating_add(1);
    let mut remaining_skip = skip;
    let mut records: Vec<StoredLearningRecord> = Vec::new();
    let mut after: Option<(String, String, String)> = None;
    loop {
        let rows = read_learning_page(
            db,
            config,
            scope_id,
            kind_filter,
            fence,
            after.as_ref(),
            probe,
        )
        .await?;
        let Some(last) = rows.last() else {
            return Ok(LearningReadPage {
                records,
                more: false,
            });
        };
        let last_key = (
            last.record_kind.clone(),
            last.handle.clone(),
            last.record_digest.clone(),
        );
        let row_count = u64::try_from(rows.len()).unwrap_or(u64::MAX);
        if remaining_skip >= row_count {
            remaining_skip -= row_count;
            after = Some(last_key);
            continue;
        }
        let skipped = usize::try_from(remaining_skip).unwrap_or(usize::MAX);
        remaining_skip = 0;
        let mut eligible = rows;
        eligible.drain(..skipped);
        let room = limit.saturating_sub(records.len());
        if eligible.len() > room {
            eligible.truncate(room);
            records.extend(eligible);
            return Ok(LearningReadPage {
                records,
                more: true,
            });
        }
        records.extend(eligible);
        after = Some(last_key);
    }
}

/// Reads one bounded keyset page of eligible learning rows in key order.
///
/// The whole predicate travels bound: scope, optional kind, the exact
/// admission fence, and the optional exclusive key of the last row the
/// previous round returned. The row key is the same joined address the
/// write path creates, so keyset order is total and stable.
async fn read_learning_page(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    scope_id: &str,
    kind_filter: Option<&str>,
    fence: &StateFence,
    after: Option<&(String, String, String)>,
    limit: usize,
) -> Result<Vec<StoredLearningRecord>, AdapterError> {
    let mut predicate =
        String::from("scope_id = $learning_scope AND state_fence = $learning_fence");
    if kind_filter.is_some() {
        predicate.push_str(" AND record_kind = $learning_kind");
    }
    if after.is_some() {
        predicate.push_str(
            " AND (record_kind > $learning_after_kind OR (record_kind = $learning_after_kind AND (handle > $learning_after_handle OR (handle = $learning_after_handle AND record_digest > $learning_after_digest))))",
        );
    }
    let sql = format!(
        "SELECT * FROM {} WHERE {predicate} ORDER BY record_kind, handle, record_digest LIMIT {limit};",
        schema::table::LEARNING_RECORD
    );
    let mut bindings = Map::new();
    bindings.insert("learning_scope".to_owned(), json!(scope_id));
    bindings.insert("learning_fence".to_owned(), json!(fence));
    if let Some(kind) = kind_filter {
        bindings.insert("learning_kind".to_owned(), json!(kind));
    }
    if let Some((record_kind, handle, record_digest)) = after {
        bindings.insert("learning_after_kind".to_owned(), json!(record_kind));
        bindings.insert("learning_after_handle".to_owned(), json!(handle));
        bindings.insert("learning_after_digest".to_owned(), json!(record_digest));
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
