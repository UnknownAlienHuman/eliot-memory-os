//! Canonical capability-evidence range read for the `SurrealDB` bridge
//! (issue #1773, I3.4).
//!
//! Mirrors the learning contour's closed read through the store-api wire
//! contract: durable Governor-owned capability-evidence rows in the
//! `capability-evidence-v1` namespace of the canonical `recovery_owner` table,
//! read under the exact admission fence with genuine keyset continuation.
//!
//! Why this leg exists: `GetCapabilityEvidenceState` answers committed
//! `ApplyLifecyclePolicy` governance rows, which carry no capability status, no
//! evidence source, no route-scope fingerprint, and no revision, so no
//! `CapabilityEvidenceRecord` can be minted from it. This read projects the
//! real evidence row instead: the verbatim document, the owner-issued
//! `record_digest` of those bytes, and the store-issued `revision` the fenced
//! compare-and-set assigned. The adapter never derives the record's semantics
//! from the document; the Governor re-proves the binding at the read edge.
//!
//! Continuation: the complete scope / skill / fence predicate is applied IN THE
//! QUERY, before `ORDER BY` and `LIMIT`, so the page limit bounds eligible rows
//! and a current-fence row is never hidden behind an other-fence prefix. The
//! skip window is served by keyset continuation on the deterministic row key,
//! so a second page never re-materializes the consumed prefix. `more` is true
//! only when a further eligible row was actually observed, and the page is empty
//! only when the eligible set was traversed to its end — so a complete hydration
//! terminates instead of re-reading the first page forever.

use eliot_store_api::{CAPABILITY_EVIDENCE_RECORD_NAMESPACE, StateFence, StoreError, sha256_hex};
use serde_json::{Map, Value, json};

use crate::SurrealAdapterConfig;
use crate::client::{self, RpcTransport};
use crate::error::AdapterError;
use crate::schema;

/// One stored capability-evidence row as projected by the range read.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StoredCapabilityEvidence {
    /// Exact skill identity of the evidence key.
    pub skill_id: String,
    /// Owner-issued digest of the exact route-scope fingerprint.
    pub scope_key: String,
    /// Presented digest of the committed record bytes.
    pub record_digest: String,
    /// Verbatim canonical evidence-record document.
    pub record_json: String,
    /// Store-issued fenced revision of this evidence key.
    pub revision: u64,
}

/// One bounded page of the current-fence capability-evidence eligible set.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CapabilityEvidenceReadPage {
    /// Eligible rows past the skip window, never more than the page limit.
    pub records: Vec<StoredCapabilityEvidence>,
    /// True only when a further eligible row exists beyond `records`; the
    /// eligible set was traversed until it ended, never truncated by an
    /// unexamined suffix.
    pub more: bool,
}

/// Returns the `key` **column** value the write path produced for one evidence
/// key.
///
/// Two addresses are in play and they are not interchangeable:
///
/// * the `key` **column** — `"evidence_<sha256>"`, produced by
///   [`eliot_store_api::capability_evidence_row_key`] and written by
///   `record.insert("key", json!(row_key.key))` in
///   `super::append_capability_evidence_owner_statements`. This is the anchor
///   the rest of the adapter addresses rows by:
///   [`crate::schema::READ_RECOVERY_OWNER_BY_KEY`] selects
///   `WHERE namespace = $ns AND key = $key`, and the blackboard leg binds
///   `blackboard_key` the same way.
/// * the **physical record id** — `sha256_hex(canonical_json_bytes(RecoveryRecordKey))`
///   over that key, produced by `recovery_owner_id` in [`super::atomic_write`] and
///   consumed only as `type::record($table, $id)`. It is never projected as a
///   column and is never compared against `key`.
///
/// The re-proof therefore compares column to column.
fn row_key_column(skill_id: &str, scope_key: &str) -> String {
    eliot_store_api::capability_evidence_row_key(skill_id, scope_key).key
}

/// Reads the eligible capability-evidence rows for the current query in key
/// order.
///
/// The fence binds as the same `state_fence` value the canonical transaction
/// compares against, so the predicate is exact. `skip` counts eligible rows
/// already consumed by earlier pages and is served by keyset continuation:
/// each round fetches at most `limit + 1` eligible rows after the last row
/// actually returned, so a continuation never re-materializes the consumed
/// prefix, and the scan ends only when a round returns no further eligible row.
pub(crate) async fn read_capability_evidence_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    scope_id: &str,
    skill_filter: Option<&str>,
    fence: &StateFence,
    skip: u64,
    limit: usize,
) -> Result<CapabilityEvidenceReadPage, AdapterError> {
    let probe = limit.saturating_add(1);
    let mut remaining_skip = skip;
    let mut records: Vec<StoredCapabilityEvidence> = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let rows = read_capability_evidence_page(
            db,
            config,
            scope_id,
            skill_filter,
            fence,
            after.as_deref(),
            probe,
        )
        .await?;
        let Some(last) = rows.last() else {
            return Ok(CapabilityEvidenceReadPage {
                records,
                more: false,
            });
        };
        let last_key = last.0.clone();
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
            records.extend(eligible.into_iter().map(|(_, row)| row));
            return Ok(CapabilityEvidenceReadPage {
                records,
                more: true,
            });
        }
        records.extend(eligible.into_iter().map(|(_, row)| row));
        after = Some(last_key);
    }
}

/// Reads one bounded keyset page of eligible capability-evidence rows in key
/// order.
///
/// The whole predicate travels bound: scope, optional exact skill, the exact
/// admission fence, and the optional exclusive key of the last row the previous
/// round returned. The row key is the same deterministic address the write path
/// creates, so keyset order is total and stable.
async fn read_capability_evidence_page(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    scope_id: &str,
    skill_filter: Option<&str>,
    fence: &StateFence,
    after: Option<&str>,
    limit: usize,
) -> Result<Vec<(String, StoredCapabilityEvidence)>, AdapterError> {
    let mut predicate = String::from(
        "namespace = $capability_evidence_namespace AND scope_id = $capability_evidence_scope AND state_fence = $capability_evidence_fence",
    );
    if skill_filter.is_some() {
        predicate.push_str(" AND skill_id = $capability_evidence_skill");
    }
    if after.is_some() {
        predicate.push_str(" AND key > $capability_evidence_after_key");
    }
    let sql = format!(
        "SELECT namespace, key, skill_id, scope_key, record_digest, payload, scope_id, revision FROM {} WHERE {predicate} ORDER BY key LIMIT {limit};",
        schema::table::RECOVERY_OWNER
    );
    let mut bindings = Map::new();
    bindings.insert(
        "capability_evidence_namespace".to_owned(),
        json!(CAPABILITY_EVIDENCE_RECORD_NAMESPACE),
    );
    bindings.insert("capability_evidence_scope".to_owned(), json!(scope_id));
    bindings.insert("capability_evidence_fence".to_owned(), json!(fence));
    if let Some(skill) = skill_filter {
        bindings.insert("capability_evidence_skill".to_owned(), json!(skill));
    }
    if let Some(after_key) = after {
        bindings.insert("capability_evidence_after_key".to_owned(), json!(after_key));
    }
    let mut response = client::query(
        db,
        config,
        "capability_evidence.read_records",
        &sql,
        bindings,
    )
    .await?;
    let errors = response.take_errors();
    if missing_recovery_table(&errors) {
        return Ok(Vec::new());
    }
    if !errors.is_empty() {
        return Err(AdapterError::Store(StoreError::Serialization(
            "capability evidence snapshot query failed".to_owned(),
        )));
    }
    let rows: Vec<Value> = response.take(0)?;
    rows.into_iter()
        .map(|row| {
            // Same acceptance boundary as the sibling recovery read: a row that
            // does not project the closed column set is a decode failure, not a
            // row to half-read.
            let projected: CapabilityEvidenceRow = serde_json::from_value(row)
                .map_err(|error| AdapterError::Serialization(error.to_string()))?;
            let key = projected.key.clone();
            let decoded = decode_capability_evidence_row(scope_id, &key, projected)?;
            Ok((key, decoded))
        })
        .collect()
}

/// One projected `recovery_owner` row for the capability-evidence leg.
///
/// The column set and the field types are the ones the write path actually
/// produces, read back the way the established recovery path reads the same
/// table:
///
/// * the write binds `json!(payload)` where `payload: &[u8]`
///   ([`super::append_capability_evidence_owner_statements`](super::atomic_write)),
///   and the column is declared `DEFINE FIELD payload ON recovery_owner TYPE
///   bytes;` ([`crate::schema`]), so the projected value is the byte sequence
///   serde renders as a JSON array of integers — not a string;
/// * [`eliot_store_api::RecoveryRecord::payload`] is `pub payload: Vec<u8>`
///   ("Exact canonical payload bytes; the store does not interpret them"),
///   and the working recovery and genesis reads satisfy that field from the same
///   projection by deserializing the row wholesale
///   ([`RecoveryRecord`](eliot_store_api::RecoveryRecord) via
///   `response.take::<Vec<RecoveryRecord>>(…)` in
///   [`super::super::genesis`](super::super::genesis) and
///   [`take_vec`](super::take_vec) in this module's sibling read). This row
///   deserializes the same way, so it needs no tolerant second branch for a
///   string shape.
///
/// `deny_unknown_fields` matches [`eliot_store_api::RecoveryRecord`]: a row
/// carrying an unexpected column is refused rather than half-read.
#[derive(Clone, Debug, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityEvidenceRow {
    namespace: String,
    key: String,
    payload: Vec<u8>,
    record_digest: String,
    skill_id: String,
    scope_key: String,
    scope_id: String,
    revision: u64,
}

/// Decodes one projected capability-evidence row.
///
/// Four refusals, all structural, and none of them interprets the document:
///
/// * the row must name the exact `capability-evidence-v1` namespace;
/// * the row's own `scope_id` must equal the scope the read was planned for, so
///   a row cannot be served into another scope's answer;
/// * the `key` column must equal the `"evidence_<sha256>"` address recomputed
///   from the row's own `(skill_id, scope_key)` identity — column to column, with
///   both write-side producers named at the check — so a row cannot be projected
///   under an address the write path could not have produced; and
/// * `sha256_hex(payload) == record_digest`, the **owner-issued reference of the
///   original committed bytes**, checked over the `TYPE bytes` column as
///   committed and with both producer symbols named at the check. This validates
///   the value the store committed, not a freshly derived substitute, so a
///   hydration can never mint a record under an evidence reference the store
///   never issued for those bytes.
///
/// The revision must be at least `1`, because the store's fenced compare-and-set
/// only ever issues `expected + 1` from a `0` floor.
fn decode_capability_evidence_row(
    requested_scope: &str,
    key: &str,
    row: CapabilityEvidenceRow,
) -> Result<StoredCapabilityEvidence, AdapterError> {
    if row.namespace != CAPABILITY_EVIDENCE_RECORD_NAMESPACE {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "capability_evidence.namespace",
            reason: "capability evidence row is in a foreign namespace",
        }));
    }
    if row.scope_id != requested_scope {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "capability_evidence.scope_id",
            reason: "capability evidence row is in a foreign scope",
        }));
    }
    // Row-address re-proof, column to column.
    //
    // LEFT:  the `key` column read off the projected row, which the write path
    //        filled from `row_key.key` in
    //        `super::append_capability_evidence_owner_statements`.
    // RIGHT: `eliot_store_api::capability_evidence_row_key(skill_id,
    //        scope_key).key` — the same `"evidence_<sha256>"` string recomputed
    //        from the row's OWN `(skill_id, scope_key)` identity fields, which the
    //        same write statement filled in.
    //
    // These are the same kind of value, so the comparison can succeed; the
    // physical record id (`recovery_owner_id`, a bare digest used only inside
    // `type::record($table, $id)`) is deliberately NOT what is compared here.
    if row_key_column(&row.skill_id, &row.scope_key) != key {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "capability_evidence.key",
            reason: "capability evidence row address does not match its identity",
        }));
    }
    // The owner-issued reference is re-proved against the ORIGINAL recorded
    // bytes, not a derived substitute.
    //
    // LEFT:  `sha256_hex(record_json.as_bytes())` where `record_json` is
    //        `String::from_utf8(row.payload)` and `row.payload` is the `TYPE bytes`
    //        column read back exactly as committed.
    // RIGHT: the `record_digest` column, which
    //        `super::append_capability_evidence_owner_statements` filled from the
    //        presented `record_digest`, and which the Governor produced as
    //        `sha256_hex(record_json.as_bytes())` in
    //        `crate::capability_evidence_mutation_request_for_record` over the very
    //        bytes it put in `record_json`.
    //
    // Same producer on both sides, over the committed value, so a row can never
    // be served under an evidence reference the store never issued for those
    // bytes.
    let record_json = String::from_utf8(row.payload).map_err(|_| {
        AdapterError::Store(StoreError::InvalidField {
            field: "capability_evidence.payload",
            reason: "capability evidence payload bytes are not valid UTF-8",
        })
    })?;
    if sha256_hex(record_json.as_bytes()) != row.record_digest {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "capability_evidence.record_digest",
            reason: "capability evidence digest does not match its record bytes",
        }));
    }
    if row.revision < 1 {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "capability_evidence.revision",
            reason: "capability evidence revision must be at least 1",
        }));
    }
    Ok(StoredCapabilityEvidence {
        skill_id: row.skill_id,
        scope_key: row.scope_key,
        record_digest: row.record_digest,
        record_json,
        revision: row.revision,
    })
}

/// Reports whether a provider statement error only observes a missing
/// `recovery_owner` table. A missing table reads as empty evidence, never as
/// failure: every error must name the nonexistent table.
fn missing_recovery_table(errors: &[String]) -> bool {
    !errors.is_empty()
        && errors.iter().all(|error| {
            error.contains("does not exist") && error.contains(schema::table::RECOVERY_OWNER)
        })
}
