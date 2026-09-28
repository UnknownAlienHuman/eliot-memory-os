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

use eliot_store_api::{
    CAPABILITY_EVIDENCE_RECORD_NAMESPACE, StateFence, StoreError, canonical_json_bytes, sha256_hex,
};
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

/// Returns the physical row-id digest of one evidence key, exactly as the write
/// path derives it.
fn row_id(skill_id: &str, scope_key: &str) -> Result<String, AdapterError> {
    let key = eliot_store_api::capability_evidence_row_key(skill_id, scope_key);
    let bytes = canonical_json_bytes(&key)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
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
        "SELECT namespace, key, skill_id, scope_key, record_digest, payload, revision FROM {} WHERE {predicate} ORDER BY key LIMIT {limit};",
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
            let object = row
                .as_object()
                .ok_or(AdapterError::Store(StoreError::InvalidField {
                    field: "capability_evidence.row",
                    reason: "capability evidence row must be an object",
                }))?;
            let key = text_row_field(object, "key")?;
            let decoded = decode_capability_evidence_row(&key, object)?;
            Ok((key, decoded))
        })
        .collect()
}

/// Decodes one projected capability-evidence row.
///
/// The row must name the exact `capability-evidence-v1` namespace and carry the
/// presented `record_digest` of its own payload bytes. That re-proof is the
/// adapter's structural acceptance boundary: the store must never echo a
/// document under a reference it does not match, so a hydration can never mint a
/// record under an evidence reference the store never issued for those bytes.
fn decode_capability_evidence_row(
    key: &str,
    object: &Map<String, Value>,
) -> Result<StoredCapabilityEvidence, AdapterError> {
    let namespace = text_row_field(object, "namespace")?;
    if namespace != CAPABILITY_EVIDENCE_RECORD_NAMESPACE {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "capability_evidence.namespace",
            reason: "capability evidence row is in a foreign namespace",
        }));
    }
    let skill_id = text_row_field(object, "skill_id")?;
    let scope_key = text_row_field(object, "scope_key")?;
    // The address is derived from exactly the two identity parts, so a row whose
    // address disagrees with its own identity fields is refused rather than
    // projected under a key the write path could not have produced.
    if row_id(&skill_id, &scope_key)? != key {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "capability_evidence.key",
            reason: "capability evidence row address does not match its identity",
        }));
    }
    let record_digest = text_row_field(object, "record_digest")?;
    let record_json = record_json_field(object, "payload")?;
    if sha256_hex(record_json.as_bytes()) != record_digest {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "capability_evidence.record_digest",
            reason: "capability evidence digest does not match its record bytes",
        }));
    }
    let revision = object
        .get("revision")
        .and_then(Value::as_u64)
        .filter(|revision| *revision >= 1)
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "capability_evidence.revision",
            reason: "capability evidence revision must be at least 1",
        }))?;
    Ok(StoredCapabilityEvidence {
        skill_id,
        scope_key,
        record_digest,
        record_json,
        revision,
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

fn text_row_field(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<String, AdapterError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field,
            reason: "capability evidence row field must be present text",
        }))
}

/// Decodes the stored evidence document, which the provider persists verbatim.
///
/// `payload` is the canonical `RecoveryRecord` byte column: the owner stored the
/// record document as a JSON string, so the projected value is that string and
/// the document is carried through unchanged. A non-text projection is refused
/// rather than re-serialized, so the bytes the Governor re-proves are the exact
/// bytes that were committed.
fn record_json_field(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<String, AdapterError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field,
            reason: "capability evidence payload must be present text",
        }))
}
