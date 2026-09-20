//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01.
//! Implementation: I5.1, I5.3, I5.9, I2.2, I2.23.
//! Ownership: bounded physical named-read execution and validation only; no semantic command-catalog, write/transition, authority, policy, retry, or default ownership.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::SurrealStoreAdapter;
use crate::client;
use crate::config::{SchemaGeneration, SurrealAdapterConfig};
use crate::error::AdapterError;
use crate::plan;
use crate::plan::validate_revision_heads;
use crate::schema;
use eliot_store_api::{
    CanonicalValidationSnapshot, EVIDENCE_PACK_MAX_RECORDS, ExactJsonBytes, NamedReadOperation,
    NamedReadRequest, NamedReadResponse, OperationId, OrderingHead, OrderingScopeId,
    PAYLOAD_AUTHORITY_VERSION, PayloadEncoding, PayloadSource, RevisionHead, RevisionKey, ScopeId,
    ScopeRevisionView, StateFence, StoreError, WriteReceipt, WriteReceiptStatus,
    generated_operation_manifests, named_mutation_operation_name,
};

use super::{
    FenceRecord, SchemaMetaRecord, ensure_ready, ensure_unique_ordering_scopes,
    ensure_unique_revision_keys, read_fence, read_ordering_heads_inner, read_receipt_by_operation,
    read_revision_heads_inner, take_schema_meta, take_vec, to_value, validate_fence_record,
    validate_schema_meta_record,
};

pub(super) const READ_VALIDATION_SNAPSHOT: &str = "BEGIN TRANSACTION; SELECT * FROM ONLY schema_meta:current; SELECT VALUE { state_fence: state_fence, next_commit_sequence: next_commit_sequence, next_outbox_sequence: next_outbox_sequence } FROM ONLY canonical_fence:current; SELECT VALUE body FROM revision_head; COMMIT TRANSACTION;";

/// Version of the `GetEvidencePack` payload shape built below.
///
/// Must stay equal to the reference handler's version in
/// `eliot-store-memory`: consumers match on this version before interpreting
/// `records` / `provenance`; any shape change bumps it on both sides.
const EVIDENCE_PACK_PAYLOAD_VERSION: u32 = 1;

/// Version of the T11.3 cognitive read payloads. Each must stay equal to its
/// reference counterpart in `eliot-store-memory`.
const TASK_STATE_PAYLOAD_VERSION: u32 = 1;
const ATTENTION_PROBLEMS_PAYLOAD_VERSION: u32 = 1;
const UNDERSTANDING_INPUTS_PAYLOAD_VERSION: u32 = 1;
const CAPABILITY_EVIDENCE_PAYLOAD_VERSION: u32 = 1;

/// One receipt row of the closed evidence SELECT (see
/// [`schema::READ_EVIDENCE_RECORDS`](crate::schema::READ_EVIDENCE_RECORDS)).
///
/// Pre-change receipts lack all three fields (they read as `NONE`); the
/// boundary treats a missing array as empty, never as an error. Those
/// pre-change captures had no recoverable bytes persisted and stay absent
/// from the pack — only post-change captures are served.
#[derive(Clone, Debug, Deserialize)]
struct EvidenceReceiptRow {
    commit_sequence: Option<u64>,
    named_operation_count: Option<usize>,
    evidence_records: Option<Vec<EvidenceRecordRow>>,
    /// Joined by the immutable commit marker, never by the caller's scope.
    #[serde(skip)]
    receipt: Option<WriteReceipt>,
}

/// One recoverable capture as persisted by the atomic writer (see
/// `atomic_write::evidence_binding`). Strict: a malformed post-change record
/// fails closed at deserialization, never as a silent empty.
#[derive(Clone, Debug, Deserialize)]
struct EvidenceRecordRow {
    operation_index: usize,
    subject: String,
    parameters: BTreeMap<String, Value>,
    version: u16,
    encoding: String,
    digest_hex: String,
    byte_len: usize,
    bytes_utf8: String,
    commit_sequence: u64,
    named_operation_count: usize,
}

/// Enforces the active generated catalogue on one named read before dispatch
/// (slice C2, issue #19).
///
/// Only the ten activated reads (plus the genesis bootstrap entry, which
/// never arrives through this path) are admitted: catalogue membership, the
/// owner-approved typed parameters, the scope declaration, and the declared
/// input bound are checked here, before any provider I/O. Unknown operations
/// fail with [`StoreError::UnknownOperation`]; extra, control-substitution,
/// or misshapen parameters fail with their existing typed mismatch variants.
/// Nothing is normalized and there is no fallback: every rejection maps to a
/// typed [`StoreFailure`](eliot_store_api::StoreFailure) at the dispatch
/// boundary, never to a generic error.
fn validate_named_against_active_catalogue(query: &NamedReadRequest) -> Result<(), StoreError> {
    let entries = generated_operation_manifests()?;
    query.validate_against_catalogue(&entries)
}

pub(crate) async fn read_validation_snapshot(
    adapter: &SurrealStoreAdapter,
) -> Result<CanonicalValidationSnapshot, AdapterError> {
    let db = super::client(adapter).await?;
    let mut response = client::query(
        db,
        &adapter.config,
        "read.validation_snapshot",
        READ_VALIDATION_SNAPSHOT,
        Map::new(),
    )
    .await?;
    let observed_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AdapterError::ProviderUnavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| AdapterError::ProviderUnavailable)?;
    parse_validation_snapshot(
        &mut response,
        &adapter.config.expected_schema_generation,
        observed_at_unix_ms,
    )
}

fn parse_validation_snapshot(
    response: &mut client::RpcResults,
    expected_generation: &SchemaGeneration,
    observed_at_unix_ms: i64,
) -> Result<CanonicalValidationSnapshot, AdapterError> {
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let schema = take_schema_meta(response, 1)?.ok_or(AdapterError::MigrationRequired)?;
    validate_schema_meta_record(&schema)?;
    if schema.migration_state != "APPLIED" || schema.generation != expected_generation.as_str() {
        return Err(AdapterError::MigrationRequired);
    }
    let fence = response
        .take::<Option<FenceRecord>>(2)?
        .ok_or(StoreError::Unavailable)?;
    validate_fence_record(&fence)?;
    let revision_heads = response.take::<Vec<RevisionHead>>(3)?;
    let commit_result = response.take::<Value>(4)?;
    build_validation_snapshot(
        Some(schema),
        Some(fence),
        revision_heads,
        expected_generation,
        observed_at_unix_ms,
        commit_result,
    )
}

pub(super) fn build_validation_snapshot(
    schema: Option<SchemaMetaRecord>,
    fence: Option<FenceRecord>,
    revision_heads: Vec<RevisionHead>,
    expected_generation: &SchemaGeneration,
    observed_at_unix_ms: i64,
    _commit_result: Value,
) -> Result<CanonicalValidationSnapshot, AdapterError> {
    let schema = schema.ok_or(AdapterError::MigrationRequired)?;
    validate_schema_meta_record(&schema)?;
    if schema.migration_state != "APPLIED" || schema.generation != expected_generation.as_str() {
        return Err(AdapterError::MigrationRequired);
    }
    let fence = fence.ok_or(StoreError::Unavailable)?;
    validate_fence_record(&fence)?;
    let snapshot = CanonicalValidationSnapshot {
        state_fence: fence.state_fence,
        revision_heads,
        validation_revision: fence.next_commit_sequence,
        observed_at_unix_ms,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

pub(crate) async fn read_revision_heads(
    adapter: &SurrealStoreAdapter,
    keys: Vec<RevisionKey>,
) -> Result<Vec<RevisionHead>, AdapterError> {
    ensure_unique_revision_keys(&keys)?;
    let db = super::client(adapter).await?;
    ensure_ready(adapter, db).await?;
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let mut bindings = Map::new();
    bindings.insert(
        "keys".to_owned(),
        to_value(&keys.iter().map(ToString::to_string).collect::<Vec<_>>())?,
    );
    let mut response = client::query(
        db,
        &adapter.config,
        "read.revision_heads",
        schema::READ_REVISION_HEADS_BY_KEYS,
        bindings,
    )
    .await?;
    let heads = take_vec::<RevisionHead>(&mut response, 0)?;
    validate_revision_heads(&heads)?;
    Ok(heads)
}

pub(crate) async fn read_ordering_heads(
    adapter: &SurrealStoreAdapter,
    scopes: Vec<OrderingScopeId>,
) -> Result<Vec<OrderingHead>, AdapterError> {
    ensure_unique_ordering_scopes(&scopes)?;
    let db = super::client(adapter).await?;
    ensure_ready(adapter, db).await?;
    if scopes.is_empty() {
        return Ok(Vec::new());
    }
    let mut bindings = Map::new();
    bindings.insert(
        "scopes".to_owned(),
        to_value(&scopes.iter().map(ToString::to_string).collect::<Vec<_>>())?,
    );
    let mut response = client::query(
        db,
        &adapter.config,
        "read.ordering_heads",
        schema::READ_ORDERING_HEADS_BY_SCOPES,
        bindings,
    )
    .await?;
    let heads = take_vec::<OrderingHead>(&mut response, 0)?;
    plan::validate_ordering_heads(&heads)?;
    Ok(heads)
}

pub(crate) async fn read_scope_view(
    adapter: &SurrealStoreAdapter,
    scope_id: ScopeId,
) -> Result<ScopeRevisionView, AdapterError> {
    let db = super::client(adapter).await?;
    ensure_ready(adapter, db).await?;
    let fence = read_fence(db, &adapter.config).await?;
    let state_fence = fence.ok_or(StoreError::ReceiptNotFound)?.state_fence;
    let revision_heads = read_revision_heads_inner(
        db,
        &adapter.config,
        &[RevisionKey::new(format!("scope:{scope_id}"))?],
    )
    .await?;
    let ordering_heads = read_ordering_heads_inner(
        db,
        &adapter.config,
        &[OrderingScopeId::new(scope_id.as_str())?],
    )
    .await?;
    let view = ScopeRevisionView {
        scope_id,
        revision_heads,
        ordering_heads,
        state_fence,
    };
    view.validate()?;
    Ok(view)
}

pub(crate) async fn execute_named(
    adapter: &SurrealStoreAdapter,
    query: NamedReadRequest,
) -> Result<NamedReadResponse, AdapterError> {
    validate_named_against_active_catalogue(&query).map_err(AdapterError::Store)?;
    let db = super::client(adapter).await?;
    ensure_ready(adapter, db).await?;

    let fence = read_fence(db, &adapter.config).await?;
    let state_fence = resolve_state_fence(fence.as_ref(), &query.state_fence)?;

    let revision_heads = read_all_revision_heads(db, &adapter.config).await?;
    let payload = named_read_payload(adapter, db, &query, &state_fence).await?;
    let response = NamedReadResponse {
        operation: query.operation,
        state_fence,
        revision_heads,
        payload,
    };
    response.validate()?;
    Ok(response)
}

/// Resolves the read fence for one named read (pure, shared by all reads).
///
/// Empty stores read through the query fence; otherwise the durable fence
/// must equal the query fence exactly, or the read refuses with
/// [`StoreError::FenceMismatch`] — never a successful stale view.
fn resolve_state_fence(
    fence: Option<&FenceRecord>,
    query_fence: &StateFence,
) -> Result<StateFence, AdapterError> {
    match fence {
        None => Ok(query_fence.clone()),
        Some(fence) if fence.state_fence == *query_fence => Ok(fence.state_fence.clone()),
        Some(_) => Err(AdapterError::Store(StoreError::FenceMismatch)),
    }
}

async fn named_read_payload(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
    query: &NamedReadRequest,
    state_fence: &StateFence,
) -> Result<Value, AdapterError> {
    match query.operation {
        NamedReadOperation::GetCurrentEpistemicPosition => {
            read_epistemic_position(db, &adapter.config, query).await
        }
        NamedReadOperation::GetRevisionHeads => Ok(to_value(
            &read_all_revision_heads(db, &adapter.config).await?,
        )?),
        NamedReadOperation::GetOrderingHeads => Ok(to_value(
            &read_all_ordering_heads(db, &adapter.config).await?,
        )?),
        NamedReadOperation::GetScopeRevisionView => {
            let scope_id = query.scope_id.clone().ok_or(StoreError::InvalidField {
                field: "scope_id",
                reason: "scope revision read requires scope_id",
            })?;
            Ok(to_value(&read_scope_view(adapter, scope_id).await?)?)
        }
        NamedReadOperation::ResolveWriteReceipt => {
            let operation_id = query
                .parameters
                .get("operation_id")
                .and_then(Value::as_str)
                .ok_or(StoreError::InvalidField {
                    field: "operation_id",
                    reason: "named receipt read requires a string operation_id",
                })?;
            let operation_id = OperationId::new(operation_id).map_err(StoreError::Foundation)?;
            Ok(to_value(
                &read_receipt_by_operation(db, &adapter.config, &operation_id).await?,
            )?)
        }
        NamedReadOperation::GetEvidencePack => {
            let rows = read_evidence_records(db, &adapter.config).await?;
            let suppression = read_erasure_suppression(db, &adapter.config).await?;
            evidence_pack_payload(query, state_fence, &rows, &suppression)
                .map_err(AdapterError::Store)
        }
        NamedReadOperation::GetTaskState => {
            let rows = read_authority_records(db, &adapter.config).await?;
            task_state_payload(query, state_fence, &rows).map_err(AdapterError::Store)
        }
        NamedReadOperation::GetAttentionAndProblems => {
            let rows = read_authority_records(db, &adapter.config).await?;
            attention_problems_payload(query, state_fence, &rows).map_err(AdapterError::Store)
        }
        NamedReadOperation::GetUnderstandingProjectionInputs => {
            let rows = read_authority_records(db, &adapter.config).await?;
            understanding_inputs_payload(query, state_fence, &rows).map_err(AdapterError::Store)
        }
        NamedReadOperation::GetCapabilityEvidenceState => {
            let rows = read_authority_records(db, &adapter.config).await?;
            capability_evidence_payload(query, state_fence, &rows).map_err(AdapterError::Store)
        }
        other => Err(AdapterError::NamedOperationUnavailable {
            operation: format!("{other:?}"),
        }),
    }
}

#[derive(serde::Deserialize)]
struct EpistemicPositionRow {
    epistemic_position_revision: u64,
    epistemic_payload: String,
    body: eliot_store_api::WriteReceipt,
}

const READ_EPISTEMIC_POSITION: &str = r"
SELECT epistemic_position_revision, epistemic_payload, body FROM write_receipt
WHERE epistemic_position_key = $epistemic_position_key
ORDER BY epistemic_position_revision DESC LIMIT 1;
";

async fn read_epistemic_position(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    query: &NamedReadRequest,
) -> Result<Value, AdapterError> {
    use eliot_store_api::epistemic_revision::{EpistemicCommit, position_key};
    let scope = query
        .scope_id
        .as_ref()
        .ok_or(StoreError::ManifestMismatch)?;
    let position = query
        .parameters
        .get("position")
        .and_then(Value::as_str)
        .ok_or(StoreError::ManifestMismatch)?;
    let key = position_key(scope.as_str(), position)?;
    let mut bindings = Map::new();
    bindings.insert(
        "epistemic_position_key".to_owned(),
        Value::String(key.clone()),
    );
    let mut response = client::query(
        db,
        config,
        "read.epistemic_position",
        READ_EPISTEMIC_POSITION,
        bindings,
    )
    .await?;
    let rows = take_vec::<EpistemicPositionRow>(&mut response, 0)?;
    let Some(row) = rows.first() else {
        return Ok(Value::Null);
    };
    let commit: EpistemicCommit = serde_json::from_str(&row.epistemic_payload)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    if commit.payload.position_key()? != key
        || commit.payload.next_revision()?.value() != row.epistemic_position_revision
        || commit.prepared.state_fence != query.state_fence
    {
        return Err(StoreError::InvalidReceipt.into());
    }
    to_value(&commit.readback(&row.body)?)
}

/// One sealed erasure-intent row: the exact `(operation_id, subject,
/// scope_id)` triple named by a recorded intent (see the
/// `TX_ERASURE_INTENT` binding shape in `atomic_write`, owned there — never
/// re-declared here).
#[derive(Clone, Debug, Deserialize)]
struct ErasureIntentRow {
    operation_id: String,
    subject: String,
    scope_id: String,
}

/// One sealed erasure-outcome row: the exact per-surface outcome strings
/// bound by the atomic writer (`PURGED:<Surface>`, `INCOMPLETE:<Surface>`,
/// `UNKNOWN:<Surface>`, `NOT_ATTEMPTED:<Surface>`), keyed by the same
/// `operation_id` as the intent row above.
#[derive(Clone, Debug, Deserialize)]
struct ErasureOutcomeRow {
    operation_id: String,
    outcomes: Vec<String>,
}

/// Evidence-backed erased `(scope_id, subject)` pairs for `GetEvidencePack`.
///
/// `Known` carries the sealed suppression set. `Unknown` means the lookup is
/// unavailable or unparsable and the pack read must refuse fail-closed — it
/// must never serve rows that could include erased records.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ErasureSuppression {
    Known(std::collections::BTreeSet<(String, String)>),
    Unknown,
}

impl ErasureSuppression {
    /// Returns the fail-closed suppression verdict for one exact pair.
    ///
    /// `Unknown` refuses with [`StoreError::Unavailable`] even before
    /// matching: an undecidable lookup must never admit a possibly-erased row.
    fn check(&self, scope_id: &str, subject: &str) -> Result<bool, StoreError> {
        match self {
            Self::Known(erased) => Ok(erased.contains(&(scope_id.to_owned(), subject.to_owned()))),
            Self::Unknown => Err(StoreError::Unavailable),
        }
    }
}

/// Collects the evidence-backed suppressed `(scope_id, subject)` pairs.
///
/// One pair suppresses only when its sealed intent row names a non-blank
/// scope and subject and a `PURGED` store-owned surface (`CanonicalPayload`,
/// `Projection`, `Index`) seals the outcome for the same `operation_id`.
/// `Unknown`/`Incomplete`/`NotAttempted` outcomes, foreign surfaces, and
/// malformed rows never suppress — exactly the reference handler's rule that
/// suppression requires a recorded intent plus dispatched store-owned
/// removal.
fn suppressed_pairs(
    intents: &[ErasureIntentRow],
    outcomes: &[ErasureOutcomeRow],
) -> std::collections::BTreeSet<(String, String)> {
    let mut purged_by_operation = std::collections::BTreeSet::new();
    for outcome in outcomes {
        if outcome.outcomes.iter().any(|cell| {
            cell.split_once(':').is_some_and(|(state, surface)| {
                state == "PURGED"
                    && matches!(surface, "CanonicalPayload" | "Projection" | "Index")
            })
        }) {
            purged_by_operation.insert(outcome.operation_id.clone());
        }
    }
    let mut suppressed = std::collections::BTreeSet::new();
    for intent in intents {
        if !purged_by_operation.contains(&intent.operation_id) {
            continue;
        }
        if intent.scope_id.trim().is_empty()
            || intent.scope_id.chars().any(char::is_control)
            || intent.subject.trim().is_empty()
            || intent.subject.chars().any(char::is_control)
        {
            continue;
        }
        suppressed.insert((intent.scope_id.clone(), intent.subject.clone()));
    }
    suppressed
}

/// Closed erasure-intent read: one `(operation_id, subject, scope_id)` row
/// per recorded intent (see the `TX_ERASURE_INTENT` binding shape in
/// `atomic_write`, owned there — never re-declared here). Defined here (not
/// in `schema.rs`) because only the `GetEvidencePack` read boundary consumes
/// it on this slice.
const READ_ERASURE_INTENTS: &str =
    "SELECT VALUE { operation_id: operation_id, subject: subject, scope_id: scope_id } FROM erasure_intent;";

/// Closed erasure-outcome read: one `(operation_id, outcomes)` row per sealed
/// outcome (see `READ_ERASURE_OUTCOME` in `atomic_write`, owned there).
/// Joined in Rust by exact `operation_id` — never by caller scope.
const READ_ALL_ERASURE_OUTCOMES: &str =
    "SELECT VALUE { operation_id: operation_id, outcomes: outcomes } FROM erasure_outcome;";

/// One side of the sealed erasure join: the observed state of one
/// never-vs-defined erasure table.
enum ErasureTable<T> {
    /// The table is defined; carries its decoded sealed rows.
    Rows(Vec<T>),
    /// The table was never defined on this pre-erasure store: the exact
    /// absent-table signal, an empty side of the join.
    Absent,
    /// Any other provider error or malformed envelope: the pack must refuse
    /// fail-closed.
    Unknown,
}

/// Reads one sealed erasure table through its closed single-statement SELECT,
/// never inside `BEGIN TRANSACTION`: a missing table aborts the whole
/// transaction, so the absent-table signal is only observable outside one.
/// Live provider observation for the transactional form was
/// `"The table 'erasure_intent' does not exist"` plus
/// `"The query was not executed due to a cancelled transaction"` and
/// `"Cannot COMMIT: the transaction was aborted due to a prior error"` for
/// the cancelled remainder — which the old `all(is_absent_table)` check
/// (correctly, but fatally) refused to call absent.
///
/// Only the exact absent-table signal naming `table` maps to `Absent`;
/// every other error class — including those transaction-cancellation
/// artifacts — maps to `Unknown` so the pack refuses fail-closed instead of
/// silently including erased records. Transport loss
/// (`ProviderUnavailable`) likewise maps to `Unknown`; any other transport
/// error propagates.
async fn read_erasure_table<T: serde::de::DeserializeOwned>(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    operation: &'static str,
    sql: &str,
    table: &str,
) -> Result<ErasureTable<T>, AdapterError> {
    let mut response = match client::query(db, config, operation, sql, Map::new()).await {
        Ok(response) => response,
        Err(AdapterError::ProviderUnavailable) => return Ok(ErasureTable::Unknown),
        Err(error) => return Err(error),
    };
    let errors = response.take_errors();
    if !errors.is_empty() {
        if errors
            .iter()
            .all(|error| client::is_absent_table(error) && error.contains(table))
        {
            return Ok(ErasureTable::Absent);
        }
        return Ok(ErasureTable::Unknown);
    }
    match response.take::<Vec<T>>(0) {
        Ok(rows) => Ok(ErasureTable::Rows(rows)),
        Err(_) => Ok(ErasureTable::Unknown),
    }
}

/// Reads the sealed erasure-suppression set for `GetEvidencePack`.
///
/// Sealed intent rows plus their sealed outcome rows, each through its own
/// closed non-transactional SELECT and joined in Rust by exact
/// `operation_id`. Only pairs with a `PURGED` store-owned surface outcome
/// suppress — the reference handler's evidence-backed `erased_subjects`
/// rule. Never-defined erasure tables on a pre-erasure store observe the
/// exact absent-table signal and read as the empty side of the join,
/// matching the reference handler's empty suppression on a fresh store.
/// Any other provider error or malformed envelope returns `Unknown` so the
/// pack read refuses fail-closed instead of silently including erased
/// records.
async fn read_erasure_suppression(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<ErasureSuppression, AdapterError> {
    let intents = match read_erasure_table::<ErasureIntentRow>(
        db,
        config,
        "read.erasure_suppression_intents",
        READ_ERASURE_INTENTS,
        "erasure_intent",
    )
    .await?
    {
        ErasureTable::Rows(intents) => intents,
        ErasureTable::Absent => Vec::new(),
        ErasureTable::Unknown => return Ok(ErasureSuppression::Unknown),
    };
    let outcomes = match read_erasure_table::<ErasureOutcomeRow>(
        db,
        config,
        "read.erasure_suppression_outcomes",
        READ_ALL_ERASURE_OUTCOMES,
        "erasure_outcome",
    )
    .await?
    {
        ErasureTable::Rows(outcomes) => outcomes,
        ErasureTable::Absent => Vec::new(),
        ErasureTable::Unknown => return Ok(ErasureSuppression::Unknown),
    };
    Ok(ErasureSuppression::Known(
        suppressed_pairs(&intents, &outcomes),
    ))
}

/// Reads all persisted capture-evidence rows through the closed SELECT.
///
/// One row per receipt; pre-change receipts carry no evidence array and
/// contribute nothing (they had no recoverable bytes persisted). The Rust
/// boundary joins the canonical receipt for scope/fence provenance. Both
/// closed reads share one snapshot; global operation counts remain intact
/// so filtering never changes an existing capture index.
async fn read_evidence_records(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<Vec<EvidenceReceiptRow>, AdapterError> {
    let sql = format!(
        "BEGIN TRANSACTION; {} {} COMMIT TRANSACTION;",
        schema::READ_EVIDENCE_RECORDS,
        schema::READ_ALL_RECEIPTS,
    );
    let mut response = client::query(db, config, "read.evidence_records", &sql, Map::new()).await?;
    if !response.take_errors().is_empty() {
        return Err(StoreError::Serialization("evidence snapshot query failed".to_owned()).into());
    }
    // SurrealDB 3 retains the BEGIN result at index 0 (null).
    let mut rows = take_vec::<EvidenceReceiptRow>(&mut response, 1)?;
    let receipts = take_vec::<WriteReceipt>(&mut response, 2)?;
    let mut by_commit = BTreeMap::new();
    for receipt in receipts {
        if let Some(marker) = &receipt.committed_at
            && by_commit.insert(marker.clone(), receipt).is_some()
        {
            return Err(StoreError::InvalidReceipt.into());
        }
    }
    for row in &mut rows {
        if let Some(sequence) = row.commit_sequence {
            row.receipt = by_commit.remove(&format!("commit-sequence-{sequence:016}"));
        }
    }
    Ok(rows)
}

/// Validates one persisted evidence record against its own provenance.
///
/// The writer bound the exact bytes to version/encoding/digest/length and to
/// the admitted parameters; any durable mismatch (substituted bytes,
/// truncated length, wrong encoding, or row/record order disagreement) fails
/// closed here instead of serving a lossy projection. This keeps the full
/// recoverable record (subject + exact bytes + provenance) honest for T13
/// while the pack itself returns the memory-parity `parameters` projection.
fn validate_evidence_record(
    row: &EvidenceReceiptRow,
    record: &EvidenceRecordRow,
) -> Result<(), StoreError> {
    if record.version != PAYLOAD_AUTHORITY_VERSION {
        return Err(StoreError::Serialization(
            "evidence record version mismatch".to_owned(),
        ));
    }
    if record.encoding != PayloadEncoding::Utf8Json.mnemonic() {
        return Err(StoreError::Serialization(
            "evidence record encoding mismatch".to_owned(),
        ));
    }
    if record.byte_len != record.bytes_utf8.len() {
        return Err(StoreError::Serialization(
            "evidence record length mismatch".to_owned(),
        ));
    }
    let bound = ExactJsonBytes::parse(
        PayloadSource::NamedOperationParameter,
        record.bytes_utf8.as_bytes(),
    )?;
    if bound.digest_hex() != record.digest_hex || bound.byte_len() != record.byte_len {
        return Err(StoreError::Serialization(
            "evidence record digest mismatch".to_owned(),
        ));
    }
    if bound.decode_object_parameters()? != record.parameters {
        return Err(StoreError::Serialization(
            "evidence record bytes do not match parameters".to_owned(),
        ));
    }
    if record.parameters.get("subject").and_then(Value::as_str) != Some(record.subject.as_str())
        || record.operation_index >= record.named_operation_count
    {
        return Err(StoreError::InvalidReceipt);
    }
    if let Some(commit_sequence) = row.commit_sequence
        && commit_sequence != record.commit_sequence
    {
        return Err(StoreError::Serialization(
            "evidence record commit order mismatch".to_owned(),
        ));
    }
    if let Some(named_operation_count) = row.named_operation_count
        && named_operation_count != record.named_operation_count
    {
        return Err(StoreError::Serialization(
            "evidence record operation count mismatch".to_owned(),
        ));
    }
    Ok(())
}

/// Builds the versioned exact evidence-pack payload for one request.
///
/// Parity with the reference `MemoryStore::evidence_pack_payload`: exact
/// scope/`subject` match (never substring, never a default), current read
/// fence validation independent of historical write fences, explicit
/// `max_records` decimal-string bound with over-bound
/// [`StoreError::PayloadTooLarge`] refusal, identity
/// (`capture_index` / `operation` / `parameters`), envelope `version = 1`
/// plus `provenance{state_fence, matched_total, returned, max_records,
/// truncated}`, and zero matches as an exact empty — never an error.
///
/// `capture_index` is the global operation position reconstructed from the
/// durable capture order: receipts walk in `commit_sequence` order,
/// accumulating each receipt's total operation count, so interleaved
/// non-capture operations consume indices exactly as the reference global
/// `named_operations` vector does. Pre-change receipts (no evidence array)
/// contribute zero to the walk and serve nothing; on a fresh store the walk
/// starts at zero and matches the reference exactly.
///
/// 688-STORE-2: an evidence-backed erased `(scope_id, subject)` pair
/// suppresses its records — the pack returns exact empty with
/// `matched_total = 0` — even if rows remain in the log. `Unknown` lookup
/// state refuses fail-closed with [`StoreError::Unavailable`] instead of
/// serving rows that may include erased records.
#[allow(
    clippy::too_many_lines,
    reason = "the pack payload validates shape, bound, suppression, fence, walk, and provenance in one closed unit"
)]
fn evidence_pack_payload(
    query: &NamedReadRequest,
    state_fence: &StateFence,
    rows: &[EvidenceReceiptRow],
    suppression: &ErasureSuppression,
) -> Result<Value, StoreError> {
    let scope_id = query.scope_id.clone().ok_or(StoreError::InvalidField {
        field: "scope_id",
        reason: "evidence pack read requires scope_id",
    })?;
    // The catalogue gate already enforces presence and shape; re-check
    // fail-closed so this arm never depends on call order (mirrors the
    // reference handler).
    let subject = query
        .parameters
        .get("subject")
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "missing required parameter",
        })?;
    if subject.trim().is_empty() || subject.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "subject must be a non-blank string",
        });
    }
    let bound_raw = query
        .parameters
        .get("max_records")
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "missing required parameter",
        })?;
    let max_records: u32 = bound_raw.parse().map_err(|_| StoreError::InvalidField {
        field: "operation.parameter",
        reason: "max_records must be a positive decimal bound",
    })?;
    if max_records == 0 {
        return Err(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "max_records must be a positive decimal bound",
        });
    }
    if max_records > EVIDENCE_PACK_MAX_RECORDS {
        return Err(StoreError::PayloadTooLarge);
    }
    let limit = usize::try_from(max_records).map_err(|_| StoreError::PayloadTooLarge)?;
    // Evidence-backed suppression (688-STORE-2, memory parity): a sealed
    // erased pair returns exact empty even when capture rows remain.
    // `Unknown` lookup state refuses here — before any row is admitted —
    // so the pack never silently includes erased records.
    if suppression.check(scope_id.as_str(), subject)? {
        return Ok(json!({
            "version": EVIDENCE_PACK_PAYLOAD_VERSION,
            "subject": subject,
            "scope_id": scope_id,
            "records": Vec::<Value>::new(),
            "provenance": {
                "state_fence": state_fence,
                "matched_total": 0,
                "returned": 0,
                "max_records": max_records,
                "truncated": false,
            },
        }));
    }
    if query.state_fence != *state_fence {
        return Err(StoreError::FenceMismatch);
    }

    // Durable capture order: receipts by commit_sequence (pre-change rows
    // without a sequence sort first and contribute zero), evidence within a
    // receipt by operation_index.
    let mut ordered: Vec<&EvidenceReceiptRow> = rows.iter().collect();
    ordered.sort_by_key(|row| row.commit_sequence.unwrap_or(0));
    let mut indexed: Vec<(u64, &EvidenceRecordRow)> = Vec::new();
    let mut operation_base: u64 = 0;
    for row in ordered {
        let mut records: Vec<&EvidenceRecordRow> = row
            .evidence_records
            .as_ref()
            .map_or(Vec::new(), |records| records.iter().collect());
        records.sort_by_key(|record| record.operation_index);
        // Legacy receipts without recoverable captures remain absent. A
        // recoverable capture without its admitted identity fails closed.
        let in_scope = if records.is_empty() {
            false
        } else {
            let receipt = row.receipt.as_ref().ok_or(StoreError::InvalidReceipt)?;
            receipt.validate()?;
            let binding = &receipt.require_reconciliation_envelope()?.core.work_scope;
            if receipt.status != WriteReceiptStatus::Committed
                || row.named_operation_count != Some(receipt.applied_command_ids.len())
            {
                return Err(StoreError::InvalidReceipt);
            }
            // The validated receipt retains its original write fence. Read
            // freshness does not erase observations admitted under older fences.
            binding.scope_id.as_str() == scope_id.as_str()
        };
        for record in records {
            validate_evidence_record(row, record)?;
            let capture_index = operation_base.saturating_add(record.operation_index as u64);
            if in_scope {
                indexed.push((capture_index, record));
            }
        }
        operation_base =
            operation_base.saturating_add(row.named_operation_count.unwrap_or(0) as u64);
    }
    // Exact subject match only — never substring, never a default.
    let matched: Vec<(u64, &EvidenceRecordRow)> = indexed
        .into_iter()
        .filter(|(_, record)| record.subject == subject)
        .collect();
    let matched_total = matched.len();
    let records: Vec<Value> = matched
        .into_iter()
        .take(limit)
        .map(|(capture_index, record)| {
            json!({
                "capture_index": capture_index,
                "operation": named_mutation_operation_name(
                    eliot_store_api::NamedMutationOperation::CaptureObservation,
                ),
                "parameters": record.parameters,
            })
        })
        .collect();
    let returned = records.len();
    Ok(json!({
        "version": EVIDENCE_PACK_PAYLOAD_VERSION,
        "subject": subject,
        "scope_id": scope_id,
        "records": records,
        "provenance": {
            "state_fence": state_fence,
            "matched_total": matched_total,
            "returned": returned,
            "max_records": max_records,
            "truncated": matched_total > returned,
        },
    }))
}

/// One payload-authority row of the closed T11.3 SELECT (defined below).
///
/// Pre-authority receipts carry no array (they read as `NONE`); the boundary
/// treats a missing array as empty, never as an error. Those receipts had no
/// recoverable bytes persisted and stay absent from the T11.3 packs — only
/// authority-carrying captures are served. Strict: a malformed
/// authority-carrying record fails closed at deserialization/validation,
/// never as a silent empty.
#[derive(Clone, Debug, Deserialize)]
struct AuthorityRecordRow {
    operation_index: usize,
    version: u16,
    encoding: String,
    digest_hex: String,
    byte_len: usize,
    bytes_utf8: String,
}

/// One receipt row of the closed T11.3 authority SELECT.
#[derive(Clone, Debug, Deserialize)]
struct AuthorityReceiptRow {
    commit_sequence: Option<u64>,
    named_operation_count: Option<usize>,
    payload_authority: Option<Vec<AuthorityRecordRow>>,
    /// Joined by the immutable commit marker, never by the caller's scope.
    #[serde(skip)]
    receipt: Option<WriteReceipt>,
}

/// Closed T11.3 authority read: one row per receipt with its durable commit
/// order and opaque payload-authority array. Defined here (not in
/// `schema.rs`) because only the T11.3 read boundary consumes it; the
/// physical table/columns already exist via the atomic writer.
const READ_AUTHORITY_RECORDS: &str = "SELECT VALUE { commit_sequence: commit_sequence, named_operation_count: named_operation_count, payload_authority: payload_authority } FROM write_receipt;";

/// Reads all persisted payload-authority rows through the closed SELECT.
///
/// One row per receipt; pre-authority receipts carry no authority array and
/// contribute nothing. The Rust boundary joins the canonical receipt for
/// scope/fence/transition-class provenance. Both closed reads share one
/// snapshot; global operation counts remain intact so filtering never changes
/// an existing capture index.
async fn read_authority_records(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<Vec<AuthorityReceiptRow>, AdapterError> {
    let sql = format!(
        "BEGIN TRANSACTION; {READ_AUTHORITY_RECORDS} {} COMMIT TRANSACTION;",
        schema::READ_ALL_RECEIPTS,
    );
    let mut response = client::query(db, config, "read.authority_records", &sql, Map::new()).await?;
    if !response.take_errors().is_empty() {
        return Err(StoreError::Serialization("authority snapshot query failed".to_owned()).into());
    }
    // SurrealDB 3 retains the BEGIN result at index 0 (null).
    let mut rows = take_vec::<AuthorityReceiptRow>(&mut response, 1)?;
    let receipts = take_vec::<WriteReceipt>(&mut response, 2)?;
    let mut by_commit = BTreeMap::new();
    for receipt in receipts {
        if let Some(marker) = &receipt.committed_at
            && by_commit.insert(marker.clone(), receipt).is_some()
        {
            return Err(StoreError::InvalidReceipt.into());
        }
    }
    for row in &mut rows {
        if let Some(sequence) = row.commit_sequence {
            row.receipt = by_commit.remove(&format!("commit-sequence-{sequence:016}"));
        }
    }
    Ok(rows)
}

/// Validates one persisted payload-authority record against its own provenance.
///
/// The writer bound the exact bytes to version/encoding/digest/length; any
/// durable mismatch fails closed here instead of serving a lossy projection.
/// Returns the decoded admitted parameters on success.
fn validate_authority_record(
    row: &AuthorityReceiptRow,
    record: &AuthorityRecordRow,
) -> Result<BTreeMap<String, Value>, StoreError> {
    if record.version != PAYLOAD_AUTHORITY_VERSION {
        return Err(StoreError::Serialization(
            "authority record version mismatch".to_owned(),
        ));
    }
    if record.encoding != PayloadEncoding::Utf8Json.mnemonic() {
        return Err(StoreError::Serialization(
            "authority record encoding mismatch".to_owned(),
        ));
    }
    if record.byte_len != record.bytes_utf8.len() {
        return Err(StoreError::Serialization(
            "authority record length mismatch".to_owned(),
        ));
    }
    let bound = ExactJsonBytes::parse(
        PayloadSource::NamedOperationParameter,
        record.bytes_utf8.as_bytes(),
    )?;
    if bound.digest_hex() != record.digest_hex || bound.byte_len() != record.byte_len {
        return Err(StoreError::Serialization(
            "authority record digest mismatch".to_owned(),
        ));
    }
    let parameters = bound.decode_object_parameters()?;
    let _ = record_operation_count(row, record)?;
    Ok(parameters)
}

fn record_operation_count(
    row: &AuthorityReceiptRow,
    record: &AuthorityRecordRow,
) -> Result<usize, StoreError> {
    // The receipt row carries the transition's total operation count; when
    // absent (pre-authority shape) the record itself cannot be ordered, so
    // fail closed rather than guessing.
    let count = row.named_operation_count.ok_or(StoreError::InvalidReceipt)?;
    if count == 0 || record.operation_index >= count {
        return Err(StoreError::InvalidReceipt);
    }
    Ok(count)
}

/// Infers the closed mutation operation for one decoded authority parameter
/// map within its receipt transition class.
///
/// The atomic writer does not persist operation names beside the opaque
/// bytes; the closed parameter shapes plus the receipt transition class
/// discriminate exactly one activated mutation per class on base
/// (`TaskControl` → `UpdateTaskState`, `LifecyclePolicy` →
/// `ApplyLifecyclePolicy`, `RecoverySchema` → `ReconcileRecovery`,
/// `CaptureCandidate` → `CaptureObservation`/`AppendAuditEvent`,
/// `Epistemic` → `ApplyEpistemicRevision`). Anything else fails closed.
fn infer_authority_operation(
    transition_class: eliot_store_api::TransitionClass,
    parameters: &BTreeMap<String, Value>,
) -> Result<eliot_store_api::NamedMutationOperation, StoreError> {
    use eliot_store_api::{NamedMutationOperation, TransitionClass};
    match transition_class {
        TransitionClass::TaskControl
            if parameters.contains_key("task_id") && parameters.contains_key("event_id") =>
        {
            Ok(NamedMutationOperation::UpdateTaskState)
        }
        TransitionClass::LifecyclePolicy if parameters.contains_key("skill_id") => {
            Ok(NamedMutationOperation::ApplyLifecyclePolicy)
        }
        TransitionClass::RecoverySchema if parameters.contains_key("problem_id") => {
            Ok(NamedMutationOperation::ReconcileRecovery)
        }
        TransitionClass::CaptureCandidate
            if parameters.contains_key("operation_id")
                && parameters.contains_key("idempotency_key") =>
        {
            Ok(NamedMutationOperation::AppendAuditEvent)
        }
        TransitionClass::CaptureCandidate if parameters.contains_key("subject") => {
            Ok(NamedMutationOperation::CaptureObservation)
        }
        TransitionClass::Epistemic if parameters.contains_key("revision") => {
            Ok(NamedMutationOperation::ApplyEpistemicRevision)
        }
        _ => Err(StoreError::InvalidReceipt),
    }
}

struct IndexedAuthority {
    capture_index: u64,
    operation: eliot_store_api::NamedMutationOperation,
    parameters: BTreeMap<String, Value>,
    scope_id: String,
}

/// Walks authority rows in durable commit order and returns indexed records
/// with scope provenance.
///
/// Receipts walk in `commit_sequence` order, accumulating each receipt's
/// total operation count, so interleaved operations consume global indices
/// exactly as the reference `named_operations` vector does. Pre-authority
/// receipts (no authority array) contribute zero to the walk and serve
/// nothing. Each authority record is validated (version/encoding/digest/
/// length/bytes-vs-parameters) and its receipt is validated (committed
/// status, envelope, command-count agreement); any mismatch fails closed.
/// Scope comes from the validated receipt envelope, never from the caller.
fn indexed_authorities(
    rows: &[AuthorityReceiptRow],
) -> Result<Vec<IndexedAuthority>, StoreError> {
    let mut ordered: Vec<&AuthorityReceiptRow> = rows.iter().collect();
    ordered.sort_by_key(|row| row.commit_sequence.unwrap_or(0));
    let mut indexed = Vec::new();
    let mut operation_base: u64 = 0;
    for row in ordered {
        let authorities: Vec<&AuthorityRecordRow> = row
            .payload_authority
            .as_ref()
            .map_or(Vec::new(), |records| records.iter().collect());
        let in_scope_receipt = if authorities.is_empty() {
            None
        } else {
            let receipt = row.receipt.as_ref().ok_or(StoreError::InvalidReceipt)?;
            receipt.validate()?;
            let binding = &receipt.require_reconciliation_envelope()?.core.work_scope;
            if receipt.status != WriteReceiptStatus::Committed
                || row.named_operation_count != Some(receipt.applied_command_ids.len())
            {
                return Err(StoreError::InvalidReceipt);
            }
            Some((receipt.transition_class, binding.scope_id.as_str().to_owned()))
        };
        for record in authorities {
            let parameters = validate_authority_record(row, record)?;
            let capture_index = operation_base.saturating_add(record.operation_index as u64);
            if let Some((transition_class, scope_id)) = &in_scope_receipt {
                let operation = infer_authority_operation(*transition_class, &parameters)?;
                indexed.push(IndexedAuthority {
                    capture_index,
                    operation,
                    parameters,
                    scope_id: scope_id.clone(),
                });
            }
        }
        operation_base =
            operation_base.saturating_add(row.named_operation_count.unwrap_or(0) as u64);
    }
    Ok(indexed)
}

fn parse_max_records_param(query: &NamedReadRequest) -> Result<(u32, usize), StoreError> {
    let bound_raw = query
        .parameters
        .get("max_records")
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "missing required parameter",
        })?;
    let max_records: u32 = bound_raw.parse().map_err(|_| StoreError::InvalidField {
        field: "operation.parameter",
        reason: "max_records must be a positive decimal bound",
    })?;
    if max_records == 0 {
        return Err(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "max_records must be a positive decimal bound",
        });
    }
    if max_records > EVIDENCE_PACK_MAX_RECORDS {
        return Err(StoreError::PayloadTooLarge);
    }
    let limit = usize::try_from(max_records).map_err(|_| StoreError::PayloadTooLarge)?;
    Ok((max_records, limit))
}

/// Builds the versioned `GetTaskState` payload (T11.3, Surreal).
///
/// Parity with the reference handler: exact scope/`task_id` match over
/// `UpdateTaskState` (`TaskControl`) authority records in durable commit
/// order, explicit `max_records` bound with over-bound refusal, bounded
/// history plus current (last matching parameters) or null, envelope
/// provenance, and zero matches as an exact empty — never an error.
fn task_state_payload(
    query: &NamedReadRequest,
    state_fence: &StateFence,
    rows: &[AuthorityReceiptRow],
) -> Result<Value, StoreError> {
    let scope_id = query.scope_id.clone().ok_or(StoreError::InvalidField {
        field: "scope_id",
        reason: "task state read requires scope_id",
    })?;
    let task_id = query
        .parameters
        .get("task_id")
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "missing required parameter",
        })?;
    if task_id.trim().is_empty() || task_id.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "task_id must be a non-blank string",
        });
    }
    let (max_records, limit) = parse_max_records_param(query)?;
    if query.state_fence != *state_fence {
        return Err(StoreError::FenceMismatch);
    }
    let indexed = indexed_authorities(rows)?;
    let matched: Vec<&IndexedAuthority> = indexed
        .iter()
        .filter(|record| {
            record.scope_id == scope_id.as_str()
                && record.operation == eliot_store_api::NamedMutationOperation::UpdateTaskState
                && record.parameters.get("task_id").and_then(Value::as_str) == Some(task_id)
        })
        .collect();
    let matched_total = matched.len();
    let current = matched.last().map(|record| record.parameters.clone());
    let records: Vec<Value> = matched
        .into_iter()
        .take(limit)
        .map(|record| {
            json!({
                "capture_index": record.capture_index,
                "operation": named_mutation_operation_name(record.operation),
                "parameters": record.parameters,
            })
        })
        .collect();
    let returned = records.len();
    Ok(json!({
        "version": TASK_STATE_PAYLOAD_VERSION,
        "task_id": task_id,
        "scope_id": scope_id,
        "records": records,
        "current": current,
        "provenance": {
            "state_fence": state_fence,
            "matched_total": matched_total,
            "returned": returned,
            "max_records": max_records,
            "truncated": matched_total > returned,
        },
    }))
}

/// Builds the versioned `GetAttentionAndProblems` payload (T11.3, Surreal).
fn attention_problems_payload(
    query: &NamedReadRequest,
    state_fence: &StateFence,
    rows: &[AuthorityReceiptRow],
) -> Result<Value, StoreError> {
    let scope_id = query.scope_id.clone().ok_or(StoreError::InvalidField {
        field: "scope_id",
        reason: "attention read requires scope_id",
    })?;
    let problem_id = match query.parameters.get("problem_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => {
            if text.trim().is_empty() || text.chars().any(char::is_control) {
                return Err(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "problem_id must be a non-blank string",
                });
            }
            Some(text.as_str())
        }
        Some(_) => {
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "problem_id must be a non-blank string",
            });
        }
    };
    let (max_records, limit) = parse_max_records_param(query)?;
    if query.state_fence != *state_fence {
        return Err(StoreError::FenceMismatch);
    }
    let indexed = indexed_authorities(rows)?;
    let matched: Vec<&IndexedAuthority> = indexed
        .iter()
        .filter(|record| {
            record.scope_id == scope_id.as_str()
                && record.operation == eliot_store_api::NamedMutationOperation::ReconcileRecovery
                && problem_id.is_none_or(|wanted| {
                    record.parameters.get("problem_id").and_then(Value::as_str) == Some(wanted)
                })
        })
        .collect();
    let matched_total = matched.len();
    let records: Vec<Value> = matched
        .into_iter()
        .take(limit)
        .map(|record| {
            json!({
                "capture_index": record.capture_index,
                "operation": named_mutation_operation_name(record.operation),
                "parameters": record.parameters,
            })
        })
        .collect();
    let returned = records.len();
    Ok(json!({
        "version": ATTENTION_PROBLEMS_PAYLOAD_VERSION,
        "scope_id": scope_id,
        "problem_id": problem_id,
        "records": records,
        "provenance": {
            "state_fence": state_fence,
            "matched_total": matched_total,
            "returned": returned,
            "max_records": max_records,
            "truncated": matched_total > returned,
        },
    }))
}

/// Builds the versioned `GetUnderstandingProjectionInputs` payload (T11.3, Surreal).
fn understanding_inputs_payload(
    query: &NamedReadRequest,
    state_fence: &StateFence,
    rows: &[AuthorityReceiptRow],
) -> Result<Value, StoreError> {
    let scope_id = query.scope_id.clone().ok_or(StoreError::InvalidField {
        field: "scope_id",
        reason: "understanding inputs read requires scope_id",
    })?;
    let selector = query
        .parameters
        .get("selector")
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "missing required parameter",
        })?;
    if selector.trim().is_empty() || selector.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "selector must be a non-blank string",
        });
    }
    let (max_records, limit) = parse_max_records_param(query)?;
    if query.state_fence != *state_fence {
        return Err(StoreError::FenceMismatch);
    }
    let indexed = indexed_authorities(rows)?;
    let matched: Vec<&IndexedAuthority> = indexed
        .iter()
        .filter(|record| {
            record.scope_id == scope_id.as_str()
                && record
                    .parameters
                    .values()
                    .any(|value| value.as_str() == Some(selector))
        })
        .collect();
    let matched_total = matched.len();
    let records: Vec<Value> = matched
        .into_iter()
        .take(limit)
        .map(|record| {
            json!({
                "capture_index": record.capture_index,
                "operation": named_mutation_operation_name(record.operation),
                "parameters": record.parameters,
            })
        })
        .collect();
    let returned = records.len();
    Ok(json!({
        "version": UNDERSTANDING_INPUTS_PAYLOAD_VERSION,
        "selector": selector,
        "scope_id": scope_id,
        "records": records,
        "provenance": {
            "state_fence": state_fence,
            "matched_total": matched_total,
            "returned": returned,
            "max_records": max_records,
            "truncated": matched_total > returned,
        },
    }))
}

/// Builds the versioned `GetCapabilityEvidenceState` payload (T11.3, Surreal).
fn capability_evidence_payload(
    query: &NamedReadRequest,
    state_fence: &StateFence,
    rows: &[AuthorityReceiptRow],
) -> Result<Value, StoreError> {
    let scope_id = query.scope_id.clone().ok_or(StoreError::InvalidField {
        field: "scope_id",
        reason: "capability evidence read requires scope_id",
    })?;
    let skill_id = query
        .parameters
        .get("skill_id")
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "missing required parameter",
        })?;
    if skill_id.trim().is_empty() || skill_id.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "skill_id must be a non-blank string",
        });
    }
    let (max_records, limit) = parse_max_records_param(query)?;
    if query.state_fence != *state_fence {
        return Err(StoreError::FenceMismatch);
    }
    let indexed = indexed_authorities(rows)?;
    let matched: Vec<&IndexedAuthority> = indexed
        .iter()
        .filter(|record| {
            record.scope_id == scope_id.as_str()
                && record.operation
                    == eliot_store_api::NamedMutationOperation::ApplyLifecyclePolicy
                && record.parameters.get("skill_id").and_then(Value::as_str) == Some(skill_id)
        })
        .collect();
    let matched_total = matched.len();
    let records: Vec<Value> = matched
        .into_iter()
        .take(limit)
        .map(|record| {
            json!({
                "capture_index": record.capture_index,
                "operation": named_mutation_operation_name(record.operation),
                "parameters": record.parameters,
            })
        })
        .collect();
    let returned = records.len();
    Ok(json!({
        "version": CAPABILITY_EVIDENCE_PAYLOAD_VERSION,
        "skill_id": skill_id,
        "scope_id": scope_id,
        "records": records,
        "provenance": {
            "state_fence": state_fence,
            "matched_total": matched_total,
            "returned": returned,
            "max_records": max_records,
            "truncated": matched_total > returned,
        },
    }))
}

async fn read_all_revision_heads(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<Vec<RevisionHead>, AdapterError> {
    let mut response = client::query(
        db,
        config,
        "read.all_revision_heads",
        schema::READ_ALL_REVISION_HEADS,
        Map::new(),
    )
    .await?;
    let heads = take_vec::<RevisionHead>(&mut response, 0)?;
    validate_revision_heads(&heads)?;
    Ok(heads)
}

async fn read_all_ordering_heads(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<Vec<OrderingHead>, AdapterError> {
    let mut response = client::query(
        db,
        config,
        "read.all_ordering_heads",
        schema::READ_ALL_ORDERING_HEADS,
        Map::new(),
    )
    .await?;
    let heads = take_vec::<OrderingHead>(&mut response, 0)?;
    plan::validate_ordering_heads(&heads)?;
    Ok(heads)
}

#[cfg(test)]
mod admitted_read_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use eliot_store_api::ReadConsistency;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn test_fence() -> eliot_store_api::StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("epoch");
        eliot_store_api::StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn read_request(
        operation: NamedReadOperation,
        scope_id: Option<ScopeId>,
        parameters: BTreeMap<String, Value>,
    ) -> NamedReadRequest {
        NamedReadRequest {
            operation,
            scope_id,
            consistency: ReadConsistency::Eventual,
            state_fence: test_fence(),
            parameters,
        }
    }

    #[test]
    fn activated_reads_are_accepted_before_dispatch() {
        for request in [
            read_request(NamedReadOperation::GetRevisionHeads, None, BTreeMap::new()),
            read_request(NamedReadOperation::GetOrderingHeads, None, BTreeMap::new()),
            read_request(
                NamedReadOperation::GetScopeRevisionView,
                Some(ScopeId::new("scope-1").expect("scope")),
                BTreeMap::new(),
            ),
            read_request(
                NamedReadOperation::ResolveWriteReceipt,
                None,
                BTreeMap::from([("operation_id".to_owned(), json!("op-1"))]),
            ),
            read_request(
                NamedReadOperation::GetEvidencePack,
                Some(ScopeId::new("scope-1").expect("scope")),
                BTreeMap::from([
                    ("subject".to_owned(), json!("observation-1")),
                    ("max_records".to_owned(), json!("10")),
                ]),
            ),
            read_request(
                NamedReadOperation::GetCurrentEpistemicPosition,
                Some(ScopeId::new("scope-1").expect("scope")),
                BTreeMap::from([("position".to_owned(), json!("position-1"))]),
            ),
            read_request(
                NamedReadOperation::GetTaskState,
                Some(ScopeId::new("scope-1").expect("scope")),
                BTreeMap::from([
                    ("task_id".to_owned(), json!("task-1")),
                    ("max_records".to_owned(), json!("10")),
                ]),
            ),
            read_request(
                NamedReadOperation::GetAttentionAndProblems,
                Some(ScopeId::new("scope-1").expect("scope")),
                BTreeMap::from([("max_records".to_owned(), json!("10"))]),
            ),
            read_request(
                NamedReadOperation::GetUnderstandingProjectionInputs,
                Some(ScopeId::new("scope-1").expect("scope")),
                BTreeMap::from([
                    ("selector".to_owned(), json!("task-1")),
                    ("max_records".to_owned(), json!("10")),
                ]),
            ),
            read_request(
                NamedReadOperation::GetCapabilityEvidenceState,
                Some(ScopeId::new("scope-1").expect("scope")),
                BTreeMap::from([
                    ("skill_id".to_owned(), json!("skill-1")),
                    ("max_records".to_owned(), json!("10")),
                ]),
            ),
        ] {
            assert!(
                validate_named_against_active_catalogue(&request).is_ok(),
                "activated read must pass the pre-dispatch gate: {:?}",
                request.operation
            );
        }
    }

    #[test]
    fn extra_unknown_and_control_parameters_are_rejected_before_dispatch() {
        // Extra undeclared parameter on an activated read.
        let extra = read_request(
            NamedReadOperation::GetRevisionHeads,
            None,
            BTreeMap::from([("extra".to_owned(), json!(1))]),
        );
        assert!(matches!(
            validate_named_against_active_catalogue(&extra),
            Err(StoreError::InvalidField { .. })
        ));
        // Control-substitution parameter name.
        let control = read_request(
            NamedReadOperation::GetRevisionHeads,
            None,
            BTreeMap::from([("state_fence".to_owned(), json!("x"))]),
        );
        assert!(matches!(
            validate_named_against_active_catalogue(&control),
            Err(StoreError::InvalidField {
                field: "payload.control_field",
                ..
            })
        ));
        // Known-but-unadvertised operation stays unsupported (T11.3 activates
        // GetTaskState, so the negative case moves to a still-unsupported op).
        let unadvertised = read_request(NamedReadOperation::GetMailbox, None, BTreeMap::new());
        assert_eq!(
            validate_named_against_active_catalogue(&unadvertised),
            Err(StoreError::UnknownOperation)
        );
        // Missing required typed parameter.
        let missing = read_request(
            NamedReadOperation::ResolveWriteReceipt,
            None,
            BTreeMap::new(),
        );
        assert!(matches!(
            validate_named_against_active_catalogue(&missing),
            Err(StoreError::InvalidField { .. })
        ));
        // Scope declaration mismatch in both directions.
        let stray_scope = read_request(
            NamedReadOperation::GetRevisionHeads,
            Some(ScopeId::new("scope-1").expect("scope")),
            BTreeMap::new(),
        );
        assert!(validate_named_against_active_catalogue(&stray_scope).is_err());
        let missing_scope = read_request(
            NamedReadOperation::GetScopeRevisionView,
            None,
            BTreeMap::new(),
        );
        assert!(validate_named_against_active_catalogue(&missing_scope).is_err());
    }

    // --- T11.1 GetEvidencePack behaviour (real plan outputs, no canned rows) ---

    pub(super) fn capture_transition(
        operation_id: &str,
        subject: &str,
    ) -> eliot_store_api::PreparedTransition {
        use eliot_store_api::{
            EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
            NamedMutationRequest, OperationIdentity, OperationManifestDigest, OrderingScopeId,
            SecurityContext, TransitionClass,
        };
        let fence = test_fence();
        eliot_store_api::PreparedTransition {
            identity: OperationIdentity {
                operation_id: eliot_store_api::OperationId::new(operation_id).expect("operation"),
                idempotency_key: format!("idem-{operation_id}"),
                canonical_request_hash: "a".repeat(64),
            },
            state_fence: fence,
            scope_id: ScopeId::new("scope-1").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope-1").expect("ordering")],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "b".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest-1")
                .expect("manifest digest"),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters: BTreeMap::from([("subject".to_owned(), json!(subject))]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        }
    }

    /// Plans one capture through the real planner and renders its durable
    /// receipt row (the same shape `write_transaction` persists and the
    /// closed SELECT returns). Never a canned row: bytes, digest, and order
    /// all come from [`crate::plan`].
    fn evidence_row_for(
        operation_id: &str,
        subject: &str,
        commit_sequence: u64,
    ) -> EvidenceReceiptRow {
        use crate::plan::plan_apply;
        let transition = capture_transition(operation_id, subject);
        let plan = plan_apply(&transition, &[], &[], commit_sequence, 1).expect("plan applies");
        assert_eq!(
            plan.evidence_records.len(),
            1,
            "one capture plans exactly one evidence record"
        );
        let record = &plan.evidence_records[0];
        EvidenceReceiptRow {
            receipt: Some(
                plan::build_receipt(&capture_context(), &transition, &plan).expect("receipt"),
            ),
            commit_sequence: Some(plan.commit_sequence),
            named_operation_count: Some(transition.named_operations.len()),
            evidence_records: Some(vec![EvidenceRecordRow {
                operation_index: record.operation_index,
                subject: record.subject.clone(),
                parameters: record.parameters.clone(),
                version: record.version,
                encoding: record.encoding.clone(),
                digest_hex: record.digest_hex.clone(),
                byte_len: record.byte_len,
                bytes_utf8: String::from_utf8(record.bytes.clone()).expect("UTF-8 bytes"),
                commit_sequence: record.commit_sequence,
                named_operation_count: record.named_operation_count,
            }]),
        }
    }

    pub(super) fn capture_context() -> eliot_store_api::RequestMeta {
        use eliot_contracts::{ClockReading, ProductId, RequestId, SourceId};
        eliot_store_api::RequestMeta {
            request_id: RequestId::new("evidence-scope-request").expect("request"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("evidence-scope-product").expect("product"),
            source_id: SourceId::new("evidence-scope-source").expect("source"),
            state_fence: test_fence(),
            clock: ClockReading {
                valid_time_ms: Some(1000),
                known_time_ms: Some(1001),
                ..ClockReading::default()
            },
        }
    }

    #[test]
    fn evidence_pack_requires_receipt_scope_and_current_read_fence() {
        let fence = test_fence();
        let query = evidence_query("shared-subject", "1");
        let no_suppression = ErasureSuppression::Known(std::collections::BTreeSet::new());
        let row = evidence_row_for("scope-provenance", "shared-subject", 1);
        let mut wrong_scope_query = query.clone();
        wrong_scope_query.scope_id = Some(ScopeId::new("other").expect("scope"));
        let absent = evidence_pack_payload(
            &wrong_scope_query,
            &fence,
            std::slice::from_ref(&row),
            &no_suppression,
        )
        .expect("empty");
        assert_eq!(absent["provenance"]["matched_total"], json!(0));
        let mut no_receipt = row.clone();
        no_receipt.receipt = None;
        assert_eq!(
            evidence_pack_payload(&query, &fence, &[no_receipt], &no_suppression),
            Err(StoreError::InvalidReceipt)
        );
        let mut no_envelope = row.clone();
        no_envelope.receipt.as_mut().expect("receipt").envelope = None;
        assert_eq!(
            evidence_pack_payload(&query, &fence, &[no_envelope], &no_suppression),
            Err(StoreError::MissingReceiptEnvelope)
        );
        let mut other_fence = fence.clone();
        other_fence.resource_generation =
            eliot_contracts::ResourceGeneration::new(2).expect("generation");
        let mut newer_query = query.clone();
        newer_query.state_fence = other_fence.clone();
        let historical = evidence_pack_payload(
            &newer_query,
            &other_fence,
            std::slice::from_ref(&row),
            &no_suppression,
        )
        .expect("historical captures remain visible under a current read fence");
        assert_eq!(historical["provenance"]["matched_total"], json!(1));
        assert_eq!(historical["provenance"]["state_fence"], json!(other_fence));
        assert_eq!(
            historical["records"][0]["parameters"]["subject"],
            json!("shared-subject")
        );
        assert_eq!(
            evidence_pack_payload(&query, &other_fence, &[row], &no_suppression),
            Err(StoreError::FenceMismatch),
            "a historical record cannot authorize a stale read request",
        );
    }

    /// Builds the empty sealed suppression set shared by the pre-erasure pack
    /// tests below: no sealed erasure rows, so no pair suppresses.
    fn empty_suppression() -> ErasureSuppression {
        ErasureSuppression::Known(std::collections::BTreeSet::new())
    }

    pub(super) fn evidence_query(subject: &str, max_records: &str) -> NamedReadRequest {
        read_request(
            NamedReadOperation::GetEvidencePack,
            Some(ScopeId::new("scope-1").expect("scope")),
            BTreeMap::from([
                ("subject".to_owned(), json!(subject)),
                ("max_records".to_owned(), json!(max_records)),
            ]),
        )
    }

    #[test]
    fn evidence_pack_returns_exact_captured_record_with_provenance() {
        let fence = test_fence();
        let rows = vec![evidence_row_for("op-evidence-1", "evidence-alpha", 1)];
        let query = evidence_query("evidence-alpha", "10");
        assert!(
            validate_named_against_active_catalogue(&query).is_ok(),
            "activated pack passes the gate"
        );
        let payload =
            evidence_pack_payload(&query, &fence, &rows, &empty_suppression())
                .expect("pack builds");
        assert_eq!(
            payload.get("version").and_then(Value::as_u64),
            Some(u64::from(EVIDENCE_PACK_PAYLOAD_VERSION))
        );
        assert_eq!(
            payload.get("subject").and_then(Value::as_str),
            Some("evidence-alpha")
        );
        let records = payload
            .get("records")
            .and_then(Value::as_array)
            .expect("records array");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].get("operation").and_then(Value::as_str),
            Some("CaptureObservation")
        );
        assert_eq!(
            records[0].get("capture_index").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            records[0]
                .get("parameters")
                .and_then(|parameters| parameters.get("subject"))
                .and_then(Value::as_str),
            Some("evidence-alpha")
        );
        let provenance = payload
            .get("provenance")
            .and_then(Value::as_object)
            .expect("provenance object");
        assert_eq!(
            provenance.get("state_fence"),
            Some(&serde_json::to_value(&fence).expect("fence serializes"))
        );
        assert_eq!(
            provenance.get("matched_total").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(provenance.get("returned").and_then(Value::as_u64), Some(1));
        assert_eq!(
            provenance.get("max_records").and_then(Value::as_u64),
            Some(10)
        );
        assert_eq!(
            provenance.get("truncated").and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn evidence_pack_absence_is_an_exact_empty_result() {
        let fence = test_fence();
        let rows = vec![evidence_row_for("op-evidence-2", "evidence-alpha", 1)];
        let query = evidence_query("evidence-missing", "10");
        let payload =
            evidence_pack_payload(&query, &fence, &rows, &empty_suppression())
                .expect("empty pack builds");
        let records = payload
            .get("records")
            .and_then(Value::as_array)
            .expect("records array");
        assert!(records.is_empty(), "unknown subject is empty, not an error");
        let provenance = payload
            .get("provenance")
            .and_then(Value::as_object)
            .expect("provenance object");
        assert_eq!(
            provenance.get("matched_total").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            provenance.get("truncated").and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn evidence_pack_wrong_fence_is_refused_by_the_shared_resolver() {
        use eliot_contracts::{EpochId, EpochLineageId};
        use std::num::NonZeroU64;
        let fence = test_fence();
        let fence_record = FenceRecord {
            state_fence: fence.clone(),
            next_commit_sequence: 2,
            next_outbox_sequence: 1,
        };
        assert_eq!(
            resolve_state_fence(Some(&fence_record), &fence).expect("matching fence resolves"),
            fence
        );
        assert!(resolve_state_fence(None, &fence).is_ok());
        let other = {
            let lineage =
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
            let epoch =
                EpochId::new(lineage, NonZeroU64::new(2).expect("non-zero")).expect("epoch");
            eliot_store_api::StateFence::new(epoch, eliot_contracts::ResourceGeneration::genesis())
        };
        assert_ne!(other, fence);
        assert_eq!(
            resolve_state_fence(Some(&fence_record), &other),
            Err(AdapterError::Store(StoreError::FenceMismatch)),
            "the pre-dispatch fence check refuses a changed fence before any evidence read"
        );
    }

    #[test]
    fn evidence_pack_over_bound_request_is_refused() {
        let fence = test_fence();
        let rows = vec![evidence_row_for("op-evidence-4", "evidence-alpha", 1)];
        for bound in [
            (EVIDENCE_PACK_MAX_RECORDS + 1).to_string(),
            "1000".to_owned(),
        ] {
            let query = evidence_query("evidence-alpha", &bound);
            assert_eq!(
                evidence_pack_payload(&query, &fence, &rows, &empty_suppression()),
                Err(StoreError::PayloadTooLarge),
                "bound {bound} exceeds the declared maximum"
            );
        }
        let query = evidence_query("evidence-alpha", &format!("{EVIDENCE_PACK_MAX_RECORDS}"));
        assert!(
            evidence_pack_payload(&query, &fence, &rows, &empty_suppression()).is_ok(),
            "the exact maximum stays admissible"
        );
    }

    #[test]
    fn evidence_pack_exact_subject_match_never_substring() {
        let fence = test_fence();
        let rows = vec![evidence_row_for("op-exact-1", "observation-1", 1)];
        // Substring and superstring selectors match nothing — never a
        // successful view of a neighbouring subject.
        for selector in ["observation", "observation-1-extra", "OBSERVATION-1"] {
            let query = evidence_query(selector, "10");
            let payload =
                evidence_pack_payload(&query, &fence, &rows, &empty_suppression())
                    .expect("non-match builds");
            assert!(
                payload
                    .get("records")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty),
                "selector {selector} must not substring-match"
            );
        }
        let query = evidence_query("observation-1", "10");
        let payload =
            evidence_pack_payload(&query, &fence, &rows, &empty_suppression()).expect("exact builds");
        assert_eq!(
            payload
                .get("records")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn evidence_pack_bounds_results_with_visible_truncation() {
        let fence = test_fence();
        let rows = vec![
            evidence_row_for("op-bulk-1", "evidence-bulk", 1),
            evidence_row_for("op-bulk-2", "evidence-bulk", 2),
            evidence_row_for("op-bulk-3", "evidence-bulk", 3),
        ];
        let query = evidence_query("evidence-bulk", "2");
        let payload =
            evidence_pack_payload(&query, &fence, &rows, &empty_suppression())
                .expect("bounded pack builds");
        let records = payload
            .get("records")
            .and_then(Value::as_array)
            .expect("records array");
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].get("capture_index").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            records[1].get("capture_index").and_then(Value::as_u64),
            Some(1)
        );
        let provenance = payload
            .get("provenance")
            .and_then(Value::as_object)
            .expect("provenance object");
        assert_eq!(
            provenance.get("matched_total").and_then(Value::as_u64),
            Some(3)
        );
        assert_eq!(provenance.get("returned").and_then(Value::as_u64), Some(2));
        assert_eq!(
            provenance.get("truncated").and_then(Value::as_bool),
            Some(true)
        );
        let query = evidence_query("evidence-bulk", "3");
        let payload =
            evidence_pack_payload(&query, &fence, &rows, &empty_suppression())
                .expect("full pack builds");
        assert_eq!(
            payload
                .get("provenance")
                .and_then(Value::as_object)
                .and_then(|provenance| provenance.get("truncated"))
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn evidence_pack_malformed_selectors_fail_closed() {
        let fence = test_fence();
        let rows = vec![evidence_row_for("op-malformed-1", "evidence-alpha", 1)];
        // Missing scope on a scope-addressed read.
        let query = read_request(
            NamedReadOperation::GetEvidencePack,
            None,
            BTreeMap::from([
                ("subject".to_owned(), json!("evidence-alpha")),
                ("max_records".to_owned(), json!("10")),
            ]),
        );
        assert!(matches!(
            evidence_pack_payload(&query, &fence, &rows, &empty_suppression()),
            Err(StoreError::InvalidField {
                field: "scope_id",
                ..
            })
        ));
        // Missing subject selector.
        let query = read_request(
            NamedReadOperation::GetEvidencePack,
            Some(ScopeId::new("scope-1").expect("scope")),
            BTreeMap::from([("max_records".to_owned(), json!("10"))]),
        );
        assert!(matches!(
            evidence_pack_payload(&query, &fence, &rows, &empty_suppression()),
            Err(StoreError::InvalidField { .. })
        ));
        // Zero and non-decimal bounds fail the bound shape.
        for bound in ["0", "many"] {
            let query = evidence_query("evidence-alpha", bound);
            assert!(
                matches!(
                    evidence_pack_payload(&query, &fence, &rows, &empty_suppression()),
                    Err(StoreError::InvalidField { .. })
                ),
                "bound {bound} must fail closed"
            );
        }
    }

    #[test]
    fn evidence_pack_excludes_sealed_erased_subject_scope_pair() {
        // 688-STORE-2: sealed intent + sealed `PURGED` store-owned outcome
        // suppress the exact pair (memory `erased_subjects` parity), even
        // though the capture row remains. A neighbouring subject in the same
        // scope still reads — suppression is exact-pair, never whole-scope.
        let fence = test_fence();
        let rows = vec![
            evidence_row_for("op-erased-1", "evidence-erased", 1),
            evidence_row_for("op-kept-1", "evidence-kept", 2),
        ];
        let intents = vec![ErasureIntentRow {
            operation_id: "erasure-op-1".to_owned(),
            subject: "evidence-erased".to_owned(),
            scope_id: "scope-1".to_owned(),
        }];
        let outcomes = vec![ErasureOutcomeRow {
            operation_id: "erasure-op-1".to_owned(),
            outcomes: vec!["PURGED:CanonicalPayload".to_owned()],
        }];
        let suppression = ErasureSuppression::Known(suppressed_pairs(&intents, &outcomes));
        let erased = evidence_pack_payload(
            &evidence_query("evidence-erased", "10"),
            &fence,
            &rows,
            &suppression,
        )
        .expect("erased pack builds exact empty");
        assert!(
            erased
                .get("records")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty),
            "sealed erased pair serves no records"
        );
        assert_eq!(erased["provenance"]["matched_total"], json!(0));
        assert_eq!(erased["provenance"]["returned"], json!(0));
        assert_eq!(erased["provenance"]["truncated"], json!(false));
        let kept = evidence_pack_payload(
            &evidence_query("evidence-kept", "10"),
            &fence,
            &rows,
            &suppression,
        )
        .expect("neighbouring subject still reads");
        assert_eq!(
            kept.get("records")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        // An `UNKNOWN`-only outcome never suppresses: the row stays visible
        // and the pack still serves it (reconciliation owns the ambiguity,
        // never silent hiding).
        let unknown_outcomes = vec![ErasureOutcomeRow {
            operation_id: "erasure-op-1".to_owned(),
            outcomes: vec!["UNKNOWN:CanonicalPayload".to_owned()],
        }];
        let unknown_suppression =
            ErasureSuppression::Known(suppressed_pairs(&intents, &unknown_outcomes));
        let visible = evidence_pack_payload(
            &evidence_query("evidence-erased", "10"),
            &fence,
            &rows,
            &unknown_suppression,
        )
        .expect("unknown outcome keeps the row visible");
        assert_eq!(visible["provenance"]["matched_total"], json!(1));
    }

    #[test]
    fn evidence_pack_refuses_fail_closed_when_erasure_lookup_is_unknown() {
        // 688-STORE-2: an unavailable/unparsable erasure-outcome lookup
        // refuses with `Unavailable` instead of silently including records
        // that may have been erased.
        let fence = test_fence();
        let rows = vec![evidence_row_for("op-unknown-1", "evidence-alpha", 1)];
        let query = evidence_query("evidence-alpha", "10");
        assert_eq!(
            evidence_pack_payload(&query, &fence, &rows, &ErasureSuppression::Unknown),
            Err(StoreError::Unavailable),
            "unknown suppression state must refuse the pack read"
        );
    }

    // --- T11.3 cognitive reads (real plan outputs, no canned rows) ---

    /// Task transition shape awaiting operation-aware persistence (see
    /// `task_state_returns_exact_history_with_current`): kept so the intended
    /// canonical record shape stays compiler-checked.
    #[allow(dead_code)]
    fn task_transition(
        operation_id: &str,
        task_id: &str,
        to: &str,
    ) -> eliot_store_api::PreparedTransition {
        use eliot_store_api::{
            EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
            NamedMutationRequest, OperationIdentity, OperationManifestDigest, OrderingScopeId,
            SecurityContext, TransitionClass,
        };
        let fence = test_fence();
        eliot_store_api::PreparedTransition {
            identity: OperationIdentity {
                operation_id: eliot_store_api::OperationId::new(operation_id).expect("operation"),
                idempotency_key: format!("idem-{operation_id}"),
                canonical_request_hash: "a".repeat(64),
            },
            state_fence: fence,
            scope_id: ScopeId::new("scope-1").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope-1").expect("ordering")],
            transition_class: TransitionClass::TaskControl,
            requested_effect_ceiling: EffectClass::ReversibleMutation,
            admission_contract_set_digest: "b".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest-1")
                .expect("manifest digest"),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::UpdateTaskState,
                parameters: BTreeMap::from([
                    ("task_id".to_owned(), json!(task_id)),
                    ("event_id".to_owned(), json!(format!("event-{operation_id}"))),
                    ("to".to_owned(), json!(to)),
                    ("expected_revision".to_owned(), json!("1")),
                    ("actor_ref".to_owned(), json!("actor-1")),
                ]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        }
    }

    /// Recovery transition shape awaiting operation-aware persistence (see
    /// `attention_problems_filters_and_bounds_with_truncation`).
    #[allow(dead_code)]
    fn recovery_transition(
        operation_id: &str,
        problem_id: &str,
    ) -> eliot_store_api::PreparedTransition {
        use eliot_store_api::{
            EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
            NamedMutationRequest, OperationIdentity, OperationManifestDigest, OrderingScopeId,
            SecurityContext, TransitionClass,
        };
        let fence = test_fence();
        eliot_store_api::PreparedTransition {
            identity: OperationIdentity {
                operation_id: eliot_store_api::OperationId::new(operation_id).expect("operation"),
                idempotency_key: format!("idem-{operation_id}"),
                canonical_request_hash: "a".repeat(64),
            },
            state_fence: fence,
            scope_id: ScopeId::new("scope-1").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope-1").expect("ordering")],
            transition_class: TransitionClass::RecoverySchema,
            requested_effect_ceiling: EffectClass::ReversibleMutation,
            admission_contract_set_digest: "b".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest-1")
                .expect("manifest digest"),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::ReconcileRecovery,
                parameters: BTreeMap::from([
                    ("problem_id".to_owned(), json!(problem_id)),
                    ("expected_problem_revision".to_owned(), json!("1")),
                    ("attempt_digest".to_owned(), json!("a".repeat(64))),
                    ("effect_digest".to_owned(), json!("b".repeat(64))),
                    (
                        "operation_manifest_digest".to_owned(),
                        json!("c".repeat(64)),
                    ),
                    ("artifact_binding_digest".to_owned(), json!("b".repeat(64))),
                    ("fence_digest".to_owned(), json!("d".repeat(64))),
                    ("observation_operation_id".to_owned(), json!("op-1")),
                    ("observation_record_id".to_owned(), json!("record-1")),
                    (
                        "observation_request_digest".to_owned(),
                        json!("e".repeat(64)),
                    ),
                ]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        }
    }

    fn lifecycle_transition(
        operation_id: &str,
        skill_id: &str,
    ) -> eliot_store_api::PreparedTransition {
        use eliot_store_api::{
            EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
            NamedMutationRequest, OperationIdentity, OperationManifestDigest, OrderingScopeId,
            SecurityContext, TransitionClass,
        };
        let fence = test_fence();
        eliot_store_api::PreparedTransition {
            identity: OperationIdentity {
                operation_id: eliot_store_api::OperationId::new(operation_id).expect("operation"),
                idempotency_key: format!("idem-{operation_id}"),
                canonical_request_hash: "a".repeat(64),
            },
            state_fence: fence,
            scope_id: ScopeId::new("scope-1").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope-1").expect("ordering")],
            transition_class: TransitionClass::LifecyclePolicy,
            requested_effect_ceiling: EffectClass::ReversibleMutation,
            admission_contract_set_digest: "b".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest-1")
                .expect("manifest digest"),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::ApplyLifecyclePolicy,
                parameters: BTreeMap::from([
                    ("action".to_owned(), json!("keep")),
                    ("base_view_digest".to_owned(), json!("a".repeat(64))),
                    ("candidate_digest".to_owned(), json!("b".repeat(64))),
                    ("candidate_package_digest".to_owned(), json!("c".repeat(64))),
                    ("skill_id".to_owned(), json!(skill_id)),
                    ("verifier_ref".to_owned(), json!("verifier-1")),
                ]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        }
    }

    /// Plans one transition through the real planner with its real payload
    /// authority and renders the durable authority receipt row. Never a
    /// canned row: bytes, digest, and order all come from [`crate::plan`].
    fn authority_row_for(
        transition: &eliot_store_api::PreparedTransition,
        commit_sequence: u64,
    ) -> AuthorityReceiptRow {
        use crate::plan::plan_apply_with_payload_authority;
        use eliot_store_api::{ExactJsonBytes, PayloadSource, canonical_json_bytes};
        let raw = canonical_json_bytes(&transition.named_operations[0].parameters)
            .expect("parameters serialize");
        let authority = ExactJsonBytes::parse(PayloadSource::NamedOperationParameter, &raw)
            .expect("authority parses");
        let plan = plan_apply_with_payload_authority(
            transition,
            &[Some(authority)],
            &[],
            &[],
            commit_sequence,
            1,
        )
        .expect("plan applies");
        assert_eq!(
            plan.payload_authority.len(),
            1,
            "one operation plans exactly one authority record"
        );
        let record = &plan.payload_authority[0];
        AuthorityReceiptRow {
            receipt: Some(
                plan::build_receipt(&capture_context(), transition, &plan).expect("receipt"),
            ),
            commit_sequence: Some(plan.commit_sequence),
            named_operation_count: Some(transition.named_operations.len()),
            payload_authority: Some(vec![AuthorityRecordRow {
                operation_index: record.operation_index,
                version: record.version,
                encoding: record.encoding.clone(),
                digest_hex: record.digest_hex.clone(),
                byte_len: record.byte_len,
                bytes_utf8: String::from_utf8(record.bytes.clone()).expect("UTF-8 bytes"),
            }]),
        }
    }

    fn task_query(task_id: &str, max_records: &str) -> NamedReadRequest {
        read_request(
            NamedReadOperation::GetTaskState,
            Some(ScopeId::new("scope-1").expect("scope")),
            BTreeMap::from([
                ("task_id".to_owned(), json!(task_id)),
                ("max_records".to_owned(), json!(max_records)),
            ]),
        )
    }

    fn attention_query(problem_id: Option<&str>, max_records: &str) -> NamedReadRequest {
        let mut parameters = BTreeMap::from([("max_records".to_owned(), json!(max_records))]);
        if let Some(problem_id) = problem_id {
            parameters.insert("problem_id".to_owned(), json!(problem_id));
        }
        read_request(
            NamedReadOperation::GetAttentionAndProblems,
            Some(ScopeId::new("scope-1").expect("scope")),
            parameters,
        )
    }

    fn understanding_query(selector: &str, max_records: &str) -> NamedReadRequest {
        read_request(
            NamedReadOperation::GetUnderstandingProjectionInputs,
            Some(ScopeId::new("scope-1").expect("scope")),
            BTreeMap::from([
                ("selector".to_owned(), json!(selector)),
                ("max_records".to_owned(), json!(max_records)),
            ]),
        )
    }

    fn capability_query(skill_id: &str, max_records: &str) -> NamedReadRequest {
        read_request(
            NamedReadOperation::GetCapabilityEvidenceState,
            Some(ScopeId::new("scope-1").expect("scope")),
            BTreeMap::from([
                ("skill_id".to_owned(), json!(skill_id)),
                ("max_records".to_owned(), json!(max_records)),
            ]),
        )
    }

    #[test]
    fn task_state_returns_exact_history_with_current() {
        // Surreal persistence gap (reported as residual): `UpdateTaskState`
        // owner parameters contain `task_id`, which the generic
        // `ExactJsonBytes` control denylist rejects, so no
        // operation-aware authority binding exists yet (needs `plan.rs` /
        // `atomic_write.rs`, unclaimed here). The handler itself is real
        // (authority-row walk, exact scope/`task_id` match, bound,
        // history + current, provenance); the reference memory handler
        // proves the data path end to end. Here we prove the gate, the
        // exact-empty contract, and filtering against real lifecycle rows.
        let fence = test_fence();
        let rows = vec![authority_row_for(
            &lifecycle_transition("op-task-probe-1", "skill-probe"),
            1,
        )];
        let query = task_query("task-1", "10");
        assert!(
            validate_named_against_active_catalogue(&query).is_ok(),
            "activated task read passes the gate"
        );
        let payload = task_state_payload(&query, &fence, &rows).expect("pack builds");
        assert_eq!(
            payload.get("version").and_then(Value::as_u64),
            Some(u64::from(TASK_STATE_PAYLOAD_VERSION))
        );
        // Lifecycle rows never match a task selector: exact empty, not error.
        assert!(
            payload
                .get("records")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        );
        assert!(payload.get("current").is_some_and(Value::is_null));
        // Unknown task over empty rows is also an exact empty.
        let empty = task_state_payload(
            &task_query("task-missing", "10"),
            &fence,
            &[],
        )
        .expect("empty builds");
        assert!(
            empty
                .get("records")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        );
        assert!(empty.get("current").is_some_and(Value::is_null));
    }

    #[test]
    fn attention_problems_filters_and_bounds_with_truncation() {
        // Same persistence gap as task state: `ReconcileRecovery` owner
        // parameters contain `operation_manifest_digest` (control-denylisted),
        // so no authority binding exists yet. Handler is real; memory proves
        // the data path. Here we prove gate, empty contract, and bound
        // enforcement against real lifecycle rows.
        let fence = test_fence();
        let rows = vec![authority_row_for(
            &lifecycle_transition("op-prob-probe-1", "skill-probe"),
            1,
        )];
        let query = attention_query(Some("problem-1"), "10");
        assert!(
            validate_named_against_active_catalogue(&query).is_ok(),
            "activated attention read passes the gate"
        );
        let payload = attention_problems_payload(&query, &fence, &rows).expect("pack builds");
        assert!(
            payload
                .get("records")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        );
        // Unfiltered listing over empty rows is empty with intact provenance.
        let empty =
            attention_problems_payload(&attention_query(None, "2"), &fence, &[]).expect("builds");
        assert_eq!(
            empty
                .get("records")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        assert_eq!(empty["provenance"]["matched_total"], json!(0));
        assert_eq!(empty["provenance"]["truncated"], json!(false));
    }

    #[test]
    fn understanding_inputs_exact_selector_never_substring() {
        let fence = test_fence();
        // Authority-compatible families only (capture subject + lifecycle
        // skill are control-allowlisted; task/recovery selectors are proven
        // via the reference memory handler until operation-aware persistence
        // lands).
        let rows = vec![
            authority_row_for(&capture_transition("op-und-1", "task-alpha"), 1),
            authority_row_for(&lifecycle_transition("op-und-2", "skill-alpha"), 2),
        ];
        let query = understanding_query("task-alpha", "10");
        assert!(
            validate_named_against_active_catalogue(&query).is_ok(),
            "activated understanding read passes the gate"
        );
        let payload = understanding_inputs_payload(&query, &fence, &rows).expect("pack builds");
        assert_eq!(
            payload
                .get("records")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        // Substring selectors match nothing — never a neighbouring input.
        for selector in ["task", "task-alpha-extra", "TASK-ALPHA"] {
            let query = understanding_query(selector, "10");
            let payload =
                understanding_inputs_payload(&query, &fence, &rows).expect("non-match builds");
            assert!(
                payload
                    .get("records")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty),
                "selector {selector} must not substring-match"
            );
        }
    }

    #[test]
    fn capability_evidence_returns_exact_skill_records() {
        let fence = test_fence();
        let rows = vec![
            authority_row_for(&lifecycle_transition("op-cap-1", "skill-1"), 1),
            authority_row_for(&lifecycle_transition("op-cap-2", "skill-2"), 2),
        ];
        let query = capability_query("skill-1", "10");
        assert!(
            validate_named_against_active_catalogue(&query).is_ok(),
            "activated capability read passes the gate"
        );
        let payload = capability_evidence_payload(&query, &fence, &rows).expect("pack builds");
        assert_eq!(
            payload.get("version").and_then(Value::as_u64),
            Some(u64::from(CAPABILITY_EVIDENCE_PAYLOAD_VERSION))
        );
        let records = payload
            .get("records")
            .and_then(Value::as_array)
            .expect("records array");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].get("operation").and_then(Value::as_str),
            Some("ApplyLifecyclePolicy")
        );
        assert_eq!(
            records[0]
                .get("parameters")
                .and_then(|parameters| parameters.get("skill_id"))
                .and_then(Value::as_str),
            Some("skill-1")
        );
    }

    #[test]
    fn t11_3_malformed_and_over_bound_requests_fail_closed() {
        let fence = test_fence();
        // Authority-compatible rows only (lifecycle); task/recovery rows
        // need operation-aware persistence (see above).
        let rows = vec![authority_row_for(
            &lifecycle_transition("op-mal-1", "skill-1"),
            1,
        )];
        // Missing scope on a scope-addressed read.
        let query = read_request(
            NamedReadOperation::GetTaskState,
            None,
            BTreeMap::from([
                ("task_id".to_owned(), json!("task-1")),
                ("max_records".to_owned(), json!("10")),
            ]),
        );
        assert!(matches!(
            task_state_payload(&query, &fence, &rows),
            Err(StoreError::InvalidField {
                field: "scope_id",
                ..
            })
        ));
        // Missing required selector.
        let query = read_request(
            NamedReadOperation::GetCapabilityEvidenceState,
            Some(ScopeId::new("scope-1").expect("scope")),
            BTreeMap::from([("max_records".to_owned(), json!("10"))]),
        );
        assert!(matches!(
            capability_evidence_payload(&query, &fence, &rows),
            Err(StoreError::InvalidField { .. })
        ));
        // Zero and non-decimal bounds fail the bound shape.
        for bound in ["0", "many"] {
            let query = task_query("task-1", bound);
            assert!(
                matches!(
                    task_state_payload(&query, &fence, &rows),
                    Err(StoreError::InvalidField { .. })
                ),
                "bound {bound} must fail closed"
            );
        }
        // Over-bound requests refuse instead of returning a successful view.
        for bound in [
            (EVIDENCE_PACK_MAX_RECORDS + 1).to_string(),
            "1000".to_owned(),
        ] {
            let query = task_query("task-1", &bound);
            assert_eq!(
                task_state_payload(&query, &fence, &rows),
                Err(StoreError::PayloadTooLarge),
                "bound {bound} exceeds the declared maximum"
            );
        }
        // Wrong fence is refused by the shared resolver contract.
        let mut other_fence = fence.clone();
        other_fence.resource_generation =
            eliot_contracts::ResourceGeneration::new(2).expect("generation");
        let mut stale_query = task_query("task-1", "10");
        stale_query.state_fence = fence.clone();
        assert_eq!(
            task_state_payload(&stale_query, &other_fence, &rows),
            Err(StoreError::FenceMismatch)
        );
    }
}

#[cfg(all(test, windows))]
mod real_scope_tests {
    #![allow(clippy::expect_used, clippy::large_futures, clippy::print_stdout)]

    use super::*;
    use eliot_platform_windows::WindowsPlatform;
    use eliot_store_api::{
        CanonicalRequestView, CanonicalStoreClient, canonical_request_hash,
        operation_manifest_set_digest, sha256_hex,
    };
    use futures_util::FutureExt;
    use secrecy::{ExposeSecret, SecretString};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio::process::Command;
    use tokio::time::{Instant, sleep};

    struct Harness {
        root: PathBuf,
        config: SurrealAdapterConfig,
        adapter: Option<SurrealStoreAdapter>,
    }

    impl Harness {
        async fn start() -> Self {
            let port = TcpListener::bind("127.0.0.1:0")
                .expect("loopback")
                .local_addr()
                .expect("address")
                .port();
            let root =
                std::env::temp_dir().join(format!("eliot-evidence-scope-{}", uuid::Uuid::new_v4()));
            let exe = root.join("bin/surreal.exe");
            let data = root.join("store/data");
            let work = root.join("store/work");
            let tmp = root.join("store/tmp");
            for path in [root.join("bin"), data.clone(), work.clone(), tmp.clone()] {
                std::fs::create_dir_all(path).expect("isolated root");
            }
            let provider = std::env::var_os("ELIOT_TEST_SURREAL_EXE").map_or_else(
                || PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
                PathBuf::from,
            );
            std::fs::copy(provider, &exe).expect("stage provider");
            let digest = sha256_hex(&std::fs::read(&exe).expect("provider bytes"));
            let bind = format!("127.0.0.1:{port}");
            let mut config = SurrealAdapterConfig {
                endpoint: format!("ws://{bind}/rpc"),
                namespace: "scope_test".into(),
                database: "evidence".into(),
                username: "scope-test".into(),
                password: SecretString::new(format!("test-{}", uuid::Uuid::new_v4()).into()),
                provider_bind_address: bind,
                installation_id: "evidence-scope-test".into(),
                installation_profile: "portable_dev".into(),
                runtime_state_roots_digest: "a".repeat(64),
                provider_executable_path: exe.to_string_lossy().into_owned(),
                provider_artifact_digest: digest,
                provider_arguments: Vec::new(),
                store_data_root: data.to_string_lossy().into_owned(),
                store_work_root: work.to_string_lossy().into_owned(),
                store_temp_root: tmp.to_string_lossy().into_owned(),
                connect_timeout_ms: 30_000,
                query_timeout_ms: 30_000,
                expected_provider_major: crate::PINNED_SURREALDB_MAJOR,
                expected_schema_generation: SchemaGeneration::v2(),
            };
            config.provider_arguments = config.expected_provider_arguments();
            let mut harness = Self {
                root,
                config,
                adapter: None,
            };
            println!(
                "EVIDENCE-SCOPE provider={} sha256={} root={}",
                exe.display(),
                harness.config.provider_artifact_digest,
                harness.root.display()
            );
            // Provision credentials in this fresh root, as installation does.
            // Secrets go only through the child environment, never argv/logs.
            let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
            let mut child = Command::new(&exe)
                .args(&harness.config.provider_arguments)
                .current_dir(&work)
                .env_clear()
                .env("SystemRoot", &system_root)
                .env("WINDIR", &system_root)
                .env("TEMP", &tmp)
                .env("TMP", &tmp)
                .env("SURREAL_USER", &harness.config.username)
                .env("SURREAL_PASS", harness.config.password.expose_secret())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(0x0800_0000)
                .kill_on_drop(true)
                .spawn()
                .expect("bootstrap provider");
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                assert!(
                    child.try_wait().expect("child status").is_none(),
                    "bootstrap exited"
                );
                if TcpStream::connect(&harness.config.provider_bind_address)
                    .await
                    .is_ok()
                {
                    break;
                }
                assert!(Instant::now() < deadline, "bootstrap bind timeout");
                sleep(Duration::from_millis(50)).await;
            }
            child.kill().await.expect("stop bootstrap");
            child.wait().await.expect("reap bootstrap");
            harness.open().await;
            harness
        }

        async fn open(&mut self) {
            let platform = WindowsPlatform::new(self.root.clone()).expect("platform");
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut last_error = None;
            loop {
                let lease = platform
                    .retain_process_path_lease(
                        Path::new(&self.config.provider_executable_path),
                        Path::new(&self.config.store_work_root),
                        &self.config.provider_artifact_digest,
                    )
                    .expect("process lease");
                self.adapter =
                    Some(SurrealStoreAdapter::new(self.config.clone(), lease).expect("adapter"));
                match tokio::time::timeout_at(deadline, self.adapter().connect()).await {
                    Ok(Ok(())) => return,
                    Ok(Err(error)) => last_error = Some(error),
                    Err(_) => {
                        self.adapter = None;
                        panic!(
                            "authenticated provider readiness timed out; last error: {last_error:?}"
                        );
                    }
                }
                // The adapter caches its first connection result. Drop the
                // failed attempt before retrying startup in this isolated root;
                // no migration or canonical operation has been submitted yet.
                self.adapter = None;
                assert!(
                    Instant::now() < deadline,
                    "authenticated provider readiness timed out; last error: {last_error:?}"
                );
                sleep(
                    Duration::from_millis(100)
                        .min(deadline.saturating_duration_since(Instant::now())),
                )
                .await;
            }
        }

        fn adapter(&self) -> &SurrealStoreAdapter {
            self.adapter.as_ref().expect("live adapter")
        }

        async fn close(&mut self) {
            self.adapter = None;
            let deadline = Instant::now() + Duration::from_secs(10);
            while TcpStream::connect(&self.config.provider_bind_address)
                .await
                .is_ok()
            {
                assert!(
                    Instant::now() < deadline,
                    "provider did not release endpoint"
                );
                sleep(Duration::from_millis(50)).await;
            }
        }

        async fn cleanup(&mut self) {
            self.close().await;
            let deadline = Instant::now() + Duration::from_secs(10);
            while let Err(error) = std::fs::remove_dir_all(&self.root) {
                assert!(
                    Instant::now() < deadline,
                    "test root cleanup failed: {error}"
                );
                sleep(Duration::from_millis(50)).await;
            }
            assert!(!self.root.exists(), "test root removed");
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.adapter = None;
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    async fn assert_scope_reads(adapter: &SurrealStoreAdapter, current_fence: &StateFence) {
        for (scope, expected_index) in [
            ("scope-other", Some(0)),
            ("scope-1", Some(1)),
            ("scope-missing", None),
        ] {
            let mut query = admitted_read_tests::evidence_query("shared-subject", "1");
            query.scope_id = Some(ScopeId::new(scope).expect("scope"));
            query.state_fence = current_fence.clone();
            let response = adapter
                .execute_named(query)
                .await
                .expect("scoped named read");
            let records = response.payload["records"].as_array().expect("records");
            assert_eq!(records.len(), usize::from(expected_index.is_some()));
            if let Some(index) = expected_index {
                assert_eq!(records[0]["capture_index"], json!(index));
                assert_eq!(records[0]["parameters"]["subject"], json!("shared-subject"));
            }
            assert_eq!(
                response.payload["provenance"]["matched_total"],
                json!(records.len())
            );
            assert_eq!(response.payload["provenance"]["truncated"], json!(false));
            assert_eq!(response.state_fence, *current_fence);
            assert_eq!(
                response.payload["provenance"]["state_fence"],
                json!(current_fence)
            );
        }
        let mut query = admitted_read_tests::evidence_query("shared", "1");
        query.state_fence = current_fence.clone();
        let response = adapter
            .execute_named(query)
            .await
            .expect("nonmatching subject");
        assert_eq!(response.payload["provenance"]["matched_total"], json!(0));
        let mut wrong_fence = admitted_read_tests::evidence_query("shared-subject", "1");
        wrong_fence.state_fence = current_fence.clone();
        wrong_fence.state_fence.resource_generation =
            eliot_contracts::ResourceGeneration::new(current_fence.resource_generation.value() + 1)
                .expect("generation");
        assert_eq!(
            adapter.execute_named(wrong_fence).await,
            Err(StoreError::FenceMismatch)
        );
    }

    /// Installs only the isolated fixture's current fence using the existing
    /// closed CAS statement. This is not a Host/Kernel cutover proof; real
    /// captures, their bytes and immutable receipt envelopes remain untouched.
    async fn install_fixture_fence(adapter: &SurrealStoreAdapter, current: &StateFence) {
        let db = crate::apply::client(adapter).await.expect("client");
        let mut fence = read_fence(db, &adapter.config)
            .await
            .expect("read fence")
            .expect("fence");
        let mut bindings = Map::new();
        bindings.insert("fence_table".into(), json!("canonical_fence"));
        bindings.insert("fence_key".into(), json!("current"));
        bindings.insert("expected_state_fence".into(), json!(fence.state_fence));
        bindings.insert(
            "expected_commit_sequence".into(),
            json!(fence.next_commit_sequence),
        );
        bindings.insert(
            "expected_outbox_sequence".into(),
            json!(fence.next_outbox_sequence),
        );
        fence.state_fence = current.clone();
        bindings.insert("fence".into(), to_value(&fence).expect("fence value"));
        let mut response = client::query(
            db,
            &adapter.config,
            "test.install_read_fence",
            schema::TX_UPSERT_FENCE,
            bindings,
        )
        .await
        .expect("fixture fence CAS");
        assert!(
            response.take_errors().is_empty(),
            "fixture fence CAS succeeded"
        );
        let observed = read_fence(db, &adapter.config)
            .await
            .expect("read fence")
            .expect("fence");
        assert_eq!(observed.state_fence, *current);
        assert_eq!(observed.next_commit_sequence, fence.next_commit_sequence);
        assert_eq!(observed.next_outbox_sequence, fence.next_outbox_sequence);
    }

    #[tokio::test]
    async fn real_surreal_evidence_pack_isolates_scopes_and_survives_reopen() {
        let mut harness = Harness::start().await;
        let result = std::panic::AssertUnwindSafe(async {
            let ctx = admitted_read_tests::capture_context();
            harness
                .adapter()
                .apply_migration(
                    &SurrealStoreAdapter::v2_baseline_migration(),
                    &ctx.clock,
                    &ctx.state_fence,
                )
                .await
                .expect("migration");
            let mut receipts = Vec::new();
            for (index, scope) in ["scope-other", "scope-1"].into_iter().enumerate() {
                let mut capture = admitted_read_tests::capture_transition(
                    &format!("scope-capture-{index}"),
                    "shared-subject",
                );
                capture.scope_id = ScopeId::new(scope).expect("scope");
                capture.ordering_scopes = vec![OrderingScopeId::new(scope).expect("ordering")];
                capture.operation_manifest_digest = operation_manifest_set_digest(
                    &generated_operation_manifests().expect("catalogue"),
                )
                .expect("manifest digest");
                capture.identity.canonical_request_hash = canonical_request_hash(
                    &CanonicalRequestView::from_apply(&ctx, &capture, &[], &[]),
                )
                .expect("request hash");
                let receipt = harness
                    .adapter()
                    .apply_prepared(&ctx, capture.clone(), vec![], vec![])
                    .await
                    .expect("capture");
                assert_eq!(receipt.status, WriteReceiptStatus::Committed);
                let replay = harness
                    .adapter()
                    .apply_prepared(&ctx, capture, vec![], vec![])
                    .await
                    .expect("exact replay");
                assert_eq!(replay, receipt);
                receipts.push(receipt);
            }
            assert_scope_reads(harness.adapter(), &ctx.state_fence).await;
            let mut current = ctx.state_fence.clone();
            current.authority_epoch = eliot_contracts::EpochId::new(
                current.authority_epoch.lineage_id.clone(),
                std::num::NonZeroU64::new(2).expect("nonzero epoch"),
            )
            .expect("epoch");
            current.resource_generation =
                eliot_contracts::ResourceGeneration::new(2).expect("generation");
            current.task_revision =
                Some(eliot_contracts::TaskRevision::new(2).expect("task revision"));
            current.policy_revision =
                Some(eliot_contracts::PolicyRevision::new(2).expect("policy revision"));
            current.integration_revision =
                Some(eliot_contracts::IntegrationRevision::new(2).expect("integration revision"));
            install_fixture_fence(harness.adapter(), &current).await;
            assert_scope_reads(harness.adapter(), &current).await;
            assert_eq!(
                harness
                    .adapter()
                    .execute_named(admitted_read_tests::evidence_query("shared-subject", "1"))
                    .await,
                Err(StoreError::FenceMismatch),
                "the old request fence remains refused",
            );
            harness.close().await;
            harness.open().await;
            assert_scope_reads(harness.adapter(), &current).await;
            for receipt in receipts {
                let db = crate::apply::client(harness.adapter())
                    .await
                    .expect("client");
                let stored = read_receipt_by_operation(db, &harness.config, &receipt.operation_id)
                    .await
                    .expect("historical receipt");
                assert_eq!(
                    stored,
                    Some(receipt),
                    "historical receipt is immutable after reopen"
                );
            }
        })
        .catch_unwind()
        .await;
        harness.cleanup().await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }
}
