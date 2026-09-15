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
    ScopeRevisionView, StateFence, StoreError, generated_operation_manifests,
    named_mutation_operation_name,
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
/// Only the five activated reads (plus the genesis bootstrap entry, which
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
            evidence_pack_payload(query, state_fence, &rows).map_err(AdapterError::Store)
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

/// Reads all persisted capture-evidence rows through the closed SELECT.
///
/// One row per receipt; pre-change receipts carry no evidence array and
/// contribute nothing (they had no recoverable bytes persisted). The Rust
/// boundary assigns capture identity and filters by exact subject — never a
/// substring match in the query string.
async fn read_evidence_records(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<Vec<EvidenceReceiptRow>, AdapterError> {
    let mut response = client::query(
        db,
        config,
        "read.evidence_records",
        schema::READ_EVIDENCE_RECORDS,
        Map::new(),
    )
    .await?;
    take_vec::<EvidenceReceiptRow>(&mut response, 0)
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
/// `subject` match only (never substring, never a default), explicit
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
fn evidence_pack_payload(
    query: &NamedReadRequest,
    state_fence: &StateFence,
    rows: &[EvidenceReceiptRow],
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
        for record in records {
            validate_evidence_record(row, record)?;
            let capture_index = operation_base.saturating_add(record.operation_index as u64);
            indexed.push((capture_index, record));
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
        // Known-but-unadvertised operation stays unsupported.
        let unadvertised = read_request(NamedReadOperation::GetTaskState, None, BTreeMap::new());
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

    fn capture_transition(
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

    fn evidence_query(subject: &str, max_records: &str) -> NamedReadRequest {
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
        let payload = evidence_pack_payload(&query, &fence, &rows).expect("pack builds");
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
        let payload = evidence_pack_payload(&query, &fence, &rows).expect("empty pack builds");
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
                evidence_pack_payload(&query, &fence, &rows),
                Err(StoreError::PayloadTooLarge),
                "bound {bound} exceeds the declared maximum"
            );
        }
        let query = evidence_query("evidence-alpha", &format!("{EVIDENCE_PACK_MAX_RECORDS}"));
        assert!(
            evidence_pack_payload(&query, &fence, &rows).is_ok(),
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
            let payload = evidence_pack_payload(&query, &fence, &rows).expect("non-match builds");
            assert!(
                payload
                    .get("records")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty),
                "selector {selector} must not substring-match"
            );
        }
        let query = evidence_query("observation-1", "10");
        let payload = evidence_pack_payload(&query, &fence, &rows).expect("exact builds");
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
        let payload = evidence_pack_payload(&query, &fence, &rows).expect("bounded pack builds");
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
        let payload = evidence_pack_payload(&query, &fence, &rows).expect("full pack builds");
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
            evidence_pack_payload(&query, &fence, &rows),
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
            evidence_pack_payload(&query, &fence, &rows),
            Err(StoreError::InvalidField { .. })
        ));
        // Zero and non-decimal bounds fail the bound shape.
        for bound in ["0", "many"] {
            let query = evidence_query("evidence-alpha", bound);
            assert!(
                matches!(
                    evidence_pack_payload(&query, &fence, &rows),
                    Err(StoreError::InvalidField { .. })
                ),
                "bound {bound} must fail closed"
            );
        }
    }
}
