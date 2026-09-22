//! Canonical backup capture backend (issue #951).
//!
//! Implements the capture half of [`eliot_store_api::CanonicalBackupPorts`]
//! in the sole credential/client/canonical-table owner. No second database
//! client, no raw provider export, no filesystem copy: every statement is a
//! fixed adapter-owned parameterized query through the accepted session
//! facade, and every digest is computed here over actual bytes through the
//! existing digest owner. Caller SQL/table/URL/credential input is
//! unrepresentable.
//!
//! Coherence model: `Begin` freezes the complete bounded member set inside
//! one provider transaction (fence sequences, revision/ordering heads, then
//! every canonical table in fixed deterministic order). The frozen rows,
//! per-residency dispositions, and frozen fence sequences persist in the
//! backup coordination tables in that same transaction. `Page` serves only
//! frozen rows and refuses with `FenceMismatch` (marking the capture
//! expired) when the live fence moved: pages never mix a newer read into an
//! older snapshot, and sequential independent `SELECT`s are never presented
//! as snapshot authority. `End` recomputes the snapshot digest and every
//! denominator over the frozen rows and commits the completion receipt
//! atomically. A bounded capture that exceeds its admitted product fails
//! closed with `PayloadTooLarge`; no partial success is manufactured.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::fmt::Write as _;

use crate::client::{self, RpcTransport};
use crate::config::SurrealAdapterConfig;
use crate::error::AdapterError;
use crate::{plan, schema};
use eliot_store_api::{
    OperationId, ResidencyDisposition, StateFence, StoreBackupBeginRequest,
    StoreBackupCompletionReceipt, StoreBackupConsistency, StoreBackupEndRequest, StoreBackupMember,
    StoreBackupPage, StoreBackupPageRequest, StoreError, sha256_hex,
};

use super::receipt_reconciliation::read_fence;
use super::schema_contract::FenceRecord;
use super::take_vec;

/// Operation kind recorded on a backup coordination row.
pub(super) const KIND_CAPTURE: &str = "capture";
/// Lifecycle status of an open capture.
pub(super) const STATUS_CAPTURING: &str = "capturing";
/// Lifecycle status of a closed capture.
pub(super) const STATUS_COMPLETED: &str = "completed";
/// Lifecycle status of a capture refused after fence drift.
pub(super) const STATUS_EXPIRED: &str = "expired";

/// One canonical table covered by the frozen capture denominator, in fixed
/// enumeration order with its deterministic ordering and stable residency
/// domain. Equal content under different tables stays distinct: the member
/// digest always binds the table name.
pub(super) struct CaptureTable {
    pub(super) table: &'static str,
    pub(super) order_by: &'static str,
    pub(super) domain: &'static str,
    pub(super) id_kind: TableIdKind,
}

/// How the restore replay re-derives a table's deterministic record key
/// from a frozen member row. Every variant reproduces the exact convention
/// the canonical write path used at creation.
#[derive(Clone, Copy)]
pub(super) enum TableIdKind {
    /// Single logical key field carried on the row.
    Field(&'static str),
    /// Recovery tables: `sha256` over the canonical `(namespace, key)`
    /// JSON, reproducing the genesis convention.
    NamespaceKey,
    /// Automation revisions: the `revision_key` join convention.
    AutomationRevision,
    /// Automation failures: the canonical failure-key owner.
    AutomationFailure,
}

/// Fixed capture denominator: every canonical record class in deterministic
/// order. Multi-term `ORDER BY` appears only for composite-key tables on the
/// pinned provider's core `SurrealQL`; every other table orders by its
/// unique logical key.
pub(super) const CAPTURE_TABLES: &[CaptureTable] = &[
    CaptureTable {
        table: schema::table::REVISION_HEAD,
        order_by: "revision_key",
        domain: "canonical.revision_head",
        id_kind: TableIdKind::Field("revision_key"),
    },
    CaptureTable {
        table: schema::table::ORDERING_HEAD,
        order_by: "ordering_scope",
        domain: "canonical.ordering_head",
        id_kind: TableIdKind::Field("ordering_scope"),
    },
    CaptureTable {
        table: schema::table::CANONICAL_EVENT,
        order_by: "event_id",
        domain: "canonical.event",
        id_kind: TableIdKind::Field("event_id"),
    },
    CaptureTable {
        table: schema::table::PROJECTION_RECORD,
        order_by: "publication_id",
        domain: "canonical.projection",
        id_kind: TableIdKind::Field("publication_id"),
    },
    CaptureTable {
        table: schema::table::RELATION_RECORD,
        order_by: "relation_id",
        domain: "canonical.relation",
        id_kind: TableIdKind::Field("relation_id"),
    },
    CaptureTable {
        table: schema::table::OUTBOX_EVENT,
        order_by: "outbox_id",
        domain: "canonical.outbox",
        id_kind: TableIdKind::Field("outbox_id"),
    },
    CaptureTable {
        table: schema::table::WRITE_RECEIPT,
        order_by: "operation_id",
        domain: "canonical.receipt",
        id_kind: TableIdKind::Field("operation_id"),
    },
    CaptureTable {
        table: schema::table::RECOVERY_OWNER,
        order_by: "namespace, key",
        domain: "canonical.recovery_owner",
        id_kind: TableIdKind::NamespaceKey,
    },
    CaptureTable {
        table: schema::table::RECOVERY_JOB,
        order_by: "namespace, key",
        domain: "canonical.recovery_job",
        id_kind: TableIdKind::NamespaceKey,
    },
    CaptureTable {
        table: schema::table::NOTIFICATION_RECORD,
        order_by: "dedup_key",
        domain: "canonical.notification",
        id_kind: TableIdKind::Field("dedup_key"),
    },
    CaptureTable {
        table: schema::table::REACTIVE_SESSION,
        order_by: "session_id",
        domain: "canonical.reactive_session",
        id_kind: TableIdKind::Field("session_id"),
    },
    CaptureTable {
        table: schema::table::RESOURCE_SNAPSHOT,
        order_by: "uri",
        domain: "canonical.resource_snapshot",
        id_kind: TableIdKind::Field("uri"),
    },
    CaptureTable {
        table: schema::table::AUTOMATION_REVISION,
        order_by: "automation_id, revision",
        domain: "canonical.automation_revision",
        id_kind: TableIdKind::AutomationRevision,
    },
    CaptureTable {
        table: schema::table::AUTOMATION_CURRENT,
        order_by: "automation_id",
        domain: "canonical.automation_current",
        id_kind: TableIdKind::Field("automation_id"),
    },
    CaptureTable {
        table: schema::table::AUTOMATION_INVOCATION,
        order_by: "occurrence_id",
        domain: "canonical.automation_invocation",
        id_kind: TableIdKind::Field("occurrence_id"),
    },
    CaptureTable {
        table: schema::table::AUTOMATION_FAILURE,
        order_by: "automation_id, revision, occurrence_id, fingerprint",
        domain: "canonical.automation_failure",
        id_kind: TableIdKind::AutomationFailure,
    },
    CaptureTable {
        table: schema::table::AUTOMATION_LAST_FAILURE,
        order_by: "automation_id",
        domain: "canonical.automation_pointer",
        id_kind: TableIdKind::Field("automation_id"),
    },
    CaptureTable {
        table: schema::table::ERASURE_INTENT,
        order_by: "operation_id",
        domain: "canonical.erasure_intent",
        id_kind: TableIdKind::Field("operation_id"),
    },
    CaptureTable {
        table: schema::table::ERASURE_OUTCOME,
        order_by: "operation_id",
        domain: "canonical.erasure_outcome",
        id_kind: TableIdKind::Field("operation_id"),
    },
];

/// Durable backup-operation coordination row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BackupOperationRow {
    pub(super) operation_id: String,
    pub(super) operation_kind: String,
    pub(super) idempotency_key: String,
    pub(super) canonical_request_hash: String,
    pub(super) state_fence: StateFence,
    pub(super) scope_json: String,
    pub(super) status: String,
    pub(super) consistency_point: String,
    pub(super) snapshot_digest: Option<String>,
    pub(super) member_count: i64,
    pub(super) total_bytes: i64,
    pub(super) receipt_json: Option<String>,
    pub(super) frozen_commit_sequence: i64,
    pub(super) frozen_outbox_sequence: i64,
    pub(super) frozen_heads_digest: String,
}

/// Frozen capture member row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BackupMemberRow {
    pub(super) operation_id: String,
    pub(super) member_digest: String,
    pub(super) content_digest: String,
    pub(super) residency_digest: String,
    pub(super) member_bytes: i64,
    pub(super) page_cursor: i64,
    pub(super) member_table: String,
    pub(super) member_id: String,
    pub(super) member_json: String,
}

/// Accumulated per-residency disposition row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BackupResidencyRow {
    pub(super) operation_id: String,
    pub(super) residency_digest: String,
    pub(super) domain: String,
    pub(super) member_count: i64,
    pub(super) member_bytes: i64,
    pub(super) content_digest: String,
}

/// Derives the stable residency digest for one capture domain. The digest
/// binds the domain label only; member content never collapses domains.
pub(super) fn residency_digest_for(domain: &str) -> String {
    sha256_hex(format!("backup-residency:v1:{domain}").as_bytes())
}

/// Recomputes the exact residency denominator digest over the fixed capture
/// table set. The admitted scope must name exactly this digest: scope
/// exclusion without exact scope evidence is refused.
pub(super) fn expected_denominator_digest() -> String {
    let mut material = String::from("backup-denominator:v1");
    for table in CAPTURE_TABLES {
        material.push('\n');
        material.push_str(table.table);
        material.push('\n');
        material.push_str(table.domain);
        material.push('\n');
        material.push_str(&residency_digest_for(table.domain));
    }
    sha256_hex(material.as_bytes())
}

/// Derives the owner-issued consistency point for one capture. The point
/// binds operation, fence, and denominator digests; it is never a bare
/// timestamp, so replays of the same admitted operation re-derive the same
/// point while any rebinding diverges.
pub(super) fn derive_consistency_point(
    operation_id: &OperationId,
    fence: &StateFence,
    denominator_digest: &str,
) -> Result<String, AdapterError> {
    let fence_bytes = eliot_store_api::canonical_json_bytes(fence)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let mut material = Vec::with_capacity(fence_bytes.len() + 128);
    material.extend_from_slice(b"backup-consistency:v1\n");
    material.extend_from_slice(operation_id.to_string().as_bytes());
    material.push(b'\n');
    material.extend_from_slice(&fence_bytes);
    material.push(b'\n');
    material.extend_from_slice(denominator_digest.as_bytes());
    Ok(sha256_hex(&material))
}

/// Loads one backup-operation row by exact operation identity. Absent backup
/// tables observe absent-table, which maps to `MigrationRequired`: an
/// unprovisioned backend refuses without effects instead of inventing
/// coordination state.
pub(super) async fn load_operation_row(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    operation: &'static str,
    operation_id: &OperationId,
) -> Result<Option<BackupOperationRow>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "backup_operation_id".to_owned(),
        json!(operation_id.to_string()),
    );
    let mut response = client::query(
        db,
        config,
        operation,
        &format!(
            "SELECT * FROM {} WHERE operation_id = $backup_operation_id LIMIT 1;",
            schema::table::BACKUP_OPERATION
        ),
        bindings,
    )
    .await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        if errors.iter().all(|error| client::is_absent_table(error)) {
            return Err(AdapterError::MigrationRequired);
        }
        return Err(AdapterError::PartialOutcome);
    }
    let mut rows = response.take::<Vec<BackupOperationRow>>(0)?;
    if rows.len() > 1 {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(rows.pop())
}

/// Freezes one bounded coherent canonical snapshot: fence sequences, heads,
/// and every denominator table inside a single provider transaction, then
/// persists the operation row, all frozen member rows, and all per-residency
/// dispositions atomically. Same-operation replay returns the identical
/// consistency point; a changed input under the same identity conflicts.
pub(crate) async fn backup_begin(
    adapter: &crate::SurrealStoreAdapter,
    request: StoreBackupBeginRequest,
) -> Result<StoreBackupConsistency, AdapterError> {
    request.validate().map_err(AdapterError::Store)?;
    let db = super::client(adapter).await?;
    super::ensure_ready(adapter, db).await?;
    if request.scope.schema_generation != adapter.config.expected_schema_generation.as_str() {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    }
    if request.scope.installation_id != adapter.config.installation_id {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.installation_id",
            reason: "capture source is not this installation",
        }));
    }
    if request.scope.residency_denominator_digest != expected_denominator_digest() {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.scope",
            reason: "admitted denominator does not match the canonical denominator",
        }));
    }
    let operation_id = request.identity.operation_id.clone();
    if let Some(existing) =
        load_operation_row(db, &adapter.config, "backup.begin", &operation_id).await?
    {
        return replay_or_conflict_begin(&request, &existing);
    }
    let fence = current_fence(db, &adapter.config, &request.scope.state_fence).await?;
    let consistency_point = derive_consistency_point(
        &operation_id,
        &request.scope.state_fence,
        &expected_denominator_digest(),
    )?;
    let admitted_product =
        u64::from(request.max_pages).saturating_mul(u64::from(request.max_members_per_page));
    let frozen = freeze_denominator(db, &adapter.config, admitted_product).await?;
    if frozen.fence.state_fence != request.scope.state_fence
        || frozen.fence.next_commit_sequence != fence.next_commit_sequence
        || frozen.fence.next_outbox_sequence != fence.next_outbox_sequence
    {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    let (members, residencies) = build_frozen_members(&operation_id.to_string(), frozen.rows)?;
    let total_bytes: u64 = members
        .iter()
        .map(|member| u64::try_from(member.member_bytes.max(0)).unwrap_or(0))
        .sum();
    if members.len() as u64 > admitted_product {
        return Err(AdapterError::Store(StoreError::PayloadTooLarge));
    }
    let frozen_heads_digest = heads_digest(&frozen.revision_heads, &frozen.ordering_heads)?;
    persist_frozen_capture(
        db,
        &adapter.config,
        &request,
        &fence,
        &consistency_point,
        &frozen_heads_digest,
        &members,
        &residencies,
        total_bytes,
    )
    .await?;
    Ok(StoreBackupConsistency {
        operation_id,
        state_fence: request.scope.state_fence.clone(),
        consistency_point,
    })
}

/// Reconciles a repeated `Begin` against the durable row: identical admitted
/// identity replays the original consistency point; changed input conflicts.
fn replay_or_conflict_begin(
    request: &StoreBackupBeginRequest,
    existing: &BackupOperationRow,
) -> Result<StoreBackupConsistency, AdapterError> {
    if existing.operation_kind != KIND_CAPTURE
        || existing.idempotency_key != request.identity.idempotency_key
        || existing.canonical_request_hash != request.identity.canonical_request_hash
    {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    Ok(StoreBackupConsistency {
        operation_id: request.identity.operation_id.clone(),
        state_fence: existing.state_fence.clone(),
        consistency_point: existing.consistency_point.clone(),
    })
}

/// Reads the live canonical fence and pins it to the admitted fence. A stale
/// fence, a moved sequence, or a missing fence row refuses before any
/// protected data is read.
async fn current_fence(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    expected: &StateFence,
) -> Result<FenceRecord, AdapterError> {
    let fence = read_fence(db, config)
        .await?
        .ok_or(AdapterError::MigrationRequired)?;
    super::schema_contract::validate_fence_record(&fence)?;
    if fence.state_fence != *expected {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    Ok(fence)
}

/// Frozen denominator scan: heads plus every denominator table in one
/// provider transaction, bounded per table by the admitted product.
struct FrozenDenominator {
    fence: FenceRecord,
    revision_heads: Vec<eliot_store_api::RevisionHead>,
    ordering_heads: Vec<eliot_store_api::OrderingHead>,
    rows: Vec<(usize, Vec<Value>)>,
}

async fn freeze_denominator(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    admitted_product: u64,
) -> Result<FrozenDenominator, AdapterError> {
    let per_table_limit = admitted_product.saturating_add(1).min(i64::MAX as u64);
    let mut sql = String::from(schema::TX_BEGIN);
    sql.push_str(schema::READ_FENCE);
    sql.push_str(schema::READ_ALL_REVISION_HEADS);
    sql.push_str(schema::READ_ALL_ORDERING_HEADS);
    for table in CAPTURE_TABLES {
        let _ = write!(
            sql,
            "SELECT * FROM {} ORDER BY {} LIMIT {per_table_limit};",
            table.table, table.order_by
        );
    }
    sql.push_str(schema::TX_COMMIT);
    let mut response = client::query(db, config, "backup.begin", &sql, Map::new()).await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let fence = response
        .take::<Option<FenceRecord>>(1)?
        .ok_or(AdapterError::PartialOutcome)?;
    super::schema_contract::validate_fence_record(&fence)?;
    let revision_heads = response.take::<Vec<eliot_store_api::RevisionHead>>(2)?;
    plan::validate_revision_heads(&revision_heads)?;
    let ordering_heads = response.take::<Vec<eliot_store_api::OrderingHead>>(3)?;
    plan::validate_ordering_heads(&ordering_heads)?;
    let mut rows = Vec::with_capacity(CAPTURE_TABLES.len());
    for (index, table) in CAPTURE_TABLES.iter().enumerate() {
        rows.push((index, take_capture_table(&mut response, 4 + index, table)?));
    }
    Ok(FrozenDenominator {
        fence,
        revision_heads,
        ordering_heads,
        rows,
    })
}

/// Takes one frozen table scan, tolerating exactly one case: a missing
/// feature table on an otherwise healthy database reads as empty. Any other
/// error, or a missing core table, keeps the reconciling disposition.
fn take_capture_table(
    response: &mut client::RpcResults,
    index: usize,
    table: &CaptureTable,
) -> Result<Vec<Value>, AdapterError> {
    let value = response.take::<Value>(index)?;
    match value {
        Value::Array(rows) => {
            for row in &rows {
                if !row.is_object() {
                    return Err(AdapterError::Serialization(
                        "canonical capture row is not an object".to_owned(),
                    ));
                }
            }
            Ok(rows)
        }
        Value::String(prose) => {
            let folded = prose.to_ascii_lowercase();
            if folded.contains("does not exist")
                && folded.contains("table")
                && folded.contains(&table.table.to_ascii_lowercase())
            {
                Ok(Vec::new())
            } else {
                Err(AdapterError::PartialOutcome)
            }
        }
        _ => Err(AdapterError::PartialOutcome),
    }
}

/// Builds frozen member rows plus per-residency dispositions in fixed
/// deterministic order. The member digest binds table, logical identity,
/// and content digest, so equal bytes under different obligations stay
/// distinct and no digest is ever accepted from a caller.
fn build_frozen_members(
    operation_id: &str,
    rows: Vec<(usize, Vec<Value>)>,
) -> Result<(Vec<BackupMemberRow>, Vec<BackupResidencyRow>), AdapterError> {
    let mut members = Vec::new();
    let mut residencies = Vec::new();
    let mut cursor: i64 = 0;
    for (table_index, table_rows) in rows {
        let table = &CAPTURE_TABLES[table_index];
        let residency_digest = residency_digest_for(table.domain);
        let mut domain_count: i64 = 0;
        let mut domain_bytes: u64 = 0;
        let mut domain_digests = Vec::new();
        for mut row in table_rows {
            let object = row.as_object_mut().ok_or({
                AdapterError::Serialization("canonical capture row is not an object".to_owned())
            })?;
            object.remove("id");
            let row_bytes = eliot_store_api::canonical_json_bytes(&row)
                .map_err(|error| AdapterError::Serialization(error.to_string()))?;
            let content_digest = sha256_hex(&row_bytes);
            let member_id = logical_member_id(table, &row)?;
            let member_digest = sha256_hex(
                format!(
                    "backup-member:v1\n{}\n{member_id}\n{content_digest}",
                    table.table
                )
                .as_bytes(),
            );
            let member_bytes = u64::try_from(row_bytes.len()).unwrap_or(u64::MAX);
            domain_digests.push(member_digest.clone());
            members.push(BackupMemberRow {
                operation_id: operation_id.to_owned(),
                member_digest,
                content_digest,
                residency_digest: residency_digest.clone(),
                member_bytes: i64::try_from(
                    member_bytes.min(u64::try_from(i64::MAX).unwrap_or(u64::MAX)),
                )
                .unwrap_or(i64::MAX),
                page_cursor: cursor,
                member_table: table.table.to_owned(),
                member_id,
                member_json: String::from_utf8(row_bytes).map_err(|_| {
                    AdapterError::Serialization("canonical row is not UTF-8".to_owned())
                })?,
            });
            domain_count += 1;
            domain_bytes = domain_bytes.saturating_add(member_bytes);
            cursor += 1;
        }
        domain_digests.sort();
        residencies.push(BackupResidencyRow {
            operation_id: operation_id.to_owned(),
            residency_digest,
            domain: table.domain.to_owned(),
            member_count: domain_count,
            member_bytes: i64::try_from(
                domain_bytes.min(u64::try_from(i64::MAX).unwrap_or(u64::MAX)),
            )
            .unwrap_or(i64::MAX),
            content_digest: sha256_hex(domain_digests.join("\n").as_bytes()),
        });
    }
    Ok((members, residencies))
}

/// Derives the deterministic logical identity of one frozen row, reproducing
/// the exact record-key convention the canonical write path used.
fn logical_member_id(table: &CaptureTable, row: &Value) -> Result<String, AdapterError> {
    match table.id_kind {
        TableIdKind::Field(field) => row
            .get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or({
                AdapterError::Serialization(format!(
                    "canonical row in {} is missing its logical key",
                    table.table
                ))
            }),
        TableIdKind::NamespaceKey => {
            let namespace = row.get("namespace").and_then(Value::as_str).ok_or({
                AdapterError::Serialization("recovery row is missing its namespace".to_owned())
            })?;
            let key = row.get("key").and_then(Value::as_str).ok_or({
                AdapterError::Serialization("recovery row is missing its key".to_owned())
            })?;
            let bytes = eliot_store_api::canonical_json_bytes(&json!({
                "namespace": namespace,
                "key": key,
            }))
            .map_err(|error| AdapterError::Serialization(error.to_string()))?;
            Ok(sha256_hex(&bytes))
        }
        TableIdKind::AutomationRevision => {
            let automation_id = row.get("automation_id").and_then(Value::as_str).ok_or({
                AdapterError::Serialization("automation row is missing its id".to_owned())
            })?;
            let revision = row.get("revision").and_then(Value::as_str).ok_or({
                AdapterError::Serialization("automation row is missing its revision".to_owned())
            })?;
            Ok(format!("{automation_id}\u{1f}{revision}"))
        }
        TableIdKind::AutomationFailure => {
            let automation_id = row.get("automation_id").and_then(Value::as_str).ok_or({
                AdapterError::Serialization("automation row is missing its id".to_owned())
            })?;
            let revision = row.get("revision").and_then(Value::as_str).ok_or({
                AdapterError::Serialization("automation row is missing its revision".to_owned())
            })?;
            let fingerprint = row.get("fingerprint").and_then(Value::as_str).ok_or({
                AdapterError::Serialization("automation row is missing its fingerprint".to_owned())
            })?;
            Ok(eliot_store_api::automation_failure_key(
                automation_id,
                revision,
                fingerprint,
            ))
        }
    }
}

/// Persists the operation row, all frozen member rows, and all
/// per-residency dispositions in one provider transaction. The unique
/// operation index arbitrates concurrent same-identity begins: the loser
/// observes the duplicate marker and replays against the winner's row.
#[allow(clippy::too_many_arguments)]
async fn persist_frozen_capture(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    request: &StoreBackupBeginRequest,
    fence: &FenceRecord,
    consistency_point: &str,
    frozen_heads_digest: &str,
    members: &[BackupMemberRow],
    residencies: &[BackupResidencyRow],
    total_bytes: u64,
) -> Result<(), AdapterError> {
    let operation_id = request.identity.operation_id.to_string();
    let scope_json = serde_json::to_string(&request.scope)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let mut sql = String::from(schema::TX_BEGIN);
    let _ = write!(
        sql,
        "CREATE {} CONTENT $backup_operation_record;",
        schema::table::BACKUP_OPERATION
    );
    let mut bindings = Map::new();
    bindings.insert(
        "backup_operation_record".to_owned(),
        json!({
            "operation_id": operation_id,
            "operation_kind": KIND_CAPTURE,
            "idempotency_key": request.identity.idempotency_key,
            "canonical_request_hash": request.identity.canonical_request_hash,
            "state_fence": request.scope.state_fence,
            "scope_json": scope_json,
            "status": STATUS_CAPTURING,
            "consistency_point": consistency_point,
            "snapshot_digest": None::<String>,
            "member_count": i64::try_from(members.len()).unwrap_or(i64::MAX),
            "total_bytes": i64::try_from(total_bytes.min(u64::try_from(i64::MAX).unwrap_or(u64::MAX)))
                .unwrap_or(i64::MAX),
            "receipt_json": None::<String>,
            "frozen_commit_sequence": fence.next_commit_sequence,
            "frozen_outbox_sequence": fence.next_outbox_sequence,
            "frozen_heads_digest": frozen_heads_digest,
        }),
    );
    for (index, member) in members.iter().enumerate() {
        let _ = write!(
            sql,
            "CREATE {} CONTENT $backup_member_record{index};",
            schema::table::BACKUP_MEMBER
        );
        bindings.insert(
            format!("backup_member_record{index}"),
            serde_json::to_value(member)
                .map_err(|error| AdapterError::Serialization(error.to_string()))?,
        );
    }
    for (index, residency) in residencies.iter().enumerate() {
        let _ = write!(
            sql,
            "CREATE {} CONTENT $backup_residency_record{index};",
            schema::table::BACKUP_RESIDENCY
        );
        bindings.insert(
            format!("backup_residency_record{index}"),
            serde_json::to_value(residency)
                .map_err(|error| AdapterError::Serialization(error.to_string()))?,
        );
    }
    sql.push_str(schema::TX_COMMIT);
    let mut response = db.query_admin("backup.begin", &sql, bindings).await?;
    let errors = response.take_errors();
    if errors.is_empty() {
        return Ok(());
    }
    if errors.iter().all(|error| client::is_absent_table(error)) {
        return Err(AdapterError::MigrationRequired);
    }
    if is_duplicate_operation(&errors) {
        let Some(existing) =
            load_operation_row(db, config, "backup.begin", &request.identity.operation_id).await?
        else {
            return Err(AdapterError::UnknownOutcome {
                operation_id: operation_id.clone(),
            });
        };
        replay_or_conflict_begin(request, &existing)?;
        return Ok(());
    }
    Err(AdapterError::PartialOutcome)
}

/// Reports whether provider statement errors observe a duplicate operation
/// row: a concurrent winner committed first, so the loser re-reads and
/// classifies replay versus conflict instead of retrying blindly.
pub(super) fn is_duplicate_operation(errors: &[String]) -> bool {
    errors.iter().any(|error| {
        let folded = error.to_ascii_lowercase();
        folded.contains("backup_operation_id")
            || ((folded.contains("already exists")
                || folded.contains("duplicate")
                || folded.contains("unique"))
                && folded.contains("backup_operation"))
    })
}

/// Serves one page of frozen capture rows. The page binds the same
/// operation, fence, consistency point, and cumulative denominator as the
/// freeze; cursors advance monotonically and never reset bounds. Fence drift
/// marks the capture expired and refuses rather than mixing pages.
pub(crate) async fn backup_page(
    adapter: &crate::SurrealStoreAdapter,
    request: StoreBackupPageRequest,
) -> Result<StoreBackupPage, AdapterError> {
    request.validate().map_err(AdapterError::Store)?;
    let db = super::client(adapter).await?;
    super::ensure_ready(adapter, db).await?;
    let operation = load_operation_row(db, &adapter.config, "backup.page", &request.operation_id)
        .await?
        .ok_or(AdapterError::Store(StoreError::ReceiptNotFound))?;
    if operation.operation_kind != KIND_CAPTURE {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.operation",
            reason: "page continuation requires a capture operation",
        }));
    }
    if operation.consistency_point != request.consistency_point {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    if operation.status == STATUS_EXPIRED {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    check_frozen_fence(db, &adapter.config, &operation).await?;
    let members = read_member_window(
        db,
        &adapter.config,
        &request.operation_id.to_string(),
        request.cursor,
        request.max_members,
    )
    .await?;
    let total_members = u64::try_from(operation.member_count.max(0)).unwrap_or(0);
    if request.cursor > total_members {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.cursor",
            reason: "page cursor is beyond the frozen denominator",
        }));
    }
    let page_members: Vec<StoreBackupMember> = members
        .iter()
        .map(|row| StoreBackupMember {
            member_digest: row.member_digest.clone(),
            content_digest: row.content_digest.clone(),
            residency_digest: row.residency_digest.clone(),
            member_bytes: u64::try_from(row.member_bytes.max(0)).unwrap_or(0),
        })
        .collect();
    let served = page_members.len() as u64;
    let next_cursor = if request.cursor.saturating_add(served) >= total_members {
        None
    } else {
        Some(request.cursor + served)
    };
    let page = StoreBackupPage {
        operation_id: request.operation_id.clone(),
        state_fence: operation.state_fence.clone(),
        consistency_point: operation.consistency_point.clone(),
        cursor: request.cursor,
        next_cursor,
        members: page_members,
        cumulative_members: total_members,
        cumulative_bytes: u64::try_from(operation.total_bytes.max(0)).unwrap_or(0),
    };
    page.validate().map_err(AdapterError::Store)?;
    Ok(page)
}

/// Verifies the live fence still matches the frozen point. Drift marks the
/// capture expired (best effort: the refusal below is what matters, never a
/// mixed page) and refuses with the fence mismatch.
pub(super) async fn check_frozen_fence(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    operation: &BackupOperationRow,
) -> Result<(), AdapterError> {
    let live = read_fence(db, config)
        .await?
        .ok_or(AdapterError::MigrationRequired)?;
    super::schema_contract::validate_fence_record(&live)?;
    if live.state_fence != operation.state_fence {
        mark_expired(db, config, &operation.operation_id).await;
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    let frozen_commit = u64::try_from(operation.frozen_commit_sequence.max(0)).unwrap_or(0);
    let frozen_outbox = u64::try_from(operation.frozen_outbox_sequence.max(0)).unwrap_or(0);
    if live.next_commit_sequence != frozen_commit || live.next_outbox_sequence != frozen_outbox {
        mark_expired(db, config, &operation.operation_id).await;
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    Ok(())
}

/// Marks one capture expired. Best effort: a lost race here never masks the
/// fence-mismatch refusal the caller already observed.
pub(super) async fn mark_expired(
    db: &RpcTransport,
    _config: &SurrealAdapterConfig,
    operation_id: &str,
) {
    let mut bindings = Map::new();
    bindings.insert("backup_operation_id".to_owned(), json!(operation_id));
    let _ = db
        .query_admin(
            "backup.page",
            &format!(
                "UPDATE {} SET status = 'expired' WHERE operation_id = $backup_operation_id AND status = 'capturing';",
                schema::table::BACKUP_OPERATION
            ),
            bindings,
        )
        .await;
}

/// Reads one frozen member window by cursor range. Range comparison plus
/// deterministic cursor order keeps continuation on the frozen point
/// without cursor resets.
async fn read_member_window(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    operation_id: &str,
    cursor: u64,
    max_members: u32,
) -> Result<Vec<BackupMemberRow>, AdapterError> {
    let limit = i64::from(max_members);
    let cursor_value =
        i64::try_from(cursor.min(u64::try_from(i64::MAX).unwrap_or(u64::MAX))).unwrap_or(i64::MAX);
    let mut bindings = Map::new();
    bindings.insert("backup_operation_id".to_owned(), json!(operation_id));
    bindings.insert("backup_cursor".to_owned(), json!(cursor_value));
    let mut response = client::query(
        db,
        config,
        "backup.page",
        &format!(
            "SELECT * FROM {} WHERE operation_id = $backup_operation_id AND page_cursor >= $backup_cursor ORDER BY page_cursor LIMIT {limit};",
            schema::table::BACKUP_MEMBER
        ),
        bindings,
    )
    .await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        if errors.iter().all(|error| client::is_absent_table(error)) {
            return Err(AdapterError::MigrationRequired);
        }
        return Err(AdapterError::PartialOutcome);
    }
    take_vec::<BackupMemberRow>(&mut response, 0)
}

/// Closes one capture: recomputes the snapshot digest and every denominator
/// over the frozen rows, then commits the completion receipt atomically. A
/// repeated `End` replays the stored receipt; a drifted capture refuses as
/// expired rather than completing over mixed evidence.
pub(crate) async fn backup_end(
    adapter: &crate::SurrealStoreAdapter,
    request: StoreBackupEndRequest,
) -> Result<StoreBackupCompletionReceipt, AdapterError> {
    request.validate().map_err(AdapterError::Store)?;
    let db = super::client(adapter).await?;
    super::ensure_ready(adapter, db).await?;
    let operation = load_operation_row(db, &adapter.config, "backup.end", &request.operation_id)
        .await?
        .ok_or(AdapterError::Store(StoreError::ReceiptNotFound))?;
    if operation.operation_kind != KIND_CAPTURE {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.operation",
            reason: "completion requires a capture operation",
        }));
    }
    if operation.consistency_point != request.consistency_point {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    if let Some(receipt) = completed_receipt(&operation)? {
        return Ok(receipt);
    }
    if operation.status == STATUS_EXPIRED {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.status",
            reason: "capture expired before completion",
        }));
    }
    check_frozen_fence(db, &adapter.config, &operation).await?;
    let (members, residencies) = load_frozen_denominator(db, &adapter.config, &operation).await?;
    let (live_revisions, live_orderings) = read_live_heads(db, &adapter.config).await?;
    if heads_digest(&live_revisions, &live_orderings)? != operation.frozen_heads_digest {
        mark_expired(db, &adapter.config, &operation.operation_id).await;
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    let receipt = build_completion_receipt(&operation, &members, &residencies)?;
    let mut receipt = receipt;
    receipt.revision_heads = live_revisions;
    receipt.ordering_heads = live_orderings;
    receipt.validate().map_err(AdapterError::Store)?;
    commit_completion(db, &adapter.config, &operation, &receipt).await?;
    Ok(receipt)
}

/// Returns the stored completion receipt when the operation already
/// completed, else `None`.
pub(super) fn completed_receipt(
    operation: &BackupOperationRow,
) -> Result<Option<StoreBackupCompletionReceipt>, AdapterError> {
    if operation.status != STATUS_COMPLETED {
        return Ok(None);
    }
    let receipt_json = operation.receipt_json.as_ref().ok_or({
        AdapterError::Serialization("completed capture is missing its receipt".to_owned())
    })?;
    let receipt: StoreBackupCompletionReceipt = serde_json::from_str(receipt_json)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    receipt.validate().map_err(AdapterError::Store)?;
    Ok(Some(receipt))
}

/// Loads all frozen members and residency dispositions for one operation,
/// verifying the frozen population matches the operation row.
async fn load_frozen_denominator(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    operation: &BackupOperationRow,
) -> Result<(Vec<BackupMemberRow>, Vec<BackupResidencyRow>), AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "backup_operation_id".to_owned(),
        json!(operation.operation_id),
    );
    let limit = operation.member_count.max(0).saturating_add(1);
    let mut response = client::query(
        db,
        config,
        "backup.end",
        &format!(
            "SELECT * FROM {} WHERE operation_id = $backup_operation_id ORDER BY page_cursor LIMIT {limit}; SELECT * FROM {} WHERE operation_id = $backup_operation_id ORDER BY residency_digest LIMIT 65;",
            schema::table::BACKUP_MEMBER,
            schema::table::BACKUP_RESIDENCY
        ),
        bindings,
    )
    .await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        if errors.iter().all(|error| client::is_absent_table(error)) {
            return Err(AdapterError::MigrationRequired);
        }
        return Err(AdapterError::PartialOutcome);
    }
    let members = take_vec::<BackupMemberRow>(&mut response, 0)?;
    let residencies = take_vec::<BackupResidencyRow>(&mut response, 1)?;
    if i64::try_from(members.len()).unwrap_or(i64::MAX) != operation.member_count {
        return Err(AdapterError::PartialOutcome);
    }
    Ok((members, residencies))
}

/// Recomputes the completion receipt over the frozen rows: snapshot digest
/// over ordered member digests, per-residency sums verified against the
/// stored dispositions, frozen heads re-attached. Nothing is accepted from
/// any caller here; every digest is recomputed.
fn build_completion_receipt(
    operation: &BackupOperationRow,
    members: &[BackupMemberRow],
    residencies: &[BackupResidencyRow],
) -> Result<StoreBackupCompletionReceipt, AdapterError> {
    let mut ordered_digests: Vec<&str> = members
        .iter()
        .map(|member| member.member_digest.as_str())
        .collect();
    ordered_digests.sort_unstable();
    let snapshot_digest = sha256_hex(ordered_digests.join("\n").as_bytes());
    let mut computed = std::collections::BTreeMap::new();
    for member in members {
        let entry = computed
            .entry(member.residency_digest.clone())
            .or_insert((0_u64, 0_u64));
        entry.0 += 1;
        entry.1 = entry
            .1
            .saturating_add(u64::try_from(member.member_bytes.max(0)).unwrap_or(0));
    }
    let mut receipt_residencies = Vec::with_capacity(residencies.len());
    for stored in residencies {
        let (count, bytes) = computed.remove(&stored.residency_digest).ok_or({
            AdapterError::Store(StoreError::InvalidField {
                field: "backup.denominator",
                reason: "stored disposition has no frozen members",
            })
        })?;
        if count != u64::try_from(stored.member_count.max(0)).unwrap_or(u64::MAX)
            || bytes != u64::try_from(stored.member_bytes.max(0)).unwrap_or(u64::MAX)
        {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "backup.denominator",
                reason: "stored disposition diverges from frozen members",
            }));
        }
        receipt_residencies.push(ResidencyDisposition {
            residency_digest: stored.residency_digest.clone(),
            domain: stored.domain.clone(),
            member_count: count,
            member_bytes: bytes,
            content_digest: stored.content_digest.clone(),
        });
    }
    if !computed.is_empty() {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.denominator",
            reason: "frozen members lack a stored disposition",
        }));
    }
    let total_bytes: u64 = receipt_residencies
        .iter()
        .map(|entry| entry.member_bytes)
        .sum();
    let receipt = StoreBackupCompletionReceipt {
        operation_id: OperationId::new(&operation.operation_id)
            .map_err(StoreError::Foundation)
            .map_err(AdapterError::Store)?,
        state_fence: operation.state_fence.clone(),
        consistency_point: operation.consistency_point.clone(),
        snapshot_digest,
        scope_residency_digest: expected_denominator_digest(),
        member_count: members.len() as u64,
        total_bytes,
        residencies: receipt_residencies,
        revision_heads: Vec::new(),
        ordering_heads: Vec::new(),
        partial: false,
    };
    receipt.validate().map_err(AdapterError::Store)?;
    Ok(receipt)
}

/// Commits the completion receipt atomically: the status flip plus receipt
/// payload land in one conditional update. A concurrent winner's identical
/// receipt replays; anything else stays a conflict.
async fn commit_completion(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    operation: &BackupOperationRow,
    receipt: &StoreBackupCompletionReceipt,
) -> Result<(), AdapterError> {
    let receipt_json = serde_json::to_string(receipt)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let mut bindings = Map::new();
    bindings.insert(
        "backup_operation_id".to_owned(),
        json!(operation.operation_id),
    );
    bindings.insert("backup_receipt_json".to_owned(), json!(receipt_json));
    bindings.insert(
        "backup_snapshot_digest".to_owned(),
        json!(receipt.snapshot_digest),
    );
    let mut response = db
        .query_admin(
            "backup.end",
            &format!(
                "LET $backup_complete = (UPDATE {} SET status = 'completed', snapshot_digest = $backup_snapshot_digest, receipt_json = $backup_receipt_json WHERE operation_id = $backup_operation_id AND status = 'capturing' RETURN AFTER); IF array::len($backup_complete ?? []) != 1 {{ THROW 'backup_completion_conflict'; }};",
                schema::table::BACKUP_OPERATION
            ),
            bindings,
        )
        .await?;
    let errors = response.take_errors();
    if errors.is_empty() {
        return Ok(());
    }
    if errors.iter().all(|error| client::is_absent_table(error)) {
        return Err(AdapterError::MigrationRequired);
    }
    let current = load_operation_row(
        db,
        config,
        "backup.end",
        &OperationId::new(&operation.operation_id)
            .map_err(StoreError::Foundation)
            .map_err(AdapterError::Store)?,
    )
    .await?
    .ok_or(AdapterError::PartialOutcome)?;
    if current.status == STATUS_COMPLETED
        && current.snapshot_digest.as_deref() == Some(receipt.snapshot_digest.as_str())
    {
        return Ok(());
    }
    Err(AdapterError::ProviderConflict)
}

/// Computes the frozen heads digest over deterministically ordered heads.
/// The digest commits the exact head content observed at the freeze; any
/// later divergence refuses completion rather than receipting drifted
/// evidence.
pub(super) fn heads_digest(
    revision_heads: &[eliot_store_api::RevisionHead],
    ordering_heads: &[eliot_store_api::OrderingHead],
) -> Result<String, AdapterError> {
    let mut revisions: Vec<&eliot_store_api::RevisionHead> = revision_heads.iter().collect();
    revisions.sort_by_key(|head| head.key.to_string());
    let mut orderings: Vec<&eliot_store_api::OrderingHead> = ordering_heads.iter().collect();
    orderings.sort_by_key(|head| head.scope.to_string());
    let bytes = eliot_store_api::canonical_json_bytes(&json!({
        "revision_heads": revisions,
        "ordering_heads": orderings,
    }))
    .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Loads the stored scope binding of one operation row.
pub(super) fn operation_scope(
    operation: &BackupOperationRow,
) -> Result<eliot_store_api::StoreBackupScope, AdapterError> {
    serde_json::from_str(&operation.scope_json)
        .map_err(|error| AdapterError::Serialization(error.to_string()))
}

/// Re-reads the live revision and ordering heads for drift comparison at
/// completion time.
async fn read_live_heads(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<
    (
        Vec<eliot_store_api::RevisionHead>,
        Vec<eliot_store_api::OrderingHead>,
    ),
    AdapterError,
> {
    let mut response = client::query(
        db,
        config,
        "backup.end",
        &format!(
            "{} {} {} {}",
            schema::TX_BEGIN,
            schema::READ_ALL_REVISION_HEADS,
            schema::READ_ALL_ORDERING_HEADS,
            schema::TX_COMMIT,
        ),
        Map::new(),
    )
    .await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let revision_heads = response.take::<Vec<eliot_store_api::RevisionHead>>(1)?;
    plan::validate_revision_heads(&revision_heads)?;
    let ordering_heads = response.take::<Vec<eliot_store_api::OrderingHead>>(2)?;
    plan::validate_ordering_heads(&ordering_heads)?;
    Ok((revision_heads, ordering_heads))
}
