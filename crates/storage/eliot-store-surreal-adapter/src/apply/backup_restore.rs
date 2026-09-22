//! Canonical backup restore/validation backend (issue #952).
//!
//! Implements the restore half of [`eliot_store_api::CanonicalBackupPorts`]
//! in the sole credential/client/canonical-table owner. Restore replays only
//! validated canonical rows into the admitted isolated destination: the
//! destination must be this installation, the fence must be current, and the
//! source capture must be completed with a matching snapshot digest. Source,
//! active, and foreign destinations are refused before any write.
//!
//! Replay converges instead of overwriting: a present row with identical
//! content converges, a present row with divergent content conflicts, and
//! members named by a current purge suppression are never resurrected.
//! Classification happens before any write; the replay transaction carries
//! the fence guard plus conditional creates, and the restore operation row
//! with its receipt commits only after every replayed member verifies.
//! Unknown stays unknown: transport loss or a moved fence during replay
//! reports `UnknownOutcome` for exact readback instead of success.

use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::fmt::Write as _;

use crate::client::{self, RpcTransport};
use crate::config::SurrealAdapterConfig;
use crate::error::AdapterError;
use crate::schema;
use eliot_store_api::{
    ResidencyDisposition, StateFence, StoreBackupCompletionReceipt, StoreBackupPhase,
    StoreBackupReconcileRequest, StoreBackupReconciliation, StoreBackupStatusReport,
    StoreBackupStatusRequest, StoreBackupValidationOutcome, StoreBackupValidationReceipt,
    StoreBackupValidationRequest, StoreError, StoreIsolatedRestoreRequest, sha256_hex,
};

use super::backup_snapshot::{
    BackupMemberRow, BackupOperationRow, CAPTURE_TABLES, STATUS_COMPLETED, TableIdKind,
    completed_receipt, expected_denominator_digest, is_duplicate_operation, load_operation_row,
    operation_scope,
};
use super::receipt_reconciliation::read_fence;
use super::take_vec;

/// Operation kind recorded for an isolated restore.
pub(super) const KIND_RESTORE: &str = "restore";
/// Lifecycle status of an admitted restore while replaying.
pub(super) const STATUS_RESTORING: &str = "restoring";
/// Provider marker for restore-replay fence drift.
const FENCE_DRIFT_MARKER: &str = "backup_fence_drift";
/// Provider marker for the fence-bump compare-and-set.
const FENCE_BUMP_STATEMENT: &str = "LET $backup_bump = (UPDATE canonical_fence:current SET next_commit_sequence = $backup_next_commit_sequence, next_outbox_sequence = $backup_next_outbox_sequence WHERE next_commit_sequence = $backup_expected_commit_sequence AND next_outbox_sequence = $backup_expected_outbox_sequence RETURN AFTER); IF array::len($backup_bump ?? []) != 1 { THROW 'backup_fence_drift'; };";

/// Restores validated canonical records into the admitted isolated
/// destination only. Same-operation replay returns the original receipt;
/// changed input under the same identity conflicts; loss of response stays
/// unknown for exact readback.
pub(crate) async fn backup_isolated_restore(
    adapter: &crate::SurrealStoreAdapter,
    request: StoreIsolatedRestoreRequest,
) -> Result<StoreBackupCompletionReceipt, AdapterError> {
    request.validate().map_err(AdapterError::Store)?;
    let db = super::client(adapter).await?;
    super::ensure_ready(adapter, db).await?;
    if request.scope.schema_generation != adapter.config.expected_schema_generation.as_str() {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    }
    if request.scope.dest_installation_id != adapter.config.installation_id {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.destination",
            reason: "restore destination is not this installation",
        }));
    }
    if request.scope.residency_denominator_digest != expected_denominator_digest() {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.scope",
            reason: "admitted denominator does not match the canonical denominator",
        }));
    }
    let fence = current_live_fence(db, &adapter.config, &request.scope.state_fence).await?;
    let restore_id = request.identity.operation_id.clone();
    if let Some(existing) =
        load_operation_row(db, &adapter.config, "backup.restore", &restore_id).await?
    {
        return replay_or_conflict_restore(&request, &existing);
    }
    let source = load_operation_row(
        db,
        &adapter.config,
        "backup.restore",
        &request.source_operation_id,
    )
    .await?
    .ok_or(AdapterError::Store(StoreError::ReceiptNotFound))?;
    let source_receipt = completed_source_receipt(&source)?;
    if source_receipt.snapshot_digest != request.source_snapshot_digest {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    if source_receipt.scope_residency_digest != request.scope.residency_denominator_digest {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    let source_members =
        load_source_members(db, &adapter.config, &source, request.expected_member_count).await?;
    let suppressions = load_purge_subjects(db, &adapter.config).await?;
    let candidates: Vec<&BackupMemberRow> = source_members
        .iter()
        .filter(|member| !is_suppressed(&suppressions, member))
        .collect();
    let plan = classify_replay_slots(
        db,
        &adapter.config,
        &fence,
        &candidates,
        &restore_id.to_string(),
    )
    .await?;
    apply_replay(
        db,
        &adapter.config,
        &plan,
        &candidates,
        &request.scope.state_fence,
        &restore_id.to_string(),
    )
    .await?;
    commit_restore(
        db,
        &adapter.config,
        &request,
        &source_receipt,
        &plan,
        &candidates,
    )
    .await
}

/// Reads the live canonical fence and pins it to the admitted fence.
async fn current_live_fence(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    expected: &StateFence,
) -> Result<crate::apply::schema_contract::FenceRecord, AdapterError> {
    let fence = read_fence(db, config)
        .await?
        .ok_or(AdapterError::MigrationRequired)?;
    super::schema_contract::validate_fence_record(&fence)?;
    if fence.state_fence != *expected {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    Ok(fence)
}

/// Reconciles a repeated restore against the durable row.
fn replay_or_conflict_restore(
    request: &StoreIsolatedRestoreRequest,
    existing: &BackupOperationRow,
) -> Result<StoreBackupCompletionReceipt, AdapterError> {
    if existing.operation_kind != KIND_RESTORE
        || existing.idempotency_key != request.identity.idempotency_key
        || existing.canonical_request_hash != request.identity.canonical_request_hash
    {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    completed_receipt(existing)?.ok_or(AdapterError::Store(StoreError::ReceiptNotFound))
}

/// Requires a completed capture source with a stored receipt.
fn completed_source_receipt(
    source: &BackupOperationRow,
) -> Result<StoreBackupCompletionReceipt, AdapterError> {
    if source.operation_kind != super::backup_snapshot::KIND_CAPTURE {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.source",
            reason: "restore source must be a capture operation",
        }));
    }
    completed_receipt(source)?.ok_or({
        AdapterError::Store(StoreError::InvalidField {
            field: "backup.source",
            reason: "restore source capture is not completed",
        })
    })
}

/// Loads all frozen source members, verifying the frozen population.
async fn load_source_members(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    source: &BackupOperationRow,
    expected_member_count: u64,
) -> Result<Vec<BackupMemberRow>, AdapterError> {
    if u64::try_from(source.member_count.max(0)).unwrap_or(0) != expected_member_count {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    let mut bindings = Map::new();
    bindings.insert("backup_operation_id".to_owned(), json!(source.operation_id));
    let limit = source.member_count.max(0).saturating_add(1);
    let mut response = client::query(
        db,
        config,
        "backup.restore",
        &format!(
            "SELECT * FROM {} WHERE operation_id = $backup_operation_id ORDER BY page_cursor LIMIT {limit};",
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
    let members = take_vec::<BackupMemberRow>(&mut response, 0)?;
    if i64::try_from(members.len()).unwrap_or(i64::MAX) != source.member_count {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(members)
}

/// Loads current purge-suppression subjects. An absent erasure table reads
/// as no suppressions; any other error keeps the reconciling disposition.
async fn load_purge_subjects(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<Vec<String>, AdapterError> {
    let mut response = client::query(
        db,
        config,
        "backup.restore",
        "SELECT VALUE subject FROM erasure_intent;",
        Map::new(),
    )
    .await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        if errors.iter().all(|error| client::is_absent_table(error)) {
            return Ok(Vec::new());
        }
        return Err(AdapterError::PartialOutcome);
    }
    response.take::<Vec<String>>(0)
}

/// Reports whether a frozen member is named by a current purge
/// suppression. Suppressed members are never resurrected: they are skipped
/// by the replay and excluded from the restore receipt denominators.
fn is_suppressed(subjects: &[String], member: &BackupMemberRow) -> bool {
    let qualified = format!("{}:{}", member.member_table, member.member_id);
    subjects.iter().any(|subject| {
        subject == &qualified || subject == &member.member_id || subject == &member.member_table
    })
}

/// Replay classification for one restore: slots to create, slots already
/// converged, fence guard values. Any divergent slot conflicts before any
/// write; a moved fence reports unknown instead of success.
struct ReplayPlan {
    fence_commit_sequence: u64,
    fence_outbox_sequence: u64,
    create_indexes: Vec<usize>,
}

async fn classify_replay_slots(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    fence: &crate::apply::schema_contract::FenceRecord,
    candidates: &[&BackupMemberRow],
    operation_id: &str,
) -> Result<ReplayPlan, AdapterError> {
    let mut sql = String::from(schema::TX_BEGIN);
    sql.push_str(schema::READ_FENCE);
    for index in 0..candidates.len() {
        let _ = write!(
            sql,
            "SELECT * FROM ONLY type::record($backup_table{index}, $backup_id{index});"
        );
    }
    sql.push_str(schema::TX_COMMIT);
    let mut indexed_bindings = Map::new();
    for (index, member) in candidates.iter().enumerate() {
        let (table, key) = restore_record_key(member)?;
        indexed_bindings.insert(format!("backup_table{index}"), json!(table));
        indexed_bindings.insert(format!("backup_id{index}"), json!(key));
    }
    let mut response = client::query(db, config, "backup.restore", &sql, indexed_bindings).await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let live_fence = response
        .take::<Option<crate::apply::schema_contract::FenceRecord>>(1)?
        .ok_or(AdapterError::PartialOutcome)?;
    super::schema_contract::validate_fence_record(&live_fence)?;
    if live_fence.state_fence != fence.state_fence
        || live_fence.next_commit_sequence != fence.next_commit_sequence
        || live_fence.next_outbox_sequence != fence.next_outbox_sequence
    {
        return Err(AdapterError::UnknownOutcome {
            operation_id: operation_id.to_owned(),
        });
    }
    let mut create_indexes = Vec::new();
    for (position, member) in candidates.iter().enumerate() {
        let live = response.take::<Option<Value>>(2 + position)?;
        match live {
            None => create_indexes.push(position),
            Some(value) => {
                if row_content_digest(&value)? != member.content_digest {
                    return Err(AdapterError::Store(StoreError::IdentityConflict));
                }
            }
        }
    }
    Ok(ReplayPlan {
        fence_commit_sequence: fence.next_commit_sequence,
        fence_outbox_sequence: fence.next_outbox_sequence,
        create_indexes,
    })
}

/// Derives the deterministic restore record address for one frozen member,
/// reproducing the exact key convention the canonical write path used.
fn restore_record_key(member: &BackupMemberRow) -> Result<(String, String), AdapterError> {
    let table = CAPTURE_TABLES
        .iter()
        .find(|entry| entry.table == member.member_table)
        .ok_or({
            AdapterError::Store(StoreError::InvalidField {
                field: "backup.member_table",
                reason: "frozen member names an unknown canonical table",
            })
        })?;
    let row: Value = serde_json::from_str(&member.member_json)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let key =
        match table.id_kind {
            TableIdKind::Field(field) => row
                .get(field)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or({
                    AdapterError::Serialization("frozen member lost its logical key".to_owned())
                })?,
            TableIdKind::NamespaceKey => {
                let namespace = row.get("namespace").and_then(Value::as_str).ok_or({
                    AdapterError::Serialization("frozen member lost its namespace".to_owned())
                })?;
                let key = row.get("key").and_then(Value::as_str).ok_or({
                    AdapterError::Serialization("frozen member lost its key".to_owned())
                })?;
                let bytes = eliot_store_api::canonical_json_bytes(&json!({
                    "namespace": namespace,
                    "key": key,
                }))
                .map_err(|error| AdapterError::Serialization(error.to_string()))?;
                sha256_hex(&bytes)
            }
            TableIdKind::AutomationRevision => {
                let automation_id = row.get("automation_id").and_then(Value::as_str).ok_or({
                    AdapterError::Serialization("frozen member lost its id".to_owned())
                })?;
                let revision = row.get("revision").and_then(Value::as_str).ok_or({
                    AdapterError::Serialization("frozen member lost its revision".to_owned())
                })?;
                format!("{automation_id}\u{1f}{revision}")
            }
            TableIdKind::AutomationFailure => {
                let automation_id = row.get("automation_id").and_then(Value::as_str).ok_or({
                    AdapterError::Serialization("frozen member lost its id".to_owned())
                })?;
                let revision = row.get("revision").and_then(Value::as_str).ok_or({
                    AdapterError::Serialization("frozen member lost its revision".to_owned())
                })?;
                let fingerprint = row.get("fingerprint").and_then(Value::as_str).ok_or({
                    AdapterError::Serialization("frozen member lost its fingerprint".to_owned())
                })?;
                eliot_store_api::automation_failure_key(automation_id, revision, fingerprint)
            }
        };
    if key != member.member_id {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    Ok((table.table.to_owned(), key))
}

/// Computes the content digest of a live row the same way the freeze did:
/// canonical JSON over the id-stripped object.
fn row_content_digest(value: &Value) -> Result<String, AdapterError> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or(AdapterError::Serialization(
            "canonical row is not an object".to_owned(),
        ))?;
    object.remove("id");
    let bytes = eliot_store_api::canonical_json_bytes(&Value::Object(object))
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Applies the replay transaction: fence guard, conditional creates for
/// classified slots, then verification of duplicate losers. The restore
/// operation row is never created here; commitment happens only in
/// `commit_restore` after every member verifies.
async fn apply_replay(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    plan: &ReplayPlan,
    candidates: &[&BackupMemberRow],
    fence: &StateFence,
    operation_id: &str,
) -> Result<(), AdapterError> {
    if plan.create_indexes.is_empty() {
        return Ok(());
    }
    let mut sql = String::from(schema::TX_BEGIN);
    sql.push_str(schema::TX_GUARD_FENCE);
    let mut bindings = Map::new();
    apply_replay_statements(&mut sql, &mut bindings, plan, candidates, fence)?;
    sql.push_str(schema::TX_COMMIT);
    let mut response = db.query_admin("backup.restore", &sql, bindings).await?;
    let errors = response.take_errors();
    if errors.is_empty() {
        return Ok(());
    }
    if errors
        .iter()
        .any(|error| error.contains(FENCE_DRIFT_MARKER))
    {
        return Err(AdapterError::UnknownOutcome {
            operation_id: operation_id.to_owned(),
        });
    }
    if errors.iter().all(|error| client::is_absent_table(error)) {
        return Err(AdapterError::MigrationRequired);
    }
    verify_replay_slots(db, config, plan, candidates, operation_id).await
}

/// Appends the fence guard bindings plus one conditional create per
/// classified slot. Present rows are never overwritten here; divergence
/// was already refused in classification, and concurrent winners converge
/// in verification.
fn apply_replay_statements(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    plan: &ReplayPlan,
    candidates: &[&BackupMemberRow],
    fence: &StateFence,
) -> Result<(), AdapterError> {
    bindings.insert("expected_state_fence".to_owned(), json!(fence));
    bindings.insert(
        "expected_commit_sequence".to_owned(),
        json!(plan.fence_commit_sequence),
    );
    bindings.insert(
        "expected_outbox_sequence".to_owned(),
        json!(plan.fence_outbox_sequence),
    );
    for position in &plan.create_indexes {
        let member = candidates[*position];
        let (table, key) = restore_record_key(member)?;
        let row: Value = serde_json::from_str(&member.member_json)
            .map_err(|error| AdapterError::Serialization(error.to_string()))?;
        let _ = write!(
            sql,
            "LET $backup_seen{position} = (SELECT * FROM ONLY type::record($backup_table{position}, $backup_id{position})); IF !type::is_object($backup_seen{position}) {{ CREATE type::record($backup_table{position}, $backup_id{position}) CONTENT $backup_row{position}; }};"
        );
        bindings.insert(format!("backup_table{position}"), json!(table));
        bindings.insert(format!("backup_id{position}"), json!(key));
        bindings.insert(format!("backup_row{position}"), row);
    }
    Ok(())
}

/// Verifies duplicate losers converged on identical content. A moved fence
/// stays unknown; real divergence conflicts; anything else stays
/// reconciling.
async fn verify_replay_slots(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    plan: &ReplayPlan,
    candidates: &[&BackupMemberRow],
    operation_id: &str,
) -> Result<(), AdapterError> {
    let mut sql = String::from(schema::TX_BEGIN);
    sql.push_str(schema::READ_FENCE);
    for position in &plan.create_indexes {
        let _ = write!(
            sql,
            "SELECT * FROM ONLY type::record($backup_vtable{position}, $backup_vid{position});"
        );
    }
    sql.push_str(schema::TX_COMMIT);
    let mut bindings = Map::new();
    for position in &plan.create_indexes {
        let member = candidates[*position];
        let (table, key) = restore_record_key(member)?;
        bindings.insert(format!("backup_vtable{position}"), json!(table));
        bindings.insert(format!("backup_vid{position}"), json!(key));
    }
    let mut response = client::query(db, config, "backup.restore", &sql, bindings).await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let fence = response
        .take::<Option<crate::apply::schema_contract::FenceRecord>>(1)?
        .ok_or(AdapterError::PartialOutcome)?;
    if fence.next_commit_sequence != plan.fence_commit_sequence
        || fence.next_outbox_sequence != plan.fence_outbox_sequence
    {
        return Err(AdapterError::UnknownOutcome {
            operation_id: operation_id.to_owned(),
        });
    }
    for (slot, position) in plan.create_indexes.iter().enumerate() {
        let member = candidates[*position];
        let live = response
            .take::<Option<Value>>(2 + slot)?
            .ok_or(AdapterError::PartialOutcome)?;
        if row_content_digest(&live)? != member.content_digest {
            return Err(AdapterError::Store(StoreError::IdentityConflict));
        }
    }
    Ok(())
}

/// Commits the restore atomically: fence compare-and-set bump, then the
/// restore operation row with its receipt. A concurrent winner's identical
/// receipt replays; anything else stays a conflict.
async fn commit_restore(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    request: &StoreIsolatedRestoreRequest,
    source_receipt: &StoreBackupCompletionReceipt,
    plan: &ReplayPlan,
    candidates: &[&BackupMemberRow],
) -> Result<StoreBackupCompletionReceipt, AdapterError> {
    let receipt = build_restore_receipt(request, source_receipt, candidates)?;
    let receipt_json = serde_json::to_string(&receipt)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let scope_json = serde_json::to_string(&request.scope)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let mut sql = String::from(schema::TX_BEGIN);
    sql.push_str(FENCE_BUMP_STATEMENT);
    let _ = write!(
        sql,
        "CREATE {} CONTENT $backup_operation_record;",
        schema::table::BACKUP_OPERATION
    );
    sql.push_str(schema::TX_COMMIT);
    let mut bindings = Map::new();
    bindings.insert(
        "backup_next_commit_sequence".to_owned(),
        json!(plan.fence_commit_sequence.saturating_add(1)),
    );
    bindings.insert(
        "backup_next_outbox_sequence".to_owned(),
        json!(plan.fence_outbox_sequence.saturating_add(1)),
    );
    bindings.insert(
        "backup_expected_commit_sequence".to_owned(),
        json!(plan.fence_commit_sequence),
    );
    bindings.insert(
        "backup_expected_outbox_sequence".to_owned(),
        json!(plan.fence_outbox_sequence),
    );
    bindings.insert(
        "backup_operation_record".to_owned(),
        json!({
            "operation_id": request.identity.operation_id.to_string(),
            "operation_kind": KIND_RESTORE,
            "idempotency_key": request.identity.idempotency_key,
            "canonical_request_hash": request.identity.canonical_request_hash,
            "state_fence": request.scope.state_fence,
            "scope_json": scope_json,
            "status": STATUS_COMPLETED,
            "consistency_point": source_receipt.consistency_point,
            "snapshot_digest": source_receipt.snapshot_digest,
            "member_count": i64::try_from(candidates.len()).unwrap_or(i64::MAX),
            "total_bytes": i64::try_from(
                candidates
                    .iter()
                    .map(|member| u64::try_from(member.member_bytes.max(0)).unwrap_or(0))
                    .sum::<u64>(),
            )
            .unwrap_or(i64::MAX),
            "receipt_json": receipt_json,
            "frozen_commit_sequence": plan.fence_commit_sequence,
            "frozen_outbox_sequence": plan.fence_outbox_sequence,
            "frozen_heads_digest": "",
        }),
    );
    let mut response = db.query_admin("backup.restore", &sql, bindings).await?;
    let errors = response.take_errors();
    if errors.is_empty() {
        return Ok(receipt);
    }
    if errors
        .iter()
        .any(|error| error.contains(FENCE_DRIFT_MARKER))
    {
        return Err(AdapterError::UnknownOutcome {
            operation_id: request.identity.operation_id.to_string(),
        });
    }
    if errors.iter().all(|error| client::is_absent_table(error)) {
        return Err(AdapterError::MigrationRequired);
    }
    if is_duplicate_operation(&errors) {
        let existing =
            load_operation_row(db, config, "backup.restore", &request.identity.operation_id)
                .await?
                .ok_or(AdapterError::PartialOutcome)?;
        return replay_or_conflict_restore(request, &existing);
    }
    Err(AdapterError::PartialOutcome)
}

/// Builds the restore completion receipt over the restored set only.
/// Suppressed members never enter these denominators; the delta against
/// the source receipt is the exact suppression evidence.
fn build_restore_receipt(
    request: &StoreIsolatedRestoreRequest,
    source_receipt: &StoreBackupCompletionReceipt,
    candidates: &[&BackupMemberRow],
) -> Result<StoreBackupCompletionReceipt, AdapterError> {
    use std::collections::BTreeMap;
    let mut domains: BTreeMap<String, (String, Vec<&str>, u64, u64)> = BTreeMap::new();
    for member in candidates {
        let table = CAPTURE_TABLES
            .iter()
            .find(|entry| entry.table == member.member_table)
            .ok_or({
                AdapterError::Store(StoreError::InvalidField {
                    field: "backup.member_table",
                    reason: "frozen member names an unknown canonical table",
                })
            })?;
        let entry = domains
            .entry(member.residency_digest.clone())
            .or_insert_with(|| (table.domain.to_owned(), Vec::new(), 0, 0));
        entry.1.push(member.member_digest.as_str());
        entry.2 += 1;
        entry.3 = entry
            .3
            .saturating_add(u64::try_from(member.member_bytes.max(0)).unwrap_or(0));
    }
    let mut residencies = Vec::with_capacity(domains.len());
    for (residency_digest, (domain, mut digests, count, bytes)) in domains {
        digests.sort_unstable();
        residencies.push(ResidencyDisposition {
            residency_digest,
            domain,
            member_count: count,
            member_bytes: bytes,
            content_digest: sha256_hex(digests.join("\n").as_bytes()),
        });
    }
    let total_bytes: u64 = residencies.iter().map(|entry| entry.member_bytes).sum();
    let receipt = StoreBackupCompletionReceipt {
        operation_id: request.identity.operation_id.clone(),
        state_fence: request.scope.state_fence.clone(),
        consistency_point: source_receipt.consistency_point.clone(),
        snapshot_digest: source_receipt.snapshot_digest.clone(),
        scope_residency_digest: request.scope.residency_denominator_digest.clone(),
        member_count: candidates.len() as u64,
        total_bytes,
        residencies,
        revision_heads: Vec::new(),
        ordering_heads: Vec::new(),
        partial: false,
    };
    receipt.validate().map_err(AdapterError::Store)?;
    Ok(receipt)
}

/// Validates one captured snapshot without restoring it. The frozen set is
/// recomputed and compared field by field: complete, known-empty,
/// unsupported, and conflict stay distinct, and unavailable validation
/// never returns success.
pub(crate) async fn backup_validate(
    adapter: &crate::SurrealStoreAdapter,
    request: StoreBackupValidationRequest,
) -> Result<StoreBackupValidationReceipt, AdapterError> {
    request.validate().map_err(AdapterError::Store)?;
    let db = super::client(adapter).await?;
    super::ensure_ready(adapter, db).await?;
    let operation = load_operation_row(
        db,
        &adapter.config,
        "backup.validate",
        &request.operation_id,
    )
    .await?
    .ok_or(AdapterError::Store(StoreError::ReceiptNotFound))?;
    let members = load_validation_members(db, &adapter.config, &operation).await?;
    let (checked, unresolved, outcome) = verify_frozen_set(&operation, &members, &request)?;
    let receipt = StoreBackupValidationReceipt {
        operation_id: request.operation_id.clone(),
        state_fence: operation.state_fence.clone(),
        snapshot_digest: request.snapshot_digest.clone(),
        outcome,
        checked_members: checked,
        unresolved_members: unresolved,
    };
    receipt.validate().map_err(AdapterError::Store)?;
    Ok(receipt)
}

/// Frozen member digest projection for validation. Field names mirror the
/// provider columns exactly so the projection decodes without renaming.
#[derive(Deserialize)]
#[allow(clippy::struct_field_names, reason = "fields mirror provider columns")]
struct MemberDigestRow {
    member_digest: String,
    content_digest: String,
    residency_digest: String,
}

/// Loads frozen members for validation, verifying the frozen population.
async fn load_validation_members(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    operation: &BackupOperationRow,
) -> Result<Vec<BackupMemberRow>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "backup_operation_id".to_owned(),
        json!(operation.operation_id),
    );
    let limit = operation.member_count.max(0).saturating_add(1);
    let mut response = client::query(
        db,
        config,
        "backup.validate",
        &format!(
            "SELECT member_digest, content_digest, residency_digest FROM {} WHERE operation_id = $backup_operation_id ORDER BY page_cursor LIMIT {limit};",
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
    let rows = response.take::<Vec<MemberDigestRow>>(0)?;
    if i64::try_from(rows.len()).unwrap_or(i64::MAX) != operation.member_count {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(rows
        .into_iter()
        .map(|row| BackupMemberRow {
            operation_id: operation.operation_id.clone(),
            member_digest: row.member_digest,
            content_digest: row.content_digest,
            residency_digest: row.residency_digest,
            member_bytes: 0,
            page_cursor: 0,
            member_table: String::new(),
            member_id: String::new(),
            member_json: String::new(),
        })
        .collect())
}

/// Verifies the frozen set against the validation request: snapshot digest
/// recomputed over ordered member digests, scope denominator pinned to the
/// operation row, zero unresolved on any complete claim.
fn verify_frozen_set(
    operation: &BackupOperationRow,
    members: &[BackupMemberRow],
    request: &StoreBackupValidationRequest,
) -> Result<(u64, u64, StoreBackupValidationOutcome), AdapterError> {
    let mut ordered: Vec<&str> = members
        .iter()
        .map(|member| member.member_digest.as_str())
        .collect();
    ordered.sort_unstable();
    let recomputed = sha256_hex(ordered.join("\n").as_bytes());
    let scope = operation_scope(operation)?;
    if scope.residency_denominator_digest != expected_denominator_digest() {
        return Ok((
            0,
            members.len() as u64,
            StoreBackupValidationOutcome::Conflict,
        ));
    }
    if recomputed != request.snapshot_digest {
        return Ok((
            0,
            members.len() as u64,
            StoreBackupValidationOutcome::Conflict,
        ));
    }
    if let Some(stored) = operation.snapshot_digest.as_deref()
        && stored != request.snapshot_digest
    {
        return Ok((
            0,
            members.len() as u64,
            StoreBackupValidationOutcome::Conflict,
        ));
    }
    if members.is_empty() {
        return Ok((0, 0, StoreBackupValidationOutcome::KnownEmpty));
    }
    Ok((
        members.len() as u64,
        0,
        StoreBackupValidationOutcome::Complete,
    ))
}

/// Observes the status of one backup operation. Absent operations report
/// `Unknown` with a zero denominator: status is an observation, never an
/// error and never a proof.
pub(crate) async fn backup_status(
    adapter: &crate::SurrealStoreAdapter,
    request: StoreBackupStatusRequest,
) -> Result<StoreBackupStatusReport, AdapterError> {
    request.validate().map_err(AdapterError::Store)?;
    let db = super::client(adapter).await?;
    super::ensure_ready(adapter, db).await?;
    let operation =
        load_operation_row(db, &adapter.config, "backup.status", &request.operation_id).await?;
    let report = match operation {
        None => StoreBackupStatusReport {
            operation_id: request.operation_id.clone(),
            state_fence: adapter_fence(db, &adapter.config).await?,
            phase: StoreBackupPhase::Unknown,
            completed_members: 0,
            completed_bytes: 0,
        },
        Some(operation) => {
            let phase = match operation.status.as_str() {
                super::backup_snapshot::STATUS_CAPTURING => StoreBackupPhase::Capturing,
                STATUS_RESTORING => StoreBackupPhase::Restoring,
                super::backup_snapshot::STATUS_COMPLETED => StoreBackupPhase::Completed,
                super::backup_snapshot::STATUS_EXPIRED => StoreBackupPhase::Expired,
                _ => StoreBackupPhase::Unknown,
            };
            StoreBackupStatusReport {
                operation_id: request.operation_id.clone(),
                state_fence: operation.state_fence.clone(),
                phase,
                completed_members: u64::try_from(operation.member_count.max(0)).unwrap_or(0),
                completed_bytes: u64::try_from(operation.total_bytes.max(0)).unwrap_or(0),
            }
        }
    };
    report.validate().map_err(AdapterError::Store)?;
    Ok(report)
}

/// Reads the live fence for status reports on unknown operations.
async fn adapter_fence(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<StateFence, AdapterError> {
    let fence = read_fence(db, config)
        .await?
        .ok_or(AdapterError::MigrationRequired)?;
    super::schema_contract::validate_fence_record(&fence)?;
    Ok(fence.state_fence)
}

/// Reconciles one uncertain backup mutation by exact identity.
/// Reconciliation changes correlation, never the original operation:
/// committed only with a revalidated receipt under the admitted digest,
/// conflict on a changed input, unknown for everything without durable
/// evidence. Unknown never triggers a new operation or a retry.
pub(crate) async fn backup_reconcile(
    adapter: &crate::SurrealStoreAdapter,
    request: StoreBackupReconcileRequest,
) -> Result<StoreBackupReconciliation, AdapterError> {
    request.validate().map_err(AdapterError::Store)?;
    let db = super::client(adapter).await?;
    super::ensure_ready(adapter, db).await?;
    let operation = load_operation_row(
        db,
        &adapter.config,
        "backup.reconcile",
        &request.operation_id,
    )
    .await?;
    let Some(operation) = operation else {
        return Ok(StoreBackupReconciliation::Unknown);
    };
    if operation.canonical_request_hash != request.canonical_request_hash {
        return Ok(StoreBackupReconciliation::Conflict);
    }
    match operation.status.as_str() {
        super::backup_snapshot::STATUS_COMPLETED => {
            let receipt = completed_receipt(&operation)?.ok_or(AdapterError::PartialOutcome)?;
            if receipt.operation_id != request.operation_id {
                return Ok(StoreBackupReconciliation::Conflict);
            }
            Ok(StoreBackupReconciliation::Committed)
        }
        _ => Ok(StoreBackupReconciliation::Unknown),
    }
}

/// Proves backup-table provisioning for truthful capability advertisement.
/// `true` only when a live query against the coordination table succeeds;
/// absent tables, unreadiness, and transport loss all report `false` so an
/// unowned capability is never advertised.
pub(crate) async fn backup_provisioned(adapter: &crate::SurrealStoreAdapter) -> bool {
    let Ok(db) = super::client(adapter).await else {
        return false;
    };
    if super::ensure_ready(adapter, db).await.is_err() {
        return false;
    }
    let Ok(mut response) = client::query(
        db,
        &adapter.config,
        "backup.probe_provisioned",
        &format!(
            "SELECT VALUE operation_id FROM {} LIMIT 1;",
            schema::table::BACKUP_OPERATION
        ),
        Map::new(),
    )
    .await
    else {
        return false;
    };
    if !response.take_errors().is_empty() {
        return false;
    }
    response.take::<Vec<String>>(0).is_ok()
}
