//! Canonical backup restore/validation backend (issue #952).
//!
//! Implements the restore half of [`eliot_store_api::CanonicalBackupPorts`]
//! in the sole credential/client/canonical-table owner. Restore replays only
//! validated canonical rows into the admitted isolated destination, which is
//! a genuinely separate store identity: a different `SurrealDB` database on
//! the same provider generation, reached only through a dedicated
//! destination session that is never pooled with serving traffic. The
//! destination must be provisioned (schema baseline, shared fence, and a
//! fenced non-serving destination admission record), and same-store or
//! source restores are refused before any restore I/O. The serving store's
//! canonical tables and fence sequences are never written or spent by a
//! restore; the live backup-operation ledger records only coordination
//! metadata (identity, admission digest, destination, receipt).
//!
//! Every restore presents the provisional restore admission slot: the
//! bridge recomputes the decision digest (self-consistency only, never
//! issuance proof), refuses any mismatch, binds the presented fields to
//! the independent canonical anchors below, executes exactly the
//! presented plan, and repeats the digest in the restore receipt. The
//! independent anchors are the completed live source-capture row (source
//! snapshot and denominator the caller cannot fabricate), the
//! deployment-provisioned destination record (destination identity the
//! caller cannot provision), and the frame-enforced session capability
//! plus transport identity (bound before dispatch). Replay converges
//! instead of overwriting: a present row with identical content
//! converges, a present row with divergent content conflicts, and
//! members named by a current purge suppression are never resurrected.
//! Derived rows replay verbatim only through the projection owner's
//! admission gate. Classification happens before any write; one atomic
//! destination transaction carries the fence guard, the conditional
//! creates, and the destination fence advance; the restore ledger row
//! commits only after every replayed member verifies. Unknown stays
//! unknown: transport loss or a moved fence during replay reports
//! `UnknownOutcome` for exact readback instead of success.

use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::fmt::Write as _;

use crate::client::{self, RestoreDestinationTransport, RpcTransport};
use crate::config::SurrealAdapterConfig;
use crate::error::AdapterError;
use crate::readiness::CompiledMigration;
use crate::schema;
use eliot_platform::ClockObservation;
use eliot_store_api::{
    OrderingHead, ResidencyDisposition, RevisionHead, StateFence, StoreBackupCompletionReceipt,
    StoreBackupPhase, StoreBackupReconcileRequest, StoreBackupReconciliation,
    StoreBackupStatusReport, StoreBackupStatusRequest, StoreBackupValidationOutcome,
    StoreBackupValidationReceipt, StoreBackupValidationRequest, StoreError,
    StoreIsolatedRestoreRequest, TransitionClass, WriteReceiptStatus, sha256_hex,
};

use super::backup_snapshot::{
    BackupMemberRow, BackupOperationRow, BackupResidencyRow, CAPTURE_TABLES, STATUS_COMPLETED,
    TableIdKind, completed_receipt, expected_denominator_digest, is_duplicate_operation,
    load_operation_row, operation_scope,
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
/// destination only. Same-operation replay returns the original receipt
/// only when the presented admission digest matches the stored one;
/// changed input — including a rotated admission — under the same
/// identity conflicts; loss of response stays unknown for exact
/// readback.
///
/// The presented provisional admission is verified before any restore
/// I/O: closed request validation recomputes the decision digest
/// (self-consistency) and cross-binds identity, destination, fence,
/// denominator, and snapshot; the bridge then binds the presented
/// source digest and denominator to the completed live source-capture
/// row and the presented destination to the provisioned destination
/// record — both independent canonical anchors the caller cannot
/// fabricate. The replay lands only in the dedicated destination
/// database; the serving store's canonical tables and fence sequences
/// are never written or spent. Converge-or-conflict plus fence guards
/// remain the write-safety layer *inside* the isolated destination,
/// never a substitute for it.
pub(crate) async fn backup_isolated_restore(
    adapter: &crate::SurrealStoreAdapter,
    request: StoreIsolatedRestoreRequest,
) -> Result<StoreBackupCompletionReceipt, AdapterError> {
    request.validate().map_err(AdapterError::Store)?;
    let db = super::client(adapter).await?;
    super::ensure_ready(adapter, db).await?;
    let prose_pinned = super::backup_snapshot::provider_prose_pinned(adapter);
    if request.scope.schema_generation != adapter.config.expected_schema_generation.as_str() {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    }
    // R1: the destination must be a genuinely different store identity.
    // A restore into the serving store is refused before any restore I/O;
    // the destination transport refuses it again at connect time.
    if request.scope.dest_store_id == adapter.config.database {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.destination",
            reason: "restore destination must differ from the serving store",
        }));
    }
    // R5: the admitted denominator must name exactly the canonical
    // denominator; scope exclusion without exact scope evidence refuses
    // before any restore I/O.
    if request.scope.residency_denominator_digest != expected_denominator_digest() {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.scope",
            reason: "admitted denominator does not match the canonical denominator",
        }));
    }
    // Pin the admitted fence against the live store: both endpoints share
    // it, and the composition already pinned it to its own fence.
    current_live_fence(db, &adapter.config, &request.scope.state_fence).await?;
    // F1 directive anchor: the Governor's restore directive must be a
    // committed canonical transition the bridge fetches itself — never a
    // caller-carried receipt. Only the canonical transaction path
    // (fence CAS, admission, catalogue) can create such a receipt, so its
    // presence is the issuance proof the recomputed digest cannot supply.
    // The receipt must be Committed under RecoverySchema on the shared
    // fence with the exact operation identity and canonical request hash
    // the admission names; anything else refuses before any restore I/O.
    // Until the #959/#960 minter commits directives, every restore
    // refuses here with ReceiptNotFound: fail-closed, never admittable
    // by struct alone.
    verify_governor_directive(adapter, &request).await?;
    let restore_id = request.identity.operation_id.clone();
    if let Some(existing) = load_operation_row(
        db,
        &adapter.config,
        "backup.restore",
        &restore_id,
        prose_pinned,
    )
    .await?
    {
        return replay_or_conflict_restore(&request, &existing);
    }
    let source = load_operation_row(
        db,
        &adapter.config,
        "backup.restore",
        &request.source_operation_id,
        prose_pinned,
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
    // F1 source anchor: bind the presented admission to the independent
    // canonical record — the completed live capture row the caller cannot
    // fabricate must carry the exact snapshot and denominator the
    // admission claims. Transitive with request validation by construction;
    // enforced here so the anchor binding survives at the bridge layer.
    if request.admission.source_snapshot_digest != source_receipt.snapshot_digest
        || request.admission.residency_denominator_digest
            != source_receipt.scope_residency_digest
    {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    let source_members =
        load_source_members(db, &adapter.config, &source, request.expected_member_count).await?;
    let suppressions = load_purge_subjects(db, &adapter.config, prose_pinned).await?;
    let candidates: Vec<&BackupMemberRow> = source_members
        .iter()
        .filter(|member| !is_suppressed(&suppressions, member))
        .filter(|member| !is_outbox_suppressed(member))
        .collect();
    // R4: derived rows replay verbatim only through the projection
    // owner's admission gate; anything else refuses before any write.
    for member in &candidates {
        if member.member_table == schema::table::PROJECTION_RECORD
            || member.member_table == schema::table::OUTBOX_EVENT
        {
            crate::plan::admit_frozen_derived_replay(
                &member.member_table,
                &member.member_json,
                &member.content_digest,
            )
            .map_err(AdapterError::Store)?;
        }
    }
    execute_destination_restore(
        adapter,
        db,
        &request,
        &source,
        &source_receipt,
        &candidates,
        prose_pinned,
    )
    .await
}

/// Executes the destination phase of one admitted restore: dedicated
/// destination transport, destination readiness and admission proof,
/// classification, one atomic destination transaction, convergence
/// verification, then the live coordination ledger row. Extracted so the
/// admission preamble above stays reviewable as one screen.
async fn execute_destination_restore(
    adapter: &crate::SurrealStoreAdapter,
    db: &RpcTransport,
    request: &StoreIsolatedRestoreRequest,
    source: &BackupOperationRow,
    source_receipt: &StoreBackupCompletionReceipt,
    candidates: &[&BackupMemberRow],
    prose_pinned: bool,
) -> Result<StoreBackupCompletionReceipt, AdapterError> {
    let restore_id = request.identity.operation_id.to_string();
    // R1: the dedicated destination transport joins the same provider
    // generation on the admitted destination database. It is never pooled
    // with serving traffic and never observes serving state.
    let dest = client::connect_restore_destination(
        db.provider(),
        &adapter.config,
        &request.scope.dest_store_id,
    )
    .await?;
    // R1: the destination must be provisioned (expected baseline, shared
    // fence, fenced non-serving admission record) before any replay.
    let dest_fence =
        read_destination_fence(&dest, &adapter.config, &request.scope.state_fence, prose_pinned)
            .await?;
    verify_destination_record(&dest, request, prose_pinned).await?;
    let source_commit_sequence = u64::try_from(source.frozen_commit_sequence.max(0)).unwrap_or(0);
    let source_outbox_sequence = u64::try_from(source.frozen_outbox_sequence.max(0)).unwrap_or(0);
    let plan = classify_replay_slots(
        &dest,
        &dest_fence,
        candidates,
        &restore_id,
        prose_pinned,
    )
    .await?;
    // R2: one atomic destination transaction carries the fence guard, the
    // conditional creates, and the destination fence advance. The live
    // fence is never touched: restore spends no live sequence space.
    let (next_commit_sequence, next_outbox_sequence) = commit_destination_replay(
        &dest,
        &plan,
        candidates,
        &request.scope.state_fence,
        source_commit_sequence,
        source_outbox_sequence,
        &restore_id,
    )
    .await?;
    verify_replay_slots(
        &dest,
        &plan,
        candidates,
        &restore_id,
        next_commit_sequence,
        next_outbox_sequence,
    )
    .await?;
    // The live backup-operation ledger records coordination metadata only
    // (identity, admission digest, destination, receipt) without moving
    // the live fence: bookkeeping, never canonical state.
    commit_restore_ledger(RestoreLedgerCommit {
        db,
        config: &adapter.config,
        request,
        source_receipt,
        candidates,
        dest_commit_sequence: next_commit_sequence,
        dest_outbox_sequence: next_outbox_sequence,
        prose_pinned,
    })
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

/// Verifies the Governor restore-directive anchor against the committed
/// canonical receipt chain (F1).
///
/// The bridge fetches the directive receipt itself by the operation
/// identity the admission names and binds it field by field: the receipt
/// must exist, validate as a terminal receipt, carry Committed status
/// under `RecoverySchema` on the shared fence, and repeat the exact
/// canonical request hash the admission claims. The admission decision
/// digest (recomputed in request validation) already covers the
/// directive reference, so a verified receipt binds directive,
/// admission, and restore into one tuple. No committed directive means
/// no issuance proof, and the restore refuses — including replays, which
/// re-verify the anchor on every call.
async fn verify_governor_directive(
    adapter: &crate::SurrealStoreAdapter,
    request: &StoreIsolatedRestoreRequest,
) -> Result<(), AdapterError> {
    let receipt = super::read_receipt(
        adapter,
        request.admission.governor_directive_operation_id.clone(),
    )
    .await?
    .ok_or(AdapterError::Store(StoreError::ReceiptNotFound))?;
    receipt.validate().map_err(AdapterError::Store)?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(AdapterError::Store(StoreError::ReceiptNotFound));
    }
    if receipt.transition_class != TransitionClass::RecoverySchema {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.transition_class",
            reason: "restore directives commit only under RecoverySchema",
        }));
    }
    if receipt.canonical_request_hash != request.admission.governor_directive_request_hash {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    if receipt.state_fence != request.scope.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    Ok(())
}

/// Reconciles a repeated restore against the durable row. An identical
/// admission replays the stored receipt; a rotated admission under a
/// reused identity triple conflicts instead of returning a receipt bound
/// to a different admission (F6).
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
    let receipt = completed_receipt(existing)?.ok_or(AdapterError::Store(StoreError::ReceiptNotFound))?;
    if receipt.admission_decision_digest.as_deref()
        != Some(request.admission.admission_decision_digest.as_str())
    {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    Ok(receipt)
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
    completed_receipt(source)?.ok_or(AdapterError::Store(StoreError::InvalidField {
        field: "backup.source",
        reason: "restore source capture is not completed",
    }))
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
        // Source members live in the backup coordination tables the
        // restore path already proved present by loading the source
        // operation row; any error here keeps the reconciling
        // disposition.
        return Err(AdapterError::PartialOutcome);
    }
    let members = take_vec::<BackupMemberRow>(&mut response, 0)?;
    if i64::try_from(members.len()).unwrap_or(i64::MAX) != source.member_count {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(members)
}

/// Loads current purge-suppression subjects. A missing purge ledger can
/// never mean "no suppressions": the backend is not provisioned for safe
/// restore, so it refuses with `MigrationRequired` instead of resurrecting
/// purged records. Any other error class keeps the reconciling
/// disposition.
async fn load_purge_subjects(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    prose_pinned: bool,
) -> Result<Vec<String>, AdapterError> {
    let mut response = client::query(
        db,
        config,
        "backup.restore",
        &format!(
            "SELECT VALUE subject FROM {};",
            schema::table::ERASURE_INTENT
        ),
        Map::new(),
    )
    .await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        if prose_pinned
            && errors.iter().all(|error| {
                super::backup_snapshot::is_absent_table_pinned(
                    error,
                    schema::table::ERASURE_INTENT,
                    prose_pinned,
                )
            })
        {
            return Err(AdapterError::MigrationRequired);
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

/// Reports whether a frozen outbox member must stay suppressed under the
/// normative outbox suppression/re-emission contract: only pending
/// (`ARRIVED`) effects re-emit from the isolated destination. Claimed,
/// applied, confirmed, rejected, ambiguous, or irreconcilable effect
/// evidence stays historical — resurrecting it would revive completed or
/// uncertain effects as live work. Unparseable bodies cannot prove pending
/// status, so they suppress rather than re-emit. Suppressed members are
/// excluded from replay and receipt denominators; the delta against the
/// source receipt is the exact suppression evidence.
fn is_outbox_suppressed(member: &BackupMemberRow) -> bool {
    if member.member_table != schema::table::OUTBOX_EVENT {
        return false;
    }
    let Ok(row) = serde_json::from_str::<Value>(&member.member_json) else {
        return true;
    };
    row.get("body")
        .and_then(|body| body.get("state"))
        .and_then(Value::as_str)
        != Some("ARRIVED")
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
    dest: &RestoreDestinationTransport,
    fence: &crate::apply::schema_contract::FenceRecord,
    candidates: &[&BackupMemberRow],
    operation_id: &str,
    prose_pinned: bool,
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
    // Classification reads the destination slots, never serving state: a
    // present destination row converges or conflicts here, before any
    // write.
    let mut response = dest.query("backup.restore", &sql, indexed_bindings).await?;
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
        // Shape-explicit slot read: null means absent (create below), an
        // object converges by content digest, and a provider error string
        // classifies by table — a missing destination table is
        // unprovisioned, anything else stays reconciling. Error prose is
        // never trusted on an unpinned provider version.
        let live = response.take::<Value>(2 + position)?;
        match &live {
            Value::Null => create_indexes.push(position),
            Value::Object(_) => {
                if row_content_digest(&live)? != member.content_digest {
                    return Err(AdapterError::Store(StoreError::IdentityConflict));
                }
            }
            Value::String(prose) => {
                if prose_pinned
                    && super::backup_snapshot::is_absent_table_pinned(
                        prose,
                        &member.member_table,
                        prose_pinned,
                    )
                {
                    return Err(AdapterError::MigrationRequired);
                }
                return Err(AdapterError::PartialOutcome);
            }
            _ => return Err(AdapterError::PartialOutcome),
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
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "backup.member_table",
            reason: "frozen member names an unknown canonical table",
        }))?;
    let row: Value = serde_json::from_str(&member.member_json)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let key =
        match table.id_kind {
            TableIdKind::Field(field) => row
                .get(field)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(AdapterError::Serialization(
                    "frozen member lost its logical key".to_owned(),
                ))?,
            TableIdKind::NamespaceKey => {
                let namespace = row.get("namespace").and_then(Value::as_str).ok_or(
                    AdapterError::Serialization("frozen member lost its namespace".to_owned()),
                )?;
                let key =
                    row.get("key")
                        .and_then(Value::as_str)
                        .ok_or(AdapterError::Serialization(
                            "frozen member lost its key".to_owned(),
                        ))?;
                let bytes = eliot_store_api::canonical_json_bytes(&json!({
                    "namespace": namespace,
                    "key": key,
                }))
                .map_err(|error| AdapterError::Serialization(error.to_string()))?;
                sha256_hex(&bytes)
            }
            TableIdKind::AutomationRevision => {
                let automation_id = row.get("automation_id").and_then(Value::as_str).ok_or(
                    AdapterError::Serialization("frozen member lost its id".to_owned()),
                )?;
                let revision = row.get("revision").and_then(Value::as_str).ok_or(
                    AdapterError::Serialization("frozen member lost its revision".to_owned()),
                )?;
                format!("{automation_id}\u{1f}{revision}")
            }
            TableIdKind::AutomationFailure => {
                let automation_id = row.get("automation_id").and_then(Value::as_str).ok_or(
                    AdapterError::Serialization("frozen member lost its id".to_owned()),
                )?;
                let revision = row.get("revision").and_then(Value::as_str).ok_or(
                    AdapterError::Serialization("frozen member lost its revision".to_owned()),
                )?;
                let fingerprint = row.get("fingerprint").and_then(Value::as_str).ok_or(
                    AdapterError::Serialization("frozen member lost its fingerprint".to_owned()),
                )?;
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
/// Commits the replay atomically against the isolated destination: the
/// destination fence guard, one conditional create per classified slot,
/// then the destination fence compare-and-set advance. Present rows are
/// never overwritten here; divergence was already refused in
/// classification, and concurrent winners converge in verification. The
/// fence sequences advance to cover the maximum of the destination
/// watermark and the source watermark, plus the restore itself: restored
/// commit/outbox evidence is never left above the destination fence
/// sequences, so later drift checks observe the restored state instead of
/// silently predating it. Sequences never rewind. Returns the advanced
/// destination sequences for verification and the ledger row.
///
/// A concurrent winner's identical rows converge in verification; a moved
/// destination fence stays unknown for exact readback.
async fn commit_destination_replay(
    dest: &RestoreDestinationTransport,
    plan: &ReplayPlan,
    candidates: &[&BackupMemberRow],
    fence: &StateFence,
    source_commit_sequence: u64,
    source_outbox_sequence: u64,
    operation_id: &str,
) -> Result<(u64, u64), AdapterError> {
    let next_commit_sequence = plan
        .fence_commit_sequence
        .max(source_commit_sequence)
        .saturating_add(1);
    let next_outbox_sequence = plan
        .fence_outbox_sequence
        .max(source_outbox_sequence)
        .saturating_add(1);
    let mut sql = String::from(schema::TX_BEGIN);
    sql.push_str(schema::TX_GUARD_FENCE);
    let mut bindings = Map::new();
    bindings.insert("expected_state_fence".to_owned(), json!(fence));
    bindings.insert(
        "expected_commit_sequence".to_owned(),
        json!(plan.fence_commit_sequence),
    );
    bindings.insert(
        "expected_outbox_sequence".to_owned(),
        json!(plan.fence_outbox_sequence),
    );
    bindings.insert(
        "backup_next_commit_sequence".to_owned(),
        json!(next_commit_sequence),
    );
    bindings.insert(
        "backup_next_outbox_sequence".to_owned(),
        json!(next_outbox_sequence),
    );
    bindings.insert(
        "backup_expected_commit_sequence".to_owned(),
        json!(plan.fence_commit_sequence),
    );
    bindings.insert(
        "backup_expected_outbox_sequence".to_owned(),
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
    sql.push_str(FENCE_BUMP_STATEMENT);
    sql.push_str(schema::TX_COMMIT);
    // The destination session is owned by this restore flow: no serving
    // lane is consumed and no serving session observes destination state.
    let mut response = dest.query_write("backup.restore", &sql, bindings).await?;
    let errors = response.take_errors();
    if errors.is_empty() {
        return Ok((next_commit_sequence, next_outbox_sequence));
    }
    if errors
        .iter()
        .any(|error| error.contains(FENCE_DRIFT_MARKER))
    {
        return Err(AdapterError::UnknownOutcome {
            operation_id: operation_id.to_owned(),
        });
    }
    // Any statement error resolves by re-reading the actual destination
    // slot state below: converged slots pass, divergent slots conflict,
    // and a moved fence stays unknown. Nothing is inferred from prose
    // here, so no error shape can smuggle a success claim.
    verify_replay_slots(
        dest,
        plan,
        candidates,
        operation_id,
        next_commit_sequence,
        next_outbox_sequence,
    )
    .await?;
    Ok((next_commit_sequence, next_outbox_sequence))
}

/// Verifies duplicate losers converged on identical content against the
/// destination. A moved destination fence stays unknown; real divergence
/// conflicts; anything else stays reconciling. The expected sequences are
/// the post-commit advances: verification proves the atomic transaction
/// above landed, not merely that the pre-commit guard once held.
async fn verify_replay_slots(
    dest: &RestoreDestinationTransport,
    plan: &ReplayPlan,
    candidates: &[&BackupMemberRow],
    operation_id: &str,
    expected_commit_sequence: u64,
    expected_outbox_sequence: u64,
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
    let mut response = dest.query("backup.restore", &sql, bindings).await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let fence = response
        .take::<Option<crate::apply::schema_contract::FenceRecord>>(1)?
        .ok_or(AdapterError::PartialOutcome)?;
    if fence.next_commit_sequence != expected_commit_sequence
        || fence.next_outbox_sequence != expected_outbox_sequence
    {
        return Err(AdapterError::UnknownOutcome {
            operation_id: operation_id.to_owned(),
        });
    }
    for (slot, position) in plan.create_indexes.iter().enumerate() {
        let member = candidates[*position];
        // Shape-explicit like classification: only a live object can
        // converge; error prose or anything else keeps the reconciling
        // disposition instead of a false convergence claim.
        let live = response.take::<Value>(2 + slot)?;
        match &live {
            Value::Object(_) => {
                if row_content_digest(&live)? != member.content_digest {
                    return Err(AdapterError::Store(StoreError::IdentityConflict));
                }
            }
            _ => return Err(AdapterError::PartialOutcome),
        }
    }
    Ok(())
}

/// Commits the restore coordination row to the live backup-operation
/// ledger after every replayed member verified against the destination.
/// This is bookkeeping, never canonical state: the row carries the
/// admitted identity, the repeated admission decision digest (R2), the
/// destination scope, and the completion receipt, but moves no live fence
/// sequence — restore spends destination sequences only. The unique
/// operation index arbitrates concurrent same-identity restores: a
/// concurrent winner's identical receipt replays; anything else stays a
/// conflict.
/// Inputs for the live restore ledger commit: admitted request, source
/// evidence, restored set, and destination post-commit sequences. Bundled
/// so the commit signature stays reviewable without an argument-count
/// escape.
struct RestoreLedgerCommit<'a> {
    db: &'a RpcTransport,
    config: &'a SurrealAdapterConfig,
    request: &'a StoreIsolatedRestoreRequest,
    source_receipt: &'a StoreBackupCompletionReceipt,
    candidates: &'a [&'a BackupMemberRow],
    dest_commit_sequence: u64,
    dest_outbox_sequence: u64,
    prose_pinned: bool,
}

async fn commit_restore_ledger(commit: RestoreLedgerCommit<'_>) -> Result<StoreBackupCompletionReceipt, AdapterError> {
    let RestoreLedgerCommit {
        db,
        config,
        request,
        source_receipt,
        candidates,
        dest_commit_sequence,
        dest_outbox_sequence,
        prose_pinned,
    } = commit;
    let receipt = build_restore_receipt(request, source_receipt, candidates)?;
    let receipt_json = serde_json::to_string(&receipt)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let scope_json = serde_json::to_string(&request.scope)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let mut bindings = Map::new();
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
            "frozen_commit_sequence": i64::try_from(dest_commit_sequence).unwrap_or(i64::MAX),
            "frozen_outbox_sequence": i64::try_from(dest_outbox_sequence).unwrap_or(i64::MAX),
            "frozen_heads_digest": "",
        }),
    );
    let mut sql = String::from(schema::TX_BEGIN);
    let _ = write!(
        sql,
        "CREATE {} CONTENT $backup_operation_record;",
        schema::table::BACKUP_OPERATION
    );
    sql.push_str(schema::TX_COMMIT);
    let mut response = db.query_write("backup.restore", &sql, bindings).await?;
    let errors = response.take_errors();
    if errors.is_empty() {
        return Ok(receipt);
    }
    // Coordination tables proved present by the source load above; any
    // error here keeps the reconciling disposition.
    if is_duplicate_operation(&errors, prose_pinned) {
        let existing = load_operation_row(
            db,
            config,
            "backup.restore",
            &request.identity.operation_id,
            prose_pinned,
        )
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
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "backup.member_table",
                reason: "frozen member names an unknown canonical table",
            }))?;
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
        revision_heads: source_receipt.revision_heads.clone(),
        ordering_heads: source_receipt.ordering_heads.clone(),
        partial: false,
        // R2: the committed receipt repeats the exact admitted decision
        // digest it executed under.
        admission_decision_digest: Some(
            request.admission.admission_decision_digest.clone(),
        ),
    };
    receipt.validate().map_err(AdapterError::Store)?;
    Ok(receipt)
}

/// Validates one captured snapshot without restoring it. The full frozen
/// denominator is recomputed exactly like completion — snapshot digest
/// plus cross-footed per-residency dispositions over the same frozen
/// evidence — and compared field by field: complete, known-empty,
/// unsupported, and conflict stay distinct, and unavailable validation
/// never returns success.
pub(crate) async fn backup_validate(
    adapter: &crate::SurrealStoreAdapter,
    request: StoreBackupValidationRequest,
) -> Result<StoreBackupValidationReceipt, AdapterError> {
    request.validate().map_err(AdapterError::Store)?;
    let db = super::client(adapter).await?;
    super::ensure_ready(adapter, db).await?;
    let prose_pinned = super::backup_snapshot::provider_prose_pinned(adapter);
    let operation = load_operation_row(
        db,
        &adapter.config,
        "backup.validate",
        &request.operation_id,
        prose_pinned,
    )
    .await?
    .ok_or(AdapterError::Store(StoreError::ReceiptNotFound))?;
    let (members, residencies) = super::backup_snapshot::load_frozen_denominator(
        db,
        &adapter.config,
        &operation,
        "backup.validate",
        prose_pinned,
    )
    .await?;
    let (checked, unresolved, outcome) =
        verify_frozen_set(&operation, &members, &residencies, &request)?;
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

/// Verifies the frozen set against the validation request with the same
/// recompute completion uses: snapshot digest over ordered member
/// digests, per-residency cross-foot against the stored dispositions, and
/// scope denominator pinned to the operation row. Zero unresolved on any
/// complete or known-empty claim.
fn verify_frozen_set(
    operation: &BackupOperationRow,
    members: &[BackupMemberRow],
    residencies: &[BackupResidencyRow],
    request: &StoreBackupValidationRequest,
) -> Result<(u64, u64, StoreBackupValidationOutcome), AdapterError> {
    let total = members.len() as u64;
    let scope = operation_scope(operation)?;
    if scope.residency_denominator_digest != expected_denominator_digest() {
        return Ok((0, total, StoreBackupValidationOutcome::Conflict));
    }
    let Ok((recomputed, _)) = super::backup_snapshot::recompute_denominator(members, residencies)
    else {
        return Ok((0, total, StoreBackupValidationOutcome::Conflict));
    };
    if recomputed != request.snapshot_digest {
        return Ok((0, total, StoreBackupValidationOutcome::Conflict));
    }
    if let Some(stored) = operation.snapshot_digest.as_deref()
        && stored != request.snapshot_digest
    {
        return Ok((0, total, StoreBackupValidationOutcome::Conflict));
    }
    if members.is_empty() {
        return Ok((0, 0, StoreBackupValidationOutcome::KnownEmpty));
    }
    Ok((total, 0, StoreBackupValidationOutcome::Complete))
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
    let prose_pinned = super::backup_snapshot::provider_prose_pinned(adapter);
    let operation = load_operation_row(
        db,
        &adapter.config,
        "backup.status",
        &request.operation_id,
        prose_pinned,
    )
    .await?;
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
    let prose_pinned = super::backup_snapshot::provider_prose_pinned(adapter);
    let operation = load_operation_row(
        db,
        &adapter.config,
        "backup.reconcile",
        &request.operation_id,
        prose_pinned,
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

/// Admitted isolated restore destination record (issues #952/#975 R1).
///
/// Exactly one row per destination database, written once by explicit
/// deployment provisioning. Restoring into a database without this record
/// is unprovisioned and refuses; restoring into a serving-marked database
/// refuses because only separate cutover authority may change serving
/// state, never the restore path.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreDestinationRecord {
    dest_store_id: String,
    dest_installation_id: String,
    state_fence: StateFence,
    serving: bool,
    cutover_authority: String,
}

/// Probes the destination schema generation. An absent schema means an
/// unprovisioned destination and refuses with `MigrationRequired`; any
/// other error class keeps the reconciling disposition.
async fn probe_destination_schema(
    dest: &RestoreDestinationTransport,
    prose_pinned: bool,
) -> Result<Option<super::schema_contract::SchemaMetaRecord>, AdapterError> {
    let mut response = dest
        .query("read.schema_generation", schema::READ_SCHEMA_META, Map::new())
        .await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        if prose_pinned
            && errors
                .iter()
                .all(|error| client::is_absent_table(error))
        {
            return Ok(None);
        }
        return Err(AdapterError::PartialOutcome);
    }
    match response.take::<Option<super::schema_contract::SchemaMetaRecord>>(0) {
        Ok(record) => Ok(record),
        Err(AdapterError::Serialization(_)) => Err(AdapterError::PartialOutcome),
        Err(error) => Err(error),
    }
}

/// Reads the destination fence and pins it to the admitted fence. The
/// destination shares the admitted state fence with the serving store;
/// its sequences are its own and advance only through restores into it.
async fn read_destination_fence(
    dest: &RestoreDestinationTransport,
    config: &SurrealAdapterConfig,
    expected: &StateFence,
    prose_pinned: bool,
) -> Result<super::schema_contract::FenceRecord, AdapterError> {
    match probe_destination_schema(dest, prose_pinned).await? {
        Some(record) => {
            super::schema_contract::validate_schema_meta_record(&record)?;
            if record.migration_state != "APPLIED"
                || record.generation != config.expected_schema_generation.as_str()
            {
                return Err(AdapterError::MigrationRequired);
            }
        }
        None => return Err(AdapterError::MigrationRequired),
    }
    let mut response = dest
        .query("read.canonical_fence", schema::READ_FENCE, Map::new())
        .await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let fence = match response.take::<Option<super::schema_contract::FenceRecord>>(0) {
        Ok(fence) => fence,
        Err(AdapterError::Serialization(_)) => return Err(AdapterError::PartialOutcome),
        Err(error) => return Err(error),
    }
    .ok_or(AdapterError::MigrationRequired)?;
    super::schema_contract::validate_fence_record(&fence)?;
    if fence.state_fence != *expected {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    Ok(fence)
}

/// Loads the destination admission record. Absent tables or a missing row
/// mean the destination was never provisioned and refuse with
/// `MigrationRequired` instead of restoring into an unowned database.
async fn load_destination_record(
    dest: &RestoreDestinationTransport,
    prose_pinned: bool,
) -> Result<RestoreDestinationRecord, AdapterError> {
    let mut response = dest
        .query(
            "backup.restore",
            "SELECT * FROM ONLY type::record($destination_table, $destination_key);",
            {
                let mut bindings = Map::new();
                bindings.insert(
                    "destination_table".to_owned(),
                    json!(schema::table::RESTORE_DESTINATION),
                );
                bindings.insert(
                    "destination_key".to_owned(),
                    json!(schema::RESTORE_DESTINATION_KEY),
                );
                bindings
            },
        )
        .await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        if prose_pinned
            && errors.iter().all(|error| {
                super::backup_snapshot::is_absent_table_pinned(
                    error,
                    schema::table::RESTORE_DESTINATION,
                    prose_pinned,
                )
            })
        {
            return Err(AdapterError::MigrationRequired);
        }
        return Err(AdapterError::PartialOutcome);
    }
    match response.take::<Option<RestoreDestinationRecord>>(0) {
        Ok(record) => record.ok_or(AdapterError::MigrationRequired),
        Err(AdapterError::Serialization(_)) => Err(AdapterError::PartialOutcome),
        Err(error) => Err(error),
    }
}

/// Verifies the destination admission record against the admitted restore:
/// exact destination installation/store identity, the shared fence, a
/// named separate cutover authority, and fenced (non-serving) state. A
/// serving-marked destination refuses: cutover is separate authority, and
/// the restore path can never activate a destination, unblock effects, or
/// retire the source.
async fn verify_destination_record(
    dest: &RestoreDestinationTransport,
    request: &StoreIsolatedRestoreRequest,
    prose_pinned: bool,
) -> Result<(), AdapterError> {
    // The transport itself is bound to the admitted destination database;
    // the record below must agree with both the transport and the request.
    if dest.database() != request.scope.dest_store_id {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.destination",
            reason: "destination transport is not bound to the admitted destination",
        }));
    }
    let record = load_destination_record(dest, prose_pinned).await?;
    if record.dest_store_id != request.scope.dest_store_id
        || record.dest_installation_id != request.scope.dest_installation_id
    {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.destination",
            reason: "destination admission does not name the admitted destination",
        }));
    }
    // F1 destination anchor: the presented admission must name the exact
    // deployment-provisioned destination the caller cannot provision —
    // bound here directly, not only transitively through the scope.
    if request.admission.dest_store_id != record.dest_store_id
        || request.admission.dest_installation_id != record.dest_installation_id
        || request.admission.state_fence != record.state_fence
    {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.destination",
            reason: "presented admission does not name the provisioned destination",
        }));
    }
    if record.state_fence != request.scope.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    if record.cutover_authority.trim().is_empty()
        || record.cutover_authority.chars().any(char::is_control)
    {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.cutover_authority",
            reason: "destination names no separate cutover authority",
        }));
    }
    if record.serving {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.destination",
            reason: "destination is serving; cutover requires separate authority",
        }));
    }
    Ok(())
}

// Cutover handoff (issues #952/#975, I5.13, A13.7).
//
// This lane never activates a destination, unblocks effects, or retires
// the source: cutover requires the separate owner authorization, whose
// canonical file-level algorithm lives with the `eliot-backup` owner
// (issue #1873: `IsolatedRestorePlan` + `CutoverAuthorization` +
// `authorize_cutover`, purge-first ordering, suspended recovery, fresh
// lineage at cutover). The store edge mirrors that discipline at the
// canonical-row level — isolated destination, purge suppression,
// suspended (never runnable) outbox evidence, no session/lease/epoch
// revival, serving refusal above — and hands activation to the
// coordinated cutover owner (#961) presenting plan-bound, bundle-bound
// authorization. The `cutover_authority` recorded here names the owner
// whose grant the coordinator must present; this lane mints no grant
// and accepts no activation through any of its paths.

/// Provisions one isolated restore destination database (issues #952/#975
/// R1).
///
/// Explicit deployment-owner entrypoint, never implicit: it connects the
/// dedicated destination session on the same provider generation, then
/// either provisions an empty destination (admitted v2 baseline, the
/// owner-approved domain tables, shared fence at genesis sequences,
/// fenced non-serving admission record) in one atomic transaction, or
/// verifies an already-provisioned destination, creates a missing
/// admission record under the fence guard, and brings wholly-absent
/// domain blocks to the full table set. Identity mismatch replays;
/// anything else conflicts. The serving database can never be
/// provisioned as a destination. Domain tables apply verbatim from the
/// schema owners' additive DDL consts (erasure #1712, notification #1780,
/// reactive #1941 C4, automation #1779) without reinterpreting their
/// semantics; automation failure tables have no owner DDL anywhere
/// in-tree and stay fail-closed per member until the #1779 owner
/// provides it.
pub(crate) async fn provision_restore_destination(
    adapter: &crate::SurrealStoreAdapter,
    dest_store_id: &str,
    dest_installation_id: &str,
    state_fence: &StateFence,
    cutover_authority: &str,
    observed_clock: &ClockObservation,
) -> Result<(), AdapterError> {
    if dest_store_id.trim().is_empty() || dest_store_id.chars().any(char::is_control) {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.destination",
            reason: "restore destination database name is not admitted",
        }));
    }
    if dest_store_id == adapter.config.database {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.destination",
            reason: "the serving store can never be provisioned as a restore destination",
        }));
    }
    if dest_installation_id.trim().is_empty()
        || dest_installation_id.chars().any(char::is_control)
    {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.dest_installation_id",
            reason: "restore destination installation is not admitted",
        }));
    }
    if cutover_authority.trim().is_empty() || cutover_authority.chars().any(char::is_control) {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.cutover_authority",
            reason: "restore destination requires a named separate cutover authority",
        }));
    }
    state_fence.validate().map_err(StoreError::Foundation)?;
    // Domain tables are applied verbatim from the owner-approved additive
    // DDL below; a non-additive domain body refuses before any provider
    // I/O, mirroring the migration handlers' destructive-statement guard.
    for ddl in [
        schema::ERASURE_TABLES_DDL,
        schema::NOTIFICATION_TABLES_DDL,
        schema::REACTIVE_TABLES_DDL,
        schema::AUTOMATION_TABLES_DDL,
    ] {
        let lowered = ddl.trim().to_ascii_lowercase();
        if lowered.contains("drop ")
            || lowered.contains("delete ")
            || lowered.contains("remove ")
        {
            return Err(AdapterError::Config(
                "destination domain DDL is not additive".to_owned(),
            ));
        }
    }
    let db = super::client(adapter).await?;
    super::ensure_ready(adapter, db).await?;
    let prose_pinned = super::backup_snapshot::provider_prose_pinned(adapter);
    let dest =
        client::connect_restore_destination(db.provider(), &adapter.config, dest_store_id).await?;
    observed_clock
        .validate()
        .map_err(|error| AdapterError::Config(error.to_string()))?;
    let updated_at = observed_clock
        .known_time_ms
        .or(observed_clock.valid_time_ms)
        .ok_or_else(|| {
            AdapterError::Config(
                "destination provisioning requires an observed P-01 wall-clock timestamp".to_owned(),
            )
        })?
        .to_string();
    let migration = CompiledMigration::new(
        schema::MIGRATION_ID_V2,
        schema::SCHEMA_DDL_V2,
        adapter.config.expected_schema_generation.clone(),
    );
    migration
        .validate()
        .map_err(|reason| AdapterError::Config(reason.to_owned()))?;
    if !super::is_admitted_migration(&migration) {
        return Err(AdapterError::Config(
            "destination baseline is not admitted by the S-03 schema compiler".to_owned(),
        ));
    }
    match probe_destination_schema(&dest, prose_pinned).await? {
        None => provision_empty_destination(EmptyDestinationProvision {
            dest: &dest,
            config: &adapter.config,
            migration: &migration,
            updated_at: &updated_at,
            dest_store_id,
            dest_installation_id,
            state_fence,
            cutover_authority,
            prose_pinned,
        })
        .await,
        Some(record) => {
            super::schema_contract::validate_schema_meta_record(&record)?;
            if record.generation != adapter.config.expected_schema_generation.as_str()
                || record.migration_state != "APPLIED"
            {
                return Err(AdapterError::MigrationRequired);
            }
            let fence =
                read_destination_fence(&dest, &adapter.config, state_fence, prose_pinned).await?;
            ensure_destination_record(
                &dest,
                &fence,
                dest_store_id,
                dest_installation_id,
                state_fence,
                cutover_authority,
                prose_pinned,
            )
            .await?;
            // A destination provisioned before domain tables were covered
            // is brought to the full table set without touching rows:
            // wholly-absent blocks apply atomically, partial blocks
            // refuse for deployment reconciliation.
            ensure_domain_tables(&dest, prose_pinned).await
        }
    }
}

/// Provisions an empty destination database in one atomic transaction:
/// the admitted v2 baseline, the destination admission DDL, the shared
/// fence at genesis sequences, the schema-meta record, and the fenced
/// non-serving destination admission record. A concurrent provisioner
/// wins exactly once; the loser verifies the winner's identical result.
/// Inputs for empty-destination provisioning: destination transport and
/// config, the admitted baseline migration, the observed clock stamp, and
/// the admitted destination identity. Bundled so the provisioning
/// signature stays reviewable without an argument-count escape.
struct EmptyDestinationProvision<'a> {
    dest: &'a RestoreDestinationTransport,
    config: &'a SurrealAdapterConfig,
    migration: &'a CompiledMigration,
    updated_at: &'a str,
    dest_store_id: &'a str,
    dest_installation_id: &'a str,
    state_fence: &'a StateFence,
    cutover_authority: &'a str,
    prose_pinned: bool,
}

/// Builds the bindings for empty-destination provisioning: the schema-meta
/// record for the admitted baseline, the shared fence at genesis
/// sequences, and the fenced non-serving destination admission record.
fn provision_empty_bindings(
    provision: &EmptyDestinationProvision<'_>,
    updated_at: &str,
    migration: &CompiledMigration,
) -> Map<String, Value> {
    let record = super::schema_contract::schema_meta_record(migration, updated_at);
    let mut bindings = Map::new();
    bindings.insert(
        "schema_meta_table".to_owned(),
        json!(schema::table::SCHEMA_META),
    );
    bindings.insert("schema_meta_key".to_owned(), json!(schema::SCHEMA_META_KEY));
    bindings.insert("schema_meta_record".to_owned(), json!(record));
    bindings.insert(
        "fence_table".to_owned(),
        json!(schema::table::CANONICAL_FENCE),
    );
    bindings.insert("fence_key".to_owned(), json!(schema::FENCE_KEY));
    bindings.insert(
        "fence".to_owned(),
        json!({
            "state_fence": provision.state_fence,
            "next_commit_sequence": 1_u64,
            "next_outbox_sequence": 1_u64,
        }),
    );
    bindings.insert(
        "destination_table".to_owned(),
        json!(schema::table::RESTORE_DESTINATION),
    );
    bindings.insert(
        "destination_key".to_owned(),
        json!(schema::RESTORE_DESTINATION_KEY),
    );
    bindings.insert(
        "destination_record".to_owned(),
        json!({
            "dest_store_id": provision.dest_store_id,
            "dest_installation_id": provision.dest_installation_id,
            "state_fence": provision.state_fence,
            "serving": false,
            "cutover_authority": provision.cutover_authority,
        }),
    );
    bindings
}

async fn provision_empty_destination(
    provision: EmptyDestinationProvision<'_>,
) -> Result<(), AdapterError> {
    let EmptyDestinationProvision {
        dest,
        config,
        migration,
        updated_at,
        dest_store_id,
        dest_installation_id,
        state_fence,
        cutover_authority,
        prose_pinned,
    } = provision;
    let bindings = provision_empty_bindings(&provision, updated_at, migration);
    let mut sql = String::from(schema::TX_BEGIN);
    sql.push_str(schema::SCHEMA_DDL_V2.trim());
    sql.push(' ');
    sql.push_str(schema::RESTORE_DESTINATION_DDL.trim());
    sql.push(' ');
    // Destination-domain tables applied verbatim from the owner-approved
    // additive DDL (erasure #1712, notification #1780, reactive #1941 C4,
    // automation #1779): the destination becomes a superset of every
    // provisionable live table, so restores never meet a missing domain
    // table the source capture contains. Automation failure tables have
    // no owner DDL and stay fail-closed per member.
    sql.push_str(schema::ERASURE_TABLES_DDL.trim());
    sql.push(' ');
    sql.push_str(schema::NOTIFICATION_TABLES_DDL.trim());
    sql.push(' ');
    sql.push_str(schema::REACTIVE_TABLES_DDL.trim());
    sql.push(' ');
    sql.push_str(schema::AUTOMATION_TABLES_DDL.trim());
    sql.push(' ');
    sql.push_str(schema::TX_CREATE_FENCE);
    sql.push(' ');
    sql.push_str(schema::TX_CREATE_SCHEMA_META);
    sql.push(' ');
    let _ = write!(
        sql,
        "CREATE type::record($destination_table, $destination_key) CONTENT $destination_record;"
    );
    sql.push(' ');
    sql.push_str(schema::TX_COMMIT);
    let mut response = dest.query_write("backup.restore", &sql, bindings).await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        return Err(AdapterError::UnknownMigrationOutcome {
            migration_id: migration.migration_id.clone(),
        });
    }
    // Verify the winner's result: exact baseline identity, shared fence
    // at genesis sequences, identical destination record. Verification
    // threads the real prose-pin flag (F4): on an unpinned provider an
    // absent table stays a fail-closed PartialOutcome, never a
    // misclassified success.
    let schema = probe_destination_schema(dest, prose_pinned)
        .await?
        .ok_or(AdapterError::PartialOutcome)?;
    if schema.migration_id != migration.migration_id
        || schema.migration_checksum_sha256 != migration.checksum_sha256
        || schema.generation != migration.generation_after.as_str()
        || schema.migration_state != "APPLIED"
    {
        return Err(AdapterError::PartialOutcome);
    }
    let fence = read_destination_fence(dest, config, state_fence, prose_pinned)
        .await
        .map_err(|_| AdapterError::PartialOutcome)?;
    if fence.next_commit_sequence != 1 || fence.next_outbox_sequence != 1 {
        return Err(AdapterError::PartialOutcome);
    }
    let record = load_destination_record(dest, prose_pinned)
        .await
        .map_err(|_| AdapterError::PartialOutcome)?;
    if record.dest_store_id != dest_store_id
        || record.dest_installation_id != dest_installation_id
        || record.state_fence != *state_fence
        || record.serving
        || record.cutover_authority != cutover_authority
    {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}

/// Creates a missing destination admission record under the destination
/// fence guard on an already-provisioned destination. An identical
/// existing record replays; anything else conflicts.
async fn ensure_destination_record(
    dest: &RestoreDestinationTransport,
    fence: &super::schema_contract::FenceRecord,
    dest_store_id: &str,
    dest_installation_id: &str,
    state_fence: &StateFence,
    cutover_authority: &str,
    prose_pinned: bool,
) -> Result<(), AdapterError> {
    match load_destination_record(dest, prose_pinned).await {
        Ok(record) => {
            if record.dest_store_id != dest_store_id
                || record.dest_installation_id != dest_installation_id
                || record.state_fence != *state_fence
                || record.serving
                || record.cutover_authority != cutover_authority
            {
                return Err(AdapterError::Store(StoreError::IdentityConflict));
            }
            return Ok(());
        }
        Err(AdapterError::MigrationRequired) => {}
        Err(error) => return Err(error),
    }
    let mut bindings = Map::new();
    bindings.insert("expected_state_fence".to_owned(), json!(state_fence));
    bindings.insert(
        "expected_commit_sequence".to_owned(),
        json!(fence.next_commit_sequence),
    );
    bindings.insert(
        "expected_outbox_sequence".to_owned(),
        json!(fence.next_outbox_sequence),
    );
    bindings.insert(
        "destination_table".to_owned(),
        json!(schema::table::RESTORE_DESTINATION),
    );
    bindings.insert(
        "destination_key".to_owned(),
        json!(schema::RESTORE_DESTINATION_KEY),
    );
    bindings.insert(
        "destination_record".to_owned(),
        json!({
            "dest_store_id": dest_store_id,
            "dest_installation_id": dest_installation_id,
            "state_fence": state_fence,
            "serving": false,
            "cutover_authority": cutover_authority,
        }),
    );
    let mut sql = String::from(schema::TX_BEGIN);
    sql.push_str(schema::TX_GUARD_FENCE);
    sql.push(' ');
    let _ = write!(
        sql,
        "CREATE type::record($destination_table, $destination_key) CONTENT $destination_record;"
    );
    sql.push(' ');
    sql.push_str(schema::TX_COMMIT);
    let mut response = dest.query_write("backup.restore", &sql, bindings).await?;
    let errors = response.take_errors();
    if errors.is_empty() {
        return Ok(());
    }
    // A concurrent provisioner created the record first: the winner's
    // identical record replays, anything else conflicts.
    match load_destination_record(dest, prose_pinned).await {
        Ok(record) => {
            if record.dest_store_id != dest_store_id
                || record.dest_installation_id != dest_installation_id
                || record.state_fence != *state_fence
                || record.serving
                || record.cutover_authority != cutover_authority
            {
                return Err(AdapterError::Store(StoreError::IdentityConflict));
            }
            Ok(())
        }
        Err(_) => Err(AdapterError::PartialOutcome),
    }
}

/// Ensures the destination-domain tables on an already-provisioned
/// destination without touching rows.
///
/// Each owner block (erasure, notification, reactive, automation) is
/// probed table by table: a wholly-absent block applies atomically from
/// the owner-approved additive DDL, a complete block is left alone, and a
/// partially-applied block refuses with `MigrationRequired` so deployment
/// reconciles it explicitly instead of the restore path guessing.
/// Automation failure tables have no owner DDL and are never invented
/// here; members naming them stay fail-closed per member at classify
/// time.
async fn ensure_domain_tables(
    dest: &RestoreDestinationTransport,
    prose_pinned: bool,
) -> Result<(), AdapterError> {
    ensure_domain_block(
        dest,
        &[schema::table::ERASURE_INTENT, schema::table::ERASURE_OUTCOME],
        schema::ERASURE_TABLES_DDL,
        prose_pinned,
    )
    .await?;
    ensure_domain_block(
        dest,
        &[schema::table::NOTIFICATION_RECORD],
        schema::NOTIFICATION_TABLES_DDL,
        prose_pinned,
    )
    .await?;
    ensure_domain_block(
        dest,
        &[
            schema::table::REACTIVE_SESSION,
            schema::table::RESOURCE_SNAPSHOT,
        ],
        schema::REACTIVE_TABLES_DDL,
        prose_pinned,
    )
    .await?;
    ensure_domain_block(
        dest,
        &[
            schema::table::AUTOMATION_REVISION,
            schema::table::AUTOMATION_CURRENT,
            schema::table::AUTOMATION_INVOCATION,
        ],
        schema::AUTOMATION_TABLES_DDL,
        prose_pinned,
    )
    .await
}

/// Probes one destination table: present (even when empty) or absent. An
/// unprovisioned table refuses nothing by itself here — the caller
/// decides per block. Any other error class keeps the reconciling
/// disposition.
async fn probe_destination_table(
    dest: &RestoreDestinationTransport,
    table: &str,
    prose_pinned: bool,
) -> Result<bool, AdapterError> {
    // Table names are closed crate constants at every call site, mirroring
    // the established capture-query pattern; the statement carries no
    // caller content.
    let mut response = dest
        .query(
            "backup.restore",
            &format!("SELECT VALUE id FROM {table} LIMIT 1;"),
            Map::new(),
        )
        .await?;
    let errors = response.take_errors();
    if errors.is_empty() {
        return Ok(true);
    }
    if prose_pinned
        && errors.iter().all(|error| {
            super::backup_snapshot::is_absent_table_pinned(error, table, prose_pinned)
        })
    {
        return Ok(false);
    }
    Err(AdapterError::PartialOutcome)
}

/// Applies one wholly-absent owner block atomically, or leaves a
/// complete block alone. Partial application refuses: the block's tables
/// are always written together, so a partial set means out-of-band
/// interference the restore path must not paper over.
async fn ensure_domain_block(
    dest: &RestoreDestinationTransport,
    tables: &[&str],
    ddl: &str,
    prose_pinned: bool,
) -> Result<(), AdapterError> {
    let mut absent = 0_usize;
    for table in tables {
        if !probe_destination_table(dest, table, prose_pinned).await? {
            absent += 1;
        }
    }
    if absent == 0 {
        return Ok(());
    }
    if absent != tables.len() {
        return Err(AdapterError::MigrationRequired);
    }
    let mut sql = String::from(schema::TX_BEGIN);
    sql.push_str(ddl.trim());
    sql.push(' ');
    sql.push_str(schema::TX_COMMIT);
    let mut response = dest
        .query_write("backup.restore", &sql, Map::new())
        .await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}

/// Provider marker for destination authority-rotation CAS drift.
const ROTATE_CONFLICT_MARKER: &str = "backup_destination_rotate_conflict";

/// Rotates one destination's cutover authority under compare-and-set
/// (issues #952/#975 F5).
///
/// Owner-controlled transition without out-of-band bypass: the durable
/// record must exist with matching destination identity and the shared
/// fence, and must be non-serving — a serving destination's authority
/// rotates only through the coordinated cutover owner (#961), never here.
/// The record must currently carry exactly `expected_cutover_authority`;
/// only the authority field changes, so destination identity, fence, and
/// especially the serving flag are immutable in this statement. A fence
/// change is never rotated in place: provisioning a fresh destination is
/// the only fence-change path. An identical rotation replays; a
/// concurrent winner's identical record replays; anything else conflicts.
pub(crate) async fn rotate_restore_destination_authority(
    adapter: &crate::SurrealStoreAdapter,
    dest_store_id: &str,
    expected_cutover_authority: &str,
    new_cutover_authority: &str,
    state_fence: &StateFence,
) -> Result<(), AdapterError> {
    if dest_store_id.trim().is_empty() || dest_store_id.chars().any(char::is_control) {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.destination",
            reason: "restore destination database name is not admitted",
        }));
    }
    if dest_store_id == adapter.config.database {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.destination",
            reason: "the serving store has no restore destination record",
        }));
    }
    for (value, field) in [
        (expected_cutover_authority, "backup.expected_cutover_authority"),
        (new_cutover_authority, "backup.cutover_authority"),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field,
                reason: "cutover authority rotation carries no blank identity",
            }));
        }
    }
    state_fence.validate().map_err(StoreError::Foundation)?;
    let db = super::client(adapter).await?;
    super::ensure_ready(adapter, db).await?;
    let prose_pinned = super::backup_snapshot::provider_prose_pinned(adapter);
    let dest =
        client::connect_restore_destination(db.provider(), &adapter.config, dest_store_id).await?;
    read_destination_fence(&dest, &adapter.config, state_fence, prose_pinned).await?;
    let record = load_destination_record(&dest, prose_pinned).await?;
    if record.serving {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.destination",
            reason: "a serving destination rotates only through the cutover owner",
        }));
    }
    if record.state_fence != *state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    if record.cutover_authority != expected_cutover_authority {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    if expected_cutover_authority == new_cutover_authority {
        return Ok(());
    }
    let mut bindings = Map::new();
    bindings.insert("expected_state_fence".to_owned(), json!(state_fence));
    let fence = read_destination_fence(&dest, &adapter.config, state_fence, prose_pinned).await?;
    bindings.insert(
        "expected_commit_sequence".to_owned(),
        json!(fence.next_commit_sequence),
    );
    bindings.insert(
        "expected_outbox_sequence".to_owned(),
        json!(fence.next_outbox_sequence),
    );
    bindings.insert(
        "destination_table".to_owned(),
        json!(schema::table::RESTORE_DESTINATION),
    );
    bindings.insert(
        "destination_key".to_owned(),
        json!(schema::RESTORE_DESTINATION_KEY),
    );
    bindings.insert(
        "destination_expected_authority".to_owned(),
        json!(expected_cutover_authority),
    );
    bindings.insert(
        "destination_new_authority".to_owned(),
        json!(new_cutover_authority),
    );
    let mut sql = String::from(schema::TX_BEGIN);
    sql.push_str(schema::TX_GUARD_FENCE);
    sql.push(' ');
    sql.push_str(
        "LET $backup_rotate = (UPDATE type::record($destination_table, $destination_key) SET cutover_authority = $destination_new_authority WHERE cutover_authority == $destination_expected_authority AND serving == false RETURN AFTER); IF array::len($backup_rotate ?? []) != 1 { THROW 'backup_destination_rotate_conflict'; };",
    );
    sql.push(' ');
    sql.push_str(schema::TX_COMMIT);
    let mut response = dest.query_write("backup.restore", &sql, bindings).await?;
    let errors = response.take_errors();
    if errors.is_empty() {
        return verify_rotated_record(
            &dest,
            dest_store_id,
            state_fence,
            new_cutover_authority,
            prose_pinned,
        )
        .await;
    }
    if errors
        .iter()
        .any(|error| error.contains(ROTATE_CONFLICT_MARKER))
    {
        // A concurrent winner's identical record replays; anything else
        // conflicts instead of reporting a rotation that did not happen.
        return match load_destination_record(&dest, prose_pinned).await {
            Ok(current)
                if current.cutover_authority == new_cutover_authority
                    && !current.serving
                    && current.state_fence == *state_fence =>
            {
                Ok(())
            }
            Ok(_) => Err(AdapterError::Store(StoreError::IdentityConflict)),
            Err(_) => Err(AdapterError::PartialOutcome),
        };
    }
    Err(AdapterError::PartialOutcome)
}

/// Verifies the rotated destination record: new authority present,
/// still non-serving, identity and fence otherwise unchanged.
async fn verify_rotated_record(
    dest: &RestoreDestinationTransport,
    dest_store_id: &str,
    state_fence: &StateFence,
    new_cutover_authority: &str,
    prose_pinned: bool,
) -> Result<(), AdapterError> {
    let record = load_destination_record(dest, prose_pinned)
        .await
        .map_err(|_| AdapterError::PartialOutcome)?;
    if record.dest_store_id != dest_store_id
        || record.state_fence != *state_fence
        || record.serving
        || record.cutover_authority != new_cutover_authority
    {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}

/// Verifies restored records stayed connected to the destination heads
/// (issues #952/#975).
///
/// Destination-scoped readback check: every revision scope and ordering
/// scope named by the restore receipt must read back covered by the
/// destination heads under the receipt fence. A scope behind its restored
/// revision, a foreign fence, or a missing head refuses with
/// `InvalidProjection`. This check verifies coverage after the fact; it
/// is not the rebuild path — derived rows are admitted only through the
/// projection owner's [`crate::plan::admit_frozen_derived_replay`] gate
/// before any write.
pub(crate) async fn read_restore_destination_heads(
    adapter: &crate::SurrealStoreAdapter,
    dest_store_id: &str,
    receipt: &StoreBackupCompletionReceipt,
) -> Result<(), AdapterError> {
    receipt.validate().map_err(AdapterError::Store)?;
    if dest_store_id == adapter.config.database {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "backup.destination",
            reason: "destination head verification must not read serving heads",
        }));
    }
    let db = super::client(adapter).await?;
    super::ensure_ready(adapter, db).await?;
    let dest =
        client::connect_restore_destination(db.provider(), &adapter.config, dest_store_id).await?;
    for head in &receipt.revision_heads {
        head.validate().map_err(AdapterError::Store)?;
        let mut bindings = Map::new();
        bindings.insert("head_key".to_owned(), json!(head.key.to_string()));
        let mut response = dest
            .query(
                "backup.restore",
                "SELECT VALUE body FROM revision_head WHERE revision_key = $head_key;",
                bindings,
            )
            .await?;
        if !response.take_errors().is_empty() {
            return Err(AdapterError::PartialOutcome);
        }
        let heads = response.take::<Vec<RevisionHead>>(0)?;
        let Some(current) = heads.first() else {
            return Err(AdapterError::Store(StoreError::InvalidProjection));
        };
        if current.state_fence != receipt.state_fence || current.revision < head.revision {
            return Err(AdapterError::Store(StoreError::InvalidProjection));
        }
    }
    for head in &receipt.ordering_heads {
        head.validate().map_err(AdapterError::Store)?;
        let mut bindings = Map::new();
        bindings.insert("head_scope".to_owned(), json!(head.scope.to_string()));
        let mut response = dest
            .query(
                "backup.restore",
                "SELECT VALUE body FROM ordering_head WHERE ordering_scope = $head_scope;",
                bindings,
            )
            .await?;
        if !response.take_errors().is_empty() {
            return Err(AdapterError::PartialOutcome);
        }
        let heads = response.take::<Vec<OrderingHead>>(0)?;
        let Some(current) = heads.first() else {
            return Err(AdapterError::Store(StoreError::InvalidProjection));
        };
        if current.state_fence != receipt.state_fence || current.sequence < head.sequence {
            return Err(AdapterError::Store(StoreError::InvalidProjection));
        }
    }
    Ok(())
}
