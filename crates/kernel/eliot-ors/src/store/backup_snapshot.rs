//! Quarantined backup-snapshot store projection (issue #953, writer B).
//!
//! ORS-owned backup export reads and quarantined backup import triage. This
//! module never activates authority, never advances canonical ordering, never
//! copies a live `redb` file, never touches the filesystem, and never emits raw
//! payload bytes: export carries digests plus identity metadata, and import
//! returns per-entry outcomes without writing any authority table.
//!
//! Invariants (I05-13 / I05-16 / I05-22 / I05-27 / I14-21 / I07-20):
//! - The whole capture runs inside ONE long-lived `redb` read transaction, so
//!   the fence, the order sequence, the schema marker, and the authority
//!   generation are established once and every page of the capture is the same
//!   consistent point. There is no per-page transaction boundary inside a
//!   capture, and the point is re-verified at close.
//! - Source identity, generation, schema, canonical dependency fence, and
//!   high-water are compared against owner-established values read from durable
//!   state, never accepted from the caller's token.
//! - Every declared ORS row family is read or given an explicit source-bound
//!   `OutsideAdmittedGeneration` exclusion. A table observed in the store with
//!   no declared disposition fails closed instead of disappearing from the
//!   denominator. A declared table the admitted generation creates on first
//!   write is never opened when it is absent: opening an undefined table inside
//!   one read consistency point fails the whole capture, so the #951 provider
//!   hazard is handled by an explicit disposition, not by a silent read and not
//!   by a silent omission.
//! - Every restored item imports as `suspended_recovery`, never runnable
//!   authority; old sessions, leases, routes, and grants are never activated.
//! - Import consumes the current canonical evidence provider. A caller boolean
//!   and a non-empty admission string never admit an import on their own.
//! - Unknown items stay quarantined; there is no blind retry and no durable
//!   write in the triage path. Durable quarantine belongs to the existing
//!   canonical reconciliation owner via `import_recovery_inbox`, not here.
//! - Disposition failures use stable [`crate::OrsError`] variants, and every
//!   per-entry outcome carries a typed closed reason and stable reason code.
//!
//! Writer-A API (crate root `backup_snapshot`, read here as evidence): the
//! frozen census is `row_family_census()`; `page_fence_token(source, fence,
//! after_order) -> String` is the single capture-token derivation shared by
//! export, validation, and import; `BackupCapturePoint::binding_digest(...)`
//! binds the observed state; `OrsBackupSnapshot::validate` and
//! `validate_members` are the real completeness gates;
//! `PerEntryOutcome::{Imported, Rejected, Forensic, Blocked, Unresolved}` carry
//! typed reasons; `OrsBackupImportReceipt::new` and
//! `known_zero_unresolved(&CurrentOwnerValidation)` are the zero-unresolved
//! gate; `validate_import_binding` rejects same-installation or unbound-evidence
//! imports; and `check_canonical_frozen(pre, post)` rejects any head advance
//! across the window. `PerEntryOutcome::Imported` is intentionally never
//! constructed here: nothing is imported by triage; durable import belongs to
//! the canonical owner.
//!
//! Deliberate ORS boundary: ORS owns no key material and no detached signature
//! for the opaque records it stages, so an exported entry whose cryptographic
//! identity ORS cannot observe carries no signature digest. Import therefore
//! keeps that entry `Blocked` with a typed unknown-crypto reason instead of
//! passing a digest-shape check. ORS also owns no purge ledger, so the
//! destination's admitted purge-ledger revision is bound into the quarantine
//! admission envelope the canonical evidence provider authenticates, rather
//! than being re-derived from ORS state.

use std::collections::BTreeSet;
use std::sync::Arc;

use eliot_contracts::ResourceGeneration;
use eliot_platform::PlatformHandle;
use eliot_receipts::GrantClosureState;
use eliot_security_contracts::PrivacyClass;
use redb::{
    Database, ReadTransaction, ReadableDatabase, ReadableTable, TableDefinition, TableHandle,
};

use super::persistence_codec::{decode_named, encode};
use super::persistence_models::{
    DurableGrantClosureRecord, DurableInboxRecord, DurableOperationalRecord, OperationalKind,
    ScopeReservationHead,
};
use super::storage;
use crate::backup_snapshot::{
    BACKUP_SNAPSHOT_SCHEMA_VERSION, BackupBlockReason, BackupCapturePoint, BackupCompleteness,
    BackupEntryAvailability, BackupEntryCryptoIdentity, BackupEntryLineage, BackupForensicReason,
    BackupGenerationLineage, BackupPageFamilyCount, BackupRejectReason, BackupUnresolvedReason,
    CurrentOwnerValidation, MAX_BACKUP_BYTES, MAX_BACKUP_DURATION_MS, MAX_BACKUP_ID_LEN,
    MAX_BACKUP_MEMBER_KEY_BYTES, MAX_BACKUP_PAGE_ENTRIES, MAX_BACKUP_PAGES,
    MAX_BACKUP_TABLE_CENSUS, MAX_BACKUP_WORK_UNITS, OpaqueUnavailableCause, OrsBackupDestination,
    OrsBackupEntry, OrsBackupImportReceipt, OrsBackupImportRequest, OrsBackupPage,
    OrsBackupRequest, OrsBackupSnapshot, OwnerValidationDisposition, OwnerZeroGate,
    PerEntryOutcome, RetryCheckpointClass, RowDisposition, RowFamilyAvailability, RowFamilyCensus,
    RowFamilyDisposition, RowFamilyKind, StoredEffectClass, check_canonical_frozen,
    row_family_census, validate_import_binding,
};
use crate::{
    EpochIdentity, EpochLineage, OpaqueLabel, OperationalPhase, OrsError, RecoveryAccessClass,
    RecoveryEnvelopeContext, RecoveryInboxDisposition, RecoveryInboxItem, RecoveryPayload,
    RecoveryPayloadEnvelope, RecoveryProblem, StateFenceSnapshot, VisibilityClass,
};

/// Bounded full-scan cap for the identity-conflict lookup, the canonical freeze
/// digest, and the guard census. Keeps quarantine reads from becoming unbounded
/// scans; exceeding it fails closed instead of truncating silently.
const IMPORT_SCAN_ROW_CAP: u64 = 1_048_576;

/// Base `META` row holding the current order counter.
const META_NEXT_GLOBAL_ORDER: &str = "next_global_order";
/// Base `META` row holding the admitted supervision stage-resolution schema.
const META_STAGE_RESOLUTION_SCHEMA: &str = "supervision_stage_resolution_schema";
/// Physical base meta table the schema and policy marker are read from.
const META: TableDefinition<&str, &str> = TableDefinition::new("ors_meta_v1");
/// Physical table holding current typed operational records.
const OPERATIONAL_CURRENT: TableDefinition<&str, &str> =
    TableDefinition::new("ors_operational_current_v1");
/// Physical table holding historical typed operational records.
const OPERATIONAL_HISTORY: TableDefinition<&str, &str> =
    TableDefinition::new("ors_operational_history_v1");
/// Physical table holding pending recovery-inbox items.
const RECOVERY_INBOX: TableDefinition<&str, &str> = TableDefinition::new("ors_recovery_inbox_v1");
/// Physical table holding durable recovery problems.
const RECOVERY_PROBLEMS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_recovery_problems_v1");
/// Physical table holding current Ordering Scope reservation heads.
const SCOPE_HEADS: TableDefinition<&str, &str> = TableDefinition::new("ors_scope_heads_v1");
/// Physical table holding durable grant-closure commits.
const GRANT_CLOSURE_CURRENT: TableDefinition<&str, &str> =
    TableDefinition::new("ors_grant_closure_current_v2");
/// Durable `OPERATIONAL_CURRENT` key prefix for the current authority snapshot.
const AUTHORITY_SNAPSHOT_PREFIX: &str = "authority_snapshot:";
/// Durable `OPERATIONAL_CURRENT` key prefix for a durable authority revocation.
const AUTHORITY_REVOCATION_PREFIX: &str = "authority_revocation:";
/// Bounded locator naming the quarantined backup archive as an opaque handle.
const BACKUP_ARCHIVE_LOCATOR_PREFIX: &str = "ors-backup-archive:";
/// Bounded signer identity recorded on the quarantine inbox item.
const BACKUP_IMPORT_SIGNER: &str = "ors-backup-import";
/// Key provider recorded for an inbox item whose signer authenticated it.
const INBOX_SIGNER_PROVIDER: &str = "inbox-signer";
/// Key provider recorded for a durable recovery problem identity.
const RECOVERY_PROBLEM_PROVIDER: &str = "recovery-problem";
/// Key provider recorded for an immutable-locator operational payload.
const LOCATOR_KEY_PROVIDER: &str = "immutable-locator";

/// Exact per-family backup disposition for every ORS row family.
///
/// Delegates to the frozen census in the contract module, which is the single
/// source of truth for physical table name, presence, and restore disposition,
/// so the runtime census below and this projection cannot drift apart.
pub(super) fn row_family_denominator() -> Vec<RowFamilyDisposition> {
    row_family_census()
}

/// Maps a durable phase to its backup effect class.
///
/// Committed or terminal phases export as `Terminal`, staged rows as
/// `Staged`, and in-flight rows as `Possible`.
fn effect_class_for_export(phase: OperationalPhase) -> StoredEffectClass {
    match phase {
        OperationalPhase::Staged => StoredEffectClass::Staged,
        OperationalPhase::Applying
        | OperationalPhase::Reconciling
        | OperationalPhase::Suspended => StoredEffectClass::Possible,
        OperationalPhase::Active
        | OperationalPhase::Terminal
        | OperationalPhase::Released
        | OperationalPhase::Fenced => StoredEffectClass::Terminal,
    }
}

/// Returns true for a 64-character lowercase hex digest; rejects uppercase,
/// short, long, or non-hex input so malformed bindings fail with stable
/// [`OrsError::InvalidField`] instead of passing silently.
fn is_digest_shape(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Cumulative capture budget charged once per observed row and once per
/// observed byte, across the whole capture rather than per page.
///
/// The duration budget is a wall-clock deadline on the whole capture, not a
/// per-row charge: [`Self::check_deadline`] is evaluated on a live clock reading
/// at every family boundary and at capture close, so a slow read and a capture
/// that observes no row at all are both refused instead of running unbounded.
struct CaptureBudget {
    work_used: u64,
    work_cap: u64,
    duration_cap_ms: u64,
    started_ms: i64,
}
impl CaptureBudget {
    fn new(request: &OrsBackupRequest, now_ms: i64) -> Self {
        Self {
            work_used: 0,
            work_cap: request.max_work_units.min(MAX_BACKUP_WORK_UNITS),
            duration_cap_ms: request.max_duration_ms.min(MAX_BACKUP_DURATION_MS),
            started_ms: now_ms,
        }
    }
    /// Enforces the capture's wall-clock deadline against the clock reading the
    /// caller already holds. Fails closed with the same typed error the work cap
    /// uses; the ceiling is exclusive, so a capture that has run past its budget
    /// is refused rather than truncated.
    fn check_deadline(&self, now_ms: i64) -> Result<(), OrsError> {
        let elapsed = now_ms.saturating_sub(self.started_ms).max(0);
        if u64::try_from(elapsed).unwrap_or(u64::MAX) > self.duration_cap_ms {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        Ok(())
    }
    /// Charges one observed row. The ceiling is exclusive: the row that would
    /// be the one-over fails closed instead of being silently truncated.
    fn charge_work(&mut self, now_ms: i64) -> Result<(), OrsError> {
        self.work_used = self
            .work_used
            .checked_add(1)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        self.check_deadline(now_ms)?;
        if self.work_used > self.work_cap {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        Ok(())
    }
}

/// Deterministic digest over durable operational-history state.
///
/// Binds `(order, record-bytes digest)` pairs in order under one read
/// transaction. Used as the pre/post canonical-freeze witness: any canonical
/// advance between the two observations fails the export or import with
/// [`OrsError::OrderingHeadMismatch`] instead of tearing the snapshot.
fn canonical_state_digest(database: &Database) -> Result<String, OrsError> {
    let read = database.begin_read().map_err(storage)?;
    let digest = operational_history_digest(&read)?;
    drop(read);
    Ok(digest)
}

/// The same digest computed inside a caller's existing read transaction.
fn operational_history_digest(read: &ReadTransaction) -> Result<String, OrsError> {
    let table = read.open_table(OPERATIONAL_HISTORY).map_err(storage)?;
    let mut rows: Vec<(u64, String)> = Vec::new();
    for entry in table.iter().map_err(storage)? {
        if rows.len() as u64 >= IMPORT_SCAN_ROW_CAP {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let (_, value) = entry.map_err(storage)?;
        let record: DurableOperationalRecord = decode_named(value.value(), "operational_history")?;
        rows.push((
            record.operation_order,
            crate::model::sha256_hex(encode(&record)?.as_bytes()),
        ));
    }
    drop(table);
    rows.sort_by_key(|(order, _)| *order);
    let mut material = String::new();
    for (order, digest) in &rows {
        material.push_str(&order.to_string());
        material.push(':');
        material.push_str(digest);
        material.push(';');
    }
    Ok(crate::model::sha256_hex(material.as_bytes()))
}

/// The physical table census actually observed inside one read transaction.
///
/// Enumerating before opening is what keeps a declared-but-unwritten table from
/// aborting the whole consistency point, and refusing an undeclared observed
/// table is what keeps a table from disappearing out of the denominator.
fn observed_table_census(read: &ReadTransaction) -> Result<BTreeSet<String>, OrsError> {
    let declared: BTreeSet<&str> = row_family_census()
        .iter()
        .map(|family| family.table_name)
        .collect();
    let mut observed = BTreeSet::new();
    for handle in read.list_tables().map_err(storage)? {
        let name = handle.name().to_owned();
        if name.len() > MAX_BACKUP_ID_LEN {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        if !declared.contains(name.as_str()) {
            return Err(OrsError::MigrationRequired {
                reason: format!("ORS table {name} exists with no backup row-family disposition"),
            });
        }
        observed.insert(name);
    }
    if observed.len() > MAX_BACKUP_TABLE_CENSUS {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    Ok(observed)
}

/// Digest over the observed table census, binding the capture to the exact
/// physical schema it read.
fn table_census_digest(observed: &BTreeSet<String>) -> String {
    let mut material = String::new();
    for name in observed {
        material.push_str(name);
        material.push(';');
    }
    crate::model::sha256_hex(material.as_bytes())
}

/// Reads one base `META` marker, rejecting an oversized value before cloning.
fn read_meta_marker(read: &ReadTransaction, key: &str) -> Result<String, OrsError> {
    let table = read.open_table(META).map_err(storage)?;
    let Some(value) = table.get(key).map_err(storage)? else {
        return Ok(String::new());
    };
    if value.value().len() > MAX_BACKUP_ID_LEN {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    Ok(value.value().to_owned())
}

/// The greatest order the base meta counter has assigned, if any.
fn observed_order_counter(read: &ReadTransaction) -> Result<u64, OrsError> {
    let raw = read_meta_marker(read, META_NEXT_GLOBAL_ORDER)?;
    if raw.is_empty() {
        return Ok(0);
    }
    raw.parse::<u64>().map_err(|_| OrsError::IntegrityProblem {
        record_type: "ors_meta_v1",
        reason: "next_global_order is not a decimal counter".to_owned(),
    })
}

/// Digest over the current canonical dependency heads (the Ordering Scope
/// reservation heads), which is the exact `dependency_fence` of I05-6.
fn observed_canonical_dependency_fence(read: &ReadTransaction) -> Result<String, OrsError> {
    let table = read.open_table(SCOPE_HEADS).map_err(storage)?;
    let mut rows: Vec<(String, String)> = Vec::new();
    for entry in table.iter().map_err(storage)? {
        if rows.len() as u64 >= IMPORT_SCAN_ROW_CAP {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let (key, value) = entry.map_err(storage)?;
        let head: ScopeReservationHead = decode_named(value.value(), "scope_head")?;
        let canonical = crate::model::sha256_hex(encode(&head)?.as_bytes());
        rows.push((key.value().to_owned(), canonical));
    }
    drop(table);
    let mut material = String::new();
    for (scope, digest) in &rows {
        material.push_str(scope);
        material.push('=');
        material.push_str(digest);
        material.push(';');
    }
    Ok(crate::model::sha256_hex(material.as_bytes()))
}

/// The authority snapshot in force: the highest-ordered `authority_snapshot:`
/// row in the current operational table.
fn observed_authority(
    read: &ReadTransaction,
) -> Result<Option<DurableOperationalRecord>, OrsError> {
    let table = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
    let mut newest: Option<DurableOperationalRecord> = None;
    for entry in table.iter().map_err(storage)? {
        let (key, value) = entry.map_err(storage)?;
        if !key.value().starts_with(AUTHORITY_SNAPSHOT_PREFIX) {
            continue;
        }
        let record: DurableOperationalRecord = decode_named(value.value(), "operational_current")?;
        if record.kind != OperationalKind::AuthoritySnapshot {
            continue;
        }
        if newest
            .as_ref()
            .is_none_or(|prior| record.operation_order >= prior.operation_order)
        {
            newest = Some(record);
        }
    }
    Ok(newest)
}

/// Establishes the owner-established current state at one capture point.
///
/// Everything here is read from durable ORS state inside the caller's single
/// read transaction: the physical table census, the admitted schema and policy
/// marker, the order counter, the canonical dependency fence, and the authority
/// lineage and generation in force. No field is accepted from the caller.
fn observe_capture_point(
    read: &ReadTransaction,
    observed: &BTreeSet<String>,
    now_ms: i64,
) -> Result<BackupCapturePoint, OrsError> {
    let schema_marker = read_meta_marker(read, META_STAGE_RESOLUTION_SCHEMA)?;
    let counter = observed_order_counter(read)?;
    let canonical_dependency_fence = observed_canonical_dependency_fence(read)?;
    let authority = observed_authority(read)?;
    let (lineage_id, authority_epoch) = match &authority {
        Some(record) => (
            record
                .input
                .authority_epoch
                .current
                .lineage_id
                .as_str()
                .to_owned(),
            record.input.authority_epoch.current.epoch,
        ),
        None => (String::new(), 0),
    };
    let table_digest = table_census_digest(observed);
    let mut high_water_order = counter;
    if let Some(record) = &authority {
        high_water_order = high_water_order.max(record.operation_order);
    }
    let materialized = row_family_census()
        .iter()
        .filter(|family| observed.contains(family.table_name))
        .count();
    let absent = row_family_census().len().saturating_sub(materialized);
    let binding_digest = BackupCapturePoint::binding_digest(
        schema_marker.as_str(),
        lineage_id.as_str(),
        authority_epoch,
        high_water_order,
        canonical_dependency_fence.as_str(),
        table_digest.as_str(),
    );
    Ok(BackupCapturePoint {
        binding_digest,
        schema_marker,
        lineage_id,
        authority_epoch,
        high_water_order,
        canonical_dependency_fence,
        table_census_digest: table_digest,
        materialized_families: u32::try_from(materialized).unwrap_or(u32::MAX),
        absent_families: u32::try_from(absent).unwrap_or(u32::MAX),
        work_units: 0,
        total_bytes: 0,
        opened_at_ms: now_ms,
        closed_at_ms: now_ms,
    })
}

/// A2: compares every declared source and fence field against the current
/// owner-established value observed at the capture point.
///
/// A caller-supplied token is never enough. The installation lineage, the ORS
/// generation, the admitted schema marker, the canonical dependency fence, the
/// order high-water, and the store-computed binding digest must all equal what
/// the store actually holds, or the capture is refused rather than relabelled.
fn verify_owner_binding(
    request: &OrsBackupRequest,
    point: &BackupCapturePoint,
) -> Result<(), OrsError> {
    if request.source.schema_version != BACKUP_SNAPSHOT_SCHEMA_VERSION {
        return Err(OrsError::MigrationRequired {
            reason: format!(
                "backup schema {} unsupported, expected {BACKUP_SNAPSHOT_SCHEMA_VERSION}",
                request.source.schema_version
            ),
        });
    }
    if point.schema_marker.is_empty() {
        return Err(OrsError::MigrationRequired {
            reason: "ORS base meta carries no admitted schema marker to bind the capture"
                .to_owned(),
        });
    }
    if point.lineage_id.is_empty() {
        return Err(OrsError::AuthoritySnapshotUnavailable);
    }
    if request.source.installation_id != point.lineage_id {
        return Err(OrsError::FenceMismatch);
    }
    if request.source.ors_generation != point.authority_epoch {
        return Err(OrsError::StaleWriterEpoch);
    }
    if request.source.store_binding_digest != point.binding_digest {
        return Err(OrsError::OrderingHeadMismatch);
    }
    if request.fence.canonical_dependency_fence != point.canonical_dependency_fence {
        return Err(OrsError::OrderingHeadMismatch);
    }
    if request.fence.high_water_order != point.high_water_order {
        return Err(OrsError::OrderingHeadMismatch);
    }
    Ok(())
}

/// Bounded key check for a captured physical row key.
fn capture_key(value: &str) -> Result<(), OrsError> {
    if value.is_empty()
        || value.len() > MAX_BACKUP_MEMBER_KEY_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    Ok(())
}

/// The key and signature identity of one stored operational record.
///
/// ORS owns no keys and holds no detached signature for the records it stages,
/// so the identity is exactly the provider and key reference the record already
/// carries. The signature field stays absent, which is what keeps the entry
/// blocked at import instead of passing a digest-shape check.
fn crypto_identity_for_record(record: &DurableOperationalRecord) -> BackupEntryCryptoIdentity {
    let (key_provider, key_id) = match &record.input.payload {
        RecoveryPayload::Encrypted { key, .. } => (
            Some(key.provider.as_str().to_owned()),
            Some(key.key.as_str().to_owned()),
        ),
        RecoveryPayload::ImmutableLocator { locator } => (
            Some(LOCATOR_KEY_PROVIDER.to_owned()),
            Some(locator.as_str().to_owned()),
        ),
    };
    BackupEntryCryptoIdentity {
        key_provider,
        key_id,
        content_sha256: record.input.payload_sha256.clone(),
        signature_sha256: None,
        content_schema_version: BACKUP_SNAPSHOT_SCHEMA_VERSION,
    }
}

/// The retry and checkpoint lineage class implied by a durable record kind.
fn retry_checkpoint_class(kind: OperationalKind) -> RetryCheckpointClass {
    match kind {
        OperationalKind::Retry => RetryCheckpointClass::Retry,
        OperationalKind::JobCheckpoint => RetryCheckpointClass::JobCheckpoint,
        _ => RetryCheckpointClass::NotApplicable,
    }
}

/// The generation lineage a durable record carries, when it carries one.
fn generation_lineage(record: &DurableOperationalRecord) -> Option<BackupGenerationLineage> {
    record
        .generation_cutover
        .as_ref()
        .map(|cutover| BackupGenerationLineage {
            cutover_id: cutover.cutover_id.clone(),
            route_scope: cutover.route_scope.clone(),
            old_generation: cutover.old_generation.map(ResourceGeneration::value),
            new_generation: cutover.new_generation.value(),
            old_epoch: cutover.old_epoch.value(),
            new_epoch: cutover.new_epoch.value(),
        })
}

/// Full durable lineage for one captured member of a typed operational family.
fn lineage_for_record(
    record: &DurableOperationalRecord,
    high_water_order: u64,
) -> BackupEntryLineage {
    BackupEntryLineage {
        subject_id: record.input.subject_id.as_str().to_owned(),
        operation_kind: record.kind.key_prefix().to_owned(),
        retry_checkpoint_class: retry_checkpoint_class(record.kind),
        source_order: Some(record.operation_order),
        high_water_order,
        authority_epoch: record.input.authority_epoch.current.epoch,
        lineage_id: record
            .input
            .authority_epoch
            .current
            .lineage_id
            .as_str()
            .to_owned(),
        state_fence_sha256: record.input.state_fence.sha256.clone(),
        generation: generation_lineage(record),
        receipt_id: record
            .terminal_receipt_id
            .as_ref()
            .map(|label| label.as_str().to_owned()),
        receipt_sha256: record.terminal_receipt_sha256.clone(),
        payload_length: record.input.payload_length,
        created_at_ms: record.input.created_at_ms,
        cleanup_after_ms: record.input.cleanup_after_ms,
    }
}

/// The opaque-payload availability verdict for one decoded operational record.
///
/// The declared payload digest must equal the digest of the bytes the store
/// actually holds. A mismatch keeps the member `OpaqueUnavailable`, so a
/// snapshot can never report `Complete` from a reference count alone.
fn availability_for_record(record: &DurableOperationalRecord) -> BackupEntryAvailability {
    if !is_digest_shape(&record.input.payload_sha256) {
        return BackupEntryAvailability::OpaqueUnavailable {
            cause: OpaqueUnavailableCause::DeclaredDigestMismatch,
        };
    }
    match &record.input.payload {
        RecoveryPayload::Encrypted { ciphertext, .. } => {
            let length = u64::try_from(ciphertext.len()).unwrap_or(u64::MAX);
            if length != record.input.payload_length
                || crate::model::sha256_hex(ciphertext) != record.input.payload_sha256
            {
                return BackupEntryAvailability::OpaqueUnavailable {
                    cause: OpaqueUnavailableCause::DeclaredDigestMismatch,
                };
            }
        }
        RecoveryPayload::ImmutableLocator { .. } => {}
    }
    BackupEntryAvailability::Available
}

/// Lineage for a row family ORS reads as opaque bytes.
///
/// The row's exact key and byte digest are preserved; the durable record shape
/// belongs to its owning family, so ORS does not reinterpret an opaque family's
/// payload here and does not invent a retry, receipt, or generation lineage it
/// cannot observe.
fn lineage_for_opaque_row(key: &str, high_water_order: u64) -> BackupEntryLineage {
    BackupEntryLineage {
        subject_id: key.to_owned(),
        operation_kind: "opaque_row".to_owned(),
        retry_checkpoint_class: RetryCheckpointClass::NotApplicable,
        source_order: None,
        high_water_order,
        authority_epoch: 0,
        lineage_id: String::new(),
        state_fence_sha256: crate::model::sha256_hex(key.as_bytes()),
        generation: None,
        receipt_id: None,
        receipt_sha256: None,
        payload_length: 0,
        created_at_ms: 0,
        cleanup_after_ms: None,
    }
}

/// Cryptographic identity for a row family ORS never decodes.
///
/// The row bytes were read and hashed, so the payload is available; the key and
/// signature identity is absent by construction, which keeps the entry blocked
/// at import with a typed unknown-crypto reason.
fn crypto_for_opaque_row(row_digest: &str) -> BackupEntryCryptoIdentity {
    BackupEntryCryptoIdentity {
        key_provider: None,
        key_id: None,
        content_sha256: row_digest.to_owned(),
        signature_sha256: None,
        content_schema_version: BACKUP_SNAPSHOT_SCHEMA_VERSION,
    }
}

/// One captured member before its capture-order index is assigned.
struct CapturedMember {
    record_id: String,
    member_key: String,
    family: RowFamilyKind,
    payload_digest: String,
    effect_class: StoredEffectClass,
    lineage: BackupEntryLineage,
    crypto: BackupEntryCryptoIdentity,
    availability: BackupEntryAvailability,
    unavailable: bool,
}

/// Reads every row of one declared family inside the caller's read transaction.
///
/// A family the store never materialized is recorded as an explicit
/// source-bound `OutsideAdmittedGeneration` exclusion with zero members: the
/// table is never opened and never created.
#[allow(
    clippy::too_many_lines,
    reason = "one row-family reader keeps the typed, opaque, and absent dispositions visible side by side"
)]
fn capture_family(
    read: &ReadTransaction,
    observed: &BTreeSet<String>,
    family: RowFamilyDisposition,
    point: &BackupCapturePoint,
    budget: &mut CaptureBudget,
    members: &mut Vec<CapturedMember>,
    now_ms: i64,
) -> Result<RowFamilyCensus, OrsError> {
    if !observed.contains(family.table_name) {
        return Ok(RowFamilyCensus {
            kind: family.kind,
            availability: RowFamilyAvailability::DeclaredAbsent,
            disposition: RowDisposition::OutsideAdmittedGeneration,
            observed_rows: 0,
            captured: 0,
            window_rows: 0,
            unavailable: 0,
            member_digest: RowFamilyCensus::member_digest(family.kind, &[]),
        });
    }
    let table = read
        .open_table(TableDefinition::<&str, &str>::new(family.table_name))
        .map_err(storage)?;
    let mut observed_rows: u64 = 0;
    for entry in table.iter().map_err(storage)? {
        budget.charge_work(now_ms)?;
        let (key, value) = entry.map_err(storage)?;
        capture_key(key.value())?;
        observed_rows = observed_rows
            .checked_add(1)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        if observed_rows > IMPORT_SCAN_ROW_CAP {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let row_digest = crate::model::sha256_hex(value.value().as_bytes());
        let member_key = key.value().to_owned();
        members.push(match family.kind {
            RowFamilyKind::OperationalCurrent | RowFamilyKind::OperationalHistory => {
                let record: DurableOperationalRecord =
                    decode_named(value.value(), "operational_record")?;
                let availability = availability_for_record(&record);
                CapturedMember {
                    record_id: record.input.record_id.as_str().to_owned(),
                    member_key,
                    family: family.kind,
                    payload_digest: row_digest,
                    effect_class: effect_class_for_export(record.phase),
                    lineage: lineage_for_record(&record, point.high_water_order),
                    crypto: crypto_identity_for_record(&record),
                    unavailable: !matches!(availability, BackupEntryAvailability::Available),
                    availability,
                }
            }
            RowFamilyKind::RecoveryInbox => {
                let record: DurableInboxRecord = decode_named(value.value(), "recovery_inbox")?;
                let outstanding = record.terminal_receipt_sha256.is_none();
                CapturedMember {
                    record_id: record
                        .item
                        .envelope
                        .operation_or_checkpoint_id
                        .as_str()
                        .to_owned(),
                    member_key,
                    family: family.kind,
                    payload_digest: row_digest,
                    effect_class: inbox_effect_class(record.disposition),
                    lineage: BackupEntryLineage {
                        subject_id: record
                            .item
                            .envelope
                            .operation_or_checkpoint_id
                            .as_str()
                            .to_owned(),
                        operation_kind: "recovery_inbox".to_owned(),
                        retry_checkpoint_class: RetryCheckpointClass::NotApplicable,
                        source_order: Some(record.operation_order),
                        high_water_order: point.high_water_order,
                        authority_epoch: record.item.envelope.authority_epoch.current.epoch,
                        lineage_id: record
                            .item
                            .envelope
                            .authority_epoch
                            .current
                            .lineage_id
                            .as_str()
                            .to_owned(),
                        state_fence_sha256: record.item.envelope.state_fence.sha256.clone(),
                        generation: None,
                        receipt_id: record
                            .terminal_receipt_id
                            .as_ref()
                            .map(|label| label.as_str().to_owned()),
                        receipt_sha256: record.terminal_receipt_sha256.clone(),
                        payload_length: record.item.envelope.payload_length,
                        created_at_ms: record.item.arrived_at_ms,
                        cleanup_after_ms: record.item.envelope.expires_at_ms,
                    },
                    crypto: BackupEntryCryptoIdentity {
                        key_provider: Some(INBOX_SIGNER_PROVIDER.to_owned()),
                        key_id: Some(record.item.signer_id.as_str().to_owned()),
                        content_sha256: record.item.envelope.payload_sha256.clone(),
                        signature_sha256: Some(record.item.signature_sha256.clone()),
                        content_schema_version: BACKUP_SNAPSHOT_SCHEMA_VERSION,
                    },
                    availability: if outstanding {
                        BackupEntryAvailability::OpaqueUnavailable {
                            cause: OpaqueUnavailableCause::MissingContentIdentity,
                        }
                    } else {
                        BackupEntryAvailability::Available
                    },
                    unavailable: outstanding,
                }
            }
            RowFamilyKind::RecoveryProblems => {
                let record: RecoveryProblem = decode_named(value.value(), "recovery_problems")?;
                let outstanding = record.terminal_receipt_id.is_none();
                let problem_kind = problem_kind_name(&record);
                CapturedMember {
                    record_id: record.operation_or_checkpoint_id.as_str().to_owned(),
                    member_key,
                    family: family.kind,
                    payload_digest: row_digest.clone(),
                    effect_class: if outstanding {
                        StoredEffectClass::Unknown
                    } else {
                        StoredEffectClass::Terminal
                    },
                    lineage: BackupEntryLineage {
                        subject_id: record.operation_or_checkpoint_id.as_str().to_owned(),
                        operation_kind: format!("recovery_problem_{problem_kind}"),
                        retry_checkpoint_class: RetryCheckpointClass::NotApplicable,
                        source_order: None,
                        high_water_order: point.high_water_order,
                        authority_epoch: record.authority_epoch.current.epoch,
                        lineage_id: record
                            .authority_epoch
                            .current
                            .lineage_id
                            .as_str()
                            .to_owned(),
                        state_fence_sha256: record.state_fence.sha256.clone(),
                        generation: None,
                        receipt_id: record
                            .terminal_receipt_id
                            .as_ref()
                            .map(|label| label.as_str().to_owned()),
                        receipt_sha256: record.envelope_sha256,
                        payload_length: 0,
                        created_at_ms: record.created_at_ms,
                        cleanup_after_ms: None,
                    },
                    crypto: BackupEntryCryptoIdentity {
                        key_provider: Some(RECOVERY_PROBLEM_PROVIDER.to_owned()),
                        key_id: Some(problem_kind),
                        content_sha256: row_digest,
                        signature_sha256: None,
                        content_schema_version: BACKUP_SNAPSHOT_SCHEMA_VERSION,
                    },
                    availability: BackupEntryAvailability::Available,
                    unavailable: false,
                }
            }
            RowFamilyKind::GrantClosureCurrent => {
                let record: DurableGrantClosureRecord =
                    decode_named(value.value(), "grant_closure_current")?;
                CapturedMember {
                    record_id: record.commit.operation_id.clone(),
                    member_key,
                    family: family.kind,
                    payload_digest: row_digest.clone(),
                    effect_class: effect_class_for_export(record.phase),
                    lineage: BackupEntryLineage {
                        subject_id: record.commit.operation_id.clone(),
                        operation_kind: "grant_closure".to_owned(),
                        retry_checkpoint_class: RetryCheckpointClass::NotApplicable,
                        source_order: Some(record.operation_order),
                        high_water_order: point.high_water_order,
                        authority_epoch: 0,
                        lineage_id: String::new(),
                        state_fence_sha256: crate::model::sha256_hex(row_digest.as_bytes()),
                        generation: None,
                        receipt_id: record
                            .commit
                            .canonical_receipt
                            .as_ref()
                            .map(|receipt| receipt.receipt_id.to_string()),
                        receipt_sha256: Some(record.commit.idempotency_digest.clone()),
                        payload_length: 0,
                        created_at_ms: 0,
                        cleanup_after_ms: None,
                    },
                    crypto: crypto_for_opaque_row(&row_digest),
                    availability: BackupEntryAvailability::Available,
                    unavailable: false,
                }
            }
            _ => CapturedMember {
                record_id: member_key.clone(),
                member_key,
                family: family.kind,
                payload_digest: row_digest.clone(),
                effect_class: StoredEffectClass::Terminal,
                lineage: lineage_for_opaque_row(key.value(), point.high_water_order),
                crypto: crypto_for_opaque_row(&row_digest),
                availability: BackupEntryAvailability::Available,
                unavailable: false,
            },
        });
    }
    drop(table);
    Ok(RowFamilyCensus {
        kind: family.kind,
        availability: RowFamilyAvailability::Materialized,
        disposition: family.disposition,
        observed_rows,
        captured: 0,
        window_rows: 0,
        unavailable: 0,
        member_digest: String::new(),
    })
}

/// The stored effect class a durable inbox disposition exports as.
fn inbox_effect_class(disposition: RecoveryInboxDisposition) -> StoredEffectClass {
    match disposition {
        RecoveryInboxDisposition::Imported | RecoveryInboxDisposition::Applied => {
            StoredEffectClass::Terminal
        }
        RecoveryInboxDisposition::Rejected | RecoveryInboxDisposition::DeadLetter => {
            StoredEffectClass::Possible
        }
    }
}

/// A stable bounded name for a durable recovery problem kind.
fn problem_kind_name(record: &RecoveryProblem) -> String {
    format!("{:?}", record.kind).to_lowercase()
}

/// Captures the whole snapshot inside one long-lived read transaction.
///
/// The capture point is established once from durable state, the census is read
/// and dispositioned family by family under that same point, and the point is
/// re-verified at close against a second observation. The work and byte budgets
/// are charged as the census is read, and the duration budget is a wall-clock
/// deadline checked at every family boundary, at close, and before the snapshot
/// is returned, so a slow read and a capture that observes no row at all are
/// both refused. Nothing is written and no table is created.
#[allow(
    clippy::too_many_lines,
    reason = "the capture is one ordered consistency point: bind, census, read, page, re-verify"
)]
fn capture(database: &Database, request: &OrsBackupRequest) -> Result<OrsBackupSnapshot, OrsError> {
    let started_ms = super::current_unix_ms()?;
    if !request.token_is_live(started_ms) {
        return Err(OrsError::InvalidField {
            field: "backup_token_expires_at_ms",
            reason: "capture page token expired before the capture started",
        });
    }
    let frozen_pre = canonical_state_digest(database)?;
    // ONE read transaction spans the entire capture: every page, every family,
    // and the close-time re-verification read the same consistent state.
    let read = database.begin_read().map_err(storage)?;
    let observed = observed_table_census(&read)?;
    let mut point = observe_capture_point(&read, &observed, started_ms)?;
    verify_owner_binding(request, &point)?;
    let mut budget = CaptureBudget::new(request, started_ms);
    let mut members: Vec<CapturedMember> = Vec::new();
    let mut denominator: Vec<RowFamilyCensus> = Vec::new();
    for family in row_family_census() {
        // A live reading per family, never the frozen `started_ms`: the
        // per-row duration charge can only fire against a clock that moved.
        // Bounded at one read per declared family, and a capture that observes
        // no row at all still hits the deadline here.
        let family_ms = super::current_unix_ms()?;
        budget.check_deadline(family_ms)?;
        let census = capture_family(
            &read,
            &observed,
            family,
            &point,
            &mut budget,
            &mut members,
            family_ms,
        )?;
        denominator.push(census);
    }
    let close_point = observe_capture_point(&read, &observed, started_ms)?;
    if close_point.binding_digest != point.binding_digest {
        return Err(OrsError::OrderingHeadMismatch);
    }
    members.sort_by(|left, right| {
        left.family
            .cmp(&right.family)
            .then_with(|| left.member_key.cmp(&right.member_key))
    });
    let (entries, total_bytes) = paginate_members(request, members, &mut denominator)?;
    for census in &mut denominator {
        census.member_digest = RowFamilyCensus::member_digest(census.kind, &entries);
    }
    let pages = build_pages(request, &entries, started_ms)?;
    point.work_units = budget.work_used;
    point.total_bytes = total_bytes;
    // The deadline is re-checked at close on the clock reading that closes the
    // capture point, so a read that ran past its budget is refused even when it
    // observed no row.
    let closed_ms = super::current_unix_ms()?;
    budget.check_deadline(closed_ms)?;
    point.closed_at_ms = closed_ms;
    drop(read);
    // Drift witness: the store must not have moved while the capture ran.
    let frozen_post = canonical_state_digest(database)?;
    check_canonical_frozen(&frozen_pre, &frozen_post)?;
    let post_point = observe_capture_point_standalone(database)?;
    if post_point.binding_digest != point.binding_digest {
        return Err(OrsError::OrderingHeadMismatch);
    }
    budget.check_deadline(super::current_unix_ms()?)?;
    let unavailable = denominator
        .iter()
        .fold(0_u64, |total, row| total.saturating_add(row.unavailable));
    let entry_count =
        u64::try_from(entries.len()).map_err(|_| OrsError::ProjectionLimitExceeded)?;
    let completeness = if entry_count == 0 {
        BackupCompleteness::Partial {
            reason: "no member is above the declared after_order bound".to_owned(),
        }
    } else if unavailable > 0 {
        BackupCompleteness::Incomplete {
            reason: format!("{unavailable} captured member(s) carry an unreadable opaque payload"),
        }
    } else {
        BackupCompleteness::Complete
    };
    let mut snapshot = OrsBackupSnapshot {
        source: request.source.clone(),
        fence: request.fence.clone(),
        pages,
        denominator_digest: String::new(),
        entry_count,
        total_bytes,
        completeness,
        capture_point: point,
        family_denominator: denominator,
        after_order: request.after_order,
    };
    snapshot.denominator_digest = snapshot.snapshot_digest();
    // Export is self-validating: a snapshot that cannot prove its own member
    // completeness is never returned as a capture.
    snapshot.validate()?;
    Ok(snapshot)
}

/// Assigns capture-order indices above the declared cursor, charges the
/// aggregate byte budget across the whole snapshot rather than per page, and
/// rewrites each family census so the member denominator is exact.
///
/// The byte ceiling is re-clamped here, at the point of use, exactly as
/// [`CaptureBudget::new`] re-clamps the work and duration budgets:
/// `OrsBackupRequest` has public fields and no `#[non_exhaustive]`, so a struct
/// literal bypasses `OrsBackupRequest::new` and the aggregate total must still
/// be refused against `MAX_BACKUP_BYTES` however the request was built.
///
/// The census is closed here rather than in the row reader: capture order is
/// the sorted `(family, record id)` order, so a family that mixes members above
/// and below the cursor cannot be split without knowing that order.
fn paginate_members(
    request: &OrsBackupRequest,
    members: Vec<CapturedMember>,
    denominator: &mut [RowFamilyCensus],
) -> Result<(Vec<OrsBackupEntry>, u64), OrsError> {
    let byte_ceiling = request.max_bytes.min(MAX_BACKUP_BYTES);
    let mut entries: Vec<OrsBackupEntry> = Vec::with_capacity(members.len());
    let mut total_bytes: u64 = 0;
    let mut capture_order: u64 = 0;
    for member in members {
        capture_order = capture_order
            .checked_add(1)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        let row = denominator
            .iter_mut()
            .find(|row| row.kind == member.family)
            .ok_or(OrsError::IntegrityProblem {
                record_type: "backup_family_census",
                reason: "a captured member has no declared row family".to_owned(),
            })?;
        if capture_order <= request.after_order {
            row.window_rows = row.window_rows.saturating_add(1);
            continue;
        }
        total_bytes = total_bytes
            .checked_add(
                u64::try_from(member.payload_digest.len())
                    .map_err(|_| OrsError::ProjectionLimitExceeded)?,
            )
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        if total_bytes > byte_ceiling {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        row.captured = row.captured.saturating_add(1);
        if member.unavailable {
            row.unavailable = row.unavailable.saturating_add(1);
        }
        entries.push(OrsBackupEntry {
            record_id: member.record_id,
            member_key: member.member_key,
            family: member.family,
            order: capture_order,
            payload_digest: member.payload_digest,
            effect_class: member.effect_class,
            lineage: member.lineage,
            crypto: member.crypto,
            availability: member.availability,
        });
    }
    Ok((entries, total_bytes))
}

/// Re-observes the capture point from a fresh read transaction, used only as the
/// post-capture drift witness.
fn observe_capture_point_standalone(database: &Database) -> Result<BackupCapturePoint, OrsError> {
    let read = database.begin_read().map_err(storage)?;
    let now_ms = super::current_unix_ms()?;
    let observed = observed_table_census(&read)?;
    let point = observe_capture_point(&read, &observed, now_ms)?;
    drop(read);
    Ok(point)
}

/// Slices the captured members into a chain-bound, token-bound page sequence.
///
/// An empty capture window still emits exactly one empty final page, so a
/// partial snapshot is a well-formed value with a stated reason rather than a
/// page-less structure the validator must reject.
fn build_pages(
    request: &OrsBackupRequest,
    entries: &[OrsBackupEntry],
    issued_at_ms: i64,
) -> Result<Vec<OrsBackupPage>, OrsError> {
    let page_size = usize::from(request.page_entries);
    let total_pages = entries.len().div_ceil(page_size).max(1);
    if total_pages > usize::from(request.max_pages) {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    let token = request.page_fence_token();
    let expires_at_ms = request.effective_expiry_ms();
    let mut pages: Vec<OrsBackupPage> = Vec::with_capacity(total_pages);
    let mut predecessor: Option<String> = None;
    for index in 0..total_pages {
        let start = index.saturating_mul(page_size);
        let chunk: &[OrsBackupEntry] = entries
            .get(start..)
            .map_or(&[][..], |rest| &rest[..chunk_len(rest, page_size)]);
        let mut family_counts: Vec<BackupPageFamilyCount> = Vec::new();
        for entry in chunk {
            match family_counts
                .iter_mut()
                .find(|count| count.kind == entry.family)
            {
                Some(count) => count.captured += 1,
                None => family_counts.push(BackupPageFamilyCount {
                    kind: entry.family,
                    captured: 1,
                }),
            }
        }
        let mut page = OrsBackupPage {
            page_index: u32::try_from(index).map_err(|_| OrsError::ProjectionLimitExceeded)?,
            entries: chunk.to_vec(),
            page_digest: String::new(),
            is_last: (index + 1) == total_pages,
            fence_token: token.clone(),
            predecessor_digest: predecessor.clone(),
            family_counts,
            entry_count: u64::try_from(chunk.len())
                .map_err(|_| OrsError::ProjectionLimitExceeded)?,
            issued_at_ms,
            expires_at_ms,
        };
        page.page_digest = page.page_digest();
        predecessor = Some(page.page_digest.clone());
        pages.push(page);
    }
    Ok(pages)
}

/// The members one page carries, bounded by the page size.
fn chunk_len(remaining: &[OrsBackupEntry], page_size: usize) -> usize {
    remaining.len().min(page_size)
}

/// Exports one coherent backup page from a single whole-capture consistency
/// point.
///
/// The page is sliced out of the same coherent capture that
/// [`export_snapshot`] returns in full, under one read transaction, with the
/// capture point established once and re-verified at close. Independently
/// sourced pages therefore cannot silently enter a later page: the page token
/// binds source identity, fence, and cursor, the page chains to its
/// predecessor, and both are re-derived by the shared validator.
pub(super) fn export_page(
    database: &Database,
    request: &OrsBackupRequest,
    page_index: u32,
) -> Result<OrsBackupPage, OrsError> {
    if request.page_entries == 0 || request.page_entries > MAX_BACKUP_PAGE_ENTRIES {
        return Err(OrsError::InvalidCursorLimit);
    }
    if request.max_bytes == 0 || request.max_work_units == 0 || request.max_duration_ms == 0 {
        return Err(OrsError::InvalidField {
            field: "backup_aggregate_budgets",
            reason: "aggregate byte, work, and duration budgets must be non-zero",
        });
    }
    let snapshot = capture(database, request)?;
    let index = usize::try_from(page_index).map_err(|_| OrsError::InvalidCursorLimit)?;
    snapshot
        .pages
        .get(index)
        .cloned()
        .ok_or(OrsError::InvalidCursorLimit)
}

/// Exports a full bounded coherent backup snapshot under one read consistency
/// point.
///
/// The capture point (admitted schema and policy marker, authority lineage and
/// generation, order high-water, canonical dependency fence, and physical table
/// census) is established once and re-verified at close. Every declared row
/// family is read or given an explicit source-bound exclusion, the aggregate
/// byte, page, and work budgets are charged once across the whole capture, the
/// duration budget is a wall-clock deadline over the whole capture, and
/// completeness is never declared from a reference count: the shared member
/// validator must pass before the snapshot is returned.
///
/// Fail-closed preconditions, all owner-established: a store that has never
/// established an authority snapshot has no installation identity and no ORS
/// generation to bind, so it reports
/// [`OrsError::AuthoritySnapshotUnavailable`] rather than exporting under a
/// caller-asserted identity; a store whose base meta carries no admitted schema
/// marker reports [`OrsError::MigrationRequired`]; and a physical row key
/// beyond [`MAX_BACKUP_MEMBER_KEY_BYTES`] fails the capture closed instead of
/// being truncated into a colliding identity.
pub(super) fn export_snapshot(
    database: &Database,
    request: &OrsBackupRequest,
) -> Result<OrsBackupSnapshot, OrsError> {
    if request.max_pages == 0 || request.max_pages > MAX_BACKUP_PAGES {
        return Err(OrsError::InvalidField {
            field: "backup_max_pages",
            reason: "page budget must be within 1 and MAX_BACKUP_PAGES",
        });
    }
    if request.page_entries == 0 || request.page_entries > MAX_BACKUP_PAGE_ENTRIES {
        return Err(OrsError::InvalidCursorLimit);
    }
    capture(database, request)
}

/// The durable resurrection guard consulted before any entry is triaged.
///
/// It is a current-policy and revocation read over durable destination state,
/// never the static family disposition alone: the admitted schema and policy
/// marker, the authority generation in force, durably disposed recovery-inbox
/// identities, unreconciled recovery problems, revoked authority subjects, and
/// revoked grant closures.
struct ResurrectionGuard {
    schema_marker: String,
    current_epoch: u64,
    /// Durable `RECOVERY_INBOX` keys (`item_id`) whose disposition is
    /// `Rejected` or `DeadLetter`, in the recovery-inbox identity space.
    disposed: BTreeSet<String>,
    /// Durable `RECOVERY_PROBLEMS` keys (`operation_or_checkpoint_id`) with no
    /// terminal receipt, in the operation-identity space an entry's `record_id`
    /// already uses for that family.
    unreconciled_problems: BTreeSet<String>,
    /// Authority subjects under a durable `Fenced` revocation.
    revoked_subjects: BTreeSet<String>,
    /// Durably revoked grant-closure operation ids.
    revoked_closures: BTreeSet<String>,
}
impl ResurrectionGuard {
    /// Verifies the destination's own current policy and authority generation
    /// before any per-entry triage, so an import admitted against a stale
    /// policy marker or a fenced epoch is refused as a whole.
    fn destination_verdict(&self, destination: &OrsBackupDestination) -> Option<BackupBlockReason> {
        if destination.destination_policy_marker != self.schema_marker {
            return Some(BackupBlockReason::CurrentPolicyMarkerMismatch {
                declared: destination.destination_policy_marker.clone(),
                current: self.schema_marker.clone(),
            });
        }
        // Exact equality, not `>=`: the destination epoch is a caller-asserted
        // field whose only constructor bound is `!= 0`, so a "greater than
        // current" assertion is unbound and must fail closed. Only the epoch the
        // destination's own durable authority snapshot actually carries may
        // admit an import; anything else would let a caller assert a lineage
        // that never existed here.
        if destination.destination_epoch != self.current_epoch {
            return Some(BackupBlockReason::DestinationEpochBelowCurrent {
                declared: destination.destination_epoch,
                current: self.current_epoch,
            });
        }
        None
    }
    /// Per-entry resurrection verdicts, consulted after the family disposition
    /// and the cryptographic identity check.
    fn verdict(&self, entry: &OrsBackupEntry) -> Option<PerEntryOutcome> {
        // Identity space: a durable inbox disposition is recorded against the
        // `RECOVERY_INBOX` row's physical key, which `RedbRecoveryStore` writes
        // as `record.item.item_id` -- the caller-supplied `OperationIdentity`
        // passed to `RecoveryInboxItem::bind`, which is independent of the
        // envelope's `operation_or_checkpoint_id` and routinely differs from it.
        // A `RecoveryInbox` member's `member_key` is exactly that durable key
        // ("the exact physical durable key this member was read from"), so it is
        // the only entry identity in this guard's own namespace. The check is
        // therefore scoped to that family: `RecoveryInboxHistory` rows are keyed
        // by `"{order:020}:{item_id}"` and are dispositioned `Forensic` before
        // this point, and every other family's member key belongs to a different
        // physical table where the owner never disposed anything.
        if entry.family == RowFamilyKind::RecoveryInbox && self.disposed.contains(&entry.member_key)
        {
            return Some(PerEntryOutcome::Rejected {
                reason: BackupRejectReason::DurablyDisposed {
                    record_id: entry.member_key.clone(),
                },
            });
        }
        if self.unreconciled_problems.contains(&entry.record_id) {
            return Some(PerEntryOutcome::Blocked {
                reason: BackupBlockReason::UnreconciledRecoveryProblem {
                    record_id: entry.record_id.clone(),
                },
            });
        }
        if self.revoked_subjects.contains(&entry.lineage.subject_id) {
            return Some(PerEntryOutcome::Rejected {
                reason: BackupRejectReason::RevokedAuthority {
                    subject_id: entry.lineage.subject_id.clone(),
                },
            });
        }
        if self.revoked_closures.contains(&entry.record_id) {
            return Some(PerEntryOutcome::Rejected {
                reason: BackupRejectReason::RevokedGrantClosure {
                    operation_id: entry.record_id.clone(),
                },
            });
        }
        if entry.lineage.authority_epoch > 0 && entry.lineage.authority_epoch < self.current_epoch {
            return Some(PerEntryOutcome::Rejected {
                reason: BackupRejectReason::FencedAuthorityEpoch {
                    entry_epoch: entry.lineage.authority_epoch,
                    current_epoch: self.current_epoch,
                },
            });
        }
        None
    }
}

/// Builds the quarantine inbox item the current evidence provider must
/// authenticate before any entry is triaged.
///
/// The envelope content digest binds the snapshot digest, the source identity,
/// and the destination's admitted purge-ledger revision, so the provider's
/// admission signature cryptographically covers the exact archive and policy
/// revision the import claims. The payload is an opaque immutable locator: ORS
/// never reads archive bytes and never materializes key material.
fn build_admission_item(
    import: &OrsBackupImportRequest,
    now_ms: i64,
) -> Result<RecoveryInboxItem, OrsError> {
    let binding = format!(
        "{}:{}:{}:{}",
        import.snapshot_digest,
        import.source.installation_id,
        import.destination.purge_ledger_revision,
        import.destination.destination_policy_marker
    );
    let content_sha256 = crate::model::sha256_hex(binding.as_bytes());
    let lineage = EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new(import.destination.destination_lineage_id.clone())?,
            epoch: import.destination.destination_epoch,
        },
        predecessor: None,
    };
    let fence = StateFenceSnapshot::capture(&binding, import.destination.destination_epoch)?;
    let locator = PlatformHandle::new(format!(
        "{BACKUP_ARCHIVE_LOCATOR_PREFIX}{}",
        import.snapshot_digest
    ))
    .map_err(|error| OrsError::Contract(error.to_string()))?;
    let envelope = RecoveryPayloadEnvelope::immutable_locator(
        RecoveryEnvelopeContext {
            operation_or_checkpoint_id: OpaqueLabel::new(format!(
                "backup-import-{}",
                import.destination.admission_receipt
            ))?,
            privacy_and_visibility_class: RecoveryAccessClass {
                privacy: PrivacyClass::Secret,
                visibility: VisibilityClass::new("quarantine")?,
            },
            authority_epoch: lineage,
            state_fence: fence,
            created_at_ms: now_ms,
            known_at_ms: now_ms,
            expires_at_ms: None,
        },
        locator,
        content_sha256,
        u64::try_from(binding.len()).map_err(|_| OrsError::PayloadTooLarge)?,
    )?;
    RecoveryInboxItem::bind(
        envelope.operation_or_checkpoint_id.clone(),
        OpaqueLabel::new(BACKUP_IMPORT_SIGNER)?,
        envelope,
        import.destination.admission_signature.clone(),
        now_ms,
    )
}

/// Reads the current destination resurrection guard under one read transaction.
fn read_resurrection_guard(read: &ReadTransaction) -> Result<ResurrectionGuard, OrsError> {
    let schema_marker = read_meta_marker(read, META_STAGE_RESOLUTION_SCHEMA)?;
    let current_epoch =
        observed_authority(read)?.map_or(0, |record| record.input.authority_epoch.current.epoch);
    let mut disposed = BTreeSet::new();
    {
        let inbox = read.open_table(RECOVERY_INBOX).map_err(storage)?;
        for entry in inbox.iter().map_err(storage)? {
            if disposed.len() as u64 >= IMPORT_SCAN_ROW_CAP {
                return Err(OrsError::ProjectionLimitExceeded);
            }
            let (key, value) = entry.map_err(storage)?;
            let record: DurableInboxRecord = decode_named(value.value(), "recovery_inbox")?;
            if matches!(
                record.disposition,
                RecoveryInboxDisposition::Rejected | RecoveryInboxDisposition::DeadLetter
            ) {
                disposed.insert(key.value().to_owned());
            }
        }
    }
    let mut unreconciled_problems = BTreeSet::new();
    {
        let problems = read.open_table(RECOVERY_PROBLEMS).map_err(storage)?;
        for entry in problems.iter().map_err(storage)? {
            if unreconciled_problems.len() as u64 >= IMPORT_SCAN_ROW_CAP {
                return Err(OrsError::ProjectionLimitExceeded);
            }
            let (key, value) = entry.map_err(storage)?;
            let record: RecoveryProblem = decode_named(value.value(), "recovery_problems")?;
            if record.terminal_receipt_id.is_none() {
                unreconciled_problems.insert(key.value().to_owned());
            }
        }
    }
    let mut revoked_subjects = BTreeSet::new();
    {
        let current = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        for entry in current.iter().map_err(storage)? {
            if revoked_subjects.len() as u64 >= IMPORT_SCAN_ROW_CAP {
                return Err(OrsError::ProjectionLimitExceeded);
            }
            let (key, value) = entry.map_err(storage)?;
            if !key.value().starts_with(AUTHORITY_REVOCATION_PREFIX) {
                continue;
            }
            let record: DurableOperationalRecord =
                decode_named(value.value(), "operational_current")?;
            if record.kind == OperationalKind::AuthorityRevocation
                && record.phase == OperationalPhase::Fenced
            {
                revoked_subjects.insert(
                    key.value()
                        .trim_start_matches(AUTHORITY_REVOCATION_PREFIX)
                        .to_owned(),
                );
            }
        }
    }
    let mut revoked_closures = BTreeSet::new();
    {
        let closures = read.open_table(GRANT_CLOSURE_CURRENT).map_err(storage)?;
        for entry in closures.iter().map_err(storage)? {
            if revoked_closures.len() as u64 >= IMPORT_SCAN_ROW_CAP {
                return Err(OrsError::ProjectionLimitExceeded);
            }
            let (_, value) = entry.map_err(storage)?;
            let record: DurableGrantClosureRecord =
                decode_named(value.value(), "grant_closure_current")?;
            if record.commit.state == GrantClosureState::Revoked {
                revoked_closures.insert(record.commit.operation_id.clone());
            }
        }
    }
    Ok(ResurrectionGuard {
        schema_marker,
        current_epoch,
        disposed,
        unreconciled_problems,
        revoked_subjects,
        revoked_closures,
    })
}

/// Triages one backup page into quarantine without any durable write.
///
/// The import binding is verified, the shared member validator is run against
/// the untrusted page itself, the current canonical evidence provider must
/// authenticate the exact archive admission, and the destination's current
/// policy marker, authority generation, durable dispositions, unreconciled
/// recovery problems, revoked authorities, and revoked grant closures are
/// consulted before each entry is classified. A pre/post
/// [`canonical_state_digest`] freeze check rejects concurrent canonical advance
/// across the page. Unknown stays quarantined with no blind retry; durable
/// quarantine belongs to `import_recovery_inbox`, the existing canonical owner.
pub(super) fn import_page_quarantined(
    database: &Database,
    evidence: &Arc<dyn super::CanonicalEvidenceProvider>,
    import: &OrsBackupImportRequest,
    page: &OrsBackupPage,
) -> Result<Vec<(String, PerEntryOutcome)>, OrsError> {
    validate_import_binding(&import.source, &import.destination)?;
    if !is_digest_shape(&import.snapshot_digest) {
        return Err(OrsError::InvalidField {
            field: "backup_snapshot_digest",
            reason: "snapshot digest must be 64 lowercase hex characters",
        });
    }
    if page.entries.is_empty() {
        return Err(OrsError::InvalidField {
            field: "backup_page_entry_count",
            reason: "an import page must carry at least one member to triage",
        });
    }
    if page.entries.len() > usize::from(MAX_BACKUP_PAGE_ENTRIES) {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    let now_ms = super::current_unix_ms()?;
    if page.expires_at_ms <= now_ms {
        return Err(OrsError::InvalidField {
            field: "backup_page_expires_at_ms",
            reason: "page token expired before this import page was offered",
        });
    }
    let frozen_pre = canonical_state_digest(database)?;
    let read = database.begin_read().map_err(storage)?;
    let guard = read_resurrection_guard(&read)?;
    drop(read);
    if let Some(reason) = guard.destination_verdict(&import.destination) {
        return Ok(blocked_page(page, &reason));
    }
    // A10: the current canonical evidence provider decides admission. A caller
    // boolean and a non-empty admission string are never sufficient.
    let admission = build_admission_item(import, now_ms)?;
    evidence.verify_recovery_inbox(&admission)?;
    // A6: the shared member validator runs on the untrusted page itself, so an
    // entry set that does not match its own page token, chain, counts, digests,
    // or per-family denominator is refused before any entry is triaged.
    OrsBackupSnapshot::for_import_page(import, page)?.validate_members()?;
    let mut outcomes: Vec<(String, PerEntryOutcome)> = Vec::with_capacity(page.entries.len());
    for entry in &page.entries {
        // The outcome key is the unique durable member key; the operation
        // identity stays inside the entry for the canonical owner's exact-replay
        // and changed-payload comparison, because one operation identity can own
        // several history members.
        outcomes.push((
            entry.member_key.clone(),
            triage_entry(database, &guard, entry)?,
        ));
    }
    let frozen_post = canonical_state_digest(database)?;
    check_canonical_frozen(&frozen_pre, &frozen_post)?;
    Ok(outcomes)
}

/// Blocks every member of a page with one typed destination-policy reason.
fn blocked_page(
    page: &OrsBackupPage,
    reason: &BackupBlockReason,
) -> Vec<(String, PerEntryOutcome)> {
    page.entries
        .iter()
        .map(|entry| {
            (
                entry.member_key.clone(),
                PerEntryOutcome::Blocked {
                    reason: reason.clone(),
                },
            )
        })
        .collect()
}

/// Classifies one backup entry against durable state without writing.
///
/// Order is family disposition, then cryptographic identity, then payload
/// availability, then the current resurrection guard, then a bounded identity
/// scan for a changed-payload conflict versus an exact duplicate replay.
/// Everything else stays `Unresolved` for the canonical reconciliation owner.
/// Never activates, never writes.
fn triage_entry(
    database: &Database,
    guard: &ResurrectionGuard,
    entry: &OrsBackupEntry,
) -> Result<PerEntryOutcome, OrsError> {
    match entry.family.disposition() {
        RowDisposition::NonrestorableHistorical => {
            return Ok(PerEntryOutcome::Forensic {
                reason: BackupForensicReason::HistoricalAuthorityRow,
            });
        }
        RowDisposition::ForensicOnly => {
            return Ok(PerEntryOutcome::Forensic {
                reason: BackupForensicReason::ForensicOnlyRow,
            });
        }
        RowDisposition::OutsideAdmittedGeneration => {
            return Ok(PerEntryOutcome::Forensic {
                reason: BackupForensicReason::OutsideAdmittedGeneration,
            });
        }
        RowDisposition::Restorable => {}
    }
    if let Some(reason) = entry.crypto.unknown_reason(&entry.record_id) {
        return Ok(PerEntryOutcome::Blocked { reason });
    }
    if let BackupEntryAvailability::OpaqueUnavailable { cause } = entry.availability {
        return Ok(PerEntryOutcome::Blocked {
            reason: BackupBlockReason::OpaquePayloadUnavailable { cause },
        });
    }
    if let Some(outcome) = guard.verdict(entry) {
        return Ok(outcome);
    }
    let read = database.begin_read().map_err(storage)?;
    let table = read.open_table(OPERATIONAL_HISTORY).map_err(storage)?;
    let mut scanned: u64 = 0;
    let mut conflict: Option<PerEntryOutcome> = None;
    for row in table.iter().map_err(storage)? {
        scanned = scanned
            .checked_add(1)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        if scanned > IMPORT_SCAN_ROW_CAP {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let (_, value) = row.map_err(storage)?;
        let stored: DurableOperationalRecord = decode_named(value.value(), "operational_history")?;
        if stored.input.record_id.as_str() != entry.record_id {
            continue;
        }
        let stored_digest = crate::model::sha256_hex(encode(&stored)?.as_bytes());
        conflict = Some(if stored_digest == entry.payload_digest {
            PerEntryOutcome::Rejected {
                reason: BackupRejectReason::DuplicateReplay,
            }
        } else {
            PerEntryOutcome::Rejected {
                reason: BackupRejectReason::IdentityConflict {
                    record_id: entry.record_id.clone(),
                },
            }
        });
        break;
    }
    drop(table);
    drop(read);
    Ok(conflict.unwrap_or(PerEntryOutcome::Unresolved {
        reason: if entry.effect_class == StoredEffectClass::Unknown {
            BackupUnresolvedReason::UnknownEffectOutcome
        } else {
            BackupUnresolvedReason::AwaitingCanonicalReconciliation
        },
    }))
}

/// Reconciles per-entry quarantine outcomes into one import receipt.
///
/// Binds `import.snapshot_digest`, the source and destination installations, the
/// destination's admitted purge-ledger revision, and the full per-entry outcome
/// vector. The current-owner validation is derived from the triaged outcome
/// vector itself, never from a caller-supplied count, and the production builder
/// then runs [`OrsBackupImportReceipt::known_zero_unresolved`] over it and
/// records that public gate's verdict, so a fabricated zero-unresolved claim
/// cannot be stamped onto a receipt.
pub(super) fn reconcile_import_receipt(
    import: &OrsBackupImportRequest,
    per_entry: &[(String, PerEntryOutcome)],
    import_at_ms: i64,
) -> Result<OrsBackupImportReceipt, OrsError> {
    let unresolved_count = per_entry
        .iter()
        .filter(|(_, outcome)| matches!(outcome, PerEntryOutcome::Unresolved { .. }))
        .count();
    let unresolved_count =
        u64::try_from(unresolved_count).map_err(|_| OrsError::ProjectionLimitExceeded)?;
    let owner_validation =
        derive_owner_validation(import, per_entry, unresolved_count, import_at_ms);
    let mut receipt = OrsBackupImportReceipt::new(
        import.snapshot_digest.clone(),
        import.source.installation_id.clone(),
        import.destination.installation_id.clone(),
        per_entry.to_vec(),
        unresolved_count,
        import_at_ms,
        import.destination.purge_ledger_revision.clone(),
        owner_validation,
    )?;
    let validation = receipt.owner_validation.clone();
    let gate = match receipt.known_zero_unresolved(&validation) {
        Ok(()) => OwnerZeroGate::Satisfied,
        Err(_) => receipt.evaluate_owner_zero_gate(&validation),
    };
    receipt.owner_zero_gate = gate;
    Ok(receipt)
}

/// Derives the current owner validation the receipt's zero claim rests on.
///
/// The validation is computed from the canonical owner's own triaged outcome
/// vector: it covers exactly the entries the owner dispositioned, names every
/// unresolved effect identity, and reports `Partial` whenever an entry is
/// unresolved. It is therefore never a fabricated zero.
fn derive_owner_validation(
    import: &OrsBackupImportRequest,
    per_entry: &[(String, PerEntryOutcome)],
    unresolved_count: u64,
    import_at_ms: i64,
) -> CurrentOwnerValidation {
    let unresolved_effect_identities = per_entry
        .iter()
        .filter(|(_, outcome)| matches!(outcome, PerEntryOutcome::Unresolved { .. }))
        .map(|(record_id, _)| record_id.clone())
        .collect();
    let dispositioned = u64::try_from(per_entry.len())
        .unwrap_or(u64::MAX)
        .saturating_sub(unresolved_count);
    let mut material = String::new();
    material.push_str(&import.snapshot_digest);
    material.push(':');
    material.push_str(&import.source.installation_id);
    material.push(':');
    material.push_str(&import.destination.installation_id);
    material.push(':');
    material.push_str(&import.destination.purge_ledger_revision);
    material.push(':');
    material.push_str(&unresolved_count.to_string());
    CurrentOwnerValidation {
        snapshot_digest: import.snapshot_digest.clone(),
        owner_id: format!("canonical-reconciliation-owner-{BACKUP_IMPORT_SIGNER}"),
        validated_at_ms: import_at_ms,
        validated_entry_count: dispositioned,
        unresolved_effect_identities,
        provider_digest: crate::model::sha256_hex(material.as_bytes()),
        // The owner could not validate an entry it could not resolve, so the
        // validation is not `Complete` whenever an entry is unresolved. Stamping
        // `Complete` there would make the gate's `disposition != Complete`
        // refusal branch vacuous on the production path and would assert a
        // coverage the receipt's own outcome vector contradicts. The gate still
        // refuses either way, so the refusal set is unchanged; only the exact
        // typed blocker moves to the honest one.
        disposition: if unresolved_count == 0 {
            OwnerValidationDisposition::Complete
        } else {
            OwnerValidationDisposition::Partial
        },
    }
}

/// Replays a lost import response without any duplicate effect.
///
/// Returns an idempotent copy of the prior receipt whose zero-unresolved gate is
/// re-evaluated from the receipt's own recorded current-owner validation. No
/// store read, no store write, no re-triage, so a retried response can never
/// double-apply quarantine outcomes and can never carry a zero claim the gate
/// would refuse.
pub(super) fn reconcile_lost_import_response(
    prior: &OrsBackupImportReceipt,
) -> OrsBackupImportReceipt {
    let mut replay = prior.clone();
    let validation = replay.owner_validation.clone();
    replay.owner_zero_gate = replay.evaluate_owner_zero_gate(&validation);
    replay
}
