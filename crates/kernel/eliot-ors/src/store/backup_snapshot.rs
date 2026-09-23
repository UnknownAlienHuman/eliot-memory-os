//! Quarantined backup-snapshot store projection (issue #953, writer B).
//!
//! ORS-owned backup export reads and quarantined backup import triage. This
//! module never activates authority, never advances canonical ordering, never
//! copies a live redb file, never touches the filesystem, and never emits raw
//! payload bytes: export carries digests plus identity metadata, and import
//! returns per-entry outcomes without writing any authority table.
//!
//! Invariants (I05-13 / I05-27 / I14-21 / I07-20):
//! - Every restored item imports as `suspended_recovery`, never runnable
//!   authority; old sessions, leases, routes, and grants are never activated.
//! - Operation/effect identity is preserved: key reuse with a different hash
//!   reports `IDENTITY_CONFLICT` instead of overwriting.
//! - Unknown items stay quarantined; there is no blind retry and no durable
//!   write in the triage path. Durable quarantine belongs to the existing
//!   canonical reconciliation owner via `import_recovery_inbox`, not here.
//! - Disposition failures use stable [`crate::OrsError`] variants.
//!
//! Writer-A API (crate root `backup_snapshot`, read here as evidence):
//! request fields `after_order: u64`, `page_entries: u16`, `max_bytes: u64`,
//! `max_pages: u16`, `source`, `fence`, plus `page_fence_token(&self) ->
//! String`; entry fields `record_id`, `family`, `order`, `payload_digest`,
//! `effect_class`; page fields `page_index`, `entries`, `page_digest`,
//! `is_last`; snapshot fields `source`, `fence`, `pages`,
//! `denominator_digest`, `entry_count`, `total_bytes`, `completeness`, plus
//! `snapshot_digest()` and `validate()`; `RowFamilyKind::disposition()` is the
//! single static policy and `RowFamilyDisposition::of(kind)` binds it;
//! `StoredEffectClass::{Staged, Possible, Unknown, Terminal}`;
//! `PerEntryOutcome::{Imported, Rejected, Forensic, Blocked, Unresolved}`;
//! import request fields `snapshot_digest`/`source`/`destination`; receipt
//! built via `OrsBackupImportReceipt::new(...)`; `validate_import_binding`
//! rejects same-installation or unbound-evidence imports;
//! `check_canonical_frozen(pre, post)` rejects any head advance across the
//! window. `PerEntryOutcome::Imported` is intentionally never constructed
//! here: nothing is imported by triage; durable import belongs to the
//! canonical owner.
//!
//! Policy delta for the manager: writer A's static `disposition()` maps
//! `UnknownCommitRecovery`/`RecoveryProblems` to `ForensicOnly` and the
//! history/result/journal-result families to `NonrestorableHistorical`, which
//! differs from the task brief's mapping (unknown/recovery-problems/journal
//! restorable). This module delegates to writer A's policy via `::of()` so
//! there is exactly one source of truth; both mappings still only ever land
//! `Forensic` or quarantined `Unresolved` here, never authority.

use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable};

use super::persistence_codec::{decode_named, encode};
use super::persistence_models::DurableOperationalRecord;
use super::storage;
use crate::backup_snapshot::{
    BackupCompleteness, MAX_BACKUP_BYTES, MAX_BACKUP_PAGE_ENTRIES, OrsBackupEntry,
    OrsBackupImportReceipt, OrsBackupImportRequest, OrsBackupPage, OrsBackupRequest,
    OrsBackupSnapshot, PerEntryOutcome, RowDisposition, RowFamilyDisposition, RowFamilyKind,
    StoredEffectClass, check_canonical_frozen, validate_import_binding,
};
use crate::{OperationalPhase, OrsError};

/// Bounded full-scan cap for the identity-conflict lookup and the canonical
/// freeze digest. Keeps quarantine reads from becoming unbounded scans;
/// exceeding it fails closed instead of truncating silently.
const IMPORT_SCAN_ROW_CAP: u64 = 1_048_576;

/// Exact per-family backup disposition for every ORS row family.
///
/// Built from writer A's static [`RowFamilyKind::disposition`] policy so the
/// contract module stays the single source of truth; the trailing comment on
/// each entry records the restore-safety reason. `Restorable` means eligible
/// for quarantined re-import as `suspended_recovery` only, never runnable
/// authority.
pub(super) fn row_family_denominator() -> Vec<RowFamilyDisposition> {
    vec![
        // Canonical operation evidence, re-imported suspended only.
        RowFamilyDisposition::of(RowFamilyKind::OperationalHistory),
        // Current heads are evidence snapshots, never live authority.
        RowFamilyDisposition::of(RowFamilyKind::OperationalCurrent),
        // Reservation rows re-stage as pending, never executing.
        RowFamilyDisposition::of(RowFamilyKind::Reservations),
        // Ordering index without execution meaning.
        RowFamilyDisposition::of(RowFamilyKind::ReservationOrders),
        // Opaque envelopes re-imported without interpretation.
        RowFamilyDisposition::of(RowFamilyKind::Envelopes),
        // Ordering observations, canonical owner re-verifies.
        RowFamilyDisposition::of(RowFamilyKind::ScopeHeads),
        // Terminal observations, never fresh heads.
        RowFamilyDisposition::of(RowFamilyKind::ScopeTerminals),
        // Inbox items re-enter via the canonical import owner.
        RowFamilyDisposition::of(RowFamilyKind::RecoveryInbox),
        // Inbox history is evidence, never disposition.
        RowFamilyDisposition::of(RowFamilyKind::RecoveryInboxHistory),
        // Start intents replay as unknown, never running.
        RowFamilyDisposition::of(RowFamilyKind::ProcessStartReplay),
        // Past handoffs never re-fence authority.
        RowFamilyDisposition::of(RowFamilyKind::AuthorityHandoffs),
        // Process evidence is observational only.
        RowFamilyDisposition::of(RowFamilyKind::ProcessEvidence),
        // Staged lease tickets never execute on restore.
        RowFamilyDisposition::of(RowFamilyKind::SupervisionLeaseStaged),
        // Lease heads are evidence; old leases never activate.
        RowFamilyDisposition::of(RowFamilyKind::SupervisionLeaseCurrent),
        // Lease history is audit evidence only.
        RowFamilyDisposition::of(RowFamilyKind::SupervisionLeaseHistory),
        // Lease results re-verify, never apply.
        RowFamilyDisposition::of(RowFamilyKind::SupervisionLeaseResults),
        // Stage resolutions are historical facts.
        RowFamilyDisposition::of(RowFamilyKind::SupervisionStageResolutions),
        // Local rebind debugging state, never restored as data.
        RowFamilyDisposition::of(RowFamilyKind::StoreRebindReplay),
        // Local failure retention, never restored as data.
        RowFamilyDisposition::of(RowFamilyKind::StoreFailureRetention),
        // Unknown stays quarantined, no blind retry.
        RowFamilyDisposition::of(RowFamilyKind::UnknownCommitRecovery),
        // Old cutover ownership never re-owns.
        RowFamilyDisposition::of(RowFamilyKind::CutoverOwnership),
        // Old host routes never re-dispatch.
        RowFamilyDisposition::of(RowFamilyKind::HostRequests),
        // Old activation results never re-acknowledge.
        RowFamilyDisposition::of(RowFamilyKind::ActivationResultRetention),
        // Old worker claims never re-admit.
        RowFamilyDisposition::of(RowFamilyKind::NativeWorkerClaims),
        // Replay state replays suspended, never drives workers.
        RowFamilyDisposition::of(RowFamilyKind::ReplayStreams),
        // Replay acquisitions re-resolve, never execute.
        RowFamilyDisposition::of(RowFamilyKind::ReplayRequests),
        // Replay events are evidence, never commands.
        RowFamilyDisposition::of(RowFamilyKind::ReplayEvents),
        // Acknowledgements are historical facts.
        RowFamilyDisposition::of(RowFamilyKind::ReplayAcks),
        // Diagnostic attempts are evidence only.
        RowFamilyDisposition::of(RowFamilyKind::DoctorAttempts),
        // Diagnostic effects are evidence only.
        RowFamilyDisposition::of(RowFamilyKind::DoctorEffects),
        // Budget ledgers re-verify, never spend.
        RowFamilyDisposition::of(RowFamilyKind::DoctorBudgets),
        // Visible problems stay visible across restore.
        RowFamilyDisposition::of(RowFamilyKind::RecoveryProblems),
        // Closure rows are committed facts, never grants.
        RowFamilyDisposition::of(RowFamilyKind::GrantClosureCurrent),
        // Revision watermarks re-advance only forward.
        RowFamilyDisposition::of(RowFamilyKind::GrantGraphRevisionCurrent),
        // Journal intents replay idempotently.
        RowFamilyDisposition::of(RowFamilyKind::RestoreJournalIntents),
        // Journal results are historical answers.
        RowFamilyDisposition::of(RowFamilyKind::RestoreJournalResults),
        // Journal meta is linkage evidence.
        RowFamilyDisposition::of(RowFamilyKind::RestoreJournalMeta),
    ]
}

/// Maps a durable phase to its backup effect class.
///
/// Committed or terminal phases export as `Terminal`, staged rows as
/// `Staged`, and in-flight rows as `Possible`. `Unknown` is never produced by
/// export (unknown-commit rows live outside `OPERATIONAL_HISTORY`); it is the
/// import-triage class for entries that stay reconciling.
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

/// Deterministic digest over durable operational-history state.
///
/// Binds `(order, record-bytes digest)` pairs in order under one read
/// transaction. Used as the pre/post canonical-freeze witness: any canonical
/// advance between the two observations fails the import/export with
/// [`OrsError::OrderingHeadMismatch`] instead of tearing the snapshot.
fn canonical_state_digest(database: &Database) -> Result<String, OrsError> {
    let read = database.begin_read().map_err(storage)?;
    let table = read
        .open_table(super::OPERATIONAL_HISTORY)
        .map_err(storage)?;
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
    drop(read);
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

/// Exports one coherent backup page under a single read transaction.
///
/// `page_index` binds `after_order + page_entries * page_index`: the window
/// start moves by exactly one page stride per index, so pages exported from
/// independent calls with different fence tokens are NOT one snapshot.
/// Callers building a snapshot must reuse the same request (same fence
/// token) across pages; [`export_snapshot`] enforces this by issuing every
/// page itself. Any row decode failure returns [`OrsError::IntegrityProblem`];
/// a page is never fabricated from reference counts alone. Accumulated entry
/// bytes are bounded by `request.max_bytes` (already `1..=MAX_BACKUP_BYTES`
/// by the request constructor).
pub(super) fn export_page(
    database: &Database,
    request: &OrsBackupRequest,
    page_index: u32,
) -> Result<OrsBackupPage, OrsError> {
    if request.page_entries == 0 {
        return Err(OrsError::InvalidField {
            field: "backup.page_entries",
            reason: "page size must be non-zero",
        });
    }
    if usize::from(request.page_entries) > usize::from(MAX_BACKUP_PAGE_ENTRIES) {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    if request.max_bytes == 0 || request.max_bytes > MAX_BACKUP_BYTES {
        return Err(OrsError::InvalidField {
            field: "backup_max_bytes",
            reason: "byte budget must be within 1 and MAX_BACKUP_BYTES",
        });
    }
    let fence_token = request.page_fence_token();
    let stride = u64::from(request.page_entries)
        .checked_mul(u64::from(page_index))
        .ok_or(OrsError::InvalidField {
            field: "backup.page_index",
            reason: "page window overflows the operation order",
        })?;
    let window_start = request
        .after_order
        .checked_add(stride)
        .ok_or(OrsError::InvalidField {
            field: "backup.page_index",
            reason: "page window overflows the operation order",
        })?;
    // ONE read transaction: the page is coherent by construction.
    let read = database.begin_read().map_err(storage)?;
    let table = read
        .open_table(super::OPERATIONAL_HISTORY)
        .map_err(storage)?;
    let mut selected: Vec<(u64, DurableOperationalRecord, String)> = Vec::new();
    for entry in table.iter().map_err(storage)? {
        let (_, value) = entry.map_err(storage)?;
        let record: DurableOperationalRecord = decode_named(value.value(), "operational_history")?;
        if record.operation_order > window_start {
            let encoded = encode(&record)?;
            selected.push((record.operation_order, record, encoded));
        }
    }
    drop(table);
    drop(read);
    selected.sort_by_key(|(order, _, _)| *order);
    selected.truncate(usize::from(request.page_entries));
    let mut entries: Vec<OrsBackupEntry> = Vec::with_capacity(selected.len());
    let mut total_bytes: u64 = 0;
    for (order, record, encoded) in selected {
        let encoded_len = u64::try_from(encoded.len()).map_err(|_| OrsError::PayloadTooLarge)?;
        total_bytes = total_bytes
            .checked_add(encoded_len)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        if total_bytes > request.max_bytes {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        entries.push(OrsBackupEntry {
            record_id: record.input.record_id.as_str().to_owned(),
            family: RowFamilyKind::OperationalHistory,
            order,
            payload_digest: crate::model::sha256_hex(encoded.as_bytes()),
            effect_class: effect_class_for_export(record.phase),
        });
    }
    let is_last = entries.len() < usize::from(request.page_entries);
    let mut digest_material = String::new();
    for entry in &entries {
        digest_material.push_str(&entry.payload_digest);
    }
    digest_material.push_str(&fence_token);
    let page_digest = crate::model::sha256_hex(digest_material.as_bytes());
    Ok(OrsBackupPage {
        page_index,
        entries,
        page_digest,
        is_last,
    })
}

/// Exports a full snapshot by paging with one request until `is_last`.
///
/// The same request (same fence token, same `after_order`, same page size)
/// issues every page, so `page_index * page_entries` continuity holds by
/// construction. A pre/post [`canonical_state_digest`] freeze check rejects
/// any canonical advance that lands mid-export with
/// [`OrsError::OrderingHeadMismatch`] instead of tearing the snapshot.
/// Exceeding `request.max_pages` fails with
/// [`OrsError::ProjectionLimitExceeded`]. Completeness is `Complete` only
/// when every page decoded cleanly and at least one entry landed; an empty
/// denominator reports `Partial` with a reason, and a decode failure reports
/// [`OrsError::IntegrityProblem`], never a fabricated `Complete`. The
/// denominator digest is the snapshot's own `snapshot_digest()` binding.
pub(super) fn export_snapshot(
    database: &Database,
    request: &OrsBackupRequest,
) -> Result<OrsBackupSnapshot, OrsError> {
    if request.max_pages == 0 {
        return Err(OrsError::InvalidField {
            field: "backup_max_pages",
            reason: "page budget must be non-zero",
        });
    }
    let frozen_pre = canonical_state_digest(database)?;
    let mut pages: Vec<OrsBackupPage> = Vec::new();
    let mut entry_count: u64 = 0;
    for index in 0..request.max_pages {
        let page = export_page(database, request, u32::from(index))?;
        entry_count = entry_count
            .checked_add(page.entries.len() as u64)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        let done = page.is_last;
        pages.push(page);
        if done {
            break;
        }
    }
    if pages.is_empty() || !pages.last().is_some_and(|page| page.is_last) {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    let frozen_post = canonical_state_digest(database)?;
    check_canonical_frozen(&frozen_pre, &frozen_post)?;
    // Byte budget is re-summed from the pages so the snapshot total is a
    // function of observed rows, never of a declared count alone. Entries
    // carry digests only (no raw bytes cross the boundary), so the total
    // counts carried digest-material bytes: a deterministic transport-budget
    // floor, not the store-side encoded size.
    let mut total_bytes: u64 = 0;
    for page in &pages {
        for entry in &page.entries {
            total_bytes = total_bytes
                .checked_add(entry.payload_digest.len() as u64)
                .ok_or(OrsError::ProjectionLimitExceeded)?;
        }
    }
    let completeness = if entry_count > 0 {
        BackupCompleteness::Complete
    } else {
        BackupCompleteness::Partial {
            reason: "snapshot denominator is empty; no rows above after_order".to_owned(),
        }
    };
    let mut snapshot = OrsBackupSnapshot {
        source: request.source.clone(),
        fence: request.fence.clone(),
        pages,
        denominator_digest: String::new(),
        entry_count,
        total_bytes,
        completeness,
    };
    snapshot.denominator_digest = snapshot.snapshot_digest();
    Ok(snapshot)
}

/// Triages one backup page into quarantine without any durable write.
///
/// Verifies the import binding, then classifies each entry: non-restorable
/// or forensic-only families land `Forensic` and are never activated;
/// malformed digests land `Blocked`; a stored row with the same digest
/// replays as `Rejected` (duplicate) while the same key with a different
/// hash lands `Blocked` with `IDENTITY_CONFLICT`; anything else lands
/// `Unresolved`, quarantined for the canonical owner. A pre/post
/// [`canonical_state_digest`] freeze check rejects concurrent canonical
/// advance across the page. Per-entry canonical evidence calls are
/// deliberately skipped: there is no signed inbox item here to verify, so
/// verification is deferred to `import_recovery_inbox`, which owns durable
/// quarantine. Unknown stays quarantined with no blind retry. Page-to-review
/// snapshot binding is re-established by the canonical owner from
/// `import.snapshot_digest` at reconcile time; pages carry no snapshot field.
pub(super) fn import_page_quarantined(
    database: &Database,
    evidence: &Arc<dyn super::CanonicalEvidenceProvider>,
    import: &OrsBackupImportRequest,
    page: &OrsBackupPage,
) -> Result<Vec<(String, PerEntryOutcome)>, OrsError> {
    let _ = evidence;
    validate_import_binding(&import.source, &import.destination)?;
    if !is_digest_shape(&page.page_digest) {
        return Err(OrsError::InvalidField {
            field: "backup.page_digest",
            reason: "page digest must be 64 lowercase hex characters",
        });
    }
    if page.entries.len() > usize::from(MAX_BACKUP_PAGE_ENTRIES) {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    let frozen_pre = canonical_state_digest(database)?;
    let mut outcomes: Vec<(String, PerEntryOutcome)> = Vec::with_capacity(page.entries.len());
    for entry in &page.entries {
        outcomes.push((entry.record_id.clone(), triage_entry(database, entry)?));
    }
    let frozen_post = canonical_state_digest(database)?;
    check_canonical_frozen(&frozen_pre, &frozen_post)?;
    Ok(outcomes)
}

/// Classifies one backup entry against durable state without writing.
///
/// Pure read path shared by [`import_page_quarantined`]: family disposition
/// first (forensic families never reach identity comparison), digest shape
/// second, then a bounded identity scan for `IDENTITY_CONFLICT` versus
/// duplicate replay. Returns the outcome; never activates, never writes.
fn triage_entry(database: &Database, entry: &OrsBackupEntry) -> Result<PerEntryOutcome, OrsError> {
    match entry.family.disposition() {
        RowDisposition::NonrestorableHistorical => {
            return Ok(PerEntryOutcome::Forensic {
                reason: "historical session/lease/route/grant row is never re-activated".to_owned(),
            });
        }
        RowDisposition::ForensicOnly => {
            return Ok(PerEntryOutcome::Forensic {
                reason: "forensic-only row never crosses a restore boundary".to_owned(),
            });
        }
        RowDisposition::Restorable => {}
    }
    if !is_digest_shape(&entry.payload_digest) {
        return Ok(PerEntryOutcome::Blocked {
            reason: "entry payload digest must be 64 lowercase hex characters".to_owned(),
        });
    }
    let read = database.begin_read().map_err(storage)?;
    let table = read
        .open_table(super::OPERATIONAL_HISTORY)
        .map_err(storage)?;
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
        if stored_digest == entry.payload_digest {
            conflict = Some(PerEntryOutcome::Rejected {
                reason: "duplicate entry already durably stored".to_owned(),
            });
        } else {
            conflict = Some(PerEntryOutcome::Blocked {
                reason: "IDENTITY_CONFLICT: key reuse with a different hash".to_owned(),
            });
        }
        break;
    }
    drop(table);
    drop(read);
    Ok(conflict.unwrap_or(PerEntryOutcome::Unresolved {
        reason: "quarantined for the canonical owner; no authority conferred".to_owned(),
    }))
}

/// Reconciles per-entry quarantine outcomes into one import receipt.
///
/// Binds `import.snapshot_digest` with the source/destination installations
/// and the full per-entry outcome vector via
/// [`OrsBackupImportReceipt::new`], which validates every shape. Emits no
/// store writes: receipt building is a pure function over already-triaged
/// outcomes.
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
    OrsBackupImportReceipt::new(
        import.snapshot_digest.clone(),
        import.source.installation_id.clone(),
        import.destination.installation_id.clone(),
        per_entry.to_vec(),
        unresolved_count,
        import_at_ms,
    )
}

/// Replays a lost import response without any duplicate effect.
///
/// Returns an idempotent clone of the prior receipt: pure value copy, no
/// store read, no store write, no re-triage, so a retried response can never
/// double-apply quarantine outcomes.
pub(super) fn reconcile_lost_import_response(
    prior: &OrsBackupImportReceipt,
) -> OrsBackupImportReceipt {
    prior.clone()
}
