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
//!
//! Issue #269 adds the process-stream recovery family to that denominator.
//! `RowFamilyKind::ProcessStreamRecovery` carries the `ors_process_stream_recovery_v1`
//! family — durable key, digest of the row encoded through the existing ORS
//! codec, and an activation-derived effect class — so a backup can no longer
//! drop those rows silently. Its durable import stays
//! `import_process_stream_recovery_suspended`, which writes suspended recovery
//! evidence only, so triage here still never returns
//! `PerEntryOutcome::Imported` and never revives process, session or authority
//! state.
//!
//! Issue #2884 replaces #269's "carry the whole family on the final page" with a
//! typed, owner-bound family cursor. That shape was a durable availability
//! defect: the family was materialised whole and then required to fit the unused
//! slots of one operational page under a hard 256-entry ceiling, so a retained
//! family of 257 rows made every backup fail permanently and permanently, and
//! the pre/post freeze digest covered operational history only, so a family row
//! could move between pages unnoticed.
//!
//! What replaced it:
//! - `RedbRecoveryStore::open_backup_process_stream_recovery_family` freezes the
//!   family once - durable revision plus streamed content root - and returns the
//!   start of an [`OrsFamilyCursor`].
//! - The family is enumerated in its own durable-key order, charging the row and
//!   byte budget per row as it goes. No helper on this path collects the table
//!   before applying limits, so a ten-thousand-row family exports through
//!   bounded continuation at the unchanged per-page ceiling.
//! - Every family page re-observes the frozen durable revision and re-derives
//!   the emitted key prefix from live durable state, so a caller cannot choose
//!   the boundary and no row can leave the denominator silently.
//! - Exhausting the page or byte budget is a resumable `Partial` disposition
//!   carrying the exact next family cursor, not a permanent refusal.
//! - The composite pre/post freeze covers operational history *and* the family
//!   revision and root, and both are folded into the page token and the
//!   snapshot denominator.
//! - Retirement advances the durable family revision in the family's one write
//!   path, so an in-progress export observes it as typed movement.
//! - No row is compacted: `Active`, `Suspended`, partial, unavailable, unknown
//!   and not-yet-handed-off evidence are all exported, and a row that cannot be
//!   decoded or does not fit the declared budget is refused with its own exact
//!   identity rather than dropped.
//! - A request that declares no family cursor yields a snapshot with no family
//!   denominator, which [`OrsBackupSnapshot::validate`] can never accept as
//!   `Complete`. Legacy evidence is partial evidence, not an empty family.
//!
//! Issue #2883 adds the durable `backup.verify` result family to that same
//! denominator. `RowFamilyKind::BackupVerificationResults` is one row per distinct
//! `(principal, authority lineage, operation id)` within one installation's ORS
//! file, and it is now DECLARED in this EXISTING ORS operational retention/export
//! contract, which is the existing owner of its lifecycle. Be precise about what
//! that declaration is worth: `row_family_denominator` has NO production reader in
//! this tree, on this branch and on `origin/main`, so nothing yet COUNTS the family
//! and nothing bounds it. Its real cardinality is one row per distinct
//! `(principal, authority lineage, operation id)`, plus one quarantined row per
//! pre-#2883 caller key. No eviction, TTL, cap or deletion is added here, and the
//! bounded-retirement work stays with the separate ORS retention owner. The
//! family's disposition delegates to [`RowFamilyKind::disposition`], which routes
//! it to `ForensicOnly` alongside the `UnknownCommitRecovery` sibling, so an
//! exported row lands as forensics and never as an importable answer.

use std::fmt::Write as _;
use std::ops::Bound;
use std::sync::Arc;

use redb::{Database, ReadTransaction, ReadableDatabase, ReadableTable};

use super::persistence_codec::{decode, decode_named, encode};
use super::persistence_models::DurableOperationalRecord;
use super::storage;
use crate::backup_snapshot::{
    BackupCompleteness, MAX_BACKUP_BYTES, MAX_BACKUP_PAGE_ENTRIES, OrsBackupEntry,
    OrsBackupImportReceipt, OrsBackupImportRequest, OrsBackupPage, OrsBackupRequest,
    OrsBackupSnapshot, OrsFamilyContinuation, OrsFamilyCursor, OrsFamilyRowChain,
    OrsFamilySnapshotIdentity, PerEntryOutcome, RowDisposition, RowFamilyDisposition,
    RowFamilyKind, StoredEffectClass, check_canonical_frozen, validate_import_binding,
};
use crate::{
    OperationalPhase, OrsError, ProcessStreamRecoveryProjection, StreamRecoveryActivation,
};

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
        // Process-stream recovery re-imports as suspended evidence only, never
        // a live process, session or authority owner (#269).
        RowFamilyDisposition::of(RowFamilyKind::ProcessStreamRecovery),
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
        // Old activation lifecycles never re-authorize a claim or Session.
        RowFamilyDisposition::of(RowFamilyKind::ActivationLifecycle),
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
        // Scan disclosure receipts are evidence, never live scan state (#2900).
        RowFamilyDisposition::of(RowFamilyKind::ScanDisclosure),
        // Owner-backed verification results are evidence, never authority: this
        // family is DECLARED in the EXISTING ORS operational retention/export
        // contract here (#2883 instruction 10), which is that contract's own
        // lifecycle owner. Be precise about what the declaration buys: this
        // function has NO production reader in this tree, so nothing yet counts
        // the family and nothing bounds it. No eviction, TTL, cap or deletion is
        // added; the real cardinality is one row per distinct
        // `(principal, authority lineage, operation id)` within one installation's
        // ORS file, plus one quarantined row per pre-#2883 caller key, and bounded
        // retirement stays with the separate ORS retention owner. Its
        // `ForensicOnly` disposition is the `UnknownCommitRecovery` sibling's, and
        // the reason is that this family has no `import_*_suspended` path at all —
        // `Restorable` would advertise a durable re-import that does not exist, so
        // a restored installation can never read a prior installation's
        // verification answer back as its own.
        RowFamilyDisposition::of(RowFamilyKind::BackupVerificationResults),
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

/// Maps a durable process-stream recovery activation to its backup effect
/// class.
///
/// An `Active` projection is in-flight recovery evidence (`Possible`),
/// `Suspended` — the state the quarantined import always writes — is not yet
/// committed for the destination (`Staged`), and `Retired` is terminal
/// (`Terminal`). `Unknown` is never produced here: an unreadable or
/// codec-incompatible row fails the export rather than being classified as
/// reconciling, so no backup ever asserts an unknown outcome it did not read.
fn effect_class_for_stream_recovery(activation: StreamRecoveryActivation) -> StoredEffectClass {
    match activation {
        StreamRecoveryActivation::Active => StoredEffectClass::Possible,
        StreamRecoveryActivation::Suspended => StoredEffectClass::Staged,
        StreamRecoveryActivation::Retired => StoredEffectClass::Terminal,
    }
}

/// The family's own order value for one exported recovery entry.
///
/// The process-stream recovery family has no operation order, so its entry
/// `order` is the row's own observation time in Unix milliseconds — a real
/// retained field, not a synthesized rank. It is a reporting/ordering value
/// only: selection is by the family's own durable-key order through
/// [`OrsFamilyCursor`], never by this value and never by the shared
/// `after_order` window, which is exactly why observation time may repeat here
/// without dropping or duplicating a row. The projection's fail-closed
/// `validate()` already rejects a non-positive observation time, so a
/// non-representable value can only mean the row bypassed that gate.
fn stream_recovery_entry_order(
    projection: &ProcessStreamRecoveryProjection,
) -> Result<u64, OrsError> {
    u64::try_from(projection.observed_at_ms).map_err(|_| OrsError::IntegrityProblem {
        record_type: "process_stream_recovery",
        reason: "observation time is not a representable backup order".to_owned(),
    })
}

/// One bounded read of the whole process-stream recovery family: the streamed
/// content root plus the observed size, with nothing retained.
struct ProcessStreamFamilyRoot {
    /// Chained content root over the family's durable keys and encoded rows.
    root_digest: String,
    /// Retained rows observed.
    row_count: u64,
    /// Summed encoded row bytes observed.
    total_bytes: u64,
}

/// Computes the process-stream recovery family's content root in one streaming
/// pass.
///
/// Each row is folded into an [`OrsFamilyRowChain`] link and then dropped, so
/// the pass costs a constant amount of memory no matter how many rows the family
/// retains: a ten-thousand-row family is hashed, not collected. The root binds
/// the family's total durable-key order and every row's encoded bytes, so it
/// moves on an insert, an evidence advance and a retirement alike.
///
/// This is the frozen owner snapshot identity, not page enumeration: it runs
/// once when a family cursor is opened and once per pre/post freeze check, never
/// once per page. It is bounded by [`IMPORT_SCAN_ROW_CAP`] and fails closed
/// rather than certifying a truncated family as complete.
fn stream_recovery_family_root(
    table: &redb::ReadOnlyTable<&str, &str>,
) -> Result<ProcessStreamFamilyRoot, OrsError> {
    let mut chain = OrsFamilyRowChain::start(RowFamilyKind::ProcessStreamRecovery);
    let mut row_count: u64 = 0;
    let mut total_bytes: u64 = 0;
    for row in table.iter().map_err(storage)? {
        if row_count >= IMPORT_SCAN_ROW_CAP {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let (key, value) = row.map_err(storage)?;
        let encoded = value.value().as_bytes();
        row_count = row_count
            .checked_add(1)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        total_bytes = total_bytes
            .checked_add(encoded.len() as u64)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        chain.advance_row(key.value(), &crate::model::sha256_hex(encoded));
    }
    Ok(ProcessStreamFamilyRoot {
        root_digest: chain.link().to_owned(),
        row_count,
        total_bytes,
    })
}

/// Reads the durable family revision and the family's content root under one
/// read transaction, so the frozen identity can never mix two moments.
fn process_stream_recovery_family_identity(
    read: &ReadTransaction,
) -> Result<OrsFamilySnapshotIdentity, OrsError> {
    let family_revision = super::RedbRecoveryStore::process_stream_recovery_family_revision(read)?;
    let root = {
        let table = read
            .open_table(super::PROCESS_STREAM_RECOVERY)
            .map_err(storage)?;
        let root = stream_recovery_family_root(&table)?;
        drop(table);
        root
    };
    OrsFamilySnapshotIdentity::new(
        RowFamilyKind::ProcessStreamRecovery,
        family_revision,
        root.root_digest,
        root.row_count,
        root.total_bytes,
    )
}

/// Opens the typed family cursor for the live process-stream recovery family.
///
/// The one producer of an [`OrsFamilyCursor`]: the cursor can only be born from
/// the owner's own durable revision and content root, so a caller cannot mint a
/// family snapshot and therefore cannot choose where a family page starts.
pub(super) fn open_process_stream_recovery_family(
    database: &Database,
) -> Result<OrsFamilyCursor, OrsError> {
    let read = database.begin_read().map_err(storage)?;
    let identity = process_stream_recovery_family_identity(&read)?;
    drop(read);
    OrsFamilyCursor::start(identity)
}

/// Refuses a family page whose family moved after the backup froze it.
///
/// The check is a comparison against live owner state, the same shape as the
/// owner-bound snapshot handle in the store API: the frozen revision in the
/// cursor is compared with the durable revision this write transaction actually
/// observed, and any difference is [`OrsError::ProcessStreamRecoveryFamilyMoved`]
/// — the movement/restart disposition. It fires for an insert, an evidence
/// advance, a revalidation and a retirement alike, because the family's single
/// write path advances the revision in the same transaction as the row change.
///
/// The fast path reads one meta key. The observed content root is recomputed
/// only on the refusal branch, where the extra pass buys exact evidence for the
/// operator instead of costing every page of a healthy export.
fn check_family_revision_frozen(
    read: &ReadTransaction,
    cursor: &OrsFamilyCursor,
) -> Result<(), OrsError> {
    let observed_revision =
        super::RedbRecoveryStore::process_stream_recovery_family_revision(read)?;
    if observed_revision == cursor.identity.family_revision {
        return Ok(());
    }
    let observed_root_digest = {
        let table = read
            .open_table(super::PROCESS_STREAM_RECOVERY)
            .map_err(storage)?;
        let root = stream_recovery_family_root(&table)?;
        drop(table);
        root.root_digest
    };
    Err(OrsError::ProcessStreamRecoveryFamilyMoved {
        frozen_revision: cursor.identity.family_revision,
        observed_revision,
        frozen_root_digest: cursor.identity.family_root_digest.clone(),
        observed_root_digest,
        after_key: cursor.after_key.clone(),
    })
}

/// Proves that a presented family cursor names exactly the durable-key prefix
/// the owner already emitted.
///
/// The boundary is not authenticated by shape, because every field of a
/// presented cursor is observable. Instead the emitted-prefix chain is
/// re-derived from live durable state and the walk stops the instant the
/// presented row count is reached, so the cost is the prefix the owner already
/// exported and the memory is constant — nothing is collected. A cursor whose
/// chain, offset or last key disagrees with durable state is
/// [`OrsError::ProcessStreamRecoveryFamilyCursorMismatch`]; a caller therefore
/// cannot present a later key under an earlier offset and silently drop the rows
/// in between out of the denominator.
fn check_family_cursor_boundary(
    table: &redb::ReadOnlyTable<&str, &str>,
    cursor: &OrsFamilyCursor,
) -> Result<(), OrsError> {
    let mut chain = OrsFamilyRowChain::start(cursor.identity.family);
    let mut emitted: u64 = 0;
    let mut durable_key = String::new();
    if cursor.emitted_rows > 0 {
        for row in table.iter().map_err(storage)? {
            let (key, _) = row.map_err(storage)?;
            chain.advance_key(key.value());
            key.value().clone_into(&mut durable_key);
            emitted = emitted
                .checked_add(1)
                .ok_or(OrsError::ProjectionLimitExceeded)?;
            if emitted == cursor.emitted_rows {
                break;
            }
        }
    }
    if emitted != cursor.emitted_rows
        || chain.link() != cursor.emitted_prefix_digest
        || durable_key != cursor.after_key
    {
        return Err(OrsError::ProcessStreamRecoveryFamilyCursorMismatch {
            presented_after_key: cursor.after_key.clone(),
            presented_emitted_rows: cursor.emitted_rows,
            expected_after_key: durable_key,
            expected_emitted_rows: emitted,
        });
    }
    Ok(())
}

/// Refuses one process-stream recovery row with its own exact identity.
///
/// A row that will not decode, re-encode, or fit the caller's declared byte
/// budget is named, not summarised: the export then stops at that row instead
/// of scanning the remainder of the family to decide what to do with it. The
/// disposition is [`OrsError::IntegrityProblem`] on the family's own
/// `record_type`, which is the same typed storage-failure shape an unreadable
/// operational-history row produces.
fn stream_recovery_row_refused(record_key: &str, reason: &str) -> OrsError {
    OrsError::IntegrityProblem {
        record_type: "process_stream_recovery",
        reason: format!("backup row {record_key:?} is not exportable: {reason}"),
    }
}

/// Builds one bounded process-stream recovery family page segment.
///
/// Rows are enumerated in the family's own durable-key order from
/// `cursor.after_key`, and the row and byte budgets are charged per row as the
/// loop goes: it stops the moment the admitted budget is spent, so this path
/// never holds more than one page of rows plus the one row it declined to emit.
/// There is deliberately no "read the table, then slice" step.
///
/// `row_budget` and `byte_budget` are this page's remaining admission, after
/// the operational segment has been charged. `max_bytes` is the caller's whole
/// declared per-page byte budget, which is what decides whether one row is
/// exportable at all. `cursor.emitted_rows` and `cursor.emitted_bytes` are
/// cumulative over the whole family, so they advance the continuation and are
/// never compared against a per-page budget.
///
/// Dispositions, all non-destructive:
/// - the boundary is proved against durable state before a single row is read;
/// - a row that does not fit the page's remaining budget is not emitted and not
///   dropped: it stays behind `next`, so the following page carries it and the
///   family cannot be silently truncated;
/// - a row that cannot fit the caller's declared budget at all is a bounded
///   refusal naming that exact row, and the enumeration stops there instead of
///   scanning the remainder of the family to decide what to do with it;
/// - `next` is `None` only when the enumeration reached the end of the family.
fn stream_recovery_family_segment(
    table: &redb::ReadOnlyTable<&str, &str>,
    cursor: &OrsFamilyCursor,
    row_budget: usize,
    byte_budget: u64,
    max_bytes: u64,
) -> Result<(Vec<OrsBackupEntry>, OrsFamilyContinuation), OrsError> {
    check_family_cursor_boundary(table, cursor)?;
    let mut chain = OrsFamilyRowChain::resume(cursor.emitted_prefix_digest.clone());
    let mut entries: Vec<OrsBackupEntry> = Vec::new();
    let mut page_bytes: u64 = 0;
    let mut emitted_rows = cursor.emitted_rows;
    let mut emitted_bytes = cursor.emitted_bytes;
    let mut after_key = cursor.after_key.clone();
    let mut family_open = false;
    // `range` seeks to the exclusive bound instead of walking the table, so a
    // continuation costs the rows it still owes rather than the rows it already
    // exported. The bound is a durable key built from an operation identity and
    // a stream name, so it is never the empty string a start cursor carries in
    // order to mean "from the first key".
    let rows = table
        .range::<&str>((Bound::Excluded(cursor.after_key.as_str()), Bound::Unbounded))
        .map_err(storage)?;
    for row in rows {
        if entries.len() >= row_budget {
            family_open = true;
            break;
        }
        let (key, value) = row.map_err(storage)?;
        let record_key = key.value().to_owned();
        let decode_error =
            |error: OrsError| stream_recovery_row_refused(&record_key, &error.to_string());
        let projection: ProcessStreamRecoveryProjection =
            decode(value.value()).map_err(decode_error)?;
        let encoded = encode(&projection).map_err(decode_error)?;
        let encoded_len = u64::try_from(encoded.len()).map_err(|_| OrsError::PayloadTooLarge)?;
        if encoded_len > max_bytes {
            return Err(stream_recovery_row_refused(
                &record_key,
                &format!(
                    "row encodes to {encoded_len} bytes, above the declared backup byte budget {max_bytes}"
                ),
            ));
        }
        let charged = page_bytes
            .checked_add(encoded_len)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        if charged > byte_budget {
            family_open = true;
            break;
        }
        let order = stream_recovery_entry_order(&projection).map_err(decode_error)?;
        page_bytes = charged;
        emitted_rows = emitted_rows
            .checked_add(1)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        emitted_bytes = emitted_bytes
            .checked_add(encoded_len)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        after_key.clone_from(&record_key);
        chain.advance_key(&record_key);
        entries.push(OrsBackupEntry {
            record_id: record_key,
            family: RowFamilyKind::ProcessStreamRecovery,
            order,
            payload_digest: crate::model::sha256_hex(encoded.as_bytes()),
            effect_class: effect_class_for_stream_recovery(projection.activation),
        });
    }
    let continuation = OrsFamilyContinuation {
        cursor: cursor.clone(),
        next: family_open.then(|| OrsFamilyCursor {
            version: cursor.version,
            identity: cursor.identity.clone(),
            after_key,
            emitted_rows,
            emitted_bytes,
            emitted_prefix_digest: chain.link().to_owned(),
        }),
    };
    Ok((entries, continuation))
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
/// Binds `(order, record-bytes digest)` pairs in order under the caller's read
/// transaction. Used as one half of the composite pre/post freeze witness: any
/// canonical advance between the two observations fails the import/export with
/// [`OrsError::OrderingHeadMismatch`] instead of tearing the snapshot.
fn operational_state_digest(read: &ReadTransaction) -> Result<String, OrsError> {
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

/// Deterministic digest over the composite durable state a backup certifies.
///
/// Digesting one table cannot certify a composite snapshot (issue #2884), so
/// this folds the process-stream recovery family's durable revision and its
/// streamed content root into the same witness the export already takes for
/// operational history. Any insert, evidence advance, revalidation or
/// retirement of a family row moves it, so a multi-page export can no longer
/// combine operational pages read at one moment with recovery rows read at
/// another, and a quarantined import page cannot be triaged against a family
/// that moved underneath it.
///
/// The family axis is a streaming hash chain, so this stays O(1) in the number
/// of retained family rows; only the pre-existing operational-history half
/// collects its rows.
fn composite_state_digest(database: &Database) -> Result<String, OrsError> {
    let read = database.begin_read().map_err(storage)?;
    let operational = operational_state_digest(&read)?;
    let family_revision = super::RedbRecoveryStore::process_stream_recovery_family_revision(&read)?;
    let family = process_stream_recovery_family_identity(&read)?;
    drop(read);
    let mut material = String::new();
    let _ = write!(
        material,
        "eliot.ors.composite_state.v1|operational={operational}|family_revision={family_revision}|family_root={}|rows={}|bytes={}",
        family.family_root_digest, family.family_row_count, family.family_total_bytes
    );
    Ok(crate::model::sha256_hex(material.as_bytes()))
}

/// Reads this page's process-stream recovery family segment, if the request
/// carries a family continuation.
///
/// Three things happen in order and each can refuse before any row is read: the
/// durable family revision must still equal the frozen one, the family's
/// remaining row and byte admission for this page is computed from what the
/// operational segment already spent, and the segment itself proves the cursor
/// boundary against durable keys. The family shares the page's admission rather
/// than raising the per-page ceiling, and no family row is compacted to make
/// room for an operational one.
fn stream_recovery_family_page(
    read: &ReadTransaction,
    request: &OrsBackupRequest,
    operational_entries: usize,
    operational_bytes: u64,
) -> Result<(Vec<OrsBackupEntry>, Option<OrsFamilyContinuation>), OrsError> {
    let Some(cursor) = &request.process_stream_recovery_cursor else {
        return Ok((Vec::new(), None));
    };
    check_family_revision_frozen(read, cursor)?;
    let row_budget = usize::from(request.page_entries)
        .checked_sub(operational_entries)
        .ok_or(OrsError::ProjectionLimitExceeded)?;
    let byte_budget = request
        .max_bytes
        .checked_sub(operational_bytes)
        .ok_or(OrsError::ProjectionLimitExceeded)?;
    let family = read
        .open_table(super::PROCESS_STREAM_RECOVERY)
        .map_err(storage)?;
    let segment =
        stream_recovery_family_segment(&family, cursor, row_budget, byte_budget, request.max_bytes);
    drop(family);
    let (entries, continuation) = segment?;
    Ok((entries, Some(continuation)))
}

/// Exports one coherent backup page under a single read transaction.
///
/// `page_index` binds `after_order + page_entries * page_index`: the window
/// start moves by exactly one page stride per index, so pages exported from
/// independent calls with different fence tokens are NOT one snapshot.
/// Callers building a snapshot must reuse the same request (same fence
/// token) across pages, advancing only the typed family cursor;
/// [`export_snapshot`] enforces this by issuing every page itself. Any row
/// decode failure returns [`OrsError::IntegrityProblem`]; a page is never
/// fabricated from reference counts alone. Accumulated entry bytes are bounded
/// by `request.max_bytes` (already `1..=MAX_BACKUP_BYTES` by the request
/// constructor).
///
/// The operational-history window is unchanged. The process-stream recovery
/// family (#269) is not paged on that window: it has no canonical operation
/// order, so it is paged through the request's own [`OrsFamilyCursor`] in
/// durable-key order, sharing this page's remaining row and byte budget so the
/// per-page ceiling is unchanged. `is_last` is the conjunction of the
/// operational window being exhausted and the family having no continuation
/// left, so a page that still owes family rows is never final.
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
    // ONE read transaction: the page is coherent by construction, and the
    // family segment below observes the same snapshot as the operational
    // window it shares a page with.
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
    // The operational-history segment decides whether its own window is
    // exhausted, exactly as the post-truncation `entries.len()` check below
    // does. The family has its own cursor, so it is read on every page that
    // carries a family continuation and never depends on this flag.
    let operational_exhausted = selected.len() < usize::from(request.page_entries);
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
    let (family_segment, family_continuation) =
        stream_recovery_family_page(&read, request, entries.len(), total_bytes)?;
    entries.extend(family_segment);
    drop(read);
    let family_open = family_continuation
        .as_ref()
        .is_some_and(OrsFamilyContinuation::family_open);
    let is_last = operational_exhausted && !family_open;
    let mut digest_material = String::new();
    for entry in &entries {
        digest_material.push_str(&entry.payload_digest);
    }
    digest_material.push_str(&fence_token);
    // The frozen family snapshot identity and the exact next family cursor are
    // bound into the page token, so a family page can be neither replayed under
    // a different family snapshot nor continued at a different boundary.
    if let Some(continuation) = &family_continuation {
        digest_material.push_str(&continuation.cursor.fence_token());
        if let Some(next) = &continuation.next {
            digest_material.push('|');
            digest_material.push_str(&next.fence_token());
        }
    }
    let page_digest = crate::model::sha256_hex(digest_material.as_bytes());
    Ok(OrsBackupPage {
        page_index,
        entries,
        page_digest,
        is_last,
        family_continuation,
    })
}

/// Exports a full snapshot by paging with one request until `is_last`.
///
/// The operational request (fence token, `after_order`, page size) is reused for
/// every page, so `page_index * page_entries` continuity holds by construction;
/// only the typed family cursor advances, by exactly the owner-issued cursor the
/// previous page ended with. A pre/post [`composite_state_digest`] freeze check
/// rejects any canonical advance *or* any process-stream recovery family
/// movement that lands mid-export with [`OrsError::OrderingHeadMismatch`]
/// instead of tearing the snapshot.
///
/// Exhausting `request.max_pages` is a resumable `Partial` disposition carrying
/// the exact next family cursor, not a permanent refusal: a family larger than
/// the page budget exports by continuing, so retaining more legitimate recovery
/// evidence no longer makes the backup permanently unavailable. Completeness is
/// `Complete` only when every page decoded cleanly, the operational window and
/// the family were both exhausted, and at least one entry landed. A request that
/// declared no family cursor yields `Partial` with the legacy reason, because a
/// snapshot with no family denominator is partial evidence and not an empty
/// complete family. A decode failure reports [`OrsError::IntegrityProblem`],
/// never a fabricated `Complete`. The denominator digest is the snapshot's own
/// `snapshot_digest()` binding, which chains every exported entry's payload
/// digest together with the frozen family snapshot identity, so the process
/// stream recovery family is inside the denominator on every page it appears.
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
    let frozen_pre = composite_state_digest(database)?;
    let mut continuing = request.clone();
    let mut pages: Vec<OrsBackupPage> = Vec::new();
    let mut entry_count: u64 = 0;
    let mut last_page_was_final = false;
    for index in 0..u32::from(request.max_pages) {
        let page = export_page(database, &continuing, index)?;
        entry_count = entry_count
            .checked_add(page.entries.len() as u64)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        let next_family = page
            .family_continuation
            .as_ref()
            .and_then(|continuation| continuation.next.clone());
        last_page_was_final = page.is_last;
        pages.push(page);
        if last_page_was_final {
            break;
        }
        // Exactly one owner-issued advance per family page: the next cursor is
        // the one the previous page ended with, never a recomputed offset.
        if let Some(next) = next_family {
            continuing = continuing.with_process_stream_recovery_cursor(next)?;
        }
    }
    if pages.is_empty() {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    // The last page is the authority on whether the family is finished: a page
    // that ended the family leaves no continuation even when an earlier page
    // did, so a snapshot is never left claiming an outstanding cursor it has
    // already emitted past.
    let outstanding_family = pages
        .last()
        .and_then(|page| page.family_continuation.as_ref())
        .and_then(|continuation| continuation.next.clone());
    let frozen_post = composite_state_digest(database)?;
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
    let completeness = if outstanding_family.is_some() {
        // The page budget ran out with family rows still owed. The exact cursor
        // travels on the snapshot so the caller resumes rather than restarts,
        // and the snapshot stays explicitly partial instead of all-or-nothing.
        BackupCompleteness::Partial {
            reason: format!(
                "process-stream recovery family is not fully exported; resume with next_process_stream_recovery_cursor (page budget spent: {})",
                !last_page_was_final
            ),
        }
    } else if continuing.process_stream_recovery_cursor.is_none() {
        BackupCompleteness::Partial {
            reason: "no process-stream recovery family denominator was declared; legacy evidence, not an empty complete family"
                .to_owned(),
        }
    } else if entry_count > 0 {
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
        process_stream_recovery_family: continuing
            .process_stream_recovery_cursor
            .as_ref()
            .map(|cursor| cursor.identity.clone()),
        next_process_stream_recovery_cursor: outstanding_family,
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
/// [`composite_state_digest`] freeze check rejects concurrent canonical advance
/// *or* a moved process-stream recovery family across the page, because
/// digesting one table cannot certify the composite state this page is triaged
/// against. Per-entry canonical evidence calls are deliberately skipped: there
/// is no signed inbox item here to verify, so verification is deferred to
/// `import_recovery_inbox`, which owns durable quarantine. Unknown stays
/// quarantined with no blind retry. Page-to-review snapshot binding is
/// re-established by the canonical owner from `import.snapshot_digest` at
/// reconcile time; pages carry no snapshot field.
///
/// A process-stream recovery entry lands `Unresolved` here whatever its digest,
/// because paging the family into more pages raises no authority: the only
/// durable restore route for it is
/// `RedbRecoveryStore::import_process_stream_recovery_suspended`, which discards
/// the incoming activation and always writes suspended recovery evidence. Triage
/// still never constructs `PerEntryOutcome::Imported`.
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
    if let Some(continuation) = &page.family_continuation {
        continuation.validate()?;
        if page.is_last && continuation.family_open() {
            return Err(OrsError::InvalidField {
                field: "backup_page_is_last",
                reason: "a final page must not leave an open family continuation",
            });
        }
    }
    let frozen_pre = composite_state_digest(database)?;
    let mut outcomes: Vec<(String, PerEntryOutcome)> = Vec::with_capacity(page.entries.len());
    for entry in &page.entries {
        outcomes.push((entry.record_id.clone(), triage_entry(database, entry)?));
    }
    let frozen_post = composite_state_digest(database)?;
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
