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
//! - The composite pre/post freeze covers operational history *and* every
//!   cursor-paged family's revision and root, and both are folded into the page
//!   token and the snapshot denominator.
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
//!
//! Issue #1971 registers the versioned-artifact family in that same
//! denominator. `RowFamilyKind::VersionedArtifacts` carries the
//! `ors_versioned_artifacts_v1` family — one durable row per
//! `staged:`/`retained:` `(<module_id>, <generation>)` key holding the exact
//! artifact hash and path — with the `CutoverOwnership` sibling's
//! `NonrestorableHistorical` disposition, so restore triage lands its rows as
//! forensics through the generic disposition match and no restored
//! installation can reactivate old installation-bound generation authority
//! (I05-27 / ARCH-RES-03: recovery cannot resurrect invalid state). The contract
//! discriminator already named it cursor-paged
//! ([`RowFamilyKind::uses_family_cursor`]), because its rows carry no operation
//! order.
//!
//! This completes that registration by giving the family the SAME machinery the
//! #2884 process-stream recovery family has, by imitation rather than by a second
//! design. What exists now, once per paged family:
//! - a durable monotone `versioned_artifact_family_revision` meta counter, read by
//!   `RedbRecoveryStore::versioned_artifact_family_revision` and advanced by
//!   `RedbRecoveryStore::advance_versioned_artifact_family_revision` inside the
//!   SAME write transaction as every durable change to the family — that is, in
//!   `replace_versioned_artifact_rows`, the family's single write path, which is
//!   also where the unchanged-vs-moved discriminator lives so an exact
//!   re-presentation of the same registry advances nothing;
//! - a streamed content root over `ors_versioned_artifacts_v1` and the frozen
//!   family identity built from it;
//! - `RedbRecoveryStore::open_backup_versioned_artifact_family`, the only producer
//!   of a cursor for this family;
//! - the movement and cursor-boundary refusals, reusing the existing
//!   [`OrsError`] variants (see [`family_moved_error`] and
//!   [`family_cursor_mismatch_error`]) rather than adding a new one;
//! - a page segment that charges this page's remaining row and byte admission per
//!   row, and a page that is final only when the operational window AND both
//!   paged families are closed;
//! - a second symmetric request cursor / page continuation / snapshot identity,
//!   folded into the page digest and the snapshot denominator in a fixed order;
//! - the family's revision and content root folded into
//!   [`composite_state_digest`], so a versioned-artifact commit during a capture
//!   is visible to the pre/post witness instead of being invisible to it.
//!
//! Attaching the cursor puts those rows inside the exported DENOMINATOR. It
//! confers no restore path: the family's disposition routes every exported row to
//! `PerEntryOutcome::Forensic`, and I1.6/I1.12/I14.14 stay exactly where they
//! were — a versioned binary is never replaced in place while running, and a
//! rollback is only ever another cutover to an artifact verified compatible with
//! current durable formats and epoch lineage. Reading a generation out of a backup
//! is reading history, never acquiring the authority to activate it.
//!
//! Issue #953 makes the capture coherent and the page binding self-proving:
//! - ONE `ReadTransaction` is opened per capture and threaded through the
//!   store-wide fence observation, the pre witness and EVERY page
//!   (`export_page_in`). Before, each page opened and dropped its own
//!   transaction, so the page loop was N+2 transactions and pages from different
//!   moments shared one fence and one token.
//! - The composite post witness is then taken from a SECOND read transaction
//!   opened only after the capture transaction is released, so the two ends of
//!   the pre/post freeze check are genuinely different moments. Coherence of the
//!   pages and detection of a writer that committed during the capture are two
//!   different properties with two different mechanisms; the first comes from the
//!   single transaction, the second from the post-release observation. Neither
//!   substitutes for the other, and no witness on either path compares a snapshot
//!   against itself.
//! - The owner-observed fence is COMPARED against the request, not transcribed
//!   from it: `capture_store_fence` reads the ordering high-water mark and the
//!   family revision inside the capture transaction, and `check_export_fence`
//!   refuses a request the store cannot confirm.
//! - Every page is self-describing: it carries the owner-derived fence token and
//!   a bounded capture window, and its digest is re-derived from its own bytes by
//!   the one derivation in the contract module, so the import triage path can
//!   refuse a page assembled from more than one source.
//!
//! ASSUMPTION: I05-13 names `OrsSnapshotFence` as the coherent logical ORS
//! export a `full_recovery` backup must carry, and describes what it records
//! ("Host/Kernel authority lineage, last reconciled canonical receipt/event/
//! outbox cursors, pending-operation identities and hashes, job checkpoints,
//! generation cutovers and snapshot time"). There is NO `OrsSnapshotFence` type
//! anywhere in this repository, and no document defines how ORS self-consistency
//! is established or which of those fields ORS is able to produce. The contract
//! for this work therefore exists only in the issue text. What is implemented here
//! is the part ORS can actually establish and prove on its own: one read snapshot,
//! a compared ordering high-water mark, a compared family revision, and a per-page
//! token re-derived from page content. The lineage, canonical cursor and
//! pending-operation-hash fields I05-13 describes are cross-store material this
//! crate does not hold, and are NOT approximated by a lookalike struct.

use std::fmt::Write as _;
use std::ops::Bound;
use std::sync::Arc;

use redb::{Database, ReadTransaction, ReadableDatabase, ReadableTable};

use super::persistence_codec::{decode, decode_named, encode};
use super::persistence_models::DurableOperationalRecord;
use super::storage;
use crate::backup_snapshot::{
    BACKUP_SNAPSHOT_SCHEMA_VERSION, BackupCompleteness, MAX_BACKUP_BYTES, MAX_BACKUP_PAGE_ENTRIES,
    MAX_BACKUP_PAGE_LIFETIME_MS, OrsBackupEntry, OrsBackupImportReceipt, OrsBackupImportRequest,
    OrsBackupPage, OrsBackupRequest, OrsBackupSnapshot, OrsFamilyContinuation, OrsFamilyCursor,
    OrsFamilyRowChain, OrsFamilySnapshotIdentity, PerEntryOutcome, RowDisposition,
    RowFamilyDisposition, RowFamilyKind, StoredEffectClass, check_canonical_frozen,
    validate_import_binding,
};
use crate::{
    ArtifactGenerationState, OperationalPhase, OrsError, ProcessStreamRecoveryProjection,
    StreamRecoveryActivation, VersionedArtifactEntry,
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
        // Artifact paths and generations remain installation-bound history.
        RowFamilyDisposition::of(RowFamilyKind::VersionedArtifacts),
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

/// The process-stream recovery family's own order value and effect class for one
/// exported recovery entry.
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
///
/// Paired with [`effect_class_for_stream_recovery`] in one function for the same
/// reason [`versioned_artifact_entry`] pairs its own: `order` and `effect_class`
/// must describe the same decoded row.
fn stream_recovery_entry(
    projection: &ProcessStreamRecoveryProjection,
) -> Result<(u64, StoredEffectClass), OrsError> {
    let order =
        u64::try_from(projection.observed_at_ms).map_err(|_| OrsError::IntegrityProblem {
            record_type: "process_stream_recovery",
            reason: "observation time is not a representable backup order".to_owned(),
        })?;
    Ok((
        order,
        effect_class_for_stream_recovery(projection.activation),
    ))
}

/// The versioned-artifact family's own order value and effect class for one
/// exported registry entry (issue #1971).
///
/// The generation is the row's real, durably retained, generation-addressed
/// identity field, so it is used verbatim as the reporting `order` for the same
/// reason the process-stream row uses its observation time: a real retained field
/// rather than a synthesized rank. It is a REPORTING value only — selection is by
/// the family's own durable-key order through [`OrsFamilyCursor`], which is why
/// two modules may legitimately share a generation number without dropping or
/// duplicating a row.
///
/// Paired with [`effect_class_for_versioned_artifact`] in one function because a
/// cursor-paged family is exported through a single per-row shape: an entry's
/// `order` and `effect_class` are read off the same decoded row and must not be
/// free to disagree about which row they describe. Total by construction —
/// [`VersionedArtifactEntry::validate`] has already run through the ORS codec, so
/// the generation is a stored `u64` and there is no conversion left to fail.
fn versioned_artifact_entry(entry: &VersionedArtifactEntry) -> (u64, StoredEffectClass) {
    (
        entry.artifact.generation,
        effect_class_for_versioned_artifact(entry.state),
    )
}

/// Maps a durable versioned-artifact generation state to its backup effect class
/// (issue #1971).
///
/// A staged candidate is not yet committed for the destination (`Staged`), an
/// `Active` or `Draining` generation is in-flight installation-bound authority
/// (`Possible`), and `Retired` is terminal (`Terminal`). `Unknown` is never
/// produced: an unreadable or codec-incompatible row fails the export rather than
/// being classified as reconciling, so no backup asserts an unknown outcome it did
/// not read. `Retired` is listed rather than left to a wildcard because it is
/// unreachable through the family's own row contract
/// ([`VersionedArtifactEntry::validate`] refuses it) and must stay unreachable
/// here too.
fn effect_class_for_versioned_artifact(state: ArtifactGenerationState) -> StoredEffectClass {
    match state {
        ArtifactGenerationState::Staged => StoredEffectClass::Staged,
        ArtifactGenerationState::Active | ArtifactGenerationState::Draining => {
            StoredEffectClass::Possible
        }
        ArtifactGenerationState::Retired => StoredEffectClass::Terminal,
    }
}

/// The durable table-definition type backing one cursor-paged row family.
///
/// Named once so [`family_table_definition`] and the read/open paths below state
/// the same type the store's own family constants are declared with, instead of
/// restating a lifetime spelling that would have to track redb's generics.
type FamilyTable = redb::TableDefinition<'static, &'static str, &'static str>;

/// The durable table that backs one cursor-paged row family (issue #1971).
///
/// The closed dispatch for the two families [`RowFamilyKind::uses_family_cursor`]
/// admits. There is no wildcard success arm: a family that gains its own total
/// order later must be registered here, in its own write path's durable revision
/// and here, rather than silently falling through to a table this module never
/// enumerated.
fn family_table_definition(family: RowFamilyKind) -> Result<FamilyTable, OrsError> {
    match family {
        RowFamilyKind::ProcessStreamRecovery => Ok(super::PROCESS_STREAM_RECOVERY),
        RowFamilyKind::VersionedArtifacts => Ok(super::VERSIONED_ARTIFACTS),
        _ => Err(OrsError::InvalidField {
            field: "backup_family",
            reason: "family is not paged through a typed family cursor",
        }),
    }
}

/// The ORS `record_type` naming one cursor-paged family's own rows.
///
/// Used by the per-row export refusals so a refusal names the family that produced
/// it rather than a generic backup record. Same closed dispatch as
/// [`family_table_definition`].
fn family_record_type(family: RowFamilyKind) -> Result<&'static str, OrsError> {
    match family {
        RowFamilyKind::ProcessStreamRecovery => Ok("process_stream_recovery"),
        RowFamilyKind::VersionedArtifacts => Ok("versioned_artifact_entry"),
        _ => Err(OrsError::InvalidField {
            field: "backup_family",
            reason: "family is not paged through a typed family cursor",
        }),
    }
}

/// Reads one cursor-paged family's durable monotone revision (issue #1971).
///
/// Each family has its own meta counter and its own single advancing write path,
/// so this is a dispatch over the store's two family-revision readers rather than
/// one shared counter: sharing a counter would let a process-stream recovery
/// insert look like versioned-artifact movement and refuse an unrelated
/// continuation.
fn family_revision(read: &ReadTransaction, family: RowFamilyKind) -> Result<u64, OrsError> {
    match family {
        RowFamilyKind::ProcessStreamRecovery => {
            super::RedbRecoveryStore::process_stream_recovery_family_revision(read)
        }
        RowFamilyKind::VersionedArtifacts => {
            super::RedbRecoveryStore::versioned_artifact_family_revision(read)
        }
        _ => Err(OrsError::InvalidField {
            field: "backup_family",
            reason: "family is not paged through a typed family cursor",
        }),
    }
}

/// One bounded read of one cursor-paged row family: the streamed content root
/// plus the observed size, with nothing retained.
struct FamilyRoot {
    /// Chained content root over the family's durable keys and encoded rows.
    root_digest: String,
    /// Retained rows observed.
    row_count: u64,
    /// Summed encoded row bytes observed.
    total_bytes: u64,
}

/// Computes one cursor-paged family's content root in one streaming pass.
///
/// Each row is folded into an [`OrsFamilyRowChain`] link and then dropped, so
/// the pass costs a constant amount of memory no matter how many rows the family
/// retains: a ten-thousand-row family is hashed, not collected. The root binds
/// the family's total durable-key order and every row's encoded bytes, so it
/// moves on an insert, an advance and a removal alike.
///
/// The chain is seeded with `family`, so a link is not transferable between
/// families: the versioned-artifact root and the process-stream recovery root
/// cannot collide even for byte-identical row content.
///
/// This is the frozen owner snapshot identity, not page enumeration: it runs
/// once when a family cursor is opened and once per pre/post freeze check, never
/// once per page. It is bounded by [`IMPORT_SCAN_ROW_CAP`] and fails closed
/// rather than certifying a truncated family as complete.
fn family_root(
    table: &redb::ReadOnlyTable<&str, &str>,
    family: RowFamilyKind,
) -> Result<FamilyRoot, OrsError> {
    let mut chain = OrsFamilyRowChain::start(family);
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
    Ok(FamilyRoot {
        root_digest: chain.link().to_owned(),
        row_count,
        total_bytes,
    })
}

/// Reads one cursor-paged family's durable revision and its content root under
/// one read transaction, so the frozen identity can never mix two moments.
fn family_identity(
    read: &ReadTransaction,
    family: RowFamilyKind,
) -> Result<OrsFamilySnapshotIdentity, OrsError> {
    let family_revision = family_revision(read, family)?;
    let root = {
        let table = read
            .open_table(family_table_definition(family)?)
            .map_err(storage)?;
        let root = family_root(&table, family)?;
        drop(table);
        root
    };
    OrsFamilySnapshotIdentity::new(
        family,
        family_revision,
        root.root_digest,
        root.row_count,
        root.total_bytes,
    )
}

/// Opens the typed family cursor for one live cursor-paged row family.
///
/// The one producer of an [`OrsFamilyCursor`] for that family: the cursor can
/// only be born from the owner's own durable revision and content root, so a
/// caller cannot mint a family snapshot and therefore cannot choose where that
/// family's page starts. Two callers, one per family:
/// `RedbRecoveryStore::open_backup_process_stream_recovery_family` and
/// `RedbRecoveryStore::open_backup_versioned_artifact_family` (issue #1971).
pub(super) fn open_backup_family(
    database: &Database,
    family: RowFamilyKind,
) -> Result<OrsFamilyCursor, OrsError> {
    let read = database.begin_read().map_err(storage)?;
    let identity = family_identity(&read, family)?;
    drop(read);
    OrsFamilyCursor::start(identity)
}

/// The movement refusal for a family that moved after a backup froze it.
///
/// NO new [`OrsError`] variant is introduced here (issue #1971). Both `OrsError`
/// mappings outside `eliot-ors` — `eliot-kernel-service/src/storage_replacement.rs`
/// and `bins/eliot-kernel/src/backup_restore_ports.rs` — match the enum
/// EXHAUSTIVELY with no `_` wildcard, so a new variant would not compile outside
/// this crate and the two files that own those mappings are not this change's to
/// edit. The process-stream recovery family therefore keeps its own rich typed
/// variant unchanged, and the versioned-artifact family reuses
/// [`OrsError::OrderingHeadMismatch`] — the crate's existing typed refusal for a
/// head/revision that does not match durable ORS state, already the refusal
/// `check_export_fence` uses for exactly that reason. The same operator action
/// applies to both: restart this family's export from a freshly opened family
/// snapshot.
fn family_moved_error(
    family: RowFamilyKind,
    cursor: &OrsFamilyCursor,
    observed_revision: u64,
    observed_root_digest: String,
) -> OrsError {
    match family {
        RowFamilyKind::ProcessStreamRecovery => OrsError::ProcessStreamRecoveryFamilyMoved {
            frozen_revision: cursor.identity.family_revision,
            observed_revision,
            frozen_root_digest: cursor.identity.family_root_digest.clone(),
            observed_root_digest,
            after_key: cursor.after_key.clone(),
        },
        _ => OrsError::OrderingHeadMismatch,
    }
}

/// The refusal for a presented cursor that does not name the owner-emitted
/// durable-key prefix.
///
/// Same closed-variant constraint as [`family_moved_error`], and the same reuse
/// decision: the process-stream recovery family keeps
/// [`OrsError::ProcessStreamRecoveryFamilyCursorMismatch`], and the
/// versioned-artifact family reuses [`OrsError::InvalidField`] — the crate's
/// existing typed refusal for a caller-presented value that does not name
/// durable state, with the family's own field name so no two refusals read alike.
fn family_cursor_mismatch_error(
    family: RowFamilyKind,
    cursor: &OrsFamilyCursor,
    expected_after_key: String,
    expected_emitted_rows: u64,
) -> OrsError {
    match family {
        RowFamilyKind::ProcessStreamRecovery => {
            OrsError::ProcessStreamRecoveryFamilyCursorMismatch {
                presented_after_key: cursor.after_key.clone(),
                presented_emitted_rows: cursor.emitted_rows,
                expected_after_key,
                expected_emitted_rows,
            }
        }
        _ => OrsError::InvalidField {
            field: "backup_versioned_artifact_family_cursor",
            reason: "cursor must name the owner-emitted durable-key prefix",
        },
    }
}

/// Refuses a family page whose family moved after the backup froze it.
///
/// The check is a comparison against live owner state, the same shape as the
/// owner-bound snapshot handle in the store API: the frozen revision in the
/// cursor is compared with the durable revision this read transaction actually
/// observed, and any difference is the family's movement/restart disposition
/// (see [`family_moved_error`] for which [`OrsError`] carries it). It fires for an
/// insert, an advance and a removal alike, because each family's single write path
/// advances its revision in the same transaction as the row change.
///
/// The fast path reads one meta key. The observed content root is recomputed only
/// on the refusal branch, where the extra pass buys exact evidence for the
/// operator instead of costing every page of a healthy export.
fn check_family_revision_frozen(
    read: &ReadTransaction,
    cursor: &OrsFamilyCursor,
) -> Result<(), OrsError> {
    let family = cursor.identity.family;
    let observed_revision = family_revision(read, family)?;
    if observed_revision == cursor.identity.family_revision {
        return Ok(());
    }
    let observed_root_digest = {
        let table = read
            .open_table(family_table_definition(family)?)
            .map_err(storage)?;
        let root = family_root(&table, family)?;
        drop(table);
        root.root_digest
    };
    Err(family_moved_error(
        family,
        cursor,
        observed_revision,
        observed_root_digest,
    ))
}

/// Store-wide fence values the owner can establish at a capture's consistency
/// point (issue #953).
///
/// Read once through the ONE `ReadTransaction` that also produces every page, so
/// the observed fence and the exported rows are the same moment by construction.
/// This is the same shape as [`check_family_revision_frozen`]: a comparison
/// against live owner state inside the caller's read transaction, never a
/// re-derivation from anything the caller supplied.
struct StoreFenceObservation {
    /// `next_global_order` out of `ors_meta_v1`: the store's canonical ordering
    /// high-water mark. Monotone, advanced by every operation-order allocation
    /// and by `ensure_grant_closure_order_floor`, absent (read as `0`) on a store
    /// that never allocated one.
    high_water_order: u64,
    /// Durable monotone revision of the process-stream recovery family.
    ///
    /// Named for one family, not for "the family revision": the second
    /// cursor-paged family (versioned artifacts, issue #1971) has its own counter
    /// and reaches the page through its own cursor token, which
    /// [`OrsBackupPage::expected_page_digest`] folds into `page_digest`. The
    /// composite witness [`composite_state_digest`] folds BOTH families'
    /// revisions and roots, so widening this observation would not make a
    /// concurrent versioned-artifact commit any more detectable — it would only
    /// make one store-wide token mean two independent things.
    family_revision: u64,
}

/// Observes the store-wide fence through the caller's capture transaction
/// (issue #953).
///
/// Both reads are meta reads taken under the SAME transaction the pages are read
/// under, so the observation cannot be a later moment than the rows it fences.
/// An unparseable counter is [`OrsError::IntegrityProblem`] on the meta table's
/// own `record_type`, exactly as the writer that advances these counters reports
/// a corrupt value; it is never defaulted to a value that would then look like a
/// matching fence.
fn capture_store_fence(read: &ReadTransaction) -> Result<StoreFenceObservation, OrsError> {
    let meta = read.open_table(super::META).map_err(storage)?;
    let high_water_order = meta
        .get(super::NEXT_GLOBAL_ORDER)
        .map_err(storage)?
        .map(|value| value.value().parse::<u64>())
        .transpose()
        .map_err(|error| OrsError::IntegrityProblem {
            record_type: "ors_meta_v1",
            reason: error.to_string(),
        })?
        .unwrap_or(0);
    drop(meta);
    let family_revision = super::RedbRecoveryStore::process_stream_recovery_family_revision(read)?;
    Ok(StoreFenceObservation {
        high_water_order,
        family_revision,
    })
}

/// Refuses a request whose declared fence the owner cannot confirm (issue #953).
///
/// The issue requires the capture to bind "source installation/ORS
/// generation/schema, canonical dependency fence, high-water/order", and this is
/// the step that makes the binding a comparison instead of a transcription. The
/// store establishes two of those four against durable state and refuses when the
/// request disagrees:
///
/// - `schema_version` against [`BACKUP_SNAPSHOT_SCHEMA_VERSION`], with
///   [`OrsError::MigrationRequired`] — the crate's existing refusal for a
///   snapshot whose wire contract is not the one this build speaks. Re-asserted
///   here because the store is the boundary an unvalidated request crosses, not
///   only the constructor that first built it.
/// - `fence.high_water_order` against the observed `next_global_order`, with
///   [`OrsError::OrderingHeadMismatch`] — the crate's existing typed refusal for
///   a canonical head that does not match durable ORS state, and the exact state
///   this check exists to prevent: a request that asserts a fence the store has
///   already moved past, whose pages would then silently contain rows the fence
///   excluded.
///
/// The family revision is compared separately, by
/// [`check_family_revision_frozen`], which reports the richer
/// [`OrsError::ProcessStreamRecoveryFamilyMoved`] with the observed content root.
///
/// ASSUMPTION: the issue names a "canonical dependency fence" as something the
/// capture binds, but no ORS type and no governing document defines one. The only
/// `canonical_fence` in this repository belongs to a different owner
/// (`eliot-store-surreal-adapter` / `eliot-doctor-core`), and I05-13 explicitly
/// declines cross-store atomicity ("The ORS and canonical export are not claimed
/// to be one cross-store transaction"). There is therefore no ORS-side referent to
/// compare against, and this check binds the two fence facts the store can
/// actually establish — its own ordering high-water mark and its own family
/// revision. A real cross-owner dependency fence is not approximated here.
///
/// ASSUMPTION: `installation_id` and `ors_generation` in
/// [`crate::OrsBackupSourceIdentity`] cannot be compared. ORS has no durable
/// installation-identity record and no store-wide generation counter, so the
/// store has no owner-established counterpart to compare either against, and
/// `BackupVerificationResultRecord::record_key` says normatively that "within one
/// installation" is STRUCTURAL — a row is only ever read out of the file that
/// owns it — not an in-band field. Inventing such a record would be new durable
/// schema, which this issue does not authorise. Those two fields therefore remain
/// caller-asserted and are disclosed rather than compared; the page token binds
/// what the store observed, not what the caller claimed about its installation.
fn check_export_fence(
    request: &OrsBackupRequest,
    observation: &StoreFenceObservation,
) -> Result<(), OrsError> {
    if request.source.schema_version != BACKUP_SNAPSHOT_SCHEMA_VERSION {
        return Err(OrsError::MigrationRequired {
            reason: format!(
                "backup schema {} unsupported, expected {BACKUP_SNAPSHOT_SCHEMA_VERSION}",
                request.source.schema_version
            ),
        });
    }
    if observation.high_water_order != request.fence.high_water_order {
        return Err(OrsError::OrderingHeadMismatch);
    }
    Ok(())
}

/// Proves that a presented family cursor names exactly the durable-key prefix
/// the owner already emitted.
///
/// The boundary is not authenticated by shape, because every field of a
/// presented cursor is observable. Instead the emitted-prefix chain is
/// re-derived from live durable state and the walk stops the instant the
/// presented row count is reached, so the cost is the prefix the owner already
/// exported and the memory is constant — nothing is collected. A cursor whose
/// chain, offset or last key disagrees with durable state is the family's own
/// boundary refusal (see [`family_cursor_mismatch_error`]); a caller therefore
/// cannot present a later key under an earlier offset and silently drop the rows
/// in between out of the denominator. The family is taken from the cursor itself
/// and the chain is seeded with it, so the proof is family-scoped and a cursor
/// cannot be checked against another family's table.
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
        return Err(family_cursor_mismatch_error(
            cursor.identity.family,
            cursor,
            durable_key,
            emitted,
        ));
    }
    Ok(())
}

/// Refuses one cursor-paged family row with its own exact identity.
///
/// A row that will not decode, re-encode, or fit the caller's declared byte
/// budget is named, not summarised: the export then stops at that row instead
/// of scanning the remainder of the family to decide what to do with it. The
/// disposition is [`OrsError::IntegrityProblem`] on the family's own
/// `record_type` (resolved once by [`family_record_type`]), which is the same
/// typed storage-failure shape an unreadable operational-history row produces.
fn family_row_refused(record_type: &'static str, record_key: &str, reason: &str) -> OrsError {
    OrsError::IntegrityProblem {
        record_type,
        reason: format!("backup row {record_key:?} is not exportable: {reason}"),
    }
}

/// Builds one bounded page segment for one cursor-paged row family.
///
/// Rows are enumerated in the family's own durable-key order from
/// `cursor.after_key`, and the row and byte budgets are charged per row as the
/// loop goes: it stops the moment the admitted budget is spent, so this path
/// never holds more than one page of rows plus the one row it declined to emit.
/// There is deliberately no "read the table, then slice" step.
///
/// `row_budget` and `byte_budget` are this page's remaining admission, after the
/// operational segment and any earlier family segment have been charged.
/// `max_bytes` is the caller's whole declared per-page byte budget, which is what
/// decides whether one row is exportable at all. `cursor.emitted_rows` and
/// `cursor.emitted_bytes` are cumulative over the whole family, so they advance
/// the continuation and are never compared against a per-page budget.
///
/// `entry_shape` is the family's own per-row decision — order and effect class
/// read off one decoded row, together — for a versioned-artifact row or a
/// process-stream recovery row. It is passed in rather than derived here so one
/// enumeration serves both families instead of two near-identical copies drifting
/// apart, and so `order` and `effect_class` can never be read off different rows.
///
/// Returns the page's entries, its continuation, and the encoded bytes this
/// segment charged to the page, so the next family segment on the same page is
/// admitted from what is actually left rather than from the operational total.
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
fn family_segment<E: super::persistence_codec::PersistedValue + serde::Serialize>(
    family: RowFamilyKind,
    table: &redb::ReadOnlyTable<&str, &str>,
    cursor: &OrsFamilyCursor,
    row_budget: usize,
    byte_budget: u64,
    max_bytes: u64,
    entry_shape: impl Fn(&E) -> Result<(u64, StoredEffectClass), OrsError>,
) -> Result<(Vec<OrsBackupEntry>, OrsFamilyContinuation, u64), OrsError> {
    check_family_cursor_boundary(table, cursor)?;
    // Resolved once, not per refused row: the closed dispatch can only fail for
    // a family this function was never called with, and it must be refused before
    // a single row is read rather than from inside the row loop.
    let record_type = family_record_type(family)?;
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
    // a stream name (or from a module id and a generation), so it is never the
    // empty string a start cursor carries in order to mean "from the first key".
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
            |error: OrsError| family_row_refused(record_type, &record_key, &error.to_string());
        let row_value: E = decode(value.value()).map_err(decode_error)?;
        let encoded = encode(&row_value).map_err(decode_error)?;
        let encoded_len = u64::try_from(encoded.len()).map_err(|_| OrsError::PayloadTooLarge)?;
        if encoded_len > max_bytes {
            return Err(family_row_refused(
                record_type,
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
        let (order, effect) = entry_shape(&row_value).map_err(decode_error)?;
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
            family,
            order,
            payload_digest: crate::model::sha256_hex(encoded.as_bytes()),
            effect_class: effect,
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
    Ok((entries, continuation, page_bytes))
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
/// this folds each cursor-paged family's durable revision and its streamed
/// content root into the same witness the export already takes for operational
/// history. Issue #1971 adds the versioned-artifact family's axis: without it a
/// registry commit landing between the two observations would move durable ORS
/// state and leave this digest identical, so the witness would be blind to
/// exactly the concurrent write the versioned-artifact family cursor is supposed
/// to detect. Any insert, advance or removal of a family row moves it, so a
/// multi-page export can no longer combine operational pages read at one moment
/// with family rows read at another, and a quarantined import page cannot be
/// triaged against a family that moved underneath it.
///
/// Each family axis is a streaming hash chain, so this stays O(1) in the number
/// of retained family rows; only the pre-existing operational-history half
/// collects its rows. The families are named in the material string, so the
/// versioned-artifact axis cannot be satisfied by the process-stream axis.
///
/// SCOPE, unchanged in kind and widened in coverage: this binds the operational
/// history and BOTH cursor-paged family roots. It still does not bind every
/// physical ORS table, and adding a third cursor-paged family later would have to
/// add its own axis here rather than inheriting one of these.
///
/// Issue #953 takes the `read: &ReadTransaction` parameter instead of opening its
/// own. Opening its own made the witness a moment the caller did not choose: the
/// digest was taken at whatever instant this function happened to run, which on
/// the export path could be after the pages and on the import path after the
/// triage. The caller now owns the transaction and therefore states exactly which
/// moment each observation speaks for. Both call sites deliberately take their two
/// observations from DIFFERENT snapshots, because a witness whose ends come from
/// one snapshot cannot disagree: the export takes its pre observation inside the
/// capture transaction and its post observation from a fresh transaction opened
/// after that one is released, and the import triage takes the two transactions
/// that straddle its work.
fn composite_state_digest(read: &ReadTransaction) -> Result<String, OrsError> {
    let operational = operational_state_digest(read)?;
    let recovery_revision = family_revision(read, RowFamilyKind::ProcessStreamRecovery)?;
    let recovery = family_identity(read, RowFamilyKind::ProcessStreamRecovery)?;
    let artifact_revision = family_revision(read, RowFamilyKind::VersionedArtifacts)?;
    let artifact = family_identity(read, RowFamilyKind::VersionedArtifacts)?;
    let mut material = String::new();
    let _ = write!(
        material,
        "eliot.ors.composite_state.v2|operational={operational}|recovery_family_revision={recovery_revision}|recovery_family_root={}|recovery_rows={}|recovery_bytes={}|artifact_family_revision={artifact_revision}|artifact_family_root={}|artifact_rows={}|artifact_bytes={}",
        recovery.family_root_digest,
        recovery.family_row_count,
        recovery.family_total_bytes,
        artifact.family_root_digest,
        artifact.family_row_count,
        artifact.family_total_bytes
    );
    Ok(crate::model::sha256_hex(material.as_bytes()))
}

/// Reads this page's segment for one cursor-paged row family, if the request
/// carries a continuation for that family.
///
/// Three things happen in order and each can refuse before any row is read: the
/// durable family revision must still equal the frozen one, the family's
/// remaining row and byte admission for this page is computed from what the
/// operational segment and any earlier family segment already spent, and the
/// segment itself proves the cursor boundary against durable keys. The family
/// shares the page's admission rather than raising the per-page ceiling, and no
/// family row is compacted to make room for an operational one.
///
/// The family is named by the caller, never inferred: each family reads its own
/// request slot through [`OrsBackupRequest::family_cursor`] and its own durable
/// table, so a page can never be assembled by paging one family's rows under the
/// other family's denominator.
///
/// Returns the page's family entries, its continuation (`None` when the request
/// declared none for this family) and the encoded bytes it charged to the page.
fn family_page(
    read: &ReadTransaction,
    request: &OrsBackupRequest,
    family: RowFamilyKind,
    charged_entries: usize,
    charged_bytes: u64,
) -> Result<(Vec<OrsBackupEntry>, Option<OrsFamilyContinuation>, u64), OrsError> {
    let Some(cursor) = request.family_cursor(family) else {
        return Ok((Vec::new(), None, 0));
    };
    check_family_revision_frozen(read, cursor)?;
    let row_budget = usize::from(request.page_entries)
        .checked_sub(charged_entries)
        .ok_or(OrsError::ProjectionLimitExceeded)?;
    let byte_budget = request
        .max_bytes
        .checked_sub(charged_bytes)
        .ok_or(OrsError::ProjectionLimitExceeded)?;
    let table = read
        .open_table(family_table_definition(family)?)
        .map_err(storage)?;
    let segment = match family {
        RowFamilyKind::ProcessStreamRecovery => family_segment::<ProcessStreamRecoveryProjection>(
            family,
            &table,
            cursor,
            row_budget,
            byte_budget,
            request.max_bytes,
            stream_recovery_entry,
        ),
        RowFamilyKind::VersionedArtifacts => family_segment::<VersionedArtifactEntry>(
            family,
            &table,
            cursor,
            row_budget,
            byte_budget,
            request.max_bytes,
            // Wrapped in the family's shared fallible shape even though this
            // family's own decision is total, so one enumeration serves both.
            |entry| Ok(versioned_artifact_entry(entry)),
        ),
        _ => Err(OrsError::InvalidField {
            field: "backup_family",
            reason: "family is not paged through a typed family cursor",
        }),
    };
    drop(table);
    let (entries, continuation, page_bytes) = segment?;
    Ok((entries, Some(continuation), page_bytes))
}

/// One page's cursor-paged family output, merged across every paged family.
struct PageFamilySegments {
    /// Entries from every family, in the fixed family order below.
    entries: Vec<OrsBackupEntry>,
    /// Process-stream recovery continuation, or `None` when none was declared.
    recovery: Option<OrsFamilyContinuation>,
    /// Versioned-artifact continuation, or `None` when none was declared.
    artifacts: Option<OrsFamilyContinuation>,
    /// True when ANY declared family still has rows behind its `next`.
    open: bool,
}

/// Reads every cursor-paged family's segment for one page (issue #1971).
///
/// The two families are read in a FIXED order, so a page is a function of the
/// request and the durable state alone and not of which family happened to be
/// read first, and each is charged from what the previous one actually spent, so
/// running two families can never push a page past `page_entries` or `max_bytes`.
///
/// `open` is the conjunction over both families, and it is what
/// [`export_page_in`]'s `is_last` is computed from. It is computed HERE rather
/// than at the call site so the two families cannot be enumerated in one order for
/// the entries and the other order for the finality decision.
fn family_page_segments(
    read: &ReadTransaction,
    request: &OrsBackupRequest,
    charged_entries: usize,
    charged_bytes: u64,
) -> Result<PageFamilySegments, OrsError> {
    let (recovery_entries, recovery, recovery_bytes) = family_page(
        read,
        request,
        RowFamilyKind::ProcessStreamRecovery,
        charged_entries,
        charged_bytes,
    )?;
    let spent = charged_bytes
        .checked_add(recovery_bytes)
        .ok_or(OrsError::ProjectionLimitExceeded)?;
    let (artifact_entries, artifacts, artifact_bytes) = family_page(
        read,
        request,
        RowFamilyKind::VersionedArtifacts,
        charged_entries + recovery_entries.len(),
        spent,
    )?;
    // The running total is read here, so the two family segments together are
    // asserted to leave the page inside the caller's declared byte budget rather
    // than the last charge being accumulated and discarded.
    let page_bytes = spent
        .checked_add(artifact_bytes)
        .ok_or(OrsError::ProjectionLimitExceeded)?;
    if page_bytes > request.max_bytes {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    let open = recovery
        .as_ref()
        .is_some_and(OrsFamilyContinuation::family_open)
        || artifacts
            .as_ref()
            .is_some_and(OrsFamilyContinuation::family_open);
    let mut entries = recovery_entries;
    entries.extend(artifact_entries);
    Ok(PageFamilySegments {
        entries,
        recovery,
        artifacts,
        open,
    })
}

/// Binds the next owner-issued cursor for one family to the request.
///
/// One dispatch over the request's two named family slots, and it keys on the
/// cursor's OWN frozen family rather than on the caller's expectation, so the
/// loop cannot advance one family's slot with the other family's cursor. Each
/// slot's own setter still refuses a cursor frozen for a different family; this
/// only chooses which setter to use.
fn attach_family_cursor(
    request: OrsBackupRequest,
    cursor: OrsFamilyCursor,
) -> Result<OrsBackupRequest, OrsError> {
    match cursor.identity.family {
        RowFamilyKind::ProcessStreamRecovery => request.with_process_stream_recovery_cursor(cursor),
        RowFamilyKind::VersionedArtifacts => request.with_versioned_artifact_cursor(cursor),
        _ => Err(OrsError::InvalidField {
            field: "backup_family",
            reason: "family is not paged through a typed family cursor",
        }),
    }
}

/// Exports one coherent backup page under a single read transaction (issue
/// #953).
///
/// The single-page entrypoint: it opens ONE `redb::ReadTransaction`, observes the
/// store-wide fence through it, refuses a request the owner cannot confirm, and
/// builds the page under that same transaction, so the page, the fence it names
/// and the rows it carries are one moment. A caller that wants a snapshot must
/// use [`export_snapshot`], which holds ONE transaction across the WHOLE page
/// loop; pages taken from repeated calls to this function are pages from
/// repeated read transactions and are therefore not one snapshot, whatever
/// timestamp they carry.
///
/// `page_index` selects a legacy count-stride window beginning at
/// `after_order + page_entries * page_index`. Operation orders may be sparse,
/// so this is not an exact continuation and does not prove complete coverage.
/// Callers building a snapshot must reuse the same request (same fence token)
/// across pages; [`export_snapshot`] applies a bounded refusal when its page
/// budget ends on a non-final page without an exact family continuation. This
/// does not make multi-page operational coverage exact. Any row decode failure
/// returns [`OrsError::IntegrityProblem`]; a page is never fabricated from
/// reference counts alone. Accumulated entry bytes are bounded by
/// `request.max_bytes` (already `1..=MAX_BACKUP_BYTES` by the request
/// constructor).
pub(super) fn export_page(
    database: &Database,
    request: &OrsBackupRequest,
    page_index: u32,
) -> Result<OrsBackupPage, OrsError> {
    let read = database.begin_read().map_err(storage)?;
    let observation = capture_store_fence(&read)?;
    check_export_fence(request, &observation)?;
    let page = export_page_in(&read, request, page_index, &observation)?;
    drop(read);
    Ok(page)
}

/// Builds one backup page under the caller's capture transaction (issue #953).
///
/// Split out of [`export_page`] so the whole page loop of a snapshot can run
/// under ONE read transaction, which is the issue's "one owner-established read
/// consistency point": "Independent per-page read transactions with a reused
/// timestamp are not one snapshot", so a page function that opens its own
/// transaction cannot be reused inside a page loop. Two callers: the single-page
/// entrypoint and [`export_snapshot`].
///
/// `observation` is the store-wide fence already read through `read` by
/// [`capture_store_fence`]. It is threaded in rather than re-read per page on
/// purpose: it is the same transaction, so the value would be identical, and
/// passing one observation is what makes every page of a snapshot carry the same
/// owner-observed values in its token.
///
/// No deadlock is possible from holding `read` across the loop. redb is MVCC: a
/// read transaction observes the last committed snapshot and does not block
/// writers, so a concurrent commit proceeds while this runs and simply becomes
/// invisible to it. The only cost is that pages the writer committed meanwhile are
/// not in this snapshot, and that is bounded: the page, byte and page-count
/// budgets already cap the retained pages at [`MAX_BACKUP_PAGES`] and
/// [`MAX_BACKUP_BYTES`], so the transaction's lifetime is bounded work, not
/// unbounded wait (A13.9: no unbounded wait may be held).
///
/// The operational-history window is unchanged. Neither cursor-paged family
/// (#269 process-stream recovery, #1971 versioned artifacts) is paged on that
/// window: their rows carry no canonical operation order, so each is paged
/// through its OWN request slot in durable-key order, sharing this page's
/// remaining row and byte budget so the per-page ceiling is unchanged. Each
/// family segment is admitted from what the previous one actually spent, so a
/// page can never exceed `page_entries` or `max_bytes` by running two families.
/// `is_last` is the conjunction of the operational window being exhausted and
/// BOTH families having no continuation left, so a page that still owes rows to
/// either family is never final.
fn export_page_in(
    read: &ReadTransaction,
    request: &OrsBackupRequest,
    page_index: u32,
    observation: &StoreFenceObservation,
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
    // The token binds the owner-observed fence, not only the caller's claim
    // about it, and the page's digest is derived from the finished page by the
    // ONE derivation in the contract module.
    let fence_token =
        request.observed_fence_token(observation.high_water_order, observation.family_revision);
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
    // Family paging, in a fixed order, each charged from what is actually left
    // of this page's admission.
    let families = family_page_segments(read, request, entries.len(), total_bytes)?;
    // `is_last` is the conjunction over BOTH families: a page that still owes rows
    // to either one is not final, so page continuity can never hide an unemitted
    // family tail behind a final page (issue #1971). A family the request declared
    // no cursor for contributes no continuation, which is `!open` and so does not
    // block finality — it makes the snapshot partial instead, which
    // `OrsBackupSnapshot::validate` is what refuses as `Complete`.
    let is_last = operational_exhausted && !families.open;
    entries.extend(families.entries);
    // Stamped by the store's own clock at capture, never by the caller, and
    // bounded by the ceiling the contract module enforces on validation. The
    // ordered-positive pair is validated by `validate_binding`, so a page whose
    // window does not close after it opens is refused rather than exported.
    let created_at_ms = super::current_unix_ms()?;
    let expires_at_ms = created_at_ms
        .checked_add(MAX_BACKUP_PAGE_LIFETIME_MS)
        .ok_or(OrsError::InvalidExpiry)?;
    let mut page = OrsBackupPage {
        page_index,
        entries,
        fence_token,
        created_at_ms,
        expires_at_ms,
        page_digest: String::new(),
        is_last,
        family_continuation: families.recovery,
        versioned_artifact_continuation: families.artifacts,
    };
    page.page_digest = page.expected_page_digest();
    page.validate_binding()?;
    Ok(page)
}

/// The page loop's whole output, gathered under the caller's capture
/// transaction (issue #953, #1971).
///
/// Split out of [`export_snapshot`] so the snapshot's pre/post witness ordering
/// stays readable as the ordering it exists for, and so the family-advance loop
/// is one function that is only about advancing families. `outstanding_*` are
/// read from the LAST page, which is the authority on whether each family is
/// finished even when an earlier page left a continuation open.
struct SnapshotPages {
    /// Ordered pages starting at index zero.
    pages: Vec<OrsBackupPage>,
    /// Total entries across the pages.
    entry_count: u64,
    /// Whether the last page emitted was final.
    last_page_was_final: bool,
    /// Exact continuation resuming the process-stream recovery family, if owed.
    outstanding_recovery: Option<OrsFamilyCursor>,
    /// Exact continuation resuming the versioned-artifact family, if owed.
    outstanding_artifact: Option<OrsFamilyCursor>,
    /// The request as the loop left it, carrying each family's final cursor.
    continuing: OrsBackupRequest,
}

/// Paginates one snapshot under the caller's single capture transaction.
///
/// The bounded loop of [`export_snapshot`]: at most `max_pages` pages, each built
/// by [`export_page_in`] through the SAME read transaction, until a page is final
/// or the page budget is spent. Holding one transaction across the whole loop is
/// what makes the pages one moment.
///
/// Each family advances by EXACTLY the owner-issued cursor its own previous page
/// ended with, and the advance is dispatched on that cursor's own frozen family,
/// so one family's next cursor can only ever land in that family's request slot.
fn export_pages_in(
    read: &ReadTransaction,
    request: &OrsBackupRequest,
    observation: &StoreFenceObservation,
) -> Result<SnapshotPages, OrsError> {
    let mut continuing = request.clone();
    let mut pages: Vec<OrsBackupPage> = Vec::new();
    let mut entry_count: u64 = 0;
    let mut last_page_was_final = false;
    for index in 0..u32::from(request.max_pages) {
        let page = export_page_in(read, &continuing, index, observation)?;
        entry_count = entry_count
            .checked_add(page.entries.len() as u64)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        let next_recovery = page
            .family_continuation
            .as_ref()
            .and_then(|continuation| continuation.next.clone());
        let next_artifact = page
            .versioned_artifact_continuation
            .as_ref()
            .and_then(|continuation| continuation.next.clone());
        last_page_was_final = page.is_last;
        pages.push(page);
        if last_page_was_final {
            break;
        }
        if let Some(next) = next_recovery {
            continuing = attach_family_cursor(continuing, next)?;
        }
        if let Some(next) = next_artifact {
            continuing = attach_family_cursor(continuing, next)?;
        }
    }
    if pages.is_empty() {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    // The last page is the authority on whether EACH family is finished: a page
    // that ended a family leaves no continuation for it even when an earlier page
    // did, so a snapshot is never left claiming an outstanding cursor it has
    // already emitted past.
    let outstanding_of = |page: Option<&OrsBackupPage>, family: RowFamilyKind| {
        page.and_then(|page| match family {
            RowFamilyKind::ProcessStreamRecovery => page.family_continuation.as_ref(),
            RowFamilyKind::VersionedArtifacts => page.versioned_artifact_continuation.as_ref(),
            _ => None,
        })
        .and_then(|continuation| continuation.next.clone())
    };
    let last = pages.last();
    Ok(SnapshotPages {
        outstanding_recovery: outstanding_of(last, RowFamilyKind::ProcessStreamRecovery),
        outstanding_artifact: outstanding_of(last, RowFamilyKind::VersionedArtifacts),
        pages,
        entry_count,
        last_page_was_final,
        continuing,
    })
}

/// Exports a snapshot by paging with one request until a page is final or the
/// page budget is exhausted.
///
/// The whole page loop runs under ONE `redb::ReadTransaction` (issue #953). This
/// is the issue's "one owner-established read consistency point": before, every
/// page opened and dropped its own transaction, so the page loop was N+2
/// transactions and "Independent per-page read transactions with a reused
/// timestamp are not one snapshot" — a writer committing between two pages put
/// row 1 of the snapshot at one moment and row 2 at another, under one fence and
/// one token. Now the pages, the observed fence and the PRE witness all speak for
/// the same committed snapshot, and "Changes after the fence cannot silently enter
/// later pages" holds by construction rather than by comparison. The composite
/// POST witness deliberately does NOT speak for that snapshot; see the two
/// properties below. Holding the transaction cannot deadlock: redb is MVCC, read
/// transactions do not block writers, and the loop is already bounded by
/// `max_pages`, `page_entries` and `max_bytes`.
///
/// The request's declared fence is compared against live owner state BEFORE any
/// page is read, by [`check_export_fence`], and a declared family cursor is
/// compared by [`check_family_revision_frozen`]; both refuse with existing typed
/// errors.
///
/// TWO properties, from two different mechanisms, and they must not be confused:
///
/// 1. PAGES ARE ONE MOMENT. Guaranteed by holding ONE transaction across the
///    whole loop. "Changes after the fence cannot silently enter later pages"
///    holds by construction: a write committing after the capture began is not
///    merely excluded from the pages, it is excluded from every page, because
///    there is only one snapshot to read them from. Nothing compares anything to
///    achieve this; it is a property of reading all pages under one transaction.
///
/// 2. MOVEMENT DURING THE CAPTURE IS DETECTED. Guaranteed by the
///    [`composite_state_digest`] pre/post pair, whose two ends are deliberately
///    DIFFERENT moments: `frozen_pre` is computed INSIDE the capture transaction,
///    before the page loop, and `frozen_post` is computed from a NEW read
///    transaction opened only AFTER the capture transaction has been released. A
///    writer that commits during the capture therefore moves the composite digest
///    and the export refuses with [`OrsError::OrderingHeadMismatch`].
///
/// Property 1 on its own would leave that writer undetected: the pages would be
/// perfectly coherent and simply stale relative to a store that moved on. The
/// post-release observation is what turns coherence into evidence. The
/// post-release read is a genuinely NEW snapshot precisely because the capture
/// transaction has been dropped - reading it again inside the capture transaction
/// would compare a snapshot with itself, which can never disagree and would be a
/// call that reads like a safety net while being structurally incapable of
/// firing. The two ends are therefore never taken from one snapshot on this path,
/// and the import triage path keeps the same two-separate-transactions form.
///
/// SCOPE OF PROPERTY 2, stated so this is not read as broader than it is:
/// `composite_state_digest` binds the operational history and the root of every
/// cursor-paged family (issue #1971 adds the versioned-artifact axis to the
/// process-stream recovery one #2884 added). It does **not** bind every physical
/// ORS table. A commit that moves some other table during the capture - a grant
/// closure row, a replay event, a doctor budget, an activation lifecycle, a
/// campaign record, a bridge-event record, or the meta counters themselves -
/// does not move this digest and will not trip the witness. That limit is
/// pre-existing and unchanged in kind by this issue; the two-transaction witness
/// that existed before behaved identically. It is recorded here because a witness
/// described without its scope is the same defect as a witness that cannot fire.
/// The rows with no row-family disposition at all (see the A5 gap: `RowFamilyKind`
/// enumerates 41 families while roughly 20 physical tables have none) are
/// consequently outside BOTH the denominator and this witness, which is a
/// compounding gap that neither property above closes.
///
/// ASSUMPTION: the capture's wall-clock stamp comes from the store's own
/// `current_unix_ms()` (a `SystemTime` read). I05-16 lists `created_at`,
/// `observed_at`, `valid_time`, `known_time` and `transaction_time` as distinct
/// durable fields and no governing document says which one a backup capture
/// window is. The page's window is stamped with the store's single clock at
/// capture and the page's `order` values remain the durable observation times;
/// the window is a triage-eligibility horizon, not a claim about any of the five
/// durable time fields, and it certifies nothing about the rows' times.
///
/// The operational request (fence token, `after_order`, page size) is reused
/// for every page, but its count-stride windows are not an exact continuation
/// in the sparse operation-order domain. Only the typed family cursors advance,
/// each by exactly the owner-issued cursor its own previous page ended with.
///
/// When the page budget ends on a non-final page, the exact family cursor is
/// retained as a `Partial` disposition when one exists. If no family cursor
/// remains, export returns [`OrsError::ProjectionLimitExceeded`] rather than
/// letting budget exhaustion fall through to `Complete` or an unresumable
/// partial snapshot. This bounded refusal does not make the legacy operational
/// count-stride windows an exact multi-page continuation; sparse-order coverage
/// still requires an operational cursor. A request that declared no family
/// cursor for some cursor-paged family yields `Partial` with the legacy reason
/// when its final page is otherwise exhausted, because a snapshot with no
/// denominator for that family is partial evidence and not an empty complete
/// family. A decode failure reports [`OrsError::IntegrityProblem`], never
/// fabricated completeness. The denominator digest binds every exported entry's
/// payload digest together with the frozen identity of every cursor-paged family
/// this request declared.
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
    // THE consistency point: one read transaction, opened once, threaded through
    // the fence observation, the PRE witness and every page. Nothing in the loop
    // opens a second transaction, so all pages are one moment.
    let read = database.begin_read().map_err(storage)?;
    let observation = capture_store_fence(&read)?;
    check_export_fence(request, &observation)?;
    // Every declared family cursor is proved frozen BEFORE the page loop, so a
    // family that already moved refuses the whole export rather than only the
    // page that would have read it.
    if let Some(cursor) = request.family_cursor(RowFamilyKind::ProcessStreamRecovery) {
        check_family_revision_frozen(&read, cursor)?;
    }
    if let Some(cursor) = request.family_cursor(RowFamilyKind::VersionedArtifacts) {
        check_family_revision_frozen(&read, cursor)?;
    }
    // PRE witness, INSIDE the capture snapshot: the composite state as it stood
    // when the capture began. It folds both cursor-paged families.
    let frozen_pre = composite_state_digest(&read)?;
    let paged = export_pages_in(&read, request, &observation)?;
    // Release the capture transaction BEFORE observing again. This ordering is
    // the whole point: `frozen_pre` was taken inside that transaction, and the
    // observation below is taken from a NEW snapshot that can include commits the
    // capture could not see. Reading it from the still-open capture transaction
    // would compare a snapshot with itself and could never disagree, so the
    // witness would be decorative rather than a witness.
    drop(read);
    let post_read = database.begin_read().map_err(storage)?;
    let frozen_post = composite_state_digest(&post_read)?;
    drop(post_read);
    check_canonical_frozen(&frozen_pre, &frozen_post)?;
    let SnapshotPages {
        pages,
        entry_count,
        last_page_was_final,
        outstanding_recovery,
        outstanding_artifact,
        continuing,
    } = paged;
    if !last_page_was_final && outstanding_recovery.is_none() && outstanding_artifact.is_none() {
        // Operational pagination has no exact continuation yet. Refuse this
        // bounded export instead of allowing page-budget exhaustion to be
        // mistaken for an exhausted operational denominator.
        return Err(OrsError::ProjectionLimitExceeded);
    }
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
    let completeness = if outstanding_recovery.is_some() || outstanding_artifact.is_some() {
        // The page budget ran out with family rows still owed. The exact cursor
        // travels on the snapshot so the caller resumes rather than restarts,
        // and the snapshot stays explicitly partial instead of all-or-nothing.
        BackupCompleteness::Partial {
            reason: format!(
                "cursor-paged row families are not fully exported; resume with next_process_stream_recovery_cursor / next_versioned_artifact_cursor (recovery outstanding: {}, versioned artifact outstanding: {}, page budget spent: {})",
                outstanding_recovery.is_some(),
                outstanding_artifact.is_some(),
                !last_page_was_final
            ),
        }
    } else if continuing.process_stream_recovery_cursor.is_none()
        || continuing.versioned_artifact_cursor.is_none()
    {
        BackupCompleteness::Partial {
            reason: "no process-stream recovery or versioned-artifact family denominator was declared; legacy evidence, not an empty complete family"
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
        next_process_stream_recovery_cursor: outstanding_recovery,
        versioned_artifact_family: continuing
            .versioned_artifact_cursor
            .as_ref()
            .map(|cursor| cursor.identity.clone()),
        next_versioned_artifact_cursor: outstanding_artifact,
    };
    snapshot.denominator_digest = snapshot.snapshot_digest();
    Ok(snapshot)
}

/// Triages one backup page into quarantine without any durable write.
///
/// Verifies the import binding, then re-derives the page's own digest and
/// refuses the page when it does not match (issue #953). That is the whole point
/// of the change: triage used to accept any 64-hex `page_digest` on shape, so a
/// page assembled from two different exports — or a page whose entries were
/// altered after export — was triaged as if it were one capture. The re-derivation
/// is [`OrsBackupPage::validate_binding`], the SAME function the snapshot
/// validator uses, so the two paths cannot disagree about what a page binds.
///
/// The capture window is then compared against the store's own clock, which
/// `validate_binding` cannot do because it is pure: a page whose window has
/// elapsed is [`OrsError::InvalidExpiry`] rather than triageable evidence. This is
/// a refusal horizon, never a deletion (I05-2).
///
/// Then each entry is classified: non-restorable or forensic-only families land
/// `Forensic` and are never activated; malformed digests land `Blocked`; a stored
/// row with the same digest replays as `Rejected` (duplicate) while the same key
/// with a different hash lands `Blocked` with `IDENTITY_CONFLICT`; anything else
/// lands `Unresolved`, quarantined for the canonical owner. The whole entry loop
/// runs under ONE read transaction (issue #953), for the same reason the export
/// page loop does: per-entry transactions meant the duplicate/identity comparison
/// of entry 1 and of entry N could disagree about the state they were compared
/// against, and the resulting outcome vector described no single moment. A
/// pre/post [`composite_state_digest`] freeze check brackets that work with two
/// SEPARATE transactions and so remains a genuine cross-moment witness, rejecting
/// concurrent canonical advance *or* a moved process-stream recovery family.
/// Per-entry canonical evidence calls are deliberately skipped: there is no signed
/// inbox item here to verify, so verification is deferred to
/// `import_recovery_inbox`, which owns durable quarantine. Unknown stays
/// quarantined with no blind retry. Page-to-review snapshot binding is
/// re-established by the canonical owner from `import.snapshot_digest` at
/// reconcile time; pages carry no snapshot field.
///
/// A process-stream recovery entry lands `Unresolved` here whatever its digest,
/// because paging the family into more pages raises no authority: the only
/// durable restore route for it is
/// `RedbRecoveryStore::import_process_stream_recovery_suspended`, which discards
/// the incoming activation and always writes suspended recovery evidence.
///
/// A versioned-artifact entry lands `Forensic` here (issue #1971) and nothing
/// else, because its family's disposition is `NonrestorableHistorical`: an
/// exported generation row is installation-bound history, so triaging it can
/// never reactivate a prior installation's generation authority, and no durable
/// import path for it exists at all (I1.6: a versioned binary is never replaced
/// in place while running; I1.12: a rollback is only ever an artifact verified
/// compatible with current durable formats and epoch lineage, which a restored
/// row is not). Triage still never constructs `PerEntryOutcome::Imported`.
pub(super) fn import_page_quarantined(
    database: &Database,
    evidence: &Arc<dyn super::CanonicalEvidenceProvider>,
    import: &OrsBackupImportRequest,
    page: &OrsBackupPage,
) -> Result<Vec<(String, PerEntryOutcome)>, OrsError> {
    let _ = evidence;
    validate_import_binding(&import.source, &import.destination)?;
    // Re-derive the page digest and every self-binding field. Replaces the shape
    // check this path used to do, and the duplicated entry-bound and family
    // continuation checks: `validate_binding` is now the single judgement of
    // whether a presented page is the page its token and digest claim, and it
    // reports the same `InvalidCursorLimit` the snapshot validator already
    // reported for an oversized page.
    page.validate_binding()?;
    // Same rule as the snapshot validator: a final page must leave NO paged family
    // open, and `validate_binding` cannot know that from one page alone. Both
    // continuations are checked because `is_last` is their conjunction (#1971).
    let family_open = page
        .family_continuation
        .as_ref()
        .is_some_and(OrsFamilyContinuation::family_open)
        || page
            .versioned_artifact_continuation
            .as_ref()
            .is_some_and(OrsFamilyContinuation::family_open);
    if page.is_last && family_open {
        return Err(OrsError::InvalidField {
            field: "backup_page_is_last",
            reason: "a final page must not leave an open family continuation",
        });
    }
    if page.expires_at_ms <= super::current_unix_ms()? {
        return Err(OrsError::InvalidExpiry);
    }
    let pre_read = database.begin_read().map_err(storage)?;
    let frozen_pre = composite_state_digest(&pre_read)?;
    drop(pre_read);
    // ONE read transaction for the whole entry loop: every entry is triaged
    // against the same durable state, so the outcome vector describes one moment.
    let read = database.begin_read().map_err(storage)?;
    let mut outcomes: Vec<(String, PerEntryOutcome)> = Vec::with_capacity(page.entries.len());
    for entry in &page.entries {
        outcomes.push((entry.record_id.clone(), triage_entry(&read, entry)?));
    }
    drop(read);
    let post_read = database.begin_read().map_err(storage)?;
    let frozen_post = composite_state_digest(&post_read)?;
    drop(post_read);
    check_canonical_frozen(&frozen_pre, &frozen_post)?;
    Ok(outcomes)
}

/// Classifies one backup entry against durable state without writing.
///
/// Pure read path shared by [`import_page_quarantined`]: family disposition
/// first (forensic families never reach identity comparison), digest shape
/// second, then a bounded identity scan for `IDENTITY_CONFLICT` versus
/// duplicate replay. Returns the outcome; never activates, never writes.
///
/// Takes the caller's read transaction rather than opening one per entry
/// (issue #953), so the identity comparison for every entry in a page observes
/// the same durable state and no writer can make two entries of one page disagree
/// about the row they collided with.
fn triage_entry(
    read: &ReadTransaction,
    entry: &OrsBackupEntry,
) -> Result<PerEntryOutcome, OrsError> {
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
