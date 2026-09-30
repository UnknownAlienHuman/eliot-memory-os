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
//! Issue #953 gives the row family denominator its missing reader
//! ([`check_row_family_census`]). [`row_family_denominator`] was a static
//! `vec![]` that nothing compared with anything, so a physical ORS table absent
//! from the list was invisible in both directions: not exported, not counted and
//! not refused. The census names the store's tables by referencing `store.rs`'s
//! own constants, so a renamed table cannot drift from its entry, and it compares
//! that list with the tables redb reports for the file being read, under the same
//! transaction as the pages. Counted at the time of writing: 75 distinct declared
//! tables, 45 backing a dispositioned row family and 30 carrying an explicit
//! source-bound nonrestorable/forensic exclusion with the reason written next to
//! it; 43 dispositioned families, each bound to at least one table, so none is
//! excused from having one. A table with no disposition is refused with
//! [`OrsError::MigrationRequired`] on all three paths that run —
//! [`export_page`], [`export_snapshot`] and [`import_page_quarantined`] — so it
//! cannot be silently exported, imported or counted, and no table disappears
//! because its name was absent from an old checklist.
//!
//! Be precise about what that count is. The census is a hand-maintained list of
//! constants; it is NOT derived from the `TableDefinition::new` declarations, and
//! nothing in the crate enforces that the two agree. So the live comparison in
//! check 2 is a real reader that refuses a table the file has and the list does
//! not — but it only sees a table once some write has MATERIALISED it, and two
//! of the tables in this count (`CreatedOnFirstWrite`, like the P-06 purge-ledger
//! pair) exist in no file until their first write. A newly declared table can
//! therefore still be omitted from the census and stay invisible until a
//! production write creates it, at which point the fail-closed refusal above
//! fires. Making that impossible needs a `macro_rules!` declaration macro so a
//! table cannot exist without a census entry; that is a separate architectural
//! change and is deliberately not done here. Do not read "70 of 70" as a
//! compiler-enforced invariant — it is a measurement, and a new table in
//! `store.rs` is on its author.
//!
//! Issue #2883 adds the durable `backup.verify` result family to that same
//! denominator. `RowFamilyKind::BackupVerificationResults` is one row per distinct
//! `(principal, authority lineage, operation id)` within one installation's ORS
//! file, and it is now DECLARED in this EXISTING ORS operational retention/export
//! contract, which is the existing owner of its lifecycle. Be precise about what
//! that declaration is worth: `row_family_denominator` is now READ by
//! [`check_row_family_census`], which compares it with the tables redb reports
//! for the file being read and refuses a store whose tables outrun the compiled
//! contract (issue #953, A5), so the list is a census that runs rather than a
//! constant that is compared with nothing. What it still does NOT do is bound the
//! family: nothing here evicts, expires or caps it. Its real cardinality is one row per distinct
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
//! Issue #2967 gives the OPERATIONAL axis the same treatment, because it was the
//! only axis that had none of it. The operational window used to be
//! `after_order + page_entries * page_index` over a full table scan, and that is not
//! a continuation in a sparse order domain: with orders `1, 3, 5` and
//! `page_entries = 2` it emitted `[1, 3]`, then `[3, 5]`, then `[5]`, so row 3 and
//! row 5 were each exported twice and no page after page 0 could prove which rows
//! it owed. The window also had no upper bound, so a stable row above the captured
//! `high_water_order` was emitted under the older fence.
//!
//! What replaced it, by imitation of the family axis rather than by a second design:
//! - `RedbRecoveryStore::open_backup_operational_history` freezes the operational
//!   window once - the owner-observed high-water, the streamed content root under
//!   it, the eligible row count and the encoded-byte denominator - and returns the
//!   start of an [`OrsOperationalCursor`]. It is the only producer of that cursor.
//! - The walk is enumerated in the table's OWN durable-key order, which
//!   `persist_operational_record` already makes the `operation_order` order (its key
//!   is the zero-padded order followed by the record key), so a page costs one
//!   bounded seek plus its own rows. There is no full materialize-and-sort step, no
//!   new table and no parallel history database.
//! - Every page re-derives the frozen identity from durable state, proves the
//!   presented cursor's boundary against the emitted prefix, and emits only rows in
//!   `(previous_cursor, frozen_high_water]`. The next cursor is derived from the
//!   page's ACTUAL last emitted row.
//! - Exhausting the page or byte budget is a resumable `Partial` disposition
//!   carrying the exact next operational cursor, and `Complete` is reachable only
//!   when the operational walk AND every cursor-paged family are demonstrably
//!   exhausted under one set of frozen identities.
//! - Movement of the operational window under a frozen cursor is the existing typed
//!   [`OrsError::OrderingHeadMismatch`] movement disposition (the same variant the
//!   versioned-artifact family uses), never a page stitched from two revisions and
//!   never an old cursor reinterpreted against current rows.
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
//!
//! Issue #953 A17 gives the import receipt a real current owner. A quarantined
//! entry comes back `Unresolved` because nothing durable was written, so a
//! brand-new empty destination produces a `unresolved_count` of zero while
//! holding no evidence whatsoever about the effects those members describe —
//! "no row to collide with" is not "no effect pending". `reconcile_import_receipt`
//! therefore no longer builds a receipt out of the import vector alone: it
//! opens the store's OWN live recovery rows in one read transaction —
//! `RECOVERY_INBOX` and `RECOVERY_PROBLEMS`, the two tables this crate already
//! owns and writes — asks the current owner about every member of the receipt,
//! and records the answer as a `CurrentOwnerValidation` beside the typed verdict
//! of `OrsBackupImportReceipt::known_zero_unresolved`. That gate then refuses
//! unless the validation is bound to this snapshot, covers exactly this
//! receipt's members, read both live recovery families, and reports no
//! still-unresolved identity.
//!
//! The same issue then measured that this was still circular, and repaired it.
//! The roster `observe_current_owner_validation` recorded was a clone of the very
//! `per_entry` vector it was meant to police, and the gate compared that clone
//! with the receipt's copy of the same vector, so a valid nonempty snapshot whose
//! member was never triaged compared equal on both sides and reported a known
//! zero; the live scans could not catch it either, because they only look for
//! unresolved rows whose identifier already occurs in the roster they were
//! handed. `reconcile_import_receipt` now takes the ALREADY-VALIDATED snapshot
//! the import request names by `snapshot_digest`, proves it with the ONE existing
//! `OrsBackupSnapshot::validate` (which re-derives the declared denominator from
//! the snapshot's own pages), compares the snapshot's original recorded
//! `denominator_digest` against `import.snapshot_digest`, verifies the source
//! identity, and takes the expected roster from
//! `OrsBackupSnapshot::expected_member_roster` — family plus record identity, and
//! a refusal unless the snapshot is `Complete` or is a verified empty one. No
//! second registry and no invented digest: the archive the caller already holds is
//! the only source. `unresolved_count` is derived inside the receipt constructor
//! from the outcomes instead of being asserted beside them, and the coverage check
//! requires the expected members, the provided outcomes and the consulted roster
//! to be three rosters that agree, with a duplicate, foreign or missing outcome
//! refused rather than de-duplicated. `reconcile_lost_import_response` stays
//! historical: it re-evaluates the two recorded halves and reads no live state.
//!
//! The same issue then found the exhausted axis being RESTARTED rather than
//! finished. Each continuation said "no cursor left" by carrying `None`, and the
//! page loop had nothing to hand the following page in that case, so it left the
//! axis's PRE-PAGE cursor in force and the next page re-read the axis from there.
//! Issue #2967 had already fixed that for the operational window alone; the
//! families kept the defect in its exact form, so a family that closed on page N
//! was re-emitted on page N+1 while a later family carried the snapshot forward,
//! and every page digest still agreed because nothing in a page said which STATE
//! its axis was in — only that a cursor was missing.
//!
//! What changed, in the existing continuation contract rather than beside it:
//! - `OrsAxisState::{Open, Exhausted}` replaces `next: Option<Cursor>` on both
//!   the operational continuation and the family continuation, and each arm names
//!   the boundary it means: the resume point, or the walk's FINAL frontier. The
//!   incoming cursor stays a separate field, so a page still states what it read.
//! - `operational_segment` and `family_segment` retain that frontier on EVERY
//!   return and refuse to declare exhaustion below the frozen denominator, so only
//!   an owner-established final frontier can close an axis; a page or byte limit
//!   stays `Open` with the exact frontier to resume from. The operational
//!   `operational_tail` field is gone — it was the parallel cursor the new state
//!   replaces.
//! - `operational_page` and `family_page` skip an already-exhausted axis without
//!   spending any of the page's row or byte allowance, after re-proving its
//!   revision and its durable-key prefix, so the whole remaining admission goes
//!   to the axes that are still open.
//! - `export_pages_in` attaches every axis's frontier on BOTH arms, which is what
//!   makes an exhausted axis stay inert instead of restarting, and
//!   `export_snapshot` publishes an outstanding cursor only for an `Open` axis.
//! - `snapshot_completeness` requires every required axis to be EXPLICITLY
//!   exhausted at the denominator it was opened with, and a family that was never
//!   given a denominator stays a third, unknown-coverage condition.
//! - `export_snapshot` now calls the existing `OrsBackupSnapshot::validate` on
//!   the fully assembled archive before returning it. That is a guard on the
//!   state machine above, not a substitute for it, and it is what would have
//!   caught the repeated-read archive the audit's counterexample produces.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::ops::Bound;
use std::sync::Arc;

use redb::{Database, ReadTransaction, ReadableDatabase, ReadableTable, TableHandle};

use super::persistence_codec::{decode, decode_named, encode};
use super::persistence_models::{DurableInboxRecord, DurableOperationalRecord};
use super::storage;
use crate::backup_snapshot::{
    BACKUP_SNAPSHOT_SCHEMA_VERSION, BackupCompleteness, BackupPartialReason,
    CurrentOwnerValidation, KnownZeroVerdict, MAX_BACKUP_BYTES, MAX_BACKUP_PAGE_ENTRIES,
    MAX_BACKUP_PAGE_LIFETIME_MS, OrsAxisState, OrsBackupEntry, OrsBackupImportReceipt,
    OrsBackupImportRequest, OrsBackupPage, OrsBackupRequest, OrsBackupSnapshot,
    OrsFamilyContinuation, OrsFamilyCursor, OrsFamilyRowChain, OrsFamilySnapshotIdentity,
    OrsOperationalContinuation, OrsOperationalCursor, OrsOperationalSnapshotIdentity,
    PerEntryOutcome, RowDisposition, RowFamilyDisposition, RowFamilyKind, RowPayloadState,
    StoredEffectClass, check_canonical_frozen, validate_import_binding,
};
use crate::{
    ArtifactGenerationState, OperationalPhase, OrsError, ProcessStreamRecoveryProjection,
    ProcessStreamRecoveryWriteOutcome, RecoveryProblem, StreamRecoveryActivation,
    StreamRecoveryReconciliation, StreamRecoveryReconciliationState, VersionedArtifactEntry,
};

impl super::RedbRecoveryStore {
    /// Restores exported process-stream recovery rows as suspended recovery
    /// evidence (issue #269, W7).
    ///
    /// This is the restore-side driver the family's own durable import was
    /// missing. It supplies ACTUAL projection rows — the rows the archive holds
    /// for this page — to the family's one fail-closed import,
    /// [`RedbRecoveryStore::import_process_stream_recovery_suspended`], which
    /// discards the incoming activation and always writes `Suspended` (or keeps
    /// an already `Retired` row `Retired`). It creates no reservation, session or
    /// authority row, so an imported projection is recovered as suspended
    /// evidence and can never revive old process, session or authority state
    /// (A13.7: old sessions, leases, approvals and epochs do not revive).
    ///
    /// Each row is bound to the exact backup entry the page already carries for
    /// it before anything is written, so a restore cannot import a row the
    /// presented page never exported:
    /// - the entry's `record_id` is the family's durable key, its `order` and
    ///   `effect_class` are read off the same decoded row through the one
    ///   [`stream_recovery_entry`] the export uses, and its `payload_digest` is
    ///   the digest of the row re-encoded through the same ORS codec. Any
    ///   disagreement refuses the whole driver with zero writes.
    /// - every row is then pre-flighted against the destination's CURRENT
    ///   durable row for the same `(operation, stream)` key, still before the
    ///   first write, through [`restore_row_refusal`], which MIRRORS the
    ///   refusals the family's write body applies to a restored row — the write
    ///   body is the owner of every one of them. The mirrored set is: differing
    ///   evidence axes; an activation the destination may not become; an
    ///   archived `Retired` row landing on a destination row that is not already
    ///   `Retired` (a restore must not terminate a live row); a restore
    ///   rewriting the retained reconciliation of an already `Retired`
    ///   destination row; and the write-once `Reconciled` handoff rule, in ALL
    ///   THREE of its clauses and in BOTH branches of the check — a destination
    ///   that is not `Reconciled` may not be moved into it, one that is may not
    ///   be moved out of it, and one that is already `Reconciled` may not have
    ///   its owner or its `handoff_sha256` changed. Any of these refuses the
    ///   whole driver with zero writes, so a page is never left half-restored
    ///   by a refusal the driver could have seen in advance. The pre-pass is
    ///   strictly stronger than the write body for the terminal-over-live case:
    ///   it refuses that page even when the archived row is byte-identical to
    ///   the destination row apart from the activation. The pre-pass has no
    ///   case for an EMPTY `(operation, stream)` key, because the write body
    ///   has none either: the disclosed residual is that an archived
    ///   `Reconciled` row lands on a fresh key carrying its digest.
    ///
    /// The pre-pass reads destination state in one read transaction that is
    /// dropped before the first write, so the zero-write property is exact for
    /// a destination that does not move during the driver's pre-pass. A
    /// destination that does move is still stopped row by row by the write body
    /// itself, fail closed; the only difference is that such a move can abort
    /// the page after an earlier row was already written.
    ///
    /// The same source/destination and page bindings
    /// [`import_page_quarantined`](super::RedbRecoveryStore::import_backup_page_quarantined)
    /// applies are applied here, so a same-installation or expired page restores
    /// nothing. The family is not re-triaged, because triage is the quarantine
    /// reader: it constructs no `PerEntryOutcome::Imported` and confers no
    /// authority, and the suspended write below IS the family's own durable
    /// route.
    pub fn import_backup_process_stream_recovery_suspended(
        &self,
        import: &OrsBackupImportRequest,
        page: &OrsBackupPage,
        rows: &[ProcessStreamRecoveryProjection],
    ) -> Result<Vec<ProcessStreamRecoveryWriteOutcome>, OrsError> {
        validate_import_binding(&import.source, &import.destination)?;
        page.validate_binding()?;
        if page.expires_at_ms <= super::current_unix_ms()? {
            return Err(OrsError::InvalidExpiry);
        }
        let mut bound = Vec::with_capacity(rows.len());
        {
            // One read transaction for the whole pre-pass, dropped before the
            // first write so no reader overlaps the write loop below.
            let read = self.database.begin_read().map_err(storage)?;
            let destination_rows = read
                .open_table(super::PROCESS_STREAM_RECOVERY)
                .map_err(storage)?;
            for projection in rows {
                let record_id = projection.record_key()?;
                let entry = page
                    .entries
                    .iter()
                    .find(|entry| {
                        entry.family == RowFamilyKind::ProcessStreamRecovery
                            && entry.record_id == record_id
                    })
                    .ok_or_else(|| OrsError::IntegrityProblem {
                        record_type: "process_stream_recovery",
                        reason: format!(
                            "restored row {record_id:?} is not an entry of the presented backup page"
                        ),
                    })?;
                let (order, effect_class) = stream_recovery_entry(projection)?;
                if entry.order != order || entry.effect_class != effect_class {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "process_stream_recovery",
                        reason: format!(
                            "restored row {record_id:?} does not match the exported entry's order \
                             and effect class"
                        ),
                    });
                }
                let digest = crate::model::sha256_hex(encode(projection)?.as_bytes());
                if entry.payload_digest != digest {
                    return Err(OrsError::PayloadIntegrityMismatch);
                }
                // The pre-flight, in the same pass and still before any write:
                // a refusal the write body would raise on this row is raised
                // here, once for the whole page, instead of after an earlier row
                // of the same page was already written.
                let destination = destination_rows
                    .get(record_id.as_str())
                    .map_err(storage)?
                    .map(|value| decode::<ProcessStreamRecoveryProjection>(value.value()))
                    .transpose()?;
                if let Some(destination) = destination
                    && let Some(refusal) =
                        restore_row_refusal(&record_id, projection, &destination)?
                {
                    return Err(refusal);
                }
                bound.push(projection);
            }
        }
        let mut outcomes = Vec::with_capacity(bound.len());
        for projection in bound {
            outcomes.push(self.import_process_stream_recovery_suspended(projection)?);
        }
        Ok(outcomes)
    }
}

/// Whether one archived row must be refused against the destination's current
/// durable row for the same `(operation, stream)` key.
///
/// THE WRITE BODY IS THE OWNER OF EVERY RULE MIRRORED HERE. This pre-pass
/// duplicates them on purpose, so that the driver's documented "any
/// disagreement refuses the whole driver with zero writes" property holds and
/// the pre-pass can never say `Ok(None)` where the write body will refuse; the
/// duplication is accepted rather than factored into a cross-module helper
/// because a shared helper would put the rule outside the write body it
/// describes. If a rule changes in `RedbRecoveryStore`'s write body, it changes
/// here in the same item.
///
/// The activation an archived row imports as is restated here exactly as
/// [`RedbRecoveryStore::import_process_stream_recovery_suspended`] maps it,
/// which is the single owner of that rule: an already `Retired` row stays
/// `Retired` and every other row becomes `Suspended`.
///
/// `Ok(None)` means the write body accepts the pair. Each refusal below is one
/// the write body raises too, except the terminal-over-live case, where this
/// pre-flight is deliberately stricter: a restore proves no terminal
/// disposition, so it may re-preserve a terminal row into an empty key or over
/// an already terminal row, and never turns a live destination row terminal.
/// That single stricter case is disclosed at its own write path rather than
/// closed here, because closing it would break "an archived `Retired` row stays
/// `Retired`" (merged W7).
///
/// The caller invokes this only for a key the destination already holds; for
/// an EMPTY `(operation, stream)` key it is not called, and neither is the write
/// body able to compare any of its rules against anything, so an archived
/// `Reconciled` row lands on a fresh key with its digest. That is the one
/// remaining author of a `Reconciled` handoff and it is disclosed, not closed,
/// at [`RedbRecoveryStore::import_process_stream_recovery_suspended`].
fn restore_row_refusal(
    record_id: &str,
    archived: &ProcessStreamRecoveryProjection,
    destination: &ProcessStreamRecoveryProjection,
) -> Result<Option<OrsError>, OrsError> {
    let refusal = |reason: String| OrsError::IntegrityProblem {
        record_type: "process_stream_recovery",
        reason: format!(
            "restored row {record_id:?} conflicts with the destination's durable row: {reason}"
        ),
    };
    if destination.evidence_axes_sha256()? != archived.evidence_axes_sha256()? {
        return Ok(Some(refusal(
            "the durable evidence axes are immutable and differ".to_owned(),
        )));
    }
    let imported = if archived.activation == StreamRecoveryActivation::Retired {
        StreamRecoveryActivation::Retired
    } else {
        StreamRecoveryActivation::Suspended
    };
    let terminal_restore = imported == StreamRecoveryActivation::Retired;
    // The write-once `Reconciled` handoff rule, mirrored into BOTH branches
    // below, because the write body applies it above its whole `match`.
    let handoff_rewrite =
        reconciled_handoff_rewrite(&destination.reconciliation, &archived.reconciliation);
    if destination.activation == imported {
        // Observation-advance arm of the write body, which cannot move
        // activation. The write body's blanket "a non-admitted writer may not
        // change a durable row's reconciliation" rule does NOT apply here,
        // because a restore is admitted; what still applies is the write-once
        // handoff rule mirrored above, and the retained-history rule, which is
        // the comparison below. Mirroring both is what keeps this pre-pass
        // faithful to the write body it stands in front of, so the documented
        // "any disagreement refuses the whole driver with zero writes" property
        // holds for these conflicts instead of aborting the page after an
        // earlier row was written.
        if let Some(reason) = handoff_rewrite {
            return Ok(Some(refusal(reason.to_owned())));
        }
        if terminal_restore && destination.reconciliation != archived.reconciliation {
            return Ok(Some(refusal(
                "a restore must not rewrite the retained reconciliation of an already retired \
                 destination row"
                    .to_owned(),
            )));
        }
        return Ok(None);
    }
    if let Some(reason) = handoff_rewrite {
        return Ok(Some(refusal(reason.to_owned())));
    }
    if terminal_restore || !destination.activation.permits_transition_to(imported) {
        return Ok(Some(refusal(format!(
            "the destination row is {:?} and the restored row imports as {:?}, which that durable \
             row may not become",
            destination.activation, imported
        ))));
    }
    Ok(None)
}

/// The refusal reason for a write that rewrites a `Reconciled` handoff on a
/// durable row, or `None` for a write that does not.
///
/// This MIRRORS `RedbRecoveryStore`'s write-body rule and is not its owner: the
/// write body applies that rule above its whole `match`, for every writer, and
/// this pre-pass must agree with it in both the same-activation branch and the
/// transition branch or the driver's zero-write property would not hold. Three
/// clauses, exactly as the write body states them: a reconciliation that is not
/// `Reconciled` is never moved into it, a `Reconciled` one is never moved out
/// of it, and a row already `Reconciled` keeps its `owner` and its
/// `handoff_sha256` byte for byte.
///
/// A `destination` that is not `Reconciled` may still change owner and move
/// between the other three states — that is the ordinary cross-installation
/// restore, which legitimately presents a different `owner` and carries no
/// proof.
fn reconciled_handoff_rewrite(
    destination: &StreamRecoveryReconciliation,
    archived: &StreamRecoveryReconciliation,
) -> Option<&'static str> {
    let reconciled = StreamRecoveryReconciliationState::Reconciled;
    match (
        destination.state == reconciled,
        archived.state == reconciled,
    ) {
        (false, true) => Some(
            "a durable reconciliation is never moved into Reconciled by a restore, so an archived \
             reconciled handoff cannot be placed on a row that does not already carry one",
        ),
        (true, false) => Some(
            "a durable Reconciled handoff is write-once, so a restore may never move it out of \
             Reconciled",
        ),
        (true, true)
            if archived.owner != destination.owner
                || archived.handoff_sha256 != destination.handoff_sha256 =>
        {
            Some(
                "a durable Reconciled handoff is write-once and immutable, so a restore may not \
                 re-point its owner or its handoff digest",
            )
        }
        _ => None,
    }
}

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
        // Process evidence is observational only, and a pre-#269 row of this
        // family still holds the inline stdout/stderr payload: it exports as
        // forensics and never as an importable observation (#269 A1).
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
        // Cold-start leases and terminal readiness never revive on restore (#1790).
        RowFamilyDisposition::of(RowFamilyKind::ColdStartReadiness),
        // Owner-backed verification results are evidence, never authority: this
        // family is DECLARED in the EXISTING ORS operational retention/export
        // contract here (#2883 instruction 10), which is that contract's own
        // lifecycle owner. Be precise about what the declaration buys: since
        // issue #953 this function has a production reader,
        // `check_row_family_census`, so the family is now COUNTED against the
        // store's real tables — but nothing BOUNDS it, and that is a separate
        // owner's job. No eviction, TTL, cap or deletion is
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

/// The source-bound backup disposition of ONE physical ORS table (issue #953,
/// A5).
///
/// The issue's requirement is two-sided and both sides are here. "Every stored
/// row family is included" is [`TableDisposition::Family`]: the table is the
/// durable backing of a row family, and that family's exact policy is
/// [`row_family_denominator`], so there is one disposition per family and not
/// one per table. "or has an explicit source-bound nonrestorable/forensic
/// exclusion" is [`TableDisposition::Excluded`]: the table is named, its
/// disposition is one of the two exclusion dispositions, and the reason is
/// written next to it. An unnamed table is not an option — that is the whole
/// point, because a table that is merely absent from a list is indistinguishable
/// from a table that was forgotten.
#[derive(PartialEq, Eq)]
enum TableDisposition {
    /// The table is the durable backing of a dispositioned row family.
    Family(RowFamilyKind),
    /// The table is not a backup row family, permanently and by decision.
    Excluded {
        /// Always `NonrestorableHistorical` or `ForensicOnly`. `Restorable` is
        /// refused for an excluded table by [`check_row_family_census`]: it means
        /// "eligible for the family's own quarantined import", and a table with
        /// no family has no import path, so the word would advertise a durable
        /// re-import that does not exist.
        disposition: RowDisposition,
        /// Why this table is excluded, in terms of what restoring it would mean.
        reason: &'static str,
    },
}

/// One physical ORS table and the disposition that covers it.
struct DispositionedTable {
    /// The store's OWN table constant, not a re-spelled name.
    table: FamilyTable,
    disposition: TableDisposition,
}

/// Every physical table the ORS store declares, each with its exact disposition
/// (issue #953, A5).
///
/// The table is named by referencing `store.rs`'s own `const`, never by
/// restating its string. That is the difference between a census and another
/// hand-maintained list: a renamed or replaced table changes its `TableDefinition`
/// here too, so the two cannot drift apart, and the live-name comparison in
/// [`check_row_family_census`] is the only place a literal name appears at all —
/// and there it comes from redb, not from this file.
///
/// Counted against `store.rs`, `store/restore_journal.rs` and `status.rs` at the
/// time of writing: 76 distinct declared tables, of which 46 back a dispositioned
/// row family and 30 are explicit source-bound exclusions.
/// `row_family_denominator` carries 43 families and every one of them is now bound
/// to a table by this census.
///
/// That count is a MEASUREMENT, not an enforced invariant, and the difference
/// matters. This census is a hand-maintained list of constants; nothing in the
/// crate derives it from the `TableDefinition::new` declarations themselves, so a
/// NEW table added to `store.rs` is not automatically censused, and it will not be
/// caught here until some write materialises it in a file and check 2 reads its
/// name out of `list_tables()`. The two P-06 purge-ledger tables were exactly
/// that omission for exactly that long: declared, written by the production
/// `backup.verify` path, and absent from this list, which refused every export of
/// every store that had answered one verification. Closing that permanently needs
/// a `macro_rules!` declaration macro so a table cannot exist without an entry
/// here, which is a separate architectural change and deliberately not attempted
/// in this issue. Until it exists, a table added to `store.rs` is on the author.
///
/// Split in four so no half can grow past the point where a reader stops
/// checking it: 46 table-backed tables and 29 source-bound exclusions.
fn dispositioned_tables() -> Vec<DispositionedTable> {
    let mut tables = family_backed_tables();
    tables.extend(source_bound_exclusions());
    tables
}

/// Binds one table to the row family that owns it.
fn family(table: FamilyTable, kind: RowFamilyKind) -> DispositionedTable {
    DispositionedTable {
        table,
        disposition: TableDisposition::Family(kind),
    }
}

/// Records one table as an explicit, source-bound exclusion.
///
/// The reason is a mandatory argument, not a comment: it is what makes this entry
/// a decision rather than an absence, and it says what restoring the table would
/// MEAN, which is the question an operator actually has when a row is missing
/// from a restore.
fn excluded(
    table: FamilyTable,
    disposition: RowDisposition,
    reason: &'static str,
) -> DispositionedTable {
    DispositionedTable {
        table,
        disposition: TableDisposition::Excluded {
            disposition,
            reason,
        },
    }
}

/// The 45 tables that back a dispositioned row family.
fn family_backed_tables() -> Vec<DispositionedTable> {
    let mut tables = canonical_family_tables();
    tables.extend(supervision_and_replay_family_tables());
    tables.extend(restore_journal_family_tables());
    tables
}

/// The 22 tables backing the canonical operational and recovery row families.
fn canonical_family_tables() -> Vec<DispositionedTable> {
    vec![
        family(super::ENVELOPES, RowFamilyKind::Envelopes),
        family(super::RESERVATIONS, RowFamilyKind::Reservations),
        family(super::RESERVATION_ORDERS, RowFamilyKind::ReservationOrders),
        family(super::SCOPE_HEADS, RowFamilyKind::ScopeHeads),
        family(super::SCOPE_TERMINALS, RowFamilyKind::ScopeTerminals),
        family(
            super::OPERATIONAL_CURRENT,
            RowFamilyKind::OperationalCurrent,
        ),
        family(
            super::OPERATIONAL_HISTORY,
            RowFamilyKind::OperationalHistory,
        ),
        family(super::RECOVERY_INBOX, RowFamilyKind::RecoveryInbox),
        family(
            super::RECOVERY_INBOX_HISTORY,
            RowFamilyKind::RecoveryInboxHistory,
        ),
        family(
            super::PROCESS_START_REPLAY,
            RowFamilyKind::ProcessStartReplay,
        ),
        family(super::AUTHORITY_HANDOFFS, RowFamilyKind::AuthorityHandoffs),
        family(super::PROCESS_EVIDENCE, RowFamilyKind::ProcessEvidence),
        family(
            super::PROCESS_STREAM_RECOVERY,
            RowFamilyKind::ProcessStreamRecovery,
        ),
        family(
            super::SCAN_DISCLOSURE_RECORDS,
            RowFamilyKind::ScanDisclosure,
        ),
        // Lease revisions, revision heads, and exact-binding indexes belong to
        // one readiness family; none can be restored as live readiness.
        family(
            super::COLD_START_READINESS_RECORDS,
            RowFamilyKind::ColdStartReadiness,
        ),
        family(
            super::COLD_START_READINESS_HEADS,
            RowFamilyKind::ColdStartReadiness,
        ),
        family(
            super::COLD_START_READINESS_BINDINGS,
            RowFamilyKind::ColdStartReadiness,
        ),
        family(
            super::BACKUP_VERIFICATION_RESULTS,
            RowFamilyKind::BackupVerificationResults,
        ),
        family(super::CUTOVER_OWNERSHIP, RowFamilyKind::CutoverOwnership),
        family(super::HOST_REQUESTS, RowFamilyKind::HostRequests),
        // #1945: evaluated tool-exposure receipts are operation-bound evidence
        // of past completions, never re-dispatchable routes, so they ride the
        // host-requests family beside the rows they evidence.
        family(
            super::HOST_REQUEST_TOOL_EXPOSURE_RECEIPTS,
            RowFamilyKind::HostRequests,
        ),
        family(
            super::VERSIONED_ARTIFACTS,
            RowFamilyKind::VersionedArtifacts,
        ),
        family(
            super::ACTIVATION_LIFECYCLES,
            RowFamilyKind::ActivationLifecycle,
        ),
    ]
}

/// The 17 tables backing the supervision, replay, doctor and retention families.
///
/// A separate function from [`canonical_family_tables`] only because the whole
/// census must stay inside one reviewable length; the split is at the
/// supervision-lease boundary, which is also where the issue's own list of
/// retained families begins.
fn supervision_and_replay_family_tables() -> Vec<DispositionedTable> {
    vec![
        family(
            super::SUPERVISION_LEASE_STAGED,
            RowFamilyKind::SupervisionLeaseStaged,
        ),
        family(
            super::SUPERVISION_LEASE_CURRENT,
            RowFamilyKind::SupervisionLeaseCurrent,
        ),
        family(
            super::SUPERVISION_LEASE_HISTORY,
            RowFamilyKind::SupervisionLeaseHistory,
        ),
        family(
            super::SUPERVISION_LEASE_RESULTS,
            RowFamilyKind::SupervisionLeaseResults,
        ),
        family(
            super::SUPERVISION_LEASE_STAGE_RESOLUTIONS,
            RowFamilyKind::SupervisionStageResolutions,
        ),
        family(super::STORE_REBIND_REPLAY, RowFamilyKind::StoreRebindReplay),
        family(
            super::STORE_FAILURE_RETENTION,
            RowFamilyKind::StoreFailureRetention,
        ),
        family(
            super::UNKNOWN_COMMIT_RECOVERY,
            RowFamilyKind::UnknownCommitRecovery,
        ),
        family(
            super::ACTIVATION_RESULT_RETENTION,
            RowFamilyKind::ActivationResultRetention,
        ),
        family(
            super::NATIVE_WORKER_CLAIMS,
            RowFamilyKind::NativeWorkerClaims,
        ),
        family(super::REPLAY_STREAMS, RowFamilyKind::ReplayStreams),
        family(super::REPLAY_REQUESTS, RowFamilyKind::ReplayRequests),
        family(super::REPLAY_EVENTS, RowFamilyKind::ReplayEvents),
        family(super::REPLAY_ACKS, RowFamilyKind::ReplayAcks),
        family(super::DOCTOR_ATTEMPTS, RowFamilyKind::DoctorAttempts),
        family(super::DOCTOR_EFFECTS, RowFamilyKind::DoctorEffects),
        family(super::DOCTOR_BUDGETS, RowFamilyKind::DoctorBudgets),
        family(super::RECOVERY_PROBLEMS, RowFamilyKind::RecoveryProblems),
        family(
            super::GRANT_CLOSURE_CURRENT,
            RowFamilyKind::GrantClosureCurrent,
        ),
        family(
            super::GRANT_GRAPH_REVISION_CURRENT,
            RowFamilyKind::GrantGraphRevisionCurrent,
        ),
    ]
}

/// The three tables backing the restore-journal row families (issue #953, A5).
///
/// These are real redb tables, declared and created by
/// `store/restore_journal.rs` on every store that adopts the journal, and each
/// one is the durable backing of a [`RowFamilyKind`] that
/// [`row_family_denominator`] already dispositions. They were previously
/// recorded in a `table_less_families` list whose stated premise — that the
/// restore-journal families "are not a redb table family at all" — was false, and
/// that false premise is exactly what let three LIVE table names through check 2
/// uncensored while their families were covered by check 4. They are named here
/// so a census entry and a live table name are the same fact.
fn restore_journal_family_tables() -> Vec<DispositionedTable> {
    vec![
        family(
            super::restore_journal::RESTORE_JOURNAL_INTENTS,
            RowFamilyKind::RestoreJournalIntents,
        ),
        family(
            super::restore_journal::RESTORE_JOURNAL_RESULTS,
            RowFamilyKind::RestoreJournalResults,
        ),
        family(
            super::restore_journal::RESTORE_JOURNAL_META,
            RowFamilyKind::RestoreJournalMeta,
        ),
    ]
}

/// The 29 tables that are explicitly NOT backup row families, each with the
/// disposition and the reason that excludes it.
///
/// Grouped by what makes a table un-restorable rather than alphabetically, so
/// the grouping's own justification is visible.
fn source_bound_exclusions() -> Vec<DispositionedTable> {
    let mut tables = owner_state_exclusions();
    tables.extend(projection_family_exclusions());
    tables.extend(effect_replay_family_exclusions());
    tables.extend(purge_ledger_exclusions());
    tables
}

/// The six exclusions that are owner state: four re-established by the
/// receiving owner, two superseded or already-committed facts.
fn owner_state_exclusions() -> Vec<DispositionedTable> {
    vec![
        // ---- Owner-re-established state, not historical evidence ------------
        // #953 (A5). The store's own record of which exact write it already
        // performed. It is not a historical projection and not an index over
        // another table: it IS the dedup decision, and the receiving
        // installation re-establishes it from its own writes. A restored binding
        // would make the destination answer "already written" for an operation
        // it never performed, which is a lost write, not a stale row.
        excluded(
            super::WRITE_IDEMPOTENCY,
            RowDisposition::NonrestorableHistorical,
            "the durable write-dedup index is the store's own record of which exact write it already performed; the receiving owner re-establishes it from its own writes, and a restored binding would answer already-written for an operation this installation never performed",
        ),
        // Not a row family: the store's own counters and schema keys. The
        // receiving installation re-establishes them from its own writes, and a
        // restored counter would let a fresh file claim an ordering head or a
        // family revision it never had.
        excluded(
            super::META,
            RowDisposition::NonrestorableHistorical,
            "store-owned counters and schema keys are re-established by the receiving owner; a restored counter would let a fresh file claim an ordering head it never had",
        ),
        // #1872: the generation a capability route scope started at. It is
        // installation-bound generation authority, not history: it is what makes
        // "no committed cutover for this scope" name one generation instead of
        // any. A restored row would present the destination with the source
        // installation's initial route owner, so recovery must not resurrect it
        // (I14.14 / ARCH-RES-03).
        excluded(
            super::CANONICAL_STORE_ROUTE_OWNERSHIP,
            RowDisposition::NonrestorableHistorical,
            "the established owner of a capability route scope is installation-bound generation authority naming the generation that scope started at; recovery must not resurrect another installation's initial route owner",
        ),
        // #1872: an irreversible migration or external effect already declared
        // on this installation's canonical_store route. It is a write-ahead
        // declaration bound to one committed cutover's own ORS linearization
        // identity, and both halves of that binding are installation-bound: a
        // restored row would name a cutover the destination's own committed
        // lineage does not carry, so it could not be honoured, and the
        // destination must reach its own forward-repair decision from its own
        // effects rather than from this installation's (I5.11 / I14.14).
        excluded(
            super::IRREVERSIBLE_STORAGE_EFFECTS,
            RowDisposition::NonrestorableHistorical,
            "a declared irreversible storage effect is installation-bound generation authority about what this installation already did to its own canonical store; a restored row names a cutover of the source installation's committed lineage and would either be unprovable here or refuse a rollback for an effect this installation never issued",
        ),
        // Not a row family: the durable operation index is re-derived by the
        // canonical ordering owner from the operational history it admits, so a
        // restored index would present another installation's operations as this
        // one's.
        excluded(
            super::OPERATIONS,
            RowDisposition::NonrestorableHistorical,
            "the durable operation index is re-derived by the canonical ordering owner; a restored index would present another installation's operations as this one's",
        ),
        // Not a row family: a derived index over HOST_REQUESTS, carrying no row a
        // backup of that family does not already carry.
        excluded(
            super::HOST_REQUEST_LOGICAL_KEYS,
            RowDisposition::NonrestorableHistorical,
            "a derived lookup index over HOST_REQUESTS; it is rebuilt from those rows and holds no row of its own",
        ),
        // ---- Explicit source-bound exclusions: superseded or committed ----
        // Superseded by `GRANT_CLOSURE_CURRENT` (v2). Its bytes are an explicit
        // startup-migration input and are removed by that migration, so a
        // restored row is a legacy artefact, never a closure fact.
        excluded(
            super::GRANT_CLOSURE_LEGACY_CURRENT,
            RowDisposition::ForensicOnly,
            "superseded by the v2 closure table; these bytes are a startup-migration input that migration removes, never a restorable closure fact",
        ),
        // Committed second-phase closure links. They record that an order was
        // placed; no import path re-authorizes one, and re-deriving them from
        // the first-phase row is the owner's job at its own write time.
        excluded(
            super::GRANT_CLOSURE_SECOND_PHASE_CURRENT,
            RowDisposition::ForensicOnly,
            "committed second-phase closure links are evidence that an order was placed; no import path re-authorizes one and the owner re-derives them at its own write time",
        ),
    ]
}

/// The seventeen exclusions that are another owner's projection: four campaign
/// families and thirteen bridge families.
///
/// `ForensicOnly` for all of them, and for the same reason the
/// `BackupVerificationResults` sibling is: none has a durable `import_*_suspended`
/// path in this crate, so `Restorable` would advertise a re-import that does not
/// exist, while every one of them is genuinely evidence about a past event.
fn projection_family_exclusions() -> Vec<DispositionedTable> {
    vec![
        // ---- Campaign projections ------------------------------------------
        // Generated views are derived from authenticated local reads. A
        // restored view is stale by construction, and its content address names
        // bytes a future read of the restored store need not reproduce.
        excluded(
            super::CAMPAIGN_LEARNING_STATE_VIEWS,
            RowDisposition::ForensicOnly,
            "content-addressed views generated from authenticated local reads; a restored view is stale by construction and its address need not name anything a future read reproduces",
        ),
        // Immutable owner-source rows: evidence of a past publication, with no
        // durable import path in this crate.
        excluded(
            super::CAMPAIGN_SOURCE_RECORDS,
            RowDisposition::ForensicOnly,
            "immutable owner-source rows are evidence of a past publication; this crate has no import path that would make one current again",
        ),
        // Current heads are the installation's own source authority. A restored
        // head would re-point the owner at a source the restored installation
        // never read from.
        excluded(
            super::CAMPAIGN_SOURCE_HEADS,
            RowDisposition::ForensicOnly,
            "current owner-source heads are this installation's own source authority; a restored head would re-point the owner at a source it never read",
        ),
        // Pre-commit CAS reservations exist to reconcile a crash this
        // installation did not have. Replaying one would re-reserve against
        // durable state that no longer exists.
        excluded(
            super::CAMPAIGN_SOURCE_PENDING,
            RowDisposition::ForensicOnly,
            "pre-commit CAS reservations reconcile a crash the restored installation did not have; replaying one would re-reserve against state that no longer exists",
        ),
        // ---- Bridge families, owned by the bridge owner -------------------
        // Bridge-event rows are bound to the bridge owner's own stream cursors.
        // A restored row would re-present an event this installation never
        // received, behind a cursor that never advanced.
        excluded(
            super::BRIDGE_EVENT_RECORDS,
            RowDisposition::ForensicOnly,
            "bridge-event rows are bound to the bridge owner's own cursors; a restored row re-presents an event this installation never received",
        ),
        // #953 (A5). The I7.23 normalized `HostEventEnvelope` item of the same
        // staged event, bound to its record by the transport hash and the
        // recorded disposition. It is a projection of a record this
        // installation never received, so it is the `BRIDGE_EVENT_RECORDS`
        // reason one step downstream: a restored projection re-presents the same
        // un-received event in normalized form, and `require_bridge_event_
        // relation_in` would then hold in a destination where the record it
        // must be related to does not exist.
        excluded(
            super::BRIDGE_EVENT_PROJECTIONS,
            RowDisposition::ForensicOnly,
            "a bridge-event projection is the normalized form of a staged bridge event this installation never received; a restored projection re-presents that event and the record-to-projection relation would hold with no record behind it",
        ),
        // Per-stream cursors are the bridge owner's progress state. Restoring one
        // would silently skip or repeat events.
        excluded(
            super::BRIDGE_EVENT_CURSORS,
            RowDisposition::ForensicOnly,
            "per-stream bridge cursors are the bridge owner's own progress; a restored cursor skips or repeats events without the owner ever moving it",
        ),
        // #953 (A5). Owner-scope continuation for bounded handoff
        // repair/retirement. It is the same category as the per-stream cursor
        // above and one scope wider: the row binds the complete presenter
        // identity and the owner-index schema, so a restored position would
        // resume a repair the bridge owner never started, on a stream the
        // destination has not re-read.
        excluded(
            super::BRIDGE_EVENT_OWNER_MAINTENANCE_CURSORS,
            RowDisposition::ForensicOnly,
            "owner-scope maintenance continuation is the bridge owner's own position in a bounded handoff repair; a restored position resumes maintenance the owner never started, on a stream the destination has not re-read",
        ),
        // Coverage gaps record what the owner did not receive, which is only
        // meaningful next to the cursor that would have closed them.
        excluded(
            super::BRIDGE_EVENT_GAPS,
            RowDisposition::ForensicOnly,
            "coverage gaps record what the bridge owner did not receive and are only meaningful beside the cursor that would close them",
        ),
        // Staged handoffs belong to a handoff the destination never accepted.
        excluded(
            super::BRIDGE_EVENT_HANDOFFS,
            RowDisposition::ForensicOnly,
            "staged bridge handoffs belong to a handoff this installation never accepted, and completing one would cross an authority boundary",
        ),
        // Retained authority lineage, principals and presenter-scope ownership:
        // installation-bound authority, exactly what recovery must not resurrect
        // (I05-27 / ARCH-RES-03).
        excluded(
            super::BRIDGE_STREAM_OWNERS,
            RowDisposition::ForensicOnly,
            "retained bridge authority lineage, principals and presenter-scope ownership are installation-bound authority; recovery must not resurrect them",
        ),
        // A derived enumeration index over the row above.
        excluded(
            super::BRIDGE_STREAM_OWNER_LIST_INDEX,
            RowDisposition::ForensicOnly,
            "a derived enumeration index over BRIDGE_STREAM_OWNERS; it is rebuilt from those rows and holds no owner of its own",
        ),
        // Recovery windows are bound to a presenter and an owner inventory
        // cutoff. Neither is re-establishable in the destination, so a restored
        // window would authorize a search over an inventory that no longer
        // exists.
        excluded(
            super::BRIDGE_EVENT_RECOVERY_WINDOWS,
            RowDisposition::ForensicOnly,
            "recovery windows are bound to a presenter and an owner inventory cutoff; neither is re-establishable in the destination, so a restored window authorizes a search over an inventory that no longer exists",
        ),
        // Per-window cuts are the window's own progress through a stream and gap
        // set: forensic evidence of a past window.
        excluded(
            super::BRIDGE_EVENT_RECOVERY_CUTS,
            RowDisposition::ForensicOnly,
            "per-window stream and gap cuts are forensic evidence of a past window, not state any owner resumes from",
        ),
        // Monotonic per-owner view revisions. Re-establishing them would misreport
        // how much of the owner's view the destination has seen.
        excluded(
            super::BRIDGE_EVENT_RECOVERY_REVISIONS,
            RowDisposition::ForensicOnly,
            "monotonic per-owner view revisions describe how much the owner has seen; a restored value misreports that for the destination",
        ),
        // Compacted replay-commitment boundaries. The owner recomputes them from
        // live evidence, and a restored boundary would retire replay evidence
        // that is still exact.
        excluded(
            super::BRIDGE_EVENT_POSITIONS,
            RowDisposition::ForensicOnly,
            "compacted replay boundaries are recomputed by the owner from live evidence; a restored one would retire evidence that is still exact",
        ),
        // Replay commitments are minted against the committing store's own
        // evidence. A restored commitment names a commitment this installation
        // never made.
        excluded(
            super::BRIDGE_EVENT_REPLAY_COMMITMENTS,
            RowDisposition::ForensicOnly,
            "replay commitments are minted against the committing store's own evidence; a restored one names a commitment this installation never made",
        ),
    ]
}

/// The three #1885 effect-replay tables: retained authority over a past
/// execution, not history a restore may re-establish.
///
/// Each is `ForensicOnly` for the same reason the
/// [`RowFamilyKind::UnknownCommitRecovery`] sibling is: none of them has a
/// durable `import_*_suspended` path in this crate, so `Restorable` would
/// advertise a re-import that does not exist, while every one of them is
/// genuinely evidence about a past execution. They were created on every open
/// since #1885 and carried no disposition at all, which is what made the census
/// refuse every export of a real store.
fn effect_replay_family_exclusions() -> Vec<DispositionedTable> {
    vec![
        // One row per exact already-authorized effect the Kernel may replay,
        // keyed by the lease identity. It is installation-bound ownership of an
        // effect slot: the sibling supervision leases are restorable only
        // because they re-stage as pending, and there is no such re-staging
        // path here, so a restored lease would present the destination as still
        // holding an effect lease it never acquired.
        excluded(
            super::EFFECT_OPERATION_LEASES,
            RowDisposition::ForensicOnly,
            "an effect-operation lease is this installation's ownership of an already-authorized effect; there is no re-staging import path for it, so a restored lease would present the destination as holding an effect lease it never acquired",
        ),
        // The exact immutable execution manifest copied into the Generation
        // Registry, keyed by `{module_id}::{generation}`. The sibling
        // `VERSIONED_ARTIFACTS` family is `NonrestorableHistorical` for the
        // same reason and stronger: a restored manifest is installation-bound
        // generation authority — the artifact/config/protocol hashes, start
        // command, restart class and accepted Catalog revision a restart reads —
        // and recovery must not resurrect it (I05-27 / ARCH-RES-03).
        excluded(
            super::KERNEL_EXECUTION_MANIFESTS,
            RowDisposition::ForensicOnly,
            "an execution manifest is installation-bound generation authority naming the exact artifact, config and protocol hashes, start command, restart class and accepted Catalog revision a restart reads; recovery must not resurrect it",
        ),
        // A denied replay's durable escalation, keyed
        // `{module_id}::{generation}::{operation_id}`. It records that a replay
        // was REFUSED. A restored row would report a refusal this installation
        // never received and suppress the destination's own adjudication of the
        // same operation identity.
        excluded(
            super::EFFECT_REPLAY_RECONCILIATIONS,
            RowDisposition::ForensicOnly,
            "an effect-replay reconciliation row records that a replay was denied; a restored row reports a refusal this installation never received and would suppress the destination's own adjudication of that operation identity",
        ),
    ]
}

/// The two P-06 purge-ledger tables: applied-purge evidence, not state a
/// restore may re-establish.
///
/// `ForensicOnly` for the same reason as the [`RowFamilyKind::UnknownCommitRecovery`]
/// sibling: neither table has a [`RowFamilyKind`] or an `import_*_suspended` path
/// in this crate, so `Restorable` would advertise a quarantined re-import that does
/// not exist, while both are genuinely evidence about a past purge.
///
/// These two carried no disposition of any kind until this entry, and that is
/// what made the census refuse every export of a real store. Neither is
/// materialised by `initialize_ors_tables`: each is created by the first write
/// that touches it, and `bind_purge_ledger_revision` runs inside the production
/// `backup.verify` answer path, so the revision-bindings table appears in the file
/// of any installation that has answered exactly one verification. Check 2
/// compares the census against `list_tables()`, so that table's mere presence was
/// enough to refuse `export_backup_snapshot`, `export_backup_page` and
/// `import_backup_page_quarantined` on a real production store. Being created on
/// first write is also why the omission stayed invisible: a store that never
/// verified an archive has neither table, so the census and the file agreed by
/// accident.
fn purge_ledger_exclusions() -> Vec<DispositionedTable> {
    vec![
        // One row per applied purge, carrying the accepted ledger entry and the
        // ledger-wide revision the owner allocated when it applied that purge.
        // The revision is the owner's own applied sequence — never a
        // caller-proposed value and never a count recomputed over a reader's
        // rows — so a restored ledger would present the destination with a purge
        // progression it never performed, and restoring the entry side would
        // reintroduce as still-applied a scope this installation never erased.
        // A13.7 requires a restore to verify purge closure against the CURRENT
        // owner, and only the owner that applied the purges may issue that
        // revision, so an archived copy is evidence of a past purge and never a
        // substitute for the live one.
        excluded(
            super::PURGE_LEDGER,
            RowDisposition::ForensicOnly,
            "an applied-purge record carries the owner-allocated ledger revision and the accepted purge scope; A13.7 requires purge closure to be verified against the current owner, so an archived ledger is evidence of a past purge and a restored one would reintroduce a scope this installation never erased",
        ),
        // The owner-observed purge revision each `backup.verify` answer was
        // staged against, keyed by that operation's own record key and written in
        // the same transaction that read the counter, so it is the revision the
        // owner held at that instant. It is historical evidence by construction:
        // replaying after a later purge must answer with the revision observed
        // when the answer was produced rather than re-deriving one, and the
        // current owner-issued revision is `purge_ledger_revision()`, a different
        // fact. A restored binding would let a replay assert that a purge state
        // this installation never observed was the one in force when it answered.
        excluded(
            super::PURGE_LEDGER_REVISION_BINDINGS,
            RowDisposition::ForensicOnly,
            "a verification-to-purge-revision binding records the revision the owner held when it staged one backup.verify answer; it is historical evidence beside the answer, and the current owner-issued revision is re-read from the live ledger rather than restored from an archive",
        ),
    ]
}

/// Refuses a backup whose row-family denominator does not cover the store the
/// snapshot is being taken from (issue #953, A5).
///
/// This is the production reader [`row_family_denominator`] did not have. The
/// disposition list used to be a decorative constant compared with nothing, so a
/// table that no entry named was invisible in both directions: it was not
/// exported, not counted, and not refused. It is now compared with the tables
/// redb reports for the file being read, under the caller's own transaction, so
/// the census describes the same moment as the pages.
///
/// Five checks, all fail-closed, all [`OrsError::MigrationRequired`] because a
/// store whose tables outrun the compiled contract is exactly a schema the
/// compiled binary was not built for:
///
/// 1. No table name appears twice in the census — a doubled entry would make one
///    physical table look dispositioned twice and hide a genuine gap behind the
///    duplicate.
/// 2. Every table redb reports for this file is dispositioned. This is the
///    issue's sentence verbatim: "No table disappears because its name was
///    absent from an old checklist." A table the file has and the contract does
///    not name is refused, not exported around.
/// 3. Every census entry that claims a family is dispositioned by
///    [`row_family_denominator`], so the physical census and the family policy
///    cannot disagree about a family's disposition.
/// 4. Every family in [`row_family_denominator`] is bound to a table by the
///    census, so a new declared family cannot be added without also naming the
///    table that backs it. There is deliberately no "table-less family" escape
///    any more: the list that used to excuse the three restore-journal families
///    did so on the stated premise that they "are not a redb table family at
///    all", which was false — `store/restore_journal.rs` declares three
///    `TableDefinition::new("ors_restore_journal_...")` tables and
///    `initialize_restore_journal_schema` creates them, so `list_tables` reports
///    them. Because the list fed check 4 (family-policy coverage) and not check 2
///    (live-name coverage), those three LIVE names went uncensored while their
///    families looked fully covered; the false statement is exactly what let them
///    through. They are bound to their own tables in
///    [`restore_journal_family_tables`] (issue #953, A5).
/// 5. No excluded table claims [`RowDisposition::Restorable`], which would
///    advertise a quarantined import path for a table that has no family and
///    therefore no import path.
///
/// Cost is one `list_tables` plus a 72-entry linear scan, both bounded and both
/// independent of store size: it is a schema census, not a data scan. It runs
/// once per export entrypoint and once per quarantined import, never per page.
///
/// What this function does NOT establish is that the census covers every table
/// the crate declares. Check 2 is bounded by what the FILE contains, so a
/// declared-but-uncensused table that no write has materialised yet is not seen
/// here at all; see the module header and [`dispositioned_tables`] for why that
/// gap is real and what would close it.
fn check_row_family_census(read: &ReadTransaction) -> Result<(), OrsError> {
    let census = dispositioned_tables();
    let mut census_names: Vec<&str> = Vec::with_capacity(census.len());
    for entry in &census {
        let name = entry.table.name();
        if census_names.contains(&name) {
            return Err(OrsError::MigrationRequired {
                reason: format!("row family census declares table {name:?} more than once"),
            });
        }
        if let TableDisposition::Excluded { disposition, .. } = entry.disposition
            && disposition == RowDisposition::Restorable
        {
            return Err(OrsError::MigrationRequired {
                reason: format!(
                    "row family census excludes table {name:?} as Restorable; an excluded table has no quarantined import path"
                ),
            });
        }
        census_names.push(name);
    }
    // Check 2. `list_tables` is the file's own answer, not this crate's
    // compilation of it, so a table written by another build of the ORS is
    // caught here rather than silently skipped.
    let live = read.list_tables().map_err(storage)?;
    for handle in live {
        let name = handle.name();
        if !census_names.contains(&name) {
            return Err(OrsError::MigrationRequired {
                reason: format!(
                    "ORS table {name:?} is present in this store and has no backup row family disposition; a table must not disappear because its name is absent from an old checklist"
                ),
            });
        }
    }
    // Checks 3 and 4, against the family policy this module delegates to.
    let denominator = row_family_denominator();
    for entry in &census {
        let TableDisposition::Family(kind) = entry.disposition else {
            continue;
        };
        if !denominator
            .iter()
            .any(|disposition| disposition.kind == kind)
        {
            return Err(OrsError::MigrationRequired {
                reason: format!(
                    "table {:?} is bound to row family {kind:?}, which the backup row family denominator does not disposition",
                    entry.table.name()
                ),
            });
        }
    }
    for disposition in &denominator {
        let bound = census
            .iter()
            .any(|entry| entry.disposition == TableDisposition::Family(disposition.kind));
        if !bound {
            return Err(OrsError::MigrationRequired {
                reason: format!(
                    "row family {:?} is dispositioned as a backup row family but no ORS table is bound to it",
                    disposition.kind
                ),
            });
        }
    }
    Ok(())
}

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

/// Opens the typed operational-history cursor for one live backup walk
/// (issue #2967).
///
/// The ONE producer of an [`OrsOperationalCursor`], and the exact operational twin
/// of [`open_backup_family`]: it reads the owner-observed ordering high-water and
/// the streamed content root, row count and byte denominator of the declared window
/// under ONE read transaction, so the frozen identity can never mix two moments.
/// Because it is the only producer, a caller cannot mint an operational window and
/// therefore cannot choose where the walk starts or what it is measured against;
/// it can only choose the walk's declared LOWER bound, which becomes part of the
/// frozen identity and therefore part of the denominator the pages are counted
/// against.
///
/// `source` is the caller's own source identity and is bound into the identity, so a
/// cursor opened for one installation cannot be replayed against another.
pub(super) fn open_backup_operational_history(
    database: &Database,
    source: &crate::backup_snapshot::OrsBackupSourceIdentity,
    lower_order_bound: u64,
) -> Result<OrsOperationalCursor, OrsError> {
    let read = database.begin_read().map_err(storage)?;
    let identity = operational_history_identity(&read, source, lower_order_bound)?;
    drop(read);
    OrsOperationalCursor::start(identity)
}

/// Fixed width of the zero-padded `operation_order` prefix every operational-history
/// durable key begins with (issue #2967).
///
/// `persist_operational_record` builds the key as `format!("{:020}:{key}",
/// record.operation_order)`, and a `u64` never renders wider than twenty decimal
/// digits, so the prefix is a FIXED width and the durable-key order of
/// `OPERATIONAL_HISTORY` is its `operation_order` order. That is the ordered read
/// path this issue reuses instead of adding a table: seeking to
/// `"{order:020}:"` is an exact seek, not a scan, and no second index, no second
/// history database and no durable schema change is introduced to obtain it.
///
/// The consequence is a PREMISE, and [`operational_history_order`] is where it is
/// checked rather than assumed: every row the walk visits must carry a key of this
/// shape and a decoded `operation_order` equal to the order its key names, and a
/// row that does not is refused with its own identity. A silently reordered index
/// would be exactly the "named but not owned" failure this issue forbids.
const OPERATIONAL_ORDER_KEY_WIDTH: usize = 20;

/// The `operation_order` an operational-history durable key names, or a refusal
/// naming that exact key.
///
/// The one place the ordered read path's premise is enforced. Every caller that
/// relies on durable-key order being `operation_order` order — the window root, the
/// cursor-boundary proof and the page walk — goes through here, so a durable key
/// outside the documented `{operation_order:020}:{record_key}` form can never be
/// skipped into or out of the denominator by a range seek that assumed otherwise.
fn operational_history_order(record_key: &str) -> Result<u64, OrsError> {
    let bytes = record_key.as_bytes();
    let malformed = || {
        family_row_refused(
            "operational_history",
            record_key,
            "durable key is not the ordered {operation_order:020}:{record_key} form the operational walk is ordered by",
        )
    };
    if bytes.len() <= OPERATIONAL_ORDER_KEY_WIDTH + 1 || bytes[OPERATIONAL_ORDER_KEY_WIDTH] != b':'
    {
        return Err(malformed());
    }
    std::str::from_utf8(&bytes[..OPERATIONAL_ORDER_KEY_WIDTH])
        .ok()
        .and_then(|order| order.parse::<u64>().ok())
        .ok_or_else(malformed)
}

/// The first durable key an operational walk above `lower_order_bound` can have, or
/// `None` when no operation order can exceed that bound.
///
/// `{order + 1:020}:` is an INCLUSIVE lower seek bound that skips every key of
/// order `lower_order_bound` exactly: the constant is a strict prefix of those keys
/// and therefore sorts before them, while every key of a larger order begins with a
/// greater twenty-digit number and therefore sorts after it. A start cursor carries
/// no durable key of its own, so this is how the walk's first seek is expressed
/// without scanning the rows below the declared window.
fn operational_history_lower_key(lower_order_bound: u64) -> Option<String> {
    lower_order_bound
        .checked_add(1)
        .map(|next| format!("{next:020}:"))
}

/// One bounded read of the operational-history window: the streamed content root
/// plus the observed size, with nothing retained.
struct OperationalWindow {
    /// Chained content root over the window's durable keys and encoded rows.
    root_digest: String,
    /// Eligible rows observed in the window.
    row_count: u64,
    /// Summed encoded row bytes observed in the window.
    total_bytes: u64,
}

/// Computes the operational window's content root in one ordered streaming pass.
///
/// The operational twin of [`family_root`], and the same cost characteristic: each
/// row is folded into an [`OrsFamilyRowChain`] link and then dropped, so the pass
/// costs constant memory no matter how much history the window contains. Because the
/// table is walked in durable-key order and that order IS the `operation_order`
/// order (see [`operational_history_order`]), the pass needs no collection and no
/// sort — which is what replaces the full materialize-and-sort scan that this issue
/// removes from every page.
///
/// Two bounds, both of them the contract's rather than the caller's: the walk starts
/// strictly above `lower_order_bound` and stops at the first row above
/// `high_water_order`, so the root, the row count and the byte denominator describe
/// exactly the frozen window and a row above the high-water is never counted here
/// either. Bounded by [`IMPORT_SCAN_ROW_CAP`] and fails closed rather than
/// certifying a truncated window as a complete denominator.
fn operational_window_root(
    table: &redb::ReadOnlyTable<&str, &str>,
    lower_order_bound: u64,
    high_water_order: u64,
) -> Result<OperationalWindow, OrsError> {
    let mut chain = OrsFamilyRowChain::start(RowFamilyKind::OperationalHistory);
    let mut window = OperationalWindow {
        root_digest: chain.link().to_owned(),
        row_count: 0,
        total_bytes: 0,
    };
    // A lower bound no order can exceed makes the declared window empty by
    // construction; the chain seed is the root of an empty window, which is what
    // makes "no rows" a measured value rather than an absent one.
    let Some(start) = operational_history_lower_key(lower_order_bound) else {
        return Ok(window);
    };
    let rows = table
        .range::<&str>((Bound::Included(start.as_str()), Bound::Unbounded))
        .map_err(storage)?;
    for row in rows {
        if window.row_count >= IMPORT_SCAN_ROW_CAP {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let (key, value) = row.map_err(storage)?;
        if operational_history_order(key.value())? > high_water_order {
            break;
        }
        let encoded = value.value().as_bytes();
        window.row_count = window
            .row_count
            .checked_add(1)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        window.total_bytes = window
            .total_bytes
            .checked_add(encoded.len() as u64)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        chain.advance_row(key.value(), &crate::model::sha256_hex(encoded));
    }
    chain.link().clone_into(&mut window.root_digest);
    Ok(window)
}

/// Reads the owner-observed high-water and the streamed window root under one read
/// transaction, so the frozen operational identity can never mix two moments.
fn operational_history_identity(
    read: &ReadTransaction,
    source: &crate::backup_snapshot::OrsBackupSourceIdentity,
    lower_order_bound: u64,
) -> Result<OrsOperationalSnapshotIdentity, OrsError> {
    let observation = capture_store_fence(read)?;
    let window = {
        let table = read
            .open_table(super::OPERATIONAL_HISTORY)
            .map_err(storage)?;
        let window =
            operational_window_root(&table, lower_order_bound, observation.high_water_order)?;
        drop(table);
        window
    };
    OrsOperationalSnapshotIdentity::new(
        source,
        observation.high_water_order,
        lower_order_bound,
        window.root_digest,
        window.row_count,
        window.total_bytes,
    )
}

/// The movement refusal for an operational window that moved after a backup froze
/// it (issue #2967).
///
/// NO new [`OrsError`] variant is introduced, for the reason
/// [`family_moved_error`] records and with the same consequence: `OrsError` is
/// matched EXHAUSTIVELY outside this crate, so a new variant would not compile
/// outside it, and the two files owning those mappings are not this change's to
/// edit. The operational axis therefore reuses
/// [`OrsError::OrderingHeadMismatch`] — the crate's existing typed refusal for a
/// canonical ordering head that does not match durable ORS state, and precisely the
/// fact that failed here: the ordering high-water the walk was frozen at no longer
/// describes the store.
///
/// The operator action is the same one the versioned-artifact family already uses
/// and the same one the issue names: restart the operational walk from a freshly
/// opened window. Pages already emitted are never re-read under the new window and
/// never concatenated with pages read under it, so a moved operational history can
/// never be stitched into one archive. Be precise about what the variant does NOT
/// carry: unlike the process-stream recovery family's rich variant it does not
/// carry the observed root, because a unit variant has nowhere to put one. The
/// evidence is still available to the operator, who re-opens the window and reads
/// the new high-water that caused the refusal.
fn operational_moved_error() -> OrsError {
    OrsError::OrderingHeadMismatch
}

/// The refusal for a presented operational cursor that does not name the
/// owner-emitted operational prefix (issue #2967).
///
/// The operational twin of [`family_cursor_mismatch_error`], and the same reuse
/// decision: no new variant, so the crate's existing typed refusal for a
/// caller-presented value that does not name durable state,
/// [`OrsError::InvalidField`], with the operational axis's own field name so no two
/// refusals read alike. A fabricated boundary, an edited offset, a changed prefix
/// commitment and a cursor replayed under another source or high-water all land
/// here, and all of them land BEFORE a suffix row is read.
fn operational_cursor_mismatch_error() -> OrsError {
    OrsError::InvalidField {
        field: "backup_operational_cursor",
        reason: "cursor must name the owner-emitted operational prefix under the frozen window",
    }
}

/// Refuses an operational page whose window moved after the backup froze it
/// (issue #2967).
///
/// The operational twin of [`check_family_revision_frozen`], and it re-derives
/// rather than reading a counter, because the operational axis has no dedicated
/// durable revision: what it freezes instead is the ordering high-water together
/// with the streamed content root of the window under it, and BOTH are re-measured
/// here. The fast path is therefore a comparison of the frozen high-water against
/// the one this read transaction observed — the store's own `NEXT_GLOBAL_ORDER`, the
/// same owner-established fact [`check_export_fence`] already compares — and the
/// streamed root is re-measured only when that comparison has already failed, or
/// when the high-water agrees but the content does not.
///
/// The second branch is why this is stronger than a high-water comparison alone.
/// Operational history is append-only in its single write path — every insert
/// allocates a new order — so a high-water that has not moved is expected to imply
/// an unchanged window, and measuring the root anyway turns that expectation into a
/// checked precondition at the cost of one streaming pass per page, in constant
/// memory. That is strictly cheaper than the full materialize-and-sort scan this
/// issue removes from every page, so paying it is not a regression.
fn check_operational_identity_frozen(
    read: &ReadTransaction,
    identity: &OrsOperationalSnapshotIdentity,
) -> Result<(), OrsError> {
    let observation = capture_store_fence(read)?;
    if observation.high_water_order != identity.high_water_order {
        return Err(operational_moved_error());
    }
    let table = read
        .open_table(super::OPERATIONAL_HISTORY)
        .map_err(storage)?;
    let observed = operational_window_root(
        &table,
        identity.lower_order_bound,
        identity.high_water_order,
    )?;
    drop(table);
    if observed.root_digest != identity.operational_root_digest
        || observed.row_count != identity.operational_row_count
        || observed.total_bytes != identity.operational_total_bytes
    {
        return Err(operational_moved_error());
    }
    Ok(())
}

/// Proves that a presented operational cursor names exactly the operational prefix
/// the owner already emitted (issue #2967).
///
/// The operational twin of [`check_family_cursor_boundary`], with the same shape
/// and the same reason for it: the boundary is not authenticated by shape, because
/// every field of a presented cursor is observable. The emitted-prefix chain is
/// re-derived from live durable keys and the walk stops the instant the presented
/// row count is reached, so the cost is the prefix the owner already exported and
/// the memory is constant. No row VALUE is decoded on this path, so a refusal costs
/// no more than the keys it read.
///
/// The chain is seeded for the operational family, so it cannot be satisfied by a
/// family cursor's chain, and it is walked from the frozen window's lower bound so
/// it can only ever describe rows inside the frozen window. A cursor whose chain,
/// offset, last key or last order disagrees with durable state is the operational
/// boundary refusal ([`operational_cursor_mismatch_error`]): a caller cannot present
/// a later boundary under an earlier offset and drop the rows in between out of the
/// denominator, which is the exact defect `after_order + page_entries * page_index`
/// allowed.
fn check_operational_cursor_boundary(
    table: &redb::ReadOnlyTable<&str, &str>,
    cursor: &OrsOperationalCursor,
) -> Result<(), OrsError> {
    let identity = &cursor.identity;
    let mut chain = OrsFamilyRowChain::start(RowFamilyKind::OperationalHistory);
    let mut emitted: u64 = 0;
    let mut durable_order = identity.lower_order_bound;
    let mut durable_key = String::new();
    if cursor.emitted_rows > 0 {
        let Some(start) = operational_history_lower_key(identity.lower_order_bound) else {
            return Err(operational_cursor_mismatch_error());
        };
        let rows = table
            .range::<&str>((Bound::Included(start.as_str()), Bound::Unbounded))
            .map_err(storage)?;
        for row in rows {
            let (key, _) = row.map_err(storage)?;
            if operational_history_order(key.value())? > identity.high_water_order {
                break;
            }
            chain.advance_key(key.value());
            key.value().clone_into(&mut durable_key);
            durable_order = operational_history_order(key.value())?;
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
        || durable_order != cursor.after_order
    {
        return Err(operational_cursor_mismatch_error());
    }
    Ok(())
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
    /// ORS-owned installed identity and monotone generation observed through
    /// the same transaction as the exported rows.
    store_identity: super::StoreObjectIdentityRecord,
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
    let store_identity = super::read_store_object_identity(&meta)?;
    drop(meta);
    let family_revision = super::RedbRecoveryStore::process_stream_recovery_family_revision(read)?;
    Ok(StoreFenceObservation {
        high_water_order,
        store_identity,
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
/// The durable ORS identity row is the comparison source for
/// `installation_id` and `ors_generation`. Unbound legacy opens cannot produce
/// an installation-bound backup snapshot, and a stale generation or a request
/// naming another installation fails closed.
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
    if observation.store_identity.installation_id.as_deref()
        != Some(request.source.installation_id.as_str())
        || observation.store_identity.ors_generation != request.source.ors_generation
    {
        return Err(OrsError::IntegrityProblem {
            record_type: "ors_store_object_identity",
            reason: "backup source identity does not match the durable ORS object identity"
                .to_owned(),
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
/// - the axis is left `Open` whenever a row is still behind the boundary, and
///   `Exhausted` only when the enumeration reached the end of the FROZEN family
///   denominator; the two are cross-checked so the measuring pass and the walking
///   pass cannot silently disagree.
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
            // A row that reached this point was decoded and re-encoded from the
            // source bytes, so its payload WAS obtained. The state is stated
            // rather than defaulted because the enum has no "unknown" arm: a row
            // this path cannot read is refused by `family_row_refused` above and
            // never becomes an entry, so `Unavailable` is unreachable from the
            // store and is an admission-side refusal only (issue #953, A6).
            payload_state: RowPayloadState::Obtained,
        });
    }
    // ONE assembly of the boundary this page's family walk ended at. Built
    // unconditionally, because an exhausted family HAS a real terminal frontier
    // and the pages that follow exist only to carry the other axes and must still
    // be read under it (issue #953). When the page emitted nothing the chain is
    // resumed from the in-force cursor's own commitment and every field is that
    // cursor's, so an exhausted empty page re-reads to the same empty segment
    // rather than a second copy of the walk.
    let frontier = OrsFamilyCursor {
        version: cursor.version,
        identity: cursor.identity.clone(),
        after_key,
        emitted_rows,
        emitted_bytes,
        emitted_prefix_digest: chain.link().to_owned(),
    };
    if !family_open && frontier.emitted_rows != cursor.identity.family_row_count {
        // The family was re-measured by `check_family_revision_frozen` and its
        // emitted prefix re-proved by `check_family_cursor_boundary` on this same
        // read transaction, so the two passes cannot legitimately disagree. If
        // they do, the walk would be about to declare itself exhausted against a
        // denominator it never reached, which is the "Complete from row presence"
        // defect in its exact form, so it is refused by name instead.
        return Err(family_row_refused(
            record_type,
            &frontier.after_key,
            &format!(
                "the family walk stopped at {} emitted row(s) against a frozen denominator of {}",
                frontier.emitted_rows, cursor.identity.family_row_count
            ),
        ));
    }
    // Only an owner-established terminal frontier may close the axis; a page or
    // byte limit that merely spent this page's admission stays `Open` and hands
    // on the exact frontier to resume from.
    let state = if family_open {
        OrsAxisState::Open(frontier)
    } else {
        OrsAxisState::Exhausted(frontier)
    };
    let continuation = OrsFamilyContinuation {
        cursor: cursor.clone(),
        state,
    };
    Ok((entries, continuation, page_bytes))
}

/// One page's bounded operational-history segment (issue #2967).
struct OperationalSegment {
    /// Entries emitted from the operational walk on this page.
    entries: Vec<OrsBackupEntry>,
    /// The page's in-force cursor and the axis's exact outgoing state.
    ///
    /// The outgoing boundary is reached through
    /// [`OrsOperationalContinuation::frontier`] on BOTH states, so there is no
    /// second, parallel cursor to keep in step with it: the durable key and the
    /// chained prefix digest are over the key the owner walked under, which a
    /// page's `OrsBackupEntry` does not carry, and the walk is the only place that
    /// has both, so the state carries them (issue #2967, W6/A2; #953).
    continuation: OrsOperationalContinuation,
    /// Encoded bytes this segment charged to the page.
    page_bytes: u64,
}

/// The walk's running state as this page advanced it (issue #2967).
///
/// A named state rather than eight locals, so the boundary the next cursor names
/// is assembled in ONE place instead of being spread across a loop and read back
/// from a variable the reader has to find. Every field is either the cursor's own
/// starting value or a value derived from a row the loop actually emitted.
struct OperationalProgress {
    /// Chained digest of the emitted durable-key prefix, resumed from the cursor.
    chain: OrsFamilyRowChain,
    /// Entries emitted so far on this page.
    entries: Vec<OrsBackupEntry>,
    /// Encoded bytes charged to this page so far.
    page_bytes: u64,
    /// Rows emitted for the whole walk so far.
    emitted_rows: u64,
    /// Encoded bytes emitted for the whole walk so far.
    emitted_bytes: u64,
    /// Order of the walk's last emitted row, which is the next cursor's bound.
    after_order: u64,
    /// Durable key of the walk's last emitted row.
    after_key: String,
    /// Whether an eligible row is still behind this page.
    open: bool,
}
impl OperationalProgress {
    /// The state a walk begins in: exactly what the in-force cursor says it has
    /// already emitted, with the chain resumed from its own commitment.
    fn resumed(cursor: &OrsOperationalCursor) -> Self {
        Self {
            chain: OrsFamilyRowChain::resume(cursor.emitted_prefix_digest.clone()),
            entries: Vec::new(),
            page_bytes: 0,
            emitted_rows: cursor.emitted_rows,
            emitted_bytes: cursor.emitted_bytes,
            after_order: cursor.after_order,
            after_key: cursor.after_key.clone(),
            open: false,
        }
    }
}

/// The durable-key bound this page's walk starts from, and whether it is inclusive.
///
/// A start cursor carries no durable key, so the first seek is the frozen window's
/// declared lower bound; every later page seeks strictly after the exact durable key
/// of the row the previous page ACTUALLY emitted, which is what makes page N+1 start
/// after page N's real tail instead of at a count-stride guess. `None` means the
/// declared window is empty by construction, which is a truthful exhausted page
/// rather than a failure.
fn operational_seek(cursor: &OrsOperationalCursor) -> Option<(String, bool)> {
    if cursor.emitted_rows > 0 {
        return Some((cursor.after_key.clone(), false));
    }
    operational_history_lower_key(cursor.identity.lower_order_bound).map(|key| (key, true))
}

/// Decodes one candidate operational row and refuses it unless it names the order
/// its durable key named.
///
/// The ordered read path's premise, checked rather than assumed: the range seek
/// above selected by `operation_order` only because the durable key's padded prefix
/// IS that order, and a row whose own field disagrees would silently be emitted at
/// the wrong position in the walk. Re-encoding here is also what produces the
/// payload digest the entry carries, so the decoded bytes and the hashed bytes are
/// the same bytes by construction.
fn operational_row(
    record_key: &str,
    encoded_value: &str,
    order: u64,
) -> Result<(DurableOperationalRecord, String), OrsError> {
    let record: DurableOperationalRecord = decode_named(encoded_value, "operational_history")?;
    if record.operation_order != order {
        return Err(family_row_refused(
            "operational_history",
            record_key,
            &format!(
                "row carries operation order {} but its durable key names {order}",
                record.operation_order
            ),
        ));
    }
    let encoded = encode(&record)?;
    Ok((record, encoded))
}

/// Walks this page's segment of the frozen operational window in durable-key order.
///
/// The operational twin of `family_segment`'s loop, and it obeys the same rules:
/// the row and byte budgets are charged per row as the loop goes, so the path never
/// holds more than one page of rows plus the one row it declined to emit; there is
/// no "read the table, then slice" step and no sort; and every emitted row satisfies
/// `previous_cursor < operation_order <= frozen_high_water`. A row at or below the
/// previous cursor is a REFUSAL rather than a skip, because it would mean the
/// ordered read path's premise is false, and a row above the high-water ENDS the walk
/// because it belongs to a successor snapshot - which is what makes the A5 bound a
/// property of the read boundary rather than of the caller's fence.
fn operational_walk(
    table: &redb::ReadOnlyTable<&str, &str>,
    cursor: &OrsOperationalCursor,
    mut progress: OperationalProgress,
    row_budget: usize,
    byte_budget: u64,
    max_bytes: u64,
) -> Result<OperationalProgress, OrsError> {
    let identity = &cursor.identity;
    let Some((seek_key, inclusive)) = operational_seek(cursor) else {
        return Ok(progress);
    };
    let lower = if inclusive {
        Bound::Included(seek_key.as_str())
    } else {
        Bound::Excluded(seek_key.as_str())
    };
    let rows = table
        .range::<&str>((lower, Bound::Unbounded))
        .map_err(storage)?;
    let mut previous_order = cursor.after_order;
    for row in rows {
        let (key, value) = row.map_err(storage)?;
        let record_key = key.value().to_owned();
        let order = operational_history_order(&record_key)?;
        if order > identity.high_water_order {
            break;
        }
        if order <= previous_order {
            return Err(family_row_refused(
                "operational_history",
                &record_key,
                "operational durable keys must name strictly increasing operation orders",
            ));
        }
        // The budget is checked after the row is decoded and after the window is
        // applied, so "open" can only ever be set for a row that really is this
        // snapshot's member. The family path checks its budget first, which is
        // harmless there because a family has no upper bound to stop at.
        let (record, encoded) = operational_row(&record_key, value.value(), order)?;
        if progress.entries.len() >= row_budget {
            progress.open = true;
            break;
        }
        let encoded_len = u64::try_from(encoded.len()).map_err(|_| OrsError::PayloadTooLarge)?;
        if encoded_len > max_bytes {
            return Err(family_row_refused(
                "operational_history",
                &record_key,
                &format!(
                    "row encodes to {encoded_len} bytes, above the declared backup byte budget {max_bytes}"
                ),
            ));
        }
        let charged = progress
            .page_bytes
            .checked_add(encoded_len)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        if charged > byte_budget {
            progress.open = true;
            break;
        }
        progress.page_bytes = charged;
        progress.emitted_rows = progress
            .emitted_rows
            .checked_add(1)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        progress.emitted_bytes = progress
            .emitted_bytes
            .checked_add(encoded_len)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        progress.after_order = order;
        progress.after_key.clone_from(&record_key);
        previous_order = order;
        progress.chain.advance_key(&record_key);
        progress.entries.push(OrsBackupEntry {
            record_id: record.input.record_id.as_str().to_owned(),
            family: RowFamilyKind::OperationalHistory,
            order,
            payload_digest: crate::model::sha256_hex(encoded.as_bytes()),
            effect_class: effect_class_for_export(record.phase),
            // A row that reached this point was decoded and re-encoded from the
            // source bytes, so its payload was obtained. A row this path cannot
            // read is refused above and never becomes an entry, so `Unavailable` is
            // unreachable from the store and is an admission-side refusal only
            // (issue #953, A6).
            payload_state: RowPayloadState::Obtained,
        });
    }
    Ok(progress)
}

/// Builds one bounded page segment for the operational-history walk.
///
/// The operational twin of [`family_segment`], in the same order:
///
/// - the boundary is proved against durable state BEFORE a single row is decoded
///   ([`check_operational_cursor_boundary`]), so a fabricated or edited cursor is
///   refused before a suffix read;
/// - a row that does not fit the page's remaining budget is not emitted and not
///   dropped: it stays behind `next`, so the following page carries it and the walk
///   cannot be silently truncated;
/// - the axis is closed only when the walk reached the end of the FROZEN
///   denominator, never because this scan happened to find nothing, and the two are
///   cross-checked here so the measuring pass and the walking pass cannot silently
///   disagree.
fn operational_segment(
    table: &redb::ReadOnlyTable<&str, &str>,
    cursor: &OrsOperationalCursor,
    row_budget: usize,
    byte_budget: u64,
    max_bytes: u64,
) -> Result<OperationalSegment, OrsError> {
    check_operational_cursor_boundary(table, cursor)?;
    let progress = operational_walk(
        table,
        cursor,
        OperationalProgress::resumed(cursor),
        row_budget,
        byte_budget,
        max_bytes,
    )?;
    if !progress.open && progress.emitted_rows != cursor.identity.operational_row_count {
        // The window was re-measured by `check_operational_identity_frozen` on this
        // same read transaction, so the two passes cannot legitimately disagree. If
        // they do, the walk would be about to be declared exhausted against a
        // denominator it never reached, which is the "Complete from row presence"
        // defect in its exact form, so it is refused by name instead.
        return Err(family_row_refused(
            "operational_history",
            &progress.after_key,
            &format!(
                "the walk stopped at {} emitted row(s) against a frozen denominator of {}",
                progress.emitted_rows, cursor.identity.operational_row_count
            ),
        ));
    }
    // ONE assembly of the boundary this page's walk ended at, read two ways. Built
    // unconditionally, because an exhausted walk still HAS a real boundary and the
    // next page has to be read under it; the state below is then only the question
    // of whether that boundary is still owed. When the page emitted nothing at all
    // the chain is resumed from the in-force cursor's own commitment and every field
    // is that cursor's, so an exhausted empty page re-reads to the same empty segment
    // rather than a second copy of the walk.
    let frontier = OrsOperationalCursor {
        version: cursor.version,
        identity: cursor.identity.clone(),
        after_order: progress.after_order,
        after_key: progress.after_key,
        emitted_rows: progress.emitted_rows,
        emitted_bytes: progress.emitted_bytes,
        emitted_prefix_digest: progress.chain.link().to_owned(),
    };
    let state = if progress.open {
        OrsAxisState::Open(frontier)
    } else {
        OrsAxisState::Exhausted(frontier)
    };
    Ok(OperationalSegment {
        entries: progress.entries,
        continuation: OrsOperationalContinuation {
            cursor: cursor.clone(),
            state,
        },
        page_bytes: progress.page_bytes,
    })
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

/// Deterministic digest over durable operational-history state under an observed
/// high-water (issue #2967).
///
/// The witness's operational half, and it is now the SAME measured value the walk
/// is frozen against rather than a separate digest computed a different way. It
/// used to collect every decoded `(order, record-digest)` pair into a vector and
/// sort it, so the witness cost memory proportional to the retained history and
/// bound nothing; it is now one ordered streaming pass over the table's own
/// durable-key order, cut at the high-water this read transaction observed, which
/// is O(1) in memory and O(walk) in time.
///
/// SCOPE CHANGE, stated so it is not read as narrower than it is. The old digest
/// bound EVERY operational row regardless of order; this one bounds the rows at or
/// below the observed high-water, which is what the backup walk can see, and
/// `composite_state_digest` now folds the high-water itself into the material so a
/// commit that consumes an order without writing a history row still moves the
/// witness. The composition of the two is therefore at least as sensitive as the old
/// digest, and it no longer has to sort the table to say so.
fn operational_state_digest(
    read: &ReadTransaction,
    high_water_order: u64,
) -> Result<String, OrsError> {
    let table = read
        .open_table(super::OPERATIONAL_HISTORY)
        .map_err(storage)?;
    let window = operational_window_root(&table, 0, high_water_order)?;
    drop(table);
    Ok(window.root_digest)
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
/// of retained family rows; the operational-history half is now the same streaming
/// pass the walk itself uses, so every axis of the witness is allocation-free. The
/// families are named in the material string, so the versioned-artifact axis cannot
/// be satisfied by the process-stream axis, and since issue #2967 the operational
/// axis is named together with the high-water it was measured under, so it cannot
/// be satisfied by a family root either.
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
    // The high-water is observed by the SAME transaction that measures the window
    // under it, so the pair describes one moment and a commit that consumed an
    // order without writing a history row still moves the witness.
    let observation = capture_store_fence(read)?;
    let operational = operational_state_digest(read, observation.high_water_order)?;
    let recovery_revision = family_revision(read, RowFamilyKind::ProcessStreamRecovery)?;
    let recovery = family_identity(read, RowFamilyKind::ProcessStreamRecovery)?;
    let artifact_revision = family_revision(read, RowFamilyKind::VersionedArtifacts)?;
    let artifact = family_identity(read, RowFamilyKind::VersionedArtifacts)?;
    let mut material = String::new();
    let _ = write!(
        material,
        "eliot.ors.composite_state.v3|operational_high_water={}|operational_root={operational}|recovery_family_revision={recovery_revision}|recovery_family_root={}|recovery_rows={}|recovery_bytes={}|artifact_family_revision={artifact_revision}|artifact_family_root={}|artifact_rows={}|artifact_bytes={}",
        observation.high_water_order,
        recovery.family_root_digest,
        recovery.family_row_count,
        recovery.family_total_bytes,
        artifact.family_root_digest,
        artifact.family_row_count,
        artifact.family_total_bytes
    );
    Ok(crate::model::sha256_hex(material.as_bytes()))
}

/// Resolves the operational cursor this page is read under (issue #2967).
///
/// Two cases and one rule. A request that carries no operational cursor is the
/// FIRST page of the walk its `after_order` declares, and the store mints the
/// cursor itself from the high-water, content root and denominator it observes
/// under the capture transaction — the same "the owner is the only producer"
/// property `open_backup_family` has. A request that DOES carry one has that cursor
/// re-proved against durable state before it is applied: the frozen identity is
/// re-measured, and the cursor must belong to this request's own source and fence.
///
/// The four refusals here are the A6 cases and each is a different fact:
///
/// - a cursor whose frozen window no longer describes the store is the movement
///   disposition ([`operational_moved_error`]), because the store advanced;
/// - a cursor frozen for a different source, or at a different high-water than the
///   fence this request declares, is refused here, BEFORE any row is read, so an
///   old window cannot be reinterpreted against a newer fence;
/// - a start cursor whose frozen lower bound is not this request's `after_order` is
///   refused, so a walk cannot be restarted at a different window under a cursor
///   that looks well formed.
fn resolve_operational_cursor(
    read: &ReadTransaction,
    request: &OrsBackupRequest,
) -> Result<OrsOperationalCursor, OrsError> {
    let Some(cursor) = &request.operational_cursor else {
        return operational_history_identity(read, &request.source, request.after_order)
            .and_then(OrsOperationalCursor::start);
    };
    check_operational_identity_frozen(read, &cursor.identity)?;
    if cursor.identity.source_installation_id != request.source.installation_id
        || cursor.identity.ors_generation != request.source.ors_generation
    {
        return Err(OrsError::InvalidField {
            field: "backup_operational_cursor",
            reason: "the operational cursor was frozen for a different source installation or ORS generation",
        });
    }
    if cursor.identity.high_water_order != request.fence.high_water_order {
        return Err(operational_moved_error());
    }
    // The declared walk start is re-checked here and not only in
    // `OrsBackupRequest::with_operational_cursor`, because that setter is a
    // convenience, not the only way the field can be populated: the store is the
    // boundary an unvalidated request crosses and must judge it itself.
    if cursor.identity.lower_order_bound != request.after_order {
        return Err(OrsError::InvalidField {
            field: "backup_operational_cursor",
            reason: "the operational cursor is frozen for a different walk start than this request declares",
        });
    }
    Ok(cursor.clone())
}

/// Reads this page's operational-history segment (issue #2967).
///
/// The operational counterpart of [`family_page`], and it runs FIRST so the
/// remaining row and byte admission every family segment is charged from is what
/// the walk actually spent. It is given this page's WHOLE admission, because nothing
/// has been charged yet on this page; the walk does not get a private allowance, so
/// paging it can never raise the per-page ceiling, and it is charged first precisely
/// so it can never take more than the page's ceiling either.
///
/// An axis that a previous page already closed is SKIPPED (issue #953): its
/// verified terminal frontier is re-proved against durable state and carried
/// forward unchanged, it emits zero rows, and it charges zero of this page's
/// allowance, which is then available in full to the families. Only an
/// owner-established frontier takes that path — the cursor must name the
/// owner-emitted prefix of the frozen window, which
/// `check_operational_cursor_boundary` re-derives from durable keys — so a
/// caller cannot declare exhaustion by counting.
fn operational_page(
    read: &ReadTransaction,
    request: &OrsBackupRequest,
) -> Result<OperationalSegment, OrsError> {
    let cursor = resolve_operational_cursor(read, request)?;
    let table = read
        .open_table(super::OPERATIONAL_HISTORY)
        .map_err(storage)?;
    let segment = if cursor.emitted_rows == cursor.identity.operational_row_count {
        check_operational_cursor_boundary(&table, &cursor)?;
        Ok(OperationalSegment {
            entries: Vec::new(),
            continuation: OrsOperationalContinuation {
                cursor: cursor.clone(),
                state: OrsAxisState::Exhausted(cursor),
            },
            page_bytes: 0,
        })
    } else {
        operational_segment(
            &table,
            &cursor,
            usize::from(request.page_entries),
            request.max_bytes,
            request.max_bytes,
        )
    };
    drop(table);
    segment
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
///
/// A family a previous page already closed is SKIPPED (issue #953): its verified
/// terminal frontier is re-proved against durable state and carried forward
/// unchanged, it emits zero rows, and it charges none of this page's row or byte
/// allowance, so every remaining slot goes to the axes that are still open. The
/// two checks that make the frontier OWNER-ESTABLISHED rather than caller-asserted
/// still run on this path: the family's durable revision must be the frozen one,
/// and the presented cursor must name the owner-emitted durable-key prefix, so a
/// caller-selected row count cannot declare a family exhausted.
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
    if cursor.emitted_rows == cursor.identity.family_row_count {
        let table = read
            .open_table(family_table_definition(family)?)
            .map_err(storage)?;
        check_family_cursor_boundary(&table, cursor)?;
        drop(table);
        return Ok((
            Vec::new(),
            Some(OrsFamilyContinuation {
                cursor: cursor.clone(),
                state: OrsAxisState::Exhausted(cursor.clone()),
            }),
            0,
        ));
    }
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
    /// True when ANY declared family still has rows behind its frontier.
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
/// `page_index` is the page's position in the walk, NOT a window selector. Since
/// issue #2967 there is no count-stride window left to select: page 0 is the walk
/// the request's `after_order` declares, and every later page is read under the
/// owner-issued operational cursor its previous page ended with, echoed back
/// through [`OrsBackupRequest::with_operational_cursor`]. Calling this with
/// `page_index > 0` and no declared operational cursor is refused rather than
/// answered with a count-stride guess, because a guess over a sparse order domain
/// is how rows were duplicated in the first place. The mirror rule holds at
/// `page_index == 0`: a declared cursor that has already emitted rows is refused
/// there too, because a page 0 that opens mid-walk is a page
/// [`OrsBackupSnapshot::validate`] will not accept, and this crate must not
/// manufacture a page its own validator rejects.
///
/// Callers building a snapshot should use [`export_snapshot`], which holds ONE
/// transaction across the whole page loop; pages taken from repeated calls to this
/// function are pages from repeated read transactions and are therefore not one
/// snapshot, whatever timestamp they carry. Any row decode failure returns
/// [`OrsError::IntegrityProblem`]; a page is never fabricated from reference counts
/// alone. Accumulated entry bytes are bounded by `request.max_bytes` (already
/// `1..=MAX_BACKUP_BYTES` by the request constructor).
pub(super) fn export_page(
    database: &Database,
    request: &OrsBackupRequest,
    page_index: u32,
) -> Result<OrsBackupPage, OrsError> {
    let read = database.begin_read().map_err(storage)?;
    let observation = capture_store_fence(&read)?;
    check_export_fence(request, &observation)?;
    // The census runs on the single-page entrypoint too, not only on the whole
    // snapshot: a page is the unit a caller actually holds, and a page built
    // from a store whose tables outrun the compiled contract must not be
    // produced at all. It is the same transaction as the page, so it describes
    // the same moment (issue #953, A5).
    check_row_family_census(&read)?;
    // The walk's end boundary needs no separate hand-off here, and not by
    // oversight: it travels on the page itself, inside the axis's outgoing state.
    // A single-page export has no following page, and a multi-page one reads the
    // boundary straight off each page.
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
/// The operational-history walk is this page's FIRST segment and is paged by its
/// own owner-issued cursor under its own frozen window (issue #2967). Neither
/// cursor-paged family (#269 process-stream recovery, #1971 versioned artifacts)
/// shares that cursor: their rows carry no canonical operation order, so each is
/// paged through its OWN request slot in durable-key order, sharing this page's
/// remaining row and byte budget so the per-page ceiling is unchanged. Each family
/// segment is admitted from what the previous one actually spent, so a page can
/// never exceed `page_entries` or `max_bytes` by running three segments. An axis an
/// earlier page already closed emits nothing here and spends none of that
/// admission (issue #953).
/// `is_last` is the conjunction of the operational walk having no continuation left
/// and BOTH families having no continuation left, so a page that still owes rows on
/// any axis is never final.
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
    if page_index > 0 && request.operational_cursor.is_none() {
        // The count-stride window this used to derive is gone, and a page beyond the
        // first with no declared operational cursor has no boundary to be read
        // under. Answering it anyway would mean recomputing a stride guess, which
        // is the defect this issue closes.
        return Err(OrsError::InvalidField {
            field: "backup.page_index",
            reason: "a page beyond the first requires the owner-issued operational continuation from the previous page",
        });
    }
    if page_index == 0
        && request
            .operational_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.emitted_rows != 0)
    {
        // The mirror of the rule above, and the exact reason a snapshot always
        // opens its operational axis at the walk's declared start: pages must be
        // continuous from zero, and `check_operational_pages` refuses a page 0
        // that opens mid-walk, so a snapshot built here would be one this crate's
        // own validator rejects. Continuation therefore goes the way
        // `after_order` is documented to work — a truncated walk is resumed by
        // opening a NEW window at the outstanding cursor's `after_order`, and that
        // window is a snapshot in its own right, complete over exactly the window
        // it declares. Appending a suffix to a frozen identity is refused here
        // rather than answered, because its declared denominator covers rows the
        // pages could never carry.
        return Err(OrsError::InvalidField {
            field: "backup_operational_cursor",
            reason: "a snapshot opens the operational walk at its declared start; resume a truncated walk by opening a new window at the outstanding cursor's after_order",
        });
    }
    // The token binds the owner-observed fence, not only the caller's claim
    // about it, and the page's digest is derived from the finished page by the
    // ONE derivation in the contract module.
    let fence_token =
        request.observed_fence_token(observation.high_water_order, observation.family_revision);
    // The walk: an exact continuation under a re-proved frozen window, enumerated
    // in the table's own durable-key order. No full table scan, no sort, no
    // truncation, and no row above the frozen high-water.
    let operational = operational_page(read, request)?;
    let mut entries = operational.entries;
    let total_bytes = operational.page_bytes;
    // Family paging, in a fixed order, each charged from what is actually left
    // of this page's admission.
    let families = family_page_segments(read, request, entries.len(), total_bytes)?;
    // `is_last` is the conjunction over ALL THREE axes: a page that still owes rows
    // to the operational walk or to either family is not final, so page continuity
    // can never hide an unemitted tail behind a final page (issue #1971, extended by
    // #2967). A family the request declared no cursor for contributes no
    // continuation, which is `!open` and so does not block finality — it makes the
    // snapshot partial instead, which `OrsBackupSnapshot::validate` is what refuses
    // as `Complete`.
    let is_last = !operational.continuation.operational_open() && !families.open;
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
        operational_continuation: operational.continuation,
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
    /// Exact continuation resuming the operational walk, if owed.
    outstanding_operational: Option<OrsOperationalCursor>,
    /// Exact continuation resuming the process-stream recovery family, if owed.
    outstanding_recovery: Option<OrsFamilyCursor>,
    /// Exact continuation resuming the versioned-artifact family, if owed.
    outstanding_artifact: Option<OrsFamilyCursor>,
    /// The request as the loop left it, carrying each axis's final cursor.
    continuing: OrsBackupRequest,
}

/// Paginates one snapshot under the caller's single capture transaction.
///
/// The bounded loop of [`export_snapshot`]: at most `max_pages` pages, each built
/// by [`export_page_in`] through the SAME read transaction, until a page is final
/// or the page budget is spent. Holding one transaction across the whole loop is
/// what makes the pages one moment.
///
/// EVERY axis advances by EXACTLY the frontier its own previous page ended with,
/// and each advance is dispatched on that frontier's own axis, so one axis's cursor
/// can only ever land in that axis's request slot. The frontier is carried on BOTH
/// outgoing states (issue #953), and that is the fix for the restarted axis: with a
/// single `Option<Cursor>` the loop had nothing to carry once an axis closed, so it
/// left that axis's PRE-PAGE cursor in force and the next page re-read the axis
/// from there — the whole operational window, or the whole family, re-emitted while
/// a later axis carried the snapshot forward. Attaching the frontier on both arms
/// makes an exhausted axis stay exhausted and inert, and an open axis resume.
///
/// The operational axis keeps the property issue #2967 established — page N+1 is
/// read under page N's actual emitted tail, so the walk neither repeats nor skips a
/// row in the sparse order domain — and gains the family twin of it (issue #953).
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
        // The exact outgoing boundary of every axis, whatever state it is in. Read
        // off the page itself so there is no second copy to keep in step with it.
        let next_operational = page.operational_continuation.frontier().clone();
        let next_recovery = page
            .family_continuation
            .as_ref()
            .map(|continuation| continuation.frontier().clone());
        let next_artifact = page
            .versioned_artifact_continuation
            .as_ref()
            .map(|continuation| continuation.frontier().clone());
        last_page_was_final = page.is_last;
        pages.push(page);
        if last_page_was_final {
            break;
        }
        continuing = continuing.with_operational_cursor(next_operational)?;
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
    // The last page is the authority on whether EACH axis is finished: a page that
    // ended an axis leaves no outstanding cursor for it even when an earlier page
    // did, so a snapshot is never left claiming an outstanding cursor it has
    // already emitted past. An EXHAUSTED axis publishes nothing — its terminal
    // frontier stays on the page and is not converted into an outstanding cursor a
    // caller could resume from (issue #953).
    let outstanding_of = |page: Option<&OrsBackupPage>, family: RowFamilyKind| {
        page.and_then(|page| match family {
            RowFamilyKind::ProcessStreamRecovery => page.family_continuation.as_ref(),
            RowFamilyKind::VersionedArtifacts => page.versioned_artifact_continuation.as_ref(),
            _ => None,
        })
        .and_then(OrsFamilyContinuation::open_cursor)
        .cloned()
    };
    let last = pages.last();
    Ok(SnapshotPages {
        outstanding_operational: last
            .and_then(|page| page.operational_continuation.open_cursor().cloned()),
        outstanding_recovery: outstanding_of(last, RowFamilyKind::ProcessStreamRecovery),
        outstanding_artifact: outstanding_of(last, RowFamilyKind::VersionedArtifacts),
        pages,
        entry_count,
        last_page_was_final,
        continuing,
    })
}

/// Derives the snapshot's completeness from EXHAUSTION on every axis (issue #2967,
/// made EXPLICIT by #953).
///
/// `Complete` used to be a function of row presence and of the process-stream
/// family's continuation alone, so a one-page budget that stopped on a non-final
/// operational page could still mint it. Every arm below is one demonstrable reason
/// the walk is NOT exhausted, tested in a fixed order and each naming its own axis
/// through [`BackupPartialReason`], so "the caller's next action" is a decision the
/// value makes rather than a substring a caller has to parse (W13).
///
/// The arms, in order:
/// 1. an axis is still OPEN — the operational walk or a cursor-paged family. The
///    reported reason carries that axis's exact open frontier, which is what a
///    caller resumes from. A byte or page limit lands here and can never be
///    reported as exhaustion (issue #953);
/// 2. a cursor-paged family was never given a denominator at all, which is the
///    THIRD condition — unknown coverage, not an exhausted axis — and never an
///    empty complete family (I05-16);
/// 3. the declared operational window is empty, which is also unknown coverage;
/// 4. every required axis is EXPLICITLY exhausted at the denominator it was opened
///    with. This is where issue #953's guarantee lives: the check is not "no
///    outstanding cursor" but "each axis stated [`OrsAxisState::Exhausted`] and
///    that terminal frontier accounts for exactly its frozen row count". The
///    segment builders already refuse to declare exhaustion below a denominator,
///    so this arm is a producer-side statement of the same rule rather than a
///    second measurement;
/// 5. otherwise, and only then, `Complete` — and only with a non-empty aggregate and
///    a final last page, because a final page is the conjunction of every axis
///    having no continuation left.
///
/// The final `else` is a refusal rather than a fifth reason: every axis reported
/// itself exhausted and the last page was final, yet the aggregate is empty, and
/// that combination is a contradiction rather than a truncated walk. Reporting it as
/// a partial would state a reason the snapshot does not have.
fn snapshot_completeness(
    operational_history: &OrsOperationalSnapshotIdentity,
    last_operational: &OrsOperationalContinuation,
    last_recovery: Option<&OrsFamilyContinuation>,
    last_artifact: Option<&OrsFamilyContinuation>,
    continuing: &OrsBackupRequest,
    entry_count: u64,
    last_page_was_final: bool,
) -> Result<BackupCompleteness, OrsError> {
    let family_outstanding =
        |cursor: &OrsFamilyCursor, family| BackupPartialReason::FamilyContinuationOutstanding {
            family,
            emitted_rows: cursor.emitted_rows,
            remaining_rows: cursor
                .identity
                .family_row_count
                .saturating_sub(cursor.emitted_rows),
        };
    if let Some(next) = last_operational.open_cursor() {
        return Ok(BackupCompleteness::Partial {
            reason: BackupPartialReason::OperationalContinuationOutstanding {
                high_water_order: next.identity.high_water_order,
                emitted_rows: next.emitted_rows,
                remaining_rows: next
                    .identity
                    .operational_row_count
                    .saturating_sub(next.emitted_rows),
            },
        });
    }
    if let Some(next) = last_recovery.and_then(OrsFamilyContinuation::open_cursor) {
        return Ok(BackupCompleteness::Partial {
            reason: family_outstanding(next, RowFamilyKind::ProcessStreamRecovery),
        });
    }
    if let Some(next) = last_artifact.and_then(OrsFamilyContinuation::open_cursor) {
        return Ok(BackupCompleteness::Partial {
            reason: family_outstanding(next, RowFamilyKind::VersionedArtifacts),
        });
    }
    if continuing.process_stream_recovery_cursor.is_none() {
        return Ok(BackupCompleteness::Partial {
            reason: BackupPartialReason::NoFamilyDenominator {
                family: RowFamilyKind::ProcessStreamRecovery,
            },
        });
    }
    if continuing.versioned_artifact_cursor.is_none() {
        return Ok(BackupCompleteness::Partial {
            reason: BackupPartialReason::NoFamilyDenominator {
                family: RowFamilyKind::VersionedArtifacts,
            },
        });
    }
    if operational_history.operational_row_count == 0 {
        return Ok(BackupCompleteness::Partial {
            reason: BackupPartialReason::EmptyDenominator,
        });
    }
    // Arm 4: explicit exhaustion at the denominators the axes were opened with.
    let operational_exhausted = last_operational
        .exhausted_cursor()
        .is_some_and(|cursor| cursor.emitted_rows == operational_history.operational_row_count);
    let family_exhausted = |continuation: Option<&OrsFamilyContinuation>| {
        continuation
            .and_then(OrsFamilyContinuation::exhausted_cursor)
            .is_some_and(|cursor| cursor.emitted_rows == cursor.identity.family_row_count)
    };
    let recovery_exhausted = family_exhausted(last_recovery);
    let artifact_exhausted = family_exhausted(last_artifact);
    if !(operational_exhausted && recovery_exhausted && artifact_exhausted) {
        return Err(OrsError::IntegrityProblem {
            record_type: "backup_axis_exhaustion",
            reason: "a complete snapshot requires every required axis to be explicitly exhausted at the denominator it was opened with".to_owned(),
        });
    }
    if entry_count > 0 && last_page_was_final {
        return Ok(BackupCompleteness::Complete);
    }
    Err(OrsError::ProjectionLimitExceeded)
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
/// The 28 tables the census excludes with a written nonrestorable/forensic reason
/// are consequently outside BOTH the denominator and this witness. That is the
/// correct result for a table with no import path, and it is now a DECIDED
/// exclusion rather than the old A5 gap: an earlier version of this comment
/// described `RowFamilyKind` enumerating 41 families while roughly 20 physical
/// tables had no disposition at all, which was true then and is no longer true.
/// Every declared table now has a disposition, so a table can be outside the
/// denominator only by a written decision recorded in
/// [`dispositioned_tables`].
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
/// Since issue #2967 the operational window is not arithmetic at all. `after_order`
/// names the walk's declared START, every later page is read under the owner-issued
/// [`OrsOperationalCursor`] its own previous page ended with, and every emitted row
/// satisfies `previous_cursor < operation_order <= frozen_high_water`. The typed
/// family cursors advance the same way, each by exactly the owner-issued cursor its
/// own previous page ended with, on its own axis.
///
/// When the page budget ends on a non-final page, the exact outstanding cursor of
/// whichever axis still owes rows is retained as a typed `Partial` disposition
/// carrying that cursor, so the caller resumes rather than restarts. Every axis now
/// has such a cursor, which is why this function no longer has to fall back on a
/// bounded refusal for a non-resumable operational stop. A request that declared no
/// family cursor for a cursor-paged family yields `Partial` with the typed
/// no-denominator reason, because a snapshot with no denominator for that family is
/// partial evidence and not an empty complete family. A decode failure reports
/// [`OrsError::IntegrityProblem`], never fabricated completeness. The denominator
/// digest binds every exported entry's payload digest together with the frozen
/// operational identity and the frozen identity of every cursor-paged family this
/// request declared.
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
    // Every table this store declares must carry an exact row family disposition
    // BEFORE a single row is read, so a store whose tables outrun the compiled
    // contract refuses the whole export rather than producing a snapshot whose
    // denominator silently omits a table (issue #953, A5).
    check_row_family_census(&read)?;
    // Every declared cursor is proved frozen BEFORE the page loop, so an axis that
    // already moved refuses the whole export rather than only the page that would
    // have read it.
    if let Some(cursor) = &request.operational_cursor {
        check_operational_identity_frozen(&read, &cursor.identity)?;
    }
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
        outstanding_operational,
        outstanding_recovery,
        outstanding_artifact,
        continuing,
    } = paged;
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
    // THE frozen operational identity, read off the LAST page's in-force cursor:
    // the last page is the authority on which window the walk was read under, for
    // the same reason it is the authority on which families are finished. The
    // last page's three outgoing STATES are carried beside it for the same reason
    // (issue #953): `Complete` is a statement about exhaustion, not about row
    // presence.
    let (operational_history, last_operational, last_recovery, last_artifact) = {
        let last = pages.last().ok_or(OrsError::ProjectionLimitExceeded)?;
        (
            last.operational_continuation.cursor.identity.clone(),
            last.operational_continuation.clone(),
            last.family_continuation.clone(),
            last.versioned_artifact_continuation.clone(),
        )
    };
    // `Complete` is derived from EXHAUSTION on every axis, never from row presence
    // (issue #2967, W8), and from EXPLICIT exhaustion at the denominators the axes
    // were opened with (issue #953).
    let completeness = snapshot_completeness(
        &operational_history,
        &last_operational,
        last_recovery.as_ref(),
        last_artifact.as_ref(),
        &continuing,
        entry_count,
        last_page_was_final,
    )?;
    let mut snapshot = OrsBackupSnapshot {
        source: request.source.clone(),
        fence: request.fence.clone(),
        pages,
        denominator_digest: String::new(),
        entry_count,
        total_bytes,
        completeness,
        operational_history,
        next_operational_cursor: outstanding_operational,
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
    // THE producer runs its own contract before handing the archive over
    // (issue #953). This function used to set the denominator and return
    // `Ok(snapshot)`, so nothing stopped it returning a snapshot its own
    // validator rejects — the repeated-read transition this same issue repaired
    // produced exactly such an archive, and only a RECEIVER running
    // `validate()` would ever have found it. The check is a guard on the state
    // machine above, never a substitute for it, and it runs after the digest is
    // assigned so the denominator it re-derives is the real one.
    snapshot.validate()?;
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
    // Same rule as the snapshot validator: a final page must leave NO continuation
    // open on any axis, and `validate_binding` cannot know that from one page alone.
    // All three are checked because `is_last` is their conjunction (#1971, extended
    // by #2967).
    let open = page.operational_continuation.operational_open()
        || page
            .family_continuation
            .as_ref()
            .is_some_and(OrsFamilyContinuation::family_open)
        || page
            .versioned_artifact_continuation
            .as_ref()
            .is_some_and(OrsFamilyContinuation::family_open);
    if page.is_last && open {
        return Err(OrsError::InvalidField {
            field: "backup_page_is_last",
            reason: "a final page must not leave an open operational or family continuation",
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
    let destination_identity = {
        let meta = read.open_table(super::META).map_err(storage)?;
        super::read_store_object_identity(&meta)?
    };
    if destination_identity.installation_id.as_deref()
        != Some(import.destination.installation_id.as_str())
    {
        return Err(OrsError::IntegrityProblem {
            record_type: "ors_store_object_identity",
            reason: "backup destination identity does not match the durable ORS installation"
                .to_owned(),
        });
    }
    // The DESTINATION's own row family census, before a single entry is triaged
    // (issue #953, A5). The issue requires that a family with no disposition
    // "cannot be silently exported, imported or counted", and this is the import
    // half: a page carrying a family this installation's compiled contract does
    // not disposition is refused here rather than triaged entry by entry into
    // outcomes that describe a denominator nobody declared.
    check_row_family_census(&read)?;
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

/// Establishes the EXPECTED member roster of the snapshot under import,
/// independently of every import outcome (issue #953 import-denominator repair).
///
/// The denominator comes from the archive itself and from nothing else:
///
/// 1. [`OrsBackupSnapshot::validate`] is run on the presented snapshot. That is
///    the ONE existing validator, applied to the ORIGINAL recorded value: it
///    re-derives `denominator_digest` from the snapshot's own pages, frozen
///    identities and entry roster and refuses a declared value that does not
///    equal it, so the value compared below is proved rather than recomputed over
///    whatever this function happens to hold.
/// 2. The snapshot's own source identity must equal `import.source`. A receipt
///    for one installation's snapshot cannot be reconciled under another's
///    import request, and the schema version travels inside the identity, so an
///    unsupported source is refused here too.
/// 3. The snapshot's ORIGINAL recorded `denominator_digest` must equal
///    `import.snapshot_digest`. This is a comparison of the recorded value
///    against the import's recorded value, not a digest recomputed over the
///    outcomes.
/// 4. [`OrsBackupSnapshot::expected_member_roster`] then reads the member
///    identities off the proved pages, and refuses a snapshot that does not
///    establish that its pages are its whole denominator.
///
/// NO second registry, NO permanent snapshot table and NO invented digest is
/// introduced: the snapshot the caller already holds is the single source, and
/// the audited snapshot owner remains the only producer of one.
fn expected_import_roster(
    snapshot: &OrsBackupSnapshot,
    import: &OrsBackupImportRequest,
) -> Result<Vec<(RowFamilyKind, String)>, OrsError> {
    snapshot.validate()?;
    if snapshot.source != import.source {
        return Err(OrsError::IntegrityProblem {
            record_type: "backup_import_source",
            reason: format!(
                "the snapshot under import was captured from installation {:?} generation {} and is not the source this import request declares",
                snapshot.source.installation_id, snapshot.source.ors_generation
            ),
        });
    }
    if snapshot.denominator_digest != import.snapshot_digest {
        return Err(OrsError::PayloadIntegrityMismatch);
    }
    snapshot.expected_member_roster()
}

/// Observes the CURRENT owner of ORS recovery effects for one import's member
/// set, inside the caller's read transaction (issue #953, A17).
///
/// The current owner is the ORS store itself, read through its own live durable
/// rows: `RECOVERY_INBOX` (`DurableInboxRecord`, keyed by `item_id`) and
/// `RECOVERY_PROBLEMS` (`RecoveryProblem`, keyed by
/// `operation_or_checkpoint_id`). A member is STILL UNRESOLVED when the current
/// owner holds a live inbox row for it — present, with no terminal receipt yet
/// written, which is the durable shape `import_recovery_inbox` writes on
/// arrival and the only shape `record_recovery_inbox_disposition` closes — or
/// when it holds a recovery problem for it that
/// [`RecoveryProblem::is_resolved`] reports unresolved. The problem test is the
/// crate's own: unresolved problems never expire automatically, so absence of a
/// terminal receipt is a live obligation rather than a cleanup horizon.
///
/// `expected_members` — NOT the outcome vector — is the source of truth for what
/// the current owner is asked about (issue #953 import-denominator repair). It is
/// the roster [`expected_import_roster`] established from the validated snapshot
/// before a single outcome was read. The previous signature took `per_entry` and
/// cloned, sorted and de-duplicated it into `validated_record_ids`, so the record
/// stated the caller's own list back to it and
/// [`OrsBackupImportReceipt::owner_validation_is_complete`] compared two
/// projections of one vector: a missing import member, a subset, a foreign
/// outcome and a duplicated outcome all compared equal, and the live scans below
/// could not detect any of them because they only look for unresolved rows whose
/// identifier already occurs in the roster they were given. The record now
/// answers for the members the ARCHIVE declares, and a caller that triaged fewer
/// of them is caught by the coverage comparison rather than by a row scan.
///
/// Takes `&ReadTransaction` and never calls `load_recovery_problem` or
/// `list_recovery_problems`, because each of those opens its OWN `begin_read()`
/// and would therefore observe a different moment than the transaction this
/// validation is about. Both tables are read here, in the one transaction, so
/// the recorded answer describes a single instant.
///
/// Both scans are bounded by the existing [`IMPORT_SCAN_ROW_CAP`] and return the
/// existing [`OrsError::ProjectionLimitExceeded`] when it is exceeded, exactly as
/// [`triage_entry`] does. No new cap, timeout or field is introduced.
fn observe_current_owner_validation(
    read: &ReadTransaction,
    snapshot_digest: &str,
    expected_members: &[(RowFamilyKind, String)],
    validated_at_ms: i64,
) -> Result<CurrentOwnerValidation, OrsError> {
    // The roster the current owner is being asked about, taken from the snapshot
    // and indexed once so the two bounded scans below are a membership test per
    // row rather than a linear search per row against the whole member list.
    // Sorted and de-duplicated because the record states the COMPLETE set that
    // was asked about and a repeated ask of one member is not a second member.
    // Family plus record identity is preserved on the expected side; a record id
    // declared under two families is refused by the receipt's coverage check
    // rather than half-covered here, because the outcome vocabulary is keyed by
    // record id alone.
    let mut validated_record_ids: Vec<String> = expected_members
        .iter()
        .map(|(_, record_id)| record_id.clone())
        .collect();
    validated_record_ids.sort();
    validated_record_ids.dedup();
    let asked: BTreeSet<&str> = validated_record_ids.iter().map(String::as_str).collect();
    let mut unresolved_effect_identities: Vec<String> = Vec::new();

    let mut scanned: u64 = 0;
    let inbox = read.open_table(super::RECOVERY_INBOX).map_err(storage)?;
    for row in inbox.iter().map_err(storage)? {
        scanned = scanned
            .checked_add(1)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        if scanned > IMPORT_SCAN_ROW_CAP {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let (_, value) = row.map_err(storage)?;
        let record: DurableInboxRecord = decode_named(value.value(), "recovery_inbox")?;
        // A terminal receipt is what closes an inbox row; without one the
        // current owner still holds the staged effect, whatever disposition
        // marker the row carries.
        if record.terminal_receipt_id.is_some() {
            continue;
        }
        if asked.contains(record.item.item_id.as_str())
            && !unresolved_effect_identities
                .iter()
                .any(|identity| identity == record.item.item_id.as_str())
        {
            unresolved_effect_identities.push(record.item.item_id.as_str().to_owned());
        }
    }
    drop(inbox);

    let mut scanned: u64 = 0;
    let problems = read.open_table(super::RECOVERY_PROBLEMS).map_err(storage)?;
    for row in problems.iter().map_err(storage)? {
        scanned = scanned
            .checked_add(1)
            .ok_or(OrsError::ProjectionLimitExceeded)?;
        if scanned > IMPORT_SCAN_ROW_CAP {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let (_, value) = row.map_err(storage)?;
        let problem: RecoveryProblem = decode_named(value.value(), "recovery_problems")?;
        if problem.is_resolved() {
            continue;
        }
        let identity = problem.operation_or_checkpoint_id.as_str();
        if asked.contains(identity)
            && !unresolved_effect_identities
                .iter()
                .any(|held| held == identity)
        {
            unresolved_effect_identities.push(identity.to_owned());
        }
    }
    drop(problems);
    unresolved_effect_identities.sort();

    let validation = CurrentOwnerValidation {
        snapshot_digest: snapshot_digest.to_owned(),
        validated_record_ids,
        unresolved_effect_identities,
        // Both families, unconditionally: both were read above, and a validation
        // that omitted one would be refused by the gate anyway, so recording
        // what was actually read is both true and necessary.
        consulted_families: vec![
            RowFamilyKind::RecoveryInbox,
            RowFamilyKind::RecoveryProblems,
        ],
        validated_at_ms,
    };
    // Rejected here rather than carried: a record that does not pass its own
    // shape check can never satisfy the gate, so failing the builder is honest
    // and failing the gate later would only hide it.
    validation.validate()?;
    Ok(validation)
}

/// Reconciles per-entry quarantine outcomes into one import receipt.
///
/// The EXPECTED denominator is established FIRST and from the snapshot, by
/// [`expected_import_roster`], before a single outcome is read. That ordering is
/// the whole repair (issue #953 import-denominator repair): the previous signature
/// took only `per_entry`, derived the validation's roster from it and compared
/// the two, so a valid nonempty snapshot whose member was never triaged produced
/// `Satisfied` — the producer built an empty roster, the receipt carried an empty
/// member set, both live families were read, the unresolved count was zero, and
/// the gate reported a known zero for a member nobody had covered.
///
/// `snapshot` is the already-validated archive the import request names by
/// `snapshot_digest`. It is the retained exact reference resolved through the
/// existing snapshot owner, not a second registry: this crate stores no snapshot
/// table and invents no digest of its own.
///
/// Binds `import.snapshot_digest` with the source/destination installations, the
/// expected roster and the full per-entry outcome vector via
/// [`OrsBackupImportReceipt::new`], which validates every shape and derives the
/// unresolved count from the outcomes. Emits no store writes: receipt building is
/// a pure function over an already-proved snapshot and already-triaged outcomes,
/// and the one store read it performs is the read that observes the current owner
/// for [`CurrentOwnerValidation`].
///
/// It opens that read ITSELF (rather than taking a `&ReadTransaction`) and hands
/// it to [`observe_current_owner_validation`], so the current owner's answer and
/// the receipt it lands on describe one instant. `import_page_quarantined` opens
/// its own read the same way, for the same reason: a validation assembled from
/// reads taken at different moments would not be an answer to any question.
pub(super) fn reconcile_import_receipt(
    database: &Database,
    import: &OrsBackupImportRequest,
    snapshot: &OrsBackupSnapshot,
    per_entry: &[(String, PerEntryOutcome)],
    import_at_ms: i64,
) -> Result<OrsBackupImportReceipt, OrsError> {
    let expected_members = expected_import_roster(snapshot, import)?;
    let read = database.begin_read().map_err(storage)?;
    let destination_identity = {
        let meta = read.open_table(super::META).map_err(storage)?;
        super::read_store_object_identity(&meta)?
    };
    if destination_identity.installation_id.as_deref()
        != Some(import.destination.installation_id.as_str())
    {
        return Err(OrsError::IntegrityProblem {
            record_type: "ors_store_object_identity",
            reason: "backup receipt destination does not match the durable ORS installation"
                .to_owned(),
        });
    }
    let current_owner_validation = observe_current_owner_validation(
        &read,
        &import.snapshot_digest,
        &expected_members,
        import_at_ms,
    )?;
    drop(read);
    // `new` is the receipt builder and it runs the known-zero gate against this
    // freshly observed validation, recording the typed verdict on the receipt.
    OrsBackupImportReceipt::new(
        import.snapshot_digest.clone(),
        import.source.installation_id.clone(),
        import.destination.installation_id.clone(),
        expected_members,
        per_entry.to_vec(),
        import_at_ms,
        current_owner_validation,
    )
}

/// Replays a lost import response without any duplicate effect.
///
/// An idempotent clone of the prior receipt: no store write, no re-triage, so a
/// retried response can never double-apply quarantine outcomes.
///
/// It does NOT carry the prior verdict forward. The gate is RE-EVALUATED from
/// the validation RECORDED ON THE RECEIPT, so a verdict that is stale, or that
/// disagrees with the validation it was recorded beside, is corrected on replay
/// instead of being trusted. That re-evaluation is the whole point: the verdict
/// is a report of the gate, never the gate's input, so a caller cannot replay a
/// receipt into a satisfied gate by writing a satisfied verdict into it. No
/// store read happens here either — the recorded validation is the record, and
/// re-reading live state would make a replay's answer depend on when it was
/// replayed rather than on what it attests.
///
/// Replay therefore remains HISTORICAL and cannot manufacture fresh current-owner
/// evidence (issue #953 import-denominator repair, step 6). It re-derives nothing:
/// the receipt's `expected_members` and `current_owner_validation` are the two
/// halves recorded by the original `reconcile_import_receipt` for the SAME
/// snapshot and the same import operation, and the coverage check compares those
/// recorded halves. A receipt built from an incomplete roster is already refused
/// by that check, and a replay of it stays refused; there is no re-triage, no
/// blind effect retry and no path here that reads live state or re-derives a
/// roster.
pub(super) fn reconcile_lost_import_response(
    prior: &OrsBackupImportReceipt,
) -> OrsBackupImportReceipt {
    let mut replayed = prior.clone();
    replayed.known_zero_verdict =
        match replayed.known_zero_unresolved(&replayed.current_owner_validation) {
            Ok(()) => KnownZeroVerdict::Satisfied,
            Err(error) => KnownZeroVerdict::Refused {
                reason: error.to_string(),
            },
        };
    replayed
}
