//! Kernel-owned production restore adapter (issue #960).
//!
//! Architecture: A13.7 Backups, Restore, and Migration (isolated restore,
//! purge-first, suspended ORS import, new lineage, separate cutover
//! authority); A13.6 Operational Recovery State (only identities, opaque
//! envelopes, epochs, suspended leases, checkpoints, intents, manifests,
//! anchors); I5.13 backup classes (full denominator, degraded ceiling,
//! key-material rule); I14.21 unknown-commit recovery (reconcile by identity,
//! never blind retry); A0.3 Hard Boundaries (no revived authority, no minted
//! epochs, no fabricated receipts); I1.8 exact ownership and call paths (one
//! logical Governor, two internal checks — this adapter never invents
//! semantics, authorizes them, and commits them alone); I14.3 Control Reserve
//! (bounded restore work; no unbounded waits inside a held transaction).
//! Implementation: the single existing journaled state machine
//! ([`RestorePlan::execute_with_journal`](eliot_backup::RestorePlan::execute_with_journal))
//! drives execution and resumption — same-transaction resume is a second call
//! with the same bundle and target context, never a second engine. I5.19
//! intent-before-effect ordering and I5.27 canonical operation identity come
//! from that engine, not from this file; I7.20 typed refusals cross the seam
//! without silence or fabricated success.
//!
//! What this file owns: the thin [`KernelBackupRestore`] execution body plus
//! the [`RestoreTarget`](eliot_backup::RestoreTarget) adapter
//! (`apply_restore_effect` / `reconcile_restore_effect`) over the historical
//! per-phase owner methods the accepted contract retains for owner adapters.
//! Every phase maps to its responsible owner through [`phase_owner`], and the
//! apply path executes the genuine owner operation with the exact bindings
//! the coordinator supplies:
//!
//! ```text
//! prepare/finalize ......... kernel-restore-owner (destination staging,
//!                              fence gate, observed evidence);
//! purge .................... purge owner (`apply_purge_ledger`: every ledger
//!                              entry is applied through the ORS purge-ledger
//!                              owner, which issues the revision; the archive's
//!                              declared revision is cross-checked against the
//!                              owner's own durable counter before the phase
//!                              stages anything, and the entries with the
//!                              revisions they consumed are staged as this
//!                              phase's evidence, purge-first before any
//!                              import);
//! canonical/receipt/
//! projection/rebuild/verify . canonical owner (`import_*`, chain + count
//!                              verification over observed destination state);
//! sealed blobs ............. blob owner (`DestinationRestoreAdapter::
//!                              restore_blob_sealed` with backup-bound
//!                              restoration receipts, the admitted key
//!                              manifest, and the destination scope;
//!                              re-sealed bytes staged, never plaintext);
//! ORS suspension ........... ORS owner (`suspended_recovery_entries`,
//!                              persisted as suspended evidence, never
//!                              runnable);
//! Watchdog spool fence ..... #955 owner, archive side only
//!                              (`suspended_watchdog_signal_entries`: the
//!                              archive's mandatory unresolved critical
//!                              signals are read and persisted as SUSPENDED
//!                              forensic evidence, never as supervision and
//!                              never as a reconciliation claim, so the
//!                              `watchdog_signals` obligation stays
//!                              unsatisfied);
//! ```
//!
//! Effects whose bindings are absent refuse fail-closed with the exact
//! responsible capability; reconciliation answers from persisted identity
//! receipts AND from the material those receipts attest (`Applied` only on
//! exact transaction/phase/input match with that material still present and
//! still the digested bytes; `NotApplied` only where the phase's own material
//! is proven absent, which is the only phase-specific positive no-effect
//! evidence this target holds; `Unknown` for undecidable bytes — a missing
//! receipt over material that IS published among them — so the engine takes
//! its explicit rollback-required disposition). A receipt file that cannot be
//! read is never an absence: `Path::exists()` collapses missing, inaccessible
//! and broken paths into one silent `false`, so the two absence tests on the
//! RECONCILIATION path — the receipt read in `load_applied` and the member
//! probe in `phase_material_published` — are fallible reads that distinguish
//! them, and an inaccessible one refuses rather than reading as absent. The
//! staged-output CLEANUP path is a separate concern and is not covered by that
//! claim: `is_attested_phase_material` and `count_dir` still answer presence
//! with `Path::exists()`. All effects here are synchronous and local with a
//! persisted identity receipt per phase, so no ambiguous external commit
//! exists in this target; the `Unknown` outcomes above are therefore all
//! LOCAL to a phase whose own material is undecidable, never a manufactured
//! effect ambiguity. Async owner-channel unknowns belong to the #962 wire
//! layer, which must upgrade reconciliation there, never downgrade readback to
//! a blind re-apply here.
//!
//! Every staged byte is made durable BEFORE the phase receipt that names it is
//! written, in the order the same module's ORS journal already applies to its
//! own sealed bodies: reserve bounded output capacity, write the
//! operation-owned temporary file, flush it, publish it at the admitted
//! destination, establish publication durability, then flush the phase receipt
//! and let the existing ORS CAS record `ReceiptPersisted`. A failed body flush
//! is a refusal, never a silent success, so a recovered row can never point at
//! material a target power loss could remove (A13.7 ARCH-RES-03, I5.19).
//!
//! The durable journal is injected as `J: RestoreJournalPort` with
//! owner-issued [`RestoreJournalAdmission`](eliot_backup::RestoreJournalAdmission):
//! production refuses fixture-flagged or unadmitted journals, and this file
//! contains no in-memory or no-op journal type by construction. The admission
//! is additionally bound to the journal that actually runs: the production
//! entry [`KernelBackupRestore::restore_with_ors_journal`] compares the
//! admission's `journal_identity_ref` with the durable ORS restore-journal
//! namespace, and compares the ORS binding with the archive, target, and the
//! admitted owner, so a production restore cannot file its durable rows under
//! an admission describing some other store. Cutover is validated-only
//! ([`KernelBackupRestore::qualify_cutover`]): no receipt is minted here —
//! authorization and execution belong to #961 — and qualification requires
//! owner-issued new-epoch and operational-readiness evidence, refusing a
//! rehearsal outright from the posture its own destination pinned.
//!
//! Capability cell: Kernel restore ownership (isolated import execution).
//! Forbidden authority: no ORS row reinterpretation, no epoch minting, no
//! cutover, no activation/retirement of any installation, no second phase
//! engine, no archive/phase algorithm, no invented target methods, no
//! Value-based escapes.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Component, Path, PathBuf};

use eliot_backup::{
    BackupBlob, BackupBundle, BackupClass, BackupError, BlobRestorationReceipt, CanonicalRecord,
    CutoverAuthorization, DestinationRestoreAdapter, DestinationScope, OrsSnapshotFence,
    RestoreAppliedEffect, RestoreArchiveDisposition, RestoreArchiveDispositionKind, RestoreContext,
    RestoreEffectReceipt, RestoreEvidence, RestoreHistoricalAuthority, RestoreIntent,
    RestoreJournalAdmission, RestoreJournalPort, RestoreObligationState, RestoreObligations,
    RestoreOwnerObligation, RestorePhase, RestorePlan, RestoreReceipt, RestoreReconciliation,
    RestoreStep, RestoreTarget, RestoredFence, RestoredSealedBlob, WRITE_RECEIPT_RECORD_TYPE,
    WrappedKeyManifest, issue_restoration_receipts, suspended_recovery_entries,
    suspended_watchdog_signal_entries, verify_portable_key_material,
};
use eliot_backup::{ObservedLineageLimit, OwnerTrustBinding, RestoreProvenance};
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_ors::{MAX_JOURNAL_PAGE_ENTRIES, RedbRecoveryStore};
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::{
    CanonicalRestoreBatch, RetainedArchiveMember, RevocationHistoryPayload, SnapshotMemberType,
    WriteReceipt, parse_revocation_history_payload,
};
use serde::Serialize;

use super::backup_restore_ports::{
    DESTINATION_ADMISSION_FILE, DestinationManifestEvidence, KernelIsolatedDestination,
    KernelRestoreError, OrsRestoreBinding, OrsRestoreJournal, OrsRestoreJournalOwner,
    PinnedDestinationAdmission, RESTORE_EVIDENCE_FILE, RESTORE_ISOLATED_AREA,
    RESTORE_JOURNAL_IDENTITY, RESTORE_JOURNAL_PAYLOAD_AREA, RestorePorts, StagedCleanupRefusal,
    backup_to_kernel, check_kernel_effect_fence, ors_to_backup, require_production_admitted,
    sync_file, sync_parent_directory,
};

/// Maps one accepted restore step to its responsible owner.
///
/// The owner vocabulary matches the obligation owner ids carried in restore
/// evidence, so every executed phase is attributable to exactly one owner.
#[must_use]
pub const fn phase_owner(step: &RestoreStep) -> &'static str {
    match step {
        RestoreStep::PrepareIsolatedRoot | RestoreStep::FinalizeIsolatedRoot => {
            "kernel-restore-owner"
        }
        RestoreStep::ApplyPurgeLedger => owners::PURGE,
        RestoreStep::ImportSealedBlobs => owners::BLOB,
        RestoreStep::ImportCanonicalEvents
        | RestoreStep::ImportReceipts
        | RestoreStep::ImportProjections
        | RestoreStep::RebuildProjections
        | RestoreStep::VerifyReceiptEventChain => owners::CANONICAL,
        RestoreStep::SuspendOrsOperations => owners::ORS,
    }
}

/// Owner obligation identifiers and missing-binding capabilities shared by
/// the phase matrix, refusal errors, and evidence.
mod owners {
    pub const PURGE: &str = "purge-owner";
    pub const CANONICAL: &str = "canonical-owner";
    pub const REFERENCE: &str = "reference-owner";
    pub const BLOB: &str = "blob-owner";
    pub const ORS: &str = "ors-owner";
    pub const RECONCILIATION: &str = "reconciliation-owner";
    pub const WATCHDOG: &str = "watchdog-owner";
    pub const EXTERNAL_SOURCE: &str = "external-source-owner";
    pub const RUNTIME: &str = "runtime-owner";
    pub const SESSION: &str = "session-owner";
    pub const LEASE: &str = "lease-owner";
    pub const ROUTE: &str = "route-owner";
    pub const USER_BROKER: &str = "user-broker-owner";
    /// Missing destination blob-scope admission (#956/#958) for sealed-blob
    /// restoration under destination ownership.
    pub const BLOB_SCOPE_BINDING: &str = "blob-destination-scope";
    /// Missing live canonical-store import channel (#952/#962): writing the
    /// live store is never staged from here.
    pub const STORE_IMPORT: &str = "canonical-store-import";
    /// Missing accepted purge member-matching API: no in-tree contract maps
    /// a ledger `subject_ref` to archive member identities, so per-member
    /// suppression cannot be computed here. Backlog to M2.
    pub const PURGE_MEMBER_SUPPRESSION: &str = "purge-member-suppression";
    /// Absent live purge-ledger owner route (#960). The ORS owner is the only
    /// writer of the purge-ledger revision, so a restore that carries purge
    /// entries and holds no such owner cannot apply the ledger and refuses
    /// here rather than staging a ledger that names a revision no owner ever
    /// issued.
    pub const PURGE_LEDGER_OWNER: &str = "purge-ledger-owner";
}

/// Purge owner client: validates the purge ledger through the owner's
/// accepted validation before any import.
///
/// Per-entry `validate` is the owner check the archive already passed at
/// bundle validation and each purge phase re-proves; the staged ledger is
/// the tombstone preservation itself. `validate_restore` (refusing
/// `Purged`-state resurrection) is deliberately NOT called here: ledger
/// entries legitimately sit at `Purged`, and it guards resurrection into
/// live authority — isolated import preserves tombstones instead, while the
/// coordinator's erasure-refusal gate covers receipt rehydration.
/// Per-member suppression against `subject_ref` has no accepted matching
/// API in-tree and refuses as backlog rather than guessing.
pub struct PurgeOwnerClient<'a> {
    entries: &'a [PurgeLedgerEntry],
}

impl<'a> PurgeOwnerClient<'a> {
    /// Binds the client's view to the archive's validated purge ledger.
    pub fn bind(entries: &'a [PurgeLedgerEntry]) -> Self {
        Self { entries }
    }

    /// Runs the owner's accepted per-entry validation.
    pub fn validate_entries(&self) -> Result<(), BackupError> {
        for entry in self.entries {
            entry
                .validate()
                .map_err(|error| BackupError::Security(error.to_string()))?;
        }
        Ok(())
    }

    /// Suppression of one purged member. Unavailable: no accepted contract
    /// maps a ledger `subject_ref` to archive member identities. Fails
    /// closed as backlog instead of matching by spelling.
    pub fn suppress_purged_member(&self, _subject_ref: &str) -> Result<(), BackupError> {
        Err(BackupError::RestoreCapabilityUnsupported {
            capability: owners::PURGE_MEMBER_SUPPRESSION,
        })
    }
}

/// Revocation-ledger artifact kind: the bundle artifact slot carrying the
/// authority revocation history accompanying the snapshot (I12.20 S1:
///
/// "ensure backup/restore purge/revocation ledger prevents resurrection").
///
/// File-local carrier only: no archive-contract field names a revocation
/// ledger, so the accompanying history travels as an integrity-bound
/// artifact (`BackupArtifact::validate` plus the manifest section
/// checksums already bind its bytes) under this kind. Absence of the slot
/// means the source carries no revocation history and restore proceeds
/// exactly as before.
const REVOCATION_HISTORY_ARTIFACT_KIND: &str = "revocation-history";

/// Restore/import revocation-ledger gate (issue #1732).
///
/// Loads the revocation history accompanying the snapshot from the
/// integrity-bound artifact slot and enforces it before any import, so a
/// revoked lineage can never become active again after restore without
/// clean requalification:
///
/// ```text
/// no history slot ............. clean snapshot: Ok, behavior unchanged;
/// unparseable history ......... unknown evidence: refuse, never lossy;
/// disagreeing history views ... stale/drifted evidence: refuse;
/// recorded revocations ........ refuse: no accepted in-tree contract maps
///                               closure refs to archive member identities
///                               (same backlog posture as
///                               `PURGE_MEMBER_SUPPRESSION`), and no accepted
///                               carrier proves clean requalification, so any
///                               recorded revocation fails closed instead of
///                               risking resurrection by spelling match;
/// explicit zero revocations ... Ok: empty `closures` with a nonzero
///                               `source_revision` is the source attesting
///                               zero revocations (mirrors the
///                               `GetAuthorityRevocationHistory` contract).
/// ```
///
/// Fail-closed like the grant-side restore gate
/// (`AuthorityOwner::from_snapshot_with_revocation_history`): the only
/// passing histories are an absent slot or a valid explicit-empty view.
/// A recorded revocation refuses until a requalification carrier and a
/// closure-to-member matching API land; that backlog must not unblock
/// restore in this lane.
fn gate_revocation_ledger(bundle: &BackupBundle) -> Result<(), BackupError> {
    let mut histories: Vec<RevocationHistoryPayload> = Vec::new();
    for artifact in bundle
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == REVOCATION_HISTORY_ARTIFACT_KIND)
    {
        let payload: serde_json::Value = serde_json::from_slice(&artifact.bytes)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        histories.push(parse_revocation_history_payload(&payload).map_err(BackupError::Store)?);
    }
    let Some(first) = histories.first() else {
        return Ok(());
    };
    if histories.iter().any(|history| {
        history.source_revision != first.source_revision || history.origin_ref != first.origin_ref
    }) {
        return Err(BackupError::Security(
            "revocation history is stale for this restore".to_owned(),
        ));
    }
    if histories.iter().any(|history| !history.closures.is_empty()) {
        return Err(BackupError::Security(
            "restore refuses recorded revocation without clean requalification evidence".to_owned(),
        ));
    }
    Ok(())
}

/// Kernel ceiling on the number of files one restore execution may stage into
/// its isolated destination (issue #960, W11/A18 `bounds`).
///
/// The effective ceiling is the lower of this absolute limit and the count
/// derived from the archive's own members (see [`StagedOutputBudget`]), so an
/// archive can never raise the bound and the bound is never a number
/// unrelated to the archive.
pub const MAX_STAGED_OUTPUT_MEMBERS: usize = 65_536;
/// Kernel ceiling on the bytes one restore execution may stage into its
/// isolated destination.
///
/// I14.3: a restore writes into a controlled staging area with a budget, and
/// the budget is checked before the write rather than measured after it.
pub const MAX_STAGED_OUTPUT_BYTES: usize = 2 * 1024 * 1024 * 1024;
/// Byte allowance for ONE file the restore owner serializes itself: a phase
/// receipt, a phase marker, or a staged member file this owner does not copy
/// byte-for-byte from the archive.
///
/// A re-sealed blob falls in the last case: its staged length is the destination
/// envelope, not the archive's sealed length, so this allowance is also the
/// headroom that keeps a legitimate re-seal from tripping the byte bound.
pub const MAX_STAGED_RECEIPT_BYTES: usize = 64 * 1024;
/// Byte allowance for the finalize evidence document, which is assembled by
/// this owner from the plan and the archive rather than copied from either.
pub const MAX_STAGED_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;
/// Files this restore owner serializes for itself, independent of how many
/// members the archive carries: one phase receipt for each of the five fixed
/// phases (prepare, purge, rebuild, verify, finalize), the staged purge
/// ledger, the rebuild marker, the verify marker, the finalize evidence
/// document, and the pinned destination admission when Host admission exists —
/// plus headroom, so this is a bound on the owner's own fixed output set
/// rather than a tripwire that a later owner-evidence file would trip.
pub const OWNER_STAGED_FILE_ALLOWANCE: usize = 16;
/// `BackupError::LimitExceeded` field name for the member ceiling, so the
/// refusal names the exact bound that stopped the restore.
const STAGED_OUTPUT_MEMBERS_FIELD: &str = "restore.staged_output_members";
/// `BackupError::LimitExceeded` field name for the byte ceiling.
const STAGED_OUTPUT_BYTES_FIELD: &str = "restore.staged_output_bytes";
/// Exact subject of the purge-ledger revision refusal, the same subject
/// `elipt_backup::BackupBundle::validate_class_requirements` already refuses
/// this manifest field with, so one disagreement has one name here and in the
/// seam contract.
const PURGE_LEDGER_REVISION_SUBJECT: &str = "purge ledger revision";

/// Checked accumulation for the derived staged-output denominators. Overflow
/// refuses the archive through the named ceiling rather than wrapping a byte
/// count into a smaller, permissive one.
fn checked_total(total: &mut usize, bytes: usize) -> Result<(), BackupError> {
    *total = total.checked_add(bytes).ok_or(BackupError::LimitExceeded {
        field: STAGED_OUTPUT_BYTES_FIELD,
        limit: MAX_STAGED_OUTPUT_BYTES,
    })?;
    Ok(())
}

/// The archive's own member denominator: every member that costs one restore
/// phase, one staged member file, and one phase receipt.
///
/// Single-sourced so the durable-journal budget and the staged-output budget
/// can never disagree about how large this archive is.
fn archive_member_count(bundle: &BackupBundle) -> usize {
    bundle.blobs.len()
        + bundle.canonical_events.len()
        + bundle.receipts.len()
        + bundle.projections.len()
        + usize::from(bundle.ors_snapshot.is_some())
}

/// The bytes the archive itself declares for the members this target stages.
///
/// Measured, never guessed: a blob's sealed envelope length, a canonical
/// record's canonical payload length, a receipt's canonical length, the purge
/// ledger's canonical length, and the ORS snapshot's canonical length.
///
/// NOT every one of these is byte-identical to what lands in the destination.
/// A canonical record, a receipt, the purge ledger and the ORS snapshot are
/// serialized by this owner as canonical JSON, so their lengths are exact. A
/// blob is NOT: [`KernelRestoreTarget::apply_blob`] stages
/// `restored.resealed_bytes`, the envelope re-sealed for the destination scope
/// and key manifest, whose length is decided by that owner call and not by
/// `blob.sealed_bytes`. The difference is envelope metadata (destination scope
/// identity, key identity, nonce, authentication tag) and is per blob, not per
/// byte, which is why the derived ceiling covers it with a named per-staged-file
/// allowance rather than by claiming the two lengths are equal. Anyone tightening
/// [`MAX_STAGED_RECEIPT_BYTES`] must re-check that allowance still covers a
/// destination re-seal, or a legitimate large restore starts being refused
/// mid-flight.
fn staged_member_bytes(bundle: &BackupBundle) -> Result<usize, BackupError> {
    let canonical = |value: &serde_json::Value| -> Result<usize, BackupError> {
        canonical_json_bytes(value)
            .map(|bytes| bytes.len())
            .map_err(|error| BackupError::Serialization(error.to_string()))
    };
    let mut total = 0usize;
    for blob in &bundle.blobs {
        checked_total(&mut total, blob.sealed_bytes.len())?;
    }
    for record in bundle.canonical_events.iter().chain(&bundle.projections) {
        checked_total(&mut total, canonical(&record.payload)?)?;
    }
    for receipt in &bundle.receipts {
        let bytes = canonical_json_bytes(receipt)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        checked_total(&mut total, bytes.len())?;
    }
    let ledger = canonical_json_bytes(&bundle.purge_ledger)
        .map_err(|error| BackupError::Serialization(error.to_string()))?;
    checked_total(&mut total, ledger.len())?;
    if let Some(snapshot) = bundle.ors_snapshot.as_ref() {
        let bytes = canonical_json_bytes(snapshot)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        checked_total(&mut total, bytes.len())?;
    }
    Ok(total)
}

/// Canonical JSON text of one value the admitted archive holds, in the exact
/// byte sequence every digest over it is taken from.
///
/// One function, so the text a retained member publishes and the text a digest
/// is computed over can never be two different encodings of one record.
fn canonical_archive_text<T: Serialize>(value: &T) -> Result<String, BackupError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| BackupError::Serialization(error.to_string()))?;
    String::from_utf8(bytes).map_err(|_| {
        BackupError::Serialization("canonical archive bytes are not valid text".to_owned())
    })
}

/// One restore-class member's canonical bytes, as the admitted archive holds
/// them.
///
/// Private to this module and to the single publication that consumes it: the
/// resolved bytes and the owner's attestation over them are read out of the
/// admitted archive, handed to the admitted batch once, and never recomputed on
/// the far side. The digest here describes the ORIGINAL RECORDED bytes — it is
/// a value the archive itself recorded — and the receiving port validates that
/// recorded value against the bytes it actually holds rather than substituting
/// a fresh checksum of its own.
struct RetainedCanonicalPayload {
    /// Closed class label the archive itself carries for this record.
    ///
    /// Taken verbatim from the archive: `CanonicalRecord::record_type` for a
    /// canonical event or a projection, and the backup owner's own
    /// `WRITE_RECEIPT_RECORD_TYPE` for a write receipt. No class table is
    /// invented here and no record type is mapped onto another: a label the
    /// destination port does not own is refused there, typed, against the
    /// class it does not recognise.
    class: String,
    /// Digest of exactly `payload`, recorded by the archive owner.
    payload_digest: String,
    /// The canonical JSON encoding of the record, exactly as the archive holds
    /// it. This text IS the retained content: the byte count published beside
    /// it is this string's length and the digest above is this string's digest.
    payload: String,
}

/// The admitted archive's own restore-class member denominator.
///
/// Keyed by the archive's OWN recorded commitment to each member's canonical
/// content, never by anything a restore request supplied. For a canonical event
/// or projection that commitment is `CanonicalRecord::sha256`, which
/// `CanonicalRecord::validate` proves against the record's own payload here, so
/// the value published is a proven claim rather than an unverified one. A write
/// receipt carries no per-record checksum of its own — the archive records only
/// the section digest over the whole receipt list — so for a receipt the owner
/// attests once, here, over exactly the canonical bytes it holds, and the
/// destination validates that attestation against the bytes it received.
///
/// Members are held in a queue per commitment so byte-identical archive
/// records stay two members instead of collapsing into one: the admitted
/// member list decides how many of them this batch takes, and each admitted
/// member consumes exactly one.
struct RetainedArchiveIndex {
    entries: BTreeMap<String, VecDeque<RetainedCanonicalPayload>>,
}

impl RetainedArchiveIndex {
    /// Reads the admitted archive's restore-class members.
    ///
    /// Sealed blobs are deliberately absent. They are the blob owner's route —
    /// `DestinationRestoreAdapter::restore_blob_sealed`, already bound on this
    /// adapter through `apply_blob` — and no canonical-store class names them,
    /// so an admitted `Blob` member has nothing this index can honestly
    /// publish. It retains no payload here, and the destination port refuses
    /// that member typed rather than receiving bytes under a class this owner
    /// made up.
    fn read(bundle: &BackupBundle) -> Result<Self, BackupError> {
        let mut entries: BTreeMap<String, VecDeque<RetainedCanonicalPayload>> = BTreeMap::new();
        for record in bundle.canonical_events.iter().chain(&bundle.projections) {
            // The archive's own recorded checksum is proved against the
            // archive's own payload BEFORE the value is used as a lookup key or
            // published, so a record whose payload was replaced while its
            // checksum was retained can never become a retained payload here.
            record.validate()?;
            entries
                .entry(record.sha256.clone())
                .or_default()
                .push_back(RetainedCanonicalPayload {
                    class: record.record_type.clone(),
                    payload_digest: record.sha256.clone(),
                    payload: canonical_archive_text(&record.payload)?,
                });
        }
        for receipt in &bundle.receipts {
            receipt.validate().map_err(BackupError::Store)?;
            let payload = canonical_archive_text(receipt)?;
            // Attested once, over exactly the bytes published below: the
            // digest is taken from `payload` itself, so it describes the
            // retained content and not a re-encoding of it.
            let payload_digest = sha256_hex(payload.as_bytes());
            entries
                .entry(payload_digest.clone())
                .or_default()
                .push_back(RetainedCanonicalPayload {
                    class: WRITE_RECEIPT_RECORD_TYPE.to_owned(),
                    payload_digest,
                    payload,
                });
        }
        Ok(Self { entries })
    }

    /// Consumes the archive member one admitted member names, or `None` when
    /// the archive holds no member under that commitment.
    fn take(&mut self, content_digest: &str) -> Option<RetainedCanonicalPayload> {
        self.entries
            .get_mut(content_digest)
            .and_then(VecDeque::pop_front)
    }
}

/// The bounded staged-output budget one restore execution works inside.
///
/// Both ceilings are DERIVED and then capped, never chosen by a caller:
///
/// - the member ceiling is the archive's own member count (the same
///   denominator [`check_ors_journal_budget`] uses) times the two files each
///   member phase provably stages — the member file and its phase receipt —
///   plus [`OWNER_STAGED_FILE_ALLOWANCE`] for the fixed set this owner
///   serializes itself, capped by [`MAX_STAGED_OUTPUT_MEMBERS`];
/// - the byte ceiling is the archive's declared member bytes plus a named
///   per-file allowance for the receipts and markers this owner serializes
///   and a named allowance for the finalize evidence, capped by
///   [`MAX_STAGED_OUTPUT_BYTES`]. The same per-file allowance is what covers the
///   destination re-seal of each blob, whose staged length is not the declared
///   sealed length (see [`staged_member_bytes`]).
///
/// So a restore that fits its archive never meets the bound, and one that does
/// not is refused BEFORE the exceeding write instead of after it. The only
/// archive that can meet the byte bound is one whose declared members plus this
/// owner's own output exceed [`MAX_STAGED_OUTPUT_BYTES`]; that refusal is
/// deliberate, and the failure path removes what this execution staged rather
/// than leaving a half-written destination behind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StagedOutputBudget {
    members: usize,
    bytes: usize,
}

impl StagedOutputBudget {
    /// Derives the budget for one archive, refusing an arithmetic overflow
    /// instead of wrapping it into a permissive ceiling.
    fn derive(bundle: &BackupBundle) -> Result<Self, BackupError> {
        // One staged member file and one phase receipt per member phase: the
        // exact, archive-derived part of the denominator.
        let members = archive_member_count(bundle)
            .checked_mul(2)
            .and_then(|archive_files| archive_files.checked_add(OWNER_STAGED_FILE_ALLOWANCE))
            .ok_or(BackupError::LimitExceeded {
                field: STAGED_OUTPUT_MEMBERS_FIELD,
                limit: MAX_STAGED_OUTPUT_MEMBERS,
            })?
            .min(MAX_STAGED_OUTPUT_MEMBERS);
        let owner_bytes = members
            .saturating_mul(MAX_STAGED_RECEIPT_BYTES)
            .saturating_add(MAX_STAGED_EVIDENCE_BYTES);
        let bytes = staged_member_bytes(bundle)?
            .saturating_add(owner_bytes)
            .min(MAX_STAGED_OUTPUT_BYTES);
        Ok(Self { members, bytes })
    }
}

/// Canonical owner client: runs the owner's accepted validation and
/// verification over staged members.
///
/// Record/receipt validation and receipt/event-chain verification are the
/// owner's checks, invoked here with the exact members the phase touches.
/// Writing the live canonical store is a separate channel owned by the #962
/// wire: this client stages validated bytes into the isolated destination
/// substrate and refuses live import here, so a staged byte is never
/// presented as an executed owner transition.
pub struct CanonicalOwnerClient;

impl CanonicalOwnerClient {
    /// Runs the owner's accepted canonical-record validation.
    pub fn validate_event(record: &CanonicalRecord) -> Result<(), BackupError> {
        record.validate()
    }

    /// Runs the owner's accepted write-receipt validation.
    pub fn validate_receipt(receipt: &WriteReceipt) -> Result<(), BackupError> {
        receipt.validate().map_err(BackupError::Store)
    }

    /// Runs the owner's accepted receipt/event-chain verification over the
    /// exact members staged.
    pub fn verify_chain(
        receipts: &[WriteReceipt],
        events: &[CanonicalRecord],
    ) -> Result<(), BackupError> {
        let event_ids: BTreeSet<&str> = events
            .iter()
            .map(|event| event.record_id.as_str())
            .collect();
        for receipt in receipts {
            Self::validate_receipt(receipt)?;
            for event_id in &receipt.emitted_event_ids {
                if !event_ids.contains(event_id.as_str()) {
                    return Err(BackupError::ReceiptChainGap {
                        event_id: event_id.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Live canonical-store import. Unavailable in this lane: the channel
    /// belongs to the #962 wire. Fails closed before any effect.
    pub fn import_to_store(&self) -> Result<(), BackupError> {
        Err(BackupError::RestoreCapabilityUnsupported {
            capability: owners::STORE_IMPORT,
        })
    }
}

/// Blob owner client: restores one sealed blob under destination ownership
/// through the accepted destination adapter.
///
/// Binds the backup-bound restoration receipts (deterministically derived
/// from the validated bundle and admitted key manifest), the admitted key
/// manifest, and the destination scope. Invocation opens the sealed
/// envelope through the installation secret owner, digest-verifies the
/// plaintext, and re-seals under the destination lineage: key material and
/// plaintext stay memory-only inside the adapter and never cross back.
pub struct BlobOwnerClient<'a> {
    receipts: Vec<BlobRestorationReceipt>,
    manifest: &'a WrappedKeyManifest,
    scope: &'a DestinationScope,
}

impl<'a> BlobOwnerClient<'a> {
    /// Binds restoration receipts, key manifest, and destination scope.
    /// All three must be present: a blob without any binding refuses.
    pub fn bind(
        receipts: Vec<BlobRestorationReceipt>,
        manifest: Option<&'a WrappedKeyManifest>,
        scope: Option<&'a DestinationScope>,
    ) -> Result<Self, BackupError> {
        let manifest =
            manifest.ok_or(BackupError::MissingRecoveryComponent("blob_key_material"))?;
        let scope = scope.ok_or(BackupError::RestoreCapabilityUnsupported {
            capability: owners::BLOB_SCOPE_BINDING,
        })?;
        Ok(Self {
            receipts,
            manifest,
            scope,
        })
    }

    /// Restores one sealed blob: receipt binding, envelope open, plaintext
    /// digest verification, destination re-seal. Any refusal fails the phase
    /// closed — never write-through.
    pub fn restore_blob(
        &self,
        adapter: &DestinationRestoreAdapter,
        blob: &BackupBlob,
    ) -> Result<RestoredSealedBlob, BackupError> {
        let receipt = self
            .receipts
            .iter()
            .find(|receipt| receipt.blob_hash == blob.locator.hash.as_str())
            .ok_or(BackupError::PlanMismatch)?;
        adapter.restore_blob_sealed(blob, receipt, self.manifest, self.scope)
    }
}

/// ORS owner client: derives suspended-recovery evidence through the
/// accepted pure function.
///
/// Suspended entries are evidence only: restored ORS operations return as
/// `suspended_recovery`, never runnable, and this client performs no live
/// ORS mutation.
pub struct OrsOwnerClient;

impl OrsOwnerClient {
    /// Derives suspended-recovery entries from a validated ORS snapshot.
    pub fn suspend(
        snapshot: &OrsSnapshotFence,
    ) -> Result<Vec<RestoreHistoricalAuthority>, BackupError> {
        suspended_recovery_entries(snapshot)
    }
}

/// Live-authority invalidation kinds. Each names the exact owner that must
/// execute it; none executes inside isolated restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationKind {
    Runtime,
    Session,
    Lease,
    Route,
    UserBroker,
}

impl InvalidationKind {
    /// Obligation owner id for this invalidation.
    #[must_use]
    pub const fn owner_id(self) -> &'static str {
        match self {
            Self::Runtime => owners::RUNTIME,
            Self::Session => owners::SESSION,
            Self::Lease => owners::LEASE,
            Self::Route => owners::ROUTE,
            Self::UserBroker => owners::USER_BROKER,
        }
    }
}

/// Live-authority invalidation owner client (cutover-gated).
///
/// Old sessions, leases, routes, broker registrations, and epochs must not
/// survive alongside a cutover, but invalidating live authority during
/// isolated rehearsal would be destructive: without a validated cutover
/// receipt this client refuses with `CutoverNotAuthorized`. With one, the
/// effect still requires the #962 wire channel and refuses with the exact
/// missing capability. Either way no live state is touched here.
pub struct InvalidationOwnerClient {
    kind: InvalidationKind,
}

impl InvalidationOwnerClient {
    /// Binds the client to one invalidation kind.
    pub fn bind(kind: InvalidationKind) -> Self {
        Self { kind }
    }

    /// Requests the invalidation. Cutover-gated, channel-absent: always
    /// refuses here, naming either the missing cutover authority or the
    /// missing wire channel.
    pub fn request(
        &self,
        cutover: Option<&eliot_backup::CutoverReceipt>,
    ) -> Result<(), BackupError> {
        match cutover {
            None => Err(BackupError::CutoverNotAuthorized),
            Some(_) => Err(BackupError::RestoreCapabilityUnsupported {
                capability: self.kind.owner_id(),
            }),
        }
    }
}

/// Outcome of one Kernel-executed isolated restore: the journaled receipt,
/// target-observed evidence when this process executed finalize (or the
/// resumed run's evidence file re-validated), suspended work, the exact
/// applied phase log, and the observed paths. No cutover, activation, or
/// retirement is performed or reported.
#[derive(Clone, Debug, PartialEq)]
pub struct KernelRestoreOutcome {
    /// Journaled terminal receipt from the single phase engine.
    pub receipt: RestoreReceipt,
    /// Finalize evidence observed by this process, if it executed finalize.
    pub evidence: Option<RestoreEvidence>,
    /// Suspended ORS recovery entries derived from the archive snapshot.
    pub suspended_entries: Vec<RestoreHistoricalAuthority>,
    /// Exact applied phase log (phase names in execution order).
    pub phase_log: Vec<String>,
    /// Constructed isolated destination root.
    pub destination_root: PathBuf,
    /// Admitted journal owner binding behind this restore.
    pub journal_owner: String,
    /// Whether this run executed as rehearsal (never activates or retires).
    pub rehearsal: bool,
}

/// Cutover qualification report: validation only, never a receipt.
///
/// Returned when every checkable gate holds. Minting the cutover receipt
/// belongs to #961 through the accepted `authorize_cutover`; this report
/// carries no authority and performs no activation, retirement, route, or
/// live-authority mutation.
#[derive(Clone, Debug, PartialEq)]
pub struct CutoverQualification {
    /// Plan id qualified.
    pub plan_id: String,
    /// Isolated target id qualified.
    pub target_id: String,
    /// Isolated destination root qualified.
    pub destination_root: PathBuf,
    /// Owner obligations checked (always the full 13-slot denominator).
    pub obligations_checked: u32,
    /// Lineage id of the owner-issued new Authority Epoch that authorized this
    /// qualification.
    ///
    /// This value is reported only after the accepted
    /// [`RestoreOwnerEpoch`](eliot_backup::RestoreOwnerEpoch) was present and
    /// validated against the exact authority the restore actually ran under,
    /// and after its superseding set accounted for every observed lineage
    /// limit. An absent owner epoch refuses rather than qualifying, so this
    /// field can never report a caller-proposed epoch as owner authority.
    pub owner_epoch_lineage: String,
}

/// Kernel-owned production restore adapter.
///
/// Owns the constructed (not accepted) isolated destination and binds one
/// archive, one plan context, the Kernel's current effect fence, key
/// material, and the destination blob scope per call. The durable journal
/// is injected per call as `J: RestoreJournalPort` — never constructed,
/// defaulted, or substituted here. The adapter never mints epochs, never
/// activates authority, and never performs cutover. Re-running with the
/// same bundle and target context resumes the same transaction from the
/// injected durable journal instead of re-applying.
pub struct KernelBackupRestore {
    work_root: PathBuf,
}

impl KernelBackupRestore {
    /// Binds the restore owner to the Kernel work root that constructed
    /// isolated destinations must live under.
    ///
    /// There is deliberately no journal-carrying constructor: the durable
    /// journal arrives per execution from production composition, so a
    /// second writer path cannot exist even as an option.
    pub fn bind(work_root: PathBuf) -> Self {
        Self { work_root }
    }

    /// Returns the bound work root.
    #[must_use]
    pub fn work_root(&self) -> &std::path::Path {
        &self.work_root
    }

    /// Issues the owner-issued journal admission for `plan` from the durable
    /// owner (issue #962).
    ///
    /// This is the production entry to
    /// [`RestoreJournalAdmission::issue_for_operation`]. The owner is
    /// [`OrsRestoreJournalOwner`], built from the same composition-owned
    /// [`RedbRecoveryStore`] handle, the same [`OrsRestoreBinding`] and the same
    /// live effect fence
    /// [`restore_with_ors_journal`](Self::restore_with_ors_journal) seals the
    /// journal's rows with, and the journal it proves is the same durable ORS
    /// journal.
    ///
    /// `identity` is a caller-supplied argument, and that is stated rather than
    /// hidden: it names the source archive, class, destination and writer the
    /// caller is restoring against. It is NOT free text in the way a request
    /// field is — every one of those four is re-compared here and at every
    /// journal read against the archive, the target and the admitted owner by
    /// [`check_ors_journal_binding`], and its `installation_ref` is not settable
    /// at all: [`OrsRestoreBinding::from_composition`] reads it from the live
    /// composition cell and the two ORS constructors re-compare it, so no
    /// caller names an installation. The owner-issued references themselves are
    /// read out of the ORS stream-binding row the owner already committed, plus
    /// the two composition facts the record's own doc names, and
    /// `fixture_proof_only` is never set.
    ///
    /// The admission is issued against a durable journal that holds `plan`'s
    /// transaction, because an admission admits an existing durable journal and
    /// existence and shape prove nothing. That journal row has to EXIST before
    /// admission, and the only producer of it was the engine's own genesis
    /// compare-and-swap — which runs after admission. The circle is broken by
    /// the owner, not by this file:
    /// [`eliot_backup::RestoreJournalAdmissionOwner::issue_journal_stream`]
    /// establishes the stream and publishes the identity it filed it under, so
    /// a FIRST run is admitted and not only a resume.
    ///
    /// This file derives nothing and cannot: the stream key is
    /// `sha256(plan_id, bundle_sha256)`, computed inside `eliot-backup` where
    /// the plan lives, and the Kernel asks the owner for the key rather than
    /// reconstructing it — a key the owner did not issue is not the owner's key.
    /// What the owner establishes is exactly the row the engine would have
    /// written as its own first act (same transaction, revision 0, phase
    /// `Pending`, state `Ready`, no intent, no receipt, no effect), committed
    /// through the same accepted `RestoreJournalPort` seam over the same ORS
    /// store, the same [`OrsRestoreBinding`] and the same live fence this
    /// execution uses. The engine reads that row on its way in and continues
    /// from it. No target effect occurs here, and the durable row the admission
    /// is proved against is still the row the owner wrote and still has to
    /// survive a fresh read. A stream already holding this transaction is left
    /// exactly as it stands, so a second run binds once and not twice; a stream
    /// already holding another one is refused rather than adopted.
    ///
    /// The two journal facts the admission carries keep one meaning each:
    /// `journal_identity_ref` is the durable CHANNEL
    /// ([`RESTORE_JOURNAL_IDENTITY`], checked by
    /// [`check_ors_journal_binding`]), and this plan's own STREAM is proved by
    /// the issuer reading the live journal under it.
    ///
    /// The returned value grants no cutover, no readiness and no activation
    /// (A13.7: cutover requires separate authority).
    ///
    /// # Errors
    ///
    /// Refuses typed when the stream cannot be established or already exists for
    /// another transaction ([`KernelRestoreError::TargetFailed`] carrying the
    /// journal error), when the owner holds no durable record for the stream it
    /// issued ([`KernelRestoreError::TargetFailed`] carrying
    /// [`BackupError::RestoreJournalRequired`]), when the durable record
    /// disagrees with live composition
    /// ([`KernelRestoreError::JournalBindingConflict`]), or when the binding's
    /// installation identity is not the live composition-owned one
    /// ([`KernelRestoreError::OwnerEvidenceInvalid`]).
    pub fn admit_restore_journal(
        &self,
        ors: &std::sync::Arc<RedbRecoveryStore>,
        plan: &RestorePlan,
        kernel_fence: &StateFence,
        identity: &OrsRestoreBinding,
    ) -> Result<RestoreJournalAdmission, KernelRestoreError> {
        let owner = OrsRestoreJournalOwner::production(
            std::sync::Arc::clone(ors),
            identity.clone(),
            kernel_fence,
        )?;
        let mut journal = OrsRestoreJournal::production(
            std::sync::Arc::clone(ors),
            kernel_fence,
            identity.clone(),
            self.work_root
                .join(".eliot")
                .join(RESTORE_JOURNAL_PAYLOAD_AREA),
        )?;
        RestoreJournalAdmission::issue_for_operation(&owner, &mut journal, plan)
            .map_err(backup_to_kernel)
    }

    /// Production execution path (issue #960): runs the restore with the
    /// composition-owned durable ORS journal as its
    /// [`RestoreJournalPort`](eliot_backup::RestoreJournalPort).
    ///
    /// This is the call the composition makes, so the journal a production
    /// restore runs on is derived here from the owner handle and the Kernel's
    /// own live effect fence, not chosen by the caller. The writer fence the
    /// ORS owner binds for every row is the same `ports.kernel_fence` that
    /// [`check_kernel_effect_fence`] already admitted, so the journal can
    /// never name a different writer authority than the effect gate accepted,
    /// and no epoch or generation is minted here.
    ///
    /// The journal admission is **not** taken from `ports`. It is issued here
    /// by [`admit_restore_journal`](Self::admit_restore_journal) from the
    /// durable owner, and the execution body runs against that issued value, so
    /// a caller-presented admission cannot select the database, the
    /// installation, the generation, the journal identity or the receipt of
    /// this restore. `ports` still supplies the effect fence, key material,
    /// blob scope, destination evidence and the rehearsal flag; only the
    /// admission is replaced, and only by a stronger, owner-issued one.
    ///
    /// [`restore`](Self::restore) stays available with its injected `J` seam
    /// unchanged: this method is an additional production entry over the same
    /// single phase engine, not a second engine and not a fallback.
    ///
    /// The same `ors` handle is also the purge phase's owner route: it applies
    /// the archive's purge ledger through
    /// [`RedbRecoveryStore::apply_purge_ledger_entry`], so the purge-ledger
    /// revisions the purge phase consumes are the ones the one owner that
    /// writes them issued, and those owner-issued revisions are bound into
    /// this phase's evidence digest rather than recomputed here. The ledger is
    /// applied before any import.
    ///
    /// Precisely, and to avoid a claim this module cannot support: the
    /// published evidence field
    /// `provenance.purge_ledger_revision` is set from
    /// `bundle.manifest.purge_ledger_revision` — the ARCHIVE's own declared
    /// revision, not the value the owner returned during the purge phase — and
    /// `eliot_backup` REQUIRES that published field to equal the archive's
    /// declared revision. Publishing the owner's value instead is therefore not
    /// available, so the two readings of that one quantity are CROSS-CHECKED
    /// instead: [`check_purge_revision_closure`] runs inside the purge phase,
    /// after the owner issued its revisions and before the phase stages the
    /// evidence document carrying them, and refuses with the seam's
    /// [`BackupError::FenceMismatch`] naming `purge ledger revision` when they
    /// disagree, when the owner issued no revision for a carried entry, or when
    /// the owner issued the zero that means "nothing was ever applied". A
    /// published purge revision is therefore never a number copied out of the
    /// archive under check and left unverified: the archive's declaration and
    /// the owner's answer must agree before any import, and neither value is
    /// computed here.
    ///
    /// What the cross-check does NOT cover, stated rather than implied: only the
    /// per-entry completeness of a carried ledger. An archive that carries no
    /// purge entry has no owner-issued per-entry revision to compare, but its
    /// DECLARED revision is still reconciled against the owner's own counter —
    /// including the case where the owner answered nothing, which refuses — so
    /// the empty ledger cannot pass as a closure this phase never established.
    /// For that archive the finalize evidence reports the purge obligation as
    /// not established rather than `Satisfied`. A resumed transaction that
    /// reconciles the purge phase from its journaled receipt does not re-apply
    /// the ledger either, so the check is a property of the phase execution
    /// that applied the entries, and that phase's receipt is what a non-empty
    /// purge obligation binds.
    pub fn restore_with_ors_journal(
        &self,
        ors: &std::sync::Arc<RedbRecoveryStore>,
        bundle: &BackupBundle,
        target: RestoreContext,
        ports: &RestorePorts<'_>,
        identity: &OrsRestoreBinding,
    ) -> Result<KernelRestoreOutcome, KernelRestoreError> {
        check_ors_journal_budget(bundle)?;
        // Compiling the plan is pure and effect-free; the execution body
        // compiles the same plan again to build its target. The coordinator
        // needs the plan here because the admission is bound to the plan's own
        // operation and the plan is never a parameter of the issuer.
        let plan = Self::compile_plan(bundle, target.clone())?;
        let admission = self.admit_restore_journal(ors, &plan, ports.kernel_fence, identity)?;
        let admitted = admitted_restore_ports(ports, &admission);
        check_ors_journal_binding(bundle, &target, &admitted, identity)?;
        let mut journal = OrsRestoreJournal::production(
            std::sync::Arc::clone(ors),
            ports.kernel_fence,
            identity.clone(),
            self.work_root
                .join(".eliot")
                .join(RESTORE_JOURNAL_PAYLOAD_AREA),
        )?;
        self.restore_with_owner(bundle, target, &admitted, &mut journal, Some(ors))
    }

    /// Compiles the governed plan for one archive and target context.
    ///
    /// Runs the accepted [`RestorePlan::compile`](eliot_backup::RestorePlan::compile)
    /// validation (bundle, checksums, schema, purge binding, class
    /// denominator, lineage advance) with no effects, for composition
    /// diagnostics before execution.
    pub fn compile_plan(
        bundle: &BackupBundle,
        target: RestoreContext,
    ) -> Result<RestorePlan, KernelRestoreError> {
        bundle
            .validate()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        RestorePlan::compile(bundle, target)
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))
    }

    /// Publishes the admitted archive's retained canonical payloads into one
    /// admitted restore batch (issue #952, audit `5869992012`).
    ///
    /// The #950 restore carrier names identities, digests and residency
    /// metadata in [`CanonicalRestoreBatch::members`] and that is all it can
    /// carry: a member's `content_digest` names content, it does not hold it.
    /// So a batch assembled without this step reaches the destination port
    /// unable to say WHAT it restores, and the port refuses every one of its
    /// members typed rather than importing anything. This is the join the audit
    /// asked for — resolve the admitted archive/member-set reference through
    /// the archive owner and publish the canonical logical payloads — done
    /// where the bytes actually are, in the owner that holds them.
    ///
    /// Everything published is read out of `bundle`, never derived from the
    /// batch and never re-encoded from a re-encoding:
    ///
    /// - `class` is the archive's own label for the record
    ///   (`CanonicalRecord::record_type`, or the backup owner's own
    ///   `WRITE_RECEIPT_RECORD_TYPE` for a receipt). No class is mapped onto
    ///   another and none is invented; a class the destination does not own is
    ///   refused there against the class it does not recognise.
    /// - `payload` is the record's canonical JSON encoding as the archive holds
    ///   it, and `byte_count` is that text's own length. The admitted member's
    ///   own `residency.byte_count` must therefore already be the length of that
    ///   canonical text: the destination port compares the two independently,
    ///   and a member that declares a different length is refused here first
    ///   rather than reaching the port as a payload whose size disagrees with
    ///   the member it answers for.
    /// - `payload_digest` is the archive's OWN recorded commitment for those
    ///   bytes (`CanonicalRecord::sha256`, proved against the record's payload
    ///   by the existing [`CanonicalRecord::validate`]; for a receipt, which
    ///   carries no per-record checksum, the single attestation this owner
    ///   makes over exactly the bytes it publishes). The destination port
    ///   validates that recorded value against the bytes it actually received
    ///   and never substitutes a checksum of its own for it.
    /// - `record_id` is the member's own domain-qualified logical identity
    ///   (`SnapshotMember::logical_identity`), so the same admitted member
    ///   always lands at the same destination address and equal bytes under a
    ///   different residency domain never coalesce into one record.
    ///
    /// Completeness is measured against the ARCHIVE, which is the independent
    /// expected set: the admitted member list is counted first, each admitted
    /// canonical member must then consume exactly one archive member under the
    /// archive's own recorded commitment, and the published count must equal
    /// that first count. The comparison is never made against the vector this
    /// call is building, so a member with no archive backing and a published
    /// entry with no admitted member are two distinct refusals instead of one
    /// self-consistent partial result.
    ///
    /// Structural admission is deliberately not repeated here.
    /// [`CanonicalRestoreBatch::validate`] is the destination's own shape and
    /// admission check and it cannot construct content, so source resolution
    /// and destination execution admission stay separate steps; what is
    /// re-proved here is only the archive (whole-bundle integrity, section
    /// checksums and class denominator) and the three member facts the
    /// publication depends on — member type, the member's own declared byte
    /// count, and the archive's commitment to the member's content.
    ///
    /// Only a canonical `Record` member is a canonical-store payload. A
    /// `Reference` edge names a canonical object and is not one, and a sealed
    /// blob travels the blob owner's route; both retain nothing here, and the
    /// destination port refuses them typed rather than receiving a payload
    /// under a class this owner does not own.
    ///
    /// Create-only: a batch that already carries retained payloads is refused
    /// rather than merged, so a second publication can never quietly widen or
    /// replace the content a batch was admitted with. Idempotent replay is the
    /// destination's own readback of the row this content produced, not a
    /// second write here.
    ///
    /// # Errors
    ///
    /// Refuses typed, before any destination effect, when the archive does not
    /// validate ([`KernelRestoreError::ArchiveInvalid`]), when the batch
    /// already carries retained payloads, when an admitted canonical member is
    /// not attested by the archive, when an admitted member declares a byte
    /// count the archive does not hold, or when the published set does not
    /// cover the admitted member set
    /// ([`KernelRestoreError::InvalidInput`]).
    pub fn publish_retained_archive_members(
        &self,
        bundle: &BackupBundle,
        batch: &mut CanonicalRestoreBatch,
    ) -> Result<(), KernelRestoreError> {
        // The whole archive is re-proven first, so no member of a partially
        // valid archive can become a retained payload.
        bundle
            .validate()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        if !batch.retained_members.is_empty() {
            return Err(KernelRestoreError::InvalidInput {
                field: "restore.retained_members",
                reason: "batch already carries published retained archive payloads",
            });
        }
        // Independent expected set: the ARCHIVE's restore-class member
        // denominator, counted from the admitted member list BEFORE a single
        // payload is resolved, so completeness can never be measured against
        // the list this call is about to build.
        let admitted = batch
            .members
            .iter()
            .filter(|member| member.member_type == SnapshotMemberType::Record)
            .count();
        let mut index = RetainedArchiveIndex::read(bundle)
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        let mut published: Vec<RetainedArchiveMember> = Vec::with_capacity(admitted);
        for member in &batch.members {
            if member.member_type != SnapshotMemberType::Record {
                continue;
            }
            let Some(payload) = index.take(&member.content_digest) else {
                return Err(KernelRestoreError::InvalidInput {
                    field: "restore.members",
                    reason: "admitted member is not attested by the admitted archive",
                });
            };
            // The member's own declared residency length is an independent
            // expected value for the archive's bytes, so a member that declares
            // a length the archive does not hold is refused here rather than
            // handed to the destination as a payload whose size disagrees with
            // the member it answers for.
            let byte_count = member.residency.byte_count;
            if byte_count == 0 || usize::try_from(byte_count).ok() != Some(payload.payload.len()) {
                return Err(KernelRestoreError::InvalidInput {
                    field: "restore.members",
                    reason: "admitted member declares a byte count the archive does not hold",
                });
            }
            published.push(RetainedArchiveMember {
                member_id: member.member_id.clone(),
                class: payload.class,
                record_id: member.logical_identity(),
                payload_digest: payload.payload_digest,
                byte_count,
                payload: payload.payload,
            });
        }
        if published.len() != admitted {
            return Err(KernelRestoreError::InvalidInput {
                field: "restore.retained_members",
                reason: "published retained payloads do not cover the admitted member set",
            });
        }
        batch.retained_members = published;
        Ok(())
    }

    /// Executes (or resumes) one isolated restore under the Kernel effect fence.
    ///
    /// `ports` carries the admitted journal description, the Kernel's
    /// current authority fence (never caller arithmetic inside this
    /// adapter), key material, blob scope, and destination manifest
    /// evidence; `journal` is the injected durable journal. The archive
    /// fence must be compatible with the live fence before any effect,
    /// otherwise the restore is refused with zero target effects.
    /// Blob-carrying archives require exact key coverage plus the
    /// destination blob scope; a fixture-flagged or unadmitted journal
    /// refuses as not admitted for production (rehearsal admits
    /// fixture-flagged journals for mapping proof only). Coordinator
    /// failures propagate typed in
    /// [`KernelRestoreError::TargetFailed`]; the primary error is preserved,
    /// never flattened into a fabricated success. Rehearsal never
    /// activates, retires, cuts over, or unblocks effects: no such code
    /// path exists here.
    ///
    /// Every staged write is admitted against the archive-derived
    /// [`StagedOutputBudget`] BEFORE it happens, so an archive that cannot
    /// fit the budget is refused rather than written past it. When the
    /// journaled engine fails, the output this execution staged is removed by
    /// a bounded, ownership-scoped cleanup (see
    /// [`KernelRestoreTarget::cleanup_staged_output`]) and the typed cleanup
    /// disposition is carried by the SAME primary failure: the cause is never
    /// replaced, and a resume, a foreign admission, a destination that left
    /// the isolated area, and every path this execution did not write are
    /// preserved rather than removed.
    ///
    /// This entry holds no ORS owner handle, so it runs the same engine with
    /// the purge-ledger owner route absent. An archive that carries purge
    /// entries then refuses in the purge phase with
    /// [`BackupError::RestoreCapabilityUnsupported`] naming
    /// `owners::PURGE_LEDGER_OWNER` — see
    /// [`KernelRestoreTarget::apply_purge_ledger`] — instead of staging a
    /// ledger whose revision no owner ever issued.
    ///
    /// The owner route is LIVE: [`restore_with_ors_journal`](Self::restore_with_ors_journal)
    /// supplies the composition-owned ORS handle, and
    /// `KernelComposition::backup_restore_with_ors_journal` (`lib.rs`) is its
    /// production entry. That composition entry is reached on the registered
    /// production front door —
    /// `KernelComposition::dispatch_frame` →
    /// `frame_dispatch::dispatch_frame_inner`'s `is_backup_operation` arm →
    /// `request_dispatch::dispatch_backup_frame` →
    /// `request_dispatch::handle_backup_restore_test` — which obtains the
    /// owner-issued admission through
    /// [`admit_restore_journal`](Self::admit_restore_journal) and then calls
    /// that composition entry. The purge phase's owner route is therefore
    /// reachable at runtime today, not merely intended.
    ///
    /// What has no production caller is THIS entry, and the reason is its
    /// signature rather than a missing wiring: `restore` takes an injected
    /// `J: RestoreJournalPort` and passes no `ors` handle down, so it runs the
    /// same engine with the purge-ledger owner route absent. Production runs
    /// the `restore_with_ors_journal` sibling and reaches this same private
    /// `restore_with_owner` body with the composition-owned ORS
    /// handle; there is one engine and one phase order, not a fallback. A
    /// caller of this entry that DID supply a purge ledger would still be
    /// refused in the purge phase by
    /// [`KernelRestoreTarget::apply_purge_ledger`] with
    /// [`BackupError::RestoreCapabilityUnsupported`] naming
    /// `owners::PURGE_LEDGER_OWNER`, so the absent handle cannot silently
    /// degrade a restore — the refusal is enforced at the phase, not here,
    /// precisely so that the two entries do not diverge.
    pub fn restore<J: RestoreJournalPort>(
        &self,
        bundle: &BackupBundle,
        target: RestoreContext,
        ports: &RestorePorts<'_>,
        journal: &mut J,
    ) -> Result<KernelRestoreOutcome, KernelRestoreError> {
        self.restore_with_owner(bundle, target, ports, journal, None)
    }

    /// The single execution body, with the purge ledger's owner route named.
    ///
    /// `ors` is the composition-owned [`RedbRecoveryStore`] the purge phase
    /// applies the archive's purge ledger through. Both public entries reach
    /// this one body — [`restore_with_ors_journal`](Self::restore_with_ors_journal)
    /// with the same handle it admits and journals through, and
    /// [`restore`](Self::restore) with `None` — so there is no second engine,
    /// no second phase order, and no path that applies a purge ledger without
    /// the owner that issues its revision.
    #[allow(clippy::too_many_lines)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "RestoreContext is moved into compile_plan and the isolated destination; the by-value seam keeps the single audited validation gate"
    )]
    fn restore_with_owner<J: RestoreJournalPort>(
        &self,
        bundle: &BackupBundle,
        target: RestoreContext,
        ports: &RestorePorts<'_>,
        journal: &mut J,
        ors: Option<&std::sync::Arc<RedbRecoveryStore>>,
    ) -> Result<KernelRestoreOutcome, KernelRestoreError> {
        bundle
            .validate()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        ports.validate()?;
        if ports.rehearsal {
            ports
                .journal_admission
                .validate()
                .map_err(|error| KernelRestoreError::OwnerEvidenceInvalid(error.to_string()))?;
        } else {
            require_production_admitted(ports.journal_admission)?;
        }
        check_kernel_effect_fence(ports.kernel_fence, bundle)
            .map_err(|error| KernelRestoreError::FenceMismatch(error.to_string()))?;
        if let Some(manifest) = ports.keys {
            verify_portable_key_material(bundle, manifest)
                .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        } else if !bundle.blobs.is_empty() {
            return Err(KernelRestoreError::CapabilityMissing {
                capability: "blob_key_material",
            });
        }
        if !bundle.blobs.is_empty() && ports.blob_scope.is_none() {
            return Err(KernelRestoreError::CapabilityMissing {
                capability: owners::BLOB_SCOPE_BINDING,
            });
        }
        if let Some(evidence) = ports.manifest_evidence.as_ref() {
            evidence.validate()?;
            let own_root = std::fs::canonicalize(&self.work_root)
                .map_err(|error| KernelRestoreError::DestinationInvalid(error.to_string()))?;
            let admitted_root = std::fs::canonicalize(&evidence.kernel_work_root)
                .map_err(|error| KernelRestoreError::DestinationInvalid(error.to_string()))?;
            if own_root != admitted_root {
                return Err(KernelRestoreError::DestinationInvalid(
                    "admitted work root does not match the Kernel work root".to_owned(),
                ));
            }
            if let Some(config) = bundle
                .artifacts
                .iter()
                .find(|artifact| artifact.kind == "config")
                && config.sha256 != evidence.manifest_digest
            {
                return Err(KernelRestoreError::FenceMismatch(
                    "destination manifest".to_owned(),
                ));
            }
        }
        let plan = Self::compile_plan(bundle, target.clone())?;
        let transaction = plan
            .transaction()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        let destination = KernelIsolatedDestination::open(&self.work_root, &target.target_id)?;
        Self::refuse_foreign_destination(
            &destination,
            &transaction.transaction_id,
            &plan.target.target_id,
            ports.rehearsal,
            ports.manifest_evidence.as_ref(),
        )?;
        // Third axis, and the one the two above cannot reach: the CONSTRUCTED
        // root must still RESOLVE to `<work_root>/.eliot/restore-isolated/<label>`.
        // The label is the request's own `target_id`, so a directory already
        // carrying that name can be a reparse point, and a lexical containment
        // check passes straight through one. This is the same link-resolved
        // rule the bounded cleanup of this owner's own staging already applies.
        Self::refuse_destination_outside_isolated_area(&destination, &self.work_root)?;
        let receipts = match ports.keys {
            Some(manifest) => issue_restoration_receipts(
                bundle.manifest.backup_id.as_str(),
                manifest,
                &bundle.blobs,
            )
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?,
            None => Vec::new(),
        };
        let mut target_impl =
            KernelRestoreTarget::new(&self.work_root, &destination, bundle, ports, receipts, ors)
                .map_err(KernelRestoreError::TargetFailed)?;
        let receipt = match plan.execute_with_journal(bundle, &mut target_impl, journal) {
            Ok(receipt) => receipt,
            Err(primary) => {
                // The engine failed. The primary typed failure is what this
                // owner returns, and the bounded cleanup of the output THIS
                // execution staged is folded into it without replacing it.
                return Err(target_impl.refuse_with_staged_cleanup(
                    &destination,
                    &transaction.transaction_id,
                    &plan.target.target_id,
                    primary,
                ));
            }
        };
        receipt
            .validate()
            .map_err(KernelRestoreError::TargetFailed)?;
        // The caller's own classification is preserved: this site has always
        // reported a bad ORS suspension as `ArchiveInvalid`, so the read of the
        // archive's two mandatory fences keeps that class rather than widening
        // to the generic target failure.
        let suspended = historical_authority(bundle)
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        let evidence = target_impl
            .final_evidence
            .clone()
            .or_else(|| read_resumed_evidence(&target_impl.root));
        let admission = ports.journal_admission;
        let journal_owner = format!(
            "{}:{}:{}",
            super::backup_restore_ports::RESTORE_JOURNAL_OWNER_LABEL,
            admission.persistent_owner.owner_id,
            admission.journal_identity_ref
        );
        Ok(KernelRestoreOutcome {
            receipt,
            evidence,
            suspended_entries: suspended,
            phase_log: target_impl.calls,
            destination_root: target_impl.root,
            journal_owner,
            rehearsal: ports.rehearsal,
        })
    }

    /// Refuses a recovery import whose constructed destination root does not
    /// still resolve to `<work_root>/.eliot/restore-isolated/<label>` (issue
    /// #955, A11).
    ///
    /// A11's guarantee is "recovery import targets only the externally admitted
    /// isolated new installation", and its negative direction is that the
    /// recovery path must not be steerable at anything else. The two axes that
    /// already hold are the identity axis — [`RestorePlan::compile`] refuses
    /// `target_id == bundle.manifest.backup_id`, the ARCHIVE's own owner-issued
    /// identity — and the path axis: `KernelIsolatedDestination::open` accepts
    /// only a bounded label and CONSTRUCTS
    /// `<work_root>/.eliot/restore-isolated/<label>`, never a presented path.
    ///
    /// Neither of those is the whole answer, and the reason is exactly the
    /// reason the bounded cleanup of this owner's own staging already carries a
    /// `StagedCleanupRefusal::OutsideIsolatedArea` reason: the label is the
    /// REQUEST's own `target_id`
    /// (`restore_target_shape`, `request_dispatch.rs`), so
    /// `<work_root>/.eliot/restore-isolated/<label>` is a name a caller chooses,
    /// and on Windows a directory carrying that name can be a reparse point. A
    /// junction at the label resolves every subsequent write — canonical events,
    /// receipts, projections, blobs, the pinned admission and the final
    /// `evidence.json` — outside the isolated area and into whatever it names,
    /// while every lexical check above still passes. The import would then be
    /// steered at a store that is not the admitted isolated destination, which
    /// is the failure this refusal exists to make impossible.
    ///
    /// So the import now applies, BEFORE the first destination byte is staged,
    /// the same link-resolved containment rule the cleanup path already applies
    /// after a failure: both the isolated area and the destination root are
    /// resolved, the resolved root must be strictly inside the resolved area,
    /// and its final component must still be the admitted label. Nothing is
    /// compared against the caller's own copy of a path — the caller supplies a
    /// label, and what is proved is the resolved topology of the root this owner
    /// constructed.
    ///
    /// An absent or unresolvable root is a typed destination failure, never a
    /// silent pass: the destination was constructed by this owner moments
    /// earlier, so a root that cannot be resolved is a broken or replaced
    /// contour, not a reason to import into an unproved location.
    ///
    /// # Errors
    ///
    /// Returns [`KernelRestoreError::DestinationNotAdmitted`] when the resolved
    /// destination root is the isolated area itself, lies outside it, or no
    /// longer ends in the admitted label; and
    /// [`KernelRestoreError::DestinationInvalid`] when the isolated area or the
    /// destination root cannot be resolved at all.
    fn refuse_destination_outside_isolated_area(
        destination: &KernelIsolatedDestination,
        work_root: &Path,
    ) -> Result<(), KernelRestoreError> {
        let area = work_root.join(".eliot").join(RESTORE_ISOLATED_AREA);
        let resolved_area = std::fs::canonicalize(&area).map_err(|error| {
            KernelRestoreError::DestinationInvalid(format!(
                "isolated restore area could not be resolved: {error}"
            ))
        })?;
        let resolved_root = std::fs::canonicalize(destination.root()).map_err(|error| {
            KernelRestoreError::DestinationInvalid(format!(
                "isolated destination root could not be resolved: {error}"
            ))
        })?;
        let admitted_label = destination.label();
        if resolved_root == resolved_area
            || !resolved_root.starts_with(&resolved_area)
            || resolved_root.file_name().and_then(|name| name.to_str()) != Some(admitted_label)
        {
            return Err(KernelRestoreError::DestinationNotAdmitted);
        }
        Ok(())
    }

    /// Refuses a destination pinned to a different transaction, target,
    /// rehearsal posture, or manifest evidence, and corrupt pinned
    /// admissions.
    ///
    /// A pinned admission for the exact current transaction, target, posture
    /// and evidence resumes; anything else pinned refuses as foreign or
    /// drifted instead of continuing the old transaction under new authority.
    /// The rehearsal posture is part of that identity because it is what
    /// decides whether the destination may ever be qualified for cutover: a
    /// rehearsal-prepared root is never continued by a production run, and a
    /// production-prepared root is never downgraded to a rehearsal. An
    /// unpinned destination proceeds past THIS check when it is fresh or a
    /// pre-prepare crash whose byte staging the engine re-applies idempotently;
    /// that this root resolves to the admitted isolated location at all is
    /// decided separately, against the resolved filesystem topology, by
    /// [`Self::refuse_destination_outside_isolated_area`].
    fn refuse_foreign_destination(
        destination: &KernelIsolatedDestination,
        transaction_id: &str,
        target_id: &str,
        rehearsal: bool,
        expected: Option<&DestinationManifestEvidence>,
    ) -> Result<(), KernelRestoreError> {
        let path = destination.root().join(DESTINATION_ADMISSION_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(KernelRestoreError::DestinationInvalid(error.to_string()));
            }
        };
        let pinned: PinnedDestinationAdmission =
            serde_json::from_slice(&bytes).map_err(|_| KernelRestoreError::JournalCorrupt)?;
        if pinned.transaction_id != transaction_id || pinned.target_id != target_id {
            return Err(KernelRestoreError::JournalBindingConflict);
        }
        if pinned.rehearsal != rehearsal {
            return Err(KernelRestoreError::FenceMismatch(
                "destination rehearsal posture".to_owned(),
            ));
        }
        match (expected, Some(&pinned.evidence)) {
            (Some(want), Some(have)) if want != have => Err(KernelRestoreError::FenceMismatch(
                "destination admission".to_owned(),
            )),
            (None, Some(_)) => Err(KernelRestoreError::FenceMismatch(
                "destination admission".to_owned(),
            )),
            _ => Ok(()),
        }
    }

    /// Validates the #961 cutover path for one completed isolated restore:
    /// owner-approved isolated destination, separate cutover authority,
    /// epoch lineage strictly newer than every observed value, and a
    /// complete validation denominator in the observed evidence.
    ///
    /// Consumes only authenticated evidence: the accepted owner
    /// authorization (bound to this exact plan and bundle), the completed
    /// restore receipt (bound to this exact plan, bundle, and target), the
    /// observed restore evidence (validated, plan-bound, and obligation
    /// complete — any applicable unresolved effect, missing receipt, or
    /// unknown reconciliation without its complete current denominator
    /// refuses cutover qualification; suspension is not resolution), the
    /// pinned destination admission (owner-approved manifest evidence bound
    /// at prepare — absent without Host admission, and qualification refuses
    /// without it), and the freshly re-validated restored fence (lineage
    /// advance re-proven here with no caller arithmetic on epochs).
    ///
    /// Two further requirements are hard refusals, not warnings. The
    /// owner-issued new Authority Epoch is REQUIRED (see
    /// [`require_qualified_owner_epoch`]) and must be the authority this
    /// restore ran under, with a superseding set that accounts for every
    /// lineage limit the restore observed; and the owner-issued operational
    /// validation for the exact isolated root is REQUIRED (see
    /// [`require_operational_validation`]). Absent either, a safe partial
    /// isolated import stays explicitly partial and never reads as operationally
    /// ready. The owner-issued values are consumed through their accepted
    /// owner validation — never minted, never recomputed here.
    ///
    /// A rehearsal is refused outright, read from the durable rehearsal
    /// posture its own destination pinned at prepare. That is why a rehearsal
    /// cannot qualify even with a full Host admission, an owner-issued epoch,
    /// and a separate Human/System Owner authorization: it activates nothing,
    /// cuts over nothing, and retires nothing, and this method says so instead
    /// of relying on a caller to remember.
    ///
    /// Returns a qualification report only; no receipt is minted here.
    /// Minting through the accepted `authorize_cutover` belongs to #961.
    /// This path performs NO activation, retirement, route/process mutation,
    /// or live-authority invalidation.
    pub fn qualify_cutover(
        &self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        receipt: &RestoreReceipt,
        evidence: Option<&RestoreEvidence>,
        destination: &KernelIsolatedDestination,
        auth: Option<&CutoverAuthorization>,
    ) -> Result<CutoverQualification, KernelRestoreError> {
        let auth = auth.ok_or(KernelRestoreError::CutoverNotAuthorized)?;
        auth.validate()
            .map_err(|error| KernelRestoreError::OwnerEvidenceInvalid(error.to_string()))?;
        if auth.plan_id != plan.plan_id || auth.bundle_sha256 != plan.bundle_sha256 {
            return Err(KernelRestoreError::ArchiveInvalid(
                "cutover authorization does not bind this plan and bundle".to_owned(),
            ));
        }
        if receipt.plan_id != plan.plan_id
            || receipt.bundle_sha256 != plan.bundle_sha256
            || receipt.target_id != plan.target.target_id
        {
            return Err(KernelRestoreError::ArchiveInvalid(
                "restore receipt does not bind this plan and target".to_owned(),
            ));
        }
        if receipt.cutover_performed || receipt.operational_recovery_ready {
            return Err(KernelRestoreError::OwnerEvidenceInvalid(
                "isolated restore receipt must not assert cutover or readiness".to_owned(),
            ));
        }
        let evidence = evidence.ok_or(KernelRestoreError::OwnerEvidenceInvalid(
            "no observed restore evidence".to_owned(),
        ))?;
        evidence
            .validate()
            .map_err(KernelRestoreError::TargetFailed)?;
        evidence
            .validate_against_plan(plan, bundle)
            .map_err(KernelRestoreError::TargetFailed)?;
        require_cutover_obligations(&evidence.obligations, bundle)
            .map_err(KernelRestoreError::TargetFailed)?;
        let owner_epoch = require_qualified_owner_epoch(evidence)?;
        require_operational_validation(evidence)?;
        if destination.label() != plan.target.target_id
            || !destination.root().starts_with(&self.work_root)
        {
            return Err(KernelRestoreError::DestinationInvalid(
                "cutover destination is not the plan-admitted isolated root".to_owned(),
            ));
        }
        let admission_bytes = std::fs::read(destination.root().join(DESTINATION_ADMISSION_FILE))
            .map_err(|_| {
                KernelRestoreError::DestinationInvalid(
                    "no owner-approved destination admission pinned".to_owned(),
                )
            })?;
        let pinned: PinnedDestinationAdmission = serde_json::from_slice(&admission_bytes)
            .map_err(|_| KernelRestoreError::JournalCorrupt)?;
        let transaction = plan
            .transaction()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        if pinned.transaction_id != transaction.transaction_id
            || pinned.target_id != plan.target.target_id
        {
            return Err(KernelRestoreError::JournalBindingConflict);
        }
        // A rehearsal is an isolated-import proof only. The destination it
        // prepared carries that posture in durable owner state, so the
        // rehearsal path can never reach this qualification even when it ran
        // under a full Host admission, an owner-issued new epoch, and a
        // separate Human/System Owner authorization. A rehearsal never
        // activates, cuts over, or retires a source installation; it is
        // refused here, and the refusal is stated rather than inferred.
        if pinned.rehearsal {
            return Err(KernelRestoreError::CutoverNotAuthorized);
        }
        plan.restored_fence
            .validate()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        Ok(CutoverQualification {
            plan_id: plan.plan_id.clone(),
            target_id: plan.target.target_id.clone(),
            destination_root: destination.root().to_path_buf(),
            obligations_checked: 13,
            owner_epoch_lineage: owner_epoch.new_epoch.lineage_id.as_str().to_owned(),
        })
    }
}

/// Requires the owner-issued new Authority Epoch that authorizes cutover, and
/// binds it to the exact authority this restore actually ran under (issue #960,
/// W10/A16).
///
/// Three independent refusals, each a presented-vs-owner comparison:
///
/// 1. **Presence.** The accepted contract holds that "a caller-proposed target
///    epoch is planning input, not accepted authority; only this owner-issued
///    value may support cutover". An evidence without an
///    [`RestoreOwnerEpoch`](eliot_backup::RestoreOwnerEpoch) therefore carries
///    only a proposal, and an absent owner epoch refuses. A rehearsal never
///    has one, so this is also the refusal that keeps a rehearsal from
///    qualifying on any other admission.
/// 2. **Binding.** The owner-issued new epoch/generation must be the authority
///    the restore ran under. `validate_against_plan` already bound
///    `evidence.authority_epoch` / `evidence.resource_generation` to the
///    plan's restored fence, so comparing the owner-issued value against them
///    refuses an owner epoch issued for a different authority than the one
///    this restore actually obtained — a stale-authority restore presenting a
///    current-looking owner receipt.
/// 3. **Closure.** The owner-issued superseding set is compared against the
///    lineage limits this restore INDEPENDENTLY observed in the archive
///    (`evidence.observed_lineage_limits`), not against a copy of the owner's
///    own list. A limit the restore observed and the owner did not supersede
///    is an open lineage, so it refuses. The comparison is by owner identity
///    because that is what makes one limit account for another; the values
///    themselves are validated by the accepted `RestoreOwnerEpoch::validate`
///    against the recorded lineage, never recomputed here.
fn require_qualified_owner_epoch(
    evidence: &RestoreEvidence,
) -> Result<&eliot_backup::RestoreOwnerEpoch, KernelRestoreError> {
    let Some(owner_epoch) = evidence.owner_epoch.as_ref() else {
        return Err(KernelRestoreError::TargetFailed(
            BackupError::RestoreEvidenceIncomplete,
        ));
    };
    owner_epoch
        .validate()
        .map_err(KernelRestoreError::TargetFailed)?;
    if owner_epoch.new_epoch != evidence.authority_epoch
        || owner_epoch.new_generation != evidence.resource_generation
    {
        return Err(KernelRestoreError::TargetFailed(
            BackupError::StaleRestoreLineage,
        ));
    }
    for limit in &evidence.observed_lineage_limits {
        if !owner_epoch
            .supersedes
            .iter()
            .any(|superseded| superseded.owner_id == limit.owner_id)
        {
            return Err(KernelRestoreError::TargetFailed(
                BackupError::RestoreEvidenceIncomplete,
            ));
        }
    }
    Ok(owner_epoch)
}

/// Requires the owner-issued operational validation that authorizes
/// operational readiness for the exact isolated root (issue #960, W10).
///
/// The accepted contract holds that "transport acknowledgement, content
/// equality, checksum validity, a phase count, or a self-asserted
/// `active_authority_restored = false` is insufficient operational proof. Only
/// the exact owner named in `owner` may issue this evidence, and only for the
/// exact isolated destination named in `target_ref`." Without that value the
/// isolated import is at best safe and partial, so operational-readiness and
/// cutover qualification refuse. Nothing here re-derives, recomputes or
/// manufactures the evidence: presence plus the accepted
/// [`OperationalValidationEvidence`](eliot_backup::OperationalValidationEvidence)
/// `validate` (already run inside [`RestoreEvidence::validate`], which also
/// binds `target_ref` to the evidence target) is the whole check, and the
/// obligation denominator above has already refused every applicable
/// unresolved effect, absent owner channel and incomplete closure that would
/// otherwise let a partial import read as ready.
fn require_operational_validation(evidence: &RestoreEvidence) -> Result<(), KernelRestoreError> {
    let Some(operational) = evidence.operational_validation.as_ref() else {
        return Err(KernelRestoreError::TargetFailed(
            BackupError::RestoreEvidenceIncomplete,
        ));
    };
    operational
        .validate()
        .map_err(KernelRestoreError::TargetFailed)?;
    Ok(())
}

/// Reads BOTH mandatory recovery fences of the archive into the evidence's
/// historical authority list.
///
/// This is the read of the archive's `watchdog_spool` member, which
/// `BackupBundle::validate_class_requirements` makes mandatory for a
/// `full_recovery` archive and which the finalize phase previously dropped
/// unread: the published obligation was then one constant whether the fence
/// named zero unreconciled critical Watchdog signals or a thousand. I05.13
/// requires the receipt to carry them, so the member is now read here and each
/// declared digest becomes one suspended `WatchdogSignal` historical entry.
///
/// Three properties are load-bearing and are what this function is for:
///
/// - **Nothing is activated.** Every entry is `suspended: true`, and
///   `RestoreHistoricalAuthority::validate` refuses any entry that is not.
///   I05.13 requires Watchdog operational snapshots to restore "only as
///   forensic/suspended evidence and never as active supervision or
///   authority"; a restore that reactivated Watchdog supervision would be worse
///   than one that does not restore it.
/// - **Nothing is reconciled.** Reading the fence is not the #955 owner's
///   reconciliation, so the `watchdog_signals` obligation keeps its
///   unsatisfied state below. Suspension is not resolution.
/// - **Nothing is claimed beyond the archive.** The expected set is the
///   archive's own declared list, because the archive is the only carrier of
///   the fence. This is preservation evidence, not an independent completeness
///   denominator.
///
/// A member the archive does not carry contributes nothing and asserts
/// nothing: the obligation then reports the unbound-owner marker, exactly as it
/// did before, and no evidence entry is invented for evidence that is absent.
/// The `watchdog_signals` slot stays unsatisfied in BOTH cases, because the
/// read is preservation and reconciliation is the owner's.
fn historical_authority(
    bundle: &BackupBundle,
) -> Result<Vec<RestoreHistoricalAuthority>, BackupError> {
    // The ORS half is the archive's own `suspended_recovery_entries` read, the
    // one this site performed inline before the Watchdog half was added; the
    // `BackupError` is what that call site already raised, so its typed
    // classification is unchanged here.
    let mut entries = match &bundle.ors_snapshot {
        Some(snapshot) => suspended_recovery_entries(snapshot)?,
        None => Vec::new(),
    };
    if let Some(fence) = bundle.watchdog_spool.as_ref() {
        entries.extend(suspended_watchdog_signal_entries(fence)?);
    }
    Ok(entries)
}

/// Requires the validation denominator for cutover qualification: every
/// applicable owner obligation satisfied by its exact owner, with
/// blob/ORS suspension excused exactly when the archive carries no blobs
/// or ORS snapshot to suspend.
///
/// Each slot is checked twice, because state alone is not attribution: the
/// obligation must name the exact responsible owner, and it must be
/// `Satisfied` by that owner. A `Satisfied` obligation attributed to some
/// other owner is not that owner's evidence — existence and shape prove
/// nothing — so the owner identity is compared before the state, presented
/// against the owner vocabulary [`phase_owner`] and the finalize evidence
/// were built from.
///
/// A `MissingCapability` or `Unknown` anywhere — unresolved effects, stale
/// authority, unverifiable keys, incomplete closure, absent denominator —
/// refuses with the exact obligation slot: suspension is not resolution
/// and a `FullRecovery` class is not operational readiness. An applicable
/// obligation left `NotAttempted` contradicts the archive the evidence was
/// built from and fails as corruption rather than qualifying. Known-zero
/// unresolved work passes only through a satisfied reconciliation
/// obligation backed by its complete current denominator, which only the
/// exact reconciliation owner can issue.
fn require_cutover_obligations(
    obligations: &RestoreObligations,
    bundle: &BackupBundle,
) -> Result<(), BackupError> {
    fn require(
        owner: &'static str,
        obligation: &RestoreOwnerObligation,
        applicable: bool,
    ) -> Result<(), BackupError> {
        if obligation.owner_id != owner {
            return Err(BackupError::FinalizeEvidenceMismatch);
        }
        match obligation.state {
            RestoreObligationState::Satisfied => Ok(()),
            RestoreObligationState::NotAttempted if !applicable => Ok(()),
            RestoreObligationState::NotAttempted => Err(BackupError::RestoreJournalCorrupt),
            _ => Err(BackupError::RestoreCapabilityUnsupported { capability: owner }),
        }
    }
    let list: [(&RestoreOwnerObligation, &'static str, bool); 13] = [
        (&obligations.purge, owners::PURGE, true),
        (&obligations.canonical_validation, owners::CANONICAL, true),
        (&obligations.reference_validation, owners::REFERENCE, true),
        (
            &obligations.blob_validation,
            owners::BLOB,
            !bundle.blobs.is_empty(),
        ),
        (
            &obligations.ors_suspension,
            owners::ORS,
            bundle.ors_snapshot.is_some(),
        ),
        (
            &obligations.unresolved_effect_reconciliation,
            owners::RECONCILIATION,
            true,
        ),
        // Still unconditionally applicable, and that is now deliberate rather
        // than a leftover. Reading the archive's fence — which the finalize
        // phase does, and which the evidence's historical authority carries —
        // RECONCILES nothing: reconciliation is the #955 owner's own decision
        // and no Watchdog channel is bound in this composition. Excusing this
        // slot on "the archive carried no fence" would let a restore qualify for
        // cutover having consulted no Watchdog owner at all, which is the
        // substitution this gate exists to refuse.
        (&obligations.watchdog_signals, owners::WATCHDOG, true),
        (
            &obligations.external_source_revalidation,
            owners::EXTERNAL_SOURCE,
            true,
        ),
        (&obligations.runtime_invalidation, owners::RUNTIME, true),
        (&obligations.session_invalidation, owners::SESSION, true),
        (&obligations.lease_invalidation, owners::LEASE, true),
        (&obligations.route_invalidation, owners::ROUTE, true),
        (
            &obligations.user_broker_invalidation,
            owners::USER_BROKER,
            true,
        ),
    ];
    for (obligation, owner, applicable) in list {
        require(owner, obligation, applicable)?;
    }
    Ok(())
}

/// Re-reads the evidence file of a resumed run whose finalize executed in a
/// previous process. Best effort: the bytes are deterministic for the
/// transaction, so a present and valid file yields the identical value the
/// coordinator certified; absence or invalidity yields `None` rather than
/// self-attested evidence this process never observed.
fn read_resumed_evidence(root: &std::path::Path) -> Option<RestoreEvidence> {
    let bytes = std::fs::read(root.join(RESTORE_EVIDENCE_FILE)).ok()?;
    let evidence: RestoreEvidence = serde_json::from_slice(&bytes).ok()?;
    evidence.validate().ok()?;
    Some(evidence)
}

/// Kernel-observed prepare evidence: the exact intent executed, bound to the
/// compiled plan and the constructed destination. Observation, not authority.
#[derive(Serialize)]
struct ObservedPrepare {
    transaction_id: String,
    plan_id: String,
    destination: String,
    outcome: String,
}

/// Kernel-observed blob restoration: re-sealed digest, consumed receipt, and
/// lineage binding. No plaintext or key bytes cross this boundary.
#[derive(Serialize)]
struct ObservedBlobRestore {
    resealed_sha256: String,
    receipt_id: String,
    key_lineage: String,
    source_plaintext_sha256: String,
}

/// One purge-ledger revision the ORS owner issued while this restore applied
/// the entry. The value is the owner's, read from the same transaction that
/// made the purge durable; it is never recomputed over the entry or over any
/// count of entries here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct AppliedPurgeRevision {
    purge_id: String,
    revision: u64,
}

/// Kernel-observed purge application: the exact ledger entries the archive
/// carried, each bound to the ledger revision its owner issued.
///
/// This is the purge phase's evidence document. It is staged as
/// `purge_ledger.json` and is the byte string
/// [`KernelRestoreTarget::effect_receipt`] digests into the phase receipt, so
/// the owner-issued revisions are carried by the same effect evidence every
/// other phase already uses — and, through
/// [`KernelRestoreTarget::group_ref`], by the purge obligation the finalize
/// evidence publishes.
#[derive(Serialize)]
struct ObservedPurgeApplication {
    entries: Vec<PurgeLedgerEntry>,
    applied: Vec<AppliedPurgeRevision>,
}

/// Reconcile observation for one intent: exact applied receipt, proven
/// non-attempt, or undecidable bytes. Undecidable never becomes success.
enum ObservedEffect {
    Applied(Box<RestoreAppliedEffect>),
    NotAttempted,
    Undecidable,
}

/// The exact material one restore phase published under the destination.
///
/// Every phase stages its bytes through [`KernelRestoreTarget::write_file`] and
/// hands evidence to [`KernelRestoreTarget::effect_receipt`], which digests
/// those bytes into [`RestoreEffectReceipt::evidence_sha256`]. For eight of the
/// ten phases the evidence bytes ARE the published member's bytes — the phase
/// either wrote that same buffer or read it back through
/// [`KernelRestoreTarget::staged_bytes`] — so the receipt's digest is a claim
/// about material on disk and can be compared against it. The two exceptions
/// are stated in [`KernelRestoreTarget::phase_material`] rather than papered
/// over: their evidence is a separate observation document that is never
/// persisted, so only the presence of what they published is re-provable.
struct PhaseMaterial {
    /// The member this phase published, when it publishes one, resolved
    /// through the same contained-member guard
    /// [`KernelRestoreTarget::write_file`] uses.
    member: Option<PathBuf>,
    /// Whether [`RestoreEffectReceipt::evidence_sha256`] is the digest of
    /// `member`'s exact bytes.
    receipt_digests_member: bool,
}

/// Bounded removal disposition for the output one restore execution staged.
///
/// A disposition, not an error: the primary engine failure is returned either
/// way, so this only has to say what happened to the staged bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StagedCleanup {
    /// This execution staged no removable file; nothing was removed and
    /// nothing is owed.
    NothingStaged,
    /// Every removable file this execution staged was removed.
    Removed,
    /// Published phase material a still-present phase receipt attests was
    /// preserved instead of unlinked, so something this execution staged
    /// SURVIVED. This is deliberately not [`Self::Removed`] and not
    /// [`Self::NothingStaged`]: "the destination is empty" and "the
    /// destination still holds restored canonical history this cleanup chose
    /// not to destroy" are different facts about the same run, and a caller
    /// that cannot tell them apart is told a loss where there was none.
    AttestedPhaseMaterialPreserved,
    /// Cleanup preserved what it could not attribute to this execution, for
    /// the exact typed reason.
    Refused(StagedCleanupRefusal),
}

/// Kernel restore target over the accepted effect seam.
///
/// Every applicable phase re-checks the Kernel effect fence before touching
/// state, executes the genuine responsible-owner operation with the exact
/// bindings the coordinator supplies, persists exact bytes — flushed before
/// they are published, so a phase receipt is never journalled over bytes a
/// power loss could remove — and returns an observed receipt. Reconciliation
/// answers from persisted identity receipts AND the material they attest, never
/// from a receipt alone.
///
/// It also owns the two bounds the target is responsible for: every staged
/// write is admitted against [`StagedOutputBudget`] BEFORE it happens, and the
/// exact set of paths it wrote is retained so a failed execution can be
/// cleaned up without touching anything it cannot prove is its own.
struct KernelRestoreTarget<'a> {
    root: PathBuf,
    /// Work root the destination was constructed under, re-checked at cleanup
    /// time so a swapped destination cannot redirect a removal.
    work_root: PathBuf,
    /// Destination label, the last component of the isolated restore path.
    label: String,
    kernel_fence: StateFence,
    keys: Option<&'a eliot_backup::WrappedKeyManifest>,
    blob_scope: Option<&'a DestinationScope>,
    receipts: Vec<BlobRestorationReceipt>,
    manifest_evidence: Option<DestinationManifestEvidence>,
    /// Whether this execution runs as rehearsal. Pinned into the destination
    /// admission at prepare and re-checked before every later effect, so a
    /// rehearsal-prepared root is never continued by a production run and can
    /// never reach cutover qualification.
    rehearsal: bool,
    /// Composition-owned ORS owner the purge phase applies the archive's
    /// purge ledger through, when this execution was handed one.
    ///
    /// `None` is a real, declared posture — the injected-journal seam
    /// [`KernelBackupRestore::restore`] has no composition owner to name — and
    /// the purge phase refuses on it rather than degrading (see
    /// [`KernelRestoreTarget::apply_purge_ledger`]): for a carried ledger
    /// because nothing can be applied, and for an empty one because the
    /// revision that archive declares still has to be reconciled against the
    /// owner that alone can answer for it
    /// ([`check_purge_revision_closure`]). It is never a silent
    /// skip and never a locally allocated revision.
    ors: Option<std::sync::Arc<RedbRecoveryStore>>,
    /// Revisions the purge phase actually consumed from the ORS purge-ledger
    /// owner, in ledger order. Observable on the SUCCESS path only:
    /// [`KernelRestoreTarget::apply_purge_ledger`] first cross-checks the
    /// archive's declared revision against the owner's own durable counter
    /// through [`check_purge_revision_closure`], then projects these
    /// revisions into the staged phase evidence, and that staging is what the
    /// phase receipt digests. If a later step of the same phase fails, the
    /// target is dropped with this field — no reader observes it on that path,
    /// and this comment does not claim one does.
    applied_purge_revisions: Vec<AppliedPurgeRevision>,
    /// The ARCHIVE's own declared purge-ledger revision,
    /// `bundle.manifest.purge_ledger_revision`, copied once when this target
    /// was built so the purge phase can cross-check it against what the owner
    /// itself reports without reaching back into the bundle.
    ///
    /// Stored, never recomputed: nothing here increments, derives or counts to
    /// produce it.
    declared_purge_ledger_revision: u64,
    calls: Vec<String>,
    final_evidence: Option<RestoreEvidence>,
    /// Bounded output budget derived from the archive before any write.
    budget: StagedOutputBudget,
    /// Files staged so far, against [`StagedOutputBudget::members`].
    staged_members: usize,
    /// Bytes staged so far, against [`StagedOutputBudget::bytes`].
    staged_bytes: usize,
    /// Exact paths this execution wrote, in write order, each under the
    /// destination root. Nothing else is ever a cleanup candidate.
    staged: Vec<PathBuf>,
}

impl<'a> KernelRestoreTarget<'a> {
    fn new(
        work_root: &Path,
        destination: &KernelIsolatedDestination,
        bundle: &BackupBundle,
        ports: &RestorePorts<'a>,
        receipts: Vec<BlobRestorationReceipt>,
        ors: Option<&std::sync::Arc<RedbRecoveryStore>>,
    ) -> Result<Self, BackupError> {
        Ok(Self {
            root: destination.root().to_path_buf(),
            work_root: work_root.to_path_buf(),
            label: destination.label().to_owned(),
            kernel_fence: ports.kernel_fence.clone(),
            keys: ports.keys,
            blob_scope: ports.blob_scope,
            receipts,
            manifest_evidence: ports.manifest_evidence.clone(),
            rehearsal: ports.rehearsal,
            ors: ors.map(std::sync::Arc::clone),
            applied_purge_revisions: Vec::new(),
            declared_purge_ledger_revision: bundle.manifest.purge_ledger_revision,
            calls: Vec::new(),
            final_evidence: None,
            budget: StagedOutputBudget::derive(bundle)?,
            staged_members: 0,
            staged_bytes: 0,
            staged: Vec::new(),
        })
    }

    /// Re-checks the Kernel effect fence before an applicable phase.
    fn gate(&self, bundle: &BackupBundle) -> Result<(), BackupError> {
        check_kernel_effect_fence(&self.kernel_fence, bundle)
    }

    /// Applies every archive purge entry through the ORS purge-ledger owner
    /// and returns the owner's own durable purge-ledger counter as it stood
    /// BEFORE this call, together with the revision that owner issued for each
    /// entry.
    ///
    /// This is the live route to
    /// [`RedbRecoveryStore::apply_purge_ledger_entry`], the only writer of the
    /// purge-ledger revision. The revision is the owner's durable fact, read
    /// from the same transaction that made the purge durable (I5.13:44, A13.7:
    /// a backup receipt binds a purge-ledger revision and a restore compares
    /// against the owner's value — it is never recomputed over caller input),
    /// so an exact replay returns the same revision and consumes nothing, and a
    /// `purge_id` re-applied with a different entry is refused as an integrity
    /// conflict. A refusal is mapped with the same
    /// [`ors_to_backup`](super::backup_restore_ports::ors_to_backup) this crate
    /// already uses for every other ORS refusal, so the owner's cause crosses
    /// the seam typed and is never flattened, swallowed, or turned into a
    /// success.
    ///
    /// ## Absent-owner refusal rule
    ///
    /// An archive that carries at least one purge entry, restored without the
    /// composition-owned ORS handle, REFUSES here with
    /// [`BackupError::RestoreCapabilityUnsupported`] naming
    /// `owners::PURGE_LEDGER_OWNER`. It does not stage the ledger, does not
    /// report a revision, and is not a degraded success: the only writer of
    /// that revision is absent, so there is nothing this owner could honestly
    /// publish, and an unapplied ledger must never read as applied purge-first
    /// (A13.7, A0.3: recovery cannot resurrect invalid state). The absence is
    /// the injected-journal seam's declared posture, not a fallback.
    ///
    /// An archive whose purge ledger is empty still reaches the revision
    /// cross-check, because it still DECLARES a purge-ledger revision: there is
    /// no entry to apply, so this returns the owner's own counter with no
    /// per-entry revision, and [`check_purge_revision_closure`] reconciles the
    /// declaration against that answer. An empty ledger is therefore not a
    /// licence to pass the owner by — with no ORS handle the answer is `None`
    /// and the phase refuses at that cross-check, the same typed refusal the
    /// non-empty case meets.
    ///
    /// ## Rehearsal refusal rule
    ///
    /// An archive that carries at least one purge entry, executed as a
    /// rehearsal, REFUSES here with the SAME
    /// [`BackupError::RestoreCapabilityUnsupported`] naming
    /// `owners::PURGE_LEDGER_OWNER` that the absent-owner branch above uses.
    /// It is not a second refusal style: one typed error, one named
    /// capability, checked before any owner call.
    ///
    /// WHY, stated plainly: this phase calls
    /// [`RedbRecoveryStore::apply_purge_ledger_entry`] on the live `p07_ors`
    /// store, and that owner is the only writer of the purge-ledger revision.
    /// Every other phase of the restore body writes solely into the isolated
    /// destination, so this is the one place where a rehearsal could mutate
    /// PRODUCTION AUTHORITY. A rehearsal that applied the archive's ledger
    /// would commit irreversible live mutations while reporting itself to its
    /// caller as a rehearsal — the exact posture the module contract forbids
    /// ("rehearsal never activates, retires, cuts over, or unblocks effects")
    /// and the one
    /// [`KernelBackupRestore::qualify_cutover`] refuses on the durable pinned
    /// flag. The two positions are independent, so both are enforced: this
    /// one on the write, `qualify_cutover` on the later cutover.
    ///
    /// The guard is deliberately placed in `apply_purge_entries` rather than
    /// only in [`KernelBackupRestore::restore_with_ors_journal`], because
    /// `restore_with_owner` only RELAXES journal admission for a rehearsal
    /// (it admits fixture-flagged journals for mapping proof) and does not
    /// refuse one, so an entry-level guard there would leave the phase open.
    /// Placing it here holds for every future route into the phase, not just
    /// today's one — a guard that is unreachable only by accident is not a
    /// guard.
    ///
    /// An archive whose purge ledger is EMPTY is not a rehearsal-shaped
    /// exception: this guard keys off the entries actually carried, so an empty
    /// ledger still reads the owner and still has its declared revision
    /// reconciled against the owner below. A rehearsal that carries no purge
    /// entry is not a way to obtain purge evidence, and it does not make the
    /// phase's obligation `Satisfied` for an archive that purged nothing.
    ///
    /// ## Ordering against the revision cross-check
    ///
    /// The owner counter read here is the owner's own
    /// [`RedbRecoveryStore::purge_ledger_revision`] — read AFTER this function
    /// applies the archive's ledger, so the value cross-checked by
    /// [`check_purge_revision_closure`] is the ledger position this owner has
    /// now reached, which is the same kind of quantity the archive's
    /// `manifest.purge_ledger_revision` declares. Reading it BEFORE would
    /// compare the position the destination started from against the position
    /// the source finished at, which is not a closure check at all.
    /// [`KernelRestoreTarget::apply_purge_ledger`] passes it
    /// to that check on the result of THIS function, so a rehearsal carrying a
    /// purge entry still refuses at the guard above, before any owner call, and
    /// never reaches the cross-check: adding it does not move the live owner one
    /// step closer to a rehearsal.
    fn apply_purge_entries(
        &self,
        entries: &[PurgeLedgerEntry],
    ) -> Result<(Option<u64>, Vec<AppliedPurgeRevision>), BackupError> {
        // A rehearsal reaches the LIVE owner: this is the only phase in the
        // restore body that writes to the live `p07_ors` store, every other
        // phase writes solely into the isolated destination. Refuse before
        // any owner call, using the same typed refusal the absent-owner
        // branch below uses, so there is no second refusal style.
        if self.rehearsal && !entries.is_empty() {
            return Err(BackupError::RestoreCapabilityUnsupported {
                capability: owners::PURGE_LEDGER_OWNER,
            });
        }
        let Some(ors) = self.ors.as_ref() else {
            if entries.is_empty() {
                return Ok((None, Vec::new()));
            }
            return Err(BackupError::RestoreCapabilityUnsupported {
                capability: owners::PURGE_LEDGER_OWNER,
            });
        };
        // The owner's own durable counter, read through the owner's own
        // accessor AFTER this phase has applied the archive's ledger. This is
        // the only value that answers "which purge-ledger revision has this
        // owner reached", and it is read from the same durable counter the
        // applying transactions commit with each ledger row — never counted
        // over `entries`, never read out of the archive under check.
        //
        // The read is AFTER, not before, and the position matters: the
        // archive's `manifest.purge_ledger_revision` is the ledger position the
        // SOURCE observed once it had applied its own ledger, so it is a
        // POST-apply position. Comparing a pre-apply counter against it
        // compares two different quantities — on a rebuilt destination whose
        // counter starts at 0, applying 7 entries correctly leaves the owner at
        // 7, and a pre-apply read of 0 would refuse a restore that did exactly
        // the right thing, AFTER having committed the whole ledger (issue #960,
        // A14).
        let mut applied = Vec::with_capacity(entries.len());
        for entry in entries {
            let revision = ors.apply_purge_ledger_entry(entry).map_err(ors_to_backup)?;
            applied.push(AppliedPurgeRevision {
                purge_id: entry.purge_id.clone(),
                revision,
            });
        }
        let owner_revision = ors.purge_ledger_revision().map_err(ors_to_backup)?;
        Ok((Some(owner_revision), applied))
    }

    /// Stages one file, refusing BEFORE the write when the bounded output
    /// budget would be exceeded.
    ///
    /// The bound is checked against the running accounting plus this file, so
    /// the refusal happens while the destination still matches the budget —
    /// never after the exceeding bytes exist. The refusal is the typed
    /// [`BackupError::LimitExceeded`] naming the exact ceiling, not a
    /// formatted message, and it propagates through the phase and the engine
    /// unchanged.
    ///
    /// ## Order: reserved capacity, durable bytes, published name
    ///
    /// The two bounds above are the "reserve bounded output capacity" step and
    /// run BEFORE any I/O, so a refused write never creates a directory, a
    /// temporary file or a byte. The rest is the same admitted durable-file
    /// staging convention this restore lane's ORS journal already applies to
    /// its own sealed bodies
    /// ([`sync_file`](super::backup_restore_ports::sync_file) /
    /// [`sync_parent_directory`](super::backup_restore_ports::sync_parent_directory),
    /// called from `OrsRestoreJournal::seal`), in the order the durable claim
    /// requires:
    ///
    /// ```text
    /// reserve bounded output capacity                    (the two LimitExceeded checks)
    /// -> create/write the operation-owned temporary file  (std::fs::write)
    /// -> flush the written file                          (sync_file, before publishing)
    /// -> publish it at the admitted destination          (std::fs::rename)
    /// -> establish publication durability                (sync_parent_directory)
    /// -> publish/flush the phase receipt                 (persist_applied's own call)
    /// -> allow the existing ORS CAS to record ReceiptPersisted
    /// ```
    ///
    /// Atomic naming is not durability. A rename only makes the NAME atomic,
    /// while the engine CASes `ReceiptPersisted` into a store that does fsync
    /// afterwards, so without the two flushes the journal would be told
    /// `ReceiptPersisted` over bytes a power loss could still remove. That is
    /// exactly the invariant the same module already states for its journal
    /// bodies at `backup_restore_ports.rs:1567-1570`: a recovered row must
    /// never point at material a target power loss could remove. The readback
    /// half of that claim is [`Self::check_attested_material`].
    ///
    /// A failed body flush is a REFUSAL, not a silent success: the error
    /// propagates as this phase's own `BackupError`, which the engine
    /// reconciles against that same phase. No ORS transaction is held across
    /// any of this I/O, and no cross-store atomicity is claimed — the two
    /// flushes bound the window, they do not close it. The staged counters and
    /// [`Self::staged`] are committed only after both flushes, so a refusal
    /// never accounts for a file that was never published.
    fn write_file(&mut self, relative: &str, bytes: &[u8]) -> Result<(), BackupError> {
        let members = self
            .staged_members
            .checked_add(1)
            .ok_or(BackupError::LimitExceeded {
                field: STAGED_OUTPUT_MEMBERS_FIELD,
                limit: self.budget.members,
            })?;
        if members > self.budget.members {
            return Err(BackupError::LimitExceeded {
                field: STAGED_OUTPUT_MEMBERS_FIELD,
                limit: self.budget.members,
            });
        }
        let staged_bytes =
            self.staged_bytes
                .checked_add(bytes.len())
                .ok_or(BackupError::LimitExceeded {
                    field: STAGED_OUTPUT_BYTES_FIELD,
                    limit: self.budget.bytes,
                })?;
        if staged_bytes > self.budget.bytes {
            return Err(BackupError::LimitExceeded {
                field: STAGED_OUTPUT_BYTES_FIELD,
                limit: self.budget.bytes,
            });
        }
        // Atomic temp-write + rename: a crash never leaves a torn receipt
        // that later reads as success. An unparseable receipt still reports
        // Unknown (rollback disposition), never a fabricated outcome.
        let path = self.contained_member_path(relative)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| BackupError::Target(error.to_string()))?;
        }
        let tmp = path.with_extension("tmp-restore");
        std::fs::write(&tmp, bytes).map_err(|error| BackupError::Target(error.to_string()))?;
        // Flush the operation-owned temporary file BEFORE it is published.
        // Publishing first and flushing after would leave a name pointing at
        // bytes the target never made stable, which is the same defect the
        // write order above exists to prevent.
        sync_file(&tmp)?;
        std::fs::rename(&tmp, &path).map_err(|error| BackupError::Target(error.to_string()))?;
        // Flush the directory entry that now names the published file, so the
        // name itself survives the power loss the bytes must survive.
        // `contained_member_path` admits only one or more plain relative
        // segments, so the joined path always has a parent; it is resolved
        // rather than assumed anyway, because a member that named none would
        // leave the publication above unflushable, and that must be a refusal
        // rather than a silent skip of the durability step.
        sync_parent_directory(path.parent().ok_or(BackupError::RestoreJournalCorrupt)?)?;
        self.staged_members = members;
        self.staged_bytes = staged_bytes;
        self.staged.push(path);
        Ok(())
    }

    /// Resolves one member path that is guaranteed to stay inside the root.
    ///
    /// Bundle-supplied identifiers reach [`KernelRestoreTarget::write_file`]
    /// through `format!` (`events/{record_id}.json`, `receipts/{operation_id}.json`,
    /// `blobs/{hash}`, `projections/{record_id}.json`), and `Path::join` neither
    /// normalises `..` nor refuses an absolute, drive-prefixed or UNC argument,
    /// so this is the single place where the "owner-admitted isolated
    /// destination" guarantee is enforced. The accepted shape is exactly one or
    /// more non-empty plain segments: `.`, `..`, a root component and a Windows
    /// prefix component are all refused, and so is a path that names no segment
    /// at all. Refusal happens before any directory is created, before the
    /// staged-member and staged-byte counters are committed, and before any byte
    /// is written — so a refused path is also absent from `self.staged`, and the
    /// ownership-scoped cleanup can never be pointed at a path outside the
    /// isolated root.
    ///
    /// This is the same refusal the file-runner target enforces
    /// (`eliot_backup`'s `FileRestoreTarget::contained_member_path`, issue
    /// #1873). The two targets are separate owners of the same documented
    /// guarantee, and a guarantee that holds on one restore path must not be
    /// weaker on the other.
    fn contained_member_path(&self, relative: &str) -> Result<PathBuf, BackupError> {
        let refuse = |reason: &'static str| BackupError::InvalidField {
            field: "restore member path",
            reason,
        };
        let mut segments = 0usize;
        for component in Path::new(relative).components() {
            match component {
                Component::Normal(_) => segments += 1,
                Component::CurDir
                | Component::ParentDir
                | Component::RootDir
                | Component::Prefix(_) => {
                    return Err(refuse(
                        "must be plain relative segments inside the isolated restore root",
                    ));
                }
            }
        }
        if segments == 0 {
            return Err(refuse(
                "must name at least one segment inside the isolated restore root",
            ));
        }
        Ok(self.root.join(relative))
    }

    fn phase_receipt_path(&self, phase: &RestorePhase) -> Result<PathBuf, BackupError> {
        let bytes = canonical_json_bytes(phase)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        Ok(self
            .root
            .join("phase-receipts")
            .join(format!("{}.json", sha256_hex(&bytes))))
    }

    fn effect_receipt(
        intent: &RestoreIntent,
        evidence_bytes: &[u8],
    ) -> Result<RestoreEffectReceipt, BackupError> {
        let phase_bytes = canonical_json_bytes(&intent.phase)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        Ok(RestoreEffectReceipt {
            transaction_id: intent.transaction_id.clone(),
            phase: intent.phase.clone(),
            input_digest: intent.input_digest.clone(),
            external_identity_sha256: sha256_hex(&phase_bytes),
            evidence_sha256: sha256_hex(evidence_bytes),
        })
    }

    fn persist_applied(
        &mut self,
        intent: &RestoreIntent,
        applied: &RestoreAppliedEffect,
    ) -> Result<(), BackupError> {
        let bytes = canonical_json_bytes(applied)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let relative = self
            .phase_receipt_path(&intent.phase)?
            .strip_prefix(&self.root)
            .map_err(|_| BackupError::RestoreJournalCorrupt)?
            .to_string_lossy()
            .into_owned();
        self.write_file(&relative, &bytes)
    }

    /// Turns an engine failure plus the cleanup disposition into the refusal
    /// this owner returns.
    ///
    /// The engine's typed failure is the cause and is never replaced. When the
    /// cleanup removed everything, or had nothing removable to remove, the
    /// refusal stays plain [`KernelRestoreError::TargetFailed`] — in both of
    /// those cases the bounded cleanup did exactly what it exists to do, so
    /// there is no second fact to report and nothing about the primary cause is
    /// lost. When the cleanup preserved something — either what it could not
    /// attribute, or published phase material a still-present phase receipt
    /// attests — that exact typed reason travels with the SAME primary failure,
    /// so nothing is lost and nothing is stringified. The two preservation
    /// causes are distinct typed reasons and never collapse into one, because
    /// "we could not prove this was ours to remove" and "these bytes are
    /// applied history the journal still accounts for" are different facts a
    /// caller needs separately (#960 W13/A18).
    fn refuse_with_staged_cleanup(
        &self,
        destination: &KernelIsolatedDestination,
        transaction_id: &str,
        target_id: &str,
        primary: BackupError,
    ) -> KernelRestoreError {
        match self.cleanup_staged_output(destination, transaction_id, target_id) {
            StagedCleanup::NothingStaged | StagedCleanup::Removed => {
                KernelRestoreError::TargetFailed(primary)
            }
            StagedCleanup::AttestedPhaseMaterialPreserved => {
                KernelRestoreError::StagedCleanupIncomplete {
                    primary,
                    cleanup: StagedCleanupRefusal::AttestedPhaseMaterialPreserved,
                }
            }
            StagedCleanup::Refused(cleanup) => {
                KernelRestoreError::StagedCleanupIncomplete { primary, cleanup }
            }
        }
    }

    /// Bounded, ownership-scoped removal of the output THIS execution staged.
    ///
    /// Ownership, in the order it is proved:
    ///
    /// 1. candidates are the exact paths this execution wrote
    ///    ([`Self::staged`]) minus the preserved observation classes, so a
    ///    prior execution's staging, a pinned admission, and the reconcileable
    ///    phase receipts are never candidates at all;
    /// 2. a staged path whose publishing phase still has its phase receipt on
    ///    disk is not a candidate either
    ///    ([`Self::is_attested_phase_material`]): that receipt is the durable
    ///    observation the ORS restore journal committed `ReceiptPersisted`
    ///    against, so the bytes it digests are applied history a resume will
    ///    reconcile and never re-run. Unlinking them is a loss, not a
    ///    cleanup — `ARCH-RES-03` (A13.7) and the item's own "cleanup
    ///    preserved" clause;
    /// 3. a destination that was resumed rather than constructed fresh is
    ///    refused outright, because its contents are not provably ours;
    /// 4. the pinned destination admission is re-read through the same
    ///    [`KernelBackupRestore::refuse_foreign_destination`] gate that
    ///    admitted it, so a destination pinned to another transaction or
    ///    target is refused rather than emptied;
    /// 5. the destination root and the isolated area are resolved again HERE,
    ///    not reused from open time, and the root must still sit inside
    ///    `<work_root>/.eliot/restore-isolated/<label>`, so a swapped or
    ///    re-pointed destination cannot redirect a removal.
    ///
    /// Bounded work, in four dimensions: the walk is over a known path set,
    /// so there is no unbounded directory recursion; the set is at most
    /// [`StagedOutputBudget::members`] because those are the same writes the
    /// budget admitted; the aggregate unlinked bytes stop at
    /// [`StagedOutputBudget::bytes`], the same ceiling that admitted them; and
    /// the attestation probe is one bounded `Path::exists` per staged path
    /// over the same set, never a directory walk. Empty directories left behind
    /// are reclaimed with [`std::fs::remove_dir`], which cannot remove a
    /// non-empty directory, so a directory this pass did not empty always
    /// survives — and now a directory whose attested material this pass
    /// deliberately kept can never be emptied at all.
    fn cleanup_staged_output(
        &self,
        destination: &KernelIsolatedDestination,
        transaction_id: &str,
        target_id: &str,
    ) -> StagedCleanup {
        let mut preserved_attested = false;
        let mut candidates: Vec<&PathBuf> = Vec::with_capacity(self.staged.len());
        for path in &self.staged {
            if self.is_attested_phase_material(path) {
                preserved_attested = true;
            } else if !Self::is_preserved_observation(path, &self.root) {
                candidates.push(path);
            }
        }
        if candidates.is_empty() {
            return if preserved_attested {
                StagedCleanup::AttestedPhaseMaterialPreserved
            } else {
                StagedCleanup::NothingStaged
            };
        }
        if destination.is_resumed() {
            return StagedCleanup::Refused(StagedCleanupRefusal::AdmittedResume);
        }
        if KernelBackupRestore::refuse_foreign_destination(
            destination,
            transaction_id,
            target_id,
            self.rehearsal,
            self.manifest_evidence.as_ref(),
        )
        .is_err()
        {
            return StagedCleanup::Refused(StagedCleanupRefusal::ForeignAdmission);
        }
        let isolated = self.work_root.join(".eliot").join(RESTORE_ISOLATED_AREA);
        let area = match std::fs::canonicalize(isolated.join(&self.label)) {
            Ok(area) => area,
            // The isolated area is already gone, so none of the staged output
            // this execution produced is still on disk.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return StagedCleanup::Removed;
            }
            Err(_) => return StagedCleanup::Refused(StagedCleanupRefusal::OutsideIsolatedArea),
        };
        let root = match std::fs::canonicalize(&self.root) {
            Ok(root) => root,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return StagedCleanup::Removed;
            }
            Err(_) => return StagedCleanup::Refused(StagedCleanupRefusal::OutsideIsolatedArea),
        };
        if !root.starts_with(&area) {
            return StagedCleanup::Refused(StagedCleanupRefusal::OutsideIsolatedArea);
        }
        let mut refusal: Option<StagedCleanupRefusal> = None;
        let mut removed_bytes = 0usize;
        let mut parents: BTreeSet<PathBuf> = BTreeSet::new();
        for path in candidates {
            if !path.starts_with(&self.root) {
                refusal.get_or_insert(StagedCleanupRefusal::PathNotOurs);
                continue;
            }
            let metadata = match std::fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => {
                    refusal.get_or_insert(StagedCleanupRefusal::RemovalFailed);
                    continue;
                }
            };
            // A directory (or any non-file) at a staged path means the shape
            // this pass admitted is not the shape on disk, so it refuses rather
            // than recursing into it.
            if metadata.is_dir() {
                refusal.get_or_insert(StagedCleanupRefusal::PathNotOurs);
                continue;
            }
            let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
            if size > self.budget.bytes.saturating_sub(removed_bytes) {
                refusal.get_or_insert(StagedCleanupRefusal::BudgetReached);
                break;
            }
            match std::fs::remove_file(path) {
                Ok(()) => {
                    removed_bytes += size;
                    if let Some(parent) = path.parent() {
                        parents.insert(parent.to_path_buf());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    refusal.get_or_insert(StagedCleanupRefusal::RemovalFailed);
                }
            }
        }
        Self::reclaim_empty_directories(&parents, &self.root);
        match refusal {
            Some(refusal) => StagedCleanup::Refused(refusal),
            // `Removed` would be a false claim here: it says every removable
            // file this execution staged is gone, and the attested material
            // this pass declined to unlink is still on disk.
            None if preserved_attested => StagedCleanup::AttestedPhaseMaterialPreserved,
            None => StagedCleanup::Removed,
        }
    }

    /// Whether a staged path is an observation or owner evidence rather than
    /// derived payload, and is therefore never removed by cleanup.
    ///
    /// - `phase-receipts/**` is the per-phase observation the journal
    ///   reconciles against and that the finalize obligation denominator
    ///   digests; its absence is
    ///   [`BackupError::RestoreJournalCorrupt`], which is a worse outcome
    ///   than the staging left behind;
    /// - [`DESTINATION_ADMISSION_FILE`] is Host-issued owner evidence (#958)
    ///   pinned to this transaction, not a byte this execution produced;
    /// - [`RESTORE_EVIDENCE_FILE`] is the finalize evidence a later resume
    ///   re-reads and cutover qualification requires.
    ///
    /// A path this execution never wrote is absent from [`Self::staged`] by
    /// construction, so another execution's output is preserved without
    /// needing to be recognised here.
    fn is_preserved_observation(path: &Path, root: &Path) -> bool {
        let Ok(relative) = path.strip_prefix(root) else {
            return true;
        };
        let Some(std::path::Component::Normal(first)) = relative.components().next() else {
            return true;
        };
        let Some(first) = first.to_str() else {
            return true;
        };
        first == "phase-receipts"
            || first == DESTINATION_ADMISSION_FILE
            || first == RESTORE_EVIDENCE_FILE
    }

    /// Whether a staged path is published phase material whose phase receipt
    /// is STILL on disk, and is therefore attested applied history rather than
    /// abandoned staging.
    ///
    /// Each phase publishes its material first and persists
    /// `phase-receipts/<phase-digest>.json` second, whose `evidence_sha256` is
    /// the digest of the material it just read back; only then does the engine
    /// compare-and-swap `ReceiptPersisted` into the durable ORS journal. A
    /// receipt that is still present therefore names material the journal
    /// already accounts for, and the engine resumes at `record.phase` — it
    /// never re-runs the phases behind the journal head, because the only
    /// destination verifier (`apply_rebuild`'s `count_dir`) is itself a phase
    /// behind that head.
    ///
    /// Unlinking such bytes leaves a durable journal and retained receipts
    /// attesting restored canonical history that does not exist, which
    /// `ARCH-RES-03` (A13.7) forbids. So they are not cleanup candidates at
    /// all: they are preserved, and the disposition reports that something
    /// survived rather than claiming the destination was emptied.
    ///
    /// A path that is not recognised as a phase's published material is left to
    /// the ordinary candidate rules, so a file this execution staged whose
    /// phase never reached its receipt is still removable.
    fn is_attested_phase_material(&self, path: &Path) -> bool {
        let Ok(relative) = path.strip_prefix(&self.root) else {
            return false;
        };
        let Some(phase) = Self::publishing_phase(relative) else {
            return false;
        };
        self.phase_receipt_path(&phase)
            .is_ok_and(|receipt| receipt.exists())
    }

    /// Maps one staged path back to the single phase that publishes it.
    ///
    /// The mapping is the inverse of the `write_file` relative path each phase
    /// uses, so the receipt named here is the very receipt that phase
    /// persisted for exactly these bytes. A path no phase publishes — or a
    /// path whose shape does not match one of these phases — has no phase to
    /// attest it and is `None`.
    fn publishing_phase(relative: &Path) -> Option<RestorePhase> {
        let staged = relative.to_str()?;
        let phase = match staged {
            "purge_ledger.json" => RestorePhase::ApplyPurgeLedger,
            "suspended_ors.json" => RestorePhase::SuspendOrsOperations,
            "rebuild.json" => RestorePhase::RebuildProjections,
            "verify.json" => RestorePhase::VerifyReceiptEventChain,
            _ => {
                let (directory, member) = staged.split_once('/')?;
                // A member is one path segment: a nested staged path belongs to
                // no phase and is never attested.
                if member.is_empty() || member.contains('/') {
                    return None;
                }
                match directory {
                    // A blob is staged under its own content hash, with no
                    // extension; every other member is staged as `<id>.json`.
                    "blobs" => RestorePhase::ImportSealedBlob {
                        hash: member.to_owned(),
                    },
                    "events" => RestorePhase::ImportCanonicalEvent {
                        record_id: member.strip_suffix(".json")?.to_owned(),
                    },
                    "receipts" => RestorePhase::ImportReceipt {
                        operation_id: member.strip_suffix(".json")?.to_owned(),
                    },
                    "projections" => RestorePhase::ImportProjection {
                        record_id: member.strip_suffix(".json")?.to_owned(),
                    },
                    _ => return None,
                }
            }
        };
        Some(phase)
    }

    /// Reclaims the directories this pass emptied, deepest first.
    ///
    /// Only plain [`std::fs::remove_dir`] is used, and only on directories
    /// strictly below the destination root, so a directory that still holds
    /// anything — including anything this pass did not write — cannot be
    /// removed. A failure is absorbed: the consequence is a retained empty
    /// directory, never a wrong answer about what is still staged.
    fn reclaim_empty_directories(parents: &BTreeSet<PathBuf>, root: &Path) {
        let mut deepest: Vec<&PathBuf> = parents.iter().filter(|dir| *dir != root).collect();
        deepest.sort_by_key(|dir| std::cmp::Reverse(dir.components().count()));
        for dir in deepest {
            let _reclaimed = std::fs::remove_dir(dir);
        }
    }

    /// The exact material one restore phase published, and whether the phase
    /// receipt digests those bytes.
    ///
    /// The mapping is the mirror of the `apply_*` methods: every arm names the
    /// same member that method stages. Nothing here is derived from the
    /// receipt, from a count, or from a name the phase did not write, so a
    /// resumed receipt is checked against the same member the phase produced
    /// rather than against a weaker echo of itself.
    fn phase_material(&self, phase: &RestorePhase) -> Result<PhaseMaterial, BackupError> {
        match phase {
            RestorePhase::Pending => Err(BackupError::RestorePhaseMismatch),
            RestorePhase::PrepareIsolatedRoot => Ok(PhaseMaterial {
                // The pinned destination admission is the one durable byte
                // prepare publishes, and only when this execution carries Host
                // admission to pin; a rehearsal without it publishes no member.
                member: self
                    .manifest_evidence
                    .as_ref()
                    .map(|_| self.contained_member_path(DESTINATION_ADMISSION_FILE))
                    .transpose()?,
                // `apply_prepare` digests `ObservedPrepare`, an observation
                // assembled in memory and never persisted, so the admission's
                // own bytes carry no digest this receipt attests.
                receipt_digests_member: false,
            }),
            RestorePhase::ApplyPurgeLedger => self.digested_member("purge_ledger.json"),
            RestorePhase::ImportSealedBlob { hash } => Ok(PhaseMaterial {
                member: Some(self.contained_member_path(&format!("blobs/{hash}"))?),
                // `apply_blob` digests `ObservedBlobRestore` — the observed
                // re-seal, whose `resealed_sha256` is a destination-encrypted
                // digest no archive member carries. That document is never
                // persisted, so the receipt attests no digest of the re-sealed
                // bytes and only their presence is re-provable. The content
                // binding this phase does own is `BlobOwnerClient::restore_blob`,
                // which re-verifies the plaintext digest and the restoration
                // receipt before it stages anything.
                receipt_digests_member: false,
            }),
            RestorePhase::ImportCanonicalEvent { record_id } => {
                self.digested_member(&format!("events/{record_id}.json"))
            }
            RestorePhase::ImportReceipt { operation_id } => {
                self.digested_member(&format!("receipts/{operation_id}.json"))
            }
            RestorePhase::ImportProjection { record_id } => {
                self.digested_member(&format!("projections/{record_id}.json"))
            }
            RestorePhase::SuspendOrsOperations => self.digested_member("suspended_ors.json"),
            RestorePhase::RebuildProjections => self.digested_member("rebuild.json"),
            RestorePhase::VerifyReceiptEventChain => self.digested_member("verify.json"),
            RestorePhase::FinalizeIsolatedRoot => self.digested_member(RESTORE_EVIDENCE_FILE),
        }
    }

    /// Whether a phase's own material is present under the destination.
    ///
    /// This is the readback of [`Self::phase_material`] for the one case where
    /// the receipt that would have carried the digest is itself gone, so
    /// presence of the phase-owned member is the only phase-specific evidence
    /// still available. Exactly that member is consulted — never a directory
    /// listing, a count, or a name the phase did not write — and the probe is a
    /// fallible read, so an inaccessible member refuses
    /// ([`BackupError::Target`]) rather than reading as an absence.
    fn phase_material_published(&self, phase: &RestorePhase) -> Result<bool, BackupError> {
        let Some(member) = self.phase_material(phase)?.member else {
            // The phase publishes no member at all under this execution's
            // authority (a rehearsal prepare carries no Host admission to
            // pin), so there is nothing of its own that could exist.
            return Ok(false);
        };
        match std::fs::metadata(&member) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(BackupError::Target(error.to_string())),
        }
    }

    /// Material for a phase whose receipt digest IS the digest of the bytes it
    /// published, because the `apply_*` method either staged that same buffer
    /// or read it back through [`Self::staged_bytes`] and handed it to
    /// [`Self::effect_receipt`].
    fn digested_member(&self, relative: &str) -> Result<PhaseMaterial, BackupError> {
        Ok(PhaseMaterial {
            member: Some(self.contained_member_path(relative)?),
            receipt_digests_member: true,
        })
    }

    /// Re-reads the material a recovered phase receipt attests.
    ///
    /// This is the readback half of the durability order
    /// [`Self::write_file`] establishes on the write half. A receipt is an
    /// observation of an effect; it is not the effect. Without this, a receipt
    /// whose material a power loss removed — or that now names bytes other than
    /// the ones on disk — still reports `Applied` and the engine advances to
    /// the next phase over material that was never durably produced.
    ///
    /// Refusals reuse this file's existing vocabulary rather than a new error
    /// kind: [`BackupError::RestoreJournalCorrupt`] is what a journaled effect
    /// without its observation already is here ([`Self::group_ref`],
    /// [`Self::check_destination_admission`]), and
    /// [`BackupError::RestoreJournalMismatch`] is what a receipt that disagrees
    /// with what it names already is. An unreadable path is a
    /// [`BackupError::Target`], never an absence.
    fn check_attested_material(
        material: &PhaseMaterial,
        evidence_sha256: &str,
    ) -> Result<(), BackupError> {
        let Some(member) = material.member.as_deref() else {
            return Ok(());
        };
        let bytes = match std::fs::read(member) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(BackupError::RestoreJournalCorrupt);
            }
            Err(error) => return Err(BackupError::Target(error.to_string())),
        };
        if material.receipt_digests_member && sha256_hex(&bytes) != evidence_sha256 {
            return Err(BackupError::RestoreJournalMismatch);
        }
        Ok(())
    }

    /// Reads one phase's recovered observation back off the destination.
    ///
    /// A present receipt bound to this transaction, phase and input digest is
    /// only `Applied` when the material it attests is STILL THERE and, where
    /// the receipt's `evidence_sha256` is that material's digest, is still the
    /// same bytes ([`Self::check_attested_material`]). Validating a receipt's
    /// own digests against themselves is not a weaker form of this check, it is
    /// the substitution being fixed: a receipt is a description, and a
    /// description is not its own evidence.
    ///
    /// A MISSING receipt is not the same fact, and it is not a proven no-effect
    /// verdict. The engine reaches `IntentPersisted` before the phase executes
    /// and calls this reconciliation first, so a crash inside the phase leaves
    /// the receipt absent while the phase's own material may already be
    /// published and, since [`Self::write_file`], already durable. The
    /// phase-specific question is therefore asked of the material
    /// ([`Self::phase_material_published`]), never of the receipt's absence:
    ///
    /// - material PRESENT means the phase DID publish. That is positive
    ///   evidence of an effect and never of no-effect, and the receipt that
    ///   would have described it is gone, so the observation cannot be
    ///   reconstructed. The state is [`ObservedEffect::Undecidable`], so the
    ///   engine pauses this Ordering Scope, keeps the intent and opens a
    ///   Problem State rather than duplicating a published effect (I14.21).
    /// - material ABSENT means the phase produced nothing durable. Every phase
    ///   here publishes exactly the member [`Self::phase_material`] names and
    ///   nothing else, and that member is flushed to stable storage before the
    ///   receipt is written, so a phase that had completed would have left it
    ///   behind. That is the phase-specific positive no-effect evidence this
    ///   target holds, and only it returns [`ObservedEffect::NotAttempted`].
    ///
    /// The receipt test itself is a FALLIBLE READ, not an existence probe:
    /// `Path::exists()` collapses a missing file, a permission denial and a
    /// broken path into one silent `false`, so inaccessible evidence would be
    /// reported as evidence of absence and the phase would be re-applied over
    /// it. Only `NotFound` means "no receipt" here; every other error refuses,
    /// because a refusal is a fact the coordinator can act on and a false
    /// absence is not. Unparseable bytes remain [`ObservedEffect::Undecidable`]
    /// so the coordinator takes its explicit rollback-required disposition
    /// (I14.21).
    fn load_applied(&self, intent: &RestoreIntent) -> Result<ObservedEffect, BackupError> {
        let path = self.phase_receipt_path(&intent.phase)?;
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return if self.phase_material_published(&intent.phase)? {
                    Ok(ObservedEffect::Undecidable)
                } else {
                    Ok(ObservedEffect::NotAttempted)
                };
            }
            // Inaccessible receipt state is not absence: it is a refusal.
            Err(error) => return Err(BackupError::Target(error.to_string())),
        };
        let applied: RestoreAppliedEffect = match serde_json::from_slice(&bytes) {
            Ok(applied) => applied,
            // Torn or foreign bytes: the effect state cannot be established
            // from this observation. Propagate Unknown so the coordinator
            // takes the explicit rollback-required disposition (I14.21);
            // never guess, never blind-retry.
            Err(_) => return Ok(ObservedEffect::Undecidable),
        };
        if applied.receipt.transaction_id != intent.transaction_id
            || applied.receipt.phase != intent.phase
            || applied.receipt.input_digest != intent.input_digest
        {
            return Err(BackupError::RestoreJournalCorrupt);
        }
        // A receipt is a description of an effect, not the effect: it is only
        // evidence of a phase that ran if the material it names is still there.
        Self::check_attested_material(
            &self.phase_material(&intent.phase)?,
            &applied.receipt.evidence_sha256,
        )?;
        Ok(ObservedEffect::Applied(Box::new(applied)))
    }

    /// Re-verifies the pinned destination admission before a post-prepare
    /// effect. Unadmitted restores skip; admitted ones require the exact
    /// pinned transaction, target, rehearsal posture, and manifest evidence —
    /// any drift refuses the effect instead of continuing under changed
    /// authority.
    fn check_destination_admission(
        &self,
        intent: &RestoreIntent,
        plan_target_id: &str,
    ) -> Result<(), BackupError> {
        let Some(expected) = self.manifest_evidence.as_ref() else {
            return Ok(());
        };
        let bytes = std::fs::read(self.root.join(DESTINATION_ADMISSION_FILE))
            .map_err(|_| BackupError::RestoreJournalCorrupt)?;
        let pinned: PinnedDestinationAdmission =
            serde_json::from_slice(&bytes).map_err(|_| BackupError::RestoreJournalCorrupt)?;
        if pinned.transaction_id != intent.transaction_id
            || pinned.target_id != plan_target_id
            || pinned.rehearsal != self.rehearsal
            || pinned.evidence != *expected
        {
            return Err(BackupError::FenceMismatch {
                subject: "destination admission".to_owned(),
            });
        }
        Ok(())
    }

    fn find_blob<'b>(bundle: &'b BackupBundle, hash: &str) -> Result<&'b BackupBlob, BackupError> {
        bundle
            .blobs
            .iter()
            .find(|blob| blob.locator.hash.as_str() == hash)
            .ok_or(BackupError::PlanMismatch)
    }

    fn find_event<'b>(
        records: &'b [CanonicalRecord],
        record_id: &str,
    ) -> Result<&'b CanonicalRecord, BackupError> {
        records
            .iter()
            .find(|record| record.record_id == record_id)
            .ok_or(BackupError::PlanMismatch)
    }

    fn staged_bytes(&self, relative: &str) -> Result<Vec<u8>, BackupError> {
        std::fs::read(self.root.join(relative))
            .map_err(|error| BackupError::Target(error.to_string()))
    }

    fn count_dir(&self, relative: &str) -> Result<usize, BackupError> {
        let path = self.root.join(relative);
        if !path.exists() {
            return Ok(0);
        }
        let mut count = 0;
        let entries =
            std::fs::read_dir(&path).map_err(|error| BackupError::Target(error.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|error| BackupError::Target(error.to_string()))?;
            if entry
                .file_type()
                .map_err(|error| BackupError::Target(error.to_string()))?
                .is_file()
            {
                count += 1;
            }
        }
        Ok(count)
    }

    fn apply_prepare(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.prepare_isolated(&plan.target, &plan.restored_fence)?;
        self.gate(bundle)?;
        if let Some(evidence) = self.manifest_evidence.clone() {
            let pinned = PinnedDestinationAdmission {
                transaction_id: intent.transaction_id.clone(),
                target_id: plan.target.target_id.clone(),
                evidence,
                rehearsal: self.rehearsal,
            };
            let bytes = canonical_json_bytes(&pinned)
                .map_err(|error| BackupError::Serialization(error.to_string()))?;
            self.write_file(DESTINATION_ADMISSION_FILE, &bytes)?;
        }
        let observed = ObservedPrepare {
            transaction_id: intent.transaction_id.clone(),
            plan_id: plan.plan_id.clone(),
            destination: self.root.to_string_lossy().into_owned(),
            outcome: "prepared".to_owned(),
        };
        let evidence_bytes = canonical_json_bytes(&observed)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push("prepare".to_owned());
        Ok(applied)
    }

    fn apply_blob(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
        hash: &str,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        let blob = Self::find_blob(bundle, hash)?;
        let client = BlobOwnerClient::bind(self.receipts.clone(), self.keys, self.blob_scope)?;
        let adapter = DestinationRestoreAdapter::bind(self.root.as_path())?;
        let restored: RestoredSealedBlob = client.restore_blob(&adapter, blob)?;
        self.write_file(&format!("blobs/{hash}"), &restored.resealed_bytes)?;
        let observed = ObservedBlobRestore {
            resealed_sha256: restored.resealed_sha256.clone(),
            receipt_id: restored.receipt_id.clone(),
            key_lineage: restored.key_lineage.clone(),
            source_plaintext_sha256: restored.source_plaintext_sha256.clone(),
        };
        let evidence_bytes = canonical_json_bytes(&observed)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push(format!("blob:{hash}"));
        Ok(applied)
    }

    fn apply_event(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
        record_id: &str,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        let record = Self::find_event(&bundle.canonical_events, record_id)?;
        self.import_canonical_event(record)?;
        let evidence_bytes = self.staged_bytes(&format!("events/{record_id}.json"))?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push(format!("event:{record_id}"));
        Ok(applied)
    }

    fn apply_receipt_phase(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
        operation_id: &str,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        let receipt = bundle
            .receipts
            .iter()
            .find(|receipt| receipt.operation_id.as_str() == operation_id)
            .ok_or(BackupError::PlanMismatch)?;
        self.import_receipt(receipt)?;
        let evidence_bytes = self.staged_bytes(&format!("receipts/{operation_id}.json"))?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push(format!("receipt:{operation_id}"));
        Ok(applied)
    }

    fn apply_projection(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
        record_id: &str,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        let record = Self::find_event(&bundle.projections, record_id)?;
        self.import_projection(record)?;
        let evidence_bytes = self.staged_bytes(&format!("projections/{record_id}.json"))?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push(format!("projection:{record_id}"));
        Ok(applied)
    }

    fn apply_suspend(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        let snapshot = bundle
            .ors_snapshot
            .as_ref()
            .ok_or(BackupError::PlanMismatch)?;
        self.suspend_ors_operations(snapshot)?;
        let evidence_bytes = self.staged_bytes("suspended_ors.json")?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push("suspend-ors".to_owned());
        Ok(applied)
    }

    fn apply_rebuild(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        if self.count_dir("blobs")? != bundle.blobs.len()
            || self.count_dir("events")? != bundle.canonical_events.len()
            || self.count_dir("receipts")? != bundle.receipts.len()
            || self.count_dir("projections")? != bundle.projections.len()
        {
            return Err(BackupError::RestoreEvidenceIncomplete);
        }
        let marker = serde_json::json!({
            "blobs": bundle.blobs.len(),
            "events": bundle.canonical_events.len(),
            "receipts": bundle.receipts.len(),
            "projections": bundle.projections.len(),
        });
        let evidence_bytes = serde_json::to_vec(&marker)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file("rebuild.json", &evidence_bytes)?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push("rebuild".to_owned());
        Ok(applied)
    }

    fn apply_verify(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        self.verify_receipt_event_chain(&bundle.receipts, &bundle.canonical_events)?;
        let marker = serde_json::json!({
            "verified": true,
            "receipts": bundle.receipts.len(),
            "events": bundle.canonical_events.len(),
        });
        let evidence_bytes = serde_json::to_vec(&marker)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file("verify.json", &evidence_bytes)?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push("verify".to_owned());
        Ok(applied)
    }

    fn apply_purge_phase(
        &mut self,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        // Revocation-ledger barrier (I12.20 S1, issue #1732): a recorded
        // revocation refuses before the purge ledger is staged and long
        // before any import, so no revoked lineage can resurrect.
        gate_revocation_ledger(bundle)?;
        self.apply_purge_ledger(&bundle.purge_ledger)?;
        let evidence_bytes = self.staged_bytes("purge_ledger.json")?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: None,
        };
        self.persist_applied(intent, &applied)?;
        self.calls.push("purge".to_owned());
        Ok(applied)
    }

    #[allow(clippy::too_many_lines)]
    fn apply_phase(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        match &intent.phase {
            RestorePhase::Pending => Err(BackupError::RestorePhaseMismatch),
            RestorePhase::PrepareIsolatedRoot => self.apply_prepare(plan, bundle, intent),
            RestorePhase::ApplyPurgeLedger => self.apply_purge_phase(bundle, intent),
            RestorePhase::ImportSealedBlob { hash } => self.apply_blob(bundle, intent, hash),
            RestorePhase::ImportCanonicalEvent { record_id } => {
                self.apply_event(bundle, intent, record_id)
            }
            RestorePhase::ImportReceipt { operation_id } => {
                self.apply_receipt_phase(bundle, intent, operation_id)
            }
            RestorePhase::ImportProjection { record_id } => {
                self.apply_projection(bundle, intent, record_id)
            }
            RestorePhase::SuspendOrsOperations => self.apply_suspend(bundle, intent),
            RestorePhase::RebuildProjections => self.apply_rebuild(bundle, intent),
            RestorePhase::VerifyReceiptEventChain => self.apply_verify(bundle, intent),
            RestorePhase::FinalizeIsolatedRoot => self.apply_finalize(plan, bundle, intent),
        }
    }

    fn obligation(
        owner_id: &str,
        evidence_ref: String,
        state: RestoreObligationState,
    ) -> RestoreOwnerObligation {
        RestoreOwnerObligation {
            owner_id: owner_id.to_owned(),
            evidence_ref,
            state,
        }
    }

    /// Reads the persisted phase-receipt digest for one obligation group.
    ///
    /// Every phase the coordinator journaled as receipt-persisted left its
    /// observed applied record under the destination; a journaled effect
    /// without its observation is corruption, never success.
    fn group_ref(&self, phases: &[RestorePhase]) -> Result<String, BackupError> {
        let mut digests = Vec::with_capacity(phases.len());
        for phase in phases {
            let path = self.phase_receipt_path(phase)?;
            let bytes = std::fs::read(&path).map_err(|_| BackupError::RestoreJournalCorrupt)?;
            digests.push(sha256_hex(&bytes));
        }
        Ok(format!(
            "kernel-restore-phase-receipt:{}",
            sha256_hex(digests.join(",").as_bytes())
        ))
    }

    fn canonical_phases(bundle: &BackupBundle) -> Vec<RestorePhase> {
        let mut phases = Vec::new();
        phases.extend(bundle.canonical_events.iter().map(|record| {
            RestorePhase::ImportCanonicalEvent {
                record_id: record.record_id.clone(),
            }
        }));
        phases.extend(
            bundle
                .receipts
                .iter()
                .map(|receipt| RestorePhase::ImportReceipt {
                    operation_id: receipt.operation_id.as_str().to_owned(),
                }),
        );
        phases.extend(
            bundle
                .projections
                .iter()
                .map(|record| RestorePhase::ImportProjection {
                    record_id: record.record_id.clone(),
                }),
        );
        phases.push(RestorePhase::RebuildProjections);
        phases.push(RestorePhase::VerifyReceiptEventChain);
        phases
    }

    #[allow(clippy::too_many_lines)]
    fn apply_finalize(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
        let purge_ref = self.group_ref(&[RestorePhase::ApplyPurgeLedger])?;
        let canonical = Self::canonical_phases(bundle);
        let canonical_ref = self.group_ref(&canonical)?;
        let blob_phases: Vec<RestorePhase> = bundle
            .blobs
            .iter()
            .map(|blob| RestorePhase::ImportSealedBlob {
                hash: blob.locator.hash.as_str().to_owned(),
            })
            .collect();
        let blob_obligation = if blob_phases.is_empty() {
            Self::obligation(
                owners::BLOB,
                "kernel-restore:archive-carries-no-blobs".to_owned(),
                RestoreObligationState::NotAttempted,
            )
        } else {
            let blob_ref = self.group_ref(&blob_phases)?;
            Self::obligation(owners::BLOB, blob_ref, RestoreObligationState::Satisfied)
        };
        let ors_obligation = if bundle.ors_snapshot.is_some() {
            let ors_ref = self.group_ref(&[RestorePhase::SuspendOrsOperations])?;
            Self::obligation(owners::ORS, ors_ref, RestoreObligationState::Satisfied)
        } else {
            Self::obligation(
                owners::ORS,
                "kernel-restore:archive-carries-no-ors-snapshot".to_owned(),
                RestoreObligationState::NotAttempted,
            )
        };
        let missing = |owner_id: &str| {
            Self::obligation(
                owner_id,
                format!("kernel-restore:unbound:{owner_id}"),
                RestoreObligationState::MissingCapability,
            )
        };
        // An archive that carried no purge entry established no privacy-purge
        // closure for this restore: the purge phase applied nothing, so there is
        // no purge effect of this restore for `owners::PURGE` to attest, and a
        // phase receipt over an empty ledger is a receipt that says "nothing was
        // purged", not a closure. Publishing `Satisfied` here on the strength
        // of the caller's own emptiness is the substitution this restore must
        // not make — do not fill a missing obligation with `Satisfied` to make
        // the slice return success — and it is the shape the two neighbouring
        // slots above already refuse. The obligation is therefore reported as
        // not established in the existing unbound-owner vocabulary, and
        // `require_cutover_obligations` refuses this slot on that state rather
        // than accepting a closure no owner issued. The revision itself was
        // still reconciled against the purge owner before any evidence was
        // staged (see [`check_purge_revision_closure`]); that reconciliation
        // is not a substitute for a purge effect that never happened.
        let purge_obligation = if bundle.purge_ledger.is_empty() {
            missing(owners::PURGE)
        } else {
            Self::obligation(owners::PURGE, purge_ref, RestoreObligationState::Satisfied)
        };
        let obligations = RestoreObligations {
            purge: purge_obligation,
            canonical_validation: Self::obligation(
                owners::CANONICAL,
                canonical_ref.clone(),
                RestoreObligationState::Satisfied,
            ),
            reference_validation: Self::obligation(
                owners::REFERENCE,
                canonical_ref,
                RestoreObligationState::Satisfied,
            ),
            blob_validation: blob_obligation,
            ors_suspension: ors_obligation,
            unresolved_effect_reconciliation: Self::obligation(
                owners::RECONCILIATION,
                "kernel-restore:reconciliation-denominator-absent".to_owned(),
                RestoreObligationState::Unknown,
            ),
            // The state stays `MissingCapability`, and that is the point of the
            // read above rather than a leftover: reading the archive's fence
            // RECONCILES nothing. Reconciliation is the #955 owner's decision
            // and no Watchdog channel is bound here, so nothing in this
            // composition can attest the signals were resolved, and I05.13 is
            // explicit that suspension is not resolution. Marking this slot
            // `Satisfied` on the strength of a member the restore merely read
            // would publish exactly the false readiness the obligation
            // vocabulary exists to prevent.
            //
            // What the read DOES change is the evidence: the published
            // evidence_ref now names the fence this restore actually read, and
            // its unresolved signals are carried as suspended historical
            // entries. It was one constant before, byte-identical for a fence
            // naming zero unreconciled critical signals and for one naming a
            // thousand, so a reader could not tell a read archive from a
            // dropped one.
            watchdog_signals: Self::obligation(
                owners::WATCHDOG,
                match &bundle.watchdog_spool {
                    Some(fence) => format!(
                        "kernel-restore:watchdog-spool-read:{}:{}",
                        fence.fence_id,
                        fence.unresolved_signal_digests.len()
                    ),
                    None => format!("kernel-restore:unbound:{}", owners::WATCHDOG),
                },
                RestoreObligationState::MissingCapability,
            ),
            external_source_revalidation: missing(owners::EXTERNAL_SOURCE),
            runtime_invalidation: missing(owners::RUNTIME),
            session_invalidation: missing(owners::SESSION),
            lease_invalidation: missing(owners::LEASE),
            route_invalidation: missing(owners::ROUTE),
            user_broker_invalidation: missing(owners::USER_BROKER),
        };
        let build_digest = bundle
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == "host_dependency_build")
            .map_or_else(
                || bundle.manifest.integrity_sha256.clone(),
                |artifact| artifact.sha256.clone(),
            );
        let validation_bytes =
            canonical_json_bytes(&(plan.plan_id.as_str(), bundle.bundle_sha256()?.as_str()))
                .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let owner = OwnerTrustBinding {
            owner_id: "kernel-restore-owner".to_owned(),
            trust_binding_ref: "trust-binding-kernel-restore-owner-restore-1".to_owned(),
        };
        let evidence = RestoreEvidence {
            target_id: plan.target.target_id.clone(),
            isolated_root: true,
            purge_applied: true,
            blobs_imported: true,
            projections_rebuilt: true,
            receipt_event_chain_verified: true,
            ors_suspended: bundle.ors_snapshot.is_some(),
            active_authority_restored: false,
            authority_epoch: plan.restored_fence.authority_epoch.clone(),
            resource_generation: plan.restored_fence.resource_generation,
            provenance: RestoreProvenance {
                transaction_id: intent.transaction_id.clone(),
                plan_id: plan.plan_id.clone(),
                operation_id: format!("restore-operation-{}", plan.plan_id),
                phase: RestorePhase::FinalizeIsolatedRoot,
                source_archive_id: bundle.manifest.backup_id.clone(),
                source_class: bundle.manifest.class,
                source_digest: bundle.bundle_sha256()?,
                source_endpoint_ref: bundle.manifest.source_adapter.clone(),
                isolated_destination_ref: plan.target.target_id.clone(),
                // The predecessor binding lives in the injected journal's
                // CAS chain (surfaced in the outcome's journal_owner
                // binding), not in this target observation.
                expected_predecessor_ref: "none".to_owned(),
                schema_revision: bundle.manifest.schema_generation.clone(),
                build_manifest_digest: build_digest,
                purge_ledger_revision: bundle.manifest.purge_ledger_revision,
                owner: owner.clone(),
                observed_generation: plan.restored_fence.resource_generation,
                observed_epoch: plan.restored_fence.authority_epoch.clone(),
                validation_digest: sha256_hex(&validation_bytes),
            },
            obligations,
            observed_lineage_limits: vec![ObservedLineageLimit {
                owner_id: owner.owner_id.clone(),
                observed_epoch: bundle.export_fence.state_fence.authority_epoch.clone(),
                observed_generation: bundle.export_fence.state_fence.resource_generation,
            }],
            owner_epoch: None,
            reconciliation_denominator: None,
            operational_validation: None,
            historical_authority: historical_authority(bundle)?,
            archive_disposition: RestoreArchiveDisposition {
                disposition: RestoreArchiveDispositionKind::Current,
                compatibility_ref: "ecxf-1-current".to_owned(),
            },
        };
        evidence.validate()?;
        let evidence_bytes = canonical_json_bytes(&evidence)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file(RESTORE_EVIDENCE_FILE, &evidence_bytes)?;
        let applied = RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, &evidence_bytes)?,
            final_evidence: Some(evidence.clone()),
        };
        self.persist_applied(intent, &applied)?;
        self.final_evidence = Some(evidence);
        self.calls.push("finalize".to_owned());
        Ok(applied)
    }
}

impl RestoreTarget for KernelRestoreTarget<'_> {
    fn prepare_isolated(
        &mut self,
        context: &RestoreContext,
        restored_fence: &RestoredFence,
    ) -> Result<(), BackupError> {
        context.validate()?;
        restored_fence.validate()?;
        for dir in [
            "blobs",
            "events",
            "receipts",
            "projections",
            "phase-receipts",
        ] {
            std::fs::create_dir_all(self.root.join(dir))
                .map_err(|error| BackupError::Target(error.to_string()))?;
        }
        Ok(())
    }

    fn apply_purge_ledger(&mut self, entries: &[PurgeLedgerEntry]) -> Result<(), BackupError> {
        PurgeOwnerClient::bind(entries).validate_entries()?;
        let (owner_revision, applied) = self.apply_purge_entries(entries)?;
        // The archive's declared revision and the ledger position the OWNER
        // itself reports for its own applied ledger are two readings of one
        // quantity, so they are compared here — after the owner answered, and
        // BEFORE this phase stages the evidence document that carries the
        // answer. A disagreement therefore never becomes a staged phase
        // receipt, and it is never published as the restore's
        // `provenance.purge_ledger_revision`.
        check_purge_revision_closure(
            self.declared_purge_ledger_revision,
            owner_revision,
            entries,
            &applied,
        )?;
        self.applied_purge_revisions = applied;
        // The staged document is this phase's evidence, so the owner-issued
        // revisions ride the SAME effect evidence every other phase already
        // carries: `apply_purge_phase` digests exactly these bytes into its
        // phase receipt, and finalize binds that receipt through
        // `group_ref` into the purge obligation the restore evidence
        // publishes. Nothing here recomputes a revision or counts entries to
        // stand in for one.
        let observed = ObservedPurgeApplication {
            entries: entries.to_vec(),
            applied: self.applied_purge_revisions.clone(),
        };
        let bytes = canonical_json_bytes(&observed)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file("purge_ledger.json", &bytes)?;
        Ok(())
    }

    fn import_sealed_blob(&mut self, _blob: &BackupBlob) -> Result<(), BackupError> {
        // The legacy single-argument form cannot carry the restoration
        // receipt, the admitted key manifest, or the destination scope that
        // destination-owned re-sealing requires: refusing here instead of
        // staging sealed bytes without ownership. The journaled apply path
        // supplies the full binding.
        Err(BackupError::RestoreCapabilityUnsupported {
            capability: owners::BLOB_SCOPE_BINDING,
        })
    }

    fn import_canonical_event(&mut self, record: &CanonicalRecord) -> Result<(), BackupError> {
        CanonicalOwnerClient::validate_event(record)?;
        let bytes = canonical_json_bytes(&record.payload)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file(&format!("events/{}.json", record.record_id), &bytes)?;
        Ok(())
    }

    fn import_receipt(&mut self, receipt: &WriteReceipt) -> Result<(), BackupError> {
        CanonicalOwnerClient::validate_receipt(receipt)?;
        let bytes = canonical_json_bytes(receipt)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file(
            &format!("receipts/{}.json", receipt.operation_id.as_str()),
            &bytes,
        )?;
        Ok(())
    }

    fn import_projection(&mut self, record: &CanonicalRecord) -> Result<(), BackupError> {
        CanonicalOwnerClient::validate_event(record)?;
        let bytes = canonical_json_bytes(&record.payload)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file(&format!("projections/{}.json", record.record_id), &bytes)?;
        Ok(())
    }

    fn suspend_ors_operations(&mut self, snapshot: &OrsSnapshotFence) -> Result<(), BackupError> {
        let entries = OrsOwnerClient::suspend(snapshot)?;
        let bytes = canonical_json_bytes(&entries)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file("suspended_ors.json", &bytes)?;
        Ok(())
    }

    fn rebuild_projections(&mut self, _restored_fence: &RestoredFence) -> Result<(), BackupError> {
        // The legacy form lacks the bundle counts that make a rebuild claim
        // verifiable; the journaled apply path verifies observed destination
        // state instead of attesting an unanchorable marker.
        Err(BackupError::RestoreCapabilityNotAttempted {
            capability: "projection-rebuild-counts",
        })
    }

    fn verify_receipt_event_chain(
        &mut self,
        receipts: &[WriteReceipt],
        events: &[CanonicalRecord],
    ) -> Result<(), BackupError> {
        CanonicalOwnerClient::verify_chain(receipts, events)
    }

    fn finalize_isolated(
        &mut self,
        _restored_fence: &RestoredFence,
    ) -> Result<RestoreEvidence, BackupError> {
        // Plan-bound evidence (plan/bundle identity, transaction digests,
        // obligation receipts) cannot be assembled from the fence alone: the
        // receipt-bearing apply path assembles it instead. Legacy callers
        // must migrate to that seam rather than receive unbound evidence.
        Err(BackupError::RestoreTargetReceiptRequired)
    }

    fn apply_restore_effect(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        if intent.transaction_id.is_empty() {
            return Err(BackupError::RestoreJournalCorrupt);
        }
        if !matches!(
            intent.phase,
            RestorePhase::Pending | RestorePhase::PrepareIsolatedRoot
        ) {
            self.check_destination_admission(intent, plan.target.target_id.as_str())?;
        }
        self.apply_phase(plan, bundle, intent)
    }

    fn reconcile_restore_effect(
        &mut self,
        intent: &RestoreIntent,
    ) -> Result<RestoreReconciliation, BackupError> {
        // Every effect in this target is synchronous and local with one
        // persisted identity receipt per phase, so reconciliation reads the
        // observation back by exact identity AND re-reads the material that
        // receipt attests (`load_applied` / `check_attested_material`). A
        // present receipt bound to this transaction, phase and input digest,
        // and still describing material that is still there, is Applied. A
        // receipt is a description of an effect, not the effect, so a receipt
        // whose material was removed — or that now names bytes other than the
        // ones on disk — refuses rather than advancing the journal over a phase
        // that never produced what the journal and the finalize obligations say
        // it produced (A13.7 ARCH-RES-03).
        //
        // Its ABSENCE is never a proven no-effect by itself. Only the absence
        // of the phase's own material is, because that member is the phase's
        // entire durable effect and `write_file` flushes it to stable storage
        // before any receipt that could describe it is written; there the
        // coordinator re-applies idempotently (byte staging overwrites,
        // re-sealing mints fresh bytes with a fresh receipt — no prior receipt
        // exists to contradict). A missing receipt over material that IS
        // published is evidence of an effect whose observation was lost, so it
        // is Undecidable, not NotApplied, and both the receipt test and the
        // material test are fallible reads — a permission denial is a refusal,
        // never a fabricated no-effect. Bytes that parse as nothing are
        // likewise Undecidable and propagate as Unknown: the coordinator takes
        // the explicit rollback-required disposition (I14.21) with no new
        // identity and no blind duplicate effect. Async owner-channel unknowns
        // belong to the #962 wire layer, which must upgrade reconciliation
        // there, never downgrade readback here.
        match &intent.phase {
            RestorePhase::Pending => Err(BackupError::RestorePhaseMismatch),
            _ => match self.load_applied(intent)? {
                ObservedEffect::Applied(applied) => Ok(RestoreReconciliation::Applied(*applied)),
                ObservedEffect::NotAttempted => Ok(RestoreReconciliation::NotApplied),
                ObservedEffect::Undecidable => Ok(RestoreReconciliation::Unknown),
            },
        }
    }
}

/// Carries the owner-issued admission into the execution body.
///
/// Every other field is the caller's, moved across unchanged, so the ONLY
/// difference between the bundle the caller presented and the bundle the
/// restore runs on is the journal admission — and that one field is the value
/// the durable owner issued for this exact plan. Nothing is defaulted and no
/// field is dropped: an absent key manifest, blob scope or destination evidence
/// stays absent, because "rehearsal without Host admission" is a supported
/// production shape and inventing an empty stand-in for one would change the
/// gate.
fn admitted_restore_ports<'a>(
    ports: &'a RestorePorts<'_>,
    admission: &'a RestoreJournalAdmission,
) -> RestorePorts<'a> {
    RestorePorts {
        journal_admission: admission,
        kernel_fence: ports.kernel_fence,
        keys: ports.keys,
        blob_scope: ports.blob_scope,
        manifest_evidence: ports.manifest_evidence.clone(),
        rehearsal: ports.rehearsal,
    }
}

/// Rejects a journal binding that names a different source, class or
/// destination than the archive and target actually being restored (issue
/// #960).
///
/// The ORS binding is what every journal row is keyed to, so a binding that
/// disagrees with the archive would file this transaction's durable rows under
/// another source's, another class's or another destination's stream while the
/// effects land in this target. The comparison is exact equality against the
/// archive's own declared identity, never a normalisation that could make two
/// different values compare equal.
///
/// The owner-issued admission is compared here too, and this is the check that
/// carries W1's "production cannot substitute an in-memory or no-op port".
/// [`require_production_admitted`](super::backup_restore_ports::require_production_admitted)
/// alone only proves an admission VALUE is well-formed and not fixture-flagged;
/// it says nothing about which journal the execution then ran on, because
/// `restore` takes its `J` as a parameter. Requiring the admission's
/// `journal_identity_ref` to be [`RESTORE_JOURNAL_IDENTITY`] is what makes the
/// presented admission and the journal actually executing the same owner
/// channel: that constant is the exact namespace this adapter's ORS rows are
/// filed under and the identity composition is required to place in the
/// admission it issues. An admission for any other journal identity, including
/// one describing an in-process store, refuses before a single effect runs.
///
/// This field carries the CHANNEL and only the channel. It cannot also carry
/// the per-execution stream key: that key is
/// `sha256(plan_id, bundle_sha256)` and differs for every plan/bundle pair, so
/// requiring the two to be equal refused every owner-issued admission — the
/// constant here and the derived key in the issuer's re-proof were mutually
/// exclusive requirements on one field, and the route was dead in both
/// directions. The per-execution guarantee is not dropped and is not weaker: it
/// is proved where the derivation lives, in
/// [`RestoreJournalAdmission::binds_owner_record`](eliot_backup::RestoreJournalAdmission::binds_owner_record),
/// which reads the live journal UNDER this plan's own stream key and requires
/// that row to hold this plan's own transaction before it compares any owner
/// field, and which compares the owner record read under that same key.
/// `admit_restore_journal` runs that check for every admission this coordinator
/// issues, so both facts are proved on every production restore.
fn check_ors_journal_binding(
    bundle: &BackupBundle,
    target: &RestoreContext,
    ports: &RestorePorts<'_>,
    identity: &OrsRestoreBinding,
) -> Result<(), KernelRestoreError> {
    // The durable CHANNEL identity. `OrsRestoreJournalOwner::durable_journal_record`
    // reports this exact constant, so an owner-issued admission passes it; any
    // other journal identity — including one describing an in-process store or
    // a second database — refuses before a single effect runs.
    //
    // This is a live comparison against a value the owner actually issues, and
    // it is the only field check here: the composition ALSO proves the
    // per-execution stream, in the issuer's own re-proof, and it does not do so
    // by making this channel field equal a per-plan digest. See the function
    // doc for why one field cannot carry both.
    if ports.journal_admission.journal_identity_ref != RESTORE_JOURNAL_IDENTITY {
        return Err(KernelRestoreError::OwnerEvidenceInvalid(
            "restore journal admission does not name the durable ORS restore journal".to_owned(),
        ));
    }
    if identity.source_archive_id() != bundle.manifest.backup_id {
        return Err(KernelRestoreError::OwnerEvidenceInvalid(
            "restore journal source archive does not name this archive".to_owned(),
        ));
    }
    if identity.destination_ref() != target.target_id {
        return Err(KernelRestoreError::OwnerEvidenceInvalid(
            "restore journal destination does not name this target".to_owned(),
        ));
    }
    // The writer that owns the durable rows must be the owner the admission
    // already authenticated for this journal. Without this, an admission for
    // one owner could file its durable rows under a different writer identity
    // while the outcome still reports the admitted owner.
    if identity.writer_id() != ports.journal_admission.persistent_owner.owner_id {
        return Err(KernelRestoreError::OwnerEvidenceInvalid(
            "restore journal writer does not match the admitted journal owner".to_owned(),
        ));
    }
    let declared = match bundle.manifest.class {
        BackupClass::FullRecovery => eliot_ors::RestoreJournalArchiveClass::FullRecovery,
        BackupClass::CanonicalOnlyDegraded => {
            eliot_ors::RestoreJournalArchiveClass::CanonicalOnlyDegraded
        }
        BackupClass::ScopeExport => eliot_ors::RestoreJournalArchiveClass::ScopeExport,
    };
    if identity.archive_class() != declared {
        return Err(KernelRestoreError::OwnerEvidenceInvalid(
            "restore journal archive class does not match the declared class".to_owned(),
        ));
    }
    Ok(())
}

/// Refuses an archive whose restore cannot fit the durable journal before any
/// effect runs (issue #960).
///
/// The single phase engine writes three journal records per phase (intent,
/// receipt, advance) plus two genesis records, and the ORS owner caps one
/// stream at its page ceiling. An archive past that ceiling would commit
/// records until the owner refuses the next append, and because the oldest
/// record is never resolved the stream can never be pruned, leaving a restore
/// that is permanently unprogressable rather than merely refused. The
/// denominator is computed from the archive's own member counts and checked
/// against the same ceiling the owner enforces, so the limit refuses the
/// archive up front instead of bricking it mid-run.
fn check_ors_journal_budget(bundle: &BackupBundle) -> Result<(), KernelRestoreError> {
    let members = archive_member_count(bundle);
    // Two fixed phases (prepare, purge) and three fixed tail phases (rebuild,
    // verify, finalize), plus the conditional ORS suspension phase.
    let phases = 5 + members;
    let records = 2usize
        .checked_add(phases.saturating_mul(3))
        .ok_or_else(|| {
            KernelRestoreError::ArchiveInvalid("restore journal budget overflowed".to_owned())
        })?;
    if records > MAX_JOURNAL_PAGE_ENTRIES {
        return Err(KernelRestoreError::CapabilityMissing {
            capability: "restore_journal_history_budget",
        });
    }
    Ok(())
}

/// Cross-checks the archive's declared purge-ledger revision against the ORS
/// purge-ledger OWNER's own durable counter (issue #960, A14: "current
/// purge/residency/reference closure preserved").
///
/// The restore evidence publishes
/// `provenance.purge_ledger_revision`, and `eliot_backup` REQUIRES that
/// published field to equal `bundle.manifest.purge_ledger_revision` — the
/// ARCHIVE's own declared revision
/// ([`RestoreEvidence::validate_against_plan`]).
/// That field is therefore copied from the manifest, and until this check the
/// owner's answer for the same quantity was never compared against it: two
/// independent numbers, one copied out of the archive under check and one
/// issued by the owner that applies the ledger. `A13.7` requires a restore to
/// verify privacy purge closure against the CURRENT owner, and
/// `I5.13:44` requires the manifest to bind the purge-ledger revision, so the
/// two must be cross-checked rather than one of them published unchecked.
///
/// `owner_revision` is that owner answer, and it is the ONLY owner answer this
/// check may use: the durable counter
/// [`RedbRecoveryStore::purge_ledger_revision`] reports, read through the
/// owner itself AFTER this phase applied the archive's ledger.
///
/// It is deliberately NOT the highest revision
/// [`RedbRecoveryStore::apply_purge_ledger_entry`] returned while applying the
/// entries. Those are the positions THIS restore allocated, in a ledger that was
/// already at some other position: on a destination that had applied purges
/// before, that maximum disagreed with the archive's declaration by exactly the
/// destination's prior count, so the phase refused for every archive carrying a
/// non-empty ledger and passed only where a virgin store's arithmetic happened
/// to agree. Comparing an archive's declaration against a copy of the caller's
/// own entry list is a completeness check with no owner behind it (`A14`), and
/// a coincidence is not evidence.
///
/// Nor is it the counter read BEFORE this phase applied anything. The archive's
/// declared revision is the position the SOURCE reached once it had applied its
/// own ledger, so it is a post-apply position; a pre-apply read is the position
/// the DESTINATION started from, and the two are different quantities. On a
/// rebuilt destination starting at 0, applying 7 entries correctly leaves the
/// owner at the declared 7, and a pre-apply read of 0 refuses a restore that did
/// exactly the right thing — after having already committed the whole ledger.
///
/// The compared values are therefore only ever the two legitimate ones: the
/// archive's declared `manifest.purge_ledger_revision`, and the revision the
/// owner reports for its own applied ledger. Nothing here computes, increments,
/// counts or derives a revision: there is no `+ 1`, no `wrapping_add`, no
/// counter and no use of an entry count as a revision.
///
/// The archive side is whatever its producer declared for that manifest field —
/// `elipt_backup` leaves the value to the producer and only refuses the
/// incoherent pairs — and it is never re-derived here. An archive whose
/// declared revision is not the revision the applying owner holds is therefore
/// refused at this check rather than published as a closure: this module does
/// not reconcile two producers' conventions and never rewrites either number
/// to make them agree.
///
/// The comparison is fail-closed in every direction:
///
/// * a count disagreement — the owner did not issue one revision for every
///   carried entry — refuses, so a phase that applied less than the archive
///   carries cannot pass as closure;
/// * an owner-issued revision of zero refuses, because the owner's own record
///   contract states an applied purge always consumes a NON-ZERO ledger
///   revision (`PurgeLedgerRecord::validate`); a zero is the owner's "nothing
///   was ever applied" answer, not an issued revision, and treating it as one
///   would be absence of proof read as proof;
/// * a declared revision that differs from the owner's own counter refuses —
///   both when the owner's ledger is AHEAD of the archive's declaration and
///   when it is BEHIND it. This is the same shape as the archive-side binding
///   `elipt_backup::BackupBundle::validate_class_requirements` already
///   enforces for this field, and as the owner-side answer comparison in
///   `eliot-host`'s `project_owner_bound`: a destination that does not hold
///   exactly the ledger position the archive declares is not a closed purge
///   position, and re-applying the archive's ledger into it would publish a
///   closure this restore never established;
/// * an owner that reported NO revision at all refuses, because `None` is not
///   a revision and must not stand in for agreement.
///
/// The refusal is the seam's existing typed
/// [`BackupError::FenceMismatch`] naming `purge ledger revision` — the same
/// variant and subject `elipt_backup` already uses when this field's binding
/// does not hold, so no new error variant and no second refusal style is
/// introduced here. It crosses the layer boundary through the existing
/// `BackupError` → `KernelRestoreError::TargetFailed` mapping
/// ([`backup_to_kernel`](super::backup_restore_ports::backup_to_kernel)), so
/// the cause stays typed and is never stringified.
///
/// ## An archive with no purge entry
///
/// An archive that carries no purge entry has no owner-issued per-entry
/// revision, so the per-entry completeness arm above has nothing to check. That
/// is a property of the emptiness itself and is NOT a cross-checked agreement.
///
/// What still has to hold is the DECLARED revision. It names the purge-ledger
/// position this archive was taken at; the destination holds that position only
/// if the purge owner reports it, and a ledger with nothing in it cannot put the
/// destination there. So the owner comparison above is not skipped for an empty
/// ledger: an owner that answered no revision at all — the absent-owner seam —
/// and a destination whose ledger position is not the declared one both refuse
/// with the same typed `FenceMismatch` naming `purge ledger revision`. `I5.13:44`
/// binds the purge-ledger revision into the receipt precisely so an unexplained
/// revision gap fails rather than reading as coherent.
///
/// An empty ledger therefore establishes no privacy-purge closure, and the
/// restore does not claim one: [`KernelRestoreTarget::apply_finalize`] reports
/// the purge obligation as NOT established for an archive that carried no purge
/// entry — the same posture its blob and ORS slots already take — instead of
/// publishing `Satisfied` on the strength of the caller's own emptiness.
fn check_purge_revision_closure(
    declared: u64,
    owner_revision: Option<u64>,
    entries: &[PurgeLedgerEntry],
    applied: &[AppliedPurgeRevision],
) -> Result<(), BackupError> {
    // One owner-issued revision per carried entry, and no owner-issued
    // revision may be the owner's own "nothing was applied" zero. This arm is
    // about the entries the archive actually carries: an archive carrying none
    // has no per-entry revision to expect, and `applied` is then empty by
    // construction because it is built only by iterating `entries`. A
    // completeness check is never performed against a copy of the caller's own
    // list, in this arm or the other.
    if !entries.is_empty()
        && (applied.len() != entries.len() || applied.iter().any(|record| record.revision == 0))
    {
        return Err(BackupError::FenceMismatch {
            subject: PURGE_LEDGER_REVISION_SUBJECT.to_owned(),
        });
    }
    // The owner's own durable counter, read through the owner before this phase
    // moved it, against the archive's declaration. `None` — the owner answered
    // with no revision at all — is compared as itself, so it refuses rather
    // than standing in for agreement.
    //
    // This comparison is NOT conditional on the ledger being non-empty. An
    // archive that carries no purge entry still DECLARES a purge-ledger
    // revision: that number names the ledger position the source was taken at,
    // and the destination holds that position only if the purge owner says so —
    // nothing this phase applied puts it there. So the declaration is
    // reconciled against the owner here in the empty arm exactly as it is for a
    // carried ledger, and an uncorroborated declaration — including one no owner
    // was ever asked about — refuses instead of being passed over.
    if owner_revision != Some(declared) {
        return Err(BackupError::FenceMismatch {
            subject: PURGE_LEDGER_REVISION_SUBJECT.to_owned(),
        });
    }
    Ok(())
}
