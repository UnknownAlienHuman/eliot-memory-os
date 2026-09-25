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
//! purge .................... purge owner (`apply_purge_ledger`, staged
//!                              purge-first before any import);
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
//! ```
//!
//! Effects whose bindings are absent refuse fail-closed with the exact
//! responsible capability; reconciliation answers from persisted identity
//! receipts (`Applied` on exact transaction/phase/input match, `NotApplied`
//! otherwise, `Unknown` only for undecidable bytes so the engine takes its
//! explicit rollback-required disposition). All effects here are synchronous
//! and local with a persisted identity receipt per phase, so no ambiguous
//! external commit exists in this target and no `Unknown` outcome is
//! manufactured: async owner-channel unknowns belong to the #962 wire layer,
//! which must upgrade reconciliation there, never downgrade readback to a
//! blind re-apply here.
//!
//! The durable journal is injected as `J: RestoreJournalPort` with
//! owner-issued [`RestoreJournalAdmission`](eliot_backup::RestoreJournalAdmission):
//! production refuses fixture-flagged or unadmitted journals, and this file
//! contains no in-memory or no-op journal type by construction. Cutover is
//! validated-only ([`KernelBackupRestore::qualify_cutover`]): no receipt is
//! minted here — authorization and execution belong to #961.
//!
//! Capability cell: Kernel restore ownership (isolated import execution).
//! Forbidden authority: no ORS row reinterpretation, no epoch minting, no
//! cutover, no activation/retirement of any installation, no second phase
//! engine, no archive/phase algorithm, no invented target methods, no
//! Value-based escapes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use eliot_backup::{
    BackupBlob, BackupBundle, BackupClass, BackupError, BlobRestorationReceipt, CanonicalRecord,
    CutoverAuthorization, DestinationRestoreAdapter, DestinationScope, OrsSnapshotFence,
    RestoreAppliedEffect, RestoreArchiveDisposition, RestoreArchiveDispositionKind, RestoreContext,
    RestoreEffectReceipt, RestoreEvidence, RestoreHistoricalAuthority, RestoreIntent,
    RestoreJournalPort, RestoreObligationState, RestoreObligations, RestoreOwnerObligation,
    RestorePhase, RestorePlan, RestoreReceipt, RestoreReconciliation, RestoreStep, RestoreTarget,
    RestoredFence, RestoredSealedBlob, WrappedKeyManifest, issue_restoration_receipts,
    suspended_recovery_entries, verify_key_coverage,
};
use eliot_backup::{ObservedLineageLimit, OwnerTrustBinding, RestoreProvenance};
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_ors::{MAX_JOURNAL_PAGE_ENTRIES, RedbRecoveryStore};
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::{RevocationHistoryPayload, WriteReceipt, parse_revocation_history_payload};
use serde::Serialize;

use super::backup_restore_ports::{
    DESTINATION_ADMISSION_FILE, DestinationManifestEvidence, KernelIsolatedDestination,
    KernelRestoreError, OrsRestoreBinding, OrsRestoreJournal, PinnedDestinationAdmission,
    RESTORE_EVIDENCE_FILE, RESTORE_ISOLATED_AREA, RESTORE_JOURNAL_PAYLOAD_AREA, RestorePorts,
    StagedCleanupRefusal, check_kernel_effect_fence, require_production_admitted,
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
    /// Whether owner-issued new-epoch evidence was present and validated.
    pub owner_epoch_present: bool,
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
    /// [`restore`](Self::restore) stays available with its injected `J` seam
    /// unchanged: this method is an additional production entry over the same
    /// single phase engine, not a second engine and not a fallback.
    pub fn restore_with_ors_journal(
        &self,
        ors: &std::sync::Arc<RedbRecoveryStore>,
        bundle: &BackupBundle,
        target: RestoreContext,
        ports: &RestorePorts<'_>,
        identity: &OrsRestoreBinding,
    ) -> Result<KernelRestoreOutcome, KernelRestoreError> {
        check_ors_journal_binding(bundle, &target, ports, identity)?;
        check_ors_journal_budget(bundle)?;
        let mut journal = OrsRestoreJournal::production(
            std::sync::Arc::clone(ors),
            ports.kernel_fence,
            identity.clone(),
            self.work_root
                .join(".eliot")
                .join(RESTORE_JOURNAL_PAYLOAD_AREA),
        )?;
        self.restore(bundle, target, ports, &mut journal)
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
    #[allow(clippy::too_many_lines)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "RestoreContext is moved into compile_plan and the isolated destination; the by-value seam keeps the single audited validation gate"
    )]
    pub fn restore<J: RestoreJournalPort>(
        &self,
        bundle: &BackupBundle,
        target: RestoreContext,
        ports: &RestorePorts<'_>,
        journal: &mut J,
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
            verify_key_coverage(&bundle.blobs, manifest)
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
            ports.manifest_evidence.as_ref(),
        )?;
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
            KernelRestoreTarget::new(&self.work_root, &destination, bundle, ports, receipts)
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
        let suspended = suspended_entries(bundle)?;
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

    /// Refuses a destination pinned to a different transaction, target, or
    /// manifest evidence, and corrupt pinned admissions.
    ///
    /// A pinned admission for the exact current transaction, target, and
    /// evidence resumes; anything else pinned refuses as foreign or drifted
    /// instead of continuing the old transaction under new authority. An
    /// unpinned destination proceeds: it is either fresh or a pre-prepare
    /// crash whose byte staging the engine re-applies idempotently.
    fn refuse_foreign_destination(
        destination: &KernelIsolatedDestination,
        transaction_id: &str,
        target_id: &str,
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
    /// Owner-issued new-epoch evidence, when present, is consumed through
    /// its owner validation — never minted.
    ///
    /// Returns a qualification report only; no receipt is minted here.
    /// Minting through the accepted `authorize_cutover` belongs to #961.
    /// This path performs NO activation, retirement, route/process mutation,
    /// or live-authority invalidation. Rehearsal is safe by construction —
    /// there is simply no effect to rehearse beyond validation.
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
        let owner_epoch_present = evidence.owner_epoch.is_some();
        if let Some(owner_epoch) = evidence.owner_epoch.as_ref() {
            owner_epoch
                .validate()
                .map_err(KernelRestoreError::TargetFailed)?;
        }
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
        plan.restored_fence
            .validate()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        Ok(CutoverQualification {
            plan_id: plan.plan_id.clone(),
            target_id: plan.target.target_id.clone(),
            destination_root: destination.root().to_path_buf(),
            obligations_checked: 13,
            owner_epoch_present,
        })
    }
}

fn suspended_entries(
    bundle: &BackupBundle,
) -> Result<Vec<RestoreHistoricalAuthority>, KernelRestoreError> {
    match &bundle.ors_snapshot {
        Some(snapshot) => suspended_recovery_entries(snapshot)
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string())),
        None => Ok(Vec::new()),
    }
}

/// Requires the validation denominator for cutover qualification: every
/// applicable owner obligation satisfied by its exact owner, with
/// blob/ORS suspension excused exactly when the archive carries no blobs
/// or ORS snapshot to suspend.
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
        capability: &'static str,
        obligation: &RestoreOwnerObligation,
        applicable: bool,
    ) -> Result<(), BackupError> {
        match obligation.state {
            RestoreObligationState::Satisfied => Ok(()),
            RestoreObligationState::NotAttempted if !applicable => Ok(()),
            RestoreObligationState::NotAttempted => Err(BackupError::RestoreJournalCorrupt),
            _ => Err(BackupError::RestoreCapabilityUnsupported { capability }),
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
    for (obligation, capability, applicable) in list {
        require(capability, obligation, applicable)?;
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

/// Reconcile observation for one intent: exact applied receipt, proven
/// non-attempt, or undecidable bytes. Undecidable never becomes success.
enum ObservedEffect {
    Applied(Box<RestoreAppliedEffect>),
    NotAttempted,
    Undecidable,
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
    /// Cleanup preserved what it could not attribute to this execution, for
    /// the exact typed reason.
    Refused(StagedCleanupRefusal),
}

/// Kernel restore target over the accepted effect seam.
///
/// Every applicable phase re-checks the Kernel effect fence before touching
/// state, executes the genuine responsible-owner operation with the exact
/// bindings the coordinator supplies, persists exact bytes, and returns an
/// observed receipt. Reconciliation answers from persisted identity receipts
/// only.
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

    /// Stages one file, refusing BEFORE the write when the bounded output
    /// budget would be exceeded.
    ///
    /// The bound is checked against the running accounting plus this file, so
    /// the refusal happens while the destination still matches the budget —
    /// never after the exceeding bytes exist. The refusal is the typed
    /// [`BackupError::LimitExceeded`] naming the exact ceiling, not a
    /// formatted message, and it propagates through the phase and the engine
    /// unchanged.
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
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| BackupError::Target(error.to_string()))?;
        }
        let tmp = path.with_extension("tmp-restore");
        std::fs::write(&tmp, bytes).map_err(|error| BackupError::Target(error.to_string()))?;
        std::fs::rename(&tmp, &path).map_err(|error| BackupError::Target(error.to_string()))?;
        self.staged_members = members;
        self.staged_bytes = staged_bytes;
        self.staged.push(path);
        Ok(())
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
    /// refusal stays plain [`KernelRestoreError::TargetFailed`] — there is no
    /// second fact to report. When the cleanup preserved what it could not
    /// attribute, that exact typed reason travels with the SAME primary
    /// failure, so nothing is lost and nothing is stringified.
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
    /// 2. a destination that was resumed rather than constructed fresh is
    ///    refused outright, because its contents are not provably ours;
    /// 3. the pinned destination admission is re-read through the same
    ///    [`KernelBackupRestore::refuse_foreign_destination`] gate that
    ///    admitted it, so a destination pinned to another transaction or
    ///    target is refused rather than emptied;
    /// 4. the destination root and the isolated area are resolved again HERE,
    ///    not reused from open time, and the root must still sit inside
    ///    `<work_root>/.eliot/restore-isolated/<label>`, so a swapped or
    ///    re-pointed destination cannot redirect a removal.
    ///
    /// Bounded work, in three dimensions: the walk is over a known path set,
    /// so there is no unbounded directory recursion; the set is at most
    /// [`StagedOutputBudget::members`] because those are the same writes the
    /// budget admitted; and the aggregate unlinked bytes stop at
    /// [`StagedOutputBudget::bytes`], the same ceiling that admitted them.
    /// Empty directories left behind are reclaimed with
    /// [`std::fs::remove_dir`], which cannot remove a non-empty directory, so
    /// a directory this pass did not empty always survives.
    fn cleanup_staged_output(
        &self,
        destination: &KernelIsolatedDestination,
        transaction_id: &str,
        target_id: &str,
    ) -> StagedCleanup {
        let candidates: Vec<&PathBuf> = self
            .staged
            .iter()
            .filter(|path| !Self::is_preserved_observation(path, &self.root))
            .collect();
        if candidates.is_empty() {
            return StagedCleanup::NothingStaged;
        }
        if destination.is_resumed() {
            return StagedCleanup::Refused(StagedCleanupRefusal::AdmittedResume);
        }
        if KernelBackupRestore::refuse_foreign_destination(
            destination,
            transaction_id,
            target_id,
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

    fn load_applied(&self, intent: &RestoreIntent) -> Result<ObservedEffect, BackupError> {
        let path = self.phase_receipt_path(&intent.phase)?;
        if !path.exists() {
            return Ok(ObservedEffect::NotAttempted);
        }
        let bytes = std::fs::read(&path).map_err(|error| BackupError::Target(error.to_string()))?;
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
        Ok(ObservedEffect::Applied(Box::new(applied)))
    }

    /// Re-verifies the pinned destination admission before a post-prepare
    /// effect. Unadmitted restores skip; admitted ones require the exact
    /// pinned transaction, target, and manifest evidence — any drift
    /// refuses the effect instead of continuing under changed authority.
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
        let obligations = RestoreObligations {
            purge: Self::obligation(owners::PURGE, purge_ref, RestoreObligationState::Satisfied),
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
            watchdog_signals: missing(owners::WATCHDOG),
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
            historical_authority: match &bundle.ors_snapshot {
                Some(snapshot) => suspended_recovery_entries(snapshot)?,
                None => Vec::new(),
            },
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
        let bytes = canonical_json_bytes(&entries)
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
        // observation back by exact identity: a present receipt bound to this
        // transaction, phase, and input digest is Applied; its absence is
        // NotApplied and the coordinator re-applies idempotently (byte
        // staging overwrites, re-sealing mints fresh bytes with a fresh
        // receipt — no prior receipt exists to contradict). Bytes that parse
        // as nothing are Undecidable and propagate as Unknown: the
        // coordinator takes the explicit rollback-required disposition
        // (I14.21) with no new identity and no blind retry. Async
        // owner-channel unknowns belong to the #962 wire layer, which must
        // upgrade reconciliation there, never downgrade readback here.
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
fn check_ors_journal_binding(
    bundle: &BackupBundle,
    target: &RestoreContext,
    ports: &RestorePorts<'_>,
    identity: &OrsRestoreBinding,
) -> Result<(), KernelRestoreError> {
    if identity.source_archive_id != bundle.manifest.backup_id {
        return Err(KernelRestoreError::OwnerEvidenceInvalid(
            "restore journal source archive does not name this archive".to_owned(),
        ));
    }
    if identity.destination_ref != target.target_id {
        return Err(KernelRestoreError::OwnerEvidenceInvalid(
            "restore journal destination does not name this target".to_owned(),
        ));
    }
    // The writer that owns the durable rows must be the owner the admission
    // already authenticated for this journal. Without this, an admission for
    // one owner could file its durable rows under a different writer identity
    // while the outcome still reports the admitted owner.
    if identity.writer_id != ports.journal_admission.persistent_owner.owner_id {
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
    if identity.archive_class != declared {
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
