//! I5.11 storage replacement: the Kernel-owned `canonical_store` cutover
//! coordinator (issue #1872).
//!
//! Architecture traceability: `I5.11`
//! (`docs/architecture/I05-11-storage-replacement.md`) requires a candidate
//! store bridge to be installed, a snapshot imported, counts/hashes and
//! graph/projection invariants verified, both stores shadow-read, canonical
//! events tailed, affected writes quiesced, the final sequence reconciled, the
//! `canonical_store` `CapabilityRouteScope` cutover committed through the
//! Kernel Generation Registry, reads/writes canaried, the old store kept
//! read-only for a rollback window, and the old store retired only after backup
//! and a cutover receipt. `I5.11` also states the rollback rule this module
//! enforces: rollback switches generation back only if no irreversible
//! migration/effect occurred; otherwise it uses forward repair.
//!
//! `I5.10` names `ECXF/1` as the logical transfer format and states that an
//! export is tied to an `ExportFence`. [`StorageReplacementTransfer`] is the
//! typed record of one such exchange: the format identity, the digest of the
//! exact exported bytes, and the digest of the export fence the bytes were
//! taken at. The two stages that move data — I5.11 stage 2 and stage 5 — cannot
//! be recorded without it, and the cutover receipt binds it.
//!
//! `I14.14` owns the `CapabilityRouteScope`, the durable cutover record, the
//! in-flight disposition set, the rollback boundary and the receipt, and states
//! that the ORS commit is the durable linearization point while an irreversible
//! state migration requires forward repair or a separately proven rollback
//! path. `A13.3` supplies the promotion contour (shadow, bounded canary, active
//! generation, drain and retire or forward rollback) this module orders.
//!
//! ## Ordered stages
//!
//! ```text
//! install candidate store bridge
//!   -> import snapshot into candidate          (records its ECXF transfer)
//!   -> verify counts, hashes, graph/projection invariants
//!   -> shadow reads against both stores
//!   -> tail canonical events into candidate    (records its ECXF transfer)
//!   -> quiesce affected writes
//!   -> reconcile final sequence
//!   -> commit the canonical_store CapabilityRouteScope cutover through ORS
//!   -> canary reads/writes
//!   -> keep old store read-only for rollback window
//!   -> retire only after backup and cutover receipt
//! ```
//!
//! ## Division of responsibility
//!
//! ```text
//! Owner                           Evidence
//! ------------------------------- -------------------------------------------
//! This module (`StorageReplacement`) the I5.11 stage machine, the required
//!                                 ECXF transfer records, the per-stage
//!                                 recorded evidence, the irreversible-effect
//!                                 ledger and the cutover receipt
//! ORS (`eliot_ors`)               the committed `GenerationCutoverOwnership`
//!                                 row this coordinator re-derives its receipt
//!                                 from, its `GenerationCutoverOwnershipReceipt`,
//!                                 the in-flight dispositions, the route
//!                                 snapshot and the route-scope hash
//! Store / candidate bridge        the exported bytes and export fence, the
//!                                 imported snapshot, the verification and
//!                                 shadow-read comparison, the canary result,
//!                                 the read-only rollback window and the backup
//! ```
//!
//! ## Negative: the candidate cannot become canonical except through this
//! ## coordinator's receipt
//!
//! Established by this module:
//!
//! - The route scope is pinned. [`canonical_store_route_scope`] is the only
//!   scope a replacement is ever bound to; it is declared once through
//!   [`CapabilityRouteScope::declare`] and is never supplied by a caller, so no
//!   other four-tuple carrying the `canonical_store` capability string is
//!   reachable.
//! - The cutover receipt is re-derived from ORS rather than asserted by a
//!   caller. [`StorageReplacement::commit_canonical_store_route_cutover`] loads
//!   the `GenerationCutoverOwnership` from the durable [`RedbRecoveryStore`] by
//!   its cutover identity and refuses anything that is not a committed row, so a
//!   hand-built record with a synthetic `state` and
//!   `linearization_record_id` can never reach a receipt.
//! - The receipt is a serializable, deny-unknown-fields record whose
//!   [`StorageReplacementCutoverReceipt::validate`] runs on the construction
//!   path before the coordinator stores it.
//! - A restart cannot silently reopen a closed rollback path.
//!   [`StorageReplacement::begin`] refuses a candidate generation that already
//!   owns the route through a committed cutover, and
//!   [`StorageReplacement::resume_after_committed_cutover`] reconstructs a
//!   replacement from the durable cutover receipt plus the ORS-committed record
//!   that receipt names, restoring the irreversible-effect ledger fixed at the
//!   cutover.
//! - The two data-transfer stages cannot be recorded without the transfer
//!   record that binds the exact exported bytes and their export fence, and the
//!   cutover receipt binds that transfer, so a cutover cannot be proven against
//!   bytes the coordinator never saw.
//! - After a committed cutover, the Store gateway admits nothing against the
//!   incumbent generation. [`active_canonical_store_generation`] is the read
//!   side of the same committed row, and
//!   `KernelStoreGateway::require_active_store_generation` refuses every Store
//!   read and write — including the two that carry no caller fence and the
//!   borrowed client contour that reaches the retained client directly — unless
//!   this gateway's generation *is* the durable route's active generation. A
//!   gateway for a non-active generation can therefore be built and retained by
//!   any composition path, but it is not a writer or a reader of the canonical
//!   store, so the incumbent is served by nobody while the `I5.11` stage-10
//!   window is open, and only another committed cutover can serve it again.
//!
//! **Not** established by this module, and stated here so no reader mistakes
//! this file for a safety net it is not:
//!
//! - This coordinator is not the only way a `KernelStoreGateway` comes into
//!   being. `KernelStoreGateway::new` is reachable from the composition root's
//!   initial canonical-store connect and from `KernelComposition::rebind_store`,
//!   and that rebind path mints its own unrelated `StoreRebindReceipt` without
//!   consulting this module. What the route gate closes is the consequence: a
//!   gateway composed for a generation the durable `canonical_store` route does
//!   not name is refused every read and write, so a rebind to a candidate that
//!   has no committed cutover cannot serve as a second canonical writer *once a
//!   cutover exists*. What it does **not** do is stop such a gateway from being
//!   constructed, and while no cutover has ever been committed for this route
//!   the durable owner names no active generation at all, so the gate imposes
//!   nothing and the composition's own ordering argument is still what keeps the
//!   initial generation the one served. Telling those two apart is the
//!   composition root's own decision, not this module's.
//! - A cutover is still *committed* by the Kernel Generation Registry's owner,
//!   which writes the ORS `CUTOVER_OWNERSHIP` row. This coordinator stages,
//!   orders and proves the replacement and re-derives its receipt from that
//!   row; it does not write it.
//! - The read-only rollback window (stage 10) is enforced on the Kernel side:
//!   once the cutover is committed the incumbent generation is not the active
//!   `canonical_store` generation, so the governed Store path admits nothing
//!   against it. What this module does not do is stop the Host or the retired
//!   Store process from serving that generation to a reader outside the Kernel
//!   gateway; `I5.11` names no mechanism for that, so it is not invented here.
//! - A stage's evidence is bounded opaque text, plus the transfer record for the
//!   two transferring stages. This module orders and records stages; it does not
//!   perform the import, verification, shadow read, tail, reconciliation, canary
//!   or backup, and it interprets no store payload.
//! - The per-stage evidence recorded before a cutover is not durable material
//!   and is not reconstructed by a resumed replacement; the durable material is
//!   the ORS-committed record and the cutover receipt.
//!
//! ## Typed ORS refusals
//!
//! [`RedbRecoveryStore`], [`GenerationCutoverOwnershipReceipt::from_committed`]
//! and [`CapabilityRouteScope::validate`] fail with a typed [`OrsError`], and
//! this module classifies every class of it onto the existing
//! [`KernelServiceError`] variants by class. A fence mismatch, an epoch-lineage
//! break, a stale writer epoch, a duplicate conflict, an invalid transition, a
//! field rejection and an unavailability therefore stay distinguishable at the
//! Kernel service boundary; only the classes that are text in the source type
//! reach [`KernelServiceError::Platform`]. No ORS class is collapsed into a
//! string or a generic code between the layers.
//!
//! ## Rollback
//!
//! [`StorageReplacement::rollback_disposition`] is a pure classifier over the
//! recorded irreversible effects. [`StorageReplacement::request_rollback`]
//! enforces it, and it does not decide from that ledger alone: it reloads the
//! ORS-committed cutover ownership row its own receipt names, and a row that
//! already records a forward-repair-required state migration refuses the request
//! even when the in-process ledger is silent, so the durable record of
//! irreversibility is the authority and the caller cannot obtain a permitted
//! generation rollback by declining to record an effect. While no irreversible
//! effect is recorded the generation rollback is admitted (and the route switch
//! itself is another committed cutover with a newer epoch, never a local flag
//! flip); once one is recorded the request is refused as
//! [`KernelServiceError::GenerationFenced`] and only the explicit forward-repair
//! path follows. A post-cutover irreversible effect is not yet in the committed
//! row and the ledger does not survive a restart; that residual gap is stated on
//! [`StorageReplacement::request_rollback`] and named there as the `I5.14`
//! durable-effect-ledger owner's, because inventing a second durable store for
//! it here would be a second canonical path beside the one that already exists.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use eliot_contracts::ResourceGeneration;
use eliot_ors::{
    CapabilityRouteScope, CutoverRouteSnapshot, GenerationCutoverOwnership,
    GenerationCutoverOwnershipReceipt, MAX_RECOVERY_PAGE, OrsError, RedbRecoveryStore,
    StateMigrationDecision,
};
use eliot_runtime_contracts::GenerationCutoverState;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{KernelServiceError, validate_text};

/// The capability whose route this coordinator is bound to.
///
/// A replacement is refused for any other capability: the I5.11 stage machine
/// governs the canonical Store route, not an arbitrary module capability.
pub const CANONICAL_STORE_CAPABILITY: &str = "canonical_store";

/// The pinned owning module identity of the canonical store capability route.
///
/// It names the store bridge whose generation this coordinator switches; it is
/// one of the four coordinates of [`canonical_store_route_scope`] and is fixed
/// here rather than chosen by a caller.
pub const CANONICAL_STORE_MODULE_ID: &str = "mod-store";

/// The pinned work scope of the canonical store capability route.
///
/// It is one of the four coordinates of [`canonical_store_route_scope`] and is
/// fixed here rather than chosen by a caller.
pub const CANONICAL_STORE_WORK_SCOPE: &str = "work";

/// The pinned effect domain of the canonical store capability route.
///
/// It is one of the four coordinates of [`canonical_store_route_scope`] and is
/// fixed here rather than chosen by a caller.
pub const CANONICAL_STORE_EFFECT_DOMAIN: &str = "effects";

/// The `I5.10` logical transfer format used for the snapshot import and the
/// canonical event tail.
///
/// It is the format identity every [`StorageReplacementTransfer`] must name.
pub const STORAGE_REPLACEMENT_TRANSFER_FORMAT: &str = "ECXF/1";

/// Declares the one `canonical_store` `CapabilityRouteScope` this coordinator
/// is bound to.
///
/// The four coordinates are declared here and the stable route-scope hash is
/// bound by [`CapabilityRouteScope::declare`]; no caller supplies a scope and
/// no route-scope hash is hand-computed. Every replacement, receipt and
/// ORS-committed record this module accepts is checked against this hash.
pub fn canonical_store_route_scope() -> Result<CapabilityRouteScope, KernelServiceError> {
    CapabilityRouteScope::declare(
        CANONICAL_STORE_MODULE_ID,
        CANONICAL_STORE_CAPABILITY,
        CANONICAL_STORE_WORK_SCOPE,
        CANONICAL_STORE_EFFECT_DOMAIN,
    )
    .map_err(|error| ors_refusal(&error))
}

/// Resolves the store generation that currently owns the pinned
/// `canonical_store` capability route.
///
/// This is the read side of the `I5.11` stage-8 cutover. It answers through the
/// *existing* admitted owner rather than a rule of its own: the committed ORS
/// `CUTOVER_OWNERSHIP` rows are handed to [`CutoverRouteSnapshot::rebuild`], the
/// same reconstruction the Kernel's own recovery performs
/// (`bins/eliot-kernel/src/generation_recovery.rs::recover_cutover_ownership`), and
/// the active generation is read back from that snapshot's entry for the pinned
/// route-scope hash. The strictly newest committed epoch therefore wins, exactly
/// as `I14.14` requires ("rollback is another cutover with a newer epoch; an old
/// epoch is never reactivated"), and a pre-commit `Armed` candidate cannot
/// appear because the listing itself returns committed rows only. `None` means
/// no committed cutover has ever switched this route, so the composition's own
/// route is still the active one and this module imposes nothing.
///
/// Every Store read and write is admitted against this answer rather than a
/// composition-fixed route snapshot. After a committed cutover the incumbent
/// generation is therefore no longer the active generation, and the governed
/// path can neither read nor write it — which is what lets the old store stay
/// read-only for the `I5.11` stage-10 rollback window.
///
/// The read is bounded by [`MAX_RECOVERY_PAGE`], the bound ORS itself applies
/// to this listing, and ORS reports [`OrsError::ProjectionLimitExceeded`]
/// rather than truncating once the committed cutover rows reach it. That refusal
/// reaches the caller, so a route table grown past the bound closes this gate
/// instead of silently answering from a prefix. The bound is not raised here:
/// the listing belongs to the existing owner, and a second, larger read beside
/// it would be a second way to answer the same question.
pub fn active_canonical_store_generation(
    ors: &RedbRecoveryStore,
) -> Result<Option<ResourceGeneration>, KernelServiceError> {
    let scope = canonical_store_route_scope()?;
    let committed = committed_canonical_store_cutovers(ors, &scope)?;
    Ok(CutoverRouteSnapshot::rebuild(&committed)
        .map_err(|error| ors_refusal(&error))?
        .entry(&scope.route_scope_hash)
        .map(|entry| entry.active_generation))
}

/// Committed cutover ownership rows that belong to exactly the pinned
/// `canonical_store` route scope.
///
/// Rows of other capability routes are dropped before the snapshot is rebuilt,
/// so another module's committed cutover can neither answer this route's
/// question nor close this gate; the winner rule stays the snapshot's.
///
/// An ORS database written before the optional `CUTOVER_OWNERSHIP` table
/// existed reports the absence through [`OrsError::Storage`] rather than an
/// empty listing. Absence is a fact about the database, not about a route: the
/// table is created by the first staged cutover, so an absent one means no
/// cutover has ever been committed and therefore that no candidate generation
/// can own this route. This is the same compatibility reading the Kernel's own
/// recovery boundary makes (`bins/eliot-kernel/src/generation_recovery.rs`),
/// which notes that ORS exposes the absence only as a typed storage message and
/// therefore keeps the test at its own boundary; it is repeated here for the
/// same stated reason and is not a second rule. Any other storage refusal, and
/// every typed ORS class, still reaches the caller unchanged.
fn committed_canonical_store_cutovers(
    ors: &RedbRecoveryStore,
    scope: &CapabilityRouteScope,
) -> Result<Vec<GenerationCutoverOwnership>, KernelServiceError> {
    let committed = match ors.latest_committed_cutover_ownership(MAX_RECOVERY_PAGE) {
        Ok(committed) => committed,
        Err(error) if is_absent_cutover_ownership_table(&error) => return Ok(Vec::new()),
        Err(error) => return Err(ors_refusal(&error)),
    };
    Ok(committed
        .into_iter()
        .filter(|record| record.scope.route_scope_hash == scope.route_scope_hash)
        .collect())
}

/// Whether an ORS refusal is only the absence of the optional cutover
/// ownership table in a database that predates it.
///
/// ORS exposes the absence through its typed storage text and no other class,
/// so the message is matched exactly. A present table whose contents fail
/// validation is not this, and stays a refusal.
fn is_absent_cutover_ownership_table(error: &OrsError) -> bool {
    matches!(
        error,
        OrsError::Storage(message)
            if message.contains("Table 'ors_cutover_ownership_v1' does not exist")
    )
}

/// One recorded `I5.10` exchange into the candidate store.
///
/// It is the typed record the coordinator carries in place of the exported
/// bytes themselves: the Kernel never holds or interprets a transfer payload.
/// It binds the logical transfer format, the exact exported bytes, and the
/// export fence those bytes were taken at.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageReplacementTransfer {
    /// The logical transfer format identity, which is
    /// [`STORAGE_REPLACEMENT_TRANSFER_FORMAT`].
    pub format: String,
    /// Lowercase SHA-256 digest of the exact exported transfer bytes.
    pub payload_digest: String,
    /// Lowercase SHA-256 digest over the `I5.10` export fence the bytes were
    /// taken at.
    pub export_fence_digest: String,
}

impl StorageReplacementTransfer {
    /// Validates the format identity and both bound digests.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.format != STORAGE_REPLACEMENT_TRANSFER_FORMAT {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_transfer_format",
                reason: "the storage replacement transfer format is the I5.10 ECXF/1 exchange",
            });
        }
        validate_digest(
            &self.payload_digest,
            "storage_replacement_transfer_payload_digest",
        )?;
        validate_digest(
            &self.export_fence_digest,
            "storage_replacement_transfer_export_fence_digest",
        )
    }
}

/// One ordered I5.11 storage-replacement stage.
///
/// The discriminants are the I5.11 stage numbers, so the declared order is
/// also the only admissible order: [`StorageReplacementStage::predecessor`]
/// and [`StorageReplacementStage::next`] are exact neighbours and nothing may
/// skip or repeat one.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StorageReplacementStage {
    /// I5.11 stage 1: install candidate store bridge.
    InstallCandidateStoreBridge = 1,
    /// I5.11 stage 2: import snapshot into candidate.
    ImportSnapshotIntoCandidate = 2,
    /// I5.11 stage 3: verify counts, hashes, graph/projection invariants.
    VerifyCountsHashesAndInvariants = 3,
    /// I5.11 stage 4: run shadow reads against both stores.
    ShadowReadBothStores = 4,
    /// I5.11 stage 5: tail canonical events into candidate.
    TailCanonicalEventsIntoCandidate = 5,
    /// I5.11 stage 6: quiesce affected writes.
    QuiesceAffectedWrites = 6,
    /// I5.11 stage 7: reconcile final sequence.
    ReconcileFinalSequence = 7,
    /// I5.11 stage 8: commit the `canonical_store` `CapabilityRouteScope`
    /// cutover through the Kernel Generation Registry.
    CommitCanonicalStoreRouteCutover = 8,
    /// I5.11 stage 9: canary reads/writes.
    CanaryReadsAndWrites = 9,
    /// I5.11 stage 10: keep the old store read-only for the rollback window.
    ReadOnlyRollbackWindow = 10,
    /// I5.11 stage 11: retire the old store only after backup and cutover
    /// receipt.
    RetireAfterBackupAndCutoverReceipt = 11,
}

impl StorageReplacementStage {
    /// The eleven I5.11 stages in their required order.
    pub const ORDER: [Self; 11] = [
        Self::InstallCandidateStoreBridge,
        Self::ImportSnapshotIntoCandidate,
        Self::VerifyCountsHashesAndInvariants,
        Self::ShadowReadBothStores,
        Self::TailCanonicalEventsIntoCandidate,
        Self::QuiesceAffectedWrites,
        Self::ReconcileFinalSequence,
        Self::CommitCanonicalStoreRouteCutover,
        Self::CanaryReadsAndWrites,
        Self::ReadOnlyRollbackWindow,
        Self::RetireAfterBackupAndCutoverReceipt,
    ];

    /// The I5.11 stage number of this stage, from 1 through 11.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        self as usize
    }

    /// Whether this stage moves `I5.10` transfer data into the candidate and
    /// therefore cannot be recorded without a [`StorageReplacementTransfer`].
    #[must_use]
    pub const fn transfers_data(self) -> bool {
        matches!(
            self,
            Self::ImportSnapshotIntoCandidate | Self::TailCanonicalEventsIntoCandidate
        )
    }

    /// The exact stage that must follow this one, or `None` once the old store
    /// has been retired.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::InstallCandidateStoreBridge => Some(Self::ImportSnapshotIntoCandidate),
            Self::ImportSnapshotIntoCandidate => Some(Self::VerifyCountsHashesAndInvariants),
            Self::VerifyCountsHashesAndInvariants => Some(Self::ShadowReadBothStores),
            Self::ShadowReadBothStores => Some(Self::TailCanonicalEventsIntoCandidate),
            Self::TailCanonicalEventsIntoCandidate => Some(Self::QuiesceAffectedWrites),
            Self::QuiesceAffectedWrites => Some(Self::ReconcileFinalSequence),
            Self::ReconcileFinalSequence => Some(Self::CommitCanonicalStoreRouteCutover),
            Self::CommitCanonicalStoreRouteCutover => Some(Self::CanaryReadsAndWrites),
            Self::CanaryReadsAndWrites => Some(Self::ReadOnlyRollbackWindow),
            Self::ReadOnlyRollbackWindow => Some(Self::RetireAfterBackupAndCutoverReceipt),
            Self::RetireAfterBackupAndCutoverReceipt => None,
        }
    }

    /// The exact stage that must have been recorded before this one, or `None`
    /// for the first stage.
    #[must_use]
    pub const fn predecessor(self) -> Option<Self> {
        match self {
            Self::InstallCandidateStoreBridge => None,
            Self::ImportSnapshotIntoCandidate => Some(Self::InstallCandidateStoreBridge),
            Self::VerifyCountsHashesAndInvariants => Some(Self::ImportSnapshotIntoCandidate),
            Self::ShadowReadBothStores => Some(Self::VerifyCountsHashesAndInvariants),
            Self::TailCanonicalEventsIntoCandidate => Some(Self::ShadowReadBothStores),
            Self::QuiesceAffectedWrites => Some(Self::TailCanonicalEventsIntoCandidate),
            Self::ReconcileFinalSequence => Some(Self::QuiesceAffectedWrites),
            Self::CommitCanonicalStoreRouteCutover => Some(Self::ReconcileFinalSequence),
            Self::CanaryReadsAndWrites => Some(Self::CommitCanonicalStoreRouteCutover),
            Self::ReadOnlyRollbackWindow => Some(Self::CanaryReadsAndWrites),
            Self::RetireAfterBackupAndCutoverReceipt => Some(Self::ReadOnlyRollbackWindow),
        }
    }

    /// The stable operator-visible stage name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InstallCandidateStoreBridge => "install_candidate_store_bridge",
            Self::ImportSnapshotIntoCandidate => "import_snapshot_into_candidate",
            Self::VerifyCountsHashesAndInvariants => "verify_counts_hashes_and_invariants",
            Self::ShadowReadBothStores => "shadow_read_both_stores",
            Self::TailCanonicalEventsIntoCandidate => "tail_canonical_events_into_candidate",
            Self::QuiesceAffectedWrites => "quiesce_affected_writes",
            Self::ReconcileFinalSequence => "reconcile_final_sequence",
            Self::CommitCanonicalStoreRouteCutover => "commit_canonical_store_route_cutover",
            Self::CanaryReadsAndWrites => "canary_reads_and_writes",
            Self::ReadOnlyRollbackWindow => "read_only_rollback_window",
            Self::RetireAfterBackupAndCutoverReceipt => "retire_after_backup_and_cutover_receipt",
        }
    }
}

impl fmt::Display for StorageReplacementStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One irreversible occurrence that closes the generation-rollback path.
///
/// `I5.11` allows switching generation back only when no irreversible
/// migration/effect occurred. These are the two occurrences the issue names;
/// the coordinator records them as an append-only set and never clears one,
/// because an observed irreversible effect cannot be un-observed.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum IrreversibleStorageEffect {
    /// The candidate's imported state cannot be reconciled back into the
    /// incumbent store, so a generation switch back would lose canonical data.
    IrreversibleMigration,
    /// A canonical or external effect was already issued through the candidate
    /// route, so the effect must be reconciled forward rather than undone.
    ExternalEffectIssued,
}

impl fmt::Display for IrreversibleStorageEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::IrreversibleMigration => "irreversible_migration",
            Self::ExternalEffectIssued => "external_effect_issued",
        })
    }
}

/// The disposition of one rollback request against the `canonical_store` route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRollbackDisposition {
    /// No irreversible migration or external effect is recorded, so the route
    /// may switch back to the incumbent generation as another committed cutover
    /// with a newer epoch.
    GenerationRollbackPermitted,
    /// An irreversible migration or external effect is recorded. The request is
    /// refused as a generation rollback; `state` is the cutover state a refused
    /// rollback leaves behind, and forward repair is the only next transition.
    ForwardRepairRequired {
        /// The cutover state a refused rollback leaves behind.
        state: GenerationCutoverState,
    },
}

/// The durable cutover receipt of one governed storage replacement.
///
/// It names both store generations, the pinned `canonical_store` route scope,
/// the `I5.10` transfer the cutover is proven against, and the
/// ORS-committed cutover the route cutover was re-derived from. It is
/// constructed only by [`StorageReplacement::commit_canonical_store_route_cutover`],
/// which loads the ORS row rather than accepting one, and by
/// [`StorageReplacement::resume_after_committed_cutover`], which re-derives it
/// from that same row. [`Self::validate`] runs before the coordinator stores
/// the value, so a receipt can never precede the durable linearization point.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageReplacementCutoverReceipt {
    /// The replacement identity this receipt belongs to.
    pub replacement_id: String,
    /// The store generation that owned the route before the cutover.
    pub incumbent_generation: Option<ResourceGeneration>,
    /// The store generation that owns the route after the cutover.
    pub candidate_generation: ResourceGeneration,
    /// The pinned `canonical_store` `CapabilityRouteScope`.
    pub route_scope: CapabilityRouteScope,
    /// The `I5.10` transfer the cutover is proven against: the canonical event
    /// tail recorded at I5.11 stage 5, the last transfer into the candidate
    /// before write quiescence and final reconciliation.
    pub transfer: StorageReplacementTransfer,
    /// The ORS-committed cutover ownership receipt proving the linearization
    /// point.
    pub committed_cutover: GenerationCutoverOwnershipReceipt,
    /// The irreversible effects recorded when the cutover was committed.
    pub irreversible_effects: BTreeSet<IrreversibleStorageEffect>,
}

impl StorageReplacementCutoverReceipt {
    /// Validates every binding this receipt claims, including the pinned route
    /// scope, the two store generations, the transfer and the ORS linearization.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_text(&self.replacement_id, "storage_replacement_id")?;
        if self.incumbent_generation == Some(self.candidate_generation) {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_cutover_receipt_generations",
                reason: "a cutover receipt must name two distinct store generations",
            });
        }
        self.route_scope
            .validate()
            .map_err(|error| ors_refusal(&error))?;
        if self.route_scope.capability != CANONICAL_STORE_CAPABILITY
            || self.route_scope.route_scope_hash != canonical_store_route_scope()?.route_scope_hash
        {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_cutover_receipt_route_scope",
                reason: "a cutover receipt must name the pinned canonical_store route scope",
            });
        }
        self.transfer.validate()?;
        let committed = &self.committed_cutover;
        validate_text(
            &committed.linearization_record_id,
            "storage_replacement_cutover_receipt_linearization",
        )?;
        if committed.state != GenerationCutoverState::Committed {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_cutover_receipt_state",
                reason: "a cutover receipt requires a committed ORS cutover state",
            });
        }
        if committed.route_scope_hash != self.route_scope.route_scope_hash
            || committed.old_generation != self.incumbent_generation
            || committed.new_generation != self.candidate_generation
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "storage_replacement_cutover_receipt_binding",
            });
        }
        if (committed.migration == StateMigrationDecision::ForwardRepairRequired)
            == self.irreversible_effects.is_empty()
        {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_cutover_receipt_migration",
                reason: "the committed state migration must name forward repair exactly when an irreversible effect is recorded",
            });
        }
        Ok(())
    }
}

/// The Kernel-owned coordinator for one I5.11 storage replacement.
///
/// It owns the stage position, the per-stage recorded evidence, the two store
/// generations, the pinned route scope, the two required transfer records, the
/// irreversible-effect ledger and the cutover receipt. It stores no snapshot
/// bytes, no event tail and no canary result: those stay with the Store and the
/// candidate bridge and reach the coordinator only as the evidence a stage
/// records.
#[derive(Clone, Debug)]
pub struct StorageReplacement {
    replacement_id: String,
    scope: CapabilityRouteScope,
    incumbent_generation: Option<ResourceGeneration>,
    candidate_generation: ResourceGeneration,
    next_stage: Option<StorageReplacementStage>,
    evidence: BTreeMap<StorageReplacementStage, String>,
    snapshot_import: Option<StorageReplacementTransfer>,
    event_tail: Option<StorageReplacementTransfer>,
    irreversible_effects: BTreeSet<IrreversibleStorageEffect>,
    cutover: Option<GenerationCutoverOwnership>,
    receipt: Option<StorageReplacementCutoverReceipt>,
}

impl StorageReplacement {
    /// Starts one replacement bound to the pinned `canonical_store` capability
    /// route scope.
    ///
    /// The first stage to record is
    /// [`StorageReplacementStage::InstallCandidateStoreBridge`]; nothing about
    /// the candidate is active before its own evidence is recorded. A candidate
    /// generation that already owns the route through a committed cutover is
    /// refused, so a restarted process cannot reopen a replacement from the top:
    /// it must resume through [`Self::resume_after_committed_cutover`].
    pub fn begin(
        ors: &RedbRecoveryStore,
        replacement_id: impl Into<String>,
        incumbent_generation: Option<ResourceGeneration>,
        candidate_generation: ResourceGeneration,
    ) -> Result<Self, KernelServiceError> {
        let replacement_id = replacement_id.into();
        validate_text(&replacement_id, "storage_replacement_id")?;
        let scope = canonical_store_route_scope()?;
        if incumbent_generation == Some(candidate_generation) {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_candidate_generation",
                reason: "a replacement must select a distinct candidate store generation",
            });
        }
        let committed = committed_canonical_store_cutovers(ors, &scope)?;
        if committed
            .iter()
            .any(|record| record.new_generation == candidate_generation)
        {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_candidate_generation",
                reason: "the candidate generation already owns the canonical_store route through a committed cutover, so the replacement must be resumed from its durable cutover receipt",
            });
        }
        Ok(Self {
            replacement_id,
            scope,
            incumbent_generation,
            candidate_generation,
            next_stage: Some(StorageReplacementStage::InstallCandidateStoreBridge),
            evidence: BTreeMap::new(),
            snapshot_import: None,
            event_tail: None,
            irreversible_effects: BTreeSet::new(),
            cutover: None,
            receipt: None,
        })
    }

    /// Reconstructs a replacement after a restart from its durable material:
    /// the cutover receipt and the ORS-committed cutover record it names.
    ///
    /// The receipt is validated and then re-derived from ORS, so a receipt that
    /// does not match the durable row is refused. The reconstructed replacement
    /// starts at the stage after the committed cutover, carries the
    /// irreversible-effect ledger the receipt fixed at the cutover, and holds no
    /// per-stage evidence: evidence recorded before the cutover is not durable
    /// material.
    pub fn resume_after_committed_cutover(
        ors: &RedbRecoveryStore,
        replacement_id: impl Into<String>,
        incumbent_generation: Option<ResourceGeneration>,
        candidate_generation: ResourceGeneration,
        receipt: &StorageReplacementCutoverReceipt,
    ) -> Result<Self, KernelServiceError> {
        let replacement_id = replacement_id.into();
        validate_text(&replacement_id, "storage_replacement_id")?;
        receipt.validate()?;
        if receipt.replacement_id != replacement_id
            || receipt.incumbent_generation != incumbent_generation
            || receipt.candidate_generation != candidate_generation
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "storage_replacement_cutover_receipt_identity",
            });
        }
        let record = ors
            .load_cutover_ownership(&receipt.committed_cutover.cutover_id)
            .map_err(|error| ors_refusal(&error))?
            .ok_or(KernelServiceError::InvalidField {
                field: "storage_replacement_cutover_record",
                reason: "a resumed replacement requires its ORS-committed cutover ownership record",
            })?;
        if GenerationCutoverOwnershipReceipt::from_committed(&record)
            .map_err(|error| ors_refusal(&error))?
            != receipt.committed_cutover
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "storage_replacement_cutover_receipt_binding",
            });
        }
        Ok(Self {
            replacement_id,
            scope: receipt.route_scope.clone(),
            incumbent_generation,
            candidate_generation,
            next_stage: StorageReplacementStage::CommitCanonicalStoreRouteCutover.next(),
            evidence: BTreeMap::new(),
            snapshot_import: None,
            event_tail: Some(receipt.transfer.clone()),
            irreversible_effects: receipt.irreversible_effects.clone(),
            cutover: Some(record),
            receipt: Some(receipt.clone()),
        })
    }

    /// The replacement identity.
    #[must_use]
    pub fn replacement_id(&self) -> &str {
        &self.replacement_id
    }

    /// The pinned `canonical_store` `CapabilityRouteScope` this replacement is
    /// bound to.
    #[must_use]
    pub const fn route_scope(&self) -> &CapabilityRouteScope {
        &self.scope
    }

    /// The store generation that owned the route before this replacement.
    #[must_use]
    pub const fn incumbent_generation(&self) -> Option<ResourceGeneration> {
        self.incumbent_generation
    }

    /// The store generation that will own the route after the cutover.
    #[must_use]
    pub const fn candidate_generation(&self) -> ResourceGeneration {
        self.candidate_generation
    }

    /// The one stage that may be recorded next, or `None` once the old store
    /// has been retired.
    #[must_use]
    pub const fn next_stage(&self) -> Option<StorageReplacementStage> {
        self.next_stage
    }

    /// The evidence recorded for one already reached stage, if it was reached.
    #[must_use]
    pub fn evidence(&self, stage: StorageReplacementStage) -> Option<&str> {
        self.evidence.get(&stage).map(String::as_str)
    }

    /// Every stage reached so far with its recorded evidence, in I5.11 order.
    #[must_use]
    pub const fn recorded_evidence(&self) -> &BTreeMap<StorageReplacementStage, String> {
        &self.evidence
    }

    /// The `I5.10` transfer recorded for the snapshot import, if that stage was
    /// reached.
    #[must_use]
    pub const fn snapshot_import_transfer(&self) -> Option<&StorageReplacementTransfer> {
        self.snapshot_import.as_ref()
    }

    /// The `I5.10` transfer recorded for the canonical event tail, if that stage
    /// was reached.
    #[must_use]
    pub const fn event_tail_transfer(&self) -> Option<&StorageReplacementTransfer> {
        self.event_tail.as_ref()
    }

    /// The irreversible effects observed so far.
    #[must_use]
    pub const fn irreversible_effects(&self) -> &BTreeSet<IrreversibleStorageEffect> {
        &self.irreversible_effects
    }

    /// The ORS cutover ownership record, present only once the
    /// `canonical_store` route cutover has been committed.
    #[must_use]
    pub const fn cutover(&self) -> Option<&GenerationCutoverOwnership> {
        self.cutover.as_ref()
    }

    /// The cutover receipt, present only once the `canonical_store` route
    /// cutover has been committed.
    #[must_use]
    pub const fn cutover_receipt(&self) -> Option<&StorageReplacementCutoverReceipt> {
        self.receipt.as_ref()
    }

    /// Records the evidence of the exact next I5.11 stage and advances.
    ///
    /// A stage is reached only through its exact predecessor: a repeated,
    /// skipped or out-of-order stage is refused without recording anything, so
    /// the recorded evidence is a faithful account of what was actually done.
    /// The two transferring stages are recorded by
    /// [`Self::record_transfer_stage`], stage 8 is recorded by
    /// [`Self::commit_canonical_store_route_cutover`], and stage 11 is refused
    /// until a cutover receipt exists.
    pub fn record_stage(
        &mut self,
        stage: StorageReplacementStage,
        evidence: impl Into<String>,
    ) -> Result<StorageReplacementStage, KernelServiceError> {
        let evidence = evidence.into();
        validate_text(&evidence, "storage_replacement_evidence")?;
        if stage.transfers_data() {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_stage",
                reason: "a stage that transfers data is recorded together with its I5.10 transfer record",
            });
        }
        if stage == StorageReplacementStage::CommitCanonicalStoreRouteCutover {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_stage",
                reason: "the canonical_store route cutover is recorded by re-deriving its committed ORS cutover ownership record",
            });
        }
        self.require_exact_next(stage)?;
        if stage == StorageReplacementStage::RetireAfterBackupAndCutoverReceipt
            && self.receipt.is_none()
        {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_cutover_receipt",
                reason: "the incumbent store is retired only after backup and the cutover receipt",
            });
        }
        self.record_evidence(stage, evidence);
        Ok(stage)
    }

    /// Records the exact next data-transfering stage with the `I5.10` transfer
    /// it was performed with, and advances.
    ///
    /// The snapshot import (stage 2) and the canonical event tail (stage 5)
    /// cannot be recorded without the exact exported bytes' digest and the
    /// export fence they were taken at, so the transfer is part of reaching the
    /// stage rather than a note attached to it afterwards.
    pub fn record_transfer_stage(
        &mut self,
        stage: StorageReplacementStage,
        transfer: &StorageReplacementTransfer,
        evidence: impl Into<String>,
    ) -> Result<StorageReplacementStage, KernelServiceError> {
        let evidence = evidence.into();
        validate_text(&evidence, "storage_replacement_evidence")?;
        transfer.validate()?;
        match stage {
            StorageReplacementStage::ImportSnapshotIntoCandidate => {
                self.require_exact_next(stage)?;
                self.snapshot_import = Some(transfer.clone());
            }
            StorageReplacementStage::TailCanonicalEventsIntoCandidate => {
                self.require_exact_next(stage)?;
                self.event_tail = Some(transfer.clone());
            }
            _ => {
                return Err(KernelServiceError::InvalidField {
                    field: "storage_replacement_stage",
                    reason: "only the snapshot import and the canonical event tail transfer data into the candidate",
                });
            }
        }
        self.record_evidence(stage, evidence);
        Ok(stage)
    }

    /// Commits the `canonical_store` `CapabilityRouteScope` cutover through the
    /// Kernel Generation Registry (I5.11 stage 8) and publishes its receipt.
    ///
    /// The cutover record is not accepted from the caller: it is loaded from the
    /// durable ORS row named by `cutover_id`, so only a committed row can
    /// produce a receipt and a hand-built record with a synthetic state and
    /// linearization identity cannot. The row must be for this replacement's own
    /// pinned route scope and its own two store generations, and its declared
    /// state migration must name forward repair exactly when an irreversible
    /// effect is already recorded, so the committed record and the coordinator's
    /// own irreversible-effect ledger can never disagree about whether a
    /// generation rollback is still available. The receipt binds the canonical
    /// event tail transfer, so a cutover cannot be proven against bytes the
    /// coordinator never saw, and it is validated before it is stored.
    pub fn commit_canonical_store_route_cutover(
        &mut self,
        ors: &RedbRecoveryStore,
        cutover_id: &str,
        evidence: impl Into<String>,
    ) -> Result<StorageReplacementCutoverReceipt, KernelServiceError> {
        let evidence = evidence.into();
        validate_text(&evidence, "storage_replacement_evidence")?;
        validate_text(cutover_id, "storage_replacement_cutover_id")?;
        self.require_exact_next(StorageReplacementStage::CommitCanonicalStoreRouteCutover)?;
        let Some(transfer) = self.event_tail.clone() else {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_transfer",
                reason: "the canonical event tail must be transferred into the candidate before the route cutover",
            });
        };
        let record = ors
            .load_cutover_ownership(cutover_id)
            .map_err(|error| ors_refusal(&error))?
            .ok_or(KernelServiceError::InvalidField {
                field: "storage_replacement_cutover_record",
                reason: "the canonical_store route cutover must be an ORS-committed cutover ownership record",
            })?;
        if record.scope.route_scope_hash != self.scope.route_scope_hash {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "storage_replacement_route_scope",
            });
        }
        if record.old_generation != self.incumbent_generation
            || record.new_generation != self.candidate_generation
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "storage_replacement_store_generations",
            });
        }
        if (record.migration == StateMigrationDecision::ForwardRepairRequired)
            == self.irreversible_effects.is_empty()
        {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_migration",
                reason: "the declared state migration must name forward repair exactly when an irreversible effect is recorded",
            });
        }
        let committed_cutover = GenerationCutoverOwnershipReceipt::from_committed(&record)
            .map_err(|error| ors_refusal(&error))?;
        let receipt = StorageReplacementCutoverReceipt {
            replacement_id: self.replacement_id.clone(),
            incumbent_generation: self.incumbent_generation,
            candidate_generation: self.candidate_generation,
            route_scope: self.scope.clone(),
            transfer,
            committed_cutover,
            irreversible_effects: self.irreversible_effects.clone(),
        };
        receipt.validate()?;
        self.cutover = Some(record);
        self.record_evidence(
            StorageReplacementStage::CommitCanonicalStoreRouteCutover,
            evidence,
        );
        self.receipt = Some(receipt.clone());
        Ok(receipt)
    }

    /// Records that an irreversible migration or external effect occurred.
    ///
    /// The ledger only grows: an observed irreversible effect can never be
    /// un-observed, so this closes the generation-rollback path for the rest of
    /// the replacement's life.
    ///
    /// This records an observation; it is not itself the durable proof. The
    /// durable record of irreversibility is the committed ORS
    /// `GenerationCutoverOwnership` row's `migration` decision, and
    /// [`Self::request_rollback`] reads that row rather than trusting this
    /// in-memory set alone.
    pub fn record_irreversible_effect(&mut self, effect: IrreversibleStorageEffect) {
        self.irreversible_effects.insert(effect);
    }

    /// Classifies a rollback request without changing any state.
    ///
    /// This is the pure form of the `I5.11` rule; it reads only the recorded
    /// irreversible effects. It is a projection, not the decision:
    /// [`Self::request_rollback`] also consults the durable ORS cutover
    /// ownership row, so a caller cannot obtain a permitted generation rollback
    /// by simply declining to record an effect.
    #[must_use]
    pub fn rollback_disposition(&self) -> StorageRollbackDisposition {
        if self.irreversible_effects.is_empty() {
            StorageRollbackDisposition::GenerationRollbackPermitted
        } else {
            StorageRollbackDisposition::ForwardRepairRequired {
                state: GenerationCutoverState::FailedRequiresForwardCutover,
            }
        }
    }

    /// Answers one rollback request for the `canonical_store` route.
    ///
    /// The decision is anchored to a durable record written *before* rollback is
    /// ever offered, not to the caller's own bookkeeping. The ORS-committed
    /// [`GenerationCutoverOwnership`] row this replacement's receipt names is
    /// reloaded by cutover identity and re-derived, so a rollback can only be
    /// admitted against the very record the cutover receipt was built from. When
    /// the coordinator's ledger records no irreversible effect, that durable
    /// row's `migration` decision is the authority: a row that already names
    /// [`StateMigrationDecision::ForwardRepairRequired`] refuses the request
    /// even though the in-process ledger is silent, so a caller cannot obtain a
    /// permitted generation rollback by declining to record an effect. Any other
    /// mismatch between the row and the receipt is refused rather than read as
    /// an absence of irreversible effect.
    ///
    /// Once an irreversible effect is recorded — by the ledger or by the durable
    /// row — the request is refused as a generation rollback with
    /// [`KernelServiceError::GenerationFenced`] and only the forward-repair path
    /// named by [`Self::rollback_disposition`] follows. The rollback itself, when
    /// admitted, is another committed cutover with a newer epoch, never a local
    /// flag flip.
    ///
    /// A post-cutover irreversible effect is the one case this cannot prove: it
    /// is not yet in the committed row, and the `I5.11` documents name no
    /// durable record for an effect issued after the linearization point. The
    /// ledger still refuses the request in this process, and a restart that
    /// loses it is a gap the owner of the `I5.14` durable effect ledger has to
    /// close; it is named here rather than papered over with a second store.
    pub fn request_rollback(
        &self,
        ors: &RedbRecoveryStore,
    ) -> Result<StorageRollbackDisposition, KernelServiceError> {
        if let Some(receipt) = self.receipt.as_ref() {
            let record = ors
                .load_cutover_ownership(&receipt.committed_cutover.cutover_id)
                .map_err(|error| ors_refusal(&error))?
                .ok_or(KernelServiceError::InvalidField {
                    field: "storage_replacement_cutover_record",
                    reason: "a rollback decision requires the ORS-committed cutover ownership record the receipt names",
                })?;
            if GenerationCutoverOwnershipReceipt::from_committed(&record)
                .map_err(|error| ors_refusal(&error))?
                != receipt.committed_cutover
            {
                return Err(KernelServiceError::HandshakeMismatch {
                    field: "storage_replacement_cutover_receipt_binding",
                });
            }
            if self.irreversible_effects.is_empty()
                && record.migration == StateMigrationDecision::ForwardRepairRequired
            {
                return Err(KernelServiceError::GenerationFenced);
            }
        }
        match self.rollback_disposition() {
            StorageRollbackDisposition::GenerationRollbackPermitted if self.receipt.is_none() => {
                Err(KernelServiceError::InvalidField {
                    field: "storage_replacement_cutover_receipt",
                    reason: "the canonical_store route cutover is not committed, so no route was switched",
                })
            }
            StorageRollbackDisposition::GenerationRollbackPermitted => {
                Ok(StorageRollbackDisposition::GenerationRollbackPermitted)
            }
            StorageRollbackDisposition::ForwardRepairRequired { .. } => {
                Err(KernelServiceError::GenerationFenced)
            }
        }
    }

    /// Refuses any stage that is not the exact next unreached stage.
    fn require_exact_next(&self, stage: StorageReplacementStage) -> Result<(), KernelServiceError> {
        if self.evidence.contains_key(&stage) {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_stage",
                reason: "the stage is already recorded for this replacement",
            });
        }
        if self.next_stage != Some(stage) {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_stage",
                reason: "a storage replacement stage may only be reached through its exact predecessor",
            });
        }
        Ok(())
    }

    /// Records one stage's evidence and advances the machine past it.
    fn record_evidence(&mut self, stage: StorageReplacementStage, evidence: String) {
        self.evidence.insert(stage, evidence);
        self.next_stage = stage.next();
    }
}

/// Refuses anything that is not a lowercase SHA-256 digest.
fn validate_digest(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

/// Projects one ORS refusal onto the existing [`KernelServiceError`] variants
/// without collapsing its class into a string.
///
/// Every current [`OrsError`] class is classified. A class that asserts the
/// presented ORS state does not match the required authority, fence, epoch,
/// owner or durable head becomes [`KernelServiceError::HandshakeMismatch`] with
/// a `field` naming that exact class, so it stays distinguishable from a field
/// rejection, a transition refusal and an unavailability. The remaining
/// bounded-field, bound, conflict and lifecycle classes become
/// [`KernelServiceError::InvalidField`] with a `field` naming that exact class;
/// [`OrsError::InvalidField`], which already carries both values, maps across
/// with both `&'static str` values verbatim. Only the classes that are strings
/// in the source type — a foundation contract text, a
/// storage/encoding/staging text, canonical-evidence text, a migration reason
/// and an integrity reason — reach [`KernelServiceError::Platform`], because
/// there is nothing typed left to preserve in them.
///
/// The match is exhaustive by construction: a new ORS class is a compile error
/// here rather than a silently stringified refusal.
fn ors_refusal(error: &OrsError) -> KernelServiceError {
    match error {
        // The presented ORS state does not match the required authority,
        // fence, owner or durable head.
        OrsError::FenceMismatch => mismatch("authority_epoch_fence"),
        OrsError::EpochMismatch => mismatch("authority_epoch"),
        OrsError::InvalidEpochLineage => mismatch("epoch_lineage"),
        OrsError::StaleWriterEpoch => mismatch("writer_epoch"),
        OrsError::AuthorityHandoffNotFresh => mismatch("authority_handoff"),
        OrsError::RecoveryOwnerMismatch => mismatch("recovery_owner"),
        OrsError::OrderingHeadMismatch => mismatch("ordering_head"),
        OrsError::ReconciliationMismatch => mismatch("canonical_reconciliation"),
        OrsError::IncompatibleArtifact => mismatch("candidate_artifact"),
        OrsError::ProcessStreamRecoveryFamilyCursorMismatch { .. } => {
            mismatch("process_stream_recovery_cursor")
        }
        OrsError::WorkerReplayStaleStream { .. } => mismatch("worker_replay_stream"),
        OrsError::WorkerReplayAckMismatch { .. } => mismatch("worker_replay_ack"),
        OrsError::RecoverySnapshotMoved { .. } => mismatch("recovery_inventory_revision"),
        // An ORS field rejection already has this crate's exact refusal shape.
        OrsError::InvalidField { field, reason } => {
            KernelServiceError::InvalidField { field, reason }
        }
        // The free-form classes: their payload is text in the source type, so
        // this is the only place a string is honest.
        OrsError::Contract(_)
        | OrsError::CanonicalEvidence(_)
        | OrsError::MigrationRequired { .. }
        | OrsError::IntegrityProblem { .. }
        | OrsError::Storage(_)
        | OrsError::Encoding(_)
        | OrsError::StagingNotDurable(_) => KernelServiceError::Platform(error.to_string()),
        // Stale or unbound lease lineage is a presented-record mismatch.
        OrsError::SupervisionLeaseStaleRevision => mismatch("lease_revision_stale"),
        OrsError::SupervisionLeaseBindingMismatch => mismatch("lease_binding"),
        // Every remaining class is a bounded-field, bound, conflict or
        // lifecycle refusal with no authority claim to mismatch against.
        OrsError::BridgeEventCapacityExceeded(_) => invalid_field("bridge_event_capacity"),
        OrsError::UnsupportedContractVersion(_) => invalid_field("envelope_contract_version"),
        OrsError::PayloadTooLarge => invalid_field("payload_length"),
        OrsError::PayloadIntegrityMismatch => invalid_field("payload_integrity"),
        OrsError::InvalidExpiry => invalid_field("expiry_ordering"),
        OrsError::UnsafeExpiry => invalid_field("expiry_reconciliation"),
        OrsError::EmptyScopeSet => invalid_field("ordering_scopes_empty"),
        OrsError::DuplicateScope => invalid_field("ordering_scopes_duplicate"),
        OrsError::InvalidCursorLimit => invalid_field("recovery_cursor_limit"),
        OrsError::DuplicateConflict => invalid_field("durable_state_duplicate"),
        OrsError::AlreadyTerminalWrite(_) => invalid_field("reservation_already_terminal"),
        OrsError::ReservationNotFound => invalid_field("reservation_missing"),
        OrsError::InvalidTransition => invalid_field("reservation_lifecycle"),
        OrsError::PredecessorPending => invalid_field("ordering_scope_predecessor"),
        OrsError::ScopeRecoveryRequired => invalid_field("ordering_scope_reconciliation"),
        OrsError::UnknownReceiptCannotResolve => invalid_field("unknown_receipt_resolution"),
        OrsError::InboxIntegrityMismatch => invalid_field("recovery_inbox_integrity"),
        OrsError::AuthoritySnapshotUnavailable => invalid_field("authority_snapshot"),
        OrsError::ProjectionLimitExceeded => invalid_field("operational_projection_bound"),
        OrsError::ProcessStreamRecoveryFamilyMoved { .. } => {
            invalid_field("process_stream_family_moved")
        }
        OrsError::SupervisionLeaseTicketConflict => invalid_field("lease_ticket_conflict"),
        OrsError::SupervisionLeaseTicketNotStaged => invalid_field("lease_ticket_not_staged"),
        OrsError::SupervisionLeaseTicketResolved => invalid_field("lease_ticket_resolved"),
        OrsError::SupervisionLeaseTicketNotExpired => invalid_field("lease_ticket_not_expired"),
        OrsError::SupervisionLeaseTicketExpired => invalid_field("lease_ticket_expired"),
        OrsError::SupervisionLeaseTicketAlreadyCommitted => invalid_field("lease_ticket_committed"),
        OrsError::InvalidSupervisionLeaseHistoryLimit => invalid_field("lease_history_limit"),
        OrsError::HostRequestIdentityConflict { .. } => invalid_field("host_request_identity"),
        OrsError::HostRequestLegacyCorrelationUnresolved => {
            invalid_field("host_request_legacy_correlation")
        }
        OrsError::CampaignLearningStateViewConflict { .. } => {
            invalid_field("campaign_learning_state_view")
        }
        OrsError::CampaignSourcePublicationConflict { .. } => {
            invalid_field("campaign_source_publication")
        }
        OrsError::ActivationResultRetentionIdentityConflict { .. } => {
            invalid_field("activation_result_ticket")
        }
        OrsError::ActivationLifecycleIdentityConflict { .. } => {
            invalid_field("activation_lifecycle_ticket")
        }
        OrsError::ActivationLifecycleExpired { .. } => {
            invalid_field("activation_lifecycle_ticket_expired")
        }
        OrsError::ActivationLifecycleStateConflict { .. } => {
            invalid_field("activation_lifecycle_ticket_state")
        }
        OrsError::NativeWorkerClaimIdentityConflict { .. } => {
            invalid_field("native_worker_claim_identity")
        }
        OrsError::WorkerReplayIdentityConflict { .. } => invalid_field("worker_replay_identity"),
        OrsError::WorkerReplayIncomplete { .. } => invalid_field("worker_replay_suffix"),
        OrsError::VersionedArtifactConflict => invalid_field("versioned_artifact_conflict"),
        OrsError::ActiveExecutableReplacement => invalid_field("active_executable"),
        OrsError::VersionedArtifactNotFound => invalid_field("versioned_artifact_missing"),
        OrsError::VersionedArtifactNotDrained => invalid_field("versioned_artifact_draining"),
        OrsError::RecoveryProblemRetained { .. } => invalid_field("staged_payload_recovery"),
        // Neither write-staging failure is an admitted storage-replacement
        // outcome. If an ORS provider surfaces one here, close generation
        // authority until the original operation is reconciled by its owner.
        OrsError::StagingCommitOutcomeUnknown { .. }
        | OrsError::RecoveryProblemRecordFailed { .. } => KernelServiceError::GenerationFenced,
    }
}

/// Names one ORS mismatch class on the crate's typed mismatch refusal.
fn mismatch(field: &'static str) -> KernelServiceError {
    KernelServiceError::HandshakeMismatch { field }
}

/// Names one ORS field or bound refusal on the crate's typed field refusal.
///
/// The `field` is the ORS class name, so no two ORS refusals of this family read
/// alike. The shared reason states who refused: the durable ORS owner. A class
/// that carries its own reason — [`OrsError::InvalidField`] — keeps it verbatim
/// instead.
fn invalid_field(field: &'static str) -> KernelServiceError {
    KernelServiceError::InvalidField {
        field,
        reason: "rejected by the durable ORS owner",
    }
}
