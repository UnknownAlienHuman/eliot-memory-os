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
//! `I5.10` names `ECXF/1` as the logical transfer format, so the snapshot
//! import and the event tail are ECXF exchanges. `I14.14` owns the
//! `CapabilityRouteScope`, the durable cutover record, the in-flight
//! disposition set, the rollback boundary and the receipt, and states that the
//! ORS commit is the durable linearization point while an irreversible state
//! migration requires forward repair or a separately proven rollback path.
//! `A13.3` supplies the promotion contour (shadow, bounded canary, active
//! generation, drain and retire or forward rollback) this module orders.
//!
//! ## Ordered stages
//!
//! ```text
//! install candidate store bridge
//!   -> import snapshot into candidate
//!   -> verify counts, hashes, graph/projection invariants
//!   -> shadow reads against both stores
//!   -> tail canonical events into candidate
//!   -> quiesce affected writes
//!   -> reconcile final sequence
//!   -> commit the canonical_store CapabilityRouteScope cutover
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
//! This module (`StorageReplacement`) the I5.11 stage machine, its per-stage
//!                                 recorded evidence, the irreversible-effect
//!                                 ledger and the cutover receipt
//! ORS (`eliot_ors`)               the committed `GenerationCutoverOwnership`,
//!                                 its `GenerationCutoverOwnershipReceipt`, the
//!                                 in-flight dispositions, the route snapshot
//!                                 and the route-scope hash
//! Store / candidate bridge        the imported snapshot, the verification and
//!                                 shadow-read comparison, the canary result
//!                                 and the read-only rollback window
//! ```
//!
//! ## Negative: the candidate cannot become canonical by configuration
//!
//! The coordinator is the only writer of a replacement's stage position, and
//! the cutover receipt is derived exclusively from an ORS-committed
//! `GenerationCutoverOwnership` for this replacement's own
//! `canonical_store` route scope and its own two store generations. A
//! configuration flip, a restart or a direct route selection therefore cannot
//! name the candidate as canonical: before stage 8 is committed no receipt
//! exists, and after it the only authority is the committed ORS record that
//! [`GenerationCutoverOwnershipReceipt::from_committed`] already refuses to
//! synthesize while the record is still staged. The coordinator grants no
//! authority of its own and interprets no store payload.
//!
//! ## Typed ORS refusals
//!
//! [`GenerationCutoverOwnershipReceipt::from_committed`] and
//! [`CapabilityRouteScope::validate`] fail with a typed [`OrsError`], and this
//! module classifies every class of it onto the existing [`KernelServiceError`]
//! Every class of it is classified onto the existing [`KernelServiceError`]
//! variants by class. A fence mismatch, an epoch-lineage break, a stale writer
//! epoch, a duplicate conflict, an invalid transition, a field rejection and an
//! unavailability therefore stay distinguishable at the Kernel service
//! boundary; only the classes that are text in the source type reach
//! [`KernelServiceError::Platform`]. No ORS class is collapsed into a string or
//! a generic code between the layers.
//!
//! ## Rollback
//!
//! [`StorageReplacement::rollback_disposition`] is a pure classifier over the
//! recorded irreversible effects. [`StorageReplacement::request_rollback`]
//! enforces it: while no irreversible effect is recorded a generation rollback
//! is admitted (and the route switch itself is another committed cutover with a
//! newer epoch, never a local flag flip); once one is recorded the request is
//! refused as [`KernelServiceError::GenerationFenced`] and only the explicit
//! forward-repair path follows.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use eliot_contracts::ResourceGeneration;
use eliot_ors::{
    CapabilityRouteScope, GenerationCutoverOwnership, GenerationCutoverOwnershipReceipt, OrsError,
    StateMigrationDecision,
};
use eliot_runtime_contracts::GenerationCutoverState;

use crate::{KernelServiceError, validate_text};

/// The capability whose route this coordinator is bound to.
///
/// A replacement is refused for any other capability: the I5.11 stage machine
/// governs the canonical Store route, not an arbitrary module capability.
pub const CANONICAL_STORE_CAPABILITY: &str = "canonical_store";

/// The `I5.10` logical transfer format used for the snapshot import and the
/// canonical event tail.
pub const STORAGE_REPLACEMENT_TRANSFER_FORMAT: &str = "ECXF/1";

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
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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
/// It names both store generations, the full `canonical_store` route scope, and
/// the ORS-committed cutover the route cutover was derived from. It is
/// constructed only by
/// [`StorageReplacement::commit_canonical_store_route_cutover`], which calls
/// [`GenerationCutoverOwnershipReceipt::from_committed`] and therefore fails
/// while the ORS record is still staged: a receipt can never precede the
/// durable linearization point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageReplacementCutoverReceipt {
    /// The replacement identity this receipt belongs to.
    pub replacement_id: String,
    /// The store generation that owned the route before the cutover.
    pub incumbent_generation: Option<ResourceGeneration>,
    /// The store generation that owns the route after the cutover.
    pub candidate_generation: ResourceGeneration,
    /// The committed `canonical_store` `CapabilityRouteScope`.
    pub route_scope: CapabilityRouteScope,
    /// The ORS-committed cutover ownership receipt proving the linearization
    /// point.
    pub committed_cutover: GenerationCutoverOwnershipReceipt,
    /// The irreversible effects recorded when the cutover was committed.
    pub irreversible_effects: BTreeSet<IrreversibleStorageEffect>,
}

/// The Kernel-owned coordinator for one I5.11 storage replacement.
///
/// It owns the stage position, the per-stage recorded evidence, the two store
/// generations, the `canonical_store` route scope, the irreversible-effect
/// ledger and the cutover receipt. It stores no snapshot bytes, no event tail
/// and no canary result: those stay with the Store and the candidate bridge and
/// reach the coordinator only as the evidence a stage records.
#[derive(Clone, Debug)]
pub struct StorageReplacement {
    replacement_id: String,
    scope: CapabilityRouteScope,
    incumbent_generation: Option<ResourceGeneration>,
    candidate_generation: ResourceGeneration,
    next_stage: Option<StorageReplacementStage>,
    evidence: BTreeMap<StorageReplacementStage, String>,
    irreversible_effects: BTreeSet<IrreversibleStorageEffect>,
    cutover: Option<GenerationCutoverOwnership>,
    receipt: Option<StorageReplacementCutoverReceipt>,
}

impl StorageReplacement {
    /// Starts one replacement bound to the `canonical_store` capability route
    /// scope.
    ///
    /// The first stage to record is
    /// [`StorageReplacementStage::InstallCandidateStoreBridge`]; nothing about
    /// the candidate is active before its own evidence is recorded.
    pub fn begin(
        replacement_id: impl Into<String>,
        scope: CapabilityRouteScope,
        incumbent_generation: Option<ResourceGeneration>,
        candidate_generation: ResourceGeneration,
    ) -> Result<Self, KernelServiceError> {
        let replacement_id = replacement_id.into();
        validate_text(&replacement_id, "storage_replacement_id")?;
        scope.validate().map_err(|error| ors_refusal(&error))?;
        if scope.capability != CANONICAL_STORE_CAPABILITY {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_capability",
                reason: "storage replacement is bound to the canonical_store capability route scope",
            });
        }
        if incumbent_generation == Some(candidate_generation) {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_candidate_generation",
                reason: "a replacement must select a distinct candidate store generation",
            });
        }
        Ok(Self {
            replacement_id,
            scope,
            incumbent_generation,
            candidate_generation,
            next_stage: Some(StorageReplacementStage::InstallCandidateStoreBridge),
            evidence: BTreeMap::new(),
            irreversible_effects: BTreeSet::new(),
            cutover: None,
            receipt: None,
        })
    }

    /// The replacement identity.
    #[must_use]
    pub fn replacement_id(&self) -> &str {
        &self.replacement_id
    }

    /// The `canonical_store` `CapabilityRouteScope` this replacement is bound
    /// to.
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
    /// Stage 8 has its own method because it also carries the ORS commit, and
    /// stage 11 is refused until a cutover receipt exists.
    pub fn record_stage(
        &mut self,
        stage: StorageReplacementStage,
        evidence: impl Into<String>,
    ) -> Result<StorageReplacementStage, KernelServiceError> {
        let evidence = evidence.into();
        validate_text(&evidence, "storage_replacement_evidence")?;
        if stage == StorageReplacementStage::CommitCanonicalStoreRouteCutover {
            return Err(KernelServiceError::InvalidField {
                field: "storage_replacement_stage",
                reason: "the canonical_store route cutover is recorded by committing its generation cutover record",
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

    /// Commits the `canonical_store` `CapabilityRouteScope` cutover through the
    /// Kernel Generation Registry (I5.11 stage 8) and publishes its receipt.
    ///
    /// The record must be the ORS-committed cutover for this replacement's own
    /// route scope and its own two store generations; a staged record yields no
    /// receipt, because
    /// [`GenerationCutoverOwnershipReceipt::from_committed`] refuses before the
    /// durable linearization point. The declared state migration must name
    /// forward repair exactly when an irreversible effect is already recorded,
    /// so the committed record and the coordinator's own irreversible-effect
    /// ledger can never disagree about whether a generation rollback is still
    /// available.
    pub fn commit_canonical_store_route_cutover(
        &mut self,
        record: GenerationCutoverOwnership,
        evidence: impl Into<String>,
    ) -> Result<StorageReplacementCutoverReceipt, KernelServiceError> {
        let evidence = evidence.into();
        validate_text(&evidence, "storage_replacement_evidence")?;
        self.require_exact_next(StorageReplacementStage::CommitCanonicalStoreRouteCutover)?;
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
            committed_cutover,
            irreversible_effects: self.irreversible_effects.clone(),
        };
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
    pub fn record_irreversible_effect(&mut self, effect: IrreversibleStorageEffect) {
        self.irreversible_effects.insert(effect);
    }

    /// Classifies a rollback request without changing any state.
    ///
    /// This is the pure form of the `I5.11` rule; it reads only the recorded
    /// irreversible effects.
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
    /// While no irreversible effect is recorded and the cutover is committed,
    /// the generation rollback is permitted; performing it is another committed
    /// cutover with a newer epoch, never a local flag flip. Once an irreversible
    /// effect is recorded the request is refused as a generation rollback with
    /// [`KernelServiceError::GenerationFenced`] and only the forward-repair path
    /// named by [`Self::rollback_disposition`] follows.
    pub fn request_rollback(&self) -> Result<StorageRollbackDisposition, KernelServiceError> {
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
