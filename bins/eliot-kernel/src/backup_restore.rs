//! Kernel-owned production restore adapter (issue #960, lane F first slice).
//!
//! Architecture: A13.7 Backups, Restore, and Migration (isolated restore,
//! purge-first, suspended ORS import, new lineage, separate cutover
//! authority); A13.6 Operational Recovery State (only identities, opaque
//! envelopes, epochs, suspended leases, checkpoints, intents, manifests,
//! anchors); I5.13 backup classes (full denominator, degraded ceiling,
//! key-material rule); I14.21 unknown-commit recovery (reconcile by identity,
//! never blind retry); A0.3 Hard Boundaries (no revived authority, no minted
//! epochs, no fabricated receipts).
//! Implementation: the single existing journaled state machine
//! ([`RestorePlan::execute_with_journal`](eliot_backup::RestorePlan::execute_with_journal))
//! drives execution and resumption — same-transaction resume is a second call
//! with the same bundle and target context, never a second engine. I5.19
//! intent-before-effect ordering and I5.27 canonical operation identity come
//! from that engine, not from this file.
//!
//! What this file owns: the thin [`KernelBackupRestore`] execution body plus
//! the [`RestoreTarget`](eliot_backup::RestoreTarget) adapter
//! (`apply_restore_effect` / `reconcile_restore_effect`) over the historical
//! per-phase owner methods the accepted contract retains for owner adapters.
//! Every phase maps to its responsible owner through [`phase_owner`]. Owner
//! channels bind in #962: until then every owner phase refuses fail-closed
//! with the exact responsible capability
//! ([`RestoreCapabilityUnsupported`](eliot_backup::BackupError::RestoreCapabilityUnsupported)),
//! and owner-phase reconciliation reports `Unknown` so the outcome propagates
//! without a new identity and without blind retry (I14.21). `NotApplied` is
//! returned only where this target proves non-application: the Kernel-owned
//! prepare phase via persisted-receipt readback, and finalize, whose arm is
//! statically refuse-only this turn (required owner obligations were not
//! attempted). The #962 turn must upgrade owner-phase reconciliation to
//! owner readback-or-`Unknown`; it must never downgrade `Unknown` to a blind
//! re-apply.
//!
//! Capability cell: Kernel restore ownership (isolated import execution).
//! Forbidden authority: no ORS row reinterpretation, no epoch minting, no
//! cutover, no activation/retirement of any installation, no second phase
//! engine, no archive/phase algorithm, no invented target methods, no
//! Value-based escapes.

use std::path::PathBuf;

use eliot_backup::{
    BackupBundle, BackupError, RestoreAppliedEffect, RestoreContext, RestoreEffectReceipt,
    RestoreEvidence, RestoreHistoricalAuthority, RestoreIntent, RestorePhase, RestorePlan,
    RestoreReceipt, RestoreReconciliation, RestoreStep, RestoreTarget, WrappedKeyManifest,
    suspended_recovery_entries, verify_key_coverage,
};
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use serde::Serialize;

use super::backup_restore_ports::{
    KernelIsolatedDestination, KernelRestoreError, KernelRestoreJournal, check_kernel_effect_fence,
};

/// Maps one accepted restore step to its responsible owner.
///
/// The owner vocabulary matches the obligation owner ids carried in restore
/// evidence, so every executed phase is attributable to exactly one owner.
/// Steps whose external owner channel is not yet bound (#962) keep their
/// true owner here and refuse at execution; the mapping never substitutes
/// the Kernel restore owner for a missing external owner.
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

/// Owner obligation identifiers shared by the phase matrix and evidence.
///
/// These name the exact owners from the accepted obligation vocabulary; they
/// are attribution labels and refusal capabilities, never new authority.
mod owners {
    pub const PURGE: &str = "purge-owner";
    pub const CANONICAL: &str = "canonical-owner";
    pub const BLOB: &str = "blob-owner";
    pub const ORS: &str = "ors-owner";
}

/// Outcome of one Kernel-executed isolated restore: the journaled receipt,
/// target-observed evidence when this process executed finalize, suspended
/// work, the exact applied phase log, and the observed paths. No cutover,
/// activation, or retirement is performed or reported.
///
/// `evidence` is `None` until owner channels bind (#962) and this process
/// executes finalize: no evidence is reconstructed from counts, and a
/// resumed run whose finalize executed elsewhere reports that run's receipt
/// without self-attesting evidence it never observed.
#[derive(Clone, Debug, PartialEq)]
pub struct KernelRestoreOutcome {
    pub receipt: RestoreReceipt,
    pub evidence: Option<RestoreEvidence>,
    pub suspended_entries: Vec<RestoreHistoricalAuthority>,
    pub phase_log: Vec<String>,
    pub destination_root: PathBuf,
    pub journal_path: PathBuf,
}

/// Kernel-owned production restore adapter.
///
/// Owns the admitted durable journal and the constructed (not accepted)
/// isolated destination. Execution binds one archive, one plan context, the
/// Kernel's current effect fence, and optional key material. The adapter
/// never mints epochs, never activates authority, and never performs
/// cutover. Re-running with the same bundle and target context resumes the
/// same transaction from the durable journal instead of re-applying.
pub struct KernelBackupRestore {
    journal: KernelRestoreJournal,
    work_root: PathBuf,
}

impl KernelBackupRestore {
    /// Binds the restore owner to its admitted journal and work root.
    pub fn bind(journal: KernelRestoreJournal, work_root: PathBuf) -> Self {
        Self { journal, work_root }
    }

    /// Opens the restore owner on a fresh journal below `work_root`.
    ///
    /// The journal starts unadmitted: bind owner admission on
    /// [`KernelRestoreJournal::admit`] before executing. Production
    /// durability claims additionally require a non-fixture admission (see
    /// [`RestoreJournalAdmission::admits_production_durable_recovery`](eliot_backup::RestoreJournalAdmission::admits_production_durable_recovery)).
    pub fn open(work_root: &std::path::Path) -> Result<Self, KernelRestoreError> {
        Ok(Self {
            journal: KernelRestoreJournal::open(work_root)?,
            work_root: work_root.to_path_buf(),
        })
    }

    /// Returns the bound journal (admission, resume inspection).
    pub fn journal(&mut self) -> &mut KernelRestoreJournal {
        &mut self.journal
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
    /// `kernel_fence` is the Kernel's current authority fence supplied by the
    /// production caller (never caller arithmetic inside this adapter): the
    /// archive fence must be compatible with it before any effect, otherwise
    /// the restore is refused with zero target effects. Blob-carrying
    /// archives without exact key coverage refuse before any effect; a
    /// fixture-flagged journal admission refuses as not admitted for
    /// production. Coordinator failures propagate typed in
    /// [`KernelRestoreError::TargetFailed`]; the primary error is preserved,
    /// never flattened into a fabricated success.
    pub fn restore(
        &mut self,
        bundle: &BackupBundle,
        target: RestoreContext,
        kernel_fence: &StateFence,
        keys: Option<&WrappedKeyManifest>,
    ) -> Result<KernelRestoreOutcome, KernelRestoreError> {
        bundle
            .validate()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        self.journal.require_production_admitted()?;
        if !bundle
            .export_fence
            .state_fence
            .is_compatible_with(kernel_fence)
        {
            return Err(KernelRestoreError::FenceMismatch(
                "archive fence is not compatible with the Kernel effect fence".to_owned(),
            ));
        }
        match keys {
            Some(manifest) => verify_key_coverage(&bundle.blobs, manifest)
                .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?,
            None if !bundle.blobs.is_empty() => {
                return Err(KernelRestoreError::CapabilityMissing {
                    capability: "blob_key_material",
                });
            }
            None => {}
        }
        let plan = RestorePlan::compile(bundle, target.clone())
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        let destination = KernelIsolatedDestination::open(&self.work_root, &target.target_id)?;
        let mut target_impl =
            KernelRestoreTarget::new(&destination, kernel_fence.clone());
        let receipt = plan
            .execute_with_journal(bundle, &mut target_impl, &mut self.journal)
            .map_err(KernelRestoreError::TargetFailed)?;
        let suspended = suspended_entries(bundle)?;
        Ok(KernelRestoreOutcome {
            receipt,
            evidence: target_impl.final_evidence,
            suspended_entries: suspended,
            phase_log: target_impl.calls,
            destination_root: target_impl.root,
            journal_path: self.journal.journal_path().to_path_buf(),
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

/// Kernel-observed prepare evidence: the exact intent executed, bound to the
/// compiled plan and the constructed destination. Observation, not authority.
#[derive(Serialize)]
struct ObservedPrepare {
    transaction_id: String,
    plan_id: String,
    destination: String,
    outcome: String,
}

/// Kernel restore target over the accepted effect seam.
///
/// Every applicable phase re-checks the Kernel effect fence before touching
/// state. The Kernel-owned prepare phase validates the exact bundle member
/// path it touches, persists exact bytes, and returns an observed receipt;
/// finalize is statically refuse-only until owner channels bind (#962), and
/// every owner phase refuses with its exact responsible capability. Unknown
/// owner outcomes propagate as `Unknown`: no new identity, no blind retry.
struct KernelRestoreTarget {
    root: PathBuf,
    kernel_fence: StateFence,
    calls: Vec<String>,
    final_evidence: Option<RestoreEvidence>,
}

impl KernelRestoreTarget {
    fn new(destination: &KernelIsolatedDestination, kernel_fence: StateFence) -> Self {
        Self {
            root: destination.root().to_path_buf(),
            kernel_fence,
            calls: Vec::new(),
            final_evidence: None,
        }
    }

    fn write_file(&self, relative: &str, bytes: &[u8]) -> Result<(), BackupError> {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| BackupError::Target(error.to_string()))?;
        }
        std::fs::write(&path, bytes).map_err(|error| BackupError::Target(error.to_string()))
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
        &self,
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

    fn load_applied(
        &self,
        intent: &RestoreIntent,
    ) -> Result<Option<RestoreAppliedEffect>, BackupError> {
        let path = self.phase_receipt_path(&intent.phase)?;
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(|error| BackupError::Target(error.to_string()))?;
        let applied: RestoreAppliedEffect =
            serde_json::from_slice(&bytes).map_err(|_| BackupError::RestoreJournalCorrupt)?;
        if applied.receipt.transaction_id != intent.transaction_id
            || applied.receipt.phase != intent.phase
            || applied.receipt.input_digest != intent.input_digest
        {
            return Err(BackupError::RestoreJournalCorrupt);
        }
        Ok(Some(applied))
    }

    /// Re-checks the Kernel effect fence before an applicable phase.
    fn gate(&self, bundle: &BackupBundle) -> Result<(), BackupError> {
        check_kernel_effect_fence(&self.kernel_fence, bundle)
    }

    fn apply_prepare(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        self.gate(bundle)?;
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

    fn apply_phase(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        match &intent.phase {
            RestorePhase::Pending => Err(BackupError::RestorePhaseMismatch),
            RestorePhase::PrepareIsolatedRoot => self.apply_prepare(plan, bundle, intent),
            // Owner phases: channels bind in #962. Refuse with the exact
            // responsible capability; never self-attest an owner effect.
            RestorePhase::ApplyPurgeLedger => {
                Err(BackupError::RestoreCapabilityUnsupported {
                    capability: owners::PURGE,
                })
            }
            RestorePhase::ImportSealedBlob { .. } => {
                Err(BackupError::RestoreCapabilityUnsupported {
                    capability: owners::BLOB,
                })
            }
            RestorePhase::ImportCanonicalEvent { .. }
            | RestorePhase::ImportReceipt { .. }
            | RestorePhase::ImportProjection { .. }
            | RestorePhase::RebuildProjections
            | RestorePhase::VerifyReceiptEventChain => {
                Err(BackupError::RestoreCapabilityUnsupported {
                    capability: owners::CANONICAL,
                })
            }
            RestorePhase::SuspendOrsOperations => {
                Err(BackupError::RestoreCapabilityUnsupported {
                    capability: owners::ORS,
                })
            }
            // Finalize cannot attest evidence while required owner effects
            // were not attempted: honest evidence cannot validate
            // (`RestoreEvidence::validate` requires observed import claims),
            // so this arm refuses instead of minting invalid evidence. The
            // #962 turn replaces this arm with observed-evidence assembly.
            RestorePhase::FinalizeIsolatedRoot => {
                Err(BackupError::RestoreCapabilityNotAttempted {
                    capability: "owner-effect-obligations",
                })
            }
        }
    }
}

impl RestoreTarget for KernelRestoreTarget {
    fn apply_restore_effect(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        if intent.transaction_id.is_empty() {
            return Err(BackupError::RestoreJournalCorrupt);
        }
        self.apply_phase(plan, bundle, intent)
    }

    fn reconcile_restore_effect(
        &mut self,
        intent: &RestoreIntent,
    ) -> Result<RestoreReconciliation, BackupError> {
        match &intent.phase {
            RestorePhase::PrepareIsolatedRoot => match self.load_applied(intent)? {
                Some(applied) => Ok(RestoreReconciliation::Applied(applied)),
                None => Ok(RestoreReconciliation::NotApplied),
            },
            // Statically refuse-only this turn: no finalize effect could have
            // happened, so re-applying deterministically refuses again. No
            // duplicate effect is possible through this arm.
            RestorePhase::FinalizeIsolatedRoot => Ok(RestoreReconciliation::NotApplied),
            RestorePhase::Pending => Err(BackupError::RestorePhaseMismatch),
            // Owner phases: no owner readback exists until #962 binds the
            // channels, so the outcome stays unknown and propagates. The
            // coordinator converts this to an explicit rollback-required
            // disposition; nothing here invents a new identity or retries.
            _ => Ok(RestoreReconciliation::Unknown),
        }
    }
}
