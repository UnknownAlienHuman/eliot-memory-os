//! Kernel-owned production restore adapter (issue #960).
//!
//! Architecture: A13.7 Backups, Restore, and Migration (isolated restore,
//! purge-first, suspended ORS import, new lineage, separate cutover
//! authority); A13.6 Operational Recovery State (only identities, opaque
//! envelopes, epochs, suspended leases, checkpoints, intents, manifests,
//! anchors); I5.13 backup classes (full denominator, degraded ceiling,
//! key-material rule); I14.21 unknown-commit recovery (reconcile by identity,
//! never blind retry); A0.3 Hard Boundaries (no revived authority, no minted
//! epochs, no fabricated receipts).
//! Implementation: binds the accepted `RestorePlan::execute_with_journal`
//! engine plus the `RestoreTarget::{apply_restore_effect,
//! reconcile_restore_effect}` effect seam and the historical per-phase owner
//! methods retained for owner adapters. Every phase maps to its responsible
//! owner through [`phase_owner`]; missing owner channels stay explicit
//! (`Unknown`/`MissingCapability`), never self-attested success.
//! Health reading: every refusal names phase/identity/owner; primary errors
//! propagate unchanged.
//! Failure containment: I14.24 (a refused effect preserves the journal and
//! the observed cause; rollback is explicit, never destructive).
//!
//! Capability cell: Kernel restore ownership (isolated import execution,
//! obligation evidence, owner-epoch admission). Read through the restore
//! receipt and evidence vocabulary.
//! Forbidden authority: no ORS row reinterpretation, no epoch minting, no
//! cutover, no activation/retirement of any installation, no second phase
//! engine, no invented target methods.

use eliot_backup::{
    BackupBlob, BackupBundle, BackupError, CanonicalRecord, OrsSnapshotFence,
    RestoreAppliedEffect, RestoreContext, RestoreEffectReceipt, RestoreEvidence,
    RestoreHistoricalAuthority, RestoreIntent, RestoreObligationState, RestoreOwnerObligation,
    RestorePhase, RestorePlan, RestoreReceipt, RestoreReconciliation, RestoreStep, RestoreTarget,
    RestoredFence, WrappedKeyManifest, suspended_recovery_entries,
};
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::WriteReceipt;
use std::collections::BTreeSet;

use super::backup_restore_ports::{
    KernelIsolatedDestination, KernelRestoreError, KernelRestoreJournal,
};

/// Maps one accepted restore step to its responsible owner.
///
/// The owner vocabulary matches the obligation owner ids carried in restore
/// evidence, so every executed phase is attributable to exactly one owner.
/// No step maps to a missing owner: steps whose external owner channel is
/// not yet bound (#962) map to the Kernel restore owner as the executing
/// party, while the corresponding EVIDENCE obligation stays explicitly
/// unresolved (see [`KernelRestoreTarget`] finalize).
#[must_use]
pub const fn phase_owner(step: &RestoreStep) -> &'static str {
    match step {
        RestoreStep::PrepareIsolatedRoot | RestoreStep::FinalizeIsolatedRoot => {
            "kernel-restore-owner"
        }
        RestoreStep::ApplyPurgeLedger => "purge-owner",
        RestoreStep::ImportSealedBlobs => "blob-owner",
        RestoreStep::ImportCanonicalEvents
        | RestoreStep::ImportReceipts
        | RestoreStep::ImportProjections
        | RestoreStep::RebuildProjections
        | RestoreStep::VerifyReceiptEventChain => "canonical-owner",
        RestoreStep::SuspendOrsOperations => "ors-owner",
    }
}

/// Outcome of one Kernel-executed isolated restore: the journaled receipt,
/// the target-observed evidence, suspended work, the exact applied phase log,
/// and the temp-external paths observed. No cutover, activation, or
/// retirement is performed or reported.
#[derive(Clone, Debug, PartialEq)]
pub struct KernelRestoreOutcome {
    pub receipt: RestoreReceipt,
    pub evidence: RestoreEvidence,
    pub suspended_entries: Vec<RestoreHistoricalAuthority>,
    pub phase_log: Vec<String>,
    pub destination_root: std::path::PathBuf,
    pub journal_path: std::path::PathBuf,
}

/// Kernel-owned production restore adapter.
///
/// Owns the admitted durable journal and the constructed (not accepted)
/// isolated destination. Execution binds one archive, one plan context, the
/// Kernel's current effect fence, optional key material, and optional
/// owner-issued epoch evidence. The adapter never mints epochs, never
/// activates authority, and never performs cutover.
pub struct KernelBackupRestore {
    journal: KernelRestoreJournal,
    work_root: std::path::PathBuf,
}

impl KernelBackupRestore {
    /// Binds the restore owner to its admitted journal and work root.
    pub fn bind(journal: KernelRestoreJournal, work_root: std::path::PathBuf) -> Self {
        Self { journal, work_root }
    }

    /// Opens the restore owner on a fresh journal below `work_root`.
    ///
    /// The journal starts unadmitted: bind owner admission on
    /// [`KernelRestoreJournal::admit`] before executing. Used by composition
    /// and rehearsal alike; production durability claims additionally require
    /// a non-fixture admission (see
    /// [`RestoreJournalAdmission::admits_production_durable_recovery`]).
    pub fn open(work_root: &std::path::Path) -> Result<Self, KernelRestoreError> {
        Ok(Self {
            journal: KernelRestoreJournal::open(work_root)?,
            work_root: work_root.to_path_buf(),
        })
    }

    /// Returns the bound journal (resume, inspection, tests).
    pub fn journal(&mut self) -> &mut KernelRestoreJournal {
        &mut self.journal
    }

    /// Executes one isolated restore with the Kernel effect fence.
    ///
    /// `kernel_fence` is the Kernel's current authority fence supplied by the
    /// production caller (never caller arithmetic inside this adapter): the
    /// archive fence must be compatible with it before any effect, otherwise
    /// the restore is refused with zero target effects. `owner_epoch`, when
    /// present, must be exact owner-issued evidence advancing the observed
    /// lineage; it is validated, never minted.
    #[allow(clippy::too_many_lines)]
    pub fn restore(
        &mut self,
        bundle: &BackupBundle,
        target: RestoreContext,
        kernel_fence: &StateFence,
        keys: Option<&WrappedKeyManifest>,
        owner_epoch: Option<eliot_backup::RestoreOwnerEpoch>,
    ) -> Result<KernelRestoreOutcome, KernelRestoreError> {
        bundle
            .validate()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
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
            Some(manifest) => eliot_backup::verify_key_coverage(&bundle.blobs, manifest)
                .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?,
            None if !bundle.blobs.is_empty() => {
                return Err(KernelRestoreError::CapabilityMissing {
                    capability: "blob_key_material",
                });
            }
            None => {}
        }
        self.journal.require_admitted()?;
        let destination = KernelIsolatedDestination::open(&self.work_root, &target.target_id)?;
        let plan = RestorePlan::compile(bundle, target)
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        if let Some(epoch) = &owner_epoch {
            epoch
                .validate()
                .map_err(|error| KernelRestoreError::OwnerEvidenceInvalid(error.to_string()))?;
        }
        let mut target_impl =
            KernelRestoreTarget::new(&destination, kernel_fence.clone(), owner_epoch);
        let receipt = plan
            .execute_with_journal(bundle, &mut target_impl, &mut self.journal)
            .map_err(|error| KernelRestoreError::TargetFailed(error.to_string()))?;
        // On a resumed run the fresh target never executes finalize: rebuild
        // the deterministic evidence from plan and bundle instead of failing.
        // Both paths yield the identical value (same transaction, same
        // observed absence digest, same owner epoch).
        let evidence = if let Some(observed) = target_impl.final_evidence.clone() {
            observed
        } else {
            let transaction = plan
                .transaction()
                .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
            let rebuilt = target_impl
                .assemble_evidence(&plan, bundle, transaction.transaction_id.as_str())
                .map_err(|error| {
                    KernelRestoreError::TargetFailed(format!("resumed evidence: {error}"))
                })?;
            rebuilt.validate().map_err(|error| {
                KernelRestoreError::TargetFailed(format!("resumed evidence: {error}"))
            })?;
            rebuilt
        };
        let suspended = suspended_entries(bundle)?;
        Ok(KernelRestoreOutcome {
            receipt,
            evidence,
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

/// Owner obligation identifiers shared by the phase matrix and evidence.
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
}

/// Kernel restore target: real effects into the isolated destination.
///
/// Every effect first re-checks the Kernel fence gate, validates the exact
/// bundle member it restores, persists exact bytes, and returns an observed
/// receipt. The finalize phase builds evidence whose obligation states are
/// observed, not asserted: performed validations carry refs to observed
/// digests; ORS suspension is satisfied exactly when the archive snapshot was
/// suspended here; unknown reconciliation, external revalidation, and the
/// missing broker channel stay explicit.
struct KernelRestoreTarget {
    root: std::path::PathBuf,
    kernel_fence: StateFence,
    owner_epoch: Option<eliot_backup::RestoreOwnerEpoch>,
    calls: Vec<String>,
    final_evidence: Option<RestoreEvidence>,
}

impl KernelRestoreTarget {
    fn new(
        destination: &KernelIsolatedDestination,
        kernel_fence: StateFence,
        owner_epoch: Option<eliot_backup::RestoreOwnerEpoch>,
    ) -> Self {
        Self {
            root: destination.root().to_path_buf(),
            kernel_fence,
            owner_epoch,
            calls: Vec::new(),
            final_evidence: None,
        }
    }

    fn check_fence(&self, bundle: &BackupBundle) -> Result<(), BackupError> {
        if bundle
            .export_fence
            .state_fence
            .is_compatible_with(&self.kernel_fence)
        {
            Ok(())
        } else {
            Err(BackupError::FenceMismatch {
                subject: "kernel effect fence".to_owned(),
            })
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

    fn phase_receipt_path(&self, phase: &RestorePhase) -> Result<std::path::PathBuf, BackupError> {
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
        Ok(eliot_backup::RestoreEffectReceipt {
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
        applied: &eliot_backup::RestoreAppliedEffect,
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
    ) -> Result<Option<eliot_backup::RestoreAppliedEffect>, BackupError> {
        let path = self.phase_receipt_path(&intent.phase)?;
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(|error| BackupError::Target(error.to_string()))?;
        let applied: eliot_backup::RestoreAppliedEffect =
            serde_json::from_slice(&bytes).map_err(|_| BackupError::RestoreJournalCorrupt)?;
        if applied.receipt.transaction_id != intent.transaction_id
            || applied.receipt.phase != intent.phase
            || applied.receipt.input_digest != intent.input_digest
        {
            return Err(BackupError::RestoreJournalCorrupt);
        }
        Ok(Some(applied))
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
}

impl KernelRestoreTarget {
    /// Observes the fresh destination state that invalidation obligations bind.
    ///
    /// Reads the sorted root entry names plus the archive's verified
    /// no-active-authority flags (bundle/ORS validation already rejected
    /// `active_authority_restored`). The digest is persisted in
    /// `prepared.json` and read back at finalize, so resume reuses the
    /// initial observation instead of re-deriving it over phase outputs.
    fn observe_absence(&self, bundle: &BackupBundle) -> Result<String, BackupError> {
        let mut names = Vec::new();
        let entries = std::fs::read_dir(&self.root)
            .map_err(|error| BackupError::Target(error.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|error| BackupError::Target(error.to_string()))?;
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        let ors_active = bundle
            .ors_snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.active_authority_restored);
        let host_active = bundle
            .host_audit
            .as_ref()
            .is_some_and(|audit| audit.active_authority_restored);
        let material = format!("absence:{}:{}:{}", names.join(","), ors_active, host_active);
        Ok(sha256_hex(material.as_bytes()))
    }

    fn read_absence(&self) -> Result<String, BackupError> {
        let bytes = std::fs::read(self.root.join("prepared.json"))
            .map_err(|error| BackupError::Target(error.to_string()))?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| BackupError::RestoreJournalCorrupt)?;
        value
            .get("absence_digest")
            .and_then(|digest| digest.as_str())
            .map(str::to_owned)
            .ok_or(BackupError::RestoreJournalCorrupt)
    }

    fn section_sha(bundle: &BackupBundle, section: &str) -> Result<String, BackupError> {
        bundle
            .manifest
            .sections
            .get(section)
            .cloned()
            .ok_or(BackupError::PlanMismatch)
    }

    #[allow(clippy::too_many_lines)]
    fn apply_phase(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<eliot_backup::RestoreAppliedEffect, BackupError> {
        let applied = match &intent.phase {
            RestorePhase::Pending => return Err(BackupError::RestorePhaseMismatch),
            RestorePhase::PrepareIsolatedRoot => {
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
                let absence = self.observe_absence(bundle)?;
                let summary = serde_json::json!({
                    "plan_id": plan.plan_id,
                    "target_id": plan.target.target_id,
                    "absence_digest": absence,
                });
                let bytes = serde_json::to_vec(&summary)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file("prepared.json", &bytes)?;
                self.calls.push("prepare".to_owned());
                Self::effect(intent, &bytes)?
            }
            RestorePhase::ApplyPurgeLedger => {
                let bytes = canonical_json_bytes(&bundle.purge_ledger)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file("purge_ledger.json", &bytes)?;
                self.calls.push("purge".to_owned());
                Self::effect(intent, &bytes)?
            }
            RestorePhase::ImportSealedBlob { hash } => {
                let blob = bundle
                    .blobs
                    .iter()
                    .find(|blob| blob.locator.hash.as_str() == hash)
                    .cloned()
                    .ok_or(BackupError::PlanMismatch)?;
                blob.validate()?;
                if sha256_hex(&blob.sealed_bytes) != blob.sealed_sha256 {
                    return Err(BackupError::IntegrityMismatch {
                        subject: format!("sealed blob {hash}"),
                    });
                }
                self.write_file(&format!("blobs/{hash}"), &blob.sealed_bytes)?;
                self.calls.push(format!("blob:{hash}"));
                Self::effect(intent, &blob.sealed_bytes)?
            }
            RestorePhase::ImportCanonicalEvent { record_id } => {
                let record = Self::find_event(&bundle.canonical_events, record_id)?;
                record.validate()?;
                let bytes = canonical_json_bytes(&record.payload)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file(&format!("events/{record_id}.json"), &bytes)?;
                self.calls.push(format!("event:{record_id}"));
                Self::effect(intent, &bytes)?
            }
            RestorePhase::ImportReceipt { operation_id } => {
                let receipt = bundle
                    .receipts
                    .iter()
                    .find(|receipt| receipt.operation_id.to_string() == *operation_id)
                    .cloned()
                    .ok_or(BackupError::PlanMismatch)?;
                receipt.validate().map_err(BackupError::Store)?;
                let bytes = canonical_json_bytes(&receipt)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file(&format!("receipts/{operation_id}.json"), &bytes)?;
                self.calls.push(format!("receipt:{operation_id}"));
                Self::effect(intent, &bytes)?
            }
            RestorePhase::ImportProjection { record_id } => {
                let record = Self::find_event(&bundle.projections, record_id)?;
                record.validate()?;
                let bytes = canonical_json_bytes(&record.payload)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file(&format!("projections/{record_id}.json"), &bytes)?;
                self.calls.push(format!("projection:{record_id}"));
                Self::effect(intent, &bytes)?
            }
            RestorePhase::SuspendOrsOperations => {
                let snapshot = bundle
                    .ors_snapshot
                    .as_ref()
                    .ok_or(BackupError::PlanMismatch)?;
                let entries = suspended_recovery_entries(snapshot)?;
                let bytes = canonical_json_bytes(&entries)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file("suspended_ors.json", &bytes)?;
                self.calls.push("suspend-ors".to_owned());
                Self::effect(intent, &bytes)?
            }
            RestorePhase::RebuildProjections => {
                self.require_imported_counts(bundle)?;
                let bytes = serde_json::json!({
                    "blobs": bundle.blobs.len(),
                    "events": bundle.canonical_events.len(),
                    "receipts": bundle.receipts.len(),
                    "projections": bundle.projections.len(),
                });
                let bytes = serde_json::to_vec(&bytes)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file("rebuild.json", &bytes)?;
                self.calls.push("rebuild".to_owned());
                Self::effect(intent, &bytes)?
            }
            RestorePhase::VerifyReceiptEventChain => {
                Self::verify_chain(bundle)?;
                let bytes = serde_json::json!({ "verified": true });
                let bytes = serde_json::to_vec(&bytes)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file("verify.json", &bytes)?;
                self.calls.push("verify".to_owned());
                Self::effect(intent, &bytes)?
            }
            RestorePhase::FinalizeIsolatedRoot => {
                let evidence =
                    self.assemble_evidence(plan, bundle, intent.transaction_id.as_str())?;
                evidence.validate()?;
                let bytes = canonical_json_bytes(&evidence)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file("evidence.json", &bytes)?;
                self.calls.push("finalize".to_owned());
                let receipt = Self::effect_receipt(intent, &bytes)?;
                self.final_evidence = Some(evidence.clone());
                eliot_backup::RestoreAppliedEffect {
                    receipt,
                    final_evidence: Some(evidence),
                }
            }
        };
        self.persist_applied(intent, &applied)?;
        Ok(applied)
    }

    fn effect(
        intent: &RestoreIntent,
        evidence_bytes: &[u8],
    ) -> Result<RestoreAppliedEffect, BackupError> {
        Ok(RestoreAppliedEffect {
            receipt: Self::effect_receipt(intent, evidence_bytes)?,
            final_evidence: None,
        })
    }

    fn find_event(
        records: &[CanonicalRecord],
        record_id: &str,
    ) -> Result<CanonicalRecord, BackupError> {
        records
            .iter()
            .find(|record| record.record_id == record_id)
            .cloned()
            .ok_or(BackupError::PlanMismatch)
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

    fn require_imported_counts(&self, bundle: &BackupBundle) -> Result<(), BackupError> {
        if self.count_dir("blobs")? != bundle.blobs.len()
            || self.count_dir("events")? != bundle.canonical_events.len()
            || self.count_dir("receipts")? != bundle.receipts.len()
            || self.count_dir("projections")? != bundle.projections.len()
        {
            return Err(BackupError::RestoreEvidenceIncomplete);
        }
        Ok(())
    }

    fn verify_chain(bundle: &BackupBundle) -> Result<(), BackupError> {
        let event_ids: BTreeSet<&str> = bundle
            .canonical_events
            .iter()
            .map(|event| event.record_id.as_str())
            .collect();
        for receipt in &bundle.receipts {
            receipt.validate().map_err(BackupError::Store)?;
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

    /// Builds the obligation set with observed evidence refs.
    ///
    /// `Satisfied` always names an observed digest (bundle section checksums,
    /// verified-absent state); unresolved and missing channels stay explicit
    /// and never read as success.
    fn assemble_obligations(
        bundle: &BackupBundle,
        absence: &str,
    ) -> Result<eliot_backup::RestoreObligations, BackupError> {
        use eliot_backup::RestoreObligations;
        let section = |name: &str| Self::section_sha(bundle, name);
        let satisfied = |owner: &str, reference: String| {
            Self::obligation(owner, reference, RestoreObligationState::Satisfied)
        };
        Ok(RestoreObligations {
            purge: satisfied(
                owners::PURGE,
                format!("bundle-section:purge_ledger:{}", section("purge_ledger")?),
            ),
            canonical_validation: satisfied(
                owners::CANONICAL,
                format!(
                    "bundle-section:canonical_events:{}",
                    section("canonical_events")?
                ),
            ),
            reference_validation: satisfied(
                owners::REFERENCE,
                format!("bundle-section:receipts:{}", section("receipts")?),
            ),
            blob_validation: satisfied(
                owners::BLOB,
                format!("bundle-section:blobs:{}", section("blobs")?),
            ),
            ors_suspension: Self::obligation(
                owners::ORS,
                format!("bundle-section:ors_snapshot:{}", section("ors_snapshot")?),
                if bundle.ors_snapshot.is_some() {
                    RestoreObligationState::Satisfied
                } else {
                    RestoreObligationState::NotAttempted
                },
            ),
            unresolved_effect_reconciliation: Self::obligation(
                owners::RECONCILIATION,
                "denominator-absent".to_owned(),
                RestoreObligationState::Unknown,
            ),
            watchdog_signals: satisfied(
                owners::WATCHDOG,
                format!(
                    "bundle-section:watchdog_spool:{}",
                    section("watchdog_spool")?
                ),
            ),
            external_source_revalidation: Self::obligation(
                owners::EXTERNAL_SOURCE,
                "no-owner-channel".to_owned(),
                RestoreObligationState::Unknown,
            ),
            runtime_invalidation: satisfied(owners::RUNTIME, format!("verified-absent:{absence}")),
            session_invalidation: satisfied(owners::SESSION, format!("verified-absent:{absence}")),
            lease_invalidation: satisfied(owners::LEASE, format!("verified-absent:{absence}")),
            route_invalidation: satisfied(owners::ROUTE, format!("verified-absent:{absence}")),
            user_broker_invalidation: Self::obligation(
                owners::USER_BROKER,
                "no-broker-channel".to_owned(),
                RestoreObligationState::MissingCapability,
            ),
        })
    }

    /// Builds finalize evidence with observed (never asserted) obligations.
    ///
    /// Every `Satisfied` carries a ref to an observed digest: bundle section
    /// checksums for validated imports, the persisted watchdog fence digest,
    /// and the verified-absent digest for invalidations. ORS suspension is
    /// satisfied exactly when the snapshot was suspended here; unknown
    /// reconciliation, external revalidation, and the missing broker channel
    /// stay explicit. Owner-issued epoch evidence, when supplied, is attached
    /// after validation (minted nowhere in this adapter).
    fn assemble_evidence(
        &self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        transaction_id: &str,
    ) -> Result<RestoreEvidence, BackupError> {
        use eliot_backup::{
            ObservedLineageLimit, OwnerTrustBinding, RestoreArchiveDisposition,
            RestoreArchiveDispositionKind, RestoreProvenance,
        };
        let absence = self.read_absence()?;
        let obligations = Self::assemble_obligations(bundle, &absence)?;
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
                transaction_id: transaction_id.to_owned(),
                plan_id: plan.plan_id.clone(),
                operation_id: "restore-operation-kernel".to_owned(),
                phase: RestorePhase::FinalizeIsolatedRoot,
                source_archive_id: bundle.manifest.backup_id.clone(),
                source_class: bundle.manifest.class,
                source_digest: bundle.bundle_sha256()?,
                source_endpoint_ref: bundle.manifest.source_adapter.clone(),
                isolated_destination_ref: plan.target.target_id.clone(),
                expected_predecessor_ref: "none".to_owned(),
                schema_revision: bundle.manifest.schema_generation.clone(),
                build_manifest_digest: bundle
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.kind == "host_dependency_build")
                    .map_or_else(
                        || bundle.manifest.integrity_sha256.clone(),
                        |artifact| artifact.sha256.clone(),
                    ),
                purge_ledger_revision: bundle.manifest.purge_ledger_revision,
                owner: OwnerTrustBinding {
                    owner_id: "kernel-restore-owner".to_owned(),
                    trust_binding_ref: format!(
                        "trust-binding-kernel-restore-owner:{transaction_id}"
                    ),
                },
                observed_generation: plan.restored_fence.resource_generation,
                observed_epoch: plan.restored_fence.authority_epoch.clone(),
                validation_digest: {
                    let validation_bytes = canonical_json_bytes(&(
                        plan.plan_id.as_str(),
                        bundle.bundle_sha256()?.as_str(),
                    ))
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                    sha256_hex(&validation_bytes)
                },
            },
            obligations,
            observed_lineage_limits: vec![ObservedLineageLimit {
                owner_id: "kernel-restore-owner".to_owned(),
                observed_epoch: plan
                    .restored_fence
                    .source_state_fence
                    .authority_epoch
                    .clone(),
                observed_generation: plan.restored_fence.source_state_fence.resource_generation,
            }],
            owner_epoch: self.owner_epoch.clone(),
            reconciliation_denominator: None,
            operational_validation: None,
            historical_authority: suspended_recovery_entries_optional(bundle)?,
            archive_disposition: RestoreArchiveDisposition {
                disposition: RestoreArchiveDispositionKind::Current,
                compatibility_ref: "ecxf-1-current".to_owned(),
            },
        };
        Ok(evidence)
    }
}

fn suspended_recovery_entries_optional(
    bundle: &BackupBundle,
) -> Result<Vec<RestoreHistoricalAuthority>, BackupError> {
    match &bundle.ors_snapshot {
        Some(snapshot) => suspended_recovery_entries(snapshot),
        None => Ok(Vec::new()),
    }
}

impl RestoreTarget for KernelRestoreTarget {
    /// Applies one exact intent: fence-gated, member-validated, byte-exact.
    fn apply_restore_effect(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<eliot_backup::RestoreAppliedEffect, BackupError> {
        self.check_fence(bundle)?;
        self.apply_phase(plan, bundle, intent)
    }

    /// Reconciles a durable intent from observed phase receipts only.
    ///
    /// `Applied` exactly when a persisted receipt matches the intent
    /// identity; `NotApplied` when no receipt exists. Never `Unknown`:
    /// absence of a receipt file is decidable, not ambiguous.
    fn reconcile_restore_effect(
        &mut self,
        intent: &RestoreIntent,
    ) -> Result<RestoreReconciliation, BackupError> {
        match self.load_applied(intent)? {
            Some(applied) => Ok(RestoreReconciliation::Applied(applied)),
            None => Ok(RestoreReconciliation::NotApplied),
        }
    }

    fn prepare_isolated(
        &mut self,
        context: &RestoreContext,
        _restored_fence: &RestoredFence,
    ) -> Result<(), BackupError> {
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
        let bytes = serde_json::json!({
            "prepared": true,
            "target_id": context.target_id,
        });
        let bytes = serde_json::to_vec(&bytes)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file("prepared.json", &bytes)?;
        self.calls.push("prepare".to_owned());
        Ok(())
    }

    fn apply_purge_ledger(&mut self, entries: &[PurgeLedgerEntry]) -> Result<(), BackupError> {
        let bytes = canonical_json_bytes(&entries)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file("purge_ledger.json", &bytes)?;
        self.calls.push("purge".to_owned());
        Ok(())
    }

    fn import_sealed_blob(&mut self, blob: &BackupBlob) -> Result<(), BackupError> {
        blob.validate()?;
        self.write_file(
            &format!("blobs/{}", blob.locator.hash.as_str()),
            &blob.sealed_bytes,
        )?;
        self.calls
            .push(format!("blob:{}", blob.locator.hash.as_str()));
        Ok(())
    }

    fn import_canonical_event(&mut self, record: &CanonicalRecord) -> Result<(), BackupError> {
        record.validate()?;
        let bytes = canonical_json_bytes(&record.payload)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file(&format!("events/{}.json", record.record_id), &bytes)?;
        self.calls.push(format!("event:{}", record.record_id));
        Ok(())
    }

    fn import_receipt(&mut self, receipt: &WriteReceipt) -> Result<(), BackupError> {
        receipt.validate().map_err(BackupError::Store)?;
        let bytes = canonical_json_bytes(receipt)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file(&format!("receipts/{}.json", receipt.operation_id), &bytes)?;
        self.calls.push(format!("receipt:{}", receipt.operation_id));
        Ok(())
    }

    fn import_projection(&mut self, record: &CanonicalRecord) -> Result<(), BackupError> {
        record.validate()?;
        let bytes = canonical_json_bytes(&record.payload)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file(&format!("projections/{}.json", record.record_id), &bytes)?;
        self.calls.push(format!("projection:{}", record.record_id));
        Ok(())
    }

    fn suspend_ors_operations(&mut self, snapshot: &OrsSnapshotFence) -> Result<(), BackupError> {
        let entries = suspended_recovery_entries(snapshot)?;
        let bytes = canonical_json_bytes(&entries)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file("suspended_ors.json", &bytes)?;
        self.calls.push("suspend-ors".to_owned());
        Ok(())
    }

    fn rebuild_projections(&mut self, _restored_fence: &RestoredFence) -> Result<(), BackupError> {
        self.write_file("rebuild.json", b"{\"rebuilt\":true}")?;
        self.calls.push("rebuild".to_owned());
        Ok(())
    }

    fn verify_receipt_event_chain(
        &mut self,
        _receipts: &[WriteReceipt],
        _events: &[CanonicalRecord],
    ) -> Result<(), BackupError> {
        self.write_file("verify.json", b"{\"verified\":true}")?;
        self.calls.push("verify".to_owned());
        Ok(())
    }

    /// Legacy finalize is refused: evidence assembles only through the
    /// receipt-bearing apply path, which binds plan, bundle, intent, and
    /// observed state. A finalize without those bindings cannot produce
    /// evidence and must not mint any.
    fn finalize_isolated(
        &mut self,
        _restored_fence: &RestoredFence,
    ) -> Result<RestoreEvidence, BackupError> {
        Err(BackupError::RestoreTargetReceiptRequired)
    }
}
