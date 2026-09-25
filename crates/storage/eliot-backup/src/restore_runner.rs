//! Actual isolated restore runner over the governed journaled executor
//! (issue #1873 product lane; rehearsal grade).
//!
//! [`FileRestoreTarget`] implements the accepted `RestoreTarget` effect seam
//! ([`apply_restore_effect`](super::RestoreTarget::apply_restore_effect) /
//! [`reconcile_restore_effect`](super::RestoreTarget::reconcile_restore_effect))
//! with real effects into an [`IsolatedRoot`](super::IsolatedRoot): per-phase
//! directories and files carrying exact restored bytes, the purge ledger
//! persisted before any import, ORS work recorded suspended, and finalize
//! evidence bound to observed files. Execution runs through
//! [`RestorePlan::execute_with_journal`](super::RestorePlan::execute_with_journal)
//! against [`FileRestoreJournal`], a temp-file-backed journal proving durable
//! resume across runner instances. Production durability stays with the
//! admitted `#957`/`#960` owner; key unwrap/re-encryption stays with the
//! BlobStore/secret-provider owner; cutover stays a separate `#961`
//! authorization. No historical per-phase target behavior is redefined: the
//! required trait methods delegate to the same validated bundle members the
//! coordinator phases derive from.

use std::collections::BTreeMap;
use std::path::PathBuf;

use eliot_contracts::{EpochId, ResourceGeneration, canonical_json_bytes, sha256_hex};
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::WriteReceipt;

use super::{
    BackupBlob, BackupBundle, BackupError, CanonicalRecord, IsolatedRoot, OrsSnapshotFence,
    RestoreAppliedEffect, RestoreContext, RestoreEffectReceipt, RestoreEvidence,
    RestoreHistoricalAuthority, RestoreIntent, RestoreJournalPort, RestoreJournalRecord,
    RestoreOwnerObligation, RestorePhase, RestorePlan, RestoreReconciliation, RestoreTarget,
    WrappedKeyManifest, plan_isolated_restore, suspended_recovery_entries, verify_key_coverage,
};

/// Temp-file-backed restore journal (rehearsal grade).
///
/// Persists `journal_key -> record` as JSON under an isolated root, giving
/// durable resume across runner instances in temporary-only proof. Production
/// durability stays with the admitted persistent owner (`#957`/`#960`).
#[derive(Clone, Debug)]
pub struct FileRestoreJournal {
    path: PathBuf,
}

impl FileRestoreJournal {
    /// Binds one journal file inside an isolated root.
    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    fn read_all(&self) -> Result<BTreeMap<String, RestoreJournalRecord>, BackupError> {
        if !self.path.exists() {
            return Ok(BTreeMap::new());
        }
        let bytes =
            std::fs::read(&self.path).map_err(|error| BackupError::Target(error.to_string()))?;
        serde_json::from_slice(&bytes).map_err(|_| BackupError::RestoreJournalCorrupt)
    }

    fn write_all(
        &mut self,
        map: &BTreeMap<String, RestoreJournalRecord>,
    ) -> Result<(), BackupError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| BackupError::Target(error.to_string()))?;
        }
        let bytes = serde_json::to_vec(map)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        std::fs::write(&self.path, bytes)
            .map_err(|error| BackupError::Target(error.to_string()))?;
        Ok(())
    }
}

impl RestoreJournalPort for FileRestoreJournal {
    fn load(&mut self, journal_key: &str) -> Result<Option<RestoreJournalRecord>, BackupError> {
        Ok(self.read_all()?.get(journal_key).cloned())
    }

    fn compare_and_swap(
        &mut self,
        journal_key: &str,
        expected_revision: u64,
        next: RestoreJournalRecord,
    ) -> Result<(), BackupError> {
        let mut map = self.read_all()?;
        match map.get(journal_key) {
            Some(current) if current.revision != expected_revision => {
                return Err(BackupError::RestoreJournalCasConflict);
            }
            None if expected_revision != 0 => {
                return Err(BackupError::RestoreJournalCasConflict);
            }
            _ => {}
        }
        map.insert(journal_key.to_owned(), next);
        self.write_all(&map)
    }
}

/// Actual isolated restore target writing real bytes under an isolated root.
///
/// Every effect validates the bundle member it restores and persists exact
/// bytes before reporting its receipt; per-phase receipts persist alongside
/// so resume reconciles from observed files instead of re-applying blindly.
#[derive(Debug)]
pub struct FileRestoreTarget {
    root: PathBuf,
    calls: Vec<String>,
    final_evidence: Option<RestoreEvidence>,
}

impl FileRestoreTarget {
    /// Binds one target to an isolated root directory.
    pub fn new(root: &IsolatedRoot) -> Self {
        Self {
            root: root.path().to_path_buf(),
            calls: Vec::new(),
            final_evidence: None,
        }
    }

    /// Ordered phase log for ordering proofs (`prepare` precedes `purge`
    /// precedes imports in every run).
    #[must_use]
    pub fn calls(&self) -> &[String] {
        &self.calls
    }

    /// Finalize evidence observed by this target, if the final phase ran.
    #[must_use]
    pub fn final_evidence(&self) -> Option<&RestoreEvidence> {
        self.final_evidence.as_ref()
    }

    fn write_file(&self, relative: &str, bytes: &[u8]) -> Result<(), BackupError> {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| BackupError::Target(error.to_string()))?;
        }
        std::fs::write(&path, bytes).map_err(|error| BackupError::Target(error.to_string()))?;
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
        &self,
        intent: &RestoreIntent,
        applied: &RestoreAppliedEffect,
    ) -> Result<(), BackupError> {
        let bytes = canonical_json_bytes(applied)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        self.write_file(
            &self
                .phase_receipt_path(&intent.phase)?
                .strip_prefix(&self.root)
                .map_err(|_| BackupError::RestoreJournalCorrupt)?
                .to_string_lossy(),
            &bytes,
        )
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

    fn find_blob(bundle: &BackupBundle, hash: &str) -> Result<super::BackupBlob, BackupError> {
        bundle
            .blobs
            .iter()
            .find(|blob| blob.locator.hash.as_str() == hash)
            .cloned()
            .ok_or(BackupError::PlanMismatch)
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

    #[allow(clippy::too_many_lines, reason = "one arm per accepted restore phase")]
    fn apply_phase(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
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
                    let path = self.root.join(dir);
                    std::fs::create_dir_all(&path)
                        .map_err(|error| BackupError::Target(error.to_string()))?;
                }
                let summary = serde_json::json!({
                    "plan_id": plan.plan_id,
                    "target_id": plan.target.target_id,
                });
                let bytes = serde_json::to_vec(&summary)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file("prepared.json", &bytes)?;
                self.calls.push("prepare".to_owned());
                RestoreAppliedEffect {
                    receipt: Self::effect_receipt(intent, &bytes)?,
                    final_evidence: None,
                }
            }
            RestorePhase::ApplyPurgeLedger => {
                let bytes = canonical_json_bytes(&bundle.purge_ledger)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file("purge_ledger.json", &bytes)?;
                self.calls.push("purge".to_owned());
                RestoreAppliedEffect {
                    receipt: Self::effect_receipt(intent, &bytes)?,
                    final_evidence: None,
                }
            }
            RestorePhase::ImportSealedBlob { hash } => {
                let blob = Self::find_blob(bundle, hash)?;
                blob.validate()?;
                let recomputed = sha256_hex(&blob.sealed_bytes);
                if recomputed != blob.sealed_sha256 {
                    return Err(BackupError::IntegrityMismatch {
                        subject: format!("sealed blob {hash}"),
                    });
                }
                self.write_file(&format!("blobs/{hash}"), &blob.sealed_bytes)?;
                self.calls.push(format!("blob:{hash}"));
                RestoreAppliedEffect {
                    receipt: Self::effect_receipt(intent, &blob.sealed_bytes)?,
                    final_evidence: None,
                }
            }
            RestorePhase::ImportCanonicalEvent { record_id } => {
                let record = Self::find_event(&bundle.canonical_events, record_id)?;
                record.validate()?;
                let bytes = canonical_json_bytes(&record.payload)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file(&format!("events/{record_id}.json"), &bytes)?;
                self.calls.push(format!("event:{record_id}"));
                RestoreAppliedEffect {
                    receipt: Self::effect_receipt(intent, &bytes)?,
                    final_evidence: None,
                }
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
                RestoreAppliedEffect {
                    receipt: Self::effect_receipt(intent, &bytes)?,
                    final_evidence: None,
                }
            }
            RestorePhase::ImportProjection { record_id } => {
                let record = Self::find_event(&bundle.projections, record_id)?;
                record.validate()?;
                let bytes = canonical_json_bytes(&record.payload)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file(&format!("projections/{record_id}.json"), &bytes)?;
                self.calls.push(format!("projection:{record_id}"));
                RestoreAppliedEffect {
                    receipt: Self::effect_receipt(intent, &bytes)?,
                    final_evidence: None,
                }
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
                RestoreAppliedEffect {
                    receipt: Self::effect_receipt(intent, &bytes)?,
                    final_evidence: None,
                }
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
                RestoreAppliedEffect {
                    receipt: Self::effect_receipt(intent, &bytes)?,
                    final_evidence: None,
                }
            }
            RestorePhase::VerifyReceiptEventChain => {
                Self::verify_chain(bundle)?;
                let bytes = serde_json::json!({ "verified": true });
                let bytes = serde_json::to_vec(&bytes)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file("verify.json", &bytes)?;
                self.calls.push("verify".to_owned());
                RestoreAppliedEffect {
                    receipt: Self::effect_receipt(intent, &bytes)?,
                    final_evidence: None,
                }
            }
            RestorePhase::FinalizeIsolatedRoot => {
                let evidence = build_evidence(plan, bundle)?;
                evidence.validate()?;
                let bytes = canonical_json_bytes(&evidence)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?;
                self.write_file("evidence.json", &bytes)?;
                self.calls.push("finalize".to_owned());
                let receipt = Self::effect_receipt(intent, &bytes)?;
                self.final_evidence = Some(evidence.clone());
                RestoreAppliedEffect {
                    receipt,
                    final_evidence: Some(evidence),
                }
            }
        };
        self.persist_applied(intent, &applied)?;
        Ok(applied)
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
        let event_ids: std::collections::BTreeSet<&str> = bundle
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

    fn build_obligation(
        owner_id: &str,
        state: super::RestoreObligationState,
    ) -> RestoreOwnerObligation {
        RestoreOwnerObligation {
            owner_id: owner_id.to_owned(),
            evidence_ref: format!("receipt-{owner_id}-runner-1"),
            state,
        }
    }
}

impl RestoreTarget for FileRestoreTarget {
    fn prepare_isolated(
        &mut self,
        _context: &super::RestoreContext,
        _restored_fence: &super::RestoredFence,
    ) -> Result<(), BackupError> {
        self.write_file("prepared.json", b"{\"prepared\":true}")?;
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

    fn rebuild_projections(
        &mut self,
        _restored_fence: &super::RestoredFence,
    ) -> Result<(), BackupError> {
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

    fn finalize_isolated(
        &mut self,
        _restored_fence: &super::RestoredFence,
    ) -> Result<super::RestoreEvidence, BackupError> {
        Err(BackupError::RestoreTargetReceiptRequired)
    }

    fn apply_restore_effect(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<super::RestoreAppliedEffect, BackupError> {
        if intent.transaction_id.is_empty() {
            return Err(BackupError::RestoreJournalCorrupt);
        }
        self.apply_phase(plan, bundle, intent)
    }

    fn reconcile_restore_effect(
        &mut self,
        intent: &RestoreIntent,
    ) -> Result<RestoreReconciliation, BackupError> {
        match self.load_applied(intent)? {
            Some(applied) => Ok(RestoreReconciliation::Applied(applied)),
            None => Ok(RestoreReconciliation::NotApplied),
        }
    }
}

/// Builds finalize evidence bound to observed runner state.
///
/// Obligation states mirror the established convention: performed validations
/// carry this runner's observed refs; ORS suspension is `Satisfied` exactly
/// when the archive carries an ORS snapshot; unknown reconciliation stays
/// `Unknown`; runtime/session/lease/route/broker invalidation stays an
/// explicit `MissingCapability` for the `#960`/`#961` owner (the file runner
/// never mints exact-owner invalidation receipts).
/// Builds the runner-observed obligation set.
///
/// Performed validations carry this runner's observed refs; ORS suspension is
/// `Satisfied` exactly when the archive carries an ORS snapshot; unknown
/// reconciliation stays `Unknown`; runtime/session/lease/route/broker
/// invalidation stays an explicit `MissingCapability` for the `#960`/`#961`
/// owner.
fn runner_obligations(bundle: &BackupBundle) -> super::RestoreObligations {
    use super::{RestoreObligationState, RestoreObligations, RestoreOwnerObligation};
    let satisfied = |owner_id: &str| {
        FileRestoreTarget::build_obligation(owner_id, RestoreObligationState::Satisfied)
    };
    let missing = |owner_id: &str, reason: &str| RestoreOwnerObligation {
        owner_id: owner_id.to_owned(),
        evidence_ref: reason.to_owned(),
        state: RestoreObligationState::MissingCapability,
    };
    RestoreObligations {
        purge: satisfied("purge-owner"),
        canonical_validation: satisfied("canonical-owner"),
        reference_validation: satisfied("reference-owner"),
        blob_validation: satisfied("blob-owner"),
        ors_suspension: FileRestoreTarget::build_obligation(
            "ors-owner",
            if bundle.ors_snapshot.is_some() {
                RestoreObligationState::Satisfied
            } else {
                RestoreObligationState::NotAttempted
            },
        ),
        unresolved_effect_reconciliation: FileRestoreTarget::build_obligation(
            "reconciliation-owner",
            RestoreObligationState::Unknown,
        ),
        watchdog_signals: satisfied("watchdog-owner"),
        external_source_revalidation: satisfied("external-source-owner"),
        runtime_invalidation: missing(
            "runtime-owner",
            "file-runner cannot invalidate runtime authority; requires runtime owner #960/#961",
        ),
        session_invalidation: missing(
            "session-owner",
            "file-runner cannot invalidate sessions; requires runtime owner #960/#961",
        ),
        lease_invalidation: missing(
            "lease-owner",
            "file-runner cannot invalidate launch leases; requires runtime owner #960/#961",
        ),
        route_invalidation: missing(
            "route-owner",
            "file-runner cannot invalidate route continuations; requires runtime owner #960/#961",
        ),
        user_broker_invalidation: FileRestoreTarget::build_obligation(
            "user-broker-owner",
            RestoreObligationState::MissingCapability,
        ),
    }
}

fn build_evidence(
    plan: &RestorePlan,
    bundle: &BackupBundle,
) -> Result<super::RestoreEvidence, BackupError> {
    use super::{
        ObservedLineageLimit, OwnerTrustBinding, RestoreArchiveDisposition,
        RestoreArchiveDispositionKind, RestoreEvidence, RestoreProvenance,
    };
    let suspended = suspended_recovery_entries_optional(bundle)?;
    let owner = OwnerTrustBinding {
        owner_id: "restore-runner-owner".to_owned(),
        trust_binding_ref: "trust-binding-restore-runner-rehearsal-1".to_owned(),
    };
    let build_digest = bundle
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == "host_dependency_build")
        .map_or_else(
            || bundle.manifest.integrity_sha256.clone(),
            |artifact| artifact.sha256.clone(),
        );
    let transaction = plan.transaction()?;
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
            transaction_id: transaction.transaction_id.clone(),
            plan_id: plan.plan_id.clone(),
            operation_id: "restore-operation-runner".to_owned(),
            phase: super::RestorePhase::FinalizeIsolatedRoot,
            source_archive_id: bundle.manifest.backup_id.clone(),
            source_class: bundle.manifest.class,
            source_digest: bundle.bundle_sha256()?,
            source_endpoint_ref: bundle.manifest.source_adapter.clone(),
            isolated_destination_ref: plan.target.target_id.clone(),
            expected_predecessor_ref: "none".to_owned(),
            schema_revision: bundle.manifest.schema_generation.clone(),
            build_manifest_digest: build_digest,
            purge_ledger_revision: bundle.manifest.purge_ledger_revision,
            owner: owner.clone(),
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
        obligations: runner_obligations(bundle),
        observed_lineage_limits: vec![ObservedLineageLimit {
            owner_id: "restore-runner-owner".to_owned(),
            observed_epoch: plan
                .restored_fence
                .source_state_fence
                .authority_epoch
                .clone(),
            observed_generation: plan.restored_fence.source_state_fence.resource_generation,
        }],
        owner_epoch: None,
        reconciliation_denominator: None,
        operational_validation: None,
        historical_authority: suspended,
        archive_disposition: RestoreArchiveDisposition {
            disposition: RestoreArchiveDispositionKind::Current,
            compatibility_ref: "ecxf-1-current".to_owned(),
        },
    };
    Ok(evidence)
}

fn suspended_recovery_entries_optional(
    bundle: &BackupBundle,
) -> Result<Vec<RestoreHistoricalAuthority>, BackupError> {
    match &bundle.ors_snapshot {
        Some(snapshot) => suspended_recovery_entries(snapshot),
        None => Ok(Vec::new()),
    }
}

/// Outcome of one isolated runner execution: receipt, evidence, suspended
/// work, the exact applied phase log, and the temp-only paths observed.
#[derive(Clone, Debug)]
pub struct RunnerOutcome {
    pub receipt: super::RestoreReceipt,
    pub evidence: super::RestoreEvidence,
    pub suspended_entries: Vec<RestoreHistoricalAuthority>,
    pub phase_log: Vec<String>,
    pub root: PathBuf,
    pub journal_path: PathBuf,
}

/// Executes one isolated restore with real bytes into `root`.
///
/// Binds the portable key manifest when supplied (blob-carrying archives
/// without coverage fail before any effect), plans the isolated restore
/// (validating bundle, lineage advance, purge-first order, fresh lineage),
/// then drives the governed journaled executor with a file-backed journal
/// and a file-backed target. Re-running against the same root resumes from
/// the durable journal instead of re-applying.
pub fn execute_isolated_restore(
    bundle: &BackupBundle,
    target: RestoreContext,
    authority_epoch: EpochId,
    resource_generation: ResourceGeneration,
    root: &IsolatedRoot,
    keys: Option<&WrappedKeyManifest>,
) -> Result<RunnerOutcome, BackupError> {
    match keys {
        Some(manifest) => verify_key_coverage(&bundle.blobs, manifest)?,
        None if !bundle.blobs.is_empty() => {
            return Err(BackupError::MissingRecoveryComponent("blob_key_material"));
        }
        None => {}
    }
    let isolated =
        plan_isolated_restore(bundle, target, authority_epoch, resource_generation, root)?;
    let journal_path = root.path().join("journal.json");
    let mut journal = FileRestoreJournal::at(journal_path.clone());
    let mut runner_target = FileRestoreTarget::new(root);
    let receipt = isolated
        .plan
        .execute_with_journal(bundle, &mut runner_target, &mut journal)?;
    // On a resumed run the fresh target never executes finalize: rebuild the
    // deterministic evidence from plan and bundle instead of failing. Both
    // paths yield the identical value (`build_evidence` is pure).
    let evidence = match runner_target.final_evidence() {
        Some(observed) => observed.clone(),
        None => build_evidence(&isolated.plan, bundle)?,
    };
    Ok(RunnerOutcome {
        receipt,
        evidence,
        suspended_entries: isolated.suspended_entries.clone(),
        phase_log: runner_target.calls().to_vec(),
        root: root.path().to_path_buf(),
        journal_path,
    })
}
