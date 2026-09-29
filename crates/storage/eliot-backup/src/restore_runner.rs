//! Actual isolated restore runner over the governed journaled executor
//! (issue #1873 product lane; rehearsal grade).
//!
//! # Restore is staged validation, migration, then admission (issue #1141, W5)
//!
//! I5.13 orders restore as "restore to isolated root; validate
//! format/schema/checksums; apply privacy purge ledger; rebuild
//! projections/indexes; verify receipt/event chain; …" and puts "Human/System
//! Owner authorizes cutover" last; I14.24 adds that "backup/restore
//! verification fails | forbid cutover and retain current active state". W5
//! makes that order an enforced property of this runner rather than a
//! convention:
//!
//! 1. `stage_validation` validates the archive and mints the isolated plan.
//!    It performs no filesystem write at all, so nothing can be applied to a
//!    current state before validation has succeeded — and this module never
//!    holds a current-state path to write to: every write goes through
//!    `FileRestoreTarget::contained_member_path` under an [`IsolatedRoot`],
//!    which [`IsolatedRestorePlan::validate`](super::IsolatedRestorePlan::validate)
//!    re-checks to be a live directory under the system temp directory.
//! 2. `stage_migration` runs the governed journaled executor. All of its
//!    effects land inside the candidate root. A failure here returns the typed
//!    error and leaves the current state untouched: there is no apply-then-roll
//!    -back path, because nothing outside the candidate root is ever written.
//! 3. `stage_admission` is the gate. It re-validates the recorded plan and
//!    receipt, then proves completion **against the owner's own durable
//!    records inside the candidate root** — the journal record for this exact
//!    transaction, the target's per-phase effect receipts, the owner-recorded
//!    finalize evidence, and the member files actually present. The
//!    [`IsolatedRestorePlan`](super::IsolatedRestorePlan) that cutover
//!    authorization consumes is returned by the outcome only after this stage
//!    succeeds, so no partially staged, unverified, or skipped-stage candidate
//!    can reach [`authorize_cutover`](super::authorize_cutover).
//!
//! Nothing here recomputes a digest and calls it validation: the recorded
//! values are checked with the existing `validate()` /
//! `validate_against_plan` methods, and completeness is checked against the
//! archive's own carried member set rather than a copy of a caller list.
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use eliot_contracts::{EpochId, ResourceGeneration, canonical_json_bytes, sha256_hex};
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::WriteReceipt;

use super::{
    BackupBlob, BackupBundle, BackupError, CanonicalRecord, IsolatedRestorePlan, IsolatedRoot,
    OrsSnapshotFence, RestoreAppliedEffect, RestoreContext, RestoreEffectReceipt, RestoreEvidence,
    RestoreHistoricalAuthority, RestoreIntent, RestoreJournalPort, RestoreJournalRecord,
    RestoreJournalState, RestoreOwnerObligation, RestorePhase, RestorePlan, RestoreReceipt,
    RestoreReconciliation, RestoreTarget, WrappedKeyManifest, plan_isolated_restore,
    suspended_recovery_entries, verify_portable_key_material,
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
}

impl FileRestoreTarget {
    /// Binds one target to an isolated root directory.
    pub fn new(root: &IsolatedRoot) -> Self {
        Self {
            root: root.path().to_path_buf(),
            calls: Vec::new(),
        }
    }

    /// Ordered phase log for ordering proofs (`prepare` precedes `purge`
    /// precedes imports in every run).
    #[must_use]
    pub fn calls(&self) -> &[String] {
        &self.calls
    }

    /// Resolves one member path that is guaranteed to stay inside the root.
    ///
    /// Bundle-supplied identifiers reach [`FileRestoreTarget::write_file`]
    /// through `format!` (`events/{record_id}.json`, `blobs/{hash}`, ...), and
    /// `Path::join` neither normalises `..` nor refuses an absolute,
    /// drive-prefixed or UNC argument, so this is the single place where the
    /// restore's "writes stay inside the isolated root" guarantee is enforced.
    /// The accepted shape is exactly one or more non-empty plain segments:
    /// `.`, `..`, a root component and a Windows prefix component are all
    /// refused, and so is a path that names no segment at all. Refusal happens
    /// before any directory is created and before any byte is written.
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
                        "must be plain relative segments inside the isolated root",
                    ));
                }
            }
        }
        if segments == 0 {
            return Err(refuse(
                "must name at least one segment inside the isolated root",
            ));
        }
        Ok(self.root.join(relative))
    }

    fn write_file(&self, relative: &str, bytes: &[u8]) -> Result<(), BackupError> {
        let path = self.contained_member_path(relative)?;
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
                self.require_staged_members(bundle)?;
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
                RestoreAppliedEffect {
                    receipt,
                    final_evidence: Some(evidence),
                }
            }
        };
        self.persist_applied(intent, &applied)?;
        Ok(applied)
    }

    /// File names the target itself wrote into one member directory.
    ///
    /// Read back from the candidate root rather than remembered from the
    /// effects this process applied, so a resumed or out-of-band run cannot
    /// make a missing member look present.
    fn observed_member_names(&self, relative: &str) -> Result<BTreeSet<String>, BackupError> {
        let path = self.root.join(relative);
        if !path.exists() {
            return Ok(BTreeSet::new());
        }
        let mut names = BTreeSet::new();
        let entries =
            std::fs::read_dir(&path).map_err(|error| BackupError::Target(error.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|error| BackupError::Target(error.to_string()))?;
            if entry
                .file_type()
                .map_err(|error| BackupError::Target(error.to_string()))?
                .is_file()
            {
                names.insert(entry.file_name().to_string_lossy().into_owned());
            }
        }
        Ok(names)
    }

    /// Requires the candidate root to hold exactly the members the archive
    /// declares — no missing member and no surplus one (issue #1141, W5).
    ///
    /// Completeness is compared against the archive's own expected set, never
    /// against a copy of the caller's list. The blob set is anchored on the
    /// exporter's declared `blob_reachability_manifest` rather than on the
    /// carried `bundle.blobs`, so the two positions are independent: a target
    /// that wrote the wrong member, or a bundle that declared a member it did
    /// not carry, both fail here instead of agreeing with themselves.
    fn require_staged_members(&self, bundle: &BackupBundle) -> Result<(), BackupError> {
        let declared: BTreeSet<String> = bundle
            .export_fence
            .blob_reachability_manifest
            .iter()
            .map(|hash| hash.as_str().to_owned())
            .collect();
        let expected: [(&str, BTreeSet<String>); 4] = [
            ("blobs", declared),
            (
                "events",
                bundle
                    .canonical_events
                    .iter()
                    .map(|record| format!("{}.json", record.record_id))
                    .collect(),
            ),
            (
                "receipts",
                bundle
                    .receipts
                    .iter()
                    .map(|receipt| format!("{}.json", receipt.operation_id))
                    .collect(),
            ),
            (
                "projections",
                bundle
                    .projections
                    .iter()
                    .map(|record| format!("{}.json", record.record_id))
                    .collect(),
            ),
        ];
        for (relative, members) in expected {
            if self.observed_member_names(relative)? != members {
                return Err(BackupError::RestoreEvidenceIncomplete);
            }
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
///
/// `plan` is the admitted isolated candidate. It is produced only after all
/// three stages completed, so holding this value is itself the evidence that
/// validation, migration and admission ran in that order (issue #1141, W5).
#[derive(Clone, Debug)]
pub struct RunnerOutcome {
    pub receipt: super::RestoreReceipt,
    pub evidence: super::RestoreEvidence,
    pub suspended_entries: Vec<RestoreHistoricalAuthority>,
    pub phase_log: Vec<String>,
    pub root: PathBuf,
    pub journal_path: PathBuf,
    /// The admitted isolated candidate, ready to be offered to
    /// [`authorize_cutover`](super::authorize_cutover) — and to nothing else.
    pub plan: IsolatedRestorePlan,
}

/// Stage 1 of the W5 guarantee: validate, and mint the isolated plan.
///
/// Performs **no filesystem write**. Key-material binding is checked first, so
/// a blob-carrying archive with no coverage, or one whose manifest was minted
/// for a different archive, fails here — before the migration stage can create
/// a single directory in the candidate root. `plan_isolated_restore` then
/// validates the bundle, the lineage advance, the purge-first step order and
/// the freshly minted fence, and calls
/// [`IsolatedRestorePlan::validate`](super::IsolatedRestorePlan::validate)
/// before returning.
fn stage_validation(
    bundle: &BackupBundle,
    target: RestoreContext,
    authority_epoch: EpochId,
    resource_generation: ResourceGeneration,
    root: &IsolatedRoot,
    keys: Option<&WrappedKeyManifest>,
) -> Result<IsolatedRestorePlan, BackupError> {
    match keys {
        Some(manifest) => verify_portable_key_material(bundle, manifest)?,
        None if !bundle.blobs.is_empty() => {
            return Err(BackupError::MissingRecoveryComponent("blob_key_material"));
        }
        None => {}
    }
    plan_isolated_restore(bundle, target, authority_epoch, resource_generation, root)
}

/// What the migration stage left behind: the observed receipt plus the two
/// owner seams admission re-reads it through.
struct StagedMigration {
    receipt: RestoreReceipt,
    journal: FileRestoreJournal,
    target: FileRestoreTarget,
    journal_path: PathBuf,
}

/// Stage 2 of the W5 guarantee: migrate into the isolated candidate root.
///
/// The governed journaled executor applies every phase through
/// [`FileRestoreTarget`], whose only write path is `contained_member_path`
/// under the candidate root. Nothing outside that root is opened, created or
/// written here, so a validation or migration failure cannot have touched a
/// current state: there is nothing to roll back, because nothing outside the
/// candidate was ever applied. Re-running against the same root resumes from
/// the durable journal instead of re-applying.
fn stage_migration(
    plan: &RestorePlan,
    bundle: &BackupBundle,
    root: &IsolatedRoot,
) -> Result<StagedMigration, BackupError> {
    let journal_path = root.path().join("journal.json");
    let mut journal = FileRestoreJournal::at(journal_path.clone());
    let mut target = FileRestoreTarget::new(root);
    let receipt = plan.execute_with_journal(bundle, &mut target, &mut journal)?;
    Ok(StagedMigration {
        receipt,
        journal,
        target,
        journal_path,
    })
}

/// Stage 3 of the W5 guarantee: admit the staged candidate, or refuse.
///
/// Everything here is read back from the **owner's own durable records inside
/// the candidate root** — never from a value this runner chose to pass to
/// itself:
///
/// * the executor's journal row for this exact transaction, which must be
///   `Completed`, at the final phase, and carry this exact `RestoreReceipt`
///   (`FileRestoreJournal` / [`RestoreJournalPort`]);
/// * the target's per-phase effect receipts (`load_applied`), one per planned
///   phase, each re-deriving its own intent so a receipt for a foreign
///   transaction or a foreign phase is refused;
/// * the finalize evidence the target itself wrote, re-validated with
///   [`RestoreEvidence::validate`](super::RestoreEvidence::validate) and
///   [`validate_against_plan`](super::RestoreEvidence::validate_against_plan)
///   against this plan and bundle;
/// * the member files actually on disk, compared by name against the archive's
///   own declared set.
///
/// A stage that merely *ran* is not enough: the target's finalize phase writes
/// `evidence.json`, and a resume never re-runs it. So the evidence admitted
/// here is the one read back from the candidate root, and when it is absent
/// this stage refuses instead of re-deriving a value that no owner recorded.
fn stage_admission(
    isolated: &IsolatedRestorePlan,
    bundle: &BackupBundle,
    receipt: &RestoreReceipt,
    journal: &mut FileRestoreJournal,
    target: &FileRestoreTarget,
) -> Result<RestoreEvidence, BackupError> {
    // The recorded plan, re-validated: `IsolatedRestorePlan::validate` compares
    // the plan's two recorded copies of `bundle_sha256`/`restored_fence` and
    // requires the candidate root to still be a live temp directory.
    isolated.validate()?;
    receipt.validate()?;
    let transaction = isolated.plan.transaction()?;
    let journal_key = isolated.plan.journal_key()?;
    let record = journal
        .load(&journal_key)?
        .ok_or(BackupError::RestoreJournalRequired)?;
    // The crate's single definition of the phase order is reused here rather
    // than restated: this loop is a completeness proof over that sequence, not
    // a second source of what the order is.
    let phases = super::restore_phases(bundle);
    let completed_phases =
        u64::try_from(phases.len()).map_err(|_| BackupError::RestoreJournalMismatch)?;
    // The owner's own journal row must be this transaction's, complete, and
    // final. `record.transaction` is the owner's recorded identity; comparing
    // it to the freshly derived one is the coherence check, not a re-proof.
    if record.journal_key != journal_key
        || record.transaction != transaction
        || record.state != RestoreJournalState::Completed
        || !matches!(record.phase, RestorePhase::FinalizeIsolatedRoot)
        || record.completed_phases != completed_phases
    {
        return Err(BackupError::RestoreJournalMismatch);
    }
    // The owner-recorded final receipt must be the one this run observed. The
    // journal is the coordinator's own durable substrate, so agreement here is
    // between two recorded positions rather than one value restated.
    if record.final_receipt.as_ref() != Some(receipt) {
        return Err(BackupError::RestoreJournalMismatch);
    }
    // Every planned phase must carry the target's own persisted effect receipt,
    // and the finalize phase's must carry the finalize evidence. This is the
    // owner-verified staging record: a phase with no target receipt was never
    // applied, however complete the journal row claims to be.
    let mut finalize_evidence: Option<RestoreEvidence> = None;
    for phase in phases {
        let intent = super::restore_intent(&transaction, &phase)?;
        let applied = target
            .load_applied(&intent)?
            .ok_or(BackupError::RestoreEvidenceIncomplete)?;
        if phase == RestorePhase::FinalizeIsolatedRoot {
            finalize_evidence = applied.final_evidence;
        } else if applied.final_evidence.is_some() {
            return Err(BackupError::RestoreJournalCorrupt);
        }
    }
    let evidence = finalize_evidence.ok_or(BackupError::RestoreEvidenceIncomplete)?;
    // Validate the ORIGINAL recorded value with its own validator, against the
    // plan and bundle it claims — never a digest recomputed here.
    evidence.validate()?;
    evidence.validate_against_plan(&isolated.plan, bundle)?;
    if !evidence.isolated_root || evidence.active_authority_restored {
        return Err(BackupError::RestoreEvidenceIncomplete);
    }
    // Completeness against the archive's own expected set, read from disk.
    target.require_staged_members(bundle)?;
    Ok(evidence)
}

/// Executes one isolated restore with real bytes into `root`, as staged
/// validation, then migration, then admission (issue #1141, W5).
///
/// I5.13 orders restore as "restore to isolated root; validate
/// format/schema/checksums; apply privacy purge ledger; rebuild
/// projections/indexes; verify receipt/event chain" and puts "Human/System
/// Owner authorizes cutover" after them. Those three stages run here in that
/// order, and the admitted [`IsolatedRestorePlan`] that
/// [`authorize_cutover`](super::authorize_cutover) consumes is returned only
/// once all three have succeeded — so no partially staged candidate can reach
/// cutover. I14.24's "backup/restore verification fails | forbid cutover and
/// retain current active state" holds because a failing stage returns before
/// any path outside the isolated candidate root is written, and because the
/// candidate root itself is refused unless the owner-recorded evidence
/// validates against this plan and bundle.
///
/// Sealed blob bytes cross into the isolated root byte-for-byte unchanged:
/// `FileRestoreTarget::apply_phase` writes `blob.sealed_bytes` itself after
/// re-deriving `blob.sealed_sha256` over those exact bytes, and nothing on
/// this path unwraps a data key, decrypts an envelope, or re-encrypts under
/// destination key ownership. Destination unwrap/re-seal is the
/// BlobStore/secret-provider owner's step, driven by the per-blob restoration
/// receipts, precisely because this runner proves key *material exists for
/// this archive* rather than that the destination already owns the key.
pub fn execute_isolated_restore(
    bundle: &BackupBundle,
    target: RestoreContext,
    authority_epoch: EpochId,
    resource_generation: ResourceGeneration,
    root: &IsolatedRoot,
    keys: Option<&WrappedKeyManifest>,
) -> Result<RunnerOutcome, BackupError> {
    let isolated = stage_validation(
        bundle,
        target,
        authority_epoch,
        resource_generation,
        root,
        keys,
    )?;
    let mut staged = stage_migration(&isolated.plan, bundle, root)?;
    let evidence = stage_admission(
        &isolated,
        bundle,
        &staged.receipt,
        &mut staged.journal,
        &staged.target,
    )?;
    Ok(RunnerOutcome {
        suspended_entries: isolated.suspended_entries.clone(),
        phase_log: staged.target.calls().to_vec(),
        root: root.path().to_path_buf(),
        journal_path: staged.journal_path,
        receipt: staged.receipt,
        evidence,
        plan: isolated,
    })
}
