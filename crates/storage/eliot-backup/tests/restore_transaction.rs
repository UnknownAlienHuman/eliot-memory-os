//! Journaled restore transaction proofs (issue #949).
//!
//! Twenty-four executable cases over `RestorePlan::execute_with_journal`
//! through deterministic fake durable-journal/target state that survives
//! coordinator recreation. Fault injection covers both sides of every target
//! and journal boundary: failing target applies, corrupt receipts,
//! reconciliation modes, failing journal CAS, forged journal records, and two
//! coordinators competing on one journal.
//!
//! Finite fixtures live under `tests/data/restore-transaction/` (exact paths
//! frozen in `paths.json` before coding); this file consumes `manifest.json`
//! parameters and asserts `vectors.json` expectations, so fixture drift fails
//! deterministically.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::rc::Rc;

use eliot_backup::{
    BackupArtifact, BackupBlob, BackupBundle, BackupClass, BackupError, BackupInput,
    CanonicalRecord, EventRange, ExportFence, ObservedLineageLimit, OperationalValidationEvidence,
    OrsSnapshotFence, OwnerTrustBinding, ReconciliationDenominator, RestoreAppliedEffect,
    RestoreArchiveDisposition, RestoreArchiveDispositionKind, RestoreContext, RestoreEffectReceipt,
    RestoreEvidence, RestoreEvidenceLevel, RestoreIntent, RestoreJournalPort, RestoreJournalRecord,
    RestoreJournalState, RestoreObligationState, RestoreObligations, RestoreOwnerEpoch,
    RestoreOwnerObligation, RestorePhase, RestorePlan, RestoreProvenance, RestoreReceipt,
    RestoreReconciliation, RestoreTarget, RestoredFence, WatchdogSpoolFence,
    suspended_recovery_entries,
};
use eliot_blob_api::{
    BlobHash, BlobId, BlobLocator, CompressionDescriptor, CryptoDescriptor, ObjectResidencyKey,
    VersionedContentDigest,
};
use eliot_contracts::{
    EpochId, EpochLineageId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_security_contracts::{PurgeLedgerEntry, PurgeLocation, PurgeState};
use eliot_store_api::{
    CommitId, OperationId, OperationManifestDigest, Resubmission, ScopeId, TransitionClass,
    WriteReceipt, WriteReceiptStatus,
};
use serde_json::{Value, json};

const FIXTURE_PATHS: &str = include_str!("data/restore-transaction/paths.json");
const FIXTURE_MANIFEST: &str = include_str!("data/restore-transaction/manifest.json");
const FIXTURE_VECTORS: &str = include_str!("data/restore-transaction/vectors.json");

fn fixture_manifest() -> Value {
    serde_json::from_str(FIXTURE_MANIFEST).expect("frozen manifest parses")
}

fn fixture_vectors() -> Value {
    serde_json::from_str(FIXTURE_VECTORS).expect("frozen vectors parse")
}

fn manifest_string(manifest: &Value, key: &str) -> String {
    manifest
        .get(key)
        .and_then(Value::as_str)
        .expect("frozen manifest field")
        .to_owned()
}

/// Every bundle builder consumes the frozen fixture inventory first, so the
/// exact-path freeze is load-bearing in all 24 cases.
fn check_fixture_inventory() -> Value {
    let paths: Value = serde_json::from_str(FIXTURE_PATHS).expect("frozen paths parse");
    let fixtures = paths
        .get("fixtures")
        .and_then(Value::as_array)
        .expect("frozen fixture list");
    let names: Vec<&str> = fixtures.iter().filter_map(Value::as_str).collect();
    assert_eq!(
        names,
        vec![
            "crates/storage/eliot-backup/tests/data/restore-transaction/paths.json",
            "crates/storage/eliot-backup/tests/data/restore-transaction/manifest.json",
            "crates/storage/eliot-backup/tests/data/restore-transaction/vectors.json",
        ],
        "fixture set stays finite and path-frozen"
    );
    fixture_manifest()
}

fn epoch(sequence: u64) -> EpochId {
    let manifest = fixture_manifest();
    EpochId::new(
        EpochLineageId::new(manifest_string(&manifest, "lineage_id")).expect("valid lineage"),
        NonZeroU64::new(sequence).expect("nonzero sequence"),
    )
    .expect("valid epoch")
}

fn source_fence() -> StateFence {
    StateFence::new(epoch(1), ResourceGeneration::genesis())
}

fn target_context(target_id: &str) -> RestoreContext {
    RestoreContext {
        target_id: target_id.to_owned(),
        target_authority_epoch: epoch(2),
        target_resource_generation: ResourceGeneration::new(2).expect("generation"),
    }
}

fn locator_for(label: &str, retention_domain: &str) -> BlobLocator {
    let manifest = fixture_manifest();
    let digest_hex = sha256_hex(label.as_bytes());
    let domain = |key: &str| BlobId::new(manifest_string(&manifest, key)).expect("domain id");
    BlobLocator {
        hash: BlobHash::new(digest_hex.clone()).expect("valid blob hash"),
        residency: ObjectResidencyKey {
            scope_domain_id: domain("blob_scope_domain"),
            access_domain_id: domain("blob_access_domain"),
            confidentiality_domain_id: domain("blob_confidentiality_domain"),
            encryption_key_domain_id: domain("blob_key_domain"),
            retention_domain_id: BlobId::new(retention_domain).expect("retention domain"),
            erasure_domain_id: domain("blob_erasure_domain"),
            content_digest: VersionedContentDigest {
                algorithm: BlobId::new("blake3").expect("valid algorithm"),
                version: 1,
                digest: BlobHash::new(digest_hex).expect("valid digest"),
            },
        },
        root_generation: 1,
        path_generation: 1,
    }
}

/// Two members sharing one plaintext under distinct sealed envelopes and
/// distinct retention obligation domains: equal content stays two distinct
/// logical objects (I5.13, I5.27).
fn blob_for(label: &str, retention_domain: &str, shared_plaintext: &[u8]) -> BackupBlob {
    let manifest = fixture_manifest();
    let sealed_bytes = format!("sealed-envelope-949-{label}").into_bytes();
    let lineage = manifest_string(&manifest, "key_lineage");
    BackupBlob {
        locator: locator_for(label, retention_domain),
        sealed_sha256: sha256_hex(&sealed_bytes),
        plaintext_sha256: sha256_hex(shared_plaintext),
        sealed_bytes,
        key_lineage: BlobId::new(&lineage).expect("key lineage"),
        format: BlobId::new("backup-format-949").expect("format"),
        format_version: 1,
        compression: CompressionDescriptor {
            algorithm: BlobId::new("none").expect("compression"),
            version: 1,
        },
        crypto: CryptoDescriptor {
            algorithm: BlobId::new("aead-test-949").expect("crypto"),
            version: 1,
            key_lineage: BlobId::new(&lineage).expect("crypto lineage"),
            key_generation: 1,
        },
    }
}

fn artifact(kind: &str) -> BackupArtifact {
    let bytes = format!("{kind}-manifest-949-bytes").into_bytes();
    let sha256 = sha256_hex(&bytes);
    BackupArtifact {
        kind: kind.to_owned(),
        artifact_id: format!("{kind}-949-1"),
        bytes,
        sha256,
    }
}

fn purge_entry() -> PurgeLedgerEntry {
    let manifest = fixture_manifest();
    let id = manifest_string(&manifest, "purge_id");
    PurgeLedgerEntry {
        purge_id: id.clone(),
        subject_ref: format!("subject-{id}"),
        scope: manifest_string(&manifest, "blob_scope_domain"),
        purged_locations: vec![PurgeLocation::CanonicalPayload],
        tombstone_digest: sha256_hex(format!("tombstone-{id}").as_bytes()),
        state: PurgeState::Purged,
        state_fence: source_fence(),
        revision: 1,
    }
}

fn receipt_for(operation: &str, _event_id: &str) -> WriteReceipt {
    WriteReceipt {
        operation_id: OperationId::new(operation).expect("operation"),
        idempotency_key: format!("idem-949-{operation}"),
        canonical_request_hash: "a".repeat(64),
        transition_class: TransitionClass::CaptureCandidate,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new(format!("commit-{operation}")).expect("commit")),
        state_fence: source_fence(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec![format!("cmd-{operation}")],
        // Empty emission keeps the store-API receipt valid while the chain
        // itself is still verified by the VerifyReceiptEventChain phase.
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: OperationManifestDigest::new("manifest-runner-949")
            .expect("manifest"),
        admission_digest: "e".repeat(64),
        mutation_plan_digest: "f".repeat(64),
        semantic_source_revisions: Vec::new(),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000949".to_owned()),
        envelope: None,
    }
}

fn ors_snapshot() -> OrsSnapshotFence {
    let manifest = fixture_manifest();
    OrsSnapshotFence {
        snapshot_id: manifest_string(&manifest, "ors_snapshot_id"),
        authority_epoch: epoch(1),
        resource_generation: ResourceGeneration::genesis(),
        last_receipt_cursor: 0,
        last_event_cursor: 1,
        last_outbox_cursor: 0,
        pending_operation_ids: vec!["op-949-b".to_owned(), "op-949-a".to_owned()],
        job_checkpoint_ids: Vec::new(),
        generation_cutover_ids: Vec::new(),
        state_fence: source_fence(),
        active_authority_restored: false,
    }
}

fn watchdog_spool() -> WatchdogSpoolFence {
    let manifest = fixture_manifest();
    WatchdogSpoolFence {
        fence_id: manifest_string(&manifest, "watchdog_fence_id"),
        unresolved_signal_digests: vec![sha256_hex(b"signal-949")],
        state_fence: source_fence(),
        bounded: true,
    }
}

fn bundle_input(class: BackupClass, with_ors: bool, scoped: bool) -> BackupInput {
    let manifest = check_fixture_inventory();
    let shared_plaintext = b"plaintext-shared-949";
    let retention_a = manifest_string(&manifest, "blob_retention_domain_a");
    let retention_b = manifest_string(&manifest, "blob_retention_domain_b");
    let labels: Vec<String> = manifest
        .get("blob_labels")
        .and_then(Value::as_array)
        .expect("frozen blob labels")
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    assert_eq!(labels.len(), 2, "frozen member denominator is two blobs");
    let blobs: Vec<BackupBlob> = labels
        .iter()
        .enumerate()
        .map(|(index, label)| {
            let retention = if index == 0 {
                &retention_a
            } else {
                &retention_b
            };
            blob_for(label, retention, shared_plaintext)
        })
        .collect();
    let reachability: Vec<BlobHash> = blobs.iter().map(|blob| blob.locator.hash.clone()).collect();
    let event_id = manifest_string(&manifest, "event_record_id");
    let (events, projections, receipts, counts) = if scoped {
        (Vec::new(), Vec::new(), Vec::new(), (None, None, 0))
    } else {
        let event =
            CanonicalRecord::new("task_state", &event_id, json!({"subject": "subject-949-1"}))
                .expect("event builds");
        let projection = CanonicalRecord::new("task_state", &event_id, json!({"projected": true}))
            .expect("projection builds");
        (
            vec![event],
            vec![projection],
            vec![receipt_for(
                &manifest_string(&manifest, "receipt_operation_id"),
                &event_id,
            )],
            (Some(1), Some(1), 1),
        )
    };
    BackupInput {
        backup_id: manifest_string(&manifest, "backup_id"),
        class,
        source_adapter: manifest_string(&manifest, "source_adapter"),
        schema_generation: manifest_string(&manifest, "schema_generation"),
        export_fence: ExportFence {
            export_id: manifest_string(&manifest, "export_id"),
            installation_id: manifest_string(&manifest, "installation_id"),
            schema_generation: manifest_string(&manifest, "schema_generation"),
            store_generation: manifest_string(&manifest, "store_generation"),
            state_fence: source_fence(),
            scope_id: if scoped {
                Some(ScopeId::new(manifest_string(&manifest, "blob_scope_domain")).expect("scope"))
            } else {
                None
            },
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            event_range: EventRange {
                first_sequence: counts.0,
                last_sequence: counts.1,
                count: counts.2,
            },
            blob_reachability_manifest: if scoped {
                vec![reachability[0].clone()]
            } else {
                reachability
            },
            consistent: true,
        },
        canonical_events: events,
        projections,
        receipts,
        blobs: if scoped {
            vec![blobs[0].clone()]
        } else {
            blobs
        },
        purge_ledger: if scoped {
            Vec::new()
        } else {
            vec![purge_entry()]
        },
        ors_snapshot: if with_ors { Some(ors_snapshot()) } else { None },
        artifacts: if with_ors {
            ["config", "policy", "module", "host_dependency_build"]
                .iter()
                .map(|kind| artifact(kind))
                .collect()
        } else {
            Vec::new()
        },
        watchdog_spool: if with_ors {
            Some(watchdog_spool())
        } else {
            None
        },
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: manifest
            .get("purge_ledger_revision")
            .and_then(Value::as_u64)
            .expect("frozen purge revision"),
    }
}

fn full_bundle() -> BackupBundle {
    BackupBundle::build(bundle_input(BackupClass::FullRecovery, true, false)).expect("full bundle")
}

fn degraded_bundle() -> BackupBundle {
    BackupBundle::build(bundle_input(
        BackupClass::CanonicalOnlyDegraded,
        false,
        false,
    ))
    .expect("degraded bundle")
}

fn scope_bundle() -> BackupBundle {
    BackupBundle::build(bundle_input(BackupClass::ScopeExport, false, true)).expect("scope bundle")
}

fn plan_for(bundle: &BackupBundle, target_id: &str) -> RestorePlan {
    RestorePlan::compile(bundle, target_context(target_id)).expect("plan compiles")
}

fn owner(owner_id: &str) -> OwnerTrustBinding {
    OwnerTrustBinding {
        owner_id: owner_id.to_owned(),
        trust_binding_ref: format!("trust-binding-{owner_id}-session-949"),
    }
}

fn obligation(owner_id: &str, state: RestoreObligationState) -> RestoreOwnerObligation {
    RestoreOwnerObligation {
        owner_id: owner_id.to_owned(),
        evidence_ref: format!("receipt-949-{owner_id}-1"),
        state,
    }
}

fn satisfied_obligations(owner_id: &str) -> RestoreObligations {
    let satisfied = |suffix: &str| {
        obligation(
            &format!("{owner_id}-{suffix}"),
            RestoreObligationState::Satisfied,
        )
    };
    RestoreObligations {
        purge: satisfied("purge"),
        canonical_validation: satisfied("canonical"),
        reference_validation: satisfied("reference"),
        blob_validation: satisfied("blob"),
        ors_suspension: satisfied("ors"),
        unresolved_effect_reconciliation: satisfied("reconciliation"),
        watchdog_signals: satisfied("watchdog"),
        external_source_revalidation: satisfied("external-source"),
        runtime_invalidation: satisfied("runtime"),
        session_invalidation: satisfied("session"),
        lease_invalidation: satisfied("lease"),
        route_invalidation: satisfied("route"),
        user_broker_invalidation: satisfied("user-broker"),
    }
}

fn provenance_for(bundle: &BackupBundle, plan: &RestorePlan) -> RestoreProvenance {
    let manifest = fixture_manifest();
    let owner_id = manifest_string(&manifest, "owner_id");
    RestoreProvenance {
        transaction_id: plan.transaction().expect("transaction").transaction_id,
        plan_id: plan.plan_id.clone(),
        operation_id: "restore-operation-949-1".to_owned(),
        phase: RestorePhase::FinalizeIsolatedRoot,
        source_archive_id: bundle.manifest.backup_id.clone(),
        source_class: bundle.manifest.class,
        source_digest: bundle.bundle_sha256().expect("bundle digest"),
        source_endpoint_ref: bundle.manifest.source_adapter.clone(),
        isolated_destination_ref: plan.target.target_id.clone(),
        expected_predecessor_ref: "predecessor-949-0".to_owned(),
        schema_revision: bundle.manifest.schema_generation.clone(),
        build_manifest_digest: sha256_hex(b"build-manifest-949"),
        purge_ledger_revision: bundle.manifest.purge_ledger_revision,
        owner: owner(&owner_id),
        observed_generation: plan.restored_fence.resource_generation,
        observed_epoch: plan.restored_fence.authority_epoch.clone(),
        validation_digest: sha256_hex(b"bounded-validation-evidence-949"),
    }
}

fn evidence_for(bundle: &BackupBundle, plan: &RestorePlan) -> RestoreEvidence {
    let manifest = fixture_manifest();
    let owner_id = manifest_string(&manifest, "owner_id");
    RestoreEvidence {
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
        provenance: provenance_for(bundle, plan),
        obligations: satisfied_obligations(&owner_id),
        observed_lineage_limits: vec![ObservedLineageLimit {
            owner_id,
            observed_epoch: plan
                .restored_fence
                .source_state_fence
                .authority_epoch
                .clone(),
            observed_generation: plan.restored_fence.source_state_fence.resource_generation,
        }],
        owner_epoch: None,
        reconciliation_denominator: Some(ReconciliationDenominator {
            owner_id: manifest_string(&manifest, "owner_id"),
            denominator_ref: "denominator-949-1".to_owned(),
            expected_total: 0,
            reconciled_refs: Vec::new(),
        }),
        operational_validation: None,
        historical_authority: bundle
            .ors_snapshot
            .as_ref()
            .map(|snapshot| suspended_recovery_entries(snapshot).expect("suspended entries"))
            .unwrap_or_default(),
        archive_disposition: RestoreArchiveDisposition {
            disposition: RestoreArchiveDispositionKind::Current,
            compatibility_ref: "ecxf-1-current-949".to_owned(),
        },
    }
}

fn canonical_digest<T: serde::Serialize>(value: &T) -> String {
    let bytes = canonical_json_bytes(value).expect("canonical bytes");
    sha256_hex(&bytes)
}

fn phase_call_name(phase: &RestorePhase) -> &'static str {
    match phase {
        RestorePhase::Pending => "pending",
        RestorePhase::PrepareIsolatedRoot => "prepare",
        RestorePhase::ApplyPurgeLedger => "purge",
        RestorePhase::ImportSealedBlob { .. } => "blob",
        RestorePhase::ImportCanonicalEvent { .. } => "event",
        RestorePhase::ImportReceipt { .. } => "receipt",
        RestorePhase::ImportProjection { .. } => "projection",
        RestorePhase::SuspendOrsOperations => "ors",
        RestorePhase::RebuildProjections => "rebuild",
        RestorePhase::VerifyReceiptEventChain => "verify",
        RestorePhase::FinalizeIsolatedRoot => "finalize",
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ReconcileMode {
    #[default]
    Unknown,
    NotApplied,
    Applied,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum EvidenceTamper {
    #[default]
    None,
    PurgeUnapplied,
    OrsUnsuspended,
    TargetMismatch,
}

#[derive(Clone, Debug, Default)]
struct TargetFaults {
    fail_apply_on: Option<String>,
    fail_apply_once_on: Option<String>,
    bad_receipt_digest: bool,
    tamper_evidence: EvidenceTamper,
    reconcile: ReconcileMode,
}

struct FakeTarget {
    bundle: BackupBundle,
    plan: RestorePlan,
    faults: TargetFaults,
    calls: Vec<String>,
    legacy_calls: Vec<String>,
    applies: Vec<String>,
    failed_once: bool,
}

impl FakeTarget {
    fn new(bundle: &BackupBundle, plan: &RestorePlan) -> Self {
        Self {
            bundle: bundle.clone(),
            plan: plan.clone(),
            faults: TargetFaults::default(),
            calls: Vec::new(),
            legacy_calls: Vec::new(),
            applies: Vec::new(),
            failed_once: false,
        }
    }

    fn with_faults(mut self, faults: TargetFaults) -> Self {
        self.faults = faults;
        self
    }

    fn apply_count(&self, call: &str) -> usize {
        self.applies
            .iter()
            .filter(|name| name.as_str() == call)
            .count()
    }

    fn applied_effect(&self, intent: &RestoreIntent) -> RestoreAppliedEffect {
        let final_evidence = if matches!(intent.phase, RestorePhase::FinalizeIsolatedRoot) {
            let mut evidence = evidence_for(&self.bundle, &self.plan);
            match self.faults.tamper_evidence {
                EvidenceTamper::None => {}
                EvidenceTamper::PurgeUnapplied => evidence.purge_applied = false,
                EvidenceTamper::OrsUnsuspended => {
                    evidence.ors_suspended = false;
                    evidence.obligations.ors_suspension.state =
                        RestoreObligationState::NotAttempted;
                }
                EvidenceTamper::TargetMismatch => {
                    "target-949-tampered".clone_into(&mut evidence.target_id);
                }
            }
            Some(evidence)
        } else {
            None
        };
        let evidence_sha256 = final_evidence.as_ref().map_or_else(
            || sha256_hex(b"target-observed-effect-949"),
            canonical_digest,
        );
        let mut receipt = RestoreEffectReceipt {
            transaction_id: intent.transaction_id.clone(),
            phase: intent.phase.clone(),
            input_digest: intent.input_digest.clone(),
            external_identity_sha256: canonical_digest(&intent.phase),
            evidence_sha256,
        };
        if self.faults.bad_receipt_digest {
            receipt.input_digest = "0".repeat(64);
        }
        RestoreAppliedEffect {
            receipt,
            final_evidence,
        }
    }
}

impl RestoreTarget for FakeTarget {
    fn apply_restore_effect(
        &mut self,
        _plan: &RestorePlan,
        _bundle: &BackupBundle,
        intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        let call = phase_call_name(&intent.phase).to_owned();
        let key = format!("{:?}", intent.phase);
        if self.faults.fail_apply_on.as_deref() == Some(call.as_str()) {
            return Err(BackupError::Target("injected apply failure".to_owned()));
        }
        if self.faults.fail_apply_once_on.as_deref() == Some(call.as_str()) && !self.failed_once {
            self.failed_once = true;
            return Err(BackupError::Target(
                "injected single apply failure".to_owned(),
            ));
        }
        self.calls.push(call);
        self.applies.push(key);
        Ok(self.applied_effect(intent))
    }

    fn reconcile_restore_effect(
        &mut self,
        intent: &RestoreIntent,
    ) -> Result<RestoreReconciliation, BackupError> {
        match self.faults.reconcile {
            ReconcileMode::Unknown => Ok(RestoreReconciliation::Unknown),
            ReconcileMode::NotApplied => Ok(RestoreReconciliation::NotApplied),
            ReconcileMode::Applied => {
                Ok(RestoreReconciliation::Applied(self.applied_effect(intent)))
            }
        }
    }

    fn prepare_isolated(
        &mut self,
        _context: &RestoreContext,
        _restored_fence: &RestoredFence,
    ) -> Result<(), BackupError> {
        self.legacy_calls.push("prepare".to_owned());
        Ok(())
    }

    fn apply_purge_ledger(&mut self, _entries: &[PurgeLedgerEntry]) -> Result<(), BackupError> {
        self.legacy_calls.push("purge".to_owned());
        Ok(())
    }

    fn import_sealed_blob(&mut self, _blob: &BackupBlob) -> Result<(), BackupError> {
        self.legacy_calls.push("blob".to_owned());
        Ok(())
    }

    fn import_canonical_event(&mut self, _record: &CanonicalRecord) -> Result<(), BackupError> {
        self.legacy_calls.push("event".to_owned());
        Ok(())
    }

    fn import_receipt(&mut self, _receipt: &WriteReceipt) -> Result<(), BackupError> {
        self.legacy_calls.push("receipt".to_owned());
        Ok(())
    }

    fn import_projection(&mut self, _record: &CanonicalRecord) -> Result<(), BackupError> {
        self.legacy_calls.push("projection".to_owned());
        Ok(())
    }

    fn suspend_ors_operations(&mut self, _snapshot: &OrsSnapshotFence) -> Result<(), BackupError> {
        self.legacy_calls.push("ors".to_owned());
        Ok(())
    }

    fn rebuild_projections(&mut self, _restored_fence: &RestoredFence) -> Result<(), BackupError> {
        self.legacy_calls.push("rebuild".to_owned());
        Ok(())
    }

    fn verify_receipt_event_chain(
        &mut self,
        _receipts: &[WriteReceipt],
        _events: &[CanonicalRecord],
    ) -> Result<(), BackupError> {
        self.legacy_calls.push("verify".to_owned());
        Ok(())
    }

    fn finalize_isolated(
        &mut self,
        _restored_fence: &RestoredFence,
    ) -> Result<RestoreEvidence, BackupError> {
        self.legacy_calls.push("finalize".to_owned());
        Err(BackupError::RestoreTargetReceiptRequired)
    }
}

#[derive(Clone, Debug)]
struct CasLog {
    expected_revision: u64,
    next_state: RestoreJournalState,
    phase_key: String,
}

#[derive(Clone, Debug, Default)]
struct JournalFaults {
    all_cas: bool,
    state_once: Option<RestoreJournalState>,
    state_always: Option<RestoreJournalState>,
    expected_revision_once: Option<u64>,
}

#[derive(Clone, Default)]
struct FakeJournal {
    inner: Rc<RefCell<JournalInner>>,
}

#[derive(Default)]
struct JournalInner {
    store: HashMap<String, RestoreJournalRecord>,
    log: Vec<CasLog>,
    seen_keys: Vec<String>,
    faults: JournalFaults,
}

impl FakeJournal {
    fn with_faults(faults: JournalFaults) -> Self {
        let journal = Self::default();
        journal.inner.borrow_mut().faults = faults;
        journal
    }

    fn record(&self) -> Option<RestoreJournalRecord> {
        self.inner.borrow().store.values().next().cloned()
    }

    fn mutate_record(&self, mutate: impl FnOnce(&mut RestoreJournalRecord)) {
        let mut inner = self.inner.borrow_mut();
        let record = inner
            .store
            .values_mut()
            .next()
            .expect("journal holds a record");
        mutate(record);
    }

    fn cas_log(&self) -> Vec<CasLog> {
        self.inner.borrow().log.clone()
    }

    fn seen_keys(&self) -> Vec<String> {
        self.inner.borrow().seen_keys.clone()
    }
}

impl RestoreJournalPort for FakeJournal {
    fn load(&mut self, journal_key: &str) -> Result<Option<RestoreJournalRecord>, BackupError> {
        let mut inner = self.inner.borrow_mut();
        if !inner.seen_keys.contains(&journal_key.to_owned()) {
            inner.seen_keys.push(journal_key.to_owned());
        }
        Ok(inner.store.get(journal_key).cloned())
    }

    fn compare_and_swap(
        &mut self,
        journal_key: &str,
        expected_revision: u64,
        next: RestoreJournalRecord,
    ) -> Result<(), BackupError> {
        let mut inner = self.inner.borrow_mut();
        let current = inner
            .store
            .get(journal_key)
            .map_or(0, |record| record.revision);
        if next.journal_key != journal_key || current != expected_revision {
            return Err(BackupError::RestoreJournalCasConflict);
        }
        if inner.faults.all_cas {
            return Err(BackupError::RestoreJournalCasConflict);
        }
        if inner.faults.state_always == Some(next.state) {
            return Err(BackupError::RestoreJournalCasConflict);
        }
        if inner.faults.state_once == Some(next.state) {
            inner.faults.state_once = None;
            return Err(BackupError::RestoreJournalCasConflict);
        }
        if inner.faults.expected_revision_once == Some(expected_revision) {
            inner.faults.expected_revision_once = None;
            return Err(BackupError::RestoreJournalCasConflict);
        }
        inner.log.push(CasLog {
            expected_revision,
            next_state: next.state,
            phase_key: format!("{:?}", next.phase),
        });
        inner.store.insert(journal_key.to_owned(), next);
        Ok(())
    }
}

fn run(
    bundle: &BackupBundle,
    plan: &RestorePlan,
    target: &mut FakeTarget,
    journal: &mut FakeJournal,
) -> Result<RestoreReceipt, BackupError> {
    plan.execute_with_journal(bundle, target, journal)
}

fn full_harness() -> (BackupBundle, RestorePlan, FakeTarget, FakeJournal) {
    let bundle = full_bundle();
    let manifest = fixture_manifest();
    let plan = plan_for(&bundle, &manifest_string(&manifest, "target_id"));
    let target = FakeTarget::new(&bundle, &plan);
    let journal = FakeJournal::default();
    (bundle, plan, target, journal)
}

fn with_forged_completion(
    mutate: fn(&mut RestoreJournalRecord),
) -> (BackupBundle, RestorePlan, FakeJournal) {
    let (bundle, plan, mut target, journal) = full_harness();
    run(&bundle, &plan, &mut target, &mut journal.clone()).expect("completes");
    journal.mutate_record(mutate);
    (bundle, plan, journal)
}

fn vector_strings(vectors: &Value, key: &str) -> Vec<String> {
    vectors
        .get(key)
        .and_then(Value::as_array)
        .expect("frozen vector")
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

// WORK_UNIT_CASE: 949/1
#[test]
fn valid_actual_phase_sequence_and_existing_safe_ordering() {
    let (bundle, plan, mut target, mut journal) = full_harness();
    let receipt = run(&bundle, &plan, &mut target, &mut journal).expect("restore completes");

    let expected = vector_strings(&fixture_vectors(), "full_class_phase_calls");
    assert_eq!(target.calls, expected, "exact frozen phase sequence runs");
    assert_eq!(target.applies.len(), expected.len());

    let position = |name: &str| {
        target
            .calls
            .iter()
            .position(|call| call == name)
            .expect("phase ran")
    };
    assert!(
        position("purge") < position("blob"),
        "purge stays first boundary"
    );
    assert!(
        position("blob") < position("ors"),
        "members precede ORS suspension"
    );
    assert!(
        position("ors") < position("rebuild"),
        "suspension precedes rebuild"
    );
    assert!(
        position("rebuild") < position("verify"),
        "rebuild precedes chain verify"
    );
    assert!(
        position("verify") < position("finalize"),
        "verify precedes finalize"
    );
    assert_eq!(target.calls.last().expect("last call"), "finalize");

    receipt.validate().expect("receipt validates");
    assert_eq!(
        receipt.evidence_level,
        RestoreEvidenceLevel::ReconciliationRequired
    );
    assert!(!receipt.canonical_only);
    assert!(!receipt.operational_recovery_ready);
    assert!(!receipt.cutover_performed);
    assert_eq!(receipt.plan_id, plan.plan_id);
    assert_eq!(receipt.target_id, plan.target.target_id);
    assert_eq!(
        receipt.bundle_sha256,
        bundle.bundle_sha256().expect("digest")
    );
    assert!(
        target.legacy_calls.is_empty(),
        "coordinator dispatches through the single receipt-bearing seam only"
    );
}

// WORK_UNIT_CASE: 949/2
#[test]
fn class_applicability_and_distinct_proof_levels() {
    let vectors = fixture_vectors();
    let levels = vectors.get("proof_levels").expect("frozen proof levels");
    let level_name = |class: &str| {
        levels
            .get(class)
            .and_then(Value::as_str)
            .expect("frozen level")
            .to_owned()
    };

    let bundle = full_bundle();
    let manifest = fixture_manifest();
    let target_id = manifest_string(&manifest, "target_id");
    let plan = plan_for(&bundle, &target_id);
    let mut target = FakeTarget::new(&bundle, &plan);
    let mut journal = FakeJournal::default();
    let full_receipt = run(&bundle, &plan, &mut target, &mut journal).expect("full restores");
    assert_eq!(level_name("full_recovery"), "reconciliation_required");
    assert_eq!(
        full_receipt.evidence_level,
        RestoreEvidenceLevel::ReconciliationRequired
    );
    assert!(!full_receipt.canonical_only);
    assert!(
        target.calls.contains(&"ors".to_owned()),
        "full applies ORS suspension"
    );

    let degraded = degraded_bundle();
    let degraded_plan = plan_for(&degraded, &target_id);
    let mut degraded_target = FakeTarget::new(&degraded, &degraded_plan);
    let mut degraded_journal = FakeJournal::default();
    let degraded_receipt = run(
        &degraded,
        &degraded_plan,
        &mut degraded_target,
        &mut degraded_journal,
    )
    .expect("degraded restores");
    assert_eq!(
        level_name("canonical_only_degraded"),
        "isolated_import_complete"
    );
    assert_eq!(
        degraded_receipt.evidence_level,
        RestoreEvidenceLevel::IsolatedImportComplete
    );
    assert!(degraded_receipt.canonical_only);
    assert!(
        !degraded_target.calls.contains(&"ors".to_owned()),
        "degraded carries no ORS applicability"
    );

    let scoped = scope_bundle();
    let scoped_plan = plan_for(&scoped, &target_id);
    let mut scoped_target = FakeTarget::new(&scoped, &scoped_plan);
    let mut scoped_journal = FakeJournal::default();
    let scoped_receipt = run(
        &scoped,
        &scoped_plan,
        &mut scoped_target,
        &mut scoped_journal,
    )
    .expect("scope restores");
    assert_eq!(level_name("scope_export"), "isolated_import_complete");
    assert_eq!(
        scoped_receipt.evidence_level,
        RestoreEvidenceLevel::IsolatedImportComplete
    );
    assert!(scoped_receipt.canonical_only);
    assert_ne!(
        full_receipt.evidence_level, degraded_receipt.evidence_level,
        "full and degraded ceilings stay distinct"
    );
    assert!(
        !scoped_receipt.operational_recovery_ready && !scoped_receipt.cutover_performed,
        "scope transfer never reports installation recovery"
    );
}

// WORK_UNIT_CASE: 949/3
#[test]
fn source_active_and_foreign_destinations_rejected_before_effects() {
    let (bundle, plan, mut target, mut journal) = full_harness();

    let mut sourced = plan.clone();
    sourced
        .target
        .target_id
        .clone_from(&bundle.manifest.backup_id);
    let mut sourced_target = FakeTarget::new(&bundle, &sourced);
    let mut sourced_journal = FakeJournal::default();
    assert_eq!(
        run(&bundle, &sourced, &mut sourced_target, &mut sourced_journal),
        Err(BackupError::PlanMismatch),
        "source archive identity is refused as a destination"
    );
    assert!(
        sourced_target.calls.is_empty(),
        "no effect before source rejection"
    );

    let mut activated = plan.clone();
    activated.restored_fence.authority_epoch = epoch(1);
    let mut activated_target = FakeTarget::new(&bundle, &activated);
    let mut activated_journal = FakeJournal::default();
    assert_eq!(
        run(
            &bundle,
            &activated,
            &mut activated_target,
            &mut activated_journal
        ),
        Err(BackupError::StaleRestoreLineage),
        "non-advancing (active) destination lineage is refused"
    );
    assert!(
        activated_target.calls.is_empty(),
        "no effect before lineage rejection"
    );

    run(&bundle, &plan, &mut target, &mut journal).expect("home target completes");
    let manifest = fixture_manifest();
    let foreign_id = manifest_string(&manifest, "foreign_target_id");
    let foreign_plan = plan_for(&bundle, &foreign_id);
    let mut foreign_target = FakeTarget::new(&bundle, &foreign_plan);
    assert_eq!(
        run(&bundle, &foreign_plan, &mut foreign_target, &mut journal),
        Err(BackupError::RestoreJournalMismatch),
        "foreign destination conflicts on the single-target namespace"
    );
    assert!(
        foreign_target.calls.is_empty(),
        "no effect for the foreign destination"
    );
    assert_eq!(
        journal.seen_keys().len(),
        1,
        "both destinations resolve to one explicitly single-target namespace"
    );
}

// WORK_UNIT_CASE: 949/4
#[test]
fn changed_archive_target_purge_and_fence_binding_conflict() {
    let (bundle, plan, mut target, mut journal) = full_harness();
    run(&bundle, &plan, &mut target, &mut journal).expect("restore completes");
    let applies = target.applies.len();

    let mut changed_input = bundle_input(BackupClass::FullRecovery, true, false);
    changed_input.purge_ledger_revision = 4;
    let changed_bundle = BackupBundle::build(changed_input).expect("changed bundle builds");
    let mut changed_target = FakeTarget::new(&changed_bundle, &plan);
    assert_eq!(
        run(&changed_bundle, &plan, &mut changed_target, &mut journal),
        Err(BackupError::PlanMismatch),
        "changed archive (purge revision) conflicts with the journaled transaction"
    );
    assert!(changed_target.calls.is_empty());

    let manifest = fixture_manifest();
    let foreign_plan = plan_for(&bundle, &manifest_string(&manifest, "foreign_target_id"));
    let mut foreign_target = FakeTarget::new(&bundle, &foreign_plan);
    assert_eq!(
        run(&bundle, &foreign_plan, &mut foreign_target, &mut journal),
        Err(BackupError::RestoreJournalMismatch),
        "changed target admission conflicts with the journaled transaction"
    );
    assert!(foreign_target.calls.is_empty());

    let mut defenced = plan.clone();
    defenced.target.target_resource_generation = ResourceGeneration::genesis();
    let mut defenced_target = FakeTarget::new(&bundle, &defenced);
    let mut defenced_journal = FakeJournal::default();
    assert_eq!(
        run(
            &bundle,
            &defenced,
            &mut defenced_target,
            &mut defenced_journal
        ),
        Err(BackupError::PlanMismatch),
        "target that disagrees with its restored fence is refused"
    );
    assert!(defenced_target.calls.is_empty());

    assert_eq!(
        journal.record().expect("journal").completed_phases,
        applies as u64,
        "conflicting attempts leave the completed transaction untouched"
    );
}

// WORK_UNIT_CASE: 949/5
#[test]
fn every_possible_effect_has_a_durable_intent_before_dispatch() {
    let (bundle, plan, mut target, mut journal) = full_harness();
    run(&bundle, &plan, &mut target, &mut journal).expect("restore completes");

    let log = journal.cas_log();
    for applied in &target.applies {
        let intent_index = log
            .iter()
            .position(|entry| {
                entry.next_state == RestoreJournalState::IntentPersisted
                    && entry.phase_key == *applied
            })
            .expect("durable intent precedes every effect");
        let receipt_index = log
            .iter()
            .position(|entry| {
                entry.next_state == RestoreJournalState::ReceiptPersisted
                    && entry.phase_key == *applied
            })
            .expect("durable receipt follows every effect");
        assert!(
            intent_index < receipt_index,
            "intent CAS precedes receipt CAS for {applied}"
        );
    }
    let intent_count = log
        .iter()
        .filter(|entry| entry.next_state == RestoreJournalState::IntentPersisted)
        .count();
    assert_eq!(intent_count, target.applies.len(), "one intent per effect");
}

// WORK_UNIT_CASE: 949/6
#[test]
fn failed_intent_persistence_dispatches_nothing() {
    let bundle = full_bundle();
    let plan = plan_for(&bundle, &manifest_string(&fixture_manifest(), "target_id"));
    let mut failing = FakeTarget::new(&bundle, &plan);
    let mut journal = FakeJournal::with_faults(JournalFaults {
        state_always: Some(RestoreJournalState::IntentPersisted),
        ..JournalFaults::default()
    });
    assert_eq!(
        run(&bundle, &plan, &mut failing, &mut journal),
        Err(BackupError::RestoreJournalCasConflict)
    );
    assert!(
        failing.calls.is_empty(),
        "no dispatch without durable intent"
    );
    assert!(failing.applies.is_empty());
    let record = journal
        .record()
        .expect("journal holds the pre-intent record");
    assert_ne!(record.state, RestoreJournalState::IntentPersisted);
    assert!(record.intent.is_none());
}

// WORK_UNIT_CASE: 949/7
#[test]
fn crash_after_intent_before_dispatch_reconciles_the_exact_operation() {
    let bundle = full_bundle();
    let plan = plan_for(&bundle, &manifest_string(&fixture_manifest(), "target_id"));
    let journal = FakeJournal::default();

    let mut crashing = FakeTarget::new(&bundle, &plan).with_faults(TargetFaults {
        fail_apply_once_on: Some("prepare".to_owned()),
        ..TargetFaults::default()
    });
    assert!(matches!(
        run(&bundle, &plan, &mut crashing, &mut journal.clone()),
        Err(BackupError::Target(_))
    ));
    assert!(
        crashing.applies.is_empty(),
        "failed apply dispatches no effect"
    );
    let record = journal.record().expect("intent survives the crash");
    assert_eq!(record.state, RestoreJournalState::IntentPersisted);
    let intent = record.intent.clone().expect("durable intent");

    let mut resumed = FakeTarget::new(&bundle, &plan).with_faults(TargetFaults {
        reconcile: ReconcileMode::NotApplied,
        ..TargetFaults::default()
    });
    let receipt = run(&bundle, &plan, &mut resumed, &mut journal.clone())
        .expect("resume reconciles and completes");
    receipt.validate().expect("receipt validates");
    let prepare_key = format!("{:?}", intent.phase);
    assert_eq!(
        resumed
            .applies
            .iter()
            .filter(|key| *key == &prepare_key)
            .count(),
        1,
        "the exact persisted operation applies exactly once"
    );
    for applied in &resumed.applies {
        assert_eq!(
            resumed.applies.iter().filter(|key| *key == applied).count(),
            1,
            "no phase repeats after resume"
        );
    }
}

// WORK_UNIT_CASE: 949/8
#[test]
fn lost_target_response_cannot_create_a_replacement_operation() {
    let (bundle, plan, _, _) = full_harness();
    let journal = FakeJournal::with_faults(JournalFaults {
        state_once: Some(RestoreJournalState::ReceiptPersisted),
        ..JournalFaults::default()
    });

    let mut first = FakeTarget::new(&bundle, &plan);
    assert_eq!(
        run(&bundle, &plan, &mut first, &mut journal.clone()),
        Err(BackupError::RestoreJournalCasConflict),
        "lost receipt CAS surfaces instead of succeeding"
    );
    assert_eq!(first.apply_count("prepare"), 1, "the effect happened once");
    let intent = journal
        .record()
        .expect("intent")
        .intent
        .clone()
        .expect("durable intent");

    let mut ambiguous = FakeTarget::new(&bundle, &plan);
    assert_eq!(
        run(&bundle, &plan, &mut ambiguous, &mut journal.clone()),
        Err(BackupError::RestoreRollbackRequired),
        "unknown outcome escalates instead of minting a replacement operation"
    );
    assert!(
        ambiguous.applies.is_empty(),
        "no replacement operation is created"
    );
    let record = journal.record().expect("rollback record");
    assert_eq!(record.state, RestoreJournalState::RollbackRequired);
    assert_eq!(
        record.intent.expect("intent").input_digest,
        intent.input_digest,
        "the same stable operation is preserved, not replaced"
    );
    assert!(record.receipt.is_none());
}

// WORK_UNIT_CASE: 949/9
#[test]
fn successful_effect_plus_failed_receipt_cas_does_not_repeat_the_effect() {
    let (bundle, plan, _, _) = full_harness();
    let journal = FakeJournal::with_faults(JournalFaults {
        state_once: Some(RestoreJournalState::ReceiptPersisted),
        ..JournalFaults::default()
    });

    let mut first = FakeTarget::new(&bundle, &plan);
    assert_eq!(
        run(&bundle, &plan, &mut first, &mut journal.clone()),
        Err(BackupError::RestoreJournalCasConflict)
    );
    assert_eq!(first.apply_count("prepare"), 1);

    let mut resumed = FakeTarget::new(&bundle, &plan).with_faults(TargetFaults {
        reconcile: ReconcileMode::Applied,
        ..TargetFaults::default()
    });
    let receipt = run(&bundle, &plan, &mut resumed, &mut journal.clone())
        .expect("resume adopts the bound receipt and completes");
    receipt.validate().expect("receipt validates");
    assert_eq!(
        resumed.apply_count("prepare"),
        0,
        "adopted effect is not repeated"
    );
    for applied in &resumed.applies {
        assert_eq!(
            resumed.applies.iter().filter(|key| *key == applied).count()
                + first.applies.iter().filter(|key| *key == applied).count(),
            1,
            "every phase applies exactly once across crash and resume"
        );
    }
}

// WORK_UNIT_CASE: 949/10
#[test]
fn exact_accepted_operation_replay_returns_its_prior_bound_receipt() {
    let (bundle, plan, mut target, mut journal) = full_harness();
    let first = run(&bundle, &plan, &mut target, &mut journal).expect("first restore");

    let mut replay_target = FakeTarget::new(&bundle, &plan);
    let replay = run(&bundle, &plan, &mut replay_target, &mut journal).expect("replay");
    assert_eq!(first, replay, "replay returns the prior bound receipt");
    assert!(
        replay_target.calls.is_empty(),
        "replay dispatches no target effects"
    );
    assert!(replay_target.applies.is_empty());
    assert_eq!(
        journal.record().expect("journal").state,
        RestoreJournalState::Completed
    );
}

// WORK_UNIT_CASE: 949/11
#[test]
fn malformed_stale_and_out_of_order_resumed_states_are_rejected() {
    let (bundle, plan, journal) = with_forged_completion(|record| {
        record
            .final_receipt
            .as_mut()
            .expect("final receipt")
            .plan_id = "restore-plan-foreign".to_owned();
    });
    let mut target = FakeTarget::new(&bundle, &plan);
    assert_eq!(
        run(&bundle, &plan, &mut target, &mut journal.clone()),
        Err(BackupError::RestoreJournalMismatch),
        "negative mutation: foreign Completed receipt is refused"
    );
    assert!(target.calls.is_empty());

    let (bundle, plan, journal) = with_forged_completion(|record| {
        let forged = record.final_receipt.as_mut().expect("final receipt");
        forged.target_id = "target-949-foreign".to_owned();
    });
    let mut target = FakeTarget::new(&bundle, &plan);
    assert_eq!(
        run(&bundle, &plan, &mut target, &mut journal.clone()),
        Err(BackupError::RestoreJournalMismatch),
        "negative mutation: target/fence mismatch in Completed evidence is refused"
    );

    let (bundle, plan, journal) = with_forged_completion(|record| {
        record.state = RestoreJournalState::ReceiptPersisted;
        record.intent = None;
    });
    let mut target = FakeTarget::new(&bundle, &plan);
    assert_eq!(
        run(&bundle, &plan, &mut target, &mut journal.clone()),
        Err(BackupError::RestoreJournalCorrupt),
        "negative mutation: receipt-before-intent execution is refused"
    );

    let (bundle, plan, journal) = with_forged_completion(|record| {
        record.state = RestoreJournalState::Ready;
        record.phase = RestorePhase::FinalizeIsolatedRoot;
        record.completed_phases = 0;
        record.intent = None;
        record.receipt = None;
        record.final_receipt = None;
    });
    let mut target = FakeTarget::new(&bundle, &plan);
    assert_eq!(
        run(&bundle, &plan, &mut target, &mut journal.clone()),
        Err(BackupError::RestorePhaseMismatch),
        "out-of-order resumed phase is refused"
    );

    let (bundle, plan, journal) = with_forged_completion(|record| {
        record.intent.as_mut().expect("intent").input_digest = "0".repeat(64);
    });
    let mut target = FakeTarget::new(&bundle, &plan);
    assert_eq!(
        run(&bundle, &plan, &mut target, &mut journal.clone()),
        Err(BackupError::RestoreJournalCorrupt),
        "Completed with a forged intent digest is refused"
    );

    let (bundle, plan, journal) = with_forged_completion(|record| {
        record
            .final_receipt
            .as_mut()
            .expect("final receipt")
            .evidence_level = RestoreEvidenceLevel::Cutover;
    });
    let mut target = FakeTarget::new(&bundle, &plan);
    assert_eq!(
        run(&bundle, &plan, &mut target, &mut journal.clone()),
        Err(BackupError::RestoreJournalMismatch),
        "Completed with an inflated proof level is refused"
    );

    let bundle = full_bundle();
    let plan = plan_for(&bundle, &manifest_string(&fixture_manifest(), "target_id"));
    let mut failing = FakeTarget::new(&bundle, &plan).with_faults(TargetFaults {
        fail_apply_on: Some("prepare".to_owned()),
        ..TargetFaults::default()
    });
    let journal = FakeJournal::default();
    assert!(matches!(
        run(&bundle, &plan, &mut failing, &mut journal.clone()),
        Err(BackupError::Target(_))
    ));
    journal.mutate_record(|record| {
        record.intent = None;
    });
    let mut target = FakeTarget::new(&bundle, &plan);
    assert_eq!(
        run(&bundle, &plan, &mut target, &mut journal.clone()),
        Err(BackupError::RestoreJournalCorrupt),
        "intent-less resumed intent state is refused"
    );
}

// WORK_UNIT_CASE: 949/12
#[test]
fn per_residency_member_denominator_survives_subset_crash_and_resume() {
    let bundle = full_bundle();
    assert_eq!(bundle.blobs.len(), 2, "frozen two-member denominator");
    assert_eq!(
        bundle.blobs[0].plaintext_sha256, bundle.blobs[1].plaintext_sha256,
        "members share content yet stay distinct objects"
    );
    assert_ne!(
        bundle.blobs[0].locator.residency, bundle.blobs[1].locator.residency,
        "residency obligation domains stay distinct"
    );
    let plan = plan_for(&bundle, &manifest_string(&fixture_manifest(), "target_id"));
    let journal = FakeJournal::default();

    let first_hash = format!(
        "{:?}",
        RestorePhase::ImportSealedBlob {
            hash: bundle.blobs[0].locator.hash.to_string(),
        }
    );
    let mut crashing = FakeTarget::new(&bundle, &plan).with_faults(TargetFaults {
        fail_apply_once_on: Some("blob".to_owned()),
        ..TargetFaults::default()
    });
    assert!(
        matches!(
            run(&bundle, &plan, &mut crashing, &mut journal.clone()),
            Err(BackupError::Target(_))
        ),
        "crash inside the blob subset"
    );
    assert_eq!(
        crashing.apply_count("blob"),
        0,
        "failed subset member applies nothing"
    );
    assert_eq!(crashing.apply_count("prepare"), 1);
    assert_eq!(crashing.apply_count("purge"), 1);

    let mut resumed = FakeTarget::new(&bundle, &plan).with_faults(TargetFaults {
        reconcile: ReconcileMode::NotApplied,
        ..TargetFaults::default()
    });
    let receipt =
        run(&bundle, &plan, &mut resumed, &mut journal.clone()).expect("subset resume completes");
    receipt.validate().expect("receipt validates");
    let blob_applies: Vec<&String> = resumed
        .applies
        .iter()
        .chain(crashing.applies.iter())
        .filter(|key| key.starts_with("ImportSealedBlob"))
        .collect();
    assert_eq!(
        blob_applies.len(),
        2,
        "both members imported exactly once in total"
    );
    assert!(
        blob_applies.contains(&&first_hash),
        "stable member identities survive restart"
    );
    let initial_order: Vec<&String> = resumed
        .applies
        .iter()
        .filter(|key| key.starts_with("ImportSealedBlob"))
        .collect();
    assert_eq!(
        initial_order.len(),
        2,
        "no member skipped or replayed with new IDs"
    );
}

// WORK_UNIT_CASE: 949/13
#[test]
fn current_purge_suppression_cannot_be_omitted_or_undone_by_rebuild() {
    let (bundle, plan, mut target, mut journal) = full_harness();
    let receipt = run(&bundle, &plan, &mut target, &mut journal).expect("restore completes");
    receipt.validate().expect("receipt validates");
    let position = |name: &str| {
        target
            .calls
            .iter()
            .position(|call| call == name)
            .expect("phase ran")
    };
    assert!(
        position("purge") < position("rebuild"),
        "purge precedes rebuild"
    );
    assert!(
        position("purge") < position("finalize"),
        "purge precedes finalize"
    );

    let tampered = FakeTarget::new(&bundle, &plan).with_faults(TargetFaults {
        tamper_evidence: EvidenceTamper::PurgeUnapplied,
        ..TargetFaults::default()
    });
    let mut tampered_target = tampered;
    let mut tampered_journal = FakeJournal::default();
    assert_eq!(
        run(&bundle, &plan, &mut tampered_target, &mut tampered_journal),
        Err(BackupError::RestoreEvidenceIncomplete),
        "evidence without purge suppression is refused even after rebuild"
    );
}

// WORK_UNIT_CASE: 949/14
#[test]
fn failed_canonical_or_reference_validation_cannot_advance_proof_level() {
    let bundle = full_bundle();
    let plan = plan_for(&bundle, &manifest_string(&fixture_manifest(), "target_id"));
    let mut evidence = evidence_for(&bundle, &plan);
    evidence.obligations.canonical_validation.state = RestoreObligationState::Unknown;
    evidence.obligations.reference_validation.state = RestoreObligationState::NotAttempted;
    evidence
        .validate()
        .expect("structural evidence still validates");
    assert_eq!(
        evidence.evidence_level(),
        RestoreEvidenceLevel::ReconciliationRequired,
        "level stays at the class ceiling, never operational"
    );
    assert_eq!(
        evidence.operationally_validated_by_owner(),
        Err(BackupError::RestoreEvidenceIncomplete),
        "failed validation obligations block operational advancement"
    );

    let failing = evidence_for(&bundle, &plan);
    assert!(
        failing.operationally_validated_by_owner().is_err(),
        "import proof alone never advances without owner validation evidence"
    );
}

// WORK_UNIT_CASE: 949/15
#[test]
fn ors_or_spool_unknown_or_partial_evidence_is_not_known_zero() {
    let bundle = full_bundle();
    let plan = plan_for(&bundle, &manifest_string(&fixture_manifest(), "target_id"));

    let tampered = FakeTarget::new(&bundle, &plan).with_faults(TargetFaults {
        tamper_evidence: EvidenceTamper::OrsUnsuspended,
        ..TargetFaults::default()
    });
    let mut tampered_target = tampered;
    let mut tampered_journal = FakeJournal::default();
    assert_eq!(
        run(&bundle, &plan, &mut tampered_target, &mut tampered_journal),
        Err(BackupError::RestoreEvidenceIncomplete),
        "unknown ORS suspension is not silent success"
    );

    let mut partial = evidence_for(&bundle, &plan);
    partial.reconciliation_denominator = Some(ReconciliationDenominator {
        owner_id: manifest_string(&fixture_manifest(), "owner_id"),
        denominator_ref: "denominator-949-partial".to_owned(),
        expected_total: 2,
        reconciled_refs: vec!["ref-949-1".to_owned()],
    });
    assert_eq!(
        partial
            .reconciliation_denominator
            .as_ref()
            .expect("denominator")
            .validate(),
        Err(BackupError::RestoreEvidenceIncomplete),
        "partial denominator is not complete owner evidence"
    );
    assert_eq!(
        partial.operationally_validated_by_owner(),
        Err(BackupError::RestoreEvidenceIncomplete)
    );
    assert!(
        !partial
            .reconciliation_denominator
            .as_ref()
            .expect("denominator")
            .is_known_zero()
    );
}

// WORK_UNIT_CASE: 949/16
#[test]
fn applicable_effect_fence_evidence_precedes_the_affected_phase() {
    let vectors = fixture_vectors();
    let sequence = vector_strings(&vectors, "full_class_phase_calls");
    let position = |name: &str| {
        sequence
            .iter()
            .position(|call| call == name)
            .expect("frozen phase")
    };
    assert!(position("ors") < position("rebuild"));
    assert!(position("rebuild") < position("verify"));
    assert!(position("verify") < position("finalize"));

    let (bundle, plan, mut target, mut journal) = full_harness();
    run(&bundle, &plan, &mut target, &mut journal).expect("restore completes");
    assert_eq!(target.calls, sequence, "frozen order executes");

    let evidence = evidence_for(&bundle, &plan);
    assert!(
        evidence.ors_suspended,
        "ORS fence evidence is present before finalize"
    );
    assert_eq!(
        evidence.obligations.ors_suspension.state,
        RestoreObligationState::Satisfied
    );
    for name in ["runtime", "session", "lease", "route", "user-broker"] {
        let found = [
            &evidence.obligations.runtime_invalidation,
            &evidence.obligations.session_invalidation,
            &evidence.obligations.lease_invalidation,
            &evidence.obligations.route_invalidation,
            &evidence.obligations.user_broker_invalidation,
        ]
        .iter()
        .any(|obligation| obligation.owner_id.contains(name));
        assert!(found, "effect-fence owner {name} is explicitly represented");
    }
}

// WORK_UNIT_CASE: 949/17
#[test]
fn zero_unresolved_count_alone_cannot_fabricate_readiness() {
    let bundle = full_bundle();
    let plan = plan_for(&bundle, &manifest_string(&fixture_manifest(), "target_id"));

    let mut missing = evidence_for(&bundle, &plan);
    missing.reconciliation_denominator = None;
    assert_eq!(
        missing.operationally_validated_by_owner(),
        Err(BackupError::RestoreEvidenceIncomplete),
        "absent denominator is unknown, never known-zero"
    );

    let mut nonzero = evidence_for(&bundle, &plan);
    nonzero.reconciliation_denominator = Some(ReconciliationDenominator {
        owner_id: manifest_string(&fixture_manifest(), "owner_id"),
        denominator_ref: "denominator-949-open".to_owned(),
        expected_total: 1,
        reconciled_refs: vec!["ref-949-1".to_owned()],
    });
    assert_eq!(
        nonzero.operationally_validated_by_owner(),
        Err(BackupError::RestoreEvidenceIncomplete),
        "a non-zero denominator never unblocks effects"
    );

    let mut satisfied = evidence_for(&bundle, &plan);
    satisfied.operational_validation = Some(OperationalValidationEvidence {
        owner: owner(&manifest_string(&fixture_manifest(), "owner_id")),
        target_ref: plan.target.target_id.clone(),
        validation_digest: sha256_hex(b"bounded-owner-validation-949"),
        observed_at_state_fence: source_fence(),
    });
    satisfied
        .operationally_validated_by_owner()
        .expect("complete owner evidence validates");
    let denominator = satisfied
        .reconciliation_denominator
        .as_ref()
        .expect("denominator");
    assert!(denominator.is_known_zero());
    assert_eq!(denominator.expected_total, 0);
    assert!(denominator.reconciled_refs.is_empty());
}

// WORK_UNIT_CASE: 949/18
#[test]
fn new_epoch_and_user_broker_evidence_is_owner_issued_exact_and_replay_bound() {
    let manifest = fixture_manifest();
    let owner_id = manifest_string(&manifest, "owner_id");
    let valid = RestoreOwnerEpoch {
        owner: owner(&owner_id),
        new_epoch: epoch(2),
        new_generation: ResourceGeneration::new(2).expect("generation"),
        supersedes: vec![ObservedLineageLimit {
            owner_id: owner_id.clone(),
            observed_epoch: epoch(1),
            observed_generation: ResourceGeneration::genesis(),
        }],
    };
    valid.validate().expect("advancing owner epoch validates");

    let unbound = RestoreOwnerEpoch {
        supersedes: Vec::new(),
        ..valid.clone()
    };
    assert_eq!(
        unbound.validate(),
        Err(BackupError::RestoreEvidenceIncomplete),
        "owner epoch without superseded limits is not evidence"
    );

    let repeated = RestoreOwnerEpoch {
        new_epoch: epoch(1),
        new_generation: ResourceGeneration::genesis(),
        ..valid.clone()
    };
    assert_eq!(
        repeated.validate(),
        Err(BackupError::StaleRestoreLineage),
        "a repeated local increment is not new authority"
    );

    let cross_lineage = RestoreOwnerEpoch {
        new_epoch: EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440099").expect("lineage"),
            NonZeroU64::new(2).expect("nonzero"),
        )
        .expect("epoch"),
        ..valid.clone()
    };
    assert_eq!(
        cross_lineage.validate(),
        Err(BackupError::StaleRestoreLineage),
        "non-genesis cross-lineage sequence never authorizes"
    );

    let bundle = full_bundle();
    assert_eq!(
        RestorePlan::compile(
            &bundle,
            RestoreContext {
                target_id: manifest_string(&manifest, "target_id"),
                target_authority_epoch: epoch(1),
                target_resource_generation: ResourceGeneration::new(2).expect("generation"),
            },
        ),
        Err(BackupError::StaleRestoreLineage),
        "caller-proposed epoch cannot mint authority at compile time"
    );
}

// WORK_UNIT_CASE: 949/19
#[test]
fn generation_lease_route_session_and_ui_invalidation_receipts_are_individually_required() {
    let bundle = full_bundle();
    let plan = plan_for(&bundle, &manifest_string(&fixture_manifest(), "target_id"));
    let base = evidence_for(&bundle, &plan);

    let flip = |mutate: fn(&mut RestoreObligations)| {
        let mut evidence = base.clone();
        mutate(&mut evidence.obligations);
        assert_eq!(
            evidence.operationally_validated_by_owner(),
            Err(BackupError::RestoreEvidenceIncomplete),
        );
    };
    flip(|obligations| {
        obligations.runtime_invalidation.state = RestoreObligationState::MissingCapability;
    });
    flip(|obligations| {
        obligations.session_invalidation.state = RestoreObligationState::MissingCapability;
    });
    flip(|obligations| {
        obligations.lease_invalidation.state = RestoreObligationState::MissingCapability;
    });
    flip(|obligations| {
        obligations.route_invalidation.state = RestoreObligationState::MissingCapability;
    });
    flip(|obligations| {
        obligations.user_broker_invalidation.state = RestoreObligationState::MissingCapability;
    });

    let mut satisfied = base;
    satisfied.operational_validation = Some(OperationalValidationEvidence {
        owner: owner(&manifest_string(&fixture_manifest(), "owner_id")),
        target_ref: plan.target.target_id.clone(),
        validation_digest: sha256_hex(b"bounded-owner-validation-949"),
        observed_at_state_fence: source_fence(),
    });
    satisfied
        .operationally_validated_by_owner()
        .expect("all invalidation receipts present validates");
}

// WORK_UNIT_CASE: 949/20
#[test]
fn external_source_revalidation_is_current_explicit_and_replay_bound() {
    let bundle = full_bundle();
    let plan = plan_for(&bundle, &manifest_string(&fixture_manifest(), "target_id"));

    let mut missing = evidence_for(&bundle, &plan);
    missing.obligations.external_source_revalidation.state =
        RestoreObligationState::MissingCapability;
    assert_eq!(
        missing.operationally_validated_by_owner(),
        Err(BackupError::RestoreEvidenceIncomplete),
        "absent external-source revalidation never reads as current"
    );

    let mut stale = evidence_for(&bundle, &plan);
    stale.provenance.purge_ledger_revision += 1;
    assert_eq!(
        stale.validate_against_plan(&plan, &bundle),
        Err(BackupError::FinalizeEvidenceMismatch),
        "evidence bound to another revision is not current for this plan"
    );

    let mut replayed = evidence_for(&bundle, &plan);
    replayed.provenance.transaction_id = "restore-transaction-foreign".to_owned();
    assert_eq!(
        replayed.validate_against_plan(&plan, &bundle),
        Err(BackupError::FinalizeEvidenceMismatch),
        "evidence replayed from another transaction is refused"
    );

    let foreign = FakeTarget::new(&bundle, &plan).with_faults(TargetFaults {
        tamper_evidence: EvidenceTamper::TargetMismatch,
        ..TargetFaults::default()
    });
    let mut foreign_target = foreign;
    let mut foreign_journal = FakeJournal::default();
    assert_eq!(
        run(&bundle, &plan, &mut foreign_target, &mut foreign_journal),
        Err(BackupError::FinalizeEvidenceMismatch),
        "evidence naming another destination is not explicit for this plan"
    );
}

// WORK_UNIT_CASE: 949/21
#[test]
fn cancellation_before_and_after_possible_effect_keeps_reconciliation_without_rollback() {
    let bundle = full_bundle();
    let plan = plan_for(&bundle, &manifest_string(&fixture_manifest(), "target_id"));

    let mut cancelled_early = FakeTarget::new(&bundle, &plan);
    let mut early_journal = FakeJournal::with_faults(JournalFaults {
        all_cas: true,
        ..JournalFaults::default()
    });
    assert_eq!(
        run(&bundle, &plan, &mut cancelled_early, &mut early_journal),
        Err(BackupError::RestoreJournalCasConflict),
        "cancellation before any possible effect fails the CAS"
    );
    assert!(cancelled_early.applies.is_empty());
    assert!(
        early_journal.record().is_none(),
        "no intent exists, so nothing requires reconciliation"
    );
    let mut retried = FakeTarget::new(&bundle, &plan);
    run(&bundle, &plan, &mut retried, &mut early_journal.clone())
        .expect("retry after early cancellation completes cleanly");
    assert_eq!(
        early_journal.record().expect("journal").state,
        RestoreJournalState::Completed
    );

    let journal = FakeJournal::default();
    let mut crashing = FakeTarget::new(&bundle, &plan).with_faults(TargetFaults {
        fail_apply_once_on: Some("prepare".to_owned()),
        ..TargetFaults::default()
    });
    assert!(
        matches!(
            run(&bundle, &plan, &mut crashing, &mut journal.clone()),
            Err(BackupError::Target(_))
        ),
        "cancellation after a persisted intent leaves the effect unknown"
    );
    let mut unknown = FakeTarget::new(&bundle, &plan);
    assert_eq!(
        run(&bundle, &plan, &mut unknown, &mut journal.clone()),
        Err(BackupError::RestoreRollbackRequired),
        "unknown outcome escalates without automatic rollback"
    );
    assert!(unknown.applies.is_empty(), "escalation applies nothing");
    let record = journal.record().expect("rollback record");
    assert_eq!(record.state, RestoreJournalState::RollbackRequired);
    assert!(
        record.intent.is_some(),
        "the intent is preserved for owner reconciliation"
    );
    let mut late = FakeTarget::new(&bundle, &plan);
    assert_eq!(
        run(&bundle, &plan, &mut late, &mut journal.clone()),
        Err(BackupError::RestoreRollbackRequired),
        "rollback stays terminal until explicit owner-evidence transition"
    );
    assert!(
        late.applies.is_empty(),
        "no automatic destructive rollback occurs"
    );
}

// WORK_UNIT_CASE: 949/22
#[test]
fn journal_cleanup_and_diagnostic_failures_preserve_primary_outcome_and_owner_identity() {
    let (bundle, plan, _, _) = full_harness();
    let transaction = plan.transaction().expect("transaction");
    let journal = FakeJournal::with_faults(JournalFaults {
        state_once: Some(RestoreJournalState::Completed),
        ..JournalFaults::default()
    });

    let mut first = FakeTarget::new(&bundle, &plan);
    assert_eq!(
        run(&bundle, &plan, &mut first, &mut journal.clone()),
        Err(BackupError::RestoreJournalCasConflict),
        "completion-advance failure surfaces instead of succeeding"
    );
    let preserved = journal.record().expect("primary outcome survives");
    assert_eq!(preserved.state, RestoreJournalState::ReceiptPersisted);
    let preserved_receipt = preserved
        .final_receipt
        .clone()
        .expect("bound final receipt");

    let mut resumed = FakeTarget::new(&bundle, &plan);
    let receipt = run(&bundle, &plan, &mut resumed, &mut journal.clone())
        .expect("retry preserves the primary outcome");
    assert_eq!(
        receipt, preserved_receipt,
        "stable receipt across journal failure"
    );
    assert!(
        resumed.applies.is_empty(),
        "retry dispatches no duplicate effect"
    );
    assert_eq!(receipt.plan_id, plan.plan_id, "stable owner plan identity");
    assert_eq!(
        receipt.bundle_sha256, transaction.bundle_sha256,
        "stable owner transaction identity"
    );
}

// WORK_UNIT_CASE: 949/23
#[test]
fn bounded_crash_replay_reference_model_proves_no_loss_or_duplication() {
    let (bundle, plan, mut probe_target, mut probe_journal) = full_harness();
    run(&bundle, &plan, &mut probe_target, &mut probe_journal).expect("clean run");
    let revisions: Vec<u64> = {
        let mut seen = probe_journal
            .cas_log()
            .iter()
            .map(|entry| entry.expected_revision)
            .collect::<Vec<_>>();
        seen.sort_unstable();
        seen.dedup();
        seen
    };
    assert!(!revisions.is_empty());

    for revision in revisions {
        let journal = FakeJournal::with_faults(JournalFaults {
            expected_revision_once: Some(revision),
            ..JournalFaults::default()
        });
        let mut first = FakeTarget::new(&bundle, &plan);
        assert_eq!(
            run(&bundle, &plan, &mut first, &mut journal.clone()),
            Err(BackupError::RestoreJournalCasConflict),
            "crash at revision {revision} surfaces"
        );
        let mut resumed = FakeTarget::new(&bundle, &plan).with_faults(TargetFaults {
            reconcile: ReconcileMode::Applied,
            ..TargetFaults::default()
        });
        let receipt = run(&bundle, &plan, &mut resumed, &mut journal.clone())
            .expect("resume completes after crash");
        receipt.validate().expect("receipt validates");
        for phase in &probe_target.applies {
            let total = first.applies.iter().filter(|key| *key == phase).count()
                + resumed.applies.iter().filter(|key| *key == phase).count();
            assert_eq!(
                total, 1,
                "phase {phase} applies exactly once after crash at {revision}"
            );
        }
        assert_eq!(
            first.applies.len() + resumed.applies.len(),
            probe_target.applies.len(),
            "no lost phase or member after crash at {revision}"
        );
    }

    let journal = FakeJournal::with_faults(JournalFaults {
        expected_revision_once: Some(1),
        ..JournalFaults::default()
    });
    let mut coordinator_a = FakeTarget::new(&bundle, &plan);
    assert_eq!(
        run(&bundle, &plan, &mut coordinator_a, &mut journal.clone()),
        Err(BackupError::RestoreJournalCasConflict),
        "first coordinator loses the shared predecessor race"
    );
    let mut coordinator_b = FakeTarget::new(&bundle, &plan);
    let winner_receipt = run(&bundle, &plan, &mut coordinator_b, &mut journal.clone())
        .expect("second coordinator wins the predecessor");
    let mut coordinator_a_again = FakeTarget::new(&bundle, &plan);
    let loser_receipt = run(
        &bundle,
        &plan,
        &mut coordinator_a_again,
        &mut journal.clone(),
    )
    .expect("loser replays the won transaction");
    assert_eq!(
        winner_receipt, loser_receipt,
        "one stable outcome for both coordinators"
    );
    assert!(
        coordinator_a_again.applies.is_empty(),
        "loser dispatches nothing"
    );
    assert_eq!(
        coordinator_a.applies.len() + coordinator_b.applies.len(),
        probe_target.applies.len(),
        "two coordinators produce no duplicate effect"
    );
}

// WORK_UNIT_CASE: 949/24
#[test]
fn output_never_claims_cutover_or_active_authority_and_has_no_second_engine() {
    let (bundle, plan, mut target, mut journal) = full_harness();
    assert_eq!(
        plan.execute(&bundle, &mut target),
        Err(BackupError::RestoreJournalRequired),
        "journal-less execution is refused"
    );
    assert!(
        target.calls.is_empty(),
        "refused execution dispatches nothing"
    );

    let receipt = run(&bundle, &plan, &mut target, &mut journal).expect("restore completes");
    receipt.validate().expect("receipt validates");
    assert!(!receipt.cutover_performed, "no cutover performed");
    assert!(
        !receipt.operational_recovery_ready,
        "no operational readiness claimed"
    );
    assert!(!receipt.evidence_level.permits_operational_readiness());

    let evidence = evidence_for(&bundle, &plan);
    assert!(
        !evidence.active_authority_restored,
        "no active restored authority"
    );
    assert!(
        !matches!(
            evidence.archive_disposition.disposition,
            RestoreArchiveDispositionKind::Rejected
        ),
        "source archive keeps its explicit disposition, never silent retirement"
    );
    assert!(
        target.legacy_calls.is_empty(),
        "no second restore engine behind the legacy seam"
    );

    let mut forged = receipt.clone();
    forged.cutover_performed = true;
    assert_eq!(
        forged.validate(),
        Err(BackupError::CutoverNotAuthorized),
        "cutover claim without owner authorization is refused"
    );
    let mut ready = receipt;
    ready.operational_recovery_ready = true;
    assert_eq!(
        ready.validate(),
        Err(BackupError::RestoreEvidenceLevelMismatch),
        "readiness claim below the operational level is refused"
    );
}
