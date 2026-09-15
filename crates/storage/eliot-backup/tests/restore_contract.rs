//! Restore evidence owner-binding contract tests, cases 947/1..947/10.
//!
//! Worker A (contract half) owns cases 1-10 in this file. Worker B owns
//! cases 11-20 in the same file on a separate worktree/branch; fixtures for
//! this half live under `tests/data/restore-contract/947-a-*.json` so the two
//! halves never collide on filenames.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_backup::{
    BackupBundle, BackupClass, BackupError, BackupInput, EventRange, ExportFence,
    ObservedLineageLimit, OperationalValidationEvidence, OwnerTrustBinding,
    ReconciliationDenominator, RestoreArchiveDisposition, RestoreArchiveDispositionKind,
    RestoreContext, RestoreEvidence, RestoreEvidenceLevel, RestoreHistoricalAuthority,
    RestoreHistoricalKind, RestoreJournalAdmission, RestoreJournalRecord, RestoreJournalState,
    RestoreObligationState, RestoreOwnerEpoch, RestoreOwnerObligation, RestorePhase, RestorePlan,
    RestoreProvenance, RestoreReceipt, RestoreReconciliation, RestoreTarget,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use std::num::NonZeroU64;

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";

fn epoch_in(lineage: &str, sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(lineage).expect("valid lineage"),
        NonZeroU64::new(sequence).expect("nonzero sequence"),
    )
    .expect("valid epoch")
}

fn epoch(sequence: u64) -> EpochId {
    epoch_in(LINEAGE_A, sequence)
}

fn owner(owner_id: &str) -> OwnerTrustBinding {
    OwnerTrustBinding {
        owner_id: owner_id.to_owned(),
        trust_binding_ref: format!("trust-binding-{owner_id}-session-1"),
    }
}

fn obligation(owner_id: &str, state: RestoreObligationState) -> RestoreOwnerObligation {
    RestoreOwnerObligation {
        owner_id: owner_id.to_owned(),
        evidence_ref: format!("receipt-{owner_id}-1"),
        state,
    }
}

fn degraded_bundle_with_class(class: BackupClass, scope: bool) -> BackupBundle {
    let source_fence = StateFence::new(epoch(1), ResourceGeneration::genesis());
    let is_full = class == BackupClass::FullRecovery;
    let ors_snapshot = if is_full {
        Some(eliot_backup::OrsSnapshotFence {
            snapshot_id: "ors-1".to_owned(),
            authority_epoch: epoch(1),
            resource_generation: ResourceGeneration::genesis(),
            last_receipt_cursor: 0,
            last_event_cursor: 0,
            last_outbox_cursor: 0,
            pending_operation_ids: Vec::new(),
            job_checkpoint_ids: Vec::new(),
            generation_cutover_ids: Vec::new(),
            state_fence: source_fence.clone(),
            active_authority_restored: false,
        })
    } else {
        None
    };
    let watchdog_spool = if is_full {
        Some(eliot_backup::WatchdogSpoolFence {
            fence_id: "watchdog-1".to_owned(),
            unresolved_signal_digests: vec![sha256_hex(b"signal-1")],
            state_fence: source_fence.clone(),
            bounded: true,
        })
    } else {
        None
    };
    let artifacts = if is_full {
        ["config", "policy", "module", "host_dependency_build"]
            .iter()
            .map(|kind| {
                let bytes = format!("{kind}-manifest-bytes").into_bytes();
                let digest = sha256_hex(&bytes);
                eliot_backup::BackupArtifact {
                    kind: (*kind).to_owned(),
                    artifact_id: format!("{kind}-1"),
                    bytes,
                    sha256: digest,
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    BackupBundle::build(BackupInput {
        backup_id: "bundle-947-a".to_owned(),
        class,
        source_adapter: "test-adapter".to_owned(),
        schema_generation: "schema-1".to_owned(),
        export_fence: ExportFence {
            export_id: "export-1".to_owned(),
            store_generation: "store-1".to_owned(),
            state_fence: source_fence,
            scope_id: if scope {
                Some(eliot_store_api::ScopeId::new("scope-1").expect("scope"))
            } else {
                None
            },
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            event_range: EventRange {
                first_sequence: None,
                last_sequence: None,
                count: 0,
            },
            blob_reachability_manifest: Vec::new(),
            consistent: true,
        },
        canonical_events: Vec::new(),
        projections: Vec::new(),
        receipts: Vec::new(),
        blobs: Vec::new(),
        purge_ledger: Vec::new(),
        ors_snapshot,
        artifacts,
        watchdog_spool,
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 7,
    })
    .expect("bundle builds")
}

fn target_context(target_id: &str) -> RestoreContext {
    RestoreContext {
        target_id: target_id.to_owned(),
        target_authority_epoch: epoch(2),
        target_resource_generation: ResourceGeneration::new(2).expect("generation"),
    }
}

fn provenance_for(bundle: &BackupBundle, plan: &RestorePlan) -> RestoreProvenance {
    RestoreProvenance {
        transaction_id: plan.transaction().expect("transaction").transaction_id,
        plan_id: plan.plan_id.clone(),
        operation_id: "restore-operation-1".to_owned(),
        phase: RestorePhase::FinalizeIsolatedRoot,
        source_archive_id: bundle.manifest.backup_id.clone(),
        source_class: bundle.manifest.class,
        source_digest: bundle.bundle_sha256().expect("bundle digest"),
        source_endpoint_ref: "source-adapter-test".to_owned(),
        isolated_destination_ref: plan.target.target_id.clone(),
        expected_predecessor_ref: "predecessor-receipt-0".to_owned(),
        schema_revision: bundle.manifest.schema_generation.clone(),
        build_manifest_digest: sha256_hex(b"test-build-manifest"),
        purge_ledger_revision: bundle.manifest.purge_ledger_revision,
        owner: owner("restore-owner"),
        observed_generation: plan.restored_fence.resource_generation,
        observed_epoch: plan.restored_fence.authority_epoch.clone(),
        validation_digest: sha256_hex(b"bounded-validation-evidence"),
    }
}

fn evidence_for(bundle: &BackupBundle, plan: &RestorePlan) -> RestoreEvidence {
    RestoreEvidence {
        target_id: plan.target.target_id.clone(),
        isolated_root: true,
        purge_applied: true,
        blobs_imported: true,
        projections_rebuilt: true,
        receipt_event_chain_verified: true,
        ors_suspended: false,
        active_authority_restored: false,
        authority_epoch: plan.restored_fence.authority_epoch.clone(),
        resource_generation: plan.restored_fence.resource_generation,
        provenance: provenance_for(bundle, plan),
        obligations: eliot_backup::RestoreObligations {
            purge: obligation("purge-owner", RestoreObligationState::Satisfied),
            canonical_validation: obligation("canonical-owner", RestoreObligationState::Satisfied),
            reference_validation: obligation("reference-owner", RestoreObligationState::Satisfied),
            blob_validation: obligation("blob-owner", RestoreObligationState::Satisfied),
            ors_suspension: obligation("ors-owner", RestoreObligationState::NotAttempted),
            unresolved_effect_reconciliation: obligation(
                "reconciliation-owner",
                RestoreObligationState::Unknown,
            ),
            watchdog_signals: obligation("watchdog-owner", RestoreObligationState::Satisfied),
            external_source_revalidation: obligation(
                "external-source-owner",
                RestoreObligationState::Satisfied,
            ),
            runtime_invalidation: obligation("runtime-owner", RestoreObligationState::Satisfied),
            session_invalidation: obligation("session-owner", RestoreObligationState::Satisfied),
            lease_invalidation: obligation("lease-owner", RestoreObligationState::Satisfied),
            route_invalidation: obligation("route-owner", RestoreObligationState::Satisfied),
            user_broker_invalidation: obligation(
                "user-broker-owner",
                RestoreObligationState::MissingCapability,
            ),
        },
        observed_lineage_limits: vec![ObservedLineageLimit {
            owner_id: "restore-owner".to_owned(),
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
        historical_authority: Vec::new(),
        archive_disposition: RestoreArchiveDisposition {
            disposition: RestoreArchiveDispositionKind::Current,
            compatibility_ref: "ecxf-1-current".to_owned(),
        },
    }
}

fn load_fixture(name: &str) -> serde_json::Value {
    let path = format!(
        "{}/tests/data/restore-contract/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(&path).expect("fixture reads");
    serde_json::from_slice(&bytes).expect("fixture parses")
}

// WORK_UNIT_CASE: 947/1
#[test]
fn archive_classes_have_distinct_restore_applicability() {
    let full = degraded_bundle_with_class(BackupClass::FullRecovery, false);
    full.validate().expect("full bundle validates");
    assert_eq!(
        RestoreEvidenceLevel::for_class(full.manifest.class),
        RestoreEvidenceLevel::ReconciliationRequired
    );
    let degraded = degraded_bundle_with_class(BackupClass::CanonicalOnlyDegraded, false);
    degraded.validate().expect("degraded bundle validates");
    let scope = degraded_bundle_with_class(BackupClass::ScopeExport, true);
    scope.validate().expect("scope bundle validates");
    assert_eq!(
        RestoreEvidenceLevel::for_class(BackupClass::FullRecovery),
        RestoreEvidenceLevel::ReconciliationRequired
    );
    assert_eq!(
        RestoreEvidenceLevel::for_class(BackupClass::CanonicalOnlyDegraded),
        RestoreEvidenceLevel::IsolatedImportComplete
    );
    assert_eq!(
        RestoreEvidenceLevel::for_class(BackupClass::ScopeExport),
        RestoreEvidenceLevel::IsolatedImportComplete
    );
    // A scope transfer can never report installation recovery.
    assert!(
        !RestoreEvidenceLevel::for_class(BackupClass::ScopeExport).permits_operational_readiness()
    );
    let plan = RestorePlan::compile(&degraded, target_context("target-1")).expect("plan");
    let evidence = evidence_for(&degraded, &plan);
    evidence.validate().expect("evidence validates");
    assert_eq!(
        evidence.evidence_level(),
        RestoreEvidenceLevel::IsolatedImportComplete
    );
    let manifest_fixture = load_fixture("947-a-manifest.json");
    assert_eq!(
        manifest_fixture["expected_levels"]["full_recovery"],
        "reconciliation_required"
    );
    assert_eq!(
        manifest_fixture["expected_levels"]["canonical_only_degraded"],
        "isolated_import_complete"
    );
    assert_eq!(
        manifest_fixture["expected_levels"]["scope_export"],
        "isolated_import_complete"
    );
}

// WORK_UNIT_CASE: 947/2
#[test]
fn execute_refuses_without_journal() {
    struct NoopTarget;
    impl RestoreTarget for NoopTarget {
        fn prepare_isolated(
            &mut self,
            _: &RestoreContext,
            _: &eliot_backup::RestoredFence,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn apply_purge_ledger(
            &mut self,
            _: &[eliot_security_contracts::PurgeLedgerEntry],
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_sealed_blob(&mut self, _: &eliot_backup::BackupBlob) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_canonical_event(
            &mut self,
            _: &eliot_backup::CanonicalRecord,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_receipt(&mut self, _: &eliot_store_api::WriteReceipt) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_projection(
            &mut self,
            _: &eliot_backup::CanonicalRecord,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn suspend_ors_operations(
            &mut self,
            _: &eliot_backup::OrsSnapshotFence,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn rebuild_projections(
            &mut self,
            _: &eliot_backup::RestoredFence,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn verify_receipt_event_chain(
            &mut self,
            _: &[eliot_store_api::WriteReceipt],
            _: &[eliot_backup::CanonicalRecord],
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn finalize_isolated(
            &mut self,
            _: &eliot_backup::RestoredFence,
        ) -> Result<RestoreEvidence, BackupError> {
            Err(BackupError::RestoreTargetReceiptRequired)
        }
    }
    let bundle = degraded_bundle_with_class(BackupClass::CanonicalOnlyDegraded, false);
    let plan = RestorePlan::compile(&bundle, target_context("target-2")).expect("plan");
    let mut target = NoopTarget;
    assert_eq!(
        plan.execute(&bundle, &mut target),
        Err(BackupError::RestoreJournalRequired)
    );
}

// WORK_UNIT_CASE: 947/3
#[test]
fn default_apply_fails_before_effect() {
    struct DefaultTarget;
    impl RestoreTarget for DefaultTarget {
        fn prepare_isolated(
            &mut self,
            _: &RestoreContext,
            _: &eliot_backup::RestoredFence,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn apply_purge_ledger(
            &mut self,
            _: &[eliot_security_contracts::PurgeLedgerEntry],
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_sealed_blob(&mut self, _: &eliot_backup::BackupBlob) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_canonical_event(
            &mut self,
            _: &eliot_backup::CanonicalRecord,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_receipt(&mut self, _: &eliot_store_api::WriteReceipt) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_projection(
            &mut self,
            _: &eliot_backup::CanonicalRecord,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn suspend_ors_operations(
            &mut self,
            _: &eliot_backup::OrsSnapshotFence,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn rebuild_projections(
            &mut self,
            _: &eliot_backup::RestoredFence,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn verify_receipt_event_chain(
            &mut self,
            _: &[eliot_store_api::WriteReceipt],
            _: &[eliot_backup::CanonicalRecord],
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn finalize_isolated(
            &mut self,
            _: &eliot_backup::RestoredFence,
        ) -> Result<RestoreEvidence, BackupError> {
            Err(BackupError::RestoreTargetReceiptRequired)
        }
    }
    let bundle = degraded_bundle_with_class(BackupClass::CanonicalOnlyDegraded, false);
    let plan = RestorePlan::compile(&bundle, target_context("target-3")).expect("plan");
    let transaction = plan.transaction().expect("transaction");
    let intent = eliot_backup::RestoreIntent {
        transaction_id: transaction.transaction_id.clone(),
        phase: RestorePhase::PrepareIsolatedRoot,
        input_digest: sha256_hex(b"intent"),
    };
    let mut target = DefaultTarget;
    assert_eq!(
        target.apply_restore_effect(&plan, &bundle, &intent),
        Err(BackupError::RestoreTargetReceiptRequired)
    );
}

// WORK_UNIT_CASE: 947/4
#[test]
fn default_reconcile_remains_unknown() {
    struct DefaultTarget;
    impl RestoreTarget for DefaultTarget {
        fn prepare_isolated(
            &mut self,
            _: &RestoreContext,
            _: &eliot_backup::RestoredFence,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn apply_purge_ledger(
            &mut self,
            _: &[eliot_security_contracts::PurgeLedgerEntry],
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_sealed_blob(&mut self, _: &eliot_backup::BackupBlob) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_canonical_event(
            &mut self,
            _: &eliot_backup::CanonicalRecord,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_receipt(&mut self, _: &eliot_store_api::WriteReceipt) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_projection(
            &mut self,
            _: &eliot_backup::CanonicalRecord,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn suspend_ors_operations(
            &mut self,
            _: &eliot_backup::OrsSnapshotFence,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn rebuild_projections(
            &mut self,
            _: &eliot_backup::RestoredFence,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn verify_receipt_event_chain(
            &mut self,
            _: &[eliot_store_api::WriteReceipt],
            _: &[eliot_backup::CanonicalRecord],
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn finalize_isolated(
            &mut self,
            _: &eliot_backup::RestoredFence,
        ) -> Result<RestoreEvidence, BackupError> {
            Err(BackupError::RestoreTargetReceiptRequired)
        }
    }
    let intent = eliot_backup::RestoreIntent {
        transaction_id: "transaction-1".to_owned(),
        phase: RestorePhase::PrepareIsolatedRoot,
        input_digest: sha256_hex(b"intent"),
    };
    let mut target = DefaultTarget;
    let outcome = target
        .reconcile_restore_effect(&intent)
        .expect("reconcile answers");
    assert!(matches!(outcome, RestoreReconciliation::Unknown));
    assert!(!matches!(outcome, RestoreReconciliation::NotApplied));
    if let RestoreReconciliation::Applied(_) = outcome {
        panic!("unknown must not report applied");
    }
}

// WORK_UNIT_CASE: 947/5
#[test]
fn ors_suspension_does_not_assert_reconciliation() {
    let bundle = degraded_bundle_with_class(BackupClass::CanonicalOnlyDegraded, false);
    let plan = RestorePlan::compile(&bundle, target_context("target-5")).expect("plan");
    let mut evidence = evidence_for(&bundle, &plan);
    // Suspension alone leaves unresolved-effect reconciliation unknown, so
    // owner operational validation must fail closed.
    evidence.ors_suspended = true;
    evidence.validate().expect("suspended evidence validates");
    assert_eq!(
        evidence.operationally_validated_by_owner(),
        Err(BackupError::RestoreEvidenceIncomplete)
    );
    let fixture = load_fixture("947-a-ors-suspension.json");
    assert_eq!(fixture["ors_suspended"], true);
    assert_eq!(fixture["unresolved_effect_reconciliation"], "unknown");
    assert_eq!(fixture["operationally_validated"], false);
}

// WORK_UNIT_CASE: 947/6
#[test]
fn watchdog_spool_evidence_cannot_be_silent_or_known_empty() {
    let fence = eliot_backup::WatchdogSpoolFence {
        fence_id: "watchdog-1".to_owned(),
        unresolved_signal_digests: vec![sha256_hex(b"signal-1")],
        state_fence: StateFence::new(epoch(1), ResourceGeneration::genesis()),
        bounded: true,
    };
    fence.validate().expect("bounded fence validates");
    let unbounded = eliot_backup::WatchdogSpoolFence {
        bounded: false,
        ..fence.clone()
    };
    assert_eq!(
        unbounded.validate(),
        Err(BackupError::UnboundedWatchdogSpool)
    );
    // A known-empty digest list would silently assert "no signals"; the
    // obligation model instead requires the exact owner receipt or an
    // explicit missing capability, never a silent empty success.
    let silent = obligation("watchdog-owner", RestoreObligationState::Satisfied);
    assert_eq!(silent.evidence_ref, "receipt-watchdog-owner-1");
    let fixture = load_fixture("947-a-watchdog-spool.json");
    assert_eq!(fixture["bounded"], true);
    assert!(
        !fixture["unresolved_signal_digests"]
            .as_array()
            .expect("array")
            .is_empty()
    );
}

// WORK_UNIT_CASE: 947/7
#[test]
fn effect_blocking_claim_requires_responsible_owner_evidence() {
    let satisfied = obligation("ors-owner", RestoreObligationState::Satisfied);
    assert_eq!(satisfied.owner_id, "ors-owner");
    let missing = obligation("ors-owner", RestoreObligationState::MissingCapability);
    assert_ne!(satisfied.state, missing.state);
    // An unblocking claim without the responsible owner's receipt is an
    // explicit missing capability, never fabricated success.
    let bundle = degraded_bundle_with_class(BackupClass::CanonicalOnlyDegraded, false);
    let plan = RestorePlan::compile(&bundle, target_context("target-7")).expect("plan");
    let mut evidence = evidence_for(&bundle, &plan);
    evidence.obligations.ors_suspension = missing;
    evidence
        .validate()
        .expect("explicit missing capability validates");
    assert!(!evidence.obligations.all_satisfied());
    assert_eq!(
        evidence.operationally_validated_by_owner(),
        Err(BackupError::RestoreEvidenceIncomplete)
    );
}

// WORK_UNIT_CASE: 947/8
#[test]
fn proposed_epochs_are_not_owner_issued_authority() {
    // A caller-proposed target epoch passes planning validation when it
    // advances the observed lineage, but it is planning input, not accepted
    // authority: no owner issued it.
    let context = target_context("target-8");
    context.validate().expect("context shape validates");
    let owner_epoch = RestoreOwnerEpoch {
        owner: owner("epoch-owner"),
        new_epoch: epoch(2),
        new_generation: ResourceGeneration::new(2).expect("generation"),
        supersedes: vec![ObservedLineageLimit {
            owner_id: "epoch-owner".to_owned(),
            observed_epoch: epoch(1),
            observed_generation: ResourceGeneration::genesis(),
        }],
    };
    owner_epoch
        .validate()
        .expect("owner-issued epoch validates");
    // Owner issuance under a different lineage at a non-genesis sequence is
    // unrelated to the observed epoch (exact-tuple rule) and fails.
    let forged = RestoreOwnerEpoch {
        owner: owner("epoch-owner"),
        new_epoch: epoch_in(LINEAGE_B, 9),
        new_generation: ResourceGeneration::new(2).expect("generation"),
        supersedes: vec![ObservedLineageLimit {
            owner_id: "epoch-owner".to_owned(),
            observed_epoch: epoch(1),
            observed_generation: ResourceGeneration::genesis(),
        }],
    };
    assert_eq!(forged.validate(), Err(BackupError::StaleRestoreLineage));
    let fixture = load_fixture("947-a-proposed-epoch.json");
    assert_eq!(fixture["planning_input_accepted"], true);
    assert_eq!(fixture["accepted_as_authority"], false);
}

// WORK_UNIT_CASE: 947/9
#[test]
fn old_runtime_generation_invalidation_requires_current_evidence() {
    let bundle = degraded_bundle_with_class(BackupClass::CanonicalOnlyDegraded, false);
    let plan = RestorePlan::compile(&bundle, target_context("target-9")).expect("plan");
    let mut evidence = evidence_for(&bundle, &plan);
    // Stale runtime invalidation (not attempted by the exact current owner)
    // cannot support operational validation.
    evidence.obligations.runtime_invalidation =
        obligation("runtime-owner", RestoreObligationState::NotAttempted);
    assert_eq!(
        evidence.operationally_validated_by_owner(),
        Err(BackupError::RestoreEvidenceIncomplete)
    );
    let current = OperationalValidationEvidence {
        owner: owner("runtime-owner"),
        target_ref: "target-9".to_owned(),
        validation_digest: sha256_hex(b"runtime-validation"),
        observed_at_state_fence: StateFence::new(
            epoch(2),
            ResourceGeneration::new(2).expect("generation"),
        ),
    };
    current
        .validate()
        .expect("current owner evidence validates");
    let fixture = load_fixture("947-a-runtime-invalidation.json");
    assert_eq!(fixture["stale_invalidation_accepted"], false);
    assert_eq!(fixture["requires_current_owner_evidence"], true);
}

// WORK_UNIT_CASE: 947/10
#[test]
fn old_session_lease_route_state_never_becomes_active_authority() {
    let suspended = RestoreHistoricalAuthority {
        kind: RestoreHistoricalKind::Session,
        historical_ref: "session-historical-1".to_owned(),
        suspended: true,
    };
    suspended.validate().expect("suspended history validates");
    for kind in [
        RestoreHistoricalKind::Lease,
        RestoreHistoricalKind::Route,
        RestoreHistoricalKind::UserBrokerRegistration,
        RestoreHistoricalKind::AuthorityEpoch,
        RestoreHistoricalKind::OrsOperation,
        RestoreHistoricalKind::WatchdogSignal,
    ] {
        RestoreHistoricalAuthority {
            kind,
            historical_ref: "historical-1".to_owned(),
            suspended: true,
        }
        .validate()
        .expect("suspended history validates");
    }
    let activated = RestoreHistoricalAuthority {
        kind: RestoreHistoricalKind::Session,
        historical_ref: "session-historical-1".to_owned(),
        suspended: false,
    };
    assert_eq!(
        activated.validate(),
        Err(BackupError::HistoricalAuthorityActivated)
    );
    // Evidence carrying activated history is rejected.
    let bundle = degraded_bundle_with_class(BackupClass::CanonicalOnlyDegraded, false);
    let plan = RestorePlan::compile(&bundle, target_context("target-10")).expect("plan");
    let mut evidence = evidence_for(&bundle, &plan);
    evidence.historical_authority.push(activated);
    assert_eq!(
        evidence.validate(),
        Err(BackupError::HistoricalAuthorityActivated)
    );
    // A complete known-zero denominator proves suspension accounting without
    // activation.
    let denominator = ReconciliationDenominator {
        owner_id: "reconciliation-owner".to_owned(),
        denominator_ref: "denominator-current-10".to_owned(),
        expected_total: 0,
        reconciled_refs: Vec::new(),
    };
    assert!(denominator.is_known_zero());
    let admission = RestoreJournalAdmission {
        persistent_owner: owner("journal-owner"),
        database_ref: "journal-db-1".to_owned(),
        installation_ref: "installation-1".to_owned(),
        generation: ResourceGeneration::new(2).expect("generation"),
        journal_identity_ref: "journal-1".to_owned(),
        admission_receipt_ref: "admission-receipt-1".to_owned(),
        fixture_proof_only: false,
    };
    assert!(admission.admits_production_durable_recovery());
    let receipt = RestoreReceipt {
        receipt_id: "restore-receipt-947-10".to_owned(),
        plan_id: plan.plan_id.clone(),
        bundle_sha256: bundle.bundle_sha256().expect("digest"),
        target_id: plan.target.target_id.clone(),
        restored_fence: plan.restored_fence.clone(),
        effect_receipt_sha256: sha256_hex(b"effect-10"),
        evidence_level: RestoreEvidenceLevel::IsolatedImportComplete,
        canonical_only: true,
        operational_recovery_ready: false,
        cutover_performed: false,
    };
    receipt.validate().expect("isolated receipt validates");
    let _ = RestoreJournalRecord {
        journal_key: "journal-key-10".to_owned(),
        transaction: plan.transaction().expect("transaction"),
        revision: 0,
        completed_phases: 0,
        phase: RestorePhase::Pending,
        state: RestoreJournalState::Ready,
        intent: None,
        receipt: None,
        final_receipt: None,
    };
}
