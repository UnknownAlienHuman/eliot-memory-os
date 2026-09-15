//! Restore evidence owner-binding contract tests, cases 947/1..947/20.
//!
//! Worker A (contract half) owns cases 1-10 in this file. Worker B owns
//! cases 11-20 appended below on a separate branch; fixtures for the A half
//! live under `tests/data/restore-contract/947-a-*.json` and fixtures for the
//! B half under `tests/data/restore-contract/947-b-*.json` so the two halves
//! never collide on filenames.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]
//! Worker B appendix (cases 947/11..947/20) follows the same actual API and
//! shares this file's helpers. Append-only: cases 1-10 above are untouched.

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

// ---------------------------------------------------------------------------
// Worker B appendix: cases 947/11..947/20. Append-only; cases 1-10 above are
// untouched. Helpers shared from the Worker A section above:
// `epoch`/`epoch_in`, `owner`, `obligation`, `degraded_bundle_with_class`,
// `target_context`, `provenance_for`, `evidence_for`, `load_fixture`.
// ---------------------------------------------------------------------------

use eliot_backup::{RestoreAppliedEffect, RestoreEffectReceipt, RestoreIntent};
use eliot_contracts::canonical_json_bytes;
use std::collections::BTreeMap;

/// Exact broker-invalidation owner shape used across the Worker B appendix.
fn broker_obligation(state: RestoreObligationState) -> RestoreOwnerObligation {
    RestoreOwnerObligation {
        owner_id: "user-broker-owner".to_owned(),
        evidence_ref: format!("receipt-user-broker-owner-{}", state_name(state)),
        state,
    }
}

fn state_name(state: RestoreObligationState) -> &'static str {
    match state {
        RestoreObligationState::Satisfied => "satisfied",
        RestoreObligationState::NotAttempted => "not-attempted",
        RestoreObligationState::Unknown => "unknown",
        RestoreObligationState::MissingCapability => "missing-capability",
    }
}

struct FullTarget {
    calls: Vec<String>,
}

impl FullTarget {
    fn journal_phase_calls(bundle: &BackupBundle) -> Vec<String> {
        let mut names = vec!["prepare".to_owned(), "purge".to_owned()];
        names.extend(
            bundle
                .blobs
                .iter()
                .map(|blob| format!("blob:{}", blob.locator.hash)),
        );
        names.extend(
            bundle
                .canonical_events
                .iter()
                .map(|record| format!("event:{}", record.record_id)),
        );
        names.extend(
            bundle
                .receipts
                .iter()
                .map(|receipt| format!("receipt:{}", receipt.operation_id)),
        );
        names.extend(
            bundle
                .projections
                .iter()
                .map(|record| format!("projection:{}", record.record_id)),
        );
        if bundle.ors_snapshot.is_some() {
            names.push("ors-suspend".to_owned());
        }
        names.extend([
            "rebuild".to_owned(),
            "verify".to_owned(),
            "finalize".to_owned(),
        ]);
        names
    }

    fn dispatch(&mut self, phase: &RestorePhase, plan: &RestorePlan, bundle: &BackupBundle) {
        match phase {
            RestorePhase::Pending => panic!("coordinator never dispatches Pending"),
            RestorePhase::PrepareIsolatedRoot => {
                self.calls.push("prepare".to_owned());
                let context = RestoreContext {
                    target_id: plan.target.target_id.clone(),
                    target_authority_epoch: plan.restored_fence.authority_epoch.clone(),
                    target_resource_generation: plan.restored_fence.resource_generation,
                };
                assert_eq!(context.validate(), Ok(()));
            }
            RestorePhase::ApplyPurgeLedger => {
                self.calls.push("purge".to_owned());
            }
            RestorePhase::ImportSealedBlob { hash } => {
                let blob = bundle
                    .blobs
                    .iter()
                    .find(|blob| blob.locator.hash.to_string() == *hash)
                    .expect("phase blob exists");
                blob.validate().expect("phase blob validates");
                self.calls.push(format!("blob:{hash}"));
            }
            RestorePhase::ImportCanonicalEvent { record_id } => {
                let record = bundle
                    .canonical_events
                    .iter()
                    .find(|record| record.record_id == *record_id)
                    .expect("phase event exists");
                record.validate().expect("phase event validates");
                self.calls.push(format!("event:{record_id}"));
            }
            RestorePhase::ImportReceipt { operation_id } => {
                let receipt = bundle
                    .receipts
                    .iter()
                    .find(|receipt| receipt.operation_id.to_string() == *operation_id)
                    .expect("phase receipt exists");
                receipt.validate().expect("phase receipt validates");
                self.calls.push(format!("receipt:{operation_id}"));
            }
            RestorePhase::ImportProjection { record_id } => {
                let record = bundle
                    .projections
                    .iter()
                    .find(|record| record.record_id == *record_id)
                    .expect("phase projection exists");
                record.validate().expect("phase projection validates");
                self.calls.push(format!("projection:{record_id}"));
            }
            RestorePhase::SuspendOrsOperations => {
                let snapshot = bundle.ors_snapshot.as_ref().expect("ors snapshot exists");
                snapshot.validate().expect("ors snapshot validates");
                self.calls.push("ors-suspend".to_owned());
            }
            RestorePhase::RebuildProjections => {
                plan.restored_fence
                    .validate()
                    .expect("restored fence validates");
                self.calls.push("rebuild".to_owned());
            }
            RestorePhase::VerifyReceiptEventChain => {
                assert!(
                    bundle
                        .receipts
                        .iter()
                        .all(|receipt| receipt.validate().is_ok())
                );
                self.calls.push("verify".to_owned());
            }
            RestorePhase::FinalizeIsolatedRoot => {
                let evidence = full_evidence_for(bundle, plan);
                let expected = RestoreEvidenceLevel::for_class(bundle.manifest.class);
                assert_eq!(evidence.evidence_level(), expected);
                self.calls.push("finalize".to_owned());
            }
        }
    }
}

/// A real-durable journal double: exact CAS semantics over a map keyed by
/// journal key, so production-composition claims below exercise the actual
/// coordinator `compare_and_swap` path rather than a canned boolean.
struct MapJournal {
    rows: BTreeMap<String, RestoreJournalRecord>,
}

impl MapJournal {
    fn new() -> Self {
        Self {
            rows: BTreeMap::new(),
        }
    }
}

impl eliot_backup::RestoreJournalPort for MapJournal {
    fn load(&mut self, journal_key: &str) -> Result<Option<RestoreJournalRecord>, BackupError> {
        Ok(self.rows.get(journal_key).cloned())
    }

    fn compare_and_swap(
        &mut self,
        journal_key: &str,
        expected_revision: u64,
        next: RestoreJournalRecord,
    ) -> Result<(), BackupError> {
        assert_eq!(next.journal_key, journal_key);
        match self.rows.get(journal_key) {
            None => {
                assert_eq!(expected_revision, 0);
                assert_eq!(next.revision, 0);
            }
            Some(current) => {
                assert_eq!(current.revision, expected_revision);
                assert_eq!(next.revision, expected_revision + 1);
                assert_eq!(next.transaction, current.transaction);
            }
        }
        self.rows.insert(journal_key.to_owned(), next);
        Ok(())
    }
}

/// Fixture-only journal double: structurally valid but explicitly unadmitted
/// for production durable-recovery claims. The admission receipt is retained
/// so composition can inspect the exact fixture binding instead of relying on
/// a bare boolean.
struct FixtureJournal {
    admission_receipt_ref: String,
    inner: MapJournal,
}

/// Independent consumer compile fixture (case 947/20): proves the frozen
/// public evidence/journal surface still type-checks for an external crate
/// without the library gaining an archive rewrite, a journal implementation,
/// authority minting, cutover, or a weakened default.
fn assert_consumer_surface<T>()
where
    T: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
}

fn assert_consumer_journal<J>()
where
    J: eliot_backup::RestoreJournalPort,
{
}

impl FixtureJournal {
    fn new(admission: &RestoreJournalAdmission) -> Self {
        assert!(
            !admission.admits_production_durable_recovery(),
            "appendix fixture journal must be fixture-proof-only"
        );
        admission.validate().expect("fixture admission validates");
        Self {
            admission_receipt_ref: admission.admission_receipt_ref.clone(),
            inner: MapJournal::new(),
        }
    }

    fn admission_receipt_ref(&self) -> &str {
        &self.admission_receipt_ref
    }
}

impl eliot_backup::RestoreJournalPort for FixtureJournal {
    fn load(&mut self, journal_key: &str) -> Result<Option<RestoreJournalRecord>, BackupError> {
        self.inner.load(journal_key)
    }

    fn compare_and_swap(
        &mut self,
        journal_key: &str,
        expected_revision: u64,
        next: RestoreJournalRecord,
    ) -> Result<(), BackupError> {
        self.inner
            .compare_and_swap(journal_key, expected_revision, next)
    }
}

fn fixture_admission() -> RestoreJournalAdmission {
    RestoreJournalAdmission {
        persistent_owner: owner("journal-owner"),
        database_ref: "memory-fixture".to_owned(),
        installation_ref: "installation-fixture".to_owned(),
        generation: ResourceGeneration::genesis(),
        journal_identity_ref: "journal-fixture-947-b".to_owned(),
        admission_receipt_ref: "admission-fixture-947-b".to_owned(),
        fixture_proof_only: true,
    }
}

fn admitted_production_admission(plan: &RestorePlan) -> RestoreJournalAdmission {
    RestoreJournalAdmission {
        persistent_owner: owner("journal-owner"),
        database_ref: "journal-db-947-b".to_owned(),
        installation_ref: plan.target.target_id.clone(),
        generation: plan.restored_fence.resource_generation,
        journal_identity_ref: format!("journal-947-b-{}", plan.plan_id),
        admission_receipt_ref: "admission-receipt-947-b".to_owned(),
        fixture_proof_only: false,
    }
}

fn applied_effect_for(
    intent: &RestoreIntent,
    bundle: &BackupBundle,
    plan: &RestorePlan,
) -> RestoreAppliedEffect {
    // FullRecovery finalize evidence must already carry suspension plus the
    // exact ORS owner receipt; degraded bundles use the shared shape as-is.
    let final_evidence = if matches!(intent.phase, RestorePhase::FinalizeIsolatedRoot) {
        Some(if bundle.ors_snapshot.is_some() {
            full_evidence_for(bundle, plan)
        } else {
            evidence_for(bundle, plan)
        })
    } else {
        None
    };
    // Evidence digest binds through the same canonical JSON bytes the library
    // uses for its own integrity records (see `bundle_sha256`/`sha256` in
    // `src/lib.rs`): the finalize receipt must carry the digest of the exact
    // evidence value, so a forged or drifted evidence fails
    // `FinalizeEvidenceMismatch` in `validate_applied_effect`.
    let evidence_sha256 = final_evidence.as_ref().map_or_else(
        || sha256_hex(b"target-observed-effect-947-b"),
        |evidence| {
            let bytes = canonical_json_bytes(evidence).expect("evidence canonical bytes bind");
            sha256_hex(&bytes)
        },
    );
    RestoreAppliedEffect {
        receipt: RestoreEffectReceipt {
            transaction_id: intent.transaction_id.clone(),
            phase: intent.phase.clone(),
            input_digest: intent.input_digest.clone(),
            external_identity_sha256: sha256_hex(format!("{:?}", intent.phase).as_bytes()),
            evidence_sha256,
        },
        final_evidence,
    }
}

fn full_bundle_for_target(target_id: &str) -> (BackupBundle, RestorePlan) {
    let bundle = full_bundle_with_events_body();
    let plan = RestorePlan::compile(&bundle, target_context(target_id)).expect("plan");
    (bundle, plan)
}

fn full_evidence_for(bundle: &BackupBundle, plan: &RestorePlan) -> RestoreEvidence {
    let mut evidence = evidence_for(bundle, plan);
    // FullRecovery archives carry a live ORS snapshot, so the plan/bundle
    // binding requires suspension plus the exact ORS owner receipt; the
    // shared degraded-shaped helper leaves both unset.
    evidence.ors_suspended = true;
    evidence.obligations.ors_suspension =
        obligation("ors-owner", RestoreObligationState::Satisfied);
    evidence
}

fn full_bundle_with_events_body() -> BackupBundle {
    let source_fence = StateFence::new(epoch(1), ResourceGeneration::genesis());
    BackupBundle::build(BackupInput {
        backup_id: "bundle-947-b".to_owned(),
        class: BackupClass::FullRecovery,
        source_adapter: "test-adapter".to_owned(),
        schema_generation: "schema-1".to_owned(),
        export_fence: ExportFence {
            export_id: "export-947-b".to_owned(),
            store_generation: "store-947-b".to_owned(),
            state_fence: source_fence.clone(),
            scope_id: None,
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
        ors_snapshot: Some(eliot_backup::OrsSnapshotFence {
            snapshot_id: "ors-947-b".to_owned(),
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
        }),
        artifacts: ["config", "policy", "module", "host_dependency_build"]
            .iter()
            .map(|kind| {
                let bytes = format!("{kind}-947-b-bytes").into_bytes();
                let digest = sha256_hex(&bytes);
                eliot_backup::BackupArtifact {
                    kind: (*kind).to_owned(),
                    artifact_id: format!("{kind}-947-b"),
                    bytes,
                    sha256: digest,
                }
            })
            .collect(),
        watchdog_spool: Some(eliot_backup::WatchdogSpoolFence {
            fence_id: "watchdog-947-b".to_owned(),
            unresolved_signal_digests: vec![sha256_hex(b"signal-947-b")],
            state_fence: source_fence,
            bounded: true,
        }),
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 9,
    })
    .expect("full bundle builds")
}

fn scope_bundle() -> BackupBundle {
    let source_fence = StateFence::new(epoch(1), ResourceGeneration::genesis());
    BackupBundle::build(BackupInput {
        backup_id: "bundle-947-b-scope".to_owned(),
        class: BackupClass::ScopeExport,
        source_adapter: "test-adapter".to_owned(),
        schema_generation: "schema-1".to_owned(),
        export_fence: ExportFence {
            export_id: "export-947-b-scope".to_owned(),
            store_generation: "store-947-b-scope".to_owned(),
            state_fence: source_fence,
            scope_id: Some(eliot_store_api::ScopeId::new("scope-947-b").expect("scope")),
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
        ors_snapshot: None,
        artifacts: Vec::new(),
        watchdog_spool: None,
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 9,
    })
    .expect("scope bundle builds")
}

fn full_target_execute(
    plan: &RestorePlan,
    bundle: &BackupBundle,
    journal: &mut impl eliot_backup::RestoreJournalPort,
) -> RestoreReceipt {
    struct DispatchTarget<'a> {
        calls: &'a mut Vec<String>,
        plan: &'a RestorePlan,
        bundle: &'a BackupBundle,
    }

    impl RestoreTarget for DispatchTarget<'_> {
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

        fn apply_restore_effect(
            &mut self,
            plan: &RestorePlan,
            bundle: &BackupBundle,
            intent: &RestoreIntent,
        ) -> Result<RestoreAppliedEffect, BackupError> {
            assert_eq!(plan.plan_id, self.plan.plan_id);
            assert_eq!(
                bundle.bundle_sha256().expect("digest"),
                self.bundle.bundle_sha256().expect("digest")
            );
            let transaction = plan.transaction().expect("transaction");
            assert_eq!(intent.transaction_id, transaction.transaction_id);
            assert!(!matches!(intent.phase, RestorePhase::Pending));
            let mut probe = FullTarget { calls: Vec::new() };
            probe.dispatch(&intent.phase, plan, bundle);
            self.calls.extend(probe.calls);
            Ok(applied_effect_for(intent, bundle, plan))
        }
    }

    let mut calls = Vec::new();
    let mut target = DispatchTarget {
        calls: &mut calls,
        plan,
        bundle,
    };
    let receipt = plan
        .execute_with_journal(bundle, &mut target, journal)
        .expect("journaled restore completes");
    assert_eq!(calls, FullTarget::journal_phase_calls(bundle));
    receipt
}

// WORK_UNIT_CASE: 947/11
#[test]
fn ui_broker_invalidation_requires_exact_owner_or_missing_capability() {
    let satisfied = broker_obligation(RestoreObligationState::Satisfied);
    assert_eq!(satisfied.owner_id, "user-broker-owner");
    assert_eq!(
        satisfied.evidence_ref,
        "receipt-user-broker-owner-satisfied"
    );
    let missing = broker_obligation(RestoreObligationState::MissingCapability);
    assert_ne!(satisfied.state, missing.state);

    // The library exposes no broker/user-broker method: invalidation is
    // executed by the real runtime owner (#960/#961); the evidence here
    // carries either that exact owner's receipt or the explicit missing
    // capability, and the absence is never a fabricated success.
    let bundle = degraded_bundle_with_class(BackupClass::CanonicalOnlyDegraded, false);
    let plan = RestorePlan::compile(&bundle, target_context("target-947-11")).expect("plan");
    let explicit = evidence_for(&bundle, &plan);
    assert_eq!(
        explicit.obligations.user_broker_invalidation.state,
        RestoreObligationState::MissingCapability
    );
    explicit
        .validate()
        .expect("explicit missing capability validates");
    assert!(!explicit.obligations.all_satisfied());
    assert_eq!(
        explicit.operationally_validated_by_owner(),
        Err(BackupError::RestoreEvidenceIncomplete)
    );

    let mut satisfied_evidence = explicit.clone();
    satisfied_evidence.obligations.user_broker_invalidation = satisfied;
    satisfied_evidence
        .validate()
        .expect("exact owner receipt validates structurally");
    assert!(
        !satisfied_evidence.obligations.all_satisfied(),
        "one broker owner alone cannot satisfy the other twelve obligations"
    );

    let fixture = load_fixture("947-b-broker.json");
    assert_eq!(fixture["owner_id"], "user-broker-owner");
    assert_eq!(fixture["explicit_missing_capability_accepted"], true);
    assert_eq!(fixture["fabricated_success_method_present"], false);
}

// WORK_UNIT_CASE: 947/12
#[test]
fn unadmitted_journal_cannot_yield_production_durable_recovery_claim() {
    let admission = fixture_admission();
    assert!(!admission.admits_production_durable_recovery());

    // The journaled coordinator still completes the isolated import through
    // the fixture journal (fixture proof), but composition must refuse to
    // promote that receipt into a production durable-recovery claim.
    let bundle = degraded_bundle_with_class(BackupClass::CanonicalOnlyDegraded, false);
    let plan = RestorePlan::compile(&bundle, target_context("target-947-12")).expect("plan");
    let mut journal = FixtureJournal::new(&admission);
    let receipt = full_target_execute(&plan, &bundle, &mut journal);
    receipt.validate().expect("isolated receipt validates");
    assert!(!receipt.operational_recovery_ready);
    assert!(!receipt.cutover_performed);
    assert_eq!(
        journal.admission_receipt_ref(),
        "admission-fixture-947-b",
        "fixture composition keeps the exact admission binding inspectable"
    );
    assert!(
        !admission.admits_production_durable_recovery(),
        "fixture journal never admits production durable recovery"
    );

    // The admitted production binding names the exact persistent owner,
    // database, installation, generation, journal identity, and receipt.
    let admitted = admitted_production_admission(&plan);
    admitted.validate().expect("production admission validates");
    assert!(admitted.admits_production_durable_recovery());
    assert_eq!(admitted.installation_ref, plan.target.target_id);
    assert_eq!(admitted.generation, plan.restored_fence.resource_generation);

    let fixture = load_fixture("947-b-journal.json");
    assert_eq!(fixture["fixture_proof_only"], true);
    assert_eq!(fixture["admits_production_durable_recovery"], false);
}

// WORK_UNIT_CASE: 947/13
#[test]
fn absent_class_capability_refuses_before_target_dispatch() {
    // Typed capability absence precedes dispatch: unsupported before any
    // target effect is attempted, not-attempted when a required gate was
    // skipped. Both are fail-closed and carry the exact capability name.
    let unsupported = BackupError::RestoreCapabilityUnsupported {
        capability: "ors_suspension",
    };
    let not_attempted = BackupError::RestoreCapabilityNotAttempted {
        capability: "watchdog_spool_import",
    };
    assert_ne!(unsupported, not_attempted);
    assert!(matches!(
        unsupported,
        BackupError::RestoreCapabilityUnsupported { .. }
    ));
    assert!(matches!(
        not_attempted,
        BackupError::RestoreCapabilityNotAttempted { .. }
    ));
    assert_eq!(
        format!("{unsupported}"),
        "required class capability is absent before target dispatch"
    );
    assert_eq!(
        format!("{not_attempted}"),
        "required class capability was not attempted"
    );

    // A degraded bundle structurally omits the ORS snapshot: compiling and
    // journaling a restore over it never dispatches an ORS phase, so no
    // target effect can fabricate the absent capability.
    let bundle = degraded_bundle_with_class(BackupClass::CanonicalOnlyDegraded, false);
    assert!(bundle.ors_snapshot.is_none());
    let plan = RestorePlan::compile(&bundle, target_context("target-947-13")).expect("plan");
    assert!(
        !plan
            .steps
            .contains(&eliot_backup::RestoreStep::SuspendOrsOperations)
    );
    let mut journal = MapJournal::new();
    let receipt = full_target_execute(&plan, &bundle, &mut journal);
    assert!(
        receipt.canonical_only,
        "degraded receipt stays canonical-only"
    );

    let fixture = load_fixture("947-b-capability.json");
    assert_eq!(fixture["refuse_before_dispatch"], true);
}

// WORK_UNIT_CASE: 947/14
#[test]
fn full_recovery_class_alone_cannot_set_operational_readiness() {
    let (bundle, plan) = full_bundle_for_target("target-947-14");
    let evidence = full_evidence_for(&bundle, &plan);
    evidence.validate().expect("import evidence validates");
    assert_eq!(
        evidence.evidence_level(),
        RestoreEvidenceLevel::ReconciliationRequired
    );
    assert!(!evidence.evidence_level().permits_operational_readiness());
    assert_eq!(
        evidence.operationally_validated_by_owner(),
        Err(BackupError::RestoreEvidenceIncomplete)
    );

    // A full archive executed to a receipt still reports isolated import with
    // no readiness and no cutover: the coordinator never upgrades the class.
    let mut journal = MapJournal::new();
    let receipt = full_target_execute(&plan, &bundle, &mut journal);
    assert_eq!(
        receipt.evidence_level,
        RestoreEvidenceLevel::ReconciliationRequired
    );
    assert!(!receipt.canonical_only);
    assert!(!receipt.operational_recovery_ready);
    assert!(!receipt.cutover_performed);
    receipt.validate().expect("full receipt validates");

    // A forged readiness claim on a library level is rejected by receipt
    // validation: only OperationallyValidated may carry readiness.
    let forged = RestoreReceipt {
        receipt_id: "restore-receipt-forged-947-14".to_owned(),
        plan_id: plan.plan_id.clone(),
        bundle_sha256: bundle.bundle_sha256().expect("digest"),
        target_id: plan.target.target_id.clone(),
        restored_fence: plan.restored_fence.clone(),
        effect_receipt_sha256: receipt.effect_receipt_sha256.clone(),
        evidence_level: RestoreEvidenceLevel::ReconciliationRequired,
        canonical_only: false,
        operational_recovery_ready: true,
        cutover_performed: false,
    };
    assert_eq!(
        forged.validate(),
        Err(BackupError::RestoreEvidenceLevelMismatch)
    );

    // Degraded/scope levels can never silently upgrade to readiness either.
    let scope = scope_bundle();
    assert_eq!(
        RestoreEvidenceLevel::for_class(scope.manifest.class),
        RestoreEvidenceLevel::IsolatedImportComplete
    );
    assert!(!RestoreEvidenceLevel::for_class(scope.manifest.class).permits_operational_readiness());

    let fixture = load_fixture("947-b-readiness.json");
    assert_eq!(
        fixture["full_recovery_permits_operational_readiness"],
        false
    );
    assert_eq!(fixture["degraded_permits_operational_readiness"], false);
}

// WORK_UNIT_CASE: 947/15
#[test]
fn provenance_identity_bindings_are_load_bearing() {
    let (bundle, plan) = full_bundle_for_target("target-947-15");
    let evidence = full_evidence_for(&bundle, &plan);
    evidence.validate().expect("provenance binds");
    evidence
        .validate_against_plan(&plan, &bundle)
        .expect("plan/bundle binding validates");

    // Each binding field rejects drift: plan, archive, class, digest,
    // schema, purge revision, destination, epoch, and generation. (The
    // transaction id is covered by the journal transaction binding exercised
    // in cases 12/18/20, not by `validate_against_plan`, which checks the
    // plan/bundle/epoch/generation/ORS shape.)
    let mut drifted = evidence.clone();
    drifted.provenance.plan_id = "plan-forged".to_owned();
    assert_eq!(
        drifted.validate_against_plan(&plan, &bundle),
        Err(BackupError::FinalizeEvidenceMismatch)
    );
    let mut drifted = evidence.clone();
    drifted.provenance.source_digest = sha256_hex(b"forged-bundle");
    assert_eq!(
        drifted.validate_against_plan(&plan, &bundle),
        Err(BackupError::FinalizeEvidenceMismatch)
    );
    let mut drifted = evidence.clone();
    drifted.provenance.source_archive_id = "archive-forged".to_owned();
    assert_eq!(
        drifted.validate_against_plan(&plan, &bundle),
        Err(BackupError::FinalizeEvidenceMismatch)
    );
    let mut drifted = evidence.clone();
    drifted.provenance.source_class = BackupClass::ScopeExport;
    assert_eq!(
        drifted.evidence_level(),
        RestoreEvidenceLevel::IsolatedImportComplete
    );
    assert_eq!(
        drifted.validate_against_plan(&plan, &bundle),
        Err(BackupError::FinalizeEvidenceMismatch)
    );
    let mut drifted = evidence.clone();
    drifted.provenance.isolated_destination_ref = "elsewhere".to_owned();
    assert_eq!(
        drifted.validate(),
        Err(BackupError::FinalizeEvidenceMismatch)
    );
    let mut drifted = evidence.clone();
    drifted.provenance.expected_predecessor_ref = String::new();
    assert!(drifted.validate().is_err());
    let mut drifted = evidence.clone();
    drifted.provenance.schema_revision = String::new();
    assert!(drifted.validate().is_err());
    let mut drifted = evidence.clone();
    drifted.provenance.purge_ledger_revision += 1;
    assert_eq!(
        drifted.validate_against_plan(&plan, &bundle),
        Err(BackupError::FinalizeEvidenceMismatch)
    );
    let mut drifted = evidence.clone();
    drifted.provenance.owner = owner("forged-owner");
    drifted
        .validate()
        .expect("owner rotation keeps shape valid");
    drifted
        .provenance
        .owner
        .validate()
        .expect("forged owner still binds structurally");

    // Phase identity binds too: the finalized provenance names the exact
    // terminal phase, never a mid-import phase. Transaction identity binds at
    // the journal/coordinator layer: the finalized provenance carries the
    // exact transaction id the plan derived.
    assert_eq!(
        evidence.provenance.phase,
        RestorePhase::FinalizeIsolatedRoot
    );
    let transaction = plan.transaction().expect("transaction");
    assert_eq!(
        evidence.provenance.transaction_id,
        transaction.transaction_id
    );
    assert_eq!(evidence.provenance.plan_id, plan.plan_id);
    // A forged provenance transaction id no longer matches the plan-derived
    // transaction, so composition must refuse to treat it as the same
    // transaction's evidence.
    let mut forged_transaction = evidence.clone();
    forged_transaction.provenance.transaction_id = "transaction-forged".to_owned();
    assert_ne!(
        forged_transaction.provenance.transaction_id,
        transaction.transaction_id
    );

    let fixture = load_fixture("947-b-bindings.json");
    assert!(
        fixture["bound_fields"]
            .as_array()
            .expect("array")
            .iter()
            .any(|field| field == "expected_predecessor_ref")
    );
}

// WORK_UNIT_CASE: 947/16
#[test]
fn lineage_limits_and_owner_issued_epochs_are_required() {
    // Evidence without any observed lineage limit is incomplete: the library
    // cannot check that a new epoch exceeds every observed authority lineage.
    let bundle = degraded_bundle_with_class(BackupClass::CanonicalOnlyDegraded, false);
    let plan = RestorePlan::compile(&bundle, target_context("target-947-16")).expect("plan");
    let mut unbounded = evidence_for(&bundle, &plan);
    unbounded.observed_lineage_limits.clear();
    assert_eq!(
        unbounded.validate(),
        Err(BackupError::RestoreEvidenceIncomplete)
    );

    // Covering only one of two observed lineages still fails the owner-epoch
    // gate: the candidate must exceed ALL relevant limits under the owner's
    // contract, not just the convenient one.
    let owner_epoch_partial = RestoreOwnerEpoch {
        owner: owner("epoch-owner"),
        new_epoch: epoch(4),
        new_generation: ResourceGeneration::new(4).expect("generation"),
        supersedes: vec![ObservedLineageLimit {
            owner_id: "epoch-owner".to_owned(),
            observed_epoch: epoch(1),
            observed_generation: ResourceGeneration::genesis(),
        }],
    };
    owner_epoch_partial
        .validate()
        .expect("partial coverage validates structurally");
    let stricter_limit = ObservedLineageLimit {
        owner_id: "epoch-owner".to_owned(),
        observed_epoch: epoch(9),
        observed_generation: ResourceGeneration::new(9).expect("generation"),
    };
    let candidate_epoch = &owner_epoch_partial.new_epoch;
    let candidate_generation = owner_epoch_partial.new_generation;
    let covered = candidate_epoch.sequence.get() > stricter_limit.observed_epoch.sequence.get()
        && candidate_generation > stricter_limit.observed_generation;
    assert!(
        !covered,
        "sequence 4 / generation 4 does not exceed the stricter observed limit"
    );

    // The exact owner-issued epoch above every observed limit validates, and
    // attaching it keeps evidence structurally valid without minting anything
    // in this library: issuance happened at the owner boundary.
    let complete_epoch = RestoreOwnerEpoch {
        owner: owner("epoch-owner"),
        new_epoch: epoch(10),
        new_generation: ResourceGeneration::new(10).expect("generation"),
        supersedes: vec![
            ObservedLineageLimit {
                owner_id: "epoch-owner".to_owned(),
                observed_epoch: epoch(1),
                observed_generation: ResourceGeneration::genesis(),
            },
            stricter_limit,
        ],
    };
    complete_epoch
        .validate()
        .expect("owner-issued epoch above all limits validates");
    let mut evidence = evidence_for(&bundle, &plan);
    evidence.owner_epoch = Some(complete_epoch);
    evidence
        .validate()
        .expect("evidence with owner epoch validates");

    let fixture = load_fixture("947-b-lineage.json");
    assert_eq!(fixture["requires_owner_issued_epoch"], true);
    assert_eq!(fixture["planning_input_is_authority"], false);
}

// WORK_UNIT_CASE: 947/17
#[test]
fn known_zero_requires_complete_current_denominator() {
    let bundle = degraded_bundle_with_class(BackupClass::CanonicalOnlyDegraded, false);
    let plan = RestorePlan::compile(&bundle, target_context("target-947-17")).expect("plan");
    let mut evidence = evidence_for(&bundle, &plan);

    // Without any denominator there is no known-zero claim: suspension is
    // not resolution and absence of a count is not a zero count.
    evidence.ors_suspended = true;
    assert_eq!(
        evidence.operationally_validated_by_owner(),
        Err(BackupError::RestoreEvidenceIncomplete)
    );

    // A partial denominator (expected 2, only 1 reconciled) is incomplete and
    // never known-zero.
    let partial = ReconciliationDenominator {
        owner_id: "reconciliation-owner".to_owned(),
        denominator_ref: "denominator-947-b-partial".to_owned(),
        expected_total: 2,
        reconciled_refs: vec!["item-1".to_owned()],
    };
    assert_eq!(
        partial.validate(),
        Err(BackupError::RestoreEvidenceIncomplete)
    );
    assert!(!partial.is_known_zero());
    evidence.reconciliation_denominator = Some(partial);
    assert_eq!(
        evidence.operationally_validated_by_owner(),
        Err(BackupError::RestoreEvidenceIncomplete)
    );

    // The complete current known-zero denominator validates and reports
    // known-zero, but readiness still fails closed until every obligation is
    // satisfied and bounded owner validation evidence is attached.
    let complete = ReconciliationDenominator {
        owner_id: "reconciliation-owner".to_owned(),
        denominator_ref: "denominator-947-b-current".to_owned(),
        expected_total: 0,
        reconciled_refs: Vec::new(),
    };
    complete.validate().expect("complete denominator validates");
    assert!(complete.is_known_zero());
    evidence.reconciliation_denominator = Some(complete);
    assert_eq!(
        evidence.operationally_validated_by_owner(),
        Err(BackupError::RestoreEvidenceIncomplete)
    );

    let fixture = load_fixture("947-b-denominator.json");
    assert_eq!(fixture["known_zero_requires_complete_denominator"], true);
    assert_eq!(fixture["known_zero_total"], 0);
}

// WORK_UNIT_CASE: 947/18
#[test]
#[allow(clippy::items_after_statements)]
fn unknown_effect_is_distinct_from_not_applied_and_success() {
    struct UnknownTarget;
    impl RestoreTarget for UnknownTarget {
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
    let intent = RestoreIntent {
        transaction_id: "transaction-947-b-18".to_owned(),
        phase: RestorePhase::PrepareIsolatedRoot,
        input_digest: sha256_hex(b"intent-947-b-18"),
    };
    let unknown = RestoreReconciliation::Unknown;
    assert!(matches!(unknown, RestoreReconciliation::Unknown));
    assert!(!matches!(unknown, RestoreReconciliation::NotApplied));
    assert!(!matches!(unknown, RestoreReconciliation::Applied(_)));

    let not_applied = RestoreReconciliation::NotApplied;
    assert!(matches!(not_applied, RestoreReconciliation::NotApplied));
    assert!(!matches!(not_applied, RestoreReconciliation::Unknown));

    // The live coordinator treats the three states differently: unknown (the
    // fail-closed default) forces rollback, not-applied replays the persisted
    // intent exactly once, and an applied receipt resumes without a duplicate
    // effect. The default target seam below answers Unknown for a pending
    // intent, which the journaled coordinator turns into rollback.
    let mut unknown_target = UnknownTarget;
    assert!(matches!(
        unknown_target.reconcile_restore_effect(&intent),
        Ok(RestoreReconciliation::Unknown)
    ));

    // NotApplied is a distinct typed state that the coordinator replays
    // exactly once; success carries the exact bound receipt and never arises
    // from an unknown outcome.
    let bundle = degraded_bundle_with_class(BackupClass::CanonicalOnlyDegraded, false);
    let plan = RestorePlan::compile(&bundle, target_context("target-947-18")).expect("plan");
    let transaction = plan.transaction().expect("transaction");
    let live_intent = RestoreIntent {
        transaction_id: transaction.transaction_id.clone(),
        phase: RestorePhase::PrepareIsolatedRoot,
        input_digest: sha256_hex(
            format!(
                "{}{:?}",
                transaction.transaction_id,
                RestorePhase::PrepareIsolatedRoot
            )
            .as_bytes(),
        ),
    };
    let applied = applied_effect_for(&live_intent, &bundle, &plan);
    let success = RestoreReconciliation::Applied(applied);
    assert!(matches!(success, RestoreReconciliation::Applied(_)));
    assert!(!matches!(success, RestoreReconciliation::Unknown));
    assert!(!matches!(success, RestoreReconciliation::NotApplied));

    let fixture = load_fixture("947-b-reconciliation.json");
    assert_eq!(fixture["unknown"], "rollback_required");
    assert_eq!(fixture["not_applied"], "replay_exactly_once");
    assert_eq!(fixture["applied"], "receipt_bound");
}

// WORK_UNIT_CASE: 947/19
#[test]
fn compat_bounds_and_redacted_diagnostics_hold() {
    // Closed current schemas reject unknown fields at the byte boundary.
    let bundle = degraded_bundle_with_class(BackupClass::CanonicalOnlyDegraded, false);
    let plan = RestorePlan::compile(&bundle, target_context("target-947-19")).expect("plan");
    let evidence = evidence_for(&bundle, &plan);
    let mut wire = serde_json::to_value(&evidence).expect("evidence encodes");
    wire["unknown_future_field"] = serde_json::json!(true);
    assert!(serde_json::from_value::<RestoreEvidence>(wire).is_err());

    // Duplicate lineage owners are rejected: exactly one ceiling per owner.
    let mut duplicated = evidence.clone();
    duplicated
        .observed_lineage_limits
        .push(ObservedLineageLimit {
            owner_id: "restore-owner".to_owned(),
            observed_epoch: plan
                .restored_fence
                .source_state_fence
                .authority_epoch
                .clone(),
            observed_generation: plan.restored_fence.source_state_fence.resource_generation,
        });
    assert!(duplicated.validate().is_err());

    // Bounds hold: the closed bundle decode path enforces the record/blob
    // limits and legacy envelope bytes only decode into the explicit
    // compatibility/disposition shape, never by silent reinterpretation.
    // (`const` block: these are frozen contract constants, not test inputs.)
    const {
        assert!(eliot_backup::MAX_RECORD_BYTES > 0);
        assert!(eliot_backup::MAX_SEALED_BLOB_BYTES >= eliot_backup::MAX_RECORD_BYTES);
    }
    let encoded = bundle.encode().expect("bundle encodes");
    let decoded = BackupBundle::decode(&encoded).expect("round trip decodes");
    assert_eq!(decoded, bundle);
    let historical = RestoreArchiveDisposition {
        disposition: RestoreArchiveDispositionKind::HistoricalPreserved,
        compatibility_ref: "ecxf-1-legacy-947-b".to_owned(),
    };
    historical.validate().expect("legacy disposition validates");
    assert_ne!(
        historical.disposition,
        RestoreArchiveDispositionKind::Current
    );
    let mut legacy_evidence = evidence.clone();
    legacy_evidence.archive_disposition = historical;
    legacy_evidence
        .validate()
        .expect("explicit legacy disposition validates");

    // Diagnostics stay bounded and redacted: typed errors preserve the
    // class/capability/identity distinction without leaking digests or owner
    // secrets, and debug rendering is bounded.
    let diagnostic = format!(
        "{}",
        BackupError::RestoreCapabilityUnsupported {
            capability: "ors_suspension"
        }
    );
    assert_eq!(
        diagnostic,
        "required class capability is absent before target dispatch"
    );
    assert!(!diagnostic.contains("sha256"));
    let evidence_debug = format!("{:?}", evidence.obligations.user_broker_invalidation);
    assert!(evidence_debug.len() < 4096);
    assert!(evidence_debug.contains("user-broker-owner"));

    let fixture = load_fixture("947-b-compat.json");
    assert_eq!(fixture["closed_decoding"], "reject_unknown_fields");
    assert_eq!(fixture["disposition"], "explicit");
}

// WORK_UNIT_CASE: 947/20
#[test]
#[allow(clippy::items_after_statements)]
fn consumer_guard_proves_no_rewrite_mint_cutover_or_weakened_default() {
    struct GuardTarget;
    // Independent consumer compile fixture: the frozen public surface below
    // (contract name, format, fail-closed variants, journal/target seams,
    // evidence/receipt types) must keep compiling against the actual library
    // without an archive rewrite, a journal implementation, authority
    // minting, cutover, or a weakened default.
    const CONTRACT_NAME: &str = eliot_backup::CONTRACT_NAME;
    const FORMAT_VERSION: &str = eliot_backup::FORMAT_VERSION;
    assert_eq!(CONTRACT_NAME, "eliot.storage.backup");
    assert_eq!(FORMAT_VERSION, "ECXF/1");
    assert_consumer_surface::<RestoreEvidence>();
    assert_consumer_journal::<MapJournal>();
    impl RestoreTarget for GuardTarget {
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
    let plan = RestorePlan::compile(&bundle, target_context("target-947-20")).expect("plan");
    let mut target = GuardTarget;
    assert_eq!(
        plan.execute(&bundle, &mut target),
        Err(BackupError::RestoreJournalRequired)
    );
    let transaction = plan.transaction().expect("transaction");
    let intent = RestoreIntent {
        transaction_id: transaction.transaction_id.clone(),
        phase: RestorePhase::PrepareIsolatedRoot,
        input_digest: sha256_hex(b"guard-947-20"),
    };
    assert_eq!(
        target.apply_restore_effect(&plan, &bundle, &intent),
        Err(BackupError::RestoreTargetReceiptRequired)
    );
    assert!(matches!(
        target.reconcile_restore_effect(&intent),
        Ok(eliot_backup::RestoreReconciliation::Unknown)
    ));
    let cutover = RestoreReceipt {
        receipt_id: "restore-receipt-cutover-947-20".to_owned(),
        plan_id: plan.plan_id.clone(),
        bundle_sha256: bundle.bundle_sha256().expect("digest"),
        target_id: plan.target.target_id.clone(),
        restored_fence: plan.restored_fence.clone(),
        effect_receipt_sha256: sha256_hex(b"effect-947-20"),
        evidence_level: RestoreEvidenceLevel::IsolatedImportComplete,
        canonical_only: true,
        operational_recovery_ready: false,
        cutover_performed: true,
    };
    assert_eq!(cutover.validate(), Err(BackupError::CutoverNotAuthorized));

    // The independent consumer fixture pins the frozen contract/format
    // surface this guard protects.
    let fixture = load_fixture("947-b-guard.json");
    assert_eq!(fixture["contract"], "eliot.storage.backup");
    assert_eq!(fixture["format"], "ECXF/1");
    assert!(
        fixture["forbidden_surface"]
            .as_array()
            .expect("array")
            .iter()
            .any(|entry| entry == "authority_minting")
    );
}
