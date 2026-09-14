// DISPATCH-A (issue #461): Kernel-service production one-shot registry proofs.
//
// The bins composition supplies the exact manifest revision and the one
// automatic-safe recipe; `DoctorRecipeRegistry::production_one_shot`
// validates both through the unchanged `register` path and additionally
// requires the single recipe to be `RepairClass::AutomaticSafe`. No recipe,
// manifest, or provenance value is minted here.
//
// The ledger below is the same fail-closed in-memory test double used by
// the existing doctor tests: it implements the exact
// `DoctorRecoveryLedger` first-writer-wins contract from its trait docs
// (exact replay returns the durable row, changed terms conflict, no row is
// ever overwritten). `eliot-ors` ships no reusable in-memory ledger, so
// this file reuses the existing doctor-test ledger shape instead of
// inventing a new ledger type. Test-only scaffolding, never authority.
//
// Proven here: the production constructor builds the exact same closed
// registry the one-shot tests use (same manifest digest, same bound recipe
// identity), non-automatic-safe recipes fail typed, unknown recipes
// resolve to `None` without panic, one attempt admits through the real
// gate on the production registry, and admission still requires `Ready`
// plus a live epoch/generation context.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::Mutex;

use eliot_contracts::{EpochId, EpochLineageId};
use eliot_doctor_core::{
    ClosedRepairRequest, ClosedRequestParams, DiagnosticBrief, EvidenceHandle, RecoveryLease,
    RegisteredOperation, RepairClass, RepairRecipe, RepairRecipeManifest, StateFence,
};
use eliot_kernel_service::{
    DOCTOR_REPAIR_WIRE_ID, DOCTOR_REPAIR_WIRE_VERSION, DoctorAdmissionContext,
    DoctorRecipeRegistry, DoctorRegistryError, DoctorRepairAttemptRequest, DoctorRepairResponse,
    KernelServiceError, KernelServiceState, admit_doctor_repair,
};
use eliot_ors::{
    DoctorAttemptAdmission, DoctorAttemptRecord, DoctorAttemptStageOutcome, DoctorAttemptState,
    DoctorBudgetLedger, DoctorEffectOutcomeReport, DoctorEffectRecord, DoctorEffectStageOutcome,
    DoctorEffectState, DoctorLedgerError, DoctorRecoveryLedger, OpaqueLabel, OperationIdentity,
};
use serde::de::DeserializeOwned;

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const EPOCH_SEQUENCE: u64 = 4;
const GENERATION: u64 = 7;
const NOW_UNIX_NANOS: u64 = 1_700_000_000_000_000_000;

/// Fail-closed in-memory test ledger. Same shape and contract as the ledger
/// in the existing doctor tests; see the file header.
struct TestLedger {
    attempts: Mutex<HashMap<String, DoctorAttemptRecord>>,
    effects: Mutex<HashMap<String, DoctorEffectRecord>>,
    budgets: Mutex<HashMap<String, DoctorBudgetLedger>>,
}

impl TestLedger {
    fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            effects: Mutex::new(HashMap::new()),
            budgets: Mutex::new(HashMap::new()),
        }
    }
}

impl DoctorRecoveryLedger for TestLedger {
    fn stage_doctor_attempt(
        &self,
        record: &DoctorAttemptRecord,
    ) -> Result<DoctorAttemptStageOutcome, DoctorLedgerError> {
        let storage = |reason: String| DoctorLedgerError::Storage(reason);
        record
            .validate()
            .map_err(|error| storage(error.to_string()))?;
        let mut attempts = self
            .attempts
            .lock()
            .expect("test ledger is single-threaded");
        let key = record.record_key();
        if let Some(durable) = attempts.get(&key) {
            if durable.same_binding(record) {
                return Ok(DoctorAttemptStageOutcome::Existing(durable.clone()));
            }
            return Err(DoctorLedgerError::AttemptIdentityConflict {
                attempt_digest: key,
            });
        }
        attempts.insert(key, record.clone());
        Ok(DoctorAttemptStageOutcome::Stored(record.clone()))
    }

    fn load_doctor_attempt(
        &self,
        attempt_digest: &OperationIdentity,
    ) -> Result<Option<DoctorAttemptRecord>, DoctorLedgerError> {
        let attempts = self
            .attempts
            .lock()
            .expect("test ledger is single-threaded");
        Ok(attempts.get(attempt_digest.as_str()).cloned())
    }

    fn advance_doctor_attempt(
        &self,
        attempt_digest: &OperationIdentity,
        target: DoctorAttemptState,
        admission: Option<&DoctorAttemptAdmission>,
    ) -> Result<Option<DoctorAttemptRecord>, DoctorLedgerError> {
        let storage = |reason: String| DoctorLedgerError::Storage(reason);
        let mut attempts = self
            .attempts
            .lock()
            .expect("test ledger is single-threaded");
        let Some(current) = attempts.get_mut(attempt_digest.as_str()) else {
            return Ok(None);
        };
        if current.state == target {
            let replayed = match (
                &current.admission_digest,
                current.admitted_at_unix_nanos,
                admission,
            ) {
                (Some(digest), Some(at), Some(evidence)) => {
                    evidence.admission_digest == *digest && evidence.admitted_at_unix_nanos == at
                }
                (None, None, None) => true,
                _ => false,
            };
            if !replayed {
                return Err(DoctorLedgerError::AttemptIdentityConflict {
                    attempt_digest: attempt_digest.as_str().to_owned(),
                });
            }
            return Ok(Some(current.clone()));
        }
        let from = current.state;
        from.transition_to(target)
            .map_err(|error| storage(error.to_string()))?;
        match (from, target) {
            (
                DoctorAttemptState::Requested,
                DoctorAttemptState::Admitted | DoctorAttemptState::Cancelled,
            ) => {
                let evidence = admission
                    .ok_or_else(|| storage("admission evidence is required".to_owned()))?;
                evidence
                    .validate()
                    .map_err(|error| storage(error.to_string()))?;
                current.admission_digest = Some(evidence.admission_digest.clone());
                current.admitted_at_unix_nanos = Some(evidence.admitted_at_unix_nanos);
            }
            (DoctorAttemptState::Requested, DoctorAttemptState::Expired) => {
                if admission.is_some() {
                    return Err(storage("an expired intent carries no admission".to_owned()));
                }
            }
            _ => {
                if admission.is_some() {
                    return Err(storage(
                        "admission evidence binds only on first admission".to_owned(),
                    ));
                }
            }
        }
        current.state = target;
        current
            .validate()
            .map_err(|error| storage(error.to_string()))?;
        Ok(Some(current.clone()))
    }

    fn stage_doctor_effect(
        &self,
        record: &DoctorEffectRecord,
    ) -> Result<DoctorEffectStageOutcome, DoctorLedgerError> {
        let storage = |reason: String| DoctorLedgerError::Storage(reason);
        record
            .validate()
            .map_err(|error| storage(error.to_string()))?;
        let mut effects = self.effects.lock().expect("test ledger is single-threaded");
        let key = record.record_key();
        if let Some(durable) = effects.get(&key) {
            if durable.same_binding(record) {
                return Ok(DoctorEffectStageOutcome::Existing(durable.clone()));
            }
            return Err(DoctorLedgerError::EffectIdentityConflict { effect_digest: key });
        }
        effects.insert(key, record.clone());
        Ok(DoctorEffectStageOutcome::Stored(record.clone()))
    }

    fn load_doctor_effect(
        &self,
        effect_digest: &OperationIdentity,
    ) -> Result<Option<DoctorEffectRecord>, DoctorLedgerError> {
        let effects = self.effects.lock().expect("test ledger is single-threaded");
        Ok(effects.get(effect_digest.as_str()).cloned())
    }

    fn record_doctor_effect_outcome(
        &self,
        effect_digest: &OperationIdentity,
        report: &DoctorEffectOutcomeReport,
    ) -> Result<Option<DoctorEffectRecord>, DoctorLedgerError> {
        let storage = |reason: String| DoctorLedgerError::Storage(reason);
        report
            .validate()
            .map_err(|error| storage(error.to_string()))?;
        let mut effects = self.effects.lock().expect("test ledger is single-threaded");
        let Some(current) = effects.get_mut(effect_digest.as_str()) else {
            return Ok(None);
        };
        if report.unknown {
            match current.state {
                DoctorEffectState::Intended => {
                    current.state = DoctorEffectState::Unknown;
                    current.reconciliation_key = Some(current.effect_digest.as_str().to_owned());
                }
                DoctorEffectState::Unknown | DoctorEffectState::Reconciling => {}
                DoctorEffectState::Reported => {
                    return Err(DoctorLedgerError::EffectIdentityConflict {
                        effect_digest: effect_digest.as_str().to_owned(),
                    });
                }
            }
        } else {
            let outcome = report
                .outcome_digest
                .clone()
                .ok_or_else(|| storage("a known outcome carries its exact digest".to_owned()))?;
            match current.state {
                DoctorEffectState::Intended
                | DoctorEffectState::Unknown
                | DoctorEffectState::Reconciling => {
                    current.state = DoctorEffectState::Reported;
                    current.outcome_digest = Some(outcome);
                    current
                        .adapter_receipt_digest
                        .clone_from(&report.adapter_receipt_digest);
                    current.reconciliation_key = None;
                }
                DoctorEffectState::Reported => {
                    if current.outcome_digest.as_deref() != Some(outcome.as_str()) {
                        return Err(DoctorLedgerError::EffectIdentityConflict {
                            effect_digest: effect_digest.as_str().to_owned(),
                        });
                    }
                }
            }
        }
        current
            .validate()
            .map_err(|error| storage(error.to_string()))?;
        Ok(Some(current.clone()))
    }

    fn load_doctor_budget(
        &self,
        scope_key: &OpaqueLabel,
    ) -> Result<Option<DoctorBudgetLedger>, DoctorLedgerError> {
        let budgets = self.budgets.lock().expect("test ledger is single-threaded");
        Ok(budgets.get(scope_key.as_str()).cloned())
    }

    fn store_doctor_budget(&self, ledger: &DoctorBudgetLedger) -> Result<(), DoctorLedgerError> {
        ledger
            .validate()
            .map_err(|error| DoctorLedgerError::Storage(error.to_string()))?;
        let mut budgets = self.budgets.lock().expect("test ledger is single-threaded");
        budgets.insert(ledger.record_key(), ledger.clone());
        Ok(())
    }
}

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_A).expect("valid test lineage"),
        NonZeroU64::new(sequence).expect("non-zero test sequence"),
    )
    .expect("valid test epoch")
}

/// Builds a `time` value from its tuple encoding without naming the type:
/// this crate must not grow a `time` dependency for one contour, mirroring
/// the gate itself.
fn fixture_time<T: DeserializeOwned>(value: serde_json::Value) -> T {
    serde_json::from_value(value).expect("fixture time value")
}

fn manifest() -> RepairRecipeManifest {
    RepairRecipeManifest {
        manifest_id: "manifest".to_owned(),
        manifest_revision: 1,
        operations: vec![RegisteredOperation {
            operation_id: "restart".to_owned(),
            adapter_id: "adapter".to_owned(),
            description: "restart the component".to_owned(),
            definition_digest: "c".repeat(64),
        }],
    }
}

fn auto_recipe() -> RepairRecipe {
    RepairRecipe {
        recipe_id: "restart-disk".to_owned(),
        revision: 3,
        problem_classes: ["disk-failure".to_owned()].into_iter().collect(),
        components: ["disk-0".to_owned()].into_iter().collect(),
        repair_class: RepairClass::AutomaticSafe,
        prerequisites: vec!["precondition".to_owned()],
        required_authority: "kernel.recovery".to_owned(),
        allowed_effects: ["restart".to_owned()].into_iter().collect(),
        operations: vec!["restart".to_owned()],
        expected_observables: vec!["healthy".to_owned()],
        verification_contract: vec!["verify".to_owned()],
        rollback_or_compensation: vec!["rollback".to_owned()],
        attempt_budget: 8,
        cooldown: fixture_time(serde_json::json!([30, 0])),
        stop_conditions: vec!["stop".to_owned()],
    }
}

fn guarded_recipe() -> RepairRecipe {
    RepairRecipe {
        recipe_id: "rebuild-index".to_owned(),
        revision: 1,
        repair_class: RepairClass::Guarded,
        ..auto_recipe()
    }
}

fn diagnose_recipe() -> RepairRecipe {
    RepairRecipe {
        recipe_id: "observe-disk".to_owned(),
        revision: 1,
        repair_class: RepairClass::DiagnoseOnly,
        allowed_effects: std::collections::BTreeSet::new(),
        operations: Vec::new(),
        ..auto_recipe()
    }
}

fn production_registry() -> DoctorRecipeRegistry {
    DoctorRecipeRegistry::production_one_shot(manifest(), auto_recipe())
        .expect("valid production one-shot registry")
}

fn context() -> DoctorAdmissionContext {
    DoctorAdmissionContext::new(
        KernelServiceState::Ready,
        test_epoch(EPOCH_SEQUENCE),
        GENERATION,
    )
    .expect("valid test context")
}

fn brief() -> DiagnosticBrief {
    DiagnosticBrief {
        problem_id: "problem-1".to_owned(),
        component: "disk-0".to_owned(),
        failure_class: "disk-failure".to_owned(),
        symptom: "symptom".to_owned(),
        impact: "impact".to_owned(),
        evidence: vec![EvidenceHandle::new("ev-1", "a".repeat(64)).unwrap()],
        unknowns: Vec::new(),
    }
}

fn lease() -> RecoveryLease {
    RecoveryLease {
        lease_id: "lease-1".to_owned(),
        owner: "kernel".to_owned(),
        expires_at: fixture_time(serde_json::json!([2030, 1, 0, 0, 0, 0, 0, 0, 0])),
        allowed_effects: ["restart".to_owned()].into_iter().collect(),
    }
}

fn closed_envelope(recipe: RepairRecipe, epoch: EpochId) -> ClosedRepairRequest {
    let manifest = manifest();
    let operation = manifest.resolve("restart").unwrap();
    ClosedRepairRequest::for_effect(ClosedRequestParams {
        request_id: "job-1".to_owned(),
        brief: brief(),
        recipe,
        operations: vec![operation],
        fence: StateFence::new(epoch, GENERATION, "b".repeat(64)).unwrap(),
        lease: lease(),
        approval: None,
        budget_units: 1,
        deadline: fixture_time(serde_json::json!([2030, 1, 0, 0, 0, 0, 0, 0, 0])),
        cancellation: false,
        escalation_target: "operator".to_owned(),
    })
    .unwrap()
}

fn wire_request(envelope: &ClosedRepairRequest, attempt_id: &str) -> DoctorRepairAttemptRequest {
    DoctorRepairAttemptRequest {
        wire_id: DOCTOR_REPAIR_WIRE_ID.to_owned(),
        wire_version: DOCTOR_REPAIR_WIRE_VERSION,
        attempt_id: attempt_id.to_owned(),
        effect_seq: 0,
        closed_request_json: serde_json::to_string(envelope).unwrap(),
        target_resource_digest: "1".repeat(64),
        request_digest: String::new(),
    }
    .with_computed_digest()
    .unwrap()
}

#[test]
fn production_one_shot_builds_the_single_automatic_safe_registry() {
    let registry = production_registry();
    assert_eq!(registry.recipe_count(), 1);
    assert_eq!(registry.manifest().manifest_revision, 1);

    // The production constructor builds the exact same closed registry the
    // one-shot tests register directly: same manifest digest, same bound
    // recipe identity.
    let via_register = DoctorRecipeRegistry::register(manifest(), vec![auto_recipe()])
        .expect("valid test registry");
    assert_eq!(registry.manifest_digest(), via_register.manifest_digest());
    let (_, identity) = registry.resolve_recipe("restart-disk", 3).unwrap();
    let (_, expected) = via_register.resolve_recipe("restart-disk", 3).unwrap();
    assert_eq!(identity.digest(), expected.digest());
}

#[test]
fn production_one_shot_rejects_non_automatic_safe_recipes_typed() {
    let guarded = DoctorRecipeRegistry::production_one_shot(manifest(), guarded_recipe());
    assert!(matches!(
        guarded,
        Err(DoctorRegistryError::NotAutomaticSafe)
    ));

    let diagnose = DoctorRecipeRegistry::production_one_shot(manifest(), diagnose_recipe());
    assert!(matches!(
        diagnose,
        Err(DoctorRegistryError::NotAutomaticSafe)
    ));
}

#[test]
fn unknown_recipe_resolves_to_none_without_panic() {
    let registry = production_registry();
    assert!(registry.resolve_recipe("no-such-recipe", 1).is_none());
    assert!(registry.resolve_recipe("restart-disk", 99).is_none());
}

#[test]
fn production_registry_admits_one_attempt_through_the_real_gate() {
    let ledger = TestLedger::new();
    let registry = production_registry();
    let context = context();
    let envelope = closed_envelope(auto_recipe(), test_epoch(EPOCH_SEQUENCE));
    let request = wire_request(&envelope, "attempt-1");

    let response = admit_doctor_repair(
        &ledger,
        &registry,
        &context,
        "test-principal",
        &request,
        NOW_UNIX_NANOS,
    )
    .unwrap();
    let DoctorRepairResponse::Admitted(admission) = response else {
        panic!("production one-shot attempt must be admitted, got {response:?}");
    };
    admission.validate().unwrap();
    assert_eq!(admission.operation_id, "restart");
    assert_eq!(admission.manifest_digest, registry.manifest_digest());
}

#[test]
fn admission_still_requires_ready_context_with_live_epoch() {
    // The context carries live authority, never envelope bytes: Ready plus
    // the live epoch and generation.
    let context = context();
    assert_eq!(context.service_state, KernelServiceState::Ready);
    assert_eq!(context.authority_epoch, test_epoch(EPOCH_SEQUENCE));
    assert_eq!(context.generation, GENERATION);
    // A zero generation binds no authority.
    assert!(
        DoctorAdmissionContext::new(KernelServiceState::Ready, test_epoch(EPOCH_SEQUENCE), 0)
            .is_err()
    );

    // A non-Ready service admits nothing through the production registry.
    let ledger = TestLedger::new();
    let registry = production_registry();
    let draining = DoctorAdmissionContext::new(
        KernelServiceState::Draining,
        test_epoch(EPOCH_SEQUENCE),
        GENERATION,
    )
    .expect("draining context builds");
    let envelope = closed_envelope(auto_recipe(), test_epoch(EPOCH_SEQUENCE));
    let request = wire_request(&envelope, "attempt-1");
    let error = admit_doctor_repair(
        &ledger,
        &registry,
        &draining,
        "test-principal",
        &request,
        NOW_UNIX_NANOS,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        KernelServiceError::AdmissionClosed(KernelServiceState::Draining)
    ));
}
