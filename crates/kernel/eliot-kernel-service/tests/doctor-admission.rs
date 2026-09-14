// T6-D1 (issue #461): Doctor admission cutover proofs through the real
// owner path (`admit_doctor_repair` + `reconcile_doctor_repair_admission`).
//
// The ledger below is a fail-closed in-memory test double implementing the
// exact `DoctorRecoveryLedger` first-writer-wins contract from its trait
// docs (exact replay returns the durable row, changed terms conflict, no
// row is ever overwritten, admission evidence binds once). It is test-only
// scaffolding: it is never promoted to authority, and the durable redb
// implementation lands with Wave E.
//
// Proven here: accepted automatic-safe admission, exact-duplicate replay
// without a second effect, changed-target conflict under one identity,
// foreign-lineage fence rejection before any effect, and fail-closed
// guarded refusals (missing approval vs. present-but-unactivated).
//
// Dimension note the tests pin down: recipe and approval *values* are part
// of the Slice 1 attempt identity, so changing them mints a different
// identity (a fresh admission under a new key), while non-identity row
// dimensions (target envelope, principal, lease, evidence, exact request
// bytes) keep the identity and surface as typed `Conflict` with named
// changed fields. Both halves are the same anti-substitution rule.
//
// DEFERRED (exhaustive matrix, follow-up slices): guarded-with-live-grant
// admission (blocked on the approval-to-activation owner contract),
// multi-effect recipes, crash-between-writes recovery, verifier axes,
// cooldown/budget-exhaustion sequences.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::Mutex;

use eliot_contracts::{EpochId, EpochLineageId, sha256_hex};
use eliot_doctor_core::{
    ClosedRepairRequest, ClosedRequestParams, DiagnosticBrief, EvidenceHandle, RecoveryLease,
    RegisteredOperation, RepairClass, RepairRecipe, RepairRecipeManifest, StateFence,
};
use eliot_kernel_service::{
    DOCTOR_REPAIR_WIRE_ID, DOCTOR_REPAIR_WIRE_VERSION, DoctorAdmissionContext,
    DoctorRecipeRegistry, DoctorRepairAttemptRequest, DoctorRepairRejectionReason,
    DoctorRepairResponse, KernelServiceState, admit_doctor_repair,
    reconcile_doctor_repair_admission,
};
use eliot_ors::{
    DoctorAttemptAdmission, DoctorAttemptRecord, DoctorAttemptStageOutcome, DoctorAttemptState,
    DoctorBudgetLedger, DoctorEffectOutcomeReport, DoctorEffectRecord, DoctorEffectStageOutcome,
    DoctorEffectState, DoctorLedgerError, DoctorRecoveryLedger, OpaqueLabel, OperationIdentity,
};
use serde::de::DeserializeOwned;

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";
const EPOCH_SEQUENCE: u64 = 4;
const GENERATION: u64 = 7;
const NOW_UNIX_NANOS: u64 = 1_700_000_000_000_000_000;

/// Fail-closed in-memory test ledger. Implements the documented
/// first-writer-wins contract and nothing else; see the file header.
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

fn foreign_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_B).expect("valid test lineage"),
        NonZeroU64::new(EPOCH_SEQUENCE).expect("non-zero test sequence"),
    )
    .expect("valid test epoch")
}

/// Builds a `time` value from its tuple encoding without naming the type:
/// this crate must not grow a `time` dependency for one contour, mirroring
/// the gate itself. The encoding is fixed while `serde-human-readable`
/// stays disabled for the `time` build (see D1 report).
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

fn registry() -> DoctorRecipeRegistry {
    DoctorRecipeRegistry::register(manifest(), vec![auto_recipe(), guarded_recipe()])
        .expect("valid test registry")
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

fn closed_envelope(
    recipe: RepairRecipe,
    epoch: EpochId,
    approval: Option<String>,
) -> ClosedRepairRequest {
    let manifest = manifest();
    let operation = manifest.resolve("restart").unwrap();
    ClosedRepairRequest::for_effect(ClosedRequestParams {
        request_id: "job-1".to_owned(),
        brief: brief(),
        recipe,
        operations: vec![operation],
        fence: StateFence::new(epoch, GENERATION, "b".repeat(64)).unwrap(),
        lease: lease(),
        approval,
        budget_units: 1,
        deadline: fixture_time(serde_json::json!([2030, 1, 0, 0, 0, 0, 0, 0, 0])),
        cancellation: false,
        escalation_target: "operator".to_owned(),
    })
    .unwrap()
}

fn wire_request(
    envelope: &ClosedRepairRequest,
    attempt_id: &str,
    target_resource_digest: &str,
) -> DoctorRepairAttemptRequest {
    DoctorRepairAttemptRequest {
        wire_id: DOCTOR_REPAIR_WIRE_ID.to_owned(),
        wire_version: DOCTOR_REPAIR_WIRE_VERSION,
        attempt_id: attempt_id.to_owned(),
        effect_seq: 0,
        closed_request_json: serde_json::to_string(envelope).unwrap(),
        target_resource_digest: target_resource_digest.to_owned(),
        request_digest: String::new(),
    }
    .with_computed_digest()
    .unwrap()
}

fn budget_scope_key(registry: &DoctorRecipeRegistry) -> OpaqueLabel {
    let (_, identity) = registry.resolve_recipe("restart-disk", 3).unwrap();
    OpaqueLabel::new(sha256_hex(
        format!("disk-0::{}", identity.digest()).as_bytes(),
    ))
    .unwrap()
}

#[test]
fn automatic_safe_attempt_is_admitted_on_the_live_epoch() {
    let ledger = TestLedger::new();
    let registry = registry();
    let context = context();
    let envelope = closed_envelope(auto_recipe(), test_epoch(EPOCH_SEQUENCE), None);
    let request = wire_request(&envelope, "attempt-1", &"1".repeat(64));

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
        panic!("automatic-safe attempt must be admitted, got {response:?}");
    };
    admission.validate().unwrap();

    // The staged row carries the live lineage, never `None`, with the `u64`
    // column as the sequence projection only.
    let stored = ledger
        .load_doctor_attempt(&OperationIdentity::new(&admission.attempt_digest).unwrap())
        .unwrap()
        .unwrap();
    let lineage = stored.epoch_lineage.as_ref().unwrap();
    assert_eq!(lineage.current.lineage_id.as_str(), LINEAGE_A);
    assert_eq!(lineage.current.epoch, EPOCH_SEQUENCE);
    assert_eq!(stored.authority_epoch, EPOCH_SEQUENCE);
    assert_eq!(stored.generation, GENERATION);

    // The retained admission reconciles against the live authority.
    assert!(
        reconcile_doctor_repair_admission(
            &admission,
            &request,
            &envelope,
            &test_epoch(EPOCH_SEQUENCE)
        )
        .unwrap()
    );
    // ... and never against a foreign lineage at the same sequence.
    assert!(
        !reconcile_doctor_repair_admission(&admission, &request, &envelope, &foreign_epoch())
            .unwrap_or(false)
    );
}

#[test]
fn exact_duplicate_returns_the_prior_admission_without_a_second_effect() {
    let ledger = TestLedger::new();
    let registry = registry();
    let context = context();
    let envelope = closed_envelope(auto_recipe(), test_epoch(EPOCH_SEQUENCE), None);
    let request = wire_request(&envelope, "attempt-1", &"1".repeat(64));

    let first = admit_doctor_repair(
        &ledger,
        &registry,
        &context,
        "test-principal",
        &request,
        NOW_UNIX_NANOS,
    )
    .unwrap();
    let second = admit_doctor_repair(
        &ledger,
        &registry,
        &context,
        "test-principal",
        &request,
        NOW_UNIX_NANOS,
    )
    .unwrap();
    let (DoctorRepairResponse::Admitted(first), DoctorRepairResponse::Admitted(second)) =
        (first, second)
    else {
        panic!("exact replay must rebuild the same admission");
    };
    assert_eq!(first.admission_digest, second.admission_digest);
    assert_eq!(first.attempt_digest, second.attempt_digest);

    // The replay consumed no second budget admission.
    let budget = ledger
        .load_doctor_budget(&budget_scope_key(&registry))
        .unwrap()
        .unwrap();
    assert_eq!(budget.total_admissions, 1);
}

#[test]
fn changed_target_returns_typed_identity_conflict() {
    let ledger = TestLedger::new();
    let registry = registry();
    let context = context();
    let envelope = closed_envelope(auto_recipe(), test_epoch(EPOCH_SEQUENCE), None);
    let first_request = wire_request(&envelope, "attempt-1", &"1".repeat(64));
    let first = admit_doctor_repair(
        &ledger,
        &registry,
        &context,
        "test-principal",
        &first_request,
        NOW_UNIX_NANOS,
    )
    .unwrap();
    assert!(matches!(first, DoctorRepairResponse::Admitted(_)));

    // Same attempt identity (the target envelope is not an identity input)
    // with changed row terms: typed conflict, never a second admission.
    let second_request = wire_request(&envelope, "attempt-1", &"9".repeat(64));
    let conflict = admit_doctor_repair(
        &ledger,
        &registry,
        &context,
        "test-principal",
        &second_request,
        NOW_UNIX_NANOS,
    )
    .unwrap();
    let DoctorRepairResponse::Conflict(conflict) = conflict else {
        panic!("changed target must conflict, got {conflict:?}");
    };
    conflict.validate().unwrap();
    assert!(
        conflict
            .changed_fields
            .contains(&"target_resource_digest".to_owned())
    );
    // One identity, two presentations: the binding digest is shared while
    // the row terms differ.
    assert_eq!(conflict.expected_digest, conflict.observed_digest);
}

#[test]
fn foreign_lineage_fence_is_rejected_before_any_effect() {
    let ledger = TestLedger::new();
    let registry = registry();
    let context = context();
    let envelope = closed_envelope(auto_recipe(), foreign_epoch(), None);
    let request = wire_request(&envelope, "attempt-1", &"1".repeat(64));

    let response = admit_doctor_repair(
        &ledger,
        &registry,
        &context,
        "test-principal",
        &request,
        NOW_UNIX_NANOS,
    )
    .unwrap();
    let DoctorRepairResponse::Rejected(rejection) = response else {
        panic!("foreign lineage must be rejected, got {response:?}");
    };
    assert_eq!(rejection.reason, DoctorRepairRejectionReason::StaleEpoch);

    // Before any effect means before any durable write: no attempt row and
    // no budget row exist.
    assert!(
        ledger
            .attempts
            .lock()
            .expect("test ledger is single-threaded")
            .is_empty()
    );
    assert!(
        ledger
            .budgets
            .lock()
            .expect("test ledger is single-threaded")
            .is_empty()
    );
}

#[test]
fn guarded_attempts_fail_closed_without_a_live_activation() {
    let ledger = TestLedger::new();
    let registry = registry();
    let context = context();

    // A present approval with no published approval-to-activation contract
    // authorizes nothing: typed fail-closed rejection, no admission.
    let envelope = closed_envelope(
        guarded_recipe(),
        test_epoch(EPOCH_SEQUENCE),
        Some("op-approval-1".to_owned()),
    );
    let request = wire_request(&envelope, "guarded-1", &"1".repeat(64));
    let response = admit_doctor_repair(
        &ledger,
        &registry,
        &context,
        "test-principal",
        &request,
        NOW_UNIX_NANOS,
    )
    .unwrap();
    let DoctorRepairResponse::Rejected(rejection) = response else {
        panic!("guarded approval without activation must fail closed, got {response:?}");
    };
    assert_eq!(
        rejection.reason,
        DoctorRepairRejectionReason::ApprovalNotActivated
    );

    // A missing approval keeps its distinct typed refusal.
    let envelope = closed_envelope(guarded_recipe(), test_epoch(EPOCH_SEQUENCE), None);
    let request = wire_request(&envelope, "guarded-2", &"1".repeat(64));
    let response = admit_doctor_repair(
        &ledger,
        &registry,
        &context,
        "test-principal",
        &request,
        NOW_UNIX_NANOS,
    )
    .unwrap();
    let DoctorRepairResponse::Rejected(rejection) = response else {
        panic!("guarded attempt without approval must be refused, got {response:?}");
    };
    assert_eq!(
        rejection.reason,
        DoctorRepairRejectionReason::ApprovalRequired
    );
}
