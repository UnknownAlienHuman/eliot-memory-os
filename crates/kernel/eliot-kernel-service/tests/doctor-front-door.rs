// T6-D2 Slice A (issue #461): Doctor P-07 front-door seam proofs through the
// real owner path (`AuthenticatedDoctorSession::bind` +
// `handle_doctor_repair_attempt` / `handle_doctor_repair_cancellation` /
// `reconcile_doctor_repair_delivery` over `admit_doctor_repair`).
//
// The ledger below reuses the exact fail-closed in-memory test double from
// `tests/doctor-admission.rs` (first-writer-wins, exact replay returns the
// durable row, changed terms conflict, no row is ever overwritten). It is
// test-only scaffolding, never authority. The Kernel side is a real
// `KernelService` driven to `Ready` through reconcile/activate/publish_ready,
// so session binding, live-epoch context, and activation gating are proven
// against live authority, not canned values.
//
// Proven here: one admitted automatic-safe attempt through the seam with
// lost-reply reconciliation of the same effect (no second effect, no second
// budget admission); exact duplicate returns the prior admission; changed
// target returns a typed conflict; cancellation travels through its separate
// control entry (effect attempts submitted there fail closed); diagnose-only
// envelopes classify as the read-only path without admission; binding fails
// closed without activation and on stale epoch/peer, and a foreign-lineage
// fence is rejected before any durable write.
//
// DEFERRED (follow-up slices): guarded-with-live-grant admission (blocked on
// the approval-to-activation owner contract, same as T6-D1), named effect
// adapter execution (Wave C), binary IPC dispatch (Wave D), verifier/
// Governor disposition (Wave E).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeSet, HashMap};
use std::num::NonZeroU64;
use std::sync::Mutex;

use eliot_contracts::{AuthorityEpoch, EpochId, EpochLineageId, ResourceGeneration, sha256_hex};
use eliot_doctor_core::{
    ClosedRepairRequest, ClosedRequestParams, DiagnosticBrief, EvidenceHandle, RecoveryLease,
    RegisteredOperation, RepairClass, RepairRecipe, RepairRecipeManifest, StateFence,
};
use eliot_kernel_service::{
    AuthenticatedDoctorSession, DOCTOR_REPAIR_WIRE_ID, DOCTOR_REPAIR_WIRE_VERSION,
    DoctorRecipeRegistry, DoctorRepairAttemptRequest, DoctorRepairRejectionReason,
    DoctorRepairResponse, HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot,
    HostKernelCandidateBinding, HostProcessBinding, KernelActivationPermit,
    KernelActivationReceipt, KernelControlCommand, KernelReadyReceipt, KernelService,
    KernelServiceError, KernelServiceState, ProcessObservation, RestartBudget,
    handle_doctor_repair_attempt, handle_doctor_repair_cancellation,
    is_doctor_diagnosis_only_envelope, reconcile_doctor_repair_delivery,
};
use eliot_ors::{
    DoctorAttemptAdmission, DoctorAttemptRecord, DoctorAttemptStageOutcome, DoctorAttemptState,
    DoctorBudgetLedger, DoctorEffectOutcomeReport, DoctorEffectRecord, DoctorEffectStageOutcome,
    DoctorEffectState, DoctorLedgerError, DoctorRecoveryLedger, OpaqueLabel, OperationIdentity,
};
use eliot_platform::{KernelActivationNonce, PlatformHandle};
use eliot_runtime_contracts::{
    HealthVector, RegisteredActivityWakePolicy, ServiceProcessState, SupervisionJournalEpoch,
    SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
};
use serde::de::DeserializeOwned;

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";
const EPOCH_SEQUENCE: u64 = 4;
const GENERATION: u64 = 7;
const NOW_UNIX_NANOS: u64 = 1_700_000_000_000_000_000;
const LATER_UNIX_NANOS: u64 = NOW_UNIX_NANOS + 61_000_000_000;

/// Fail-closed in-memory test ledger. Same contract as
/// `tests/doctor-admission.rs`; see the file header.
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

fn handle(value: &str) -> PlatformHandle {
    PlatformHandle::new(value).expect("valid test handle")
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

fn live_generation() -> ResourceGeneration {
    ResourceGeneration::new(GENERATION).expect("non-zero test generation")
}

/// Builds a `time` value from its tuple encoding without naming the type:
/// this crate must not grow a `time` dependency for one contour, mirroring
/// the gate itself.
fn fixture_time<T: DeserializeOwned>(value: serde_json::Value) -> T {
    serde_json::from_value(value).expect("fixture time value")
}

fn supervision_incarnation() -> SupervisionLeaseIncarnationBinding {
    SupervisionLeaseIncarnationBinding {
        supervision_lease_scope_id: "eliot-supervision-scope:v1:test".to_owned(),
        supervision_lease_id: String::new(),
        scope_ref_digest: String::new(),
        installation_id: "installation-1".to_owned(),
        host_epoch: SupervisionJournalEpoch {
            lineage_id: "host-lineage-1".to_owned(),
            sequence: 1,
        },
        activation_id: "activation-1".to_owned(),
        activation_generation: SupervisionJournalEpoch {
            lineage_id: "activation-lineage-1".to_owned(),
            sequence: 1,
        },
        kernel_generation: SupervisionJournalEpoch {
            lineage_id: "kernel-lineage-1".to_owned(),
            sequence: 1,
        },
        watchdog_epoch: SupervisionJournalEpoch {
            lineage_id: "watchdog-lineage-1".to_owned(),
            sequence: 1,
        },
        observation_scope: SupervisionObservationScope {
            targets: vec!["eliot-kernel".to_owned()],
            sensor_profile: "eliot-runtime-live-v3".to_owned(),
            claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
            governance_axis: "runtime-live-v3".to_owned(),
        },
        wake_policy: RegisteredActivityWakePolicy::Disabled,
        predecessor: None,
    }
    .with_derived_ids()
    .expect("valid test incarnation")
}

fn candidate() -> HostKernelCandidateBinding {
    HostKernelCandidateBinding {
        installation_id: handle("installation-1"),
        host_epoch: AuthorityEpoch::new(1).expect("non-zero test epoch"),
        kernel_epoch: test_epoch(EPOCH_SEQUENCE),
        activation_id: handle("activation-1"),
        artifact_hash: handle("artifact-1"),
        config_hash: handle("config-1"),
        job_object_id: handle("Local\\Eliot-Host-Kernel-test"),
        pipe_identity: handle("\\\\.\\pipe\\eliot-kernel-test"),
        host_process: HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: "C:\\eliot\\host.exe".to_owned(),
        },
        job_binding: HostJobBinding {
            job: HostJobIdentity {
                name: "Local\\Eliot-Host-Kernel-test".to_owned(),
            },
            root: HostJobRoot {
                process: HostProcessBinding {
                    process_id: 42,
                    start_time_100ns: 10,
                    image_path: "C:\\eliot\\kernel.exe".to_owned(),
                },
                executable: HostFileIdentity {
                    volume_serial_number: 1,
                    file_index: 2,
                },
            },
        },
        supervision_incarnation: supervision_incarnation(),
        restart_budget: RestartBudget::new(1, 1).expect("valid test budget"),
        agent_bridge_admission: None,
        containment_action: None,
    }
}

fn permit(candidate: &HostKernelCandidateBinding) -> KernelActivationPermit {
    KernelActivationPermit {
        operation_id: handle("activation-operation-1"),
        candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: handle("journal-transaction-1"),
        journal_sequence: 7,
        generation: live_generation(),
        authority_epoch: candidate.kernel_epoch.clone(),
        activation_nonce: KernelActivationNonce::new(handle(&"a".repeat(64)))
            .expect("valid test nonce"),
    }
}

fn ready_receipt(
    candidate: &HostKernelCandidateBinding,
    activation: &KernelActivationReceipt,
    evidence: &str,
) -> KernelReadyReceipt {
    KernelReadyReceipt {
        activation_id: candidate.activation_id.clone(),
        activation_operation_id: activation.operation_id.clone(),
        activation_nonce_digest: activation.activation_nonce_digest.clone(),
        process: ProcessObservation {
            process_id: handle("pid:42:start:10"),
            job_object_id: candidate.job_object_id.clone(),
            state: ServiceProcessState::Ready,
            health: HealthVector::healthy(),
            evidence_refs: vec![handle("process-evidence")],
        },
        health: HealthVector::healthy(),
        evidence_refs: vec![handle(evidence)],
    }
}

/// Drives a real `KernelService` to `Ready` on the test lineage/sequence and
/// generation, so the seam binds live authority.
fn ready_service() -> KernelService {
    let mut service = KernelService::new([7; 32], 2, 4).expect("test service");
    let candidate = candidate();
    let permit = permit(&candidate);
    service.reconcile(candidate.clone()).expect("reconcile");
    service.apply(KernelControlCommand::Shadow).expect("shadow");
    service
        .apply(KernelControlCommand::PrepareHandoff)
        .expect("handoff");
    let activation = service
        .activate_permit(&permit, live_generation(), "c".repeat(64))
        .expect("activation");
    service
        .publish_ready(ready_receipt(&candidate, &activation, "ready-initial"))
        .expect("ready");
    assert_eq!(service.state(), KernelServiceState::Ready);
    service
}

fn session(service: &KernelService) -> AuthenticatedDoctorSession {
    AuthenticatedDoctorSession::bind(service, "doctor-peer:test").expect("test session")
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

fn diagnose_recipe() -> RepairRecipe {
    RepairRecipe {
        recipe_id: "observe-disk".to_owned(),
        revision: 1,
        repair_class: RepairClass::DiagnoseOnly,
        allowed_effects: BTreeSet::new(),
        operations: Vec::new(),
        ..auto_recipe()
    }
}

fn registry() -> DoctorRecipeRegistry {
    DoctorRecipeRegistry::register(manifest(), vec![auto_recipe()]).expect("valid test registry")
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
    cancellation: bool,
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
        cancellation,
        escalation_target: "operator".to_owned(),
    })
    .unwrap()
}

fn effect_envelope() -> ClosedRepairRequest {
    closed_envelope(auto_recipe(), test_epoch(EPOCH_SEQUENCE), None, false)
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
fn front_door_admits_one_attempt_and_lost_reply_reconciles_same_effect() {
    let ledger = TestLedger::new();
    let registry = registry();
    let service = ready_service();
    let session = session(&service);
    // Live context comes from the service lineage, never the envelope.
    assert_eq!(session.authority_epoch(), &test_epoch(EPOCH_SEQUENCE));
    assert_eq!(session.generation(), GENERATION);

    let envelope = effect_envelope();
    let request = wire_request(&envelope, "attempt-1", &"1".repeat(64));
    let response = handle_doctor_repair_attempt(
        &ledger,
        &registry,
        &service,
        &session,
        &request,
        NOW_UNIX_NANOS,
    )
    .unwrap();
    let DoctorRepairResponse::Admitted(admission) = response else {
        panic!("front door must admit the registered attempt, got {response:?}");
    };
    admission.validate().unwrap();
    // One admitted automatic-safe reversible effect: exactly the registered
    // operation, pending independent verification (Wave E owns disposition).
    assert_eq!(admission.operation_id, "restart");
    assert!(!admission.cancelled);
    assert!(admission.effect_digest.is_some());

    // The staged row carries the live lineage and generation.
    let stored = ledger
        .load_doctor_attempt(&OperationIdentity::new(&admission.attempt_digest).unwrap())
        .unwrap()
        .unwrap();
    let lineage = stored.epoch_lineage.as_ref().unwrap();
    assert_eq!(lineage.current.lineage_id.as_str(), LINEAGE_A);
    assert_eq!(stored.generation, GENERATION);

    // Lost reply: the retained admission reconciles as the same effect
    // without admitting again — no new row, no new budget admission.
    assert!(
        reconcile_doctor_repair_delivery(&service, &session, &admission, &request, &envelope)
            .unwrap()
    );
    // ... while a different delivery never reconciles as this admission.
    let other_request = wire_request(&envelope, "attempt-9", &"1".repeat(64));
    assert!(
        !reconcile_doctor_repair_delivery(
            &service,
            &session,
            &admission,
            &other_request,
            &envelope
        )
        .unwrap()
    );
    assert_eq!(
        ledger
            .attempts
            .lock()
            .expect("test ledger is single-threaded")
            .len(),
        1
    );
    assert_eq!(
        ledger
            .load_doctor_budget(&budget_scope_key(&registry))
            .unwrap()
            .unwrap()
            .total_admissions,
        1
    );
}

#[test]
fn front_door_duplicate_returns_same_admission_without_second_effect() {
    let ledger = TestLedger::new();
    let registry = registry();
    let service = ready_service();
    let session = session(&service);
    let envelope = effect_envelope();
    let request = wire_request(&envelope, "attempt-1", &"1".repeat(64));

    let first = handle_doctor_repair_attempt(
        &ledger,
        &registry,
        &service,
        &session,
        &request,
        NOW_UNIX_NANOS,
    )
    .unwrap();
    let second = handle_doctor_repair_attempt(
        &ledger,
        &registry,
        &service,
        &session,
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
    assert_eq!(first.effect_digest, second.effect_digest);

    // One identity keeps one effect intent: no second staged effect.
    assert_eq!(
        ledger
            .effects
            .lock()
            .expect("test ledger is single-threaded")
            .len(),
        1
    );
    let budget = ledger
        .load_doctor_budget(&budget_scope_key(&registry))
        .unwrap()
        .unwrap();
    assert_eq!(budget.total_admissions, 1);
}

#[test]
fn front_door_conflict_cancel_entry_and_diagnosis_path() {
    let ledger = TestLedger::new();
    let registry = registry();
    let service = ready_service();
    let session = session(&service);
    let envelope = effect_envelope();
    let first_request = wire_request(&envelope, "attempt-1", &"1".repeat(64));
    let first = handle_doctor_repair_attempt(
        &ledger,
        &registry,
        &service,
        &session,
        &first_request,
        NOW_UNIX_NANOS,
    )
    .unwrap();
    assert!(matches!(first, DoctorRepairResponse::Admitted(_)));

    // Same attempt identity with changed row terms: typed conflict, never a
    // second admission.
    let second_request = wire_request(&envelope, "attempt-1", &"9".repeat(64));
    let conflict = handle_doctor_repair_attempt(
        &ledger,
        &registry,
        &service,
        &session,
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

    // Cancellation has its own control entry: a cancellation-flagged envelope
    // is admitted cancelled with no effect intent and no effect digest. It is
    // submitted past the recipe cooldown so the budget gate proves nothing
    // but the control separation.
    let cancel_envelope = closed_envelope(auto_recipe(), test_epoch(EPOCH_SEQUENCE), None, true);
    let cancel_request = wire_request(&cancel_envelope, "cancel-1", &"1".repeat(64));
    let cancelled = handle_doctor_repair_cancellation(
        &ledger,
        &registry,
        &service,
        &session,
        &cancel_request,
        LATER_UNIX_NANOS,
    )
    .unwrap();
    let DoctorRepairResponse::Admitted(cancelled) = cancelled else {
        panic!("cancellation entry must admit the flagged request, got {cancelled:?}");
    };
    cancelled.validate().unwrap();
    assert!(cancelled.cancelled);
    assert!(cancelled.effect_digest.is_none());
    assert!(cancelled.allowed_effects.is_empty());
    assert_eq!(
        ledger
            .effects
            .lock()
            .expect("test ledger is single-threaded")
            .len(),
        1
    );

    // ... while an effect attempt submitted to the cancellation entry fails
    // closed without admission.
    let refused = handle_doctor_repair_cancellation(
        &ledger,
        &registry,
        &service,
        &session,
        &first_request,
        NOW_UNIX_NANOS,
    );
    assert!(matches!(
        refused,
        Err(KernelServiceError::InvalidField { .. })
    ));

    // Read-only diagnosis path: a diagnose-only envelope classifies without
    // admission, while the effect envelope does not.
    let diagnose_envelope = ClosedRepairRequest::diagnose(ClosedRequestParams {
        request_id: "job-diagnose".to_owned(),
        brief: brief(),
        recipe: diagnose_recipe(),
        operations: Vec::new(),
        fence: StateFence::new(test_epoch(EPOCH_SEQUENCE), GENERATION, "b".repeat(64)).unwrap(),
        lease: lease(),
        approval: None,
        budget_units: 1,
        deadline: fixture_time(serde_json::json!([2030, 1, 0, 0, 0, 0, 0, 0, 0])),
        cancellation: false,
        escalation_target: "operator".to_owned(),
    })
    .unwrap();
    assert!(is_doctor_diagnosis_only_envelope(&diagnose_envelope));
    assert!(!is_doctor_diagnosis_only_envelope(&envelope));
}

#[test]
fn front_door_fails_closed_without_activation_and_on_stale_authority() {
    // No activation, no session: a Cold service binds nothing.
    let cold = KernelService::new([9; 32], 2, 4).expect("test service");
    assert_eq!(cold.state(), KernelServiceState::Cold);
    assert!(AuthenticatedDoctorSession::bind(&cold, "doctor-peer:test").is_err());

    // No peer, no session: a blank principal binds nothing on a Ready service.
    let service = ready_service();
    assert!(AuthenticatedDoctorSession::bind(&service, "   ").is_err());

    // Stale epoch, no protected input: a foreign-lineage fence is rejected
    // before any durable write, through the seam.
    let ledger = TestLedger::new();
    let registry = registry();
    let session = session(&service);
    let envelope = closed_envelope(auto_recipe(), foreign_epoch(), None, false);
    let request = wire_request(&envelope, "attempt-1", &"1".repeat(64));
    let response = handle_doctor_repair_attempt(
        &ledger,
        &registry,
        &service,
        &session,
        &request,
        NOW_UNIX_NANOS,
    )
    .unwrap();
    let DoctorRepairResponse::Rejected(rejection) = response else {
        panic!("foreign lineage must be rejected, got {response:?}");
    };
    assert_eq!(rejection.reason, DoctorRepairRejectionReason::StaleEpoch);
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

    // Unknown wire, no admission: the seam enforces the exact wire pair.
    let envelope = effect_envelope();
    let mut request = wire_request(&envelope, "attempt-2", &"1".repeat(64));
    request.wire_id = "eliot.kernel.unknown".to_owned();
    request = request.with_computed_digest().unwrap();
    let response = handle_doctor_repair_attempt(
        &ledger,
        &registry,
        &service,
        &session,
        &request,
        NOW_UNIX_NANOS,
    )
    .unwrap();
    let DoctorRepairResponse::Rejected(rejection) = response else {
        panic!("unknown wire must be rejected, got {response:?}");
    };
    assert_eq!(
        rejection.reason,
        DoctorRepairRejectionReason::UnknownWireVersion
    );
}
