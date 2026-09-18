//! T2-S06 Slice A: Doctor second consumer through the production seam.
//!
//! The composition, advertisement, gate-key, and fail-closed proofs are
//! portable; only the closing drive spawns a real child and is
//! Windows-gated. The REAL Kernel admission gate
//! ([`admit_doctor_repair`][eliot_kernel_service::admit_doctor_repair])
//! mints the admission over a REAL production one-shot registry
//! ([`DoctorRecipeRegistry::production_one_shot`]) plus an in-memory durable
//! ledger standing in for the store slice (which owns production durability
//! and is out of claim). The harness transport replays those owner-produced
//! admission bytes verbatim — echo-checking exactly like the production
//! submit path — and the production drive
//! ([`drive_validated_dispatched_attempt`][eliot_doctor::kernel_client::drive_validated_dispatched_attempt])
//! runs the single registered automatic-safe effect on the REAL
//! [`WindowsProcessExecutor`][eliot_process_executor::WindowsProcessExecutor]
//! behind the REAL
//! [`DoctorDispatchAuthority`][eliot_doctor::dispatch_authority::DoctorDispatchAuthority].
//! There is no `FakeTransport` anywhere in this proof: the closing drive
//! never touches the `kernel_client` unit-test double, and no
//! `ProcessRequest` is ever deserialized (the composition root mints it from
//! the validated material via the local authority, exactly like production).
//!
//! Production path proven here, with the out-of-claim halves cited as
//! read-only evidence:
//!
//! ```text
//! ComposedDoctorFrontDoor::compose (ledger + registry + principal, T6-D2)
//!   -> advertise_doctor_repair (crates/kernel/eliot-kernel-service/src/doctor.rs:166)
//!   -> doctor_repair_advertised (bins/eliot-kernel/src/dispatch_launch.rs:944)
//!   -> health frame "doctor_repair_advertised" (bins/eliot-kernel/src/frame_dispatch.rs:80-81)
//!   -> advertise_doctor gate (bins/eliot-doctor/src/main.rs:118)
//!   -> drive_validated_dispatched_attempt (this crate, production driver)
//!   -> one registered automatic-safe effect on the real executor
//! ```
//!
//! The per-request trigger call site
//! (`trigger_admitted_doctor_launch`,
//! `bins/eliot-kernel/src/dispatch_launch.rs:2176`) is a separately queued
//! item: it stays tested kernel-side and is never wired here. This file
//! proves the doctor-side half that trigger feeds — the same validated
//! material, admission echo, and drive its tested contour covers — against
//! owner-minted admission bytes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[cfg(windows)]
use eliot_contracts::sha256_hex;
use eliot_contracts::{EpochId, EpochLineageId};
#[cfg(windows)]
use eliot_doctor::admitted_effect::EXIT_PENDING_VERIFICATION;
use eliot_doctor::admitted_effect::EvidenceCollector;
use eliot_doctor::dispatch_authority::DoctorDispatchAuthority;
use eliot_doctor::dispatched_material::{
    DispatchGrant, DispatchedAttemptEnvelope, ValidatedDispatchedAttempt,
    read_dispatched_material_from,
};
use eliot_doctor::kernel_client::{
    AdmittedDoctorTransport, DoctorIpcError, GateDecision, drive_validated_dispatched_attempt,
    gate_after_advertise, health_advertises_doctor,
};
#[cfg(windows)]
use eliot_doctor_core::DoctorDisposition;
use eliot_doctor_core::{
    BindingArg, ClosedRepairRequest, ClosedRequestParams, DiagnosticBrief, DoctorError,
    EffectIntent, EffectOutcome, EvidenceHandle, ExecutableBinding, KernelAdmission,
    KernelDoctorClient, RecoveryLease, RegisteredOperation, RepairClass, RepairRecipe,
    RepairRecipeManifest, StateFence,
};
use eliot_kernel_service::{
    ComposedDoctorFrontDoor, DOCTOR_REPAIR_ADVERTISED, DOCTOR_REPAIR_WIRE_ID,
    DOCTOR_REPAIR_WIRE_VERSION, DoctorAdmissionContext, DoctorRecipeRegistry,
    DoctorRepairAdmission, DoctorRepairAttemptRequest, DoctorRepairResponse, KernelServiceState,
    admit_doctor_repair, advertise_doctor_repair, route_doctor_repair,
};
use eliot_ors::{
    DoctorAttemptAdmission, DoctorAttemptRecord, DoctorAttemptStageOutcome, DoctorAttemptState,
    DoctorBudgetLedger, DoctorEffectOutcomeReport, DoctorEffectRecord, DoctorEffectStageOutcome,
    DoctorEffectState, DoctorLedgerError, DoctorRecoveryLedger, OpaqueLabel, OperationIdentity,
};
#[cfg(windows)]
use eliot_process::{ExitDisposition, OperationId, ProcessExecutor, ProcessLifecycle};
use eliot_process_executor::WindowsProcessExecutor;
use time::{Duration, OffsetDateTime};

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const EPOCH_SEQUENCE: u64 = 7;
const FENCE_GENERATION: u64 = 3;
const OPERATION_ID: &str = "op-doctor-effect";
const ATTEMPT_ID: &str = "attempt-t2-s06-1";
const EFFECT_SEQ: u32 = 0;
const PRINCIPAL: &str = "kernel.doctor-principal-t2-s06";
const PROGRAM: &str = "doctor-effect-host.exe";
const SESSION_NONCE: &str = "doctor-t2-s06-session-01";

fn digest(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn load<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("t2-s06 fixture failed: {error:?}"),
    }
}

fn test_epoch() -> EpochId {
    load(EpochId::new(
        load(EpochLineageId::new(TEST_LINEAGE)),
        load(NonZeroU64::new(EPOCH_SEQUENCE).ok_or("non-zero test sequence")),
    ))
}

fn nanos(when: OffsetDateTime) -> u64 {
    load(u64::try_from(when.unix_timestamp_nanos()))
}

fn now_ms(when: OffsetDateTime) -> u64 {
    nanos(when) / 1_000_000
}

// ---------------------------------------------------------------------------
// In-memory durable recovery ledger. First-writer-wins with exact-replay
// identity, mirroring the `eliot-kernel-service` front-door test ledger:
// test-only scaffolding standing in for the store slice, never authority.
// ---------------------------------------------------------------------------

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

    fn guard<T>(
        locked: std::sync::LockResult<std::sync::MutexGuard<'_, T>>,
    ) -> std::sync::MutexGuard<'_, T> {
        match locked {
            Ok(guard) => guard,
            Err(error) => error.into_inner(),
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
        let mut attempts = Self::guard(self.attempts.lock());
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
        let attempts = Self::guard(self.attempts.lock());
        Ok(attempts.get(attempt_digest.as_str()).cloned())
    }

    fn advance_doctor_attempt(
        &self,
        attempt_digest: &OperationIdentity,
        target: DoctorAttemptState,
        admission: Option<&DoctorAttemptAdmission>,
    ) -> Result<Option<DoctorAttemptRecord>, DoctorLedgerError> {
        let storage = |reason: String| DoctorLedgerError::Storage(reason);
        let mut attempts = Self::guard(self.attempts.lock());
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
        let mut effects = Self::guard(self.effects.lock());
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
        let effects = Self::guard(self.effects.lock());
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
        let mut effects = Self::guard(self.effects.lock());
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
        let budgets = Self::guard(self.budgets.lock());
        Ok(budgets.get(scope_key.as_str()).cloned())
    }

    fn store_doctor_budget(&self, ledger: &DoctorBudgetLedger) -> Result<(), DoctorLedgerError> {
        ledger
            .validate()
            .map_err(|error| DoctorLedgerError::Storage(error.to_string()))?;
        let mut budgets = Self::guard(self.budgets.lock());
        budgets.insert(ledger.record_key(), ledger.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Owner-admission transport. Replays the exact owner-minted admission bytes
// verbatim (echo-checked like the production submit path) and retains the
// admission for the pre-effect intent check, mirroring the production
// retained logic. Harness scaffolding for the unavailable live Kernel IPC
// channel — it invents no admission.
// ---------------------------------------------------------------------------

struct RetainedBinding {
    attempt_id: String,
    job_id: String,
    recipe_digest: String,
    effect_digest: Option<String>,
}

struct OwnerAdmissionTransport {
    admission: DoctorRepairAdmission,
    advertise: bool,
    submits: usize,
    retained: Option<RetainedBinding>,
}

impl OwnerAdmissionTransport {
    fn with_owner_admission(admission: DoctorRepairAdmission) -> Self {
        Self {
            admission,
            advertise: true,
            submits: 0,
            retained: None,
        }
    }
}

impl AdmittedDoctorTransport for OwnerAdmissionTransport {
    fn submit_repair_attempt(
        &mut self,
        request: &DoctorRepairAttemptRequest,
    ) -> Result<DoctorRepairResponse, DoctorIpcError> {
        self.submits += 1;
        if !route_doctor_repair(&request.wire_id, request.wire_version) {
            return Err(DoctorIpcError::Contract(
                "owner transport: wire pair mismatch".to_owned(),
            ));
        }
        request.validate().map_err(|error| {
            DoctorIpcError::Contract(format!("owner transport envelope invalid: {error}"))
        })?;
        request.validate_canonical_digest().map_err(|error| {
            DoctorIpcError::Contract(format!("owner transport digest invalid: {error}"))
        })?;
        let envelope: ClosedRepairRequest = serde_json::from_str(&request.closed_request_json)
            .map_err(|error| {
                DoctorIpcError::Contract(format!("owner transport envelope unreadable: {error}"))
            })?;
        if self.admission.attempt_id != request.attempt_id {
            return Err(DoctorIpcError::Contract(
                "owner transport: admission echo mismatch".to_owned(),
            ));
        }
        self.retained = Some(RetainedBinding {
            attempt_id: self.admission.attempt_id.clone(),
            job_id: envelope.request_id.clone(),
            recipe_digest: self.admission.recipe_digest.clone(),
            effect_digest: self.admission.effect_digest.clone(),
        });
        Ok(DoctorRepairResponse::Admitted(Box::new(
            self.admission.clone(),
        )))
    }
}

impl KernelDoctorClient for OwnerAdmissionTransport {
    type Error = DoctorIpcError;

    fn advertise_doctor(&mut self) -> Result<bool, Self::Error> {
        Ok(self.advertise)
    }

    fn admit(
        &mut self,
        _request: &eliot_doctor_core::RepairRequest,
    ) -> Result<KernelAdmission, Self::Error> {
        Err(DoctorIpcError::Contract(
            "legacy RepairRequest cannot carry the doctor repair-attempt identity; present the full envelope"
                .to_owned(),
        ))
    }

    fn record_intent(&mut self, intent: &EffectIntent) -> Result<(), Self::Error> {
        let retained = self.retained.as_ref().ok_or_else(|| {
            DoctorIpcError::Contract("owner transport: no retained admission".to_owned())
        })?;
        if intent.attempt_id == retained.attempt_id
            && intent.job_id == retained.job_id
            && intent.recipe_digest == retained.recipe_digest
            && Some(intent.effect_digest.as_str()) == retained.effect_digest.as_deref()
        {
            Ok(())
        } else {
            Err(DoctorIpcError::Contract(
                "owner transport: intent binding mismatch".to_owned(),
            ))
        }
    }

    fn execute(&mut self, _intent: &EffectIntent) -> Result<EffectOutcome, Self::Error> {
        Err(DoctorIpcError::Contract(
            "owner transport: execution belongs to the adapter".to_owned(),
        ))
    }

    fn reconcile(
        &mut self,
        _job_id: &str,
        _attempt_id: &str,
    ) -> Result<EffectOutcome, Self::Error> {
        Err(DoctorIpcError::Contract(
            "owner transport: reconciliation belongs to the adapter".to_owned(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Fixtures: one registered automatic-safe operation with a governed binding.
// Env carries only explicit named grants; the placeholder shape stands in
// wherever no child spawns, while the closing drive reads the live values.
// ---------------------------------------------------------------------------

fn test_brief() -> DiagnosticBrief {
    DiagnosticBrief {
        problem_id: "problem-t2-s06".to_owned(),
        component: "module-supervision".to_owned(),
        failure_class: "stale-session".to_owned(),
        symptom: "session does not resume".to_owned(),
        impact: "bounded supervision retry".to_owned(),
        evidence: vec![load(EvidenceHandle::new("evidence-ref-1", digest(0xe1)))],
        unknowns: Vec::new(),
    }
}

/// Placeholder env shape for proofs that never spawn: validation shapes
/// only, never executed. The closing drive uses the live named grants.
fn shape_env() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("SYSTEMROOT".to_owned(), "C:\\Windows".to_owned()),
        (
            "PATH".to_owned(),
            "C:\\Windows\\System32;C:\\Windows".to_owned(),
        ),
    ])
}

/// Live named grants for the real child: exactly the two variables the
/// shell needs, nothing inherited wholesale.
#[cfg(windows)]
fn named_env() -> BTreeMap<String, String> {
    let system_root = load(
        std::env::var("SystemRoot").map_err(|error| format!("SystemRoot is not set: {error:?}")),
    );
    BTreeMap::from([
        ("SYSTEMROOT".to_owned(), system_root.clone()),
        (
            "PATH".to_owned(),
            format!("{system_root}\\System32;{system_root}"),
        ),
    ])
}

fn test_binding(
    artifact_digest: &str,
    argv: Vec<BindingArg>,
    env: BTreeMap<String, String>,
) -> ExecutableBinding {
    let binding = ExecutableBinding {
        artifact_digest: artifact_digest.to_owned(),
        program: PROGRAM.to_owned(),
        argv,
        env,
        timeout_ms: 5_000,
        max_stdout_bytes: 65_536,
        max_stderr_bytes: 65_536,
    };
    load(binding.validate());
    binding
}

fn test_manifest(binding: &ExecutableBinding) -> RepairRecipeManifest {
    let manifest = RepairRecipeManifest {
        manifest_id: "doctor-t2-s06-manifest".to_owned(),
        manifest_revision: 1,
        operations: vec![RegisteredOperation {
            operation_id: OPERATION_ID.to_owned(),
            adapter_id: "automatic-safe".to_owned(),
            description: "drive one registered automatic-safe effect".to_owned(),
            definition_digest: binding.digest(),
            binding: binding.clone(),
        }],
    };
    load(manifest.validate());
    manifest
}

fn test_recipe(binding: &ExecutableBinding) -> RepairRecipe {
    let recipe = RepairRecipe {
        recipe_id: "recipe-t2-s06".to_owned(),
        revision: 1,
        problem_classes: BTreeSet::from(["stale-session".to_owned()]),
        components: BTreeSet::from(["module-supervision".to_owned()]),
        repair_class: RepairClass::AutomaticSafe,
        prerequisites: Vec::new(),
        required_authority: "kernel.doctor-recovery".to_owned(),
        allowed_effects: BTreeSet::from([OPERATION_ID.to_owned()]),
        operations: vec![OPERATION_ID.to_owned()],
        expected_observables: vec!["observable-1".to_owned()],
        verification_contract: vec!["verify-1".to_owned()],
        rollback_or_compensation: vec!["rollback-1".to_owned()],
        attempt_budget: 3,
        cooldown: Duration::seconds(60),
        stop_conditions: Vec::new(),
        executable_bindings: [(OPERATION_ID.to_owned(), binding.clone())]
            .into_iter()
            .collect(),
    };
    load(recipe.validate());
    recipe
}

fn test_request(
    now: OffsetDateTime,
    manifest: &RepairRecipeManifest,
    recipe: &RepairRecipe,
) -> ClosedRepairRequest {
    let operation = load(manifest.resolve(OPERATION_ID));
    load(ClosedRepairRequest::for_effect(ClosedRequestParams {
        request_id: "req-t2-s06-1".to_owned(),
        brief: test_brief(),
        recipe: recipe.clone(),
        operations: vec![operation],
        fence: load(StateFence::new(
            test_epoch(),
            FENCE_GENERATION,
            digest(0xf1),
        )),
        lease: RecoveryLease {
            lease_id: "lease-t2-s06-1".to_owned(),
            owner: "kernel.doctor-recovery".to_owned(),
            expires_at: now + Duration::hours(1),
            allowed_effects: BTreeSet::from([OPERATION_ID.to_owned()]),
        },
        approval: None,
        budget_units: 1,
        deadline: now + Duration::hours(1),
        cancellation: false,
        escalation_target: "governor".to_owned(),
    }))
}

fn test_envelope(request: &ClosedRepairRequest) -> DoctorRepairAttemptRequest {
    load(
        DoctorRepairAttemptRequest {
            wire_id: DOCTOR_REPAIR_WIRE_ID.to_owned(),
            wire_version: DOCTOR_REPAIR_WIRE_VERSION,
            attempt_id: ATTEMPT_ID.to_owned(),
            effect_seq: EFFECT_SEQ,
            closed_request_json: load(serde_json::to_string(request)),
            target_resource_digest: digest(0xb1),
            request_digest: String::new(),
        }
        .with_computed_digest(),
    )
}

fn test_registry(manifest: &RepairRecipeManifest, recipe: &RepairRecipe) -> DoctorRecipeRegistry {
    load(DoctorRecipeRegistry::production_one_shot(
        manifest.clone(),
        recipe.clone(),
    ))
}

fn test_context() -> DoctorAdmissionContext {
    load(DoctorAdmissionContext::new(
        KernelServiceState::Ready,
        test_epoch(),
        FENCE_GENERATION,
    ))
}

fn owner_admit(
    ledger: &TestLedger,
    registry: &DoctorRecipeRegistry,
    context: &DoctorAdmissionContext,
    envelope: &DoctorRepairAttemptRequest,
    now_nanos: u64,
) -> DoctorRepairAdmission {
    let response = load(
        admit_doctor_repair(ledger, registry, context, PRINCIPAL, envelope, now_nanos)
            .map_err(|error| format!("owner gate must admit: {error:?}")),
    );
    match response {
        DoctorRepairResponse::Admitted(admission) => {
            load(admission.validate().map_err(|error| error.to_string()));
            *admission
        }
        other => panic!("owner gate must admit the registered attempt, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Staging: the dispatch file the contour would deliver. Runtime input to the
// reader, never a repo mutation.
// ---------------------------------------------------------------------------

fn dispatched_grant(now_unix_ms: u64) -> DispatchGrant {
    DispatchGrant {
        grant_digest: digest(0x61),
        authority_epoch: test_epoch(),
        fence_generation: FENCE_GENERATION,
        fence_nonce: "doctor-launch-fence-t2-s06".to_owned(),
        idempotency_key: "doctor-launch-lease-t2-s06".to_owned(),
        expires_at: now_unix_ms.saturating_add(60_000),
    }
}

fn stage_dispatch_file(
    tag: &str,
    request: &ClosedRepairRequest,
    manifest: &RepairRecipeManifest,
    now_unix_ms: u64,
) -> PathBuf {
    let envelope = DispatchedAttemptEnvelope {
        attempt: test_envelope(request),
        request: request.clone(),
        manifest: manifest.clone(),
        epoch: test_epoch(),
        generation: FENCE_GENERATION,
        nonce: SESSION_NONCE.to_owned(),
        grant: dispatched_grant(now_unix_ms),
    };
    let path = std::env::temp_dir().join(format!("eliot-t2-s06-{tag}.dispatch.json"));
    load(std::fs::write(
        &path,
        load(serde_json::to_string(&envelope)),
    ));
    path
}

fn read_validated(path: &std::path::Path) -> ValidatedDispatchedAttempt {
    let validated = load(read_dispatched_material_from(path, &test_epoch()));
    match validated {
        Some(validated) => {
            assert!(!path.exists(), "validated material must be consumed once");
            validated
        }
        None => panic!("valid grant material must present"),
    }
}

// ---------------------------------------------------------------------------
// Proof 1: the production owners compose and advertise.
// ---------------------------------------------------------------------------

fn compose_and_advertise() -> Result<(), String> {
    let binding = test_binding(
        &digest(0xc1),
        vec![BindingArg::Literal {
            value: "/c".to_owned(),
        }],
        shape_env(),
    );
    let manifest = test_manifest(&binding);
    let recipe = test_recipe(&binding);
    let registry = test_registry(&manifest, &recipe);
    if registry.recipe_count() != 1 {
        return Err("production registry must carry exactly one recipe".to_owned());
    }
    if registry.manifest_digest().len() != 64 {
        return Err("production registry must bind its manifest digest".to_owned());
    }
    let ledger = TestLedger::new();
    let owner = ComposedDoctorFrontDoor::compose(&ledger, &registry, PRINCIPAL)
        .map_err(|error| format!("production owners must compose: {error:?}"))?;
    if owner.principal_ref() != PRINCIPAL {
        return Err("composed owner must carry the Kernel-owned principal".to_owned());
    }
    if owner.registry().recipe_count() != 1 {
        return Err("composed owner must carry the immutable registry".to_owned());
    }
    if !advertise_doctor_repair(&owner) {
        return Err("composed ledger/registry/principal must advertise repair".to_owned());
    }
    if DOCTOR_REPAIR_ADVERTISED {
        return Err("the uncomposed default must stay inert".to_owned());
    }
    if !route_doctor_repair(DOCTOR_REPAIR_WIRE_ID, DOCTOR_REPAIR_WIRE_VERSION) {
        return Err("the exact wire pair must route".to_owned());
    }
    if route_doctor_repair("eliot.kernel.unknown", DOCTOR_REPAIR_WIRE_VERSION)
        || route_doctor_repair(DOCTOR_REPAIR_WIRE_ID, 999)
    {
        return Err("any other wire must stay inert".to_owned());
    }
    if ComposedDoctorFrontDoor::compose(&ledger, &registry, "   ").is_ok() {
        return Err("a blank principal must not compose".to_owned());
    }
    if DoctorRecipeRegistry::register(manifest, Vec::new()).is_ok() {
        return Err("an empty registry must not compose".to_owned());
    }
    Ok(())
}

#[test]
fn production_owners_compose_and_advertise() {
    if let Err(detail) = compose_and_advertise() {
        panic!("production owners must compose and advertise: {detail}");
    }
}

// ---------------------------------------------------------------------------
// Proof 2: the exact health-frame key the Kernel contour writes opens the
// composition gate — and nothing else does.
// ---------------------------------------------------------------------------

fn frame_key_drives_gate() -> Result<(), String> {
    let epoch_value = serde_json::to_value(test_epoch()).map_err(|error| format!("{error:?}"))?;
    let advertised = serde_json::json!({
        "status": "OPEN",
        "authority_epoch": epoch_value,
        "doctor_repair_advertised": true,
    });
    if !health_advertises_doctor(&advertised) {
        return Err("the Kernel advertise key must open the probe".to_owned());
    }
    if gate_after_advertise(true, true) != GateDecision::Drive {
        return Err("advertised plus presented must be the only Drive arm".to_owned());
    }
    let operations_only = serde_json::json!({
        "status": "OPEN",
        "authority_epoch": epoch_value,
        "operations": [DOCTOR_REPAIR_WIRE_ID],
    });
    if !health_advertises_doctor(&operations_only) {
        return Err("the operations-list advertisement must open the probe".to_owned());
    }
    let silent = serde_json::json!({
        "status": "OPEN",
        "authority_epoch": epoch_value,
        "doctor_repair_advertised": false,
    });
    if health_advertises_doctor(&silent) {
        return Err("an unadvertised Kernel must fail the probe closed".to_owned());
    }
    let missing = serde_json::json!({
        "status": "OPEN",
        "authority_epoch": epoch_value,
    });
    if health_advertises_doctor(&missing) {
        return Err("a missing advertisement must fail the probe closed".to_owned());
    }
    if gate_after_advertise(false, true) != GateDecision::DenyNotAdvertised {
        return Err("unadvertised must deny even with presented material".to_owned());
    }
    if gate_after_advertise(true, false) != GateDecision::DenyNoPresentedAttempt {
        return Err("advertised without presentation must deny".to_owned());
    }
    if gate_after_advertise(false, false) != GateDecision::DenyNotAdvertised {
        return Err("silent must deny".to_owned());
    }
    Ok(())
}

#[test]
fn health_frame_key_drives_composition_gate() {
    if let Err(detail) = frame_key_drives_gate() {
        panic!("health-frame key must drive the composition gate: {detail}");
    }
}

// ---------------------------------------------------------------------------
// Proof 3: mutated terms deny before any submit and without effect, through
// the production drive on the real executor contour (which never starts).
// ---------------------------------------------------------------------------

async fn deny_mutated_terms() -> Result<(), String> {
    let now = OffsetDateTime::now_utc();
    let binding = test_binding(
        &digest(0xc1),
        vec![
            BindingArg::Literal {
                value: "/c".to_owned(),
            },
            BindingArg::Literal {
                value: "C:\\eliot\\doctor-effect-probe.bat".to_owned(),
            },
        ],
        shape_env(),
    );
    let manifest = test_manifest(&binding);
    let recipe = test_recipe(&binding);
    let request = test_request(now, &manifest, &recipe);
    let registry = test_registry(&manifest, &recipe);
    let ledger = TestLedger::new();
    let context = test_context();
    let admission = owner_admit(
        &ledger,
        &registry,
        &context,
        &test_envelope(&request),
        nanos(now),
    );
    let path = stage_dispatch_file("mutated", &request, &manifest, now_ms(now));
    let mut validated = read_validated(&path);
    validated.request.approval = Some("forged-approval".to_owned());
    let mut transport = OwnerAdmissionTransport::with_owner_admission(admission);
    let authority = Arc::new(DoctorDispatchAuthority::new().map_err(|error| format!("{error:?}"))?);
    let concrete = Arc::clone(&authority);
    let executor_authority: Arc<dyn eliot_process_executor::DispatchValidationPort> = concrete;
    let executor = Arc::new(WindowsProcessExecutor::new(executor_authority));
    let outcome = drive_validated_dispatched_attempt(
        &mut transport,
        &authority,
        Arc::clone(&executor),
        Arc::new(EvidenceCollector::new()),
        &validated,
        std::path::Path::new("C:\\eliot\\doctor"),
        now,
        now_ms(now),
    )
    .await;
    match outcome {
        Err(eliot_doctor::admitted_effect::AdapterError::Admission(
            DoctorError::IdentityMismatch,
        )) => {}
        Err(error) => {
            return Err(format!(
                "changed approval must deny IdentityMismatch, got {error:?}"
            ));
        }
        Ok(_) => return Err("changed approval must deny without effect".to_owned()),
    }
    if transport.submits != 0 {
        return Err("mutated terms must deny before any submit".to_owned());
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[tokio::test]
async fn mutated_terms_deny_before_submit_or_start() {
    if let Err(detail) = deny_mutated_terms().await {
        panic!("mutated terms must deny before submit or start: {detail}");
    }
}

// ---------------------------------------------------------------------------
// Proof 4 (closing, Windows-only): one registered automatic-safe effect
// through the REAL `WindowsProcessExecutor`, admitted by the REAL Kernel
// gate. The program pins the exact bytes the executor launches; the digest
// is computed from the staged file, never hardcoded.
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn stage_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("eliot-t2-s06-{tag}"));
    load(std::fs::create_dir_all(&root));
    root
}

#[cfg(windows)]
fn stage_program(root: &std::path::Path) -> String {
    let bytes = load(
        std::fs::read("C:\\Windows\\System32\\cmd.exe")
            .map_err(|error| format!("admitted executable is missing: {error:?}")),
    );
    let artifact = sha256_hex(&bytes);
    load(std::fs::write(root.join(PROGRAM), &bytes));
    artifact
}

#[cfg(windows)]
fn stage_bat(root: &std::path::Path, tag: &str) -> String {
    let path = root.join(format!("eliot-t2-s06-{tag}.bat"));
    load(std::fs::write(
        &path,
        "@echo off\r\necho T2-S06-BOUNDED-STDOUT\r\nexit 0\r\n",
    ));
    path.to_string_lossy().into_owned()
}

#[cfg(windows)]
fn remove_staged(root: &std::path::Path, tag: &str) {
    let _ = std::fs::remove_file(root.join(PROGRAM));
    let _ = std::fs::remove_file(root.join(format!("eliot-t2-s06-{tag}.bat")));
    let _ = std::fs::remove_dir(root);
}

#[cfg(windows)]
fn check_owner_outcome(
    outcome: &eliot_doctor::admitted_effect::OneShotOutcome,
    expected_effect: Option<&String>,
    expected_attempt: &str,
    submits: usize,
    evidence: usize,
) -> Result<(), String> {
    if !matches!(
        outcome.disposition,
        DoctorDisposition::RepairedPendingVerification { .. }
    ) {
        return Err(format!(
            "expected pending verification, got {:?}",
            outcome.disposition
        ));
    }
    if outcome.exit_code() != EXIT_PENDING_VERIFICATION {
        return Err(format!("expected exit 10, got {}", outcome.exit_code()));
    }
    if outcome.report.effect_digest.as_ref() != expected_effect {
        return Err("effect digest must equal the owner-admitted digest".to_owned());
    }
    if outcome.report.attempt_digest.as_deref() != Some(expected_attempt) {
        return Err("attempt digest must equal the owner-admitted digest".to_owned());
    }
    if outcome.report.effect_disposition.as_deref() != Some("succeeded") {
        return Err("the bounded child must complete".to_owned());
    }
    if outcome.report.evidence_reference.is_none() {
        return Err("the driven effect must carry executor evidence".to_owned());
    }
    if submits != 1 {
        return Err(format!("expected one submit, got {submits}"));
    }
    if evidence == 0 {
        return Err("the real executor must record evidence".to_owned());
    }
    Ok(())
}

#[cfg(windows)]
async fn check_child_completed(executor: &WindowsProcessExecutor) -> Result<(), String> {
    let operation = OperationId::new(OPERATION_ID).map_err(|error| format!("{error:?}"))?;
    let view = executor
        .inspect(operation)
        .await
        .map_err(|error| format!("inspect must observe the completed child: {error:?}"))?;
    if view.lifecycle() != ProcessLifecycle::Exited {
        return Err("the bounded child must reach Exited".to_owned());
    }
    if !view
        .exit()
        .is_some_and(|exit| exit.disposition() == ExitDisposition::Completed)
    {
        return Err("the bounded child must complete".to_owned());
    }
    Ok(())
}

#[cfg(windows)]
async fn drive_owner_admitted_effect() -> Result<(), String> {
    let now = OffsetDateTime::now_utc();
    let root = stage_root("drive");
    let artifact = stage_program(&root);
    let bat = stage_bat(&root, "drive");
    let binding = test_binding(
        &artifact,
        vec![
            BindingArg::Literal {
                value: "/c".to_owned(),
            },
            BindingArg::Literal { value: bat },
        ],
        named_env(),
    );
    let manifest = test_manifest(&binding);
    let recipe = test_recipe(&binding);
    let request = test_request(now, &manifest, &recipe);
    let registry = test_registry(&manifest, &recipe);
    let ledger = TestLedger::new();
    let context = test_context();
    let admission = owner_admit(
        &ledger,
        &registry,
        &context,
        &test_envelope(&request),
        nanos(now),
    );
    let expected_effect = admission.effect_digest.clone();
    let expected_attempt = admission.attempt_digest.clone();
    let path = stage_dispatch_file("drive", &request, &manifest, now_ms(now));
    let validated = read_validated(&path);
    if validated.generation != FENCE_GENERATION {
        remove_staged(&root, "drive");
        return Err("validated material must bind the live generation".to_owned());
    }
    let mut transport = OwnerAdmissionTransport::with_owner_admission(admission);
    let authority = Arc::new(DoctorDispatchAuthority::new().map_err(|error| format!("{error:?}"))?);
    let concrete = Arc::clone(&authority);
    let executor_authority: Arc<dyn eliot_process_executor::DispatchValidationPort> = concrete;
    let executor = Arc::new(WindowsProcessExecutor::new(executor_authority));
    let sink = Arc::new(EvidenceCollector::new());
    let outcome = drive_validated_dispatched_attempt(
        &mut transport,
        &authority,
        Arc::clone(&executor),
        Arc::clone(&sink),
        &validated,
        &root,
        now,
        now_ms(now),
    )
    .await
    .map_err(|error| format!("owner-admitted effect must drive: {error:?}"))?;
    remove_staged(&root, "drive");
    check_owner_outcome(
        &outcome,
        expected_effect.as_ref(),
        &expected_attempt,
        transport.submits,
        sink.len(),
    )?;
    check_child_completed(&executor).await
}

#[cfg(windows)]
#[tokio::test]
async fn owner_admitted_effect_drives_on_real_executor() {
    if let Err(detail) = drive_owner_admitted_effect().await {
        panic!("owner-admitted effect must drive on the real executor: {detail}");
    }
}
