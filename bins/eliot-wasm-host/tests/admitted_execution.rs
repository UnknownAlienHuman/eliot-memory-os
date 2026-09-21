//! Joined admitted-execution proof (issue #1955, I14.19).
//!
//! Seats the three owner lanes through the real
//! [`WasmHostRunner::execute_admitted`] path — no mocks on any evaluation
//! logic:
//!
//! - Governor lane: [`GovernorWasmAdmission::from_owners`] over an admitted
//!   [`KernelGenerationSnapshot`] (fence/epoch from recovery state, never
//!   threaded) plus a [`ContourAdmission`] built from the host admission
//!   proof and the raw artifact/WIT/configuration bytes (re-hashed, never
//!   trusted).
//! - P03 lane: the frozen [`WasmP03ProcessAdapter`] over the real
//!   [`WindowsProcessExecutor`]. Every `execute` spawns a real child through
//!   a genuinely issued one-shot permit: the test plays the Kernel/P-07
//!   lane with test-only key material, exactly as the executor's own tests
//!   do. The staged request mirrors the runtime-derived envelope field for
//!   field (operation/tree/generation/fence-epoch+generation/wall/memory/
//!   stdout ceilings).
//! - Engine lane: the real [`WasmtimeComponentEngine`] compiled from the
//!   checked-in `guest-conformance.wat` bytes, digest-bound end to end.
//!
//! Conformance vector (fixed, documented): the seed travels as the first 8
//! input bytes because the checked-in guest replicates the oracle as
//! `out[i] = in[i] + in[i % 8]` — only a seed-prefixed input makes guest
//! output equal the [`DeterministicEchoCore`] image. The threaded promotion
//! corpus is therefore computed over that exact framed input via
//! [`PromotionExpectations::for_component`]. Threading the bare
//! [`CONFORMANCE_INPUT`] corpus instead is *correctly* rejected with
//! `DifferentialMismatch` (proven by
//! `bare_corpus_against_framed_execution_is_rejected`), because no input
//! makes this guest emit the bare-input oracle image. The corpus digest
//! honestly binds the executed vector either way.
//!
//! The positive proof retries whole real invocations (fresh invocation id,
//! fresh permit, fresh child) until a genuinely `Succeeded` result lands or
//! a deadline panics: the P03 reap races the child, so a transient
//! `Unknown` must never become a pass — and any `Rejected` verdict aborts
//! immediately, proving fail-closed holds under scheduling variance.
//!
//! Documentation route `sha256:066b9e92b6369661a70cefc73744b67fee06d5bb825983d55a00b5cdbd52c90f`,
//! read receipt `sha256:02048eb89b5bead028e6b5d61cbe586b5451e258872b19d84a16df483720d9fc`,
//! bundle `sha256:98cbfb2502b66aa6b0e79de736e39861707a2c308b4ac1f928064219d67e4dc5`
//! (83/83 required items read before mutation).

#![cfg(windows)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eliot_contracts::{ArtifactId, ContractId, EpochId, EpochLineageId, ResourceGeneration};
use eliot_governor::{
    CONFORMANCE_COMPONENT, CONFORMANCE_SEED, ContourAdmission, GovernorWasmAdmission,
    KernelGenerationSnapshot, PromotionExpectations,
};
use eliot_observation_contracts::ObservationScope;
use eliot_platform::ClockObservation;
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
    EnvironmentProjection, EvidenceSinkError, FencingToken, Generation, ImageId, JobId,
    KernelDispatchKey, OperationId, PermitIssuance, ProcessEvidence, ProcessEvidenceSink,
    ProcessExecutionError, ProcessIntent, ProcessRequest, ProcessTreeId, ResourceLimits, SessionId,
    SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{
    DispatchValidationPort, WindowsProcessExecutor, wasm_p03_adapter::WasmP03ProcessAdapter,
};
use eliot_receipts::WorkScopeId;
use eliot_runtime::{Runtime, RuntimeConfig};
use eliot_runtime_contracts::{HealthVector, LeaseState, ModuleGeneration, ModuleGenerationState};
use eliot_security_contracts::{
    CompetenceLevel, EffectCeiling, EpistemicUse, FreshnessStatus, IndependenceLevel,
    InstructionTaint, IntegrityStatus, PrivacyClass, QuarantineState, SourceAssurance,
};
use eliot_wasm_host::{
    AdmittedGeneration, GenerationManifest, Profile, PrototypeContourDecision,
    STANDARD_GUEST_TARGET, WasmHostRunner, WasmtimeComponentEngine, admit_generation,
    provider_configuration_digest,
};
use eliot_wasm_runtime::lifecycle::{DeterministicEchoCore, SemanticCore};
use eliot_wasm_runtime::{
    ArtifactAccessLimits, CancellationPolicy, CapabilityId, ComponentManifest, EngineBinding,
    EpochPolicy, ExecutionContour, InvocationDisposition, InvocationId, InvocationLimits,
    InvocationRequest, OwnerId, PortError, Revision, RuntimeError, RuntimePorts, Sha256Digest,
    WasmRuntime, WorkScopeRef, WorkUnitId,
};

/// Raw WIT world bytes the interface digest binds (same file the provider
/// binds internally — no copy, no pasted hex).
const GUEST_WIT: &[u8] = include_bytes!("../wit/guest.wit");

/// Component configuration bytes chosen for this proof (distinct from the
/// provider unit-test constant, so the digest binding is exercised, not
/// echoed). The manifest digest is recomputed from these bytes.
const JOINED_COMPONENT_CONFIGURATION: &[u8] =
    b"component=guest-conformance;world=eliot:wasm/guest;export=run;imports=closed;proof=join-1955";

/// Engine identity string the engine artifact digest is derived from.
/// Wasmtime links statically, so no engine artifact file exists to hash;
/// the digest names the exact pinned implementation instead (recomputed,
/// never pasted).
const ENGINE_IDENTITY: &[u8] = b"wasmtime-component/47.0.4";

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const COMPONENT: &str = "component-1956";
const WORK_UNIT: &str = "work-1956";
const SCOPE: &str = "scope-1956";
const TASK: &str = "task-1956";
const OWNER: &str = "owner-1956";
const LEASE: &str = "lease-1956";
const VERIFIER: &str = "verifier:a12";

/// Fixed framed input: seed (LE) + conformance payload. The guest reads its
/// mixing seed from the first 8 input bytes, so only this framing makes real
/// guest output equal the oracle image.
fn framed_input() -> Vec<u8> {
    let mut framed = CONFORMANCE_SEED.to_le_bytes().to_vec();
    framed.extend_from_slice(b"lc-wasm-1956");
    framed
}

/// Real component artifact bytes compiled by the engine lane.
fn component_bytes() -> Vec<u8> {
    match wat::parse_file("tests/fixtures/guest-conformance.wat") {
        Ok(bytes) => bytes,
        Err(error) => panic!("joined proof fixture unreadable: {error}"),
    }
}

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("joined proof fixture failed: {error:?}"),
    }
}

fn test_epoch() -> EpochId {
    must(EpochId::new(
        must(EpochLineageId::new(TEST_LINEAGE)),
        must(NonZeroU64::new(1).ok_or("non-zero test sequence")),
    ))
}

fn test_profile() -> Profile {
    if Profile::D2Operational.is_compiled() {
        Profile::D2Operational
    } else {
        Profile::FullComposition
    }
}

fn test_runtime() -> Runtime {
    must(Runtime::new(
        RuntimeConfig {
            mailbox_capacity: 4,
            control_reserve: 1,
            concurrency: 1,
            control_concurrency_reserve: 1,
            fairness_quantum: 1,
            restart_budget: 0,
            restart_window: Duration::from_secs(1),
            restart_backoff: Duration::from_millis(1),
            shutdown_grace: Duration::from_millis(1),
        },
        None,
    ))
}

/// Test-only permit authority. Production issuance belongs to the
/// Kernel/P-07 lane; this proof plays that lane with test-only key
/// material, exactly as the executor's own tests do.
fn test_authority() -> DispatchPermitAuthority {
    DispatchPermitAuthority::activate(
        must(DispatchAuthorityId::new("wasm-join-test-authority")),
        must(KernelDispatchKey::from_secret_bytes([0x5A; 32])),
    )
}

fn revisions() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("authority".to_owned(), "a".repeat(64)),
        ("state".to_owned(), "b".repeat(64)),
    ])
}

struct FakePort {
    authority: Mutex<DispatchPermitAuthority>,
    context: DispatchValidationContext,
}

impl FakePort {
    fn new(authority: DispatchPermitAuthority, fence: FencingToken) -> Self {
        let context = must(DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(150),
            },
            fence,
            test_epoch(),
            revisions(),
            41,
        ));
        Self {
            authority: Mutex::new(authority),
            context,
        }
    }
}

impl DispatchValidationPort for FakePort {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let mut authority = self.authority.lock().map_err(|_| {
            ProcessExecutionError::Unavailable("dispatch authority lock poisoned".to_owned())
        })?;
        authority
            .validate_and_consume(request, observed, &self.context)
            .map_err(Into::into)
    }
}

#[derive(Default)]
struct RecordingSink {
    evidence: Mutex<Vec<ProcessEvidence>>,
}

impl ProcessEvidenceSink for RecordingSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        match self.evidence.lock() {
            Ok(mut guard) => {
                guard.push(evidence);
                Ok(())
            }
            Err(_) => Err(EvidenceSinkError {
                message: "recording sink lock poisoned".to_owned(),
            }),
        }
    }
}

/// Limits admitted for the joined vector: engine-exact (stack 8192, epoch
/// ceiling, artifact bound) and P03-mirrored (wall/memory/stdout ceilings
/// re-checked against the staged request).
fn joined_limits(component_digest: &Sha256Digest) -> InvocationLimits {
    InvocationLimits {
        max_input_bytes: 64,
        max_output_bytes: 64,
        max_host_calls: 1,
        max_fuel: 100_000,
        max_memory_bytes: 1_048_576,
        max_table_elements: 64,
        max_instances: 2,
        max_stack_bytes: 8_192,
        wall_deadline_ms: 30_000,
        epoch: EpochPolicy {
            deadline_ticks: 100,
            cancellation: CancellationPolicy::EpochAndFuel,
        },
        artifact_access: ArtifactAccessLimits {
            allowed_digests: BTreeSet::from([component_digest.clone()]),
            max_reads: 2,
            max_bytes: 131_072,
        },
    }
}

/// Manifest bound to the real bytes: component binary, WIT, and the
/// provider-read engine binding. Imports stay empty — the closed world the
/// engine enforces.
fn joined_manifest(
    component_digest: &Sha256Digest,
    engine_binding: &EngineBinding,
    configuration_digest: &Sha256Digest,
) -> ComponentManifest {
    ComponentManifest {
        component_id: must(CapabilityId::new(COMPONENT)),
        world: must(CapabilityId::new("eliot:wasm/guest")),
        wit_version: "1.0.0".to_owned(),
        guest_target: "wasm32-wasip2".to_owned(),
        artifact_digest: component_digest.clone(),
        interface_digest: Sha256Digest::of_bytes(GUEST_WIT),
        source_digest: component_digest.clone(),
        configuration_digest: configuration_digest.clone(),
        state_contract_digest: must(Sha256Digest::new(
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        )),
        imports: BTreeSet::new(),
        exports: BTreeSet::from([must(CapabilityId::new("run"))]),
        admitted_privacy_classes: vec![PrivacyClass::Internal],
        required_verifier: VERIFIER.to_owned(),
        engine: engine_binding.clone(),
    }
}

fn joined_engine_binding() -> EngineBinding {
    EngineBinding {
        implementation_id: "wasmtime-component".to_owned(),
        exact_version: "47.0.4".to_owned(),
        engine_artifact_digest: Sha256Digest::of_bytes(ENGINE_IDENTITY),
        engine_configuration_digest: provider_configuration_digest(),
        wit_interface_digest: Sha256Digest::of_bytes(GUEST_WIT),
    }
}

fn snapshot_fixture() -> KernelGenerationSnapshot {
    KernelGenerationSnapshot {
        service: "eliot-kernel".to_owned(),
        protocol: "eliot.kernel.v1".to_owned(),
        generation: must(ResourceGeneration::new(1)),
        authority_epoch: test_epoch(),
        artifact_digest: "a".repeat(64),
        protected_snapshot_digest: "b".repeat(64),
        principal: "S-1-5-18".to_owned(),
    }
}

fn generation_fixture(
    fence: &eliot_contracts::StateFence,
    artifact_hex: &str,
    state: ModuleGenerationState,
) -> ModuleGeneration {
    ModuleGeneration {
        module_id: must(ContractId::new(COMPONENT)),
        generation: must(ResourceGeneration::new(1)),
        artifact_id: must(ArtifactId::new(artifact_hex)),
        state,
        health: HealthVector::healthy(),
        state_fence: fence.clone(),
    }
}

fn lease_fixture(fence: &eliot_contracts::StateFence) -> eliot_runtime_contracts::RuntimeLease {
    eliot_runtime_contracts::RuntimeLease {
        lease_id: LEASE.to_owned(),
        scope_ref: SCOPE.to_owned(),
        authority_epoch: test_epoch(),
        state_fence: fence.clone(),
        state: LeaseState::Active,
    }
}

fn scope_fixture() -> ObservationScope {
    ObservationScope {
        work_scope: must(WorkScopeId::new(SCOPE)),
        task_ref: Some(TASK.to_owned()),
        attempt_ref: Some(WORK_UNIT.to_owned()),
        module_or_route_ref: Some(COMPONENT.to_owned()),
    }
}

fn assurance_fixture(fence: &eliot_contracts::StateFence) -> SourceAssurance {
    SourceAssurance {
        source_ref: "source-1956".to_owned(),
        provenance_ref: "provenance-1956".to_owned(),
        integrity: IntegrityStatus::Verified,
        freshness: FreshnessStatus::Current,
        competence: CompetenceLevel::DomainVerified,
        independence: IndependenceLevel::Independent,
        privacy_class: PrivacyClass::Internal,
        instruction_taint: InstructionTaint::DataOnly,
        allowed_epistemic_use: vec![EpistemicUse::VerificationInput],
        allowed_effects: vec![EffectCeiling::NoExternalEffect],
        required_verifier: Some(VERIFIER.to_owned()),
        quarantine: QuarantineState::None,
        state_fence: fence.clone(),
    }
}

/// Host contour admission over the real fixture: default WASM decision,
/// closed manifest, no actual imports.
fn host_admission(
    component_digest: &Sha256Digest,
    limits: &InvocationLimits,
) -> eliot_wasm_host::AdmittedGeneration {
    let manifest = GenerationManifest {
        target: STANDARD_GUEST_TARGET.to_owned(),
        artifact_digest: component_digest.clone(),
        wit_digest: Sha256Digest::of_bytes(GUEST_WIT),
        world: "eliot:wasm/guest".to_owned(),
        allowed_imports: Vec::new(),
        allowed_exports: vec!["run".to_owned()],
        capability_grants: Vec::new(),
        limits: limits.clone(),
        state_class: "stateless".to_owned(),
        migration_contract: "none".to_owned(),
        privacy_policy: "project_code".to_owned(),
        comparator: "shadow-exact".to_owned(),
        rollback_generation: None,
    };
    let decision = PrototypeContourDecision::default();
    must(admit_generation(Some(&decision), &manifest, &[]))
}

/// Kernel-admitted P03 request mirroring the runtime-derived envelope field
/// for field. The envelope is computed inside `execute`; every value below
/// is fixed by the admission the test threads, so the binding is exact.
fn admitted_request(
    authority: &mut DispatchPermitAuthority,
    operation_id: &str,
    fence: FencingToken,
    limits: &InvocationLimits,
) -> ProcessRequest {
    let executable = r"C:\Windows\System32\cmd.exe";
    let executable_digest = match std::fs::read(executable) {
        Ok(bytes) => eliot_contracts::sha256_hex(&bytes),
        Err(error) => panic!("joined proof executable unreadable: {error}"),
    };
    let generation = must(Generation::new(1));
    let working_directory = match std::env::temp_dir().to_str() {
        Some(dir) => dir.to_owned(),
        None => panic!("joined proof temp directory is not valid unicode"),
    };
    let intent = must(ProcessIntent::new(
        must(OperationId::new(operation_id)),
        must(ProcessTreeId::new(SCOPE)),
        must(JobId::new(format!("job-{operation_id}"))),
        must(ImageId::new(format!("image-{operation_id}"))),
        must(SessionId::new(format!("session-{operation_id}"))),
        generation,
        executable,
        executable_digest,
        vec![
            "/c".to_owned(),
            "echo".to_owned(),
            "joined-1955-proof".to_owned(),
        ],
        working_directory,
        EnvironmentProjection::default(),
        must(ResourceLimits::new(
            limits.wall_deadline_ms,
            Some(10_000),
            Some(limits.max_memory_bytes),
            limits.max_output_bytes,
            limits.max_output_bytes,
            4,
        )),
    ));
    let permit = must(authority.issue(
        &intent,
        must(PermitIssuance::new(
            must(ActionLeaseRef::new(format!("lease-{operation_id}"))),
            fence,
            revisions(),
            100,
            120_000,
            format!("nonce-{operation_id}"),
        )),
    ));
    must(ProcessRequest::new(intent, permit))
}

/// Sealed caller request for one attempt.
fn attempt_request(
    operation_id: &str,
    contour: ExecutionContour,
    input: Vec<u8>,
) -> InvocationRequest {
    must(InvocationRequest::new(
        must(InvocationId::new(operation_id)),
        must(CapabilityId::new(COMPONENT)),
        must(WorkUnitId::new(WORK_UNIT)),
        must(WorkScopeRef::new(SCOPE)),
        contour,
        input,
        CONFORMANCE_SEED,
        false,
    ))
}

#[allow(clippy::too_many_lines)]
#[test]
fn admitted_execution_succeeds_through_real_wasmtime() {
    let component = component_bytes();
    let component_digest = Sha256Digest::of_bytes(&component);
    let configuration_digest = Sha256Digest::of_bytes(JOINED_COMPONENT_CONFIGURATION);
    let engine_binding = joined_engine_binding();
    let limits = joined_limits(&component_digest);
    let manifest = joined_manifest(&component_digest, &engine_binding, &configuration_digest);
    let framed = framed_input();
    let reference =
        DeterministicEchoCore::new(CONFORMANCE_COMPONENT).invoke(&framed, CONFORMANCE_SEED);

    let snapshot = snapshot_fixture();
    let fence = snapshot.state_fence();
    let admitted_gen = host_admission(&component_digest, &limits);
    let contour = ContourAdmission {
        artifact_bytes: component.clone(),
        wit_bytes: GUEST_WIT.to_vec(),
        configuration_bytes: JOINED_COMPONENT_CONFIGURATION.to_vec(),
        admitted_artifact: admitted_gen.artifact_digest().clone(),
        admitted_wit: admitted_gen.wit_digest().clone(),
        admitted_world: admitted_gen.world().to_owned(),
        admitted_target: admitted_gen.target().to_owned(),
    };
    let promotion = must(PromotionExpectations::for_component(
        CONFORMANCE_COMPONENT,
        &framed,
        CONFORMANCE_SEED,
    ));
    let admission = must(GovernorWasmAdmission::from_owners(
        &snapshot,
        manifest,
        &contour,
        generation_fixture(
            &fence,
            &eliot_contracts::sha256_hex(&component),
            ModuleGenerationState::Ready,
        ),
        lease_fixture(&fence),
        must(OwnerId::new(OWNER)),
        must(WorkUnitId::new(WORK_UNIT)),
        scope_fixture(),
        assurance_fixture(&fence),
        limits.clone(),
        must(Revision::new(1)),
        must(Revision::new(1)),
        must(Revision::new(1)),
        BTreeSet::new(),
        BTreeSet::new(),
        promotion.clone(),
    ));
    // Fence and epoch come from recovery state, never threading.
    assert_eq!(admission.admitted_fence(), &fence);
    assert!(
        admission
            .authority_epoch()
            .is_same_authority(&snapshot.authority_epoch)
    );

    // Whole real invocations until a genuinely Succeeded result lands: the
    // P03 reap races the child, so transient Unknown is retried while any
    // Rejected verdict aborts immediately (fail-closed under scheduling
    // variance). The deadline panics — a pass is never manufactured.
    let deadline = Instant::now() + Duration::from_mins(2);
    let mut attempts = 0_u32;
    loop {
        attempts += 1;
        let operation_id = format!("join-1956-succeed-{attempts}");
        let mut authority = test_authority();
        let request_fence = must(FencingToken::new(
            test_epoch(),
            must(Generation::new(1)),
            format!("fence-{operation_id}"),
        ));
        let staged = admitted_request(
            &mut authority,
            &operation_id,
            request_fence.clone(),
            &limits,
        );
        let executor = Arc::new(WindowsProcessExecutor::new(Arc::new(FakePort::new(
            authority,
            request_fence,
        ))));
        let sink = Arc::new(RecordingSink::default());
        let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
        let process_port = WasmP03ProcessAdapter::new(Arc::clone(&executor), Arc::clone(&sink_dyn));
        must(process_port.stage_admitted_request(staged));
        let verify_port = WasmP03ProcessAdapter::new(executor, sink_dyn);
        let slotted_engine = must(
            eliot_wasm_host::WasmtimeComponentEngine::new(
                engine_binding.clone(),
                component_digest.clone(),
                &component,
                JOINED_COMPONENT_CONFIGURATION,
            )
            .map_err(|error| format!("{error:?}")),
        );
        let ports = RuntimePorts::new(
            Box::new(admission.clone()),
            Box::new(admission.clone()),
            Box::new(admission.clone()),
            Box::new(admission.clone()),
            Box::new(process_port),
            Box::new(verify_port),
            Box::new(slotted_engine),
        );
        let invoked_engine = must(
            eliot_wasm_host::WasmtimeComponentEngine::new(
                engine_binding.clone(),
                component_digest.clone(),
                &component,
                JOINED_COMPONENT_CONFIGURATION,
            )
            .map_err(|error| format!("{error:?}")),
        );
        let mut runner = must(WasmHostRunner::with_wasmtime_engine(
            test_profile(),
            test_runtime(),
            ports,
            invoked_engine,
        ));
        let request = attempt_request(&operation_id, ExecutionContour::Conformance, framed.clone());
        let result = match runner.execute_admitted(&admitted_gen, request) {
            Ok(result) => result,
            Err(error) => panic!("contour gate refused a WASM admission: {error}"),
        };
        match result.receipt.disposition {
            InvocationDisposition::Succeeded => {
                assert_eq!(result.receipt.error, None);
                assert_eq!(result.output, Some(reference.result.clone()));
                assert_eq!(
                    Sha256Digest::of_bytes(must(
                        result.output.as_deref().ok_or("output present on success")
                    )),
                    promotion.expected_result_digest,
                    "guest output must equal the oracle image over the framed input",
                );
                assert_eq!(
                    result.receipt.output_digest,
                    Some(Sha256Digest::of_bytes(&reference.result)),
                );
                assert!(result.proposed_effects.is_empty());
                assert_eq!(result.observed_state_delta, Some(Vec::new()));
                let bound = must(
                    result
                        .receipt
                        .engine_binding
                        .as_ref()
                        .ok_or("success binds the engine identity"),
                );
                assert_eq!(bound.implementation_id, "wasmtime-component");
                assert_eq!(bound.exact_version, "47.0.4");
                assert_eq!(
                    bound.engine_artifact_digest,
                    Sha256Digest::of_bytes(ENGINE_IDENTITY)
                );
                assert_eq!(
                    bound.wit_interface_digest,
                    Sha256Digest::of_bytes(GUEST_WIT)
                );
                assert_eq!(
                    bound.engine_configuration_digest,
                    provider_configuration_digest()
                );
                assert_eq!(bound, &engine_binding);
                return;
            }
            InvocationDisposition::Unknown => {
                assert_eq!(
                    result.receipt.error,
                    Some(RuntimeError::UnknownOutcome),
                    "transient attempts may only be unknown, never rejected"
                );
            }
            unexpected => {
                panic!(
                    "fail-closed violation on attempt {attempts}: {unexpected:?} {:?}",
                    result.receipt.error
                );
            }
        }
        assert!(attempts < 200, "bounded attempts exhausted");
        assert!(
            Instant::now() <= deadline,
            "no Succeeded joined execution within 2 minutes"
        );
    }
}

/// Composes one full runner for negative proofs: the admission (and optional
/// foreign authority override) plus an optionally staged P03 slot and two
/// real engines (slotted, then rebound — both compiled from real bytes).
#[allow(clippy::too_many_arguments)]
fn compose_negative(
    admission: GovernorWasmAdmission,
    authority_admission: Option<GovernorWasmAdmission>,
    stage_operation_id: Option<String>,
    slot_artifact: &[u8],
    invoked_artifact: &[u8],
    limits: &InvocationLimits,
    engine_binding: &EngineBinding,
) -> (WasmHostRunner, AdmittedGeneration) {
    let (executor, staged) = if let Some(operation_id) = stage_operation_id {
        let mut authority = test_authority();
        let fence = must(FencingToken::new(
            test_epoch(),
            must(Generation::new(1)),
            format!("fence-{operation_id}"),
        ));
        let staged = admitted_request(&mut authority, &operation_id, fence.clone(), limits);
        let executor = Arc::new(WindowsProcessExecutor::new(Arc::new(FakePort::new(
            authority, fence,
        ))));
        (executor, Some(staged))
    } else {
        let authority = test_authority();
        let fence = must(FencingToken::new(
            test_epoch(),
            must(Generation::new(1)),
            "fence-unstaged".to_owned(),
        ));
        let executor = Arc::new(WindowsProcessExecutor::new(Arc::new(FakePort::new(
            authority, fence,
        ))));
        (executor, None)
    };
    let sink = Arc::new(RecordingSink::default());
    let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
    let process_port = WasmP03ProcessAdapter::new(Arc::clone(&executor), Arc::clone(&sink_dyn));
    if let Some(staged) = staged {
        must(process_port.stage_admitted_request(staged));
    }
    let verify_port = WasmP03ProcessAdapter::new(executor, sink_dyn);
    let slot_digest = Sha256Digest::of_bytes(slot_artifact);
    let slot_engine = must(
        WasmtimeComponentEngine::new(
            engine_binding.clone(),
            slot_digest,
            slot_artifact,
            JOINED_COMPONENT_CONFIGURATION,
        )
        .map_err(|error| format!("{error:?}")),
    );
    let invoked_digest = Sha256Digest::of_bytes(invoked_artifact);
    let invoked_engine = must(
        WasmtimeComponentEngine::new(
            engine_binding.clone(),
            invoked_digest,
            invoked_artifact,
            JOINED_COMPONENT_CONFIGURATION,
        )
        .map_err(|error| format!("{error:?}")),
    );
    let authority_box = authority_admission.unwrap_or_else(|| admission.clone());
    let source = admission.clone();
    let promotion = admission.clone();
    let ports = RuntimePorts::new(
        Box::new(admission),
        Box::new(authority_box),
        Box::new(source),
        Box::new(promotion),
        Box::new(process_port),
        Box::new(verify_port),
        Box::new(slot_engine),
    );
    let runner = must(WasmHostRunner::with_wasmtime_engine(
        test_profile(),
        test_runtime(),
        ports,
        invoked_engine,
    ));
    let admitted = host_admission_for(slot_artifact, limits);
    (runner, admitted)
}

/// Host admission binding exactly the given artifact digest (no hashing
/// here — the Governor factory re-hashes the bytes itself).
fn host_admission_for(artifact: &[u8], limits: &InvocationLimits) -> AdmittedGeneration {
    let digest = Sha256Digest::of_bytes(artifact);
    host_admission(&digest, limits)
}

/// Standard joined admission parts: snapshot fence shared by generation,
/// lease, and assurance (single snapshot), framed-input promotion.
struct NegativeParts {
    snapshot: KernelGenerationSnapshot,
    manifest: ComponentManifest,
    contour_bytes: Vec<u8>,
    generation: ModuleGeneration,
    promotion: PromotionExpectations,
    limits: InvocationLimits,
    engine_binding: EngineBinding,
}

fn negative_parts(artifact: &[u8]) -> NegativeParts {
    let manifest_digest = Sha256Digest::of_bytes(artifact);
    let engine_binding = joined_engine_binding();
    let limits = joined_limits(&manifest_digest);
    let configuration_digest = Sha256Digest::of_bytes(JOINED_COMPONENT_CONFIGURATION);
    let manifest = joined_manifest(&manifest_digest, &engine_binding, &configuration_digest);
    let snapshot = snapshot_fixture();
    let fence = snapshot.state_fence();
    let framed = framed_input();
    let promotion = must(PromotionExpectations::for_component(
        CONFORMANCE_COMPONENT,
        &framed,
        CONFORMANCE_SEED,
    ));
    let generation = generation_fixture(
        &fence,
        &eliot_contracts::sha256_hex(artifact),
        ModuleGenerationState::Ready,
    );
    NegativeParts {
        snapshot,
        manifest,
        contour_bytes: artifact.to_vec(),
        generation,
        promotion,
        limits,
        engine_binding,
    }
}

fn admit_negative(parts: &NegativeParts) -> GovernorWasmAdmission {
    let fence = parts.snapshot.state_fence();
    must(GovernorWasmAdmission::from_owners(
        &parts.snapshot,
        parts.manifest.clone(),
        &ContourAdmission {
            artifact_bytes: parts.contour_bytes.clone(),
            wit_bytes: GUEST_WIT.to_vec(),
            configuration_bytes: JOINED_COMPONENT_CONFIGURATION.to_vec(),
            admitted_artifact: parts.manifest.artifact_digest.clone(),
            admitted_wit: parts.manifest.interface_digest.clone(),
            admitted_world: parts.manifest.world.as_str().to_owned(),
            admitted_target: parts.manifest.guest_target.clone(),
        },
        parts.generation.clone(),
        lease_fixture(&fence),
        must(OwnerId::new(OWNER)),
        must(WorkUnitId::new(WORK_UNIT)),
        scope_fixture(),
        assurance_fixture(&fence),
        parts.limits.clone(),
        must(Revision::new(1)),
        must(Revision::new(1)),
        must(Revision::new(1)),
        BTreeSet::new(),
        BTreeSet::new(),
        parts.promotion.clone(),
    ))
}

/// Foreign authority admission: coherent standalone, but bound to a
/// different work unit, so the genuine request is denied at the authority
/// port before any P03 or engine contact.
fn foreign_authority_admission(parts: &NegativeParts) -> GovernorWasmAdmission {
    let fence = parts.snapshot.state_fence();
    let mut scope = scope_fixture();
    scope.attempt_ref = Some("work-foreign".to_owned());
    must(GovernorWasmAdmission::new(
        fence.clone(),
        test_epoch(),
        parts.manifest.clone(),
        parts.generation.clone(),
        lease_fixture(&fence),
        must(OwnerId::new(OWNER)),
        must(WorkUnitId::new("work-foreign")),
        scope,
        assurance_fixture(&fence),
        parts.limits.clone(),
        must(Revision::new(1)),
        must(Revision::new(1)),
        must(Revision::new(1)),
        BTreeSet::new(),
        BTreeSet::new(),
        parts.promotion.clone(),
    ))
}

fn divergent_bytes() -> Vec<u8> {
    match wat::parse_file("tests/fixtures/guest-conformance-divergent.wat") {
        Ok(bytes) => bytes,
        Err(error) => panic!("joined proof divergent fixture unreadable: {error}"),
    }
}

#[test]
fn divergent_fixture_is_denied_before_effects() {
    let component = component_bytes();
    let divergent = divergent_bytes();
    let divergent_digest = Sha256Digest::of_bytes(&divergent);
    assert_ne!(
        divergent_digest,
        Sha256Digest::of_bytes(&component),
        "fixtures must genuinely differ"
    );
    // Manifest claims the divergent bytes; the engine is compiled from the
    // conformance bytes. The engine denies the mismatch before any guest
    // executes, and the runtime reports unknown — never success.
    let parts = negative_parts(&divergent);
    let mut limits = parts.limits.clone();
    limits
        .artifact_access
        .allowed_digests
        .insert(Sha256Digest::of_bytes(&component));
    let admission = admit_negative(&parts);
    let (mut runner, admitted) = compose_negative(
        admission,
        None,
        Some("join-1956-divergent".to_owned()),
        &component,
        &component,
        &limits,
        &parts.engine_binding,
    );
    let request = attempt_request(
        "join-1956-divergent",
        ExecutionContour::Conformance,
        framed_input(),
    );
    let result = must(
        runner
            .execute_admitted(&admitted, request)
            .map_err(|error| format!("contour gate fired instead of engine denial: {error}")),
    );
    assert_eq!(result.receipt.disposition, InvocationDisposition::Unknown);
    assert_eq!(result.receipt.error, Some(RuntimeError::UnknownOutcome));
    assert_eq!(result.output, None);
}

#[test]
fn foreign_authority_is_rejected_before_process_or_engine() {
    let parts = negative_parts(&component_bytes());
    let admission = admit_negative(&parts);
    let foreign = foreign_authority_admission(&parts);
    // The P03 slot stays empty on purpose: reaching `prepare` would surface
    // `Unavailable`/`PlanGap`, so `AuthorityDenied` proves the denial lands
    // at the authority port, before any process or engine contact.
    let (mut runner, admitted) = compose_negative(
        admission,
        Some(foreign),
        None,
        &component_bytes(),
        &component_bytes(),
        &parts.limits,
        &parts.engine_binding,
    );
    let request = attempt_request(
        "join-1956-foreign-authority",
        ExecutionContour::Conformance,
        framed_input(),
    );
    let result = must(
        runner
            .execute_admitted(&admitted, request)
            .map_err(|error| format!("unexpected contour refusal: {error}")),
    );
    assert_eq!(result.receipt.disposition, InvocationDisposition::Rejected);
    assert_eq!(result.receipt.error, Some(RuntimeError::AuthorityDenied));
}

#[test]
fn non_wasm_admission_is_refused_before_a12() {
    let parts = negative_parts(&component_bytes());
    let native = must(PrototypeContourDecision::select_native_process(
        "needs raw USB scan",
    ));
    let manifest = GenerationManifest {
        target: STANDARD_GUEST_TARGET.to_owned(),
        artifact_digest: Sha256Digest::of_bytes(&component_bytes()),
        wit_digest: Sha256Digest::of_bytes(GUEST_WIT),
        world: "eliot:wasm/guest".to_owned(),
        allowed_imports: Vec::new(),
        allowed_exports: vec!["run".to_owned()],
        capability_grants: Vec::new(),
        limits: parts.limits.clone(),
        state_class: "stateless".to_owned(),
        migration_contract: "none".to_owned(),
        privacy_policy: "project_code".to_owned(),
        comparator: "shadow-exact".to_owned(),
        rollback_generation: None,
    };
    let admitted = must(admit_generation(Some(&native), &manifest, &[]));
    let mut runner = must(
        WasmHostRunner::new(test_profile(), test_runtime(), WasmRuntime::new(None))
            .map_err(|error| format!("{error:?}")),
    );
    let request = attempt_request(
        "join-1956-non-wasm",
        ExecutionContour::Conformance,
        framed_input(),
    );
    let Err(error) = runner.execute_admitted(&admitted, request) else {
        panic!("native contour executed on the WASM host")
    };
    assert_eq!(
        error.to_string(),
        "CONTOUR_NOT_SERVED_HERE:ISOLATED_NATIVE_PROCESS"
    );
}

#[test]
fn rotated_fence_is_denied_before_engine() {
    let parts = negative_parts(&component_bytes());
    let fence = parts.snapshot.state_fence();
    let mut rotated = fence.clone();
    rotated.resource_generation = must(eliot_contracts::ResourceGeneration::new(2));
    // Observations from a different snapshot never compose: construction
    // itself denies, so no engine is ever contacted.
    let denied = GovernorWasmAdmission::new(
        fence,
        test_epoch(),
        parts.manifest.clone(),
        generation_fixture(
            &rotated,
            &eliot_contracts::sha256_hex(&component_bytes()),
            ModuleGenerationState::Ready,
        ),
        lease_fixture(&rotated),
        must(OwnerId::new(OWNER)),
        must(WorkUnitId::new(WORK_UNIT)),
        scope_fixture(),
        assurance_fixture(&rotated),
        parts.limits.clone(),
        must(Revision::new(1)),
        must(Revision::new(1)),
        must(Revision::new(1)),
        BTreeSet::new(),
        BTreeSet::new(),
        parts.promotion.clone(),
    );
    assert_eq!(denied.map(|_| ()), Err(PortError::Denied));

    // A sealed request whose bytes are tampered after sealing breaks the
    // request digest: validation rejects before any port binding check.
    let admission = admit_negative(&parts);
    let (mut runner, admitted) = compose_negative(
        admission,
        None,
        None,
        &component_bytes(),
        &component_bytes(),
        &parts.limits,
        &parts.engine_binding,
    );
    let mut request = attempt_request(
        "join-1956-tampered",
        ExecutionContour::Conformance,
        framed_input(),
    );
    request.input.push(0xFF);
    let result = must(
        runner
            .execute_admitted(&admitted, request)
            .map_err(|error| format!("unexpected contour refusal: {error}")),
    );
    assert_eq!(result.receipt.disposition, InvocationDisposition::Rejected);
    assert_eq!(
        result.receipt.error,
        Some(RuntimeError::RequestDigestMismatch)
    );
}

#[test]
fn active_contour_denies_rejected_lifecycle_verdicts() {
    // Conformance ignores verdicts and admits (positive proof); Active
    // requires verified shadow + canary + rollback + cutover. All verdicts
    // stay Rejected until lifecycle evidence is threaded (A13.3), so the
    // high contour denies while the low contour admits — conformance and
    // lifecycle promotion are distinct.
    let parts = negative_parts(&component_bytes());
    let fence = parts.snapshot.state_fence();
    let mut active_generation = parts.generation.clone();
    active_generation.state = ModuleGenerationState::Active;
    let admission = must(GovernorWasmAdmission::from_owners(
        &parts.snapshot,
        parts.manifest.clone(),
        &ContourAdmission {
            artifact_bytes: parts.contour_bytes.clone(),
            wit_bytes: GUEST_WIT.to_vec(),
            configuration_bytes: JOINED_COMPONENT_CONFIGURATION.to_vec(),
            admitted_artifact: parts.manifest.artifact_digest.clone(),
            admitted_wit: parts.manifest.interface_digest.clone(),
            admitted_world: parts.manifest.world.as_str().to_owned(),
            admitted_target: parts.manifest.guest_target.clone(),
        },
        active_generation,
        lease_fixture(&fence),
        must(OwnerId::new(OWNER)),
        must(WorkUnitId::new(WORK_UNIT)),
        scope_fixture(),
        assurance_fixture(&fence),
        parts.limits.clone(),
        must(Revision::new(1)),
        must(Revision::new(1)),
        must(Revision::new(1)),
        BTreeSet::new(),
        BTreeSet::new(),
        parts.promotion.clone(),
    ));
    // Promotion fails before P03: the empty slot proves `prepare` is never
    // reached — `PromotionDenied`, not `PlanGap`.
    let (mut runner, admitted) = compose_negative(
        admission,
        None,
        None,
        &component_bytes(),
        &component_bytes(),
        &parts.limits,
        &parts.engine_binding,
    );
    let request = attempt_request("join-1956-active", ExecutionContour::Active, framed_input());
    let result = must(
        runner
            .execute_admitted(&admitted, request)
            .map_err(|error| format!("unexpected contour refusal: {error}")),
    );
    assert_eq!(result.receipt.disposition, InvocationDisposition::Rejected);
    assert_eq!(result.receipt.error, Some(RuntimeError::PromotionDenied));
}

#[test]
fn bare_corpus_against_framed_execution_is_rejected() {
    // The Governor unit corpus covers the bare `lc-wasm-1956` bytes, but no
    // input makes the seed-prefix guest emit that oracle image — the
    // differential gate honestly rejects. This pins why the joined vector
    // threads the framed-input corpus instead.
    let parts = negative_parts(&component_bytes());
    let fence = parts.snapshot.state_fence();
    let bare = must(PromotionExpectations::conformance());
    let admission = must(GovernorWasmAdmission::from_owners(
        &parts.snapshot,
        parts.manifest.clone(),
        &ContourAdmission {
            artifact_bytes: parts.contour_bytes.clone(),
            wit_bytes: GUEST_WIT.to_vec(),
            configuration_bytes: JOINED_COMPONENT_CONFIGURATION.to_vec(),
            admitted_artifact: parts.manifest.artifact_digest.clone(),
            admitted_wit: parts.manifest.interface_digest.clone(),
            admitted_world: parts.manifest.world.as_str().to_owned(),
            admitted_target: parts.manifest.guest_target.clone(),
        },
        parts.generation.clone(),
        lease_fixture(&fence),
        must(OwnerId::new(OWNER)),
        must(WorkUnitId::new(WORK_UNIT)),
        scope_fixture(),
        assurance_fixture(&fence),
        parts.limits.clone(),
        must(Revision::new(1)),
        must(Revision::new(1)),
        must(Revision::new(1)),
        BTreeSet::new(),
        BTreeSet::new(),
        bare,
    ));
    let (mut runner, admitted) = compose_negative(
        admission,
        None,
        Some("join-1956-bare-corpus".to_owned()),
        &component_bytes(),
        &component_bytes(),
        &parts.limits,
        &parts.engine_binding,
    );
    let request = attempt_request(
        "join-1956-bare-corpus",
        ExecutionContour::Conformance,
        framed_input(),
    );
    let result = must(
        runner
            .execute_admitted(&admitted, request)
            .map_err(|error| format!("unexpected contour refusal: {error}")),
    );
    assert_eq!(result.receipt.disposition, InvocationDisposition::Rejected);
    assert_eq!(
        result.receipt.error,
        Some(RuntimeError::DifferentialMismatch)
    );
}
