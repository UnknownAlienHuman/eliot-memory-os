use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use eliot_observation_contracts::ObservationScope;
use eliot_process::{
    ActionLeaseRef, CancellationReceipt, CancellationRequest, DescendantEvidence,
    DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
    EnvironmentInheritance, EnvironmentProjection, ExitDisposition, ExitStatus, FencingToken,
    Generation, ImageId, JobId, KernelDispatchKey, OperationId, PermitIssuance,
    PhysicalProcessBinding, ProcessEvidence, ProcessHealth, ProcessHealthStatus, ProcessId,
    ProcessIntent, ProcessLifecycle, ProcessRequest, ProcessStartReceipt, ProcessState,
    ProcessTreeId, ResourceLimits as ProcessLimits, SessionId, SuspendedProcessIdentity,
};
use eliot_runtime_contracts::{ModuleGeneration, RuntimeLease};
use eliot_security_contracts::{PrivacyClass, SourceAssurance};
use serde_json::json;

use crate::*;

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("fixture result failed: {error:?}"),
    }
}

fn must_some<T>(value: Option<T>) -> T {
    match value {
        Some(value) => value,
        None => panic!("fixture value was unexpectedly absent"),
    }
}

fn lock_state(state: &Mutex<MockState>) -> std::sync::MutexGuard<'_, MockState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn digest(character: char) -> Sha256Digest {
    must(Sha256Digest::new(character.to_string().repeat(64)))
}

fn binding() -> EngineBinding {
    EngineBinding {
        implementation_id: "engine.test.v1".to_owned(),
        exact_version: "1.2.3".to_owned(),
        engine_artifact_digest: digest('8'),
        engine_configuration_digest: digest('9'),
        wit_interface_digest: digest('b'),
    }
}

fn manifest() -> ComponentManifest {
    ComponentManifest {
        component_id: must(CapabilityId::new("component-1")),
        world: must(CapabilityId::new("eliot:test/world")),
        wit_version: "1.0.0".to_owned(),
        guest_target: DEFAULT_GUEST_TARGET.to_owned(),
        artifact_digest: digest('a'),
        interface_digest: digest('b'),
        source_digest: digest('c'),
        configuration_digest: digest('d'),
        state_contract_digest: digest('e'),
        imports: [must(CapabilityId::new("log"))].into_iter().collect(),
        exports: [must(CapabilityId::new("run"))].into_iter().collect(),
        admitted_privacy_classes: vec![PrivacyClass::Internal],
        required_verifier: "verifier:a12".to_owned(),
        engine: binding(),
    }
}

fn module_generation() -> ModuleGeneration {
    must(serde_json::from_value(json!({
        "module_id": "component-1",
        "generation": 1,
        "artifact_id": "a".repeat(64),
        "state": "READY",
        "health": {
            "liveness": "HEALTHY", "readiness": "HEALTHY",
            "freshness": "HEALTHY", "compatibility": "HEALTHY",
            "integrity": "HEALTHY", "capacity": "HEALTHY"
        },
        "state_fence": {
            "authority_epoch": 1, "resource_generation": 1,
            "task_revision": 1, "policy_revision": 1,
            "integration_revision": null
        }
    })))
}

fn work_scope() -> ObservationScope {
    must(serde_json::from_value(json!({
        "work_scope": "scope-1", "task_ref": "task-1",
        "attempt_ref": "work-1", "module_or_route_ref": "component-1"
    })))
}

fn lease() -> RuntimeLease {
    must(serde_json::from_value(json!({
        "lease_id": "lease-1", "scope_ref": "scope-1", "authority_epoch": 1,
        "state_fence": {
            "authority_epoch": 1, "resource_generation": 1,
            "task_revision": 1, "policy_revision": 1,
            "integration_revision": null
        },
        "state": "ACTIVE"
    })))
}

fn source_assurance() -> SourceAssurance {
    must(serde_json::from_value(json!({
        "source_ref": "source-1", "provenance_ref": "provenance-1",
        "integrity": "VERIFIED", "freshness": "CURRENT",
        "competence": "DOMAIN_VERIFIED", "independence": "INDEPENDENT",
        "privacy_class": "INTERNAL", "instruction_taint": "DATA_ONLY",
        "allowed_epistemic_use": ["VERIFICATION_INPUT"],
        "allowed_effects": ["NO_EXTERNAL_EFFECT"],
        "required_verifier": "verifier:a12", "quarantine": "NONE",
        "state_fence": {
            "authority_epoch": 1, "resource_generation": 1,
            "task_revision": 1, "policy_revision": 1,
            "integration_revision": null
        }
    })))
}

fn limits() -> InvocationLimits {
    InvocationLimits {
        max_input_bytes: 128,
        max_output_bytes: 128,
        max_host_calls: 4,
        max_fuel: 1_000,
        max_memory_bytes: 65_536,
        max_table_elements: 64,
        max_instances: 2,
        max_stack_bytes: 8_192,
        wall_deadline_ms: 500,
        epoch: EpochPolicy {
            deadline_ticks: 50,
            cancellation: CancellationPolicy::EpochAndFuel,
        },
        artifact_access: ArtifactAccessLimits {
            allowed_digests: [digest('a')].into_iter().collect(),
            max_reads: 2,
            max_bytes: 1_024,
        },
    }
}

fn request() -> InvocationRequest {
    must(InvocationRequest::new(
        must(InvocationId::new("invoke-1")),
        must(CapabilityId::new("component-1")),
        must(WorkUnitId::new("work-1")),
        must(WorkScopeRef::new("scope-1")),
        ExecutionContour::Conformance,
        vec![1, 2, 3],
        7,
        false,
    ))
}

fn request_with_id(id: usize) -> InvocationRequest {
    let mut request = request();
    request.invocation_id = must(InvocationId::new(format!("invoke-{id}")));
    must(request.refresh_digest());
    request
}

#[derive(Clone)]
struct ReportSpec {
    termination: EngineTermination,
    output: Vec<u8>,
    effects: Vec<EffectProposal>,
    state_delta: Vec<u8>,
    post_commit_known: bool,
    over_meter: bool,
    effective_epoch_policy: Option<EpochPolicy>,
    epoch_ticks: u64,
}

impl ReportSpec {
    fn success() -> Self {
        Self {
            termination: EngineTermination::Completed,
            output: vec![4, 5],
            effects: Vec::new(),
            state_delta: vec![6],
            post_commit_known: true,
            over_meter: false,
            effective_epoch_policy: None,
            epoch_ticks: 10,
        }
    }

    fn terminated(termination: EngineTermination) -> Self {
        Self {
            termination,
            ..Self::success()
        }
    }
}

#[derive(Clone, Copy)]
enum InvalidLimit {
    Table,
    Instance,
    Stack,
    Epoch,
    ArtifactReads,
    ArtifactBytes,
    ArtifactDigest,
}

#[derive(Clone)]
#[allow(clippy::struct_excessive_bools)]
struct Config {
    governor_error: Option<PortError>,
    authority_error: Option<PortError>,
    source_error: Option<PortError>,
    promotion_error: Option<PortError>,
    execution_verify_error: Option<PortError>,
    process_prepare_invalid: bool,
    process_start_error: Option<PortError>,
    reject_start_receipt: bool,
    cancel_receipt_mismatch: bool,
    reject_cancel_receipt: bool,
    reject_reconcile_evidence: bool,
    process_reaped: bool,
    invalid_limit: Option<InvalidLimit>,
    stale_source: bool,
    promotion_mismatch: bool,
    report: ReportSpec,
    reconcile_report: ReportSpec,
    reconcile_error: Option<PortError>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            governor_error: None,
            authority_error: None,
            source_error: None,
            promotion_error: None,
            execution_verify_error: None,
            process_prepare_invalid: false,
            process_start_error: None,
            reject_start_receipt: false,
            cancel_receipt_mismatch: false,
            reject_cancel_receipt: false,
            reject_reconcile_evidence: false,
            process_reaped: true,
            invalid_limit: None,
            stale_source: false,
            promotion_mismatch: false,
            report: ReportSpec::success(),
            reconcile_report: ReportSpec::success(),
            reconcile_error: None,
        }
    }
}

#[derive(Default)]
struct MockState {
    process_start_calls: usize,
    cancel_calls: usize,
    engine_calls: usize,
    process: Option<ProcessState>,
    last_invocation: Option<EngineInvocation>,
}

struct GovernorMock {
    config: Config,
}

impl GovernorResolutionPort for GovernorMock {
    fn resolve(&mut self, _request: &InvocationRequest) -> Result<GovernorResolution, PortError> {
        if let Some(error) = self.config.governor_error {
            return Err(error);
        }
        let mut resolved_limits = limits();
        match self.config.invalid_limit {
            Some(InvalidLimit::Table) => resolved_limits.max_table_elements = 0,
            Some(InvalidLimit::Instance) => resolved_limits.max_instances = 0,
            Some(InvalidLimit::Stack) => resolved_limits.max_stack_bytes = 0,
            Some(InvalidLimit::Epoch) => resolved_limits.epoch.deadline_ticks = 0,
            Some(InvalidLimit::ArtifactReads) => resolved_limits.artifact_access.max_reads = 0,
            Some(InvalidLimit::ArtifactBytes) => resolved_limits.artifact_access.max_bytes = 0,
            Some(InvalidLimit::ArtifactDigest) => {
                resolved_limits.artifact_access.allowed_digests.clear();
            }
            None => {}
        }
        Ok(GovernorResolution {
            manifest: manifest(),
            generation: module_generation(),
            lease: lease(),
            authority_revision: must(Revision::new(1)),
            lifecycle_revision: must(Revision::new(1)),
            limits: resolved_limits,
            resolution_receipt_digest: digest('2'),
        })
    }
}

struct AuthorityMock {
    config: Config,
}

impl AuthorityResolutionPort for AuthorityMock {
    fn resolve(&mut self, _request: &InvocationRequest) -> Result<AuthorityResolution, PortError> {
        if let Some(error) = self.config.authority_error {
            return Err(error);
        }
        Ok(AuthorityResolution {
            owner: must(OwnerId::new("owner-1")),
            work_unit: must(WorkUnitId::new("work-1")),
            work_scope: work_scope(),
            allowed_host_calls: [must(CapabilityId::new("log"))].into_iter().collect(),
            allowed_effect_proposals: BTreeSet::new(),
            resolution_receipt_digest: digest('3'),
        })
    }
}

struct SourceMock {
    config: Config,
}

impl SourceVerificationPort for SourceMock {
    fn verify(&mut self, _request: &InvocationRequest) -> Result<SourceVerification, PortError> {
        if let Some(error) = self.config.source_error {
            return Err(error);
        }
        let mut assurance = source_assurance();
        if self.config.stale_source {
            assurance.state_fence.task_revision = None;
        }
        Ok(SourceVerification {
            assurance,
            verification_revision: must(Revision::new(1)),
            verification_receipt_digest: digest('4'),
        })
    }
}

struct PromotionMock {
    config: Config,
}

impl PromotionVerificationPort for PromotionMock {
    fn verify(&mut self, _query: &PromotionQuery) -> Result<PromotionVerification, PortError> {
        if let Some(error) = self.config.promotion_error {
            return Err(error);
        }
        Ok(PromotionVerification {
            corpus_digest: digest('f'),
            expected_result_digest: if self.config.promotion_mismatch {
                digest('7')
            } else {
                Sha256Digest::of_bytes(&[4, 5])
            },
            expected_effect_digest: must(canonical_digest(&Vec::<EffectProposal>::new())),
            expected_state_delta_digest: Sha256Digest::of_bytes(&[6]),
            verification_revision: must(Revision::new(1)),
            shadow: VerificationVerdict::Verified,
            canary: VerificationVerdict::Verified,
            rollback: VerificationVerdict::Verified,
            cutover: VerificationVerdict::Verified,
            verification_receipt_digest: digest('5'),
        })
    }

    fn verify_execution(
        &mut self,
        invocation: &EngineInvocation,
        report: &EngineReport,
        derived: &DerivedExecutionEvidence,
    ) -> Result<(), PortError> {
        if let Some(error) = self.config.execution_verify_error {
            return Err(error);
        }
        let exact = invocation.imports == invocation.manifest.imports
            && invocation.exports == invocation.manifest.exports
            && invocation.generation.state_fence == invocation.lease.state_fence
            && invocation.source_assurance.state_fence == invocation.generation.state_fence
            && invocation.conformance_corpus_digest == digest('f')
            && invocation.governor_resolution_receipt_digest == digest('2')
            && invocation.authority_resolution_receipt_digest == digest('3')
            && invocation.source_verification_receipt_digest == digest('4')
            && invocation.promotion_verification_receipt_digest == digest('5')
            && invocation.state_contract_digest == invocation.manifest.state_contract_digest
            && derived.result_digest == Sha256Digest::of_bytes(&report.output)
            && derived.effect_digest == must(canonical_digest(&report.proposed_effects))
            && derived.state_delta_digest == Sha256Digest::of_bytes(&report.observed_state_delta);
        if exact {
            Ok(())
        } else {
            Err(PortError::Denied)
        }
    }
}

struct ProcessMock {
    config: Config,
    state: Arc<Mutex<MockState>>,
    authority: DispatchPermitAuthority,
}

impl P03ProcessPort for ProcessMock {
    fn prepare(&mut self, envelope: &ProcessLaunchEnvelope) -> Result<ProcessRequest, PortError> {
        let generation = must(Generation::new(envelope.generation.generation.value()));
        let intent = ProcessIntent::new(
            must(OperationId::new(envelope.invocation_id.as_str())),
            must(ProcessTreeId::new(if self.config.process_prepare_invalid {
                "wrong-scope"
            } else {
                "scope-1"
            })),
            must(JobId::new(format!(
                "job-{}",
                envelope.invocation_id.as_str()
            ))),
            must(ImageId::new(format!(
                "image-{}",
                envelope.invocation_id.as_str()
            ))),
            must(SessionId::new(format!(
                "session-{}",
                envelope.invocation_id.as_str()
            ))),
            generation,
            "eliot-wasm-host.exe",
            "e".repeat(64),
            Vec::new(),
            "C:\\eliot\\runtime",
            must(EnvironmentProjection::new(
                BTreeMap::new(),
                Vec::new(),
                EnvironmentInheritance::None,
            )),
            must(ProcessLimits::new(
                envelope.limits.wall_deadline_ms,
                None,
                Some(envelope.limits.max_memory_bytes),
                envelope.limits.max_output_bytes,
                envelope.limits.max_output_bytes,
                0,
            )),
        )
        .map_err(|_| PortError::Denied)?;
        let permit = self
            .authority
            .issue(
                &intent,
                must(PermitIssuance::new(
                    must(ActionLeaseRef::new(format!(
                        "process-lease-{}",
                        envelope.invocation_id.as_str()
                    ))),
                    must(FencingToken::new(
                        envelope.lease.state_fence.authority_epoch.value(),
                        generation,
                        format!("fence-{}", envelope.invocation_id.as_str()),
                    )),
                    process_revision_heads(),
                    100,
                    10_000,
                    format!("nonce-{}", envelope.invocation_id.as_str()),
                )),
            )
            .map_err(|_| PortError::Denied)?;
        ProcessRequest::new(intent, permit).map_err(|_| PortError::Denied)
    }

    fn start(&mut self, request: ProcessRequest) -> Result<ProcessStartReceipt, PortError> {
        lock_state(&self.state).process_start_calls += 1;
        if let Some(error) = self.config.process_start_error {
            return Err(error);
        }
        let observed = SuspendedProcessIdentity::new(
            ProcessId::new(format!("process-{}", request.operation_id().as_str()))
                .map_err(|_| PortError::Denied)?,
            request.process_tree_id().clone(),
            request.job_id().clone(),
            request.image_id().clone(),
            request.session_id().clone(),
            request.generation(),
            PhysicalProcessBinding::new(4242, 11, request.executable(), r"Local\Eliot-Wasm-Test")
                .map_err(|_| PortError::Denied)?,
            120,
            request.executable_sha256(),
        )
        .map_err(|_| PortError::Denied)?;
        let clock = must(serde_json::from_value(json!({
            "valid_time_ms": 150,
            "known_time_ms": 150,
            "transaction_sequence": null,
            "monotonic_ns": 1
        })));
        let context = DispatchValidationContext::new(
            clock,
            request.fence().clone(),
            request.fence().authority_epoch(),
            process_revision_heads(),
            1,
        )
        .map_err(|_| PortError::Denied)?;
        let validated = self
            .authority
            .validate_and_consume(request, observed, &context)
            .map_err(|_| PortError::Denied)?;
        let mut process = ProcessState::from_validated(&validated);
        process
            .mark_resumed(
                151,
                ProcessHealth::new(ProcessHealthStatus::Healthy, true, 151, None)
                    .map_err(|_| PortError::Denied)?,
            )
            .map_err(|_| PortError::Denied)?;
        let receipt = ProcessStartReceipt::new(&process).map_err(|_| PortError::Denied)?;
        lock_state(&self.state).process = Some(process);
        Ok(receipt)
    }

    fn cancel(&mut self, binding: &ProcessBinding) -> Result<CancellationReceipt, PortError> {
        let mut state = lock_state(&self.state);
        state.cancel_calls += 1;
        let process = state.process.as_mut().ok_or(PortError::UnknownOutcome)?;
        if !binding_matches_state(binding, process) {
            return Err(PortError::Denied);
        }
        process
            .cancel(&CancellationRequest::new(process.binding().clone()))
            .map_err(|_| PortError::UnknownOutcome)
    }

    fn reconcile(&mut self, binding: &ProcessBinding) -> Result<ProcessEvidence, PortError> {
        let mut state = lock_state(&self.state);
        let process = state.process.as_ref().ok_or(PortError::UnknownOutcome)?;
        if !binding_matches_state(binding, process) {
            return Err(PortError::Denied);
        }
        if self.config.process_reaped && process.view().lifecycle() == ProcessLifecycle::Running {
            let root = process
                .view()
                .identity()
                .ok_or(PortError::UnknownOutcome)?
                .process_id()
                .clone();
            let process_binding = process.binding().clone();
            let descendants = DescendantEvidence::new(
                process_binding,
                root.clone(),
                vec![root],
                true,
                true,
                Some("reaped".to_owned()),
            )
            .map_err(|_| PortError::UnknownOutcome)?;
            state
                .process
                .as_mut()
                .ok_or(PortError::UnknownOutcome)?
                .exit(
                    ExitStatus::new(ExitDisposition::Completed, Some(0), None, 200)
                        .map_err(|_| PortError::UnknownOutcome)?,
                    descendants,
                )
                .map_err(|_| PortError::UnknownOutcome)?;
        }
        let process = state.process.as_ref().ok_or(PortError::UnknownOutcome)?;
        let axes = must(serde_json::from_value(json!({
            "status": "OBSERVED",
            "assertability": "NON_ASSERTABLE_UNVERIFIED",
            "accessibility": "AVAILABLE",
            "influence": "ALLOWED",
            "physical": "PRESENT",
            "taint": "CLEAR"
        })));
        ProcessEvidence::new(process.view(), None, None, axes)
            .map_err(|_| PortError::UnknownOutcome)
    }
}

fn process_authority() -> DispatchPermitAuthority {
    DispatchPermitAuthority::activate(
        must(DispatchAuthorityId::new("wasm-runtime-authority")),
        must(KernelDispatchKey::from_secret_bytes([0x6b; 32])),
    )
}

fn process_revision_heads() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("authority".to_owned(), "a".repeat(64)),
        ("state".to_owned(), "b".repeat(64)),
    ])
}

fn binding_matches_state(binding: &ProcessBinding, process: &ProcessState) -> bool {
    let observed = process.binding();
    observed.operation_id() == binding.operation_id()
        && observed.process_tree_id() == binding.process_tree_id()
        && observed.request_digest() == binding.request_digest()
        && observed.state_fence().matches(binding.fence())
}

struct ReceiptVerifierMock {
    config: Config,
}

impl P03ReceiptVerifierPort for ReceiptVerifierMock {
    fn verify_start(
        &mut self,
        binding: &ProcessBinding,
        receipt: &ProcessStartReceipt,
        envelope: &ProcessLaunchEnvelope,
    ) -> Result<(), PortError> {
        if self.config.reject_start_receipt
            || receipt.operation_id() != binding.operation_id()
            || receipt.request_digest() != binding.request_digest()
            || !receipt.binding().state_fence().matches(binding.fence())
            || binding.fence().authority_epoch()
                != envelope.lease.state_fence.authority_epoch.value()
        {
            Err(PortError::Denied)
        } else {
            Ok(())
        }
    }

    fn verify_cancellation(
        &mut self,
        binding: &ProcessBinding,
        receipt: &CancellationReceipt,
        envelope: &ProcessLaunchEnvelope,
    ) -> Result<(), PortError> {
        let receipt_binding = receipt.binding();
        let exact = receipt_binding.operation_id() == binding.operation_id()
            && receipt_binding.process_tree_id() == binding.process_tree_id()
            && receipt_binding.request_digest() == binding.request_digest()
            && receipt_binding.state_fence().matches(binding.fence())
            && binding.fence().authority_epoch()
                == envelope.lease.state_fence.authority_epoch.value();
        if self.config.cancel_receipt_mismatch || self.config.reject_cancel_receipt || !exact {
            Err(PortError::Denied)
        } else {
            Ok(())
        }
    }

    fn verify_reconciliation(
        &mut self,
        binding: &ProcessBinding,
        evidence: &ProcessEvidence,
        envelope: &ProcessLaunchEnvelope,
    ) -> Result<(), PortError> {
        let evidence_binding = evidence.binding();
        let exact = evidence_binding.operation_id() == binding.operation_id()
            && evidence_binding.process_tree_id() == binding.process_tree_id()
            && evidence_binding.request_digest() == binding.request_digest()
            && evidence_binding.state_fence().matches(binding.fence())
            && binding.fence().authority_epoch()
                == envelope.lease.state_fence.authority_epoch.value();
        if self.config.reject_reconcile_evidence || !exact {
            Err(PortError::Denied)
        } else {
            Ok(())
        }
    }
}

struct EngineMock {
    config: Config,
    state: Arc<Mutex<MockState>>,
    binding: EngineBinding,
}

impl EngineMock {
    fn report(invocation: &EngineInvocation, spec: &ReportSpec) -> EngineReport {
        let output_bytes = if spec.over_meter {
            invocation.limits.max_output_bytes + 1
        } else {
            spec.output.len() as u64
        };
        EngineReport {
            request_digest: invocation.request_digest.clone(),
            termination: spec.termination,
            usage: EngineUsage {
                attempted_output_bytes: output_bytes,
                output_bytes,
                host_calls: 0,
                fuel_consumed: 10,
                peak_memory_bytes: Some(1_024),
                table_elements: Some(1),
                instances: 1,
                stack_bytes: Some(1_024),
                enforced_stack_limit_bytes: None,
                elapsed_ms: 10,
                effective_epoch_policy: spec
                    .effective_epoch_policy
                    .unwrap_or(invocation.limits.epoch),
                epoch_ticks: Some(spec.epoch_ticks),
                artifact_reads: 1,
                artifact_bytes: 64,
                accessed_artifact_digests: vec![invocation.manifest.artifact_digest.clone()],
            },
            output: spec.output.clone(),
            host_calls: Vec::new(),
            proposed_effects: spec.effects.clone(),
            observed_state_delta: spec.state_delta.clone(),
            post_commit_known: spec.post_commit_known,
        }
    }
}

impl ComponentEnginePort for EngineMock {
    fn binding(&self) -> &EngineBinding {
        &self.binding
    }

    fn invoke(&mut self, invocation: &EngineInvocation) -> Result<EngineReport, PortError> {
        let mut state = lock_state(&self.state);
        state.engine_calls += 1;
        state.last_invocation = Some(invocation.clone());
        Ok(Self::report(invocation, &self.config.report))
    }

    fn reconcile(&mut self, invocation: &EngineInvocation) -> Result<EngineReport, PortError> {
        lock_state(&self.state).engine_calls += 1;
        if let Some(error) = self.config.reconcile_error {
            return Err(error);
        }
        Ok(Self::report(invocation, &self.config.reconcile_report))
    }
}

fn runtime(config: Config) -> (WasmRuntime, Arc<Mutex<MockState>>) {
    let state = Arc::new(Mutex::new(MockState::default()));
    let ports = RuntimePorts::new(
        Box::new(GovernorMock {
            config: config.clone(),
        }),
        Box::new(AuthorityMock {
            config: config.clone(),
        }),
        Box::new(SourceMock {
            config: config.clone(),
        }),
        Box::new(PromotionMock {
            config: config.clone(),
        }),
        Box::new(ProcessMock {
            config: config.clone(),
            state: Arc::clone(&state),
            authority: process_authority(),
        }),
        Box::new(ReceiptVerifierMock {
            config: config.clone(),
        }),
        Box::new(EngineMock {
            config,
            state: Arc::clone(&state),
            binding: binding(),
        }),
    );
    (WasmRuntime::new(Some(ports)), state)
}

#[test]
fn caller_request_is_inert_without_ports_and_denial_never_reaches_process() {
    let mut no_ports = WasmRuntime::new(None);
    let unavailable = no_ports.execute(request());
    assert_eq!(
        unavailable.receipt.disposition,
        InvocationDisposition::Unavailable
    );
    assert_eq!(unavailable.receipt.error, Some(RuntimeError::PlanGap));

    let config = Config {
        governor_error: Some(PortError::Denied),
        ..Config::default()
    };
    let (mut denied_runtime, state) = runtime(config);
    let denied = denied_runtime.execute(request());
    assert_eq!(denied.receipt.error, Some(RuntimeError::AuthorityDenied));
    assert_eq!(lock_state(&state).process_start_calls, 0);
    assert_eq!(lock_state(&state).engine_calls, 0);
}

#[test]
fn p03_start_and_separate_receipt_verification_precede_engine() {
    let config = Config {
        process_prepare_invalid: true,
        ..Config::default()
    };
    let (mut invalid_request_runtime, state) = runtime(config);
    let result = invalid_request_runtime.execute(request());
    assert_eq!(
        result.receipt.error,
        Some(RuntimeError::InvalidProcessBinding)
    );
    assert_eq!(lock_state(&state).process_start_calls, 0);
    assert_eq!(lock_state(&state).engine_calls, 0);

    let config = Config {
        reject_start_receipt: true,
        ..Config::default()
    };
    let (mut runtime, state) = runtime(config);
    let result = runtime.execute(request());
    assert_eq!(result.receipt.disposition, InvocationDisposition::Unknown);
    assert_eq!(
        result.receipt.error,
        Some(RuntimeError::InvalidProcessReceipt)
    );
    assert_eq!(lock_state(&state).process_start_calls, 1);
    assert_eq!(lock_state(&state).engine_calls, 0);
}

#[test]
fn engine_receives_exact_admission_limits_and_inert_process_binding() {
    let (mut runtime, state) = runtime(Config::default());
    let result = runtime.execute(request());
    assert_eq!(result.receipt.disposition, InvocationDisposition::Succeeded);
    assert_eq!(
        result
            .receipt
            .usage
            .as_ref()
            .map(|usage| usage.effective_epoch_policy),
        Some(limits().epoch)
    );
    let state = lock_state(&state);
    let invocation = must_some(state.last_invocation.as_ref());
    assert_eq!(invocation.contour, ExecutionContour::Conformance);
    assert_eq!(invocation.imports, invocation.manifest.imports);
    assert_eq!(invocation.exports, invocation.manifest.exports);
    assert_eq!(
        invocation.generation.state_fence,
        invocation.lease.state_fence
    );
    assert_eq!(invocation.work_unit.as_str(), "work-1");
    assert_eq!(invocation.authority_revision.get(), 1);
    assert_eq!(invocation.lifecycle_revision.get(), 1);
    assert_eq!(invocation.source_verification_revision.get(), 1);
    assert_eq!(invocation.promotion_verification_revision.get(), 1);
    assert_eq!(
        invocation.source_assurance.state_fence,
        invocation.generation.state_fence
    );
    assert_eq!(invocation.conformance_corpus_digest, digest('f'));
    assert_eq!(invocation.governor_resolution_receipt_digest, digest('2'));
    assert_eq!(invocation.authority_resolution_receipt_digest, digest('3'));
    assert_eq!(invocation.source_verification_receipt_digest, digest('4'));
    assert_eq!(
        invocation.promotion_verification_receipt_digest,
        digest('5')
    );
    assert_eq!(
        invocation.state_contract_digest,
        invocation.manifest.state_contract_digest
    );
    assert!(invocation.limits.max_table_elements > 0);
    assert!(invocation.limits.max_instances > 0);
    assert!(invocation.limits.max_stack_bytes > 0);
    assert!(invocation.limits.epoch.deadline_ticks > 0);
    assert_eq!(
        invocation.process_binding.operation_id().as_str(),
        "invoke-1"
    );
    assert_eq!(
        invocation.process_start_receipt.operation_id(),
        invocation.process_binding.operation_id()
    );
    assert_eq!(
        invocation.process_start_receipt.request_digest(),
        invocation.process_binding.request_digest()
    );
    assert!(
        invocation
            .limits
            .artifact_access
            .allowed_digests
            .contains(&invocation.manifest.artifact_digest)
    );
}

#[test]
fn actual_values_are_digested_locally_and_promotion_unavailability_is_plan_gap() {
    let config = Config {
        promotion_error: Some(PortError::Unavailable),
        ..Config::default()
    };
    let (mut unavailable_runtime, state) = runtime(config);
    let unavailable = unavailable_runtime.execute(request());
    assert_eq!(unavailable.receipt.error, Some(RuntimeError::PlanGap));
    assert_eq!(lock_state(&state).process_start_calls, 0);

    let config = Config {
        promotion_mismatch: true,
        ..Config::default()
    };
    let (mut mismatch_runtime, _) = runtime(config);
    let mismatch = mismatch_runtime.execute(request());
    assert_eq!(
        mismatch.receipt.error,
        Some(RuntimeError::DifferentialMismatch)
    );

    let config = Config {
        execution_verify_error: Some(PortError::Unavailable),
        ..Config::default()
    };
    let (mut post_execution_gap_runtime, _) = runtime(config);
    let post_execution_gap = post_execution_gap_runtime.execute(request());
    assert_eq!(
        post_execution_gap.receipt.disposition,
        InvocationDisposition::Unknown
    );
    assert_eq!(
        post_execution_gap.receipt.error,
        Some(RuntimeError::PlanGap)
    );
}

#[test]
fn terminal_success_cannot_be_overwritten_by_cancel_and_replay_is_stable() {
    let original = request();
    let invocation_id = original.invocation_id.clone();
    let request_digest = original.request_digest().clone();
    let (mut runtime, state) = runtime(Config::default());
    let success = runtime.execute(original.clone());
    assert_eq!(
        runtime.cancel(&invocation_id, &request_digest),
        Err(RuntimeError::TerminalCancellationConflict)
    );
    assert_eq!(runtime.execute(original), success);
    assert_eq!(lock_state(&state).cancel_calls, 0);
}

#[test]
fn cancellation_receipt_must_bind_exact_request_and_fence() {
    let mut partial = ReportSpec::terminated(EngineTermination::Partial);
    partial.post_commit_known = false;
    let config = Config {
        cancel_receipt_mismatch: true,
        report: partial,
        ..Config::default()
    };
    let original = request();
    let invocation_id = original.invocation_id.clone();
    let request_digest = original.request_digest().clone();
    let (mut runtime, _) = runtime(config);
    assert_eq!(
        runtime.execute(original).receipt.disposition,
        InvocationDisposition::Unknown
    );
    let cancelled = must(runtime.cancel(&invocation_id, &request_digest));
    assert_eq!(
        cancelled.receipt.disposition,
        InvocationDisposition::Unknown
    );
    assert_eq!(
        cancelled.receipt.error,
        Some(RuntimeError::InvalidProcessReceipt)
    );
}

#[test]
fn unknown_start_is_single_shot_and_follow_up_uses_inert_binding() {
    let config = Config {
        process_start_error: Some(PortError::UnknownOutcome),
        ..Config::default()
    };
    let original = request();
    let invocation_id = original.invocation_id.clone();
    let request_digest = original.request_digest().clone();
    let (mut runtime, state) = runtime(config);

    let unknown = runtime.execute(original.clone());
    assert_eq!(unknown.receipt.disposition, InvocationDisposition::Unknown);
    assert_eq!(unknown.receipt.error, Some(RuntimeError::UnknownOutcome));
    assert_eq!(lock_state(&state).process_start_calls, 1);

    let cancellation = must(runtime.cancel(&invocation_id, &request_digest));
    assert_eq!(
        cancellation.receipt.disposition,
        InvocationDisposition::Unknown
    );
    assert_eq!(
        cancellation.receipt.error,
        Some(RuntimeError::UnknownOutcome)
    );
    assert_eq!(lock_state(&state).cancel_calls, 1);
    assert_eq!(runtime.execute(original), cancellation);
    assert_eq!(lock_state(&state).process_start_calls, 1);
}

#[test]
fn missing_descendant_evidence_keeps_cancellation_unknown() {
    let mut partial = ReportSpec::terminated(EngineTermination::Partial);
    partial.post_commit_known = false;
    let config = Config {
        report: partial,
        ..Config::default()
    };
    let original = request();
    let invocation_id = original.invocation_id.clone();
    let request_digest = original.request_digest().clone();
    let (mut runtime, state) = runtime(config);

    assert_eq!(
        runtime.execute(original).receipt.disposition,
        InvocationDisposition::Unknown
    );
    let cancellation = must(runtime.cancel(&invocation_id, &request_digest));
    assert_eq!(
        cancellation.receipt.disposition,
        InvocationDisposition::Unknown
    );
    assert_eq!(
        cancellation.receipt.error,
        Some(RuntimeError::UnknownOutcome)
    );
    assert_eq!(lock_state(&state).cancel_calls, 1);
}

#[test]
fn extended_table_instance_stack_epoch_and_artifact_limits_fail_closed() {
    for invalid_limit in [
        InvalidLimit::Table,
        InvalidLimit::Instance,
        InvalidLimit::Stack,
        InvalidLimit::Epoch,
        InvalidLimit::ArtifactReads,
        InvalidLimit::ArtifactBytes,
        InvalidLimit::ArtifactDigest,
    ] {
        let config = Config {
            invalid_limit: Some(invalid_limit),
            ..Config::default()
        };
        let (mut runtime, state) = runtime(config);
        let result = runtime.execute(request());
        assert_eq!(result.receipt.error, Some(RuntimeError::InvalidLimits));
        assert_eq!(lock_state(&state).process_start_calls, 0);
        assert_eq!(lock_state(&state).engine_calls, 0);
    }

    let mut invalid_cancellation = must(serde_json::to_value(limits()));
    invalid_cancellation["epoch"]["cancellation"] = json!("CALLER_CONTROLLED");
    assert!(serde_json::from_value::<InvocationLimits>(invalid_cancellation).is_err());
}

#[test]
fn effective_epoch_policy_substitution_and_excess_metering_fail_closed() {
    let expected = limits().epoch;

    let deadline_substitution = Config {
        report: ReportSpec {
            effective_epoch_policy: Some(EpochPolicy {
                deadline_ticks: expected.deadline_ticks - 1,
                cancellation: expected.cancellation,
            }),
            ..ReportSpec::success()
        },
        ..Config::default()
    };
    let (mut deadline_runtime, _) = runtime(deadline_substitution);
    assert_eq!(
        deadline_runtime.execute(request()).receipt.error,
        Some(RuntimeError::EngineContractViolation)
    );

    let cancellation_substitution = Config {
        report: ReportSpec {
            effective_epoch_policy: Some(EpochPolicy {
                deadline_ticks: expected.deadline_ticks,
                cancellation: CancellationPolicy::EpochInterruption,
            }),
            ..ReportSpec::success()
        },
        ..Config::default()
    };
    let (mut cancellation_runtime, _) = runtime(cancellation_substitution);
    assert_eq!(
        cancellation_runtime.execute(request()).receipt.error,
        Some(RuntimeError::EngineContractViolation)
    );

    let excess_ticks = Config {
        report: ReportSpec {
            epoch_ticks: expected.deadline_ticks + 1,
            ..ReportSpec::success()
        },
        ..Config::default()
    };
    let (mut excess_ticks_runtime, _) = runtime(excess_ticks);
    assert_eq!(
        excess_ticks_runtime.execute(request()).receipt.error,
        Some(RuntimeError::EngineContractViolation)
    );
}

#[test]
fn malformed_ids_digests_and_unknown_fields_fail_deserialization() {
    let value = must(serde_json::to_value(request()));
    let mut blank_id = value.clone();
    blank_id["invocation_id"] = json!("");
    assert!(serde_json::from_value::<InvocationRequest>(blank_id).is_err());
    let mut bad_digest = value.clone();
    bad_digest["request_digest"] = json!("A".repeat(64));
    assert!(serde_json::from_value::<InvocationRequest>(bad_digest).is_err());
    let mut unknown = value;
    unknown["authority"] = json!({});
    assert!(serde_json::from_value::<InvocationRequest>(unknown).is_err());
}

#[test]
fn unsupported_guest_target_remains_fail_closed() {
    let mut unsupported = manifest();
    unsupported.guest_target = "wasm32-unknown-unknown".to_owned();
    assert_eq!(
        unsupported.validate(),
        Err(RuntimeError::UnsupportedGuestTarget)
    );
}

#[test]
fn replay_conflict_is_rejected_without_second_engine_call() {
    let original = request();
    let (mut runtime, state) = runtime(Config::default());
    let success = runtime.execute(original.clone());
    let mut conflict = original.clone();
    conflict.input.push(9);
    must(conflict.refresh_digest());
    assert_eq!(
        runtime.execute(conflict).receipt.error,
        Some(RuntimeError::ReplayConflict)
    );
    assert_eq!(runtime.execute(original), success);
    assert_eq!(lock_state(&state).engine_calls, 1);
}

#[test]
fn trap_and_all_limit_terminations_remain_typed() {
    let cases = [
        (
            EngineTermination::Trap(TrapClass::GuestTrap),
            RuntimeError::Trap(TrapClass::GuestTrap),
        ),
        (EngineTermination::OutputLimit, RuntimeError::OutputLimit),
        (
            EngineTermination::HostCallLimit,
            RuntimeError::HostCallLimit,
        ),
        (
            EngineTermination::FuelExhausted,
            RuntimeError::FuelExhausted,
        ),
        (EngineTermination::MemoryLimit, RuntimeError::MemoryLimit),
        (EngineTermination::TableLimit, RuntimeError::TableLimit),
        (
            EngineTermination::InstanceLimit,
            RuntimeError::InstanceLimit,
        ),
        (EngineTermination::StackLimit, RuntimeError::StackLimit),
        (EngineTermination::Deadline, RuntimeError::Deadline),
        (
            EngineTermination::EpochDeadline,
            RuntimeError::EpochDeadline,
        ),
        (
            EngineTermination::ArtifactAccessDenied,
            RuntimeError::ArtifactAccessDenied,
        ),
        (EngineTermination::Cancelled, RuntimeError::Cancelled),
    ];
    for (termination, expected) in cases {
        let config = Config {
            report: ReportSpec::terminated(termination),
            ..Config::default()
        };
        let (mut runtime, _) = runtime(config);
        assert_eq!(runtime.execute(request()).receipt.error, Some(expected));
    }
}

#[test]
fn partial_and_post_commit_unknown_reconcile_only_after_p03_evidence() {
    for termination in [
        EngineTermination::Partial,
        EngineTermination::PostCommitUnknown,
    ] {
        let mut initial = ReportSpec::terminated(termination);
        initial.post_commit_known = false;
        let config = Config {
            report: initial,
            reconcile_report: ReportSpec::success(),
            ..Config::default()
        };
        let original = request();
        let invocation_id = original.invocation_id.clone();
        let request_digest = original.request_digest().clone();
        let (mut runtime, state) = runtime(config);
        assert_eq!(
            runtime.execute(original.clone()).receipt.disposition,
            InvocationDisposition::Unknown
        );
        let reconciled = must(runtime.reconcile(&invocation_id, &request_digest));
        assert_eq!(
            reconciled.receipt.disposition,
            InvocationDisposition::Succeeded
        );
        assert_eq!(lock_state(&state).engine_calls, 2);
        let replayed = must(runtime.reconcile(&invocation_id, &request_digest));
        assert_eq!(replayed.receipt, reconciled.receipt);
        assert_eq!(lock_state(&state).engine_calls, 2);
        assert_eq!(runtime.execute(original), reconciled);
    }
}

#[test]
fn reconciliation_engine_error_is_cached_and_single_shot() {
    let original = request();
    let invocation_id = original.invocation_id.clone();
    let request_digest = original.request_digest().clone();
    let mut initial = ReportSpec::terminated(EngineTermination::Partial);
    initial.post_commit_known = false;
    let (mut runtime, state) = runtime(Config {
        report: initial,
        reconcile_error: Some(PortError::UnknownOutcome),
        ..Config::default()
    });
    assert_eq!(
        runtime.execute(original.clone()).receipt.disposition,
        InvocationDisposition::Unknown
    );
    let first = must(runtime.reconcile(&invocation_id, &request_digest));
    let second = must(runtime.reconcile(&invocation_id, &request_digest));
    assert_eq!(first, second);
    assert_eq!(first.receipt.disposition, InvocationDisposition::Unknown);
    assert_eq!(lock_state(&state).engine_calls, 2);
    assert_eq!(runtime.execute(original), first);
}

#[test]
fn unknown_reconciliation_report_is_cached_and_replayed() {
    let original = request();
    let invocation_id = original.invocation_id.clone();
    let request_digest = original.request_digest().clone();
    let mut initial = ReportSpec::terminated(EngineTermination::Partial);
    initial.post_commit_known = false;
    let mut reconcile_report = ReportSpec::terminated(EngineTermination::PostCommitUnknown);
    reconcile_report.post_commit_known = false;
    let (mut runtime, state) = runtime(Config {
        report: initial,
        reconcile_report,
        ..Config::default()
    });
    runtime.execute(original.clone());
    let first = must(runtime.reconcile(&invocation_id, &request_digest));
    let second = must(runtime.reconcile(&invocation_id, &request_digest));
    assert_eq!(first, second);
    assert_eq!(first.receipt.disposition, InvocationDisposition::Unknown);
    assert_eq!(lock_state(&state).engine_calls, 2);
}

#[test]
fn failed_p03_reconciliation_verification_does_not_consume_engine_attempt() {
    let original = request();
    let invocation_id = original.invocation_id.clone();
    let request_digest = original.request_digest().clone();
    let (mut runtime, state) = runtime(Config {
        reject_reconcile_evidence: true,
        ..Config::default()
    });
    runtime.execute(original);
    assert_eq!(
        runtime.reconcile(&invocation_id, &request_digest),
        Err(RuntimeError::InvalidProcessReceipt)
    );
    assert_eq!(
        runtime.reconcile(&invocation_id, &request_digest),
        Err(RuntimeError::InvalidProcessReceipt)
    );
    assert_eq!(lock_state(&state).engine_calls, 1);
}

#[test]
fn replay_capacity_fails_closed_without_eviction_or_second_execution() {
    let (mut runtime, state) = runtime(Config::default());
    let first = request_with_id(0);
    let first_result = runtime.execute(first.clone());
    for id in 1..256 {
        assert_eq!(
            runtime.execute(request_with_id(id)).receipt.disposition,
            InvocationDisposition::Succeeded
        );
    }
    let rejected = runtime.execute(request_with_id(256));
    assert_eq!(
        rejected.receipt.error,
        Some(RuntimeError::ReplayCapacityExceeded)
    );
    let state_after_reject = lock_state(&state);
    assert_eq!(state_after_reject.process_start_calls, 256);
    assert_eq!(state_after_reject.engine_calls, 256);
    drop(state_after_reject);
    assert_eq!(runtime.execute(first), first_result);
    let state_after_replay = lock_state(&state);
    assert_eq!(state_after_replay.process_start_calls, 256);
    assert_eq!(state_after_replay.engine_calls, 256);
}

#[test]
fn running_p03_process_cannot_authorize_success() {
    let config = Config {
        process_reaped: false,
        ..Config::default()
    };
    let (mut runtime, _) = runtime(config);
    let result = runtime.execute(request());
    assert_eq!(result.receipt.disposition, InvocationDisposition::Unknown);
    assert_eq!(result.receipt.error, Some(RuntimeError::UnknownOutcome));
}

#[test]
fn stale_source_forbidden_effect_and_meter_violation_never_succeed() {
    let stale = Config {
        stale_source: true,
        ..Config::default()
    };
    let (mut stale_runtime, _) = runtime(stale);
    assert_eq!(
        stale_runtime.execute(request()).receipt.error,
        Some(RuntimeError::StaleFence)
    );

    let forbidden = Config {
        report: ReportSpec {
            effects: vec![EffectProposal {
                effect_kind: must(CapabilityId::new("network.send")),
                payload_digest: digest('6'),
            }],
            ..ReportSpec::success()
        },
        ..Config::default()
    };
    let (mut forbidden_runtime, _) = runtime(forbidden);
    assert_eq!(
        forbidden_runtime.execute(request()).receipt.error,
        Some(RuntimeError::EngineContractViolation)
    );

    let over_meter = Config {
        report: ReportSpec {
            over_meter: true,
            ..ReportSpec::success()
        },
        ..Config::default()
    };
    let (mut metered_runtime, _) = runtime(over_meter);
    assert_eq!(
        metered_runtime.execute(request()).receipt.error,
        Some(RuntimeError::EngineContractViolation)
    );
}

#[test]
fn caller_cancellation_is_checked_before_any_port_effect() {
    let mut cancelled = request();
    cancelled.cancellation_requested = true;
    must(cancelled.refresh_digest());
    let (mut runtime, state) = runtime(Config::default());
    assert_eq!(
        runtime.execute(cancelled).receipt.error,
        Some(RuntimeError::Cancelled)
    );
    assert_eq!(lock_state(&state).process_start_calls, 0);
    assert_eq!(lock_state(&state).engine_calls, 0);
}
