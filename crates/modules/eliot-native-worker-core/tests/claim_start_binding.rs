//! T5-01 claim-bound start tests (issue #22).
//!
//! Binds `WorkerCore::demand_start_claimed` to one exact
//! `ClaimAdmissionRequest`: a matching projection reaches the real
//! admission port and then reports the U1 executable-binding gap instead
//! of starting; every mismatched dimension fails before admission and
//! never reaches `ProcessExecutor::start`. The port doubles below are
//! faithful to `src/tests.rs` (admit through the real port shape, count
//! starts) and bypass nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use eliot_agent_api::{
    AttemptId, AuthorityEnvelope, AuthorityEpoch, BudgetEnvelope, EffectCeiling, EffectKind,
    ResourceGeneration, StateFence, WorkLeaseId,
};
use eliot_contracts::{DecisionId, SessionId, TaskId};
use eliot_native_worker_core::{
    AdmissionLivenessOutcome, CapabilityAdmissionFacts, CapabilityAdmissionOutcome,
    CapabilityAdmissionPort, CapabilityAdmissionRequest, CapabilityLivenessRequest,
    ClaimAdmissionRequest, DurableCheckpointPort, DurableCheckpointRequest, DurableReplayPort,
    DurableRequestDecision, EXECUTION_UNIT_SCHEMA_VERSION, EffectAdmissionOutcome,
    EffectAdmissionRequest, EventAckReceipt, JSON_ENCODING_PROFILE, NativeClaimId,
    NativeRegistrationId, NativeRenewalId, NativeWorkerClaim, NativeWorkerRegistration,
    PROTOCOL_VERSION, ProviderFailure, WorkerCore, WorkerError, WorkerEventDraft,
    WorkerEventEnvelope, WorkerHello, WorkerLifecycle,
};
use eliot_process::SessionId as ProcessSessionId;
use eliot_process::{
    ActionLeaseRef, CancellationReceipt, DispatchAuthorityId, DispatchPermitAuthority,
    EnvironmentProjection, EvidenceSinkError, FencingToken, Generation, ImageId, JobId,
    KernelDispatchKey, OperationId, PermitIssuance, ProcessEvidence, ProcessEvidenceSink,
    ProcessExecutionError, ProcessExecutionView, ProcessExecutor, ProcessIntent, ProcessRequest,
    ProcessStartReceipt, ProcessTreeId, ResourceLimits,
};

type TestCore = WorkerCore<FakeExecutor, FakeAdmission, FakeReplay, FakeReplay>;

struct FakeExecutor {
    starts: Arc<Mutex<usize>>,
}

impl ProcessExecutor for FakeExecutor {
    async fn start(
        &self,
        _request: ProcessRequest,
        _sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
        *lock(&self.starts) += 1;
        Err(ProcessExecutionError::NotFound)
    }

    async fn inspect(
        &self,
        _operation_id: OperationId,
    ) -> Result<ProcessExecutionView, ProcessExecutionError> {
        Err(ProcessExecutionError::NotFound)
    }

    async fn cancel(
        &self,
        _operation_id: OperationId,
    ) -> Result<CancellationReceipt, ProcessExecutionError> {
        Err(ProcessExecutionError::NotFound)
    }

    async fn reconcile(
        &self,
        _operation_id: OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError> {
        Err(ProcessExecutionError::NotFound)
    }
}

struct FakeAdmission {
    admissions: Arc<Mutex<usize>>,
    last_claim_digest: Arc<Mutex<Option<String>>>,
    corrupt_claim_echo: bool,
}

impl CapabilityAdmissionPort for FakeAdmission {
    fn admit(
        &mut self,
        request: &CapabilityAdmissionRequest,
    ) -> Result<CapabilityAdmissionOutcome, ProviderFailure> {
        *lock(&self.admissions) += 1;
        *lock(&self.last_claim_digest) = request
            .claim()
            .map(|presented| presented.claim().binding_digest.clone());
        let mut facts = CapabilityAdmissionFacts::new(
            "admission-1",
            "admission-revision-1",
            1,
            100,
            10_000,
            "worker-stream-1",
            "worker-producer-1",
            request.hello().route_ref.clone(),
            request.hello().artifact_manifest_digest.clone(),
            request.hello().worker_generation,
            authority(request.hello().state_fence.clone()),
            request.hello().requested_capabilities.clone(),
            request.operation_id().clone(),
            request.process_tree_id().clone(),
            request.process_generation(),
            request.process_fence().clone(),
            request.process_request_digest(),
            *request.resource_limits(),
        );
        if let Some(presented) = request.claim() {
            facts = if self.corrupt_claim_echo {
                let mut tampered = presented.claim().clone();
                tampered.binding_digest = "0".repeat(64);
                facts.with_claim_binding(&tampered)
            } else {
                facts.with_claim_binding(presented.claim())
            };
        }
        Ok(CapabilityAdmissionOutcome::Admitted(Box::new(facts)))
    }

    fn revalidate(
        &mut self,
        _request: &CapabilityLivenessRequest,
    ) -> Result<AdmissionLivenessOutcome, ProviderFailure> {
        Err(ProviderFailure::new(
            "admission",
            "claim-start tests never revalidate",
        ))
    }

    fn authorize_effect(
        &mut self,
        _request: &EffectAdmissionRequest,
    ) -> Result<EffectAdmissionOutcome, ProviderFailure> {
        Err(ProviderFailure::new(
            "admission",
            "claim-start tests never authorize effects",
        ))
    }
}

#[derive(Clone)]
struct FakeReplay;

impl DurableReplayPort for FakeReplay {
    fn lookup_request(
        &mut self,
        _stream_id: &str,
        _request_id: &str,
        _fingerprint: &str,
    ) -> Result<DurableRequestDecision, ProviderFailure> {
        Err(ProviderFailure::new(
            "replay",
            "claim-start tests never look up requests",
        ))
    }

    fn begin_request(
        &mut self,
        _stream_id: &str,
        _request_id: &str,
        _fingerprint: &str,
    ) -> Result<DurableRequestDecision, ProviderFailure> {
        Err(ProviderFailure::new(
            "replay",
            "claim-start tests never begin requests",
        ))
    }

    fn append(&mut self, _draft: WorkerEventDraft) -> Result<WorkerEventEnvelope, ProviderFailure> {
        Err(ProviderFailure::new(
            "replay",
            "claim-start tests never append events",
        ))
    }

    fn replay(
        &mut self,
        _stream_id: &str,
        _after_sequence: u64,
    ) -> Result<Vec<WorkerEventEnvelope>, ProviderFailure> {
        Err(ProviderFailure::new(
            "replay",
            "claim-start tests never replay",
        ))
    }

    fn acknowledge(&mut self, _receipt: &EventAckReceipt) -> Result<(), ProviderFailure> {
        Err(ProviderFailure::new(
            "replay",
            "claim-start tests never acknowledge",
        ))
    }
}

impl DurableCheckpointPort for FakeReplay {
    fn persist_checkpoint(
        &mut self,
        _request: &DurableCheckpointRequest,
    ) -> Result<eliot_native_worker_core::CheckpointProviderOutcome, ProviderFailure> {
        Err(ProviderFailure::new(
            "checkpoint",
            "claim-start tests never persist checkpoints",
        ))
    }
}

struct RecordingSink;

impl ProcessEvidenceSink for RecordingSink {
    fn record(&self, _evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        Ok(())
    }
}

struct Fixture {
    core: TestCore,
    executor_starts: Arc<Mutex<usize>>,
    admissions: Arc<Mutex<usize>>,
    last_claim_digest: Arc<Mutex<Option<String>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|_| panic!("claim-start fixture lock failed"))
}

fn load<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("claim-start fixture failed: {error:?}"),
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn epoch() -> AuthorityEpoch {
    load(AuthorityEpoch::new(1))
}

fn fence() -> StateFence {
    StateFence::new(epoch(), load(ResourceGeneration::new(1)))
}

fn authority(state_fence: StateFence) -> AuthorityEnvelope {
    AuthorityEnvelope {
        epoch: epoch(),
        scope_ref: "scope-1".to_owned(),
        effect_ceiling: EffectCeiling {
            scope_ref: "scope-1".to_owned(),
            allowed: [EffectKind::WriteCandidate].into_iter().collect(),
            max_external_effects: 0,
        },
        lease: load(serde_json::from_value::<WorkLeaseId>(
            serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"}),
        )),
        state_fence,
        valid_until: "provider-owned".to_owned(),
    }
}

fn revisions() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("authority".to_owned(), "a".repeat(64)),
        ("state".to_owned(), "b".repeat(64)),
    ])
}

fn limits() -> ResourceLimits {
    load(ResourceLimits::new(
        5_000,
        Some(1_000),
        Some(1_048_576),
        4_096,
        4_096,
        2,
    ))
}

fn process_request() -> ProcessRequest {
    let generation = load(Generation::new(1));
    let intent = load(ProcessIntent::new(
        load(OperationId::new("operation-1")),
        load(ProcessTreeId::new("tree-1")),
        load(JobId::new("job-operation-1")),
        load(ImageId::new("image-operation-1")),
        load(ProcessSessionId::new("session-operation-1")),
        generation,
        "worker.exe",
        "a".repeat(64),
        vec!["--native-worker".to_owned()],
        "C:/work",
        EnvironmentProjection::default(),
        limits(),
    ));
    let fence = load(FencingToken::new(
        1,
        generation,
        "process-fence-1".to_owned(),
    ));
    let mut permit_authority = DispatchPermitAuthority::activate(
        load(DispatchAuthorityId::new("native-worker-authority")),
        load(KernelDispatchKey::from_secret_bytes([0x5a; 32])),
    );
    let permit = load(permit_authority.issue(
        &intent,
        load(PermitIssuance::new(
            load(ActionLeaseRef::new("native-worker-lease")),
            fence,
            revisions(),
            100,
            10_000,
            "nonce-native-worker-1",
        )),
    ));
    load(ProcessRequest::new(intent, permit))
}

fn hello() -> WorkerHello {
    WorkerHello {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        encoding_profile: JSON_ENCODING_PROFILE.to_owned(),
        connection_id: "connection-claim-1".to_owned(),
        request_id: "start-claim-1".to_owned(),
        trace_context: BTreeMap::from([("trace_id".to_owned(), "trace-claim-1".to_owned())]),
        deadline_unix_ms: 5_000,
        artifact_manifest_digest: "manifest-digest-1".to_owned(),
        launch_nonce: "launch-nonce-claim-1".to_owned(),
        worker_generation: 1,
        authority_epoch: epoch(),
        state_fence: fence(),
        route_ref: "route-1".to_owned(),
        requested_capabilities: BTreeSet::from(["inspect".to_owned()]),
    }
}

fn registration() -> NativeWorkerRegistration {
    NativeWorkerRegistration {
        registration_id: load(NativeRegistrationId::new("registration-1")),
        installation_id: "installation-1".to_owned(),
        worker_artifact_digest: "a".repeat(64),
        worker_config_digest: "b".repeat(64),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        worker_generation: 1,
        process_id: 4242,
        process_start_100ns: 120,
        process_image_digest: "c".repeat(64),
        principal_ref: "principal-1".to_owned(),
        session_id: load(SessionId::new("session-operation-1")),
        connection_id: "connection-claim-1".to_owned(),
        authority_epoch: epoch(),
        state_fence: fence(),
        lease_id: "lease-reg-1".to_owned(),
        lease_expires_at_unix_ms: 9_000,
        renewal_id: load(NativeRenewalId::new("renewal-1")),
        execution_unit_schema_version: EXECUTION_UNIT_SCHEMA_VERSION,
        resource_limits: limits(),
        invalidation_set: BTreeSet::new(),
    }
}

fn claim(registration: &NativeWorkerRegistration) -> NativeWorkerClaim {
    let draft = NativeWorkerClaim {
        claim_id: load(NativeClaimId::new("claim-1")),
        registration_id: registration.registration_id.clone(),
        worker_generation: 1,
        parent_job_id: "job-parent-1".to_owned(),
        task_id: load(TaskId::new("task-1")),
        work_scope_id: "scope-1".to_owned(),
        decision_id: load(DecisionId::new("decision-1")),
        attempt_id: load(AttemptId::new("attempt-1")),
        operation_id: load(OperationId::new("operation-1")),
        route_class: "test-route".to_owned(),
        budget: BudgetEnvelope {
            context_tokens: 100,
            wall_time_ms: 4_000,
            output_bytes: 4_096,
            cost_microunits: 1_000,
            max_depth: 4,
            max_descendants: 8,
        },
        deadline_unix_ms: 9_000,
        cancellation_policy_id: "policy-1".to_owned(),
        expected_result_schema: "result-schema-1".to_owned(),
        expected_result_schema_version: 1,
        predecessor_revision: "rev-0".to_owned(),
        authority_epoch: epoch(),
        state_fence: fence(),
        binding_digest: String::new(),
    };
    load(draft.with_computed_digest())
}

fn claim_request(
    registration: &NativeWorkerRegistration,
    claim: &NativeWorkerClaim,
) -> ClaimAdmissionRequest {
    load(serde_json::from_value(serde_json::json!({
        "registration": registration,
        "claim": claim,
    })))
}

fn fixture(corrupt_claim_echo: bool) -> Fixture {
    let executor_starts = Arc::new(Mutex::new(0_usize));
    let admissions = Arc::new(Mutex::new(0_usize));
    let last_claim_digest = Arc::new(Mutex::new(None::<String>));
    let executor = FakeExecutor {
        starts: Arc::clone(&executor_starts),
    };
    let admission = FakeAdmission {
        admissions: Arc::clone(&admissions),
        last_claim_digest: Arc::clone(&last_claim_digest),
        corrupt_claim_echo,
    };
    let replay = FakeReplay;
    let core = WorkerCore::new(
        Some(executor),
        Some(admission),
        Some(replay.clone()),
        Some(replay),
        Some(Arc::new(RecordingSink)),
    );
    Fixture {
        core,
        executor_starts,
        admissions,
        last_claim_digest,
    }
}

type Setup = fn(
    NativeWorkerRegistration,
    NativeWorkerClaim,
) -> (NativeWorkerRegistration, NativeWorkerClaim);

fn tamper_registration_id(
    registration: NativeWorkerRegistration,
    claim: NativeWorkerClaim,
) -> (NativeWorkerRegistration, NativeWorkerClaim) {
    let mut claim = claim;
    claim.registration_id = load(NativeRegistrationId::new("registration-other"));
    let claim = load(claim.with_computed_digest());
    (registration, claim)
}

fn tamper_generation(
    registration: NativeWorkerRegistration,
    claim: NativeWorkerClaim,
) -> (NativeWorkerRegistration, NativeWorkerClaim) {
    let mut registration = registration;
    let mut claim = claim;
    registration.worker_generation = 2;
    claim.worker_generation = 2;
    let claim = load(claim.with_computed_digest());
    (registration, claim)
}

fn tamper_epoch(
    registration: NativeWorkerRegistration,
    claim: NativeWorkerClaim,
) -> (NativeWorkerRegistration, NativeWorkerClaim) {
    let other = load(AuthorityEpoch::new(2));
    let other_fence = StateFence::new(other, load(ResourceGeneration::new(1)));
    let mut registration = registration;
    let mut claim = claim;
    registration.authority_epoch = other;
    registration.state_fence = other_fence.clone();
    claim.authority_epoch = other;
    claim.state_fence = other_fence;
    let claim = load(claim.with_computed_digest());
    (registration, claim)
}

fn tamper_fence(
    registration: NativeWorkerRegistration,
    claim: NativeWorkerClaim,
) -> (NativeWorkerRegistration, NativeWorkerClaim) {
    let other_fence = StateFence::new(epoch(), load(ResourceGeneration::new(2)));
    let mut registration = registration;
    let mut claim = claim;
    registration.state_fence = other_fence.clone();
    claim.state_fence = other_fence;
    let claim = load(claim.with_computed_digest());
    (registration, claim)
}

fn tamper_operation(
    registration: NativeWorkerRegistration,
    claim: NativeWorkerClaim,
) -> (NativeWorkerRegistration, NativeWorkerClaim) {
    let mut claim = claim;
    claim.operation_id = load(OperationId::new("operation-other"));
    let claim = load(claim.with_computed_digest());
    (registration, claim)
}

fn tamper_deadline(
    registration: NativeWorkerRegistration,
    claim: NativeWorkerClaim,
) -> (NativeWorkerRegistration, NativeWorkerClaim) {
    let mut claim = claim;
    claim.deadline_unix_ms = 1_000;
    let claim = load(claim.with_computed_digest());
    (registration, claim)
}

fn tamper_attempt_without_redigest(
    registration: NativeWorkerRegistration,
    claim: NativeWorkerClaim,
) -> (NativeWorkerRegistration, NativeWorkerClaim) {
    // The attempt has no start-time counterpart to equate: it is carried
    // digest-bound. A rewired attempt without a recomputed digest must fail
    // the claim's own binding check before admission.
    let mut claim = claim;
    claim.attempt_id = load(AttemptId::new("attempt-other"));
    (registration, claim)
}

#[test]
fn matching_projection_reaches_admission_then_reports_u1_gap() {
    let Fixture {
        mut core,
        executor_starts,
        admissions,
        last_claim_digest,
    } = fixture(false);
    let registration = registration();
    let claim_value = claim(&registration);
    let expected_digest = claim_value.binding_digest.clone();
    let request = claim_request(&registration, &claim_value);
    let result = block_on(core.demand_start_claimed(request, hello(), process_request()));
    assert_eq!(
        result,
        Err(WorkerError::InvalidRequest("u1_missing_route_fingerprint"))
    );
    assert_eq!(*lock(&admissions), 1);
    assert_eq!(*lock(&executor_starts), 0);
    assert_eq!((*lock(&last_claim_digest)).clone(), Some(expected_digest));
    assert_eq!(core.lifecycle(), WorkerLifecycle::Created);
}

#[test]
fn mismatched_dimensions_never_reach_admission_or_start() {
    let cases: [(&str, Setup, WorkerError); 7] = [
        (
            "registration",
            tamper_registration_id,
            WorkerError::InvalidRequest("registration_binding"),
        ),
        (
            "generation",
            tamper_generation,
            WorkerError::InvalidRequest("generation_binding"),
        ),
        ("epoch", tamper_epoch, WorkerError::StaleEpoch),
        ("fence", tamper_fence, WorkerError::StaleFence),
        (
            "attempt",
            tamper_attempt_without_redigest,
            WorkerError::InvalidRequest("binding_digest"),
        ),
        (
            "operation",
            tamper_operation,
            WorkerError::InvalidRequest("claim_operation"),
        ),
        ("deadline", tamper_deadline, WorkerError::DeadlineExpired),
    ];
    for (name, setup, expected) in cases {
        let Fixture {
            mut core,
            executor_starts,
            admissions,
            last_claim_digest: _,
        } = fixture(false);
        let registration = registration();
        let claim_value = claim(&registration);
        let (registration, claim_value) = setup(registration, claim_value);
        let request = claim_request(&registration, &claim_value);
        let result = block_on(core.demand_start_claimed(request, hello(), process_request()));
        assert_eq!(result, Err(expected), "mismatched dimension: {name}");
        assert_eq!(*lock(&admissions), 0, "mismatched dimension: {name}");
        assert_eq!(*lock(&executor_starts), 0, "mismatched dimension: {name}");
        assert_eq!(core.lifecycle(), WorkerLifecycle::Created);
    }
}

#[test]
fn disagreeing_grant_claim_echo_fails_closed_before_start() {
    let Fixture {
        mut core,
        executor_starts,
        admissions,
        last_claim_digest: _,
    } = fixture(true);
    let registration = registration();
    let claim_value = claim(&registration);
    let request = claim_request(&registration, &claim_value);
    let result = block_on(core.demand_start_claimed(request, hello(), process_request()));
    assert_eq!(result, Err(WorkerError::AdmissionMismatch("claim_binding")));
    assert_eq!(*lock(&admissions), 1);
    assert_eq!(*lock(&executor_starts), 0);
    assert_eq!(core.lifecycle(), WorkerLifecycle::Created);
}

#[test]
fn admission_projection_wire_keeps_preclaim_shape_compatible() {
    let registration = registration();
    let claim_value = claim(&registration);
    let hello_value = hello();
    let process = process_request();
    let legacy: CapabilityAdmissionRequest = load(serde_json::from_value(serde_json::json!({
        "hello": hello_value,
        "operation_id": process.operation_id(),
        "process_tree_id": process.process_tree_id(),
        "process_generation": process.generation(),
        "process_fence": process.fence(),
        "process_request_digest": process.invocation_digest(),
        "resource_limits": process.resource_limits(),
    })));
    assert_eq!(legacy.claim(), None);
    let presented = claim_request(&registration, &claim_value);
    let request = load(CapabilityAdmissionRequest::from_claim(
        &presented,
        &hello_value,
        &process,
    ));
    assert_eq!(
        request
            .claim()
            .map(|joined| joined.claim().binding_digest.as_str()),
        Some(claim_value.binding_digest.as_str())
    );
    let wire = load(serde_json::to_value(&request));
    assert!(wire.get("claim").is_some());
    let roundtrip: CapabilityAdmissionRequest = load(serde_json::from_value(wire));
    assert_eq!(roundtrip, request);
    let mut polluted = load(serde_json::to_value(&request));
    polluted["unknown_field"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CapabilityAdmissionRequest>(polluted).is_err());
}
