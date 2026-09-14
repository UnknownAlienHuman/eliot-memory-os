//! T2-S05 Slice A: first claimed consumer through `NativeWorker::start_claimed`.
//!
//! Windows-only trusted composition. The REAL admitted `WindowsProcessExecutor`
//! runs real bounded children in-process; every production validator runs (the
//! `from_claim` join, the executable gate, grant checks, receipt/proof
//! checks). The admission/replay/checkpoint ports are doubles seeded from
//! owner-produced records (the claim digest and executable join are echoed by
//! the admission double), following the `claim_start_binding` fixture pattern,
//! because Kernel admission transport belongs to T9-06. There is no fake
//! executor, no deserialized `ProcessRequest` (requests are built with
//! `ProcessIntent` plus the production `DispatchPermitAuthority`), and no
//! direct `std::process::Command` (forbidden by `bins/AGENTS.md`).
//!
//! Start proves launch only: a nonzero exit surfaces post-start through
//! `inspect`. The worker-failure test therefore observes the nonzero exit
//! directly through the real executor and proves the worker-level typed
//! handling (`UnknownOutcome`, never Ready) with a rejecting evidence sink,
//! then shows the host still launches workers afterwards.

#![cfg(windows)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use eliot_agent_api::{
    AttemptId, AuthorityEnvelope, BudgetEnvelope, EffectCeiling, EffectKind, ResourceGeneration,
    StateFence, WorkLeaseId,
};
use eliot_contracts::{
    ClockReading, DecisionId, EpochId, EpochLineageId, SessionId, TaskId, sha256_hex,
};
use eliot_native_worker::{NativeWorker, NativeWorkerError};
use eliot_native_worker_core::{
    AdmissionLivenessOutcome, CapabilityAdmissionFacts, CapabilityAdmissionOutcome,
    CapabilityAdmissionPort, CapabilityAdmissionRequest, CapabilityLivenessRequest,
    CheckpointProviderOutcome, CheckpointReceiptFacts, ClaimAdmissionRequest,
    DurableCheckpointPort, DurableCheckpointRequest, DurableReplayPort, DurableRequestDecision,
    EXECUTION_UNIT_SCHEMA_VERSION, EffectAdmissionOutcome, EffectAdmissionRequest, EventAckReceipt,
    JSON_ENCODING_PROFILE, NATIVE_WORKER_CLAIM_WIRE_VERSION,
    NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION, NativeClaimId, NativeRegistrationId,
    NativeRenewalId, NativeWorkerClaim, NativeWorkerExecutableBinding,
    NativeWorkerExecutableExpectation, NativeWorkerRegistration, PROTOCOL_VERSION, ProviderFailure,
    WorkerCore, WorkerError, WorkerEventDraft, WorkerEventEnvelope, WorkerHello, WorkerLifecycle,
};
use eliot_process::SessionId as ProcessSessionId;
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
    EnvironmentInheritance, EnvironmentProjection, EvidenceSinkError, FencingToken, Generation,
    ImageId, JobId, KernelDispatchKey, OperationId, PermitIssuance, ProcessEvidence,
    ProcessEvidenceSink, ProcessExecutionError, ProcessExecutionView, ProcessExecutor,
    ProcessIntent, ProcessLifecycle, ProcessRequest, ProcessTreeId, ResourceLimits,
    SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};

type TestWorker = NativeWorker<WindowsProcessExecutor, TestAdmission, TestReplay, TestReplay>;

/// Production dispatch validation behind a test-owned key and nonce ledger.
///
/// This is the same composition the executor's own tests use: the authority is
/// the production `DispatchPermitAuthority` (real one-shot permit validation),
/// owned in-process because the P-07 controller lives in `bins/eliot-kernel`
/// and provider selection belongs to #874. The executor itself is real.
struct TestAuthorityPort {
    authority: Mutex<DispatchPermitAuthority>,
    context: DispatchValidationContext,
}

impl DispatchValidationPort for TestAuthorityPort {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let mut authority = lock(&self.authority);
        authority
            .validate_and_consume(request, observed, &self.context)
            .map_err(Into::into)
    }
}

/// Admission double seeded from owner-produced records.
///
/// Echoes the presented claim digest/attempt/operation and the presented
/// executable join as the live owner expectation, exactly like the
/// `claim_start_binding` fixture. Every production grant check still runs.
struct TestAdmission {
    admissions: Arc<Mutex<usize>>,
    last_claim_digest: Arc<Mutex<Option<String>>>,
    corrupt_claim_echo: bool,
}

impl CapabilityAdmissionPort for TestAdmission {
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
            if !self.corrupt_claim_echo
                && let Some(join) = &presented.claim().executable_binding
            {
                facts = facts.with_executable_expectation(NativeWorkerExecutableExpectation {
                    current: join.clone(),
                    revoked: false,
                });
            }
        }
        Ok(CapabilityAdmissionOutcome::Admitted(Box::new(facts)))
    }

    fn revalidate(
        &mut self,
        _request: &CapabilityLivenessRequest,
    ) -> Result<AdmissionLivenessOutcome, ProviderFailure> {
        Err(ProviderFailure::new(
            "admission",
            "claimed-first-consumer tests never revalidate",
        ))
    }

    fn authorize_effect(
        &mut self,
        _request: &EffectAdmissionRequest,
    ) -> Result<EffectAdmissionOutcome, ProviderFailure> {
        Err(ProviderFailure::new(
            "admission",
            "claimed-first-consumer tests never authorize effects",
        ))
    }
}

/// Durable replay/checkpoint double with real draft storage.
///
/// `append` assigns durable identity and sequence exactly like the core's own
/// fixture replay; the start path only needs `append`, the rest stays faithful
/// for completeness.
#[derive(Clone)]
struct TestReplay {
    next_sequence: Arc<Mutex<u64>>,
    requests: Arc<Mutex<BTreeMap<(String, String), String>>>,
    events: Arc<Mutex<Vec<WorkerEventEnvelope>>>,
    acknowledgements: Arc<Mutex<Vec<EventAckReceipt>>>,
}

impl TestReplay {
    fn new(events: Arc<Mutex<Vec<WorkerEventEnvelope>>>) -> Self {
        Self {
            next_sequence: Arc::new(Mutex::new(0)),
            requests: Arc::new(Mutex::new(BTreeMap::new())),
            events,
            acknowledgements: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl DurableReplayPort for TestReplay {
    fn lookup_request(
        &mut self,
        stream_id: &str,
        request_id: &str,
        fingerprint: &str,
    ) -> Result<DurableRequestDecision, ProviderFailure> {
        let state = lock(&self.requests);
        let key = (stream_id.to_owned(), request_id.to_owned());
        let Some(recorded) = state.get(&key) else {
            return Ok(DurableRequestDecision::New);
        };
        if recorded != fingerprint {
            return Ok(DurableRequestDecision::Conflict);
        }
        Ok(DurableRequestDecision::Replay(
            lock(&self.events)
                .iter()
                .filter(|event| event.stream_id == stream_id && event.request_id == request_id)
                .cloned()
                .collect(),
        ))
    }

    fn begin_request(
        &mut self,
        stream_id: &str,
        request_id: &str,
        fingerprint: &str,
    ) -> Result<DurableRequestDecision, ProviderFailure> {
        let mut state = lock(&self.requests);
        let key = (stream_id.to_owned(), request_id.to_owned());
        if let Some(recorded) = state.get(&key) {
            if recorded != fingerprint {
                return Ok(DurableRequestDecision::Conflict);
            }
            return Ok(DurableRequestDecision::Replay(
                lock(&self.events)
                    .iter()
                    .filter(|event| event.stream_id == stream_id && event.request_id == request_id)
                    .cloned()
                    .collect(),
            ));
        }
        state.insert(key, fingerprint.to_owned());
        Ok(DurableRequestDecision::New)
    }

    fn append(&mut self, draft: WorkerEventDraft) -> Result<WorkerEventEnvelope, ProviderFailure> {
        let mut sequence = lock(&self.next_sequence);
        *sequence += 1;
        let event = draft
            .into_envelope(format!("event-{sequence}"), *sequence)
            .map_err(|error| ProviderFailure::new("replay", error.to_string()))?;
        lock(&self.events).push(event.clone());
        Ok(event)
    }

    fn replay(
        &mut self,
        stream_id: &str,
        after_sequence: u64,
    ) -> Result<Vec<WorkerEventEnvelope>, ProviderFailure> {
        Ok(lock(&self.events)
            .iter()
            .filter(|event| event.stream_id == stream_id && event.sequence > after_sequence)
            .cloned()
            .collect())
    }

    fn acknowledge(&mut self, receipt: &EventAckReceipt) -> Result<(), ProviderFailure> {
        lock(&self.acknowledgements).push(receipt.clone());
        Ok(())
    }
}

impl DurableCheckpointPort for TestReplay {
    fn persist_checkpoint(
        &mut self,
        request: &DurableCheckpointRequest,
    ) -> Result<CheckpointProviderOutcome, ProviderFailure> {
        Ok(CheckpointProviderOutcome::Stored(Box::new(
            CheckpointReceiptFacts::new(
                "checkpoint-receipt-1",
                request.checkpoint_ref(),
                request.request_id(),
                request.stream_id(),
                request.producer_generation(),
                request.authority_epoch().clone(),
                request.state_fence().clone(),
                request.admission_revision(),
                request.operation_id().clone(),
                request.process_request_digest(),
                300,
            ),
        )))
    }
}

struct RecordingSink {
    evidence: Arc<Mutex<Vec<ProcessEvidence>>>,
}

impl ProcessEvidenceSink for RecordingSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        lock(&self.evidence).push(evidence);
        Ok(())
    }
}

/// Rejecting evidence sink: the worker-level failure injector for the
/// failing-operation test. The real child still launches through the real
/// executor, but P-03 cannot prove its start, so the core must land in
/// `UnknownOutcome` (never Ready) instead of fabricating readiness.
struct RejectingSink;

impl ProcessEvidenceSink for RejectingSink {
    fn record(&self, _evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        Err(EvidenceSinkError {
            message: "claimed-first-consumer rejects P-03 evidence".to_owned(),
        })
    }
}

struct ClaimedSetup {
    worker: TestWorker,
    registration: NativeWorkerRegistration,
    claim_value: NativeWorkerClaim,
    hello_value: WorkerHello,
    process: ProcessRequest,
    admissions: Arc<Mutex<usize>>,
    evidence: Arc<Mutex<Vec<ProcessEvidence>>>,
    events: Arc<Mutex<Vec<WorkerEventEnvelope>>>,
}

impl ClaimedSetup {
    fn build(
        argv: Vec<String>,
        operation: &str,
        tree: &str,
        nonce: &str,
        corrupt_claim_echo: bool,
        reject_evidence: bool,
    ) -> Self {
        let (process, authority) = build_process(operation, tree, argv, nonce);
        let hello_value = hello();
        let registration = registration();
        let claim_value = claim_for(&registration, &hello_value, &process);
        let port = authority_port(authority, process.fence().clone());
        let executor = WindowsProcessExecutor::new(port);
        let admissions = Arc::new(Mutex::new(0_usize));
        let admission = TestAdmission {
            admissions: Arc::clone(&admissions),
            last_claim_digest: Arc::new(Mutex::new(None::<String>)),
            corrupt_claim_echo,
        };
        let evidence = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let replay = TestReplay::new(Arc::clone(&events));
        let sink: Arc<dyn ProcessEvidenceSink> = if reject_evidence {
            Arc::new(RejectingSink)
        } else {
            Arc::new(RecordingSink {
                evidence: Arc::clone(&evidence),
            })
        };
        let core = WorkerCore::new(
            Some(executor),
            Some(admission),
            Some(replay.clone()),
            Some(replay),
            Some(sink),
        );
        Self {
            worker: NativeWorker::new(core),
            registration,
            claim_value,
            hello_value,
            process,
            admissions,
            evidence,
            events,
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|_| panic!("claimed-first-consumer fixture lock failed"))
}

fn load<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("claimed-first-consumer fixture failed: {error:?}"),
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

fn epoch() -> EpochId {
    load(EpochId::new(
        load(EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")),
        load(std::num::NonZeroU64::new(1).ok_or("non-zero test sequence")),
    ))
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

/// Resource envelope for REAL child launch: the limits become the live Job
/// Object limits, so memory must fit a real `cmd.exe` (the 1 MiB shape in the
/// core's fake-executor fixtures would kill a real child at startup).
fn limits() -> ResourceLimits {
    load(ResourceLimits::new(
        30_000,
        Some(10_000),
        Some(512_000_000),
        4_096,
        4_096,
        4,
    ))
}

/// Real admitted executable: never hardcoded, the digest is computed from the
/// exact bytes the executor will launch.
fn executable_path() -> String {
    r"C:\Windows\System32\cmd.exe".to_owned()
}

fn executable_digest() -> String {
    let bytes = std::fs::read(executable_path()).unwrap_or_else(|_| {
        panic!("claimed-first-consumer fixture: admitted executable is missing")
    });
    sha256_hex(&bytes)
}

fn working_directory() -> String {
    std::env::temp_dir().to_string_lossy().into_owned()
}

/// Exact child environment, constructed from named grants only.
///
/// P-04 launches the child with exactly the admitted `non_secret` map (no
/// ambient inheritance), and `cmd.exe` cannot initialize with an empty block.
/// Each variable is named explicitly here; nothing is inherited wholesale.
fn test_environment() -> EnvironmentProjection {
    let system_root = std::env::var("SystemRoot")
        .unwrap_or_else(|_| panic!("claimed-first-consumer fixture: SystemRoot is not set"));
    let path = format!("{system_root}\\System32;{system_root}");
    load(EnvironmentProjection::new(
        BTreeMap::from([
            ("SystemRoot".to_owned(), system_root),
            ("PATH".to_owned(), path),
        ]),
        Vec::new(),
        EnvironmentInheritance::None,
    ))
}

/// Bounded stdout, completing 0: a short ping burst through the real shell.
///
/// The program is a batch file because P-04 quotes every argv element and the
/// quoted-`/c` form only reliably dispatches a script path (the same pattern
/// the executor's own S03/S04 tests use); external waits like ping work here
/// because the fixture grants an explicit PATH.
const SUCCESS_BAT: &str = "@echo off\r\necho T2-S05-BOUNDED-STDOUT\r\nping -n 3 127.0.0.1\r\n";
/// Bounded, failing fast with exit code 3 through the real shell.
const FAIL_BAT: &str = "@echo off\r\nexit 3\r\n";

/// Writes one test-owned batch program under the temp dir (a runtime input to
/// the real executor, not a repo mutation) and returns its path.
fn write_bat(tag: &str, contents: &str) -> String {
    let path = std::env::temp_dir().join(format!("eliot-t2-s05-{tag}.bat"));
    std::fs::write(&path, contents)
        .unwrap_or_else(|_| panic!("claimed-first-consumer fixture: cannot write batch program"));
    path.to_string_lossy().into_owned()
}

fn remove_bat(tag: &str) {
    let _ = std::fs::remove_file(std::env::temp_dir().join(format!("eliot-t2-s05-{tag}.bat")));
}

fn success_argv(bat: &str) -> Vec<String> {
    vec!["/c".to_owned(), bat.to_owned()]
}

fn fail_argv(bat: &str) -> Vec<String> {
    vec!["/c".to_owned(), bat.to_owned()]
}

fn build_process(
    operation: &str,
    tree: &str,
    argv: Vec<String>,
    nonce: &str,
) -> (ProcessRequest, DispatchPermitAuthority) {
    let generation = load(Generation::new(1));
    let intent = load(ProcessIntent::new(
        load(OperationId::new(operation)),
        load(ProcessTreeId::new(tree)),
        load(JobId::new(format!("job-{operation}"))),
        load(ImageId::new(format!("image-{operation}"))),
        load(ProcessSessionId::new(format!("session-{operation}"))),
        generation,
        executable_path(),
        executable_digest(),
        argv,
        working_directory(),
        test_environment(),
        limits(),
    ));
    let fence = load(FencingToken::new(
        epoch(),
        generation,
        format!("process-fence-{operation}"),
    ));
    let mut authority = DispatchPermitAuthority::activate(
        load(DispatchAuthorityId::new("native-worker-authority")),
        load(KernelDispatchKey::from_secret_bytes([0x5a; 32])),
    );
    let permit = load(authority.issue(
        &intent,
        load(PermitIssuance::new(
            load(ActionLeaseRef::new("native-worker-lease")),
            fence,
            revisions(),
            100,
            10_000,
            nonce,
        )),
    ));
    (load(ProcessRequest::new(intent, permit)), authority)
}

fn authority_port(
    authority: DispatchPermitAuthority,
    fence: FencingToken,
) -> Arc<dyn DispatchValidationPort> {
    let context = load(DispatchValidationContext::new(
        ClockReading {
            valid_time_ms: Some(150),
            known_time_ms: Some(150),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        },
        fence,
        epoch(),
        revisions(),
        41,
    ));
    Arc::new(TestAuthorityPort {
        authority: Mutex::new(authority),
        context,
    })
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

/// Opaque owner-produced executable digest stand-in: deterministic SHA-256
/// over stable seed bytes through the real hash procedure, never hardcoded.
fn owner_issued_digest() -> String {
    sha256_hex(b"t9-02 w-c owner-issued executable digest stand-in")
}

fn valid_join(
    registration: &NativeWorkerRegistration,
    hello_value: &WorkerHello,
    process: &ProcessRequest,
) -> NativeWorkerExecutableBinding {
    NativeWorkerExecutableBinding {
        route_ref: hello_value.route_ref.clone(),
        adapter_id: "adapter-test".to_owned(),
        adapter_revision: 3,
        config_digest: registration.worker_config_digest.clone(),
        facet_manifest_ref: "facet-manifest-7".to_owned(),
        grant_graph_revision: 5,
        replay_stream_id: "worker-stream-1".to_owned(),
        launch_nonce: hello_value.launch_nonce.clone(),
        process_invocation_digest: process.invocation_digest().to_owned(),
        authority_epoch: epoch(),
        generation: load(ResourceGeneration::new(1)),
        state_fence: fence(),
        deadline_unix_ms: 8_000,
        expires_at_unix_ms: 9_500,
        executable_wire_version: NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION,
        executable_binding_digest: owner_issued_digest(),
    }
}

fn claim_for(
    registration: &NativeWorkerRegistration,
    hello_value: &WorkerHello,
    process: &ProcessRequest,
) -> NativeWorkerClaim {
    let join = valid_join(registration, hello_value, process);
    let draft = NativeWorkerClaim {
        claim_id: load(NativeClaimId::new("claim-1")),
        registration_id: registration.registration_id.clone(),
        worker_generation: 1,
        parent_job_id: "job-parent-1".to_owned(),
        task_id: load(TaskId::new("task-1")),
        work_scope_id: "scope-1".to_owned(),
        decision_id: load(DecisionId::new("decision-1")),
        attempt_id: load(AttemptId::new("attempt-1")),
        operation_id: process.operation_id().clone(),
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
        wire_version: NATIVE_WORKER_CLAIM_WIRE_VERSION,
        executable_binding: Some(join),
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
    let other = load(EpochId::new(
        load(EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")),
        load(std::num::NonZeroU64::new(2).ok_or("non-zero test sequence")),
    ));
    let other_fence = StateFence::new(other.clone(), load(ResourceGeneration::new(1)));
    let mut registration = registration;
    let mut claim = claim;
    registration.authority_epoch = other.clone();
    registration.state_fence = other_fence.clone();
    claim.authority_epoch = other;
    claim.state_fence = other_fence;
    let claim = load(claim.with_computed_digest());
    (registration, claim)
}

fn tamper_route(
    registration: NativeWorkerRegistration,
    claim: NativeWorkerClaim,
) -> (NativeWorkerRegistration, NativeWorkerClaim) {
    let mut claim = claim;
    claim
        .executable_binding
        .as_mut()
        .expect("v2 fixture carries the join")
        .route_ref = "route://changed".to_owned();
    let claim = load(claim.with_computed_digest());
    (registration, claim)
}

fn tamper_invocation_digest(
    registration: NativeWorkerRegistration,
    claim: NativeWorkerClaim,
) -> (NativeWorkerRegistration, NativeWorkerClaim) {
    let mut claim = claim;
    claim
        .executable_binding
        .as_mut()
        .expect("v2 fixture carries the join")
        .process_invocation_digest = "e".repeat(64);
    let claim = load(claim.with_computed_digest());
    (registration, claim)
}

fn identity(
    registration: NativeWorkerRegistration,
    claim: NativeWorkerClaim,
) -> (NativeWorkerRegistration, NativeWorkerClaim) {
    (registration, claim)
}

/// Polls the real executor until the bounded child terminates.
fn poll_terminal(
    executor: &WindowsProcessExecutor,
    operation: &OperationId,
) -> ProcessExecutionView {
    for _ in 0..600 {
        let view = block_on(executor.inspect(operation.clone()))
            .unwrap_or_else(|error| panic!("real executor inspect failed: {error:?}"));
        if view.lifecycle().is_terminal() {
            return view;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("bounded child did not terminate");
}

#[test]
fn admitted_bounded_op_reaches_ready_with_bound_receipt_and_durable_event() {
    let ready_bat = write_bat("a-ready", SUCCESS_BAT);
    let ClaimedSetup {
        mut worker,
        registration,
        claim_value,
        hello_value,
        process,
        admissions,
        evidence,
        events,
    } = ClaimedSetup::build(
        success_argv(&ready_bat),
        "operation-1",
        "tree-1",
        "nonce-claimed-1",
        false,
        false,
    );
    let expected_operation = process.operation_id().clone();
    let expected_digest = process.invocation_digest().to_owned();
    let expected_generation = process.generation().get();
    let expected_request_id = hello_value.request_id.clone();
    let expected_digest_for_echo = claim_value.binding_digest.clone();
    let request = claim_request(&registration, &claim_value);
    let ready = block_on(worker.start_claimed(request, hello_value, process))
        .unwrap_or_else(|error| panic!("admitted bounded op must reach Ready, got {error:?}"));

    assert_eq!(worker.lifecycle(), WorkerLifecycle::Ready);
    assert_eq!(ready.connection_id, "connection-claim-1");
    assert_eq!(ready.request_id, expected_request_id);
    assert_eq!(ready.admission_revision, "admission-revision-1");
    assert_eq!(ready.stream_id, "worker-stream-1");
    assert_eq!(
        ready.process_start_receipt.operation_id(),
        &expected_operation
    );
    assert_eq!(
        ready.process_start_receipt.request_digest(),
        expected_digest
    );
    assert_eq!(
        ready.process_start_receipt.accepted_generation().get(),
        expected_generation
    );
    assert_eq!(
        ready.process_start_receipt.lifecycle(),
        ProcessLifecycle::Running
    );
    assert_eq!(ready.ready_event.stream_id, "worker-stream-1");
    assert_eq!(ready.ready_event.request_id, expected_request_id);
    assert_eq!(ready.ready_event.sequence, 1);
    assert_eq!(ready.ready_event.payload_type, "worker.ready");
    assert_eq!(*lock(&admissions), 1);
    // Exactly one P-03 start was observed and exactly one durable ready event
    // was appended; the receipt above already binds operation/digest/generation.
    assert_eq!(lock(&evidence).len(), 1);
    assert_eq!(lock(&events).len(), 1);
    assert_eq!(
        lock(&events).first().map(|event| event.event_id.clone()),
        Some(ready.ready_event.event_id.clone())
    );
    assert!(!expected_digest_for_echo.is_empty());

    // Exactly once: a second claimed start is refused before admission. The
    // duplicate reuses the same nonce so its invocation digest still matches
    // the admitted join; the call therefore reaches the lifecycle gate (which
    // runs before admission) instead of failing the join first.
    let (process_two, _) = build_process(
        "operation-1",
        "tree-1",
        success_argv(&ready_bat),
        "nonce-claimed-1",
    );
    let request_two = claim_request(&registration, &claim_value);
    let second = block_on(worker.start_claimed(request_two, hello(), process_two));
    assert!(
        matches!(
            second,
            Err(NativeWorkerError::Core(WorkerError::InvalidLifecycle))
        ),
        "second start must be refused without a new admission, got {second:?}"
    );
    assert_eq!(*lock(&admissions), 1);
    assert_eq!(lock(&evidence).len(), 1);
    assert_eq!(lock(&events).len(), 1);

    // The same bounded shape completes 0 with bounded stdout through the real
    // executor directly: launch a fresh instance and observe it to termination.
    let direct_bat = write_bat("a-direct", SUCCESS_BAT);
    let (direct_process, direct_authority) = build_process(
        "operation-1-complete",
        "tree-1-complete",
        success_argv(&direct_bat),
        "nonce-direct-1",
    );
    let direct_operation = direct_process.operation_id().clone();
    let direct_executor = WindowsProcessExecutor::new(authority_port(
        direct_authority,
        direct_process.fence().clone(),
    ));
    let direct_sink: Arc<dyn ProcessEvidenceSink> = Arc::new(RecordingSink {
        evidence: Arc::new(Mutex::new(Vec::new())),
    });
    block_on(direct_executor.start(direct_process, direct_sink))
        .unwrap_or_else(|error| panic!("bounded child must launch, got {error:?}"));
    let terminal = poll_terminal(&direct_executor, &direct_operation);
    let exit = terminal
        .exit()
        .expect("terminal view carries an exit observation");
    let exit_json = serde_json::to_value(exit).expect("exit observation serializes");
    assert_eq!(
        exit_json
            .get("disposition")
            .and_then(|value| value.as_str()),
        Some("completed")
    );
    assert_eq!(
        exit_json.get("code").and_then(|value| value.as_i64()),
        Some(0)
    );
    let (stdout, _) = direct_executor
        .captured_output(&direct_operation)
        .expect("completed operation retains stream projections");
    assert!(stdout.captured && stdout.complete && !stdout.bytes.is_empty());
    assert!(stdout.total_bytes <= 4_096);
    remove_bat("a-ready");
    remove_bat("a-direct");
}

#[test]
fn stale_and_mismatched_claims_are_refused_with_zero_starts() {
    type SetupFn = fn(
        NativeWorkerRegistration,
        NativeWorkerClaim,
    ) -> (NativeWorkerRegistration, NativeWorkerClaim);
    struct NegativeCase {
        name: &'static str,
        setup: SetupFn,
        corrupt_echo: bool,
        expected: WorkerError,
        expected_admissions: usize,
    }
    let cases: [NegativeCase; 5] = [
        NegativeCase {
            name: "stale epoch",
            setup: tamper_epoch,
            corrupt_echo: false,
            expected: WorkerError::StaleEpoch,
            expected_admissions: 0,
        },
        NegativeCase {
            name: "stale generation",
            setup: tamper_generation,
            corrupt_echo: false,
            expected: WorkerError::InvalidRequest("generation_binding"),
            expected_admissions: 0,
        },
        NegativeCase {
            name: "changed route",
            setup: tamper_route,
            corrupt_echo: false,
            expected: WorkerError::InvalidRequest("executable_binding.route_ref"),
            expected_admissions: 0,
        },
        NegativeCase {
            name: "changed invocation digest",
            setup: tamper_invocation_digest,
            corrupt_echo: false,
            expected: WorkerError::InvalidRequest("executable_binding.process_invocation_digest"),
            expected_admissions: 0,
        },
        NegativeCase {
            name: "disagreeing grant claim echo",
            setup: identity,
            corrupt_echo: true,
            expected: WorkerError::AdmissionMismatch("claim_binding"),
            expected_admissions: 1,
        },
    ];
    for case in cases {
        let negative_bat = write_bat("b-negative", SUCCESS_BAT);
        let ClaimedSetup {
            mut worker,
            registration,
            claim_value,
            hello_value,
            process,
            admissions,
            evidence,
            events,
        } = ClaimedSetup::build(
            success_argv(&negative_bat),
            "operation-1",
            "tree-1",
            "nonce-negative-1",
            case.corrupt_echo,
            false,
        );
        let (registration, claim_value) = (case.setup)(registration, claim_value);
        let request = claim_request(&registration, &claim_value);
        let result = block_on(worker.start_claimed(request, hello_value, process));
        match result {
            Err(NativeWorkerError::Core(error)) => {
                assert_eq!(error, case.expected, "refusal dimension: {}", case.name);
            }
            other => panic!(
                "refusal dimension {}: expected a typed core refusal, got {other:?}",
                case.name
            ),
        }
        assert_eq!(worker.lifecycle(), WorkerLifecycle::Created);
        assert_eq!(
            *lock(&admissions),
            case.expected_admissions,
            "refusal dimension: {}",
            case.name
        );
        // Zero process starts through the real executor: P-03 records its
        // initial evidence on every start, so an empty sink plus no durable
        // events proves nothing launched and nothing became Ready.
        assert!(
            lock(&evidence).is_empty(),
            "refusal dimension: {}",
            case.name
        );
        assert!(lock(&events).is_empty(), "refusal dimension: {}", case.name);
        remove_bat("b-negative");
    }
}

#[test]
fn failing_bounded_op_is_typed_and_never_ready_while_host_survives() {
    // The nonzero exit is observed directly through the real executor: launch
    // the failing bounded shape and watch it terminate with code 3.
    let fail_direct_bat = write_bat("c-fail-direct", FAIL_BAT);
    let (fail_process, fail_authority) = build_process(
        "operation-fail-direct",
        "tree-fail-direct",
        fail_argv(&fail_direct_bat),
        "nonce-fail-direct",
    );
    let fail_operation = fail_process.operation_id().clone();
    let fail_executor =
        WindowsProcessExecutor::new(authority_port(fail_authority, fail_process.fence().clone()));
    let fail_sink: Arc<dyn ProcessEvidenceSink> = Arc::new(RecordingSink {
        evidence: Arc::new(Mutex::new(Vec::new())),
    });
    block_on(fail_executor.start(fail_process, fail_sink))
        .unwrap_or_else(|error| panic!("failing child must still launch, got {error:?}"));
    let terminal = poll_terminal(&fail_executor, &fail_operation);
    let exit = terminal
        .exit()
        .expect("terminal view carries an exit observation");
    let exit_json = serde_json::to_value(exit).expect("exit observation serializes");
    assert_eq!(
        exit_json
            .get("disposition")
            .and_then(|value| value.as_str()),
        Some("completed")
    );
    assert_eq!(
        exit_json.get("code").and_then(|value| value.as_i64()),
        Some(3)
    );

    // The worker-level failure path is typed and never Ready: with P-03
    // evidence rejected, the same failing shape lands in `UnknownOutcome`.
    let fail_worker_bat = write_bat("c-fail-worker", FAIL_BAT);
    let ClaimedSetup {
        mut worker,
        registration,
        claim_value,
        hello_value,
        process,
        admissions,
        evidence: _,
        events,
    } = ClaimedSetup::build(
        fail_argv(&fail_worker_bat),
        "operation-fail-worker",
        "tree-fail-worker",
        "nonce-fail-worker",
        false,
        true,
    );
    let request = claim_request(&registration, &claim_value);
    let result = block_on(worker.start_claimed(request, hello_value, process));
    assert!(
        matches!(
            result,
            Err(NativeWorkerError::Core(WorkerError::UnknownOutcome))
        ),
        "failing worker must surface typed UnknownOutcome, got {result:?}"
    );
    assert_eq!(worker.lifecycle(), WorkerLifecycle::UnknownOutcome);
    assert_ne!(worker.lifecycle(), WorkerLifecycle::Ready);
    assert_eq!(*lock(&admissions), 1);
    assert_eq!(lock(&events).len(), 1);
    assert_eq!(
        lock(&events)
            .first()
            .map(|event| event.payload_type.clone()),
        Some("worker.unknown_outcome".to_owned())
    );

    // The host survives: a fresh worker still reaches Ready afterwards.
    let live_bat = write_bat("c-live", SUCCESS_BAT);
    let ClaimedSetup {
        mut worker,
        registration,
        claim_value,
        hello_value,
        process,
        ..
    } = ClaimedSetup::build(
        success_argv(&live_bat),
        "operation-1",
        "tree-1",
        "nonce-live-1",
        false,
        false,
    );
    let request = claim_request(&registration, &claim_value);
    block_on(worker.start_claimed(request, hello_value, process))
        .unwrap_or_else(|error| panic!("host must still launch workers, got {error:?}"));
    assert_eq!(worker.lifecycle(), WorkerLifecycle::Ready);
    remove_bat("c-fail-direct");
    remove_bat("c-fail-worker");
    remove_bat("c-live");
}
