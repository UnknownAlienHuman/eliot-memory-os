#![allow(
    clippy::expect_used,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use eliot_agent_api::{
    AttemptId, AuthorityEnvelope, AuthorityEpoch, AuthorizedEffect, EffectCeiling, EffectKind,
    ProposedEffect, WorkLeaseId,
};
use eliot_process::{
    CancellationReceipt, DescendantEvidence, EnvironmentProjection, EvidenceSinkError,
    FencingToken, Generation, OperationId, ProcessEvidence, ProcessEvidenceSink,
    ProcessExecutionError, ProcessExecutionView, ProcessExecutor, ProcessHealth,
    ProcessHealthStatus, ProcessIdentity, ProcessLifecycle, ProcessRequest, ProcessStartReceipt,
    ProcessState, ProcessTreeId, ResourceLimits,
};

use super::*;

type TestCore = WorkerCore<FakeExecutor, FakeAdmission, FakeReplay, FakeReplay>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartMode {
    Normal,
    NoEvidence,
    MismatchedEvidence,
    MismatchedReceipt,
    Unknown,
}

struct ExecutorState {
    starts: usize,
    inspections: usize,
    cancels: usize,
    reconciliations: usize,
    start_mode: StartMode,
    cancel_unknown: bool,
    request: Option<ProcessRequest>,
    process: Option<ProcessState>,
}

impl Default for ExecutorState {
    fn default() -> Self {
        Self {
            starts: 0,
            inspections: 0,
            cancels: 0,
            reconciliations: 0,
            start_mode: StartMode::Normal,
            cancel_unknown: false,
            request: None,
            process: None,
        }
    }
}

#[derive(Clone, Default)]
struct FakeExecutor {
    state: Arc<Mutex<ExecutorState>>,
}

impl FakeExecutor {
    fn with_start_mode(mode: StartMode) -> Self {
        let this = Self::default();
        this.state.lock().expect("executor lock").start_mode = mode;
        this
    }
}

impl ProcessExecutor for FakeExecutor {
    async fn start(
        &self,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
        let mut state = self.state.lock().expect("executor lock");
        state.starts += 1;
        state.request = Some(request.clone());
        if state.start_mode == StartMode::Unknown {
            return Err(ProcessExecutionError::UnknownOutcome);
        }

        let mut process = ProcessState::new(request.clone())?;
        let identity = ProcessIdentity::new(
            eliot_process::ProcessId::new("process-1")?,
            request.process_tree_id().clone(),
            request.generation(),
            42,
            100,
            request.executable_sha256(),
        )?;
        process.start(identity)?;
        process.mark_running(ProcessHealth::new(
            ProcessHealthStatus::Healthy,
            true,
            101,
            None,
        )?)?;
        let mut evidence = ProcessEvidence::new(
            request.operation_id().clone(),
            request.invocation_digest(),
            process.view(),
            None,
            None,
        )?;
        if state.start_mode == StartMode::MismatchedEvidence {
            let other = process_request_with("operation-other", "tree-other", 2);
            let mut other_process = ProcessState::new(other.clone())?;
            other_process.start(ProcessIdentity::new(
                eliot_process::ProcessId::new("process-other")?,
                other.process_tree_id().clone(),
                other.generation(),
                43,
                101,
                other.executable_sha256(),
            )?)?;
            other_process.mark_running(ProcessHealth::new(
                ProcessHealthStatus::Healthy,
                true,
                102,
                None,
            )?)?;
            evidence = ProcessEvidence::new(
                other.operation_id().clone(),
                other.invocation_digest(),
                other_process.view(),
                None,
                None,
            )?;
        }
        if state.start_mode != StartMode::NoEvidence {
            sink.record(evidence)?;
        }
        state.process = Some(process);

        if state.start_mode == StartMode::MismatchedReceipt {
            let other = process_request_with("operation-other", "tree-other", 2);
            return Ok(ProcessStartReceipt::new(&other, ProcessLifecycle::Running)?);
        }
        Ok(ProcessStartReceipt::new(
            &request,
            ProcessLifecycle::Running,
        )?)
    }

    async fn inspect(
        &self,
        _operation_id: OperationId,
    ) -> Result<ProcessExecutionView, ProcessExecutionError> {
        let mut state = self.state.lock().expect("executor lock");
        state.inspections += 1;
        state
            .process
            .as_ref()
            .map(ProcessState::view)
            .ok_or(ProcessExecutionError::NotFound)
    }

    async fn cancel(
        &self,
        _operation_id: OperationId,
    ) -> Result<CancellationReceipt, ProcessExecutionError> {
        let mut state = self.state.lock().expect("executor lock");
        state.cancels += 1;
        let cancel_unknown = state.cancel_unknown;
        let process = state
            .process
            .as_mut()
            .ok_or(ProcessExecutionError::NotFound)?;
        if cancel_unknown {
            process.transition(ProcessLifecycle::UnknownOutcome)?;
            return Err(ProcessExecutionError::UnknownOutcome);
        }
        let fence = process.request().fence().clone();
        Ok(process.cancel(&fence)?)
    }

    async fn reconcile(
        &self,
        _operation_id: OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError> {
        let mut state = self.state.lock().expect("executor lock");
        state.reconciliations += 1;
        let process = state
            .process
            .as_mut()
            .ok_or(ProcessExecutionError::NotFound)?;
        let descendants = DescendantEvidence::new(
            vec![eliot_process::ProcessId::new("process-1")?],
            true,
            true,
            Some("evidence-1".to_owned()),
        )?;
        process.reconcile(descendants)?;
        Ok(ProcessEvidence::new(
            process.request().operation_id().clone(),
            process.request().invocation_digest(),
            process.view(),
            None,
            None,
        )?)
    }
}

#[derive(Default)]
struct AdmissionState {
    admissions: usize,
    revalidations: usize,
    effect_admissions: usize,
    revoked: bool,
    stale_lease: bool,
    stale_fence: bool,
    stale_revision: bool,
    effect_rejected: bool,
    effect_revoked: bool,
    effect_expired: bool,
    observed_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

#[derive(Clone, Default)]
struct FakeAdmission {
    state: Arc<Mutex<AdmissionState>>,
}

impl CapabilityAdmissionPort for FakeAdmission {
    fn admit(
        &mut self,
        request: &CapabilityAdmissionRequest,
    ) -> Result<CapabilityAdmissionOutcome, ProviderFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProviderFailure::new("admission", "lock"))?;
        state.admissions += 1;
        if state.expires_at_unix_ms == 0 {
            state.observed_at_unix_ms = 100;
            state.expires_at_unix_ms = 10_000;
        }
        let authority = authority(request.hello().state_fence.clone());
        Ok(CapabilityAdmissionOutcome::Admitted(Box::new(
            CapabilityAdmissionFacts::new(
                "admission-1",
                "admission-revision-1",
                1,
                state.observed_at_unix_ms,
                state.expires_at_unix_ms,
                "worker-stream-1",
                "worker-producer-1",
                request.hello().route_ref.clone(),
                request.hello().artifact_manifest_digest.clone(),
                request.hello().worker_generation,
                authority,
                request.hello().requested_capabilities.clone(),
                request.operation_id().clone(),
                request.process_tree_id().clone(),
                request.process_generation(),
                request.process_fence().clone(),
                request.process_request_digest(),
                *request.resource_limits(),
            ),
        )))
    }

    fn revalidate(
        &mut self,
        request: &CapabilityLivenessRequest,
    ) -> Result<AdmissionLivenessOutcome, ProviderFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProviderFailure::new("admission", "lock"))?;
        state.revalidations += 1;
        if state.revoked {
            return Ok(AdmissionLivenessOutcome::Revoked {
                revision: "revocation-2".to_owned(),
            });
        }
        Ok(AdmissionLivenessOutcome::Live(AdmissionLivenessFacts::new(
            request.admission_id(),
            if state.stale_revision {
                "admission-revision-2".to_owned()
            } else {
                request.admission_revision().to_owned()
            },
            request.revocation_revision(),
            if state.stale_lease {
                WorkLeaseId::new("lease-stale").expect("stale lease")
            } else {
                request.lease().clone()
            },
            request.authority_epoch(),
            if state.stale_fence {
                "state-fence-stale".to_owned()
            } else {
                request.state_fence().to_owned()
            },
            state.observed_at_unix_ms,
            state.expires_at_unix_ms,
            false,
        )))
    }

    fn authorize_effect(
        &mut self,
        request: &EffectAdmissionRequest,
    ) -> Result<EffectAdmissionOutcome, ProviderFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProviderFailure::new("admission", "lock"))?;
        state.effect_admissions += 1;
        if state.effect_rejected {
            return Ok(EffectAdmissionOutcome::Rejected {
                reason: "policy".to_owned(),
            });
        }
        if state.effect_revoked {
            return Ok(EffectAdmissionOutcome::Revoked {
                revision: "revocation-2".to_owned(),
            });
        }
        let expires_at_unix_ms = if state.effect_expired {
            state.observed_at_unix_ms.saturating_sub(1)
        } else {
            state.expires_at_unix_ms
        };
        Ok(EffectAdmissionOutcome::Authorized(Box::new(
            EffectAdmissionFacts::new(
                AuthorizedEffect {
                    proposal: request.proposal().clone(),
                    authority_epoch: AuthorityEpoch::new(request.authority_epoch())
                        .expect("authority epoch"),
                    authorization_ref: "effect-authorization-1".to_owned(),
                    authorized_at: "provider-observed".to_owned(),
                    expires_at: "provider-expiry".to_owned(),
                },
                request.lease().clone(),
                request.state_fence(),
                request.admission_revision(),
                request.revocation_revision(),
                state.observed_at_unix_ms,
                expires_at_unix_ms,
                false,
            ),
        )))
    }
}

#[derive(Default)]
struct ReplayState {
    next_sequence: u64,
    requests: BTreeMap<(String, String), String>,
    events: Vec<WorkerEventEnvelope>,
    acknowledgements: Vec<EventAckReceipt>,
    checkpoints: usize,
    checkpoint_fail: bool,
    checkpoint_mismatch: bool,
    append_fail: bool,
    replay_stale_tail: bool,
    replay_out_of_order: bool,
}

#[derive(Clone, Default)]
struct FakeReplay {
    state: Arc<Mutex<ReplayState>>,
}

impl DurableReplayPort for FakeReplay {
    fn lookup_request(
        &mut self,
        stream_id: &str,
        request_id: &str,
        fingerprint: &str,
    ) -> Result<DurableRequestDecision, ProviderFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProviderFailure::new("replay", "lock"))?;
        let key = (stream_id.to_owned(), request_id.to_owned());
        let Some(recorded) = state.requests.get(&key) else {
            return Ok(DurableRequestDecision::New);
        };
        if recorded != fingerprint {
            return Ok(DurableRequestDecision::Conflict);
        }
        Ok(DurableRequestDecision::Replay(
            state
                .events
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
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProviderFailure::new("replay", "lock"))?;
        let key = (stream_id.to_owned(), request_id.to_owned());
        if let Some(recorded) = state.requests.get(&key) {
            if recorded != fingerprint {
                return Ok(DurableRequestDecision::Conflict);
            }
            return Ok(DurableRequestDecision::Replay(
                state
                    .events
                    .iter()
                    .filter(|event| event.stream_id == stream_id && event.request_id == request_id)
                    .cloned()
                    .collect(),
            ));
        }
        state.requests.insert(key, fingerprint.to_owned());
        Ok(DurableRequestDecision::New)
    }

    fn append(&mut self, draft: WorkerEventDraft) -> Result<WorkerEventEnvelope, ProviderFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProviderFailure::new("replay", "lock"))?;
        if state.append_fail {
            return Err(ProviderFailure::new("replay", "append failed"));
        }
        state.next_sequence += 1;
        let sequence = state.next_sequence;
        let event = draft
            .into_envelope(format!("event-{sequence}"), sequence)
            .map_err(|error| ProviderFailure::new("replay", error.to_string()))?;
        state.events.push(event.clone());
        Ok(event)
    }

    fn replay(
        &mut self,
        stream_id: &str,
        after_sequence: u64,
    ) -> Result<Vec<WorkerEventEnvelope>, ProviderFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProviderFailure::new("replay", "lock"))?;
        let mut events: Vec<_> = state
            .events
            .iter()
            .filter(|event| event.stream_id == stream_id && event.sequence > after_sequence)
            .cloned()
            .collect();
        if state.replay_stale_tail {
            events.pop();
        }
        if state.replay_out_of_order {
            events.reverse();
        }
        Ok(events)
    }

    fn acknowledge(&mut self, receipt: &EventAckReceipt) -> Result<(), ProviderFailure> {
        self.state
            .lock()
            .map_err(|_| ProviderFailure::new("replay", "lock"))?
            .acknowledgements
            .push(receipt.clone());
        Ok(())
    }
}

impl DurableCheckpointPort for FakeReplay {
    fn persist_checkpoint(
        &mut self,
        request: &DurableCheckpointRequest,
    ) -> Result<CheckpointProviderOutcome, ProviderFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProviderFailure::new("checkpoint", "lock"))?;
        if state.checkpoint_fail {
            return Err(ProviderFailure::new("checkpoint", "persist failed"));
        }
        state.checkpoints += 1;
        let checkpoint_ref = if state.checkpoint_mismatch {
            "checkpoint-wrong"
        } else {
            request.checkpoint_ref()
        };
        Ok(CheckpointProviderOutcome::Stored(Box::new(
            CheckpointReceiptFacts::new(
                format!("checkpoint-receipt-{}", state.checkpoints),
                checkpoint_ref,
                request.request_id(),
                request.stream_id(),
                request.producer_generation(),
                request.authority_epoch(),
                request.state_fence(),
                request.admission_revision(),
                request.operation_id().clone(),
                request.process_request_digest(),
                300,
            ),
        )))
    }
}

#[derive(Clone, Default)]
struct RecordingSink {
    evidence: Arc<Mutex<Vec<ProcessEvidence>>>,
}

impl ProcessEvidenceSink for RecordingSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        self.evidence
            .lock()
            .map_err(|_| EvidenceSinkError {
                message: "lock".to_owned(),
            })?
            .push(evidence);
        Ok(())
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

fn authority(state_fence: String) -> AuthorityEnvelope {
    AuthorityEnvelope {
        epoch: AuthorityEpoch::new("epoch-1").expect("epoch"),
        scope_ref: "scope-1".to_owned(),
        effect_ceiling: EffectCeiling {
            scope_ref: "scope-1".to_owned(),
            allowed: [EffectKind::WriteCandidate].into_iter().collect(),
            max_external_effects: 0,
        },
        lease: WorkLeaseId::new("lease-1").expect("lease"),
        state_fence,
        valid_until: "provider-owned".to_owned(),
    }
}

fn process_request() -> ProcessRequest {
    process_request_with("operation-1", "tree-1", 1)
}

fn process_request_with(operation: &str, tree: &str, generation: u64) -> ProcessRequest {
    let generation = Generation::new(generation).expect("generation");
    ProcessRequest::new(
        OperationId::new(operation).expect("operation"),
        ProcessTreeId::new(tree).expect("tree"),
        generation,
        "worker.exe",
        "a".repeat(64),
        vec!["--native-worker".to_owned()],
        "C:/work",
        EnvironmentProjection::default(),
        ResourceLimits::new(5_000, Some(1_000), Some(1_048_576), 4_096, 4_096, 2).expect("limits"),
        FencingToken::new(1, generation, format!("process-fence-{generation:?}")).expect("fence"),
    )
    .expect("process request")
}

fn hello(connection: &str, request: &str) -> WorkerHello {
    WorkerHello {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        encoding_profile: JSON_ENCODING_PROFILE.to_owned(),
        connection_id: connection.to_owned(),
        request_id: request.to_owned(),
        trace_context: [("trace_id".to_owned(), "trace-1".to_owned())]
            .into_iter()
            .collect(),
        deadline_unix_ms: 5_000,
        artifact_manifest_digest: "manifest-digest-1".to_owned(),
        launch_nonce: "launch-nonce-1".to_owned(),
        worker_generation: 1,
        state_fence: "state-fence-1".to_owned(),
        route_ref: "route-1".to_owned(),
        requested_capabilities: ["inspect".to_owned()].into_iter().collect(),
    }
}

fn frame(request_id: &str, body: WorkerFrameBody) -> WorkerFrame {
    WorkerFrame {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        encoding_profile: JSON_ENCODING_PROFILE.to_owned(),
        connection_id: "connection-1".to_owned(),
        request_id: request_id.to_owned(),
        trace_context: [("trace_id".to_owned(), format!("trace-{request_id}"))]
            .into_iter()
            .collect(),
        deadline_unix_ms: 5_000,
        authority_epoch: "epoch-1".to_owned(),
        state_fence: "state-fence-1".to_owned(),
        lease_id: "lease-1".to_owned(),
        admission_revision: "admission-revision-1".to_owned(),
        producer_generation: 1,
        body,
    }
}

fn request(effect: Option<ProposedEffect>) -> WorkerRequest {
    WorkerRequest {
        attempt_id: AttemptId::new("attempt-1").expect("attempt"),
        capability: "inspect".to_owned(),
        payload: BTreeMap::new(),
        proposed_effect: effect,
    }
}

fn proposed_effect() -> ProposedEffect {
    ProposedEffect {
        effect_id: "effect-1".to_owned(),
        attempt_id: AttemptId::new("attempt-1").expect("attempt"),
        kind: EffectKind::WriteCandidate,
        scope_ref: "scope-1".to_owned(),
        payload_digest: "payload-digest-1".to_owned(),
        rationale_ref: None,
    }
}

fn fixture() -> (
    TestCore,
    FakeExecutor,
    FakeAdmission,
    FakeReplay,
    RecordingSink,
) {
    fixture_with_executor(FakeExecutor::default())
}

fn fixture_with_executor(
    executor: FakeExecutor,
) -> (
    TestCore,
    FakeExecutor,
    FakeAdmission,
    FakeReplay,
    RecordingSink,
) {
    let admission = FakeAdmission::default();
    let replay = FakeReplay::default();
    let sink = RecordingSink::default();
    let core = WorkerCore::new(
        Some(executor.clone()),
        Some(admission.clone()),
        Some(replay.clone()),
        Some(replay.clone()),
        Some(Arc::new(sink.clone())),
    );
    (core, executor, admission, replay, sink)
}

fn start(core: &mut TestCore) -> ProcessRequest {
    let process = process_request();
    block_on(core.demand_start(hello("connection-1", "start-1"), process.clone()))
        .expect("demand start");
    process
}

#[test]
fn missing_process_provider_is_a_typed_plan_gap_before_admission() {
    let admission = FakeAdmission::default();
    let replay = FakeReplay::default();
    let sink = RecordingSink::default();
    let mut core: TestCore = WorkerCore::new(
        None,
        Some(admission.clone()),
        Some(replay.clone()),
        Some(replay),
        Some(Arc::new(sink)),
    );
    let result = block_on(core.demand_start(hello("connection-1", "start-1"), process_request()));
    assert!(matches!(
        result,
        Err(WorkerError::PlanGap {
            code: PROCESS_PROVIDER_PLAN_GAP,
            ..
        })
    ));
    assert_eq!(
        admission.state.lock().expect("admission lock").admissions,
        0
    );
    assert_eq!(core.lifecycle(), WorkerLifecycle::Created);
}

#[test]
fn public_start_is_inert_without_g01_admission() {
    let executor = FakeExecutor::default();
    let replay = FakeReplay::default();
    let sink = RecordingSink::default();
    let mut core: TestCore = WorkerCore::new(
        Some(executor.clone()),
        None,
        Some(replay.clone()),
        Some(replay),
        Some(Arc::new(sink)),
    );
    assert!(matches!(
        block_on(core.demand_start(hello("connection-1", "start-1"), process_request())),
        Err(WorkerError::PlanGap {
            code: ADMISSION_PROVIDER_PLAN_GAP,
            ..
        })
    ));
    assert_eq!(executor.state.lock().expect("executor lock").starts, 0);
}

#[test]
fn exact_process_start_receipt_and_evidence_precede_readiness() {
    let (mut core, executor, admission, replay, sink) = fixture();
    let process = start(&mut core);
    assert_eq!(core.lifecycle(), WorkerLifecycle::Ready);
    assert_eq!(
        core.process_state(),
        eliot_runtime_contracts::ServiceProcessState::Ready
    );
    let state = executor.state.lock().expect("executor lock");
    assert_eq!(state.starts, 1);
    assert_eq!(state.inspections, 1);
    let observed = state.request.as_ref().expect("captured request");
    assert_eq!(observed.operation_id(), process.operation_id());
    assert_eq!(observed.process_tree_id(), process.process_tree_id());
    assert_eq!(observed.generation(), process.generation());
    assert!(observed.fence().matches(process.fence()));
    assert_eq!(observed.resource_limits(), process.resource_limits());
    assert_eq!(observed.invocation_digest(), process.invocation_digest());
    drop(state);
    assert_eq!(
        admission.state.lock().expect("admission lock").admissions,
        1
    );
    assert_eq!(sink.evidence.lock().expect("evidence lock").len(), 1);
    assert_eq!(replay.state.lock().expect("replay lock").events.len(), 1);
    let receipt = core.process_start_receipt().expect("start receipt");
    assert_eq!(receipt.operation_id(), process.operation_id());
    assert_eq!(receipt.request_digest(), process.invocation_digest());
}

#[test]
fn mismatched_start_receipt_never_reaches_ready() {
    let (mut core, _, _, _, _) =
        fixture_with_executor(FakeExecutor::with_start_mode(StartMode::MismatchedReceipt));
    assert!(matches!(
        block_on(core.demand_start(hello("connection-1", "start-1"), process_request())),
        Err(WorkerError::ProcessReceiptMismatch(_))
    ));
    assert_eq!(core.lifecycle(), WorkerLifecycle::UnknownOutcome);
}

#[test]
fn stale_epoch_and_fence_are_rejected_before_live_provider_use() {
    let (mut core, _, admission, _, _) = fixture();
    start(&mut core);
    let before = admission
        .state
        .lock()
        .expect("admission lock")
        .revalidations;
    let mut stale_epoch = frame("execute-epoch", WorkerFrameBody::Execute(request(None)));
    stale_epoch.authority_epoch = "epoch-stale".to_owned();
    assert_eq!(
        block_on(core.handle(stale_epoch)),
        Err(WorkerError::StaleEpoch)
    );
    let mut stale_fence = frame("execute-fence", WorkerFrameBody::Execute(request(None)));
    stale_fence.state_fence = "state-fence-stale".to_owned();
    assert_eq!(
        block_on(core.handle(stale_fence)),
        Err(WorkerError::StaleFence)
    );
    assert_eq!(
        admission
            .state
            .lock()
            .expect("admission lock")
            .revalidations,
        before
    );
}

#[test]
fn live_lease_revision_expiry_and_revocation_fail_closed() {
    for expected in ["lease", "revision", "expired", "revoked"] {
        let (mut core, _, admission, _, _) = fixture();
        start(&mut core);
        {
            let mut state = admission.state.lock().expect("admission lock");
            match expected {
                "lease" => state.stale_lease = true,
                "revision" => state.stale_revision = true,
                "expired" => state.observed_at_unix_ms = 20_000,
                "revoked" => state.revoked = true,
                _ => unreachable!(),
            }
        }
        let result = block_on(core.handle(frame(
            &format!("execute-{expected}"),
            WorkerFrameBody::Execute(request(None)),
        )));
        match expected {
            "lease" | "expired" => assert_eq!(result, Err(WorkerError::StaleLease)),
            "revision" => assert_eq!(result, Err(WorkerError::StaleRevision)),
            "revoked" => assert!(matches!(result, Err(WorkerError::Revoked(_)))),
            _ => unreachable!(),
        }
    }
}

#[test]
fn effect_is_only_candidate_after_exact_live_provider_admission() {
    let (mut core, executor, admission, replay, _) = fixture();
    start(&mut core);
    let events = block_on(core.handle(frame(
        "effect-1",
        WorkerFrameBody::Execute(request(Some(proposed_effect()))),
    )))
    .expect("authorized candidate");
    assert_eq!(events.len(), 2);
    assert!(matches!(
        events[1].payload,
        WorkerEventPayload::CandidateOnly { .. }
    ));
    assert_eq!(
        admission
            .state
            .lock()
            .expect("admission lock")
            .effect_admissions,
        1
    );
    assert_eq!(executor.state.lock().expect("executor lock").starts, 1);
    assert_eq!(replay.state.lock().expect("replay lock").events.len(), 3);
}

#[test]
fn rejected_revoked_and_expired_effects_emit_no_candidate_event() {
    for mode in ["rejected", "revoked", "expired"] {
        let (mut core, _, admission, replay, _) = fixture();
        start(&mut core);
        {
            let mut state = admission.state.lock().expect("admission lock");
            match mode {
                "rejected" => state.effect_rejected = true,
                "revoked" => state.effect_revoked = true,
                "expired" => state.effect_expired = true,
                _ => unreachable!(),
            }
        }
        let result = block_on(core.handle(frame(
            &format!("effect-{mode}"),
            WorkerFrameBody::Execute(request(Some(proposed_effect()))),
        )));
        match mode {
            "rejected" => assert!(matches!(result, Err(WorkerError::EffectRejected(_)))),
            "revoked" => assert!(matches!(result, Err(WorkerError::Revoked(_)))),
            "expired" => assert_eq!(result, Err(WorkerError::StaleLease)),
            _ => unreachable!(),
        }
        assert_eq!(replay.state.lock().expect("replay lock").events.len(), 1);
    }
}

#[test]
fn cancel_calls_p03_once_and_replays_the_same_durable_event() {
    let (mut core, executor, _, _, _) = fixture();
    start(&mut core);
    let cancel = frame(
        "cancel-1",
        WorkerFrameBody::Cancel(CancelRequest {
            attempt_id: AttemptId::new("attempt-1").expect("attempt"),
            reason: "operator".to_owned(),
        }),
    );
    let first = block_on(core.handle(cancel.clone())).expect("cancel");
    let second = block_on(core.handle(cancel)).expect("cancel replay");
    assert_eq!(first, second);
    assert_eq!(first[0].event_id, second[0].event_id);
    assert_eq!(executor.state.lock().expect("executor lock").cancels, 1);
}

#[test]
fn unknown_cancel_blocks_work_until_exact_p03_reconciliation() {
    let (mut core, executor, _, _, _) = fixture();
    start(&mut core);
    executor.state.lock().expect("executor lock").cancel_unknown = true;
    let unknown = block_on(core.handle(frame(
        "cancel-unknown",
        WorkerFrameBody::Cancel(CancelRequest {
            attempt_id: AttemptId::new("attempt-1").expect("attempt"),
            reason: "timeout".to_owned(),
        }),
    )))
    .expect("unknown event");
    assert!(matches!(
        unknown[0].payload,
        WorkerEventPayload::UnknownOutcome
    ));
    assert_eq!(core.lifecycle(), WorkerLifecycle::UnknownOutcome);
    assert_eq!(
        block_on(core.handle(frame(
            "execute-blocked",
            WorkerFrameBody::Execute(request(None))
        ))),
        Err(WorkerError::InvalidLifecycle)
    );
    let reconciled =
        block_on(core.handle(frame("reconcile-1", WorkerFrameBody::Reconcile))).expect("reconcile");
    assert!(matches!(
        reconciled[0].payload,
        WorkerEventPayload::Reconciled { .. }
    ));
    assert_eq!(core.lifecycle(), WorkerLifecycle::Reconciled);
    assert_eq!(
        executor
            .state
            .lock()
            .expect("executor lock")
            .reconciliations,
        1
    );
}

#[test]
fn restart_uses_inspect_and_durable_replay_without_duplicate_start() {
    let (mut first, executor, admission, replay, sink) = fixture();
    let process = start(&mut first);
    let heartbeat = block_on(first.handle(frame("heartbeat-1", WorkerFrameBody::Heartbeat)))
        .expect("heartbeat");
    let original_id = heartbeat[0].event_id.clone();

    let mut restarted = WorkerCore::new(
        Some(executor.clone()),
        Some(admission),
        Some(replay.clone()),
        Some(replay),
        Some(Arc::new(sink)),
    );
    let recovery =
        block_on(restarted.recover_after_restart(hello("connection-2", "recover-1"), process, 0))
            .expect("recovery");
    assert_eq!(recovery.lifecycle, WorkerLifecycle::Ready);
    assert!(
        recovery
            .replayed_events
            .iter()
            .any(|event| event.event_id == original_id)
    );
    let state = executor.state.lock().expect("executor lock");
    assert_eq!(state.starts, 1);
    assert_eq!(state.inspections, 2);
}

#[test]
fn reconnect_replays_and_ack_advances_only_through_durable_port() {
    let (mut core, _, _, replay, _) = fixture();
    start(&mut core);
    let heartbeat =
        block_on(core.handle(frame("heartbeat-1", WorkerFrameBody::Heartbeat))).expect("heartbeat");
    let events = block_on(core.handle(frame(
        "reconnect-1",
        WorkerFrameBody::Reconnect(ReconnectRequest {
            previous_connection_id: "connection-1".to_owned(),
            new_connection_id: "connection-2".to_owned(),
            replay_after_sequence: 0,
        }),
    )))
    .expect("reconnect");
    assert!(
        events
            .iter()
            .any(|event| event.event_id == heartbeat[0].event_id)
    );
    let mut ack_frame = frame(
        "ack-1",
        WorkerFrameBody::Acknowledge(EventAckReceipt {
            stream_id: heartbeat[0].stream_id.clone(),
            event_id: heartbeat[0].event_id.clone(),
            sequence: heartbeat[0].sequence,
            producer_generation: 1,
            authority_epoch: "epoch-1".to_owned(),
            state_fence: "state-fence-1".to_owned(),
            phase: AckPhase::Normalized,
            acknowledged_at_unix_ms: 200,
        }),
    );
    ack_frame.connection_id = "connection-2".to_owned();
    assert!(block_on(core.handle(ack_frame)).expect("ack").is_empty());
    assert_eq!(
        replay
            .state
            .lock()
            .expect("replay lock")
            .acknowledgements
            .len(),
        1
    );
}

#[test]
fn health_checkpoint_quiesce_and_shutdown_are_explicit_lifecycle_messages() {
    let (mut core, _, _, _, _) = fixture();
    start(&mut core);
    let health = block_on(core.handle(frame("health-1", WorkerFrameBody::Health))).expect("health");
    assert!(matches!(
        health[0].payload,
        WorkerEventPayload::Health { .. }
    ));
    let checkpoint = block_on(core.handle(frame(
        "checkpoint-1",
        WorkerFrameBody::Checkpoint(CheckpointRequest {
            checkpoint_ref: "checkpoint-blob-1".to_owned(),
        }),
    )))
    .expect("checkpoint");
    assert!(matches!(
        checkpoint[0].payload,
        WorkerEventPayload::Checkpoint { .. }
    ));
    block_on(core.handle(frame("quiesce-1", WorkerFrameBody::Quiesce))).expect("quiesce");
    assert_eq!(core.lifecycle(), WorkerLifecycle::Quiescing);
    block_on(core.handle(frame("shutdown-1", WorkerFrameBody::Shutdown))).expect("shutdown");
    assert_eq!(core.lifecycle(), WorkerLifecycle::Stopped);
}

#[test]
fn start_unknown_outcome_is_durable_and_never_ready() {
    let (mut core, _, _, replay, _) =
        fixture_with_executor(FakeExecutor::with_start_mode(StartMode::Unknown));
    assert_eq!(
        block_on(core.demand_start(hello("connection-1", "start-unknown"), process_request())),
        Err(WorkerError::UnknownOutcome)
    );
    assert_eq!(core.lifecycle(), WorkerLifecycle::UnknownOutcome);
    let state = replay.state.lock().expect("replay lock");
    assert!(matches!(
        state.events[0].payload,
        WorkerEventPayload::UnknownOutcome
    ));
}

#[test]
fn exact_receipt_without_observed_evidence_never_reaches_ready() {
    let (mut core, _, _, _, sink) =
        fixture_with_executor(FakeExecutor::with_start_mode(StartMode::NoEvidence));
    assert!(matches!(
        block_on(core.demand_start(
            hello("connection-1", "start-no-evidence"),
            process_request()
        )),
        Err(WorkerError::PlanGap {
            code: PROCESS_EVIDENCE_PLAN_GAP,
            ..
        })
    ));
    assert_eq!(core.lifecycle(), WorkerLifecycle::UnknownOutcome);
    assert!(sink.evidence.lock().expect("evidence lock").is_empty());
}

#[test]
fn mismatched_observed_evidence_never_reaches_ready() {
    let (mut core, _, _, _, _) =
        fixture_with_executor(FakeExecutor::with_start_mode(StartMode::MismatchedEvidence));
    assert!(matches!(
        block_on(core.demand_start(
            hello("connection-1", "start-bad-evidence"),
            process_request()
        )),
        Err(WorkerError::ProcessReceiptMismatch("process_evidence"))
    ));
    assert_eq!(core.lifecycle(), WorkerLifecycle::UnknownOutcome);
}

#[test]
fn checkpoint_requires_exact_durable_provider_receipt() {
    let (mut core, _, _, replay, _) = fixture();
    start(&mut core);
    core.checkpoint = None;
    assert!(matches!(
        block_on(core.handle(frame(
            "checkpoint-gap",
            WorkerFrameBody::Checkpoint(CheckpointRequest {
                checkpoint_ref: "checkpoint-blob-1".to_owned(),
            })
        ))),
        Err(WorkerError::PlanGap {
            code: CHECKPOINT_PROVIDER_PLAN_GAP,
            ..
        })
    ));
    core.checkpoint = Some(replay.clone());
    replay
        .state
        .lock()
        .expect("replay lock")
        .checkpoint_mismatch = true;
    assert!(matches!(
        block_on(core.handle(frame(
            "checkpoint-mismatch",
            WorkerFrameBody::Checkpoint(CheckpointRequest {
                checkpoint_ref: "checkpoint-blob-1".to_owned(),
            })
        ))),
        Err(WorkerError::CheckpointReceiptMismatch("request_binding"))
    ));
}

#[test]
fn checkpoint_and_lifecycle_provider_failures_do_not_overclaim() {
    let (mut core, _, _, replay, _) = fixture();
    start(&mut core);
    replay.state.lock().expect("replay lock").checkpoint_fail = true;
    assert!(matches!(
        block_on(core.handle(frame(
            "checkpoint-fail",
            WorkerFrameBody::Checkpoint(CheckpointRequest {
                checkpoint_ref: "checkpoint-blob-1".to_owned(),
            })
        ))),
        Err(WorkerError::Provider(_))
    ));
    {
        let mut state = replay.state.lock().expect("replay lock");
        state.checkpoint_fail = false;
        state.append_fail = true;
    }
    assert!(matches!(
        block_on(core.handle(frame("quiesce-fail", WorkerFrameBody::Quiesce))),
        Err(WorkerError::Provider(_))
    ));
    assert_eq!(core.lifecycle(), WorkerLifecycle::Ready);
    replay.state.lock().expect("replay lock").append_fail = false;
    block_on(core.handle(frame("quiesce-ok", WorkerFrameBody::Quiesce))).expect("quiesce");
    replay.state.lock().expect("replay lock").append_fail = true;
    assert!(matches!(
        block_on(core.handle(frame("shutdown-fail", WorkerFrameBody::Shutdown))),
        Err(WorkerError::Provider(_))
    ));
    assert_eq!(core.lifecycle(), WorkerLifecycle::Quiescing);
}

#[test]
fn reconnect_failure_preserves_connection_and_cursor() {
    let (mut core, _, _, replay, _) = fixture();
    start(&mut core);
    replay.state.lock().expect("replay lock").append_fail = true;
    assert!(matches!(
        block_on(core.handle(frame(
            "reconnect-fail",
            WorkerFrameBody::Reconnect(ReconnectRequest {
                previous_connection_id: "connection-1".to_owned(),
                new_connection_id: "connection-2".to_owned(),
                replay_after_sequence: 1,
            })
        ))),
        Err(WorkerError::Provider(_))
    ));
    replay.state.lock().expect("replay lock").append_fail = false;
    assert!(block_on(core.handle(frame("health-old-connection", WorkerFrameBody::Health))).is_ok());
}

#[test]
fn reconnect_rejects_stale_out_of_order_and_ahead_cursors() {
    let (mut core, _, _, replay, _) = fixture();
    start(&mut core);
    block_on(core.handle(frame("heartbeat-cursor", WorkerFrameBody::Heartbeat)))
        .expect("heartbeat");
    replay.state.lock().expect("replay lock").replay_stale_tail = true;
    let reconnect = || {
        WorkerFrameBody::Reconnect(ReconnectRequest {
            previous_connection_id: "connection-1".to_owned(),
            new_connection_id: "connection-2".to_owned(),
            replay_after_sequence: 0,
        })
    };
    assert!(matches!(
        block_on(core.handle(frame("reconnect-stale", reconnect()))),
        Err(WorkerError::ReplayContract("stale_replay_tail"))
    ));
    {
        let mut state = replay.state.lock().expect("replay lock");
        state.replay_stale_tail = false;
        state.replay_out_of_order = true;
    }
    assert!(matches!(
        block_on(core.handle(frame("reconnect-order", reconnect()))),
        Err(WorkerError::ReplayContract("replay_binding"))
    ));
    replay
        .state
        .lock()
        .expect("replay lock")
        .replay_out_of_order = false;
    assert!(matches!(
        block_on(core.handle(frame(
            "reconnect-ahead",
            WorkerFrameBody::Reconnect(ReconnectRequest {
                previous_connection_id: "connection-1".to_owned(),
                new_connection_id: "connection-2".to_owned(),
                replay_after_sequence: 3,
            })
        ))),
        Err(WorkerError::ReplayContract("cursor_ahead"))
    ));
}

#[test]
fn restart_rejects_invalid_durable_tail_without_installing_binding() {
    let (mut first, executor, admission, replay, sink) = fixture();
    let process = start(&mut first);
    block_on(first.handle(frame("heartbeat-restart", WorkerFrameBody::Heartbeat)))
        .expect("heartbeat");
    replay
        .state
        .lock()
        .expect("replay lock")
        .replay_out_of_order = true;
    let mut restarted = WorkerCore::new(
        Some(executor.clone()),
        Some(admission),
        Some(replay.clone()),
        Some(replay),
        Some(Arc::new(sink)),
    );
    assert!(matches!(
        block_on(restarted.recover_after_restart(
            hello("connection-2", "recover-invalid-tail"),
            process,
            0,
        )),
        Err(WorkerError::ReplayContract("replay_binding"))
    ));
    assert_eq!(restarted.lifecycle(), WorkerLifecycle::Created);
    assert_eq!(executor.state.lock().expect("executor lock").starts, 1);
}

#[test]
fn serde_rejects_unknown_fields_on_tagged_inputs() {
    let json = r#"{"kind":"HEALTH","unexpected":true}"#;
    assert!(serde_json::from_str::<WorkerFrameBody>(json).is_err());
}
