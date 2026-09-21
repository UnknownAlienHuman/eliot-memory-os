use std::collections::VecDeque;
use std::error::Error;
use std::num::NonZeroU64;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractIdentity, ContractVersion, EpochId,
    EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration, SessionId, SourceId,
    StateFence, TaskId, TaskRevision, TransactionSequence,
};
use eliot_host_service::{
    DeliveryDisposition, DrainOutcome, HostDeliveryAdmission, HostDeliveryState,
    ReactiveContextCancelOutcome, ReactiveContextCancelRequest, ReactiveContextChannelCloseOutcome,
    ReactiveContextClock, ReactiveContextCloseChannelRequest, ReactiveContextDelivery,
    ReactiveContextDeliveryLimits, ReactiveContextDeliveryRequest,
    ReactiveContextEndpointResolution, ReactiveContextQueryOutcome, ReactiveContextQueryRequest,
    ReactiveContextResolveRequest, ReactiveContextResolvedEndpoint, ReactiveContextSendOutcome,
    ReactiveContextSendRequest, ReactiveContextTransportError, ReactiveContextTransportPort,
    ReactiveContextTransportReceipt, RestartReconciliation,
};
use eliot_host_state::{
    ActivationState, EliotActivationRecord, EpochTransition, FaultPoint, HostInstallationEpoch,
    HostKernelStoreLineage, HostStateJournal, HostStateRecord, IdempotencyIdentity, JournalBackend,
    LifecycleTimestamps, MemoryBackend, ReactiveContextEnqueueReceipt,
    ReactiveContextPrepareRequest, ReactiveContextPrepareResult, ReactiveContextQueueError,
    ReadinessEvidence, RecordFence,
};
use eliot_platform::PlatformHandle;
use eliot_protocol::reactive_context::{
    ReactiveContextAckDisposition, ReactiveContextAckEvidence, ReactiveContextContentRef,
    ReactiveContextLifecycleEvidence, ReactiveContextPayload, ReactiveContextPlannerBinding,
    ReactiveContextPrivacy, ReactiveContextRecipient, ReactiveContextSafetyFloor,
    ReactiveContextSequence, ReactiveContextStage, ReactiveContextValidity,
    ReactiveContextViewBinding, reactive_context_contract_identity,
};
use eliot_protocol::{AckPhase, EventAckReceipt, EventDisposition};
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, CausalBinding, CoordinationBinding, EffectClass,
    OperationBinding, ProofCeiling, ReceiptCore, ReceiptDisposition, ReceiptEnvelope, ReceiptKind,
    RequestBinding, SessionBinding, TaskBinding, WorkScopeBinding, WorkScopeId,
};

type TestResult = Result<(), Box<dyn Error>>;

fn handle(value: &str) -> PlatformHandle {
    PlatformHandle::new(value.to_owned()).expect("valid handle")
}

fn lineage(value: &str) -> EpochLineageId {
    EpochLineageId::new(value).expect("valid lineage")
}

fn epoch(lineage_name: &str, sequence: u64) -> EpochId {
    EpochId::new(
        lineage(lineage_name),
        NonZeroU64::new(sequence).expect("non-zero epoch"),
    )
    .expect("valid epoch")
}

fn transition(lineage_name: &str, sequence: u64) -> EpochTransition {
    EpochTransition {
        current: epoch(lineage_name, sequence),
        parent: (sequence > 1).then(|| epoch(lineage_name, sequence - 1)),
    }
}

fn host() -> HostInstallationEpoch {
    HostInstallationEpoch {
        installation: handle("eliot-test-installation"),
        epoch: transition("550e8400-e29b-41d4-a716-446655440000", 1),
        nonce: handle("eliot-test-host-nonce"),
        recovery: None,
    }
}

fn activation_generation() -> EpochTransition {
    transition("550e8400-e29b-41d4-a716-446655440001", 1)
}

fn record_fence(host: &HostInstallationEpoch) -> RecordFence {
    RecordFence {
        host: host.clone(),
        activation_id: handle("eliot-test-activation"),
        activation_generation: activation_generation(),
    }
}

fn operation(name: &str) -> IdempotencyIdentity {
    IdempotencyIdentity {
        operation_id: handle(name),
        idempotency_key: handle(&format!("key-{name}")),
    }
}

fn activation_record(
    host: &HostInstallationEpoch,
    state: ActivationState,
    name: &str,
) -> HostStateRecord {
    let ready = matches!(
        state,
        ActivationState::ControlReady | ActivationState::Active
    );
    HostStateRecord::Activation(EliotActivationRecord {
        fence: record_fence(host),
        operation: operation(name),
        activation_id: handle("eliot-test-activation"),
        trigger_class: handle("test-trigger"),
        trigger_evidence: vec![handle("test-trigger-evidence")],
        requester_principal_session_or_scheduler: handle("test-principal"),
        requested_capabilities: vec![handle("host-state")],
        candidate_scope: handle("test-scope"),
        state,
        drain_generation: matches!(
            state,
            ActivationState::Draining | ActivationState::StoppedClean
        )
        .then(activation_generation),
        lineage: HostKernelStoreLineage {
            host_epoch: host.epoch.current.clone(),
            kernel_epoch: epoch("550e8400-e29b-41d4-a716-446655440002", 1),
            watchdog_epoch: epoch("550e8400-e29b-41d4-a716-446655440003", 1),
            store_generation: epoch("550e8400-e29b-41d4-a716-446655440004", 1),
        },
        readiness: ReadinessEvidence {
            supervision_ready: ready,
            control_ready: ready,
            evidence_refs: vec![handle("test-readiness")],
        },
        governance_profile: handle("test-governed"),
        runtime_lease_refs: Vec::new(),
        supervision_lease_refs: Vec::new(),
        wake_intent_refs: Vec::new(),
        drain_commit_ref: None,
        wake_during_drain_disposition: None,
        boot_session_evidence: vec![handle("test-boot")],
        power_transition_evidence: Vec::new(),
        timestamps: LifecycleTimestamps {
            started_at: Some(handle("test-started")),
            ready_at: ready.then(|| handle("test-ready")),
            draining_at: (state == ActivationState::Draining).then(|| handle("test-draining")),
            stopped_at: (state == ActivationState::StoppedClean).then(|| handle("test-stopped")),
        },
        failure_and_recovery_directive: None,
    })
}

fn active_journal() -> HostStateJournal<MemoryBackend> {
    let host = host();
    let journal = HostStateJournal::open(MemoryBackend::default(), host.clone()).expect("open");
    for (state, name) in [
        (ActivationState::Starting, "activation-start"),
        (ActivationState::ControlReady, "activation-ready"),
        (ActivationState::Active, "activation-active"),
    ] {
        journal
            .append(activation_record(&host, state, name))
            .expect("activation transition");
    }
    journal
}

fn protocol_fence() -> StateFence {
    StateFence::new(
        epoch("550e8400-e29b-41d4-a716-446655440000", 1),
        ResourceGeneration::new(1).expect("generation"),
    )
}

fn content(name: &str) -> ReactiveContextContentRef {
    ReactiveContextContentRef {
        contract: ContractIdentity {
            name: ContractId::new(format!("owner.{name}")).expect("contract"),
            version: ContractVersion::new(1, 0, 0),
            shape_sha256: "0".repeat(64),
        },
        source_revision: format!("source-{name}"),
        content_sha256: "1".repeat(64),
        byte_length: Some(1),
        artifact_id: Some(ArtifactId::new(format!("artifact-{name}")).expect("artifact")),
    }
}

fn payload(
    key: u64,
    stream: &str,
    sequence: u64,
    predecessors: Vec<String>,
    attempt: &str,
) -> ReactiveContextPayload {
    let fence = protocol_fence();
    let contract = reactive_context_contract_identity().expect("reactive contract");
    let mut representation = content(&format!("representation-{key}"));
    representation.byte_length = Some(16);
    ReactiveContextPayload {
        contract,
        operation_id: OperationId::new(format!("operation-{key}")).expect("operation"),
        request_id: RequestId::new(format!("request-{key}")).expect("request"),
        idempotency_key: format!("idempotency-{key}"),
        task_id: TaskId::new(format!("task-{key}")).expect("task"),
        attempt_id: AgentAttemptId::new(attempt.to_owned()).expect("attempt"),
        producer_generation: ResourceGeneration::new(1).expect("producer generation"),
        work_scope: WorkScopeBinding {
            scope_id: WorkScopeId::new("reactive-test-scope").expect("scope"),
            product_id: ProductId::new("eliot-memory-os").expect("product"),
            resource_generation: ResourceGeneration::new(1).expect("resource generation"),
            state_fence: fence.clone(),
        },
        planner: ReactiveContextPlannerBinding {
            request: content(&format!("planner-request-{key}")),
            decision: content(&format!("planner-decision-{key}")),
            receipt: content(&format!("planner-receipt-{key}")),
        },
        recipient: ReactiveContextRecipient {
            session_id: SessionId::new(format!("session-{key}")).expect("session"),
            runtime_id: format!("runtime-{key}"),
            runtime_generation: ResourceGeneration::new(1).expect("runtime generation"),
            route: format!("route-{key}"),
        },
        view: ReactiveContextViewBinding {
            view_id: ArtifactId::new(format!("view-{key}")).expect("view"),
            view_generation: ResourceGeneration::new(1).expect("view generation"),
            admitted_set: content(&format!("admitted-{key}")),
            recipe: content(&format!("recipe-{key}")),
            assembly_receipt: content(&format!("assembly-{key}")),
            representation,
            measurement: eliot_protocol::reactive_context::ReactiveContextMeasurement {
                serializer: content(&format!("serializer-{key}")),
                tokenizer: content(&format!("tokenizer-{key}")),
                serialized_byte_length: 16,
                token_count: Some(4),
            },
        },
        safety_floor: ReactiveContextSafetyFloor {
            owner: content(&format!("safety-{key}")),
            privacy: ReactiveContextPrivacy::Internal,
            disclosure_closure: content(&format!("disclosure-{key}")),
            proof_ceiling: ProofCeiling::Observation,
        },
        sequence: ReactiveContextSequence {
            stream_id: stream.to_owned(),
            sequence,
            predecessor_event_ids: predecessors,
            cursor: sequence,
        },
        acknowledgement_deadline_unix_ms: 100,
        cancellation_id: format!("cancel-{key}"),
        expires_at_unix_ms: Some(200),
        validity: ReactiveContextValidity::Current,
    }
}

fn admission(value: &ReactiveContextPayload, state: HostDeliveryState) -> HostDeliveryAdmission {
    HostDeliveryAdmission {
        fence: record_fence(&host()),
        state,
        recipient: value.recipient.clone(),
        endpoint_ref: handle("test-endpoint"),
        admission_ref: handle("admission-1"),
    }
}

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn new(value: u64) -> Self {
        Self(Arc::new(AtomicU64::new(value)))
    }

    fn set(&self, value: u64) {
        self.0.store(value, Ordering::SeqCst);
    }
}

impl ReactiveContextClock for TestClock {
    fn now_unix_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
struct TransportSpy {
    resolve_overrides: VecDeque<ReactiveContextEndpointResolution>,
    send_overrides: VecDeque<ReactiveContextSendOutcome>,
    query_overrides: VecDeque<ReactiveContextQueryOutcome>,
    cancel_overrides: VecDeque<ReactiveContextCancelOutcome>,
    close_overrides: VecDeque<ReactiveContextChannelCloseOutcome>,
    resolve_calls: Vec<ReactiveContextResolveRequest>,
    send_calls: Vec<ReactiveContextSendRequest>,
    query_calls: Vec<ReactiveContextQueryRequest>,
    cancel_calls: Vec<ReactiveContextCancelRequest>,
    close_calls: Vec<ReactiveContextCloseChannelRequest>,
}

impl ReactiveContextTransportPort for TransportSpy {
    fn resolve_endpoint(
        &mut self,
        request: ReactiveContextResolveRequest,
    ) -> Result<ReactiveContextEndpointResolution, ReactiveContextTransportError> {
        self.resolve_calls.push(request.clone());
        Ok(self.resolve_overrides.pop_front().unwrap_or_else(|| {
            ReactiveContextEndpointResolution::Exact(ReactiveContextResolvedEndpoint {
                endpoint_ref: request.endpoint_ref,
                recipient: request.payload.recipient,
                transport_operation: handle("transport-operation"),
            })
        }))
    }

    fn send_event(
        &mut self,
        request: ReactiveContextSendRequest,
    ) -> Result<ReactiveContextSendOutcome, ReactiveContextTransportError> {
        self.send_calls.push(request.clone());
        Ok(self.send_overrides.pop_front().unwrap_or_else(|| {
            ReactiveContextSendOutcome::Delivered(ReactiveContextTransportReceipt {
                operation: request.endpoint.transport_operation,
                endpoint_ref: request.endpoint.endpoint_ref,
                owner_receipt: content("transport-delivery"),
            })
        }))
    }

    fn query_delivery(
        &mut self,
        request: ReactiveContextQueryRequest,
    ) -> Result<ReactiveContextQueryOutcome, ReactiveContextTransportError> {
        self.query_calls.push(request);
        Ok(self.query_overrides.pop_front().unwrap_or_else(|| {
            ReactiveContextQueryOutcome::Unknown {
                reconciliation: handle("reconcile-operation"),
                reason: "query remains unknown".to_owned(),
            }
        }))
    }

    fn cancel_delivery(
        &mut self,
        request: ReactiveContextCancelRequest,
    ) -> Result<ReactiveContextCancelOutcome, ReactiveContextTransportError> {
        self.cancel_calls.push(request);
        Ok(self
            .cancel_overrides
            .pop_front()
            .unwrap_or(ReactiveContextCancelOutcome::Cancelled))
    }

    fn close_attempt_channel(
        &mut self,
        request: ReactiveContextCloseChannelRequest,
    ) -> Result<ReactiveContextChannelCloseOutcome, ReactiveContextTransportError> {
        self.close_calls.push(request);
        Ok(self
            .close_overrides
            .pop_front()
            .unwrap_or(ReactiveContextChannelCloseOutcome::Closed))
    }
}

fn delivery(
    transport: TransportSpy,
    clock: TestClock,
) -> ReactiveContextDelivery<HostStateJournal<MemoryBackend>, TransportSpy, TestClock> {
    ReactiveContextDelivery::new(
        active_journal(),
        transport,
        clock,
        ReactiveContextDeliveryLimits::default(),
    )
    .expect("valid delivery limits")
}

fn request(value: ReactiveContextPayload) -> ReactiveContextDeliveryRequest {
    ReactiveContextDeliveryRequest {
        payload: value,
        owner_receipt: None,
        control: false,
    }
}

fn operation_for(value: &ReactiveContextPayload) -> IdempotencyIdentity {
    IdempotencyIdentity {
        operation_id: handle(value.operation_id.as_str()),
        idempotency_key: handle(&value.idempotency_key),
    }
}

fn prepare<B: JournalBackend>(
    journal: &HostStateJournal<B>,
    value: ReactiveContextPayload,
) -> Result<ReactiveContextPrepareResult, ReactiveContextQueueError> {
    let snapshot = journal.snapshot()?;
    let revision = snapshot.reactive_context.map_or(0, |queue| queue.revision);
    journal.prepare_reactive_context(ReactiveContextPrepareRequest {
        fence: record_fence(&host()),
        payload: value,
        endpoint_ref: handle("test-endpoint"),
        owner_receipt: None,
        expected_queue_revision: revision,
    })
}

fn enqueue<B: JournalBackend>(
    journal: &HostStateJournal<B>,
    value: ReactiveContextPayload,
) -> Result<ReactiveContextEnqueueReceipt, ReactiveContextQueueError> {
    let prepared = match prepare(journal, value)? {
        ReactiveContextPrepareResult::Prepared(prepared) => prepared,
        ReactiveContextPrepareResult::Replay(_) => {
            return Err(ReactiveContextQueueError::IdentityConflict);
        }
    };
    journal.commit_reactive_context(prepared)
}

fn ack_lifecycle(phase: AckPhase) -> ReactiveContextLifecycleEvidence {
    let (stage, predecessor, owner_receipt) = match phase {
        AckPhase::Received => (ReactiveContextStage::RecipientReceived, None, None),
        AckPhase::Durable => (
            ReactiveContextStage::RecipientDurable,
            Some(ReactiveContextStage::RecipientReceived),
            None,
        ),
        AckPhase::Normalized => (
            ReactiveContextStage::NormalizedProjection,
            Some(ReactiveContextStage::RecipientDurable),
            None,
        ),
        AckPhase::Applied => (
            ReactiveContextStage::AppliedProjection,
            Some(ReactiveContextStage::NormalizedProjection),
            Some(content("projection-receipt")),
        ),
        AckPhase::Rejected => (ReactiveContextStage::AcknowledgementRejected, None, None),
        AckPhase::Unknown => (ReactiveContextStage::AcknowledgementUnknown, None, None),
    };
    ReactiveContextLifecycleEvidence {
        stage,
        predecessor,
        owner_receipt,
    }
}

fn generic_receipt(
    value: &ReactiveContextPayload,
    phase: AckPhase,
    sequence: u64,
) -> Result<EventAckReceipt, Box<dyn Error>> {
    let fence = value.work_scope.state_fence.clone();
    let envelope = value.to_event_envelope()?;
    let core = ReceiptCore {
        contract: eliot_receipts::contract_identity()?,
        kind: ReceiptKind::Coordination,
        work_scope: value.work_scope.clone(),
        task: Some(TaskBinding {
            task_id: value.task_id.clone(),
            task_revision: TaskRevision::genesis(),
            state_fence: fence.clone(),
        }),
        session: Some(SessionBinding {
            session_id: value.recipient.session_id.clone(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
        }),
        causal: CausalBinding {
            state_fence: fence.clone(),
            transaction_sequence: TransactionSequence::new(sequence)?,
            parent_receipt_id: None,
            predecessor_receipt_ids: Vec::new(),
        },
        request: RequestBinding {
            metadata: eliot_contracts::RequestMetadata {
                request_id: value.request_id.clone(),
                session_id: Some(value.recipient.session_id.clone()),
                task_id: Some(value.task_id.clone()),
                product_id: value.work_scope.product_id.clone(),
                source_id: SourceId::new("reactive-test-source")?,
                state_fence: fence.clone(),
                clock: ClockReading::default(),
            },
            state_fence: fence.clone(),
        },
        operation: OperationBinding {
            operation_id: value.operation_id.clone(),
            request_id: value.request_id.clone(),
            idempotency_key: value.idempotency_key.clone(),
            operation_kind: "reactive-context".to_owned(),
            effect: EffectClass::Read,
            state_fence: fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: ContractId::new("reactive-recipient-authority")?,
            authority_owner: "reactive-recipient".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            allowed_effect: EffectClass::Read,
            proof_ceiling: ProofCeiling::Observation,
        },
        artifacts: vec![ArtifactBinding {
            artifact_id: ArtifactId::new("reactive-ack-proof")?,
            sha256: value.payload_sha256()?,
            role: ReceiptKind::Artifact,
            source_revision: Some("reactive-test-revision".to_owned()),
        }],
        verifier: None,
        problem: None,
        coordination: Some(CoordinationBinding {
            event_id: ContractId::new(&envelope.event_id)?,
            idempotency_key: value.idempotency_key.clone(),
            state_fence: fence.clone(),
        }),
        disposition: ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
    };
    Ok(EventAckReceipt {
        stream_id: envelope.stream_id,
        event_id: envelope.event_id,
        phase,
        disposition: match phase {
            AckPhase::Rejected => EventDisposition::Rejected,
            _ => EventDisposition::Accepted,
        },
        state_fence: fence,
        receipt: ReceiptEnvelope::issue(core)?,
    })
}

fn ack_evidence(
    value: &ReactiveContextPayload,
    phase: AckPhase,
    proof: &str,
) -> Result<ReactiveContextAckEvidence, Box<dyn Error>> {
    let receipt = generic_receipt(value, phase, 1)?;
    Ok(ReactiveContextAckEvidence {
        receipt,
        operation_id: value.operation_id.clone(),
        task_id: value.task_id.clone(),
        attempt_id: value.attempt_id.clone(),
        session_id: value.recipient.session_id.clone(),
        runtime_id: value.recipient.runtime_id.clone(),
        runtime_generation: value.recipient.runtime_generation,
        route: value.recipient.route.clone(),
        work_scope: value.work_scope.clone(),
        state_fence: value.work_scope.state_fence.clone(),
        view_id: value.view.view_id.clone(),
        view_generation: value.view.view_generation,
        payload_sha256: value.payload_sha256()?,
        expected_phase: phase,
        observed_phase: phase,
        owner_ref: content("ack-owner"),
        issuer_ref: content("ack-issuer"),
        receive_sequence: value.sequence.sequence,
        receive_cursor: value.sequence.cursor,
        observed_at_unix_ms: 50,
        freshness_ref: Some(content("ack-freshness")),
        disposition: match phase {
            AckPhase::Rejected => ReactiveContextAckDisposition::Rejected,
            AckPhase::Unknown => ReactiveContextAckDisposition::Unknown,
            _ => ReactiveContextAckDisposition::Accepted,
        },
        proof_sha256: proof.to_owned(),
        lifecycle: ack_lifecycle(phase),
    })
}

fn deliver_one(
    transport: TransportSpy,
    value: ReactiveContextPayload,
) -> (
    ReactiveContextDelivery<HostStateJournal<MemoryBackend>, TransportSpy, TestClock>,
    HostDeliveryAdmission,
    ReactiveContextPayload,
    TestClock,
) {
    let admission = admission(&value, HostDeliveryState::Active);
    let clock = TestClock::new(50);
    let delivery = delivery(transport, clock.clone());
    (delivery, admission, value, clock)
}

fn assert_fixture_denominator() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("data/reactive-context-delivery/cases.json"))
            .expect("valid case fixture");
    assert_eq!(fixture.as_array().expect("array").len(), 38);
}

// WORK_UNIT_CASE: 798/1
#[test]
fn queue_owner_and_no_duplicate() -> TestResult {
    assert_fixture_denominator();
    let value = payload(1, "stream-1", 1, Vec::new(), "attempt-1");
    let (mut delivery, admission, value, _) = deliver_one(TransportSpy::default(), value);
    delivery.deliver(&admission, request(value.clone()))?;
    let second = delivery.deliver(&admission, request(value))?;
    let (_, transport, _) = delivery.into_parts();
    assert_eq!(transport.send_calls.len(), 1);
    assert_eq!(second.disposition, DeliveryDisposition::Delivered);
    Ok(())
}

// WORK_UNIT_CASE: 798/2
#[test]
fn enqueue_send_delivered_ack() -> TestResult {
    let value = payload(2, "stream-2", 1, Vec::new(), "attempt-2");
    let operation = operation_for(&value);
    let (mut delivery, admission, value, _) = deliver_one(TransportSpy::default(), value);
    let delivered = delivery.deliver(&admission, request(value.clone()))?;
    assert_eq!(
        delivered.entry.stage,
        ReactiveContextStage::DeliveredToExactEndpoint
    );
    let acknowledged = delivery.acknowledge(
        operation,
        ack_evidence(&value, AckPhase::Received, &"2".repeat(64))?,
    )?;
    assert_eq!(
        acknowledged.entry.stage,
        ReactiveContextStage::RecipientReceived
    );
    Ok(())
}

// WORK_UNIT_CASE: 798/3
#[test]
fn commit_before_endpoint_send() -> TestResult {
    let value = payload(3, "stream-3", 1, Vec::new(), "attempt-3");
    let (mut delivery, admission, value, _) = deliver_one(TransportSpy::default(), value);
    let result = delivery.deliver(&admission, request(value))?;
    assert_eq!(
        result.entry.stage,
        ReactiveContextStage::DeliveredToExactEndpoint
    );
    assert!(result.entry.last_mutation_sequence > 0);
    let (_, transport, _) = delivery.into_parts();
    assert_eq!(transport.resolve_calls.len(), 1);
    assert_eq!(transport.send_calls.len(), 1);
    Ok(())
}

// WORK_UNIT_CASE: 798/4
#[test]
fn unknown_enqueue_blocks_send() -> TestResult {
    let base = active_journal();
    let mut backend = base.into_backend()?;
    backend.inject_fault(FaultPoint::CommitAfterUnknown);
    let queue = HostStateJournal::open(backend, host())?;
    let value = payload(4, "stream-4", 1, Vec::new(), "attempt-4");
    let admission = admission(&value, HostDeliveryState::Active);
    let clock = TestClock::new(50);
    let mut delivery = ReactiveContextDelivery::new(
        queue,
        TransportSpy::default(),
        clock,
        ReactiveContextDeliveryLimits::default(),
    )?;
    assert!(delivery.deliver(&admission, request(value)).is_err());
    let (_, transport, _) = delivery.into_parts();
    assert!(transport.send_calls.is_empty());
    Ok(())
}

// WORK_UNIT_CASE: 798/5
#[test]
fn replay_and_changed_content_conflict() -> TestResult {
    let value = payload(5, "stream-5", 1, Vec::new(), "attempt-5");
    let (mut delivery, admission, value, _) = deliver_one(TransportSpy::default(), value);
    delivery.deliver(&admission, request(value.clone()))?;
    let mut changed = value.clone();
    changed.view.view_id = ArtifactId::new("changed-view")?;
    let error = delivery
        .deliver(&admission, request(changed))
        .expect_err("identity conflict");
    assert!(matches!(
        error,
        eliot_host_service::ReactiveContextDeliveryError::Queue(
            ReactiveContextQueueError::IdentityConflict
        )
    ));
    let mut changed_admission = admission.clone();
    changed_admission.endpoint_ref = handle("changed-endpoint");
    let error = delivery
        .deliver(&changed_admission, request(value))
        .expect_err("endpoint identity conflict");
    assert!(matches!(
        error,
        eliot_host_service::ReactiveContextDeliveryError::Queue(
            ReactiveContextQueueError::IdentityConflict
        )
    ));
    Ok(())
}

// WORK_UNIT_CASE: 798/6
#[test]
fn queue_capacity_and_cas() -> TestResult {
    let value = payload(6, "stream-6", 1, Vec::new(), "attempt-6");
    let first_admission = admission(&value, HostDeliveryState::Active);
    let clock = TestClock::new(50);
    let limits = ReactiveContextDeliveryLimits {
        max_in_flight: 1,
        ..Default::default()
    };
    let mut delivery = ReactiveContextDelivery::new(
        active_journal(),
        TransportSpy {
            send_overrides: VecDeque::from([ReactiveContextSendOutcome::Unknown {
                reconciliation: handle("reconcile-6"),
                reason: "possible".to_owned(),
            }]),
            ..Default::default()
        },
        clock,
        limits,
    )?;
    delivery.deliver(&first_admission, request(value))?;
    let second = payload(66, "stream-66", 1, Vec::new(), "attempt-66");
    assert!(matches!(
        delivery.deliver(
            &admission(&second, HostDeliveryState::Active),
            request(second)
        ),
        Err(eliot_host_service::ReactiveContextDeliveryError::Capacity {
            dimension: "in_flight"
        })
    ));
    let journal = active_journal();
    let stale = ReactiveContextPrepareRequest {
        fence: record_fence(&host()),
        payload: payload(67, "stream-67", 1, Vec::new(), "attempt-67"),
        endpoint_ref: handle("test-endpoint"),
        owner_receipt: None,
        expected_queue_revision: 999,
    };
    assert!(matches!(
        journal.prepare_reactive_context(stale),
        Err(ReactiveContextQueueError::StaleRevision { .. })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 798/7
#[test]
fn host_admission_states() -> TestResult {
    for state in [
        HostDeliveryState::Draining,
        HostDeliveryState::DegradedRecovery,
        HostDeliveryState::Unavailable,
    ] {
        let value = payload(
            70 + state as u64,
            &format!("stream-{}", state as u8),
            1,
            Vec::new(),
            "attempt-admission",
        );
        let adm = admission(&value, state);
        let mut delivery = delivery(TransportSpy::default(), TestClock::new(50));
        assert!(matches!(
            delivery.deliver(&adm, request(value)),
            Err(eliot_host_service::ReactiveContextDeliveryError::HostAdmission { .. })
        ));
    }
    Ok(())
}

// WORK_UNIT_CASE: 798/8
#[test]
fn recipient_identity_binding() -> TestResult {
    let value = payload(8, "stream-8", 1, Vec::new(), "attempt-8");
    let mut adm = admission(&value, HostDeliveryState::Active);
    adm.recipient.runtime_generation = ResourceGeneration::new(2)?;
    let mut delivery = delivery(TransportSpy::default(), TestClock::new(50));
    assert!(delivery.deliver(&adm, request(value)).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 798/9
#[test]
fn stale_context_rejected() -> TestResult {
    let mut value = payload(9, "stream-9", 1, Vec::new(), "attempt-9");
    value.validity = ReactiveContextValidity::Superseded {
        replacement: ArtifactId::new("replacement")?,
    };
    let adm = admission(&value, HostDeliveryState::Active);
    let mut delivery = delivery(TransportSpy::default(), TestClock::new(50));
    assert!(delivery.deliver(&adm, request(value)).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 798/10
#[test]
fn send_intent_persisted() -> TestResult {
    let value = payload(10, "stream-10", 1, Vec::new(), "attempt-10");
    let (mut delivery, adm, value, _) = deliver_one(TransportSpy::default(), value);
    let result = delivery.deliver(&adm, request(value))?;
    assert!(result.entry.transport_ref.is_some());
    assert!(result.entry.predecessor_stage.is_some());
    Ok(())
}

// WORK_UNIT_CASE: 798/11
#[test]
fn unknown_send_intent_blocks_transport() -> TestResult {
    let base = active_journal();
    let value = payload(11, "stream-11", 1, Vec::new(), "attempt-11");
    enqueue(&base, value.clone())?;
    let mut backend = base.into_backend()?;
    backend.inject_fault(FaultPoint::CommitAfterUnknown);
    let queue = HostStateJournal::open(backend, host())?;
    let mut delivery = ReactiveContextDelivery::new(
        queue,
        TransportSpy::default(),
        TestClock::new(50),
        Default::default(),
    )?;
    let adm = admission(&value, HostDeliveryState::Active);
    assert!(delivery.deliver(&adm, request(value)).is_err());
    let (_, transport, _) = delivery.into_parts();
    assert!(transport.send_calls.is_empty());
    Ok(())
}

// WORK_UNIT_CASE: 798/12
#[test]
fn rejected_not_attempted_transport() -> TestResult {
    let value = payload(12, "stream-12", 1, Vec::new(), "attempt-12");
    let mut spy = TransportSpy::default();
    spy.send_overrides
        .push_back(ReactiveContextSendOutcome::Rejected {
            reason: "not admitted".to_owned(),
        });
    let (mut delivery, adm, value, _) = deliver_one(spy, value);
    let first = delivery.deliver(&adm, request(value.clone()))?;
    assert_eq!(first.entry.stage, ReactiveContextStage::UnavailableFenced);
    let second = delivery.deliver(&adm, request(value))?;
    assert_eq!(second.disposition, DeliveryDisposition::AlreadyTerminal);
    let (_, transport, _) = delivery.into_parts();
    assert_eq!(transport.send_calls.len(), 1);
    Ok(())
}

// WORK_UNIT_CASE: 798/13
#[test]
fn exact_delivery_receipt() -> TestResult {
    let value = payload(13, "stream-13", 1, Vec::new(), "attempt-13");
    let (mut delivery, adm, value, _) = deliver_one(TransportSpy::default(), value);
    let result = delivery.deliver(&adm, request(value))?;
    assert_eq!(
        result.entry.stage,
        ReactiveContextStage::DeliveredToExactEndpoint
    );
    assert!(result.entry.owner_receipt.is_some());
    Ok(())
}

// WORK_UNIT_CASE: 798/14
#[test]
fn disconnect_reconciliation() -> TestResult {
    let value = payload(14, "stream-14", 1, Vec::new(), "attempt-14");
    let mut spy = TransportSpy::default();
    spy.send_overrides
        .push_back(ReactiveContextSendOutcome::Unknown {
            reconciliation: handle("reconcile-14"),
            reason: "disconnect".to_owned(),
        });
    spy.query_overrides
        .push_back(ReactiveContextQueryOutcome::Delivered(
            ReactiveContextTransportReceipt {
                operation: handle("transport-operation"),
                endpoint_ref: handle("test-endpoint"),
                owner_receipt: content("reconciled-14"),
            },
        ));
    let (mut delivery, adm, value, _) = deliver_one(spy, value);
    let unknown = delivery.deliver(&adm, request(value.clone()))?;
    assert_eq!(unknown.entry.stage, ReactiveContextStage::UnknownDelivery);
    let reconciled = delivery.reconcile(operation_for(&value))?;
    assert_eq!(
        reconciled.entry.stage,
        ReactiveContextStage::DeliveredToExactEndpoint
    );
    let (_, transport, _) = delivery.into_parts();
    assert_eq!(transport.send_calls.len(), 1);
    assert_eq!(transport.query_calls.len(), 1);
    Ok(())
}

// WORK_UNIT_CASE: 798/15
#[test]
fn same_operation_replay() -> TestResult {
    let value = payload(15, "stream-15", 1, Vec::new(), "attempt-15");
    let mut spy = TransportSpy::default();
    spy.send_overrides
        .push_back(ReactiveContextSendOutcome::Unknown {
            reconciliation: handle("reconcile-15"),
            reason: "possible".to_owned(),
        });
    spy.query_overrides
        .push_back(ReactiveContextQueryOutcome::Delivered(
            ReactiveContextTransportReceipt {
                operation: handle("transport-operation"),
                endpoint_ref: handle("test-endpoint"),
                owner_receipt: content("replayed-15"),
            },
        ));
    let (mut delivery, adm, value, _) = deliver_one(spy, value);
    delivery.deliver(&adm, request(value.clone()))?;
    let replay = delivery.deliver(&adm, request(value))?;
    assert_eq!(
        replay.entry.stage,
        ReactiveContextStage::DeliveredToExactEndpoint
    );
    let (_, transport, _) = delivery.into_parts();
    assert_eq!(transport.send_calls.len(), 1);
    Ok(())
}

// WORK_UNIT_CASE: 798/16
#[test]
fn retry_deadline_cancel_fence_bounds() -> TestResult {
    let value = payload(16, "stream-16", 1, Vec::new(), "attempt-16");
    let adm = admission(&value, HostDeliveryState::Active);
    let mut delivery = delivery(TransportSpy::default(), TestClock::new(100));
    assert!(matches!(
        delivery.deliver(&adm, request(value)),
        Err(eliot_host_service::ReactiveContextDeliveryError::DeadlineExceeded)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 798/17
#[test]
fn exact_acknowledgement() -> TestResult {
    let value = payload(17, "stream-17", 1, Vec::new(), "attempt-17");
    let operation = operation_for(&value);
    let (mut delivery, adm, value, _) = deliver_one(TransportSpy::default(), value);
    delivery.deliver(&adm, request(value.clone()))?;
    let ack = delivery.acknowledge(
        operation,
        ack_evidence(&value, AckPhase::Received, &"a".repeat(64))?,
    )?;
    assert_eq!(ack.disposition, ReactiveContextAckDisposition::Accepted);
    assert_eq!(ack.entry.stage, ReactiveContextStage::RecipientReceived);
    Ok(())
}

// WORK_UNIT_CASE: 798/18
#[test]
fn ack_identity_mismatch() -> TestResult {
    let value = payload(18, "stream-18", 1, Vec::new(), "attempt-18");
    let operation = operation_for(&value);
    let (mut delivery, adm, value, _) = deliver_one(TransportSpy::default(), value);
    delivery.deliver(&adm, request(value.clone()))?;
    let mut evidence = ack_evidence(&value, AckPhase::Received, &"b".repeat(64))?;
    evidence.session_id = SessionId::new("foreign-session")?;
    assert!(delivery.acknowledge(operation, evidence).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 798/19
#[test]
fn issuer_evidence_validation() -> TestResult {
    let value = payload(19, "stream-19", 1, Vec::new(), "attempt-19");
    let operation = operation_for(&value);
    let (mut delivery, adm, value, _) = deliver_one(TransportSpy::default(), value);
    delivery.deliver(&adm, request(value.clone()))?;
    let mut evidence = ack_evidence(&value, AckPhase::Received, &"c".repeat(64))?;
    evidence.issuer_ref.source_revision.clear();
    assert!(delivery.acknowledge(operation, evidence).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 798/20
#[test]
fn duplicate_history_and_changed_duplicate() -> TestResult {
    let value = payload(20, "stream-20", 1, Vec::new(), "attempt-20");
    let operation = operation_for(&value);
    let (mut delivery, adm, value, _) = deliver_one(TransportSpy::default(), value);
    delivery.deliver(&adm, request(value.clone()))?;
    let evidence = ack_evidence(&value, AckPhase::Received, &"d".repeat(64))?;
    delivery.acknowledge(operation.clone(), evidence.clone())?;
    let duplicate = delivery.acknowledge(operation.clone(), evidence)?;
    assert_eq!(
        duplicate.disposition,
        ReactiveContextAckDisposition::DuplicateHistorical
    );
    let changed = ack_evidence(&value, AckPhase::Received, &"e".repeat(64))?;
    assert!(delivery.acknowledge(operation, changed).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 798/21
#[test]
fn ack_transition_order() -> TestResult {
    let value = payload(21, "stream-21", 1, Vec::new(), "attempt-21");
    let operation = operation_for(&value);
    let (mut delivery, adm, value, _) = deliver_one(TransportSpy::default(), value);
    delivery.deliver(&adm, request(value.clone()))?;
    assert!(
        delivery
            .acknowledge(
                operation.clone(),
                ack_evidence(&value, AckPhase::Durable, &"f".repeat(64))?
            )
            .is_err()
    );
    let received = ack_evidence(&value, AckPhase::Received, &"1".repeat(64))?;
    delivery.acknowledge(operation.clone(), received.clone())?;
    let duplicate = delivery.acknowledge(operation, received)?;
    assert_eq!(
        duplicate.disposition,
        ReactiveContextAckDisposition::DuplicateHistorical
    );
    Ok(())
}

// WORK_UNIT_CASE: 798/22
#[test]
fn delivery_ack_visibility_use_distinct() -> TestResult {
    let value = payload(22, "stream-22", 1, Vec::new(), "attempt-22");
    let operation = operation_for(&value);
    let (mut delivery, adm, value, _) = deliver_one(TransportSpy::default(), value);
    let delivered = delivery.deliver(&adm, request(value.clone()))?;
    assert_eq!(
        delivered.entry.stage,
        ReactiveContextStage::DeliveredToExactEndpoint
    );
    let received = delivery.acknowledge(
        operation,
        ack_evidence(&value, AckPhase::Received, &"2".repeat(64))?,
    )?;
    assert_eq!(
        received.entry.stage,
        ReactiveContextStage::RecipientReceived
    );
    assert!(
        received
            .entry
            .ack_evidence
            .iter()
            .all(|item| item.observed_phase == AckPhase::Received)
    );
    Ok(())
}

// WORK_UNIT_CASE: 798/23
#[test]
fn expiry_before_and_after_possible_delivery() -> TestResult {
    let value = payload(23, "stream-23", 1, Vec::new(), "attempt-23");
    let clock = TestClock::new(50);
    let mut delivery = delivery(TransportSpy::default(), clock.clone());
    let adm = admission(&value, HostDeliveryState::Active);
    let operation = operation_for(&value);
    delivery.deliver(&adm, request(value))?;
    clock.set(200);
    let expired = delivery.expire(operation)?;
    assert_eq!(expired.entry.stage, ReactiveContextStage::ExpiredBeforeAck);
    Ok(())
}

// WORK_UNIT_CASE: 798/24
#[test]
fn cancellation_before_and_after_send() -> TestResult {
    let value = payload(24, "stream-24", 1, Vec::new(), "attempt-24");
    let journal = active_journal();
    enqueue(&journal, value.clone())?;
    let mut delivery = ReactiveContextDelivery::new(
        journal,
        TransportSpy::default(),
        TestClock::new(50),
        Default::default(),
    )?;
    let cancelled = delivery.cancel(operation_for(&value))?;
    assert_eq!(
        cancelled.entry.stage,
        ReactiveContextStage::CancelledRetracted
    );

    let value2 = payload(25, "stream-25", 1, Vec::new(), "attempt-25");
    let mut spy = TransportSpy::default();
    spy.send_overrides
        .push_back(ReactiveContextSendOutcome::Unknown {
            reconciliation: handle("reconcile-25"),
            reason: "possible".to_owned(),
        });
    spy.cancel_overrides
        .push_back(ReactiveContextCancelOutcome::Cancelled);
    let (mut delivery2, adm2, value2, _) = deliver_one(spy, value2);
    delivery2.deliver(&adm2, request(value2.clone()))?;
    let cancelled2 = delivery2.cancel(operation_for(&value2))?;
    assert_eq!(
        cancelled2.entry.stage,
        ReactiveContextStage::CancelledRetracted
    );
    Ok(())
}

// WORK_UNIT_CASE: 798/25
#[test]
fn supersession_preserves_history() -> TestResult {
    let value = payload(25, "stream-25b", 1, Vec::new(), "attempt-25b");
    let operation = operation_for(&value);
    let (mut delivery, adm, value, _) = deliver_one(TransportSpy::default(), value);
    delivery.deliver(&adm, request(value.clone()))?;
    delivery.acknowledge(
        operation.clone(),
        ack_evidence(&value, AckPhase::Received, &"3".repeat(64))?,
    )?;
    let superseded = delivery.supersede(operation, "newer view".to_owned())?;
    assert_eq!(
        superseded.entry.stage,
        ReactiveContextStage::StaleSuperseded
    );
    assert_eq!(superseded.entry.ack_evidence.len(), 1);
    Ok(())
}

// WORK_UNIT_CASE: 798/26
#[test]
fn restart_reconciles_durable_stages() -> TestResult {
    let value = payload(26, "stream-26", 1, Vec::new(), "attempt-26");
    let mut spy = TransportSpy::default();
    spy.send_overrides
        .push_back(ReactiveContextSendOutcome::Unknown {
            reconciliation: handle("reconcile-26"),
            reason: "restart".to_owned(),
        });
    spy.query_overrides
        .push_back(ReactiveContextQueryOutcome::Delivered(
            ReactiveContextTransportReceipt {
                operation: handle("transport-operation"),
                endpoint_ref: handle("test-endpoint"),
                owner_receipt: content("restart-26"),
            },
        ));
    let (mut delivery, adm, value, _) = deliver_one(spy, value);
    delivery.deliver(&adm, request(value))?;
    let result = delivery.reconcile_after_restart()?;
    assert_eq!(result.reconciled, 1);
    assert!(result.blocked_unknown.is_empty());
    Ok(())
}

// WORK_UNIT_CASE: 798/27
#[test]
fn unknown_restart_blocks_duplicate() -> TestResult {
    let value = payload(27, "stream-27", 1, Vec::new(), "attempt-27");
    let mut spy = TransportSpy::default();
    spy.send_overrides
        .push_back(ReactiveContextSendOutcome::Unknown {
            reconciliation: handle("reconcile-27"),
            reason: "restart".to_owned(),
        });
    spy.query_overrides
        .push_back(ReactiveContextQueryOutcome::Unknown {
            reconciliation: handle("reconcile-27b"),
            reason: "still unknown".to_owned(),
        });
    let (mut delivery, adm, value, _) = deliver_one(spy, value);
    delivery.deliver(&adm, request(value))?;
    let result = delivery.reconcile_after_restart()?;
    assert_eq!(result.blocked_unknown.len(), 1);
    let (_, transport, _) = delivery.into_parts();
    assert_eq!(transport.send_calls.len(), 1);
    Ok(())
}

// WORK_UNIT_CASE: 798/28
#[test]
fn acknowledged_never_resent() -> TestResult {
    let value = payload(28, "stream-28", 1, Vec::new(), "attempt-28");
    let operation = operation_for(&value);
    let (mut delivery, adm, value, _) = deliver_one(TransportSpy::default(), value);
    delivery.deliver(&adm, request(value.clone()))?;
    delivery.acknowledge(
        operation,
        ack_evidence(&value, AckPhase::Received, &"4".repeat(64))?,
    )?;
    let replay = delivery.deliver(&adm, request(value))?;
    assert_eq!(replay.disposition, DeliveryDisposition::AlreadyAcknowledged);
    let (_, transport, _) = delivery.into_parts();
    assert_eq!(transport.send_calls.len(), 1);
    Ok(())
}

// WORK_UNIT_CASE: 798/29
#[test]
fn bounded_clean_drain() -> TestResult {
    let mut delivery = delivery(TransportSpy::default(), TestClock::new(50));
    let DrainOutcome {
        clean,
        open_operations,
        ..
    } = delivery.drain()?;
    assert!(clean);
    assert!(open_operations.is_empty());
    Ok(())
}

// WORK_UNIT_CASE: 798/30
#[test]
fn unknown_drain_not_clean() -> TestResult {
    let value = payload(30, "stream-30", 1, Vec::new(), "attempt-30");
    let mut spy = TransportSpy::default();
    spy.send_overrides
        .push_back(ReactiveContextSendOutcome::Unknown {
            reconciliation: handle("reconcile-30"),
            reason: "possible".to_owned(),
        });
    spy.close_overrides
        .push_back(ReactiveContextChannelCloseOutcome::Unknown {
            reason: "channel uncertain".to_owned(),
        });
    let (mut delivery, adm, value, _) = deliver_one(spy, value);
    delivery.deliver(&adm, request(value))?;
    let result = delivery.drain()?;
    assert!(!result.clean);
    assert_eq!(result.unknown_attempts, vec!["attempt-30".to_owned()]);
    Ok(())
}

// WORK_UNIT_CASE: 798/31
#[test]
fn fairness_and_concurrency_bounds() -> TestResult {
    let first = payload(31, "stream-31", 1, Vec::new(), "attempt-31");
    let mut spy = TransportSpy::default();
    spy.send_overrides
        .push_back(ReactiveContextSendOutcome::Unknown {
            reconciliation: handle("reconcile-31"),
            reason: "held".to_owned(),
        });
    spy.send_overrides
        .push_back(ReactiveContextSendOutcome::Unknown {
            reconciliation: handle("reconcile-31b"),
            reason: "control".to_owned(),
        });
    let clock = TestClock::new(50);
    let mut delivery = ReactiveContextDelivery::new(
        active_journal(),
        spy,
        clock,
        ReactiveContextDeliveryLimits {
            max_in_flight: 1,
            reserved_control_capacity: 1,
            ..Default::default()
        },
    )?;
    delivery.deliver(
        &admission(&first, HostDeliveryState::Active),
        request(first),
    )?;
    let normal = payload(32, "stream-32", 1, Vec::new(), "attempt-32");
    assert!(
        delivery
            .deliver(
                &admission(&normal, HostDeliveryState::Active),
                request(normal)
            )
            .is_err()
    );
    let control = payload(33, "stream-33", 1, Vec::new(), "attempt-33");
    let mut control_request = request(control.clone());
    control_request.control = true;
    assert!(
        delivery
            .deliver(
                &admission(&control, HostDeliveryState::Active),
                control_request
            )
            .is_ok()
    );
    Ok(())
}

// WORK_UNIT_CASE: 798/32
#[test]
fn deterministic_receipt() -> TestResult {
    let value = payload(34, "stream-34", 1, Vec::new(), "attempt-34");
    let (mut left, adm_left, value_left, _) = deliver_one(TransportSpy::default(), value.clone());
    let left_receipt = left.deliver(&adm_left, request(value_left))?;
    let (mut right, adm_right, value_right, _) = deliver_one(TransportSpy::default(), value);
    let right_receipt = right.deliver(&adm_right, request(value_right))?;
    assert_eq!(left_receipt.entry.operation, right_receipt.entry.operation);
    assert_eq!(left_receipt.entry.stage, right_receipt.entry.stage);
    assert_eq!(
        left_receipt.entry.transport_ref,
        right_receipt.entry.transport_ref
    );
    Ok(())
}

// WORK_UNIT_CASE: 798/33
#[test]
fn malformed_port_result_bounded() -> TestResult {
    let value = payload(35, "stream-35", 1, Vec::new(), "attempt-35");
    let mut spy = TransportSpy::default();
    spy.resolve_overrides
        .push_back(ReactiveContextEndpointResolution::Exact(
            ReactiveContextResolvedEndpoint {
                endpoint_ref: handle("wrong-endpoint"),
                recipient: value.recipient.clone(),
                transport_operation: handle("transport-operation"),
            },
        ));
    let (mut delivery, adm, value, _) = deliver_one(spy, value);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        delivery.deliver(&adm, request(value))
    }));
    assert!(result.is_ok());
    assert!(result.expect("no panic").is_err());
    Ok(())
}

// WORK_UNIT_CASE: 798/34
#[test]
fn send_has_durable_evidence() -> TestResult {
    let value = payload(36, "stream-36", 1, Vec::new(), "attempt-36");
    let (mut delivery, adm, value, _) = deliver_one(TransportSpy::default(), value);
    let result = delivery.deliver(&adm, request(value))?;
    assert!(result.entry.transport_ref.is_some());
    assert!(result.entry.owner_receipt.is_some());
    Ok(())
}

// WORK_UNIT_CASE: 798/35
#[test]
fn ack_exact_event_predecessor() -> TestResult {
    let value = payload(37, "stream-37", 1, Vec::new(), "attempt-37");
    let operation = operation_for(&value);
    let (mut delivery, adm, value, _) = deliver_one(TransportSpy::default(), value);
    delivery.deliver(&adm, request(value.clone()))?;
    let result = delivery.acknowledge(
        operation,
        ack_evidence(&value, AckPhase::Received, &"5".repeat(64))?,
    )?;
    assert_eq!(
        result.entry.ack_evidence[0].receipt.event_id,
        result.entry.envelope.event_id
    );
    Ok(())
}

// WORK_UNIT_CASE: 798/36
#[test]
fn unknown_does_not_create_new_operation() -> TestResult {
    let value = payload(38, "stream-38", 1, Vec::new(), "attempt-38");
    let mut spy = TransportSpy::default();
    spy.send_overrides
        .push_back(ReactiveContextSendOutcome::Unknown {
            reconciliation: handle("reconcile-38"),
            reason: "possible".to_owned(),
        });
    spy.query_overrides
        .push_back(ReactiveContextQueryOutcome::Unknown {
            reconciliation: handle("reconcile-38b"),
            reason: "still possible".to_owned(),
        });
    let (mut delivery, adm, value, _) = deliver_one(spy, value.clone());
    delivery.deliver(&adm, request(value.clone()))?;
    let result = delivery.reconcile(operation_for(&value))?;
    assert_eq!(result.entry.operation, operation_for(&value));
    let (_, transport, _) = delivery.into_parts();
    assert_eq!(transport.send_calls.len(), 1);
    assert_eq!(transport.query_calls[0].operation, operation_for(&value));
    Ok(())
}

// WORK_UNIT_CASE: 798/37
#[test]
fn restart_uses_queue_and_transport_only() -> TestResult {
    let value = payload(39, "stream-39", 1, Vec::new(), "attempt-39");
    let mut spy = TransportSpy::default();
    spy.send_overrides
        .push_back(ReactiveContextSendOutcome::Unknown {
            reconciliation: handle("reconcile-39"),
            reason: "restart".to_owned(),
        });
    spy.query_overrides
        .push_back(ReactiveContextQueryOutcome::Delivered(
            ReactiveContextTransportReceipt {
                operation: handle("transport-operation"),
                endpoint_ref: handle("test-endpoint"),
                owner_receipt: content("restart-39"),
            },
        ));
    let (mut delivery, adm, value, _) = deliver_one(spy, value);
    delivery.deliver(&adm, request(value))?;
    let RestartReconciliation {
        queries,
        reconciled,
        ..
    } = delivery.reconcile_after_restart()?;
    assert_eq!((queries, reconciled), (1, 1));
    let (_, transport, _) = delivery.into_parts();
    assert_eq!(transport.resolve_calls.len(), 1);
    assert_eq!(transport.send_calls.len(), 1);
    assert_eq!(transport.query_calls.len(), 1);
    Ok(())
}

// WORK_UNIT_CASE: 798/38
#[test]
fn scope_has_no_runtime_or_authority_owner() -> TestResult {
    let value = payload(40, "stream-40", 1, Vec::new(), "attempt-40");
    let (mut delivery, adm, value, _) = deliver_one(TransportSpy::default(), value);
    let result = delivery.deliver(&adm, request(value))?;
    assert!(result.entry.ack_evidence.is_empty());
    assert!(matches!(
        result.entry.payload.validity,
        ReactiveContextValidity::Current
    ));
    let (_, transport, _) = delivery.into_parts();
    assert_eq!(transport.send_calls.len(), 1);
    assert!(
        transport.send_calls[0]
            .payload
            .view
            .view_id
            .as_str()
            .starts_with("view-40")
    );
    Ok(())
}
