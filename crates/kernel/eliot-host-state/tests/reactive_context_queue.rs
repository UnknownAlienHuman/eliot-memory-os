#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::num::NonZeroU64;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractIdentity, ContractVersion, EpochId,
    EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration, SessionId, SourceId,
    StateFence, TaskId, TransactionSequence,
};
use eliot_host_state::{
    ActivationState, AppendDisposition, EliotActivationRecord, EpochTransition,
    HostInstallationEpoch, HostKernelStoreLineage, HostStateJournal, HostStateJournalService,
    HostStateRecord, IdempotencyIdentity, JOURNAL_MAGIC, JOURNAL_VERSION, JournalBackend,
    JournalError, LifecycleTimestamps, MemoryBackend, ReactiveContextEnqueueReceipt,
    ReactiveContextJournalAction, ReactiveContextPrepareRequest, ReactiveContextPrepareResult,
    ReactiveContextQueueError, ReactiveContextQueuePort, ReactiveContextQueueQuery,
    ReactiveContextReconcileOutcome, ReactiveContextReconcileRequest, ReactiveContextRecord,
    ReactiveContextTransition, ReactiveContextTransitionEvidence, ReadinessEvidence, RecordFence,
    RedbJournalBackend,
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
use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn Error>>;

fn handle(value: &str) -> PlatformHandle {
    PlatformHandle::new(value.to_owned()).expect("valid platform handle")
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
    let journal =
        HostStateJournal::open(MemoryBackend::default(), host.clone()).expect("open journal");
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

fn journal_with_fault(fault: eliot_host_state::FaultPoint) -> HostStateJournal<MemoryBackend> {
    let host = host();
    let journal = active_journal();
    let mut backend = journal.into_backend().expect("extract backend");
    backend.inject_fault(fault);
    HostStateJournal::open(backend, host).expect("reopen faulted journal")
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
            name: ContractId::new(format!("owner.{name}")).expect("contract name"),
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
            proof_ceiling: eliot_receipts::ProofCeiling::Observation,
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

fn current_revision<B: JournalBackend>(journal: &HostStateJournal<B>) -> u64 {
    journal
        .snapshot()
        .expect("snapshot")
        .reactive_context
        .expect("queue projection")
        .revision
}

fn prepare<B: JournalBackend>(
    journal: &HostStateJournal<B>,
    value: ReactiveContextPayload,
) -> Result<ReactiveContextPrepareResult, ReactiveContextQueueError> {
    let host = host();
    journal.prepare_reactive_context(ReactiveContextPrepareRequest {
        fence: record_fence(&host),
        payload: value,
        endpoint_ref: handle("test-endpoint"),
        owner_receipt: None,
        expected_queue_revision: current_revision(journal),
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

fn evidence(
    reason: Option<&str>,
    transport: Option<&str>,
    cancellation: Option<&str>,
    reconciliation: Option<&str>,
) -> ReactiveContextTransitionEvidence {
    ReactiveContextTransitionEvidence {
        owner_receipt: None,
        ack: None,
        transport_ref: transport.map(handle),
        cancellation_ref: cancellation.map(handle),
        reconciliation_ref: reconciliation.map(handle),
        reason: reason.map(str::to_owned),
        observed_at_unix_ms: Some(50),
    }
}

fn advance<B: JournalBackend>(
    journal: &HostStateJournal<B>,
    value: &eliot_host_state::ReactiveContextQueueEntry,
    mutation: &str,
    next_stage: ReactiveContextStage,
    evidence: ReactiveContextTransitionEvidence,
) -> Result<eliot_host_state::ReactiveContextTransitionReceipt, ReactiveContextQueueError> {
    journal.compare_and_transition(ReactiveContextTransition {
        fence: value.fence.clone(),
        mutation: operation(mutation),
        target: value.operation.clone(),
        expected_queue_revision: current_revision(journal),
        expected_stage: value.stage,
        next_stage,
        evidence,
    })
}

fn queue_query() -> ReactiveContextQueueQuery {
    ReactiveContextQueueQuery {
        limit: 0,
        ..ReactiveContextQueueQuery::default()
    }
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
    receipt_sequence: u64,
    parent: Option<eliot_contracts::ReceiptId>,
) -> Result<EventAckReceipt, Box<dyn Error>> {
    let fence = value.work_scope.state_fence.clone();
    let request_id = value.request_id.clone();
    let envelope = value.to_event_envelope()?;
    let core = ReceiptCore {
        contract: eliot_receipts::contract_identity()?,
        kind: ReceiptKind::Coordination,
        work_scope: value.work_scope.clone(),
        task: Some(TaskBinding {
            task_id: value.task_id.clone(),
            task_revision: eliot_contracts::TaskRevision::genesis(),
            state_fence: fence.clone(),
        }),
        session: Some(SessionBinding {
            session_id: value.recipient.session_id.clone(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
        }),
        causal: CausalBinding {
            state_fence: fence.clone(),
            transaction_sequence: TransactionSequence::new(receipt_sequence)?,
            parent_receipt_id: parent.clone(),
            predecessor_receipt_ids: parent.into_iter().collect(),
        },
        request: RequestBinding {
            metadata: eliot_contracts::RequestMetadata {
                request_id: request_id.clone(),
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
            request_id,
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
    receipt_sequence: u64,
    parent: Option<eliot_contracts::ReceiptId>,
) -> Result<ReactiveContextTransitionEvidence, Box<dyn Error>> {
    let receipt = generic_receipt(value, phase, receipt_sequence, parent)?;
    Ok(ReactiveContextTransitionEvidence {
        owner_receipt: None,
        ack: Some(ReactiveContextAckEvidence {
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
            proof_sha256: "2".repeat(64),
            lifecycle: ack_lifecycle(phase),
        }),
        ..ReactiveContextTransitionEvidence::default()
    })
}

fn temp_redb_path(label: &str) -> PathBuf {
    let digest = format!("{:x}", Sha256::digest(label.as_bytes()));
    let run = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    std::env::temp_dir()
        .join("eliot-host-state-reactive-context")
        .join(format!(
            "{label}-{}-{}-{}",
            std::process::id(),
            run,
            &digest[..16]
        ))
        .join("host-state.redb")
}

fn redb_active(path: &Path) -> Result<HostStateJournal<RedbJournalBackend>, Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let journal =
        HostStateJournal::open(RedbJournalBackend::open_unprotected_for_test(path)?, host())?;
    let host = host();
    for (state, name) in [
        (ActivationState::Starting, "redb-activation-start"),
        (ActivationState::ControlReady, "redb-activation-ready"),
        (ActivationState::Active, "redb-activation-active"),
    ] {
        journal.append(activation_record(&host, state, name))?;
    }
    Ok(journal)
}

fn raw_frame(sequence: u64, record: &HostStateRecord) -> Vec<u8> {
    let payload = serde_json::to_vec(record).expect("serialize record");
    let header = serde_json::json!({
        "version": JOURNAL_VERSION,
        "sequence": sequence,
        "length": payload.len(),
        "checksum": format!("{:x}", Sha256::digest(&payload)),
    });
    let mut bytes = Vec::new();
    bytes.extend_from_slice(JOURNAL_MAGIC);
    bytes.extend_from_slice(&serde_json::to_vec(&header).expect("serialize header"));
    bytes.push(b'\n');
    bytes.extend_from_slice(&payload);
    bytes.push(b'\n');
    bytes
}

fn prepared_record<B: JournalBackend>(
    journal: &HostStateJournal<B>,
    value: ReactiveContextPayload,
) -> ReactiveContextRecord {
    match prepare(journal, value).expect("prepare") {
        ReactiveContextPrepareResult::Prepared(token) => token.record,
        ReactiveContextPrepareResult::Replay(_) => panic!("fresh test operation replayed"),
    }
}

// WORK_UNIT_CASE: 800/1
#[test]
fn first_event_enqueue_and_snapshot() -> TestResult {
    let journal = active_journal();
    let value = payload(1, "stream-1", 1, Vec::new(), "attempt-1");
    let receipt = enqueue(&journal, value.clone())?;
    assert_eq!(receipt.entry.stage, ReactiveContextStage::EnqueuedPersisted);
    assert_eq!(receipt.journal.disposition(), AppendDisposition::Applied);
    let snapshot = journal.load_reactive_context_queue(queue_query())?;
    assert_eq!(snapshot.items.len(), 1);
    assert!(!snapshot.known_empty);
    assert_eq!(snapshot.items[0].payload_sha256, value.payload_sha256()?);
    Ok(())
}

// WORK_UNIT_CASE: 800/2
#[test]
fn monotonic_events_in_one_stream() -> TestResult {
    let journal = active_journal();
    let first = payload(2, "stream-monotonic", 1, Vec::new(), "attempt-2");
    let first_event = first.event_id()?;
    enqueue(&journal, first)?;
    let second = payload(3, "stream-monotonic", 2, vec![first_event], "attempt-2");
    enqueue(&journal, second)?;
    let snapshot = journal.load_reactive_context_queue(queue_query())?;
    assert_eq!(snapshot.items.len(), 2);
    assert_eq!(snapshot.items[1].envelope.sequence, 2);
    assert_eq!(snapshot.items[1].envelope.causal_predecessor_refs.len(), 1);
    Ok(())
}

// WORK_UNIT_CASE: 800/3
#[test]
fn independent_attempts_and_streams_have_no_global_order() -> TestResult {
    let journal = active_journal();
    enqueue(&journal, payload(4, "stream-b", 1, Vec::new(), "attempt-b"))?;
    enqueue(&journal, payload(5, "stream-a", 1, Vec::new(), "attempt-a"))?;
    let snapshot = journal.load_reactive_context_queue(queue_query())?;
    assert_eq!(snapshot.items.len(), 2);
    assert_ne!(
        snapshot.items[0].envelope.stream_id,
        snapshot.items[1].envelope.stream_id
    );
    assert!(
        snapshot
            .items
            .iter()
            .all(|item| item.envelope.sequence == 1)
    );
    Ok(())
}

// WORK_UNIT_CASE: 800/4
#[test]
fn replay_and_changed_operation_are_distinct() -> TestResult {
    let journal = active_journal();
    let value = payload(6, "stream-replay", 1, Vec::new(), "attempt-replay");
    enqueue(&journal, value.clone())?;
    assert!(matches!(
        prepare(&journal, value.clone())?,
        ReactiveContextPrepareResult::Replay(_)
    ));
    let mut changed = value;
    changed.cancellation_id.push_str("-changed");
    assert!(matches!(
        prepare(&journal, changed),
        Err(ReactiveContextQueueError::IdentityConflict)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 800/5
#[test]
fn same_sequence_event_and_conflicting_event_are_bound() -> TestResult {
    let journal = active_journal();
    let value = payload(7, "stream-sequence", 1, Vec::new(), "attempt-sequence");
    enqueue(&journal, value.clone())?;
    assert!(matches!(
        prepare(&journal, value)?,
        ReactiveContextPrepareResult::Replay(_)
    ));
    let conflicting = prepared_record(
        &journal,
        payload(8, "stream-sequence", 1, Vec::new(), "attempt-sequence"),
    );
    assert!(matches!(
        journal.commit_reactive_context(eliot_host_state::ReactiveContextPreparedEnqueue {
            record: conflicting,
            record_checksum: "0".repeat(64),
            transaction_id: handle("wrong-transaction"),
        }),
        Err(ReactiveContextQueueError::IdentityConflict)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 800/6
#[test]
fn gaps_regressions_and_wrong_predecessors_fail_closed() -> TestResult {
    let journal = active_journal();
    let gap = payload(9, "stream-gap", 3, Vec::new(), "attempt-gap");
    assert!(matches!(
        enqueue(&journal, gap),
        Err(ReactiveContextQueueError::Journal(_))
    ));
    let first = payload(10, "stream-gap", 1, Vec::new(), "attempt-gap");
    let first_event = first.event_id()?;
    enqueue(&journal, first)?;
    let wrong = payload(
        11,
        "stream-gap",
        2,
        vec!["wrong-event".to_owned()],
        "attempt-gap",
    );
    assert!(enqueue(&journal, wrong).is_err());
    let regression = payload(12, "stream-gap", 1, vec![first_event], "attempt-gap");
    assert!(enqueue(&journal, regression).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 800/7
#[test]
fn two_enqueue_writers_accept_exactly_one_commit() -> TestResult {
    let journal = Arc::new(active_journal());
    let first = match prepare(
        &journal,
        payload(13, "stream-race-a", 1, Vec::new(), "attempt-race"),
    )? {
        ReactiveContextPrepareResult::Prepared(token) => token,
        ReactiveContextPrepareResult::Replay(_) => panic!("fresh token replayed"),
    };
    let second = match prepare(
        &journal,
        payload(14, "stream-race-b", 1, Vec::new(), "attempt-race"),
    )? {
        ReactiveContextPrepareResult::Prepared(token) => token,
        ReactiveContextPrepareResult::Replay(_) => panic!("fresh token replayed"),
    };
    std::thread::scope(|scope| {
        let left = Arc::clone(&journal);
        let right = Arc::clone(&journal);
        let left_handle = scope.spawn(move || left.commit_reactive_context(first));
        let right_handle = scope.spawn(move || right.commit_reactive_context(second));
        let left = left_handle.join().expect("left writer");
        let right = right_handle.join().expect("right writer");
        assert_eq!(left.is_ok(), right.is_err());
        assert_eq!(right.is_ok(), left.is_err());
    });
    assert_eq!(
        journal
            .load_reactive_context_queue(queue_query())?
            .items
            .len(),
        1
    );
    Ok(())
}

// WORK_UNIT_CASE: 800/8
#[test]
fn stale_queue_revision_is_not_applied() -> TestResult {
    let journal = active_journal();
    let stale = match prepare(
        &journal,
        payload(15, "stream-stale-a", 1, Vec::new(), "attempt-stale"),
    )? {
        ReactiveContextPrepareResult::Prepared(token) => token,
        ReactiveContextPrepareResult::Replay(_) => panic!("fresh token replayed"),
    };
    enqueue(
        &journal,
        payload(16, "stream-stale-b", 1, Vec::new(), "attempt-stale"),
    )?;
    assert!(matches!(
        journal.commit_reactive_context(stale),
        Err(ReactiveContextQueueError::Journal(
            JournalError::ReactiveContext(_)
        ))
    ));
    assert_eq!(
        journal
            .load_reactive_context_queue(queue_query())?
            .items
            .len(),
        1
    );
    Ok(())
}

// WORK_UNIT_CASE: 800/9
#[test]
fn lost_commit_response_remains_unknown() -> TestResult {
    let journal = journal_with_fault(eliot_host_state::FaultPoint::CommitAfterUnknown);
    let value = payload(
        17,
        "stream-unknown-commit",
        1,
        Vec::new(),
        "attempt-unknown-commit",
    );
    let token = match prepare(&journal, value)? {
        ReactiveContextPrepareResult::Prepared(token) => token,
        ReactiveContextPrepareResult::Replay(_) => panic!("fresh token replayed"),
    };
    let result = journal.commit_reactive_context(token);
    assert!(matches!(
        result,
        Err(ReactiveContextQueueError::Journal(
            JournalError::OutcomeUnknown { .. }
        ))
    ));
    Ok(())
}

// WORK_UNIT_CASE: 800/10
#[test]
fn reconciliation_returns_exact_committed_receipt() -> TestResult {
    let journal = journal_with_fault(eliot_host_state::FaultPoint::CommitAfterUnknown);
    let value = payload(18, "stream-reconcile", 1, Vec::new(), "attempt-reconcile");
    let token = match prepare(&journal, value.clone())? {
        ReactiveContextPrepareResult::Prepared(token) => token,
        ReactiveContextPrepareResult::Replay(_) => panic!("fresh token replayed"),
    };
    let _ = journal.commit_reactive_context(token.clone());
    assert!(matches!(
        journal.reconcile_reactive_context(ReactiveContextReconcileRequest {
            operation: operation("unrelated-operation"),
            transaction_id: token.transaction_id.clone(),
        }),
        Err(ReactiveContextQueueError::IdentityConflict)
    ));
    let outcome = journal.reconcile_reactive_context(ReactiveContextReconcileRequest {
        operation: IdempotencyIdentity {
            operation_id: handle(value.operation_id.as_str()),
            idempotency_key: handle(&value.idempotency_key),
        },
        transaction_id: token.transaction_id,
    })?;
    match outcome {
        ReactiveContextReconcileOutcome::Committed(entry) => {
            assert_eq!(entry.stage, ReactiveContextStage::EnqueuedPersisted);
            assert_eq!(entry.payload_sha256, value.payload_sha256()?);
        }
        other => panic!("expected committed outcome, got {other:?}"),
    }
    Ok(())
}

// WORK_UNIT_CASE: 800/11
#[test]
fn independently_not_applied_commit_is_reported() -> TestResult {
    let journal = journal_with_fault(eliot_host_state::FaultPoint::PrepareFailed);
    let value = payload(
        19,
        "stream-not-applied",
        1,
        Vec::new(),
        "attempt-not-applied",
    );
    let token = match prepare(&journal, value.clone())? {
        ReactiveContextPrepareResult::Prepared(token) => token,
        ReactiveContextPrepareResult::Replay(_) => panic!("fresh token replayed"),
    };
    assert!(matches!(
        journal.commit_reactive_context(token.clone()),
        Err(ReactiveContextQueueError::Journal(JournalError::Backend(_)))
    ));
    let outcome = journal.reconcile_reactive_context(ReactiveContextReconcileRequest {
        operation: IdempotencyIdentity {
            operation_id: handle(value.operation_id.as_str()),
            idempotency_key: handle(&value.idempotency_key),
        },
        transaction_id: token.transaction_id,
    })?;
    assert!(matches!(
        outcome,
        ReactiveContextReconcileOutcome::NotApplied
    ));
    Ok(())
}

// WORK_UNIT_CASE: 800/12
#[test]
fn query_and_reconcile_do_not_create_mutations() -> TestResult {
    let journal = active_journal();
    let value = payload(20, "stream-read-only", 1, Vec::new(), "attempt-read-only");
    let token = match prepare(&journal, value.clone())? {
        ReactiveContextPrepareResult::Prepared(token) => token,
        ReactiveContextPrepareResult::Replay(_) => panic!("fresh token replayed"),
    };
    let before = journal.snapshot()?.sequence;
    let empty = journal.load_reactive_context_queue(queue_query())?;
    assert!(empty.known_empty);
    assert!(matches!(
        journal.query_reactive_context_operation(eliot_host_state::ReactiveContextOperationQuery {
            operation: operation("missing-operation")
        }),
        Err(ReactiveContextQueueError::NotFound)
    ));
    let outcome = journal.reconcile_reactive_context(ReactiveContextReconcileRequest {
        operation: IdempotencyIdentity {
            operation_id: handle(value.operation_id.as_str()),
            idempotency_key: handle(&value.idempotency_key),
        },
        transaction_id: token.transaction_id,
    })?;
    assert!(matches!(
        outcome,
        ReactiveContextReconcileOutcome::NotApplied
    ));
    assert_eq!(journal.snapshot()?.sequence, before);
    Ok(())
}

// WORK_UNIT_CASE: 800/13
#[test]
fn every_legal_ack_stage_transition_is_reduced() -> TestResult {
    let journal = active_journal();
    let value = payload(21, "stream-stages", 1, Vec::new(), "attempt-stages");
    let receipt = enqueue(&journal, value.clone())?;
    let mut current = receipt.entry;
    current = advance(
        &journal,
        &current,
        "stage-delivery-attempted",
        ReactiveContextStage::DeliveryAttempted,
        evidence(None, Some("transport-attempt"), None, None),
    )?
    .entry;
    current = advance(
        &journal,
        &current,
        "stage-delivered",
        ReactiveContextStage::DeliveredToExactEndpoint,
        evidence(None, Some("transport-delivered"), None, None),
    )?
    .entry;
    let mut parent = None;
    for (mutation, phase, sequence) in [
        ("stage-received", AckPhase::Received, 1),
        ("stage-durable", AckPhase::Durable, 2),
        ("stage-normalized", AckPhase::Normalized, 3),
        ("stage-applied", AckPhase::Applied, 4),
    ] {
        let ack = ack_evidence(&value, phase, sequence, parent.clone())?;
        parent = ack
            .ack
            .as_ref()
            .map(|item| item.receipt.receipt.identity.receipt_id.clone());
        current = advance(
            &journal,
            &current,
            mutation,
            match phase {
                AckPhase::Received => ReactiveContextStage::RecipientReceived,
                AckPhase::Durable => ReactiveContextStage::RecipientDurable,
                AckPhase::Normalized => ReactiveContextStage::NormalizedProjection,
                AckPhase::Applied => ReactiveContextStage::AppliedProjection,
                AckPhase::Rejected | AckPhase::Unknown => unreachable!(),
            },
            ack,
        )?
        .entry;
    }
    assert_eq!(current.stage, ReactiveContextStage::AppliedProjection);
    assert_eq!(current.ack_ledger.maximum_phase, Some(AckPhase::Applied));
    Ok(())
}

// WORK_UNIT_CASE: 800/14
#[test]
fn illegal_transition_and_duplicate_ack_cannot_downgrade() -> TestResult {
    let journal = active_journal();
    let value = payload(22, "stream-illegal", 1, Vec::new(), "attempt-illegal");
    let receipt = enqueue(&journal, value.clone())?;
    let current = receipt.entry;
    let illegal = advance(
        &journal,
        &current,
        "illegal-skip",
        ReactiveContextStage::RecipientReceived,
        ack_evidence(&value, AckPhase::Received, 1, None)?,
    );
    assert!(matches!(
        illegal,
        Err(ReactiveContextQueueError::Journal(
            JournalError::IllegalTransition { .. }
        ))
    ));

    let mut current = advance(
        &journal,
        &current,
        "illegal-delivery",
        ReactiveContextStage::DeliveryAttempted,
        evidence(None, Some("transport"), None, None),
    )?
    .entry;
    current = advance(
        &journal,
        &current,
        "illegal-delivered",
        ReactiveContextStage::DeliveredToExactEndpoint,
        evidence(None, Some("transport"), None, None),
    )?
    .entry;
    let received = ack_evidence(&value, AckPhase::Received, 1, None)?;
    current = advance(
        &journal,
        &current,
        "illegal-received",
        ReactiveContextStage::RecipientReceived,
        received.clone(),
    )?
    .entry;
    let downgrade = advance(
        &journal,
        &current,
        "illegal-regression",
        ReactiveContextStage::EnqueuedPersisted,
        ReactiveContextTransitionEvidence::default(),
    );
    assert!(matches!(
        downgrade,
        Err(ReactiveContextQueueError::Journal(
            JournalError::IllegalTransition { .. }
        ))
    ));
    let duplicate = advance(
        &journal,
        &current,
        "duplicate-received",
        ReactiveContextStage::RecipientReceived,
        received,
    )?;
    assert_eq!(
        duplicate.entry.stage,
        ReactiveContextStage::RecipientReceived
    );
    Ok(())
}

// WORK_UNIT_CASE: 800/15
#[test]
fn two_transition_writers_compete_on_one_revision() -> TestResult {
    let journal = active_journal();
    let value = payload(
        23,
        "stream-transition-race",
        1,
        Vec::new(),
        "attempt-transition-race",
    );
    let initial = enqueue(&journal, value.clone())?.entry;
    let revision = current_revision(&journal);
    let left = ReactiveContextTransition {
        fence: initial.fence.clone(),
        mutation: operation("transition-race-left"),
        target: initial.operation.clone(),
        expected_queue_revision: revision,
        expected_stage: initial.stage,
        next_stage: ReactiveContextStage::DeliveryAttempted,
        evidence: evidence(None, Some("left-transport"), None, None),
    };
    let right = ReactiveContextTransition {
        mutation: operation("transition-race-right"),
        evidence: evidence(None, Some("right-transport"), None, None),
        ..left.clone()
    };
    let first = journal.compare_and_transition(left)?;
    assert_eq!(first.entry.stage, ReactiveContextStage::DeliveryAttempted);
    assert!(matches!(
        journal.compare_and_transition(right),
        Err(ReactiveContextQueueError::Journal(
            JournalError::ReactiveContext(_)
        ))
    ));
    Ok(())
}

// WORK_UNIT_CASE: 800/16
#[test]
fn transition_replay_is_exact_and_changed_bytes_conflict() -> TestResult {
    let journal = active_journal();
    let value = payload(
        24,
        "stream-transition-replay",
        1,
        Vec::new(),
        "attempt-transition-replay",
    );
    let initial = enqueue(&journal, value)?.entry;
    let transition = ReactiveContextTransition {
        fence: initial.fence.clone(),
        mutation: operation("transition-replay"),
        target: initial.operation.clone(),
        expected_queue_revision: current_revision(&journal),
        expected_stage: initial.stage,
        next_stage: ReactiveContextStage::DeliveryAttempted,
        evidence: evidence(None, Some("replay-transport"), None, None),
    };
    let first = journal.compare_and_transition(transition.clone())?;
    let replay = journal.compare_and_transition(transition.clone())?;
    assert_eq!(replay.journal.disposition(), AppendDisposition::Replayed);
    assert_eq!(first.entry, replay.entry);
    let mut changed = transition;
    changed.evidence.transport_ref = Some(handle("changed-transport"));
    assert!(matches!(
        journal.compare_and_transition(changed),
        Err(ReactiveContextQueueError::Journal(
            JournalError::IdempotencyConflict
        ))
    ));
    Ok(())
}

// WORK_UNIT_CASE: 800/17
#[test]
fn mismatched_ack_bindings_are_rejected() -> TestResult {
    let journal = active_journal();
    let value = payload(
        25,
        "stream-binding-mismatch",
        1,
        Vec::new(),
        "attempt-binding-mismatch",
    );
    let current = enqueue(&journal, value.clone())?.entry;
    let current = advance(
        &journal,
        &current,
        "binding-delivery",
        ReactiveContextStage::DeliveryAttempted,
        evidence(None, Some("binding-transport"), None, None),
    )?
    .entry;
    let current = advance(
        &journal,
        &current,
        "binding-delivered",
        ReactiveContextStage::DeliveredToExactEndpoint,
        evidence(None, Some("binding-transport"), None, None),
    )?
    .entry;
    let mut ack = ack_evidence(&value, AckPhase::Received, 1, None)?;
    ack.ack.as_mut().expect("ack evidence").attempt_id = AgentAttemptId::new("wrong-attempt")?;
    assert!(matches!(
        advance(
            &journal,
            &current,
            "binding-mismatch",
            ReactiveContextStage::RecipientReceived,
            ack,
        ),
        Err(ReactiveContextQueueError::Journal(
            JournalError::ReactiveContext(_)
        ))
    ));
    assert_eq!(
        journal.load_reactive_context_queue(queue_query())?.items[0].stage,
        ReactiveContextStage::DeliveredToExactEndpoint
    );
    Ok(())
}

// WORK_UNIT_CASE: 800/18
#[test]
fn queue_attempt_bound_rejects_one_over_capacity() -> TestResult {
    let journal = active_journal();
    for key in 26..90 {
        enqueue(
            &journal,
            payload(
                key,
                &format!("stream-bound-{key}"),
                1,
                Vec::new(),
                "attempt-bound",
            ),
        )?;
    }
    let over = enqueue(
        &journal,
        payload(90, "stream-bound-90", 1, Vec::new(), "attempt-bound"),
    );
    assert!(matches!(
        over,
        Err(ReactiveContextQueueError::Journal(JournalError::ReactiveContext(message)))
            if message.contains("attempt_items")
    ));
    assert_eq!(
        journal
            .load_reactive_context_queue(queue_query())?
            .items
            .len(),
        64
    );
    Ok(())
}

// WORK_UNIT_CASE: 800/19
#[test]
fn page_cursor_frontier_and_truncation_are_stable() -> TestResult {
    let journal = active_journal();
    for key in 91..94 {
        enqueue(
            &journal,
            payload(
                key,
                &format!("stream-page-{key}"),
                1,
                Vec::new(),
                &format!("attempt-page-{key}"),
            ),
        )?;
    }
    let first = journal.load_reactive_context_queue(ReactiveContextQueueQuery {
        limit: 1,
        ..ReactiveContextQueueQuery::default()
    })?;
    assert_eq!(first.items.len(), 1);
    assert!(first.partial);
    let cursor = first.next_cursor.clone().expect("continuation");
    let second = journal.load_reactive_context_queue(ReactiveContextQueueQuery {
        limit: 1,
        cursor: Some(cursor),
        ..ReactiveContextQueueQuery::default()
    })?;
    assert_eq!(second.items.len(), 1);
    assert_ne!(first.items[0].operation, second.items[0].operation);
    Ok(())
}

// WORK_UNIT_CASE: 800/20
#[test]
fn stale_foreign_and_drifting_cursors_are_rejected() -> TestResult {
    let journal = active_journal();
    enqueue(
        &journal,
        payload(94, "stream-cursor", 1, Vec::new(), "attempt-cursor"),
    )?;
    let page = journal.load_reactive_context_queue(ReactiveContextQueueQuery {
        limit: 1,
        ..ReactiveContextQueueQuery::default()
    })?;
    let cursor = page
        .next_cursor
        .unwrap_or(eliot_host_state::ReactiveContextQueueCursor {
            revision: page.revision,
            offset: 0,
        });
    let mut foreign = cursor.clone();
    foreign.revision = 999;
    assert!(matches!(
        journal.load_reactive_context_queue(ReactiveContextQueueQuery {
            cursor: Some(foreign),
            ..ReactiveContextQueueQuery::default()
        }),
        Err(ReactiveContextQueueError::StaleCursor)
    ));
    enqueue(
        &journal,
        payload(95, "stream-cursor-2", 1, Vec::new(), "attempt-cursor-2"),
    )?;
    assert!(matches!(
        journal.load_reactive_context_queue(ReactiveContextQueueQuery {
            cursor: Some(cursor),
            ..ReactiveContextQueueQuery::default()
        }),
        Err(ReactiveContextQueueError::StaleCursor)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 800/21
#[test]
fn known_empty_is_distinct_from_partial_page() -> TestResult {
    let journal = active_journal();
    let empty = journal.load_reactive_context_queue(queue_query())?;
    assert!(empty.known_empty);
    assert!(!empty.partial);
    enqueue(
        &journal,
        payload(96, "stream-partial-a", 1, Vec::new(), "attempt-partial"),
    )?;
    enqueue(
        &journal,
        payload(97, "stream-partial-b", 1, Vec::new(), "attempt-partial"),
    )?;
    let partial = journal.load_reactive_context_queue(ReactiveContextQueueQuery {
        limit: 1,
        ..ReactiveContextQueueQuery::default()
    })?;
    assert!(!partial.known_empty);
    assert!(partial.partial);
    Ok(())
}

// WORK_UNIT_CASE: 800/22
#[test]
fn canonical_digest_ignores_irrelevant_insertion_order() -> TestResult {
    let left = active_journal();
    let right = active_journal();
    let left_a = payload(
        98,
        "stream-canonical-a",
        1,
        Vec::new(),
        "attempt-canonical-a",
    );
    let left_b = payload(
        99,
        "stream-canonical-b",
        1,
        Vec::new(),
        "attempt-canonical-b",
    );
    enqueue(&left, left_a.clone())?;
    enqueue(&left, left_b.clone())?;
    enqueue(&right, left_b)?;
    enqueue(&right, left_a)?;
    let left_snapshot = left.load_reactive_context_queue(queue_query())?;
    let right_snapshot = right.load_reactive_context_queue(queue_query())?;
    assert_eq!(left_snapshot.digest, right_snapshot.digest);
    assert_eq!(
        left_snapshot
            .items
            .iter()
            .map(|item| item.operation.clone())
            .collect::<Vec<_>>(),
        right_snapshot
            .items
            .iter()
            .map(|item| item.operation.clone())
            .collect::<Vec<_>>()
    );
    Ok(())
}

// WORK_UNIT_CASE: 800/23
#[test]
fn real_redb_reopens_across_queue_stages() -> TestResult {
    let stages = vec![
        (ReactiveContextStage::EnqueuedPersisted, None),
        (
            ReactiveContextStage::DeliveryAttempted,
            Some(evidence(None, Some("redb-transport"), None, None)),
        ),
        (
            ReactiveContextStage::DeliveredToExactEndpoint,
            Some(evidence(None, Some("redb-transport"), None, None)),
        ),
        (
            ReactiveContextStage::UnknownDelivery,
            Some(evidence(None, None, None, Some("redb-reconcile"))),
        ),
        (
            ReactiveContextStage::RejectedNotAttempted,
            Some(evidence(Some("redb-rejected"), None, None, None)),
        ),
        (
            ReactiveContextStage::ExpiredBeforeAck,
            Some(evidence(Some("redb-expired"), None, None, None)),
        ),
        (
            ReactiveContextStage::CancelledRetracted,
            Some(evidence(
                Some("redb-cancelled"),
                None,
                Some("redb-cancel"),
                None,
            )),
        ),
        (
            ReactiveContextStage::StaleSuperseded,
            Some(evidence(Some("redb-stale"), None, None, None)),
        ),
        (
            ReactiveContextStage::UnavailableFenced,
            Some(evidence(Some("redb-unavailable"), None, None, None)),
        ),
    ];
    for (index, (expected, transition_evidence)) in stages.into_iter().enumerate() {
        let path = temp_redb_path(&format!("stage-{index}"));
        let journal = redb_active(&path)?;
        let value = payload(
            101 + index as u64,
            &format!("redb-stage-{index}"),
            1,
            Vec::new(),
            &format!("attempt-redb-{index}"),
        );
        let current = enqueue(&journal, value)?.entry;
        if let Some(evidence) = transition_evidence {
            let _ = advance(
                &journal,
                &current,
                &format!("redb-stage-mutation-{index}"),
                expected,
                evidence,
            )?;
        }
        drop(journal);
        let reopened = HostStateJournal::open(
            RedbJournalBackend::open_unprotected_for_test(&path)?,
            host(),
        )?;
        let snapshot = reopened.load_reactive_context_queue(ReactiveContextQueueQuery {
            include_terminal: true,
            ..ReactiveContextQueueQuery::default()
        })?;
        assert_eq!(snapshot.items.len(), 1);
        assert_eq!(snapshot.items[0].stage, expected);
        drop(reopened);
        if let Some(parent) = path.parent() {
            fs::remove_dir_all(parent)?;
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 800/24
#[test]
fn unresolved_operation_survives_real_redb_reopen() -> TestResult {
    let path = temp_redb_path("unresolved-reopen");
    let journal = redb_active(&path)?;
    let value = payload(
        111,
        "redb-unresolved",
        1,
        Vec::new(),
        "attempt-redb-unresolved",
    );
    let current = enqueue(&journal, value.clone())?.entry;
    let current = advance(
        &journal,
        &current,
        "redb-unknown",
        ReactiveContextStage::UnknownDelivery,
        evidence(None, None, None, Some("unknown-delivery-reconcile")),
    )?;
    assert!(!current.entry.is_terminal());
    drop(journal);
    let reopened = HostStateJournal::open(
        RedbJournalBackend::open_unprotected_for_test(&path)?,
        host(),
    )?;
    let snapshot = reopened.load_reactive_context_queue(queue_query())?;
    assert_eq!(
        snapshot.items[0].stage,
        ReactiveContextStage::UnknownDelivery
    );
    assert!(!snapshot.known_empty);
    drop(reopened);
    if let Some(parent) = path.parent() {
        fs::remove_dir_all(parent)?;
    }
    Ok(())
}

// WORK_UNIT_CASE: 800/25
#[test]
fn duplicate_and_missing_predecessor_records_are_rejected() -> TestResult {
    let journal = active_journal();
    let first = payload(112, "stream-integrity", 1, Vec::new(), "attempt-integrity");
    let first_event = first.event_id()?;
    enqueue(&journal, first)?;
    let duplicate_sequence = payload(113, "stream-integrity", 1, Vec::new(), "attempt-integrity");
    assert!(matches!(
        enqueue(&journal, duplicate_sequence),
        Err(ReactiveContextQueueError::Journal(
            JournalError::IdempotencyConflict
        ))
    ));
    let missing_predecessor = payload(
        114,
        "stream-integrity",
        2,
        vec!["missing".to_owned()],
        "attempt-integrity",
    );
    assert!(matches!(
        enqueue(&journal, missing_predecessor),
        Err(ReactiveContextQueueError::Journal(
            JournalError::ReactiveContext(_)
        ))
    ));
    let valid_successor = payload(
        115,
        "stream-integrity",
        2,
        vec![first_event],
        "attempt-integrity",
    );
    enqueue(&journal, valid_successor)?;
    assert_eq!(
        journal
            .load_reactive_context_queue(queue_query())?
            .items
            .len(),
        2
    );
    Ok(())
}

// WORK_UNIT_CASE: 800/26
#[test]
fn checksum_and_payload_digest_corruption_fail_replay() {
    let journal = active_journal();
    let value = payload(
        116,
        "stream-corruption",
        1,
        Vec::new(),
        "attempt-corruption",
    );
    let queue_record = prepared_record(&journal, value);
    let host = host();
    let activation = activation_generation();
    let mut bytes = Vec::new();
    bytes.extend(raw_frame(
        1,
        &activation_record(&host, ActivationState::Starting, "corrupt-start"),
    ));
    bytes.extend(raw_frame(
        2,
        &activation_record(&host, ActivationState::ControlReady, "corrupt-ready"),
    ));
    bytes.extend(raw_frame(
        3,
        &activation_record(&host, ActivationState::Active, "corrupt-active"),
    ));
    bytes.extend(raw_frame(
        4,
        &HostStateRecord::ReactiveContext(queue_record.clone()),
    ));
    let last = bytes.len().saturating_sub(2);
    bytes[last] ^= 1;
    assert!(matches!(
        HostStateJournal::<MemoryBackend>::replay_bytes(&bytes, host.clone()),
        Err(JournalError::Checksum { .. })
    ));

    let mut digest_record = queue_record;
    digest_record.fence.activation_generation = activation;
    if let ReactiveContextJournalAction::Enqueue(entry) = &mut digest_record.action {
        entry.payload_sha256 = "f".repeat(64);
    }
    let mut digest_bytes = Vec::new();
    digest_bytes.extend(raw_frame(
        1,
        &activation_record(&host, ActivationState::Starting, "digest-start"),
    ));
    digest_bytes.extend(raw_frame(
        2,
        &activation_record(&host, ActivationState::ControlReady, "digest-ready"),
    ));
    digest_bytes.extend(raw_frame(
        3,
        &activation_record(&host, ActivationState::Active, "digest-active"),
    ));
    digest_bytes.extend(raw_frame(
        4,
        &HostStateRecord::ReactiveContext(digest_record),
    ));
    assert!(matches!(
        HostStateJournal::<MemoryBackend>::replay_bytes(&digest_bytes, host),
        Err(JournalError::IdempotencyConflict)
    ));
}

// WORK_UNIT_CASE: 800/27
#[test]
fn legacy_non_queue_journal_remains_readable() -> TestResult {
    let host = host();
    let bytes = raw_frame(
        1,
        &activation_record(&host, ActivationState::Starting, "legacy-start"),
    );
    let state = HostStateJournal::<MemoryBackend>::replay_bytes(&bytes, host)?;
    assert_eq!(state.sequence, 1);
    assert!(
        state
            .reactive_context
            .expect("queue projection")
            .entries
            .is_empty()
    );
    Ok(())
}

// WORK_UNIT_CASE: 800/28
#[test]
fn exact_replay_is_idempotent_and_ready_for_recovery() -> TestResult {
    let journal = active_journal();
    let value = payload(
        117,
        "stream-replay-ready",
        1,
        Vec::new(),
        "attempt-replay-ready",
    );
    let token = match prepare(&journal, value)? {
        ReactiveContextPrepareResult::Prepared(token) => token,
        ReactiveContextPrepareResult::Replay(_) => panic!("fresh token replayed"),
    };
    let first = journal.commit_reactive_context(token.clone())?;
    let second = journal.commit_reactive_context(token)?;
    assert_eq!(first.journal.sequence(), second.journal.sequence());
    assert_eq!(second.journal.disposition(), AppendDisposition::Replayed);
    assert_eq!(
        journal
            .load_reactive_context_queue(queue_query())?
            .items
            .len(),
        1
    );
    Ok(())
}

// WORK_UNIT_CASE: 800/29
#[test]
fn non_reactive_records_leave_queue_projection_unchanged() -> TestResult {
    let journal = active_journal();
    let before = journal.load_reactive_context_queue(queue_query())?;
    let state = journal.snapshot()?;
    assert_eq!(
        state.activation.map(|item| item.state),
        Some(ActivationState::Active)
    );
    assert!(before.known_empty);
    assert_eq!(before.revision, 0);
    Ok(())
}

// WORK_UNIT_CASE: 800/30
#[test]
fn unknown_delivery_is_retained_and_stream_continuity_survives() -> TestResult {
    let journal = active_journal();
    let first = payload(118, "stream-retain", 1, Vec::new(), "attempt-retain");
    let first_event = first.event_id()?;
    let current = enqueue(&journal, first)?.entry;
    let current = advance(
        &journal,
        &current,
        "retain-unknown",
        ReactiveContextStage::UnknownDelivery,
        evidence(None, None, None, Some("retain-reconcile")),
    )?;
    assert!(!current.entry.is_terminal());
    let second = payload(119, "stream-retain", 2, vec![first_event], "attempt-retain");
    enqueue(&journal, second)?;
    let snapshot = journal.load_reactive_context_queue(queue_query())?;
    assert_eq!(snapshot.items.len(), 2);
    assert!(
        snapshot
            .items
            .iter()
            .any(|item| item.stage == ReactiveContextStage::UnknownDelivery)
    );
    Ok(())
}

// WORK_UNIT_CASE: 800/31
#[test]
fn terminal_history_is_retained_for_audit() -> TestResult {
    let journal = active_journal();
    let value = payload(120, "stream-terminal", 1, Vec::new(), "attempt-terminal");
    let current = enqueue(&journal, value)?.entry;
    let terminal = advance(
        &journal,
        &current,
        "terminal-cancel",
        ReactiveContextStage::CancelledRetracted,
        evidence(Some("operator-retracted"), None, Some("cancel-ref"), None),
    )?;
    assert!(terminal.entry.is_terminal());
    assert!(
        journal
            .load_reactive_context_queue(queue_query())?
            .known_empty
    );
    let history = journal.load_reactive_context_queue(ReactiveContextQueueQuery {
        include_terminal: true,
        ..ReactiveContextQueueQuery::default()
    })?;
    assert_eq!(history.items.len(), 1);
    assert_eq!(
        history.items[0].reason.as_deref(),
        Some("operator-retracted")
    );
    Ok(())
}

// WORK_UNIT_CASE: 800/32
#[test]
fn snapshots_contain_typed_references_without_secret_payloads() -> TestResult {
    let journal = active_journal();
    let value = payload(
        121,
        "stream-secret-canary",
        1,
        Vec::new(),
        "attempt-secret-canary",
    );
    enqueue(&journal, value)?;
    let wire = serde_json::to_string(&journal.snapshot()?)?;
    assert!(!wire.contains("password"));
    assert!(!wire.contains("bearer "));
    assert!(!wire.contains("secret="));
    assert!(wire.contains("reactive-context"));
    Ok(())
}

// WORK_UNIT_CASE: 800/33
#[test]
fn malformed_persisted_input_returns_error_without_panic() {
    let result = catch_unwind(AssertUnwindSafe(|| {
        HostStateJournal::<MemoryBackend>::replay_bytes(b"not-a-host-journal", host())
    }));
    assert!(result.is_ok());
    assert!(result.expect("no panic").is_err());
}

// WORK_UNIT_CASE: 800/34
#[test]
fn accepted_operations_have_unique_attempt_stream_sequence_and_event_keys() -> TestResult {
    let journal = active_journal();
    for key in 122..126 {
        enqueue(
            &journal,
            payload(
                key,
                &format!("stream-unique-{key}"),
                1,
                Vec::new(),
                &format!("attempt-unique-{key}"),
            ),
        )?;
    }
    let snapshot = journal.load_reactive_context_queue(queue_query())?;
    let operations: BTreeSet<_> = snapshot
        .items
        .iter()
        .map(|item| item.operation.clone())
        .collect();
    let events: BTreeSet<_> = snapshot
        .items
        .iter()
        .map(|item| item.envelope.event_id.clone())
        .collect();
    let streams: BTreeSet<_> = snapshot
        .items
        .iter()
        .map(|item| item.envelope.stream_id.clone())
        .collect();
    assert_eq!(operations.len(), 4);
    assert_eq!(events.len(), 4);
    assert_eq!(streams.len(), 4);
    assert!(
        snapshot
            .items
            .iter()
            .all(|item| item.envelope.sequence == 1)
    );
    Ok(())
}

// WORK_UNIT_CASE: 800/35
#[test]
fn predecessor_and_context_identity_remain_immutable_after_transition() -> TestResult {
    let journal = active_journal();
    let value = payload(126, "stream-immutable", 1, Vec::new(), "attempt-immutable");
    let before = enqueue(&journal, value.clone())?.entry;
    let after = advance(
        &journal,
        &before,
        "immutable-transition",
        ReactiveContextStage::DeliveryAttempted,
        evidence(None, Some("immutable-transport"), None, None),
    )?
    .entry;
    assert_eq!(before.payload, after.payload);
    assert_eq!(before.payload_sha256, after.payload_sha256);
    assert_eq!(before.envelope, after.envelope);
    assert_eq!(
        after.predecessor_stage,
        Some(ReactiveContextStage::EnqueuedPersisted)
    );
    Ok(())
}

// WORK_UNIT_CASE: 800/36
#[test]
fn recovery_snapshot_matches_the_accepted_redb_digest() -> TestResult {
    let path = temp_redb_path("recovery-digest");
    let journal = redb_active(&path)?;
    let value = payload(127, "stream-recovery", 1, Vec::new(), "attempt-recovery");
    enqueue(&journal, value)?;
    let accepted = journal.load_reactive_context_queue(queue_query())?;
    drop(journal);
    let reopened = HostStateJournal::open(
        RedbJournalBackend::open_unprotected_for_test(&path)?,
        host(),
    )?;
    let recovered = reopened.load_reactive_context_queue(queue_query())?;
    assert_eq!(accepted.revision, recovered.revision);
    assert_eq!(accepted.queue_generation, recovered.queue_generation);
    assert_eq!(accepted.digest, recovered.digest);
    assert_eq!(accepted.items, recovered.items);
    drop(reopened);
    if let Some(parent) = path.parent() {
        fs::remove_dir_all(parent)?;
    }
    Ok(())
}

// WORK_UNIT_CASE: 800/37
#[test]
fn unknown_operation_is_neither_compacted_nor_successful() -> TestResult {
    let journal = active_journal();
    let value = payload(
        128,
        "stream-unknown-retained",
        1,
        Vec::new(),
        "attempt-unknown-retained",
    );
    let current = enqueue(&journal, value)?.entry;
    let unknown = advance(
        &journal,
        &current,
        "unknown-retained",
        ReactiveContextStage::UnknownDelivery,
        evidence(None, None, None, Some("unknown-reconcile")),
    )?;
    assert!(!unknown.entry.is_terminal());
    let active = journal.load_reactive_context_queue(queue_query())?;
    assert_eq!(active.items.len(), 1);
    assert_eq!(active.items[0].stage, ReactiveContextStage::UnknownDelivery);
    assert!(!active.known_empty);
    Ok(())
}

// WORK_UNIT_CASE: 800/38
#[test]
fn production_journal_and_service_implement_only_the_queue_port() -> TestResult {
    fn assert_port<T: ReactiveContextQueuePort>() {}
    assert_port::<HostStateJournal<MemoryBackend>>();
    assert_port::<HostStateJournalService<MemoryBackend>>();
    let service = HostStateJournalService::from_backend(MemoryBackend::default(), host())?;
    let snapshot = ReactiveContextQueuePort::load_attempt_queue(&service, queue_query())?;
    assert!(snapshot.known_empty);
    assert_eq!(snapshot.items.len(), 0);
    let fixture: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("data/reactive_context_queue.json"))?;
    assert_eq!(fixture.len(), 38);
    Ok(())
}
