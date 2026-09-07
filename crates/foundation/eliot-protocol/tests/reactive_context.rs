#![allow(clippy::expect_used)]

use std::error::Error;

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ClockReading, ContractId, ContractIdentity, ContractVersion,
    OperationId, ProductId, RequestId, ResourceGeneration, SessionId, SourceId, StateFence, TaskId,
    TransactionSequence,
};
use eliot_protocol::reactive_context::{
    ReactiveContextAckDisposition, ReactiveContextAckEvidence, ReactiveContextAckLedger,
    ReactiveContextContentRef, ReactiveContextLifecycleEvidence, ReactiveContextPayload,
    ReactiveContextPrivacy, ReactiveContextRecipient, ReactiveContextSafetyFloor,
    ReactiveContextSequence, ReactiveContextStage, ReactiveContextViewBinding,
    reactive_context_contract_identity,
};
use eliot_protocol::{AckPhase, EventAckReceipt, EventDisposition, ProtocolError};
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, CausalBinding, CoordinationBinding, EffectClass,
    OperationBinding, ProofCeiling, ReceiptCore, ReceiptDisposition, ReceiptEnvelope, ReceiptKind,
    RequestBinding, SessionBinding, TaskBinding, WorkScopeBinding, WorkScopeId,
};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn typed_payload_maps_to_one_deterministic_blob_event() -> TestResult {
    let payload = payload(1, Vec::new());
    let envelope = payload.to_event_envelope()?;
    assert_eq!(envelope.payload_type, "reactive-context/v1");
    assert!(matches!(
        envelope.payload_or_blob_ref,
        eliot_protocol::EventPayload::BlobRef(_)
    ));
    assert_ne!(
        envelope.payload_or_blob_ref,
        eliot_protocol::EventPayload::Inline(Box::new(eliot_protocol::ProtocolPayload::Json(
            serde_json::json!({})
        ),))
    );
    assert_eq!(envelope.event_id, payload.event_id()?);
    assert_eq!(envelope, payload.to_event_envelope()?);
    let _: ReactiveContextPayload = payload.clone();

    let mut changed = payload.clone();
    changed.cancellation_id.push_str("-changed");
    assert_eq!(changed.event_id()?, payload.event_id()?);
    assert_ne!(changed.payload_sha256()?, payload.payload_sha256()?);
    assert_ne!(
        changed.to_event_envelope()?.payload_or_blob_ref,
        envelope.payload_or_blob_ref
    );
    Ok(())
}

#[test]
fn sequence_requires_exact_first_and_successor() -> TestResult {
    let first = payload(1, Vec::new());
    first.validate()?;
    let successor = payload(2, vec![first.event_id()?]);
    successor.validate_successor(&first)?;

    let gap = payload(3, vec![first.event_id()?]);
    assert!(matches!(
        gap.validate_successor(&first),
        Err(eliot_protocol::reactive_context::ReactiveContextError::SequenceGap { .. })
    ));
    let regression = payload(1, Vec::new());
    assert!(matches!(
        regression.validate_successor(&successor),
        Err(eliot_protocol::reactive_context::ReactiveContextError::SequenceRegression { .. })
    ));
    Ok(())
}

#[test]
fn closed_decode_rejects_unknown_duplicate_and_zero_bounds() -> TestResult {
    let source = payload(1, Vec::new());
    let valid = serde_json::to_string(&source)?;
    assert_eq!(ReactiveContextPayload::decode(valid.as_bytes())?, source);
    let wire = serde_json::to_value(&source)?;
    let mut unknown = wire.clone();
    unknown["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ReactiveContextPayload>(unknown).is_err());

    let duplicate = valid.replacen(
        "\"operation_id\":\"operation-1\"",
        "\"operation_id\":\"operation-1\",\"operation_id\":\"operation-2\"",
        1,
    );
    assert!(ReactiveContextPayload::decode(duplicate.as_bytes()).is_err());

    let mut invalid = payload(1, Vec::new());
    invalid.view.representation.byte_length = Some(0);
    assert!(invalid.validate().is_err());
    Ok(())
}

#[test]
fn supplied_ack_binds_generic_receipt_and_replay_keeps_maximum_phase() -> TestResult {
    let payload = payload(1, Vec::new());
    let envelope = payload.to_event_envelope()?;
    let mut ledger = ReactiveContextAckLedger::new(&payload)?;
    let mut parent = None;
    let mut durable_evidence = None;
    for (receipt_sequence, phase) in [
        AckPhase::Received,
        AckPhase::Durable,
        AckPhase::Normalized,
        AckPhase::Applied,
    ]
    .into_iter()
    .enumerate()
    {
        let receipt = generic_receipt(
            &payload,
            &envelope,
            phase,
            receipt_sequence as u64 + 1,
            parent.clone(),
        )?;
        parent = Some(receipt.receipt.identity.receipt_id.clone());
        let evidence = evidence(&payload, receipt, phase)?;
        evidence.validate_against(&payload)?;
        assert_eq!(
            ledger.record(&evidence, &payload)?,
            ReactiveContextAckDisposition::Accepted
        );
        if phase == AckPhase::Durable {
            durable_evidence = Some(evidence);
        }
    }
    assert_eq!(ledger.maximum_phase, Some(AckPhase::Applied));
    let durable = durable_evidence.expect("durable evidence");
    assert_eq!(
        ledger.record(&durable, &payload)?,
        ReactiveContextAckDisposition::DuplicateHistorical
    );

    let mut changed = durable.clone();
    changed.proof_sha256 = "f".repeat(64);
    assert!(matches!(
        ledger.record(&changed, &payload),
        Err(eliot_protocol::reactive_context::ReactiveContextError::ReplayConflict)
    ));

    let mut terminal = ReactiveContextAckLedger::new(&payload)?;
    let received = generic_receipt(&payload, &envelope, AckPhase::Received, 1, None)?;
    let received_id = received.receipt.identity.receipt_id.clone();
    terminal.record(&evidence(&payload, received, AckPhase::Received)?, &payload)?;
    let rejected = generic_receipt(
        &payload,
        &envelope,
        AckPhase::Rejected,
        2,
        Some(received_id),
    )?;
    let rejected_id = rejected.receipt.identity.receipt_id.clone();
    terminal.record(&evidence(&payload, rejected, AckPhase::Rejected)?, &payload)?;
    assert_eq!(terminal.current_phase, Some(AckPhase::Rejected));
    let reopened = generic_receipt(&payload, &envelope, AckPhase::Durable, 3, Some(rejected_id))?;
    let reopened_result =
        terminal.record(&evidence(&payload, reopened, AckPhase::Durable)?, &payload);
    assert!(matches!(
        reopened_result,
        Err(
            eliot_protocol::reactive_context::ReactiveContextError::Protocol(
                ProtocolError::InvalidAckTransition { .. }
            )
        )
    ));
    Ok(())
}

#[test]
fn applied_ack_requires_admitted_projection_evidence() -> TestResult {
    let payload = payload(1, Vec::new());
    let envelope = payload.to_event_envelope()?;
    let receipt = generic_receipt(&payload, &envelope, AckPhase::Applied, 1, None)?;
    let mut evidence = evidence(&payload, receipt, AckPhase::Applied)?;
    evidence.lifecycle.stage = ReactiveContextStage::RecipientReceived;
    evidence.lifecycle.predecessor = None;
    assert!(matches!(
        evidence.validate_against(&payload),
        Err(eliot_protocol::reactive_context::ReactiveContextError::UnsupportedStage)
    ));
    Ok(())
}

fn payload(sequence: u64, predecessors: Vec<String>) -> ReactiveContextPayload {
    let fence = fence();
    let contract = reactive_context_contract_identity().expect("contract");
    let mut representation = content("representation");
    representation.byte_length = Some(16);
    ReactiveContextPayload {
        contract,
        operation_id: OperationId::new("operation-1").expect("operation"),
        request_id: RequestId::new("request-1").expect("request"),
        idempotency_key: "idempotency-1".to_owned(),
        task_id: TaskId::new("task-1").expect("task"),
        attempt_id: AgentAttemptId::new("attempt-1").expect("attempt"),
        producer_generation: ResourceGeneration::new(1).expect("generation"),
        work_scope: WorkScopeBinding {
            scope_id: WorkScopeId::new("scope-1").expect("scope"),
            product_id: ProductId::new("product-1").expect("product"),
            resource_generation: ResourceGeneration::new(1).expect("generation"),
            state_fence: fence.clone(),
        },
        planner: eliot_protocol::reactive_context::ReactiveContextPlannerBinding {
            request: content("planner-request"),
            decision: content("planner-decision"),
            receipt: content("planner-receipt"),
        },
        recipient: ReactiveContextRecipient {
            session_id: SessionId::new("session-1").expect("session"),
            runtime_id: "runtime-1".to_owned(),
            runtime_generation: ResourceGeneration::new(1).expect("generation"),
            route: "route-1".to_owned(),
        },
        view: ReactiveContextViewBinding {
            view_id: ArtifactId::new("view-1").expect("view"),
            view_generation: ResourceGeneration::new(1).expect("generation"),
            admitted_set: content("admitted-set"),
            recipe: content("recipe"),
            assembly_receipt: content("assembly"),
            representation,
            measurement: eliot_protocol::reactive_context::ReactiveContextMeasurement {
                serializer: content("serializer"),
                tokenizer: content("tokenizer"),
                serialized_byte_length: 16,
                token_count: Some(4),
            },
        },
        safety_floor: ReactiveContextSafetyFloor {
            owner: content("safety-floor"),
            privacy: ReactiveContextPrivacy::Internal,
            disclosure_closure: content("disclosure"),
            proof_ceiling: ProofCeiling::Observation,
        },
        sequence: ReactiveContextSequence {
            stream_id: "reactive-context/stream-1".to_owned(),
            sequence,
            predecessor_event_ids: predecessors,
            cursor: sequence,
        },
        acknowledgement_deadline_unix_ms: 100,
        cancellation_id: "cancel-1".to_owned(),
        expires_at_unix_ms: Some(200),
        validity: eliot_protocol::reactive_context::ReactiveContextValidity::Current,
    }
}

fn content(name: &str) -> ReactiveContextContentRef {
    ReactiveContextContentRef {
        contract: ContractIdentity {
            name: ContractId::new(format!("owner.{name}")).expect("owner"),
            version: ContractVersion::new(1, 0, 0),
            shape_sha256: "0".repeat(64),
        },
        source_revision: "rev-1".to_owned(),
        content_sha256: "1".repeat(64),
        byte_length: Some(1),
        artifact_id: Some(ArtifactId::new(format!("artifact-{name}")).expect("artifact")),
    }
}

fn evidence(
    payload: &ReactiveContextPayload,
    receipt: EventAckReceipt,
    phase: AckPhase,
) -> Result<ReactiveContextAckEvidence, Box<dyn Error>> {
    Ok(ReactiveContextAckEvidence {
        receipt,
        operation_id: payload.operation_id.clone(),
        task_id: payload.task_id.clone(),
        attempt_id: payload.attempt_id.clone(),
        session_id: payload.recipient.session_id.clone(),
        runtime_id: payload.recipient.runtime_id.clone(),
        runtime_generation: payload.recipient.runtime_generation,
        route: payload.recipient.route.clone(),
        work_scope: payload.work_scope.clone(),
        state_fence: payload.work_scope.state_fence.clone(),
        view_id: payload.view.view_id.clone(),
        view_generation: payload.view.view_generation,
        payload_sha256: payload.payload_sha256()?,
        expected_phase: phase,
        observed_phase: phase,
        owner_ref: content("ack-owner"),
        issuer_ref: content("ack-issuer"),
        receive_sequence: payload.sequence.sequence,
        receive_cursor: payload.sequence.cursor,
        observed_at_unix_ms: 50,
        freshness_ref: Some(content("freshness")),
        disposition: match phase {
            AckPhase::Rejected => ReactiveContextAckDisposition::Rejected,
            AckPhase::Unknown => ReactiveContextAckDisposition::Unknown,
            _ => ReactiveContextAckDisposition::Accepted,
        },
        proof_sha256: "2".repeat(64),
        lifecycle: lifecycle_for(phase),
    })
}

fn lifecycle_for(phase: AckPhase) -> ReactiveContextLifecycleEvidence {
    let (stage, predecessor, needs_receipt) = match phase {
        AckPhase::Received => (ReactiveContextStage::RecipientReceived, None, false),
        AckPhase::Durable => (
            ReactiveContextStage::RecipientDurable,
            Some(ReactiveContextStage::RecipientReceived),
            false,
        ),
        AckPhase::Normalized => (
            ReactiveContextStage::NormalizedProjection,
            Some(ReactiveContextStage::RecipientDurable),
            false,
        ),
        AckPhase::Applied => (
            ReactiveContextStage::AppliedProjection,
            Some(ReactiveContextStage::NormalizedProjection),
            true,
        ),
        AckPhase::Rejected => (ReactiveContextStage::AcknowledgementRejected, None, false),
        AckPhase::Unknown => (ReactiveContextStage::AcknowledgementUnknown, None, false),
    };
    ReactiveContextLifecycleEvidence {
        stage,
        predecessor,
        owner_receipt: needs_receipt.then(|| content("projection-receipt")),
    }
}

fn generic_receipt(
    payload: &ReactiveContextPayload,
    envelope: &eliot_protocol::EventEnvelope,
    phase: AckPhase,
    receipt_sequence: u64,
    parent_receipt_id: Option<eliot_contracts::ReceiptId>,
) -> Result<EventAckReceipt, Box<dyn Error>> {
    let fence = payload.work_scope.state_fence.clone();
    let request_id = RequestId::new("request-1")?;
    let core = ReceiptCore {
        contract: eliot_receipts::contract_identity()?,
        kind: ReceiptKind::Coordination,
        work_scope: payload.work_scope.clone(),
        task: Some(TaskBinding {
            task_id: payload.task_id.clone(),
            task_revision: eliot_contracts::TaskRevision::genesis(),
            state_fence: fence.clone(),
        }),
        session: Some(SessionBinding {
            session_id: payload.recipient.session_id.clone(),
            authority_epoch: fence.authority_epoch,
            state_fence: fence.clone(),
        }),
        causal: CausalBinding {
            state_fence: fence.clone(),
            transaction_sequence: TransactionSequence::new(receipt_sequence)?,
            parent_receipt_id: parent_receipt_id.clone(),
            predecessor_receipt_ids: parent_receipt_id.into_iter().collect(),
        },
        request: RequestBinding {
            metadata: eliot_contracts::RequestMetadata {
                request_id: request_id.clone(),
                session_id: Some(payload.recipient.session_id.clone()),
                task_id: Some(payload.task_id.clone()),
                product_id: payload.work_scope.product_id.clone(),
                source_id: SourceId::new("source-1")?,
                state_fence: fence.clone(),
                clock: ClockReading::default(),
            },
            state_fence: fence.clone(),
        },
        operation: OperationBinding {
            operation_id: payload.operation_id.clone(),
            request_id,
            idempotency_key: payload.idempotency_key.clone(),
            operation_kind: "reactive-context".to_owned(),
            effect: EffectClass::Read,
            state_fence: fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: ContractId::new("recipient-authority")?,
            authority_owner: "recipient".to_owned(),
            authority_epoch: fence.authority_epoch,
            state_fence: fence.clone(),
            allowed_effect: EffectClass::Read,
            proof_ceiling: ProofCeiling::Observation,
        },
        artifacts: vec![ArtifactBinding {
            artifact_id: ArtifactId::new("ack-proof")?,
            sha256: payload.payload_sha256()?,
            role: ReceiptKind::Artifact,
            source_revision: Some("rev-1".to_owned()),
        }],
        verifier: None,
        problem: None,
        coordination: Some(CoordinationBinding {
            event_id: ContractId::new(&envelope.event_id)?,
            idempotency_key: payload.idempotency_key.clone(),
            state_fence: fence.clone(),
        }),
        disposition: ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
    };
    Ok(EventAckReceipt {
        stream_id: envelope.stream_id.clone(),
        event_id: envelope.event_id.clone(),
        phase,
        disposition: match phase {
            AckPhase::Rejected => EventDisposition::Rejected,
            _ => EventDisposition::Accepted,
        },
        state_fence: fence,
        receipt: ReceiptEnvelope::issue(core)?,
    })
}

fn fence() -> StateFence {
    StateFence::new(
        AuthorityEpoch::genesis(),
        ResourceGeneration::new(1).expect("generation"),
    )
}
