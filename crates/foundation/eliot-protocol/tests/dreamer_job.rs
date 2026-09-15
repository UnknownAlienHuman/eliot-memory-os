#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractIdentity, ContractVersion, EpochId,
    EpochLineageId, OperationId, ProductId, ReceiptId, RequestId, ResourceGeneration, SourceId,
    StateFence, TaskId,
};
use eliot_protocol::{
    AdmissionRef, CancellationState, DurableJobRecord, DurableJobRequest, DurableJobResponse,
    DurableRequestIdentity, JobOperation, JobOperationKind, JobRole, JobState, LeaseSelector,
    MutationDisposition, MutationReconciliation, OpaqueContentRef, RequestIdentity,
};
use eliot_receipts::{
    AuthorityBinding, EffectClass, OperationBinding, ProofCeiling, RequestBinding,
    WorkScopeBinding, WorkScopeId,
};

#[test]
fn admitted_submission_round_trips_and_validates() {
    let operation = JobOperation::Submit {
        submission: Box::new(submission()),
    };
    let request = DurableJobRequest {
        request_identity: identity(&operation, "operation-1", "stable-submit"),
        role: JobRole::Requester,
        operation,
    };
    request.validate().expect("admitted submission");
    let wire = serde_json::to_string(&request).expect("serialize");
    let decoded: DurableJobRequest = serde_json::from_str(&wire).expect("deserialize");
    decoded.validate().expect("round-trip validation");
}

#[test]
fn retry_commitment_rejects_payload_change() {
    let operation = JobOperation::Submit {
        submission: Box::new(submission()),
    };
    let identity = identity(&operation, "operation-2", "stable-retry");
    let mut fresh_retry = identity.clone();
    fresh_retry.request.request.metadata.request_id =
        RequestId::new("fresh-retry").expect("request");
    DurableJobRequest {
        request_identity: fresh_retry,
        role: JobRole::Requester,
        operation: operation.clone(),
    }
    .validate()
    .expect("fresh transport retry keeps commitment");

    let mut changed_context = identity.clone();
    changed_context.request.request.metadata.product_id =
        ProductId::new("different-product").expect("product");
    assert!(
        DurableJobRequest {
            request_identity: changed_context,
            role: JobRole::Requester,
            operation: operation.clone(),
        }
        .validate()
        .is_err()
    );

    let mut changed_effect = identity.clone();
    changed_effect.operation.effect = EffectClass::ExternalEffect;
    assert!(
        DurableJobRequest {
            request_identity: changed_effect,
            role: JobRole::Requester,
            operation: operation.clone(),
        }
        .validate()
        .is_err()
    );

    let mut changed = submission();
    changed.cancellation_id = "different-cancellation".to_owned();
    let retry = DurableJobRequest {
        request_identity: identity,
        role: JobRole::Requester,
        operation: JobOperation::Submit {
            submission: Box::new(changed),
        },
    };
    assert!(retry.validate().is_err());
}

#[test]
fn record_preserves_cancellation_and_terminal_immutability() {
    assert!(!JobState::Running.can_transition_to(JobState::Verifying));
    let mut record = DurableJobRecord {
        submission: submission(),
        state: JobState::Running,
        revision: 1,
        lease: Some(lease()),
        checkpoint: Some(checkpoint()),
        cancellation: CancellationState::None,
        outcome: None,
    };
    record.validate().expect("coherent active record");
    let mut wrong_attempt = record.clone();
    wrong_attempt.lease.as_mut().expect("lease").attempt_id =
        ArtifactId::new("other-attempt").expect("attempt");
    assert!(wrong_attempt.validate().is_err());
    record
        .request_cancel(
            "requester".to_owned(),
            "user requested stop".to_owned(),
            OperationId::new("cancel-op").expect("operation"),
            10,
        )
        .expect("cancel intent");
    assert_eq!(record.state, JobState::Running);
    record
        .transition(JobState::Checkpointed)
        .expect("checkpoint");
    record.transition(JobState::Verifying).expect("verify");
    assert!(record.transition(JobState::Running).is_err());
}

#[test]
fn active_lease_binds_checkpoint_to_same_fence() {
    let fence = fence();
    let lease: eliot_protocol::JobLease = serde_json::from_value(serde_json::json!({
        "job_id": "job",
        "attempt_id": "attempt",
        "lease_id": {
            "namespace": "eliot.governor.work-lease",
            "revision": "v1",
            "value": "lease-1"
        },
        "owner_artifact_id": "worker",
        "resource_generation": 1,
        "state_fence": fence,
        "issued_at_unix_ms": 10,
        "expires_at_unix_ms": 100,
        "revision": 1
    }))
    .expect("lease");
    let checkpoint = eliot_protocol::JobCheckpoint {
        checkpoint_id: ArtifactId::new("artifact-checkpoint").expect("checkpoint"),
        reference: content_ref("checkpoint"),
        completed_phases: vec!["phase-1".to_owned()],
        remaining_phases: vec!["phase-2".to_owned()],
        budget_remaining: 1,
        possible_effects: Vec::new(),
        state_fence: fence.clone(),
    };
    let operation = JobOperation::Checkpoint {
        lease,
        checkpoint: Box::new(checkpoint),
        now_unix_ms: 50,
    };
    operation.validate().expect("lease-bound checkpoint");
}

#[test]
fn semantic_unknown_reconciliation_carries_original_operation() {
    let operation = OperationBinding {
        operation_id: OperationId::new("operation-4").expect("operation"),
        request_id: RequestId::new("originating-request").expect("request"),
        idempotency_key: "stable-reconcile".to_owned(),
        operation_kind: JobOperationKind::Publish.as_str().to_owned(),
        effect: EffectClass::Candidate,
        state_fence: fence(),
    };
    let reconciliation = MutationReconciliation {
        job_id: TaskId::new("job").expect("job"),
        attempt_id: ArtifactId::new("attempt").expect("attempt"),
        operation,
        canonical_request_hash: "0".repeat(64),
        disposition: MutationDisposition::Committed,
        committed_state: Some(JobState::UnknownOutcome),
        receipt_id: Some(ReceiptId::new("commit-receipt").expect("receipt")),
        evidence: vec![artifact("unknown-evidence")],
    };
    reconciliation.validate().expect("unknown reconciliation");
    let mut uncommitted = reconciliation.clone();
    uncommitted.disposition = MutationDisposition::ProvenNotApplied;
    uncommitted.evidence.clear();
    assert!(uncommitted.validate().is_err());
    let mut request_identity = identity(
        &JobOperation::Submit {
            submission: Box::new(submission()),
        },
        "operation-5",
        "stable-reconcile",
    );
    request_identity.operation = reconciliation.operation.clone();
    request_identity.canonical_request_hash = reconciliation.canonical_request_hash.clone();
    DurableJobRequest {
        request_identity,
        role: JobRole::Controller,
        operation: JobOperation::Reconcile {
            mutation: Box::new(reconciliation.clone()),
        },
    }
    .validate()
    .expect("reconcile preserves original identity");
    let record = DurableJobRecord {
        submission: submission(),
        state: JobState::UnknownOutcome,
        revision: 2,
        lease: None,
        checkpoint: None,
        cancellation: CancellationState::None,
        outcome: Some(eliot_protocol::JobOutcome {
            state: JobState::UnknownOutcome,
            result: None,
            evidence: vec![artifact("unknown-evidence")],
            verifier: None,
            proof_ceiling: ProofCeiling::CandidateArtifact,
            abstention_reason: Some("semantic outcome remains unresolved".to_owned()),
            unresolved: vec!["store commit classification".to_owned()],
        }),
    };
    record.validate().expect("terminal unknown record");
    assert!(JobState::UnknownOutcome.is_terminal());
}

#[test]
fn submit_lease_status_exchange_validates_response() {
    let bound_scope = scope();
    // Submit (Requester) → QUEUED record at revision 1.
    let submit_operation = JobOperation::Submit {
        submission: Box::new(submission()),
    };
    let submit_request = exchange_request(
        submit_operation,
        "operation-t12-submit",
        "stable-t12-submit",
        JobRole::Requester,
    );
    let mut submit_response = base_response(&submit_request, bound_scope.clone());
    submit_response.disposition = Some(MutationDisposition::Committed);
    submit_response.receipt_id = Some(ReceiptId::new("submit-receipt").expect("receipt"));
    round_trip(&submit_response)
        .validate_for(&submit_request)
        .expect("submit response");

    // LeaseExact (Worker) → LEASED at the selected revision.
    let lease_operation = JobOperation::LeaseExact {
        selector: LeaseSelector {
            scope_id: bound_scope.scope_id.clone(),
            expected_revision: 1,
            expected_fence: fence(),
            worker_artifact_id: ArtifactId::new("worker").expect("worker"),
            max_candidates: 8,
        },
        job_id: TaskId::new("job").expect("job"),
    };
    let lease_request = exchange_request(
        lease_operation,
        "operation-t12-lease",
        "stable-t12-lease",
        JobRole::Worker,
    );
    let mut lease_response = base_response(&lease_request, bound_scope.clone());
    lease_response.state = JobState::Leased;
    lease_response.disposition = Some(MutationDisposition::Committed);
    lease_response.receipt_id = Some(ReceiptId::new("lease-receipt").expect("receipt"));
    lease_response.lease = Some(lease());
    round_trip(&lease_response)
        .validate_for(&lease_request)
        .expect("lease response");

    // Status (Requester) → pure observation, no mutation disposition.
    let status_operation = JobOperation::Status {
        job_id: TaskId::new("job").expect("job"),
        attempt_id: ArtifactId::new("attempt").expect("attempt"),
        expected_revision: 1,
        expected_fence: fence(),
    };
    let status_request = exchange_request(
        status_operation,
        "operation-t12-status",
        "stable-t12-status",
        JobRole::Requester,
    );
    let mut status_response = base_response(&status_request, bound_scope);
    status_response.state = JobState::Leased;
    status_response.lease = Some(lease());
    round_trip(&status_response)
        .validate_for(&status_request)
        .expect("status response");
}

#[test]
fn response_with_same_identity_but_changed_content_fails() {
    let (request, matching) = status_exchange();
    matching
        .validate_for(&request)
        .expect("matching response validates");
    let mut changed_revision = matching.clone();
    changed_revision.revision = 2;
    assert!(changed_revision.validate_for(&request).is_err());
    let mut changed_job = matching;
    changed_job.job_id = TaskId::new("other-job").expect("job");
    assert!(changed_job.validate_for(&request).is_err());
}

#[test]
fn exact_response_replay_validates() {
    let (request, response) = status_exchange();
    response
        .validate_for(&request)
        .expect("first validation passes");
    let wire = serde_json::to_string(&response).expect("encode");
    let replayed: DurableJobResponse = serde_json::from_str(&wire).expect("decode");
    assert_eq!(replayed, response);
    replayed
        .validate_for(&request)
        .expect("exact replay validates");

    // A fresh transport retry carries new correlation, so the old response
    // does not apply to it even though the stable commitment is unchanged.
    let mut retry_identity = request.request_identity.clone();
    retry_identity.request.request.metadata.request_id =
        RequestId::new("fresh-retry").expect("request");
    let retry = DurableJobRequest {
        request_identity: retry_identity,
        role: JobRole::Requester,
        operation: request.operation.clone(),
    };
    retry.validate().expect("retry keeps commitment");
    assert!(response.validate_for(&retry).is_err());
}

fn status_exchange() -> (DurableJobRequest, DurableJobResponse) {
    let operation = JobOperation::Status {
        job_id: TaskId::new("job").expect("job"),
        attempt_id: ArtifactId::new("attempt").expect("attempt"),
        expected_revision: 1,
        expected_fence: fence(),
    };
    let request = exchange_request(
        operation,
        "operation-t12-replay",
        "stable-t12-replay",
        JobRole::Requester,
    );
    let mut response = base_response(&request, scope());
    response.state = JobState::Leased;
    response.lease = Some(lease());
    (request, round_trip(&response))
}

fn exchange_request(
    operation: JobOperation,
    operation_id: &str,
    idempotency: &str,
    role: JobRole,
) -> DurableJobRequest {
    let request = DurableJobRequest {
        request_identity: identity_as(&operation, operation_id, idempotency, role),
        role,
        operation,
    };
    request.validate().expect("exchange request");
    round_trip(&request)
}

fn base_response(
    request: &DurableJobRequest,
    bound_scope: WorkScopeBinding,
) -> DurableJobResponse {
    DurableJobResponse {
        request_identity: request.request_identity.clone(),
        job_id: TaskId::new("job").expect("job"),
        attempt_id: ArtifactId::new("attempt").expect("attempt"),
        scope: bound_scope,
        revision: 1,
        state: JobState::Queued,
        disposition: None,
        receipt_id: None,
        lease: None,
        checkpoint: None,
        result_under_verification: None,
        outcome: None,
        selection_coverage: Vec::new(),
        selection_frontier: None,
    }
}

fn round_trip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    serde_json::from_str(&serde_json::to_string(value).expect("encode")).expect("decode")
}

fn submission() -> eliot_protocol::JobSubmission {
    let scope = scope();
    eliot_protocol::JobSubmission {
        job_id: TaskId::new("job").expect("job"),
        attempt_id: ArtifactId::new("attempt").expect("attempt"),
        work_scope: scope.clone(),
        semantic_input: content_ref("input"),
        output_contract: content_ref("output"),
        admission: AdmissionRef {
            authority: AuthorityBinding {
                authority_id: ContractId::new("kernel").expect("authority"),
                authority_owner: "kernel".to_owned(),
                authority_epoch: test_epoch(),
                state_fence: fence(),
                allowed_effect: EffectClass::Candidate,
                proof_ceiling: ProofCeiling::CandidateArtifact,
            },
            requester_principal: "requester".to_owned(),
            session: None,
            scope,
            capability: "dreamer.submit".to_owned(),
            route_class: "bounded".to_owned(),
            budget_units: 1,
            deadline_unix_ms: 100,
            validity_epoch: test_epoch(),
            resource_generation: ResourceGeneration::genesis(),
            admission_receipt: ReceiptId::new("admission-receipt").expect("receipt"),
        },
        cancellation_id: "cancel".to_owned(),
    }
}

fn identity(
    operation: &JobOperation,
    operation_id: &str,
    idempotency: &str,
) -> DurableRequestIdentity {
    identity_as(operation, operation_id, idempotency, JobRole::Requester)
}

fn identity_as(
    operation: &JobOperation,
    operation_id: &str,
    idempotency: &str,
    role: JobRole,
) -> DurableRequestIdentity {
    let fence = fence();
    let request_id = RequestId::new("fresh-request").expect("request");
    let request = RequestBinding {
        metadata: eliot_contracts::RequestMetadata {
            request_id: request_id.clone(),
            session_id: None,
            task_id: Some(TaskId::new("job").expect("task")),
            product_id: ProductId::new("product").expect("product"),
            source_id: SourceId::new("source").expect("source"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        },
        state_fence: fence.clone(),
    };
    let operation_id = OperationId::new(operation_id).expect("operation");
    let binding = OperationBinding {
        operation_id: operation_id.clone(),
        request_id: RequestId::new("originating-request").expect("request"),
        idempotency_key: idempotency.to_owned(),
        operation_kind: operation.kind().as_str().to_owned(),
        effect: EffectClass::Candidate,
        state_fence: fence.clone(),
    };
    let request = RequestIdentity {
        request,
        idempotency_key: "transport-request".to_owned(),
        deadline_unix_ms: 100,
        cancellation_id: "cancel".to_owned(),
    };
    let hash = DurableRequestIdentity::digest_for(&binding, &request, operation, role)
        .expect("digest");
    DurableRequestIdentity {
        request,
        operation: binding,
        canonical_request_hash: hash,
    }
}

fn artifact(id: &str) -> eliot_receipts::ArtifactBinding {
    eliot_receipts::ArtifactBinding {
        artifact_id: ArtifactId::new(id).expect("artifact"),
        sha256: "0".repeat(64),
        role: eliot_receipts::ReceiptKind::Artifact,
        source_revision: Some("test".to_owned()),
    }
}

fn lease() -> eliot_protocol::JobLease {
    serde_json::from_value(serde_json::json!({
        "job_id": "job",
        "attempt_id": "attempt",
        "lease_id": {
            "namespace": "eliot.governor.work-lease",
            "revision": "v1",
            "value": "lease-1"
        },
        "owner_artifact_id": "worker",
        "resource_generation": 1,
        "state_fence": fence(),
        "issued_at_unix_ms": 10,
        "expires_at_unix_ms": 100,
        "revision": 1
    }))
    .expect("lease")
}

fn checkpoint() -> eliot_protocol::JobCheckpoint {
    eliot_protocol::JobCheckpoint {
        checkpoint_id: ArtifactId::new("artifact-checkpoint").expect("checkpoint"),
        reference: content_ref("checkpoint"),
        completed_phases: vec!["phase-1".to_owned()],
        remaining_phases: vec!["phase-2".to_owned()],
        budget_remaining: 1,
        possible_effects: Vec::new(),
        state_fence: fence(),
    }
}

fn content_ref(revision: &str) -> OpaqueContentRef {
    OpaqueContentRef {
        contract: ContractIdentity {
            name: ContractId::new("eliot.smart.dreamer.contracts").expect("contract"),
            version: ContractVersion::new(1, 0, 0),
            shape_sha256: "0".repeat(64),
        },
        source_revision: revision.to_owned(),
        byte_length: 1,
        sha256: "0".repeat(64),
        artifact_id: Some(ArtifactId::new(format!("artifact-{revision}")).expect("artifact")),
    }
}

fn scope() -> WorkScopeBinding {
    WorkScopeBinding {
        scope_id: WorkScopeId::new("scope").expect("scope"),
        product_id: ProductId::new("product").expect("product"),
        resource_generation: ResourceGeneration::genesis(),
        state_fence: fence(),
    }
}

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch")
}

fn fence() -> StateFence {
    StateFence::new(test_epoch(), ResourceGeneration::genesis())
}
