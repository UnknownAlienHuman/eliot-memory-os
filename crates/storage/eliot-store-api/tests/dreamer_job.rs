#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractIdentity, ContractVersion, EpochId,
    EpochLineageId, OperationId, ProductId, ReceiptId, RequestId, ResourceGeneration, SourceId,
    StateFence, TaskId,
};
use eliot_protocol::{
    AdmissionRef, DurableJobRequest, DurableJobResponse, DurableRequestIdentity, JobOperation,
    JobOperationKind, JobRole, JobState, LeaseSelector, MutationDisposition, OpaqueContentRef,
    RequestIdentity,
};
use eliot_receipts::{
    AuthorityBinding, EffectClass, OperationBinding, ProofCeiling, RequestBinding,
};
use eliot_receipts::{WorkScopeBinding, WorkScopeId};
use eliot_store_api::{
    CAPABILITIES, CAPABILITY_DREAMER_JOB_LEASE_EXACT, CAPABILITY_DREAMER_JOB_STATUS,
    CAPABILITY_DREAMER_JOB_SUBMIT, DreamerJobLedgerEvent, DreamerJobLedgerRecord,
    DreamerJobMutationIdentity, StoreRequest, StoreResponse, decode_request_frame,
    decode_response_frame, dreamer_job_capability, dreamer_job_queue_key, request_frame,
    response_frame, validate_ledger_bundle,
};

const CONNECTION_ID: &str = "connection-dreamer-s0";

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

fn scope() -> WorkScopeBinding {
    WorkScopeBinding {
        scope_id: WorkScopeId::new("scope").expect("scope"),
        product_id: ProductId::new("product").expect("product"),
        resource_generation: ResourceGeneration::genesis(),
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
    let binding = OperationBinding {
        operation_id: OperationId::new(operation_id).expect("operation"),
        request_id: RequestId::new("originating-request").expect("request"),
        idempotency_key: idempotency.to_owned(),
        operation_kind: operation.kind().as_str().to_owned(),
        effect: EffectClass::Candidate,
        state_fence: fence.clone(),
    };
    let request_identity = RequestIdentity {
        request,
        idempotency_key: "transport-request".to_owned(),
        deadline_unix_ms: 100,
        cancellation_id: "cancel".to_owned(),
    };
    let hash = DurableRequestIdentity::digest_for(&binding, &request_identity, operation, role)
        .expect("digest");
    DurableRequestIdentity {
        request: request_identity,
        operation: binding,
        canonical_request_hash: hash,
    }
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

fn base_response(request: &DurableJobRequest, bound_scope: WorkScopeBinding) -> DurableJobResponse {
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

fn mutation_identity(request: &DurableJobRequest) -> DreamerJobMutationIdentity {
    DreamerJobMutationIdentity {
        operation_id: request.request_identity.operation.operation_id.clone(),
        idempotency_key: request.request_identity.operation.idempotency_key.clone(),
        canonical_request_hash: request.request_identity.canonical_request_hash.clone(),
        operation_kind: request.operation.kind().as_str().to_owned(),
    }
}

fn ledger_record_for(
    request: &DurableJobRequest,
    response: &DurableJobResponse,
    record_state: eliot_protocol::DurableJobRecord,
) -> DreamerJobLedgerRecord {
    let queue_key = dreamer_job_queue_key(
        &record_state.submission.job_id,
        &record_state.submission.attempt_id,
    );
    let placeholder = DreamerJobLedgerRecord {
        record: record_state,
        event_cursor: 1,
        queue_key,
        active_lease: response.lease.clone(),
        lease_history: Vec::new(),
        result_under_verification: response.result_under_verification.clone(),
        last_mutation: mutation_identity(request),
        last_receipt_id: response.receipt_id.clone(),
        record_digest: "0".repeat(64),
    };
    let digest = placeholder.compute_digest().expect("record digest");
    DreamerJobLedgerRecord {
        record_digest: digest,
        ..placeholder
    }
}

fn ledger_event_for(
    request: &DurableJobRequest,
    response: &DurableJobResponse,
    prior_state: JobState,
    prior_revision: u64,
) -> DreamerJobLedgerEvent {
    let placeholder = DreamerJobLedgerEvent {
        job_id: response.job_id.clone(),
        attempt_id: response.attempt_id.clone(),
        prior_state,
        next_state: response.state,
        prior_revision,
        next_revision: response.revision,
        event_cursor: 1,
        operation: request.operation.clone(),
        role: request.role,
        lease: response.lease.clone(),
        checkpoint: response.checkpoint.clone(),
        result_under_verification: response.result_under_verification.clone(),
        mutation: mutation_identity(request),
        receipt_id: response.receipt_id.clone(),
        event_digest: "0".repeat(64),
    };
    let digest = placeholder.compute_digest().expect("event digest");
    DreamerJobLedgerEvent {
        event_digest: digest,
        ..placeholder
    }
}

fn submit_bundle() -> (
    DurableJobRequest,
    DurableJobResponse,
    DreamerJobLedgerRecord,
    DreamerJobLedgerEvent,
) {
    let operation = JobOperation::Submit {
        submission: Box::new(submission()),
    };
    let request = exchange_request(
        operation,
        "operation-t12-submit",
        "stable-t12-submit",
        JobRole::Requester,
    );
    let mut response = base_response(&request, scope());
    response.disposition = Some(MutationDisposition::Committed);
    response.receipt_id = Some(ReceiptId::new("submit-receipt").expect("receipt"));
    let response = round_trip(&response);
    let record_state = eliot_protocol::DurableJobRecord {
        submission: submission(),
        state: JobState::Queued,
        revision: 1,
        lease: None,
        checkpoint: None,
        cancellation: eliot_protocol::CancellationState::None,
        outcome: None,
    };
    let record = ledger_record_for(&request, &response, record_state);
    let event = ledger_event_for(&request, &response, JobState::NotStarted, 0);
    (request, response, record, event)
}

fn status_bundle() -> (
    DurableJobRequest,
    DurableJobResponse,
    DreamerJobLedgerRecord,
    DreamerJobLedgerEvent,
) {
    let operation = JobOperation::Status {
        job_id: TaskId::new("job").expect("job"),
        attempt_id: ArtifactId::new("attempt").expect("attempt"),
        expected_revision: 1,
        expected_fence: fence(),
    };
    let request = exchange_request(
        operation,
        "operation-t12-status",
        "stable-t12-status",
        JobRole::Requester,
    );
    let mut response = base_response(&request, scope());
    response.state = JobState::Leased;
    response.lease = Some(lease());
    let response = round_trip(&response);
    let record_state = eliot_protocol::DurableJobRecord {
        submission: submission(),
        state: JobState::Leased,
        revision: 1,
        lease: Some(lease()),
        checkpoint: None,
        cancellation: eliot_protocol::CancellationState::None,
        outcome: None,
    };
    // Status observes the leased record: the ledger record retains the last
    // committed receipt and active lease while the observation event itself
    // advances neither state nor revision and carries no receipt.
    let queue_key = dreamer_job_queue_key(
        &record_state.submission.job_id,
        &record_state.submission.attempt_id,
    );
    let placeholder_record = DreamerJobLedgerRecord {
        record: record_state,
        event_cursor: 1,
        queue_key,
        active_lease: Some(lease()),
        lease_history: Vec::new(),
        result_under_verification: None,
        last_mutation: mutation_identity(&request),
        last_receipt_id: Some(ReceiptId::new("lease-receipt").expect("receipt")),
        record_digest: "0".repeat(64),
    };
    let record = DreamerJobLedgerRecord {
        record_digest: placeholder_record
            .compute_digest()
            .expect("status record digest"),
        ..placeholder_record
    };
    // The observation event mirrors the leased state without advancing it.
    let placeholder_event = DreamerJobLedgerEvent {
        job_id: response.job_id.clone(),
        attempt_id: response.attempt_id.clone(),
        prior_state: JobState::Leased,
        next_state: JobState::Leased,
        prior_revision: 1,
        next_revision: 1,
        event_cursor: 1,
        operation: request.operation.clone(),
        role: request.role,
        lease: None,
        checkpoint: None,
        result_under_verification: None,
        mutation: mutation_identity(&request),
        receipt_id: None,
        event_digest: "0".repeat(64),
    };
    let event_digest = placeholder_event
        .compute_digest()
        .expect("status event digest");
    let event = DreamerJobLedgerEvent {
        event_digest,
        ..placeholder_event
    };
    (request, response, record, event)
}

fn store_context_for(request: &DurableJobRequest) -> eliot_store_api::RequestMeta {
    request.request_identity.request.request.metadata.clone()
}

fn outer_identity_for(request: &DurableJobRequest) -> RequestIdentity {
    request.request_identity.request.clone()
}

#[test]
fn dreamer_named_request_decodes_and_response_validates_for_request() {
    let (request, response, record, event) = submit_bundle();
    let context = store_context_for(&request);
    let outer = outer_identity_for(&request);
    let wire_request = StoreRequest::DreamerJob {
        context: context.clone(),
        request: request.clone(),
    };
    wire_request.validate().expect("dreamer request validates");
    assert_eq!(wire_request.capability(), CAPABILITY_DREAMER_JOB_SUBMIT);
    assert_eq!(
        dreamer_job_capability(&request.operation),
        CAPABILITY_DREAMER_JOB_SUBMIT
    );

    // Closed JSON denies unknown fields; the named request round-trips.
    let wire_value = serde_json::to_value(&wire_request).expect("encode request");
    let decoded_request: StoreRequest = serde_json::from_value(wire_value).expect("decode request");
    decoded_request
        .validate()
        .expect("decoded request validates");

    // Authenticated frame binds context and K0 correlation together.
    let frame = request_frame(
        CONNECTION_ID,
        eliot_protocol::ProtocolVersion::CURRENT,
        context.request_id.clone(),
        outer,
        wire_request,
    )
    .expect("dreamer frame builds");
    let (_, _, decoded_frame_request) =
        decode_request_frame(&frame).expect("dreamer frame decodes");
    decoded_frame_request
        .validate()
        .expect("frame request validates");

    // Returned record/event/receipt consistency validates as one bundle.
    response
        .validate_for(&request)
        .expect("response answers request");
    validate_ledger_bundle(&request, &response, &record, &event).expect("ledger bundle");

    // The response also flows through the closed wire envelope.
    let wire_response = StoreResponse::DreamerJob {
        response: response.clone(),
    };
    wire_response
        .validate()
        .expect("dreamer response validates");
    let response_frame = response_frame(
        CONNECTION_ID,
        eliot_protocol::ProtocolVersion::CURRENT,
        Some(context.request_id.clone()),
        wire_response,
    )
    .expect("response frame builds");
    let (_, decoded_response) = decode_response_frame(
        &response_frame,
        CONNECTION_ID,
        eliot_protocol::ProtocolVersion::CURRENT,
    )
    .expect("response frame decodes");
    let StoreResponse::DreamerJob { response: decoded } = decoded_response else {
        panic!("dreamer response round-trips");
    };
    decoded.validate_for(&request).expect("decoded response");
}

#[test]
fn changed_content_under_same_identity_fails() {
    let (request, matching, record, event) = status_bundle();
    matching
        .validate_for(&request)
        .expect("matching response validates");
    validate_ledger_bundle(&request, &matching, &record, &event).expect("matching bundle");

    // Same stable identity with a changed revision fails.
    let mut changed_revision = matching.clone();
    changed_revision.revision = 2;
    assert!(changed_revision.validate_for(&request).is_err());
    assert!(validate_ledger_bundle(&request, &changed_revision, &record, &event).is_err());

    // Same stable identity with a changed job fails.
    let mut changed_job = matching;
    changed_job.job_id = TaskId::new("other-job").expect("job");
    assert!(changed_job.validate_for(&request).is_err());
}

#[test]
fn exact_response_replay_validates() {
    let (request, response, record, event) = status_bundle();
    response
        .validate_for(&request)
        .expect("first validation passes");
    let wire = serde_json::to_string(&response).expect("encode");
    let replayed: DurableJobResponse = serde_json::from_str(&wire).expect("decode");
    assert_eq!(replayed, response);
    replayed
        .validate_for(&request)
        .expect("exact replay validates");
    validate_ledger_bundle(&request, &replayed, &record, &event).expect("replay bundle");

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

#[test]
fn status_response_has_no_disposition() {
    let (status_request, status_response, _, _) = status_bundle();
    assert!(status_response.disposition.is_none());
    assert!(status_response.receipt_id.is_none());
    assert_eq!(
        StoreRequest::DreamerJob {
            context: store_context_for(&status_request),
            request: status_request.clone(),
        }
        .capability(),
        CAPABILITY_DREAMER_JOB_STATUS
    );

    let (submit_request, submit_response, _, _) = submit_bundle();
    assert_eq!(
        submit_response.disposition,
        Some(MutationDisposition::Committed)
    );
    assert!(submit_response.receipt_id.is_some());
    assert_eq!(
        StoreRequest::DreamerJob {
            context: store_context_for(&submit_request),
            request: submit_request.clone(),
        }
        .capability(),
        CAPABILITY_DREAMER_JOB_SUBMIT
    );

    // LeaseExact carries its own per-operation capability, distinct from
    // Submit and Status.
    let lease_operation = JobOperation::LeaseExact {
        selector: LeaseSelector {
            scope_id: scope().scope_id.clone(),
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
    assert_eq!(
        dreamer_job_capability(&lease_request.operation),
        CAPABILITY_DREAMER_JOB_LEASE_EXACT
    );
}

#[test]
fn dreamer_capabilities_are_per_operation_and_closed() {
    for (operation, expected) in [
        (
            JobOperation::Submit {
                submission: Box::new(submission()),
            },
            CAPABILITY_DREAMER_JOB_SUBMIT,
        ),
        (
            JobOperation::LeaseNext {
                selector: LeaseSelector {
                    scope_id: scope().scope_id.clone(),
                    expected_revision: 1,
                    expected_fence: fence(),
                    worker_artifact_id: ArtifactId::new("worker").expect("worker"),
                    max_candidates: 8,
                },
            },
            eliot_store_api::CAPABILITY_DREAMER_JOB_LEASE_NEXT,
        ),
        (
            JobOperation::Status {
                job_id: TaskId::new("job").expect("job"),
                attempt_id: ArtifactId::new("attempt").expect("attempt"),
                expected_revision: 1,
                expected_fence: fence(),
            },
            CAPABILITY_DREAMER_JOB_STATUS,
        ),
    ] {
        assert_eq!(dreamer_job_capability(&operation), expected);
        assert!(CAPABILITIES.contains(&expected), "capability is advertised");
    }
    assert_eq!(
        JobOperationKind::Submit.as_str(),
        "SUBMIT_JOB",
        "closed kind vocabulary"
    );

    // Unknown operation kinds never validate as ledger mutation identity.
    let (request, _, _, _) = submit_bundle();
    let mut unknown = mutation_identity(&request);
    unknown.operation_kind = "GENERIC_PATCH".to_owned();
    assert!(unknown.validate().is_err());
}
