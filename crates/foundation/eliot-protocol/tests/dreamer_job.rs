#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractIdentity, ContractVersion, EpochId,
    EpochLineageId, OperationId, ProductId, ReceiptId, RequestId, ResourceGeneration, SourceId,
    StateFence, TaskId,
};
use eliot_protocol::{
    AdmissionRef, CancellationState, DurableJobError, DurableJobRecord, DurableJobRequest,
    DurableJobResponse, DurableRequestIdentity, JobCapability, JobCheckpoint, JobLease,
    JobOperation, JobOperationKind, JobOutcome, JobRole, JobState, LeaseSelector,
    MutationDisposition, MutationReconciliation, OpaqueContentRef, RequestIdentity,
};
use eliot_receipts::{
    AuthorityBinding, EffectClass, OperationBinding, ProofCeiling, RequestBinding, VerifierBinding,
    WorkScopeBinding, WorkScopeId,
};

// WORK_UNIT_CASE: 769/9
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

// WORK_UNIT_CASE: 769/10
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

// WORK_UNIT_CASE: 769/19
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

// WORK_UNIT_CASE: 769/21
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

// WORK_UNIT_CASE: 769/17
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

// WORK_UNIT_CASE: 769/33
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

// WORK_UNIT_CASE: 769/29
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

// WORK_UNIT_CASE: 769/35
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
    let hash =
        DurableRequestIdentity::digest_for(&binding, &request, operation, role).expect("digest");
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

// ---------------------------------------------------------------------------
// #769 requester/worker control proof: shared helpers for WORK_UNIT_CASE
// 769/1..53. Reference histories below are explicit test-local pins over real
// contract types; they reject conflicting leases but prove no database race
// (race/commit ownership is #775).
// ---------------------------------------------------------------------------

fn fixture(name: &str) -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/dreamer-job")
        .join(name);
    let text = std::fs::read_to_string(&path).expect("fixture");
    serde_json::from_str(&text).expect("fixture json")
}

fn unchecked_request(
    operation: JobOperation,
    operation_id: &str,
    idempotency: &str,
    role: JobRole,
) -> DurableJobRequest {
    round_trip(&DurableJobRequest {
        request_identity: identity_as(&operation, operation_id, idempotency, role),
        role,
        operation,
    })
}

fn selector() -> LeaseSelector {
    LeaseSelector {
        scope_id: WorkScopeId::new("scope").expect("scope"),
        expected_revision: 1,
        expected_fence: fence(),
        worker_artifact_id: ArtifactId::new("worker").expect("worker"),
        max_candidates: 8,
    }
}

fn lease_window(issued_at_unix_ms: u64, expires_at_unix_ms: u64) -> JobLease {
    JobLease {
        issued_at_unix_ms,
        expires_at_unix_ms,
        ..lease()
    }
}

fn lease_owned(owner: &str, revision: u64) -> JobLease {
    JobLease {
        owner_artifact_id: ArtifactId::new(owner).expect("owner"),
        revision,
        ..lease()
    }
}

fn epoch_seq(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch")
}

fn epoch_other() -> EpochId {
    EpochId::new(
        EpochLineageId::new("6ba7b810-9dad-11d1-80b4-00c04fd430c8").expect("lineage"),
        std::num::NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch")
}

fn fence_seq(sequence: u64) -> StateFence {
    StateFence::new(epoch_seq(sequence), ResourceGeneration::genesis())
}

fn outcome_completed_with_result() -> JobOutcome {
    JobOutcome {
        state: JobState::Completed,
        result: Some(content_ref("output")),
        evidence: vec![artifact("result-evidence")],
        verifier: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        abstention_reason: None,
        unresolved: Vec::new(),
    }
}

fn outcome_completed_abstention() -> JobOutcome {
    JobOutcome {
        state: JobState::Completed,
        result: None,
        evidence: vec![artifact("abstention-evidence")],
        verifier: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        abstention_reason: Some("no candidate satisfies the admitted contract".to_owned()),
        unresolved: Vec::new(),
    }
}

fn outcome_partial() -> JobOutcome {
    JobOutcome {
        state: JobState::Partial,
        result: None,
        evidence: vec![artifact("partial-evidence")],
        verifier: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        abstention_reason: None,
        unresolved: vec!["phase-3".to_owned()],
    }
}

fn outcome_failed() -> JobOutcome {
    JobOutcome {
        state: JobState::Failed,
        result: None,
        evidence: vec![artifact("failure-evidence")],
        verifier: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        abstention_reason: None,
        unresolved: Vec::new(),
    }
}

fn outcome_cancelled() -> JobOutcome {
    JobOutcome {
        state: JobState::Cancelled,
        result: None,
        evidence: vec![artifact("cancellation-evidence")],
        verifier: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        abstention_reason: None,
        unresolved: Vec::new(),
    }
}

fn outcome_unknown() -> JobOutcome {
    JobOutcome {
        state: JobState::UnknownOutcome,
        result: None,
        evidence: vec![artifact("unknown-evidence")],
        verifier: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        abstention_reason: Some("semantic outcome remains unresolved".to_owned()),
        unresolved: vec!["store commit classification".to_owned()],
    }
}

fn outcome_for(state: JobState) -> JobOutcome {
    match state {
        JobState::Completed => outcome_completed_with_result(),
        JobState::Partial => outcome_partial(),
        JobState::Failed => outcome_failed(),
        JobState::Cancelled => outcome_cancelled(),
        _ => outcome_unknown(),
    }
}

fn other_terminal(state: JobState) -> JobState {
    match state {
        JobState::Completed => JobState::Failed,
        JobState::Partial => JobState::Completed,
        JobState::Failed => JobState::Cancelled,
        JobState::Cancelled => JobState::UnknownOutcome,
        _ => JobState::Completed,
    }
}

fn record_in(state: JobState) -> DurableJobRecord {
    DurableJobRecord {
        submission: submission(),
        state,
        revision: 1,
        lease: match state {
            JobState::Leased | JobState::Running | JobState::Checkpointed | JobState::Verifying => {
                Some(lease())
            }
            _ => None,
        },
        checkpoint: if state == JobState::Checkpointed {
            Some(checkpoint())
        } else {
            None
        },
        cancellation: CancellationState::None,
        outcome: if state.is_terminal() {
            Some(outcome_for(state))
        } else {
            None
        },
    }
}

fn mutation_committed_unknown() -> MutationReconciliation {
    MutationReconciliation {
        job_id: TaskId::new("job").expect("job"),
        attempt_id: ArtifactId::new("attempt").expect("attempt"),
        operation: OperationBinding {
            operation_id: OperationId::new("operation-36").expect("operation"),
            request_id: RequestId::new("originating-request").expect("request"),
            idempotency_key: "stable-36".to_owned(),
            operation_kind: JobOperationKind::Publish.as_str().to_owned(),
            effect: EffectClass::Candidate,
            state_fence: fence(),
        },
        canonical_request_hash: "a".repeat(64),
        disposition: MutationDisposition::Committed,
        committed_state: Some(JobState::UnknownOutcome),
        receipt_id: Some(ReceiptId::new("commit-receipt").expect("receipt")),
        evidence: vec![artifact("unknown-evidence")],
    }
}

fn reconcile_request(mutation: &MutationReconciliation, role: JobRole) -> DurableJobRequest {
    let mut request_identity = identity(
        &JobOperation::Submit {
            submission: Box::new(submission()),
        },
        "operation-reconcile",
        "stable-reconcile",
    );
    request_identity.operation = mutation.operation.clone();
    request_identity.canonical_request_hash = mutation.canonical_request_hash.clone();
    round_trip(&DurableJobRequest {
        request_identity,
        role,
        operation: JobOperation::Reconcile {
            mutation: Box::new(mutation.clone()),
        },
    })
}

fn checkpoint_other() -> JobCheckpoint {
    JobCheckpoint {
        checkpoint_id: ArtifactId::new("artifact-checkpoint-other").expect("checkpoint"),
        reference: OpaqueContentRef {
            artifact_id: Some(ArtifactId::new("artifact-checkpoint-other").expect("checkpoint")),
            ..content_ref("checkpoint-other")
        },
        ..checkpoint()
    }
}

fn wire_of_state(state: &JobState) -> String {
    serde_json::to_string(state)
        .expect("wire")
        .trim_matches('"')
        .to_owned()
}

fn wire_of_capability(capability: &JobCapability) -> String {
    serde_json::to_string(capability)
        .expect("wire")
        .trim_matches('"')
        .to_owned()
}

fn wire_of_role(role: &JobRole) -> String {
    serde_json::to_string(role)
        .expect("wire")
        .trim_matches('"')
        .to_owned()
}

fn state_of(wire: &str) -> Option<JobState> {
    match wire {
        "NOT_STARTED" => Some(JobState::NotStarted),
        "QUEUED" => Some(JobState::Queued),
        "LEASED" => Some(JobState::Leased),
        "RUNNING" => Some(JobState::Running),
        "CHECKPOINTED" => Some(JobState::Checkpointed),
        "VERIFYING" => Some(JobState::Verifying),
        "COMPLETED" => Some(JobState::Completed),
        "PARTIAL" => Some(JobState::Partial),
        "FAILED" => Some(JobState::Failed),
        "CANCELLED" => Some(JobState::Cancelled),
        "UNKNOWN_OUTCOME" => Some(JobState::UnknownOutcome),
        _ => None,
    }
}

fn kind_of(wire: &str) -> Option<JobOperationKind> {
    match wire {
        "SUBMIT_JOB" => Some(JobOperationKind::Submit),
        "LEASE_NEXT" => Some(JobOperationKind::LeaseNext),
        "LEASE_EXACT" => Some(JobOperationKind::LeaseExact),
        "RENEW_LEASE" => Some(JobOperationKind::Renew),
        "START_JOB" => Some(JobOperationKind::Start),
        "CHECKPOINT_JOB" => Some(JobOperationKind::Checkpoint),
        "RESUME_JOB" => Some(JobOperationKind::Resume),
        "BEGIN_VERIFICATION" => Some(JobOperationKind::BeginVerification),
        "PUBLISH_OUTCOME" => Some(JobOperationKind::Publish),
        "STATUS" => Some(JobOperationKind::Status),
        "REQUEST_CANCEL" => Some(JobOperationKind::RequestCancel),
        "RECONCILE_MUTATION" => Some(JobOperationKind::Reconcile),
        _ => None,
    }
}

fn collect_keys(value: &serde_json::Value, out: &mut Vec<String>) {
    if let Some(object) = value.as_object() {
        for (key, nested) in object {
            out.push(key.clone());
            collect_keys(nested, out);
        }
    } else if let Some(items) = value.as_array() {
        for nested in items {
            collect_keys(nested, out);
        }
    }
}

fn rejects(value: &serde_json::Value) -> bool {
    match serde_json::from_value::<DurableJobRequest>(value.clone()) {
        Err(_) => true,
        Ok(request) => request.validate().is_err(),
    }
}

/// Explicit two-history comparator: two shape-valid leases at one revision
/// with different bytes cannot both validate against one reference history.
fn same_revision_diverged(first: &JobLease, second: &JobLease) -> bool {
    first.revision == second.revision
        && serde_json::to_value(first).expect("json") != serde_json::to_value(second).expect("json")
}

struct RevisionPin {
    current: u64,
}

impl RevisionPin {
    fn admits(&self, lease: &JobLease) -> bool {
        lease.revision == self.current && lease.validate_active_at(50).is_ok()
    }
}

struct OwnerPin {
    revision: u64,
    owner: String,
    digest: String,
}

impl OwnerPin {
    fn for_lease(lease: &JobLease) -> Self {
        Self {
            revision: lease.revision,
            owner: lease.owner_artifact_id.as_str().to_owned(),
            digest: serde_json::to_string(lease).expect("json"),
        }
    }

    fn admits(&self, lease: &JobLease) -> bool {
        lease.revision == self.revision
            && lease.owner_artifact_id.as_str() == self.owner
            && serde_json::to_string(lease).expect("json") == self.digest
            && lease.validate_active_at(50).is_ok()
    }
}

fn resume_selects_current(current: &JobCheckpoint, offered: &JobCheckpoint) -> bool {
    current.checkpoint_id == offered.checkpoint_id
        && serde_json::to_value(&current.reference).expect("json")
            == serde_json::to_value(&offered.reference).expect("json")
}

/// Worker-side resume gate over the surfaced checkpoint: checkpoints that
/// still carry possible effects require proof before an unsafe replay.
fn resume_gate(checkpoint: &JobCheckpoint) -> Result<(), &'static str> {
    if checkpoint.possible_effects.is_empty() {
        Ok(())
    } else {
        Err("uncertain effects require proof before resume")
    }
}

// WORK_UNIT_CASE: 769/1
#[test]
fn canonical_lifecycle_vocabulary_matches_i14_20() {
    let vocabulary = fixture("lifecycle-vocabulary.json");
    assert_eq!(
        vocabulary["contract"].as_str().expect("contract"),
        "eliot.foundation.protocol.durable-job"
    );
    let fixture_states: Vec<String> =
        serde_json::from_value(vocabulary["states"].clone()).expect("states");
    let all = [
        JobState::NotStarted,
        JobState::Queued,
        JobState::Leased,
        JobState::Running,
        JobState::Checkpointed,
        JobState::Verifying,
        JobState::Completed,
        JobState::Partial,
        JobState::Failed,
        JobState::Cancelled,
        JobState::UnknownOutcome,
    ];
    let wire: Vec<String> = all.iter().map(wire_of_state).collect();
    assert_eq!(wire, fixture_states);
    let fixture_terminal: Vec<String> =
        serde_json::from_value(vocabulary["terminal"].clone()).expect("terminal");
    let terminal: Vec<String> = all
        .iter()
        .filter(|state| state.is_terminal())
        .map(wire_of_state)
        .collect();
    assert_eq!(terminal, fixture_terminal);
    let edges: Vec<(String, String)> = vocabulary["legal_edges"]
        .as_array()
        .expect("edges")
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().expect("from").to_owned(),
                pair[1].as_str().expect("to").to_owned(),
            )
        })
        .collect();
    for from in all {
        for to in all {
            let listed = edges.iter().any(|(edge_from, edge_to)| {
                edge_from == &wire_of_state(&from) && edge_to == &wire_of_state(&to)
            });
            assert_eq!(
                from.can_transition_to(to),
                from == to || listed,
                "{from:?} -> {to:?}"
            );
        }
    }
    let identity = eliot_protocol::durable_job_contract_identity().expect("identity");
    assert_eq!(
        identity.name,
        ContractId::new("eliot.foundation.protocol.durable-job").expect("contract")
    );
    assert_eq!(identity.version, ContractVersion::new(1, 0, 0));
}

// WORK_UNIT_CASE: 769/2
#[test]
fn private_lifecycle_tokens_are_rejected() {
    for token in [
        "CLAIMED",
        "CANDIDATE_READY",
        "RECONCILIATION_REQUIRED",
        "STALE",
        "VERIFIED_COMPLETE",
        "queued",
        "running",
        "",
    ] {
        assert!(
            serde_json::from_str::<JobState>(&format!("\"{token}\"")).is_err(),
            "{token} must not parse as a job state"
        );
    }
    let mut record = serde_json::to_value(record_in(JobState::Queued)).expect("json");
    record["state"] = serde_json::json!("STALE");
    assert!(serde_json::from_value::<DurableJobRecord>(record).is_err());
}

// WORK_UNIT_CASE: 769/3
#[test]
fn operation_catalogue_is_closed_at_twelve() {
    let catalogue = fixture("operation-catalogue.json");
    assert_eq!(catalogue["count"].as_u64().expect("count"), 12);
    let kinds = [
        JobOperationKind::Submit,
        JobOperationKind::LeaseNext,
        JobOperationKind::LeaseExact,
        JobOperationKind::Renew,
        JobOperationKind::Start,
        JobOperationKind::Checkpoint,
        JobOperationKind::Resume,
        JobOperationKind::BeginVerification,
        JobOperationKind::Publish,
        JobOperationKind::Status,
        JobOperationKind::RequestCancel,
        JobOperationKind::Reconcile,
    ];
    let wires: Vec<&str> = kinds.iter().map(|kind| kind.as_str()).collect();
    let fixture_wires: Vec<String> = catalogue["operations"]
        .as_array()
        .expect("operations")
        .iter()
        .map(|entry| entry["wire"].as_str().expect("wire").to_owned())
        .collect();
    assert_eq!(wires, fixture_wires);
    let operations = [
        JobOperation::Submit {
            submission: Box::new(submission()),
        },
        JobOperation::LeaseNext {
            selector: selector(),
        },
        JobOperation::LeaseExact {
            selector: selector(),
            job_id: TaskId::new("job").expect("job"),
        },
        JobOperation::Renew {
            lease: lease(),
            now_unix_ms: 50,
        },
        JobOperation::Start {
            lease: lease(),
            now_unix_ms: 50,
        },
        JobOperation::Checkpoint {
            lease: lease(),
            checkpoint: Box::new(checkpoint()),
            now_unix_ms: 50,
        },
        JobOperation::Resume {
            lease: lease(),
            checkpoint: Box::new(checkpoint()),
            now_unix_ms: 50,
        },
        JobOperation::BeginVerification {
            lease: lease(),
            result: Box::new(content_ref("result")),
            evidence: vec![artifact("stage-evidence")],
            now_unix_ms: 50,
        },
        JobOperation::Publish {
            lease: lease(),
            outcome: Box::new(outcome_failed()),
            now_unix_ms: 50,
        },
        JobOperation::Status {
            job_id: TaskId::new("job").expect("job"),
            attempt_id: ArtifactId::new("attempt").expect("attempt"),
            expected_revision: 1,
            expected_fence: fence(),
        },
        JobOperation::RequestCancel {
            job_id: TaskId::new("job").expect("job"),
            attempt_id: ArtifactId::new("attempt").expect("attempt"),
            reason: "stop".to_owned(),
            requested_at_unix_ms: 10,
            expected_fence: fence(),
        },
        JobOperation::Reconcile {
            mutation: Box::new(mutation_committed_unknown()),
        },
    ];
    for (operation, kind) in operations.iter().zip(kinds) {
        assert_eq!(operation.kind(), kind);
        assert_eq!(operation.kind().as_str(), kind.as_str());
        assert_eq!(operation.kind().to_string(), kind.as_str());
        operation.validate().expect("catalogue shape");
    }
    let mut unknown = serde_json::to_value(unchecked_request(
        JobOperation::Status {
            job_id: TaskId::new("job").expect("job"),
            attempt_id: ArtifactId::new("attempt").expect("attempt"),
            expected_revision: 1,
            expected_fence: fence(),
        },
        "operation-3",
        "stable-3",
        JobRole::Requester,
    ))
    .expect("json");
    unknown["operation"]["operation"] = serde_json::json!("FINISH_TASK");
    assert!(rejects(&unknown));
}

// WORK_UNIT_CASE: 769/4
#[test]
fn role_capabilities_are_distinct_and_closed() {
    let matrix = fixture("role-capability-matrix.json");
    for role in [JobRole::Requester, JobRole::Worker, JobRole::Controller] {
        let wire: Vec<String> = role.capabilities().iter().map(wire_of_capability).collect();
        let expected: Vec<String> =
            serde_json::from_value(matrix["roles"][wire_of_role(&role)].clone())
                .expect("capabilities");
        assert_eq!(wire, expected, "{role:?}");
    }
    assert!(
        !JobRole::Worker
            .capabilities()
            .contains(&JobCapability::Submit)
    );
    assert!(
        !JobRole::Requester
            .capabilities()
            .contains(&JobCapability::Lease)
    );
    assert!(
        !JobRole::Controller
            .capabilities()
            .contains(&JobCapability::Publish)
    );
    assert_ne!(
        JobRole::Requester.capabilities(),
        JobRole::Worker.capabilities()
    );
    let catalogue = fixture("operation-catalogue.json");
    for entry in catalogue["operations"].as_array().expect("operations") {
        let kind = kind_of(entry["wire"].as_str().expect("wire")).expect("known operation");
        let listed: Vec<String> = serde_json::from_value(entry["roles"].clone()).expect("roles");
        for role in [JobRole::Requester, JobRole::Worker, JobRole::Controller] {
            assert_eq!(
                role.permits(kind),
                listed.contains(&wire_of_role(&role)),
                "{role:?} on {}",
                kind.as_str()
            );
        }
    }
}

// WORK_UNIT_CASE: 769/5
#[test]
fn worker_cannot_submit_arbitrary_job() {
    let operation = JobOperation::Submit {
        submission: Box::new(submission()),
    };
    let request = unchecked_request(operation, "operation-5", "stable-5", JobRole::Worker);
    assert!(matches!(
        request.validate(),
        Err(DurableJobError::CapabilityDenied)
    ));
}

// WORK_UNIT_CASE: 769/6
#[test]
fn requester_cannot_drive_worker_operations() {
    let operations = [
        JobOperation::LeaseNext {
            selector: selector(),
        },
        JobOperation::LeaseExact {
            selector: selector(),
            job_id: TaskId::new("job").expect("job"),
        },
        JobOperation::Start {
            lease: lease(),
            now_unix_ms: 50,
        },
        JobOperation::Checkpoint {
            lease: lease(),
            checkpoint: Box::new(checkpoint()),
            now_unix_ms: 50,
        },
        JobOperation::Publish {
            lease: lease(),
            outcome: Box::new(outcome_failed()),
            now_unix_ms: 50,
        },
    ];
    for (index, operation) in operations.into_iter().enumerate() {
        let request = unchecked_request(
            operation,
            &format!("operation-6-{index}"),
            &format!("stable-6-{index}"),
            JobRole::Requester,
        );
        assert!(
            matches!(request.validate(), Err(DurableJobError::CapabilityDenied)),
            "requester must not drive worker operation {index}"
        );
    }
}

// WORK_UNIT_CASE: 769/7
#[test]
fn payload_names_grant_no_authority() {
    let lease_operation = JobOperation::LeaseNext {
        selector: selector(),
    };
    let named_worker = unchecked_request(
        lease_operation,
        "operation-7-lease",
        "stable-7-lease",
        JobRole::Requester,
    );
    assert!(matches!(
        named_worker.validate(),
        Err(DurableJobError::CapabilityDenied)
    ));
    let submit = JobOperation::Submit {
        submission: Box::new(submission()),
    };
    let requester = identity_as(&submit, "operation-7", "stable-7", JobRole::Requester);
    let worker = identity_as(&submit, "operation-7", "stable-7", JobRole::Worker);
    assert_ne!(
        requester.canonical_request_hash, worker.canonical_request_hash,
        "wire role is commitment, not display"
    );
    let publish = JobOperation::Publish {
        lease: lease(),
        outcome: Box::new(outcome_failed()),
        now_unix_ms: 50,
    };
    assert!(matches!(
        unchecked_request(
            publish,
            "operation-7-publish",
            "stable-7",
            JobRole::Controller
        )
        .validate(),
        Err(DurableJobError::CapabilityDenied)
    ));
    assert!(matches!(
        unchecked_request(
            JobOperation::Submit {
                submission: Box::new(submission())
            },
            "operation-7-submit",
            "stable-7",
            JobRole::Controller,
        )
        .validate(),
        Err(DurableJobError::CapabilityDenied)
    ));
}

// WORK_UNIT_CASE: 769/8
#[test]
fn unknown_schema_fields_variants_and_duplicate_keys_fail() {
    let request = unchecked_request(
        JobOperation::Submit {
            submission: Box::new(submission()),
        },
        "operation-8",
        "stable-8",
        JobRole::Requester,
    );
    request.validate().expect("anchor");
    let wire = serde_json::to_value(&request).expect("json");
    let mut unknown_field = wire.clone();
    unknown_field["unknown_field"] = serde_json::json!(true);
    assert!(rejects(&unknown_field));
    let mut unknown_operation = wire.clone();
    unknown_operation["operation"]["operation"] = serde_json::json!("CLAIM_JOB");
    assert!(rejects(&unknown_operation));
    let mut unknown_role = wire.clone();
    unknown_role["role"] = serde_json::json!("ADMIN");
    assert!(rejects(&unknown_role));
    let mut unknown_state = wire.clone();
    unknown_state["operation"]["submission"]["work_scope"]["state_fence"]["extra"] =
        serde_json::json!(1);
    assert!(rejects(&unknown_state));
    let raw = serde_json::to_string(&request).expect("encode");
    let duplicated = raw.replacen("\"role\":", "\"role\":\"REQUESTER\",\"role\":", 1);
    assert_ne!(duplicated, raw);
    assert!(serde_json::from_str::<DurableJobRequest>(&duplicated).is_err());
}

// WORK_UNIT_CASE: 769/11
#[test]
fn stale_admission_route_budget_scope_fence_epoch_generation_fail() {
    let variants: Vec<(&str, eliot_protocol::JobSubmission)> = vec![
        ("budget", {
            let mut submission = submission();
            submission.admission.budget_units = 0;
            submission
        }),
        ("deadline", {
            let mut submission = submission();
            submission.admission.deadline_unix_ms = 0;
            submission
        }),
        ("route", {
            let mut submission = submission();
            submission.admission.route_class = String::new();
            submission
        }),
        ("scope", {
            let mut submission = submission();
            submission.work_scope.scope_id = WorkScopeId::new("other-scope").expect("scope");
            submission
        }),
        ("fence", {
            let mut submission = submission();
            submission.admission.scope.state_fence = fence_seq(2);
            submission
        }),
        ("epoch-sequence", {
            let mut submission = submission();
            submission.admission.validity_epoch = epoch_seq(2);
            submission
        }),
        ("epoch-lineage", {
            let mut submission = submission();
            submission.admission.validity_epoch = epoch_other();
            submission
        }),
        ("generation", {
            let mut submission = submission();
            submission.admission.resource_generation =
                ResourceGeneration::new(2).expect("generation");
            submission
        }),
    ];
    for (name, variant) in variants {
        let operation = JobOperation::Submit {
            submission: Box::new(variant),
        };
        let request = unchecked_request(operation, "operation-11", "stable-11", JobRole::Requester);
        assert!(request.validate().is_err(), "stale {name} must fail");
    }
}

// WORK_UNIT_CASE: 769/12
#[test]
fn bounded_lease_next_and_lease_exact_select_compatibly() {
    let next = unchecked_request(
        JobOperation::LeaseNext {
            selector: selector(),
        },
        "operation-12-next",
        "stable-12-next",
        JobRole::Worker,
    );
    next.validate().expect("lease next");
    let exact_operation = JobOperation::LeaseExact {
        selector: selector(),
        job_id: TaskId::new("job").expect("job"),
    };
    let exact = unchecked_request(
        exact_operation,
        "operation-12-exact",
        "stable-12-exact",
        JobRole::Worker,
    );
    exact.validate().expect("lease exact");
    let mut empty_selector = selector();
    empty_selector.max_candidates = 0;
    assert!(
        JobOperation::LeaseNext {
            selector: empty_selector
        }
        .validate()
        .is_err()
    );
    let mut zero_revision = selector();
    zero_revision.expected_revision = 0;
    assert!(
        JobOperation::LeaseExact {
            selector: zero_revision,
            job_id: TaskId::new("job").expect("job"),
        }
        .validate()
        .is_err()
    );
    let mut response = base_response(&next, scope());
    response.state = JobState::Leased;
    response.disposition = Some(MutationDisposition::Committed);
    response.receipt_id = Some(ReceiptId::new("lease-receipt").expect("receipt"));
    response.lease = Some(lease());
    response.selection_coverage = vec!["job".to_owned()];
    round_trip(&response)
        .validate_for(&next)
        .expect("lease next");
    let mut exact_response = base_response(&exact, scope());
    exact_response.state = JobState::Leased;
    exact_response.disposition = Some(MutationDisposition::Committed);
    exact_response.receipt_id = Some(ReceiptId::new("lease-receipt").expect("receipt"));
    exact_response.lease = Some(lease());
    round_trip(&exact_response)
        .validate_for(&exact)
        .expect("lease exact");
}

// WORK_UNIT_CASE: 769/13
#[test]
fn lease_selection_coverage_rules_reject_empty_and_partial() {
    let next = unchecked_request(
        JobOperation::LeaseNext {
            selector: selector(),
        },
        "operation-13",
        "stable-13",
        JobRole::Worker,
    );
    next.validate().expect("lease next");
    let covered = |coverage: Vec<String>| {
        let mut response = base_response(&next, scope());
        response.state = JobState::Leased;
        response.disposition = Some(MutationDisposition::Committed);
        response.receipt_id = Some(ReceiptId::new("lease-receipt").expect("receipt"));
        response.lease = Some(lease());
        response.selection_coverage = coverage;
        response
    };
    assert!(covered(Vec::new()).validate_for(&next).is_err());
    assert!(
        covered(vec!["unrelated".to_owned()])
            .validate_for(&next)
            .is_err()
    );
    covered(vec!["other".to_owned(), "job".to_owned()])
        .validate_for(&next)
        .expect("coverage names the bound job");
    let exact = unchecked_request(
        JobOperation::LeaseExact {
            selector: selector(),
            job_id: TaskId::new("job").expect("job"),
        },
        "operation-13-exact",
        "stable-13-exact",
        JobRole::Worker,
    );
    exact.validate().expect("lease exact");
    let mut exact_response = base_response(&exact, scope());
    exact_response.state = JobState::Leased;
    exact_response.disposition = Some(MutationDisposition::Committed);
    exact_response.receipt_id = Some(ReceiptId::new("lease-receipt").expect("receipt"));
    exact_response.lease = Some(lease());
    exact_response.selection_coverage = vec!["job".to_owned()];
    assert!(exact_response.validate_for(&exact).is_err());
}

// WORK_UNIT_CASE: 769/14
#[test]
fn competing_same_revision_lease_histories_conflict() {
    let first = lease_owned("worker-a", 2);
    let second = lease_owned("worker-b", 2);
    first.validate_active_at(50).expect("first lease");
    second.validate_active_at(50).expect("second lease");
    let mut first_record = record_in(JobState::Leased);
    first_record.revision = 2;
    first_record.lease = Some(first.clone());
    first_record.validate().expect("first history");
    let mut second_record = record_in(JobState::Leased);
    second_record.revision = 2;
    second_record.lease = Some(second.clone());
    second_record.validate().expect("second history");
    assert!(
        same_revision_diverged(&first, &second),
        "histories cannot both validate against one owner"
    );
    assert!(!same_revision_diverged(&first, &first));
    assert!(!same_revision_diverged(&first, &lease_owned("worker-a", 3)));
}

// WORK_UNIT_CASE: 769/15
#[test]
fn wrong_artifact_generation_or_attempt_binding_is_rejected() {
    let start = unchecked_request(
        JobOperation::Start {
            lease: lease(),
            now_unix_ms: 50,
        },
        "operation-15",
        "stable-15",
        JobRole::Worker,
    );
    start.validate().expect("worker start");
    let mut swapped = start.clone();
    swapped.operation = JobOperation::Start {
        lease: lease_owned("worker-b", 1),
        now_unix_ms: 50,
    };
    assert!(matches!(
        swapped.validate(),
        Err(DurableJobError::OperationMismatch)
    ));
    let mut generation = lease();
    generation.resource_generation = ResourceGeneration::new(2).expect("generation");
    assert!(
        JobOperation::Start {
            lease: generation,
            now_unix_ms: 50,
        }
        .validate()
        .is_err()
    );
    let mut mismatched = checkpoint();
    mismatched.reference.artifact_id = Some(ArtifactId::new("artifact-other").expect("artifact"));
    assert!(mismatched.validate().is_err());
    let mut record = record_in(JobState::Leased);
    let mut other_attempt = lease();
    other_attempt.attempt_id = ArtifactId::new("other-attempt").expect("attempt");
    record.lease = Some(other_attempt);
    assert!(record.validate().is_err());
}

// WORK_UNIT_CASE: 769/16
#[test]
fn lease_boundary_expiry_renewal_and_stale_renewal() {
    let lease = lease_window(10, 100);
    lease.validate_active_at(10).expect("issued boundary");
    lease.validate_active_at(99).expect("last instant");
    assert!(lease.validate_active_at(9).is_err());
    assert!(lease.validate_active_at(100).is_err());
    JobOperation::Renew {
        lease: lease.clone(),
        now_unix_ms: 50,
    }
    .validate()
    .expect("renewal inside validity");
    assert!(
        JobOperation::Renew {
            lease: lease.clone(),
            now_unix_ms: 100,
        }
        .validate()
        .is_err()
    );
    assert!(
        JobOperation::Renew {
            lease,
            now_unix_ms: 9,
        }
        .validate()
        .is_err()
    );
}

// WORK_UNIT_CASE: 769/18
#[test]
fn every_legal_lifecycle_edge_applies() {
    let vocabulary = fixture("lifecycle-vocabulary.json");
    let edges: Vec<(JobState, JobState)> = vocabulary["legal_edges"]
        .as_array()
        .expect("edges")
        .iter()
        .map(|pair| {
            (
                state_of(pair[0].as_str().expect("from")).expect("known state"),
                state_of(pair[1].as_str().expect("to")).expect("known state"),
            )
        })
        .collect();
    assert_eq!(edges.len(), 17);
    for (from, to) in edges {
        let mut record = record_in(from);
        record.validate().expect("coherent source");
        record.transition(to).expect("legal edge");
        match to {
            JobState::Leased | JobState::Running | JobState::Verifying => {
                record.lease = Some(lease());
            }
            JobState::Checkpointed => {
                record.lease = Some(lease());
                record.checkpoint = Some(checkpoint());
            }
            JobState::NotStarted | JobState::Queued => {}
            _ => {
                record.outcome = Some(outcome_for(to));
            }
        }
        record.validate().expect("coherent target");
    }
    for state in [
        JobState::NotStarted,
        JobState::Queued,
        JobState::Leased,
        JobState::Running,
        JobState::Checkpointed,
        JobState::Verifying,
        JobState::Completed,
        JobState::Partial,
        JobState::Failed,
        JobState::Cancelled,
        JobState::UnknownOutcome,
    ] {
        let mut record = record_in(state);
        record.transition(state).expect("replay");
        record.validate().expect("replayed record");
    }
    let mut queued = record_in(JobState::Queued);
    queued.transition(JobState::Leased).expect("edge");
    assert_eq!(queued.revision, 2);
    queued.lease = Some(lease());
    queued.validate().expect("leased record");
}

// WORK_UNIT_CASE: 769/20
#[test]
fn start_requires_the_exact_active_lease() {
    let operation = JobOperation::Start {
        lease: lease(),
        now_unix_ms: 50,
    };
    unchecked_request(operation, "operation-20", "stable-20", JobRole::Worker)
        .validate()
        .expect("active lease starts");
    assert!(
        JobOperation::Start {
            lease: lease_window(10, 100),
            now_unix_ms: 100,
        }
        .validate()
        .is_err()
    );
    assert!(
        JobOperation::Start {
            lease: lease_window(10, 100),
            now_unix_ms: 9,
        }
        .validate()
        .is_err()
    );
    let mut fenced = unchecked_request(
        JobOperation::Start {
            lease: lease(),
            now_unix_ms: 50,
        },
        "operation-20-fence",
        "stable-20-fence",
        JobRole::Worker,
    );
    fenced.request_identity.operation.state_fence = fence_seq(2);
    assert!(matches!(
        fenced.validate(),
        Err(DurableJobError::FenceMismatch)
    ));
    let mut record = record_in(JobState::Leased);
    let mut other_job = lease();
    other_job.job_id = TaskId::new("other-job").expect("job");
    record.lease = Some(other_job);
    assert!(matches!(
        record.validate(),
        Err(DurableJobError::FenceMismatch)
    ));
}

// WORK_UNIT_CASE: 769/22
#[test]
fn resume_binds_the_exact_current_checkpoint() {
    unchecked_request(
        JobOperation::Resume {
            lease: lease(),
            checkpoint: Box::new(checkpoint()),
            now_unix_ms: 50,
        },
        "operation-22",
        "stable-22",
        JobRole::Worker,
    )
    .validate()
    .expect("exact resume");
    let mut off_fence = checkpoint();
    off_fence.state_fence = fence_seq(2);
    assert!(matches!(
        JobOperation::Resume {
            lease: lease(),
            checkpoint: Box::new(off_fence),
            now_unix_ms: 50,
        }
        .validate(),
        Err(DurableJobError::FenceMismatch)
    ));
    let current = checkpoint();
    assert!(resume_selects_current(&current, &checkpoint()));
    let other = checkpoint_other();
    other.validate().expect("shape-valid rival");
    assert!(!resume_selects_current(&current, &other));
}

// WORK_UNIT_CASE: 769/23
#[test]
fn unknown_effects_block_unsafe_resume() {
    let mut uncertain = checkpoint();
    uncertain.possible_effects = vec!["external-effect-1".to_owned()];
    let round_tripped: JobCheckpoint =
        serde_json::from_value(serde_json::to_value(&uncertain).expect("json")).expect("decode");
    assert_eq!(round_tripped.possible_effects, uncertain.possible_effects);
    assert!(resume_gate(&uncertain).is_err());
    assert!(resume_gate(&checkpoint()).is_ok());
    JobOperation::Resume {
        lease: lease(),
        checkpoint: Box::new(uncertain),
        now_unix_ms: 50,
    }
    .validate()
    .expect("contract surfaces uncertainty for the worker gate");
}

// WORK_UNIT_CASE: 769/24
#[test]
fn verification_requires_exact_result_and_stage_evidence() {
    unchecked_request(
        JobOperation::BeginVerification {
            lease: lease(),
            result: Box::new(content_ref("result")),
            evidence: vec![artifact("stage-evidence")],
            now_unix_ms: 50,
        },
        "operation-24",
        "stable-24",
        JobRole::Worker,
    )
    .validate()
    .expect("verification");
    assert!(
        JobOperation::BeginVerification {
            lease: lease(),
            result: Box::new(content_ref("result")),
            evidence: Vec::new(),
            now_unix_ms: 50,
        }
        .validate()
        .is_err()
    );
    let mut handleless = content_ref("result");
    handleless.artifact_id = None;
    assert!(
        JobOperation::BeginVerification {
            lease: lease(),
            result: Box::new(handleless),
            evidence: vec![artifact("stage-evidence")],
            now_unix_ms: 50,
        }
        .validate()
        .is_err()
    );
    let request = unchecked_request(
        JobOperation::Status {
            job_id: TaskId::new("job").expect("job"),
            attempt_id: ArtifactId::new("attempt").expect("attempt"),
            expected_revision: 1,
            expected_fence: fence(),
        },
        "operation-24-status",
        "stable-24-status",
        JobRole::Requester,
    );
    let mut verifying = base_response(&request, scope());
    verifying.state = JobState::Verifying;
    verifying.lease = Some(lease());
    assert!(verifying.validate().is_err());
    verifying.result_under_verification = Some(content_ref("result"));
    verifying.validate().expect("result under verification");
    let mut misplaced = base_response(&request, scope());
    misplaced.result_under_verification = Some(content_ref("result"));
    assert!(misplaced.validate().is_err());
}

// WORK_UNIT_CASE: 769/25
#[test]
fn complete_result_publishes() {
    let operation = JobOperation::Publish {
        lease: lease(),
        outcome: Box::new(outcome_completed_with_result()),
        now_unix_ms: 50,
    };
    let request = unchecked_request(operation, "operation-25", "stable-25", JobRole::Worker);
    request.validate().expect("complete publish");
    let mut record = record_in(JobState::Verifying);
    record.transition(JobState::Completed).expect("edge");
    record.outcome = Some(outcome_completed_with_result());
    record.validate().expect("completed record");
}

// WORK_UNIT_CASE: 769/26
#[test]
fn partial_result_carries_frontier() {
    let operation = JobOperation::Publish {
        lease: lease(),
        outcome: Box::new(outcome_partial()),
        now_unix_ms: 50,
    };
    unchecked_request(operation, "operation-26", "stable-26", JobRole::Worker)
        .validate()
        .expect("partial publish");
    let mut frontierless = outcome_partial();
    frontierless.unresolved.clear();
    assert!(
        JobOperation::Publish {
            lease: lease(),
            outcome: Box::new(frontierless),
            now_unix_ms: 50,
        }
        .validate()
        .is_err()
    );
    let mut record = record_in(JobState::Verifying);
    record.transition(JobState::Partial).expect("edge");
    record.outcome = Some(outcome_partial());
    record.validate().expect("partial record");
}

// WORK_UNIT_CASE: 769/27
#[test]
fn failed_cancelled_and_semantic_unknown_carry_evidence() {
    for (name, outcome) in [
        ("failed", outcome_failed()),
        ("cancelled", outcome_cancelled()),
        ("unknown", outcome_unknown()),
    ] {
        JobOperation::Publish {
            lease: lease(),
            outcome: Box::new(outcome),
            now_unix_ms: 50,
        }
        .validate()
        .expect(name);
    }
    for (name, mut outcome) in [
        ("failed", outcome_failed()),
        ("cancelled", outcome_cancelled()),
        ("unknown", outcome_unknown()),
    ] {
        outcome.evidence.clear();
        assert!(
            JobOperation::Publish {
                lease: lease(),
                outcome: Box::new(outcome),
                now_unix_ms: 50,
            }
            .validate()
            .is_err(),
            "{name} requires evidence"
        );
    }
}

// WORK_UNIT_CASE: 769/28
#[test]
fn result_contract_mismatch_fails() {
    let mut mismatched_result = content_ref("output");
    mismatched_result.contract.name = ContractId::new("eliot.other.contract").expect("contract");
    let mut mismatched = outcome_completed_with_result();
    mismatched.result = Some(mismatched_result);
    let mut record = record_in(JobState::Verifying);
    record.transition(JobState::Completed).expect("edge");
    record.outcome = Some(mismatched);
    assert!(matches!(
        record.validate(),
        Err(DurableJobError::OutcomeMismatch)
    ));
    let mut handleless = content_ref("output");
    handleless.artifact_id = None;
    let mut outcome = outcome_completed_with_result();
    outcome.result = Some(handleless);
    assert!(
        JobOperation::Publish {
            lease: lease(),
            outcome: Box::new(outcome),
            now_unix_ms: 50,
        }
        .validate()
        .is_err()
    );
}

// WORK_UNIT_CASE: 769/30
#[test]
fn stale_or_late_worker_cannot_replace_current_attempt() {
    let pin = RevisionPin { current: 5 };
    assert!(!pin.admits(&lease_owned("worker-a", 3)));
    assert!(pin.admits(&lease_owned("worker-a", 5)));
    assert!(!pin.admits(&lease_owned("worker-a", 6)));
    assert!(!pin.admits(&lease_window(10, 100)));
    let mut record = record_in(JobState::Running);
    record.revision = 5;
    record.validate().expect("current attempt");
    let mut other_attempt = lease_owned("worker-a", 5);
    other_attempt.attempt_id = ArtifactId::new("other-attempt").expect("attempt");
    record.lease = Some(other_attempt);
    assert!(record.validate().is_err());
}

// WORK_UNIT_CASE: 769/31
#[test]
fn cancellation_requested_differs_from_cancelled() {
    let mut record = record_in(JobState::Running);
    record
        .request_cancel(
            "requester".to_owned(),
            "user requested stop".to_owned(),
            OperationId::new("cancel-31").expect("operation"),
            10,
        )
        .expect("cancel intent");
    assert_eq!(record.state, JobState::Running);
    assert_eq!(record.revision, 2);
    assert!(matches!(
        record.cancellation,
        CancellationState::Requested { .. }
    ));
    record.validate().expect("requested record");
    let terminal = record_in(JobState::Completed);
    let mut terminal_cancel = terminal.clone();
    assert!(matches!(
        terminal_cancel.request_cancel(
            "requester".to_owned(),
            "too late".to_owned(),
            OperationId::new("cancel-31-late").expect("operation"),
            11,
        ),
        Err(DurableJobError::TerminalImmutable)
    ));
    let mut without_outcome = record_in(JobState::Cancelled);
    without_outcome.outcome = None;
    assert!(without_outcome.validate().is_err());
    unchecked_request(
        JobOperation::RequestCancel {
            job_id: TaskId::new("job").expect("job"),
            attempt_id: ArtifactId::new("attempt").expect("attempt"),
            reason: "stop".to_owned(),
            requested_at_unix_ms: 10,
            expected_fence: fence(),
        },
        "operation-31",
        "stable-31",
        JobRole::Controller,
    )
    .validate()
    .expect("controller scoped cancel");
    let requested = serde_json::to_value(&record.cancellation).expect("json");
    assert_eq!(requested["state"], serde_json::json!("REQUESTED"));
    let none = serde_json::to_value(CancellationState::None).expect("json");
    assert_eq!(none["state"], serde_json::json!("NONE"));
}

// WORK_UNIT_CASE: 769/32
#[test]
fn late_actual_outcome_after_cancel_is_preserved() {
    let mut record = record_in(JobState::Running);
    record
        .request_cancel(
            "requester".to_owned(),
            "user requested stop".to_owned(),
            OperationId::new("cancel-32").expect("operation"),
            10,
        )
        .expect("cancel intent");
    record.transition(JobState::Failed).expect("late failure");
    record.outcome = Some(outcome_failed());
    record.validate().expect("late outcome retained");
    assert_eq!(record.state, JobState::Failed);
    assert!(matches!(
        record.cancellation,
        CancellationState::Requested { .. }
    ));
    assert!(matches!(
        record.outcome,
        Some(JobOutcome {
            state: JobState::Failed,
            ..
        })
    ));
}

// WORK_UNIT_CASE: 769/34
#[test]
fn stale_applicability_is_separate_from_execution_history() {
    let status = unchecked_request(
        JobOperation::Status {
            job_id: TaskId::new("job").expect("job"),
            attempt_id: ArtifactId::new("attempt").expect("attempt"),
            expected_revision: 3,
            expected_fence: fence(),
        },
        "operation-34",
        "stable-34",
        JobRole::Requester,
    );
    status.validate().expect("status");
    let mut stale_response = base_response(&status, scope());
    stale_response.state = JobState::Leased;
    stale_response.lease = Some(lease());
    stale_response.revision = 1;
    assert!(stale_response.validate_for(&status).is_err());
    let mut current_response = base_response(&status, scope());
    current_response.state = JobState::Leased;
    current_response.lease = Some(lease());
    current_response.revision = 3;
    current_response
        .validate_for(&status)
        .expect("current revision");
    let mut record = record_in(JobState::Leased);
    record.revision = 3;
    record.validate().expect("history unchanged");
    for token in ["STALE", "FRESH", "SUPERSEDED", "APPLICABLE"] {
        assert!(
            serde_json::from_str::<JobState>(&format!("\"{token}\"")).is_err(),
            "applicability is not execution history"
        );
    }
}

// WORK_UNIT_CASE: 769/36
#[test]
fn unknown_mutation_dispositions_validate_separately() {
    mutation_committed_unknown().validate().expect("committed");
    reconcile_request(&mutation_committed_unknown(), JobRole::Controller)
        .validate()
        .expect("reconcile request");
    let mut not_applied = mutation_committed_unknown();
    not_applied.disposition = MutationDisposition::ProvenNotApplied;
    not_applied.committed_state = None;
    not_applied.receipt_id = None;
    not_applied.validate().expect("proven not applied");
    let mut still_unknown = mutation_committed_unknown();
    still_unknown.disposition = MutationDisposition::StillUnknown;
    still_unknown.committed_state = None;
    still_unknown.receipt_id = None;
    still_unknown.evidence.clear();
    still_unknown.validate().expect("still unknown");
    let mut irreconcilable = still_unknown.clone();
    irreconcilable.disposition = MutationDisposition::Irreconcilable;
    irreconcilable.validate().expect("irreconcilable");
    let mut no_receipt = mutation_committed_unknown();
    no_receipt.receipt_id = None;
    assert!(no_receipt.validate().is_err());
    let mut no_evidence = mutation_committed_unknown();
    no_evidence.disposition = MutationDisposition::ProvenNotApplied;
    no_evidence.committed_state = None;
    no_evidence.receipt_id = None;
    no_evidence.evidence.clear();
    assert!(no_evidence.validate().is_err());
    let mut claimed = mutation_committed_unknown();
    claimed.disposition = MutationDisposition::StillUnknown;
    assert!(claimed.validate().is_err());
    let text = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/dreamer-job/unknown-outcome-reconciliation.json"),
    )
    .expect("fixture");
    serde_json::from_str::<DurableJobRequest>(&text)
        .expect("fixture parses")
        .validate()
        .expect("fixture reconciles");
}

// WORK_UNIT_CASE: 769/37
#[test]
fn committed_semantic_unknown_is_not_promoted() {
    let text = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/dreamer-job/unknown-outcome-reconciliation.json"),
    )
    .expect("fixture");
    let request: DurableJobRequest = serde_json::from_str(&text).expect("fixture parses");
    request.validate().expect("fixture reconciles");
    let JobOperation::Reconcile { mutation } = &request.operation else {
        panic!("fixture must reconcile");
    };
    assert_eq!(mutation.disposition, MutationDisposition::Committed);
    assert_eq!(mutation.committed_state, Some(JobState::UnknownOutcome));
    let mut record = record_in(JobState::Verifying);
    record
        .transition(mutation.committed_state.expect("committed"))
        .expect("reconciled edge");
    record.outcome = Some(outcome_unknown());
    record.validate().expect("unknown record");
    assert_eq!(record.state, JobState::UnknownOutcome);
    let mut promoted = outcome_unknown();
    promoted.state = JobState::Completed;
    promoted.abstention_reason = None;
    assert!(promoted.validate().is_err());
}

// WORK_UNIT_CASE: 769/38
#[test]
fn reconciliation_creates_no_job_or_repeat_effect() {
    let mutation = mutation_committed_unknown();
    let request = reconcile_request(&mutation, JobRole::Controller);
    request.validate().expect("reconcile");
    request.clone().validate().expect("idempotent replay");
    assert_eq!(
        request.request_identity.canonical_request_hash,
        mutation.canonical_request_hash
    );
    let mut tampered = request.clone();
    let JobOperation::Reconcile {
        mutation: tampered_mutation,
    } = &mut tampered.operation
    else {
        panic!("must reconcile");
    };
    tampered_mutation.operation.operation_id =
        OperationId::new("other-operation").expect("operation");
    assert!(matches!(
        tampered.validate(),
        Err(DurableJobError::OperationMismatch)
    ));
    let value = serde_json::to_value(&request.operation).expect("json");
    assert_eq!(value["operation"], serde_json::json!("RECONCILE_MUTATION"));
    assert!(value.get("submission").is_none());
    assert!(value.get("outcome").is_none());
}

// WORK_UNIT_CASE: 769/39
#[test]
fn completed_with_complete_candidate() {
    let operation = JobOperation::Publish {
        lease: lease(),
        outcome: Box::new(outcome_completed_with_result()),
        now_unix_ms: 50,
    };
    let request = unchecked_request(operation, "operation-39", "stable-39", JobRole::Worker);
    request.validate().expect("publish candidate");
    let mut record = record_in(JobState::Verifying);
    record.transition(JobState::Completed).expect("edge");
    record.outcome = Some(outcome_completed_with_result());
    record.validate().expect("completed record");
    let mut response = base_response(&request, scope());
    response.state = JobState::Completed;
    response.disposition = Some(MutationDisposition::Committed);
    response.receipt_id = Some(ReceiptId::new("publish-receipt").expect("receipt"));
    response.lease = Some(lease());
    response.outcome = Some(outcome_completed_with_result());
    round_trip(&response)
        .validate_for(&request)
        .expect("completed response");
}

// WORK_UNIT_CASE: 769/40
#[test]
fn completed_with_evidence_backed_abstention() {
    let operation = JobOperation::Publish {
        lease: lease(),
        outcome: Box::new(outcome_completed_abstention()),
        now_unix_ms: 50,
    };
    unchecked_request(operation, "operation-40", "stable-40", JobRole::Worker)
        .validate()
        .expect("abstention publishes");
    let mut record = record_in(JobState::Verifying);
    record.transition(JobState::Completed).expect("edge");
    record.outcome = Some(outcome_completed_abstention());
    record.validate().expect("abstention record");
    let mut bare = outcome_completed_abstention();
    bare.abstention_reason = None;
    assert!(
        JobOperation::Publish {
            lease: lease(),
            outcome: Box::new(bare),
            now_unix_ms: 50,
        }
        .validate()
        .is_err()
    );
}

// WORK_UNIT_CASE: 769/41
#[test]
fn no_user_task_verified_complete_or_close() {
    for token in [
        "VERIFIED_COMPLETE",
        "VerifiedComplete",
        "verified_complete",
        "FINISH",
        "CLOSED",
    ] {
        assert!(
            serde_json::from_str::<JobState>(&format!("\"{token}\"")).is_err(),
            "{token} must not parse as a job state"
        );
    }
    let outcome = serde_json::to_value(outcome_completed_with_result()).expect("json");
    let keys: BTreeSet<String> = outcome
        .as_object()
        .expect("object")
        .keys()
        .cloned()
        .collect();
    let expected: BTreeSet<String> = [
        "state",
        "result",
        "evidence",
        "verifier",
        "proof_ceiling",
        "abstention_reason",
        "unresolved",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(keys, expected);
    let request = unchecked_request(
        JobOperation::Submit {
            submission: Box::new(submission()),
        },
        "operation-41",
        "stable-41",
        JobRole::Requester,
    );
    let mut keys = Vec::new();
    collect_keys(&serde_json::to_value(&request).expect("json"), &mut keys);
    for key in keys {
        let lowered = key.to_lowercase();
        for forbidden in [
            "finish",
            "close",
            "grant",
            "apply",
            "verified_complete",
            "task_close",
        ] {
            assert!(
                !lowered.contains(forbidden),
                "control key {key} must not close a user task"
            );
        }
    }
}

// WORK_UNIT_CASE: 769/42
#[test]
fn no_candidate_application_or_effect_authority() {
    let kinds = [
        (JobOperationKind::Submit, "SUBMIT_JOB"),
        (JobOperationKind::LeaseNext, "LEASE_NEXT"),
        (JobOperationKind::LeaseExact, "LEASE_EXACT"),
        (JobOperationKind::Renew, "RENEW_LEASE"),
        (JobOperationKind::Start, "START_JOB"),
        (JobOperationKind::Checkpoint, "CHECKPOINT_JOB"),
        (JobOperationKind::Resume, "RESUME_JOB"),
        (JobOperationKind::BeginVerification, "BEGIN_VERIFICATION"),
        (JobOperationKind::Publish, "PUBLISH_OUTCOME"),
        (JobOperationKind::Status, "STATUS"),
        (JobOperationKind::RequestCancel, "REQUEST_CANCEL"),
        (JobOperationKind::Reconcile, "RECONCILE_MUTATION"),
    ];
    for (kind, wire) in kinds {
        let observed = match kind {
            JobOperationKind::Submit => "SUBMIT_JOB",
            JobOperationKind::LeaseNext => "LEASE_NEXT",
            JobOperationKind::LeaseExact => "LEASE_EXACT",
            JobOperationKind::Renew => "RENEW_LEASE",
            JobOperationKind::Start => "START_JOB",
            JobOperationKind::Checkpoint => "CHECKPOINT_JOB",
            JobOperationKind::Resume => "RESUME_JOB",
            JobOperationKind::BeginVerification => "BEGIN_VERIFICATION",
            JobOperationKind::Publish => "PUBLISH_OUTCOME",
            JobOperationKind::Status => "STATUS",
            JobOperationKind::RequestCancel => "REQUEST_CANCEL",
            JobOperationKind::Reconcile => "RECONCILE_MUTATION",
        };
        assert_eq!(observed, wire);
        assert_eq!(kind.as_str(), wire);
    }
    let catalogue = fixture("operation-catalogue.json");
    assert_eq!(catalogue["count"].as_u64().expect("count"), 12);
    let submit = unchecked_request(
        JobOperation::Submit {
            submission: Box::new(submission()),
        },
        "operation-42",
        "stable-42",
        JobRole::Worker,
    );
    assert_eq!(
        submit.request_identity.operation.effect,
        EffectClass::Candidate
    );
    assert!(matches!(
        submit.validate(),
        Err(DurableJobError::CapabilityDenied)
    ));
}

// WORK_UNIT_CASE: 769/43
#[test]
fn semantic_bytes_are_opaque_and_digest_bound() {
    let mut empty = content_ref("input");
    empty.byte_length = 0;
    assert!(empty.validate("semantic_input.sha256").is_err());
    let mut upper = content_ref("input");
    upper.sha256 = "A".repeat(64);
    assert!(upper.validate("semantic_input.sha256").is_err());
    let mut short = content_ref("input");
    short.sha256 = "0".repeat(63);
    assert!(short.validate("semantic_input.sha256").is_err());
    let mut handleless = content_ref("input");
    handleless.artifact_id = None;
    assert!(handleless.validate("semantic_input.sha256").is_err());
    let mut renamed = content_ref("input");
    renamed.contract.name = ContractId::new("eliot.other.contract").expect("contract");
    renamed
        .validate("semantic_input.sha256")
        .expect("bytes stay opaque");
    content_ref("input")
        .validate("semantic_input.sha256")
        .expect("ref");
}

// WORK_UNIT_CASE: 769/44
#[test]
fn each_terminal_shape_has_exact_evidence() {
    let matrix = fixture("terminal-evidence-matrix.json");
    for (state, outcome) in [
        (JobState::Completed, outcome_completed_with_result()),
        (JobState::Partial, outcome_partial()),
        (JobState::Failed, outcome_failed()),
        (JobState::Cancelled, outcome_cancelled()),
        (JobState::UnknownOutcome, outcome_unknown()),
    ] {
        let wire = wire_of_state(&state);
        let flags = &matrix["terminal"][wire.as_str()];
        assert_eq!(
            flags["requires_evidence"].as_bool().expect("flag"),
            true,
            "{wire}"
        );
        outcome.validate().expect("evidence present");
        let mut evidenceless = outcome.clone();
        evidenceless.evidence.clear();
        assert!(evidenceless.validate().is_err(), "{wire} requires evidence");
        if wire == "COMPLETED" {
            assert_eq!(
                flags["requires_result_or_abstention"]
                    .as_bool()
                    .expect("flag"),
                true
            );
            let mut bare = outcome.clone();
            bare.result = None;
            bare.abstention_reason = None;
            assert!(bare.validate().is_err());
        }
        if wire == "PARTIAL" {
            assert_eq!(flags["requires_unresolved"].as_bool().expect("flag"), true);
            let mut frontierless = outcome.clone();
            frontierless.unresolved.clear();
            assert!(frontierless.validate().is_err());
        }
    }
    let mut overclaimed = outcome_failed();
    overclaimed.proof_ceiling = ProofCeiling::ScopedVerification;
    overclaimed.verifier = Some(VerifierBinding {
        verifier_id: ContractId::new("verifier").expect("verifier"),
        verifier_revision: ContractVersion::new(1, 0, 0),
        artifact_ids: vec![ArtifactId::new("verification-evidence").expect("artifact")],
        proof_ceiling: ProofCeiling::CandidateArtifact,
        state_fence: fence(),
    });
    assert!(matches!(
        overclaimed.validate(),
        Err(DurableJobError::ProofOverclaim)
    ));
}

// WORK_UNIT_CASE: 769/45
#[test]
fn each_bound_holds_at_limit_and_one_over() {
    let text_limit = eliot_protocol::dreamer_job::DURABLE_JOB_MAX_TEXT_BYTES;
    assert_eq!(text_limit, 16 * 1024);
    let cancel = |reason: String| JobOperation::RequestCancel {
        job_id: TaskId::new("job").expect("job"),
        attempt_id: ArtifactId::new("attempt").expect("attempt"),
        reason,
        requested_at_unix_ms: 10,
        expected_fence: fence(),
    };
    cancel("x".repeat(text_limit)).validate().expect("limit");
    assert!(matches!(
        cancel("x".repeat(text_limit + 1)).validate(),
        Err(DurableJobError::LimitExceeded(_))
    ));
    let ref_limit = eliot_protocol::dreamer_job::DURABLE_JOB_MAX_REFERENCES;
    assert_eq!(ref_limit, 256);
    let mut phases = checkpoint();
    phases.completed_phases = (0..ref_limit)
        .map(|index| format!("phase-{index}"))
        .collect();
    phases.validate().expect("phase limit");
    phases.completed_phases.push("phase-overflow".to_owned());
    assert!(matches!(
        phases.validate(),
        Err(DurableJobError::LimitExceeded(_))
    ));
    let mut crowded = outcome_failed();
    crowded.evidence = (0..ref_limit)
        .map(|index| artifact(&format!("evidence-{index}")))
        .collect();
    crowded.validate().expect("evidence limit");
    crowded.evidence.push(artifact("evidence-overflow"));
    assert!(matches!(
        crowded.validate(),
        Err(DurableJobError::LimitExceeded(_))
    ));
}

// WORK_UNIT_CASE: 769/46
#[test]
fn canonical_encoding_is_set_order_invariant() {
    let first = serde_json::json!({"beta": 1, "alpha": [1, 2]});
    let second = serde_json::json!({"alpha": [1, 2], "beta": 1});
    let canonical_first = eliot_contracts::canonical_json_bytes(&first).expect("canonical");
    let canonical_second = eliot_contracts::canonical_json_bytes(&second).expect("canonical");
    assert_eq!(canonical_first, canonical_second);
    let next = unchecked_request(
        JobOperation::LeaseNext {
            selector: selector(),
        },
        "operation-46",
        "stable-46",
        JobRole::Worker,
    );
    next.validate().expect("lease next");
    for coverage in [
        vec!["job".to_owned(), "other".to_owned()],
        vec!["other".to_owned(), "job".to_owned()],
    ] {
        let mut response = base_response(&next, scope());
        response.state = JobState::Leased;
        response.disposition = Some(MutationDisposition::Committed);
        response.receipt_id = Some(ReceiptId::new("lease-receipt").expect("receipt"));
        response.lease = Some(lease());
        response.selection_coverage = coverage;
        response.validate_for(&next).expect("order-free match");
    }
    let repeated = identity_as(
        &JobOperation::Submit {
            submission: Box::new(submission()),
        },
        "operation-46",
        "stable-46",
        JobRole::Requester,
    );
    let original = identity_as(
        &JobOperation::Submit {
            submission: Box::new(submission()),
        },
        "operation-46",
        "stable-46",
        JobRole::Requester,
    );
    assert_eq!(
        repeated.canonical_request_hash,
        original.canonical_request_hash
    );
}

// WORK_UNIT_CASE: 769/47
#[test]
fn control_identity_mutation_changes_digest() {
    let operation = JobOperation::Submit {
        submission: Box::new(submission()),
    };
    let base = unchecked_request(operation, "operation-47", "stable-47", JobRole::Requester);
    base.validate().expect("base");
    let mut operation_id = base.clone();
    operation_id.request_identity.operation.operation_id =
        OperationId::new("other-operation").expect("operation");
    assert!(matches!(
        operation_id.validate(),
        Err(DurableJobError::OperationMismatch)
    ));
    let mut idempotency = base.clone();
    idempotency.request_identity.operation.idempotency_key = "other-stable".to_owned();
    assert!(matches!(
        idempotency.validate(),
        Err(DurableJobError::OperationMismatch)
    ));
    let mut kind = base.clone();
    kind.request_identity.operation.operation_kind = "LEASE_NEXT".to_owned();
    assert!(matches!(
        kind.validate(),
        Err(DurableJobError::OperationMismatch)
    ));
    let mut task = base.clone();
    task.request_identity.request.request.metadata.task_id =
        Some(TaskId::new("other-task").expect("task"));
    assert!(matches!(
        task.validate(),
        Err(DurableJobError::OperationMismatch)
    ));
    let mut effect = base.clone();
    effect.request_identity.operation.effect = EffectClass::ExternalEffect;
    assert!(matches!(
        effect.validate(),
        Err(DurableJobError::OperationMismatch)
    ));
    let mut role = base.clone();
    role.role = JobRole::Worker;
    assert!(matches!(
        role.validate(),
        Err(DurableJobError::OperationMismatch)
    ));
    let mut payload = base.clone();
    let JobOperation::Submit { submission } = &mut payload.operation else {
        panic!("must submit");
    };
    submission.cancellation_id = "other-cancellation".to_owned();
    assert!(matches!(
        payload.validate(),
        Err(DurableJobError::OperationMismatch)
    ));
    let mut retry = base.clone();
    retry.request_identity.request.request.metadata.request_id =
        RequestId::new("fresh-47").expect("request");
    retry.validate().expect("fresh transport keeps commitment");
}

// WORK_UNIT_CASE: 769/48
#[test]
fn malformed_inputs_fail_bounded_without_panic() {
    let anchor = unchecked_request(
        JobOperation::Submit {
            submission: Box::new(submission()),
        },
        "operation-48",
        "stable-48",
        JobRole::Requester,
    );
    anchor.validate().expect("anchor");
    let wire = serde_json::to_value(&anchor).expect("json");
    assert!(!rejects(&wire));
    assert!(rejects(&serde_json::json!({})));
    assert!(rejects(&serde_json::Value::Null));
    assert!(rejects(&serde_json::json!([1, 2])));
    let mut null_identity = wire.clone();
    null_identity["request_identity"] = serde_json::Value::Null;
    assert!(rejects(&null_identity));
    let mut admin_role = wire.clone();
    admin_role["role"] = serde_json::json!("ADMIN");
    assert!(rejects(&admin_role));
    let mut lowercase_role = wire.clone();
    lowercase_role["role"] = serde_json::json!("worker");
    assert!(rejects(&lowercase_role));
    let mut finish_operation = wire.clone();
    finish_operation["operation"]["operation"] = serde_json::json!("FINISH_TASK");
    assert!(rejects(&finish_operation));
    let mut zero_budget = wire.clone();
    zero_budget["operation"]["submission"]["admission"]["budget_units"] = serde_json::json!(0);
    assert!(rejects(&zero_budget));
    let mut bad_hash = wire.clone();
    bad_hash["request_identity"]["canonical_request_hash"] = serde_json::json!("ZZZ");
    assert!(rejects(&bad_hash));
    let mut rotated_hash = wire.clone();
    rotated_hash["request_identity"]["canonical_request_hash"] = serde_json::json!("1".repeat(64));
    assert!(rejects(&rotated_hash));
    let mut rotated_role = wire.clone();
    rotated_role["role"] = serde_json::json!("WORKER");
    assert!(rejects(&rotated_role));
    let mut deep = serde_json::json!({"operation": "SUBMIT_JOB"});
    for _ in 0..200 {
        deep = serde_json::json!({"nested": deep});
    }
    let mut nested_operation = wire.clone();
    nested_operation["operation"] = deep;
    assert!(rejects(&nested_operation));
    let raw = serde_json::to_string(&anchor).expect("encode");
    assert!(serde_json::from_str::<DurableJobRequest>(&raw[..128]).is_err());
    let duplicated = raw.replacen("\"role\":", "\"role\":\"REQUESTER\",\"role\":", 1);
    assert!(serde_json::from_str::<DurableJobRequest>(&duplicated).is_err());
    let bytes = raw.as_bytes();
    for position in (0..bytes.len()).step_by(157).take(32) {
        let mut mutated = bytes.to_vec();
        mutated[position] ^= 0x01;
        match serde_json::from_slice::<DurableJobRequest>(&mutated) {
            Err(_) => {}
            Ok(request) => {
                let wire = serde_json::to_vec(&request).expect("encode");
                let back: DurableJobRequest = serde_json::from_slice(&wire).expect("decode");
                assert_eq!(request, back);
            }
        }
    }
}

// WORK_UNIT_CASE: 769/49
#[test]
fn each_nonterminal_state_has_exact_ownership() {
    for state in [
        JobState::NotStarted,
        JobState::Queued,
        JobState::Leased,
        JobState::Running,
        JobState::Checkpointed,
        JobState::Verifying,
    ] {
        record_in(state).validate().expect("coherent record");
    }
    for state in [
        JobState::Leased,
        JobState::Running,
        JobState::Checkpointed,
        JobState::Verifying,
    ] {
        let mut leaseless = record_in(state);
        leaseless.lease = None;
        assert!(matches!(
            leaseless.validate(),
            Err(DurableJobError::LeaseInvalid)
        ));
    }
    let mut checkpointless = record_in(JobState::Checkpointed);
    checkpointless.checkpoint = None;
    assert!(checkpointless.validate().is_err());
}

// WORK_UNIT_CASE: 769/50
#[test]
fn each_terminal_outcome_is_immutable_with_allowed_evidence() {
    for state in [
        JobState::Completed,
        JobState::Partial,
        JobState::Failed,
        JobState::Cancelled,
        JobState::UnknownOutcome,
    ] {
        let record = record_in(state);
        record.validate().expect("coherent terminal");
        let mut moved = record.clone();
        assert!(matches!(
            moved.transition(JobState::Running),
            Err(DurableJobError::TerminalImmutable)
        ));
        assert!(matches!(
            moved.request_cancel(
                "requester".to_owned(),
                "too late".to_owned(),
                OperationId::new("operation-50").expect("operation"),
                10,
            ),
            Err(DurableJobError::TerminalImmutable)
        ));
        let mut mismatched = record.clone();
        mismatched.outcome = Some(outcome_for(other_terminal(state)));
        assert!(matches!(
            mismatched.validate(),
            Err(DurableJobError::OutcomeMismatch)
        ));
        assert_eq!(moved.state, state);
        assert_eq!(moved.revision, 1);
    }
}

// WORK_UNIT_CASE: 769/51
#[test]
fn at_most_one_worker_owner_per_revision() {
    let pin = OwnerPin::for_lease(&lease_owned("worker-a", 4));
    assert!(pin.admits(&lease_owned("worker-a", 4)));
    assert!(!pin.admits(&lease_owned("worker-b", 4)));
    assert!(!pin.admits(&lease_owned("worker-a", 5)));
    let mut tampered = lease_owned("worker-a", 4);
    tampered.expires_at_unix_ms = 90;
    assert!(!pin.admits(&tampered));
    assert!(!pin.admits(&lease_window(10, 100)));
}

// WORK_UNIT_CASE: 769/52
#[test]
fn store_uncertainty_cannot_become_semantic_success() {
    let mut claimed = mutation_committed_unknown();
    claimed.disposition = MutationDisposition::StillUnknown;
    assert!(claimed.validate().is_err());
    let mut receipted = mutation_committed_unknown();
    receipted.disposition = MutationDisposition::ProvenNotApplied;
    receipted.committed_state = None;
    receipted.receipt_id = None;
    receipted.evidence = vec![artifact("rollback-evidence")];
    receipted.validate().expect("proven not applied");
    assert!(receipted.committed_state.is_none());
    let mut bare_success = outcome_unknown();
    bare_success.state = JobState::Completed;
    bare_success.abstention_reason = None;
    assert!(bare_success.validate().is_err());
    let mut overclaimed = outcome_failed();
    overclaimed.proof_ceiling = ProofCeiling::ScopedVerification;
    overclaimed.verifier = Some(VerifierBinding {
        verifier_id: ContractId::new("verifier").expect("verifier"),
        verifier_revision: ContractVersion::new(1, 0, 0),
        artifact_ids: vec![ArtifactId::new("verification-evidence").expect("artifact")],
        proof_ceiling: ProofCeiling::ScopedVerification,
        state_fence: fence(),
    });
    overclaimed.validate().expect("verifier covers outcome");
    let mut record = record_in(JobState::Verifying);
    record.transition(JobState::Failed).expect("edge");
    record.outcome = Some(overclaimed);
    assert!(matches!(
        record.validate(),
        Err(DurableJobError::ProofOverclaim)
    ));
    let publish = unchecked_request(
        JobOperation::Publish {
            lease: lease(),
            outcome: Box::new(outcome_failed()),
            now_unix_ms: 50,
        },
        "operation-52",
        "stable-52",
        JobRole::Worker,
    );
    publish.validate().expect("publish");
    let mut uncertain = base_response(&publish, scope());
    uncertain.state = JobState::Failed;
    uncertain.disposition = Some(MutationDisposition::StillUnknown);
    uncertain.outcome = Some(outcome_failed());
    uncertain.lease = Some(lease());
    uncertain
        .validate_for(&publish)
        .expect("uncertainty keeps the exact outcome");
    let mut promoted = uncertain.clone();
    promoted.outcome = Some(outcome_cancelled());
    assert!(promoted.validate_for(&publish).is_err());
}

// WORK_UNIT_CASE: 769/53
#[test]
fn contract_has_no_smart_provider_store_or_finish_implementation() {
    assert_eq!(
        eliot_protocol::DURABLE_JOB_CONTRACT_NAME,
        "eliot.foundation.protocol.durable-job"
    );
    assert_eq!(
        eliot_protocol::DURABLE_JOB_CONTRACT_VERSION,
        ContractVersion::new(1, 0, 0)
    );
    assert_eq!(
        eliot_protocol::DURABLE_JOB_CANONICAL_ENCODING,
        "eliot.durable-job.canonical.v1"
    );
    assert_eq!(
        eliot_protocol::dreamer_job::DURABLE_JOB_CONTRACT_NAME,
        eliot_protocol::DURABLE_JOB_CONTRACT_NAME
    );
    eliot_protocol::durable_job_contract_identity().expect("identity");
    let record = record_in(JobState::Completed);
    let mut pure = record.clone();
    assert!(matches!(
        pure.transition(JobState::Running),
        Err(DurableJobError::TerminalImmutable)
    ));
    assert_eq!(pure, record);
    let secret = "SECRET-PLAINTEXT-769-cancel";
    let operation = JobOperation::RequestCancel {
        job_id: TaskId::new("job").expect("job"),
        attempt_id: ArtifactId::new("attempt").expect("attempt"),
        reason: secret.to_owned(),
        requested_at_unix_ms: 0,
        expected_fence: fence(),
    };
    let error = operation.validate().expect_err("zero timestamp must fail");
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(secret));
}
