#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ClockReading, ContractId, ContractIdentity, ContractVersion,
    OperationId, ProductId, ReceiptId, RequestId, ResourceGeneration, SourceId, StateFence, TaskId,
};
use eliot_protocol::{
    AdmissionRef, CancellationState, DurableJobRecord, DurableJobRequest, DurableRequestIdentity,
    JobOperation, JobOperationKind, JobRole, JobState, MutationDisposition, MutationReconciliation,
    OpaqueContentRef, RequestIdentity,
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
                authority_epoch: AuthorityEpoch::genesis(),
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
            validity_epoch: AuthorityEpoch::genesis(),
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
        DurableRequestIdentity::digest_for(&binding, &request, operation, JobRole::Requester)
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

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}
