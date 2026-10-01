use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration, SourceId,
    StateFence,
};
use eliot_store_api::{
    CONTRACT_VERSION, EffectClass, EventProjectionRelationIntents, OperationId, OperationIdentity,
    OperationManifestDigest,
    OutboxIntentKind, PolicyConfigSchemaVersions, PreparedTransition, RequestMeta, RevisionKey,
    RevisionHeadExpectation, ScopeId, SecurityContext, TransitionClass, WorkAdmissionBudget,
    WorkAdmissionBudgetDimension, WorkAdmissionClaimRef, WorkAdmissionClaims, WorkAdmissionRecord,
    WorkAdmissionSemanticRevision, WorkAdmissionState, WorkAdmissionSubmission,
    WORK_ADMISSION_SCHEMA_V1, WriteReceipt, WriteReceiptStatus, bind_issue18_digests,
    generated_operation_manifests, operation_manifest_set_digest,
    supported_admission_contract_set_digest,
};
use serde_json::json;

fn fence() -> StateFence {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn identity(id: &str) -> OperationIdentity {
    OperationIdentity {
        operation_id: OperationId::new(id).expect("operation id"),
        idempotency_key: format!("idem-{id}"),
        canonical_request_hash: "a".repeat(64),
    }
}

fn claim(reference: &str, digest: char) -> WorkAdmissionClaimRef {
    WorkAdmissionClaimRef {
        reference: reference.to_owned(),
        sha256: digest.to_string().repeat(64),
    }
}

fn record() -> WorkAdmissionRecord {
    let state_fence = fence();
    let canonical_operation_id = OperationId::new("canonical-work-admit").expect("operation");
    WorkAdmissionRecord {
        schema: WORK_ADMISSION_SCHEMA_V1.to_owned(),
        state: WorkAdmissionState::Admitted,
        work_id: "work-1".to_owned(),
        parent_task_id: "parent-task-1".to_owned(),
        task_id: "task-1".to_owned(),
        session_id: "session-1".to_owned(),
        task_revision: "7".to_owned(),
        cell_id: "cell-1".to_owned(),
        payload_digest: "b".repeat(64),
        input_revision: "input-4".to_owned(),
        scope_id: "scope-1".to_owned(),
        term: 2,
        dependencies: Vec::new(),
        budgets: vec![WorkAdmissionBudget {
            dimension: WorkAdmissionBudgetDimension::ComputeSteps,
            limit: 1,
        }],
        route_class: "claude".to_owned(),
        max_retries: 1,
        max_children: 1,
        max_depth: 1,
        max_pending_reviews: 1,
        evidence_required: true,
        receipt_contract_revision: "receipt-v1".to_owned(),
        reservation_id: identity("reservation-1"),
        work_item_id: identity("work-item-1"),
        proposed_attempt_id: identity("attempt-1"),
        stage_operation_id: identity("stage-1"),
        claims: WorkAdmissionClaims {
            resources: claim("resources-1", 'c'),
            lane: claim("lane-1", 'd'),
            environment: claim("environment-1", 'e'),
            effects: claim("effects-1", 'f'),
            quota_view: claim("quota-1", '1'),
        },
        authority_epoch: state_fence.authority_epoch.clone(),
        state_fence,
        expires_at_ms: 1_800_000_000_000,
        semantic_admission_revision: WorkAdmissionSemanticRevision {
            key: "owner/canonical".to_owned(),
            revision: "4".to_owned(),
        },
        semantic_admission_predecessor_revision: 3,
        canonical_operation_id: canonical_operation_id.clone(),
        canonical_idempotency_key: "idem-canonical-work-admit".to_owned(),
        launch_outbox_id: OutboxIntentKind::Launch
            .outbox_id(canonical_operation_id.as_str(), 0)
            .expect("launch id"),
    }
}

fn prepared() -> PreparedTransition {
    let admitted = record();
    let command = eliot_store_api::admit_work_operation(admitted.clone()).expect("admit work");
    let mut transition = PreparedTransition {
        contract_version: CONTRACT_VERSION,
        identity: OperationIdentity {
            operation_id: admitted.canonical_operation_id.clone(),
            idempotency_key: "idem-canonical-work-admit".to_owned(),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: admitted.state_fence.clone(),
        scope_id: ScopeId::new(&admitted.scope_id).expect("scope"),
        task_id: Some(admitted.task_id.clone()),
        ordering_scopes: vec![eliot_store_api::OrderingScopeId::new("work-admission-task-1")
            .expect("ordering scope")],
        transition_class: TransitionClass::TaskControl,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest:
            supported_admission_contract_set_digest().expect("contract set digest"),
        operation_manifest_digest: operation_manifest_set_digest(
            &generated_operation_manifests().expect("operation manifests"),
        )
        .expect("manifest digest"),
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: vec![format!(
            "{}@{}",
            admitted.semantic_admission_revision.key,
            admitted.semantic_admission_predecessor_revision
        )],
        named_operations: vec![command],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    bind_issue18_digests(&mut transition).expect("derived digests");
    transition.validate().expect("valid transition");
    transition
}

fn request() -> RequestMeta {
    let fence = fence();
    RequestMeta {
        request_id: RequestId::new("request-work-admit-1").expect("request id"),
        session_id: Some(eliot_contracts::SessionId::new("session-1").expect("session")),
        task_id: Some(eliot_contracts::TaskId::new("task-1").expect("task")),
        product_id: ProductId::new("product-1").expect("product"),
        source_id: SourceId::new("source-eliotd").expect("source"),
        state_fence: fence,
        clock: ClockReading::default(),
    }
}

fn receipt(transition: &PreparedTransition) -> WriteReceipt {
    let launch = record().launch_outbox_id;
    WriteReceipt {
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        transition_class: transition.transition_class,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(eliot_store_api::CommitId::new("commit-work-admit-1").expect("commit")),
        state_fence: transition.state_fence.clone(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["admit-work".to_owned()],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: vec![launch],
        operation_manifest_digest: transition.operation_manifest_digest.clone(),
        admission_digest: transition.admission_digest.clone(),
        mutation_plan_digest: transition.mutation_plan_digest.clone(),
        semantic_source_revisions: transition.semantic_source_revisions.clone(),
        policy_config_schema_versions: PolicyConfigSchemaVersions::bound_to(transition),
        error_code: None,
        resubmission: eliot_store_api::Resubmission::None,
        committed_at: Some("2026-10-01T00:00:00Z".to_owned()),
        envelope: None,
    }
}

fn predecessor_head(revision: u64) -> RevisionHeadExpectation {
    RevisionHeadExpectation {
        key: RevisionKey::new("owner/canonical").expect("canonical owner revision key"),
        expected_revision: revision,
        state_fence: fence(),
    }
}

#[test]
fn work_admission_accepts_exact_original_transition_and_receipt() {
    let transition = prepared();
    let submission = WorkAdmissionSubmission::new(
        request(),
        transition.clone(),
        vec![predecessor_head(3)],
        Vec::new(),
    )
    .expect("original submission");

    submission
        .validate_receipt(&receipt(&transition))
        .expect("exact committed receipt");
}

#[test]
fn work_admission_refuses_same_operation_with_changed_claim_commitment() {
    let transition = prepared();
    let mut submission = WorkAdmissionSubmission::new(
        request(),
        transition.clone(),
        vec![predecessor_head(3)],
        Vec::new(),
    )
    .expect("original submission");
    let record = submission.prepared_transition.named_operations[0]
        .parameters
        .get_mut("record")
        .expect("admitted record");
    record["claims"]["effects"]["sha256"] = json!("9".repeat(64));

    assert!(submission.validate_receipt(&receipt(&transition)).is_err());
}

#[test]
fn work_admission_refuses_stale_canonical_owner_predecessor() {
    let transition = prepared();

    assert!(WorkAdmissionSubmission::new(
        request(),
        transition,
        vec![predecessor_head(2)],
        Vec::new(),
    )
    .is_err());
}
