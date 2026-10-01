use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration,
    SessionId, SourceId, StateFence, TaskId,
};
use eliot_store_api::{
    CONTRACT_VERSION, EffectClass, EventProjectionRelationIntents, OperationId,
    OperationIdentity, PolicyConfigSchemaVersions,
    PreparedTransition, RequestMeta, ScopeId, SecurityContext, TransitionClass,
    BudgetConsumptionRecord, BudgetConsumptionSubmission, BUDGET_CONSUMPTION_SCHEMA_V1,
    bind_issue18_digests, canonical_json_bytes, generated_operation_manifests,
    operation_manifest_set_digest, supported_admission_contract_set_digest,
    commit_budget_consumption_operation, sha256_hex, WriteReceipt, WriteReceiptStatus,
};
use serde_json::json;

fn fence() -> StateFence {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn record(fence: &StateFence) -> (BudgetConsumptionRecord, String) {
    let usage = json!({
        "provider_tool": {"provider_ref": "provider-1", "tool_ref": "claude"},
        "operation": {"operation_id": "provider-child-1"},
        "provider_receipt_ref": {"ref": "usage-receipt-1"},
        "cost_micros": {"status": "known", "value": 18},
        "quota_units": {"status": "known", "value": 1},
        "status": "SUCCEEDED"
    });
    let usage_bytes = canonical_json_bytes(&usage).expect("usage canonical bytes");
    let usage_json = String::from_utf8(usage_bytes.clone()).expect("usage UTF-8");
    let reservation = json!({
        "reservation_id": "budget-envelope-1-1",
        "envelope_id": "budget-envelope-1",
        "idempotency_key": "reservation-provider-child-1",
        "operation": {"operation_id": "provider-child-1"},
        "provider_tool": {"provider_ref": "provider-1", "tool_ref": "claude"},
        "state": "RELEASED",
        "disposition": "SUCCESS",
        "exhaustion_disposition": {"kind": "within_envelope"},
        "canonical_admission_receipt_ref": null,
        "activation_receipt_ref": null,
        "committed_usage": usage,
        "refund_observations": [],
        "estimated_cost_micros": 100,
        "estimated_quota_units": 2
    });
    let reservation_bytes = canonical_json_bytes(&reservation).expect("reservation bytes");
    let reservation_json = String::from_utf8(reservation_bytes.clone()).expect("receipt UTF-8");
    let next_snapshot = json!({
        "schema": "eliot.governor.budget-owner.v1",
        "version": 1,
        "state_fence": fence,
        "revision": 2,
        "state": {"kind": "configured", "ledger": {"reservations": []}}
    });
    let next_bytes = canonical_json_bytes(&next_snapshot).expect("next snapshot bytes");
    let next_snapshot_json = String::from_utf8(next_bytes.clone()).expect("snapshot UTF-8");
    let record = BudgetConsumptionRecord {
        schema: BUDGET_CONSUMPTION_SCHEMA_V1.to_owned(),
        consumption_id: "provider-child-1".to_owned(),
        state_fence: fence.clone(),
        session_id: "session-1".to_owned(),
        task_id: "task-1".to_owned(),
        work_id: "work-1".to_owned(),
        work_scope_id: "scope-1".to_owned(),
        attempt_id: "attempt-1".to_owned(),
        admitted_operation_id: OperationId::new("admitted-work-1").expect("admitted op"),
        provider_operation_id: OperationId::new("provider-child-1").expect("provider op"),
        admission_record_key: "work-1:attempt-1".to_owned(),
        admission_record_sha256: "a".repeat(64),
        reservation_id: "budget-envelope-1-1".to_owned(),
        reservation_idempotency_key: "reservation-provider-child-1".to_owned(),
        provider_ref: "provider-1".to_owned(),
        tool_ref: "claude".to_owned(),
        reservation_receipt_json: reservation_json,
        reservation_receipt_sha256: sha256_hex(&reservation_bytes),
        measured_usage_json: usage_json,
        measured_usage_sha256: sha256_hex(&usage_bytes),
        expected_budget_owner_revision: 1,
        expected_budget_owner_sha256: "b".repeat(64),
        committed_budget_owner_revision: 2,
        committed_budget_owner_sha256: sha256_hex(&next_bytes),
        canonical_operation_id: OperationId::new("canonical-consume-1").expect("canonical op"),
        canonical_idempotency_key: "original-result-submit-1".to_owned(),
    };
    (record, next_snapshot_json)
}

fn prepared() -> PreparedTransition {
    let state_fence = fence();
    let (record, snapshot_json) = record(&state_fence);
    let command = commit_budget_consumption_operation(record, snapshot_json)
        .expect("budget consumption mutation");
    let mut transition = PreparedTransition {
        contract_version: CONTRACT_VERSION,
        identity: OperationIdentity {
            operation_id: OperationId::new("canonical-consume-1").expect("operation id"),
            idempotency_key: "original-result-submit-1".to_owned(),
            canonical_request_hash: "c".repeat(64),
        },
        state_fence: state_fence.clone(),
        scope_id: ScopeId::new("scope-1").expect("scope"),
        task_id: Some("task-1".to_owned()),
        ordering_scopes: Vec::new(),
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest:
            supported_admission_contract_set_digest().expect("contract digest"),
        operation_manifest_digest: operation_manifest_set_digest(
            &generated_operation_manifests().expect("manifests"),
        )
        .expect("manifest digest"),
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
        named_operations: vec![command],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    bind_issue18_digests(&mut transition).expect("bind transition digests");
    transition.validate().expect("prepared budget mutation");
    transition
}

fn request() -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new("request-consume-1").expect("request id"),
        session_id: Some(SessionId::new("session-1").expect("session")),
        task_id: Some(TaskId::new("task-1").expect("task")),
        product_id: ProductId::new("product-1").expect("product"),
        source_id: SourceId::new("source-eliotd").expect("source"),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn receipt(transition: &PreparedTransition) -> WriteReceipt {
    WriteReceipt {
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        transition_class: transition.transition_class,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(eliot_store_api::CommitId::new("commit-budget-consume-1").expect("commit")),
        state_fence: transition.state_fence.clone(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["commit-budget-consumption".to_owned()],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
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

#[test]
fn budget_consumption_accepts_exact_original_owner_transition_and_receipt() {
    let transition = prepared();
    let submission = BudgetConsumptionSubmission::new(
        request(),
        transition.clone(),
        Vec::new(),
        Vec::new(),
    )
    .expect("original usage submission");

    submission.validate_receipt(&receipt(&transition)).expect("exact committed receipt");
}

#[test]
fn budget_consumption_refuses_same_operation_with_changed_measured_usage() {
    let transition = prepared();
    let mut submission = BudgetConsumptionSubmission::new(
        request(),
        transition.clone(),
        Vec::new(),
        Vec::new(),
    )
    .expect("original usage submission");
    submission.prepared_transition.named_operations[0].parameters["consumption"]["measured_usage_sha256"] =
        json!("f".repeat(64));

    assert!(submission.validate_receipt(&receipt(&transition)).is_err());
}

#[test]
fn budget_consumption_refuses_an_unconfigured_next_budget_owner() {
    let (record, snapshot_json) = record(&fence());
    let next_snapshot: serde_json::Value = serde_json::from_str(&snapshot_json).expect("snapshot");
    assert_eq!(next_snapshot.pointer("/state/kind").and_then(serde_json::Value::as_str), Some("configured"));

    let mut unconfigured = next_snapshot;
    unconfigured["state"] = json!({"kind": "unconfigured"});
    let bytes = canonical_json_bytes(&unconfigured).expect("unconfigured snapshot bytes");
    let snapshot_json = String::from_utf8(bytes.clone()).expect("snapshot UTF-8");
    let mut record = record;
    record.committed_budget_owner_sha256 = sha256_hex(&bytes);
    assert!(commit_budget_consumption_operation(record.clone(), snapshot_json.clone()).is_ok());

    // The transition validator, rather than the opaque operation builder,
    // refuses an unconfigured next owner image. Cover that boundary without
    // fabricating a Store receipt.
    let transition = prepared();
    let mut changed = transition;
    changed.named_operations[0].parameters["budget_owner_snapshot_json"] = json!(snapshot_json);
    changed.named_operations[0].parameters["consumption"] = json!(record);
    bind_issue18_digests(&mut changed).expect("bind invalid owner transition");
    assert!(changed.validate().is_err());
}
