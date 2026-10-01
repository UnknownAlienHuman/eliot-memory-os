use std::num::NonZeroU64;

use eliot_contracts::{
    EpochId, EpochLineageId, ResourceGeneration, StateFence,
};
use eliot_store_api::{
    BudgetConsumptionRecord, CONTRACT_VERSION, EffectClass, EventProjectionRelationIntents,
    OperationId, OperationIdentity, PreparedTransition, ScopeId, SecurityContext,
    TransitionClass, BUDGET_CONSUMPTION_SCHEMA_V1,
    bind_issue18_digests, canonical_json_bytes, commit_budget_consumption_operation,
    sha256_hex,
};
use serde_json::{Value, json};

use super::budget_consumption_statements;

fn fence() -> StateFence {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn record(fence: &StateFence) -> BudgetConsumptionRecord {
    let usage = json!({
        "provider_tool": {"provider_ref": "provider-1", "tool_ref": "claude"},
        "operation": {"operation_id": "provider-child-1"},
        "provider_receipt_ref": {"ref": "meter-receipt-1"},
        "cost_micros": {"status": "known", "value": 18},
        "quota_units": {"status": "known", "value": 1},
        "status": "SUCCEEDED"
    });
    let usage_bytes = canonical_json_bytes(&usage).expect("usage bytes");
    let usage_json = String::from_utf8(usage_bytes.clone()).expect("usage UTF-8");
    let reservation = json!({
        "reservation_id": "budget-1-1",
        "envelope_id": "budget-1",
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
    let next_snapshot = json!({
        "schema": "eliot.governor.budget-owner.v1",
        "version": 1,
        "state_fence": fence,
        "revision": 2,
        "state": {"kind": "configured", "ledger": {"reservations": []}}
    });
    let next_bytes = canonical_json_bytes(&next_snapshot).expect("snapshot bytes");
    BudgetConsumptionRecord {
        schema: BUDGET_CONSUMPTION_SCHEMA_V1.to_owned(),
        consumption_id: "provider-child-1".to_owned(),
        state_fence: fence.clone(),
        session_id: "session-1".to_owned(),
        task_id: "task-1".to_owned(),
        work_id: "work-1".to_owned(),
        work_scope_id: "scope-1".to_owned(),
        attempt_id: "attempt-1".to_owned(),
        admitted_operation_id: OperationId::new("admitted-work-1").expect("admitted operation"),
        provider_operation_id: OperationId::new("provider-child-1").expect("provider operation"),
        admission_record_key: "work-1:attempt-1".to_owned(),
        admission_record_sha256: "a".repeat(64),
        reservation_id: "budget-1-1".to_owned(),
        reservation_idempotency_key: "reservation-provider-child-1".to_owned(),
        provider_ref: "provider-1".to_owned(),
        tool_ref: "claude".to_owned(),
        reservation_receipt_json: String::from_utf8(reservation_bytes.clone())
            .expect("reservation UTF-8"),
        reservation_receipt_sha256: sha256_hex(&reservation_bytes),
        measured_usage_json: usage_json,
        measured_usage_sha256: sha256_hex(&usage_bytes),
        expected_budget_owner_revision: 1,
        expected_budget_owner_sha256: "b".repeat(64),
        committed_budget_owner_revision: 2,
        committed_budget_owner_sha256: sha256_hex(&next_bytes),
        canonical_operation_id: OperationId::new("canonical-consume-1").expect("canonical op"),
        canonical_idempotency_key: "original-result-submit-1".to_owned(),
    }
}

fn transition() -> PreparedTransition {
    let state_fence = fence();
    let value = json!({
        "schema": "eliot.governor.budget-owner.v1",
        "version": 1,
        "state_fence": state_fence,
        "revision": 2,
        "state": {"kind": "configured", "ledger": {"reservations": []}}
    });
    let snapshot = String::from_utf8(canonical_json_bytes(&value).expect("snapshot bytes"))
        .expect("snapshot UTF-8");
    let mutation = commit_budget_consumption_operation(record(&state_fence), snapshot)
        .expect("budget mutation");
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
            eliot_store_api::supported_admission_contract_set_digest().expect("contracts"),
        operation_manifest_digest: eliot_store_api::operation_manifest_set_digest(
            &eliot_store_api::generated_operation_manifests().expect("manifests"),
        )
        .expect("manifest digest"),
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
        named_operations: vec![mutation],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    bind_issue18_digests(&mut transition).expect("bind transition digests");
    transition
}

#[test]
fn budget_consumption_writes_exact_owner_cas_and_measured_record() {
    let transition = transition();
    let (statement, bindings) =
        budget_consumption_statements(&transition).expect("exact budget consumption");

    assert!(statement.contains("$budget_expected_revision"));
    assert!(statement.contains("$budget_expected_digest"));
    assert!(statement.contains("CREATE type::record($budget_consumption_table"));
    assert_eq!(
        bindings["budget_expected_revision"],
        Value::from(1_u64)
    );
    assert_eq!(
        bindings["budget_expected_digest"],
        Value::String("b".repeat(64))
    );
}

#[test]
fn budget_consumption_refuses_changed_original_owner_predecessor() {
    let mut transition = transition();
    transition.named_operations[0].parameters["expected_budget_owner_revision"] =
        Value::String("0".to_owned());

    assert!(budget_consumption_statements(&transition).is_err());
}
