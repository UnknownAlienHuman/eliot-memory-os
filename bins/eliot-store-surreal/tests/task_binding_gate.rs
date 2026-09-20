//! Store-bridge task-binding gate proof for issue #1929 (I5.5/I5.6).
//!
//! Smallest acceptance proof only, through the pure pre-provider gate (no
//! provider I/O): unbound `CaptureObservation` classifies cold; task-control
//! without evidence rejects `TASK_SELECTION_REQUIRED`; mismatched scope
//! rejects `TASK_SCOPE_INCOMPATIBLE`.

use std::collections::BTreeMap;

use eliot_contracts::{
    ClockReading, OperationId, ProductId, RequestId, SourceId, StateFence, TaskId,
};
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationIdentity, OrderingScopeId, PreparedTransition, RequestMeta, ScopeId, SecurityContext,
    TransitionClass,
};
use eliot_store_surreal::task_binding_gate::{
    GateDisposition, TASK_SCOPE_INCOMPATIBLE, TASK_SELECTION_REQUIRED, gate_apply,
};
use serde_json::json;

fn fence() -> StateFence {
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("seq")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn context(task: Option<&str>) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new("request-1929").expect("request id"),
        session_id: None,
        task_id: task.map(|t| TaskId::new(t).expect("task id")),
        product_id: ProductId::new("product-1929").expect("product"),
        source_id: SourceId::new("source-1929").expect("source"),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn binding_refs(task: &str) -> Vec<String> {
    vec![
        format!("task-contract-revision:{task}:7"),
        format!("acceptance-digest:{task}:{}", "a".repeat(64)),
    ]
}

fn transition(
    class: TransitionClass,
    ceiling: EffectClass,
    operation: NamedMutationOperation,
    params: BTreeMap<String, serde_json::Value>,
    task: Option<&str>,
    refs: Vec<String>,
) -> PreparedTransition {
    let entries = eliot_store_api::generated_operation_manifests().expect("catalogue");
    let set_digest = eliot_store_api::operation_manifest_set_digest(&entries).expect("set digest");
    PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new("op-1929-1").expect("operation id"),
            idempotency_key: "idem-1929-1".to_owned(),
            canonical_request_hash: "c".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new("scope-1929").expect("scope"),
        task_id: task.map(str::to_owned),
        ordering_scopes: vec![OrderingScopeId::new("scope-1929").expect("ordering")],
        transition_class: class,
        requested_effect_ceiling: ceiling,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: set_digest,
        named_operations: vec![NamedMutationRequest {
            operation,
            parameters: params,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: refs,
    }
}

fn capture(task: Option<&str>, refs: Vec<String>) -> PreparedTransition {
    transition(
        TransitionClass::CaptureCandidate,
        EffectClass::Candidate,
        NamedMutationOperation::CaptureObservation,
        BTreeMap::from([("subject".to_owned(), json!("observation-1929"))]),
        task,
        refs,
    )
}

fn control(task: Option<&str>, refs: Vec<String>) -> PreparedTransition {
    transition(
        TransitionClass::TaskControl,
        EffectClass::ReversibleMutation,
        NamedMutationOperation::UpdateTaskState,
        BTreeMap::from([
            ("task_id".to_owned(), json!("task-a")),
            ("event_id".to_owned(), json!("event-1")),
            ("to".to_owned(), json!("running")),
            ("expected_revision".to_owned(), json!("7")),
            ("actor_ref".to_owned(), json!("actor-1")),
        ]),
        task,
        refs,
    )
}

#[test]
fn unbound_capture_is_cold_without_task_effects() {
    let disposition =
        gate_apply(&context(None), &capture(None, Vec::new())).expect("unbound capture stays cold");
    assert_eq!(disposition, GateDisposition::ColdUnbound);
}

#[test]
fn control_without_evidence_returns_selection_required() {
    let error = gate_apply(&context(None), &control(None, Vec::new()))
        .expect_err("missing binding must reject");
    assert_eq!(error.code(), TASK_SELECTION_REQUIRED);
    // A bare task_id without exact revision/digest handles is still missing.
    let bare = gate_apply(
        &context(Some("task-a")),
        &control(Some("task-a"), Vec::new()),
    )
    .expect_err("bare task_id must reject");
    assert_eq!(bare.code(), TASK_SELECTION_REQUIRED);
}

#[test]
fn mismatched_scope_returns_incompatible_and_changes_nothing() {
    let before_task = "task-a";
    let transition = control(Some(before_task), binding_refs(before_task));
    let before = transition.clone();
    let error = gate_apply(&context(Some("task-b")), &transition)
        .expect_err("cross-task write must reject");
    assert_eq!(error.code(), TASK_SCOPE_INCOMPATIBLE);
    assert_eq!(transition, before, "rejection mutates neither task");
}
