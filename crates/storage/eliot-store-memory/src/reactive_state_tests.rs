//! Canonical reactive-state persistence proofs (issue #1941 C4).
//!
//! Drives the closed `ApplyReactiveInjectionState` /
//! `GetReactiveInjectionState` and `ApplyResourceSnapshot` /
//! `GetResourceSnapshot` operations through the reference contour:
//! verbatim ledger round-trip with revision guarding, immutable snapshot
//! serving with convergent re-apply, rewrite-with-different-bytes
//! rejection, digest/contract/grammar negatives, and class discipline.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration,
    SourceId, StateFence, TaskId, TaskRevision,
};
use eliot_receipts::EffectClass;
use eliot_store_api::{
    CanonicalRequestView, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, OperationIdentity, OrderingScopeId, PreparedTransition, RequestMeta,
    ScopeId, SecurityContext, StoreError, TransitionClass, WriteReceipt, bind_issue18_digests,
    canonical_request_hash, operation_manifest_set_digest, reactive_ledger_mutation_request,
    reactive_ledger_read_request, resource_snapshot_mutation_request,
    resource_snapshot_read_request,
};
use serde_json::{Value, json};

use super::MemoryStore;

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const CONTRACT: &str = "eliot.agent-bridge.reactive-injection-receipts/v1";

fn fence() -> StateFence {
    let mut fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new(LINEAGE).expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch"),
        ResourceGeneration::new(1).expect("generation"),
    );
    // Task-bound callers carry the plan revision on the fence: the
    // canonical receipt requires caller/transition/fence task agreement.
    fence.task_revision = Some(TaskRevision::new(7).expect("task revision"));
    fence
}

fn context(tag: &str) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(format!("request-reactive-{tag}")).expect("request"),
        session_id: None,
        // Task binding agrees with the transition envelope below: the
        // canonical receipt requires caller/transition task agreement.
        task_id: Some(TaskId::new("task-9").expect("task")),
        product_id: ProductId::new("product-reactive").expect("product"),
        source_id: SourceId::new("owner-1").expect("source"),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn ledger_json(items: u32) -> String {
    let items: Vec<Value> = (0..items)
        .map(|index| json!({"item_id": format!("reactive-item-{index}")}))
        .collect();
    serde_json::to_string(&json!({"contract": CONTRACT, "items": items})).expect("fixture")
}

fn transition_with(
    tag: &str,
    operation: NamedMutationOperation,
    parameters: BTreeMap<String, Value>,
) -> (RequestMeta, PreparedTransition) {
    let ctx = context(tag);
    let manifest_digest =
        operation_manifest_set_digest(&eliot_store_api::generated_operation_manifests().unwrap())
            .unwrap();
    let mut transition = PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new(format!("op-reactive-{tag}")).expect("operation id"),
            idempotency_key: format!("idem-reactive-{tag}"),
            canonical_request_hash: "0".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new("reactive-state").expect("scope"),
        task_id: Some("task-9".to_owned()),
        ordering_scopes: vec![OrderingScopeId::new("reactive-state").expect("ordering")],
        transition_class: TransitionClass::ReactiveState,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: "c".repeat(64),
        operation_manifest_digest: manifest_digest,
        // Issue-#18 digests are derived below via `bind_issue18_digests`,
        // never defaulted; no semantic source is bound here (`[]`).
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
        named_operations: vec![NamedMutationRequest {
            operation,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    bind_issue18_digests(&mut transition).expect("issue-18 digests bind");
    let view = CanonicalRequestView::from_apply(&ctx, &transition, &[], &[]);
    transition.identity.canonical_request_hash =
        canonical_request_hash(&view).expect("hash computes");
    (ctx, transition)
}

fn apply(
    store: &MemoryStore,
    tag: &str,
    operation: NamedMutationOperation,
    parameters: BTreeMap<String, Value>,
) -> Result<WriteReceipt, StoreError> {
    let (ctx, transition) = transition_with(tag, operation, parameters);
    store.apply_transaction(&ctx, transition, &[], &[])
}

#[test]
fn ledger_upsert_reads_back_verbatim_with_revision() {
    let store = MemoryStore::new();
    let first = ledger_json(2);
    let request = reactive_ledger_mutation_request("session-1".to_owned(), first.clone());
    apply(&store, "ledger-1", request.operation, request.parameters)
        .expect("ledger upsert commits");
    let query = reactive_ledger_read_request("session-1".to_owned(), fence()).expect("read");
    let response = store.execute_named_sync(&query).expect("read executes");
    assert_eq!(
        response.payload.get("ledger_json").and_then(Value::as_str),
        Some(first.as_str()),
        "readback is byte-identical to the admitted snapshot"
    );
    assert_eq!(
        response.payload.get("revision").and_then(Value::as_u64),
        Some(1)
    );
    // A second admitted snapshot replaces verbatim with a bumped revision.
    let second = ledger_json(5);
    let request = reactive_ledger_mutation_request("session-1".to_owned(), second.clone());
    apply(&store, "ledger-2", request.operation, request.parameters)
        .expect("second upsert commits");
    let query = reactive_ledger_read_request("session-1".to_owned(), fence()).expect("read");
    let response = store.execute_named_sync(&query).expect("read executes");
    assert_eq!(
        response.payload.get("ledger_json").and_then(Value::as_str),
        Some(second.as_str())
    );
    assert_eq!(
        response.payload.get("revision").and_then(Value::as_u64),
        Some(2)
    );
    // Unknown sessions project explicit absence, never fabricated bytes.
    let query = reactive_ledger_read_request("session-absent".to_owned(), fence()).expect("read");
    let response = store.execute_named_sync(&query).expect("read executes");
    assert!(
        response
            .payload
            .get("ledger_json")
            .is_some_and(Value::is_null)
    );
    assert_eq!(
        response.payload.get("revision").and_then(Value::as_u64),
        Some(0)
    );
}

#[test]
fn snapshot_serves_immutable_bytes_with_convergent_reapply() {
    let store = MemoryStore::new();
    let content = b"canonical report bytes";
    let request = resource_snapshot_mutation_request("eliot://report/r-1".to_owned(), content)
        .expect("snapshot builds");
    apply(&store, "snap-1", request.operation, request.parameters).expect("snapshot commits");
    let query =
        resource_snapshot_read_request("eliot://report/r-1".to_owned(), fence()).expect("read");
    let response = store.execute_named_sync(&query).expect("read executes");
    let encoded = response
        .payload
        .get("content_base64")
        .and_then(Value::as_str)
        .expect("bytes served");
    let sha = response
        .payload
        .get("content_sha256")
        .and_then(Value::as_str)
        .expect("digest served");
    assert_eq!(
        eliot_store_api::decode_resource_content(encoded, sha).expect("bytes decode"),
        content
    );
    assert_eq!(
        response.payload.get("revision").and_then(Value::as_u64),
        Some(1)
    );
    // Identical re-apply converges without a revision move.
    let request = resource_snapshot_mutation_request("eliot://report/r-1".to_owned(), content)
        .expect("snapshot builds");
    apply(&store, "snap-2", request.operation, request.parameters)
        .expect("convergent re-apply commits");
    let query =
        resource_snapshot_read_request("eliot://report/r-1".to_owned(), fence()).expect("read");
    let response = store.execute_named_sync(&query).expect("read executes");
    assert_eq!(
        response.payload.get("revision").and_then(Value::as_u64),
        Some(1),
        "convergent re-apply moves no revision"
    );
    // A rewrite with different bytes fails closed.
    let request =
        resource_snapshot_mutation_request("eliot://report/r-1".to_owned(), b"forged bytes")
            .expect("snapshot builds");
    assert_eq!(
        apply(&store, "snap-3", request.operation, request.parameters),
        Err(StoreError::IdentityConflict)
    );
    // Unknown URIs project explicit absence.
    let query =
        resource_snapshot_read_request("eliot://report/absent".to_owned(), fence()).expect("read");
    let response = store.execute_named_sync(&query).expect("read executes");
    assert!(
        response
            .payload
            .get("content_base64")
            .is_some_and(Value::is_null)
    );
    assert_eq!(
        response.payload.get("revision").and_then(Value::as_u64),
        Some(0)
    );
}

#[test]
fn foreign_contract_bad_uri_and_digest_mismatch_are_rejected() {
    let store = MemoryStore::new();
    let foreign = reactive_ledger_mutation_request(
        "session-1".to_owned(),
        r#"{"contract":"foreign"}"#.to_owned(),
    );
    assert!(
        apply(&store, "neg-1", foreign.operation, foreign.parameters).is_err(),
        "foreign ledger contract is rejected"
    );
    let corrupt = reactive_ledger_mutation_request("session-1".to_owned(), "not json".to_owned());
    assert!(
        apply(&store, "neg-2", corrupt.operation, corrupt.parameters).is_err(),
        "undecodable ledger bytes are rejected"
    );
    let content = b"bytes";
    let mut params = resource_snapshot_mutation_request("eliot://report/r-2".to_owned(), content)
        .expect("snapshot builds")
        .parameters;
    params.insert(
        eliot_store_api::REACTIVE_PARAM_CONTENT_SHA256.to_owned(),
        Value::String("0".repeat(64)),
    );
    assert_eq!(
        apply(
            &store,
            "neg-3",
            NamedMutationOperation::ApplyResourceSnapshot,
            params
        ),
        Err(StoreError::InvalidField {
            field: "reactive.content_sha256",
            reason: "digest does not name the snapshot bytes",
        })
    );
}

#[test]
fn reactive_operations_reject_a_foreign_transition_class() {
    let store = MemoryStore::new();
    let (ctx, mut transition) = transition_with(
        "class-1",
        NamedMutationOperation::ApplyReactiveInjectionState,
        reactive_ledger_mutation_request("session-1".to_owned(), ledger_json(1)).parameters,
    );
    transition.transition_class = TransitionClass::CaptureCandidate;
    transition.requested_effect_ceiling = EffectClass::Candidate;
    assert_eq!(
        store.apply_transaction(&ctx, transition, &[], &[]),
        Err(StoreError::TransitionClassExceeded)
    );
}
