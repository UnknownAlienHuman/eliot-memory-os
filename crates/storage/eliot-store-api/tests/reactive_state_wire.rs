//! Wire contract tests for canonical reactive state (issue #1941 C4).
//!
//! Proves the closed `eliot.reactive.state.v1` contract: catalogue
//! activation with exact names/ceilings/classes, ledger contract/bound
//! validation, I7.18 URI grammar mirroring, digest agreement, and request
//! builders. Durable row semantics are proven through the backend suites.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use eliot_store_api::{
    decode_reactive_mutation, decode_resource_content, encode_resource_content,
    generated_operation_manifests, named_mutation_operation_by_name, named_mutation_operation_name,
    named_read_operation_by_name, named_read_operation_name, reactive_ledger_mutation_request,
    reactive_ledger_read_request, resource_snapshot_mutation_request,
    resource_snapshot_read_request, validate_reactive_mutation_params, validate_resource_uri,
    EffectClass, NamedMutationOperation, NamedReadOperation, OperationKind, StoreError,
    TransitionClass, REACTIVE_LEDGER_CONTRACT_V1, REACTIVE_LEDGER_MUTATION_NAME,
    REACTIVE_LEDGER_READ_NAME, REACTIVE_STATE_SCHEMA_V1, RESOURCE_SNAPSHOT_MUTATION_NAME,
    RESOURCE_SNAPSHOT_READ_NAME,
};
use serde_json::{json, Value};

fn ledger_json(items: u32) -> String {
    let items: Vec<Value> = (0..items)
        .map(|index| json!({"item_id": format!("reactive-item-{index}")}))
        .collect();
    serde_json::to_string(&json!({
        "contract": REACTIVE_LEDGER_CONTRACT_V1,
        "items": items,
    }))
    .expect("fixture serializes")
}

#[test]
fn wire_identity_is_stable_and_versioned() {
    assert_eq!(REACTIVE_STATE_SCHEMA_V1, "eliot.reactive.state.v1");
    assert_eq!(
        REACTIVE_LEDGER_CONTRACT_V1,
        "eliot.agent-bridge.reactive-injection-receipts/v1"
    );
    assert_eq!(
        REACTIVE_LEDGER_MUTATION_NAME,
        named_mutation_operation_name(NamedMutationOperation::ApplyReactiveInjectionState)
    );
    assert_eq!(
        named_mutation_operation_by_name("ApplyReactiveInjectionState"),
        Some(NamedMutationOperation::ApplyReactiveInjectionState)
    );
    assert_eq!(
        RESOURCE_SNAPSHOT_MUTATION_NAME,
        named_mutation_operation_name(NamedMutationOperation::ApplyResourceSnapshot)
    );
    assert_eq!(
        named_mutation_operation_by_name("ApplyResourceSnapshot"),
        Some(NamedMutationOperation::ApplyResourceSnapshot)
    );
    assert_eq!(
        REACTIVE_LEDGER_READ_NAME,
        named_read_operation_name(NamedReadOperation::GetReactiveInjectionState)
    );
    assert_eq!(
        named_read_operation_by_name("GetReactiveInjectionState"),
        Some(NamedReadOperation::GetReactiveInjectionState)
    );
    assert_eq!(
        RESOURCE_SNAPSHOT_READ_NAME,
        named_read_operation_name(NamedReadOperation::GetResourceSnapshot)
    );
    assert_eq!(
        named_read_operation_by_name("GetResourceSnapshot"),
        Some(NamedReadOperation::GetResourceSnapshot)
    );
    assert_eq!(
        NamedMutationOperation::ApplyReactiveInjectionState.transition_class(),
        TransitionClass::ReactiveState
    );
    assert_eq!(
        NamedMutationOperation::ApplyResourceSnapshot.transition_class(),
        TransitionClass::ReactiveState
    );
    assert_eq!(
        TransitionClass::ReactiveState.maximum_effect(),
        EffectClass::ReversibleMutation
    );
}

#[test]
fn catalogue_activates_all_four_reactive_operations() {
    let entries = generated_operation_manifests().unwrap();
    assert_eq!(entries.len(), 24);
    for name in [
        REACTIVE_LEDGER_MUTATION_NAME,
        RESOURCE_SNAPSHOT_MUTATION_NAME,
    ] {
        let mutation = entries
            .iter()
            .find(|entry| entry.name == name)
            .expect("mutation row");
        assert_eq!(mutation.operation_kind, OperationKind::Mutation);
        assert_eq!(mutation.maximum_effect, EffectClass::ReversibleMutation);
        assert!(mutation
            .transition_classes
            .contains(&TransitionClass::ReactiveState));
    }
    for name in [REACTIVE_LEDGER_READ_NAME, RESOURCE_SNAPSHOT_READ_NAME] {
        let read = entries
            .iter()
            .find(|entry| entry.name == name)
            .expect("read row");
        assert_eq!(read.operation_kind, OperationKind::Read);
        assert_eq!(read.maximum_effect, EffectClass::Read);
    }
}

#[test]
fn ledger_mutation_builder_validates_positive_and_negative() {
    let request = reactive_ledger_mutation_request("session-1".to_owned(), ledger_json(2));
    assert_eq!(
        request.operation,
        NamedMutationOperation::ApplyReactiveInjectionState
    );
    validate_reactive_mutation_params(request.operation, &request.parameters).unwrap();
    let decoded = decode_reactive_mutation(request.operation, &request.parameters).unwrap();
    assert!(
        matches!(
            decoded,
            eliot_store_api::DecodedReactiveMutation::ApplyLedger { ref session_id, .. }
            if session_id == "session-1"
        ),
        "decode carries the session selector"
    );
    // Wrong contract stamp fails closed.
    let mut foreign = request.parameters.clone();
    foreign.insert(
        eliot_store_api::REACTIVE_PARAM_LEDGER_JSON.to_owned(),
        Value::String(r#"{"contract":"foreign"}"#.to_owned()),
    );
    assert!(
        validate_reactive_mutation_params(request.operation, &foreign).is_err(),
        "foreign ledger contract is rejected"
    );
    // Undecodable bytes fail closed.
    let mut corrupt = request.parameters.clone();
    corrupt.insert(
        eliot_store_api::REACTIVE_PARAM_LEDGER_JSON.to_owned(),
        Value::String("not json".to_owned()),
    );
    assert!(
        validate_reactive_mutation_params(request.operation, &corrupt).is_err(),
        "undecodable ledger bytes are rejected"
    );
    // Blank session fails closed.
    let mut blank = request.parameters.clone();
    blank.insert(
        eliot_store_api::REACTIVE_PARAM_SESSION_ID.to_owned(),
        Value::String("  ".to_owned()),
    );
    assert!(
        validate_reactive_mutation_params(request.operation, &blank).is_err(),
        "blank session is rejected"
    );
    // Missing ledger fails closed.
    let mut missing = request.parameters.clone();
    missing.remove(eliot_store_api::REACTIVE_PARAM_LEDGER_JSON);
    assert!(
        validate_reactive_mutation_params(request.operation, &missing).is_err(),
        "missing ledger is rejected"
    );
    // Unknown operation fails closed.
    assert_eq!(
        validate_reactive_mutation_params(
            NamedMutationOperation::CaptureObservation,
            &request.parameters
        ),
        Err(StoreError::UnknownOperation)
    );
}

#[test]
fn ledger_read_builder_selects_exact_session() {
    let fence = test_fence();
    let request = reactive_ledger_read_request("session-9".to_owned(), fence.clone()).unwrap();
    assert_eq!(
        request.operation,
        NamedReadOperation::GetReactiveInjectionState
    );
    assert_eq!(request.state_fence, fence);
    assert!(request.scope_id.is_none());
    let selected =
        eliot_store_api::validate_reactive_ledger_read_params(&request.parameters).unwrap();
    assert_eq!(selected, "session-9");
    let mut blank = BTreeMap::new();
    blank.insert(
        eliot_store_api::REACTIVE_PARAM_SESSION_ID.to_owned(),
        Value::String(String::new()),
    );
    assert!(
        eliot_store_api::validate_reactive_ledger_read_params(&blank).is_err(),
        "blank read selector is rejected"
    );
}

#[test]
fn snapshot_mutation_builder_proves_digest_agreement() {
    let content = b"canonical report bytes";
    let request =
        resource_snapshot_mutation_request("eliot://report/r-1".to_owned(), content).unwrap();
    assert_eq!(
        request.operation,
        NamedMutationOperation::ApplyResourceSnapshot
    );
    validate_reactive_mutation_params(request.operation, &request.parameters).unwrap();
    let decoded = decode_reactive_mutation(request.operation, &request.parameters).unwrap();
    let (uri, sha, encoded) = match decoded {
        eliot_store_api::DecodedReactiveMutation::ApplySnapshot {
            uri,
            content_sha256,
            content_base64,
        } => (uri, content_sha256, content_base64),
        other => panic!("wrong decode leg: {other:?}"),
    };
    assert_eq!(uri, "eliot://report/r-1");
    assert_eq!(decode_resource_content(&encoded, &sha).unwrap(), content);
    // Tampered digest fails closed.
    let mut tampered = request.parameters.clone();
    tampered.insert(
        eliot_store_api::REACTIVE_PARAM_CONTENT_SHA256.to_owned(),
        Value::String("0".repeat(64)),
    );
    assert!(
        validate_reactive_mutation_params(request.operation, &tampered).is_err(),
        "digest mismatch is rejected"
    );
    // Non-canonical URI fails closed.
    let bad_uri = resource_snapshot_mutation_request("https://x/1".to_owned(), content);
    assert!(bad_uri.is_ok(), "builder carries bytes; validation rejects");
    assert!(
        validate_reactive_mutation_params(
            NamedMutationOperation::ApplyResourceSnapshot,
            &bad_uri.unwrap().parameters
        )
        .is_err(),
        "non-canonical URI is rejected"
    );
    // Oversize content fails closed at the builder.
    let big = vec![b'a'; eliot_store_api::MAX_RESOURCE_CONTENT_BYTES + 1];
    assert!(
        resource_snapshot_mutation_request("eliot://report/r-1".to_owned(), &big).is_err(),
        "oversize content is rejected"
    );
    assert!(
        encode_resource_content(&[]).is_err(),
        "empty content is rejected"
    );
}

#[test]
fn snapshot_read_builder_selects_exact_uri() {
    let fence = test_fence();
    let request =
        resource_snapshot_read_request("eliot://task/t-1/packet/r-7".to_owned(), fence.clone())
            .unwrap();
    assert_eq!(request.operation, NamedReadOperation::GetResourceSnapshot);
    assert_eq!(request.state_fence, fence);
    let selected =
        eliot_store_api::validate_resource_snapshot_read_params(&request.parameters).unwrap();
    assert_eq!(selected, "eliot://task/t-1/packet/r-7");
}

#[test]
fn uri_grammar_mirrors_the_ten_canonical_forms() {
    for raw in [
        "eliot://scope/s-1/state",
        "eliot://task/t-1/packet/r-7",
        "eliot://evidence/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "eliot://conflict/c-1",
        "eliot://problem/p-1",
        "eliot://session/s-1/attention",
        "eliot://session/s-1/mailbox",
        "eliot://job/j-1/result",
        "eliot://report/r-1",
        "eliot://architecture/0.29-draft/anchor",
    ] {
        assert!(
            validate_resource_uri(raw).is_ok(),
            "accepts canonical form: {raw}"
        );
    }
    for raw in [
        "https://evidence/1",
        "eliot://evidence/",
        "eliot://task/t-1/packet",
        "eliot://task/t-1",
        "eliot://architecture/anchor",
        "eliot://unknown/1",
        "eliot://evidence/../escape",
        "eliot://report/",
        "",
    ] {
        assert!(
            validate_resource_uri(raw).is_err(),
            "rejects violation: {raw}"
        );
    }
}

fn test_fence() -> eliot_store_api::StateFence {
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;
    eliot_store_api::StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap(),
        ResourceGeneration::new(1).unwrap(),
    )
}
