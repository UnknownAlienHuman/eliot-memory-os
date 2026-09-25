//! Wire contract tests for canonical user-automation state (issue #1779).
//!
//! Proves the closed `eliot.automation.state.v1` contract: catalogue
//! activation with exact names/ceilings/classes, leg-discriminated
//! parameter validation, query decoding, and request builders. Revision
//! lineage and invocation semantics stay Kernel-owned; durable row
//! semantics are proven through the backend suites.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use eliot_store_api::{
    AUTOMATION_OPERATION_CREATE, AUTOMATION_OPERATION_PAUSE, AUTOMATION_OPERATION_REMOVE,
    AUTOMATION_OPERATION_RESUME, AUTOMATION_OPERATION_RUN_NOW, AUTOMATION_QUERY_CURRENT,
    AUTOMATION_QUERY_FAILURE, AUTOMATION_QUERY_HISTORY, AUTOMATION_QUERY_INVOCATIONS,
    AUTOMATION_QUERY_LIST, AUTOMATION_STATE_ACTIVE, AUTOMATION_STATE_PAUSED,
    AUTOMATION_STATE_RETIRED, DecodedAutomationMutation, EffectClass, MAX_AUTOMATION_PAGE_RECORDS,
    NamedMutationOperation, NamedReadOperation, OperationKind, StoreError, TransitionClass,
    USER_AUTOMATION_MUTATION_NAME, USER_AUTOMATION_READ_NAME, USER_AUTOMATION_SCOPE,
    USER_AUTOMATION_STATE_SCHEMA_V1, automation_create_params, automation_edit_params,
    automation_mutation_request, automation_read_request, automation_run_now_params,
    automation_state_transition_params, decode_automation_mutation, generated_operation_manifests,
    is_configuration_state_wire, named_mutation_operation_by_name, named_mutation_operation_name,
    named_read_operation_by_name, named_read_operation_name, validate_automation_mutation_params,
    validate_automation_read_params,
};
use serde_json::{Value, json};

fn revision_json(automation_id: &str, revision: &str) -> String {
    serde_json::to_string(&json!({
        "automation_id": automation_id,
        "revision": revision,
        "configuration_state": "ACTIVE",
    }))
    .expect("fixture serializes")
}

fn invocation_json(automation_id: &str, revision: &str, nonce: &str) -> String {
    serde_json::to_string(&json!({
        "automation_id": automation_id,
        "automation_revision": revision,
        "trigger": {"kind": "manual", "nonce": nonce},
        "trigger_origin": "HUMAN",
    }))
    .expect("fixture serializes")
}

#[test]
fn wire_identity_is_stable_and_versioned() {
    assert_eq!(USER_AUTOMATION_STATE_SCHEMA_V1, "eliot.automation.state.v1");
    assert_eq!(USER_AUTOMATION_SCOPE, "user-automation");
    assert_eq!(
        USER_AUTOMATION_MUTATION_NAME,
        named_mutation_operation_name(NamedMutationOperation::ApplyUserAutomationState)
    );
    assert_eq!(
        named_mutation_operation_by_name("ApplyUserAutomationState"),
        Some(NamedMutationOperation::ApplyUserAutomationState)
    );
    assert_eq!(
        USER_AUTOMATION_READ_NAME,
        named_read_operation_name(NamedReadOperation::GetUserAutomationState)
    );
    assert_eq!(
        named_read_operation_by_name("GetUserAutomationState"),
        Some(NamedReadOperation::GetUserAutomationState)
    );
    assert_eq!(
        NamedMutationOperation::ApplyUserAutomationState.transition_class(),
        TransitionClass::UserAutomation
    );
    assert_eq!(
        TransitionClass::UserAutomation.maximum_effect(),
        EffectClass::ReversibleMutation
    );
    for state in [
        AUTOMATION_STATE_ACTIVE,
        AUTOMATION_STATE_PAUSED,
        "BLOCKED_CONFIG",
        AUTOMATION_STATE_RETIRED,
    ] {
        assert!(is_configuration_state_wire(state), "closed state: {state}");
    }
    assert!(!is_configuration_state_wire("active"));
    assert!(!is_configuration_state_wire("ARCHIVED"));
}

#[test]
fn catalogue_activates_both_automation_operations() {
    let entries = generated_operation_manifests().unwrap();
    assert_eq!(entries.len(), 33);
    let mutation = entries
        .iter()
        .find(|entry| entry.name == "ApplyUserAutomationState")
        .expect("mutation row");
    assert_eq!(mutation.operation_kind, OperationKind::Mutation);
    assert_eq!(mutation.maximum_effect, EffectClass::ReversibleMutation);
    assert!(
        mutation
            .transition_classes
            .contains(&TransitionClass::UserAutomation)
    );
    let read = entries
        .iter()
        .find(|entry| entry.name == "GetUserAutomationState")
        .expect("read row");
    assert_eq!(read.operation_kind, OperationKind::Read);
    assert_eq!(read.maximum_effect, EffectClass::Read);
}

#[test]
fn create_and_edit_legs_validate_positive_and_negative() {
    let params = automation_create_params(
        "auto-1".to_owned(),
        "r-1".to_owned(),
        AUTOMATION_STATE_ACTIVE.to_owned(),
        revision_json("auto-1", "r-1"),
    );
    assert_eq!(
        params
            .get(eliot_store_api::AUTOMATION_PARAM_OPERATION)
            .and_then(Value::as_str),
        Some(AUTOMATION_OPERATION_CREATE),
        "create discriminator spelling is pinned"
    );
    let request = automation_mutation_request(params);
    assert_eq!(
        request.operation,
        NamedMutationOperation::ApplyUserAutomationState
    );
    validate_automation_mutation_params(request.operation, &request.parameters).unwrap();
    let decoded = decode_automation_mutation(request.operation, &request.parameters).unwrap();
    assert!(
        matches!(
            decoded,
            DecodedAutomationMutation::Create { ref automation_id, ref revision, .. }
            if automation_id == "auto-1" && revision == "r-1"
        ),
        "decode carries the create leg"
    );
    // Edit requires the superseded base.
    let mut edit = automation_edit_params(
        "auto-1".to_owned(),
        "r-1".to_owned(),
        "r-2".to_owned(),
        AUTOMATION_STATE_ACTIVE.to_owned(),
        revision_json("auto-1", "r-2"),
    );
    validate_automation_mutation_params(NamedMutationOperation::ApplyUserAutomationState, &edit)
        .unwrap();
    edit.remove(eliot_store_api::AUTOMATION_PARAM_PREVIOUS_REVISION);
    assert!(
        validate_automation_mutation_params(
            NamedMutationOperation::ApplyUserAutomationState,
            &edit
        )
        .is_err(),
        "edit without lineage base is rejected"
    );
    // Unknown discriminator fails closed.
    let mut foreign: BTreeMap<String, Value> = BTreeMap::from([
        (
            eliot_store_api::AUTOMATION_PARAM_OPERATION.to_owned(),
            Value::String("launch".to_owned()),
        ),
        (
            eliot_store_api::AUTOMATION_PARAM_AUTOMATION_ID.to_owned(),
            Value::String("auto-1".to_owned()),
        ),
    ]);
    assert_eq!(
        validate_automation_mutation_params(
            NamedMutationOperation::ApplyUserAutomationState,
            &foreign
        ),
        Err(StoreError::UnknownOperation)
    );
    // Non-object documents fail closed.
    foreign.insert(
        eliot_store_api::AUTOMATION_PARAM_OPERATION.to_owned(),
        Value::String(AUTOMATION_OPERATION_CREATE.to_owned()),
    );
    foreign.insert(
        eliot_store_api::AUTOMATION_PARAM_REVISION.to_owned(),
        Value::String("r-1".to_owned()),
    );
    foreign.insert(
        eliot_store_api::AUTOMATION_PARAM_CONFIGURATION_STATE.to_owned(),
        Value::String(AUTOMATION_STATE_ACTIVE.to_owned()),
    );
    foreign.insert(
        eliot_store_api::AUTOMATION_PARAM_REVISION_JSON.to_owned(),
        Value::String("[1,2]".to_owned()),
    );
    assert!(
        validate_automation_mutation_params(
            NamedMutationOperation::ApplyUserAutomationState,
            &foreign
        )
        .is_err(),
        "non-object revision documents are rejected"
    );
    // Unknown operation fails closed.
    assert_eq!(
        validate_automation_mutation_params(
            NamedMutationOperation::CaptureObservation,
            &automation_create_params(
                "auto-1".to_owned(),
                "r-1".to_owned(),
                AUTOMATION_STATE_ACTIVE.to_owned(),
                revision_json("auto-1", "r-1"),
            )
        ),
        Err(StoreError::UnknownOperation)
    );
}

#[test]
fn state_transition_and_run_now_legs_validate() {
    for (leg, state) in [
        (AUTOMATION_OPERATION_PAUSE, AUTOMATION_STATE_PAUSED),
        (AUTOMATION_OPERATION_RESUME, AUTOMATION_STATE_ACTIVE),
        (AUTOMATION_OPERATION_REMOVE, AUTOMATION_STATE_RETIRED),
    ] {
        let params = automation_state_transition_params(
            leg.to_owned(),
            "auto-1".to_owned(),
            "r-1".to_owned(),
            state.to_owned(),
        );
        validate_automation_mutation_params(
            NamedMutationOperation::ApplyUserAutomationState,
            &params,
        )
        .unwrap();
        let decoded =
            decode_automation_mutation(NamedMutationOperation::ApplyUserAutomationState, &params)
                .unwrap();
        assert!(
            matches!(
                decoded,
                DecodedAutomationMutation::StateTransition { ref operation, .. }
                if operation == leg
            ),
            "decode carries the transition leg"
        );
    }
    // State legs carry no revision document.
    let mut pause = automation_state_transition_params(
        AUTOMATION_OPERATION_PAUSE.to_owned(),
        "auto-1".to_owned(),
        "r-1".to_owned(),
        AUTOMATION_STATE_PAUSED.to_owned(),
    );
    pause.insert(
        eliot_store_api::AUTOMATION_PARAM_REVISION_JSON.to_owned(),
        Value::String(revision_json("auto-1", "r-1")),
    );
    assert!(
        validate_automation_mutation_params(
            NamedMutationOperation::ApplyUserAutomationState,
            &pause
        )
        .is_ok(),
        "declaration admits the field; legs ignore it"
    );
    let params = automation_run_now_params(
        "auto-1".to_owned(),
        "r-1".to_owned(),
        "user-automation-occurrence:abc".to_owned(),
        invocation_json("auto-1", "r-1", "nonce-7"),
    );
    assert_eq!(
        params
            .get(eliot_store_api::AUTOMATION_PARAM_OPERATION)
            .and_then(Value::as_str),
        Some(AUTOMATION_OPERATION_RUN_NOW),
        "run-now discriminator spelling is pinned"
    );
    validate_automation_mutation_params(NamedMutationOperation::ApplyUserAutomationState, &params)
        .unwrap();
    let decoded =
        decode_automation_mutation(NamedMutationOperation::ApplyUserAutomationState, &params)
            .unwrap();
    assert!(
        matches!(decoded, DecodedAutomationMutation::RunNow { .. }),
        "decode carries the run-now leg"
    );
    // Unknown admission state fails closed.
    let bad_state = automation_state_transition_params(
        AUTOMATION_OPERATION_PAUSE.to_owned(),
        "auto-1".to_owned(),
        "r-1".to_owned(),
        "SUSPENDED".to_owned(),
    );
    assert!(
        validate_automation_mutation_params(
            NamedMutationOperation::ApplyUserAutomationState,
            &bad_state
        )
        .is_err(),
        "unknown admission state is rejected"
    );
    assert!(
        decode_automation_mutation(
            NamedMutationOperation::ApplyUserAutomationState,
            &automation_edit_params(
                "auto-1".to_owned(),
                "r-1".to_owned(),
                "r-2".to_owned(),
                AUTOMATION_STATE_ACTIVE.to_owned(),
                revision_json("auto-1", "r-2"),
            )
        )
        .is_ok_and(|decoded| matches!(
            decoded,
            DecodedAutomationMutation::Edit { ref previous_revision, .. }
            if previous_revision == "r-1"
        )),
        "edit decode carries the lineage base"
    );
}

#[test]
fn read_queries_decode_with_closed_selectors() {
    let fence = test_fence();
    let request = automation_read_request(
        AUTOMATION_QUERY_LIST.to_owned(),
        None,
        false,
        64,
        fence.clone(),
    )
    .unwrap();
    assert_eq!(
        request.operation,
        NamedReadOperation::GetUserAutomationState
    );
    let decoded = validate_automation_read_params(&request.parameters).unwrap();
    assert_eq!(decoded.query, AUTOMATION_QUERY_LIST);
    assert_eq!(decoded.automation_id, None);
    assert!(!decoded.include_retired);
    assert_eq!(decoded.max_records, 64);
    for query in [
        AUTOMATION_QUERY_CURRENT,
        AUTOMATION_QUERY_HISTORY,
        AUTOMATION_QUERY_INVOCATIONS,
        AUTOMATION_QUERY_FAILURE,
    ] {
        let request = automation_read_request(
            query.to_owned(),
            Some("auto-1".to_owned()),
            false,
            10,
            fence.clone(),
        )
        .unwrap();
        let decoded = validate_automation_read_params(&request.parameters).unwrap();
        assert_eq!(decoded.query, query);
        assert_eq!(decoded.automation_id.as_deref(), Some("auto-1"));
    }
    // Non-list queries require the exact selector.
    let request =
        automation_read_request(AUTOMATION_QUERY_CURRENT.to_owned(), None, false, 10, fence)
            .unwrap();
    assert!(
        validate_automation_read_params(&request.parameters).is_err(),
        "selector-less current read is rejected"
    );
    // Over-bound pages fail closed.
    let over = automation_read_request(
        AUTOMATION_QUERY_LIST.to_owned(),
        None,
        false,
        MAX_AUTOMATION_PAGE_RECORDS + 1,
        test_fence(),
    )
    .unwrap();
    assert!(
        validate_automation_read_params(&over.parameters).is_err(),
        "over-bound pages are rejected"
    );
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
