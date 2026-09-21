//! Wire contract tests for canonical notification state (issue #1780).
//!
//! Proves the closed `eliot.notify.state.v1` contract: catalogue activation
//! with exact names/ceilings/classes, leg-discriminated parameter validation,
//! and request builders. Semantic transitions are proven against the shared
//! kernel-core model through the backend suites.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_store_api::{
    EffectClass, MAX_NOTIFICATION_PAGE_LIMIT, NOTIFICATION_STATE_MUTATION_NAME,
    NOTIFICATION_STATE_READ_NAME, NOTIFICATION_STATE_SCHEMA_V1, NOTIFY_MUTATION_DELIVERY,
    NOTIFY_MUTATION_UPSERT, NOTIFY_PARAM_CHANNEL, NOTIFY_PARAM_DEDUP_KEY,
    NOTIFY_PARAM_DELIVERY_JSON, NOTIFY_PARAM_MUTATION, NOTIFY_PARAM_NOTIFICATION_ID,
    NOTIFY_PARAM_RECORD_JSON, NOTIFY_PARAM_SOURCE_RECEIPT_JSON, NamedMutationOperation,
    NamedReadOperation, OperationKind, ParameterShape, StoreError, TransitionClass,
    generated_operation_manifests, named_mutation_operation_by_name, named_mutation_operation_name,
    named_read_operation_by_name, named_read_operation_name, notification_mutation_request,
    notification_read_request, validate_notification_mutation_params,
};
use serde_json::{Value, json};

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new(LINEAGE).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap(),
        ResourceGeneration::new(1).unwrap(),
    )
}

fn record_json() -> Value {
    json!({
        "notification_id": "notification-1",
        "severity": "WARNING",
        "subject": "subject",
        "summary": "summary",
        "evidence_handles": ["evidence-1"],
        "affected_scope": "scope-1",
        "owner": "owner-1",
        "required_action": "review",
        "deadline_or_review": null,
        "dedup_key": "disk-full",
        "delivery_channels": ["CONTROL_BOARD"],
        "state_fence": serde_json::to_value(fence()).unwrap(),
    })
}

fn receipt_json() -> Value {
    json!({"identity": {"receipt_id": "receipt-1", "canonical_sha256": "a".repeat(64)}})
}

fn upsert_params() -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            NOTIFY_PARAM_MUTATION.to_owned(),
            Value::String(NOTIFY_MUTATION_UPSERT.to_owned()),
        ),
        (
            NOTIFY_PARAM_DEDUP_KEY.to_owned(),
            Value::String("disk-full".to_owned()),
        ),
        (NOTIFY_PARAM_RECORD_JSON.to_owned(), record_json()),
        (NOTIFY_PARAM_SOURCE_RECEIPT_JSON.to_owned(), receipt_json()),
    ])
}

#[test]
fn wire_identity_is_stable_and_versioned() {
    assert_eq!(NOTIFICATION_STATE_SCHEMA_V1, "eliot.notify.state.v1");
    assert_eq!(
        ParameterShape::NotificationState.code(),
        "eliot.notify.state.v1"
    );
    assert_eq!(
        NOTIFICATION_STATE_MUTATION_NAME,
        named_mutation_operation_name(NamedMutationOperation::ApplyNotificationState)
    );
    assert_eq!(
        named_mutation_operation_by_name("ApplyNotificationState"),
        Some(NamedMutationOperation::ApplyNotificationState)
    );
    assert_eq!(
        NOTIFICATION_STATE_READ_NAME,
        named_read_operation_name(NamedReadOperation::GetNotificationState)
    );
    assert_eq!(
        named_read_operation_by_name("GetNotificationState"),
        Some(NamedReadOperation::GetNotificationState)
    );
    assert_eq!(
        NamedMutationOperation::ApplyNotificationState.transition_class(),
        TransitionClass::NotificationState
    );
    assert_eq!(
        TransitionClass::NotificationState.maximum_effect(),
        EffectClass::ReversibleMutation
    );
}

#[test]
fn catalogue_activates_both_notification_operations() {
    let entries = generated_operation_manifests().unwrap();
    assert_eq!(entries.len(), 24);
    let mutation = entries
        .iter()
        .find(|entry| entry.name == "ApplyNotificationState")
        .expect("mutation row");
    assert_eq!(mutation.operation_kind, OperationKind::Mutation);
    assert_eq!(mutation.maximum_effect, EffectClass::ReversibleMutation);
    assert!(
        mutation
            .transition_classes
            .contains(&TransitionClass::NotificationState)
    );
    let read = entries
        .iter()
        .find(|entry| entry.name == "GetNotificationState")
        .expect("read row");
    assert_eq!(read.operation_kind, OperationKind::Read);
    assert_eq!(read.maximum_effect, EffectClass::Read);
}

#[test]
fn upsert_leg_validates_and_other_legs_fail_without_payloads() {
    validate_notification_mutation_params(&upsert_params()).unwrap();
    let request = notification_mutation_request(upsert_params());
    assert_eq!(
        request.operation,
        NamedMutationOperation::ApplyNotificationState
    );
    request.validate().unwrap();

    let mut missing_leg = upsert_params();
    missing_leg.remove(NOTIFY_PARAM_MUTATION);
    assert!(validate_notification_mutation_params(&missing_leg).is_err());

    let mut unknown_leg = upsert_params();
    unknown_leg.insert(
        NOTIFY_PARAM_MUTATION.to_owned(),
        Value::String("SNOOZE".to_owned()),
    );
    assert_eq!(
        validate_notification_mutation_params(&unknown_leg),
        Err(StoreError::UnknownOperation)
    );

    let mut delivery = BTreeMap::from([
        (
            NOTIFY_PARAM_MUTATION.to_owned(),
            Value::String(NOTIFY_MUTATION_DELIVERY.to_owned()),
        ),
        (
            NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
            Value::String("notification-1".to_owned()),
        ),
    ]);
    assert!(validate_notification_mutation_params(&delivery).is_err());
    delivery.insert(
        NOTIFY_PARAM_CHANNEL.to_owned(),
        Value::String("PIGEON".to_owned()),
    );
    assert!(validate_notification_mutation_params(&delivery).is_err());
    delivery.insert(
        NOTIFY_PARAM_CHANNEL.to_owned(),
        Value::String("NATIVE_TOAST".to_owned()),
    );
    delivery.insert(
        NOTIFY_PARAM_DELIVERY_JSON.to_owned(),
        json!({"kind": "DELIVERED"}),
    );
    validate_notification_mutation_params(&delivery).unwrap();
}

#[test]
fn read_builder_enforces_bounds() {
    notification_read_request(None, None, None, true, 10, None, fence()).unwrap();
    assert!(notification_read_request(None, None, None, true, 0, None, fence()).is_err());
    assert!(
        notification_read_request(
            None,
            None,
            None,
            true,
            MAX_NOTIFICATION_PAGE_LIMIT + 1,
            None,
            fence()
        )
        .is_err()
    );
}
