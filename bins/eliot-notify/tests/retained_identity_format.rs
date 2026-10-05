//! Fail-closed retained identity reconstruction regressions for issue #78.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
    ResourceGeneration, SessionId, SourceId, StateFence,
};
use eliot_notify::operation_identity::{
    ChildLineageEntry, NotifyIdentityIssuer, NotifyOperation, OperationIdentityError,
};
use eliot_platform::{NotificationRequest, PlatformHandle};
use serde_json::{Value, json};

const NOW: u64 = 1_786_000_000_000;
const PARENT_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_PARENT_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const BODY_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn fence() -> StateFence {
    fence_at(1)
}

fn fence_at(sequence: u64) -> StateFence {
    let lineage = EpochLineageId::new(LINEAGE).expect("test lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(sequence).expect("non-zero")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn parent_with_id(id: &str) -> NotificationRequest {
    let now = i64::try_from(NOW).expect("now fits");
    NotificationRequest {
        context: RequestMetadata {
            request_id: RequestId::new(id).expect("request id"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("notify-test-product").expect("product"),
            source_id: SourceId::new("notify-test-source").expect("source"),
            state_fence: fence(),
            clock: ClockReading {
                valid_time_ms: Some(now),
                known_time_ms: Some(now),
                ..ClockReading::default()
            },
        },
        canonical_request_hash: PlatformHandle::new(PARENT_HASH).expect("parent hash"),
        notification: PlatformHandle::new("notification-1").expect("notification"),
        audience: PlatformHandle::new("audience-1").expect("audience"),
        body_digest: PlatformHandle::new(BODY_DIGEST).expect("body"),
    }
}

fn payload(marker: &str) -> Value {
    json!({"step": marker, "parent": PARENT_HASH})
}

fn assert_restore_is_incomplete_without_mutation(
    parent: &NotificationRequest,
    child_payload: &Value,
    retained: &ChildLineageEntry,
) {
    let mut restarted = NotifyIdentityIssuer::new();
    let restored = restarted.restore_issued(
        parent,
        NotifyOperation::G08Verify,
        child_payload,
        None,
        retained,
        NOW + 1,
    );
    assert!(
        matches!(restored, Err(OperationIdentityError::IncompleteRecord(_))),
        "contradictory or incomplete retained identity must fail closed, got {restored:?}"
    );
    assert_eq!(restarted.issued_count(), 0);
    assert!(restarted.lineage().is_empty());
}

#[test]
fn restore_rejects_cancellation_projection_mismatch_without_mutating_issuer() {
    let parent = parent_with_id("parent-cancel-projection");
    let child_payload = payload("g08");
    let mut original_issuer = NotifyIdentityIssuer::new();
    original_issuer
        .issue_g08(&parent, &child_payload, NOW)
        .expect("issue original child");
    let mut retained = original_issuer
        .lineage()
        .last()
        .expect("issued child has lineage")
        .clone();

    // The serialized record has two projections of the cancellation identity.
    // A contradiction between them is malformed recovery material.
    retained.cancellation_id = "contradictory-cancellation-id".to_owned();

    let mut restarted = NotifyIdentityIssuer::new();
    let restored = restarted.restore_issued(
        &parent,
        NotifyOperation::G08Verify,
        &child_payload,
        None,
        &retained,
        NOW + 1,
    );
    assert!(
        matches!(restored, Err(OperationIdentityError::IncompleteRecord(_))),
        "contradictory retained cancellation projection must fail closed, got {restored:?}"
    );
    assert_eq!(restarted.issued_count(), 0);
    assert!(restarted.lineage().is_empty());
}

#[test]
fn restore_preserves_exact_notification_state_read_identity() {
    let parent = parent_with_id("parent-state-read-restore");
    let child_payload = payload("notification-state-read");
    let mut original_issuer = NotifyIdentityIssuer::new();
    let original = original_issuer
        .issue_notification_state_read(&parent, &child_payload, NOW)
        .expect("issue read step");
    let retained = original_issuer
        .lineage()
        .last()
        .expect("issued read step has lineage")
        .clone();

    let mut restarted = NotifyIdentityIssuer::new();
    let restored = restarted
        .restore_issued(
            &parent,
            NotifyOperation::NotificationStateRead,
            &child_payload,
            None,
            &retained,
            NOW + 1,
        )
        .expect("restore uses the exact read operation, not the shared selector alone");

    assert_eq!(restored.operation, NotifyOperation::NotificationStateRead);
    assert_eq!(restored.identity, original.identity);
    assert_eq!(restored.request_id, original.request_id);
    assert_eq!(restarted.issued_count(), 1);
    assert_eq!(restarted.lineage(), &[retained]);
}

#[test]
fn state_read_and_mutation_with_same_payload_get_distinct_identities() {
    let parent = parent_with_id("parent-state-read-vs-mutation");
    let child_payload = payload("same-state-bytes");
    let mut issuer = NotifyIdentityIssuer::new();
    let mutation = issuer
        .issue_notification_state(&parent, &child_payload, None, NOW)
        .expect("issue state mutation");
    let read = issuer
        .issue_notification_state_read(&parent, &child_payload, NOW + 1)
        .expect("issue state read");

    assert_ne!(mutation.identity, read.identity);
    assert_ne!(mutation.request_id, read.request_id);
    assert_ne!(
        mutation.identity.idempotency_key,
        read.identity.idempotency_key
    );
    assert_ne!(
        mutation.identity.cancellation_id,
        read.identity.cancellation_id
    );
    assert_eq!(mutation.operation, NotifyOperation::NotificationState);
    assert_eq!(read.operation, NotifyOperation::NotificationStateRead);
    assert_eq!(issuer.issued_count(), 2);
    assert_eq!(issuer.lineage().len(), 2);
}

#[test]
fn reused_state_operation_key_conflicts_without_mutating_issuer() {
    let parent = parent_with_id("parent-state-operation-key-conflict");
    let child_payload = payload("same-state-bytes");
    let shared_key = "caller-selected-notification-state-key";
    let mut issuer = NotifyIdentityIssuer::new();
    issuer
        .issue_with_idempotency_key(
            &parent,
            NotifyOperation::NotificationState,
            &child_payload,
            shared_key,
            None,
            NOW,
        )
        .expect("issue mutation under caller key");

    let read = issuer.issue_with_idempotency_key(
        &parent,
        NotifyOperation::NotificationStateRead,
        &child_payload,
        shared_key,
        None,
        NOW + 1,
    );
    assert!(
        matches!(read, Err(OperationIdentityError::IdentityConflict(_))),
        "one idempotency key cannot cross mutation/read operations, got {read:?}"
    );
    assert_eq!(issuer.issued_count(), 1);
    assert_eq!(issuer.lineage().len(), 1);
}

#[test]
fn restore_rejects_parent_session_or_fence_contradictions_without_mutation() {
    let parent = parent_with_id("parent-context-consistency");
    let child_payload = payload("g08-context-consistency");
    let mut original_issuer = NotifyIdentityIssuer::new();
    original_issuer
        .issue_g08(&parent, &child_payload, NOW)
        .expect("issue original child");
    let retained = original_issuer
        .lineage()
        .last()
        .expect("issued child has lineage")
        .clone();

    // Parent request and canonical hash are immutable bindings, not caller-
    // editable lineage labels.
    let mut wrong_parent_request = retained.clone();
    wrong_parent_request.parent_request_id = "different-parent-context".to_owned();
    assert_restore_is_incomplete_without_mutation(&parent, &child_payload, &wrong_parent_request);

    let mut wrong_parent_hash = retained.clone();
    wrong_parent_hash.parent_hash = OTHER_PARENT_HASH.to_owned();
    assert_restore_is_incomplete_without_mutation(&parent, &child_payload, &wrong_parent_hash);

    // Session metadata belongs to the parent binding and cannot be rewritten
    // inside a retained identity independently of that parent.
    let mut wrong_session = retained.clone();
    wrong_session.identity.request.metadata.session_id =
        Some(SessionId::new("different-session").expect("session id"));
    assert_restore_is_incomplete_without_mutation(&parent, &child_payload, &wrong_session);

    // A serialized identity cannot move to another authority/resource
    // generation, even when its internal fence projections still agree.
    let mut wrong_fence = retained;
    let other_fence = fence_at(2);
    wrong_fence.identity.request.state_fence = other_fence.clone();
    wrong_fence.identity.request.metadata.state_fence = other_fence;
    assert_restore_is_incomplete_without_mutation(&parent, &child_payload, &wrong_fence);
}

#[test]
fn restore_rejects_incomplete_original_issuance_clock_without_mutation() {
    let parent = parent_with_id("parent-incomplete-clock");
    let child_payload = payload("g08-incomplete-clock");
    let mut original_issuer = NotifyIdentityIssuer::new();
    original_issuer
        .issue_g08(&parent, &child_payload, NOW)
        .expect("issue original child");
    let retained = original_issuer
        .lineage()
        .last()
        .expect("issued child has lineage")
        .clone();

    let mut missing_valid_time = retained.clone();
    missing_valid_time
        .identity
        .request
        .metadata
        .clock
        .valid_time_ms = None;
    assert_restore_is_incomplete_without_mutation(&parent, &child_payload, &missing_valid_time);

    let mut missing_known_time = retained;
    missing_known_time
        .identity
        .request
        .metadata
        .clock
        .known_time_ms = None;
    assert_restore_is_incomplete_without_mutation(&parent, &child_payload, &missing_known_time);
}
