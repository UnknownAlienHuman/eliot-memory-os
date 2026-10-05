//! Parent-to-child identity proof for issue #78.
//!
//! One stable parent notification intent derives a distinct versioned child
//! per Kernel step (G-08 verify, A-08 admit, Watchdog verify, delivery
//! verify, ledger reserve, ledger commit). Exact retry reuses the child;
//! cross-step or cross-payload reuse fails `IDENTITY_CONFLICT` before any
//! Kernel effect; reserve and commit never share an identity; per-step
//! cancellation is isolated; serialized retained records restore the complete
//! original identity through the issuer API. This test does not establish a
//! durable owner for those records in the normal notification path.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::num::NonZeroU64;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
    ResourceGeneration, SourceId, StateFence,
};
use eliot_notify::operation_identity::{
    ChildLineageEntry, IssuedIdentity, NOTIFY_IDENTITY_VERSION, NotifyIdentityIssuer,
    NotifyOperation, OperationIdentityError,
};
use eliot_platform::{NotificationRequest, PlatformHandle};
use serde_json::{Value, json};

const NOW: u64 = 1_786_000_000_000;
const PARENT_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BODY_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn fence() -> StateFence {
    let lineage = EpochLineageId::new(LINEAGE).expect("test lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("epoch");
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

fn retained_restore_scenarios(
    parent: &NotificationRequest,
) -> [(NotifyOperation, Value, Option<&'static str>); 10] {
    // Markers and prior digests mirror operation_identity.rs fixtures. The
    // quiet-hours payload matches the request envelope built in lib.rs.
    [
        (NotifyOperation::G08Verify, payload("g08"), None),
        (
            NotifyOperation::A08Admit,
            payload("a08"),
            Some("source-digest"),
        ),
        (NotifyOperation::WatchdogVerify, payload("watchdog"), None),
        (
            NotifyOperation::DeliveryVerify,
            payload("delivery"),
            Some("admission-digest"),
        ),
        (
            NotifyOperation::LedgerReserve,
            payload("reserve"),
            Some("admission-digest"),
        ),
        (
            NotifyOperation::LedgerCommit,
            payload("commit"),
            Some("reservation-digest"),
        ),
        (
            NotifyOperation::NotificationState,
            payload("state"),
            Some("source-digest"),
        ),
        (
            NotifyOperation::NotificationStateRead,
            payload("read"),
            None,
        ),
        (
            NotifyOperation::QuietHoursProjectionRead,
            json!({
                "operation": eliot_notify::operation_identity::QUIET_HOURS_PROJECTION_OPERATION,
                "context": &parent.context,
                "state_fence": &parent.context.state_fence,
                "scope": "notification",
            }),
            None,
        ),
        (
            NotifyOperation::UserAutomationPreflightRead,
            payload("user-automation-preflight"),
            None,
        ),
    ]
}

fn issue_through_public_api(
    issuer: &mut NotifyIdentityIssuer,
    parent: &NotificationRequest,
    operation: NotifyOperation,
    child_payload: &Value,
    prior_digest: Option<&str>,
    now_unix_ms: u64,
) -> Result<IssuedIdentity, OperationIdentityError> {
    match operation {
        NotifyOperation::G08Verify => issuer.issue_g08(parent, child_payload, now_unix_ms),
        NotifyOperation::A08Admit => {
            issuer.issue_a08(parent, child_payload, prior_digest, now_unix_ms)
        }
        NotifyOperation::WatchdogVerify => {
            issuer.issue_watchdog(parent, child_payload, now_unix_ms)
        }
        NotifyOperation::DeliveryVerify => {
            issuer.issue_delivery(parent, child_payload, prior_digest, now_unix_ms)
        }
        NotifyOperation::LedgerReserve => {
            issuer.issue_reserve(parent, child_payload, prior_digest, now_unix_ms)
        }
        NotifyOperation::LedgerCommit => {
            issuer.issue_commit(parent, child_payload, prior_digest, now_unix_ms)
        }
        NotifyOperation::NotificationState => {
            issuer.issue_notification_state(parent, child_payload, prior_digest, now_unix_ms)
        }
        NotifyOperation::NotificationStateRead => {
            issuer.issue_notification_state_read(parent, child_payload, now_unix_ms)
        }
        NotifyOperation::QuietHoursProjectionRead => {
            issuer.issue_quiet_hours_projection_read(parent, child_payload, now_unix_ms)
        }
        NotifyOperation::UserAutomationPreflightRead => {
            issuer.issue_user_automation_preflight_read(parent, child_payload, now_unix_ms)
        }
    }
}

#[test]
fn one_parent_derives_six_distinct_versioned_children() {
    let mut issuer = NotifyIdentityIssuer::new();
    let parent = parent_with_id("parent-78");
    let g08 = issuer
        .issue_g08(&parent, &payload("g08"), NOW)
        .expect("g08");
    let a08 = issuer
        .issue_a08(&parent, &payload("a08"), Some("source-sha"), NOW)
        .expect("a08");
    let watchdog = issuer
        .issue_watchdog(&parent, &payload("watchdog"), NOW)
        .expect("watchdog");
    let delivery = issuer
        .issue_delivery(&parent, &payload("delivery"), Some("admission-sha"), NOW)
        .expect("delivery");
    let reserve = issuer
        .issue_reserve(&parent, &payload("reserve"), Some("admission-sha"), NOW)
        .expect("reserve");
    let commit = issuer
        .issue_commit(&parent, &payload("commit"), Some("reservation-sha"), NOW)
        .expect("commit");

    let ids = [
        g08.request_id.as_str(),
        a08.request_id.as_str(),
        watchdog.request_id.as_str(),
        delivery.request_id.as_str(),
        reserve.request_id.as_str(),
        commit.request_id.as_str(),
    ];
    let mut distinct = ids.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), 6, "every step owns a distinct child");

    for id in &ids {
        assert!(
            id.contains(NOTIFY_IDENTITY_VERSION),
            "child {id} carries the version tag"
        );
    }

    let keys = [
        g08.identity.idempotency_key.as_str(),
        a08.identity.idempotency_key.as_str(),
        watchdog.identity.idempotency_key.as_str(),
        delivery.identity.idempotency_key.as_str(),
        reserve.identity.idempotency_key.as_str(),
        commit.identity.idempotency_key.as_str(),
    ];
    let mut distinct_keys = keys.to_vec();
    distinct_keys.sort_unstable();
    distinct_keys.dedup();
    assert_eq!(distinct_keys.len(), 6);

    let cancels = [
        g08.identity.cancellation_id.as_str(),
        a08.identity.cancellation_id.as_str(),
        watchdog.identity.cancellation_id.as_str(),
        delivery.identity.cancellation_id.as_str(),
        reserve.identity.cancellation_id.as_str(),
        commit.identity.cancellation_id.as_str(),
    ];
    let mut distinct_cancels = cancels.to_vec();
    distinct_cancels.sort_unstable();
    distinct_cancels.dedup();
    assert_eq!(
        distinct_cancels.len(),
        6,
        "cancellation of one step cannot cancel another"
    );

    for issued in [&g08, &a08, &watchdog, &delivery, &reserve, &commit] {
        issued.identity.validate().expect("child validates");
        assert_eq!(issued.parent_hash, PARENT_HASH);
        assert_eq!(issued.parent_request_id, "parent-78");
        assert_eq!(
            issued.identity.request.state_fence,
            parent.context.state_fence
        );
    }

    assert_eq!(issuer.issued_count(), 6);
    assert_eq!(issuer.lineage().len(), 6);
    for entry in issuer.lineage() {
        assert_eq!(entry.parent_hash, PARENT_HASH);
        assert_eq!(entry.parent_request_id, "parent-78");
    }
}

#[test]
fn exact_retry_returns_the_same_child() {
    let mut issuer = NotifyIdentityIssuer::new();
    let parent = parent_with_id("parent-retry");
    let first = issuer
        .issue_g08(&parent, &payload("same"), NOW)
        .expect("first");
    let second = issuer
        .issue_g08(&parent, &payload("same"), NOW + 700)
        .expect("retry");
    assert_eq!(first.identity, second.identity);
    assert_eq!(first.request_id, second.request_id);
    assert_eq!(
        first.identity.idempotency_key,
        second.identity.idempotency_key
    );
    assert_eq!(
        first.identity.cancellation_id,
        second.identity.cancellation_id
    );
    assert_eq!(
        first.identity.deadline_unix_ms, second.identity.deadline_unix_ms,
        "exact retry reuses the recorded deadline"
    );

    let reserve_first = issuer
        .issue_reserve(&parent, &payload("r"), Some("admission-sha"), NOW)
        .expect("reserve first");
    let reserve_retry = issuer
        .issue_reserve(&parent, &payload("r"), Some("admission-sha"), NOW + 100)
        .expect("reserve retry");
    assert_eq!(reserve_first.identity, reserve_retry.identity);
    assert_eq!(reserve_first.request_id, reserve_retry.request_id);
}

#[test]
fn cross_step_reuse_is_identity_conflict() {
    let mut issuer = NotifyIdentityIssuer::new();
    let parent = parent_with_id("parent-conflict");
    let g08 = issuer
        .issue_g08(&parent, &payload("g08"), NOW)
        .expect("g08");
    let foreign = g08.identity.idempotency_key.clone();

    let conflict = issuer.issue_with_idempotency_key(
        &parent,
        NotifyOperation::LedgerReserve,
        &payload("other-bytes"),
        &foreign,
        None,
        NOW,
    );
    assert!(
        matches!(conflict, Err(OperationIdentityError::IdentityConflict(_))),
        "cross-step reuse must conflict, got {conflict:?}"
    );
    assert_eq!(issuer.issued_count(), 1);

    let same_step_other_bytes = issuer.issue_with_idempotency_key(
        &parent,
        NotifyOperation::G08Verify,
        &payload("different-bytes"),
        &foreign,
        None,
        NOW,
    );
    assert!(
        matches!(
            same_step_other_bytes,
            Err(OperationIdentityError::IdentityConflict(_))
        ),
        "same key with different bytes must conflict"
    );
}

#[test]
fn reserve_and_commit_never_share_an_identity() {
    let mut issuer = NotifyIdentityIssuer::new();
    let parent = parent_with_id("parent-ledger");
    // Same logical claim bytes, but reserve and commit are separate operations.
    let claim_payload = payload("claim");
    let reserve = issuer
        .issue_reserve(&parent, &claim_payload, Some("admission-sha"), NOW)
        .expect("reserve");
    let commit = issuer
        .issue_commit(&parent, &claim_payload, Some("reservation-sha"), NOW)
        .expect("commit");
    assert_ne!(reserve.request_id, commit.request_id);
    assert_ne!(
        reserve.identity.idempotency_key,
        commit.identity.idempotency_key
    );
    assert_ne!(
        reserve.identity.cancellation_id,
        commit.identity.cancellation_id
    );
}

#[test]
fn unknown_delivery_step_is_distinct_from_source_and_ledger() {
    let mut issuer = NotifyIdentityIssuer::new();
    let parent = parent_with_id("parent-unknown");
    let g08 = issuer
        .issue_g08(&parent, &payload("g08"), NOW)
        .expect("g08");
    let delivery_unknown = issuer
        .issue_delivery(
            &parent,
            &json!({"evidence": "unknown"}),
            Some("admission-sha"),
            NOW,
        )
        .expect("delivery unknown");
    let delivery_known = issuer
        .issue_delivery(
            &parent,
            &json!({"evidence": "known"}),
            Some("admission-sha"),
            NOW,
        )
        .expect("delivery known");
    assert_ne!(g08.request_id, delivery_unknown.request_id);
    assert_ne!(delivery_unknown.request_id, delivery_known.request_id);
    assert_ne!(
        delivery_unknown.identity.idempotency_key, delivery_known.identity.idempotency_key,
        "unknown delivery outcome remains distinct from a known one"
    );
}

#[test]
fn serialized_lineage_restores_complete_identity_at_t_plus_one() {
    let parent = parent_with_id("parent-crash");
    let scenarios = retained_restore_scenarios(&parent);
    let covered_operations = scenarios
        .iter()
        .map(|(operation, _, _)| *operation)
        .collect::<Vec<_>>();
    let closed_operations = NotifyOperation::all().into_iter().collect::<Vec<_>>();
    assert_eq!(
        covered_operations, closed_operations,
        "the retained-record round trip covers the entire closed operation set"
    );

    // This is the issuer's retained-record restore API, not evidence that the
    // normal notification path has a durable owner for these records.
    for (operation, child_payload, prior_digest) in scenarios {
        let mut issuer = NotifyIdentityIssuer::new();
        let first = issue_through_public_api(
            &mut issuer,
            &parent,
            operation,
            &child_payload,
            prior_digest,
            NOW,
        )
        .unwrap_or_else(|error| panic!("issue {operation:?}: {error:?}"));
        assert_eq!(first.operation, operation);
        assert_eq!(first.parent_request_id, parent.context.request_id.as_str());
        assert_eq!(first.parent_hash, parent.canonical_request_hash.as_str());
        assert_eq!(
            first.identity.request.state_fence, parent.context.state_fence,
            "first issuance retains the parent fence for {operation:?}"
        );

        let retained = issuer
            .lineage()
            .last()
            .expect("issued step has retained lineage")
            .clone();
        assert_eq!(retained.operation, operation.selector());
        assert_eq!(
            retained.parent_request_id,
            parent.context.request_id.as_str()
        );
        assert_eq!(retained.parent_hash, parent.canonical_request_hash.as_str());
        assert_eq!(retained.prior_receipt_digest.as_deref(), prior_digest);
        assert_eq!(
            retained.identity.request.state_fence, parent.context.state_fence,
            "retained record preserves the parent fence for {operation:?}"
        );
        let encoded = serde_json::to_vec(&retained).expect("lineage serializes");
        let restored_entry: ChildLineageEntry =
            serde_json::from_slice(&encoded).expect("lineage deserializes");

        let mut restarted = NotifyIdentityIssuer::new();
        let restored = restarted
            .restore_issued(
                &parent,
                operation,
                &child_payload,
                prior_digest,
                &restored_entry,
                NOW + 1,
            )
            .unwrap_or_else(|error| panic!("restore {operation:?}: {error:?}"));
        assert_eq!(
            restored.identity, first.identity,
            "restore preserves the complete original identity for {operation:?}"
        );
        assert_eq!(restored.operation, operation);
        assert_eq!(restored.canonical_digest, first.canonical_digest);
        assert_eq!(restored.request_id, first.request_id);
        assert_eq!(
            restored.parent_request_id,
            parent.context.request_id.as_str()
        );
        assert_eq!(restored.parent_hash, parent.canonical_request_hash.as_str());
        assert_eq!(
            restored.identity.request.state_fence, parent.context.state_fence,
            "restored identity preserves the parent fence for {operation:?}"
        );
        assert_eq!(restarted.issued_count(), 1);
        assert_eq!(restarted.lineage().len(), 1);
        assert_eq!(restarted.lineage()[0], restored_entry);
    }
}

#[test]
fn restore_rejects_changed_payload_or_prior_receipt() {
    let parent = parent_with_id("parent-restore-conflict");
    let original_payload = payload("reserve");
    let mut issuer = NotifyIdentityIssuer::new();
    issuer
        .issue_reserve(&parent, &original_payload, Some("admission-sha"), NOW)
        .expect("reserve");
    let retained = issuer.lineage().last().expect("retained reserve").clone();
    let encoded = serde_json::to_vec(&retained).expect("lineage serializes");
    let restored_entry: ChildLineageEntry =
        serde_json::from_slice(&encoded).expect("lineage deserializes");

    let mut changed_payload_issuer = NotifyIdentityIssuer::new();
    let changed_payload = changed_payload_issuer.restore_issued(
        &parent,
        NotifyOperation::LedgerReserve,
        &payload("changed"),
        Some("admission-sha"),
        &restored_entry,
        NOW + 1,
    );
    assert!(
        matches!(
            changed_payload,
            Err(OperationIdentityError::IdentityConflict(_))
        ),
        "changed canonical payload must conflict, got {changed_payload:?}"
    );
    assert_eq!(changed_payload_issuer.issued_count(), 0);

    let mut changed_prior_issuer = NotifyIdentityIssuer::new();
    let changed_prior = changed_prior_issuer.restore_issued(
        &parent,
        NotifyOperation::LedgerReserve,
        &original_payload,
        Some("different-admission-sha"),
        &restored_entry,
        NOW + 1,
    );
    assert!(
        matches!(
            changed_prior,
            Err(OperationIdentityError::IdentityConflict(_))
        ),
        "changed prior receipt must conflict, got {changed_prior:?}"
    );
    assert_eq!(changed_prior_issuer.issued_count(), 0);
}

#[test]
fn expired_restore_refuses_without_renewing_deadline() {
    let parent = parent_with_id("parent-expired-restore");
    let original_payload = payload("g08");
    let mut issuer = NotifyIdentityIssuer::new();
    let original = issuer
        .issue_g08(&parent, &original_payload, NOW)
        .expect("original g08");
    let retained = issuer.lineage().last().expect("retained g08").clone();
    let encoded = serde_json::to_vec(&retained).expect("lineage serializes");
    let restored_entry: ChildLineageEntry =
        serde_json::from_slice(&encoded).expect("lineage deserializes");
    let expired_at = original.identity.deadline_unix_ms + 1;

    let mut restarted = NotifyIdentityIssuer::new();
    let result = restarted.restore_issued(
        &parent,
        NotifyOperation::G08Verify,
        &original_payload,
        None,
        &restored_entry,
        expired_at,
    );
    assert!(
        matches!(result, Err(OperationIdentityError::ExpiredIdentity(_))),
        "expired original must require reconciliation, got {result:?}"
    );
    assert_eq!(
        restored_entry.identity.deadline_unix_ms, original.identity.deadline_unix_ms,
        "the retained deadline remains unchanged"
    );
    assert_eq!(restarted.issued_count(), 0, "no renewed child is installed");
    assert!(restarted.lineage().is_empty());
}

#[test]
fn wall_clock_is_observed_from_the_host() {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("host clock")
        .as_millis();
    let now_ms = u64::try_from(now_ms).expect("clock fits");
    assert!(now_ms > NOW, "test host clock advances past the fixture");
}
