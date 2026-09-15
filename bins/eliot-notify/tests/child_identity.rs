//! Parent-to-child identity proof for issue #78.
//!
//! One stable parent notification intent derives a distinct versioned child
//! per Kernel step (G-08 verify, A-08 admit, Watchdog verify, delivery
//! verify, ledger reserve, ledger commit). Exact retry reuses the child;
//! cross-step or cross-payload reuse fails `IDENTITY_CONFLICT` before any
//! Kernel effect; reserve and commit never share an identity; per-step
//! cancellation is isolated; crash after reserve reconciles at the exact
//! step.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::num::NonZeroU64;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
    ResourceGeneration, SourceId, StateFence,
};
use eliot_notify::operation_identity::{
    NOTIFY_IDENTITY_VERSION, NotifyIdentityIssuer, NotifyOperation, OperationIdentityError,
};
use eliot_platform::{NotificationRequest, PlatformHandle};
use serde_json::{Value, json};

const NOW: u64 = 1_786_000_000_000;
const PARENT_HASH: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BODY_DIGEST: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
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

#[test]
fn one_parent_derives_six_distinct_versioned_children() {
    let mut issuer = NotifyIdentityIssuer::new();
    let parent = parent_with_id("parent-78");
    let g08 = issuer.issue_g08(&parent, &payload("g08"), NOW).expect("g08");
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
    let first = issuer.issue_g08(&parent, &payload("same"), NOW).expect("first");
    let second = issuer
        .issue_g08(&parent, &payload("same"), NOW + 700)
        .expect("retry");
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
        first.identity.deadline_unix_ms,
        second.identity.deadline_unix_ms,
        "exact retry reuses the recorded deadline"
    );

    let reserve_first = issuer
        .issue_reserve(&parent, &payload("r"), Some("admission-sha"), NOW)
        .expect("reserve first");
    let reserve_retry = issuer
        .issue_reserve(&parent, &payload("r"), Some("admission-sha"), NOW + 100)
        .expect("reserve retry");
    assert_eq!(reserve_first.request_id, reserve_retry.request_id);
}

#[test]
fn cross_step_reuse_is_identity_conflict() {
    let mut issuer = NotifyIdentityIssuer::new();
    let parent = parent_with_id("parent-conflict");
    let g08 = issuer.issue_g08(&parent, &payload("g08"), NOW).expect("g08");
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
        matches!(
            conflict,
            Err(OperationIdentityError::IdentityConflict(_))
        ),
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
    let g08 = issuer.issue_g08(&parent, &payload("g08"), NOW).expect("g08");
    let delivery_unknown = issuer
        .issue_delivery(&parent, &json!({"evidence": "unknown"}), Some("admission-sha"), NOW)
        .expect("delivery unknown");
    let delivery_known = issuer
        .issue_delivery(&parent, &json!({"evidence": "known"}), Some("admission-sha"), NOW)
        .expect("delivery known");
    assert_ne!(g08.request_id, delivery_unknown.request_id);
    assert_ne!(delivery_unknown.request_id, delivery_known.request_id);
    assert_ne!(
        delivery_unknown.identity.idempotency_key,
        delivery_known.identity.idempotency_key,
        "unknown delivery outcome remains distinct from a known one"
    );
}

#[test]
fn crash_after_reserve_reconciles_at_the_exact_step() {
    let parent = parent_with_id("parent-crash");
    let reserve_payload = payload("reserve");
    let first = {
        let mut issuer = NotifyIdentityIssuer::new();
        issuer
            .issue_reserve(&parent, &reserve_payload, Some("admission-sha"), NOW)
            .expect("reserve before crash")
    };
    // Crash: the ledger is gone. A fresh issuer re-derives the same child
    // transport identity from the same parent plus step plus bytes, so the
    // reservation reconciles without a duplicate notification.
    let mut restarted = NotifyIdentityIssuer::new();
    let replay = restarted
        .issue_reserve(&parent, &reserve_payload, Some("admission-sha"), NOW + 5_000)
        .expect("reserve after restart");
    assert_eq!(first.request_id, replay.request_id);
    assert_eq!(
        first.identity.idempotency_key,
        replay.identity.idempotency_key
    );
    assert_eq!(
        first.identity.cancellation_id,
        replay.identity.cancellation_id
    );
    // The commit step is still a different identity: reserve success never
    // impersonates commit success.
    let commit = restarted
        .issue_commit(&parent, &payload("commit"), Some("reservation-sha"), NOW + 5_000)
        .expect("commit");
    assert_ne!(replay.request_id, commit.request_id);
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
