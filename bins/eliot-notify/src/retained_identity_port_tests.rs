#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "these tests build fixed-valid protocol fixtures and inspect exact typed outcomes"
)]

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
    ResourceGeneration, SourceId, StateFence,
};
use eliot_platform::{NotificationRequest, PlatformHandle};
use eliot_protocol::RequestIdentity;
use serde_json::Value;

use super::{KernelClientError, KernelPort, NotifyKernelExchange, issue_step, operation_identity};

type RecordedCall = (String, RequestIdentity, Value);

#[derive(Clone)]
struct RecordingExchange {
    calls: Arc<Mutex<Vec<RecordedCall>>>,
}

impl NotifyKernelExchange for RecordingExchange {
    fn transact_with_identity(
        &mut self,
        identity: &RequestIdentity,
        operation: &str,
        payload: Value,
    ) -> Result<Value, KernelClientError> {
        self.calls.lock().expect("recording exchange lock").push((
            operation.to_owned(),
            identity.clone(),
            payload,
        ));
        Ok(serde_json::json!({"accepted": true}))
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_millis(),
    )
    .expect("test clock fits in u64")
}

fn state_fence() -> StateFence {
    let lineage =
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("valid test lineage");
    let epoch = EpochId::new(
        lineage,
        std::num::NonZeroU64::new(1).expect("non-zero test epoch"),
    )
    .expect("valid test epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn parent(request_id: &str, now_unix_ms: u64) -> NotificationRequest {
    let observed = i64::try_from(now_unix_ms).expect("test clock fits i64");
    NotificationRequest {
        context: RequestMetadata {
            request_id: RequestId::new(request_id).expect("valid request id"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("notify-test-product").expect("valid product id"),
            source_id: SourceId::new("notify-test-source").expect("valid source id"),
            state_fence: state_fence(),
            clock: ClockReading {
                valid_time_ms: Some(observed),
                known_time_ms: Some(observed),
                ..ClockReading::default()
            },
        },
        canonical_request_hash: PlatformHandle::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("valid parent hash"),
        notification: PlatformHandle::new("notification-1").expect("valid notification"),
        audience: PlatformHandle::new("audience-1").expect("valid audience"),
        body_digest: PlatformHandle::new(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .expect("valid body digest"),
    }
}

fn port() -> (
    KernelPort<RecordingExchange>,
    operation_identity::IssuerHandle,
    Arc<Mutex<Vec<RecordedCall>>>,
) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let issuer = Arc::new(Mutex::new(operation_identity::NotifyIdentityIssuer::new()));
    let port = KernelPort {
        exchange: Arc::new(Mutex::new(RecordingExchange {
            calls: Arc::clone(&calls),
        })),
        issuer: Arc::clone(&issuer),
    };
    (port, issuer, calls)
}

#[test]
fn retained_issue_step_replays_the_full_identity_at_t_plus_one() {
    let issued_at = now_ms();
    let parent = parent("notify-retained-replay", issued_at);
    let operation = operation_identity::NotifyOperation::LedgerReserve;
    let payload = serde_json::json!({"claim": "claim-1", "step": "reserve"});
    let prior = Some("admission-receipt-1");
    let original_issuer = Arc::new(Mutex::new(operation_identity::NotifyIdentityIssuer::new()));

    let original = issue_step(
        &original_issuer,
        &parent,
        operation,
        &payload,
        prior,
        None,
        issued_at,
    )
    .expect("first issuance succeeds");
    let retained = original_issuer
        .lock()
        .expect("original issuer lock")
        .lineage()[0]
        .clone();

    let restored_issuer = Arc::new(Mutex::new(operation_identity::NotifyIdentityIssuer::new()));
    let replay = issue_step(
        &restored_issuer,
        &parent,
        operation,
        &payload,
        prior,
        Some(&retained),
        issued_at + 1,
    )
    .expect("retained first issuance is replayed");

    assert_eq!(
        replay.identity, original.identity,
        "request, key, cancellation, clock and absolute deadline must all remain identical"
    );
    let restored = restored_issuer.lock().expect("restored issuer lock");
    assert_eq!(restored.issued_count(), 1);
    assert_eq!(restored.lineage(), &[retained]);
}

#[test]
fn retained_payload_mismatch_is_rejected_without_adopting_the_identity() {
    let issued_at = now_ms();
    let parent = parent("notify-retained-mismatch", issued_at);
    let operation = operation_identity::NotifyOperation::LedgerReserve;
    let original_payload = serde_json::json!({"claim": "claim-1", "step": "reserve"});
    let changed_payload = serde_json::json!({"claim": "claim-2", "step": "reserve"});
    let prior = Some("admission-receipt-1");
    let original_issuer = Arc::new(Mutex::new(operation_identity::NotifyIdentityIssuer::new()));
    let _ = issue_step(
        &original_issuer,
        &parent,
        operation,
        &original_payload,
        prior,
        None,
        issued_at,
    )
    .expect("first issuance succeeds");
    let retained = original_issuer
        .lock()
        .expect("original issuer lock")
        .lineage()[0]
        .clone();
    let receiving_issuer = Arc::new(Mutex::new(operation_identity::NotifyIdentityIssuer::new()));

    let result = issue_step(
        &receiving_issuer,
        &parent,
        operation,
        &changed_payload,
        prior,
        Some(&retained),
        issued_at + 1,
    );

    assert!(matches!(
        result,
        Err(operation_identity::OperationIdentityError::IdentityConflict(_))
    ));
    let receiving = receiving_issuer.lock().expect("receiving issuer lock");
    assert_eq!(receiving.issued_count(), 0);
    assert!(receiving.lineage().is_empty());
}

#[test]
fn retained_prior_receipt_mismatch_is_rejected_without_adopting_the_identity() {
    let issued_at = now_ms();
    let parent = parent("notify-retained-prior-mismatch", issued_at);
    let operation = operation_identity::NotifyOperation::LedgerReserve;
    let payload = serde_json::json!({"claim": "claim-1", "step": "reserve"});
    let original_prior = Some("admission-receipt-1");
    let changed_prior = Some("admission-receipt-2");
    let original_issuer = Arc::new(Mutex::new(operation_identity::NotifyIdentityIssuer::new()));
    let _ = issue_step(
        &original_issuer,
        &parent,
        operation,
        &payload,
        original_prior,
        None,
        issued_at,
    )
    .expect("first issuance succeeds");
    let retained = original_issuer
        .lock()
        .expect("original issuer lock")
        .lineage()[0]
        .clone();
    let receiving_issuer = Arc::new(Mutex::new(operation_identity::NotifyIdentityIssuer::new()));

    let result = issue_step(
        &receiving_issuer,
        &parent,
        operation,
        &payload,
        changed_prior,
        Some(&retained),
        issued_at + 1,
    );

    assert!(matches!(
        result,
        Err(operation_identity::OperationIdentityError::IdentityConflict(_))
    ));
    let receiving = receiving_issuer.lock().expect("receiving issuer lock");
    assert_eq!(receiving.issued_count(), 0);
    assert!(receiving.lineage().is_empty());
}

#[test]
fn expired_retained_identity_is_rejected_without_adopting_it() {
    let issued_at = now_ms();
    let parent = parent("notify-retained-expired", issued_at);
    let operation = operation_identity::NotifyOperation::LedgerReserve;
    let payload = serde_json::json!({"claim": "claim-1", "step": "reserve"});
    let prior = Some("admission-receipt-1");
    let original_issuer = Arc::new(Mutex::new(operation_identity::NotifyIdentityIssuer::new()));
    let _ = issue_step(
        &original_issuer,
        &parent,
        operation,
        &payload,
        prior,
        None,
        issued_at,
    )
    .expect("first issuance succeeds");
    let retained = original_issuer
        .lock()
        .expect("original issuer lock")
        .lineage()[0]
        .clone();
    let receiving_issuer = Arc::new(Mutex::new(operation_identity::NotifyIdentityIssuer::new()));
    let expired_at = issued_at + operation_identity::OPERATION_IDENTITY_TTL_MS + 1;

    let result = issue_step(
        &receiving_issuer,
        &parent,
        operation,
        &payload,
        prior,
        Some(&retained),
        expired_at,
    );

    assert!(matches!(
        result,
        Err(operation_identity::OperationIdentityError::ExpiredIdentity(
            _
        ))
    ));
    let receiving = receiving_issuer.lock().expect("receiving issuer lock");
    assert_eq!(receiving.issued_count(), 0);
    assert!(receiving.lineage().is_empty());
}

#[test]
fn ledger_port_rejects_non_ledger_operation_before_issuing_or_dispatching() {
    let (port, issuer, calls) = port();
    let parent = parent("notify-invalid-ledger-selector", now_ms());

    let result = port.transact_ledger(
        &parent,
        operation_identity::NotifyOperation::G08Verify,
        serde_json::json!({"step": "not-a-ledger-operation"}),
        None,
    );

    assert!(matches!(result, Err(KernelClientError::Configuration(_))));
    assert_eq!(issuer.lock().expect("issuer lock").issued_count(), 0);
    assert!(calls.lock().expect("recording calls lock").is_empty());
}

#[test]
fn ledger_reserve_and_commit_dispatch_distinct_children_with_exact_prior_receipts() {
    let (port, issuer, calls) = port();
    let parent = parent("notify-ledger-lineage", now_ms());
    let admission_receipt = "admission-receipt-1";
    let reservation_receipt = "reservation-receipt-1";
    let reserve_payload = serde_json::json!({"claim": "claim-1", "step": "reserve"});
    let commit_payload = serde_json::json!({"claim": "claim-1", "step": "commit"});

    port.transact_ledger(
        &parent,
        operation_identity::NotifyOperation::LedgerReserve,
        reserve_payload.clone(),
        Some(admission_receipt),
    )
    .expect("reserve is dispatched");
    let first_reserve = calls
        .lock()
        .expect("recording calls lock")
        .first()
        .expect("first reserve call is recorded")
        .1
        .clone();
    let first_reserve_clock = u64::try_from(
        first_reserve
            .request
            .metadata
            .clock
            .valid_time_ms
            .expect("issued identity has valid time"),
    )
    .expect("issued clock is non-negative");
    std::thread::sleep(std::time::Duration::from_millis(2));
    assert!(
        now_ms() > first_reserve_clock,
        "retry must observe a later clock than the first issuance"
    );
    port.transact_ledger(
        &parent,
        operation_identity::NotifyOperation::LedgerReserve,
        reserve_payload.clone(),
        Some(admission_receipt),
    )
    .expect("exact reserve retry is dispatched");
    port.transact_ledger(
        &parent,
        operation_identity::NotifyOperation::LedgerCommit,
        commit_payload.clone(),
        Some(reservation_receipt),
    )
    .expect("commit is dispatched");

    let calls = calls.lock().expect("recording calls lock");
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls[0].0,
        operation_identity::NotifyOperation::LedgerReserve.selector()
    );
    assert_eq!(
        calls[1].0,
        operation_identity::NotifyOperation::LedgerReserve.selector()
    );
    assert_eq!(
        calls[2].0,
        operation_identity::NotifyOperation::LedgerCommit.selector()
    );
    assert_eq!(calls[0].2, reserve_payload);
    assert_eq!(calls[1].2, calls[0].2);
    assert_eq!(calls[2].2, commit_payload);
    assert_eq!(
        calls[1].1, calls[0].1,
        "an exact retry at a later observed clock must replay the full original identity"
    );
    assert_ne!(
        calls[0].1.request.metadata.request_id,
        calls[2].1.request.metadata.request_id
    );
    assert_ne!(calls[0].1.idempotency_key, calls[2].1.idempotency_key);
    assert_ne!(calls[0].1.cancellation_id, calls[2].1.cancellation_id);

    let issuer = issuer.lock().expect("issuer lock");
    let lineage = issuer.lineage();
    assert_eq!(
        lineage.len(),
        2,
        "an exact retry must not add a lineage row"
    );
    assert_eq!(
        lineage[0].operation,
        operation_identity::NotifyOperation::LedgerReserve.selector()
    );
    assert_eq!(
        lineage[0].prior_receipt_digest.as_deref(),
        Some(admission_receipt)
    );
    assert_eq!(
        lineage[1].operation,
        operation_identity::NotifyOperation::LedgerCommit.selector()
    );
    assert_eq!(
        lineage[1].prior_receipt_digest.as_deref(),
        Some(reservation_receipt)
    );
}
