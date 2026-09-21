//! Kernel `WriteCoordinator` proofs (issue #1926).
//!
//! Five cases (`1926/1`..`1926/5`) prove the coordinator around real isolated
//! ORS/redb reservations. No test fabricates a token: every token comes from
//! [`WriteCoordinator::reserve`], every execution passes the durable
//! `Eligible -> Executing` transition, and every recovery passes exact receipt
//! reconciliation. Concurrency is proved with rendezvous channels, never
//! sleeps: overlap is observed, not timed.
//!
//! Case map:
//! - 01 one in-flight canonical execution per shared `task:<id>` scope; a
//!   second acquire fails closed while the first guard lives.
//! - 02 disjoint scopes execute concurrently: both guards held at once across
//!   two threads.
//! - 03 multi-scope reservation is all-or-none with one order: a failed scope
//!   consumes no order and no sequence.
//! - 04 restart reconciles the in-flight reservation from its receipt/head
//!   before the scope accepts reallocation.
//! - 05 executor lanes bound concurrency and change only on a drained
//!   generation switch.
//!
//! Rendezvous channels (never sleeps) prove overlap; thread bodies use
//! `expect` exactly as the `992` suite does for the same reason.

#![allow(clippy::expect_used)]

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::channel;
use std::thread;

use eliot_ors::{
    CanonicalDisposition, CanonicalEvidenceProvider, CanonicalReconciliation,
    CanonicalScopeObservation, EpochIdentity, EpochLineage, ExpectedOrderingHead, OpaqueLabel,
    OrsError, RecoveryAccessClass, RecoveryEnvelopeContext, RecoveryInboxItem,
    RecoveryPayloadEnvelope, RedbRecoveryStore, ReservationRequest, ReservationState,
    ScopeReservationRequest, StateFenceSnapshot, WriterReservationToken,
};
use eliot_platform::SecretReference;
use eliot_receipts::{ReceiptCore, ReceiptEnvelope};
use eliot_security_contracts::PrivacyClass;
use serde_json::{Value, json};

use super::{CoordinatorError, WriteCoordinator, WriteCoordinatorConfig, default_executor_lanes};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(1);

/// Accept-all composition evidence for coordinator proofs.
///
/// Structural validation still runs inside ORS (`ReservationRequest::validate`,
/// envelope/fence/digest checks); this provider only stands in for the
/// canonical readback authenticator that composition binds in production.
struct AcceptEvidence;

impl CanonicalEvidenceProvider for AcceptEvidence {
    fn verify_ordering_heads(&self, _scopes: &[ScopeReservationRequest]) -> Result<(), OrsError> {
        Ok(())
    }

    fn verify_reconciliation(
        &self,
        _token: &WriterReservationToken,
        _reconciliation: &CanonicalReconciliation,
    ) -> Result<(), OrsError> {
        Ok(())
    }

    fn verify_receipt(&self, _receipt: &ReceiptEnvelope) -> Result<(), OrsError> {
        Ok(())
    }

    fn verify_recovery_inbox(&self, _item: &RecoveryInboxItem) -> Result<(), OrsError> {
        Ok(())
    }
}

fn label(value: &str) -> Result<OpaqueLabel, OrsError> {
    OpaqueLabel::new(value)
}

fn epoch(value: u64) -> Result<EpochLineage, OrsError> {
    Ok(EpochLineage {
        current: EpochIdentity {
            lineage_id: label(TEST_LINEAGE)?,
            epoch: value,
        },
        predecessor: None,
    })
}

fn fence(authority_epoch: &EpochLineage) -> Result<StateFenceSnapshot, OrsError> {
    eliot_ors::StateFenceSnapshot::capture(
        &json!({
            "authority_epoch": {
                "lineage_id": authority_epoch.current.lineage_id.as_str(),
                "sequence": authority_epoch.current.epoch
            },
            "integration_revision": null,
            "policy_revision": null,
            "resource_generation": 1,
            "task_revision": null
        }),
        authority_epoch.current.epoch,
    )
}

fn genesis_head() -> ExpectedOrderingHead {
    ExpectedOrderingHead {
        sequence: 0,
        head_sha256: "00".repeat(32),
        revision_head: Some("revision-0".to_owned()),
    }
}

fn request(
    reservation_id: &str,
    operation_id: &str,
    writer_epoch: EpochLineage,
    scopes: &[&str],
    heads: Option<Vec<ExpectedOrderingHead>>,
) -> TestResult<ReservationRequest> {
    let state_fence = fence(&writer_epoch)?;
    let envelope = RecoveryPayloadEnvelope::encrypted(
        RecoveryEnvelopeContext {
            operation_or_checkpoint_id: label(operation_id)?,
            privacy_and_visibility_class: RecoveryAccessClass {
                privacy: PrivacyClass::Private,
                visibility: label("owner-only")?,
            },
            authority_epoch: writer_epoch.clone(),
            state_fence,
            created_at_ms: 10,
            known_at_ms: 11,
            expires_at_ms: Some(10_000),
        },
        SecretReference::new("test-key-provider", "key-1")?,
        format!("opaque-{operation_id}").into_bytes(),
    )?;
    let heads = heads.unwrap_or_else(|| scopes.iter().map(|_| genesis_head()).collect());
    assert_eq!(heads.len(), scopes.len(), "heads cover every scope");
    Ok(ReservationRequest {
        reservation_id: label(reservation_id)?,
        envelope,
        writer_epoch,
        scopes: scopes
            .iter()
            .zip(heads)
            .map(|(scope, expected_head)| {
                Ok(ScopeReservationRequest {
                    scope: label(scope)?,
                    expected_head,
                })
            })
            .collect::<Result<Vec<_>, OrsError>>()?,
        prepared_transition_sha256: "11".repeat(32),
        expires_at_ms: 1_000,
        recovery_owner: label("kernel-recovery-owner")?,
    })
}

fn receipt(token: &WriterReservationToken) -> TestResult<ReceiptEnvelope> {
    let state_fence: Value = serde_json::from_str(&token.state_fence.canonical_json)?;
    let contract = serde_json::to_value(eliot_receipts::contract_identity()?)?;
    let request_id = format!("request-{}", token.operation_id.as_str());
    let core: ReceiptCore = serde_json::from_value(json!({
        "contract": contract,
        "kind": "OPERATION",
        "work_scope": {
            "scope_id": token.scopes[0].scope.as_str(),
            "product_id": "product-1",
            "resource_generation": 1,
            "state_fence": state_fence
        },
        "task": null,
        "session": null,
        "causal": {
            "state_fence": state_fence,
            "transaction_sequence": token.scopes[0].reserved_sequence,
            "parent_receipt_id": null,
            "predecessor_receipt_ids": []
        },
        "request": {
            "metadata": {
                "request_id": request_id,
                "session_id": null,
                "task_id": null,
                "product_id": "product-1",
                "source_id": "source-1",
                "state_fence": state_fence,
                "clock": {
                    "valid_time_ms": 20,
                    "known_time_ms": 21,
                    "transaction_sequence": token.scopes[0].reserved_sequence,
                    "monotonic_ns": 22
                }
            },
            "state_fence": state_fence
        },
        "operation": {
            "operation_id": token.operation_id.as_str(),
            "request_id": request_id,
            "idempotency_key": token.reservation_id.as_str(),
            "operation_kind": "canonical-write",
            "effect": "REVERSIBLE_MUTATION",
            "state_fence": state_fence
        },
        "authority": {
            "authority_id": "authority-1",
            "authority_owner": "governor",
            "authority_epoch": {
                "lineage_id": token.writer_epoch.current.lineage_id.as_str(),
                "sequence": token.writer_epoch.current.epoch
            },
            "state_fence": state_fence,
            "allowed_effect": "REVERSIBLE_MUTATION",
            "proof_ceiling": "SCOPED_VERIFICATION"
        },
        "artifacts": [],
        "verifier": null,
        "problem": null,
        "coordination": null,
        "disposition": {"kind": "SUCCESS", "proof": "SCOPED_VERIFICATION"}
    }))?;
    Ok(ReceiptEnvelope::issue(core)?)
}

fn reconciliation(token: &WriterReservationToken) -> TestResult<CanonicalReconciliation> {
    let envelope = receipt(token)?;
    let receipt_id = label(envelope.identity.receipt_id.as_str())?;
    let receipt_sha = envelope.identity.canonical_sha256.clone();
    Ok(CanonicalReconciliation {
        reservation_id: token.reservation_id.clone(),
        operation_id: token.operation_id.clone(),
        reservation_order: token.reservation_order,
        state_fence: token.state_fence.clone(),
        recovery_owner: token.recovery_owner.clone(),
        scopes: token
            .scopes
            .iter()
            .map(|reserved| CanonicalScopeObservation {
                scope: reserved.scope.clone(),
                prior_head: reserved.expected_head.clone(),
                committed_sequence: reserved.reserved_sequence,
                committed_head_sha256: receipt_sha.clone(),
                committed_revision_head: Some(format!("receipt:{}", receipt_id.as_str())),
                receipt_id: receipt_id.clone(),
            })
            .collect(),
        receipt: envelope,
        disposition: CanonicalDisposition::Committed,
    })
}

fn database_path(label: &str) -> PathBuf {
    let serial = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "eliot-1926-{label}-{}-{serial}.redb",
        std::process::id()
    ))
}

fn coordinator_for(path: &PathBuf, lanes: u32) -> TestResult<WriteCoordinator> {
    let store = RedbRecoveryStore::open_with_evidence(path, Arc::new(AcceptEvidence))?;
    Ok(WriteCoordinator::new(
        Arc::new(store),
        WriteCoordinatorConfig::new(NonZeroUsize::try_from(lanes as usize)?),
    ))
}

fn cleanup(path: &PathBuf) {
    let _ignored = std::fs::remove_file(path);
}

fn eligible_token(
    coordinator: &WriteCoordinator,
    reservation_id: &str,
    operation_id: &str,
    writer_epoch: &EpochLineage,
    scopes: &[&str],
) -> TestResult<WriterReservationToken> {
    let token = coordinator.reserve(request(
        reservation_id,
        operation_id,
        writer_epoch.clone(),
        scopes,
        None,
    )?)?;
    coordinator.mark_eligible(&token)?;
    Ok(token)
}

#[test]
fn shared_task_scope_has_one_in_flight_canonical_execution() -> TestResult {
    let path = database_path("shared-scope");
    cleanup(&path);
    let coordinator = coordinator_for(&path, 4)?;
    let writer_epoch = epoch(7)?;

    // 1926/1: two transitions sharing `task:<same-task-id>` cannot overlap.
    let token = eligible_token(
        &coordinator,
        "reservation-1",
        "operation-1",
        &writer_epoch,
        &["task:task-1926"],
    )?;
    let guard = coordinator.begin_execution(&token, &writer_epoch.current)?;
    assert_eq!(guard.operation_id(), "operation-1");
    assert_eq!(guard.scopes(), ["task:task-1926".to_owned()].as_slice());
    assert_eq!(coordinator.in_flight_count(), 1);
    assert_eq!(coordinator.busy_scopes(), vec!["task:task-1926".to_owned()]);

    // The same token cannot enter a second overlapping execution: the
    // coordinator refuses before ORS (which would replay `Executing` as Ok).
    assert!(matches!(
        coordinator.begin_execution(&token, &writer_epoch.current),
        Err(CoordinatorError::ScopeBusy { .. })
    ));
    assert_eq!(coordinator.in_flight_count(), 1);

    drop(guard);
    assert_eq!(coordinator.in_flight_count(), 0);
    assert!(coordinator.busy_scopes().is_empty());
    // Reacquiring after release succeeds through the durable idempotent replay.
    let guard = coordinator.begin_execution(&token, &writer_epoch.current)?;
    assert_eq!(coordinator.in_flight_count(), 1);
    drop(guard);

    drop(coordinator);
    cleanup(&path);
    Ok(())
}

#[test]
fn disjoint_scopes_execute_concurrently() -> TestResult {
    let path = database_path("disjoint");
    cleanup(&path);
    let coordinator = coordinator_for(&path, 4)?;
    let writer_epoch = epoch(7)?;

    // 1926/1 acceptance, second half: disjoint scopes reach execution together.
    let token_a = eligible_token(
        &coordinator,
        "reservation-a",
        "operation-a",
        &writer_epoch,
        &["scope-1926-a"],
    )?;
    let token_b = eligible_token(
        &coordinator,
        "reservation-b",
        "operation-b",
        &writer_epoch,
        &["scope-1926-b"],
    )?;
    // Lower reservation order first: readiness follows the ORS order, and the
    // worker below still overlaps the main thread regardless of priority.
    assert!(token_a.reservation_order < token_b.reservation_order);

    let (acquired_tx, acquired_rx) = channel::<()>();
    let (proceed_tx, proceed_rx) = channel::<()>();
    let (done_tx, done_rx) = channel::<()>();

    let coordinator_ref = &coordinator;
    let epoch_identity = &writer_epoch.current;
    thread::scope(|scope| {
        scope.spawn(move || {
            let guard = coordinator_ref
                .begin_execution(&token_a, epoch_identity)
                .expect("scope-a executes");
            acquired_tx.send(()).expect("report acquired");
            // Wait until the main thread holds the disjoint guard, then
            // observe the overlap directly: no global serialization.
            proceed_rx.recv().expect("wait for disjoint execution");
            assert_eq!(
                coordinator_ref.in_flight_count(),
                2,
                "disjoint scopes overlap in flight"
            );
            drop(guard);
            done_tx.send(()).expect("report done");
        });
        acquired_rx.recv().expect("worker acquires scope-a");
        let guard_b = coordinator
            .begin_execution(&token_b, &writer_epoch.current)
            .expect("disjoint scope-b executes concurrently");
        assert_eq!(coordinator.in_flight_count(), 2);
        proceed_tx.send(()).expect("release worker");
        done_rx.recv().expect("worker finishes overlapping");
        drop(guard_b);
        assert_eq!(coordinator.in_flight_count(), 0);
    });

    drop(coordinator);
    cleanup(&path);
    Ok(())
}

#[test]
fn multi_scope_reserve_is_all_or_none_with_single_order() -> TestResult {
    let path = database_path("atomic");
    cleanup(&path);
    let coordinator = coordinator_for(&path, 4)?;
    let writer_epoch = epoch(7)?;

    // 1926/1 acceptance: one multi-scope transition receives every sequence
    // and one order, with stable scope sorting at the boundary.
    let first = coordinator.reserve(request(
        "reservation-1",
        "operation-1",
        writer_epoch.clone(),
        &["scope-1926-m3", "scope-1926-m1", "scope-1926-m2"],
        None,
    )?)?;
    assert_eq!(
        first
            .scopes
            .iter()
            .map(|reserved| reserved.scope.as_str())
            .collect::<Vec<_>>(),
        vec!["scope-1926-m1", "scope-1926-m2", "scope-1926-m3"]
    );
    assert!(first.reservation_order > 0);
    for reserved in &first.scopes {
        assert_eq!(reserved.reserved_sequence, 1);
    }

    // The last scope head mismatches after the first two scopes already
    // allocated inside the ORS transaction: the whole reservation must roll
    // back, consuming no order and no sequence on any scope.
    let wrong_head = ExpectedOrderingHead {
        sequence: 7,
        head_sha256: "77".repeat(32),
        revision_head: None,
    };
    assert!(matches!(
        coordinator.reserve(request(
            "reservation-2",
            "operation-2",
            writer_epoch.clone(),
            &["scope-1926-m1", "scope-1926-m2", "scope-1926-m3"],
            Some(vec![genesis_head(), genesis_head(), wrong_head]),
        )?),
        Err(OrsError::OrderingHeadMismatch)
    ));

    // No order consumed, no sequence advanced: the retried scopes continue
    // exactly where the single committed reservation left them.
    let third = coordinator.reserve(request(
        "reservation-3",
        "operation-3",
        writer_epoch.clone(),
        &["scope-1926-m1"],
        None,
    )?)?;
    assert_eq!(third.reservation_order, first.reservation_order + 1);
    assert_eq!(third.scopes[0].reserved_sequence, 2);
    let fourth = coordinator.reserve(request(
        "reservation-4",
        "operation-4",
        writer_epoch.clone(),
        &["scope-1926-m2"],
        None,
    )?)?;
    assert_eq!(fourth.reservation_order, first.reservation_order + 2);
    assert_eq!(fourth.scopes[0].reserved_sequence, 2);
    let fifth = coordinator.reserve(request(
        "reservation-5",
        "operation-5",
        writer_epoch.clone(),
        &["scope-1926-m3"],
        None,
    )?)?;
    assert_eq!(fifth.reservation_order, first.reservation_order + 3);
    assert_eq!(fifth.scopes[0].reserved_sequence, 2);

    drop(coordinator);
    cleanup(&path);
    Ok(())
}

#[test]
fn restart_reconciles_in_flight_before_scope_reallocation() -> TestResult {
    let path = database_path("restart");
    cleanup(&path);
    let writer_epoch = epoch(7)?;
    let token = {
        let coordinator = coordinator_for(&path, 4)?;
        let token = eligible_token(
            &coordinator,
            "reservation-1",
            "operation-1",
            &writer_epoch,
            &["scope-1926-r"],
        )?;
        let guard = coordinator.begin_execution(&token, &writer_epoch.current)?;
        drop(guard);
        // Durable state stays `Executing` across the simulated restart; only
        // the in-memory permits are gone with the old generation.
        token
    };

    // 1926/1 acceptance: after restart the in-flight reservation resolves from
    // its receipt/head before another operation receives the scope sequence.
    let coordinator = coordinator_for(&path, 4)?;
    let unresolved = coordinator.unresolved(10)?;
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].state, ReservationState::Reconciling);
    assert_eq!(unresolved[0].token, token);

    // The stale token cannot re-enter execution, and the rollback leaves the
    // new generation idle instead of wedging the scope.
    assert!(matches!(
        coordinator.begin_execution(&token, &writer_epoch.current),
        Err(CoordinatorError::Ors(OrsError::InvalidTransition))
    ));
    assert_eq!(coordinator.in_flight_count(), 0);

    // Reallocation on the blocked scope is refused until reconciliation.
    assert!(matches!(
        coordinator.reserve(request(
            "reservation-2",
            "operation-2",
            writer_epoch.clone(),
            &["scope-1926-r"],
            None,
        )?),
        Err(OrsError::ScopeRecoveryRequired)
    ));

    let exact = reconciliation(&token)?;
    let finalized = coordinator.finalize(&exact)?;
    assert_eq!(finalized.state, ReservationState::Finalized);

    // With the canonical head advanced by the receipt, the successor receives
    // the next sequence, never the same one.
    let next = coordinator.reserve(request(
        "reservation-3",
        "operation-3",
        writer_epoch.clone(),
        &["scope-1926-r"],
        Some(vec![ExpectedOrderingHead {
            sequence: token.scopes[0].reserved_sequence,
            head_sha256: exact.receipt.identity.canonical_sha256.clone(),
            revision_head: exact.scopes[0].committed_revision_head.clone(),
        }]),
    )?)?;
    assert_eq!(
        next.scopes[0].reserved_sequence,
        token.scopes[0].reserved_sequence + 1
    );

    drop(coordinator);
    cleanup(&path);
    Ok(())
}

#[test]
fn lanes_bound_concurrency_and_switch_only_when_drained() -> TestResult {
    let path = database_path("lanes");
    cleanup(&path);
    let coordinator = coordinator_for(&path, 1)?;
    let writer_epoch = epoch(7)?;
    assert!(default_executor_lanes().get() >= 1 && default_executor_lanes().get() <= 4);

    let token_a = eligible_token(
        &coordinator,
        "reservation-a",
        "operation-a",
        &writer_epoch,
        &["scope-1926-x"],
    )?;
    let token_b = eligible_token(
        &coordinator,
        "reservation-b",
        "operation-b",
        &writer_epoch,
        &["scope-1926-y"],
    )?;

    // One lane: disjoint scopes still serialize at the lane bound.
    let guard_a = coordinator.begin_execution(&token_a, &writer_epoch.current)?;
    assert!(matches!(
        coordinator.begin_execution(&token_b, &writer_epoch.current),
        Err(CoordinatorError::LanesExhausted { .. })
    ));
    // The lane count cannot change under a live generation.
    assert!(matches!(
        coordinator.reconfigure_lanes(NonZeroUsize::try_from(2)?),
        Err(CoordinatorError::NotDrained { .. })
    ));
    drop(guard_a);

    // Drained switch succeeds; both lanes then run disjoint scopes at once.
    coordinator.reconfigure_lanes(NonZeroUsize::try_from(2)?)?;
    assert_eq!(coordinator.lanes().get(), 2);
    let guard_a = coordinator.begin_execution(&token_a, &writer_epoch.current)?;
    let guard_b = coordinator.begin_execution(&token_b, &writer_epoch.current)?;
    assert_eq!(coordinator.in_flight_count(), 2);
    drop((guard_a, guard_b));
    assert_eq!(coordinator.in_flight_count(), 0);

    drop(coordinator);
    cleanup(&path);
    Ok(())
}
