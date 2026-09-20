#![cfg(feature = "test-support")]
//! Kernel-route ORS store fixture proof (issue #2031).
//!
//! The public test-usable fixture (`KernelRouteStoreFixture`) opens one
//! isolated temp redb store bound to the structural Kernel-route evidence and
//! drives a real reserve-to-eligible lifecycle through it. A store opened
//! without evidence rejects the same reservation, and two fixtures stay
//! isolated. Compiled only with the `test-support` feature:
//! `cargo test -p eliot-ors --features test-support`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::too_many_lines)]

use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_ors::{
    test_support::{kernel_fixture_dir, kernel_route_writer_epoch, KernelRouteStoreFixture},
    ExpectedOrderingHead, OpaqueLabel, OperationalRecoveryStore, OrsError, RecoveryAccessClass,
    RecoveryCursor, RecoveryEnvelopeContext, RecoveryPayloadEnvelope, RedbRecoveryStore,
    ReservationRequest, ReservationState, ScopeReservationRequest, StateFenceSnapshot,
};
use eliot_platform::SecretReference;
use eliot_security_contracts::PrivacyClass;

const LINEAGE_2031: &str = "550e8400-e29b-41d4-a716-446655440000";

fn fence() -> StateFence {
    let lineage = EpochLineageId::new(LINEAGE_2031).expect("2031 lineage parses");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("2031 nonzero epoch"))
        .expect("2031 epoch builds");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn reservation_request(tag: &str) -> ReservationRequest {
    let writer_epoch =
        kernel_route_writer_epoch(LINEAGE_2031, 1).expect("2031 writer epoch builds");
    let snapshot = StateFenceSnapshot::capture(&fence(), 1).expect("2031 fence snapshot captures");
    let envelope = RecoveryPayloadEnvelope::encrypted(
        RecoveryEnvelopeContext {
            operation_or_checkpoint_id: OpaqueLabel::new(format!("op-2031-{tag}"))
                .expect("2031 operation label"),
            privacy_and_visibility_class: RecoveryAccessClass {
                privacy: PrivacyClass::Private,
                visibility: OpaqueLabel::new("owner-only").expect("2031 visibility label"),
            },
            authority_epoch: writer_epoch.clone(),
            state_fence: snapshot,
            created_at_ms: 1_700_000_000_000,
            known_at_ms: 1_700_000_000_000,
            expires_at_ms: Some(1_700_000_100_000),
        },
        SecretReference::new("kernel-reservation-key", "store-write-reservation-v1")
            .expect("2031 key reference"),
        format!("kernel-fixture-payload-{tag}").into_bytes(),
    )
    .expect("2031 envelope binds");
    ReservationRequest {
        reservation_id: OpaqueLabel::new(format!("reservation-2031-{tag}"))
            .expect("2031 reservation label"),
        envelope,
        writer_epoch,
        scopes: vec![ScopeReservationRequest {
            scope: OpaqueLabel::new("scope-2031-a").expect("2031 scope label"),
            expected_head: ExpectedOrderingHead {
                sequence: 6,
                head_sha256: "c".repeat(64),
                revision_head: None,
            },
        }],
        prepared_transition_sha256: "a".repeat(64),
        expires_at_ms: 1_700_000_100_000,
        recovery_owner: OpaqueLabel::new("owner-2031").expect("2031 owner label"),
    }
}

fn empty_page(store: &RedbRecoveryStore) {
    let cursor = RecoveryCursor::new(0, 16).expect("2031 cursor builds");
    let page = store.recover_page(cursor).expect("2031 recovery scans");
    assert!(
        page.records.is_empty(),
        "2031 fixture starts unresolved-free"
    );
    assert!(
        page.next_after_order.is_none(),
        "2031 empty store has no continuation"
    );
}

#[test]
fn kernel_route_fixture_binds_evidence_and_drives_reserve_eligible() {
    let fixture = KernelRouteStoreFixture::open("2031-lifecycle").expect("2031 fixture opens");
    assert!(fixture.path().join("ors.redb").exists());
    empty_page(fixture.store());

    let token = fixture
        .store()
        .stage_and_reserve(reservation_request("lifecycle"))
        .expect("2031 bound store reserves");
    assert_ne!(
        token.reservation_order, 0,
        "2031 reservation carries a monotonic order"
    );
    let record = fixture
        .store()
        .mark_eligible(&token)
        .expect("2031 reservation becomes eligible");
    assert_eq!(
        record.state,
        ReservationState::Eligible,
        "2031 head reservation is eligible"
    );
    assert!(
        !record.state.is_terminal(),
        "2031 eligible reservation is not terminal"
    );

    assert!(ReservationState::Finalized.is_terminal());
    assert!(ReservationState::Released.is_terminal());
    assert!(!ReservationState::Reserved.is_terminal());
    assert!(!ReservationState::Executing.is_terminal());
    assert!(!ReservationState::Reconciling.is_terminal());

    let other = KernelRouteStoreFixture::open("2031-isolation").expect("2031 second opens");
    assert_ne!(fixture.path(), other.path(), "2031 fixtures isolate paths");
    empty_page(other.store());
}

#[test]
fn store_without_evidence_rejects_reservation() {
    let dir = kernel_fixture_dir("2031-unbound").expect("2031 temp dir builds");
    let plain = RedbRecoveryStore::open(dir.join("ors.redb")).expect("2031 plain store opens");
    let error = plain
        .stage_and_reserve(reservation_request("unbound"))
        .expect_err("2031 unbound store must refuse");
    assert!(
        matches!(error, OrsError::CanonicalEvidence(_)),
        "2031 refusal names the missing canonical evidence: {error}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn fixture_rejects_blank_labels_before_filesystem_work() {
    let error = match KernelRouteStoreFixture::open("") {
        Ok(_) => panic!("2031 blank tag must fail"),
        Err(error) => error,
    };
    assert!(
        matches!(error, OrsError::InvalidField { .. }),
        "2031 blank tag fails closed: {error}"
    );
}
