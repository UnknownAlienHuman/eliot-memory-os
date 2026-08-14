#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_campaign_executor::EpochId;
use eliot_campaign_executor::control::{ControllerAttempt, StateFence};
use eliot_campaign_executor::coordination::{
    AnchorResolution, AnchorRevision, FailureDisposition, FirstPassMap, IndependentMaps,
    MapSealReason, MechanismFailure, MechanismFailureBook, PeerDelivery, PeerDeliveryBook,
    PeerDeliveryState, Replan, ReplanPublication, ReviewAnchor, ReviewBook, ReviewItem,
};
use serde_json::to_value;
use uuid::Uuid;

fn fence(epoch_sequence: u64, ledger_sequence: u64, head: &str) -> StateFence {
    StateFence::new(
        EpochId {
            lineage: Uuid::from_u128(0xD02),
            sequence: epoch_sequence,
        },
        ledger_sequence,
        head,
    )
}

#[test]
fn negotiated_maps_seal_only_at_completion_or_exact_timeout() {
    let current = fence(1, 1, "head");
    let mut maps = IndependentMaps::new(["worker-a", "worker-b"], Some(10)).expect("map set");
    maps.submit_first_pass(FirstPassMap {
        worker_id: "worker-a".into(),
        map_digest: "digest-a".into(),
        fence: current.clone(),
    })
    .expect("first map");
    assert!(maps.seal(9).is_err(), "partial maps cannot seal early");

    let timeout = maps.seal(10).expect("exact timeout seal");
    assert_eq!(timeout.reason, MapSealReason::ExactTimeout);
    assert_eq!(timeout.map_ids, vec!["worker-a"]);
    assert!(maps.is_sealed());
    assert!(
        maps.submit_first_pass(FirstPassMap {
            worker_id: "worker-b".into(),
            map_digest: "digest-b".into(),
            fence: current,
        })
        .is_err()
    );
    let receipt_json = to_value(&timeout).expect("seal receipt JSON");
    assert!(receipt_json.get("map_digest").is_none());
    assert!(receipt_json.get("map_ids").is_some());

    let mut complete =
        IndependentMaps::new(["worker-a", "worker-b"], Some(10)).expect("complete map set");
    for (worker_id, map_digest) in [("worker-a", "digest-a"), ("worker-b", "digest-b")] {
        complete
            .submit_first_pass(FirstPassMap {
                worker_id: worker_id.into(),
                map_digest: map_digest.into(),
                fence: fence(1, 1, "head"),
            })
            .expect("map pass");
    }
    let all = complete.seal(4).expect("all map passes seal");
    assert_eq!(all.reason, MapSealReason::AllFirstPasses);
    assert_eq!(all.map_ids, vec!["worker-a", "worker-b"]);
    assert_eq!(complete.seal(4).expect("sealed receipt is idempotent"), all);
}

#[test]
fn only_current_controller_can_publish_one_immutable_replan() {
    let current = fence(1, 2, "head");
    let stale = fence(1, 1, "old-head");
    let attempt = ControllerAttempt::new("attempt", "controller", current.clone())
        .expect("controller attempt");
    let replan = Replan {
        replan_id: "replan-1".into(),
        controller_id: "controller".into(),
        fence: current.clone(),
        plan_digest: "plan-digest".into(),
        published_at: 3,
    };
    let mut publication = ReplanPublication::default();
    assert!(publication.publish(replan.clone(), false).is_err());
    assert!(
        publication
            .publish_from_controller(
                &attempt,
                Replan {
                    fence: stale,
                    ..replan.clone()
                }
            )
            .is_err()
    );
    assert!(
        publication
            .publish_from_controller(
                &ControllerAttempt::new("other", "other-controller", current.clone())
                    .expect("other controller"),
                replan.clone(),
            )
            .is_err()
    );
    let published = publication
        .publish_from_controller(&attempt, replan.clone())
        .expect("controller replan");
    assert_eq!(published, replan);
    assert!(publication.publish(replan, true).is_err());
}

#[test]
fn next_boundary_delivery_preserves_all_four_states_and_deduplicates() {
    let current = fence(1, 4, "head");
    let other_fence = fence(1, 5, "next-head");
    let states = [
        PeerDeliveryState::EventIntegrated,
        PeerDeliveryState::ToolOnly,
        PeerDeliveryState::OfflineWorker,
        PeerDeliveryState::Unavailable,
    ];
    let mut book = PeerDeliveryBook::default();
    for (index, state) in states.iter().copied().enumerate() {
        book.deliver(PeerDelivery {
            delivery_id: format!("delivery-{index}"),
            recipient: "recipient".into(),
            fence: current.clone(),
            evidence_digest: format!("evidence-{index}"),
            dedup_key: format!("boundary-{index}"),
            state,
        })
        .expect("delivery");
    }
    assert_eq!(
        book.for_next_boundary("recipient", &current).len(),
        states.len()
    );
    assert!(book.for_next_boundary("recipient", &other_fence).is_empty());
    assert!(book.for_next_boundary("other", &current).is_empty());

    let replay = book
        .deliver(PeerDelivery {
            delivery_id: "delivery-0".into(),
            recipient: "recipient".into(),
            fence: current.clone(),
            evidence_digest: "evidence-0".into(),
            dedup_key: "boundary-0".into(),
            state: PeerDeliveryState::EventIntegrated,
        })
        .expect("same delivery replay is idempotent");
    assert_eq!(replay.delivery_id, "delivery-0");
    assert!(
        book.deliver(PeerDelivery {
            delivery_id: "delivery-other".into(),
            recipient: "recipient".into(),
            fence: current.clone(),
            evidence_digest: "evidence-other".into(),
            dedup_key: "boundary-0".into(),
            state: PeerDeliveryState::ToolOnly,
        })
        .is_err()
    );
    assert!(
        book.deliver(PeerDelivery {
            delivery_id: "delivery-0".into(),
            recipient: "recipient".into(),
            fence: current,
            evidence_digest: "evidence-other".into(),
            dedup_key: "boundary-other".into(),
            state: PeerDeliveryState::ToolOnly,
        })
        .is_err()
    );
}

#[test]
fn review_anchor_survives_rename_and_reports_missing_or_ambiguous_rebase() {
    let mut reviews = ReviewBook::default();
    reviews
        .add(ReviewItem {
            review_id: "review-1".into(),
            batch_id: "batch-1".into(),
            anchor: ReviewAnchor {
                anchor_id: "anchor-1".into(),
                path: "src/old.rs".into(),
                symbol: "run".into(),
                line: 10,
                context_digest: "context-old".into(),
            },
            summary: "review finding".into(),
            open: true,
        })
        .expect("review item");
    let renamed = AnchorRevision {
        anchor_id: "anchor-1".into(),
        batch_id: "batch-2".into(),
        path: "src/new.rs".into(),
        symbol: "run".into(),
        line: 12,
        context_digest: "context-new".into(),
    };
    reviews
        .revise_anchor(renamed.clone())
        .expect("rename/rebase revision");
    assert_eq!(reviews.revisions["anchor-1"].len(), 1);
    assert!(reviews.revise_anchor(renamed.clone()).is_err());

    let exact = reviews
        .resolve_anchor("review-1", [renamed.clone()])
        .expect("exact anchor");
    assert_eq!(exact.resolution, AnchorResolution::Exact);
    let missing = reviews
        .resolve_anchor("review-1", std::iter::empty::<AnchorRevision>())
        .expect("missing anchor");
    assert_eq!(missing.resolution, AnchorResolution::Missing);
    let ambiguous = reviews
        .resolve_anchor(
            "review-1",
            [
                renamed,
                AnchorRevision {
                    anchor_id: "anchor-1".into(),
                    batch_id: "batch-3".into(),
                    path: "src/other.rs".into(),
                    symbol: "run".into(),
                    line: 12,
                    context_digest: "context-other".into(),
                },
            ],
        )
        .expect("ambiguous anchor");
    assert_eq!(ambiguous.resolution, AnchorResolution::Ambiguous);
}

#[test]
fn second_same_mechanism_failure_opens_review_and_duplicate_is_rejected() {
    let mut failures = MechanismFailureBook::default();
    let first = MechanismFailure {
        mechanism: "transport".into(),
        failure_digest: "failure-1".into(),
        evidence: "evidence-1".into(),
    };
    assert_eq!(
        failures.record(first.clone()).expect("first failure"),
        FailureDisposition::Recorded
    );
    assert!(failures.record(first).is_err());
    assert_eq!(
        failures
            .record(MechanismFailure {
                mechanism: "transport".into(),
                failure_digest: "failure-2".into(),
                evidence: "evidence-2".into(),
            })
            .expect("second failure"),
        FailureDisposition::MechanismReviewOpened
    );
    assert_eq!(failures.reviews["transport"].failures.len(), 2);
}
