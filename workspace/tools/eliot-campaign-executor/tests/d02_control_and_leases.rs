#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_campaign_executor::EpochId;
use eliot_campaign_executor::control::{
    AuthorityCeiling, BuildCoordinator, BuildFingerprint, BuildJoin, ChildState, ClaimRegistry,
    ClaimRequest, ClaimScope, ControlCommand, ControllerAttempt, HandoffKind, HandoffSlot,
    HandoffStatus, PackageLeaseBook, PackageLeaseState, ParentFinishGate, StateFence,
    WorkCheckpoint, WorkLease, WorkLeaseState, WorkerAttempt,
};
use uuid::Uuid;

fn epoch(sequence: u64) -> EpochId {
    EpochId {
        lineage: Uuid::from_u128(0xD02),
        sequence,
    }
}

fn fence(epoch_sequence: u64, ledger_sequence: u64, head: &str) -> StateFence {
    StateFence::new(epoch(epoch_sequence), ledger_sequence, head)
}

#[test]
fn lost_controller_epoch_fences_old_attempts() {
    let old_fence = fence(1, 7, "head-7");
    let new_fence = fence(2, 1, "head-1");
    assert!(old_fence.is_older_than(&new_fence));
    assert!(!old_fence.matches(&new_fence));

    let old = ControllerAttempt::new("attempt-old", "controller-old", old_fence.clone())
        .expect("old controller attempt");
    let current = ControllerAttempt::new("attempt-new", "controller-new", new_fence.clone())
        .expect("new controller attempt");
    assert!(!old.fence.matches(&current.fence));

    let stale_worker =
        WorkerAttempt::new("worker-old", "worker", old_fence).expect("stale worker attempt");
    assert!(!stale_worker.is_current(&new_fence));
}

#[test]
fn lost_worker_reassignment_fences_stale_slice_and_old_worker() {
    let original_fence = fence(1, 7, "head-7");
    let replacement_fence = fence(1, 8, "head-8");
    let mut lease = WorkLease::new(
        "lease-1",
        "owner",
        "worker-old",
        ClaimScope::path("src/worker.rs"),
        original_fence.clone(),
    )
    .expect("work lease");

    lease
        .checkpoint(WorkCheckpoint {
            checkpoint_id: "checkpoint-1".into(),
            lease_id: "lease-1".into(),
            worker_attempt_id: "worker-old".into(),
            generation: 1,
            fence: original_fence.clone(),
            status: eliot_campaign_executor::control::CheckpointStatus::Saved,
            evidence_digest: "evidence-1".into(),
        })
        .expect("initial checkpoint");
    let lost = lease
        .mark_worker_lost("lost-1", "lost-evidence")
        .expect("lost-worker checkpoint");
    assert_eq!(
        lost.status,
        eliot_campaign_executor::control::CheckpointStatus::LostWorker
    );
    assert_eq!(lease.state, WorkLeaseState::WorkerLost);

    let reassigned = lease
        .reassign("worker-new", replacement_fence.clone())
        .expect("reassign worker");
    assert_eq!(
        reassigned.status,
        eliot_campaign_executor::control::CheckpointStatus::Reassigned
    );
    assert_eq!(reassigned.generation, 2);
    assert_eq!(lease.state, WorkLeaseState::Active);

    assert!(
        lease
            .checkpoint(WorkCheckpoint {
                checkpoint_id: "stale-generation".into(),
                lease_id: "lease-1".into(),
                worker_attempt_id: "worker-new".into(),
                generation: 1,
                fence: replacement_fence.clone(),
                status: eliot_campaign_executor::control::CheckpointStatus::Saved,
                evidence_digest: "stale".into(),
            })
            .is_err(),
        "a stale slice generation must not be accepted"
    );
    assert!(
        lease.complete("worker-old", &replacement_fence).is_err(),
        "the lost worker cannot complete the reassigned slice"
    );
    lease
        .complete("worker-new", &replacement_fence)
        .expect("replacement worker completion");
    assert_eq!(lease.state, WorkLeaseState::Completed);
}

#[test]
fn one_slot_handoff_requires_author_review_or_assembly_temporal_order() {
    let current = fence(1, 9, "head-9");
    let stale = fence(1, 8, "head-8");
    let mut slot = HandoffSlot::default();
    let offered = slot
        .offer(
            "handoff-review",
            "author",
            "reviewer",
            HandoffKind::Review,
            current.clone(),
            "review-evidence",
        )
        .expect("review handoff offer");
    assert_eq!(offered.slot, 1);
    assert_eq!(offered.status, HandoffStatus::Offered);
    assert!(
        slot.offer(
            "duplicate",
            "author",
            "reviewer",
            HandoffKind::Review,
            current.clone(),
            "e"
        )
        .is_err()
    );
    assert!(
        slot.accept("handoff-review", "other-reviewer", &current)
            .is_err()
    );
    assert!(slot.accept("handoff-review", "reviewer", &stale).is_err());
    assert!(
        slot.complete("handoff-review", "reviewer", &current)
            .is_err()
    );
    let accepted = slot
        .accept("handoff-review", "reviewer", &current)
        .expect("review acceptance");
    assert_eq!(accepted.status, HandoffStatus::Accepted);
    let completed = slot
        .complete("handoff-review", "reviewer", &current)
        .expect("review completion");
    assert_eq!(completed.status, HandoffStatus::Completed);
    assert!(slot.receipt.is_none());

    let assembly = slot
        .offer(
            "handoff-assembly",
            "author",
            "assembler",
            HandoffKind::Assembly,
            current.clone(),
            "assembly-evidence",
        )
        .expect("assembly handoff offer");
    assert_eq!(assembly.kind, HandoffKind::Assembly);
    slot.accept("handoff-assembly", "assembler", &current)
        .expect("assembly acceptance");
    slot.complete("handoff-assembly", "assembler", &current)
        .expect("assembly completion");
    assert!(
        HandoffSlot::default()
            .offer(
                "self",
                "author",
                "author",
                HandoffKind::Review,
                current,
                "e"
            )
            .is_err()
    );
}

#[test]
fn claim_registry_rejects_path_package_symbol_and_generated_overlap() {
    let current = fence(1, 1, "head");
    let mut registry = ClaimRegistry::default();
    registry
        .claim(ClaimRequest {
            claim_id: "path".into(),
            owner_id: "owner-a".into(),
            scope: ClaimScope::path("crates/demo/src"),
            fence: current.clone(),
        })
        .expect("path claim");
    assert!(
        registry
            .claim(ClaimRequest {
                claim_id: "symbol".into(),
                owner_id: "owner-b".into(),
                scope: ClaimScope::symbol("demo", "crates/demo/src/lib.rs", "run"),
                fence: current.clone(),
            })
            .is_err()
    );
    assert!(
        registry
            .claim(ClaimRequest {
                claim_id: "package".into(),
                owner_id: "owner-c".into(),
                scope: ClaimScope::package("crates/demo"),
                fence: current.clone(),
            })
            .is_err()
    );

    registry
        .release("path", "owner-a")
        .expect("claim owner release");
    registry
        .claim(ClaimRequest {
            claim_id: "generated-a".into(),
            owner_id: "owner-a".into(),
            scope: ClaimScope::generated("help/demo"),
            fence: current.clone(),
        })
        .expect("generated claim");
    assert!(
        registry
            .claim(ClaimRequest {
                claim_id: "generated-b".into(),
                owner_id: "owner-b".into(),
                scope: ClaimScope::generated("help/demo"),
                fence: current,
            })
            .is_err()
    );
}

#[test]
fn package_and_integration_leases_are_single_holder_and_fenced() {
    let current = fence(1, 2, "head");
    let stale = fence(1, 1, "old-head");
    let mut book = PackageLeaseBook::default();
    let assembly = book
        .acquire_assembly("assembly-1", "demo", "assembler", current.clone())
        .expect("assembly lease");
    assert_eq!(assembly.state, PackageLeaseState::Held);
    assert!(
        book.acquire_assembly("assembly-2", "demo", "other", current.clone())
            .is_err()
    );
    assert!(book.release_assembly("demo", "other", &current).is_err());
    assert!(book.release_assembly("demo", "assembler", &stale).is_err());
    book.release_assembly("demo", "assembler", &current)
        .expect("assembly release");

    assert!(
        book.queue_integration(eliot_campaign_executor::control::IntegrationRequest {
            package: "demo".into(),
            author_id: "author".into(),
            integrator_id: "author".into(),
            fence: current.clone(),
        })
        .is_err()
    );
    let request = eliot_campaign_executor::control::IntegrationRequest {
        package: "demo".into(),
        author_id: "author".into(),
        integrator_id: "integrator".into(),
        fence: current.clone(),
    };
    book.queue_integration(request.clone())
        .expect("queue integration");
    assert!(book.queue_integration(request).is_err());
    let integration = book
        .acquire_next_integration("integration-1", "integrator", current.clone())
        .expect("integration lease");
    assert_eq!(integration.state, PackageLeaseState::Held);
    assert!(
        book.acquire_next_integration("integration-2", "integrator", current.clone())
            .is_err()
    );
    assert!(
        book.release_integration("integration-1", "other", &current)
            .is_err()
    );
    assert!(
        book.release_integration("integration-1", "integrator", &stale)
            .is_err()
    );
    let released = book
        .release_integration("integration-1", "integrator", &current)
        .expect("integration release");
    assert_eq!(released.state, PackageLeaseState::Released);
}

#[test]
fn identical_build_fingerprint_is_single_flight_and_wakes_waiters() {
    let current = fence(1, 3, "head");
    let fingerprint = BuildFingerprint::new("build-fingerprint-1").expect("fingerprint");
    let mut builds = BuildCoordinator::default();
    assert!(BuildFingerprint::new(" ").is_err());
    assert!(matches!(
        builds.join("producer", "producer", fingerprint.clone(), current.clone()),
        Ok(BuildJoin::Producer(_))
    ));
    assert!(matches!(
        builds.join("producer", "waiter-a", fingerprint.clone(), current.clone()),
        Ok(BuildJoin::Waiter(_))
    ));
    assert!(matches!(
        builds.join("producer", "waiter-b", fingerprint.clone(), current.clone()),
        Ok(BuildJoin::Waiter(_))
    ));
    assert!(builds.complete(&fingerprint, "wrong-producer").is_err());
    let waiters = builds
        .complete(&fingerprint, "producer")
        .expect("build completion");
    assert_eq!(
        waiters
            .iter()
            .map(|waiter| waiter.waiter_id.as_str())
            .collect::<Vec<_>>(),
        vec!["waiter-a", "waiter-b"]
    );
    assert!(
        matches!(
            builds.join("second-producer", "after", fingerprint, current),
            Ok(BuildJoin::Waiter(_))
        ),
        "a completed fingerprint must not start a duplicate producer"
    );
}

#[test]
fn authority_ceiling_and_parent_child_finish_are_monotonic() {
    assert!(AuthorityCeiling::Observe.permits(ControlCommand::Observe));
    assert!(!AuthorityCeiling::Observe.permits(ControlCommand::ClaimWork));
    assert!(AuthorityCeiling::Claim.permits(ControlCommand::ClaimWork));
    assert!(!AuthorityCeiling::Claim.permits(ControlCommand::Checkpoint));
    assert!(AuthorityCeiling::Write.permits(ControlCommand::Checkpoint));
    assert!(!AuthorityCeiling::Write.permits(ControlCommand::AssemblePackage));
    assert!(AuthorityCeiling::Assemble.permits(ControlCommand::AssemblePackage));
    assert!(!AuthorityCeiling::Assemble.permits(ControlCommand::IntegratePackage));
    assert!(AuthorityCeiling::Integrate.permits(ControlCommand::IntegratePackage));
    assert!(!AuthorityCeiling::Integrate.permits(ControlCommand::Replan));
    assert!(AuthorityCeiling::Controller.permits(ControlCommand::Replan));
    assert!(AuthorityCeiling::Controller.permits(ControlCommand::FinishParent));
    assert!(
        AuthorityCeiling::Write
            .reject_command(ControlCommand::AssemblePackage)
            .is_err()
    );

    let mut gate = ParentFinishGate::default();
    assert!(gate.can_finish());
    gate.set_child("live", ChildState::Live)
        .expect("live child");
    gate.set_child("lost", ChildState::Unreachable)
        .expect("unreachable child");
    assert!(!gate.can_finish());
    let blocked = gate
        .finish("parent")
        .expect_err("parent finish must be blocked");
    assert!(blocked.to_string().contains("parent"));
    gate.set_child("live", ChildState::Finished)
        .expect("finish live child");
    gate.set_child("lost", ChildState::Finished)
        .expect("reconcile unreachable child");
    assert!(gate.can_finish());
    gate.finish("parent").expect("all children finished");
}
