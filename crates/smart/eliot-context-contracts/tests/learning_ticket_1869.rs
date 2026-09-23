//! Learning admission ticket proof for issue #1869 (round 7).
//!
//! The wire twin carries the exact bound fields and digest of an issuance.
//! Deterministic digests, tamper sensitivity, and the pure freshness check
//! (`ticket_fresh_for`) are proven here; live owner minting is proven in
//! `eliot-governor`, guest enforcement in the compiler adapter.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_context_contracts::{
    LEARNING_TICKET_SCHEMA_VERSION, LearningAdmissionTicket, learning_ticket_digest,
    ticket_fresh_for,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskRevision};

const LINEAGE_1869: &str = "550e8400-e29b-41d4-a716-446655440000";

fn epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_1869).expect("lineage"),
        NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch")
}

fn fence(sequence: u64) -> StateFence {
    StateFence::new(
        epoch(sequence),
        ResourceGeneration::new(7).expect("generation"),
    )
}

fn ticket() -> LearningAdmissionTicket {
    LearningAdmissionTicket {
        schema_version: LEARNING_TICKET_SCHEMA_VERSION,
        source_campaign_id: "campaign-1869-a".to_string(),
        target_task_id: "task-1869-a".to_string(),
        fence: fence(3),
        overlay_id: Some("overlay-1869-live".to_string()),
        candidate_id: Some("candidate-1869-a".to_string()),
        scope_ref: "scope-1869".to_string(),
        authority_ref: "governor-1869".to_string(),
        retention_ref: "retention-1869".to_string(),
        evaluator_ref: "evaluator-1869-a".to_string(),
        rollback_ref: "rollback-1869".to_string(),
        digest: "0".repeat(64),
    }
}

fn minted() -> LearningAdmissionTicket {
    let mut ticket = ticket();
    ticket.digest = learning_ticket_digest(&ticket).expect("digest computes");
    ticket
}

#[test]
fn digest_is_deterministic_and_shape_valid() {
    let first = minted();
    let second = minted();
    assert_eq!(first.digest, second.digest);
    first.validate().expect("minted shape validates");
}

#[test]
fn tampering_breaks_the_digest() {
    let ticket = minted();
    let mut forged = ticket.clone();
    forged.overlay_id = Some("overlay-forged".to_string());
    assert_ne!(
        learning_ticket_digest(&forged).expect("digest computes"),
        ticket.digest
    );
    let mut swapped = ticket.clone();
    swapped.target_task_id = "task-1869-other".to_string();
    assert_ne!(
        learning_ticket_digest(&swapped).expect("digest computes"),
        ticket.digest
    );
}

#[test]
fn fresh_check_binds_live_state() {
    let ticket = minted();
    let live = || {
        (
            epoch(3),
            ResourceGeneration::new(7).expect("generation"),
            fence(3),
        )
    };
    let (epoch_live, gen_live, fence_live) = live();
    assert!(ticket_fresh_for(&ticket, &epoch_live, gen_live, &fence_live));
    // Rotated epoch: stale.
    assert!(!ticket_fresh_for(
        &ticket,
        &epoch(4),
        gen_live,
        &fence_live
    ));
    // Drifted fence under the same epoch: stale.
    let mut drifted = fence(3);
    drifted.task_revision = Some(TaskRevision::new(2).expect("task revision"));
    assert!(!ticket_fresh_for(&ticket, &epoch_live, gen_live, &drifted));
    // Tampered digest: stale.
    let mut forged = ticket.clone();
    forged.digest = "f".repeat(64);
    assert!(!ticket_fresh_for(&forged, &epoch_live, gen_live, &fence_live));
}
