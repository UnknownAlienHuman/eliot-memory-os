//! Governor learning-admission proof for issue #1869 (round 3).
//!
//! Genuine issuer-to-consumer path: permits are issued by the real
//! [`Governor`] owner and verified against live owner state. Fabricated,
//! foreign-epoch, rotated-epoch, and stale-fence inputs are refused. The
//! opaque [`LearningAdmissionPermit`] cannot be constructed by hand here —
//! its fields are private to the owner crate — so forgery is a compile-time
//! impossibility, not a test assertion.

use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskRevision};
use eliot_governor::{
    Governor, GovernorConfig, LearningAdmissionClaim, LearningAdmissionError, QueueLimits,
    issue_learning_admission, verify_learning_admission,
};

const LINEAGE_1869: &str = "550e8400-e29b-41d4-a716-446655440000";
const FOREIGN_LINEAGE: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

fn epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_1869).expect("valid test lineage"),
        NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

fn governor_at(sequence: u64) -> Governor {
    let config = GovernorConfig {
        authority_epoch: epoch(sequence),
        resource_generation: ResourceGeneration::new(7).expect("valid test generation"),
        queues: QueueLimits::default(),
        background_pause_interactive_depth: 1,
    };
    let mut governor = Governor::new(config).expect("valid test governor config");
    governor.begin_startup().expect("startup begins");
    governor
}

fn fence_at(sequence: u64) -> StateFence {
    StateFence::new(
        epoch(sequence),
        ResourceGeneration::new(7).expect("valid test generation"),
    )
}

fn claim_1869(sequence: u64) -> LearningAdmissionClaim {
    LearningAdmissionClaim {
        schema_version: eliot_governor::LEARNING_ADMISSION_SCHEMA_VERSION,
        source_campaign_id: "campaign-1869-a".to_string(),
        target_task_id: "task-1869-a".to_string(),
        fence: fence_at(sequence),
        overlay_id: Some("overlay-1869-live".to_string()),
        candidate_id: Some("candidate-1869-a".to_string()),
        scope_ref: "scope-1869".to_string(),
        authority_ref: "governor-1869-policy-1".to_string(),
        retention_ref: "retention-1869".to_string(),
        evaluator_ref: "evaluator-1869-a".to_string(),
        rollback_ref: "rollback-1869".to_string(),
    }
}

#[test]
fn issuer_to_verifier_roundtrip() {
    let governor = governor_at(3);
    let fence = fence_at(3);
    let permit = issue_learning_admission(&governor, &claim_1869(3))
        .expect("live owner issues under live epoch");
    assert_eq!(permit.source_campaign_id(), "campaign-1869-a");
    assert_eq!(permit.target_task_id(), "task-1869-a");
    assert_eq!(permit.overlay_id(), Some("overlay-1869-live"));
    assert_eq!(permit.candidate_id(), Some("candidate-1869-a"));
    assert_eq!(permit.authority_ref(), "governor-1869-policy-1");
    assert_eq!(permit.rollback_ref(), "rollback-1869");
    assert!(!permit.digest().is_empty());
    let verified = verify_learning_admission(&governor, &permit, &fence)
        .expect("live owner verifies its own permit under the same fence");
    assert_eq!(
        verified.permit().digest(),
        permit.digest(),
        "verified handle borrows the exact permit it verified"
    );
}

#[test]
fn constructed_governor_does_not_issue() {
    let config = GovernorConfig {
        authority_epoch: epoch(3),
        resource_generation: ResourceGeneration::new(7).expect("valid test generation"),
        queues: QueueLimits::default(),
        background_pause_interactive_depth: 1,
    };
    let governor = Governor::new(config).expect("valid test governor config");
    let err = issue_learning_admission(&governor, &claim_1869(3))
        .expect_err("constructed owner admits nothing");
    assert_eq!(err, LearningAdmissionError::GovernorNotAdmitting);
}

#[test]
fn foreign_epoch_claim_refused() {
    let governor = governor_at(3);
    let mut claim = claim_1869(3);
    claim.fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new(FOREIGN_LINEAGE).expect("valid foreign lineage"),
            NonZeroU64::new(3).expect("nonzero sequence"),
        )
        .expect("valid foreign epoch"),
        ResourceGeneration::new(7).expect("valid test generation"),
    );
    let err =
        issue_learning_admission(&governor, &claim).expect_err("foreign lineage never authorizes");
    assert_eq!(err, LearningAdmissionError::StaleAuthorityEpoch);
}

#[test]
fn rotated_epoch_invalidates_permit() {
    let governor = governor_at(3);
    let fence = fence_at(3);
    let permit = issue_learning_admission(&governor, &claim_1869(3)).expect("issued under epoch 3");
    let rotated = governor_at(4);
    let err = verify_learning_admission(&rotated, &permit, &fence)
        .expect_err("epoch rotation invalidates old permits");
    assert_eq!(err, LearningAdmissionError::DigestMismatch);
}

#[test]
fn stale_fence_refused() {
    let governor = governor_at(3);
    let fence = fence_at(3);
    let permit = issue_learning_admission(&governor, &claim_1869(3)).expect("issued under epoch 3");
    let mut drifted = fence.clone();
    drifted.task_revision = Some(TaskRevision::new(2).expect("valid task revision"));
    let err = verify_learning_admission(&governor, &permit, &drifted)
        .expect_err("fence drift refuses even under the same epoch");
    assert_eq!(err, LearningAdmissionError::StaleStateFence);
    // Exact same fence still verifies: no false stale.
    verify_learning_admission(&governor, &permit, &fence).expect("identical fence verifies");
}

#[test]
fn subjectless_claim_refused() {
    let governor = governor_at(3);
    let mut claim = claim_1869(3);
    claim.overlay_id = None;
    claim.candidate_id = None;
    let err = issue_learning_admission(&governor, &claim)
        .expect_err("permits bind at least one influence subject");
    assert_eq!(err, LearningAdmissionError::NoInfluenceSubject);
}
