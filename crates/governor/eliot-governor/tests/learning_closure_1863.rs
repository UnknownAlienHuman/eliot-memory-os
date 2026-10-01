use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence,
};
use eliot_governor::{
    ClosureIdentityInput, LearningClosureOutcome, LearningClosureService, PromotionBoundaryInput,
    StoredDeltaIdentity, retry_relation_from_prior,
};
use eliot_learning_contracts::{CampaignId, OverlayId};
use eliot_learning_delta::{
    AttemptCloseDisposition, ConsequentialBoundary, LifecycleActivity, RetryEquivalence,
};

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn aid(value: &str) -> ArtifactId {
    ArtifactId::new(value.to_owned()).expect("valid artifact identity")
}

fn fence(sequence: u64) -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new(LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero sequence"),
        )
        .expect("valid test epoch"),
        ResourceGeneration::new(7).expect("valid resource generation"),
    )
}

fn identity(job_id: &str, attempts: u32, fingerprint: char, state_fence: StateFence) -> ClosureIdentityInput {
    ClosureIdentityInput {
        task_id: "task-1863".to_owned(),
        job_id: job_id.to_owned(),
        attempts,
        actor_id: "actor-1863".to_owned(),
        route_id: "route-1863".to_owned(),
        overlay_id: OverlayId::from_artifact(aid("overlay-1863")),
        strategy_fingerprint: fingerprint.to_string().repeat(64),
        state_fence,
        evidence_refs: vec![aid("canonical-verifier-run")],
    }
}

fn close(
    service: &LearningClosureService,
    identity: ClosureIdentityInput,
) -> eliot_governor::LearningClosureReceipt {
    let evidence = vec![aid("canonical-raw-verifier-evidence")];
    let outcome = service
        .close_attempt(
            identity,
            "cargo-test",
            &[LifecycleActivity::AttemptSettled, LifecycleActivity::VerifierOutcome],
            AttemptCloseDisposition::InvalidEvidence,
            None,
            evidence,
            None,
            &[],
            PromotionBoundaryInput::absent(),
        )
        .expect("owner close commits");
    let LearningClosureOutcome::Committed(receipt) = outcome else {
        panic!("observed verifier failure is a consequential close");
    };
    *receipt
}

#[test]
fn related_retry_readback_references_exact_durable_failed_close() {
    let service = LearningClosureService::new();
    let first = close(&service, identity("job-failed", 1, 'a', fence(1)));
    let (committed, version) = service.store().load().expect("canonical readback");
    assert_eq!(version, 1);
    assert_eq!(committed, vec![first.record.clone()]);
    assert_eq!(
        first.record.disposition,
        eliot_learning_delta::StoredDeltaDisposition::InvalidEvidence
    );

    let retry = close(&service, identity("job-retry", 1, 'b', fence(1)));
    let (committed, version) = service.store().load().expect("retry readback");
    assert_eq!(version, 2);
    let stored_retry = committed.last().expect("retry record persisted");
    let relation = stored_retry
        .retry_relation
        .as_ref()
        .expect("materially related retry retains its prior lineage");
    assert_eq!(relation.prior_attempt_id, first.record.attempt_id);
    assert_eq!(relation.prior_delta_artifact, first.record.delta_artifact);
    assert_eq!(relation.prior_delta_digest, first.record.delta_digest);
    assert_eq!(relation.prior_observable_refs, first.record.evidence_refs);
    assert_eq!(relation.equivalence, RetryEquivalence::Distinct);
    assert!(stored_retry
        .retry_canonical_evidence()
        .contains(&first.record.evidence_refs[0]));
    assert_eq!(&retry.record, stored_retry);
}

#[test]
fn foreign_stale_same_attempt_and_empty_evidence_cannot_form_retry_lineage() {
    let service = LearningClosureService::new();
    let first = close(&service, identity("job-failed", 1, 'a', fence(1)));
    let (records, _) = service.store().load().expect("canonical readback");
    let prior = records.first().expect("failed close persisted");

    let base = StoredDeltaIdentity {
        campaign_id: CampaignId::from_artifact(aid("task-1863")),
        attempt_id: eliot_learning_contracts::AgentAttemptId::new("job-retry:attempt:1")
            .expect("retry attempt identity"),
        state_fence: fence(1),
        actor_id: "actor-1863".to_owned(),
        route_id: "route-1863".to_owned(),
        overlay_id: OverlayId::from_artifact(aid("overlay-1863")),
        consequential_boundary: ConsequentialBoundary::VerifierOutcome,
        strategy_fingerprint: "b".repeat(64),
        evidence_refs: vec![aid("retry-verifier-run")],
    };
    assert!(retry_relation_from_prior(Some(prior), &base, None).is_some());

    let mut foreign = base.clone();
    foreign.campaign_id = CampaignId::from_artifact(aid("other-task"));
    assert!(retry_relation_from_prior(Some(prior), &foreign, None).is_none());

    let mut stale = base.clone();
    stale.state_fence = fence(2);
    assert!(retry_relation_from_prior(Some(prior), &stale, None).is_none());

    let mut same_attempt = base.clone();
    same_attempt.attempt_id = first.record.attempt_id.clone();
    assert!(retry_relation_from_prior(Some(prior), &same_attempt, None).is_none());

    let mut empty_evidence = base;
    empty_evidence.evidence_refs.clear();
    assert!(retry_relation_from_prior(Some(prior), &empty_evidence, None).is_none());
}
