//! Bounded candidate backlog + cross-task refusal proof for issue #1869.
//!
//! Smallest proof named under the acceptance criteria: lineage dedup merge,
//! expired/unclosed retrieval refusal, and governed cross-task admission.

use eliot_improvement::candidate_bounds::{
    AdmitOutcome, ArchiveCause, BoundedBacklog, BoundsError, CandidateBoundPolicy,
    CrossTaskAdmission, GovernedOverlay, OverlayState, ReusableCandidateRef, retrieve_for_attempt,
};
use eliot_improvement::{ImprovementCandidate, ImprovementSurface, ReplayPlan};
use std::collections::BTreeMap;
use time::{Duration, OffsetDateTime};

fn replay_plan() -> ReplayPlan {
    ReplayPlan {
        fixed_replay_refs: vec!["replay-1869-a".to_string()],
        holdout_refs: vec!["holdout-1869-a".to_string()],
        transfer_refs: vec!["transfer-1869-a".to_string()],
        counter_metric_names: vec!["cost-1869".to_string()],
        verifier_refs: vec!["verifier-1869-a".to_string()],
    }
}

fn candidate(evidence: &[&str]) -> ImprovementCandidate {
    ImprovementCandidate::new(
        "project-1869",
        ImprovementSurface::Memory,
        "tighten context budget",
        vec!["retrieval-regret".to_string()],
        vec!["authority-change".to_string()],
        vec!["trace-1869-a".to_string()],
        evidence.iter().map(|e| e.to_string()).collect(),
        replay_plan(),
        BTreeMap::new(),
    )
    .expect("fixture candidate validates")
}

fn policy(max_active: usize) -> CandidateBoundPolicy {
    CandidateBoundPolicy {
        target_surface: ImprovementSurface::Memory,
        max_active,
        min_value: 1.0,
        governor_authority_ref: "governor-1869-policy-1".to_string(),
        policy_revision: 1,
    }
}

fn live_overlay(campaign: &str, now: OffsetDateTime) -> GovernedOverlay {
    GovernedOverlay {
        overlay_id: format!("overlay-{campaign}"),
        campaign_id: campaign.to_string(),
        task_id: format!("task-{campaign}"),
        fence_ref: format!("fence-{campaign}"),
        compatible_recipe_ref: "recipe-1869".to_string(),
        state: OverlayState::LocalAdmitted,
        admission_ref: Some(format!("admission-{campaign}")),
        expires_at: Some(now + Duration::hours(1)),
    }
}

fn closed_reusable(origin_campaign: &str) -> ReusableCandidateRef {
    ReusableCandidateRef {
        candidate_id: "candidate-reusable-1869".to_string(),
        closure_ref: Some("closure-1869-a".to_string()),
        owner: Some("governor-1869".to_string()),
        origin_campaign_id: origin_campaign.to_string(),
    }
}

#[test]
fn duplicate_lineage_merges_with_provenance() {
    let mut backlog = BoundedBacklog::new(vec![policy(8)]).expect("policy validates");
    let first = candidate(&["ev-1869-a", "ev-1869-b"]);
    let first_id = first.candidate_id.clone();
    assert!(matches!(
        backlog.admit(first, 3.0, Some("governor-1869".to_string())),
        Ok(AdmitOutcome::Admitted { .. })
    ));

    let second = candidate(&["ev-1869-b", "ev-1869-c"]);
    let second_id = second.candidate_id.clone();
    let outcome = backlog
        .admit(second, 4.0, Some("governor-1869".to_string()))
        .expect("duplicate admits merge");
    assert_eq!(
        outcome,
        AdmitOutcome::Merged {
            surviving_candidate_id: first_id.clone(),
            absorbed_candidate_id: second_id.clone(),
        }
    );

    let active = backlog.active_for(ImprovementSurface::Memory);
    assert_eq!(active.len(), 1);
    let surviving = active[0];
    assert_eq!(surviving.candidate.candidate_id, first_id);
    assert!(surviving.merged_from.contains(&second_id));
    for evidence in ["ev-1869-a", "ev-1869-b", "ev-1869-c"] {
        assert!(
            surviving
                .candidate
                .evidence_refs
                .iter()
                .any(|r| r == evidence),
            "merged candidate preserves {evidence}"
        );
    }
}

#[test]
fn expired_overlay_and_unclosed_reusable_are_refused() {
    let now = OffsetDateTime::now_utc();
    let mut expired = live_overlay("campaign-a", now);
    expired.expires_at = Some(now - Duration::minutes(1));
    let refusal = retrieve_for_attempt(
        "campaign-b",
        "task-campaign-b",
        &expired,
        None,
        false,
        None,
        now,
    );
    assert_eq!(refusal, Err(BoundsError::ExpiredOverlay));

    let overlay_b = live_overlay("campaign-b", now);
    let mut unclosed = closed_reusable("campaign-a");
    unclosed.closure_ref = None;
    let refusal = retrieve_for_attempt(
        "campaign-b",
        "task-campaign-b",
        &overlay_b,
        Some(&unclosed),
        false,
        None,
        now,
    );
    assert_eq!(refusal, Err(BoundsError::UnclosedReusable));
}

#[test]
fn cross_task_use_requires_governed_admission() {
    let now = OffsetDateTime::now_utc();
    let overlay_a = live_overlay("campaign-a", now);
    let reusable = closed_reusable("campaign-a");

    // No admission: refused.
    let refusal = retrieve_for_attempt(
        "campaign-b",
        "task-campaign-b",
        &overlay_a,
        Some(&reusable),
        false,
        None,
        now,
    );
    assert_eq!(refusal, Err(BoundsError::CrossTaskAdmissionMissing));

    // Admission missing rollback revalidation: still refused.
    let incomplete = CrossTaskAdmission {
        admission_id: "xadmit-1869-1".to_string(),
        source_campaign_id: "campaign-a".to_string(),
        target_task_id: "task-campaign-b".to_string(),
        scope_ref: "scope-1869".to_string(),
        authority_ref: "governor-1869".to_string(),
        retention_ref: "retention-1869".to_string(),
        evaluator_ref: "evaluator-1869".to_string(),
        rollback_ref: String::new(),
        governor_admission_ref: "governor-admission-1869".to_string(),
    };
    let refusal = retrieve_for_attempt(
        "campaign-b",
        "task-campaign-b",
        &overlay_a,
        Some(&reusable),
        false,
        Some(&incomplete),
        now,
    );
    assert_eq!(refusal, Err(BoundsError::MissingField("rollback_ref")));

    // Complete revalidation: eligible, explicitly marked cross-task.
    let admission = CrossTaskAdmission {
        rollback_ref: "rollback-1869".to_string(),
        ..incomplete
    };
    let decision = retrieve_for_attempt(
        "campaign-b",
        "task-campaign-b",
        &overlay_a,
        Some(&reusable),
        false,
        Some(&admission),
        now,
    )
    .expect("governed cross-task admission authorizes carryover");
    assert!(decision.cross_task);
    assert_eq!(
        decision.cross_task_admission_id,
        Some("xadmit-1869-1".to_string())
    );
}

#[test]
fn bound_refuses_until_explicit_archive() {
    let mut backlog = BoundedBacklog::new(vec![policy(1)]).expect("policy validates");
    let first = candidate(&["ev-1869-bound-a"]);
    let first_id = first.candidate_id.clone();
    assert!(matches!(
        backlog.admit(first, 2.0, Some("governor-1869".to_string())),
        Ok(AdmitOutcome::Admitted { .. })
    ));
    let err = backlog
        .admit(
            candidate(&["ev-1869-bound-b"]),
            3.0,
            Some("governor-1869".to_string()),
        )
        .expect_err("full bound refuses");
    assert!(matches!(err, BoundsError::BoundExceeded { .. }));

    let archived = backlog
        .archive(
            &first_id,
            ArchiveCause::Stale,
            "superseded by replay".to_string(),
        )
        .expect("explicit archive transitions");
    assert_eq!(archived.candidate_id, first_id);
    assert!(backlog.active_for(ImprovementSurface::Memory).is_empty());
    assert!(matches!(
        backlog.admit(
            candidate(&["ev-1869-bound-b"]),
            3.0,
            Some("governor-1869".to_string())
        ),
        Ok(AdmitOutcome::Admitted { .. })
    ));
}
