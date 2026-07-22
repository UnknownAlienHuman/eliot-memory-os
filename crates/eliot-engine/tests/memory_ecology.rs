#![allow(clippy::expect_used)]

use eliot_engine::memory_lifecycle::{
    MemoryGravityService, MemoryGravitySignals, MemoryLifecycleGate, MemoryLifecycleService,
    MemoryVitalityService, MemoryVitalitySignals,
};
use eliot_engine::{ForgettingPolicyService, SkillLifecycleService, SkillRegistryService};
use eliot_types::{
    EpistemicStatus, ExperienceAuthority, ExperienceMaturity, ExperienceMaturityState,
    ExperiencePattern, ForgettingOperator, ForgettingReason, MemoryEcologyDecision,
    MemoryLifecycleDecision, MemoryLifecycleState, MinorityPressureRecord, MinorityPressureStatus,
    ProcedurePromotionOutcome, ProjectId, ReactivationCondition, SkillInputRequirement,
    SkillInputSource, SkillLevel, SkillOutputSpec, SkillScopeRule, SkillStep, VerifierCommandKind,
    VerifierPlan, VerifierRequirement,
};
use time::{Duration, OffsetDateTime};

#[test]
fn vitality_is_driven_by_observed_signals_not_handle_spelling() {
    let project_id = ProjectId::new_v7();
    let useful = MemoryVitalityService::score_from_signals(
        project_id,
        "memory:same-handle",
        &MemoryVitalitySignals {
            reuse_count: 7,
            beneficial_use_count: 5,
            prevented_failure_count: 2,
            correct_verifier_selection_count: 3,
            verification_success_count: 6,
            freshness_millis: 900,
            scope_fit_millis: 900,
            ..MemoryVitalitySignals::default()
        },
    );
    let harmful = MemoryVitalityService::score_from_signals(
        project_id,
        "memory:same-handle",
        &MemoryVitalitySignals {
            reuse_count: 7,
            verification_failure_count: 3,
            negative_transfer_count: 2,
            false_activation_count: 3,
            stale_hits: 2,
            contradiction_count: 1,
            context_cost_tokens: 800,
            freshness_millis: 100,
            scope_fit_millis: 200,
            ..MemoryVitalitySignals::default()
        },
    );

    assert_eq!(useful.decision, MemoryEcologyDecision::KeepHot);
    assert!(useful.utility_millis > useful.harm_millis);
    assert_eq!(harmful.decision, MemoryEcologyDecision::Suppress);
    assert!(harmful.harm_millis > harmful.utility_millis);
}

#[test]
fn gravity_detects_dominance_and_open_contradiction() {
    let score = MemoryVitalityService::score_from_signals(
        ProjectId::new_v7(),
        "memory:dominant",
        &MemoryVitalitySignals {
            reuse_count: 20,
            beneficial_use_count: 1,
            contradiction_count: 2,
            freshness_millis: 700,
            scope_fit_millis: 700,
            ..MemoryVitalitySignals::default()
        },
    );
    let gravity = MemoryGravityService::gravity_from_signals(
        &score,
        &MemoryGravitySignals {
            packet_inclusion_count: 15,
            top_rank_count: 10,
            cluster_share_millis: 900,
        },
    );

    assert_eq!(gravity.activation_pressure_millis, 1000);
    assert_eq!(gravity.decision, MemoryEcologyDecision::SplitPattern);
    assert!(gravity.suppression_needed);
}

#[test]
fn normalized_lifecycle_transitions_are_idempotent_and_reversible() {
    let now = OffsetDateTime::now_utc();
    let mut service = MemoryLifecycleService::new();
    for (operator, expected_state) in [
        (ForgettingOperator::Compress, MemoryLifecycleState::Dormant),
        (ForgettingOperator::Demote, MemoryLifecycleState::Dormant),
        (
            ForgettingOperator::Suppress,
            MemoryLifecycleState::Suppressed,
        ),
        (
            ForgettingOperator::Supersede,
            MemoryLifecycleState::Archived,
        ),
        (ForgettingOperator::Archive, MemoryLifecycleState::Archived),
        (ForgettingOperator::Forget, MemoryLifecycleState::Forgotten),
    ] {
        let target = format!("memory:{operator:?}");
        let mut policy = policy(&target, operator, now);
        if operator == ForgettingOperator::Supersede {
            policy.rollback_or_tombstone_ref = Some("memory:replacement".to_owned());
        }
        if operator == ForgettingOperator::Forget {
            policy.rollback_or_tombstone_ref = Some("tombstone:forget".to_owned());
        }
        let first = service
            .transition_for_policy_at(&policy, "controller", &[], now)
            .expect("valid transition");
        let replay = service
            .transition_for_policy_at(&policy, "controller", &[], now)
            .expect("idempotent replay");
        assert_eq!(first.transition_id, replay.transition_id);
        assert_eq!(first.to_state, expected_state);
        assert!(service.apply_transition(&first));
        assert!(!service.apply_transition(&first));

        let reverse = service
            .reverse_transition(&first, "controller", vec!["evidence:restore".to_owned()])
            .expect("reversible transition");
        assert_eq!(reverse.from_state, expected_state);
        assert_eq!(reverse.to_state, MemoryLifecycleState::Active);
    }
}

#[test]
fn purge_is_privacy_admin_only_and_never_reversible() {
    let now = OffsetDateTime::now_utc();
    let service = MemoryLifecycleService::new();
    let mut purge = policy("memory:privacy", ForgettingOperator::Purge, now);
    purge.reason = ForgettingReason::Privacy;
    purge.reversible = false;

    assert_eq!(
        service.transition_for_policy_at(&purge, "controller", &[], now),
        Err(MemoryLifecycleDecision::DenyPurgeInI0)
    );
    purge.requires_admin_approval = true;
    purge.approval_ref = Some("approval:exact-action-hash".to_owned());
    let transition = service
        .transition_for_policy_at(&purge, "controller", &[], now)
        .expect("approved privacy purge");
    assert_eq!(transition.to_state, MemoryLifecycleState::HardDeleted);
    assert!(!transition.reversible);
    assert!(
        service
            .reverse_transition(&transition, "controller", vec!["evidence:any".to_owned()])
            .is_err()
    );
}

#[test]
fn restore_requires_prior_inactive_state_and_reactivation_evidence() {
    let now = OffsetDateTime::now_utc();
    let service = MemoryLifecycleService::new()
        .with_state("memory:forgotten", MemoryLifecycleState::Forgotten);
    let mut restore = policy("memory:forgotten", ForgettingOperator::Restore, now);
    restore.expected_current_state = MemoryLifecycleState::Forgotten;
    restore.reactivation_condition = Some(ReactivationCondition {
        condition_id: "condition:new-evidence".to_owned(),
        description: "new verifier evidence".to_owned(),
        required_evidence_refs: vec!["verification:new".to_owned()],
        required_current_truth_change: None,
        expires_at: None,
    });
    restore.evidence_refs.clear();
    assert_eq!(
        service.transition_for_policy_at(&restore, "controller", &[], now),
        Err(MemoryLifecycleDecision::RequireEvidence)
    );
    restore.evidence_refs.push("verification:new".to_owned());
    let transition = service
        .transition_for_policy_at(&restore, "controller", &[], now)
        .expect("evidence-backed restore");
    assert_eq!(transition.to_state, MemoryLifecycleState::Restored);
}

#[test]
fn minority_pin_releases_only_after_explicit_resolution() {
    let now = OffsetDateTime::now_utc();
    let minority = MinorityPressureRecord {
        minority_record_id: "minority:1".to_owned(),
        project_id: ProjectId::new_v7(),
        minority_claim_ref: "memory:rare-contradiction".to_owned(),
        majority_claim_ref: Some("memory:dominant".to_owned()),
        why_minority_matters: "could falsify dominant procedure".to_owned(),
        discriminative_probe: Some("run exact verifier".to_owned()),
        status: MinorityPressureStatus::Open,
        pinned: true,
        release_condition: Some("verification:resolved".to_owned()),
        resolved_by_ref: None,
        suppression_forbidden_until: None,
        evidence_refs: vec!["evidence:contradiction".to_owned()],
        created_at: now,
        write_receipt: None,
    };
    let suppress = policy(
        "memory:rare-contradiction",
        ForgettingOperator::Suppress,
        now,
    );
    assert_eq!(
        MemoryLifecycleGate::decide_at(
            &suppress,
            std::slice::from_ref(&minority),
            MemoryLifecycleState::Active,
            now,
        ),
        MemoryLifecycleDecision::ProtectMinorityEvidence
    );

    let released = MemoryLifecycleGate::release_minority(
        &minority,
        MinorityPressureStatus::Resolved,
        "verification:resolved",
    )
    .expect("explicit resolution releases pin");
    assert_eq!(
        MemoryLifecycleGate::decide_at(&suppress, &[released], MemoryLifecycleState::Active, now,),
        MemoryLifecycleDecision::Allow
    );
}

#[test]
fn trajectory_checks_continuity_and_observed_admission_effect() {
    let now = OffsetDateTime::now_utc();
    let mut service = MemoryLifecycleService::new();
    let demote = service
        .transition_for_policy_at(
            &policy("memory:trajectory", ForgettingOperator::Demote, now),
            "controller",
            &[],
            now,
        )
        .expect("demote");
    assert!(service.apply_transition(&demote));
    let mut restore_policy = policy("memory:trajectory", ForgettingOperator::Restore, now);
    restore_policy.expected_current_state = MemoryLifecycleState::Dormant;
    restore_policy.reactivation_condition = Some(ReactivationCondition {
        condition_id: "restore:trajectory".to_owned(),
        description: "fresh verification".to_owned(),
        required_evidence_refs: vec!["verification:fresh".to_owned()],
        required_current_truth_change: None,
        expires_at: None,
    });
    restore_policy.evidence_refs = vec!["verification:fresh".to_owned()];
    let restore = service
        .transition_for_policy_at(&restore_policy, "controller", &[], now)
        .expect("restore");
    let trajectory = MemoryLifecycleService::trajectory_correctness(
        &[demote, restore],
        MemoryEcologyDecision::KeepHot,
        vec!["packet:after-restore".to_owned()],
    );
    assert!(trajectory.correct);
}

#[test]
fn transfer_validated_pattern_can_truthfully_remain_not_ready_for_procedure() {
    let pattern = transfer_validated_pattern();
    let candidate = SkillRegistryService::create_candidate("unknown outcome", "curator");
    let record = SkillLifecycleService::procedure_promotion_disposition(
        &pattern,
        &candidate,
        &["holdout:passed".to_owned()],
        &[],
    );

    assert_eq!(
        record.promotion_outcome,
        Some(ProcedurePromotionOutcome::NotReadyForProcedure)
    );
    assert_eq!(record.state, eliot_types::SkillLifecycleState::Candidate);
}

#[test]
fn procedure_promotion_requires_transfer_holdout_rollback_and_verifier() {
    let pattern = transfer_validated_pattern();
    let mut candidate = SkillRegistryService::create_candidate("unknown outcome", "curator");
    candidate.level = SkillLevel::Procedure;
    candidate.applies_when = vec![scope_rule("remote outcome is unknown")];
    candidate.does_not_apply_when = vec![scope_rule("provider reports terminal failure")];
    candidate.required_inputs = vec![SkillInputRequirement {
        name: "original invocation".to_owned(),
        description: "reconcile original invocation".to_owned(),
        required: true,
        source: SkillInputSource::CurrentState,
    }];
    candidate.ordered_steps = vec![SkillStep {
        step_id: "reconcile".to_owned(),
        order: 1,
        instruction: "reconcile before retry".to_owned(),
        expected_observation: Some("terminal outcome or safe retry boundary".to_owned()),
        required_tool_or_capability: Some("provider reconciliation".to_owned()),
        stop_if_fails: true,
    }];
    candidate.expected_outputs = vec![SkillOutputSpec {
        name: "reconciliation receipt".to_owned(),
        description: "exact original invocation outcome".to_owned(),
        evidence_required: true,
        verifier_required: true,
    }];
    candidate.verification_plan = VerifierPlan {
        required: vec![VerifierRequirement {
            name: "provider-invocation-reconciliation".to_owned(),
            command_kind: VerifierCommandKind::DomainVerifier,
            command_display: "reconcile original invocation".to_owned(),
            scope: Vec::new(),
            required_for_done: true,
            expected_signal: "terminal outcome or safe retry boundary".to_owned(),
        }],
        optional: Vec::new(),
        acceptance_items: vec!["blind retry is forbidden while outcome is unknown".to_owned()],
    };
    candidate.stop_conditions = vec!["unknown outcome remains unresolved".to_owned()];
    candidate.rollback_or_recovery = Some("demote to transfer-validated pattern".to_owned());
    candidate.source_trace_refs = vec!["case:verified-a".to_owned(), "case:verified-b".to_owned()];

    let record = SkillLifecycleService::procedure_promotion_disposition(
        &pattern,
        &candidate,
        &["holdout:passed".to_owned()],
        &[],
    );
    assert_eq!(
        record.promotion_outcome,
        Some(ProcedurePromotionOutcome::Promoted)
    );
    assert_eq!(record.state, eliot_types::SkillLifecycleState::Active);

    let mut partially_verified_pattern = pattern.clone();
    partially_verified_pattern.authority.exact_source_refs = vec!["case:verified-a".to_owned()];
    let incomplete = SkillLifecycleService::procedure_promotion_disposition(
        &partially_verified_pattern,
        &candidate,
        &["holdout:passed".to_owned()],
        &[],
    );
    assert_eq!(
        incomplete.promotion_outcome,
        Some(ProcedurePromotionOutcome::NotReadyForProcedure)
    );

    let reused_transfer = SkillLifecycleService::procedure_promotion_disposition(
        &pattern,
        &candidate,
        &["transfer:cross-host".to_owned()],
        &[],
    );
    assert_eq!(
        reused_transfer.promotion_outcome,
        Some(ProcedurePromotionOutcome::NotReadyForProcedure)
    );

    let negative = SkillLifecycleService::procedure_promotion_disposition(
        &pattern,
        &candidate,
        &["holdout:passed".to_owned()],
        &["negative-transfer:1".to_owned()],
    );
    assert_eq!(
        negative.promotion_outcome,
        Some(ProcedurePromotionOutcome::Demoted)
    );
    assert_ne!(negative.state, eliot_types::SkillLifecycleState::Active);
}

fn policy(
    target: &str,
    operator: ForgettingOperator,
    now: OffsetDateTime,
) -> eliot_types::ForgettingPolicy {
    let mut policy = ForgettingPolicyService::propose(
        ProjectId::new_v7(),
        target,
        operator,
        ForgettingReason::LowUtility,
        vec!["evidence:observed-outcome".to_owned()],
        None,
        None,
    );
    policy.policy_id = format!("policy:{target}:{operator:?}");
    policy.effective_at = Some(now - Duration::seconds(1));
    policy.expected_current_state = MemoryLifecycleState::Active;
    policy.observed_epistemic_status = EpistemicStatus::Supported;
    policy.precondition_refs = vec!["current-state:observed".to_owned()];
    policy
}

fn scope_rule(description: &str) -> SkillScopeRule {
    SkillScopeRule {
        rule_id: format!("rule:{description}"),
        description: description.to_owned(),
        positive_examples: vec![description.to_owned()],
        negative_examples: vec!["different causal boundary".to_owned()],
        required_evidence_refs: vec!["current-truth:checked".to_owned()],
    }
}

fn transfer_validated_pattern() -> ExperiencePattern {
    ExperiencePattern {
        pattern_id: "pattern:unknown-outcome".to_owned(),
        project_id: ProjectId::new_v7(),
        member_case_refs: vec!["case:verified-a".to_owned(), "case:verified-b".to_owned()],
        invariant_core: vec!["unknown external outcome forbids blind retry".to_owned()],
        varying_surface_features: vec!["provider wording".to_owned()],
        success_conditions: vec!["original invocation can be reconciled".to_owned()],
        failure_conditions: vec!["terminal result already known".to_owned()],
        counterexamples: vec!["pre-dispatch local rejection".to_owned()],
        applicability_classifier_features: vec!["outcome unknown".to_owned()],
        required_local_probe: "reconcile original invocation".to_owned(),
        maturity: ExperienceMaturity {
            state: ExperienceMaturityState::TransferValidated,
            support_count: 2,
            contrast_count: 1,
            cross_host_transfer_count: 1,
            negative_transfer_count: 0,
        },
        transfer_evidence: vec!["transfer:cross-host".to_owned()],
        authority: ExperienceAuthority {
            current_truth: false,
            candidate_only: true,
            exact_source_refs: vec!["case:verified-a".to_owned(), "case:verified-b".to_owned()],
            reasoning_job_ref: None,
            review_refs: vec!["review:transfer".to_owned()],
            canonical_receipt: None,
        },
        formed_at: OffsetDateTime::now_utc(),
    }
}
