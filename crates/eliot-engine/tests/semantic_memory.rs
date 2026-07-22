#![allow(clippy::expect_used, clippy::float_cmp, clippy::too_many_arguments)]

use eliot_engine::{
    ApplicabilityService, CognitiveTransferLabService, ContextReinstatementService,
    ContrastiveAbstractionService, ExperienceFormationService, ExperienceRetrievalService,
    MaturityGateService, MemoryKindCompatibilityService, MemoryNeedService,
    NegativeTransferService, TaskMeaningService, TransferValidationEvidence,
    deduplicate_experience_cases, deduplicate_experience_patterns,
};
use eliot_types::{
    ApplicabilityVerdict, CognitiveCaseSpec, CognitiveHiddenEssence, CognitiveReaderAnswer,
    ContrastiveAbstractionResult, ExperienceCausalModel, ExperienceFormationResult,
    ExperienceInterventionOutcome, ExperienceMaturity, ExperienceMaturityState,
    ExperienceProblemFrame, ExperienceRecallRequest, ExperienceTransferBoundary,
    MemoryExposureMode, MemoryExposurePolicy, MemoryKind, MemoryNeed, NegativeTransferHarm,
    NegativeTransferLifecycleAction, ProjectId, SourceBranchCommitEnvironment, TaskMeaningFrame,
    VerificationResult, VerifiedEpisodeProjection,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn episode(
    project_id: ProjectId,
    suffix: &str,
    mechanism: &str,
    trigger: &str,
    applies_when: &str,
    does_not_apply_when: &str,
    cue: &str,
    alias: &str,
) -> VerifiedEpisodeProjection {
    VerifiedEpisodeProjection {
        project_id,
        source_episode_refs: vec![format!("episode:{suffix}")],
        source_task_refs: vec![format!("task:{suffix}")],
        source_agent_sessions: Vec::new(),
        source_branch_commit_environment: SourceBranchCommitEnvironment {
            branch: "semantic-memory".to_owned(),
            commit: format!("commit-{suffix}"),
            environment: vec!["windows".to_owned()],
            observed_at: None,
        },
        problem_frame: ExperienceProblemFrame {
            goal_pattern: format!("repair {trigger}"),
            task_or_action_type: "diagnose runtime".to_owned(),
            trigger_or_symptom: trigger.to_owned(),
            desired_state_transition: "unsafe state to verified state".to_owned(),
            constraints: vec!["preserve current truth".to_owned()],
            relevant_invariants: vec!["local verifier is authoritative".to_owned()],
            ..ExperienceProblemFrame::default()
        },
        causal_model: ExperienceCausalModel {
            mechanism: mechanism.to_owned(),
            causal_chain: vec![trigger.to_owned(), "discriminative probe".to_owned()],
            expected_observables: vec!["verified state transition".to_owned()],
            falsification_cues: vec![does_not_apply_when.to_owned()],
        },
        intervention_and_outcome: ExperienceInterventionOutcome {
            attempted_actions: vec!["read current state".to_owned()],
            decisive_action_or_non_action: "run discriminative probe".to_owned(),
            observed_outcome: "verified state transition".to_owned(),
            verifier_refs: vec![format!("verify:{suffix}")],
        },
        transfer_boundary: ExperienceTransferBoundary {
            retrieval_cues: vec![cue.to_owned()],
            conceptual_aliases: vec![alias.to_owned()],
            applies_when: vec![applies_when.to_owned()],
            does_not_apply_when: vec![does_not_apply_when.to_owned()],
            counterexample_refs: vec![format!("counterexample:{suffix}")],
            required_local_checks: vec![applies_when.to_owned()],
            recommended_first_probe: "read current state".to_owned(),
            forbidden_direct_inference: vec!["do not treat memory as current truth".to_owned()],
        },
        exact_evidence_refs: vec![format!("evidence:{suffix}")],
        reasoning_job_ref: Some(format!("reasoning-job:{suffix}")),
    }
}

fn formed(episode: VerifiedEpisodeProjection) -> eliot_types::ExperienceCase {
    match ExperienceFormationService::reconstruct(episode).expect("formation") {
        ExperienceFormationResult::Formed { experience_case } => *experience_case,
        ExperienceFormationResult::NothingToLearn { reason } => panic!("{reason}"),
    }
}

#[test]
fn formation_preserves_causality_boundaries_and_candidate_authority() {
    let case = formed(episode(
        ProjectId::new_v7(),
        "formation",
        "stale identity routes the client to an obsolete runtime",
        "auth generation mismatch",
        "auth generation mismatch",
        "auth generation already matches",
        "stale daemon identity",
        "obsolete session publication",
    ));
    assert_eq!(
        case.maturity.state,
        ExperienceMaturityState::ReconstructedCase
    );
    assert_eq!(case.maturity.support_count, 1);
    assert!(!case.authority.current_truth);
    assert!(case.authority.candidate_only);
    assert!(!case.transfer_boundary.does_not_apply_when.is_empty());
    assert!(!case.intervention_and_outcome.verifier_refs.is_empty());
}

#[test]
fn formation_and_projection_are_deterministic_and_preserve_only_one_logical_case() {
    let input = episode(
        ProjectId::new_v7(),
        "idempotent-formation",
        "stable semantic identity prevents duplicate case writes",
        "client retries the same verified episode",
        "episode content is unchanged",
        "episode evidence changed",
        "semantic idempotency",
        "same episode replay",
    );
    let first = formed(input.clone());
    let second = formed(input);
    assert_eq!(first.case_id, second.case_id);
    assert_eq!(first.formed_at, second.formed_at);
    assert_eq!(
        deduplicate_experience_cases(vec![first.clone(), second]),
        vec![first]
    );
}

#[test]
fn formation_returns_nothing_to_learn_without_a_reusable_mechanism() -> TestResult {
    let mut input = episode(
        ProjectId::new_v7(),
        "nothing",
        "temporary",
        "one-off observation",
        "one-off observation",
        "different observation",
        "one off",
        "temporary",
    );
    input.causal_model.mechanism.clear();
    assert!(matches!(
        ExperienceFormationService::reconstruct(input)?,
        ExperienceFormationResult::NothingToLearn { .. }
    ));
    Ok(())
}

#[test]
fn contrastive_abstraction_requires_multiple_cases_and_counterevidence() -> TestResult {
    let project_id = ProjectId::new_v7();
    let first = formed(episode(
        project_id,
        "contrast-a",
        "unknown external outcome makes blind retry unsafe",
        "provider outcome unknown",
        "provider outcome unknown",
        "provider returned a terminal receipt",
        "unknown completion",
        "ambiguous provider result",
    ));
    assert!(matches!(
        ContrastiveAbstractionService::abstract_cases(project_id, std::slice::from_ref(&first))?,
        ContrastiveAbstractionResult::NoLearnablePattern { .. }
    ));
    let second = formed(episode(
        project_id,
        "contrast-b",
        "unknown external outcome makes blind retry unsafe",
        "external call timed out after dispatch",
        "provider outcome unknown",
        "provider returned a terminal receipt",
        "uncertain delivery",
        "ambiguous provider result",
    ));
    let result = ContrastiveAbstractionService::abstract_cases(project_id, &[first, second])?;
    let ContrastiveAbstractionResult::Formed { pattern } = result else {
        panic!("pattern expected");
    };
    assert_eq!(
        pattern.maturity.state,
        ExperienceMaturityState::PatternCandidate
    );
    assert_eq!(pattern.member_case_refs.len(), 2);
    assert!(!pattern.counterexamples.is_empty());
    Ok(())
}

#[test]
fn abstraction_and_projection_are_deterministic() -> TestResult {
    let project_id = ProjectId::new_v7();
    let first = formed(episode(
        project_id,
        "idempotent-pattern-a",
        "the same causal mechanism survives contrast",
        "surface a",
        "condition matches",
        "condition differs",
        "stable pattern",
        "repeatable abstraction",
    ));
    let second = formed(episode(
        project_id,
        "idempotent-pattern-b",
        "the same causal mechanism survives contrast",
        "surface b",
        "condition matches",
        "condition differs",
        "stable pattern",
        "repeatable abstraction",
    ));
    let first_result = ContrastiveAbstractionService::abstract_cases(
        project_id,
        &[first.clone(), second.clone()],
    )?;
    let second_result =
        ContrastiveAbstractionService::abstract_cases(project_id, &[second, first])?;
    let ContrastiveAbstractionResult::Formed { pattern: first } = first_result else {
        panic!("pattern expected");
    };
    let ContrastiveAbstractionResult::Formed { pattern: second } = second_result else {
        panic!("pattern expected");
    };
    assert_eq!(first.pattern_id, second.pattern_id);
    assert_eq!(first.member_case_refs, second.member_case_refs);
    assert_eq!(
        deduplicate_experience_patterns(vec![*first.clone(), *second]),
        vec![*first]
    );
    Ok(())
}

#[test]
fn maturity_gate_blocks_single_episode_procedure_promotion() {
    let reconstructed = ExperienceMaturity {
        state: ExperienceMaturityState::ReconstructedCase,
        support_count: 1,
        contrast_count: 0,
        cross_host_transfer_count: 0,
        negative_transfer_count: 0,
    };
    assert!(
        MaturityGateService::transition(
            &reconstructed,
            ExperienceMaturityState::ActiveProcedure,
            &TransferValidationEvidence::default()
        )
        .is_err()
    );
}

#[test]
fn transfer_validation_requires_paraphrase_near_miss_independent_host_and_delta() -> TestResult {
    let candidate = ExperienceMaturity {
        state: ExperienceMaturityState::PatternCandidate,
        support_count: 2,
        contrast_count: 1,
        cross_host_transfer_count: 0,
        negative_transfer_count: 0,
    };
    let evidence = TransferValidationEvidence {
        paraphrase_survived: true,
        near_miss_rejected: true,
        independent_host_refs: vec!["host:antigravity".to_owned()],
        verified_decision_delta_refs: vec!["verification:delta".to_owned()],
        ..TransferValidationEvidence::default()
    };
    let validated = MaturityGateService::transition(
        &candidate,
        ExperienceMaturityState::TransferValidated,
        &evidence,
    )?;
    assert_eq!(validated.state, ExperienceMaturityState::TransferValidated);
    assert_eq!(validated.cross_host_transfer_count, 1);
    Ok(())
}

#[test]
fn task_meaning_requires_intent_to_verifier_bridge() {
    let frame = TaskMeaningFrame {
        task_id: "bridge".to_owned(),
        normalized_goal: "repair governed packet".to_owned(),
        task_or_action_type: "code change".to_owned(),
        project_module_boundary: vec!["eliot-engine".to_owned()],
        files_symbols_config: vec!["semantic_memory.rs".to_owned()],
        control_data_state_path: vec!["task -> packet -> verifier".to_owned()],
        current_evidence: vec!["file:semantic_memory.rs".to_owned()],
        predicted_observable: "experience prior appears separately".to_owned(),
        verifier_need: "semantic_memory".to_owned(),
        ..TaskMeaningFrame::default()
    };
    assert!(TaskMeaningService::bridge_quality(&frame).decision_sufficient);
    let mut broken = frame;
    broken.verifier_need.clear();
    assert!(!TaskMeaningService::bridge_quality(&broken).decision_sufficient);
}

#[test]
fn kind_compatibility_rejects_weak_claim_as_procedure() {
    assert!(!MemoryKindCompatibilityService::compatible(
        MemoryNeed::Procedure,
        MemoryKind::Claim
    ));
    assert!(
        MemoryKindCompatibilityService::require_compatible(
            MemoryNeed::Procedure,
            MemoryKind::Claim
        )
        .is_err()
    );
}

#[test]
fn memory_need_can_return_no_useful_memory() {
    let frame = TaskMeaningFrame {
        task_id: "sufficient".to_owned(),
        current_evidence: vec!["current source and verifier are present".to_owned()],
        ..TaskMeaningFrame::default()
    };
    assert_eq!(
        MemoryNeedService::decide(&frame, None).need,
        MemoryNeed::None
    );
}

#[test]
fn low_lexical_overlap_alias_retrieval_finds_case_but_keeps_it_as_prior() {
    let project_id = ProjectId::new_v7();
    let mut case = formed(episode(
        project_id,
        "semantic",
        "stale identity routes the client to an obsolete runtime",
        "auth generation mismatch",
        "auth generation mismatch",
        "auth generation already matches",
        "stale daemon identity",
        "obsolete session publication",
    ));
    case.maturity.state = ExperienceMaturityState::TransferValidated;
    let frame = TaskMeaningFrame {
        task_id: "semantic-target".to_owned(),
        user_goal: "investigate obsolete session publication".to_owned(),
        normalized_goal: "investigate obsolete session publication".to_owned(),
        task_or_action_type: "diagnose runtime".to_owned(),
        desired_state_transition: "unsafe state to verified state".to_owned(),
        problem_or_failure_signature: "auth generation mismatch".to_owned(),
        constraints: vec!["auth generation mismatch".to_owned()],
        current_evidence: vec!["auth generation mismatch".to_owned()],
        ..TaskMeaningFrame::default()
    };
    let response = ExperienceRetrievalService::recall(
        &ExperienceRecallRequest {
            project_id,
            task_frame: frame.clone(),
            need: MemoryNeedService::decide(&frame, Some(MemoryNeed::CausalCase)),
            exposure_policy: MemoryExposurePolicy::default(),
        },
        &[case],
    );
    assert!(!response.no_useful_memory);
    assert_eq!(response.experience_priors.len(), 1);
    assert!(
        response.experience_priors[0]
            .maturity_and_authority
            .contains("current_truth=false")
    );
}

#[test]
fn deceptive_near_miss_is_retrieved_then_rejected() {
    let case = formed(episode(
        ProjectId::new_v7(),
        "near-miss",
        "isolated supervised config prevents unrelated host context",
        "supervised launch includes unrelated config",
        "supervised automated launch",
        "interactive human launch",
        "OpenCode config isolation",
        "reduce unrelated context",
    ));
    let frame = TaskMeaningFrame {
        task_id: "interactive".to_owned(),
        user_goal: "install permanent configuration for an interactive human launch".to_owned(),
        normalized_goal: "interactive human launch permanent configuration".to_owned(),
        task_or_action_type: "configure host".to_owned(),
        current_evidence: vec!["interactive human launch".to_owned()],
        ..TaskMeaningFrame::default()
    };
    assert_eq!(
        ApplicabilityService::decide(&frame, &case).verdict,
        ApplicabilityVerdict::NearMiss
    );
}

#[test]
fn desired_observable_does_not_contaminate_current_applicability() {
    let project_id = ProjectId::new_v7();
    let case = formed(episode(
        project_id,
        "desired-state-contamination",
        "a staged artifact becomes durable only after its canonical receipt resolves",
        "staged artifact exists without canonical receipt",
        "canonical receipt absent",
        "canonical receipt resolves at expected revision",
        "staged writeback",
        "inbox is not persistence",
    ));
    let frame = TaskMeaningFrame {
        task_id: "desired-state-target".to_owned(),
        task_or_action_type: "memory writeback verification".to_owned(),
        problem_or_failure_signature: "staged artifact exists without canonical receipt".to_owned(),
        current_evidence: vec!["canonical receipt absent".to_owned()],
        predicted_observable: "canonical receipt resolves at expected revision".to_owned(),
        material_unknowns: vec!["whether the writer committed".to_owned()],
        ..TaskMeaningFrame::default()
    };
    let decision = ApplicabilityService::decide(&frame, &case);
    assert_eq!(decision.verdict, ApplicabilityVerdict::RequireProbe);
    assert!(decision.critical_differences.is_empty());
}

#[test]
fn exposure_policy_partitions_control_and_candidate_conditions() {
    let project_id = ProjectId::new_v7();
    let case = formed(episode(
        project_id,
        "exposure",
        "staged writeback is not a canonical receipt",
        "staged writeback",
        "canonical receipt absent",
        "canonical receipt present",
        "write receipt missing",
        "staged is not persisted",
    ));
    let frame = TaskMeaningFrame {
        task_id: "exposure".to_owned(),
        normalized_goal: "write receipt missing".to_owned(),
        problem_or_failure_signature: "canonical receipt absent".to_owned(),
        current_evidence: vec!["canonical receipt absent".to_owned()],
        ..TaskMeaningFrame::default()
    };
    let need = MemoryNeedService::decide(&frame, Some(MemoryNeed::CausalCase));
    let control = ExperienceRetrievalService::recall(
        &ExperienceRecallRequest {
            project_id,
            task_frame: frame.clone(),
            need: need.clone(),
            exposure_policy: MemoryExposurePolicy {
                mode: MemoryExposureMode::MemoryFreeControl,
                ..MemoryExposurePolicy::default()
            },
        },
        std::slice::from_ref(&case),
    );
    assert!(control.no_useful_memory);
    let candidate = ExperienceRetrievalService::recall(
        &ExperienceRecallRequest {
            project_id,
            task_frame: frame,
            need,
            exposure_policy: MemoryExposurePolicy {
                mode: MemoryExposureMode::IncludeCaseCandidates,
                ..MemoryExposurePolicy::default()
            },
        },
        &[case],
    );
    assert!(!candidate.fused_rank_traces.is_empty());
}

#[test]
fn context_reinstatement_restores_exact_episode_and_verifier() {
    let case = formed(episode(
        ProjectId::new_v7(),
        "context",
        "candidate observation cannot satisfy verifier evidence",
        "candidate-only observation",
        "verifier evidence absent",
        "verification receipt present",
        "candidate is not verifier",
        "evidence authority mismatch",
    ));
    let bundle = ContextReinstatementService::bundle(&case);
    assert_eq!(bundle.experience_ref, case.case_id);
    assert!(!bundle.exact_evidence_refs.is_empty());
    assert!(!bundle.verifier_refs.is_empty());
    assert!(bundle.action_outcome_chain.len() >= 3);
}

#[test]
fn harmful_l8_claim_is_suppressed_for_guidance_when_no_episode_exists() {
    let form_record = || {
        NegativeTransferService::record(
            "l8-opencode-memory-value-20260715-v2".to_owned(),
            vec!["1abfc485-5887-44de-bc64-3c9ef24b730c".to_owned()],
            "c12cac7c-d700-4185-8b0d-ed9cf349d431".to_owned(),
            NegativeTransferHarm {
                extra_tool_calls: 17,
                wrong_generalization: true,
                rejected_proof: "weak_claim_used_as_truth".to_owned(),
            },
            "representation".to_owned(),
            false,
        )
    };
    let record = form_record();
    assert_eq!(
        record.lifecycle_action,
        NegativeTransferLifecycleAction::SuppressForGuidance
    );
    assert_eq!(record.record_id, form_record().record_id);
}

fn sealed_case(index: usize) -> (CognitiveCaseSpec, CognitiveReaderAnswer) {
    let case_id = match index {
        0 => "paraphrase-1",
        1 => "paraphrase-2",
        2 => "low-lexical-1",
        3 => "low-lexical-2",
        4 => "procedure",
        5 => "negative-memory",
        6 => "near-miss-1",
        7 => "near-miss-2",
        8 => "stale-current-truth",
        _ => "no-useful-memory",
    }
    .to_owned();
    let verdict = match index {
        6 | 7 => ApplicabilityVerdict::NearMiss,
        8 => ApplicabilityVerdict::Contradicted,
        9 => ApplicabilityVerdict::InsufficientContext,
        _ => ApplicabilityVerdict::ApplicableAsPrior,
    };
    let memory_kind = match index {
        4 => MemoryKind::Procedure,
        5 => MemoryKind::NegativeMemory,
        _ => MemoryKind::CausalCase,
    };
    let source_ref = format!("case:{case_id}");
    let hidden = CognitiveHiddenEssence {
        required_concepts: vec![format!("concept-{index}")],
        mechanism: format!("mechanism-{index}"),
        applicability_conditions: vec![format!("applies-{index}")],
        non_applicability_conditions: vec![format!("not-applies-{index}")],
        first_probe_or_action: format!("probe-{index}"),
        predicted_observable: format!("observable-{index}"),
        verifier: format!("verifier-{index}"),
        forbidden_conclusions: vec![format!("forbidden-{index}")],
    };
    let spec = CognitiveCaseSpec {
        case_id: case_id.clone(),
        source_case_refs: vec![source_ref.clone()],
        source_agent: if index.is_multiple_of(2) {
            "codex".to_owned()
        } else {
            "antigravity".to_owned()
        },
        target_agent: if index.is_multiple_of(2) {
            "antigravity".to_owned()
        } else {
            "codex".to_owned()
        },
        expected_memory_kind: memory_kind,
        hidden_essence: hidden.clone(),
        target_task_or_query: format!("surface-shifted-target-{index}"),
        lexical_overlap_limit: if matches!(index, 2 | 3) { 10 } else { 40 },
        distractor_memory_refs: vec![format!("distractor-{index}")],
        expected_retrieval: if index == 9 {
            Vec::new()
        } else {
            vec![source_ref.clone()]
        },
        expected_applicability_verdict: verdict,
        expected_behavioral_delta: format!("delta-{index}"),
        deterministic_checks: vec!["sealed".to_owned()],
    };
    let answer = CognitiveReaderAnswer {
        case_id,
        retrieved_refs: if index == 9 {
            Vec::new()
        } else {
            vec![source_ref]
        },
        memory_kind,
        recovered_concepts: hidden.required_concepts.clone(),
        mechanism: hidden.mechanism.clone(),
        applicability_conditions: hidden.applicability_conditions.clone(),
        non_applicability_conditions: hidden.non_applicability_conditions.clone(),
        first_probe_or_action: hidden.first_probe_or_action.clone(),
        predicted_observable: hidden.predicted_observable.clone(),
        verifier: hidden.verifier.clone(),
        forbidden_conclusions: hidden.forbidden_conclusions.clone(),
        applicability_verdict: verdict,
        tool_calls_to_useful_boundary: 1,
        tokens_to_useful_boundary: 100,
        latency_ms: 1,
    };
    (spec, answer)
}

#[test]
fn provider_free_cognitive_lab_passes_ten_sealed_contracts() {
    let (specs, answers): (Vec<_>, Vec<_>) = (0..10).map(sealed_case).unzip();
    let report = CognitiveTransferLabService::evaluate(
        "semantic-memory-provider-free".to_owned(),
        &specs,
        &answers,
    );
    assert_eq!(report.results.len(), 10);
    assert!(report.results.iter().all(|result| {
        result.encoding_pass
            && result.retrieval_pass
            && result.applicability_pass
            && result.near_miss_pass
            && result.verifier_pass
            && result.forbidden_conclusion_pass
    }));
    assert_eq!(report.metrics.encoding_gist_fidelity, 1.0);
    assert_eq!(report.metrics.applicability_precision, 1.0);
    assert_eq!(report.metrics.near_miss_rejection_rate, 1.0);
    assert_eq!(report.metrics.current_truth_contamination_rate, 0.0);
    assert!(
        report
            .results
            .iter()
            .all(|result| result.verifier_result == VerificationResult::Passed)
    );
}
