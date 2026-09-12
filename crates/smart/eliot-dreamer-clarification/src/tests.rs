use std::fmt::Debug;

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
use eliot_dreamer_contracts::{
    BudgetLimits, DreamJobInput, JobClass, Requester, RequesterOrigin, ValidatedDreamDraft,
    ValidationReceipt,
};
use eliot_dreamer_contracts::job::DREAM_JOB_SCHEMA_VERSION;

use super::*;

fn must<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

fn digest(ch: char) -> String {
    std::iter::repeat_n(ch, 64).collect()
}

fn job() -> DreamJobInput {
    DreamJobInput {
        schema_version: DREAM_JOB_SCHEMA_VERSION,
        job_class: JobClass::Clarification,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "human-1".to_owned(),
            session: Some("session-1".to_owned()),
        },
        operation_id: "operation-1".to_owned(),
        idempotency_key: "idempotency-1".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        privacy_profile: "local_only".to_owned(),
        contract_ref: "clarification-contract-v1".to_owned(),
        policy_ref: "eliot.clarification.policy.v1".to_owned(),
        budget: BudgetLimits {
            input_bytes: Some(1_048_576),
            output_bytes: Some(1_048_576),
            source_width: Some(512),
            reference_width: Some(512),
            model_calls: Some(1),
            attempts: Some(1),
            candidates: Some(1),
            wall_ms: Some(10_000),
            work_fan_out: Some(1),
            report_bytes: Some(1_048_576),
            max_stu: Some(10_000),
        },
        deadline_ms: Some(100_000),
        frozen_manifest_digest: digest('a'),
    }
}

fn validated_draft(job: &DreamJobInput) -> ValidatedDreamDraft {
    let receipt = ValidationReceipt {
        schema_version: 1,
        validator_contract: "eliot.dreamer.validation.v1".to_owned(),
        validator_policy: "validator-policy-v1".to_owned(),
        job_id: job.canonical_id(),
        draft_digest: digest('b'),
        bundle_digest: digest('c'),
        manifest_digest: job.frozen_manifest_digest.clone(),
        task_id: job.task_id.clone(),
        scope_id: job.scope_id.clone(),
        input_digest: digest('d'),
        output_digest: digest('e'),
        terminal_disposition: "accepted".to_owned(),
        proof_ceiling: "pre_handler_validation_only".to_owned(),
        state_fence: job.state_fence.clone(),
        preservation_digest: digest('f'),
        budget_digest: digest('1'),
    };
    ValidatedDreamDraft {
        receipt,
        draft_digest: digest('b'),
        scope_id: job.scope_id.clone(),
        task_id: job.task_id.clone(),
        state_fence: job.state_fence.clone(),
    }
}

fn policy() -> ClarificationPolicy {
    let mut value = ClarificationPolicy::default();
    value.observation_time_ms = 1_000;
    value.candidate_ttl_ms = 5_000;
    must(value.seal());
    value
}

fn option(key: &str, label: &str) -> AnswerOption {
    AnswerOption {
        key: key.to_owned(),
        label: label.to_owned(),
        referenced_variables: vec!["decision-1".to_owned()],
    }
}

fn branch(key: &str, outcome: &str) -> AnswerBranch {
    AnswerBranch {
        branch_id: format!("branch-{key}"),
        matcher: AnswerMatcher::Exact {
            key: key.to_owned(),
        },
        outcome_id: outcome.to_owned(),
        summary: format!("Continue with {outcome}"),
        referenced_variables: vec!["decision-1".to_owned()],
    }
}

fn non_answers() -> NonAnswerBranches {
    NonAnswerBranches {
        unknown: "unknown".to_owned(),
        refusal: "refused".to_owned(),
        unanswered: "unanswered".to_owned(),
        expired: "expired".to_owned(),
        invalid_value: "invalid_value".to_owned(),
    }
}

fn variable(owner: DecisionOwner) -> DecisionVariable {
    DecisionVariable {
        variable_id: "decision-1".to_owned(),
        label: "the deployment mode".to_owned(),
        component_ids: vec!["decision-1".to_owned()],
        content_class: ClarificationContentClass::OrdinaryData,
        owner,
        required_capability: match owner {
            DecisionOwner::TaskLocalAgent => Some("choose-task-local-mode".to_owned()),
            DecisionOwner::Human(_) | DecisionOwner::Unknown => None,
        },
        answer_schema: AnswerSchema::Choice {
            options: vec![option("safe", "Safe mode"), option("fast", "Fast mode")],
        },
        branches: vec![branch("safe", "safe-outcome"), branch("fast", "fast-outcome")],
        non_answer_branches: non_answers(),
    }
}

fn fallback() -> UnansweredFallback {
    UnansweredFallback::PartialResult {
        result_code: "partial_without_decision".to_owned(),
        referenced_variables: vec!["decision-1".to_owned()],
    }
}

fn ambiguity(owner: DecisionOwner) -> ClarificationAmbiguity {
    ClarificationAmbiguity {
        ambiguity_id: "ambiguity-1".to_owned(),
        objective_id: "objective-1".to_owned(),
        state: AmbiguityState::Unresolved,
        variables: vec![variable(owner)],
        materiality: Some(MaterialityEvidence {
            basis: MaterialityBasis::BranchDivergence,
            summary: "The two values lead to different safe branches".to_owned(),
            evidence_refs: vec!["source-1".to_owned()],
            referenced_variables: vec!["decision-1".to_owned()],
        }),
        fallback: Some(fallback()),
        source_refs: vec!["source-1".to_owned()],
    }
}

fn denominator() -> SourceDenominator {
    let mut value = SourceDenominator {
        snapshot_id: "snapshot-1".to_owned(),
        snapshot_digest: digest('2'),
        material_handles: vec!["source-1".to_owned()],
        omission_handles: Vec::new(),
        complete: true,
        denominator_digest: String::new(),
    };
    value.denominator_digest = must(value.identity_digest());
    value
}

fn admitted_with(ambiguities: Vec<ClarificationAmbiguity>, policy: &ClarificationPolicy) -> AdmittedClarificationJob {
    let mut value = AdmittedClarificationJob {
        schema_version: CLARIFICATION_SCHEMA_VERSION,
        job: job(),
        ambiguities,
        source_denominator: denominator(),
        admission_digest: String::new(),
    };
    must(value.seal(policy));
    value
}

fn boundary() -> ActiveAgentOrHumanBoundary {
    let state_fence = fence();
    let mut value = ActiveAgentOrHumanBoundary {
        schema_version: CLARIFICATION_SCHEMA_VERSION,
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: state_fence.clone(),
        active_agent: Some(ActiveAgentBoundary {
            principal: "agent-1".to_owned(),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: state_fence.clone(),
            capability_ids: vec!["choose-task-local-mode".to_owned()],
            boundary_ref: "agent-boundary-1".to_owned(),
            current: true,
        }),
        human: Some(HumanBoundary {
            principal: "human-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence,
            decision_kinds: vec![
                HumanDecisionKind::Approval,
                HumanDecisionKind::HighImpactAmbiguity,
            ],
            authority_ref: "human-authority-1".to_owned(),
            current: true,
        }),
        boundary_digest: String::new(),
    };
    must(value.seal());
    value
}

fn valid_inputs() -> (
    ClarificationPolicy,
    AdmittedClarificationJob,
    ValidatedDreamDraft,
    ActiveAgentOrHumanBoundary,
) {
    let policy = policy();
    let admitted = admitted_with(vec![ambiguity(DecisionOwner::TaskLocalAgent)], &policy);
    let draft = validated_draft(&admitted.job);
    (policy, admitted, draft, boundary())
}

fn decide(
    policy: &ClarificationPolicy,
    admitted: &AdmittedClarificationJob,
    draft: &ValidatedDreamDraft,
    boundary: &ActiveAgentOrHumanBoundary,
) -> ClarificationDecision {
    must(propose_clarification(admitted, draft, boundary, policy))
}

// WORK_UNIT_CASE: 630/1
#[test]
fn valid_atomic_choice_question() {
    let (policy, admitted, draft, boundary) = valid_inputs();
    let decision = decide(&policy, &admitted, &draft, &boundary);
    assert_eq!(decision.disposition, ClarificationDisposition::Candidate);
    let candidate = match decision.candidate {
        Some(value) => value,
        None => panic!("candidate expected"),
    };
    assert_eq!(candidate.variable.variable_id, "decision-1");
    assert!(candidate.question.ends_with('?'));
}

// WORK_UNIT_CASE: 630/2
#[test]
fn closed_answer_families_validate() {
    let policy = policy();
    let mut value = variable(DecisionOwner::TaskLocalAgent);
    let families = [
        AnswerSchema::Boolean,
        AnswerSchema::Ternary,
        AnswerSchema::Date,
        AnswerSchema::DateTime,
        AnswerSchema::Interval,
        AnswerSchema::Version,
    ];
    for family in families {
        value.answer_schema = family;
        value.branches = match &value.answer_schema {
            AnswerSchema::Boolean => vec![branch("false", "no"), branch("true", "yes")],
            AnswerSchema::Ternary => vec![
                branch("no", "no"),
                branch("unknown", "unknown"),
                branch("yes", "yes"),
            ],
            _ => vec![AnswerBranch {
                branch_id: "any-valid".to_owned(),
                matcher: AnswerMatcher::AnyValid,
                outcome_id: "bounded-value".to_owned(),
                summary: "Continue with the bounded value".to_owned(),
                referenced_variables: vec!["decision-1".to_owned()],
            }],
        };
        must(value.validate(&policy));
    }
}

// WORK_UNIT_CASE: 630/3
#[test]
fn bounded_text_requires_external_interpretation_owner() {
    let mut policy = policy();
    policy.allow_bounded_text = true;
    must(policy.seal());
    let mut item = ambiguity(DecisionOwner::TaskLocalAgent);
    item.variables[0].answer_schema = AnswerSchema::BoundedText {
        max_bytes: 128,
        interpretation_owner: "bounded-text-interpreter-v1".to_owned(),
    };
    item.variables[0].branches = vec![AnswerBranch {
        branch_id: "any-valid".to_owned(),
        matcher: AnswerMatcher::AnyValid,
        outcome_id: "unresolved-text".to_owned(),
        summary: "Retain the answer for external interpretation".to_owned(),
        referenced_variables: vec!["decision-1".to_owned()],
    }];
    let admitted = admitted_with(vec![item], &policy);
    let result = decide(&policy, &admitted, &validated_draft(&admitted.job), &boundary());
    assert!(result.candidate.is_some());
}

// WORK_UNIT_CASE: 630/4
#[test]
fn wrong_job_class_is_rejected() {
    let (policy, mut admitted, draft, boundary) = valid_inputs();
    admitted.job.job_class = JobClass::Orientation;
    assert!(admitted.seal(&policy).is_err());
    assert!(propose_clarification(&admitted, &draft, &boundary, &policy).is_err());
}

// WORK_UNIT_CASE: 630/5
#[test]
fn request_scope_fence_and_boundary_must_match() {
    let (policy, admitted, draft, mut boundary) = valid_inputs();
    boundary.scope_id = "other-scope".to_owned();
    if let Some(agent) = &mut boundary.active_agent {
        agent.scope_id = "other-scope".to_owned();
    }
    if let Some(human) = &mut boundary.human {
        human.scope_id = "other-scope".to_owned();
    }
    must(boundary.seal());
    assert!(propose_clarification(&admitted, &draft, &boundary, &policy).is_err());
}

// WORK_UNIT_CASE: 630/6
#[test]
fn nonmaterial_ambiguity_emits_no_question() {
    let policy = policy();
    let mut item = ambiguity(DecisionOwner::TaskLocalAgent);
    item.state = AmbiguityState::NonMaterial {
        reason_code: "presentation_only".to_owned(),
    };
    let admitted = admitted_with(vec![item], &policy);
    let decision = decide(&policy, &admitted, &validated_draft(&admitted.job), &boundary());
    assert_eq!(
        decision.disposition,
        ClarificationDisposition::NoQuestion {
            reason: NoQuestionReason::NoMaterialAmbiguity
        }
    );
}

// WORK_UNIT_CASE: 630/7
#[test]
fn admitted_evidence_prevents_redundant_question() {
    let policy = policy();
    let mut item = ambiguity(DecisionOwner::TaskLocalAgent);
    item.state = AmbiguityState::ResolvedByEvidence {
        resolution_ref: "resolution-1".to_owned(),
        evidence_refs: vec!["source-1".to_owned()],
    };
    let admitted = admitted_with(vec![item], &policy);
    let decision = decide(&policy, &admitted, &validated_draft(&admitted.job), &boundary());
    assert_eq!(
        decision.disposition,
        ClarificationDisposition::NoQuestion {
            reason: NoQuestionReason::AlreadyAnswerable
        }
    );
}

// WORK_UNIT_CASE: 630/8
#[test]
fn owner_safe_default_prevents_redundant_question() {
    let policy = policy();
    let mut item = ambiguity(DecisionOwner::TaskLocalAgent);
    item.state = AmbiguityState::SafeDefaultAvailable {
        authority_ref: "owner-policy-1".to_owned(),
        evidence_refs: vec!["source-1".to_owned()],
        outcome_id: "safe-default".to_owned(),
    };
    let admitted = admitted_with(vec![item], &policy);
    let decision = decide(&policy, &admitted, &validated_draft(&admitted.job), &boundary());
    assert_eq!(
        decision.disposition,
        ClarificationDisposition::NoQuestion {
            reason: NoQuestionReason::SafeFallbackAvailable
        }
    );
}

// WORK_UNIT_CASE: 630/9
#[test]
fn no_safe_continuation_yields_blocked_without_answer_fallback() {
    let policy = policy();
    let mut item = ambiguity(DecisionOwner::TaskLocalAgent);
    item.fallback = None;
    item.materiality = Some(MaterialityEvidence {
        basis: MaterialityBasis::NoSafeContinuation {
            blocking_code: "missing_hard_value".to_owned(),
        },
        summary: "No safe branch exists without this value".to_owned(),
        evidence_refs: vec!["source-1".to_owned()],
        referenced_variables: vec!["decision-1".to_owned()],
    });
    let admitted = admitted_with(vec![item], &policy);
    let decision = decide(&policy, &admitted, &validated_draft(&admitted.job), &boundary());
    let candidate = match decision.candidate {
        Some(value) => value,
        None => panic!("candidate expected"),
    };
    assert!(matches!(
        candidate.fallback,
        UnansweredFallback::BlockedWithoutAnswer { .. }
    ));
}

// WORK_UNIT_CASE: 630/10
#[test]
fn two_independent_variables_require_decomposition() {
    let policy = policy();
    let mut item = ambiguity(DecisionOwner::TaskLocalAgent);
    let mut second = variable(DecisionOwner::TaskLocalAgent);
    second.variable_id = "decision-2".to_owned();
    second.component_ids = vec!["decision-2".to_owned()];
    item.variables.push(second);
    let admitted = admitted_with(vec![item], &policy);
    let decision = decide(&policy, &admitted, &validated_draft(&admitted.job), &boundary());
    assert_eq!(
        decision.disposition,
        ClarificationDisposition::NoQuestion {
            reason: NoQuestionReason::DecompositionRequired
        }
    );
}

// WORK_UNIT_CASE: 630/11
#[test]
fn hidden_second_variable_in_branch_is_rejected() {
    let policy = policy();
    let mut item = ambiguity(DecisionOwner::TaskLocalAgent);
    item.variables[0].branches[0]
        .referenced_variables
        .push("hidden-second-variable".to_owned());
    let admitted = admitted_with(vec![item], &policy);
    let decision = decide(&policy, &admitted, &validated_draft(&admitted.job), &boundary());
    assert_eq!(
        decision.disposition,
        ClarificationDisposition::NoQuestion {
            reason: NoQuestionReason::DecompositionRequired
        }
    );
}

// WORK_UNIT_CASE: 630/12
#[test]
fn one_question_mark_does_not_hide_compound_semantics() {
    let policy = policy();
    let mut item = ambiguity(DecisionOwner::TaskLocalAgent);
    item.variables[0]
        .component_ids
        .push("second-component".to_owned());
    let admitted = admitted_with(vec![item], &policy);
    let decision = decide(&policy, &admitted, &validated_draft(&admitted.job), &boundary());
    assert_eq!(
        decision.disposition,
        ClarificationDisposition::NoQuestion {
            reason: NoQuestionReason::DecompositionRequired
        }
    );
}

// WORK_UNIT_CASE: 630/13
#[test]
fn unbounded_text_schema_is_rejected() {
    let mut policy = policy();
    policy.allow_bounded_text = true;
    must(policy.seal());
    let mut item = ambiguity(DecisionOwner::TaskLocalAgent);
    item.variables[0].answer_schema = AnswerSchema::BoundedText {
        max_bytes: u32::MAX,
        interpretation_owner: "text-owner".to_owned(),
    };
    item.variables[0].branches = vec![AnswerBranch {
        branch_id: "any".to_owned(),
        matcher: AnswerMatcher::AnyValid,
        outcome_id: "outcome".to_owned(),
        summary: "Bounded interpretation".to_owned(),
        referenced_variables: vec!["decision-1".to_owned()],
    }];
    let admitted = admitted_with(vec![item], &policy);
    assert!(propose_clarification(
        &admitted,
        &validated_draft(&admitted.job),
        &boundary(),
        &policy,
    )
    .is_err());
}

// WORK_UNIT_CASE: 630/14
#[test]
fn unsupported_scalar_unit_is_rejected() {
    let policy = policy();
    let mut value = variable(DecisionOwner::TaskLocalAgent);
    value.answer_schema = AnswerSchema::Scalar {
        unit: "arbitrary".to_owned(),
        min_milli: 0,
        max_milli: 10,
        precision: 0,
    };
    value.branches = vec![AnswerBranch {
        branch_id: "range".to_owned(),
        matcher: AnswerMatcher::ScalarRange {
            min_milli: 0,
            max_milli: 10,
        },
        outcome_id: "range-outcome".to_owned(),
        summary: "Use the bounded scalar".to_owned(),
        referenced_variables: vec!["decision-1".to_owned()],
    }];
    assert!(value.validate(&policy).is_err());
}

// WORK_UNIT_CASE: 630/15
#[test]
fn valid_answer_denominator_requires_complete_branch_map() {
    let policy = policy();
    let mut value = variable(DecisionOwner::TaskLocalAgent);
    value.branches.pop();
    assert!(matches!(
        value.validate(&policy),
        Err(ClarificationError::IncompleteBranchMap { .. })
    ));
}

// WORK_UNIT_CASE: 630/16
#[test]
fn nonanswer_states_are_distinct() {
    let policy = policy();
    let mut value = variable(DecisionOwner::TaskLocalAgent);
    value.non_answer_branches.expired = value.non_answer_branches.unanswered.clone();
    assert!(matches!(
        value.validate(&policy),
        Err(ClarificationError::DuplicateIdentity { .. })
    ));
}

// WORK_UNIT_CASE: 630/17
#[test]
fn task_local_agent_route_requires_current_capability() {
    let (policy, admitted, draft, boundary) = valid_inputs();
    let decision = decide(&policy, &admitted, &draft, &boundary);
    let candidate = match decision.candidate {
        Some(value) => value,
        None => panic!("candidate expected"),
    };
    assert!(matches!(
        candidate.routing,
        RoutingRecommendation::TaskLocalAgent { .. }
    ));
}

// WORK_UNIT_CASE: 630/18
#[test]
fn human_owned_choice_routes_to_explicit_human_boundary() {
    let policy = policy();
    let admitted = admitted_with(
        vec![ambiguity(DecisionOwner::Human(HumanDecisionKind::Approval))],
        &policy,
    );
    let decision = decide(&policy, &admitted, &validated_draft(&admitted.job), &boundary());
    let candidate = match decision.candidate {
        Some(value) => value,
        None => panic!("candidate expected"),
    };
    assert!(matches!(candidate.routing, RoutingRecommendation::Human { .. }));
}

// WORK_UNIT_CASE: 630/19
#[test]
fn agent_cannot_answer_human_owned_choice() {
    let policy = policy();
    let admitted = admitted_with(
        vec![ambiguity(DecisionOwner::Human(HumanDecisionKind::Approval))],
        &policy,
    );
    let mut recipient = boundary();
    recipient.human = None;
    must(recipient.seal());
    let decision = decide(
        &policy,
        &admitted,
        &validated_draft(&admitted.job),
        &recipient,
    );
    assert_eq!(
        decision.disposition,
        ClarificationDisposition::NoQuestion {
            reason: NoQuestionReason::UnauthorizedResponder
        }
    );
}

// WORK_UNIT_CASE: 630/20
#[test]
fn model_uncertainty_alone_does_not_create_human_authority() {
    let policy = policy();
    let admitted = admitted_with(
        vec![ambiguity(DecisionOwner::Human(
            HumanDecisionKind::HighImpactAmbiguity,
        ))],
        &policy,
    );
    let mut recipient = boundary();
    recipient.human = None;
    must(recipient.seal());
    let decision = decide(
        &policy,
        &admitted,
        &validated_draft(&admitted.job),
        &recipient,
    );
    assert!(decision.candidate.is_none());
}

// WORK_UNIT_CASE: 630/21
#[test]
fn unknown_responder_authority_blocks_selection() {
    let policy = policy();
    let admitted = admitted_with(vec![ambiguity(DecisionOwner::Unknown)], &policy);
    let decision = decide(&policy, &admitted, &validated_draft(&admitted.job), &boundary());
    assert_eq!(
        decision.disposition,
        ClarificationDisposition::NoQuestion {
            reason: NoQuestionReason::UnauthorizedResponder
        }
    );
}

// WORK_UNIT_CASE: 630/22
#[test]
fn neutral_rendering_is_deterministic() {
    let (policy, admitted, draft, boundary) = valid_inputs();
    let first = decide(&policy, &admitted, &draft, &boundary);
    let second = decide(&policy, &admitted, &draft, &boundary);
    assert_eq!(first, second);
    let question = match first.candidate {
        Some(value) => value.question,
        None => panic!("candidate expected"),
    };
    assert_eq!(question, "Which value should be used for the deployment mode?");
}

// WORK_UNIT_CASE: 630/23
#[test]
fn preferred_or_default_option_framing_is_rejected() {
    let policy = policy();
    let mut value = variable(DecisionOwner::TaskLocalAgent);
    if let AnswerSchema::Choice { options } = &mut value.answer_schema {
        options[0].label = "Recommended safe mode".to_owned();
    }
    assert!(value.validate(&policy).is_err());
}

// WORK_UNIT_CASE: 630/24
#[test]
fn secret_material_never_becomes_a_question() {
    let policy = policy();
    let mut item = ambiguity(DecisionOwner::TaskLocalAgent);
    item.variables[0].content_class = ClarificationContentClass::Secret;
    let admitted = admitted_with(vec![item], &policy);
    let decision = decide(&policy, &admitted, &validated_draft(&admitted.job), &boundary());
    assert_eq!(
        decision.disposition,
        ClarificationDisposition::NoQuestion {
            reason: NoQuestionReason::SecretOrProtected
        }
    );
}

// WORK_UNIT_CASE: 630/25
#[test]
fn executable_instruction_remains_inert_and_unrendered() {
    let policy = policy();
    let mut item = ambiguity(DecisionOwner::TaskLocalAgent);
    item.variables[0].content_class = ClarificationContentClass::ExecutableInstruction;
    let admitted = admitted_with(vec![item], &policy);
    let decision = decide(&policy, &admitted, &validated_draft(&admitted.job), &boundary());
    assert!(decision.candidate.is_none());
}

// WORK_UNIT_CASE: 630/26
#[test]
fn unanswered_fallback_preserves_unknown_without_assumed_answer() {
    let (policy, admitted, draft, boundary) = valid_inputs();
    let decision = decide(&policy, &admitted, &draft, &boundary);
    let candidate = match decision.candidate {
        Some(value) => value,
        None => panic!("candidate expected"),
    };
    assert!(matches!(candidate.fallback, UnansweredFallback::PartialResult { .. }));
}

// WORK_UNIT_CASE: 630/27
#[test]
fn expiry_fence_and_policy_bind_candidate_invalidation() {
    let (policy, admitted, draft, boundary) = valid_inputs();
    let decision = decide(&policy, &admitted, &draft, &boundary);
    let mut candidate = match decision.candidate {
        Some(value) => value,
        None => panic!("candidate expected"),
    };
    candidate.invalidation.policy_digest = digest('9');
    assert!(candidate.validate(&policy).is_err());
}

// WORK_UNIT_CASE: 630/28
#[test]
fn multiple_material_ambiguities_yield_decomposition() {
    let policy = policy();
    let first = ambiguity(DecisionOwner::TaskLocalAgent);
    let mut second = first.clone();
    second.ambiguity_id = "ambiguity-2".to_owned();
    let admitted = admitted_with(vec![first, second], &policy);
    let decision = decide(&policy, &admitted, &validated_draft(&admitted.job), &boundary());
    assert_eq!(
        decision.disposition,
        ClarificationDisposition::NoQuestion {
            reason: NoQuestionReason::DecompositionRequired
        }
    );
}

// WORK_UNIT_CASE: 630/29
#[test]
fn public_result_contains_no_answer_delivery_ack_or_finish_state() {
    let (policy, admitted, draft, boundary) = valid_inputs();
    let decision = decide(&policy, &admitted, &draft, &boundary);
    let wire = must(serde_json::to_string(&decision));
    for forbidden in ["delivered", "acknowledged", "actual_answer", "task_finish"] {
        assert!(!wire.contains(forbidden));
    }
}

// WORK_UNIT_CASE: 630/30
#[test]
fn public_api_exposes_no_response_validation_operation() {
    let source = include_str!("lib.rs");
    assert!(!source.contains("validate_answer"));
    assert!(!source.contains("submit_answer"));
    assert!(!source.contains("receive_answer"));
}

// WORK_UNIT_CASE: 630/31
#[test]
fn every_output_and_work_bound_is_enforced() {
    let (mut policy, mut admitted, draft, boundary) = valid_inputs();
    policy.max_work_units = 1;
    must(policy.seal());
    must(admitted.seal(&policy));
    assert!(propose_clarification(&admitted, &draft, &boundary, &policy).is_err());
}

// WORK_UNIT_CASE: 630/32
#[test]
fn changed_same_identity_input_conflicts_with_frozen_digest() {
    let (policy, mut admitted, draft, boundary) = valid_inputs();
    admitted.ambiguities[0].objective_id = "changed-objective".to_owned();
    assert!(matches!(
        propose_clarification(&admitted, &draft, &boundary, &policy),
        Err(ClarificationError::IdentityConflict)
    ));
}

// WORK_UNIT_CASE: 630/33
#[test]
fn ambiguity_permutation_preserves_decision_identity() {
    let policy = policy();
    let first = ambiguity(DecisionOwner::TaskLocalAgent);
    let mut second = first.clone();
    second.ambiguity_id = "nonmaterial-2".to_owned();
    second.state = AmbiguityState::NonMaterial {
        reason_code: "presentation_only".to_owned(),
    };
    let admitted_a = admitted_with(vec![first.clone(), second.clone()], &policy);
    let admitted_b = admitted_with(vec![second, first], &policy);
    let draft_a = validated_draft(&admitted_a.job);
    let draft_b = validated_draft(&admitted_b.job);
    let first_decision = decide(&policy, &admitted_a, &draft_a, &boundary());
    let second_decision = decide(&policy, &admitted_b, &draft_b, &boundary());
    assert_eq!(first_decision.decision_digest, second_decision.decision_digest);
}

// WORK_UNIT_CASE: 630/34
#[test]
fn malformed_input_is_bounded_and_does_not_panic() {
    let outcome = std::panic::catch_unwind(|| {
        serde_json::from_str::<ClarificationDecision>("{not-json")
    });
    assert!(outcome.is_ok());
    match outcome {
        Ok(result) => assert!(result.is_err()),
        Err(_) => panic!("JSON rejection panicked"),
    }
}

// WORK_UNIT_CASE: 630/35
#[test]
fn emitted_candidate_has_exactly_one_decision_variable() {
    let (policy, admitted, draft, boundary) = valid_inputs();
    let decision = decide(&policy, &admitted, &draft, &boundary);
    let candidate = match decision.candidate {
        Some(value) => value,
        None => panic!("candidate expected"),
    };
    assert_eq!(
        candidate.variable.component_ids,
        vec![candidate.variable.variable_id.clone()]
    );
}

// WORK_UNIT_CASE: 630/36
#[test]
fn every_valid_answer_maps_to_exactly_one_branch() {
    let (policy, admitted, draft, boundary) = valid_inputs();
    let decision = decide(&policy, &admitted, &draft, &boundary);
    let candidate = match decision.candidate {
        Some(value) => value,
        None => panic!("candidate expected"),
    };
    assert_eq!(candidate.variable.branches.len(), 2);
    must(candidate.validate(&policy));
}

// WORK_UNIT_CASE: 630/37
#[test]
fn removed_materiality_evidence_invalidates_candidate_construction() {
    let policy = policy();
    let mut item = ambiguity(DecisionOwner::TaskLocalAgent);
    if let Some(materiality) = &mut item.materiality {
        materiality.evidence_refs.clear();
    }
    let mut admitted = AdmittedClarificationJob {
        schema_version: CLARIFICATION_SCHEMA_VERSION,
        job: job(),
        ambiguities: vec![item],
        source_denominator: denominator(),
        admission_digest: String::new(),
    };
    assert!(admitted.seal(&policy).is_err());
}

// WORK_UNIT_CASE: 630/38
#[test]
fn crate_has_no_orientation_rival_probe_or_validator_algorithm_dependency() {
    let manifest = include_str!("../Cargo.toml");
    for forbidden in [
        "eliot-dreamer-orientation",
        "eliot-dreamer-rival-model",
        "eliot-dreamer-probe-plan",
        "eliot-dreamer-candidate-validation",
    ] {
        assert!(!manifest.contains(forbidden));
    }
}

// WORK_UNIT_CASE: 630/39
#[test]
fn crate_has_no_transport_provider_store_mutation_or_finish_path() {
    let lib = include_str!("lib.rs");
    let selector = include_str!("select.rs");
    let manifest = include_str!("../Cargo.toml");
    let combined = format!("{lib}\n{selector}\n{manifest}").to_ascii_lowercase();
    let forbidden = [
        ["to", "kio"].concat(),
        ["req", "west"].concat(),
        ["surreal", "db"].concat(),
        ["std::", "process"].concat(),
        ["std::", "fs"].concat(),
        ["finish", "_task"].concat(),
        ["send", "_message"].concat(),
        ["write", "_canonical"].concat(),
    ];
    for item in forbidden {
        assert!(!combined.contains(&item));
    }
}
