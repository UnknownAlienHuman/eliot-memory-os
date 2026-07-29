use eliot_engine::{
    DreamCandidateService, ReplayCaseInput, ReplayCaseService, ReplayRunnerService,
    ReplaySafetyGate, ReplaySetInput, ReplaySetService, ReplayVerdictService,
    SleepConsolidationService, SleepRunInput, TraceCompletenessInput, TraceCompletenessService,
    WorkState,
};
use eliot_types::{
    BlackboardItemKind, DreamCandidateKind, MissingTracePart, ProhibitedDreamEffect, ProjectId,
    ReplayCaseId, ReplayCaseKind, ReplayCaseStatus, ReplayDecision, ReplayRunStatus,
    SkillReplayRequirement, SleepConsolidationStatus, SleepTrigger, TaintClass, TaskId,
};

fn full_trace_refs() -> Vec<String> {
    [
        "task_contract",
        "context_packet",
        "current_truth_revision",
        "memory_exposure_set",
        "agent_tool_events",
        "expected_observation",
        "actual_observation",
        "verifier_run",
        "artifact_ref",
        "finish_decision",
        "policy_snapshot",
        "model_route",
        "outcome_and_cost",
    ]
    .iter()
    .map(|value| (*value).to_owned())
    .collect()
}

fn complete_contract(
    project_id: ProjectId,
    task_id: TaskId,
) -> eliot_types::TraceCompletenessContract {
    TraceCompletenessService::build(TraceCompletenessInput {
        project_id,
        task_id: Some(task_id),
        trace_ref: "trace:test".to_owned(),
        present_refs: full_trace_refs(),
    })
}

#[test]
fn trace_completeness_contract_blocks_incomplete_replay() {
    let complete = complete_contract(ProjectId::new_v7(), TaskId::new_v7());
    assert!(complete.replay_allowed);
    assert!(complete.missing_trace_parts.is_empty());
    assert!(
        complete
            .contract_id
            .starts_with("legacy-unverified-trace-contract:")
    );

    let incomplete = TraceCompletenessService::build(TraceCompletenessInput {
        project_id: ProjectId::new_v7(),
        task_id: Some(TaskId::new_v7()),
        trace_ref: "trace:missing".to_owned(),
        present_refs: vec!["user_prompt".to_owned(), "task_contract".to_owned()],
    });
    assert!(!incomplete.replay_allowed);
    assert!(
        incomplete
            .missing_trace_parts
            .contains(&MissingTracePart::ContextPacket)
    );
}

#[test]
fn replay_case_requires_trace_contract() {
    let result = ReplayCaseService::create(ReplayCaseInput {
        project_id: ProjectId::new_v7(),
        source_task_id: Some(TaskId::new_v7()),
        case_kind: ReplayCaseKind::Regression,
        trace_contract_ref: String::new(),
        input_snapshot_refs: Vec::new(),
    });
    assert!(result.is_err());
}

#[test]
fn replay_set_fixed_and_holdout_metadata() {
    let mut set = ReplaySetService::create(ReplaySetInput {
        project_id: ProjectId::new_v7(),
        name: "fixed".to_owned(),
        purpose: "test".to_owned(),
        cases: vec![ReplayCaseId::new_v7()],
        fixed: true,
        holdout: true,
        created_from_refs: vec!["trace-contract:test".to_owned()],
    });
    assert!(set.fixed);
    assert!(set.holdout);
    assert!(ReplaySetService::add_case(&mut set, ReplayCaseId::new_v7()).is_err());
}

#[test]
fn replay_run_is_deterministic_no_mutation() {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let contract = complete_contract(project_id, task_id);
    let case = match ReplayCaseService::create(ReplayCaseInput {
        project_id,
        source_task_id: Some(task_id),
        case_kind: ReplayCaseKind::Regression,
        trace_contract_ref: contract.contract_id,
        input_snapshot_refs: vec!["context_packet".to_owned()],
    }) {
        Ok(case) => case,
        Err(error) => panic!("complete trace should create replay case: {error}"),
    };
    let set = ReplaySetService::create(ReplaySetInput {
        project_id,
        name: "deterministic".to_owned(),
        purpose: "test".to_owned(),
        cases: vec![case.replay_case_id],
        fixed: false,
        holdout: true,
        created_from_refs: vec!["trace-contract:test".to_owned()],
    });
    let (run, audit) =
        ReplayRunnerService::run(project_id, &set, &[case], None, Some("apply truth"));
    assert_eq!(run.status, ReplayRunStatus::Completed);
    assert!(ReplaySafetyGate::profile_is_safe(&run.run_profile));
    assert!(audit.authority_mutation_blocked);
    assert!(!audit.mutation_attempts_blocked.is_empty());
}

#[test]
fn replay_success_criteria_evaluated() {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let contract = complete_contract(project_id, task_id);
    let case = match ReplayCaseService::create(ReplayCaseInput {
        project_id,
        source_task_id: Some(task_id),
        case_kind: ReplayCaseKind::Regression,
        trace_contract_ref: contract.contract_id,
        input_snapshot_refs: vec!["trace:test".to_owned()],
    }) {
        Ok(case) => case,
        Err(error) => panic!("complete trace should create replay case: {error}"),
    };
    let set = ReplaySetService::create(ReplaySetInput {
        project_id,
        name: "criteria".to_owned(),
        purpose: "test".to_owned(),
        cases: vec![case.replay_case_id],
        fixed: false,
        holdout: true,
        created_from_refs: Vec::new(),
    });
    let (run, _) = ReplayRunnerService::run(project_id, &set, &[case], None, None);
    assert!(run.case_results.iter().all(|result| {
        result.status == ReplayCaseStatus::Passed && !result.measurements.is_empty()
    }));
}

#[test]
fn replay_verdict_marker_only_does_not_apply() {
    let project_id = ProjectId::new_v7();
    let set = ReplaySetService::create(ReplaySetInput {
        project_id,
        name: "verdict".to_owned(),
        purpose: "test".to_owned(),
        cases: Vec::new(),
        fixed: false,
        holdout: true,
        created_from_refs: Vec::new(),
    });
    let (run, _) = ReplayRunnerService::run(project_id, &set, &[], None, None);
    let verdict = ReplayVerdictService::verdict(&run);
    let requirement = SkillReplayRequirement {
        required: true,
        reason: "test".to_owned(),
        replay_marker: None,
        verifier_refs: vec!["deterministic-no-mutation".to_owned()],
    };
    let marked = ReplayVerdictService::marker_only_requirement(&requirement, &verdict);
    assert_eq!(verdict.decision, ReplayDecision::Pass);
    assert!(marked.replay_marker.is_some());
    assert_eq!(marked.verifier_refs, requirement.verifier_refs);
    assert!(
        verdict
            .reasons
            .iter()
            .any(|reason| reason.contains("no apply authority"))
    );
}

#[test]
fn sleep_outputs_candidate_only_and_does_not_mutate_truth() {
    let run = match SleepConsolidationService::run(
        SleepRunInput {
            project_id: ProjectId::new_v7(),
            trigger: SleepTrigger::Manual,
            dry_run: true,
            input_traces: vec!["trace:test".to_owned()],
            max_input_bytes: 8_192,
            reasoning_retry_limit: 1,
        },
        false,
    ) {
        Ok(run) => run,
        Err(error) => panic!("sleep dry-run should create candidate output: {error}"),
    };
    assert_eq!(run.status, SleepConsolidationStatus::CompletedCandidateOnly);
    assert!(run.outputs.iter().all(|output| output.candidate_only));
    assert!(run.replay_requirement.required);
    assert_eq!(run.taint, TaintClass::Unknown);
    assert_eq!(run.input_bytes, 10);
    assert_eq!(run.input_budget_bytes, 8_192);
    assert_eq!(run.reasoning_attempts, 0);
    assert_eq!(run.reasoning_retry_limit, 1);
    assert!(run.deterministic_fallback);
    assert!(!run.degraded);
}

#[test]
fn sleep_rejects_oversized_inputs_and_more_than_one_reasoning_retry() {
    let project_id = ProjectId::new_v7();
    for (max_input_bytes, reasoning_retry_limit) in [(4, 1), (8_192, 2)] {
        let result = SleepConsolidationService::run(
            SleepRunInput {
                project_id,
                trigger: SleepTrigger::Manual,
                dry_run: true,
                input_traces: vec!["trace:test".to_owned()],
                max_input_bytes,
                reasoning_retry_limit,
            },
            false,
        );
        assert!(result.is_err());
    }
}

#[test]
fn dream_candidates_tainted_excluded_from_l3() {
    let (candidate, taint) = DreamCandidateService::create(
        ProjectId::new_v7(),
        DreamCandidateKind::Hypothesis,
        "trace:test".to_owned(),
    );
    assert_eq!(candidate.taint, TaintClass::Unknown);
    assert!(candidate.required_replay.is_some());
    assert!(taint.promotion_block);
    assert!(
        candidate
            .prohibited_direct_effects
            .contains(&ProhibitedDreamEffect::CurrentTruth)
    );
    assert!(!DreamCandidateService::allowed_in_normal_l3(&candidate));
}

#[test]
fn blackboard_mailbox_receive_dream_candidates_for_review() {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let (candidate, _) = DreamCandidateService::create(
        project_id,
        DreamCandidateKind::Hypothesis,
        "trace:test".to_owned(),
    );
    let mut state = WorkState::default();
    let (item, message) =
        DreamCandidateService::route_to_collective(&mut state, project_id, task_id, &candidate);
    assert_eq!(item.kind, BlackboardItemKind::HypothesisCandidate);
    assert_eq!(
        message.kind,
        eliot_types::MailboxMessageKind::ReviewRequested
    );
    assert_eq!(state.blackboard_items.len(), 1);
    assert_eq!(state.mailbox_messages.len(), 1);
}

#[test]
fn incident_lockdown_blocks_sleep_candidate_creation() {
    let result = SleepConsolidationService::run(
        SleepRunInput {
            project_id: ProjectId::new_v7(),
            trigger: SleepTrigger::Manual,
            dry_run: true,
            input_traces: vec!["trace:test".to_owned()],
            max_input_bytes: 8_192,
            reasoning_retry_limit: 1,
        },
        true,
    );
    assert!(result.is_err());
}
