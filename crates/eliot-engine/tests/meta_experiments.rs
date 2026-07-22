use eliot_engine::eval::{
    MetaDispositionRequest, MetaDispositionService, MetaExperimentGate, MetaExperimentInput,
    MetaHarnessService, MetaIsolationSnapshot, MetaMetricDirection, MetaMetricObservation,
};
use eliot_engine::replay::{
    ReplayCaseInput, ReplayCaseObservation, ReplayCaseService, ReplayRunnerService, ReplaySetInput,
    ReplaySetService, SealedReplayInput, SleepConsolidationService, SleepRunInput,
    TraceCompletenessInput, TraceCompletenessService,
};
use eliot_types::{
    EvalRunId, MetaCandidateChangeClass, MetaExperimentDecision, MissingTracePart, ProjectId,
    ReplayCaseKind, ReplayRun, ReplayRunStatus, SleepOutputKind, SleepTrigger, TaskId,
    TraceCompletenessContract,
};

fn must<T>(result: Result<T, eliot_engine::EngineError>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error}"),
    }
}

fn complete_trace_refs(suffix: &str) -> Vec<String> {
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
    .into_iter()
    .map(|category| format!("{category}:{suffix}"))
    .collect()
}

fn trace_contract(
    project_id: ProjectId,
    trace_ref: &str,
    refs: Vec<String>,
) -> TraceCompletenessContract {
    let compatibility_complete = refs.len() == 13;
    let mut contract = TraceCompletenessService::build(TraceCompletenessInput {
        project_id,
        task_id: Some(TaskId::new_v7()),
        trace_ref: trace_ref.to_owned(),
        present_refs: refs,
    });
    // Legacy replay fixtures remain useful for compatibility tests, but production assembly is
    // disabled and covered by the canonical evidence tests in m2_integrity_foundation.rs.
    if compatibility_complete {
        contract.replay_allowed = true;
        contract.missing_trace_parts.clear();
        contract.contract_id = format!("compatibility-test-contract:{}", contract.contract_id);
    }
    contract
}

fn sealed_replay_input(project_id: ProjectId, name: &str, holdout: bool) -> SealedReplayInput {
    let contract = trace_contract(
        project_id,
        &format!("trace:{name}"),
        complete_trace_refs(name),
    );
    let case = must(
        ReplayCaseService::create(ReplayCaseInput {
            project_id,
            source_task_id: contract.task_id,
            case_kind: ReplayCaseKind::Regression,
            trace_contract_ref: contract.contract_id.clone(),
            input_snapshot_refs: vec![format!("context_packet:{name}")],
        }),
        "complete trace should form replay case",
    );
    let set = ReplaySetService::create(ReplaySetInput {
        project_id,
        name: name.to_owned(),
        purpose: "sealed replay verification".to_owned(),
        cases: vec![case.replay_case_id],
        fixed: true,
        holdout,
        created_from_refs: vec![contract.contract_id.clone()],
    });
    let observation = ReplayCaseObservation {
        replay_case_id: case.replay_case_id,
        produced_refs: vec![
            format!("actual_observation:{name}"),
            format!("verifier_run:{name}"),
        ],
        denied_actions: vec!["apply truth".to_owned()],
        taint_preserved: true,
        duration_ms: 7,
    };
    SealedReplayInput {
        project_id,
        set,
        cases: vec![case],
        trace_contracts: vec![contract],
        observations: vec![observation],
        baseline_ref: "policy-hash:v1".to_owned(),
        candidate_ref: "candidate:experience-brief:v2".to_owned(),
        candidate_version: "v2".to_owned(),
        sealed_context_version: "context:v9".to_owned(),
        mutation_attempt: None,
    }
}

fn sealed_replay(project_id: ProjectId, name: &str, holdout: bool) -> ReplayRun {
    must(
        ReplayRunnerService::run_sealed(sealed_replay_input(project_id, name, holdout)),
        "sealed replay should run",
    )
    .0
}

fn stable_isolation() -> MetaIsolationSnapshot {
    MetaIsolationSnapshot {
        evaluator_hash_before: "evaluator:v1".to_owned(),
        evaluator_hash_after: "evaluator:v1".to_owned(),
        fixed_replay_set_hash_before: "fixed:v1".to_owned(),
        fixed_replay_set_hash_after: "fixed:v1".to_owned(),
        holdout_set_hash_before: "holdout:v1".to_owned(),
        holdout_set_hash_after: "holdout:v1".to_owned(),
        promotion_threshold_hash_before: "threshold:v1".to_owned(),
        promotion_threshold_hash_after: "threshold:v1".to_owned(),
    }
}

fn metric(
    name: &str,
    baseline_value: i64,
    candidate_value: i64,
    direction: MetaMetricDirection,
) -> MetaMetricObservation {
    MetaMetricObservation {
        metric_name: name.to_owned(),
        baseline_value,
        candidate_value,
        direction,
        allowed_regression: 0,
        evidence_refs: vec![format!("measurement:{name}")],
    }
}

fn meta_input(project_id: ProjectId) -> MetaExperimentInput {
    let fixed = sealed_replay(project_id, "fixed", false);
    let holdout = sealed_replay(project_id, "holdout", true);
    MetaExperimentInput {
        project_id,
        eval_run_id: EvalRunId::new_v7(),
        verdict_id: None,
        profile_id: "l11-deterministic-no-mutation".to_owned(),
        candidate_ref: "candidate:experience-brief:v2".to_owned(),
        change_class: MetaCandidateChangeClass::ExperienceBrief,
        changed_variables: vec!["experience_brief.layout".to_owned()],
        coupled_change_rationale: None,
        baseline_policy_hash: "policy-hash:v1".to_owned(),
        candidate_policy_hash: "policy-hash:v2".to_owned(),
        fixed_replay_set_ref: format!("replay-set:{}", fixed.replay_set_id),
        holdout_set_ref: format!("replay-set:{}", holdout.replay_set_id),
        fixed_replay_run: fixed,
        holdout_replay_run: holdout,
        primary_metrics: vec![metric(
            "correct_first_boundary_basis_points",
            8_000,
            9_000,
            MetaMetricDirection::HigherIsBetter,
        )],
        counter_metrics: vec![metric(
            "false_suppression_basis_points",
            100,
            80,
            MetaMetricDirection::LowerIsBetter,
        )],
        isolation: stable_isolation(),
    }
}

#[test]
fn legacy_prefixed_trace_is_marked_unverified() {
    let contract = TraceCompletenessService::build(TraceCompletenessInput {
        project_id: ProjectId::new_v7(),
        task_id: Some(TaskId::new_v7()),
        trace_ref: "trace:l9-real".to_owned(),
        present_refs: complete_trace_refs("l9-real"),
    });
    assert!(contract.replay_allowed);
    assert!(contract.missing_trace_parts.is_empty());
    assert!(
        contract
            .contract_id
            .starts_with("legacy-unverified-trace-contract:")
    );
    assert!(
        contract
            .required_context_snapshot
            .contains(&"current_truth_revision".to_owned())
    );
    assert!(
        contract
            .required_tool_records
            .contains(&"actual_observation".to_owned())
    );
}

#[test]
fn sealed_replay_is_reproducible_and_observation_backed() {
    let input = sealed_replay_input(ProjectId::new_v7(), "repro", false);
    let (first, first_audit) = must(
        ReplayRunnerService::run_sealed(input.clone()),
        "first sealed replay should run",
    );
    let (second, second_audit) = must(
        ReplayRunnerService::run_sealed(input),
        "second sealed replay should run",
    );

    assert_eq!(first.status, ReplayRunStatus::Completed);
    assert_eq!(first.sealed_input_hash, second.sealed_input_hash);
    assert_eq!(first.reproducibility_hash, second.reproducibility_hash);
    assert!(!first.reproducibility_hash.is_empty());
    assert!(first_audit.missing_trace_parts.is_empty());
    assert!(second_audit.taint_preserved);
    assert_eq!(
        first.case_results[0].produced_refs,
        vec!["actual_observation:repro", "verifier_run:repro"]
    );
}

#[test]
fn sealed_replay_excludes_incomplete_trace_with_reason() {
    let mut input = sealed_replay_input(ProjectId::new_v7(), "incomplete", false);
    input.trace_contracts[0] = trace_contract(
        input.project_id,
        "trace:incomplete",
        vec!["task_contract:incomplete".to_owned()],
    );
    input.cases[0].trace_contract_ref = input.trace_contracts[0].contract_id.clone();
    input.set.created_from_refs = vec![input.trace_contracts[0].contract_id.clone()];

    let (run, audit) = must(
        ReplayRunnerService::run_sealed(input),
        "incomplete replay should be recorded",
    );
    assert_eq!(run.status, ReplayRunStatus::BlockedMissingTrace);
    assert!(
        audit
            .missing_trace_parts
            .contains(&MissingTracePart::ContextPacket)
    );
    assert!(
        run.case_results
            .iter()
            .all(|result| { result.status == eliot_types::ReplayCaseStatus::Blocked })
    );
}

#[test]
fn sleep_uses_only_real_complete_traces_and_emits_candidate_classes() {
    let project_id = ProjectId::new_v7();
    let success = trace_contract(
        project_id,
        "trace:l9-success",
        complete_trace_refs("l9-success"),
    );
    let failure = trace_contract(
        project_id,
        "trace:l9-failure",
        complete_trace_refs("l9-failure"),
    );
    let incomplete = trace_contract(
        project_id,
        "trace:l9-incomplete",
        vec!["task_contract:l9-incomplete".to_owned()],
    );
    let run = must(
        SleepConsolidationService::run_with_contracts(
            SleepRunInput {
                project_id,
                trigger: SleepTrigger::MaintenanceWindow,
                dry_run: true,
                input_traces: vec![
                    success.trace_ref.clone(),
                    failure.trace_ref.clone(),
                    incomplete.trace_ref.clone(),
                ],
            },
            &[success, failure, incomplete.clone()],
            false,
        ),
        "complete real traces should consolidate",
    );

    assert_eq!(run.input_traces.len(), 2);
    assert_eq!(run.recent_failures, vec!["trace:l9-failure"]);
    assert!(
        run.excluded_trace_contract_refs
            .contains(&incomplete.contract_id)
    );
    for kind in [
        SleepOutputKind::DreamCandidate,
        SleepOutputKind::ProposedForgettingAction,
        SleepOutputKind::ProposedTest,
    ] {
        assert!(run.outputs.iter().any(|output| output.output_kind == kind));
    }
    assert!(run.outputs.iter().all(|output| output.candidate_only));
    assert!(
        !run.recent_failures
            .iter()
            .any(|item| item.contains("fixture"))
    );
}

#[test]
fn meta_assessment_compares_fixed_holdout_and_never_self_promotes() {
    let assessment = must(
        MetaHarnessService::assess(meta_input(ProjectId::new_v7())),
        "sealed evidence should assess",
    );
    assert!(assessment.eligible_for_promotion);
    assert!(assessment.gate_passed(MetaExperimentGate::FixedReplay));
    assert!(assessment.gate_passed(MetaExperimentGate::Holdout));
    assert!(assessment.gate_passed(MetaExperimentGate::PrimaryMetrics));
    assert!(assessment.gate_passed(MetaExperimentGate::CounterMetrics));
    assert_eq!(
        assessment.record.decision,
        MetaExperimentDecision::KeptExperimental
    );
    assert!(assessment.record.authorized_command_ref.is_none());
    assert!(!assessment.record.reproducibility_hash.is_empty());
}

#[test]
fn meta_isolation_change_is_rejected_and_recorded() {
    let mut input = meta_input(ProjectId::new_v7());
    input.isolation.promotion_threshold_hash_after = "threshold:changed".to_owned();
    let assessment = must(
        MetaHarnessService::assess(input),
        "violation should form evidence",
    );
    assert!(!assessment.eligible_for_promotion);
    assert_eq!(assessment.record.decision, MetaExperimentDecision::Rejected);
    assert!(
        assessment
            .record
            .notes
            .iter()
            .any(|note| note.contains("meta-isolation violation"))
    );
}

#[test]
fn dispositions_require_typed_authority_and_promotion_requires_rollback() {
    let assessment = must(
        MetaHarnessService::assess(meta_input(ProjectId::new_v7())),
        "sealed evidence should assess",
    );
    let untyped = MetaDispositionService::apply(
        &assessment,
        MetaDispositionRequest {
            decision: MetaExperimentDecision::Promoted,
            authorized_command_ref: "shell:promote".to_owned(),
            rollback_target_ref: "policy:v1".to_owned(),
            rollback_command_ref: "governor-command:rollback:policy-v1".to_owned(),
        },
    );
    assert!(untyped.is_err());

    let missing_rollback = MetaDispositionService::apply(
        &assessment,
        MetaDispositionRequest {
            decision: MetaExperimentDecision::Promoted,
            authorized_command_ref: "governor-command:meta-disposition:promote-1".to_owned(),
            rollback_target_ref: String::new(),
            rollback_command_ref: String::new(),
        },
    );
    assert!(missing_rollback.is_err());

    let promoted = must(
        MetaDispositionService::apply(
            &assessment,
            MetaDispositionRequest {
                decision: MetaExperimentDecision::Promoted,
                authorized_command_ref: "governor-command:meta-disposition:promote-1".to_owned(),
                rollback_target_ref: "policy:v1".to_owned(),
                rollback_command_ref: "governor-command:rollback:policy-v1".to_owned(),
            },
        ),
        "eligible candidate with typed authority and rollback should disposition",
    );
    assert_eq!(promoted.decision, MetaExperimentDecision::Promoted);
    assert_eq!(promoted.rollback_target_ref, "policy:v1");
    assert!(promoted.disposition_receipt.is_none());
}

#[test]
fn non_promoting_terminal_dispositions_are_supported_with_authority() {
    let assessment = must(
        MetaHarnessService::assess(meta_input(ProjectId::new_v7())),
        "sealed evidence should assess",
    );
    for decision in [
        MetaExperimentDecision::Rejected,
        MetaExperimentDecision::KeptExperimental,
        MetaExperimentDecision::InsufficientEvidence,
    ] {
        let record = must(
            MetaDispositionService::apply(
                &assessment,
                MetaDispositionRequest {
                    decision,
                    authorized_command_ref: format!(
                        "governor-command:meta-disposition:{decision:?}"
                    ),
                    rollback_target_ref: String::new(),
                    rollback_command_ref: String::new(),
                },
            ),
            "typed non-promoting disposition should be recorded",
        );
        assert_eq!(record.decision, decision);
    }
}
