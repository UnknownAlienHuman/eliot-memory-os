use eliot_engine::{
    CanonicalMetaExperimentAssessment, CanonicalMetaExperimentInput, CanonicalReplayExecutionInput,
    CanonicalTraceCompletenessInput, MetaHarnessService, MetaPolicyExecutor, ReplayCaseInput,
    ReplayCaseObservation, ReplayCaseService, ReplayRunnerService, ReplaySealBundle,
    ReplaySealInput, ReplaySealService, ReplaySetInput, ReplaySetService, SealedReplayInput,
    SleepConsolidationService, SleepRunInput, TraceCompletenessInput, TraceCompletenessService,
};
use eliot_types::{
    CanonicalReplayExecutionRecord, CanonicalReplayObservationEvidence,
    CanonicalTraceCompletenessContract, CanonicalTraceEvidenceKind, CanonicalTraceReceiptBinding,
    ExperimentalMetaPolicyPayload, MemoryRevision, MetaCandidateChangeClass,
    MetaExperimentDecision, MetaIsolationFence, MetaPolicyAuthorization, MetaPolicyExecutionAction,
    ProjectId, ReceiptId, ReplayCaseKind, ReplayCaseStatus, ReplayRunStatus, ReplaySetRole,
    ReplayThresholdPolicyV1, SemanticCommandKind, SleepCandidateArtifactKind, SleepTrigger,
    TaintClass, TaskId, WriteId, WriteReceiptRef,
};
use time::OffsetDateTime;

fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error}"),
    }
}

fn canonical_contract(
    project_id: ProjectId,
    task_id: TaskId,
    trace_ref: &str,
) -> CanonicalTraceCompletenessContract {
    let receipt_kinds = [
        CanonicalTraceEvidenceKind::TaskContract,
        CanonicalTraceEvidenceKind::ActualObservation,
        CanonicalTraceEvidenceKind::VerifierRun,
    ];
    let mut evidence = Vec::new();
    let mut input_refs = Vec::new();
    let mut input_hashes = Vec::new();
    for (index, kind) in receipt_kinds.into_iter().enumerate() {
        let reference = format!("{}:canonical-{index}", kind.as_str());
        let input_hash = blake3::hash(format!("fixture-input:{index}").as_bytes())
            .to_hex()
            .to_string();
        input_refs.push(reference.clone());
        input_hashes.push(input_hash.clone());
        evidence.push(must(
            TraceCompletenessService::receipt_evidence(
                kind,
                project_id,
                task_id,
                MemoryRevision::new(7),
                reference,
                CanonicalTraceReceiptBinding {
                    receipt: WriteReceiptRef {
                        receipt_id: ReceiptId::from_uuid(uuid::Uuid::from_u128(
                            0x1000 + u128::try_from(index).unwrap_or_default(),
                        )),
                        write_id: WriteId::from_uuid(uuid::Uuid::from_u128(
                            0x2000 + u128::try_from(index).unwrap_or_default(),
                        )),
                    },
                    command_kind: SemanticCommandKind::TaskContractWrite,
                    input_hash,
                    source_content_hash: blake3::hash(
                        format!("fixture-content:{index}").as_bytes(),
                    )
                    .to_hex()
                    .to_string(),
                },
                TaintClass::LocalVerified,
            ),
            "receipt evidence",
        ));
    }
    for kind in CanonicalTraceEvidenceKind::ALL
        .into_iter()
        .filter(|kind| !receipt_kinds.contains(kind))
    {
        evidence.push(must(
            TraceCompletenessService::derivation_evidence(
                kind,
                project_id,
                task_id,
                MemoryRevision::new(7),
                format!("{}:canonical", kind.as_str()),
                "fixture-derivation-v1".to_owned(),
                input_refs.clone(),
                input_hashes.clone(),
                TaintClass::LocalVerified,
            ),
            "derivation evidence",
        ));
    }
    must(
        TraceCompletenessService::build_canonical(CanonicalTraceCompletenessInput {
            project_id,
            task_id,
            source_task_revision: MemoryRevision::new(7),
            trace_ref: trace_ref.to_owned(),
            evidence,
        }),
        "canonical contract",
    )
}

fn replay_fixture(
    project_id: ProjectId,
    task_id: TaskId,
    role: ReplaySetRole,
    trace_ref: &str,
) -> (ReplaySealBundle, Vec<CanonicalTraceCompletenessContract>) {
    let contracts = ["a", "b"]
        .into_iter()
        .map(|suffix| canonical_contract(project_id, task_id, &format!("{trace_ref}:{suffix}")))
        .collect::<Vec<_>>();
    let cases = contracts
        .iter()
        .map(|contract| {
            must(
                ReplayCaseService::create(ReplayCaseInput {
                    project_id,
                    source_task_id: Some(task_id),
                    case_kind: ReplayCaseKind::Regression,
                    trace_contract_ref: contract.contract_id.clone(),
                    input_snapshot_refs: vec![format!("snapshot:{}", contract.trace_ref)],
                }),
                "canonical replay case",
            )
        })
        .collect::<Vec<_>>();
    let holdout = role == ReplaySetRole::Holdout;
    let set = ReplaySetService::create(ReplaySetInput {
        project_id,
        name: if holdout { "holdout" } else { "fixed" }.to_owned(),
        purpose: "M2 integrity test".to_owned(),
        cases: cases.iter().map(|case| case.replay_case_id).collect(),
        fixed: true,
        holdout,
        created_from_refs: contracts
            .iter()
            .map(|contract| contract.contract_id.clone())
            .collect(),
    });
    let snapshots = cases
        .iter()
        .map(|case| eliot_types::ReplayInputSnapshot {
            snapshot_id: format!("snapshot:{}", case.replay_case_id),
            replay_case_id: case.replay_case_id,
            context_packet_ref: Some("context:sealed".to_owned()),
            memory_refs: vec!["memory:sealed".to_owned()],
            skill_refs: Vec::new(),
            policy_refs: vec!["policy:baseline".to_owned()],
            artifact_refs: Vec::new(),
            created_at: OffsetDateTime::now_utc(),
        })
        .collect();
    let bundle = must(
        ReplaySealService::seal(ReplaySealInput {
            set,
            role,
            version: 1,
            evaluator_version: "v1".to_owned(),
            context_version: "context-v1".to_owned(),
            cases,
            snapshots,
        }),
        "seal replay set",
    );
    (bundle, contracts)
}

fn execute(
    bundle: &ReplaySealBundle,
    contracts: &[CanonicalTraceCompletenessContract],
    baseline_ref: &str,
    candidate_ref: &str,
) -> CanonicalReplayExecutionRecord {
    must(
        ReplayRunnerService::run_canonical(CanonicalReplayExecutionInput {
            sealed_set: bundle.set.clone(),
            cases: bundle.cases.clone(),
            snapshots: bundle.snapshots.clone(),
            trace_contracts: contracts.to_vec(),
            observations: canonical_observations(bundle, contracts),
            baseline_ref: baseline_ref.to_owned(),
            candidate_ref: candidate_ref.to_owned(),
            candidate_version: "candidate-v1".to_owned(),
            mutation_attempt: Some("apply policy mutation".to_owned()),
        }),
        "canonical replay",
    )
}

fn canonical_observations(
    bundle: &ReplaySealBundle,
    contracts: &[CanonicalTraceCompletenessContract],
) -> Vec<CanonicalReplayObservationEvidence> {
    bundle
        .cases
        .iter()
        .map(|case| {
            let contract = must(
                contracts
                    .iter()
                    .find(|contract| contract.contract_id == case.case.trace_contract_ref)
                    .ok_or("fixture trace contract is missing"),
                "fixture trace contract",
            );
            let snapshot = must(
                bundle
                    .snapshots
                    .iter()
                    .find(|snapshot| snapshot.snapshot.replay_case_id == case.case.replay_case_id)
                    .ok_or("fixture replay snapshot is missing"),
                "fixture replay snapshot",
            );
            CanonicalReplayObservationEvidence {
                replay_case_id: case.case.replay_case_id,
                snapshot_hash: snapshot.content_hash.clone(),
                evidence: contract.evidence.clone(),
            }
        })
        .collect()
}

#[test]
fn legacy_trace_strings_are_marked_unverified_and_canonical_evidence_is_tamper_evident() {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let legacy = TraceCompletenessService::build(TraceCompletenessInput {
        project_id,
        task_id: Some(task_id),
        trace_ref: "trace:legacy".to_owned(),
        present_refs: CanonicalTraceEvidenceKind::ALL
            .into_iter()
            .map(|kind| format!("{}:caller-value", kind.as_str()))
            .collect(),
    });
    assert!(legacy.replay_allowed);
    assert!(
        legacy
            .contract_id
            .starts_with("legacy-unverified-trace-contract:")
    );
    let case = must(
        ReplayCaseService::create(ReplayCaseInput {
            project_id,
            source_task_id: Some(task_id),
            case_kind: ReplayCaseKind::Regression,
            trace_contract_ref: legacy.contract_id.clone(),
            input_snapshot_refs: vec!["snapshot:legacy".to_owned()],
        }),
        "legacy replay case",
    );
    let set = ReplaySetService::create(ReplaySetInput {
        project_id,
        name: "legacy".to_owned(),
        purpose: "prove legacy execution is disabled".to_owned(),
        cases: vec![case.replay_case_id],
        fixed: true,
        holdout: false,
        created_from_refs: vec![legacy.contract_id.clone()],
    });
    let (run, _) = must(
        ReplayRunnerService::run_sealed(SealedReplayInput {
            project_id,
            set,
            cases: vec![case.clone()],
            trace_contracts: vec![legacy],
            observations: vec![ReplayCaseObservation {
                replay_case_id: case.replay_case_id,
                produced_refs: Vec::new(),
                denied_actions: Vec::new(),
                taint_preserved: true,
                duration_ms: 0,
            }],
            baseline_ref: "baseline".to_owned(),
            candidate_ref: "candidate".to_owned(),
            candidate_version: "v1".to_owned(),
            sealed_context_version: "context-v1".to_owned(),
            mutation_attempt: None,
        }),
        "legacy replay is rejected without panicking",
    );
    assert_eq!(run.status, ReplayRunStatus::BlockedMissingTrace);

    let mut contract = canonical_contract(project_id, task_id, "trace:canonical");
    assert!(contract.replay_allowed);
    contract.evidence[0].content_hash = "0".repeat(64);
    let rejected = TraceCompletenessService::build_canonical(CanonicalTraceCompletenessInput {
        project_id,
        task_id,
        source_task_revision: MemoryRevision::new(7),
        trace_ref: "trace:tampered".to_owned(),
        evidence: contract.evidence,
    });
    assert!(rejected.is_err());

    let mut receipt_only_contract = canonical_contract(project_id, task_id, "trace:receipt-only");
    receipt_only_contract.evidence[1].source = receipt_only_contract.evidence[0].source.clone();
    assert!(
        TraceCompletenessService::build_canonical(CanonicalTraceCompletenessInput {
            project_id,
            task_id,
            source_task_revision: MemoryRevision::new(7),
            trace_ref: "trace:receipt-only".to_owned(),
            evidence: receipt_only_contract.evidence,
        })
        .is_err()
    );
}

#[test]
fn sealed_replay_rejects_tampered_membership_and_derives_results() {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let (bundle, contracts) =
        replay_fixture(project_id, task_id, ReplaySetRole::Fixed, "trace:fixed");
    let execution = execute(&bundle, &contracts, "baseline", "candidate");
    let repeated = execute(&bundle, &contracts, "baseline", "candidate");
    assert_eq!(execution, repeated);
    assert_eq!(
        must(serde_json::to_vec(&execution), "serialize first execution"),
        must(
            serde_json::to_vec(&repeated),
            "serialize repeated execution"
        )
    );
    assert_eq!(
        execution.run.case_results[0].status,
        ReplayCaseStatus::Passed
    );
    assert!(execution.audit.authority_mutation_blocked);
    assert_eq!(execution.audit.mutation_attempts_blocked.len(), 1);

    let mut one_case_set = bundle.set.set.clone();
    one_case_set.cases.truncate(1);
    assert!(
        ReplaySealService::seal(ReplaySealInput {
            set: one_case_set,
            role: ReplaySetRole::Fixed,
            version: 2,
            evaluator_version: "v1".to_owned(),
            context_version: "context-v1".to_owned(),
            cases: vec![bundle.cases[0].case.clone()],
            snapshots: vec![bundle.snapshots[0].snapshot.clone()],
        })
        .is_err()
    );

    let mut tampered_cases = bundle.cases.clone();
    tampered_cases[0].content_hash = "f".repeat(64);
    let observations = canonical_observations(&bundle, &contracts);
    let rejected = ReplayRunnerService::run_canonical(CanonicalReplayExecutionInput {
        sealed_set: bundle.set,
        cases: tampered_cases,
        snapshots: bundle.snapshots.clone(),
        trace_contracts: contracts,
        observations,
        baseline_ref: "baseline".to_owned(),
        candidate_ref: "candidate".to_owned(),
        candidate_version: "candidate-v1".to_owned(),
        mutation_attempt: None,
    });
    assert!(rejected.is_err());
}

#[test]
fn sleep_materializes_all_five_candidate_only_artifact_types() {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let contract = canonical_contract(project_id, task_id, "trace:sleep");
    let bundle = must(
        SleepConsolidationService::run_with_artifacts(
            SleepRunInput {
                project_id,
                trigger: SleepTrigger::Manual,
                dry_run: false,
                input_traces: vec![contract.trace_ref.clone()],
            },
            &[contract],
            false,
        ),
        "sleep artifacts",
    );
    assert_eq!(bundle.artifacts.len(), 5);
    assert!(
        bundle
            .artifacts
            .iter()
            .all(|artifact| artifact.candidate_only)
    );
    let kinds = bundle
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_kind)
        .collect::<Vec<_>>();
    assert!(kinds.contains(&SleepCandidateArtifactKind::Procedure));
    assert!(kinds.contains(&SleepCandidateArtifactKind::ForgettingAction));
    assert!(kinds.contains(&SleepCandidateArtifactKind::Test));
    assert!(kinds.contains(&SleepCandidateArtifactKind::ReplayCase));
    assert!(kinds.contains(&SleepCandidateArtifactKind::Dream));
}

#[test]
fn meta_isolation_rejection_is_receiptable_and_policy_rolls_back_exactly() {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let (fixed, fixed_contract) = replay_fixture(
        project_id,
        task_id,
        ReplaySetRole::Fixed,
        "trace:fixed-meta",
    );
    let (holdout, holdout_contract) = replay_fixture(
        project_id,
        task_id,
        ReplaySetRole::Holdout,
        "trace:holdout-meta",
    );
    let baseline_payload = ExperimentalMetaPolicyPayload::ReplayThresholdV1 {
        policy: ReplayThresholdPolicyV1 {
            schema_version: "1".to_owned(),
            evaluator_version: "v1".to_owned(),
            minimum_pass_basis_points: 9_000,
            maximum_counter_regressions: 0,
        },
    };
    let candidate_payload = ExperimentalMetaPolicyPayload::ReplayThresholdV1 {
        policy: ReplayThresholdPolicyV1 {
            schema_version: "1".to_owned(),
            evaluator_version: "v1".to_owned(),
            minimum_pass_basis_points: 10_000,
            maximum_counter_regressions: 0,
        },
    };
    let baseline_hash = blake3::hash(&must(
        serde_json::to_vec(&baseline_payload),
        "serialize baseline policy",
    ))
    .to_hex()
    .to_string();
    let candidate_hash = blake3::hash(&must(
        serde_json::to_vec(&candidate_payload),
        "serialize candidate policy",
    ))
    .to_hex()
    .to_string();
    let fixed_baseline = execute(&fixed, &fixed_contract, &baseline_hash, &baseline_hash);
    let fixed_candidate = execute(&fixed, &fixed_contract, &baseline_hash, &candidate_hash);
    let holdout_baseline = execute(&holdout, &holdout_contract, &baseline_hash, &baseline_hash);
    let holdout_candidate = execute(&holdout, &holdout_contract, &baseline_hash, &candidate_hash);
    let threshold = ReplayThresholdPolicyV1 {
        schema_version: "1".to_owned(),
        evaluator_version: "v1".to_owned(),
        minimum_pass_basis_points: 10_000,
        maximum_counter_regressions: 0,
    };
    let base_input = CanonicalMetaExperimentInput {
        project_id,
        eval_run_id: eliot_types::EvalRunId::new_v7(),
        verdict_id: None,
        profile_id: "canonical-meta-v1".to_owned(),
        candidate_ref: candidate_hash.clone(),
        change_class: MetaCandidateChangeClass::ForgettingThreshold,
        changed_variables: vec!["memory_activation_window".to_owned()],
        coupled_change_rationale: None,
        baseline_policy_hash: baseline_hash.clone(),
        candidate_policy_hash: candidate_hash.clone(),
        fixed_set: fixed.set.clone(),
        holdout_set: holdout.set.clone(),
        fixed_baseline,
        fixed_candidate,
        holdout_baseline,
        holdout_candidate,
        threshold: threshold.clone(),
        attempted_fence: None,
    };
    let mut isolated_attempt = base_input.clone();
    isolated_attempt.attempted_fence = Some(MetaIsolationFence {
        evaluator_version: "tampered".to_owned(),
        evaluator_hash: "0".repeat(64),
        threshold_version: "1".to_owned(),
        threshold_hash: "0".repeat(64),
        fixed_replay_set_hash: fixed.set.sealed_hash.clone(),
        holdout_replay_set_hash: holdout.set.sealed_hash.clone(),
    });
    let rejected = must(
        MetaHarnessService::assess_canonical(isolated_attempt),
        "rejection record",
    );
    assert_eq!(
        rejected.records.experiment.decision,
        MetaExperimentDecision::Rejected
    );
    assert!(rejected.records.isolation_rejection.is_some());

    let assessment = must(
        MetaHarnessService::assess_canonical(base_input),
        "meta assessment",
    );
    assert!(assessment.eligible_for_promotion);
    exercise_policy_roundtrip(project_id, &assessment, baseline_payload, candidate_payload);
}

fn exercise_policy_roundtrip(
    project_id: ProjectId,
    assessment: &CanonicalMetaExperimentAssessment,
    baseline_payload: ExperimentalMetaPolicyPayload,
    candidate_payload: ExperimentalMetaPolicyPayload,
) {
    let candidate = must(
        MetaPolicyExecutor::stage(
            project_id,
            assessment
                .records
                .experiment
                .harness_experiment_record_id
                .to_string(),
            baseline_payload,
            candidate_payload,
        ),
        "stage policy",
    );
    let promote_hash = must(
        MetaPolicyExecutor::exact_action_hash(&candidate, MetaPolicyExecutionAction::Promote),
        "promote hash",
    );
    let authorization = MetaPolicyAuthorization {
        operator_command_ref: "governor:exact-action".to_owned(),
        expected_action_hash: promote_hash.clone(),
        exact_action_hash: promote_hash,
    };
    let (promoted, promotion_receipt) = must(
        MetaPolicyExecutor::promote(&candidate, assessment, &authorization),
        "promote",
    );
    let rollback_hash = must(
        MetaPolicyExecutor::exact_action_hash(&promoted, MetaPolicyExecutionAction::Rollback),
        "rollback hash",
    );
    let rollback_authorization = MetaPolicyAuthorization {
        operator_command_ref: "governor:exact-rollback".to_owned(),
        expected_action_hash: rollback_hash.clone(),
        exact_action_hash: rollback_hash,
    };
    let (_, rollback_receipt) = must(
        MetaPolicyExecutor::rollback(&promoted, &promotion_receipt, &rollback_authorization),
        "rollback",
    );
    assert_eq!(rollback_receipt.after_hash, candidate.baseline_hash);
    assert_eq!(rollback_receipt.active_policy, candidate.baseline);

    let unsupported = MetaPolicyExecutor::stage(
        project_id,
        "experiment:unsupported".to_owned(),
        candidate_payload_for_unsupported_test(),
        ExperimentalMetaPolicyPayload::Unsupported {
            kind: "arbitrary-executor".to_owned(),
            payload: serde_json::json!({"unsafe": true}),
        },
    );
    assert!(unsupported.is_err());
}

fn candidate_payload_for_unsupported_test() -> ExperimentalMetaPolicyPayload {
    ExperimentalMetaPolicyPayload::ReplayThresholdV1 {
        policy: ReplayThresholdPolicyV1 {
            schema_version: "1".to_owned(),
            evaluator_version: "v1".to_owned(),
            minimum_pass_basis_points: 10_000,
            maximum_counter_regressions: 0,
        },
    }
}
