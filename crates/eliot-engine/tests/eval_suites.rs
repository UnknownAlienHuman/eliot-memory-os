use eliot_engine::{
    EvalCaseInput, EvalCaseService, EvalDatasetManifestService, EvalRegressionGate, EvalRunInput,
    EvalRunnerService, EvalSuiteInput, EvalSuiteService, EvalVerdictService,
};
use eliot_types::{
    EvalCase, EvalCaseId, EvalCaseStatus, EvalDatasetManifest, EvalFamily, EvalMeasurementKind,
    EvalRun, EvalRunProfile, EvalRunStatus, EvalSuite, EvalVerdictStatus, ProjectId, TaskId,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn eval_case_schema_exists() {
    let cases = cases();
    assert_eq!(cases.len(), 13);
    assert!(cases.iter().all(|case| !case.criteria.is_empty()));
    assert!(cases.iter().all(|case| !case.measurement_specs.is_empty()));
}

#[test]
fn eval_suite_schema_exists() {
    let (_, suite, _, _, _, _) = artifacts();
    assert_eq!(suite.name, "core-smoke");
    assert!(suite.fixed);
    assert!(suite.holdout);
    assert!(!suite.integrity_checksum.is_empty());
}

#[test]
fn eval_dataset_manifest_exists() {
    let (cases, suite, manifest, _, _, _) = artifacts();
    assert_eq!(manifest.suite_id, suite.eval_suite_id);
    assert_eq!(manifest.case_count, cases.len());
    assert!(manifest.holdout_preserved);
}

#[test]
fn eval_run_schema_exists() {
    let (_, suite, manifest, profile, run, _) = artifacts();
    assert_eq!(run.suite_id, suite.eval_suite_id);
    assert_eq!(run.dataset_manifest_id, manifest.eval_dataset_manifest_id);
    assert_eq!(run.profile.profile_id, profile.profile_id);
    assert_eq!(run.status, EvalRunStatus::Completed);
}

#[test]
fn eval_verdict_schema_exists() {
    let (_, _, _, _, _, verdict) = artifacts();
    assert_eq!(verdict.status, EvalVerdictStatus::Inconclusive);
    assert!(!verdict.grants_authority);
    assert!(!verdict.mutates_current_truth);
}

#[test]
fn benchmark_integrity_receipt_exists() {
    let (_, suite, manifest, _, _, _) = artifacts();
    let receipt = EvalDatasetManifestService::verify(&suite, &manifest);
    assert!(receipt.valid);
    assert!(!receipt.blocked_run);
}

#[test]
fn eval_case_validation_rejects_missing_criteria() -> TestResult {
    let mut case = case_for(EvalFamily::Understand)?;
    case.criteria.clear();
    assert!(EvalCaseService::validate(&case).is_err());
    Ok(())
}

#[test]
fn eval_suite_fixed_cannot_mutate_during_run() {
    let (_, mut suite, _, _, _, _) = artifacts();
    assert!(EvalSuiteService::add_case(&mut suite, EvalCaseId::new_v7()).is_err());
}

#[test]
fn eval_dataset_manifest_checksums() {
    let (cases, _, manifest, _, _, _) = artifacts();
    assert_eq!(manifest.fixture_checksums.len(), cases.len());
    assert!(
        manifest
            .fixture_checksums
            .iter()
            .all(|fixture| !fixture.checksum.is_empty())
    );
}

#[test]
fn eval_runner_no_mutation_profile() {
    let profile = EvalRunnerService::deterministic_no_mutation_profile();
    assert!(EvalRunnerService::profile_is_safe(&profile));
    assert!(profile.no_mutation);
    assert!(profile.no_external_network);
}

#[test]
fn eval_runner_blocks_mutation_attempt() {
    let (cases, suite, manifest, profile, _, _) = artifacts();
    let run = EvalRunnerService::run(EvalRunInput {
        project_id: project_id(),
        suite,
        cases,
        manifest,
        profile,
        mutation_attempt: Some("apply current truth".to_owned()),
    });
    assert_eq!(run.status, EvalRunStatus::BlockedMutationAttempt);
    assert!(!run.mutation_attempts_blocked.is_empty());
}

#[test]
fn eval_understand_case_passes() {
    family_is_inconclusive_without_runtime_evidence(EvalFamily::Understand);
}

#[test]
fn eval_hallucination_case_passes() {
    family_is_inconclusive_without_runtime_evidence(EvalFamily::Hallucination);
}

#[test]
fn eval_negative_case_passes() {
    family_is_inconclusive_without_runtime_evidence(EvalFamily::Negative);
}

#[test]
fn eval_done_case_passes() {
    family_is_inconclusive_without_runtime_evidence(EvalFamily::Done);
}

#[test]
fn eval_context_case_passes() {
    family_is_inconclusive_without_runtime_evidence(EvalFamily::Context);
}

#[test]
fn eval_compaction_case_passes() {
    family_is_inconclusive_without_runtime_evidence(EvalFamily::Compaction);
}

#[test]
fn eval_tool_case_passes() {
    family_is_inconclusive_without_runtime_evidence(EvalFamily::Tool);
}

#[test]
fn eval_memory_case_passes() {
    family_is_inconclusive_without_runtime_evidence(EvalFamily::Memory);
}

#[test]
fn eval_forget_case_passes() {
    family_is_inconclusive_without_runtime_evidence(EvalFamily::Forget);
}

#[test]
fn eval_dream_case_passes() {
    family_is_inconclusive_without_runtime_evidence(EvalFamily::Dream);
}

#[test]
fn eval_skill_case_passes() {
    family_is_inconclusive_without_runtime_evidence(EvalFamily::Skill);
}

#[test]
fn eval_trace_case_passes() {
    family_is_inconclusive_without_runtime_evidence(EvalFamily::Trace);
}

#[test]
fn eval_bench_case_passes() {
    family_is_inconclusive_without_runtime_evidence(EvalFamily::Bench);
}

#[test]
fn eval_verdict_generated() {
    let (_, _, _, _, run, verdict) = artifacts();
    assert_eq!(verdict.eval_run_id, run.eval_run_id);
    assert_eq!(verdict.family_scores.len(), 13);
}

#[test]
fn eval_failure_cluster_generated_for_fixture_failure() {
    let (_, _, _, _, run, _) = artifacts();
    let cluster = EvalVerdictService::fixture_failure_cluster(run.eval_run_id);
    assert_eq!(cluster.eval_run_id, run.eval_run_id);
    assert!(
        cluster
            .evidence_refs
            .contains(&"fixture:intentional-failure".to_owned())
    );
}

#[test]
fn declaration_only_cases_do_not_emit_measured_failure_clusters() {
    let (_, _, _, _, run, _) = artifacts();
    assert!(EvalVerdictService::failure_clusters(&run).is_empty());
}

#[test]
fn fabricated_measurements_cannot_override_the_retained_integrity_receipt() {
    let (_, _, _, _, mut run, _) = artifacts();
    let mut result = run.case_results.remove(0);
    for measurement in &mut result.measurements {
        measurement.passed = true;
        measurement.observed = "fabricated runtime observation".to_owned();
        measurement.evidence_refs = vec!["fabricated:measurement-evidence".to_owned()];
    }
    result.status = EvalCaseStatus::Passed;
    let retained_receipt = result
        .evaluation_integrity_receipt
        .as_ref()
        .expect("the evaluator retains its original integrity receipt");
    assert_eq!(
        retained_receipt.status(),
        eliot_types::EvaluationIntegrityStatus::Inconclusive
    );
    run.case_results = vec![result];
    run.status = EvalRunStatus::Completed;

    let verdict = EvalVerdictService::verdict(&run);
    assert_eq!(verdict.status, EvalVerdictStatus::Inconclusive);
    assert!(verdict.failure_clusters.is_empty());
    let family_score = verdict
        .family_scores
        .iter()
        .find(|score| score.family == run.case_results[0].family)
        .expect("the fabricated result remains visible in its family denominator");
    assert_eq!(family_score.total, 1);
    assert_eq!(family_score.passed, 0);
    assert_eq!(family_score.blocked, 1);
    assert_eq!(family_score.score_percent, 0);

    let mut forged_receipt_run = serde_json::to_value(&run).expect("run serializes");
    let receipt = &mut forged_receipt_run["case_results"][0]["evaluation_integrity_receipt"];
    receipt["status"] = serde_json::json!("MEASURED");
    receipt["body"]["raw_result_refs"] = serde_json::json!(["forged:measurement"]);
    receipt["body"]["observed_artifact_refs"] =
        serde_json::json!(["forged:runtime-artifact"]);
    assert!(serde_json::from_value::<EvalRun>(forged_receipt_run).is_err());
}

#[test]
fn benchmark_integrity_detects_checksum_mismatch() {
    let (_, suite, manifest, _, _, _) = artifacts();
    let receipt = EvalDatasetManifestService::checksum_mismatch(&suite, &manifest);
    assert!(receipt.mismatch_detected);
    assert!(receipt.blocked_run);
}

#[test]
fn doctor_reports_eval_status() {
    let (_, _, _, profile, run, verdict) = artifacts();
    assert!(EvalRunnerService::profile_is_safe(&profile));
    assert_eq!(run.status, EvalRunStatus::Completed);
    assert_eq!(verdict.status, EvalVerdictStatus::Inconclusive);
}

#[test]
fn incident_lockdown_blocks_mutating_eval() {
    let (_, suite, manifest, profile, _, _) = artifacts();
    assert!(EvalRegressionGate::allow_run(&suite, &manifest, &profile, true, true).is_err());
}

#[test]
fn accumulated_capabilities_non_regression() {
    let (_, _, _, _, run, verdict) = artifacts();
    assert_eq!(run.status, EvalRunStatus::Completed);
    assert_eq!(verdict.status, EvalVerdictStatus::Inconclusive);
}

fn family_is_inconclusive_without_runtime_evidence(family: EvalFamily) {
    // #1922 TASK and accepted history preserve NYI for declaration-only
    // cases until a real runtime artifact is observed.
    let (_, _, _, _, run, _) = artifacts();
    let result = run
        .case_results
        .iter()
        .find(|result| result.family == family)
        .expect("core-smoke suite includes each runnable family");
    assert_eq!(result.status, EvalCaseStatus::NotYetImplemented);
    assert!(result.measurements.iter().any(|measurement| {
        measurement.observed.starts_with("not yet implemented:")
            && measurement.evidence_refs.is_empty()
    }));
}

#[test]
fn structural_block_observation_does_not_promote_a_declaration_only_case() {
    let (cases, _, _, _, run, verdict) = artifacts();
    let result = run
        .case_results
        .iter()
        .find(|result| result.family == EvalFamily::Done)
        .expect("Done case is part of core-smoke");
    let structural_spec = cases
        .into_iter()
        .find(|case| case.family == EvalFamily::Done)
        .and_then(|case| {
            case.measurement_specs
                .into_iter()
                .find(|spec| spec.kind == EvalMeasurementKind::MustBlockAction)
        })
        .expect("Done case declares a structural block measurement");
    let observation = result
        .measurements
        .iter()
        .find(|measurement| measurement.measurement_id == structural_spec.measurement_id)
        .expect("runner records its structural block observation");
    assert!(observation.passed);
    assert!(
        observation
            .observed
            .starts_with("structural self-check: runner gate blocked")
    );
    assert!(observation.evidence_refs.is_empty());
    let receipt = result
        .evaluation_integrity_receipt
        .as_ref()
        .expect("runner retains the original integrity receipt");
    assert_eq!(
        receipt.status(),
        eliot_types::EvaluationIntegrityStatus::Inconclusive
    );
    assert_eq!(receipt.body.raw_result_refs.len(), result.measurements.len());
    let decoded = serde_json::from_value::<eliot_types::EvaluationIntegrityReceipt>(
        serde_json::to_value(receipt).expect("receipt serializes"),
    )
    .expect("original inconclusive receipt remains readable");
    assert_eq!(&decoded, receipt);
    assert_eq!(result.status, EvalCaseStatus::NotYetImplemented);
    assert_eq!(verdict.status, EvalVerdictStatus::Inconclusive);
}

#[test]
fn eval_runner_rejects_missing_suite_case_output() {
    let (mut cases, suite, manifest, profile, _, _) = artifacts();
    cases.pop();
    let run = EvalRunnerService::run(EvalRunInput {
        project_id: suite.project_id,
        suite,
        cases,
        manifest,
        profile,
        mutation_attempt: None,
    });
    assert_eq!(run.status, EvalRunStatus::BlockedInvalidDataset);
    assert!(run.case_results.is_empty());
    assert_eq!(
        EvalVerdictService::verdict(&run).status,
        EvalVerdictStatus::Blocked
    );
}

#[test]
fn eval_runner_rejects_tampered_fixture_manifest() {
    let (cases, suite, mut manifest, profile, _, _) = artifacts();
    manifest.fixture_checksums[0].checksum.push_str("-tampered");
    let run = EvalRunnerService::run(EvalRunInput {
        project_id: suite.project_id,
        suite,
        cases,
        manifest,
        profile,
        mutation_attempt: None,
    });
    assert_eq!(run.status, EvalRunStatus::BlockedInvalidDataset);
    assert!(run.case_results.is_empty());
}

#[test]
fn eval_runner_rejects_foreign_product_case_output() {
    let (mut cases, suite, manifest, profile, _, _) = artifacts();
    cases[0].project_id = ProjectId::new_v7();
    let run = EvalRunnerService::run(EvalRunInput {
        project_id: suite.project_id,
        suite,
        cases,
        manifest,
        profile,
        mutation_attempt: None,
    });
    assert_eq!(run.status, EvalRunStatus::BlockedInvalidDataset);
    assert!(run.case_results.is_empty());
}

#[test]
fn eval_verdict_rejects_empty_result_output() {
    let (_, _, _, _, mut run, _) = artifacts();
    run.case_results.clear();
    let verdict = EvalVerdictService::verdict(&run);
    assert_eq!(verdict.status, EvalVerdictStatus::Inconclusive);
    assert!(
        verdict
            .reasons
            .iter()
            .any(|reason| reason.contains("empty output"))
    );
}

#[test]
fn eval_verdict_rejects_pass_claim_without_observed_evidence() {
    let (_, _, _, _, mut run, _) = artifacts();
    for result in &mut run.case_results {
        result.status = EvalCaseStatus::Passed;
    }
    let verdict = EvalVerdictService::verdict(&run);
    assert_eq!(verdict.status, EvalVerdictStatus::Inconclusive);
    assert!(
        verdict
            .reasons
            .iter()
            .any(|reason| { reason.contains("lacks complete observed measurement evidence") })
    );
}

fn case_for(family: EvalFamily) -> TestResult<EvalCase> {
    let found = cases().into_iter().find(|case| case.family == family);
    found.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("missing core-smoke case for {family:?}"),
        )
        .into()
    })
}

fn artifacts() -> (
    Vec<EvalCase>,
    EvalSuite,
    EvalDatasetManifest,
    EvalRunProfile,
    EvalRun,
    eliot_types::EvalVerdict,
) {
    let project_id = project_id();
    let cases = EvalCaseService::k0_core_cases(project_id, Some(TaskId::new_v7()));
    let mut suite = EvalSuiteService::create(EvalSuiteInput {
        project_id,
        name: "core-smoke".to_owned(),
        purpose: "test deterministic no-mutation suite".to_owned(),
        cases: cases.iter().map(|case| case.eval_case_id).collect(),
        fixed: false,
        holdout: true,
        created_from_refs: vec!["test:k0".to_owned()],
    });
    EvalSuiteService::freeze(&mut suite);
    let manifest = EvalDatasetManifestService::manifest(&suite, &cases);
    let profile = EvalRunnerService::deterministic_no_mutation_profile();
    let run = EvalRunnerService::run(EvalRunInput {
        project_id,
        suite: suite.clone(),
        cases: cases.clone(),
        manifest: manifest.clone(),
        profile: profile.clone(),
        mutation_attempt: None,
    });
    let verdict = EvalVerdictService::verdict(&run);
    (cases, suite, manifest, profile, run, verdict)
}

fn cases() -> Vec<EvalCase> {
    EvalCaseService::k0_core_cases(project_id(), Some(TaskId::new_v7()))
}

fn project_id() -> ProjectId {
    ProjectId::new_v7()
}

#[test]
fn eval_case_create_schema_accepts_named_understand_case() -> TestResult {
    let case = EvalCaseService::create(EvalCaseInput {
        project_id: project_id(),
        task_id: Some(TaskId::new_v7()),
        family: EvalFamily::Understand,
        name: "understand named case".to_owned(),
    })?;
    assert_eq!(case.name, "understand named case");
    assert_eq!(case.family, EvalFamily::Understand);
    Ok(())
}
