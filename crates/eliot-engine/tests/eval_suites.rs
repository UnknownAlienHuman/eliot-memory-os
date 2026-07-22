use eliot_engine::{
    EvalCaseInput, EvalCaseService, EvalDatasetManifestService, EvalRegressionGate, EvalRunInput,
    EvalRunnerService, EvalSuiteInput, EvalSuiteService, EvalVerdictService,
};
use eliot_types::{
    EvalCase, EvalCaseId, EvalCaseStatus, EvalDatasetManifest, EvalFamily, EvalRun, EvalRunProfile,
    EvalRunStatus, EvalSuite, EvalVerdictStatus, ProjectId, TaskId,
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
    assert_eq!(verdict.status, EvalVerdictStatus::Pass);
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
    family_passes(EvalFamily::Understand);
}

#[test]
fn eval_hallucination_case_passes() {
    family_passes(EvalFamily::Hallucination);
}

#[test]
fn eval_negative_case_passes() {
    family_passes(EvalFamily::Negative);
}

#[test]
fn eval_done_case_passes() {
    family_passes(EvalFamily::Done);
}

#[test]
fn eval_context_case_passes() {
    family_passes(EvalFamily::Context);
}

#[test]
fn eval_compaction_case_passes() {
    family_passes(EvalFamily::Compaction);
}

#[test]
fn eval_tool_case_passes() {
    family_passes(EvalFamily::Tool);
}

#[test]
fn eval_memory_case_passes() {
    family_passes(EvalFamily::Memory);
}

#[test]
fn eval_forget_case_passes() {
    family_passes(EvalFamily::Forget);
}

#[test]
fn eval_dream_case_passes() {
    family_passes(EvalFamily::Dream);
}

#[test]
fn eval_skill_case_passes() {
    family_passes(EvalFamily::Skill);
}

#[test]
fn eval_trace_case_passes() {
    family_passes(EvalFamily::Trace);
}

#[test]
fn eval_bench_case_passes() {
    family_passes(EvalFamily::Bench);
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
    assert_eq!(verdict.status, EvalVerdictStatus::Pass);
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
    assert_eq!(verdict.status, EvalVerdictStatus::Pass);
}

fn family_passes(family: EvalFamily) {
    let (_, _, _, _, run, _) = artifacts();
    assert!(
        run.case_results
            .iter()
            .any(|result| result.family == family && result.status == EvalCaseStatus::Passed)
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
    let cases = cases();
    let mut suite = EvalSuiteService::create(EvalSuiteInput {
        project_id: project_id(),
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
        project_id: project_id(),
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
