use eliot_engine::{
    EvalBaselineService, EvalCaseService, EvalComparisonService, EvalCoverageService,
    EvalDatasetManifestService, EvalDoctorIntegration, EvalFixtureStabilityService,
    EvalGateProfileService, EvalRegressionGateService, EvalRunInput, EvalRunnerService,
    EvalSuiteInput, EvalSuiteService, EvalTrendService, EvalVerdictService, runnable_k0_families,
};
use eliot_types::{
    BenchmarkIntegrityReceipt, EvalBaseline, EvalCase, EvalComparisonVerdict, EvalCoverageMatrix,
    EvalCoverageStatus, EvalFamily, EvalGateDecisionKind, EvalRegressionGateProfile, EvalRun,
    EvalRunStatus, EvalSuite, EvalTrendDirection, EvalVerdictStatus, ProjectId, TaskId,
};

#[test]
fn coverage_matrix_generated() {
    let artifacts = artifacts();
    let coverage = coverage(&artifacts);
    assert!(!coverage.matrix_id.is_empty());
    assert_eq!(coverage.family_coverage.len(), 16);
}

#[test]
fn coverage_matrix_maps_families() {
    let artifacts = artifacts();
    let coverage = coverage(&artifacts);
    for family in runnable_k0_families() {
        assert!(
            coverage
                .family_coverage
                .iter()
                .any(|entry| entry.family == *family && entry.case_count > 0)
        );
    }
}

#[test]
fn coverage_matrix_maps_components() {
    let artifacts = artifacts();
    let coverage = coverage(&artifacts);
    for component in ["MemoryCore", "CodeCortex", "EvalHarness"] {
        assert!(
            coverage
                .component_coverage
                .iter()
                .any(|entry| entry.component == component)
        );
    }
}

#[test]
fn coverage_matrix_marks_placeholder_families_honestly() {
    let artifacts = artifacts();
    let coverage = coverage(&artifacts);
    for family in [EvalFamily::Ale, EvalFamily::Provider, EvalFamily::Future] {
        assert!(coverage.family_coverage.iter().any(|entry| {
            entry.family == family
                && entry.case_count == 0
                && entry.coverage_status == EvalCoverageStatus::PlaceholderOnly
        }));
    }
}

#[test]
fn baseline_created_from_passing_fixed_suite() {
    let artifacts = artifacts();
    let baseline = baseline(&artifacts);
    assert_eq!(baseline.overall_status, EvalVerdictStatus::Pass);
    assert_eq!(baseline.eval_run_id, artifacts.run.eval_run_id.to_string());
}

#[test]
fn baseline_rejects_failed_run() {
    let artifacts = artifacts();
    let failed =
        EvalComparisonService::run_with_failed_family(&artifacts.run, EvalFamily::Understand);
    let verdict = EvalVerdictService::verdict(&failed);
    assert!(
        EvalBaselineService::create(
            &artifacts.suite,
            &artifacts.manifest,
            &artifacts.integrity,
            &failed,
            &verdict,
            "test-git",
            "test",
        )
        .is_err()
    );
}

#[test]
fn baseline_requires_benchmark_integrity() {
    let artifacts = artifacts();
    let mismatch =
        EvalDatasetManifestService::checksum_mismatch(&artifacts.suite, &artifacts.manifest);
    assert!(
        EvalBaselineService::create(
            &artifacts.suite,
            &artifacts.manifest,
            &mismatch,
            &artifacts.run,
            &artifacts.verdict,
            "test-git",
            "test",
        )
        .is_err()
    );
}

#[test]
fn candidate_comparison_generated() {
    let artifacts = artifacts();
    let comparison = clean_comparison(&artifacts);
    assert_eq!(comparison.verdict, EvalComparisonVerdict::Equivalent);
    assert_eq!(
        comparison.candidate_run_id,
        artifacts.run.eval_run_id.to_string()
    );
}

#[test]
fn comparison_detects_new_failure() {
    let artifacts = artifacts();
    let baseline = baseline(&artifacts);
    let failed =
        EvalComparisonService::run_with_failed_family(&artifacts.run, EvalFamily::Understand);
    let comparison =
        EvalComparisonService::compare(&artifacts.suite, &baseline, &failed, "test-git");
    assert!(!comparison.newly_failed_cases.is_empty());
    assert_eq!(comparison.verdict, EvalComparisonVerdict::RegressedCritical);
}

#[test]
fn comparison_detects_new_pass() {
    let artifacts = artifacts();
    let failed = EvalComparisonService::run_with_failed_family(&artifacts.run, EvalFamily::Context);
    let failed_verdict = EvalVerdictService::verdict(&failed);
    let diagnostic_baseline = EvalBaselineService::create_diagnostic(
        &artifacts.suite,
        &artifacts.manifest,
        &failed,
        &failed_verdict,
        "test-git",
    );
    let comparison = EvalComparisonService::compare(
        &artifacts.suite,
        &diagnostic_baseline,
        &artifacts.run,
        "test-git",
    );
    assert!(!comparison.newly_passing_cases.is_empty());
}

#[test]
fn comparison_reports_family_delta() {
    let artifacts = artifacts();
    let baseline = baseline(&artifacts);
    let failed = EvalComparisonService::run_with_failed_family(&artifacts.run, EvalFamily::Bench);
    let comparison =
        EvalComparisonService::compare(&artifacts.suite, &baseline, &failed, "test-git");
    assert!(
        comparison
            .family_deltas
            .iter()
            .any(|delta| { delta.family == EvalFamily::Bench && delta.delta < 0.0 })
    );
}

#[test]
fn gate_profiles_created() {
    let profiles = EvalGateProfileService::built_in_profiles();
    for profile_id in [
        "phase-minimal",
        "phase-standard",
        "provider-integration",
        "production-release",
    ] {
        assert!(
            profiles
                .iter()
                .any(|profile| profile.profile_id == profile_id)
        );
    }
}

#[test]
fn phase_minimal_gate_passes() {
    let artifacts = artifacts();
    let profile = profile("phase-minimal");
    let comparison = clean_comparison(&artifacts);
    let decision =
        EvalRegressionGateService::evaluate_comparison(&profile, &comparison, &artifacts.integrity);
    assert_eq!(decision.decision, EvalGateDecisionKind::Allow);
}

#[test]
fn phase_minimal_gate_blocks_critical_regression_fixture() {
    let artifacts = artifacts();
    let profile = profile("phase-minimal");
    let baseline = baseline(&artifacts);
    let failed =
        EvalComparisonService::run_with_failed_family(&artifacts.run, EvalFamily::Understand);
    let comparison =
        EvalComparisonService::compare(&artifacts.suite, &baseline, &failed, "test-git");
    let decision =
        EvalRegressionGateService::evaluate_comparison(&profile, &comparison, &artifacts.integrity);
    assert_eq!(decision.decision, EvalGateDecisionKind::Block);
}

#[test]
fn phase_standard_gate_blocks_new_required_failure() {
    let artifacts = artifacts();
    let profile = profile("phase-standard");
    let baseline = baseline(&artifacts);
    let failed = EvalComparisonService::run_with_failed_family(&artifacts.run, EvalFamily::Memory);
    let comparison =
        EvalComparisonService::compare(&artifacts.suite, &baseline, &failed, "test-git");
    let decision =
        EvalRegressionGateService::evaluate_comparison(&profile, &comparison, &artifacts.integrity);
    assert_eq!(decision.decision, EvalGateDecisionKind::Block);
}

#[test]
fn provider_integration_gate_requires_taint_tool_coverage() {
    let artifacts = artifacts();
    let profile = profile("provider-integration");
    let baseline = baseline(&artifacts);
    let failed = EvalComparisonService::run_with_failed_family(&artifacts.run, EvalFamily::Tool);
    let comparison =
        EvalComparisonService::compare(&artifacts.suite, &baseline, &failed, "test-git");
    let decision =
        EvalRegressionGateService::evaluate_comparison(&profile, &comparison, &artifacts.integrity);
    assert_eq!(decision.decision, EvalGateDecisionKind::Block);
}

#[test]
fn production_release_gate_requires_bench_done_trace() {
    let artifacts = artifacts();
    let profile = profile("production-release");
    let baseline = baseline(&artifacts);
    let failed = EvalComparisonService::run_with_failed_family(&artifacts.run, EvalFamily::Done);
    let comparison =
        EvalComparisonService::compare(&artifacts.suite, &baseline, &failed, "test-git");
    let decision =
        EvalRegressionGateService::evaluate_comparison(&profile, &comparison, &artifacts.integrity);
    assert_eq!(decision.decision, EvalGateDecisionKind::Block);
}

#[test]
fn benchmark_integrity_required_by_gate() {
    let artifacts = artifacts();
    let profile = profile("phase-minimal");
    let comparison = clean_comparison(&artifacts);
    let mismatch =
        EvalDatasetManifestService::checksum_mismatch(&artifacts.suite, &artifacts.manifest);
    let decision = EvalRegressionGateService::evaluate_comparison(&profile, &comparison, &mismatch);
    assert_eq!(
        decision.decision,
        EvalGateDecisionKind::RequireBenchmarkRepair
    );
}

#[test]
fn trend_report_generated() {
    let artifacts = artifacts();
    let trend = EvalTrendService::trend(
        &artifacts.suite,
        &[artifacts.run.clone(), artifacts.run.clone()],
    );
    assert!(!trend.trend_report_id.is_empty());
    assert!(!trend.family_trends.is_empty());
}

#[test]
fn trend_detects_degrading_family_fixture() {
    let artifacts = artifacts();
    let failed =
        EvalComparisonService::run_with_failed_family(&artifacts.run, EvalFamily::Understand);
    let trend = EvalTrendService::trend(&artifacts.suite, &[artifacts.run.clone(), failed]);
    assert!(trend.family_trends.iter().any(|family| {
        family.family == EvalFamily::Understand && family.direction == EvalTrendDirection::Degrading
    }));
}

#[test]
fn fixture_stability_report_generated() {
    let artifacts = artifacts();
    let report = EvalFixtureStabilityService::report(
        &artifacts.suite,
        &[artifacts.run.clone(), artifacts.run.clone()],
    );
    assert!(!report.report_id.is_empty());
    assert!(!report.stable_cases.is_empty());
}

#[test]
fn fixture_stability_detects_flaky_case_fixture() {
    let artifacts = artifacts();
    let failed = EvalComparisonService::run_with_failed_family(&artifacts.run, EvalFamily::Context);
    let report =
        EvalFixtureStabilityService::report(&artifacts.suite, &[artifacts.run.clone(), failed]);
    assert!(!report.flaky_cases.is_empty());
}

#[test]
fn doctor_reports_eval_status() {
    let artifacts = artifacts();
    let coverage = coverage(&artifacts);
    let baseline = baseline(&artifacts);
    let profile = profile("phase-minimal");
    let comparison = clean_comparison(&artifacts);
    let decision =
        EvalRegressionGateService::evaluate_comparison(&profile, &comparison, &artifacts.integrity);
    let trend = EvalTrendService::trend(
        &artifacts.suite,
        &[artifacts.run.clone(), artifacts.run.clone()],
    );
    let stability = EvalFixtureStabilityService::report(
        &artifacts.suite,
        &[artifacts.run.clone(), artifacts.run.clone()],
    );
    let status = EvalDoctorIntegration::status(
        Some(&baseline),
        Some(&decision),
        &coverage,
        Some(&trend),
        Some(&stability),
        &artifacts.integrity,
    );
    assert_eq!(
        status.get("component").and_then(|value| value.as_str()),
        Some("eval_doctor_status")
    );
}

#[test]
fn incident_lockdown_blocks_baseline_mutation() {
    assert!(EvalRegressionGateService::incident_lockdown_blocks_baseline_mutation(true));
}

#[test]
fn incident_lockdown_blocks_suite_mutation() {
    assert!(EvalRegressionGateService::incident_lockdown_blocks_suite_mutation(true));
}

#[test]
fn phase_b_c_d_e_f0_f1_f2_f3_g0_g1_h0_i0_i1_i2_j0_k0_non_regression() {
    let artifacts = artifacts();
    assert_eq!(artifacts.run.status, EvalRunStatus::Completed);
    assert_eq!(artifacts.verdict.status, EvalVerdictStatus::Pass);
}

struct Artifacts {
    cases: Vec<EvalCase>,
    suite: EvalSuite,
    manifest: eliot_types::EvalDatasetManifest,
    integrity: BenchmarkIntegrityReceipt,
    run: EvalRun,
    verdict: eliot_types::EvalVerdict,
}

fn artifacts() -> Artifacts {
    let project_id = ProjectId::new_v7();
    let cases = EvalCaseService::k0_core_cases(project_id, Some(TaskId::new_v7()));
    let mut suite = EvalSuiteService::create(EvalSuiteInput {
        project_id,
        name: "k0-core-smoke".to_owned(),
        purpose: "test deterministic no-mutation suite".to_owned(),
        cases: cases.iter().map(|case| case.eval_case_id).collect(),
        fixed: false,
        holdout: true,
        created_from_refs: vec!["test:k1".to_owned()],
    });
    EvalSuiteService::freeze(&mut suite);
    let manifest = EvalDatasetManifestService::manifest(&suite, &cases);
    let integrity = EvalDatasetManifestService::verify(&suite, &manifest);
    let profile = EvalRunnerService::deterministic_no_mutation_profile();
    let run = EvalRunnerService::run(EvalRunInput {
        project_id,
        suite: suite.clone(),
        cases: cases.clone(),
        manifest: manifest.clone(),
        profile,
        mutation_attempt: None,
    });
    let verdict = EvalVerdictService::verdict(&run);
    Artifacts {
        cases,
        suite,
        manifest,
        integrity,
        run,
        verdict,
    }
}

fn coverage(artifacts: &Artifacts) -> EvalCoverageMatrix {
    EvalCoverageService::matrix(
        artifacts.suite.project_id,
        std::slice::from_ref(&artifacts.suite),
        &artifacts.cases,
    )
}

fn baseline(artifacts: &Artifacts) -> EvalBaseline {
    match EvalBaselineService::create(
        &artifacts.suite,
        &artifacts.manifest,
        &artifacts.integrity,
        &artifacts.run,
        &artifacts.verdict,
        "test-git",
        "test",
    ) {
        Ok(baseline) => baseline,
        Err(error) => panic!("expected passing K1 baseline: {error}"),
    }
}

fn profile(profile_id: &str) -> EvalRegressionGateProfile {
    match EvalGateProfileService::find(profile_id) {
        Some(profile) => profile,
        None => panic!("missing K1 eval gate profile {profile_id}"),
    }
}

fn clean_comparison(artifacts: &Artifacts) -> eliot_types::EvalCandidateComparison {
    EvalComparisonService::compare(
        &artifacts.suite,
        &baseline(artifacts),
        &artifacts.run,
        "test-git",
    )
}
