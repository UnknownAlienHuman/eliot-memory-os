//! The evaluation command surface.
//!
//! Cases, suites, runs, baselines and the smoke artifacts they are checked
//! against. These share the report layout and the family parsing, so a change
//! to how an eval result is recorded lands in one file.

// This child module implements part of the parent command surface and shares
// its private command/report vocabulary by design.
#[allow(clippy::wildcard_imports)]
use super::*;

pub fn run_eval_case_create(config_path: &Path, family: &str, name: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut report = read_eval_cases_report(&root).unwrap_or_else(|_| EvalCasesReport {
        component: "eval_cases".to_owned(),
        cases: Vec::new(),
        generated_at: time::OffsetDateTime::now_utc(),
    });
    let case = EvalCaseService::create(EvalCaseInput {
        project_id: project_id_from_label("eliot-governor"),
        task_id: Some(task_id_from_label("core-eval-cli")),
        family: parse_eval_family(family)?,
        name: name.to_owned(),
    })?;
    report.cases.push(case.clone());
    report.generated_at = time::OffsetDateTime::now_utc();
    write_eval_report(&root, "eval-cases", "Eval Cases", &report)?;
    write_json(&case)
}

pub fn run_eval_case_list(config_path: &Path, family: Option<&str>) -> Result<()> {
    let root = runtime_root(config_path);
    let cases = match read_eval_cases_report(&root) {
        Ok(report) => report.cases,
        Err(_) => k0_default_cases(),
    };
    let filtered = if let Some(family) = family {
        let family = parse_eval_family(family)?;
        cases
            .into_iter()
            .filter(|case| case.family == family)
            .collect::<Vec<_>>()
    } else {
        cases
    };
    write_json(&serde_json::json!({
        "component": "eval_case_list",
        "cases": filtered,
        "generated_at": time::OffsetDateTime::now_utc()
    }))
}

pub fn run_eval_suite_create(config_path: &Path, name: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let cases = ensure_eval_cases(&root)?;
    let suite = EvalSuiteService::create(EvalSuiteInput {
        project_id: project_id_from_label("eliot-governor"),
        name: name.to_owned(),
        purpose: "Deterministic no-mutation eval suite".to_owned(),
        cases: cases.iter().map(|case| case.eval_case_id).collect(),
        fixed: false,
        holdout: true,
        created_from_refs: vec!["eval:cli".to_owned()],
    });
    let report = EvalSuitesReport {
        component: "eval_suites".to_owned(),
        suites: vec![suite.clone()],
        latest: suite.clone(),
        manifest: None,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(&root, "eval-suites", "Eval Suites", &report)?;
    write_json(&suite)
}

pub fn run_eval_suite_add(config_path: &Path, suite: &str, case: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut report = read_eval_suites_report(&root)
        .context("no latest eval suite found; run eval suite create first")?;
    if suite != "latest"
        && suite != report.latest.name
        && suite != report.latest.eval_suite_id.to_string()
    {
        bail!("only the latest eval suite or its name/id is available through this CLI");
    }
    let cases = ensure_eval_cases(&root)?;
    let eval_case = cases
        .iter()
        .find(|eval_case| {
            case == "latest"
                || eval_case.eval_case_id.to_string() == case
                || eval_case.name == case
                || family_slug(eval_case.family) == case
        })
        .context("eval case not found")?;
    EvalSuiteService::add_case(&mut report.latest, eval_case.eval_case_id)?;
    report.suites.push(report.latest.clone());
    report.generated_at = time::OffsetDateTime::now_utc();
    write_eval_report(&root, "eval-suites", "Eval Suites", &report)?;
    write_json(&report.latest)
}

pub fn run_eval_suite_freeze(config_path: &Path, suite: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut report = read_eval_suites_report(&root)
        .context("no latest eval suite found; run eval suite create first")?;
    if suite != "latest"
        && suite != report.latest.name
        && suite != report.latest.eval_suite_id.to_string()
    {
        bail!("only the latest eval suite or its name/id is available through this CLI");
    }
    EvalSuiteService::freeze(&mut report.latest);
    report.suites.push(report.latest.clone());
    report.generated_at = time::OffsetDateTime::now_utc();
    write_eval_report(&root, "eval-suites", "Eval Suites", &report)?;
    write_json(&report.latest)
}

pub fn run_eval_manifest(config_path: &Path, suite: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut report = read_eval_suites_report(&root)
        .context("no latest eval suite found; run eval suite create first")?;
    if suite != "latest"
        && suite != report.latest.name
        && suite != report.latest.eval_suite_id.to_string()
    {
        bail!("only the latest eval suite or its name/id is available through this CLI");
    }
    let cases = ensure_eval_cases(&root)?;
    let manifest = EvalDatasetManifestService::manifest(&report.latest, &cases);
    report.manifest = Some(manifest.clone());
    report.generated_at = time::OffsetDateTime::now_utc();
    write_eval_report(&root, "eval-suites", "Eval Suites", &report)?;
    write_json(&manifest)
}

pub fn run_eval_run(config_path: &Path, suite: &str, profile: &str) -> Result<()> {
    if normalized_cli_value(profile) != "deterministicnomutation" {
        bail!("the core eval runner supports only deterministic-no-mutation runs");
    }
    let root = runtime_root(config_path);
    let artifacts = ensure_core_smoke_artifacts(&root, suite)?;
    write_json(&artifacts.run)
}

pub fn run_eval_verdict(config_path: &Path, run: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let run_report = read_eval_runs_report(&root)
        .context("no latest eval run found; run eval run or eval smoke first")?;
    if run != "latest" && run != run_report.run.eval_run_id.to_string() {
        bail!("only the latest eval run or its id is available through this CLI");
    }
    let verdict = EvalVerdictService::verdict(&run_report.run);
    let report = EvalVerdictsReport {
        component: "eval_verdicts".to_owned(),
        verdict: verdict.clone(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(&root, "eval-verdicts", "Eval Verdicts", &report)?;
    write_json(&verdict)
}

pub fn run_eval_failures(config_path: &Path, run: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let run_report = read_eval_runs_report(&root)
        .context("no latest eval run found; run eval run or eval smoke first")?;
    if run != "latest" && run != run_report.run.eval_run_id.to_string() {
        bail!("only the latest eval run or its id is available through this CLI");
    }
    let mut clusters = EvalVerdictService::failure_clusters(&run_report.run);
    if clusters.is_empty() {
        clusters.push(EvalVerdictService::fixture_failure_cluster(
            run_report.run.eval_run_id,
        ));
    }
    let report = EvalFailuresReport {
        component: "eval_failures".to_owned(),
        clusters: clusters.clone(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(&root, "eval-failures", "Eval Failures", &report)?;
    write_json(&report)
}

pub fn run_eval_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = eval_summary_report(&root)?;
    write_json(&report)
}

pub fn run_eval_smoke(config_path: &Path, suite: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_core_smoke_artifacts(&root, suite)?;
    let report = serde_json::json!({
        "component": "eval_smoke",
        "suite": artifacts.suite,
        "manifest": artifacts.manifest,
        "run": artifacts.run,
        "verdict": artifacts.verdict,
        "failure_cluster": artifacts.fixture_failure_cluster,
        "benchmark_integrity": {
            "valid_receipt": artifacts.integrity_receipt,
            "mismatch_receipt": artifacts.mismatch_receipt
        },
        "operation_status": match artifacts.verdict.status {
            EvalVerdictStatus::Pass => OperationStatus::OperationCompleted,
            EvalVerdictStatus::Fail => OperationStatus::Failed,
            EvalVerdictStatus::Inconclusive | EvalVerdictStatus::Blocked => {
                OperationStatus::Blocked
            }
        },
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_json(&report)
}

pub fn run_eval_coverage(config_path: &Path, suite: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_core_smoke_artifacts(&root, suite)?;
    let report = eval_coverage_report(&artifacts);
    write_eval_report(&root, "eval-coverage", "Eval Coverage", &report)?;
    write_json(&report.coverage)
}

pub fn run_eval_baseline_create(config_path: &Path, suite: &str, run: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_core_smoke_artifacts(&root, suite)?;
    ensure_eval_run_ref(&artifacts.run, run)?;
    let git_commit = git_head_blocking(&repo_root()).unwrap_or_else(|_| "unknown".to_owned());
    let baseline = EvalBaselineService::create(
        &artifacts.suite,
        &artifacts.manifest,
        &artifacts.integrity_receipt,
        &artifacts.run,
        &artifacts.verdict,
        &git_commit,
        "local-cli",
    )?;
    write_eval_baseline_registry(&root, &artifacts.suite, baseline.clone())?;
    write_json(&baseline)
}

pub fn run_eval_baseline_list(config_path: &Path, suite: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_core_smoke_artifacts(&root, suite)?;
    let report = read_eval_baselines_report(&root).unwrap_or_else(|_| EvalBaselinesReport {
        component: "eval_baselines".to_owned(),
        suite_id: artifacts.suite.eval_suite_id.to_string(),
        baselines: Vec::new(),
        active: None,
        incident_lockdown_blocks_mutation:
            EvalRegressionGateService::incident_lockdown_blocks_baseline_mutation(true),
        generated_at: time::OffsetDateTime::now_utc(),
    });
    write_json(&report)
}

pub fn run_eval_compare(
    config_path: &Path,
    suite: &str,
    baseline: &str,
    candidate_run: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_core_smoke_artifacts(&root, suite)?;
    ensure_eval_run_ref(&artifacts.run, candidate_run)?;
    let baseline = resolve_eval_baseline(&root, &artifacts, baseline)?;
    let git_commit = git_head_blocking(&repo_root()).unwrap_or_else(|_| "unknown".to_owned());
    let comparison =
        EvalComparisonService::compare(&artifacts.suite, &baseline, &artifacts.run, &git_commit);
    let report = EvalComparisonsReport {
        component: "eval_comparisons".to_owned(),
        baseline: baseline.clone(),
        candidate_run: artifacts.run.clone(),
        comparison: comparison.clone(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(
        &root,
        "eval-comparisons",
        "Eval Candidate Comparisons",
        &report,
    )?;
    write_json(&comparison)
}

pub fn run_eval_gate(config_path: &Path, profile: &str, suite: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_integration_smoke_artifacts(&root, suite)?;
    let profile = EvalGateProfileService::find(profile)
        .with_context(|| format!("unknown eval gate profile: {profile}"))?;
    EvalGateProfileService::validate(&profile)?;
    let decision = EvalRegressionGateService::evaluate_comparison(
        &profile,
        &artifacts.comparison,
        &artifacts.core.integrity_receipt,
    );
    let report = EvalGatesReport {
        component: "eval_gates".to_owned(),
        profile: profile.clone(),
        comparison: Some(artifacts.comparison.clone()),
        decision: decision.clone(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(&root, "eval-gates", "Eval Gates", &report)?;
    write_json(&decision)
}

pub fn run_eval_profiles(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = EvalProfilesReport {
        component: "eval_profiles".to_owned(),
        profiles: EvalGateProfileService::built_in_profiles(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    for profile in &report.profiles {
        EvalGateProfileService::validate(profile)?;
    }
    write_eval_report(&root, "eval-gates", "Eval Gate Profiles", &report)?;
    write_json(&report)
}

pub fn run_eval_trend(config_path: &Path, suite: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_core_smoke_artifacts(&root, suite)?;
    let trend = EvalTrendService::trend(
        &artifacts.suite,
        &[artifacts.run.clone(), artifacts.run.clone()],
    );
    let report = EvalTrendsReport {
        component: "eval_trends".to_owned(),
        trend: trend.clone(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(&root, "eval-trends", "Eval Trends", &report)?;
    write_json(&trend)
}

pub fn run_eval_stability(config_path: &Path, suite: &str, repeat: u8) -> Result<()> {
    let root = runtime_root(config_path);
    let repeat = repeat.clamp(2, 5);
    let artifacts = ensure_core_smoke_artifacts(&root, suite)?;
    let runs = std::iter::repeat_with(|| artifacts.run.clone())
        .take(usize::from(repeat))
        .collect::<Vec<_>>();
    let stability = EvalFixtureStabilityService::report(&artifacts.suite, &runs);
    let report = EvalFixtureStabilityReportEnvelope {
        component: "eval_fixture_stability".to_owned(),
        repeat,
        stability: stability.clone(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(
        &root,
        "eval-fixture-stability",
        "Eval Fixture Stability",
        &report,
    )?;
    write_json(&stability)
}

pub fn run_eval_integration_smoke(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_integration_smoke_artifacts(&root, "core-smoke")?;
    let report = serde_json::json!({
        "component": "eval_integration_smoke",
        "coverage": artifacts.coverage,
        "baseline": artifacts.baseline,
        "comparison": artifacts.comparison,
        "gate_decision": artifacts.gate_decision,
        "critical_comparison": artifacts.critical_comparison,
        "critical_gate_decision": artifacts.critical_gate_decision,
        "trend": artifacts.trend,
        "stability": artifacts.stability,
        "doctor_status": artifacts.doctor_status,
        "operation_status": if artifacts.gate_decision.decision == EvalGateDecisionKind::Allow
            && artifacts.critical_gate_decision.decision == EvalGateDecisionKind::Block
        {
            OperationStatus::OperationCompleted
        } else {
            OperationStatus::Failed
        },
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_json(&report)
}

pub(super) fn ensure_core_smoke_artifacts(
    root: &Path,
    suite_name: &str,
) -> Result<CoreSmokeArtifacts> {
    let suite_name = if suite_name == "latest" {
        "core-smoke"
    } else {
        suite_name
    };
    let project_id = project_id_from_label("eliot-governor");
    let task_id = task_id_from_label("core-eval-smoke");
    let cases = EvalCaseService::k0_core_cases(project_id, Some(task_id));
    let mut suite = EvalSuiteService::create(EvalSuiteInput {
        project_id,
        name: suite_name.to_owned(),
        purpose: "Deterministic no-mutation core smoke suite".to_owned(),
        cases: cases.iter().map(|case| case.eval_case_id).collect(),
        fixed: false,
        holdout: true,
        created_from_refs: vec!["eval:core-smoke".to_owned()],
    });
    EvalSuiteService::freeze(&mut suite);
    let manifest = EvalDatasetManifestService::manifest(&suite, &cases);
    let profile = EvalRunnerService::deterministic_no_mutation_profile();
    EvalRegressionGate::allow_run(&suite, &manifest, &profile, false, false)?;
    let integrity_receipt = EvalDatasetManifestService::verify(&suite, &manifest);
    let mismatch_receipt = EvalDatasetManifestService::checksum_mismatch(&suite, &manifest);
    let run = EvalRunnerService::run(EvalRunInput {
        project_id,
        suite: suite.clone(),
        cases: cases.clone(),
        manifest: manifest.clone(),
        profile: profile.clone(),
        mutation_attempt: None,
    });
    let blocked_mutation_run = EvalRunnerService::run(EvalRunInput {
        project_id,
        suite: suite.clone(),
        cases: cases.clone(),
        manifest: manifest.clone(),
        profile: profile.clone(),
        mutation_attempt: Some("apply current truth".to_owned()),
    });
    let verdict = EvalVerdictService::verdict(&run);
    let fixture_failure_cluster = EvalVerdictService::fixture_failure_cluster(run.eval_run_id);
    let experiment = harness_experiment_record(&run, &verdict);
    let artifacts = CoreSmokeArtifacts {
        cases,
        suite,
        manifest,
        profile,
        integrity_receipt,
        mismatch_receipt,
        run,
        blocked_mutation_run,
        verdict,
        fixture_failure_cluster,
        experiment,
    };
    write_core_artifact_reports(root, &artifacts)?;
    Ok(artifacts)
}

pub(super) fn write_core_artifact_reports(
    root: &Path,
    artifacts: &CoreSmokeArtifacts,
) -> Result<()> {
    let generated_at = time::OffsetDateTime::now_utc();
    write_eval_report(
        root,
        "eval-cases",
        "Eval Cases",
        &EvalCasesReport {
            component: "eval_cases".to_owned(),
            cases: artifacts.cases.clone(),
            generated_at,
        },
    )?;
    write_eval_report(
        root,
        "eval-suites",
        "Eval Suites",
        &EvalSuitesReport {
            component: "eval_suites".to_owned(),
            suites: vec![artifacts.suite.clone()],
            latest: artifacts.suite.clone(),
            manifest: Some(artifacts.manifest.clone()),
            generated_at,
        },
    )?;
    write_eval_report(
        root,
        "eval-runs",
        "Eval Runs",
        &EvalRunsReport {
            component: "eval_runs".to_owned(),
            run: artifacts.run.clone(),
            profile: artifacts.profile.clone(),
            blocked_mutation_run: artifacts.blocked_mutation_run.clone(),
            experiment: artifacts.experiment.clone(),
            generated_at,
        },
    )?;
    write_eval_report(
        root,
        "eval-verdicts",
        "Eval Verdicts",
        &EvalVerdictsReport {
            component: "eval_verdicts".to_owned(),
            verdict: artifacts.verdict.clone(),
            generated_at,
        },
    )?;
    write_eval_report(
        root,
        "eval-failures",
        "Eval Failures",
        &EvalFailuresReport {
            component: "eval_failures".to_owned(),
            clusters: vec![artifacts.fixture_failure_cluster.clone()],
            generated_at,
        },
    )?;
    write_eval_report(
        root,
        "benchmark-integrity",
        "Benchmark Integrity",
        &BenchmarkIntegrityReport {
            component: "benchmark_integrity".to_owned(),
            valid_receipt: artifacts.integrity_receipt.clone(),
            mismatch_receipt: artifacts.mismatch_receipt.clone(),
            generated_at,
        },
    )
}

#[allow(clippy::too_many_lines)]
pub(super) fn ensure_integration_smoke_artifacts(
    root: &Path,
    suite_name: &str,
) -> Result<IntegrationSmokeArtifacts> {
    let core = ensure_core_smoke_artifacts(root, suite_name)?;
    let coverage = eval_coverage_report(&core).coverage;
    write_eval_report(
        root,
        "eval-coverage",
        "Eval Coverage",
        &EvalCoverageReport {
            component: "eval_coverage".to_owned(),
            coverage: coverage.clone(),
            generated_at: time::OffsetDateTime::now_utc(),
        },
    )?;

    let git_commit = git_head_blocking(&repo_root()).unwrap_or_else(|_| "unknown".to_owned());
    let baseline = EvalBaselineService::create(
        &core.suite,
        &core.manifest,
        &core.integrity_receipt,
        &core.run,
        &core.verdict,
        &git_commit,
        "provider-integration-smoke",
    )?;
    write_eval_baseline_registry(root, &core.suite, baseline.clone())?;

    let candidate_run = core.run.clone();
    let comparison =
        EvalComparisonService::compare(&core.suite, &baseline, &candidate_run, &git_commit);
    write_eval_report(
        root,
        "eval-comparisons",
        "Eval Candidate Comparisons",
        &EvalComparisonsReport {
            component: "eval_comparisons".to_owned(),
            baseline: baseline.clone(),
            candidate_run: candidate_run.clone(),
            comparison: comparison.clone(),
            generated_at: time::OffsetDateTime::now_utc(),
        },
    )?;

    let profiles = EvalGateProfileService::built_in_profiles();
    for profile in &profiles {
        EvalGateProfileService::validate(profile)?;
    }
    let fast_deterministic = EvalGateProfileService::find("fast-deterministic")
        .context("fast-deterministic eval gate profile is missing")?;
    let gate_decision = EvalRegressionGateService::evaluate_comparison(
        &fast_deterministic,
        &comparison,
        &core.integrity_receipt,
    );
    let critical_candidate_run =
        EvalComparisonService::run_with_failed_family(&candidate_run, EvalFamily::Understand);
    let critical_comparison = EvalComparisonService::compare(
        &core.suite,
        &baseline,
        &critical_candidate_run,
        &git_commit,
    );
    let critical_gate_decision = EvalRegressionGateService::evaluate_comparison(
        &fast_deterministic,
        &critical_comparison,
        &core.integrity_receipt,
    );
    let benchmark_repair_decision = EvalRegressionGateService::evaluate_comparison(
        &fast_deterministic,
        &comparison,
        &core.mismatch_receipt,
    );
    anyhow::ensure!(
        benchmark_repair_decision.decision == EvalGateDecisionKind::RequireBenchmarkRepair,
        "a mismatched benchmark integrity receipt must require benchmark repair"
    );
    write_eval_report(
        root,
        "eval-gates",
        "Eval Gates",
        &EvalGatesReport {
            component: "eval_gates".to_owned(),
            profile: fast_deterministic,
            comparison: Some(comparison.clone()),
            decision: gate_decision.clone(),
            generated_at: time::OffsetDateTime::now_utc(),
        },
    )?;

    let trend = EvalTrendService::trend(
        &core.suite,
        &[candidate_run.clone(), critical_candidate_run.clone()],
    );
    write_eval_report(
        root,
        "eval-trends",
        "Eval Trends",
        &EvalTrendsReport {
            component: "eval_trends".to_owned(),
            trend: trend.clone(),
            generated_at: time::OffsetDateTime::now_utc(),
        },
    )?;

    let stability = EvalFixtureStabilityService::report(
        &core.suite,
        &[candidate_run.clone(), candidate_run.clone()],
    );
    write_eval_report(
        root,
        "eval-fixture-stability",
        "Eval Fixture Stability",
        &EvalFixtureStabilityReportEnvelope {
            component: "eval_fixture_stability".to_owned(),
            repeat: 2,
            stability: stability.clone(),
            generated_at: time::OffsetDateTime::now_utc(),
        },
    )?;

    let doctor_status = EvalDoctorIntegration::status(
        Some(&baseline),
        Some(&gate_decision),
        &coverage,
        Some(&trend),
        Some(&stability),
        &core.integrity_receipt,
    );

    Ok(IntegrationSmokeArtifacts {
        core,
        coverage,
        baseline,
        comparison,
        gate_decision,
        critical_comparison,
        critical_gate_decision,
        trend,
        stability,
        doctor_status,
    })
}

pub(super) fn eval_coverage_report(artifacts: &CoreSmokeArtifacts) -> EvalCoverageReport {
    EvalCoverageReport {
        component: "eval_coverage".to_owned(),
        coverage: EvalCoverageService::matrix(
            project_id_from_label("eliot-governor"),
            std::slice::from_ref(&artifacts.suite),
            &artifacts.cases,
        ),
        generated_at: time::OffsetDateTime::now_utc(),
    }
}

pub(super) fn write_eval_baseline_registry(
    root: &Path,
    suite: &EvalSuite,
    baseline: EvalBaseline,
) -> Result<()> {
    let mut baselines = read_eval_baselines_report(root)
        .map(|report| report.baselines)
        .unwrap_or_default();
    baselines.push(baseline);
    let active = EvalBaselineService::active_baseline(&baselines);
    let report = EvalBaselinesReport {
        component: "eval_baselines".to_owned(),
        suite_id: suite.eval_suite_id.to_string(),
        baselines,
        active,
        incident_lockdown_blocks_mutation:
            EvalRegressionGateService::incident_lockdown_blocks_baseline_mutation(true),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(root, "eval-baselines", "Eval Baselines", &report)
}

pub(super) fn resolve_eval_baseline(
    root: &Path,
    artifacts: &CoreSmokeArtifacts,
    baseline_ref: &str,
) -> Result<EvalBaseline> {
    let report = read_eval_baselines_report(root).ok();
    if let Some(report) = report {
        if baseline_ref == "latest"
            && let Some(active) = report.active
        {
            return Ok(active);
        }
        if let Some(baseline) = report
            .baselines
            .into_iter()
            .find(|baseline| baseline.baseline_id == baseline_ref)
        {
            return Ok(baseline);
        }
    }
    let git_commit = git_head_blocking(&repo_root()).unwrap_or_else(|_| "unknown".to_owned());
    let baseline = EvalBaselineService::create(
        &artifacts.suite,
        &artifacts.manifest,
        &artifacts.integrity_receipt,
        &artifacts.run,
        &artifacts.verdict,
        &git_commit,
        "auto-baseline",
    )?;
    write_eval_baseline_registry(root, &artifacts.suite, baseline.clone())?;
    Ok(baseline)
}

pub(super) fn ensure_eval_run_ref(run: &EvalRun, run_ref: &str) -> Result<()> {
    if run_ref != "latest" && run_ref != run.eval_run_id.to_string() {
        bail!("only the latest integration eval run or its id is available through this CLI");
    }
    Ok(())
}

pub(super) fn ensure_eval_cases(root: &Path) -> Result<Vec<EvalCase>> {
    match read_eval_cases_report(root) {
        Ok(report) if !report.cases.is_empty() => Ok(report.cases),
        _ => {
            let cases = k0_default_cases();
            write_eval_report(
                root,
                "eval-cases",
                "Eval Cases",
                &EvalCasesReport {
                    component: "eval_cases".to_owned(),
                    cases: cases.clone(),
                    generated_at: time::OffsetDateTime::now_utc(),
                },
            )?;
            Ok(cases)
        }
    }
}

pub(super) fn k0_default_cases() -> Vec<EvalCase> {
    EvalCaseService::k0_core_cases(
        project_id_from_label("eliot-governor"),
        Some(task_id_from_label("core-eval-smoke")),
    )
}

pub(super) fn eval_summary_report(root: &Path) -> Result<serde_json::Value> {
    if !latest_report_path(root, "eval-runs").is_file() {
        let _ = ensure_core_smoke_artifacts(root, "core-smoke")?;
    }
    let run_report = read_latest_value(root, "eval-runs").ok();
    let verdict_report = read_latest_value(root, "eval-verdicts").ok();
    let integrity_report = read_latest_value(root, "benchmark-integrity").ok();
    let failures_report = read_latest_value(root, "eval-failures").ok();
    let coverage_report = read_latest_value(root, "eval-coverage").ok();
    let baseline_report = read_latest_value(root, "eval-baselines").ok();
    let comparison_report = read_latest_value(root, "eval-comparisons").ok();
    let gate_report = read_latest_value(root, "eval-gates").ok();
    let trend_report = read_latest_value(root, "eval-trends").ok();
    let stability_report = read_latest_value(root, "eval-fixture-stability").ok();
    let report = serde_json::json!({
        "component": "eval_report",
        "last_eval_run": run_report,
        "last_eval_verdict": verdict_report,
        "failure_clusters": failures_report,
        "benchmark_integrity_state": integrity_report,
        "coverage": coverage_report,
        "active_baseline": baseline_report,
        "last_candidate_comparison": comparison_report,
        "last_eval_gate_decision": gate_report,
        "trend": trend_report,
        "fixture_stability": stability_report,
        "eval_regression_gate_state": "deterministic-no-mutation-only",
        "missing_fixed_suite": false,
        "holdout_contamination_warnings": [],
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_eval_report(root, "eval-report", "Eval Report", &report)?;
    Ok(report)
}

pub(super) fn read_eval_cases_report(root: &Path) -> Result<EvalCasesReport> {
    read_latest_typed(root, "eval-cases")
}

pub(super) fn read_eval_suites_report(root: &Path) -> Result<EvalSuitesReport> {
    read_latest_typed(root, "eval-suites")
}

pub(super) fn read_eval_runs_report(root: &Path) -> Result<EvalRunsReport> {
    read_latest_typed(root, "eval-runs")
}

pub(super) fn read_eval_baselines_report(root: &Path) -> Result<EvalBaselinesReport> {
    read_latest_typed(root, "eval-baselines")
}

pub(super) fn write_eval_report<T>(root: &Path, dir: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    let json_value = serde_json::to_value(value)?;
    write_report_pair(
        &latest_report_path(root, dir),
        &latest_markdown_path(root, dir),
        value,
        &eval_value_markdown(title, &json_value),
    )
}

pub(super) fn eval_value_markdown(title: &str, value: &serde_json::Value) -> String {
    let mut output = format!("# {title}\n\n");
    if let Some(component) = value.get("component").and_then(serde_json::Value::as_str) {
        let _ = writeln!(output, "- component: `{component}`");
    }
    if let Some(verdict) = value
        .get("verdict")
        .and_then(|verdict| verdict.get("status"))
        .and_then(serde_json::Value::as_str)
    {
        let _ = writeln!(output, "- verdict: `{verdict}`");
    }
    if let Some(run_status) = value
        .get("run")
        .and_then(|run| run.get("status"))
        .and_then(serde_json::Value::as_str)
    {
        let _ = writeln!(output, "- run_status: `{run_status}`");
    }
    let _ = writeln!(
        output,
        "- profile: `deterministic-no-mutation`\n- authority: `report-only; no truth, policy, skill, action, patch, or completion mutation`"
    );
    output
}

pub(super) fn parse_eval_family(value: &str) -> Result<EvalFamily> {
    match normalized_cli_value(value).as_str() {
        "understand" => Ok(EvalFamily::Understand),
        "hallucination" => Ok(EvalFamily::Hallucination),
        "negative" => Ok(EvalFamily::Negative),
        "done" => Ok(EvalFamily::Done),
        "context" => Ok(EvalFamily::Context),
        "compaction" => Ok(EvalFamily::Compaction),
        "tool" => Ok(EvalFamily::Tool),
        "memory" => Ok(EvalFamily::Memory),
        "forget" => Ok(EvalFamily::Forget),
        "dream" => Ok(EvalFamily::Dream),
        "skill" => Ok(EvalFamily::Skill),
        "trace" => Ok(EvalFamily::Trace),
        "bench" => Ok(EvalFamily::Bench),
        "ale" => Ok(EvalFamily::Ale),
        "provider" => Ok(EvalFamily::Provider),
        "future" => Ok(EvalFamily::Future),
        other => bail!("unknown eval family: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integration_smoke_accepts_repairable_benchmark_integrity_state() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("eliot-app-eval-readiness-{}", uuid::Uuid::now_v7()));
        let artifacts = ensure_integration_smoke_artifacts(&root, "core-smoke")?;

        assert!(
            artifacts.core.integrity_receipt.valid,
            "the canonical smoke receipt should remain valid"
        );
        assert_eq!(
            artifacts.gate_decision.decision,
            EvalGateDecisionKind::Allow
        );
        let profile = EvalGateProfileService::find("fast-deterministic")
            .context("fast-deterministic eval gate profile is missing")?;
        let benchmark_repair_decision = EvalRegressionGateService::evaluate_comparison(
            &profile,
            &artifacts.comparison,
            &artifacts.core.mismatch_receipt,
        );
        assert_eq!(
            benchmark_repair_decision.decision,
            EvalGateDecisionKind::RequireBenchmarkRepair
        );

        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
