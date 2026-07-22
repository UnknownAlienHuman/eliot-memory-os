//! Evaluation and the metrics that judge it.
//!
//! Eval cases, suites, runs, verdicts and baselines, and the metric registry,
//! SLOs and dashboards they are read against. A verdict is only meaningful
//! next to the numbers behind it, so the two surfaces share this module and
//! its report writers.

use super::*;

pub(super) fn dispatch_eval_case_list(arguments: Value) -> Result<Value> {
    let input: EvalFamilyToolInput = serde_json::from_value(arguments)?;
    let mut cases = mcp_k0_cases();
    if let Some(family) = input.family.as_deref() {
        let family = parse_eval_family(family)?;
        cases.retain(|case| case.family == family);
    }
    serde_json::to_value(json!({
        "component": "eval_case_list",
        "bounded": true,
        "cases": cases
    }))
    .map_err(Into::into)
}

pub(super) fn dispatch_eval_suite_list(state: &McpState, arguments: Value) -> Result<Value> {
    let input: EvalSuiteToolInput = serde_json::from_value(arguments)?;
    let artifacts = mcp_eval_artifacts(
        state,
        input.suite.as_deref().unwrap_or("k0-core-smoke"),
        None,
    )?;
    Ok(json!({
        "component": "eval_suite_list",
        "bounded": true,
        "suite": artifacts.suite,
        "manifest": artifacts.manifest,
        "report_ref": state.root.join("reports").join("eval-suites").join("latest.json")
    }))
}

pub(super) fn dispatch_eval_run(state: &McpState, arguments: Value) -> Result<Value> {
    let input: EvalRunToolInput = serde_json::from_value(arguments)?;
    if input
        .profile
        .as_deref()
        .map(normalized_cli_value)
        .is_some_and(|profile| profile != "deterministicnomutation")
    {
        anyhow::bail!("K0 MCP eval run supports only deterministic-no-mutation profile");
    }
    let artifacts = mcp_eval_artifacts(
        state,
        input.suite.as_deref().unwrap_or("k0-core-smoke"),
        None,
    )?;
    serde_json::to_value(json!({
        "component": "eval_run",
        "bounded": true,
        "run": artifacts.run,
        "report_ref": state.root.join("reports").join("eval-runs").join("latest.json")
    }))
    .map_err(Into::into)
}

pub(super) fn dispatch_eval_verdict(state: &McpState, arguments: Value) -> Result<Value> {
    let input: EvalRunRefToolInput = serde_json::from_value(arguments)?;
    let artifacts = mcp_eval_artifacts(state, "k0-core-smoke", None)?;
    if let Some(run) = input.run.as_deref()
        && run != "latest"
        && run != artifacts.run.eval_run_id.to_string()
    {
        anyhow::bail!("only latest eval run or its id is available through MCP");
    }
    serde_json::to_value(json!({
        "component": "eval_verdict",
        "bounded": true,
        "verdict": artifacts.verdict,
        "report_ref": state.root.join("reports").join("eval-verdicts").join("latest.json")
    }))
    .map_err(Into::into)
}

pub(super) fn dispatch_eval_report(state: &McpState) -> Result<Value> {
    let artifacts = mcp_eval_artifacts(state, "k0-core-smoke", None)?;
    let report = json!({
        "component": "eval_report",
        "bounded": true,
        "last_eval_run": artifacts.run,
        "last_eval_verdict": artifacts.verdict,
        "failure_cluster_count": 1,
        "benchmark_integrity_state": artifacts.integrity_receipt,
        "eval_regression_gate_state": "deterministic-no-mutation-only",
        "missing_fixed_suite": false,
        "holdout_contamination_warnings": [],
        "report_ref": state.root.join("reports").join("eval-report").join("latest.json")
    });
    write_eval_report_json_md(state, "eval-report", "Eval Report", &report)?;
    Ok(report)
}

pub(super) fn dispatch_eval_smoke(state: &McpState, arguments: Value) -> Result<Value> {
    let input: EvalSuiteToolInput = serde_json::from_value(arguments)?;
    let artifacts = mcp_eval_artifacts(
        state,
        input.suite.as_deref().unwrap_or("k0-core-smoke"),
        None,
    )?;
    serde_json::to_value(json!({
        "component": "eval_smoke",
        "bounded": true,
        "suite": artifacts.suite,
        "manifest": artifacts.manifest,
        "run": artifacts.run,
        "verdict": artifacts.verdict,
        "final_status": if artifacts.verdict.status == EvalVerdictStatus::Pass {
            "DONE_VERIFIED"
        } else {
            "PARTIAL_PROGRESS"
        }
    }))
    .map_err(Into::into)
}

pub(super) fn dispatch_eval_coverage(state: &McpState, arguments: Value) -> Result<Value> {
    let input: EvalSuiteToolInput = serde_json::from_value(arguments)?;
    let artifacts = mcp_eval_artifacts(
        state,
        input.suite.as_deref().unwrap_or("k0-core-smoke"),
        None,
    )?;
    let coverage = EvalCoverageService::matrix(
        project_id_from_label("eliot-governor"),
        std::slice::from_ref(&artifacts.suite),
        &artifacts.cases,
    );
    let report = json!({
        "component": "eval_coverage",
        "bounded": true,
        "coverage": coverage,
        "report_ref": state.root.join("reports").join("eval-coverage").join("latest.json")
    });
    write_eval_report_json_md(state, "eval-coverage", "Eval Coverage", &report)?;
    Ok(report)
}

pub(super) fn dispatch_eval_baseline_list(state: &McpState, arguments: Value) -> Result<Value> {
    let input: EvalSuiteToolInput = serde_json::from_value(arguments)?;
    let artifacts = mcp_eval_artifacts(
        state,
        input.suite.as_deref().unwrap_or("k0-core-smoke"),
        None,
    )?;
    let baseline = mcp_diagnostic_baseline(&artifacts);
    let report = json!({
        "component": "eval_baselines",
        "bounded": true,
        "no_mutation_authority": true,
        "baseline_create_exposed": false,
        "baselines": [baseline],
        "active": Value::Null,
        "report_ref": state.root.join("reports").join("eval-baselines").join("latest.json")
    });
    write_eval_report_json_md(state, "eval-baselines", "Eval Baselines", &report)?;
    Ok(report)
}

pub(super) fn dispatch_eval_compare(state: &McpState, arguments: Value) -> Result<Value> {
    let input: EvalCompareToolInput = serde_json::from_value(arguments)?;
    let artifacts = mcp_eval_artifacts(
        state,
        input.suite.as_deref().unwrap_or("k0-core-smoke"),
        None,
    )?;
    if input
        .candidate_run
        .as_deref()
        .is_some_and(|run| run != "latest" && run != artifacts.run.eval_run_id.to_string())
    {
        anyhow::bail!("only latest eval run or its id is available through MCP");
    }
    let baseline = mcp_diagnostic_baseline(&artifacts);
    if input.baseline.as_deref().is_some_and(|baseline_ref| {
        baseline_ref != "latest" && baseline_ref != baseline.baseline_id.as_str()
    }) {
        anyhow::bail!("only latest diagnostic baseline or its id is available through MCP");
    }
    let comparison = EvalComparisonService::compare(
        &artifacts.suite,
        &baseline,
        &artifacts.run,
        "mcp-read-only",
    );
    let report = json!({
        "component": "eval_comparisons",
        "bounded": true,
        "baseline": baseline,
        "candidate_run": artifacts.run,
        "comparison": comparison,
        "report_ref": state.root.join("reports").join("eval-comparisons").join("latest.json")
    });
    write_eval_report_json_md(
        state,
        "eval-comparisons",
        "Eval Candidate Comparisons",
        &report,
    )?;
    Ok(report)
}

pub(super) fn dispatch_eval_gate(state: &McpState, arguments: Value) -> Result<Value> {
    let input: EvalGateToolInput = serde_json::from_value(arguments)?;
    let artifacts = mcp_eval_artifacts(
        state,
        input.suite.as_deref().unwrap_or("k0-core-smoke"),
        None,
    )?;
    let profile_id = input.profile.as_deref().unwrap_or("phase-minimal");
    let profile = EvalGateProfileService::find(profile_id)
        .with_context(|| format!("unknown eval gate profile: {profile_id}"))?;
    let baseline = mcp_diagnostic_baseline(&artifacts);
    let comparison = EvalComparisonService::compare(
        &artifacts.suite,
        &baseline,
        &artifacts.run,
        "mcp-read-only",
    );
    let decision = EvalRegressionGateService::evaluate_comparison(
        &profile,
        &comparison,
        &artifacts.integrity_receipt,
    );
    let report = json!({
        "component": "eval_gates",
        "bounded": true,
        "profile": profile,
        "comparison": comparison,
        "decision": decision,
        "grant_authority": false,
        "report_ref": state.root.join("reports").join("eval-gates").join("latest.json")
    });
    write_eval_report_json_md(state, "eval-gates", "Eval Gates", &report)?;
    Ok(report)
}

pub(super) fn dispatch_eval_profiles(state: &McpState) -> Result<Value> {
    let profiles = EvalGateProfileService::built_in_profiles();
    for profile in &profiles {
        EvalGateProfileService::validate(profile)?;
    }
    let report = json!({
        "component": "eval_profiles",
        "bounded": true,
        "profiles": profiles,
        "report_ref": state.root.join("reports").join("eval-gates").join("latest.json")
    });
    write_eval_report_json_md(state, "eval-gates", "Eval Gate Profiles", &report)?;
    Ok(report)
}

pub(super) fn dispatch_eval_trend(state: &McpState, arguments: Value) -> Result<Value> {
    let input: EvalSuiteToolInput = serde_json::from_value(arguments)?;
    let artifacts = mcp_eval_artifacts(
        state,
        input.suite.as_deref().unwrap_or("k0-core-smoke"),
        None,
    )?;
    let trend = EvalTrendService::trend(
        &artifacts.suite,
        &[artifacts.run.clone(), artifacts.run.clone()],
    );
    let report = json!({
        "component": "eval_trends",
        "bounded": true,
        "trend": trend,
        "report_ref": state.root.join("reports").join("eval-trends").join("latest.json")
    });
    write_eval_report_json_md(state, "eval-trends", "Eval Trends", &report)?;
    Ok(report)
}

pub(super) fn dispatch_metrics_registry(state: &McpState) -> Result<Value> {
    serde_json::to_value(mcp_metrics_registry_report(state)?).map_err(Into::into)
}

pub(super) fn dispatch_metrics_dashboard(state: &McpState) -> Result<Value> {
    serde_json::to_value(mcp_metrics_dashboard_report(state)?).map_err(Into::into)
}

pub(super) fn dispatch_metrics_slo(state: &McpState) -> Result<Value> {
    let samples = mcp_metrics_samples_report(state)?.samples;
    let rollup = mcp_metrics_rollup_report(state, &samples)?.rollup;
    serde_json::to_value(mcp_metrics_slo_report(state, &rollup)?).map_err(Into::into)
}

pub(super) fn dispatch_metrics_latency(state: &McpState) -> Result<Value> {
    let samples = mcp_metrics_samples_report(state)?.samples;
    let rollup = mcp_metrics_rollup_report(state, &samples)?.rollup;
    serde_json::to_value(mcp_metrics_latency_report(state, &rollup)?).map_err(Into::into)
}

pub(super) fn dispatch_metrics_cost(state: &McpState) -> Result<Value> {
    serde_json::to_value(mcp_metrics_cost_report(state)?).map_err(Into::into)
}

pub(super) fn dispatch_metrics_quality(state: &McpState) -> Result<Value> {
    serde_json::to_value(mcp_metrics_quality_report(state)?).map_err(Into::into)
}

pub(super) fn dispatch_metrics_report(state: &McpState) -> Result<Value> {
    mcp_metrics_summary_report(state)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct McpMetricsRegistryReport {
    component: String,
    definitions: Vec<MetricDefinition>,
    categories: Vec<String>,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct McpMetricsSamplesReport {
    component: String,
    samples: Vec<MetricSample>,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct McpMetricsRollupReport {
    component: String,
    rollup: TelemetryRollup,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct McpMetricsSloReport {
    component: String,
    definitions: Vec<SloDefinition>,
    evaluations: Vec<SloEvaluation>,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct McpMetricsLatencyReport {
    component: String,
    histograms: Vec<LatencyHistogram>,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct McpMetricsCostReport {
    component: String,
    cost: CostLedger,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct McpMetricsQualityReport {
    component: String,
    signals: Vec<QualitySignal>,
    generated_at: time::OffsetDateTime,
}

pub(super) fn mcp_metrics_summary_report(state: &McpState) -> Result<Value> {
    let dashboard = mcp_metrics_dashboard_report(state)?;
    let registry = mcp_metrics_registry_report(state)?;
    let samples = mcp_metrics_samples_report(state)?;
    let rollup = mcp_metrics_rollup_report(state, &samples.samples)?;
    let slo = mcp_metrics_slo_report(state, &rollup.rollup)?;
    let latency = mcp_metrics_latency_report(state, &rollup.rollup)?;
    let cost = mcp_metrics_cost_report(state)?;
    let quality = mcp_metrics_quality_report(state)?;
    let report = json!({
        "component": "metrics_report",
        "bounded": true,
        "registry": registry,
        "samples": samples,
        "rollup": rollup,
        "slo": slo,
        "latency": latency,
        "cost": cost,
        "quality": quality,
        "dashboard": dashboard,
        "authority": "local-observability-only; no raw payloads, remote export, or authority mutation",
        "report_ref": state.root.join("reports").join("metrics-report").join("latest.json"),
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_metrics_mcp_report(state, "metrics-report", "Metrics Report", &report)?;
    Ok(report)
}

pub(super) fn mcp_metrics_dashboard_report(state: &McpState) -> Result<DashboardReport> {
    let definitions = mcp_metrics_registry_report(state)?.definitions;
    let samples = mcp_metrics_samples_report(state)?.samples;
    let rollup = mcp_metrics_rollup_report(state, &samples)?.rollup;
    let latency = mcp_metrics_latency_report(state, &rollup)?.histograms;
    let slo = mcp_metrics_slo_report(state, &rollup)?;
    let cost = mcp_metrics_cost_report(state)?.cost;
    let quality = mcp_metrics_quality_report(state)?.signals;
    let dashboard = RuntimeDashboardService.dashboard(
        project_id_from_label("eliot-governor"),
        latency,
        cost,
        slo.evaluations,
        quality,
        mcp_recent_incident_refs(state),
        Some("reports/eval-report/latest.json".to_owned()),
        Some("reports/verification/latest.json".to_owned()),
    );
    let trends = RuntimeDashboardService.trends(&dashboard);
    let doctor = MetricsDoctorIntegration.status(&definitions, Some(&dashboard), &trends);
    let report = DashboardReport {
        component: "runtime_dashboard".to_owned(),
        dashboard,
        trends,
        doctor,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_mcp_report(state, "runtime-dashboard", "Runtime Dashboard", &report)?;
    Ok(report)
}

pub(super) fn mcp_metrics_registry_report(state: &McpState) -> Result<McpMetricsRegistryReport> {
    let definitions = MetricRegistryService.definitions();
    for definition in &definitions {
        MetricRegistryService.validate_definition(definition)?;
    }
    let report = McpMetricsRegistryReport {
        component: "metrics_registry".to_owned(),
        definitions,
        categories: MetricRegistryService.categories(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_mcp_report(state, "metrics-registry", "Metrics Registry", &report)?;
    Ok(report)
}

pub(super) fn mcp_metrics_samples_report(state: &McpState) -> Result<McpMetricsSamplesReport> {
    let definitions = MetricRegistryService.definitions();
    let report = McpMetricsSamplesReport {
        component: "metrics_samples".to_owned(),
        samples: MetricRecorderService.smoke_samples(&definitions)?,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_mcp_report(state, "metrics-samples", "Metrics Samples", &report)?;
    Ok(report)
}

pub(super) fn mcp_metrics_rollup_report(
    state: &McpState,
    samples: &[MetricSample],
) -> Result<McpMetricsRollupReport> {
    let report = McpMetricsRollupReport {
        component: "metrics_rollups".to_owned(),
        rollup: MetricRollupService.rollup(
            project_id_from_label("eliot-governor"),
            MetricWindow::OneRun,
            samples,
        ),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_mcp_report(state, "metrics-rollups", "Metrics Rollups", &report)?;
    Ok(report)
}

pub(super) fn mcp_metrics_slo_report(
    state: &McpState,
    rollup: &TelemetryRollup,
) -> Result<McpMetricsSloReport> {
    let definitions = SloService.definitions();
    let report = McpMetricsSloReport {
        component: "metrics_slo".to_owned(),
        evaluations: SloService.evaluate(&definitions, rollup),
        definitions,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_mcp_report(state, "metrics-slo", "Metrics SLO", &report)?;
    Ok(report)
}

pub(super) fn mcp_metrics_latency_report(
    state: &McpState,
    rollup: &TelemetryRollup,
) -> Result<McpMetricsLatencyReport> {
    let report = McpMetricsLatencyReport {
        component: "metrics_latency".to_owned(),
        histograms: MetricRollupService.latency_histograms(rollup),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_mcp_report(state, "metrics-latency", "Metrics Latency", &report)?;
    Ok(report)
}

pub(super) fn mcp_metrics_cost_report(state: &McpState) -> Result<McpMetricsCostReport> {
    let report = McpMetricsCostReport {
        component: "metrics_cost".to_owned(),
        cost: CostLedgerService.ledger(
            project_id_from_label("eliot-governor"),
            MetricWindow::OneRun,
        ),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_mcp_report(state, "metrics-cost", "Metrics Cost", &report)?;
    Ok(report)
}

pub(super) fn mcp_metrics_quality_report(state: &McpState) -> Result<McpMetricsQualityReport> {
    let report = McpMetricsQualityReport {
        component: "metrics_quality".to_owned(),
        signals: QualitySignalService.signals(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_mcp_report(state, "metrics-quality", "Metrics Quality", &report)?;
    Ok(report)
}

pub(super) fn mcp_recent_incident_refs(state: &McpState) -> Vec<String> {
    if state
        .root
        .join("reports")
        .join("incident")
        .join("latest.json")
        .is_file()
    {
        vec!["reports/incident/latest.json".to_owned()]
    } else {
        Vec::new()
    }
}

pub(super) fn write_metrics_mcp_report<T>(
    state: &McpState,
    report_dir: &str,
    title: &str,
    value: &T,
) -> Result<()>
where
    T: serde::Serialize,
{
    write_json_report(
        &state
            .root
            .join("reports")
            .join(report_dir)
            .join("latest.json"),
        value,
    )?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join(report_dir)
            .join("latest.md"),
        &typed_report_markdown(title, value)?,
    )
}

struct McpEvalArtifacts {
    cases: Vec<EvalCase>,
    suite: EvalSuite,
    manifest: EvalDatasetManifest,
    profile: EvalRunProfile,
    integrity_receipt: BenchmarkIntegrityReceipt,
    mismatch_receipt: BenchmarkIntegrityReceipt,
    run: EvalRun,
    blocked_mutation_run: EvalRun,
    verdict: EvalVerdict,
    fixture_failure_cluster: EvalFailureCluster,
}

pub(super) fn mcp_diagnostic_baseline(artifacts: &McpEvalArtifacts) -> EvalBaseline {
    EvalBaselineService::create_diagnostic(
        &artifacts.suite,
        &artifacts.manifest,
        &artifacts.run,
        &artifacts.verdict,
        "mcp-read-only",
    )
}

pub(super) fn mcp_eval_artifacts(
    state: &McpState,
    suite_name: &str,
    mutation_attempt: Option<String>,
) -> Result<McpEvalArtifacts> {
    let project_id = project_id_from_label("eliot-governor");
    let cases = mcp_k0_cases();
    let mut suite = EvalSuiteService::create(EvalSuiteInput {
        project_id,
        name: suite_name.to_owned(),
        purpose: "K0 governed MCP deterministic no-mutation suite".to_owned(),
        cases: cases.iter().map(|case| case.eval_case_id).collect(),
        fixed: false,
        holdout: true,
        created_from_refs: vec!["phase-k0:mcp".to_owned()],
    });
    EvalSuiteService::freeze(&mut suite);
    let manifest = EvalDatasetManifestService::manifest(&suite, &cases);
    let profile = EvalRunnerService::deterministic_no_mutation_profile();
    let integrity_receipt = EvalDatasetManifestService::verify(&suite, &manifest);
    let mismatch_receipt = EvalDatasetManifestService::checksum_mismatch(&suite, &manifest);
    let run = EvalRunnerService::run(EvalRunInput {
        project_id,
        suite: suite.clone(),
        cases: cases.clone(),
        manifest: manifest.clone(),
        profile: profile.clone(),
        mutation_attempt,
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
    let artifacts = McpEvalArtifacts {
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
    };
    write_mcp_eval_reports(state, &artifacts, &experiment)?;
    Ok(artifacts)
}

pub(super) fn mcp_k0_cases() -> Vec<EvalCase> {
    EvalCaseService::k0_core_cases(
        project_id_from_label("eliot-governor"),
        Some(task_id_from_label("phase-k0-mcp")),
    )
}

pub(super) fn write_mcp_eval_reports(
    state: &McpState,
    artifacts: &McpEvalArtifacts,
    experiment: &eliot_types::HarnessExperimentRecord,
) -> Result<()> {
    write_eval_report_json_md(
        state,
        "eval-cases",
        "Eval Cases",
        &json!({ "component": "eval_cases", "cases": artifacts.cases }),
    )?;
    write_eval_report_json_md(
        state,
        "eval-suites",
        "Eval Suites",
        &json!({
            "component": "eval_suites",
            "suites": [artifacts.suite.clone()],
            "latest": artifacts.suite,
            "manifest": artifacts.manifest
        }),
    )?;
    write_eval_report_json_md(
        state,
        "eval-runs",
        "Eval Runs",
        &json!({
            "component": "eval_runs",
            "run": artifacts.run,
            "profile": artifacts.profile,
            "blocked_mutation_run": artifacts.blocked_mutation_run,
            "experiment": experiment
        }),
    )?;
    write_eval_report_json_md(
        state,
        "eval-verdicts",
        "Eval Verdicts",
        &json!({ "component": "eval_verdicts", "verdict": artifacts.verdict }),
    )?;
    write_eval_report_json_md(
        state,
        "eval-failures",
        "Eval Failures",
        &json!({
            "component": "eval_failures",
            "clusters": [artifacts.fixture_failure_cluster.clone()]
        }),
    )?;
    write_eval_report_json_md(
        state,
        "benchmark-integrity",
        "Benchmark Integrity",
        &json!({
            "component": "benchmark_integrity",
            "valid_receipt": artifacts.integrity_receipt,
            "mismatch_receipt": artifacts.mismatch_receipt
        }),
    )
}

pub(super) fn write_eval_report_json_md<T: serde::Serialize>(
    state: &McpState,
    dir: &str,
    title: &str,
    value: &T,
) -> Result<()> {
    let json_path = state.root.join("reports").join(dir).join("latest.json");
    let markdown_path = state.root.join("reports").join(dir).join("latest.md");
    write_json_report(&json_path, value)?;
    write_markdown_report(
        &markdown_path,
        &format!(
            "# {title}\n\n- profile: `deterministic-no-mutation`\n- authority: `report-only; no mutation authority`\n"
        ),
    )
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
        other => anyhow::bail!("unknown eval family: {other}"),
    }
}
