#![allow(clippy::expect_used)]

use eliot_engine::{
    CostLedgerService, MetricRecorderService, MetricRegistryService, MetricRollupService,
    MetricsDoctorIntegration, MetricsMcpBoundaryService, QualitySignalService,
    RuntimeDashboardService, SloService, TelemetryEventService, VerificationProfileService,
};
use eliot_types::{
    DashboardHealthStatus, MetricDefinition, MetricLabel, MetricLabelDefinition,
    MetricRedactionPolicy, MetricWindow, ProjectId, QualitySignalKind, SloObjective,
    TelemetryEventKind, TelemetryRollup,
};

#[test]
fn metric_definitions_created() {
    let definitions = definitions();

    assert!(!definitions.is_empty());
    assert!(
        definitions
            .iter()
            .any(|definition| definition.metric_id == "mcp.p95_latency_ms")
    );
}

#[test]
fn metric_registry_lists_builtin_categories() {
    let categories = MetricRegistryService.categories();

    for category in [
        "mcp",
        "cli",
        "ipc",
        "service",
        "adapter",
        "external_review",
        "memory",
        "context",
        "action",
        "patch",
        "verifier",
        "completion",
        "incident",
        "eval",
        "verify",
        "sleep",
        "replay",
        "skill",
    ] {
        assert!(categories.contains(&category.to_owned()));
    }
}

#[test]
fn metric_registry_rejects_secret_labels() {
    let mut definition = mcp_latency_definition();
    definition.labels.push(MetricLabelDefinition {
        name: "api_token".to_owned(),
        allowed_values: Vec::new(),
        high_cardinality: false,
        secret_risk: true,
    });

    assert!(
        MetricRegistryService
            .validate_definition(&definition)
            .is_err()
    );
}

#[test]
fn metric_registry_rejects_high_cardinality_by_default() {
    let mut definition = mcp_latency_definition();
    definition.labels.push(MetricLabelDefinition {
        name: "request_id".to_owned(),
        allowed_values: Vec::new(),
        high_cardinality: true,
        secret_risk: false,
    });

    assert!(
        MetricRegistryService
            .validate_definition(&definition)
            .is_err()
    );
}

#[test]
fn metric_recorder_records_sample() {
    let sample = MetricRecorderService
        .record_sample(
            &mcp_latency_definition(),
            42.0,
            labels("mcp", "tools/list"),
            Some("trace:m0".to_owned()),
            Some("metric:m0".to_owned()),
            None,
        )
        .expect("sample");

    assert_eq!(sample.metric_id, "mcp.p95_latency_ms");
    assert!((sample.value - 42.0).abs() < f64::EPSILON);
    assert_eq!(sample.trace_id.as_deref(), Some("trace:m0"));
}

#[test]
fn metric_recorder_redacts_labels() {
    let mut definition = mcp_latency_definition();
    definition.redaction = MetricRedactionPolicy::HashIdentifiers;

    let sample = MetricRecorderService
        .record_sample(
            &definition,
            42.0,
            labels("mcp", "tools/list"),
            None,
            None,
            None,
        )
        .expect("redacted sample");

    assert!(sample.labels.iter().any(|label| label.redacted));
    assert!(
        sample
            .labels
            .iter()
            .any(|label| label.name == "operation" && label.value.starts_with("hash:"))
    );
}

#[test]
fn metric_recorder_rejects_raw_payload() {
    let result = MetricRecorderService.record_sample(
        &mcp_latency_definition(),
        42.0,
        labels("mcp", "tools/list"),
        None,
        None,
        Some("raw artifact payload"),
    );

    assert!(result.is_err());
}

#[test]
fn telemetry_event_created() {
    let sample = sample(42.0);
    let event = TelemetryEventService
        .create_event(
            TelemetryEventKind::McpCall,
            "mcp",
            Some("trace:m0".to_owned()),
            Some("metric:m0".to_owned()),
            Vec::new(),
            vec![sample],
        )
        .expect("telemetry event");

    assert_eq!(event.event_kind, TelemetryEventKind::McpCall);
    assert_eq!(event.component, "mcp");
}

#[test]
fn telemetry_event_to_metric_sample() {
    let sample = sample(42.0);
    let event = TelemetryEventService
        .create_event(
            TelemetryEventKind::McpCall,
            "mcp",
            None,
            None,
            Vec::new(),
            vec![sample.clone()],
        )
        .expect("telemetry event");

    assert_eq!(TelemetryEventService.metric_samples(&event), vec![sample]);
}

#[test]
fn metric_rollup_generated() {
    let rollup = rollup();

    assert!(!rollup.metric_rollups.is_empty());
    assert!(
        rollup
            .metric_rollups
            .iter()
            .any(|metric| metric.metric_id == "mcp.p95_latency_ms")
    );
}

#[test]
fn metric_rollup_computes_p50_p95_p99() {
    let samples = [10.0, 20.0, 30.0]
        .into_iter()
        .map(sample)
        .collect::<Vec<_>>();

    let rollup = MetricRollupService.rollup(ProjectId::new_v7(), MetricWindow::OneRun, &samples);
    let metric = rollup
        .metric_rollups
        .iter()
        .find(|metric| metric.metric_id == "mcp.p95_latency_ms")
        .expect("mcp rollup");

    assert_eq!(metric.p50, Some(20.0));
    assert_eq!(metric.p95, Some(30.0));
    assert_eq!(metric.p99, Some(30.0));
}

#[test]
fn latency_histogram_generated() {
    let histograms = MetricRollupService.latency_histograms(&rollup());

    assert!(!histograms.is_empty());
    assert!(
        histograms
            .iter()
            .any(|histogram| histogram.component == "mcp")
    );
}

#[test]
fn slo_definitions_created() {
    let definitions = SloService.definitions();

    assert!(definitions.len() >= 8);
    assert!(
        definitions
            .iter()
            .any(|definition| definition.objective == SloObjective::MaxP95LatencyMs)
    );
}

#[test]
fn slo_evaluation_generated() {
    let definitions = SloService.definitions();
    let evaluations = SloService.evaluate(&definitions, &rollup());

    assert!(!evaluations.is_empty());
    assert!(
        evaluations
            .iter()
            .all(|evaluation| !evaluation.evidence_refs.is_empty())
    );
}

#[test]
fn slo_breach_detected_fixture() {
    let definition = SloService
        .definitions()
        .into_iter()
        .find(|definition| definition.slo_id == "mcp.p95_latency_ms")
        .expect("mcp slo");
    let evaluation = SloService.evaluate_observed(
        &definition,
        definition.threshold + 1.0,
        vec!["fixture".into()],
    );

    assert!(evaluation.breached);
}

#[test]
fn cost_ledger_generated() {
    let ledger = CostLedgerService.ledger(ProjectId::new_v7(), MetricWindow::OneRun);

    assert!(!ledger.entries.is_empty());
    assert!(ledger.total_estimated_cost.abs() < f64::EPSILON);
}

#[test]
fn cost_ledger_mock_provider_zero_cost() {
    let ledger = CostLedgerService.ledger(ProjectId::new_v7(), MetricWindow::OneRun);

    assert!(ledger.entries.iter().any(|entry| {
        entry.provider_id.as_deref() == Some("mock-auditor") && entry.estimated_cost == 0.0
    }));
}

#[test]
fn quality_signals_generated() {
    let signals = QualitySignalService.signals();

    assert!(!signals.is_empty());
    assert!(
        signals
            .iter()
            .any(|signal| signal.signal_kind == QualitySignalKind::EvalPassRate)
    );
    assert!(
        signals
            .iter()
            .any(|signal| signal.signal_kind == QualitySignalKind::VerificationPassRate)
    );
}

#[test]
fn runtime_dashboard_generated() {
    let dashboard = dashboard(Vec::new());

    assert!(dashboard.health_summary.ready);
    assert_eq!(
        dashboard.health_summary.status,
        DashboardHealthStatus::Healthy
    );
    assert!(!dashboard.latency.is_empty());
}

#[test]
fn dashboard_includes_eval_and_verification_refs() {
    let dashboard = dashboard(Vec::new());

    assert_eq!(
        dashboard.eval_summary_ref.as_deref(),
        Some("reports/eval-report/latest.json")
    );
    assert_eq!(
        dashboard.verification_summary_ref.as_deref(),
        Some("reports/verification/latest.json")
    );
}

#[test]
fn dashboard_includes_incident_summary() {
    let dashboard = dashboard(vec!["incident:blocking:fixture".to_owned()]);

    assert_eq!(
        dashboard.health_summary.status,
        DashboardHealthStatus::IncidentLockdown
    );
    assert_eq!(dashboard.health_summary.blocking_incidents.len(), 1);
}

#[test]
fn doctor_reports_metrics_status() {
    let definitions = definitions();
    let dashboard = dashboard(Vec::new());
    let trends = RuntimeDashboardService.trends(&dashboard);
    let status = MetricsDoctorIntegration.status(&definitions, Some(&dashboard), &trends);

    assert!(status.metric_registry_ready);
    assert!(status.last_dashboard_ref.is_some());
    assert!(status.missing_metric_definitions.is_empty());
    assert!(status.redaction_violations.is_empty());
}

#[test]
fn mcp_exposes_only_safe_metrics_tools() {
    assert!(MetricsMcpBoundaryService.exposes_only_safe_metrics_tools(&[
        "eliot_metrics_registry",
        "eliot_metrics_dashboard",
        "eliot_metrics_slo",
        "eliot_metrics_latency",
        "eliot_metrics_cost",
        "eliot_metrics_quality",
        "eliot_metrics_report",
    ]));
}

#[test]
fn mcp_exposes_no_raw_ingest_remote_export_tools() {
    assert!(
        MetricsMcpBoundaryService.exposes_no_raw_ingest_remote_export_tools(&[
            "eliot_metrics_registry",
            "eliot_metrics_dashboard",
            "eliot_metrics_slo",
            "eliot_metrics_latency",
            "eliot_metrics_cost",
            "eliot_metrics_quality",
            "eliot_metrics_report",
        ])
    );
    assert!(
        !MetricsMcpBoundaryService.exposes_no_raw_ingest_remote_export_tools(&[
            "eliot_metrics_registry",
            "eliot_metrics_export_remote",
        ])
    );
}

#[test]
fn phase_b_c_d_e_f0_f1_f2_f3_g0_g1_g2_h0_h1_i0_i1_i2_j0_k0_k1_k2_non_regression() {
    assert!(!VerificationProfileService.profiles().is_empty());
    assert!(!MetricRegistryService.definitions().is_empty());
}

fn definitions() -> Vec<MetricDefinition> {
    MetricRegistryService.definitions()
}

fn mcp_latency_definition() -> MetricDefinition {
    MetricRegistryService
        .find("mcp.p95_latency_ms")
        .expect("mcp latency definition")
}

fn sample(value: f64) -> eliot_types::MetricSample {
    MetricRecorderService
        .record_sample(
            &mcp_latency_definition(),
            value,
            labels("mcp", "tools/list"),
            None,
            None,
            None,
        )
        .expect("metric sample")
}

fn samples() -> Vec<eliot_types::MetricSample> {
    MetricRecorderService
        .smoke_samples(&definitions())
        .expect("smoke samples")
}

fn rollup() -> TelemetryRollup {
    MetricRollupService.rollup(ProjectId::new_v7(), MetricWindow::OneRun, &samples())
}

fn dashboard(recent_incidents: Vec<String>) -> eliot_types::RuntimeDashboard {
    let rollup = rollup();
    let latency = MetricRollupService.latency_histograms(&rollup);
    let definitions = SloService.definitions();
    let slo = SloService.evaluate(&definitions, &rollup);
    RuntimeDashboardService.dashboard(
        ProjectId::new_v7(),
        latency,
        CostLedgerService.ledger(ProjectId::new_v7(), MetricWindow::OneRun),
        slo,
        QualitySignalService.signals(),
        recent_incidents,
        Some("reports/eval-report/latest.json".to_owned()),
        Some("reports/verification/latest.json".to_owned()),
    )
}

fn labels(component: &str, operation: &str) -> Vec<MetricLabel> {
    vec![
        MetricLabel {
            name: "component".to_owned(),
            value: component.to_owned(),
            redacted: false,
        },
        MetricLabel {
            name: "operation".to_owned(),
            value: operation.to_owned(),
            redacted: false,
        },
        MetricLabel {
            name: "status".to_owned(),
            value: "ok".to_owned(),
            redacted: false,
        },
    ]
}
