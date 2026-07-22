use crate::EngineError;
use eliot_types::{
    CostLedger, CostLedgerEntry, DashboardHealthStatus, DashboardHealthSummary, LatencyHistogram,
    MetricDefinition, MetricKind, MetricLabel, MetricLabelDefinition, MetricRedactionPolicy,
    MetricRetentionPolicy, MetricRollup, MetricSample, MetricUnit, MetricWindow,
    MetricsDoctorStatus, OperationalTrend, OperationalTrendDirection, ProjectId, QualitySignal,
    QualitySignalKind, RuntimeDashboard, SloBreachSeverity, SloDefinition, SloEvaluation,
    SloObjective, TelemetryEvent, TelemetryEventKind, TelemetryRollup,
};
use std::collections::BTreeMap;
use time::OffsetDateTime;

pub struct MetricRegistryService;
pub struct MetricRecorderService;
pub struct TelemetryEventService;
pub struct MetricRollupService;
pub struct SloService;
pub struct CostLedgerService;
pub struct QualitySignalService;
pub struct RuntimeDashboardService;
pub struct MetricsDoctorIntegration;
pub struct MetricsMcpBoundaryService;

impl MetricRegistryService {
    #[must_use]
    pub fn definitions(&self) -> Vec<MetricDefinition> {
        builtin_metric_definitions()
    }

    pub fn validate_definition(&self, definition: &MetricDefinition) -> Result<(), EngineError> {
        for label in &definition.labels {
            if label.secret_risk {
                return Err(rejected(
                    "metric-registry",
                    &format!("secret-risk metric label rejected: {}", label.name),
                ));
            }
            if label.high_cardinality {
                return Err(rejected(
                    "metric-registry",
                    &format!("high-cardinality metric label rejected: {}", label.name),
                ));
            }
        }
        Ok(())
    }

    pub fn find(&self, metric_id: &str) -> Result<MetricDefinition, EngineError> {
        self.definitions()
            .into_iter()
            .find(|definition| definition.metric_id == metric_id)
            .ok_or_else(|| rejected("metric-registry", &format!("unknown metric: {metric_id}")))
    }

    #[must_use]
    pub fn categories(&self) -> Vec<String> {
        self.definitions()
            .into_iter()
            .map(|definition| definition.component)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

impl MetricRecorderService {
    pub fn record_sample(
        &self,
        definition: &MetricDefinition,
        value: f64,
        labels: Vec<MetricLabel>,
        trace_id: Option<String>,
        source_ref: Option<String>,
        raw_payload: Option<&str>,
    ) -> Result<MetricSample, EngineError> {
        if raw_payload.is_some_and(|payload| !payload.trim().is_empty()) {
            return Err(rejected(
                "metric-recorder",
                "raw payload metric ingestion is not allowed",
            ));
        }
        MetricRegistryService.validate_definition(definition)?;
        let labels = self.redact_labels(definition, labels)?;
        Ok(MetricSample {
            sample_id: new_id("metric-sample"),
            metric_id: definition.metric_id.clone(),
            value,
            labels,
            trace_id,
            source_ref,
            observed_at: OffsetDateTime::now_utc(),
        })
    }

    pub fn smoke_samples(
        &self,
        definitions: &[MetricDefinition],
    ) -> Result<Vec<MetricSample>, EngineError> {
        let mut samples = Vec::new();
        for (metric_id, value, operation) in [
            ("mcp.p95_latency_ms", 85.0, "tools/list"),
            ("cli.command_count", 1.0, "verify change-gate"),
            ("ipc.p95_latency_ms", 25.0, "status"),
            ("context.packet_bytes", 14_000.0, "compile_l3"),
            ("verify.change_gate_runtime_ms", 850_000.0, "change-gate"),
            ("eval.pass_rate", 1.0, "core-smoke"),
            ("incident.blocking_count", 0.0, "incident-list"),
            ("external_review.malformed_rate", 0.0, "mock-review"),
        ] {
            let definition = definitions
                .iter()
                .find(|definition| definition.metric_id == metric_id)
                .ok_or_else(|| {
                    rejected(
                        "metric-recorder",
                        &format!("smoke metric missing definition: {metric_id}"),
                    )
                })?;
            samples.push(self.record_sample(
                definition,
                value,
                vec![
                    label("component", &definition.component),
                    label("operation", operation),
                    label("status", "ok"),
                ],
                Some("trace:m0-smoke".to_owned()),
                Some(format!("metric:{metric_id}:smoke")),
                None,
            )?);
        }
        Ok(samples)
    }

    pub fn redact_labels(
        &self,
        definition: &MetricDefinition,
        labels: Vec<MetricLabel>,
    ) -> Result<Vec<MetricLabel>, EngineError> {
        for label in &labels {
            if secret_like(&label.name) || secret_like(&label.value) {
                return Err(rejected(
                    "metric-recorder",
                    &format!("secret-like metric label rejected: {}", label.name),
                ));
            }
            let allowed = definition
                .labels
                .iter()
                .any(|defined| defined.name == label.name);
            if !allowed {
                return Err(rejected(
                    "metric-recorder",
                    &format!("unknown metric label rejected: {}", label.name),
                ));
            }
        }
        Ok(match definition.redaction {
            MetricRedactionPolicy::NoPayloads => labels,
            MetricRedactionPolicy::HashIdentifiers => labels
                .into_iter()
                .map(|mut label| {
                    if label.name.ends_with("_id") || label.name == "operation" {
                        label.value = format!("hash:{}", hash_value(&label.value));
                        label.redacted = true;
                    }
                    label
                })
                .collect(),
            MetricRedactionPolicy::RedactLabels => labels
                .into_iter()
                .map(|label| MetricLabel {
                    name: label.name,
                    value: "redacted".to_owned(),
                    redacted: true,
                })
                .collect(),
            MetricRedactionPolicy::AggregateOnly => Vec::new(),
        })
    }
}

impl TelemetryEventService {
    pub fn create_event(
        &self,
        event_kind: TelemetryEventKind,
        component: &str,
        trace_id: Option<String>,
        source_ref: Option<String>,
        labels: Vec<MetricLabel>,
        measurements: Vec<MetricSample>,
    ) -> Result<TelemetryEvent, EngineError> {
        if labels
            .iter()
            .any(|label| secret_like(&label.name) || secret_like(&label.value))
        {
            return Err(rejected(
                "telemetry-event",
                "secret-like telemetry label rejected",
            ));
        }
        Ok(TelemetryEvent {
            event_id: new_id("telemetry-event"),
            event_kind,
            component: component.to_owned(),
            trace_id,
            source_ref,
            redaction_applied: measurements
                .iter()
                .flat_map(|sample| sample.labels.iter())
                .any(|label| label.redacted),
            labels,
            measurements,
            created_at: OffsetDateTime::now_utc(),
        })
    }

    #[must_use]
    pub fn metric_samples(&self, event: &TelemetryEvent) -> Vec<MetricSample> {
        event.measurements.clone()
    }
}

impl MetricRollupService {
    #[must_use]
    pub fn rollup(
        &self,
        project_id: ProjectId,
        window: MetricWindow,
        samples: &[MetricSample],
    ) -> TelemetryRollup {
        let mut grouped: BTreeMap<String, Vec<f64>> = BTreeMap::new();
        for sample in samples {
            grouped
                .entry(sample.metric_id.clone())
                .or_default()
                .push(sample.value);
        }
        let metric_rollups = grouped
            .into_iter()
            .map(|(metric_id, values)| rollup_values(&metric_id, window, &values))
            .collect();
        TelemetryRollup {
            rollup_id: new_id("telemetry-rollup"),
            project_id,
            window,
            metric_rollups,
            generated_at: OffsetDateTime::now_utc(),
        }
    }

    #[must_use]
    pub fn latency_histograms(&self, rollup: &TelemetryRollup) -> Vec<LatencyHistogram> {
        rollup
            .metric_rollups
            .iter()
            .filter(|metric| metric.metric_id.ends_with("latency_ms"))
            .map(|metric| LatencyHistogram {
                histogram_id: new_id("latency-histogram"),
                component: metric
                    .metric_id
                    .split('.')
                    .next()
                    .unwrap_or("unknown")
                    .to_owned(),
                operation: metric.metric_id.clone(),
                count: metric.count,
                p50_ms: metric.p50.unwrap_or(metric.avg),
                p95_ms: metric.p95.unwrap_or(metric.max),
                p99_ms: metric.p99.unwrap_or(metric.max),
                max_ms: metric.max,
                generated_at: OffsetDateTime::now_utc(),
            })
            .collect()
    }
}

impl SloService {
    #[must_use]
    pub fn definitions(&self) -> Vec<SloDefinition> {
        builtin_slo_definitions()
    }

    #[must_use]
    pub fn evaluate(
        &self,
        definitions: &[SloDefinition],
        rollup: &TelemetryRollup,
    ) -> Vec<SloEvaluation> {
        definitions
            .iter()
            .filter(|definition| definition.enabled)
            .map(|definition| {
                let observed = observed_for_slo(definition, rollup);
                self.evaluate_observed(definition, observed.0, observed.1)
            })
            .collect()
    }

    #[must_use]
    pub fn evaluate_observed(
        &self,
        definition: &SloDefinition,
        observed_value: f64,
        evidence_refs: Vec<String>,
    ) -> SloEvaluation {
        let breached = match definition.objective {
            SloObjective::MinEvalPassRate => observed_value < definition.threshold,
            _ => observed_value > definition.threshold,
        };
        SloEvaluation {
            evaluation_id: new_id("slo-evaluation"),
            slo_id: definition.slo_id.clone(),
            observed_value,
            threshold: definition.threshold,
            breached,
            severity: definition.severity_if_breached,
            evidence_refs,
            evaluated_at: OffsetDateTime::now_utc(),
        }
    }
}

impl CostLedgerService {
    #[must_use]
    pub fn ledger(&self, project_id: ProjectId, window: MetricWindow) -> CostLedger {
        let entries = vec![
            CostLedgerEntry {
                entry_id: new_id("cost-entry"),
                component: "external_review".to_owned(),
                operation: "mock_provider".to_owned(),
                provider_id: Some("mock-auditor".to_owned()),
                estimated_input_tokens: None,
                estimated_output_tokens: None,
                estimated_cost: 0.0,
                source_ref: Some("external-review:mock".to_owned()),
            },
            CostLedgerEntry {
                entry_id: new_id("cost-entry"),
                component: "verify".to_owned(),
                operation: "change-gate-runtime".to_owned(),
                provider_id: None,
                estimated_input_tokens: None,
                estimated_output_tokens: None,
                estimated_cost: 0.0,
                source_ref: Some("verification:change-gate".to_owned()),
            },
        ];
        CostLedger {
            ledger_id: new_id("cost-ledger"),
            project_id,
            window,
            total_estimated_cost: entries.iter().map(|entry| entry.estimated_cost).sum(),
            unit: "local-estimate".to_owned(),
            entries,
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

impl QualitySignalService {
    #[must_use]
    pub fn signals(&self) -> Vec<QualitySignal> {
        vec![
            signal(
                "eval",
                QualitySignalKind::EvalPassRate,
                1.0,
                "eval-gates:fast-deterministic",
            ),
            signal(
                "verify",
                QualitySignalKind::VerificationPassRate,
                1.0,
                "verification-verdicts:change-gate",
            ),
            signal(
                "completion",
                QualitySignalKind::CompletionGateBlockRate,
                0.0,
                "completion-gate:latest",
            ),
            signal(
                "external_review",
                QualitySignalKind::ExternalReviewMalformedRate,
                0.0,
                "external-review-normalization:mock",
            ),
        ]
    }
}

impl RuntimeDashboardService {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn dashboard(
        &self,
        project_id: ProjectId,
        latency: Vec<LatencyHistogram>,
        cost: CostLedger,
        slo_evaluations: Vec<SloEvaluation>,
        quality_signals: Vec<QualitySignal>,
        recent_incidents: Vec<String>,
        eval_summary_ref: Option<String>,
        verification_summary_ref: Option<String>,
    ) -> RuntimeDashboard {
        let blocking_incidents = recent_incidents
            .iter()
            .filter(|incident| incident.contains("blocking"))
            .cloned()
            .collect::<Vec<_>>();
        let degraded_reasons = slo_evaluations
            .iter()
            .filter(|evaluation| evaluation.breached)
            .map(|evaluation| format!("slo_breach:{}", evaluation.slo_id))
            .collect::<Vec<_>>();
        let status = if !blocking_incidents.is_empty() {
            DashboardHealthStatus::IncidentLockdown
        } else if degraded_reasons.is_empty() {
            DashboardHealthStatus::Healthy
        } else {
            DashboardHealthStatus::Degraded
        };
        RuntimeDashboard {
            dashboard_id: new_id("runtime-dashboard"),
            project_id,
            generated_at: OffsetDateTime::now_utc(),
            health_summary: DashboardHealthSummary {
                ready: matches!(status, DashboardHealthStatus::Healthy),
                status,
                degraded_reasons,
                blocking_incidents,
                last_change_gate_ref: Some("verification:change-gate".to_owned()),
            },
            latency,
            costs: Some(cost),
            slo_evaluations,
            quality_signals,
            recent_incidents,
            eval_summary_ref,
            verification_summary_ref,
            recommendations: vec![
                "keep metrics local and redacted".to_owned(),
                "review SLO breaches before enabling real providers".to_owned(),
            ],
        }
    }

    #[must_use]
    pub fn trends(&self, dashboard: &RuntimeDashboard) -> Vec<OperationalTrend> {
        let direction = if dashboard
            .slo_evaluations
            .iter()
            .any(|evaluation| evaluation.breached)
        {
            OperationalTrendDirection::Degrading
        } else {
            OperationalTrendDirection::Stable
        };
        vec![OperationalTrend {
            trend_id: new_id("operational-trend"),
            component: "runtime".to_owned(),
            metric_id: "slo.overall".to_owned(),
            direction,
            evidence_refs: vec![format!("dashboard:{}", dashboard.dashboard_id)],
            generated_at: OffsetDateTime::now_utc(),
        }]
    }
}

impl MetricsDoctorIntegration {
    #[must_use]
    pub fn status(
        &self,
        definitions: &[MetricDefinition],
        dashboard: Option<&RuntimeDashboard>,
        trends: &[OperationalTrend],
    ) -> MetricsDoctorStatus {
        let slo_breaches = dashboard
            .into_iter()
            .flat_map(|dashboard| dashboard.slo_evaluations.iter())
            .filter(|evaluation| evaluation.breached)
            .map(|evaluation| evaluation.slo_id.clone())
            .collect::<Vec<_>>();
        MetricsDoctorStatus {
            metric_registry_ready: !definitions.is_empty(),
            last_dashboard_ref: dashboard
                .map(|dashboard| format!("dashboard:{}", dashboard.dashboard_id)),
            slo_breaches,
            missing_metric_definitions: missing_metric_definitions(definitions),
            high_cardinality_label_violations: Vec::new(),
            redaction_violations: Vec::new(),
            degrading_operational_trends: trends
                .iter()
                .filter(|trend| trend.direction == OperationalTrendDirection::Degrading)
                .map(|trend| trend.trend_id.clone())
                .collect(),
        }
    }
}

impl MetricsMcpBoundaryService {
    #[must_use]
    pub fn exposes_only_safe_metrics_tools(&self, tools: &[&str]) -> bool {
        let expected = [
            "eliot_metrics_registry",
            "eliot_metrics_dashboard",
            "eliot_metrics_slo",
            "eliot_metrics_latency",
            "eliot_metrics_cost",
            "eliot_metrics_quality",
            "eliot_metrics_report",
        ];
        expected.iter().all(|tool| tools.contains(tool))
            && tools
                .iter()
                .filter(|tool| tool.contains("metrics"))
                .all(|tool| expected.contains(tool))
    }

    #[must_use]
    pub fn exposes_no_raw_ingest_remote_export_tools(&self, tools: &[&str]) -> bool {
        let denied = [
            "record_raw",
            "ingest_raw",
            "raw_payload",
            "logs_raw",
            "secret_metric",
            "export_remote",
            "raw_sql",
            "raw_db",
            "raw_shell",
        ];
        tools
            .iter()
            .all(|tool| denied.iter().all(|needle| !tool.contains(needle)))
    }
}

#[allow(clippy::too_many_lines)]
fn builtin_metric_definitions() -> Vec<MetricDefinition> {
    [
        (
            "mcp.p95_latency_ms",
            "mcp",
            MetricKind::Timer,
            MetricUnit::Milliseconds,
        ),
        (
            "cli.command_count",
            "cli",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "ipc.p95_latency_ms",
            "ipc",
            MetricKind::Timer,
            MetricUnit::Milliseconds,
        ),
        (
            "service.ready",
            "service",
            MetricKind::Gauge,
            MetricUnit::Ratio,
        ),
        (
            "adapter.job_count",
            "adapter",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "external_review.malformed_rate",
            "external_review",
            MetricKind::Ratio,
            MetricUnit::Ratio,
        ),
        (
            "memory.write_count",
            "memory",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "context.packet_bytes",
            "context",
            MetricKind::Gauge,
            MetricUnit::Bytes,
        ),
        (
            "action.block_rate",
            "action",
            MetricKind::Ratio,
            MetricUnit::Ratio,
        ),
        (
            "patch.run_count",
            "patch",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "verifier.run_ms",
            "verifier",
            MetricKind::Timer,
            MetricUnit::Milliseconds,
        ),
        (
            "completion.false_done_rate",
            "completion",
            MetricKind::Ratio,
            MetricUnit::Ratio,
        ),
        (
            "incident.blocking_count",
            "incident",
            MetricKind::Gauge,
            MetricUnit::Count,
        ),
        (
            "eval.pass_rate",
            "eval",
            MetricKind::Ratio,
            MetricUnit::Ratio,
        ),
        (
            "verify.change_gate_runtime_ms",
            "verify",
            MetricKind::Timer,
            MetricUnit::Milliseconds,
        ),
        (
            "sleep.run_count",
            "sleep",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "replay.pass_rate",
            "replay",
            MetricKind::Ratio,
            MetricUnit::Ratio,
        ),
        (
            "skill.activation_count",
            "skill",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_requests_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_decisions_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_denials_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_executions_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_shadow_recommendations_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_recursion_denied_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_budget_denied_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_provider_failures_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_outcomes_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_unique_findings_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_accepted_findings_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_duplicate_findings_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_runtime_ms",
            "delegation",
            MetricKind::Timer,
            MetricUnit::Milliseconds,
        ),
        (
            "delegation_live_tree_violation_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_authority_violation_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_recursive_execution_total",
            "delegation",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_calibration_samples_total",
            "delegation_calibration",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_calibration_complete_samples_total",
            "delegation_calibration",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_calibration_shadow_total",
            "delegation_calibration",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_calibration_counterfactual_total",
            "delegation_calibration",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_calibration_findings_total",
            "delegation_calibration",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_calibration_outcomes_total",
            "delegation_calibration",
            MetricKind::Counter,
            MetricUnit::Count,
        ),
        (
            "delegation_calibration_readiness",
            "delegation_calibration",
            MetricKind::Gauge,
            MetricUnit::Count,
        ),
        (
            "delegation_calibration_candidate_status",
            "delegation_calibration",
            MetricKind::Gauge,
            MetricUnit::Count,
        ),
        (
            "delegation_calibration_promotion_status",
            "delegation_calibration",
            MetricKind::Gauge,
            MetricUnit::Count,
        ),
    ]
    .into_iter()
    .map(|(metric_id, component, kind, unit)| metric(metric_id, component, kind, unit))
    .collect()
}

fn builtin_slo_definitions() -> Vec<SloDefinition> {
    vec![
        slo(
            "mcp.p95_latency_ms",
            "mcp",
            SloObjective::MaxP95LatencyMs,
            500.0,
        ),
        slo(
            "ipc.p95_latency_ms",
            "ipc",
            SloObjective::MaxP95LatencyMs,
            100.0,
        ),
        slo(
            "context.max_packet_bytes",
            "context",
            SloObjective::MaxContextPacketBytes,
            64_000.0,
        ),
        slo(
            "eval.min_pass_rate",
            "eval",
            SloObjective::MinEvalPassRate,
            1.0,
        ),
        slo(
            "verify.max_change_gate_runtime_ms",
            "verify",
            SloObjective::MaxVerificationRuntimeMs,
            1_200_000.0,
        ),
        slo(
            "external_review.max_malformed_rate",
            "external_review",
            SloObjective::MaxExternalCandidateNoiseRate,
            0.0,
        ),
        slo(
            "incident.max_blocking_count",
            "incident",
            SloObjective::MaxIncidentRate,
            0.0,
        ),
        slo(
            "completion.max_false_done_rate",
            "completion",
            SloObjective::MaxErrorRate,
            0.0,
        ),
    ]
}

fn metric(
    metric_id: &str,
    component: &str,
    kind: MetricKind,
    unit: MetricUnit,
) -> MetricDefinition {
    MetricDefinition {
        metric_id: metric_id.to_owned(),
        name: metric_id.to_owned(),
        description: format!("Local redacted {component} metric"),
        kind,
        unit,
        component: component.to_owned(),
        labels: safe_label_definitions(),
        retention: MetricRetentionPolicy {
            hot_days: 7,
            rollup_days: 30,
            archive_days: Some(90),
        },
        redaction: MetricRedactionPolicy::HashIdentifiers,
        created_at: OffsetDateTime::now_utc(),
    }
}

fn safe_label_definitions() -> Vec<MetricLabelDefinition> {
    ["component", "operation", "status", "profile", "provider_id"]
        .into_iter()
        .map(|name| MetricLabelDefinition {
            name: name.to_owned(),
            allowed_values: Vec::new(),
            high_cardinality: false,
            secret_risk: false,
        })
        .collect()
}

fn slo(slo_id: &str, component: &str, objective: SloObjective, threshold: f64) -> SloDefinition {
    SloDefinition {
        slo_id: slo_id.to_owned(),
        name: slo_id.to_owned(),
        component: component.to_owned(),
        objective,
        threshold,
        window: MetricWindow::OneRun,
        severity_if_breached: SloBreachSeverity::Warning,
        enabled: true,
        created_at: OffsetDateTime::now_utc(),
    }
}

fn observed_for_slo(definition: &SloDefinition, rollup: &TelemetryRollup) -> (f64, Vec<String>) {
    let metric_id = match definition.objective {
        SloObjective::MaxP95LatencyMs if definition.component == "mcp" => "mcp.p95_latency_ms",
        SloObjective::MaxP95LatencyMs if definition.component == "ipc" => "ipc.p95_latency_ms",
        SloObjective::MaxContextPacketBytes => "context.packet_bytes",
        SloObjective::MinEvalPassRate => "eval.pass_rate",
        SloObjective::MaxVerificationRuntimeMs => "verify.change_gate_runtime_ms",
        SloObjective::MaxExternalCandidateNoiseRate => "external_review.malformed_rate",
        SloObjective::MaxIncidentRate => "incident.blocking_count",
        SloObjective::MaxErrorRate => "completion.false_done_rate",
        _ => "",
    };
    rollup
        .metric_rollups
        .iter()
        .find(|rollup| rollup.metric_id == metric_id)
        .map_or_else(
            || (0.0, vec![format!("insufficient_data:{metric_id}")]),
            |rollup| {
                let value = match definition.objective {
                    SloObjective::MaxP95LatencyMs => rollup.p95.unwrap_or(rollup.max),
                    SloObjective::MaxP99LatencyMs => rollup.p99.unwrap_or(rollup.max),
                    _ => rollup.avg,
                };
                (value, vec![format!("metric_rollup:{}", rollup.rollup_id)])
            },
        )
}

fn rollup_values(metric_id: &str, window: MetricWindow, values: &[f64]) -> MetricRollup {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let count = u64::try_from(sorted.len()).unwrap_or(u64::MAX);
    let min = sorted.first().copied().unwrap_or(0.0);
    let max = sorted.last().copied().unwrap_or(0.0);
    let avg = if sorted.is_empty() {
        0.0
    } else {
        let denominator = u32::try_from(sorted.len()).map_or(f64::from(u32::MAX), f64::from);
        sorted.iter().sum::<f64>() / denominator
    };
    MetricRollup {
        rollup_id: new_id("metric-rollup"),
        metric_id: metric_id.to_owned(),
        window,
        count,
        min,
        max,
        avg,
        p50: percentile(&sorted, 0.50),
        p95: percentile(&sorted, 0.95),
        p99: percentile(&sorted, 0.99),
        started_at: OffsetDateTime::now_utc(),
        ended_at: OffsetDateTime::now_utc(),
    }
}

fn percentile(sorted: &[f64], percentile: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let max_index = sorted.len() - 1;
    let rank = if percentile <= 0.0 {
        0
    } else if percentile >= 1.0 {
        max_index
    } else if (percentile - 0.50).abs() < f64::EPSILON {
        max_index.div_ceil(2)
    } else if (percentile - 0.95).abs() < f64::EPSILON {
        max_index.saturating_mul(95).div_ceil(100)
    } else if (percentile - 0.99).abs() < f64::EPSILON {
        max_index.saturating_mul(99).div_ceil(100)
    } else {
        max_index
    };
    sorted.get(rank).copied()
}

fn signal(
    component: &str,
    signal_kind: QualitySignalKind,
    value: f64,
    evidence_ref: &str,
) -> QualitySignal {
    QualitySignal {
        signal_id: new_id("quality-signal"),
        component: component.to_owned(),
        signal_kind,
        value,
        evidence_refs: vec![evidence_ref.to_owned()],
        observed_at: OffsetDateTime::now_utc(),
    }
}

fn label(name: &str, value: &str) -> MetricLabel {
    MetricLabel {
        name: name.to_owned(),
        value: value.to_owned(),
        redacted: false,
    }
}

fn secret_like(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "secret",
        "token",
        "password",
        "credential",
        "raw_prompt",
        "raw_payload",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn hash_value(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex()[..16].to_owned()
}

fn missing_metric_definitions(definitions: &[MetricDefinition]) -> Vec<String> {
    let present = definitions
        .iter()
        .map(|definition| definition.component.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    [
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
    ]
    .into_iter()
    .filter(|component| !present.contains(component))
    .map(str::to_owned)
    .collect()
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}-{}", eliot_types::WriteId::new_v7())
}

fn rejected(service: &str, reason: &str) -> EngineError {
    EngineError::ServiceNotReady {
        service: service.to_owned(),
        reason: reason.to_owned(),
    }
}
