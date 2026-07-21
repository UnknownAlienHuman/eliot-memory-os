use crate::ProjectId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    Counter,
    Gauge,
    Histogram,
    Timer,
    Distribution,
    Ratio,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricUnit {
    Count,
    Bytes,
    Milliseconds,
    Seconds,
    Percent,
    Ratio,
    Tokens,
    Dollars,
    None,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricDefinition {
    pub metric_id: String,
    pub name: String,
    pub description: String,
    pub kind: MetricKind,
    pub unit: MetricUnit,
    pub component: String,
    pub labels: Vec<MetricLabelDefinition>,
    pub retention: MetricRetentionPolicy,
    pub redaction: MetricRedactionPolicy,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetricLabelDefinition {
    pub name: String,
    pub allowed_values: Vec<String>,
    pub high_cardinality: bool,
    pub secret_risk: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetricRetentionPolicy {
    pub hot_days: u32,
    pub rollup_days: u32,
    pub archive_days: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricRedactionPolicy {
    NoPayloads,
    HashIdentifiers,
    RedactLabels,
    AggregateOnly,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricSample {
    pub sample_id: String,
    pub metric_id: String,
    pub value: f64,
    pub labels: Vec<MetricLabel>,
    pub trace_id: Option<String>,
    pub source_ref: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetricLabel {
    pub name: String,
    pub value: String,
    pub redacted: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricSeries {
    pub series_id: String,
    pub metric_id: String,
    pub labels_hash: String,
    pub samples: Vec<MetricSample>,
    pub rollups: Vec<MetricRollup>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricRollup {
    pub rollup_id: String,
    pub metric_id: String,
    pub window: MetricWindow,
    pub count: u64,
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub p50: Option<f64>,
    pub p95: Option<f64>,
    pub p99: Option<f64>,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub ended_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricWindow {
    OneMinute,
    FiveMinutes,
    OneHour,
    OneDay,
    OneRun,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event_id: String,
    pub event_kind: TelemetryEventKind,
    pub component: String,
    pub trace_id: Option<String>,
    pub source_ref: Option<String>,
    pub labels: Vec<MetricLabel>,
    pub measurements: Vec<MetricSample>,
    pub redaction_applied: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryEventKind {
    McpCall,
    CliCommand,
    IpcRequest,
    ServiceReadiness,
    AdapterJob,
    ExternalReviewJob,
    MemoryRead,
    MemoryWrite,
    ContextCompile,
    ActionLeaseDecision,
    PatchRun,
    VerifierRun,
    CompletionGateDecision,
    IncidentOpened,
    EvalRun,
    VerificationRun,
    SleepRun,
    ReplayRun,
    SkillActivation,
    SkillCuration,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TelemetryRollup {
    pub rollup_id: String,
    pub project_id: ProjectId,
    pub window: MetricWindow,
    pub metric_rollups: Vec<MetricRollup>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SloDefinition {
    pub slo_id: String,
    pub name: String,
    pub component: String,
    pub objective: SloObjective,
    pub threshold: f64,
    pub window: MetricWindow,
    pub severity_if_breached: SloBreachSeverity,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SloObjective {
    MaxP95LatencyMs,
    MaxP99LatencyMs,
    MaxErrorRate,
    MaxBlockRate,
    MinEvalPassRate,
    MaxIncidentRate,
    MaxExternalCandidateNoiseRate,
    MaxContextPacketBytes,
    MaxVerificationRuntimeMs,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SloBreachSeverity {
    Info,
    Warning,
    Blocking,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SloEvaluation {
    pub evaluation_id: String,
    pub slo_id: String,
    pub observed_value: f64,
    pub threshold: f64,
    pub breached: bool,
    pub severity: SloBreachSeverity,
    pub evidence_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub evaluated_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LatencyHistogram {
    pub histogram_id: String,
    pub component: String,
    pub operation: String,
    pub count: u64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CostLedger {
    pub ledger_id: String,
    pub project_id: ProjectId,
    pub window: MetricWindow,
    pub entries: Vec<CostLedgerEntry>,
    pub total_estimated_cost: f64,
    pub unit: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CostLedgerEntry {
    pub entry_id: String,
    pub component: String,
    pub operation: String,
    pub provider_id: Option<String>,
    pub estimated_input_tokens: Option<u64>,
    pub estimated_output_tokens: Option<u64>,
    pub estimated_cost: f64,
    pub source_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QualitySignal {
    pub signal_id: String,
    pub component: String,
    pub signal_kind: QualitySignalKind,
    pub value: f64,
    pub evidence_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualitySignalKind {
    EvalPassRate,
    VerificationPassRate,
    CompletionGateBlockRate,
    CandidateRejectionRate,
    ExternalReviewMalformedRate,
    FalseActivationRate,
    SkillNegativeTransferRate,
    MemoryRegretRate,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RuntimeDashboard {
    pub dashboard_id: String,
    pub project_id: ProjectId,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub health_summary: DashboardHealthSummary,
    pub latency: Vec<LatencyHistogram>,
    pub costs: Option<CostLedger>,
    pub slo_evaluations: Vec<SloEvaluation>,
    pub quality_signals: Vec<QualitySignal>,
    pub recent_incidents: Vec<String>,
    pub eval_summary_ref: Option<String>,
    pub verification_summary_ref: Option<String>,
    pub recommendations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DashboardHealthSummary {
    pub status: DashboardHealthStatus,
    pub ready: bool,
    pub degraded_reasons: Vec<String>,
    pub blocking_incidents: Vec<String>,
    pub last_phase_gate_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardHealthStatus {
    Healthy,
    Degraded,
    IncidentLockdown,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationalTrend {
    pub trend_id: String,
    pub component: String,
    pub metric_id: String,
    pub direction: OperationalTrendDirection,
    pub evidence_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalTrendDirection {
    Improving,
    Stable,
    Degrading,
    InsufficientData,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DashboardReport {
    pub component: String,
    pub dashboard: RuntimeDashboard,
    pub trends: Vec<OperationalTrend>,
    pub doctor: MetricsDoctorStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricsDoctorStatus {
    pub metric_registry_ready: bool,
    pub last_dashboard_ref: Option<String>,
    pub slo_breaches: Vec<String>,
    pub missing_metric_definitions: Vec<String>,
    pub high_cardinality_label_violations: Vec<String>,
    pub redaction_violations: Vec<String>,
    pub degrading_operational_trends: Vec<String>,
}
