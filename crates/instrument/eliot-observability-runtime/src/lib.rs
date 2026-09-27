//! Shared ELIOT observability runtime (issue #1836, I16.2).
//!
//! This crate is the single runtime observability capability cell reachable
//! from every shipped bundle binary. It installs structured `tracing` with
//! bounded fields, writes non-blocking rolling operational logs, exposes a
//! bounded-label `OpenMetrics` exposition, bridges to OTLP only behind a
//! disabled-by-default feature, reports Host/Kernel startup and recovery to the
//! Windows Event Log in the `system_service` profile, spools to a protected
//! rolling file in the `user_mode` and portable profiles, emits structured
//! crash reports carrying build and module-generation metadata, and owns the
//! I16.11 critical-path fallback state machine that ends in a durable, visible
//! `control_loss` state instead of a silent success.
//!
//! What already exists is reused, never duplicated: the contract-shaped
//! telemetry families and label dispositions stay in `eliot-observability`
//! (`field_policy`), and the only Event Log FFI stays in
//! `eliot-platform-windows` (`report_local_event`). This crate owns
//! installation, sinks, retention, the fallback chain, and the crash surface.
//!
//! Normative anchors: I16.1 four surfaces (logs rotate/sample and are not
//! canonical; metrics labels are bounded; audit is never sampled), I16.2 the
//! stack above, I16.4 required operational events, I16.9 retention and
//! telemetry cost (telemetry consumes the resources it observes, so every
//! buffer here is finite), I16.11 no hidden telemetry failure, I15.4 secrets
//! never reach logs.

#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod config;
pub mod crash;
pub mod critical_path;
pub mod event_log;
pub mod metric_groups;
pub mod metrics;
pub mod otlp;
pub mod rolling_log;
pub mod spool;
pub mod usage_cost;

pub use bootstrap::{MetricsRegistry, ObservabilityInstall, ObservabilityInstallOutcome, install};
pub use config::{
    ObservabilityConfig, ObservabilityConfigError, RollingLogPolicy, RuntimeProfile, SpoolPolicy,
};
pub use crash::{CrashReport, CrashReportError, CrashReportMetadata, SymbolArtifact};
pub use critical_path::{
    CriticalEventError, CriticalEventRecord, CriticalEventSinks, CriticalEventSinksEntry,
    CriticalEventState, CriticalPath, CriticalPathOutcome, SinkStatus, UnavailableReason,
};
pub use event_log::{EventLogOutcome, EventLogReport, SystemServiceEvent};
pub use metric_groups::{
    AuditSinkOutcome, BinaryIdentity, ExecutionPathMetrics, FinishOutcome, LABEL_KEY_COUNT,
    LabelKey, LifecycleOutcome, LocalPortOutcome, LocalPortPhase, MetricDefinition, MetricGroup,
    MetricLabelError, MetricSubject, ModuleHealthOutcome, ModuleIdentity, RouteFingerprintId,
    RouteOutcome, TraceCompletenessOutcome, WorkClass, WorkTerminationOutcome, metric_catalogue,
    metric_label_schema_version,
};
pub use metrics::{METRIC_LABEL_KEYS, Metric, MetricError, MetricKind, OpenMetrics};
pub use otlp::{OtlpBridge, OtlpBridgeError, OtlpDisposition, OtlpExport, otlp_enabled};
pub use rolling_log::{RollingLogError, RollingLogHandle, RollingLogShutdown, RollingLogWriter};
pub use spool::{EventSpool, EventSpoolError, SpoolSinks};
pub use usage_cost::{
    BilledCost, CallCounts, CostEstimate, CurrencyCode, CurrencyContract, EstimateUnit,
    IncidentalCost, ProviderId, QuotaSource, ResourceUse, SubscriptionQuota, TokenCounts,
    UsageCostError, UsageCostRecord, UsageCostStore, UsageFacts, UsageKey, UsageScope, UsageTruth,
};
