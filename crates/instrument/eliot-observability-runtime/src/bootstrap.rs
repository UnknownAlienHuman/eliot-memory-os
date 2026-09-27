//! Process-wide observability bootstrap (I16.2).
//!
//! One call from a bundle binary's `main` installs the whole stack:
//!
//! 1. structured `tracing` with bounded fields, writing JSON operational
//!    records to the non-blocking rolling appender and to stderr;
//! 2. the bounded-label `OpenMetrics` registry published for scraping;
//! 3. the OTLP bridge disposition, active only when the `otlp` feature is
//!    built;
//! 4. the `system_service` Windows Event Log stage, or the protected event
//!    spool for `user_mode` and portable;
//! 5. the I16.11 critical-path fallback machine.
//!
//! Installation is idempotent and never gates startup. A second call returns
//! [`ObservabilityInstallOutcome::AlreadyInstalled`] with the first owner's
//! live handles, so a caller can report the real state instead of assuming
//! success.

use std::sync::{Arc, Mutex, OnceLock};

use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use crate::config::{ObservabilityConfig, ObservabilityConfigError, RuntimeProfile};
use crate::critical_path::{
    CriticalEventSinks, CriticalEventSinksEntry, CriticalPath, SinkStatus, UnavailableReason,
};
use crate::event_log::EventLogReport;
use crate::metrics::{Metric, MetricKind, OpenMetrics};
use crate::otlp::{OtlpDisposition, disposition as otlp_disposition};
use crate::rolling_log::{RollingLogHandle, RollingLogWriter};
use crate::spool::{EventSpool, SpoolSinks};

/// Target every runtime record carries.
pub const OBSERVABILITY_TARGET: &str = "eliot_observability";

/// Metric name of the rolling appender's dropped-record gauge.
pub const DROPPED_LOG_RECORDS_METRIC: &str = "eliot_observability_dropped_log_records";

/// Metric name of the critical-path control-loss counter.
pub const CONTROL_LOSS_METRIC: &str = "eliot_observability_control_loss_total";

/// Metric name of the held control-loss record gauge.
pub const CONTROL_LOSS_HELD_METRIC: &str = "eliot_observability_control_loss_held";

/// Shared bounded metric registry.
#[derive(Debug, Default)]
pub struct MetricsRegistry(Mutex<OpenMetrics>);

impl MetricsRegistry {
    /// Records one bounded sample, discarding a poisoned registry rather than
    /// panicking on the diagnostic path.
    pub fn record(&self, metric: &Metric<'_>) {
        if let Ok(mut registry) = self.0.lock() {
            let _ = registry.record(metric);
        }
    }

    /// Renders the current `OpenMetrics` exposition.
    #[must_use]
    pub fn expose(&self) -> String {
        self.0
            .lock()
            .map_or_else(|_| String::new(), |registry| registry.expose())
    }
}

/// Live handles to the installed observability stack.
#[derive(Clone, Debug)]
pub struct ObservabilityInstall {
    /// Non-blocking rolling-log producer.
    pub log: RollingLogWriter,
    /// Shared bounded metric registry.
    pub metrics: Arc<MetricsRegistry>,
    /// I16.11 critical-path fallback machine.
    pub critical_path: CriticalPath,
    /// Honest OTLP bridge disposition for this build.
    pub otlp: OtlpDisposition,
    /// Installation profile the stack was configured with.
    pub profile: RuntimeProfile,
}

impl ObservabilityInstall {
    /// Publishes the appender's dropped-record count and the critical-path
    /// control-loss gauges into the scrape, so a scrape is never a success
    /// indication while telemetry is being lost.
    pub fn publish_runtime_counters(&self) {
        self.metrics.record(&Metric::new(
            DROPPED_LOG_RECORDS_METRIC,
            MetricKind::Gauge,
            "operational log records dropped by bounded-queue admission",
            exact_f64(self.log.dropped_records()),
        ));
        self.metrics.record(&Metric::new(
            CONTROL_LOSS_METRIC,
            MetricKind::Counter,
            "critical events that reached the visible control_loss state",
            exact_f64(self.critical_path.control_loss_total()),
        ));
        self.metrics.record(&Metric::new(
            CONTROL_LOSS_HELD_METRIC,
            MetricKind::Gauge,
            "critical events held for replay on a returning channel",
            exact_f64(u64::try_from(self.critical_path.held_control_loss()).unwrap_or(u64::MAX)),
        ));
    }
}

/// Converts a bounded counter to a metric value.
///
/// The counters are drop/loss/held-record counts bounded well below 2^53, the
/// largest integer `f64` represents exactly, so the widening is lossless. The
/// cast is annotated rather than split arithmetically: an artificial
/// half-and-recombine would be less clear than a stated bound.
// Owner: this crate. Operation: metric value publication.
// Removal condition: never (the counters are structurally bounded).
#[allow(clippy::cast_precision_loss)]
fn exact_f64(value: u64) -> f64 {
    value as f64
}

/// Result of one install attempt.
#[derive(Clone, Debug)]
pub enum ObservabilityInstallOutcome {
    /// This call installed the stack.
    Installed(ObservabilityInstall),
    /// The stack was already installed; the first owner is unchanged and these
    /// are its live handles.
    AlreadyInstalled(ObservabilityInstall),
}

impl ObservabilityInstallOutcome {
    /// The live handles, whether installed now or previously.
    #[must_use]
    pub fn handles(&self) -> &ObservabilityInstall {
        match self {
            Self::Installed(install) | Self::AlreadyInstalled(install) => install,
        }
    }
}

static INSTALL: OnceLock<ObservabilityInstall> = OnceLock::new();

/// Installs the whole observability runtime, or returns the existing one.
///
/// Diagnostics never gate startup (A13.10): a rejected configuration returns a
/// typed error and leaves the process free to run, and the refusal is never
/// turned into a panic or a fabricated success.
///
/// # Errors
///
/// Returns [`ObservabilityConfigError`] when the configuration bounds or the
/// profile/sink rule are violated, or when the rolling appender, event spool,
/// or last-resort stage cannot be opened. A returned error is honest: no
/// partial stack is presented as complete.
pub fn install(
    config: &ObservabilityConfig,
) -> Result<ObservabilityInstallOutcome, ObservabilityConfigError> {
    if let Some(existing) = INSTALL.get() {
        return Ok(ObservabilityInstallOutcome::AlreadyInstalled(
            existing.clone(),
        ));
    }
    config.validate()?;
    let log = RollingLogHandle::start(&config.rolling_log).map_err(|_| {
        ObservabilityConfigError::Inconsistent("rolling log appender could not be opened")
    })?;
    install_subscriber(log.writer());
    let install = ObservabilityInstall {
        log: log.writer(),
        metrics: Arc::new(MetricsRegistry::default()),
        critical_path: CriticalPath::new(sinks_for(config, &log.writer())?),
        otlp: otlp_disposition(config.otlp_endpoint.as_deref()),
        profile: config.profile,
    };
    let _ = INSTALL.set(install.clone());
    Ok(ObservabilityInstallOutcome::Installed(install))
}

/// Builds the I16.11 sink group for the configured profile.
///
/// The normal stage is `normal_writer` — the same bounded appender the
/// `tracing` rolling layer writes to, so a critical record and an ordinary
/// operational record share one retention policy and one queue instead of two
/// independent sinks that could disagree about what was written.
fn sinks_for(
    config: &ObservabilityConfig,
    normal_writer: &RollingLogWriter,
) -> Result<CriticalEventSinks, ObservabilityConfigError> {
    let (spool, last_resort) = match (config.profile, config.spool.as_ref()) {
        (RuntimeProfile::SystemService, _) => (SpoolSinks::absent(), Some(EventLogReport)),
        (_, Some(policy)) => {
            let spool = EventSpool::open(policy.clone()).map_err(|_| {
                ObservabilityConfigError::Inconsistent("event spool could not be opened")
            })?;
            (SpoolSinks::new(spool), None)
        }
        (_, None) => {
            return Err(ObservabilityConfigError::Inconsistent(
                "user_mode and portable profiles require a protected event spool",
            ));
        }
    };
    let normal_writer = normal_writer.clone();
    Ok(CriticalEventSinks {
        normal: Some(CriticalEventSinksEntry::new(
            move |record| match serde_json::to_string(record) {
                Ok(line) if normal_writer.try_send(&line) => SinkStatus::Delivered,
                Ok(_) => SinkStatus::Unavailable(UnavailableReason::Saturated),
                Err(_) => SinkStatus::Unavailable(UnavailableReason::NotApplicable),
            },
        )),
        spool: Some(spool),
        last_resort,
    })
}

/// Installs the JSON `tracing` subscriber over stderr and the rolling appender.
///
/// A foreign pre-existing global subscriber is kept as-is: the first owner
/// stands and no second global install is attempted, so a process that already
/// installed diagnostics keeps them.
fn install_subscriber(writer: RollingLogWriter) {
    let stderr_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_ansi(false)
        .with_target(true)
        .with_writer(std::io::stderr);
    let rolling_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_ansi(false)
        .with_target(true)
        .with_writer(writer);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer)
        .with(rolling_layer)
        .try_init();
}
