//! Execution-path `OpenMetrics` wiring for the running Kernel (issue #1841,
//! I16.1/I16.2/I16.5).
//!
//! The bounded metric schema, the label policy, the registry and the exporter
//! all live in `eliot-observability-runtime`, which is their owner. This module
//! owns no metric name, no label key and no series: it installs that stack at the
//! Kernel's own never-gate startup site and maps observations the Kernel's
//! existing owners already hold onto the catalogue that crate already defines
//! ([`ExecutionPathMetrics`]). A new schema or a second metrics crate would be
//! the wrong answer, so none is created here.
//!
//! Three properties are load-bearing and are enforced, not documented:
//!
//! * **One registry.** Samples are written through
//!   [`MetricsRegistry::with_open_metrics`], the accessor that edits the *same*
//!   registry the installed exporter serves. A second private registry would
//!   produce a scrape that never carries an execution-path series.
//! * **Bounded cardinality.** The only free-form input is the route identity
//!   behind `route_fingerprint_id`, and it is reduced to a fixed-width digest
//!   before it becomes a label. Task text, prompt content, user text, unbounded
//!   error strings and secrets are never label material, so repeated unique task
//!   content cannot create a new series.
//! * **Never gates startup.** Installation happens on the same best-effort
//!   footing as the diagnostics subscriber; a typed refusal is reported and the
//!   launch funnel continues, exactly as A13.10 requires.
//!
//! I16.5 keeps usage and cost facts in their own store with their own truth
//! hierarchy; nothing in this module reads, converts or estimates them, so a
//! subscription quota can never reach a metric as currency.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use eliot_contracts::sha256_hex;
use eliot_observability_runtime::{
    BinaryIdentity, ExecutionPathMetrics, LocalPortOutcome, LocalPortPhase, MetricError,
    MetricLabelError, MetricSubject, MetricsRegistry, ModuleHealthOutcome, ModuleIdentity,
    ObservabilityConfig, ObservabilityConfigError, ObservabilityInstall, RollingLogPolicy,
    RouteFingerprintId, RouteOutcome, RuntimeProfile, SpoolPolicy, WorkClass,
    WorkTerminationOutcome, install,
};

use crate::KernelConfig;
use crate::kernel_build_contract::AuthorityDescriptorContour;

/// Tracing target for this module's own refusals.
const EXECUTION_METRICS_TARGET: &str = "eliot_kernel_execution_metrics";

/// Bounded events buffered for the rolling appender's writer thread.
///
/// The library accepts any non-zero value and publishes no ceiling for it, so
/// this is the Kernel's own bounded choice: large enough that a burst of frames
/// is not dropped, small enough that a stalled writer cannot grow without limit.
/// A dropped record stays visible through the exporter's dropped-records gauge,
/// so the bound is never silent.
const KERNEL_MAX_BUFFERED_RECORDS: usize = 4096;

/// Exit code appended to the active rolling generation's name.
///
/// It distinguishes a rolling rotation from a fresh process start and is a file
/// name component only. `0` is the ordinary successful-exit code, so a normal
/// shutdown is not rendered as a failure generation.
const KERNEL_ROLLING_EXIT_CODE: u32 = 0;

/// Stable stem of the Kernel's rolling operational generations.
const KERNEL_ROLLING_FILE_STEM: &str = "kernel-operational";

/// Stable stem of the Kernel's protected event spool.
const KERNEL_SPOOL_FILE_STEM: &str = "kernel-event-spool";

/// Directory name of the Kernel's own telemetry root under its work root.
///
/// The Kernel already owns sibling directories under the Host-injected work root
/// (`kernel_audit_dir`), so telemetry lands in the same owner-controlled place
/// instead of a process-global or per-user temporary path.
const KERNEL_TELEMETRY_DIR: &str = "observability";

/// Largest accepted rolling generation size, in bytes (owner ceiling).
const OWNER_MAX_ROLLING_BYTES: u64 = 64 * 1024 * 1024;

/// Largest accepted rolling generation count (owner ceiling).
const OWNER_MAX_ROLLING_GENERATIONS: u32 = 64;

/// Largest accepted single spooled record, in bytes (owner ceiling).
const OWNER_MAX_SPOOL_RECORD_BYTES: u64 = 8 * 1024;

/// Local scrape surface the installed exporter publishes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetricsEndpoint {
    /// The exporter is serving the admitted loopback address.
    Bound(String),
    /// No address was admitted, so samples are recorded but nothing is served.
    ///
    /// This is reported rather than papered over: the Kernel never invents a
    /// port, and an operator that admitted no endpoint gets a populated registry
    /// it can render, not a listener on a guessed address.
    Absent,
}

/// Typed refusal of one metric sample.
///
/// The Kernel does not take a new error dependency for a diagnostics path, so
/// the message is written out directly. Every message is a fixed sentence: no
/// label value, route name, task string or error text from a caller reaches it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricRecordRefusal {
    /// The shared registry could not be read, so the sample was not recorded.
    RegistryUnreadable,
    /// The label value is not exportable under the bounded label policy.
    Label,
    /// The sample value is not finite, so no exposition is possible.
    NotFinite,
    /// The bounded series registry is full; a new series would exceed it.
    SeriesFull,
    /// The sample carried more labels than the bounded label count allows.
    TooManyLabels,
}

impl MetricRecordRefusal {
    /// Stable refusal code, safe to place in a bounded diagnostic field.
    const fn code(self) -> &'static str {
        match self {
            Self::RegistryUnreadable => "METRIC_REGISTRY_UNREADABLE",
            Self::Label => "METRIC_LABEL_REFUSED",
            Self::NotFinite => "METRIC_VALUE_REFUSED",
            Self::SeriesFull => "METRIC_SERIES_REFUSED",
            Self::TooManyLabels => "METRIC_LABEL_COUNT_REFUSED",
        }
    }
}

impl std::fmt::Display for MetricRecordRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for MetricRecordRefusal {}

impl From<MetricError> for MetricRecordRefusal {
    fn from(error: MetricError) -> Self {
        match error {
            MetricError::InvalidName | MetricError::InvalidLabel => Self::Label,
            MetricError::NonFiniteValue => Self::NotFinite,
            MetricError::TooManyLabels => Self::TooManyLabels,
            MetricError::RegistryFull => Self::SeriesFull,
        }
    }
}

impl From<MetricLabelError> for MetricRecordRefusal {
    fn from(_: MetricLabelError) -> Self {
        Self::Label
    }
}

/// Typed failure of the whole observability install.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelObservabilityError {
    /// The composed configuration was refused by the owner's own validator.
    Config,
    /// The admitted scrape address is not a loopback endpoint.
    ///
    /// The metrics surface carries queue, claim, route and audit shape, so it is
    /// a local surface only. A non-loopback address is refused instead of being
    /// narrowed silently, because a bound public endpoint would publish
    /// operational shape to every host that can reach it.
    EndpointNotLoopback,
}

impl std::fmt::Display for KernelObservabilityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Config => "observability configuration refused by its owner validator",
            Self::EndpointNotLoopback => "metrics endpoint must be a loopback address",
        })
    }
}

impl std::error::Error for KernelObservabilityError {}

impl From<ObservabilityConfigError> for KernelObservabilityError {
    fn from(_: ObservabilityConfigError) -> Self {
        Self::Config
    }
}

/// The Kernel's live handle on the shared bounded metric registry.
///
/// Cloning is cheap and shares the one registry, so an owner deep in the
/// dispatch contour records into the same series the exporter serves.
#[derive(Clone, Debug)]
pub struct KernelMetricRecorder {
    /// The owner's registry; the only place samples are written.
    registry: Arc<MetricsRegistry>,
    /// Installation profile carried in every `profile` label.
    profile: RuntimeProfile,
    /// Refusals observed so far, reported rather than discarded.
    refusals: Arc<AtomicU64>,
}

impl KernelMetricRecorder {
    /// Builds the bounded label subject of one sample.
    ///
    /// Every dimension is a closed value: the binary is the Kernel, the module
    /// and work class come from the owner's vocabularies, the profile is the
    /// installation contour, and the route is a reduced fingerprint. Nothing here
    /// reads a task, a prompt, a path, a user string or an error message.
    fn subject(
        &self,
        module: ModuleIdentity,
        work_class: WorkClass,
        route: RouteFingerprintId,
    ) -> MetricSubject {
        MetricSubject {
            binary: BinaryIdentity::Kernel,
            module,
            work_class,
            route,
            profile: self.profile,
        }
    }

    /// Records one result, reporting a refusal instead of discarding it.
    ///
    /// A refused sample stays visible: the exporter's contract is that a rejected
    /// sample is rejected, never folded into an existing series. The refusal is
    /// counted and emitted as one bounded diagnostic code, so a saturating
    /// registry or an unreadable lock is visible to an operator instead of
    /// quietly producing a healthy-looking scrape.
    pub fn record(&self, outcome: Result<(), MetricRecordRefusal>) {
        if let Err(refusal) = outcome {
            self.refusals.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                target: EXECUTION_METRICS_TARGET,
                event = "kernel.metric_sample_refused",
                code = refusal.code(),
            );
        }
    }

    /// Number of samples this process refused to record.
    #[must_use]
    pub fn refusals(&self) -> u64 {
        self.refusals.load(Ordering::Relaxed)
    }

    /// Records the requested route beside the route actually taken.
    ///
    /// I16.5 asks for "requested vs actual route and route drift", so the outcome
    /// is derived from the pair rather than asserted by the caller: equal routes
    /// are `Matched`, different ones are `Drifted`, and a dispatch that exposed
    /// no actual route at all is `ActualNotExposed` instead of a false match.
    ///
    /// # Errors
    ///
    /// Returns [`MetricRecordRefusal`] when the route identity cannot be reduced
    /// to a bounded label, or when the sample itself is refused.
    pub fn record_route(
        &self,
        module: ModuleIdentity,
        work_class: WorkClass,
        requested: &str,
        actual: Option<&str>,
    ) -> Result<(), MetricRecordRefusal> {
        let route = route_fingerprint_id(&[requested, actual.unwrap_or("unexposed")])?;
        let outcome = match actual {
            None => RouteOutcome::ActualNotExposed,
            Some(actual) if actual == requested => RouteOutcome::Matched,
            Some(_) => RouteOutcome::Drifted,
        };
        self.edit(|metrics| {
            metrics.record_route_dispatch(&self.subject(module, work_class, route), outcome)
        })
    }

    /// Records one local-port execution and how long the port took.
    ///
    /// The phase is derived from whether the module has already served an
    /// execution, so "first execution" and "steady state" are observations rather
    /// than a label the caller can pick to flatter itself.
    ///
    /// # Errors
    ///
    /// Returns [`MetricRecordRefusal`] when the sample is refused.
    pub fn record_local_port(
        &self,
        module: ModuleIdentity,
        work_class: WorkClass,
        route_label: &str,
        outcome: LocalPortOutcome,
        elapsed: Duration,
    ) -> Result<(), MetricRecordRefusal> {
        let route = route_fingerprint_id(&[route_label])?;
        let phase = if LOCAL_PORT_SERVED.swap(true, Ordering::Relaxed) {
            LocalPortPhase::SteadyState
        } else {
            LocalPortPhase::ModuleStart
        };
        let subject = self.subject(module, work_class, route);
        let seconds = elapsed.as_secs_f64();
        self.edit(|metrics| {
            metrics.record_local_port_execution(&subject, outcome)?;
            metrics.record_local_port_latency(&subject, phase, seconds)
        })
    }

    /// Records the queue depth and the number of live claims.
    ///
    /// Both are gauges read from the owners' own live state at the moment of the
    /// observation, so a sample measures the current contour instead of carrying
    /// a total forward.
    ///
    /// # Errors
    ///
    /// Returns [`MetricRecordRefusal`] when the sample is refused.
    pub fn record_queue_and_claims(
        &self,
        module: ModuleIdentity,
        work_class: WorkClass,
        route_label: &str,
        depth: u32,
        active_claims: u32,
    ) -> Result<(), MetricRecordRefusal> {
        let route = route_fingerprint_id(&[route_label])?;
        let subject = self.subject(module, work_class, route);
        self.edit(|metrics| {
            metrics.record_queue_depth(&subject, depth)?;
            metrics.record_active_claims(&subject, active_claims)
        })
    }

    /// Records that a supervision lease expired and the unit lost its lease.
    ///
    /// # Errors
    ///
    /// Returns [`MetricRecordRefusal`] when the sample is refused.
    pub fn record_lease_expiry(
        &self,
        module: ModuleIdentity,
        work_class: WorkClass,
        route_label: &str,
    ) -> Result<(), MetricRecordRefusal> {
        let route = route_fingerprint_id(&[route_label])?;
        self.edit(|metrics| metrics.record_lease_expiry(&self.subject(module, work_class, route)))
    }

    /// Records a cancellation or an orphan observation.
    ///
    /// # Errors
    ///
    /// Returns [`MetricRecordRefusal`] when the sample is refused.
    pub fn record_work_termination(
        &self,
        module: ModuleIdentity,
        work_class: WorkClass,
        route_label: &str,
        outcome: WorkTerminationOutcome,
    ) -> Result<(), MetricRecordRefusal> {
        let route = route_fingerprint_id(&[route_label])?;
        self.edit(|metrics| {
            metrics.record_work_termination(&self.subject(module, work_class, route), outcome)
        })
    }

    /// Records the Kernel module's own health.
    ///
    /// # Errors
    ///
    /// Returns [`MetricRecordRefusal`] when the sample is refused.
    pub fn record_module_health(
        &self,
        module: ModuleIdentity,
        work_class: WorkClass,
        route_label: &str,
        outcome: ModuleHealthOutcome,
    ) -> Result<(), MetricRecordRefusal> {
        let route = route_fingerprint_id(&[route_label])?;
        self.edit(|metrics| {
            metrics.record_module_health(&self.subject(module, work_class, route), outcome)
        })
    }

    /// Runs one catalogue recorder against the shared registry.
    fn edit(
        &self,
        record: impl FnOnce(&mut ExecutionPathMetrics<'_>) -> Result<(), MetricError>,
    ) -> Result<(), MetricRecordRefusal> {
        self.registry
            .with_open_metrics(|registry| {
                let mut metrics = ExecutionPathMetrics::new(registry);
                record(&mut metrics)
            })
            .ok_or(MetricRecordRefusal::RegistryUnreadable)?
            .map_err(MetricRecordRefusal::from)
    }
}

/// Whether a local-port execution has already been served in this process.
static LOCAL_PORT_SERVED: AtomicBool = AtomicBool::new(false);

/// The process-wide recorder, published by the install so deep owners can reach
/// the one registry without threading a handle through every signature.
static RECORDER: OnceLock<Arc<KernelMetricRecorder>> = OnceLock::new();

/// The Kernel's live metric recorder, once the stack is installed.
#[must_use]
pub fn kernel_metrics() -> Option<&'static Arc<KernelMetricRecorder>> {
    RECORDER.get()
}

/// Live observability handles plus the local scrape surface.
#[derive(Clone, Debug)]
pub struct KernelObservability {
    /// The scrape surface the installed exporter publishes.
    pub endpoint: MetricsEndpoint,
    /// Installation profile the stack was configured with.
    pub profile: RuntimeProfile,
    /// Handle used by the Kernel's own observation sites.
    recorder: Arc<KernelMetricRecorder>,
    /// The owner's live handles: appender, registry, critical path, OTLP state.
    pub install: ObservabilityInstall,
}

impl KernelObservability {
    /// The recorder every observation site writes through.
    #[must_use]
    pub fn recorder(&self) -> &Arc<KernelMetricRecorder> {
        &self.recorder
    }

    /// Publishes the appender's dropped-record and control-loss gauges.
    ///
    /// A scrape is never a success indication while telemetry is being lost, so
    /// these counters are published before the surface is read.
    pub fn publish_runtime_counters(&self) {
        self.install.publish_runtime_counters();
    }

    /// Stable description of how the install went, so a repeated call is never
    /// reported as a first one.
    #[must_use]
    pub fn describe(&self) -> &'static str {
        match self.endpoint {
            MetricsEndpoint::Bound(_) => "installed_with_endpoint",
            MetricsEndpoint::Absent => "installed_without_endpoint",
        }
    }
}

/// Installs the bounded `OpenMetrics` stack and publishes the local scrape
/// surface.
///
/// The installation profile is the installation contour the Kernel was admitted
/// with, not an inference from a path or a port: the `ProgramData` contour is
/// the `system_service` profile whose last-resort sink is the Windows Event Log,
/// and the portable current-user contour is `user_mode`, which the owner requires
/// to carry a protected event spool.
///
/// # Errors
///
/// Returns [`KernelObservabilityError::Config`] when the owner's own validator
/// refuses a bound, and [`KernelObservabilityError::EndpointNotLoopback`] when an
/// endpoint was admitted that is not a loopback address. Diagnostics never gate
/// startup (A13.10), so the caller reports the refusal and continues.
pub fn install_kernel_execution_metrics(
    config: &KernelConfig,
    contour: &AuthorityDescriptorContour,
) -> Result<KernelObservability, KernelObservabilityError> {
    let profile = match contour {
        AuthorityDescriptorContour::ProgramData => RuntimeProfile::SystemService,
        AuthorityDescriptorContour::PortableCurrentUser { .. } => RuntimeProfile::UserMode,
    };
    let metrics_listen = match config.metrics_listen.as_deref() {
        None => None,
        Some(address) if is_loopback_address(address) => Some(address.to_owned()),
        Some(_) => return Err(KernelObservabilityError::EndpointNotLoopback),
    };
    let directory = telemetry_directory(&config.work_root);
    let observability = ObservabilityConfig {
        profile,
        rolling_log: RollingLogPolicy {
            directory: directory.clone(),
            file_stem: KERNEL_ROLLING_FILE_STEM.to_owned(),
            // The owner's published ceilings, so the Kernel adds no telemetry
            // retention policy of its own on top of them.
            max_bytes_per_generation: OWNER_MAX_ROLLING_BYTES,
            max_generations: OWNER_MAX_ROLLING_GENERATIONS,
            max_buffered_records: KERNEL_MAX_BUFFERED_RECORDS,
            exit_code: KERNEL_ROLLING_EXIT_CODE,
        },
        // `system_service` uses the Windows Event Log as its last-resort sink;
        // the other profiles must carry the protected file spool, which the
        // owner refuses to accept as absent.
        spool: (profile != RuntimeProfile::SystemService).then(|| SpoolPolicy {
            directory,
            file_stem: KERNEL_SPOOL_FILE_STEM.to_owned(),
            max_generations: OWNER_MAX_ROLLING_GENERATIONS,
            max_record_bytes: OWNER_MAX_SPOOL_RECORD_BYTES,
        }),
        metrics_listen,
        otlp_endpoint: None,
    };
    let outcome = install(&observability)?;
    let endpoint = match observability.metrics_listen {
        Some(address) => MetricsEndpoint::Bound(address),
        None => MetricsEndpoint::Absent,
    };
    let recorder = Arc::new(KernelMetricRecorder {
        registry: Arc::clone(&outcome.handles().metrics),
        profile,
        refusals: Arc::new(AtomicU64::new(0)),
    });
    recorder.record(recorder.record_module_health(
        ModuleIdentity::InternalRust,
        WorkClass::Control,
        "kernel.install",
        ModuleHealthOutcome::Healthy,
    ));
    let _ = RECORDER.set(Arc::clone(&recorder));
    Ok(KernelObservability {
        endpoint,
        profile,
        recorder,
        install: outcome.handles().clone(),
    })
}

/// Returns the Kernel's telemetry directory under its work root.
fn telemetry_directory(work_root: &Path) -> PathBuf {
    work_root.join(KERNEL_TELEMETRY_DIR)
}

/// Reports whether an admitted metrics address is a loopback endpoint.
///
/// Only the loopback families are accepted, with or without the explicit
/// IPv4-mapped form. Anything else - a wildcard bind, a routable address, a
/// hostname - is refused rather than narrowed, because a bound non-loopback
/// endpoint would publish queue, claim, route and audit shape off-box.
fn is_loopback_address(address: &str) -> bool {
    let Some((host, port)) = address.rsplit_once(':') else {
        return false;
    };
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host == "localhost" {
        return true;
    }
    match host.rsplit_once(':') {
        // Bare `::1` and the IPv4-mapped loopback such as `::ffff:127.0.0.1`.
        Some(("::1", "" | "0:0:0:0:0:0:0:1")) => true,
        Some((prefix, "127.0.0.1")) => prefix.is_empty() || prefix == "::ffff",
        _ => {
            let octets = host.split('.').collect::<Vec<_>>();
            // A `u8` parse already refuses any octet above 255, and the first
            // octet must be the loopback 127/8 prefix.
            octets.len() == 4
                && octets[0] == "127"
                && octets.iter().all(|octet| octet.parse::<u8>().is_ok())
        }
    }
}

/// Reduces route identity to one bounded `route_fingerprint_id` label value.
///
/// I16.1 requires fixed/bounded labels and the issue forbids task ids, prompt
/// content, user text, unbounded error strings and secrets. The route identity
/// is therefore reduced to a fixed-width digest of the route names themselves,
/// which bounds cardinality by the number of routes rather than by the number of
/// tasks, and keeps repeated unique task content from creating a new series. A
/// name that is already exportable is used as it stands, so an operator reading a
/// scrape sees the route whenever the charset allows it.
///
/// # Errors
///
/// Returns [`MetricRecordRefusal::Label`] when even the reduced identity cannot
/// be rendered as a label. The refusal is reported rather than replaced by an
/// invented constant, because a constant would merge unrelated routes into one
/// series.
fn route_fingerprint_id(parts: &[&str]) -> Result<RouteFingerprintId, MetricRecordRefusal> {
    let joined = parts.join(".");
    if let Ok(identifier) = RouteFingerprintId::new(&joined) {
        return Ok(identifier);
    }
    RouteFingerprintId::new(&sha256_hex(joined.as_bytes())).map_err(MetricRecordRefusal::from)
}
