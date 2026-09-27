//! Execution-path `OpenMetrics` wiring for the running daemon (issue #1841,
//! I16.1/I16.2/I16.5).
//!
//! The bounded metric schema, the label policy, the registry and the exporter
//! all live in `eliot-observability-runtime`, which is their owner. This module
//! owns no metric name, no label key and no series: it installs that stack at
//! the daemon's own never-gate startup site and maps observations the daemon's
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
//! * **Bounded cardinality.** Every label is a closed value: the binary is the
//!   daemon, the module, work class, outcome and profile come from the owner's
//!   vocabularies, and the route fingerprint is a fixed site identity. Task
//!   text, prompt content, user text, unbounded error strings and secrets are
//!   never label material, so repeated unique task content cannot create a new
//!   series. Callers pass observed values only and pick no label.
//! * **Never gates startup.** Installation happens on the same best-effort
//!   footing as the daemon diagnostics; a typed refusal is reported and the
//!   launch funnel continues, exactly as A13.10 requires.
//!
//! I16.5 keeps usage and cost facts in their own store with their own truth
//! hierarchy; nothing in this module reads, converts or estimates them, so a
//! subscription quota can never reach a metric as currency.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use eliot_observability_runtime::{
    BinaryIdentity, ExecutionPathMetrics, FinishOutcome, LifecycleOutcome, MetricError,
    MetricLabelError, MetricSubject, MetricsRegistry, ModuleHealthOutcome, ModuleIdentity,
    ObservabilityConfig, ObservabilityConfigError, ObservabilityInstall, RollingLogPolicy,
    RouteFingerprintId, RouteOutcome, RuntimeProfile, SpoolPolicy, WorkClass,
    WorkTerminationOutcome, install,
};
use eliot_platform_windows::protected_program_data_root;

use super::DaemonConfig;
use super::agent_fabric::FabricError;
use super::diagnostics::DrainOutcome;

/// Tracing target for this module's own refusals.
const EXECUTION_METRICS_TARGET: &str = "eliotd_execution_metrics";

/// Bounded events buffered for the rolling appender's writer thread.
///
/// At the owner's declared ceiling: the config validator rejects anything
/// above `MAX_ROLLING_QUEUED_RECORDS`, and a dropped record stays visible
/// through the exporter's dropped-records gauge, so the bound is never silent.
const DAEMON_MAX_BUFFERED_RECORDS: usize =
    eliot_observability_runtime::config::MAX_ROLLING_QUEUED_RECORDS;

/// Exit code appended to the active rolling generation's name.
///
/// It distinguishes a rolling rotation from a fresh process start and is a file
/// name component only. `0` is the ordinary successful-exit code, so a normal
/// shutdown is not rendered as a failure generation.
const DAEMON_ROLLING_EXIT_CODE: u32 = 0;

/// Stable stem of the daemon's rolling operational generations.
const DAEMON_ROLLING_FILE_STEM: &str = "daemon-operational";

/// Stable stem of the daemon's protected event spool.
const DAEMON_SPOOL_FILE_STEM: &str = "daemon-event-spool";

/// Directory name of the daemon's own telemetry root under its state root.
///
/// The daemon already owns its protected state root, so telemetry lands in the
/// same owner-controlled place instead of a process-global or per-user
/// temporary path.
const DAEMON_TELEMETRY_DIR: &str = "observability";

/// Largest accepted rolling generation size, in bytes (owner ceiling).
const OWNER_MAX_ROLLING_BYTES: u64 = eliot_observability_runtime::config::MAX_ROLLING_BYTES;

/// Largest accepted rolling generation count (owner ceiling).
const OWNER_MAX_ROLLING_GENERATIONS: u32 =
    eliot_observability_runtime::config::MAX_ROLLING_GENERATIONS;

/// Largest accepted single spooled record, in bytes (owner ceiling).
const OWNER_MAX_SPOOL_RECORD_BYTES: u64 =
    eliot_observability_runtime::config::MAX_SPOOL_RECORD_BYTES;

/// Local scrape surface the installed exporter publishes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaemonMetricsEndpoint {
    /// The exporter is serving the admitted loopback address.
    Bound(String),
    /// No address was admitted, so samples are recorded but nothing is served.
    ///
    /// This is reported rather than papered over: the daemon never invents a
    /// port, and an operator that admitted no endpoint gets a populated registry
    /// it can render, not a listener on a guessed address.
    Absent,
}

/// Typed refusal of one metric sample.
///
/// The daemon does not take a new error dependency for a diagnostics path, so
/// the message is written out directly. Every message is a fixed sentence: no
/// label value, route name, task string or error text from a caller reaches it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonMetricRecordRefusal {
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

impl DaemonMetricRecordRefusal {
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

impl std::fmt::Display for DaemonMetricRecordRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for DaemonMetricRecordRefusal {}

impl From<MetricError> for DaemonMetricRecordRefusal {
    fn from(error: MetricError) -> Self {
        match error {
            MetricError::InvalidName | MetricError::InvalidLabel => Self::Label,
            MetricError::NonFiniteValue => Self::NotFinite,
            MetricError::TooManyLabels => Self::TooManyLabels,
            MetricError::RegistryFull => Self::SeriesFull,
        }
    }
}

impl From<MetricLabelError> for DaemonMetricRecordRefusal {
    fn from(_: MetricLabelError) -> Self {
        Self::Label
    }
}

/// Typed failure of the whole observability install.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonObservabilityError {
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

impl std::fmt::Display for DaemonObservabilityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Config => "observability configuration refused by its owner validator",
            Self::EndpointNotLoopback => "metrics endpoint must be a loopback address",
        })
    }
}

impl std::error::Error for DaemonObservabilityError {}

impl From<ObservabilityConfigError> for DaemonObservabilityError {
    fn from(_: ObservabilityConfigError) -> Self {
        Self::Config
    }
}

/// The daemon's live handle on the shared bounded metric registry.
///
/// Cloning is cheap and shares the one registry, so an owner deep in the
/// daemon records into the same series the exporter serves.
#[derive(Clone, Debug)]
pub struct DaemonMetricRecorder {
    /// The owner's registry; the only place samples are written.
    registry: Arc<MetricsRegistry>,
    /// Installation profile carried in every `profile` label.
    profile: RuntimeProfile,
    /// Refusals observed so far, reported rather than discarded.
    refusals: Arc<AtomicU64>,
}

impl DaemonMetricRecorder {
    /// Builds the bounded label subject of one sample.
    ///
    /// Every dimension is a closed value: the binary is the daemon, the module
    /// and work class come from the owner's vocabularies, the profile is the
    /// installation contour, and the route is a fixed site identity. Nothing here
    /// reads a task, a prompt, a path, a user string or an error message.
    fn subject(
        &self,
        module: ModuleIdentity,
        work_class: WorkClass,
        route: RouteFingerprintId,
    ) -> MetricSubject {
        MetricSubject {
            binary: BinaryIdentity::Daemon,
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
    pub fn record(&self, outcome: Result<(), DaemonMetricRecordRefusal>) {
        if let Err(refusal) = outcome {
            self.refusals.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                target: EXECUTION_METRICS_TARGET,
                event = "daemon.metric_sample_refused",
                code = refusal.code(),
            );
        }
    }

    /// Number of samples this process refused to record.
    #[must_use]
    pub fn refusals(&self) -> u64 {
        self.refusals.load(Ordering::Relaxed)
    }

    /// Records the daemon's own readiness as module health.
    ///
    /// The outcome is derived from the same pair the readiness record carries:
    /// ready and not degraded is `Healthy`, degraded is `Degraded`, and
    /// anything else is `Unavailable` instead of a false healthy.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonMetricRecordRefusal`] when the sample is refused.
    pub fn record_daemon_readiness(
        &self,
        ready: bool,
        degraded: bool,
    ) -> Result<(), DaemonMetricRecordRefusal> {
        let outcome = if ready && !degraded {
            ModuleHealthOutcome::Healthy
        } else if degraded {
            ModuleHealthOutcome::Degraded
        } else {
            ModuleHealthOutcome::Unavailable
        };
        let subject = self.subject(
            ModuleIdentity::InternalRust,
            WorkClass::Control,
            route_label("daemon.readiness")?,
        );
        self.edit(|metrics| metrics.record_module_health(&subject, outcome))
    }

    /// Records that the agent fabric attached to its admitted descriptor.
    ///
    /// An attach is the fabric serving its generation, so the health outcome is
    /// `Healthy`; a failed attach never reaches this observation.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonMetricRecordRefusal`] when the sample is refused.
    pub fn record_fabric_attached(&self) -> Result<(), DaemonMetricRecordRefusal> {
        let subject = self.subject(
            ModuleIdentity::InternalRust,
            WorkClass::Control,
            route_label("daemon.fabric_attach")?,
        );
        self.edit(|metrics| metrics.record_module_health(&subject, ModuleHealthOutcome::Healthy))
    }

    /// Records one agent-fabric rejection in the group that owns its variant.
    ///
    /// Only rejections with a metric group produce a sample: quarantine is a
    /// lifecycle observation, a stale owner lease is a lease expiry, the four
    /// cancellation variants are one terminal cancellation, and a missing route
    /// is a dispatch that exposed no actual route. Every other variant keeps its
    /// diagnostics record and no metric, because no group owns it; inventing a
    /// sample for an unowned rejection would be a fabricated series.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonMetricRecordRefusal`] when the sample is refused.
    pub fn record_fabric_rejection(
        &self,
        error: &FabricError,
    ) -> Result<(), DaemonMetricRecordRefusal> {
        let subject = self.subject(
            ModuleIdentity::InternalRust,
            WorkClass::Swarm,
            route_label("daemon.fabric_rejection")?,
        );
        match error {
            FabricError::Quarantined(_) => self
                .edit(|metrics| metrics.record_lifecycle(&subject, LifecycleOutcome::Quarantined)),
            FabricError::StaleOwnerLease(_) => {
                self.edit(|metrics| metrics.record_lease_expiry(&subject))
            }
            FabricError::Cancelled(_)
            | FabricError::Superseded(_)
            | FabricError::CancellationRequested(_)
            | FabricError::TerminalCancellation(_) => self.edit(|metrics| {
                metrics.record_work_termination(&subject, WorkTerminationOutcome::Cancelled)
            }),
            FabricError::NoRoute(_) => self.edit(|metrics| {
                metrics.record_route_dispatch(&subject, RouteOutcome::ActualNotExposed)
            }),
            _ => Ok(()),
        }
    }

    /// Records the currently held activation as the active-claims gauge.
    ///
    /// The daemon holds at most one activation in flight, so a busy loop reads
    /// `1` and an idle loop reads `0`. The value is the run loop's own live
    /// observation, not a total carried forward.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonMetricRecordRefusal`] when the sample is refused.
    pub fn record_maintenance_observation(
        &self,
        idle: bool,
    ) -> Result<(), DaemonMetricRecordRefusal> {
        let subject = self.subject(
            ModuleIdentity::InternalRust,
            WorkClass::Maintenance,
            route_label("daemon.maintenance_trigger")?,
        );
        self.edit(|metrics| metrics.record_active_claims(&subject, u32::from(!idle)))
    }

    /// Records one shutdown-drain observation.
    ///
    /// A drain that retains an unknown activation is an orphan detection; an
    /// idle drain observed no orphan and records nothing.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonMetricRecordRefusal`] when the sample is refused.
    pub fn record_drain_observation(
        &self,
        outcome: DrainOutcome,
    ) -> Result<(), DaemonMetricRecordRefusal> {
        match outcome {
            DrainOutcome::ActivationUnknown => {
                let subject = self.subject(
                    ModuleIdentity::InternalRust,
                    WorkClass::Swarm,
                    route_label("daemon.drain")?,
                );
                self.edit(|metrics| {
                    metrics
                        .record_work_termination(&subject, WorkTerminationOutcome::OrphanDetected)
                })
            }
            DrainOutcome::Idle => Ok(()),
        }
    }

    /// Records one terminal finish refusal.
    ///
    /// The fabric refuses every finish claim by owner design because an attempt
    /// result is never task Finish, so each refusal is a refuted finish claim.
    /// No verifier verdict exists on this path; verified and unverified finish
    /// outcomes have no daemon producer and are not synthesized here.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonMetricRecordRefusal`] when the sample is refused.
    pub fn record_finish_refusal(&self) -> Result<(), DaemonMetricRecordRefusal> {
        let subject = self.subject(
            ModuleIdentity::InternalRust,
            WorkClass::Swarm,
            route_label("daemon.finish")?,
        );
        self.edit(|metrics| metrics.record_finish(&subject, FinishOutcome::Refuted))
    }

    /// Runs one catalogue recorder against the shared registry.
    fn edit(
        &self,
        record: impl FnOnce(&mut ExecutionPathMetrics<'_>) -> Result<(), MetricError>,
    ) -> Result<(), DaemonMetricRecordRefusal> {
        self.registry
            .with_open_metrics(|registry| {
                let mut metrics = ExecutionPathMetrics::new(registry);
                record(&mut metrics)
            })
            .ok_or(DaemonMetricRecordRefusal::RegistryUnreadable)?
            .map_err(DaemonMetricRecordRefusal::from)
    }
}

/// The process-wide recorder, published by the install so deep owners can reach
/// the one registry without threading a handle through every signature.
static RECORDER: OnceLock<Arc<DaemonMetricRecorder>> = OnceLock::new();

/// The daemon's live metric recorder, once the stack is installed.
#[must_use]
pub fn daemon_metrics() -> Option<&'static Arc<DaemonMetricRecorder>> {
    RECORDER.get()
}

/// Live observability handles plus the local scrape surface.
#[derive(Clone, Debug)]
pub struct DaemonObservability {
    /// The scrape surface the installed exporter publishes.
    pub endpoint: DaemonMetricsEndpoint,
    /// Installation profile the stack was configured with.
    pub profile: RuntimeProfile,
    /// Handle used by the daemon's own observation sites.
    recorder: Arc<DaemonMetricRecorder>,
    /// The owner's live handles: appender, registry, critical path, OTLP state.
    pub install: ObservabilityInstall,
}

impl DaemonObservability {
    /// The recorder every observation site writes through.
    #[must_use]
    pub fn recorder(&self) -> &Arc<DaemonMetricRecorder> {
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
            DaemonMetricsEndpoint::Bound(_) => "installed_with_endpoint",
            DaemonMetricsEndpoint::Absent => "installed_without_endpoint",
        }
    }
}

/// Installs the bounded `OpenMetrics` stack and publishes the local scrape
/// surface.
///
/// The installation profile is the installation contour the daemon was admitted
/// with, not an inference from a path or a port: a launch descriptor retained
/// under the protected `ProgramData` root is the `system_service` profile whose
/// last-resort sink is the Windows Event Log, and any other admitted contour is
/// `user_mode`, which the owner requires to carry a protected event spool.
///
/// The scrape address is an operator/Host admission, not a daemon default: the
/// daemon refuses to invent a port for an operational surface. While the Host
/// launch contour carries no address, the caller passes `None` and the install
/// reports [`DaemonMetricsEndpoint::Absent`].
///
/// # Errors
///
/// Returns [`DaemonObservabilityError::Config`] when the owner's own validator
/// refuses a bound, and [`DaemonObservabilityError::EndpointNotLoopback`] when an
/// endpoint was admitted that is not a loopback address. Diagnostics never gate
/// startup (A13.10), so the caller reports the refusal and continues.
pub fn install_daemon_execution_metrics(
    config: &DaemonConfig,
    metrics_listen: Option<&str>,
) -> Result<DaemonObservability, DaemonObservabilityError> {
    let profile = daemon_profile(config);
    let metrics_listen = match metrics_listen {
        None => None,
        Some(address) if is_loopback_address(address) => Some(address.to_owned()),
        Some(_) => return Err(DaemonObservabilityError::EndpointNotLoopback),
    };
    let directory = telemetry_directory(config.state_root());
    let observability = ObservabilityConfig {
        profile,
        rolling_log: RollingLogPolicy {
            directory: directory.clone(),
            file_stem: DAEMON_ROLLING_FILE_STEM.to_owned(),
            // The owner's published ceilings, so the daemon adds no telemetry
            // retention policy of its own on top of them.
            max_bytes_per_generation: OWNER_MAX_ROLLING_BYTES,
            max_generations: OWNER_MAX_ROLLING_GENERATIONS,
            max_buffered_records: DAEMON_MAX_BUFFERED_RECORDS,
            exit_code: DAEMON_ROLLING_EXIT_CODE,
        },
        // `system_service` uses the Windows Event Log as its last-resort sink;
        // the other profiles must carry the protected file spool, which the
        // owner refuses to accept as absent.
        spool: (profile != RuntimeProfile::SystemService).then(|| SpoolPolicy {
            directory,
            file_stem: DAEMON_SPOOL_FILE_STEM.to_owned(),
            max_generations: OWNER_MAX_ROLLING_GENERATIONS,
            max_record_bytes: OWNER_MAX_SPOOL_RECORD_BYTES,
        }),
        metrics_listen,
        otlp_endpoint: None,
    };
    let outcome = install(&observability)?;
    // The install may have already happened in `main` (#1836/#3513): the
    // recorder profile is the served install's profile, never a second
    // derivation that could disagree with it.
    let profile = outcome.handles().profile;
    let endpoint = match observability.metrics_listen {
        Some(address) => DaemonMetricsEndpoint::Bound(address),
        None => DaemonMetricsEndpoint::Absent,
    };
    let recorder = Arc::new(DaemonMetricRecorder {
        registry: Arc::clone(&outcome.handles().metrics),
        profile,
        refusals: Arc::new(AtomicU64::new(0)),
    });
    recorder.record(recorder.record_daemon_readiness(true, false));
    let _ = RECORDER.set(Arc::clone(&recorder));
    Ok(DaemonObservability {
        endpoint,
        profile,
        recorder,
        install: outcome.handles().clone(),
    })
}

/// Returns the installation profile of the admitted launch contour.
///
/// The launch descriptor path is Host-approved and digest-bound, so containment
/// under the protected `ProgramData` root is the admitted service contour, not
/// an inference: anything else, including an unresolvable root, serves as
/// `user_mode` with the protected spool the owner requires.
fn daemon_profile(config: &DaemonConfig) -> RuntimeProfile {
    let under_program_data =
        protected_program_data_root().is_ok_and(|root| config.config_path().starts_with(&root));
    if under_program_data {
        RuntimeProfile::SystemService
    } else {
        RuntimeProfile::UserMode
    }
}

/// Returns the daemon's telemetry directory under its state root.
fn telemetry_directory(state_root: &Path) -> PathBuf {
    state_root.join(DAEMON_TELEMETRY_DIR)
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

/// Validates one fixed site identity as a `route_fingerprint_id` label value.
///
/// Every call site passes a literal, so a refusal here names a programming
/// error in this module rather than caller input; it is still reported rather
/// than replaced by an invented constant, because a constant would merge
/// unrelated sites into one series.
///
/// # Errors
///
/// Returns [`DaemonMetricRecordRefusal::Label`] when the identity cannot be
/// rendered as a label.
fn route_label(value: &'static str) -> Result<RouteFingerprintId, DaemonMetricRecordRefusal> {
    RouteFingerprintId::new(value).map_err(DaemonMetricRecordRefusal::from)
}
