//! Architecture: A8.1, A13.2, A13.3, ARCH-WDG-01, ARCH-RES-01, ARCH-RES-04.
//! Implementation: I2.23, I8.1, I8.3, I8.4, I14.10, I14.15.
//! Responsibility/Forbidden ownership: bounded Watchdog runtime composition and admitted heartbeat only; no Kernel effect, Host identity, Store canonical state, unbounded restart, default, retry, or mint authority.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use eliot_contracts::sha256_hex;
use eliot_runtime::{
    ChildClass, Runtime, ShutdownOutcome, SupervisionOutcome, SupervisionStrategy, TaskFailure,
};
use eliot_watchdog_core::{CoverageGapExplanation, CoverageManifestProjection, EvidenceRef};

use crate::AdmittedIsolatedDestination;
use crate::CompositionError;
use crate::HostObservationSource;
use crate::HostObservationState;
use crate::KernelWatchdogPort;
use crate::LiveHostObservationSource;
use crate::PROTOCOL_VERSION;
use crate::SERVICE_NAME;
use crate::SpoolError;
use crate::WatchdogAdmissionSource;
use crate::WatchdogConfig;
use crate::WatchdogRuntimeBinding;
use crate::admission_gap_reason;
use crate::backup_control::BackupControlRegistration;
use crate::current_unix_ms;
use crate::health_projection::{HealthProjectionCell, evaluate_interval_health};
use crate::heartbeat_transport::{HeartbeatTransport, HeartbeatTransportError};
use crate::kernel_gap_reason;
use crate::observation_coverage::{
    CoverageDisposition, IntervalCoverageCell, IntervalCoveragePublication, IntervalCoverageReport,
    ObservationChannel, ObservationClass, RecordOutcome, channel_capability,
};
use crate::report_gap_nonfatal;
use crate::watchdog_spool::WatchdogSpool;
use crate::watchdog_spool::backup::{
    CaptureFenceParams, SpoolRestoreDisposition, SpoolRestoreStep, WatchdogSpoolBackupLimits,
    WatchdogSpoolFence, WatchdogSpoolSnapshotPage,
};
use crate::watchdog_spool::owner_issued_active_installation;

mod authority_state;

use authority_state::WatchdogAuthorityStateCell;
pub use authority_state::{WatchdogAuthorityState, WatchdogReadiness};

/// Records one offered live coverage sample and reports an offer that was not
/// kept.
///
/// An offer that is not [`RecordOutcome::Recorded`] is a duplicate, a class the
/// map does not support for that channel, or an offer made with no interval open
/// to hold it. All three are evidence the publication must not lose quietly, so
/// this traces them; a duplicate also leaves a `SAMPLE_DROPPED` gap on the
/// channel's own record. The trace is per offer rather than per tick, and one
/// tick offers each of its channel/class pairs exactly once, so an unchanged
/// channel produces no such trace at any level.
fn record_coverage_sample(
    coverage: &IntervalCoverageCell,
    channel: ObservationChannel,
    class: ObservationClass,
) {
    let outcome = coverage.record(channel, class);
    if outcome != RecordOutcome::Recorded {
        tracing::debug!(
            event = "watchdog.observation_coverage_sample_not_kept",
            observation = outcome.as_str(),
            channel = channel.as_str(),
            class = class.as_str(),
            "offered coverage sample was not kept as evidence for this channel"
        );
    }
}

/// Publishes one finished coverage interval's full per-channel record.
///
/// `interval_closed` is `false` for the window a tick opened and did not
/// finish, which the cell reports as a named omission; both cases reach this
/// reader, so an unfinished tick is published rather than dropped. It restates
/// at the top level what the cell already decided, and the per-record
/// `interval_closed` copied into `channels` is the authoritative one.
///
/// This is the reader that makes the publication a publication rather than a
/// write: every field W5 requires to be recorded — expected source and classes,
/// the declared interval, the live and replayed portions, the dropped samples,
/// whether the interval closed, the named gaps, the sensor map revision, and
/// the validity verdict — is read here and emitted, so none of it is
/// write-only.
///
/// What is emitted, and how often, differs by case and both follow the record:
/// a **closed** interval is emitted when the set of blocking channels changed,
/// because that set is largely a measured property of the current sensor map
/// and of the samples the last interval actually held, so a steady set is
/// change-gated rather than per-tick noise. An **unclosed** interval is emitted
/// every single time it happens, because the omission belongs to the tick it
/// occurred on and change-gating it would emit one line for an indefinite run
/// of unfinished ticks. That is bounded by the tick body, which closes its own
/// interval on every exit, so an unclosed interval is an exceptional event
/// rather than an ordinary degraded one. The readiness projection and the
/// owner-bound capture path read the same cell on every tick and every capture.
/// A poisoned cell, or a close with no interval open, publishes nothing at
/// all — never a claim.
fn publish_interval_coverage(publication: &IntervalCoveragePublication, interval_closed: bool) {
    let report = publication.report();
    // Every record of a report shares one close state, so this is the report's
    // own: it asks whether the tick that produced these samples declared an end
    // for the window they belong to.
    let unclosed = report
        .records()
        .iter()
        .any(|record| !record.interval_closed());
    if !unclosed && !publication.blocking_changed() {
        return;
    }
    let interval = report.interval();
    let channels: Vec<_> = report
        .records()
        .iter()
        .map(|record| {
            (
                record.channel().as_str(),
                record.disposition().as_str(),
                record
                    .observed_classes()
                    .iter()
                    .map(|class| ObservationClass::as_str(*class))
                    .collect::<Vec<_>>(),
                record.observed_replayed_observations(),
                record.dropped_samples(),
                record.interval_closed(),
                record
                    .gaps()
                    .iter()
                    .map(|gap| (gap.channel.as_str(), gap.reason))
                    .collect::<Vec<_>>(),
                record.expected_source(),
                record
                    .expected_classes()
                    .iter()
                    .map(|class| ObservationClass::as_str(*class))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    tracing::warn!(
        event = "watchdog.observation_coverage_publication",
        observation = "published",
        interval_closed = interval_closed,
        interval_start_ms = interval.start_ms,
        interval_end_ms = interval.end_ms,
        sensor_map_revision = report.sensor_map_revision(),
        valid = report.valid(),
        full_coverage = report.full_coverage_claimed(),
        blocking_channels = ?report.blocking_channels(),
        channels = ?channels,
        "one supervision tick's per-channel I8.2 observation coverage published"
    );
}

/// Projects the actual #1755 interval manifest on one closed interval.
///
/// This is the A4 adapter's read of the owner's own record: the interval
/// identity, the manifest evidence handle, and the gap verdict are all derived
/// from the closed [`IntervalCoverageReport`] through its public claims only.
/// A supplied coverage input built anywhere else — a restated
/// label, a stale interval, or a verdict the manifest does not carry — cannot
/// match this projection: supplied values are judged against the actual
/// manifest record above, never against a restatement of the detector's input.
///
/// The verdict categories are the rule's own: an internally inconsistent
/// manifest, or one no tick closed, establishes no verdict; a manifest whose
/// every short channel is a measured missing adapter is explained; any other
/// short wired channel is a gap this owner cannot account for. The evidence
/// handle is this adapter's digest over the manifest's public record data —
/// the manifest's own handle, not the detector's internal publication digest
/// — so supplied values are judged against the actual manifest, never against
/// a restatement of the detector's input.
#[must_use]
pub fn project_actual_coverage_manifest(
    manifest: &IntervalCoverageReport,
) -> CoverageManifestProjection {
    CoverageManifestProjection {
        interval_id: manifest_interval_identity(manifest),
        evidence: EvidenceRef {
            evidence_id: sha256_hex(manifest_evidence_fields(manifest).as_bytes()),
        },
        explanation: manifest_gap_verdict(manifest),
    }
}

/// The actual manifest's own interval identity: the declared owner-clock
/// bounds under the sensor map revision they were derived under.
///
/// Length-prefixed with the manifest's own tag, so it can never collide with
/// the detector's internal source-event identity: the two name different
/// things — the owner's published record versus one rule's comparison event.
fn manifest_interval_identity(manifest: &IntervalCoverageReport) -> String {
    let interval = manifest.interval();
    crate::health_projection::encode_identity(&[
        "watchdog_coverage_manifest".to_owned(),
        interval.start_ms.to_string(),
        interval.end_ms.to_string(),
        manifest.sensor_map_revision().to_string(),
    ])
}

/// The manifest's own evidence fields: every public record claim bound into
/// one digest.
///
/// Map revision, declared bounds, and per record the channel, disposition,
/// observed-class count, dropped samples, and every named gap reason. A
/// supplied evidence handle matches only when it was built from this same
/// record, so a stale or foreign manifest can never validate.
fn manifest_evidence_fields(manifest: &IntervalCoverageReport) -> String {
    let interval = manifest.interval();
    let mut fields = vec![
        "watchdog_coverage_manifest".to_owned(),
        manifest.sensor_map_revision().to_string(),
        interval.start_ms.to_string(),
        interval.end_ms.to_string(),
    ];
    for record in manifest.records() {
        fields.push(record.channel().as_str().to_owned());
        fields.push(record.disposition().as_str().to_owned());
        fields.push(record.observed_classes().len().to_string());
        fields.push(record.dropped_samples().to_string());
        for gap in record.gaps() {
            fields.push(gap.reason.to_owned());
        }
    }
    crate::health_projection::encode_identity(&fields)
}

/// The actual manifest's own gap verdict in the rule's vocabulary.
///
/// An inconsistent manifest, or one no tick closed, establishes no verdict. A
/// channel the map says has no competent source is a measured structural
/// limitation, not a gap that appeared between two intervals, so only a short
/// wired channel is unexplained. These are the same categories the runtime
/// projection derives, read here through the manifest's public claims, so the
/// adapter can never contradict the projection about one interval.
fn manifest_gap_verdict(manifest: &IntervalCoverageReport) -> CoverageGapExplanation {
    if !manifest.valid()
        || manifest
            .records()
            .iter()
            .any(|record| !record.interval_closed())
    {
        return CoverageGapExplanation::Unknown;
    }
    let unexplained = manifest.records().iter().any(|record| {
        matches!(
            record.disposition(),
            CoverageDisposition::Partial | CoverageDisposition::Unknown
        ) && channel_capability(record.channel()).wiring.is_wired()
    });
    if unexplained {
        CoverageGapExplanation::Unexplained
    } else {
        CoverageGapExplanation::Explained
    }
}

/// Ends one supervision tick's coverage interval when the tick body is left.
///
/// One published interval belongs to exactly one tick, so it has to end when that
/// tick ends — on the ordinary fall-through and on each `continue` alike. An
/// admission refusal and a lost Host are ordinary degraded outcomes in which
/// this owner still read a channel and recorded a live sample, and leaving the
/// window open there made the next tick republish that earned sample as
/// `INTERVAL_NOT_CLOSED` / `UNKNOWN`: present evidence discarded because an
/// unrelated branch was taken. Closing on drop removes that coupling — a new exit
/// path cannot forget a close it has no reason to know about.
///
/// It adds no owner, no second cell, and no flag a caller must remember to set.
/// [`IntervalCoverageCell::close_interval`] returns `None` when no interval is
/// open, so a second close is a no-op by construction rather than a double
/// publication, and a poisoned cell still publishes nothing.
struct CoverageIntervalCloser<'cell> {
    cell: &'cell IntervalCoverageCell,
}

impl Drop for CoverageIntervalCloser<'_> {
    fn drop(&mut self) {
        if let Some(closed) = self.cell.close_interval(current_unix_ms().unwrap_or(0)) {
            publish_interval_coverage(&closed, true);
        }
    }
}

/// Runtime-owned watchdog composition.
pub struct WatchdogComposition {
    runtime: Runtime,
    admission: Arc<dyn WatchdogAdmissionSource>,
    /// The injected Kernel port, retained so the admitted backup control port
    /// can reach the owner-held spool through the same owner the supervision
    /// task supervises through.
    ///
    /// The supervision task holds its own clone for the whole process lifetime,
    /// so retaining one here adds no second owner, no second spool handle, and
    /// no effect: the admitted backup port is the only reader this exposes.
    kernel: Arc<dyn KernelWatchdogPort>,
    authority_state: WatchdogAuthorityStateCell,
    config: WatchdogConfig,
    task: eliot_runtime::SupervisedHandle,
    shutdown_requested: Arc<AtomicBool>,
    heartbeat: Option<Arc<HeartbeatTransport>>,
    /// This composition's own bounded backup-control registration table.
    ///
    /// Opened once at composition start, so backup control is registrable for
    /// this composition's whole supervised lifetime and only this
    /// composition's own shutdown closes it. It is not a process global: a
    /// second composition in the same process opens its own table, and
    /// starting supervision never touches either one.
    backup_control_registration: BackupControlRegistration,
    /// This owner's shared per-interval I8.2 coverage cell.
    ///
    /// The very same cell the owner-bound backup port captures against, so the
    /// coverage a readiness projection claims and the coverage a fence carries
    /// are one publication, not two.
    coverage: Arc<IntervalCoverageCell>,
}

impl WatchdogComposition {
    /// Builds and admits the watchdog loop against an injected kernel port.
    ///
    /// # Errors
    ///
    /// Returns an error if runtime configuration or initial supervision
    /// authority is invalid, or if the runtime is already shutting down.
    pub fn start(
        config: WatchdogConfig,
        admission: Arc<dyn WatchdogAdmissionSource>,
        kernel: Arc<dyn KernelWatchdogPort>,
    ) -> Result<Self, CompositionError> {
        Self::start_with_shutdown(config, admission, kernel, Arc::new(AtomicBool::new(false)))
    }

    /// Starts the composition with a caller-owned stop flag.  SCM control
    /// handlers use this flag because they execute outside the Tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if runtime configuration is invalid or if the runtime
    /// denies task admission. An unavailable initial lease remains a nonfatal
    /// observation gap and publishes no current coverage epochs.
    pub fn start_with_shutdown(
        config: WatchdogConfig,
        admission: Arc<dyn WatchdogAdmissionSource>,
        kernel: Arc<dyn KernelWatchdogPort>,
        shutdown_requested: Arc<AtomicBool>,
    ) -> Result<Self, CompositionError> {
        let expected_host_image = admission.approved_host_image().ok_or_else(|| {
            CompositionError::InvalidConfiguration(
                "approved Host image is required for the production observer".to_owned(),
            )
        })?;
        let expected_host_registration =
            admission.approved_host_registration().ok_or_else(|| {
                CompositionError::InvalidConfiguration(
                    "installer-approved Host registration is required for the production observer"
                        .to_owned(),
                )
            })?;
        let host = Arc::new(LiveHostObservationSource::try_new(
            expected_host_image,
            expected_host_registration,
        ));
        Self::start_with_shutdown_and_host(config, admission, kernel, host, shutdown_requested)
    }

    /// Starts the composition with an injected read-only Host observation
    /// source. The source can classify Host loss but cannot perform lifecycle
    /// effects or supply supervision authority.
    ///
    /// # Errors
    ///
    /// Returns an error if runtime configuration is invalid or if the runtime
    /// denies task admission. An unavailable initial lease remains a nonfatal
    /// observation gap and publishes no current coverage epochs.
    pub fn start_with_shutdown_and_host(
        config: WatchdogConfig,
        admission: Arc<dyn WatchdogAdmissionSource>,
        kernel: Arc<dyn KernelWatchdogPort>,
        host: Arc<dyn HostObservationSource>,
        shutdown_requested: Arc<AtomicBool>,
    ) -> Result<Self, CompositionError> {
        Self::start_with_shutdown_and_host_and_heartbeat(
            config,
            admission,
            kernel,
            host,
            shutdown_requested,
            None,
        )
    }

    /// Starts the composition with an optional Host heartbeat sink. The
    /// sink receives one admitted emission per Kernel-accepted heartbeat;
    /// emission failures are traced inside the tick and never fail
    /// supervision. `None` preserves the stdout-only contour.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as
    /// [`Self::start_with_shutdown_and_host`].
    #[allow(
        clippy::too_many_lines,
        reason = "the bounded supervision task keeps admission, observation, heartbeat emission, and gap reporting in one reviewable contour"
    )]
    pub fn start_with_shutdown_and_host_and_heartbeat(
        config: WatchdogConfig,
        admission: Arc<dyn WatchdogAdmissionSource>,
        kernel: Arc<dyn KernelWatchdogPort>,
        host: Arc<dyn HostObservationSource>,
        shutdown_requested: Arc<AtomicBool>,
        heartbeat: Option<Arc<HeartbeatTransport>>,
    ) -> Result<Self, CompositionError> {
        let _span = tracing::debug_span!("watchdog.composition_start").entered();
        tracing::debug!(
            event = "watchdog.composition_requested",
            observation = "requested",
            "watchdog composition requested"
        );
        config.validate()?;
        let runtime = config.runtime()?;
        let task_admission = admission.clone();
        let task_host = host;
        let authority_state = WatchdogAuthorityStateCell::new();
        let task_authority_state = authority_state.clone();
        let task_heartbeat = heartbeat.clone();
        let task_kernel = Arc::clone(&kernel);
        // Reconciliation is a separate bounded side task: authenticated IPC
        // waits and durable receipt writes cannot lengthen a heartbeat tick.
        //
        // One permit bounds *both* intent classes. The escalation intents and the
        // Signal-linked publication intents travel the same admitted route over
        // the same durable submit-once ledger, so letting a pass of one run
        // concurrently with a pass of the other would mean two owners mutating
        // that one ledger from two in-flight transports. A single in-flight
        // reconciliation keeps the background work bounded and the ledger
        // single-writer; the next live tick retries whatever either class left
        // pending.
        let intent_reconciliation_slot = Arc::new(tokio::sync::Semaphore::new(1));
        let task_intent_reconciliation_slot = Arc::clone(&intent_reconciliation_slot);
        // I8.2 (#1755 W1/W5): one coverage cell per composition, shared with
        // the owner-bound backup port so the readiness claim and any capture
        // read the same publication. It is opened with the owner clock, and it
        // holds observations only.
        let coverage = kernel.spool_backup_port().map_or_else(
            || Arc::new(IntervalCoverageCell::new(current_unix_ms().unwrap_or(0))),
            |port| Arc::clone(port.coverage()),
        );
        let task_coverage = Arc::clone(&coverage);
        // I8.18 (#2381): one health-projection cell per composition, so the
        // previous interval a rule compares against is always this owner's own
        // last interval and never another composition's.
        let health = Arc::new(HealthProjectionCell::default());
        let task_health = Arc::clone(&health);
        let interval = config.tick_interval;
        let task = match runtime.supervisor(SupervisionStrategy::OneForOne).spawn(
            SERVICE_NAME,
            ChildClass::Worker,
            move |token| {
                let kernel = task_kernel.clone();
                let admission = task_admission.clone();
                let host = task_host.clone();
                let authority_state = task_authority_state.clone();
                let heartbeat = task_heartbeat.clone();
                let coverage = task_coverage.clone();
                let intent_reconciliation_slot =
                    Arc::clone(&task_intent_reconciliation_slot);
                let health = task_health.clone();
                async move {
                    loop {
                        tokio::select! {
                            () = token.cancelled() => return Ok(()),
                            () = tokio::time::sleep(interval) => {}
                        }
                        // I8.18 (#2381): the five health rules run on the
                        // interval the PREVIOUS tick closed, read before this
                        // tick opens its own window — `begin_interval` clears
                        // the published report, and an interval in progress
                        // establishes no coverage at all. Reading it here is
                        // therefore the only point at which a closed manifest
                        // exists, and it is read against the retained
                        // observation bank through the same owner handle every
                        // heartbeat appends through. A port that owns no spool,
                        // a sensor that has never held a lease, and the first
                        // interval after start are each reported as unknown
                        // evidence and open nothing; a rule that observes no
                        // delta is traced with its own named reason.
                        let now_ms = current_unix_ms().unwrap_or(0);
                        if let Some(closed) = coverage.latest() {
                            // I8.18 A4 (#2381): project the actual #1755
                            // interval manifest the five rules are about to
                            // run on, and publish its own interval identity,
                            // evidence handle, and gap verdict as bounded
                            // operator evidence on the same tick. The
                            // coverage-gap rule derives its explanation from
                            // these same public manifest claims, so the two
                            // can never contradict each other about one
                            // interval; the trace makes that agreement
                            // checkable per interval. Read-only: no store is
                            // touched beyond the closed report, and no effect
                            // is authorized.
                            let manifest = project_actual_coverage_manifest(&closed);
                            let manifest_verdict = match manifest.explanation {
                                CoverageGapExplanation::Explained => "explained",
                                CoverageGapExplanation::Unexplained => "unexplained",
                                CoverageGapExplanation::Unknown => "unknown",
                            };
                            tracing::debug!(
                                event = "watchdog.health_manifest_projected",
                                observation = "observed",
                                manifest_interval_id = manifest.interval_id.as_str(),
                                manifest_evidence = manifest.evidence.evidence_id.as_str(),
                                manifest_verdict = manifest_verdict,
                                "I8.18 health rules run against the owner-issued #1755 manifest on this interval"
                            );
                            evaluate_interval_health(
                                health.as_ref(),
                                &closed,
                                &manifest,
                                kernel.health_evidence(now_ms).as_ref(),
                            );
                        }
                        // I8.2 (#1755 W5): one published coverage interval is
                        // exactly one tick. Opening it here also reports a
                        // window the previous tick left open: the closer below
                        // ends that tick's interval on every one of its exit
                        // paths, so a window found open here is one whose close
                        // did not take effect. It is published as a named
                        // `INTERVAL_NOT_CLOSED` omission rather than silently
                        // replaced, so a sample can never be carried across a
                        // window it did not cover and an unfinished tick
                        // invalidates the last publication instead of widening
                        // it.
                        if let Some(abandoned) =
                            coverage.begin_interval(current_unix_ms().unwrap_or(0))
                        {
                            publish_interval_coverage(&abandoned, false);
                        }
                        let _interval_closer = CoverageIntervalCloser { cell: &coverage };
                        // Host liveness is an independent sibling observation.
                        // It must run even when a lease is missing, stale, or
                        // otherwise unavailable during first install/recovery.
                        let host_observation = host.observe();
                        let host_gap = host_observation.gap_reason();
                        // I8.2 (#1755 W5): this tick's Host read is the live
                        // sample for the two I8.2 channels it can actually
                        // reach. Every state other than `Unknown` was produced
                        // by the SCM registration readback inside `observe`,
                        // so the SCM channel is covered; `Unknown` may equally
                        // mean the readback itself failed, so it establishes
                        // no coverage at all. The health result (absent, PID
                        // reuse, image substitution) stays in `host_gap` and in
                        // `HostObservationState`; only the coverage disposition
                        // is recorded here.
                        if host_observation.state != HostObservationState::Unknown {
                            record_coverage_sample(
                                &coverage,
                                ObservationChannel::ScmServiceState,
                                ObservationClass::ServiceState,
                            );
                        }
                        if host_observation.identity.is_some() {
                            record_coverage_sample(
                                &coverage,
                                ObservationChannel::ProcessExitIdentity,
                                ObservationClass::ProcessIdentity,
                            );
                        }
                        let admission = match admission.reload() {
                            Ok(admission) => admission,
                            Err(error) => {
                                authority_state.publish_no_authority();
                                // I14.23: intentional and incomplete shutdown
                                // are distinct observed states, not generic
                                // gaps. The lease stays fenced either way;
                                // only the observation vocabulary differs so
                                // recovery can tell a clean stop from retained
                                // pending work.
                                if crate::supervision_lease_load::is_intentional_shutdown_fence(
                                    &error,
                                ) {
                                    tracing::info!(
                                        event = "watchdog.shutdown.intentional_observed",
                                        observation = "intentional",
                                        "watchdog observed intentional shutdown; pre-drain leases fenced"
                                    );
                                } else if crate::supervision_lease_load::is_incomplete_shutdown_fence(
                                    &error,
                                ) {
                                    tracing::info!(
                                        event = "watchdog.shutdown.incomplete_observed",
                                        observation = "incomplete",
                                        "watchdog observed incomplete shutdown; pending work retained"
                                    );
                                }
                                if let Some(reason) = host_gap {
                                    report_gap_nonfatal(kernel.as_ref(), reason).await;
                                }
                                report_gap_nonfatal(kernel.as_ref(), admission_gap_reason(&error))
                                    .await;
                                continue;
                            }
                        };
                        if let Some(reason) = host_gap {
                            authority_state.publish_no_authority();
                            // Observation/spool failure is nonfatal. The
                            // Watchdog remains alive and will retry on the
                            // next bounded tick; no restart-budget path is
                            // entered for a lost Host or stale lease.
                            report_gap_nonfatal(kernel.as_ref(), reason).await;
                            if matches!(
                                host_observation.state,
                                HostObservationState::PidReused
                                    | HostObservationState::ImageSubstituted
                                    | HostObservationState::IdentityChanged
                            ) {
                                // A changed process identity is eligible for
                                // one fresh baseline only after this tick's
                                // signed lease was verified. Absent/unknown
                                // observations never get a free baseline.
                                host.rebaseline_after_verified_lease(admission.lease());
                            }
                            continue;
                        }
                        match kernel.supervise(admission.lease()).await {
                            Ok(()) => {
                                // I8.2 (#1755 W5): the Kernel channel is
                                // observed live only on this arm, where the
                                // heartbeat was actually recorded in the
                                // Watchdog's own spool. Nothing answers on the
                                // far side, so the accepted append is the whole
                                // of the evidence, and a refusal below is not
                                // this class at all — it is reported as the
                                // health gap it is, and the channel stays
                                // unobserved.
                                record_coverage_sample(
                                    &coverage,
                                    ObservationChannel::KernelHeartbeat,
                                    ObservationClass::Liveness,
                                );
                                let kernel_epoch =
                                    admission.lease().lease().kernel_epoch.sequence.get();
                                let watchdog_epoch = admission.watchdog_epoch().value();
                                authority_state.publish_admitted(kernel_epoch, watchdog_epoch);
                                // I8.18 (#2381): the health projection's signal
                                // target and expected revisions come from the
                                // same verified lease this tick supervises
                                // through, on the admitted path only. A
                                // degraded tick never admits a lease, so it
                                // leaves the last admitted revisions in place
                                // rather than substituting a placeholder scope.
                                if let Some(installation_id) = kernel.installation_identity() {
                                    health.observe_admitted(
                                        installation_id,
                                        admission.lease().lease().scope_ref.as_str(),
                                        kernel_epoch,
                                        watchdog_epoch,
                                    );
                                }
                                emit_admitted_heartbeat_best_effort(
                                    heartbeat.as_ref(),
                                    kernel_epoch,
                                    watchdog_epoch,
                                    interval.as_millis(),
                                )
                                .await;
                                // Submit retained Watchdog intents only after
                                // this exact signed lease passed continuous
                                // admission and Kernel supervision. One
                                // in-flight pass bounds background work; the
                                // next live tick retries any retained record
                                // after a failed/unknown transport outcome.
                                if let Ok(permit) = Arc::clone(&intent_reconciliation_slot)
                                    .try_acquire_owned()
                                {
                                    let reconcile_kernel = Arc::clone(&kernel);
                                    let verified_lease = admission.lease().clone();
                                    tokio::spawn(async move {
                                        match reconcile_kernel
                                            .reconcile_intents(verified_lease)
                                            .await
                                        {
                                            Ok(crate::WatchdogIntentReconciliation::NothingPending) => {}
                                            Ok(crate::WatchdogIntentReconciliation::Reconciled {
                                                first_sequence,
                                                recorded,
                                                already_submitted,
                                            }) => tracing::info!(
                                                event = "watchdog.intent_reconciliation_recorded",
                                                first_sequence,
                                                recorded,
                                                already_submitted,
                                                canonical_decision = "pending_governor_decision",
                                                "Kernel recorded Watchdog intents for later Governor decision"
                                            ),
                                            Ok(crate::WatchdogIntentReconciliation::Blocked {
                                                pending_sequence,
                                                reason,
                                                ..
                                            }) => tracing::warn!(
                                                event = "watchdog.intent_reconciliation_blocked",
                                                pending_sequence,
                                                reason = ?reason,
                                                "retained Watchdog intent is outside the current bounded export window"
                                            ),
                                            Err(error) => tracing::debug!(
                                                event = "watchdog.intent_reconciliation_skipped",
                                                error = %error,
                                                "Watchdog intent reconciliation did not receive a verified Kernel acknowledgement"
                                            ),
                                        }
                                        drop(permit);
                                    });
                                }
                                // The retained Signal-linked publication intents
                                // are presented on the same admitted lease and
                                // through the same admitted route, in the same
                                // bounded background slot. Sharing the slot is
                                // what keeps background work bounded: one
                                // in-flight pass at a time, and the next live
                                // tick retries whatever a failed or unknown
                                // transport outcome left pending. A publication
                                // intent authorizes nothing here — the route
                                // records a bounded pending projection and the
                                // canonical Problem/attention/Incident decision
                                // stays with the owner that already owns it.
                                if let Ok(permit) = Arc::clone(&intent_reconciliation_slot)
                                    .try_acquire_owned()
                                {
                                    let reconcile_kernel = Arc::clone(&kernel);
                                    let verified_lease = admission.lease().clone();
                                    tokio::spawn(async move {
                                        match reconcile_kernel
                                            .reconcile_publications(verified_lease)
                                            .await
                                        {
                                            Ok(crate::WatchdogPublicationReconciliation::NothingPending) => {}
                                            Ok(crate::WatchdogPublicationReconciliation::Reconciled {
                                                first_sequence,
                                                recorded,
                                                already_acknowledged,
                                            }) => tracing::info!(
                                                event = "watchdog.publication_reconciliation_recorded",
                                                first_sequence,
                                                recorded,
                                                already_acknowledged,
                                                canonical_decision = "pending_governor_decision",
                                                "the admitted owner recorded Watchdog publication intents; no canonical Problem or Incident was decided"
                                            ),
                                            Ok(crate::WatchdogPublicationReconciliation::Blocked {
                                                pending_sequence,
                                                reason,
                                                ..
                                            }) => tracing::warn!(
                                                event = "watchdog.publication_reconciliation_blocked",
                                                pending_sequence,
                                                reason = ?reason,
                                                "a retained Watchdog publication intent is outside the current bounded export window and stays pending"
                                            ),
                                            Err(error) => tracing::debug!(
                                                event = "watchdog.publication_reconciliation_skipped",
                                                error = %error,
                                                "Watchdog publication reconciliation did not receive an acknowledged outcome; the retained intents stay pending"
                                            ),
                                        }
                                        drop(permit);
                                    });
                                }
                            }
                            Err(error) => {
                                authority_state.publish_no_authority();
                                report_gap_nonfatal(kernel.as_ref(), kernel_gap_reason(&error))
                                    .await;
                            }
                        }
                        // The interval is closed by `_interval_closer` when this
                        // tick body ends, so the degraded `continue` paths above
                        // and this fall-through publish through the same close.
                    }
                }
            },
        ) {
            eliot_runtime::SpawnDisposition::Admitted(task) => {
                tracing::info!(
                    event = "watchdog.composition_admitted",
                    observation = "admitted",
                    "watchdog supervision task admitted"
                );
                task
            }
            eliot_runtime::SpawnDisposition::DeniedShuttingDown => {
                // Refusal, not failed execution: the runtime is already
                // shutting down, so no supervision task was admitted.
                tracing::warn!(
                    event = "watchdog.composition_refused",
                    observation = "refused",
                    reason_code = "ADMISSION_CLOSED",
                    "watchdog composition refused: runtime is shutting down"
                );
                return Err(CompositionError::AdmissionClosed);
            }
        };
        Ok(Self {
            runtime,
            admission,
            kernel,
            authority_state,
            config,
            task,
            shutdown_requested,
            heartbeat,
            backup_control_registration: BackupControlRegistration::open(),
            coverage,
        })
    }

    #[must_use]
    pub fn readiness(&self) -> WatchdogReadiness {
        let snapshot = self.authority_state.load();
        let (service_instance_guid, host_challenge_nonce, watchdog_readiness_sequence) =
            self.heartbeat.as_ref().map_or_else(
                || {
                    (
                        String::new(),
                        String::new(),
                        crate::heartbeat_transport::FENCE_SEQUENCE,
                    )
                },
                |transport| {
                    let (service_instance_guid, host_challenge_nonce) = transport.echo_identity();
                    (
                        service_instance_guid,
                        host_challenge_nonce,
                        transport.last_sequence(),
                    )
                },
            );
        WatchdogReadiness {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            authority_state: snapshot.state,
            // I8.2 (#1755 W5): admitted authority is not coverage. The claim
            // is the conjunction of admitted authority and a closed interval
            // whose every I8.2 channel was observed CONTINUOUS, so one good
            // channel cannot erase another channel's blind interval and an
            // owner that has not closed an interval yet claims nothing.
            coverage_claimed: snapshot.state.coverage_claimed()
                && self
                    .coverage
                    .latest()
                    .is_some_and(|report| report.full_coverage_claimed()),
            kernel_epoch: snapshot.kernel_epoch,
            watchdog_epoch: snapshot.watchdog_epoch,
            tick_interval_ms: self.config.tick_interval.as_millis(),
            service_instance_guid,
            host_challenge_nonce,
            watchdog_readiness_sequence,
        }
    }

    /// Waits for process termination and performs ordered runtime shutdown.
    ///
    /// Supervision STARTING is not a lifecycle end for backup control: this
    /// method only begins waiting, so it does not close, release, or otherwise
    /// touch the composition's backup-control registration table. Registration
    /// stays open for the whole supervised lifetime and is closed only by the
    /// genuine shutdown path, [`request_shutdown`](Self::request_shutdown).
    /// Backup control holds no supervised task, so bounded cleanup needs no
    /// join here and supervision priority is preserved.
    ///
    /// # Errors
    ///
    /// Returns an error if the supervised watchdog task, shutdown signal, or
    /// externally requested shutdown path fails.
    pub async fn run_until_shutdown(self) -> Result<ShutdownOutcome, TaskFailure> {
        let _span = tracing::info_span!("watchdog.run_until_shutdown").entered();
        tracing::info!(
            event = "watchdog.supervision_running",
            observation = "admitted",
            "watchdog supervision running until shutdown"
        );
        let WatchdogComposition {
            runtime,
            admission,
            task,
            shutdown_requested,
            ..
        } = self;
        let _admission_source = admission;
        let mut task_result = Box::pin(task.join());
        tokio::select! {
            result = &mut task_result => {
                let shutdown = runtime.shutdown().await;
                report_restart_budget_exhaustion(&result);
                result.map(|_| shutdown)
            }
            signal = tokio::signal::ctrl_c() => {
                if signal.is_err() {
                    return Err(TaskFailure::Failed("failed to receive shutdown signal".to_owned()));
                }
                runtime.shutdown_handle().request();
                let result = task_result.await;
                let shutdown = runtime.shutdown().await;
                report_restart_budget_exhaustion(&result);
                complete_requested_shutdown(result, shutdown)
            }
            result = wait_for_shutdown(shutdown_requested) => {
                if result {
                    runtime.shutdown_handle().request();
                    let result = task_result.await;
                    let shutdown = runtime.shutdown().await;
                    report_restart_budget_exhaustion(&result);
                    complete_requested_shutdown(result, shutdown)
                } else {
                    Err(TaskFailure::Failed("watchdog shutdown signal failed".to_owned()))
                }
            }
        }
    }

    /// Registers the admitted backup control port against this composition.
    ///
    /// Delegates to [`crate::backup_control::register_backup_control`], which
    /// binds the port to the owner-held spool reachable through
    /// [`Self::owner_backup_port`] and reserves a slot in THIS composition's own
    /// bounded registration table. Backup control holds no supervision task:
    /// it cannot stall supervision or exhaust the Control Reserve.
    ///
    /// Registration is refused only by this composition's own bounded table
    /// (exhausted, or closed by this composition's own shutdown), by an
    /// unrecognized composition identity, or by an unreachable owner spool.
    /// Starting supervision does not close it, and another composition's
    /// shutdown does not affect it, so the port stays registrable for the whole
    /// supervised lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`crate::BackupControlError`] when the composition identity is
    /// unexpected, when the injected kernel port owns no spool, when the
    /// owner-bound spool is not reachable, or when this composition's own
    /// bounded registration table is exhausted or closed.
    pub fn register_backup_control(
        &self,
    ) -> Result<crate::backup_control::BackupControlHandle, crate::BackupControlError> {
        crate::backup_control::register_backup_control(self)
    }

    /// Returns this composition's own bounded backup-control registration
    /// table, so registration is scoped to this lifecycle.
    ///
    /// Cloned into each registered handle, never into process-global state: a
    /// fresh composition opens its own open table, and only
    /// [`Self::request_shutdown`] closes this one.
    pub(crate) fn backup_control_registration(&self) -> BackupControlRegistration {
        self.backup_control_registration.clone()
    }

    /// Returns the owner-bound backup port exposed by this composition's
    /// kernel port, or `None` when the injected port owns no spool.
    ///
    /// This is the only route from the composition to the Watchdog spool: the
    /// composition holds no `WatchdogSpool` of its own, so the single owner
    /// handle lives inside the sensor that also appends every heartbeat and
    /// gap record. No second database handle is opened anywhere on this path.
    pub(crate) fn owner_backup_port(&self) -> Option<Arc<WatchdogBackupPort>> {
        self.kernel.spool_backup_port()
    }

    /// Requests bounded shutdown from an SCM control path.
    pub fn request_shutdown(&self) {
        // Genuine lifecycle end: this composition closes its OWN backup-control
        // table, releasing exactly its registrations. Backup control holds no
        // task to join: shutdown stays bounded and supervision teardown never
        // waits on backup wiring.
        self.backup_control_registration.close();
        self.shutdown_requested.store(true, Ordering::Release);
    }
}

/// Records a restart-budget-exhausted supervision terminal, if that is what
/// the supervised task reached.
///
/// Observation only: [`SupervisionOutcome::Quarantined`] is the exact typed
/// restart-budget-exhaustion signal from the runtime supervisor (I1.4
/// quarantine), and without this record it would be indistinguishable from a
/// completed supervision. Every other terminal keeps its existing downstream
/// record: task failures surface through the runtime-failure boundary and
/// cancellation through shutdown. The return value is untouched: logging never
/// changes supervision, recovery, or shutdown behavior.
fn report_restart_budget_exhaustion(result: &Result<SupervisionOutcome, TaskFailure>) {
    if matches!(result, Ok(SupervisionOutcome::Quarantined)) {
        tracing::error!(
            event = "watchdog.restart_budget_exhausted",
            supervision_outcome = "quarantined",
            failure_code = "RESTART_BUDGET_EXHAUSTED",
            "watchdog supervision task quarantined after restart-budget exhaustion"
        );
    }
}

fn complete_requested_shutdown<T>(
    result: Result<T, TaskFailure>,
    shutdown: ShutdownOutcome,
) -> Result<ShutdownOutcome, TaskFailure> {
    match result {
        Ok(_) | Err(TaskFailure::Cancelled) => Ok(shutdown),
        Err(error) => Err(error),
    }
}

/// Emits one admitted heartbeat best-effort: emission failures are traced
/// and never fail the supervision tick.
async fn emit_admitted_heartbeat_best_effort(
    heartbeat: Option<&Arc<HeartbeatTransport>>,
    kernel_epoch: u64,
    watchdog_epoch: u64,
    tick_interval_ms: u128,
) {
    let Some(transport) = heartbeat else {
        return;
    };
    if let Err(error) = transport
        .emit_admitted(kernel_epoch, watchdog_epoch, tick_interval_ms)
        .await
    {
        tracing::debug!(
            event = "watchdog.heartbeat.emit_skipped",
            observation = "attempted",
            error_code = match &error {
                HeartbeatTransportError::Unavailable(_) => "transport_unavailable",
                HeartbeatTransportError::InvalidDescriptor(_) => "invalid_descriptor",
                HeartbeatTransportError::Emit(_) => "emission_failed",
            },
            "heartbeat emission skipped; supervision continues"
        );
    }
}

async fn wait_for_shutdown(shutdown_requested: Arc<AtomicBool>) -> bool {
    loop {
        if shutdown_requested.load(Ordering::Acquire) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Owner-bound admitted backup control port over the Watchdog spool.
///
/// The port is bound to the exact owner that holds the spool: the construction
/// seam is the same
/// [`IndependentKernelSensor`](crate::IndependentKernelSensor) that appends
/// through `KernelWatchdogPort::supervise`, so the composition's kernel port
/// hands out this one object and no second database handle is ever opened. The
/// port also carries that owner's retained installation identity and watchdog
/// generation, and binds every request and every fence against those
/// owner-held values, failing closed on any mismatch.
///
/// The caller must be the admitted backup role (`BackupRole::SpoolOwner` per
/// #954). Role authentication happens above this port: this crate carries no
/// `eliot-protocol` dependency, so this type takes no role argument and mints
/// no authority. The port therefore validates no peer identity and no
/// generation fence of its own; those need the role-bound control contract.
///
/// Every method runs OUTSIDE the heartbeat tick with finite limits, so backup
/// work can never block Control Reserve through unbounded work. Captures are
/// read-only owner transactions; isolated imports target only the externally
/// admitted isolated installation and never reuse the active lease, heartbeat
/// readiness, supervision authority, or kernel/watchdog epochs. This port
/// performs no SCM, restart, cutover, authority, lease, epoch, or transport
/// work, and changes nothing on the start/readiness/heartbeat paths.
pub struct WatchdogBackupPort {
    spool: Arc<WatchdogSpool>,
    source_installation: String,
    watchdog_generation: u64,
    limits: WatchdogSpoolBackupLimits,
    /// This owner's shared per-interval I8.2 coverage cell.
    ///
    /// The same cell the bounded supervision tick publishes into, so a capture
    /// carries the coverage this owner actually observed rather than coverage
    /// a caller asserted. It holds observations only: no lease, heartbeat,
    /// supervision, or epoch authority passes through it.
    coverage: Arc<IntervalCoverageCell>,
}

impl WatchdogBackupPort {
    /// Binds the admitted port to the composition's spool owner handle, that
    /// owner's retained identities, and finite page limits.
    ///
    /// The spool handle is the same owner the supervision path appends
    /// through; no second database handle is opened and no global state is
    /// introduced. `source_installation` and `watchdog_generation` are the
    /// owner's own retained binding values, not caller input: every later
    /// capture and page read is bound against them. `limits` bounds every
    /// later [`Self::read_page`] call.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when `limits` is unbounded, unprogressable, or
    /// above its hard ceilings, when the owner installation identity is
    /// unusable, or when the owner generation is zero.
    pub(crate) fn new(
        spool: Arc<WatchdogSpool>,
        source_installation: String,
        watchdog_generation: u64,
        limits: WatchdogSpoolBackupLimits,
        coverage: Arc<IntervalCoverageCell>,
    ) -> Result<Self, SpoolError> {
        limits.validate()?;
        if source_installation.trim().is_empty()
            || source_installation.chars().any(char::is_control)
        {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses an unusable owner installation identity".to_owned(),
            ));
        }
        if watchdog_generation == 0 {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses an uninitialized owner generation".to_owned(),
            ));
        }
        Ok(Self {
            spool,
            source_installation,
            watchdog_generation,
            limits,
            coverage,
        })
    }

    /// Returns this owner's shared per-interval coverage cell.
    #[must_use]
    pub(crate) fn coverage(&self) -> &Arc<IntervalCoverageCell> {
        &self.coverage
    }

    /// Returns the owner-held installation identity this port is bound to.
    #[must_use]
    pub fn source_installation(&self) -> &str {
        &self.source_installation
    }

    /// Returns the owner-held watchdog generation this port is bound to.
    #[must_use]
    pub const fn watchdog_generation(&self) -> u64 {
        self.watchdog_generation
    }

    /// Proves the owner spool this port is bound to is live and readable now.
    ///
    /// One real read transaction against the owner's own `watchdog.redb`
    /// high-water metadata, through the same owner handle every heartbeat and
    /// gap record is appended through. No second database is opened and no
    /// state is mutated.
    ///
    /// The returned value is the owner's own durable sequence, not a synthetic
    /// one. Callers use this to establish that the resource behind a backup
    /// registration is genuinely reachable, instead of establishing only that a
    /// slot number was handed out; it mints no identity, authority, fence, or
    /// approval, and it is not a health verdict about the owner.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the owner's database cannot be read or its
    /// high-water metadata is absent or invalid.
    pub(crate) fn owner_spool_high_water(&self) -> Result<u64, SpoolError> {
        self.spool.high_water_sequence()
    }

    /// Binds one capture request against the owner's retained identity.
    ///
    /// The requested source installation and watchdog generation are compared
    /// with the values the owner itself holds, so a request naming another
    /// installation or another generation fails closed instead of producing a
    /// fence that claims the wrong provenance.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when either binding differs from the owner's.
    fn check_owner_bindings(&self, params: &CaptureFenceParams) -> Result<(), SpoolError> {
        if params.source_installation != self.source_installation {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses a capture for a foreign source installation"
                    .to_owned(),
            ));
        }
        if params.watchdog_generation != self.watchdog_generation {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses a capture for a foreign watchdog generation"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Captures one bounded coherent fence through the spool owner.
    ///
    /// Thin delegation to `WatchdogSpool::snapshot_backup`: one bounded read
    /// transaction over header, high-water, and retained entries, after the
    /// request is bound against the owner-held installation identity and
    /// generation.
    ///
    /// The captured fence is then put through the SAME age window
    /// [`Self::read_page`] applies, by the same [`Self::check_capture_age`]
    /// check against the same owner clock. That is what keeps the two halves
    /// of this port from disagreeing: the freshness anchor is the fence's
    /// capture anchor, which is the newest retained observation rather than a
    /// wall-clock instant (this fence builder is clock-free and mints no
    /// instant of its own), so a spool whose newest retained observation is
    /// already older than the admitted window yields a fence that could never
    /// be paged. Refusing it here, with the identical reason and verdict a
    /// page read would give, is the honest outcome — the alternative is handing
    /// out a capture that is born expired. Nothing is invented to avoid that
    /// refusal: no second clock is read and no timestamp is stamped, so a
    /// capture is still admitted exactly when the same fence would still pass
    /// its own page read.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the admitted bindings or limits fail
    /// validation, the retained evidence fails capture validation, or the
    /// captured fence is outside the admitted page-freshness and
    /// whole-snapshot lifetime windows.
    pub fn snapshot(
        &self,
        params: CaptureFenceParams,
        limits: WatchdogSpoolBackupLimits,
    ) -> Result<WatchdogSpoolFence, SpoolError> {
        self.check_owner_bindings(&params)?;
        // I8.2 (#1755 W5): the capture carries the coverage this owner most
        // recently published, never caller-supplied coverage. `None` — no
        // interval closed yet — is retained as unknown coverage, so the fence
        // cannot report a full-coverage claim before the owner observed
        // anything.
        let channel_coverage = self.coverage.latest();
        let fence = self
            .spool
            .snapshot_backup(params, limits, channel_coverage.as_ref())?;
        self.check_capture_age(&fence)?;
        Ok(fence)
    }

    /// Applies the owner clock's capture-age window to one fence.
    ///
    /// The anchor is [`WatchdogSpoolFence::captured_at_ms`] — the newest
    /// retained observation the fence carries, which is never later than its own
    /// evidence — measured against this owner's own clock with the bounds fixed
    /// at [`Self::new`]. A future-dated anchor, or one older than either the
    /// page-freshness window or the whole-snapshot lifetime window, is refused.
    ///
    /// Both [`Self::snapshot`] and [`Self::read_page`] call this one function, so
    /// for the same fence and the same instant the two halves of this port give
    /// the same verdict: capture admits exactly the fences a later page read
    /// would still accept, and refuses a born-expired fence instead of issuing
    /// one that can never be paged. The reasons below name both callers because
    /// the check is one check.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the owner clock is unavailable, the fence is
    /// future-dated, or the fence is older than the admitted freshness or
    /// lifetime window.
    fn check_capture_age(&self, fence: &WatchdogSpoolFence) -> Result<(), SpoolError> {
        let now_ms = crate::current_unix_ms()?;
        if now_ms < fence.captured_at_ms {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses a future-dated capture; a page read of it would be refused"
                    .to_owned(),
            ));
        }
        let age_ms = now_ms - fence.captured_at_ms;
        if age_ms > self.limits.page_ttl_ms || age_ms > self.limits.snapshot_lifetime_ms {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses an expired capture; a page read of it would be refused"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Reads one finite, unexpired page of a captured fence.
    ///
    /// The fence is re-validated against the evidence it holds, bound against
    /// the owner-held installation identity and generation, and bounded by the
    /// limits fixed at [`Self::new`]. The clock-dependent page-freshness and
    /// whole-snapshot lifetime windows are consulted here against the owner's
    /// own clock, through the same [`Self::check_capture_age`] that
    /// [`Self::snapshot`] applies: an expired fence is incomplete, never a
    /// current empty page. Continuation binds the one fence digest, so drift
    /// fails closed instead of returning partial coverage.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the fence fails re-validation, is not this
    /// owner's, the page is older than the admitted freshness or lifetime
    /// window, the page runs past the retained window, or the cumulative bound
    /// is exceeded.
    pub fn read_page(
        &self,
        fence: &WatchdogSpoolFence,
        page_index: u64,
    ) -> Result<WatchdogSpoolSnapshotPage, SpoolError> {
        fence.validate()?;
        if fence.source_installation != self.source_installation {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses a page read for a foreign source installation"
                    .to_owned(),
            ));
        }
        if fence.watchdog_generation != self.watchdog_generation {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses a page read for a foreign watchdog generation"
                    .to_owned(),
            ));
        }
        self.check_capture_age(fence)?;
        crate::watchdog_spool::backup::read_page(fence, page_index, &self.limits)
    }

    /// Imports bounded restore steps INTO THE ADMITTED ISOLATED DESTINATION and
    /// reports whether recovery is accepted.
    ///
    /// Thin delegation to `WatchdogSpool::import_backup_isolated`. The `active`
    /// argument is this OWNER'S OWN RETAINED RUNTIME BINDING, not a caller
    /// string, and that is what makes the isolation gate mean anything: the
    /// owner reads the active installation identity and the active Watchdog
    /// state root out of its own digest-verified, root-leased admission — the
    /// same admission its live spool was opened from — and compares the
    /// destination's own owner-issued identity and state root against them. A
    /// caller cannot present a convenient "active" installation to make the
    /// comparison a comparison of its own claim with itself, and a destination
    /// that shares the active state root is refused even when its installation
    /// identity differs, because then it is the same store.
    ///
    /// The port still refuses a request whose `active` binding is not THIS
    /// owner's own retained admission, so a foreign active installation fails
    /// closed with its own exact reason before the owner path runs.
    ///
    /// The destination is not a string: it is the externally admitted
    /// installation binding, and the admitted destination's own owner-issued
    /// identity is what the isolation gate compares — so the destination must
    /// differ from both `source` and the active identity by owner-issued fact,
    /// not by presentation. Old signed observations stay historical evidence
    /// under their exact source identity and grant no active supervision,
    /// heartbeat, lease, or epoch authority. A repeated byte-identical import
    /// appends nothing to the destination; the observed disposition is then
    /// passed through `acceptance_allowed`, so an unresolved reconciliation
    /// blocks recovery acceptance instead of returning zero by default.
    ///
    /// `destination: None` is refused by the owner with
    /// [`SpoolError::InvalidLease`]; this port never substitutes the active
    /// installation's own spool for a missing destination admission.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the active identity is not the owner's, no
    /// externally admitted destination was supplied, the destination is not
    /// isolated on either the identity or the state-root axis, its spool cannot
    /// be opened, the step chain breaks, content conflicts, or reconciliation
    /// is unknown.
    pub fn import_isolated(
        &self,
        source: &str,
        destination: Option<&AdmittedIsolatedDestination>,
        active: &WatchdogRuntimeBinding,
        steps: &[SpoolRestoreStep],
    ) -> Result<SpoolRestoreDisposition, SpoolError> {
        // The active identity is read out of the owner's own retained runtime
        // admission by the same owner-issued reader the spool import uses, not
        // from a caller string, so this port and the owner cannot disagree
        // about which installation is live.
        if owner_issued_active_installation(active) != self.source_installation {
            return Err(SpoolError::Corrupt(
                "watchdog backup port refuses an import bound to an active installation that is not this owner's retained admission"
                    .to_owned(),
            ));
        }
        let disposition =
            WatchdogSpool::import_backup_isolated(source, destination, active, steps)?;
        crate::watchdog_spool::backup::acceptance_allowed(disposition)?;
        Ok(disposition)
    }
}
