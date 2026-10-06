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
use crate::host_identity_observation::{
    ApprovedRecoveryPolicy, ApprovedRegistrationReadback, BoundedChallengeWait,
    ChallengeAttemptOutcome, ChallengeUncertainty, HostObservation, HostResponsiveness,
    MAX_CHALLENGE_WAIT_SECS,
};
use crate::host_recovery::{
    AuditCorrelation, AuditEventKind, BoundaryEvidence, DualAuditRecord,
    EXISTING_SCM_ADAPTER_GUARANTEE, RecoveryFence, RecoveryOperation, RecoveryScope,
    RecoveryTarget, begin_recovery_operation, bounded_responsiveness, fence_recovery,
    identity_digest, read_recovery_budget, read_recovery_operation, record_recovery_audit,
    record_recovery_budget,
};
use crate::kernel_gap_reason;
use crate::observation_coverage::{
    CoverageDisposition, IntervalCoverageCell, IntervalCoveragePublication, IntervalCoverageReport,
    ObservationChannel, ObservationClass, RecordOutcome, channel_capability,
};
use crate::report_gap_nonfatal;
use crate::watchdog_spool::WatchdogSpool;
use crate::watchdog_spool::attempt as attempt_evidence;
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

/// Retains one published shared coverage manifest in the owner spool (#1755
/// W6).
///
/// `true` when the payload reached durable owner evidence. `false` when the
/// interval was omitted (nothing to retain, and the previously retained row
/// stands) or when no owner spool is bound or the retain failed: the tick
/// traces the miss, and an omission never clears a previously published
/// manifest, so the reader always sees a complete retained row or nothing.
fn retain_published_shared_manifest(
    port: Option<&WatchdogBackupPort>,
    outcome: &crate::coverage_manifest_projection::CoverageManifestOutcome,
) -> bool {
    let crate::coverage_manifest_projection::CoverageManifestOutcome::Published {
        manifest, ..
    } = outcome
    else {
        return false;
    };
    let Some(port) = port else {
        return false;
    };
    port.retain_shared_coverage_manifest(manifest).is_ok()
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
                            // Issue #1755 (W6): the SAME closed interval also
                            // projects into the shared
                            // `ObservationCoverageManifest`, which until now
                            // had no producer anywhere in the workspace. Both
                            // identities come from the admitted Kernel port;
                            // when either is unavailable the interval is a named
                            // omission and no manifest is invented, so a
                            // fabricated denominator can never reach evidence.
                            let shared = crate::coverage_manifest_projection::
                                publish_interval_coverage_manifest(
                                    kernel.installation_identity(),
                                    kernel.allowed_manifest_digest(),
                                    &closed,
                                );
                            // Issue #1755 (W7): gate every channel's
                            // downstream absence/compliance claim on the
                            // exact active profile the admitted port
                            // supplies, if any. The verdicts are operator
                            // evidence on the same tick, like the gap
                            // verdict above: a channel without a named
                            // competent sensor keeps its gap and earns no
                            // claim downstream (#1756/#1758), and a port
                            // that resolved no profile disables every
                            // claim rather than substituting one.
                            let gated_claims =
                                crate::observation_coverage::gate_downstream_claims(
                                    &closed,
                                    kernel.active_coverage_profile().as_ref(),
                                );
                            tracing::debug!(
                                event = "watchdog.downstream_claims_gated",
                                observation = "gated",
                                gated_allowed = gated_claims
                                    .iter()
                                    .filter(|claim| claim.claim_allowed)
                                    .count(),
                                gated_blocked = gated_claims
                                    .iter()
                                    .filter(|claim| !claim.claim_allowed)
                                    .map(|claim| claim.channel.as_str())
                                    .collect::<Vec<_>>()
                                    .join(","),
                                "downstream absence/compliance claims gated on the active coverage profile for this interval"
                            );
                            // The payload reaches the owner spool on this
                            // tick (#1755 W6); the log keeps the summary
                            // only. A retain miss is warned: evidence that
                            // was built but not retained must be visible, and
                            // the next published interval replaces the row
                            // anyway.
                            let retained = retain_published_shared_manifest(
                                kernel.spool_backup_port().as_deref(),
                                &shared,
                            );
                            match &shared {
                                crate::coverage_manifest_projection::CoverageManifestOutcome::Published {
                                    completeness,
                                    streams,
                                    ..
                                } => {
                                    if retained {
                                        tracing::debug!(
                                            event = "watchdog.shared_coverage_manifest_published",
                                            observation = "published",
                                            completeness = ?completeness,
                                            streams = streams,
                                            "shared ObservationCoverageManifest built and retained from this interval"
                                        );
                                    } else {
                                        tracing::warn!(
                                            event = "watchdog.shared_coverage_manifest_retain_missed",
                                            observation = "unretained",
                                            completeness = ?completeness,
                                            streams = streams,
                                            "shared ObservationCoverageManifest built but not retained in the owner spool"
                                        );
                                    }
                                }
                                crate::coverage_manifest_projection::CoverageManifestOutcome::Omitted(
                                    reason,
                                ) => {
                                    tracing::debug!(
                                        event = "watchdog.shared_coverage_manifest_omitted",
                                        observation = "omitted",
                                        reason = reason,
                                        "no owner identity for the shared denominator; no manifest invented"
                                    );
                                }
                            }
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
                        // I8.2 (#1755 W2): this tick's approved-artifact digest
                        // is the live sample for the artifact half of the
                        // ArtifactConfigIdentity channel. The digest is read
                        // through the retained no-follow image lease and
                        // hashed, never retained: bytes are event evidence,
                        // not file contents. A refused probe records no
                        // sample, so the channel stays UNKNOWN on denial and
                        // PARTIAL while config identity has no reader — never
                        // healthy-by-absence. Readiness stays explicitly
                        // unprobed: a matching digest is integrity evidence,
                        // not application readiness.
                        if let Some(digest) = host.observe_approved_artifact(
                            crate::independent_sensor::MAX_APPROVED_ARTIFACT_DIGEST_BYTES,
                        ) {
                            tracing::debug!(
                                event = "watchdog.artifact_digest_observed",
                                observation = "observed",
                                digest = digest.digest(),
                                bytes = digest.bytes(),
                                readiness = digest.readiness().as_str(),
                                "approved artifact digest bound to the retained installation generation"
                            );
                            record_coverage_sample(
                                &coverage,
                                ObservationChannel::ArtifactConfigIdentity,
                                ObservationClass::ArtifactDigest,
                            );
                        }
                        // I8.2 (#1755 W2-rem): this tick exercises the store-endpoint
                        // probe feeding the StoreProcessHealth and
                        // ListenerInventory channels (manifest-shaped target ->
                        // OS listener-owner table -> platform PID-to-identity
                        // binding -> approved-image match; see
                        // `store_endpoint_observation`). A refused probe
                        // records no sample, so both channels stay UNKNOWN
                        // rather than healthy-by-absence.
                        if let Some(store) = host.observe_store_endpoint() {
                            tracing::debug!(
                                event = "watchdog.store_endpoint_observed",
                                observation = "observed",
                                endpoint = store.endpoint().to_string(),
                                process_id = store.process_id(),
                                readiness = store.readiness().as_str(),
                                "store loopback listener owned by the approved store image process"
                            );
                            record_coverage_sample(
                                &coverage,
                                ObservationChannel::StoreProcessHealth,
                                ObservationClass::ReadOnlyProbe,
                            );
                            record_coverage_sample(
                                &coverage,
                                ObservationChannel::ListenerInventory,
                                ObservationClass::ListenerBinding,
                            );
                        }
                        // I8.2 (#1755 W3/C6): one registered-scope journal-replay
                        // step over the admitted scopes. No production registrar
                        // issues scopes, so the admitted set is empty here and
                        // the step is a measured no-op; the disposable scopes
                        // that prove it are owner-issued test-side. The step
                        // takes no daemon handle: with `eliotd` down this still
                        // runs on the owner spool and platform reads alone.
                        if let Some(port) = kernel.spool_backup_port() {
                            let _ = crate::registered_scope_replay::replay_registered_scopes(
                                port.spool.as_ref(),
                                &coverage,
                                &[],
                                &[],
                                &[],
                                crate::registered_scope_replay::JOURNAL_REPLAY_PAGE_BYTES,
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
                        // I8.3 (#1757 W10): one journal-before-effects
                        // recovery decision pass over this tick's live Host
                        // observation. Decision only: it journals through
                        // the owner-held watchdog.redb and never performs
                        // or requests an SCM effect.
                        if let Some(port) = kernel.spool_backup_port() {
                            observe_host_recovery_decision(
                                &host,
                                port.spool.as_ref(),
                                &host_observation,
                            );
                        } else {
                            tracing::debug!(
                                event = "watchdog.recovery_decision_skipped",
                                observation = "unobserved",
                                reason_code = "NO_OWNER_SPOOL",
                                "injected kernel port owns no spool; the recovery decision needs the owner-held watchdog.redb"
                            );
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
                                    let export_lease = admission.lease().clone();
                                    tokio::spawn(async move {
                                        // `KernelWatchdogPort` takes `self:
                                        // Arc<Self>`, so each call consumes the
                                        // handle it is given. Both passes run
                                        // inside this one task, so the intent
                                        // pass takes a fresh handle and the
                                        // export pass keeps this binding. Only
                                        // the `Arc` handle is duplicated; the
                                        // sensor behind it is shared, never
                                        // cloned.
                                        match Arc::clone(&reconcile_kernel)
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
                                        // Drain one bounded owner-spool export
                                        // window through the same authenticated
                                        // Kernel front door in the same one-in-
                                        // flight pass. A refusal here is honest,
                                        // not fatal: a window the Governor has
                                        // not canonically admitted carries a
                                        // non-terminal disposition, so the cursor
                                        // stays put, nothing compacts, and the
                                        // exact same window replays on the next
                                        // live tick.
                                        match reconcile_kernel.export_spool(export_lease).await {
                                            Ok(acknowledged) => tracing::info!(
                                                event = "watchdog.spool_export_advanced",
                                                acknowledged,
                                                canonical_decision = "pending_governor_admission",
                                                "one bounded Watchdog spool export window was acknowledged and compacted"
                                            ),
                                            Err(error) => {
                                                let reason_code =
                                                    crate::diagnostics::spool_error_observation(
                                                        &error,
                                                    );
                                                tracing::debug!(
                                                    event = "watchdog.spool_export_not_acknowledged",
                                                    reason_code,
                                                    "the bounded Watchdog spool export window was not acknowledged; the exact window stays replayable"
                                                );
                                            }
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

/// Owner-contour challenge-attempt producer seam (#1757 steps 1-3, STITCH).
///
/// The competent attempt is produced by the Host control-owner answerer, which
/// has no production caller on this contour yet, so there is nothing to poll,
/// wait on, or correlate here. Returns `None` until that producer lands; the
/// pass then classifies explicit inadequate coverage rather than a fabricated
/// timeout or a forged answer.
fn produce_challenge_attempt() -> Option<ChallengeAttemptOutcome> {
    None
}

/// Installer-owned recovery-policy loader seam (#1757 step 3, STITCH).
///
/// The installation-approved policy — service/installation identity,
/// admissible epoch lineage, permitted recipe, failure threshold, budget
/// window, cooldown, concurrent-attempt exclusion, and audit-failure
/// disposition — is installer-owned service configuration. It is never
/// invented from a constant and never reset, so without the installer lane's
/// loader this pass journals nothing and refuses effects.
fn load_installed_recovery_policy() -> Option<ApprovedRecoveryPolicy> {
    None
}

/// Fenced-target binding seam (#1757 step 4, STITCH).
///
/// Binding needs the approved registration, the expected generation, and the
/// Host-issued owner epoch beside the challenged identity digest. The
/// generation and Host-issued epoch readbacks have no production reader on
/// this contour yet (Host composition lane), so no target is bound here.
/// Returns `None` until those readbacks land; the pass then journals nothing
/// and refuses effects rather than acting on a substituted target.
fn bind_recovery_target(
    _policy: &ApprovedRecoveryPolicy,
    _challenged: &HostObservation,
) -> Option<RecoveryTarget> {
    None
}

/// Fresh boundary-evidence seam (#1757 step 4).
///
/// The fence revalidates approved registration, runtime identity, and expected
/// generation against a readback taken at the boundary itself, never against the
/// challenge-time observation, and it compares each observed value by content
/// with the values the operation recorded (`host_recovery::revalidate_boundary`).
///
/// The approved-registration and runtime-identity legs ARE plumbed here. Both
/// come from ONE fresh read-only SCM query issued by the live observation
/// source this composition was given, not from anything the caller claimed and
/// not from the challenge-time observation: `HostObservationSource::
/// observe_approved_registration` delegates to
/// `HostIdentityMonitor::observe_approved_registration`, which re-queries
/// `host_identity_observation::read_host_registration_runtime` against the
/// installer approval the source retains. Only a `Matching` readback yields a
/// handle, and that handle is the approval's own recorded SCM configuration
/// digest, so a readback over a substituted registration yields nothing at all
/// rather than the approved value.
///
/// The expected-generation leg still has NO owner on this contour, so
/// `generation` stays `None`: nothing here attributes a live Host process to an
/// approved generation. `HostIdentityMonitor`'s `sensor_binding` is the
/// installer-selected generation the Watchdog itself holds, so feeding it back
/// here would compare the Watchdog's own copy with itself; the Host composition
/// lane must expose a real readback (`CompleteKernelControl` already records
/// `kernel_generation`). That absence is not silently defaulted: it is what
/// `revalidate_boundary` refuses as `BoundaryRefusal::GenerationUnavailable`,
/// and the same refusal now names the registration leg it did reach.
fn read_boundary_evidence(host: &dyn HostObservationSource) -> BoundaryEvidence {
    let readback = host.observe_approved_registration();
    let identity = readback
        .as_ref()
        .and_then(ApprovedRegistrationReadback::identity)
        .and_then(|identity| match identity_digest(identity) {
            Ok(digest) => Some(digest),
            Err(error) => {
                tracing::debug!(
                    event = "watchdog.recovery_decision_identity_digest_unavailable",
                    observation = "refused",
                    reason = %error,
                    "observed process identity has no coordination digest; the boundary refuses the identity leg"
                );
                None
            }
        });
    BoundaryEvidence {
        observed_registration: readback
            .as_ref()
            .map(|readback| readback.registration().clone()),
        identity_digest: identity,
        generation: None,
    }
}

/// Audit-correlation and sibling-scope seam (#1757 steps 5-6, STITCH).
///
/// Correlation needs the stable operation identity for this attempt, and the
/// scope needs one disposition per supervised sibling branch from the
/// installed recipe. Both arrive with the installer and owner-contour
/// bindings above; inventing either would fabricate provenance. Returns `None`
/// until they land; without them no audit record is opened and no operation
/// is begun.
fn correlate_recovery_attempt(
    _policy: &ApprovedRecoveryPolicy,
    _target: &RecoveryTarget,
) -> Option<(AuditCorrelation, RecoveryScope)> {
    None
}

/// I8.3 (#1757 W10, #1754): one journal-before-effects recovery decision pass.
///
/// Runs once per tick while the observed Host target is live. The per-pass
/// chain is `bounded_responsiveness` to `recovery_eligibility` to
/// `fence_recovery` / `begin_recovery_operation`, all against the owner-held
/// `watchdog.redb` the composition already holds through its own spool port:
/// no second database handle is opened and no Host journal is touched.
///
/// Decision only: a fenced intent is journaled, never executed. This pass
/// performs no SCM effect, requests none, and calls no step that does — the
/// stop/start-separated execution and its effect-time boundary readbacks
/// belong to the Host composition lane. Every input without a production
/// reader on this contour is an explicit named seam above (STITCH): no
/// policy, no target, and no challenge attempt is invented, so a pass that
/// cannot be fully bound journals nothing but the attempt and refuses effects.
/// The boundary readback is NOT such an input any more: it issues its own live
/// query and carries an absent leg as an explicit refusal.
///
/// I8.3 also requires two of the spool's record categories, and both are written
/// here so they are produced by the live pass rather than by a fixture: the
/// attempt this pass actually made is journalled through the owner spool right
/// after the bounded wait, before any policy seam can stop the pass, and the
/// pre-authorized containment request is journalled once the boundary fence
/// admitted it. Neither record performs an effect, and neither claims a
/// canonical Problem, Incident, or completion.
///
/// All journal touches here are bounded local transactions. Nothing waits on
/// the hung Host: the competing-attempt exclusion is the durable single-key
/// operation row, not a lock anyone can hold across an attempt.
#[allow(
    clippy::too_many_lines,
    reason = "the journal-before-effects decision keeps classification, durable accounting, fencing, and intent journaling in one reviewable per-pass contour"
)]
fn observe_host_recovery_decision(
    host: &Arc<dyn HostObservationSource>,
    spool: &WatchdogSpool,
    before: &HostObservation,
) {
    let database = &spool.database;
    let now_ms = current_unix_ms().unwrap_or(0);
    // No competent attempt can be claimed yet (see the producer seam): stay
    // an explicit uncertainty, never a fabricated timeout.
    let attempt = if let Some(attempt) = produce_challenge_attempt() {
        attempt
    } else {
        tracing::debug!(
            event = "watchdog.recovery_decision_attempt_unproduced",
            observation = "unresolved",
            seam = "STITCH",
            "no production challenge-attempt producer on the Host owner contour; refusing to invent one"
        );
        ChallengeAttemptOutcome::Uncertain(ChallengeUncertainty::InadequateCoverage)
    };
    // The contour's own admitted bound for one observation interval. The
    // producer-owned wait itself remains STITCH; this only bounds the recheck
    // below, never a verdict.
    let Some(wait) = BoundedChallengeWait::new(MAX_CHALLENGE_WAIT_SECS) else {
        return;
    };
    // W7 interval shape: the after-interval read is always fresh. Reusing
    // `before` as `after` would confirm a verdict without rechecking, so a
    // substituted target could never be refused here.
    let after = host.observe();
    let verdict = bounded_responsiveness(before, &wait, &attempt, &after);
    // I8.3: "Every attempt is recorded in the Watchdog spool ... for later
    // reconciliation." This is the attempt this pass really made over two real
    // observations, so it is journalled before any seam below can stop the pass.
    // It states what was and was not established — the named uncertainty is
    // carried as itself, never resolved into a fabricated timeout or a forged
    // answer — and it claims nothing about health, eligibility, or canonical
    // Problem/Incident state.
    let before_identity = attempt_evidence::target_identity_digest(before);
    let after_identity = attempt_evidence::target_identity_digest(&after);
    let attempt_evidence_refs = [
        attempt_evidence::observation_evidence_ref(
            attempt_evidence::attempt_service().as_str(),
            host_observation_state_code(before.state),
            before_identity.as_deref(),
            wait.timeout_secs(),
        ),
        attempt_evidence::observation_evidence_ref(
            attempt_evidence::attempt_service().as_str(),
            host_observation_state_code(after.state),
            after_identity.as_deref(),
            wait.timeout_secs(),
        ),
    ];
    let attempt_record = match attempt_evidence::HostAttemptRecord::new(
        attempt_evidence::attempt_service(),
        attempt,
        verdict,
        wait.timeout_secs(),
        after_identity.or(before_identity),
        attempt_evidence_refs.to_vec(),
    ) {
        Ok(record) => record,
        Err(error) => {
            tracing::debug!(
                event = "watchdog.recovery_decision_attempt_not_canonical",
                observation = "unobserved",
                reason = %error,
                "the bounded attempt is not a canonical restricted record; journaling nothing and refusing effects"
            );
            return;
        }
    };
    let attempt_verdict = attempt_record.verdict_code().to_owned();
    match spool.journal_host_attempt(now_ms.max(1), &attempt_record) {
        Ok(entry) => tracing::debug!(
            event = "watchdog.recovery_decision_attempt_journaled",
            observation = "committed",
            sequence = entry.sequence,
            verdict = attempt_verdict,
            "bounded Host responsiveness attempt recorded in the owner spool; no effect performed"
        ),
        Err(error) => tracing::debug!(
            event = "watchdog.recovery_decision_attempt_unavailable",
            observation = "attempted",
            reason = %error,
            "the bounded attempt could not be recorded in the owner spool; refusing effects"
        ),
    }
    // Without the installer loader there is no policy to decide under: trace
    // the seam and stop before any journal write.
    let Some(policy) = load_installed_recovery_policy() else {
        tracing::debug!(
            event = "watchdog.recovery_decision_policy_unavailable",
            observation = "refused",
            seam = "STITCH",
            verdict = ?verdict,
            "no installation-approved recovery policy on this contour; journaling no request and refusing effects"
        );
        return;
    };
    // Durable failure and attempt accounting from the owner's own journal, so
    // exhaustion survives a Watchdog restart and is never invented. One more
    // consecutive failure is counted exactly when this pass classified one.
    let budget = match verdict {
        HostResponsiveness::AliveUnresponsive => {
            record_recovery_budget(database, true, None, &policy)
        }
        _ => read_recovery_budget(database),
    };
    let budget = match budget {
        Ok(budget) => budget,
        Err(error) => {
            tracing::debug!(
                event = "watchdog.recovery_decision_journal_unavailable",
                observation = "refused",
                reason = %error,
                "durable recovery budget is unreadable; refusing effects"
            );
            return;
        }
    };
    let decision = verdict.recovery_eligibility(&policy, budget.used_attempts(now_ms, &policy));
    if !decision.admits_effect() {
        tracing::debug!(
            event = "watchdog.recovery_decision_not_admitted",
            observation = "refused",
            verdict = ?verdict,
            decision = ?decision,
            "budget decision admits no SCM effect"
        );
        return;
    }
    let Some(target) = bind_recovery_target(&policy, &after) else {
        tracing::debug!(
            event = "watchdog.recovery_decision_target_unbound",
            observation = "refused",
            seam = "STITCH",
            "fenced target cannot be bound without the generation and Host-issued epoch readbacks; refusing effects"
        );
        return;
    };
    let evidence = read_boundary_evidence(host.as_ref());
    let Some((correlation, scope)) = correlate_recovery_attempt(&policy, &target) else {
        tracing::debug!(
            event = "watchdog.recovery_decision_uncorrelated",
            observation = "refused",
            seam = "STITCH",
            "no stable operation identity or installed-recipe scope on this contour; opening nothing"
        );
        return;
    };
    let audit = DualAuditRecord::new(correlation, AuditEventKind::ChallengeTimeout);
    let open_operation = match read_recovery_operation(database) {
        Ok(open) => open,
        Err(error) => {
            tracing::debug!(
                event = "watchdog.recovery_decision_operation_unreadable",
                observation = "refused",
                reason = %error,
                "open recovery operation is unreadable; refusing effects"
            );
            return;
        }
    };
    let fence = RecoveryFence {
        policy: &policy,
        target: &target,
        evidence,
        guarantee: EXISTING_SCM_ADAPTER_GUARANTEE,
        open_operation: open_operation.as_ref(),
        budget: &budget,
        audit: &audit,
        now_ms,
    };
    let intent = match fence_recovery(&fence) {
        Ok(intent) => intent,
        Err(refusal) => {
            let denied =
                DualAuditRecord::new(audit.correlation.clone(), AuditEventKind::DecisionDenied);
            match record_recovery_audit(database, &denied) {
                Ok(persisted) => tracing::debug!(
                    event = "watchdog.recovery_decision_fence_refused",
                    observation = "refused",
                    refusal = ?refusal,
                    operation = persisted.correlation.operation_id.as_str(),
                    "boundary refused the recovery attempt; the refusal is journaled and no effect follows"
                ),
                Err(error) => tracing::debug!(
                    event = "watchdog.recovery_decision_audit_unavailable",
                    observation = "refused",
                    refusal = ?refusal,
                    reason = %error,
                    "boundary refused the recovery attempt and the refusal itself could not be journaled"
                ),
            }
            return;
        }
    };
    let operation =
        match RecoveryOperation::begin(audit.correlation.clone(), target, verdict, decision, scope)
        {
            Ok(operation) => operation,
            Err(error) => {
                tracing::debug!(
                    event = "watchdog.recovery_decision_operation_invalid",
                    observation = "refused",
                    reason = %error,
                    "recovery operation is not canonical; opening nothing"
                );
                return;
            }
        };
    let stored = match begin_recovery_operation(database, None, &operation) {
        Ok(stored) => stored,
        Err(error) => {
            tracing::debug!(
                event = "watchdog.recovery_decision_begin_refused",
                observation = "refused",
                reason = %error,
                "recovery operation was not opened; a competing open attempt excludes this one"
            );
            return;
        }
    };
    // Journal-before-effects: the challenge-timeout audit and one consumed
    // attempt land in the owner's journal before any SCM effect could be
    // requested. This pass still requests none: execution belongs to the Host
    // composition lane.
    match record_recovery_audit(database, &audit) {
        Ok(persisted) => tracing::debug!(
            event = "watchdog.recovery_decision_committed",
            observation = "committed",
            operation = persisted.correlation.operation_id.as_str(),
            revision = stored.revision(),
            intent_target = intent.target.identity_digest.as_str(),
            "fenced recovery intent journaled before effects; no SCM effect performed or requested"
        ),
        Err(error) => tracing::debug!(
            event = "watchdog.recovery_decision_audit_unavailable",
            observation = "attempted",
            reason = %error,
            "fenced recovery intent is open but its challenge audit could not be journaled"
        ),
    }
    if let Err(error) = record_recovery_budget(database, false, Some(now_ms), &policy) {
        tracing::debug!(
            event = "watchdog.recovery_decision_budget_unadvanced",
            observation = "attempted",
            reason = %error,
            "fenced recovery intent is open but its attempt could not be consumed from the budget"
        );
    }
    // I8.3: "emit a signed pre-authorized containment request to the owning
    // Host/Kernel boundary". The fence above admitted this request, so the
    // retained copy below names a request this Watchdog was authorized to emit.
    // It records the request only: the owning boundary revalidates target,
    // evidence, recipe class, current epoch, and allowed effect before any
    // containment runs, and this pass performs none.
    let request_evidence_refs = [
        audit.correlation.operation_id.as_str().to_owned(),
        intent.target.identity_digest.as_str().to_owned(),
        intent.target.recipe_digest.as_str().to_owned(),
    ];
    match attempt_evidence::ContainmentRequestRecord::new(
        attempt_evidence::attempt_service(),
        &intent,
        request_evidence_refs.to_vec(),
    ) {
        Ok(record) => match spool.journal_containment_request(now_ms.max(1), &record) {
            Ok(entry) => tracing::debug!(
                event = "watchdog.recovery_decision_request_journaled",
                observation = "committed",
                sequence = entry.sequence,
                operation = intent.operation_id.as_str(),
                "pre-authorized containment request recorded in the owner spool; the owning boundary decides whether to run it"
            ),
            Err(error) => tracing::debug!(
                event = "watchdog.recovery_decision_request_unavailable",
                observation = "attempted",
                reason = %error,
                "the fenced request is open but its retained copy could not be journaled"
            ),
        },
        Err(error) => tracing::debug!(
            event = "watchdog.recovery_decision_request_not_canonical",
            observation = "unobserved",
            reason = %error,
            "the admitted request is not a canonical restricted record; no effect was requested"
        ),
    }
}

/// Closed wire code of one observed Host target state.
///
/// The attempt record's evidence references are taken over these codes, so the
/// durable record and the trace can never state two different states for the
/// same observation.
fn host_observation_state_code(state: HostObservationState) -> &'static str {
    match state {
        HostObservationState::Running => "RUNNING",
        HostObservationState::AbsentOrStopped => "ABSENT_OR_STOPPED",
        HostObservationState::PidReused => "PID_REUSED",
        HostObservationState::ImageSubstituted => "IMAGE_SUBSTITUTED",
        HostObservationState::IdentityChanged => "IDENTITY_CHANGED",
        HostObservationState::Unknown => "UNKNOWN",
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

    /// Retains the newest published shared I8.2 coverage manifest (#1755 W6).
    ///
    /// Thin delegation to
    /// [`WatchdogSpool::retain_shared_coverage_manifest`](crate::watchdog_spool::WatchdogSpool::retain_shared_coverage_manifest):
    /// the same owner spool every heartbeat and gap record is appended
    /// through, so the wrapper-built payload reaches durable owner evidence on
    /// the supervision tick instead of only a debug-log summary. Carries no
    /// backup, restore, or export semantics: backup captures and export
    /// batches never read the manifest row.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the manifest does not validate or the row
    /// cannot be committed.
    pub(crate) fn retain_shared_coverage_manifest(
        &self,
        manifest: &eliot_evaluation_contracts::ObservationCoverageManifest,
    ) -> Result<(), SpoolError> {
        self.spool.retain_shared_coverage_manifest(manifest)
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

#[cfg(test)]
mod boundary_evidence_tests {
    use eliot_platform::PlatformHandle;
    use eliot_platform_windows::ProcessIdentity;

    use super::*;
    use crate::host_recovery::{BoundaryRefusal, revalidate_boundary};

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

    /// A read-only source that observed the installer-approved registration and
    /// the runtime identity ONE readback carried.
    ///
    /// This fixture stands in for the live SCM query
    /// `host_identity_observation::approved_registration_readback` performs. It
    /// supplies observed VALUES, never a verdict about them, so the boundary
    /// comparison below exercises exactly the comparison production performs.
    struct ObservedRegistrationHost {
        readback: Option<ApprovedRegistrationReadback>,
    }

    impl HostObservationSource for ObservedRegistrationHost {
        fn observe(&self) -> HostObservation {
            HostObservation {
                state: HostObservationState::Running,
                identity: None,
            }
        }

        fn observe_approved_registration(&self) -> Option<ApprovedRegistrationReadback> {
            self.readback.clone()
        }
    }

    fn handle(seed: char) -> Fallible<PlatformHandle> {
        Ok(PlatformHandle::new(seed.to_string().repeat(32))?)
    }

    fn process() -> ProcessIdentity {
        ProcessIdentity {
            process_id: 4_200,
            start_time_100ns: 1_000_000,
            image_path: r"C:\Program Files\Eliot\eliot-host.exe".to_owned(),
        }
    }

    /// Positive: the composition supplies the owner-issued approved registration
    /// the live source reported, and the boundary's own content comparison
    /// agrees with what the operation recorded against it.
    ///
    /// FAILS WITHOUT THIS CHANGE: the seam returned `None`, so no boundary
    /// evidence existed and neither the approved registration nor the runtime
    /// identity could reach `revalidate_boundary` at all. The refusal that
    /// remains is `GenerationUnavailable` — a DIFFERENT leg with no owner on this
    /// contour — which is what proves the two compared legs actually agreed
    /// rather than being skipped on the way to the first refusal.
    #[test]
    fn boundary_evidence_carries_the_observed_registration_and_identity() -> TestResult {
        let identity = process();
        let observed_registration = handle('a')?;
        let source = ObservedRegistrationHost {
            readback: Some(ApprovedRegistrationReadback::new(
                observed_registration.clone(),
                Some(identity.clone()),
            )),
        };

        let evidence = read_boundary_evidence(&source);
        assert_eq!(
            evidence.observed_registration,
            Some(observed_registration.clone())
        );
        assert_eq!(evidence.identity_digest, Some(identity_digest(&identity)?));
        assert_eq!(evidence.generation, None);

        let target = RecoveryTarget::bind(
            observed_registration,
            handle('b')?,
            handle('c')?,
            handle('d')?,
            &identity,
        )?;
        assert_eq!(
            revalidate_boundary(&target, &evidence),
            Err(BoundaryRefusal::GenerationUnavailable)
        );
        Ok(())
    }

    /// Refusal: a source that retained no installer approval compares no
    /// approved registration, so the evidence carries none and the boundary
    /// refuses the registration leg BY NAME instead of reading the absence as
    /// agreement.
    ///
    /// FAILS WITHOUT THIS CHANGE: the seam returned `None` and the pass stopped
    /// before `fence_recovery`, so `BoundaryRefusal::RegistrationUnavailable` had
    /// no production path that could reach it. The `None` readback here is the
    /// same state a live `Mismatched`/`Absent`/`Unknown` readback produces, since
    /// `approved_registration_readback` yields no evidence for those.
    #[test]
    fn boundary_evidence_refuses_when_no_approved_registration_was_compared() -> TestResult {
        let source = ObservedRegistrationHost { readback: None };
        let evidence = read_boundary_evidence(&source);
        assert_eq!(evidence.observed_registration, None);
        assert_eq!(evidence.identity_digest, None);

        let target = RecoveryTarget::bind(
            handle('a')?,
            handle('b')?,
            handle('c')?,
            handle('d')?,
            &process(),
        )?;
        assert_eq!(
            revalidate_boundary(&target, &evidence),
            Err(BoundaryRefusal::RegistrationUnavailable)
        );
        Ok(())
    }
}

#[cfg(test)]
mod shared_manifest_tick_tests {
    use super::*;

    use crate::coverage_manifest_projection::{
        CoverageManifestOutcome, publish_interval_coverage_manifest,
    };
    use crate::observation_coverage::{
        IntervalCoveragePublisher, ObservationChannel, channel_capability,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn test_port(name: &str) -> Result<WatchdogBackupPort, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "eliot-watchdog-manifest-port-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let spool = Arc::new(crate::watchdog_spool::WatchdogSpool::open_test(&path)?);
        Ok(WatchdogBackupPort::new(
            Arc::clone(&spool),
            "installation-1755".to_owned(),
            7,
            WatchdogSpoolBackupLimits::default(),
            Arc::new(IntervalCoverageCell::new(1_000)),
        )?)
    }

    /// The owner's own fully observed interval, published through the same
    /// wrapper the tick calls.
    fn published_outcome() -> CoverageManifestOutcome {
        let mut publisher = IntervalCoveragePublisher::new(1_000);
        for channel in ObservationChannel::ALL {
            for class in channel_capability(channel).supported_classes {
                publisher.record(channel, *class);
            }
        }
        let report = publisher.close(2_000);
        publish_interval_coverage_manifest(
            Some("installation-1755"),
            Some(&"a".repeat(64)),
            &report,
        )
    }

    /// A published interval reaches the owner spool through the port: the
    /// payload the tick retains reads back identical (#1755 W6).
    #[test]
    fn published_interval_reaches_owner_spool_through_port() -> TestResult {
        let port = test_port("tick")?;
        let outcome = published_outcome();
        let CoverageManifestOutcome::Published { ref manifest, .. } = outcome else {
            return Err("both owner identities are present, expected a manifest".into());
        };
        assert!(retain_published_shared_manifest(Some(&port), &outcome));
        assert_eq!(
            port.spool.read_shared_coverage_manifest()?,
            Some(manifest.as_ref().clone())
        );
        Ok(())
    }

    /// An omitted interval retains nothing and clears nothing: the reader
    /// sees no manifest rather than a fabricated one.
    #[test]
    fn omitted_interval_retains_nothing() -> TestResult {
        let port = test_port("omitted")?;
        let mut publisher = IntervalCoveragePublisher::new(1_000);
        for channel in ObservationChannel::ALL {
            for class in channel_capability(channel).supported_classes {
                publisher.record(channel, *class);
            }
        }
        let report = publisher.close(2_000);
        let outcome = publish_interval_coverage_manifest(None, None, &report);
        assert!(matches!(outcome, CoverageManifestOutcome::Omitted(_)));
        assert!(!retain_published_shared_manifest(Some(&port), &outcome));
        assert_eq!(port.spool.read_shared_coverage_manifest()?, None);
        Ok(())
    }

    /// Without a bound owner spool nothing is retained and nothing fails:
    /// the miss is for the tick to trace, not a refusal.
    #[test]
    fn missing_port_retains_nothing() {
        let outcome = published_outcome();
        assert!(matches!(outcome, CoverageManifestOutcome::Published { .. }));
        assert!(!retain_published_shared_manifest(None, &outcome));
    }
}
