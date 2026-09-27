//! T2-S08W sensor/port recovery/containment demonstration.
//!
//! Reuses the T2-S08K pattern read-only as the model (reconcile by original
//! identity, Unknown fenced, ORS staged/latest readback): this test drives the
//! existing admitted Watchdog route without inventing a child launcher and
//! without any new public process signature or arbitrary launch authority.
//!
//! Route demonstrated (all existing production paths, no new launcher):
//! `IndependentKernelSensor::supervise` heartbeat plus `report_gap_nonfatal`
//! gaps, composition containment `PidReused`/`ImageSubstituted` mapping to
//! `publish_no_authority`, and `export`/`ack`/`compact` through `export_once`.
//! The trailing manifest/source assertions prove no private launcher is
//! present (zero `eliot_process` refs, no new dep edge).
//!
//! Proof ceiling: this is a sensor/port and composition demonstration driven by
//! fixtures — a fixture-issued supervision lease, a fake Host observation
//! source, a fake admission source, a fake Kernel port, and an in-test export
//! sink. It is NOT a Windows process/SCM demonstration, NOT production
//! ingestion, and NOT Product or release certification. The exported batch and
//! the acknowledgements below are fixture evidence of the acknowledgement
//! contract only; they establish no real backend delivery.

use super::{
    supervision_fixture_binding, supervision_fixture_envelope, supervision_fixture_path,
    supervision_fixture_request, supervision_fixture_verifier,
};
use crate::{
    GapRecoveryReason, HostIdentityMonitor, HostObservation, HostObservationSource,
    HostObservationState, IndependentKernelSensor, KernelWatchdogPort, SpoolError,
    VerifiedWatchdogAdmission, WatchdogAuthorityState, WatchdogComposition, WatchdogConfig,
    WatchdogExportSink, WatchdogSpoolExportLimits, WatchdogSpoolPayload, export_once,
};
use eliot_runtime_contracts::SupervisionLeaseVerifier;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Bounded ceiling for every wait in this demonstration.
///
/// No wait below is a "sleep long enough and hope". Each one is a bounded
/// observation of one expected event from an injected seam, and a timeout
/// fails the test by naming the event that never arrived.
const S08W_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(10);

struct S08wTerminalSink {
    sink_id: String,
    /// The exact acknowledgement this fixture sink returned, retained so the
    /// test can prove the per-entry dispositions it issued were bound 1:1 to
    /// the immutable batch the real export driver handed it.
    last_acknowledged: Arc<Mutex<Option<eliot_watchdog_core::WatchdogSpoolAcknowledgement>>>,
}

/// Sink that cannot form an acknowledgement at all (a sink-side fault).
///
/// This is the "failed sink" class: the export driver must propagate the
/// error, must not advance the cursor, and must not compact anything, so the
/// unacknowledged evidence stays replayable.
struct S08wFailingSink {
    sink_id: String,
}

impl WatchdogExportSink for S08wTerminalSink {
    fn sink_id(&self) -> &str {
        &self.sink_id
    }

    fn submit(
        &self,
        batch: &eliot_watchdog_core::WatchdogSpoolExportBatch,
    ) -> Result<eliot_watchdog_core::WatchdogSpoolAcknowledgement, SpoolError> {
        let dispositions = crate::watchdog_entry_views(batch)
            .into_iter()
            .map(
                |(sequence, kind, record_digest, _payload_digest, _observed_at_ms)| {
                    let disposition = match kind {
                        eliot_watchdog_core::WatchdogSpoolPayloadKind::Heartbeat => {
                            eliot_watchdog_core::WatchdogSpoolSinkDisposition::Applied
                        }
                        eliot_watchdog_core::WatchdogSpoolPayloadKind::Gap
                        | eliot_watchdog_core::WatchdogSpoolPayloadKind::Recovery => {
                            eliot_watchdog_core::WatchdogSpoolSinkDisposition::GapRequiresRecovery
                        }
                    };
                    eliot_watchdog_core::WatchdogSpoolEntryDisposition {
                        sequence,
                        disposition,
                        record_digest,
                    }
                },
            )
            .collect();
        let acknowledgement = eliot_watchdog_core::WatchdogSpoolAcknowledgement {
            schema_version: batch.schema_version,
            batch_id: batch.batch_id.clone(),
            batch_digest: batch.batch_digest.clone(),
            predecessor_sequence: batch.predecessor_cursor.acknowledged_sequence,
            first_sequence: batch.first_sequence,
            last_sequence: batch.last_sequence,
            sink_id: batch.predecessor_cursor.sink_id.clone(),
            watchdog_generation: batch.watchdog_generation,
            watchdog_epoch: batch.watchdog_epoch,
            installation_id: batch.installation_id.clone(),
            dispositions,
        };
        if let Ok(mut guard) = self.last_acknowledged.lock() {
            *guard = Some(acknowledgement.clone());
        }
        Ok(acknowledgement)
    }
}

impl WatchdogExportSink for S08wFailingSink {
    fn sink_id(&self) -> &str {
        &self.sink_id
    }

    fn submit(
        &self,
        _batch: &eliot_watchdog_core::WatchdogSpoolExportBatch,
    ) -> Result<eliot_watchdog_core::WatchdogSpoolAcknowledgement, SpoolError> {
        Err(SpoolError::Corrupt(
            "s08w fixture sink cannot form an acknowledgement".to_owned(),
        ))
    }
}

/// Sink that answers a foreign batch identity it never received.
///
/// Every scalar echo is taken from a batch the fixture did not submit, so the
/// acknowledgement is refused by the owner-side identity gate. This is the
/// "foreign acknowledgement" class: a valid-looking acknowledgement for
/// somebody else's evidence must not advance this spool's cursor.
struct S08wForeignAckSink {
    sink_id: String,
}

impl WatchdogExportSink for S08wForeignAckSink {
    fn sink_id(&self) -> &str {
        &self.sink_id
    }

    fn submit(
        &self,
        batch: &eliot_watchdog_core::WatchdogSpoolExportBatch,
    ) -> Result<eliot_watchdog_core::WatchdogSpoolAcknowledgement, SpoolError> {
        let dispositions = crate::watchdog_entry_views(batch)
            .into_iter()
            .map(
                |(sequence, _kind, record_digest, _payload_digest, _observed_at_ms)| {
                    eliot_watchdog_core::WatchdogSpoolEntryDisposition {
                        sequence,
                        disposition: eliot_watchdog_core::WatchdogSpoolSinkDisposition::Applied,
                        record_digest,
                    }
                },
            )
            .collect();
        Ok(eliot_watchdog_core::WatchdogSpoolAcknowledgement {
            schema_version: batch.schema_version,
            // A foreign identity: the digests and ranges below answer records
            // this spool never exported, while the per-entry lines still cover
            // the submitted batch. Identity validation runs before coverage, so
            // the batch-identity break is the exact refusal reason.
            batch_id: "foreign-batch-s08w".to_owned(),
            batch_digest: "foreign-digest-s08w".to_owned(),
            predecessor_sequence: batch.predecessor_cursor.acknowledged_sequence,
            first_sequence: batch.first_sequence,
            last_sequence: batch.last_sequence,
            // A sink identity this export contour is not bound to.
            sink_id: "sink-foreign-s08w".to_owned(),
            watchdog_generation: batch.watchdog_generation,
            watchdog_epoch: batch.watchdog_epoch,
            installation_id: batch.installation_id.clone(),
            dispositions,
        })
    }
}

struct S08wPidReusedHost;

impl HostObservationSource for S08wPidReusedHost {
    fn observe(&self) -> HostObservation {
        HostObservation {
            state: HostObservationState::PidReused,
            identity: None,
        }
    }
}

/// The second identity-loss class this demonstration owes: a same-PID,
/// same-start-time process running a substituted image.
///
/// Composed separately from [`S08wPidReusedHost`] so both typed reasons
/// (`HostPidReused` and `HostImageSubstituted`) are observed crossing the real
/// composition boundary, not merely classified by the monitor in isolation.
struct S08wImageSubstitutedHost;

impl HostObservationSource for S08wImageSubstitutedHost {
    fn observe(&self) -> HostObservation {
        HostObservation {
            state: HostObservationState::ImageSubstituted,
            identity: None,
        }
    }
}

struct S08wInvalidAdmission;

impl crate::WatchdogAdmissionSource for S08wInvalidAdmission {
    fn reload(&self) -> Result<VerifiedWatchdogAdmission, SpoolError> {
        Err(SpoolError::InvalidLease(
            "s08w containment proof has no admission".to_owned(),
        ))
    }
}

struct S08wRecordingPort {
    gaps: Arc<Mutex<Vec<GapRecoveryReason>>>,
    /// Notification seam: the composition reports a gap through the existing
    /// injected port, and the test waits on that notification instead of
    /// sleeping for a fixed interval and hoping the tick had already run.
    reported: Arc<tokio::sync::Notify>,
}

impl S08wRecordingPort {
    fn new() -> Self {
        Self {
            gaps: Arc::new(Mutex::new(Vec::new())),
            reported: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn gaps(&self) -> Arc<Mutex<Vec<GapRecoveryReason>>> {
        Arc::clone(&self.gaps)
    }
}

impl KernelWatchdogPort for S08wRecordingPort {
    fn supervise<'a>(
        &'a self,
        _lease: &'a eliot_runtime_contracts::VerifiedSupervisionLease,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::KernelWatchdogError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn report_gap<'a>(
        &'a self,
        disposition: crate::GapRecoveryDisposition,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::KernelWatchdogError>> + Send + 'a>> {
        let gaps = Arc::clone(&self.gaps);
        let reported = Arc::clone(&self.reported);
        let reason = disposition.reason;
        Box::pin(async move {
            match gaps.lock() {
                Ok(mut guard) => {
                    guard.push(reason);
                    // `notify_waiters` deliberately does not store a permit, so
                    // the test can only ever be woken by a gap reported after it
                    // started waiting. A missed wake fails the wait below rather
                    // than passing on a stale signal.
                    reported.notify_waiters();
                    Ok(())
                }
                Err(_) => Err(crate::KernelWatchdogError::Failed),
            }
        })
    }
}

/// Awaits the next gap notification from the injected port, bounded.
///
/// Fails with the absence of the event when the bound elapses, so a
/// composition that never reports the expected containment gap is an
/// observable failure rather than a timing coincidence.
async fn await_reported_gap(reported: &Arc<tokio::sync::Notify>, expected: GapRecoveryReason) {
    let observed = tokio::time::timeout(S08W_OBSERVATION_TIMEOUT, reported.notified());
    assert!(
        observed.await.is_ok(),
        "s08w composition never reported {expected:?} within {S08W_OBSERVATION_TIMEOUT:?}; \
         the containment gap did not cross the composition boundary"
    );
}

/// Observes removal of the exact test-owned temporary paths this demonstration
/// creates, on success and on failure alike.
///
/// The paths are named by this test and only this test (per-process id plus a
/// shared fixture counter), so removal is bounded to what the test owns and
/// never targets an arbitrary location. A failed removal is reported with the
/// exact path instead of being discarded, and residue is retained for
/// inspection rather than force-removed. This is an explicit, reported action:
/// cleanup is never left to `Drop`, and the test's primary assertion failure is
/// preserved rather than replaced by a cleanup failure.
struct S08wOwnedTempState {
    paths: Vec<std::path::PathBuf>,
    removed: usize,
}

impl S08wOwnedTempState {
    fn new(paths: Vec<std::path::PathBuf>) -> Self {
        Self { paths, removed: 0 }
    }

    /// Removes every owned path, reporting each failure with its exact path.
    ///
    /// Must run after the sensor and ORS store are closed, because both keep a
    /// live file handle on their own path; removal before that would fail for a
    /// reason that has nothing to do with the demonstration.
    fn remove(&mut self) {
        for path in &self.paths {
            let outcome = if path.is_dir() {
                std::fs::remove_dir_all(path)
            } else {
                std::fs::remove_file(path)
            };
            match outcome {
                Ok(()) => {
                    self.removed += 1;
                    assert!(
                        !path.exists(),
                        "s08w owned temp path still present after removal: {}",
                        path.display()
                    );
                }
                Err(error) => panic!(
                    "s08w owned temp cleanup failed for {}: {error}; \
                     residue is retained for inspection and the primary failure above is preserved",
                    path.display()
                ),
            }
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "T2-S08W keeps one focused heartbeat+gaps+containment+export proof in a single test"
)]
#[tokio::test]
async fn s08w_sensor_port_recovery_containment_export() {
    // Sensor/port heartbeat: one real verified lease through the existing ORS
    // fixture path, matching the sensor epoch so `record_heartbeat` admits it.
    let serial = super::FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
    let state_dir = std::env::temp_dir().join(format!(
        "eliot-watchdog-s08w-{}-{serial}",
        std::process::id()
    ));
    std::fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("s08w state dir: {error}"));
    let sensor =
        IndependentKernelSensor::open_for_export_driver_test(&state_dir, "s08w-installation", 7, 1)
            .unwrap_or_else(|error| panic!("s08w sensor: {error}"));
    let ors_path = supervision_fixture_path();
    let store = eliot_ors::RedbRecoveryStore::open(&ors_path)
        .unwrap_or_else(|error| panic!("s08w ors store: {error}"));
    let now_ms = crate::current_unix_ms().unwrap_or_else(|error| panic!("s08w clock: {error}"));
    let binding = supervision_fixture_binding(now_ms.saturating_sub(200))
        .unwrap_or_else(|error| panic!("s08w lease binding: {error}"));
    let request = supervision_fixture_request(
        "ticket-s08w-1",
        "operation-s08w-1",
        "lease-s08w-1",
        None,
        eliot_ors::SupervisionLeaseOperation::Commit,
        binding,
    )
    .unwrap_or_else(|error| panic!("s08w lease request: {error}"));
    let stage = store
        .prepare_supervision_lease(request)
        .unwrap_or_else(|error| panic!("s08w lease prepare: {error}"));
    let envelope = supervision_fixture_envelope(&stage)
        .unwrap_or_else(|error| panic!("s08w lease envelope: {error}"));
    let (anchor, context) = supervision_fixture_verifier(&envelope)
        .unwrap_or_else(|error| panic!("s08w lease verifier: {error}"));
    let verified = anchor
        .verify(&envelope, &context)
        .unwrap_or_else(|error| panic!("s08w lease verify: {error}"));
    assert_eq!(verified.lease().watchdog_epoch.value(), 1);
    KernelWatchdogPort::supervise(&sensor, &verified)
        .await
        .unwrap_or_else(|error| panic!("s08w heartbeat: {error}"));

    // Composition containment inputs: PID reuse and image substitution are
    // classified by the existing monitor and map to typed gap reasons. The
    // composition loop turns each into `publish_no_authority` plus a nonfatal
    // gap; here the sensor port records the same gaps durably.
    let mut monitor = HostIdentityMonitor::new(None);
    let base = eliot_platform_windows::ProcessIdentity {
        process_id: 4242,
        start_time_100ns: 1000,
        image_path: r"C:\ProgramData\Eliot\eliot-host.exe".to_owned(),
    };
    assert_eq!(
        monitor.observe_process_identity(base.clone()).state,
        HostObservationState::Running
    );
    let pid_reused = eliot_platform_windows::ProcessIdentity {
        start_time_100ns: 2000,
        ..base.clone()
    };
    let pid_observation = monitor.observe_process_identity(pid_reused);
    assert_eq!(pid_observation.state, HostObservationState::PidReused);
    assert_eq!(
        pid_observation.gap_reason(),
        Some(GapRecoveryReason::HostPidReused)
    );
    let image_substituted = eliot_platform_windows::ProcessIdentity {
        image_path: r"C:\Temp\evil.exe".to_owned(),
        ..base.clone()
    };
    let image_observation = monitor.observe_process_identity(image_substituted);
    assert_eq!(
        image_observation.state,
        HostObservationState::ImageSubstituted
    );
    assert_eq!(
        image_observation.gap_reason(),
        Some(GapRecoveryReason::HostImageSubstituted)
    );
    crate::report_gap_nonfatal(&sensor, GapRecoveryReason::HostPidReused).await;
    crate::report_gap_nonfatal(&sensor, GapRecoveryReason::HostImageSubstituted).await;
    let retained = sensor
        .retained_spool_entries_for_export_driver_test()
        .unwrap_or_else(|error| panic!("s08w retained: {error}"));
    assert_eq!(retained.len(), 3, "heartbeat plus two containment gaps");
    assert!(
        matches!(retained[0].payload, WatchdogSpoolPayload::Heartbeat { .. }),
        "first record must be the admitted heartbeat"
    );
    assert!(
        matches!(
            retained[1].payload,
            WatchdogSpoolPayload::Gap {
                reason: GapRecoveryReason::HostPidReused,
                coverage_claimed: false,
                ..
            }
        ),
        "second record must be the PID-reuse containment gap"
    );
    assert!(
        matches!(
            retained[2].payload,
            WatchdogSpoolPayload::Gap {
                reason: GapRecoveryReason::HostImageSubstituted,
                coverage_claimed: false,
                ..
            }
        ),
        "third record must be the image-substitution containment gap"
    );

    // Composition containment, class one: a `PidReused` host observation with
    // no admission stays `RunningNoAuthority` (the public `publish_no_authority`
    // projection) while the gap port observes the typed reason nonfatally.
    // The wait is a bounded observation of the injected port's notification,
    // never a fixed sleep: absence of the event is the failure.
    let pid_port = S08wRecordingPort::new();
    let pid_gaps = pid_port.gaps();
    let pid_reported = Arc::clone(&pid_port.reported);
    let pid_shutdown = Arc::new(AtomicBool::new(false));
    let config = WatchdogConfig {
        tick_interval: Duration::from_millis(5),
        ..WatchdogConfig::default()
    };
    let pid_composition = WatchdogComposition::start_with_shutdown_and_host(
        config.clone(),
        Arc::new(S08wInvalidAdmission),
        Arc::new(pid_port),
        Arc::new(S08wPidReusedHost),
        Arc::clone(&pid_shutdown),
    )
    .unwrap_or_else(|error| panic!("s08w composition (pid reuse): {error}"));
    let pid_readiness = pid_composition.readiness();
    assert_eq!(
        pid_readiness.authority_state,
        WatchdogAuthorityState::RunningNoAuthority
    );
    assert!(!pid_readiness.coverage_claimed);
    await_reported_gap(&pid_reported, GapRecoveryReason::HostPidReused).await;
    let pid_observed: Vec<GapRecoveryReason> = pid_gaps
        .lock()
        .unwrap_or_else(|error| panic!("s08w pid gaps lock: {error}"))
        .clone();
    assert!(
        pid_observed.contains(&GapRecoveryReason::HostPidReused),
        "PidReused containment must report a nonfatal gap, got {pid_observed:?}"
    );
    assert_eq!(
        pid_composition.readiness().authority_state,
        WatchdogAuthorityState::RunningNoAuthority
    );
    assert!(!pid_composition.readiness().coverage_claimed);
    // Shut the composition down and join it before any later resource
    // inspection, so nothing this test inspects is still held by a live task.
    pid_shutdown.store(true, Ordering::Release);
    pid_composition
        .run_until_shutdown()
        .await
        .unwrap_or_else(|error| panic!("s08w shutdown (pid reuse): {error:?}"));

    // Composition containment, class two: the substituted-image identity loss
    // crossing the same real composition boundary. Separate monitor
    // assertions above are not composition proof, so this observes the typed
    // `HostImageSubstituted` reason reaching the injected port through the
    // production loop, and re-proves the no-authority/no-coverage state.
    let image_port = S08wRecordingPort::new();
    let image_gaps = image_port.gaps();
    let image_reported = Arc::clone(&image_port.reported);
    let image_shutdown = Arc::new(AtomicBool::new(false));
    let image_composition = WatchdogComposition::start_with_shutdown_and_host(
        config,
        Arc::new(S08wInvalidAdmission),
        Arc::new(image_port),
        Arc::new(S08wImageSubstitutedHost),
        Arc::clone(&image_shutdown),
    )
    .unwrap_or_else(|error| panic!("s08w composition (image substitution): {error}"));
    let image_readiness = image_composition.readiness();
    assert_eq!(
        image_readiness.authority_state,
        WatchdogAuthorityState::RunningNoAuthority
    );
    assert!(!image_readiness.coverage_claimed);
    await_reported_gap(&image_reported, GapRecoveryReason::HostImageSubstituted).await;
    let image_observed: Vec<GapRecoveryReason> = image_gaps
        .lock()
        .unwrap_or_else(|error| panic!("s08w image gaps lock: {error}"))
        .clone();
    assert!(
        image_observed.contains(&GapRecoveryReason::HostImageSubstituted),
        "ImageSubstituted containment must report a nonfatal gap, got {image_observed:?}"
    );
    assert_eq!(
        image_composition.readiness().authority_state,
        WatchdogAuthorityState::RunningNoAuthority
    );
    assert!(!image_composition.readiness().coverage_claimed);
    image_shutdown.store(true, Ordering::Release);
    image_composition
        .run_until_shutdown()
        .await
        .unwrap_or_else(|error| panic!("s08w shutdown (image substitution): {error:?}"));

    // Existing admitted recovery route: bounded export, exact ack, compaction
    // below the cursor. No child is launched; the sink only returns
    // dispositions for the immutable batch.
    let limits = WatchdogSpoolExportLimits {
        max_items: 10,
        max_bytes: 65_536,
    };
    let retained_before_export = sensor
        .retained_spool_entries_for_export_driver_test()
        .unwrap_or_else(|error| panic!("s08w retained before export: {error}"));
    let retained_sequences: Vec<u64> = retained_before_export
        .iter()
        .map(|entry| entry.sequence)
        .collect();

    // Refusal/replay discriminator, run BEFORE the accepting export so the
    // unacknowledged evidence is still present to be lost. Both classes must
    // leave every record retained and the cursor unmoved, so the exact same
    // batch is still replayable afterwards. A refusal that dropped or
    // acknowledged anything would fail the identity comparison below.
    let failing_sink = S08wFailingSink {
        sink_id: "sink-s08w".to_owned(),
    };
    let failed = export_once(&sensor, &failing_sink, limits);
    assert!(
        failed.is_err(),
        "a sink that cannot acknowledge must not report a cursor advance"
    );

    let foreign_sink = S08wForeignAckSink {
        sink_id: "sink-s08w".to_owned(),
    };
    let foreign = export_once(&sensor, &foreign_sink, limits);
    assert!(
        foreign.is_err(),
        "a foreign acknowledgement must not report a cursor advance"
    );

    let after_refusal = sensor
        .retained_spool_entries_for_export_driver_test()
        .unwrap_or_else(|error| panic!("s08w retained after refusal: {error}"));
    assert_eq!(
        after_refusal
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        retained_sequences,
        "a failed or foreign acknowledgement must not discard unacknowledged evidence"
    );
    assert_eq!(
        after_refusal, retained_before_export,
        "refused acknowledgements must leave every retained record byte-identical"
    );

    // The accepting route is now proven to be the only thing that advances:
    // the same exact batch identity is re-exported and acknowledged.
    let sink = S08wTerminalSink {
        sink_id: "sink-s08w".to_owned(),
        last_acknowledged: Arc::new(Mutex::new(None)),
    };
    let sink_acknowledged = Arc::clone(&sink.last_acknowledged);
    let batch = sensor
        .export_spool_batch(sink.sink_id(), limits)
        .unwrap_or_else(|error| panic!("s08w export: {error}"));
    assert_eq!(batch.entries.len(), 3);
    assert_eq!(batch.first_sequence, 1);
    assert_eq!(batch.last_sequence, 3);
    assert_eq!(batch.high_water_sequence, 3);
    assert_eq!(
        batch
            .entries
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        retained_sequences,
        "the replayed batch must carry the exact record sequences still retained"
    );
    assert_eq!(
        batch
            .entries
            .iter()
            .map(|entry| entry.payload_kind)
            .collect::<Vec<_>>(),
        vec![
            eliot_watchdog_core::WatchdogSpoolPayloadKind::Heartbeat,
            eliot_watchdog_core::WatchdogSpoolPayloadKind::Gap,
            eliot_watchdog_core::WatchdogSpoolPayloadKind::Gap,
        ],
        "the replayed batch must preserve per-entry record identity in order"
    );
    // The batch the driver exported and the batch the sink answered must be
    // the same immutable batch, and the acknowledgement must cover exactly its
    // entries 1:1 with each record's own digest. This is fixture evidence of
    // the ack contract, not evidence of a real backend delivery.
    let replayed_digests: Vec<String> = batch
        .entries
        .iter()
        .map(|entry| entry.record_digest.clone())
        .collect();
    let replayed_ids: Vec<u64> = batch.entries.iter().map(|entry| entry.sequence).collect();
    let advanced = export_once(&sensor, &sink, limits)
        .unwrap_or_else(|error| panic!("s08w export_once: {error}"));
    assert_eq!(advanced, 3);
    let acknowledged = sink_acknowledged
        .lock()
        .unwrap_or_else(|error| panic!("s08w sink ack lock: {error}"))
        .clone()
        .unwrap_or_else(|| panic!("s08w fixture sink returned no acknowledgement"));
    assert_eq!(acknowledged.batch_id, batch.batch_id);
    assert_eq!(acknowledged.batch_digest, batch.batch_digest);
    assert_eq!(acknowledged.first_sequence, batch.first_sequence);
    assert_eq!(acknowledged.last_sequence, batch.last_sequence);
    assert_eq!(acknowledged.sink_id, "sink-s08w");
    assert_eq!(
        acknowledged
            .dispositions
            .iter()
            .map(|line| line.sequence)
            .collect::<Vec<_>>(),
        replayed_ids,
        "acknowledgement must cover exactly the exported sequences, in order"
    );
    assert_eq!(
        acknowledged
            .dispositions
            .iter()
            .map(|line| line.record_digest.clone())
            .collect::<Vec<_>>(),
        replayed_digests,
        "per-entry record identity must survive the acknowledgement unchanged"
    );
    assert_eq!(
        acknowledged.dispositions[0].disposition,
        eliot_watchdog_core::WatchdogSpoolSinkDisposition::Applied,
        "the admitted heartbeat is applied by the fixture sink"
    );
    for line in &acknowledged.dispositions[1..] {
        assert_eq!(
            line.disposition,
            eliot_watchdog_core::WatchdogSpoolSinkDisposition::GapRequiresRecovery,
            "gap records stay in the gap-resolution phase, not applied"
        );
    }
    let tail = sensor
        .retained_spool_entries_for_export_driver_test()
        .unwrap_or_else(|error| panic!("s08w tail: {error}"));
    assert_eq!(
        tail.iter().map(|entry| entry.sequence).collect::<Vec<_>>(),
        vec![3],
        "compaction must remove exactly the acknowledged prefix"
    );
    assert_eq!(
        tail[0].payload, retained_before_export[2].payload,
        "the surviving tail record must be byte-identical to the exported one"
    );

    // No private launcher: the watchdog keeps deterministic
    // health/containment policy and never acquires arbitrary launch authority.
    let manifest = include_str!("../../Cargo.toml");
    assert!(
        !manifest.contains("eliot-process"),
        "watchdog must not gain a process-launch edge"
    );
    assert!(
        !manifest.contains("eliot_process"),
        "watchdog must not gain a process-launch edge"
    );
    let lib_src = include_str!("../lib.rs");
    assert!(
        !lib_src.contains("eliot_process"),
        "watchdog lib must not reference a process executor"
    );
    assert!(
        !lib_src.contains("ProcessExecutor"),
        "watchdog lib must not reference a process executor"
    );
    assert!(
        !lib_src.contains("Command::new"),
        "watchdog lib must not invent a child launcher"
    );
    let composition_src = include_str!("../watchdog_composition.rs");
    assert!(
        !composition_src.contains("eliot_process"),
        "watchdog composition must not reference a process executor"
    );
    assert!(
        !composition_src.contains("Command::new"),
        "watchdog composition must not invent a child launcher"
    );
    let driver_src = include_str!("../watchdog_spool/export_driver.rs");
    assert!(
        driver_src.contains("no process execution"),
        "export driver must document the no-launcher boundary"
    );

    // Owned temporary state: cleanup is an explicit, reported action, never a
    // `Drop` side effect. Both the sensor (holding `watchdog.redb` open) and
    // the ORS store (holding its own file open) are closed first, then the
    // exact paths this test created are removed and verified gone. A failure
    // here reports the exact path and retains the residue.
    let owned = S08wOwnedTempState::new(vec![ors_path.clone(), state_dir.clone()]);
    drop(sensor);
    drop(store);
    let mut owned = owned;
    owned.remove();
    assert_eq!(
        owned.removed,
        owned.paths.len(),
        "every test-owned temporary path must be observed removed"
    );
}
