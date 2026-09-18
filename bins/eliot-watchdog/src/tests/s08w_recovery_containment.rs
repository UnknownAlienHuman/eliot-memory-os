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
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

struct S08wTerminalSink {
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
        Ok(eliot_watchdog_core::WatchdogSpoolAcknowledgement {
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
        let gaps = self.gaps.clone();
        let reason = disposition.reason;
        Box::pin(async move {
            match gaps.lock() {
                Ok(mut guard) => {
                    guard.push(reason);
                    Ok(())
                }
                Err(_) => Err(crate::KernelWatchdogError::Failed),
            }
        })
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
    let now_ms =
        crate::current_unix_ms().unwrap_or_else(|error| panic!("s08w clock: {error}"));
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
        matches!(
            retained[0].payload,
            WatchdogSpoolPayload::Heartbeat { .. }
        ),
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

    // Composition containment: a `PidReused` host observation with no
    // admission stays `RunningNoAuthority` (the public `publish_no_authority`
    // projection) while the gap port observes the typed reason nonfatally.
    let gaps = Arc::new(Mutex::new(Vec::new()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let config = WatchdogConfig {
        tick_interval: Duration::from_millis(5),
        ..WatchdogConfig::default()
    };
    let composition = WatchdogComposition::start_with_shutdown_and_host(
        config,
        Arc::new(S08wInvalidAdmission),
        Arc::new(S08wRecordingPort { gaps: gaps.clone() }),
        Arc::new(S08wPidReusedHost),
        shutdown.clone(),
    )
    .unwrap_or_else(|error| panic!("s08w composition: {error}"));
    let readiness = composition.readiness();
    assert_eq!(
        readiness.authority_state,
        WatchdogAuthorityState::RunningNoAuthority
    );
    assert!(!readiness.coverage_claimed);
    tokio::time::sleep(Duration::from_millis(35)).await;
    let observed: Vec<GapRecoveryReason> = gaps
        .lock()
        .unwrap_or_else(|error| panic!("s08w gaps lock: {error}"))
        .clone();
    assert!(
        observed.contains(&GapRecoveryReason::HostPidReused),
        "PidReused containment must report a nonfatal gap, got {observed:?}"
    );
    assert_eq!(
        composition.readiness().authority_state,
        WatchdogAuthorityState::RunningNoAuthority
    );
    shutdown.store(true, Ordering::Release);
    composition
        .run_until_shutdown()
        .await
        .unwrap_or_else(|error| panic!("s08w shutdown: {error:?}"));

    // Existing admitted recovery route: bounded export, exact ack, compaction
    // below the cursor. No child is launched; the sink only returns
    // dispositions for the immutable batch.
    let sink = S08wTerminalSink {
        sink_id: "sink-s08w".to_owned(),
    };
    let limits = WatchdogSpoolExportLimits {
        max_items: 10,
        max_bytes: 65_536,
    };
    let batch = sensor
        .export_spool_batch(sink.sink_id(), limits)
        .unwrap_or_else(|error| panic!("s08w export: {error}"));
    assert_eq!(batch.entries.len(), 3);
    assert_eq!(batch.first_sequence, 1);
    assert_eq!(batch.last_sequence, 3);
    let advanced = export_once(&sensor, &sink, limits)
        .unwrap_or_else(|error| panic!("s08w export_once: {error}"));
    assert_eq!(advanced, 3);
    let tail = sensor
        .retained_spool_entries_for_export_driver_test()
        .unwrap_or_else(|error| panic!("s08w tail: {error}"));
    assert_eq!(
        tail.iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        vec![3]
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

    drop(sensor);
    let _ = std::fs::remove_dir_all(&state_dir);
    let _ = std::fs::remove_file(&ors_path);
}
