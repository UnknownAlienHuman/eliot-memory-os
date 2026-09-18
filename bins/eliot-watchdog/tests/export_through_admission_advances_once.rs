//! Wave C driver proof: one bounded spool export advances through admission.
//!
//! Drives the real [`eliot_watchdog::export_once`] chain over a real spool:
//! Heartbeat, Gap, and Recovery records are seeded through the real retention
//! path, exported under a tight window, acknowledged by a transport-agnostic
//! fake sink using the terminal admission mapping (Heartbeat to `Applied`,
//! Gap/Recovery to `GapRequiresRecovery`), and compacted below the cursor.
//! The fake sink lives only in this test; production takes a real
//! [`eliot_watchdog::WatchdogExportSink`] from the Governor lane.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_watchdog::{
    GapRecoveryReason, IndependentKernelSensor, SERVICE_NAME, SpoolAppendOutcome, SpoolError,
    WatchdogExportSink, WatchdogSpoolExportLimits, WatchdogSpoolPayload, export_once,
    watchog_entry_views, watchdog_entry_views,
};
use eliot_watchdog_core::{
    WatchdogSpoolAcknowledgement, WatchdogSpoolExportBatch, WatchdogSpoolEntryDisposition,
    WatchdogSpoolPayloadKind, WatchdogSpoolSinkDisposition, export_retry_identity_equal,
    is_duplicate_ack,
};

static SERIAL: AtomicU64 = AtomicU64::new(0);

fn temp_state_dir(tag: &str) -> std::path::PathBuf {
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "eliot-watchdog-wave-c-{tag}-{}-{serial}",
        std::process::id()
    ))
}

fn open_sensor(tag: &str) -> (IndependentKernelSensor, std::path::PathBuf) {
    let dir = temp_state_dir(tag);
    std::fs::create_dir_all(&dir).expect("create temp watchdog state dir");
    let sensor =
        IndependentKernelSensor::open_for_export_driver_test(&dir, "installation-wave-c", 7, 3)
            .expect("open Wave C test sensor");
    (sensor, dir)
}

fn heartbeat_payload() -> WatchdogSpoolPayload {
    WatchdogSpoolPayload::Heartbeat {
        service: SERVICE_NAME.to_owned(),
        lease_id: "lease-wave-c-1".to_owned(),
        scope_ref: "scope-wave-c".to_owned(),
        kernel_epoch: 2,
        watchdog_epoch: 3,
        payload_digest: "a".repeat(64),
        envelope_digest: "b".repeat(64),
        signer_id: "signer-wave-c".to_owned(),
        key_id: "key-wave-c".to_owned(),
        signature_algorithm: "ed25519".to_owned(),
        signature: "c".repeat(64),
        public_key_fingerprint: "d".repeat(64),
        lease_revision: 1,
    }
}

fn gap_payload() -> WatchdogSpoolPayload {
    WatchdogSpoolPayload::Gap {
        service: SERVICE_NAME.to_owned(),
        reason: GapRecoveryReason::AdmissionUnavailable,
        coverage_claimed: false,
    }
}

fn recovery_payload() -> WatchdogSpoolPayload {
    WatchdogSpoolPayload::Recovery {
        service: SERVICE_NAME.to_owned(),
        reason: "wave-c export proof".to_owned(),
        corrupt_sequence: None,
        corrupt_digest: "e".repeat(64),
    }
}

/// Fake terminal sink: builds the exact acknowledgement for the submitted
/// batch from the pure admission-entry projection, mapping Heartbeat entries
/// to `Applied` and Gap/Recovery entries to `GapRequiresRecovery`, exactly
/// like the Governor-lane terminal mapping.
struct TerminalSink {
    sink_id: String,
    submits: Cell<usize>,
}

impl WatchdogExportSink for TerminalSink {
    fn sink_id(&self) -> &str {
        &self.sink_id
    }

    fn submit(
        &self,
        batch: &WatchdogSpoolExportBatch,
    ) -> Result<WatchdogSpoolAcknowledgement, SpoolError> {
        self.submits.set(self.submits.get() + 1);
        let dispositions = watchog_entry_views(batch)
            .into_iter()
            .map(
                |(sequence, kind, record_digest, _payload_digest, _observed_at_ms)| {
                    let disposition = match kind {
                        WatchdogSpoolPayloadKind::Heartbeat => {
                            WatchdogSpoolSinkDisposition::Applied
                        }
                        WatchdogSpoolPayloadKind::Gap | WatchdogSpoolPayloadKind::Recovery => {
                            WatchdogSpoolSinkDisposition::GapRequiresRecovery
                        }
                    };
                    WatchdogSpoolEntryDisposition {
                        sequence,
                        disposition,
                        record_digest,
                    }
                },
            )
            .collect();
        Ok(WatchdogSpoolAcknowledgement {
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

#[test]
fn export_through_admission_advances_once() {
    let (sensor, dir) = open_sensor("advances-once");
    let sink = TerminalSink {
        sink_id: "sink-wave-c".to_owned(),
        submits: Cell::new(0),
    };
    let limits = WatchdogSpoolExportLimits {
        max_items: 2,
        max_bytes: 65_536,
    };

    assert!(matches!(
        sensor.append_spool_entry_for_export_driver_test(1_000, heartbeat_payload()),
        Ok(SpoolAppendOutcome::Stored)
    ));
    assert!(matches!(
        sensor.append_spool_entry_for_export_driver_test(2_000, gap_payload()),
        Ok(SpoolAppendOutcome::Stored)
    ));
    assert!(matches!(
        sensor.append_spool_entry_for_export_driver_test(3_000, recovery_payload()),
        Ok(SpoolAppendOutcome::Stored)
    ));

    let probe = sensor
        .export_spool_batch(sink.sink_id(), limits)
        .expect("export probe batch");
    assert_eq!(probe.first_sequence, 1);
    assert_eq!(probe.last_sequence, 2);
    let views = watchog_entry_views(&probe);
    assert_eq!(views, watchdog_entry_views(&probe));
    assert_eq!(views.len(), probe.entries.len());
    assert_eq!(views[0].0, 1);
    assert_eq!(views[0].1, WatchdogSpoolPayloadKind::Heartbeat);
    assert_eq!(views[0].2, probe.entries[0].record_digest);
    assert_eq!(views[0].3, probe.entries[0].payload_digest);
    assert_eq!(views[0].4, 1_000);
    assert_eq!(views[1].0, 2);
    assert_eq!(views[1].1, WatchdogSpoolPayloadKind::Gap);

    let retry = sensor
        .export_spool_batch(sink.sink_id(), limits)
        .expect("retry export before acknowledgement");
    assert!(export_retry_identity_equal(&probe, &retry));

    let advanced = export_once(&sensor, &sink, limits).expect("drive one export");
    assert_eq!(advanced, probe.last_sequence);
    assert_eq!(advanced, 2);
    assert_eq!(sink.submits.get(), 1);
    let retained = sensor
        .retained_spool_entries_for_export_driver_test()
        .expect("read retained spool");
    assert_eq!(
        retained
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );

    let ack = sink.submit(&probe).expect("rebuild terminal acknowledgement");
    assert!(is_duplicate_ack(advanced, &ack));
    assert!(!is_duplicate_ack(0, &ack));
    let duplicate = sensor
        .apply_spool_acknowledgement(&probe, &ack)
        .expect("duplicate acknowledgement returns stored");
    assert_eq!(duplicate, advanced);

    let second = sensor
        .export_spool_batch(sink.sink_id(), limits)
        .expect("second export");
    assert_eq!(second.predecessor_cursor.acknowledged_sequence, advanced);
    assert_eq!(second.first_sequence, advanced + 1);
    assert_eq!(second.first_sequence, 3);

    let drained = export_once(&sensor, &sink, limits).expect("drain recovery entry");
    assert_eq!(drained, 3);
    let submits_before_empty = sink.submits.get();
    let empty = export_once(&sensor, &sink, limits).expect("empty export short-circuits");
    assert_eq!(empty, 3);
    assert_eq!(sink.submits.get(), submits_before_empty);
    let tail = sensor
        .retained_spool_entries_for_export_driver_test()
        .expect("read retained tail");
    assert_eq!(
        tail.iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        vec![3]
    );

    drop(sensor);
    let _ = std::fs::remove_dir_all(&dir);
}
