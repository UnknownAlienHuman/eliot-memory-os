//! Wave C driver proof: store-unavailable acknowledgements stay replayable.
//!
//! Drives the real [`eliot_watchdog::export_once`] chain over a real spool
//! with a flaky fake sink. `Durable` and `Unknown` acknowledgement shapes fail
//! closed in the spool owner: the cursor never moves and the exact batch
//! re-exports byte-identically until the sink recovers with the terminal
//! mapping. Compaction then removes only sub-cursor heartbeats while the open
//! Gap boundary is retained at the cursor until a later acknowledgement
//! advances past it. The fake sink lives only in this test; production takes
//! a real [`eliot_watchdog::WatchdogExportSink`] from the Governor lane.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_watchdog::{
    GapRecoveryReason, IndependentKernelSensor, SERVICE_NAME, SpoolAppendOutcome, SpoolError,
    WatchdogExportSink, WatchdogSpoolExportLimits, WatchdogSpoolPayload, export_once,
    watchog_entry_views,
};
use eliot_watchdog_core::{
    WatchdogSpoolAcknowledgement, WatchdogSpoolExportBatch, WatchdogSpoolEntryDisposition,
    WatchdogSpoolPayloadKind, WatchdogSpoolSinkDisposition, export_retry_identity_equal,
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

fn heartbeat_payload(lease_id: &str) -> WatchdogSpoolPayload {
    WatchdogSpoolPayload::Heartbeat {
        service: SERVICE_NAME.to_owned(),
        lease_id: lease_id.to_owned(),
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum FakeMode {
    Durable,
    Unknown,
    Terminal,
}

/// Fake flaky sink: returns the honest store-unavailable acknowledgement
/// shapes (`Durable`, `Unknown`) or the terminal admission mapping, all built
/// from the pure admission-entry projection over the submitted batch.
struct FlakySink {
    sink_id: String,
    mode: Cell<FakeMode>,
}

impl WatchdogExportSink for FlakySink {
    fn sink_id(&self) -> &str {
        &self.sink_id
    }

    fn submit(
        &self,
        batch: &WatchdogSpoolExportBatch,
    ) -> Result<WatchdogSpoolAcknowledgement, SpoolError> {
        let mode = self.mode.get();
        let dispositions = watchog_entry_views(batch)
            .into_iter()
            .map(
                |(sequence, kind, record_digest, _payload_digest, _observed_at_ms)| {
                    let disposition = match mode {
                        FakeMode::Durable => WatchdogSpoolSinkDisposition::Durable,
                        FakeMode::Unknown => WatchdogSpoolSinkDisposition::Unknown,
                        FakeMode::Terminal => match kind {
                            WatchdogSpoolPayloadKind::Heartbeat => {
                                WatchdogSpoolSinkDisposition::Applied
                            }
                            WatchdogSpoolPayloadKind::Gap
                            | WatchdogSpoolPayloadKind::Recovery => {
                                WatchdogSpoolSinkDisposition::GapRequiresRecovery
                            }
                        },
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

fn retained_sequences(sensor: &IndependentKernelSensor) -> Vec<u64> {
    sensor
        .retained_spool_entries_for_export_driver_test()
        .expect("read retained spool")
        .iter()
        .map(|entry| entry.sequence)
        .collect()
}

#[test]
fn store_unavailable_leaves_cursor_replayable() {
    let (sensor, dir) = open_sensor("replayable");
    let sink = FlakySink {
        sink_id: "sink-wave-c".to_owned(),
        mode: Cell::new(FakeMode::Durable),
    };
    let limits = WatchdogSpoolExportLimits {
        max_items: 2,
        max_bytes: 65_536,
    };

    assert!(matches!(
        sensor.append_spool_entry_for_export_driver_test(1_000, heartbeat_payload("lease-1")),
        Ok(SpoolAppendOutcome::Stored)
    ));
    assert!(matches!(
        sensor.append_spool_entry_for_export_driver_test(2_000, heartbeat_payload("lease-2")),
        Ok(SpoolAppendOutcome::Stored)
    ));

    let (batch, raws) = sensor
        .export_spool_batch_with_raws(sink.sink_id(), limits)
        .expect("export batch with raws");
    assert_eq!((batch.first_sequence, batch.last_sequence), (1, 2));

    let durable = sink.submit(&batch).expect("durable acknowledgement builds");
    let error = sensor
        .apply_spool_acknowledgement(&batch, &durable)
        .expect_err("durable dispositions must not advance the cursor");
    assert!(
        error.to_string().contains("terminal"),
        "durable refusal must name the terminal rule, got: {error}"
    );
    let (re_batch, re_raws) = sensor
        .export_spool_batch_with_raws(sink.sink_id(), limits)
        .expect("re-export after durable refusal");
    assert_eq!(re_batch.predecessor_cursor.acknowledged_sequence, 0);
    assert!(export_retry_identity_equal(&batch, &re_batch));
    assert_eq!(raws, re_raws);

    sink.mode.set(FakeMode::Unknown);
    let unknown = sink.submit(&batch).expect("unknown acknowledgement builds");
    let error = sensor
        .apply_spool_acknowledgement(&batch, &unknown)
        .expect_err("unknown outcomes must fail closed");
    assert!(
        error.to_string().contains("unknown outcome"),
        "unknown refusal must name the outcome rule, got: {error}"
    );
    let again = sensor
        .export_spool_batch(sink.sink_id(), limits)
        .expect("re-export after unknown refusal");
    assert_eq!(again.predecessor_cursor.acknowledged_sequence, 0);

    sink.mode.set(FakeMode::Terminal);
    let advanced = export_once(&sensor, &sink, limits).expect("export after sink recovers");
    assert_eq!(advanced, batch.last_sequence);
    assert_eq!(advanced, 2);
    assert!(retained_sequences(&sensor).is_empty());

    assert!(matches!(
        sensor.append_spool_entry_for_export_driver_test(3_000, gap_payload()),
        Ok(SpoolAppendOutcome::Stored)
    ));
    let gap_batch = sensor
        .export_spool_batch(sink.sink_id(), limits)
        .expect("export open gap");
    assert_eq!((gap_batch.first_sequence, gap_batch.last_sequence), (3, 3));
    sink.mode.set(FakeMode::Durable);
    let gap_durable = sink
        .submit(&gap_batch)
        .expect("durable gap acknowledgement builds");
    let error = sensor
        .apply_spool_acknowledgement(&gap_batch, &gap_durable)
        .expect_err("durable gap must not advance the cursor");
    assert!(error.to_string().contains("terminal"));
    let held = sensor
        .export_spool_batch(sink.sink_id(), limits)
        .expect("re-export held gap");
    assert_eq!(held.predecessor_cursor.acknowledged_sequence, 2);

    sink.mode.set(FakeMode::Terminal);
    let advanced_gap = export_once(&sensor, &sink, limits).expect("resolve open gap");
    assert_eq!(advanced_gap, 3);
    let removed = sensor
        .compact_spool_below_cursor(advanced_gap)
        .expect("re-compact at boundary");
    assert_eq!(removed, 0);
    assert_eq!(retained_sequences(&sensor), vec![3]);

    assert!(matches!(
        sensor.append_spool_entry_for_export_driver_test(4_000, heartbeat_payload("lease-4")),
        Ok(SpoolAppendOutcome::Stored)
    ));
    let advanced_tail = export_once(&sensor, &sink, limits).expect("advance past boundary");
    assert_eq!(advanced_tail, 4);
    assert!(retained_sequences(&sensor).is_empty());

    drop(sensor);
    let _ = std::fs::remove_dir_all(&dir);
}
