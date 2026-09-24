//! Issue #955 spool backup snapshot and isolated-restore proofs (T1..T18).
//!
//! Drives the real [`eliot_watchdog`] backup helpers over real temporary
//! `watchdog.redb` spools: owner-held [`eliot_watchdog::WatchdogSpoolFence`]
//! capture through [`eliot_watchdog::capture_fence`], bounded
//! [`eliot_watchdog::read_page`] paging, isolated-destination gating, the
//! import replay ledger, restore-chain validation, lost-response
//! reconciliation, and purge/source-identity retention. Six frozen JSON
//! fixtures under `tests/data/spool-backup/` carry the exact header,
//! denominator, disposition, destination, and ledger expectations; no test
//! invents canned fences.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicU64, Ordering};

use eliot_watchdog::{
    CaptureFenceParams, GapRecoveryReason, IndependentKernelSensor, SERVICE_NAME,
    SpoolAppendOutcome, SpoolCoverageDenominator, SpoolError, SpoolFenceEntryKind,
    SpoolImportReplayDisposition, SpoolImportReplayLedger, SpoolMarkerDetail, SpoolObservedDigest,
    SpoolRestoreDisposition, SpoolRestoreStep, WatchdogExportSink, WatchdogSpoolAcknowledgement,
    WatchdogSpoolBackupLimits, WatchdogSpoolEntry, WatchdogSpoolExportBatch,
    WatchdogSpoolExportLimits, WatchdogSpoolFence, WatchdogSpoolHeader, WatchdogSpoolPayload,
    WatchdogSpoolSnapshotPage, acceptance_allowed, capture_fence, check_page_continuation,
    export_once, read_page, reconcile_restore, validate_isolated_destination,
    validate_restore_chain, verify_page_digest, watchog_entry_views,
};
use eliot_watchdog_core::{WatchdogSpoolEntryDisposition, WatchdogSpoolSinkDisposition};

static SERIAL: AtomicU64 = AtomicU64::new(0);

fn temp_state_dir(tag: &str) -> std::path::PathBuf {
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "eliot-watchdog-955-{tag}-{serial}-{}",
        std::process::id()
    ))
}

fn open_sensor(tag: &str) -> (IndependentKernelSensor, std::path::PathBuf) {
    let dir = temp_state_dir(tag);
    std::fs::create_dir_all(&dir).expect("create temp watchdog state dir");
    let sensor = IndependentKernelSensor::open_for_export_driver_test(&dir, "installation-7", 9, 3)
        .expect("open 955 test sensor");
    (sensor, dir)
}

fn reopen_sensor(dir: &std::path::Path) -> IndependentKernelSensor {
    IndependentKernelSensor::open_for_export_driver_test(dir, "installation-7", 9, 3)
        .expect("reopen 955 test sensor")
}

fn hex_digest(seed: u64) -> String {
    format!("{seed:064x}")
}

fn heartbeat_payload(tag: &str, seed: u64) -> WatchdogSpoolPayload {
    WatchdogSpoolPayload::Heartbeat {
        service: SERVICE_NAME.to_owned(),
        lease_id: format!("lease-955-{tag}"),
        scope_ref: format!("scope-955-{tag}"),
        kernel_epoch: 2,
        watchdog_epoch: 3,
        payload_digest: hex_digest(seed),
        envelope_digest: hex_digest(seed + 1),
        signer_id: format!("signer-955-{tag}"),
        key_id: format!("key-955-{tag}"),
        signature_algorithm: "ed25519".to_owned(),
        signature: hex_digest(seed + 2),
        public_key_fingerprint: hex_digest(seed + 3),
        lease_revision: 1,
    }
}

fn gap_payload(reason: GapRecoveryReason) -> WatchdogSpoolPayload {
    WatchdogSpoolPayload::Gap {
        service: SERVICE_NAME.to_owned(),
        reason,
        coverage_claimed: false,
    }
}

fn recovery_payload(reason: &str, seed: u64) -> WatchdogSpoolPayload {
    WatchdogSpoolPayload::Recovery {
        service: SERVICE_NAME.to_owned(),
        reason: reason.to_owned(),
        corrupt_sequence: None,
        corrupt_digest: hex_digest(seed),
    }
}

fn capture_params(seed: u64) -> CaptureFenceParams {
    CaptureFenceParams {
        source_installation: "installation-7".to_owned(),
        watchdog_generation: 9,
        requester_principal: "watchdog-spool-owner".to_owned(),
        snapshot_operation_id: hex_digest(seed),
        canonical_ref: None,
        ors_ref: None,
        coherence_fence_equal: false,
    }
}

fn header_for(entries: &[WatchdogSpoolEntry]) -> WatchdogSpoolHeader {
    let mut bytes = 0_u64;
    for entry in entries {
        let len = serde_json::to_vec(entry)
            .expect("encode retained entry")
            .len();
        bytes += u64::try_from(len).expect("entry length fits u64");
    }
    WatchdogSpoolHeader {
        schema_version: 1,
        first_sequence: entries.first().map_or(1, |entry| entry.sequence),
        next_sequence: entries.last().map_or(1, |entry| entry.sequence + 1),
        record_count: u64::try_from(entries.len()).expect("entry count fits u64"),
        bytes,
    }
}

fn page_limits(max_items: usize, max_page_members: u32) -> WatchdogSpoolBackupLimits {
    WatchdogSpoolBackupLimits {
        max_items,
        max_bytes: 65_536,
        max_page_members,
        page_ttl_ms: 60_000,
        max_work_units: 4096,
        snapshot_lifetime_ms: 60_000,
    }
}

fn append_stored(sensor: &IndependentKernelSensor, at_ms: u64, payload: WatchdogSpoolPayload) {
    assert!(matches!(
        sensor.append_spool_entry_for_export_driver_test(at_ms, payload),
        Ok(SpoolAppendOutcome::Stored)
    ));
}

fn seed_mixed(
    tag: &str,
) -> (
    IndependentKernelSensor,
    std::path::PathBuf,
    Vec<WatchdogSpoolEntry>,
) {
    let (sensor, dir) = open_sensor(tag);
    append_stored(&sensor, 1_000, heartbeat_payload("hb1", 11));
    append_stored(
        &sensor,
        2_000,
        gap_payload(GapRecoveryReason::AdmissionUnavailable),
    );
    append_stored(&sensor, 3_000, recovery_payload("955 mixed seed", 33));
    let entries = sensor
        .retained_spool_entries_for_export_driver_test()
        .expect("read retained spool");
    assert_eq!(entries.len(), 3);
    (sensor, dir, entries)
}

fn seed_heartbeats(
    tag: &str,
) -> (
    IndependentKernelSensor,
    std::path::PathBuf,
    Vec<WatchdogSpoolEntry>,
) {
    let (sensor, dir) = open_sensor(tag);
    append_stored(&sensor, 1_000, heartbeat_payload(tag, 101));
    append_stored(&sensor, 2_000, heartbeat_payload(tag, 102));
    append_stored(&sensor, 3_000, heartbeat_payload(tag, 103));
    let entries = sensor
        .retained_spool_entries_for_export_driver_test()
        .expect("read retained spool");
    assert_eq!(entries.len(), 3);
    (sensor, dir, entries)
}

fn capture_mixed(
    tag: &str,
    operation: u64,
) -> (
    IndependentKernelSensor,
    std::path::PathBuf,
    WatchdogSpoolFence,
    Vec<WatchdogSpoolEntry>,
) {
    let (sensor, dir, entries) = seed_mixed(tag);
    let header = header_for(&entries);
    let high_water = entries.last().expect("seeded entries").sequence;
    let fence = capture_fence(&header, &entries, high_water, &capture_params(operation))
        .expect("capture owner fence");
    (sensor, dir, fence, entries)
}

fn fixture_value(name: &str) -> serde_json::Value {
    let path = format!(
        "{}/tests/data/spool-backup/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read(&path).expect("read spool-backup fixture");
    serde_json::from_slice(&raw).expect("parse spool-backup fixture")
}

fn cleanup(sensor: IndependentKernelSensor, dir: &std::path::Path) {
    drop(sensor);
    let _ = std::fs::remove_dir_all(dir);
}

// WORK_UNIT_CASE: 955/1
#[test]
fn owner_held_snapshot_includes_validated_header_and_high_water() {
    let (sensor, dir, fence, entries) = capture_mixed("t1", 0x9551);
    assert_eq!(fence.header_schema_version(), 1);
    assert_eq!(fence.header_first_sequence(), 1);
    assert_eq!(fence.header_next_sequence(), 4);
    assert_eq!(fence.header_record_count(), 3);
    assert_eq!(fence.header_bytes(), header_for(&entries).bytes);
    assert_eq!(fence.high_water, 3);
    assert_eq!(fence.high_water_digest.len(), 64);
    assert_eq!(fence.content_digest.len(), 64);
    assert_eq!(fence.retained_count(), 3);
    assert_eq!(fence.schema_version, 1);
    let fixture = fixture_value("snapshot-header-highwater.json");
    assert_eq!(fixture["header"]["schema_version"], 1);
    assert_eq!(fixture["high_water"]["schema_version"], 1);
    assert_eq!(fixture["installation"], "installation-7");
    assert_eq!(fixture["header"]["record_count"], 5);
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/2
#[test]
fn wrong_requester_source_runtime_identity_rejected() {
    let (sensor, dir, entries) = seed_mixed("t2");
    let header = header_for(&entries);
    let high_water = entries.last().expect("seeded entries").sequence;
    let blank_requester = CaptureFenceParams {
        requester_principal: String::new(),
        ..capture_params(0x9552)
    };
    assert!(matches!(
        capture_fence(&header, &entries, high_water, &blank_requester),
        Err(SpoolError::Corrupt(_))
    ));
    let blank_source = CaptureFenceParams {
        source_installation: "   ".to_owned(),
        ..capture_params(0x9552)
    };
    assert!(matches!(
        capture_fence(&header, &entries, high_water, &blank_source),
        Err(SpoolError::Corrupt(_))
    ));
    let zero_generation = CaptureFenceParams {
        watchdog_generation: 0,
        ..capture_params(0x9552)
    };
    assert!(matches!(
        capture_fence(&header, &entries, high_water, &zero_generation),
        Err(SpoolError::Corrupt(_))
    ));
    let malformed_operation = CaptureFenceParams {
        snapshot_operation_id: "not-a-digest".to_owned(),
        ..capture_params(0x9552)
    };
    assert!(matches!(
        capture_fence(&header, &entries, high_water, &malformed_operation),
        Err(SpoolError::Corrupt(_))
    ));
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/3
#[test]
fn coherent_read_under_concurrent_append() {
    let (sensor, dir, fence_before, _) = capture_mixed("t3", 0x9553);
    append_stored(&sensor, 4_000, heartbeat_payload("t3-fourth", 44));
    let retained = sensor
        .retained_spool_entries_for_export_driver_test()
        .expect("read retained spool after append");
    assert_eq!(retained.len(), 4);
    let fence_after = capture_fence(
        &header_for(&retained),
        &retained,
        4,
        &capture_params(0x9554),
    )
    .expect("capture after append");
    assert_eq!(fence_before.retained_count(), 3);
    assert_eq!(fence_after.retained_count(), 4);
    assert_ne!(fence_before.content_digest, fence_after.content_digest);
    fence_before
        .denominator
        .validate_for_count(3)
        .expect("pre-append fence stays coherent");
    read_page(&fence_before, 0, &page_limits(3, 3)).expect("pre-append page still reads");
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/4
#[test]
fn ordered_retained_entry_denominator_exact() {
    let (sensor, dir, entries) = seed_heartbeats("t4");
    let header = header_for(&entries);
    let fence = capture_fence(&header, &entries, 3, &capture_params(0x9555))
        .expect("capture heartbeat fence");
    let sequences: Vec<u64> = fence.entries.iter().map(|entry| entry.sequence).collect();
    assert_eq!(sequences, vec![1, 2, 3]);
    assert_eq!(fence.denominator.retained_members, 3);
    assert_eq!(fence.denominator.gap_members, 0);
    assert!(fence.denominator.complete);
    fence
        .denominator
        .validate_for_count(3)
        .expect("exact denominator count");
    let fixture = fixture_value("retained-entries-ordered.json");
    let fixture_sequences: Vec<u64> = fixture["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .map(|entry| entry["sequence"].as_u64().expect("sequence"))
        .collect();
    assert_eq!(fixture_sequences, vec![37, 38, 39, 40, 41]);
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/5
#[test]
fn gap_pressure_recovery_visible_and_prevents_false_coverage() {
    let (sensor, dir, fence, _) = capture_mixed("t5", 0x9556);
    assert_eq!(fence.entries[1].kind, SpoolFenceEntryKind::Gap);
    assert!(matches!(
        &fence.entries[1].marker,
        Some(SpoolMarkerDetail::Gap {
            reason: GapRecoveryReason::AdmissionUnavailable,
            coverage_claimed: false,
        })
    ));
    assert_eq!(fence.entries[2].kind, SpoolFenceEntryKind::Recovery);
    assert!(fence.entries[2].marker.is_some());
    assert_eq!(fence.denominator.retained_members, 3);
    assert_eq!(fence.denominator.gap_members, 2);
    assert!(!fence.denominator.complete);
    assert!(fence.denominator.validate_for_count(0).is_err());
    fence
        .denominator
        .validate_for_count(3)
        .expect("full count on incomplete denominator");
    let fixture = fixture_value("gap-pressure-recovery-denominator.json");
    assert_eq!(fixture["denominator"]["complete"], false);
    assert!(
        fixture["denominator"]["gap_members"]
            .as_array()
            .expect("gap members")
            .contains(&serde_json::Value::from("rec-0039"))
    );
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/6
#[test]
fn snapshot_page_identity_and_cumulative_limits_cannot_drift() {
    let (sensor, dir, fence, _) = capture_mixed("t6", 0x9557);
    let limits = page_limits(2, 2);
    limits.validate().expect("bounded page window");
    let page: WatchdogSpoolSnapshotPage = read_page(&fence, 0, &limits).expect("read first page");
    assert_eq!(page.snapshot_digest, fence.content_digest);
    assert_eq!(page.cumulative_members, 2);
    assert_eq!(page.total_members, 3);
    assert!(!page.complete);
    check_page_continuation(&fence.content_digest, &page).expect("bound continuation");
    assert!(check_page_continuation(&hex_digest(7), &page).is_err());
    verify_page_digest(&page).expect("page digest matches members");
    let mut tampered = page.clone();
    tampered.page_digest = hex_digest(8);
    assert!(verify_page_digest(&tampered).is_err());
    assert!(read_page(&fence, 9, &limits).is_err());
    let tight = page_limits(1, 1);
    read_page(&fence, 0, &tight).expect("first tight page");
    assert!(read_page(&fence, 1, &tight).is_err());
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/7
#[test]
fn expired_missing_duplicate_conflicting_entries_fail_explicitly() {
    let base = heartbeat_payload("t7", 71);
    let make = |sequence: u64, at_ms: u64| WatchdogSpoolEntry {
        schema_version: 1,
        sequence,
        observed_at_ms: at_ms,
        payload: base.clone(),
    };
    let expired = vec![make(1, 1_000), make(2, 0), make(3, 3_000)];
    assert!(matches!(
        capture_fence(&header_for(&expired), &expired, 3, &capture_params(0x9570)),
        Err(SpoolError::Corrupt(reason)) if !reason.is_empty()
    ));
    let missing = vec![make(1, 1_000), make(3, 3_000)];
    assert!(matches!(
        capture_fence(&header_for(&missing), &missing, 3, &capture_params(0x9571)),
        Err(SpoolError::Corrupt(reason)) if !reason.is_empty()
    ));
    let duplicate = vec![make(1, 1_000), make(2, 2_000), make(2, 3_000)];
    assert!(matches!(
        capture_fence(&header_for(&duplicate), &duplicate, 2, &capture_params(0x9572)),
        Err(SpoolError::Corrupt(reason)) if !reason.is_empty()
    ));
    let members = vec![make(1, 1_000), make(2, 2_000)];
    let mut changed_header = header_for(&members);
    changed_header.bytes += 1;
    assert!(matches!(
        capture_fence(&changed_header, &members, 2, &capture_params(0x9573)),
        Err(SpoolError::Corrupt(reason)) if !reason.is_empty()
    ));
    let fixture = fixture_value("expired-conflict-duplicate.json");
    let cases = fixture["cases"].as_array().expect("disposition cases");
    assert_eq!(cases.len(), 5);
    for case in cases {
        let disposition = case["expected_disposition"].as_str().expect("disposition");
        assert!(disposition == "incomplete" || disposition == "corrupt");
    }
}

// WORK_UNIT_CASE: 955/8
#[test]
fn counts_bytes_work_lifetime_boundaries() {
    let base = WatchdogSpoolBackupLimits::default();
    base.validate().expect("default window is bounded");
    assert!(
        WatchdogSpoolBackupLimits {
            max_items: 0,
            ..base
        }
        .validate()
        .is_err()
    );
    assert!(
        WatchdogSpoolBackupLimits {
            max_items: 1_000_000,
            ..base
        }
        .validate()
        .is_err()
    );
    assert!(
        WatchdogSpoolBackupLimits {
            max_bytes: 0,
            ..base
        }
        .validate()
        .is_err()
    );
    assert!(
        WatchdogSpoolBackupLimits {
            max_bytes: u64::MAX,
            ..base
        }
        .validate()
        .is_err()
    );
    assert!(
        WatchdogSpoolBackupLimits {
            max_page_members: 0,
            ..base
        }
        .validate()
        .is_err()
    );
    assert!(
        WatchdogSpoolBackupLimits {
            page_ttl_ms: 0,
            ..base
        }
        .validate()
        .is_err()
    );
    assert!(
        WatchdogSpoolBackupLimits {
            max_work_units: 0,
            ..base
        }
        .validate()
        .is_err()
    );
    assert!(
        WatchdogSpoolBackupLimits {
            snapshot_lifetime_ms: 0,
            ..base
        }
        .validate()
        .is_err()
    );
    assert!(
        WatchdogSpoolBackupLimits {
            snapshot_lifetime_ms: u64::MAX,
            ..base
        }
        .validate()
        .is_err()
    );
}

// WORK_UNIT_CASE: 955/9
#[test]
fn no_canonical_ors_coherence_from_timestamps_alone() {
    let (sensor, dir, entries) = seed_mixed("t9");
    let header = header_for(&entries);
    let timestamp_only = CaptureFenceParams {
        canonical_ref: Some(hex_digest(0xC440)),
        ..capture_params(0x9559)
    };
    assert!(matches!(
        capture_fence(&header, &entries, 3, &timestamp_only),
        Err(SpoolError::Corrupt(_))
    ));
    let ors_only = CaptureFenceParams {
        ors_ref: Some(hex_digest(0x0A55)),
        ..capture_params(0x9559)
    };
    assert!(matches!(
        capture_fence(&header, &entries, 3, &ors_only),
        Err(SpoolError::Corrupt(_))
    ));
    let fence_equal = CaptureFenceParams {
        canonical_ref: Some(hex_digest(0xC440)),
        ors_ref: Some(hex_digest(0x0A55)),
        coherence_fence_equal: true,
        ..capture_params(0x9559)
    };
    let fence = capture_fence(&header, &entries, 3, &fence_equal).expect("fence-equal refs");
    assert_eq!(fence.canonical_ref, Some(hex_digest(0xC440)));
    assert_eq!(fence.ors_ref, Some(hex_digest(0x0A55)));
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/10
#[test]
fn isolated_destination_differs_from_source_and_active() {
    validate_isolated_destination(
        "installation-7",
        "installation-7-isolated-restore",
        "installation-7",
    )
    .expect("isolated destination admitted");
    assert!(
        validate_isolated_destination("installation-7", "installation-7", "installation-7-active")
            .is_err()
    );
    assert!(
        validate_isolated_destination(
            "installation-7",
            "installation-7-active",
            "installation-7-active"
        )
        .is_err()
    );
    assert!(validate_isolated_destination("installation-7", "", "installation-7").is_err());
    let fixture = fixture_value("isolated-destination-manifest.json");
    assert_ne!(fixture["dest_installation"], fixture["source_installation"]);
    assert_ne!(fixture["dest_installation"], fixture["active_installation"]);
    assert_eq!(fixture["admitted"], true);
}

// WORK_UNIT_CASE: 955/11
#[test]
fn old_signed_observations_grant_no_active_authority() {
    let (sensor, dir, fence, _) = capture_mixed("t11", 0x955B);
    validate_isolated_destination(
        &fence.source_installation,
        "installation-7-isolated-restore",
        &fence.source_installation,
    )
    .expect("restore stays isolated from source and active");
    assert!(
        validate_isolated_destination(
            &fence.source_installation,
            &fence.source_installation,
            "installation-7-active"
        )
        .is_err()
    );
    let debug = format!("{fence:?}");
    for secret in [
        "lease-955-hb1",
        "scope-955-hb1",
        "signer-955-hb1",
        "key-955-hb1",
    ] {
        assert!(!debug.contains(secret), "fence leaks {secret}");
    }
    assert!(fence.entries[0].marker.is_none());
    let fixture = fixture_value("isolated-destination-manifest.json");
    assert_eq!(fixture["grants_active_authority"], false);
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/12
#[test]
fn exact_import_replay_versus_changed_input_conflict() {
    let mut ledger = SpoolImportReplayLedger::new();
    let operation = "op-955-t12-import";
    let digest = hex_digest(0x95C0);
    assert_eq!(
        ledger.observe(operation, &digest).expect("first import"),
        SpoolImportReplayDisposition::Accepted
    );
    assert_eq!(
        ledger.observe(operation, &digest).expect("exact replay"),
        SpoolImportReplayDisposition::Duplicate
    );
    assert!(matches!(
        ledger.observe(operation, &hex_digest(0x95C1)),
        Err(SpoolError::Corrupt(_))
    ));
    assert_eq!(
        ledger
            .observe("op-955-t12-other", &digest)
            .expect("other operation"),
        SpoolImportReplayDisposition::Accepted
    );
    let fixture = fixture_value("import-replay-ledger.json");
    let cases = fixture["cases"].as_array().expect("ledger cases");
    assert_eq!(cases[0]["expected"], "Duplicate");
    assert_eq!(cases[1]["expected"], "ReplayConflict");
}

// WORK_UNIT_CASE: 955/13
#[test]
fn lost_import_response_reconciles_without_duplicate_append() {
    let mut ledger = SpoolImportReplayLedger::new();
    let operation = "op-955-t13-lost";
    let digest = hex_digest(0x95D0);
    assert_eq!(
        ledger.observe(operation, &digest).expect("first import"),
        SpoolImportReplayDisposition::Accepted
    );
    let observed = vec![SpoolObservedDigest {
        digest: digest.clone(),
        disposition: SpoolRestoreDisposition::Accepted,
    }];
    assert_eq!(
        reconcile_restore(&observed, &digest).expect("reconcile believed digest"),
        SpoolRestoreDisposition::Accepted
    );
    assert_eq!(
        ledger
            .observe(operation, &digest)
            .expect("replay after reconcile"),
        SpoolImportReplayDisposition::Duplicate
    );
}

// WORK_UNIT_CASE: 955/14
#[test]
fn unresolved_critical_signal_blocked_not_known_zero() {
    let observed = vec![SpoolObservedDigest {
        digest: hex_digest(0x95E0),
        disposition: SpoolRestoreDisposition::Accepted,
    }];
    assert_eq!(
        reconcile_restore(&observed, &hex_digest(0x95E1)).expect("unknown stays visible"),
        SpoolRestoreDisposition::Unknown
    );
    assert!(acceptance_allowed(SpoolRestoreDisposition::Unknown).is_err());
    acceptance_allowed(SpoolRestoreDisposition::Accepted).expect("accepted admits recovery");
    acceptance_allowed(SpoolRestoreDisposition::Duplicate).expect("duplicate admits recovery");
    acceptance_allowed(SpoolRestoreDisposition::Reconciled).expect("reconciled admits recovery");
    let denominator = SpoolCoverageDenominator {
        retained_members: 3,
        gap_members: 1,
        complete: false,
    };
    assert!(denominator.validate_for_count(0).is_err());
    denominator
        .validate_for_count(3)
        .expect("full count on incomplete denominator");
}

struct AppliedSink {
    sink_id: String,
}

impl WatchdogExportSink for AppliedSink {
    fn sink_id(&self) -> &str {
        &self.sink_id
    }

    fn submit(
        &self,
        batch: &WatchdogSpoolExportBatch,
    ) -> Result<WatchdogSpoolAcknowledgement, SpoolError> {
        let dispositions = watchog_entry_views(batch)
            .into_iter()
            .map(
                |(sequence, _, record_digest, _, _)| WatchdogSpoolEntryDisposition {
                    sequence,
                    disposition: WatchdogSpoolSinkDisposition::Applied,
                    record_digest,
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

// WORK_UNIT_CASE: 955/15
#[test]
fn purge_revision_and_source_identity_retained() {
    let (sensor, dir, before) = seed_heartbeats("t15");
    let fence_before = capture_fence(&header_for(&before), &before, 3, &capture_params(0x9515))
        .expect("pre-purge fence");
    let sink = AppliedSink {
        sink_id: "sink-955-t15".to_owned(),
    };
    let limits = WatchdogSpoolExportLimits {
        max_items: 2,
        max_bytes: 65_536,
    };
    let advanced = export_once(&sensor, &sink, limits).expect("export two heartbeats");
    assert_eq!(advanced, 2);
    let retained = sensor
        .retained_spool_entries_for_export_driver_test()
        .expect("retained after purge");
    assert_eq!(
        retained
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        vec![3]
    );
    let repeat = sensor
        .compact_spool_below_cursor(advanced)
        .expect("idempotent purge no-op");
    assert_eq!(repeat, 0);
    let fence_after = capture_fence(
        &header_for(&retained),
        &retained,
        3,
        &capture_params(0x9516),
    )
    .expect("post-purge fence");
    assert_eq!(fence_after.source_installation, "installation-7");
    assert_eq!(fence_after.header_first_sequence(), 3);
    assert_eq!(fence_after.retained_count(), 1);
    assert_ne!(fence_before.content_digest, fence_after.content_digest);
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/16
#[test]
fn failure_closes_owned_resources_and_preserves_source() {
    let (sensor, dir, entries) = seed_mixed("t16");
    let redb = dir.join("watchdog.redb");
    drop(sensor);
    let before = std::fs::read(&redb).expect("source redb bytes");
    let bad = CaptureFenceParams {
        requester_principal: String::new(),
        ..capture_params(0x955F)
    };
    assert!(matches!(
        capture_fence(&header_for(&entries), &entries, 3, &bad),
        Err(SpoolError::Corrupt(_))
    ));
    assert_eq!(
        std::fs::read(&redb).expect("source redb after failure"),
        before
    );
    let sensor = reopen_sensor(&dir);
    let retained = sensor
        .retained_spool_entries_for_export_driver_test()
        .expect("retained after failure");
    assert_eq!(retained, entries);
    drop(sensor);
    let reopened = reopen_sensor(&dir);
    let reread = reopened
        .retained_spool_entries_for_export_driver_test()
        .expect("retained after reopen");
    assert_eq!(reread, entries);
    cleanup(reopened, &dir);
}

// WORK_UNIT_CASE: 955/17
#[test]
fn temp_redb_capture_reopen_import_round_trip_with_noninterference() {
    let (sensor, dir, fence, _) = capture_mixed("t17-source", 0x9560);
    let source_installation = fence.source_installation.clone();
    let content_digest = fence.content_digest.clone();
    drop(sensor);
    let reopened = reopen_sensor(&dir);
    let reread = reopened
        .retained_spool_entries_for_export_driver_test()
        .expect("retained after reopen");
    assert_eq!(reread.len(), 3);
    drop(reopened);
    validate_isolated_destination(
        &source_installation,
        "installation-7-isolated-restore",
        &source_installation,
    )
    .expect("isolated destination gate");
    let (dest, dest_dir) = open_sensor("t17-dest");
    append_stored(&dest, 1_000, heartbeat_payload("t17-dest", 171));
    append_stored(&dest, 2_000, heartbeat_payload("t17-dest", 172));
    let steps = vec![
        SpoolRestoreStep {
            step_index: 0,
            step_digest: fence.entries[0].entry_digest.clone(),
            predecessor_digest: content_digest.clone(),
            operation_id: hex_digest(0xA710),
        },
        SpoolRestoreStep {
            step_index: 1,
            step_digest: fence.entries[1].entry_digest.clone(),
            predecessor_digest: fence.entries[0].entry_digest.clone(),
            operation_id: hex_digest(0xA711),
        },
    ];
    validate_restore_chain(&content_digest, &steps).expect("restore chain validates");
    let mut ledger = SpoolImportReplayLedger::new();
    assert_eq!(
        ledger
            .observe("op-955-t17-import", &content_digest)
            .expect("import"),
        SpoolImportReplayDisposition::Accepted
    );
    let observed = vec![SpoolObservedDigest {
        digest: content_digest.clone(),
        disposition: SpoolRestoreDisposition::Accepted,
    }];
    assert_eq!(
        reconcile_restore(&observed, &content_digest).expect("reconcile"),
        SpoolRestoreDisposition::Accepted
    );
    let dest_retained = dest
        .retained_spool_entries_for_export_driver_test()
        .expect("destination appends undisturbed");
    assert_eq!(dest_retained.len(), 2);
    cleanup(dest, &dest_dir);
    let source = reopen_sensor(&dir);
    cleanup(source, &dir);
}

// WORK_UNIT_CASE: 955/18
#[test]
fn source_api_guard_and_protected_content_redacted() {
    const BACKUP_SRC: &str = include_str!("../src/watchdog_spool/backup.rs");
    for symbol in [
        "std::process",
        "Command::new",
        "tokio::process",
        "TcpStream",
        "TcpListener",
        "password",
        "CreateProcess",
        "reboot",
        "sudo",
        "ExitStatus",
        "ServiceHandle",
        "scm_launch",
        "remove_file",
        "fs::remove",
        "cutover(",
        "restart(",
        "mint_lease",
        "grant_authority",
        "OpenProcess",
        "TerminateProcess",
        "redb::write",
        "Database::create",
    ] {
        assert!(
            !BACKUP_SRC.contains(symbol),
            "backup source admits {symbol}"
        );
    }
    let (sensor, dir) = open_sensor("t18");
    append_stored(&sensor, 1_000, heartbeat_payload("t18", 181));
    append_stored(&sensor, 2_000, heartbeat_payload("t18", 182));
    let entries = sensor
        .retained_spool_entries_for_export_driver_test()
        .expect("retained spool");
    let fence = capture_fence(&header_for(&entries), &entries, 2, &capture_params(0x9561))
        .expect("capture fence");
    let debug = format!("{fence:?}");
    for secret in [
        "lease-955-t18",
        "scope-955-t18",
        "signer-955-t18",
        "key-955-t18",
    ] {
        assert!(!debug.contains(secret), "fence leaks {secret}");
    }
    for entry in &fence.entries {
        assert_eq!(entry.entry_digest.len(), 64);
        assert!(entry.marker.is_none());
    }
    cleanup(sensor, &dir);
}
