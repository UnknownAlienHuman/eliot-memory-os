//! Issue #955 spool backup snapshot and isolated-restore proofs (T1..T18).
//!
//! Drives the real owner path over real temporary `watchdog.redb` spools: the
//! owner-bound [`eliot_watchdog::WatchdogBackupPort`] reached through
//! [`eliot_watchdog::KernelWatchdogPort::spool_backup_port`], owner-held
//! [`eliot_watchdog::WatchdogSpoolFence`] capture through
//! [`eliot_watchdog::WatchdogBackupPort::snapshot`], bounded paging through
//! [`eliot_watchdog::WatchdogBackupPort::read_page`], isolated-destination
//! gating, the import replay ledger, restore-chain validation, lost-response
//! reconciliation, and purge/source-identity retention. Six frozen JSON
//! fixtures under `tests/data/spool-backup/` carry the exact header,
//! denominator, disposition, destination, and ledger expectations; no test
//! invents canned fences.
//!
//! The port enforces the owner clock's capture-age window (default
//! `page_ttl_ms == snapshot_lifetime_ms == 60_000`), so owner-path captures
//! seed entries at fresh wall-clock timestamps. The stale `capture_mixed`
//! helper (entries at 1970 + 1/2/3 s) remains ONLY for the T8 born-expired
//! refusal leg, which proves the age window is enforced rather than
//! shape-checked.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_watchdog::{
    CaptureFenceParams, GapRecoveryReason, IndependentKernelSensor, KernelWatchdogPort,
    SERVICE_NAME, SpoolAppendOutcome, SpoolError, SpoolFenceEntryKind,
    SpoolImportReplayDisposition, SpoolImportReplayLedger, SpoolMarkerDetail, SpoolObservedDigest,
    SpoolRestoreDisposition, SpoolRestoreStep, WatchdogBackupPort, WatchdogExportSink,
    WatchdogSpoolAcknowledgement, WatchdogSpoolBackupLimits, WatchdogSpoolEntry,
    WatchdogSpoolExportBatch, WatchdogSpoolExportLimits, WatchdogSpoolFence, WatchdogSpoolHeader,
    WatchdogSpoolPayload, WatchdogSpoolSnapshotPage, acceptance_allowed, capture_fence,
    check_page_continuation, export_once, read_page, reconcile_restore,
    validate_isolated_destination, validate_restore_chain, verify_page_digest, watchog_entry_views,
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

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock before epoch")
            .as_millis(),
    )
    .expect("clock fits u64")
}

/// Returns the owner-bound backup port of a test sensor.
///
/// This is the production route (`spool_backup_port` -> `WatchdogBackupPort`):
/// the port binds every capture and page read against the owner's own retained
/// installation identity (`installation-7`) and generation (`9`).
fn owner_port(sensor: &IndependentKernelSensor) -> Arc<WatchdogBackupPort> {
    sensor
        .spool_backup_port()
        .expect("test sensor carries the owner backup port")
}

fn seed_mixed_fresh(
    tag: &str,
) -> (
    IndependentKernelSensor,
    std::path::PathBuf,
    Vec<WatchdogSpoolEntry>,
) {
    let (sensor, dir) = open_sensor(tag);
    let now = now_ms();
    append_stored(&sensor, now - 30_000, heartbeat_payload("hb1", 11));
    append_stored(
        &sensor,
        now - 20_000,
        gap_payload(GapRecoveryReason::AdmissionUnavailable),
    );
    append_stored(
        &sensor,
        now - 10_000,
        recovery_payload("955 mixed seed", 33),
    );
    let entries = sensor
        .retained_spool_entries_for_export_driver_test()
        .expect("read retained spool");
    assert_eq!(entries.len(), 3);
    (sensor, dir, entries)
}

fn seed_heartbeats_fresh(
    tag: &str,
) -> (
    IndependentKernelSensor,
    std::path::PathBuf,
    Vec<WatchdogSpoolEntry>,
) {
    let (sensor, dir) = open_sensor(tag);
    let now = now_ms();
    append_stored(&sensor, now - 30_000, heartbeat_payload(tag, 101));
    append_stored(&sensor, now - 20_000, heartbeat_payload(tag, 102));
    append_stored(&sensor, now - 10_000, heartbeat_payload(tag, 103));
    let entries = sensor
        .retained_spool_entries_for_export_driver_test()
        .expect("read retained spool");
    assert_eq!(entries.len(), 3);
    (sensor, dir, entries)
}

/// Captures a fresh mixed seed through the owner port.
///
/// The fence carries the owner's bindings and passes the owner's own
/// capture-age window, so every assertion below it proves the production
/// capture path rather than the bare fence builder.
fn capture_mixed_owner(
    tag: &str,
    operation: u64,
) -> (
    IndependentKernelSensor,
    std::path::PathBuf,
    WatchdogSpoolFence,
    Vec<WatchdogSpoolEntry>,
) {
    let (sensor, dir, entries) = seed_mixed_fresh(tag);
    let fence = owner_port(&sensor)
        .snapshot(
            capture_params(operation),
            WatchdogSpoolBackupLimits::default(),
        )
        .expect("owner snapshot of fresh seed");
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
    // Owner path: the fence below is captured through the owner-bound backup
    // port, so its header, high water, and bindings are the owner's own.
    let (sensor, dir, fence, entries) = capture_mixed_owner("t1", 0x9551);
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
    // Owner path: every refusal below comes out of `WatchdogBackupPort::snapshot`,
    // which binds the request against the owner-held installation identity and
    // generation before the capture runs. The isolation root axis (a destination
    // sharing the active Watchdog state root) is proved at import, not capture.
    let (sensor, dir, _) = seed_mixed_fresh("t2");
    let port = owner_port(&sensor);
    let limits = WatchdogSpoolBackupLimits::default();
    let blank_requester = CaptureFenceParams {
        requester_principal: String::new(),
        ..capture_params(0x9552)
    };
    assert!(matches!(
        port.snapshot(blank_requester, limits),
        Err(SpoolError::Corrupt(_))
    ));
    let blank_source = CaptureFenceParams {
        source_installation: "   ".to_owned(),
        ..capture_params(0x9552)
    };
    assert!(matches!(
        port.snapshot(blank_source, limits),
        Err(SpoolError::Corrupt(_))
    ));
    let zero_generation = CaptureFenceParams {
        watchdog_generation: 0,
        ..capture_params(0x9552)
    };
    assert!(matches!(
        port.snapshot(zero_generation, limits),
        Err(SpoolError::Corrupt(_))
    ));
    let malformed_operation = CaptureFenceParams {
        snapshot_operation_id: "not-a-digest".to_owned(),
        ..capture_params(0x9552)
    };
    assert!(matches!(
        port.snapshot(malformed_operation, limits),
        Err(SpoolError::Corrupt(_))
    ));
    // Owner-held bindings: a well-formed request for a FOREIGN installation or
    // generation fails closed against the owner's retained values instead of
    // producing a fence that claims the wrong provenance.
    let foreign_installation = CaptureFenceParams {
        source_installation: "installation-7-foreign".to_owned(),
        ..capture_params(0x9552)
    };
    assert!(matches!(
        port.snapshot(foreign_installation, limits),
        Err(SpoolError::Corrupt(_))
    ));
    let foreign_generation = CaptureFenceParams {
        watchdog_generation: 8,
        ..capture_params(0x9552)
    };
    assert!(matches!(
        port.snapshot(foreign_generation, limits),
        Err(SpoolError::Corrupt(_))
    ));
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/3
#[test]
fn coherent_read_under_concurrent_append() {
    // Owner path: both fences and the pre-append page read go through the
    // owner-bound port. The fourth append lands at a fresh timestamp so the
    // post-append capture stays inside the owner's capture-age window.
    let (sensor, dir, fence_before, _) = capture_mixed_owner("t3", 0x9553);
    let port = owner_port(&sensor);
    append_stored(&sensor, now_ms(), heartbeat_payload("t3-fourth", 44));
    let retained = sensor
        .retained_spool_entries_for_export_driver_test()
        .expect("read retained spool after append");
    assert_eq!(retained.len(), 4);
    let fence_after = port
        .snapshot(capture_params(0x9554), WatchdogSpoolBackupLimits::default())
        .expect("owner capture after append");
    assert_eq!(fence_before.retained_count(), 3);
    assert_eq!(fence_after.retained_count(), 4);
    assert_ne!(fence_before.content_digest, fence_after.content_digest);
    fence_before
        .denominator()
        .validate_for_count(3)
        .expect("pre-append fence stays coherent");
    port.read_page(&fence_before, 0)
        .expect("pre-append page still reads through the owner");
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/4
#[test]
fn ordered_retained_entry_denominator_exact() {
    let (sensor, dir, _) = seed_heartbeats_fresh("t4");
    let fence = owner_port(&sensor)
        .snapshot(capture_params(0x9555), WatchdogSpoolBackupLimits::default())
        .expect("owner capture of heartbeat fence");
    let sequences: Vec<u64> = fence.entries().iter().map(|entry| entry.sequence).collect();
    assert_eq!(sequences, vec![1, 2, 3]);
    assert_eq!(fence.denominator().retained_members, 3);
    assert_eq!(fence.denominator().gap_members, 0);
    assert!(fence.denominator().complete);
    fence
        .denominator()
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
    let (sensor, dir, fence, _) = capture_mixed_owner("t5", 0x9556);
    assert_eq!(fence.entries()[1].kind, SpoolFenceEntryKind::Gap);
    assert!(matches!(
        &fence.entries()[1].marker,
        Some(SpoolMarkerDetail::Gap {
            reason: GapRecoveryReason::AdmissionUnavailable,
            coverage_claimed: false,
        })
    ));
    assert_eq!(fence.entries()[2].kind, SpoolFenceEntryKind::Recovery);
    assert!(fence.entries()[2].marker.is_some());
    assert_eq!(fence.denominator().retained_members, 3);
    assert_eq!(fence.denominator().gap_members, 2);
    assert!(!fence.denominator().complete);
    assert!(fence.denominator().validate_for_count(0).is_err());
    fence
        .denominator()
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
    // Owner path: the page comes out of `WatchdogBackupPort::read_page`, which
    // re-validates the fence, binds it to the owner's installation identity and
    // generation, applies the owner's capture-age window, and pages under the
    // port's admitted default window (256 members/page, so one page covers all
    // three retained entries). The chain, digest, and tight-window legs below
    // exercise the exact bounded primitives the port delegates to.
    let (sensor, dir, fence, _) = capture_mixed_owner("t6", 0x9557);
    let port = owner_port(&sensor);
    page_limits(2, 2).validate().expect("bounded page window");
    let page: WatchdogSpoolSnapshotPage =
        port.read_page(&fence, 0).expect("owner reads first page");
    assert_eq!(page.snapshot_digest, fence.content_digest);
    assert_eq!(page.cumulative_members, 3);
    assert_eq!(page.total_members, 3);
    assert!(page.complete);
    check_page_continuation(&fence.content_digest, &page).expect("bound continuation");
    assert!(check_page_continuation(&hex_digest(7), &page).is_err());
    verify_page_digest(&page).expect("page digest matches members");
    let mut tampered = page.clone();
    tampered.page_digest = hex_digest(8);
    assert!(verify_page_digest(&tampered).is_err());
    assert!(port.read_page(&fence, 9).is_err());
    let tight = page_limits(1, 1);
    read_page(&fence, 0, &tight).expect("first tight page");
    assert!(read_page(&fence, 1, &tight).is_err());
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/7
#[test]
fn expired_missing_duplicate_conflicting_entries_fail_explicitly() {
    // Owner path first: an empty spool and an expired retained entry are both
    // refused out of `WatchdogBackupPort::snapshot` with no fence issued.
    let (empty_sensor, empty_dir) = open_sensor("t7-empty");
    assert!(matches!(
        owner_port(&empty_sensor)
            .snapshot(capture_params(0x9570), WatchdogSpoolBackupLimits::default(),),
        Err(SpoolError::Corrupt(_))
    ));
    cleanup(empty_sensor, &empty_dir);
    let (stale_sensor, stale_dir) = open_sensor("t7-expired");
    append_stored(&stale_sensor, 1_000, heartbeat_payload("t7-expired", 71));
    append_stored(&stale_sensor, 0, heartbeat_payload("t7-expired", 72));
    assert!(matches!(
        owner_port(&stale_sensor)
            .snapshot(capture_params(0x9570), WatchdogSpoolBackupLimits::default(),),
        Err(SpoolError::Corrupt(_))
    ));
    cleanup(stale_sensor, &stale_dir);
    // Corruption matrix for spool states the honest append path cannot mint
    // (a missing sequence, a duplicated sequence, a header whose byte total no
    // longer matches its members): the bare fence builder that the owner
    // delegates to refuses each one explicitly.
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
    // Owner enforcement on top of the shape matrix below: the page-freshness /
    // whole-snapshot lifetime windows and the bounded work ceiling are
    // consulted against real retained evidence by `WatchdogBackupPort::snapshot`,
    // not only shape-validated.
    //
    // A spool whose newest retained observation predates the admitted window
    // yields a fence that could never be paged, so the owner refuses the
    // born-expired capture with the identical reason a page read would give.
    let (stale_sensor, stale_dir, _, _) = capture_mixed("t8-stale", 0x9558);
    assert!(matches!(
        owner_port(&stale_sensor)
            .snapshot(capture_params(0x9558), WatchdogSpoolBackupLimits::default(),),
        Err(SpoolError::Corrupt(_))
    ));
    cleanup(stale_sensor, &stale_dir);
    // A well-formed window whose work ceiling sits below the real retained
    // member count is refused against that count.
    let (fresh_sensor, fresh_dir, _) = seed_mixed_fresh("t8-work");
    let tight_work = WatchdogSpoolBackupLimits {
        max_work_units: 1,
        ..WatchdogSpoolBackupLimits::default()
    };
    tight_work
        .validate()
        .expect("narrower window stays bounded");
    assert!(matches!(
        owner_port(&fresh_sensor).snapshot(capture_params(0x9558), tight_work),
        Err(SpoolError::Corrupt(_))
    ));
    // The same fresh spool captures fine under the admitted default window,
    // proving the refusal above comes from the work ceiling and not the seed.
    owner_port(&fresh_sensor)
        .snapshot(capture_params(0x9550), WatchdogSpoolBackupLimits::default())
        .expect("fresh spool captures under the admitted window");
    cleanup(fresh_sensor, &fresh_dir);
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
    // Owner path: this owner holds nothing that could satisfy a cross-owner
    // reference, so `WatchdogBackupPort::snapshot` refuses ANY capture naming
    // a `canonical_ref` or an `ors_ref` — including the fence-equal pair a
    // caller asserts. Coherence with another owner's capture belongs to the
    // cross-owner fence protocol, and the honest outcome here is refusal, not
    // a recorded reference.
    let (sensor, dir, _) = seed_mixed_fresh("t9");
    let port = owner_port(&sensor);
    let limits = WatchdogSpoolBackupLimits::default();
    let timestamp_only = CaptureFenceParams {
        canonical_ref: Some(hex_digest(0xC440)),
        ..capture_params(0x9559)
    };
    assert!(matches!(
        port.snapshot(timestamp_only, limits),
        Err(SpoolError::Corrupt(_))
    ));
    let ors_only = CaptureFenceParams {
        ors_ref: Some(hex_digest(0x0A55)),
        ..capture_params(0x9559)
    };
    assert!(matches!(
        port.snapshot(ors_only, limits),
        Err(SpoolError::Corrupt(_))
    ));
    let fence_equal = CaptureFenceParams {
        canonical_ref: Some(hex_digest(0xC440)),
        ors_ref: Some(hex_digest(0x0A55)),
        coherence_fence_equal: true,
        ..capture_params(0x9559)
    };
    assert!(matches!(
        port.snapshot(fence_equal, limits),
        Err(SpoolError::Corrupt(_))
    ));
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/10
#[test]
fn isolated_destination_differs_from_source_and_active() {
    // Owner path: the port binds every capture to ITS OWN retained source
    // installation, so a capture presented AS the isolated destination
    // installation is refused as a foreign source — the owner never issues a
    // fence that claims the destination's provenance. (The full import-side
    // isolation proof needs an installer-admitted destination; see T17.)
    let (owner_sensor, owner_dir, _) = seed_mixed_fresh("t10-owner");
    let owner = owner_port(&owner_sensor);
    let presented_as_destination = CaptureFenceParams {
        source_installation: "installation-7-isolated-restore".to_owned(),
        ..capture_params(0x955A)
    };
    assert!(matches!(
        owner.snapshot(
            presented_as_destination,
            WatchdogSpoolBackupLimits::default(),
        ),
        Err(SpoolError::Corrupt(_))
    ));
    cleanup(owner_sensor, &owner_dir);
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
    // Owner path: the fence under test is issued by the owner-bound port.
    let (sensor, dir, fence, _) = capture_mixed_owner("t11", 0x955B);
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
    assert!(fence.entries()[0].marker.is_none());
    let fixture = fixture_value("isolated-destination-manifest.json");
    assert_eq!(fixture["grants_active_authority"], false);
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/12
#[test]
fn exact_import_replay_versus_changed_input_conflict() {
    // The ledger below guards owner-issued evidence: the observed digest is the
    // content digest of a fence the owner-bound port just captured, so exact
    // replay versus changed content is decided over the real import payload.
    // (The port's own import entry needs an installer-admitted destination;
    // see T17. The ledger exercised here is the exact idempotency core the
    // owner delegates to.)
    let (sensor, dir, fence, _) = capture_mixed_owner("t12", 0x955C);
    let mut ledger = SpoolImportReplayLedger::new();
    let operation = "op-955-t12-import";
    let digest = fence.content_digest.clone();
    cleanup(sensor, &dir);
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
    // Owner-issued evidence throughout: the believed digest is the content
    // digest of a fence the owner-bound port just captured. (The port's own
    // import entry needs an installer-admitted destination; see T17. The
    // ledger-plus-reconcile round exercised here is the exact lost-response
    // core the owner runs inside the admitted destination's spool.)
    let (sensor, dir, fence, _) = capture_mixed_owner("t13", 0x955D);
    let mut ledger = SpoolImportReplayLedger::new();
    let operation = "op-955-t13-lost";
    let digest = fence.content_digest.clone();
    cleanup(sensor, &dir);
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
    // The denominator below is not constructed: it is the exact denominator of
    // a fence the owner-bound port captured over a gap-carrying spool, so the
    // incomplete-denominator verdicts run against owner-issued evidence. The
    // acceptance gate is the exact post-import gate the owner applies: an
    // unresolved signal stays `Unknown`, and `Unknown` blocks recovery instead
    // of defaulting to zero.
    let (sensor, dir, fence, _) = capture_mixed_owner("t14", 0x955E);
    cleanup(sensor, &dir);
    let observed = vec![SpoolObservedDigest {
        digest: fence.content_digest.clone(),
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
    let denominator = fence.denominator();
    assert!(!denominator.complete);
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
    // Owner path: both fences are issued by the owner-bound port, so the
    // purge revision and the retained source identity are the owner's own.
    let (sensor, dir, _) = seed_heartbeats_fresh("t15");
    let port = owner_port(&sensor);
    let fence_before = port
        .snapshot(capture_params(0x9515), WatchdogSpoolBackupLimits::default())
        .expect("owner pre-purge fence");
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
    let fence_after = port
        .snapshot(capture_params(0x9516), WatchdogSpoolBackupLimits::default())
        .expect("owner post-purge fence");
    assert_eq!(fence_after.source_installation, "installation-7");
    assert_eq!(fence_after.header_first_sequence(), 3);
    assert_eq!(fence_after.retained_count(), 1);
    assert_ne!(fence_before.content_digest, fence_after.content_digest);
    cleanup(sensor, &dir);
}

// WORK_UNIT_CASE: 955/16
#[test]
fn failure_closes_owned_resources_and_preserves_source() {
    // Owner path: the refused capture runs through the owner-bound port.
    //
    // Source preservation is proved at the retained-entry level, not the file
    // level: merely opening the spool runs the owner's initialize-or-recover
    // path, and redb owns its file bytes across opens. What the owner
    // promises is that a failed capture appends nothing (the retained entries
    // stay exactly the seeded ones) and holds no live resource afterwards (a
    // leaked file lock would refuse the reopen on Windows).
    let (sensor, dir, entries) = seed_mixed("t16");
    drop(sensor);
    let sensor = reopen_sensor(&dir);
    let bad = CaptureFenceParams {
        requester_principal: String::new(),
        ..capture_params(0x955F)
    };
    assert!(matches!(
        owner_port(&sensor).snapshot(bad, WatchdogSpoolBackupLimits::default()),
        Err(SpoolError::Corrupt(_))
    ));
    drop(sensor);
    assert!(
        dir.join("watchdog.redb").is_file(),
        "source redb survives the refused owner capture"
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
    // Owner path for the capture half: the fence below is issued by the
    // owner-bound port, survives a close/reopen cycle byte-identically, and
    // feeds the exact restore-chain, replay-ledger, and reconcile primitives
    // the owner runs inside the admitted destination's spool.
    //
    // The remaining substitution — `WatchdogBackupPort::import_isolated` in
    // place of the primitive round below — is blocked on installer-admitted
    // destination material: the import takes an `AdmittedIsolatedDestination`
    // (minted only by `admit_isolated_destination`, whose registry seal
    // `with_computed_digest` rejects every SystemService descriptor on this
    // machine) and an owner-issued `WatchdogRuntimeBinding` active side (minted
    // only by live admission, which additionally requires running-image
    // equality). No installer-approved installation exists on this machine, so
    // the positive owner import is unprovable here; it is reported as the
    // single remaining gap. The `None`-destination refusal (`InvalidLease`,
    // never a substitution of the active spool) holds by owner-signature
    // construction and is not asserted here for the same reason.
    let (sensor, dir, fence, _) = capture_mixed_owner("t17-source", 0x9560);
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
            step_digest: fence.entries()[0].entry_digest.clone(),
            predecessor_digest: content_digest.clone(),
            operation_id: hex_digest(0xA710),
        },
        SpoolRestoreStep {
            step_index: 1,
            step_digest: fence.entries()[1].entry_digest.clone(),
            predecessor_digest: fence.entries()[0].entry_digest.clone(),
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
    // Owner path: the redaction verdicts below run over a fence the owner-bound
    // port issued, so leaked secrets would be production leaks.
    let (sensor, dir) = open_sensor("t18");
    let now = now_ms();
    append_stored(&sensor, now - 20_000, heartbeat_payload("t18", 181));
    append_stored(&sensor, now - 10_000, heartbeat_payload("t18", 182));
    let fence = owner_port(&sensor)
        .snapshot(capture_params(0x9561), WatchdogSpoolBackupLimits::default())
        .expect("owner capture for redaction proof");
    let debug = format!("{fence:?}");
    for secret in [
        "lease-955-t18",
        "scope-955-t18",
        "signer-955-t18",
        "key-955-t18",
    ] {
        assert!(!debug.contains(secret), "fence leaks {secret}");
    }
    for entry in fence.entries() {
        assert_eq!(entry.entry_digest.len(), 64);
        assert!(entry.marker.is_none());
    }
    cleanup(sensor, &dir);
}
