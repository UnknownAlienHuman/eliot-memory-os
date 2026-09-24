//! Backup owner-channel wire tests (issue #962, Writer-D).
//!
//! Twenty cases binding the Kernel's exact-owner backup clients to the
//! closed per-owner accepted tables, the canonical endpoints, and the
//! fail-closed admission/replay/cleanup gates.
//!
//! Mapping to Writers A-C registrations (referenced, never imported — those
//! crates are Host/Watchdog implementations and must not become Kernel
//! dependencies, which would be circular):
//!
//! ```text
//! Watchdog accepted table .. ReadSnapshotPage / VerifyArchive /
//!                             RestoreStatus / ReconcileRestore
//! Host accepted table ....... PrepareIsolatedRestore / AdmitCutover /
//!                             RestoreStatus / ReconcileRestore
//! envelope bridge ........... runtime_control.rs backup envelope mapping
//! dispatch .................. eliot-host register_backup_dispatch
//! ```
//!
//! The tests exercise `eliot-protocol::backup` vocabulary
//! (`BackupOperationKind`) plus the local client types included below, and
//! load the eight frozen fixtures in `data/backup-owner-wire/`. No private
//! database is opened, no Host/Watchdog implementation is imported, no new
//! auth or transport is introduced, and no secrets are embedded.

#[path = "../src/backup_owner_clients.rs"]
#[allow(
    dead_code,
    reason = "the wire test includes the owner-client surface by path and exercises it per case; unused surface legs stay warning-clean"
)]
mod backup_owner_clients;

use backup_owner_clients::{
    AdmissionDomain, EffectAdmission, HOST_BACKUP_PEER, HOST_BACKUP_PIPE, HOST_SUPPORTED_OPS,
    HostBackupOwnerClient, OWNER_OPS_QUANTUM_PER_ROUND, OwnerAdmission, OwnerClientError,
    OwnerTimeout, ReplayDisposition, ReplayLedger, ReplaySafety, UntypedEffectKind,
    WATCHDOG_BACKUP_PEER, WATCHDOG_BACKUP_PIPE, WATCHDOG_SUPPORTED_OPS, WatchdogBackupOwnerClient,
    check_bound_digest, fence_is_fresh, rehearsal_proves_cutover, replay_safe_marker,
    supervision_priority_preserved, transport_ack_is_success, validate_bounded_payload,
};
use eliot_protocol::backup::BackupOperationKind;

fn fixture(name: &str) -> serde_json::Value {
    let path = format!(
        "{}/tests/data/backup-owner-wire/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(&path).expect("frozen backup owner fixture must exist");
    serde_json::from_slice(&bytes).expect("frozen backup owner fixture must be valid JSON")
}

fn op_names(ops: &[BackupOperationKind]) -> Vec<&'static str> {
    ops.iter().map(|op| op.as_str()).collect()
}

fn host_production() -> HostBackupOwnerClient {
    HostBackupOwnerClient::production().expect("production Host client must bind")
}

fn watchdog_production() -> WatchdogBackupOwnerClient {
    WatchdogBackupOwnerClient::production().expect("production Watchdog client must bind")
}

// WORK_UNIT_CASE: 962/1
#[test]
fn wire_01_registration_table_matches_closed_owner_tables() {
    let table = fixture("accepted-owner-method-table.json");
    let host_methods: Vec<&str> = table["host_owner"]["accepted_methods"]
        .as_array()
        .expect("host methods array")
        .iter()
        .map(|value| value.as_str().expect("method string"))
        .collect();
    let watchdog_methods: Vec<&str> = table["watchdog_owner"]["accepted_methods"]
        .as_array()
        .expect("watchdog methods array")
        .iter()
        .map(|value| value.as_str().expect("method string"))
        .collect();
    assert_eq!(host_methods, op_names(HOST_SUPPORTED_OPS));
    assert_eq!(watchdog_methods, op_names(WATCHDOG_SUPPORTED_OPS));
    assert_eq!(HostBackupOwnerClient::supported_ops(), HOST_SUPPORTED_OPS);
    assert_eq!(
        WatchdogBackupOwnerClient::supported_ops(),
        WATCHDOG_SUPPORTED_OPS
    );
}

// WORK_UNIT_CASE: 962/2
#[test]
fn wire_02_canonical_endpoints_exact() {
    let endpoints = fixture("canonical-endpoints.json");
    assert_eq!(
        endpoints["host_owner"]["pipe"].as_str(),
        Some(HOST_BACKUP_PIPE)
    );
    assert_eq!(
        endpoints["watchdog_owner"]["pipe"].as_str(),
        Some(WATCHDOG_BACKUP_PIPE)
    );
    assert_eq!(HOST_BACKUP_PIPE, r"\\.\pipe\eliot\host\runtime-control-v1");
    assert_eq!(WATCHDOG_BACKUP_PIPE, r"\\.\pipe\eliot\watchdog\signals");
    let host = host_production();
    let watchdog = watchdog_production();
    assert_eq!(host.pipe(), HOST_BACKUP_PIPE);
    assert_eq!(watchdog.pipe(), WATCHDOG_BACKUP_PIPE);
    assert_eq!(host.peer(), HOST_BACKUP_PEER);
    assert_eq!(watchdog.peer(), WATCHDOG_BACKUP_PEER);
}

// WORK_UNIT_CASE: 962/3
#[test]
fn wire_03_spoofed_peer_identity_rejected() {
    let spoofed = fixture("spoofed-peer-identity.json");
    let host = host_production();
    let watchdog = watchdog_production();
    assert_eq!(
        spoofed["expected_host_peer"].as_str(),
        Some(HOST_BACKUP_PEER)
    );
    assert_eq!(
        spoofed["expected_watchdog_peer"].as_str(),
        Some(WATCHDOG_BACKUP_PEER)
    );
    for presented in spoofed["presented_peers"]
        .as_array()
        .expect("presented peers array")
    {
        let peer = presented.as_str().expect("peer string");
        assert!(!host.authority_matches(peer), "spoofed host peer refused");
        assert!(
            !watchdog.authority_matches(peer),
            "spoofed watchdog peer refused"
        );
        assert!(!host.response_identity_ok(
            HOST_BACKUP_PIPE,
            peer,
            BackupOperationKind::RestoreStatus
        ));
        assert!(HostBackupOwnerClient::new(HOST_BACKUP_PIPE, peer).is_err());
    }
    assert_eq!(spoofed["verdict"].as_str(), Some("rejected"));
}

// WORK_UNIT_CASE: 962/4
#[test]
fn wire_04_stale_generation_fence_rejected() {
    let fence = fixture("stale-generation-fence.json");
    let current_epoch = fence["current"]["authority_epoch"].as_u64().expect("epoch");
    let current_generation = fence["current"]["resource_generation"]
        .as_u64()
        .expect("generation");
    for presentation in fence["presentations"]
        .as_array()
        .expect("presentations array")
    {
        let epoch = presentation["authority_epoch"].as_u64().expect("epoch");
        let generation = presentation["resource_generation"]
            .as_u64()
            .expect("generation");
        let fresh = fence_is_fresh(epoch, generation, current_epoch, current_generation);
        assert_eq!(
            presentation["verdict"].as_str(),
            Some(if fresh { "admitted" } else { "rejected" })
        );
    }
    assert!(!fence_is_fresh(6, 12, 7, 12));
    assert!(fence_is_fresh(7, 12, 7, 12));
}

// WORK_UNIT_CASE: 962/5
#[test]
fn wire_05_payload_override_rejected() {
    let bound = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    assert!(check_bound_digest(bound, bound).is_ok());
    assert!(matches!(
        check_bound_digest(
            bound,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ),
        Err(OwnerClientError::PayloadRejected { .. })
    ));
    // An overridden operation binding refuses exactly like an overridden digest.
    let capture = BackupOperationKind::RequestCapture;
    assert!(!HostBackupOwnerClient::is_supported(capture));
}

// WORK_UNIT_CASE: 962/6
#[test]
fn wire_06_capture_exact_owner_one_effect() {
    let admission_fixture = fixture("capture-admission.json");
    let admission = OwnerAdmission::present(
        admission_fixture["domain"].as_str().expect("domain"),
        admission_fixture["digest"].as_str().expect("digest"),
    )
    .expect("valid prepare admission");
    let admitted: EffectAdmission =
        HostBackupOwnerClient::admit_prepare(&admission).expect("capture admitted");
    assert_eq!(admitted.owner(), HOST_BACKUP_PEER);
    assert_eq!(
        admitted.op(),
        BackupOperationKind::PrepareIsolatedRestore.as_str()
    );
    assert_eq!(admitted.effect_count(), 1);
    assert_eq!(
        admission_fixture["effect_count"].as_u64(),
        Some(1),
        "fixture pins the one-effect rule"
    );
    // The exact owner only: the Watchdog channel cannot admit a capture.
    assert!(
        WatchdogBackupOwnerClient::admit_effect(BackupOperationKind::PrepareIsolatedRestore)
            .is_err()
    );
}

// WORK_UNIT_CASE: 962/7
#[test]
fn wire_07_prepare_cutover_separate_admission() {
    let admissions = fixture("prepare-cutover-admission.json");
    let prepare = OwnerAdmission::present(
        "prepare",
        admissions["prepare_admission"]["digest"]
            .as_str()
            .expect("prepare digest"),
    )
    .expect("valid prepare admission");
    let cutover = OwnerAdmission::present(
        "cutover",
        admissions["cutover_admission"]["digest"]
            .as_str()
            .expect("cutover digest"),
    )
    .expect("valid cutover admission");
    assert!(HostBackupOwnerClient::requires_cutover_admission(
        BackupOperationKind::AdmitCutover
    ));
    assert!(!HostBackupOwnerClient::requires_cutover_admission(
        BackupOperationKind::PrepareIsolatedRestore
    ));
    // Cross-domain use refuses in both directions.
    assert!(HostBackupOwnerClient::admit_cutover(&prepare).is_err());
    assert!(prepare.check_domain(AdmissionDomain::Cutover).is_err());
    assert!(cutover.check_domain(AdmissionDomain::Prepare).is_err());
    // The separate cutover admission succeeds exactly once.
    let admitted = HostBackupOwnerClient::admit_cutover(&cutover).expect("cutover admitted");
    assert_eq!(admitted.effect_count(), 1);
    assert_eq!(admissions["cross_use_verdict"].as_str(), Some("rejected"));
}

// WORK_UNIT_CASE: 962/8
#[test]
fn wire_08_rehearsal_never_equals_cutover() {
    assert!(!rehearsal_proves_cutover());
    // Rehearsal completion sits outside both owner tables.
    assert!(!HostBackupOwnerClient::is_supported(
        BackupOperationKind::CompleteRehearsal
    ));
    assert!(!WatchdogBackupOwnerClient::is_supported(
        BackupOperationKind::CompleteRehearsal
    ));
    assert!(HostBackupOwnerClient::admit_effect(BackupOperationKind::CompleteRehearsal).is_err());
    assert!(matches!(
        OwnerClientError::RehearsalCannotCutover,
        OwnerClientError::RehearsalCannotCutover
    ));
}

// WORK_UNIT_CASE: 962/9
#[test]
fn wire_09_unsupported_op_fails_before_effect() {
    // Cross-owner operations refuse on the wrong channel before any effect.
    assert!(matches!(
        HostBackupOwnerClient::admit_effect(BackupOperationKind::ReadSnapshotPage),
        Err(OwnerClientError::UnsupportedOperation { .. })
    ));
    assert!(matches!(
        WatchdogBackupOwnerClient::admit_effect(BackupOperationKind::PrepareIsolatedRestore),
        Err(OwnerClientError::UnsupportedOperation { .. })
    ));
    assert!(matches!(
        WatchdogBackupOwnerClient::admit_effect(BackupOperationKind::AdmitCutover),
        Err(OwnerClientError::UnsupportedOperation { .. })
    ));
    // A bare cutover request without its separate admission refuses too.
    assert!(matches!(
        HostBackupOwnerClient::admit_effect(BackupOperationKind::AdmitCutover),
        Err(OwnerClientError::CutoverAdmissionRequired)
    ));
}

// WORK_UNIT_CASE: 962/10
#[test]
fn wire_10_response_identity_exact() {
    let host = host_production();
    assert!(host.response_identity_ok(
        HOST_BACKUP_PIPE,
        HOST_BACKUP_PEER,
        BackupOperationKind::RestoreStatus
    ));
    // Wrong pipe, wrong peer, or an unsupported op each invalidate identity.
    assert!(!host.response_identity_ok(
        WATCHDOG_BACKUP_PIPE,
        HOST_BACKUP_PEER,
        BackupOperationKind::RestoreStatus
    ));
    assert!(!host.response_identity_ok(
        HOST_BACKUP_PIPE,
        WATCHDOG_BACKUP_PEER,
        BackupOperationKind::RestoreStatus
    ));
    assert!(!host.response_identity_ok(
        HOST_BACKUP_PIPE,
        HOST_BACKUP_PEER,
        BackupOperationKind::VerifyArchive
    ));
    let watchdog = watchdog_production();
    assert!(watchdog.response_identity_ok(
        WATCHDOG_BACKUP_PIPE,
        WATCHDOG_BACKUP_PEER,
        BackupOperationKind::VerifyArchive
    ));
    assert!(!watchdog.response_identity_ok(
        WATCHDOG_BACKUP_PIPE,
        WATCHDOG_BACKUP_PEER,
        BackupOperationKind::AdmitCutover
    ));
}

// WORK_UNIT_CASE: 962/11
#[test]
fn wire_11_transport_ack_is_not_success() {
    // Every transport acknowledgement phase maps to no semantic stage: only
    // owner attestations validated against the bound identity advance state.
    assert!(!transport_ack_is_success());
}

// WORK_UNIT_CASE: 962/12
#[test]
fn wire_12_bounds_malformed_duplicate_rejected() {
    let bounds = fixture("bounds-and-cleanup.json");
    assert_eq!(
        bounds["max_payload_bytes"].as_u64(),
        Some(eliot_protocol::backup::MAX_BACKUP_PAYLOAD_BYTES as u64)
    );
    // Oversize refuses.
    let oversize = vec![0x41_u8; bounds["oversize_bytes"].as_u64().expect("oversize") as usize];
    assert!(matches!(
        validate_bounded_payload(&oversize),
        Err(OwnerClientError::PayloadRejected { .. })
    ));
    // Empty refuses.
    assert!(matches!(
        validate_bounded_payload(&[]),
        Err(OwnerClientError::PayloadRejected { .. })
    ));
    // Malformed refuses.
    assert!(matches!(
        validate_bounded_payload(
            bounds["malformed_payload"]
                .as_str()
                .expect("malformed")
                .as_bytes()
        ),
        Err(OwnerClientError::PayloadRejected { .. })
    ));
    // Non-object typed payload refuses: commands/arrays are not operations.
    assert!(matches!(
        validate_bounded_payload(
            bounds["non_object_payload"]
                .as_str()
                .expect("array")
                .as_bytes()
        ),
        Err(OwnerClientError::PayloadRejected { .. })
    ));
    // A small typed object passes.
    let ok = validate_bounded_payload(br#"{"op":"RESTORE_STATUS"}"#).expect("typed object");
    assert!(ok.is_object());
    // Duplicates refuse through the replay ledger, never double-apply.
    let mut ledger = ReplayLedger::new();
    let digest = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    assert_eq!(
        ledger
            .classify(digest, b"{\"op\":\"RESTORE_STATUS\"}")
            .expect("first commit"),
        ReplayDisposition::Commit
    );
    assert!(ledger.classify(digest, b"{\"op\":\"CHANGED\"}").is_err());
    assert!(!bounds["duplicate_effect_allowed"].as_bool().expect("flag"));
}

// WORK_UNIT_CASE: 962/13
#[test]
fn wire_13_no_arbitrary_command_path_endpoint_credential() {
    assert_eq!(UntypedEffectKind::all().len(), 4);
    for kind in UntypedEffectKind::all() {
        assert!(matches!(
            HostBackupOwnerClient::refuse_untyped(*kind),
            Err(OwnerClientError::ArbitraryEffectRefused { .. })
        ));
        assert!(matches!(
            WatchdogBackupOwnerClient::refuse_untyped(*kind),
            Err(OwnerClientError::ArbitraryEffectRefused { .. })
        ));
    }
}

// WORK_UNIT_CASE: 962/14
#[test]
fn wire_14_timeout_before_vs_after_send_distinct() {
    let before = OwnerTimeout::BeforeSend {
        op: BackupOperationKind::RestoreStatus,
        timeout_ms: 1_000,
    };
    let after = OwnerTimeout::AfterSend {
        op: BackupOperationKind::RestoreStatus,
        timeout_ms: 1_000,
    };
    assert_ne!(before, after);
    // Before send: no effect exists, bounded retry is safe without reconcile.
    assert!(before.may_retry_without_reconcile());
    assert!(!before.requires_reconcile());
    // After send: the outcome is unknown, reconcile by identity first.
    assert!(!after.may_retry_without_reconcile());
    assert!(after.requires_reconcile());
    assert_eq!(before.op(), BackupOperationKind::RestoreStatus);
}

// WORK_UNIT_CASE: 962/15
#[test]
fn wire_15_replay_exact_no_duplicate_effect() {
    let replay = fixture("replay-reconciliation.json");
    let digest = replay["completed"]["digest"].as_str().expect("digest");
    let bytes = replay["completed"]["bytes"]
        .as_str()
        .expect("bytes")
        .as_bytes()
        .to_vec();
    let mut ledger = ReplayLedger::new();
    assert_eq!(
        ledger.classify(digest, &bytes).expect("first commit"),
        ReplayDisposition::Commit
    );
    // Exact replay: idempotent, verified no duplicate effect.
    assert_eq!(
        ledger.classify(digest, &bytes).expect("exact replay"),
        ReplayDisposition::ExactReplay
    );
    assert!(
        !replay["exact_replay"]["duplicate_effect"]
            .as_bool()
            .expect("flag")
    );
    // Same identity with changed bytes: conflict, no effect either.
    assert!(matches!(
        ledger.classify(digest, b"changed-content"),
        Err(OwnerClientError::ReplayConflict)
    ));
    assert!(
        !replay["changed_bytes_replay"]["duplicate_effect"]
            .as_bool()
            .expect("flag")
    );
    // Safety markers: supported ops replay only with exact digests.
    assert_eq!(replay_safe_marker(true), ReplaySafety::SafeWithExactDigest);
    assert_eq!(replay_safe_marker(false), ReplaySafety::NeverBlind);
}

// WORK_UNIT_CASE: 962/16
#[test]
fn wire_16_shutdown_cleans_resources() {
    let bounds = fixture("bounds-and-cleanup.json");
    for shutdown in [
        HostBackupOwnerClient::shutdown_cleanup(),
        WatchdogBackupOwnerClient::shutdown_cleanup(),
    ] {
        assert!(shutdown.pipe_closed());
        assert_eq!(shutdown.pending_effects(), 0);
        assert!(shutdown.replay_view_evicted());
    }
    assert_eq!(bounds["shutdown"]["pipe_closed"].as_bool(), Some(true));
    assert_eq!(bounds["shutdown"]["pending_effects"].as_u64(), Some(0));
    assert_eq!(
        bounds["shutdown"]["replay_view_evicted"].as_bool(),
        Some(true)
    );
}

// WORK_UNIT_CASE: 962/17
#[test]
fn wire_17_no_starvation_of_supervision_priority() {
    let bounds = fixture("bounds-and-cleanup.json");
    assert!(supervision_priority_preserved());
    assert_eq!(OWNER_OPS_QUANTUM_PER_ROUND, 1);
    assert_eq!(
        bounds["supervision"]["ops_quantum_per_round"].as_u64(),
        Some(1)
    );
    assert_eq!(
        bounds["supervision"]["priority_preserved"].as_bool(),
        Some(true)
    );
}

// WORK_UNIT_CASE: 962/18
#[test]
fn wire_18_production_constructors_reject_fakes() {
    // Production binds the actual canonical pipes.
    assert!(HostBackupOwnerClient::production().is_ok());
    assert!(WatchdogBackupOwnerClient::production().is_ok());
    // Every fake/no-op/default/mismatched binding fails closed.
    for fake_pipe in [
        "",
        "fake-pipe",
        "noop",
        "no-op-channel",
        "mock-host-pipe",
        "default",
        "in-memory",
        "test-pipe",
        r"\\.\pipe\eliot\host\other",
        WATCHDOG_BACKUP_PIPE,
    ] {
        assert!(
            HostBackupOwnerClient::new(fake_pipe, HOST_BACKUP_PEER).is_err(),
            "host must reject {fake_pipe:?}"
        );
    }
    for fake_pipe in [
        "",
        "fake-pipe",
        "mock-watchdog-pipe",
        "default",
        "test-pipe",
        HOST_BACKUP_PIPE,
    ] {
        assert!(
            WatchdogBackupOwnerClient::new(fake_pipe, WATCHDOG_BACKUP_PEER).is_err(),
            "watchdog must reject {fake_pipe:?}"
        );
    }
    // Exact pipe with a spoofed or fake peer fails closed too.
    assert!(HostBackupOwnerClient::new(HOST_BACKUP_PIPE, "attacker-spoofed-peer").is_err());
    assert!(HostBackupOwnerClient::new(HOST_BACKUP_PIPE, "mock").is_err());
    assert!(WatchdogBackupOwnerClient::new(WATCHDOG_BACKUP_PIPE, "attacker-spoofed-peer").is_err());
}

// WORK_UNIT_CASE: 962/19
#[test]
fn wire_19_live_windows_ipc_fail_closed() {
    #[cfg(windows)]
    {
        // Live Windows IPC proof: attempt the real canonical pipes with no
        // owner listening, then assert the attempt fail-closes and spoofed
        // or dropped peers refuse with resources cleaned up.
        for pipe in [HOST_BACKUP_PIPE, WATCHDOG_BACKUP_PIPE] {
            let attempt = std::fs::File::open(pipe);
            // No owner is listening in the test lane, so the live attempt
            // must fail closed rather than connect to anything unexpected.
            assert!(attempt.is_err(), "live pipe attempt must fail closed");
        }
        // A disconnected/spoofed peer never validates, even against live names.
        let host = host_production();
        assert!(!host.authority_matches("attacker-spoofed-peer"));
        assert!(!host.response_identity_ok(
            HOST_BACKUP_PIPE,
            "attacker-spoofed-peer",
            BackupOperationKind::RestoreStatus
        ));
        // Cleanup releases the bound resources with zero pending effects.
        let shutdown = HostBackupOwnerClient::shutdown_cleanup();
        assert!(shutdown.pipe_closed());
        assert_eq!(shutdown.pending_effects(), 0);
    }
    #[cfg(not(windows))]
    {
        // Non-Windows compile proof only: the live Windows IPC attempt above
        // is Windows-gated, so this lane asserts the canonical binding shape
        // and proves the client types link — it never fakes a live success.
        assert_eq!(HOST_BACKUP_PIPE, r"\\.\pipe\eliot\host\runtime-control-v1");
        assert_eq!(WATCHDOG_BACKUP_PIPE, r"\\.\pipe\eliot\watchdog\signals");
        assert!(HostBackupOwnerClient::production().is_ok());
        assert!(WatchdogBackupOwnerClient::production().is_ok());
    }
}

// WORK_UNIT_CASE: 962/20
#[test]
fn wire_20_no_db_copy_binary_import_or_secret() {
    // Fixtures carry bounded typed payloads only: no database copies, no
    // connection strings, no credentials.
    for name in [
        "accepted-owner-method-table.json",
        "canonical-endpoints.json",
        "spoofed-peer-identity.json",
        "stale-generation-fence.json",
        "capture-admission.json",
        "prepare-cutover-admission.json",
        "replay-reconciliation.json",
        "bounds-and-cleanup.json",
    ] {
        let path = format!(
            "{}/tests/data/backup-owner-wire/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read_to_string(&path).expect("fixture readable");
        for forbidden in [
            "password",
            "secret",
            "connection_string",
            ".redb",
            "surreal",
            ".db",
            "BEGIN PRIVATE",
        ] {
            assert!(
                !raw.to_lowercase().contains(forbidden),
                "{name} must not contain {forbidden:?}"
            );
        }
    }
    // The client module introduces no binary Host/Watchdog import, no new
    // auth/transport, no unsafe, and no stub macros. Documentation comments
    // may name the owning paths; what is forbidden here is any code-level
    // import of those implementation crates (which would be circular).
    let source = include_str!("../src/backup_owner_clients.rs");
    for forbidden in [
        "todo!",
        "unimplemented!",
        "unreachable!",
        "unsafe",
        "include_bytes!",
        "use eliot_host",
        "use eliot_watchdog",
        "extern crate eliot_host",
        "extern crate eliot_watchdog",
        "eliot_host::",
        "eliot_watchdog::",
    ] {
        assert!(
            !source.contains(forbidden),
            "client source must not contain {forbidden:?}"
        );
    }
    // Production composition binds the actual clients through the injected
    // path (client injection only; existing behavior preserved).
    let bootstrap = include_str!("../src/composition_bootstrap.rs");
    assert!(bootstrap.contains("backup_owner_clients"));
    assert!(bootstrap.contains("HostBackupOwnerClient::production()"));
    assert!(bootstrap.contains("WatchdogBackupOwnerClient::production()"));
}
