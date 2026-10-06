//! Owner-port import-positive proofs (issue #955 T13/T17).
//!
//! The snapshot legs in `tests/spool_backup.rs` prove the owner capture path;
//! the import legs need installer-admitted material no snapshot contour mints:
//! an externally admitted destination ([`crate::admit_isolated_destination`])
//! and an owner-issued active binding
//! ([`crate::FileWatchdogAdmission::from_registry`]). Both verify approved
//! image digests against real bytes; the live admission additionally requires
//! the running image to be the approved Watchdog image plus durable
//! provisioned supervision authority. The [`crate::registry_fixture`] import
//! contour mints exactly that, in-test only (parent AUTH-GRANTED): the running
//! test binary approves itself with its own real digest, and the authority is
//! self-provisioned with test values bound to the contour's own installation
//! and generation. No production path is touched: the sensor, the port, the
//! admission and the import are the production route throughout.
//!
//! The contour is `SystemService`-shaped under a thread-local
//! `override_protected_root` pin the fixture holds, so no elevation and no
//! production root are touched. Every identity the import binds (installation
//! keys, generation, image digests, manifest digest, authority) is derived
//! inside the contour, never invented.

use crate::registry_fixture::RegistryFixture;
use crate::watchdog_admission::test_binding_from_registry;
use crate::watchdog_spool::owner_issued_active_installation;
use crate::{
    AdmittedIsolatedDestination, CaptureFenceParams, IndependentKernelSensor, KernelWatchdogPort,
    SERVICE_NAME, SpoolAppendOutcome, SpoolRestoreDisposition, SpoolRestoreStep,
    WatchdogBackupPort, WatchdogSpoolBackupLimits, WatchdogSpoolFence, WatchdogSpoolPayload,
    admit_isolated_destination,
};

/// One disposable import contour: the source registry with its committed
/// authority, the destination registry, and the sensor whose spool the owner
/// port captures through — all bound to the source contour's own
/// installation identity.
struct ImportContour {
    source: RegistryFixture,
    sensor_dir: std::path::PathBuf,
    sensor: IndependentKernelSensor,
    port: std::sync::Arc<WatchdogBackupPort>,
    fence: WatchdogSpoolFence,
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

fn hex_seed(seed: u64) -> String {
    format!("{seed:064x}")
}

fn heartbeat_payload(tag: &str, seed: u64) -> WatchdogSpoolPayload {
    WatchdogSpoolPayload::Heartbeat {
        service: SERVICE_NAME.to_owned(),
        lease_id: format!("lease-955-{tag}"),
        scope_ref: format!("scope-955-{tag}"),
        kernel_epoch: 2,
        watchdog_epoch: 3,
        payload_digest: hex_seed(seed),
        envelope_digest: hex_seed(seed + 1),
        signer_id: format!("signer-955-{tag}"),
        key_id: format!("key-955-{tag}"),
        signature_algorithm: "ed25519".to_owned(),
        signature: hex_seed(seed + 2),
        public_key_fingerprint: hex_seed(seed + 3),
        lease_revision: 1,
    }
}

/// Builds one source contour: installer-admitted registry with committed
/// authority, runtime children materialized for root retention, and a sensor
/// opened ON the contour's own installation identity whose spool carries
/// fresh heartbeats the owner port captures.
fn import_contour(tag: &str) -> ImportContour {
    let source = RegistryFixture::new();
    source.write_registry(&source.import_ready_projection());
    source.ensure_runtime_children();
    let sensor_dir = std::env::temp_dir().join(format!(
        "eliot-watchdog-955-import-{tag}-{}-{}",
        std::process::id(),
        &source.installation_key()[..16]
    ));
    std::fs::create_dir_all(&sensor_dir).expect("create import sensor dir");
    let sensor = IndependentKernelSensor::open_for_export_driver_test(
        &sensor_dir,
        source.installation_key(),
        9,
        3,
    )
    .expect("open import sensor on the contour installation");
    let now = now_ms();
    for (offset_ms, seed) in [(30_000, 101), (20_000, 102), (10_000, 103)] {
        assert!(matches!(
            sensor.append_spool_entry_for_export_driver_test(
                now - offset_ms,
                heartbeat_payload(tag, seed)
            ),
            Ok(SpoolAppendOutcome::Stored)
        ));
    }
    let port = sensor
        .spool_backup_port()
        .expect("import sensor carries the owner backup port");
    assert_eq!(
        port.source_installation(),
        source.installation_key(),
        "the port binds the contour's own installation"
    );
    let fence = port
        .snapshot(
            CaptureFenceParams {
                source_installation: source.installation_key().to_owned(),
                watchdog_generation: 9,
                requester_principal: "watchdog-spool-owner".to_owned(),
                snapshot_operation_id: eliot_contracts::sha256_hex(tag.as_bytes()),
                canonical_ref: None,
                ors_ref: None,
                coherence_fence_equal: false,
            },
            WatchdogSpoolBackupLimits::default(),
        )
        .expect("owner snapshot of the import contour");
    ImportContour {
        source,
        sensor_dir,
        sensor,
        port,
        fence,
    }
}

/// Builds one destination contour: installer-admitted registry with real
/// image digests over its own artifact copies, runtime children materialized
/// for root retention. No authority and no terminal: a new isolated
/// installation has neither.
fn destination_contour() -> RegistryFixture {
    let destination = RegistryFixture::new();
    destination.write_registry(&destination.destination_projection());
    destination.ensure_runtime_children();
    destination
}

/// Mints the source active binding out of the contour's own registry: the
/// owner-issued active side the import compares the destination against.
///
/// This runs the full production admission chain through
/// `test_binding_from_registry` — retained root, manifest selection, durable
/// authority, approvals, both image digests, profile, retention — minus only
/// the running-image string-equality gate, which binds the running process
/// by design and no test process can satisfy (see the minter's docs).
fn admit_source_active(contour: &ImportContour) -> crate::WatchdogRuntimeBinding {
    let binding = test_binding_from_registry(
        contour.source.registry_file().to_path_buf(),
        &contour.source.bootstrap_import_ready(),
    )
    .expect("source active binding");
    assert_eq!(
        owner_issued_active_installation(&binding),
        contour.source.installation_key(),
        "the active binding carries the contour's own installation"
    );
    binding
}

/// Admits one isolated destination out of its own registry and bootstrap.
fn admit_destination(destination: &RegistryFixture) -> AdmittedIsolatedDestination {
    let admitted =
        admit_isolated_destination(destination.registry_file(), &destination.base_bootstrap())
            .expect("isolated destination admission");
    assert_eq!(
        admitted.installation(),
        destination.installation_key(),
        "the destination binding carries its own installation"
    );
    admitted
}

/// Builds the restore steps from a captured fence: the first step's
/// predecessor is the fence content digest, every later step chains the
/// previous entry — the same chain the owner validates at import.
fn import_steps(fence: &WatchdogSpoolFence, operation: &str) -> Vec<SpoolRestoreStep> {
    vec![
        SpoolRestoreStep {
            step_index: 0,
            step_digest: fence.entries()[0].entry_digest.clone(),
            predecessor_digest: fence.content_digest.clone(),
            operation_id: format!("{operation}-0"),
        },
        SpoolRestoreStep {
            step_index: 1,
            step_digest: fence.entries()[1].entry_digest.clone(),
            predecessor_digest: fence.entries()[0].entry_digest.clone(),
            operation_id: format!("{operation}-1"),
        },
    ]
}

/// Counts the entries the destination spool retains, by reopening its state
/// root read-only: reopening an existing spool recovers without mutating, so
/// the count is the import's own effect.
fn destination_retained(state_root: &std::path::Path, installation: &str) -> usize {
    let sensor =
        IndependentKernelSensor::open_for_export_driver_test(state_root, installation, 9, 3)
            .expect("reopen destination spool");
    let retained = sensor
        .retained_spool_entries_for_export_driver_test()
        .expect("read destination spool");
    retained.len()
}

/// Removes one contour's sensor directory after the whole contour (sensor
/// database handle, port, fence, source fixture) is dropped — redb files
/// cannot be removed while a handle is open. Fixtures remove their own roots
/// on drop.
fn release_contour(contour: ImportContour) {
    let sensor_dir = contour.sensor_dir.clone();
    drop(contour);
    let _ = std::fs::remove_dir_all(&sensor_dir);
}

/// T17 owner import (issue #955): the captured fence imports through the
/// owner port into the admitted destination — `Accepted` — and the
/// destination spool retains the imported Recovery records while the source
/// spool is undisturbed. The primitive round in `tests/spool_backup.rs`
/// stays as the admission-free core; this test is the production-path
/// substitution its gap comment names.
/// Norm: `docs/architecture/I05-13-backup-and-restore.md` Restore
/// ("restore to isolated root;").
#[test]
fn owner_port_imports_captured_fence_into_admitted_destination() {
    let contour = import_contour("t17-owner-import");
    let active = admit_source_active(&contour);
    let destination = destination_contour();
    let admitted = admit_destination(&destination);
    let steps = import_steps(&contour.fence, "op-955-t17-owner-import");
    assert_eq!(
        contour
            .port
            .import_isolated(
                contour.source.installation_key(),
                Some(&admitted),
                &active,
                &steps
            )
            .expect("owner import accepts"),
        SpoolRestoreDisposition::Accepted,
        "the owner import accepts the captured fence"
    );
    drop(active);
    drop(admitted);
    let retained = destination_retained(
        std::path::Path::new(
            destination
                .manifest_destination()
                .runtime_launch
                .runtime_state_roots
                .watchdog_state_root
                .as_str(),
        ),
        destination.installation_key(),
    );
    assert_eq!(
        retained, 2,
        "the destination spool retains exactly the two imported Recovery records"
    );
    // The import never touches the owner's own spool: the three captured
    // heartbeats are still all that the source retains.
    assert_eq!(
        contour
            .sensor
            .retained_spool_entries_for_export_driver_test()
            .expect("reread source spool")
            .len(),
        3,
        "the source spool is undisturbed by its own export"
    );
    release_contour(contour);
}

/// T13 lost-response leg through the owner port (issue #955): repeating the
/// identical import after acceptance reconciles to `Duplicate` with no second
/// append — the response the caller lost does not become a second import.
/// The ledger-plus-reconcile round in `tests/spool_backup.rs` stays as the
/// admission-free core; this test drives the same guarantee through the
/// production import entry.
#[test]
fn owner_port_import_replay_reconciles_without_duplicate_append() {
    let contour = import_contour("t13-owner-replay");
    let active = admit_source_active(&contour);
    let destination = destination_contour();
    let admitted = admit_destination(&destination);
    let steps = import_steps(&contour.fence, "op-955-t13-owner-replay");
    assert_eq!(
        contour
            .port
            .import_isolated(
                contour.source.installation_key(),
                Some(&admitted),
                &active,
                &steps
            )
            .expect("first owner import accepts"),
        SpoolRestoreDisposition::Accepted,
    );
    let state_root = std::path::PathBuf::from(
        destination
            .manifest_destination()
            .runtime_launch
            .runtime_state_roots
            .watchdog_state_root
            .as_str(),
    );
    let retained_once = destination_retained(&state_root, destination.installation_key());
    assert_eq!(
        contour
            .port
            .import_isolated(
                contour.source.installation_key(),
                Some(&admitted),
                &active,
                &steps
            )
            .expect("replayed owner import reconciles"),
        SpoolRestoreDisposition::Duplicate,
        "the replay reconciles instead of importing again"
    );
    assert_eq!(
        destination_retained(&state_root, destination.installation_key()),
        retained_once,
        "the replay appends nothing behind the retained import"
    );
    assert_eq!(
        contour
            .sensor
            .retained_spool_entries_for_export_driver_test()
            .expect("reread source spool")
            .len(),
        3,
        "the replay never touches the source spool either"
    );
    drop(active);
    drop(admitted);
    release_contour(contour);
}
