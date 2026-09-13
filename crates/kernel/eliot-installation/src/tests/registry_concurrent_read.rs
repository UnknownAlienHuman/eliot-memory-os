//! Watchdog-approval concurrent-read proof (INSTALL-WATCHDOG-APPROVAL, s36).
//!
//! Holds the installer's writer `Database` across a staged bootstrap approval
//! while a second read-only open reads the same file. The reader mirrors the
//! Watchdog `inspect_existing_at` path (`ReadOnlyDatabase::open` + table read
//! in `redb_state.rs`), minus the protected-lease contour which cannot be
//! constructed without an elevated install. No mocks: both handles use the
//! real redb open paths on one shared temp file.
//! Test-oracle-only: no production ownership or approval semantics.

use std::sync::atomic::Ordering;

use redb::{Database, ReadableDatabase};

use super::NEXT_TRANSACTION_ROOT;
use super::PRODUCTION_INSTALLER_TEST_LOCK;
use super::decode_registry_bytes;
use super::must;
use super::registering_system_service_start_transaction;
use super::transaction_store_private;
use crate::InstallationTransaction;
use crate::PendingActivationState;
use crate::REGISTRY_TABLE;
use crate::RedbInstallationRegistry;
use crate::RedbInstallationTransactionStore;
use crate::transaction_store_private::TransactionVersion;

#[cfg(windows)]
#[test]
fn held_installer_writer_permits_concurrent_readonly_approval_read() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let registering = registering_system_service_start_transaction();
    let planned = must(InstallationTransaction::new(
        registering.transaction_id.clone(),
        registering.installation_epoch.clone(),
        registering.profile,
        registering.request.clone(),
        registering.current_active_manifest.clone(),
        registering.candidate_manifest.clone(),
        registering.staging_root.clone(),
        registering.planned_changes.clone(),
        registering.installer_effects.clone(),
        registering.minimum_store_available_bytes,
        registering.precondition_evidence.clone(),
        registering.recovery_command.clone(),
    ));
    let transaction_path = std::env::temp_dir().join(format!(
        "eliot-watchdog-approval-transaction-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let registry_path = std::env::temp_dir().join(format!(
        "eliot-watchdog-approval-registry-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&transaction_path);
    let _ = std::fs::remove_file(&registry_path);
    let mut transaction_store = must(
        RedbInstallationTransactionStore::create_unpublished_stage_fixture_at_exact_path(
            &transaction_path,
            &planned,
        ),
    );
    let expected = must(TransactionVersion::of(&planned));
    let mut persisted = registering.clone();
    persisted.revision = expected.revision + 1;
    must(
        <RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
            &mut transaction_store,
            expected,
            &persisted,
        ),
    );
    // Installer-held writer, as in `bins/eliot/src/main.rs` before the fix:
    // the writer `Database` stays open across the SCM start + convergence wait.
    let registry =
        RedbInstallationRegistry::from_database_for_test(must(Database::create(&registry_path)));
    let revision = must(registry.load()).revision();
    must(registry.stage_pending_activation_bootstrap(
        &mut transaction_store,
        &registering.transaction_id,
        revision,
    ));
    // Bug mechanism (INSTALL-WATCHDOG-APPROVAL): while the installer writer
    // is held, the Watchdog reader open fails closed on the redb file lock
    // (observed on Windows: "Database already open. Cannot acquire lock.").
    let writer_view = must(registry.load());
    let blocked = redb::ReadOnlyDatabase::open(&registry_path);
    assert!(
        blocked.is_err(),
        "held installer writer must block the Watchdog reader open (pre-fix contention)"
    );
    drop(blocked);
    // Post-fix behavior: releasing the writer (the `drop(registry)` in
    // `bins/eliot/src/main.rs` before the SCM start + convergence wait) lets
    // the Watchdog reader open the same file and observe the exact approval.
    drop(registry);
    // Watchdog reader after release: the exact `ReadOnlyDatabase::open` +
    // `begin_read` + table read from `inspect_existing_at` /
    // `read_existing_registry`.
    let reader = must(redb::ReadOnlyDatabase::open(&registry_path));
    let read = must(reader.begin_read());
    let table = must(read.open_table(REGISTRY_TABLE));
    let value = must(table.get("registry"))
        .unwrap_or_else(|| unreachable!("staged bootstrap approval must be durable"));
    let observed = must(decode_registry_bytes(value.value()));
    must(observed.validate());
    assert_eq!(observed.revision(), writer_view.revision());
    let pending = observed
        .pending_activation()
        .unwrap_or_else(|| unreachable!("staged bootstrap approval must be pending"));
    assert!(matches!(pending.state, PendingActivationState::Pending));
    assert_eq!(pending.transaction_id, registering.transaction_id);
    assert_eq!(
        pending.approval.transaction_id, registering.transaction_id,
        "reader must observe the exact staged approval binding"
    );
    drop(read);
    drop(reader);
    drop(transaction_store);
    let _ = std::fs::remove_file(registry_path);
    let _ = std::fs::remove_file(transaction_path);
}

/// Bounded-retry contention oracle (standing s37 + issue #1339).
///
/// Interleaves a held installer writer transaction with a polling Watchdog
/// reader on the REAL registry retry open paths
/// (`crate::redb_state::open_registry_reader_with_retry` /
/// `open_registry_writer_with_retry`, the exact primitives shared with
/// `inspect_existing_at` and `open_existing_at`). No mocks: one shared temp
/// redb file, one real staged bootstrap approval.
///
/// The test proves both halves of "transient, not fatal":
/// 1. a single raw `ReadOnlyDatabase::open` while the writer is held fails
///    with typed `redb::DatabaseError::DatabaseAlreadyOpen` (the pre-fix
///    fatal; redb `src/error.rs:208,257`), so without retry this test fails;
/// 2. the bounded registry retry converges once the short-lived writer is
///    released (A13.9: no handle held across an unbounded wait) and observes
///    the exact staged approval, and the writer primitive re-opens the same
///    file for terminal reconcile.
#[cfg(windows)]
#[test]
fn held_writer_contention_is_transient_under_bounded_registry_retry() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let registering = registering_system_service_start_transaction();
    let planned = must(InstallationTransaction::new(
        registering.transaction_id.clone(),
        registering.installation_epoch.clone(),
        registering.profile,
        registering.request.clone(),
        registering.current_active_manifest.clone(),
        registering.candidate_manifest.clone(),
        registering.staging_root.clone(),
        registering.planned_changes.clone(),
        registering.installer_effects.clone(),
        registering.minimum_store_available_bytes,
        registering.precondition_evidence.clone(),
        registering.recovery_command.clone(),
    ));
    let transaction_path = std::env::temp_dir().join(format!(
        "eliot-watchdog-retry-transaction-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let registry_path = std::env::temp_dir().join(format!(
        "eliot-watchdog-retry-registry-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&transaction_path);
    let _ = std::fs::remove_file(&registry_path);
    let mut transaction_store = must(
        RedbInstallationTransactionStore::create_unpublished_stage_fixture_at_exact_path(
            &transaction_path,
            &planned,
        ),
    );
    let expected = must(TransactionVersion::of(&planned));
    let mut persisted = registering.clone();
    persisted.revision = expected.revision + 1;
    must(
        <RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
            &mut transaction_store,
            expected,
            &persisted,
        ),
    );
    // Installer-held writer across the Watchdog poll window.
    let registry =
        RedbInstallationRegistry::from_database_for_test(must(Database::create(&registry_path)));
    let revision = must(registry.load()).revision();
    must(registry.stage_pending_activation_bootstrap(
        &mut transaction_store,
        &registering.transaction_id,
        revision,
    ));
    let writer_view = must(registry.load());
    // Pre-retry proof: without retry the reader open is fatal while the
    // writer is held. This typed failure is what the bounded retry below
    // must converge past; if contention ever stops occurring, this assert
    // (like the pre-fix oracle above) tells us the test no longer exercises
    // the retry path.
    let contention = match redb::ReadOnlyDatabase::open(&registry_path) {
        Ok(_) => unreachable!("raw reader open must fail while the writer is held"),
        Err(error) => error,
    };
    assert!(
        matches!(contention, redb::DatabaseError::DatabaseAlreadyOpen),
        "expected typed DatabaseAlreadyOpen while writer held, got: {contention}"
    );
    assert!(
        contention.to_string().contains("already open"),
        "contention cause must preserve the redb AlreadyOpen message, got: {contention}"
    );
    // Polling reader on the REAL registry retry path. It first proves
    // contention is live on its own thread, signals the main thread, then
    // enters the bounded retry while the writer stays held; the writer is
    // released mid-poll so retry must spin transiently, then converge.
    let (contended_tx, contended_rx) = std::sync::mpsc::channel::<()>();
    let reader_path = registry_path.clone();
    let reader = std::thread::spawn(move || {
        let live = match redb::ReadOnlyDatabase::open(&reader_path) {
            Ok(_) => unreachable!("reader thread must observe live contention at retry entry"),
            Err(error) => error,
        };
        assert!(
            matches!(live, redb::DatabaseError::DatabaseAlreadyOpen),
            "reader thread must observe live contention at retry entry, got: {live}"
        );
        contended_tx
            .send(())
            .unwrap_or_else(|_| unreachable!("contention signal must deliver"));
        let database = crate::redb_state::open_registry_reader_with_retry(&reader_path)
            .unwrap_or_else(|error| panic!("bounded registry reader retry must converge: {error}"));
        let read = database
            .begin_read()
            .unwrap_or_else(|_| unreachable!("retry-opened reader must begin a read"));
        let table = read
            .open_table(REGISTRY_TABLE)
            .unwrap_or_else(|_| unreachable!("retry-opened reader must open the registry table"));
        let value = table
            .get("registry")
            .unwrap_or_else(|_| unreachable!("staged bootstrap approval must be durable"))
            .unwrap_or_else(|| unreachable!("staged bootstrap approval must be durable"));
        let observed = must(decode_registry_bytes(value.value()));
        must(observed.validate());
        observed
    });
    // Wait for the reader to prove live contention (bounded: the reader
    // terminates on its own even if the main thread stalls), then hold the
    // writer across one Watchdog poll window before the A13.9 release.
    contended_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap_or_else(|_| {
            unreachable!("reader must prove contention before the writer is released")
        });
    std::thread::sleep(std::time::Duration::from_millis(300));
    drop(registry);
    let observed = reader
        .join()
        .unwrap_or_else(|_| unreachable!("polling reader thread must converge after release"));
    assert_eq!(observed.revision(), writer_view.revision());
    let pending = observed
        .pending_activation()
        .unwrap_or_else(|| unreachable!("staged bootstrap approval must be pending"));
    assert!(matches!(pending.state, PendingActivationState::Pending));
    assert_eq!(pending.transaction_id, registering.transaction_id);
    assert_eq!(
        pending.approval.transaction_id, registering.transaction_id,
        "retry reader must observe the exact staged approval binding"
    );
    // Terminal-reconcile mirror: the writer retry primitive
    // (`open_existing_at`'s `Database::open` shape) re-opens the same file
    // after release and loads the exact projection.
    let reopened = RedbInstallationRegistry::from_database_for_test(must(
        crate::redb_state::open_registry_writer_with_retry(&registry_path),
    ));
    assert_eq!(must(reopened.load()).revision(), writer_view.revision());
    drop(reopened);
    drop(transaction_store);
    let _ = std::fs::remove_file(registry_path);
    let _ = std::fs::remove_file(transaction_path);
}
