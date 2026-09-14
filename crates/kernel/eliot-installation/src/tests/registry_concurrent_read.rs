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
use std::sync::{Arc, Barrier};

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

/// Short-lived open-use-drop interleave proof (#1339, A13.9).
///
/// `INTERLEAVES` x open-mutate-drop interleaved with open-read-drop from two
/// threads on the REAL registry retry primitives
/// (`crate::redb_state::open_registry_writer_with_retry` /
/// `open_registry_reader_with_retry`, the exact primitives shared with
/// `open_existing_at` and `inspect_existing_at`). No mocks: one shared temp
/// redb file with a raw `REGISTRY_TABLE` revision cell.
///
/// The test proves the post-fix lifetime: every handle is dropped before the
/// next open, so the bounded `AlreadyOpen` retry never returns a fatal
/// beyond-budget contention and the final revision is exact. Before the fix,
/// a process-lifetime held writer made this contention deterministic (see the
/// held-writer oracles above); the trailing control re-proves that a held
/// writer exhausts even a small bounded retry, documenting why the Host
/// lifetime hold was wrong.
#[cfg(windows)]
#[test]
fn short_lived_registry_interleave_converges_with_exact_revision() {
    const INTERLEAVES: u64 = 25;
    let registry_path = std::env::temp_dir().join(format!(
        "eliot-host-short-lived-registry-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&registry_path);
    // Seed revision cell 0, then drop (short-lived).
    {
        let database = must(Database::create(&registry_path));
        let write = must(database.begin_write());
        {
            let mut table = must(write.open_table(REGISTRY_TABLE));
            let zero = 0_u64.to_le_bytes();
            must(table.insert("rev", zero.as_slice()));
        }
        must(write.commit());
    }
    let barrier = Arc::new(Barrier::new(2));
    // Writer: INTERLEAVES x open-mutate-drop via the real writer retry.
    let writer_path = registry_path.clone();
    let writer_barrier = Arc::clone(&barrier);
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        for expected in 1..=INTERLEAVES {
            let database = crate::redb_state::open_registry_writer_with_retry(&writer_path)
                .unwrap_or_else(|error| {
                    panic!("short-lived writer open {expected} must converge: {error}")
                });
            let write = database.begin_write().unwrap_or_else(|error| {
                panic!("short-lived writer begin_write must succeed: {error}")
            });
            {
                let mut table = write
                    .open_table(REGISTRY_TABLE)
                    .unwrap_or_else(|error| panic!("short-lived writer must open table: {error}"));
                let bytes = expected.to_le_bytes();
                table
                    .insert("rev", bytes.as_slice())
                    .unwrap_or_else(|error| {
                        panic!("short-lived writer insert must succeed: {error}")
                    });
            }
            write
                .commit()
                .unwrap_or_else(|error| panic!("short-lived writer commit must succeed: {error}"));
            // Drop before the next open: no exclusive owner across iterations.
            drop(database);
        }
    });
    // Reader: INTERLEAVES x open-read-drop via the real reader retry.
    let reader_path = registry_path.clone();
    let reader_barrier = Arc::clone(&barrier);
    let reader = std::thread::spawn(move || {
        reader_barrier.wait();
        for _ in 0..INTERLEAVES {
            let database = crate::redb_state::open_registry_reader_with_retry(&reader_path)
                .unwrap_or_else(|error| panic!("short-lived reader open must converge: {error}"));
            let read = database
                .begin_read()
                .unwrap_or_else(|_| unreachable!("short-lived reader must begin a read"));
            let table = read
                .open_table(REGISTRY_TABLE)
                .unwrap_or_else(|_| unreachable!("short-lived reader must open the table"));
            let value = table
                .get("rev")
                .unwrap_or_else(|_| unreachable!("revision cell must be readable"))
                .unwrap_or_else(|| unreachable!("revision cell must exist"));
            let bytes: [u8; 8] = value
                .value()
                .try_into()
                .unwrap_or_else(|_| unreachable!("revision cell must be 8 bytes"));
            let observed = u64::from_le_bytes(bytes);
            assert!(
                observed <= INTERLEAVES,
                "reader must never observe a revision beyond the writer budget, got {observed}"
            );
            drop(read);
            drop(database);
        }
    });
    writer
        .join()
        .unwrap_or_else(|_| unreachable!("writer thread must converge"));
    reader
        .join()
        .unwrap_or_else(|_| unreachable!("reader thread must converge"));
    // Final revision is exact: one more short-lived read observes INTERLEAVES.
    // All read handles drop at the end of this block so the held-writer
    // control below observes only its own retained handle.
    {
        let database = must(crate::redb_state::open_registry_reader_with_retry(
            &registry_path,
        ));
        let read = must(database.begin_read());
        let table = must(read.open_table(REGISTRY_TABLE));
        let value =
            must(table.get("rev")).unwrap_or_else(|| unreachable!("final revision must exist"));
        let bytes: [u8; 8] = value
            .value()
            .try_into()
            .unwrap_or_else(|_| unreachable!("final revision must be 8 bytes"));
        assert_eq!(
            u64::from_le_bytes(bytes),
            INTERLEAVES,
            "final revision must be exact after short-lived interleaves"
        );
    }
    // Held-writer control: a retained exclusive handle exhausts even a small
    // bounded retry, documenting why the Host lifetime hold was wrong.
    let held = must(Database::open(&registry_path));
    let exhausted = crate::redb_state::retry_registry_open_on_already_open(
        3,
        std::time::Duration::from_millis(10),
        std::time::Duration::from_millis(20),
        || redb::ReadOnlyDatabase::open(&registry_path),
    );
    let Err(contention) = exhausted else {
        unreachable!("bounded retry must exhaust while the writer is held")
    };
    assert!(
        matches!(contention, redb::DatabaseError::DatabaseAlreadyOpen),
        "held writer must exhaust bounded retry with typed AlreadyOpen, got: {contention}"
    );
    drop(held);
    let _ = std::fs::remove_file(&registry_path);
}
