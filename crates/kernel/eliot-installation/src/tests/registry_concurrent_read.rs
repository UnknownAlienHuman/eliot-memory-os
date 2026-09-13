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
