//! Test oracle for installation transaction recovery.
//! Architecture: A13.1, A13.6, ARCH-RES-01, ARCH-RES-03
//! Implementation: I3.15, I14.21, I2.2, I2.23
//! Test-oracle-only: no production logic.

use std::sync::{Arc, Mutex};

use super::SharedStore;
use super::absent;
use super::fake_port;
use super::matching;
use super::must;
use super::planned_transaction;
use super::test_handle;
use crate::InstallationCoordinator;
use crate::InstallationEffectDisposition;
use crate::InstallationEffectProgressState;
use crate::InstallationTransactionStore;
use crate::PortOutcome;

#[test]
fn crash_after_mutation_reconciles_without_replay_and_receipt_never_replays() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let execute_count = Arc::new(Mutex::new(0));
    let mut crashing_port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent(&transaction))],
        Vec::new(),
        execute_count.clone(),
    );
    crashing_port.panic_reconcile_once = true;
    let mut coordinator = InstallationCoordinator::new(crashing_port, store.clone());
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = coordinator.drive_effect(&transaction_id);
    }));
    assert!(crashed.is_err());
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
    let intent = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        intent.effect_progress[0].state,
        InstallationEffectProgressState::IntentCommitted { .. }
    ));

    let recovering_port = fake_port(
        store.clone(),
        Vec::new(),
        vec![PortOutcome::Known(matching(
            InstallationEffectDisposition::CreatedByTransaction,
        ))],
        execute_count.clone(),
    );
    let mut recovering = InstallationCoordinator::new(recovering_port, store.clone());
    must(recovering.drive_effect(&transaction_id));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);

    let mut complete = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    for (index, progress) in complete.effect_progress.iter_mut().enumerate().skip(1) {
        progress.state = InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::PreexistingMatching,
            external_identity: test_handle(format!("external:receipt-{index}")),
            evidence: vec![test_handle(format!("evidence:receipt-{index}"))],
            postcondition_digest: test_handle(format!("{index:064x}")),
        };
    }
    complete.revision += 1;
    must(complete.validate());
    *store.state.lock().unwrap_or_else(|_| unreachable!()) = Some(complete);

    let receipt_port = fake_port(store.clone(), Vec::new(), Vec::new(), execute_count.clone());
    let mut receipt = InstallationCoordinator::new(receipt_port, store);
    must(receipt.drive_effect(&transaction_id));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
}
