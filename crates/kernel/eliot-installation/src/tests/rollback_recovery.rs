//! Test oracle for installation rollback recovery.
//! Architecture: A13.6, A13.12, ARCH-RES-01, ARCH-RES-03
//! Implementation: I19.11, I14.21, I2.2, I2.23
//! Test-oracle-only: no production logic.

use std::sync::{Arc, Mutex};

use super::SharedStore;
use super::absent;
use super::admitted_precondition;
use super::fake_port;
use super::matching;
use super::must;
use super::planned_transaction;
use super::test_handle;
use super::test_ownership_secret;
use crate::InstallationCoordinator;
use crate::InstallationCreateDisposition;
use crate::InstallationEffectDisposition;
use crate::InstallationEffectProgressState;
use crate::InstallationSecretLifecycle;
use crate::InstallationStage;
use crate::InstallationStepOutcome;
use crate::InstallationTransaction;
use crate::InstallationTransactionStore;
use crate::PortOutcome;

fn rollback_ready_transaction() -> InstallationTransaction {
    let mut transaction = planned_transaction();
    transaction.effect_progress[0].admitted_precondition =
        Some(admitted_precondition(&transaction));
    transaction.effect_progress[0].ownership_secret = Some(test_ownership_secret(
        InstallationCreateDisposition::Created,
        InstallationSecretLifecycle::Active,
    ));
    transaction.effect_progress[0].state = InstallationEffectProgressState::Applied {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity: test_handle("external:effect-0"),
        evidence: vec![test_handle("evidence:created-root")],
        postcondition_digest: test_handle("e".repeat(64)),
    };
    transaction.pending_external_changes = vec![test_handle("pending:rollback")];
    transaction.stage = InstallationStage::RollbackRequired;
    transaction.revision = 4;
    must(transaction.validate());
    transaction
}

#[test]
fn crash_before_credential_delete_retains_intent_and_resumes() {
    let transaction = rollback_ready_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let mut crashing = fake_port(
        store.clone(),
        Vec::new(),
        vec![
            PortOutcome::Known(matching(
                InstallationEffectDisposition::CreatedByTransaction,
            )),
            PortOutcome::Known(absent(&transaction)),
        ],
        execute_count.clone(),
    );
    crashing.secret_absence = vec![PortOutcome::Known(false)].into();
    crashing.secret_deletes = vec![PortOutcome::Unknown(
        eliot_platform::UnknownReason::Indeterminate,
    )]
    .into();
    let mut coordinator = InstallationCoordinator::new(crashing, store.clone());
    assert!(matches!(
        must(coordinator.rollback(&transaction_id)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    let retained = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(retained.stage, InstallationStage::RollbackRequired);
    assert_eq!(
        retained.effect_progress[0]
            .ownership_secret
            .as_ref()
            .unwrap_or_else(|| unreachable!())
            .lifecycle,
        InstallationSecretLifecycle::DeleteIntentCommitted
    );

    let mut recovering = fake_port(
        store.clone(),
        Vec::new(),
        vec![PortOutcome::Known(absent(&transaction))],
        execute_count,
    );
    recovering.secret_absence = vec![PortOutcome::Known(false), PortOutcome::Known(true)].into();
    recovering.secret_deletes = vec![PortOutcome::Known(())].into();
    let mut coordinator = InstallationCoordinator::new(recovering, store.clone());
    assert!(matches!(
        must(coordinator.rollback(&transaction_id)),
        InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack,
            ..
        }
    ));
    let terminal = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(
        terminal.effect_progress[0]
            .ownership_secret
            .as_ref()
            .unwrap_or_else(|| unreachable!())
            .lifecycle,
        InstallationSecretLifecycle::Deleted
    );
    must(terminal.validate());
}

#[test]
fn crash_after_credential_delete_reobserves_absence_before_terminal_state() {
    let transaction = rollback_ready_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let mut crashing = fake_port(
        store.clone(),
        Vec::new(),
        vec![
            PortOutcome::Known(matching(
                InstallationEffectDisposition::CreatedByTransaction,
            )),
            PortOutcome::Known(absent(&transaction)),
        ],
        execute_count.clone(),
    );
    crashing.secret_absence = vec![
        PortOutcome::Known(false),
        PortOutcome::Unknown(eliot_platform::UnknownReason::Indeterminate),
    ]
    .into();
    crashing.secret_deletes = vec![PortOutcome::Known(())].into();
    let mut coordinator = InstallationCoordinator::new(crashing, store.clone());
    assert!(matches!(
        must(coordinator.rollback(&transaction_id)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    let retained = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(retained.stage, InstallationStage::RollbackRequired);
    assert_eq!(
        retained.effect_progress[0]
            .ownership_secret
            .as_ref()
            .unwrap_or_else(|| unreachable!())
            .lifecycle,
        InstallationSecretLifecycle::DeleteIntentCommitted
    );

    let mut recovering = fake_port(
        store.clone(),
        Vec::new(),
        vec![PortOutcome::Known(absent(&transaction))],
        execute_count,
    );
    recovering.secret_absence = vec![PortOutcome::Known(true)].into();
    let mut coordinator = InstallationCoordinator::new(recovering, store.clone());
    assert!(matches!(
        must(coordinator.rollback(&transaction_id)),
        InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack,
            ..
        }
    ));
    let terminal = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(terminal.stage, InstallationStage::RolledBack);
    must(terminal.validate());
}
