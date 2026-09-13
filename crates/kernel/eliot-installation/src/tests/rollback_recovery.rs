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
#[cfg(windows)]
use super::absent_with_file_index;
#[cfg(windows)]
use super::matching_for;
#[cfg(windows)]
use super::system_registration_transaction;
use crate::InstallationCoordinator;
use crate::InstallationCreateDisposition;
use crate::InstallationEffectDisposition;
use crate::InstallationEffectObservation;
use crate::InstallationEffectPrecondition;
use crate::InstallationEffectProgressState;
use crate::InstallationSecretLifecycle;
use crate::InstallationStage;
use crate::InstallationStepOutcome;
use crate::InstallationTransaction;
use crate::InstallationTransactionStore;
use crate::InstallerEffectPlan;
use crate::InstallerServiceRole;
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

/// s32 item 2: resume from a half-done service rollback (Watchdog already
/// deleted, Host still present, mimicking the stuck rc4 transaction).
///
/// PRE-FIX failure reproduction (fails `validate()` on unpatched base):
/// `empty_absent.validate()` below returns
/// `observation.observed_precondition is invalid: absence must contain an
/// independently observed OS snapshot`.
/// That is the exact production shape from `service_absent_observation`
/// (lib.rs:5973 clones the request precondition with no os/credential
/// snapshot) reaching the rollback strict gate `observed.validate()`
/// (allow=false, lib.rs:7862) before the `Absent => continue` arm can run,
/// so the Host delete is never reached.
///
/// POST-FIX pass (passes on base with snapshot-carrying Absent, and passes
/// fully once Writer A's production fix makes service Absent carry an
/// independently observed snapshot):
/// snapshot-carrying Absents pass `validate()`; rollback treats the first
/// Watchdog Absent as done (`continue`, no execute), deletes Host through
/// the Matching+identity => execute => reconcile Absent path, treats the
/// package Absent as done, and reaches terminal `RolledBack`.
#[cfg(windows)]
#[test]
fn interrupted_service_rollback_resumes_after_first_delete() {
    let mut transaction = system_registration_transaction();
    let host_index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::RegisterService {
                    role: InstallerServiceRole::Host,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    let watchdog_index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::RegisterService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    let package_index = transaction
        .installer_effects
        .iter()
        .position(|effect| matches!(effect, InstallerEffectPlan::StagePackage { .. }))
        .unwrap_or_else(|| unreachable!());
    // Rollback rev-iterates CreatedByTransaction, so the stuck rc4 shape
    // (Watchdog deleted first) requires Watchdog to sort last.
    assert!(
        package_index < host_index && host_index < watchdog_index,
        "service rollback order must rev-visit Watchdog, then Host, then package"
    );
    for index in [package_index, host_index, watchdog_index] {
        assert!(
            matches!(
                transaction.effect_progress[index].state,
                InstallationEffectProgressState::Applied {
                    disposition: InstallationEffectDisposition::CreatedByTransaction,
                    ..
                }
            ),
            "effect {index} must start as transaction-created"
        );
    }

    // PRE-FIX reproduction: the production empty-Absent shape (no snapshot)
    // must fail the same strict `validate()` the rollback loop applies.
    let host_change = transaction
        .planned_changes
        .iter()
        .find(|change| {
            change.change_id == *transaction.installer_effects[host_index].effect_id()
        })
        .cloned()
        .unwrap_or_else(|| unreachable!());
    let empty_precondition = must(InstallationEffectPrecondition::from_change(&host_change));
    assert!(
        empty_precondition.os_snapshot.is_none()
            && empty_precondition.credential_snapshot.is_none(),
        "pre-fix shape must carry no independently observed snapshot"
    );
    let empty_absent = InstallationEffectObservation::Absent {
        observed_precondition: empty_precondition,
        evidence: vec![test_handle("evidence:empty-service-absent")],
        service_runtime_lineage: None,
    };
    let error = empty_absent
        .validate()
        .expect_err("pre-fix empty service Absent must fail strict validate()");
    assert!(
        error.to_string().contains(
            "absence must contain an independently observed OS snapshot"
        ),
        "pre-fix validate() must report the missing OS snapshot, observed {error}"
    );

    // POST-FIX shape: snapshot-carrying Absents (the `absent()` helper shape
    // Writer A's fix will produce in production) pass strict `validate()`.
    let watchdog_absent = absent_with_file_index(&transaction, 11);
    must(watchdog_absent.validate());
    let host_absent_after_delete = absent_with_file_index(&transaction, 12);
    must(host_absent_after_delete.validate());
    let package_absent = absent_with_file_index(&transaction, 13);
    must(package_absent.validate());

    // Host Matching must carry the exact durable external identity, otherwise
    // the rollback identity guard (`request.expected_external_identity ==
    // Some(external_identity)`) quarantines instead of deleting.
    let host_expected = match &transaction.effect_progress[host_index].state {
        InstallationEffectProgressState::Applied {
            external_identity, ..
        } => external_identity.clone(),
        _ => unreachable!(),
    };
    let mut host_matching = matching_for(
        &transaction.installer_effects[host_index],
        host_index,
        InstallationEffectDisposition::CreatedByTransaction,
    );
    match &mut host_matching {
        InstallationEffectObservation::Matching {
            external_identity, ..
        } => *external_identity = host_expected.clone(),
        _ => unreachable!(),
    }
    must(host_matching.validate());

    transaction.stage = InstallationStage::RollbackRequired;
    transaction.pending_external_changes =
        vec![test_handle("pending:interrupted-service-rollback")];
    transaction.revision += 1;
    must(transaction.validate());
    let transaction_id = transaction.transaction_id.clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    // Rev order: Watchdog Absent (already deleted => continue, no execute),
    // Host Matching => execute delete => Absent (one execute), package Absent
    // (done => continue, no execute).
    let port = fake_port(
        store.clone(),
        Vec::new(),
        vec![
            PortOutcome::Known(watchdog_absent),
            PortOutcome::Known(host_matching),
            PortOutcome::Known(host_absent_after_delete),
            PortOutcome::Known(package_absent),
        ],
        execute_count.clone(),
    );
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    assert!(matches!(
        must(coordinator.rollback(&transaction_id)),
        InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack,
            ..
        }
    ));
    // Matching-identity path exercised exactly once (Host delete); the two
    // Absent=>continue arms must not execute. A foreign identity would miss
    // the identity guard and quarantine instead of reaching RolledBack.
    assert_eq!(
        *execute_count.lock().unwrap_or_else(|_| unreachable!()),
        1,
        "only the Host Matching=>delete arm may execute"
    );
    let terminal = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(terminal.stage, InstallationStage::RolledBack);
    must(terminal.validate());
}
