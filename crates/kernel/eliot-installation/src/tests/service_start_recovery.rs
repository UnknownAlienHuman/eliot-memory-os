//! Test oracle for installation service-start recovery.
//! Architecture: A13.12 - fail-closed recovery handles for service start response-loss, race, and foreign-ownership.
//! Implementation: I19.11, I14.21, I2.2, I2.23
//! Test-oracle-only: no production logic; no product authority.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use super::NEXT_TRANSACTION_ROOT;
use super::SharedStore;
use super::absent_with_file_index;
use super::configure_start_already_running_execution;
use super::configure_start_already_starting_execution;
use super::configure_start_runtime_receipt;
use super::configure_start_waiting_execution;
use super::configure_start_waiting_execution_with_lineage;
use super::fake_port;
use super::matching;
use super::matching_service_runtime;
use super::must;
use super::pending_start_precondition;
use super::pending_system_service_start_transaction;
use super::registering_system_service_start_transaction;
use super::start_absent;
use super::start_absent_with_lineage;
use super::test_handle;
use crate::InstallationCoordinator;
use crate::InstallationEffectAction;
use crate::InstallationEffectDisposition;
use crate::InstallationEffectObservation;
use crate::InstallationEffectProgressState;
use crate::InstallationServiceProcessLineage;
use crate::InstallationServiceStartProof;
use crate::InstallationStage;
use crate::InstallationStepOutcome;
use crate::InstallationTransaction;
use crate::InstallationTransactionStore;
use crate::InstallerEffectPlan;
use crate::InstallerServiceRole;
use crate::PortOutcome;
use crate::RedbInstallationTransactionStore;
use crate::TransactionVersion;
use crate::effect_request;
use crate::transaction_store_private;

#[cfg(windows)]
#[test]
fn start_service_never_duplicates_after_authoritative_receipt() {
    let transaction = pending_system_service_start_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let watchdog_index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let mut port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(start_absent(
            &transaction,
            watchdog_index,
            "service-stopped",
        ))],
        vec![PortOutcome::Known(matching_service_runtime(
            InstallationEffectDisposition::CreatedByTransaction,
            "external:effect-0",
        ))],
        execute_count.clone(),
    );
    configure_start_runtime_receipt(&mut port, "external:effect-0");
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    assert!(matches!(
        must(coordinator.drive_effect_at(&transaction_id, 1_000)),
        InstallationStepOutcome::Applied { .. }
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[watchdog_index].state,
        InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            ..
        }
    ));
}

#[cfg(windows)]
#[test]
fn start_service_already_running_is_preexisting_and_not_owned() {
    let transaction = pending_system_service_start_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let watchdog_index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(matching(
            InstallationEffectDisposition::PreexistingMatching,
        ))],
        Vec::new(),
        execute_count.clone(),
    );
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    assert!(matches!(
        must(coordinator.drive_effect_at(&transaction_id, 1_000)),
        InstallationStepOutcome::Applied { .. }
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[watchdog_index].state,
        InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::PreexistingMatching,
            ..
        }
    ));
}

#[cfg(windows)]
fn race_rollback_inputs(
    saved: &InstallationTransaction,
) -> (
    Vec<PortOutcome<InstallationEffectObservation>>,
    VecDeque<PortOutcome<bool>>,
) {
    let mut rollback_reconciliations = VecDeque::new();
    let mut secret_absence = VecDeque::new();
    for index in (0..saved.effect_progress.len()).rev() {
        let InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            ref external_identity,
            ..
        } = saved.effect_progress[index].state
        else {
            continue;
        };
        let _request = must(effect_request(
            saved,
            index,
            1,
            InstallationEffectAction::Rollback,
            Some(external_identity.clone()),
        ));
        rollback_reconciliations.push_back(PortOutcome::Known(
            InstallationEffectObservation::Matching {
                disposition: InstallationEffectDisposition::CreatedByTransaction,
                external_identity: external_identity.clone(),
                evidence: vec![test_handle(format!("evidence:rollback-match:{index}"))],
                postcondition_digest: test_handle(format!("{index:064x}")),
                service_control_grant: None,
                credential_receipt: None,
                staging_receipt: None,
                phase_b_receipt: None,
                service_runtime_lineage: None,
            },
        ));
        rollback_reconciliations.push_back(PortOutcome::Known(
            InstallationEffectObservation::Absent {
                observed_precondition: match absent_with_file_index(saved, index as u64) {
                    InstallationEffectObservation::Absent {
                        observed_precondition,
                        ..
                    } => observed_precondition,
                    InstallationEffectObservation::Matching { .. }
                    | InstallationEffectObservation::Mismatch { .. } => unreachable!(),
                },
                evidence: vec![test_handle(format!("evidence:rollback-absent:{index}"))],
                service_runtime_lineage: None,
            },
        ));
        if saved.effect_progress[index].ownership_secret.is_some() {
            secret_absence.push_back(PortOutcome::Known(true));
        }
    }
    (
        rollback_reconciliations.into_iter().collect(),
        secret_absence,
    )
}

#[cfg(windows)]
#[test]
fn start_service_race_already_running_never_becomes_owned_or_stopped() {
    let transaction = pending_system_service_start_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let watchdog_index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    let watchdog_effect_id = transaction.effect_progress[watchdog_index]
        .effect_id
        .clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let mut port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(start_absent(
            &transaction,
            watchdog_index,
            "service-stopped",
        ))],
        vec![PortOutcome::Known(
            InstallationEffectObservation::Matching {
                disposition: InstallationEffectDisposition::CreatedByTransaction,
                external_identity: test_handle("external:race-running"),
                evidence: vec![test_handle("evidence:race-running")],
                postcondition_digest: test_handle("a".repeat(64)),
                service_control_grant: None,
                credential_receipt: None,
                staging_receipt: None,
                phase_b_receipt: None,
                service_runtime_lineage: None,
            },
        )],
        execute_count.clone(),
    );
    let apply_executed = port.executed_effect_ids.clone();
    configure_start_already_running_execution(&mut port, "external:race-running");
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    let race_outcome = must(coordinator.drive_effect_at(&transaction_id, 1_000));
    assert!(matches!(
        race_outcome,
        InstallationStepOutcome::Applied { .. }
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
    assert_eq!(
        *apply_executed.lock().unwrap_or_else(|_| unreachable!()),
        vec![watchdog_effect_id.clone()]
    );
    let mut saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[watchdog_index].state,
        InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::PreexistingMatching,
            ..
        }
    ));

    // Force recovery after the race.  Rollback must skip the raced start
    // even when its authoritative readback reports the generic Created
    // disposition from the provider-neutral observation seam.
    saved.stage = InstallationStage::RollbackRequired;
    saved.pending_external_changes = vec![test_handle("pending:race-running")];
    saved.revision += 1;
    must(saved.validate());
    *store.state.lock().unwrap_or_else(|_| unreachable!()) = Some(saved.clone());

    let (rollback_reconciliations, secret_absence) = race_rollback_inputs(&saved);
    let rollback_store = SharedStore {
        state: store.state.clone(),
        ..SharedStore::default()
    };
    let rollback_count = Arc::new(Mutex::new(0));
    let mut rollback_port = fake_port(
        rollback_store.clone(),
        Vec::new(),
        rollback_reconciliations.into_iter().collect(),
        rollback_count,
    );
    rollback_port.secret_absence = secret_absence;
    let rollback_executed = rollback_port.executed_effect_ids.clone();
    let mut rollback_coordinator = InstallationCoordinator::new(rollback_port, rollback_store);
    assert!(matches!(
        must(rollback_coordinator.rollback(&transaction_id)),
        InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack,
            ..
        }
    ));
    assert!(
        !rollback_executed
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .iter()
            .any(|effect_id| effect_id == &watchdog_effect_id)
    );
}

#[cfg(windows)]
#[test]
fn start_service_race_already_starting_is_unknown_and_never_owned() {
    let transaction = pending_system_service_start_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let watchdog_index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let mut port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(start_absent(
            &transaction,
            watchdog_index,
            "service-stopped",
        ))],
        Vec::new(),
        execute_count.clone(),
    );
    configure_start_already_starting_execution(&mut port);
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    assert!(matches!(
        must(coordinator.drive_effect_at(&transaction_id, 1_000)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[watchdog_index].state,
        InstallationEffectProgressState::Unknown { .. }
    ));
    assert!(
        saved.effect_progress[watchdog_index]
            .service_start_proof
            .is_none()
    );
}

#[cfg(windows)]
#[test]
fn start_service_absent_fails_closed_without_start_intent() {
    let transaction = pending_system_service_start_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(
            InstallationEffectObservation::Mismatch {
                pending_ref: test_handle("service-missing:watchdog"),
            },
        )],
        Vec::new(),
        execute_count.clone(),
    );
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    assert!(matches!(
        must(coordinator.drive_effect_at(&transaction_id, 1_000)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[index].state,
        InstallationEffectProgressState::Unknown { .. }
    ));
    assert!(
        saved.effect_progress[index]
            .service_start_deadline_ms
            .is_none()
    );
}

#[cfg(windows)]
#[test]
fn start_service_response_loss_blocks_retry_without_ownership_inference() {
    let transaction = pending_system_service_start_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let watchdog_index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let mut port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(start_absent(
            &transaction,
            watchdog_index,
            "service-stopped",
        ))],
        Vec::new(),
        execute_count.clone(),
    );
    port.execute_outcomes.push_back(PortOutcome::Unknown(
        eliot_platform::UnknownReason::Indeterminate,
    ));
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    assert!(matches!(
        must(coordinator.drive_effect_at(&transaction_id, 1_000)),
        InstallationStepOutcome::Rejected
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[watchdog_index].state,
        InstallationEffectProgressState::IntentCommitted { .. }
    ));
    drop(coordinator);
    let restart_store = SharedStore {
        state: store.state.clone(),
        ..SharedStore::default()
    };
    let restart_count = Arc::new(Mutex::new(0));
    let restart_port = fake_port(
        restart_store.clone(),
        Vec::new(),
        vec![PortOutcome::Known(matching_service_runtime(
            InstallationEffectDisposition::CreatedByTransaction,
            "external:foreign-restart",
        ))],
        restart_count.clone(),
    );
    let mut restarted = InstallationCoordinator::new(restart_port, restart_store.clone());
    assert!(matches!(
        must(restarted.drive_effect_at(&transaction_id, 2_000)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    assert_eq!(*restart_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(restart_store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[watchdog_index].state,
        InstallationEffectProgressState::Unknown { .. }
    ));
}

#[cfg(windows)]
#[test]
fn start_service_waits_on_starting_then_times_out_without_resend() {
    let mut transaction = pending_system_service_start_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    transaction.effect_progress[index].admitted_precondition =
        Some(pending_start_precondition(&transaction, index));
    transaction.effect_progress[index].service_start_deadline_ms = Some(2_000);
    let request = must(effect_request(
        &transaction,
        index,
        1,
        InstallationEffectAction::Apply,
        None,
    ));
    transaction.effect_progress[index].state = InstallationEffectProgressState::IntentCommitted {
        attempt: 1,
        intent_digest: must(request.intent_digest()),
    };
    transaction.revision += 1;
    must(transaction.validate());
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        Vec::new(),
        vec![PortOutcome::Known(start_absent(
            &transaction,
            index,
            "service-starting",
        ))],
        execute_count.clone(),
    );
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    assert!(matches!(
        must(coordinator.drive_effect_at(&transaction_id, 1_500)),
        InstallationStepOutcome::Rejected
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    assert!(matches!(
        must(coordinator.drive_effect_at(&transaction_id, 2_000)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
}

#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "this test covers durable START_PENDING restart and no-resend convergence"
)]
fn start_service_starting_without_pid_preserves_intent_until_running() {
    let transaction = pending_system_service_start_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let mut port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(start_absent(
            &transaction,
            index,
            "service-stopped",
        ))],
        Vec::new(),
        execute_count.clone(),
    );
    configure_start_waiting_execution(&mut port);
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    assert!(matches!(
        must(coordinator.drive_effect_at(&transaction_id, 1_000)),
        InstallationStepOutcome::Rejected
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[index].state,
        InstallationEffectProgressState::IntentCommitted { .. }
    ));
    assert_eq!(
        saved.effect_progress[index].service_start_deadline_ms,
        Some(31_000)
    );
    assert_eq!(
        saved.effect_progress[index]
            .service_start_proof
            .as_ref()
            .map(|proof| proof.intent_digest.clone()),
        match &saved.effect_progress[index].state {
            InstallationEffectProgressState::IntentCommitted { intent_digest, .. } => {
                Some(intent_digest.clone())
            }
            _ => None,
        }
    );
    let started_intent_digest = match &saved.effect_progress[index].state {
        InstallationEffectProgressState::IntentCommitted { intent_digest, .. } => {
            intent_digest.clone()
        }
        _ => unreachable!(),
    };

    let restart_store = SharedStore {
        state: store.state.clone(),
        ..SharedStore::default()
    };
    let restart_count = Arc::new(Mutex::new(0));
    let restart_port = fake_port(
        restart_store.clone(),
        Vec::new(),
        vec![PortOutcome::Known(start_absent(
            &transaction,
            index,
            "service-starting",
        ))],
        restart_count.clone(),
    );
    let mut restarted = InstallationCoordinator::new(restart_port, restart_store.clone());
    assert!(matches!(
        must(restarted.drive_effect_at(&transaction_id, 2_000)),
        InstallationStepOutcome::Rejected
    ));
    assert_eq!(*restart_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(restart_store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[index].state,
        InstallationEffectProgressState::IntentCommitted { .. }
    ));
    assert_eq!(
        saved.effect_progress[index]
            .service_start_proof
            .as_ref()
            .map(|proof| proof.intent_digest.clone()),
        match &saved.effect_progress[index].state {
            InstallationEffectProgressState::IntentCommitted { intent_digest, .. } => {
                Some(intent_digest.clone())
            }
            _ => None,
        }
    );

    let running_count = Arc::new(Mutex::new(0));
    let running_port = fake_port(
        restart_store.clone(),
        Vec::new(),
        vec![PortOutcome::Known(matching(
            InstallationEffectDisposition::CreatedByTransaction,
        ))],
        running_count.clone(),
    );
    let mut running_restarted = InstallationCoordinator::new(running_port, restart_store.clone());
    assert!(matches!(
        must(running_restarted.drive_effect_at(&transaction_id, 2_500)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    assert_eq!(*running_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(restart_store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[index].state,
        InstallationEffectProgressState::Unknown { .. }
    ));
    assert_eq!(
        saved.effect_progress[index]
            .service_start_proof
            .as_ref()
            .map(|proof| proof.intent_digest.clone()),
        Some(started_intent_digest)
    );
}

#[cfg(windows)]
#[test]
#[allow(clippy::too_many_lines)]
fn start_pending_nonzero_lineage_is_durable_and_required_for_running() {
    let transaction = pending_system_service_start_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    let lineage = InstallationServiceProcessLineage {
        process_id: 17,
        start_time_100ns: 23,
        image_path: test_handle(r"C:\Eliot\host.exe"),
    };
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let mut port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(start_absent(
            &transaction,
            index,
            "service-stopped",
        ))],
        vec![PortOutcome::Known(start_absent_with_lineage(
            &transaction,
            index,
            "service-starting",
            lineage.clone(),
        ))],
        execute_count.clone(),
    );
    configure_start_waiting_execution_with_lineage(&mut port, lineage.clone());
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    assert!(matches!(
        must(coordinator.drive_effect_at(&transaction_id, 1_000)),
        InstallationStepOutcome::Rejected
    ));
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(
        saved.effect_progress[index]
            .service_start_proof
            .as_ref()
            .and_then(|proof| proof.process_lineage.clone()),
        Some(lineage.clone())
    );
    drop(coordinator);

    let restart_count = Arc::new(Mutex::new(0));
    let restart_port = fake_port(
        store.clone(),
        Vec::new(),
        vec![PortOutcome::Known(matching_service_runtime(
            InstallationEffectDisposition::CreatedByTransaction,
            "external:lineage-running",
        ))],
        restart_count.clone(),
    );
    let mut restarted = InstallationCoordinator::new(restart_port, store.clone());
    assert!(matches!(
        must(restarted.drive_effect_at(&transaction_id, 2_000)),
        InstallationStepOutcome::Applied { .. }
    ));
    assert_eq!(*restart_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[index].state,
        InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            ..
        }
    ));
}

#[cfg(windows)]
#[test]
#[allow(clippy::too_many_lines)]
fn start_pending_pid_zero_physical_redb_restart_foreign_running_quarantines_without_stop() {
    let transaction = registering_system_service_start_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    let planned = must(InstallationTransaction::new(
        transaction.transaction_id.clone(),
        transaction.installation_epoch.clone(),
        transaction.profile,
        transaction.request.clone(),
        transaction.current_active_manifest.clone(),
        transaction.candidate_manifest.clone(),
        transaction.staging_root.clone(),
        transaction.planned_changes.clone(),
        transaction.installer_effects.clone(),
        transaction.minimum_store_available_bytes,
        transaction.precondition_evidence.clone(),
        transaction.recovery_command.clone(),
    ));
    let path = std::env::temp_dir().join(format!(
        "eliot-start-pending-lineage-redb-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let mut physical = must(
        RedbInstallationTransactionStore::create_unpublished_stage_fixture_at_exact_path(
            &path, &planned,
        ),
    );
    let expected = must(TransactionVersion::of(&planned));
    let mut registering = transaction.clone();
    registering.revision = expected.revision + 1;
    must(
        <RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
            &mut physical,
            expected,
            &registering,
        ),
    );
    let expected = must(TransactionVersion::of(&registering));
    let mut activating = registering.clone();
    must(activating.advance(
        InstallationStage::Activating,
        vec![test_handle("evidence:physical-start-pending")],
    ));
    must(
        <RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
            &mut physical,
            expected,
            &activating,
        ),
    );

    // The fake provider only supplies deterministic SCM outcomes; the
    // transaction and every state transition below are the physical redb
    // store used by the production coordinator.
    let shared_intent = {
        let mut intent = activating.clone();
        let request = must(effect_request(
            &intent,
            index,
            1,
            InstallationEffectAction::Apply,
            None,
        ));
        intent.effect_progress[index].state = InstallationEffectProgressState::IntentCommitted {
            attempt: 1,
            intent_digest: must(request.intent_digest()),
        };
        intent.effect_progress[index].service_start_deadline_ms = Some(31_000);
        intent
    };
    let shared = SharedStore {
        state: Arc::new(Mutex::new(Some(shared_intent))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let mut port = fake_port(
        shared.clone(),
        vec![PortOutcome::Known(start_absent(
            &activating,
            index,
            "service-stopped",
        ))],
        Vec::new(),
        execute_count,
    );
    configure_start_waiting_execution(&mut port);
    let mut coordinator = InstallationCoordinator::new(port, physical);
    assert!(matches!(
        must(coordinator.drive_effect_at(&transaction_id, 1_000)),
        InstallationStepOutcome::Rejected
    ));
    let saved = must(coordinator.store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[index].state,
        InstallationEffectProgressState::IntentCommitted { .. }
    ));
    assert!(
        saved.effect_progress[index]
            .service_start_proof
            .as_ref()
            .is_some_and(|proof| proof.process_lineage.is_none())
    );
    drop(coordinator);

    let reopened =
        must(RedbInstallationTransactionStore::open_unpublished_stage_fixture_exact_path(&path));
    let reopened_state = must(reopened.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(
        reopened_state.effect_progress[index]
            .service_start_proof
            .as_ref()
            .is_some_and(|proof| proof.process_lineage.is_none())
    );
    // The caller-issued PID-0 start may have stopped before this first
    // readback, after which another actor starts the unchanged service.
    // A new coordinator must reject that foreign Running lineage: the
    // durable proof contains no prior process identity to adopt.
    let restart_count = Arc::new(Mutex::new(0));
    let restart_port = fake_port(
        SharedStore {
            state: Arc::new(Mutex::new(Some(reopened_state.clone()))),
            ..SharedStore::default()
        },
        Vec::new(),
        vec![PortOutcome::Known(matching_service_runtime(
            InstallationEffectDisposition::CreatedByTransaction,
            "external:foreign-restart",
        ))],
        restart_count.clone(),
    );
    let mut restarted = InstallationCoordinator::new(restart_port, reopened);
    assert!(matches!(
        must(restarted.drive_effect_at(&transaction_id, 2_500)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    assert_eq!(*restart_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    assert!(matches!(
        must(restarted.rollback(&transaction_id)),
        InstallationStepOutcome::Quarantined { .. }
    ));
    assert_eq!(*restart_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let quarantined = must(restarted.store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(quarantined.stage(), InstallationStage::Quarantined);
    let _ = std::fs::remove_file(path);
}

#[cfg(windows)]
#[test]
fn serialized_redb_foreign_replacement_lineage_never_rolls_back_foreign_service() {
    let mut transaction = pending_system_service_start_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    transaction.effect_progress[index].admitted_precondition =
        Some(pending_start_precondition(&transaction, index));
    transaction.effect_progress[index].service_start_deadline_ms = Some(31_000);
    transaction.effect_progress[index].service_start_proof = Some(InstallationServiceStartProof {
        intent_digest: test_handle("2".repeat(64)),
        process_lineage: Some(InstallationServiceProcessLineage {
            process_id: 17,
            start_time_100ns: 23,
            image_path: test_handle(r"C:\Eliot\host.exe"),
        }),
    });
    transaction.effect_progress[index].state = InstallationEffectProgressState::Applied {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity: test_handle("external:owned-start"),
        evidence: vec![test_handle("evidence:owned-start")],
        postcondition_digest: test_handle("3".repeat(64)),
    };
    transaction.stage = InstallationStage::RollbackRequired;
    transaction.pending_external_changes = vec![test_handle("pending:foreign-replacement")];
    transaction.revision += 1;
    must(transaction.validate());

    let planned = must(InstallationTransaction::new(
        transaction.transaction_id.clone(),
        transaction.installation_epoch.clone(),
        transaction.profile,
        transaction.request.clone(),
        transaction.current_active_manifest.clone(),
        transaction.candidate_manifest.clone(),
        transaction.staging_root.clone(),
        transaction.planned_changes.clone(),
        transaction.installer_effects.clone(),
        transaction.minimum_store_available_bytes,
        transaction.precondition_evidence.clone(),
        transaction.recovery_command.clone(),
    ));
    let path = std::env::temp_dir().join(format!(
        "eliot-foreign-replacement-redb-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let mut physical = must(
        RedbInstallationTransactionStore::create_unpublished_stage_fixture_at_exact_path(
            &path, &planned,
        ),
    );
    let expected = must(TransactionVersion::of(&planned));
    let mut persisted = transaction.clone();
    persisted.revision = expected.revision + 1;
    must(
        <RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
            &mut physical,
            expected,
            &persisted,
        ),
    );
    drop(physical);
    let physical =
        must(RedbInstallationTransactionStore::open_unpublished_stage_fixture_exact_path(&path));
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        SharedStore::default(),
        Vec::new(),
        vec![PortOutcome::Known(matching_service_runtime(
            InstallationEffectDisposition::CreatedByTransaction,
            "external:foreign-replacement",
        ))],
        execute_count.clone(),
    );
    let mut coordinator = InstallationCoordinator::new(port, physical);
    assert!(matches!(
        must(coordinator.rollback(&transaction_id)),
        InstallationStepOutcome::Quarantined { .. }
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    assert_eq!(
        must(coordinator.store.load(&transaction_id))
            .unwrap_or_else(|| unreachable!())
            .stage(),
        InstallationStage::Quarantined
    );
    let _ = std::fs::remove_file(path);
}

#[cfg(windows)]
#[test]
fn start_service_pid_substitution_and_watchdog_failure_block_host() {
    let transaction = pending_system_service_start_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let watchdog_index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let mut port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(start_absent(
            &transaction,
            watchdog_index,
            "service-stopped",
        ))],
        vec![PortOutcome::Known(matching(
            InstallationEffectDisposition::CreatedByTransaction,
        ))],
        execute_count.clone(),
    );
    configure_start_runtime_receipt(&mut port, "external:substituted");
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    assert!(matches!(
        must(coordinator.drive_effect_at(&transaction_id, 1_000)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[watchdog_index].state,
        InstallationEffectProgressState::Unknown { .. }
    ));
    let host_index = saved
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Host,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[host_index].state,
        InstallationEffectProgressState::Pending
    ));

    let mut blocked = pending_system_service_start_transaction();
    blocked.pending_external_changes = vec![test_handle("pending:watchdog")];
    blocked.stage = InstallationStage::RollbackRequired;
    blocked.revision += 1;
    let blocked_id = blocked.transaction_id.clone();
    must(blocked.validate());
    let blocked_store = SharedStore {
        state: Arc::new(Mutex::new(Some(blocked.clone()))),
        ..SharedStore::default()
    };
    let blocked_count = Arc::new(Mutex::new(0));
    let blocked_port = fake_port(
        blocked_store.clone(),
        vec![PortOutcome::Unknown(
            eliot_platform::UnknownReason::Indeterminate,
        )],
        Vec::new(),
        blocked_count.clone(),
    );
    let mut blocked_coordinator = InstallationCoordinator::new(blocked_port, blocked_store);
    assert!(matches!(
        must(blocked_coordinator.drive_effect_at(&blocked_id, 1_000)),
        InstallationStepOutcome::Rejected
    ));
    assert_eq!(*blocked_count.lock().unwrap_or_else(|_| unreachable!()), 0);
}

#[cfg(windows)]
#[test]
fn foreign_service_rollback_quarantines_without_stop() {
    let mut transaction = pending_system_service_start_transaction();
    let index = transaction
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    transaction.effect_progress[index].admitted_precondition =
        Some(pending_start_precondition(&transaction, index));
    transaction.effect_progress[index].service_start_deadline_ms = Some(31_000);
    transaction.effect_progress[index].service_start_proof = Some(InstallationServiceStartProof {
        intent_digest: test_handle("2".repeat(64)),
        process_lineage: Some(InstallationServiceProcessLineage {
            process_id: 17,
            start_time_100ns: 23,
            image_path: test_handle(r"C:\Eliot\host.exe"),
        }),
    });
    transaction.effect_progress[index].state = InstallationEffectProgressState::Applied {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity: test_handle("external:owned-start"),
        evidence: vec![test_handle("evidence:start")],
        postcondition_digest: test_handle("3".repeat(64)),
    };
    transaction.stage = InstallationStage::RollbackRequired;
    transaction.pending_external_changes = vec![test_handle("pending:foreign-service")];
    transaction.revision += 1;
    must(transaction.validate());
    let transaction_id = transaction.transaction_id.clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        Vec::new(),
        vec![PortOutcome::Known(
            InstallationEffectObservation::Mismatch {
                pending_ref: test_handle("foreign-service-observed"),
            },
        )],
        execute_count.clone(),
    );
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    assert!(matches!(
        must(coordinator.rollback(&transaction_id)),
        InstallationStepOutcome::Quarantined { .. }
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        &saved.effect_progress[index].state,
        InstallationEffectProgressState::Applied {
            external_identity,
            ..
        } if external_identity == &test_handle("external:owned-start")
    ));
}
