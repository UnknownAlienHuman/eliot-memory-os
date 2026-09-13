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
use super::test_secret_creation_proof;
#[cfg(windows)]
use super::test_secret_reference;
#[cfg(windows)]
use super::absent_with_file_index;
#[cfg(windows)]
use super::matching_for;
#[cfg(windows)]
use super::system_registration_transaction;
#[cfg(windows)]
use crate::CredentialAccessReceipt;
#[cfg(windows)]
use crate::CredentialOwnershipMarkerIdentity;
#[cfg(windows)]
use crate::InstallationOsObjectSnapshot;
#[cfg(windows)]
use crate::InstallationOwnershipSecret;
#[cfg(windows)]
use crate::InstallationRootAbsentSnapshot;
#[cfg(windows)]
use crate::InstallationSecretProvisionDisposition;
#[cfg(windows)]
use crate::InstallationServiceProcessLineage;
#[cfg(windows)]
use crate::InstallationServiceStartProof;
#[cfg(windows)]
use crate::PackageObservationSnapshot;
#[cfg(windows)]
use crate::PlatformHandle;
#[cfg(windows)]
use crate::StoreCredentialLifecycle;
#[cfg(windows)]
use crate::StoreCredentialProgress;
#[cfg(windows)]
use crate::credential_matching_response_digest;
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

/// s33.3 (#1313): distinct ownership-secret references for multi-secret
/// rollback. `test_ownership_secret` uses one fixed target, so two secrets in
/// one transaction would collide in `completed_stage_refs`
/// (`secret-absent:<target>` must be unique). This mirrors its construction
/// with a caller-chosen suffix.
#[cfg(windows)]
fn ownership_with_suffix(
    disposition: InstallationCreateDisposition,
    lifecycle: InstallationSecretLifecycle,
    suffix: &str,
) -> InstallationOwnershipSecret {
    InstallationOwnershipSecret {
        reference: test_secret_reference(suffix),
        create_disposition: disposition,
        secret_provision_disposition: match disposition {
            InstallationCreateDisposition::Created => {
                InstallationSecretProvisionDisposition::Created
            }
            InstallationCreateDisposition::NotAttempted
            | InstallationCreateDisposition::AlreadyExists => {
                InstallationSecretProvisionDisposition::NotAttempted
            }
        },
        creation_proof: test_secret_creation_proof(),
        lifecycle,
    }
}

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

/// s33.3 (#1313): rollback resumes from half-done through ALL effect kinds.
///
/// Extends `interrupted_service_rollback_resumes_after_first_delete` (services
/// + package) with the remaining production `Absent` shapes that blocked rc6
/// recover on rc4 with `INSTALLATION_RECOVER_ERROR absence snapshot`:
///
/// - `StartService` stopped `Absent` now carries a live OS snapshot (the
///   StartService analogue of #1308); strict `validate()` requires
///   os/credential/package.
/// - `StagePackage` `Absent` carries its `package_snapshot`; strict accepts
///   it after the s33.3 `validate()` fix (previously only os/credential).
/// - `ProvisionStoreCredential` delete-acknowledged `Absent` carries its
///   `credential_snapshot` via `with_credential_snapshot` (preserved admitted
///   or freshly re-observed `Inspect`); the `DeleteIntentCommitted =Absent=>`
///   `DeleteExecuted` transition is exercised here.
/// - one `CreateRoot` is promoted to `Applied CreatedByTransaction` so the
///   root contour (`os_snapshot`) is also exercised through `Absent=>continue`
///   plus the ownership-secret delete loop.
///
/// `MaterializePhaseB` stays `Pending` (skipped by the reverse loop by
/// design); an `Applied` Phase-B quarantines as retained authority before the
/// loop and can never report `RolledBack`.
///
/// Rollback rev-visits `Provision, Start Host, Start Watchdog, Register
/// Watchdog, Register Host (Matching=>execute=>Absent, the single execute),
/// StagePackage, root`, collecting the credential absence ref, deleting both
/// ownership secrets (`secret_absence=true` twice, forward order), and
/// reaching terminal `RolledBack`. A foreign Host identity would miss the
/// identity guard and quarantine instead.
#[cfg(windows)]
#[test]
fn interrupted_rollback_resumes_through_all_effect_kinds() {
    let mut transaction = system_registration_transaction();

    let find_effect = |transaction: &InstallationTransaction,
                       predicate: &dyn Fn(&InstallerEffectPlan) -> bool| {
        transaction
            .installer_effects
            .iter()
            .position(predicate)
            .unwrap_or_else(|| unreachable!())
    };
    let root_index = find_effect(
        &transaction,
        &|effect| matches!(effect, InstallerEffectPlan::CreateRoot { .. }),
    );
    let package_index = find_effect(
        &transaction,
        &|effect| matches!(effect, InstallerEffectPlan::StagePackage { .. }),
    );
    let host_reg_index = find_effect(
        &transaction,
        &|effect| {
            matches!(
                effect,
                InstallerEffectPlan::RegisterService {
                    role: InstallerServiceRole::Host,
                    ..
                }
            )
        },
    );
    let watchdog_reg_index = find_effect(
        &transaction,
        &|effect| {
            matches!(
                effect,
                InstallerEffectPlan::RegisterService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        },
    );
    let provision_index = find_effect(
        &transaction,
        &|effect| matches!(effect, InstallerEffectPlan::ProvisionStoreCredential { .. }),
    );
    let watchdog_start_index = find_effect(
        &transaction,
        &|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        },
    );
    let host_start_index = find_effect(
        &transaction,
        &|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Host,
                    ..
                }
            )
        },
    );
    // Rollback rev-iterates `CreatedByTransaction`, so the stuck-rc4 shape
    // (Watchdog service deleted first, Host deleted by this recover) requires
    // this exact ascending order; rev then visits Provision first and the
    // root last. (Provision follows both Starts in `installer_plan_parts`, so
    // rev visits Provision, then Start Host, then Start Watchdog.)
    assert!(
        root_index < package_index
            && package_index < host_reg_index
            && host_reg_index < watchdog_reg_index
            && watchdog_reg_index < watchdog_start_index
            && watchdog_start_index < host_start_index
            && host_start_index < provision_index,
        "all-kinds rollback order must rev-visit Provision, Start Host, Start \
         Watchdog, Register Watchdog, Register Host, StagePackage, root"
    );

    // StartService both to Applied CreatedByTransaction (admitted None is
    // allowed for Register/Start per `validate_effect_progress`; the nonce is
    // mandatory and is copied from the matching registration).
    for (start_index, role) in [
        (watchdog_start_index, InstallerServiceRole::Watchdog),
        (host_start_index, InstallerServiceRole::Host),
    ] {
        let nonce = transaction
            .installer_effects
            .iter()
            .zip(&transaction.effect_progress)
            .find_map(|(effect, progress)| match effect {
                InstallerEffectPlan::RegisterService {
                    role: registered_role,
                    ..
                } if registered_role == &role => progress.registration_nonce.clone(),
                _ => None,
            })
            .unwrap_or_else(|| unreachable!());
        transaction.effect_progress[start_index].registration_nonce = Some(nonce);
        transaction.effect_progress[start_index].service_start_deadline_ms = Some(30_000);
        transaction.effect_progress[start_index].service_start_proof =
            Some(InstallationServiceStartProof {
                intent_digest: test_handle("2".repeat(64)),
                process_lineage: Some(InstallationServiceProcessLineage {
                    process_id: 17,
                    start_time_100ns: 23,
                    image_path: test_handle(r"C:\Eliot\host.exe"),
                }),
            });
        transaction.effect_progress[start_index].state =
            InstallationEffectProgressState::Applied {
                disposition: InstallationEffectDisposition::CreatedByTransaction,
                external_identity: test_handle(format!("external:start:{role:?}")),
                evidence: vec![test_handle(format!("evidence:start:{role:?}"))],
                postcondition_digest: test_handle("2".repeat(64)),
            };
    }

    // Provision to Applied CreatedByTransaction with a credential snapshot,
    // ownership, and DeleteIntentCommitted store progress (so the Absent arm
    // transitions DeleteIntentCommitted=>DeleteExecuted and the terminal
    // DeleteExecuted=>Deleted passes instead of failing on Active=>Deleted).
    {
        let provision = match &transaction.installer_effects[provision_index].clone() {
            InstallerEffectPlan::ProvisionStoreCredential { provision, .. } => provision.clone(),
            _ => unreachable!(),
        };
        let change = transaction
            .planned_changes
            .iter()
            .find(|change| {
                change.change_id == transaction.effect_progress[provision_index].effect_id
            })
            .cloned()
            .unwrap_or_else(|| unreachable!());
        let marker = CredentialOwnershipMarkerIdentity {
            canonical_path_digest: test_handle("a".repeat(64)),
            volume_serial_number: 1,
            file_index: 41,
            security_descriptor_digest: test_handle("b".repeat(64)),
        };
        let host_owner_epoch = test_handle("host-owner:system");
        let host_process_identity = test_handle("c".repeat(64));
        let request_digest = test_handle("d".repeat(64));
        let credential_envelope_digest = test_handle("e".repeat(64));
        let response_digest = must(credential_matching_response_digest(
            &request_digest,
            &host_owner_epoch,
            &host_process_identity,
            &marker,
            &credential_envelope_digest,
        ));
        let snapshot = crate::StoreCredentialAbsentSnapshot {
            host_owner_epoch: host_owner_epoch.clone(),
            host_process_identity: host_process_identity.clone(),
            host_state_root: marker.clone(),
            marker_path_digest: test_handle("f".repeat(64)),
            marker_absent: true,
            target_absent: true,
        };
        transaction.effect_progress[provision_index].admitted_precondition = Some(must(
            must(InstallationEffectPrecondition::from_change(&change))
                .with_credential_snapshot(snapshot),
        ));
        transaction.effect_progress[provision_index].ownership_secret =
            Some(ownership_with_suffix(
                InstallationCreateDisposition::Created,
                InstallationSecretLifecycle::Active,
                "0123456789abcdef0123456789abcdef",
            ));
        transaction.effect_progress[provision_index].store_credential =
            Some(StoreCredentialProgress {
                lifecycle: StoreCredentialLifecycle::DeleteIntentCommitted,
                receipt: Some(CredentialAccessReceipt {
                    transaction_id: transaction.transaction_id.clone(),
                    effect_id: transaction.effect_progress[provision_index].effect_id.clone(),
                    generation: provision.generation,
                    config_digest: provision.config_digest.clone(),
                    target: provision.target.clone(),
                    provider: provision.provider,
                    scope: provision.scope,
                    principal_sid: provision.expected_principal_sid.clone(),
                    host_owner_epoch,
                    host_process_identity,
                    marker,
                    credential_envelope_digest,
                    request_digest,
                    response_digest,
                }),
            });
        transaction.effect_progress[provision_index].state =
            InstallationEffectProgressState::Applied {
                disposition: InstallationEffectDisposition::CreatedByTransaction,
                external_identity: test_handle("external:credential-all-kinds"),
                evidence: vec![test_handle("evidence:credential-all-kinds")],
                postcondition_digest: test_handle("1".repeat(64)),
            };
    }

    // One root to Applied CreatedByTransaction with an OS snapshot plus
    // ownership (required for CreateRoot Applied per `validate_effect_progress`).
    {
        let change = transaction
            .planned_changes
            .iter()
            .find(|change| {
                change.change_id == transaction.effect_progress[root_index].effect_id
            })
            .cloned()
            .unwrap_or_else(|| unreachable!());
        let object = InstallationOsObjectSnapshot {
            canonical_path_digest: test_handle("b".repeat(64)),
            volume_serial_number: 1,
            file_index: 43,
            security_descriptor_digest: test_handle("c".repeat(64)),
        };
        let snapshot = InstallationRootAbsentSnapshot {
            target_path_digest: test_handle("d".repeat(64)),
            profile_anchor: object.clone(),
            ancestors: vec![object.clone()],
            parent: object,
            root_absent: true,
        };
        transaction.effect_progress[root_index].admitted_precondition = Some(must(
            must(InstallationEffectPrecondition::from_change(&change)).with_os_snapshot(snapshot),
        ));
        transaction.effect_progress[root_index].ownership_secret = Some(ownership_with_suffix(
            InstallationCreateDisposition::Created,
            InstallationSecretLifecycle::Active,
            "fedcba9876543210fedcba9876543210",
        ));
        transaction.effect_progress[root_index].state = InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            external_identity: test_handle("external:root-all-kinds"),
            evidence: vec![test_handle("evidence:root-all-kinds")],
            postcondition_digest: test_handle("e".repeat(64)),
        };
    }

    // Production-shape Absents for every visited kind. OS-snapshot Absents
    // reuse the `absent_with_file_index` contour (rollback only applies the
    // strict gate to the observation itself, not evidence-refs equality, so
    // the shared test contour is sufficient); the package Absent carries its
    // real `package_snapshot` (generation-bound source readback) and the
    // credential Absent carries its real `credential_snapshot`.
    let start_host_absent = absent_with_file_index(&transaction, 21);
    must(start_host_absent.validate());
    let start_watchdog_absent = absent_with_file_index(&transaction, 22);
    must(start_watchdog_absent.validate());
    let watchdog_absent = absent_with_file_index(&transaction, 23);
    must(watchdog_absent.validate());
    let host_absent_after_delete = absent_with_file_index(&transaction, 24);
    must(host_absent_after_delete.validate());
    let root_absent = absent_with_file_index(&transaction, 25);
    must(root_absent.validate());

    let package_absent = {
        let (source_bundle_identity, generation, manifest_digest) =
            match &transaction.installer_effects[package_index] {
                InstallerEffectPlan::StagePackage {
                    source_bundle_identity,
                    generation,
                    manifest,
                    ..
                } => (
                    *source_bundle_identity,
                    generation.clone(),
                    must(PlatformHandle::new(manifest.canonical_digest())),
                ),
                _ => unreachable!(),
            };
        let change = transaction
            .planned_changes
            .iter()
            .find(|change| {
                change.change_id == transaction.effect_progress[package_index].effect_id
            })
            .cloned()
            .unwrap_or_else(|| unreachable!());
        let files = Vec::new();
        let total_bytes = 0;
        let digest = must(PackageObservationSnapshot::compute_digest(
            &source_bundle_identity,
            &generation,
            &manifest_digest,
            &files,
            total_bytes,
        ));
        let snapshot = PackageObservationSnapshot {
            source_bundle_identity,
            generation,
            manifest_digest,
            files,
            total_bytes,
            digest,
        };
        let observed_precondition = must(
            must(InstallationEffectPrecondition::from_change(&change))
                .with_package_snapshot(snapshot),
        );
        let observation = InstallationEffectObservation::Absent {
            observed_precondition,
            evidence: vec![test_handle("evidence:package-absent-all-kinds")],
            service_runtime_lineage: None,
        };
        must(observation.validate());
        observation
    };

    let provision_absent = {
        let change = transaction
            .planned_changes
            .iter()
            .find(|change| {
                change.change_id == transaction.effect_progress[provision_index].effect_id
            })
            .cloned()
            .unwrap_or_else(|| unreachable!());
        let marker = CredentialOwnershipMarkerIdentity {
            canonical_path_digest: test_handle("a".repeat(64)),
            volume_serial_number: 1,
            file_index: 41,
            security_descriptor_digest: test_handle("b".repeat(64)),
        };
        let snapshot = crate::StoreCredentialAbsentSnapshot {
            host_owner_epoch: test_handle("host-owner:system"),
            host_process_identity: test_handle("c".repeat(64)),
            host_state_root: marker,
            marker_path_digest: test_handle("f".repeat(64)),
            marker_absent: true,
            target_absent: true,
        };
        let observed_precondition = must(
            must(InstallationEffectPrecondition::from_change(&change))
                .with_credential_snapshot(snapshot),
        );
        let observation = InstallationEffectObservation::Absent {
            observed_precondition,
            evidence: vec![test_handle("evidence:credential-absent-all-kinds")],
            service_runtime_lineage: None,
        };
        must(observation.validate());
        observation
    };

    // Host Matching must carry the exact durable external identity, otherwise
    // the rollback identity guard quarantines instead of deleting.
    let host_expected = match &transaction.effect_progress[host_reg_index].state {
        InstallationEffectProgressState::Applied {
            external_identity, ..
        } => external_identity.clone(),
        _ => unreachable!(),
    };
    let mut host_matching = matching_for(
        &transaction.installer_effects[host_reg_index],
        host_reg_index,
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
        vec![test_handle("pending:interrupted-all-kinds-rollback")];
    transaction.revision += 1;
    must(transaction.validate());
    let transaction_id = transaction.transaction_id.clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    // Rev order: Provision Absent (DeleteIntentCommitted=>DeleteExecuted, no
    // execute), Start Host Absent, Start Watchdog Absent, Watchdog Absent,
    // Host Matching=>execute delete=>Absent (one execute), package Absent,
    // root Absent.
    let mut port = fake_port(
        store.clone(),
        Vec::new(),
        vec![
            PortOutcome::Known(provision_absent),
            PortOutcome::Known(start_host_absent),
            PortOutcome::Known(start_watchdog_absent),
            PortOutcome::Known(watchdog_absent),
            PortOutcome::Known(host_matching),
            PortOutcome::Known(host_absent_after_delete),
            PortOutcome::Known(package_absent),
            PortOutcome::Known(root_absent),
        ],
        execute_count.clone(),
    );
    // Both ownership secrets (root forward-first, then provision) are already
    // absent: no secret delete call, just absence evidence.
    port.secret_absence =
        vec![PortOutcome::Known(true), PortOutcome::Known(true)].into();
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    assert!(matches!(
        must(coordinator.rollback(&transaction_id)),
        InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack,
            ..
        }
    ));
    // Only the Host Matching=>delete arm may execute; every Absent=>continue
    // arm (Start x2, credential, Watchdog, package, root) must not execute. A
    // foreign identity would miss the identity guard and quarantine instead
    // of reaching RolledBack.
    assert_eq!(
        *execute_count.lock().unwrap_or_else(|_| unreachable!()),
        1,
        "only the Host Matching=>delete arm may execute across all effect kinds"
    );
    let terminal = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(terminal.stage, InstallationStage::RolledBack);
    must(terminal.validate());
}
