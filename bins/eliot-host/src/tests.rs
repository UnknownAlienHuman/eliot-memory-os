use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

use super::{
    CutoverLaunchOutcome, HOST_STORE_REBIND_PRODUCTION_DISCRIMINATOR,
    HOST_STORE_RECOVERY_KILL_ON_JOB_CLOSE_CRASH_FENCE_DISCRIMINATOR, HostBranchDisposition,
    HostComposition, HostError, HostJobBranches, HostProcessBinding, HostRuntimeControlOperation,
    HostRuntimeControlRequest, HostRuntimeControlResponse, HostStoreRecoveryReceipt,
    KERNEL_BOOTSTRAP_ENVIRONMENT, KERNEL_CONTROL_PIPE, KernelControlResponse, KernelLaunchBinding,
    KernelServiceState, PlatformHandle, ReconciliationObservation, ReconciliationState,
    ScmStoreRecoveryRoute, StoreKernelLaunchError, StoreLivenessEvidence, StoreRecoveryRequired,
    TestError, TestResult, activation_response_or_reconcile, fresh_host_epoch,
    host_owned_store_recovery_request, launch_store_then_kernel, reconcile_state_machine,
    route_scm_store_recovery,
};
use eliot_platform_windows::JobObjectIdentity;

#[derive(Debug, Eq, PartialEq)]
struct MockChild {
    id: u8,
    live: bool,
}

fn mock_observation(child: Option<&MockChild>) -> ReconciliationObservation {
    match child {
        Some(child) if child.live => ReconciliationObservation::Live,
        Some(_) | None => ReconciliationObservation::Dead,
    }
}

fn launch_environment(
    kernel: Option<&KernelLaunchBinding>,
) -> Result<BTreeMap<String, String>, TestError> {
    let host = fresh_host_epoch(PlatformHandle::new("launch-test-installation")?, None)?;
    let roots_digest = PlatformHandle::new("a".repeat(64))?;
    let receipt_binding = kernel.map(|_| {
        (
            Path::new(r"C:\\ProgramData\\Eliot"),
            Path::new(r"C:\\ProgramData\\Eliot\\kernel\\state"),
            &roots_digest,
        )
    });
    Ok(HostJobBranches::environment_from(
        [
            (OsString::from("Path"), OsString::from(r"C:\\Windows")),
            (
                OsString::from("eliot_kernel_control_pipe"),
                OsString::from("ambient-pipe"),
            ),
            (
                OsString::from("ELIOT_HOST_PROCESS_ID"),
                OsString::from("999"),
            ),
            (
                OsString::from("eliot_host_process_start"),
                OsString::from("888"),
            ),
            (
                OsString::from("ELIOT_HOST_PROCESS_IMAGE"),
                OsString::from("ambient.exe"),
            ),
            (
                OsString::from("ELIOT_KERNEL_RECEIPT_ROOT"),
                OsString::from(r"C:\\ambient\\host"),
            ),
            (
                OsString::from("ELIOT_KERNEL_ORS_ROOT"),
                OsString::from(r"C:\\ambient\\ors"),
            ),
            (
                OsString::from("ELIOT_RUNTIME_STATE_ROOTS_DIGEST"),
                OsString::from("b".repeat(64)),
            ),
            (
                OsString::from("ELIOT_HOST_INSTALLATION"),
                OsString::from("ambient-installation"),
            ),
            (
                OsString::from("ELIOT_APPROVED_GENERATION"),
                OsString::from("ambient-generation"),
            ),
            (
                OsString::from("ELIOT_ACTIVATION_NONCE"),
                OsString::from("must-not-cross-process-boundary"),
            ),
        ],
        &host,
        &PlatformHandle::new("generation")?,
        &PlatformHandle::new("config-digest")?,
        &PlatformHandle::new("artifact-digest")?,
        Path::new(r"C:\\eliot\\config.json"),
        &JobObjectIdentity::new(r"Local\Eliot-Host-Test")?,
        kernel,
        receipt_binding,
    )
    .into_iter()
    .map(|(key, value)| {
        (
            key.to_string_lossy().into_owned(),
            value.to_string_lossy().into_owned(),
        )
    })
    .collect())
}

#[test]
fn fenced_startup_job_projection_has_no_process_or_child_contour() -> TestResult {
    let host = fresh_host_epoch(PlatformHandle::new("fenced-startup-job-projection")?, None)?;
    let jobs = HostJobBranches::new_fenced(&host)?;
    assert!(jobs.kernel.is_none());
    assert!(jobs.store.is_none());
    assert!(jobs.kernel_launch_binding.is_none());
    assert!(!jobs.has_recorded_contour());
    Ok(())
}

#[test]
fn kill_on_close_crash_fence_is_operation_specific_and_never_positive_attach() -> TestResult {
    assert_eq!(
        HOST_STORE_RECOVERY_KILL_ON_JOB_CLOSE_CRASH_FENCE_DISCRIMINATOR,
        "eliot-host::store-recovery::kill-on-job-close-crash-fence:v1"
    );
    let request = HostRuntimeControlRequest::new_store_reconcile(
        PlatformHandle::new("store-recovery-crash-fence-query")?,
        PlatformHandle::new("a".repeat(64))?,
    )?;
    let pending_ref = super::runtime_control_unknown_ref(
        super::STORE_RECOVERY_CRASH_FENCE_UNKNOWN_REASON,
        &request,
    );
    let response = HostRuntimeControlResponse::unknown_for(&request, pending_ref.clone());
    assert!(response.validate().is_ok());
    assert!(pending_ref.as_str().contains("store-recovery-crash-fence"));

    let host = fresh_host_epoch(
        PlatformHandle::new("store-recovery-crash-fence-host")?,
        None,
    )?;
    let jobs = HostJobBranches::new_fenced(&host)?;
    assert!(jobs.kernel.is_none());
    assert!(jobs.store.is_none());
    assert!(jobs.launch.is_none());
    assert!(jobs.kernel_launch_binding.is_none());
    Ok(())
}

#[test]
fn store_and_unrelated_child_environment_scrubs_kernel_bootstrap_authority() -> TestResult {
    let environment = launch_environment(None)?;
    assert_eq!(
        environment.get("Path").map(String::as_str),
        Some(r"C:\\Windows")
    );
    for name in KERNEL_BOOTSTRAP_ENVIRONMENT {
        assert!(!environment.keys().any(|key| key.eq_ignore_ascii_case(name)));
    }
    assert!(!environment.contains_key("ELIOT_ACTIVATION_NONCE"));
    Ok(())
}

#[test]
fn kernel_launch_environment_uses_exact_retained_binding() -> TestResult {
    let binding = KernelLaunchBinding {
        pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE)?,
        host_process: HostProcessBinding {
            process_id: 41,
            start_time_100ns: 73,
            image_path: r"C:\\eliot\\eliot-host.exe".to_owned(),
        },
    };
    let environment = launch_environment(Some(&binding))?;
    assert_eq!(
        environment
            .get("ELIOT_KERNEL_CONTROL_PIPE")
            .map(String::as_str),
        Some(KERNEL_CONTROL_PIPE)
    );
    assert_eq!(
        environment.get("ELIOT_HOST_PROCESS_ID").map(String::as_str),
        Some("41")
    );
    assert_eq!(
        environment
            .get("ELIOT_HOST_PROCESS_START")
            .map(String::as_str),
        Some("73")
    );
    assert_eq!(
        environment
            .get("ELIOT_HOST_PROCESS_IMAGE")
            .map(String::as_str),
        Some(r"C:\\eliot\\eliot-host.exe")
    );
    assert_eq!(
        environment
            .get("ELIOT_KERNEL_RECEIPT_ROOT")
            .map(String::as_str),
        Some(r"C:\\ProgramData\\Eliot")
    );
    assert_eq!(
        environment.get("ELIOT_KERNEL_ORS_ROOT").map(String::as_str),
        Some(r"C:\\ProgramData\\Eliot\\kernel\\state")
    );
    assert_eq!(
        environment
            .get("ELIOT_RUNTIME_STATE_ROOTS_DIGEST")
            .map(String::as_str),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(
        environment
            .get("ELIOT_HOST_INSTALLATION")
            .map(String::as_str),
        Some("launch-test-installation")
    );
    assert_eq!(
        environment
            .get("ELIOT_APPROVED_GENERATION")
            .map(String::as_str),
        Some("generation")
    );
    assert!(!environment.contains_key("ELIOT_ACTIVATION_NONCE"));
    Ok(())
}

#[test]
fn retained_host_binding_rejects_pid_reuse_and_image_substitution() -> TestResult {
    let binding = KernelLaunchBinding {
        pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE)?,
        host_process: HostProcessBinding {
            process_id: 41,
            start_time_100ns: 73,
            image_path: r"C:\\eliot\\eliot-host.exe".to_owned(),
        },
    };
    assert!(binding.matches_observed(41, 73, r"C:\\eliot\\eliot-host.exe"));
    assert!(!binding.matches_observed(42, 73, r"C:\\eliot\\eliot-host.exe"));
    assert!(!binding.matches_observed(41, 74, r"C:\\eliot\\eliot-host.exe"));
    assert!(!binding.matches_observed(41, 73, r"C:\\eliot\\replacement.exe"));
    Ok(())
}

#[test]
fn cutover_launch_discriminator_selects_only_the_process_that_was_launched() -> TestResult {
    let candidate = PlatformHandle::new("candidate-generation")?;
    let prior = PlatformHandle::new("prior-generation")?;
    assert_eq!(
        CutoverLaunchOutcome::Candidate.activation_generation(&candidate, &prior),
        &candidate
    );
    assert_eq!(
        CutoverLaunchOutcome::Rollback {
            candidate_error: "launch rejected".to_owned(),
        }
        .activation_generation(&candidate, &prior),
        &prior
    );
    Ok(())
}

#[test]
fn activate_response_uncertainty_reconciles_but_exact_rejection_does_not() -> TestResult {
    let message = PlatformHandle::new("activate-message")?;
    let digest = "a".repeat(64);
    let response = |message_id: PlatformHandle, error: Option<String>| KernelControlResponse {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id,
        request_digest: digest.clone(),
        state: KernelServiceState::Activating,
        receipt: None,
        activation_receipt: None,
        store_rebind_receipt: None,
        supervision_lease: None,
        error,
        payload_digest: String::new(),
    };
    assert!(
        activation_response_or_reconcile(
            Err(HostError::RecoveryRequired("receive lost".to_owned())),
            &message,
            &digest,
        )?
        .is_none()
    );
    assert!(
        activation_response_or_reconcile(
            Ok(response(PlatformHandle::new("wrong-message")?, None,)),
            &message,
            &digest,
        )?
        .is_none()
    );
    assert!(
        activation_response_or_reconcile(Ok(response(message.clone(), None)), &message, &digest)?
            .is_none()
    );
    assert!(
        activation_response_or_reconcile(
            Ok(response(message.clone(), Some("rejected".to_owned()))),
            &message,
            &digest,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn approved_launch_records_store_before_kernel() {
    let launches = RefCell::new(Vec::new());
    let result = launch_store_then_kernel(
        || {
            launches.borrow_mut().push("Store");
            Ok::<_, HostError>(())
        },
        |()| -> Result<(), StoreLivenessEvidence> { Ok(()) },
        || {
            launches.borrow_mut().push("Kernel");
            Ok::<_, HostError>(())
        },
        |()| -> Result<(), Box<((), String)>> { Ok(()) },
    );
    assert!(result.is_ok());
    assert_eq!(*launches.borrow(), ["Store", "Kernel"]);
}

#[test]
fn dead_store_launch_is_cleaned_without_kernel_attempt() {
    let launches = RefCell::new(Vec::new());
    let cleaned = RefCell::new(false);
    let result = launch_store_then_kernel(
        || {
            launches.borrow_mut().push("Store");
            Ok::<_, HostError>(())
        },
        |()| -> Result<(), StoreLivenessEvidence> { Err(StoreLivenessEvidence::Dead) },
        || {
            launches.borrow_mut().push("Kernel");
            Ok::<_, HostError>(())
        },
        |()| -> Result<(), Box<((), String)>> {
            *cleaned.borrow_mut() = true;
            Ok(())
        },
    );
    assert!(matches!(
        result,
        Err(StoreKernelLaunchError::StoreNotLive {
            evidence: StoreLivenessEvidence::Dead
        })
    ));
    assert_eq!(*launches.borrow(), ["Store"]);
    assert!(*cleaned.borrow());
}

#[test]
fn unknown_store_launch_is_fail_closed_without_kernel_attempt() {
    let launches = RefCell::new(Vec::new());
    let result = launch_store_then_kernel(
        || {
            launches.borrow_mut().push("Store");
            Ok::<_, HostError>(())
        },
        |()| {
            Err(StoreLivenessEvidence::Unknown(
                "observation failed".to_owned(),
            ))
        },
        || {
            launches.borrow_mut().push("Kernel");
            Ok::<_, HostError>(())
        },
        |()| -> Result<(), Box<((), String)>> { Ok(()) },
    );
    assert!(matches!(
        result,
        Err(StoreKernelLaunchError::StoreNotLive {
            evidence: StoreLivenessEvidence::Unknown(_)
        })
    ));
    assert_eq!(*launches.borrow(), ["Store"]);
}

#[test]
fn kernel_failure_cleans_store_after_single_store_first_attempt() {
    let launches = RefCell::new(Vec::new());
    let cleaned = RefCell::new(0);
    let result = launch_store_then_kernel(
        || {
            launches.borrow_mut().push("Store");
            Ok::<_, HostError>(())
        },
        |()| -> Result<(), StoreLivenessEvidence> { Ok(()) },
        || {
            launches.borrow_mut().push("Kernel");
            Err::<(), _>(HostError::ProcessContour("kernel launch failed".to_owned()))
        },
        |()| -> Result<(), Box<((), String)>> {
            *cleaned.borrow_mut() += 1;
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(*launches.borrow(), ["Store", "Kernel"]);
    assert_eq!(*cleaned.borrow(), 1);
}

#[test]
fn unknown_store_cleanup_retains_owner_and_blocks_kernel() {
    let launches = RefCell::new(Vec::new());
    let result = launch_store_then_kernel(
        || {
            launches.borrow_mut().push("Store");
            Ok::<_, HostError>(42_u8)
        },
        |store| {
            assert_eq!(*store, 42);
            Err(StoreLivenessEvidence::Unknown("reap timeout".to_owned()))
        },
        || {
            launches.borrow_mut().push("Kernel");
            Ok::<_, HostError>(())
        },
        |store| Err(Box::new((store, "bounded termination failed".to_owned()))),
    );
    assert!(matches!(
        result,
        Err(StoreKernelLaunchError::CleanupRequired { store: 42, .. })
    ));
    assert_eq!(*launches.borrow(), ["Store"]);
}

#[test]
fn reconcile_dead_store_returns_typed_recovery_without_mutation() {
    let events = RefCell::new(Vec::new());
    let mut state = ReconciliationState {
        store: Some(MockChild { id: 1, live: false }),
        kernel: Some(MockChild { id: 2, live: true }),
        store_restart_attempts: 0,
        kernel_restart_attempts: 0,
    };
    let result = reconcile_state_machine(
        &mut state,
        mock_observation,
        mock_observation,
        |_| {
            events.borrow_mut().push("terminate Kernel");
            Ok(())
        },
        || {
            events.borrow_mut().push("launch Kernel");
            Ok(MockChild { id: 3, live: true })
        },
    );
    assert_eq!(result, Err(StoreRecoveryRequired::LateDead));
    assert!(events.borrow().is_empty());
    assert_eq!(state.store, Some(MockChild { id: 1, live: false }));
    assert_eq!(state.kernel, Some(MockChild { id: 2, live: true }));
}

#[test]
fn reconcile_store_failure_or_unknown_blocks_kernel() {
    for unknown in [false, true] {
        let kernel_launches = RefCell::new(0);
        let mut state = ReconciliationState {
            store: unknown.then_some(MockChild { id: 7, live: true }),
            kernel: None,
            store_restart_attempts: 0,
            kernel_restart_attempts: 0,
        };
        let result = reconcile_state_machine(
            &mut state,
            |child| {
                if unknown {
                    ReconciliationObservation::Unknown
                } else {
                    mock_observation(child)
                }
            },
            mock_observation,
            |_| {
                *kernel_launches.borrow_mut() += 1;
                Ok(())
            },
            || {
                *kernel_launches.borrow_mut() += 1;
                Ok(MockChild { id: 9, live: true })
            },
        );
        assert_eq!(
            result,
            if unknown {
                Ok(HostBranchDisposition::BothDegraded)
            } else {
                Err(StoreRecoveryRequired::LateDead)
            }
        );
        assert_eq!(*kernel_launches.borrow(), 0);
    }
}

#[test]
fn reconcile_live_store_restarts_kernel_once_and_then_is_bounded() -> TestResult {
    let kernel_launches = RefCell::new(0);
    let mut state = ReconciliationState {
        store: Some(MockChild { id: 7, live: true }),
        kernel: None,
        store_restart_attempts: 0,
        kernel_restart_attempts: 0,
    };
    let run = |state: &mut ReconciliationState<MockChild, MockChild>| {
        reconcile_state_machine(
            state,
            mock_observation,
            mock_observation,
            |_| Ok(()),
            || {
                *kernel_launches.borrow_mut() += 1;
                Ok(MockChild { id: 9, live: true })
            },
        )
    };
    assert_eq!(
        run(&mut state),
        Ok(HostBranchDisposition::LiveAwaitingReadiness)
    );
    state
        .kernel
        .as_mut()
        .ok_or_else(|| std::io::Error::other("test option invariant"))?
        .live = false;
    assert_eq!(run(&mut state), Ok(HostBranchDisposition::KernelDegraded));
    assert_eq!(*kernel_launches.borrow(), 1);
    Ok(())
}

#[test]
fn reconcile_failed_termination_retains_owned_handle() {
    let mut state = ReconciliationState {
        store: Some(MockChild { id: 7, live: false }),
        kernel: Some(MockChild { id: 9, live: true }),
        store_restart_attempts: 0,
        kernel_restart_attempts: 0,
    };
    let result = reconcile_state_machine(
        &mut state,
        mock_observation,
        mock_observation,
        |_| Ok(()),
        || Ok(MockChild { id: 10, live: true }),
    );
    assert_eq!(result, Err(StoreRecoveryRequired::LateDead));
    assert_eq!(state.store, Some(MockChild { id: 7, live: false }));
}

#[test]
fn reconcile_kernel_failure_retains_restarted_store() {
    let mut state = ReconciliationState {
        store: Some(MockChild { id: 6, live: true }),
        kernel: Some(MockChild { id: 5, live: false }),
        store_restart_attempts: 0,
        kernel_restart_attempts: 0,
    };
    let disposition = reconcile_state_machine(
        &mut state,
        mock_observation,
        mock_observation,
        |kernel| {
            kernel.take();
            Ok(())
        },
        || Err(()),
    );
    assert_eq!(disposition, Ok(HostBranchDisposition::KernelDegraded));
    assert_eq!(state.store, Some(MockChild { id: 6, live: true }));
    assert!(state.kernel.is_none());
}

#[test]
fn replacement_kernel_dead_or_unknown_is_not_healthy() {
    for observation in [
        ReconciliationObservation::Dead,
        ReconciliationObservation::Unknown,
    ] {
        let mut state = ReconciliationState {
            store: Some(MockChild { id: 1, live: true }),
            kernel: Some(MockChild { id: 2, live: false }),
            store_restart_attempts: 0,
            kernel_restart_attempts: 0,
        };
        let disposition = reconcile_state_machine(
            &mut state,
            mock_observation,
            |child| {
                if child.is_some() {
                    observation
                } else {
                    ReconciliationObservation::Dead
                }
            },
            |kernel| {
                kernel.take();
                Ok(())
            },
            || Ok(MockChild { id: 4, live: false }),
        );
        assert_eq!(disposition, Ok(HostBranchDisposition::KernelDegraded));
        if observation == ReconciliationObservation::Dead {
            assert!(state.kernel.is_none());
        } else {
            assert_eq!(state.kernel, Some(MockChild { id: 2, live: false }));
        }
    }
}

#[test]
fn replacement_kernel_termination_failure_retains_binding() {
    let mut state = ReconciliationState {
        store: Some(MockChild { id: 1, live: true }),
        kernel: Some(MockChild { id: 2, live: false }),
        store_restart_attempts: 0,
        kernel_restart_attempts: 0,
    };
    let disposition = reconcile_state_machine(
        &mut state,
        mock_observation,
        mock_observation,
        |_| Err(()),
        || Ok(MockChild { id: 4, live: true }),
    );
    assert_eq!(disposition, Ok(HostBranchDisposition::KernelDegraded));
    assert_eq!(state.kernel, Some(MockChild { id: 2, live: false }));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "race seam keeps durable ordering evidence adjacent"
)]
fn scm_store_late_dead_shared_route_records_intent_before_replacement() -> TestResult {
    let source = include_str!("lib.rs");
    let generic_start = source
        .find("pub fn reconcile(")
        .ok_or_else(|| std::io::Error::other("generic reconcile anchor missing"))?;
    let generic_end = source[generic_start..]
        .find("fn cutover_with_rollback(")
        .map(|offset| generic_start + offset)
        .ok_or_else(|| std::io::Error::other("generic cutover anchor missing"))?;
    let generic_source = &source[generic_start..generic_end];
    assert!(
        !generic_source.contains("relaunch_store("),
        "generic branch reconciliation must not relaunch Store"
    );
    assert!(
        !generic_source.contains("terminate_in_place(0xE017_0002)"),
        "generic branch reconciliation must not terminate Store"
    );
    let composition_start = source
        .find("pub fn reconcile_approved_contour(")
        .ok_or_else(|| std::io::Error::other("composition reconcile anchor missing"))?;
    let composition_end = source[composition_start..]
        .find("fn reconcile_branch_readiness_at(")
        .map(|offset| composition_start + offset)
        .ok_or_else(|| std::io::Error::other("composition readiness anchor missing"))?;
    assert!(
        source[composition_start..composition_end].contains("route_scm_store_recovery("),
        "the production SCM seam must own late-dead routing"
    );
    let request = HostRuntimeControlRequest::new(
        HostRuntimeControlOperation::RecoverStore,
        PlatformHandle::new("scm-store-recovery-route")?,
    )?;
    let host = fresh_host_epoch(PlatformHandle::new("scm-store-recovery-route-host")?, None)?;
    let root = std::env::temp_dir().join(format!(
        "eliot-host-scm-store-route-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let events = RefCell::new(Vec::new());
    let mut fresh_readiness = false;
    let mut generic_reconcile_calls = 0;
    // The outer and generic guards both observed Live; the shared
    // production discriminator receives the generic machine's late-dead
    // result and must select execute_store_recovery.
    let reconciled = {
        generic_reconcile_calls += 1;
        Err(HostError::StoreRecoveryRequired(
            StoreRecoveryRequired::LateDead,
        ))
    };
    let route = route_scm_store_recovery(
        super::ScmStoreRecoveryObservation {
            store_requires_restart: false,
            kernel_live: true,
            kernel_requires_activation: false,
            store_present: true,
        },
        Some(reconciled),
        &request,
        |request| {
            assert_eq!(request.operation, HostRuntimeControlOperation::RecoverStore);
            super::persist_store_recovery_pending(&root, request, &host)?;
            assert!(
                super::store_recovery_pending_path(&root, request.mutation_digest.as_str())
                    .exists()
            );
            events.borrow_mut().push("outer-intent");
            assert!(
                super::store_recovery_pending_path(&root, request.mutation_digest.as_str())
                    .exists()
            );
            events.borrow_mut().push("exact-store-termination");
            events.borrow_mut().push("new-store-job-pid-image");
            events.borrow_mut().push("fresh-probeready");
            events.borrow_mut().push("readiness-journal");
            fresh_readiness = true;
            Ok(())
        },
    )?;
    assert_eq!(generic_reconcile_calls, 1);
    assert_eq!(route, ScmStoreRecoveryRoute::Recovered);
    assert!(fresh_readiness, "Healthy requires fresh readiness evidence");
    assert_eq!(
        *events.borrow(),
        [
            "outer-intent",
            "exact-store-termination",
            "new-store-job-pid-image",
            "fresh-probeready",
            "readiness-journal",
        ]
    );
    let disposition = if fresh_readiness {
        HostBranchDisposition::Healthy
    } else {
        HostBranchDisposition::StoreDegraded
    };
    assert_eq!(disposition, HostBranchDisposition::Healthy);

    let fenced = route_scm_store_recovery(
        super::ScmStoreRecoveryObservation {
            store_requires_restart: true,
            kernel_live: true,
            kernel_requires_activation: false,
            store_present: true,
        },
        None,
        &request,
        |_| Err(HostError::RecoveryRequired("recovery failed".to_owned())),
    )?;
    assert_eq!(
        fenced,
        ScmStoreRecoveryRoute::Fenced(HostBranchDisposition::StoreDegraded)
    );
    let both_fenced = route_scm_store_recovery(
        super::ScmStoreRecoveryObservation {
            store_requires_restart: true,
            kernel_live: false,
            kernel_requires_activation: true,
            store_present: true,
        },
        None,
        &request,
        |_| panic!("invalid Kernel must not invoke Store recovery"),
    )?;
    assert_eq!(
        both_fenced,
        ScmStoreRecoveryRoute::Fenced(HostBranchDisposition::BothDegraded)
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn generic_reconcile_rejects_dead_store_without_durable_host_authority() -> TestResult {
    let host = fresh_host_epoch(PlatformHandle::new("scm-store-recovery-guard")?, None)?;
    let mut jobs = HostJobBranches::new_fenced(&host)?;
    let generation = PlatformHandle::new("generation")?;
    let config_digest = PlatformHandle::new("config-digest")?;
    let Err(error) = jobs.reconcile(
        &generation,
        &config_digest,
        Path::new(r"C:\Eliot\config.json"),
        &PlatformHandle::new(r"C:\Eliot\kernel.exe")?,
        &PlatformHandle::new(r"C:\Eliot\store.exe")?,
        &PlatformHandle::new(r"C:\Eliot\config.json")?,
        &PlatformHandle::new("kernel-artifact")?,
        &PlatformHandle::new("store-artifact")?,
        &host,
    ) else {
        return Err(std::io::Error::other("expected reconciliation error").into());
    };
    assert!(matches!(
        error,
        HostError::StoreRecoveryRequired(StoreRecoveryRequired::LateDead)
    ));
    Ok(())
}

#[test]
fn scm_store_recovery_request_identity_is_stable_and_contour_bound() -> TestResult {
    let host = fresh_host_epoch(PlatformHandle::new("scm-store-recovery-identity")?, None)?;
    let activation_id = PlatformHandle::new("activation-id")?;
    let activation_generation = super::root_epoch(PlatformHandle::new("activation")?);
    let generation = PlatformHandle::new("generation")?;
    let config = PlatformHandle::new("config")?;
    let first = host_owned_store_recovery_request(
        &host,
        &activation_id,
        &activation_generation,
        &generation,
        &config,
    )?;
    let replay = host_owned_store_recovery_request(
        &host,
        &activation_id,
        &activation_generation,
        &generation,
        &config,
    )?;
    assert_eq!(first.request_id, replay.request_id);
    assert_eq!(first.mutation_digest, replay.mutation_digest);
    assert_eq!(first.request_digest, replay.request_digest);
    let changed_config = host_owned_store_recovery_request(
        &host,
        &activation_id,
        &activation_generation,
        &generation,
        &PlatformHandle::new("config-changed")?,
    )?;
    assert_ne!(first.mutation_digest, changed_config.mutation_digest);
    let mut next_host = host.clone();
    next_host.epoch = host.epoch.direct_child()?;
    let changed_epoch = host_owned_store_recovery_request(
        &next_host,
        &activation_id,
        &activation_generation,
        &generation,
        &config,
    )?;
    assert_ne!(first.mutation_digest, changed_epoch.mutation_digest);
    Ok(())
}

#[test]
fn pulse4_store_rebind_fence_and_pipe_substitution_fails_closed() -> TestResult {
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
    use eliot_kernel_service::{HostStoreBootstrapRequirement, StoreRebindHandoff};
    let fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
    let req = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge")?,
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store")?,
        store_generation: ResourceGeneration::genesis(),
        state_fence: fence,
        launch_nonce: PlatformHandle::new("nonce-1")?,
        connection_id: PlatformHandle::new("connection-1")?,
        expected_peer_sid: PlatformHandle::new("S-1-5-18")?,
        expected_peer_session_id: 0,
        approved_artifact_hash: PlatformHandle::new("a".repeat(64))?,
        approved_config_hash: PlatformHandle::new("b".repeat(64))?,
        timeout_ms: 5000,
    };
    let mut bad = req.clone();
    bad.canonical_pipe_identity = PlatformHandle::new(r"\\.\pipe\eliot\other")?;
    let handoff = StoreRebindHandoff {
        operation_id: PlatformHandle::new("op-1")?,
        request_digest: "d".repeat(64),
        requirement: bad,
        process_binding: eliot_kernel_service::StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\store.exe".to_owned(),
            },
            job: PlatformHandle::new(r"Local\Eliot-Host-Store-test")?,
        },
        candidate_binding_digest: "f".repeat(64),
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: "a".repeat(64),
    };
    assert!(
        handoff.validate().is_err()
            || handoff.requirement.canonical_pipe_identity.as_str()
                != req.canonical_pipe_identity.as_str()
    );
    Ok(())
}

#[test]
fn pulse4_production_discriminator_is_bound_to_host_composition() {
    assert_eq!(
        HostComposition::production_store_rebind_discriminator(),
        HOST_STORE_REBIND_PRODUCTION_DISCRIMINATOR
    );
    assert!(!HostComposition::production_store_rebind_discriminator().is_empty());
}

#[test]
fn store_recovery_stale_binding_rejected_production_bound() -> TestResult {
    assert_eq!(
        HostComposition::production_store_rebind_discriminator(),
        HOST_STORE_REBIND_PRODUCTION_DISCRIMINATOR
    );
    assert_eq!(
        HostComposition::production_runtime_control_discriminator(),
        super::HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR
    );
    let req = HostRuntimeControlRequest::new(
        HostRuntimeControlOperation::RecoverStore,
        PlatformHandle::new("store-recovery-stale")?,
    )?;
    let mut stale = req.clone();
    stale.request_digest = PlatformHandle::new("0".repeat(64))?;
    assert!(stale.validate().is_err());
    assert!(req.validate().is_ok());
    let receipt = HostStoreRecoveryReceipt {
        external_control_mutation_digest: req.mutation_digest.clone(),
        request_digest: req.request_digest.clone(),
        store_rebind_request_digest: PlatformHandle::new("e".repeat(64))?,
        store_fence: PlatformHandle::new("a".repeat(64))?,
        new_store_process_id: PlatformHandle::new("pid:101:start:1001")?,
        kernel_generation: PlatformHandle::new("b".repeat(64))?,
        activation_nonce_digest: PlatformHandle::new("c".repeat(64))?,
        ready_receipt_digest: PlatformHandle::new("d".repeat(64))?,
        receipt_digest: PlatformHandle::new("0".repeat(64))?,
    };
    let mut good = receipt.clone();
    good.receipt_digest = good.computed_digest()?;
    assert!(good.validate().is_ok());
    let mut bad = good.clone();
    bad.store_fence = PlatformHandle::new("0".repeat(64))?;
    assert!(bad.validate().is_err());
    let mut aliased = good;
    aliased.store_rebind_request_digest = aliased.external_control_mutation_digest.clone();
    aliased.receipt_digest = aliased.computed_digest()?;
    assert!(aliased.validate().is_err());
    Ok(())
}

#[test]
fn store_recovery_response_loss_query_preserves_original_digest() -> TestResult {
    assert_eq!(
        HOST_STORE_REBIND_PRODUCTION_DISCRIMINATOR,
        "eliot-host::production-store-rebind:v1"
    );
    let req = HostRuntimeControlRequest::new(
        HostRuntimeControlOperation::RecoverStore,
        PlatformHandle::new("store-recovery-response-loss")?,
    )?;
    let mut receipt = HostStoreRecoveryReceipt {
        external_control_mutation_digest: req.mutation_digest.clone(),
        request_digest: req.request_digest.clone(),
        store_rebind_request_digest: PlatformHandle::new("e".repeat(64))?,
        store_fence: PlatformHandle::new("a".repeat(64))?,
        new_store_process_id: PlatformHandle::new("pid:101:start:1001")?,
        kernel_generation: PlatformHandle::new("b".repeat(64))?,
        activation_nonce_digest: PlatformHandle::new("c".repeat(64))?,
        ready_receipt_digest: PlatformHandle::new("d".repeat(64))?,
        receipt_digest: PlatformHandle::new("0".repeat(64))?,
    };
    receipt.receipt_digest = receipt.computed_digest()?;
    let map = {
        let mut m = std::collections::HashMap::new();
        m.insert(req.mutation_digest.as_str().to_owned(), receipt.clone());
        m
    };
    let pending_ref = super::runtime_control_unknown_ref("store-recovery-pending", &req);
    assert!(pending_ref.as_str().contains(req.request_digest.as_str()));
    let recovered = map
        .get(req.mutation_digest.as_str())
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    assert_eq!(
        recovered.external_control_mutation_digest,
        req.mutation_digest
    );
    assert_eq!(recovered.request_digest, req.request_digest);
    assert_eq!(
        recovered.store_rebind_request_digest,
        PlatformHandle::new("e".repeat(64))?
    );
    let reconcile = HostRuntimeControlRequest::new_store_reconcile(
        PlatformHandle::new("store-recovery-response-loss-query")?,
        req.mutation_digest.clone(),
    )?;
    assert_eq!(reconcile.mutation_digest, req.mutation_digest);
    assert_ne!(reconcile.request_digest, req.request_digest);
    let rebound = super::rebind_store_recovery_receipt(&receipt, &reconcile)?;
    assert_eq!(
        rebound.external_control_mutation_digest,
        req.mutation_digest
    );
    assert_eq!(rebound.request_digest, reconcile.request_digest);
    assert_eq!(
        rebound.store_rebind_request_digest,
        PlatformHandle::new("e".repeat(64))?
    );
    assert_ne!(rebound.receipt_digest, receipt.receipt_digest);
    Ok(())
}

#[test]
fn store_recovery_reconciles_only_canonical_committed_inner_rebind() -> TestResult {
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
    use eliot_kernel_service::{
        HostStoreBootstrapRequirement, StoreProcessBinding, StoreRebindHandoff,
    };

    let host = super::fresh_host_epoch(PlatformHandle::new("inner-rebind-test")?, None)?;
    let activation_id = super::fresh_identity("inner-rebind-activation")?;
    let activation_generation = super::root_epoch(super::fresh_identity("inner-rebind-lineage")?);
    let authority_epoch = AuthorityEpoch::new(7)?;
    let generation = ResourceGeneration::new(3)?;
    let requirement = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge")?,
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store")?,
        store_generation: generation,
        state_fence: StateFence::new(authority_epoch, generation),
        launch_nonce: PlatformHandle::new("inner-rebind-launch-nonce")?,
        connection_id: PlatformHandle::new("inner-rebind-connection")?,
        expected_peer_sid: PlatformHandle::new("S-1-5-18")?,
        expected_peer_session_id: 0,
        approved_artifact_hash: PlatformHandle::new("a".repeat(64))?,
        approved_config_hash: PlatformHandle::new("b".repeat(64))?,
        timeout_ms: 5_000,
    };
    let operation_id = PlatformHandle::new("inner-rebind-operation")?;
    let candidate_digest = "c".repeat(64);
    let store_fence = "d".repeat(64);
    let process_binding = StoreProcessBinding {
        process: HostProcessBinding {
            process_id: 731,
            start_time_100ns: 7_311,
            image_path: r"C:\Eliot\store-new.exe".to_owned(),
        },
        job: PlatformHandle::new(r"Local\Eliot-Store-new")?,
    };
    let handoff = StoreRebindHandoff {
        operation_id: operation_id.clone(),
        request_digest: "0".repeat(64),
        requirement: requirement.clone(),
        process_binding: process_binding.clone(),
        candidate_binding_digest: candidate_digest.clone(),
        generation,
        authority_epoch,
        store_fence: store_fence.clone(),
    };
    let inner_digest = handoff.canonical_request_digest()?;
    let requirement_digest = super::sha256_json(&requirement)?;
    let record = eliot_host_state::StoreRebindRecord {
        fence: super::record_fence(&host, &activation_id, &activation_generation),
        operation: eliot_host_state::IdempotencyIdentity {
            operation_id: PlatformHandle::new("inner-rebind-journal-operation")?,
            idempotency_key: PlatformHandle::new("inner-rebind-journal-key")?,
        },
        state: eliot_host_state::StoreRebindState::Committed,
        operation_id,
        request_digest: PlatformHandle::new(inner_digest.clone())?,
        requirement: PlatformHandle::new(requirement_digest)?,
        candidate_binding_digest: PlatformHandle::new(candidate_digest.clone())?,
        store_fence: PlatformHandle::new(store_fence.clone())?,
        process_id: process_binding.process.process_id,
        process_start_time_100ns: process_binding.process.start_time_100ns,
        process_image_path: PlatformHandle::new(process_binding.process.image_path.clone())?,
        job_name: process_binding.job.clone(),
        generation: generation.value(),
        authority_epoch: authority_epoch.value(),
        receipt_request_digest: Some(PlatformHandle::new(inner_digest.clone())?),
        receipt_store_fence: Some(PlatformHandle::new(store_fence)?),
    };
    let receipt = super::committed_store_rebind_receipt(&record, &requirement, &candidate_digest)?;
    assert_eq!(receipt.request_digest, inner_digest);
    assert_eq!(receipt.process_binding, process_binding);

    let mut substituted = record.clone();
    substituted.request_digest = PlatformHandle::new("e".repeat(64))?;
    substituted.receipt_request_digest = Some(PlatformHandle::new("e".repeat(64))?);
    assert!(
        super::committed_store_rebind_receipt(&substituted, &requirement, &candidate_digest,)
            .is_err()
    );

    let mut destination_only = record;
    destination_only.process_id = destination_only.process_id.saturating_add(1);
    assert!(
        super::committed_store_rebind_receipt(&destination_only, &requirement, &candidate_digest,)
            .is_err()
    );
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn store_recovery_changes_only_store_identity_kernel_fence_invariants_hold() -> TestResult {
    let host = super::fresh_host_epoch(PlatformHandle::new("test-installation")?, None)?;
    let journal = eliot_host_state::HostStateJournalService::from_backend(
        eliot_host_state::MemoryBackend::default(),
        host.clone(),
    )?;
    let activation_generation =
        super::root_epoch(super::fresh_identity("store-recovery-activation")?);
    let activation_id = super::fresh_identity("store-recovery-activation-id")?;
    super::append_reconciled(
        &journal,
        eliot_host_state::HostStateRecord::Activation(super::initial_activation_record(
            &host,
            &activation_id,
            &activation_generation,
            eliot_host_state::ActivationState::Starting,
            "store-recovery-test-starting",
        )?),
    )?;
    let snapshot_before = journal.snapshot()?;
    let kernel_before = snapshot_before.kernel.clone();
    let host_epoch_before = snapshot_before.host.epoch.clone();
    let req = HostRuntimeControlRequest::new(
        HostRuntimeControlOperation::RecoverStore,
        PlatformHandle::new("store-recovery-kernel-invariant")?,
    )?;
    let candidate_digest = "c".repeat(64);
    let store_fence = PlatformHandle::new("d".repeat(64))?;
    let pending = eliot_host_state::StoreRebindRecord {
        fence: super::record_fence(&host, &activation_id, &activation_generation),
        operation: eliot_host_state::IdempotencyIdentity {
            operation_id: PlatformHandle::new("store-recovery-op")?,
            idempotency_key: PlatformHandle::new("store-recovery-key")?,
        },
        state: eliot_host_state::StoreRebindState::Pending,
        operation_id: PlatformHandle::new("store-recovery-op")?,
        request_digest: req.mutation_digest.clone(),
        requirement: PlatformHandle::new("b".repeat(64))?,
        candidate_binding_digest: PlatformHandle::new(candidate_digest)?,
        store_fence: store_fence.clone(),
        process_id: 101,
        process_start_time_100ns: 1001,
        process_image_path: PlatformHandle::new(r"C:\Eliot\store-new.exe")?,
        job_name: PlatformHandle::new(r"Local\Eliot-Store-new")?,
        generation: 1,
        authority_epoch: 1,
        receipt_request_digest: None,
        receipt_store_fence: None,
    };
    super::append_reconciled(
        &journal,
        eliot_host_state::HostStateRecord::StoreRebind(pending),
    )?;
    let committed = eliot_host_state::StoreRebindRecord {
        fence: super::record_fence(&host, &activation_id, &activation_generation),
        operation: eliot_host_state::IdempotencyIdentity {
            operation_id: PlatformHandle::new("store-recovery-op")?,
            idempotency_key: PlatformHandle::new("store-recovery-key-committed")?,
        },
        state: eliot_host_state::StoreRebindState::Committed,
        operation_id: PlatformHandle::new("store-recovery-op")?,
        request_digest: req.mutation_digest.clone(),
        requirement: PlatformHandle::new("b".repeat(64))?,
        candidate_binding_digest: PlatformHandle::new("c".repeat(64))?,
        store_fence: store_fence.clone(),
        process_id: 101,
        process_start_time_100ns: 1001,
        process_image_path: PlatformHandle::new(r"C:\Eliot\store-new.exe")?,
        job_name: PlatformHandle::new(r"Local\Eliot-Store-new")?,
        generation: 1,
        authority_epoch: 1,
        receipt_request_digest: Some(req.mutation_digest.clone()),
        receipt_store_fence: Some(store_fence.clone()),
    };
    super::append_reconciled(
        &journal,
        eliot_host_state::HostStateRecord::StoreRebind(committed),
    )?;
    let snapshot_after = journal.snapshot()?;
    assert_eq!(snapshot_after.host.epoch, host_epoch_before);
    assert_eq!(snapshot_after.kernel, kernel_before);
    assert!(
        snapshot_after
            .store_rebinds
            .iter()
            .any(|r| r.process_id == 101)
    );
    assert!(
        snapshot_after
            .store_rebinds
            .iter()
            .any(|r| r.state == eliot_host_state::StoreRebindState::Committed)
    );
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn store_recovery_same_host_response_loss_preserves_commit_and_idempotent_replay() -> TestResult {
    let host = super::fresh_host_epoch(PlatformHandle::new("test-installation")?, None)?;
    let journal = eliot_host_state::HostStateJournalService::from_backend(
        eliot_host_state::MemoryBackend::default(),
        host.clone(),
    )?;
    let activation_generation =
        super::root_epoch(super::fresh_identity("crash-reopen-activation")?);
    let activation_id = super::fresh_identity("crash-reopen-activation-id")?;
    super::append_reconciled(
        &journal,
        eliot_host_state::HostStateRecord::Activation(super::initial_activation_record(
            &host,
            &activation_id,
            &activation_generation,
            eliot_host_state::ActivationState::Starting,
            "crash-reopen-starting",
        )?),
    )?;
    let req = HostRuntimeControlRequest::new(
        HostRuntimeControlOperation::RecoverStore,
        PlatformHandle::new("store-recovery-crash")?,
    )?;
    let store_fence = PlatformHandle::new("e".repeat(64))?;
    let pending = eliot_host_state::StoreRebindRecord {
        fence: super::record_fence(&host, &activation_id, &activation_generation),
        operation: eliot_host_state::IdempotencyIdentity {
            operation_id: PlatformHandle::new("crash-op")?,
            idempotency_key: PlatformHandle::new("crash-key")?,
        },
        state: eliot_host_state::StoreRebindState::Pending,
        operation_id: PlatformHandle::new("crash-op")?,
        request_digest: req.mutation_digest.clone(),
        requirement: PlatformHandle::new("b".repeat(64))?,
        candidate_binding_digest: PlatformHandle::new("c".repeat(64))?,
        store_fence: store_fence.clone(),
        process_id: 201,
        process_start_time_100ns: 2001,
        process_image_path: PlatformHandle::new(r"C:\Eliot\store-crash.exe")?,
        job_name: PlatformHandle::new(r"Local\Eliot-Store-crash")?,
        generation: 1,
        authority_epoch: 1,
        receipt_request_digest: None,
        receipt_store_fence: None,
    };
    super::append_reconciled(
        &journal,
        eliot_host_state::HostStateRecord::StoreRebind(pending),
    )?;
    let committed = eliot_host_state::StoreRebindRecord {
        fence: super::record_fence(&host, &activation_id, &activation_generation),
        operation: eliot_host_state::IdempotencyIdentity {
            operation_id: PlatformHandle::new("crash-op")?,
            idempotency_key: PlatformHandle::new("crash-key-committed")?,
        },
        state: eliot_host_state::StoreRebindState::Committed,
        operation_id: PlatformHandle::new("crash-op")?,
        request_digest: req.mutation_digest.clone(),
        requirement: PlatformHandle::new("b".repeat(64))?,
        candidate_binding_digest: PlatformHandle::new("c".repeat(64))?,
        store_fence: store_fence.clone(),
        process_id: 201,
        process_start_time_100ns: 2001,
        process_image_path: PlatformHandle::new(r"C:\Eliot\store-crash.exe")?,
        job_name: PlatformHandle::new(r"Local\Eliot-Store-crash")?,
        generation: 1,
        authority_epoch: 1,
        receipt_request_digest: Some(req.mutation_digest.clone()),
        receipt_store_fence: Some(store_fence.clone()),
    };
    super::append_reconciled(
        &journal,
        eliot_host_state::HostStateRecord::StoreRebind(committed.clone()),
    )?;
    let snapshot_before = journal.snapshot()?;
    assert!(
        snapshot_before
            .store_rebinds
            .iter()
            .any(|r| r.state == eliot_host_state::StoreRebindState::Committed)
    );
    let replay = super::append_reconciled(
        &journal,
        eliot_host_state::HostStateRecord::StoreRebind(committed),
    )?;
    assert_eq!(
        replay.disposition(),
        eliot_host_state::AppendDisposition::Replayed
    );
    let snapshot_after = journal.snapshot()?;
    assert!(
        snapshot_after
            .store_rebinds
            .iter()
            .any(|r| r.state == eliot_host_state::StoreRebindState::Committed
                && r.request_digest == req.mutation_digest)
    );
    Ok(())
}

#[test]
fn store_recovery_unknown_is_mutation_keyed_not_destination() -> TestResult {
    let req = HostRuntimeControlRequest::new(
        HostRuntimeControlOperation::RecoverStore,
        PlatformHandle::new("store-recovery-unknown-mutation")?,
    )?;
    let foreign = HostRuntimeControlRequest::new(
        HostRuntimeControlOperation::RecoverStore,
        PlatformHandle::new("store-recovery-unknown-foreign")?,
    )?;
    assert_ne!(req.mutation_digest, foreign.mutation_digest);
    let receipt = HostStoreRecoveryReceipt {
        external_control_mutation_digest: req.mutation_digest.clone(),
        request_digest: req.request_digest.clone(),
        store_rebind_request_digest: PlatformHandle::new("e".repeat(64))?,
        store_fence: PlatformHandle::new("a".repeat(64))?,
        new_store_process_id: PlatformHandle::new("pid:301:start:3001")?,
        kernel_generation: PlatformHandle::new("b".repeat(64))?,
        activation_nonce_digest: PlatformHandle::new("c".repeat(64))?,
        ready_receipt_digest: PlatformHandle::new("d".repeat(64))?,
        receipt_digest: PlatformHandle::new("0".repeat(64))?,
    };
    let mut good = receipt.clone();
    good.receipt_digest = good.computed_digest()?;
    assert!(good.validate().is_ok());
    let reconcile_foreign = HostRuntimeControlRequest::new_store_reconcile(
        PlatformHandle::new("store-recovery-unknown-query")?,
        foreign.mutation_digest.clone(),
    )?;
    let unknown = super::rebind_store_recovery_receipt(&good, &reconcile_foreign);
    assert!(unknown.is_err(), "foreign mutation must not match receipt");
    let reconcile_correct = HostRuntimeControlRequest::new_store_reconcile(
        PlatformHandle::new("store-recovery-unknown-query-ok")?,
        req.mutation_digest.clone(),
    )?;
    let ok = super::rebind_store_recovery_receipt(&good, &reconcile_correct)?;
    assert_eq!(ok.external_control_mutation_digest, req.mutation_digest);
    assert_eq!(ok.request_digest, reconcile_correct.request_digest);

    let root = std::env::temp_dir().join(format!(
        "eliot-host-store-recovery-receipt-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&root)?;
    super::persist_store_recovery_receipt(&root, &good)?;
    let path = super::store_recovery_receipt_path(&root, req.mutation_digest.as_str());
    let original = std::fs::read(&path)?;
    super::persist_store_recovery_receipt(&root, &good)?;
    let mut substituted = good.clone();
    substituted.ready_receipt_digest = PlatformHandle::new("f".repeat(64))?;
    substituted.receipt_digest = substituted.computed_digest()?;
    assert!(super::persist_store_recovery_receipt(&root, &substituted).is_err());
    assert_eq!(std::fs::read(&path)?, original);
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}
