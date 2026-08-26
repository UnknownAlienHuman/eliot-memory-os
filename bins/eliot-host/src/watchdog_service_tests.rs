use super::*;
use eliot_platform::{PortOutcome, ServiceRequest};
use eliot_platform_windows::ServiceBootstrapArguments;
use std::collections::VecDeque;

struct FakeInstalledWatchdog {
    inspections: VecDeque<InstalledWatchdogRuntimeInspection>,
    fallback_inspection: InstalledWatchdogRuntimeInspection,
    start_outcomes: VecDeque<PortOutcome<eliot_platform::ServiceObservation>>,
    starts: usize,
}

impl InstalledWatchdogControl for FakeInstalledWatchdog {
    fn inspect_registration_runtime(
        &mut self,
        _request: &ServiceRegistrationRequest,
    ) -> InstalledWatchdogRuntimeInspection {
        self.inspections
            .pop_front()
            .unwrap_or_else(|| self.fallback_inspection.clone())
    }
}

impl InstalledWatchdogStartControl for FakeInstalledWatchdog {
    fn start(
        &mut self,
        _request: &ServiceRequest,
    ) -> PortOutcome<eliot_platform::ServiceObservation> {
        self.starts += 1;
        self.start_outcomes
            .pop_front()
            .unwrap_or(PortOutcome::Unknown(
                eliot_platform::UnknownReason::Indeterminate,
            ))
    }
}

struct FakeWatchdogClock {
    now_ms: u64,
    sleeps: Vec<Duration>,
}

impl FakeWatchdogClock {
    fn new() -> Self {
        Self {
            now_ms: 0,
            sleeps: Vec::new(),
        }
    }
}

struct ScriptedWatchdogClock {
    readings: VecDeque<u64>,
    last: u64,
    sleeps: Vec<Duration>,
}

impl WatchdogStartClock for ScriptedWatchdogClock {
    fn now_ms(&mut self) -> u64 {
        if let Some(reading) = self.readings.pop_front() {
            self.last = reading;
        }
        self.last
    }

    fn sleep(&mut self, duration: Duration) {
        self.sleeps.push(duration);
    }
}

impl WatchdogStartClock for FakeWatchdogClock {
    fn now_ms(&mut self) -> u64 {
        self.now_ms
    }

    fn sleep(&mut self, duration: Duration) {
        self.sleeps.push(duration);
        self.now_ms = self
            .now_ms
            .saturating_add(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
    }
}

fn fake_control(
    inspections: impl IntoIterator<Item = InstalledWatchdogRuntimeInspection>,
    fallback_inspection: InstalledWatchdogRuntimeInspection,
    start_outcomes: impl IntoIterator<Item = PortOutcome<eliot_platform::ServiceObservation>>,
) -> FakeInstalledWatchdog {
    FakeInstalledWatchdog {
        inspections: inspections.into_iter().collect(),
        fallback_inspection,
        start_outcomes: start_outcomes.into_iter().collect(),
        starts: 0,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ApprovedHostStartCall {
    branch: HostStartupBranch,
    kernel_executable: PathBuf,
    store_bridge_executable: PathBuf,
    store_artifact: PlatformHandle,
}

#[derive(Default)]
struct SpyApprovedHostStartup {
    calls: Vec<ApprovedHostStartCall>,
}

impl ApprovedHostStartupPort for SpyApprovedHostStartup {
    fn start_approved_manifest(
        &mut self,
        _manifest: &CandidateManifest,
        branch: HostStartupBranch,
        kernel_executable: &Path,
        store_bridge_executable: &Path,
        store_artifact: &PlatformHandle,
        _pending: Option<&eliot_installation::PendingActivation>,
    ) -> Result<(), HostError> {
        self.calls.push(ApprovedHostStartCall {
            branch,
            kernel_executable: kernel_executable.to_path_buf(),
            store_bridge_executable: store_bridge_executable.to_path_buf(),
            store_artifact: store_artifact.clone(),
        });
        Ok(())
    }
}

fn registration() -> ServiceRegistrationRequest {
    ServiceRegistrationRequest::new(
        ELIOT_WATCHDOG_SERVICE_NAME,
        "Eliot Watchdog",
        std::env::current_exe().unwrap_or_else(|_| unreachable!()),
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
    )
    .unwrap_or_else(|_| unreachable!())
}

fn approved_registration_fixture(
    launch: &RuntimeLaunchDescriptor,
    role: InstallerServiceRole,
    nonce: &str,
) -> Result<(InstallerServiceRegistrationApproval, PathBuf), TestError> {
    let root = std::env::temp_dir().join(format!(
        "eliot-host-scm-approval-{}",
        Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&root)?;
    let executable_path = root.join(match role {
        InstallerServiceRole::Host => "eliot-host.exe",
        InstallerServiceRole::Watchdog => "eliot-watchdog.exe",
    });
    std::fs::write(&executable_path, b"approved service fixture")?;
    let service_name = match role {
        InstallerServiceRole::Host => ELIOT_HOST_SERVICE_NAME,
        InstallerServiceRole::Watchdog => ELIOT_WATCHDOG_SERVICE_NAME,
    };
    let display_name = match role {
        InstallerServiceRole::Host => "Eliot Host",
        InstallerServiceRole::Watchdog => "Eliot Watchdog",
    };
    let descriptor_digest = phase_b_scm_selector(&launch.authority_descriptor_digest)?;
    let bootstrap = ServiceBootstrapArguments::new(
        PathBuf::from(launch.authority_descriptor_path.as_str()),
        descriptor_digest.as_str(),
        launch.installation_epoch.installation.as_str(),
        launch.authority_generation.value(),
        Vec::<String>::new(),
    )
    .and_then(|value| {
        value.with_host_state_root(PathBuf::from(
            launch.runtime_state_roots.host_state_root.as_str(),
        ))
    })
    .and_then(|value| value.with_registration_nonce(nonce))?;
    let request = ServiceRegistrationRequest::with_bootstrap(
        service_name,
        display_name,
        executable_path.clone(),
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
        bootstrap,
    )?;
    let service_control_grant = match role {
        InstallerServiceRole::Host => None,
        InstallerServiceRole::Watchdog => {
            let principal_sid = "S-1-5-80-1-2-3-4-5";
            Some(serde_json::json!({
                "principal_service": ELIOT_HOST_SERVICE_NAME,
                "principal_sid": principal_sid,
                "access_mask": eliot_platform_windows::ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
                "security_descriptor_digest":
                    eliot_platform_windows::watchdog_service_security_descriptor_digest(
                        principal_sid,
                    )?,
            }))
        }
    };
    let value = serde_json::json!({
        "transaction_id": "transaction:host-scm-test",
        "generation": launch.generation,
        "effect_id": format!("effect:{}", service_name),
        "role": match role {
            InstallerServiceRole::Host => "HOST",
            InstallerServiceRole::Watchdog => "WATCHDOG",
        },
        "service_name": service_name,
        "executable_path": executable_path,
        "account": "LOCAL_SERVICE",
        "automatic_start": true,
        "service_bootstrap": {
            "descriptor_path": launch.authority_descriptor_path,
            "descriptor_digest": descriptor_digest,
            "installation_id": launch.installation_epoch.installation,
            "plan_generation": launch.authority_generation.value(),
            "host_state_root": launch.runtime_state_roots.host_state_root,
        },
        "registration_nonce": nonce,
        "configuration_digest": request.expected_configuration_digest(),
        "service_control_grant": service_control_grant,
    });
    let approval = serde_json::from_value(value)?;
    Ok((approval, root))
}

fn service_observation(state: ServiceState) -> eliot_platform::ServiceObservation {
    eliot_platform::ServiceObservation {
        service: PlatformHandle::new(ELIOT_WATCHDOG_SERVICE_NAME)
            .unwrap_or_else(|_| unreachable!()),
        state,
        generation: None,
        process: None,
    }
}

fn runtime_observation(
    state: ServiceState,
    wait_hint_ms: u32,
    process: Option<ProcessIdentity>,
) -> InstalledWatchdogRuntimeInspection {
    InstalledWatchdogRuntimeInspection::Matching {
        state,
        wait_hint_ms,
        process,
    }
}

fn process_for(registration: &ServiceRegistrationRequest) -> ProcessIdentity {
    ProcessIdentity {
        process_id: 41,
        start_time_100ns: 7,
        image_path: registration.binary_path().to_string_lossy().into_owned(),
    }
}

fn context() -> RequestMetadata {
    let host = fresh_host_epoch(
        PlatformHandle::new("installation:test").unwrap_or_else(|_| unreachable!()),
        None,
    )
    .unwrap_or_else(|_| unreachable!());
    lifecycle_context(&host, "watchdog-test").unwrap_or_else(|_| unreachable!())
}

#[test]
fn host_watchdog_surface_contains_no_registration_mutation() {
    let source = include_str!("lib.rs");
    let registration_mutation = [".register_", "service("].concat();
    let registration_operation = ["ServiceOperation::", "Register"].concat();
    assert!(!source.contains(&registration_mutation));
    assert!(!source.contains(&registration_operation));
    assert_eq!(SERVICE_NAME, ELIOT_HOST_SERVICE_NAME);
}

#[test]
fn production_watchdog_inspection_rejects_stopped_without_start_and_accepts_running() {
    let registration = registration();
    let mut stopped = fake_control(
        [runtime_observation(ServiceState::Stopped, 0, None)],
        InstalledWatchdogRuntimeInspection::Unknown,
        [],
    );
    assert!(matches!(
        require_running_watchdog(&mut stopped, &registration),
        Err(HostError::RecoveryRequired(_))
    ));
    assert_eq!(stopped.starts, 0);

    let mut running = fake_control(
        [runtime_observation(
            ServiceState::Running,
            0,
            Some(process_for(&registration)),
        )],
        InstalledWatchdogRuntimeInspection::Unknown,
        [],
    );
    require_running_watchdog(&mut running, &registration).unwrap_or_else(|_| unreachable!());
    assert_eq!(running.starts, 0);
}

#[test]
fn absent_mismatched_or_unknown_registration_never_starts() {
    for inspection in [
        InstalledWatchdogRuntimeInspection::Absent,
        InstalledWatchdogRuntimeInspection::Mismatched,
        InstalledWatchdogRuntimeInspection::Unknown,
    ] {
        let mut control = fake_control(
            [inspection],
            InstalledWatchdogRuntimeInspection::Unknown,
            [],
        );
        assert!(start_installed_watchdog(&mut control, &registration(), context()).is_err());
        assert_eq!(control.starts, 0);
    }
}

#[test]
fn already_running_is_accepted_without_start() {
    let registration = registration();
    let process = process_for(&registration);
    let mut control = fake_control(
        [runtime_observation(ServiceState::Running, 0, Some(process))],
        InstalledWatchdogRuntimeInspection::Unknown,
        [],
    );

    start_installed_watchdog(&mut control, &registration, context())
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(control.starts, 0);
}

#[test]
fn starting_converges_without_start() {
    let registration = registration();
    let process = process_for(&registration);
    let mut control = fake_control(
        [
            runtime_observation(ServiceState::Starting, 25, None),
            runtime_observation(ServiceState::Running, 0, Some(process)),
        ],
        InstalledWatchdogRuntimeInspection::Unknown,
        [],
    );
    let mut clock = FakeWatchdogClock::new();

    start_installed_watchdog_with_clock(&mut control, &registration, context(), &mut clock)
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(control.starts, 0);
    assert_eq!(clock.sleeps, vec![Duration::from_millis(25)]);
}

#[test]
fn stopped_unknown_start_reconciles_through_starting_to_running_once() {
    let registration = registration();
    let process = process_for(&registration);
    let mut control = fake_control(
        [
            runtime_observation(ServiceState::Stopped, 0, None),
            InstalledWatchdogRuntimeInspection::Unknown,
            runtime_observation(ServiceState::Starting, 1_000, None),
            runtime_observation(ServiceState::Running, 0, Some(process)),
        ],
        InstalledWatchdogRuntimeInspection::Unknown,
        [PortOutcome::Unknown(
            eliot_platform::UnknownReason::Indeterminate,
        )],
    );
    let mut clock = FakeWatchdogClock::new();

    start_installed_watchdog_with_clock(&mut control, &registration, context(), &mut clock)
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(control.starts, 1);
    assert_eq!(
        clock.sleeps,
        vec![Duration::from_millis(50), Duration::from_millis(250)]
    );
}

#[test]
fn start_partial_outcome_reconciles_to_running_without_trusting_start_result() {
    let registration = registration();
    let process = process_for(&registration);
    let mut control = fake_control(
        [
            runtime_observation(ServiceState::Stopped, 0, None),
            runtime_observation(ServiceState::Running, 0, Some(process)),
        ],
        InstalledWatchdogRuntimeInspection::Unknown,
        [PortOutcome::Partial {
            value: service_observation(ServiceState::Running),
            missing: vec![
                PlatformHandle::new("authority_bound_process_record")
                    .unwrap_or_else(|_| unreachable!()),
            ],
        }],
    );

    start_installed_watchdog(&mut control, &registration, context())
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(control.starts, 1);
}

#[test]
fn production_inspection_selects_scm_only_for_system_service() -> TestResult {
    let (manifest, root) = super::journal_tests::liveness_manifest_with_distinct_store_digests()?;
    assert_eq!(
        select_watchdog_approval_for_inspection(&ApprovedGenerationRegistry::new(), &manifest)
            .unwrap_or_else(|_| unreachable!()),
        None
    );

    let mut system_manifest = manifest.clone();
    system_manifest.runtime_launch.profile = InstallationProfile::SystemService;
    assert!(
        select_watchdog_approval_for_inspection(
            &ApprovedGenerationRegistry::new(),
            &system_manifest,
        )
        .is_err()
    );
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn production_active_and_pending_start_pass_bridge_and_digest_through_shared_port() -> TestResult {
    let (manifest, root) = super::journal_tests::liveness_manifest_with_distinct_store_digests()?;
    let (pending_manifest, pending_root) =
        super::journal_tests::liveness_manifest_with_distinct_store_digests()?;
    let mut spy = SpyApprovedHostStartup::default();
    start_approved_manifest_contour(&mut spy, &manifest, HostStartupBranch::Active, None)
        .unwrap_or_else(|_| unreachable!());
    start_approved_manifest_contour(
        &mut spy,
        &pending_manifest,
        HostStartupBranch::Pending,
        None,
    )
    .unwrap_or_else(|_| unreachable!());

    assert_eq!(spy.calls.len(), 2);
    for (call, candidate) in spy.calls.iter().zip([&manifest, &pending_manifest]) {
        let (approved_kernel, approved_store_bridge, _) = candidate.host_child_paths();
        let (_, approved_store_artifact) = candidate
            .host_child_artifact_digests()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            call.kernel_executable,
            PathBuf::from(approved_kernel.as_str())
        );
        assert_eq!(
            call.store_bridge_executable,
            PathBuf::from(approved_store_bridge.as_str())
        );
        assert_eq!(call.store_artifact, *approved_store_artifact);
        assert_ne!(
            call.store_bridge_executable,
            PathBuf::from(candidate.canonical_store_executable_path.as_str())
        );
    }
    assert_eq!(spy.calls[0].branch, HostStartupBranch::Active);
    assert_eq!(spy.calls[1].branch, HostStartupBranch::Pending);

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(pending_root);
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the single matrix keeps role, nonce, generation, and bootstrap substitutions bound to the same approved registration fixture"
)]
fn approved_registration_reconstructs_exact_role_scoped_bootstrap_and_rejects_substitution()
-> TestResult {
    let (manifest, manifest_root) =
        super::journal_tests::liveness_manifest_with_distinct_store_digests()?;
    let (host, host_root) = approved_registration_fixture(
        &manifest.runtime_launch,
        InstallerServiceRole::Host,
        &"a".repeat(64),
    )?;
    let (watchdog, watchdog_root) = approved_registration_fixture(
        &manifest.runtime_launch,
        InstallerServiceRole::Watchdog,
        &"b".repeat(64),
    )?;
    let host_approved_request = host
        .service_registration_request()
        .map_err(|error| std::io::Error::other(format!("host approval request: {error}")))?;
    let host_image = PlatformHandle::new(
        host_approved_request
            .binary_path()
            .to_string_lossy()
            .into_owned(),
    )?;
    let watchdog_approved_request = watchdog
        .service_registration_request()
        .map_err(|error| std::io::Error::other(format!("watchdog approval request: {error}")))?;
    let watchdog_image = PlatformHandle::new(
        watchdog_approved_request
            .binary_path()
            .to_string_lossy()
            .into_owned(),
    )?;
    let mut launch = manifest.runtime_launch.clone();
    launch.host_executable_path = host_image.clone();
    launch.watchdog_executable_path = watchdog_image.clone();
    let host_request = approved_service_registration_request(
        &launch,
        &host,
        InstallerServiceRole::Host,
        &host_image,
    )?;
    let watchdog_request = approved_service_registration_request(
        &launch,
        &watchdog,
        InstallerServiceRole::Watchdog,
        &watchdog_image,
    )?;
    assert_eq!(host_request, host_approved_request);
    assert_eq!(watchdog_request, watchdog_approved_request);
    let mut live_generation_launch = launch.clone();
    let live_generation = ResourceGeneration::new(9)?;
    live_generation_launch.authority_generation = live_generation;
    live_generation_launch
        .authority_state_fence
        .resource_generation = live_generation;
    assert!(
        approved_service_registration_request(
            &live_generation_launch,
            &watchdog,
            InstallerServiceRole::Watchdog,
            &watchdog_image,
        )
        .is_ok()
    );
    assert_eq!(host_request.service_name(), ELIOT_HOST_SERVICE_NAME);
    assert_eq!(watchdog_request.service_name(), ELIOT_WATCHDOG_SERVICE_NAME);
    assert_eq!(host_request.binary_path(), Path::new(host_image.as_str()));
    assert_eq!(
        watchdog_request.binary_path(),
        Path::new(watchdog_image.as_str())
    );
    assert_eq!(
        host_request
            .bootstrap()
            .and_then(|value| value.host_state_root()),
        Some(Path::new(
            launch.runtime_state_roots.host_state_root.as_str()
        ))
    );
    assert_eq!(
        watchdog_request
            .bootstrap()
            .map(ServiceBootstrapArguments::config_descriptor_digest),
        Some(launch.authority_descriptor_digest.as_str())
    );
    assert_ne!(
        host_request
            .bootstrap()
            .and_then(|value| value.registration_nonce()),
        watchdog_request
            .bootstrap()
            .and_then(|value| value.registration_nonce())
    );

    let pending_marker = PlatformHandle::new(PHASE_B_PENDING_MARKER)?;
    let mut pending_scm_launch = launch.clone();
    pending_scm_launch.authority_descriptor_digest = pending_marker.clone();
    pending_scm_launch.store_bootstrap_descriptor_digest = pending_marker.clone();
    pending_scm_launch.kernel_arguments[5] = pending_marker.clone();
    pending_scm_launch.kernel_arguments[9] = pending_marker;
    pending_scm_launch.supervision_authority =
        eliot_installation::SupervisionAuthorityBinding::Pending {
            supervision_lease_scope_id: PlatformHandle::new("test-supervision-scope")?,
        };
    pending_scm_launch = pending_scm_launch.with_computed_digest()?;
    let (pending_watchdog, pending_watchdog_root) = approved_registration_fixture(
        &pending_scm_launch,
        InstallerServiceRole::Watchdog,
        &"c".repeat(64),
    )?;
    let pending_watchdog_image = PlatformHandle::new(
        pending_watchdog
            .service_registration_request()?
            .binary_path()
            .to_string_lossy()
            .into_owned(),
    )?;
    pending_scm_launch.watchdog_executable_path = pending_watchdog_image.clone();
    pending_scm_launch = pending_scm_launch.with_computed_digest()?;
    let intermediate = pending_scm_launch.with_phase_b_pending_bootstrap_overlay(
        pending_scm_launch.authority_generation,
        pending_scm_launch.authority_state_fence.clone(),
        launch.authority_descriptor_digest.clone(),
        launch.eliotd_descriptor_digest.clone(),
        test_provisioned_supervision_authority(
            launch.installation_epoch.installation.as_str(),
            launch.generation.as_str(),
            launch.authority_generation,
        ),
    )?;
    let live_overlay = intermediate.with_phase_b_materialization(
        intermediate.authority_generation,
        intermediate.authority_state_fence.clone(),
        launch.authority_descriptor_digest.clone(),
        launch.store_bootstrap_descriptor_digest.clone(),
        launch.eliotd_descriptor_digest.clone(),
    )?;
    let pending_watchdog_request = approved_service_registration_request(
        &pending_scm_launch,
        &pending_watchdog,
        InstallerServiceRole::Watchdog,
        &pending_watchdog_image,
    )?;
    assert_eq!(
        pending_watchdog_request
            .bootstrap()
            .map(ServiceBootstrapArguments::config_descriptor_digest),
        Some(eliot_installation::PHASE_B_PENDING_SCM_DIGEST)
    );
    assert_ne!(
        pending_watchdog_request
            .bootstrap()
            .map(ServiceBootstrapArguments::config_descriptor_digest),
        Some(live_overlay.authority_descriptor_digest.as_str())
    );

    assert!(
        approved_service_registration_request(
            &launch,
            &watchdog,
            InstallerServiceRole::Host,
            &host_image,
        )
        .is_err()
    );
    let mut substituted_launch = launch.clone();
    substituted_launch.generation = PlatformHandle::new("generation:substituted")?;
    assert!(
        approved_service_registration_request(
            &substituted_launch,
            &watchdog,
            InstallerServiceRole::Watchdog,
            &watchdog_image,
        )
        .is_err()
    );
    let mut missing_nonce_value = serde_json::to_value(&host)?;
    missing_nonce_value["registration_nonce"] = serde_json::Value::String(String::new());
    let missing_nonce =
        serde_json::from_value::<InstallerServiceRegistrationApproval>(missing_nonce_value)?;
    assert!(
        approved_service_registration_request(
            &launch,
            &missing_nonce,
            InstallerServiceRole::Host,
            &host_image,
        )
        .is_err()
    );
    let _ = std::fs::remove_dir_all(host_root);
    let _ = std::fs::remove_dir_all(watchdog_root);
    let _ = std::fs::remove_dir_all(pending_watchdog_root);
    let _ = std::fs::remove_dir_all(manifest_root);
    Ok(())
}

#[test]
fn stopped_after_start_requires_recovery_without_resend() {
    let registration = registration();
    let mut control = fake_control(
        [
            runtime_observation(ServiceState::Stopped, 0, None),
            runtime_observation(ServiceState::Stopped, 0, None),
        ],
        InstalledWatchdogRuntimeInspection::Unknown,
        [PortOutcome::Unknown(
            eliot_platform::UnknownReason::Indeterminate,
        )],
    );

    assert!(matches!(
        start_installed_watchdog(&mut control, &registration, context()),
        Err(HostError::RecoveryRequired(_))
    ));
    assert_eq!(control.starts, 1);
}

#[test]
fn running_without_process_identity_requires_recovery() {
    let registration = registration();
    let mut control = fake_control(
        [runtime_observation(ServiceState::Running, 0, None)],
        InstalledWatchdogRuntimeInspection::Unknown,
        [],
    );

    assert!(matches!(
        start_installed_watchdog(&mut control, &registration, context()),
        Err(HostError::RecoveryRequired(_))
    ));
    assert_eq!(control.starts, 0);
}

#[test]
fn pid_reuse_during_start_requires_recovery_without_resend() {
    let registration = registration();
    let first = process_for(&registration);
    let mut reused = first.clone();
    reused.start_time_100ns += 1;
    let mut control = fake_control(
        [
            runtime_observation(ServiceState::Stopped, 0, None),
            runtime_observation(ServiceState::Starting, 25, Some(first)),
            runtime_observation(ServiceState::Running, 0, Some(reused)),
        ],
        InstalledWatchdogRuntimeInspection::Unknown,
        [PortOutcome::Unknown(
            eliot_platform::UnknownReason::Indeterminate,
        )],
    );
    let mut clock = FakeWatchdogClock::new();

    assert!(matches!(
        start_installed_watchdog_with_clock(&mut control, &registration, context(), &mut clock,),
        Err(HostError::RecoveryRequired(_))
    ));
    assert_eq!(control.starts, 1);
}

#[test]
fn pid_change_during_start_requires_recovery_without_resend() {
    let registration = registration();
    let first = process_for(&registration);
    let mut changed = first.clone();
    changed.process_id += 1;
    let mut control = fake_control(
        [
            runtime_observation(ServiceState::Stopped, 0, None),
            runtime_observation(ServiceState::Starting, 25, Some(first)),
            runtime_observation(ServiceState::Running, 0, Some(changed)),
        ],
        InstalledWatchdogRuntimeInspection::Unknown,
        [PortOutcome::Unknown(
            eliot_platform::UnknownReason::Indeterminate,
        )],
    );
    let mut clock = FakeWatchdogClock::new();

    assert!(matches!(
        start_installed_watchdog_with_clock(&mut control, &registration, context(), &mut clock,),
        Err(HostError::RecoveryRequired(_))
    ));
    assert_eq!(control.starts, 1);
}

#[test]
fn image_substitution_during_start_requires_recovery_without_resend() {
    let registration = registration();
    let first = process_for(&registration);
    let mut substituted = first.clone();
    substituted.image_path = r"C:\Windows\System32\not-eliot.exe".to_owned();
    let mut control = fake_control(
        [
            runtime_observation(ServiceState::Stopped, 0, None),
            runtime_observation(ServiceState::Starting, 25, Some(first)),
            runtime_observation(ServiceState::Running, 0, Some(substituted)),
        ],
        InstalledWatchdogRuntimeInspection::Unknown,
        [PortOutcome::Unknown(
            eliot_platform::UnknownReason::Indeterminate,
        )],
    );
    let mut clock = FakeWatchdogClock::new();

    assert!(matches!(
        start_installed_watchdog_with_clock(&mut control, &registration, context(), &mut clock,),
        Err(HostError::RecoveryRequired(_))
    ));
    assert_eq!(control.starts, 1);
}

#[test]
fn unknown_reconciliation_is_bounded_and_never_resends_start() {
    let registration = registration();
    let mut control = fake_control(
        [runtime_observation(ServiceState::Stopped, 0, None)],
        InstalledWatchdogRuntimeInspection::Unknown,
        [PortOutcome::Unknown(
            eliot_platform::UnknownReason::Indeterminate,
        )],
    );
    let mut clock = FakeWatchdogClock::new();

    assert!(matches!(
        start_installed_watchdog_with_clock(&mut control, &registration, context(), &mut clock,),
        Err(HostError::RecoveryRequired(_))
    ));
    assert_eq!(control.starts, 1);
    assert_eq!(clock.now_ms, WATCHDOG_START_TIMEOUT_MS);
}

#[test]
fn running_observed_at_deadline_is_rejected_without_resending_start() {
    let registration = registration();
    let process = process_for(&registration);
    let mut control = fake_control(
        [
            runtime_observation(ServiceState::Starting, 25, None),
            runtime_observation(ServiceState::Running, 0, Some(process)),
        ],
        InstalledWatchdogRuntimeInspection::Unknown,
        [],
    );
    let mut clock = ScriptedWatchdogClock {
        readings: VecDeque::from([0, 0, 0, WATCHDOG_START_TIMEOUT_MS]),
        last: 0,
        sleeps: Vec::new(),
    };

    assert!(matches!(
        start_installed_watchdog_with_clock(&mut control, &registration, context(), &mut clock),
        Err(HostError::RecoveryRequired(_))
    ));
    assert_eq!(control.starts, 0);
}

#[test]
fn wait_hint_is_clamped_to_bounded_poll_interval() {
    assert_eq!(watchdog_start_wait(0), Duration::from_millis(25));
    assert_eq!(watchdog_start_wait(1), Duration::from_millis(25));
    assert_eq!(watchdog_start_wait(u32::MAX), Duration::from_millis(250));
}
