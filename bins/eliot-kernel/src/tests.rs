#![allow(clippy::default_trait_access, clippy::expect_used)]
#![allow(
    clippy::large_futures,
    reason = "control-path tests intentionally await the concrete production future so their fixtures exercise its full state machine"
)]

//! Kernel unit tests — acceptance-only scope.
//!
//! Architecture traceability:
//! - `ELIOT_ARCHITECTURE.md` :: A2.3 and `ARCH-MOD-01` — modular architecture, ordinary module boundary.
//! - `ELIOT_IMPLEMENTATION.md` :: I2.2 and `I2.16` — crate capability extraction and crate-size/Agent Context Envelope.
//!
//! This module owns no runtime authority and exercises only the Kernel composition
//! boundary via `super::*`. It is an ordinary module kept under 10k LOC.
use super::*;
use eliot_contracts::ContractVersion;
use eliot_kernel_core::{KernelError, KernelResult, SealedAuthoritySnapshot};
use eliot_ors::{
    EpochIdentity, EpochLineage, OpaqueLabel, OperationIdentity, RecoveryPayload,
    StateFenceSnapshot,
};
use eliot_platform::{PlatformHandle, SecretReference};
use eliot_process::{
    ActionLeaseRef, DispatchPermitAuthority, DispatchPermitReplaySnapshot, EnvironmentInheritance,
    EnvironmentProjection, FencingToken, ImageId, JobId, OperationId, PermitIssuance,
    ProcessTreeId, ResourceLimits, SessionId,
};
use eliot_runtime_contracts::{
    ModuleContract, RegisteredActivityWakePolicy, SupervisionJournalEpoch,
    SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
    SupervisionSealedKeyFileIdentity,
};
use eliot_store_api::{RevisionHead, RevisionKey};
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod activation;
mod process_execution;

#[test]
fn daemon_health_response_matches_the_eliotd_typed_value_contract() {
    for status in [
        StoreHealthStatus::Ready,
        StoreHealthStatus::Degraded,
        StoreHealthStatus::Unavailable,
    ] {
        let health = StoreHealth {
            status,
            contract_version: eliot_store_api::CONTRACT_VERSION,
            manifest_digest: eliot_store_api::OperationManifestDigest::new("a".repeat(64))
                .expect("manifest digest"),
        };
        let health_value = serde_json::to_value(&health).expect("health JSON");

        assert_eq!(
            KernelComposition::daemon_health_response(&health),
            serde_json::json!({
                "status": "known",
                "value": {
                    "kind": "health",
                    "value": health_value,
                },
                "recovery": null,
            })
        );
    }
}

fn supervision_incarnation() -> SupervisionLeaseIncarnationBinding {
    SupervisionLeaseIncarnationBinding {
        supervision_lease_scope_id: "eliot-supervision-scope:v1:test".to_owned(),
        supervision_lease_id: String::new(),
        scope_ref_digest: String::new(),
        installation_id: "installation-1".to_owned(),
        host_epoch: SupervisionJournalEpoch {
            lineage_id: "host-lineage-1".to_owned(),
            sequence: 1,
        },
        activation_id: "activation-1".to_owned(),
        activation_generation: SupervisionJournalEpoch {
            lineage_id: "activation-lineage-1".to_owned(),
            sequence: 1,
        },
        kernel_generation: SupervisionJournalEpoch {
            lineage_id: "kernel-lineage-1".to_owned(),
            sequence: 1,
        },
        watchdog_epoch: SupervisionJournalEpoch {
            lineage_id: "watchdog-lineage-1".to_owned(),
            sequence: 1,
        },
        observation_scope: SupervisionObservationScope {
            targets: vec!["eliot-kernel".to_owned()],
            sensor_profile: "eliot-runtime-live-v3".to_owned(),
            claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
            governance_axis: "runtime-live-v3".to_owned(),
        },
        wake_policy: RegisteredActivityWakePolicy::Disabled,
        predecessor: None,
    }
    .with_derived_ids()
    .expect("sealed supervision incarnation")
}

#[cfg(windows)]
const BIND_SESSION_CHILD_PIPE_ENV: &str = "ELIOT_TEST_BIND_SESSION_CHILD_PIPE";
#[cfg(windows)]
const REAL_EXECUTOR_CHILD_ENV: &str = "ELIOT_TEST_REAL_EXECUTOR_CHILD";

#[cfg(windows)]
struct RealExecutorTestAuthority {
    authority: Mutex<DispatchPermitAuthority>,
    context: DispatchValidationContext,
    fence: FencingToken,
    revision_heads: BTreeMap<String, String>,
    issued_at_ms: u64,
}

#[cfg(windows)]
impl RealExecutorTestAuthority {
    fn new(authority_id: DispatchAuthorityId) -> Self {
        let issued_at_ms = unix_ms();
        let generation = Generation::new(1).expect("generation");
        let fence =
            FencingToken::new(1, generation, "real-executor-test-fence").expect("test fence");
        let revision_heads = BTreeMap::from([("real-executor".to_owned(), "a".repeat(64))]);
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(i64::try_from(issued_at_ms).expect("clock range")),
                known_time_ms: Some(i64::try_from(issued_at_ms).expect("clock range")),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            fence.clone(),
            1,
            revision_heads.clone(),
            1,
        )
        .expect("test validation context");
        Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(
                authority_id,
                KernelDispatchKey::from_secret_bytes([0x7e; 32]).expect("executor test key"),
            )),
            context,
            fence,
            revision_heads,
            issued_at_ms,
        }
    }

    fn issue(&self, admission: &ProcessExecutionAdmissionRequest) -> ProcessRequest {
        let issuance = PermitIssuance::new_with_validation_revision(
            admission.action_lease_ref().clone(),
            self.fence.clone(),
            self.revision_heads.clone(),
            self.issued_at_ms,
            admission.deadline_unix_ms(),
            format!(
                "real-executor:{}",
                admission.intent().operation_id().as_str()
            ),
            1,
        )
        .expect("permit issuance");
        let permit = self
            .authority
            .lock()
            .expect("test authority lock")
            .issue(admission.intent(), issuance)
            .expect("test dispatch permit");
        ProcessRequest::new(admission.intent().clone(), permit).expect("test process request")
    }
}

#[cfg(windows)]
impl DispatchValidationPort for RealExecutorTestAuthority {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        self.authority
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable(
                    "real executor test authority lock poisoned".to_owned(),
                )
            })?
            .validate_and_consume(request, observed, &self.context)
            .map_err(ProcessExecutionError::Contract)
    }
}

#[cfg(windows)]
fn real_process_gateway(
    root: &Path,
    containment_root: &Path,
) -> (
    ProcessExecutionGateway,
    Arc<WindowsPlatform>,
    Arc<RealExecutorTestAuthority>,
) {
    std::fs::create_dir_all(root).expect("real gateway test root");
    let ors = Arc::new(
        RedbRecoveryStore::open(root.join("kernel-ors.redb")).expect("real gateway ORS store"),
    );
    let authority_id =
        DispatchAuthorityId::new("kernel-real-executor-authority").expect("authority id");
    let snapshot_binding = authority_binding(&authority_id);
    let authority_store: Arc<dyn OperationalRecoveryStore> = ors.clone();
    let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(JsonSnapshotCodec);
    let controller = Arc::new(Mutex::new(ProcessDispatchAuthorityController::activate(
        authority_id,
        KernelDispatchKey::from_secret_bytes([0x6d; 32]).expect("dispatch key"),
        authority_store,
        codec,
    )));
    let platform = Arc::new(
        WindowsPlatform::new(containment_root.to_path_buf()).expect("real gateway platform root"),
    );
    let path_admission = Arc::new(KernelPathAdmission::new(Arc::clone(&platform)));
    let test_authority = Arc::new(RealExecutorTestAuthority::new(
        DispatchAuthorityId::new("kernel-real-executor-test-permit")
            .expect("test permit authority"),
    ));
    let validation_port: Arc<dyn DispatchValidationPort> = test_authority.clone();
    let launch_admission: Arc<dyn ProcessLaunchAdmission> = path_admission.clone();
    let mut gateway =
        ProcessExecutionGateway::new(controller, ors, snapshot_binding, path_admission);
    gateway.executor =
        WindowsProcessExecutor::new_with_launch_admission(validation_port, launch_admission);
    (gateway, platform, test_authority)
}

#[cfg(windows)]
fn real_executor_admission(
    executable: &Path,
    executable_sha256: &str,
    operation: &str,
    child_test: &str,
    environment: BTreeMap<String, String>,
) -> ProcessExecutionAdmissionRequest {
    let generation = Generation::new(1).expect("generation");
    let working_directory = executable.parent().expect("test executable parent");
    let intent = ProcessIntent::new(
        OperationId::new(operation).expect("operation id"),
        ProcessTreeId::new(format!("real-executor-tree-{operation}")).expect("process tree"),
        JobId::new(format!("real-executor-logical-job-{operation}")).expect("logical Job id"),
        ImageId::new(format!("real-executor-image-{operation}")).expect("image id"),
        SessionId::new(format!("real-executor-session-{operation}")).expect("session id"),
        generation,
        executable.to_string_lossy(),
        executable_sha256,
        vec![
            "--exact".to_owned(),
            child_test.to_owned(),
            "--nocapture".to_owned(),
        ],
        working_directory.to_string_lossy(),
        EnvironmentProjection::new(environment, Vec::new(), EnvironmentInheritance::None)
            .expect("closed child environment"),
        ResourceLimits::new(60_000, Some(30_000), None, 64 * 1024, 64 * 1024, 4)
            .expect("resource limits"),
    )
    .expect("real executor intent");
    ProcessExecutionAdmissionRequest::new(
        ACTIVE_DAEMON_CALLER,
        intent,
        ActionLeaseRef::new(format!("real-executor-lease-{operation}")).expect("action lease"),
        FencingToken::new(1, generation, format!("real-executor-fence-{operation}"))
            .expect("state fence"),
        unix_ms().saturating_add(60_000),
    )
    .expect("real executor admission")
}

#[cfg(windows)]
fn real_executor_path_proof(
    platform: &WindowsPlatform,
    admission: &ProcessExecutionAdmissionRequest,
) -> ProcessPathProof {
    let executable = PathBuf::from(admission.intent().executable());
    let working_directory = PathBuf::from(admission.intent().working_directory());
    let lease = platform
        .retain_process_path_lease(
            &executable,
            &working_directory,
            admission.intent().executable_sha256(),
        )
        .expect("retained real executor path proof");
    ProcessPathProof {
        executable,
        working_directory,
        lease: Arc::new(lease),
    }
}

#[cfg(windows)]
async fn start_real_executor_child(
    gateway: &ProcessExecutionGateway,
    platform: &WindowsPlatform,
    authority: &RealExecutorTestAuthority,
    admission: &ProcessExecutionAdmissionRequest,
    owner: &ProcessOwnerBinding,
) -> ProcessStartReceipt {
    let request = authority.issue(admission);
    let path_guard = gateway
        .insert_path(
            admission.intent().operation_id().clone(),
            real_executor_path_proof(platform, admission),
        )
        .expect("retain path proof");
    let receipt = gateway
        .execute(owner, request)
        .await
        .expect("WindowsProcessExecutor start");
    drop(path_guard);
    receipt
}

#[test]
fn runtime_probe_gate_admits_only_initial_repeat_and_recovery_states() {
    for state in [
        KernelServiceState::Activating,
        KernelServiceState::Ready,
        KernelServiceState::Degraded,
    ] {
        assert!(probe_ready_state_admitted(state));
    }
    for state in [
        KernelServiceState::Cold,
        KernelServiceState::Reconciling,
        KernelServiceState::ShadowNoAuthority,
        KernelServiceState::HandoffPrepared,
        KernelServiceState::Draining,
        KernelServiceState::Stopped,
        KernelServiceState::Failed,
        KernelServiceState::ManualRecovery,
    ] {
        assert!(!probe_ready_state_admitted(state));
    }
}

#[test]
fn repeated_handshake_policy_updates_retain_kernel_artifact_for_bridge_begin() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-handshake-artifact-retention-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let expected_artifact = "d".repeat(64);
    let kernel = KernelComposition::new(
        KernelConfig::new(&root).with_kernel_artifact_sha256(expected_artifact.clone()),
    )
    .expect("kernel composition");
    let generations = kernel
        .generations
        .lock()
        .expect("generation router lock")
        .clone();
    let mut policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy lock")
        .clone();
    let expected_protected = "e".repeat(64);
    policy.config_snapshot["protected_snapshot_digest"] =
        serde_json::Value::String(expected_protected.clone());

    for _ in 0..2 {
        update_handshake_policy(&mut policy, &generations).expect("policy update");
        assert_eq!(
            policy
                .config_snapshot
                .get("artifact_digest")
                .and_then(serde_json::Value::as_str),
            Some(expected_artifact.as_str()),
            "begin_agent_bridge must retain the exact artifact prerequisite after policy updates"
        );
        assert_eq!(
            policy
                .config_snapshot
                .get("protected_snapshot_digest")
                .and_then(serde_json::Value::as_str),
            Some(expected_protected.as_str()),
            "handshake updates must retain the Host-approved protected snapshot identity"
        );
    }

    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_snapshot_exposes_only_a_canonical_protected_digest() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-protected-snapshot-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
    let protected = "f".repeat(64);
    {
        let mut policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy lock");
        policy.config_snapshot["protected_snapshot_digest"] =
            serde_json::Value::String(protected.clone());
    }
    let snapshot = kernel.daemon_snapshot().expect("daemon snapshot");
    assert_eq!(snapshot["protected_snapshot_digest"], protected);

    {
        let mut policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy lock");
        policy.config_snapshot["protected_snapshot_digest"] =
            serde_json::Value::String("F".repeat(64));
    }
    assert!(kernel.daemon_snapshot().is_err());
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn handshake_policy_update_rejects_invalid_protected_digest_without_mutation() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-protected-policy-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
    let generations = kernel
        .generations
        .lock()
        .expect("generation router lock")
        .clone();
    let baseline = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy lock")
        .clone();

    for value in [serde_json::json!(null), serde_json::json!("A".repeat(64))] {
        let mut policy = baseline.clone();
        policy.config_snapshot["protected_snapshot_digest"] = value;
        let before = policy.clone();
        assert!(update_handshake_policy(&mut policy, &generations).is_err());
        assert_eq!(policy, before);
    }

    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn ready_receipt_rejects_absent_running_degraded_and_fatal_daemon_states() {
    assert!(daemon_status_proves_ready(&DaemonRuntimeStatus::Ready));
    for status in [
        DaemonRuntimeStatus::NotLaunched,
        DaemonRuntimeStatus::Launching,
        DaemonRuntimeStatus::Running,
        DaemonRuntimeStatus::Degraded("store unavailable".to_owned()),
        DaemonRuntimeStatus::Failed("fatal".to_owned()),
    ] {
        assert!(!daemon_status_proves_ready(&status));
    }
}

#[cfg(windows)]
#[test]
fn recovery_attempt_uses_fresh_nonce_descriptor_and_operation_identity() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-daemon-recovery-attempt-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let original = test_daemon_launch(&root);
    let first = fresh_eliotd_launch_descriptor(&original, 1).expect("first recovery launch");
    let second = fresh_eliotd_launch_descriptor(&first, 2).expect("second recovery launch");
    first.validate().expect("first descriptor remains exact");
    second.validate().expect("second descriptor remains exact");
    assert_ne!(original.launch_nonce, first.launch_nonce);
    assert_ne!(first.launch_nonce, second.launch_nonce);
    assert_eq!(first.arguments[5], first.launch_nonce);
    assert_eq!(second.arguments[5], second.launch_nonce);
    let first_identity = eliotd_launch_attempt_identity(&first, 41_001, 9_001, "kernel.exe")
        .expect("first launch identity");
    let second_identity = eliotd_launch_attempt_identity(&second, 41_001, 9_001, "kernel.exe")
        .expect("second launch identity");
    let first_operation = eliotd_operation_id(
        Generation::new(first.generation.value()).expect("generation"),
        &first_identity,
    )
    .expect("first operation");
    let second_operation = eliotd_operation_id(
        Generation::new(second.generation.value()).expect("generation"),
        &second_identity,
    )
    .expect("second operation");
    assert_ne!(first_operation, second_operation);
    assert_eq!(first.authority_epoch, original.authority_epoch);
    assert_eq!(first.generation, original.generation);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn recovery_nonce_rotation_fences_stale_daemon_sessions() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-daemon-recovery-session-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let original = test_daemon_launch(&root);
    let kernel = KernelComposition::new(
        KernelConfig::new(&root)
            .with_daemon_launch(original.clone())
            .with_kernel_artifact_sha256("c".repeat(64)),
    )
    .expect("kernel composition");
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let stale = Session {
        connection_id: "stale-eliotd-session".to_owned(),
        protocol_version: policy.protocol_range.maximum,
        peer: PeerIdentity::Unavailable {
            reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
        },
        authority_epoch: policy.module_generation.state_fence.authority_epoch.value(),
        module_generation: policy.module_generation.clone(),
        launch_nonce: policy.launch_nonce.clone(),
        capabilities: policy.allowed_capabilities.clone(),
        privacy_classes: policy.allowed_privacy_classes.clone(),
        effects: policy.allowed_effects.clone(),
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    };
    kernel
        .require_current_daemon_session(&stale)
        .expect("original session binding is current");
    let next = fresh_eliotd_launch_descriptor(&original, 1).expect("fresh recovery launch");
    *kernel
        .daemon_active_launch
        .lock()
        .expect("active launch lock") = Some(next.clone());
    kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .launch_nonce = next.launch_nonce.as_str().to_owned();
    assert!(matches!(
        kernel.require_current_daemon_session(&stale),
        Err(TransportError::SessionFenced)
    ));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn production_handshake_policy_binds_observed_current_process_principal() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-observed-principal-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
    let observed = current_process_named_pipe_expectation().expect("current process identity");
    let expected = format!(
        "sid={};session={}",
        observed.expected_sid(),
        observed.expected_session_id()
    );
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy lock");
    assert_eq!(policy.session_principal_binding, expected);
    assert_ne!(policy.session_principal_binding, "local-user");
}

#[cfg(windows)]
#[tokio::test]
async fn named_job_bind_session_child_connector() {
    let Ok(pipe_name) = std::env::var(BIND_SESSION_CHILD_PIPE_ENV) else {
        return;
    };
    let expectation = current_process_named_pipe_expectation().expect("child expectation");
    let _transport =
        NamedPipeTransport::connect_authenticated(&pipe_name, Duration::from_secs(5), &expectation)
            .await
            .expect("child authenticated connection");
    tokio::time::sleep(Duration::from_secs(30)).await;
}

#[cfg(windows)]
#[tokio::test]
#[ignore = "requires the built external bridge, the protected Windows ACL fixture, and the production 30s no-resolver deadline"]
#[allow(clippy::too_many_lines)]
async fn external_agent_bridge_os_process_receives_typed_semantic_resolution_denial() {
    let bridge_exe = PathBuf::from(
        std::env::var_os("ELIOT_AGENT_BRIDGE_EXE")
            .expect("ELIOT_AGENT_BRIDGE_EXE must name the external bridge executable"),
    );
    assert!(
        bridge_exe.is_absolute(),
        "ELIOT_AGENT_BRIDGE_EXE must be an absolute path"
    );
    assert_eq!(
        bridge_exe.extension().and_then(|value| value.to_str()),
        Some("exe"),
        "ELIOT_AGENT_BRIDGE_EXE must point to an .exe"
    );
    let bridge_bytes = std::fs::read(&bridge_exe).expect("read external bridge executable");
    let bridge_sha256 = sha256_hex(&bridge_bytes);
    assert_eq!(bridge_sha256.len(), 64);
    let bridge_identity =
        eliot_platform_windows::file_identity_for_path(&bridge_exe).expect("bridge file identity");
    assert_ne!(bridge_identity.volume_serial_number, 0);
    assert_ne!(bridge_identity.file_index, 0);

    let host_process = eliot_platform_windows::observe_named_pipe_peer_process(std::process::id())
        .expect("current Host process binding");
    let host_expectation = current_process_named_pipe_expectation()
        .expect("current Host token identity")
        .with_process_binding(host_process)
        .expect("current Host process identity");
    let bridge_generation = ResourceGeneration::new(7).expect("bridge generation");
    let bridge_authority_epoch = AuthorityEpoch::new(8).expect("bridge authority epoch");
    let bridge_state_fence = StateFence::new(bridge_authority_epoch, bridge_generation);
    let work_root = std::env::temp_dir().join(format!(
        "eliot-kernel-r13-denied-os-harness-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&work_root).expect("harness work root");

    // Read the production Kernel ServerHello inputs from a real composition
    // before constructing the protected bridge declaration. This is only
    // fixture setup; admission still goes through the exact descriptor,
    // declaration, peer-set, and Ready checks below.
    let kernel_artifact_sha256 = "e".repeat(64);
    let provisional = KernelComposition::new(
        KernelConfig::new(&work_root).with_kernel_artifact_sha256(kernel_artifact_sha256.clone()),
    )
    .expect("provisional Kernel composition");
    let kernel_policy = provisional
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let kernel_config_snapshot_sha256 =
        sha256_json(&kernel_policy.config_snapshot).expect("Kernel config snapshot digest");
    drop(provisional);

    let protected_root = protected_program_data_root().expect("ProgramData root");
    let installation_id = sha256_hex(
        format!("r13-denied-os-harness-{}-{}", std::process::id(), unix_ms()).as_bytes(),
    );
    let installation_root = protected_root
        .join("Eliot")
        .join("installations")
        .join(&installation_id);
    let installer = eliot_platform_windows::WindowsInstallerRootPrimitive::new();
    let installation_spec = eliot_platform_windows::InstallerRootPrimitiveSpec {
        root: installation_root.clone(),
        installation_root: installation_root.clone(),
        profile_anchor: protected_root.clone(),
        profile: InstallerRootProfile::SystemService,
    };
    let installation_absence = match installer
        .inspect(&installation_spec)
        .expect("inspect exact system-service installation root")
    {
        eliot_platform_windows::InstallerRootPrimitiveObservation::Absent(absence) => absence,
        eliot_platform_windows::InstallerRootPrimitiveObservation::Matching(_) => {
            panic!("unique installation root unexpectedly exists")
        }
        eliot_platform_windows::InstallerRootPrimitiveObservation::Mismatch => {
            panic!("unique installation root has a foreign contour")
        }
    };
    installer
        .create(&installation_spec, &installation_absence)
        .expect("create exact system-service installation root");
    let host_state_root = installation_root;
    let bridge_directory = host_state_root.join("agent-bridge");
    let bridge_spec = eliot_platform_windows::InstallerRootPrimitiveSpec {
        root: bridge_directory.clone(),
        installation_root: host_state_root.clone(),
        profile_anchor: protected_root.clone(),
        profile: InstallerRootProfile::SystemService,
    };
    let bridge_absence = match installer
        .inspect(&bridge_spec)
        .expect("inspect exact system-service bridge directory")
    {
        eliot_platform_windows::InstallerRootPrimitiveObservation::Absent(absence) => absence,
        eliot_platform_windows::InstallerRootPrimitiveObservation::Matching(_) => {
            panic!("unique Agent Bridge directory unexpectedly exists")
        }
        eliot_platform_windows::InstallerRootPrimitiveObservation::Mismatch => {
            panic!("unique Agent Bridge directory has a foreign contour")
        }
    };
    installer
        .create(&bridge_spec, &bridge_absence)
        .expect("create exact system-service Agent Bridge directory");
    eliot_platform_windows::ensure_agent_bridge_directory(&host_state_root)
        .expect("protected bridge directory");
    let profile_path = bridge_directory.join("admission-profile-v1.json");
    let declaration_path = bridge_directory.join("client-declaration-v2.json");
    let profile_id = sha256_hex(host_state_root.to_string_lossy().as_bytes());
    let profile_bytes = serde_json::to_vec(&serde_json::json!({
        "profile_id": profile_id.clone(),
        "executable": bridge_exe.to_string_lossy(),
        "executable_sha256": bridge_sha256.clone(),
        "client_declaration": declaration_path.to_string_lossy(),
    }))
    .expect("profile bytes");
    let profile_sha256 = sha256_hex(&profile_bytes);

    let module_id = ContractId::new(AGENT_BRIDGE_MODULE_ID).expect("bridge module id");
    let artifact_id = ArtifactId::new(bridge_sha256.clone()).expect("bridge artifact id");
    let capabilities = vec!["agent.bridge.activate".to_owned()];
    let privacy_classes = vec!["PUBLIC".to_owned()];
    let declaration = AgentBridgeClientDeclaration {
        wire_id: eliot_protocol::AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION,
        module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
        profile_id: profile_id.clone(),
        protocol_range: eliot_protocol::ProtocolRange {
            minimum: eliot_protocol::ProtocolVersion::CURRENT,
            maximum: eliot_protocol::ProtocolVersion::CURRENT,
        },
        module_contract: ModuleContract {
            module_id: module_id.clone(),
            version: ContractVersion::new(1, 0, 0),
            artifact_id: artifact_id.clone(),
            protocols: vec!["eliot.agent-bridge.v1".to_owned()],
            required_capabilities: capabilities.clone(),
            optional_capabilities: Vec::new(),
            advisory_capabilities: Vec::new(),
            state_owner: "eliot-host".to_owned(),
            failure_domain: "agent-bridge".to_owned(),
            hot_replace: false,
        },
        module_generation: ModuleGeneration {
            module_id,
            generation: bridge_generation,
            artifact_id,
            state: ModuleGenerationState::Ready,
            health: HealthVector::healthy(),
            state_fence: bridge_state_fence.clone(),
        },
        capabilities: capabilities.clone(),
        privacy_classes: privacy_classes.clone(),
        max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES).expect("frame ceiling"),
        expected_kernel_sid: host_expectation.expected_sid().to_owned(),
        expected_kernel_session_id: host_expectation.expected_session_id(),
        expected_kernel_principal_binding: kernel_policy.session_principal_binding.clone(),
        expected_kernel_authority_epoch: kernel_policy
            .module_generation
            .state_fence
            .authority_epoch,
        expected_kernel_generation: kernel_policy.module_generation.generation,
        expected_kernel_artifact_sha256: kernel_artifact_sha256,
        expected_kernel_config_snapshot_sha256: kernel_config_snapshot_sha256.clone(),
        declaration_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("declaration digest");
    declaration.validate().expect("exact declaration");
    let declaration_sha256 = declaration.declaration_sha256.clone();
    let admission = AgentBridgeAdmissionDescriptor {
        wire_id: eliot_kernel_service::AGENT_BRIDGE_ADMISSION_DESCRIPTOR_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::AGENT_BRIDGE_ADMISSION_DESCRIPTOR_WIRE_VERSION,
        module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
        profile_id: PlatformHandle::new(profile_id.clone()).expect("profile handle"),
        profile_sha256,
        executable: PlatformHandle::new(bridge_exe.to_string_lossy()).expect("bridge path"),
        executable_sha256: bridge_sha256.clone(),
        executable_identity: eliot_kernel_service::HostFileIdentity {
            volume_serial_number: bridge_identity.volume_serial_number,
            file_index: bridge_identity.file_index,
        },
        generation: bridge_generation,
        authority_epoch: bridge_authority_epoch,
        state_fence: bridge_state_fence,
        approved_user_sid: host_expectation.expected_sid().to_owned(),
        caller_session_policy:
            eliot_kernel_service::AgentBridgeCallerSessionPolicy::AnyInteractiveSessionForApprovedSid,
        process_policy: eliot_kernel_service::AgentBridgeProcessPolicy::ExactProcessPerConnection,
        allowed_capabilities: capabilities,
        allowed_privacy_classes: privacy_classes,
        max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES).expect("frame ceiling"),
        allowed_effects: vec!["REVERSIBLE_MUTATION".to_owned()],
        expected_kernel_principal_binding: kernel_policy.session_principal_binding,
        expected_kernel_config_snapshot_sha256: kernel_config_snapshot_sha256,
        client_declaration_path: PlatformHandle::new(declaration_path.to_string_lossy())
            .expect("declaration path"),
        client_declaration_sha256: declaration_sha256,
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("admission descriptor digest");
    admission.validate().expect("exact admission descriptor");
    admission
        .validate_client_declaration(&declaration)
        .expect("descriptor/declaration binding");

    installer
        .create_protected_file(&bridge_spec, &profile_path, |_| Ok(profile_bytes.clone()))
        .expect("publish protected profile fixture");
    let declaration_bytes = serde_json::to_vec(&declaration).expect("declaration bytes");
    installer
        .create_protected_file(&bridge_spec, &declaration_path, |_| {
            Ok(declaration_bytes.clone())
        })
        .expect("publish protected declaration fixture");
    eliot_platform_windows::converge_agent_bridge_security(
        &host_state_root,
        host_expectation.expected_sid(),
        &profile_path,
        &declaration_path,
    )
    .expect("converge exact Agent Bridge ACL fixture");
    eliot_platform_windows::verify_agent_bridge_security(
        &host_state_root,
        host_expectation.expected_sid(),
        &profile_path,
        &declaration_path,
    )
    .expect("verify exact Agent Bridge ACL fixture");

    let kernel = KernelComposition::new(
        KernelConfig::new(&work_root)
            .with_kernel_artifact_sha256("e".repeat(64))
            .with_agent_bridge_admission(admission.clone()),
    )
    .expect("Kernel composition with protected bridge admission");

    // Host Phase-B/ProbeReady is a separate integration gate. For this
    // transport harness, install the same validated profile and Ready
    // service state directly, without weakening any production validator.
    *kernel
        .agent_bridge_profile
        .lock()
        .expect("bridge profile lock") = Some(AgentBridgeProfile {
        admission: admission.clone(),
        declaration,
    });
    let candidate = HostKernelCandidateBinding {
        installation_id: PlatformHandle::new("installation-1").expect("installation"),
        host_epoch: AuthorityEpoch::new(1).expect("host epoch"),
        kernel_epoch: bridge_authority_epoch,
        activation_id: PlatformHandle::new("activation-1").expect("activation"),
        artifact_hash: PlatformHandle::new("artifact-r13-denied-os").expect("artifact"),
        config_hash: PlatformHandle::new("config-r13-denied-os").expect("config"),
        job_object_id: PlatformHandle::new("Local\\Eliot-R13-Denied-OS").expect("job"),
        pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE).expect("pipe"),
        host_process: eliot_kernel_service::HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: r"C:\eliot\host.exe".to_owned(),
        },
        job_binding: eliot_kernel_service::HostJobBinding {
            job: eliot_kernel_service::HostJobIdentity {
                name: "Local\\Eliot-R13-Denied-OS".to_owned(),
            },
            root: eliot_kernel_service::HostJobRoot {
                process: eliot_kernel_service::HostProcessBinding {
                    process_id: 42,
                    start_time_100ns: 10,
                    image_path: r"C:\eliot\kernel.exe".to_owned(),
                },
                executable: eliot_kernel_service::HostFileIdentity {
                    volume_serial_number: 1,
                    file_index: 2,
                },
            },
        },
        supervision_incarnation: supervision_incarnation(),
        restart_budget: eliot_kernel_service::RestartBudget::new(1, 1).expect("restart budget"),
        agent_bridge_admission: Some(admission),
        containment_action: None,
    };
    {
        let mut service = kernel.service.lock().expect("service lock");
        service
            .reconcile(candidate.clone())
            .expect("candidate reconcile");
        service
            .apply(KernelControlCommand::Shadow)
            .expect("shadow transition");
        service
            .apply(KernelControlCommand::PrepareHandoff)
            .expect("handoff transition");
        let permit = eliot_kernel_service::KernelActivationPermit {
            operation_id: PlatformHandle::new("activation-op-r13-denied-os").expect("operation"),
            candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: PlatformHandle::new("txn-r13-denied-os").expect("transaction"),
            journal_sequence: 1,
            generation: bridge_generation,
            authority_epoch: bridge_authority_epoch,
            activation_nonce: eliot_platform::KernelActivationNonce::new(
                PlatformHandle::new("a".repeat(64)).expect("activation nonce"),
            )
            .expect("activation nonce"),
        };
        service
            .activate_permit(&permit, bridge_generation, "c".repeat(64))
            .expect("activate candidate");
        let activation_nonce_digest = service
            .activation_receipt()
            .expect("activation receipt")
            .activation_nonce_digest
            .clone();
        service
            .publish_ready(KernelReadyReceipt {
                activation_id: candidate.activation_id.clone(),
                activation_operation_id: permit.operation_id,
                activation_nonce_digest,
                process: eliot_kernel_service::ProcessObservation {
                    process_id: PlatformHandle::new("pid:42:start:10").expect("process"),
                    job_object_id: candidate.job_object_id.clone(),
                    state: eliot_runtime_contracts::ServiceProcessState::Ready,
                    health: HealthVector::healthy(),
                    evidence_refs: vec![PlatformHandle::new("ev-r13-denied-os").expect("evidence")],
                },
                health: HealthVector::healthy(),
                evidence_refs: vec![PlatformHandle::new("ev-r13-denied-os").expect("evidence")],
            })
            .expect("publish Ready state");
    }
    kernel.note_agent_bridge_peer_set_change();

    let peers = kernel
        .front_door_peer_set(&host_expectation)
        .expect("production bridge peer set");
    assert!(peers.entries().iter().any(|entry| {
        entry.kind() == NamedPipePeerKind::AgentBridge
            && entry.profile_id() == Some(profile_id.as_str())
    }));
    let mut server = NamedPipeServer::create_with_peer_set(DEFAULT_PIPE_NAME, &peers)
        .expect("default Kernel front-door pipe");
    let mut child_command = tokio::process::Command::new(&bridge_exe);
    child_command
        .args([
            "--profile",
            "SPINE_FUNCTIONAL",
            "--transport",
            "stdio",
            "--client-declaration",
            declaration_path.to_str().expect("declaration UTF-8 path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = child_command
        .spawn()
        .expect("spawn real external Agent Bridge process");
    let mut child_stdin = child.stdin.take().expect("child stdin");
    let mut child_stdout = child.stdout.take().expect("child stdout");
    let mut child_stderr = child.stderr.take().expect("child stderr");
    let stderr_reader = tokio::spawn(async move {
        let mut stderr = Vec::new();
        child_stderr.read_to_end(&mut stderr).await.map(|_| stderr)
    });

    let selection = match server
        .wait_for_authenticated_client_with_peer_set(Duration::from_secs(5), &peers)
        .await
    {
        Ok(selection) => selection,
        Err(error) => {
            drop(child_stdin);
            let _ = child.kill().await;
            let _ = child.wait().await;
            let stderr = stderr_reader
                .await
                .expect("join bridge stderr reader")
                .expect("read bridge stderr");
            panic!(
                "authenticated real bridge peer-set selection failed: {error}; bridge stderr: {}",
                String::from_utf8_lossy(&stderr)
            );
        }
    };
    assert_eq!(selection.kind(), NamedPipePeerKind::AgentBridge);
    assert_eq!(selection.profile_id(), Some(profile_id.as_str()));
    let peer = server.peer_identity().clone();
    assert!(kernel.agent_bridge_peer_admitted(&selection, &peer));
    let observed = peer
        .process_binding()
        .expect("observed bridge process binding");
    assert!(
        observed
            .image_path()
            .eq_ignore_ascii_case(&bridge_exe.to_string_lossy())
    );
    assert_eq!(
        observed.executable_file_identity(),
        Some((
            bridge_identity.volume_serial_number,
            bridge_identity.file_index,
        ))
    );

    let handshake = kernel
        .begin_agent_bridge(&selection, peer)
        .expect("server-first challenge");
    server
        .send_frame(&handshake.challenge_frame, kernel.ipc_limits())
        .await
        .expect("send server challenge");
    let hello_frame = server
        .receive_frame(kernel.ipc_limits())
        .await
        .expect("receive bridge hello");
    let hello_receipt = kernel
        .accept_agent_bridge_hello(&handshake.connection_id, &hello_frame)
        .expect("accept exact bridge hello");
    hello_receipt.validate().expect("typed admission receipt");
    let receipt_frame = kernel
        .agent_bridge_admission_receipt_frame(&handshake.connection_id)
        .expect("build typed admission receipt frame");
    server
        .send_frame(&receipt_frame, kernel.ipc_limits())
        .await
        .expect("send typed admission receipt");

    let attach_line = serde_json::json!({
        "op": "attach",
        "request": {
            "demand_id": "r13-denied-os-demand",
            "connection_id": handshake.connection_id,
            "attach_kind": "MANAGED",
            "pre_attach_blind_interval": null
        }
    });
    child_stdin
        .write_all(format!("{attach_line}\n").as_bytes())
        .await
        .expect("send bridge attach request");
    let activation_frame = server
        .receive_frame(kernel.ipc_limits())
        .await
        .expect("receive real bridge activation request");
    let denial_frame = kernel
        .await_agent_bridge_activation_response(&handshake.connection_id, &activation_frame)
        .await
        .expect("production no-resolver denial");
    let denial = match &denial_frame.payload {
        ProtocolPayload::Json(payload) => {
            serde_json::from_value::<AgentBridgeActivationResponse>(payload.clone())
                .expect("typed denial payload")
        }
        _ => panic!("denial must be JSON"),
    };
    assert!(matches!(
        denial.disposition,
        AgentBridgeActivationDisposition::Denied {
            reason_code: AgentBridgeActivationDenialCode::SemanticResolutionUnavailable
        }
    ));
    assert!(
        !kernel
            .agent_bridge_connections
            .lock()
            .expect("bridge connection lock")
            .values()
            .any(|state| state.session.is_some() || state.activation_completed),
        "denial must not mint an Authenticated binding or session"
    );
    server
        .send_frame(&denial_frame, kernel.ipc_limits())
        .await
        .expect("send typed denial to real child");
    drop(child_stdin);
    let mut stdout = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        child_stdout.read_to_end(&mut stdout),
    )
    .await
    .expect("bridge stdout deadline")
    .expect("read bridge stdout");
    let stdout = String::from_utf8(stdout).expect("bridge stdout UTF-8");
    assert_eq!(
        stdout,
        concat!(
            r#"{"status":"error","code":"BRIDGE_REQUEST_REJECTED","detail":"activation denied by the trusted host provider: SEMANTIC_RESOLUTION_UNAVAILABLE"}"#,
            "\n"
        )
    );
    assert!(child.wait().await.expect("wait bridge child").success());
    let stderr = stderr_reader
        .await
        .expect("join bridge stderr reader")
        .expect("read bridge stderr");
    assert!(
        stderr.is_empty(),
        "successful bridge child wrote stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    drop(server);
    drop(kernel);
    let _ = std::fs::remove_dir_all(&work_root);
    if std::fs::remove_dir_all(&host_state_root).is_err() {
        // Final ACLs intentionally preserve only the exact bridge
        // declaration read/traverse rights for the approved user. If a
        // normal recursive removal is denied, use the production
        // identity/content-fenced retirement API on the exact child,
        // then remove the now-empty unique installation root.
        let observation = eliot_platform_windows::observe_owned_directory_exact(
            &bridge_directory,
            &["admission-profile-v1.json", "client-declaration-v2.json"],
            16 * 1024 * 1024,
        )
        .expect("observe exact bridge files for cleanup");
        let outcome = eliot_platform_windows::retire_owned_directory_exact(
            &bridge_directory,
            &observation.retirement_precondition(),
        )
        .expect("retire exact bridge files for cleanup");
        assert!(matches!(
            outcome,
            eliot_platform_windows::OwnedDirectoryRetirementOutcome::Retired
                | eliot_platform_windows::OwnedDirectoryRetirementOutcome::CommittedUnknown(_)
        ));
        std::fs::remove_dir(&host_state_root)
            .expect("remove empty unique installation root after retirement");
    }
}

#[cfg(windows)]
#[tokio::test]
async fn real_executor_receipt_child() {
    if std::env::var(REAL_EXECUTOR_CHILD_ENV).as_deref() != Ok("1") {
        return;
    }
    tokio::time::sleep(Duration::from_secs(30)).await;
}

#[cfg(windows)]
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the production discriminator must retain one real named Job child, authenticated pipe peer, receipt, and bind_session call"
)]
async fn bind_session_uses_physical_executor_job_not_logical_job_id() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-bind-session-job-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let executable = std::env::current_exe().expect("test executable");
    let executable_sha256 = sha256_hex(&std::fs::read(&executable).expect("read test executable"));
    let executable_handle =
        PlatformHandle::new(executable.to_string_lossy()).expect("test executable handle");
    let mut launch = test_daemon_launch(&root);
    launch.executable = executable_handle;
    launch.executable_sha256.clone_from(&executable_sha256);
    launch.working_directory = PlatformHandle::new(
        executable
            .parent()
            .expect("test executable parent")
            .to_string_lossy(),
    )
    .expect("working directory handle");
    launch.arguments[7] =
        PlatformHandle::new(launch.executable_sha256.clone()).expect("executable digest argument");
    launch.descriptor_sha256 = String::new();
    launch = launch.with_computed_digest().expect("test launch digest");
    let kernel = KernelComposition::new(
        KernelConfig::new(&root)
            .with_daemon_launch(launch.clone())
            .with_kernel_artifact_sha256("c".repeat(64)),
    )
    .expect("kernel composition");

    let expectation = current_process_named_pipe_expectation().expect("server expectation");
    let pipe_name = format!(
        r"\\.\pipe\eliot\kernel-bind-session-test\{}-{}",
        std::process::id(),
        unix_ms()
    );
    let mut server = NamedPipeServer::create(&pipe_name, &expectation).expect("test pipe");
    let containment_root = executable.parent().expect("test executable parent");
    let (gateway, platform, test_authority) =
        real_process_gateway(&root.join("real-executor"), containment_root);
    let operation = format!("bind-session-real-executor-{}", unix_ms());
    let admission = real_executor_admission(
        &executable,
        &executable_sha256,
        &operation,
        "tests::named_job_bind_session_child_connector",
        BTreeMap::from([(BIND_SESSION_CHILD_PIPE_ENV.to_owned(), pipe_name.clone())]),
    );
    let owner = gateway_test_owner();
    let receipt =
        start_real_executor_child(&gateway, &platform, &test_authority, &admission, &owner).await;
    server
        .wait_for_authenticated_client(Duration::from_secs(5), &expectation)
        .await
        .expect("authenticated child peer");
    let peer = server.peer_identity().clone();
    {
        let mut state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
        state.status = DaemonRuntimeStatus::Running;
        state.receipt = Some(receipt.clone());
    }
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let client = test_client(&policy);
    kernel
        .bind_session("eliotd-real-job", peer.clone(), &client)
        .expect("physical Job-bound session");

    let mut substituted = serde_json::to_value(&receipt).expect("serialize actual receipt");
    substituted["identity"]["suspended"]["physical"]["executor_job_name"] =
        serde_json::Value::String(r"Local\Eliot-Missing-Executor-Job".to_owned());
    let missing_job_receipt: ProcessStartReceipt =
        serde_json::from_value(substituted).expect("structurally valid substituted receipt");
    missing_job_receipt
        .validate()
        .expect("substitution remains structurally valid but has no live OS Job proof");
    kernel
        .daemon_runtime
        .lock()
        .expect("daemon runtime lock")
        .receipt = Some(missing_job_receipt);
    assert!(
        kernel
            .bind_session("eliotd-logical-job-only", peer, &client)
            .is_err()
    );
    gateway
        .executor
        .shutdown()
        .expect("terminate real executor child Job");
    drop(gateway);
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

fn test_client(policy: &ServerHandshakePolicy) -> eliot_protocol::ClientHello {
    eliot_protocol::ClientHello {
        protocol_range: policy.protocol_range,
        module_bridge_identity: policy.module_id.clone(),
        artifact_hash: policy.module_generation.artifact_id.clone(),
        module_contract: ModuleContract {
            module_id: policy.module_generation.module_id.clone(),
            version: ContractVersion::new(1, 0, 0),
            artifact_id: policy.module_generation.artifact_id.clone(),
            protocols: vec![PROTOCOL_VERSION.to_owned()],
            required_capabilities: Vec::new(),
            optional_capabilities: Vec::new(),
            advisory_capabilities: Vec::new(),
            state_owner: SERVICE_NAME.to_owned(),
            failure_domain: SERVICE_NAME.to_owned(),
            hot_replace: false,
        },
        module_generation: policy.module_generation.clone(),
        launch_nonce: policy.launch_nonce.clone(),
        capabilities: policy.allowed_capabilities.clone(),
        privacy_classes: policy.allowed_privacy_classes.clone(),
        max_frame: policy.max_frame,
        authority_epoch: policy.module_generation.state_fence.authority_epoch,
    }
}

#[cfg(windows)]
#[test]
fn bridge_client_first_identity_is_fenced_before_session_creation() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-bridge-client-first-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let mut client = test_client(&policy);
    client.module_bridge_identity = AGENT_BRIDGE_MODULE_ID.to_owned();
    assert!(matches!(
        kernel.bind_session(
            "bridge-client-first",
            PeerIdentity::Unavailable {
                reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
            },
            &client,
        ),
        Err(TransportError::SessionFenced)
    ));
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
fn test_daemon_launch(root: &Path) -> EliotdLaunchDescriptor {
    let executable =
        PlatformHandle::new(root.join("eliotd.exe").to_string_lossy()).expect("eliotd path");
    let config = PlatformHandle::new(root.join("eliotd-governor.json").to_string_lossy())
        .expect("eliotd config path");
    let working_directory = PlatformHandle::new(root.to_string_lossy()).expect("working directory");
    let executable_sha256 = "a".repeat(64);
    let config_sha256 = "b".repeat(64);
    let nonce =
        PlatformHandle::new("eliotd:0123456789abcdef0123456789abcdef").expect("launch nonce");
    EliotdLaunchDescriptor {
        wire_id: "eliot.kernel.eliotd-launch".to_owned(),
        wire_version: EliotdLaunchDescriptor::CONTRACT_VERSION,
        executable,
        executable_sha256: executable_sha256.clone(),
        arguments: vec![
            PlatformHandle::new("--config-descriptor").expect("argument"),
            config.clone(),
            PlatformHandle::new("--config-descriptor-sha256").expect("argument"),
            PlatformHandle::new(&config_sha256).expect("argument"),
            PlatformHandle::new("--launch-nonce").expect("argument"),
            nonce.clone(),
            PlatformHandle::new("--executable-sha256").expect("argument"),
            PlatformHandle::new(&executable_sha256).expect("argument"),
        ],
        working_directory,
        config_descriptor: config,
        config_descriptor_sha256: config_sha256,
        protected_snapshot_digest: "c".repeat(64),
        launch_nonce: nonce,
        authority_epoch: AuthorityEpoch::genesis(),
        generation: ResourceGeneration::genesis(),
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("descriptor digest")
}

#[cfg(windows)]
#[allow(dead_code, clippy::too_many_lines)]
fn live_receipt_manifest(
    root: &Path,
    roots: &eliot_installation::RuntimeStateRoots,
    launch: &EliotdLaunchDescriptor,
    descriptor_artifact_sha256: &str,
    supervision_key_fingerprint: &str,
) -> eliot_installation::CandidateManifest {
    let handle = |value: String| PlatformHandle::new(value).expect("manifest handle");
    let path = |name: &str| {
        handle(
            root.join("artifacts")
                .join(name)
                .to_string_lossy()
                .into_owned(),
        )
    };
    let installation_epoch = eliot_installation::InstallationEpoch {
        installation: handle("installation-1".to_owned()),
        lineage_id: handle("lineage-live-receipt-1".to_owned()),
        sequence: 1,
    };
    let generation = handle("generation-live-1".to_owned());
    let store_config_path = path("generation.json");
    let authority_descriptor_path = path("authority.json");
    let store_bootstrap_descriptor_path = path("store-bootstrap.json");
    let store_bridge_executable_path = path("eliot-store-surreal.exe");
    let canonical_store_executable_path = path("surreal.exe");
    let host_executable_path = path("eliot-host.exe");
    let watchdog_executable_path = path("eliot-watchdog.exe");
    let kernel_executable_path = path("eliot-kernel.exe");
    let authority_descriptor_digest = handle("7".repeat(64));
    let store_bootstrap_descriptor_digest = handle("6".repeat(64));
    let kernel_artifact_digest = handle("c".repeat(64));
    let store_bridge_artifact_digest = handle("1".repeat(64));
    let canonical_store_artifact_digest = handle("5".repeat(64));
    let host_artifact_digest = handle("8".repeat(64));
    let mut runtime_launch = eliot_installation::RuntimeLaunchDescriptor {
        profile: eliot_installation::InstallationProfile::PortableDev,
        portable_root: Some(handle(root.to_string_lossy().into_owned())),
        installation_epoch,
        generation: generation.clone(),
        authority_generation: ResourceGeneration::genesis(),
        authority_state_fence: StateFence::new(
            AuthorityEpoch::genesis(),
            ResourceGeneration::genesis(),
        ),
        authority_descriptor_path: authority_descriptor_path.clone(),
        authority_descriptor_digest: authority_descriptor_digest.clone(),
        supervision_authority: eliot_installation::SupervisionAuthorityBinding::Pending {
            supervision_lease_scope_id: handle("supervision-lease-live-receipt".to_owned()),
        },
        runtime_state_roots: roots.clone(),
        kernel_work_root: roots.kernel_work_root.clone(),
        kernel_artifact_digest: kernel_artifact_digest.clone(),
        eliotd_executable_path: launch.executable.clone(),
        eliotd_artifact_digest: handle(launch.executable_sha256.clone()),
        eliotd_config_path: launch.config_descriptor.clone(),
        eliotd_config_digest: handle(launch.config_descriptor_sha256.clone()),
        protected_snapshot_digest: handle(launch.protected_snapshot_digest.clone()),
        eliotd_descriptor_path: path("eliotd.json"),
        eliotd_descriptor_digest: handle(descriptor_artifact_sha256.to_owned()),
        eliotd_launch_nonce: launch.launch_nonce.clone(),
        store_config_path: store_config_path.clone(),
        store_credential_target: handle(
            "eliot/store/v1/0123456789abcdef0123456789abcdef".to_owned(),
        ),
        store_bridge_executable_path: store_bridge_executable_path.clone(),
        store_bridge_artifact_digest: store_bridge_artifact_digest.clone(),
        store_bootstrap_descriptor_path: store_bootstrap_descriptor_path.clone(),
        store_bootstrap_descriptor_digest: store_bootstrap_descriptor_digest.clone(),
        canonical_store_executable_path: canonical_store_executable_path.clone(),
        canonical_store_artifact_digest: canonical_store_artifact_digest.clone(),
        kernel_arguments: vec![
            handle("--work-root".to_owned()),
            roots.kernel_work_root.clone(),
            handle("--store-bootstrap".to_owned()),
            store_bootstrap_descriptor_path,
            handle("--store-bootstrap-sha256".to_owned()),
            store_bootstrap_descriptor_digest,
            handle("--authority-descriptor".to_owned()),
            authority_descriptor_path,
            handle("--authority-descriptor-sha256".to_owned()),
            authority_descriptor_digest,
            handle("--kernel-artifact-sha256".to_owned()),
            kernel_artifact_digest.clone(),
            handle("--eliotd-descriptor".to_owned()),
            path("eliotd.json"),
            handle("--eliotd-descriptor-sha256".to_owned()),
            handle(descriptor_artifact_sha256.to_owned()),
        ],
        store_bridge_arguments: vec![
            handle("--portable-dev-root".to_owned()),
            handle(root.to_string_lossy().into_owned()),
            handle("--config".to_owned()),
            store_config_path.clone(),
        ],
        canonical_store_arguments: vec![
            handle("start".to_owned()),
            handle("--no-banner".to_owned()),
            handle("--bind".to_owned()),
            handle("127.0.0.1:8000".to_owned()),
            handle("--temporary-directory".to_owned()),
            roots.store_temp_root.clone(),
            handle("--log-file-enabled".to_owned()),
            handle("--log-file-path".to_owned()),
            roots.store_work_root.clone(),
            handle("--log-file-name".to_owned()),
            handle("surrealdb.log".to_owned()),
            handle(format!(
                "surrealkv://{}",
                roots.store_data_root.as_str().replace('\\', "/")
            )),
        ],
        host_executable_path: host_executable_path.clone(),
        host_artifact_digest: host_artifact_digest.clone(),
        watchdog_executable_path,
        watchdog_artifact_digest: handle("4".repeat(64)),
        descriptor_digest: handle("0".repeat(64)),
    };
    runtime_launch = runtime_launch
        .with_computed_digest()
        .expect("sealed live receipt runtime launch");
    let manifest = eliot_installation::CandidateManifest {
        generation,
        components: vec![
            handle("component:kernel".to_owned()),
            handle("component:store".to_owned()),
        ],
        kernel_artifact_digest,
        store_bridge_artifact_digest,
        canonical_store_artifact_digest,
        host_artifact_digest,
        kernel_executable_path,
        store_bridge_executable_path,
        canonical_store_executable_path,
        host_executable_path,
        config_path: store_config_path,
        dependency_closure_refs: vec![handle("evidence:dependency-closure".to_owned())],
        license_refs: vec![handle("evidence:licenses".to_owned())],
        config_digest: handle("2".repeat(64)),
        store_credential_target: handle(
            "eliot/store/v1/0123456789abcdef0123456789abcdef".to_owned(),
        ),
        supervision_key_slot: handle(supervision_key_fingerprint.to_owned()),
        signature_ref: handle("evidence:signature".to_owned()),
        runtime_state_roots_digest: roots.roots_digest.clone(),
        runtime_launch,
    };
    manifest.validate().expect("live receipt manifest");
    manifest
}

#[cfg(windows)]
#[allow(dead_code)]
fn write_active_manifest_registry(
    host_root: &Path,
    manifest: &eliot_installation::CandidateManifest,
) {
    let candidate_digest = manifest.compute_digest().expect("candidate digest");
    let generation = manifest.generation.as_str();
    let registry = serde_json::json!({
        "registry_wire_version": { "major": 10, "minor": 0, "patch": 0 },
        "revision": 2,
        "generations": [{
            "manifest": manifest,
            "approval": {
                "approval_ref": "approval:live-receipt",
                "transaction_id": "transaction:live-receipt",
                "installer_plan_digest": "d".repeat(64),
                "generation": generation,
                "candidate_manifest_digest": candidate_digest.as_str(),
                "runtime_descriptor_digest": manifest.runtime_launch.descriptor_digest.as_str(),
                "required_owner": "owner:installation",
                "signature_ref": manifest.signature_ref.as_str(),
                "authority_descriptor_path": manifest.runtime_launch.authority_descriptor_path.as_str(),
                "authority_descriptor_digest": manifest.runtime_launch.authority_descriptor_digest.as_str(),
                "authority_generation": manifest.runtime_launch.authority_generation,
                "authority_state_fence": manifest.runtime_launch.authority_state_fence,
            },
            "active": true,
            "last_known_good": true,
        }],
        "service_registration_approvals": [],
        "active_generation": generation,
        "last_known_good_generation": generation,
        "pending_activation": null,
        "last_terminal_activation": null,
        "active_phase_b_rebind": null,
    });
    let path = host_root.join("installation-registry.redb");
    let database = redb::Database::create(&path).expect("create active registry");
    let write = database.begin_write().expect("begin active registry write");
    {
        let mut table = write
            .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                "eliot_approved_generations_v2",
            ))
            .expect("open active registry table");
        let bytes = serde_json::to_vec(&registry).expect("active registry bytes");
        table
            .insert("registry", bytes.as_slice())
            .expect("insert active registry");
    }
    write.commit().expect("commit active registry");
}

#[cfg(windows)]
fn test_process_start_receipt(pid: u32) -> ProcessStartReceipt {
    test_process_start_receipt_with_physical(
        pid,
        1,
        r"C:\ProgramData\Eliot\bin\eliotd.exe",
        r"Local\Eliot-P04-test",
    )
}

#[cfg(windows)]
fn test_process_start_receipt_with_physical(
    pid: u32,
    start_time_100ns: u64,
    image_path: &str,
    executor_job_name: &str,
) -> ProcessStartReceipt {
    serde_json::from_value(serde_json::json!({
        "binding": {
            "operation_id": "eliotd-ready-test-operation",
            "process_tree_id": "eliotd-ready-test-tree",
            "job_id": "eliotd-ready-test-job",
            "image_id": "eliotd-ready-test-image",
            "session_id": "eliotd-ready-test-session",
            "generation": 1,
            "action_lease_ref": "eliotd-ready-test-lease",
            "authority_id": "eliotd",
            "authority_epoch": 1,
            "state_fence": {
                "authority_epoch": 1,
                "generation": 1,
                "nonce": "eliotd-ready-test-fence"
            },
            "request_digest": "a".repeat(64),
            "permit_digest": "b".repeat(64),
            "effect_digest": "c".repeat(64),
            "validation_revision": 1
        },
        "identity": {
            "suspended": {
                "process_id": "eliotd-ready-test-process",
                "process_tree_id": "eliotd-ready-test-tree",
                "job_id": "eliotd-ready-test-job",
                "image_id": "eliotd-ready-test-image",
            "session_id": "eliotd-ready-test-session",
            "generation": 1,
            "physical": {
                "process_id": pid,
                "start_time_100ns": start_time_100ns,
                "image_path": image_path,
                "executor_job_name": executor_job_name
            },
            "created_suspended_at_unix_ms": 1,
                "executable_sha256": "a".repeat(64)
            },
            "resumed_at_unix_ms": 2
        },
        "lifecycle": "running"
    }))
    .expect("test process start receipt")
}

#[cfg(windows)]
fn test_eliotd_live_receipt(
    revision: u64,
    ors_receipt_sha256: &str,
    request_id: &str,
) -> EliotdLiveReceipt {
    EliotdLiveReceipt::new(
        r"C:\ProgramData\Eliot\HostState",
        "1".repeat(64),
        "2".repeat(64),
        "installation-1",
        "generation-1",
        1,
        1,
        "3".repeat(64),
        "4".repeat(64),
        "5".repeat(64),
        test_process_start_receipt(401),
        EliotdLiveSupervisionEvidence {
            lease_id: "eliot-supervision-lease:v1:current".to_owned(),
            record_id: format!("eliot-supervision-lease:v1:current::r{revision:020}"),
            revision,
            receipt_sha256: ors_receipt_sha256.to_owned(),
            envelope_sha256: "6".repeat(64),
            payload_sha256: "7".repeat(64),
            public_key_fingerprint: "8".repeat(64),
        },
        EliotdLiveReadyEvidence {
            request_id: request_id.to_owned(),
            request_payload_sha256: "9".repeat(64),
            connection_id: "connection-1".to_owned(),
            session_epoch: 1,
            authority_epoch: 1,
            generation: 1,
            launch_nonce_sha256: "a".repeat(64),
        },
        1_000 + revision,
    )
    .expect("valid test eliotd live receipt")
}

#[cfg(windows)]
#[test]
fn eliotd_receipt_replay_and_renewal_require_exact_operation_lineage() {
    let first = test_eliotd_live_receipt(1, &"b".repeat(64), "daemon-ready-1");
    assert_eq!(
        classify_eliotd_live_receipt_transition(&first, &first, false, None, None)
            .expect("exact response-loss replay"),
        EliotdLiveReceiptDisposition::ExactReplay
    );
    let foreign_request = test_eliotd_live_receipt(1, &"b".repeat(64), "daemon-ready-foreign");
    assert!(
        classify_eliotd_live_receipt_transition(&first, &foreign_request, false, None, None,)
            .is_err()
    );

    let renewed = test_eliotd_live_receipt(2, &"c".repeat(64), "daemon-ready-1");
    let successor = EliotdSupervisionSuccessorEvidence {
        operation: SupervisionLeaseOperation::Renew,
        state: LeaseState::Active,
        lease_id: renewed.supervision.lease_id.clone(),
        revision: renewed.supervision.revision,
        receipt_sha256: renewed.supervision.receipt_sha256.clone(),
        previous_receipt_sha256: Some(first.supervision.receipt_sha256.clone()),
    };
    assert_eq!(
        classify_eliotd_live_receipt_transition(&first, &renewed, true, None, Some(&successor),)
            .expect("exact ORS renewal predecessor"),
        EliotdLiveReceiptDisposition::ReplaceRenewalPredecessor
    );
    let mut substituted = successor;
    substituted.previous_receipt_sha256 = Some("d".repeat(64));
    assert!(
        classify_eliotd_live_receipt_transition(&first, &renewed, true, None, Some(&substituted),)
            .is_err()
    );
}

#[cfg(windows)]
#[test]
fn running_daemon_retains_only_the_same_authenticated_ready_publication_operation() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-ready-operation-binding-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("composition");
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let session = Session {
        connection_id: "authenticated-eliotd-connection".to_owned(),
        protocol_version: policy.protocol_range.maximum,
        peer: PeerIdentity::Unavailable {
            reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
        },
        authority_epoch: policy.module_generation.state_fence.authority_epoch.value(),
        module_generation: policy.module_generation.clone(),
        launch_nonce: policy.launch_nonce.clone(),
        capabilities: policy.allowed_capabilities.clone(),
        privacy_classes: policy.allowed_privacy_classes.clone(),
        effects: policy.allowed_effects.clone(),
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    };
    let payload = serde_json::json!({
        "generation": session.module_generation.generation.value(),
        "authority_epoch": session.authority_epoch,
    });
    let exact = KernelComposition::eliotd_live_ready_evidence(
        &session,
        &RequestId::new("daemon-ready-1").expect("request id"),
        &payload,
    )
    .expect("exact authenticated operation");
    let foreign = KernelComposition::eliotd_live_ready_evidence(
        &session,
        &RequestId::new("daemon-ready-foreign").expect("request id"),
        &payload,
    )
    .expect("foreign authenticated operation");
    let mut state = DaemonRuntimeState {
        status: DaemonRuntimeStatus::Running,
        receipt: Some(test_process_start_receipt(401)),
        recovery_fenced: false,
        supervision: None,
        live_ready: None,
    };
    state
        .bind_live_receipt_publication_operation(&exact)
        .expect("first authenticated operation binding");
    state
        .bind_live_receipt_publication_operation(&exact)
        .expect("same operation response-loss replay");
    assert!(
        state
            .bind_live_receipt_publication_operation(&foreign)
            .is_err()
    );
    assert_eq!(state.live_ready.as_ref(), Some(&exact));
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the cryptographic replay discriminator constructs and corrupts one complete active-to-terminal Redb history"
)]
fn superseded_replay_requires_the_exact_terminal_signature_and_history() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-supervision-terminal-replay-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&root).expect("create ORS test root");
    let ors = RedbRecoveryStore::open(root.join("kernel-ors.redb")).expect("open ORS");
    let signer = Ed25519SupervisionLeaseSigner::from_secret_key(
        "kernel-test-signer",
        "kernel-test-key",
        [0x31; 32],
    )
    .expect("test signer");
    let anchor = SupervisionTrustAnchor::new(
        "installation-1",
        signer.signer_id(),
        signer.key_id(),
        signer.public_key().to_vec(),
    )
    .expect("test trust anchor");
    let lease_id =
        OperationIdentity::new(supervision_incarnation().supervision_lease_id).expect("lease id");
    let now_ms = unix_ms();
    let binding = eliot_ors::SupervisionLeaseBinding {
        scope_ref: OperationIdentity::new(
            supervision_incarnation()
                .derived_scope_ref()
                .expect("scope ref"),
        )
        .expect("scope identity"),
        observation_scope: eliot_runtime_contracts::canonical_observation_scope(),
        installation_id: OperationIdentity::new("installation-1").expect("installation"),
        host_epoch: AuthorityEpoch::genesis(),
        activation_id: OperationIdentity::new("activation-1").expect("activation"),
        activation_generation: ResourceGeneration::genesis(),
        kernel_epoch: AuthorityEpoch::genesis(),
        watchdog_epoch: AuthorityEpoch::genesis(),
        generation_binding: SupervisionGenerationBinding {
            target_id: "eliotd-artifact".to_owned(),
            target_generation: ResourceGeneration::genesis(),
            module_id: "eliotd".to_owned(),
            module_generation: ResourceGeneration::genesis(),
            process_id: "pid:401:start:1".to_owned(),
            process_generation: ResourceGeneration::genesis(),
        },
        state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        issued_at_ms: now_ms,
        expires_at_ms: now_ms.saturating_add(60_000),
        renew_before_ms: now_ms.saturating_add(30_000),
        wake_policy: eliot_runtime_contracts::canonical_wake_policy(),
        state: LeaseState::Active,
        terminal_disposition: None,
        revocation_reason: None,
        revocation_id: None,
        revocation_epoch: None,
    };
    let active_stage = ors
        .prepare_supervision_lease(SupervisionLeasePrepareRequest {
            ticket_id: OperationIdentity::new("active-ticket").expect("ticket"),
            operation_id: OperationIdentity::new("active-operation").expect("operation"),
            lease_id: lease_id.clone(),
            expected_revision: None,
            operation: SupervisionLeaseOperation::Commit,
            binding: binding.clone(),
        })
        .expect("prepare active");
    let active_envelope = active_stage
        .ticket
        .expected_payload()
        .expect("active payload")
        .sign(&signer)
        .expect("sign active");
    let active_context = verification_context_for_supervision_payload(
        &anchor,
        &active_envelope.payload,
        active_envelope.payload.issued_at_ms,
    );
    let active_verified = anchor
        .verify(&active_envelope, &active_context)
        .expect("verify active");
    let active = ors
        .commit_supervision_lease(&active_stage.ticket, &active_verified)
        .expect("commit active");
    let predecessor = SupervisionLeasePredecessorIdentity {
        supervision_lease_id: lease_id.as_str().to_owned(),
        ors_receipt_sha256: active.receipt.receipt_sha256.clone(),
    };
    let mut terminal_binding = binding;
    terminal_binding.state = LeaseState::Superseded;
    terminal_binding.terminal_disposition = Some(SupervisionLeaseTerminalDisposition::Superseded);
    let terminal_stage = ors
        .prepare_supervision_lease(SupervisionLeasePrepareRequest {
            ticket_id: OperationIdentity::new("terminal-ticket").expect("ticket"),
            operation_id: OperationIdentity::new("terminal-operation").expect("operation"),
            lease_id,
            expected_revision: Some(active.record.revision),
            operation: SupervisionLeaseOperation::Supersede,
            binding: terminal_binding,
        })
        .expect("prepare terminal");
    let terminal_envelope = terminal_stage
        .ticket
        .expected_payload()
        .expect("terminal payload")
        .sign(&signer)
        .expect("sign terminal");
    let predecessor_proof = SupervisionLeasePredecessorProof {
        lease_id: active.record.lease_id.as_str().to_owned(),
        record_id: active.record.record_id.as_str().to_owned(),
        lease_revision: active.record.revision,
        receipt_sha256: active.receipt.receipt_sha256.clone(),
        envelope_sha256: active
            .record
            .artifact
            .envelope_digest()
            .expect("active envelope digest"),
    };
    let terminal_verified = anchor
        .verify_terminal_transition(&active_verified, &terminal_envelope, &predecessor_proof)
        .expect("verify terminal");
    let terminal = ors
        .commit_terminal_supervision_lease(&terminal_stage.ticket, &terminal_verified)
        .expect("commit terminal");
    verify_superseded_supervision_replay(&ors, &anchor, &terminal, &predecessor)
        .expect("cryptographic terminal replay");

    let mut forged_signature = terminal.clone();
    forged_signature.record.artifact.signature = "00".repeat(64);
    assert!(
        verify_superseded_supervision_replay(&ors, &anchor, &forged_signature, &predecessor,)
            .is_err()
    );
    let mut forged_mirror = terminal.clone();
    forged_mirror
        .record
        .artifact
        .payload
        .ors_mirror
        .previous_receipt_sha256 = Some("d".repeat(64));
    assert!(
        verify_superseded_supervision_replay(&ors, &anchor, &forged_mirror, &predecessor,).is_err()
    );

    let foreign_signer = Ed25519SupervisionLeaseSigner::from_secret_key(
        "kernel-test-signer",
        "kernel-test-key",
        [0x32; 32],
    )
    .expect("foreign signer");
    let foreign_anchor = SupervisionTrustAnchor::new(
        "installation-1",
        foreign_signer.signer_id(),
        foreign_signer.key_id(),
        foreign_signer.public_key().to_vec(),
    )
    .expect("foreign anchor");
    assert!(
        verify_superseded_supervision_replay(&ors, &foreign_anchor, &terminal, &predecessor,)
            .is_err()
    );
    drop(ors);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn eliotd_attempt_identity_is_stable_within_one_kernel_and_changes_after_restart() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-daemon-attempt-identity-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let launch = test_daemon_launch(&root);
    let first = eliotd_launch_attempt_identity(
        &launch,
        41_001,
        9_001,
        r"C:\ProgramData\Eliot\bin\eliot-kernel.exe",
    )
    .expect("first attempt identity");
    let same = eliotd_launch_attempt_identity(
        &launch,
        41_001,
        9_001,
        r"C:\ProgramData\Eliot\bin\eliot-kernel.exe",
    )
    .expect("same attempt identity");
    let restarted = eliotd_launch_attempt_identity(
        &launch,
        41_001,
        9_002,
        r"C:\ProgramData\Eliot\bin\eliot-kernel.exe",
    )
    .expect("restarted attempt identity");
    assert_eq!(first, same);
    assert_ne!(first, restarted);
    assert_ne!(
        first,
        sha256_hex(launch.launch_nonce.as_str().as_bytes()),
        "the fixed descriptor nonce alone must never key a process effect replay"
    );
}

#[cfg(windows)]
#[test]
fn receipt_publication_race_is_retryable_only_for_exact_bound_client() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-daemon-receipt-race-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let launch = test_daemon_launch(&root);
    let kernel = KernelComposition::new(
        KernelConfig::new(&root)
            .with_daemon_launch(launch.clone())
            .with_kernel_artifact_sha256("c".repeat(64)),
    )
    .expect("kernel composition");
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let exact_client = test_client(&policy);
    KernelComposition::validate_eliotd_client_binding(&launch, &policy, &exact_client)
        .expect("exact descriptor-bound client");
    let mut substituted = exact_client.clone();
    substituted.launch_nonce = "eliotd:ffffffffffffffffffffffffffffffff".to_owned();
    assert!(matches!(
        KernelComposition::validate_eliotd_client_binding(&launch, &policy, &substituted),
        Err(TransportError::SessionFenced)
    ));

    let receipt = test_process_start_receipt(std::process::id());
    let mut state = DaemonRuntimeState {
        status: DaemonRuntimeStatus::Launching,
        receipt: None,
        recovery_fenced: false,
        supervision: None,
        live_ready: None,
    };
    assert!(matches!(
        KernelComposition::published_daemon_receipt(&state),
        Err(TransportError::PlanGap {
            dependency: ELIOTD_RECEIPT_PENDING_DEPENDENCY,
            reason: ELIOTD_RECEIPT_PENDING_REASON,
        })
    ));
    state.status = DaemonRuntimeStatus::Running;
    state.receipt = Some(receipt.clone());
    assert_eq!(
        KernelComposition::published_daemon_receipt(&state).expect("published exact receipt"),
        receipt
    );
}

#[cfg(windows)]
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the authenticated handshake negative keeps generation and missing production supervision dependencies on one retained contour"
)]
async fn authenticated_handshake_fences_ready_without_production_supervision_dependencies() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-daemon-ready-rendezvous-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel =
        Arc::new(KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition"));
    let expectation = current_process_named_pipe_expectation().expect("current identity");
    let pipe_name = format!(
        r"\\.\pipe\eliot\kernel-ready-test\{}-{}",
        std::process::id(),
        unix_ms()
    );
    let mut server = NamedPipeServer::create(&pipe_name, &expectation).expect("test pipe");
    let server_expectation = expectation.clone();
    let server_task = tokio::spawn(async move {
        server
            .wait_for_authenticated_client(Duration::from_secs(2), &server_expectation)
            .await
            .expect("authenticated client");
        server
    });
    let _client =
        NamedPipeTransport::connect_authenticated(&pipe_name, Duration::from_secs(2), &expectation)
            .await
            .expect("authenticated transport");
    let server = server_task.await.expect("server task");
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let handshake = Session::establish_with_server(
        "eliotd-ready-test",
        server.peer_identity().clone(),
        &test_client(&policy),
        &policy,
    )
    .expect("authenticated daemon handshake");
    assert_eq!(
        handshake.server_hello.session_principal_binding,
        observed_session_principal_binding().expect("observed binding")
    );

    let receipt = test_process_start_receipt(std::process::id());
    {
        let mut state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
        state.status = DaemonRuntimeStatus::Running;
        state.receipt = Some(receipt.clone());
    }
    let wait_kernel = Arc::clone(&kernel);
    let wait_receipt = receipt.clone();
    let waiter = tokio::spawn(async move {
        wait_kernel
            .await_daemon_ready(&wait_receipt, Duration::from_millis(50))
            .await
    });
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());
    assert!(
        kernel
            .execute_daemon_request(
                &handshake.session,
                RequestId::new("eliotd-ready-wrong-generation").expect("request id"),
                "daemon_ready",
                serde_json::json!({
                    "generation": policy.module_generation.generation.value() + 1,
                    "authority_epoch": policy
                        .module_generation
                        .state_fence
                        .authority_epoch
                        .value(),
                }),
            )
            .await
            .is_err()
    );
    assert!(!waiter.is_finished());
    assert!(
        kernel
            .execute_daemon_request(
                &handshake.session,
                RequestId::new("eliotd-ready-exact").expect("request id"),
                "daemon_ready",
                serde_json::json!({
                    "generation": policy.module_generation.generation.value(),
                    "authority_epoch": policy
                        .module_generation
                        .state_fence
                        .authority_epoch
                        .value(),
                }),
            )
            .await
            .is_err()
    );
    assert!(!kernel.daemon_ready());
    assert!(waiter.await.expect("ready waiter task").is_err());
    let state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
    assert!(matches!(state.status, DaemonRuntimeStatus::Failed(_)));
    drop(state);
    assert_eq!(
        kernel
            .front_door_policy
            .lock()
            .expect("front-door policy")
            .launch_nonce,
        policy.launch_nonce
    );
}

struct JsonSnapshotCodec;

impl DispatchSnapshotCodec for JsonSnapshotCodec {
    fn seal(
        &self,
        snapshot: &DispatchPermitReplaySnapshot,
        _binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<SealedAuthoritySnapshot> {
        let ciphertext = serde_json::to_vec(snapshot)
            .map_err(|error| KernelError::DependencyUnavailable(error.to_string()))?;
        let key = SecretReference::new("test-provider", "kernel-authority")
            .map_err(|error| KernelError::DependencyUnavailable(error.to_string()))?;
        SealedAuthoritySnapshot::new(key, ciphertext)
    }

    fn open(
        &self,
        payload: &RecoveryPayload,
        _binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<DispatchPermitReplaySnapshot> {
        let RecoveryPayload::Encrypted { ciphertext, .. } = payload else {
            return Err(KernelError::RecoveryUnavailable(
                "authority fixture payload is not encrypted".to_owned(),
            ));
        };
        serde_json::from_slice(ciphertext)
            .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))
    }
}

fn authority_binding(authority_id: &DispatchAuthorityId) -> AuthoritySnapshotBinding {
    let epoch = EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new("kernel-test-lineage").expect("lineage"),
            epoch: 1,
        },
        predecessor: None,
    };
    let state_fence =
        StateFenceSnapshot::capture(&serde_json::json!({"authority": "kernel-test"}), 1)
            .expect("state fence");
    AuthoritySnapshotBinding::new(
        authority_id.clone(),
        OperationIdentity::new("kernel-test-authority-record").expect("record id"),
        epoch,
        state_fence,
        1,
        None,
    )
    .expect("authority binding")
}

fn seed_intent() -> ProcessIntent {
    ProcessIntent::new(
        OperationId::new("kernel-authority-seed-operation").expect("operation"),
        ProcessTreeId::new("kernel-authority-seed-tree").expect("tree"),
        JobId::new("kernel-authority-seed-job").expect("job"),
        ImageId::new("kernel-authority-seed-image").expect("image"),
        SessionId::new("kernel-authority-seed-session").expect("session"),
        Generation::new(1).expect("generation"),
        "C:\\eliot\\seed-worker.exe",
        "c".repeat(64),
        vec!["--seed".to_owned()],
        "C:\\eliot",
        EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
            .expect("environment"),
        ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4).expect("limits"),
    )
    .expect("intent")
}

fn test_validation_context(seed: &str) -> DispatchValidationContext {
    DispatchValidationContext::new(
        ClockObservation {
            valid_time_ms: Some(1_000),
            known_time_ms: Some(1_000),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        FencingToken::new(1, Generation::new(1).expect("generation"), "context-fence")
            .expect("fence"),
        1,
        BTreeMap::from([(seed.to_owned(), "a".repeat(64))]),
        1,
    )
    .expect("context")
}

fn gateway_test_owner() -> ProcessOwnerBinding {
    ProcessOwnerBinding::new(
        "eliotd",
        "a".repeat(64),
        1,
        Generation::new(1).expect("generation"),
    )
    .expect("owner")
}

fn gateway_test_admission(operation: &str) -> ProcessExecutionAdmissionRequest {
    let mut intent = seed_intent();
    intent = ProcessIntent::new(
        OperationId::new(operation).expect("operation"),
        intent.process_tree_id().clone(),
        intent.job_id().clone(),
        intent.image_id().clone(),
        intent.session_id().clone(),
        intent.generation(),
        intent.executable(),
        intent.executable_sha256(),
        intent.argv().to_vec(),
        intent.working_directory(),
        intent.environment().clone(),
        *intent.resource_limits(),
    )
    .expect("unique intent");
    ProcessExecutionAdmissionRequest::new(
        "eliotd",
        intent,
        ActionLeaseRef::new(format!("lease-{operation}")).expect("lease"),
        FencingToken::new(
            1,
            Generation::new(1).expect("generation"),
            format!("fence-{operation}"),
        )
        .expect("fence"),
        unix_ms().saturating_add(60_000),
    )
    .expect("admission")
}

#[cfg(windows)]
fn authority_test_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    )
}

#[cfg(windows)]
struct AuthorityTestCleanup {
    paths: Vec<PathBuf>,
}

#[cfg(windows)]
impl Drop for AuthorityTestCleanup {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = std::fs::remove_dir_all(path);
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(windows)]
struct CredentialCleanup {
    platform: Arc<WindowsPlatform>,
    key: String,
}

#[cfg(windows)]
impl Drop for CredentialCleanup {
    fn drop(&mut self) {
        let _ = self.platform.delete_credential(&self.key);
    }
}

#[cfg(windows)]
fn test_provisioned_supervision_authority(suffix: &str) -> ProvisionedSupervisionAuthority {
    let signer = Ed25519SupervisionLeaseSigner::from_secret_key(
        format!("supervision-signer-{suffix}"),
        format!("supervision-key-{suffix}"),
        [0x39; 32],
    )
    .expect("test supervision signer");
    let trust_anchor = SupervisionTrustAnchor::new(
        format!("installation-{suffix}"),
        signer.signer_id().to_owned(),
        signer.key_id().to_owned(),
        signer.public_key().to_vec(),
    )
    .expect("test supervision trust anchor");
    let key_reference = SupervisionSealedKeyReference::new(
        format!("supervision-{suffix}.sealed"),
        "S-1-5-80-1-2-3-4-5",
        SupervisionSealedKeyFileIdentity {
            canonical_path_digest: "1".repeat(64),
            volume_serial_number: 7,
            file_index: 11,
            security_descriptor_digest: "2".repeat(64),
        },
        "3".repeat(64),
    )
    .expect("test supervision key reference");
    ProvisionedSupervisionAuthority::new(
        format!("supervision-lease-{suffix}"),
        format!("candidate-{suffix}"),
        ResourceGeneration::genesis(),
        key_reference,
        trust_anchor,
    )
    .expect("test provisioned supervision authority")
}

#[cfg(windows)]
fn authority_descriptor(suffix: &str, provider: &str) -> ProcessAuthorityHandoffDescriptor {
    let authority_id =
        DispatchAuthorityId::new(format!("authority-{suffix}")).expect("authority id");
    let state_fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
    let epoch = EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new(format!("handoff-lineage-{suffix}")).expect("lineage"),
            epoch: 1,
        },
        predecessor: None,
    };
    let snapshot_binding = AuthoritySnapshotBindingWire {
        authority_id: authority_id.clone(),
        record_id: OperationIdentity::new(format!("snapshot-{suffix}")).expect("snapshot record"),
        authority_epoch: epoch,
        state_fence: StateFenceSnapshot::capture(&state_fence, 1).expect("snapshot fence"),
        created_at_ms: 1,
        cleanup_after_ms: Some(2),
    };
    let now = i64::try_from(unix_ms()).expect("test clock");
    ProcessAuthorityHandoffDescriptor {
        contract_version: ProcessAuthorityHandoffDescriptor::CONTRACT_VERSION,
        handoff_id: PlatformHandle::new(format!("handoff-{suffix}")).expect("handoff"),
        handoff_nonce: PlatformHandle::new(format!("nonce-{suffix}")).expect("nonce"),
        authority_id,
        snapshot_binding,
        state_fence,
        generation: ResourceGeneration::genesis(),
        revision_policy_binding: PlatformHandle::new(format!("policy-{suffix}")).expect("policy"),
        dispatch_key: SecretReference::new(provider, format!("eliot/kernel/test/{suffix}"))
            .expect("credential reference"),
        supervision_authority: test_provisioned_supervision_authority(suffix),
        descriptor_sha256: String::new(),
        issued_at_ms: now.saturating_sub(1_000),
        expires_at_ms: now.saturating_add(60_000),
        contour_refs: vec![
            PlatformHandle::new("portable_dev").expect("contour"),
            PlatformHandle::new("authority_descriptor").expect("descriptor contour"),
        ],
    }
    .with_computed_digest()
    .expect("descriptor digest")
}

#[cfg(windows)]
fn write_authority_descriptor(
    root: &Path,
    name: &str,
    descriptor: &ProcessAuthorityHandoffDescriptor,
) -> (PathBuf, String) {
    let bytes = serde_json::to_vec(descriptor).expect("descriptor bytes");
    let path = root.join(format!("{name}.json"));
    std::fs::write(&path, &bytes).expect("descriptor file");
    (path, sha256_hex(&bytes))
}

#[cfg(windows)]
fn write_authority_bytes(root: &Path, name: &str, bytes: &[u8]) -> (PathBuf, String) {
    let path = root.join(format!("{name}.json"));
    std::fs::write(&path, bytes).expect("descriptor bytes");
    (path, sha256_hex(bytes))
}

#[cfg(windows)]
fn credential_cleanup(platform: &Arc<WindowsPlatform>, key: &str) -> CredentialCleanup {
    CredentialCleanup {
        platform: Arc::clone(platform),
        key: key.to_owned(),
    }
}

#[test]
fn pre_poison_ipc_handles_cannot_establish_handshake() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-ipc-fence-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");

    // These are the only public IPC values retained across the fence:
    // immutable diagnostics, not a transport or policy authority.
    let saved_ipc_name = kernel.ipc().to_owned();
    let saved_limits = kernel.ipc_limits();
    let stale_client = {
        let policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy lock");
        test_client(&policy)
    };

    kernel.poison_generation_for_test();

    assert_eq!(kernel.ipc(), saved_ipc_name);
    assert_eq!(kernel.ipc_limits(), saved_limits);
    assert!(matches!(
        kernel.bind_session(
            "pre-poison-connection",
            PeerIdentity::Unavailable {
                reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
            },
            &stale_client,
        ),
        Err(TransportError::SessionFenced)
    ));

    #[cfg(windows)]
    {
        assert!(matches!(
            kernel.bind_authenticated_front_door(),
            Err(KernelBuildError::Principal(reason))
                if reason.contains("generation gateway fenced")
        ));
        assert!(matches!(
            kernel.bind_authenticated_front_door_next(),
            Err(KernelBuildError::Principal(reason))
                if reason.contains("generation gateway fenced")
        ));
    }

    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn canonical_store_slot_rejects_a_second_client_or_writer() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-store-slot-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");

    assert!(kernel.claim_canonical_store_slot().is_ok());
    assert!(matches!(
        kernel.claim_canonical_store_slot(),
        Err(KernelBuildError::StoreAlreadyConnected)
    ));

    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
struct TestCanonicalStoreAttachment {
    slot: Arc<Mutex<Option<Arc<u8>>>>,
    gateway: Arc<u8>,
    active: Arc<AtomicBool>,
}

#[cfg(windows)]
impl CanonicalStoreAttachmentTransaction for TestCanonicalStoreAttachment {
    fn commit(self: Box<Self>) {
        self.active.store(false, Ordering::Release);
    }
}

#[cfg(windows)]
impl Drop for TestCanonicalStoreAttachment {
    fn drop(&mut self) {
        if self.active.load(Ordering::Acquire)
            && let Ok(mut slot) = self.slot.lock()
            && slot
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.gateway))
        {
            *slot = None;
        }
    }
}

#[cfg(windows)]
#[test]
fn canonical_store_attach_failure_does_not_retain_or_poison_retry() {
    let retained = Mutex::new(None);
    let gateway = Arc::new(7_u8);
    assert!(matches!(
        attach_then_retain_canonical_store(Arc::clone(&gateway), &retained, |_| {
            Err(KernelBuildError::StoreAlreadyConnected)
        }),
        Err(KernelBuildError::StoreAlreadyConnected)
    ));
    assert!(retained.lock().expect("retained lock").is_none());

    let process_slot = Arc::new(Mutex::new(None));
    let active = Arc::new(AtomicBool::new(true));
    assert!(retained.lock().expect("retry lock").is_none());
    assert!(
        attach_then_retain_canonical_store(Arc::clone(&gateway), &retained, |gateway| {
            *process_slot.lock().expect("process slot") = Some(Arc::clone(&gateway));
            Ok(Box::new(TestCanonicalStoreAttachment {
                slot: Arc::clone(&process_slot),
                gateway,
                active: Arc::clone(&active),
            })
                as Box<dyn CanonicalStoreAttachmentTransaction>)
        },)
        .is_ok()
    );
    assert!(retained.lock().expect("retry lock").is_some());
    assert!(!active.load(Ordering::Acquire));
}

#[cfg(windows)]
#[test]
fn canonical_store_retain_failure_rolls_back_only_new_process_attachment() {
    let retained = Arc::new(Mutex::new(None));
    let poisoned = Arc::clone(&retained);
    let _ = std::thread::spawn(move || {
        let _guard = poisoned.lock().expect("poison lock");
        panic!("force composition retain failure");
    })
    .join();

    let process_slot = Arc::new(Mutex::new(None));
    let unrelated = Arc::new(99_u8);
    let unrelated_slot = Arc::new(Mutex::new(Some(Arc::clone(&unrelated))));
    let gateway = Arc::new(7_u8);
    assert!(matches!(
        attach_then_retain_canonical_store(
            Arc::clone(&gateway),
            &retained,
            |gateway| {
                *process_slot.lock().expect("process slot") = Some(Arc::clone(&gateway));
                Ok(Box::new(TestCanonicalStoreAttachment {
                    slot: Arc::clone(&process_slot),
                    gateway,
                    active: Arc::new(AtomicBool::new(true)),
                }) as Box<dyn CanonicalStoreAttachmentTransaction>)
            },
        ),
        Err(KernelBuildError::Service(reason)) if reason == "store gateway lock poisoned"
    ));
    assert!(
        process_slot
            .lock()
            .expect("process rollback slot")
            .is_none()
    );
    assert!(Arc::ptr_eq(
        unrelated_slot
            .lock()
            .expect("unrelated slot")
            .as_ref()
            .expect("unrelated gateway"),
        &unrelated
    ));
}

#[test]
fn normal_composition_is_not_process_ready_without_host_handoff() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-no-process-authority-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("composition");
    assert!(!kernel.process_execution_configured());
    assert_eq!(Arc::strong_count(&kernel.generation_gateway.ors), 1);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn validation_context_slot_is_entry_based_and_one_shot() {
    let slot = Arc::new(ValidationContextSlot::new());
    let operation = OperationId::new("slot-operation").expect("operation");
    let first = test_validation_context("first");
    let second = test_validation_context("second");
    let guard = slot
        .insert(operation.clone(), first.clone())
        .expect("first insertion");
    assert!(slot.insert(operation.clone(), second).is_err());
    assert_eq!(slot.take(&operation).expect("take first"), first);
    assert!(slot.take(&operation).is_err());
    drop(guard);
    let guard = slot
        .insert(operation.clone(), test_validation_context("replacement"))
        .expect("replacement insertion");
    drop(guard);
    assert!(slot.take(&operation).is_err());
}

#[test]
fn validation_context_slot_guards_independent_operations_and_abort_cleanup() {
    let slot = Arc::new(ValidationContextSlot::new());
    let first_id = OperationId::new("slot-first").expect("operation");
    let second_id = OperationId::new("slot-second").expect("operation");
    let first_guard = slot
        .insert(first_id.clone(), test_validation_context("first"))
        .expect("first insertion");
    let second_guard = slot
        .insert(second_id.clone(), test_validation_context("second"))
        .expect("second insertion");
    let second = slot.take(&second_id).expect("second take");
    assert_eq!(second, test_validation_context("second"));
    drop(first_guard);
    drop(second_guard);
    assert!(slot.take(&first_id).is_err());
    assert!(slot.take(&second_id).is_err());
}

#[cfg(windows)]
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the restart discriminator must exercise a live WindowsProcessExecutor receipt, durable Completed replay, a fresh production gateway inspect, and a new attempt"
)]
async fn real_gateway_completed_replay_requires_live_executor_inspection() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-real-completed-replay-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    let executable = std::env::current_exe().expect("test executable");
    let containment_root = executable.parent().expect("test executable parent");
    let executable_sha256 = sha256_hex(&std::fs::read(&executable).expect("read test executable"));
    let owner = gateway_test_owner();
    let old_operation = format!("real-completed-old-{}", unix_ms());
    let old_admission = real_executor_admission(
        &executable,
        &executable_sha256,
        &old_operation,
        "tests::real_executor_receipt_child",
        BTreeMap::from([(REAL_EXECUTOR_CHILD_ENV.to_owned(), "1".to_owned())]),
    );
    let (old_gateway, old_platform, old_authority) =
        real_process_gateway(&root.join("old-kernel"), containment_root);
    let old_receipt = start_real_executor_child(
        &old_gateway,
        &old_platform,
        &old_authority,
        &old_admission,
        &owner,
    )
    .await;
    let completed_record = ProcessExecutionReplayRecord {
        admission_digest: process_admission_digest(&old_admission).expect("old admission digest"),
        owner: owner.clone(),
        state: ProcessExecutionReplayState::Completed,
        receipt: Some(old_receipt.clone()),
    };
    let same_kernel_replay = old_gateway
        .completed_receipt(completed_record.clone())
        .await
        .expect("same Kernel live inspection")
        .expect("same Kernel exact Completed receipt");
    assert_eq!(same_kernel_replay, old_receipt);

    let (restarted_gateway, restarted_platform, restarted_authority) =
        real_process_gateway(&root.join("restarted-kernel"), containment_root);
    let stale = restarted_gateway.completed_receipt(completed_record).await;
    assert!(matches!(stale, Err(ProcessExecutionError::UnknownOutcome)));

    let new_operation = format!("real-completed-restarted-{}", unix_ms());
    let new_admission = real_executor_admission(
        &executable,
        &executable_sha256,
        &new_operation,
        "tests::real_executor_receipt_child",
        BTreeMap::from([(REAL_EXECUTOR_CHILD_ENV.to_owned(), "1".to_owned())]),
    );
    let new_receipt = start_real_executor_child(
        &restarted_gateway,
        &restarted_platform,
        &restarted_authority,
        &new_admission,
        &owner,
    )
    .await;
    assert_eq!(
        new_receipt.operation_id(),
        new_admission.intent().operation_id()
    );
    assert_ne!(
        new_receipt.operation_id(),
        old_admission.intent().operation_id()
    );

    old_gateway
        .executor
        .shutdown()
        .expect("shutdown old Kernel executor");
    restarted_gateway
        .executor
        .shutdown()
        .expect("shutdown restarted Kernel executor");
    drop(old_gateway);
    drop(restarted_gateway);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[tokio::test]
async fn daemon_readiness_requires_fresh_running_executor_receipt() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-daemon-readiness-executor-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    std::fs::create_dir_all(root.join("kernel")).expect("kernel work root");
    let executable = std::env::current_exe().expect("test executable");
    let executable_sha256 = sha256_hex(&std::fs::read(&executable).expect("read test executable"));
    let containment_root = executable.parent().expect("test executable parent");
    let mut launch = test_daemon_launch(&root);
    launch.executable =
        PlatformHandle::new(executable.to_string_lossy()).expect("test executable handle");
    launch.executable_sha256.clone_from(&executable_sha256);
    launch.working_directory =
        PlatformHandle::new(containment_root.to_string_lossy()).expect("working directory handle");
    launch.arguments[7] =
        PlatformHandle::new(launch.executable_sha256.clone()).expect("executable digest");
    launch.descriptor_sha256.clear();
    launch = launch.with_computed_digest().expect("test launch digest");
    let mut kernel = KernelComposition::new(
        KernelConfig::new(root.join("kernel"))
            .with_daemon_launch(launch.clone())
            .with_kernel_artifact_sha256("c".repeat(64)),
    )
    .expect("kernel composition");
    let kernel_process =
        observe_named_pipe_peer_process(std::process::id()).expect("Kernel process identity");
    let generation = Generation::new(launch.generation.value()).expect("generation");
    let attempt = eliotd_launch_attempt_identity(
        &launch,
        kernel_process.process_id(),
        kernel_process.start_time_100ns(),
        kernel_process.image_path(),
    )
    .expect("launch attempt identity");
    let operation = eliotd_operation_id(generation, &attempt).expect("operation identity");
    let admission = real_executor_admission(
        &executable,
        &executable_sha256,
        operation.as_str(),
        "tests::real_executor_receipt_child",
        BTreeMap::from([(REAL_EXECUTOR_CHILD_ENV.to_owned(), "1".to_owned())]),
    );
    let (gateway, platform, authority) =
        real_process_gateway(&root.join("real-executor"), containment_root);
    let gateway = Arc::new(gateway);
    let owner = gateway_test_owner();
    let receipt =
        start_real_executor_child(&gateway, &platform, &authority, &admission, &owner).await;
    assert_eq!(receipt.operation_id(), &operation);
    gateway
        .persist_completed(
            receipt.operation_id(),
            &process_admission_digest(&admission).expect("admission digest"),
            &owner,
            receipt.clone(),
        )
        .expect("persist live completion");
    kernel.process_gateway = Some(Arc::clone(&gateway));
    {
        let mut state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
        state.status = DaemonRuntimeStatus::Ready;
        state.receipt = Some(receipt.clone());
    }

    let inspection = gateway.inspect_exact_running_receipt(&receipt).await;
    assert!(
        inspection.is_ok(),
        "gateway exact inspection must accept the live receipt: {inspection:?}"
    );
    kernel
        .validate_daemon_process_readiness(&launch, &receipt)
        .await
        .expect("live exact process accepted");
    assert!(kernel.daemon_ready());

    gateway
        .executor
        .shutdown()
        .expect("terminate executor child");
    assert!(
        kernel
            .validate_daemon_process_readiness(&launch, &receipt)
            .await
            .is_err(),
        "terminal executor inspection must reject readiness"
    );
    assert!(!kernel.daemon_ready());
    assert!(matches!(
        kernel
            .daemon_runtime
            .lock()
            .expect("daemon runtime lock")
            .status,
        DaemonRuntimeStatus::Failed(_)
    ));
    drop(gateway);
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the production-bound recovery proof retains one real Job, receipt, stale rejection, and cleanup path"
)]
async fn daemon_recovery_closes_exact_prior_tree_and_rejects_stale_receipt() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-daemon-recovery-proof-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    std::fs::create_dir_all(root.join("kernel")).expect("kernel work root");
    let executable = std::env::current_exe().expect("test executable");
    let executable_sha256 = sha256_hex(&std::fs::read(&executable).expect("read test executable"));
    let containment_root = executable.parent().expect("test executable parent");
    let mut launch = test_daemon_launch(&root);
    launch.executable =
        PlatformHandle::new(executable.to_string_lossy()).expect("test executable handle");
    launch.executable_sha256.clone_from(&executable_sha256);
    launch.working_directory =
        PlatformHandle::new(containment_root.to_string_lossy()).expect("working directory handle");
    launch.arguments[7] =
        PlatformHandle::new(launch.executable_sha256.clone()).expect("executable digest");
    launch.descriptor_sha256.clear();
    launch = launch.with_computed_digest().expect("test launch digest");
    let mut kernel = KernelComposition::new(
        KernelConfig::new(root.join("kernel"))
            .with_daemon_launch(launch.clone())
            .with_kernel_artifact_sha256("c".repeat(64)),
    )
    .expect("kernel composition");
    let kernel_process =
        observe_named_pipe_peer_process(std::process::id()).expect("Kernel identity");
    let generation = Generation::new(launch.generation.value()).expect("generation");
    let attempt = eliotd_launch_attempt_identity(
        &launch,
        kernel_process.process_id(),
        kernel_process.start_time_100ns(),
        kernel_process.image_path(),
    )
    .expect("launch attempt");
    let operation = eliotd_operation_id(generation, &attempt).expect("operation");
    let admission = real_executor_admission(
        &executable,
        &executable_sha256,
        operation.as_str(),
        "tests::real_executor_receipt_child",
        BTreeMap::from([(REAL_EXECUTOR_CHILD_ENV.to_owned(), "1".to_owned())]),
    );
    let (gateway, platform, authority) =
        real_process_gateway(&root.join("real-executor"), containment_root);
    let gateway = Arc::new(gateway);
    let expectation = current_process_named_pipe_expectation().expect("Kernel expectation");
    let owner = ProcessOwnerBinding::new(
        ACTIVE_DAEMON_CALLER,
        stable_owner_principal_digest(
            expectation.expected_sid(),
            ACTIVE_DAEMON_CALLER,
            launch.authority_epoch.value(),
            generation,
        ),
        launch.authority_epoch.value(),
        generation,
    )
    .expect("daemon owner");
    let receipt =
        start_real_executor_child(&gateway, &platform, &authority, &admission, &owner).await;
    gateway
        .persist_completed(
            receipt.operation_id(),
            &process_admission_digest(&admission).expect("admission digest"),
            &owner,
            receipt.clone(),
        )
        .expect("persist exact completed receipt");
    kernel.process_gateway = Some(Arc::clone(&gateway));
    {
        let mut state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
        state.status = DaemonRuntimeStatus::Failed("daemon timeout".to_owned());
        state.receipt = Some(receipt.clone());
    }
    kernel
        .close_previous_daemon_process(&launch, &receipt)
        .await
        .expect("exact prior process tree closure");
    let closed = gateway
        .inspect(&owner, receipt.operation_id().clone())
        .await
        .expect("closed prior operation inspection");
    assert_eq!(closed.lifecycle(), ProcessLifecycle::Exited);

    let stale = test_process_start_receipt(41_002);
    assert!(
        kernel
            .close_previous_daemon_process(&launch, &stale)
            .await
            .is_err(),
        "a stale completed receipt must not be adopted for recovery"
    );
    gateway
        .executor
        .shutdown()
        .expect("shutdown recovery proof executor");
    drop(gateway);
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn store_projection_is_deterministic_and_binds_empty_and_full_fence_state() {
    let fence = StoreStateFence::new(
        eliot_contracts::AuthorityEpoch::new(3).expect("epoch"),
        eliot_contracts::ResourceGeneration::new(4).expect("generation"),
    );
    let first = CanonicalValidationSnapshot {
        state_fence: fence.clone(),
        revision_heads: vec![RevisionHead {
            key: RevisionKey::new("scope:b").expect("key"),
            revision: 2,
            state_fence: fence.clone(),
        }],
        validation_revision: 9,
        observed_at_unix_ms: 1_000,
    };
    let mut reordered = first.clone();
    reordered.observed_at_unix_ms = 2_000;
    let (first_fence, first_heads) = project_store_snapshot(&first).expect("projection");
    let (reordered_fence, reordered_heads) =
        project_store_snapshot(&reordered).expect("projection");
    assert_eq!(first_fence, reordered_fence);
    assert_eq!(first_heads, reordered_heads);
    assert!(first_heads.contains_key(RESERVED_STORE_SNAPSHOT_HEAD));
    assert_eq!(first_heads.len(), 2);

    let empty = CanonicalValidationSnapshot {
        state_fence: fence.clone(),
        revision_heads: Vec::new(),
        validation_revision: 1,
        observed_at_unix_ms: 1_000,
    };
    let (_, empty_heads) = project_store_snapshot(&empty).expect("empty projection");
    assert_eq!(empty_heads.len(), 1);
    assert!(empty_heads.contains_key(RESERVED_STORE_SNAPSHOT_HEAD));

    let mut changed = first.clone();
    changed.state_fence.task_revision =
        Some(eliot_contracts::TaskRevision::new(1).expect("task revision"));
    for head in &mut changed.revision_heads {
        head.state_fence = changed.state_fence.clone();
    }
    let (changed_fence, changed_heads) = project_store_snapshot(&changed).expect("changed");
    assert_ne!(first_fence, changed_fence);
    assert_ne!(first_heads, changed_heads);

    let mut changed_head = first.clone();
    changed_head.revision_heads[0].revision += 1;
    let (_, changed_head_projection) = project_store_snapshot(&changed_head).expect("changed head");
    assert_ne!(first_heads, changed_head_projection);
    let mut changed_validation_revision = first;
    changed_validation_revision.validation_revision += 1;
    let (_, changed_revision_projection) =
        project_store_snapshot(&changed_validation_revision).expect("changed revision");
    assert_ne!(first_heads, changed_revision_projection);
}

#[test]
fn process_authority_first_issue_is_versioned_and_stale_controller_fails_closed() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-process-authority-cas-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let ors_path = root.join("kernel-ors.redb");
    let authority_id = DispatchAuthorityId::new("kernel-cas-authority").expect("authority");
    let binding = authority_binding(&authority_id);
    let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(JsonSnapshotCodec);
    let store = Arc::new(RedbRecoveryStore::open(&ors_path).expect("real ORS store"));
    let authority_store: Arc<dyn OperationalRecoveryStore> = store.clone();
    let key = || KernelDispatchKey::from_secret_bytes([0x4a; 32]).expect("dispatch key");
    let issuance = |nonce: &str| {
        PermitIssuance::new(
            ActionLeaseRef::new("cas-lease").expect("lease"),
            FencingToken::new(1, Generation::new(1).expect("generation"), "cas-fence")
                .expect("fence"),
            BTreeMap::from([("authority".to_owned(), "a".repeat(64))]),
            1,
            2,
            nonce,
        )
        .expect("issuance")
    };

    let mut winner = ProcessDispatchAuthorityController::activate_and_persist_initial(
        authority_id.clone(),
        key(),
        Arc::clone(&authority_store),
        Arc::clone(&codec),
        &binding,
    )
    .expect("initial snapshot");
    let mut stale = ProcessDispatchAuthorityController::restore(
        authority_id.clone(),
        key(),
        Arc::clone(&authority_store),
        Arc::clone(&codec),
        &binding,
    )
    .expect("stale controller restore");
    winner
        .issue(&seed_intent(), issuance("cas-winner"), &binding)
        .expect("one controller wins the CAS");
    assert!(matches!(
        stale.issue(&seed_intent(), issuance("cas-stale"), &binding),
        Err(KernelError::RecoveryState(
            eliot_ors::OrsError::DuplicateConflict
        ))
    ));
    assert!(matches!(
        stale.issue(&seed_intent(), issuance("cas-stale-retry"), &binding),
        Err(KernelError::DependencyUnavailable(_))
    ));

    let subject = OperationIdentity::new(authority_id.as_str()).expect("subject");
    let current = store
        .load_authority_snapshot(&subject)
        .expect("load current snapshot")
        .expect("current snapshot");
    assert!(current.operation_order() > 1);
    let mut restarted = ProcessDispatchAuthorityController::restore(
        authority_id,
        key(),
        authority_store,
        codec,
        &binding,
    )
    .expect("restart snapshot");
    assert!(
        restarted
            .issue(&seed_intent(), issuance("cas-winner"), &binding)
            .is_err()
    );
    drop(restarted);
    drop(stale);
    drop(winner);
    drop(store);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[allow(clippy::too_many_lines)]
fn process_authority_constructor_reuses_one_real_ors_store() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-process-authority-constructor-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let ors_path = root.join(".eliot").join("kernel-ors.redb");
    let authority_id = DispatchAuthorityId::new("kernel-test-authority").expect("authority");
    let binding = authority_binding(&authority_id);
    let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(JsonSnapshotCodec);
    let store = Arc::new(RedbRecoveryStore::open(&ors_path).expect("real ORS store"));
    let seed_store: Arc<dyn OperationalRecoveryStore> = store.clone();
    let seed_key = KernelDispatchKey::from_secret_bytes([0x4a; 32]).expect("seed key");
    let mut seeder = ProcessDispatchAuthorityController::activate(
        authority_id.clone(),
        seed_key,
        seed_store,
        Arc::clone(&codec),
    );
    let seed_fence = FencingToken::new(1, Generation::new(1).expect("generation"), "seed-fence")
        .expect("seed fence");
    seeder
        .issue(
            &seed_intent(),
            PermitIssuance::new(
                ActionLeaseRef::new("seed-lease").expect("lease"),
                seed_fence,
                BTreeMap::from([("authority".to_owned(), "a".repeat(64))]),
                1,
                2,
                "seed-nonce",
            )
            .expect("issuance"),
            &binding,
        )
        .expect("production authority snapshot seed");
    drop(seeder);

    let subject = OperationIdentity::new(authority_id.as_str()).expect("authority subject");
    let original_input = store
        .load_authority_snapshot(&subject)
        .expect("load seeded authority snapshot")
        .expect("seeded authority snapshot")
        .snapshot()
        .record()
        .clone();
    for substitution in 0..3 {
        let mut tampered = original_input.clone();
        match substitution {
            0 => {
                tampered.record_id = OperationIdentity::new("substituted-record").expect("record");
            }
            1 => tampered.created_at_ms += 1,
            2 => tampered.cleanup_after_ms = Some(3_000),
            _ => unreachable!(),
        }
        eliot_ors::test_support::substitute_authority_snapshot_metadata(
            &store,
            eliot_ors::test_support::AuthoritySnapshotMetadataSubstitution {
                record_id: tampered.record_id,
                created_at_ms: tampered.created_at_ms,
                cleanup_after_ms: tampered.cleanup_after_ms,
            },
        )
        .expect("persist metadata substitution");
        assert!(
            ProcessDispatchAuthorityController::restore(
                authority_id.clone(),
                KernelDispatchKey::from_secret_bytes([0x4a; 32]).expect("restore key"),
                store.clone(),
                Arc::clone(&codec),
                &binding,
            )
            .is_err()
        );
        eliot_ors::test_support::substitute_authority_snapshot_metadata(
            &store,
            eliot_ors::test_support::AuthoritySnapshotMetadataSubstitution {
                record_id: original_input.record_id.clone(),
                created_at_ms: original_input.created_at_ms,
                cleanup_after_ms: original_input.cleanup_after_ms,
            },
        )
        .expect("restore original metadata");
    }
    drop(store);

    let kernel = KernelComposition::new_with_process_authority(
        KernelConfig::new(&root),
        ProcessExecutionAuthorityConfig {
            authority_id,
            key: KernelDispatchKey::from_secret_bytes([0x4a; 32]).expect("restore key"),
            snapshot_binding: binding,
            snapshot_codec: codec,
        },
    )
    .expect("process authority constructor");
    assert!(kernel.process_execution_configured());
    assert_eq!(Arc::strong_count(&kernel.generation_gateway.ors), 4);
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn process_owner_survives_reconnect_but_rejects_cross_owner() {
    let generation = Generation::new(7).expect("generation");
    let owner = ProcessOwnerBinding::new("testd", "a".repeat(64), 3, generation).expect("owner");
    let reconnected =
        ProcessOwnerBinding::new("testd", "a".repeat(64), 3, generation).expect("owner");
    assert!(authorize_process_owner(&owner, &reconnected).is_ok());

    let wrong_module =
        ProcessOwnerBinding::new("native", "a".repeat(64), 3, generation).expect("owner");
    let wrong_principal =
        ProcessOwnerBinding::new("testd", "b".repeat(64), 3, generation).expect("owner");
    let wrong_generation = ProcessOwnerBinding::new(
        "testd",
        "a".repeat(64),
        3,
        Generation::new(8).expect("generation"),
    )
    .expect("owner");
    for candidate in [wrong_module, wrong_principal, wrong_generation] {
        assert!(authorize_process_owner(&owner, &candidate).is_err());
    }
}

#[test]
fn protected_authority_preparation_rejects_untrusted_input_before_consumption() {
    let root = std::env::temp_dir().join(format!(
        "eliot-kernel-authority-preparation-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("composition");
    let descriptor_path = root.join("authority.json");
    assert!(matches!(
        kernel.prepare_authority_descriptor(
            &descriptor_path,
            "not-a-digest",
            AuthorityDescriptorContour::ProgramData,
        ),
        Err(AuthorityPreparationError::DigestMismatch)
    ));
    let empty_digest = sha256_hex(&[]);
    assert!(matches!(
        kernel.prepare_authority_descriptor(
            &descriptor_path,
            &empty_digest,
            AuthorityDescriptorContour::ProgramData,
        ),
        Err(AuthorityPreparationError::ProtectedInput)
    ));
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
#[allow(clippy::too_many_lines)]
fn protected_authority_preparation_acceptance_matrix() {
    let suffix = authority_test_suffix();
    let root = std::env::temp_dir().join(format!("eliot-kernel-authority-{suffix}"));
    let outside = std::env::temp_dir().join(format!("eliot-kernel-authority-outside-{suffix}"));
    let _cleanup = AuthorityTestCleanup {
        paths: vec![root.clone(), outside.clone()],
    };
    std::fs::create_dir_all(&root).expect("test work root");
    std::fs::create_dir_all(&outside).expect("outside root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("composition");
    let platform = Arc::new(WindowsPlatform::new(&root).expect("platform"));

    let positive =
        authority_descriptor(&format!("{suffix}-positive"), "windows-credential-manager");
    let (positive_path, positive_digest) = write_authority_descriptor(&root, "positive", &positive);
    let positive_key = positive.dispatch_key.key.as_str().to_owned();
    let positive_cleanup = credential_cleanup(&platform, &positive_key);
    platform
        .write_credential(&positive_key, &[0x5a; 32])
        .expect("positive credential");
    let prepared = kernel
        .prepare_authority_descriptor(
            &positive_path,
            &positive_digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        )
        .expect("positive authority preparation");
    assert_eq!(prepared.descriptor, positive);
    assert_eq!(prepared.handoff.state, AuthorityHandoffState::Reserved);
    // The preparation step only commits the activation intent.  The
    // production constructor owns initial snapshot persistence and the
    // terminal handoff transition.
    drop(kernel);
    let resumed = KernelComposition::new_with_authority_descriptor(
        KernelConfig::new(&root),
        &positive_path,
        &positive_digest,
        AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
    )
    .expect("clean first boot resumes reserved intent");
    assert!(resumed.process_execution_configured());
    drop(resumed);
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("reopen ORS");
    let handoff_id = OperationIdentity::new(positive.handoff_id.as_str()).expect("handoff id");
    let consumed = kernel
        .generation_gateway
        .ors
        .load_authority_handoff(&handoff_id)
        .expect("load consumed handoff")
        .expect("consumed handoff");
    assert_eq!(consumed.state, AuthorityHandoffState::Consumed);
    assert_eq!(consumed.descriptor_digest, positive.descriptor_sha256);
    assert_eq!(
        consumed.authority_id.as_str(),
        positive.authority_id.as_str()
    );
    assert_eq!(
        consumed.snapshot_record_id,
        positive.snapshot_binding.record_id
    );
    assert_eq!(
        consumed.snapshot_binding_digest,
        sha256_json(&positive.snapshot_binding).expect("binding digest")
    );
    assert_eq!(
        consumed.authority_epoch,
        positive.state_fence.authority_epoch.value()
    );
    assert_eq!(consumed.generation, positive.generation.value());
    assert_eq!(
        consumed.state_fence_digest,
        sha256_json(&positive.state_fence).expect("state fence digest")
    );
    assert_eq!(
        consumed.secret_reference_identity_digest,
        sha256_json(&positive.dispatch_key).expect("secret reference digest")
    );
    drop(kernel);
    // A second production start is exact recovery, not a replay failure:
    // it restores the same durable replay fence without minting a key or
    // a new nonce.
    let restart = KernelComposition::new_with_authority_descriptor(
        KernelConfig::new(&root),
        &positive_path,
        &positive_digest,
        AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
    )
    .expect("exact same-generation restart");
    drop(restart);
    drop(positive_cleanup);
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("reopen ORS");
    assert!(matches!(
        kernel.prepare_authority_descriptor(
            &positive_path,
            &positive_digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        ),
        Err(AuthorityPreparationError::CredentialUnavailable)
    ));

    let missing = authority_descriptor(&format!("{suffix}-missing"), "windows-credential-manager");
    let (missing_path, missing_digest) = write_authority_descriptor(&root, "missing", &missing);
    let mismatch_digest = "0".repeat(64);
    let mismatch_handoff_id =
        OperationIdentity::new(missing.handoff_id.as_str()).expect("handoff id");
    assert_ne!(missing_digest, mismatch_digest);
    assert!(matches!(
        kernel.prepare_authority_descriptor(
            &missing_path,
            &mismatch_digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        ),
        Err(AuthorityPreparationError::DigestMismatch)
    ));
    assert!(
        kernel
            .generation_gateway
            .ors
            .load_authority_handoff(&mismatch_handoff_id)
            .expect("digest mismatch lookup")
            .is_none()
    );
    assert!(matches!(
        kernel.prepare_authority_descriptor(
            &missing_path,
            &missing_digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        ),
        Err(AuthorityPreparationError::CredentialUnavailable)
    ));

    for (name, secret) in [("short", vec![1_u8]), ("long", vec![1_u8; 33])] {
        let descriptor =
            authority_descriptor(&format!("{suffix}-{name}"), "windows-credential-manager");
        let (path, digest) = write_authority_descriptor(&root, name, &descriptor);
        let key = descriptor.dispatch_key.key.as_str().to_owned();
        let cleanup = credential_cleanup(&platform, &key);
        platform
            .write_credential(&key, &secret)
            .expect("invalid credential");
        assert!(matches!(
            kernel.prepare_authority_descriptor(
                &path,
                &digest,
                AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
            ),
            Err(AuthorityPreparationError::CredentialInvalid)
        ));
        drop(cleanup);
    }

    let zero = authority_descriptor(&format!("{suffix}-zero"), "windows-credential-manager");
    let (zero_path, zero_digest) = write_authority_descriptor(&root, "zero", &zero);
    let zero_key = zero.dispatch_key.key.as_str().to_owned();
    let zero_cleanup = credential_cleanup(&platform, &zero_key);
    platform
        .write_credential(&zero_key, &[0_u8; 32])
        .expect("zero credential");
    assert!(matches!(
        kernel.prepare_authority_descriptor(
            &zero_path,
            &zero_digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        ),
        Err(AuthorityPreparationError::CredentialInvalid)
    ));
    drop(zero_cleanup);

    let wrong_provider = authority_descriptor(&format!("{suffix}-provider"), "not-a-provider");
    let (wrong_provider_path, wrong_provider_digest) =
        write_authority_descriptor(&root, "wrong-provider", &wrong_provider);
    assert!(matches!(
        kernel.prepare_authority_descriptor(
            &wrong_provider_path,
            &wrong_provider_digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        ),
        Err(AuthorityPreparationError::DescriptorInvalid)
    ));

    let malformed = b"not-json".to_vec();
    let (malformed_path, malformed_digest) = write_authority_bytes(&root, "malformed", &malformed);
    assert!(matches!(
        kernel.prepare_authority_descriptor(
            &malformed_path,
            &malformed_digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        ),
        Err(AuthorityPreparationError::DescriptorInvalid)
    ));

    let unknown = authority_descriptor(&format!("{suffix}-unknown"), "windows-credential-manager");
    let mut unknown_wire = serde_json::to_value(&unknown).expect("unknown descriptor value");
    unknown_wire["unknown"] = serde_json::json!(true);
    let unknown_bytes = serde_json::to_vec(&unknown_wire).expect("unknown descriptor bytes");
    let (unknown_path, unknown_digest) = write_authority_bytes(&root, "unknown", &unknown_bytes);
    assert!(matches!(
        kernel.prepare_authority_descriptor(
            &unknown_path,
            &unknown_digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        ),
        Err(AuthorityPreparationError::DescriptorInvalid)
    ));

    let mut expired =
        authority_descriptor(&format!("{suffix}-expired"), "windows-credential-manager");
    expired.issued_at_ms = 1;
    expired.expires_at_ms = 2;
    expired = expired.with_computed_digest().expect("expired digest");
    let (expired_path, expired_digest) = write_authority_descriptor(&root, "expired", &expired);
    let expired_key = expired.dispatch_key.key.as_str().to_owned();
    let expired_cleanup = credential_cleanup(&platform, &expired_key);
    platform
        .write_credential(&expired_key, &[0x4a; 32])
        .expect("expired credential");
    assert!(matches!(
        kernel.prepare_authority_descriptor(
            &expired_path,
            &expired_digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        ),
        Err(AuthorityPreparationError::DescriptorNotFresh)
    ));
    let expired_id = OperationIdentity::new(expired.handoff_id.as_str()).expect("handoff id");
    assert!(
        kernel
            .generation_gateway
            .ors
            .load_authority_handoff(&expired_id)
            .expect("expired handoff lookup")
            .is_none()
    );
    drop(expired_cleanup);

    let now = i64::try_from(unix_ms()).expect("test clock");
    let mut future = authority_descriptor(
        &format!("{suffix}-future-issued"),
        "windows-credential-manager",
    );
    future.issued_at_ms = now.saturating_add(60_000);
    future.expires_at_ms = now.saturating_add(120_000);
    future = future.with_computed_digest().expect("future-issued digest");
    let (future_path, future_digest) = write_authority_descriptor(&root, "future-issued", &future);
    let future_key = future.dispatch_key.key.as_str().to_owned();
    let future_cleanup = credential_cleanup(&platform, &future_key);
    platform
        .write_credential(&future_key, &[0x4b; 32])
        .expect("future-issued credential");
    assert!(matches!(
        kernel.prepare_authority_descriptor(
            &future_path,
            &future_digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        ),
        Err(AuthorityPreparationError::DescriptorNotFresh)
    ));
    let future_id = OperationIdentity::new(future.handoff_id.as_str()).expect("handoff id");
    assert!(
        kernel
            .generation_gateway
            .ors
            .load_authority_handoff(&future_id)
            .expect("future-issued handoff lookup")
            .is_none()
    );
    drop(future_cleanup);

    let valid_substitution = authority_descriptor(
        &format!("{suffix}-substitution"),
        "windows-credential-manager",
    );
    let mut descriptor_substitution = valid_substitution.clone();
    descriptor_substitution.authority_id =
        DispatchAuthorityId::new(format!("substituted-{suffix}")).expect("substituted authority");
    descriptor_substitution = descriptor_substitution
        .with_computed_digest()
        .expect("substituted descriptor digest");
    let (descriptor_substitution_path, descriptor_substitution_digest) =
        write_authority_descriptor(&root, "descriptor-substitution", &descriptor_substitution);
    assert!(matches!(
        kernel.prepare_authority_descriptor(
            &descriptor_substitution_path,
            &descriptor_substitution_digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        ),
        Err(AuthorityPreparationError::DescriptorInvalid)
    ));
    let descriptor_substitution_id =
        OperationIdentity::new(descriptor_substitution.handoff_id.as_str()).expect("handoff id");
    assert!(
        kernel
            .generation_gateway
            .ors
            .load_authority_handoff(&descriptor_substitution_id)
            .expect("substitution lookup")
            .is_none()
    );

    let mut state_fence_substitution = valid_substitution;
    state_fence_substitution.state_fence = StateFence::new(
        AuthorityEpoch::new(2).expect("epoch"),
        ResourceGeneration::genesis(),
    );
    state_fence_substitution = state_fence_substitution
        .with_computed_digest()
        .expect("state fence substitution digest");
    let (state_fence_path, state_fence_digest) =
        write_authority_descriptor(&root, "state-fence-substitution", &state_fence_substitution);
    assert!(matches!(
        kernel.prepare_authority_descriptor(
            &state_fence_path,
            &state_fence_digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        ),
        Err(AuthorityPreparationError::DescriptorInvalid)
    ));
    let state_fence_id =
        OperationIdentity::new(state_fence_substitution.handoff_id.as_str()).expect("handoff id");
    assert!(
        kernel
            .generation_gateway
            .ors
            .load_authority_handoff(&state_fence_id)
            .expect("state fence lookup")
            .is_none()
    );

    let out_of_contour_descriptor = authority_descriptor(
        &format!("{suffix}-out-of-contour"),
        "windows-credential-manager",
    );
    let outside_path = outside.join("authority.json");
    let outside_bytes = serde_json::to_vec(&out_of_contour_descriptor).expect("outside bytes");
    std::fs::write(&outside_path, &outside_bytes).expect("outside descriptor");
    assert!(matches!(
        kernel.prepare_authority_descriptor(
            &outside_path,
            &sha256_hex(&outside_bytes),
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        ),
        Err(AuthorityPreparationError::ProtectedInput)
    ));
    // Reparse/junction substitution coverage is lower-layer-owned by
    // user_owned_portable_dev_rejects_reparse_path_when_available and
    // protected_path_lease_rejects_directory_and_file_reparse_substitution.
}

#[cfg(windows)]
#[test]
fn protected_authority_restart_after_admission_expiry_restores_exact_snapshot() {
    let suffix = authority_test_suffix();
    let root = std::env::temp_dir().join(format!("eliot-kernel-authority-expiry-{suffix}"));
    let _cleanup = AuthorityTestCleanup {
        paths: vec![root.clone()],
    };
    std::fs::create_dir_all(&root).expect("test work root");
    let platform = Arc::new(WindowsPlatform::new(&root).expect("platform"));
    let now = i64::try_from(unix_ms()).expect("test clock");
    let mut descriptor =
        authority_descriptor(&format!("{suffix}-expiry"), "windows-credential-manager");
    descriptor.issued_at_ms = now.saturating_sub(1_000);
    descriptor.expires_at_ms = now.saturating_add(2_000);
    descriptor = descriptor
        .with_computed_digest()
        .expect("descriptor digest");
    let (path, digest) = write_authority_descriptor(&root, "expiry", &descriptor);
    let key = descriptor.dispatch_key.key.as_str().to_owned();
    let credential = credential_cleanup(&platform, &key);
    platform
        .write_credential(&key, &[0x4d; 32])
        .expect("credential");

    // Persist the initial replay snapshot while the activation intent is
    // still Reserved.  This is the exact crash boundary that must remain
    // recoverable after the descriptor's one-shot admission interval.
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("composition");
    let prepared = kernel
        .prepare_authority_descriptor(
            &path,
            &digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        )
        .expect("reserve handoff before admission expiry");
    assert_eq!(prepared.handoff.state, AuthorityHandoffState::Reserved);
    let binding = AuthoritySnapshotBinding::from_wire(
        prepared.descriptor.snapshot_binding.clone(),
        &prepared.descriptor.authority_id,
    )
    .expect("snapshot binding");
    let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(WindowsDispatchSnapshotCodec::new(
        Arc::clone(&platform),
        prepared.descriptor.dispatch_key.clone(),
    ));
    let controller = KernelComposition::prepare_descriptor_controller(
        prepared.descriptor.authority_id.clone(),
        prepared.key,
        Arc::clone(&kernel.generation_gateway.ors) as Arc<dyn OperationalRecoveryStore>,
        codec,
        &binding,
        &prepared.descriptor,
        &prepared.handoff,
    )
    .expect("initial snapshot before handoff consume");
    let handoff_id = OperationIdentity::new(descriptor.handoff_id.as_str()).expect("handoff id");
    assert_eq!(
        kernel
            .generation_gateway
            .ors
            .load_authority_handoff(&handoff_id)
            .expect("reserved handoff")
            .expect("reserved handoff record")
            .state,
        AuthorityHandoffState::Reserved
    );
    drop(controller);
    drop(kernel);
    std::thread::sleep(Duration::from_millis(2_200));

    let restarted = KernelComposition::new_with_authority_descriptor(
        KernelConfig::new(&root),
        &path,
        &digest,
        AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
    )
    .expect("exact Reserved restart after admission expiry");
    assert!(restarted.process_execution_configured());
    drop(restarted);
    drop(credential);
}

#[cfg(windows)]
#[test]
fn protected_authority_consume_reconciles_without_demoting_consumed() {
    let suffix = authority_test_suffix();
    let root = std::env::temp_dir().join(format!("eliot-kernel-authority-unknown-{suffix}"));
    let _cleanup = AuthorityTestCleanup {
        paths: vec![root.clone()],
    };
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("composition");
    let platform = Arc::new(WindowsPlatform::new(&root).expect("platform"));
    let descriptor = authority_descriptor(
        &format!("{suffix}-unknown-outcome"),
        "windows-credential-manager",
    );
    let (path, digest) = write_authority_descriptor(&root, "unknown-outcome", &descriptor);
    let key = descriptor.dispatch_key.key.as_str().to_owned();
    let credential = credential_cleanup(&platform, &key);
    platform
        .write_credential(&key, &[0x6b; 32])
        .expect("credential");
    let failpoint =
        Arc::new(eliot_ors::test_support::AuthorityHandoffPersistenceFailpoint::default());
    eliot_ors::test_support::install_authority_handoff_failpoint(
        &kernel.generation_gateway.ors,
        Arc::clone(&failpoint),
    );
    failpoint.fail_next_consume_commit_after_durable_effect();
    let prepared = kernel
        .prepare_authority_descriptor(
            &path,
            &digest,
            AuthorityDescriptorContour::PortableCurrentUser { root: root.clone() },
        )
        .expect("reserve handoff before consume");
    let binding = AuthoritySnapshotBinding::from_wire(
        prepared.descriptor.snapshot_binding.clone(),
        &prepared.descriptor.authority_id,
    )
    .expect("snapshot binding");
    let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(WindowsDispatchSnapshotCodec::new(
        Arc::clone(&platform),
        prepared.descriptor.dispatch_key.clone(),
    ));
    let controller = KernelComposition::prepare_descriptor_controller(
        prepared.descriptor.authority_id.clone(),
        prepared.key,
        Arc::clone(&kernel.generation_gateway.ors) as Arc<dyn OperationalRecoveryStore>,
        codec,
        &binding,
        &prepared.descriptor,
        &prepared.handoff,
    )
    .expect("initial snapshot");
    KernelComposition::consume_authority_handoff(&kernel.generation_gateway.ors, &prepared.handoff)
        .expect("uncertain consume reconciles to committed state");
    drop(controller);
    let handoff_id = OperationIdentity::new(descriptor.handoff_id.as_str()).expect("handoff id");
    let consumed = kernel
        .generation_gateway
        .ors
        .load_authority_handoff(&handoff_id)
        .expect("load consumed handoff")
        .expect("consumed handoff");
    assert_eq!(consumed.state, AuthorityHandoffState::Consumed);
    drop(credential);
}

#[cfg(windows)]
#[test]
fn supervision_authority_root_spec_uses_the_exact_system_installation_contour() {
    let profile_anchor = protected_program_data_root().expect("protected ProgramData root");
    let installation_root = profile_anchor.join("Eliot");
    let kernel_root = installation_root.join("kernel").join("work");
    let spec = supervision_authority_root_spec(&kernel_root).expect("Kernel root contour");
    assert_eq!(spec.root, kernel_root);
    assert_eq!(spec.installation_root, installation_root);
    assert_eq!(spec.profile_anchor, profile_anchor);
    assert_eq!(spec.profile, InstallerRootProfile::SystemService);

    let foreign = supervision_authority_root_spec(
        &spec
            .profile_anchor
            .join("foreign-installation")
            .join("kernel"),
    )
    .expect("foreign contour remains a data-only spec until the physical boundary");
    assert_eq!(
        eliot_platform_windows::WindowsInstallerRootPrimitive::new().inspect(&foreign),
        Err(eliot_platform_windows::InstallerRootError::InvalidPath),
        "the physical read boundary must reject a foreign ProgramData root"
    );
}

/// Physical acceptance gate. Run this test inside the installed
/// `NT SERVICE\\EliotHost` service process with the exact public authority
/// JSON and Kernel work root supplied by the test harness. Successful
/// unseal is itself proof that the current token contains the descriptor's
/// exact service SID; DPAPI-NG rejects Watchdog, LocalService-only and user
/// tokens before any Ed25519 operation.
#[cfg(windows)]
#[test]
#[ignore = "requires the installed EliotHost service-SID token and provisioned key receipt"]
fn physical_supervision_signer_unseals_only_with_exact_eliot_host_service_sid_token() {
    let kernel_root = PathBuf::from(
        std::env::var_os("ELIOT_TEST_KERNEL_WORK_ROOT")
            .expect("physical Kernel work root must be injected"),
    );
    let authority: ProvisionedSupervisionAuthority = serde_json::from_str(
        &std::env::var("ELIOT_TEST_PROVISIONED_SUPERVISION_AUTHORITY")
            .expect("public provisioned authority must be injected"),
    )
    .expect("public provisioned authority JSON");
    let live_sid = eliot_platform_windows::resolve_service_sid(
        eliot_runtime_contracts::SUPERVISION_AUTHORITY_HOST_SERVICE,
    )
    .expect("resolve exact EliotHost service SID");
    assert_eq!(live_sid, authority.key_reference.host_service_sid);
    let signer = ProtectedSupervisionLeaseSigner::new(
        kernel_root,
        &SupervisionLeaseAuthorityConfig { authority },
    )
    .expect("exact EliotHost service token must unseal the provisioned key");
    assert_eq!(
        signer
            .sign(b"eliot-supervision-authority-physical-proof")
            .expect("physical signing")
            .len(),
        64
    );
}

#[test]
fn stable_sid_owner_digest_ignores_process_and_session_replacement() {
    let generation = Generation::new(7).expect("generation");
    let first_digest = stable_owner_principal_digest("S-1-5-18", "testd", 3, generation);
    let restarted_digest = stable_owner_principal_digest("S-1-5-18", "testd", 3, generation);
    assert_eq!(first_digest, restarted_digest);
    let first = ProcessOwnerBinding::new("testd", first_digest, 3, generation).expect("owner");
    let restarted =
        ProcessOwnerBinding::new("testd", restarted_digest, 3, generation).expect("owner");
    let first_session = ProcessSessionBinding::new("connection-a", 1).expect("session");
    let restarted_session = ProcessSessionBinding::new("connection-b", 2).expect("session");
    assert_ne!(first_session, restarted_session);
    assert!(authorize_process_owner(&first, &restarted).is_ok());

    for (sid, module, authority, candidate_generation) in [
        ("S-1-5-19", "testd", 3, generation),
        ("S-1-5-18", "native", 3, generation),
        ("S-1-5-18", "testd", 4, generation),
        (
            "S-1-5-18",
            "testd",
            3,
            Generation::new(8).expect("generation"),
        ),
    ] {
        let digest = stable_owner_principal_digest(sid, module, authority, candidate_generation);
        let candidate = ProcessOwnerBinding::new(module, digest, authority, candidate_generation)
            .expect("owner");
        assert!(authorize_process_owner(&first, &candidate).is_err());
    }
}

#[test]
fn pulse4_production_discriminator_is_bound_to_kernel_composition() {
    assert_eq!(
        KernelComposition::production_store_rebind_discriminator(),
        KERNEL_STORE_REBIND_PRODUCTION_DISCRIMINATOR
    );
    assert!(!KernelComposition::production_store_rebind_discriminator().is_empty());
}

#[cfg(windows)]
#[test]
fn store_rebind_restart_reconstructs_exact_handoff_and_rejects_substitution() {
    let suffix = authority_test_suffix();
    let root = std::env::temp_dir().join(format!("eliot-kernel-store-rebind-{suffix}"));
    std::fs::create_dir_all(root.join(".eliot")).expect("test ORS root");
    let requirement = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge").expect("route"),
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store").expect("pipe"),
        store_generation: ResourceGeneration::genesis(),
        state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        launch_nonce: PlatformHandle::new("store-launch-nonce").expect("launch nonce"),
        connection_id: PlatformHandle::new("store-connection").expect("connection"),
        expected_peer_sid: PlatformHandle::new("S-1-5-18").expect("sid"),
        expected_peer_session_id: 0,
        approved_artifact_hash: PlatformHandle::new("a".repeat(64)).expect("artifact"),
        approved_config_hash: PlatformHandle::new("b".repeat(64)).expect("config"),
        timeout_ms: 5_000,
    };
    let operation_id = OperationIdentity::new("store-rebind-recovery").expect("operation");
    let request_digest = "c".repeat(64);
    let process_image_path = r"C:\Eliot\eliot-store.exe".to_owned();
    let job_name = r"Local\Eliot-Store-recovered".to_owned();
    let record = eliot_ors::StoreRebindReplayRecord {
        operation_id: operation_id.clone(),
        request_digest: request_digest.clone(),
        candidate_binding_digest: "d".repeat(64),
        store_fence: "e".repeat(64),
        requirement_digest: sha256_json(&requirement).expect("requirement digest"),
        process_id: 42_001,
        process_start_time_100ns: 77,
        process_image_path: process_image_path.clone(),
        job_name: job_name.clone(),
        generation: requirement.state_fence.resource_generation.value(),
        authority_epoch: requirement.state_fence.authority_epoch.value(),
        state: eliot_ors::StoreRebindReplayState::Committed,
        receipt: Some(request_digest.clone()),
        commit_order: 0,
    };
    let ors_path = root.join(".eliot").join("kernel-ors.redb");
    let ors = RedbRecoveryStore::open(&ors_path).expect("open ORS");
    ors.persist_store_rebind(&record)
        .expect("persist committed rebind");
    let mut unrelated = record.clone();
    unrelated.operation_id =
        OperationIdentity::new("store-rebind-unrelated-lineage").expect("unrelated op");
    unrelated.request_digest = "f".repeat(64);
    unrelated.receipt = Some(unrelated.request_digest.clone());
    unrelated.requirement_digest = "0".repeat(64);
    ors.persist_store_rebind(&unrelated)
        .expect("persist unrelated committed rebind");
    drop(ors);

    let kernel =
        KernelComposition::new(KernelConfig::new(&root).with_store_bootstrap(requirement.clone()))
            .expect("restart composition");
    let service = kernel.service.lock().expect("service lock");
    assert_eq!(service.state(), KernelServiceState::Cold);
    assert_eq!(
        service
            .store_rebind_receipt()
            .expect("recovered receipt")
            .request_digest,
        request_digest
    );
    drop(service);
    let recovered = kernel
        .store_handoff
        .lock()
        .expect("handoff lock")
        .clone()
        .expect("exact recovered handoff");
    assert_eq!(recovered.requirement, requirement);
    assert_eq!(
        recovered.process_binding.process.process_id,
        record.process_id
    );
    assert_eq!(
        recovered.process_binding.process.start_time_100ns,
        record.process_start_time_100ns
    );
    assert_eq!(
        recovered.process_binding.process.image_path,
        process_image_path
    );
    assert_eq!(recovered.process_binding.job.as_str(), job_name);

    // Replaying the exact BootstrapStore handoff is idempotent. A new
    // process/Job binding is a substitution, even when its requirement is
    // otherwise identical.
    kernel
        .install_store_bootstrap(recovered.clone())
        .expect("exact BootstrapStore replay");
    let mut substituted = recovered;
    substituted.process_binding.process.process_id += 1;
    assert!(kernel.install_store_bootstrap(substituted).is_err());
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
// The C54 tests intentionally keep the complete control-path fixture
// together; fixed data and expected setup transitions use unwrap as
// concise assertions.
#[allow(clippy::too_many_lines, clippy::unwrap_used)]
#[tokio::test]
async fn c54_p1_reconcile_rebind_fenced_until_publication_via_control_path() {
    assert_eq!(
        KernelComposition::production_store_rebind_discriminator(),
        KERNEL_STORE_REBIND_PRODUCTION_DISCRIMINATOR
    );
    let dir = std::env::temp_dir().join(format!(
        "c54-p1-reconcile-pub-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let requirement = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge").unwrap(),
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store").unwrap(),
        store_generation: ResourceGeneration::genesis(),
        state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        launch_nonce: PlatformHandle::new("store-launch-nonce").unwrap(),
        connection_id: PlatformHandle::new("store-connection").unwrap(),
        expected_peer_sid: PlatformHandle::new("S-1-5-18").unwrap(),
        expected_peer_session_id: 0,
        approved_artifact_hash: PlatformHandle::new("a".repeat(64)).unwrap(),
        approved_config_hash: PlatformHandle::new("b".repeat(64)).unwrap(),
        timeout_ms: 5000,
    };
    let kernel =
        KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement.clone()))
            .unwrap();
    let operation_id = PlatformHandle::new("c54-op-1").unwrap();
    let request_digest = "b".repeat(64);
    let candidate = {
        let mut svc = kernel.service.lock().unwrap();
        let cand = HostKernelCandidateBinding {
            installation_id: PlatformHandle::new("installation-1").unwrap(),
            host_epoch: AuthorityEpoch::new(1).unwrap(),
            kernel_epoch: AuthorityEpoch::genesis(),
            activation_id: PlatformHandle::new("activation-1").unwrap(),
            artifact_hash: PlatformHandle::new("artifact-1").unwrap(),
            config_hash: PlatformHandle::new("config-1").unwrap(),
            job_object_id: PlatformHandle::new("Local\\Eliot-Host-Kernel-test").unwrap(),
            pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE).unwrap(),
            host_process: eliot_kernel_service::HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: r"C:\eliot\host.exe".to_owned(),
            },
            job_binding: eliot_kernel_service::HostJobBinding {
                job: eliot_kernel_service::HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-test".to_owned(),
                },
                root: eliot_kernel_service::HostJobRoot {
                    process: eliot_kernel_service::HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: r"C:\eliot\kernel.exe".to_owned(),
                    },
                    executable: eliot_kernel_service::HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            supervision_incarnation: supervision_incarnation(),
            restart_budget: eliot_kernel_service::RestartBudget::new(1, 1).unwrap(),
            agent_bridge_admission: None,
            containment_action: None,
        };
        svc.reconcile(cand.clone()).unwrap();
        svc.apply(KernelControlCommand::Shadow).unwrap();
        svc.apply(KernelControlCommand::PrepareHandoff).unwrap();
        let permit = eliot_kernel_service::KernelActivationPermit {
            operation_id: PlatformHandle::new("op-activation-c54-1").unwrap(),
            candidate_binding_digest: cand.compute_digest().unwrap(),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: PlatformHandle::new("txn-1").unwrap(),
            journal_sequence: 1,
            generation: ResourceGeneration::genesis(),
            authority_epoch: cand.kernel_epoch,
            activation_nonce: eliot_platform::KernelActivationNonce::new(
                PlatformHandle::new("a".repeat(64)).unwrap(),
            )
            .unwrap(),
        };
        svc.activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
            .unwrap();
        let ready = KernelReadyReceipt {
            activation_id: cand.activation_id.clone(),
            activation_operation_id: permit.operation_id.clone(),
            activation_nonce_digest: svc
                .activation_receipt()
                .unwrap()
                .activation_nonce_digest
                .clone(),
            process: eliot_kernel_service::ProcessObservation {
                process_id: PlatformHandle::new("pid:42:start:10").unwrap(),
                job_object_id: cand.job_object_id.clone(),
                state: eliot_runtime_contracts::ServiceProcessState::Ready,
                health: eliot_runtime_contracts::HealthVector::healthy(),
                evidence_refs: vec![PlatformHandle::new("ev1").unwrap()],
            },
            health: eliot_runtime_contracts::HealthVector::healthy(),
            evidence_refs: vec![PlatformHandle::new("ev1").unwrap()],
        };
        svc.publish_ready(ready).unwrap();
        cand
    };
    let handoff = eliot_kernel_service::StoreRebindHandoff {
        operation_id: operation_id.clone(),
        request_digest: request_digest.clone(),
        requirement: requirement.clone(),
        process_binding: eliot_kernel_service::StoreProcessBinding {
            process: eliot_kernel_service::HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\store.exe".to_owned(),
            },
            job: PlatformHandle::new(r"Local\Eliot-Store-test").unwrap(),
        },
        candidate_binding_digest: candidate.compute_digest().unwrap(),
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: String::new(),
    };
    let mut handoff = handoff;
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&handoff.requirement.state_fence).unwrap());
    hasher.update(handoff.generation.value().to_le_bytes());
    hasher.update(handoff.authority_epoch.value().to_le_bytes());
    hasher.update(
        handoff
            .requirement
            .approved_artifact_hash
            .as_str()
            .as_bytes(),
    );
    hasher.update(handoff.requirement.approved_config_hash.as_str().as_bytes());
    hasher.update(handoff.process_binding.process.process_id.to_le_bytes());
    hasher.update(
        handoff
            .process_binding
            .process
            .start_time_100ns
            .to_le_bytes(),
    );
    hasher.update(handoff.process_binding.process.image_path.as_bytes());
    hasher.update(handoff.process_binding.job.as_str().as_bytes());
    hasher.update(handoff.candidate_binding_digest.as_bytes());
    handoff.store_fence = format!("{:x}", hasher.finalize());
    let record = eliot_ors::StoreRebindReplayRecord {
        operation_id: eliot_ors::OperationIdentity::new(operation_id.as_str()).unwrap(),
        request_digest: request_digest.clone(),
        candidate_binding_digest: handoff.candidate_binding_digest.clone(),
        store_fence: handoff.store_fence.clone(),
        requirement_digest: {
            let b = serde_json::to_vec(&requirement).unwrap();
            format!("{:x}", Sha256::digest(b))
        },
        process_id: handoff.process_binding.process.process_id,
        process_start_time_100ns: handoff.process_binding.process.start_time_100ns,
        process_image_path: handoff.process_binding.process.image_path.clone(),
        job_name: handoff.process_binding.job.as_str().to_owned(),
        generation: handoff.generation.value(),
        authority_epoch: handoff.authority_epoch.value(),
        state: eliot_ors::StoreRebindReplayState::Committed,
        receipt: Some(request_digest.clone()),
        commit_order: 0,
    };
    kernel
        .generation_gateway
        .ors
        .persist_store_rebind(&record)
        .unwrap();
    let peer = eliot_ipc::PeerIdentity::authenticated_for_test(
        eliot_ipc::ProcessBinding::from_observation(
            candidate.host_process.process_id,
            candidate.host_process.start_time_100ns,
            candidate.host_process.image_path.clone(),
        )
        .unwrap(),
        "S-1-5-18".to_owned(),
        "0".to_owned(),
    )
    .unwrap();
    let query = eliot_kernel_service::StoreRebindQuery {
        operation_id: operation_id.clone(),
        request_digest: request_digest.clone(),
    };
    let request = KernelControlRequest {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id: PlatformHandle::new("msg-reconcile-pub").unwrap(),
        sequence: 0,
        peer_process_id: candidate.host_process.process_id,
        generation: ResourceGeneration::genesis(),
        candidate: candidate.clone(),
        command: KernelControlCommand::ReconcileRebindStore(query),
        payload_digest: request_digest.clone(),
    }
    .with_computed_digest()
    .unwrap();
    let result = kernel.apply_control_request(request, &peer, 0).await;
    assert!(result.is_err());
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(windows)]
// The C54 tests intentionally keep the complete control-path fixture
// together; fixed data and expected setup transitions use unwrap as
// concise assertions.
#[allow(clippy::too_many_lines, clippy::unwrap_used)]
#[tokio::test]
async fn c54_p1_superseded_rebind_durably_fenced_via_control_path() {
    assert_eq!(
        KernelComposition::production_store_rebind_discriminator(),
        KERNEL_STORE_REBIND_PRODUCTION_DISCRIMINATOR
    );
    let dir = std::env::temp_dir().join(format!(
        "c54-p1-superseded-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let requirement = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge").unwrap(),
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store").unwrap(),
        store_generation: ResourceGeneration::genesis(),
        state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        launch_nonce: PlatformHandle::new("store-launch-nonce").unwrap(),
        connection_id: PlatformHandle::new("store-connection").unwrap(),
        expected_peer_sid: PlatformHandle::new("S-1-5-18").unwrap(),
        expected_peer_session_id: 0,
        approved_artifact_hash: PlatformHandle::new("a".repeat(64)).unwrap(),
        approved_config_hash: PlatformHandle::new("b".repeat(64)).unwrap(),
        timeout_ms: 5000,
    };
    let kernel =
        KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement.clone()))
            .unwrap();
    let candidate = {
        let mut svc = kernel.service.lock().unwrap();
        let cand = HostKernelCandidateBinding {
            installation_id: PlatformHandle::new("installation-1").unwrap(),
            host_epoch: AuthorityEpoch::new(1).unwrap(),
            kernel_epoch: AuthorityEpoch::genesis(),
            activation_id: PlatformHandle::new("activation-1").unwrap(),
            artifact_hash: PlatformHandle::new("artifact-1").unwrap(),
            config_hash: PlatformHandle::new("config-1").unwrap(),
            job_object_id: PlatformHandle::new("Local\\Eliot-Host-Kernel-test").unwrap(),
            pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE).unwrap(),
            host_process: eliot_kernel_service::HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: r"C:\eliot\host.exe".to_owned(),
            },
            job_binding: eliot_kernel_service::HostJobBinding {
                job: eliot_kernel_service::HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-test".to_owned(),
                },
                root: eliot_kernel_service::HostJobRoot {
                    process: eliot_kernel_service::HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: r"C:\eliot\kernel.exe".to_owned(),
                    },
                    executable: eliot_kernel_service::HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            supervision_incarnation: supervision_incarnation(),
            restart_budget: eliot_kernel_service::RestartBudget::new(1, 1).unwrap(),
            agent_bridge_admission: None,
            containment_action: None,
        };
        svc.reconcile(cand.clone()).unwrap();
        svc.apply(KernelControlCommand::Shadow).unwrap();
        svc.apply(KernelControlCommand::PrepareHandoff).unwrap();
        let permit = eliot_kernel_service::KernelActivationPermit {
            operation_id: PlatformHandle::new("op-superseded").unwrap(),
            candidate_binding_digest: cand.compute_digest().unwrap(),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: PlatformHandle::new("txn-1").unwrap(),
            journal_sequence: 1,
            generation: ResourceGeneration::genesis(),
            authority_epoch: cand.kernel_epoch,
            activation_nonce: eliot_platform::KernelActivationNonce::new(
                PlatformHandle::new("a".repeat(64)).unwrap(),
            )
            .unwrap(),
        };
        svc.activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
            .unwrap();
        let ready = KernelReadyReceipt {
            activation_id: cand.activation_id.clone(),
            activation_operation_id: permit.operation_id.clone(),
            activation_nonce_digest: svc
                .activation_receipt()
                .unwrap()
                .activation_nonce_digest
                .clone(),
            process: eliot_kernel_service::ProcessObservation {
                process_id: PlatformHandle::new("pid:42:start:10").unwrap(),
                job_object_id: cand.job_object_id.clone(),
                state: eliot_runtime_contracts::ServiceProcessState::Ready,
                health: eliot_runtime_contracts::HealthVector::healthy(),
                evidence_refs: vec![PlatformHandle::new("ev1").unwrap()],
            },
            health: eliot_runtime_contracts::HealthVector::healthy(),
            evidence_refs: vec![PlatformHandle::new("ev1").unwrap()],
        };
        svc.publish_ready(ready).unwrap();
        cand
    };
    let requirement_digest = {
        let b = serde_json::to_vec(&requirement).unwrap();
        format!("{:x}", Sha256::digest(b))
    };
    let candidate_digest = candidate.compute_digest().unwrap();
    let make_fence = |pid: u32, start: u64, img: &str, job: &str| {
        let mut h = Sha256::new();
        h.update(serde_json::to_vec(&requirement.state_fence).unwrap());
        h.update(ResourceGeneration::genesis().value().to_le_bytes());
        h.update(AuthorityEpoch::genesis().value().to_le_bytes());
        h.update(requirement.approved_artifact_hash.as_str().as_bytes());
        h.update(requirement.approved_config_hash.as_str().as_bytes());
        h.update(pid.to_le_bytes());
        h.update(start.to_le_bytes());
        h.update(img.as_bytes());
        h.update(job.as_bytes());
        h.update(candidate_digest.as_bytes());
        format!("{:x}", h.finalize())
    };
    let first = eliot_ors::StoreRebindReplayRecord {
        operation_id: eliot_ors::OperationIdentity::new("c54-first").unwrap(),
        request_digest: "a".repeat(64),
        candidate_binding_digest: candidate_digest.clone(),
        store_fence: make_fence(
            101,
            201,
            r"C:\Eliot\store-101.exe",
            r"Local\Eliot-Store-test",
        ),
        requirement_digest: requirement_digest.clone(),
        process_id: 101,
        process_start_time_100ns: 201,
        process_image_path: r"C:\Eliot\store-101.exe".to_owned(),
        job_name: r"Local\Eliot-Store-test".to_owned(),
        generation: 1,
        authority_epoch: 1,
        state: eliot_ors::StoreRebindReplayState::Committed,
        receipt: Some("a".repeat(64)),
        commit_order: 0,
    };
    let mut second = first.clone();
    second.operation_id = eliot_ors::OperationIdentity::new("c54-second").unwrap();
    second.request_digest = "d".repeat(64);
    second.receipt = Some(second.request_digest.clone());
    second.process_id = 102;
    second.store_fence = make_fence(
        102,
        201,
        r"C:\Eliot\store-101.exe",
        r"Local\Eliot-Store-test",
    );
    kernel
        .generation_gateway
        .ors
        .persist_store_rebind(&first)
        .unwrap();
    kernel
        .generation_gateway
        .ors
        .persist_store_rebind(&second)
        .unwrap();
    let peer = eliot_ipc::PeerIdentity::authenticated_for_test(
        eliot_ipc::ProcessBinding::from_observation(
            candidate.host_process.process_id,
            candidate.host_process.start_time_100ns,
            candidate.host_process.image_path.clone(),
        )
        .unwrap(),
        "S-1-5-18".to_owned(),
        "0".to_owned(),
    )
    .unwrap();
    let query = eliot_kernel_service::StoreRebindQuery {
        operation_id: PlatformHandle::new("c54-first").unwrap(),
        request_digest: "a".repeat(64),
    };
    let request = KernelControlRequest {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id: PlatformHandle::new("msg-superseded").unwrap(),
        sequence: 0,
        peer_process_id: candidate.host_process.process_id,
        generation: ResourceGeneration::genesis(),
        candidate: candidate.clone(),
        command: KernelControlCommand::ReconcileRebindStore(query),
        payload_digest: "a".repeat(64),
    }
    .with_computed_digest()
    .unwrap();
    let result = kernel.apply_control_request(request, &peer, 0).await;
    assert!(result.is_err());
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(windows)]
// The C54 tests intentionally keep the complete control-path fixture
// together; fixed data and expected setup transitions use unwrap as
// concise assertions.
#[allow(clippy::too_many_lines, clippy::unwrap_used)]
#[tokio::test]
async fn c54_p1_generic_reconcile_fenced_on_mismatched_store_gate_via_control_path() {
    assert_eq!(
        KernelComposition::production_store_rebind_discriminator(),
        KERNEL_STORE_REBIND_PRODUCTION_DISCRIMINATOR
    );
    let dir = std::env::temp_dir().join(format!(
        "c54-p1-generic-reconcile-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let requirement = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge").unwrap(),
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store").unwrap(),
        store_generation: ResourceGeneration::genesis(),
        state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        launch_nonce: PlatformHandle::new("store-launch-nonce").unwrap(),
        connection_id: PlatformHandle::new("store-connection").unwrap(),
        expected_peer_sid: PlatformHandle::new("S-1-5-18").unwrap(),
        expected_peer_session_id: 0,
        approved_artifact_hash: PlatformHandle::new("a".repeat(64)).unwrap(),
        approved_config_hash: PlatformHandle::new("b".repeat(64)).unwrap(),
        timeout_ms: 5000,
    };
    let kernel =
        KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement.clone()))
            .unwrap();
    let candidate = {
        let mut svc = kernel.service.lock().unwrap();
        let cand = HostKernelCandidateBinding {
            installation_id: PlatformHandle::new("installation-1").unwrap(),
            host_epoch: AuthorityEpoch::new(1).unwrap(),
            kernel_epoch: AuthorityEpoch::genesis(),
            activation_id: PlatformHandle::new("activation-1").unwrap(),
            artifact_hash: PlatformHandle::new("artifact-1").unwrap(),
            config_hash: PlatformHandle::new("config-1").unwrap(),
            job_object_id: PlatformHandle::new("Local\\Eliot-Host-Kernel-test").unwrap(),
            pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE).unwrap(),
            host_process: eliot_kernel_service::HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: r"C:\eliot\host.exe".to_owned(),
            },
            job_binding: eliot_kernel_service::HostJobBinding {
                job: eliot_kernel_service::HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-test".to_owned(),
                },
                root: eliot_kernel_service::HostJobRoot {
                    process: eliot_kernel_service::HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: r"C:\eliot\kernel.exe".to_owned(),
                    },
                    executable: eliot_kernel_service::HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            supervision_incarnation: supervision_incarnation(),
            restart_budget: eliot_kernel_service::RestartBudget::new(1, 1).unwrap(),
            agent_bridge_admission: None,
            containment_action: None,
        };
        svc.reconcile(cand.clone()).unwrap();
        svc.apply(KernelControlCommand::Shadow).unwrap();
        svc.apply(KernelControlCommand::PrepareHandoff).unwrap();
        let permit = eliot_kernel_service::KernelActivationPermit {
            operation_id: PlatformHandle::new("op-1").unwrap(),
            candidate_binding_digest: cand.compute_digest().unwrap(),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: PlatformHandle::new("txn-1").unwrap(),
            journal_sequence: 1,
            generation: ResourceGeneration::genesis(),
            authority_epoch: cand.kernel_epoch,
            activation_nonce: eliot_platform::KernelActivationNonce::new(
                PlatformHandle::new("a".repeat(64)).unwrap(),
            )
            .unwrap(),
        };
        svc.activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
            .unwrap();
        let ready = KernelReadyReceipt {
            activation_id: cand.activation_id.clone(),
            activation_operation_id: permit.operation_id.clone(),
            activation_nonce_digest: svc
                .activation_receipt()
                .unwrap()
                .activation_nonce_digest
                .clone(),
            process: eliot_kernel_service::ProcessObservation {
                process_id: PlatformHandle::new("pid:42:start:10").unwrap(),
                job_object_id: cand.job_object_id.clone(),
                state: eliot_runtime_contracts::ServiceProcessState::Ready,
                health: eliot_runtime_contracts::HealthVector::healthy(),
                evidence_refs: vec![PlatformHandle::new("ev1").unwrap()],
            },
            health: eliot_runtime_contracts::HealthVector::healthy(),
            evidence_refs: vec![PlatformHandle::new("ev1").unwrap()],
        };
        svc.publish_ready(ready).unwrap();
        let handoff = eliot_kernel_service::StoreRebindHandoff {
            operation_id: PlatformHandle::new("c54-rebind-1").unwrap(),
            request_digest: "d".repeat(64),
            requirement: requirement.clone(),
            process_binding: eliot_kernel_service::StoreProcessBinding {
                process: eliot_kernel_service::HostProcessBinding {
                    process_id: 99,
                    start_time_100ns: 100,
                    image_path: r"C:\Eliot\store.exe".to_owned(),
                },
                job: PlatformHandle::new(r"Local\Eliot-Store-test").unwrap(),
            },
            candidate_binding_digest: cand.compute_digest().unwrap(),
            generation: ResourceGeneration::genesis(),
            authority_epoch: AuthorityEpoch::genesis(),
            store_fence: String::new(),
        };
        let mut handoff = handoff;
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&handoff.requirement.state_fence).unwrap());
        hasher.update(handoff.generation.value().to_le_bytes());
        hasher.update(handoff.authority_epoch.value().to_le_bytes());
        hasher.update(
            handoff
                .requirement
                .approved_artifact_hash
                .as_str()
                .as_bytes(),
        );
        hasher.update(handoff.requirement.approved_config_hash.as_str().as_bytes());
        hasher.update(handoff.process_binding.process.process_id.to_le_bytes());
        hasher.update(
            handoff
                .process_binding
                .process
                .start_time_100ns
                .to_le_bytes(),
        );
        hasher.update(handoff.process_binding.process.image_path.as_bytes());
        hasher.update(handoff.process_binding.job.as_str().as_bytes());
        hasher.update(handoff.candidate_binding_digest.as_bytes());
        handoff.store_fence = format!("{:x}", hasher.finalize());
        svc.rebind_store(&handoff, "e".repeat(64)).unwrap();
        *kernel.store_handoff.lock().unwrap() = Some(eliot_kernel_service::StoreBootstrapHandoff {
            requirement: requirement.clone(),
            process_binding: handoff.process_binding.clone(),
        });
        cand
    };
    let peer = eliot_ipc::PeerIdentity::authenticated_for_test(
        eliot_ipc::ProcessBinding::from_observation(
            candidate.host_process.process_id,
            candidate.host_process.start_time_100ns,
            candidate.host_process.image_path.clone(),
        )
        .unwrap(),
        "S-1-5-18".to_owned(),
        "0".to_owned(),
    )
    .unwrap();
    let mut mismatched = candidate.clone();
    mismatched.config_hash = PlatformHandle::new("mismatch-config").unwrap();
    let request = KernelControlRequest {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id: PlatformHandle::new("msg-1").unwrap(),
        sequence: 0,
        peer_process_id: candidate.host_process.process_id,
        generation: ResourceGeneration::genesis(),
        candidate: mismatched,
        command: KernelControlCommand::Reconcile,
        payload_digest: String::new(),
    }
    .with_computed_digest()
    .unwrap();
    let result = kernel.apply_control_request(request, &peer, 0).await;
    assert!(result.is_err());
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(windows)]
// The C54 tests intentionally keep the complete control-path fixture
// together; fixed data and expected setup transitions use unwrap as
// concise assertions.
#[allow(clippy::too_many_lines, clippy::unwrap_used)]
#[tokio::test]
async fn c54_p1_probe_ready_requires_exact_store_fence_via_control_path() {
    assert_eq!(
        KernelComposition::production_store_rebind_discriminator(),
        KERNEL_STORE_REBIND_PRODUCTION_DISCRIMINATOR
    );
    let dir = std::env::temp_dir().join(format!(
        "c54-p1-probe-ready-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let requirement = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge").unwrap(),
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store").unwrap(),
        store_generation: ResourceGeneration::genesis(),
        state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        launch_nonce: PlatformHandle::new("store-launch-nonce").unwrap(),
        connection_id: PlatformHandle::new("store-connection").unwrap(),
        expected_peer_sid: PlatformHandle::new("S-1-5-18").unwrap(),
        expected_peer_session_id: 0,
        approved_artifact_hash: PlatformHandle::new("a".repeat(64)).unwrap(),
        approved_config_hash: PlatformHandle::new("b".repeat(64)).unwrap(),
        timeout_ms: 5000,
    };
    let kernel =
        KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement.clone()))
            .unwrap();
    let record = eliot_ors::StoreRebindReplayRecord {
        operation_id: eliot_ors::OperationIdentity::new("c54-probe-op").unwrap(),
        request_digest: "c".repeat(64),
        candidate_binding_digest: "d".repeat(64),
        store_fence: "e".repeat(64),
        requirement_digest: {
            let b = serde_json::to_vec(&requirement).unwrap();
            format!("{:x}", Sha256::digest(b))
        },
        process_id: 42_001,
        process_start_time_100ns: 77,
        process_image_path: r"C:\Eliot\eliot-store.exe".to_owned(),
        job_name: r"Local\Eliot-Store-recovered".to_owned(),
        generation: requirement.state_fence.resource_generation.value(),
        authority_epoch: requirement.state_fence.authority_epoch.value(),
        state: eliot_ors::StoreRebindReplayState::Committed,
        receipt: Some("c".repeat(64)),
        commit_order: 0,
    };
    kernel
        .generation_gateway
        .ors
        .persist_store_rebind(&record)
        .unwrap();
    let candidate = HostKernelCandidateBinding {
        installation_id: PlatformHandle::new("installation-1").unwrap(),
        host_epoch: AuthorityEpoch::new(1).unwrap(),
        kernel_epoch: AuthorityEpoch::genesis(),
        activation_id: PlatformHandle::new("activation-1").unwrap(),
        artifact_hash: PlatformHandle::new("artifact-1").unwrap(),
        config_hash: PlatformHandle::new("config-1").unwrap(),
        job_object_id: PlatformHandle::new("Local\\Eliot-Host-Kernel-test").unwrap(),
        pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE).unwrap(),
        host_process: eliot_kernel_service::HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: r"C:\eliot\host.exe".to_owned(),
        },
        job_binding: eliot_kernel_service::HostJobBinding {
            job: eliot_kernel_service::HostJobIdentity {
                name: "Local\\Eliot-Host-Kernel-test".to_owned(),
            },
            root: eliot_kernel_service::HostJobRoot {
                process: eliot_kernel_service::HostProcessBinding {
                    process_id: 42,
                    start_time_100ns: 10,
                    image_path: r"C:\eliot\kernel.exe".to_owned(),
                },
                executable: eliot_kernel_service::HostFileIdentity {
                    volume_serial_number: 1,
                    file_index: 2,
                },
            },
        },
        supervision_incarnation: supervision_incarnation(),
        restart_budget: eliot_kernel_service::RestartBudget::new(1, 1).unwrap(),
        agent_bridge_admission: None,
        containment_action: None,
    };
    let peer = eliot_ipc::PeerIdentity::authenticated_for_test(
        eliot_ipc::ProcessBinding::from_observation(
            candidate.host_process.process_id,
            candidate.host_process.start_time_100ns,
            candidate.host_process.image_path.clone(),
        )
        .unwrap(),
        "S-1-5-18".to_owned(),
        "0".to_owned(),
    )
    .unwrap();
    let request = KernelControlRequest {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id: PlatformHandle::new("probe-msg").unwrap(),
        sequence: 0,
        peer_process_id: 7,
        generation: ResourceGeneration::genesis(),
        candidate: candidate.clone(),
        command: KernelControlCommand::ProbeReady,
        payload_digest: String::new(),
    }
    .with_computed_digest()
    .unwrap();
    let result = kernel.apply_control_request(request, &peer, 0).await;
    assert!(result.is_err());
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(windows)]
// The C54 tests intentionally keep the complete control-path fixture
// together; fixed data and expected setup transitions use unwrap as
// concise assertions.
#[allow(clippy::too_many_lines, clippy::unwrap_used)]
#[tokio::test]
async fn c54_p1_legacy_zero_order_requires_migration_via_control_path() {
    assert_eq!(
        KernelComposition::production_store_rebind_discriminator(),
        KERNEL_STORE_REBIND_PRODUCTION_DISCRIMINATOR
    );
    let dir = std::env::temp_dir().join(format!(
        "c54-p1-legacy-zero-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let requirement = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge").unwrap(),
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store").unwrap(),
        store_generation: ResourceGeneration::genesis(),
        state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        launch_nonce: PlatformHandle::new("store-launch-nonce").unwrap(),
        connection_id: PlatformHandle::new("store-connection").unwrap(),
        expected_peer_sid: PlatformHandle::new("S-1-5-18").unwrap(),
        expected_peer_session_id: 0,
        approved_artifact_hash: PlatformHandle::new("a".repeat(64)).unwrap(),
        approved_config_hash: PlatformHandle::new("b".repeat(64)).unwrap(),
        timeout_ms: 5000,
    };
    let kernel =
        KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement.clone()))
            .unwrap();
    let candidate = {
        let mut svc = kernel.service.lock().unwrap();
        let cand = HostKernelCandidateBinding {
            installation_id: PlatformHandle::new("installation-1").unwrap(),
            host_epoch: AuthorityEpoch::new(1).unwrap(),
            kernel_epoch: AuthorityEpoch::genesis(),
            activation_id: PlatformHandle::new("activation-1").unwrap(),
            artifact_hash: PlatformHandle::new("artifact-1").unwrap(),
            config_hash: PlatformHandle::new("config-1").unwrap(),
            job_object_id: PlatformHandle::new("Local\\Eliot-Host-Kernel-test").unwrap(),
            pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE).unwrap(),
            host_process: eliot_kernel_service::HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: r"C:\eliot\host.exe".to_owned(),
            },
            job_binding: eliot_kernel_service::HostJobBinding {
                job: eliot_kernel_service::HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-test".to_owned(),
                },
                root: eliot_kernel_service::HostJobRoot {
                    process: eliot_kernel_service::HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: r"C:\eliot\kernel.exe".to_owned(),
                    },
                    executable: eliot_kernel_service::HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            supervision_incarnation: supervision_incarnation(),
            restart_budget: eliot_kernel_service::RestartBudget::new(1, 1).unwrap(),
            agent_bridge_admission: None,
            containment_action: None,
        };
        svc.reconcile(cand.clone()).unwrap();
        svc.apply(KernelControlCommand::Shadow).unwrap();
        svc.apply(KernelControlCommand::PrepareHandoff).unwrap();
        let permit = eliot_kernel_service::KernelActivationPermit {
            operation_id: PlatformHandle::new("op-legacy").unwrap(),
            candidate_binding_digest: cand.compute_digest().unwrap(),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: PlatformHandle::new("txn-1").unwrap(),
            journal_sequence: 1,
            generation: ResourceGeneration::genesis(),
            authority_epoch: cand.kernel_epoch,
            activation_nonce: eliot_platform::KernelActivationNonce::new(
                PlatformHandle::new("a".repeat(64)).unwrap(),
            )
            .unwrap(),
        };
        svc.activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
            .unwrap();
        let ready = KernelReadyReceipt {
            activation_id: cand.activation_id.clone(),
            activation_operation_id: permit.operation_id.clone(),
            activation_nonce_digest: svc
                .activation_receipt()
                .unwrap()
                .activation_nonce_digest
                .clone(),
            process: eliot_kernel_service::ProcessObservation {
                process_id: PlatformHandle::new("pid:42:start:10").unwrap(),
                job_object_id: cand.job_object_id.clone(),
                state: eliot_runtime_contracts::ServiceProcessState::Ready,
                health: eliot_runtime_contracts::HealthVector::healthy(),
                evidence_refs: vec![PlatformHandle::new("ev1").unwrap()],
            },
            health: eliot_runtime_contracts::HealthVector::healthy(),
            evidence_refs: vec![PlatformHandle::new("ev1").unwrap()],
        };
        svc.publish_ready(ready).unwrap();
        cand
    };
    let requirement_digest = {
        let b = serde_json::to_vec(&requirement).unwrap();
        format!("{:x}", Sha256::digest(b))
    };
    let candidate_digest = candidate.compute_digest().unwrap();
    let make_fence = |pid: u32| {
        let mut h = Sha256::new();
        h.update(serde_json::to_vec(&requirement.state_fence).unwrap());
        h.update(ResourceGeneration::genesis().value().to_le_bytes());
        h.update(AuthorityEpoch::genesis().value().to_le_bytes());
        h.update(requirement.approved_artifact_hash.as_str().as_bytes());
        h.update(requirement.approved_config_hash.as_str().as_bytes());
        h.update(pid.to_le_bytes());
        h.update(201u64.to_le_bytes());
        h.update(r"C:\Eliot\store-legacy.exe".as_bytes());
        h.update(r"Local\Eliot-Store-test".as_bytes());
        h.update(candidate_digest.as_bytes());
        format!("{:x}", h.finalize())
    };
    let first = eliot_ors::StoreRebindReplayRecord {
        operation_id: eliot_ors::OperationIdentity::new("c54-legacy-first").unwrap(),
        request_digest: "a".repeat(64),
        candidate_binding_digest: candidate_digest.clone(),
        store_fence: make_fence(101),
        requirement_digest: requirement_digest.clone(),
        process_id: 101,
        process_start_time_100ns: 201,
        process_image_path: r"C:\Eliot\store-legacy.exe".to_owned(),
        job_name: r"Local\Eliot-Store-test".to_owned(),
        generation: 1,
        authority_epoch: 1,
        state: eliot_ors::StoreRebindReplayState::Committed,
        receipt: Some("a".repeat(64)),
        commit_order: 0,
    };
    let mut second = first.clone();
    second.operation_id = eliot_ors::OperationIdentity::new("c54-legacy-second").unwrap();
    second.request_digest = "b".repeat(64);
    second.receipt = Some(second.request_digest.clone());
    second.process_id = 102;
    second.store_fence = make_fence(102);
    kernel
        .generation_gateway
        .ors
        .insert_store_rebind_legacy_for_test(&first)
        .unwrap();
    kernel
        .generation_gateway
        .ors
        .insert_store_rebind_legacy_for_test(&second)
        .unwrap();
    let peer = eliot_ipc::PeerIdentity::authenticated_for_test(
        eliot_ipc::ProcessBinding::from_observation(
            candidate.host_process.process_id,
            candidate.host_process.start_time_100ns,
            candidate.host_process.image_path.clone(),
        )
        .unwrap(),
        "S-1-5-18".to_owned(),
        "0".to_owned(),
    )
    .unwrap();
    for (op, digest) in [
        ("c54-legacy-first", "a".repeat(64)),
        ("c54-legacy-second", "b".repeat(64)),
    ] {
        let query = eliot_kernel_service::StoreRebindQuery {
            operation_id: PlatformHandle::new(op).unwrap(),
            request_digest: digest.clone(),
        };
        let request = KernelControlRequest {
            wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
            message_id: PlatformHandle::new(format!("msg-legacy-{op}")).unwrap(),
            sequence: 0,
            peer_process_id: candidate.host_process.process_id,
            generation: ResourceGeneration::genesis(),
            candidate: candidate.clone(),
            command: KernelControlCommand::ReconcileRebindStore(query),
            payload_digest: digest,
        }
        .with_computed_digest()
        .unwrap();
        let result = kernel.apply_control_request(request, &peer, 0).await;
        assert!(result.is_err(), "legacy {op} should be fenced");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(windows)]
#[allow(clippy::too_many_lines, clippy::unwrap_used, clippy::expect_used)]
#[tokio::test]
async fn c183_probe_ready_shares_store_rebind_gate_and_requires_committed_publication() {
    assert_eq!(
        KernelComposition::production_store_rebind_discriminator(),
        KERNEL_STORE_REBIND_PRODUCTION_DISCRIMINATOR
    );
    let dir = std::env::temp_dir().join(format!(
        "c183-probe-gate-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let requirement = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new("store_bridge").unwrap(),
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store").unwrap(),
        store_generation: ResourceGeneration::genesis(),
        state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        launch_nonce: PlatformHandle::new("store-launch-nonce").unwrap(),
        connection_id: PlatformHandle::new("store-connection").unwrap(),
        expected_peer_sid: PlatformHandle::new("S-1-5-18").unwrap(),
        expected_peer_session_id: 0,
        approved_artifact_hash: PlatformHandle::new("a".repeat(64)).unwrap(),
        approved_config_hash: PlatformHandle::new("b".repeat(64)).unwrap(),
        timeout_ms: 5000,
    };
    let kernel =
        KernelComposition::new(KernelConfig::new(&dir).with_store_bootstrap(requirement.clone()))
            .unwrap();
    let candidate = {
        let mut svc = kernel.service.lock().unwrap();
        let cand = HostKernelCandidateBinding {
            installation_id: PlatformHandle::new("installation-1").unwrap(),
            host_epoch: AuthorityEpoch::new(1).unwrap(),
            kernel_epoch: AuthorityEpoch::genesis(),
            activation_id: PlatformHandle::new("activation-1").unwrap(),
            artifact_hash: PlatformHandle::new("artifact-1").unwrap(),
            config_hash: PlatformHandle::new("config-1").unwrap(),
            job_object_id: PlatformHandle::new("Local\\Eliot-Host-Kernel-test").unwrap(),
            pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE).unwrap(),
            host_process: eliot_kernel_service::HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: r"C:\eliot\host.exe".to_owned(),
            },
            job_binding: eliot_kernel_service::HostJobBinding {
                job: eliot_kernel_service::HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-test".to_owned(),
                },
                root: eliot_kernel_service::HostJobRoot {
                    process: eliot_kernel_service::HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: r"C:\eliot\kernel.exe".to_owned(),
                    },
                    executable: eliot_kernel_service::HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            supervision_incarnation: supervision_incarnation(),
            restart_budget: eliot_kernel_service::RestartBudget::new(1, 1).unwrap(),
            agent_bridge_admission: None,
            containment_action: None,
        };
        svc.reconcile(cand.clone()).unwrap();
        svc.apply(KernelControlCommand::Shadow).unwrap();
        svc.apply(KernelControlCommand::PrepareHandoff).unwrap();
        let permit = eliot_kernel_service::KernelActivationPermit {
            operation_id: PlatformHandle::new("op-c183").unwrap(),
            candidate_binding_digest: cand.compute_digest().unwrap(),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: PlatformHandle::new("txn-1").unwrap(),
            journal_sequence: 1,
            generation: ResourceGeneration::genesis(),
            authority_epoch: cand.kernel_epoch,
            activation_nonce: eliot_platform::KernelActivationNonce::new(
                PlatformHandle::new("a".repeat(64)).unwrap(),
            )
            .unwrap(),
        };
        svc.activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
            .unwrap();
        let ready = KernelReadyReceipt {
            activation_id: cand.activation_id.clone(),
            activation_operation_id: permit.operation_id.clone(),
            activation_nonce_digest: svc
                .activation_receipt()
                .unwrap()
                .activation_nonce_digest
                .clone(),
            process: eliot_kernel_service::ProcessObservation {
                process_id: PlatformHandle::new("pid:42:start:10").unwrap(),
                job_object_id: cand.job_object_id.clone(),
                state: eliot_runtime_contracts::ServiceProcessState::Ready,
                health: eliot_runtime_contracts::HealthVector::healthy(),
                evidence_refs: vec![PlatformHandle::new("ev1").unwrap()],
            },
            health: eliot_runtime_contracts::HealthVector::healthy(),
            evidence_refs: vec![PlatformHandle::new("ev1").unwrap()],
        };
        svc.publish_ready(ready).unwrap();
        cand
    };
    let peer = eliot_ipc::PeerIdentity::authenticated_for_test(
        eliot_ipc::ProcessBinding::from_observation(
            candidate.host_process.process_id,
            candidate.host_process.start_time_100ns,
            candidate.host_process.image_path.clone(),
        )
        .unwrap(),
        "S-1-5-18".to_owned(),
        "0".to_owned(),
    )
    .unwrap();
    assert_eq!(
        kernel.service.lock().unwrap().state(),
        KernelServiceState::Ready
    );
    let kernel = std::sync::Arc::new(kernel);
    let gate_kernel = std::sync::Arc::clone(&kernel);
    let holder = tokio::spawn(async move {
        let _guard = gate_kernel.store_rebind_gate.lock().await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        kernel.store_rebind_gate.try_lock().is_err(),
        "gate must be held by holder task"
    );
    let probe_request = KernelControlRequest {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id: PlatformHandle::new("probe-gate-1").unwrap(),
        sequence: 1,
        peer_process_id: candidate.host_process.process_id,
        generation: ResourceGeneration::genesis(),
        candidate: candidate.clone(),
        command: KernelControlCommand::ProbeReady,
        payload_digest: String::new(),
    }
    .with_computed_digest()
    .unwrap();
    let probe_fut = kernel.apply_control_request(probe_request, &peer, 1);
    let mut probe_fut = Box::pin(probe_fut);
    let timeout = tokio::time::sleep(std::time::Duration::from_millis(150));
    tokio::pin!(timeout);
    let blocked = tokio::select! {
        _ = &mut probe_fut => false,
        () = &mut timeout => true,
    };
    assert!(
        blocked,
        "ProbeReady must share store_rebind_gate and block while gate is held"
    );
    let _ = holder.await;
    let probe_result = probe_fut.await;
    assert!(
        probe_result.is_err(),
        "ProbeReady still fenced without Store gateway publication"
    );
    let operation_id = PlatformHandle::new("c183-rebind-1").unwrap();
    let candidate_digest = candidate.compute_digest().unwrap();
    let make_fence = |pid: u32, start: u64| {
        let mut h = Sha256::new();
        h.update(serde_json::to_vec(&requirement.state_fence).unwrap());
        h.update(ResourceGeneration::genesis().value().to_le_bytes());
        h.update(AuthorityEpoch::genesis().value().to_le_bytes());
        h.update(requirement.approved_artifact_hash.as_str().as_bytes());
        h.update(requirement.approved_config_hash.as_str().as_bytes());
        h.update(pid.to_le_bytes());
        h.update(start.to_le_bytes());
        h.update(r"C:\Eliot\store.exe".as_bytes());
        h.update(r"Local\Eliot-Store-test".as_bytes());
        h.update(candidate_digest.as_bytes());
        format!("{:x}", h.finalize())
    };
    let store_fence = make_fence(99, 199);
    let handoff = eliot_kernel_service::StoreRebindHandoff {
        operation_id: operation_id.clone(),
        request_digest: String::new(),
        requirement: requirement.clone(),
        process_binding: eliot_kernel_service::StoreProcessBinding {
            process: eliot_kernel_service::HostProcessBinding {
                process_id: 99,
                start_time_100ns: 199,
                image_path: r"C:\Eliot\store.exe".to_owned(),
            },
            job: PlatformHandle::new(r"Local\Eliot-Store-test").unwrap(),
        },
        candidate_binding_digest: candidate_digest.clone(),
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: store_fence.clone(),
    };
    let mut handoff = handoff;
    handoff.request_digest = handoff.canonical_request_digest().unwrap();
    let request_digest = handoff.request_digest.clone();
    let requirement_digest = {
        let b = serde_json::to_vec(&requirement).unwrap();
        format!("{:x}", Sha256::digest(b))
    };
    let pending = eliot_ors::StoreRebindReplayRecord {
        operation_id: eliot_ors::OperationIdentity::new(operation_id.as_str()).unwrap(),
        request_digest: request_digest.clone(),
        candidate_binding_digest: candidate_digest.clone(),
        store_fence: store_fence.clone(),
        requirement_digest: requirement_digest.clone(),
        process_id: 99,
        process_start_time_100ns: 199,
        process_image_path: r"C:\Eliot\store.exe".to_owned(),
        job_name: r"Local\Eliot-Store-test".to_owned(),
        generation: 1,
        authority_epoch: 1,
        state: eliot_ors::StoreRebindReplayState::Pending,
        receipt: None,
        commit_order: 0,
    };
    kernel
        .generation_gateway
        .ors
        .begin_store_rebind(&pending)
        .unwrap();
    {
        let mut svc = kernel.service.lock().unwrap();
        svc.rebind_store(&handoff, request_digest.clone()).unwrap();
        assert_eq!(svc.state(), KernelServiceState::Degraded);
        *kernel.store_handoff.lock().unwrap() = Some(eliot_kernel_service::StoreBootstrapHandoff {
            requirement: requirement.clone(),
            process_binding: handoff.process_binding.clone(),
        });
    }
    let query = eliot_kernel_service::StoreRebindQuery {
        operation_id: operation_id.clone(),
        request_digest: request_digest.clone(),
    };
    let reconcile_pending = KernelControlRequest {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id: PlatformHandle::new("reconcile-pending").unwrap(),
        sequence: 1,
        peer_process_id: candidate.host_process.process_id,
        generation: ResourceGeneration::genesis(),
        candidate: candidate.clone(),
        command: KernelControlCommand::ReconcileRebindStore(query.clone()),
        payload_digest: request_digest.clone(),
    }
    .with_computed_digest()
    .unwrap();
    let pending_result = kernel
        .apply_control_request(reconcile_pending, &peer, 1)
        .await;
    assert!(pending_result.is_ok());
    assert!(pending_result.unwrap().store_rebind_receipt.is_none());
    assert_eq!(
        kernel.service.lock().unwrap().state(),
        KernelServiceState::Ready
    );
    let aborted = kernel
        .generation_gateway
        .ors
        .load_store_rebind(
            &eliot_ors::OperationIdentity::new(operation_id.as_str()).unwrap(),
            &request_digest,
        )
        .unwrap();
    assert!(aborted.is_none());
    kernel
        .generation_gateway
        .ors
        .begin_store_rebind(&pending)
        .unwrap();
    {
        let mut svc = kernel.service.lock().unwrap();
        if svc.state() == KernelServiceState::Ready {
            let _ = svc.rebind_store(&handoff, request_digest.clone());
            *kernel.store_handoff.lock().unwrap() =
                Some(eliot_kernel_service::StoreBootstrapHandoff {
                    requirement: requirement.clone(),
                    process_binding: handoff.process_binding.clone(),
                });
        }
    }
    let committed = eliot_ors::StoreRebindReplayRecord {
        state: eliot_ors::StoreRebindReplayState::Committed,
        receipt: Some(request_digest.clone()),
        ..pending.clone()
    };
    kernel
        .generation_gateway
        .ors
        .persist_store_rebind(&committed)
        .unwrap();
    {
        let mut svc = kernel.service.lock().unwrap();
        let _ = svc.commit_store_rebind();
    }
    let query2 = eliot_kernel_service::StoreRebindQuery {
        operation_id: operation_id.clone(),
        request_digest: request_digest.clone(),
    };
    let reconcile_committed = KernelControlRequest {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id: PlatformHandle::new("reconcile-committed").unwrap(),
        sequence: 1,
        peer_process_id: candidate.host_process.process_id,
        generation: ResourceGeneration::genesis(),
        candidate: candidate.clone(),
        command: KernelControlCommand::ReconcileRebindStore(query2),
        payload_digest: request_digest.clone(),
    }
    .with_computed_digest()
    .unwrap();
    let committed_result = kernel
        .apply_control_request(reconcile_committed, &peer, 1)
        .await;
    assert!(
        committed_result.is_err(),
        "publication not yet drained: gateway missing so ReconcileRebindStore must stay fenced"
    );
    {
        let svc = kernel.service.lock().unwrap();
        assert!(svc.store_rebind_receipt().is_some());
        assert_eq!(svc.state(), KernelServiceState::Degraded);
    }
    let activation = {
        let svc = kernel.service.lock().unwrap();
        svc.activation_receipt().unwrap().clone()
    };
    let fresh = KernelReadyReceipt {
        activation_id: candidate.activation_id.clone(),
        activation_operation_id: activation.operation_id.clone(),
        activation_nonce_digest: activation.activation_nonce_digest.clone(),
        process: eliot_kernel_service::ProcessObservation {
            process_id: PlatformHandle::new("pid:42:start:10").unwrap(),
            job_object_id: candidate.job_object_id.clone(),
            state: eliot_runtime_contracts::ServiceProcessState::Ready,
            health: eliot_runtime_contracts::HealthVector::healthy(),
            evidence_refs: vec![PlatformHandle::new("ev1").unwrap()],
        },
        health: eliot_runtime_contracts::HealthVector::healthy(),
        evidence_refs: vec![PlatformHandle::new("ev-fresh").unwrap()],
    };
    let probe_ready_after = KernelControlRequest {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id: PlatformHandle::new("probe-after-commit").unwrap(),
        sequence: 1,
        peer_process_id: candidate.host_process.process_id,
        generation: ResourceGeneration::genesis(),
        candidate: candidate.clone(),
        command: KernelControlCommand::ProbeReady,
        payload_digest: String::new(),
    }
    .with_computed_digest()
    .unwrap();
    let still_fenced = kernel
        .apply_control_request(probe_ready_after, &peer, 1)
        .await;
    assert!(
        still_fenced.is_err(),
        "ProbeReady must remain fenced until fresh proof with exact committed publication"
    );
    {
        let mut svc = kernel.service.lock().unwrap();
        let second = svc.publish_ready(fresh.clone());
        assert!(second.is_ok() || svc.state() == KernelServiceState::Degraded);
    }
    let replay_probe = KernelControlRequest {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id: PlatformHandle::new("probe-replay").unwrap(),
        sequence: 1,
        peer_process_id: candidate.host_process.process_id,
        generation: ResourceGeneration::genesis(),
        candidate: candidate.clone(),
        command: KernelControlCommand::ProbeReady,
        payload_digest: String::new(),
    }
    .with_computed_digest()
    .unwrap();
    let gate_before_replay = kernel.store_rebind_gate.lock().await;
    let replay_fut = kernel.apply_control_request(replay_probe, &peer, 1);
    let mut replay_fut = Box::pin(replay_fut);
    let replay_timeout = tokio::time::sleep(std::time::Duration::from_millis(80));
    tokio::pin!(replay_timeout);
    let replay_blocked = tokio::select! {
        _ = &mut replay_fut => false,
        () = &mut replay_timeout => true,
    };
    assert!(
        replay_blocked,
        "replayed ProbeReady must also share store_rebind_gate"
    );
    drop(gate_before_replay);
    let _ = replay_fut.await;
    let _ = std::fs::remove_dir_all(dir);
}
