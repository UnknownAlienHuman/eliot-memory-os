//! Successful-open backup-dispatch preparation fixture (issue #958).
//!
//! The directory-only `prepare_isolated_destination` port is proved by the
//! `backup_preparation` integration suite. These cases prove the ADMITTED
//! dispatch port: [`crate::HostComposition::backup_dispatch_prepare`] runs
//! caller authentication, owner-evidence inspection, the owner-bound
//! configuration projection and the delegated preparation against a real
//! seeded installation registry on a disposable SystemService-shaped contour.
//!
//! The contour is SystemService-shaped (never PortableDev: a portable contour
//! retains no isolated restore root outside the preparation source, so
//! `resolve_owner_staging_parent` refuses it by contract) under a
//! thread-local `override_protected_root` pin over a unique temp case root
//! (the `real_windows_isolated_root_preparation_and_cleanup` precedent), so
//! no elevation and no production root are touched. Every identity the
//! preparation binds (installation key, generation, digests, digests of the
//! roots) is derived inside the case, never invented: requests copy the
//! owner-issued values back out of the inspected evidence.

use super::*;
use eliot_installation::{InstallationEpoch, RuntimeStateRoots};
use eliot_platform_windows::test_support::override_protected_root;
use std::path::{Path, PathBuf};

/// One disposable SystemService-shaped contour for a dispatch case.
struct DispatchContour {
    /// Temp case root, pinned as the protected-root override while alive.
    case_root: PathBuf,
    /// `override_protected_root` guard; dropped last.
    _override: eliot_platform_windows::test_support::ProtectedRootOverride,
    /// Owner topology for this case (SystemService-shaped, temp-anchored).
    roots: RuntimeStateRoots,
    /// Seeded source manifest (active generation after seeding).
    manifest: eliot_installation::CandidateManifest,
    /// Installation identity string (epoch installation handle).
    installation: String,
    /// Lowercase SHA-256 installation key (root leaf name).
    installation_key: String,
    /// Redb registry file (fixed `<host>\installation-registry.redb` child).
    registry_file: PathBuf,
    /// Host journal file for the composition epoch.
    journal_file: PathBuf,
    /// Owner-issued isolated restore area (created on disk).
    staging_parent: PathBuf,
    /// Transaction/plan handles bound into the seed approval.
    transaction_id: String,
    plan_digest: String,
}

fn dispatch_handle(value: impl Into<String>) -> eliot_installation::PlatformHandle {
    eliot_installation::PlatformHandle::new(value.into()).unwrap_or_else(|_| unreachable!())
}

fn dispatch_sha256(text: &str) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(text.as_bytes()))
}

/// Mirror of the owner's digest-bound roots serialization: the digest covers
/// the ten topology fields in contract order as canonical JSON. The shape is
/// dictated by `RuntimeStateRoots::validate` (digest mismatch refuses), so
/// this helper reproduces that exact projection rather than inventing one.
#[derive(serde::Serialize)]
struct UnsignedDispatchRoots<'a> {
    profile: eliot_installation::InstallationProfile,
    profile_anchor_root: &'a eliot_installation::PlatformHandle,
    installation_root: &'a eliot_installation::PlatformHandle,
    host_state_root: &'a eliot_installation::PlatformHandle,
    kernel_ors_root: &'a eliot_installation::PlatformHandle,
    kernel_work_root: &'a eliot_installation::PlatformHandle,
    store_data_root: &'a eliot_installation::PlatformHandle,
    store_work_root: &'a eliot_installation::PlatformHandle,
    store_temp_root: &'a eliot_installation::PlatformHandle,
    watchdog_state_root: &'a eliot_installation::PlatformHandle,
}

fn dispatch_roots_digest(roots: &RuntimeStateRoots) -> eliot_installation::PlatformHandle {
    use sha2::Digest as _;
    let bytes = serde_json::to_vec(&UnsignedDispatchRoots {
        profile: roots.profile,
        profile_anchor_root: &roots.profile_anchor_root,
        installation_root: &roots.installation_root,
        host_state_root: &roots.host_state_root,
        kernel_ors_root: &roots.kernel_ors_root,
        kernel_work_root: &roots.kernel_work_root,
        store_data_root: &roots.store_data_root,
        store_work_root: &roots.store_work_root,
        store_temp_root: &roots.store_temp_root,
        watchdog_state_root: &roots.watchdog_state_root,
    })
    .unwrap_or_else(|_| unreachable!());
    dispatch_handle(format!("{:x}", sha2::Sha256::digest(&bytes)))
}

/// Builds the SystemService-shaped roots for one case: anchor is the case
/// root itself, the installation leaf is `Eliot\installations\<key>` (the
/// exact suffix `validate_installation_host_root` demands), and every fixed
/// runtime child hangs below it. No OS anchor is consulted: the anchor check
/// lives in the `derive_*` constructors, while every VALIDATION rule the
/// preparation enforces (`validate`, host-root suffix, digest) is satisfied.
fn dispatch_roots(case_root: &Path, key: &str) -> RuntimeStateRoots {
    let anchor = dispatch_handle(case_root.to_string_lossy().into_owned());
    let installation = dispatch_handle(format!(
        "{}\\Eliot\\installations\\{key}",
        case_root.to_string_lossy()
    ));
    let installation_str = installation.as_str().to_owned();
    let child = |leaf: &str| dispatch_handle(format!("{installation_str}\\{leaf}"));
    let mut roots = RuntimeStateRoots {
        profile: eliot_installation::InstallationProfile::SystemService,
        profile_anchor_root: anchor,
        installation_root: installation,
        host_state_root: child("host"),
        kernel_ors_root: child("kernel\\state"),
        kernel_work_root: child("kernel\\work"),
        store_data_root: child("store\\data"),
        store_work_root: child("store\\work"),
        store_temp_root: child("store\\tmp"),
        watchdog_state_root: child("watchdog"),
        roots_digest: dispatch_handle("0".repeat(64)),
    };
    roots.roots_digest = dispatch_roots_digest(&roots);
    roots
        .validate()
        .expect("case roots follow the fixed runtime topology");
    roots
}

/// Builds the seeded source manifest for one case: the exact
/// `liveness_manifest_with_distinct_store_digests` shape (which passes
/// `manifest.validate`), re-anchored onto the case contour with a
/// SystemService profile. Only the profile, the roots, the epoch and the
/// path-anchored fields differ; every digest rule keeps the proven binding.
fn dispatch_manifest(
    roots: &RuntimeStateRoots,
    installation: &str,
    generation_name: &str,
    case_root: &Path,
    case_bin: &Path,
) -> eliot_installation::CandidateManifest {
    use eliot_installation::InstallationProfile;
    let path = |name: &str| dispatch_handle(case_bin.join(name).to_string_lossy().into_owned());
    let generation = dispatch_handle(generation_name);
    let kernel_digest = dispatch_handle("a".repeat(64));
    let bridge_digest = dispatch_handle("b".repeat(64));
    let provider_digest = dispatch_handle("d".repeat(64));
    let config_digest = dispatch_handle("c".repeat(64));
    let config_path = path("generation.json");
    let bootstrap_path = path("store-bootstrap.json");
    let authority_path = path("authority.json");
    let bridge_path = path("eliot-store-surreal.exe");
    let provider_path = path("surreal.exe");
    let host_path = path("eliot-host.exe");
    let user_broker_file = case_bin.join("eliot-user-broker.exe");
    let user_broker_path = path("eliot-user-broker.exe");
    let user_broker_bytes = b"approved-user-broker-fixture-958";
    std::fs::write(&user_broker_file, user_broker_bytes).unwrap_or_else(|_| unreachable!());
    use sha2::Digest as _;
    let user_broker_digest =
        dispatch_handle(format!("{:x}", sha2::Sha256::digest(user_broker_bytes)));
    // I3.1 SystemService table: the durable-data root is `<anchor>\Eliot`
    // (the installer-owned state contour the per-installation runtime tree
    // sits strictly below), while binaries and user config/cache keep the
    // proven liveness layout re-anchored onto the case root.
    let anchor_eliot = case_root
        .join("Eliot")
        .to_string_lossy()
        .into_owned();
    // The I3.1 user root is a sibling of the durable contour (production:
    // `%LocalAppData%\Eliot` beside `%ProgramData%\Eliot`), so it must not
    // sit under the durable root the separation rule compares it against.
    let user_root = case_root
        .join("user")
        .to_string_lossy()
        .into_owned();
    let profile_governed_roots = eliot_installation::InstallationRoots {
        binding_version: eliot_installation::INSTALLATION_ROOT_BINDING_VERSION,
        immutable_binaries: case_bin
            .join("eliot")
            .join("test-version")
            .to_string_lossy()
            .into_owned(),
        durable_data: anchor_eliot,
        user_config: user_root.clone(),
        user_cache: user_root,
        runtime_state_roots: roots.clone(),
    };
    let lineage = dispatch_handle(format!("lineage:{installation}"));
    let epoch = |seq: u64| {
        eliot_contracts::EpochId::new(
            eliot_host_state::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .unwrap_or_else(|_| unreachable!()),
            std::num::NonZeroU64::new(seq).unwrap_or_else(|| unreachable!()),
        )
        .unwrap_or_else(|_| unreachable!())
    };
    let mut runtime_launch = eliot_installation::RuntimeLaunchDescriptor {
        profile: InstallationProfile::SystemService,
        profile_component: dispatch_handle("eliot"),
        profile_version: dispatch_handle("test-version"),
        profile_installation_key: Some(dispatch_handle(
            roots
                .installation_root
                .as_str()
                .rsplit('\\')
                .next()
                .unwrap_or_else(|| unreachable!()),
        )),
        profile_governed_roots,
        portable_root: None,
        installation_epoch: InstallationEpoch {
            installation: dispatch_handle(installation),
            lineage_id: lineage,
            sequence: 1,
        },
        generation: generation.clone(),
        authority_generation: eliot_contracts::ResourceGeneration::genesis(),
        authority_state_fence: eliot_contracts::StateFence::new(
            epoch(1),
            eliot_contracts::ResourceGeneration::genesis(),
        ),
        supervision_authority: eliot_installation::SupervisionAuthorityBinding::Provisioned {
            authority: Box::new(test_provisioned_supervision_authority(
                installation,
                generation_name,
                eliot_contracts::ResourceGeneration::genesis(),
            )),
        },
        authority_descriptor_path: authority_path.clone(),
        authority_descriptor_digest: dispatch_handle("9".repeat(64)),
        runtime_state_roots: roots.clone(),
        kernel_work_root: roots.kernel_work_root.clone(),
        kernel_artifact_digest: kernel_digest.clone(),
        eliotd_executable_path: path("eliotd.exe"),
        eliotd_artifact_digest: dispatch_handle("e".repeat(64)),
        eliotd_config_path: path("eliotd-governor.json"),
        eliotd_config_digest: dispatch_handle("2".repeat(64)),
        protected_snapshot_digest: dispatch_handle("a".repeat(64)),
        eliotd_descriptor_path: path("eliotd.json"),
        eliotd_descriptor_digest: dispatch_handle("f".repeat(64)),
        eliotd_launch_nonce: dispatch_handle(format!("eliotd:{}", "1".repeat(32))),
        store_config_path: config_path.clone(),
        store_credential_target: dispatch_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
        store_bridge_executable_path: bridge_path.clone(),
        store_bridge_artifact_digest: bridge_digest.clone(),
        store_bootstrap_descriptor_path: bootstrap_path.clone(),
        store_bootstrap_descriptor_digest: dispatch_handle("8".repeat(64)),
        canonical_store_executable_path: provider_path.clone(),
        canonical_store_artifact_digest: provider_digest.clone(),
        kernel_arguments: vec![
            dispatch_handle("--work-root"),
            roots.kernel_work_root.clone(),
            dispatch_handle("--store-bootstrap"),
            bootstrap_path,
            dispatch_handle("--store-bootstrap-sha256"),
            dispatch_handle("8".repeat(64)),
            dispatch_handle("--authority-descriptor"),
            authority_path,
            dispatch_handle("--authority-descriptor-sha256"),
            dispatch_handle("9".repeat(64)),
            dispatch_handle("--kernel-artifact-sha256"),
            kernel_digest.clone(),
            dispatch_handle("--doctor-artifact-sha256"),
            dispatch_handle("b".repeat(64)),
            dispatch_handle("--testd-artifact-sha256"),
            dispatch_handle("c".repeat(64)),
            dispatch_handle("--native-worker-artifact-sha256"),
            dispatch_handle("d".repeat(64)),
            dispatch_handle("--user-broker-executable"),
            user_broker_path.clone(),
            dispatch_handle("--user-broker-artifact-sha256"),
            user_broker_digest.clone(),
            dispatch_handle("--eliotd-descriptor"),
            path("eliotd.json"),
            dispatch_handle("--eliotd-descriptor-sha256"),
            dispatch_handle("f".repeat(64)),
        ],
        store_bridge_arguments: vec![
            dispatch_handle("--config"),
            config_path.clone(),
        ],
        canonical_store_arguments: vec![
            dispatch_handle("start"),
            dispatch_handle("--no-banner"),
            dispatch_handle("--bind"),
            dispatch_handle("127.0.0.1:8000"),
            dispatch_handle("--temporary-directory"),
            roots.store_temp_root.clone(),
            dispatch_handle("--log-file-enabled"),
            dispatch_handle("--log-file-path"),
            roots.store_work_root.clone(),
            dispatch_handle("--log-file-name"),
            dispatch_handle("surrealdb.log"),
            dispatch_handle(format!(
                "surrealkv://{}",
                roots.store_data_root.as_str().replace('\\', "/")
            )),
        ],
        host_executable_path: host_path.clone(),
        host_artifact_digest: dispatch_handle("e".repeat(64)),
        watchdog_executable_path: path("eliot-watchdog.exe"),
        watchdog_artifact_digest: dispatch_handle("7".repeat(64)),
        doctor_artifact_digest: dispatch_handle("b".repeat(64)),
        testd_artifact_digest: dispatch_handle("c".repeat(64)),
        native_worker_artifact_digest: dispatch_handle("d".repeat(64)),
        user_broker_artifact_digest: user_broker_digest.clone(),
        wasm_host_artifact_digest: dispatch_handle("f".repeat(64)),
        doctor_executable_path: path("eliot-doctor.exe"),
        testd_executable_path: path("eliot-testd.exe"),
        native_worker_executable_path: path("eliot-native-worker.exe"),
        user_broker_executable_path: user_broker_path,
        wasm_host_executable_path: path("eliot-wasm-host.exe"),
        descriptor_digest: dispatch_handle("0".repeat(64)),
    };
    runtime_launch = match runtime_launch.with_computed_digest() {
        Ok(launch) => launch,
        Err(error) => panic!("case launch descriptor rejected: {error:?}"),
    };
    let manifest = eliot_installation::CandidateManifest {
        generation,
        components: vec![
            dispatch_handle("component:kernel"),
            dispatch_handle("component:store"),
        ],
        kernel_artifact_digest: kernel_digest,
        store_bridge_artifact_digest: bridge_digest,
        canonical_store_artifact_digest: provider_digest,
        host_artifact_digest: dispatch_handle("e".repeat(64)),
        doctor_artifact_digest: dispatch_handle("b".repeat(64)),
        testd_artifact_digest: dispatch_handle("c".repeat(64)),
        native_worker_artifact_digest: dispatch_handle("d".repeat(64)),
        user_broker_artifact_digest: user_broker_digest,
        wasm_host_artifact_digest: dispatch_handle("f".repeat(64)),
        kernel_executable_path: path("eliot-kernel.exe"),
        store_bridge_executable_path: bridge_path,
        canonical_store_executable_path: provider_path,
        host_executable_path: host_path,
        doctor_executable_path: path("eliot-doctor.exe"),
        testd_executable_path: path("eliot-testd.exe"),
        native_worker_executable_path: path("eliot-native-worker.exe"),
        user_broker_executable_path: path("eliot-user-broker.exe"),
        wasm_host_executable_path: path("eliot-wasm-host.exe"),
        config_path,
        dependency_closure_refs: vec![dispatch_handle("evidence:dependency-closure")],
        license_refs: vec![dispatch_handle("evidence:licenses")],
        config_digest,
        store_credential_target: dispatch_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
        supervision_key_slot: dispatch_handle("6".repeat(64)),
        signature_ref: dispatch_handle("evidence:signature"),
        runtime_state_roots_digest: roots.roots_digest.clone(),
        runtime_launch,
    };
    manifest
        .validate()
        .expect("case manifest validates before seeding");
    manifest
}

/// Builds the activation commit fence for one case manifest: the exact
/// `test_commit_fence` shape (which passes `validate_against_manifest`),
/// bound to this case's manifest digest and supervision authority.
fn dispatch_commit_fence(
    manifest: &eliot_installation::CandidateManifest,
    installation: &str,
) -> eliot_installation::ActivationCommitFence {
    let runtime = &manifest.runtime_launch;
    let manifest_digest = manifest
        .compute_digest()
        .expect("case manifest digest computes");
    eliot_installation::ActivationCommitFence {
        generation: manifest.generation.clone(),
        config_digest: manifest.config_digest.clone(),
        materialized_config_digest: manifest.config_digest.clone(),
        phase_b_live_binding: Some(eliot_installation::PhaseBLiveBinding {
            manifest_digest,
            authority_descriptor_digest: dispatch_handle("1".repeat(64)),
            store_bootstrap_descriptor_digest: dispatch_handle("2".repeat(64)),
            config_file_digest: manifest.config_digest.clone(),
            eliotd_descriptor_digest: dispatch_handle("3".repeat(64)),
            semantic_config_hash: dispatch_handle("5".repeat(64)),
            host_epoch_lineage: dispatch_handle(format!("lineage:{installation}")),
            host_epoch_sequence: 1,
            host_process_nonce_digest: dispatch_handle("4".repeat(64)),
            receipt_digest: dispatch_handle("4".repeat(64)),
            effect_id: dispatch_handle("phase-b-effect-958"),
            credential_receipt_digest: dispatch_handle("9".repeat(64)),
            request_digest: dispatch_handle("6".repeat(64)),
            host_owner_epoch: dispatch_handle("host-owner:958-dispatch"),
            host_process_identity: dispatch_handle("7".repeat(64)),
            public_receipt_digest: dispatch_handle("8".repeat(64)),
            provisioned_supervision_authority: test_provisioned_supervision_authority(
                installation,
                manifest.generation.as_str(),
                runtime.authority_generation,
            ),
            agent_bridge: None,
            user_broker: None,
        }),
        authority_generation: runtime.authority_generation,
        authority_state_fence: runtime.authority_state_fence.clone(),
        active_kernel_record_checksum: dispatch_handle("a".repeat(64)),
        probe_request_digest: dispatch_handle("b".repeat(64)),
        ready_receipt_digest: dispatch_handle("c".repeat(64)),
        store_proof_fence: dispatch_handle("store-proof:958-dispatch"),
        candidate_binding_digest: dispatch_handle("d".repeat(64)),
        store_requirement_digest: dispatch_handle("e".repeat(64)),
        readiness_sequence: 1,
        readiness_journal_checksum: dispatch_handle("f".repeat(64)),
    }
}

/// Sets up one disposable dispatch contour: temp case root, SystemService
/// roots, seeded registry with an active generation, an initialised ORS
/// store, the Host journal epoch and the struct-literal composition (the
/// `journal_tests` builder pattern: in-crate code sees the private fields,
/// so no design decision is left to guesswork).
fn dispatch_contour(case: &str) -> (DispatchContour, HostComposition) {
    let unique = format!(
        "{case}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    );
    let case_root = std::env::temp_dir().join(format!("eliot-958-dispatch-{unique}"));
    std::fs::create_dir_all(&case_root).expect("case root");
    let key = dispatch_sha256(&format!("958-dispatch-installation-{unique}"));
    let roots = dispatch_roots(&case_root, &key);
    for root in [
        &roots.host_state_root,
        &roots.kernel_ors_root,
        &roots.kernel_work_root,
        &roots.store_data_root,
        &roots.store_work_root,
        &roots.store_temp_root,
        &roots.watchdog_state_root,
    ] {
        std::fs::create_dir_all(Path::new(root.as_str())).expect("case runtime child");
    }
    // Binaries sit beside the durable contour, never under it: production
    // keeps immutable images under `%ProgramFiles%` while durable state
    // lives under `%ProgramData%`, and the separation rule refuses overlap.
    let bin = case_root.join("bin");
    std::fs::create_dir_all(&bin).expect("case binaries");
    let staging_parent = case_root
        .join("Eliot")
        .join(eliot_platform_windows::ISOLATED_RESTORE_ROOT_DIR);
    std::fs::create_dir_all(&staging_parent).expect("case isolated restore area");
    let pinned = override_protected_root(&case_root);
    let installation = format!("installation:958-dispatch-{unique}");
    let manifest = dispatch_manifest(
        &roots,
        &installation,
        &format!("generation-958-dispatch-{case}"),
        &case_root,
        &bin,
    );
    let owner_lease = HostOwnerLease::acquire(&dispatch_handle(installation.clone()))
        .expect("case owner lease");
    let fence = dispatch_commit_fence(&manifest, &installation);
    let transaction_id = dispatch_handle(format!("transaction:958-dispatch-{unique}"));
    let plan_digest = dispatch_handle(dispatch_sha256(&format!("plan:958-dispatch-{unique}")));
    let registry_file = Path::new(roots.host_state_root.as_str()).join("installation-registry.redb");
    let store = eliot_installation::RedbInstallationRegistry::open_test_support(&registry_file)
        .expect("case registry store");
    store
        .seed_active_generation_for_test_support(
            &owner_lease.activation_capability(),
            &manifest,
            &transaction_id,
            &plan_digest,
            &fence,
        )
        .expect("case active generation");
    let registry = store.load().expect("case registry projection");
    drop(store);
    let ors_file =
        Path::new(roots.kernel_ors_root.as_str()).join("kernel-ors.redb");
    drop(
        eliot_ors::RedbRecoveryStore::open(&ors_file).expect("case ORS store"),
    );
    let journal_file = case_root.join("host-journal.redb");
    let (journal, host, activation_generation, activation_id, _) =
        super::host_epoch_reopen::open_test_support_epoch(
            &journal_file,
            dispatch_handle(installation.clone()),
            None,
            None,
        )
        .expect("case host epoch");
    let launch_options = HostLaunchOptions {
        config_descriptor_path: PathBuf::from(
            manifest
                .runtime_launch
                .authority_descriptor_path
                .as_str(),
        ),
        config_descriptor_digest: phase_b_scm_selector(
            &manifest.runtime_launch.authority_descriptor_digest,
        )
        .expect("case descriptor selector"),
        installation: dispatch_handle(installation.clone()),
        transaction_plan_generation: manifest.runtime_launch.authority_generation.value(),
        host_state_root: PathBuf::from(manifest.runtime_launch.runtime_state_roots.host_state_root.as_str()),
        registration_nonce: None,
    };
    let jobs =
        HostJobBranches::new_test_support(&host).expect("case job branches");
    let composition = HostComposition {
        store_rebind_boundary: HostStoreRebindProductionBoundary,
        runtime_control_boundary: HostRuntimeControlProductionBoundary,
        journal,
        registry_host_root: PathBuf::from(roots.host_state_root.as_str()),
        test_registry_file: Some(registry_file.clone()),
        registry,
        launch_options,
        host,
        activation_generation,
        activation_id,
        running: true,
        jobs,
        readiness_gate: HostReadinessGate::with_cadence(ReadinessCadence::default()),
        phase_b: None,
        watchdog_start_recovery: None,
        runtime_restarts: std::collections::HashMap::new(),
        runtime_control_queue: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::VecDeque::new(),
        )),
        user_automation_execution_queue: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::VecDeque::new(),
        )),
        backup_dispatch_queue: crate::HostBackupDispatchQueue::bounded(),
        store_recovery_startup_fence: StoreRecoveryStartupFence::Clear,
        active_phase_b_rebind_recovery: ActivePhaseBRebindRecoveryKind::None,
        owner_lease,
        pending_record: None,
        durable_finalized: false,
        owner_released: false,
        shutdown_failed: false,
    };
    let contour = DispatchContour {
        case_root,
        _override: pinned,
        roots,
        manifest,
        installation,
        installation_key: key,
        registry_file,
        journal_file,
        staging_parent,
        transaction_id: transaction_id.as_str().to_owned(),
        plan_digest: plan_digest.as_str().to_owned(),
    };
    (contour, composition)
}

/// Removes one case contour. The composition (journal backend), the evidence
/// leases and the override guard must already be dropped: redb files cannot
/// be removed while a Database handle is open.
fn release_contour(contour: DispatchContour) {
    let _ = std::fs::remove_dir_all(&contour.case_root);
}

/// First staging proof: the disposable contour inspects into real owner
/// evidence bound to the seeded active generation, with the registry
/// revision fence agreeing between the evidence and the composition.
#[test]
fn dispatch_contour_inspects_owner_evidence() {
    let (contour, composition) = dispatch_contour("inspect");
    let evidence =
        crate::backup_preparation::OwnerEvidence::inspect(Path::new(
            contour.roots.host_state_root.as_str(),
        ))
        .expect("contour inspects");
    assert_eq!(
        evidence.approved().manifest.generation.as_str(),
        contour.manifest.generation.as_str(),
        "evidence binds the seeded active generation"
    );
    assert_eq!(
        evidence.revision(),
        composition.registry.revision(),
        "no registry movement between inspection and composition load"
    );
    assert_eq!(
        evidence.runtime_roots().profile,
        eliot_installation::InstallationProfile::SystemService,
        "contour carries the production open profile"
    );
    drop(composition);
    drop(evidence);
    release_contour(contour);
}
