#![allow(clippy::expect_used)]
//! Successful-open backup-dispatch preparation fixture (issue #958).
//! TEST ALLOW: `.expect` below is the named fixture-construction expectation,
//! mirroring the sibling `backup_preparation` integration suite (whose first
//! line carries the same allow). Production code in this branch adds no allows.
//!
//! The directory-only `prepare_isolated_destination` port is proved by the
//! `backup_preparation` integration suite. These cases prove the ADMITTED
//! dispatch port: [`crate::HostComposition::backup_dispatch_prepare`] runs
//! caller authentication, owner-evidence inspection, the owner-bound
//! configuration projection and the delegated preparation against a real
//! seeded installation registry on a disposable SystemService-shaped contour.
//!
//! The contour is `SystemService`-shaped (never `PortableDev`: a portable contour
//! retains no isolated restore root outside the preparation source, so
//! `resolve_owner_staging_parent` refuses it by contract) under a
//! thread-local `override_protected_root` pin over a unique temp case root
//! (the `real_windows_isolated_root_preparation_and_cleanup` precedent), so
//! no elevation and no production root are touched. Every identity the
//! preparation binds (installation key, generation, digests, digests of the
//! roots) is derived inside the case, never invented: requests copy the
//! owner-issued values back out of the inspected evidence.

use super::*;
use eliot_installation::RuntimeStateRoots;
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
    dispatch_roots_for_profile(
        case_root,
        key,
        eliot_installation::InstallationProfile::SystemService,
    )
}

/// Builds the profiled roots for one case under an already-proved anchor.
/// `SystemService` refines `<anchor>\Eliot` directly while `UserMode` refines
/// the I3.1 durable-data sibling (`<anchor>\Eliot\data`): the suffix each
/// profile's `validate` demands (F1-F4, issue #958-continue), so a `UserMode`
/// contour is a `UserMode` installation, never a `SystemService`-shaped path
/// under the wrong anchor.
fn dispatch_roots_for_profile(
    case_root: &Path,
    key: &str,
    profile: eliot_installation::InstallationProfile,
) -> RuntimeStateRoots {
    let anchor = dispatch_handle(case_root.to_string_lossy().into_owned());
    let installation = dispatch_handle(match profile {
        eliot_installation::InstallationProfile::UserMode => format!(
            "{}\\Eliot\\data\\installations\\{key}",
            case_root.to_string_lossy()
        ),
        _ => format!(
            "{}\\Eliot\\installations\\{key}",
            case_root.to_string_lossy()
        ),
    });
    let installation_str = installation.as_str().to_owned();
    let child = |leaf: &str| dispatch_handle(format!("{installation_str}\\{leaf}"));
    let mut roots = RuntimeStateRoots {
        profile,
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
/// `SystemService` profile. Only the profile, the roots, the epoch and the
/// path-anchored fields differ; every digest rule keeps the proven binding.
fn dispatch_manifest(
    roots: &RuntimeStateRoots,
    installation: &str,
    generation_name: &str,
    case_root: &Path,
    case_bin: &Path,
) -> eliot_installation::CandidateManifest {
    dispatch_manifest_for_profile(
        roots,
        installation,
        generation_name,
        case_root,
        case_bin,
        eliot_installation::InstallationProfile::SystemService,
    )
}

/// Builds the seeded source manifest for one case under the given profile:
/// the roots, the launch profile and the governed-roots sibling layout all
/// carry that profile, so a `UserMode` manifest binds the I3.1 durable-data
/// sibling instead of the `SystemService` contour.
fn dispatch_manifest_for_profile(
    roots: &RuntimeStateRoots,
    installation: &str,
    generation_name: &str,
    case_root: &Path,
    case_bin: &Path,
    profile: eliot_installation::InstallationProfile,
) -> eliot_installation::CandidateManifest {
    ManifestSeed {
        roots,
        installation,
        generation_name,
        case_root,
        case_bin,
        profile,
    }
    .manifest()
}

/// Inputs for one seeded case manifest. The seed exists so the manifest
/// builder stays a composition of small honest helpers instead of one
/// 200-line literal: each method below builds one named part (paths, governed
/// roots, argument vectors, launch descriptor) and `manifest` assembles them.
struct ManifestSeed<'a> {
    roots: &'a RuntimeStateRoots,
    installation: &'a str,
    generation_name: &'a str,
    case_root: &'a Path,
    case_bin: &'a Path,
    profile: eliot_installation::InstallationProfile,
}

/// Every derived path and digest one case manifest binds.
struct ManifestPaths {
    generation: eliot_installation::PlatformHandle,
    kernel_digest: eliot_installation::PlatformHandle,
    bridge_digest: eliot_installation::PlatformHandle,
    provider_digest: eliot_installation::PlatformHandle,
    config_digest: eliot_installation::PlatformHandle,
    config_path: eliot_installation::PlatformHandle,
    bootstrap_path: eliot_installation::PlatformHandle,
    authority_path: eliot_installation::PlatformHandle,
    bridge_path: eliot_installation::PlatformHandle,
    provider_path: eliot_installation::PlatformHandle,
    host_path: eliot_installation::PlatformHandle,
    user_broker_path: eliot_installation::PlatformHandle,
    user_broker_digest: eliot_installation::PlatformHandle,
}

impl ManifestSeed<'_> {
    fn path(&self, name: &str) -> eliot_installation::PlatformHandle {
        dispatch_handle(self.case_bin.join(name).to_string_lossy().into_owned())
    }

    fn manifest_paths(&self) -> ManifestPaths {
        let user_broker_file = self.case_bin.join("eliot-user-broker.exe");
        let user_broker_bytes = b"approved-user-broker-fixture-958";
        std::fs::write(&user_broker_file, user_broker_bytes).unwrap_or_else(|_| unreachable!());
        ManifestPaths {
            generation: dispatch_handle(self.generation_name),
            kernel_digest: dispatch_handle("a".repeat(64)),
            bridge_digest: dispatch_handle("b".repeat(64)),
            provider_digest: dispatch_handle("d".repeat(64)),
            config_digest: dispatch_handle("c".repeat(64)),
            config_path: self.path("generation.json"),
            bootstrap_path: self.path("store-bootstrap.json"),
            authority_path: self.path("authority.json"),
            bridge_path: self.path("eliot-store-surreal.exe"),
            provider_path: self.path("surreal.exe"),
            host_path: self.path("eliot-host.exe"),
            user_broker_path: self.path("eliot-user-broker.exe"),
            user_broker_digest: {
                use sha2::Digest as _;
                dispatch_handle(format!("{:x}", sha2::Sha256::digest(user_broker_bytes)))
            },
        }
    }

    fn governed_roots(&self) -> eliot_installation::InstallationRoots {
        // I3.1 `SystemService` table: the durable-data root is
        // `<anchor>\Eliot` (the installer-owned state contour the
        // per-installation runtime tree sits strictly below), while binaries
        // and user config/cache keep the proven liveness layout re-anchored
        // onto the case root.
        //
        // I3.1 `UserMode` table: the durable-data root is the sibling
        // `<anchor>\Eliot\data` with config/cache beside it
        // (`<anchor>\Eliot\config`, `<anchor>\Eliot\cache`) — the exact
        // layout `validate_durable_runtime_join` demands, so the join
        // compares the installation root the F3 fix names.
        let anchor_eliot = self.case_root.join("Eliot").to_string_lossy().into_owned();
        // The I3.1 user root is a sibling of the durable contour
        // (production: `%LocalAppData%\Eliot` beside `%ProgramData%\Eliot`),
        // so it must not sit under the durable root the separation rule
        // compares it against.
        let (durable_data, user_root) = match self.profile {
            eliot_installation::InstallationProfile::UserMode => (
                self.case_root
                    .join("Eliot")
                    .join("data")
                    .to_string_lossy()
                    .into_owned(),
                anchor_eliot.clone(),
            ),
            _ => (
                anchor_eliot.clone(),
                self.case_root.join("user").to_string_lossy().into_owned(),
            ),
        };
        // `UserMode` pins the exact I3.1 sibling names; every other
        // profile keeps the proven liveness layout.
        let (user_config, user_cache) = match self.profile {
            eliot_installation::InstallationProfile::UserMode => (
                self.case_root
                    .join("Eliot")
                    .join("config")
                    .to_string_lossy()
                    .into_owned(),
                self.case_root
                    .join("Eliot")
                    .join("cache")
                    .to_string_lossy()
                    .into_owned(),
            ),
            _ => (user_root.clone(), user_root),
        };
        eliot_installation::InstallationRoots {
            binding_version: eliot_installation::INSTALLATION_ROOT_BINDING_VERSION,
            immutable_binaries: self
                .case_bin
                .join("eliot")
                .join("test-version")
                .to_string_lossy()
                .into_owned(),
            durable_data,
            user_config,
            user_cache,
            runtime_state_roots: self.roots.clone(),
        }
    }

    fn kernel_arguments(&self, paths: &ManifestPaths) -> Vec<eliot_installation::PlatformHandle> {
        vec![
            dispatch_handle("--work-root"),
            self.roots.kernel_work_root.clone(),
            dispatch_handle("--store-bootstrap"),
            paths.bootstrap_path.clone(),
            dispatch_handle("--store-bootstrap-sha256"),
            dispatch_handle("8".repeat(64)),
            dispatch_handle("--authority-descriptor"),
            paths.authority_path.clone(),
            dispatch_handle("--authority-descriptor-sha256"),
            dispatch_handle("9".repeat(64)),
            dispatch_handle("--kernel-artifact-sha256"),
            paths.kernel_digest.clone(),
            dispatch_handle("--doctor-artifact-sha256"),
            dispatch_handle("b".repeat(64)),
            dispatch_handle("--testd-artifact-sha256"),
            dispatch_handle("c".repeat(64)),
            dispatch_handle("--native-worker-artifact-sha256"),
            dispatch_handle("d".repeat(64)),
            dispatch_handle("--user-broker-executable"),
            paths.user_broker_path.clone(),
            dispatch_handle("--user-broker-artifact-sha256"),
            paths.user_broker_digest.clone(),
            dispatch_handle("--eliotd-descriptor"),
            self.path("eliotd.json"),
            dispatch_handle("--eliotd-descriptor-sha256"),
            dispatch_handle("f".repeat(64)),
        ]
    }

    fn store_arguments(&self) -> Vec<eliot_installation::PlatformHandle> {
        vec![
            dispatch_handle("start"),
            dispatch_handle("--no-banner"),
            dispatch_handle("--bind"),
            dispatch_handle("127.0.0.1:8000"),
            dispatch_handle("--temporary-directory"),
            self.roots.store_temp_root.clone(),
            dispatch_handle("--log-file-enabled"),
            dispatch_handle("--log-file-path"),
            self.roots.store_work_root.clone(),
            dispatch_handle("--log-file-name"),
            dispatch_handle("surrealdb.log"),
            dispatch_handle(format!(
                "surrealkv://{}",
                self.roots.store_data_root.as_str().replace('\\', "/")
            )),
        ]
    }

    fn runtime_launch(&self, paths: &ManifestPaths) -> eliot_installation::RuntimeLaunchDescriptor {
        let epoch = |seq: u64| {
            eliot_contracts::EpochId::new(
                eliot_host_state::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .unwrap_or_else(|_| unreachable!()),
                std::num::NonZeroU64::new(seq).unwrap_or_else(|| unreachable!()),
            )
            .unwrap_or_else(|_| unreachable!())
        };
        let lineage = dispatch_handle(format!("lineage:{}", self.installation));
        let launch = eliot_installation::RuntimeLaunchDescriptor {
            profile: self.profile,
            profile_component: dispatch_handle("eliot"),
            profile_version: dispatch_handle("test-version"),
            profile_installation_key: Some(dispatch_handle(
                self.roots
                    .installation_root
                    .as_str()
                    .rsplit('\\')
                    .next()
                    .unwrap_or_else(|| unreachable!()),
            )),
            profile_governed_roots: self.governed_roots(),
            portable_root: None,
            installation_epoch: eliot_installation::InstallationEpoch {
                installation: dispatch_handle(self.installation),
                lineage_id: lineage,
                sequence: 1,
            },
            generation: paths.generation.clone(),
            authority_generation: eliot_contracts::ResourceGeneration::genesis(),
            authority_state_fence: eliot_contracts::StateFence::new(
                epoch(1),
                eliot_contracts::ResourceGeneration::genesis(),
            ),
            supervision_authority: eliot_installation::SupervisionAuthorityBinding::Provisioned {
                authority: Box::new(test_provisioned_supervision_authority(
                    self.installation,
                    self.generation_name,
                    eliot_contracts::ResourceGeneration::genesis(),
                )),
            },
            authority_descriptor_path: paths.authority_path.clone(),
            authority_descriptor_digest: dispatch_handle("9".repeat(64)),
            runtime_state_roots: self.roots.clone(),
            kernel_work_root: self.roots.kernel_work_root.clone(),
            kernel_artifact_digest: paths.kernel_digest.clone(),
            eliotd_executable_path: self.path("eliotd.exe"),
            eliotd_artifact_digest: dispatch_handle("e".repeat(64)),
            eliotd_config_path: self.path("eliotd-governor.json"),
            eliotd_config_digest: dispatch_handle("2".repeat(64)),
            protected_snapshot_digest: dispatch_handle("a".repeat(64)),
            eliotd_descriptor_path: self.path("eliotd.json"),
            eliotd_descriptor_digest: dispatch_handle("f".repeat(64)),
            eliotd_launch_nonce: dispatch_handle(format!("eliotd:{}", "1".repeat(32))),
            store_config_path: paths.config_path.clone(),
            store_credential_target: dispatch_handle(
                "eliot/store/v1/0123456789abcdef0123456789abcdef",
            ),
            store_bridge_executable_path: paths.bridge_path.clone(),
            store_bridge_artifact_digest: paths.bridge_digest.clone(),
            store_bootstrap_descriptor_path: paths.bootstrap_path.clone(),
            store_bootstrap_descriptor_digest: dispatch_handle("8".repeat(64)),
            canonical_store_executable_path: paths.provider_path.clone(),
            canonical_store_artifact_digest: paths.provider_digest.clone(),
            kernel_arguments: self.kernel_arguments(paths),
            store_bridge_arguments: vec![dispatch_handle("--config"), paths.config_path.clone()],
            canonical_store_arguments: self.store_arguments(),
            host_executable_path: paths.host_path.clone(),
            host_artifact_digest: dispatch_handle("e".repeat(64)),
            watchdog_executable_path: self.path("eliot-watchdog.exe"),
            watchdog_artifact_digest: dispatch_handle("7".repeat(64)),
            doctor_artifact_digest: dispatch_handle("b".repeat(64)),
            testd_artifact_digest: dispatch_handle("c".repeat(64)),
            native_worker_artifact_digest: dispatch_handle("d".repeat(64)),
            user_broker_artifact_digest: paths.user_broker_digest.clone(),
            wasm_host_artifact_digest: dispatch_handle("f".repeat(64)),
            doctor_executable_path: self.path("eliot-doctor.exe"),
            testd_executable_path: self.path("eliot-testd.exe"),
            native_worker_executable_path: self.path("eliot-native-worker.exe"),
            user_broker_executable_path: paths.user_broker_path.clone(),
            wasm_host_executable_path: self.path("eliot-wasm-host.exe"),
            descriptor_digest: dispatch_handle("0".repeat(64)),
        };
        match launch.with_computed_digest() {
            Ok(launch) => launch,
            Err(error) => panic!("case launch descriptor rejected: {error:?}"),
        }
    }

    fn manifest(&self) -> eliot_installation::CandidateManifest {
        let paths = self.manifest_paths();
        let runtime_launch = self.runtime_launch(&paths);
        let manifest = eliot_installation::CandidateManifest {
            generation: paths.generation.clone(),
            components: vec![
                dispatch_handle("component:kernel"),
                dispatch_handle("component:store"),
            ],
            kernel_artifact_digest: paths.kernel_digest.clone(),
            store_bridge_artifact_digest: paths.bridge_digest.clone(),
            canonical_store_artifact_digest: paths.provider_digest.clone(),
            host_artifact_digest: dispatch_handle("e".repeat(64)),
            doctor_artifact_digest: dispatch_handle("b".repeat(64)),
            testd_artifact_digest: dispatch_handle("c".repeat(64)),
            native_worker_artifact_digest: dispatch_handle("d".repeat(64)),
            user_broker_artifact_digest: paths.user_broker_digest.clone(),
            wasm_host_artifact_digest: dispatch_handle("f".repeat(64)),
            kernel_executable_path: self.path("eliot-kernel.exe"),
            store_bridge_executable_path: paths.bridge_path.clone(),
            canonical_store_executable_path: paths.provider_path.clone(),
            host_executable_path: paths.host_path.clone(),
            doctor_executable_path: self.path("eliot-doctor.exe"),
            testd_executable_path: self.path("eliot-testd.exe"),
            native_worker_executable_path: self.path("eliot-native-worker.exe"),
            user_broker_executable_path: self.path("eliot-user-broker.exe"),
            wasm_host_executable_path: self.path("eliot-wasm-host.exe"),
            config_path: paths.config_path.clone(),
            dependency_closure_refs: vec![dispatch_handle("evidence:dependency-closure")],
            license_refs: vec![dispatch_handle("evidence:licenses")],
            config_digest: paths.config_digest.clone(),
            store_credential_target: dispatch_handle(
                "eliot/store/v1/0123456789abcdef0123456789abcdef",
            ),
            supervision_key_slot: dispatch_handle("6".repeat(64)),
            signature_ref: dispatch_handle("evidence:signature"),
            runtime_state_roots_digest: self.roots.roots_digest.clone(),
            runtime_launch,
        };
        manifest
            .validate()
            .expect("case manifest validates before seeding");
        manifest
    }
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

/// Sets up one disposable dispatch contour: temp case root, `SystemService`
/// roots, seeded registry with an active generation, an initialised ORS
/// store, the Host journal epoch and the struct-literal composition (the
/// `journal_tests` builder pattern: in-crate code sees the private fields,
/// so no design decision is left to guesswork).
/// Sets up one disposable dispatch contour: temp case root, `SystemService`
/// roots, seeded registry with an active generation, an initialised ORS
/// store, the Host journal epoch and the struct-literal composition (the
/// `journal_tests` builder pattern: in-crate code sees the private fields,
/// so no design decision is left to guesswork).
fn dispatch_contour(case: &str) -> (DispatchContour, HostComposition) {
    dispatch_contour_for_profile(case, eliot_installation::InstallationProfile::SystemService)
}

/// Sets up one disposable dispatch contour under the given profile. The
/// `SystemService` shape keeps the Host + Watchdog SCM approvals the
/// registry demands of that profile; `UserMode` seeds approval-free through
/// the same Pending stage/commit path (the two-approval rule is gated on
/// `SystemService`), so the committed row is the same installer-driven shape
/// minus the service registrations a user-mode activation never performs.
fn dispatch_contour_for_profile(
    case: &str,
    profile: eliot_installation::InstallationProfile,
) -> (DispatchContour, HostComposition) {
    let filesystem = contour_filesystem(case, profile);
    let seed = contour_seed_registry(&filesystem, case, profile);
    contour_apply_purge(&filesystem);
    contour_compose(filesystem, seed)
}

/// Temp filesystem one contour case owns: roots, binaries, restore area.
struct ContourFilesystem {
    unique: String,
    case_root: PathBuf,
    key: String,
    roots: RuntimeStateRoots,
    bin: PathBuf,
    staging_parent: PathBuf,
    pinned: eliot_platform_windows::test_support::ProtectedRootOverride,
}

/// Seeded installation state one contour case prepares against.
struct ContourSeed {
    installation: String,
    manifest: eliot_installation::CandidateManifest,
    owner_lease: HostOwnerLease,
    fence: eliot_installation::ActivationCommitFence,
    transaction_id: eliot_installation::PlatformHandle,
    plan_digest: eliot_installation::PlatformHandle,
    registry_file: PathBuf,
    registry: eliot_installation::ApprovedGenerationRegistry,
}

fn contour_filesystem(
    case: &str,
    profile: eliot_installation::InstallationProfile,
) -> ContourFilesystem {
    let unique = format!(
        "{case}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    );
    let case_root = std::env::temp_dir().join(format!("eliot-958-dispatch-{unique}"));
    std::fs::create_dir_all(&case_root).expect("case root");
    let key = dispatch_sha256(&format!("958-dispatch-installation-{unique}"));
    let roots = dispatch_roots_for_profile(&case_root, &key, profile);
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
    // The SCM approval issuer binds the canonical SCM configuration digest
    // through a real `ServiceRegistrationRequest`, which requires the
    // registered images to exist on disk (the
    // `system_registration_transaction` precedent writes the same fixture
    // bytes). Content is fixture-owned; identity comes from the paths the
    // manifest binds, never from these bytes.
    for image in ["eliot-host.exe", "eliot-watchdog.exe"] {
        std::fs::write(bin.join(image), b"approved-service-image-fixture-958")
            .expect("case service image");
    }
    let staging_parent = case_root
        .join("Eliot")
        .join(eliot_platform_windows::ISOLATED_RESTORE_ROOT_DIR);
    std::fs::create_dir_all(&staging_parent).expect("case isolated restore area");
    let pinned = override_protected_root(&case_root);
    ContourFilesystem {
        unique,
        case_root,
        key,
        roots,
        bin,
        staging_parent,
        pinned,
    }
}

fn contour_seed_registry(
    filesystem: &ContourFilesystem,
    case: &str,
    profile: eliot_installation::InstallationProfile,
) -> ContourSeed {
    let installation = format!("installation:958-dispatch-{}", filesystem.unique);
    let manifest = dispatch_manifest_for_profile(
        &filesystem.roots,
        &installation,
        &format!("generation-958-dispatch-{case}"),
        &filesystem.case_root,
        &filesystem.bin,
        profile,
    );
    let owner_lease =
        HostOwnerLease::acquire(&dispatch_handle(installation.clone())).expect("case owner lease");
    let fence = dispatch_commit_fence(&manifest, &installation);
    let transaction_id = dispatch_handle(format!("transaction:958-dispatch-{}", filesystem.unique));
    let plan_digest = dispatch_handle(dispatch_sha256(&format!(
        "plan:958-dispatch-{}",
        filesystem.unique
    )));
    let registry_file =
        Path::new(filesystem.roots.host_state_root.as_str()).join("installation-registry.redb");
    // The registry opens through the real lease-bound owner (`open_at` over
    // a retained protected-root lease), never through the leaseless
    // test-support opener: every capability-bound record/read seam the arm
    // exercises (`validate_host_owner_capability`) refuses a registry
    // without a retained installation Host root, and the contour owns a
    // real one (the T17 override precedent).
    let host_lease = eliot_platform_windows::ProtectedRootLease::open_existing(Path::new(
        filesystem.roots.host_state_root.as_str(),
    ))
    .expect("case Host root lease");
    let store = eliot_installation::RedbInstallationRegistry::open_at(host_lease)
        .expect("case registry store");
    // A `SystemService` generation is invalid without exactly the Host +
    // Watchdog SCM approvals: the issuer derives the pair from this case's
    // own manifest (images, bootstrap, transaction), so the seeded row is
    // the same projection an installer-driven activation would commit.
    // Every other profile seeds approval-free through the same Pending
    // stage/commit path: the two-approval rule the registry enforces is
    // gated on `SystemService`, and a user-mode activation registers no
    // services.
    if profile == eliot_installation::InstallationProfile::SystemService {
        let service_approvals =
            eliot_installation::issue_test_support_service_registration_approvals(
                &transaction_id,
                &manifest,
            )
            .expect("case SCM approvals");
        assert_eq!(
            service_approvals.len(),
            2,
            "SystemService seeding carries exactly the Host + Watchdog approvals"
        );
        store
            .seed_active_generation_with_service_approvals_for_test_support(
                &owner_lease.activation_capability(),
                &manifest,
                &transaction_id,
                &plan_digest,
                &fence,
                &service_approvals,
            )
            .expect("case active generation");
    } else {
        store
            .seed_active_generation_for_test_support(
                &owner_lease.activation_capability(),
                &manifest,
                &transaction_id,
                &plan_digest,
                &fence,
            )
            .expect("case active generation");
    }
    let registry = store.load().expect("case registry projection");
    drop(store);
    ContourSeed {
        installation,
        manifest,
        owner_lease,
        fence,
        transaction_id,
        plan_digest,
        registry_file,
        registry,
    }
}

fn contour_apply_purge(filesystem: &ContourFilesystem) {
    let ors_file = Path::new(filesystem.roots.kernel_ors_root.as_str()).join("kernel-ors.redb");
    // The contour's ORS owner applies one purge before any preparation runs:
    // the admission seam refuses a zero purge-ledger revision (a destination
    // bound to no purge revision would restore without the current privacy
    // purge), so the fixture carries the owner's own issued revision rather
    // than an empty ledger. Entry shape mirrors the ORS owner's own
    // `purge_ledger_advances_953_18` precedent; only the case-bound ids differ.
    let ors_store = eliot_ors::RedbRecoveryStore::open(&ors_file).expect("case ORS store");
    let purge_epoch = eliot_contracts::EpochId::new(
        eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .unwrap_or_else(|_| unreachable!()),
        std::num::NonZeroU64::new(1).unwrap_or_else(|| unreachable!()),
    )
    .unwrap_or_else(|_| unreachable!());
    let unique = &filesystem.unique;
    let purge = eliot_security_contracts::PurgeLedgerEntry {
        purge_id: format!("purge-958-dispatch-{unique}"),
        subject_ref: format!("subject-958-dispatch-{unique}"),
        scope: format!("scope-958-dispatch-{unique}"),
        purged_locations: vec![
            eliot_security_contracts::PurgeLocation::OperationalRecovery,
            eliot_security_contracts::PurgeLocation::BackupRestorePath,
        ],
        tombstone_digest: dispatch_sha256(&format!("tombstone-958-dispatch-{unique}")),
        state: eliot_security_contracts::PurgeState::Purged,
        state_fence: eliot_contracts::StateFence::new(
            purge_epoch,
            eliot_contracts::ResourceGeneration::genesis(),
        ),
        revision: 1,
    };
    assert_eq!(
        ors_store
            .apply_purge_ledger_entry(&purge)
            .expect("case purge applies"),
        1,
        "the contour's first applied purge consumes ledger revision one"
    );
    drop(ors_store);
}

fn contour_compose(
    filesystem: ContourFilesystem,
    seed: ContourSeed,
) -> (DispatchContour, HostComposition) {
    let journal_file = filesystem.case_root.join("host-journal.redb");
    let (journal, host, activation_generation, activation_id, _) =
        super::host_epoch_reopen::open_test_support_epoch(
            &journal_file,
            dispatch_handle(seed.installation.clone()),
            None,
            None,
        )
        .expect("case host epoch");
    let launch_options = HostLaunchOptions {
        config_descriptor_path: PathBuf::from(
            seed.manifest
                .runtime_launch
                .authority_descriptor_path
                .as_str(),
        ),
        config_descriptor_digest: phase_b_scm_selector(
            &seed.manifest.runtime_launch.authority_descriptor_digest,
        )
        .expect("case descriptor selector"),
        installation: dispatch_handle(seed.installation.clone()),
        transaction_plan_generation: seed.manifest.runtime_launch.authority_generation.value(),
        host_state_root: PathBuf::from(
            seed.manifest
                .runtime_launch
                .runtime_state_roots
                .host_state_root
                .as_str(),
        ),
        registration_nonce: None,
    };
    let jobs = HostJobBranches::new_test_support(&host).expect("case job branches");
    let composition = HostComposition {
        store_rebind_boundary: HostStoreRebindProductionBoundary,
        runtime_control_boundary: HostRuntimeControlProductionBoundary,
        journal,
        registry_host_root: PathBuf::from(filesystem.roots.host_state_root.as_str()),
        // No test-file hook: the arm under proof opens the registry through
        // the production lease-bound path (`open_registry_store` falls
        // through to `open_registry_store_at_profile` when no hook is set),
        // which is the only opener whose retained root passes the
        // capability binding the record/read seams enforce.
        test_registry_file: None,
        registry: seed.registry,
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
        owner_lease: seed.owner_lease,
        pending_record: None,
        durable_finalized: false,
        owner_released: false,
        shutdown_failed: false,
    };
    let contour = DispatchContour {
        case_root: filesystem.case_root,
        _override: filesystem.pinned,
        roots: filesystem.roots,
        manifest: seed.manifest,
        installation: seed.installation,
        installation_key: filesystem.key,
        registry_file: seed.registry_file,
        journal_file,
        staging_parent: filesystem.staging_parent,
        transaction_id: seed.transaction_id.as_str().to_owned(),
        plan_digest: seed.plan_digest.as_str().to_owned(),
    };
    (contour, composition)
}

/// Removes one case contour. The composition (journal backend), the evidence
/// leases and the override guard must already be dropped: redb files cannot
/// be removed while a Database handle is open.
fn release_contour(contour: &DispatchContour) {
    let _ = std::fs::remove_dir_all(&contour.case_root);
}

/// Builds one admitted dispatch request for a contour: every owner-checked
/// name (target build, target profile, staging parent, authority generation)
/// is copied back out of freshly inspected owner evidence, so the request
/// carries owner-issued values, never invented ones. The only caller-chosen
/// values are the operation identity and the forensic digests, which the
/// admission binds but never sources authority from.
fn admitted_dispatch_request(
    contour: &DispatchContour,
    operation: &str,
    source_installation_id: &str,
) -> crate::backup_preparation::PresentedPreparationRequest {
    use crate::backup_preparation::{
        OwnerEvidence, PreparationClass, resolve_owner_staging_parent,
    };
    let evidence = OwnerEvidence::inspect(Path::new(contour.roots.host_state_root.as_str()))
        .expect("request builder inspects owner evidence");
    let binding = evidence
        .approved_binding()
        .expect("owner-approved build binding");
    // The presented parent is a claim about the owner-issued root: resolve
    // the owner's value and echo it, so a mismatch here would be a fixture
    // bug, never a second parent.
    let staging_parent =
        resolve_owner_staging_parent(&contour.roots).expect("owner staging parent");
    assert_eq!(
        staging_parent, contour.staging_parent,
        "fixture staging area is the owner-declared isolated root"
    );
    crate::backup_preparation::PresentedPreparationRequest {
        operation_id: operation.to_owned(),
        class: PreparationClass::IsolatedRestoreRehearsal,
        source_installation_id: source_installation_id.to_owned(),
        staging_parent,
        target_build: binding.generation_handle.clone(),
        target_profile: binding.approved_profile.clone(),
        approved_generation: evidence.authority_generation(),
        authority_generation: evidence.authority_generation(),
        owner_lease_ref: String::new(),
        purge_ledger_revision: 0,
        build_digests: binding.artifact_digests.clone(),
        audit_fence_note: None,
        authority_nonce: format!("nonce-958-{operation}"),
        state_fence_digest: dispatch_sha256(&format!("fence:{operation}")),
    }
}

/// Caller authentication material for the dispatch port: shape-checked
/// digests only, carrying no authority of their own.
fn dispatch_caller_auth() -> crate::backup_preparation::BackupCallerAuth {
    crate::backup_preparation::BackupCallerAuth {
        lease_digest: dispatch_sha256("caller-lease-958"),
        fence_digest: dispatch_sha256("caller-fence-958"),
    }
}

/// Journal-port regression proof: the admitted `backup_dispatch_prepare`
/// port prepares through the Host journal sink and reconciles the recorded
/// result. This is the port that caught the inverted `admits` operands
/// (`retained.state.admits(outcome)` refused every `Pending -> Prepared`
/// move, so no result could ever be recorded through the Host journal);
/// it retains no installation row by design — the row belongs to the
/// installation-authority arm proved below — and asserts none.
#[test]
fn dispatch_journal_port_prepares_and_reconciles() {
    use crate::backup_preparation::ReconcileDisposition;
    let (contour, composition) = dispatch_contour("journal");
    let operation = "op-958-dispatch-journal";
    let request = admitted_dispatch_request(&contour, operation, &contour.installation);
    let (_sink, prepared) = composition
        .backup_dispatch_prepare(&dispatch_caller_auth(), &request)
        .expect("admitted dispatch prepares");
    assert_eq!(prepared.operation_id, operation);
    assert!(prepared.root.exists(), "destination created");
    match composition
        .backup_dispatch_reconcile(operation)
        .expect("reconcile resolves")
    {
        ReconcileDisposition::Current(current) => assert_eq!(
            current.root, prepared.root,
            "status resolves the original destination"
        ),
        other => panic!("reconcile must resolve Current, got {other:?}"),
    }
    drop(composition);
    release_contour(&contour);
}

/// Refusal proof on the journal port: a foreign source is refused by the
/// caller gate before any effect — no destination directory appears.
#[test]
fn dispatch_journal_port_refuses_foreign_source_before_effect() {
    let (contour, composition) = dispatch_contour("refusal");
    let operation = "op-958-dispatch-refusal";
    let request =
        admitted_dispatch_request(&contour, operation, "installation:foreign-958-refusal");
    let Err(error) = composition.backup_dispatch_prepare(&dispatch_caller_auth(), &request) else {
        panic!("foreign source refused");
    };
    assert!(
        format!("{error:?}").contains("caller_auth"),
        "refusal names the caller-auth gate, got {error:?}"
    );
    let staged: Vec<_> = std::fs::read_dir(&contour.staging_parent)
        .expect("staging parent readable")
        .collect();
    assert!(
        staged.is_empty(),
        "refused preparation leaves no destination behind"
    );
    drop(composition);
    release_contour(&contour);
}

/// Opens one short-lived lease-bound registry handle over a contour's Host
/// root: the production `open_at` shape the arm itself uses, so the
/// capability-bound read seams under proof pass the same owner binding.
fn open_case_registry(contour: &DispatchContour) -> eliot_installation::RedbInstallationRegistry {
    assert!(
        contour.registry_file.exists(),
        "seeding committed the registry file"
    );
    let lease = eliot_platform_windows::ProtectedRootLease::open_existing(Path::new(
        contour.roots.host_state_root.as_str(),
    ))
    .expect("readback Host root lease");
    eliot_installation::RedbInstallationRegistry::open_at(lease).expect("readback store")
}

/// Builds the `#954` fence this fixture's identities bind: the same epoch
/// and generation everywhere the contract demands agreement (identity,
/// transport, admission scope and authority).
fn dispatch_fence() -> eliot_contracts::StateFence {
    let epoch = eliot_contracts::EpochId::new(
        eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .unwrap_or_else(|_| unreachable!()),
        std::num::NonZeroU64::new(1).unwrap_or_else(|| unreachable!()),
    )
    .unwrap_or_else(|_| unreachable!());
    eliot_contracts::StateFence::new(
        epoch,
        eliot_contracts::ResourceGeneration::new(1).unwrap_or_else(|_| unreachable!()),
    )
}

/// Builds the `#954` transport correlation for one envelope, mirroring the
/// protocol oracle's shape with fixture-owned correlation names.
fn dispatch_transport(
    request_id: &str,
    fence: &eliot_contracts::StateFence,
) -> eliot_protocol::RequestIdentity {
    eliot_protocol::RequestIdentity {
        request: eliot_receipts::RequestBinding {
            metadata: eliot_contracts::RequestMetadata {
                request_id: eliot_contracts::RequestId::new(request_id)
                    .unwrap_or_else(|_| unreachable!()),
                session_id: Some(
                    eliot_contracts::SessionId::new("session-958-dispatch")
                        .unwrap_or_else(|_| unreachable!()),
                ),
                task_id: None,
                product_id: eliot_contracts::ProductId::new("product-958-dispatch")
                    .unwrap_or_else(|_| unreachable!()),
                source_id: eliot_contracts::SourceId::new("source-958-dispatch")
                    .unwrap_or_else(|_| unreachable!()),
                state_fence: fence.clone(),
                clock: eliot_contracts::ClockReading::default(),
            },
            state_fence: fence.clone(),
        },
        idempotency_key: format!("transport-958-{request_id}"),
        deadline_unix_ms: 10_000,
        cancellation_id: "cancel-958-dispatch".to_owned(),
    }
}

/// Builds the `#954` admission reference all of whose fences agree, mirroring
/// the protocol oracle's shape.
fn dispatch_admission(
    fence: &eliot_contracts::StateFence,
) -> eliot_protocol::backup::BackupAdmissionRef {
    eliot_protocol::backup::BackupAdmissionRef {
        authority: eliot_receipts::AuthorityBinding {
            authority_id: eliot_contracts::ContractId::new("admission-authority-958")
                .unwrap_or_else(|_| unreachable!()),
            authority_owner: "backup-admission-authority-958".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            allowed_effect: eliot_receipts::EffectClass::Read,
            proof_ceiling: eliot_receipts::ProofCeiling::Observation,
        },
        scope: eliot_receipts::WorkScopeBinding {
            scope_id: eliot_receipts::WorkScopeId::new("scope-958-dispatch")
                .unwrap_or_else(|_| unreachable!()),
            product_id: eliot_contracts::ProductId::new("product-958-dispatch")
                .unwrap_or_else(|_| unreachable!()),
            resource_generation: fence.resource_generation,
            state_fence: fence.clone(),
        },
        capability: "backup.capture".to_owned(),
        admission_receipt: eliot_contracts::ReceiptId::new("admission-958-dispatch")
            .unwrap_or_else(|_| unreachable!()),
    }
}

/// Builds one `#954` request identity for a contour: the Requester principal
/// (the role that may prepare and reconcile), the contour's own source
/// installation, the case destination identity, and the case-stable
/// canonical request hash that prepare, status and cleanup all key by.
fn dispatch_identity(
    contour: &DispatchContour,
    operation: eliot_protocol::backup::BackupOperationKind,
    dest_installation: &str,
    request_id: &str,
    canonical_request_hash: &str,
) -> eliot_protocol::backup::BackupRequestIdentity {
    use eliot_protocol::backup::{
        BACKUP_REQUEST_IDENTITY_WIRE_ID, BACKUP_REQUEST_IDENTITY_WIRE_VERSION,
    };
    let fence = dispatch_fence();
    let contract = |name: &str| eliot_contracts::ContractIdentity {
        name: eliot_contracts::ContractId::new(name).unwrap_or_else(|_| unreachable!()),
        version: eliot_contracts::ContractVersion::new(1, 0, 0),
        shape_sha256: dispatch_sha256(name),
    };
    eliot_protocol::backup::BackupRequestIdentity {
        wire_id: BACKUP_REQUEST_IDENTITY_WIRE_ID.to_owned(),
        wire_version: BACKUP_REQUEST_IDENTITY_WIRE_VERSION,
        principal: eliot_protocol::backup::BackupAuthenticatedPrincipal {
            principal: "principal-958-dispatch".to_owned(),
            session_id: "session-958-dispatch".to_owned(),
            role: eliot_protocol::backup::BackupRole::Requester,
            authority_epoch: fence.authority_epoch.clone(),
        },
        request: dispatch_transport(request_id, &fence),
        mutation: eliot_protocol::backup::BackupMutationBinding {
            operation,
            canonical_request_hash: canonical_request_hash.to_owned(),
        },
        archive_id: "archive-958-dispatch".to_owned(),
        archive_contract: contract("archive.owner.958"),
        archive_digest: dispatch_sha256("archive-958-dispatch"),
        owner_contract: contract("attesting.owner.958"),
        schema_digest: dispatch_sha256("schema-958-dispatch"),
        build_digest: dispatch_sha256("build-958-dispatch"),
        source_installation: contour.installation.clone(),
        dest_installation: dest_installation.to_owned(),
        class: eliot_protocol::backup::BackupClassWire::FullRecovery,
        fence: fence.clone(),
        snapshot_digest: dispatch_sha256("snapshot-958-dispatch"),
        member_digest: dispatch_sha256("members-958-dispatch"),
        max_page_members: 16,
        max_payload_bytes: 65_536,
        deadline_unix_ms: 10_000,
        cancellation_id: "cancel-958-dispatch".to_owned(),
        admission: dispatch_admission(&fence),
        identity_digest: String::new(),
    }
    .with_computed_digest()
    .expect("identity digest computes")
}

/// Builds the `#954` prepare body for one case destination: the identity
/// above plus the body's own destination echo and a bounded restore bound.
fn dispatch_prepare_body(
    identity: eliot_protocol::backup::BackupRequestIdentity,
    dest_installation: &str,
) -> eliot_host_service::runtime_control::BackupOperationBody {
    use eliot_protocol::backup::{
        BACKUP_ISOLATED_RESTORE_PREPARE_WIRE_ID, BACKUP_ISOLATED_RESTORE_PREPARE_WIRE_VERSION,
    };
    let body = eliot_protocol::backup::BackupIsolatedRestorePrepare {
        wire_id: BACKUP_ISOLATED_RESTORE_PREPARE_WIRE_ID.to_owned(),
        wire_version: BACKUP_ISOLATED_RESTORE_PREPARE_WIRE_VERSION,
        identity,
        operation: eliot_protocol::backup::BackupOperationKind::PrepareIsolatedRestore,
        destination_installation: dest_installation.to_owned(),
        max_restore_bytes: 65_536,
        request_digest: String::new(),
    }
    .with_computed_digest()
    .expect("prepare digest computes");
    eliot_host_service::runtime_control::BackupOperationBody::PrepareIsolatedRestore(body)
}

/// Builds the `#954` reconcile body that selects the SAME retained operation:
/// the case-stable canonical request hash is carried unchanged while the
/// mutation operation labels the body's own reconcile operation, which is
/// the stable-selector binding P4 requires across prepare and status.
fn dispatch_reconcile_body(
    contour: &DispatchContour,
    canonical_request_hash: &str,
    request_id: &str,
) -> eliot_host_service::runtime_control::BackupOperationBody {
    use eliot_protocol::backup::{
        BACKUP_RESTORE_RECONCILE_WIRE_ID, BACKUP_RESTORE_RECONCILE_WIRE_VERSION,
    };
    // The status read names the same destination the preparation allocated:
    // only the mutation operation is relabeled to the body's own reconcile
    // operation, while the canonical request hash — the selector — stays
    // the case-stable value.
    let dest_key = dispatch_sha256(&format!("destination:{}", contour.installation));
    let identity = dispatch_identity(
        contour,
        eliot_protocol::backup::BackupOperationKind::ReconcileRestore,
        &dest_key,
        request_id,
        canonical_request_hash,
    );
    let body = eliot_protocol::backup::BackupRestoreReconcile {
        wire_id: BACKUP_RESTORE_RECONCILE_WIRE_ID.to_owned(),
        wire_version: BACKUP_RESTORE_RECONCILE_WIRE_VERSION,
        identity,
        operation: eliot_protocol::backup::BackupOperationKind::ReconcileRestore,
        believed_digest: dispatch_sha256(&format!("believed:{canonical_request_hash}")),
        request_digest: String::new(),
    }
    .with_computed_digest()
    .expect("reconcile digest computes");
    eliot_host_service::runtime_control::BackupOperationBody::ReconcileRestore(body)
}

/// Wraps one `#954` body in its transport envelope through the exact
/// `new_backup` constructor the endpoint ingress uses, so the header commits
/// the body's own request digest and cannot describe another operation.
fn dispatch_envelope(
    body: eliot_host_service::runtime_control::BackupOperationBody,
    tag: &str,
) -> eliot_host_control_endpoint::BackupRuntimeControlRequest {
    let handle = |value: String| {
        eliot_platform::PlatformHandle::new(value).unwrap_or_else(|_| unreachable!())
    };
    eliot_host_service::runtime_control::BackupRuntimeControlRequest::new_backup(
        body,
        handle("host-owner-958-dispatch".to_owned()),
        handle(format!("request-958-{tag}")),
        handle(dispatch_sha256(&format!("nonce:{tag}"))),
        handle(dispatch_sha256(&format!("generation:{tag}"))),
        handle(dispatch_sha256(&format!("fence:{tag}"))),
    )
    .unwrap_or_else(|error| panic!("envelope admits the fixture body: {error}"))
}

/// Production-path success proof (P2/P3/P4): the live queue arm
/// (`process_backup_dispatch_requests -> dispatch_backup_owner_operation ->
/// Prepare`) answers `PossibleEffect` once the effect boundary is crossed,
/// retains the destination `ApprovedGeneration` row (inactive, new
/// installation) with its creation pair naming the created root, and the
/// status arm resolves the original destination under the same admitted
/// operation hash.
#[test]
fn dispatch_arm_admits_and_records_destination() {
    use eliot_host_service::runtime_control::BackupOwnerOutcome;
    use eliot_protocol::backup::BackupOperationKind;
    let (contour, composition) = dispatch_contour("arm");
    // The case destination identity is an owner installation KEY (64-hex),
    // minted for this case alone; the source stays the contour's own
    // installation, so the pair is isolated by construction.
    let dest_key = dispatch_sha256(&format!("destination:{}", contour.installation));
    let canonical_request_hash =
        dispatch_sha256(&format!("canonical-request:{}", contour.installation));
    let identity = dispatch_identity(
        &contour,
        BackupOperationKind::PrepareIsolatedRestore,
        &dest_key,
        "prepare-958-arm",
        &canonical_request_hash,
    );
    let prepare = dispatch_envelope(
        dispatch_prepare_body(identity, &dest_key),
        "prepare-958-arm",
    );
    match composition.dispatch_backup_owner_operation(&prepare) {
        Ok(BackupOwnerOutcome::PossibleEffect { retained }) => assert_eq!(
            retained.operation,
            BackupOperationKind::PrepareIsolatedRestore,
            "possible effect retains the exact admitted operation"
        ),
        other => panic!("prepare arm must answer PossibleEffect, got {other:?}"),
    }
    // Durable readback through a fresh lease-bound handle, using the
    // production read seams: the destination row exists, is inactive, is a
    // new installation, and the creation pair names the created root.
    let store = open_case_registry(&contour);
    let capability = composition.owner_lease.activation_capability();
    let operation_id =
        eliot_installation::PlatformHandle::new(&canonical_request_hash).expect("operation handle");
    let row = store
        .read_prepared_destination_generation(&capability, &operation_id)
        .expect("destination row recorded");
    assert!(
        !row.active,
        "prepared destination never activates at preparation"
    );
    assert_ne!(
        row.manifest.generation.as_str(),
        contour.manifest.generation.as_str(),
        "destination row is a new installation, not the source generation"
    );
    // The destination is a new installation the installer has not provisioned
    // yet: its authority is the Phase-A plan state, never the source's
    // transaction-bound receipt (which names the source generation and cannot
    // be re-bound).
    assert!(
        matches!(
            row.manifest.runtime_launch.supervision_authority,
            eliot_installation::SupervisionAuthorityBinding::Pending { .. }
        ),
        "destination row carries pending plan authority, not the source receipt"
    );
    let (admission, materialisation) = store
        .read_prepared_isolated_destination_creation(&capability, &operation_id)
        .expect("creation pair recorded");
    let created = Path::new(&materialisation.destination_installation_root);
    assert!(created.exists(), "recorded root exists on disk");
    let canonical_parent =
        std::fs::canonicalize(&contour.staging_parent).expect("parent canonicalizes");
    let canonical_root = std::fs::canonicalize(created).expect("root canonicalizes");
    assert!(
        canonical_root.starts_with(&canonical_parent),
        "created root sits under the owner-issued staging parent"
    );
    drop(admission);
    drop(store);
    // Status arm (P4): the reconcile body carries the SAME canonical request
    // hash and resolves the retained operation instead of preparing again.
    let reconcile = dispatch_envelope(
        dispatch_reconcile_body(&contour, &canonical_request_hash, "reconcile-958-arm"),
        "reconcile-958-arm",
    );
    match composition.dispatch_backup_owner_operation(&reconcile) {
        Ok(BackupOwnerOutcome::Admitted { retained }) => assert_eq!(
            retained.operation,
            BackupOperationKind::ReconcileRestore,
            "status retains the reconcile operation it answered"
        ),
        other => panic!("status arm must answer Admitted, got {other:?}"),
    }
    drop(composition);
    release_contour(&contour);
}

/// Production-path success proof on a `UserMode` contour (#958-continue
/// F1-F4): the same live queue arm admits a preparation whose source is a
/// current-user installation, answers `PossibleEffect` once the effect
/// boundary is crossed, and retains the destination `ApprovedGeneration` row
/// (inactive, new installation, pending plan authority) with its creation
/// pair naming the created root under the owner-issued staging parent. The
/// validators the arm traverses (`RuntimeStateRoots::validate` per-profile
/// suffix, the installation Host-root shape check, the durable-runtime join
/// installation comparison, the profile-aware installations root) refused
/// every `UserMode` root before F1-F4; this test drives all four on the
/// production path. Refusal and replay halves stay proved by their
/// profile-independent `SystemService` twins above.
/// Norm: `docs/architecture/I05-13-backup-and-restore.md` Restore
/// ("restore to isolated root;").
#[test]
fn dispatch_user_mode_arm_admits_and_records_destination() {
    use eliot_host_service::runtime_control::BackupOwnerOutcome;
    use eliot_protocol::backup::BackupOperationKind;
    let (contour, composition) = dispatch_contour_for_profile(
        "user-mode-arm",
        eliot_installation::InstallationProfile::UserMode,
    );
    assert_eq!(
        contour.roots.profile,
        eliot_installation::InstallationProfile::UserMode,
        "the contour carries the production user profile"
    );
    let dest_key = dispatch_sha256(&format!("destination:{}", contour.installation));
    let canonical_request_hash = dispatch_sha256(&format!(
        "canonical-request-user-mode:{}",
        contour.installation
    ));
    let identity = dispatch_identity(
        &contour,
        BackupOperationKind::PrepareIsolatedRestore,
        &dest_key,
        "prepare-958-user-mode-arm",
        &canonical_request_hash,
    );
    let prepare = dispatch_envelope(
        dispatch_prepare_body(identity, &dest_key),
        "prepare-958-user-mode-arm",
    );
    match composition.dispatch_backup_owner_operation(&prepare) {
        Ok(BackupOwnerOutcome::PossibleEffect { retained }) => assert_eq!(
            retained.operation,
            BackupOperationKind::PrepareIsolatedRestore,
            "possible effect retains the exact admitted operation"
        ),
        other => panic!("prepare arm must answer PossibleEffect, got {other:?}"),
    }
    let store = open_case_registry(&contour);
    let capability = composition.owner_lease.activation_capability();
    let operation_id =
        eliot_installation::PlatformHandle::new(&canonical_request_hash).expect("operation handle");
    let row = store
        .read_prepared_destination_generation(&capability, &operation_id)
        .expect("destination row recorded");
    assert!(
        !row.active,
        "prepared destination never activates at preparation"
    );
    assert!(
        matches!(
            row.manifest.runtime_launch.supervision_authority,
            eliot_installation::SupervisionAuthorityBinding::Pending { .. }
        ),
        "destination row carries pending plan authority, not the source receipt"
    );
    let (_, materialisation) = store
        .read_prepared_isolated_destination_creation(&capability, &operation_id)
        .expect("creation pair recorded");
    let created = Path::new(&materialisation.destination_installation_root);
    assert!(created.exists(), "recorded root exists on disk");
    let canonical_parent =
        std::fs::canonicalize(&contour.staging_parent).expect("parent canonicalizes");
    let canonical_root = std::fs::canonicalize(created).expect("root canonicalizes");
    assert!(
        canonical_root.starts_with(&canonical_parent),
        "created root sits under the owner-issued staging parent"
    );
    drop(store);
    drop(composition);
    release_contour(&contour);
}

/// T5 installation-identity proof (#958 A2): an admitted preparation on the
/// production dispatch path allocates a destination `ApprovedGeneration` row
/// whose generation IS the requested owner installation key — inactive, with
/// pending plan authority — and records the creation pair naming the created
/// root. The negative half (an arbitrary non-key destination is refused
/// before any effect, allocating no row) is proved by
/// `dispatch_arm_refuses_arbitrary_destination_before_effect` below.
/// Red on pre-A2 code by construction: the `read_prepared_destination_...`
/// seams and the isolated-destination allocation they read do not exist on
/// `main` (new `isolated_destination.rs` allocation path).
/// Norm: `docs/architecture/I05-13-backup-and-restore.md` Restore
/// ("restore to isolated root;").
#[test]
fn dispatch_t5_admitted_destination_carries_installation_identity() {
    use eliot_host_service::runtime_control::BackupOwnerOutcome;
    use eliot_protocol::backup::BackupOperationKind;
    let (contour, composition) = dispatch_contour("t5-identity");
    let dest_key = dispatch_sha256(&format!("destination-identity:{}", contour.installation));
    let canonical_request_hash =
        dispatch_sha256(&format!("canonical-request-t5:{}", contour.installation));
    let identity = dispatch_identity(
        &contour,
        BackupOperationKind::PrepareIsolatedRestore,
        &dest_key,
        "prepare-958-t5",
        &canonical_request_hash,
    );
    let prepare = dispatch_envelope(dispatch_prepare_body(identity, &dest_key), "prepare-958-t5");
    match composition.dispatch_backup_owner_operation(&prepare) {
        Ok(BackupOwnerOutcome::PossibleEffect { .. }) => {}
        other => panic!("prepare arm must answer PossibleEffect, got {other:?}"),
    }
    let store = open_case_registry(&contour);
    let capability = composition.owner_lease.activation_capability();
    let operation_id =
        eliot_installation::PlatformHandle::new(&canonical_request_hash).expect("operation handle");
    let row = store
        .read_prepared_destination_generation(&capability, &operation_id)
        .expect("destination row recorded");
    assert_eq!(
        row.manifest.generation.as_str(),
        dest_key,
        "destination row generation is the requested installation key"
    );
    assert!(
        !row.active,
        "prepared destination never activates at preparation"
    );
    assert!(
        matches!(
            row.manifest.runtime_launch.supervision_authority,
            eliot_installation::SupervisionAuthorityBinding::Pending { .. }
        ),
        "destination row carries pending plan authority, not the source receipt"
    );
    let (_, materialisation) = store
        .read_prepared_isolated_destination_creation(&capability, &operation_id)
        .expect("creation pair recorded");
    assert!(
        Path::new(&materialisation.destination_installation_root).exists(),
        "recorded root exists on disk"
    );
    drop(store);
    drop(composition);
    release_contour(&contour);
}

/// Replay proof (A2/A4/T12): a repeated admitted prepare resolves the SAME
/// verified destination instead of refusing or allocating again. The first
/// prepare retains the destination; the second prepare — same canonical
/// operation, fresh envelope — answers the identical `PossibleEffect` with
/// the same retained identity digest, keeps the same destination row, and
/// creates no second directory. Before the repair this second prepare was
/// refused (`ExistingInstallation` out of the allocation, which ran before
/// any retained lookup): the installation authority already held the
/// destination the first prepare created, so the fresh-allocation guard fired
/// on the operation's own effect.
/// Norm: `docs/architecture/A13-06-operational-recovery-state.md`
/// (receipt/effect reconciliation before replay) and the live issue (repeated
/// requests resolve the same verified destination or conflict).
#[test]
fn dispatch_repeated_prepare_resolves_same_destination() {
    use eliot_host_service::runtime_control::BackupOwnerOutcome;
    use eliot_protocol::backup::BackupOperationKind;
    let (contour, composition) = dispatch_contour("replay");
    let dest_key = dispatch_sha256(&format!("destination-replay:{}", contour.installation));
    let canonical_request_hash = dispatch_sha256(&format!(
        "canonical-request-replay:{}",
        contour.installation
    ));
    let build_prepare = || {
        let identity = dispatch_identity(
            &contour,
            BackupOperationKind::PrepareIsolatedRestore,
            &dest_key,
            "prepare-958-replay",
            &canonical_request_hash,
        );
        dispatch_envelope(
            dispatch_prepare_body(identity, &dest_key),
            "prepare-958-replay",
        )
    };
    let first = match composition.dispatch_backup_owner_operation(&build_prepare()) {
        Ok(BackupOwnerOutcome::PossibleEffect { retained }) => retained,
        other => panic!("first prepare must answer PossibleEffect, got {other:?}"),
    };
    let staged_once: Vec<_> = std::fs::read_dir(&contour.staging_parent)
        .expect("staging parent readable")
        .collect();
    assert_eq!(
        staged_once.len(),
        1,
        "the first prepare creates exactly one destination"
    );
    let second = match composition.dispatch_backup_owner_operation(&build_prepare()) {
        Ok(BackupOwnerOutcome::PossibleEffect { retained }) => retained,
        other => panic!("repeated prepare must resolve, never refuse, got {other:?}"),
    };
    assert_eq!(
        second.identity_digest, first.identity_digest,
        "the replay retains the same operation, not a second one"
    );
    let staged_twice: Vec<_> = std::fs::read_dir(&contour.staging_parent)
        .expect("staging parent readable")
        .collect();
    assert_eq!(
        staged_twice.len(),
        1,
        "the replay allocates no second destination"
    );
    drop(composition);
    release_contour(&contour);
}

/// Uncertainty proof (A2/A4/T12): an admission-only replay — the admission
/// recorded, the creation not yet — stays retained and reconciling instead
/// of allocating again or refusing. The fixture records the admission
/// through the real seams (`admit_allocation` +
/// `record_admission_before_materialise`, no materialisation, exactly the
/// crash window between the two production steps), then dispatches the full
/// prepare: the answer is `PossibleEffect`, and no destination directory
/// appears behind it.
#[test]
fn dispatch_admission_only_replay_stays_uncertain() {
    use eliot_host_service::runtime_control::{BackupOperationBody, BackupOwnerOutcome};
    use eliot_protocol::backup::BackupOperationKind;
    let (contour, composition) = dispatch_contour("admission-only");
    let dest_key = dispatch_sha256(&format!("destination-admonly:{}", contour.installation));
    let canonical_request_hash = dispatch_sha256(&format!(
        "canonical-request-admonly:{}",
        contour.installation
    ));
    let identity = dispatch_identity(
        &contour,
        BackupOperationKind::PrepareIsolatedRestore,
        &dest_key,
        "prepare-958-admonly",
        &canonical_request_hash,
    );
    let facts =
        eliot_installation::PreparedDestinationFacts::issue_for_admitted_identity(&identity)
            .expect("admission facts issue from the admitted identity");
    let BackupOperationBody::PrepareIsolatedRestore(ref body) =
        dispatch_prepare_body(identity, &dest_key)
    else {
        panic!("prepare body builder builds a prepare body");
    };
    let max_restore_bytes =
        u64::try_from(eliot_protocol::backup::MAX_BACKUP_PAYLOAD_BYTES).unwrap_or(u64::MAX);
    let (_area_lease, allocation, purge_revision, evidence_revision) = composition
        .admit_allocation(body, &facts, max_restore_bytes)
        .expect("fresh admission allocates before anything is retained");
    let store = composition
        .open_registry_store()
        .expect("writer store opens for the admission record");
    HostComposition::record_admission_before_materialise(
        &store,
        &composition.owner_lease.activation_capability(),
        &allocation,
        evidence_revision,
        purge_revision,
    )
    .expect("the admission record commits");
    drop(store);
    let replay_identity = dispatch_identity(
        &contour,
        BackupOperationKind::PrepareIsolatedRestore,
        &dest_key,
        "prepare-958-admonly",
        &canonical_request_hash,
    );
    let replay = dispatch_envelope(
        dispatch_prepare_body(replay_identity, &dest_key),
        "prepare-958-admonly",
    );
    match composition.dispatch_backup_owner_operation(&replay) {
        Ok(BackupOwnerOutcome::PossibleEffect { retained }) => assert_eq!(
            retained.operation,
            BackupOperationKind::PrepareIsolatedRestore,
            "the uncertain replay retains the admitted operation for reconcile"
        ),
        other => panic!("admission-only replay must stay uncertain, got {other:?}"),
    }
    let staged: Vec<_> = std::fs::read_dir(&contour.staging_parent)
        .expect("staging parent readable")
        .collect();
    assert!(
        staged.is_empty(),
        "the uncertain replay creates no destination behind the retained admission"
    );
    drop(composition);
    release_contour(&contour);
}

/// Production-path refusal proof (P2): a destination identity that is not
/// an owner installation key is refused by the installation authority
/// before any effect — no directory appears and no row is retained.
#[test]
fn dispatch_arm_refuses_arbitrary_destination_before_effect() {
    use eliot_protocol::backup::BackupOperationKind;
    let (contour, composition) = dispatch_contour("refusal");
    let canonical_request_hash = dispatch_sha256(&format!(
        "canonical-request-refusal:{}",
        contour.installation
    ));
    let foreign = "installation:foreign-958-refusal";
    let identity = dispatch_identity(
        &contour,
        BackupOperationKind::PrepareIsolatedRestore,
        foreign,
        "prepare-958-refusal",
        &canonical_request_hash,
    );
    let prepare = dispatch_envelope(
        dispatch_prepare_body(identity, foreign),
        "prepare-958-refusal",
    );
    let refusal = match composition.dispatch_backup_owner_operation(&prepare) {
        Ok(outcome) => panic!("arbitrary destination refused, got {outcome:?}"),
        Err(refusal) => refusal,
    };
    assert_eq!(
        refusal.operation,
        BackupOperationKind::PrepareIsolatedRestore,
        "refusal names the refused operation"
    );
    let staged: Vec<_> = std::fs::read_dir(&contour.staging_parent)
        .expect("staging parent readable")
        .collect();
    assert!(
        staged.is_empty(),
        "refused preparation leaves no destination behind"
    );
    let store = open_case_registry(&contour);
    let projection = store.load().expect("registry projection");
    assert!(
        projection.prepared_isolated_destinations().is_empty(),
        "refused preparation retains no admission"
    );
    assert!(
        projection
            .prepared_destination_materialisations()
            .is_empty(),
        "refused preparation retains no materialisation"
    );
    assert!(
        projection
            .generations()
            .iter()
            .all(|generation| generation.active),
        "refused preparation allocates no destination row"
    );
    drop(store);
    drop(composition);
    release_contour(&contour);
}

/// First staging proof: the disposable contour inspects into real owner
/// evidence bound to the seeded active generation, with the registry
/// revision fence agreeing between the evidence and the composition.
#[test]
fn dispatch_contour_inspects_owner_evidence() {
    let (contour, composition) = dispatch_contour("inspect");
    let evidence = crate::backup_preparation::OwnerEvidence::inspect(Path::new(
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
    release_contour(&contour);
}
