//! Test-only redb fixtures for the Watchdog's protected registry boundary.
//!
//! The production Watchdog remains read-only.  This module owns the deliberately
//! separate writer used by the unit matrix so the production source scan cannot
//! mistake test setup for an activation capability.

#![allow(
    clippy::too_many_lines,
    reason = "the fixture keeps one complete registry projection in one test-only contour"
)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence, sha256_hex};
use eliot_installation::{
    CandidateManifest, InstallationEpoch, InstallationProfile, PlatformHandle,
    RuntimeLaunchDescriptor, RuntimeStateRoots,
};
use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_DISPLAY_NAME, ELIOT_HOST_SERVICE_NAME, ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
    ELIOT_WATCHDOG_SERVICE_NAME, InstallerRootPrimitiveSpec, InstallerRootProfile, ServiceAccount,
    ServiceBootstrapArguments, ServiceRegistrationRequest, ServiceStartMode,
    WindowsInstallerRootPrimitive, protected_program_data_root,
};
use redb::{Database, TableDefinition};
use serde_json::{Value, json};

const REGISTRY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_approved_generations_v2");
const LEGACY_REGISTRY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_approved_generations_v1");
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

/// A unique protected per-installation Host root and its fixed registry file.
pub struct RegistryFixture {
    program_data: PathBuf,
    host_root: PathBuf,
    registry_path: PathBuf,
    installation_key: String,
    artifact_root: PathBuf,
    root_spec: InstallerRootPrimitiveSpec,
}

impl RegistryFixture {
    /// Creates an isolated SystemService-shaped root without creating a registry.
    ///
    /// The registry is created only by the writer helpers below, and its file is
    /// provisioned with the same installer protected-file descriptor consumed by
    /// `ProtectedRuntimePathLease::open_existing_absolute`.
    #[must_use]
    pub fn new() -> Self {
        let program_data = protected_program_data_root()
            .unwrap_or_else(|error| panic!("ProgramData fixture root unavailable: {error}"));
        let unique = format!(
            "{}:{:?}:{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
        );
        let installation_key = sha256_hex(unique.as_bytes());
        let host_root = program_data
            .join("Eliot")
            .join("installations")
            .join(&installation_key)
            .join("host");
        std::fs::create_dir_all(&host_root).unwrap_or_else(|error| {
            panic!(
                "failed to create unique protected fixture parent {}: {error}",
                host_root.display()
            )
        });
        let artifact_root = std::env::temp_dir().join(format!(
            "eliot-watchdog-registry-{}-{}",
            std::process::id(),
            &installation_key[..16]
        ));
        std::fs::create_dir_all(&artifact_root).unwrap_or_else(|error| {
            panic!(
                "failed to create unique artifact fixture root {}: {error}",
                artifact_root.display()
            )
        });
        let source = std::env::current_exe()
            .unwrap_or_else(|error| panic!("test executable path unavailable: {error}"));
        for name in [
            "eliot-host.exe",
            "eliot-watchdog.exe",
            "eliot-kernel.exe",
            "eliot-store-surreal.exe",
            "surreal.exe",
            "eliotd.exe",
        ] {
            let destination = artifact_root.join(name);
            std::fs::copy(&source, &destination).unwrap_or_else(|error| {
                panic!(
                    "failed to materialize fixture image {}: {error}",
                    destination.display()
                )
            });
        }
        let registry_path = host_root.join("installation-registry.redb");
        let root_spec = InstallerRootPrimitiveSpec {
            root: host_root.clone(),
            installation_root: program_data.join("Eliot"),
            profile_anchor: program_data.clone(),
            profile: InstallerRootProfile::SystemService,
        };
        Self {
            program_data,
            host_root,
            registry_path,
            installation_key,
            artifact_root,
            root_spec,
        }
    }

    /// Returns the exact retained-root path supplied to Watchdog production.
    #[must_use]
    pub fn host_root(&self) -> &Path {
        &self.host_root
    }

    /// Returns the bootstrap selecting generation 7 in this fixture.
    #[must_use]
    pub fn base_bootstrap(&self) -> ServiceBootstrapArguments {
        self.bootstrap_for(7)
    }

    /// Returns a valid SystemService bootstrap for one fixture generation.
    #[must_use]
    pub fn bootstrap_for(&self, generation: u64) -> ServiceBootstrapArguments {
        let descriptor_path = self.authority_descriptor_path(generation);
        ServiceBootstrapArguments::new(
            descriptor_path,
            self.digest(generation),
            &self.installation_key,
            generation,
            std::iter::empty::<String>(),
        )
        .and_then(|value| value.with_host_state_root(&self.host_root))
        .and_then(|value| value.with_registration_nonce(self.digest(generation + 200)))
        .unwrap_or_else(|error| panic!("invalid fixture bootstrap: {error}"))
    }

    /// Writes a complete current v4 registry projection.
    pub fn write_registry(&self, value: &Value) {
        let bytes = serde_json::to_vec(value)
            .unwrap_or_else(|error| panic!("serialize registry fixture: {error}"));
        self.write_table(REGISTRY_TABLE, &bytes);
    }

    /// Writes bytes into the current registry table without parsing them.
    pub fn write_current_bytes(&self, bytes: &[u8]) {
        self.write_table(REGISTRY_TABLE, bytes);
    }

    /// Creates the retired v1 table so production classification must require migration.
    pub fn write_legacy_table(&self) {
        self.ensure_registry_file();
        let database = Database::open(&self.registry_path)
            .unwrap_or_else(|error| panic!("open legacy fixture database: {error}"));
        let write = database
            .begin_write()
            .unwrap_or_else(|error| panic!("begin legacy fixture write: {error}"));
        {
            let mut table = write
                .open_table(LEGACY_REGISTRY_TABLE)
                .unwrap_or_else(|error| panic!("open legacy fixture table: {error}"));
            table
                .insert("registry", b"legacy".as_slice())
                .unwrap_or_else(|error| panic!("insert legacy fixture row: {error}"));
        }
        write
            .commit()
            .unwrap_or_else(|error| panic!("commit legacy fixture: {error}"));
    }

    /// Returns a valid pending-only first-install projection.
    #[must_use]
    pub fn pending_only(&self) -> Value {
        let manifest = self.manifest(7);
        self.registry(
            vec![self.generation(&manifest, false, false)],
            vec![
                self.service_approval(&manifest, true),
                self.service_approval(&manifest, false),
            ],
            None,
            Some(self.pending(&manifest, None, "PENDING")),
        )
    }

    /// Returns an active generation plus a distinct pending upgrade.
    #[must_use]
    pub fn active_with_pending(&self) -> Value {
        let active = self.manifest(6);
        let pending = self.manifest(7);
        self.registry(
            vec![
                self.generation(&active, true, false),
                self.generation(&pending, false, false),
            ],
            vec![
                self.service_approval(&active, true),
                self.service_approval(&active, false),
                self.service_approval(&pending, true),
                self.service_approval(&pending, false),
            ],
            Some("generation-6"),
            Some(self.pending(&pending, Some("generation-6"), "PENDING")),
        )
    }

    /// Returns two approved generations that intentionally share the bootstrap contour.
    #[must_use]
    pub fn ambiguous_generations(&self) -> Value {
        let first = self.manifest(7);
        let mut second = self.manifest(8);
        second.runtime_launch.authority_descriptor_path =
            first.runtime_launch.authority_descriptor_path.clone();
        second.runtime_launch.authority_descriptor_digest =
            first.runtime_launch.authority_descriptor_digest.clone();
        second.runtime_launch.authority_generation = first.runtime_launch.authority_generation;
        second.runtime_launch.authority_state_fence =
            first.runtime_launch.authority_state_fence.clone();
        second.runtime_launch = second
            .runtime_launch
            .with_computed_digest()
            .unwrap_or_else(|error| panic!("re-seal ambiguous fixture descriptor: {error}"));
        second = self.rebind_manifest(second);
        self.registry(
            vec![
                self.generation(&first, false, false),
                self.generation(&second, false, false),
            ],
            vec![
                self.service_approval(&first, true),
                self.service_approval(&first, false),
                self.service_approval(&second, true),
                self.service_approval(&second, false),
            ],
            None,
            None,
        )
    }

    /// Returns a pending projection whose state is RecoveryRequired.
    #[must_use]
    pub fn recovery_required(&self) -> Value {
        let manifest = self.manifest(7);
        self.registry(
            vec![self.generation(&manifest, false, false)],
            vec![
                self.service_approval(&manifest, true),
                self.service_approval(&manifest, false),
            ],
            None,
            Some(self.pending(&manifest, None, "RECOVERY_REQUIRED")),
        )
    }

    /// Returns an active-only projection for service-approval and bootstrap substitution tests.
    #[must_use]
    pub fn active_only(&self) -> Value {
        let manifest = self.manifest(7);
        self.registry(
            vec![self.generation(&manifest, true, false)],
            vec![
                self.service_approval(&manifest, true),
                self.service_approval(&manifest, false),
            ],
            Some("generation-7"),
            None,
        )
    }

    /// Returns a structurally current projection with a retired v3 discriminator.
    #[must_use]
    pub fn migration_wire(&self) -> Value {
        let mut value = self.active_only();
        value["registry_wire_version"] = json!({ "major": 3, "minor": 0, "patch": 0 });
        value
    }

    /// Mutates one service approval in a fresh projection and returns the result.
    #[must_use]
    pub fn substituted_service_approval(&self, field: &str, replacement: Value) -> Value {
        let mut value = self.active_only();
        let approvals = value["service_registration_approvals"]
            .as_array_mut()
            .unwrap_or_else(|| unreachable!());
        match field {
            "role"
            | "generation"
            | "service_name"
            | "executable_path"
            | "account"
            | "automatic_start"
            | "registration_nonce"
            | "configuration_digest" => {
                approvals[0][field] = replacement;
            }
            "descriptor_path" | "descriptor_digest" | "installation_id" | "plan_generation"
            | "host_state_root" => {
                approvals[0]["service_bootstrap"][field] = replacement;
            }
            _ => panic!("unknown service approval substitution field: {field}"),
        }
        value
    }

    /// Rewrites only the generation descriptor while retaining the original approval,
    /// producing a read-time projection drift that must fail closed.
    #[must_use]
    pub fn drifted_active_projection(&self) -> Value {
        let mut value = self.active_only();
        value["generations"][0]["manifest"]["runtime_launch"]["authority_descriptor_digest"] =
            Value::String(self.digest(9));
        value
    }

    fn registry(
        &self,
        generations: Vec<Value>,
        service_registration_approvals: Vec<Value>,
        active_generation: Option<&str>,
        pending_activation: Option<Value>,
    ) -> Value {
        json!({
            "registry_wire_version": { "major": 4, "minor": 0, "patch": 0 },
            "revision": 1,
            "generations": generations,
            "service_registration_approvals": service_registration_approvals,
            "active_generation": active_generation,
            "last_known_good_generation": Value::Null,
            "pending_activation": pending_activation,
            "last_terminal_activation": Value::Null,
        })
    }

    fn generation(
        &self,
        manifest: &CandidateManifest,
        active: bool,
        last_known_good: bool,
    ) -> Value {
        json!({
            "manifest": manifest,
            "approval": self.activation_approval(manifest),
            "active": active,
            "last_known_good": last_known_good,
        })
    }

    fn pending(
        &self,
        manifest: &CandidateManifest,
        prior_active: Option<&str>,
        state: &str,
    ) -> Value {
        let approval = self.activation_approval(manifest);
        let manifest_value = serde_json::to_value(manifest)
            .unwrap_or_else(|error| panic!("serialize pending manifest: {error}"));
        let manifest_digest = sha256_hex(
            &serde_json::to_vec(manifest)
                .unwrap_or_else(|error| panic!("serialize pending manifest bytes: {error}")),
        );
        let reason = if state == "RECOVERY_REQUIRED" {
            Some("fixture recovery proof required".to_owned())
        } else {
            None
        };
        let state_value = match reason {
            Some(reason) => json!({ "state": state, "reason": reason }),
            None => json!({ "state": state }),
        };
        json!({
            "transaction_id": format!("transaction:{}", manifest.generation.as_str()),
            "plan_digest": self.digest(manifest.runtime_launch.authority_generation.value()),
            "manifest": manifest_value,
            "config_digest": manifest.config_digest,
            "kernel_artifact_digest": manifest.kernel_artifact_digest,
            "store_bridge_artifact_digest": manifest.store_bridge_artifact_digest,
            "canonical_store_artifact_digest": manifest.canonical_store_artifact_digest,
            "host_executable_path": manifest.host_executable_path,
            "host_artifact_digest": manifest.host_artifact_digest,
            "runtime_state_roots_digest": manifest.runtime_state_roots_digest,
            "manifest_digest": manifest_digest,
            "prior_active_generation": prior_active,
            "approval": approval,
            "state": state_value,
        })
    }

    fn activation_approval(&self, manifest: &CandidateManifest) -> Value {
        let generation = manifest.runtime_launch.authority_generation.value();
        json!({
            "approval_ref": format!("evidence:activation:{}", manifest.generation.as_str()),
            "transaction_id": format!("transaction:{}", manifest.generation.as_str()),
            "installer_plan_digest": self.digest(generation),
            "generation": manifest.generation,
            "candidate_manifest_digest": sha256_hex(
                &serde_json::to_vec(manifest)
                    .unwrap_or_else(|error| panic!("serialize activation manifest: {error}"))
            ),
            "runtime_descriptor_digest": manifest.runtime_launch.descriptor_digest,
            "required_owner": "owner:installation",
            "signature_ref": manifest.signature_ref,
            "authority_descriptor_path": manifest.runtime_launch.authority_descriptor_path,
            "authority_descriptor_digest": manifest.runtime_launch.authority_descriptor_digest,
            "authority_generation": manifest.runtime_launch.authority_generation,
            "authority_state_fence": manifest.runtime_launch.authority_state_fence,
        })
    }

    fn service_approval(&self, manifest: &CandidateManifest, host: bool) -> Value {
        let generation = manifest.runtime_launch.authority_generation.value();
        let role_name = if host { "HOST" } else { "WATCHDOG" };
        let service_name = if host {
            ELIOT_HOST_SERVICE_NAME
        } else {
            ELIOT_WATCHDOG_SERVICE_NAME
        };
        let display_name = if host {
            ELIOT_HOST_SERVICE_DISPLAY_NAME
        } else {
            ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME
        };
        let executable_path = if host {
            self.artifact_root.join("eliot-host.exe")
        } else {
            self.artifact_root.join("eliot-watchdog.exe")
        };
        let nonce = if host {
            self.digest(generation + 100)
        } else {
            self.digest(generation + 200)
        };
        let bootstrap = ServiceBootstrapArguments::new(
            PathBuf::from(manifest.runtime_launch.authority_descriptor_path.as_str()),
            manifest.runtime_launch.authority_descriptor_digest.as_str(),
            manifest
                .runtime_launch
                .installation_epoch
                .installation
                .as_str(),
            generation,
            std::iter::empty::<String>(),
        )
        .and_then(|value| {
            value.with_host_state_root(PathBuf::from(
                manifest
                    .runtime_launch
                    .runtime_state_roots
                    .host_state_root
                    .as_str(),
            ))
        })
        .and_then(|value| value.with_registration_nonce(&nonce))
        .unwrap_or_else(|error| panic!("invalid service approval bootstrap: {error}"));
        let request = ServiceRegistrationRequest::with_bootstrap(
            service_name,
            display_name,
            executable_path.clone(),
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
            bootstrap,
        )
        .unwrap_or_else(|error| panic!("invalid service approval request: {error}"));
        json!({
            "transaction_id": format!("transaction:{}", manifest.generation.as_str()),
            "generation": manifest.generation,
            "effect_id": format!("effect:{role_name}:{}", manifest.generation.as_str()),
            "role": role_name,
            "service_name": service_name,
            "executable_path": executable_path,
            "account": "LOCAL_SERVICE",
            "automatic_start": true,
            "service_bootstrap": {
                "descriptor_path": manifest.runtime_launch.authority_descriptor_path,
                "descriptor_digest": manifest.runtime_launch.authority_descriptor_digest,
                "installation_id": manifest.runtime_launch.installation_epoch.installation,
                "plan_generation": generation,
                "host_state_root": manifest.runtime_launch.runtime_state_roots.host_state_root,
            },
            "registration_nonce": nonce,
            "configuration_digest": request.expected_configuration_digest(),
        })
    }

    fn manifest(&self, generation: u64) -> CandidateManifest {
        let roots = RuntimeStateRoots::derive_profiled(
            InstallationProfile::SystemService,
            PlatformHandle::new(self.program_data.to_string_lossy().into_owned())
                .unwrap_or_else(|error| panic!("invalid ProgramData handle: {error}")),
            &self.installation_key,
        )
        .unwrap_or_else(|error| panic!("derive fixture runtime roots: {error}"));
        let generation_handle = handle(format!("generation-{generation}"));
        let authority_descriptor_path = self.authority_descriptor_path(generation);
        let config_path = self
            .artifact_root
            .join(format!("generation-{generation}.json"));
        let authority_digest = self.digest(generation);
        let kernel_digest = self.digest(10);
        let eliotd_digest = self.digest(11);
        let eliotd_config_digest = self.digest(12);
        let eliotd_descriptor_digest = self.digest(13);
        let store_bridge_digest = self.digest(14);
        let store_bootstrap_digest = self.digest(15);
        let canonical_store_digest = self.digest(16);
        let host_digest = self.digest(17);
        let watchdog_digest = self.digest(18);
        let kernel_path = self.artifact_root.join("eliot-kernel.exe");
        let eliotd_path = self.artifact_root.join("eliotd.exe");
        let eliotd_config_path = self
            .artifact_root
            .join(format!("eliotd-governor-{generation}.json"));
        let eliotd_descriptor_path = self.artifact_root.join(format!("eliotd-{generation}.json"));
        let store_bridge_path = self.artifact_root.join("eliot-store-surreal.exe");
        let store_bootstrap_path = self
            .artifact_root
            .join(format!("store-bootstrap-{generation}.json"));
        let canonical_store_path = self.artifact_root.join("surreal.exe");
        let host_path = self.artifact_root.join("eliot-host.exe");
        let watchdog_path = self.artifact_root.join("eliot-watchdog.exe");
        let config_handle = path_handle(&config_path);
        let mut runtime_launch = RuntimeLaunchDescriptor {
            profile: InstallationProfile::SystemService,
            portable_root: None,
            installation_epoch: InstallationEpoch {
                installation: handle(self.installation_key.clone()),
                lineage_id: handle(format!("lineage-{}", &self.installation_key[..16])),
                sequence: 1,
            },
            generation: generation_handle,
            authority_generation: ResourceGeneration::new(generation)
                .unwrap_or_else(|error| panic!("invalid authority generation: {error}")),
            authority_state_fence: StateFence::new(
                AuthorityEpoch::genesis(),
                ResourceGeneration::new(generation)
                    .unwrap_or_else(|error| panic!("invalid state generation: {error}")),
            ),
            authority_descriptor_path: path_handle(&authority_descriptor_path),
            authority_descriptor_digest: handle(authority_digest),
            runtime_state_roots: roots.clone(),
            kernel_work_root: roots.kernel_work_root.clone(),
            kernel_artifact_digest: handle(kernel_digest.clone()),
            eliotd_executable_path: path_handle(&eliotd_path),
            eliotd_artifact_digest: handle(eliotd_digest),
            eliotd_config_path: path_handle(&eliotd_config_path),
            eliotd_config_digest: handle(eliotd_config_digest),
            eliotd_descriptor_path: path_handle(&eliotd_descriptor_path),
            eliotd_descriptor_digest: handle(eliotd_descriptor_digest),
            eliotd_launch_nonce: handle(format!("eliotd:{}", "a".repeat(32))),
            store_config_path: config_handle.clone(),
            store_credential_target: handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            store_bridge_executable_path: path_handle(&store_bridge_path),
            store_bridge_artifact_digest: handle(store_bridge_digest.clone()),
            store_bootstrap_descriptor_path: path_handle(&store_bootstrap_path),
            store_bootstrap_descriptor_digest: handle(store_bootstrap_digest),
            canonical_store_executable_path: path_handle(&canonical_store_path),
            canonical_store_artifact_digest: handle(canonical_store_digest.clone()),
            kernel_arguments: Vec::new(),
            store_bridge_arguments: Vec::new(),
            canonical_store_arguments: vec![
                handle("start"),
                handle("--no-banner"),
                handle("--bind"),
                handle("127.0.0.1:8000"),
                handle("--temporary-directory"),
                roots.store_temp_root.clone(),
                handle("--log-file-enabled"),
                handle("--log-file-path"),
                roots.store_work_root.clone(),
                handle("--log-file-name"),
                handle("surrealdb.log"),
                handle(format!(
                    "surrealkv://{}",
                    roots.store_data_root.as_str().replace('\\', "/")
                )),
            ],
            host_executable_path: path_handle(&host_path),
            host_artifact_digest: handle(host_digest),
            watchdog_executable_path: path_handle(&watchdog_path),
            watchdog_artifact_digest: handle(watchdog_digest),
            descriptor_digest: handle("0".repeat(64)),
        };
        runtime_launch.kernel_arguments = vec![
            handle("--work-root"),
            runtime_launch.kernel_work_root.clone(),
            handle("--store-bootstrap"),
            runtime_launch.store_bootstrap_descriptor_path.clone(),
            handle("--store-bootstrap-sha256"),
            runtime_launch.store_bootstrap_descriptor_digest.clone(),
            handle("--authority-descriptor"),
            runtime_launch.authority_descriptor_path.clone(),
            handle("--authority-descriptor-sha256"),
            runtime_launch.authority_descriptor_digest.clone(),
            handle("--kernel-artifact-sha256"),
            runtime_launch.kernel_artifact_digest.clone(),
            handle("--eliotd-descriptor"),
            runtime_launch.eliotd_descriptor_path.clone(),
            handle("--eliotd-descriptor-sha256"),
            runtime_launch.eliotd_descriptor_digest.clone(),
        ];
        runtime_launch.store_bridge_arguments =
            vec![handle("--config"), runtime_launch.store_config_path.clone()];
        runtime_launch = runtime_launch
            .with_computed_digest()
            .unwrap_or_else(|error| panic!("seal fixture descriptor: {error}"));
        CandidateManifest {
            generation: runtime_launch.generation.clone(),
            components: vec![handle("component:kernel"), handle("component:store")],
            kernel_artifact_digest: runtime_launch.kernel_artifact_digest.clone(),
            store_bridge_artifact_digest: runtime_launch.store_bridge_artifact_digest.clone(),
            canonical_store_artifact_digest: runtime_launch.canonical_store_artifact_digest.clone(),
            host_artifact_digest: runtime_launch.host_artifact_digest.clone(),
            kernel_executable_path: path_handle(&kernel_path),
            store_bridge_executable_path: runtime_launch.store_bridge_executable_path.clone(),
            canonical_store_executable_path: runtime_launch.canonical_store_executable_path.clone(),
            host_executable_path: runtime_launch.host_executable_path.clone(),
            config_path: config_handle,
            dependency_closure_refs: vec![handle("evidence:dependency-closure")],
            license_refs: vec![handle("evidence:licenses")],
            config_digest: handle(self.digest(19)),
            store_credential_target: runtime_launch.store_credential_target.clone(),
            supervision_key_fingerprint: handle(self.digest(20)),
            signature_ref: handle(format!("evidence:signature:generation-{generation}")),
            runtime_state_roots_digest: roots.roots_digest.clone(),
            runtime_launch,
        }
    }

    fn rebind_manifest(&self, mut manifest: CandidateManifest) -> CandidateManifest {
        manifest.generation = manifest.runtime_launch.generation.clone();
        manifest.runtime_state_roots_digest = manifest
            .runtime_launch
            .runtime_state_roots
            .roots_digest
            .clone();
        manifest = manifest
            .runtime_launch
            .clone()
            .with_computed_digest()
            .map(|runtime_launch| CandidateManifest {
                runtime_launch,
                ..manifest
            })
            .unwrap_or_else(|error| panic!("rebind ambiguous manifest: {error}"));
        manifest
    }

    fn authority_descriptor_path(&self, generation: u64) -> PathBuf {
        self.artifact_root
            .join(format!("authority-{generation}.json"))
    }

    fn digest(&self, value: u64) -> String {
        let nibble = b"0123456789abcdef"[(value % 16) as usize] as char;
        std::iter::repeat_n(nibble, 64).collect()
    }

    fn ensure_registry_file(&self) {
        if self.registry_path.exists() {
            return;
        }
        let primitive = WindowsInstallerRootPrimitive::new();
        primitive
            .create_protected_file(&self.root_spec, &self.registry_path, |_| Ok(Vec::new()))
            .unwrap_or_else(|error| {
                panic!(
                    "create protected registry fixture {}: {error}",
                    self.registry_path.display()
                )
            });
        let database = Database::create(&self.registry_path)
            .unwrap_or_else(|error| panic!("initialize registry fixture database: {error}"));
        drop(database);
    }

    fn write_table(&self, definition: TableDefinition<&str, &[u8]>, bytes: &[u8]) {
        self.ensure_registry_file();
        let database = Database::open(&self.registry_path)
            .unwrap_or_else(|error| panic!("open registry fixture database: {error}"));
        let write = database
            .begin_write()
            .unwrap_or_else(|error| panic!("begin registry fixture write: {error}"));
        {
            let mut table = write
                .open_table(definition)
                .unwrap_or_else(|error| panic!("open registry fixture table: {error}"));
            table
                .insert("registry", bytes)
                .unwrap_or_else(|error| panic!("insert registry fixture row: {error}"));
        }
        write
            .commit()
            .unwrap_or_else(|error| panic!("commit registry fixture: {error}"));
    }
}

impl Default for RegistryFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RegistryFixture {
    fn drop(&mut self) {
        let installation_parent = self.host_root.parent().and_then(Path::parent);
        let _ = std::fs::remove_dir_all(self.host_root.parent().unwrap_or(&self.host_root));
        if let Some(path) = installation_parent {
            let _ = std::fs::remove_dir(path);
        }
        let _ = std::fs::remove_dir_all(&self.artifact_root);
    }
}

fn handle(value: impl Into<String>) -> PlatformHandle {
    PlatformHandle::new(value.into())
        .unwrap_or_else(|error| panic!("invalid fixture handle: {error}"))
}

fn path_handle(path: &Path) -> PlatformHandle {
    handle(path.to_string_lossy().into_owned())
}
