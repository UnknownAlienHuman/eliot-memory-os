// Integration fixtures fail immediately when static paths or emitted JSON are invalid.
#![allow(clippy::expect_used)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use eliot_installation::{
    AuthorityEpoch, CandidateManifest, INSTALLATION_TRANSACTION_WIRE_VERSION, InstallationEpoch,
    InstallationProfile, InstallationTransaction, InstallerAclPrincipal, InstallerEffectPlan,
    ManagedEnvironmentAction, ManagedEnvironmentChangeRequest, PHASE_B_PENDING_MARKER,
    PlannedChange, RedbInstallationTransactionStore, ResourceGeneration, RuntimeLaunchDescriptor,
    RuntimeStateRoots, StateFence, SupervisionAuthorityBinding, UserOwnedRootLease,
    parse_installation_transaction_id,
};
#[cfg(windows)]
use eliot_platform_windows::protected_program_data_root;
use serde_json::Value;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_owned()
}

fn assert_installation_error(output: &Value, code: &str) {
    assert_eq!(output["status"], "ERROR");
    assert_eq!(output["code"], code);
    assert_eq!(output["completed"], false);
    assert_eq!(output["scope"], "bounded_all_effects_or_exact_rollback");
    assert!(output["detail"].is_string());
}

#[cfg(windows)]
#[allow(clippy::cast_possible_truncation)]
fn minimal_pe(label: &str) -> Vec<u8> {
    let pe_offset = 0x80_usize;
    let optional_size = 0xf0_usize;
    let section_end = pe_offset + 4 + 20 + optional_size + 40;
    let mut bytes = vec![0_u8; section_end];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
    bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    let coff = pe_offset + 4;
    bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
    bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
    bytes[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
    bytes[coff + 18..coff + 20].copy_from_slice(&2_u16.to_le_bytes());
    bytes[coff + 20..coff + 22].copy_from_slice(&0x20b_u16.to_le_bytes());
    bytes.extend_from_slice(label.as_bytes());
    bytes
}

#[cfg(windows)]
#[test]
fn installation_generate_cli_is_retired_before_output_or_store_mutation() {
    let temp_root = std::env::temp_dir().join(format!(
        "eliot-installation-generate-{}",
        std::process::id()
    ));
    let portable_root = temp_root.join("portable");
    let source_root = temp_root.join("source");
    let other_cwd = temp_root.join("other-cwd");
    let output = temp_root.join("generated.json");
    let store = temp_root.join("transaction.redb");
    fs::create_dir_all(&portable_root).expect("create portable root");
    fs::create_dir_all(&source_root).expect("create source root");
    fs::create_dir_all(&other_cwd).expect("create unrelated cwd");
    drop(UserOwnedRootLease::open_existing(&portable_root).expect("protect portable root"));
    for (name, executable) in [
        ("eliot-host.exe", true),
        ("eliot-watchdog.exe", true),
        ("eliot-kernel.exe", true),
        ("eliot-store-surreal.exe", true),
        ("surreal.exe", true),
        ("eliotd.exe", true),
        ("generation.json", false),
        ("eliotd-governor.json", false),
        ("eliotd.json", false),
    ] {
        let bytes = if executable {
            minimal_pe(name)
        } else {
            format!("descriptor:{name}").into_bytes()
        };
        fs::write(source_root.join(name), bytes).expect("write source role");
    }
    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&other_cwd)
        .args([
            "installation",
            "generate",
            "--source-root",
            source_root.to_str().expect("source root is utf8"),
            "--profile",
            "portable_dev",
            "--profile-anchor-root",
            portable_root.to_str().expect("portable root is utf8"),
            "--installation",
            "installation:cli",
            "--lineage-id",
            "lineage:cli",
            "--sequence",
            "1",
            "--generation",
            "candidate",
            "--staging-root",
            portable_root.to_str().expect("staging root is utf8"),
            "--transaction-id",
            "transaction:cli",
            "--minimum-store-available-bytes",
            "1",
            "--recovery-command",
            "eliot installation recover --transaction-id transaction:cli",
            "--output",
            output.to_str().expect("output is utf8"),
            "--store",
            store.to_str().expect("store is utf8"),
        ])
        .output()
        .expect("run retired generation command");
    assert!(
        !result.status.success(),
        "retired generation unexpectedly succeeded: {}",
        String::from_utf8_lossy(&result.stdout),
    );
    let summary: Value = serde_json::from_slice(&result.stdout).expect("generation summary JSON");
    assert_installation_error(&summary, "INSTALLATION_GENERATE_RETIRED");
    assert!(
        summary["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("materialize-source-bundle"))
    );
    assert!(
        !output.exists(),
        "retired Generate created an output artifact"
    );
    assert!(!store.exists(), "retired Generate created a durable store");
    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn snapshot_binds_explicit_root_when_process_starts_in_non_git_directory() {
    let root = repository_root();
    let temp_root =
        std::env::temp_dir().join(format!("eliot-system-snapshot-{}", std::process::id()));
    let output = temp_root.join("snapshot.json");
    fs::create_dir_all(&temp_root).expect("create non-git cwd");

    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "system",
            "snapshot",
            "--repo-root",
            root.to_str().expect("root is utf8"),
            "--output",
            output.to_str().expect("output is utf8"),
        ])
        .output()
        .expect("run snapshot command");

    assert!(
        result.status.success(),
        "snapshot failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout: Value = serde_json::from_slice(&result.stdout).expect("snapshot JSON on stdout");
    let file: Value = serde_json::from_slice(&fs::read(&output).expect("snapshot artifact"))
        .expect("snapshot JSON on disk");
    assert_eq!(stdout, file);
    assert_eq!(
        file.pointer("/receipt/snapshot_sha256")
            .and_then(Value::as_str),
        file.pointer("/snapshot/snapshot_sha256")
            .and_then(Value::as_str)
    );
    assert_eq!(
        file.pointer("/snapshot/selected_repository_root")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase),
        Some(
            fs::canonicalize(&root)
                .expect("canonical root")
                .to_string_lossy()
                .to_ascii_lowercase()
        )
    );
    assert_eq!(
        file.pointer("/snapshot/records")
            .and_then(Value::as_array)
            .and_then(|records| {
                records.iter().find(|record| {
                    record.get("key").and_then(Value::as_str) == Some("runtime.status")
                })
            })
            .and_then(|record| record.get("value"))
            .and_then(Value::as_str),
        Some("NOT_RUNNING")
    );

    let second = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "system",
            "snapshot",
            "--repo-root",
            root.to_str().expect("root is utf8"),
            "--output",
            output.to_str().expect("output is utf8"),
        ])
        .output()
        .expect("rerun snapshot command");
    assert!(
        !second.status.success(),
        "existing artifact was overwritten"
    );

    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn installation_status_requires_existing_host_state_root() {
    let temp_root =
        std::env::temp_dir().join(format!("eliot-installation-status-{}", std::process::id()));
    fs::create_dir_all(&temp_root).expect("create status fixture");
    let host_state_root = temp_root.join("missing-host");
    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "installation",
            "status",
            "--host-state-root",
            host_state_root.to_str().expect("Host state root is utf8"),
        ])
        .output()
        .expect("run status command");

    assert!(!result.status.success());
    assert!(!host_state_root.exists(), "status created a missing root");
    let output: Value = serde_json::from_slice(&result.stdout).expect("status JSON error");
    assert_installation_error(&output, "INSTALLATION_STATUS_UNAVAILABLE");
    let _ = fs::remove_dir_all(temp_root);
}

#[cfg(windows)]
#[test]
fn runtime_status_json_is_a_production_subprocess_and_never_creates_state() {
    let host_state_root = protected_program_data_root()
        .expect("ProgramData root")
        .join(format!(
            "eliot-runtime-status-cli-proof-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
    fs::create_dir_all(&host_state_root).expect("create existing Host root fixture");
    let observed_files = [
        "installation-registry.redb",
        "watchdog-admission.json",
        "supervision-lease.json",
        "host-state-journal.redb",
    ];
    let before: Vec<_> = observed_files
        .iter()
        .map(|name| host_state_root.join(name).exists())
        .collect();
    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .args([
            "runtime",
            "status",
            "--json",
            "--host-state-root",
            host_state_root.to_str().expect("Host root is utf8"),
        ])
        .output()
        .expect("run production runtime status subprocess");

    assert_eq!(
        result.status.code(),
        Some(2),
        "missing evidence must not be live"
    );
    let output: Value = serde_json::from_slice(&result.stdout).expect("runtime status JSON");
    assert_eq!(output["contract"], "eliot.runtime.live");
    assert_eq!(output["status"], "NOT_HEALTHY");
    assert_eq!(output["deadline_exceeded"], false);
    assert_eq!(output["completed"], false);
    assert_eq!(
        output["recovery_command"],
        "eliot installation recover --help"
    );
    assert!(output["ors"]["state"].is_object());
    let after: Vec<_> = observed_files
        .iter()
        .map(|name| host_state_root.join(name).exists())
        .collect();
    assert_eq!(
        before, after,
        "runtime status created or changed Host state"
    );
    let _ = fs::remove_dir_all(&host_state_root);
}

#[test]
fn runtime_status_json_reports_deadline_exceeded() {
    let host_state_root = std::env::temp_dir().join(format!(
        "eliot-runtime-status-timeout-{}",
        std::process::id()
    ));
    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .args([
            "runtime",
            "status",
            "--json",
            "--host-state-root",
            host_state_root.to_str().expect("Host root is utf8"),
            "--deadline-ms",
            "0",
        ])
        .output()
        .expect("run deadline-bounded runtime status subprocess");

    assert_eq!(result.status.code(), Some(2));
    let output: Value = serde_json::from_slice(&result.stdout).expect("timeout JSON");
    assert_eq!(output["status"], "ERROR");
    assert_eq!(output["code"], "RUNTIME_STATUS_TIMEOUT");
    assert_eq!(output["deadline_exceeded"], true);
    assert_eq!(output["completed"], false);
    assert!(!host_state_root.exists(), "timeout created the Host root");
}

#[cfg(windows)]
#[test]
fn installation_status_reports_missing_registry_under_retained_root() {
    let temp_root = std::env::temp_dir().join(format!(
        "eliot-installation-status-cwd-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_root).expect("create status cwd fixture");
    let host_state_root = protected_program_data_root()
        .expect("ProgramData root")
        .join("Eliot");
    let registry = host_state_root.join("installation-registry.redb");
    let expected_code = match fs::symlink_metadata(&host_state_root) {
        Ok(metadata) if metadata.is_dir() => "INSTALLATION_STATUS_INVALID",
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            "INSTALLATION_STATUS_UNAVAILABLE"
        }
        Ok(_) | Err(_) => "INSTALLATION_STATUS_INVALID",
    };
    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "installation",
            "status",
            "--host-state-root",
            host_state_root.to_str().expect("Host state root is utf8"),
        ])
        .output()
        .expect("run missing registry status command");

    assert!(!result.status.success());
    assert!(!registry.exists(), "status created a missing registry");
    let output: Value = serde_json::from_slice(&result.stdout).expect("status JSON error");
    assert_installation_error(&output, expected_code);
    let _ = fs::remove_dir_all(temp_root);
}

#[cfg(windows)]
#[test]
fn installation_status_rejects_a_wrong_installation_root_without_creation() {
    let temp_root = std::env::temp_dir().join(format!(
        "eliot-installation-status-wrong-root-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_root).expect("create wrong-root cwd fixture");
    let wrong_host_root = protected_program_data_root()
        .expect("ProgramData root")
        .join("Eliot");
    let registry = wrong_host_root.join("installation-registry.redb");
    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "installation",
            "status",
            "--host-state-root",
            wrong_host_root.to_str().expect("wrong root is utf8"),
        ])
        .output()
        .expect("run wrong-root status command");

    assert!(!result.status.success());
    assert!(!registry.exists(), "status created a wrong-root registry");
    let output: Value = serde_json::from_slice(&result.stdout).expect("status JSON error");
    assert_installation_error(&output, "INSTALLATION_STATUS_INVALID");
    let _ = fs::remove_dir_all(temp_root);
}

#[cfg(windows)]
#[test]
fn installation_status_rejects_legacy_host_root_without_reading_it() {
    let host_state_root = protected_program_data_root()
        .expect("ProgramData root")
        .join("Eliot")
        .join("host");
    let expected_code = match fs::symlink_metadata(&host_state_root) {
        Ok(metadata) if metadata.is_dir() => "INSTALLATION_STATUS_INVALID",
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            "INSTALLATION_STATUS_UNAVAILABLE"
        }
        Ok(_) | Err(_) => "INSTALLATION_STATUS_INVALID",
    };
    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .args([
            "installation",
            "status",
            "--host-state-root",
            host_state_root.to_str().expect("legacy Host root is utf8"),
        ])
        .output()
        .expect("run legacy Host root status command");

    assert!(!result.status.success());
    let output: Value = serde_json::from_slice(&result.stdout).expect("legacy status JSON error");
    assert_installation_error(&output, expected_code);
}

#[test]
fn installation_status_rejects_removed_registry_selector() {
    let temp_root = std::env::temp_dir().join(format!(
        "eliot-installation-status-registry-selector-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_root).expect("create removed-selector fixture");
    let registry = temp_root.join("installation-registry.redb");
    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "installation",
            "status",
            "--registry",
            registry.to_str().expect("registry is utf8"),
        ])
        .output()
        .expect("run removed-selector status command");

    assert!(!result.status.success());
    assert!(!registry.exists(), "removed selector created a registry");
    assert!(result.stdout.is_empty(), "removed selector emitted JSON");
    assert!(String::from_utf8_lossy(&result.stderr).contains("unexpected argument"));
    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn installation_create_rejects_migration_before_creating_store() {
    let temp_root =
        std::env::temp_dir().join(format!("eliot-installation-create-{}", std::process::id()));
    fs::create_dir_all(&temp_root).expect("create create fixture");
    let input = temp_root.join("plan.json");
    let store = temp_root.join("transactions.redb");
    fs::write(
        &input,
        r#"{"transaction_wire_version":{"major":5,"minor":0,"patch":0}}"#,
    )
    .expect("write migration fixture");

    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "installation",
            "create",
            "--input",
            input.to_str().expect("input is utf8"),
            "--store",
            store.to_str().expect("store is utf8"),
        ])
        .output()
        .expect("run create command");

    assert!(!result.status.success());
    let output: Value = serde_json::from_slice(&result.stdout).expect("create JSON error");
    assert_installation_error(&output, "INSTALLATION_CREATE_PRODUCTION_DISABLED");
    assert!(!store.exists(), "rejected input created a durable store");
    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn installation_create_raw_import_is_not_a_production_constructor() {
    let temp_root = std::env::temp_dir().join(format!(
        "eliot-installation-create-raw-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_root).expect("create raw-create fixture");
    let input = temp_root.join("transaction.json");
    let store = temp_root.join("transactions.redb");
    fs::write(&input, br#"{"not":"a trusted planner artifact"}"#)
        .expect("write raw-create fixture");

    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "installation",
            "create",
            "--input",
            input.to_str().expect("input is utf8"),
            "--store",
            store.to_str().expect("store is utf8"),
        ])
        .output()
        .expect("run raw-create command");

    assert!(!result.status.success());
    let output: Value = serde_json::from_slice(&result.stdout).expect("raw-create JSON error");
    assert_installation_error(&output, "INSTALLATION_CREATE_PRODUCTION_DISABLED");
    assert!(!store.exists(), "raw import created a durable store");
    let _ = fs::remove_dir_all(temp_root);
}

fn fixture_handle(value: impl Into<String>) -> eliot_installation::PlatformHandle {
    parse_installation_transaction_id(value).expect("valid fixture handle")
}

fn fixture_path(root: &Path, name: &str) -> eliot_installation::PlatformHandle {
    fixture_handle(root.join(name).to_string_lossy().into_owned())
}

#[allow(
    clippy::too_many_lines,
    reason = "the positive CLI fixture spells out the constructor's complete durable contract"
)]
fn portable_cli_transaction(root: &Path) -> InstallationTransaction {
    let portable_root = fixture_handle(root.to_string_lossy().into_owned());
    let runtime_state_roots =
        RuntimeStateRoots::derive_portable(portable_root.clone()).expect("portable roots");
    let installation_epoch = InstallationEpoch {
        installation: fixture_handle("installation:cli-positive"),
        lineage_id: fixture_handle("lineage:cli-positive"),
        sequence: 1,
    };
    let generation = fixture_handle("generation:cli-positive");
    let mut runtime_launch = RuntimeLaunchDescriptor {
        profile: InstallationProfile::PortableDev,
        portable_root: Some(portable_root.clone()),
        installation_epoch: installation_epoch.clone(),
        generation: generation.clone(),
        authority_generation: ResourceGeneration::genesis(),
        authority_state_fence: StateFence::new(
            AuthorityEpoch::genesis(),
            ResourceGeneration::genesis(),
        ),
        supervision_authority: SupervisionAuthorityBinding::Pending {
            supervision_lease_scope_id: fixture_handle(format!(
                "eliot-supervision-scope:v1:{}:{}",
                installation_epoch.installation, generation
            )),
        },
        authority_descriptor_path: fixture_path(root, "authority.json"),
        authority_descriptor_digest: fixture_handle(PHASE_B_PENDING_MARKER),
        runtime_state_roots: runtime_state_roots.clone(),
        kernel_work_root: runtime_state_roots.kernel_work_root.clone(),
        kernel_artifact_digest: fixture_handle("a".repeat(64)),
        eliotd_executable_path: fixture_path(root, "eliotd.exe"),
        eliotd_artifact_digest: fixture_handle("8".repeat(64)),
        eliotd_config_path: fixture_path(root, "eliotd-governor.json"),
        eliotd_config_digest: fixture_handle("4".repeat(64)),
        eliotd_descriptor_path: fixture_path(root, "eliotd.json"),
        eliotd_descriptor_digest: fixture_handle("9".repeat(64)),
        eliotd_launch_nonce: fixture_handle(format!("eliotd:{}", "a".repeat(32))),
        store_config_path: fixture_path(root, "generation.json"),
        store_credential_target: fixture_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
        store_bridge_executable_path: fixture_path(root, "eliot-store-surreal.exe"),
        store_bridge_artifact_digest: fixture_handle("1".repeat(64)),
        store_bootstrap_descriptor_path: fixture_path(root, "store-bootstrap.json"),
        store_bootstrap_descriptor_digest: fixture_handle(PHASE_B_PENDING_MARKER),
        canonical_store_executable_path: fixture_path(root, "surreal.exe"),
        canonical_store_artifact_digest: fixture_handle("5".repeat(64)),
        kernel_arguments: vec![
            fixture_handle("--work-root"),
            runtime_state_roots.kernel_work_root.clone(),
            fixture_handle("--store-bootstrap"),
            fixture_path(root, "store-bootstrap.json"),
            fixture_handle("--store-bootstrap-sha256"),
            fixture_handle(PHASE_B_PENDING_MARKER),
            fixture_handle("--authority-descriptor"),
            fixture_path(root, "authority.json"),
            fixture_handle("--authority-descriptor-sha256"),
            fixture_handle(PHASE_B_PENDING_MARKER),
            fixture_handle("--kernel-artifact-sha256"),
            fixture_handle("a".repeat(64)),
            fixture_handle("--eliotd-descriptor"),
            fixture_path(root, "eliotd.json"),
            fixture_handle("--eliotd-descriptor-sha256"),
            fixture_handle("9".repeat(64)),
        ],
        store_bridge_arguments: vec![
            fixture_handle("--portable-dev-root"),
            portable_root.clone(),
            fixture_handle("--config"),
            fixture_path(root, "generation.json"),
        ],
        canonical_store_arguments: vec![
            fixture_handle("start"),
            fixture_handle("--no-banner"),
            fixture_handle("--bind"),
            fixture_handle("127.0.0.1:8000"),
            fixture_handle("--temporary-directory"),
            runtime_state_roots.store_temp_root.clone(),
            fixture_handle("--log-file-enabled"),
            fixture_handle("--log-file-path"),
            runtime_state_roots.store_work_root.clone(),
            fixture_handle("--log-file-name"),
            fixture_handle("surrealdb.log"),
            fixture_handle(format!(
                "surrealkv://{}",
                runtime_state_roots
                    .store_data_root
                    .as_str()
                    .replace('\\', "/")
            )),
        ],
        host_executable_path: fixture_path(root, "eliot-host.exe"),
        host_artifact_digest: fixture_handle("8".repeat(64)),
        watchdog_executable_path: fixture_path(root, "eliot-watchdog.exe"),
        watchdog_artifact_digest: fixture_handle("4".repeat(64)),
        descriptor_digest: fixture_handle("0".repeat(64)),
    };
    runtime_launch = runtime_launch
        .with_computed_digest()
        .expect("sealed runtime launch");
    let candidate_manifest = CandidateManifest {
        generation: generation.clone(),
        components: vec![
            fixture_handle("component:kernel"),
            fixture_handle("component:store"),
        ],
        kernel_artifact_digest: fixture_handle("a".repeat(64)),
        store_bridge_artifact_digest: fixture_handle("1".repeat(64)),
        canonical_store_artifact_digest: fixture_handle("5".repeat(64)),
        host_artifact_digest: fixture_handle("8".repeat(64)),
        kernel_executable_path: fixture_path(root, "eliot-kernel.exe"),
        store_bridge_executable_path: fixture_path(root, "eliot-store-surreal.exe"),
        canonical_store_executable_path: fixture_path(root, "surreal.exe"),
        host_executable_path: fixture_path(root, "eliot-host.exe"),
        config_path: fixture_path(root, "generation.json"),
        dependency_closure_refs: vec![fixture_handle("evidence:dependency-closure")],
        license_refs: vec![fixture_handle("evidence:licenses")],
        config_digest: fixture_handle("2".repeat(64)),
        store_credential_target: fixture_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
        supervision_key_slot: fixture_handle("3".repeat(64)),
        signature_ref: fixture_handle("evidence:signature"),
        runtime_state_roots_digest: runtime_state_roots.roots_digest.clone(),
        runtime_launch,
    };
    let rollback_plan = fixture_handle("rollback:cli-positive");
    let request = ManagedEnvironmentChangeRequest {
        request_id: fixture_handle("request:cli-positive"),
        requester_and_reason: fixture_handle("requester:test"),
        action: ManagedEnvironmentAction::Install,
        target_family: fixture_handle("family:eliot"),
        exact_candidate: generation,
        expected_delta: fixture_handle("delta:installed"),
        source_assurance_refs: vec![fixture_handle("evidence:source-assurance")],
        affected_refs: Vec::new(),
        impact_class: fixture_handle("impact:test"),
        required_owner: fixture_handle("owner:installation"),
        rollback_plan: rollback_plan.clone(),
        verifier: fixture_handle("verifier:installation"),
        budget: fixture_handle("budget:test"),
        stop_condition: fixture_handle("stop:on-failure"),
    };
    let roots = [
        runtime_state_roots.installation_root.clone(),
        runtime_state_roots.host_state_root.clone(),
        runtime_state_roots.kernel_ors_root.clone(),
        runtime_state_roots.kernel_work_root.clone(),
        runtime_state_roots.store_data_root.clone(),
        runtime_state_roots.store_work_root.clone(),
        runtime_state_roots.store_temp_root.clone(),
        runtime_state_roots.watchdog_state_root.clone(),
    ];
    let mut planned_changes = Vec::new();
    let mut installer_effects = Vec::new();
    for (index, root) in roots.iter().enumerate() {
        let effect_id = fixture_handle(format!("effect:create-root-{index}"));
        planned_changes.push(PlannedChange {
            change_id: effect_id.clone(),
            target: root.clone(),
            precondition_refs: vec![fixture_handle(format!("evidence:precondition-{index}"))],
            postcondition_refs: vec![fixture_handle(format!("evidence:postcondition-{index}"))],
        });
        installer_effects.push(InstallerEffectPlan::CreateRoot {
            effect_id,
            root: root.clone(),
        });
    }
    for (index, root) in roots.iter().enumerate() {
        let effect_id = fixture_handle(format!("effect:apply-acl-{index}"));
        planned_changes.push(PlannedChange {
            change_id: effect_id.clone(),
            target: root.clone(),
            precondition_refs: vec![fixture_handle(format!("evidence:acl-precondition-{index}"))],
            postcondition_refs: vec![fixture_handle(format!(
                "evidence:acl-postcondition-{index}"
            ))],
        });
        installer_effects.push(InstallerEffectPlan::ApplyAcl {
            effect_id,
            root: root.clone(),
            principals: vec![
                InstallerAclPrincipal::CurrentUser,
                InstallerAclPrincipal::LocalSystem,
            ],
        });
    }
    InstallationTransaction::new(
        fixture_handle("transaction:cli-positive"),
        installation_epoch,
        InstallationProfile::PortableDev,
        request,
        None,
        candidate_manifest,
        fixture_path(root, "staging"),
        planned_changes,
        installer_effects,
        1,
        vec![fixture_handle("evidence:plan-precondition")],
        rollback_plan,
    )
    .expect("constructor-produced PortableDev transaction")
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the raw-import rejection assertion keeps the production CLI boundary evidence together"
)]
fn installation_cli_rejects_exact_diagnostic_transaction_import() {
    let temp_root = std::env::temp_dir().join(format!(
        "eliot-installation-cli-round-trip-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&temp_root).expect("create portable fixture root");
    let portable_root = temp_root.join("portable");
    fs::create_dir_all(&portable_root).expect("create nested portable fixture root");
    drop(UserOwnedRootLease::open_existing(&portable_root).expect("protect portable fixture root"));
    let transaction = portable_cli_transaction(&portable_root);
    let state_roots = &transaction
        .candidate_manifest
        .runtime_launch
        .runtime_state_roots;
    for root in [
        &state_roots.installation_root,
        &state_roots.host_state_root,
        &state_roots.kernel_ors_root,
        &state_roots.kernel_work_root,
        &state_roots.store_data_root,
        &state_roots.store_work_root,
        &state_roots.store_temp_root,
        &state_roots.watchdog_state_root,
    ] {
        if let Some(parent) = Path::new(root.as_str()).parent() {
            fs::create_dir_all(parent).expect("create effect parent contour");
        }
    }
    let input = temp_root.join("transaction.json");
    let store = temp_root.join("transaction.redb");
    let mut diagnostic =
        serde_json::to_vec_pretty(&transaction).expect("serialize constructor transaction");
    diagnostic.push(b'\n');
    fs::write(&input, diagnostic).expect("write exact diagnostic transaction projection");

    let plan = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "installation",
            "plan",
            "--input",
            input.to_str().expect("input is utf8"),
        ])
        .output()
        .expect("run plan command");
    assert!(
        plan.status.success(),
        "plan failed: {}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let planned: Value = serde_json::from_slice(&plan.stdout).expect("plan JSON");
    assert_eq!(
        planned["transaction_wire_version"],
        serde_json::to_value(INSTALLATION_TRANSACTION_WIRE_VERSION)
            .expect("serialize current transaction wire version")
    );

    let create = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "installation",
            "create",
            "--input",
            input.to_str().expect("input is utf8"),
            "--store",
            store.to_str().expect("store is utf8"),
        ])
        .output()
        .expect("run create command");
    assert!(!create.status.success());
    let created: Value = serde_json::from_slice(&create.stdout).expect("create JSON");
    assert_installation_error(&created, "INSTALLATION_CREATE_PRODUCTION_DISABLED");
    assert!(
        created["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("materialize-source-bundle --store"))
    );
    assert!(
        !store.exists(),
        "valid raw transaction created a durable store"
    );

    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn installation_apply_opens_only_existing_transaction_store() {
    let temp_root =
        std::env::temp_dir().join(format!("eliot-installation-apply-{}", std::process::id()));
    fs::create_dir_all(&temp_root).expect("create apply fixture");
    let store = temp_root.join("missing.redb");
    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "installation",
            "apply",
            "--store",
            store.to_str().expect("store is utf8"),
            "--transaction-id",
            "transaction-fixture",
        ])
        .output()
        .expect("run apply command");

    assert!(!result.status.success());
    let output: Value = serde_json::from_slice(&result.stdout).expect("apply JSON error");
    assert_installation_error(&output, "INSTALLATION_APPLY_UNAVAILABLE");
    assert!(!store.exists(), "apply created a missing transaction store");
    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn installation_apply_rejects_removed_raw_approval_ref_without_writing() {
    let temp_root = std::env::temp_dir().join(format!(
        "eliot-installation-raw-approval-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_root).expect("create raw approval fixture");
    let store = temp_root.join("missing.redb");
    let registry = temp_root.join("installation-registry.redb");
    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "installation",
            "apply",
            "--store",
            store.to_str().expect("store is utf8"),
            "--transaction-id",
            "transaction:raw-approval",
            "--approval-ref",
            "caller-shaped",
        ])
        .output()
        .expect("run raw approval command");

    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("--approval-ref"),
        "removed approval option was unexpectedly accepted: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!store.exists(), "raw approval created a transaction store");
    assert!(!registry.exists(), "raw approval created a registry");
    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn installation_transaction_status_reads_existing_store_without_inventing_transaction() {
    let temp_root = std::env::temp_dir().join(format!(
        "eliot-installation-transaction-status-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_root).expect("create transaction status fixture");
    let store_path = temp_root.join("transactions.redb");
    #[cfg(windows)]
    let (fixture_root, _portable_lease) = {
        let portable_root = temp_root.join("portable");
        fs::create_dir_all(&portable_root).expect("create portable fixture root");
        let lease = UserOwnedRootLease::open_existing(&portable_root)
            .expect("protect portable fixture root");
        (portable_root, lease)
    };
    #[cfg(not(windows))]
    let fixture_root = temp_root.clone();
    let transaction = portable_cli_transaction(&fixture_root);
    RedbInstallationTransactionStore::create_planned_at_exact_path(&store_path, &transaction)
        .expect("create planned transaction store");

    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "installation",
            "status",
            "--store",
            store_path.to_str().expect("store is utf8"),
            "--transaction-id",
            "transaction-fixture",
        ])
        .output()
        .expect("run transaction status command");

    assert!(!result.status.success());
    assert!(result.stdout.is_empty(), "removed selector emitted JSON");
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("unexpected argument"),
        "removed transaction-store selector was unexpectedly accepted: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(store_path.exists(), "status removed the transaction store");
    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn installation_remove_canary_is_a_non_mutating_blocker() {
    let temp_root = std::env::temp_dir().join(format!(
        "eliot-installation-remove-canary-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_root).expect("create remove-canary fixture");
    let store_path = temp_root.join("transactions.redb");
    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "installation",
            "remove-canary",
            "--store",
            store_path.to_str().expect("store is utf8"),
            "--transaction-id",
            "transaction-fixture",
        ])
        .output()
        .expect("run remove-canary command");

    assert!(!result.status.success());
    let output: Value = serde_json::from_slice(&result.stdout).expect("remove-canary JSON error");
    assert_installation_error(&output, "INSTALLATION_REMOVE_CANARY_UNSUPPORTED");
    assert!(
        !store_path.exists(),
        "remove-canary created a transaction store"
    );
    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn installation_plan_rejects_relative_input() {
    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .args(["installation", "plan", "--input", "plan.json"])
        .output()
        .expect("run plan command");

    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("path must be absolute"));
}

fn run_installation_plan_fixture(name: &str, fixture: &str) -> std::process::Output {
    let temp_root = std::env::temp_dir().join(format!(
        "eliot-installation-plan-{name}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_root).expect("create plan fixture");
    let input = temp_root.join("plan.json");
    fs::write(&input, fixture).expect("write plan fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "installation",
            "plan",
            "--input",
            input.to_str().expect("input is utf8"),
        ])
        .output()
        .expect("run plan command");
    let _ = fs::remove_dir_all(temp_root);
    output
}

#[test]
fn installation_plan_reports_missing_v9_discriminator_as_migration() {
    let result = run_installation_plan_fixture("missing-discriminator", "{}");

    assert!(!result.status.success());
    let output: Value = serde_json::from_slice(&result.stdout).expect("plan JSON error");
    assert_installation_error(&output, "INSTALLATION_PLAN_MIGRATION_REQUIRED");
    assert!(
        output["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("discriminator"))
    );
}

#[test]
fn installation_plan_reports_v5_discriminator_as_migration() {
    let result = run_installation_plan_fixture(
        "v5",
        r#"{"transaction_wire_version":{"major":5,"minor":0,"patch":0}}"#,
    );

    assert!(!result.status.success());
    let output: Value = serde_json::from_slice(&result.stdout).expect("plan JSON error");
    assert_installation_error(&output, "INSTALLATION_PLAN_MIGRATION_REQUIRED");
    assert!(
        output["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("wire 5.0.0"))
    );
}

#[test]
fn installation_plan_reports_malformed_v7_as_migration() {
    let result = run_installation_plan_fixture(
        "malformed-v7",
        r#"{"transaction_wire_version":{"major":7,"minor":0,"patch":0},"transaction_id":"malformed"}"#,
    );

    assert!(!result.status.success());
    let output: Value = serde_json::from_slice(&result.stdout).expect("plan JSON error");
    assert_installation_error(&output, "INSTALLATION_PLAN_MIGRATION_REQUIRED");
    assert!(
        output["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("wire 7.0.0"))
    );
}
