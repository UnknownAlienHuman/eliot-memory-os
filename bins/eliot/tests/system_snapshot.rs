// Integration fixtures fail immediately when static paths or emitted JSON are invalid.
#![allow(clippy::expect_used)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(windows)]
use eliot_contracts::sha256_hex;
use eliot_contracts::{EpochId, EpochLineageId};
use eliot_installation::{
    CANARY_REMOVAL_WIRE_VERSION, CanaryRemovalAction, CanaryRemovalBuildBinding,
    CanaryRemovalEffect, CanaryRemovalEffectBound, CanaryRemovalPlan, CanaryRemovalPlanEnvelope,
    CanaryRemovalPostcondition, CanaryRemovalQuiesce, CanaryRemovalResource,
    CanaryRemovalResourceOrigin, CandidateManifest, GenerationPackagePlanInput,
    GenerationPackagePlanner, INSTALLATION_ROOT_BINDING_VERSION,
    INSTALLATION_TRANSACTION_WIRE_VERSION, InstallationEpoch, InstallationProfile,
    InstallationRoots, InstallationTransaction, InstallerAclPrincipal, InstallerEffectPlan,
    ManagedEnvironmentAction, ManagedEnvironmentChangeRequest, PHASE_B_PENDING_MARKER,
    PackageArtifactDigest, PlannedChange, PlatformHandle, RedbInstallationRegistry,
    RedbInstallationTransactionStore, ResourceGeneration, RuntimeLaunchDescriptor,
    RuntimeStateRoots, StateFence, SupervisionAuthorityBinding, UserOwnedRootLease,
    canary_removal_operation_id, parse_installation_transaction_id,
};
#[cfg(windows)]
use eliot_installation::{
    InstallationError, InstallationTransactionStore, WindowsInstallationCoordinator,
};
#[cfg(windows)]
use eliot_platform_windows::{
    PackageFileSpec, PackageManifest, ProtectedRootLease, TrustedSourceBundle,
    prepare_protected_directory, protected_program_data_root,
};
use serde_json::Value;

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch")
}

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

fn assert_installation_not_healthy(
    output: &Value,
    host_state_root: &Path,
    registry_state: &str,
    registry_reason: &str,
) {
    assert_eq!(output["contract"], "eliot.runtime.live");
    assert_eq!(output["status"], "NOT_HEALTHY");
    assert_eq!(output["completed"], false);
    assert_eq!(output["deadline_exceeded"], false);
    assert_eq!(output["scope"], "bounded_all_effects_or_exact_rollback");
    assert_eq!(output["host_state_root"].as_str(), host_state_root.to_str());
    assert_eq!(
        output["components"]["installation_registry"][registry_state]["reason"].as_str(),
        Some(registry_reason)
    );
    let expected_gap = format!("registry: {registry_reason}");
    assert!(output["gaps"].as_array().is_some_and(|gaps| {
        gaps.iter()
            .any(|gap| gap.as_str() == Some(expected_gap.as_str()))
    }));
}

/// Lists the immediate entry names below one fixture directory.
///
/// Used to prove a refused owner command wrote nothing into its fixture.
fn fixture_entry_names(root: &Path) -> Vec<String> {
    fs::read_dir(root)
        .expect("read fixture directory")
        .map(|entry| {
            entry
                .expect("fixture directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
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
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let installation_key = format!("{:032x}{nonce:032x}", std::process::id());
    let installation_root = protected_program_data_root()
        .expect("ProgramData root")
        .join("Eliot")
        .join("installations")
        .join(installation_key);
    let host_state_root = installation_root.join("host");
    prepare_protected_directory(&host_state_root).expect("create retained Host root fixture");
    let registry = host_state_root.join("installation-registry.redb");
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
    assert_eq!(result.status.code(), Some(2));
    assert!(!registry.exists(), "status created a missing registry");
    let output: Value = serde_json::from_slice(&result.stdout).expect("status JSON error");
    assert_installation_not_healthy(
        &output,
        &host_state_root,
        "Missing",
        "registry does not exist; status never creates it",
    );
    let _ = fs::remove_dir_all(installation_root);
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
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let wrong_host_root = protected_program_data_root()
        .expect("ProgramData root")
        .join(format!(
            "eliot-installation-wrong-root-{}-{nonce}",
            std::process::id()
        ));
    prepare_protected_directory(&wrong_host_root).expect("create wrong retained root fixture");
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
    assert_eq!(result.status.code(), Some(2));
    assert!(!registry.exists(), "status created a wrong-root registry");
    let output: Value = serde_json::from_slice(&result.stdout).expect("status JSON error");
    assert_installation_not_healthy(
        &output,
        &wrong_host_root,
        "Unavailable",
        "installation_registry.host_root is invalid: retained root must end in Eliot/installations/<sha256-key>/host",
    );
    let _ = fs::remove_dir_all(wrong_host_root);
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

fn fixture_handle(value: impl Into<String>) -> PlatformHandle {
    parse_installation_transaction_id(value).expect("valid fixture handle")
}

fn fixture_path(root: &Path, name: &str) -> eliot_installation::PlatformHandle {
    fixture_handle(root.join(name).to_string_lossy().into_owned())
}

#[cfg(windows)]
#[allow(
    dead_code,
    reason = "retained planner fixture documents the rejected unjournaled StagePackage shape"
)]
fn planner_bound_status_transaction(root: &Path) -> InstallationTransaction {
    let source_root = root.join("source-bundle");
    fs::create_dir_all(&source_root).expect("create planner source root");
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
        fs::write(source_root.join(name), bytes).expect("write planner source role");
    }
    let source = TrustedSourceBundle::open(&source_root).expect("retain planner source");
    let observed = source.observe().expect("observe planner source");
    let generation = fixture_handle("cli-status");
    let role_order = [
        "eliot-host.exe",
        "eliot-watchdog.exe",
        "eliot-kernel.exe",
        "eliot-store-surreal.exe",
        "surreal.exe",
        "eliotd.exe",
        "generation.json",
        "eliotd-governor.json",
        "eliotd.json",
    ];
    let role_facts = role_order
        .iter()
        .map(|role| {
            observed
                .files
                .iter()
                .find(|file| file.relative_path == *role)
                .expect("planner role observation")
        })
        .collect::<Vec<_>>();
    let files = role_facts
        .iter()
        .map(|file| PackageArtifactDigest {
            relative_path: file.relative_path.clone(),
            expected_size: file.size,
            sha256: fixture_handle(file.sha256.clone()),
        })
        .collect::<Vec<_>>();
    let manifest = PackageManifest::new(
        generation.as_str(),
        role_facts
            .iter()
            .map(|file| {
                PackageFileSpec::new(&file.relative_path, file.pe.is_some(), file.size)
                    .expect("planner package file")
            })
            .collect(),
    )
    .expect("planner package manifest");
    let evidence = GenerationPackagePlanner::artifact_set_evidence_digest(&manifest, &files)
        .expect("planner evidence digest");
    let installation_epoch = InstallationEpoch {
        installation: fixture_handle("installation:cli-status"),
        lineage_id: fixture_handle("lineage:cli-status"),
        sequence: 1,
    };
    let input = GenerationPackagePlanInput {
        transaction_id: fixture_handle("transaction:cli-status"),
        installation_epoch,
        profile: InstallationProfile::PortableDev,
        profile_anchor_root: fixture_handle(root.to_string_lossy().into_owned()),
        installation_key: None,
        generation,
        source_root: fixture_handle(source_root.to_string_lossy().into_owned()),
        staging_root: fixture_path(root, "staging"),
        minimum_store_available_bytes: 1,
        recovery_command: fixture_handle("recover:cli-status"),
        agent_bridge_source: None,
    };
    GenerationPackagePlanner::plan_with_source_publication_binding(
        input,
        source.identity(),
        files,
        evidence,
    )
    .expect("planner-bound status transaction")
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
    let generation = fixture_handle("generation-cli-positive");
    let mut runtime_launch = RuntimeLaunchDescriptor {
        profile: InstallationProfile::PortableDev,
        profile_component: fixture_handle("eliot"),
        profile_version: fixture_handle("test-version"),
        profile_installation_key: None,
        profile_governed_roots: InstallationRoots {
            binding_version: INSTALLATION_ROOT_BINDING_VERSION,
            immutable_binaries: root
                .join("target")
                .join("eliot-dev")
                .join(generation.as_str())
                .to_string_lossy()
                .into_owned(),
            durable_data: root
                .join(".eliot-dev")
                .join("state")
                .to_string_lossy()
                .into_owned(),
            user_config: root
                .join(".eliot-dev")
                .join("config")
                .to_string_lossy()
                .into_owned(),
            user_cache: root
                .join(".eliot-dev")
                .join("cache")
                .to_string_lossy()
                .into_owned(),
            runtime_state_roots: runtime_state_roots.clone(),
        },
        portable_root: Some(portable_root.clone()),
        installation_epoch: installation_epoch.clone(),
        generation: generation.clone(),
        authority_generation: ResourceGeneration::genesis(),
        authority_state_fence: StateFence::new(test_epoch(1), ResourceGeneration::genesis()),
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
        protected_snapshot_digest: fixture_handle("a".repeat(64)),
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
            fixture_handle("--doctor-artifact-sha256"),
            fixture_handle("6".repeat(64)),
            fixture_handle("--testd-artifact-sha256"),
            fixture_handle("7".repeat(64)),
            fixture_handle("--native-worker-artifact-sha256"),
            fixture_handle("b".repeat(64)),
            fixture_handle("--user-broker-executable"),
            fixture_path(root, "eliot-user-broker.exe"),
            fixture_handle("--user-broker-artifact-sha256"),
            fixture_handle("e".repeat(64)),
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
        doctor_artifact_digest: fixture_handle("6".repeat(64)),
        testd_artifact_digest: fixture_handle("7".repeat(64)),
        native_worker_artifact_digest: fixture_handle("b".repeat(64)),
        user_broker_artifact_digest: fixture_handle("e".repeat(64)),
        wasm_host_artifact_digest: fixture_handle("f".repeat(64)),
        doctor_executable_path: fixture_path(root, "eliot-doctor.exe"),
        testd_executable_path: fixture_path(root, "eliot-testd.exe"),
        native_worker_executable_path: fixture_path(root, "eliot-native-worker.exe"),
        user_broker_executable_path: fixture_path(root, "eliot-user-broker.exe"),
        wasm_host_executable_path: fixture_path(root, "eliot-wasm-host.exe"),
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
        doctor_artifact_digest: fixture_handle("6".repeat(64)),
        testd_artifact_digest: fixture_handle("7".repeat(64)),
        native_worker_artifact_digest: fixture_handle("b".repeat(64)),
        user_broker_artifact_digest: fixture_handle("e".repeat(64)),
        wasm_host_artifact_digest: fixture_handle("f".repeat(64)),
        kernel_executable_path: fixture_path(root, "eliot-kernel.exe"),
        store_bridge_executable_path: fixture_path(root, "eliot-store-surreal.exe"),
        canonical_store_executable_path: fixture_path(root, "surreal.exe"),
        host_executable_path: fixture_path(root, "eliot-host.exe"),
        doctor_executable_path: fixture_path(root, "eliot-doctor.exe"),
        testd_executable_path: fixture_path(root, "eliot-testd.exe"),
        native_worker_executable_path: fixture_path(root, "eliot-native-worker.exe"),
        user_broker_executable_path: fixture_path(root, "eliot-user-broker.exe"),
        wasm_host_executable_path: fixture_path(root, "eliot-wasm-host.exe"),
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
    InstallationTransaction::new_unbound_for_fixture(
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

#[cfg(windows)]
#[test]
fn installation_transaction_status_rejects_removed_selector_without_touching_existing_file() {
    let temp_root = std::env::temp_dir().join(format!(
        "eliot-installation-transaction-status-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_root).expect("create transaction status fixture");
    let store_path = temp_root.join("transactions.redb");
    let original = b"caller-owned-existing-file";
    fs::write(&store_path, original).expect("create existing status fixture");

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
    assert_eq!(fs::read(&store_path).expect("read existing file"), original);
    let _ = fs::remove_dir_all(temp_root);
}

/// The one namespace the governed canary-removal entry publishes refusals in.
///
/// The entry's `refuse` composes every refusal it owns as this prefix followed
/// by one route phase and one closed failure class, so the retired CLI-local
/// blocker code and any renamed local code both fail the closed set below. What
/// the namespace does not establish is which function composed the answer: a
/// CLI-local writer in the composition root that published one of these codes
/// with the same exit and no writes would satisfy every assertion in this file.
/// A fixture that withholds owner state is refused inside the entry's own input
/// decode, before any owner seam runs at all.
const REMOVE_CANARY_REFUSAL_PREFIX: &str = "INSTALLATION_REMOVE_CANARY_";

/// The route phases `run_remove_canary` can refuse from.
///
/// It tags every refusal it composes `PLAN` (decoding the authorization and
/// resolving the plan) or `APPLY` (driving that same plan). `STATUS` and
/// `RECOVER` are tags of `canary-removal-status` and `recover-canary-removal`,
/// which this route never composes, so accepting them would assert something
/// the route under test cannot demonstrate.
const REMOVE_CANARY_ROUTE_OPERATIONS: [&str; 2] = ["PLAN", "APPLY"];

/// The route phases the `plan-canary-removal` command composes.
///
/// It is the one command that only ever decodes the authorization and resolves
/// the owner's plan, so it publishes `PLAN` and nothing else. Naming the single
/// tag is what lets an all-route proof say that this command did not also answer
/// with an apply-phase or status-phase code.
///
/// This command is deliberately NOT called read-only here. It is not a
/// byte-preserving read of the owner's registry file: the route obtains that
/// registry through `open_retained_registry_writer`
/// (`canary_removal_entry.rs::open_retained_registry_writer`), which yields the
/// owner's exclusive redb WRITER handle because the owner's `plan_canary_removal`
/// seam admits only a writer, and redb commits a quick-repair `allocator_state`
/// transaction when such a handle drops. The bounded claim actually available
/// about this route is asserted by `assert_durable_state_unchanged` and stated on
/// the test that uses this set.
#[cfg(windows)]
const REMOVAL_PLAN_ROUTE_OPERATIONS: [&str; 1] = ["PLAN"];

/// The route phases the admitting `apply-canary-removal` command composes.
///
/// It is the one command that only ever decodes the frozen plan document and
/// drives admission, so it publishes `APPLY` and nothing else.
#[cfg(windows)]
const REMOVAL_APPLY_ROUTE_OPERATIONS: [&str; 1] = ["APPLY"];

/// The route phases the read-only `canary-removal-status` command composes.
///
/// Status resolves one durable removal row and never drives an effect, so it
/// publishes `STATUS` and nothing else.
#[cfg(windows)]
const REMOVAL_STATUS_ROUTE_OPERATIONS: [&str; 1] = ["STATUS"];

/// The route phases the reconciling `recover-canary-removal` command composes.
///
/// Recovery reuses one already admitted removal identity, so it publishes
/// `RECOVER` and nothing else.
#[cfg(windows)]
const REMOVAL_RECOVER_ROUTE_OPERATIONS: [&str; 1] = ["RECOVER"];

/// The closed failure classes the entry's mapping projects for the owner errors.
///
/// `removal_error_code` covers every `InstallationError` variant with exactly
/// these nine classes, so this list is complete rather than selective.
const REMOVE_CANARY_OWNER_CLASSES: [&str; 9] = [
    "INVALID",
    "CONFLICT",
    "REFUSED",
    "UNKNOWN",
    "RECOVERY_REQUIRED",
    "UNAVAILABLE",
    "CORRUPT",
    "MIGRATION_REQUIRED",
    "NOT_FOUND",
];

/// Exact sentences of the retired CLI-local blocker on the public name.
///
/// The closed code set above already rejects the retired blocker code, whose
/// suffix names no route phase; these two sentences reject that same blocker
/// re-introduced under any other code, or left behind as prose in any field or
/// message of the route.
const REMOVE_CANARY_CLI_LOCAL_REFUSAL: [&str; 2] = [
    "is not implemented",
    "no durable canary removal, activation, or generation-retirement API exists",
];

/// True when `suffix` is one of `operations` plus one closed refusal class.
fn is_remove_canary_owner_refusal(operations: &[&str], suffix: &str) -> bool {
    operations.iter().any(|operation| {
        suffix
            .strip_prefix(operation)
            .and_then(|class| class.strip_prefix('_'))
            .is_some_and(|class| REMOVE_CANARY_OWNER_CLASSES.contains(&class))
    })
}

/// Rejects every `INSTALLATION_REMOVE_CANARY_*` token one route published that
/// is not a closed owner refusal of one phase that route composes.
///
/// `operations` is the route's OWN phase set, not the union of every phase the
/// entry can compose. That is the difference between this check and a global one:
/// a global phase set would accept `plan-canary-removal` answering an
/// apply-phase refusal code, which no code path in the entry can produce and
/// which would mean the phase tag stopped naming the phase that composed it.
/// The class set is closed, so a CLI-local blocker, a renamed local code or a
/// leftover refusal string in any field, message or exit path fails here.
fn assert_removal_route_owner_codes_only(route: &str, operations: &[&str], transcript: &str) {
    let mut index = 0;
    while let Some(offset) = transcript[index..].find(REMOVE_CANARY_REFUSAL_PREFIX) {
        let start = index + offset + REMOVE_CANARY_REFUSAL_PREFIX.len();
        let end = transcript[start..]
            .find(|character: char| !character.is_ascii_uppercase() && character != '_')
            .map_or(transcript.len(), |length| start + length);
        let token = &transcript[start..end];
        assert!(
            is_remove_canary_owner_refusal(operations, token),
            "{route} published a code outside its own closed owner refusal set: \
             {REMOVE_CANARY_REFUSAL_PREFIX}{token} in {transcript}"
        );
        index = end;
    }
}

/// Rejects every `INSTALLATION_REMOVE_CANARY_*` token on the public route that
/// is not a closed owner refusal, wherever the CLI published it.
///
/// This is the historical remove-canary phase set, kept as its own entry point
/// so the two public-name proofs keep exactly the meaning they already had:
/// `remove-canary` resolves AND drives one plan in one command, so both of its
/// phases are admissible there and neither `STATUS` nor `RECOVER` is.
fn assert_remove_canary_owner_refusals_only(transcript: &str) {
    assert_removal_route_owner_codes_only(
        "the public remove-canary name",
        &REMOVE_CANARY_ROUTE_OPERATIONS,
        transcript,
    );
}

/// Reads the value-taking long options the public `remove-canary` surface declares.
///
/// The route shape belongs to the composition root, so the fixture supplies a
/// value for exactly the options the surface itself declares instead of
/// duplicating a flag list here that would drift from that route.
fn remove_canary_surface_options(help: &str) -> Vec<String> {
    let mut options: Vec<String> = Vec::new();
    for line in help.lines() {
        let declaration = line.trim_start();
        let Some(token) = declaration
            .split_whitespace()
            .find(|token| token.starts_with("--"))
        else {
            continue;
        };
        // `token` is a whitespace-delimited slice of `declaration`, so this split
        // always finds it; the else arm keeps a future rename from reading a
        // `rest` that is not the text following the option.
        let Some((_, rest)) = declaration.split_once(token) else {
            continue;
        };
        // A value option is declared as `--name <NAME>` or `--name [<NAME>]`; a
        // switch carries no placeholder and needs no fixture value. That is also
        // why clap's own `--help` and `--version` can never reach `options`.
        if !rest.contains('<') && !rest.contains('[') {
            continue;
        }
        let name = token.trim_start_matches("--").trim_end_matches(',');
        if !options.iter().any(|option| option == name) {
            options.push(name.to_owned());
        }
    }
    options
}

/// Supplies one fixture value for a declared option of the public surface.
///
/// Every value names owner state this fixture never provides: no durable store,
/// no accepted registry below the retained Host root, no authorization document,
/// and a generation no registry has ever accepted as an installed canary. The
/// arms cover exactly the selectors `remove-canary` declares, so an option added
/// to that surface reaches the caller's panic instead of a silent guess.
fn remove_canary_fixture_value(
    option: &str,
    store: &Path,
    host_state_root: &Path,
    request: &Path,
) -> Option<String> {
    let value = match option {
        "store" => store.to_string_lossy().into_owned(),
        "host-state-root" => host_state_root.to_string_lossy().into_owned(),
        "request" => request.to_string_lossy().into_owned(),
        "generation" => "generation:unproven-canary".to_owned(),
        _ => return None,
    };
    Some(value)
}

/// Builds the option list the public `remove-canary` name accepts.
///
/// The surface must expose both durable owner selectors the removal route
/// reads: the transaction store and the retained Host state root holding the
/// accepted registry. A public name that carries only one of them can refuse
/// before it reaches any installed generation, so it stays a CLI-local answer
/// by construction.
fn remove_canary_public_args(
    help: &str,
    store: &Path,
    host_state_root: &Path,
    request: &Path,
) -> Vec<String> {
    let options = remove_canary_surface_options(help);
    for selector in ["store", "host-state-root"] {
        assert!(
            options.iter().any(|option| option == selector),
            "the public remove-canary name selects no owner state through --{selector}: {help}"
        );
    }
    let mut args = Vec::new();
    for option in &options {
        let Some(value) = remove_canary_fixture_value(option, store, host_state_root, request)
        else {
            panic!(
                "the public remove-canary surface declares an unmodelled option --{option}; \
                 extend the fixture mapping instead of leaving that route untested"
            );
        };
        args.push(format!("--{option}"));
        args.push(value);
    }
    args
}

/// The public `installation remove-canary` name is refused inside the governed
/// remove-canary refusal namespace on a fixture with no owner state, and it
/// mutates nothing.
///
/// The name must carry both durable owner selectors the removal route reads, and
/// every `INSTALLATION_REMOVE_CANARY_*` token it publishes must be a closed code
/// the entry composes rather than a CLI-local unsupported blocker or a CLI-local
/// deletion, and it must land before any of that owner state is created.
///
/// This test is the negative half of the acceptance pair and it deliberately
/// keeps the retired `INSTALLATION_REMOVE_CANARY_UNSUPPORTED` blocker out of
/// reach: the closed code set above rejects that code, because its suffix names
/// no route phase, and the two CLI-local refusal sentences below reject the same
/// blocker re-introduced under another code or left behind as prose. Pinning the
/// entry's own decode-phase refusal `PLAN_INVALID` is what additionally rejects a
/// renamed local code and a decode phase re-tagged as `APPLY`.
///
/// Proof ceiling, stated rather than hidden. This fixture withholds the
/// authorization document, so the entry refuses inside `load_request`, which is
/// its own input decode and runs before `open_existing_store`,
/// `open_retained_registry_writer` and the owner's `plan_canary_removal`. It
/// therefore proves the refusal namespace and the absence of any CLI-local
/// blocker, and it deliberately proves nothing about owner reach.
/// `installation_remove_canary_reaches_the_installation_owner` is the positive
/// half: on a fixture that publishes the authorization, a real transaction store
/// and a real retained registry, it observes the owner's own typed refusal from
/// inside `plan_canary_removal`. The two are not contradictory — they differ in
/// what the fixture withholds — and together they close the audit's mandatory
/// check that the public name reaches the owner and that neither of these two
/// fixtures answers `...UNSUPPORTED`.
///
/// That last clause is scoped to these two fixtures, and it is written that way
/// on purpose. It is NOT an unconditional property of the route: the owner's own
/// required-cleanup refusal is still reachable in production and deliberately
/// kept. `unsupported_cleanup_refusal`
/// (`crates/kernel/eliot-installation/src/canary_removal.rs::unsupported_cleanup_refusal`) composes a
/// sentence carrying the literal words `UNSUPPORTED` and `OUT_OF_SCOPE`, and it
/// answers a frozen plan that carries a row classified `Unsupported`
/// (`canary_removal.rs::classify_action`). What rejects the retired CLI-local blocker
/// for ANY input is the fixture-independent half stated above: the closed code
/// set cannot express `INSTALLATION_REMOVE_CANARY_UNSUPPORTED`, because that
/// suffix names neither a route phase nor a closed failure class, and the two
/// CLI-local refusal sentences appear in no owner vocabulary.
#[test]
fn installation_remove_canary_refuses_in_the_removal_namespace_before_any_owner_state() {
    let temp_root = std::env::temp_dir().join(format!(
        "eliot-installation-remove-canary-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&temp_root).expect("create remove-canary fixture");
    // An unproven target: no durable transaction store, a retained Host root
    // that holds no accepted installation registry below it, and no removal
    // authorization document.
    let store = temp_root.join("transactions.redb");
    let host_state_root = temp_root.join("host-state");
    let request = temp_root.join("removal-request.json");
    fs::create_dir_all(&host_state_root).expect("create retained Host root fixture");

    let surface = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args(["installation", "remove-canary", "--help"])
        .output()
        .expect("read the public remove-canary surface");
    assert!(
        surface.status.success(),
        "the public remove-canary name is not a readable command: {}",
        String::from_utf8_lossy(&surface.stderr)
    );
    let help = String::from_utf8_lossy(&surface.stdout).into_owned();
    let args = remove_canary_public_args(&help, &store, &host_state_root, &request);

    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args(["installation", "remove-canary"])
        .args(&args)
        .output()
        .expect("run remove-canary command");
    let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&result.stderr).into_owned();
    let transcript = format!("{stdout}\n{stderr}");

    // The route answers on the bounded refusal exit, never on a success or an
    // unknown-outcome exit: this fixture names no admitted removal, so a zero
    // exit would mean the public name acted on the machine and a 75 exit would
    // mean it left a durable effect in doubt.
    assert_eq!(
        result.status.code(),
        Some(2),
        "an unproven removal target must stay a bounded typed refusal: {transcript}"
    );
    let output: Value = serde_json::from_slice(&result.stdout).unwrap_or_else(|error| {
        panic!("the public remove-canary name must answer with the typed installation envelope, not usage text or prose: {error}; {transcript}")
    });
    assert_eq!(output["status"], "ERROR");
    assert_eq!(output["completed"], false);
    assert_eq!(output["scope"], "bounded_all_effects_or_exact_rollback");
    let detail = output["detail"]
        .as_str()
        .expect("remove-canary refusal detail");
    let code = output["code"].as_str().expect("remove-canary refusal code");

    // The answer is the entry's decode-phase refusal, not a CLI-local blocker
    // code. This fixture withholds the authorization document, so `load_request`
    // fails first and the route answers `PLAN_INVALID`; pinning that exact code
    // is what rejects a renamed local code and a decode phase re-tagged as
    // `APPLY`.
    assert_eq!(
        code, "INSTALLATION_REMOVE_CANARY_PLAN_INVALID",
        "the public remove-canary name did not answer with the removal entry's \
         decode-phase refusal: {code} ({detail})"
    );
    assert_remove_canary_owner_refusals_only(&transcript);
    for marker in REMOVE_CANARY_CLI_LOCAL_REFUSAL {
        assert!(
            !transcript.contains(marker),
            "the public remove-canary name kept CLI-local refusal prose: {marker} in {transcript}"
        );
    }

    // The refusal precedes every destructive path. This fixture supplies no
    // durable owner state at all, so afterwards no store exists, nothing
    // appeared below the retained Host root, and nothing else was written into
    // the fixture.
    assert!(
        !store.exists(),
        "the public remove-canary name created a transaction store"
    );
    let host_root_entries = fixture_entry_names(&host_state_root);
    assert!(
        host_root_entries.is_empty(),
        "the public remove-canary name wrote below the retained Host root: {host_root_entries:?}"
    );
    let unexpected: Vec<String> = fixture_entry_names(&temp_root)
        .into_iter()
        .filter(|name| name != "host-state")
        .collect();
    assert!(
        unexpected.is_empty(),
        "the public remove-canary name wrote into its own fixture: {unexpected:?}"
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

/// The one owner sentence that proves a canary-removal refusal was composed
/// after the installation owner loaded, validated and searched the retained
/// accepted-generation registry.
///
/// `canary_removal::resolve_approved_generation` composes exactly this sentence
/// and no other function composes it, so pinning it pins the reach of the route
/// itself rather than the shape of a code the composition root could also print.
#[cfg(windows)]
const REMOVE_CANARY_OWNER_REGISTRY_REFUSAL: &str =
    "is not an approved generation of this installation";

/// Serde wording a deserialisation failure of the plan document would carry.
///
/// Each marker is asserted only beside a positive owner verdict: the point is
/// that the owner answered about the plan's MEANING, never that some string is
/// missing.
#[cfg(windows)]
const PLAN_DOCUMENT_DECODE_MARKERS: [&str; 4] = [
    "is not a CanaryRemovalPlanEnvelope",
    "unknown field",
    "missing field",
    "invalid type",
];

/// The exact member set the owner's `CanaryRemovalStatus` projection publishes.
///
/// The thirteen names and their count are read off the owner type itself —
/// `canary_removal.rs::CanaryRemovalStatus`, whose public members are
/// `removal_transaction_id`, `install_transaction_id`, `generation`,
/// `plan_digest`, `stage`, `registry_revision`, `resolved_effect_ids`,
/// `unresolved_effect_ids`, `blocking_effect_id`, `primary_uncertainty`,
/// `cleanup_uncertainty`, `next_permitted_action` and `evidence_refs` — so the
/// declared length is the count of fields the type actually has rather than a
/// remembered number.
///
/// Pinning the set, not just the values, is what makes an added credential,
/// environment value or free-form path member fail here instead of passing as
/// extra evidence.
#[cfg(windows)]
const CANARY_REMOVAL_STATUS_MEMBERS: [&str; 13] = [
    "blocking_effect_id",
    "cleanup_uncertainty",
    "evidence_refs",
    "generation",
    "install_transaction_id",
    "next_permitted_action",
    "plan_digest",
    "primary_uncertainty",
    "registry_revision",
    "removal_transaction_id",
    "resolved_effect_ids",
    "stage",
    "unresolved_effect_ids",
];

/// One real installation-owner surface for the governed canary-removal routes.
///
/// The fixture publishes exactly the three durable inputs the public
/// `remove-canary`, `plan-canary-removal` and `apply-canary-removal` routes read
/// before they can reach the owner, and it publishes them through the owner's own
/// public constructors rather than by hand-writing files:
///
/// * a real `redb` database at the exact existing path the route's own
///   `open_existing_store` requires, verified here by reopening it through
///   `RedbInstallationTransactionStore::open_existing_exact_path` so that call
///   cannot be the thing that fails inside the route under test;
/// * a real retained per-installation Host state root below
///   `Eliot/installations/<sha256-key>/host` carrying a real accepted-generation
///   registry, published through `RedbInstallationRegistry::open_at` over the very
///   `ProtectedRootLease` the route opens itself;
/// * a real explicit `Remove` authorization document, serialised from the owner's
///   own request type.
///
/// Two limits are stated here rather than discovered later. The store database is
/// created through `RedbInstallationRegistry::open_test_support`, because the
/// installation owner's only other public database constructor,
/// `RedbInstallationTransactionStore::create_planned_at_exact_path`, refuses a
/// transaction whose `profile_governed_roots` is unset, and
/// `InstallationTransaction::new_unbound_for_fixture` sets that binding only under
/// the owning crate's own `cfg(test)`. The same gap means the fixture can publish
/// no accepted generation and no `ActiveVerified` install transaction: both need
/// `InstallationCoordinator` staging that this package cannot drive. So the routes
/// reach the owner's own target resolution and refuse there, which is the reach
/// this issue's acceptance names, while a completed removal stays the #11
/// installed pulse.
#[cfg(windows)]
struct RemovalOwnerFixture {
    temp_root: PathBuf,
    installation_root: PathBuf,
    host_state_root: PathBuf,
    store: PathBuf,
    request: PathBuf,
    install_transaction_id: PlatformHandle,
    generation: PlatformHandle,
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture publishes each durable owner input through its own production constructor"
)]
fn removal_owner_fixture(label: &str) -> RemovalOwnerFixture {
    let temp_root = std::env::temp_dir().join(format!(
        "eliot-removal-owner-{label}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&temp_root).expect("create removal fixture root");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let installation_key = format!("{:032x}{nonce:032x}", std::process::id());
    let installation_root = protected_program_data_root()
        .expect("ProgramData root")
        .join("Eliot")
        .join("installations")
        .join(&installation_key);
    let host_state_root = installation_root.join("host");
    prepare_protected_directory(&host_state_root).expect("create retained Host root fixture");

    // A real redb database at the exact path the route's own store constructor
    // requires. The installation owner's only other public store constructors
    // either need a verified source-bundle publication journal or a
    // publication-bound profile root binding, so this database is what the
    // fixture can honestly publish; it carries no transaction row, which is the
    // documented ceiling of these proofs.
    let store = temp_root.join("transactions.redb");
    drop(
        RedbInstallationRegistry::open_test_support(&store)
            .expect("create the durable transaction-store database"),
    );
    RedbInstallationTransactionStore::open_existing_exact_path(&store).unwrap_or_else(|error| {
        panic!(
            "the fixture store must open through the owner's production store constructor \
             (`open_existing_exact_path`); a real redb database that this rejects means the \
             route's own `open_existing_store` could never be reached from this package: {error}"
        )
    });

    // The accepted-generation registry below the retained Host root, opened
    // through the very same two calls the route makes.
    let lease = ProtectedRootLease::open_existing(&host_state_root)
        .expect("retain the fixture Host state root as the owner does");
    let registry = RedbInstallationRegistry::open_at(lease)
        .expect("create the retained installation registry below the Host root");
    let projection = registry
        .load()
        .expect("load the retained installation registry");
    assert_eq!(
        projection.revision(),
        1,
        "the retained registry must be the owner's own empty revision-1 projection"
    );
    assert!(
        projection.generations().is_empty(),
        "the retained registry must publish no accepted generation"
    );
    drop(registry);

    let install_transaction_id = fixture_handle(format!("transaction:remove-canary-{label}"));
    let generation = fixture_handle(format!("generation:remove-canary-{label}"));
    let removal_authorization = ManagedEnvironmentChangeRequest {
        request_id: fixture_handle(format!("request:remove-canary-{label}")),
        requester_and_reason: fixture_handle("requester:test"),
        action: ManagedEnvironmentAction::Remove,
        target_family: fixture_handle("family:eliot"),
        exact_candidate: generation.clone(),
        expected_delta: fixture_handle("delta:removed"),
        source_assurance_refs: vec![fixture_handle("evidence:source-assurance")],
        affected_refs: Vec::new(),
        impact_class: fixture_handle("impact:test"),
        required_owner: fixture_handle("owner:installation"),
        rollback_plan: fixture_handle(format!("rollback:remove-canary-{label}")),
        verifier: fixture_handle("verifier:installation"),
        budget: fixture_handle("budget:test"),
        stop_condition: fixture_handle("stop:on-failure"),
    };
    let request = temp_root.join("removal-request.json");
    fs::write(
        &request,
        serde_json::to_vec_pretty(&removal_authorization).expect("serialize removal authorization"),
    )
    .expect("write the explicit Remove authorization");

    RemovalOwnerFixture {
        temp_root,
        installation_root,
        host_state_root,
        store,
        request,
        install_transaction_id,
        generation,
    }
}

#[cfg(windows)]
impl RemovalOwnerFixture {
    /// `installation remove-canary --store --host-state-root --generation --request`.
    fn remove_canary_args(&self) -> Vec<String> {
        vec![
            "installation".to_owned(),
            "remove-canary".to_owned(),
            "--store".to_owned(),
            self.store.to_string_lossy().into_owned(),
            "--host-state-root".to_owned(),
            self.host_state_root.to_string_lossy().into_owned(),
            "--generation".to_owned(),
            self.generation.as_str().to_owned(),
            "--request".to_owned(),
            self.request.to_string_lossy().into_owned(),
        ]
    }

    /// `installation plan-canary-removal --store --host-state-root --generation --request`.
    fn plan_canary_removal_args(&self) -> Vec<String> {
        vec![
            "installation".to_owned(),
            "plan-canary-removal".to_owned(),
            "--store".to_owned(),
            self.store.to_string_lossy().into_owned(),
            "--host-state-root".to_owned(),
            self.host_state_root.to_string_lossy().into_owned(),
            "--generation".to_owned(),
            self.generation.as_str().to_owned(),
            "--request".to_owned(),
            self.request.to_string_lossy().into_owned(),
        ]
    }

    /// `installation apply-canary-removal --store --host-state-root --plan`.
    fn apply_canary_removal_args(&self, plan: &Path) -> Vec<String> {
        vec![
            "installation".to_owned(),
            "apply-canary-removal".to_owned(),
            "--store".to_owned(),
            self.store.to_string_lossy().into_owned(),
            "--host-state-root".to_owned(),
            self.host_state_root.to_string_lossy().into_owned(),
            "--plan".to_owned(),
            plan.to_string_lossy().into_owned(),
        ]
    }

    /// `installation canary-removal-status --store --removal-transaction-id`.
    fn canary_removal_status_args(&self, removal_transaction_id: &PlatformHandle) -> Vec<String> {
        vec![
            "installation".to_owned(),
            "canary-removal-status".to_owned(),
            "--store".to_owned(),
            self.store.to_string_lossy().into_owned(),
            "--removal-transaction-id".to_owned(),
            removal_transaction_id.as_str().to_owned(),
        ]
    }

    /// `installation recover-canary-removal --store --host-state-root --removal-transaction-id`.
    fn recover_canary_removal_args(&self, removal_transaction_id: &PlatformHandle) -> Vec<String> {
        vec![
            "installation".to_owned(),
            "recover-canary-removal".to_owned(),
            "--store".to_owned(),
            self.store.to_string_lossy().into_owned(),
            "--host-state-root".to_owned(),
            self.host_state_root.to_string_lossy().into_owned(),
            "--removal-transaction-id".to_owned(),
            removal_transaction_id.as_str().to_owned(),
        ]
    }

    fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.temp_root);
        let _ = fs::remove_dir_all(&self.installation_root);
    }
}

#[cfg(windows)]
fn run_removal_command(args: &[String], cwd: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("run the eliot installation subcommand")
}

/// Which owner-derived rows one frozen fixture plan accounts for.
///
/// Each arm is a different frozen graph, so the arm a test names is part of what
/// that test proves, and every arm is a graph `CanaryRemovalPlanEnvelope::new`
/// itself admits:
///
/// * `DriverOnly` freezes the installer-effect row and the terminal registry
///   record alone, so the document proves the carrier and nothing else.
/// * `BlockingUnsupported` adds the Store/Blob row frozen as `Unsupported`, the
///   classification issue #1138 replaced. The arm is retained because the
///   blocking-row proof still needs a plan that carries a row this owner cannot
///   drive, and because `require_quiesced_owner_effects` still refuses such a
///   record at the destructive fence
///   (`crates/kernel/eliot-installation/src/canary_removal.rs::require_quiesced_owner_effects`), which is
///   the behaviour a pre-#1138 admission is refused for.
/// * `NamedOutOfScope` adds BOTH shared surfaces the owner classifies
///   `OutOfScope`: `CanaryEvidenceRoot` and `StoreObjects`. Each is frozen with
///   the category, the `ForeignToThisRemoval` origin, the owner-recorded
///   identity, the ownership evidence and the reconciliation query that the
///   owner's own `canary_evidence_row` (`canary_removal.rs::canary_evidence_row`) and
///   `store_objects_row` (`canary_removal.rs::store_objects_row`) freeze, in the same row
///   order the owner's own `expected_owners` list uses
///   (`canary_removal.rs::require_quiesced_owner_effects`), and with the same
///   `canary-removal/effect/…` effect-identity shape those two functions mint.
///   That shape is what makes an operator able to SEE both categories named in
///   the reported denominator instead of dropped from it.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemovalFixtureRows {
    DriverOnly,
    BlockingUnsupported,
    NamedOutOfScope,
}

/// Builds one frozen, owner-validated `CanaryRemovalPlanEnvelope`.
///
/// The document is produced from the owner's own plan type and the owner's own
/// envelope constructor, and it is serialised exactly the way
/// `canary_removal_entry::run_plan_canary_removal` prints it
/// (`serde_json::to_string_pretty` plus the `println!` newline), so the bytes
/// handed to apply are the bytes the plan surface emits. `plan.validate()`
/// re-derives the plan digest, the removal identity and the frozen graph inside
/// `CanaryRemovalPlanEnvelope::new`, so a fixture that did not model the owner's
/// contract would fail here rather than produce a document apply must accept.
///
/// `canary_evidence_root` is only read by the `NamedOutOfScope` arm. It is where
/// the fixture NAMES the canary evidence root this plan accounts for; the
/// fixture deliberately never creates that directory, because the only owner
/// that could observe it is the one this crate cannot reach, and a created
/// directory would be a durable member that proves nothing about the
/// classification under test.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the frozen plan spells out the owner's complete durable contract"
)]
fn removal_plan_envelope(
    install_transaction_id: &PlatformHandle,
    generation: &PlatformHandle,
    canary_evidence_root: &Path,
    authorization: &ManagedEnvironmentChangeRequest,
    rows: RemovalFixtureRows,
) -> (CanaryRemovalPlanEnvelope, Vec<PlatformHandle>) {
    let bound = CanaryRemovalEffectBound {
        attempt: 1,
        max_attempts: 2,
    };
    // The generation's own owner-recorded Store bridge binding. The owner's
    // `store_objects_row` takes exactly this member as the `StoreObjects` row's
    // `resource_identity` AND as its sole `ownership_evidence` handle
    // (`CanaryRemovalBuildBinding::from_manifest`, `canary_removal.rs::CanaryRemovalBuildBinding::from_manifest`), so
    // the fixture freezes the shared Store row named the way the owner names it.
    let store_bridge_artifact_digest = fixture_handle("1".repeat(64));
    let canary_evidence_root_identity = fixture_path(canary_evidence_root, "canary-evidence");
    let mut effects = vec![CanaryRemovalEffect {
        effect_id: fixture_handle("canary-removal/row:installation-root"),
        category: CanaryRemovalResource::InstallationRoot,
        origin: CanaryRemovalResourceOrigin::CreatedByInstallTransaction,
        action: CanaryRemovalAction::Remove,
        resource_identity: fixture_handle("canary-removal/resource:installation-root"),
        ownership_evidence: vec![fixture_handle("evidence:installation-root-created")],
        reference_users: Vec::new(),
        prerequisites: Vec::new(),
        expected_postcondition: CanaryRemovalPostcondition::Absent,
        reconciliation_query: fixture_handle("canary-removal/query:installation-root"),
        bound,
        install_effect_index: Some(0),
    }];
    match rows {
        RemovalFixtureRows::DriverOnly => {}
        RemovalFixtureRows::BlockingUnsupported => {
            effects.push(CanaryRemovalEffect {
                effect_id: fixture_handle("canary-removal/row:store-objects"),
                category: CanaryRemovalResource::StoreObjects,
                origin: CanaryRemovalResourceOrigin::ForeignToThisRemoval,
                action: CanaryRemovalAction::Unsupported,
                resource_identity: fixture_handle("canary-removal/resource:store-objects"),
                ownership_evidence: vec![fixture_handle("evidence:store-binding-recorded")],
                reference_users: Vec::new(),
                prerequisites: Vec::new(),
                expected_postcondition: CanaryRemovalPostcondition::Retained,
                reconciliation_query: fixture_handle("canary-removal/query:store-objects"),
                bound,
                install_effect_index: None,
            });
        }
        RemovalFixtureRows::NamedOutOfScope => {
            effects.push(CanaryRemovalEffect {
                effect_id: fixture_handle(format!(
                    "canary-removal/effect/canary-evidence-root:{install_transaction_id}"
                )),
                category: CanaryRemovalResource::CanaryEvidenceRoot,
                origin: CanaryRemovalResourceOrigin::ForeignToThisRemoval,
                action: CanaryRemovalAction::OutOfScope,
                resource_identity: canary_evidence_root_identity.clone(),
                ownership_evidence: vec![canary_evidence_root_identity.clone()],
                reference_users: Vec::new(),
                prerequisites: Vec::new(),
                expected_postcondition: CanaryRemovalPostcondition::Retained,
                reconciliation_query: fixture_handle(format!(
                    "canary-removal/reconcile/canary-evidence-root:{install_transaction_id}"
                )),
                bound,
                install_effect_index: None,
            });
            effects.push(CanaryRemovalEffect {
                effect_id: fixture_handle(format!(
                    "canary-removal/effect/store-objects:{generation}"
                )),
                category: CanaryRemovalResource::StoreObjects,
                origin: CanaryRemovalResourceOrigin::ForeignToThisRemoval,
                action: CanaryRemovalAction::OutOfScope,
                resource_identity: store_bridge_artifact_digest.clone(),
                ownership_evidence: vec![store_bridge_artifact_digest.clone()],
                reference_users: Vec::new(),
                prerequisites: Vec::new(),
                expected_postcondition: CanaryRemovalPostcondition::Retained,
                reconciliation_query: fixture_handle(format!(
                    "canary-removal/reconcile/store-owner:{generation}"
                )),
                bound,
                install_effect_index: None,
            });
        }
    }
    effects.push(CanaryRemovalEffect {
        effect_id: fixture_handle("canary-removal/row:generation-registry-record"),
        category: CanaryRemovalResource::GenerationRegistryRecord,
        origin: CanaryRemovalResourceOrigin::ForeignToThisRemoval,
        action: CanaryRemovalAction::Retain,
        resource_identity: fixture_handle("canary-removal/resource:generation-registry-record"),
        ownership_evidence: vec![fixture_handle("evidence:registry-record-admitted")],
        reference_users: Vec::new(),
        prerequisites: Vec::new(),
        expected_postcondition: CanaryRemovalPostcondition::Retained,
        reconciliation_query: fixture_handle("canary-removal/query:generation-registry-record"),
        bound,
        install_effect_index: None,
    });
    let mut plan = CanaryRemovalPlan {
        canary_removal_wire_version: CANARY_REMOVAL_WIRE_VERSION,
        removal_transaction_id: canary_removal_operation_id(install_transaction_id, generation)
            .expect("derive the removal operation identity"),
        install_transaction_id: install_transaction_id.clone(),
        install_plan_digest: fixture_handle("a".repeat(64)),
        installation_epoch: InstallationEpoch {
            installation: fixture_handle("installation:remove-canary-fixture"),
            lineage_id: fixture_handle("lineage:remove-canary-fixture"),
            sequence: 1,
        },
        generation: generation.clone(),
        manifest_digest: fixture_handle("b".repeat(64)),
        build: CanaryRemovalBuildBinding {
            host_artifact_digest: fixture_handle("8".repeat(64)),
            kernel_artifact_digest: fixture_handle("a".repeat(64)),
            store_bridge_artifact_digest: store_bridge_artifact_digest.clone(),
            canonical_store_artifact_digest: fixture_handle("5".repeat(64)),
        },
        registry_revision: 1,
        request: authorization.clone(),
        quiesce: CanaryRemovalQuiesce {
            active_generation: None,
            last_known_good_generation: None,
            retirement_barrier: Some(fixture_handle("canary-removal/barrier:observed-handoff")),
            open_install_effects: 0,
            pending_external_changes: 0,
            pending_activation_generation: None,
        },
        effects,
        plan_digest: fixture_handle("0".repeat(64)),
    };
    plan.plan_digest = plan.computed_digest().expect("seal the frozen plan digest");
    let effect_ids = plan
        .effects
        .iter()
        .map(|effect| effect.effect_id.clone())
        .collect();
    let envelope = CanaryRemovalPlanEnvelope::new(
        fixture_handle("bounded_all_effects_or_exact_rollback"),
        plan,
    )
    .expect("build the versioned plan envelope the owner admits");
    (envelope, effect_ids)
}

/// Collects every string leaf of one JSON value.
#[cfg(windows)]
fn json_string_leaves(value: &Value, into: &mut Vec<String>) {
    match value {
        Value::String(text) => into.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                json_string_leaves(item, into);
            }
        }
        Value::Object(members) => {
            for member in members.values() {
                json_string_leaves(member, into);
            }
        }
        _ => {}
    }
}

/// The public `installation remove-canary` name reaches the installation owner.
///
/// The route is invoked on a fixture that publishes every durable input the
/// owner reads — a decodable explicit `Remove` authorization, a real `redb`
/// transaction store and a real retained Host root carrying a real
/// accepted-generation registry — so the refusal this run observes can only be
/// composed after `load_request`, after `open_existing_store`, after
/// `open_retained_registry_writer`, and inside the owner's own
/// `plan_canary_removal` target resolution.
///
/// It is therefore the owner's typed refusal and specifically not the retired
/// `INSTALLATION_REMOVE_CANARY_UNSUPPORTED` CLI-local blocker: the transcript
/// carries no `...UNSUPPORTED` token and no CLI-local refusal prose, every
/// `INSTALLATION_REMOVE_CANARY_*` code it publishes is one the closed owner
/// refusal set admits, and the exact `REFUSED` code plus the owner's own
/// registry-resolution sentence is present as the positive counterpart.
///
/// The bare-token scan above is FIXTURE-SCOPED and is stated as such rather than
/// read as a route guarantee. This run refuses inside the owner's own target
/// resolution, before any removal row is frozen or classified, so no row of this
/// plan can carry `Unsupported` and the owner's required-cleanup refusal has no
/// row to answer. That refusal is still production-reachable:
/// `unsupported_cleanup_refusal`
/// (`crates/kernel/eliot-installation/src/canary_removal.rs::unsupported_cleanup_refusal`) composes a
/// sentence containing the literal words `UNSUPPORTED` and `OUT_OF_SCOPE` and is
/// returned for a frozen plan carrying a row classified `Unsupported`
/// (`canary_removal.rs::classify_action`), which `apply_canary_removal` admits for any
/// externally supplied envelope. The pair asserted beside it is the
/// fixture-independent half and is what keeps the regression red for any input:
/// the closed code set cannot express the retired blocker code, and neither
/// CLI-local refusal sentence is one the owner composes.
///
/// The target this fixture publishes is never an accepted generation, so the run
/// stops inside the owner before any destructive path exists. That ceiling is
/// the honest one: a completed removal needs an accepted generation and an
/// `ActiveVerified` install transaction, and this package cannot publish either
/// (see [`RemovalOwnerFixture`]).
#[cfg(windows)]
#[test]
fn installation_remove_canary_reaches_the_installation_owner() {
    let fixture = removal_owner_fixture("owner-reach");
    let result = run_removal_command(&fixture.remove_canary_args(), &fixture.temp_root);
    let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&result.stderr).into_owned();
    let transcript = format!("{stdout}\n{stderr}");

    assert_eq!(
        result.status.code(),
        Some(2),
        "the public remove-canary name must answer on the bounded typed refusal exit: {transcript}"
    );
    let output: Value = serde_json::from_slice(&result.stdout).unwrap_or_else(|error| {
        panic!("the public remove-canary name must answer with the typed installation envelope, not usage text or prose: {error}; {transcript}")
    });
    assert_eq!(output["status"], "ERROR");
    assert_eq!(output["completed"], false);
    assert_eq!(output["scope"], "bounded_all_effects_or_exact_rollback");
    let code = output["code"].as_str().expect("remove-canary refusal code");
    let detail = output["detail"]
        .as_str()
        .expect("remove-canary refusal detail");

    // The retired CLI-local blocker is gone from this run under every spelling.
    // This scan is fixture-scoped, and the reason is the owner's own: the run
    // refuses at target resolution before any row is frozen, so nothing here
    // classifies a row `Unsupported` and `unsupported_cleanup_refusal`
    // (`canary_removal.rs::unsupported_cleanup_refusal`) has no row to answer with its `UNSUPPORTED`
    // sentence. The closed code set and the two prose markers below are the
    // fixture-independent half, and a route that regressed to that blocker fails
    // on all three.
    assert!(
        !transcript.contains("UNSUPPORTED"),
        "the public remove-canary name published an UNSUPPORTED refusal again, on a fixture whose \
         plan freezes no row classified Unsupported: {transcript}"
    );
    for marker in REMOVE_CANARY_CLI_LOCAL_REFUSAL {
        assert!(
            !transcript.contains(marker),
            "the public remove-canary name kept CLI-local refusal prose: {marker} in {transcript}"
        );
    }
    assert_remove_canary_owner_refusals_only(&transcript);

    // The positive counterpart: the refusal is the owner's own typed
    // `IncompleteObservation` projected through the entry's closed REFUSED class,
    // and it names the exact generation this fixture asked about. That sentence
    // exists in no composition-root code path.
    assert_eq!(
        code, "INSTALLATION_REMOVE_CANARY_PLAN_REFUSED",
        "the public remove-canary name did not answer with the owner's own plan refusal: {code} ({detail})"
    );
    assert!(
        detail.contains(REMOVE_CANARY_OWNER_REGISTRY_REFUSAL),
        "the public remove-canary name did not reach the owner's registry target resolution: {detail}"
    );
    assert!(
        detail.contains(fixture.generation.as_str()),
        "the owner's refusal must name the exact generation the route was asked to remove: {detail}"
    );

    // Reaching the owner this far created no durable state: planning resolved the
    // target and the retained registry is still the owner's own empty revision-1
    // projection. "Read-only" is not claimed of this route, because it resolves
    // through `open_retained_registry_writer` and therefore writes redb's own
    // `allocator_state` bookkeeping into the registry file when that handle drops.
    // Only the DOMAIN is asserted below, and it is read back through the owner's
    // own reader rather than inferred from file bytes.
    let lease = ProtectedRootLease::open_existing(&fixture.host_state_root)
        .expect("retain the fixture Host state root after the refused run");
    let registry = RedbInstallationRegistry::open_existing_at(lease)
        .expect("reopen the retained registry")
        .expect("the retained registry must still exist");
    assert_eq!(
        registry.load().expect("reload the registry").revision(),
        1,
        "a refused public remove-canary name advanced the accepted-generation registry"
    );
    drop(registry);
    fixture.cleanup();
}

/// The bytes `plan-canary-removal` writes are accepted by `apply-canary-removal`
/// with no transformation, and apply's answer is the owner's semantic verdict.
///
/// The plan surface is invoked first and must reach the same owner target
/// resolution the public name reaches; because this package cannot publish an
/// accepted generation, that run refuses and emits no plan document, which this
/// test states rather than hides. The plan document handed to apply is therefore
/// the owner's own `CanaryRemovalPlanEnvelope`, serialised exactly the way the
/// plan surface prints it, and written to disk with no re-serialisation, no
/// re-parse, no field extraction and no trimming.
///
/// Apply's answer is then the owner's SEMANTIC verdict about that plan — it
/// decodes and re-validates the envelope, admits a durable removal operation
/// under the plan's own removal identity, and only then refuses because the
/// install transaction the plan names is absent from the store. The refusal
/// carries that exact install transaction identity, which no deserialisation
/// failure could produce, and none of the serde wording a decode failure carries.
#[cfg(windows)]
#[test]
fn plan_canary_removal_stdout_is_accepted_by_apply_canary_removal_unmodified() {
    let fixture = removal_owner_fixture("plan-round-trip");
    let authorization = ManagedEnvironmentChangeRequest {
        request_id: fixture_handle("request:remove-canary-plan-round-trip"),
        requester_and_reason: fixture_handle("requester:test"),
        action: ManagedEnvironmentAction::Remove,
        target_family: fixture_handle("family:eliot"),
        exact_candidate: fixture.generation.clone(),
        expected_delta: fixture_handle("delta:removed"),
        source_assurance_refs: vec![fixture_handle("evidence:source-assurance")],
        affected_refs: Vec::new(),
        impact_class: fixture_handle("impact:test"),
        required_owner: fixture_handle("owner:installation"),
        rollback_plan: fixture_handle("rollback:remove-canary-plan-round-trip"),
        verifier: fixture_handle("verifier:installation"),
        budget: fixture_handle("budget:test"),
        stop_condition: fixture_handle("stop:on-failure"),
    };

    // The plan surface first: it must reach the same owner seam as the public
    // name, and on this fixture it therefore emits a refusal, not a document.
    let planned = run_removal_command(&fixture.plan_canary_removal_args(), &fixture.temp_root);
    let plan_transcript = format!(
        "{}\n{}",
        String::from_utf8_lossy(&planned.stdout),
        String::from_utf8_lossy(&planned.stderr)
    );
    let planned_output: Value =
        serde_json::from_slice(&planned.stdout).expect("plan-canary-removal typed answer");
    assert_eq!(
        planned_output["code"], "INSTALLATION_REMOVE_CANARY_PLAN_REFUSED",
        "the plan surface must reach the same owner target resolution: {plan_transcript}"
    );
    assert!(
        planned_output["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains(REMOVE_CANARY_OWNER_REGISTRY_REFUSAL)),
        "the plan surface must reach the owner's registry target resolution: {plan_transcript}"
    );
    assert!(
        !plan_transcript.contains("canary_removal_wire_version"),
        "the plan surface emitted a plan document on a refused target: {plan_transcript}"
    );

    // The document, byte for byte the way the plan surface prints it.
    let (envelope, _) = removal_plan_envelope(
        &fixture.install_transaction_id,
        &fixture.generation,
        &fixture.host_state_root,
        &authorization,
        RemovalFixtureRows::DriverOnly,
    );
    let mut plan_bytes =
        serde_json::to_vec_pretty(&envelope).expect("serialise the versioned plan envelope");
    plan_bytes.push(b'\n');
    let plan_path = fixture.temp_root.join("removal-plan.json");
    fs::write(&plan_path, &plan_bytes).expect("write the unmodified plan document");

    let applied = run_removal_command(
        &fixture.apply_canary_removal_args(&plan_path),
        &fixture.temp_root,
    );
    let apply_transcript = format!(
        "{}\n{}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    assert_eq!(
        applied.status.code(),
        Some(2),
        "apply must answer on the bounded typed refusal exit for a plan whose install \
         transaction is absent: {apply_transcript}"
    );
    let apply_output: Value =
        serde_json::from_slice(&applied.stdout).expect("apply-canary-removal typed answer");
    assert_installation_error(&apply_output, "INSTALLATION_REMOVE_CANARY_APPLY_NOT_FOUND");
    let apply_detail = apply_output["detail"]
        .as_str()
        .expect("apply refusal detail");

    // The positive semantic verdict: the owner read the plan's own install
    // transaction identity out of the document and refused on THAT, which a
    // document that had not been decoded and interpreted could not do.
    assert!(
        apply_detail.contains(fixture.install_transaction_id.as_str()),
        "apply's verdict must name the install transaction the plan declares: {apply_detail}"
    );
    for marker in PLAN_DOCUMENT_DECODE_MARKERS {
        assert!(
            !apply_detail.contains(marker),
            "apply rejected the plan document's shape instead of its meaning: {marker} in {apply_detail}"
        );
    }
    fixture.cleanup();
}

/// The durable status projection of one removal this binary knows about is
/// bounded, typed and non-success.
///
/// Apply admits the frozen plan durably under the plan's own removal identity and
/// then refuses at the owner's destructive fence because the install transaction
/// the plan names is absent from the store. `canary-removal-status` and
/// `recover-canary-removal` then run against that same removal identity. The
/// projection must name the removal and install transaction identities, the
/// generation, the plan digest and the registry revision the plan was admitted
/// against; must carry every planned row — including the `StoreObjects` row whose
/// action is `Unsupported`, which the owner must keep in the denominator rather
/// than drop or pre-resolve — as still unresolved; must carry both retained
/// uncertainties; must publish a `next_permitted_action`; and must publish exactly
/// the owner's declared member set, every string of which is an identity handle
/// this fixture authored or one of the owner's closed typed classes, so no
/// credential, environment value or free-form absolute path can appear where a
/// `PlatformHandle` is specified. Neither status nor recovery may report success.
///
/// Proof ceiling, stated rather than hidden: the owner's own
/// `Unsupported`-cleanup refusal now runs behind both the install-transaction load
/// and the already-retired check inside `revalidate_fence`, so no fixture this
/// package can build reaches that sentence. What is reachable, and what this test
/// pins, is that the row stays a reported open row of the denominator.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the bounded status projection is asserted member by member"
)]
#[test]
fn canary_removal_status_reports_the_blocking_row_and_next_action() {
    let fixture = removal_owner_fixture("status");
    let authorization = ManagedEnvironmentChangeRequest {
        request_id: fixture_handle("request:remove-canary-status"),
        requester_and_reason: fixture_handle("requester:test"),
        action: ManagedEnvironmentAction::Remove,
        target_family: fixture_handle("family:eliot"),
        exact_candidate: fixture.generation.clone(),
        expected_delta: fixture_handle("delta:removed"),
        source_assurance_refs: vec![fixture_handle("evidence:source-assurance")],
        affected_refs: Vec::new(),
        impact_class: fixture_handle("impact:test"),
        required_owner: fixture_handle("owner:installation"),
        rollback_plan: fixture_handle("rollback:remove-canary-status"),
        verifier: fixture_handle("verifier:installation"),
        budget: fixture_handle("budget:test"),
        stop_condition: fixture_handle("stop:on-failure"),
    };
    let (envelope, effect_ids) = removal_plan_envelope(
        &fixture.install_transaction_id,
        &fixture.generation,
        &fixture.host_state_root,
        &authorization,
        RemovalFixtureRows::BlockingUnsupported,
    );
    let removal_transaction_id = envelope.plan.removal_transaction_id.clone();
    let mut plan_bytes =
        serde_json::to_vec_pretty(&envelope).expect("serialise the versioned plan envelope");
    plan_bytes.push(b'\n');
    let plan_path = fixture.temp_root.join("removal-plan.json");
    fs::write(&plan_path, &plan_bytes).expect("write the unmodified plan document");

    // Make this binary know the removal: apply admits it durably under the plan's
    // own removal identity and then refuses inside the owner's fence.
    let applied = run_removal_command(
        &fixture.apply_canary_removal_args(&plan_path),
        &fixture.temp_root,
    );
    let apply_transcript = format!(
        "{}\n{}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    assert_eq!(
        applied.status.code(),
        Some(2),
        "an admitted but unfinished removal must not exit zero: {apply_transcript}"
    );
    let apply_output: Value =
        serde_json::from_slice(&applied.stdout).expect("apply-canary-removal typed answer");
    assert_installation_error(&apply_output, "INSTALLATION_REMOVE_CANARY_APPLY_NOT_FOUND");
    assert!(
        apply_output["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains(fixture.install_transaction_id.as_str())),
        "apply must refuse on the owner's own fence about the plan's install transaction: \
         {apply_transcript}"
    );

    let status = run_removal_command(
        &fixture.canary_removal_status_args(&removal_transaction_id),
        &fixture.temp_root,
    );
    let status_transcript = format!(
        "{}\n{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    assert_eq!(
        status.status.code(),
        Some(2),
        "an admitted but unfinished removal must not exit zero: {status_transcript}"
    );
    let status_output: Value =
        serde_json::from_slice(&status.stdout).expect("canary-removal-status projection");
    assert_eq!(status_output["contract"], "eliot.kernel.installation");
    assert_eq!(
        status_output["scope"],
        "bounded_all_effects_or_exact_rollback"
    );
    assert_eq!(status_output["status"], "ADMITTED");
    assert_eq!(status_output["completed"], false);
    let removal = &status_output["removal"];

    // Bounded and typed: exactly the owner's declared member set.
    let members = removal
        .as_object()
        .expect("the removal projection is a JSON object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        members.len(),
        CANARY_REMOVAL_STATUS_MEMBERS.len(),
        "the removal projection published an unexpected member set: {members:?}"
    );
    for member in CANARY_REMOVAL_STATUS_MEMBERS {
        assert!(
            removal.get(member).is_some(),
            "the removal projection dropped the owner's `{member}` member: {status_transcript}"
        );
    }

    // Every identity the projection names is the one this fixture submitted.
    assert_eq!(
        removal["removal_transaction_id"].as_str(),
        Some(removal_transaction_id.as_str())
    );
    assert_eq!(
        removal["install_transaction_id"].as_str(),
        Some(fixture.install_transaction_id.as_str())
    );
    assert_eq!(
        removal["generation"].as_str(),
        Some(fixture.generation.as_str())
    );
    assert_eq!(
        removal["plan_digest"].as_str(),
        Some(envelope.plan.plan_digest.as_str())
    );
    assert_eq!(removal["registry_revision"], Value::from(1_u64));

    // The whole denominator is still open, the `StoreObjects`/`Unsupported` row
    // included: a plan may never drop it from the reported set.
    assert!(
        removal["resolved_effect_ids"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "no row of an admitted removal may already be resolved: {status_transcript}"
    );
    // The repair's blocking row specifically: the Store/Blob row the owner cannot
    // remove stays a reported OPEN row. Reporting it resolved would let a plan
    // stand in for an owner readback that never happened; dropping it would let
    // the denominator shrink below the plan.
    let unsupported_store_objects_row = fixture_handle("canary-removal/row:store-objects");
    assert!(
        removal["unresolved_effect_ids"]
            .as_array()
            .is_some_and(|identities| identities.iter().any(|identity| {
                identity.as_str() == Some(unsupported_store_objects_row.as_str())
            })),
        "the unsupported Store/Blob row must stay a reported open row: {status_transcript}"
    );
    assert_eq!(
        removal["unresolved_effect_ids"]
            .as_array()
            .expect("unresolved effect ids")
            .iter()
            .map(|value| value.as_str().expect("effect identity"))
            .collect::<Vec<_>>(),
        effect_ids
            .iter()
            .map(PlatformHandle::as_str)
            .collect::<Vec<_>>(),
        "the projection must report every planned row, the unsupported Store/Blob row included: \
         {status_transcript}"
    );
    assert!(
        removal["blocking_effect_id"].is_null(),
        "an operation that never started a row has no blocking row yet: {status_transcript}"
    );
    assert!(removal["primary_uncertainty"].is_null());
    assert!(removal["cleanup_uncertainty"].is_null());
    assert!(
        removal["evidence_refs"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "an admitted removal retains no resolved evidence yet: {status_transcript}"
    );

    // The only action the owner admits next is not a success action.
    assert_eq!(
        removal["next_permitted_action"].as_str(),
        Some("RECONCILE"),
        "an admitted removal must not advertise a terminal action: {status_transcript}"
    );
    assert_ne!(status_output["status"].as_str(), Some("COMPLETED"));

    // Nothing in the projection is a credential, an environment value or a
    // free-form absolute path where a `PlatformHandle` is specified. The only
    // strings this fixture did not submit are the owner's own closed typed
    // classes, which carry no identity and no value at all.
    let mut leaves = Vec::new();
    json_string_leaves(removal, &mut leaves);
    let authored = [
        removal_transaction_id.as_str(),
        fixture.install_transaction_id.as_str(),
        fixture.generation.as_str(),
        envelope.plan.plan_digest.as_str(),
        "ADMITTED",
        "RECONCILE",
    ]
    .into_iter()
    .chain(effect_ids.iter().map(PlatformHandle::as_str))
    .collect::<Vec<_>>();
    assert!(
        !leaves.is_empty(),
        "the removal projection published no identity at all"
    );
    for leaf in &leaves {
        assert!(
            authored.contains(&leaf.as_str()),
            "the removal projection published a value this fixture never submitted: {leaf}"
        );
        assert!(
            !leaf.contains('='),
            "the removal projection published an environment assignment: {leaf}"
        );
        assert!(
            !leaf.contains(":\\") && !leaf.contains(":/"),
            "the removal projection published a free-form absolute path where a PlatformHandle \
             is specified: {leaf}"
        );
    }

    // Recovery reuses the same operation identity and re-enters the same owner
    // fence instead of admitting a fresh removal identity or reporting success.
    let recovered = run_removal_command(
        &fixture.recover_canary_removal_args(&removal_transaction_id),
        &fixture.temp_root,
    );
    let recover_transcript = format!(
        "{}\n{}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        recovered.status.code(),
        Some(2),
        "recovery of an unfinished removal must not report success: {recover_transcript}"
    );
    let recover_output: Value =
        serde_json::from_slice(&recovered.stdout).expect("recover-canary-removal typed answer");
    assert_installation_error(
        &recover_output,
        "INSTALLATION_REMOVE_CANARY_RECOVER_NOT_FOUND",
    );
    assert!(
        recover_output["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains(fixture.install_transaction_id.as_str())),
        "recovery must reach the owner's own fence about the same plan's install transaction: \
         {recover_transcript}"
    );
    fixture.cleanup();
}

/// The two evidence-handle shapes this mechanism used to fabricate about itself.
///
/// `canary-removal/evidence/store-owner:<generation>` restated the Store row's own
/// generation identity and could never fail, and `canary-removal/readback/registry-terminal:`
/// stood in for a registry reload that never happened. Neither may reach anything an
/// operator reads, because a removal is never proved by a string this owner wrote about
/// itself. These are the same two prefixes the owner's own record-level proof
/// scans for (`tests.rs::canary_removal_stops_on_an_unreadable_row_before_any_destructive_call`),
/// and neither exists in production source: the only `canary-removal/evidence/`
/// handles the owner mints are FROZEN plan-time ownership evidence inside a plan
/// document (`canary_removal.rs::ownership_evidence`
/// `canary-removal/evidence/install-effect:…` and
/// `canary_removal.rs::registry_record_row`
/// `canary-removal/evidence/registry-record:…`), and `canary-removal/readback/`
/// exists nowhere in the crate outside tests.
#[cfg(windows)]
const FABRICATED_REMOVAL_EVIDENCE_HANDLES: [&str; 2] = [
    "canary-removal/evidence/store-owner:",
    "canary-removal/readback/registry-terminal:",
];

/// Asserts one removal route's whole published answer carries no fabricated
/// evidence handle and — on a fixture whose frozen plans classify no row
/// `Unsupported` — no `UNSUPPORTED` token, and is the owner's own output.
///
/// stdout and stderr are scanned TOGETHER, because a route that published either
/// string on either stream published it. The scans are kept from passing for want
/// of output: the typed answer is parsed and must carry the bounded installation
/// scope, a false `completed` member, and either a typed refusal `code` or the
/// owner's own `removal` projection with its `stage` and
/// `next_permitted_action` members. The caller then pins the exact code, the exact
/// owner-composed `detail` member, or the exact projection members, so this helper
/// cannot pass for a route that crashed or that answered with nothing.
///
/// The fabricated-handle scan is bounded to the routes that publish a refusal or a
/// status disposition, none of which prints a plan document on this fixture. That
/// bound is asserted here rather than assumed, so a route that started printing its
/// frozen plan — whose `ownership_evidence` legitimately uses the
/// `canary-removal/evidence/` namespace — fails loudly instead of silently making
/// this scan weaker than it reads.
///
/// Scope of the `UNSUPPORTED` scan, stated rather than glossed. It holds for every
/// caller HERE because every caller freezes its plan through `removal_plan_envelope`
/// with the `NamedOutOfScope` arm, which classifies every row `Remove`, `Retain` or
/// `OutOfScope` and never `Unsupported`. That is a property of those fixtures, not of
/// the production surface. The owner's own required-cleanup refusal is still reachable
/// and deliberately kept: `unsupported_cleanup_refusal`
/// (`crates/kernel/eliot-installation/src/canary_removal.rs::unsupported_cleanup_refusal`) composes one
/// sentence carrying the literal words `UNSUPPORTED` and `OUT_OF_SCOPE`, and it is
/// returned for a frozen plan that carries a row classified `Unsupported`
/// (`canary_removal.rs::classify_action`) — a classification `CanaryRemovalEffect::validate`
/// admits (`canary_removal.rs::CanaryRemovalEffect::validate`) and `apply_canary_removal` admits for any
/// externally supplied envelope. So a plan naming a required cleanup this owner has
/// no path for still answers with both of those words, and this scan would be red
/// on it. What is NOT fixture-scoped is the pair asserted alongside every scan
/// here: the closed `INSTALLATION_REMOVE_CANARY_*` code set its callers pin each
/// route inside, and the two CLI-local prose markers below. A route that regressed
/// to `INSTALLATION_REMOVE_CANARY_UNSUPPORTED`, to that same blocker under another
/// code, or to its prose is red on all of them.
#[cfg(windows)]
fn assert_no_fabricated_removal_evidence(route: &str, result: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&result.stderr).into_owned();
    let transcript = format!("{stdout}\n{stderr}");

    assert!(
        !transcript.contains("UNSUPPORTED"),
        "{route} published an UNSUPPORTED refusal again, on a fixture whose frozen rows are \
         Remove, Retain or OutOfScope and none of them Unsupported. The two shared surfaces \
         are named OutOfScope rows now, and a required-cleanup blocker is not what this \
         owner says about them: {transcript}"
    );
    for fabricated in FABRICATED_REMOVAL_EVIDENCE_HANDLES {
        assert!(
            !transcript.contains(fabricated),
            "{route} presented a handle shaped {fabricated} as removal evidence; a removal is \
             never proved by a handle its own owner minted about itself: {transcript}"
        );
    }
    for marker in REMOVE_CANARY_CLI_LOCAL_REFUSAL {
        assert!(
            !transcript.contains(marker),
            "{route} kept CLI-local refusal prose: {marker} in {transcript}"
        );
    }
    assert!(
        !stdout.contains("canary_removal_wire_version"),
        "{route} printed a canary-removal plan document. A frozen plan legitimately carries \
         plan-time ownership evidence, so the fabricated-handle scan above is only valid \
         while no plan document is published here: {transcript}"
    );

    // The positive half: this route really published the owner's typed answer.
    let output: Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!(
            "{route} must answer with the typed installation envelope, not usage text or prose: \
             {error}; {transcript}"
        )
    });
    assert_eq!(
        output["scope"], "bounded_all_effects_or_exact_rollback",
        "{route} must answer under the bounded installation scope: {transcript}"
    );
    assert_eq!(
        output["completed"], false,
        "{route} must never report a completed operation on this fixture: {transcript}"
    );
    if let Some(code) = output["code"].as_str() {
        assert_eq!(
            output["status"], "ERROR",
            "{route} published a refusal code with a non-error status: {transcript}"
        );
        assert!(
            code.starts_with(REMOVE_CANARY_REFUSAL_PREFIX),
            "{route} published a refusal code outside the removal namespace: {code} ({transcript})"
        );
    } else {
        assert_eq!(
            output["contract"].as_str(),
            Some("eliot.kernel.installation"),
            "{route} published neither a typed refusal code nor the owner's removal \
             projection: {transcript}"
        );
        let removal = output["removal"]
            .as_object()
            .unwrap_or_else(|| panic!("{route} published no removal projection: {transcript}"));
        assert!(
            !removal.is_empty(),
            "{route} published an empty removal projection: {transcript}"
        );
        assert!(
            removal["stage"].is_string() && removal["next_permitted_action"].is_string(),
            "{route} published a removal projection without its typed stage and next permitted \
             action: {transcript}"
        );
    }
    transcript
}

/// The two shared surfaces the owner classifies `OutOfScope` are NAMED in the
/// reported removal denominator and are never readable as verified.
///
/// `CanaryRemovalAction::OutOfScope`
/// (`crates/kernel/eliot-installation/src/canary_removal.rs::CanaryRemovalAction::OutOfScope`) is issue
/// #1138's algorithm step 2 read literally: the row stays in the denominator
/// carrying the owner-recorded identity, the ownership evidence and the
/// reconciliation query that are frozen in the plan, it is never reported as
/// `Retain` and proved — `Retain` is a readback outcome and no owner this crate
/// can reach reports one for either surface — and it therefore requires no
/// readback and does not block apply. The whole point of the classification is
/// what an OPERATOR can tell: both surfaces were named rather than silently
/// dropped, and neither can be read as verified.
///
/// So this is asserted at the `installation canary-removal-status` surface, on a
/// removal that really is durably admitted, in both directions. Named: the
/// reported denominator is exactly the four frozen rows in plan order, and the
/// two out-of-scope categories are two of them under the same
/// `canary-removal/effect/…` identity shape the owner's own `canary_evidence_row`
/// and `store_objects_row` mint (`canary_removal.rs::canary_evidence_row` and
/// `canary_removal.rs::store_objects_row`), which is what makes the category
/// legible in the projection at all. Not verified: no row is resolved, `evidence_refs` is empty, no string leaf of the whole printed
/// payload is a fabricated evidence handle, neither of the two plan-time
/// owner-recorded identities is re-published as if it were a readback result, the
/// exit code is non-zero and `next_permitted_action` is `RECONCILE` rather than
/// the `READBACK` the owner admits only once the whole denominator is resolved.
/// Every absence assertion is paired with a positive one: the projection is
/// asserted to carry its exact declared member set, the four row identities, the
/// four durable identities of this fixture and the owner's two closed typed
/// classes, so none of the absence checks can pass on an empty or crashed answer.
///
/// What makes this red, in one line: an admission or a projection that drops an
/// `OutOfScope` row from the denominator, pre-resolves one, attaches an evidence
/// handle to one, or re-publishes a row's frozen ownership identity as a proof.
///
/// Proof ceiling, stated rather than hidden. Two, and neither is papered over by
/// a claim this test makes:
///
/// * No removal this package can drive reaches `Completed`. The store's only
///   transaction-publishing constructor, `RedbInstallationTransactionStore::create_planned_at_exact_path`,
///   refuses a transaction whose `profile_governed_roots` is unset
///   (`redb_state.rs::RedbInstallationTransactionStore::create_planned_at_exact_path`),
///   and the only
///   constructor this package can call, `InstallationTransaction::new_unbound_for_fixture`
///   (`transaction.rs:656`), leaves that binding unset outside the owning crate's
///   own `cfg(test)` (`transaction.rs:799`); `create_canary_removal_operation` itself is
///   `pub(crate)` (`redb_state.rs::create_canary_removal_operation`). This test
///   therefore observes stage
///   `ADMITTED` and proves the naming and the non-verification of the rows. It
///   proves nothing about a removal that drove a row to a mutating outcome, and
///   `plan-canary-removal` cannot return `Ok` from this package at all, so the
///   audit's literal "capture plan stdout and feed it to apply" is owner-level
///   proven only (`plan_canary_removal_stdout_is_accepted_by_apply_canary_removal_unmodified`
///   above states the same ceiling for the document itself).
/// * The fence that PINS these two categories to `OutOfScope` is not reached here.
///   `require_quiesced_owner_effects` compares each owner-derived row's identity
///   and action against the transaction the durable store holds
///   (`canary_removal.rs::require_quiesced_owner_effects`), and inside
///   `canary_removal.rs::revalidate_fence` that call runs AFTER the
///   install-transaction load, which is exactly what refuses this fixture. So what
///   this test proves is the ADMISSION and PROJECTION surface — the rows survive
///   admission and are named in the reported denominator — and the enforcement half
///   is the owning crate's own proof, not this package's.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the projection is asserted member by member, in both the named and the not-verified direction"
)]
#[test]
fn canary_removal_status_reports_the_out_of_scope_rows_as_named_not_verified() {
    let fixture = removal_owner_fixture("out-of-scope-rows");
    let authorization = ManagedEnvironmentChangeRequest {
        request_id: fixture_handle("request:remove-canary-out-of-scope-rows"),
        requester_and_reason: fixture_handle("requester:test"),
        action: ManagedEnvironmentAction::Remove,
        target_family: fixture_handle("family:eliot"),
        exact_candidate: fixture.generation.clone(),
        expected_delta: fixture_handle("delta:removed"),
        source_assurance_refs: vec![fixture_handle("evidence:source-assurance")],
        affected_refs: Vec::new(),
        impact_class: fixture_handle("impact:test"),
        required_owner: fixture_handle("owner:installation"),
        rollback_plan: fixture_handle("rollback:remove-canary-out-of-scope-rows"),
        verifier: fixture_handle("verifier:installation"),
        budget: fixture_handle("budget:test"),
        stop_condition: fixture_handle("stop:on-failure"),
    };
    let (envelope, effect_ids) = removal_plan_envelope(
        &fixture.install_transaction_id,
        &fixture.generation,
        &fixture.host_state_root,
        &authorization,
        RemovalFixtureRows::NamedOutOfScope,
    );
    let removal_transaction_id = envelope.plan.removal_transaction_id.clone();

    // The two out-of-scope rows, under the effect-identity shapes the owner's own
    // row constructors mint. These are fixture-authored STRINGS; what is under test
    // is that the owner reports them in the denominator at all, and the plan
    // document below is the independent statement of what was admitted.
    let canary_evidence_root_row = fixture_handle(format!(
        "canary-removal/effect/canary-evidence-root:{}",
        fixture.install_transaction_id.as_str()
    ));
    let store_objects_row = fixture_handle(format!(
        "canary-removal/effect/store-objects:{}",
        fixture.generation.as_str()
    ));
    let out_of_scope_rows = [canary_evidence_root_row.clone(), store_objects_row.clone()];
    for row in &out_of_scope_rows {
        assert!(
            effect_ids.contains(row),
            "the frozen fixture plan does not carry {row}; the naming proof needs it admitted"
        );
    }
    assert_eq!(
        effect_ids.len(),
        4,
        "the frozen plan must account for exactly the installer-effect row, the two out-of-scope \
         rows and the terminal registry record: {effect_ids:?}"
    );
    let store_binding = envelope
        .plan
        .effects
        .iter()
        .find(|effect| effect.effect_id == store_objects_row)
        .expect("the frozen Store/Blob row");
    let evidence_root_identity = envelope
        .plan
        .effects
        .iter()
        .find(|effect| effect.effect_id == canary_evidence_root_row)
        .expect("the frozen canary evidence root row");
    // Preconditions on the document this fixture admitted, asserted so the proof
    // below cannot silently degrade into proving something about a different
    // classification: both rows really carry `OutOfScope`, neither claims an
    // installer effect (the owner refuses that pairing,
    // `canary_removal.rs::CanaryRemovalEffect::validate`),
    // and each is named with its owner-recorded identity as its ownership
    // evidence, which is what `OutOfScope` says it is and NOT a readback result.
    for (label, row) in [
        ("canary evidence root", evidence_root_identity),
        ("Store/Blob", store_binding),
    ] {
        assert_eq!(
            row.action,
            CanaryRemovalAction::OutOfScope,
            "the frozen {label} row must carry the OutOfScope classification under test"
        );
        assert!(
            row.install_effect_index.is_none(),
            "the frozen {label} row must name no installer effect; OutOfScope is for a surface no \
             owner in this crate can observe"
        );
        assert_eq!(
            row.origin,
            CanaryRemovalResourceOrigin::ForeignToThisRemoval,
            "the frozen {label} row must record that the surface is not this removal's to destroy"
        );
        assert!(
            row.ownership_evidence.contains(&row.resource_identity),
            "the frozen {label} row must name its owner-recorded identity as its ownership \
             evidence: {row:?}"
        );
    }
    assert_ne!(
        store_binding.resource_identity, evidence_root_identity.resource_identity,
        "the two shared surfaces must be frozen under distinct identities; one handle for both \
         would name one surface, not two"
    );
    let store_binding = store_binding.resource_identity.as_str();
    let evidence_root_identity = evidence_root_identity.resource_identity.as_str();

    let mut plan_bytes =
        serde_json::to_vec_pretty(&envelope).expect("serialise the versioned plan envelope");
    plan_bytes.push(b'\n');
    let plan_path = fixture.temp_root.join("removal-plan.json");
    fs::write(&plan_path, &plan_bytes).expect("write the unmodified plan document");

    // Admit the removal durably, the way the status route needs it. Apply refuses
    // at the owner's fence because the install transaction this plan names is
    // absent from the store, and that refusal is itself asserted: an admitted row
    // this test did not really create could not be what status reads back.
    let applied = run_removal_command(
        &fixture.apply_canary_removal_args(&plan_path),
        &fixture.temp_root,
    );
    let apply_transcript = format!(
        "{}\n{}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    assert_eq!(
        applied.status.code(),
        Some(2),
        "an admitted but unfinished removal must not exit zero: {apply_transcript}"
    );
    let apply_output: Value =
        serde_json::from_slice(&applied.stdout).expect("apply-canary-removal typed answer");
    assert_installation_error(&apply_output, "INSTALLATION_REMOVE_CANARY_APPLY_NOT_FOUND");
    assert!(
        apply_output["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains(fixture.install_transaction_id.as_str())),
        "apply must refuse on the owner's own fence about the plan's install transaction: \
         {apply_transcript}"
    );

    // The operator surface under test.
    let status = run_removal_command(
        &fixture.canary_removal_status_args(&removal_transaction_id),
        &fixture.temp_root,
    );
    let status_transcript = format!(
        "{}\n{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    assert_eq!(
        status.status.code(),
        Some(2),
        "a removal with two named, never-verified rows must not exit zero; the exit code follows \
         the projected stage: {status_transcript}"
    );
    let status_output: Value =
        serde_json::from_slice(&status.stdout).expect("canary-removal-status projection");
    assert_eq!(status_output["contract"], "eliot.kernel.installation");
    assert_eq!(
        status_output["scope"],
        "bounded_all_effects_or_exact_rollback"
    );
    assert_eq!(
        status_output["status"], "ADMITTED",
        "the owner must project the admitted stage it durably recorded: {status_transcript}"
    );
    assert_eq!(
        status_output["completed"], false,
        "an admitted removal is not a completed one: {status_transcript}"
    );
    let removal = &status_output["removal"];

    // Bounded and typed: exactly the member set `CanaryRemovalStatus` declares
    // (canary_removal.rs::CanaryRemovalStatus), so no evidence member can be added to the
    // projection without failing here.
    let members = removal
        .as_object()
        .expect("the removal projection is a JSON object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        members.len(),
        CANARY_REMOVAL_STATUS_MEMBERS.len(),
        "the removal projection published an unexpected member set: {members:?}"
    );
    for member in CANARY_REMOVAL_STATUS_MEMBERS {
        assert!(
            removal.get(member).is_some(),
            "the removal projection dropped the owner's `{member}` member: {status_transcript}"
        );
    }

    // NAMED. The four identities this fixture admitted, in the order the owner
    // projected them, with both out-of-scope categories among them. Reporting the
    // denominator is a claim about the OWNER: it could drop any row it liked.
    assert_eq!(
        removal["unresolved_effect_ids"]
            .as_array()
            .expect("unresolved effect ids")
            .iter()
            .map(|value| value.as_str().expect("effect identity"))
            .collect::<Vec<_>>(),
        effect_ids
            .iter()
            .map(PlatformHandle::as_str)
            .collect::<Vec<_>>(),
        "the reported denominator must name every admitted row, both out-of-scope rows \
         included: {status_transcript}"
    );
    for row in &out_of_scope_rows {
        assert!(
            removal["unresolved_effect_ids"]
                .as_array()
                .is_some_and(|identities| identities
                    .iter()
                    .any(|identity| identity.as_str() == Some(row.as_str()))),
            "the out-of-scope row {row} was dropped from the reported denominator: \
             {status_transcript}"
        );
    }

    // NOT VERIFIED. No row is resolved, so no row — and therefore neither
    // out-of-scope row — is reported as having an authoritative outcome.
    assert!(
        removal["resolved_effect_ids"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "no row of a just-admitted removal may already be resolved, and an out-of-scope row can \
         never be one: {status_transcript}"
    );
    assert!(
        removal["evidence_refs"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "an admitted removal retains no resolved evidence; an evidence handle here would be \
         standing in for a readback that no owner ever reported: {status_transcript}"
    );
    assert!(
        removal["blocking_effect_id"].is_null()
            && removal["primary_uncertainty"].is_null()
            && removal["cleanup_uncertainty"].is_null(),
        "an operation that has started no row has no blocking row and no retained uncertainty: \
         {status_transcript}"
    );

    // NOT VERIFIED, at the string level, over the WHOLE printed payload rather
    // than over the members this test happened to think of. `RESOLVED` is a durable
    // row state an owner-reported readback would have to reach for, and both
    // fabricated handle shapes are the ones this mechanism used to mint about
    // itself; neither may appear where an operator reads a disposition.
    let mut payload_leaves = Vec::new();
    json_string_leaves(&status_output, &mut payload_leaves);
    assert!(
        !payload_leaves.is_empty(),
        "the printed disposition carried no string at all, so the scans below could not fail"
    );
    assert!(
        !payload_leaves
            .iter()
            .any(|leaf| leaf.as_str() == "RESOLVED"),
        "the printed disposition reported a RESOLVED row while resolving none: {status_transcript}"
    );
    for fabricated in FABRICATED_REMOVAL_EVIDENCE_HANDLES {
        assert!(
            !payload_leaves
                .iter()
                .any(|leaf| leaf.starts_with(fabricated)),
            "the printed disposition presented a fabricated handle shaped {fabricated} as \
             evidence: {status_transcript}"
        );
    }
    // The near neighbours that ARE present, which is what makes the scan above
    // discriminating rather than passing for want of anything to match.
    assert!(
        payload_leaves
            .iter()
            .any(|leaf| leaf.starts_with("canary-removal/effect/canary-evidence-root:")),
        "the projection must carry the canary evidence root row identity, so the fabricated-handle \
         scan above ran against a payload that really does carry row identities: \
         {status_transcript}"
    );
    // The two plan-time owner-recorded identities must not come back out as a
    // result. They are the exact handles `OutOfScope` exists to name WITHOUT
    // claiming them proved, so re-publishing one would be the classification read
    // as verification.
    for (label, frozen_identity) in [
        ("canary evidence root", evidence_root_identity),
        ("Store bridge binding", store_binding),
    ] {
        assert!(
            !payload_leaves
                .iter()
                .any(|leaf| leaf.as_str() == frozen_identity),
            "the printed disposition re-published the {label} identity the plan froze \
             ({frozen_identity}) as if it were a removal result: {status_transcript}"
        );
    }

    // The four durable identities this fixture submitted, so nothing above can
    // pass because the projection published nothing recognisable, and nothing in
    // it is a credential, an environment value or a free-form absolute path.
    assert_eq!(
        removal["removal_transaction_id"].as_str(),
        Some(removal_transaction_id.as_str())
    );
    assert_eq!(
        removal["install_transaction_id"].as_str(),
        Some(fixture.install_transaction_id.as_str())
    );
    assert_eq!(
        removal["generation"].as_str(),
        Some(fixture.generation.as_str())
    );
    assert_eq!(
        removal["plan_digest"].as_str(),
        Some(envelope.plan.plan_digest.as_str())
    );
    assert_eq!(removal["registry_revision"], Value::from(1_u64));
    let mut removal_leaves = Vec::new();
    json_string_leaves(removal, &mut removal_leaves);
    let authored = [
        removal_transaction_id.as_str(),
        fixture.install_transaction_id.as_str(),
        fixture.generation.as_str(),
        envelope.plan.plan_digest.as_str(),
        "ADMITTED",
        "RECONCILE",
    ]
    .into_iter()
    .chain(effect_ids.iter().map(PlatformHandle::as_str))
    .collect::<Vec<_>>();
    assert!(
        !removal_leaves.is_empty(),
        "the removal projection published no identity at all"
    );
    for leaf in &removal_leaves {
        assert!(
            authored.contains(&leaf.as_str()),
            "the removal projection published a value this fixture never submitted: {leaf}"
        );
        assert!(
            !leaf.contains('='),
            "the removal projection published an environment assignment: {leaf}"
        );
    }

    // The only action the owner admits next is not a success action. `READBACK` is
    // the terminal action, admitted only once the whole denominator is resolved,
    // so publishing it here would be this projection claiming the two unobservable
    // surfaces were proved.
    assert_eq!(
        removal["next_permitted_action"].as_str(),
        Some("RECONCILE"),
        "a removal whose whole denominator is open must ask for reconciliation: {status_transcript}"
    );
    assert_ne!(
        removal["next_permitted_action"].as_str(),
        Some("READBACK"),
        "an out-of-scope row can never be read back by any owner this owner can reach, so this \
         projection must never advertise the terminal action: {status_transcript}"
    );
    assert_ne!(status_output["status"].as_str(), Some("COMPLETED"));
    fixture.cleanup();
}

/// On the fixture below, no governed canary-removal route prints a fabricated
/// evidence handle or an `UNSUPPORTED` token, and every route answers with the
/// owner's own typed output.
///
/// This is the all-route form of the single-route check
/// `installation_remove_canary_reaches_the_installation_owner` makes for
/// `remove-canary` alone, and it is the check the audit's "no CLI-local deletion
/// or unsupported route" clause needs. All FIVE routes are covered here:
/// `remove-canary`, `plan-canary-removal`, `apply-canary-removal`,
/// `canary-removal-status` and `recover-canary-removal`. For each one, stdout and
/// stderr together must carry no `...UNSUPPORTED` token, no handle shaped
/// `canary-removal/evidence/store-owner:` or `canary-removal/readback/registry-terminal:`,
/// and no CLI-local blocker prose; and what it DID publish is pinned as the
/// owner's own — the exact `INSTALLATION_REMOVE_CANARY_*` code inside that route's
/// OWN closed phase set, plus a `detail` member carrying a sentence the owner
/// composes, or the owner's own `removal` projection.
///
/// Scope of the `...UNSUPPORTED` scan, stated rather than glossed: it is a property
/// of THIS fixture, not an unconditional property of the routes. The plan all five
/// routes run against is frozen here with `RemovalFixtureRows::NamedOutOfScope`,
/// and that arm classifies every row `Remove`, `Retain` or `OutOfScope` and never
/// `Unsupported`, so no frozen row of this fixture can make the owner's own
/// required-cleanup refusal answer. That refusal is still reachable in production
/// and deliberately kept: `unsupported_cleanup_refusal`
/// (`crates/kernel/eliot-installation/src/canary_removal.rs::unsupported_cleanup_refusal`) composes one
/// sentence carrying the literal words `UNSUPPORTED` and `OUT_OF_SCOPE` and is
/// returned for a frozen plan carrying a row classified `Unsupported`
/// (`canary_removal.rs::classify_action`), which `apply_canary_removal` admits for any
/// externally supplied envelope. The fixture-independent half of the same
/// requirement is asserted here too: the closed code set each route is pinned
/// inside cannot express the retired `INSTALLATION_REMOVE_CANARY_UNSUPPORTED`
/// code, and neither CLI-local sentence is one the owner composes.
///
/// Fixture state, stated rather than glossed. `recover-canary-removal` needs an
/// already ADMITTED removal: `recover_canary_removal` starts from
/// `load_operation` (`canary_removal.rs::load_operation`) and returns the owner's
/// `TransactionNotFound` for an identity that was never admitted, which is a
/// different answer and would not demonstrate that recovery reaches the owner's
/// fence about this plan's install transaction. So the admitting route
/// (`apply-canary-removal`) runs first and the recovery route runs last against
/// the identity it really recorded. That ordering is also why
/// `apply-canary-removal` is invoked with the frozen plan document rather than
/// being skipped: it is the only one of the five that admits a durable row here,
/// and its refusal is asserted as the owner's own so the rows this test then reads
/// are not rows it imagined.
///
/// Proof ceiling, stated rather than hidden. `plan-canary-removal` cannot return
/// `Ok` from this package: it resolves its target from the accepted installation
/// registry, and publishing an accepted generation needs an `ActiveVerified`
/// install transaction, which needs the generation staging this package cannot
/// drive (see [`RemovalOwnerFixture`]). So the audit's literal "capture plan
/// stdout and feed it to apply" is owner-level proven only, and what is asserted
/// here is that the plan route reaches the same owner seam, publishes no plan
/// document and no fabricated handle, and answers inside its own `PLAN` phase set.
/// The plan document handed to apply is the owner's own `CanaryRemovalPlanEnvelope`
/// serialised exactly the way the plan surface prints it, which
/// `plan_canary_removal_stdout_is_accepted_by_apply_canary_removal_unmodified` above
/// already separates from the literal capture-and-feed claim. The second ceiling is
/// the one this file already records for every canary-removal route: no removal
/// this package can drive reaches `Completed`, because the store's only
/// transaction-publishing constructor refuses a transaction whose
/// `profile_governed_roots` is unset
/// (`redb_state.rs::RedbInstallationTransactionStore::create_planned_at_exact_path`)
/// and the only constructor available here leaves it unset outside the owning
/// crate's `cfg(test)`
/// (`transaction.rs:799`). Every route therefore answers on the bounded non-zero
/// refusal exit or on a non-completed projection, and a completed removal stays the
/// #11 installed pulse.
///
/// What makes this red, in one line: any one of the five routes composing the
/// retired CLI-local `...UNSUPPORTED` refusal or either fabricated handle, or
/// answering with anything other than the owner's own typed refusal or
/// projection. A required-cleanup `UNSUPPORTED` refusal cannot be composed on
/// this fixture at all, because no row of it is classified `Unsupported`.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "five routes are each asserted on the fabricated-handle scans and on the owner's own answer"
)]
#[test]
fn no_route_prints_a_fabricated_handle_or_the_retired_cli_local_unsupported_refusal() {
    let fixture = removal_owner_fixture("no-fabricated-evidence");
    let authorization = ManagedEnvironmentChangeRequest {
        request_id: fixture_handle("request:remove-canary-no-fabricated-evidence"),
        requester_and_reason: fixture_handle("requester:test"),
        action: ManagedEnvironmentAction::Remove,
        target_family: fixture_handle("family:eliot"),
        exact_candidate: fixture.generation.clone(),
        expected_delta: fixture_handle("delta:removed"),
        source_assurance_refs: vec![fixture_handle("evidence:source-assurance")],
        affected_refs: Vec::new(),
        impact_class: fixture_handle("impact:test"),
        required_owner: fixture_handle("owner:installation"),
        rollback_plan: fixture_handle("rollback:remove-canary-no-fabricated-evidence"),
        verifier: fixture_handle("verifier:installation"),
        budget: fixture_handle("budget:test"),
        stop_condition: fixture_handle("stop:on-failure"),
    };
    let (envelope, effect_ids) = removal_plan_envelope(
        &fixture.install_transaction_id,
        &fixture.generation,
        &fixture.host_state_root,
        &authorization,
        RemovalFixtureRows::NamedOutOfScope,
    );
    let removal_transaction_id = envelope.plan.removal_transaction_id.clone();
    let mut plan_bytes =
        serde_json::to_vec_pretty(&envelope).expect("serialise the versioned plan envelope");
    plan_bytes.push(b'\n');
    let plan_path = fixture.temp_root.join("removal-plan.json");
    fs::write(&plan_path, &plan_bytes).expect("write the unmodified plan document");

    // The two target-resolving routes. Neither admits anything, so both are
    // expected to answer inside their own phase set with the owner's own
    // registry-resolution sentence.
    for (route, args, operations) in [
        (
            "remove-canary",
            fixture.remove_canary_args(),
            &REMOVE_CANARY_ROUTE_OPERATIONS[..],
        ),
        (
            "plan-canary-removal",
            fixture.plan_canary_removal_args(),
            &REMOVAL_PLAN_ROUTE_OPERATIONS[..],
        ),
    ] {
        let result = run_removal_command(&args, &fixture.temp_root);
        assert_no_fabricated_removal_evidence(route, &result);
        let detail = assert_owner_typed_refusal(
            route,
            operations,
            &result,
            "INSTALLATION_REMOVE_CANARY_PLAN_REFUSED",
            REMOVE_CANARY_OWNER_REGISTRY_REFUSAL,
        );
        assert!(
            detail.contains(fixture.generation.as_str()),
            "{route} must name the exact generation the route was asked about: {detail}"
        );
    }

    // The admitting route. It really admits the two out-of-scope rows durably and
    // then refuses at the owner's fence about the plan's absent install
    // transaction; that refusal is the positive half that proves the row status
    // reads back is one this fixture really created.
    let applied = run_removal_command(
        &fixture.apply_canary_removal_args(&plan_path),
        &fixture.temp_root,
    );
    assert_no_fabricated_removal_evidence("apply-canary-removal", &applied);
    let apply_detail = assert_owner_typed_refusal(
        "apply-canary-removal",
        &REMOVAL_APPLY_ROUTE_OPERATIONS,
        &applied,
        "INSTALLATION_REMOVE_CANARY_APPLY_NOT_FOUND",
        fixture.install_transaction_id.as_str(),
    );

    // The read-only status route, which publishes the owner's projection rather
    // than a refusal. It is asserted to resolve nothing and to retain no evidence,
    // so the fabricated-handle scan over its answer is bounded correctly and the
    // near neighbours it does carry make that scan discriminating.
    let status = run_removal_command(
        &fixture.canary_removal_status_args(&removal_transaction_id),
        &fixture.temp_root,
    );
    let status_transcript = assert_no_fabricated_removal_evidence("canary-removal-status", &status);
    assert_eq!(
        status.status.code(),
        Some(2),
        "the status route must not exit zero for a removal that drove nothing: \
         {status_transcript}"
    );
    let status_output: Value =
        serde_json::from_slice(&status.stdout).expect("canary-removal-status projection");
    let removal = &status_output["removal"];
    assert!(
        removal["resolved_effect_ids"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && removal["evidence_refs"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "the status route published a resolved row or an evidence handle: {status_transcript}"
    );
    assert_eq!(
        removal["unresolved_effect_ids"]
            .as_array()
            .expect("unresolved effect ids")
            .iter()
            .map(|value| value.as_str().expect("effect identity"))
            .collect::<Vec<_>>(),
        effect_ids
            .iter()
            .map(PlatformHandle::as_str)
            .collect::<Vec<_>>(),
        "the status route must report every admitted row, both out-of-scope rows included: \
         {status_transcript}"
    );
    // This route published a projection, not a refusal, so any refusal code on it
    // would be a second answer beside the first. The closed set still applies: the
    // only tag status may ever publish is its own.
    assert_removal_route_owner_codes_only(
        "canary-removal-status",
        &REMOVAL_STATUS_ROUTE_OPERATIONS,
        &status_transcript,
    );

    // The reconciling route, against the identity apply really admitted.
    let recovered = run_removal_command(
        &fixture.recover_canary_removal_args(&removal_transaction_id),
        &fixture.temp_root,
    );
    assert_no_fabricated_removal_evidence("recover-canary-removal", &recovered);
    let recover_detail = assert_owner_typed_refusal(
        "recover-canary-removal",
        &REMOVAL_RECOVER_ROUTE_OPERATIONS,
        &recovered,
        "INSTALLATION_REMOVE_CANARY_RECOVER_NOT_FOUND",
        fixture.install_transaction_id.as_str(),
    );
    // Recovery re-entered the SAME fence about the SAME absent install
    // transaction apply stopped at, which is the observable form of "it reused the
    // one admitted removal identity": a recovery that had found no admitted row
    // would have reported the REMOVAL identity absent instead, and these two
    // sentences would differ.
    assert_eq!(
        recover_detail, apply_detail,
        "recovery must reuse the admitted removal operation and re-enter the same owner fence, \
         not report the removal itself absent: {recover_detail}"
    );
    fixture.cleanup();
}

/// The exact byte-level observation of one durable member.
///
/// A directory is recorded as `directory`, a regular file as
/// `file <byte length> <sha256>`, and anything else — a reparse point, a
/// symlink, anything non-regular — as `other (symlink=…)`. `other` exists so
/// that this walk never silently skips a member it cannot classify: an
/// unclassified member changes the record, and a snapshot that quietly omitted
/// one would not be a snapshot.
#[cfg(windows)]
fn durable_member_observation(entry: &fs::DirEntry) -> String {
    let file_type = entry.file_type().expect("durable member file type");
    if file_type.is_dir() {
        return "directory".to_owned();
    }
    if !file_type.is_file() {
        return format!("other (symlink={})", file_type.is_symlink());
    }
    let bytes = fs::read(entry.path()).expect("read a durable member for its digest");
    format!("file {} {}", bytes.len(), sha256_hex(&bytes))
}

/// True for a recorded member that names a redb database file.
///
/// The comparison is case-insensitive on the extension only, because a
/// case-sensitive suffix test would accept `X.RED` as the owner's registry and
/// reject the owner's real `<hash>.redb` if its own naming ever changed case.
#[cfg(windows)]
fn is_redb_database_member(path: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("redb"))
}

/// Records every member below one durable root, recursively.
///
/// Nothing is filtered and nothing is skipped: directories, regular files and
/// every other entry kind are all recorded, so creating, deleting, renaming or
/// replacing any member changes the record. `label` prefixes each key so the
/// two roots the routes can reach cannot collide.
#[cfg(windows)]
fn collect_durable_members(label: &str, root: &Path, members: &mut Vec<(String, String)>) {
    let mut entries = fs::read_dir(root)
        .unwrap_or_else(|error| {
            panic!(
                "enumerate the durable root {label} at {}: {error}",
                root.display()
            )
        })
        .map(|entry| entry.expect("durable directory entry"))
        .collect::<Vec<_>>();
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let relative = format!("{label}/{}", entry.file_name().to_string_lossy());
        let is_directory = entry
            .file_type()
            .expect("durable member file type")
            .is_dir();
        members.push((relative.clone(), durable_member_observation(&entry)));
        if is_directory {
            collect_durable_members(&relative, &entry.path(), members);
        }
    }
}

/// The complete record of every durable member the governed canary-removal
/// routes can reach on one fixture.
///
/// The route reads exactly two durable roots: the retained per-installation
/// Host root passed as `--host-state-root`, and the caller-owned directory the
/// store path and the explicit `Remove` authorization live in. The Host root is
/// snapshotted from its installation parent, so anything created beside it is
/// recorded too.
#[cfg(windows)]
fn durable_state_members(fixture: &RemovalOwnerFixture) -> Vec<(String, String)> {
    let mut members = Vec::new();
    collect_durable_members(
        "installation-root",
        &fixture.installation_root,
        &mut members,
    );
    collect_durable_members("fixture-root", &fixture.temp_root, &mut members);
    members.sort();
    members
}

/// Renders the record so a difference is reported as raw measurements.
#[cfg(windows)]
fn render_durable_state(members: &[(String, String)]) -> String {
    members
        .iter()
        .map(|(path, observation)| format!("{path} -> {observation}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Prints the raw before/after record of every durable member.
///
/// The comparison below is the assertion; this makes the exact measured lengths
/// and digests visible in the run output rather than only inside a failure
/// message, because "did these database bytes move?" is a measurement and a
/// summary cannot answer it.
#[cfg(windows)]
#[allow(
    clippy::print_stdout,
    reason = "the raw before/after durable-state measurement is the evidence this proof reports"
)]
fn report_durable_state_measurement(
    label: &str,
    before: &[(String, String)],
    after: &[(String, String)],
) {
    println!(
        "durable-state measurement ({label}):\nBEFORE:\n{}\nAFTER:\n{}",
        render_durable_state(before),
        render_durable_state(after)
    );
}

/// Asserts the AFTER record has the BEFORE members and unchanged content.
///
/// Both halves the issue needs are asserted. First the member SET, over every
/// member including the databases, so a created, deleted or renamed member fails
/// even when nothing else moved. Then the byte length and content digest of
/// every member except the ones `writable_databases` names, so a changed byte in
/// any real durable file fails even when the member is still there. The excluded
/// members are REPORTED, not skipped silently: the returned list names every one
/// of them whose bytes actually moved, so the caller can see the measurement and
/// assert on it.
///
/// Only a redb database the owner itself opens for writing belongs in that
/// exclusion list, and that exclusion is a measured property of the owner plus its
/// pinned `redb`, not a convenience. The owner's registry reader,
/// `RedbInstallationRegistry::open_existing_at`, opens the retained registry as a
/// redb WRITER
/// (`crates/kernel/eliot-installation/src/installation_registry.rs:322` through
/// `open_registry_writer_with_retry`, `redb_state.rs::open_registry_writer_with_retry`), and redb commits a
/// quick-repair transaction that deletes and rewrites its own `allocator_state`
/// system table every time a writable handle is dropped
/// (`redb-4.1.0/src/db.rs:1061` `impl Drop for Database` calling
/// `ensure_allocator_state_table_and_trim` at `redb-4.1.0/src/db.rs:1048`, whose
/// commit is `WriteTransaction::durable_commit` at
/// `redb-4.1.0/src/transactions.rs:1629`). The registry database's byte length
/// and digest therefore move on every route run, before and independently of any
/// refusal, and are not a domain measurement.
///
/// What the issue actually cares about is asserted instead: the owner-read domain
/// projection, plus byte-for-byte equality of the read-only transaction-store
/// database, because every read of it goes through `ReadOnlyDatabase::open` whose
/// backend cannot write at all
/// (`redb-4.1.0/src/tree_store/page_store/backends.rs:34`).
///
/// The failure message carries the full raw record on both sides, including the
/// exact lengths and digests, so a difference is reported as a measurement and not
/// as a verdict.
#[cfg(windows)]
fn assert_durable_state_unchanged(
    routes: &str,
    before: &[(String, String)],
    after: &[(String, String)],
    writable_databases: &[String],
) -> Vec<String> {
    let before_paths = before
        .iter()
        .map(|(path, _)| path.as_str())
        .collect::<Vec<_>>();
    let after_paths = after
        .iter()
        .map(|(path, _)| path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        before_paths,
        after_paths,
        "{routes} changed the SET of durable members below the fixture; nothing may be created, \
         deleted or renamed.\nBEFORE:\n{}\nAFTER:\n{}",
        render_durable_state(before),
        render_durable_state(after)
    );
    let mut moved_databases = Vec::new();
    for ((path, before_observation), (_, after_observation)) in before.iter().zip(after.iter()) {
        if writable_databases.contains(path) {
            if before_observation != after_observation {
                moved_databases.push(path.clone());
            }
            continue;
        }
        assert_eq!(
            before_observation,
            after_observation,
            "{routes} changed the bytes of durable member {path}.\nBEFORE:\n{}\nAFTER:\n{}",
            render_durable_state(before),
            render_durable_state(after)
        );
    }
    moved_databases
}

/// The record key the durable transaction-store database must appear under.
#[cfg(windows)]
fn store_member_key(fixture: &RemovalOwnerFixture) -> String {
    format!(
        "fixture-root/{}",
        fixture
            .store
            .file_name()
            .expect("transaction-store file name")
            .to_string_lossy()
    )
}

/// Reports the one redb database the owner itself opens for writing, and fails
/// closed unless the record really carries the durable state under proof.
///
/// An empty or partial record would make the comparison vacuous, so the two
/// named durable inputs the routes read — the `redb` transaction-store database
/// and the explicit `Remove` authorization — and the owner's one registry
/// database below the retained Host root must each appear as a hashed file
/// member. The registry file is located by shape, not by a hand-written name, so
/// this cannot drift from the owner's private file-name constant, and its key is
/// returned so the byte comparison can be scoped to exactly that one member
/// instead of to a file-name pattern.
///
/// It also fails closed if any OTHER `.redb` database appears in the record. The
/// exclusion below must never become a shape-based hole: every database member is
/// either the one writable database returned here or byte-compared like any other
/// member.
#[cfg(windows)]
fn writable_database_members(
    fixture: &RemovalOwnerFixture,
    members: &[(String, String)],
) -> Vec<String> {
    let hashed = |name: String| {
        members
            .iter()
            .any(|(path, observation)| path == &name && observation.starts_with("file "))
    };
    let store_member = store_member_key(fixture);
    assert!(
        hashed(store_member.clone()),
        "the record must carry the durable transaction-store database as a hashed file member: \
         {members:?}"
    );
    assert!(
        hashed(format!(
            "fixture-root/{}",
            fixture
                .request
                .file_name()
                .expect("authorization file name")
                .to_string_lossy()
        )),
        "the record must carry the explicit Remove authorization the routes decode as a hashed \
         file member: {members:?}"
    );
    assert!(
        members.iter().any(|(path, observation)| {
            path == "installation-root/host" && observation == "directory"
        }),
        "the record must carry the retained Host state root itself: {members:?}"
    );
    let registry_members = members
        .iter()
        .filter(|(path, observation)| {
            path.starts_with("installation-root/host/")
                && is_redb_database_member(path)
                && observation.starts_with("file ")
        })
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        registry_members.len(),
        1,
        "the record must carry the installation owner's one registry database below the retained \
         Host root as a hashed file member: {registry_members:?}"
    );
    let mut every_database = members
        .iter()
        .filter(|(path, _)| is_redb_database_member(path))
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    let mut expected_databases = registry_members.clone();
    expected_databases.push(store_member);
    every_database.sort();
    expected_databases.sort();
    assert_eq!(
        every_database, expected_databases,
        "the record must contain exactly two redb databases, the transaction store and the \
         owner's registry, so the writable-database exclusion can never become a shape-based \
         hole; database members in the record: {every_database:?}"
    );
    registry_members
}

/// The owner-read domain projection of the same fixture.
///
/// This is what the issue cares about if a database file's own bytes ever move
/// for open/close bookkeeping reasons: the registry revision, the registry's
/// accepted generation set with each entry's active and last-known-good flags,
/// the active and last-known-good generation selectors, and the install
/// transaction row the store carries. Every value comes from the owner's own
/// public readers — `RedbInstallationRegistry::load` and
/// `InstallationTransactionStore::load` — never from raw file bytes.
#[cfg(windows)]
fn removal_domain_projection(fixture: &RemovalOwnerFixture) -> String {
    let lease = ProtectedRootLease::open_existing(&fixture.host_state_root)
        .expect("retain the fixture Host state root to read the registry domain");
    let registry = RedbInstallationRegistry::open_existing_at(lease)
        .expect("reopen the retained installation registry")
        .expect("the retained installation registry must still exist");
    let projection = registry
        .load()
        .expect("reload the retained installation registry");
    let mut lines = vec![
        format!("registry.revision={}", projection.revision()),
        format!(
            "registry.generations={:?}",
            projection
                .generations()
                .iter()
                .map(|entry| (
                    entry.manifest.generation.as_str(),
                    entry.active,
                    entry.last_known_good
                ))
                .collect::<Vec<_>>()
        ),
        format!(
            "registry.active_generation={:?}",
            projection.active_generation().map(PlatformHandle::as_str)
        ),
        format!(
            "registry.last_known_good_generation={:?}",
            projection
                .last_known_good_generation()
                .map(PlatformHandle::as_str)
        ),
    ];
    drop(registry);
    let store = RedbInstallationTransactionStore::open_existing_exact_path(&fixture.store)
        .expect("reopen the durable transaction store");
    lines.push(match store.load(&fixture.install_transaction_id) {
        Ok(Some(transaction)) => format!(
            "install.stage={}",
            serde_json::to_string(&transaction.stage()).expect("installation stage JSON")
        ),
        Ok(None) => "install.row=absent".to_owned(),
        Err(error) => panic!("the owner's own store refused to read its install row: {error}"),
    });
    lines.join("\n")
}

/// The exact member set [`removal_domain_projection`] publishes on this fixture.
///
/// Pinning the SET, not only the values, is what keeps the
/// `before_domain == after_domain` comparison from being vacuous. That
/// comparison is an absence claim about every domain member at once, so it
/// passes for free if the projection returns an empty or partial record — two
/// empty strings are equal. Asserting the declared member set first means such a
/// record fails here, and the equality check below then compares five named,
/// non-empty lines read through the owner's own public readers AFTER the routes
/// ran. Two of those lines are live durable reads rather than constants:
/// `registry.revision=1` comes from `RedbInstallationRegistry::load` and
/// `install.row=absent` from `InstallationTransactionStore::load` on this
/// fixture's own install identity, so a route that advanced either is caught by
/// the pinned value itself and not only by the equality.
///
/// The empty members are the fixture's DOCUMENTED ceiling, stated here so the
/// pinned set is not read as more than it is (see [`RemovalOwnerFixture`]): this
/// package cannot publish an accepted generation or an `ActiveVerified` install
/// transaction, so there is no accepted generation set, no active or
/// last-known-good selector and no install row to advance. The values below are
/// what the owner actually reports for such a fixture, and `removal_owner_fixture`
/// proves the first two of them at construction, before any route runs.
#[cfg(windows)]
const REMOVAL_DOMAIN_PROJECTION_MEMBERS: [&str; 5] = [
    "registry.revision=1",
    "registry.generations=[]",
    "registry.active_generation=None",
    "registry.last_known_good_generation=None",
    "install.row=absent",
];

/// The exact byte measurement of the durable transaction-store database.
#[cfg(windows)]
fn removal_store_measurement(store: &Path) -> String {
    let bytes = fs::read(store).expect("read the durable transaction-store database");
    format!("file {} {}", bytes.len(), sha256_hex(&bytes))
}

/// The removal operation identities the installation owner itself reports present.
///
/// `RedbInstallationTransactionStore::load_canary_removal_operation`
/// (`redb_state.rs::RedbInstallationTransactionStore::load_canary_removal_operation`) and its generation-scoped sibling
/// (`redb_state.rs::RedbInstallationTransactionStore::load_canary_removal_for_generation`) are `pub(crate)`, and this test package is not the
/// owning crate, so there is no public table enumeration and no public
/// reader that lists rows. The only public reader of a removal operation is the
/// owner's own `WindowsInstallationCoordinator::canary_removal_status`
/// (`lib.rs::WindowsInstallationCoordinator::canary_removal_status`), which loads the durable row and projects it; that is what
/// is used here rather than reaching into private state or the raw database.
///
/// An absent row is the owner's typed `TransactionNotFound`. Any other answer
/// fails closed instead of being read as absence, so a corrupt or unreadable
/// store cannot make an empty set look like proof.
#[cfg(windows)]
fn known_removal_operation_identities(store_path: &Path, probes: &[PlatformHandle]) -> Vec<String> {
    let store = RedbInstallationTransactionStore::open_existing_exact_path(store_path)
        .expect("reopen the durable transaction store through the owner's production constructor");
    let coordinator = WindowsInstallationCoordinator::new(store);
    let mut present = Vec::new();
    for probe in probes {
        match coordinator.canary_removal_status(probe) {
            Ok(status) => {
                assert_eq!(
                    &status.removal_transaction_id, probe,
                    "the owner answered about a different removal identity than the one asked for"
                );
                present.push(status.removal_transaction_id.as_str().to_owned());
            }
            Err(InstallationError::TransactionNotFound { .. }) => {}
            Err(error) => panic!(
                "the owner's own removal read must answer a typed verdict about {}: {error}",
                probe.as_str()
            ),
        }
    }
    present
}

/// Asserts one route answered with the owner's own bounded typed refusal.
///
/// `detail_member` is an exact string the OWNER composes, never one this
/// package or the composition root could print: for the two target-resolving
/// routes it is the sentence `canary_removal::resolve_approved_generation`
/// formats (`canary_removal.rs::resolve_approved_generation`), and for the
/// read-only status route it is the removal operation identity the owner reports
/// absent. The exit code, the closed `INSTALLATION_REMOVE_CANARY_*` refusal
/// class set and the typed envelope are asserted through the existing harness
/// (`assert_installation_error` and `assert_removal_route_owner_codes_only`), so
/// this is the positive half of the unchanged-state proof: a route that crashed
/// or never reached the owner cannot satisfy it.
///
/// `operations` is the route's own phase set, so this also rejects a route that
/// answered with a phase tag it never composes.
///
/// Returns the owner's `detail` so a caller can pin one more owner-composed
/// member of the same sentence.
#[cfg(windows)]
fn assert_owner_typed_refusal(
    route: &str,
    operations: &[&str],
    result: &std::process::Output,
    expected_code: &str,
    detail_member: &str,
) -> String {
    let transcript = format!(
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        result.status.code(),
        Some(2),
        "{route} must answer on the bounded typed refusal exit, never on success and never on an \
         unknown-outcome exit that leaves a durable effect in doubt: {transcript}"
    );
    let output: Value = serde_json::from_slice(&result.stdout).unwrap_or_else(|error| {
        panic!(
            "{route} must answer with the typed installation envelope, not usage text or prose: \
             {error}; {transcript}"
        )
    });
    assert_installation_error(&output, expected_code);
    let detail = output["detail"]
        .as_str()
        .expect("removal refusal detail")
        .to_owned();
    assert!(
        detail.contains(detail_member),
        "{route} did not answer with the owner's own verdict naming {detail_member}: {detail}; \
         {transcript}"
    );
    assert_removal_route_owner_codes_only(route, operations, &transcript);
    detail
}

/// `plan-canary-removal`, `remove-canary` and `canary-removal-status` create no
/// durable state on this fixture beyond the owner's own redb bookkeeping inside
/// its one registry file, and every refusal they answer with is the
/// installation owner's own.
///
/// The one exception is stated here, at the top, because it is the reason this
/// test is named the way it is and because leaving it to a reader who opens this
/// comment is the wrong place to leave it. NONE of these routes is a
/// byte-preserving read of the owner's registry file: the owner's
/// `plan_canary_removal` seam admits only a redb WRITER handle, so
/// `run_plan_canary_removal` obtains the registry through
/// `open_retained_registry_writer` and redb commits a quick-repair
/// `allocator_state` transaction when that handle drops. So the plan route, and
/// the public name that resolves a plan before refusing, DO write redb's own
/// bookkeeping into that one file on every run — including on the runs that
/// refuse. `canary-removal-status` is the opposite case and really is
/// byte-preserving: it never opens the registry at all. The property proved
/// here is therefore the bounded one the name states: no durable removal
/// transaction, no admitted accepted generation, no advanced registry revision,
/// no install transaction row, no created, deleted or renamed durable member
/// below the fixture or the retained Host root, and no changed byte in any of
/// those members other than the owner's registry file itself — whose movement is
/// measured, cited, named one member at a time by [`writable_database_members`],
/// reported in full, and additionally pinned to be exactly one member below the
/// retained Host root.
///
/// This is the proof for the two #1138 acceptance clauses that had none, at the
/// strength this fixture can actually carry. #1138 words the first as "Plan
/// creates no files, secrets, services, reservations or transaction rows"; the
/// durable-state half of that clause is what is proved here and, for transaction
/// rows, again in `remove_canary_creates_no_transaction_row`. What is NOT claimed
/// is the stronger form the clause invites in the abstract — that planning is a
/// read of the owner's registry with no write at all. The code does not have that
/// property and no test in this package asserts it. "No CLI-local deletion" is a
/// negative claim about the same three routes, and an unchanged-state assertion
/// only means something beside the positive proof that the owner actually ran: a
/// route that died before reaching the owner would pass an unchanged-state check
/// on its own. So each route's run is asserted twice — the raw before/after
/// record below, and the owner's own typed refusal above.
///
/// The record covers, with nothing skipped, every member below the retained
/// per-installation Host root (each as a relative path, a byte length and a
/// SHA-256 content digest), every member of the caller-owned fixture directory
/// that holds the `redb` transaction-store database and the explicit `Remove`
/// authorization, and the owner's registry database below the Host root. The
/// owner-read domain projection — registry revision, accepted generation set,
/// active and last-known-good selectors, install transaction row — is asserted
/// independently of the file bytes, so the acceptance signal does not depend on
/// a database file's own layout.
///
/// The two byte-level halves are asserted without softening them: the member set
/// must be identical, and every member's length and digest must be unchanged
/// except for the owner's own registry database below the Host root, which redb
/// moves for reasons unrelated to a domain mutation. That exception is measured,
/// cited and named one member at a time by
/// [`writable_database_members`], not assumed from a file-name pattern. Two things
/// keep it from being a silent weakening. The raw before/after record of every
/// member, databases included, is printed and is repeated in full inside any
/// failure, so the exact byte difference is always reported as a measurement. And
/// the two assertions that actually carry the issue's meaning do not depend on the
/// excluded bytes at all: the owner-read domain projection must be identical, and
/// the transaction-store database is byte-compared like any other member because
/// every one of these routes opens it through `ReadOnlyDatabase::open`, whose
/// backend cannot write.
///
/// Every route carries its OWN phase set, one line per route beside the route's
/// own name, never the union of the phases the entry can compose and never a
/// neighbour's set. That is not tidiness: the status route's expectation below is
/// `INSTALLATION_REMOVE_CANARY_STATUS_NOT_FOUND`, which the entry composes by
/// tagging every status refusal `STATUS_OPERATION`
/// (`canary_removal_entry.rs::run_canary_removal_status`, with that tag declared
/// at `canary_removal_entry.rs::STATUS_OPERATION`), mapping `TransactionNotFound`
/// to the `NOT_FOUND` class and formatting it into the code in
/// `canary_removal_entry.rs::removal_error_code`. A `PLAN`/`APPLY` set rejects
/// that code by construction, so one shared set for all three routes makes this
/// proof red for a reason that has nothing to do with durable state. The route
/// name sits beside its own set in every arm, so the closed-code check names the
/// one route that published an out-of-phase code.
///
/// Proof ceiling, stated rather than hidden. The target this fixture publishes is
/// never an accepted generation, so both target-resolving routes refuse inside
/// the owner's own registry target resolution and the apply phase of
/// `remove-canary` is never entered (see
/// `remove_canary_creates_no_transaction_row`). This proves the refusal path
/// itself creates no durable state beyond the owner's registry redb bookkeeping,
/// which is what these routes do on this fixture. A completed removal needs an
/// accepted generation and an `ActiveVerified`
/// install transaction, neither of which this package can publish (see
/// [`RemovalOwnerFixture`]), and stays the #11 installed pulse.
///
/// What makes this red, in one line: any of the three routes advancing a registry
/// revision, admitting an accepted generation or active/last-known-good selector,
/// writing an install transaction row, creating or changing ANY durable member
/// below the fixture or the retained Host root other than the owner's own redb
/// bookkeeping in its registry file, or publishing a refusal code outside the one
/// phase set that route composes.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    clippy::print_stdout,
    reason = "the unchanged-state proof and the owner-ran proof are asserted per route, and the \
              raw measurement is reported"
)]
#[test]
fn plan_canary_removal_and_remove_canary_create_no_durable_state_but_the_owners_registry_redb_bookkeeping()
 {
    // One row per route: its name, the argv the fixture composes, the operation
    // tags its refusals must carry, the code its refusal must compose, and the
    // detail every such refusal must name.
    type RouteCase<'a> = (&'a str, Vec<String>, &'a [&'a str], &'a str, &'a str);
    let fixture = removal_owner_fixture("no-observable-state");
    let removal_transaction_id =
        canary_removal_operation_id(&fixture.install_transaction_id, &fixture.generation)
            .expect("derive the removal operation identity for this target");
    let routes: [RouteCase<'_>; 3] = [
        (
            "plan-canary-removal",
            fixture.plan_canary_removal_args(),
            &REMOVAL_PLAN_ROUTE_OPERATIONS[..],
            "INSTALLATION_REMOVE_CANARY_PLAN_REFUSED",
            REMOVE_CANARY_OWNER_REGISTRY_REFUSAL,
        ),
        (
            "remove-canary",
            fixture.remove_canary_args(),
            &REMOVE_CANARY_ROUTE_OPERATIONS[..],
            "INSTALLATION_REMOVE_CANARY_PLAN_REFUSED",
            REMOVE_CANARY_OWNER_REGISTRY_REFUSAL,
        ),
        (
            "canary-removal-status",
            fixture.canary_removal_status_args(&removal_transaction_id),
            &REMOVAL_STATUS_ROUTE_OPERATIONS[..],
            "INSTALLATION_REMOVE_CANARY_STATUS_NOT_FOUND",
            removal_transaction_id.as_str(),
        ),
    ];

    // BEFORE. The domain projection is read first so the byte records on both
    // sides sit symmetrically: each is taken after the same number of this
    // test's own owner-shaped opens, and only the routes' own opens sit between
    // them.
    let before_domain = removal_domain_projection(&fixture);
    let before_members = durable_state_members(&fixture);
    let writable_databases = writable_database_members(&fixture, &before_members);

    for (route, args, operations, code, detail_member) in &routes {
        let result = run_removal_command(args, &fixture.temp_root);
        // The positive half of this route's durable-state claim: the route
        // answered on the bounded typed refusal exit with a parsed installation
        // envelope whose exact code, `ERROR` status, false `completed` member,
        // bounded scope and string detail are all pinned here. A route that died,
        // printed prose or exited zero fails before any absence is considered, so
        // the absence claim can never be satisfied by a route that never ran.
        let detail = assert_owner_typed_refusal(route, operations, &result, code, detail_member);
        // All three refusals name the exact generation this fixture asked
        // about: the two target-resolving ones directly, and the status route
        // inside the removal operation identity it reports absent. That second
        // half is what makes the status route's absence discriminating — the same
        // `detail` member that carries the absent removal identity also carries
        // this fixture's generation verbatim, because
        // `canary_removal::canary_removal_operation_id` composes that identity
        // from the install identity and the generation
        // (`canary_removal.rs::canary_removal_operation_id`). An empty or generic "not found" answer
        // cannot satisfy it.
        assert!(
            detail.contains(fixture.generation.as_str()),
            "{route} must name the exact generation the route was asked about: {detail}"
        );
    }

    let after_members = durable_state_members(&fixture);
    report_durable_state_measurement(
        "after the three refused canary-removal routes",
        &before_members,
        &after_members,
    );
    let moved_databases = assert_durable_state_unchanged(
        "the three refused canary-removal routes",
        &before_members,
        &after_members,
        &writable_databases,
    );

    // The transaction-store database must NOT be in the writable exclusion, so
    // its byte length and digest were compared above like any other member. That
    // comparison is what makes "no transaction row of any kind" a fact about the
    // store rather than an inference: nothing can be inserted into any table of a
    // byte-identical database. This guard fails the moment the exclusion widens.
    assert!(
        !writable_databases.contains(&store_member_key(&fixture)),
        "the transaction-store database was excluded from the byte comparison even though every \
         one of these routes opens it read-only; writable databases: {writable_databases:?}"
    );
    // The positive that makes the exclusion above a bounded, named exception rather
    // than a blanket skip: it is exactly ONE member and it names a database below
    // the retained Host root, which is where the owner's own registry lives and the
    // one redb file `open_retained_registry_writer` opens as a writer. Everything
    // else in the record — the read-only transaction-store database, the explicit
    // `Remove` authorization, the Host root itself — was byte-compared above, and
    // `writable_database_members` already proved the record really carries all
    // three as hashed file members and contains exactly two `redb` databases.
    assert_eq!(
        writable_databases.len(),
        1,
        "the writable exclusion must be exactly the owner's one registry database: \
         {writable_databases:?}"
    );
    assert!(
        writable_databases
            .iter()
            .all(|member| member.starts_with("installation-root/host/")),
        "the writable exclusion must name a database below the retained Host root and nothing else: \
         {writable_databases:?}"
    );
    println!("redb databases whose own bytes moved across the refused routes: {moved_databases:?}");

    // The domain projection carries the issue's meaning and is asserted on its
    // own: no accepted generation, no advanced revision, no install row.
    let after_domain = removal_domain_projection(&fixture);
    // The positive that makes the equality below discriminating. `before_domain`
    // and `after_domain` are both absence claims over the whole domain at once,
    // so an empty, truncated or error record would satisfy the comparison for
    // free. Asserting the declared member set on the AFTER record — read through
    // the owner's own readers, after the three routes ran — makes the comparison
    // run over five named non-empty lines instead, and makes `registry.revision=1`
    // and `install.row=absent` pinned observations rather than assumptions.
    assert_eq!(
        after_domain.lines().count(),
        REMOVAL_DOMAIN_PROJECTION_MEMBERS.len(),
        "the owner-read domain projection must publish every declared member, so the before/after \
         comparison is over real values:\n{after_domain}"
    );
    for member in REMOVAL_DOMAIN_PROJECTION_MEMBERS {
        assert!(
            after_domain.lines().any(|line| line == member),
            "the owner-read domain projection dropped or changed `{member}`:\n{after_domain}"
        );
    }
    assert_eq!(
        before_domain, after_domain,
        "the refused canary-removal routes advanced the owner's durable domain"
    );
    fixture.cleanup();
}

/// Planning and the refused apply leave no canary-removal operation row behind
/// and no transaction row of any kind.
///
/// This is the transaction-row half of #1138's "Plan creates no files, secrets,
/// services, reservations or transaction rows", stated as a set comparison, and
/// it is deliberately only that half: the file half of the clause (no durable
/// member created, deleted or renamed below the fixture or the retained Host
/// root) is carried by the test above, whose registry-byte exception is stated
/// on it, and the secret, service and reservation halves are not claimed by this
/// test at all because this fixture has no such surface to observe. The
/// expectation here is INDEPENDENT
/// and empty: the set of removal operation identities the installation owner
/// itself reports present, observed through its own public read API BEFORE the
/// routes run. It is not compared against a copy of a caller list, and the probe
/// identity is the owner's own derivation (`canary_removal_operation_id`, which
/// `plan_canary_removal` itself calls) over the fixture's own two durable
/// inputs, so it is the identity `remove-canary` would have admitted had its
/// plan resolved. The existing status test in this file,
/// `canary_removal_status_reports_the_blocking_row_and_next_action`, proves that
/// same identity is the one `apply-canary-removal` really admits for this
/// fixture.
///
/// "Of any kind" is carried by two further observations rather than by the probe
/// alone: the durable store database's own byte length and content digest are
/// unchanged, which no insert into any table of that database can survive, and
/// the owner's `InstallationTransactionStore::load` still reports no install
/// transaction row for this fixture's install identity.
///
/// Which route is the "refused apply", stated rather than glossed. On this
/// fixture `remove-canary` refuses inside `plan_canary_removal`, so its apply
/// phase is never entered and no admission is even attempted. The separate
/// `apply-canary-removal` command is deliberately NOT invoked here and must not
/// be: with a frozen plan document it ADMITS a durable removal operation on
/// purpose (`admit_or_resume` calls `create_canary_removal_operation`), which is
/// the issue's admitted durable intent rather than a planning mutation, and
/// `canary_removal_status_reports_the_blocking_row_and_next_action` depends on
/// that row existing. This test therefore asserts the row is absent before and
/// absent after the two routes that must not create one, and it asserts absence
/// against the empty set observed beforehand — never absence alone.
///
/// Each route carries its OWN phase set, one line per route beside the route's
/// own name. `plan-canary-removal` decodes and resolves and never drives an
/// effect, so only its own `PLAN` phase is admissible; `remove-canary` resolves
/// AND drives one plan in one command, so both of its phases are. Both are
/// tagged in `bins/eliot/src/canary_removal_entry.rs`:
/// `canary_removal_entry.rs::run_plan_canary_removal` composes only
/// `canary_removal_entry.rs::PLAN_OPERATION`, and
/// `canary_removal_entry.rs::run_remove_canary` composes
/// `canary_removal_entry.rs::PLAN_OPERATION` then
/// `canary_removal_entry.rs::APPLY_OPERATION`, and
/// `plan_canary_removal_and_remove_canary_create_no_durable_state_but_the_owners_registry_redb_bookkeeping`
/// above needs the same distinction for the status route, so the closed-code check is driven
/// from the route rather than from one shared set.
///
/// What makes this red, in one line: either route creating a durable removal
/// operation row for this identity, or moving a single byte of the transaction
/// store the owner reads through `ReadOnlyDatabase::open`, whose backend has no
/// write path at all.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the empty-set comparison and the byte-level store proof are both asserted"
)]
#[test]
fn remove_canary_creates_no_transaction_row() {
    let fixture = removal_owner_fixture("no-transaction-row");
    let removal_transaction_id =
        canary_removal_operation_id(&fixture.install_transaction_id, &fixture.generation)
            .expect("derive the removal operation identity for this target");
    let probe = std::slice::from_ref(&removal_transaction_id);

    // The positive that makes the empty-set expectation below discriminating: the
    // probe is not an empty list. The set the owner reports is compared against a
    // list that holds exactly one identity, this fixture's own removal operation
    // identity as the owner itself derives it from this fixture's two durable
    // inputs, so "the owner reports none of the probed identities present" is a
    // statement about a named identity rather than about nothing.
    assert_eq!(
        probe.len(),
        1,
        "the probe must name the one removal identity this fixture could have admitted"
    );
    assert_eq!(
        probe[0], removal_transaction_id,
        "the probed identity must be the owner's own derivation for this fixture"
    );

    // The independent BEFORE expectation: the empty set the owner reports.
    let before = known_removal_operation_identities(&fixture.store, probe);
    assert!(
        before.is_empty(),
        "the fixture's durable store already carried a removal operation: {before:?}"
    );
    let store_before = removal_store_measurement(&fixture.store);

    for (route, args, operations) in [
        (
            "plan-canary-removal",
            fixture.plan_canary_removal_args(),
            &REMOVAL_PLAN_ROUTE_OPERATIONS[..],
        ),
        (
            "remove-canary",
            fixture.remove_canary_args(),
            &REMOVE_CANARY_ROUTE_OPERATIONS[..],
        ),
    ] {
        let result = run_removal_command(&args, &fixture.temp_root);
        assert_owner_typed_refusal(
            route,
            operations,
            &result,
            "INSTALLATION_REMOVE_CANARY_PLAN_REFUSED",
            REMOVE_CANARY_OWNER_REGISTRY_REFUSAL,
        );
    }

    // The AFTER set must equal the independently observed empty BEFORE set.
    let after = known_removal_operation_identities(&fixture.store, probe);
    assert_eq!(
        before, after,
        "a refused canary-removal route changed the set of durable removal operation identities"
    );
    assert!(
        after.is_empty(),
        "a refused canary-removal route left a removal operation row behind: {after:?}"
    );

    // No transaction row of any kind: the store database is byte-identical, and
    // the install transaction table still carries no row for this install.
    let store_after = removal_store_measurement(&fixture.store);
    // The positive that makes the byte comparison below a comparison at all: both
    // measurements are real `file <byte length> <sha256>` records, so the equality
    // check runs over two named kinds with two byte lengths and two content
    // digests rather than over two empty or partial strings that would be equal
    // for free. `removal_store_measurement` panics if the database cannot be read
    // at all, so a missing store fails instead of measuring an empty string.
    for measurement in [&store_before, &store_after] {
        let mut fields = measurement.split_ascii_whitespace();
        assert!(
            fields.next() == Some("file")
                && fields.next().is_some_and(|length| {
                    !length.is_empty() && length.bytes().all(|byte| byte.is_ascii_digit())
                })
                && fields.next().is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                && fields.next().is_none(),
            "the durable store measurement must be a real `file <byte length> <sha256>` record and \
             not an empty or partial string: {measurement}"
        );
    }
    assert_eq!(
        store_before, store_after,
        "a refused canary-removal route changed the bytes of the durable transaction-store database"
    );
    // The positive that makes the install-row absence below discriminating, and
    // the honest limit of what it can be on its own. This fixture publishes no
    // install transaction row at all (see [`RemovalOwnerFixture`]), so
    // `load` answering `None` for this identity is also what an uninformative
    // reader would return. The measurement above is the carrier that rules the
    // alternative out: an insert of ANY row into ANY table of a byte-identical
    // `redb` database cannot survive, so a route that wrote one fails on the
    // bytes rather than depending on this read. The read is kept because it is the
    // owner's own typed absence rather than an inference, and it is kept failing
    // closed: a corrupt or unreadable store is an error here, never an absence.
    let store = RedbInstallationTransactionStore::open_existing_exact_path(&fixture.store)
        .expect("reopen the durable transaction store");
    assert!(
        store
            .load(&fixture.install_transaction_id)
            .expect("read the install transaction row through the owner's store")
            .is_none(),
        "a refused canary-removal route wrote a transaction row for the fixture's install identity"
    );
    fixture.cleanup();
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
