#![forbid(unsafe_code)]
// Machine-readable and human CLI output is the public contract of this binary.
#![allow(clippy::print_stdout)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use eliot_bootstrap::capture::{capture_snapshot, write_snapshot_artifact};
use eliot_cli::{CommandCatalogue, CommandPort, CommandPortError, CommandRequest};
use eliot_installation::{
    ActivationCommitFence, ApprovedGenerationRegistry, CandidateManifest,
    GenerationPackagePlanInput, GenerationPackagePlanner, InstallationEpoch, InstallationError,
    InstallationProfile, InstallationStage, InstallationStepOutcome, InstallationTransaction,
    InstallationTransactionStore, PlatformHandle, RedbInstallationRegistry,
    RedbInstallationTransactionStore, WindowsInstallationCoordinator,
    parse_installation_transaction_id, require_published_source_bundle_journal,
    validate_installation_transaction_json,
};
use eliot_live_canary::{
    CANARY_COMPLETION_SCHEMA, CanaryConfig, CanaryError, ProductionCanary,
    ProductionCanaryCompletionBinding, Pulse, publish_production_evidence,
};
use eliot_platform_windows::{
    FileIdentity, InstallerRootError, InstallerRootObjectSnapshot,
    InstallerRootPrimitiveObservation, InstallerRootPrimitiveSpec, InstallerRootProfile,
    PackageStagingError, PackageStagingStage, ProtectedRootLease, ProtectedRuntimePathLease,
    TrustedSourceBundle, TrustedSourceFileLease, WindowsInstallerRootPrimitive,
    is_eliot_governor_running, is_process_elevated, observe_current_user_config,
    windows_path_identity_digest,
};
use eliot_runtime_contracts::{
    RUNTIME_LIVE_STORE_BIND, RUNTIME_LIVE_STORE_ENDPOINT, RUNTIME_LIVE_STORE_NAMESPACE,
    RuntimeLiveStoreIdentity,
};
use eliot_store_surreal::{StoreLaunchConfig, launch_config_digest};
use eliot_types::GovernorConfig;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    time::Duration,
};
use tracing_subscriber::EnvFilter;

mod source_bundle_materializer;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const INVALID_REQUEST_EXIT: i32 = 2;
const FRONT_DOOR_CLOSED_EXIT: i32 = 69;
const UNKNOWN_OUTCOME_EXIT: i32 = 75;
const INSTALLATION_INPUT_LIMIT: u64 = 16 * 1024 * 1024;
const INSTALLATION_CONTRACT_VERSION: &str = "3.0.0";
const INSTALLATION_SCOPE: &str = "bounded_all_effects_or_exact_rollback";

#[derive(Debug, Parser)]
#[command(name = "eliot", about = "ELIOT Memory OS command-line client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Command {
    Catalogue {
        #[command(subcommand)]
        command: CatalogueCommand,
    },
    /// Read one typed command request from stdin and forward it to Kernel.
    Dispatch,
    /// Compile an immutable current-system evidence artifact.
    System {
        #[command(subcommand)]
        command: SystemCommand,
    },
    /// Inspect or validate the governed installation transaction surfaces.
    Installation {
        #[command(subcommand)]
        command: InstallationCommand,
    },
    /// Read the manifest-bound Runtime Live status contour.
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    Version,
    /// Start or reuse the authenticated User Broker and launch Operator.
    Ui,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum InstallationCommand {
    /// Retired compatibility command. It remains parseable but always fails
    /// closed before the planner, output, or durable store; use
    /// `installation materialize-source-bundle` for production generation.
    #[command(alias = "plan-generation", alias = "generation-plan")]
    Generate {
        /// Absolute retained source bundle containing the exact nine-file Phase-A inventory.
        #[arg(long, value_parser = absolute_path)]
        source_root: PathBuf,
        /// Explicit installation profile (`system_service`, `user_mode`, or `portable_dev`).
        #[arg(long, value_parser = parse_installation_profile)]
        profile: InstallationProfile,
        /// Absolute OS-validated profile anchor root.
        #[arg(long, value_parser = absolute_path)]
        profile_anchor_root: PathBuf,
        /// Lowercase SHA-256 installation key; required for profiled installations.
        #[arg(long)]
        installation_key: Option<String>,
        /// Stable installation identity.
        #[arg(long)]
        installation: String,
        /// Stable lineage identity.
        #[arg(long)]
        lineage_id: String,
        /// Non-zero sequence within the lineage.
        #[arg(long)]
        sequence: u64,
        /// Canonical relative package generation identity.
        #[arg(long)]
        generation: String,
        /// Absolute immutable staging root.
        #[arg(long, value_parser = absolute_path)]
        staging_root: PathBuf,
        /// Stable transaction identity.
        #[arg(long)]
        transaction_id: String,
        /// Explicit non-zero Store-space policy value.
        #[arg(long)]
        minimum_store_available_bytes: u64,
        /// Explicit recovery command/reference retained by the transaction.
        #[arg(long)]
        recovery_command: String,
        /// Absolute new output JSON path. Its parent must already exist.
        #[arg(long, value_parser = absolute_path)]
        output: PathBuf,
        /// Optional exact transaction store to create from this planner output.
        #[arg(long, value_parser = absolute_path)]
        store: Option<PathBuf>,
    },
    /// Validate an immutable v8 installation plan JSON without applying it (untrusted import/validation only).
    Plan {
        /// Absolute path to an existing serialized `InstallationTransaction`.
        #[arg(long, value_parser = absolute_path)]
        input: PathBuf,
    },
    /// Retired raw transaction-import compatibility command.
    ///
    /// Production transaction creation is owned by
    /// `installation materialize-source-bundle --store`; this command always
    /// rejects caller-authored JSON.
    Create {
        /// Absolute path to an existing serialized `InstallationTransaction`.
        #[arg(long, value_parser = absolute_path)]
        input: PathBuf,
        /// Absolute path to a new transaction redb file.
        #[arg(long, value_parser = absolute_path)]
        store: PathBuf,
    },
    /// Drive all durable effects through the bounded production coordinator loop.
    #[command(alias = "resume")]
    Apply {
        /// Absolute path to an existing transaction redb file.
        #[arg(long, value_parser = absolute_path)]
        store: PathBuf,
        /// Stable transaction identity retained in the durable store.
        #[arg(long)]
        transaction_id: String,
    },
    /// Reconcile and roll back a transaction already marked `ROLLBACK_REQUIRED`.
    Recover {
        /// Absolute path to an existing transaction redb file.
        #[arg(long, value_parser = absolute_path)]
        store: PathBuf,
        /// Stable transaction identity retained in the durable store.
        #[arg(long)]
        transaction_id: String,
    },
    /// Read the existing approved-generation registry without changing it.
    #[command(alias = "open")]
    Status {
        /// Absolute path to the retained per-installation Host state root.
        #[arg(long, value_parser = absolute_path)]
        host_state_root: PathBuf,
        /// Bounded deadline in milliseconds from now (default 2000).
        #[arg(long, default_value = "2000")]
        deadline_ms: u64,
    },
    /// Report the unsupported canary-removal seam without mutating the machine.
    RemoveCanary {
        /// Optional transaction store, accepted only to make the refusal scope explicit.
        #[arg(long, value_parser = absolute_path)]
        store: Option<PathBuf>,
        /// Optional transaction identity, accepted only to make the refusal scope explicit.
        #[arg(long)]
        transaction_id: Option<String>,
    },
    /// Materialize an exact nine-role Phase-A source bundle and feed it through
    /// the publication-bound generation planner. `--store` is required because
    /// the durable transaction store is the sole authority for a generated plan.
    MaterializeSourceBundle {
        #[arg(long, value_parser = absolute_path)]
        eliot_host: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        eliot_watchdog: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        eliot_kernel: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        eliot_store_surreal: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        surreal: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        eliotd: PathBuf,
        #[arg(long, value_parser = absolute_path)]
        output_bundle: PathBuf,
        /// Absolute create-new diagnostic JSON path. This file is never an
        /// apply/recovery authority and cannot be imported through `create`.
        #[arg(long, value_parser = absolute_path)]
        output: PathBuf,
        /// Absolute create-new durable transaction store. Apply and recovery
        /// require this exact path together with `--transaction-id`.
        #[arg(long, value_parser = absolute_path)]
        store: PathBuf,
        #[arg(long)]
        generation: String,
        #[arg(long)]
        installation: String,
        #[arg(long)]
        lineage_id: String,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        transaction_id: String,
        #[arg(long, value_parser = absolute_path)]
        staging_root: PathBuf,
        #[arg(long)]
        minimum_store_available_bytes: u64,
        #[arg(long)]
        recovery_command: String,
        #[arg(long, value_parser = parse_installation_profile)]
        profile: InstallationProfile,
        #[arg(long, value_parser = absolute_path)]
        profile_anchor_root: PathBuf,
        #[arg(long)]
        installation_key: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum RuntimeCommand {
    /// Emit the production Runtime Live status contract as JSON.
    Status {
        /// The machine-readable output contract is mandatory for this command.
        #[arg(long)]
        json: bool,
        /// Absolute path to the retained per-installation Host state root.
        #[arg(long, value_parser = absolute_path)]
        host_state_root: PathBuf,
        /// Bounded deadline in milliseconds from now (default 2000).
        #[arg(long, default_value = "2000")]
        deadline_ms: u64,
    },
    /// Run one bounded Runtime Live Pulse against the exact active
    /// `SystemService` manifest. Evidence is always written below the
    /// manifest-derived canary-evidence root; callers cannot select it.
    Canary {
        /// Absolute path to the retained per-installation Host state root.
        #[arg(long, value_parser = absolute_path)]
        host_state_root: PathBuf,
        /// Pulse number 1 through 5.
        #[arg(long, value_parser = clap::value_parser!(u8).range(1..=5))]
        pulse: u8,
        /// Bounded deadline in milliseconds from now (default 30000).
        #[arg(long, default_value = "30000")]
        deadline_ms: u64,
        /// Required before any Kernel/Store mutation or Host SCM restart.
        #[arg(long)]
        execute_faults: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SystemCommand {
    /// Capture source/build/runtime/store/integration evidence.
    Snapshot {
        /// Absolute repository root. Git evidence is always scoped to this path.
        #[arg(long, value_parser = absolute_path)]
        repo_root: PathBuf,
        /// Absolute destination. Existing artifacts are never overwritten.
        #[arg(long, value_parser = absolute_path)]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum CatalogueCommand {
    Help,
    Schema,
    Validate,
}

fn main() -> Result<()> {
    let exit_code = std::thread::Builder::new()
        .name("eliot-cli-main".to_owned())
        .stack_size(32 * 1024 * 1024)
        .spawn(run)
        .context("spawn the CLI entrypoint")?
        .join()
        .map_err(|_| anyhow::anyhow!("CLI entrypoint panicked"))??;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

fn run() -> Result<i32> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!("eliot {VERSION}");
            Ok(0)
        }
        Command::Catalogue { command } => {
            run_catalogue(&command)?;
            Ok(0)
        }
        Command::System { command } => run_system(command),
        Command::Installation { command } => run_installation(command),
        Command::Runtime { command } => run_runtime(command),
        Command::Dispatch => run_dispatch(),
        Command::Ui => run_ui(),
    }
}

fn run_runtime(command: RuntimeCommand) -> Result<i32> {
    match command {
        RuntimeCommand::Status {
            json,
            host_state_root,
            deadline_ms,
        } => {
            if !json {
                write_installation_error(
                    "RUNTIME_STATUS_JSON_REQUIRED",
                    "runtime status requires --json; no inspection or filesystem mutation was attempted",
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
            run_installation_runtime_status(&host_state_root, deadline_ms)
        }
        RuntimeCommand::Canary {
            host_state_root,
            pulse,
            deadline_ms,
            execute_faults,
        } => Ok(run_manifest_bound_canary(
            &host_state_root,
            pulse,
            deadline_ms,
            execute_faults,
        )),
    }
}

fn run_manifest_bound_canary(
    host_state_root: &Path,
    pulse_number: u8,
    deadline_ms: u64,
    execute_faults: bool,
) -> i32 {
    let pulse = match Pulse::try_from(pulse_number) {
        Ok(pulse) => pulse,
        Err(error) => {
            write_manifest_canary_error(pulse_number, "CANARY_INVALID_PULSE", &error.to_string());
            return INVALID_REQUEST_EXIT;
        }
    };
    if deadline_ms == 0 || deadline_ms > eliot_live_canary::MAX_DEADLINE_MS {
        write_manifest_canary_error(
            pulse_number,
            "CANARY_INVALID_DEADLINE",
            &format!(
                "deadline must be between 1 and {} milliseconds",
                eliot_live_canary::MAX_DEADLINE_MS
            ),
        );
        return INVALID_REQUEST_EXIT;
    }
    #[cfg(windows)]
    {
        match run_manifest_bound_canary_windows(host_state_root, pulse, deadline_ms, execute_faults)
        {
            Ok(code) => code,
            Err(error) => {
                write_manifest_canary_error(
                    pulse_number,
                    "CANARY_PREFLIGHT_OR_EVIDENCE_FAILED",
                    &error.to_string(),
                );
                INVALID_REQUEST_EXIT
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (host_state_root, pulse, deadline_ms, execute_faults);
        write_manifest_canary_error(
            pulse_number,
            "CANARY_UNSUPPORTED_PLATFORM",
            "production manifest-bound canary requires the Windows retained-root and SCM adapter",
        );
        INVALID_REQUEST_EXIT
    }
}

#[cfg(windows)]
struct ManifestBoundCanaryBinding {
    host_lease: ProtectedRootLease,
    evidence_lease: ProtectedRootLease,
    host_spec: InstallerRootPrimitiveSpec,
    evidence_spec: InstallerRootPrimitiveSpec,
    evidence_root: PathBuf,
    host_before: InstallerRootObjectSnapshot,
    evidence_before: InstallerRootObjectSnapshot,
    registry: ApprovedGenerationRegistry,
    manifest: CandidateManifest,
    fence: ActivationCommitFence,
    store_config_lease: ProtectedRuntimePathLease,
    legacy_config: Option<eliot_platform_windows::LocalAppDataConfigRead>,
}

#[cfg(windows)]
fn require_matching_installer_root(
    observation: InstallerRootPrimitiveObservation,
    label: &str,
) -> Result<InstallerRootObjectSnapshot> {
    match observation {
        InstallerRootPrimitiveObservation::Matching(snapshot) => Ok(snapshot),
        InstallerRootPrimitiveObservation::Absent(_) => {
            anyhow::bail!("{label} is absent")
        }
        InstallerRootPrimitiveObservation::Mismatch => {
            anyhow::bail!("{label} has a reparse/ACL/profile mismatch")
        }
    }
}

#[cfg(windows)]
fn validate_root_snapshot_values(
    expected_path: &Path,
    retained_path: &Path,
    retained_identity: FileIdentity,
    snapshot: &InstallerRootObjectSnapshot,
    label: &str,
) -> Result<()> {
    if !eliot_platform_windows::windows_paths_equal(expected_path, retained_path) {
        anyhow::bail!("{label} path differs from the retained handle path");
    }
    if snapshot.canonical_path_digest != windows_path_identity_digest(retained_path) {
        anyhow::bail!("{label} canonical path digest differs from the retained handle path");
    }
    if snapshot.volume_serial_number != retained_identity.volume_serial_number
        || snapshot.file_index != retained_identity.file_index
    {
        anyhow::bail!("{label} object identity differs from the retained handle identity");
    }
    Ok(())
}

#[cfg(windows)]
fn validate_snapshot_matches_lease(
    expected_path: &Path,
    snapshot: &InstallerRootObjectSnapshot,
    lease: &ProtectedRootLease,
    label: &str,
) -> Result<PathBuf> {
    lease
        .verify_stable_identity()
        .map_err(|error| anyhow::anyhow!("verify retained {label} identity: {error}"))?;
    let canonical = lease
        .canonical_path()
        .map_err(|error| anyhow::anyhow!("resolve retained {label} path: {error}"))?;
    validate_root_snapshot_values(expected_path, &canonical, lease.identity(), snapshot, label)?;
    Ok(canonical)
}

#[cfg(windows)]
fn validate_unchanged_root_snapshot(
    expected_path: &Path,
    before: &InstallerRootObjectSnapshot,
    after: &InstallerRootObjectSnapshot,
    lease: &ProtectedRootLease,
    label: &str,
) -> Result<()> {
    let _canonical = validate_snapshot_matches_lease(expected_path, after, lease, label)?;
    validate_snapshot_stability_values(before, after, label)
}

#[cfg(windows)]
fn validate_snapshot_stability_values(
    before: &InstallerRootObjectSnapshot,
    after: &InstallerRootObjectSnapshot,
    label: &str,
) -> Result<()> {
    if after == before {
        Ok(())
    } else {
        anyhow::bail!("{label} ACL/profile/object snapshot changed during canary publication")
    }
}

#[cfg(windows)]
fn canonical_json_digest<T: serde::Serialize>(value: &T, label: &str) -> Result<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| anyhow::anyhow!("serialize {label} for digest: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(windows)]
fn validate_active_phase_b_runtime_binding(
    registry: &ApprovedGenerationRegistry,
    manifest: &CandidateManifest,
    fence: &ActivationCommitFence,
) -> Result<()> {
    let manifest_digest = manifest
        .compute_digest()
        .map_err(|error| anyhow::anyhow!("compute active manifest digest: {error}"))?;
    if let Some(rebind) = registry.active_phase_b_rebind() {
        let prepared = rebind.prepared.as_ref().ok_or_else(|| {
            anyhow::anyhow!("active Phase-B rebind has no prepared materialization")
        })?;
        let receipt = rebind.receipt.as_ref().ok_or_else(|| {
            anyhow::anyhow!("active Phase-B rebind has no exact destination receipt")
        })?;
        prepared.launch.require_phase_b_live().map_err(|error| {
            anyhow::anyhow!("active Phase-B prepared launch is not live: {error}")
        })?;
        if receipt.manifest_digest != manifest_digest {
            anyhow::bail!("active Phase-B rebind receipt names a foreign manifest");
        }
    } else if fence
        .phase_b_live_binding
        .as_ref()
        .is_none_or(|binding| binding.manifest_digest != manifest_digest)
    {
        anyhow::bail!("committed activation fence has no exact current Phase-B manifest binding");
    }
    Ok(())
}

#[cfg(windows)]
fn classify_legacy_governor_process_state(state: Result<bool, String>) -> Result<(), String> {
    match state {
        Ok(false) => Ok(()),
        Ok(true) => Err("legacy eliot-governor.exe is running".to_owned()),
        Err(error) => Err(format!("legacy Governor process state is unknown: {error}")),
    }
}

#[cfg(windows)]
fn observe_legacy_governor_config() -> Result<Option<eliot_platform_windows::LocalAppDataConfigRead>>
{
    let retained = match observe_current_user_config(INSTALLATION_INPUT_LIMIT) {
        Ok(eliot_platform_windows::LocalAppDataConfigObservation::Absent { .. }) => None,
        Ok(eliot_platform_windows::LocalAppDataConfigObservation::Present(read)) => {
            let text = std::str::from_utf8(read.bytes())
                .map_err(|error| anyhow::anyhow!("legacy Governor config is not UTF-8: {error}"))?;
            let config: GovernorConfig = toml::from_str(text)
                .map_err(|error| anyhow::anyhow!("legacy Governor config is malformed: {error}"))?;
            config
                .validate()
                .map_err(|error| anyhow::anyhow!("legacy Governor config is invalid: {error}"))?;
            config
                .db
                .surreal
                .reject_store_collision(
                    RUNTIME_LIVE_STORE_BIND,
                    RUNTIME_LIVE_STORE_ENDPOINT,
                    RUNTIME_LIVE_STORE_NAMESPACE,
                )
                .map_err(|error| {
                    anyhow::anyhow!(
                        "legacy Governor config collides with runtime-live Store: {error}"
                    )
                })?;
            read.verify_stable().map_err(|error| {
                anyhow::anyhow!("legacy Governor config changed during validation: {error}")
            })?;
            Some(read)
        }
        Err(error) => anyhow::bail!("legacy Governor config observation is unknown: {error}"),
    };
    classify_legacy_governor_process_state(
        is_eliot_governor_running().map_err(|error| error.to_string()),
    )
    .map_err(|error| anyhow::anyhow!(error))?;
    Ok(retained)
}

#[cfg(windows)]
fn revalidate_legacy_governor_gate(
    retained: Option<&eliot_platform_windows::LocalAppDataConfigRead>,
) -> Result<()> {
    if let Some(read) = retained {
        let text = std::str::from_utf8(read.bytes()).map_err(|error| {
            anyhow::anyhow!("retained legacy Governor config is not UTF-8: {error}")
        })?;
        let config: GovernorConfig = toml::from_str(text).map_err(|error| {
            anyhow::anyhow!("retained legacy Governor config is malformed: {error}")
        })?;
        config.validate().map_err(|error| {
            anyhow::anyhow!("retained legacy Governor config is invalid: {error}")
        })?;
        config
            .db
            .surreal
            .reject_store_collision(
                RUNTIME_LIVE_STORE_BIND,
                RUNTIME_LIVE_STORE_ENDPOINT,
                RUNTIME_LIVE_STORE_NAMESPACE,
            )
            .map_err(|error| {
                anyhow::anyhow!(
                    "retained legacy Governor config collides with runtime-live Store: {error}"
                )
            })?;
        read.verify_stable()
            .map_err(|error| anyhow::anyhow!("retained legacy Governor config changed: {error}"))?;
    } else {
        // An absent legacy config is provisional; reobserve the OS-known path
        // after the guarded operation so appearance is not silently adopted.
        let _ = observe_legacy_governor_config()?;
    }
    classify_legacy_governor_process_state(
        is_eliot_governor_running().map_err(|error| error.to_string()),
    )
    .map_err(|error| anyhow::anyhow!(error))
}

#[cfg(windows)]
fn validate_manifest_store_config(
    manifest: &CandidateManifest,
    lease: &ProtectedRuntimePathLease,
) -> Result<()> {
    let bytes = lease
        .read_bounded(INSTALLATION_INPUT_LIMIT)
        .map_err(|error| anyhow::anyhow!("read retained generation.json: {error}"))?;
    if format!("{:x}", Sha256::digest(&bytes)) != manifest.config_digest.as_str() {
        anyhow::bail!("installed generation.json digest differs from active manifest");
    }
    let config: StoreLaunchConfig = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("installed generation.json is malformed: {error}"))?;
    config
        .validate_materialized_at(Path::new(
            manifest.runtime_launch.store_config_path.as_str(),
        ))
        .map_err(|error| anyhow::anyhow!("installed StoreLaunchConfig is invalid: {error}"))?;
    if config.runtime_launch != manifest.runtime_launch {
        anyhow::bail!("installed generation.json runtime_launch differs from active manifest");
    }
    if !RuntimeLiveStoreIdentity::canonical().is_exact_match(
        &config.provider_bind_address,
        &config.endpoint,
        &config.namespace,
    ) {
        anyhow::bail!("installed generation.json targets a non-canonical runtime-live Store");
    }
    if launch_config_digest(&config)
        .map_err(|error| anyhow::anyhow!("compute StoreLaunchConfig digest: {error}"))?
        != config.approved_config_hash
    {
        anyhow::bail!("installed generation.json approved_config_hash is not self-consistent");
    }
    lease.verify_stable_identity().map_err(|error| {
        anyhow::anyhow!("installed generation.json changed during validation: {error}")
    })?;
    Ok(())
}

#[cfg(windows)]
#[allow(clippy::too_many_lines)]
fn load_manifest_bound_canary_binding(
    host_state_root: &Path,
) -> Result<ManifestBoundCanaryBinding> {
    if !host_state_root.is_absolute() {
        anyhow::bail!("Host state root must be absolute");
    }
    let registry_root = ProtectedRootLease::open_existing(host_state_root)
        .map_err(|error| anyhow::anyhow!("retain Host state root: {error}"))?;
    let registry_root_identity = registry_root.identity();
    let canonical_host_root = registry_root
        .canonical_path()
        .map_err(|error| anyhow::anyhow!("resolve Host state root: {error}"))?;
    registry_root
        .verify_stable_identity()
        .map_err(|error| anyhow::anyhow!("verify Host state root identity: {error}"))?;
    if !eliot_platform_windows::windows_paths_equal(host_state_root, &canonical_host_root) {
        anyhow::bail!("caller Host state root differs from retained OS identity");
    }
    let registry = RedbInstallationRegistry::inspect_existing_at(registry_root)
        .map_err(|error| anyhow::anyhow!("inspect retained installation registry: {error}"))?
        .ok_or_else(|| anyhow::anyhow!("retained installation registry is absent"))?;
    registry
        .validate()
        .map_err(|error| anyhow::anyhow!("validate retained installation registry: {error}"))?;
    let active = registry
        .active()
        .ok_or_else(|| anyhow::anyhow!("installation registry has no exact active generation"))?;
    let manifest = active.manifest.clone();
    manifest
        .validate()
        .map_err(|error| anyhow::anyhow!("validate active candidate manifest: {error}"))?;
    if manifest.runtime_launch.profile != InstallationProfile::SystemService {
        anyhow::bail!("production Runtime Live canary requires the active SystemService profile");
    }
    if !eliot_platform_windows::windows_paths_equal(
        Path::new(
            manifest
                .runtime_launch
                .runtime_state_roots
                .host_state_root
                .as_str(),
        ),
        &canonical_host_root,
    ) {
        anyhow::bail!("active manifest Host state root does not equal the retained caller root");
    }
    let fence = registry
        .last_committed_activation_fence()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("active generation has no committed activation fence"))?;
    fence
        .validate()
        .map_err(|error| anyhow::anyhow!("validate committed activation fence: {error}"))?;
    if fence.generation != manifest.generation
        || fence.config_digest != manifest.config_digest
        || fence.authority_generation != manifest.runtime_launch.authority_generation
    {
        anyhow::bail!("active manifest and committed activation fence disagree");
    }
    validate_active_phase_b_runtime_binding(&registry, &manifest, &fence)?;
    let legacy_config = observe_legacy_governor_config()?;
    let store_config_lease = ProtectedRuntimePathLease::open_existing_absolute_exclusive(
        Path::new(manifest.runtime_launch.store_config_path.as_str()),
    )
    .map_err(|error| anyhow::anyhow!("retain installed generation.json exclusively: {error}"))?;
    validate_manifest_store_config(&manifest, &store_config_lease)?;
    let roots = &manifest.runtime_launch.runtime_state_roots;
    roots
        .validate()
        .map_err(|error| anyhow::anyhow!("validate active runtime roots: {error}"))?;
    let evidence_root = PathBuf::from(
        roots
            .canary_evidence_root()
            .map_err(|error| anyhow::anyhow!("derive canary evidence root: {error}"))?
            .as_str(),
    );
    let host_spec = InstallerRootPrimitiveSpec {
        root: canonical_host_root.clone(),
        installation_root: PathBuf::from(roots.installation_root.as_str()),
        profile_anchor: PathBuf::from(roots.profile_anchor_root.as_str()),
        profile: InstallerRootProfile::SystemService,
    };
    let evidence_spec = InstallerRootPrimitiveSpec {
        root: evidence_root.clone(),
        installation_root: PathBuf::from(roots.installation_root.as_str()),
        profile_anchor: PathBuf::from(roots.profile_anchor_root.as_str()),
        profile: InstallerRootProfile::SystemService,
    };
    let primitive = WindowsInstallerRootPrimitive::new();
    let host_before = require_matching_installer_root(
        primitive
            .inspect(&host_spec)
            .map_err(|error| anyhow::anyhow!("inspect Host state root: {error}"))?,
        "manifest-bound Host state root",
    )?;
    validate_root_snapshot_values(
        &canonical_host_root,
        &canonical_host_root,
        registry_root_identity,
        &host_before,
        "manifest-bound Host state root",
    )?;
    let evidence_lease = ProtectedRootLease::open_existing(&evidence_root)
        .map_err(|error| anyhow::anyhow!("retain canary evidence root: {error}"))?;
    let evidence_before = require_matching_installer_root(
        primitive
            .inspect(&evidence_spec)
            .map_err(|error| anyhow::anyhow!("inspect canary evidence root: {error}"))?,
        "manifest-derived canary evidence root",
    )?;
    validate_snapshot_matches_lease(
        &evidence_root,
        &evidence_before,
        &evidence_lease,
        "manifest-derived canary evidence root",
    )?;
    // The registry still retains the first Host root handle here.  Acquire the
    // long-lived canary lease before that registry is dropped and require the
    // same volume/file object, not merely the same path spelling.
    let host_lease = ProtectedRootLease::open_existing(&canonical_host_root)
        .map_err(|error| anyhow::anyhow!("retain Host state root for canary: {error}"))?;
    validate_snapshot_matches_lease(
        &canonical_host_root,
        &host_before,
        &host_lease,
        "manifest-bound Host state root",
    )?;
    if host_lease.identity() != registry_root_identity {
        anyhow::bail!("Host state root changed between registry retention and canary retention");
    }
    Ok(ManifestBoundCanaryBinding {
        host_lease,
        evidence_lease,
        host_spec,
        evidence_spec,
        evidence_root,
        host_before,
        evidence_before,
        registry: registry.clone(),
        manifest,
        fence,
        store_config_lease,
        legacy_config,
    })
}

#[cfg(windows)]
fn revalidate_manifest_bound_canary_binding(
    retained_host: &ProtectedRootLease,
    expected_host_snapshot: &InstallerRootObjectSnapshot,
    expected_registry: &ApprovedGenerationRegistry,
    expected_manifest: &CandidateManifest,
    expected_fence: &ActivationCommitFence,
    expected_store_config_lease: &ProtectedRuntimePathLease,
    expected_legacy_config: Option<&eliot_platform_windows::LocalAppDataConfigRead>,
) -> Result<()> {
    let canonical_host_root = validate_snapshot_matches_lease(
        &PathBuf::from(
            expected_manifest
                .runtime_launch
                .runtime_state_roots
                .host_state_root
                .as_str(),
        ),
        expected_host_snapshot,
        retained_host,
        "retained Host registry root",
    )?;
    let lease = ProtectedRootLease::open_existing(&canonical_host_root)
        .map_err(|error| anyhow::anyhow!("open exact Host registry readback lease: {error}"))?;
    validate_snapshot_matches_lease(
        &canonical_host_root,
        expected_host_snapshot,
        &lease,
        "Host registry readback root",
    )?;
    if lease.identity() != retained_host.identity() {
        anyhow::bail!("Host registry readback reopened a path-same replacement");
    }
    let registry = RedbInstallationRegistry::inspect_existing_at(lease)
        .map_err(|error| anyhow::anyhow!("reinspect installation registry: {error}"))?
        .ok_or_else(|| anyhow::anyhow!("installation registry disappeared during canary"))?;
    registry
        .validate()
        .map_err(|error| anyhow::anyhow!("revalidate installation registry: {error}"))?;
    if &registry != expected_registry {
        anyhow::bail!("active installation registry changed during canary");
    }
    let active = registry
        .active()
        .ok_or_else(|| anyhow::anyhow!("active generation disappeared during canary"))?;
    if &active.manifest != expected_manifest {
        anyhow::bail!("active manifest changed during canary");
    }
    let Some(fence) = registry.last_committed_activation_fence() else {
        anyhow::bail!("committed activation fence disappeared during canary");
    };
    if fence != expected_fence {
        anyhow::bail!("committed activation fence changed during canary");
    }
    validate_active_phase_b_runtime_binding(&registry, &active.manifest, fence)?;
    revalidate_legacy_governor_gate(expected_legacy_config)?;
    validate_manifest_store_config(expected_manifest, expected_store_config_lease)?;
    retained_host
        .verify_stable_identity()
        .map_err(|error| anyhow::anyhow!("retained Host root changed during readback: {error}"))?;
    Ok(())
}

#[cfg(windows)]
fn validate_manifest_bound_canary_state(binding: &ManifestBoundCanaryBinding) -> Result<()> {
    let primitive = WindowsInstallerRootPrimitive::new();
    let host_after = require_matching_installer_root(
        primitive
            .inspect(&binding.host_spec)
            .map_err(|error| anyhow::anyhow!("inspect Host state root after canary: {error}"))?,
        "manifest-bound Host state root",
    )?;
    validate_unchanged_root_snapshot(
        &binding.host_spec.root,
        &binding.host_before,
        &host_after,
        &binding.host_lease,
        "manifest-bound Host state root",
    )?;
    let evidence_after = require_matching_installer_root(
        primitive.inspect(&binding.evidence_spec).map_err(|error| {
            anyhow::anyhow!("inspect canary evidence root after write: {error}")
        })?,
        "manifest-derived canary evidence root",
    )?;
    validate_unchanged_root_snapshot(
        &binding.evidence_root,
        &binding.evidence_before,
        &evidence_after,
        &binding.evidence_lease,
        "manifest-derived canary evidence root",
    )?;
    revalidate_manifest_bound_canary_binding(
        &binding.host_lease,
        &binding.host_before,
        &binding.registry,
        &binding.manifest,
        &binding.fence,
        &binding.store_config_lease,
        binding.legacy_config.as_ref(),
    )
}

#[cfg(windows)]
fn run_manifest_bound_canary_windows(
    host_state_root: &Path,
    pulse: Pulse,
    deadline_ms: u64,
    execute_faults: bool,
) -> Result<i32> {
    let binding = load_manifest_bound_canary_binding(host_state_root)?;
    let config = CanaryConfig {
        host_state_root: binding.host_spec.root.clone(),
        evidence_dir: binding.evidence_root.clone(),
        pulse,
        deadline: Duration::from_millis(deadline_ms),
        execute_faults,
    };
    let canary = ProductionCanary::new(config.clone())
        .map_err(|error| anyhow::anyhow!("construct production canary: {error}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build current-thread canary runtime")?;
    let disposition = runtime.block_on(canary.run());
    // Do not create even a pending artifact from a state that already drifted.
    validate_manifest_bound_canary_state(&binding)?;
    let completion_binding = ProductionCanaryCompletionBinding {
        active_registry_digest: canonical_json_digest(&binding.registry, "active registry")?,
        active_manifest_digest: binding
            .manifest
            .compute_digest()
            .map_err(|error| anyhow::anyhow!("compute active manifest digest: {error}"))?
            .as_str()
            .to_owned(),
        activation_fence_digest: canonical_json_digest(&binding.fence, "activation fence")?,
        host_root: binding.host_before.clone(),
        evidence_root: binding.evidence_before.clone(),
    };
    let publication = publish_production_evidence(
        &binding.evidence_root,
        pulse,
        &disposition,
        completion_binding,
        |_| {
            validate_manifest_bound_canary_state(&binding).map_err(|error| {
                CanaryError::Evidence(format!(
                    "post-pending retained root/registry validation failed: {error}"
                ))
            })
        },
    )
    .map_err(|error| anyhow::anyhow!("publish marker-last canary evidence: {error}"))?;
    let result = json!({
        "schema": CANARY_COMPLETION_SCHEMA,
        "authority": "PRODUCTION_COMPLETION",
        "pulse": pulse as u8,
        "disposition": disposition,
        "evidence_path": publication.completion.path,
        "evidence_digest": publication.completion.digest,
        "pending_evidence_path": publication.pending.path,
        "pending_evidence_digest": publication.pending.digest,
    });
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(
        if result["disposition"]["disposition"].as_str() == Some("PASS") {
            0
        } else if result["disposition"]["disposition"].as_str() == Some("BLOCKED") {
            75
        } else {
            INVALID_REQUEST_EXIT
        },
    )
}

fn write_manifest_canary_error(pulse: u8, code: &str, detail: &str) {
    println!(
        "{}",
        json!({
            "schema": eliot_live_canary::CANARY_SCHEMA,
            "pulse": pulse,
            "disposition": "FAIL_CLOSED",
            "status": "ERROR",
            "code": code,
            "detail": detail,
            "completed": false,
        })
    );
}

#[allow(clippy::too_many_lines)]
fn run_installation(command: InstallationCommand) -> Result<i32> {
    match command {
        InstallationCommand::Generate { .. } => {
            write_installation_error(
                "INSTALLATION_GENERATE_RETIRED",
                "installation generate is retired and no planner, output, or durable store mutation was attempted; use installation materialize-source-bundle --store",
            );
            Ok(INVALID_REQUEST_EXIT)
        }
        InstallationCommand::Plan { input } => {
            let bytes = match load_input(&input) {
                Ok(bytes) => bytes,
                Err(error) => {
                    write_installation_error("INSTALLATION_PLAN_INVALID", &error.to_string());
                    return Ok(INVALID_REQUEST_EXIT);
                }
            };
            match validate_installation_transaction_json(&bytes) {
                Ok(()) => {}
                Err(error @ InstallationError::MigrationRequired { .. }) => {
                    write_installation_error(
                        "INSTALLATION_PLAN_MIGRATION_REQUIRED",
                        &error.to_string(),
                    );
                    return Ok(INVALID_REQUEST_EXIT);
                }
                Err(error) => {
                    write_installation_error("INSTALLATION_PLAN_INVALID", &error.to_string());
                    return Ok(INVALID_REQUEST_EXIT);
                }
            };
            let value: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(value) => value,
                Err(error) => {
                    write_installation_error("INSTALLATION_PLAN_INVALID", &error.to_string());
                    return Ok(INVALID_REQUEST_EXIT);
                }
            };
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(0)
        }
        InstallationCommand::Create { input, store } => Ok(run_installation_create(&input, &store)),
        InstallationCommand::Apply {
            store,
            transaction_id,
        } => run_installation_effect(&store, &transaction_id, false),
        InstallationCommand::Recover {
            store,
            transaction_id,
        } => run_installation_effect(&store, &transaction_id, true),
        InstallationCommand::Status {
            host_state_root,
            deadline_ms,
        } => run_installation_runtime_status(&host_state_root, deadline_ms),
        InstallationCommand::RemoveCanary {
            store,
            transaction_id,
        } => {
            let scope = match (store, transaction_id) {
                (Some(store), Some(transaction_id)) => {
                    format!(" for transaction {transaction_id} in {}", store.display())
                }
                (Some(store), None) => format!(" for store {}", store.display()),
                (None, Some(transaction_id)) => format!(" for transaction {transaction_id}"),
                (None, None) => String::new(),
            };
            write_installation_error(
                "INSTALLATION_REMOVE_CANARY_UNSUPPORTED",
                &format!(
                    "remove-canary{scope} is not implemented: no durable canary removal, activation, or generation-retirement API exists; no filesystem or SCM mutation was attempted"
                ),
            );
            Ok(INVALID_REQUEST_EXIT)
        }
        InstallationCommand::MaterializeSourceBundle {
            eliot_host,
            eliot_watchdog,
            eliot_kernel,
            eliot_store_surreal,
            surreal,
            eliotd,
            output_bundle,
            output,
            store,
            generation,
            installation,
            lineage_id,
            sequence,
            transaction_id,
            staging_root,
            minimum_store_available_bytes,
            recovery_command,
            profile,
            profile_anchor_root,
            installation_key,
        } => run_installation_materialize_source_bundle(
            eliot_host,
            eliot_watchdog,
            eliot_kernel,
            eliot_store_surreal,
            surreal,
            eliotd,
            output_bundle,
            output,
            store,
            generation,
            installation,
            lineage_id,
            sequence,
            transaction_id,
            staging_root,
            minimum_store_available_bytes,
            recovery_command,
            profile,
            profile_anchor_root,
            installation_key,
        ),
    }
}

#[derive(Debug)]
enum InstallationGenerationOutcome {
    Rejected(i32),
    Generated {
        transaction_id: PlatformHandle,
        output_path: PathBuf,
        store_path: PathBuf,
    },
    OutputReconciliationRequired(GenerationOutputReconciliation),
}

#[derive(Debug)]
struct GenerationOutputReconciliation {
    transaction_id: PlatformHandle,
    store_path: PathBuf,
    output_path: PathBuf,
    diagnostic: String,
}

fn write_generation_output_reconciliation(reconciliation: &GenerationOutputReconciliation) {
    println!(
        "{}",
        json!({
            "contract": "eliot.kernel.installation",
            "contract_version": INSTALLATION_CONTRACT_VERSION,
            "status": "INSTALLATION_GENERATION_OUTPUT_RECONCILIATION_REQUIRED",
            "disposition": "UNKNOWN",
            "completed": false,
            "exit_code": UNKNOWN_OUTCOME_EXIT,
            "transaction_id": reconciliation.transaction_id.as_str(),
            "store": reconciliation.store_path.display().to_string(),
            "output": reconciliation.output_path.display().to_string(),
            "detail": reconciliation.diagnostic,
            "authority": "DURABLE_TRANSACTION_STORE",
            "output_role": "DIAGNOSTIC_NON_IMPORTABLE",
            "action": "reconcile and continue only with installation apply/recover using the exact --store and --transaction-id; never import or adopt the JSON output",
            "scope": INSTALLATION_SCOPE,
        })
    );
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn run_installation_generate(
    source_root: PathBuf,
    profile: InstallationProfile,
    profile_anchor_root: PathBuf,
    installation_key: Option<String>,
    installation: String,
    lineage_id: String,
    sequence: u64,
    generation: String,
    staging_root: PathBuf,
    transaction_id: String,
    minimum_store_available_bytes: u64,
    recovery_command: String,
    output: PathBuf,
    store_path: PathBuf,
    source_publication: source_bundle_materializer::SourceBundlePublicationBinding,
) -> Result<InstallationGenerationOutcome> {
    run_installation_generate_with_output_writer(
        GenerationPackagePlanInput {
            transaction_id: cli_handle(transaction_id, "transaction_id")?,
            installation_epoch: InstallationEpoch {
                installation: cli_handle(installation, "installation")?,
                lineage_id: cli_handle(lineage_id, "lineage_id")?,
                sequence,
            },
            profile,
            profile_anchor_root: cli_path_handle(&profile_anchor_root, "profile_anchor_root")?,
            installation_key: installation_key
                .map(|value| cli_handle(value, "installation_key"))
                .transpose()?,
            generation: cli_handle(generation, "generation")?,
            source_root: cli_path_handle(&source_root, "source_root")?,
            staging_root: cli_path_handle(&staging_root, "staging_root")?,
            minimum_store_available_bytes,
            recovery_command: cli_handle(recovery_command, "recovery_command")?,
        },
        output,
        store_path,
        source_publication,
        write_transaction_artifact,
    )
}

fn run_installation_generate_with_output_writer<F>(
    input: GenerationPackagePlanInput,
    output: PathBuf,
    store_path: PathBuf,
    source_publication: source_bundle_materializer::SourceBundlePublicationBinding,
    write_output: F,
) -> Result<InstallationGenerationOutcome>
where
    F: FnOnce(&Path, &InstallationTransaction) -> Result<(), std::io::Error>,
{
    let transaction = match GenerationPackagePlanner::plan_with_source_publication_binding(
        input,
        source_publication.source_identity,
        source_publication.files,
        source_publication.evidence_digest,
    ) {
        Ok(transaction) => transaction,
        Err(error) => {
            write_installation_error("INSTALLATION_GENERATION_REJECTED", &error.to_string());
            return Ok(InstallationGenerationOutcome::Rejected(
                INVALID_REQUEST_EXIT,
            ));
        }
    };
    let source_store = match RedbInstallationTransactionStore::open_existing_exact_path(&store_path)
    {
        Ok(store) => store,
        Err(error) => {
            write_installation_error("INSTALLATION_GENERATION_STORE_REJECTED", &error.to_string());
            return Ok(InstallationGenerationOutcome::Rejected(
                INVALID_REQUEST_EXIT,
            ));
        }
    };
    if let Err(error) = require_published_source_bundle_journal(&source_store, &transaction) {
        write_installation_error(
            "INSTALLATION_GENERATION_PUBLICATION_REJECTED",
            &error.to_string(),
        );
        return Ok(InstallationGenerationOutcome::Rejected(
            INVALID_REQUEST_EXIT,
        ));
    }
    if let Err(error) =
        RedbInstallationTransactionStore::create_planned_at_exact_path(&store_path, &transaction)
    {
        write_installation_error("INSTALLATION_GENERATION_STORE_REJECTED", &error.to_string());
        return Ok(InstallationGenerationOutcome::Rejected(
            INVALID_REQUEST_EXIT,
        ));
    }
    if let Err(error) = write_output(&output, &transaction) {
        let reconciliation = GenerationOutputReconciliation {
            transaction_id: transaction.transaction_id.clone(),
            store_path,
            output_path: output,
            diagnostic: format!(
                "durable transaction store committed before diagnostic JSON publication/readback completed: {error}; the store is authoritative and the output must be reconciled without deleting, retrying, or adopting the store"
            ),
        };
        write_generation_output_reconciliation(&reconciliation);
        return Ok(InstallationGenerationOutcome::OutputReconciliationRequired(
            reconciliation,
        ));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "contract": "eliot.kernel.installation",
            "contract_version": INSTALLATION_CONTRACT_VERSION,
            "status": "GENERATED",
            "transaction_id": transaction.transaction_id,
            "generation": transaction.candidate_manifest.generation,
            "profile": transaction.profile,
            "effect_count": transaction.effect_progress().len(),
            "package_file_count": transaction
                .installer_effects
                .iter()
                .find_map(|effect| match effect {
                    eliot_installation::InstallerEffectPlan::StagePackage { manifest, .. } => {
                        Some(manifest.files.len())
                    }
                    _ => None,
                })
                .unwrap_or(0),
            "output": output.display().to_string(),
            "store": store_path.display().to_string(),
            "scope": "source_publication_bound_generation_planner",
            "source_publication_bound": true,
            "durable_authority": "DURABLE_TRANSACTION_STORE_PLUS_TRANSACTION_ID",
            "output_role": "DIAGNOSTIC_NON_IMPORTABLE",
            "continuation": "installation apply/recover --store <exact> --transaction-id <exact>",
        }))?
    );
    Ok(InstallationGenerationOutcome::Generated {
        transaction_id: transaction.transaction_id.clone(),
        output_path: output,
        store_path,
    })
}

#[allow(
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn run_installation_materialize_source_bundle(
    eliot_host: PathBuf,
    eliot_watchdog: PathBuf,
    eliot_kernel: PathBuf,
    eliot_store_surreal: PathBuf,
    surreal: PathBuf,
    eliotd: PathBuf,
    output_bundle: PathBuf,
    output: PathBuf,
    store: PathBuf,
    generation: String,
    installation: String,
    lineage_id: String,
    sequence: u64,
    transaction_id: String,
    staging_root: PathBuf,
    minimum_store_available_bytes: u64,
    recovery_command: String,
    profile: InstallationProfile,
    profile_anchor_root: PathBuf,
    installation_key: Option<String>,
) -> Result<i32> {
    let materialize_input = source_bundle_materializer::CanarySourceBundleMaterializeInput {
        eliot_host_exe: eliot_host,
        eliot_watchdog_exe: eliot_watchdog,
        eliot_kernel_exe: eliot_kernel,
        eliot_store_surreal_exe: eliot_store_surreal,
        surreal_exe: surreal,
        eliotd_exe: eliotd,
        output_bundle: output_bundle.clone(),
        store_path: store.clone(),
        generation: cli_handle(generation.clone(), "generation")?,
        installation_epoch: InstallationEpoch {
            installation: cli_handle(installation.clone(), "installation")?,
            lineage_id: cli_handle(lineage_id.clone(), "lineage_id")?,
            sequence,
        },
        profile,
        profile_anchor_root: cli_path_handle(&profile_anchor_root, "profile_anchor_root")?,
        installation_key: installation_key
            .clone()
            .map(|value| cli_handle(value, "installation_key"))
            .transpose()?,
        transaction_id: cli_handle(transaction_id.clone(), "transaction_id")?,
        staging_root: cli_path_handle(&staging_root, "staging_root")?,
    };
    let receipt =
        match source_bundle_materializer::materialize_canary_source_bundle(&materialize_input) {
            Ok(source_bundle_materializer::CanarySourceBundleMaterializeOutcome::Published(
                receipt,
            )) => receipt,
            Ok(
                source_bundle_materializer::CanarySourceBundleMaterializeOutcome::CommittedUnknown(
                    reconciliation,
                ),
            ) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "contract": "eliot.kernel.installation",
                        "contract_version": INSTALLATION_CONTRACT_VERSION,
                        "status": "SOURCE_BUNDLE_PUBLICATION_RECONCILIATION_REQUIRED",
                        "reconciliation": reconciliation,
                    }))?
                );
                return Ok(UNKNOWN_OUTCOME_EXIT);
            }
            Err(error) => {
                write_installation_error(
                    "SOURCE_BUNDLE_MATERIALIZATION_REJECTED",
                    &error.to_string(),
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
        };
    let source_publication = receipt.planner_binding()?;
    let generated = run_installation_generate(
        output_bundle,
        profile,
        profile_anchor_root,
        installation_key,
        installation,
        lineage_id,
        sequence,
        generation,
        staging_root,
        transaction_id,
        minimum_store_available_bytes,
        recovery_command,
        output,
        store,
        source_publication,
    )?;
    match generated {
        InstallationGenerationOutcome::Generated {
            transaction_id,
            output_path,
            store_path,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "contract": "eliot.kernel.installation",
                    "contract_version": INSTALLATION_CONTRACT_VERSION,
                    "status": "SOURCE_BUNDLE_MATERIALIZED",
                    "handoff": "SOURCE_PUBLICATION_BOUND_TO_GENERATED_PLAN",
                    "transaction_id": transaction_id.as_str(),
                    "output": output_path.display().to_string(),
                    "store": store_path.display().to_string(),
                    "durable_authority": "DURABLE_TRANSACTION_STORE_PLUS_TRANSACTION_ID",
                    "output_role": "DIAGNOSTIC_NON_IMPORTABLE",
                    "continuation": "installation apply/recover --store <exact> --transaction-id <exact>",
                    "bundle_path": receipt.bundle_path,
                    "generation": receipt.generation,
                    "evidence_digest": receipt.evidence_digest,
                    "file_count": receipt.files.len(),
                    "files": receipt.files,
                    "source_identity": receipt.source_identity,
                    "directory_publication": receipt.directory_publication,
                }))?
            );
            Ok(0)
        }
        InstallationGenerationOutcome::Rejected(exit_code) => Ok(exit_code),
        InstallationGenerationOutcome::OutputReconciliationRequired(reconciliation) => {
            let _ = reconciliation;
            Ok(UNKNOWN_OUTCOME_EXIT)
        }
    }
}

fn run_installation_create(_input: &Path, _store_path: &Path) -> i32 {
    write_installation_error(
        "INSTALLATION_CREATE_PRODUCTION_DISABLED",
        "raw and diagnostic transaction JSON is non-importable and is not a production constructor; use installation materialize-source-bundle --store, then apply/recover with the exact --store and --transaction-id",
    );
    INVALID_REQUEST_EXIT
}

fn run_installation_runtime_status(host_state_root: &Path, deadline_ms: u64) -> Result<i32> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(deadline_ms);
    if std::time::Instant::now() >= deadline {
        write_runtime_status_error(
            "RUNTIME_STATUS_TIMEOUT",
            "deadline exceeded before inspection",
            true,
        );
        return Ok(INVALID_REQUEST_EXIT);
    }
    match eliot_runtime_status::collect_status(host_state_root, deadline) {
        Ok(report) => {
            let status_code = if report.status == "RUNTIME_LIVE" {
                "RUNTIME_LIVE"
            } else {
                "NOT_HEALTHY"
            };
            let completed = status_code == "RUNTIME_LIVE";
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "contract": report.contract,
                    "contract_version": report.contract_version,
                    "status": status_code,
                    "host_state_root": report.host_state_root,
                    "active_generation": report.active_generation,
                    "last_known_good_generation": report.last_known_good_generation,
                    "generations": report.generations,
                    "host_journal": {
                        "state": report.host_journal.state,
                        "clean": report.host_journal.clean,
                        "sequence": report.host_journal.sequence,
                        "last_checksum": report.host_journal.last_checksum,
                        "prior_kernel_unknown": report.host_journal.prior_kernel_unknown,
                        "gap": report.host_journal.gap,
                    },
                    "ors": {
                        "state": report.ors.state,
                        "gap": report.ors.gap,
                    },
                    "transaction_stage": report.transaction_stage,
                    "services": {
                        "kernel": report.services.kernel,
                        "store": report.services.store,
                        "eliotd": report.services.eliotd,
                        "watchdog": report.services.watchdog,
                        "host_service_registration": report.services.host_service_registration,
                        "watchdog_service_registration": report.services.watchdog_service_registration,
                    },
                    "readiness": {
                        "proof_status": report.readiness.proof_status,
                        "gap": report.readiness.age_gap,
                    },
                    "recovery_command": report.recovery_command,
                    "gaps": report.gaps,
                    "components": report.components,
                    "deadline_exceeded": report.deadline_exceeded,
                    "completed": completed,
                    "scope": INSTALLATION_SCOPE,
                }))?
            );
            Ok(if completed { 0 } else { INVALID_REQUEST_EXIT })
        }
        Err(error) => {
            let deadline_exceeded =
                matches!(&error, eliot_runtime_status::StatusError::DeadlineExceeded);
            let (code, detail) = match error {
                eliot_runtime_status::StatusError::DeadlineExceeded => (
                    "RUNTIME_STATUS_TIMEOUT",
                    "deadline exceeded during inspection".to_owned(),
                ),
                eliot_runtime_status::StatusError::Invalid(msg) => {
                    if msg.contains("does not exist") || msg.contains("absent") {
                        ("INSTALLATION_STATUS_UNAVAILABLE", msg)
                    } else {
                        ("INSTALLATION_STATUS_INVALID", msg)
                    }
                }
                eliot_runtime_status::StatusError::Unavailable(msg) => {
                    ("INSTALLATION_STATUS_UNAVAILABLE", msg)
                }
            };
            write_runtime_status_error(code, &detail, deadline_exceeded);
            Ok(INVALID_REQUEST_EXIT)
        }
    }
}

#[allow(dead_code)]
fn validate_registry_host_state_root(
    registry: &eliot_installation::ApprovedGenerationRegistry,
    canonical_host_state_root: &Path,
) -> std::result::Result<(), InstallationError> {
    for generation in registry.generations() {
        validate_manifest_host_state_root(
            &generation
                .manifest
                .runtime_launch
                .runtime_state_roots
                .host_state_root,
            canonical_host_state_root,
            "approved_generation",
        )?;
    }
    if let Some(pending) = registry.pending_activation() {
        validate_manifest_host_state_root(
            &pending
                .manifest
                .runtime_launch
                .runtime_state_roots
                .host_state_root,
            canonical_host_state_root,
            "pending_activation",
        )?;
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_manifest_host_state_root(
    declared_host_state_root: &eliot_installation::PlatformHandle,
    canonical_host_state_root: &Path,
    field_prefix: &str,
) -> std::result::Result<(), InstallationError> {
    if eliot_platform_windows::windows_paths_equal(
        canonical_host_state_root,
        Path::new(declared_host_state_root.as_str()),
    ) {
        return Ok(());
    }
    Err(InstallationError::InvalidField {
        field: format!("{field_prefix}.runtime_state_roots.host_state_root"),
        reason: "manifest Host state root does not equal the retained installation root".to_owned(),
    })
}

#[allow(dead_code)]
fn installation_status_error_code(error: &InstallationError) -> &'static str {
    match error {
        InstallationError::MigrationRequired { .. } => "INSTALLATION_STATUS_MIGRATION_REQUIRED",
        _ => "INSTALLATION_STATUS_INVALID",
    }
}

#[cfg(windows)]
struct InstallationRuntimePreflightGuard {
    _source: TrustedSourceBundle,
    generation: TrustedSourceFileLease,
    legacy_config: Option<eliot_platform_windows::LocalAppDataConfigRead>,
}

#[cfg(windows)]
impl InstallationRuntimePreflightGuard {
    fn revalidate(&self, transaction: &InstallationTransaction) -> Result<()> {
        let bytes = self
            .generation
            .read_bounded(INSTALLATION_INPUT_LIMIT)
            .map_err(|error| anyhow::anyhow!("re-read retained generation.json: {error}"))?;
        let stage = transaction
            .installer_effects
            .iter()
            .find_map(|effect| match effect {
                eliot_installation::InstallerEffectPlan::StagePackage {
                    expected_file_digests,
                    ..
                } => Some(expected_file_digests),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("transaction lost its StagePackage effect"))?;
        let expected = stage
            .iter()
            .find(|item| item.relative_path == "generation.json")
            .ok_or_else(|| anyhow::anyhow!("StagePackage omitted generation.json digest"))?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        if digest != expected.sha256.as_str()
            || digest != transaction.candidate_manifest.config_digest.as_str()
        {
            anyhow::bail!("retained generation.json digest changed during installation effects");
        }
        let config: StoreLaunchConfig = serde_json::from_slice(&bytes).map_err(|error| {
            anyhow::anyhow!("retained generation.json became malformed: {error}")
        })?;
        config
            .validate_materialized_at(Path::new(
                transaction
                    .candidate_manifest
                    .runtime_launch
                    .store_config_path
                    .as_str(),
            ))
            .map_err(|error| anyhow::anyhow!("retained StoreLaunchConfig changed: {error}"))?;
        if config.runtime_launch != transaction.candidate_manifest.runtime_launch
            || !RuntimeLiveStoreIdentity::canonical().is_exact_match(
                &config.provider_bind_address,
                &config.endpoint,
                &config.namespace,
            )
        {
            anyhow::bail!("retained generation.json runtime binding changed during effects");
        }
        revalidate_legacy_governor_gate(self.legacy_config.as_ref())
    }
}

#[cfg(not(windows))]
struct InstallationRuntimePreflightGuard;

#[cfg(not(windows))]
impl InstallationRuntimePreflightGuard {
    fn revalidate(&self, _transaction: &InstallationTransaction) -> Result<()> {
        anyhow::bail!(
            "installation runtime preflight requires Windows retained-file and process probes"
        )
    }
}

#[cfg(windows)]
fn validate_installation_runtime_preflight(
    transaction: &InstallationTransaction,
) -> Result<InstallationRuntimePreflightGuard> {
    let stage = transaction
        .installer_effects
        .iter()
        .find_map(|effect| match effect {
            eliot_installation::InstallerEffectPlan::StagePackage {
                source_bundle,
                source_bundle_identity,
                manifest,
                expected_file_digests,
                ..
            } => Some((
                source_bundle,
                source_bundle_identity,
                manifest,
                expected_file_digests,
            )),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("transaction has no exact StagePackage effect"))?;
    let source = TrustedSourceBundle::open(Path::new(stage.0.as_str()))
        .map_err(anyhow::Error::new)
        .context("retain source bundle")?;
    if source.identity() != *stage.1 {
        anyhow::bail!("source bundle identity differs from durable StagePackage binding");
    }
    let lease = source
        .retain_file("generation.json")
        .map_err(anyhow::Error::new)
        .context("retain generation.json")?;
    let bytes = lease
        .read_bounded(INSTALLATION_INPUT_LIMIT)
        .map_err(anyhow::Error::new)
        .context("read retained generation.json")?;
    let expected = stage
        .3
        .iter()
        .find(|item| item.relative_path == "generation.json")
        .ok_or_else(|| anyhow::anyhow!("StagePackage omitted generation.json digest"))?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if digest != expected.sha256.as_str()
        || digest != transaction.candidate_manifest.config_digest.as_str()
    {
        anyhow::bail!(
            "source generation.json digest differs from StagePackage or candidate manifest"
        );
    }
    let config: StoreLaunchConfig = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("source generation.json is malformed: {error}"))?;
    config
        .validate_materialized_at(Path::new(
            transaction
                .candidate_manifest
                .runtime_launch
                .store_config_path
                .as_str(),
        ))
        .map_err(|error| anyhow::anyhow!("source StoreLaunchConfig is invalid: {error}"))?;
    if config.runtime_launch != transaction.candidate_manifest.runtime_launch {
        anyhow::bail!("source generation.json runtime_launch differs from candidate manifest");
    }
    if !RuntimeLiveStoreIdentity::canonical().is_exact_match(
        &config.provider_bind_address,
        &config.endpoint,
        &config.namespace,
    ) {
        anyhow::bail!("source generation.json targets a non-canonical runtime-live Store");
    }
    lease
        .read_bounded(INSTALLATION_INPUT_LIMIT)
        .map_err(anyhow::Error::new)
        .context("re-read generation.json lease")?;
    let legacy_config = observe_legacy_governor_config()?;
    Ok(InstallationRuntimePreflightGuard {
        _source: source,
        generation: lease,
        legacy_config,
    })
}

#[cfg(not(windows))]
fn validate_installation_runtime_preflight(
    _transaction: &InstallationTransaction,
) -> Result<InstallationRuntimePreflightGuard> {
    anyhow::bail!(
        "installation runtime preflight requires Windows retained-file and process probes"
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the CLI keeps coordinator reopen, sealed readback and bounded outcome output in one auditable boundary"
)]
fn run_installation_effect(
    store_path: &Path,
    raw_transaction_id: &str,
    recover: bool,
) -> Result<i32> {
    let transaction_id = match parse_installation_transaction_id(raw_transaction_id) {
        Ok(transaction_id) => transaction_id,
        Err(error) => {
            write_installation_error(
                if recover {
                    "INSTALLATION_RECOVER_INVALID"
                } else {
                    "INSTALLATION_APPLY_INVALID"
                },
                &error.to_string(),
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let store = match RedbInstallationTransactionStore::open_existing_exact_path(store_path) {
        Ok(store) => store,
        Err(error) => {
            write_installation_error(
                if recover {
                    "INSTALLATION_RECOVER_UNAVAILABLE"
                } else {
                    "INSTALLATION_APPLY_UNAVAILABLE"
                },
                &error.to_string(),
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let preflight_transaction = match store.load(&transaction_id) {
        Ok(Some(transaction)) => transaction,
        Ok(None) => {
            write_installation_error(
                if recover {
                    "INSTALLATION_RECOVER_NOT_FOUND"
                } else {
                    "INSTALLATION_APPLY_NOT_FOUND"
                },
                &format!("transaction is not present in {}", store_path.display()),
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
        Err(error) => {
            write_installation_error(
                if recover {
                    "INSTALLATION_RECOVER_ERROR"
                } else {
                    "INSTALLATION_APPLY_ERROR"
                },
                &format!("transaction preflight could not read durable state: {error}"),
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    if preflight_transaction.profile == InstallationProfile::SystemService {
        match is_process_elevated() {
            Ok(true) => {}
            Ok(false) => {
                write_installation_error(
                    if recover {
                        "INSTALLATION_RECOVER_NOT_ELEVATED"
                    } else {
                        "INSTALLATION_APPLY_NOT_ELEVATED"
                    },
                    "SystemService requires an elevated token; no effect was attempted",
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
            Err(InstallerRootError::UnsupportedPlatform) => {
                write_installation_error(
                    if recover {
                        "INSTALLATION_RECOVER_NOT_ELEVATED"
                    } else {
                        "INSTALLATION_APPLY_NOT_ELEVATED"
                    },
                    "SystemService requires Windows elevation; no effect was attempted",
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
            Err(error) => {
                write_installation_error(
                    if recover {
                        "INSTALLATION_RECOVER_RECOVERY_REQUIRED"
                    } else {
                        "INSTALLATION_APPLY_RECOVERY_REQUIRED"
                    },
                    &format!("elevation is unknown ({error}); recovery is required"),
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
        }
    }
    if activation_projection_state_is_invalid(
        preflight_transaction.profile,
        preflight_transaction.stage(),
        preflight_transaction.has_activation_projection_intent(),
    ) {
        write_installation_error(
            "INSTALLATION_STATE_INVALID",
            "SystemService Activating transaction is missing its durable activation projection intent",
        );
        return Ok(INVALID_REQUEST_EXIT);
    }
    let preflight_status = installation_preflight_status(preflight_transaction.stage(), recover);
    let should_query_host_terminal_now = should_query_host_terminal(
        preflight_transaction.profile,
        preflight_transaction.stage(),
        preflight_transaction.has_activation_projection_intent(),
    );
    if let Some(status) = preflight_status.filter(|_| !should_query_host_terminal_now) {
        let staging = InstallationStagingDisposition::not_attempted(if status == "ROLLED_BACK" {
            "transaction is already rolled back; no recovery effect was attempted"
        } else {
            "transaction stage is terminal or incompatible; no effect was attempted"
        });
        print_transaction_projection(
            if recover {
                "RECOVERY_RESULT"
            } else {
                "EFFECT_RESULT"
            },
            store_path,
            &preflight_transaction,
            None,
            Some(&staging),
            Some(status),
        )?;
        return Ok(installation_command_exit_code(status));
    }

    // A response can be lost after Host has durably committed activation.  A
    // recovery command must query that exact terminal before it is allowed to
    // enter rollback; otherwise a perfectly good live generation would remain
    // stranded in Activating.  The query is deliberately read/reconcile-only:
    // it does not resend any effect or touch SCM/registry projection.
    if should_query_host_terminal_now {
        let host_terminal_outcome = match reconcile_host_activation_terminal_if_required(
            preflight_transaction.profile,
            preflight_transaction.stage(),
            preflight_transaction.has_activation_projection_intent(),
            || reconcile_host_activation_terminal(store_path, &preflight_transaction),
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                write_installation_error(
                    if recover {
                        "INSTALLATION_RECOVER_ERROR"
                    } else {
                        "INSTALLATION_APPLY_ERROR"
                    },
                    &format!("Host activation terminal query failed: {error}"),
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
        };
        if let Some(outcome) = host_terminal_outcome {
            let store = match RedbInstallationTransactionStore::open_existing_exact_path(store_path)
            {
                Ok(store) => store,
                Err(error) => {
                    write_installation_error(
                        "INSTALLATION_STATE_UNAVAILABLE",
                        &format!(
                            "Host terminal was observed but transaction readback failed: {error}"
                        ),
                    );
                    return Ok(INVALID_REQUEST_EXIT);
                }
            };
            let transaction = match store.load(&transaction_id) {
                Ok(Some(transaction)) => transaction,
                Ok(None) => {
                    write_installation_error(
                        "INSTALLATION_STATE_UNAVAILABLE",
                        "Host terminal was observed but the transaction disappeared",
                    );
                    return Ok(INVALID_REQUEST_EXIT);
                }
                Err(error) => {
                    write_installation_error(
                        "INSTALLATION_STATE_UNAVAILABLE",
                        &format!("Host terminal transaction readback failed: {error}"),
                    );
                    return Ok(INVALID_REQUEST_EXIT);
                }
            };
            let staging = InstallationStagingDisposition::not_attempted(if recover {
                "recovery reconciled the exact Host terminal; no rollback effect was attempted"
            } else {
                "apply observed the exact Host terminal before projection; no effect was attempted"
            });
            print_transaction_projection(
                if recover {
                    "RECOVERY_RESULT"
                } else {
                    "EFFECT_RESULT"
                },
                store_path,
                &transaction,
                Some(&outcome),
                Some(&staging),
                Some("ACTIVE_VERIFIED"),
            )?;
            return Ok(installation_command_exit_code("ACTIVE_VERIFIED"));
        }
    }

    // A queryable stage with no committed Host terminal remains subject to the
    // ordinary preflight disposition.  Keeping this return after the query is
    // what makes apply and recover response-loss safe without allowing either
    // path to resend an effect or enter rollback before the readback.
    if let Some(status) = preflight_status {
        let staging = InstallationStagingDisposition::not_attempted(if status == "ROLLED_BACK" {
            "transaction is already rolled back; no recovery effect was attempted"
        } else {
            "transaction stage is terminal or incompatible; no effect was attempted"
        });
        print_transaction_projection(
            if recover {
                "RECOVERY_RESULT"
            } else {
                "EFFECT_RESULT"
            },
            store_path,
            &preflight_transaction,
            None,
            Some(&staging),
            Some(status),
        )?;
        return Ok(installation_command_exit_code(status));
    }

    let preflight_guard = match validate_installation_runtime_preflight(&preflight_transaction) {
        Ok(guard) => guard,
        Err(error) => {
            let (code, detail, reference) = installation_preflight_error(recover, &error);
            if let Some(reference) = reference {
                write_installation_error_with_reference(&code, &detail, &reference);
            } else {
                write_installation_error(&code, &detail);
            }
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let mut coordinator = WindowsInstallationCoordinator::new(store);
    let outcome = if recover {
        coordinator.rollback(&transaction_id)
    } else if preflight_transaction.profile == InstallationProfile::SystemService {
        match coordinator.drive_until_host_bootstrap(&transaction_id) {
            Ok(InstallationStepOutcome::Applied { .. }) => {
                let current = match coordinator.store().load(&transaction_id) {
                    Ok(Some(transaction)) => transaction,
                    Ok(None) => {
                        write_installation_error(
                            "INSTALLATION_APPLY_NOT_FOUND",
                            "transaction disappeared before pending registry projection",
                        );
                        return Ok(INVALID_REQUEST_EXIT);
                    }
                    Err(error) => {
                        write_installation_error(
                            "INSTALLATION_APPLY_ERROR",
                            &format!(
                                "transaction readback before pending projection failed: {error}"
                            ),
                        );
                        return Ok(INVALID_REQUEST_EXIT);
                    }
                };
                let host_root = match ProtectedRootLease::open_existing(Path::new(
                    current
                        .candidate_manifest
                        .runtime_launch
                        .runtime_state_roots
                        .host_state_root
                        .as_str(),
                )) {
                    Ok(root) => root,
                    Err(error) => {
                        write_installation_error(
                            "INSTALLATION_APPLY_ERROR",
                            &format!("retained Host root could not be reopened: {error}"),
                        );
                        return Ok(INVALID_REQUEST_EXIT);
                    }
                };
                let registry = match RedbInstallationRegistry::open_at(host_root) {
                    Ok(registry) => registry,
                    Err(error) => {
                        write_installation_error(
                            "INSTALLATION_APPLY_ERROR",
                            &format!("pending registry could not be opened: {error}"),
                        );
                        return Ok(INVALID_REQUEST_EXIT);
                    }
                };
                let expected_revision = match registry.load() {
                    Ok(registry) => registry.revision(),
                    Err(error) => {
                        write_installation_error(
                            "INSTALLATION_APPLY_ERROR",
                            &format!("pending registry preflight failed: {error}"),
                        );
                        return Ok(INVALID_REQUEST_EXIT);
                    }
                };
                if let Err(error) = coordinator.stage_bootstrap_pending_activation(
                    &registry,
                    &transaction_id,
                    expected_revision,
                ) {
                    write_installation_error(
                        "INSTALLATION_APPLY_ERROR",
                        &format!("pending registry projection failed: {error}"),
                    );
                    return Ok(INVALID_REQUEST_EXIT);
                }
                coordinator.drive_all_effects_until_blocked(&transaction_id)
            }
            outcome => outcome,
        }
    } else {
        coordinator.drive_all_effects_until_blocked(&transaction_id)
    };
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            let code = match &error {
                InstallationError::UnknownOutcome { .. } => {
                    if recover {
                        "INSTALLATION_RECOVER_RECOVERY_REQUIRED"
                    } else {
                        "INSTALLATION_APPLY_RECOVERY_REQUIRED"
                    }
                }
                _ => {
                    if recover {
                        "INSTALLATION_RECOVER_ERROR"
                    } else {
                        "INSTALLATION_APPLY_ERROR"
                    }
                }
            };
            write_installation_error(code, &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    drop(coordinator);
    if let Err(error) = preflight_guard.revalidate(&preflight_transaction) {
        write_installation_error(
            "POST_EFFECT_RUNTIME_GUARD_UNKNOWN",
            &format!("post-coordinator runtime lease revalidation failed: {error}"),
        );
        return Ok(UNKNOWN_OUTCOME_EXIT);
    }
    let store = match RedbInstallationTransactionStore::open_existing_exact_path(store_path) {
        Ok(store) => store,
        Err(error) => {
            write_installation_error(
                "INSTALLATION_STATE_UNAVAILABLE",
                &format!(
                    "effect outcome was returned but durable state could not be reopened: {error}"
                ),
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let transaction = match store.load(&transaction_id) {
        Ok(Some(transaction)) => transaction,
        Ok(None) => {
            write_installation_error(
                "INSTALLATION_STATE_UNAVAILABLE",
                "effect outcome was returned but the transaction disappeared from the durable store",
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
        Err(error) => {
            write_installation_error("INSTALLATION_STATE_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    if activation_projection_state_is_invalid(
        transaction.profile,
        transaction.stage(),
        transaction.has_activation_projection_intent(),
    ) {
        write_installation_error(
            "INSTALLATION_STATE_INVALID",
            "SystemService Activating transaction is missing its durable activation projection intent",
        );
        return Ok(INVALID_REQUEST_EXIT);
    }
    let host_terminal_outcome = match reconcile_host_activation_terminal_if_required(
        transaction.profile,
        transaction.stage(),
        transaction.has_activation_projection_intent(),
        || reconcile_host_activation_terminal(store_path, &transaction),
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            write_installation_error(
                "INSTALLATION_STATE_INVALID",
                &format!("Host activation terminal reconciliation failed: {error}"),
            );
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    let transaction = if host_terminal_outcome.is_some() {
        match RedbInstallationTransactionStore::open_existing_exact_path(store_path)
            .and_then(|store| store.load(&transaction_id))
        {
            Ok(Some(transaction)) => transaction,
            Ok(None) => {
                write_installation_error(
                    "INSTALLATION_STATE_UNAVAILABLE",
                    "Host terminal was observed but the transaction disappeared",
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
            Err(error) => {
                write_installation_error(
                    "INSTALLATION_STATE_UNAVAILABLE",
                    &format!("Host terminal transaction readback failed: {error}"),
                );
                return Ok(INVALID_REQUEST_EXIT);
            }
        }
    } else {
        transaction
    };
    let effective_outcome = host_terminal_outcome.as_ref().unwrap_or(&outcome);
    let all_effects_applied = transaction.effect_progress().iter().all(|progress| {
        matches!(
            progress.state,
            eliot_installation::InstallationEffectProgressState::Applied { .. }
        )
    });
    // Phase-B response loss is represented by a durable IntentCommitted
    // effect and a rejected drive step.  Keep the public command state honest:
    // activation is pending and the next invocation will query-reconcile the
    // Host receipt rather than retrying materialization.
    let phase_b_pending = !recover
        && transaction.profile == InstallationProfile::SystemService
        && transaction.stage() == InstallationStage::Activating
        && matches!(effective_outcome, InstallationStepOutcome::Rejected);
    let staging = if phase_b_pending {
        InstallationStagingDisposition {
            disposition: "PENDING_RUNTIME",
            reason: Some(
                "Host Phase-B response is unresolved; activation remains fenced and the next command will query-reconcile the exact receipt"
                    .to_owned(),
            ),
            registry: None,
        }
    } else {
        installation_staging_disposition(
            transaction.profile,
            effective_outcome,
            all_effects_applied,
            recover,
        )
    };
    let overall_status = if phase_b_pending {
        "PENDING_RUNTIME"
    } else {
        installation_command_status(
            transaction.profile,
            effective_outcome,
            all_effects_applied,
            recover,
        )
    };
    print_transaction_projection(
        if recover {
            "RECOVERY_RESULT"
        } else {
            "EFFECT_RESULT"
        },
        store_path,
        &transaction,
        Some(effective_outcome),
        Some(&staging),
        Some(overall_status),
    )?;
    Ok(installation_command_exit_code(overall_status))
}

/// Reconciles only an exact Host-committed registry terminal.  A missing
/// terminal is the expected fenced first-install state and remains pending;
/// this query never starts services, rewrites descriptors, or retries a
/// credential/SCM effect.
fn reconcile_host_activation_terminal(
    store_path: &Path,
    transaction: &InstallationTransaction,
) -> Result<Option<InstallationStepOutcome>, InstallationError> {
    let host_root = ProtectedRootLease::open_existing(Path::new(
        transaction
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .host_state_root
            .as_str(),
    ))
    .map_err(|error| InstallationError::Platform(error.to_string()))?;
    let Some(registry) = RedbInstallationRegistry::open_existing_at(host_root)? else {
        return Ok(None);
    };
    let receipt = match registry.read_committed_activation_receipt(
        &transaction.transaction_id,
        &transaction.installer_plan_digest,
        &transaction.candidate_manifest.generation,
    ) {
        Ok(receipt) => receipt,
        Err(InstallationError::IncompleteObservation(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let evidence = vec![
        receipt.terminal_digest().clone(),
        receipt.candidate_manifest_digest().clone(),
    ];
    let store = RedbInstallationTransactionStore::open_existing_exact_path(store_path)?;
    let mut coordinator = WindowsInstallationCoordinator::new(store);
    coordinator
        .reconcile_active_verified(receipt, evidence)
        .map(Some)
}

#[derive(Debug)]
struct InstallationStagingDisposition {
    disposition: &'static str,
    reason: Option<String>,
    registry: Option<PathBuf>,
}

impl InstallationStagingDisposition {
    fn not_attempted(reason: &str) -> Self {
        Self {
            disposition: "NOT_ATTEMPTED",
            reason: Some(reason.to_owned()),
            registry: None,
        }
    }
}

/// Classifies the deferred registry surface without accepting caller-shaped
/// approval input.  The registry write remains a separate transaction-bound
/// operation and is intentionally never performed by this bounded command.
fn installation_staging_disposition(
    profile: InstallationProfile,
    outcome: &InstallationStepOutcome,
    all_effects_applied: bool,
    recover: bool,
) -> InstallationStagingDisposition {
    if recover {
        return InstallationStagingDisposition::not_attempted(
            "recovery does not stage activation; the recovery outcome is authoritative",
        );
    }
    if !matches!(outcome, InstallationStepOutcome::Applied { .. }) {
        return InstallationStagingDisposition::not_attempted(
            "the effect outcome is not Applied; activation remains unstaged",
        );
    }
    if !all_effects_applied {
        return InstallationStagingDisposition::not_attempted(
            "sealed transaction still contains Pending, IntentCommitted, or Unknown effects",
        );
    }
    if profile == InstallationProfile::SystemService {
        if matches!(
            outcome,
            InstallationStepOutcome::Applied {
                stage: InstallationStage::Activating,
                ..
            }
        ) {
            return InstallationStagingDisposition {
                disposition: "PENDING_RUNTIME",
                reason: Some(
                    "Host bootstrap effects are applied; activation remains pending until the Host-owned live commit fence is observed"
                        .to_owned(),
                ),
                registry: None,
            };
        }
        if matches!(
            outcome,
            InstallationStepOutcome::Applied {
                stage: InstallationStage::ActiveVerified,
                ..
            }
        ) {
            return InstallationStagingDisposition {
                disposition: "COMMITTED",
                reason: Some(
                    "the exact Host registry terminal was reconciled into the transaction"
                        .to_owned(),
                ),
                registry: None,
            };
        }
        return InstallationStagingDisposition {
            disposition: "APPROVAL_REQUIRED",
            reason: Some(
                "transaction-bound approval is required before registry staging; no registry write was attempted"
                    .to_owned(),
            ),
            registry: None,
        };
    }
    InstallationStagingDisposition {
        disposition: "NOT_APPLICABLE",
        reason: Some(
            "registry staging is not part of the PortableDev/UserMode effect command".to_owned(),
        ),
        registry: None,
    }
}

fn installation_command_status(
    profile: InstallationProfile,
    outcome: &InstallationStepOutcome,
    all_effects_applied: bool,
    recover: bool,
) -> &'static str {
    match outcome {
        InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack,
            ..
        } if recover => "ROLLED_BACK",
        InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack | InstallationStage::Completed,
            ..
        }
        | InstallationStepOutcome::Rejected => "REJECTED",
        InstallationStepOutcome::Applied {
            stage: InstallationStage::Quarantined,
            ..
        }
        | InstallationStepOutcome::Quarantined { .. } => "QUARANTINED",
        InstallationStepOutcome::Applied { .. } if recover => "ERROR",
        InstallationStepOutcome::Applied { .. } if !all_effects_applied => "ERROR",
        InstallationStepOutcome::Applied {
            stage: InstallationStage::Activating,
            ..
        } if !recover && profile == InstallationProfile::SystemService => "PENDING_RUNTIME",
        InstallationStepOutcome::Applied {
            stage: InstallationStage::ActiveVerified,
            ..
        } if !recover && profile == InstallationProfile::SystemService => "ACTIVE_VERIFIED",
        InstallationStepOutcome::Applied { .. }
            if !recover && profile == InstallationProfile::SystemService =>
        {
            "APPROVAL_REQUIRED"
        }
        InstallationStepOutcome::Applied { .. } => "EFFECTS_APPLIED",
        InstallationStepOutcome::RollbackRequired { .. } => "ROLLBACK_REQUIRED",
    }
}

fn installation_preflight_status(stage: InstallationStage, recover: bool) -> Option<&'static str> {
    if recover {
        return match stage {
            InstallationStage::RolledBack => Some("ROLLED_BACK"),
            InstallationStage::Quarantined => Some("QUARANTINED"),
            InstallationStage::ActiveVerified => Some("ACTIVE_VERIFIED"),
            InstallationStage::Cleaning | InstallationStage::Completed => Some("REJECTED"),
            _ => None,
        };
    }
    match stage {
        InstallationStage::RollbackRequired => Some("ROLLBACK_REQUIRED"),
        InstallationStage::Quarantined => Some("QUARANTINED"),
        InstallationStage::ActiveVerified => Some("ACTIVE_VERIFIED"),
        InstallationStage::Cleaning
        | InstallationStage::Completed
        | InstallationStage::RolledBack => Some("REJECTED"),
        _ => None,
    }
}

fn should_query_host_terminal(
    profile: InstallationProfile,
    stage: InstallationStage,
    has_activation_projection_intent: bool,
) -> bool {
    profile == InstallationProfile::SystemService
        && has_activation_projection_intent
        && matches!(
            stage,
            InstallationStage::Activating | InstallationStage::RollbackRequired
        )
}

fn activation_projection_state_is_invalid(
    profile: InstallationProfile,
    stage: InstallationStage,
    has_activation_projection_intent: bool,
) -> bool {
    profile == InstallationProfile::SystemService
        && stage == InstallationStage::Activating
        && !has_activation_projection_intent
}

fn reconcile_host_activation_terminal_if_required<F>(
    profile: InstallationProfile,
    stage: InstallationStage,
    has_activation_projection_intent: bool,
    query: F,
) -> Result<Option<InstallationStepOutcome>, InstallationError>
where
    F: FnOnce() -> Result<Option<InstallationStepOutcome>, InstallationError>,
{
    if should_query_host_terminal(profile, stage, has_activation_projection_intent) {
        query()
    } else {
        Ok(None)
    }
}

fn print_transaction_projection(
    status: &str,
    store_path: &Path,
    transaction: &InstallationTransaction,
    outcome: Option<&InstallationStepOutcome>,
    staging: Option<&InstallationStagingDisposition>,
    overall_status: Option<&str>,
) -> Result<()> {
    let transaction_value = serde_json::to_value(transaction)?;
    let outcome_value = outcome.map(serde_json::to_value).transpose()?;
    let projected_status = overall_status
        .or_else(|| outcome.map(installation_outcome_status))
        .unwrap_or(status);
    let completed = installation_projection_completed(transaction.stage());
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "contract": "eliot.kernel.installation",
            "contract_version": INSTALLATION_CONTRACT_VERSION,
            "status": projected_status,
            "store": store_path.display().to_string(),
            "transaction_id": transaction.transaction_id,
            "transaction_wire_version": transaction.transaction_wire_version,
            "stage": transaction.stage(),
            "revision": transaction.revision(),
            "completed": completed,
            "outcome": outcome_value,
            "staging": staging.map(|value| {
                json!({
                    "disposition": value.disposition,
                    "reason": value.reason,
                    "registry": value.registry.as_ref().map(|path| path.display().to_string()),
                })
            }),
            "transaction": transaction_value,
            "scope": INSTALLATION_SCOPE,
            "deferred_scope": [
                "generation_activation",
                "service_start",
                "runtime_health",
                "canary_removal"
            ],
        }))?
    );
    Ok(())
}

fn installation_outcome_status(outcome: &InstallationStepOutcome) -> &'static str {
    match outcome {
        InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack,
            ..
        } => "ROLLED_BACK",
        InstallationStepOutcome::Applied {
            stage: InstallationStage::Quarantined,
            ..
        }
        | InstallationStepOutcome::Quarantined { .. } => "QUARANTINED",
        InstallationStepOutcome::Applied {
            stage: InstallationStage::Completed,
            ..
        }
        | InstallationStepOutcome::Rejected => "REJECTED",
        InstallationStepOutcome::Applied { .. } => "EFFECTS_APPLIED",
        InstallationStepOutcome::RollbackRequired { .. } => "ROLLBACK_REQUIRED",
    }
}

fn installation_command_exit_code(status: &str) -> i32 {
    if matches!(
        status,
        "EFFECTS_APPLIED" | "ROLLED_BACK" | "ACTIVE_VERIFIED"
    ) {
        0
    } else {
        INVALID_REQUEST_EXIT
    }
}

fn load_input(path: &Path) -> Result<Vec<u8>> {
    let metadata =
        fs::metadata(path).with_context(|| format!("read input metadata: {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("input is not a regular file: {}", path.display());
    }
    if metadata.len() > INSTALLATION_INPUT_LIMIT {
        anyhow::bail!("input exceeds the 16 MiB limit: {}", path.display());
    }
    fs::read(path).with_context(|| format!("read input: {}", path.display()))
}

#[cfg(windows)]
fn run_ui() -> Result<i32> {
    let mut client =
        AuthenticatedKernelPort::load().map_err(|error| anyhow::anyhow!(error.to_string()))?;
    match client.ensure_operator_launch() {
        Ok(receipt) => {
            println!("{}", serde_json::to_string(&receipt)?);
            Ok(0)
        }
        Err(eliot_cli::kernel_client::KernelClientError::FrontDoorClosed(contract)) => {
            write_json_error("KERNEL_APPLICATION_PORT_CLOSED", contract);
            Ok(FRONT_DOOR_CLOSED_EXIT)
        }
        Err(error) => {
            write_json_error("KERNEL_OPERATOR_LAUNCH_REJECTED", &error.to_string());
            Ok(FRONT_DOOR_CLOSED_EXIT)
        }
    }
}

#[cfg(not(windows))]
fn run_ui() -> Result<i32> {
    write_json_error(
        "KERNEL_APPLICATION_PORT_CLOSED",
        "Windows authenticated User Broker UI",
    );
    Ok(FRONT_DOOR_CLOSED_EXIT)
}

fn run_system(command: SystemCommand) -> Result<i32> {
    match command {
        SystemCommand::Snapshot { repo_root, output } => {
            let artifact =
                capture_snapshot(&repo_root).context("capture current-system evidence")?;
            write_snapshot_artifact(&artifact, &output).context("write current-system artifact")?;
            println!("{}", serde_json::to_string_pretty(&artifact)?);
            Ok(0)
        }
    }
}

fn absolute_path(value: &str) -> std::result::Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err("path must be absolute".to_owned())
    }
}

fn parse_installation_profile(value: &str) -> std::result::Result<InstallationProfile, String> {
    match value {
        "system_service" => Ok(InstallationProfile::SystemService),
        "user_mode" => Ok(InstallationProfile::UserMode),
        "portable_dev" => Ok(InstallationProfile::PortableDev),
        _ => Err("profile must be one of system_service, user_mode, portable_dev".to_owned()),
    }
}

fn cli_handle(value: String, field: &str) -> Result<PlatformHandle> {
    PlatformHandle::new(value).map_err(|error| anyhow::anyhow!("invalid {field}: {error}"))
}

fn cli_path_handle(path: &Path, field: &str) -> Result<PlatformHandle> {
    if !path.is_absolute() {
        anyhow::bail!("{field} must be absolute");
    }
    cli_handle(path.to_string_lossy().into_owned(), field)
}

/// Writes a create-new diagnostic projection of the already committed plan.
///
/// The file is deliberately non-importable: apply and recovery open only the
/// exact durable transaction store and transaction id. A partial diagnostic
/// left by a process crash is retained for reconciliation and cannot become
/// installation authority through the retired `create` command.
fn write_transaction_artifact(
    path: &Path,
    transaction: &InstallationTransaction,
) -> Result<(), std::io::Error> {
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "transaction output must be absolute",
        ));
    }
    let bytes = serde_json::to_vec_pretty(transaction)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let mut expected = bytes.clone();
    expected.push(b'\n');
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    let mut readback = Vec::with_capacity(expected.len());
    file.read_to_end(&mut readback)?;
    if readback != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "diagnostic transaction output readback differs from the exact written bytes",
        ));
    }
    validate_installation_transaction_json(&readback)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let readback_value: serde_json::Value = serde_json::from_slice(&readback)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let expected_value = serde_json::to_value(transaction)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if readback_value != expected_value {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "diagnostic transaction output does not deserialize to the committed transaction",
        ));
    }
    Ok(())
}

/// Non-Windows builds have no authenticated Windows Kernel front door.
#[cfg(not(windows))]
struct ClosedKernelPort;

#[cfg(not(windows))]
impl CommandPort for ClosedKernelPort {
    fn dispatch(
        &mut self,
        _request: &CommandRequest,
    ) -> Result<eliot_cli::CommandResponse, CommandPortError> {
        Err(CommandPortError::FrontDoorClosed {
            contract: "N4 application command port",
        })
    }
}

fn run_dispatch() -> Result<i32> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .context("read one command request from stdin")?;
    if input.iter().all(u8::is_ascii_whitespace) {
        write_json_error(
            "REQUEST_REQUIRED",
            "dispatch requires one JSON command request",
        );
        return Ok(INVALID_REQUEST_EXIT);
    }
    let request = match serde_json::from_slice::<CommandRequest>(&input) {
        Ok(request) => request,
        Err(error) => {
            write_json_error("REQUEST_INVALID", &error.to_string());
            return Ok(INVALID_REQUEST_EXIT);
        }
    };
    #[cfg(windows)]
    let mut port = match AuthenticatedKernelPort::load() {
        Ok(port) => port,
        Err(CommandPortError::FrontDoorClosed { contract }) => {
            write_json_error("KERNEL_APPLICATION_PORT_CLOSED", contract);
            return Ok(FRONT_DOOR_CLOSED_EXIT);
        }
        Err(error) => {
            write_json_error("KERNEL_CLIENT_CONFIGURATION_REJECTED", &error.to_string());
            return Ok(FRONT_DOOR_CLOSED_EXIT);
        }
    };
    #[cfg(not(windows))]
    let mut port = ClosedKernelPort;
    match CommandCatalogue::current().dispatch(&mut port, &request) {
        Ok(response) => {
            println!("{}", serde_json::to_string(&response)?);
            Ok(0)
        }
        Err(eliot_cli::CliError::Port(CommandPortError::FrontDoorClosed { contract })) => {
            write_json_error("KERNEL_APPLICATION_PORT_CLOSED", contract);
            Ok(FRONT_DOOR_CLOSED_EXIT)
        }
        Err(error) => {
            write_json_error("REQUEST_REJECTED", &error.to_string());
            Ok(INVALID_REQUEST_EXIT)
        }
    }
}

fn write_json_error(code: &str, detail: &str) {
    println!(
        "{}",
        json!({"status": "error", "code": code, "detail": detail})
    );
}

fn write_installation_error(code: &str, detail: &str) {
    println!(
        "{}",
        json!({
            "status": "ERROR",
            "code": code,
            "detail": detail,
            "completed": false,
            "scope": INSTALLATION_SCOPE,
        })
    );
}

fn write_installation_error_with_reference(code: &str, detail: &str, reference: &str) {
    println!(
        "{}",
        json!({
            "status": "ERROR",
            "code": code,
            "detail": detail,
            "reference": reference,
            "completed": false,
            "scope": INSTALLATION_SCOPE,
        })
    );
}

fn installation_preflight_error(
    recover: bool,
    error: &anyhow::Error,
) -> (String, String, Option<String>) {
    if let Some(PackageStagingError::Win32 { stage, code }) =
        error.downcast_ref::<PackageStagingError>()
    {
        let reference = format!(
            "stage-package-win32-v1:{}:{code:08x}",
            package_staging_stage_name(*stage)
        );
        return (
            if recover {
                "INSTALLATION_RECOVER_PREFLIGHT_REJECTED".to_owned()
            } else {
                "INSTALLATION_APPLY_PREFLIGHT_REJECTED".to_owned()
            },
            reference.clone(),
            Some(reference),
        );
    }
    (
        if recover {
            "INSTALLATION_RECOVER_PREFLIGHT_REJECTED".to_owned()
        } else {
            "INSTALLATION_APPLY_PREFLIGHT_REJECTED".to_owned()
        },
        error.to_string(),
        None,
    )
}

fn package_staging_stage_name(stage: PackageStagingStage) -> &'static str {
    match stage {
        PackageStagingStage::SetSecurityInfo => "set-security-info",
        PackageStagingStage::GetSecurityInfo => "get-security-info",
        PackageStagingStage::CreateFileW => "create-file-w",
        PackageStagingStage::FlushFileBuffers => "flush-file-buffers",
        PackageStagingStage::GetFileInformationByHandle => "get-file-information-by-handle",
        PackageStagingStage::DuplicateHandle => "duplicate-handle",
        PackageStagingStage::SetFilePointerEx => "set-file-pointer-ex",
        PackageStagingStage::ReadFile => "read-file",
        PackageStagingStage::WriteFile => "write-file",
    }
}

fn write_runtime_status_error(code: &str, detail: &str, deadline_exceeded: bool) {
    println!(
        "{}",
        json!({
            "status": "ERROR",
            "code": code,
            "detail": detail,
            "deadline_exceeded": deadline_exceeded,
            "completed": false,
            "scope": INSTALLATION_SCOPE,
        })
    );
}

fn installation_projection_completed(stage: InstallationStage) -> bool {
    stage == InstallationStage::Completed
}

#[cfg(windows)]
struct AuthenticatedKernelPort {
    client: eliot_cli::kernel_client::KernelClient,
}

#[cfg(windows)]
impl AuthenticatedKernelPort {
    fn load() -> Result<Self, CommandPortError> {
        eliot_cli::kernel_client::KernelClient::load()
            .map(|client| Self { client })
            .map_err(|error| match error {
                eliot_cli::kernel_client::KernelClientError::FrontDoorClosed(contract) => {
                    CommandPortError::FrontDoorClosed { contract }
                }
                other => CommandPortError::Rejected(other.to_string()),
            })
    }

    fn ensure_operator_launch(
        &mut self,
    ) -> std::result::Result<serde_json::Value, eliot_cli::kernel_client::KernelClientError> {
        self.client.ensure_operator_launch()
    }
}

#[cfg(windows)]
impl CommandPort for AuthenticatedKernelPort {
    fn dispatch(
        &mut self,
        request: &CommandRequest,
    ) -> Result<eliot_cli::CommandResponse, CommandPortError> {
        self.client.set_request_identity(request.request.clone());
        let payload = serde_json::to_value(request)
            .map_err(|error| CommandPortError::Rejected(error.to_string()))?;
        let response = self
            .client
            .transact_json("eliot.cli.command", payload)
            .map_err(|error| match error {
                eliot_cli::kernel_client::KernelClientError::FrontDoorClosed(contract) => {
                    CommandPortError::FrontDoorClosed { contract }
                }
                other => CommandPortError::Rejected(other.to_string()),
            })?;
        serde_json::from_value(response)
            .map_err(|error| CommandPortError::Rejected(error.to_string()))
    }
}

fn run_catalogue(command: &CatalogueCommand) -> Result<()> {
    let catalogue = eliot_cli::CommandCatalogue::current();
    match command {
        CatalogueCommand::Help => println!("{}", catalogue.help_text()?),
        CatalogueCommand::Schema => println!("{}", catalogue.schema_json()?),
        CatalogueCommand::Validate => {
            catalogue.validate()?;
            println!("catalogue {} is valid", eliot_cli::CATALOGUE_REVISION);
        }
    }
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "small pure status tests use explicit panic messages for impossible fixture states"
)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn legacy_governor_pre_gate_rejects_present_and_unknown_process_state() {
        assert!(classify_legacy_governor_process_state(Ok(false)).is_ok());
        assert!(classify_legacy_governor_process_state(Ok(true)).is_err());
        assert!(classify_legacy_governor_process_state(Err("probe failed".to_owned())).is_err());
    }

    #[test]
    fn committed_unknown_materialization_uses_reconciliation_exit() {
        assert_eq!(UNKNOWN_OUTCOME_EXIT, 75);
    }

    fn applied_outcome() -> InstallationStepOutcome {
        InstallationStepOutcome::Applied {
            stage: eliot_installation::InstallationStage::Planned,
            evidence_refs: Vec::new(),
        }
    }

    #[test]
    fn portable_all_effects_are_not_reported_as_one_effect() {
        let outcome = applied_outcome();
        assert_eq!(
            installation_command_status(InstallationProfile::PortableDev, &outcome, true, false,),
            "EFFECTS_APPLIED"
        );
        assert_eq!(installation_command_exit_code("EFFECTS_APPLIED"), 0);
        assert_ne!(installation_outcome_status(&outcome), "EFFECT_APPLIED");
    }

    #[test]
    fn system_service_all_effects_require_transaction_bound_approval() {
        let outcome = applied_outcome();
        let staging = installation_staging_disposition(
            InstallationProfile::SystemService,
            &outcome,
            true,
            false,
        );
        assert_eq!(staging.disposition, "APPROVAL_REQUIRED");
        assert_eq!(
            installation_command_status(InstallationProfile::SystemService, &outcome, true, false,),
            "APPROVAL_REQUIRED"
        );
        assert_eq!(
            installation_command_exit_code("APPROVAL_REQUIRED"),
            INVALID_REQUEST_EXIT
        );
        assert!(staging.registry.is_none());
        assert!(
            staging
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("no registry write"))
        );
    }

    #[test]
    fn applied_outcome_with_incomplete_readback_is_an_error() {
        let outcome = applied_outcome();
        let staging = installation_staging_disposition(
            InstallationProfile::PortableDev,
            &outcome,
            false,
            false,
        );
        assert_eq!(staging.disposition, "NOT_ATTEMPTED");
        assert_eq!(
            installation_command_status(InstallationProfile::PortableDev, &outcome, false, false,),
            "ERROR"
        );
        assert_eq!(
            installation_command_exit_code("ERROR"),
            INVALID_REQUEST_EXIT
        );
    }

    #[test]
    fn blocked_outcomes_have_distinct_nonzero_statuses() {
        let outcome = InstallationStepOutcome::RollbackRequired {
            pending_refs: Vec::new(),
        };
        assert_eq!(
            installation_command_status(InstallationProfile::SystemService, &outcome, false, false,),
            "ROLLBACK_REQUIRED"
        );
        assert_eq!(
            installation_command_status(
                InstallationProfile::SystemService,
                &InstallationStepOutcome::Quarantined {
                    pending_refs: Vec::new(),
                },
                false,
                false,
            ),
            "QUARANTINED"
        );
        assert_eq!(
            installation_command_status(
                InstallationProfile::SystemService,
                &InstallationStepOutcome::Rejected,
                false,
                false,
            ),
            "REJECTED"
        );
        assert_eq!(
            installation_command_exit_code("ROLLBACK_REQUIRED"),
            INVALID_REQUEST_EXIT
        );
        assert_eq!(
            installation_command_exit_code("QUARANTINED"),
            INVALID_REQUEST_EXIT
        );
        assert_eq!(
            installation_command_exit_code("REJECTED"),
            INVALID_REQUEST_EXIT
        );
    }

    #[test]
    fn successful_rollback_is_reported_as_rolled_back() {
        let outcome = InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack,
            evidence_refs: Vec::new(),
        };
        let staging = installation_staging_disposition(
            InstallationProfile::SystemService,
            &outcome,
            true,
            true,
        );

        assert_eq!(staging.disposition, "NOT_ATTEMPTED");
        assert_eq!(
            installation_command_status(InstallationProfile::SystemService, &outcome, true, true,),
            "ROLLED_BACK"
        );
        assert_eq!(installation_command_exit_code("ROLLED_BACK"), 0);
        assert!(!installation_projection_completed(
            InstallationStage::RolledBack
        ));
    }

    #[test]
    fn terminal_apply_preflight_never_reports_effects_applied() {
        for stage in [
            InstallationStage::Cleaning,
            InstallationStage::Completed,
            InstallationStage::RolledBack,
            InstallationStage::Quarantined,
        ] {
            let status = installation_preflight_status(stage, false)
                .expect("incompatible terminal stage must be rejected");
            assert_ne!(status, "EFFECTS_APPLIED");
            assert_ne!(installation_command_exit_code(status), 0);
        }
        assert_eq!(
            installation_preflight_status(InstallationStage::RollbackRequired, false),
            Some("ROLLBACK_REQUIRED")
        );
        assert_eq!(
            installation_preflight_status(InstallationStage::ActiveVerified, false),
            Some("ACTIVE_VERIFIED")
        );
        assert_eq!(
            installation_preflight_status(InstallationStage::ActiveVerified, true),
            Some("ACTIVE_VERIFIED")
        );
        assert_eq!(installation_command_exit_code("ACTIVE_VERIFIED"), 0);
    }

    #[test]
    fn package_win32_preflight_emits_typed_stage_and_code() {
        let error = anyhow::Error::new(PackageStagingError::Win32 {
            stage: PackageStagingStage::WriteFile,
            code: 5,
        })
        .context(r"retain source bundle C:\secret\package");
        assert_eq!(
            installation_preflight_error(false, &error),
            (
                "INSTALLATION_APPLY_PREFLIGHT_REJECTED".to_owned(),
                "stage-package-win32-v1:write-file:00000005".to_owned(),
                Some("stage-package-win32-v1:write-file:00000005".to_owned()),
            )
        );
        assert_eq!(
            installation_preflight_error(true, &error),
            (
                "INSTALLATION_RECOVER_PREFLIGHT_REJECTED".to_owned(),
                "stage-package-win32-v1:write-file:00000005".to_owned(),
                Some("stage-package-win32-v1:write-file:00000005".to_owned()),
            )
        );
    }

    #[test]
    fn non_package_preflight_errors_remain_generic_rejections() {
        let error = anyhow::anyhow!("secret path or credential reference");
        let (code, detail, reference) = installation_preflight_error(false, &error);
        assert_eq!(code, "INSTALLATION_APPLY_PREFLIGHT_REJECTED");
        assert_eq!(detail, "secret path or credential reference");
        assert_eq!(reference, None);
    }

    #[test]
    fn host_terminal_query_requires_durable_activation_projection() {
        assert!(!should_query_host_terminal(
            InstallationProfile::SystemService,
            InstallationStage::RollbackRequired,
            false,
        ));
        assert!(!should_query_host_terminal(
            InstallationProfile::SystemService,
            InstallationStage::Activating,
            false,
        ));
        assert!(should_query_host_terminal(
            InstallationProfile::SystemService,
            InstallationStage::Activating,
            true,
        ));
        assert!(should_query_host_terminal(
            InstallationProfile::SystemService,
            InstallationStage::RollbackRequired,
            true,
        ));
        assert!(!should_query_host_terminal(
            InstallationProfile::PortableDev,
            InstallationStage::RollbackRequired,
            true,
        ));
        // A missing terminal still leaves the original preflight disposition;
        // the query is read-only and must not turn RollbackRequired into a
        // successful result by itself.
        assert_eq!(
            installation_preflight_status(InstallationStage::RollbackRequired, false),
            Some("ROLLBACK_REQUIRED")
        );
        assert_eq!(
            installation_preflight_status(InstallationStage::RollbackRequired, true),
            None
        );
    }

    #[test]
    fn early_rollback_required_skips_host_query_and_preserves_recovery_path() {
        let queried = std::cell::Cell::new(false);
        let outcome = reconcile_host_activation_terminal_if_required(
            InstallationProfile::SystemService,
            InstallationStage::RollbackRequired,
            false,
            || {
                queried.set(true);
                Ok(None)
            },
        )
        .expect("early rollback must not fail while skipping Host query");
        assert!(outcome.is_none());
        assert!(!queried.get());
        assert!(!activation_projection_state_is_invalid(
            InstallationProfile::SystemService,
            InstallationStage::RollbackRequired,
            false,
        ));
    }

    #[test]
    fn activating_response_loss_with_projection_keeps_host_query() {
        let queried = std::cell::Cell::new(false);
        let outcome = reconcile_host_activation_terminal_if_required(
            InstallationProfile::SystemService,
            InstallationStage::Activating,
            true,
            || {
                queried.set(true);
                Ok(None)
            },
        )
        .expect("activating response-loss query must remain available");
        assert!(outcome.is_none());
        assert!(queried.get());
        assert!(!activation_projection_state_is_invalid(
            InstallationProfile::SystemService,
            InstallationStage::Activating,
            true,
        ));
    }

    #[test]
    fn activating_without_projection_is_rejected_before_any_host_query() {
        assert!(activation_projection_state_is_invalid(
            InstallationProfile::SystemService,
            InstallationStage::Activating,
            false,
        ));
        assert!(!should_query_host_terminal(
            InstallationProfile::SystemService,
            InstallationStage::Activating,
            false,
        ));
    }

    #[test]
    fn rolled_back_projection_serializes_completed_false() {
        let projection = json!({
            "status": "ROLLED_BACK",
            "stage": InstallationStage::RolledBack,
            "completed": installation_projection_completed(InstallationStage::RolledBack),
            "scope": INSTALLATION_SCOPE,
        });
        let serialized = serde_json::to_string(&projection).expect("serialize projection");
        let decoded: serde_json::Value =
            serde_json::from_str(&serialized).expect("decode serialized projection");
        assert_eq!(decoded["status"], "ROLLED_BACK");
        assert_eq!(decoded["stage"], "ROLLED_BACK");
        assert_eq!(decoded["completed"], false);
        assert_eq!(decoded["scope"], INSTALLATION_SCOPE);
    }

    #[test]
    fn installation_status_preserves_migration_and_corruption_classification() {
        assert_eq!(
            installation_status_error_code(&InstallationError::MigrationRequired {
                reason: "old table".to_owned(),
            }),
            "INSTALLATION_STATUS_MIGRATION_REQUIRED"
        );
        assert_eq!(
            installation_status_error_code(&InstallationError::CorruptRegistry {
                reason: "bad bytes".to_owned(),
            }),
            "INSTALLATION_STATUS_INVALID"
        );
        assert_eq!(
            installation_status_error_code(&InstallationError::InvalidField {
                field: "path".to_owned(),
                reason: "reparse".to_owned(),
            }),
            "INSTALLATION_STATUS_INVALID"
        );
        assert_eq!(
            installation_status_error_code(&InstallationError::Platform(
                "access denied".to_owned()
            )),
            "INSTALLATION_STATUS_INVALID"
        );
    }

    #[test]
    fn installation_status_accepts_manifest_root_bound_to_retained_root() {
        let retained_root = Path::new(
            r"C:\ProgramData\Eliot\installations\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\host",
        );
        let declared_root = parse_installation_transaction_id(retained_root.to_string_lossy())
            .expect("valid retained root fixture");
        assert!(validate_manifest_host_state_root(&declared_root, retained_root, "active").is_ok());
    }

    #[test]
    fn installation_status_rejects_manifest_root_substitution() {
        let retained_root = Path::new(
            r"C:\ProgramData\Eliot\installations\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\host",
        );
        let substituted_root = parse_installation_transaction_id(
            r"C:\ProgramData\Eliot\installations\bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\host",
        )
        .expect("valid substituted root fixture");
        let error = validate_manifest_host_state_root(&substituted_root, retained_root, "active")
            .expect_err("substituted manifest root must fail closed");
        assert!(matches!(
            error,
            InstallationError::InvalidField { field, .. }
                if field == "active.runtime_state_roots.host_state_root"
        ));
    }

    #[test]
    fn runtime_status_cli_requires_absolute_host_state_root() {
        let result = Cli::try_parse_from([
            "eliot",
            "installation",
            "status",
            "--host-state-root",
            "relative/path",
        ]);
        assert!(
            result.is_err(),
            "relative host-state-root must be rejected by value_parser"
        );
    }

    #[test]
    fn runtime_status_cli_accepts_production_json_surface() {
        let root = std::env::temp_dir().join("eliot-runtime-status-production");
        let root_arg = root.to_string_lossy().into_owned();
        let cli = Cli::try_parse_from([
            "eliot",
            "runtime",
            "status",
            "--json",
            "--host-state-root",
            root_arg.as_str(),
        ])
        .expect("production runtime status surface must parse");
        match cli.command {
            Command::Runtime { command } => match command {
                RuntimeCommand::Status {
                    json,
                    host_state_root,
                    deadline_ms,
                } => {
                    assert!(json);
                    assert_eq!(host_state_root, root);
                    assert_eq!(deadline_ms, 2000);
                }
                RuntimeCommand::Canary { .. } => {
                    panic!("expected runtime status command")
                }
            },
            _ => panic!("expected runtime command"),
        }
    }

    #[test]
    fn runtime_canary_cli_is_manifest_bound_and_has_no_evidence_dir_argument() {
        let root = std::env::temp_dir().join("eliot-runtime-canary-production");
        let root_arg = root.to_string_lossy().into_owned();
        let cli = Cli::try_parse_from([
            "eliot",
            "runtime",
            "canary",
            "--host-state-root",
            root_arg.as_str(),
            "--pulse",
            "2",
            "--deadline-ms",
            "9000",
        ])
        .expect("manifest-bound canary surface must parse");
        match cli.command {
            Command::Runtime {
                command:
                    RuntimeCommand::Canary {
                        host_state_root,
                        pulse,
                        deadline_ms,
                        execute_faults,
                    },
            } => {
                assert_eq!(host_state_root, root);
                assert_eq!(pulse, 2);
                assert_eq!(deadline_ms, 9000);
                assert!(!execute_faults);
            }
            _ => panic!("expected runtime canary command"),
        }
        assert!(
            Cli::try_parse_from([
                "eliot",
                "runtime",
                "canary",
                "--host-state-root",
                root_arg.as_str(),
                "--pulse",
                "2",
                "--evidence-dir",
                root_arg.as_str(),
            ])
            .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn canary_root_snapshot_binding_rejects_path_object_acl_and_profile_substitution() {
        let path = PathBuf::from(r"C:\ProgramData\Eliot\runtime\host");
        let identity = FileIdentity {
            volume_serial_number: 17,
            file_index: 29,
        };
        let snapshot = InstallerRootObjectSnapshot {
            canonical_path_digest: windows_path_identity_digest(&path),
            volume_serial_number: identity.volume_serial_number,
            file_index: identity.file_index,
            security_descriptor_digest: "a".repeat(64),
        };
        assert!(
            validate_root_snapshot_values(&path, &path, identity, &snapshot, "test root").is_ok()
        );

        let substituted_path = PathBuf::from(r"C:\ProgramData\Eliot\runtime\hosт");
        assert!(
            validate_root_snapshot_values(
                &path,
                &substituted_path,
                identity,
                &snapshot,
                "test root",
            )
            .is_err()
        );
        let substituted_identity = FileIdentity {
            volume_serial_number: identity.volume_serial_number,
            file_index: identity.file_index + 1,
        };
        assert!(
            validate_root_snapshot_values(
                &path,
                &path,
                substituted_identity,
                &snapshot,
                "test root",
            )
            .is_err()
        );
        let mut acl_drift = snapshot.clone();
        acl_drift.security_descriptor_digest = "b".repeat(64);
        assert!(validate_snapshot_stability_values(&snapshot, &acl_drift, "test root").is_err());
        assert!(
            require_matching_installer_root(
                InstallerRootPrimitiveObservation::Mismatch,
                "profile-substituted test root",
            )
            .is_err()
        );
    }

    #[test]
    fn runtime_status_cli_accepts_absolute_host_state_root() {
        let temp = std::env::temp_dir().join(format!("eliot-cli-abs-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp);
        let arg = temp.to_string_lossy().into_owned();
        let cli = Cli::try_parse_from([
            "eliot",
            "installation",
            "status",
            "--host-state-root",
            arg.as_str(),
        ])
        .expect("absolute root must parse");
        match cli.command {
            Command::Installation { command } => match command {
                InstallationCommand::Status {
                    host_state_root,
                    deadline_ms,
                } => {
                    assert!(host_state_root.is_absolute());
                    assert_eq!(deadline_ms, 2000);
                }
                _ => panic!("expected status command"),
            },
            _ => panic!("expected installation command"),
        }
        let _ = std::fs::remove_dir_all(temp);
    }

    fn honest_cli_temp_root(prefix: &str) -> PathBuf {
        #[cfg(windows)]
        {
            let base = eliot_platform_windows::protected_program_data_root()
                .unwrap_or_else(|_| std::env::temp_dir());
            base.join(format!(
                "eliot-test-cli-{}-{}-{}",
                prefix,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ))
        }
        #[cfg(not(windows))]
        {
            let _ = prefix;
            std::env::temp_dir().join(format!(
                "eliot-cli-collect-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ))
        }
    }

    #[test]
    fn runtime_status_collect_via_cli_construction_is_not_healthy_with_explicit_gaps_and_no_synthesis()
     {
        let root = honest_cli_temp_root("collect");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let report = eliot_runtime_status::collect_status(&root, deadline)
            .expect("honest collect must succeed");
        assert_eq!(report.status, "NOT_HEALTHY");
        assert_eq!(report.contract, "eliot.runtime.live");
        assert!(
            report
                .gaps
                .iter()
                .any(|g| g.contains("freshness cannot be proven"))
        );
        assert!(report.gaps.iter().any(|g| g.contains("trust anchor")));
        assert!(report.gaps.iter().any(|g| g.contains("transaction stage")));
        assert!(report.gaps.iter().any(|g| g.contains("Kernel")));
        assert!(report.gaps.iter().any(|g| g.contains("Store")));
        let json = serde_json::to_value(json!({
            "status": report.status,
            "host_state_root": report.host_state_root,
            "ors": report.ors,
            "transaction_stage": report.transaction_stage,
            "gaps": report.gaps,
            "components": report.components,
        }))
        .expect("serialize");
        let text = serde_json::to_string(&json)
            .expect("stringify")
            .to_ascii_lowercase();
        assert!(!text.contains("\"pid\""));
        assert!(!text.contains("\"fence\""));
        assert!(!text.contains("\"nonce\""));
        assert!(matches!(
            report.transaction_stage.state,
            eliot_runtime_status::ComponentState::Unknown { .. }
        ));
        assert_eq!(
            report.transaction_stage.gap,
            eliot_runtime_status::transaction_stage_gap_for()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_status_cli_never_synthesizes_pid_key_nonce_fence_via_collect() {
        let root = honest_cli_temp_root("no-synth");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let report = eliot_runtime_status::collect_status(&root, deadline).expect("collect");
        let serialized = serde_json::to_string(&report)
            .expect("serialize report")
            .to_ascii_lowercase();
        assert!(!serialized.contains("\"pid\""));
        assert!(!serialized.contains("\"fence\""));
        assert!(!serialized.contains("\"nonce\""));
        assert!(!serialized.contains("\"public_key\""));
        let _ = std::fs::remove_dir_all(root);
    }
}
